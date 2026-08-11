//! `deposit_sweep_batch` — upgrade #31 (F2b): drains the session's escrow
//! ATAs, 1-4 legs per call, in one of two directions:
//!
//! - **Settle direction** (escrow → vault): only once ALL swaps completed
//!   (`session.is_complete()`), the session is not stale and the vault is
//!   not mid-restructure. PERMISSIONLESS — once the swaps ran, the deposit
//!   is economically committed and finishing it only benefits the
//!   investor, so anyone (the frontend, a crank, ourselves) can drive an
//!   abandoned-but-complete session to settlement.
//!
//! - **Abort direction** (escrow → investor): for incomplete sessions,
//!   sessions made stale by a restructure, or sessions already flagged
//!   `aborting`. The investor any time; ANYONE after
//!   `DEPOSIT_SESSION_TIMEOUT_SECS` (30 min) — the orphan-session
//!   guarantee. The first abort-direction sweep sets `session.aborting`,
//!   which permanently blocks further swaps and the settle path.
//!
//! Either way each swept escrow ATA is emptied IN FULL and closed, with
//! its rent refunded to the investor (who paid to create it). The
//! direction is decided ON-CHAIN from session + vault state — the caller
//! only supplies accounts, so a malicious caller can never choose where
//! the funds go.
//!
//! # remaining_accounts layout
//!
//! For each leg in `leg_indices`: `[mint, escrow_ata, dest_ata]`.
//! `mint` must match the session's `leg_mints` snapshot (NOT the live
//! vault table — the vault may have restructured); `escrow_ata` must be
//! the canonical ATA of (session, mint); `dest_ata` the canonical ATA of
//! (vault, mint) or (investor, mint) depending on direction.

use anchor_lang::prelude::*;
use anchor_spl::token::{spl_token, Token};

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::DepositEscrowSwept;
use crate::state::deposit_session::DEPOSIT_SESSION_TIMEOUT_SECS;
use crate::state::vault_layout as vlayout;
use crate::state::{DepositSession, ProtocolConfig};
use crate::token_io::{
    close_token_account_signed, derive_live_ata, read_mint_decimals, read_token_amount,
    transfer_checked_signed, verify_token_account, TOKEN_2022_PROGRAM_ID,
};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct DepositSweepBatchArgs {
    pub leg_indices: Vec<u8>,
}

#[derive(Accounts)]
pub struct DepositSweepBatch<'info> {
    /// Settle direction: anyone. Abort direction: the investor, or anyone
    /// after the 30-minute timeout. Pays the tx fee; never receives funds.
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: pinned to `session.investor` via has_one. Receives the rent
    /// of every escrow ATA closed in this batch (they paid to create them).
    #[account(mut)]
    pub investor: UncheckedAccount<'info>,

    /// CHECK: PDA seeds + owner verified manually (VaultGuard).
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [
            DEPOSIT_SESSION_SEED,
            vault.key().as_ref(),
            investor.key().as_ref(),
        ],
        bump = deposit_session.bump,
        has_one = investor @ WagonError::DepositSessionWrongInvestor,
        has_one = vault @ WagonError::DepositSessionWrongVault,
    )]
    pub deposit_session: Box<Account<'info, DepositSession>>,

    pub token_program: Program<'info, Token>,

    /// CHECK: pubkey verified == Token-2022 program id. Used for legs whose
    /// mint lives on Token-2022 (xStocks, MetaDAO); ignored otherwise.
    pub token_program_2022: UncheckedAccount<'info>,

    /// Ceremonia #50 (S-1): da `m2m_enforced` (para el fail-closed del re-precio
    /// en el commit) y `usdc_mint`. Se pasa en TODO barrido; solo se usa para
    /// re-marcar en el barrido de COMMIT con `m2m_enforced==1`.
    #[account(seeds = [PROTOCOL_SEED], bump = protocol.bump)]
    pub protocol: Box<Account<'info, ProtocolConfig>>,
}

pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, DepositSweepBatch<'info>>,
    args: DepositSweepBatchArgs,
) -> Result<()> {
    // ---- Validate batch shape ----------------------------------------------
    require!(!args.leg_indices.is_empty(), WagonError::EmptyBatch);
    require!(
        args.leg_indices.len() <= MAX_SWEEP_LEGS_PER_BATCH,
        WagonError::BatchTooLarge
    );
    require_keys_eq!(
        ctx.accounts.token_program_2022.key(),
        TOKEN_2022_PROGRAM_ID,
        WagonError::InvalidJupiterRoute
    );

    // ---- Vault guard (owner + PDA derivation; status read, not gated) -----
    let vault_ai = ctx.accounts.vault.to_account_info();
    let guard = crate::guards::VaultGuard::load(
        &vault_ai,
        &ctx.accounts.vault.key(),
        WagonError::VaultPaused,
    )?;

    let session = &ctx.accounts.deposit_session;
    let now = Clock::get()?.unix_timestamp;
    let stale = {
        let data = vault_ai.try_borrow_data()?;
        session.created_at < vlayout::read_last_restructured_at(&data)?
    };

    // ---- Decide the direction ON-CHAIN -------------------------------------
    // The caller has no say: complete + fresh sessions settle into the
    // vault; everything else unwinds to the investor.
    // Ceremonia #42 (Change 2 / OT-3): una sesión COMPLETA y SIN barrer
    // (`legs_swept == 0`: sus tokens siguen en el escrow de la propia sesión) en
    // un vault que ya pasó a un estado TERMINAL (Liquidating/Closed) no puede
    // asentar —settle exige Active (más abajo)— y hoy quedaba ATASCADA: ni entra
    // ni se reembolsa. Se la manda al camino de ABORTO (reembolso EN ESPECIE de
    // su propio escrow al inversor). El `legs_swept == 0` es CRÍTICO: una sesión
    // con patas YA barridas al vault (OT-1/OT-2) NO entra aquí —reembolsarla
    // tocaría fondos que ya son de los demás titulares—; ese caso necesita el
    // contador de sesiones y va a la #43. Paused (transitorio, se recupera al
    // despausar) y Restructuring (lo veta el else) se dejan esperar a propósito.
    let abort_direction = session.aborting == 1
        || !session.is_complete()
        || stale
        || ((guard.status == 2u8 || guard.status == 3u8) && session.legs_swept == 0);
    if abort_direction {
        let timed_out = now.saturating_sub(session.created_at) > DEPOSIT_SESSION_TIMEOUT_SECS;
        require!(
            ctx.accounts.caller.key() == session.investor || timed_out,
            WagonError::DepositAbortTooEarly
        );
    } else {
        // Never land tokens in the vault while a restructure is selling the
        // outgoing set — it would corrupt the restructure's dust check.
        require!(guard.status != 4u8, WagonError::RestructuringInProgress);
        // M-3: the settle direction is an ENTRY into the vault — only an
        // Active vault may receive it. A COMPLETE unswept session in
        // Liquidating/Closed unwinds via the abort clause above (Ceremonia #42);
        // Paused waits for unpause (transient); Restructuring is rejected above.
        // A COMMITTED session (legs already swept) in a non-Active vault still
        // lands here and reverts — that residual (OT-1/OT-2) needs the session
        // counter and goes to the #43.
        require!(guard.status == 0u8, WagonError::VaultPaused);
    }

    // Ceremonia #50 (S-1): el barrido de COMMIT (primer settle, `legs_swept == 0`
    // en dirección settle) es el punto de no retorno y donde re-marcamos el precio
    // a mercado vivo (más abajo). `session.legs_swept` aquí es el valor PRE-batch.
    let is_commit = !abort_direction && session.legs_swept == 0;

    // ---- Session PDA signer seeds ------------------------------------------
    let vault_key = ctx.accounts.vault.key();
    let session_key = session.key();
    let investor_pk = session.investor;
    let session_ai = ctx.accounts.deposit_session.to_account_info();
    let investor_ai = ctx.accounts.investor.to_account_info();
    let session_bump_arr = [session.bump];
    let seeds: &[&[u8]] = &[
        DEPOSIT_SESSION_SEED,
        vault_key.as_ref(),
        investor_pk.as_ref(),
        &session_bump_arr,
    ];
    let signer_seeds: &[&[&[u8]]] = &[seeds];

    // ---- Walk the [mint, escrow, dest] triples ------------------------------
    let remaining = ctx.remaining_accounts;
    let triples_len = 3 * args.leg_indices.len();
    require!(remaining.len() >= triples_len, WagonError::InvalidJupiterRoute);
    // Ceremonia #50 (S-1): en el barrido de COMMIT con m2m enforcement ON se
    // RE-MARCA el precio a mercado vivo, y para eso el caller enhebra cuentas EXTRA
    // tras los triples (vault_usdc_ata + grupo de oráculo). Fail-closed: con m2m ON
    // el oráculo es OBLIGATORIO (el `require` del bloque de re-precio de más abajo),
    // si no el fallback congelado reabriría S-1. Cuando NO se re-marca, cualquier
    // cuenta tras los 3n triples se IGNORA (el bucle solo usa las 3n primeras) → el
    // frontend puede enhebrar el oráculo sin romper los barridos no-commit / abort.
    let reprice = is_commit && ctx.accounts.protocol.m2m_enforced != 0;

    let legs_completed = session.legs_completed;
    let trivial_mask = session.trivial_mask;
    let legs_swept = session.legs_swept;
    let leg_count = session.leg_count;
    let leg_mints = session.leg_mints;

    // ---- Ceremonia #50 (S-1): re-precio M2M en el COMMIT (PRE-transferencia) ----
    // Se calcula ANTES del bucle de transferencia: las ATAs del vault todavía NO
    // tienen los tokens de esta sesión, así que el M2M es la valoración
    // pre-depósito limpia. Sobrescribe la foto de la sesión más abajo (antes del
    // phantom_shares del incremento) -> el precio deja de estar congelado del init
    // -> la opción gratuita init->commit se colapsa. deposit_settle sigue puro.
    // Layout de remaining aquí: triples | vault_usdc_ata | (grupo de oráculo EXACTO
    // que exige compute_tvl_m2m_strict: registry · (ata,price)×k · [SOL]?).
    // Una sesión con restructure entre init y commit es `stale` -> abort_direction
    // -> NO llega aquí, así que la cesta del vault == la de la sesión (m2m coherente).
    let repriced: Option<(u64, u64)> = if reprice {
        require!(remaining.len() > triples_len, WagonError::MissingPriceAccounts);
        let vault_usdc_ai = &remaining[triples_len];
        let usdc_mint_pk = ctx.accounts.protocol.usdc_mint;
        let pinned_usdc_ata = {
            let data = vault_ai.try_borrow_data()?;
            vlayout::read_usdc_ata(&data)?
        };
        require_keys_eq!(
            vault_usdc_ai.key(),
            pinned_usdc_ata,
            WagonError::InvalidJupiterRoute
        );
        verify_token_account(vault_usdc_ai, &usdc_mint_pk, &vault_key)?;
        let idle_usdc = read_token_amount(vault_usdc_ai)?;
        let m2m = crate::pricing::compute_tvl_m2m_strict(
            &vault_ai,
            &vault_key,
            idle_usdc,
            &usdc_mint_pk,
            &remaining[triples_len + 1..],
        )?;
        let ts_live = {
            let data = vault_ai.try_borrow_data()?;
            vlayout::read_total_shares(&data)?
        };
        Some((m2m, ts_live))
    } else {
        None
    };

    let mut new_swept: u16 = 0;
    for (pos, &leg_idx) in args.leg_indices.iter().enumerate() {
        require!(
            (leg_idx as usize) < (leg_count as usize),
            WagonError::LegIndexOutOfRange
        );
        let bit = 1u16 << leg_idx;
        // Sweepable = swap executed, not a trivial (USDC / zero-weight) leg,
        // not already swept (including within this same batch).
        require!((legs_completed & bit) != 0, WagonError::LegNotSweepable);
        require!((trivial_mask & bit) == 0, WagonError::LegNotSweepable);
        require!(
            (legs_swept & bit) == 0 && (new_swept & bit) == 0,
            WagonError::LegNotSweepable
        );

        let mint_ai = &remaining[3 * pos];
        let escrow_ai = &remaining[3 * pos + 1];
        let dest_ai = &remaining[3 * pos + 2];

        // Mint binding comes from the session's init-time snapshot.
        let leg_mint = leg_mints[leg_idx as usize];
        require_keys_eq!(mint_ai.key(), leg_mint, WagonError::AllocMintMismatch);

        // Escrow: canonical ATA of (session, mint) on the mint's live
        // token program.
        let token_prog_id = *mint_ai.owner;
        require_keys_eq!(
            escrow_ai.key(),
            derive_live_ata(&session_key, &leg_mint, &token_prog_id),
            WagonError::EscrowAtaMismatch
        );
        verify_token_account(escrow_ai, &leg_mint, &session_key)?;

        // Destination: vault ATA (settle) or investor ATA (abort), always
        // the canonical derivation — no caller-chosen destinations.
        let expected_owner = if abort_direction { investor_pk } else { vault_key };
        require_keys_eq!(
            dest_ai.key(),
            derive_live_ata(&expected_owner, &leg_mint, &token_prog_id),
            WagonError::LegDestAtaMismatch
        );
        verify_token_account(dest_ai, &leg_mint, &expected_owner)?;

        // Pick the right token program AccountInfo for the CPI.
        let prog_ai = if token_prog_id == spl_token::ID {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        };

        let amount = read_token_amount(escrow_ai)?;
        if amount > 0 {
            let decimals = read_mint_decimals(mint_ai)?;
            transfer_checked_signed(
                &prog_ai,
                escrow_ai,
                mint_ai,
                dest_ai,
                &session_ai,
                signer_seeds,
                amount,
                decimals,
            )?;
        }
        // Close the emptied escrow ATA; rent back to the investor.
        close_token_account_signed(&prog_ai, escrow_ai, &investor_ai, &session_ai, signer_seeds)?;

        new_swept |= bit;

        emit!(DepositEscrowSwept {
            vault: vault_key,
            investor: investor_pk,
            leg_index: leg_idx,
            amount,
            to_vault: !abort_direction,
        });
    }

    // ---- Persist ------------------------------------------------------------
    let session = &mut ctx.accounts.deposit_session;
    session.legs_swept |= new_swept;
    if abort_direction {
        session.aborting = 1;
    }
    // Ceremonia #50 (S-1): fijar la foto RE-MARCADA (calculada arriba, pre-
    // transferencia) ANTES del phantom_shares del incremento de abajo, para que la
    // reserva #44 y la acuñación del settle usen el precio de commit, no el de init.
    if let Some((m2m, ts_live)) = repriced {
        session.tvl_before = m2m;
        session.total_shares_before = ts_live;
    }

    // ---- Ceremonia #43: contador de depósitos COMPROMETIDOS -----------------
    // Incrementa en la transición `legs_swept 0→≠0` en dirección SETTLE: el
    // instante EXACTO en que este depósito pasa a estar DENTRO del vault sin
    // acuñar (comprometido). `legs_swept` (local, arriba) es el valor PRE-batch,
    // así que N barridos de la misma sesión incrementan UNA sola vez. Un barrido
    // en dirección ABORTO también pone `legs_swept != 0` pero NO compromete valor
    // al vault → excluido por `!abort_direction`. saturating_add: nunca envuelve a
    // 0 (falla-CERRADO). Lo drena `deposit_settle` (decremento) — ver vault_layout.
    if !abort_direction && legs_swept == 0 && new_swept != 0 {
        let mut data = vault_ai.try_borrow_mut_data()?;
        // Ceremonia #50 (S-1): persistir el m2m re-marcado en el vault (coherencia
        // con deposit_init:261). `repriced` es Some sii m2m enforcement está ON.
        if let Some((m2m, _)) = repriced {
            vlayout::write_tvl_last_computed_usdc(&mut data, m2m)?;
        }
        let cur = vlayout::read_committed_deposits(&data)?;
        vlayout::write_committed_deposits(&mut data, cur.saturating_add(1))?;

        // ---- Ceremonia #44: reserva de participaciones fantasma (F3) --------
        // Reserva las participaciones que este depósito comprometido va a recibir
        // al asentar, para que un retiro concurrente en la ventana no reparta su
        // valor: `withdraw_init` las SUMA a su denominador. `checked_add` (NO
        // saturating): clampar `pending` a u64::MAX inflaría el denominador del
        // retiro y ESTRANGULARÍA la salida (regla sellada); falla-CERRADO
        // revirtiendo ESTE barrido (permissionless, reintentable, tokens a salvo
        // en el escrow), jamás el retiro. Emparejado en `deposit_settle` con el
        // MISMO `phantom_shares()` sobre los mismos campos inmutables de la
        // sesión → sube/baja cuadra exacto. Overflow inalcanzable (~$1,8e13).
        let p = vlayout::phantom_shares(
            session.amount_usdc,
            session.total_shares_before,
            session.tvl_before,
        );
        let cur_pending = vlayout::read_pending_committed_shares(&data)?;
        vlayout::write_pending_committed_shares(
            &mut data,
            cur_pending.checked_add(p).ok_or(WagonError::MathOverflow)?,
        )?;
    }

    Ok(())
}
