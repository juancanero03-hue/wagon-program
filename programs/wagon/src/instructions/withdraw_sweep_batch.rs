//! `withdraw_sweep_batch` — C2 (ceremonia #38): drains the withdraw session's
//! per-token escrow ATAs, 1-4 legs per call, always back TO THE VAULT (the
//! mirror of `deposit_sweep_batch`, but with a single destination):
//!
//! - **Settle direction** (session complete, fresh): every non-trivial leg was
//!   sold, so its escrow is empty — the sweep just closes it (rent → investor).
//!   PERMISSIONLESS: once the swaps ran, finishing only benefits the investor,
//!   so anyone (frontend, crank, us) can drive an abandoned-but-complete
//!   session to closure ahead of `withdraw_settle`.
//!
//! - **Abort direction** (incomplete, stale, or already `aborting`): the
//!   unsold escrows are still funded, so the sweep RETURNS the tokens to the
//!   vault and closes the escrow. Sets `session.aborting`, which permanently
//!   blocks the swap/settle paths. The investor any time; ANYONE after
//!   `WITHDRAW_SESSION_TIMEOUT_SECS` (30 min) — the orphan-session guarantee.
//!   `withdraw_abort` then re-mints the shares (deshacer-total).
//!
//! Either way each swept escrow is emptied and closed, rent → investor. The
//! direction is decided ON-CHAIN from session + vault state — the caller only
//! supplies accounts. The destination is ALWAYS the vault's canonical ATA for
//! the mint (both directions): on a withdraw the investor exits to USDC, not
//! tokens, so escrowed tokens belong back in the vault.
//!
//! # remaining_accounts layout
//!
//! For each leg in `leg_indices`: `[mint, escrow_ata, vault_ata]`.
//! `mint` must match the session's `leg_mints` snapshot (NOT the live vault
//! table); `escrow_ata` the canonical ATA of (session, mint); `vault_ata` the
//! canonical ATA of (vault, mint).

use anchor_lang::prelude::*;
use anchor_spl::token::{spl_token, Token};

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::WithdrawEscrowSwept;
use crate::state::vault_layout as vlayout;
use crate::state::withdraw_session::WITHDRAW_SESSION_TIMEOUT_SECS;
use crate::state::WithdrawSession;
use crate::token_io::{
    close_token_account_signed, derive_live_ata, read_mint_decimals, read_token_amount,
    transfer_checked_signed, verify_token_account, TOKEN_2022_PROGRAM_ID,
};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct WithdrawSweepBatchArgs {
    pub leg_indices: Vec<u8>,
}

#[derive(Accounts)]
pub struct WithdrawSweepBatch<'info> {
    /// Settle direction: anyone. Abort direction: the investor, or anyone after
    /// the 30-minute timeout. Pays the tx fee; never receives funds.
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: pinned to `session.investor` via has_one. Receives the rent of
    /// every escrow ATA closed in this batch (they paid to create them).
    #[account(mut)]
    pub investor: UncheckedAccount<'info>,

    /// CHECK: PDA seeds + owner verified manually (VaultGuard).
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [
            WITHDRAW_SESSION_SEED,
            vault.key().as_ref(),
            investor.key().as_ref(),
        ],
        bump = withdraw_session.bump,
        has_one = investor @ WagonError::WithdrawSessionWrongInvestor,
        has_one = vault @ WagonError::WithdrawSessionWrongVault,
    )]
    pub withdraw_session: Box<Account<'info, WithdrawSession>>,

    pub token_program: Program<'info, Token>,

    /// CHECK: pubkey verified == Token-2022 program id. Used for legs whose
    /// mint lives on Token-2022 (xStocks, MetaDAO); ignored otherwise.
    pub token_program_2022: UncheckedAccount<'info>,
}

pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, WithdrawSweepBatch<'info>>,
    args: WithdrawSweepBatchArgs,
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

    // ---- Vault guard (owner + PDA derivation; status read) -----------------
    let vault_ai = ctx.accounts.vault.to_account_info();
    let guard = crate::guards::VaultGuard::load(
        &vault_ai,
        &ctx.accounts.vault.key(),
        WagonError::VaultClosed,
    )?;
    // Never move tokens into the vault while a restructure is selling the
    // outgoing set — it would corrupt the restructure's dust check. Blocks both
    // directions transiently; the restructure is bounded (30-min abort).
    require!(guard.status != 4u8, WagonError::RestructuringInProgress);

    let session = &ctx.accounts.withdraw_session;
    let now = Clock::get()?.unix_timestamp;

    // ---- P3 (C-B): una sesión COMPROMETIDA (sold=1) e INCOMPLETA no puede barrer
    // — debe completarse antes (vendiendo el resto o cobrándolo en especie). Esto
    // sostiene el Lema 1 (con sold=1 nunca se alcanza aborting=1, así que el abort
    // queda vetado) e IMPIDE la ruta swap→sweep-abort que era el corazón de C-B.
    // El desacople del stale (P7) deja el abort_direction limpio.
    require!(
        session.sold == 0 || session.is_complete(),
        WagonError::SessionNotComplete
    );

    // ---- Decide the direction ON-CHAIN -------------------------------------
    let abort_direction = session.aborting == 1 || !session.is_complete();
    if abort_direction {
        let timed_out = now.saturating_sub(session.created_at) > WITHDRAW_SESSION_TIMEOUT_SECS;
        require!(
            ctx.accounts.caller.key() == session.investor || timed_out,
            WagonError::WithdrawAbortTooEarly
        );
    }

    // ---- Session PDA signer seeds ------------------------------------------
    let vault_key = ctx.accounts.vault.key();
    let session_key = session.key();
    let investor_pk = session.investor;
    let session_ai = ctx.accounts.withdraw_session.to_account_info();
    let investor_ai = ctx.accounts.investor.to_account_info();
    let session_bump_arr = [session.bump];
    let seeds: &[&[u8]] = &[
        WITHDRAW_SESSION_SEED,
        vault_key.as_ref(),
        investor_pk.as_ref(),
        &session_bump_arr,
    ];
    let signer_seeds: &[&[&[u8]]] = &[seeds];

    // ---- Walk the [mint, escrow, vault_ata] triples ------------------------
    let remaining = ctx.remaining_accounts;
    require!(
        remaining.len() == 3 * args.leg_indices.len(),
        WagonError::InvalidJupiterRoute
    );

    let sweepable_mask = session.sweepable_mask();
    let legs_swept = session.legs_swept;
    let leg_count = session.leg_count;
    let leg_mints = session.leg_mints;
    // Ceremonia #49 (A1): valor OLD de `aborting` (para detectar la transición 0→1
    // ANTES de mutarlo abajo) y las shares quemadas de esta sesión (monto de la
    // reserva). Ambos inmutables durante el barrido.
    let was_aborting = session.aborting;
    let shares_to_burn = session.shares_to_burn;

    let mut new_swept: u16 = 0;
    // Ceremonia #53 (Fix 4): patas barridas con saldo REAL > 0 (las únicas que pueden
    // dejar valor fuera de tabla). El land-and-mark de abajo solo mira estas para no
    // cuarentenar la ENTRADA por una pata sin valor (falsa cuarentena / griefing).
    let mut new_swept_funded: u16 = 0;
    for (pos, &leg_idx) in args.leg_indices.iter().enumerate() {
        require!(
            (leg_idx as usize) < (leg_count as usize),
            WagonError::LegIndexOutOfRange
        );
        let bit = 1u16 << leg_idx;
        // Sweepable = a non-trivial leg (has a token escrow), not already swept
        // (including within this same batch). Independent of `legs_completed`
        // in withdraw: every non-trivial leg is funded at init, so both an
        // unsold (abort) and a sold (settle) leg are sweepable.
        require!((sweepable_mask & bit) != 0, WagonError::LegNotSweepable);
        require!(
            (legs_swept & bit) == 0 && (new_swept & bit) == 0,
            WagonError::LegNotSweepable
        );

        let mint_ai = &remaining[3 * pos];
        let escrow_ai = &remaining[3 * pos + 1];
        let vault_ata_ai = &remaining[3 * pos + 2];

        // Mint binding from the session's init-time snapshot.
        let leg_mint = leg_mints[leg_idx as usize];
        require_keys_eq!(mint_ai.key(), leg_mint, WagonError::AllocMintMismatch);

        let token_prog_id = *mint_ai.owner;
        require_keys_eq!(
            escrow_ai.key(),
            derive_live_ata(&session_key, &leg_mint, &token_prog_id),
            WagonError::EscrowAtaMismatch
        );
        verify_token_account(escrow_ai, &leg_mint, &session_key)?;

        // Destination: always the vault's canonical ATA (both directions).
        require_keys_eq!(
            vault_ata_ai.key(),
            derive_live_ata(&vault_key, &leg_mint, &token_prog_id),
            WagonError::LegDestAtaMismatch
        );
        verify_token_account(vault_ata_ai, &leg_mint, &vault_key)?;

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
                vault_ata_ai,
                &session_ai,
                signer_seeds,
                amount,
                decimals,
            )?;
            new_swept_funded |= bit; // Ceremonia #53: solo esta pata movió valor real.
        }
        // Close the emptied escrow ATA; rent back to the investor.
        close_token_account_signed(&prog_ai, escrow_ai, &investor_ai, &session_ai, signer_seeds)?;

        new_swept |= bit;

        emit!(WithdrawEscrowSwept {
            vault: vault_key,
            investor: investor_pk,
            leg_index: leg_idx,
            amount,
            aborting: abort_direction,
        });
    }

    // ---- Persist ------------------------------------------------------------
    let session = &mut ctx.accounts.withdraw_session;
    session.legs_swept |= new_swept;
    if abort_direction {
        session.aborting = 1;
    }

    // ---- Ceremonia #49 (A1): reserva de participaciones QUEMADAS -------------
    // SOLO en la transición `aborting 0→1` (`was_aborting` es el valor PRE-batch →
    // N barridos de abort de la misma sesión reservan UNA sola vez). Es el instante
    // en que los tokens del retiro empiezan a volver al vault mientras sus shares
    // siguen quemadas: `withdraw_init` SUMA este contador al denominador de sus
    // patas de token para que un retiro CONCURRENTE no sobre-extraiga en la ventana.
    // Se DECREMENTA en `withdraw_abort` (guardado por `aborting==1`) con el MISMO
    // `shares_to_burn` → el par cuadra exacto. checked_add (NO saturating): clampar
    // inflaría el denominador del retiro y ESTRANGULARÍA la salida (regla sellada);
    // falla-CERRADO revirtiendo ESTE barrido de abort (permissionless, reintentable,
    // tokens a salvo), jamás un retiro. Overflow inalcanzable (shares_to_burn ≤
    // total_shares ≤ u64::MAX). El vault ya es `#[account(mut)]` → sin cambio de IDL.
    if abort_direction && was_aborting == 0 {
        let mut data = vault_ai.try_borrow_mut_data()?;
        let cur = vlayout::read_pending_burned_shares(&data)?;
        vlayout::write_pending_burned_shares(
            &mut data,
            cur.checked_add(shares_to_burn)
                .ok_or(WagonError::MathOverflow)?,
        )?;
    }

    // ---- Ceremonia #53 (P2-4): land-and-mark --------------------------------
    // Si en dirección abort se ha devuelto al vault el escrow de un mint que YA NO está
    // en la tabla viva (un restructure lo eliminó mientras la sesión estaba abierta),
    // ese valor queda FUERA DE TABLA. NO se VETA el barrido (vetarlo estrangularía un
    // abort multi-lote: con la eliminación entre lotes, el 2º revertiría para siempre y
    // congelaría el escrow del inversor). Se deja aterrizar (recuperable, como hoy) y se
    // MARCA el vault para bloquear la ENTRADA hasta rescatarlo. Solo desde Active(0)/
    // Paused(1): en Liquidating(2)/Closed(3) no hay depósitos (sin dilución) y marcar
    // interferiría con finalize_close/sweep_to_usdc. USDC nunca queda fuera de tabla.
    // SIN `require`/revert → la SALIDA procede idéntica (withdraw_abort re-acuña completo,
    // sin doble pago). Se evalúa CADA barrido (el strand puede caer en cualquier lote, no
    // solo en la transición aborting 0→1). Borrow: read y write en scopes separados, tras
    // soltar el mut del bloque pending_burned. Sin manifiesto → se limpia con
    // admin_clear_stranded (authority; el retiro no deja una RestructureSession).
    if abort_direction && (guard.status == 0u8 || guard.status == 1u8) {
        let stranded_here = {
            let data = vault_ai.try_borrow_data()?;
            let mut found = false;
            for leg_idx in 0..(leg_count as usize) {
                // Fix 4: solo patas con saldo REAL movido (new_swept_funded), no las
                // barridas a 0 (evita cuarentena en falso por una pata sin valor).
                if (new_swept_funded >> leg_idx) & 1 == 0 {
                    continue;
                }
                let m = leg_mints[leg_idx];
                if m == USDC_MINT {
                    continue;
                }
                if !vlayout::mint_in_allocations(&data, &m)? {
                    found = true;
                    break;
                }
            }
            found
        };
        if stranded_here {
            {
                // Ceremonia #53 (Fix 2): el strand del lado RETIRO marca el estado 2
                // (P2-4), NO 1. La bandera es de DOS estados: 1 = solo P2-3 (con
                // manifiesto, limpiable por `close_stranded` permissionless por
                // identidad); 2 = hay valor P2-4 sin manifiesto (o mezclado sobre un P2-3)
                // → solo `admin_clear_stranded` (authority) reabre. Escribir 2 sobre un 1
                // vivo INVALIDA a propósito la vía permissionless: `close_stranded` exige
                // ==1, así que un P2-4 concurrente sobre un manifiesto P2-3 fuerza la
                // firma de Squads. Cierra la coexistencia P2-4-sobre-P2-3 (la premisa de
                // «mutuamente excluyentes» era falsa: la eliminación del mint pudo ocurrir
                // con la bandera a 0, antes del strand P2-3). Ambos estados vetan la ENTRADA.
                let mut data = vault_ai.try_borrow_mut_data()?;
                vlayout::write_stranded_flag(&mut data, 2)?;
            }
            emit!(crate::events::StrandedValueQuarantined {
                vault: vault_key,
                caller: ctx.accounts.caller.key(),
                producer: 1,
            });
        }
    }

    Ok(())
}
