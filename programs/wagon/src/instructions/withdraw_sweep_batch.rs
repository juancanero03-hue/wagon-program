//! `withdraw_sweep_batch` — C2 (ceremonia #38): drains the withdraw session's
//! per-token escrow ATAs, 1-7 legs per call (G3-B1a: `MAX_WITHDRAW_SWEEP_LEGS_PER_BATCH`,
//! la cesta máxima), always back TO THE VAULT (the
//! mirror of `deposit_sweep_batch`, but with a single destination):
//!
//! - **Settle direction** (session complete, fresh): every non-trivial leg was
//!   sold, so its escrow is empty — the sweep just closes it (rent → session PDA).
//!   PERMISSIONLESS: once the swaps ran, finishing only benefits the investor,
//!   so anyone (frontend, crank, us) can drive an abandoned-but-complete
//!   session to closure ahead of `withdraw_settle`.
//!
//! - **Abort direction** (incomplete, stale, or already `aborting`): the
//!   unsold escrows are still funded, so the sweep RETURNS the tokens to the
//!   vault and closes the escrow. Sets `session.aborting`, which permanently
//!   blocks the swap/settle paths. The investor any time; a THIRD PARTY only
//!   after `WITHDRAW_ORPHAN_ABORT_SECS` (48h, DT-C #54), or after
//!   `WITHDRAW_ABORT_FINISH_SECS` (10 min) once the session is already
//!   cancelling (`aborting == 1`, G3) — nested above the
//!   in-kind window (24h) so a griefer cannot latch `aborting=1` and kill the
//!   investor's in-kind claim. `withdraw_abort` then re-mints the shares.
//!   G3-B1a (F2B-01): el barrido que EMPIEZA la cancelación (`aborting` 0 → 1)
//!   tiene que traer TODAS las patas pendientes en UNA instrucción (6221 si
//!   falta alguna): con la ATA del vault de una pata congelada la transacción
//!   entera revierte y nada latchea, así que la vía en especie sigue abierta.
//!   Con `aborting` ya puesto, los lotes parciales siguen valiendo.
//!   G5 (auditoría Codex F-02 = #51 h.13/h.15): ese mismo barrido devuelve también al vault el USDC de la hucha de la
//!   sesión, así que la reserva entera `pending_burned` entra a la vez que todo lo que la sesión había sacado.
//!
//! Either way each swept escrow is emptied and closed; since §3.3 (D1, B2) its
//! rent lands on the session PDA and leaves with the terminal, sponsor-aware. The
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
use anchor_spl::token::{self, spl_token, Token, Transfer};

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::WithdrawEscrowSwept;
use crate::state::vault_layout as vlayout;
use crate::state::{ProtocolConfig, WithdrawSession};
use crate::token_io::{
    close_token_account_signed, derive_live_ata, is_payable_usdc_ata, read_mint_decimals, read_token_amount,
    read_token_state, transfer_checked_signed, verify_token_account, TOKEN_2022_PROGRAM_ID, TOKEN_STATE_FROZEN,
};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct WithdrawSweepBatchArgs {
    pub leg_indices: Vec<u8>,
}

#[derive(Accounts)]
pub struct WithdrawSweepBatch<'info> {
    /// Settle direction: anyone. Abort direction: the investor any time, or a
    /// third party only after `WITHDRAW_ORPHAN_ABORT_SECS` (48h, DT-C #54), or
    /// after `WITHDRAW_ABORT_FINISH_SECS` (10 min) once the session is already
    /// cancelling (G3). Pays the tx fee; never receives funds.
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: pinned to `session.investor` via has_one. Since §3.3 (D1, B2) the
    /// rent of every escrow closed here lands on the SESSION PDA and leaves with
    /// the terminal (to whoever funded it); the investor receives nothing in this
    /// ix. Stays `mut` so the account shape the clients already thread is unchanged.
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

    /// G5 (F-02): da `usdc_mint` para atar la hucha USDC de la sesión.
    #[account(seeds = [PROTOCOL_SEED], bump = protocol.bump)]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// G5 (F-02): la hucha USDC de la sesión; el barrido que EMPIEZA la cancelación devuelve su USDC al vault.
    /// CHECK: atada en todo barrido a la derivación canónica (sesión, USDC); en ese barrido, además `verify_token_account`.
    #[account(mut)]
    pub session_usdc_escrow: UncheckedAccount<'info>,

    /// G5 (F-02): la ATA USDC del vault, destino de ese USDC.
    /// CHECK: atada en todo barrido a la clave pinneada en el VaultState.
    #[account(mut)]
    pub vault_usdc_ata: UncheckedAccount<'info>,
}

pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, WithdrawSweepBatch<'info>>,
    args: WithdrawSweepBatchArgs,
) -> Result<()> {
    // ---- Validate batch shape ----------------------------------------------
    require!(!args.leg_indices.is_empty(), WagonError::EmptyBatch);
    // G3-B1a (F2B-01): tope propio del retiro (7, la cesta máxima): el barrido que EMPIEZA una cancelación
    // trae todas las patas pendientes en una instrucción (abajo), así que una cesta entera tiene que caber.
    require!(
        args.leg_indices.len() <= MAX_WITHDRAW_SWEEP_LEGS_PER_BATCH as usize,
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
    // G5 (F-02, revisión N3): las dos cuentas USDC se atan en TODO barrido, aunque solo las use el que empieza la cancelación:
    // una sola forma válida de transacción para el cliente.
    bind_usdc_accounts(
        &vault_ai,
        &ctx.accounts.vault_usdc_ata.to_account_info(),
        &ctx.accounts.session_usdc_escrow.to_account_info(),
        &ctx.accounts.withdraw_session.key(),
        &ctx.accounts.protocol.usdc_mint,
    )?;

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
        // G1 (2026-10-09): el forfeit del park es DEFINITIVO de punta a punta. Sin este veto, una
        // sesión con `had_park == 1` e INCOMPLETA se barría en dirección abort (aborting = 1,
        // pending_burned += shares) y después no tenía terminal: el abort la veta (6217) y settle,
        // venta y cobro en especie exigen aborting == 0 → shares quemadas para siempre y
        // pending_burned inflado. Una sesión aparcada solo vende, cobra en especie a las 24 h o
        // asienta (`committed()`).
        require!(session.had_park == 0, WagonError::WithdrawParkedCannotAbort);
        // G1 (transición): una sesión ANTERIOR al upgrade (generation == 0) no puede EMPEZAR una
        // cancelación (re-acuñaría sin que la entrada la viera); solo CONTINÚA una ya empezada
        // (aborting == 1, reservada en pending_burned, que la entrada también mira).
        // Los tres vetos (6172 arriba vía P3, 6217 y 6218) son exactamente `!session.can_abort()`.
        require!(
            session.generation != 0 || session.aborting == 1,
            WagonError::LegacyWithdrawCannotAbort
        );
        // DT-C (#54): relojes ANIDADOS. Un TERCERO solo puede latchear el abort de
        // una sesión huérfana ESTRICTAMENTE por encima de la ventana en especie
        // (WITHDRAW_ORPHAN_ABORT_SECS = 48h > WITHDRAW_INKIND_TIMEOUT_SECS = 24h).
        // Entre 24h y 48h SOLO el inversor actúa; si un tercero pudiera abortar
        // antes, aborting=1 vetaría su cobro en especie (withdraw_claim_leg_in_kind)
        // = griefing del backstop de liveness. El inversor: cualquier hora.
        // G3 (F2B-03): `withdraw_abort` aplica este MISMO predicado (`WithdrawSession::abort_authorized`):
        // un solo reloj para cancelar, en las dos instrucciones.
        require!(
            session.abort_authorized(ctx.accounts.caller.key() == session.investor, now),
            WagonError::WithdrawAbortTooEarly
        );
    }

    // ---- Session PDA signer seeds ------------------------------------------
    let vault_key = ctx.accounts.vault.key();
    let session_key = session.key();
    let investor_pk = session.investor;
    let session_ai = ctx.accounts.withdraw_session.to_account_info();
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
        // Close the emptied escrow ATA; its rent lands on the session PDA (D1,
        // §3.3, B2) so the terminal can refund whoever funded it (sponsor-aware).
        close_token_account_signed(&prog_ai, escrow_ai, &session_ai, &session_ai, signer_seeds)?;

        new_swept |= bit;

        emit!(WithdrawEscrowSwept {
            vault: vault_key,
            investor: investor_pk,
            leg_index: leg_idx,
            amount,
            aborting: abort_direction,
        });
    }

    // ---- G3-B1a (F2B-01): el LATCH de la cancelación es ATÓMICO --------------
    // Solo en la transición `aborting 0→1`: este lote tiene que dejar barridas TODAS las patas barribles
    // (`WithdrawSession::abort_latch_complete`, predicado puro con su tabla de verdad). Con lotes parciales, el
    // primero latcheaba y reservaba `pending_burned` y, si la ATA del vault de una pata de los siguientes estaba
    // congelada, el segundo no pasaba nunca: sesión cancelando para siempre, sin cobro en especie (vetado por
    // `aborting`) ni abort (nunca `fully_swept()`). Así, si alguna ATA del vault no puede recibir, la transferencia
    // de arriba revierte la transacción ENTERA y nada latchea: la vía en especie (24 h) sigue abierta. Con
    // `aborting` ya puesto los lotes siguen como siempre (sesiones del #55 en vuelo). Se comprueba tras el bucle
    // (ya se sabe `new_swept` exacto); una tx que revierte no deja nada a medias.
    if abort_direction && was_aborting == 0 {
        require!(
            session.abort_latch_complete(new_swept),
            WagonError::WithdrawAbortSweepMustCoverAllLegs
        );
    }

    // ---- G5 (auditoría Codex F-02 = #51 h.13/h.15): el LATCH devuelve también el USDC -------------------------------
    // En la misma transición `aborting 0→1` (la que reserva `pending_burned`, abajo) vuelve al vault, además de las patas,
    // el USDC de la hucha de la sesión (el slice ocioso que se llevó el init; con `sold == 0` no hay ventas): la reserva
    // entera entra a la vez que TODO lo que la sesión había sacado. `withdraw_abort` re-acuña y cierra la hucha, ya vacía.
    // Con la hucha congelada, o si la ATA USDC del vault no puede recibir, el USDC se queda en ella y sigue el camino de
    // G3-B1a (abort aplazado y `withdraw_escrow_sweep`): el latch nunca revierte por una cuenta USDC. Las sesiones que ya
    // cancelaban antes del upgrade lo devuelven en su abort, como entonces.
    if abort_direction && was_aborting == 0 {
        return_latch_usdc(
            &ctx.accounts.token_program.to_account_info(),
            &ctx.accounts.session_usdc_escrow.to_account_info(),
            &ctx.accounts.vault_usdc_ata.to_account_info(),
            &session_ai,
            signer_seeds,
            &session_key,
            &ctx.accounts.protocol.usdc_mint,
        )?;
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
                // Ceremonia #53 (Fix 2): el strand del lado RETIRO marca el estado 2, NO 1:
                // 1 = valor fuera de tabla con manifiesto (lo limpia `close_stranded`,
                // permissionless, por identidad); 2 = hay valor sin manifiesto, solo o
                // sobre un 1 (lo limpia `admin_clear_stranded`). Escribir 2 sobre un 1 vivo
                // invalida a propósito la vía permissionless (`close_stranded` exige ==1).
                // Ambos estados vetan la ENTRADA.
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

/// G5 (F-02, revisión N3): ata las dos cuentas USDC del barrido: la del vault, a la pinneada en el VaultState; la hucha, a la
/// derivación canónica (sesión de retiro, USDC). En todo barrido, aunque solo las use el que empieza la cancelación.
#[inline(never)]
fn bind_usdc_accounts<'info>(
    vault_ai: &AccountInfo<'info>,
    vault_usdc: &AccountInfo<'info>,
    hucha: &AccountInfo<'info>,
    session_key: &Pubkey,
    usdc_mint: &Pubkey,
) -> Result<()> {
    let pinned_usdc_ata = {
        let data = vault_ai.try_borrow_data()?;
        vlayout::read_usdc_ata(&data)?
    };
    require_keys_eq!(vault_usdc.key(), pinned_usdc_ata, WagonError::InvalidJupiterRoute);
    require_keys_eq!(
        hucha.key(),
        derive_live_ata(session_key, usdc_mint, &spl_token::ID),
        WagonError::EscrowAtaMismatch
    );
    Ok(())
}

/// G5 (F-02): devuelve a la ATA USDC del vault TODO el USDC de la hucha de la sesión que empieza a cancelar (con `sold == 0`
/// es USDC del vault: el slice ocioso del init y, si lo hay, el residuo heredado). Las dos cuentas ya las ató
/// `bind_usdc_accounts`. No mueve nada si la hucha no existe o está congelada, o si la ATA del vault no puede recibir: queda
/// para el abort aplazado de G3-B1a. Va en su propia función (`inline(never)`, con su marco de pila), como en el depósito.
#[inline(never)]
fn return_latch_usdc<'info>(
    token_program: &AccountInfo<'info>,
    hucha: &AccountInfo<'info>,
    vault_usdc: &AccountInfo<'info>,
    session_ai: &AccountInfo<'info>,
    signer_seeds: &[&[&[u8]]],
    session_key: &Pubkey,
    usdc_mint: &Pubkey,
) -> Result<()> {
    if hucha.data_is_empty() {
        return Ok(());
    }
    verify_token_account(hucha, usdc_mint, session_key)?;
    let en_hucha = read_token_amount(hucha)?;
    let movible = read_token_state(hucha)? != TOKEN_STATE_FROZEN && is_payable_usdc_ata(vault_usdc, usdc_mint, None);
    if en_hucha == 0 || !movible {
        return Ok(());
    }
    token::transfer(
        CpiContext::new_with_signer(
            token_program.clone(),
            Transfer { from: hucha.clone(), to: vault_usdc.clone(), authority: session_ai.clone() },
            signer_seeds,
        ),
        en_hucha,
    )
}
