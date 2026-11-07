//! `withdraw_abort` — rollback / rescue of the fractional withdraw flow
//! (deshacer-total). C2 (ceremonia #38): with per-token escrows, cancelling a
//! withdraw is the exact mirror of `deposit_abort`:
//!
//!   1. `withdraw_sweep_batch` (abort direction) first returns every funded
//!      token escrow TO THE VAULT (the tokens the slice was moved to at init)
//!      and flags the session `aborting`, blocking the swap/settle paths.
//!   2. This instruction then re-mints the burned shares to the investor,
//!      restores `vault.total_shares` / the position, returns whatever USDC
//!      remains in the USDC escrow (idle slice + any partial-sale proceeds)
//!      TO THE VAULT (G5: normally nothing left, the abort-direction sweep that started the cancellation already
//!      returned it; it remains only when it could not move, or for sessions latched before the upgrade),
//!      and closes the USDC escrow + the session (rent →
//!      `refund_target`: the investor, or the sponsor's `refund_to` when a
//!      `FundingRecord` is paired, ceremonia USDC §3.3, B2).
//!      G3-B1a (F2B-01, caso (d) del diseño G3 §3): si ese USDC NO se puede
//!      devolver (hucha congelada o ATA USDC del vault no pagable), el abort NO
//!      revierte: re-acuña y cierra igual y deja el USDC en la hucha (abierta)
//!      como residuo del vault, que `withdraw_escrow_sweep` lleva al vault en
//!      cuanto se pueda mover (`WithdrawAbortDeferred`). Antes la sesión se
//!      quedaba cancelando para siempre.
//!
//! The investor is made whole via the re-minted shares; the vault keeps the
//! returned tokens + USDC (composition may drift after a partial sale, value
//! is conserved). This works even for a session invalidated by a mid-session
//! restructure (a stale session goes abort-direction) and for orphan cleanup.
//!
//! Authorization: the investor at any time; ANYONE after
//! `WITHDRAW_ORPHAN_ABORT_SECS` (48 h), or after `WITHDRAW_ABORT_FINISH_SECS`
//! (10 min) once the session is already cancelling (`aborting == 1`) — the SAME
//! predicate as the abort-direction sweep (`WithdrawSession::abort_authorized`,
//! G3 F2B-03), so a third party can never cancel a complete-but-unsold session
//! before the in-kind window closes, and can only FINISH a cancellation the
//! investor started.
//! Funds can only ever go to the investor (shares) or the vault.
//!
//! C-B (ceremonia #39): una sesión que ha EXTRAÍDO VALOR de una hucha
//! (`sold == 1`) — vendiendo (`withdraw_swap_batch`) o cobrando en especie
//! (`withdraw_claim_leg_in_kind`) — está COMPROMETIDA y solo puede ASENTAR,
//! nunca abortar (el abort re-acuñaría shares completas sobre valor ya pagado =
//! el ataque C-B). Lo hace real el gate `require!(session.sold == 0)` del
//! handler; antes este docstring afirmaba un "path-mixing guard" por
//! `legs_swept != 0` que NO estaba implementado, y ese hueco comentario↔código
//! ERA C-B.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, spl_token, CloseAccount, MintTo, Token, Transfer};

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::{FundingRefundPartial, WithdrawAbortDeferred, WithdrawAborted};
use crate::state::vault_layout as vlayout;
use crate::state::{ProtocolConfig, UserPosition, WithdrawSession, ESCROW_RENT_WITHDRAW_USDC_WAGON, FUNDING_KIND_WITHDRAW};
use crate::token_io::{is_payable_usdc_ata, read_token_state, verify_token_account, TOKEN_STATE_FROZEN};

#[derive(Accounts)]
pub struct WithdrawAbort<'info> {
    /// The investor any time; anyone after the timeout. Pays fees only.
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: pinned to `session.investor` via has_one. Receives the re-minted
    /// shares. The rent (USDC escrow + session) goes to `refund_target` (the
    /// investor unless the session is sponsored, §3.3).
    #[account(mut)]
    pub investor: UncheckedAccount<'info>,

    #[account(
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// CHECK: PDA seeds verified manually.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    /// CHECK: pubkey verified against `vault_layout::read_share_mint`.
    #[account(mut)]
    pub share_mint: UncheckedAccount<'info>,

    /// CHECK: SPL Token account, mint == share_mint, owner == investor.
    #[account(mut)]
    pub investor_share_ata: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [
            USER_POSITION_SEED,
            vault.key().as_ref(),
            investor.key().as_ref(),
        ],
        bump = user_position.bump,
    )]
    pub user_position: Box<Account<'info, UserPosition>>,

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
        close = refund_target,
    )]
    pub withdraw_session: Box<Account<'info, WithdrawSession>>,

    /// CHECK: C2 — la hucha USDC de la sesión (ATA canónica del PDA de sesión),
    /// verificada por derivación + verify_token_account. Su balance entero
    /// vuelve al vault en el abort y la cuenta se cierra (rent → PDA de sesión,
    /// D1, y de ahí a `refund_target`).
    #[account(mut)]
    pub session_usdc_escrow: UncheckedAccount<'info>,

    /// CHECK: pubkey verified against `vault_layout::read_usdc_ata`. Recibe de
    /// vuelta el USDC de la hucha.
    #[account(mut)]
    pub vault_usdc_ata: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,

    /// CHECK: Ceremonia USDC (§3.3, B2): registro de financiación de esta sesión en su PDA
    /// canónica (SIEMPRE esa dirección, nunca el centinela; verificada en el handler).
    /// Si existe y empareja se cierra aquí hacia `refund_target`; si la dirección está
    /// vacía es el camino legacy (rent al inversor). Al FINAL de las nombradas.
    #[account(mut)]
    pub funding_record: UncheckedAccount<'info>,

    /// CHECK: destino del saldo de la sesión y del registro: `refund_to` del registro
    /// emparejado (o `protocol.authority` como alternativo si firma el inversor o la propia
    /// authority, cinturón «la salida nunca se atasca», B2), o el inversor si no hay registro. Validado en el handler; si no es un
    /// destino admitido, la transacción entera revierte (`FundingRefundTargetMismatch`).
    #[account(mut)]
    pub refund_target: UncheckedAccount<'info>,
}

pub fn handler(ctx: Context<WithdrawAbort>) -> Result<()> {
    let session = &ctx.accounts.withdraw_session;

    // ---- Vault identity (any status — rescue works mid-liquidation too) ----
    let vault_ai = ctx.accounts.vault.to_account_info();
    let guard = crate::guards::VaultGuard::load(
        &vault_ai,
        &ctx.accounts.vault.key(),
        WagonError::VaultClosed,
    )?;
    let (creator, nonce, vault_bump) = (guard.creator, guard.nonce, guard.bump);
    let nonce_le = nonce.to_le_bytes();
    let (share_mint_pk, total_shares_now, usdc_ata_pk) = {
        let data = vault_ai.try_borrow_data()?;
        (
            vlayout::read_share_mint(&data)?,
            vlayout::read_total_shares(&data)?,
            vlayout::read_usdc_ata(&data)?,
        )
    };

    // ---- Authorization ------------------------------------------------------
    // G3 (F2B-03): el MISMO predicado que el barrido en dirección abort (`abort_authorized`: el inversor
    // a cualquier hora; un tercero pasadas 48 h). Antes esta puerta tenía un reloj propio de 30 min que
    // `fully_swept()` solo subsumía si quedaban huchas por barrer: una sesión completa sin vender ya
    // barrida en dirección settle por cualquiera (rincón I3) no las tenía.
    let now = Clock::get()?.unix_timestamp;
    require!(
        session.abort_authorized(ctx.accounts.caller.key() == session.investor, now),
        WagonError::WithdrawAbortTooEarly
    );

    // ---- Escrows must be fully handled before re-minting --------------------
    // Every token escrow must be swept + closed (via withdraw_sweep_batch)
    // before the abort re-mints the shares and returns the USDC escrow. Unlike
    // deposit, NO sweep direction "commits" a withdraw (both return to the
    // vault); the only commitment is the SETTLE, which closes the session and
    // therefore excludes the abort. So `fully_swept()` is the sole gate:
    //   - fresh / partial session (funded escrows): fully_swept() is false →
    //     the caller must run withdraw_sweep_batch (abort direction) first,
    //     which returns the funded slices → vault and sets `aborting`.
    //   - complete session swept in the SETTLE direction (empty escrows closed,
    //     `aborting` still 0) then made stale by a restructure: fully_swept()
    //     is true → this abort RESCUES it (re-mint + USDC escrow → vault).
    //     Without allowing this, that corner would deadlock — settle is
    //     stale-blocked and there is no path to `aborting==1` — stranding the
    //     burned shares + the escrowed USDC forever (I3). (Found by the C2
    //     adversarial review, 2026-07-14.)
    require!(session.fully_swept(), WagonError::EscrowNotSwept);
    // ---- P4 (C-B): EL FIX -------------------------------------------------
    // Una sesión que ha EXTRAÍDO VALOR de una hucha (sold==1: vendió o cobró en
    // especie) NO puede abortar — el abort re-acuñaría shares completas sobre
    // valor ya pagado (el ataque C-B). Su único terminal es SETTLE (permissionless
    // vía `committed`). SIN `|| stale`, SIN `|| status==4`, SIN escape por timeout
    // (las tres reabrirían C-B). El corner I3 de arriba solo aplica a sold==0.
    require!(session.sold == 0, WagonError::WithdrawAlreadySold);
    // G1 (2026-10-09, F7A-01/F7B-01): el forfeit del park es DEFINITIVO: una sesión que aparcó
    // una pata con saldo (o el ocioso congelado) no se deshace; su terminal es el settle (el
    // inversor cuando quiera, o cualquiera vía `committed`) o el cobro en especie a las 24 h.
    require!(session.had_park == 0, WagonError::WithdrawParkedCannotAbort);
    // G1 (transición): una sesión ANTERIOR al upgrade (generation == 0) no está en el contador
    // de la entrada; solo aborta si YA había empezado a cancelar antes (aborting == 1, reservada
    // en pending_burned, que la entrada también exige a 0). Una completa y barrida en dirección
    // settle (rincón I3) no puede re-acuñar sin que la entrada la haya visto: su terminal es el
    // settle (P7b: ya no se bloquea por stale) o el cobro en especie.
    // Los tres vetos (6172, 6217, 6218) son exactamente `!session.can_abort()`.
    require!(
        session.generation != 0 || session.aborting == 1,
        WagonError::LegacyWithdrawCannotAbort
    );

    // ---- Validate share mint + investor share ATA -------------------------
    require_keys_eq!(
        ctx.accounts.share_mint.key(),
        share_mint_pk,
        WagonError::InvalidJupiterRoute
    );
    require_keys_eq!(
        *ctx.accounts.share_mint.owner,
        spl_token::ID,
        WagonError::InvalidJupiterRoute
    );
    let investor_pk = ctx.accounts.investor.key();
    verify_token_account(
        &ctx.accounts.investor_share_ata.to_account_info(),
        &share_mint_pk,
        &investor_pk,
    )?;

    // ---- Re-mint shares (vault PDA signs) ---------------------------------
    let shares = session.shares_to_burn;
    // Ceremonia #49 (A1): ¿esta sesión reservó participaciones quemadas? Solo las
    // sesiones que pasaron por `aborting==1` (via withdraw_sweep_batch) lo hicieron;
    // el corner I3 (rescate de una sesión swept-en-settle) llega aquí con
    // `aborting==0` SIN haber reservado. La guarda evita restar de OTRAS sesiones.
    let was_aborting = session.aborting;
    let bump_arr = [vault_bump];
    let seeds: &[&[u8]] = &[VAULT_SEED, creator.as_ref(), &nonce_le, &bump_arr];
    let vault_signer: &[&[&[u8]]] = &[seeds];

    token::mint_to(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            MintTo {
                mint: ctx.accounts.share_mint.to_account_info(),
                to: ctx.accounts.investor_share_ata.to_account_info(),
                authority: ctx.accounts.vault.to_account_info(),
            },
            vault_signer,
        ),
        shares,
    )?;

    // Restore total_shares (live) + user_position.shares.
    let new_total_shares = total_shares_now
        .checked_add(shares)
        .ok_or(WagonError::MathOverflow)?;
    {
        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::write_total_shares(&mut data, new_total_shares)?;
        // Ceremonia #49 (A1): liberar la reserva de participaciones QUEMADAS, SOLO
        // si esta sesión estaba abortando (aborting==1) — la única que la reservó en
        // withdraw_sweep_batch. El corner I3 (aborting==0) re-acuña SIN haber
        // reservado → un decremento incondicional restaría de OTRAS sesiones que sí
        // están abortando. saturating_sub: nunca revierte (el abort es una salida).
        // Mismo `shares` (= session.shares_to_burn) que el incremento → cuadra exacto.
        if was_aborting == 1 {
            let cur = vlayout::read_pending_burned_shares(&data)?;
            vlayout::write_pending_burned_shares(&mut data, cur.saturating_sub(shares))?;
        }
        // G1 (2026-10-09): la sesión se cierra → libera su parte del contador de ENTRADA. Solo
        // las sesiones nacidas con el contador (generation != 0) sumaron; had_park == 0 ya está
        // garantizado por el require de arriba. saturating_sub: un terminal nunca revierte.
        if session.generation != 0 {
            let cur = vlayout::read_revivable_burned_shares(&data)?;
            vlayout::write_revivable_burned_shares(&mut data, cur.saturating_sub(shares))?;
        }
    }
    let position = &mut ctx.accounts.user_position;
    position.shares = position
        .shares
        .checked_add(shares)
        .ok_or(WagonError::MathOverflow)?;

    // ---- Return the USDC escrow to the vault and close it ------------------
    require_keys_eq!(
        ctx.accounts.vault_usdc_ata.key(),
        usdc_ata_pk,
        WagonError::InvalidJupiterRoute
    );
    let usdc_mint_pk = ctx.accounts.protocol.usdc_mint;
    let session_key = ctx.accounts.withdraw_session.key();
    require_keys_eq!(
        ctx.accounts.session_usdc_escrow.key(),
        crate::token_io::derive_live_ata(&session_key, &usdc_mint_pk, &spl_token::ID),
        WagonError::EscrowAtaMismatch
    );
    verify_token_account(
        &ctx.accounts.session_usdc_escrow.to_account_info(),
        &usdc_mint_pk,
        &session_key,
    )?;
    // NB: bind vault_key to a local — an inline `ctx.accounts.vault.key().as_ref()`
    // inside the seed array would dangle (E0716; `key()` returns by value).
    let vault_key = ctx.accounts.vault.key();
    let session_bump_arr = [ctx.accounts.withdraw_session.bump];
    let session_seeds: &[&[u8]] = &[
        WITHDRAW_SESSION_SEED,
        vault_key.as_ref(),
        investor_pk.as_ref(),
        &session_bump_arr,
    ];
    let session_signer: &[&[&[u8]]] = &[session_seeds];
    let escrow_ai = ctx.accounts.session_usdc_escrow.to_account_info();
    let escrow_balance = crate::token_io::read_token_amount(&escrow_ai)?;
    // ---- G3-B1a (F2B-01, caso (d) del diseño G3 §3): FAIL-OPEN, espejo del settle (DT-B) y de `deposit_abort` (G2-b) ----
    // Si la hucha está CONGELADA (ni el transfer ni el close pasan, tampoco a 0) o la ATA USDC del vault no puede
    // recibir y hay saldo que devolver, antes este abort revertía y la sesión se quedaba cancelando (`aborting == 1`)
    // para siempre: participaciones quemadas, `pending_burned` reservado y las patas ya devueltas al vault. Ahora
    // re-acuña y cierra igual; el USDC se queda en la hucha (ABIERTA, con su rent) como residuo del VAULT (en una
    // cancelación ese slice vuelve a los co-inversores, nunca al inversor), de donde lo lleva al vault
    // `withdraw_escrow_sweep` (sin permisos) en cuanto se pueda mover. Nada se pierde: se aplaza. Lecturas PURAS
    // (nunca revierten); la hucha ya está atada por derivación y `verify_token_account`, y la ATA del vault por su
    // clave pinneada en el VaultState (por eso `expected_owner = None`). Con la hucha vacía y sana se cierra como
    // siempre aunque la ATA del vault esté congelada (no hay transferencia que hacer).
    let escrow_frozen = read_token_state(&escrow_ai)? == TOKEN_STATE_FROZEN;
    let vault_ata_payable =
        is_payable_usdc_ata(&ctx.accounts.vault_usdc_ata.to_account_info(), &usdc_mint_pk, None);
    let deferred = escrow_frozen || (escrow_balance > 0 && !vault_ata_payable);
    if deferred {
        emit!(WithdrawAbortDeferred {
            vault: vault_key,
            investor: investor_pk,
            session: session_key,
            left_in_escrow_usdc: escrow_balance,
            reason: if escrow_frozen { 1 } else { 2 },
        });
        // La hucha se queda abierta: su rent no viaja con este reembolso (misma señal que el settle de DT-B y el
        // abort del depósito para la conciliación del patrocinador; `FundingRefunded.lamports` ya la excluye).
        emit!(FundingRefundPartial {
            session: session_key,
            kind: FUNDING_KIND_WITHDRAW,
            session_generation: ctx.accounts.withdraw_session.generation as u64,
            escrow: escrow_ai.key(),
            escrow_lamports: escrow_ai.lamports(),
        });
    } else {
        if escrow_balance > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from: escrow_ai.clone(),
                        to: ctx.accounts.vault_usdc_ata.to_account_info(),
                        authority: ctx.accounts.withdraw_session.to_account_info(),
                    },
                    session_signer,
                ),
                escrow_balance,
            )?;
        }
        // D1 (§3.3): el rent de la hucha cae en el PDA de la sesión y sale con su cierre.
        token::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount {
                account: escrow_ai,
                destination: ctx.accounts.withdraw_session.to_account_info(),
                authority: ctx.accounts.withdraw_session.to_account_info(),
            },
            session_signer,
        ))?;
        // G4 (F5A-01): la hucha USDC de la pareja ya no existe: el bit de quién la pagó vuelve a cero (una hucha nueva la paga
        // quien la cree, y la que cree un tercero sin sesión es, como cualquier donación, del inversor).
        ctx.accounts.user_position.escrow_rent_flags &= !ESCROW_RENT_WITHDRAW_USDC_WAGON;
    }

    // ---- Ceremonia USDC (§3.3, B2): reparto del rent temporal ----------------
    // Registro emparejado → `refund_to` (o la authority); si no, el inversor. Valida
    // `refund_target` antes de que Anchor cierre la sesión hacia él al salir.
    let authority = ctx.accounts.protocol.authority;
    crate::funding::settle_refund(
        &ctx.accounts.funding_record.to_account_info(),
        &ctx.accounts.refund_target.to_account_info(),
        &ctx.accounts.withdraw_session.to_account_info(),
        &investor_pk,
        &investor_pk,
        &authority,
        &ctx.accounts.caller.key(),
        ctx.accounts.withdraw_session.generation as u64,
        FUNDING_KIND_WITHDRAW,
        None,
    )?;

    emit!(WithdrawAborted {
        vault: ctx.accounts.vault.key(),
        investor: investor_pk,
        shares_restored: shares,
    });

    Ok(())
}
