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
//!      TO THE VAULT, and closes the USDC escrow + the session (rent →
//!      investor).
//!
//! The investor is made whole via the re-minted shares; the vault keeps the
//! returned tokens + USDC (composition may drift after a partial sale, value
//! is conserved). This works even for a session invalidated by a mid-session
//! restructure (a stale session goes abort-direction) and for orphan cleanup.
//!
//! Authorization: the investor at any time; ANYONE after
//! `WITHDRAW_SESSION_TIMEOUT_SECS` (30 min). Funds can only ever go to the
//! investor (shares) or the vault.
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
use crate::events::WithdrawAborted;
use crate::state::vault_layout as vlayout;
use crate::state::withdraw_session::WITHDRAW_SESSION_TIMEOUT_SECS;
use crate::state::{ProtocolConfig, UserPosition, WithdrawSession};
use crate::token_io::verify_token_account;

#[derive(Accounts)]
pub struct WithdrawAbort<'info> {
    /// The investor any time; anyone after the timeout. Pays fees only.
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: pinned to `session.investor` via has_one. Receives the re-minted
    /// shares, the USDC escrow rent and the session rent.
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
        close = investor,
    )]
    pub withdraw_session: Box<Account<'info, WithdrawSession>>,

    /// CHECK: C2 — la hucha USDC de la sesión (ATA canónica del PDA de sesión),
    /// verificada por derivación + verify_token_account. Su balance entero
    /// vuelve al vault en el abort y la cuenta se cierra (rent → investor).
    #[account(mut)]
    pub session_usdc_escrow: UncheckedAccount<'info>,

    /// CHECK: pubkey verified against `vault_layout::read_usdc_ata`. Recibe de
    /// vuelta el USDC de la hucha.
    #[account(mut)]
    pub vault_usdc_ata: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
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
    let now = Clock::get()?.unix_timestamp;
    let timed_out = now.saturating_sub(session.created_at) > WITHDRAW_SESSION_TIMEOUT_SECS;
    require!(
        ctx.accounts.caller.key() == session.investor || timed_out,
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
    let escrow_balance =
        crate::token_io::read_token_amount(&ctx.accounts.session_usdc_escrow.to_account_info())?;
    if escrow_balance > 0 {
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.session_usdc_escrow.to_account_info(),
                    to: ctx.accounts.vault_usdc_ata.to_account_info(),
                    authority: ctx.accounts.withdraw_session.to_account_info(),
                },
                session_signer,
            ),
            escrow_balance,
        )?;
    }
    token::close_account(CpiContext::new_with_signer(
        ctx.accounts.token_program.to_account_info(),
        CloseAccount {
            account: ctx.accounts.session_usdc_escrow.to_account_info(),
            destination: ctx.accounts.investor.to_account_info(),
            authority: ctx.accounts.withdraw_session.to_account_info(),
        },
        session_signer,
    ))?;

    emit!(WithdrawAborted {
        vault: ctx.accounts.vault.key(),
        investor: investor_pk,
        shares_restored: shares,
    });

    Ok(())
}
