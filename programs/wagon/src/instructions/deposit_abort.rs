//! `deposit_abort` — rollback of the fractional deposit flow.
//!
//! Upgrade #31 (F2b) rewrote this around the per-session escrow. Before,
//! abort was only possible if NO swap had executed (the funds were already
//! mixed into the vault); orphan sessions with partial swaps were stuck,
//! and a restructure could strand them forever. Now the session's funds
//! never touch the vault until settle, so abort works at ANY stage:
//!
//!   1. If swaps executed, `deposit_sweep_batch` first returns each leg's
//!      escrowed TOKENS to the investor (in kind — reversing the swaps
//!      would mean another round of slippage) and flags the session
//!      `aborting`, which blocks the swap/settle paths for good.
//!   2. This instruction then refunds whatever USDC remains in the escrow,
//!      closes the escrow ATA and the session (rent → investor), and
//!      reverses the optimistic `protocol.total_tvl_usdc` bump from init.
//!
//! Authorization: the investor at any time; ANYONE after
//! `DEPOSIT_SESSION_TIMEOUT_SECS` (30 min) — abandoned sessions can always
//! be cleaned up, and the funds can only ever go to the investor.
//!
//! Guard against mixing paths: if any settle-direction sweep already moved
//! tokens INTO the vault (`legs_swept != 0` while not `aborting`), abort is
//! refused — that session is committed and must settle (which is
//! permissionless, so it can always be driven to completion).

use anchor_lang::prelude::*;
use anchor_spl::token::{self, spl_token, CloseAccount, Token, Transfer};

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::DepositAborted;
use crate::state::deposit_session::DEPOSIT_SESSION_TIMEOUT_SECS;
use crate::state::{DepositSession, ProtocolConfig};
use crate::token_io::verify_token_account;

#[derive(Accounts)]
pub struct DepositAbort<'info> {
    /// The investor any time; anyone after the timeout. Pays fees only.
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: pinned to `session.investor` via has_one. Receives the USDC
    /// refund (into their canonical USDC ATA), the escrow rent and the
    /// session rent.
    #[account(mut)]
    pub investor: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// CHECK: PDA seeds + owner verified manually (VaultGuard). Read-only:
    /// the vault never held this session's funds.
    pub vault: UncheckedAccount<'info>,

    /// CHECK: SPL Token account, mint == usdc_mint, owner == investor.
    #[account(mut)]
    pub investor_usdc_ata: UncheckedAccount<'info>,

    /// CHECK: Upgrade #31 (F2b). The session's USDC escrow ATA, verified by
    /// canonical derivation. Fully refunded to the investor and closed here.
    #[account(mut)]
    pub session_usdc_escrow: UncheckedAccount<'info>,

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
        close = investor,
    )]
    pub deposit_session: Box<Account<'info, DepositSession>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<DepositAbort>) -> Result<()> {
    let session = &ctx.accounts.deposit_session;

    // ---- Vault identity (any status — abort works mid-restructure too) ----
    let vault_ai = ctx.accounts.vault.to_account_info();
    let _guard = crate::guards::VaultGuard::load(
        &vault_ai,
        &ctx.accounts.vault.key(),
        WagonError::VaultPaused,
    )?;

    // ---- Authorization ------------------------------------------------------
    let now = Clock::get()?.unix_timestamp;
    let timed_out = now.saturating_sub(session.created_at) > DEPOSIT_SESSION_TIMEOUT_SECS;
    require!(
        ctx.accounts.caller.key() == session.investor || timed_out,
        WagonError::DepositAbortTooEarly
    );

    // ---- Path-mixing guards -------------------------------------------------
    // (a) A session whose tokens were already swept INTO the vault is
    //     committed: it must settle (permissionless), never abort.
    require!(
        session.aborting == 1 || session.legs_swept == 0,
        WagonError::SessionAlreadyStarted
    );
    // (b) Every leg with escrowed tokens must have been returned to the
    //     investor first (abort-direction sweeps). For a session where no
    //     swap ever ran, this is vacuously true.
    if session.aborting == 1 {
        require!(session.fully_swept(), WagonError::EscrowNotSwept);
    } else {
        // No sweeps happened at all: only legal if no non-trivial swap ran.
        require!(
            session.legs_completed == session.trivial_mask,
            WagonError::SessionAlreadyStarted
        );
    }

    // ---- Validate refund accounts ------------------------------------------
    let usdc_mint_pk = ctx.accounts.protocol.usdc_mint;
    let investor_pk = ctx.accounts.investor.key();
    verify_token_account(
        &ctx.accounts.investor_usdc_ata.to_account_info(),
        &usdc_mint_pk,
        &investor_pk,
    )?;

    let session_key = session.key();
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

    // ---- Refund the escrowed USDC and close the escrow ----------------------
    let vault_key = ctx.accounts.vault.key();
    let session_bump_arr = [session.bump];
    let session_seeds: &[&[u8]] = &[
        DEPOSIT_SESSION_SEED,
        vault_key.as_ref(),
        investor_pk.as_ref(),
        &session_bump_arr,
    ];
    let session_signer: &[&[&[u8]]] = &[session_seeds];

    let refund_usdc =
        crate::token_io::read_token_amount(&ctx.accounts.session_usdc_escrow.to_account_info())?;
    if refund_usdc > 0 {
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.session_usdc_escrow.to_account_info(),
                    to: ctx.accounts.investor_usdc_ata.to_account_info(),
                    authority: ctx.accounts.deposit_session.to_account_info(),
                },
                session_signer,
            ),
            refund_usdc,
        )?;
    }
    token::close_account(CpiContext::new_with_signer(
        ctx.accounts.token_program.to_account_info(),
        CloseAccount {
            account: ctx.accounts.session_usdc_escrow.to_account_info(),
            destination: ctx.accounts.investor.to_account_info(),
            authority: ctx.accounts.deposit_session.to_account_info(),
        },
        session_signer,
    ))?;

    // ---- Reverse the optimistic TVL bump from init -----------------------
    // F8 (ceremonia #40): `saturating_sub`, NUNCA `checked_sub`.
    // `protocol.total_tvl_usdc` es una CACHÉ agregada que se desincroniza sola:
    // `mark_tvl` y `restructure_settle` la reescriben con
    // `saturating_sub(old).saturating_add(new)` usando el TVL almacenado del
    // vault, `withdraw_settle` le resta el valor de salida medido y el cobro en
    // especie (`withdraw_claim_leg_in_kind`) saca valor del vault sin tocarla.
    // Medido en mainnet: el agregado y la suma vault a vault NO coinciden.
    // Con `checked_sub`, un agregado que haya derivado por debajo de este
    // importe hace REVERTIR el abort — es decir, la caché tendría derecho de
    // veto sobre la DEVOLUCIÓN DEL DINERO del inversor. Prioridad: que el
    // dinero salga siempre; que la caché se quede corta es inocuo (la corrige
    // el siguiente `mark_tvl`) y además es el lado conservador: subestimar el
    // TVL agregado solo puede dejar entrar depósitos, nunca robar nada.
    let amount_usdc = ctx.accounts.deposit_session.amount_usdc;
    let protocol = &mut ctx.accounts.protocol;
    protocol.total_tvl_usdc = protocol.total_tvl_usdc.saturating_sub(amount_usdc);

    emit!(DepositAborted {
        vault: ctx.accounts.vault.key(),
        investor: investor_pk,
        amount_usdc_refunded: refund_usdc,
    });

    Ok(())
}
