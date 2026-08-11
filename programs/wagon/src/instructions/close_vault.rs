//! `close_vault` — creator-only. Transitions a vault from `Active`/`Paused`
//! to `Liquidating`. Once in Liquidating:
//!   - `deposit` and `rebalance` revert.
//!   - Creator (or anyone) calls `sweep_to_usdc` once per token to convert
//!     basket tokens -> USDC via Jupiter.
//!   - Investors can still call `withdraw`; it now pays out USDC only, with
//!     `sweep`-ed slots skipped in the Jupiter loop.
//!   - After 7 days (`LIQUIDATION_TIMEOUT_SECONDS`), any remaining
//!     illiquid tokens can be distributed in-kind at withdraw time instead
//!     of being swept. (In-kind path tracked in a follow-up task.)
//!
//! Irreversible: a vault cannot go back from `Liquidating` to `Active`.
//! Creators who want to change allocations should use `rebalance` instead.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::VaultClosed;
use crate::state::{VaultState, VaultStatus};

#[derive(Accounts)]
pub struct CloseVault<'info> {
    #[account(mut)]
    pub creator: Signer<'info>,

    #[account(
        mut,
        seeds = [
            VAULT_SEED,
            vault.creator.as_ref(),
            &vault.nonce.to_le_bytes(),
        ],
        bump = vault.bump,
        has_one = creator @ WagonError::UnauthorizedVaultCreator,
        // Ceremonia #49 (A7): solo se puede cerrar desde Active. Antes se admitía
        // Paused → el creador podía saltarse una pausa de la autoridad (pasar a
        // Liquidating es IRREVERSIBLE y habilita las ventas Jupiter). Dos constraints
        // para preservar los códigos de error: Paused → VaultPaused (respeta la
        // pausa); Liquidating/Closed/Restructuring → VaultClosed (idéntico a hoy).
        // NO estrangula ninguna salida: un vault Paused YA permite retirar
        // (withdraw_init usa VaultGuard::load y acepta Paused).
        constraint = vault.status() != VaultStatus::Paused @ WagonError::VaultPaused,
        constraint = vault.status() == VaultStatus::Active @ WagonError::VaultClosed,
    )]
    pub vault: Box<Account<'info, VaultState>>,
}

pub fn handler(ctx: Context<CloseVault>) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;

    // Ceremonia #43 (OT-1): NO sacar el vault de Active con un depósito COMPROMETIDO
    // sin asentar — su valor está dentro del vault sin participaciones que lo
    // representen y se repartiría a los demás titulares al liquidar. El contador se
    // lee byte-level (misma fuente que deposit_sweep_batch/deposit_settle). No
    // congela: el depósito se drena solo (deposit_settle es permissionless y solo
    // exige Active, que ESTE candado preserva).
    {
        let ai = ctx.accounts.vault.to_account_info();
        let data = ai.try_borrow_data()?;
        require!(
            crate::state::vault_layout::read_committed_deposits(&data)? == 0,
            WagonError::VaultHasCommittedDeposit
        );
    }

    let vault = &mut ctx.accounts.vault;
    vault.set_status(VaultStatus::Liquidating);
    vault.liquidation_started_at = now;
    // `last_fee_accrual_ts` is a frozen layout field (the management fee was
    // removed in H-2; the field stays to preserve on-chain account offsets).
    // Keep stamping it for indexer/display consistency only.
    vault.last_fee_accrual_ts = now;

    emit!(VaultClosed {
        vault: vault.key(),
        creator: vault.creator,
        ts: now,
    });

    Ok(())
}
