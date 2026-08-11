//! `finalize_close` — creator-only. Runs after all shares are burned
//! (`vault.total_shares == 0`) during a `Liquidating` vault's lifecycle.
//! Transitions the vault to `Closed` and emits `VaultFinalized`.
//!
//! M-4 (warm-up, auditoría 2026-06-29): the handler can now ALSO close the
//! vault's empty token ATAs and return their rent to the creator, via
//! OPTIONAL `remaining_accounts`:
//!   [spl_token_program, token_2022_program, ata_0, ata_1, ...]
//! With no remaining accounts the behaviour is the legacy pure state
//! transition, so existing callers keep working unchanged. Every ATA must
//! hold balance 0; ownership by the vault PDA is ultimately enforced by
//! the token program itself (the close CPI is signed with the vault's
//! seeds, so closing a foreign account simply fails).

use anchor_lang::prelude::*;
use anchor_spl::token::spl_token;

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::VaultFinalized;
use crate::state::{VaultState, VaultStatus};
use crate::token_io::TOKEN_2022_PROGRAM_ID;

#[derive(Accounts)]
pub struct FinalizeClose<'info> {
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
        constraint = vault.status() == VaultStatus::Liquidating @ WagonError::VaultNotLiquidating,
    )]
    pub vault: Box<Account<'info, VaultState>>,
}

pub fn handler<'info>(ctx: Context<'_, '_, '_, 'info, FinalizeClose<'info>>) -> Result<()> {
    // Ceremonia #43 (OT-1, defensa en profundidad): no finalizar con un depósito
    // comprometido sin asentar. En la práctica ya es 0 al entrar en Liquidating (el
    // candado de close_vault lo garantizó, y en Liquidating no se puede comprometer:
    // el barrido settle exige Active). Se comprueba igualmente.
    {
        let ai = ctx.accounts.vault.to_account_info();
        let data = ai.try_borrow_data()?;
        require!(
            crate::state::vault_layout::read_committed_deposits(&data)? == 0,
            WagonError::VaultHasCommittedDeposit
        );
    }

    let vault = &mut ctx.accounts.vault;
    // Gate: no investor shares may remain outstanding.
    require!(
        vault.total_shares == 0,
        WagonError::SharesStillOutstanding
    );

    vault.set_status(VaultStatus::Closed);

    let now = Clock::get()?.unix_timestamp;
    emit!(VaultFinalized {
        vault: vault.key(),
        ts: now,
    });

    // M-4: close the provided vault ATAs (must be empty) and return their
    // rent lamports to the creator.
    if !ctx.remaining_accounts.is_empty() {
        require!(
            ctx.remaining_accounts.len() >= 3,
            WagonError::InvalidJupiterRoute
        );
        let classic_ai = &ctx.remaining_accounts[0];
        let t22_ai = &ctx.remaining_accounts[1];
        require_keys_eq!(
            *classic_ai.key,
            spl_token::ID,
            WagonError::InvalidJupiterRoute
        );
        require_keys_eq!(
            *t22_ai.key,
            TOKEN_2022_PROGRAM_ID,
            WagonError::InvalidJupiterRoute
        );

        let creator_pk = ctx.accounts.vault.creator;
        let nonce_le = ctx.accounts.vault.nonce.to_le_bytes();
        let bump_arr = [ctx.accounts.vault.bump];
        let seeds: &[&[u8]] = &[VAULT_SEED, creator_pk.as_ref(), &nonce_le, &bump_arr];
        let signer_seeds: &[&[&[u8]]] = &[seeds];
        let vault_ai = ctx.accounts.vault.to_account_info();
        let creator_ai = ctx.accounts.creator.to_account_info();

        for ata_ai in &ctx.remaining_accounts[2..] {
            // Pick the CPI target by the account's REAL owner program
            // (lesson from upgrade #27: classic and Token-2022 ATAs coexist
            // in one vault).
            let token_program_ai = if *ata_ai.owner == spl_token::ID {
                classic_ai
            } else if *ata_ai.owner == TOKEN_2022_PROGRAM_ID {
                t22_ai
            } else {
                return err!(WagonError::InvalidJupiterRoute);
            };
            // Liquidation swept everything: an ATA with residual balance is
            // a bug upstream, never something to burn silently.
            require!(
                crate::token_io::read_token_amount(ata_ai)? == 0,
                WagonError::AtaNotEmpty
            );
            crate::token_io::close_token_account_signed(
                token_program_ai,
                ata_ai,
                &creator_ai,
                &vault_ai,
                signer_seeds,
            )?;
        }
    }

    Ok(())
}
