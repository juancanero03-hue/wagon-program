//! `cache_alloc_decimals` — permissionless backfill. Upgrade #30.
//!
//! Caches each allocation mint's decimals into the vault's per-allocation
//! reserved bytes (see vault_layout, upgrade #30 section). Needed once per
//! pre-#30 vault before oracle valuation can price its basket; new vaults
//! get the same call from the frontend right after create_vault.
//!
//! Safety: writing decimals is idempotent and value-neutral — the data is
//! read from the mint account at the address stored in the vault state, so
//! a caller cannot inject wrong decimals.

use anchor_lang::prelude::*;

use crate::constants::VAULT_SEED;
use crate::errors::WagonError;
use crate::state::vault_layout as vlayout;

#[derive(Accounts)]
pub struct CacheAllocDecimals<'info> {
    /// CHECK: vault PDA; owner + seeds verified byte-level in the handler.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
}

pub fn handler(ctx: Context<CacheAllocDecimals>) -> Result<()> {
    let vault_ai = ctx.accounts.vault.to_account_info();
    require_keys_eq!(*vault_ai.owner, crate::ID, WagonError::VaultPaused);

    let (creator, nonce, vault_bump, allocation_count) = {
        let data = vault_ai.try_borrow_data()?;
        (
            vlayout::read_creator(&data)?,
            vlayout::read_nonce(&data)?,
            vlayout::read_bump(&data)?,
            vlayout::read_allocation_count(&data)?,
        )
    };
    let nonce_le = nonce.to_le_bytes();
    let (derived_vault_key, derived_bump) =
        Pubkey::find_program_address(&[VAULT_SEED, creator.as_ref(), &nonce_le], &crate::ID);
    require_keys_eq!(
        ctx.accounts.vault.key(),
        derived_vault_key,
        WagonError::VaultPaused
    );
    require!(vault_bump == derived_bump, WagonError::VaultPaused);

    let remaining = ctx.remaining_accounts;
    require!(
        remaining.len() == allocation_count as usize,
        WagonError::AllocMintMismatch
    );

    for (i, mint_ai) in remaining.iter().enumerate() {
        let alloc_mint = {
            let data = vault_ai.try_borrow_data()?;
            vlayout::read_allocation_mint(&data, i)?
        };
        require_keys_eq!(mint_ai.key(), alloc_mint, WagonError::AllocMintMismatch);

        let decimals = crate::token_io::read_mint_decimals(mint_ai)?;

        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::write_alloc_decimals(&mut data, i, decimals)?;
    }

    msg!("cached decimals for {} allocations", allocation_count);
    Ok(())
}
