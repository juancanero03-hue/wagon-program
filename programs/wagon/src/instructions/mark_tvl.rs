//! `mark_tvl` — permissionless mark-to-market refresh. Upgrade #30.
//!
//! Recomputes the vault's TVL from live balances + Pyth prices (strict
//! path, same rules as deposit_init) and stores it. Moves no funds; the
//! only effect is reconciling `tvl_last_computed_usdc` (and the protocol
//! aggregate) with reality, so the UI can show a fair share price and the
//! next deposit starts from a fresh mark even on an idle vault.

use anchor_lang::prelude::*;

use crate::constants::{PROTOCOL_SEED, VAULT_SEED};
use crate::errors::WagonError;
use crate::events::TvlMarked;
use crate::pricing;
use crate::state::vault_layout as vlayout;
use crate::state::ProtocolConfig;

#[derive(Accounts)]
pub struct MarkTvl<'info> {
    #[account(
        mut,
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// CHECK: vault PDA; owner + seeds verified byte-level in the handler.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    /// CHECK: pubkey verified against `vault_layout::read_usdc_ata`.
    pub vault_usdc_ata: UncheckedAccount<'info>,
}

pub fn handler(ctx: Context<MarkTvl>) -> Result<()> {
    let vault_ai = ctx.accounts.vault.to_account_info();
    require_keys_eq!(*vault_ai.owner, crate::ID, WagonError::VaultPaused);

    let (creator, nonce, vault_bump, status, old_tvl, usdc_ata_pk) = {
        let data = vault_ai.try_borrow_data()?;
        (
            vlayout::read_creator(&data)?,
            vlayout::read_nonce(&data)?,
            vlayout::read_bump(&data)?,
            vlayout::read_status(&data)?,
            vlayout::read_tvl_last_computed_usdc(&data)?,
            vlayout::read_usdc_ata(&data)?,
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
    require!(status != 3u8 /* Closed */, WagonError::VaultClosed);

    require_keys_eq!(
        ctx.accounts.vault_usdc_ata.key(),
        usdc_ata_pk,
        WagonError::InvalidJupiterRoute
    );

    let idle_usdc = pricing::read_token_amount(&ctx.accounts.vault_usdc_ata.to_account_info())?;
    let usdc_mint = ctx.accounts.protocol.usdc_mint;
    let vault_key = ctx.accounts.vault.key();

    let new_tvl = pricing::compute_tvl_m2m_strict(
        &vault_ai,
        &vault_key,
        idle_usdc,
        &usdc_mint,
        ctx.remaining_accounts,
    )?;

    {
        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::write_tvl_last_computed_usdc(&mut data, new_tvl)?;
    }

    // Keep the protocol aggregate roughly in sync (best-effort cache, only
    // used for the deposit cap check).
    // H4 (ceremonia #45): el mark solo puede BAJAR el agregado. Un `old_tvl`
    // deflactado (writeback lenient de restructure_abort/withdraw_settle, o caché
    // rancio >24h) dejaría que un re-mark PERMISSIONLESS lo inflara sin tope y
    // congelara los depósitos al cruzar tvl_cap. El crecimiento del agregado es
    // EXCLUSIVO de deposit_init (+net); subestimar es el lado conservador y
    // SELLADO (deposit_abort.rs:185-196): afloja el tope, nunca bloquea ni roba.
    let protocol = &mut ctx.accounts.protocol;
    if new_tvl < old_tvl {
        protocol.total_tvl_usdc = protocol.total_tvl_usdc.saturating_sub(old_tvl - new_tvl);
    }
    // else: `tvl_last_computed` del vault ya se refrescó arriba (display); el
    // agregado NO sube.

    emit!(TvlMarked {
        vault: vault_key,
        old_tvl_usdc: old_tvl,
        new_tvl_usdc: new_tvl,
    });
    Ok(())
}
