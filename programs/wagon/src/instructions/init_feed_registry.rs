//! `init_feed_registry` — admin-only, one-shot. Upgrade #30.
//!
//! Creates the FeedRegistry PDA and writes the header bytes. Same manual
//! create_account + byte-write pattern as `init_allowed_mints` (the struct
//! is far beyond what can be materialised on the BPF stack).
//!
//! Upgrade #34: the account is created SMALL (`FEED_REGISTRY_INITIAL_CAPACITY`
//! entries = 8523 bytes, mirroring the live mainnet account) instead of at the
//! theoretical max (`MAX_PRICE_FEEDS` = 256 entries = 22603 bytes), which
//! would exceed the 10240-byte single-CPI create_account cap. Capacity then
//! grows via `extend_feed_registry`.

use anchor_lang::prelude::*;
use anchor_lang::system_program::{create_account, CreateAccount};

use crate::constants::{FEED_REGISTRY_INITIAL_CAPACITY, FEED_REGISTRY_SEED, PROTOCOL_SEED};
use crate::errors::WagonError;
use crate::events::FeedRegistryInitialized;
use crate::state::feed_registry_layout as layout;
use crate::state::ProtocolConfig;

#[derive(Accounts)]
pub struct InitFeedRegistry<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        has_one = authority @ WagonError::UnauthorizedProtocolAdmin,
    )]
    pub protocol: Account<'info, ProtocolConfig>,

    /// CHECK: PDA at [FEED_REGISTRY_SEED]. Created manually below; header
    /// bytes written via layout helpers, never deserialised as a struct.
    #[account(
        mut,
        seeds = [FEED_REGISTRY_SEED],
        bump,
    )]
    pub registry: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<InitFeedRegistry>) -> Result<()> {
    let bump = ctx.bumps.registry;
    // #34: create small (96 entries / 8523 B); grow later via extend_feed_registry.
    let space = (layout::ENTRIES_OFFSET
        + FEED_REGISTRY_INITIAL_CAPACITY * layout::ENTRY_LEN
        + layout::BUMP_LEN
        + layout::RESERVED_LEN) as u64;
    let rent = Rent::get()?.minimum_balance(space as usize);

    let signer_seeds: &[&[&[u8]]] = &[&[FEED_REGISTRY_SEED, &[bump]]];
    create_account(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            CreateAccount {
                from: ctx.accounts.authority.to_account_info(),
                to: ctx.accounts.registry.to_account_info(),
            },
            signer_seeds,
        ),
        rent,
        space,
        &crate::ID,
    )?;

    {
        let mut data = ctx.accounts.registry.try_borrow_mut_data()?;
        layout::write_discriminator(&mut data)?;
        layout::write_authority(&mut data, &ctx.accounts.authority.key())?;
        layout::write_count(&mut data, 0)?;
        // #34: the vestigial bump byte lives at the TAIL of the real account
        // (data_len - reserved - 1), not at the theoretical-max BUMP_OFFSET
        // (which sits beyond this small account). Never read back; kept for
        // layout continuity with the pre-#34 account.
        let bump_at = data.len() - layout::RESERVED_LEN - layout::BUMP_LEN;
        data[bump_at] = bump;
    }

    emit!(FeedRegistryInitialized {
        authority: ctx.accounts.authority.key(),
    });
    Ok(())
}
