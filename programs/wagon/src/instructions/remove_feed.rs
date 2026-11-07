//! `remove_feed` — admin-only. Swap-and-pop removal of a mint → feed entry.
//! Upgrade #30. Mirrors `remove_allowed_mint`.

use anchor_lang::prelude::*;

use crate::constants::FEED_REGISTRY_SEED;
use crate::errors::WagonError;
use crate::events::FeedRemoved;
use crate::state::feed_registry_layout as layout;

#[derive(Accounts)]
pub struct RemoveFeed<'info> {
    pub authority: Signer<'info>,

    /// CHECK: PDA at [FEED_REGISTRY_SEED]. Validated against the stored
    /// authority field below; never deserialised as a struct.
    #[account(
        mut,
        seeds = [FEED_REGISTRY_SEED],
        bump,
    )]
    pub registry: UncheckedAccount<'info>,
}

pub fn handler(ctx: Context<RemoveFeed>, mint: Pubkey) -> Result<()> {
    let registry_ai = ctx.accounts.registry.to_account_info();
    require_keys_eq!(
        *registry_ai.owner,
        crate::ID,
        WagonError::FeedRegistryCorrupted
    );

    let authority_key = ctx.accounts.authority.key();
    let mut data = registry_ai.try_borrow_mut_data()?;

    let stored_authority = layout::read_authority(&data)?;
    require_keys_eq!(
        stored_authority,
        authority_key,
        WagonError::UnauthorizedProtocolAdmin
    );

    let count = layout::read_count(&data)? as usize;
    let index = layout::find(&data, &mint)?.ok_or(WagonError::FeedNotFound)?;

    let last = count
        .checked_sub(1)
        .ok_or(WagonError::FeedRegistryCorrupted)?;
    if index != last {
        layout::copy_entry(&mut data, last, index)?;
    }
    layout::zero_entry(&mut data, last)?;

    let new_count = last as u16;
    layout::write_count(&mut data, new_count)?;

    emit!(FeedRemoved {
        mint,
        registry_count_after: new_count,
    });

    Ok(())
}
