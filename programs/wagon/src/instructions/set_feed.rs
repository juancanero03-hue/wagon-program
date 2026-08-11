//! `set_feed` — admin-only upsert of a mint → Pyth feed mapping. Upgrade #30.
//!
//! If the mint already has an entry it is overwritten (feed rotation /
//! flags change); otherwise it is appended. Byte-level access throughout —
//! see `state::feed_registry_layout`.

use anchor_lang::prelude::*;
use anchor_spl::token::spl_token;

use crate::constants::FEED_REGISTRY_SEED;
use crate::errors::WagonError;
use crate::events::FeedSet;
use crate::state::feed_registry::{
    FEED_FLAGS_VALID_MASK, FEED_FLAG_COMPOSED_RR, FEED_FLAG_NO_ORACLE,
};
use crate::state::feed_registry_layout as layout;
use crate::token_io::TOKEN_2022_PROGRAM_ID;

#[derive(Accounts)]
pub struct SetFeed<'info> {
    pub authority: Signer<'info>,

    /// CHECK: PDA at [FEED_REGISTRY_SEED]. Validated against the stored
    /// authority field below; never deserialised as a struct.
    #[account(
        mut,
        seeds = [FEED_REGISTRY_SEED],
        bump,
    )]
    pub registry: UncheckedAccount<'info>,

    /// The mint being mapped. M-5: must be a real, initialized SPL mint
    /// (classic or Token-2022) matching the `mint` argument — a typo'd or
    /// fabricated address can no longer get a feed registered.
    /// CHECK: owner program + base mint layout validated in the handler.
    pub mint_account: UncheckedAccount<'info>,
}

pub fn handler(ctx: Context<SetFeed>, mint: Pubkey, feed_id: [u8; 32], flags: u8) -> Result<()> {
    let registry_ai = ctx.accounts.registry.to_account_info();
    require_keys_eq!(
        *registry_ai.owner,
        crate::ID,
        WagonError::FeedRegistryCorrupted
    );

    // Reserved flag bits must be zero (forward compatibility).
    require!(
        (flags & !FEED_FLAGS_VALID_MASK) == 0,
        WagonError::InvalidFeedFlags
    );
    // Ceremonia #40: el bit 3 pasó de «Switchboard» a «SIN ORÁCULO UTILIZABLE».
    // Sigue siendo incompatible con composed-RR: una entrada sin precio legible
    // no se puede componer con nada. La combinación queda prohibida igual que
    // antes, así que las 12 entradas ex-Switchboard vivas (flags 0b1011) siguen
    // siendo válidas y ninguna entrada nueva puede pedir las dos cosas.
    require!(
        (flags & (FEED_FLAG_COMPOSED_RR | FEED_FLAG_NO_ORACLE))
            != (FEED_FLAG_COMPOSED_RR | FEED_FLAG_NO_ORACLE),
        WagonError::InvalidFeedFlags
    );
    // An all-zero feed id is almost certainly a client-side bug.
    require!(feed_id != [0u8; 32], WagonError::InvalidFeedId);

    let now = Clock::get()?.unix_timestamp;
    let authority_key = ctx.accounts.authority.key();

    let mut data = registry_ai.try_borrow_mut_data()?;

    let stored_authority = layout::read_authority(&data)?;
    require_keys_eq!(
        stored_authority,
        authority_key,
        WagonError::UnauthorizedProtocolAdmin
    );

    // M-5(a): the mapped mint must EXIST as an initialized SPL mint and
    // match the instruction argument — a typo'd or fabricated address can
    // no longer get a feed registered during a ceremony. Base mint layout:
    // 82 bytes minimum, `is_initialized` at offset 45 (Token-2022
    // extensions only append). Checked AFTER the authority gate so a
    // non-admin still gets UnauthorizedProtocolAdmin.
    let mint_ai = &ctx.accounts.mint_account;
    require_keys_eq!(mint_ai.key(), mint, WagonError::SetFeedMintInvalid);
    require!(
        *mint_ai.owner == spl_token::ID || *mint_ai.owner == TOKEN_2022_PROGRAM_ID,
        WagonError::SetFeedMintInvalid
    );
    {
        let mdata = mint_ai.try_borrow_data()?;
        require!(
            mdata.len() >= 82 && mdata[45] == 1,
            WagonError::SetFeedMintInvalid
        );
    }

    let count = layout::read_count(&data)? as usize;
    let (index, count_after) = match layout::find(&data, &mint)? {
        Some(i) => (i, count as u16),
        None => {
            require!(
                count < crate::constants::MAX_PRICE_FEEDS,
                WagonError::FeedRegistryFull
            );
            let new_count = (count as u16)
                .checked_add(1)
                .ok_or(WagonError::MathOverflow)?;
            (count, new_count)
        }
    };

    // M-5(b): a feed_id may be mapped by ONE mint only. Two mints silently
    // sharing a feed is a mispricing hazard (admin fat-finger during a feed
    // ceremony). O(n) scan, n <= MAX_PRICE_FEEDS. The entry being updated
    // (same mint, feed rotation) is exempt from the scan.
    for i in 0..count {
        if i == index {
            continue;
        }
        if layout::read_entry_feed_id(&data, i)? == feed_id {
            return err!(WagonError::DuplicateFeedId);
        }
    }

    layout::write_entry(&mut data, index, &mint, &feed_id, flags, now)?;
    layout::write_count(&mut data, count_after)?;

    emit!(FeedSet {
        mint,
        feed_id,
        flags,
        registry_count_after: count_after,
    });

    Ok(())
}
