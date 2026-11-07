//! `extend_feed_registry` — upgrade #31. Amplía el FeedRegistry con realloc.
//!
//! El registro nació con 64 entradas y ya va 61/64. El admin (Squads) puede
//! ampliarlo en caliente: realloc del PDA (+88 bytes/entrada, rent del
//! payer), tope duro 256. Los helpers byte-level ya hacen bounds-check por
//! longitud real; el límite de escritura pasa a derivarse del data_len.

use anchor_lang::prelude::*;

use crate::constants::FEED_REGISTRY_SEED;
use crate::errors::WagonError;
use crate::state::feed_registry_layout as flayout;

/// Tope absoluto de entradas tras cualquier ampliación.
pub const FEED_REGISTRY_HARD_CAP: usize = 256;

#[derive(Accounts)]
pub struct ExtendFeedRegistry<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    /// CHECK: PDA [feed-registry]; authority validada contra el campo
    /// almacenado; nunca deserializada como struct (~6 KB).
    #[account(
        mut,
        seeds = [FEED_REGISTRY_SEED],
        bump,
    )]
    pub registry: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<ExtendFeedRegistry>, extra_entries: u16) -> Result<()> {
    require!(extra_entries > 0, WagonError::InvalidFeedFlags);
    let registry_ai = ctx.accounts.registry.to_account_info();
    require_keys_eq!(
        *registry_ai.owner,
        crate::ID,
        WagonError::FeedRegistryCorrupted
    );
    {
        let data = registry_ai.try_borrow_data()?;
        require_keys_eq!(
            flayout::read_authority(&data)?,
            ctx.accounts.authority.key(),
            WagonError::UnauthorizedProtocolAdmin
        );
    }

    let old_len = registry_ai.data_len();
    let current_capacity =
        (old_len - flayout::ENTRIES_OFFSET - 1 - flayout::RESERVED_LEN) / flayout::ENTRY_LEN;
    let new_capacity = current_capacity + extra_entries as usize;
    require!(
        new_capacity <= FEED_REGISTRY_HARD_CAP,
        WagonError::FeedRegistryFull
    );

    let new_len = old_len + flayout::ENTRY_LEN * extra_entries as usize;
    // Rent adicional del payer (transfer simple; el realloc exige lamports).
    let rent_needed = Rent::get()?.minimum_balance(new_len);
    let topup = rent_needed.saturating_sub(registry_ai.lamports());
    if topup > 0 {
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.authority.to_account_info(),
                    to: registry_ai.clone(),
                },
            ),
            topup,
        )?;
    }
    registry_ai.realloc(new_len, true)?; // zero-init de la zona nueva
    msg!(
        "feed registry ampliado: {} -> {} entradas",
        current_capacity,
        new_capacity
    );
    Ok(())
}
