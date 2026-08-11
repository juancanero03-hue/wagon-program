//! `claim_creator_rewards` — the creator sweeps their accrued entry-fee
//! rewards into their own wallet (accrue-and-claim, pump.fun-style).
//!
//! The 90% creator cut of every entry fee accumulates in a USDC token account
//! owned by the per-creator PDA `[b"creator-rewards", creator]` (seeded at
//! deposit time). This instruction, signed by the creator, transfers the FULL
//! balance of that rewards vault to the creator's wallet USDC ATA.
//!
//! The balance of the rewards vault is the single source of truth — there is
//! no separate counter to drift. The payout can only ever reach the creator's
//! own USDC ATA (destination is derived, not caller-chosen), and only the
//! creator can trigger it, so nothing here is stealable or divertible.

use anchor_lang::prelude::*;
use anchor_spl::token::{spl_token, Token};

use crate::constants::{CREATOR_REWARDS_SEED, PROTOCOL_SEED};
use crate::errors::WagonError;
use crate::events::CreatorRewardsClaimed;
use crate::state::ProtocolConfig;
use crate::token_io::{
    derive_live_ata, read_mint_decimals, read_token_amount, transfer_checked_signed,
    verify_token_account,
};

#[derive(Accounts)]
pub struct ClaimCreatorRewards<'info> {
    #[account(mut)]
    pub creator: Signer<'info>,

    #[account(
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// CHECK: verified == protocol.usdc_mint in the handler.
    pub usdc_mint: UncheckedAccount<'info>,

    /// CHECK: per-creator rewards authority PDA. Owns the rewards vault and
    /// signs the payout. Validated by seeds; never deserialised.
    #[account(
        seeds = [CREATOR_REWARDS_SEED, creator.key().as_ref()],
        bump,
    )]
    pub creator_rewards_authority: UncheckedAccount<'info>,

    /// CHECK: the rewards vault — USDC ATA owned by `creator_rewards_authority`.
    /// Verified canonically + by mint/owner in the handler.
    #[account(mut)]
    pub creator_rewards_ata: UncheckedAccount<'info>,

    /// CHECK: destination — the creator's own wallet USDC ATA. The frontend
    /// creates it idempotently in the same tx. Verified canonically + mint/owner.
    #[account(mut)]
    pub creator_usdc_ata: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
}

pub fn handler(ctx: Context<ClaimCreatorRewards>) -> Result<()> {
    let usdc_mint_pk = ctx.accounts.protocol.usdc_mint;
    require_keys_eq!(
        ctx.accounts.usdc_mint.key(),
        usdc_mint_pk,
        WagonError::InvalidJupiterRoute
    );

    let creator_pk = ctx.accounts.creator.key();
    let authority_pk = ctx.accounts.creator_rewards_authority.key();

    // Rewards vault must be the canonical USDC ATA of the rewards-authority PDA.
    require_keys_eq!(
        ctx.accounts.creator_rewards_ata.key(),
        derive_live_ata(&authority_pk, &usdc_mint_pk, &spl_token::ID),
        WagonError::CreatorRewardsAtaMismatch
    );
    verify_token_account(
        &ctx.accounts.creator_rewards_ata.to_account_info(),
        &usdc_mint_pk,
        &authority_pk,
    )?;

    // Destination must be the creator's own USDC ATA.
    require_keys_eq!(
        ctx.accounts.creator_usdc_ata.key(),
        derive_live_ata(&creator_pk, &usdc_mint_pk, &spl_token::ID),
        WagonError::CreatorRewardsAtaMismatch
    );
    verify_token_account(
        &ctx.accounts.creator_usdc_ata.to_account_info(),
        &usdc_mint_pk,
        &creator_pk,
    )?;

    let amount = read_token_amount(&ctx.accounts.creator_rewards_ata.to_account_info())?;
    require!(amount > 0, WagonError::NoRewardsToClaim);

    let decimals = read_mint_decimals(&ctx.accounts.usdc_mint.to_account_info())?;

    let bump = ctx.bumps.creator_rewards_authority;
    let seeds: &[&[u8]] = &[CREATOR_REWARDS_SEED, creator_pk.as_ref(), &[bump]];
    let signer: &[&[&[u8]]] = &[seeds];

    transfer_checked_signed(
        &ctx.accounts.token_program.to_account_info(),
        &ctx.accounts.creator_rewards_ata.to_account_info(),
        &ctx.accounts.usdc_mint.to_account_info(),
        &ctx.accounts.creator_usdc_ata.to_account_info(),
        &ctx.accounts.creator_rewards_authority.to_account_info(),
        signer,
        amount,
        decimals,
    )?;

    emit!(CreatorRewardsClaimed {
        creator: creator_pk,
        amount_usdc: amount,
    });
    Ok(())
}
