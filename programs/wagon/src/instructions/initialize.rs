//! `initialize_protocol` — one-shot setup. Called exactly once, signed by the
//! Squads multisig (which becomes `ProtocolConfig.authority`).

use anchor_lang::prelude::*;
use anchor_spl::token::Mint;

use crate::constants::*;
use crate::events::ProtocolInitialized;
use crate::state::ProtocolConfig;

#[derive(Accounts)]
pub struct InitializeProtocol<'info> {
    /// Payer and initial admin authority. In production this is the Squads
    /// multisig signing via its CPI.
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = ProtocolConfig::LEN,
        seeds = [PROTOCOL_SEED],
        bump,
    )]
    pub protocol: Account<'info, ProtocolConfig>,

    /// USDC mint. Verified on-chain to match the hardcoded `USDC_MINT`
    /// constant, preventing a wrong mint being configured at init.
    #[account(address = USDC_MINT)]
    pub usdc_mint: Account<'info, Mint>,

    /// USDC ATA owned by the Squads multisig. Funds from protocol fees land here.
    /// CHECK: address ownership is verified client-side by using associated_token::get_associated_token_address.
    pub treasury_usdc_ata: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<InitializeProtocol>) -> Result<()> {
    let protocol = &mut ctx.accounts.protocol;

    protocol.authority = ctx.accounts.authority.key();
    protocol.usdc_mint = ctx.accounts.usdc_mint.key();
    protocol.treasury_usdc_ata = ctx.accounts.treasury_usdc_ata.key();

    protocol.tvl_cap_usdc = BOOTSTRAP_TVL_CAP_USDC;
    protocol.liquidity_floor_usdc = DEFAULT_LIQUIDITY_FLOOR_USDC;

    protocol.management_fee_bps = DEFAULT_MANAGEMENT_FEE_BPS;
    protocol.mgmt_fee_protocol_share_bps = MGMT_FEE_PROTOCOL_SHARE_BPS;
    protocol.mgmt_fee_creator_share_bps = MGMT_FEE_CREATOR_SHARE_BPS;

    protocol.perf_fee_protocol_share_bps = PERF_FEE_PROTOCOL_SHARE_BPS;
    protocol.perf_fee_creator_share_bps = PERF_FEE_CREATOR_SHARE_BPS;
    protocol.min_perf_fee_bps = MIN_PERF_FEE_BPS;
    protocol.max_perf_fee_bps = MAX_PERF_FEE_BPS;

    protocol.max_tokens_per_vault = MAX_TOKENS_PER_VAULT as u8;

    // Entry fee ships OFF (accrue-and-claim). Admin turns it on via set_entry_fee.
    protocol.entry_fee_bps = 0;
    protocol.entry_fee_cap_usdc = 0;
    protocol.entry_fee_exempt_below_usdc = 0;
    protocol.entry_fee_protocol_share_bps = 0;

    // Vault-creation fee ships OFF (upgrade #35). Admin turns it on via
    // set_vault_creation_fee (Squads).
    protocol.vault_creation_fee_usd_micros = 0;
    protocol.vault_creation_fee_treasury = Pubkey::default();

    protocol.paused = false;
    protocol.vault_count = 0;
    protocol.total_tvl_usdc = 0;
    protocol.last_admin_action_ts = Clock::get()?.unix_timestamp;
    protocol.bump = ctx.bumps.protocol;

    emit!(ProtocolInitialized {
        authority: protocol.authority,
        usdc_mint: protocol.usdc_mint,
        tvl_cap_usdc: protocol.tvl_cap_usdc,
        liquidity_floor_usdc: protocol.liquidity_floor_usdc,
    });

    Ok(())
}
