//! Admin-only operations. All require `ctx.accounts.authority.key() ==
//! protocol.authority`, i.e. a transaction signed by the Squads multisig.
//!
//! These are the levers the protocol can pull without a full program upgrade:
//!   - `set_tvl_cap`        — raise the TVL cap (post-audit this is bumped).
//!   - `set_liquidity_floor` — tune minimum liquidity required per token.
//!   - `pause_protocol` / `unpause_protocol` — global emergency kill-switch.
//!     Paused = blocks `deposit`, `create_vault`, `rebalance`. Withdrawals
//!     always remain open.
//!   - `pause_vault` / `unpause_vault` — per-vault pause, same rules.

use anchor_lang::prelude::*;
use anchor_lang::Discriminator;

use crate::constants::{ALLOWED_MINTS_SEED, PROTOCOL_SEED};
use crate::errors::WagonError;
use crate::events::{
    AllowedMintRegistryClosed, LiquidityFloorChanged, M2mEnforcementChanged,
    ProtocolPauseChanged, RebalanceFeeParamsChanged, SwapMaxLossChanged, TvlCapChanged,
    VaultCreationFeeParamsChanged, VaultPauseChanged, EntryFeeParamsChanged,
};
use crate::instructions::restructure_init::RESTRUCTURE_SEED;
use crate::state::{ProtocolConfig, RestructureSession, VaultState, VaultStatus};

#[derive(Accounts)]
pub struct ProtocolAdmin<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        has_one = authority @ WagonError::UnauthorizedProtocolAdmin,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,
}

pub fn set_tvl_cap_handler(ctx: Context<ProtocolAdmin>, new_cap_usdc: u64) -> Result<()> {
    let protocol = &mut ctx.accounts.protocol;
    let old = protocol.tvl_cap_usdc;
    protocol.tvl_cap_usdc = new_cap_usdc;
    protocol.last_admin_action_ts = Clock::get()?.unix_timestamp;
    emit!(TvlCapChanged {
        old_cap: old,
        new_cap: new_cap_usdc
    });
    Ok(())
}

pub fn set_liquidity_floor_handler(ctx: Context<ProtocolAdmin>, new_floor_usdc: u64) -> Result<()> {
    let protocol = &mut ctx.accounts.protocol;
    let old = protocol.liquidity_floor_usdc;
    protocol.liquidity_floor_usdc = new_floor_usdc;
    protocol.last_admin_action_ts = Clock::get()?.unix_timestamp;
    emit!(LiquidityFloorChanged {
        old_floor: old,
        new_floor: new_floor_usdc
    });
    Ok(())
}

pub fn set_m2m_enforced_handler(ctx: Context<ProtocolAdmin>, enforced: bool) -> Result<()> {
    let protocol = &mut ctx.accounts.protocol;
    protocol.m2m_enforced = enforced as u8;
    protocol.last_admin_action_ts = Clock::get()?.unix_timestamp;
    emit!(M2mEnforcementChanged { enforced });
    Ok(())
}

pub fn pause_protocol_handler(ctx: Context<ProtocolAdmin>) -> Result<()> {
    ctx.accounts.protocol.paused = true;
    ctx.accounts.protocol.last_admin_action_ts = Clock::get()?.unix_timestamp;
    emit!(ProtocolPauseChanged { paused: true });
    Ok(())
}

pub fn unpause_protocol_handler(ctx: Context<ProtocolAdmin>) -> Result<()> {
    ctx.accounts.protocol.paused = false;
    ctx.accounts.protocol.last_admin_action_ts = Clock::get()?.unix_timestamp;
    emit!(ProtocolPauseChanged { paused: false });
    Ok(())
}

pub fn set_entry_fee_handler(
    ctx: Context<ProtocolAdmin>,
    bps: u16,
    cap_usdc: u64,
    exempt_below_usdc: u64,
    protocol_share_bps: u16,
) -> Result<()> {
    require!(
        bps <= crate::constants::ENTRY_FEE_MAX_BPS,
        WagonError::InvalidEntryFeeParams
    );
    require!(
        protocol_share_bps <= crate::constants::BPS_DENOMINATOR as u16,
        WagonError::InvalidEntryFeeParams
    );
    let protocol = &mut ctx.accounts.protocol;
    protocol.entry_fee_bps = bps;
    protocol.entry_fee_cap_usdc = cap_usdc;
    protocol.entry_fee_exempt_below_usdc = exempt_below_usdc;
    protocol.entry_fee_protocol_share_bps = protocol_share_bps;
    protocol.last_admin_action_ts = Clock::get()?.unix_timestamp;
    emit!(EntryFeeParamsChanged {
        bps,
        cap_usdc,
        exempt_below_usdc,
        protocol_share_bps,
    });
    Ok(())
}

/// Upgrade #35 — fee de creación de vault. Importe en micro-USD (6 dec;
/// 1_500_000 = 1,50 USD) + tesorería SOL de destino. 0 = apagado. El cobro
/// en lamports lo calcula create_vault con el oráculo SOL/USD de Pyth.
pub fn set_vault_creation_fee_handler(
    ctx: Context<ProtocolAdmin>,
    fee_usd_micros: u64,
    treasury: Pubkey,
) -> Result<()> {
    require!(
        fee_usd_micros <= crate::constants::VAULT_CREATION_FEE_MAX_USD_MICROS,
        WagonError::InvalidVaultCreationFeeParams
    );
    require!(
        fee_usd_micros == 0 || treasury != Pubkey::default(),
        WagonError::InvalidVaultCreationFeeParams
    );
    let protocol = &mut ctx.accounts.protocol;
    protocol.vault_creation_fee_usd_micros = fee_usd_micros;
    protocol.vault_creation_fee_treasury = treasury;
    protocol.last_admin_action_ts = Clock::get()?.unix_timestamp;
    emit!(VaultCreationFeeParamsChanged {
        fee_usd_micros,
        treasury,
    });
    Ok(())
}

/// Ceremonia #46 — fija la comisión de rebalanceo / cambio de cesta en micro-USD
/// (1_000_000 = 1,00 USD) + tesorería SOL de destino. 0 = apagada. El cobro en
/// lamports lo calculan rebalance y restructure_init con el oráculo SOL/USD de
/// Pyth. Clon exacto de set_vault_creation_fee_handler; campo/palanca DEDICADOS.
pub fn set_rebalance_fee_handler(
    ctx: Context<ProtocolAdmin>,
    fee_usd_micros: u64,
    treasury: Pubkey,
) -> Result<()> {
    require!(
        fee_usd_micros <= crate::constants::VAULT_CREATION_FEE_MAX_USD_MICROS,
        WagonError::InvalidRebalanceFeeParams
    );
    require!(
        fee_usd_micros == 0 || treasury != Pubkey::default(),
        WagonError::InvalidRebalanceFeeParams
    );
    let protocol = &mut ctx.accounts.protocol;
    protocol.rebalance_fee_usd_micros = fee_usd_micros;
    protocol.rebalance_fee_treasury = treasury;
    protocol.last_admin_action_ts = Clock::get()?.unix_timestamp;
    emit!(RebalanceFeeParamsChanged {
        fee_usd_micros,
        treasury,
    });
    Ok(())
}

#[derive(Accounts)]
pub struct AdminVaultPause<'info> {
    pub authority: Signer<'info>,

    #[account(
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        has_one = authority @ WagonError::UnauthorizedProtocolAdmin,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    #[account(mut)]
    pub vault: Box<Account<'info, VaultState>>,
}

pub fn pause_vault_handler(ctx: Context<AdminVaultPause>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    // Only transition Active -> Paused; never force a Liquidating/Closed vault back.
    match vault.status() {
        VaultStatus::Active => vault.set_status(VaultStatus::Paused),
        _ => return err!(WagonError::Unsupported),
    };
    emit!(VaultPauseChanged {
        vault: vault.key(),
        paused: true
    });
    Ok(())
}

/// Accounts for `unpause_vault`. M-2: gains the vault's restructure-session
/// PDA (address-verified, may be non-existent) so the handler can tell a
/// LIVE restructure apart from an orphaned `Restructuring` status.
#[derive(Accounts)]
pub struct AdminVaultUnpause<'info> {
    pub authority: Signer<'info>,

    #[account(
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        has_one = authority @ WagonError::UnauthorizedProtocolAdmin,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    #[account(mut)]
    pub vault: Box<Account<'info, VaultState>>,

    /// The vault's restructure-session PDA. NOT typed: it usually does not
    /// exist. Its address is enforced by the seeds constraint; the handler
    /// only inspects owner + discriminator to decide if a session is live.
    /// CHECK: seeds-verified; contents only read to test liveness.
    #[account(
        seeds = [RESTRUCTURE_SEED, vault.key().as_ref()],
        bump,
    )]
    pub restructure_session: UncheckedAccount<'info>,
}

pub fn unpause_vault_handler(ctx: Context<AdminVaultUnpause>) -> Result<()> {
    let session_alive = {
        let sess = &ctx.accounts.restructure_session;
        let data = sess.try_borrow_data()?;
        *sess.owner == crate::ID
            && data.len() >= 8
            && data[..8] == RestructureSession::DISCRIMINATOR
    };

    let vault = &mut ctx.accounts.vault;
    match vault.status() {
        VaultStatus::Paused => vault.set_status(VaultStatus::Active),
        // M-2: while a restructure session is LIVE, the only legal exits are
        // restructure_settle / restructure_abort — unpausing here would let
        // deposits/withdraws cross a half-changed basket and strand the
        // session (settle/abort require status 4). WITHOUT a live session an
        // orphaned status 4 has no other recovery path, so unpause stays
        // available as the rescue hatch.
        VaultStatus::Restructuring => {
            require!(!session_alive, WagonError::RestructuringInProgress);
            vault.set_status(VaultStatus::Active);
        }
        _ => return err!(WagonError::Unsupported),
    };
    emit!(VaultPauseChanged {
        vault: vault.key(),
        paused: false
    });
    Ok(())
}


// ─── Retirada del AllowedMintRegistry (2026-07-03) ──────────────────────────
//
// El registro de mints permitidos llevaba MUERTO desde que el gating pasó al
// FeedRegistry + suelo de liquidez: `create_vault` exigía la cuenta pero no
// la leía. Esta instrucción one-shot lo cierra y devuelve su rent (~0,026
// SOL) a la autoridad (el vault de Squads, que firma la ejecución). Las
// instrucciones init/add/remove_allowed_mint ya no existen en el programa,
// así que el registro no puede volver a crearse.

#[derive(Accounts)]
pub struct CloseAllowedMintRegistry<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        has_one = authority @ WagonError::UnauthorizedProtocolAdmin,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// CHECK: PDA at [ALLOWED_MINTS_SEED] — address forced by the seeds
    /// constraint; the handler additionally requires owner == this program
    /// (i.e. the registry still exists and wasn't closed already).
    #[account(mut, seeds = [ALLOWED_MINTS_SEED], bump)]
    pub allowed_mints: UncheckedAccount<'info>,
}

pub fn close_allowed_mint_registry_handler(ctx: Context<CloseAllowedMintRegistry>) -> Result<()> {
    let registry_ai = ctx.accounts.allowed_mints.to_account_info();
    require_keys_eq!(
        *registry_ai.owner,
        crate::ID,
        WagonError::AllowedMintRegistryNotOpen
    );

    // Cierre manual — misma secuencia que el `close` de Anchor: rent a la
    // autoridad, lamports a 0, assign al System Program, datos a 0 bytes.
    let authority_ai = ctx.accounts.authority.to_account_info();
    let lamports = registry_ai.lamports();
    **authority_ai.try_borrow_mut_lamports()? = authority_ai
        .lamports()
        .checked_add(lamports)
        .ok_or(WagonError::MathOverflow)?;
    **registry_ai.try_borrow_mut_lamports()? = 0;
    registry_ai.assign(&anchor_lang::system_program::ID);
    registry_ai.realloc(0, false)?;

    let protocol = &mut ctx.accounts.protocol;
    protocol.last_admin_action_ts = Clock::get()?.unix_timestamp;

    emit!(AllowedMintRegistryClosed {
        authority: ctx.accounts.authority.key(),
        lamports_recovered: lamports,
    });
    Ok(())
}

/// Ceremonia #37 — umbral del guard de pérdida máxima por COMPRA en los
/// swaps (piso de valor-oráculo por leg). En bps sobre lo gastado; 0 = guard
/// APAGADO. Los init lo sellan en la sesión, así que encenderlo NUNCA atrapa
/// operaciones en vuelo (completan con el valor que tenían al arrancar).
pub fn set_swap_max_loss_handler(ctx: Context<ProtocolAdmin>, max_loss_bps: u16) -> Result<()> {
    require!(
        max_loss_bps <= crate::constants::SWAP_MAX_LOSS_MAX_BPS,
        WagonError::InvalidEntryFeeParams
    );
    let protocol = &mut ctx.accounts.protocol;
    protocol.swap_max_loss_bps = max_loss_bps;
    protocol.last_admin_action_ts = Clock::get()?.unix_timestamp;
    emit!(SwapMaxLossChanged { max_loss_bps });
    Ok(())
}
