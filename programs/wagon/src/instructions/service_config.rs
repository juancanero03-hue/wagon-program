//! Ceremonia USDC §3.5 — `init_service_config` (crea el singleton `ServiceConfig`) y
//! `set_service_params` (edita topes y pausa). Solo la authority del protocolo (Squads).
//! El rent del singleton lo paga `payer`, SEPARADO de la authority: en la propuesta de
//! Squads es el vault de Squads (la tesorería SOL), no el multisig.
//!
//! D5: la tesorería del servicio es `protocol.treasury_usdc_ata` (la ÚNICA fijada en
//! `initialize`); al crear se exige key-pinned (su espejo aquí es informativo, sin setter)
//! y NO que sea pagable: eso lo comprueba cada cobro, y exigirlo aquí solo podría dejar
//! la creación atada a un incidente de la tesorería.
use anchor_lang::prelude::*;

use crate::constants::{PROTOCOL_SEED, SERVICE_CONFIG_SEED};
use crate::errors::WagonError;
use crate::events::{ServiceConfigInitialized, ServiceParamsChanged};
use crate::service::validate_service_params;
use crate::state::{ProtocolConfig, ServiceConfig};

/// Los mismos parámetros para crear y para editar (una sola forma en el IDL).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug)]
pub struct ServiceParamsArgs {
    /// Topes de S por operación de entrada: 0 publicar · 1 depositar · 2 rebalancear ·
    /// 3 cambiar cesta (átomos de USDC, cada uno hasta 50 USDC).
    pub max_service_usdc: [u64; 4],
    /// Tope del S de salida por exceso (D3, PR 5B).
    pub max_exit_service_usdc: u64,
    /// 0 activo · 1 en pausa (Squads puede CREAR el singleton ya en pausa).
    pub paused: u8,
}

#[derive(Accounts)]
pub struct InitServiceConfig<'info> {
    pub authority: Signer<'info>,

    /// Paga el rent del singleton (el vault de Squads en la propuesta).
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        mut,
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        has_one = authority @ WagonError::UnauthorizedProtocolAdmin,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    #[account(
        init,
        payer = payer,
        space = ServiceConfig::LEN,
        seeds = [SERVICE_CONFIG_SEED],
        bump,
    )]
    pub service_config: Box<Account<'info, ServiceConfig>>,

    /// CHECK: key == `protocol.treasury_usdc_ata` (handler).
    pub treasury_usdc_ata: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub fn init_handler(ctx: Context<InitServiceConfig>, args: ServiceParamsArgs) -> Result<()> {
    validate_service_params(&args.max_service_usdc, args.max_exit_service_usdc, args.paused)?;
    let treasury = ctx.accounts.protocol.treasury_usdc_ata;
    require_keys_eq!(
        ctx.accounts.treasury_usdc_ata.key(),
        treasury,
        WagonError::ServiceTreasuryMismatch
    );
    let cfg = &mut ctx.accounts.service_config;
    cfg.treasury_usdc_ata = treasury;
    cfg.max_service_usdc = args.max_service_usdc;
    cfg.max_exit_service_usdc = args.max_exit_service_usdc;
    cfg.paused = args.paused;
    cfg.bump = ctx.bumps.service_config;
    cfg._reserved = [0u8; 46];
    ctx.accounts.protocol.last_admin_action_ts = Clock::get()?.unix_timestamp;
    emit!(ServiceConfigInitialized {
        treasury_usdc_ata: treasury,
        payer: ctx.accounts.payer.key(),
        max_service_usdc: args.max_service_usdc,
        max_exit_service_usdc: args.max_exit_service_usdc,
        paused: args.paused,
    });
    Ok(())
}

#[derive(Accounts)]
pub struct SetServiceParams<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        has_one = authority @ WagonError::UnauthorizedProtocolAdmin,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    #[account(mut, seeds = [SERVICE_CONFIG_SEED], bump = service_config.bump)]
    pub service_config: Box<Account<'info, ServiceConfig>>,
}

pub fn set_handler(ctx: Context<SetServiceParams>, args: ServiceParamsArgs) -> Result<()> {
    validate_service_params(&args.max_service_usdc, args.max_exit_service_usdc, args.paused)?;
    let cfg = &mut ctx.accounts.service_config;
    cfg.max_service_usdc = args.max_service_usdc;
    cfg.max_exit_service_usdc = args.max_exit_service_usdc;
    cfg.paused = args.paused;
    ctx.accounts.protocol.last_admin_action_ts = Clock::get()?.unix_timestamp;
    emit!(ServiceParamsChanged {
        max_service_usdc: args.max_service_usdc,
        max_exit_service_usdc: args.max_exit_service_usdc,
        paused: args.paused,
    });
    Ok(())
}
