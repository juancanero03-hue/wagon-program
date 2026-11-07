//! Cobro de las comisiones del CREADOR en USDC (ceremonia USDC, 2026-09-22):
//! creación de vault (`create_vault`) y rebalanceo / cambio de cesta
//! (`rebalance`, `restructure_init`). UNA sola copia (espíritu del refactor
//! R-1): las tres instrucciones la llaman cuando
//! `protocol.fee_currency_mode == FEE_CURRENCY_MODE_USDC`.
//!
//! Reglas: la ATA USDC del creador se verifica por derivación canónica + mint /
//! owner (como la comisión de entrada en `deposit_init`); la tesorería viene
//! key-pinned a `protocol.treasury_usdc_ata` (la ÚNICA fijada en `initialize`)
//! y debe ser PAGABLE (existe, mint USDC, no congelada). Estas tres operaciones
//! NO son salidas, así que un tesoro no pagable REVIERTE (`TreasuryNotPayable`),
//! a diferencia del DT-B del retiro. Con importe 0 no toca ninguna cuenta.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, spl_token, Transfer};

use crate::errors::WagonError;
use crate::state::ProtocolConfig;
use crate::token_io::{derive_live_ata, is_payable_usdc_ata, verify_token_account};

/// Cuentas que participan en el cobro (referencias a los `AccountInfo` del ctx).
pub struct CreatorFeeAccounts<'a, 'info> {
    pub creator: &'a AccountInfo<'info>,
    pub creator_usdc_ata: &'a AccountInfo<'info>,
    pub treasury_usdc_ata: &'a AccountInfo<'info>,
    pub token_program: &'a AccountInfo<'info>,
}

/// Transfiere `amount_usdc` (átomos) desde la ATA USDC canónica del creador a la
/// tesorería USDC del protocolo. Devuelve el importe cobrado (0 si `amount_usdc`
/// es 0: no se toca ni se valida ninguna cuenta).
pub fn charge_creator_fee_usdc<'info>(
    protocol: &ProtocolConfig,
    amount_usdc: u64,
    a: &CreatorFeeAccounts<'_, 'info>,
) -> Result<u64> {
    if amount_usdc == 0 {
        return Ok(0);
    }
    let usdc_mint = protocol.usdc_mint;
    // Origen: la ATA canónica del creador (USDC es del programa SPL clásico).
    require_keys_eq!(
        a.creator_usdc_ata.key(),
        derive_live_ata(a.creator.key, &usdc_mint, &spl_token::ID),
        WagonError::CreatorUsdcAtaMismatch
    );
    // Una ATA inexistente (dueño = System) o malformada muere aquí con el error
    // PROPIO del cobro, no con el genérico de `verify_token_account`
    // (`InvalidJupiterRoute`, engañoso en el camino del creador; revisión N3).
    verify_token_account(a.creator_usdc_ata, &usdc_mint, a.creator.key)
        .map_err(|_| error!(WagonError::CreatorUsdcAtaMismatch))?;
    // Destino: la tesorería fijada en initialize, y pagable (fail-closed si no).
    require_keys_eq!(
        a.treasury_usdc_ata.key(),
        protocol.treasury_usdc_ata,
        WagonError::FeeTreasuryUsdcMismatch
    );
    require!(
        is_payable_usdc_ata(a.treasury_usdc_ata, &usdc_mint, None),
        WagonError::TreasuryNotPayable
    );
    token::transfer(
        CpiContext::new(
            a.token_program.clone(),
            Transfer {
                from: a.creator_usdc_ata.clone(),
                to: a.treasury_usdc_ata.clone(),
                authority: a.creator.clone(),
            },
        ),
        amount_usdc,
    )?;
    Ok(amount_usdc)
}
