//! `RestructureSession` — upgrade #31: in-flight strategy change.
//!
//! Created by `restructure_init`, consumed by `restructure_settle` /
//! `restructure_abort`. While it exists the vault sits in
//! `VaultStatus::Restructuring` and every deposit/withdraw/rebalance path
//! is blocked, so a withdrawal can never cross a half-changed basket.
//! Funds never leave the vault during the whole flow — sells park in the
//! vault's USDC ATA and buys land in the vault's new-token ATAs — which is
//! what makes `restructure_abort` always safe.
//!
//! One session per vault (PDA seeds ["restructure", vault]).

use anchor_lang::prelude::*;

use crate::constants::MAX_TOKENS_PER_VAULT;

#[account]
pub struct RestructureSession {
    /// Creator who initiated the restructure (only they can drive it
    /// before the abort timeout).
    pub creator: Pubkey,
    /// Vault being restructured.
    pub vault: Pubkey,

    /// Target basket.
    pub new_count: u8,
    pub new_mints: [Pubkey; MAX_TOKENS_PER_VAULT],
    pub new_weights_bps: [u16; MAX_TOKENS_PER_VAULT],

    /// Progress bitmaps, one bit per slot index.
    /// sells: old-table indexes fully sold to USDC.
    /// buys:  new-table indexes fully bought from USDC.
    pub sells_done: u16,
    pub buys_done: u16,

    /// Per-NEW-index fill record (written by buy legs) used at settle to
    /// seed the last-swap price cache + decimals for the new table, so
    /// no-feed mints are born primed and strict deposits keep working.
    pub buy_usdc_in: [u64; MAX_TOKENS_PER_VAULT],
    pub buy_tokens_out: [u64; MAX_TOKENS_PER_VAULT],

    pub created_at: i64,
    pub bump: u8,

    /// Ceremonia #37: umbral del guard de pérdida por compra, SELLADO desde
    /// `protocol.swap_max_loss_bps` en `restructure_init` (los swap_batch no
    /// llevan la cuenta protocol; las sesiones pre-encendido llevan 0 → una
    /// reestructuración en vuelo nunca queda atrapada). Carved from _reserved.
    pub max_loss_bps: u16,

    pub _reserved: [u8; 30],
}

impl RestructureSession {
    pub const LEN: usize = 8      // discriminator
        + 32 + 32                 // creator, vault
        + 1                       // new_count
        + 32 * MAX_TOKENS_PER_VAULT   // new_mints
        + 2 * MAX_TOKENS_PER_VAULT    // new_weights_bps
        + 2 + 2                   // bitmaps
        + 8 * MAX_TOKENS_PER_VAULT    // buy_usdc_in
        + 8 * MAX_TOKENS_PER_VAULT    // buy_tokens_out
        + 8                       // created_at
        + 1                       // bump
        + 2                       // max_loss_bps (ceremonia #37)
        + 30; // reserved

    pub fn sells_complete(&self, old_non_usdc_mask: u16) -> bool {
        (self.sells_done & old_non_usdc_mask) == old_non_usdc_mask
    }
    pub fn buys_complete(&self, new_non_usdc_mask: u16) -> bool {
        (self.buys_done & new_non_usdc_mask) == new_non_usdc_mask
    }
}

/// Seconds after which `restructure_abort` becomes permissionless.
pub const RESTRUCTURE_ABORT_TIMEOUT_SECS: i64 = 1_800;
/// Ceremonia #49 (M1): ventana de abort permissionless MÁS CORTA cuando la
/// reestructuración aún no ha comprado nada (`buys_done == 0`). El griefing puro
/// (init sin swaps) y la fase de solo-ventas son abortables por cualquiera a los
/// 5 min (sin pérdida de fondos ni tokens fuera de tabla: el USDC de las ventas se
/// reparte siempre en el retiro). Con compras en vuelo (`buys_done != 0`) se
/// conserva el timeout largo para que un tercero no aborte una reestructuración
/// legítima y deje tokens fuera de tabla antes de que el creador re-tabule.
pub const RESTRUCTURE_ABORT_SHORT_SECS: i64 = 300;

/// Residual dust allowed per outgoing allocation at settle, expressed in
/// USDC atoms via the session's own sale price (see settle handler).
pub const RESTRUCTURE_DUST_USDC_ATOMS: u64 = 10_000; // 0.01 USDC
