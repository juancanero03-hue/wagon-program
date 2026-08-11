//! `FeedRegistry` — admin-curated mapping mint → Pyth feed id.
//!
//! Upgrade #30 (TVL mark-to-market). The program only accepts a Pyth
//! `PriceUpdateV2` account for a given mint if its `feed_id` matches the
//! entry stored here, so the frontend (or any caller) cannot substitute a
//! wrong or malicious feed. Authority = protocol authority (Squads vault).
//!
//! Sized like `AllowedMintRegistry`: fixed table, byte-level access via
//! `state::feed_registry_layout` (never materialised on the BPF stack —
//! at ~5.7 KB this struct is even bigger than the mint registry that
//! originally caused the stack overflows; see ADR 0004).

use anchor_lang::prelude::*;

use crate::constants::MAX_PRICE_FEEDS;

/// One mint → feed mapping (88 bytes).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug)]
pub struct FeedEntry {
    /// SPL / Token-2022 mint this feed prices.
    pub mint: Pubkey,
    /// Pyth feed id (32 bytes, as served by Hermes and embedded in
    /// `PriceUpdateV2.price_message.feed_id`).
    pub feed_id: [u8; 32],
    /// Bit 0-1: asset class (0=stable, 1=major, 2=xstock, 3=longtail) —
    /// selects staleness/confidence thresholds. Bit 2: composed redemption
    /// rate (price = this RR feed × SOL/USD). Bit 3: SIN ORÁCULO UTILIZABLE
    /// (ceremonia #40; era el bit de Switchboard On-Demand del upgrade #36).
    /// Bits 4-7 reserved (must be 0).
    pub flags: u8,
    pub added_at: i64,
    pub reserved: [u8; 15],
}

impl FeedEntry {
    pub const LEN: usize = 32 + 32 + 1 + 8 + 15;
}

#[account]
pub struct FeedRegistry {
    pub authority: Pubkey,
    pub count: u16,
    pub entries: [FeedEntry; MAX_PRICE_FEEDS],
    pub bump: u8,
    pub reserved: [u8; 32],
}

impl FeedRegistry {
    pub const LEN: usize = 8 + 32 + 2 + FeedEntry::LEN * MAX_PRICE_FEEDS + 1 + 32;
}

// ---- flags bit semantics ----------------------------------------------------

pub const FEED_CLASS_MASK: u8 = 0b0000_0011;
pub const FEED_CLASS_STABLE: u8 = 0;
pub const FEED_CLASS_MAJOR: u8 = 1;
pub const FEED_CLASS_XSTOCK: u8 = 2;
pub const FEED_CLASS_LONGTAIL: u8 = 3;
/// Price must be composed: entry feed is a redemption rate (e.g.
/// Crypto.JUPSOL/SOL.RR) to be multiplied by SOL/USD.
pub const FEED_FLAG_COMPOSED_RR: u8 = 0b0000_0100;
/// SIN ORÁCULO UTILIZABLE: la entrada existe en el registro pero su precio NO
/// se puede leer on-chain. `feed_id` queda como dato histórico y NO se usa.
///
/// Ceremonia #40 (2026-07-29): este bit era `FEED_FLAG_SWITCHBOARD` (upgrade
/// #36) y marcaba las 12 entradas cuyo precio venía de una quote de Switchboard
/// On-Demand. Switchboard dejó de servir esos feeds (caído desde el 23-jul; sus
/// 3 gateways devolviendo `ORACLE_UNAVAILABLE`) y el frontend ya no los enhebra
/// (PR #226), así que el bit se RESIGNIFICA en vez de tener que reescribir las
/// 12 entradas con `remove_feed` antes del upgrade. Semántica:
///
///   - camino ESTRICTO (depósito, mark_tvl, guard de compra) → falla cerrado
///     con `NoReliablePrice`, igual que un mint sin entrada en el registro.
///   - camino TOLERANTE (`sweep_to_usdc`, `rescue_untracked_token`) → se trata
///     como «sin feed»: SIN piso de precio, para que esos tokens se puedan
///     VENDER y los vaults que los llevan se puedan liquidar. Sin esto
///     quedarían en el peor sitio posible: ni depositar ni liquidar.
///
/// Los `remove_feed` de esas 12 entradas van DESPUÉS del upgrade (liberan 12
/// huecos del registro); hasta entonces este bit es lo que las hace inofensivas.
pub const FEED_FLAG_NO_ORACLE: u8 = 0b0000_1000;
/// All bits a valid `flags` value may use today.
pub const FEED_FLAGS_VALID_MASK: u8 =
    FEED_CLASS_MASK | FEED_FLAG_COMPOSED_RR | FEED_FLAG_NO_ORACLE;
