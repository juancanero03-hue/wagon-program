//! Byte-level layout of `VaultState` and helpers to write it WITHOUT ever
//! materialising the full struct on the BPF stack.
//!
//! # Why
//!
//! `VaultState` weighs 1,508 bytes of fields (32 + 8 + 32 + 32 + 1 + 32 + 256 +
//! 128 + 64 + 2 + 2 + 1 + 740 + 8*6 + 1 + 1 + 128), i.e. `VAULT_TOTAL_LEN` =
//! 1,516 with the 8-byte discriminator. (Ceremonia #41: aquí ponía 1,388, que
//! no cuadraba con la propia suma de al lado — comprobado.) When Anchor's
//! `Account<T>`
//! deserialises it during `try_accounts` for `init`, plus the create_account
//! CPI plus the share_mint and vault_usdc_ata init CPIs, the cumulative
//! transient stack copies overflow the 4 KB BPF stack frame.
//!
//! Empirically:
//!   - `Account<VaultState>` (no Box) → frame 3 (CU=2802)
//!   - `Box<Account<VaultState>>`     → frame 5 (CU=5913)
//!   - byte-level write (this module) → no struct ever on stack
//!
//! (El difunto allowed_mints_layout usaba este mismo enfoque.)
//! The struct itself is kept in `state::vault` for IDL / TypeScript client
//! convenience but `create_vault` never constructs it by value.
//!
//! # Layout (Anchor-Borsh, packed, little-endian)
//!
//! ```text
//! offset    size    field
//! ------    ----    -------------------------------------------------------
//!     0       8     discriminator
//!     8      32     creator (Pubkey)
//!    40       8     nonce (u64 LE)
//!    48      32     share_mint (Pubkey)
//!    80      32     usdc_ata (Pubkey)
//!   112       1     status (u8)
//!   113      32     name ([u8; 32])
//!   145     256     description ([u8; 256])
//!   401     128     image_url ([u8; 128])
//!   529      64     tags ([u8; 64])
//!   593       2     performance_fee_bps (u16 LE)
//!   595       2     max_slippage_bps (u16 LE)
//!   597       1     allocation_count (u8)
//!   598     740     allocations ([TokenAllocation; 10])
//!  1338       8     total_shares (u64 LE)
//!  1346       8     aggregate_cost_basis_usdc (u64 LE)
//!  1354       8     tvl_last_computed_usdc (u64 LE)
//!  1362       8     last_fee_accrual_ts (i64 LE)
//!  1370       8     created_at (i64 LE)
//!  1378       8     liquidation_started_at (i64 LE)
//!  1386       1     bump (u8)
//!  1387       1     share_mint_bump (u8)
//!  1388     128     reserved
//!
//! Total: 1516 bytes
//!
//! Each TokenAllocation entry (74 bytes):
//!     0      32     mint (Pubkey)
//!    32       2     weight_bps (u16 LE)
//!    34      32     vault_ata (Pubkey)
//!    66       8     reserved ([u8; 8])
//! ```

use anchor_lang::prelude::*;
use anchor_lang::Discriminator;

use crate::constants::{
    MAX_TOKENS_PER_VAULT, VAULT_DESC_LEN, VAULT_IMAGE_URL_LEN, VAULT_NAME_LEN, VAULT_TAGS_LEN,
};
use crate::state::VaultState;

// ---- top-level offsets ------------------------------------------------------

pub const DISC_OFFSET: usize = 0;
pub const DISC_LEN: usize = 8;

pub const CREATOR_OFFSET: usize = 8;
pub const NONCE_OFFSET: usize = 40;
pub const SHARE_MINT_OFFSET: usize = 48;
pub const USDC_ATA_OFFSET: usize = 80;
pub const STATUS_OFFSET: usize = 112;
pub const NAME_OFFSET: usize = 113;
pub const DESC_OFFSET: usize = NAME_OFFSET + VAULT_NAME_LEN; // 145
pub const IMAGE_URL_OFFSET: usize = DESC_OFFSET + VAULT_DESC_LEN; // 401
pub const TAGS_OFFSET: usize = IMAGE_URL_OFFSET + VAULT_IMAGE_URL_LEN; // 529
pub const PERF_FEE_OFFSET: usize = TAGS_OFFSET + VAULT_TAGS_LEN; // 593
pub const SLIPPAGE_OFFSET: usize = PERF_FEE_OFFSET + 2; // 595
pub const ALLOC_COUNT_OFFSET: usize = SLIPPAGE_OFFSET + 2; // 597
pub const ALLOCATIONS_OFFSET: usize = ALLOC_COUNT_OFFSET + 1; // 598

pub const ALLOC_LEN: usize = 74;
pub const ALLOC_MINT_OFFSET: usize = 0; // within an allocation entry
pub const ALLOC_WEIGHT_OFFSET: usize = 32;
pub const ALLOC_VAULT_ATA_OFFSET: usize = 34;
pub const ALLOC_RESERVED_OFFSET: usize = 66;

pub const ALLOCATIONS_TOTAL_LEN: usize = ALLOC_LEN * MAX_TOKENS_PER_VAULT; // 740

pub const TOTAL_SHARES_OFFSET: usize = ALLOCATIONS_OFFSET + ALLOCATIONS_TOTAL_LEN; // 1338
pub const AGG_COST_OFFSET: usize = TOTAL_SHARES_OFFSET + 8; // 1346
pub const TVL_OFFSET: usize = AGG_COST_OFFSET + 8; // 1354
pub const LAST_FEE_ACCRUAL_OFFSET: usize = TVL_OFFSET + 8; // 1362
pub const CREATED_AT_OFFSET: usize = LAST_FEE_ACCRUAL_OFFSET + 8; // 1370
pub const LIQ_STARTED_OFFSET: usize = CREATED_AT_OFFSET + 8; // 1378
pub const BUMP_OFFSET: usize = LIQ_STARTED_OFFSET + 8; // 1386
pub const SHARE_MINT_BUMP_OFFSET: usize = BUMP_OFFSET + 1; // 1387
pub const RESERVED_OFFSET: usize = SHARE_MINT_BUMP_OFFSET + 1; // 1388
pub const RESERVED_LEN: usize = 128;

pub const VAULT_TOTAL_LEN: usize = RESERVED_OFFSET + RESERVED_LEN; // 1516

// ---- compile-time invariants ------------------------------------------------

const _: () = {
    assert!(
        VAULT_TOTAL_LEN == VaultState::LEN,
        "vault layout total len drifted from struct LEN"
    );
    assert!(
        ALLOC_LEN == 32 + 2 + 32 + 8,
        "allocation size changed; update offsets"
    );
};

// ---- byte write helpers (used by create_vault for initial population) ------

/// Write the Anchor discriminator at offset 0.
pub fn write_discriminator(data: &mut [u8]) -> Result<()> {
    if data.len() < DISC_LEN {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[..DISC_LEN].copy_from_slice(&VaultState::DISCRIMINATOR);
    Ok(())
}

pub fn write_creator(data: &mut [u8], creator: &Pubkey) -> Result<()> {
    if data.len() < CREATOR_OFFSET + 32 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[CREATOR_OFFSET..CREATOR_OFFSET + 32].copy_from_slice(&creator.to_bytes());
    Ok(())
}

pub fn write_nonce(data: &mut [u8], nonce: u64) -> Result<()> {
    if data.len() < NONCE_OFFSET + 8 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[NONCE_OFFSET..NONCE_OFFSET + 8].copy_from_slice(&nonce.to_le_bytes());
    Ok(())
}

pub fn write_share_mint(data: &mut [u8], pk: &Pubkey) -> Result<()> {
    if data.len() < SHARE_MINT_OFFSET + 32 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[SHARE_MINT_OFFSET..SHARE_MINT_OFFSET + 32].copy_from_slice(&pk.to_bytes());
    Ok(())
}

pub fn write_usdc_ata(data: &mut [u8], pk: &Pubkey) -> Result<()> {
    if data.len() < USDC_ATA_OFFSET + 32 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[USDC_ATA_OFFSET..USDC_ATA_OFFSET + 32].copy_from_slice(&pk.to_bytes());
    Ok(())
}

pub fn write_status(data: &mut [u8], status: u8) -> Result<()> {
    if data.len() < STATUS_OFFSET + 1 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[STATUS_OFFSET] = status;
    Ok(())
}

pub fn write_name(data: &mut [u8], name: &[u8; VAULT_NAME_LEN]) -> Result<()> {
    if data.len() < NAME_OFFSET + VAULT_NAME_LEN {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[NAME_OFFSET..NAME_OFFSET + VAULT_NAME_LEN].copy_from_slice(name);
    Ok(())
}

pub fn write_description(data: &mut [u8], desc: &[u8; VAULT_DESC_LEN]) -> Result<()> {
    if data.len() < DESC_OFFSET + VAULT_DESC_LEN {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[DESC_OFFSET..DESC_OFFSET + VAULT_DESC_LEN].copy_from_slice(desc);
    Ok(())
}

pub fn write_image_url(data: &mut [u8], img: &[u8; VAULT_IMAGE_URL_LEN]) -> Result<()> {
    if data.len() < IMAGE_URL_OFFSET + VAULT_IMAGE_URL_LEN {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[IMAGE_URL_OFFSET..IMAGE_URL_OFFSET + VAULT_IMAGE_URL_LEN].copy_from_slice(img);
    Ok(())
}

pub fn write_tags(data: &mut [u8], tags: &[u8; VAULT_TAGS_LEN]) -> Result<()> {
    if data.len() < TAGS_OFFSET + VAULT_TAGS_LEN {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[TAGS_OFFSET..TAGS_OFFSET + VAULT_TAGS_LEN].copy_from_slice(tags);
    Ok(())
}

pub fn write_performance_fee_bps(data: &mut [u8], v: u16) -> Result<()> {
    if data.len() < PERF_FEE_OFFSET + 2 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[PERF_FEE_OFFSET..PERF_FEE_OFFSET + 2].copy_from_slice(&v.to_le_bytes());
    Ok(())
}

pub fn write_max_slippage_bps(data: &mut [u8], v: u16) -> Result<()> {
    if data.len() < SLIPPAGE_OFFSET + 2 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[SLIPPAGE_OFFSET..SLIPPAGE_OFFSET + 2].copy_from_slice(&v.to_le_bytes());
    Ok(())
}

pub fn write_allocation_count(data: &mut [u8], v: u8) -> Result<()> {
    if data.len() < ALLOC_COUNT_OFFSET + 1 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[ALLOC_COUNT_OFFSET] = v;
    Ok(())
}

/// Write one TokenAllocation entry at slot index `i`.
pub fn write_allocation(
    data: &mut [u8],
    i: usize,
    mint: &Pubkey,
    weight_bps: u16,
    vault_ata: &Pubkey,
) -> Result<()> {
    if i >= MAX_TOKENS_PER_VAULT {
        return err!(crate::errors::WagonError::TooManyTokens);
    }
    let start = ALLOCATIONS_OFFSET + i * ALLOC_LEN;
    if data.len() < start + ALLOC_LEN {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[start + ALLOC_MINT_OFFSET..start + ALLOC_MINT_OFFSET + 32]
        .copy_from_slice(&mint.to_bytes());
    data[start + ALLOC_WEIGHT_OFFSET..start + ALLOC_WEIGHT_OFFSET + 2]
        .copy_from_slice(&weight_bps.to_le_bytes());
    data[start + ALLOC_VAULT_ATA_OFFSET..start + ALLOC_VAULT_ATA_OFFSET + 32]
        .copy_from_slice(&vault_ata.to_bytes());
    // reserved stays as zero from create_account.
    // ⚠️ Ceremonia #43: NUNCA cero-inicializar ni escribir los bytes 66-73 del
    // reserved de un slot aquí. El slot 0 aloja [66..68] la caché de decimales y
    // [68..70] el CONTADOR de depósitos comprometidos (COMMITTED_DEPOSITS_OFFSET,
    // abajo). Esta función los PRESERVA a propósito; un memset regresionaría el
    // contador y reabriría el robo OT-1.
    Ok(())
}

pub fn write_last_fee_accrual_ts(data: &mut [u8], ts: i64) -> Result<()> {
    if data.len() < LAST_FEE_ACCRUAL_OFFSET + 8 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[LAST_FEE_ACCRUAL_OFFSET..LAST_FEE_ACCRUAL_OFFSET + 8].copy_from_slice(&ts.to_le_bytes());
    Ok(())
}

pub fn write_created_at(data: &mut [u8], ts: i64) -> Result<()> {
    if data.len() < CREATED_AT_OFFSET + 8 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[CREATED_AT_OFFSET..CREATED_AT_OFFSET + 8].copy_from_slice(&ts.to_le_bytes());
    Ok(())
}

pub fn write_bump(data: &mut [u8], bump: u8) -> Result<()> {
    if data.len() < BUMP_OFFSET + 1 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[BUMP_OFFSET] = bump;
    Ok(())
}

pub fn write_share_mint_bump(data: &mut [u8], bump: u8) -> Result<()> {
    if data.len() < SHARE_MINT_BUMP_OFFSET + 1 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[SHARE_MINT_BUMP_OFFSET] = bump;
    Ok(())
}

// =============================================================================
// READ HELPERS — for handlers that do NOT init (deposit, withdraw, rebalance,
// etc.). These let the handler pull individual fields off the account bytes
// without materialising the whole VaultState struct on the BPF stack.
// =============================================================================

pub fn read_creator(data: &[u8]) -> Result<Pubkey> {
    if data.len() < CREATOR_OFFSET + 32 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&data[CREATOR_OFFSET..CREATOR_OFFSET + 32]);
    Ok(Pubkey::new_from_array(buf))
}

pub fn read_nonce(data: &[u8]) -> Result<u64> {
    if data.len() < NONCE_OFFSET + 8 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[NONCE_OFFSET..NONCE_OFFSET + 8]);
    Ok(u64::from_le_bytes(buf))
}

pub fn read_share_mint(data: &[u8]) -> Result<Pubkey> {
    if data.len() < SHARE_MINT_OFFSET + 32 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&data[SHARE_MINT_OFFSET..SHARE_MINT_OFFSET + 32]);
    Ok(Pubkey::new_from_array(buf))
}

pub fn read_usdc_ata(data: &[u8]) -> Result<Pubkey> {
    if data.len() < USDC_ATA_OFFSET + 32 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&data[USDC_ATA_OFFSET..USDC_ATA_OFFSET + 32]);
    Ok(Pubkey::new_from_array(buf))
}

pub fn read_status(data: &[u8]) -> Result<u8> {
    if data.len() < STATUS_OFFSET + 1 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    Ok(data[STATUS_OFFSET])
}

pub fn read_performance_fee_bps(data: &[u8]) -> Result<u16> {
    if data.len() < PERF_FEE_OFFSET + 2 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&data[PERF_FEE_OFFSET..PERF_FEE_OFFSET + 2]);
    Ok(u16::from_le_bytes(buf))
}

pub fn read_max_slippage_bps(data: &[u8]) -> Result<u16> {
    if data.len() < SLIPPAGE_OFFSET + 2 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&data[SLIPPAGE_OFFSET..SLIPPAGE_OFFSET + 2]);
    Ok(u16::from_le_bytes(buf))
}

pub fn read_allocation_count(data: &[u8]) -> Result<u8> {
    if data.len() < ALLOC_COUNT_OFFSET + 1 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    Ok(data[ALLOC_COUNT_OFFSET])
}

pub fn read_allocation_mint(data: &[u8], i: usize) -> Result<Pubkey> {
    if i >= MAX_TOKENS_PER_VAULT {
        return err!(crate::errors::WagonError::TooManyTokens);
    }
    let start = ALLOCATIONS_OFFSET + i * ALLOC_LEN + ALLOC_MINT_OFFSET;
    if data.len() < start + 32 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&data[start..start + 32]);
    Ok(Pubkey::new_from_array(buf))
}

pub fn read_allocation_weight_bps(data: &[u8], i: usize) -> Result<u16> {
    if i >= MAX_TOKENS_PER_VAULT {
        return err!(crate::errors::WagonError::TooManyTokens);
    }
    let start = ALLOCATIONS_OFFSET + i * ALLOC_LEN + ALLOC_WEIGHT_OFFSET;
    if data.len() < start + 2 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&data[start..start + 2]);
    Ok(u16::from_le_bytes(buf))
}

pub fn read_allocation_vault_ata(data: &[u8], i: usize) -> Result<Pubkey> {
    if i >= MAX_TOKENS_PER_VAULT {
        return err!(crate::errors::WagonError::TooManyTokens);
    }
    let start = ALLOCATIONS_OFFSET + i * ALLOC_LEN + ALLOC_VAULT_ATA_OFFSET;
    if data.len() < start + 32 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&data[start..start + 32]);
    Ok(Pubkey::new_from_array(buf))
}

pub fn read_total_shares(data: &[u8]) -> Result<u64> {
    if data.len() < TOTAL_SHARES_OFFSET + 8 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[TOTAL_SHARES_OFFSET..TOTAL_SHARES_OFFSET + 8]);
    Ok(u64::from_le_bytes(buf))
}

pub fn read_aggregate_cost_basis_usdc(data: &[u8]) -> Result<u64> {
    if data.len() < AGG_COST_OFFSET + 8 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[AGG_COST_OFFSET..AGG_COST_OFFSET + 8]);
    Ok(u64::from_le_bytes(buf))
}

pub fn read_tvl_last_computed_usdc(data: &[u8]) -> Result<u64> {
    if data.len() < TVL_OFFSET + 8 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[TVL_OFFSET..TVL_OFFSET + 8]);
    Ok(u64::from_le_bytes(buf))
}

pub fn read_bump(data: &[u8]) -> Result<u8> {
    if data.len() < BUMP_OFFSET + 1 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    Ok(data[BUMP_OFFSET])
}

// =============================================================================
// MUTATION WRITE HELPERS — used by deposit / withdraw / rebalance to update
// individual fields after computation.
// =============================================================================

pub fn write_total_shares(data: &mut [u8], v: u64) -> Result<()> {
    if data.len() < TOTAL_SHARES_OFFSET + 8 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[TOTAL_SHARES_OFFSET..TOTAL_SHARES_OFFSET + 8].copy_from_slice(&v.to_le_bytes());
    Ok(())
}

pub fn write_aggregate_cost_basis_usdc(data: &mut [u8], v: u64) -> Result<()> {
    if data.len() < AGG_COST_OFFSET + 8 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[AGG_COST_OFFSET..AGG_COST_OFFSET + 8].copy_from_slice(&v.to_le_bytes());
    Ok(())
}

pub fn write_tvl_last_computed_usdc(data: &mut [u8], v: u64) -> Result<()> {
    if data.len() < TVL_OFFSET + 8 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[TVL_OFFSET..TVL_OFFSET + 8].copy_from_slice(&v.to_le_bytes());
    Ok(())
}

pub fn write_liquidation_started_at(data: &mut [u8], ts: i64) -> Result<()> {
    if data.len() < LIQ_STARTED_OFFSET + 8 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[LIQ_STARTED_OFFSET..LIQ_STARTED_OFFSET + 8].copy_from_slice(&ts.to_le_bytes());
    Ok(())
}

// ---- upgrade #30: mark-to-market scratch area -------------------------------
//
// The vault tail `reserved` (offset 1388, 128 bytes) hosts a per-allocation
// last-swap price cache used as valuation fallback for mints without a Pyth
// feed (design doc DISENO-TVL-MARK-TO-MARKET-2026-06-10):
//
//   slot i (i < MAX_TOKENS_PER_VAULT):
//     RESERVED_OFFSET + i*12 + 0 .. 8   price_q (u64 LE)
//     RESERVED_OFFSET + i*12 + 8 .. 12  last_swap_ts (u32 LE, unix seconds)
//
//   price_q units: USDC atoms (6 dec) per 1_000_000_000 token atoms. This
//   scale is decimals-agnostic: value_usdc = balance_atoms * price_q / 1e9.
//   price_q == 0 means "no price cached" (all existing vaults read as zero
//   because create_account zero-initialises the reserved tail).
//
// The per-allocation `reserved` 8 bytes (ALLOC_RESERVED_OFFSET) host the
// mint decimals cache needed by the Pyth path:
//     byte 0: decimals
//     byte 1: 1 = decimals_set, 0 = unset (legacy vaults)
//
// 10*12 = 120 of the 128 tail bytes are used; the final 8 stay reserved.

pub const LAST_SWAP_SLOT_LEN: usize = 12;
/// price_q scale: USDC atoms per this many token atoms.
pub const LAST_SWAP_PRICE_SCALE: u128 = 1_000_000_000;

const _: () = assert!(
    LAST_SWAP_SLOT_LEN * MAX_TOKENS_PER_VAULT <= RESERVED_LEN,
    "last-swap cache no longer fits in the vault reserved tail"
);

/// Read (price_q, last_swap_ts) for allocation `i`. (0, 0) = never cached.
pub fn read_alloc_last_swap(data: &[u8], i: usize) -> Result<(u64, u32)> {
    if i >= MAX_TOKENS_PER_VAULT {
        return err!(crate::errors::WagonError::LegIndexOutOfRange);
    }
    let start = RESERVED_OFFSET + i * LAST_SWAP_SLOT_LEN;
    if data.len() < start + LAST_SWAP_SLOT_LEN {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut p = [0u8; 8];
    p.copy_from_slice(&data[start..start + 8]);
    let mut t = [0u8; 4];
    t.copy_from_slice(&data[start + 8..start + 12]);
    Ok((u64::from_le_bytes(p), u32::from_le_bytes(t)))
}

/// Write (price_q, last_swap_ts) for allocation `i`.
pub fn write_alloc_last_swap(data: &mut [u8], i: usize, price_q: u64, ts: u32) -> Result<()> {
    if i >= MAX_TOKENS_PER_VAULT {
        return err!(crate::errors::WagonError::LegIndexOutOfRange);
    }
    let start = RESERVED_OFFSET + i * LAST_SWAP_SLOT_LEN;
    if data.len() < start + LAST_SWAP_SLOT_LEN {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[start..start + 8].copy_from_slice(&price_q.to_le_bytes());
    data[start + 8..start + 12].copy_from_slice(&ts.to_le_bytes());
    Ok(())
}

/// Read the cached mint decimals for allocation `i`. None = not cached yet.
pub fn read_alloc_decimals(data: &[u8], i: usize) -> Result<Option<u8>> {
    if i >= MAX_TOKENS_PER_VAULT {
        return err!(crate::errors::WagonError::LegIndexOutOfRange);
    }
    let start = ALLOCATIONS_OFFSET + i * ALLOC_LEN + ALLOC_RESERVED_OFFSET;
    if data.len() < start + 2 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    if data[start + 1] != 1 {
        return Ok(None);
    }
    Ok(Some(data[start]))
}

/// Cache the mint decimals for allocation `i`.
pub fn write_alloc_decimals(data: &mut [u8], i: usize, decimals: u8) -> Result<()> {
    if i >= MAX_TOKENS_PER_VAULT {
        return err!(crate::errors::WagonError::LegIndexOutOfRange);
    }
    let start = ALLOCATIONS_OFFSET + i * ALLOC_LEN + ALLOC_RESERVED_OFFSET;
    if data.len() < start + 2 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[start] = decimals;
    data[start + 1] = 1;
    Ok(())
}

// ---- upgrade #31: marca temporal de la última reestructuración --------------
//
// Los 8 bytes finales del tail reservado (offset 1508) guardan
// `last_restructured_at` (i64 LE, unix). Cero = nunca reestructurado (todos
// los vaults existentes leen cero sin migración). Las sesiones de depósito/
// retiro creadas ANTES de una reestructuración quedan invalidadas comparando
// su `created_at` contra este campo — así un flujo a medias no puede operar
// sobre una tabla de allocations que ya no es la suya.

pub const LAST_RESTRUCTURED_AT_OFFSET: usize =
    RESERVED_OFFSET + LAST_SWAP_SLOT_LEN * MAX_TOKENS_PER_VAULT; // 1508

const _: () = assert!(
    LAST_RESTRUCTURED_AT_OFFSET + 8 <= VAULT_TOTAL_LEN,
    "last_restructured_at no longer fits in the vault reserved tail"
);

pub fn read_last_restructured_at(data: &[u8]) -> Result<i64> {
    if data.len() < LAST_RESTRUCTURED_AT_OFFSET + 8 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[LAST_RESTRUCTURED_AT_OFFSET..LAST_RESTRUCTURED_AT_OFFSET + 8]);
    Ok(i64::from_le_bytes(b))
}

pub fn write_last_restructured_at(data: &mut [u8], ts: i64) -> Result<()> {
    if data.len() < LAST_RESTRUCTURED_AT_OFFSET + 8 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[LAST_RESTRUCTURED_AT_OFFSET..LAST_RESTRUCTURED_AT_OFFSET + 8]
        .copy_from_slice(&ts.to_le_bytes());
    Ok(())
}

/// Borra el caché de decimales del slot `i` (flag a 0). Usado por
/// restructure_settle al vaciar slots sobrantes.
pub fn clear_alloc_decimals(data: &mut [u8], i: usize) -> Result<()> {
    if i >= MAX_TOKENS_PER_VAULT {
        return err!(crate::errors::WagonError::LegIndexOutOfRange);
    }
    let start = ALLOCATIONS_OFFSET + i * ALLOC_LEN + ALLOC_RESERVED_OFFSET;
    if data.len() < start + 2 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[start] = 0;
    data[start + 1] = 0;
    Ok(())
}

// ---- ceremonia #43: contador de depósitos COMPROMETIDOS por vault -----------
//
// `u16` LE alojado en `allocations[0].reserved[2..4]` = offset absoluto 666.
// Cuenta las sesiones de depósito que YA barrieron sus tokens al vault
// (COMPROMETIDAS: `legs_swept != 0 && aborting == 0`) y aún no se han asentado —
// el instante en que su valor está dentro del vault sin participaciones que lo
// representen. `close_vault` / `restructure_init` / `finalize_close` exigen que
// sea 0 para no sacar el vault de Active con un depósito así en vuelo (robo OT-1,
// donde ese valor se repartiría a los demás titulares).
//
// Se incrementa en `deposit_sweep_batch` (dirección settle, transición
// `legs_swept 0→≠0`) y se decrementa en `deposit_settle` (guardado por el mismo
// predicado `comprometida`). Carvado de los bytes ociosos del `reserved` del slot
// 0 (los decimales usan [0..2]); LEN sin cambio, sin migración: los vaults
// existentes leen 0 porque `create_account` cebó a cero y NINGÚN handler pre-#43
// escribió jamás estos bytes.

pub const COMMITTED_DEPOSITS_OFFSET: usize = ALLOCATIONS_OFFSET + ALLOC_RESERVED_OFFSET + 2; // 666

const _: () = {
    // Cae dentro del reserved del slot 0 (ALLOC_RESERVED_OFFSET..ALLOC_LEN) y NO
    // solapa la caché de decimales del slot 0 ([0..2] del reserved).
    assert!(COMMITTED_DEPOSITS_OFFSET == ALLOCATIONS_OFFSET + ALLOC_RESERVED_OFFSET + 2);
    assert!(COMMITTED_DEPOSITS_OFFSET + 2 <= ALLOCATIONS_OFFSET + ALLOC_LEN);
};

pub fn read_committed_deposits(data: &[u8]) -> Result<u16> {
    if data.len() < COMMITTED_DEPOSITS_OFFSET + 2 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut b = [0u8; 2];
    b.copy_from_slice(&data[COMMITTED_DEPOSITS_OFFSET..COMMITTED_DEPOSITS_OFFSET + 2]);
    Ok(u16::from_le_bytes(b))
}

pub fn write_committed_deposits(data: &mut [u8], v: u16) -> Result<()> {
    if data.len() < COMMITTED_DEPOSITS_OFFSET + 2 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[COMMITTED_DEPOSITS_OFFSET..COMMITTED_DEPOSITS_OFFSET + 2].copy_from_slice(&v.to_le_bytes());
    Ok(())
}

// ---- ceremonia #44 (F3): participaciones fantasma reservadas ----------------
//
// `pending_committed_shares` (u64 LE) = suma de las participaciones que las
// sesiones COMPROMETIDAS (barridas al vault, sin asentar) van a recibir al
// asentar. El retiro (`withdraw_init`) lo SUMA al denominador de sus patas de
// token para no repartir el depósito en vuelo (F3): con `slice_i = balance_i *
// shares / (total_shares_before + pending)`, el que retira valora contra un pool
// que ya cuenta el depósito comprometido en vez de contra uno inflado.
//
// Emparejado 1:1 con `committed_deposits`: sube en `deposit_sweep_batch`
// (dirección settle, transición `legs_swept 0→≠0`, con `checked_add`) y baja en
// `deposit_settle` (mismo predicado `comprometida`, con `saturating_sub`), usando
// en AMBOS lados `phantom_shares()` sobre los MISMOS campos inmutables de la
// sesión → el par sube/baja cuadra exacto sin almacenar P por sesión.
//
// Almacenamiento: un u64 NO cabe en los bytes ociosos de un solo slot (cada
// `reserved` de pata tiene [0..2] decimales; el slot 0 además [2..4] = contador
// #43). Se parte: los 48 bits bajos en `allocations[1].reserved[2..8]` (offset
// 740..746) y los 16 altos en `allocations[2].reserved[2..4]` (814..816). Ambos
// rangos están LIBRES (verificado: ningún handler los escribe; `write_allocation`
// PRESERVA `reserved`, `write/clear_alloc_decimals` solo tocan [0..2] de su slot,
// `write_alloc_last_swap` vive en la COLA reservada @1388, otra región). LEN 1516
// SIN cambio, sin migración: los 49 vaults leen 0 (create_account cebó a cero).
// Los slots 1 y 2 existen SIEMPRE (array fijo [_; 10]) aunque allocation_count<3.
// ⚠️ Como `pending>0 ⟺ committed>0 ⟹ Active` y `restructure_init` está vetado con
// `committed>0`, durante cualquier reestructuración `pending==0`: nunca hay carrera
// con `write_allocation` sobre estos bytes.

pub const PENDING_SHARES_LO_OFFSET: usize =
    ALLOCATIONS_OFFSET + ALLOC_LEN + ALLOC_RESERVED_OFFSET + 2; // 740, slot 1, 6 bytes (48 bits bajos)
pub const PENDING_SHARES_HI_OFFSET: usize =
    ALLOCATIONS_OFFSET + 2 * ALLOC_LEN + ALLOC_RESERVED_OFFSET + 2; // 814, slot 2, 2 bytes (16 altos)

const _: () = {
    // LO: dentro del reserved del slot 1, NO solapa su caché de decimales [0..2].
    assert!(PENDING_SHARES_LO_OFFSET == ALLOCATIONS_OFFSET + ALLOC_LEN + ALLOC_RESERVED_OFFSET + 2);
    assert!(PENDING_SHARES_LO_OFFSET + 6 <= ALLOCATIONS_OFFSET + 2 * ALLOC_LEN); // <= fin del slot 1 (746)
    // HI: dentro del reserved del slot 2, NO solapa su caché de decimales [0..2].
    assert!(PENDING_SHARES_HI_OFFSET == ALLOCATIONS_OFFSET + 2 * ALLOC_LEN + ALLOC_RESERVED_OFFSET + 2);
    assert!(PENDING_SHARES_HI_OFFSET + 2 <= ALLOCATIONS_OFFSET + 3 * ALLOC_LEN); // <= fin del slot 2 (820)
    // No solapan el contador #43 del slot 0 (666..668) ni entre sí, y caen antes
    // de total_shares (1338) → dentro de la región de allocations.
    assert!(PENDING_SHARES_LO_OFFSET > COMMITTED_DEPOSITS_OFFSET + 2);
    assert!(PENDING_SHARES_LO_OFFSET + 6 <= PENDING_SHARES_HI_OFFSET);
    assert!(PENDING_SHARES_HI_OFFSET + 2 <= TOTAL_SHARES_OFFSET);
};

pub fn read_pending_committed_shares(data: &[u8]) -> Result<u64> {
    if data.len() < PENDING_SHARES_HI_OFFSET + 2 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut lo = [0u8; 8];
    lo[..6].copy_from_slice(&data[PENDING_SHARES_LO_OFFSET..PENDING_SHARES_LO_OFFSET + 6]);
    let low48 = u64::from_le_bytes(lo); // los 2 bytes altos quedan a 0
    let mut hi = [0u8; 2];
    hi.copy_from_slice(&data[PENDING_SHARES_HI_OFFSET..PENDING_SHARES_HI_OFFSET + 2]);
    let high16 = u16::from_le_bytes(hi) as u64;
    Ok(low48 | (high16 << 48))
}

pub fn write_pending_committed_shares(data: &mut [u8], v: u64) -> Result<()> {
    if data.len() < PENDING_SHARES_HI_OFFSET + 2 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let low48 = (v & 0x0000_ffff_ffff_ffff).to_le_bytes(); // 8 bytes, los 2 altos son 0
    data[PENDING_SHARES_LO_OFFSET..PENDING_SHARES_LO_OFFSET + 6].copy_from_slice(&low48[..6]);
    let high16 = (v >> 48) as u16;
    data[PENDING_SHARES_HI_OFFSET..PENDING_SHARES_HI_OFFSET + 2].copy_from_slice(&high16.to_le_bytes());
    Ok(())
}

// ---- ceremonia #49 (A1): participaciones QUEMADAS pendientes de re-acuñar -----
//
// `pending_burned_shares` (u64 LE) = espejo por el lado RETIRO de
// `pending_committed_shares` (#44). Un retiro quema sus shares en `withdraw_init`
// (bajando `total_shares`) y saca sus slices de token al escrow. Si se ABORTA, el
// `withdraw_sweep_batch` (dirección abort) devuelve esos tokens AL VAULT y marca
// `aborting=1` en la MISMA ix, pero las shares no se re-acuñan hasta la ix aparte
// `withdraw_abort`. Entre ambas, el vault tiene el balance de token LLENO y
// `total_shares` DEFLACTADO → un `withdraw_init` concurrente valora el slice de
// token con un denominador demasiado pequeño y SOBRE-EXTRAE (espejo de F3).
//
// La cura suma `pending_burned_shares` al denominador del slice de TOKEN de
// `withdraw_init` (NO al de USDC: el escrow USDC vuelve al vault solo en
// `withdraw_abort`, atómico con la re-acuñación, así que su numerador y denominador
// quedan proporcionalmente deflactados y no necesitan compensación). Durante la
// ventana el denominador vuelve a ser (S − s1) + s1 = S = el total verdadero.
//
// Emparejado 1:1 con el ciclo del abort: SUBE en `withdraw_sweep_batch` SOLO en la
// transición `aborting 0→1` (leyendo el valor OLD antes de mutar, `checked_add`), y
// BAJA en `withdraw_abort` SOLO si `aborting==1` (guarda CRÍTICA: el rescate I3
// re-acuña con `aborting==0` sin haber incrementado, y un decremento incondicional
// robaría la reserva de OTRAS sesiones), con `saturating_sub`, usando en ambos lados
// el MISMO `session.shares_to_burn` inmutable → el par cuadra exacto.
//
// Almacenamiento (mismo patrón partido que #44): 48 bits bajos en
// `allocations[3].reserved[2..8]` (offset 888..894) y 16 altos en
// `allocations[4].reserved[2..4]` (962..964). Rangos LIBRES: `write_allocation`
// PRESERVA `reserved`, `write/clear_alloc_decimals` solo tocan [0..2] de su slot,
// `write_alloc_last_swap` vive en la COLA @1388. LEN 1516 SIN cambio, sin migración:
// los 49 vaults leen 0 (create_account cebó a cero). Los slots 3 y 4 existen SIEMPRE
// (array fijo [_; 10]). A diferencia de #44, `pending_burned>0` NO implica un estado
// que vete `restructure_init`; es INOFENSIVO porque `restructure_settle` PRESERVA
// `reserved[2..8]` de los slots (usa write_allocation/write_alloc_decimals[0..2]/
// write_alloc_last_swap@cola) → el contador se conserva a través de la reestructuración.

pub const PENDING_BURNED_LO_OFFSET: usize =
    ALLOCATIONS_OFFSET + 3 * ALLOC_LEN + ALLOC_RESERVED_OFFSET + 2; // 888, slot 3, 6 bytes (48 bajos)
pub const PENDING_BURNED_HI_OFFSET: usize =
    ALLOCATIONS_OFFSET + 4 * ALLOC_LEN + ALLOC_RESERVED_OFFSET + 2; // 962, slot 4, 2 bytes (16 altos)

const _: () = {
    // LO: dentro del reserved del slot 3, NO solapa su caché de decimales [0..2].
    assert!(PENDING_BURNED_LO_OFFSET == ALLOCATIONS_OFFSET + 3 * ALLOC_LEN + ALLOC_RESERVED_OFFSET + 2);
    assert!(PENDING_BURNED_LO_OFFSET + 6 <= ALLOCATIONS_OFFSET + 4 * ALLOC_LEN); // <= fin del slot 3 (894)
    // HI: dentro del reserved del slot 4, NO solapa su caché de decimales [0..2].
    assert!(PENDING_BURNED_HI_OFFSET == ALLOCATIONS_OFFSET + 4 * ALLOC_LEN + ALLOC_RESERVED_OFFSET + 2);
    assert!(PENDING_BURNED_HI_OFFSET + 2 <= ALLOCATIONS_OFFSET + 5 * ALLOC_LEN); // <= fin del slot 4 (968)
    // No solapan los contadores #43 (666) / #44 (740..746, 814..816), ni entre sí, y
    // caen antes de total_shares (1338) → dentro de la región de allocations.
    assert!(PENDING_BURNED_LO_OFFSET > PENDING_SHARES_HI_OFFSET + 2);
    assert!(PENDING_BURNED_LO_OFFSET + 6 <= PENDING_BURNED_HI_OFFSET);
    assert!(PENDING_BURNED_HI_OFFSET + 2 <= TOTAL_SHARES_OFFSET);
};

pub fn read_pending_burned_shares(data: &[u8]) -> Result<u64> {
    if data.len() < PENDING_BURNED_HI_OFFSET + 2 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut lo = [0u8; 8];
    lo[..6].copy_from_slice(&data[PENDING_BURNED_LO_OFFSET..PENDING_BURNED_LO_OFFSET + 6]);
    let low48 = u64::from_le_bytes(lo); // los 2 bytes altos quedan a 0
    let mut hi = [0u8; 2];
    hi.copy_from_slice(&data[PENDING_BURNED_HI_OFFSET..PENDING_BURNED_HI_OFFSET + 2]);
    let high16 = u16::from_le_bytes(hi) as u64;
    Ok(low48 | (high16 << 48))
}

pub fn write_pending_burned_shares(data: &mut [u8], v: u64) -> Result<()> {
    if data.len() < PENDING_BURNED_HI_OFFSET + 2 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let low48 = (v & 0x0000_ffff_ffff_ffff).to_le_bytes(); // 8 bytes, los 2 altos son 0
    data[PENDING_BURNED_LO_OFFSET..PENDING_BURNED_LO_OFFSET + 6].copy_from_slice(&low48[..6]);
    let high16 = (v >> 48) as u16;
    data[PENDING_BURNED_HI_OFFSET..PENDING_BURNED_HI_OFFSET + 2].copy_from_slice(&high16.to_le_bytes());
    Ok(())
}

// ---- ceremonia #53: bandera de VALOR FUERA DE TABLA (stranded) ---------------
//
// `stranded_flag` (u8 LE) de TRES estados: 0 = limpio; 1 = P2-3 PURO (el vault sostiene
// valor fuera de tabla de un cambio de cesta abortado con compras, CON su
// RestructureSession abierta como manifiesto); 2 = hay valor P2-4 (retiro-abort de un
// mint eliminado, SIN manifiesto) — puro o MEZCLADO sobre un P2-3. AMBOS estados no-cero
// bloquean SOLO la ENTRADA (`deposit_init` / el commit de `deposit_sweep_batch` /
// `restructure_init` vetan con `flag != 0`); NINGÚN terminal de retiro lo lee → la salida
// NUNCA se estrangula. Es ORTOGONAL al status → no se overloadea el status ni colisiona con
// Paused. Se pone infalible en los DOS producers:
//   - `restructure_abort` con compras GENUINAMENTE varadas (added_mask & buys_done) → 1.
//   - `withdraw_sweep_batch` (dirección abort) que aterriza un mint pinneado con saldo>0
//     que ya NO está en la tabla, desde status Active(0)/Paused(1) → 2 (SOBRESCRIBE un 1).
// Limpieza según el estado:
//   - `close_stranded` (permissionless): exige flag EXACTAMENTE 1 (P2-3 puro) y prueba la
//     vacuidad del conjunto varado del manifiesto por IDENTIDAD (balance 0 en la ATA de
//     CADA mint varado; inmune a decoy-donación: identidad, no un contador). El estado 2
//     lo RECHAZA (no puede garantizar que no quede valor P2-4).
//   - `admin_clear_stranded` (authority): limpia CUALQUIER estado no-cero (1 o 2). Reabrir
//     la ENTRADA tras un P2-4 exige la firma de Squads (liveness, no seguridad; frecuencia ~0).
// ⚠️ P2-3 y P2-4 NO son mutuamente excluyentes: un restructure puede ELIMINAR un mint (con
// un retiro pinneado a él aún abierto) mientras la bandera está a 0, y ESE strand P2-4 (el
// barrido de abort del retiro) puede caer DESPUÉS, coexistiendo con un manifiesto P2-3. El
// estado 2 (que sobrescribe el 1) invalida a propósito la vía permissionless en ese caso →
// obliga a `admin_clear_stranded`. Por eso la bandera es de 3 estados, no un solo bit.
//
// Almacenamiento: 1 byte en `allocations[5].reserved[2]` = offset absoluto 1036 (slot 5,
// dentro de los 30 bytes ociosos de reserved[2..8] de los slots 5-9). Rango LIBRE:
// `write_allocation` PRESERVA reserved[2..8], `write/clear_alloc_decimals` solo tocan
// [0..2], `write_alloc_last_swap` vive en la COLA @1388, y `restructure_settle` PRESERVA
// reserved[2..8] de todos los slots → la bandera SOBREVIVE a la reestructuración. LEN 1516
// SIN cambio, sin migración: los 52 vaults leen 0 (create_account cebó a cero y ningún
// handler pre-existente escribió @1036) → byte-idéntico hoy.

pub const STRANDED_FLAG_OFFSET: usize = ALLOCATIONS_OFFSET + 5 * ALLOC_LEN + ALLOC_RESERVED_OFFSET + 2; // 1036

const _: () = {
    assert!(STRANDED_FLAG_OFFSET == 1036);
    // Dentro del reserved del slot 5, NO solapa su caché de decimales [0..2].
    assert!(STRANDED_FLAG_OFFSET + 1 <= ALLOCATIONS_OFFSET + 6 * ALLOC_LEN); // <= fin del slot 5 (1042)
    // No solapa los contadores #43 (666) / #44 (740..746, 814..816) / #49 (888..894,
    // 962..964), todos en slots 0-4, y cae antes de total_shares (1338).
    assert!(STRANDED_FLAG_OFFSET > PENDING_BURNED_HI_OFFSET + 2);
    assert!(STRANDED_FLAG_OFFSET + 1 <= TOTAL_SHARES_OFFSET);
};

pub fn read_stranded_flag(data: &[u8]) -> Result<u8> {
    if data.len() < STRANDED_FLAG_OFFSET + 1 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    Ok(data[STRANDED_FLAG_OFFSET])
}

pub fn write_stranded_flag(data: &mut [u8], v: u8) -> Result<()> {
    if data.len() < STRANDED_FLAG_OFFSET + 1 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    data[STRANDED_FLAG_OFFSET] = v;
    Ok(())
}

/// Ceremonia #53: ¿está `mint` en la tabla de allocations viva? (recorre
/// `0..allocation_count`). Usado por el land-and-mark de `withdraw_sweep_batch`.
pub fn mint_in_allocations(data: &[u8], mint: &Pubkey) -> Result<bool> {
    let n = read_allocation_count(data)? as usize;
    for i in 0..n {
        if read_allocation_mint(data, i)? == *mint {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Ceremonia #44 (F3): participaciones que un depósito COMPROMETIDO va a recibir
/// al asentar, calculadas sobre las FOTOS INMUTABLES de la sesión (fijadas en
/// `deposit_init`: `amount_usdc` [net del fee], `total_shares_before`,
/// `tvl_before`). Idéntica en el incremento (sweep) y el decremento (settle)
/// porque los 3 argumentos son inmutables → el par cuadra exacto sin almacenar P.
///
/// Usa `amount_usdc` (cota SUPERIOR de `value_in = min(recibido, amount_usdc)`,
/// misma fórmula floor `·tsb/tvl` que la acuñación) → `P ≥ shares reales` → SIEMPRE
/// sobre-reserva → nunca deja sobre-extraer. `tsb==0` (la FOTO de la sesión se
/// tomó con el vault VACÍO) ⇒ 0: en el caso normal (primer depósito real) no hay
/// titulares a los que proteger. ⚠️ RESIDUAL DECLARADO (→ #45): si OTRA sesión
/// concurrente asienta y crea titulares ENTRE este `deposit_init` y este
/// `deposit_settle`, este depósito conserva su foto `tsb==0` ⇒ P=0 ⇒ su ventana
/// F3 sigue abierta. Acotado a vaults recién nacidos con varios PRIMEROS depósitos
/// concurrentes; NO afecta a vaults con dinero ya existente (foto `tsb>0`); no
/// cerrable sin almacenar P por sesión. Es subconjunto estricto del F3 previo
/// (antes 100% abierto) → mejora estricta, no cierre total.
/// Saturación a u64::MAX solo alcanzable con un vault auto-inflado a lo
/// absurdo (autolesión): un P gigante solo encoge el propio slice, nunca revierte.
pub fn phantom_shares(amount_usdc: u64, total_shares_before: u64, tvl_before: u64) -> u64 {
    if total_shares_before == 0 {
        // residual F3 `tsb==0`: la FOTO se tomó con el vault VACÍO → sin titulares
        // que proteger en el caso normal (ver comentario arriba).
        return 0;
    }
    // Ceremonia 2026-08 (VL-01): SEPARAR los dos ceros. El corto-circuito único
    // `|| tvl_before == 0` apagaba la reserva anti-F3 AUNQUE hubiera shares vivas:
    // con `m2m==0` (vault vaciado, alcanzable por restructure sell-all → abort) y
    // `total_shares_before>0`, devolvía 0 → `pending_committed` no subía → un
    // `withdraw_init` en la ventana commit→settle repartía el depósito en vuelo con
    // denominador crudo. Con `tvl_before==0`, `deposit_settle` acuña por la rama
    // BOOTSTRAP `base = value_in` shares (investor + dead, `value_in <= amount_usdc`).
    // `amount_usdc` es COTA SUPERIOR de ese `base` (cubre las MIN_INITIAL_SHARES dead
    // shares) → el denominador del retiro incluye al menos el aumento real de supply
    // → el slice solo ENCOGE, nunca sobre-extrae ni estrangula. Retornar aquí también
    // evita la división por cero de la línea de abajo. El par sweep(+P)/settle(−P)
    // cuadra exacto: los 3 args son inmutables (la foto `tvl_before` se fija en el
    // commit y no cambia hasta el settle) → ambos lados devuelven `amount_usdc`.
    if tvl_before == 0 {
        return amount_usdc;
    }
    let p = ((amount_usdc as u128) * (total_shares_before as u128)) / (tvl_before as u128);
    if p > u64::MAX as u128 {
        u64::MAX
    } else {
        p as u64
    }
}
