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
// feed:
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
// 10*12 = 120 of the 128 tail bytes are used; the final 8 hold `last_restructured_at`
// (ceremonia #31, LAST_RESTRUCTURED_AT_OFFSET = 1508): the tail is 100 % used.

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
// SIN cambio, sin migración: las cuentas vivas leen 0 (create_account cebó a cero).
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
// La cura suma `pending_burned_shares` al denominador de `withdraw_init`: el de las
// patas de token y, desde la ceremonia 2026-08 (WA-01), también el del USDC ocioso.
// Durante la ventana el denominador vuelve a ser (S − s1) + s1 = S = el total verdadero.
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
// las cuentas vivas leen 0 (create_account cebó a cero). Los slots 3 y 4 existen SIEMPRE
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

// ---- Auditoría 2026-10-09 (G1, F1A-01): participaciones quemadas REVIVIBLES ----------
//
// `revivable_burned_shares` (u64) = Σ `shares_to_burn` de las `WithdrawSession` ABIERTAS que
// todavía pueden abortar (nacidas con el contador, `generation != 0`, sin park definitivo, `had_park == 0`, y sin
// nacer cobradas, G3-B2: `WithdrawSession::counts_in_revivable`): sus shares están quemadas pero `withdraw_abort` las re-acuña ENTERAS y por
// cuenta fija. Mientras no sea 0, la ENTRADA no puede fijar un precio por share justo (los
// derechos del retirador quedan fuera del denominador y cualquier USDC donado entra en el m2m):
// `deposit_init` y el commit de `deposit_sweep_batch` lo exigen a 0 (VaultHasRevivableBurn).
// NINGÚN terminal de retiro lo lee → la salida nunca se estrangula. Sube en `withdraw_init`
// (checked_add) y baja (saturating_sub, nunca revierte) en los dos terminales que cierran la
// sesión: `withdraw_settle` y `withdraw_abort`. Las sesiones abiertas ANTES del upgrade tienen
// `generation == 0`: ni sumaron ni restan, y por eso NO pueden EMPEZAR una cancelación tras el
// upgrade (`WithdrawSession::can_abort`, error 6218); la que ya la había empezado está reservada
// en `pending_burned`, que la entrada también exige a 0. El checklist de la ceremonia («0 sesiones
// con generation == 0 y sold == 0») queda de cinturón, no de única defensa. Almacenamiento como `pending_burned`: 48 bits bajos
// en `allocations[7].reserved[2..8]` (1184..1190) y 16 altos en `allocations[8].reserved[2..4]`
// (1258..1260), rangos LIBRES del mapa de abajo; `restructure_settle` PRESERVA reserved[2..8]
// de todos los slots → el contador sobrevive al cambio de cesta. LEN 1516 SIN cambio.

pub const REVIVABLE_BURNED_LO_OFFSET: usize =
    ALLOCATIONS_OFFSET + 7 * ALLOC_LEN + ALLOC_RESERVED_OFFSET + 2; // 1184, slot 7, 6 bytes (48 bajos)
pub const REVIVABLE_BURNED_HI_OFFSET: usize =
    ALLOCATIONS_OFFSET + 8 * ALLOC_LEN + ALLOC_RESERVED_OFFSET + 2; // 1258, slot 8, 2 bytes (16 altos)

const _: () = {
    assert!(REVIVABLE_BURNED_LO_OFFSET == 1184);
    assert!(REVIVABLE_BURNED_LO_OFFSET + 6 <= ALLOCATIONS_OFFSET + 8 * ALLOC_LEN); // <= fin del slot 7 (1190)
    assert!(REVIVABLE_BURNED_HI_OFFSET == 1258);
    assert!(REVIVABLE_BURNED_HI_OFFSET + 2 <= ALLOCATIONS_OFFSET + 9 * ALLOC_LEN); // <= fin del slot 8 (1264)
    // Tras la generación de sesión (slot 6, 1110..1116) y antes de total_shares (1338).
    assert!(REVIVABLE_BURNED_LO_OFFSET >= SESSION_GENERATION_OFFSET + SESSION_GENERATION_LEN);
    assert!(REVIVABLE_BURNED_HI_OFFSET + 2 <= TOTAL_SHARES_OFFSET);
};

pub fn read_revivable_burned_shares(data: &[u8]) -> Result<u64> {
    if data.len() < REVIVABLE_BURNED_HI_OFFSET + 2 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut lo = [0u8; 8];
    lo[..6].copy_from_slice(&data[REVIVABLE_BURNED_LO_OFFSET..REVIVABLE_BURNED_LO_OFFSET + 6]);
    let low48 = u64::from_le_bytes(lo);
    let mut hi = [0u8; 2];
    hi.copy_from_slice(&data[REVIVABLE_BURNED_HI_OFFSET..REVIVABLE_BURNED_HI_OFFSET + 2]);
    let high16 = u16::from_le_bytes(hi) as u64;
    Ok(low48 | (high16 << 48))
}

pub fn write_revivable_burned_shares(data: &mut [u8], v: u64) -> Result<()> {
    if data.len() < REVIVABLE_BURNED_HI_OFFSET + 2 {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let low48 = (v & 0x0000_ffff_ffff_ffff).to_le_bytes();
    data[REVIVABLE_BURNED_LO_OFFSET..REVIVABLE_BURNED_LO_OFFSET + 6].copy_from_slice(&low48[..6]);
    let high16 = (v >> 48) as u16;
    data[REVIVABLE_BURNED_HI_OFFSET..REVIVABLE_BURNED_HI_OFFSET + 2].copy_from_slice(&high16.to_le_bytes());
    Ok(())
}

/// G1: ¿debe ESPERAR la entrada (foto de precio de `deposit_init` y re-precio del commit) por
/// retiros en vuelo? Sí mientras haya shares REVIVIBLES (retiro abierto que aún puede cancelar) o
/// shares RESERVADAS por una cancelación empezada (`pending_burned`, que `withdraw_abort` re-acuñará;
/// cubre una sesión anterior al upgrade, fuera del contador). UNA sola definición para los dos sitios
/// que la aplican (`deposit_init` y la rama de commit de `deposit_sweep_batch`); error 6216. Ningún
/// terminal de retiro la lee. Lectura pura: nunca escribe.
pub fn entry_blocked_by_withdraws(data: &[u8]) -> Result<bool> {
    Ok(read_revivable_burned_shares(data)? != 0 || read_pending_burned_shares(data)? != 0)
}

// ---- G2-a (auditoría 2026-10-09, F3B-01): deriva EXACTA de cesta ----------------------
//
// Una sesión de depósito fotografía en su init la cesta del vault (`leg_count` + `leg_mints`, por
// POSICIÓN). Hasta G2-a, «la sesión es de otra cesta» se decidía SOLO por fecha
// (`created_at < last_restructured_at`, estricta): en un EMPATE de segundo entre `deposit_init` y
// `restructure_settle` (mismo `unix_timestamp` en todo el slot) una sesión abierta contra la cesta
// vieja no era rancia y su commit aterrizaba cada pata en la ATA del vault de `leg_mints[i]` aunque
// ese mint ya no estuviera en la tabla: valor FUERA DE TABLA sin bandera. La identidad no empata:
// esta es la ÚNICA definición de «sesión de otra cesta» para la ENTRADA, y la usan
// `deposit_sweep_batch` (dirección abort, reembolso en especie) y `deposit_settle` (rechazo de una
// sesión no comprometida). La fecha se conserva de CINTURÓN. Se compara por posición a propósito:
// la posición es parte de la identidad (slots de la tabla, ATAs pinneadas por slot, pesos).
pub fn basket_drift(data: &[u8], leg_count: u8, leg_mints: &[Pubkey]) -> Result<bool> {
    let n = read_allocation_count(data)? as usize;
    if n != leg_count as usize || n > leg_mints.len() {
        return Ok(true);
    }
    for (i, snapshot) in leg_mints.iter().enumerate().take(n) {
        if read_allocation_mint(data, i)? != *snapshot {
            return Ok(true);
        }
    }
    Ok(false)
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
// Paused. Se pone infalible en los TRES producers:
//   - `restructure_abort` con compras GENUINAMENTE varadas (added_mask & buys_done) → 1.
//   - `withdraw_sweep_batch` (dirección abort) que aterriza un mint pinneado con saldo>0
//     que ya NO está en la tabla, desde status Active(0)/Paused(1) → 2 (SOBRESCRIBE un 1).
//   - `deposit_sweep_batch` (dirección settle) que aterriza una pata con saldo>0 cuyo mint ya NO
//     está en la tabla → 2 (SOBRESCRIBE un 1). Cinturón de G2-a: inalcanzable con `basket_drift`.
// Limpieza según el estado:
//   - `close_stranded` (permissionless): exige flag EXACTAMENTE 1 (P2-3 puro) y prueba la
//     vacuidad del conjunto varado del manifiesto por IDENTIDAD (balance 0 en la ATA de
//     CADA mint varado; inmune a decoy-donación: identidad, no un contador). El estado 2
//     lo RECHAZA (no puede garantizar que no quede valor P2-4).
//   - `admin_clear_stranded` (authority): limpia CUALQUIER estado no-cero (1 o 2).
// El estado 2 SOBRESCRIBE al 1: si hay valor fuera de tabla con y sin manifiesto, la vía
// permissionless no puede probar la limpieza y la hace `admin_clear_stranded`. Por eso la
// bandera es de 3 estados, no un solo bit.
//
// Almacenamiento: 1 byte en `allocations[5].reserved[2]` = offset absoluto 1036 (slot 5).
// Mapa de reserved[2..8] por slot (mantener al día; registro y asserts en `VAULT_CARVES`):
// slot 0 #43 [2..4] y 5A-bis `last_service_slot` [4..8] · slot 1 #44 [2..8] · slot 2 #44 [2..4] ·
// slot 3 #49 [2..8] · slot 4 #49 [2..4] · slot 5 #53 [2] · slot 6 §3.4 `session_generation` [2..8] ·
// slot 7 G1 `revivable_burned` [2..8] · slot 8 G1 [2..4] · slot 9 #56 `vault_table_slot` [2..8] ·
// LIBRES: slot 2 [4..8], slot 4 [4..8], slot 5 [3..8], slot 8 [4..8]. Rango LIBRE:
// `write_allocation` PRESERVA reserved[2..8], `write/clear_alloc_decimals` solo tocan
// [0..2], `write_alloc_last_swap` vive en la COLA @1388, y `restructure_settle` PRESERVA
// reserved[2..8] de todos los slots → la bandera SOBREVIVE a la reestructuración. LEN 1516
// SIN cambio, sin migración: las cuentas vivas leen 0 (create_account cebó a cero y ningún
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
/// `0..allocation_count`). Usado por el land-and-mark de `withdraw_sweep_batch` y, desde G2-a, por el
/// cinturón del commit de `deposit_sweep_batch` (una pata con saldo que aterriza con un mint fuera de
/// la tabla → `stranded_flag = 2`). Definición ÚNICA de «mint en la tabla viva».
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
/// al asentar, calculadas sobre las FOTOS de la sesión: `amount_usdc` [I, el capital =
/// lo pagado − E], `total_shares_before` y `tvl_before`. Las toma `deposit_init` y, con el
/// m2m encendido, el barrido de COMMIT las re-marca a mercado ANTES de reservar (S-1, #50);
/// desde el commit ya no cambian. Idéntica en el incremento (commit) y el decremento
/// (settle) porque los 3 argumentos no cambian entre los dos → el par cuadra exacto sin
/// almacenar P.
///
/// Con titulares en la foto (`tsb>0`): usa `amount_usdc` (cota SUPERIOR de
/// `value_in = min(recibido, amount_usdc)`, misma fórmula floor `·tsb/tvl` que la
/// acuñación) → `P ≥ shares reales` → sobre-reserva. `tsb==0` ⇒ 0: en el commit una foto
/// vacía es la de un vault SIN titulares. Con el m2m encendido la foto re-marcada es la del
/// instante del commit; con el m2m apagado el commit se niega (6229) si la foto es vacía y el
/// vault ya tiene participaciones. Y entre el commit y el settle no aparece ningún titular:
/// `deposit_init` y el commit exigen `committed_deposits == 0` (candado de serialización, #51).
/// Saturación a u64::MAX solo alcanzable con un vault auto-inflado a lo
/// absurdo (autolesión): un P gigante solo encoge el propio slice, nunca revierte.
pub fn phantom_shares(amount_usdc: u64, total_shares_before: u64, tvl_before: u64) -> u64 {
    if total_shares_before == 0 {
        // `tsb==0`: vault sin titulares en el commit (ver comentario arriba).
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

// ---- Ceremonia USDC (§3.4): contador de generación de sesiones ----------------
//
// `session_generation` (u48 LE) vive en los bytes [2..8] del `reserved` del slot 6
// de allocations (offset absoluto 1110..1116), el mismo hueco por slot que ya usan
// #43 (slot 0), #44 (slots 1 y 2), #49 (slots 3 y 4) y #53 (slot 5); los bytes
// [0..2] de cada slot son la caché de decimales. `write_allocation` y
// `restructure_settle` PRESERVAN esos bytes a propósito. Cada init de sesión
// (depósito, retiro, cambio de cesta) lo incrementa ANTES de sellar su sesión, así
// que el primer valor emitido es 1 y una sesión legacy (que lee 0) jamás empareja
// con un `FundingRecord` (§3.3). NO va en la cola 1388..1516: está al 100 %
// (caché de último swap + `last_restructured_at`), y pisar ese timestamp apagaría
// en silencio los cuatro `require!` de sesión rancia.

pub const SESSION_GENERATION_OFFSET: usize =
    ALLOCATIONS_OFFSET + 6 * ALLOC_LEN + ALLOC_RESERVED_OFFSET + 2; // 1110, slot 6, 6 bytes
pub const SESSION_GENERATION_LEN: usize = 6;
pub const SESSION_GENERATION_MAX: u64 = (1u64 << 48) - 1;

const _: () = {
    assert!(SESSION_GENERATION_OFFSET == 1110);
    // Cabe en el slot 6, después de su caché de decimales [0..2].
    // 1116 <= 1116: termina justo al final del slot 6.
    assert!(
        SESSION_GENERATION_OFFSET + SESSION_GENERATION_LEN <= ALLOCATIONS_OFFSET + 7 * ALLOC_LEN
    );
    // Sin solapar NADA de lo carvado por las ceremonias anteriores ni los campos fijos.
    assert!(COMMITTED_DEPOSITS_OFFSET + 2 <= SESSION_GENERATION_OFFSET); // #43, slot 0
    assert!(PENDING_SHARES_LO_OFFSET + 6 <= SESSION_GENERATION_OFFSET); // #44, slot 1
    assert!(PENDING_SHARES_HI_OFFSET + 2 <= SESSION_GENERATION_OFFSET); // #44, slot 2
    assert!(PENDING_BURNED_LO_OFFSET + 6 <= SESSION_GENERATION_OFFSET); // #49, slot 3
    assert!(PENDING_BURNED_HI_OFFSET + 2 <= SESSION_GENERATION_OFFSET); // #49, slot 4
    assert!(STRANDED_FLAG_OFFSET + 1 <= SESSION_GENERATION_OFFSET); // #53, slot 5
    // 1116 <= 1338: antes de total_shares; lejos de la cola 1388.. y de last_restructured_at (#31).
    assert!(SESSION_GENERATION_OFFSET + SESSION_GENERATION_LEN <= TOTAL_SHARES_OFFSET);
    assert!(SESSION_GENERATION_OFFSET + SESSION_GENERATION_LEN <= RESERVED_OFFSET);
    assert!(LAST_RESTRUCTURED_AT_OFFSET >= SESSION_GENERATION_OFFSET + SESSION_GENERATION_LEN);
};

/// Registro ÚNICO de los huecos carvados a nivel de byte en el VaultState (offset, len).
/// Toda ceremonia que carve un hueco nuevo lo AÑADE aquí: la comprobación de no
/// solapamiento es por pares y, dentro de allocations, exige dejar libre la caché de
/// decimales [0..2] de cada slot. Huecos aún libres (2026-10, tras la tabla del vault en el
/// slot 9 [2..8]): slot 2 [4..8], slot 4 [4..8], slot 5 [3..8], slot 8 [4..8]. La cola 1388..1516 está al 100 %.
pub const VAULT_CARVES: [(usize, usize); 13] = [
    (COMMITTED_DEPOSITS_OFFSET, 2),                     // #43, slot 0
    (PENDING_SHARES_LO_OFFSET, 6),                      // #44, slot 1
    (PENDING_SHARES_HI_OFFSET, 2),                      // #44, slot 2
    (PENDING_BURNED_LO_OFFSET, 6),                      // #49, slot 3
    (PENDING_BURNED_HI_OFFSET, 2),                      // #49, slot 4
    (STRANDED_FLAG_OFFSET, 1),                          // #53, slot 5
    (SESSION_GENERATION_OFFSET, SESSION_GENERATION_LEN), // §3.4, slot 6
    (LAST_SERVICE_SLOT_OFFSET, LAST_SERVICE_SLOT_LEN),   // 5A-bis, slot 0 [4..8]
    (REVIVABLE_BURNED_LO_OFFSET, 6),                    // G1 2026-10-09, slot 7
    (REVIVABLE_BURNED_HI_OFFSET, 2),                    // G1 2026-10-09, slot 8
    (RESERVED_OFFSET, LAST_SWAP_SLOT_LEN * MAX_TOKENS_PER_VAULT), // #30, caché de último swap, cola
    (LAST_RESTRUCTURED_AT_OFFSET, 8),                   // #31, cola
    (VAULT_TABLE_SLOT_OFFSET, VAULT_TABLE_SLOT_LEN),     // #56, tabla de direcciones del vault, slot 9
];

const fn vault_carves_ok(c: &[(usize, usize)]) -> bool {
    let mut i = 0;
    while i < c.len() {
        let (a, la) = c[i];
        // Dentro de allocations: nunca sobre mint/peso/ATA ni sobre la caché de decimales.
        if a >= ALLOCATIONS_OFFSET && a < TOTAL_SHARES_OFFSET {
            let rel = (a - ALLOCATIONS_OFFSET) % ALLOC_LEN;
            if rel < ALLOC_RESERVED_OFFSET + 2 || rel + la > ALLOC_LEN {
                return false;
            }
        }
        let mut j = i + 1;
        while j < c.len() {
            let (b, lb) = c[j];
            if a < b + lb && b < a + la {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

const _: () = assert!(vault_carves_ok(&VAULT_CARVES), "dos carves del VaultState se solapan");
// El predicado tiene que RECHAZAR: un solape de un byte, la caché de decimales y el mint del slot.
const _: () = {
    assert!(!vault_carves_ok(&[(SESSION_GENERATION_OFFSET, 6), (SESSION_GENERATION_OFFSET + 5, 1)]));
    assert!(!vault_carves_ok(&[(ALLOCATIONS_OFFSET + 6 * ALLOC_LEN + ALLOC_RESERVED_OFFSET, 2)]));
    assert!(!vault_carves_ok(&[(ALLOCATIONS_OFFSET, 1)]));
    assert!(vault_carves_ok(&[(ALLOCATIONS_OFFSET + 7 * ALLOC_LEN + ALLOC_RESERVED_OFFSET + 2, 6)]));
};

// ---- 5A-bis: candado por slot del servicio S de `rebalance` -------
//
// `rebalance` no tiene sesión, así que N instrucciones en un mismo mensaje cobrarían S N
// veces (tope POR instrucción). Se guardan los 32 bits bajos del slot del último cobro de S
// en los 4 bytes libres del `reserved` del slot 0 de allocations ([4..8]; [0..2] decimales,
// [2..4] `committed_deposits`): un segundo `rebalance` con S > 0 en el MISMO slot revierte
// (`ServiceAlreadyChargedThisSlot`). Sin S no se toca. LEN sin cambio, sin migración: los
// vaults existentes leen 0 = nunca cobrado. La marca es `slot % (2^32 − 1) + 1`: nunca vale 0
// (0 queda reservado a «nunca») y dos slots consecutivos dan marcas distintas siempre (la
// misma técnica que la generación del §3.4). `rebalance` lee y escribe el CAMPO del struct
// (`allocations[0].reserved[4..8]`) con `read/write_service_slot_tag`, porque Anchor
// reserializa la cuenta tipada al salir; el lector byte a byte sirve a tests y sondas.

/// Posición dentro del `reserved` de 8 B de una allocation.
pub const LAST_SERVICE_SLOT_REL: usize = 4;
pub const LAST_SERVICE_SLOT_LEN: usize = 4;
pub const LAST_SERVICE_SLOT_OFFSET: usize = ALLOCATIONS_OFFSET + ALLOC_RESERVED_OFFSET + LAST_SERVICE_SLOT_REL; // 668

const _: () = {
    assert!(LAST_SERVICE_SLOT_OFFSET == 668);
    assert!(LAST_SERVICE_SLOT_REL + LAST_SERVICE_SLOT_LEN == ALLOC_LEN - ALLOC_RESERVED_OFFSET, "ocupa justo la cola del reserved del slot 0");
    assert!(COMMITTED_DEPOSITS_OFFSET + 2 == LAST_SERVICE_SLOT_OFFSET, "pegado al contador de comprometidos, sin solape");
};

/// 32 bits bajos del slot del último cobro de S en `rebalance` (0 = nunca).
pub fn read_last_service_slot(data: &[u8]) -> Result<u32> {
    if data.len() < LAST_SERVICE_SLOT_OFFSET + LAST_SERVICE_SLOT_LEN {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut b = [0u8; 4];
    b.copy_from_slice(&data[LAST_SERVICE_SLOT_OFFSET..LAST_SERVICE_SLOT_OFFSET + LAST_SERVICE_SLOT_LEN]);
    Ok(u32::from_le_bytes(b))
}

/// Marca del candado para un slot vivo: nunca 0 y distinta entre slots consecutivos.
pub fn service_slot_tag(slot: u64) -> u32 {
    (slot % 0xffff_ffff) as u32 + 1
}

/// Marca guardada en el `reserved` (8 B) de una allocation (0 = nunca cobrado).
pub fn read_service_slot_tag(reserved: &[u8; 8]) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&reserved[LAST_SERVICE_SLOT_REL..LAST_SERVICE_SLOT_REL + LAST_SERVICE_SLOT_LEN]);
    u32::from_le_bytes(b)
}

/// Escribe la marca en el `reserved` (8 B) de una allocation sin tocar sus otros 4 bytes.
pub fn write_service_slot_tag(reserved: &mut [u8; 8], tag: u32) {
    reserved[LAST_SERVICE_SLOT_REL..LAST_SERVICE_SLOT_REL + LAST_SERVICE_SLOT_LEN].copy_from_slice(&tag.to_le_bytes());
}

#[cfg(test)]
mod service_slot_tests {
    use super::*;

    #[test]
    fn la_marca_nunca_es_cero_y_cambia_entre_slots_consecutivos() {
        assert_eq!(service_slot_tag(0), 1);
        assert_eq!(service_slot_tag(0xffff_ffff), 1, "vuelta completa del módulo: nunca 0");
        for s in [0u64, 1, 441_942_947, 0xffff_fffe, 0xffff_ffff, u64::MAX - 1] {
            assert_ne!(service_slot_tag(s), 0);
            assert_ne!(service_slot_tag(s), service_slot_tag(s + 1), "slots consecutivos");
        }
    }

    #[test]
    fn el_candado_vive_en_668_y_nadie_mas_toca_esos_bytes() {
        let mut reserved = [0x55u8; 8];
        write_service_slot_tag(&mut reserved, 0x0a0b_0c0d);
        assert_eq!(&reserved[..4], &[0x55; 4], "decimales [0..2] y comprometidos [2..4] intactos");
        assert_eq!(read_service_slot_tag(&reserved), 0x0a0b_0c0d);
        // Que el campo del struct (reserved[4..8] del slot 0) sea el offset 668 lo garantiza el `const _` de arriba
        // (598 + 66 + 4) y lo mide la suite 54 en cadena; aquí solo se comprueba que el lector byte a byte y los
        // otros escritores del slot 0 conviven con esos 4 bytes.
        let mut data = vec![0x55u8; VAULT_TOTAL_LEN];
        data[LAST_SERVICE_SLOT_OFFSET..LAST_SERVICE_SLOT_OFFSET + LAST_SERVICE_SLOT_LEN].copy_from_slice(&reserved[4..8]);
        assert_eq!(read_last_service_slot(&data).unwrap(), 0x0a0b_0c0d);
        let before = data.clone();
        write_committed_deposits(&mut data, u16::MAX).unwrap();
        clear_alloc_decimals(&mut data, 0).unwrap();
        write_alloc_decimals(&mut data, 0, 9).unwrap();
        assert_eq!(&data[LAST_SERVICE_SLOT_OFFSET..LAST_SERVICE_SLOT_OFFSET + 4], &before[LAST_SERVICE_SLOT_OFFSET..LAST_SERVICE_SLOT_OFFSET + 4], "ni el contador de comprometidos ni la caché de decimales tocan el candado");
        assert_eq!(read_last_service_slot(&data).unwrap(), 0x0a0b_0c0d);
        assert_eq!(read_committed_deposits(&data).unwrap(), u16::MAX, "y el candado no pisa al contador");
    }
}

pub fn read_session_generation(data: &[u8]) -> Result<u64> {
    if data.len() < SESSION_GENERATION_OFFSET + SESSION_GENERATION_LEN {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut b = [0u8; 8];
    b[..SESSION_GENERATION_LEN].copy_from_slice(
        &data[SESSION_GENERATION_OFFSET..SESSION_GENERATION_OFFSET + SESSION_GENERATION_LEN],
    );
    Ok(u64::from_le_bytes(b))
}

pub fn write_session_generation(data: &mut [u8], v: u64) -> Result<()> {
    if data.len() < SESSION_GENERATION_OFFSET + SESSION_GENERATION_LEN {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    if v > SESSION_GENERATION_MAX {
        return err!(crate::errors::WagonError::MathOverflow);
    }
    data[SESSION_GENERATION_OFFSET..SESSION_GENERATION_OFFSET + SESSION_GENERATION_LEN]
        .copy_from_slice(&v.to_le_bytes()[..SESSION_GENERATION_LEN]);
    Ok(())
}

/// Incrementa el contador y devuelve el valor NUEVO (el que sella la sesión; >= 1).
/// UNA llamada por init: el `FundingRecord` (§3.3) debe sellar el MISMO valor que la
/// sesión, no volver a llamar aquí. Los múltiplos de 2^32 se SALTAN para que los 32
/// bits bajos (el sello de DepositSession/WithdrawSession) nunca sean 0, el marcador
/// de sesión legacy del que depende D2 (§3.3).
pub fn bump_session_generation(data: &mut [u8]) -> Result<u64> {
    let mut next = read_session_generation(data)?
        .checked_add(1)
        .ok_or(crate::errors::WagonError::MathOverflow)?;
    if next as u32 == 0 {
        next = next.checked_add(1).ok_or(crate::errors::WagonError::MathOverflow)?;
    }
    write_session_generation(data, next)?;
    Ok(next)
}

#[cfg(test)]
mod session_generation_tests {
    use super::*;

    #[test]
    fn generacion_no_toca_nada_mas_y_convive_con_last_restructured_at() {
        let mut data = vec![0x55u8; VAULT_TOTAL_LEN];
        write_last_restructured_at(&mut data, 0x0102_0304_0506_0708).unwrap();
        let before = data.clone();
        assert_eq!(read_session_generation(&data).unwrap(), 0x5555_5555_5555);
        write_session_generation(&mut data, 0).unwrap();
        assert_eq!(bump_session_generation(&mut data).unwrap(), 1);
        assert_eq!(bump_session_generation(&mut data).unwrap(), 2);
        assert_eq!(read_session_generation(&data).unwrap(), 2);
        assert_eq!(read_last_restructured_at(&data).unwrap(), 0x0102_0304_0506_0708);
        // Solo cambian los 6 bytes del contador.
        for (i, (a, b)) in before.iter().zip(data.iter()).enumerate() {
            let dentro = (SESSION_GENERATION_OFFSET..SESSION_GENERATION_OFFSET + 6).contains(&i);
            assert!(dentro || a == b, "byte {i} cambió fuera del contador");
        }
        // Escribir el timestamp no toca el contador.
        write_last_restructured_at(&mut data, 7).unwrap();
        assert_eq!(read_session_generation(&data).unwrap(), 2);
        // Los 32 bits bajos nunca son 0: tras 0xFFFF_FFFF el bump salta a 0x1_0000_0001.
        write_session_generation(&mut data, 0xFFFF_FFFF).unwrap();
        assert_eq!(bump_session_generation(&mut data).unwrap(), 0x1_0000_0001);
        // Techo de 48 bits: el valor máximo entra, uno más no.
        write_session_generation(&mut data, SESSION_GENERATION_MAX).unwrap();
        assert!(bump_session_generation(&mut data).is_err(), "sin desbordar los 48 bits");
        assert_eq!(read_session_generation(&data).unwrap(), SESSION_GENERATION_MAX, "un bump fallido no escribe");
        assert!(write_session_generation(&mut data, SESSION_GENERATION_MAX + 1).is_err());
        assert_eq!(read_session_generation(&data).unwrap(), SESSION_GENERATION_MAX);
        // Lo que hace `restructure_settle` al vaciar y reescribir slots (write_allocation
        // por defecto, caché de último swap, decimales) PRESERVA el contador.
        write_session_generation(&mut data, 2).unwrap();
        let m = Pubkey::new_from_array([7u8; 32]);
        for i in 0..MAX_TOKENS_PER_VAULT {
            write_allocation(&mut data, i, &Pubkey::default(), 0, &Pubkey::default()).unwrap();
            write_alloc_last_swap(&mut data, i, 0, 0).unwrap();
            clear_alloc_decimals(&mut data, i).unwrap();
        }
        write_allocation(&mut data, 6, &m, 1_234, &m).unwrap();
        write_alloc_decimals(&mut data, 6, 9).unwrap();
        assert_eq!(read_session_generation(&data).unwrap(), 2, "sobrevive al vaciado de slots");
        assert_eq!(read_alloc_decimals(&data, 6).unwrap(), Some(9));
        // Los otros carves por slot siguen intactos (0x55 de relleno) tras todo lo anterior.
        for off in [COMMITTED_DEPOSITS_OFFSET, PENDING_SHARES_LO_OFFSET, PENDING_SHARES_HI_OFFSET,
                    PENDING_BURNED_LO_OFFSET, PENDING_BURNED_HI_OFFSET, STRANDED_FLAG_OFFSET] {
            assert_eq!(data[off], 0x55, "offset {off} intacto");
        }
        // Y al revés: los escritores de los otros carves no tocan el contador.
        write_committed_deposits(&mut data, u16::MAX).unwrap();
        write_pending_committed_shares(&mut data, u64::MAX).unwrap();
        write_pending_burned_shares(&mut data, u64::MAX).unwrap();
        write_stranded_flag(&mut data, 2).unwrap();
        write_last_restructured_at(&mut data, i64::MAX).unwrap();
        assert_eq!(read_session_generation(&data).unwrap(), 2, "los otros carves no lo tocan");
    }
}

#[cfg(test)]
mod revivable_burned_tests {
    use super::*;

    /// G1 (2026-10-09): el códec 48 + 16 del contador es exacto por encima de 2^48 y no
    /// toca ningún byte vecino; el contador sobrevive al vaciado de slots de `restructure_settle`.
    #[test]
    fn revivable_codec_48_16_exacto_y_no_toca_nada_mas() {
        let mut data = vec![0x55u8; VAULT_TOTAL_LEN];
        assert_eq!(read_revivable_burned_shares(&data).unwrap(), 0x5555_5555_5555_5555);
        let decimales_7 = read_alloc_decimals(&data, 7).unwrap();
        let decimales_8 = read_alloc_decimals(&data, 8).unwrap();
        let before = data.clone();
        for v in [0u64, 1, 0x0123_4567_89AB_CDEF, (1u64 << 48) - 1, 1u64 << 48, u64::MAX - 1, u64::MAX] {
            write_revivable_burned_shares(&mut data, v).unwrap();
            assert_eq!(read_revivable_burned_shares(&data).unwrap(), v, "ida y vuelta de {v:#x}");
        }
        // Solo cambian los 6 bytes bajos (slot 7, 1184..1190) y los 2 altos (slot 8, 1258..1260).
        for (i, (a, b)) in before.iter().zip(data.iter()).enumerate() {
            let dentro = (REVIVABLE_BURNED_LO_OFFSET..REVIVABLE_BURNED_LO_OFFSET + 6).contains(&i)
                || (REVIVABLE_BURNED_HI_OFFSET..REVIVABLE_BURNED_HI_OFFSET + 2).contains(&i);
            assert!(dentro || a == b, "byte {i} cambió fuera del contador");
        }
        // Los vecinos siguen leyendo su relleno: pending_burned (slots 3 y 4), la generación
        // (slot 6), la caché de decimales de los slots 7 y 8 y total_shares.
        assert_eq!(read_pending_burned_shares(&data).unwrap(), 0x5555_5555_5555_5555);
        assert_eq!(read_session_generation(&data).unwrap(), 0x5555_5555_5555);
        assert_eq!(read_total_shares(&data).unwrap(), 0x5555_5555_5555_5555);
        assert_eq!(read_alloc_decimals(&data, 7).unwrap(), decimales_7);
        assert_eq!(read_alloc_decimals(&data, 8).unwrap(), decimales_8);
        // Lo que hace `restructure_settle` al vaciar y reescribir slots PRESERVA el contador.
        write_revivable_burned_shares(&mut data, 0xABCD_EF01_2345_6789).unwrap();
        let m = Pubkey::new_from_array([9u8; 32]);
        for i in 0..MAX_TOKENS_PER_VAULT {
            write_allocation(&mut data, i, &Pubkey::default(), 0, &Pubkey::default()).unwrap();
            write_alloc_last_swap(&mut data, i, 0, 0).unwrap();
            clear_alloc_decimals(&mut data, i).unwrap();
        }
        write_allocation(&mut data, 7, &m, 1_234, &m).unwrap();
        write_alloc_decimals(&mut data, 7, 6).unwrap();
        write_alloc_decimals(&mut data, 8, 9).unwrap();
        assert_eq!(read_revivable_burned_shares(&data).unwrap(), 0xABCD_EF01_2345_6789, "sobrevive al vaciado de slots");
        assert_eq!(read_alloc_decimals(&data, 7).unwrap(), Some(6));
        assert_eq!(read_alloc_decimals(&data, 8).unwrap(), Some(9));
        // Y escribir el contador no toca la caché de decimales ni pending_burned.
        write_pending_burned_shares(&mut data, 77).unwrap();
        write_revivable_burned_shares(&mut data, u64::MAX).unwrap();
        assert_eq!(read_pending_burned_shares(&data).unwrap(), 77);
        assert_eq!(read_revivable_burned_shares(&data).unwrap(), u64::MAX);
        assert_eq!(read_alloc_decimals(&data, 7).unwrap(), Some(6));
        assert_eq!(read_alloc_decimals(&data, 8).unwrap(), Some(9));
    }

    /// La puerta de entrada mira los DOS contadores de retiros y solo ellos.
    #[test]
    fn la_entrada_espera_por_revivibles_y_por_cancelaciones_en_curso() {
        let mut data = vec![0u8; VAULT_TOTAL_LEN];
        assert!(!entry_blocked_by_withdraws(&data).unwrap(), "vault limpio: entra");
        write_revivable_burned_shares(&mut data, 1).unwrap();
        assert!(entry_blocked_by_withdraws(&data).unwrap(), "con revivibles: espera");
        write_revivable_burned_shares(&mut data, 0).unwrap();
        write_pending_burned_shares(&mut data, 1).unwrap();
        assert!(entry_blocked_by_withdraws(&data).unwrap(), "con una cancelación en curso: espera");
        write_pending_burned_shares(&mut data, 0).unwrap();
        write_pending_committed_shares(&mut data, 5).unwrap(); // participaciones fantasma de un depósito comprometido: no es asunto suyo
        write_committed_deposits(&mut data, 1).unwrap();
        assert!(!entry_blocked_by_withdraws(&data).unwrap(), "solo mira a los retiros");
    }
}

#[cfg(test)]
mod basket_drift_tests {
    use super::*;

    fn vault_con(mints: &[Pubkey]) -> Vec<u8> {
        let mut data = vec![0u8; VAULT_TOTAL_LEN];
        write_allocation_count(&mut data, mints.len() as u8).unwrap();
        for (i, m) in mints.iter().enumerate() {
            write_allocation(&mut data, i, m, 1_000, &Pubkey::new_unique()).unwrap();
        }
        data
    }

    #[test]
    fn deriva_exacta_por_numero_identidad_y_posicion() {
        let (a, b, c) = (Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique());
        let mut foto = [Pubkey::default(); MAX_TOKENS_PER_VAULT];
        foto[0] = a;
        foto[1] = b;
        let data = vault_con(&[a, b]);
        assert!(!basket_drift(&data, 2, &foto).unwrap(), "misma cesta: sin deriva");
        assert!(basket_drift(&data, 1, &foto).unwrap(), "distinto numero de patas");
        assert!(basket_drift(&vault_con(&[a]), 2, &foto).unwrap(), "la tabla perdio una pata");
        assert!(basket_drift(&vault_con(&[a, c]), 2, &foto).unwrap(), "mismo numero, otro mint");
        assert!(basket_drift(&vault_con(&[b, a]), 2, &foto).unwrap(), "misma identidad, otra POSICION");
        assert!(basket_drift(&vault_con(&[a, b, c]), 2, &foto).unwrap(), "la tabla gano una pata");
        // La foto puede llevar basura en los slots >= leg_count: no cuentan.
        foto[2] = c;
        assert!(!basket_drift(&data, 2, &foto).unwrap(), "slots mas alla de leg_count se ignoran");
        // Bordes: tabla vacia y foto mas corta que la tabla (guarda `n > leg_mints.len()`).
        assert!(!basket_drift(&vault_con(&[]), 0, &foto).unwrap(), "tabla vacia y foto vacia: sin deriva");
        assert!(basket_drift(&vault_con(&[]), 1, &foto).unwrap(), "tabla vacia y foto con una pata: deriva");
        assert!(basket_drift(&data, 2, &foto[..1]).unwrap(), "foto mas corta que la tabla: deriva");
    }

    #[test]
    fn mint_in_allocations_en_cualquier_posicion() {
        let (a, b, c) = (Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique());
        let data = vault_con(&[a, b]);
        assert!(mint_in_allocations(&data, &a).unwrap());
        assert!(mint_in_allocations(&data, &b).unwrap());
        assert!(!mint_in_allocations(&data, &c).unwrap());
        assert!(!mint_in_allocations(&vault_con(&[]), &a).unwrap(), "tabla vacia: nada dentro");
    }
}

// ---- #56: tabla de direcciones del vault --------------------------------------------------------------
//
// `vault_table_sync` crea la tabla de direcciones del vault con una PDA del programa como autoridad. El programa de
// tablas deriva la dirección de `[autoridad, slot de creación]`, así que el vault guarda el SLOT (no quedan 32 B
// seguidos libres): 48 bits LE en el `reserved` del slot 9 de allocations ([2..8]; [0..2] es su caché de decimales).
// 0 = sin tabla (`vault_table_sync` nunca guarda 0). LEN 1516 sin cambio, sin migración: los vaults de antes leen 0.
// `write_allocation` y `restructure_settle` preservan `reserved[2..8]` de todos los slots.

pub const VAULT_TABLE_SLOT_OFFSET: usize =
    ALLOCATIONS_OFFSET + 9 * ALLOC_LEN + ALLOC_RESERVED_OFFSET + 2; // 1332, slot 9, 6 bytes
pub const VAULT_TABLE_SLOT_LEN: usize = 6;
pub const VAULT_TABLE_SLOT_MAX: u64 = (1u64 << 48) - 1;

const _: () = {
    assert!(VAULT_TABLE_SLOT_OFFSET == 1332);
    assert!(MAX_TOKENS_PER_VAULT == 10, "el slot 9 de allocations existe");
    assert!(VAULT_TABLE_SLOT_OFFSET + VAULT_TABLE_SLOT_LEN == TOTAL_SHARES_OFFSET, "termina justo al final del slot 9");
};

/// Slot de creación de la tabla del vault (0 = sin tabla).
pub fn read_vault_table_slot(data: &[u8]) -> Result<u64> {
    if data.len() < VAULT_TABLE_SLOT_OFFSET + VAULT_TABLE_SLOT_LEN {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    let mut b = [0u8; 8];
    b[..VAULT_TABLE_SLOT_LEN].copy_from_slice(&data[VAULT_TABLE_SLOT_OFFSET..VAULT_TABLE_SLOT_OFFSET + VAULT_TABLE_SLOT_LEN]);
    Ok(u64::from_le_bytes(b))
}

/// Guarda el slot de creación de la tabla (1 a 2^48 − 1) sin tocar la caché de decimales del slot 9.
pub fn write_vault_table_slot(data: &mut [u8], slot: u64) -> Result<()> {
    if data.len() < VAULT_TABLE_SLOT_OFFSET + VAULT_TABLE_SLOT_LEN {
        return err!(crate::errors::WagonError::VaultDataTooShort);
    }
    if slot == 0 || slot > VAULT_TABLE_SLOT_MAX {
        return err!(crate::errors::WagonError::VaultTableMismatch);
    }
    data[VAULT_TABLE_SLOT_OFFSET..VAULT_TABLE_SLOT_OFFSET + VAULT_TABLE_SLOT_LEN]
        .copy_from_slice(&slot.to_le_bytes()[..VAULT_TABLE_SLOT_LEN]);
    Ok(())
}

#[cfg(test)]
mod vault_table_slot_tests {
    use super::*;

    #[test]
    fn el_slot_de_la_tabla_vive_en_1332_sin_pisar_a_sus_vecinos() {
        let mut data = vec![0x55u8; VAULT_TOTAL_LEN];
        let before = data.clone();
        for s in [1u64, 459_426_806, VAULT_TABLE_SLOT_MAX] {
            write_vault_table_slot(&mut data, s).unwrap();
            assert_eq!(read_vault_table_slot(&data).unwrap(), s);
            assert_eq!(&data[..1332], &before[..1332], "nada antes de 1332 (la caché de decimales del slot 9 está en 1330..1332)");
            assert_eq!(&data[1338..], &before[1338..], "ni total_shares ni lo que sigue");
        }
        // Los escritores de allocations del slot 9 no tocan el slot guardado.
        write_allocation(&mut data, 9, &Pubkey::new_unique(), 1, &Pubkey::new_unique()).unwrap();
        write_alloc_decimals(&mut data, 9, 6).unwrap();
        assert_eq!(read_vault_table_slot(&data).unwrap(), VAULT_TABLE_SLOT_MAX);
        // Lo que `restructure_settle` hace en CADA asiento con los slots que quedan fuera de la cesta (también el 9).
        for i in 0..MAX_TOKENS_PER_VAULT {
            write_allocation(&mut data, i, &Pubkey::default(), 0, &Pubkey::default()).unwrap();
            write_alloc_last_swap(&mut data, i, 0, 0).unwrap();
            clear_alloc_decimals(&mut data, i).unwrap();
        }
        assert_eq!(read_vault_table_slot(&data).unwrap(), VAULT_TABLE_SLOT_MAX, "un cambio de cesta no borra el slot de la tabla");
        assert_eq!(read_vault_table_slot(&vec![0u8; VAULT_TOTAL_LEN]).unwrap(), 0, "un vault de antes lee 0 = sin tabla");
    }

    #[test]
    fn nunca_guarda_0_ni_un_slot_de_mas_de_48_bits() {
        let mut data = vec![0u8; VAULT_TOTAL_LEN];
        assert!(write_vault_table_slot(&mut data, 0).is_err());
        assert!(write_vault_table_slot(&mut data, VAULT_TABLE_SLOT_MAX + 1).is_err());
        assert_eq!(read_vault_table_slot(&data).unwrap(), 0, "un intento fallido no escribe nada");
        assert!(write_vault_table_slot(&mut data[..1337], 5).is_err(), "cuenta demasiado corta");
    }
}
