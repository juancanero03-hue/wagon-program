//! Vault-level state. PDA seeds: `[b"vault", creator, nonce_le_bytes]`.
//!
//! Every vault has a fixed-size layout (10 allocation slots). Unused slots
//! carry `Pubkey::default()` and weight 0. Keeping the layout fixed means
//! clients know exactly how much data to fetch and lets us avoid realloc.

use anchor_lang::prelude::*;

use crate::constants::{
    MAX_TOKENS_PER_VAULT, VAULT_DESC_LEN, VAULT_IMAGE_URL_LEN, VAULT_NAME_LEN, VAULT_TAGS_LEN,
};

/// Lifecycle states for a vault. Stored as u8 for layout stability.
#[repr(u8)]
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum VaultStatus {
    Active = 0,
    Paused = 1,
    Liquidating = 2,
    Closed = 3,
    /// Upgrade #31: strategy change in flight (`restructure_init` ..
    /// `restructure_settle`/`restructure_abort`). Written byte-level by the
    /// restructure handlers since day one; M-2 promotes it into the enum so
    /// typed handlers stop mis-reading it as `Paused`.
    Restructuring = 4,
}

impl Default for VaultStatus {
    fn default() -> Self {
        VaultStatus::Active
    }
}

/// One slot in the vault basket. `mint == Pubkey::default()` means the slot
/// is empty (and `weight_bps` must be 0).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default, Debug)]
pub struct TokenAllocation {
    /// SPL mint of the token.
    pub mint: Pubkey,

    /// Target weight in basis points (0 to 10_000). Sum across non-empty
    /// slots must equal 10_000.
    pub weight_bps: u16,

    /// Vault-owned ATA holding this token. Owned by the vault PDA.
    pub vault_ata: Pubkey,

    /// Reserved for forward compatibility.
    pub reserved: [u8; 8],
}

impl TokenAllocation {
    /// Byte size of one allocation slot.
    pub const LEN: usize = 32 // mint
        + 2                   // weight_bps
        + 32                  // vault_ata
        + 8;                  // reserved

    pub fn is_empty(&self) -> bool {
        self.mint == Pubkey::default() && self.weight_bps == 0
    }
}

#[account]
pub struct VaultState {
    /// Wallet that created the vault. Only this pubkey can rebalance / close.
    pub creator: Pubkey,

    /// Creator-supplied nonce to allow one wallet to create multiple vaults
    /// without colliding PDA seeds.
    pub nonce: u64,

    /// SPL mint representing vault shares. Authority = vault PDA.
    pub share_mint: Pubkey,

    /// Vault-owned USDC ATA (receives deposits, holds USDC during liquidation).
    pub usdc_ata: Pubkey,

    /// Lifecycle state. See `VaultStatus`.
    pub status: u8,

    // --- metadata (fixed-length) ---------------------------------------------
    pub name: [u8; VAULT_NAME_LEN],
    pub description: [u8; VAULT_DESC_LEN],
    pub image_url: [u8; VAULT_IMAGE_URL_LEN],
    pub tags: [u8; VAULT_TAGS_LEN],

    // --- economic parameters -------------------------------------------------
    /// Creator-chosen performance fee rate in basis points. IMMUTABLE after
    /// `create_vault`. Must fall in `[min_perf_fee_bps, max_perf_fee_bps]`
    /// as configured on `ProtocolConfig`.
    pub performance_fee_bps: u16,

    /// Per-swap max slippage in basis points (50..=500).
    pub max_slippage_bps: u16,

    /// Number of populated allocation slots (1..=10).
    pub allocation_count: u8,

    /// Fixed-size allocation table.
    pub allocations: [TokenAllocation; MAX_TOKENS_PER_VAULT],

    // --- share accounting ----------------------------------------------------
    /// Total shares outstanding (minted minus burned).
    pub total_shares: u64,

    /// Aggregate cost basis across all active `UserPosition`s. Used for HWM
    /// cross-checks and for computing creator/protocol-minted share cost basis.
    pub aggregate_cost_basis_usdc: u64,

    // --- fee accrual ---------------------------------------------------------
    /// Cached TVL in USDC atomic units, refreshed whenever the program
    /// computes NAV during any interaction.
    pub tvl_last_computed_usdc: u64,

    /// Last time `accrue_management_fee` ran to completion.
    pub last_fee_accrual_ts: i64,

    // --- lifecycle timestamps ------------------------------------------------
    pub created_at: i64,
    pub liquidation_started_at: i64,

    /// PDA bump.
    pub bump: u8,

    /// Bump for the share mint PDA.
    pub share_mint_bump: u8,

    /// Reserved for forward compatibility without breaking layout.
    pub reserved: [u8; 128],
}

impl VaultState {
    /// Total byte size of the account data.
    pub const LEN: usize = 8  // discriminator
        + 32                  // creator
        + 8                   // nonce
        + 32                  // share_mint
        + 32                  // usdc_ata
        + 1                   // status
        + VAULT_NAME_LEN
        + VAULT_DESC_LEN
        + VAULT_IMAGE_URL_LEN
        + VAULT_TAGS_LEN
        + 2                   // performance_fee_bps
        + 2                   // max_slippage_bps
        + 1                   // allocation_count
        + (TokenAllocation::LEN * MAX_TOKENS_PER_VAULT)
        + 8                   // total_shares
        + 8                   // aggregate_cost_basis_usdc
        + 8                   // tvl_last_computed_usdc
        + 8                   // last_fee_accrual_ts
        + 8                   // created_at
        + 8                   // liquidation_started_at
        + 1                   // bump
        + 1                   // share_mint_bump
        + 128;                // reserved

    pub fn status(&self) -> VaultStatus {
        match self.status {
            0 => VaultStatus::Active,
            1 => VaultStatus::Paused,
            2 => VaultStatus::Liquidating,
            3 => VaultStatus::Closed,
            4 => VaultStatus::Restructuring,
            _ => VaultStatus::Paused, // treat corrupt value as paused to fail safe
        }
    }

    pub fn set_status(&mut self, s: VaultStatus) {
        self.status = s as u8;
    }

    /// Iterator over only the populated allocation slots.
    pub fn active_allocations(&self) -> impl Iterator<Item = &TokenAllocation> {
        self.allocations
            .iter()
            .take(self.allocation_count as usize)
            .filter(|a| !a.is_empty())
    }
}
