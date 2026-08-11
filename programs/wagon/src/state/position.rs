//! Per-user, per-vault position. PDA seeds: `[b"user", vault, wallet]`.
//!
//! Tracks the investor's outstanding shares and their cost basis in USDC.
//! Cost basis is used to compute the performance fee on withdrawal:
//! `profit = exit_value_usdc - cost_basis_proportional`
//! and the fee = `max(0, profit) * performance_fee_bps / 10_000`.

use anchor_lang::prelude::*;

#[account]
pub struct UserPosition {
    /// Owner wallet.
    pub wallet: Pubkey,

    /// Vault this position belongs to.
    pub vault: Pubkey,

    /// Shares currently held.
    pub shares: u64,

    /// Accumulated USDC cost basis. Increased by each deposit; decreased
    /// pro-rata on withdrawal (by shares_burned / shares_before).
    pub cost_basis_usdc: u64,

    /// First deposit timestamp.
    pub created_at: i64,

    /// Most recent deposit timestamp.
    pub last_deposit_at: i64,

    /// PDA bump.
    pub bump: u8,

    /// Reserved for forward compatibility.
    pub reserved: [u8; 64],
}

impl UserPosition {
    pub const LEN: usize = 8  // discriminator
        + 32                  // wallet
        + 32                  // vault
        + 8                   // shares
        + 8                   // cost_basis_usdc
        + 8                   // created_at
        + 8                   // last_deposit_at
        + 1                   // bump
        + 64;                 // reserved

    /// Proportional cost basis for a slice of shares being withdrawn.
    /// Returns `(cost_basis_slice, shares_slice_checked)`.
    pub fn cost_basis_for_slice(
        &self,
        shares_being_withdrawn: u64,
    ) -> std::result::Result<u64, ProgramError> {
        // Capa 5 quirk: withdraw_init burns the shares from self.shares
        // BEFORE withdraw_settle is reached. If the user is withdrawing
        // 100% of their position, self.shares is 0 by the time settle
        // calls this helper, which previously triggered a division-by-zero
        // (mapped to MathOverflow at the call site). Reconstruct the
        // pre-burn total by adding shares_being_withdrawn back — that's
        // the denominator the proportional cost-basis calculation always
        // needed.
        let total_pre_burn = (self.shares as u128)
            .checked_add(shares_being_withdrawn as u128)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        if total_pre_burn == 0 {
            return Err(ProgramError::InvalidArgument);
        }
        let slice = (self.cost_basis_usdc as u128)
            .checked_mul(shares_being_withdrawn as u128)
            .ok_or(ProgramError::ArithmeticOverflow)?
            .checked_div(total_pre_burn)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        Ok(slice as u64)
    }
}
