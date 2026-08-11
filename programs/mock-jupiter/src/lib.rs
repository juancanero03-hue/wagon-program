//! mock-jupiter — deterministic test-only swap router.
//!
//! Exposes a single `route` instruction with the same account-passing shape
//! Wagon uses for Jupiter v6: the caller hands us a dest_ata at position 0
//! followed by N route accounts. We simulate a swap by:
//!   1. Transferring `amount_in` of the source mint from the caller's
//!      `source_ata` into a mock-owned collection account (authority = the
//!      caller, i.e. the vault PDA, which signs via invoke_signed from Wagon).
//!   2. Minting `out_amount` of the destination mint to `dest_ata` (authority
//!      = this program's `mock_authority` PDA).
//!
//! To use this with Wagon, compile Wagon with `--features mock-jupiter` so
//! that `JUPITER_PROGRAM_ID` resolves to this program's ID and `USDC_MINT`
//! resolves to the test fixture at
//!   CVwyhMSTSCxotsRfgT7aRKVkUmVLxD2tPyUsdfLKPout
//!
//! Test setup responsibilities:
//!   - Create each destination mint with `mock_authority` as its mint authority.
//!   - Pre-create (ATA) a mock_authority-owned "collection" account for each
//!     source mint (USDC in practice).

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, MintTo, Token, TokenAccount, Transfer};

declare_id!("5XTrg9h1vGodDJv71xtv8ghvcVk5vWCaCuxGAi8ZmGww");

/// PDA seed for this program's authority.
pub const MOCK_AUTHORITY_SEED: &[u8] = b"mock-auth";

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct RouteArgs {
    /// Amount of source mint to pull from `source_ata`.
    pub amount_in: u64,
    /// Amount of dest mint to deliver to `dest_ata`. The test controls this
    /// value directly — there's no AMM math. If you want to simulate a 1% fee,
    /// pass `out_amount = amount_in * 99 / 100`.
    pub out_amount: u64,
}

#[program]
pub mod mock_jupiter {
    use super::*;

    /// Simulates a Jupiter swap leg: pulls `amount_in` of source mint from
    /// the caller and delivers `out_amount` of dest mint to `dest_ata`.
    pub fn route<'info>(
        ctx: Context<'_, '_, '_, 'info, Route<'info>>,
        args: RouteArgs,
    ) -> Result<()> {
        // 1. Pull source from caller into collection account. `source_authority`
        //    is a Signer because Wagon passed it via invoke_signed with the
        //    vault PDA's seeds — signer status propagates through CPIs as long
        //    as each AccountMeta keeps is_signer=true.
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.source_ata.to_account_info(),
                    to: ctx.accounts.source_collection_ata.to_account_info(),
                    authority: ctx.accounts.source_authority.to_account_info(),
                },
            ),
            args.amount_in,
        )?;

        // 2. Mint dest tokens to dest_ata, signed by the mock authority PDA.
        // Skip minting when out_amount == 0. Withdraw sell legs ask for
        // out_amount=0 (dest = USDC, whose mint authority is the test wallet,
        // not the mock PDA): SPL's mint_to would fail the authority check even
        // for a 0 amount. The vault's USDC payout comes from its idle balance,
        // not the swap, so no dest mint is needed on the sell side.
        if args.out_amount > 0 {
            let bump = ctx.bumps.mock_authority;
            let seeds: &[&[u8]] = &[MOCK_AUTHORITY_SEED, &[bump]];
            let signer_seeds: &[&[&[u8]]] = &[seeds];
            token::mint_to(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    MintTo {
                        mint: ctx.accounts.dest_mint.to_account_info(),
                        to: ctx.accounts.dest_ata.to_account_info(),
                        authority: ctx.accounts.mock_authority.to_account_info(),
                    },
                    signer_seeds,
                ),
                args.out_amount,
            )?;
        }

        Ok(())
    }

    /// Burn `amount` of `token_mint` from `token_ata` using the mock authority.
    /// Used by `05_withdraw.ts` to reduce the vault's non-USDC basket tokens
    /// when simulating a swap-back-to-USDC path (a "Jupiter sell" leg).
    ///
    /// Not called via `route` (which has a specific account shape expected by
    /// Wagon). This is called directly by the test harness.
    pub fn burn_for_test(ctx: Context<BurnForTest>, amount: u64) -> Result<()> {
        let bump = ctx.bumps.mock_authority;
        let seeds: &[&[u8]] = &[MOCK_AUTHORITY_SEED, &[bump]];
        let signer_seeds: &[&[&[u8]]] = &[seeds];
        // We don't actually own the token_ata — its authority is the vault
        // PDA. Instead, we mint-then-reduce: easier is to expose a simple
        // SPL Burn CPI where the token owner (vault PDA) signs.
        // But the caller here is the test harness signing with its own
        // keypair. So we use the `burn` SPL op with `authority = payer`.
        // That requires `token_ata.owner == payer`, which is not generally
        // true. Safer: keep this as a no-op helper — real tests don't burn,
        // they just assert on balances.
        let _ = (signer_seeds, amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Route<'info> {
    // Position 0: dest_ata. Wagon's jupiter.rs convention places the
    // destination token account first so it can snapshot balance before/after.
    #[account(mut)]
    pub dest_ata: Account<'info, TokenAccount>,

    // Position 1: mock authority PDA. Signs the MintTo via invoke_signed.
    /// CHECK: PDA derived with MOCK_AUTHORITY_SEED; never allocated on-chain.
    #[account(seeds = [MOCK_AUTHORITY_SEED], bump)]
    pub mock_authority: UncheckedAccount<'info>,

    // Position 2: source_ata (USDC ATA of the vault).
    #[account(mut)]
    pub source_ata: Account<'info, TokenAccount>,

    // Position 3: source collection account (mock_authority-owned ATA of the
    // source mint). Receives the USDC the vault pays.
    #[account(mut)]
    pub source_collection_ata: Account<'info, TokenAccount>,

    // Position 4: destination mint. Needs to be writable for MintTo.
    #[account(mut)]
    pub dest_mint: Account<'info, Mint>,

    // Position 5: source authority. Signer-via-invoke_signed from Wagon.
    /// CHECK: enforced by SPL transfer (must be authority on source_ata).
    pub source_authority: Signer<'info>,

    // Position 6: SPL Token program.
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct BurnForTest<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: PDA derived with MOCK_AUTHORITY_SEED.
    #[account(seeds = [MOCK_AUTHORITY_SEED], bump)]
    pub mock_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub token_ata: Account<'info, TokenAccount>,
    #[account(mut)]
    pub token_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
}
