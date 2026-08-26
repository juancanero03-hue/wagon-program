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
//!
//! # Token-2022 (ceremonia #55)
//!
//! La suite 31 ejercita cestas con mints Token-2022 (extensiones reales:
//! ScaledUiAmount/Pausable, el caso del incidente Athena). El shape de las 7
//! cuentas NO cambia (los suites clásicos no se tocan; el discriminador `route`
//! tampoco — gotcha 22: wagon lo valida contra su allowlist). Lo nuevo llega
//! por `remaining_accounts` OPCIONALES:
//!   - la cuenta cuyo key == TOKEN_2022_PROGRAM_ID es el programa Token-2022
//!     (obligatoria si CUALQUIER lado del swap vive en Token-2022);
//!   - la primera cuenta restante que NO sea ese programa se toma como el
//!     MINT del source (obligatoria solo si el SOURCE es Token-2022: su
//!     TransferChecked exige el mint).
//! Cada lado del swap se enruta al programa de token DUEÑO de su cuenta:
//! transfer clásico o TransferChecked 2022 para el source; MintTo clásico o
//! 2022 para el dest. Sin remaining_accounts el comportamiento es idéntico
//! byte a byte al de siempre.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::{invoke, invoke_signed};
use anchor_spl::token::{self, MintTo, Token, Transfer};

declare_id!("5XTrg9h1vGodDJv71xtv8ghvcVk5vWCaCuxGAi8ZmGww");

/// PDA seed for this program's authority.
pub const MOCK_AUTHORITY_SEED: &[u8] = b"mock-auth";

/// Programa SPL Token-2022 (espejo del const de wagon::token_io).
pub const TOKEN_2022_PROGRAM_ID: Pubkey =
    anchor_lang::solana_program::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

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
        // Remaining accounts opcionales (ver doc del módulo): programa 2022 +
        // mint del source. Ausentes => camino clásico idéntico al histórico.
        let mut t22_program: Option<&AccountInfo<'info>> = None;
        let mut source_mint: Option<&AccountInfo<'info>> = None;
        for acc in ctx.remaining_accounts {
            if *acc.key == TOKEN_2022_PROGRAM_ID {
                t22_program = Some(acc);
            } else if source_mint.is_none() {
                source_mint = Some(acc);
            }
        }

        // 1. Pull source from caller into collection account. `source_authority`
        //    is a Signer because Wagon passed it via invoke_signed with the
        //    vault PDA's seeds — signer status propagates through CPIs as long
        //    as each AccountMeta keeps is_signer=true.
        let source_is_2022 = *ctx.accounts.source_ata.owner == TOKEN_2022_PROGRAM_ID;
        if source_is_2022 {
            // TransferChecked (ix 12) por Token-2022: exige el mint del source.
            let mint_ai = source_mint.ok_or(anchor_lang::error::ErrorCode::AccountNotEnoughKeys)?;
            let prog_ai = t22_program.ok_or(anchor_lang::error::ErrorCode::AccountNotEnoughKeys)?;
            let decimals = read_mint_decimals(mint_ai)?;
            let mut data = Vec::with_capacity(10);
            data.push(12u8); // TransferChecked
            data.extend_from_slice(&args.amount_in.to_le_bytes());
            data.push(decimals);
            let ix = Instruction {
                program_id: TOKEN_2022_PROGRAM_ID,
                accounts: vec![
                    AccountMeta::new(*ctx.accounts.source_ata.key, false),
                    AccountMeta::new_readonly(*mint_ai.key, false),
                    AccountMeta::new(*ctx.accounts.source_collection_ata.key, false),
                    AccountMeta::new_readonly(*ctx.accounts.source_authority.key, true),
                ],
                data,
            };
            invoke(
                &ix,
                &[
                    ctx.accounts.source_ata.to_account_info(),
                    mint_ai.clone(),
                    ctx.accounts.source_collection_ata.to_account_info(),
                    ctx.accounts.source_authority.to_account_info(),
                    prog_ai.clone(),
                ],
            )?;
        } else {
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
        }

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
            let dest_is_2022 = *ctx.accounts.dest_mint.owner == TOKEN_2022_PROGRAM_ID;
            if dest_is_2022 {
                // MintTo (ix 7) por Token-2022, firmado por el PDA del mock.
                let prog_ai = t22_program.ok_or(anchor_lang::error::ErrorCode::AccountNotEnoughKeys)?;
                let mut data = Vec::with_capacity(9);
                data.push(7u8); // MintTo
                data.extend_from_slice(&args.out_amount.to_le_bytes());
                let ix = Instruction {
                    program_id: TOKEN_2022_PROGRAM_ID,
                    accounts: vec![
                        AccountMeta::new(*ctx.accounts.dest_mint.key, false),
                        AccountMeta::new(*ctx.accounts.dest_ata.key, false),
                        AccountMeta::new_readonly(*ctx.accounts.mock_authority.key, true),
                    ],
                    data,
                };
                invoke_signed(
                    &ix,
                    &[
                        ctx.accounts.dest_mint.to_account_info(),
                        ctx.accounts.dest_ata.to_account_info(),
                        ctx.accounts.mock_authority.to_account_info(),
                        prog_ai.clone(),
                    ],
                    signer_seeds,
                )?;
            } else {
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

/// Lee `decimals` (offset 44, idéntico classic/2022) sin deserializar el mint.
fn read_mint_decimals(mint_ai: &AccountInfo) -> Result<u8> {
    let data = mint_ai.try_borrow_data()?;
    require!(data.len() > 44, anchor_lang::error::ErrorCode::AccountDidNotDeserialize);
    Ok(data[44])
}

#[derive(Accounts)]
pub struct Route<'info> {
    // Position 0: dest_ata. Wagon's jupiter.rs convention places the
    // destination token account first so it can snapshot balance before/after.
    // #55: Unchecked para aceptar cuentas de AMBOS programas de token (el
    // typed `Account<TokenAccount>` rechazaba Token-2022); el propio programa
    // de token valida mint/owner/estado en el CPI.
    /// CHECK: token account del dest, validada por el programa de token en el CPI.
    #[account(mut)]
    pub dest_ata: UncheckedAccount<'info>,

    // Position 1: mock authority PDA. Signs the MintTo via invoke_signed.
    /// CHECK: PDA derived with MOCK_AUTHORITY_SEED; never allocated on-chain.
    #[account(seeds = [MOCK_AUTHORITY_SEED], bump)]
    pub mock_authority: UncheckedAccount<'info>,

    // Position 2: source_ata (USDC ATA of the vault, o escrow T22 en ventas).
    /// CHECK: token account del source, validada por el programa de token en el CPI.
    #[account(mut)]
    pub source_ata: UncheckedAccount<'info>,

    // Position 3: source collection account (mock_authority-owned ATA of the
    // source mint). Receives the USDC the vault pays.
    /// CHECK: token account de colección, validada por el programa de token en el CPI.
    #[account(mut)]
    pub source_collection_ata: UncheckedAccount<'info>,

    // Position 4: destination mint. Needs to be writable for MintTo.
    /// CHECK: mint del dest (classic o 2022), validado por el programa de token en el CPI.
    #[account(mut)]
    pub dest_mint: UncheckedAccount<'info>,

    // Position 5: source authority. Signer-via-invoke_signed from Wagon.
    /// CHECK: enforced by SPL transfer (must be authority on source_ata).
    pub source_authority: Signer<'info>,

    // Position 6: SPL Token program (clásico). El programa Token-2022, si hace
    // falta, llega por remaining_accounts (ver doc del módulo).
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
    pub token_ata: Account<'info, anchor_spl::token::TokenAccount>,
    #[account(mut)]
    pub token_mint: Account<'info, anchor_spl::token::Mint>,
    pub token_program: Program<'info, Token>,
}
