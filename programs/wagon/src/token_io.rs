//! Utilidades canónicas de cuentas SPL — refactor R-1 (2026-06-11).
//!
//! Antes de R-1: `verify_token_account` vivía copiada en 6 instrucciones,
//! `read_token_amount` en 3 y el offset de decimales del mint en 3. Una
//! sola copia, un solo sitio que auditar.

use anchor_lang::prelude::*;
use anchor_spl::token::spl_token;

use crate::errors::WagonError;

/// Programa SPL Token-2022 (los xStocks y mints de MetaDAO viven ahí).
pub const TOKEN_2022_PROGRAM_ID: Pubkey =
    anchor_lang::solana_program::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

/// Offset de `decimals` en el layout de Mint (idéntico en classic y 2022).
pub const MINT_DECIMALS_OFFSET: usize = 44;

/// Valida que `acc` es una token account (classic O Token-2022, upgrade
/// #28) con el mint y owner esperados. Lectura byte-level, sin materializar
/// structs en el stack BPF (ADR 0004).
pub fn verify_token_account(
    acc: &AccountInfo,
    expected_mint: &Pubkey,
    expected_owner: &Pubkey,
) -> Result<()> {
    let prog_owner = acc.owner;
    require!(
        *prog_owner == spl_token::ID || *prog_owner == TOKEN_2022_PROGRAM_ID,
        WagonError::InvalidJupiterRoute
    );
    let data = acc.try_borrow_data()?;
    require!(data.len() >= 165, WagonError::InvalidJupiterRoute);
    let mut mint_buf = [0u8; 32];
    mint_buf.copy_from_slice(&data[0..32]);
    let mut owner_buf = [0u8; 32];
    owner_buf.copy_from_slice(&data[32..64]);
    require_keys_eq!(
        Pubkey::new_from_array(mint_buf),
        *expected_mint,
        WagonError::InvalidJupiterRoute
    );
    require_keys_eq!(
        Pubkey::new_from_array(owner_buf),
        *expected_owner,
        WagonError::InvalidJupiterRoute
    );
    Ok(())
}

/// Lee `amount` (offset 64) de una token account sin deserializarla.
pub fn read_token_amount(acc: &AccountInfo) -> Result<u64> {
    let data = acc.try_borrow_data()?;
    if data.len() < 72 {
        return err!(WagonError::InvalidPriceAccount);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[64..72]);
    Ok(u64::from_le_bytes(buf))
}

/// Offset del byte `state` en el layout de una token account SPL (classic o
/// 2022; los primeros 165 B son idénticos): mint(32)+owner(32)+amount(8)+
/// delegate COption(4+32)=108. 0=Uninitialized, 1=Initialized, 2=Frozen.
pub const TOKEN_STATE_OFFSET: usize = 108;
/// Valor de `state` cuando la token account está CONGELADA por su freeze
/// authority (Circle en USDC, el emisor de un token con freeze).
pub const TOKEN_STATE_FROZEN: u8 = 2;

/// Lee el byte `state` (offset 108) de una token account sin deserializarla.
/// Usado por A5 (`deposit_force_release`, ceremonia #50) como PRUEBA de
/// congelación: es una lectura PURA, inmune al propio freeze (leer una cuenta
/// congelada nunca revierte; solo moverla lo hace). El caller valida además
/// mint+owner con `verify_token_account` antes de fiarse de este byte.
pub fn read_token_state(acc: &AccountInfo) -> Result<u8> {
    let data = acc.try_borrow_data()?;
    if data.len() < 165 {
        return err!(WagonError::InvalidJupiterRoute);
    }
    Ok(data[TOKEN_STATE_OFFSET])
}

/// Lee `decimals` de un mint account (classic o 2022).
pub fn read_mint_decimals(mint_ai: &AccountInfo) -> Result<u8> {
    let data = mint_ai.try_borrow_data()?;
    require!(data.len() > MINT_DECIMALS_OFFSET, WagonError::AllocMintMismatch);
    Ok(data[MINT_DECIMALS_OFFSET])
}

/// ATA canónica de (owner, mint) derivada con el token program VIVO del
/// account pasado (lección del upgrade #27: los vaults pre-#27 guardan ATAs
/// derivadas con el programa equivocado para mints Token-2022).
pub fn derive_live_ata(owner: &Pubkey, mint: &Pubkey, live_token_program: &Pubkey) -> Pubkey {
    anchor_spl::associated_token::get_associated_token_address_with_program_id(
        owner,
        mint,
        live_token_program,
    )
}

// ---------------------------------------------------------------------------
// Upgrade #31 (F2b) — CPIs de movimiento de escrow, válidos para classic Y
// Token-2022. Construimos la instrucción a mano (los tags de TransferChecked
// = 12 y CloseAccount = 9 son idénticos en ambos programas) en lugar de usar
// los wrappers tipados de anchor_spl, que están ligados a un Program<> fijo.
// El program_id se toma del OWNER REAL de la cuenta de escrow, así el mismo
// código mueve xStocks (Token-2022) y SPL clásico.
// ---------------------------------------------------------------------------

/// `TransferChecked` firmado por un PDA del programa. `token_program_ai`
/// debe ser el AccountInfo del programa dueño de `from`/`to` (classic o
/// 2022); el caller ya lo validó vía `verify_token_account`.
#[allow(clippy::too_many_arguments)]
pub fn transfer_checked_signed<'info>(
    token_program_ai: &AccountInfo<'info>,
    from: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
    to: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    signer_seeds: &[&[&[u8]]],
    amount: u64,
    decimals: u8,
) -> Result<()> {
    use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
    use anchor_lang::solana_program::program::invoke_signed;

    require!(
        *token_program_ai.key == spl_token::ID || *token_program_ai.key == TOKEN_2022_PROGRAM_ID,
        WagonError::InvalidJupiterRoute
    );
    require_keys_eq!(*from.owner, *token_program_ai.key, WagonError::InvalidJupiterRoute);

    // Layout spl-token: tag(12) | amount u64 LE | decimals u8
    let mut data = Vec::with_capacity(10);
    data.push(12u8);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);

    let ix = Instruction {
        program_id: *token_program_ai.key,
        accounts: vec![
            AccountMeta::new(*from.key, false),
            AccountMeta::new_readonly(*mint.key, false),
            AccountMeta::new(*to.key, false),
            AccountMeta::new_readonly(*authority.key, true),
        ],
        data,
    };
    invoke_signed(
        &ix,
        &[from.clone(), mint.clone(), to.clone(), authority.clone()],
        signer_seeds,
    )
    .map_err(|e| {
        msg!("transfer_checked CPI failed: {:?}", e);
        error!(WagonError::InvalidJupiterRoute)
    })
}

/// `CloseAccount` firmado por un PDA del programa. La renta va a `dest`.
pub fn close_token_account_signed<'info>(
    token_program_ai: &AccountInfo<'info>,
    account: &AccountInfo<'info>,
    dest: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
    use anchor_lang::solana_program::program::invoke_signed;

    require!(
        *token_program_ai.key == spl_token::ID || *token_program_ai.key == TOKEN_2022_PROGRAM_ID,
        WagonError::InvalidJupiterRoute
    );
    require_keys_eq!(*account.owner, *token_program_ai.key, WagonError::InvalidJupiterRoute);

    let ix = Instruction {
        program_id: *token_program_ai.key,
        accounts: vec![
            AccountMeta::new(*account.key, false),
            AccountMeta::new(*dest.key, false),
            AccountMeta::new_readonly(*authority.key, true),
        ],
        data: vec![9u8],
    };
    invoke_signed(
        &ix,
        &[account.clone(), dest.clone(), authority.clone()],
        signer_seeds,
    )
    .map_err(|e| {
        msg!("close_account CPI failed: {:?}", e);
        error!(WagonError::InvalidJupiterRoute)
    })
}
