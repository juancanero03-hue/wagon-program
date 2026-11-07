//! Tabla de direcciones del vault (#56): lo que entra en ella y las CPI al programa de tablas. Lo usa
//! `instructions::vault_table_sync`; nada más escribe en estas tablas.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::address_lookup_table::{
    self as alt, instruction as alt_ix, state::AddressLookupTable,
};
use anchor_lang::solana_program::program::{invoke, invoke_signed};
use anchor_spl::token::spl_token;

use crate::constants::{CREATOR_REWARDS_SEED, MAX_TOKENS_PER_VAULT, USDC_MINT};
use crate::errors::WagonError;
use crate::instructions::restructure_init::RESTRUCTURE_SEED;
use crate::state::vault_layout as vlayout;
use crate::state::RestructureSession;
use crate::token_io::{derive_live_ata, TOKEN_2022_PROGRAM_ID};

/// Tope de direcciones de una tabla (programa de tablas).
pub const MAX_ADDRESSES: usize = alt::state::LOOKUP_TABLE_MAX_ADDRESSES;

/// Lo que va en la tabla, sacado del propio vault (sin repetir): vault, share mint, ATA USDC, ATA de participaciones del
/// vault, hucha del creador y la ATA de cada pata; con una sesión de cambio de cesta, también las de sus patas nuevas.
#[inline(never)]
pub fn wanted_addresses<'info>(
    vault_ai: &AccountInfo<'info>,
    vault: &Pubkey,
    session: Option<&UncheckedAccount<'info>>,
    remaining: &[AccountInfo<'info>],
) -> Result<Vec<Pubkey>> {
    let mut out: Vec<Pubkey> = Vec::with_capacity(5 + 2 * MAX_TOKENS_PER_VAULT);
    {
        let data = vault_ai.try_borrow_data()?;
        let creator = vlayout::read_creator(&data)?;
        let share_mint = vlayout::read_share_mint(&data)?;
        let (rewards_authority, _) =
            Pubkey::find_program_address(&[CREATOR_REWARDS_SEED, creator.as_ref()], &crate::ID);
        push_unique(&mut out, *vault);
        push_unique(&mut out, share_mint);
        push_unique(&mut out, vlayout::read_usdc_ata(&data)?);
        push_unique(&mut out, derive_live_ata(vault, &share_mint, &spl_token::ID));
        push_unique(&mut out, derive_live_ata(&rewards_authority, &USDC_MINT, &spl_token::ID));
        let count = (vlayout::read_allocation_count(&data)? as usize).min(MAX_TOKENS_PER_VAULT);
        for i in 0..count {
            let ata = vlayout::read_allocation_vault_ata(&data, i)?;
            if ata != Pubkey::default() {
                push_unique(&mut out, ata);
            }
        }
    }

    let Some(session) = session else {
        require!(remaining.is_empty(), WagonError::VaultTableMismatch);
        return Ok(out);
    };
    let session_ai = session.to_account_info();
    let (expected, _) = Pubkey::find_program_address(&[RESTRUCTURE_SEED, vault.as_ref()], &crate::ID);
    require_keys_eq!(session_ai.key(), expected, WagonError::VaultTableMismatch);
    require_keys_eq!(*session_ai.owner, crate::ID, WagonError::VaultTableMismatch);
    let s: Box<RestructureSession> = {
        let data = session_ai.try_borrow_data()?;
        Box::new(RestructureSession::try_deserialize(&mut &data[..])?)
    };
    let n = s.new_count as usize;
    require!(n <= MAX_TOKENS_PER_VAULT && remaining.len() == n, WagonError::VaultTableMismatch);
    for (i, mint_ai) in remaining.iter().enumerate() {
        require_keys_eq!(mint_ai.key(), s.new_mints[i], WagonError::AllocMintMismatch);
        let token_program = mint_ai.owner;
        require!(
            *token_program == spl_token::ID || *token_program == TOKEN_2022_PROGRAM_ID,
            WagonError::LegDestAtaMismatch
        );
        push_unique(&mut out, derive_live_ata(vault, &s.new_mints[i], token_program));
    }
    Ok(out)
}

fn push_unique(out: &mut Vec<Pubkey>, key: Pubkey) {
    if !out.contains(&key) {
        out.push(key);
    }
}

/// Lee una tabla de la PDA del vault y devuelve (entradas, direcciones de `wanted` que le faltan). Exige que sea del
/// programa de tablas, con la PDA como autoridad y activa.
#[inline(never)]
pub fn table_missing(table: &AccountInfo, authority: &Pubkey, wanted: &[Pubkey]) -> Result<(usize, Vec<Pubkey>)> {
    require_keys_eq!(*table.owner, alt::program::ID, WagonError::VaultTableMismatch);
    let data = table.try_borrow_data()?;
    let t = AddressLookupTable::deserialize(&data).map_err(|_| error!(WagonError::VaultTableMismatch))?;
    require!(t.meta.authority == Some(*authority), WagonError::VaultTableMismatch);
    require!(t.meta.deactivation_slot == u64::MAX, WagonError::VaultTableMismatch);
    let mut missing = Vec::new();
    for w in wanted {
        if !t.addresses.contains(w) {
            missing.push(*w);
        }
    }
    Ok((t.addresses.len(), missing))
}

/// Crea la tabla `[autoridad, slot]`. El programa de tablas solo exige la firma del pagador y que el slot sea reciente
/// (está en SlotHashes); si la cuenta ya es suya, no hace nada. El slot se comprueba ANTES (0 = «sin tabla» y 48 bits, lo que
/// guarda el vault): el resultado no depende de lo que haya en SlotHashes.
#[inline(never)]
pub fn cpi_create<'info>(
    table: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    payer: &AccountInfo<'info>,
    system: &AccountInfo<'info>,
    alt_program: &AccountInfo<'info>,
    slot: u64,
) -> Result<()> {
    require!(slot != 0 && slot <= vlayout::VAULT_TABLE_SLOT_MAX, WagonError::VaultTableMismatch);
    let (ix, address) = alt_ix::create_lookup_table(authority.key(), payer.key(), slot);
    require_keys_eq!(table.key(), address, WagonError::VaultTableMismatch);
    invoke(&ix, &[table.clone(), authority.clone(), payer.clone(), system.clone(), alt_program.clone()])?;
    Ok(())
}

/// Amplía la tabla con `addresses`; firma la autoridad (la PDA del vault) y el pagador cubre el rent de más.
#[inline(never)]
pub fn cpi_extend<'info>(
    table: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    payer: &AccountInfo<'info>,
    system: &AccountInfo<'info>,
    alt_program: &AccountInfo<'info>,
    addresses: Vec<Pubkey>,
    seeds: &[&[u8]],
) -> Result<()> {
    let ix = alt_ix::extend_lookup_table(table.key(), authority.key(), Some(payer.key()), addresses);
    invoke_signed(
        &ix,
        &[table.clone(), authority.clone(), payer.clone(), system.clone(), alt_program.clone()],
        &[seeds],
    )?;
    Ok(())
}
