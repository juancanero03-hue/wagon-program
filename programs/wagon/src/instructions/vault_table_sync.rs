//! `vault_table_sync` — tabla de direcciones del vault (#56). PERMISSIONLESS: cualquiera la llama y el firmante paga el
//! rent. La web la llama justo después de `create_vault` (dentro no cabe) y al abrir o asentar un cambio de cesta.
//!
//! La autoridad de la tabla es la PDA `[b"vault-table", vault]`, que solo firma (por CPI) las ampliaciones que hace esta
//! instrucción: no hay clave que guardar. El CONTENIDO no lo elige quien llama: lo saca el programa del propio vault
//! (`wanted_addresses`), así que en la tabla solo entran direcciones de ese vault, nunca de más.
//!
//! El vault guarda el SLOT de creación de su tabla (`vault_layout::VAULT_TABLE_SLOT_OFFSET`); la dirección la deriva el
//! programa de tablas de `[autoridad, slot]`. Tres caminos:
//! 1. Sin tabla (slot 0): crea la de `recent_slot`, la llena y guarda el slot. Si alguien creó antes una tabla en esa
//!    dirección (crear no exige la firma de la autoridad), el programa de tablas lo da por hecho y esta la adopta: su
//!    autoridad es por construcción la PDA del vault y solo esta instrucción puede ampliarla.
//! 2. Con tabla: añade solo las direcciones que falten (6231 si no falta ninguna).
//! 3. Si lo que falta no cabe en 256: crea una tabla NUEVA con solo lo vivo y guarda su slot (rotación); la anterior se
//!    queda como estaba. Solo se añaden direcciones distintas, así que llenar una tabla exige pasar por cientos de tokens.
//!
//! Tras cada CPI se relee la tabla: del programa de tablas, autoridad = la PDA, activa y con todo lo esperado (6230 si
//! no). Lo añadido en un slot no se puede usar hasta el slot siguiente (regla del runtime): el cliente espera un slot.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::address_lookup_table::{self as alt, instruction as alt_ix};

use crate::constants::VAULT_TABLE_SEED;
use crate::errors::WagonError;
use crate::events::VaultTableSynced;
use crate::guards::VaultGuard;
use crate::state::vault_layout as vlayout;
use crate::vault_table::{cpi_create, cpi_extend, table_missing, wanted_addresses, MAX_ADDRESSES};

#[derive(Accounts)]
pub struct VaultTableSync<'info> {
    /// Cualquiera; paga el rent de la tabla y de lo que se le añada.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: VaultState en CUALQUIER estado (dueño, semillas y bump por `VaultGuard`); guarda el slot de su tabla.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    /// CHECK: PDA [b"vault-table", vault], autoridad de la tabla. Sin datos: solo firma las ampliaciones por CPI.
    #[account(seeds = [VAULT_TABLE_SEED, vault.key().as_ref()], bump)]
    pub table_authority: UncheckedAccount<'info>,

    /// CHECK: la tabla que el vault guarda (la de la PDA y el slot guardado). Sin tabla todavía, el centinela (None).
    #[account(mut)]
    pub current_table: Option<UncheckedAccount<'info>>,

    /// CHECK: la tabla de la PDA y `recent_slot`. Solo se usa al crear (primera vez o rotación); si no, se ignora.
    #[account(mut)]
    pub new_table: UncheckedAccount<'info>,

    /// CHECK: el programa de tablas de direcciones.
    #[account(address = alt::program::ID)]
    pub address_lookup_table_program: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,

    /// CHECK: la sesión de cambio de cesta ABIERTA del vault (PDA [b"restructure", vault]). Si viene, entran también las
    /// ATAs de sus patas nuevas, con sus mints en `remaining_accounts` en el orden de la sesión; si no, ninguna remaining.
    pub restructure_session: Option<UncheckedAccount<'info>>,
}

pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, VaultTableSync<'info>>,
    recent_slot: u64,
) -> Result<()> {
    let vault = ctx.accounts.vault.key();
    let vault_ai = ctx.accounts.vault.to_account_info();
    VaultGuard::load(&vault_ai, &vault, WagonError::VaultTableMismatch)?;
    let authority = ctx.accounts.table_authority.key();
    let wanted = wanted_addresses(&vault_ai, &vault, ctx.accounts.restructure_session.as_ref(), ctx.remaining_accounts)?;
    let stored_slot = {
        let data = vault_ai.try_borrow_data()?;
        vlayout::read_vault_table_slot(&data)?
    };

    let payer = ctx.accounts.payer.to_account_info();
    let authority_ai = ctx.accounts.table_authority.to_account_info();
    let alt_program = ctx.accounts.address_lookup_table_program.to_account_info();
    let system = ctx.accounts.system_program.to_account_info();
    let new_table = ctx.accounts.new_table.to_account_info();
    let create = |table: &AccountInfo<'info>| -> Result<Vec<Pubkey>> {
        cpi_create(table, &authority_ai, &payer, &system, &alt_program, recent_slot)?;
        // Recién creada (o adoptada si alguien se adelantó, vacía: solo esta instrucción la amplía): todo lo que no tenga.
        let (_, to_add) = table_missing(table, &authority, &wanted)?;
        Ok(to_add)
    };

    // Qué tabla se escribe: la guardada si lo que falta cabe; si no hay o no cabe, una nueva con `recent_slot`.
    let (target, slot, created, rotated, to_add) = if stored_slot == 0 {
        require!(ctx.accounts.current_table.is_none(), WagonError::VaultTableMismatch);
        let to_add = create(&new_table)?;
        (new_table, recent_slot, true, false, to_add)
    } else {
        let current = ctx.accounts.current_table.as_ref().ok_or(WagonError::VaultTableMismatch)?.to_account_info();
        let (expected, _) = alt_ix::derive_lookup_table_address(&authority, stored_slot);
        require_keys_eq!(current.key(), expected, WagonError::VaultTableMismatch);
        let (len, missing) = table_missing(&current, &authority, &wanted)?;
        require!(!missing.is_empty(), WagonError::VaultTableUpToDate);
        if len + missing.len() <= MAX_ADDRESSES {
            (current, stored_slot, false, false, missing)
        } else {
            // Rotación: una tabla NUEVA (otro slot) con solo lo vivo; la anterior se queda como estaba.
            require!(recent_slot != stored_slot, WagonError::VaultTableMismatch);
            let to_add = create(&new_table)?;
            (new_table, recent_slot, false, true, to_add)
        }
    };

    let added = to_add.len();
    if added > 0 {
        let bump = [ctx.bumps.table_authority];
        let seeds: &[&[u8]] = &[VAULT_TABLE_SEED, vault.as_ref(), &bump];
        cpi_extend(&target, &authority_ai, &payer, &system, &alt_program, to_add, seeds)?;
    }

    // Comprobación final sobre la cuenta ya escrita: tiene TODO lo esperado.
    let (len, still_missing) = table_missing(&target, &authority, &wanted)?;
    require!(still_missing.is_empty(), WagonError::VaultTableMismatch);
    if created || rotated {
        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::write_vault_table_slot(&mut data, slot)?;
    }

    emit!(VaultTableSynced {
        vault,
        table: target.key(),
        slot,
        added: added as u8,
        len: len as u16,
        created,
        rotated,
    });
    Ok(())
}
