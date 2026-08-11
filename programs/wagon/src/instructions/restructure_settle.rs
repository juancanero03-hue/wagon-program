//! `restructure_settle` — upgrade #31, paso final del cambio de estrategia.
//!
//! Exige ventas de TODOS los salientes completadas (balance exacto 0) y
//! compras de TODOS los entrantes completadas. Escribe la tabla nueva
//! (mints, pesos, ATAs derivadas en vivo, decimales), traslada el caché de
//! precios de los tokens que permanecen y ceba el de los entrantes con los
//! fills reales de la sesión, recalcula el TVL, sella
//! `last_restructured_at` (invalida sesiones dep/wd antiguas) y reactiva
//! el vault. La sesión se cierra (rent al creador).
//!
//! remaining_accounts:
//!   [ (mint_i, ata_i) por cada índice NUEVO en orden ]  — 2*new_count
//!   [ ata_j por cada índice VIEJO eliminado (no-USDC), en orden ascendente ]

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::VaultRestructured;
use crate::instructions::restructure_init::RESTRUCTURE_SEED;
use crate::pricing::read_token_amount;
use crate::state::vault_layout as vlayout;
use crate::state::{ProtocolConfig, RestructureSession};

#[derive(Accounts)]
pub struct RestructureSettle<'info> {
    #[account(mut)]
    pub creator: Signer<'info>,

    #[account(
        mut,
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// CHECK: PDA verificada byte-level abajo.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    /// CHECK: pubkey verificada contra vault_layout::read_usdc_ata.
    pub vault_usdc_ata: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [RESTRUCTURE_SEED, vault.key().as_ref()],
        bump = restructure_session.bump,
        has_one = vault @ WagonError::RestructureSessionMismatch,
        close = creator,
    )]
    pub restructure_session: Box<Account<'info, RestructureSession>>,
}

pub fn handler(ctx: Context<RestructureSettle>) -> Result<()> {
    let vault_ai = ctx.accounts.vault.to_account_info();
    let guard = crate::guards::VaultGuard::load(
        &vault_ai,
        &ctx.accounts.vault.key(),
        WagonError::VaultPaused,
    )?;
    let session = &ctx.accounts.restructure_session;

    let (creator, nonce, vault_bump, status) =
        (guard.creator, guard.nonce, guard.bump, guard.status);
    let nonce_le = nonce.to_le_bytes();
    let (old_count, usdc_ata_pk, old_tvl) = {
        let data = vault_ai.try_borrow_data()?;
        (
            vlayout::read_allocation_count(&data)?,
            vlayout::read_usdc_ata(&data)?,
            vlayout::read_tvl_last_computed_usdc(&data)?,
        )
    };
    require!(status == 4u8, WagonError::NotRestructuring);
    require_keys_eq!(
        creator,
        ctx.accounts.creator.key(),
        WagonError::UnauthorizedVaultCreator
    );
    require_keys_eq!(
        ctx.accounts.vault_usdc_ata.key(),
        usdc_ata_pk,
        WagonError::InvalidJupiterRoute
    );

    let new_count = session.new_count as usize;
    let vault_key = ctx.accounts.vault.key();

    // ---- Tablas vieja/nueva: clasificar slots -------------------------------
    let mut old_mints = [Pubkey::default(); MAX_TOKENS_PER_VAULT];
    let mut old_cache = [(0u64, 0u32); MAX_TOKENS_PER_VAULT];
    let mut old_decimals = [None as Option<u8>; MAX_TOKENS_PER_VAULT];
    {
        let data = vault_ai.try_borrow_data()?;
        for j in 0..old_count as usize {
            old_mints[j] = vlayout::read_allocation_mint(&data, j)?;
            old_cache[j] = vlayout::read_alloc_last_swap(&data, j)?;
            old_decimals[j] = vlayout::read_alloc_decimals(&data, j)?;
        }
    }
    let in_new = |m: &Pubkey| (0..new_count).any(|i| session.new_mints[i] == *m);
    let in_old = |m: &Pubkey| (0..old_count as usize).any(|j| old_mints[j] == *m);

    // Máscaras de progreso exigidas.
    let mut removed_mask = 0u16;
    for j in 0..old_count as usize {
        if old_mints[j] != USDC_MINT && !in_new(&old_mints[j]) {
            removed_mask |= 1u16 << j;
        }
    }
    let mut added_mask = 0u16;
    for i in 0..new_count {
        if session.new_mints[i] != USDC_MINT && !in_old(&session.new_mints[i]) {
            added_mask |= 1u16 << i;
        }
    }
    // F4b review (2026-06-11): NO exigimos el bitmap `sells_done`. El
    // invariante real es el check por-leg de abajo: cada ATA saliente con
    // balance EXACTAMENTE 0. Exigir además el bit bloqueaba para siempre el
    // settle de vaults con un saliente de balance 0 (slot con peso 0, o
    // barrido previo por liquidación): la venta on-chain exige amount_in>0,
    // así que ese bit era imposible de marcar. El bitmap queda como
    // bookkeeping informativo para el frontend (resume). Limitación
    // documentada aparte: un vault VACÍO (sin USDC idle) tampoco puede
    // completar buys → para cambiar estrategia sin holders, abort + nuevo
    // vault.
    require!(
        session.buys_complete(added_mask),
        WagonError::RestructureIncomplete
    );

    // ---- remaining: pares nuevos + ATAs de eliminados -----------------------
    let removed_count = removed_mask.count_ones() as usize;
    let remaining = ctx.remaining_accounts;
    require!(
        remaining.len() == 2 * new_count + removed_count,
        WagonError::AllocMintMismatch
    );

    // Eliminados: balance EXACTAMENTE cero (las ventas son ExactIn del total).
    let mut r = 2 * new_count;
    for j in 0..old_count as usize {
        if removed_mask & (1u16 << j) == 0 {
            continue;
        }
        let ata_ai = &remaining[r];
        let expected = crate::token_io::derive_live_ata(&vault_key, &old_mints[j], ata_ai.owner);
        require_keys_eq!(ata_ai.key(), expected, WagonError::LegDestAtaMismatch);
        require!(
            read_token_amount(ata_ai)? == 0,
            WagonError::RestructureResidualBalance
        );
        r += 1;
    }

    // Nuevos: validar mint+ata, leer decimales y balances.
    let mut new_atas = [Pubkey::default(); MAX_TOKENS_PER_VAULT];
    let mut new_decimals = [0u8; MAX_TOKENS_PER_VAULT];
    let mut new_balances = [0u64; MAX_TOKENS_PER_VAULT];
    for i in 0..new_count {
        let mint_ai = &remaining[2 * i];
        let ata_ai = &remaining[2 * i + 1];
        require_keys_eq!(
            mint_ai.key(),
            session.new_mints[i],
            WagonError::AllocMintMismatch
        );
        let expected =
            crate::token_io::derive_live_ata(&vault_key, &session.new_mints[i], mint_ai.owner);
        require_keys_eq!(ata_ai.key(), expected, WagonError::LegDestAtaMismatch);
        new_decimals[i] = crate::token_io::read_mint_decimals(mint_ai)?;
        new_atas[i] = ata_ai.key();
        new_balances[i] = if session.new_mints[i] == USDC_MINT {
            0
        } else {
            read_token_amount(ata_ai)?
        };
    }

    // ---- Escribir la tabla nueva + caché + TVL ------------------------------
    let now = Clock::get()?.unix_timestamp;
    let ts32: u32 = u32::try_from(now.max(0)).unwrap_or(u32::MAX);
    let idle_usdc = read_token_amount(&ctx.accounts.vault_usdc_ata.to_account_info())?;
    let mut tvl: u128 = idle_usdc as u128;

    {
        let mut data = vault_ai.try_borrow_mut_data()?;
        for i in 0..new_count {
            let m = session.new_mints[i];
            vlayout::write_allocation(&mut data, i, &m, session.new_weights_bps[i], &new_atas[i])?;
            vlayout::write_alloc_decimals(&mut data, i, new_decimals[i])?;
            // Caché: entrantes con su fill real; persistentes heredan el slot viejo.
            let (pq, ts) = if added_mask & (1u16 << i) != 0 {
                let (u, t) = (session.buy_usdc_in[i], session.buy_tokens_out[i]);
                let pq = if t > 0 {
                    u64::try_from((u as u128).saturating_mul(1_000_000_000) / t as u128)
                        .unwrap_or(0)
                } else {
                    0
                };
                (pq, ts32)
            } else if let Some(j) = (0..old_count as usize).find(|&j| old_mints[j] == m) {
                old_cache[j]
            } else {
                (0u64, 0u32)
            };
            vlayout::write_alloc_last_swap(&mut data, i, pq, ts)?;
            if pq > 0 && m != USDC_MINT {
                tvl = tvl.saturating_add(
                    (new_balances[i] as u128).saturating_mul(pq as u128) / 1_000_000_000,
                );
            }
        }
        for i in new_count..MAX_TOKENS_PER_VAULT {
            vlayout::write_allocation(&mut data, i, &Pubkey::default(), 0, &Pubkey::default())?;
            vlayout::write_alloc_last_swap(&mut data, i, 0, 0)?;
            vlayout::clear_alloc_decimals(&mut data, i)?;
        }
        vlayout::write_allocation_count(&mut data, new_count as u8)?;
        let tvl64 = u64::try_from(tvl).unwrap_or(u64::MAX);
        vlayout::write_tvl_last_computed_usdc(&mut data, tvl64)?;
        vlayout::write_last_restructured_at(&mut data, now)?;
        vlayout::write_status(&mut data, 0u8 /* Active */)?;
    }

    let protocol = &mut ctx.accounts.protocol;
    let tvl64 = u64::try_from(tvl).unwrap_or(u64::MAX);
    // H4 (ceremonia #45): 2º amplificador -old+new. Mismo clamp que mark_tvl: el
    // agregado global solo puede BAJAR aquí (un `old_tvl` deflactado por un abort
    // previo no puede inflarlo). Se conserva `write_tvl_last_computed(tvl64)`
    // arriba (display per-vault exacto). Subestimar = lado conservador sellado.
    if tvl64 < old_tvl {
        protocol.total_tvl_usdc = protocol.total_tvl_usdc.saturating_sub(old_tvl - tvl64);
    }

    emit!(VaultRestructured {
        vault: vault_key,
        old_count,
        new_count: new_count as u8,
        tvl_after_usdc: tvl64,
    });
    Ok(())
}
