//! `set_vault_texts` — creator-only, de ESCRITURA ÚNICA POR CAMPO (ceremonia
//! USDC, D8: decisión de diseño del 2026-09-14, ampliada el 22-sep a TODOS los
//! caminos y afinada el 23-sep a «por campo»). Escribe la descripción y/o los
//! tags de un vault que nació con esos textos vacíos.
//!
//! Por qué existe: `create_vault` de 7 tokens con descripción larga ya no cabe
//! en una transacción de 1232 B (con las dos cuentas USDC de la comisión del
//! creador mide 1264 B). El cliente crea el vault con textos vacíos (≈ 990 B) y
//! los escribe con esta instrucción en una segunda transacción.
//!
//! Reglas:
//! - solo el creador (`has_one`) y solo un vault Active (mismo gate que
//!   `rebalance`: ni Paused, ni Liquidating, ni Restructuring, ni Closed);
//! - validaciones IDÉNTICAS a `create_vault`: longitud en bytes UTF-8 (≤ 256 y
//!   ≤ 64) y relleno a cero; «vacío» se decide sobre los BYTES (un texto de solo
//!   NUL es vacío), así todo éxito que escribe cierra su campo y el evento
//!   nunca miente; los dos textos vacíos se rechazan (`VaultTextsEmpty`);
//! - escritura única POR CAMPO: cada campo se escribe si y solo si sigue a cero
//!   (la descripción y los tags siguen siendo inmutables de por vida, como
//!   hasta hoy, que solo los escribía `create_vault`). Mandar un texto distinto
//!   para un campo ya escrito revierte (`VaultTextsAlreadySet`); mandar
//!   EXACTAMENTE lo ya escrito es un no-op con éxito, para que el reintento de
//!   una transacción que sí aterrizó no dé un falso fallo;
//! - VENTANA DE PUBLICACIÓN (decisión de diseño 2026-09-23: la descripción es
//!   INMUTABLE): solo escribe dentro de `VAULT_TEXTS_WINDOW_SECS` (24 h) desde
//!   `created_at`; después revierte con `VaultTextsWindowClosed`, salvo el reenvío
//!   idéntico, que sigue siendo un no-op con éxito (un reintento tardío de una
//!   transacción que sí aterrizó nunca da un falso fallo);
//! - NO lleva `protocol`: la pausa global no la bloquea a propósito (no mueve
//!   dinero y un vault a medio publicar debe poder completarse durante una
//!   pausa). Sin CPI ni cuentas de token.
//!
//! Toda la decisión vive en `plan::decide_texts` (`set_vault_texts/plan.rs`), una
//! función PURA fijada por tests de unidad con la tabla completa (el validador de
//! la CI no puede adelantar el reloj): el handler solo valida longitudes, decide y
//! aplica lo decidido.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::VaultTextsSet;
use crate::state::{VaultState, VaultStatus};

pub mod plan;
use plan::{decide_texts, TextsDecision};

#[derive(Accounts)]
pub struct SetVaultTexts<'info> {
    pub creator: Signer<'info>,

    #[account(
        mut,
        seeds = [
            VAULT_SEED,
            vault.creator.as_ref(),
            &vault.nonce.to_le_bytes(),
        ],
        bump = vault.bump,
        has_one = creator @ WagonError::UnauthorizedVaultCreator,
        constraint = vault.status() == VaultStatus::Active @ WagonError::VaultPaused,
    )]
    pub vault: Box<Account<'info, VaultState>>,
}

pub fn handler(ctx: Context<SetVaultTexts>, description: String, tags: String) -> Result<()> {
    require!(
        description.as_bytes().len() <= VAULT_DESC_LEN,
        WagonError::DescriptionTooLong
    );
    require!(
        tags.as_bytes().len() <= VAULT_TAGS_LEN,
        WagonError::TagsTooLong
    );
    let mut desc_buf = [0u8; VAULT_DESC_LEN];
    desc_buf[..description.len()].copy_from_slice(description.as_bytes());
    let mut tags_buf = [0u8; VAULT_TAGS_LEN];
    tags_buf[..tags.len()].copy_from_slice(tags.as_bytes());

    let vault = &mut ctx.accounts.vault;
    let now = Clock::get()?.unix_timestamp;
    let decision = decide_texts(
        &desc_buf,
        &tags_buf,
        &vault.description,
        &vault.tags,
        vault.created_at,
        now,
    );
    let (write_desc, write_tags) = match decision {
        TextsDecision::Write { desc, tags } => (desc, tags),
        TextsDecision::NoOp => return Ok(()),
        TextsDecision::Empty => return err!(WagonError::VaultTextsEmpty),
        TextsDecision::AlreadySet => return err!(WagonError::VaultTextsAlreadySet),
        TextsDecision::WindowClosed => return err!(WagonError::VaultTextsWindowClosed),
    };
    if write_desc {
        vault.description = desc_buf;
    }
    if write_tags {
        vault.tags = tags_buf;
    }
    emit!(VaultTextsSet {
        vault: vault.key(),
        creator: ctx.accounts.creator.key(),
        description_written: write_desc,
        tags_written: write_tags,
    });
    Ok(())
}
