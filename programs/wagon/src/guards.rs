//! Guardias canónicas del vault — refactor R-1 (2026-06-11).
//!
//! ÚNICA fuente de verdad para la comprobación más crítica del protocolo:
//! que la cuenta `vault` pasada a un handler es EL vault PDA legítimo
//! (owner = este programa, seeds [VAULT_SEED, creator, nonce], bump
//! correcto) y está en el estado adecuado. Antes de R-1 este bloque estaba
//! copiado a mano en 13 handlers; una divergencia accidental en una copia
//! habría sido una vulnerabilidad silenciosa.

use anchor_lang::prelude::*;

use crate::constants::VAULT_SEED;
use crate::errors::WagonError;
use crate::state::vault_layout as vlayout;

/// Snapshot verificado de los campos de identidad del vault.
pub struct VaultGuard {
    pub creator: Pubkey,
    pub nonce: u64,
    pub bump: u8,
    pub status: u8,
}

impl VaultGuard {
    /// Verifica owner + derivación PDA + bump y devuelve los campos de
    /// identidad. `err` es el error que asignaba históricamente cada
    /// handler a estos fallos (VaultPaused en deposits, VaultClosed en
    /// withdraws) — se conserva para no cambiar códigos observables.
    pub fn load(vault_ai: &AccountInfo, expected_key: &Pubkey, err: WagonError) -> Result<Self> {
        require_keys_eq!(*vault_ai.owner, crate::ID, err);
        let (creator, nonce, bump, status) = {
            let data = vault_ai.try_borrow_data()?;
            (
                vlayout::read_creator(&data)?,
                vlayout::read_nonce(&data)?,
                vlayout::read_bump(&data)?,
                vlayout::read_status(&data)?,
            )
        };
        let nonce_le = nonce.to_le_bytes();
        let (derived, derived_bump) =
            Pubkey::find_program_address(&[VAULT_SEED, creator.as_ref(), &nonce_le], &crate::ID);
        require_keys_eq!(*expected_key, derived, err);
        if bump != derived_bump {
            return Err(err.into());
        }
        Ok(Self { creator, nonce, bump, status })
    }

    /// load + exige status Active(0). El caso de 12 de los 13 call sites.
    pub fn load_active(vault_ai: &AccountInfo, expected_key: &Pubkey, err: WagonError) -> Result<Self> {
        let g = Self::load(vault_ai, expected_key, err)?;
        if g.status != 0u8 {
            return Err(err.into());
        }
        Ok(g)
    }

    /// Semillas de firma del vault PDA, listas para CPI.
    /// Uso: `let nonce_le = g.nonce.to_le_bytes(); let bump_arr = [g.bump];`
    /// y luego `g.signer_seeds(&nonce_le, &bump_arr)`.
    pub fn signer_seeds<'a>(
        &'a self,
        nonce_le: &'a [u8; 8],
        bump_arr: &'a [u8; 1],
    ) -> [&'a [u8]; 4] {
        [VAULT_SEED, self.creator.as_ref(), nonce_le, bump_arr]
    }
}
