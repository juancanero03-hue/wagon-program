//! `close_stranded` — ceremonia #53. Limpieza SELF-SERVICE (permissionless) del
//! valor fuera de tabla de un cambio de cesta abortado con compras (P2-3).
//!
//! La `RestructureSession` abortada quedó ABIERTA como MANIFIESTO exacto de los mints
//! varados (sus `new_mints` + `buys_done` + la tabla viva reconstruyen el conjunto con
//! las Pubkeys reales, que no caben en el vault). Esta ix exige que la ATA de vault de
//! CADA mint varado esté a 0 (el creador/authority las rescató antes con
//! `rescue_untracked_token`) y solo entonces baja la bandera `stranded_flag` (reabre la
//! ENTRADA) y cierra la sesión (rent → caller).
//!
//! PERMISSIONLESS: no mueve fondos ni beneficia al caller (solo cobra el rent de la
//! sesión, que su creador ya pagó). Comprueba IDENTIDAD exacta (mint == new_mints[i] +
//! ATA canónica + balance 0), NO un contador → inmune a decoy-donación (un mint donado
//! no está en el manifiesto), multi-mint (recorre toda la máscara) y rescate parcial
//! (exige 0 en TODAS). La re-tabulación está bloqueada (restructure_init veta la bandera
//! y el PDA del manifiesto colisiona) → la tabla, y con ella la máscara, es ESTABLE.
//!
//! # remaining_accounts
//! Por cada índice varado, EN ORDEN ASCENDENTE de la máscara: `[mint, vault_ata]`.

use anchor_lang::prelude::*;

use crate::errors::WagonError;
use crate::instructions::restructure_init::RESTRUCTURE_SEED;
use crate::state::vault_layout as vlayout;
use crate::state::RestructureSession;
use crate::token_io::{derive_live_ata, read_token_amount, verify_token_account};

#[derive(Accounts)]
pub struct CloseStranded<'info> {
    /// Cualquiera. Cobra solo el rent de la sesión cerrada; nunca recibe fondos.
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: PDA seeds + owner verificados con `VaultGuard::load` en el handler.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    /// El manifiesto: la RestructureSession abortada que quedó abierta. Se cierra al
    /// probar que todo el conjunto varado está a 0 (rent → caller).
    #[account(
        mut,
        seeds = [RESTRUCTURE_SEED, vault.key().as_ref()],
        bump = restructure_session.bump,
        has_one = vault @ WagonError::RestructureSessionMismatch,
        close = caller,
    )]
    pub restructure_session: Box<Account<'info, RestructureSession>>,
}

pub fn handler<'info>(ctx: Context<'_, '_, '_, 'info, CloseStranded<'info>>) -> Result<()> {
    let vault_ai = ctx.accounts.vault.to_account_info();
    // Verifica owner + derivación PDA del vault. NO gatea status: un vault con la bandera
    // puesta está Active(0), Paused(1) o Liquidating(2) (nunca Restructuring: restructure_init
    // veta la bandera; `close_vault` NO la veta, así que puede pasar a Liquidating con flag=1
    // — benigno, en Liquidating no hay depósitos que diluir), y limpiar en cualquiera es
    // correcto (baja la bandera y cierra el manifiesto).
    let _guard = crate::guards::VaultGuard::load(
        &vault_ai,
        &ctx.accounts.vault.key(),
        WagonError::VaultPaused,
    )?;
    let vault_key = ctx.accounts.vault.key();
    let session = &ctx.accounts.restructure_session;

    // Ceremonia #53 (Fix 2): exige bandera EXACTAMENTE 1 (P2-3 PURO, con manifiesto).
    // El estado 2 (hay valor P2-4 sin manifiesto, o mezclado sobre este P2-3) REVIERTE
    // aquí a propósito: `close_stranded` solo prueba el manifiesto de la sesión, así que
    // NO puede garantizar que no quede valor P2-4 fuera de tabla → esa limpieza exige
    // `admin_clear_stranded` (authority). Sin este `==1` estricto, un P2-4 concurrente
    // reabriría la ENTRADA con valor sin contar (el bloqueante de coexistencia).
    let mask = {
        let data = vault_ai.try_borrow_data()?;
        require!(
            vlayout::read_stranded_flag(&data)? == 1,
            WagonError::NotStranded
        );
        session.stranded_mask(&data)?
    };

    // Recorre los índices varados en orden ascendente, consumiendo [mint, ata] de
    // remaining; exige identidad EXACTA y ATA a CERO (rescatada).
    let remaining = ctx.remaining_accounts;
    let mut cursor = 0usize;
    for i in 0..(session.new_count as usize) {
        if (mask >> i) & 1 == 0 {
            continue;
        }
        require!(
            cursor + 2 <= remaining.len(),
            WagonError::InvalidJupiterRoute
        );
        let mint_ai = &remaining[cursor];
        let ata_ai = &remaining[cursor + 1];
        cursor += 2;

        let mint = session.new_mints[i];
        require_keys_eq!(mint_ai.key(), mint, WagonError::AllocMintMismatch);
        let token_prog = *mint_ai.owner;
        require_keys_eq!(
            ata_ai.key(),
            derive_live_ata(&vault_key, &mint, &token_prog),
            WagonError::LegDestAtaMismatch
        );
        verify_token_account(ata_ai, &mint, &vault_key)?;
        require!(
            read_token_amount(ata_ai)? == 0,
            WagonError::StrandedAtaNotEmpty
        );
    }
    // Longitud EXACTA: ni cuentas de más ni de menos.
    require!(cursor == remaining.len(), WagonError::InvalidJupiterRoute);

    // Baja la bandera → reabre la ENTRADA. La sesión la cierra el constraint close=caller.
    {
        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::write_stranded_flag(&mut data, 0)?;
    }

    emit!(crate::events::StrandedValueCleared {
        vault: vault_key,
        caller: ctx.accounts.caller.key(),
        by_authority: false,
    });
    Ok(())
}
