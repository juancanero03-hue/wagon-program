//! `restructure_abort` — upgrade #31. Salida de emergencia.
//!
//! Reactiva el vault sin tocar la tabla de allocations (que nunca se
//! modifica hasta settle). El creador puede abortar en cualquier momento;
//! pasado `RESTRUCTURE_ABORT_TIMEOUT_SECS`, CUALQUIERA puede — así una
//! reestructuración colgada jamás deja el vault pausado para siempre.
//!
//! Nota honesta: si ya se ejecutaron compras (buys_done != 0), el vault
//! queda con tokens "fuera de tabla" (no cuentan para el TVL hasta que el
//! creador re-ejecute una reestructuración al set nuevo y la complete).
//! Los fondos NUNCA salen del vault, así que nada se pierde.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::RestructureAborted;
use crate::instructions::restructure_init::RESTRUCTURE_SEED;
use crate::state::restructure_session::{
    RESTRUCTURE_ABORT_SHORT_SECS, RESTRUCTURE_ABORT_TIMEOUT_SECS,
};
use crate::state::vault_layout as vlayout;
use crate::state::RestructureSession;

#[derive(Accounts)]
pub struct RestructureAbort<'info> {
    /// Quien aborta: el creador siempre; cualquiera tras el timeout.
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: PDA verificada byte-level abajo.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [RESTRUCTURE_SEED, vault.key().as_ref()],
        bump = restructure_session.bump,
        has_one = vault @ WagonError::RestructureSessionMismatch,
        close = caller,
    )]
    pub restructure_session: Box<Account<'info, RestructureSession>>,
}

pub fn handler(ctx: Context<RestructureAbort>) -> Result<()> {
    let vault_ai = ctx.accounts.vault.to_account_info();
    require_keys_eq!(*vault_ai.owner, crate::ID, WagonError::VaultPaused);

    let status = {
        let data = vault_ai.try_borrow_data()?;
        vlayout::read_status(&data)?
    };
    require!(status == 4u8, WagonError::NotRestructuring);

    let session = &ctx.accounts.restructure_session;
    let now = Clock::get()?.unix_timestamp;
    // Ceremonia #49 (M1): ventana de abort permissionless MÁS CORTA (SHORT=300s) si
    // aún no se ha COMPRADO nada (buys_done==0) → el griefing puro y la fase de
    // solo-ventas son desbloqueables por cualquiera a los 5 min (el USDC de las
    // ventas se reparte igual en el retiro; sin tokens fuera de tabla). Con compras
    // en vuelo (buys_done!=0) se conserva 1800s para no dejar tokens fuera de tabla
    // por un abort de tercero antes de que el creador re-tabule. El creador siempre
    // aborta de inmediato. `buys_done` no es falseable (PDA canónica por vault; solo
    // lo escribe restructure_swap_batch con firma del creador).
    let abort_window = if session.buys_done == 0 {
        RESTRUCTURE_ABORT_SHORT_SECS
    } else {
        RESTRUCTURE_ABORT_TIMEOUT_SECS
    };
    let timed_out = now.saturating_sub(session.created_at) > abort_window;
    if !timed_out {
        require_keys_eq!(
            ctx.accounts.caller.key(),
            session.creator,
            WagonError::RestructureAbortTooEarly
        );
    }

    {
        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::write_status(&mut data, 0u8 /* Active */)?;
    }

    // H4 (ceremonia #45, N3): RETIRADO el refresco M-1 opcional de la caché de
    // TVL. Ese writeback era el deflactor MÁS BARATO del canal 1 de H4: con
    // `remaining = [usdc_ata]` (sin las ATAs de pata) `compute_tvl_cache_writeback`
    // truncaba en silencio a `idle_usdc` y escribía un `tvl_last_computed`
    // deflactado SIN tocar el agregado global — que luego `mark_tvl` re-contaba
    // (`-old+new`) inflándolo. El abort ya NO escribe `tvl_last_computed`: se deja
    // en su valor pre-restructure (el último legítimo) y se reconcilia solo en el
    // siguiente `mark_tvl`/depósito m2m-enforced. La salida de emergencia queda
    // aún más a prueba de bloqueo (ninguna lectura de cuentas/precios puede hacer
    // revertir el abort). `remaining_accounts` en el abort pasa a ignorarse
    // (no-op inofensivo: el frontend puede seguir enviándolo o no). El clamp de
    // `mark_tvl`/`restructure_settle` cubre el resto de deflactores.
    emit!(RestructureAborted {
        vault: ctx.accounts.vault.key(),
        caller: ctx.accounts.caller.key(),
        stranded_buys: session.buys_done != 0,
    });
    Ok(())
}
