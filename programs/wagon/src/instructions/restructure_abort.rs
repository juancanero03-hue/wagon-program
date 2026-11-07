//! `restructure_abort` — upgrade #31. Salida de emergencia.
//!
//! Reactiva el vault sin tocar la tabla de allocations (que nunca se
//! modifica hasta settle). El creador puede abortar en cualquier momento;
//! pasado `RESTRUCTURE_ABORT_TIMEOUT_SECS`, CUALQUIERA puede — así una
//! reestructuración colgada jamás deja el vault pausado para siempre.
//!
//! Si alguna compra dejó en el vault un token (no USDC) que la cesta vieja no
//! tiene (`stranded_mask != 0`), el abort marca el vault (bandera stranded, que
//! veta la ENTRADA) y conserva la sesión como manifiesto hasta `close_stranded` /
//! `admin_clear_stranded`; si no, la cierra. Los fondos NUNCA salen del vault.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::RestructureAborted;
use crate::instructions::restructure_init::RESTRUCTURE_SEED;
use crate::state::restructure_session::{
    RESTRUCTURE_ABORT_SHORT_SECS, RESTRUCTURE_ABORT_TIMEOUT_SECS,
};
use crate::state::vault_layout as vlayout;
use crate::state::{ProtocolConfig, RestructureSession, FUNDING_KIND_RESTRUCTURE};

#[derive(Accounts)]
pub struct RestructureAbort<'info> {
    /// Quien aborta: el creador siempre; cualquiera tras el timeout.
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: PDA verificada byte-level abajo.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    // Ceremonia #53: SIN `close = caller`. Si el abort deja compras GENUINAMENTE
    // varadas, la sesión se CONSERVA abierta como manifiesto exacto de lo fuera de
    // tabla (la limpieza self-service `close_stranded` la cerrará al probar vacuidad);
    // en la rama limpia (sin varados) se cierra a mano en el handler hacia
    // `refund_target` (ceremonia USDC §3.3, B3).
    #[account(
        mut,
        seeds = [RESTRUCTURE_SEED, vault.key().as_ref()],
        bump = restructure_session.bump,
        has_one = vault @ WagonError::RestructureSessionMismatch,
    )]
    pub restructure_session: Box<Account<'info, RestructureSession>>,

    /// Ceremonia USDC (§3.3, B3): solo se lee `authority` (cinturón del reembolso). PDA por
    /// seeds: no puede hacer revertir el abort por causa externa.
    #[account(seeds = [PROTOCOL_SEED], bump = protocol.bump)]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// CHECK: registro de financiación en su PDA canónica (SIEMPRE esa dirección; vacía =
    /// legacy). En la rama LIMPIA se cierra aquí; en la rama VARADA queda con el manifiesto.
    #[account(mut)]
    pub funding_record: UncheckedAccount<'info>,

    /// CHECK: destino del saldo de la sesión en la rama limpia: `refund_to` del registro
    /// emparejado o `protocol.authority` (aquí CUALQUIER caller puede elegir la authority:
    /// es la escotilla de liveness del vault, ver el handler), o el CALLER si es legacy
    /// (su incentivo permissionless de siempre). Validado en el handler.
    #[account(mut)]
    pub refund_target: UncheckedAccount<'info>,
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

    // Ceremonia #53: ¿el abort deja mints GENUINAMENTE varados (comprados, no-USDC y
    // que NO están en la tabla VIEJA que el abort conserva)? Lecturas PURAS del vault
    // y la sesión → el abort sigue sin poder revertir por causa externa (preserva la
    // escotilla de emergencia). `stranded_mask` == `added_mask & buys_done` de settle.
    let stranded_mask = {
        let data = vault_ai.try_borrow_data()?;
        session.stranded_mask(&data)?
    };
    let stranded = stranded_mask != 0;
    let buys_done_nonzero = session.buys_done != 0;

    {
        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::write_status(&mut data, 0u8 /* Active */)?;
        // Ceremonia #53: si hay valor fuera de tabla, MARCA el vault (bloquea la
        // ENTRADA; escritura infalible de 1 byte) y CONSERVA la sesión como manifiesto.
        if stranded {
            vlayout::write_stranded_flag(&mut data, 1)?;
        }
    }

    // Ceremonia #53: rama LIMPIA (sin varados) → cerrar la sesión a mano (antes lo hacía
    // el constraint `close = caller`); el cierre manual reasigna al system program →
    // Anchor NO re-serializa la cuenta al exit (Account::exit guarda por owner). En la
    // rama VARADA NO se cierra nada: sesión Y registro quedan como manifiesto para
    // close_stranded / admin_clear_stranded.
    //
    // Ceremonia USDC (§3.3, B3): reparto del rent temporal. Legacy: al caller como
    // siempre (su incentivo permissionless). Con registro emparejado: la sesión a
    // `refund_to` y el rent del PROPIO registro al caller SOLO si el caller NO es el
    // creador (§3.3.d: el incentivo es para el limpiador ajeno; el propietario que
    // aborta su propia sesión patrocinada no cobra nada del sponsor).
    //
    // ESCOTILLA DE LIVENESS (revisión N3 de B3): aquí `owner` = el caller, no el creador,
    // para que TRAS EL PLAZO cualquiera pueda elegir `protocol.authority` como destino.
    // Si `refund_to` dejara de ser pagable (p. ej. el creador, que puede ser su propio
    // sponsor con otra clave, la vuelve ejecutable mientras la red prohíba abonarle
    // lamports), un tercero seguiría pudiendo abortar hacia Squads y el vault no se
    // quedaría en Restructuring bloqueando los retiros de todos sus inversores. El
    // dinero sigue dentro de Wagon y el evento dice quién cobró; el caller no gana nada
    // más por ello (su incentivo, el registro, es el mismo). Antes del plazo el handler
    // ya exige que el caller sea el creador. En `close_stranded` (reabre la ENTRADA,
    // no la salida) el cinturón sigue restringido al propietario y a la authority.
    if !stranded {
        let authority = ctx.accounts.protocol.authority;
        let caller_key = ctx.accounts.caller.key();
        let caller_ai = ctx.accounts.caller.to_account_info();
        let session_ai = ctx.accounts.restructure_session.to_account_info();
        let record_dest = if caller_key == session.creator { None } else { Some(&caller_ai) };
        crate::funding::settle_refund(
            &ctx.accounts.funding_record.to_account_info(),
            &ctx.accounts.refund_target.to_account_info(),
            &session_ai,
            &caller_key,
            &caller_key,
            &authority,
            &caller_key,
            session.generation,
            FUNDING_KIND_RESTRUCTURE,
            record_dest,
        )?;
        crate::funding::close_account_to(
            &session_ai,
            &ctx.accounts.refund_target.to_account_info(),
        )?;
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
        stranded_buys: buys_done_nonzero,
    });
    // Ceremonia #53: aviso preciso de cuarentena (solo si hay valor GENUINAMENTE fuera
    // de tabla, más estricto que `stranded_buys`, que cuenta compras persistentes).
    if stranded {
        emit!(crate::events::StrandedValueQuarantined {
            vault: ctx.accounts.vault.key(),
            caller: ctx.accounts.caller.key(),
            producer: 0,
        });
    }
    Ok(())
}
