//! `admin_clear_stranded` — ceremonia #53. Limpieza por AUTHORITY del valor fuera de
//! tabla del lado RETIRO (P2-4, sin manifiesto on-chain) y BACKSTOP de P2-3.
//!
//! El valor que `withdraw_sweep_batch` (dirección abort) devuelve al vault de un mint que
//! ya no está en la tabla no deja una RestructureSession que sirva de manifiesto, así que
//! `close_stranded` no puede probar su limpieza: la bandera la baja la authority, una vez
//! rescatado ese valor con `rescue_untracked_token` (que la authority puede forzar sin
//! oráculo). Si viene una RestructureSession (backstop de un P2-3 cuyo `close_stranded` se
//! atascó por un token intransable), la CIERRA para no dejar el restructure brickeado (PDA
//! ocupado + `close_stranded` exige la bandera puesta). La SALIDA nunca se toca.

use anchor_lang::prelude::*;

use crate::constants::PROTOCOL_SEED;
use crate::errors::WagonError;
use crate::instructions::restructure_init::RESTRUCTURE_SEED;
use crate::state::vault_layout as vlayout;
use crate::state::{ProtocolConfig, RestructureSession, FUNDING_KIND_RESTRUCTURE};

#[derive(Accounts)]
pub struct AdminClearStranded<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        has_one = authority @ WagonError::UnauthorizedProtocolAdmin,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// CHECK: PDA seeds + owner verificados con `VaultGuard::load` en el handler.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    /// La RestructureSession-manifiesto de un strand P2-3. SIEMPRE es la PDA DERIVADA
    /// [RESTRUCTURE_SEED, vault] (los `seeds` la fuerzan; NO hay sentinela «None» que la
    /// authority pueda olvidar → cerró el footgun de la ronda 1). Si el manifiesto EXISTE
    /// (mezclado o P2-3 puro), el handler lo cierra (rent → `refund_target`, B3) para no
    /// dejar el restructure brickeado; si NO existe (P2-4 puro, PDA vacía owner=system), lo ignora.
    /// CHECK: PDA por seeds + cierre condicional en el handler (owner==este programa).
    #[account(
        mut,
        seeds = [RESTRUCTURE_SEED, vault.key().as_ref()],
        bump,
    )]
    pub restructure_session: UncheckedAccount<'info>,

    /// CHECK: Ceremonia USDC (§3.3, B3): registro de financiación del manifiesto en su PDA
    /// canónica (SIEMPRE esa dirección; vacía = legacy). Sin manifiesto se IGNORA: un
    /// registro sin sesión es un huérfano que limpia `funding_reclaim_stale`, y atar a él
    /// este rescate añadiría un motivo de revertir al único desatasco de P2-4 (revisión N3).
    #[account(mut)]
    pub funding_record: UncheckedAccount<'info>,

    /// CHECK: destino del saldo del manifiesto: `refund_to` del registro emparejado (o la
    /// authority, que aquí firma), o el CREADOR si es legacy (decisión de diseño, 24-sep: el
    /// rent que pagó el creador no se lo queda Squads). Sin manifiesto se ignora (pasar la
    /// propia authority). Validado en el handler.
    #[account(mut)]
    pub refund_target: UncheckedAccount<'info>,
}

pub fn handler(ctx: Context<AdminClearStranded>) -> Result<()> {
    let vault_ai = ctx.accounts.vault.to_account_info();
    let _guard = crate::guards::VaultGuard::load(
        &vault_ai,
        &ctx.accounts.vault.key(),
        WagonError::VaultPaused,
    )?;
    let vault_key = ctx.accounts.vault.key();

    // Exige la bandera puesta en CUALQUIER estado (1 = P2-3, 2 = P2-4/mezclado). La
    // authority la baja una vez rescatado el valor fuera de tabla.
    {
        let data = vault_ai.try_borrow_data()?;
        require!(
            vlayout::read_stranded_flag(&data)? != 0,
            WagonError::NotStranded
        );
    }

    // Baja la bandera → reabre la ENTRADA (una vez rescatado el valor fuera de tabla).
    {
        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::write_stranded_flag(&mut data, 0)?;
    }

    // Cierra el manifiesto SI existe. La cuenta SIEMPRE es la PDA derivada (seeds), así que
    // la authority no puede «olvidarse» de pasarla (sin sentinela None): si el manifiesto
    // está inicializado, se cierra SÍ o SÍ → jamás queda huérfano brickeando el restructure.
    // `owner == crate::ID` ⟺ existe (por los seeds ES la RestructureSession del vault); si la
    // PDA está vacía (P2-4 puro), owner es el system program → se ignora. Cierre MANUAL
    // (`close_account_to`, espejo exacto del `close` de Anchor) sobre el AccountInfo, sin
    // `Account::try_from` (lifetime `'info`). Sin re-init posterior → sin revival.
    //
    // Ceremonia USDC (§3.3, B3): el manifiesto se lee con su tipo (creador y sello) y su
    // saldo sigue la MISMA regla que los otros terminales: `refund_to` si el registro
    // empareja (y el rent del PROPIO registro a la authority, limpiadora, §3.3.d), o el
    // CREADOR si es legacy (decisión de diseño, 24-sep). Sin manifiesto el registro se ignora
    // (huérfano → `funding_reclaim_stale`, independiente de este rescate).
    let session_ai = ctx.accounts.restructure_session.to_account_info();
    let record_ai = ctx.accounts.funding_record.to_account_info();
    if session_ai.owner == &crate::ID {
        let (creator, generation) = {
            let data = session_ai.try_borrow_data()?;
            let s = RestructureSession::try_deserialize(&mut &data[..])?;
            (s.creator, s.generation)
        };
        let authority = ctx.accounts.authority.key();
        let authority_ai = ctx.accounts.authority.to_account_info();
        crate::funding::settle_refund(
            &record_ai,
            &ctx.accounts.refund_target.to_account_info(),
            &session_ai,
            &creator,
            &creator,
            &authority,
            &authority,
            generation,
            FUNDING_KIND_RESTRUCTURE,
            Some(&authority_ai),
        )?;
        crate::funding::close_account_to(
            &session_ai,
            &ctx.accounts.refund_target.to_account_info(),
        )?;
    }

    emit!(crate::events::StrandedValueCleared {
        vault: vault_key,
        caller: ctx.accounts.authority.key(),
        by_authority: true,
    });
    Ok(())
}
