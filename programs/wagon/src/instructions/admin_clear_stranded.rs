//! `admin_clear_stranded` — ceremonia #53. Limpieza por AUTHORITY del valor fuera de
//! tabla del lado RETIRO (P2-4, sin manifiesto on-chain) y BACKSTOP de P2-3.
//!
//! El strand de P2-4 (`withdraw_sweep_batch` de un mint eliminado) NO deja una
//! RestructureSession que sirva de manifiesto, así que reabrir la ENTRADA exige que la
//! authority (Squads 2/3) atestigüe OFF-CHAIN (enumeración RPC) que el vault ya no
//! sostiene valor fuera de tabla (rescatado con `rescue_untracked_token`, que la
//! authority puede forzar sin oráculo). Baja la bandera y, si viene una RestructureSession
//! (backstop de un P2-3 cuyo `close_stranded` se atascó por un token intransable), la
//! CIERRA para no dejar el restructure brickeado (PDA ocupado + `close_stranded` exige la
//! bandera puesta). El rescate es self-service; solo la RE-APERTURA necesita a Squads.
//! Liveness, NO seguridad: bloquear la entrada y rescatar es automático; la SALIDA nunca
//! se toca. Frecuencia ~0.

use anchor_lang::prelude::*;

use crate::constants::PROTOCOL_SEED;
use crate::errors::WagonError;
use crate::instructions::restructure_init::RESTRUCTURE_SEED;
use crate::state::vault_layout as vlayout;
use crate::state::ProtocolConfig;

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
    /// (mezclado o P2-3 puro), el handler lo cierra (rent → authority) para no dejar el
    /// restructure brickeado; si NO existe (P2-4 puro, PDA vacía owner=system), lo ignora.
    /// CHECK: PDA por seeds + cierre condicional en el handler (owner==este programa).
    #[account(
        mut,
        seeds = [RESTRUCTURE_SEED, vault.key().as_ref()],
        bump,
    )]
    pub restructure_session: UncheckedAccount<'info>,
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
    // authority atesta off-chain que ya no queda valor fuera de tabla (rescatado).
    {
        let data = vault_ai.try_borrow_data()?;
        require!(
            vlayout::read_stranded_flag(&data)? != 0,
            WagonError::NotStranded
        );
    }

    // Baja la bandera → reabre la ENTRADA (la authority ya atestó off-chain).
    {
        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::write_stranded_flag(&mut data, 0)?;
    }

    // Cierra el manifiesto SI existe. La cuenta SIEMPRE es la PDA derivada (seeds), así que
    // la authority no puede «olvidarse» de pasarla (sin sentinela None): si el manifiesto
    // está inicializado, se cierra SÍ o SÍ → jamás queda huérfano brickeando el restructure.
    // `owner == crate::ID` ⟺ existe (por los seeds ES la RestructureSession del vault); si la
    // PDA está vacía (P2-4 puro), owner es el system program → se ignora. Cierre MANUAL, espejo
    // exacto del `close` de Anchor (rent → authority, lamports a 0, reasignar al system,
    // realloc 0); se hace a mano sobre el AccountInfo para no arrastrar el lifetime `'info` que
    // exigiría `Account::try_from` sobre una cuenta local. No hay re-init posterior en esta ix
    // → sin ataque de revival; el runtime recolecta la cuenta a 0 lamports al fin de la tx.
    let session_ai = ctx.accounts.restructure_session.to_account_info();
    if session_ai.owner == &crate::ID {
        let dest = ctx.accounts.authority.to_account_info();
        let rent = session_ai.lamports();
        let new_dest = dest
            .lamports()
            .checked_add(rent)
            .ok_or(WagonError::MathOverflow)?;
        **dest.try_borrow_mut_lamports()? = new_dest;
        **session_ai.try_borrow_mut_lamports()? = 0;
        session_ai.assign(&anchor_lang::solana_program::system_program::ID);
        session_ai.realloc(0, false)?;
    }

    emit!(crate::events::StrandedValueCleared {
        vault: vault_key,
        caller: ctx.accounts.authority.key(),
        by_authority: true,
    });
    Ok(())
}
