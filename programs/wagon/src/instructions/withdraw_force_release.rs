//! `withdraw_force_release` — G3-B1b (DT-A(b); diseño G3 §3 contrastado el 16-oct-2026; decisión 2 de Juan del 14-oct):
//! el terminal de un RETIRO atascado por una cuenta CONGELADA. Cierra la contabilidad de la sesión SIN volver a acuñar
//! participaciones y deja lo congelado como DERECHO del inversor: la sesión se re-tipa en su sitio como `WithdrawRight`
//! (misma PDA, mismo rent) con las huchas que siguen abiertas, y `withdraw_escrow_claim` las vacía hacia el inversor en
//! cuanto se descongelan. Nadie diluye a nadie: las participaciones siguen quemadas y el valor congelado está fuera del
//! vault. Las patas que ya habían vuelto al vault en una cancelación se quedan en el vault (decisión 2).
//!
//! PERMISSIONLESS y FAIL-CLOSED (como `deposit_force_release`): un retiro con terminal normal nunca se libera.
//! - Reloj anidado: el inversor pasadas 24 h (`WITHDRAW_INKIND_TIMEOUT_SECS`, la ventana en especie), un tercero pasadas
//!   48 h (`WITHDRAW_ORPHAN_ABORT_SECS`).
//! - PRUEBA ligada a la cuenta EXACTA que bloquea el terminal, realmente `Frozen`:
//!   (a) la hucha de una pata con hucha abierta: ni el barrido, ni la venta ni el cobro en especie pueden moverla;
//!   (b) la cuenta del vault de esa pata, con la hucha con saldo y SIN cobro en especie posible (la sesión cancela,
//!       `aborting == 1`, o la pata ya se vendió y su polvo no puede volver al vault): el barrido no puede devolverla;
//!   (c) la hucha USDC, sin cancelación empezada (`aborting == 0`): el settle no puede pagar. Con `aborting == 1` el
//!       terminal es el abort fail-open de G3-B1a (el USDC queda como residuo del vault), no esta instrucción.
//! - Efectos: libera `pending_burned` solo si la sesión cancelaba (la única que lo reservó) y `revivable` con el MISMO
//!   predicado que el settle (`counts_in_revivable`: una sesión vendida también sumó en el init; una que NACIÓ cobrada, no), resta la
//!   base de coste de la porción de la posición y del agregado como un settle sin comisión (no se cobra comisión de éxito
//!   ni S de salida: «nunca estrangular la salida»), resta `marked_slice` del TVL agregado y cierra el registro de
//!   patrocinio hacia `refund_target` (`settle_refund`). El rent de la sesión se queda en el recibo y sale hacia
//!   `refund_to` cuando el recibo se cierra.

use anchor_lang::prelude::*;
use anchor_spl::token::spl_token;

use crate::constants::{PROTOCOL_SEED, USER_POSITION_SEED, WITHDRAW_SESSION_SEED};
use crate::errors::WagonError;
use crate::events::{FundingRefundPartial, WithdrawForceReleased};
use crate::guards::VaultGuard;
use crate::state::vault_layout as vlayout;
use crate::state::{
    ProtocolConfig, UserPosition, WithdrawRight, WithdrawSession, FUNDING_KIND_WITHDRAW, WITHDRAW_USDC_LEG_INDEX,
};
use crate::token_io::{
    derive_live_ata, mint_blocks_transfer, read_token_amount, read_token_state, verify_token_account, TOKEN_2022_PROGRAM_ID,
    TOKEN_STATE_FROZEN,
};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct WithdrawForceReleaseArgs {
    /// Pata cuya cuenta congelada es la prueba; `WITHDRAW_USDC_LEG_INDEX` (255) = la hucha USDC (prueba (c)).
    pub leg_index: u8,
}

#[derive(Accounts)]
pub struct WithdrawForceRelease<'info> {
    /// Paga la fee; jamás recibe nada. Permissionless.
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: semilla de la PDA de la sesión y dueño del derecho; se contrasta con `session.investor`.
    pub investor: UncheckedAccount<'info>,

    #[account(mut, seeds = [PROTOCOL_SEED], bump = protocol.bump)]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// CHECK: VaultState (dueño, semillas y bump por `VaultGuard`, en cualquier estado); se le escriben los contadores.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    /// CHECK: la PDA [b"withdraw-session", vault, investor] con una `WithdrawSession` VIVA (verificada a mano: si ya es
    /// un recibo, 6222). Se declara sin tipo a propósito: una `Account<WithdrawSession>` la volvería a escribir al salir
    /// y pisaría el recibo que esta instrucción deja en su lugar.
    #[account(mut)]
    pub withdraw_session: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [USER_POSITION_SEED, vault.key().as_ref(), investor.key().as_ref()],
        bump = user_position.bump,
    )]
    pub user_position: Box<Account<'info, UserPosition>>,

    /// CHECK: el mint de la pata (del snapshot de la sesión) o el USDC; su OWNER elige el programa de token de la derivación.
    pub proof_mint: UncheckedAccount<'info>,

    /// CHECK: la cuenta EXACTA congelada que bloquea el terminal (verificada canónica y `Frozen` en el handler).
    pub frozen_account: UncheckedAccount<'info>,

    /// CHECK: en la prueba (b), la hucha de la pata (con saldo), validada canónica; en (a) y (c) se ignora.
    pub escrow: UncheckedAccount<'info>,

    /// CHECK: registro de patrocinio de la sesión en su PDA canónica (verificado en `settle_refund`).
    #[account(mut)]
    pub funding_record: UncheckedAccount<'info>,

    /// CHECK: destino del rent del registro y, al cerrarse el recibo, del rent de la sesión: validado por `settle_refund`.
    #[account(mut)]
    pub refund_target: UncheckedAccount<'info>,
}

pub fn handler(ctx: Context<WithdrawForceRelease>, args: WithdrawForceReleaseArgs) -> Result<()> {
    let vault_ai = ctx.accounts.vault.to_account_info();
    let vault_key = ctx.accounts.vault.key();
    let investor = ctx.accounts.investor.key();
    let _guard = VaultGuard::load(&vault_ai, &vault_key, WagonError::WithdrawForceReleaseNotEligible)?;

    // ---- La sesión: PDA canónica con una WithdrawSession VIVA (un recibo ya liberado no vuelve a entrar) ---------------
    let (session_key, bump) = Pubkey::find_program_address(
        &[WITHDRAW_SESSION_SEED, vault_key.as_ref(), investor.as_ref()],
        &crate::ID,
    );
    let session_ai = ctx.accounts.withdraw_session.to_account_info();
    require_keys_eq!(session_ai.key(), session_key, WagonError::WithdrawForceReleaseNotEligible);
    require_keys_eq!(*session_ai.owner, crate::ID, WagonError::WithdrawForceReleaseNotEligible);
    let session: WithdrawSession = {
        let data = session_ai.try_borrow_data()?;
        WithdrawSession::try_deserialize(&mut &data[..])
            .map_err(|_| error!(WagonError::WithdrawForceReleaseNotEligible))?
    };
    require_keys_eq!(session.investor, investor, WagonError::WithdrawForceReleaseNotEligible);
    require_keys_eq!(session.vault, vault_key, WagonError::WithdrawForceReleaseNotEligible);
    require!(session.bump == bump, WagonError::WithdrawForceReleaseNotEligible);

    // ---- Gate 1: RELOJ anidado (el cinturón; la prueba es el discriminador) ----------------------------------------
    let now = Clock::get()?.unix_timestamp;
    let caller_is_investor = ctx.accounts.caller.key() == investor;
    require!(
        session.force_release_authorized(caller_is_investor, now),
        WagonError::WithdrawForceReleaseNotEligible
    );

    // ---- Gate 2: PRUEBA ligada a la cuenta EXACTA congelada -------------------------------------------------------
    // Make-or-break: una sesión sin cuenta congelada tiene terminal normal (barrido, venta, cobro en especie, settle o
    // abort fail-open); liberarla sin prueba sería griefing. `read_token_state` es lectura pura (inmune al freeze).
    let frozen_ai = ctx.accounts.frozen_account.to_account_info();
    let frozen_key = frozen_ai.key();
    let proof_mint_ai = ctx.accounts.proof_mint.to_account_info();
    let proof_mint = proof_mint_ai.key();
    let usdc_mint = ctx.accounts.protocol.usdc_mint;
    require!(
        *frozen_ai.owner == spl_token::ID || *frozen_ai.owner == TOKEN_2022_PROGRAM_ID,
        WagonError::WithdrawForceReleaseNotFrozen
    );
    // Toda prueba exige la cuenta `Frozen`, salvo la hucha de una pata con un mint bloqueador (abajo, prueba (a)).
    let frozen = read_token_state(&frozen_ai)? == TOKEN_STATE_FROZEN;
    if args.leg_index == WITHDRAW_USDC_LEG_INDEX {
        require!(frozen, WagonError::WithdrawForceReleaseNotFrozen);
        // (c) la hucha USDC congelada SIN cancelación empezada: el settle no puede pagar al inversor.
        require_keys_eq!(proof_mint, usdc_mint, WagonError::WithdrawForceReleaseNotFrozen);
        require!(session.aborting == 0, WagonError::WithdrawForceReleaseNotFrozen);
        require_keys_eq!(
            frozen_key,
            derive_live_ata(&session_key, &usdc_mint, &spl_token::ID),
            WagonError::WithdrawForceReleaseNotFrozen
        );
        verify_token_account(&frozen_ai, &usdc_mint, &session_key)?;
    } else {
        let leg = args.leg_index as usize;
        require!(leg < session.leg_count as usize, WagonError::LegIndexOutOfRange);
        let bit = 1u16 << args.leg_index;
        // Solo una pata con hucha ABIERTA (no trivial y no barrida) puede estar bloqueada.
        require!(
            (session.sweepable_mask() & bit) != 0 && (session.legs_swept & bit) == 0,
            WagonError::WithdrawForceReleaseNotFrozen
        );
        let leg_mint = session.leg_mints[leg];
        require_keys_eq!(proof_mint, leg_mint, WagonError::WithdrawForceReleaseNotFrozen);
        let token_prog_id = *proof_mint_ai.owner;
        let escrow_ata = derive_live_ata(&session_key, &leg_mint, &token_prog_id);
        let vault_dest = derive_live_ata(&vault_key, &leg_mint, &token_prog_id);
        if frozen_key == escrow_ata {
            // (a) la hucha de la pata: congelada (nada puede moverla, ni a 0: el close de una cuenta congelada revierte) o,
            // como en DT-D (c), sana pero con el MINT bloqueando toda transferencia (Token-2022 pausado, TransferHook
            // armado o NonTransferable después del init): el bloqueador es el mint y la hucha tiene saldo que no sale.
            verify_token_account(&frozen_ai, &leg_mint, &session_key)?;
            if read_token_state(&frozen_ai)? != TOKEN_STATE_FROZEN {
                let mint_data = proof_mint_ai.try_borrow_data()?;
                require!(mint_blocks_transfer(&mint_data), WagonError::WithdrawForceReleaseNotFrozen);
                require!(read_token_amount(&frozen_ai)? > 0, WagonError::WithdrawForceReleaseNotFrozen);
            }
        } else {
            // (b) la cuenta del vault de la pata congelada: el barrido no puede devolverla. Solo vale si la pata YA NO
            // puede cobrarse en especie (cancelando, o vendida con polvo); si aún puede, ese cobro es su terminal.
            require!(frozen, WagonError::WithdrawForceReleaseNotFrozen);
            require_keys_eq!(frozen_key, vault_dest, WagonError::WithdrawForceReleaseNotFrozen);
            verify_token_account(&frozen_ai, &leg_mint, &vault_key)?;
            require!(
                session.aborting == 1 || (session.legs_completed & bit) != 0,
                WagonError::WithdrawForceReleaseNotFrozen
            );
            let escrow_ai = ctx.accounts.escrow.to_account_info();
            require_keys_eq!(escrow_ai.key(), escrow_ata, WagonError::EscrowAtaMismatch);
            verify_token_account(&escrow_ai, &leg_mint, &session_key)?;
            require!(read_token_amount(&escrow_ai)? > 0, WagonError::WithdrawForceReleaseNotFrozen);
        }
    }

    // ---- Efectos 1: contadores del vault (espejo exacto de lo que sumó la sesión; saturating: un terminal nunca revierte)
    let shares = session.shares_to_burn;
    // El USDC de la hucha que es del inversor (la misma cuenta que paga el settle): el claim nunca entrega más que esto.
    let usdc_right = session
        .usdc_slice_from_vault
        .checked_add(session.usdc_from_swaps)
        .ok_or(WagonError::MathOverflow)?;
    let cost_basis_slice = ctx
        .accounts
        .user_position
        .cost_basis_for_slice(shares)
        .map_err(|_| error!(WagonError::MathOverflow))?;
    {
        let mut data = vault_ai.try_borrow_mut_data()?;
        // `pending_burned`: solo la reservó el barrido en dirección abort (transición 0 → 1), como libera `withdraw_abort`.
        if session.aborting == 1 {
            let cur = vlayout::read_pending_burned_shares(&data)?;
            vlayout::write_pending_burned_shares(&mut data, cur.saturating_sub(shares))?;
        }
        // `revivable`: lo sumó el init de toda sesión nacida con el contador y sin park definitivo, VENDIDA o no (el mismo
        // predicado que `withdraw_settle`; con `can_abort()` una sesión vendida dejaría la ENTRADA bloqueada para siempre).
        if session.counts_in_revivable() {
            let cur = vlayout::read_revivable_burned_shares(&data)?;
            vlayout::write_revivable_burned_shares(&mut data, cur.saturating_sub(shares))?;
        }
        // Base de coste agregada y caché del TVL: como el settle por el camino legacy (la porción y su valor de
        // salida dejan el vault; sin comisión de éxito). La caché es informativa: `saturating_sub`, nunca revierte.
        let agg = vlayout::read_aggregate_cost_basis_usdc(&data)?;
        vlayout::write_aggregate_cost_basis_usdc(&mut data, agg.saturating_sub(cost_basis_slice))?;
        let tvl = vlayout::read_tvl_last_computed_usdc(&data)?;
        vlayout::write_tvl_last_computed_usdc(&mut data, tvl.saturating_sub(usdc_right))?;
    }

    // ---- Efectos 2: posición y TVL agregado (las participaciones ya se quemaron en el init: no se tocan) ------------
    let position = &mut ctx.accounts.user_position;
    position.cost_basis_usdc = position.cost_basis_usdc.saturating_sub(cost_basis_slice);
    let protocol = &mut ctx.accounts.protocol;
    protocol.total_tvl_usdc = protocol.total_tvl_usdc.saturating_sub(session.marked_slice);

    // ---- Efectos 3: registro de patrocinio → `refund_target` (validado); el rent de la sesión se queda en el recibo ----
    let authority = ctx.accounts.protocol.authority;
    crate::funding::settle_refund(
        &ctx.accounts.funding_record.to_account_info(),
        &ctx.accounts.refund_target.to_account_info(),
        &session_ai,
        &investor,
        &investor,
        &authority,
        &ctx.accounts.caller.key(),
        session.generation as u64,
        FUNDING_KIND_WITHDRAW,
        None,
    )?;
    // El rent de la sesión NO viaja ahora (`FundingRefunded.lamports` lo cuenta como si Anchor cerrara la sesión): se queda
    // en el recibo y llega a `refund_to` con el último claim. Misma señal que el abort aplazado de B1a para la conciliación
    // del patrocinador: la cuenta que retiene rent es la propia PDA.
    emit!(FundingRefundPartial {
        session: session_key,
        kind: FUNDING_KIND_WITHDRAW,
        session_generation: session.generation as u64,
        escrow: session_key,
        escrow_lamports: session_ai.lamports(),
    });

    // ---- Efectos 4: la sesión se re-tipa EN SU SITIO como recibo de derecho -------------------------------------------
    // Pendientes: toda hucha de pata abierta (no trivial y no barrida) y la hucha USDC (siempre existe mientras la sesión
    // vive; vacía o no, el claim la cierra). Realloc hacia abajo: mismo rent (sobra), LEN distinto de la sesión.
    let pending_mask = session.sweepable_mask() & !session.legs_swept;
    let right = WithdrawRight {
        investor,
        vault: vault_key,
        refund_to: ctx.accounts.refund_target.key(),
        leg_mints: session.leg_mints,
        usdc_right,
        leg_count: session.leg_count,
        pending_mask,
        usdc_pending: 1,
        bump,
    };
    session_ai.realloc(WithdrawRight::LEN, false)?;
    {
        let mut data = session_ai.try_borrow_mut_data()?;
        let mut writer: &mut [u8] = &mut data;
        right.try_serialize(&mut writer)?;
    }

    emit!(WithdrawForceReleased {
        vault: vault_key,
        investor,
        session: session_key,
        shares_to_burn: shares,
        pending_mask,
        usdc_pending: 1,
        proof_leg: args.leg_index,
        by_third_party: !caller_is_investor,
    });
    Ok(())
}
