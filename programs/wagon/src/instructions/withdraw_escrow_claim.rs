//! `withdraw_escrow_claim` — G3-B1b (DT-A(b)): el inversor cobra su DERECHO. Consume el recibo (`WithdrawRight`, la sesión
//! re-tipada por `withdraw_force_release`) hucha a hucha: lleva una hucha pendiente (de pata, por índice y mint del snapshot,
//! o la USDC) a la cuenta canónica del inversor en cuanto la hucha y el destino se pueden mover, y la cierra. Si la cuenta
//! de destino no existe, la crea el programa (idempotente) y la paga el rent de la hucha que cierra (el caller solo adelanta
//! y recupera en la misma instrucción, como en `deposit_sweep_batch` desde G3-A). Si el caller es el inversor, cualquier
//! cuenta suya. Con la última hucha cobrada, el recibo se cierra hacia su `refund_to` con todo el rent acumulado.
//! La hucha USDC paga como mucho `usdc_right` (el derecho del inversor); lo que haya por encima es residuo del VAULT y se
//! queda en la hucha, que entonces NO se cierra (`withdraw_escrow_sweep` lo lleva al vault cuando el recibo ya no existe).
//! Con esa hucha abierta no hay rent del que recuperar el adelanto: lo paga el recibo si se cierra en esta misma
//! instrucción y, si no, solo el inversor crea su cuenta (la paga él); a un tercero 6224, que la crea aparte y vuelve.
//!
//! PERMISSIONLESS y calcado de `deposit_escrow_reclaim`: el caller no elige ningún destino (la ATA canónica del inversor o
//! una cuenta suya si llama él), así el cobro es neutral en valor y nadie gana nada cobrando por otro. Reintentable: con
//! la hucha o el destino congelados revierte 6224 y el derecho sigue en pie.

use anchor_lang::prelude::*;
use anchor_spl::associated_token::{self, AssociatedToken, Create};
use anchor_spl::token::{spl_token, Token};

use crate::constants::{PROTOCOL_SEED, USER_POSITION_SEED, WITHDRAW_SESSION_SEED};
use crate::errors::WagonError;
use crate::events::WithdrawRightClaimed;
use crate::state::{ProtocolConfig, UserPosition, WithdrawRight, ESCROW_RENT_WITHDRAW_USDC_WAGON, WITHDRAW_USDC_LEG_INDEX};
use crate::token_io::{
    close_token_account_signed, derive_live_ata, read_mint_decimals, read_token_amount, read_token_state,
    transfer_checked_signed, verify_token_account, TOKEN_2022_PROGRAM_ID, TOKEN_STATE_FROZEN,
};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct WithdrawEscrowClaimArgs {
    /// Pata a cobrar (índice del snapshot) o `WITHDRAW_USDC_LEG_INDEX` (255) = la hucha USDC.
    pub leg_index: u8,
}

#[derive(Accounts)]
pub struct WithdrawEscrowClaim<'info> {
    /// Cualquiera; paga la fee y, si falta la cuenta de destino, ADELANTA su rent (lo recupera aquí mismo).
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: dueño del derecho (semilla de la PDA; pinneado por `has_one`).
    pub investor: UncheckedAccount<'info>,

    /// CHECK: semilla de la PDA (puede estar cerrado: solo se usa su clave).
    pub vault: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [WITHDRAW_SESSION_SEED, vault.key().as_ref(), investor.key().as_ref()],
        bump = withdraw_right.bump,
        has_one = investor @ WagonError::WithdrawRightNotClaimable,
        has_one = vault @ WagonError::WithdrawRightNotClaimable,
    )]
    pub withdraw_right: Box<Account<'info, WithdrawRight>>,

    /// CHECK: el mint de la pata (del snapshot del recibo) o el USDC del protocolo; su OWNER elige el programa de token.
    pub mint: UncheckedAccount<'info>,

    /// CHECK: la hucha canónica de la PDA para ese mint (verificada en el handler); tiene que poder moverse.
    #[account(mut)]
    pub escrow: UncheckedAccount<'info>,

    /// CHECK: la cuenta canónica del inversor para ese mint (cualquiera suya si llama él); si no existe, se crea aquí.
    #[account(mut)]
    pub investor_dest: UncheckedAccount<'info>,

    /// CHECK: el `refund_to` del recibo; cobra el rent del recibo cuando se cierra (última hucha).
    #[account(mut)]
    pub refund_to: UncheckedAccount<'info>,

    #[account(seeds = [PROTOCOL_SEED], bump = protocol.bump)]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    pub token_program: Program<'info, Token>,

    /// CHECK: pubkey == Token-2022 (para huchas de mints Token-2022).
    pub token_program_2022: UncheckedAccount<'info>,

    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,

    /// G4 (F5A-01): la posición de la pareja; al cerrar la hucha USDC se limpia el bit de quién la pagó. Al FINAL.
    #[account(mut, seeds = [USER_POSITION_SEED, vault.key().as_ref(), investor.key().as_ref()], bump = user_position.bump)]
    pub user_position: Box<Account<'info, UserPosition>>,
}

pub fn handler(ctx: Context<WithdrawEscrowClaim>, args: WithdrawEscrowClaimArgs) -> Result<()> {
    let right = &ctx.accounts.withdraw_right;
    let right_ai = ctx.accounts.withdraw_right.to_account_info();
    let right_key = right_ai.key();
    let investor = right.investor;
    let vault = right.vault;
    require_keys_eq!(ctx.accounts.refund_to.key(), right.refund_to, WagonError::FundingRefundTargetMismatch);
    require_keys_eq!(ctx.accounts.token_program_2022.key(), TOKEN_2022_PROGRAM_ID, WagonError::InvalidJupiterRoute);
    let usdc_mint = ctx.accounts.protocol.usdc_mint;
    let mint_ai = ctx.accounts.mint.to_account_info();
    let caller_ai = ctx.accounts.caller.to_account_info();
    let caller_is_investor = ctx.accounts.caller.key() == investor;

    // ---- Qué hucha: pendiente en el recibo, con el mint del snapshot (o el USDC) ---------------------------------------
    let is_usdc = args.leg_index == WITHDRAW_USDC_LEG_INDEX;
    let (mint, token_prog_id, bit) = if is_usdc {
        require!(right.usdc_pending == 1, WagonError::WithdrawRightNotClaimable);
        require_keys_eq!(mint_ai.key(), usdc_mint, WagonError::WithdrawRightNotClaimable);
        (usdc_mint, spl_token::ID, 0u16)
    } else {
        let leg = args.leg_index as usize;
        require!(leg < right.leg_count as usize, WagonError::LegIndexOutOfRange);
        let bit = 1u16 << args.leg_index;
        require!((right.pending_mask & bit) != 0, WagonError::WithdrawRightNotClaimable);
        let leg_mint = right.leg_mints[leg];
        require_keys_eq!(mint_ai.key(), leg_mint, WagonError::AllocMintMismatch);
        (leg_mint, *mint_ai.owner, bit)
    };
    let prog_ai = if token_prog_id == spl_token::ID {
        ctx.accounts.token_program.to_account_info()
    } else {
        ctx.accounts.token_program_2022.to_account_info()
    };

    // ---- La hucha: canónica de la PDA, del inversor por derecho, y que se pueda mover ---------------------------------
    let escrow_ai = ctx.accounts.escrow.to_account_info();
    require_keys_eq!(escrow_ai.key(), derive_live_ata(&right_key, &mint, &token_prog_id), WagonError::EscrowAtaMismatch);
    verify_token_account(&escrow_ai, &mint, &right_key)?;
    require!(read_token_state(&escrow_ai)? != TOKEN_STATE_FROZEN, WagonError::WithdrawRightNotClaimable);
    let balance = read_token_amount(&escrow_ai)?;
    // La hucha USDC puede llevar, además del derecho del inversor (`usdc_right`: slice + ventas, lo que pagaría el settle),
    // un residuo del VAULT (un abort aplazado o un settle anterior de la pareja lo dejaron ahí). El inversor cobra como
    // mucho su derecho; el exceso se queda en la hucha, que entonces NO se cierra: en cuanto el recibo desaparece, la
    // PDA queda vacía y `withdraw_escrow_sweep` lo lleva al vault como cualquier residuo huérfano.
    let amount = if is_usdc { balance.min(right.usdc_right) } else { balance };
    let dejar_residuo = is_usdc && balance > amount;
    // ¿Es la última hucha pendiente? Entonces el recibo se cierra en esta misma instrucción y su rent sale hacia `refund_to`.
    let cierra_recibo = if is_usdc {
        right.pending_mask == 0
    } else {
        (right.pending_mask & !bit) == 0 && right.usdc_pending == 0
    };

    // ---- El destino: la cuenta canónica del inversor (cualquiera suya si llama él); si falta, la crea el programa -------
    // con el caller como pagador PROVISIONAL (lo recupera abajo, del rent de la hucha que cierra: misma mint, mismo
    // programa de token, mismo tamaño; o, si la hucha queda abierta por el residuo del vault, del rent del recibo cuando
    // este se cierra aquí mismo). Solo con saldo que mover; con la hucha vacía no hace falta destino. Si no hay de dónde
    // recuperarlo (hucha abierta por residuo y recibo que sigue), solo el inversor la crea (paga la suya, como cualquier
    // cuenta propia); un tercero la crea aparte (cualquiera puede, idempotente) y vuelve: ningún caller pierde rent sin
    // querer.
    let dest_ai = ctx.accounts.investor_dest.to_account_info();
    let canonical = derive_live_ata(&investor, &mint, &token_prog_id);
    let mut adelantado: u64 = 0;
    if dest_ai.data_is_empty() {
        require_keys_eq!(
            dest_ai.key(),
            canonical,
            if is_usdc { WagonError::InvestorUsdcAtaNotCanonical } else { WagonError::LegDestAtaMismatch }
        );
        if amount > 0 {
            require!(!dejar_residuo || cierra_recibo || caller_is_investor, WagonError::WithdrawRightNotClaimable);
            let antes = caller_ai.lamports();
            associated_token::create_idempotent(CpiContext::new(
                ctx.accounts.associated_token_program.to_account_info(),
                Create {
                    payer: caller_ai.clone(),
                    associated_token: dest_ai.clone(),
                    authority: ctx.accounts.investor.to_account_info(),
                    mint: mint_ai.clone(),
                    system_program: ctx.accounts.system_program.to_account_info(),
                    token_program: prog_ai.clone(),
                },
            ))?;
            adelantado = antes.saturating_sub(caller_ai.lamports());
        }
    } else {
        if !caller_is_investor {
            require_keys_eq!(
                dest_ai.key(),
                canonical,
                if is_usdc { WagonError::InvestorUsdcAtaNotCanonical } else { WagonError::LegDestAtaMismatch }
            );
        }
        verify_token_account(&dest_ai, &mint, &investor)?;
    }

    // ---- Mover y cerrar (el PDA del recibo firma por semillas: es la autoridad de la hucha desde el init) -------------
    let bump_arr = [right.bump];
    let seeds: &[&[u8]] = &[WITHDRAW_SESSION_SEED, vault.as_ref(), investor.as_ref(), &bump_arr];
    let signer_seeds: &[&[&[u8]]] = &[seeds];
    if amount > 0 {
        require!(read_token_state(&dest_ai)? != TOKEN_STATE_FROZEN, WagonError::WithdrawRightNotClaimable);
        let decimals = read_mint_decimals(&mint_ai)?;
        transfer_checked_signed(&prog_ai, &escrow_ai, &mint_ai, &dest_ai, &right_ai, signer_seeds, amount, decimals)?;
    }
    let right_lamports_inicio = right_ai.lamports();
    // El rent de la hucha cae en el recibo (D1) y sale con él hacia `refund_to`; con residuo del vault, la hucha sigue abierta.
    if !dejar_residuo {
        close_token_account_signed(&prog_ai, &escrow_ai, &right_ai, &right_ai, signer_seeds)?;
        if is_usdc {
            // G4 (F5A-01): la hucha USDC de la pareja ya no existe: el bit de quién la pagó vuelve a cero (una hucha nueva la paga
            // quien la cree, y la que cree un tercero sin sesión es, como cualquier donación, del inversor).
            ctx.accounts.user_position.escrow_rent_flags &= !ESCROW_RENT_WITHDRAW_USDC_WAGON;
        }
    }

    // ---- Devolver al caller lo adelantado (después de la última CPI) --------------------------------------------------
    // Del rent de la hucha recién cerrada (el `require` compara con el saldo de entrada del recibo) o, con la hucha
    // abierta por el residuo del vault, del rent del recibo que se cierra en esta misma instrucción hacia `refund_to`
    // (el rent de una sesión de 465 B dobla el de una cuenta de token de 165 B): sale de lo que cobraría `refund_to`,
    // que es quien pagó ese rent. Si no hay de dónde, solo pudo llegar aquí el inversor (el `require` de arriba): pagó
    // su propia cuenta.
    if adelantado > 0 {
        let ahora = right_ai.lamports();
        if !dejar_residuo {
            require!(ahora.saturating_sub(right_lamports_inicio) >= adelantado, WagonError::MathOverflow);
        } else if !cierra_recibo {
            adelantado = 0;
        }
        if adelantado > 0 {
            require!(ahora >= adelantado, WagonError::MathOverflow);
            **right_ai.try_borrow_mut_lamports()? = ahora.checked_sub(adelantado).ok_or(WagonError::MathOverflow)?;
            **caller_ai.try_borrow_mut_lamports()? =
                caller_ai.lamports().checked_add(adelantado).ok_or(WagonError::MathOverflow)?;
        }
    }

    // ---- Limpiar el bit; con la última hucha, cerrar el recibo hacia `refund_to` ---------------------------------------
    let right = &mut ctx.accounts.withdraw_right;
    if is_usdc {
        right.usdc_pending = 0;
    } else {
        right.pending_mask &= !bit;
    }
    let right_closed = right.is_empty();
    emit!(WithdrawRightClaimed {
        vault,
        investor,
        right: right_key,
        leg_index: args.leg_index,
        mint,
        amount,
        by_third_party: !caller_is_investor,
        right_closed,
    });
    if right_closed {
        // Cierre manual (lamports a `refund_to`, cuenta vaciada y devuelta al System Program): Anchor no vuelve a
        // escribir una cuenta cerrada al salir.
        crate::funding::close_account_to(&right_ai, &ctx.accounts.refund_to.to_account_info())?;
    }
    Ok(())
}
