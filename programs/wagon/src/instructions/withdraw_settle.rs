//! `withdraw_settle` — step 3 of the fractional withdraw flow.
//!
//! Once every leg has been swapped (`session.is_complete()`):
//!   1. exit_value = session.usdc_slice_from_vault + session.usdc_from_swaps
//!   2. cost basis slice = position.cost_basis_for_slice(shares_to_burn)
//!   3. profit_signed = exit_value - cost_basis_slice
//!   4. perf_fee  = (profit_signed > 0) * profit_signed * perf_fee_bps / 10000
//!      protocol_fee = perf_fee * PERF_FEE_PROTOCOL_SHARE_BPS / 10000
//!      creator_fee  = perf_fee - protocol_fee
//!   5. usdc_to_investor = exit_value - perf_fee
//!   6. Transfer USDC to investor, treasury, and the creator's rewards
//!      vault ("hucha", accrue-and-claim — same account the entry fee
//!      accrues to; the creator sweeps it via `claim_creator_rewards`)
//!   7. Update vault state (agg_cost, tvl)
//!   8. Update user_position (cost_basis decrement; shares already decremented at init)
//!   9. Update protocol total_tvl
//!  10. Close WithdrawSession (rent → investor)
//!
//! Shares were already burned at init, so no Burn CPI here.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, spl_token, CloseAccount, Token, Transfer};

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::WithdrawCompleted;
use crate::state::vault_layout as vlayout;
use crate::state::{ProtocolConfig, UserPosition, WithdrawSession};
use crate::token_io::{derive_live_ata, verify_token_account};

#[derive(Accounts)]
pub struct WithdrawSettle<'info> {
    /// P6 (C-B): quien firma. El inversor SIEMPRE; un TERCERO solo si la sesión
    /// está comprometida (sold==1), completa y barrida (verificado en el handler).
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: pinneado a `session.investor` por el `has_one = investor` del
    /// withdraw_session (abajo). Recibe el USDC del pago + los rents (close). Ya
    /// no firma: solo es el destinatario. El caller es quien firma.
    #[account(mut)]
    pub investor: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// CHECK: PDA seeds verified manually.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    /// CHECK: pubkey verified against `vault_layout::read_usdc_ata`.
    #[account(mut)]
    pub vault_usdc_ata: UncheckedAccount<'info>,

    /// CHECK: SPL Token account, mint == usdc_mint, owner == investor.
    #[account(mut)]
    pub investor_usdc_ata: UncheckedAccount<'info>,

    /// CHECK: the creator's rewards vault ("hucha") — canonical USDC ATA of
    /// the per-creator PDA [b"creator-rewards", creator] (creator read from
    /// vault state). Same derivation `claim_creator_rewards` and
    /// `deposit_init` (entry fee) enforce; verified canonically + mint/owner
    /// in the handler. The creator's perf-fee cut accrues here and is swept
    /// by the creator via `claim_creator_rewards` (accrue-and-claim).
    #[account(mut)]
    pub creator_rewards_ata: UncheckedAccount<'info>,

    /// CHECK: address from `protocol.treasury_usdc_ata`. Receives the
    /// protocol's slice of the perf fee.
    #[account(mut)]
    pub protocol_treasury_usdc_ata: UncheckedAccount<'info>,

    /// CHECK: pubkey verified against `protocol.usdc_mint`.
    pub usdc_mint: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [
            USER_POSITION_SEED,
            vault.key().as_ref(),
            investor.key().as_ref(),
        ],
        bump = user_position.bump,
    )]
    pub user_position: Box<Account<'info, UserPosition>>,

    #[account(
        mut,
        seeds = [
            WITHDRAW_SESSION_SEED,
            vault.key().as_ref(),
            investor.key().as_ref(),
        ],
        bump = withdraw_session.bump,
        has_one = investor @ WagonError::WithdrawSessionWrongInvestor,
        has_one = vault @ WagonError::WithdrawSessionWrongVault,
        close = investor,
    )]
    pub withdraw_session: Box<Account<'info, WithdrawSession>>,

    /// CHECK: H-3 — la hucha USDC de la sesión (ATA canónica del PDA de
    /// sesión), verificada por derivación + verify_token_account. Contiene
    /// la parte del idle apartada en init + el USDC de las ventas; los pagos
    /// de este settle salen de aquí y la cuenta se cierra al final (rent →
    /// investor).
    #[account(mut)]
    pub session_usdc_escrow: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
}

pub fn handler(ctx: Context<WithdrawSettle>) -> Result<()> {
    let session = &ctx.accounts.withdraw_session;
    require!(session.is_complete(), WagonError::SessionNotComplete);

    // P6 (C-B): autorización. El inversor SIEMPRE; un TERCERO solo si la sesión
    // está COMPROMETIDA (sold==1), completa y barrida — el terminal de una sesión
    // que extrajo valor es el SETTLE permissionless (el abort queda vetado, P4).
    // SEGURO: el caller no elige NINGÚN destino (investor por verify_token_account,
    // tesorería/hucha pinneadas por derivación, residuo a vault_usdc_ata pinneado,
    // rents por close=investor).
    let committed = session.sold == 1 && session.is_complete() && session.fully_swept();
    require!(
        ctx.accounts.caller.key() == session.investor || committed,
        WagonError::WithdrawSettleUnauthorized
    );

    // ---- Read vault state -------------------------------------------------
    let vault_ai = ctx.accounts.vault.to_account_info();
    require_keys_eq!(*vault_ai.owner, crate::ID, WagonError::VaultClosed);

    let (creator, nonce, vault_bump, perf_fee_bps, agg_cost_now, tvl_now, usdc_ata_pk) = {
        let data = vault_ai.try_borrow_data()?;
        (
            vlayout::read_creator(&data)?,
            vlayout::read_nonce(&data)?,
            vlayout::read_bump(&data)?,
            vlayout::read_performance_fee_bps(&data)?,
            vlayout::read_aggregate_cost_basis_usdc(&data)?,
            vlayout::read_tvl_last_computed_usdc(&data)?,
            vlayout::read_usdc_ata(&data)?,
        )
    };
    let nonce_le = nonce.to_le_bytes();
    let (derived_vault_key, derived_bump) =
        Pubkey::find_program_address(&[VAULT_SEED, creator.as_ref(), &nonce_le], &crate::ID);
    require_keys_eq!(
        ctx.accounts.vault.key(),
        derived_vault_key,
        WagonError::VaultClosed
    );
    require!(vault_bump == derived_bump, WagonError::VaultClosed);
    // P6b (C-B): status 4 admitido si la sesión está COMPROMETIDA. En ese estado
    // el pago sale ÍNTEGRO de la hucha USDC de la sesión; del vault solo se tocan
    // contadores + el residuo de polvo a vault_usdc_ata (USDC ocioso, excluido del
    // dust check del restructure por construcción). Cierra el último eslabón de
    // B-2 (creador que sostiene status 4 indefinidamente).
    // P7b: se ELIMINA el check de stale (created_at >= lra) — desde C2 los fondos
    // no dependen de la tabla viva; una sesión stale ASIENTA (el TVL cae al
    // cinturón force_legacy, más abajo). El rescate ya no necesita al abort.
    {
        let data = vault_ai.try_borrow_data()?;
        require!(
            vlayout::read_status(&data)? != 4u8 || committed,
            WagonError::RestructuringInProgress
        );
    }
    // C2: cada leg no-trivial tiene una hucha de token que hay que barrer +
    // cerrar (via withdraw_sweep_batch) ANTES del settle; si no, tokens y rent
    // quedarían varados al cerrar la sesión. Una sesión en abort no se asienta.
    require!(
        ctx.accounts.withdraw_session.fully_swept(),
        WagonError::EscrowNotSwept
    );
    require!(
        ctx.accounts.withdraw_session.aborting == 0,
        WagonError::SessionAlreadyStarted
    );

    // ---- Validate SPL accounts --------------------------------------------
    let usdc_mint_pk = ctx.accounts.protocol.usdc_mint;
    let treasury_pk = ctx.accounts.protocol.treasury_usdc_ata;
    require_keys_eq!(
        ctx.accounts.vault_usdc_ata.key(),
        usdc_ata_pk,
        WagonError::InvalidJupiterRoute
    );
    require_keys_eq!(
        ctx.accounts.usdc_mint.key(),
        usdc_mint_pk,
        WagonError::InvalidJupiterRoute
    );
    require_keys_eq!(
        *ctx.accounts.usdc_mint.owner,
        spl_token::ID,
        WagonError::InvalidJupiterRoute
    );
    require_keys_eq!(
        ctx.accounts.protocol_treasury_usdc_ata.key(),
        treasury_pk,
        WagonError::InvalidJupiterRoute
    );

    let investor_pk = ctx.accounts.investor.key();
    let vault_key = ctx.accounts.vault.key();
    verify_token_account(
        &ctx.accounts.investor_usdc_ata.to_account_info(),
        &usdc_mint_pk,
        &investor_pk,
    )?;
    // La hucha del creador: ATA USDC canónica del PDA [b"creator-rewards",
    // creator] — la MISMA cuenta donde acumula el fee de entrada y de la que
    // paga `claim_creator_rewards`. Derivada, no elegible por el caller.
    let (creator_rewards_authority, _) =
        Pubkey::find_program_address(&[CREATOR_REWARDS_SEED, creator.as_ref()], &crate::ID);
    require_keys_eq!(
        ctx.accounts.creator_rewards_ata.key(),
        derive_live_ata(&creator_rewards_authority, &usdc_mint_pk, &spl_token::ID),
        WagonError::CreatorRewardsAtaMismatch
    );
    verify_token_account(
        &ctx.accounts.creator_rewards_ata.to_account_info(),
        &usdc_mint_pk,
        &creator_rewards_authority,
    )?;
    require_keys_eq!(
        *ctx.accounts.protocol_treasury_usdc_ata.owner,
        spl_token::ID,
        WagonError::InvalidJupiterRoute
    );

    // ---- H-3: validar la hucha USDC de la sesión ---------------------------
    let session_key = ctx.accounts.withdraw_session.key();
    require_keys_eq!(
        ctx.accounts.session_usdc_escrow.key(),
        crate::token_io::derive_live_ata(&session_key, &usdc_mint_pk, &spl_token::ID),
        WagonError::EscrowAtaMismatch
    );
    verify_token_account(
        &ctx.accounts.session_usdc_escrow.to_account_info(),
        &usdc_mint_pk,
        &session_key,
    )?;

    // ---- Compute exit value, profit, fees ---------------------------------
    let shares_to_burn = session.shares_to_burn;
    // Ceremonia #45 (H4, R2): slice pro-rata MARCADO en withdraw_init (valor de
    // vault); se resta del agregado global más abajo EN LUGAR de exit_value.
    let marked_slice = session.marked_slice;
    let exit_value_usdc = session
        .usdc_slice_from_vault
        .checked_add(session.usdc_from_swaps)
        .ok_or(WagonError::MathOverflow)?;

    let cost_basis_slice = ctx
        .accounts
        .user_position
        .cost_basis_for_slice(shares_to_burn)
        .map_err(|_| error!(WagonError::MathOverflow))?;

    let profit_signed: i64 = (exit_value_usdc as i64)
        .checked_sub(cost_basis_slice as i64)
        .ok_or(WagonError::MathOverflow)?;

    let perf_fee: u64 = if profit_signed > 0 {
        let fee = (profit_signed as u128)
            .checked_mul(perf_fee_bps as u128)
            .ok_or(WagonError::MathOverflow)?
            .checked_div(BPS_DENOMINATOR as u128)
            .ok_or(WagonError::DivisionByZero)?;
        u64::try_from(fee).map_err(|_| WagonError::MathOverflow)?
    } else {
        0
    };
    let protocol_fee: u64 = (perf_fee as u128)
        .checked_mul(PERF_FEE_PROTOCOL_SHARE_BPS as u128)
        .ok_or(WagonError::MathOverflow)?
        .checked_div(BPS_DENOMINATOR as u128)
        .ok_or(WagonError::DivisionByZero)? as u64;
    let creator_fee: u64 = perf_fee
        .checked_sub(protocol_fee)
        .ok_or(WagonError::MathOverflow)?;
    let usdc_to_investor: u64 = exit_value_usdc
        .checked_sub(perf_fee)
        .ok_or(WagonError::MathOverflow)?;

    // ---- H-3: los pagos salen de la hucha de la sesión (firma la sesión) ---
    // El ATA USDC del vault ya no interviene en el pago: su balance solo
    // contiene fondos asentados, nunca derechos de sesiones en vuelo.
    let session_bump_arr = [ctx.accounts.withdraw_session.bump];
    let session_seeds: &[&[u8]] = &[
        WITHDRAW_SESSION_SEED,
        vault_key.as_ref(),
        investor_pk.as_ref(),
        &session_bump_arr,
    ];
    let signer_seeds: &[&[&[u8]]] = &[session_seeds];

    if usdc_to_investor > 0 {
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.session_usdc_escrow.to_account_info(),
                    to: ctx.accounts.investor_usdc_ata.to_account_info(),
                    authority: ctx.accounts.withdraw_session.to_account_info(),
                },
                signer_seeds,
            ),
            usdc_to_investor,
        )?;
    }
    if protocol_fee > 0 {
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.session_usdc_escrow.to_account_info(),
                    to: ctx.accounts.protocol_treasury_usdc_ata.to_account_info(),
                    authority: ctx.accounts.withdraw_session.to_account_info(),
                },
                signer_seeds,
            ),
            protocol_fee,
        )?;
    }
    if creator_fee > 0 {
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.session_usdc_escrow.to_account_info(),
                    to: ctx.accounts.creator_rewards_ata.to_account_info(),
                    authority: ctx.accounts.withdraw_session.to_account_info(),
                },
                signer_seeds,
            ),
            creator_fee,
        )?;
    }

    // ---- H-3: barrer el residuo de la hucha al vault y cerrarla ------------
    // Cualquier resto (polvo de redondeo, donaciones hostiles) pasa a ser del
    // vault; el rent de la cuenta vuelve al inversor. Espejo de deposit_settle.
    let residual_usdc =
        crate::token_io::read_token_amount(&ctx.accounts.session_usdc_escrow.to_account_info())?;
    if residual_usdc > 0 {
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.session_usdc_escrow.to_account_info(),
                    to: ctx.accounts.vault_usdc_ata.to_account_info(),
                    authority: ctx.accounts.withdraw_session.to_account_info(),
                },
                signer_seeds,
            ),
            residual_usdc,
        )?;
    }
    token::close_account(CpiContext::new_with_signer(
        ctx.accounts.token_program.to_account_info(),
        CloseAccount {
            account: ctx.accounts.session_usdc_escrow.to_account_info(),
            destination: ctx.accounts.investor.to_account_info(),
            authority: ctx.accounts.withdraw_session.to_account_info(),
        },
        signer_seeds,
    ))?;

    // ---- Update state -----------------------------------------------------
    let position = &mut ctx.accounts.user_position;
    position.cost_basis_usdc = position
        .cost_basis_usdc
        .checked_sub(cost_basis_slice)
        .ok_or(WagonError::MathOverflow)?;

    // total_shares was already decremented at withdraw_init (burn happened
    // there). agg_cost and tvl decrement happen now.
    let new_agg_cost = agg_cost_now.saturating_sub(cost_basis_slice);
    // Upgrade #30: when allocation ATAs are provided, write back a true
    // mark-to-market TVL (idle USDC after payouts + cached last-swap values
    // — every sold leg refreshed its cache moments ago in swap_batch).
    // Legacy subtraction otherwise. Never blocks an exit either way.
    // P7c (C-B): un CINTURÓN ÚNICO para el writeback del TVL (tres condiciones
    // sueltas para el mismo invariante fue como nació C-B). Cae a la resta legacy
    // (conservadora, nunca estrangula la salida) cuando NO se puede o NO se debe
    // confiar en el M2M vía caché: sin oráculos (remaining vacío), settle de
    // TERCERO (no fiarse de las cuentas que trae), status 4 (tabla mid-cambio) o
    // sesión stale (caché inválido). En todos, el TVL solo se resta el exit_value.
    let force_legacy = {
        let data = vault_ai.try_borrow_data()?;
        let status = vlayout::read_status(&data)?;
        let lra = vlayout::read_last_restructured_at(&data)?;
        ctx.remaining_accounts.is_empty()
            || ctx.accounts.caller.key() != investor_pk
            || status == 4u8
            || ctx.accounts.withdraw_session.created_at < lra
    };
    let new_tvl = if force_legacy {
        tvl_now.saturating_sub(exit_value_usdc)
    } else {
        let idle_usdc =
            crate::pricing::read_token_amount(&ctx.accounts.vault_usdc_ata.to_account_info())?;
        crate::pricing::compute_tvl_cache_writeback(
            &vault_ai,
            &vault_key,
            idle_usdc,
            &usdc_mint_pk,
            ctx.remaining_accounts,
        )?
    };
    {
        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::write_aggregate_cost_basis_usdc(&mut data, new_agg_cost)?;
        vlayout::write_tvl_last_computed_usdc(&mut data, new_tvl)?;
    }

    // H4 (ceremonia #45, R2): restar del agregado global el slice pro-rata
    // MARCADO en withdraw_init (valor de vault), NO `exit_value`. Simétrico con
    // el `+net` del depósito y con la Opción B; cierra el lado SALIDA del canal 4
    // — y del 3 (en especie: `exit_value ≈ 0` no descontaba NADA). saturating_sub:
    // nunca estrangula. Sesión legacy en vuelo: `marked_slice = 0` → resta 0
    // (no-op), el agregado se reconcilia solo en el siguiente `mark_tvl`.
    let protocol = &mut ctx.accounts.protocol;
    protocol.total_tvl_usdc = protocol.total_tvl_usdc.saturating_sub(marked_slice);

    emit!(WithdrawCompleted {
        vault: vault_key,
        investor: investor_pk,
        shares_burned: shares_to_burn,
        usdc_out_to_user: usdc_to_investor,
        performance_fee_usdc: perf_fee,
        profit_realised_usdc: profit_signed,
    });

    Ok(())
}
