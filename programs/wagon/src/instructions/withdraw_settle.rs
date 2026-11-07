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
//!   5b. PR 5B (§3.5, D3 / M-04): exit_service = min(S guardado en el FundingRecord
//!      emparejado, tope vivo de ServiceConfig, usdc_to_investor); 0 en pausa, legacy, sin
//!      registro o con la tesorería NO pagable (entonces ni se descuenta: descontado ⟺
//!      transferido ⟺ `ServiceCharged`); en especie solo sale el USDC ocioso, y el mínimo lo
//!      acota a eso. Se descuenta del pago al inversor y va a la tesorería. Nunca revierte.
//!   6. Transfer USDC to investor, treasury, and the creator's rewards
//!      vault ("hucha", accrue-and-claim — same account the entry fee
//!      accrues to; the creator sweeps it via `claim_creator_rewards`)
//!   7. Update vault state (agg_cost, tvl)
//!   8. Update user_position (cost_basis decrement; shares already decremented at init)
//!   9. Update protocol total_tvl
//!  10. Close WithdrawSession (and its FundingRecord, if paired): the whole
//!      balance of the session PDA (own rent + escrows closed into it, D1) goes
//!      to `refund_target` (§3.3: the sponsor's `refund_to`, or the investor).
//!
//! Shares were already burned at init, so no Burn CPI here.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, spl_token, CloseAccount, Token, Transfer};

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::{FundingRefundPartial, ServiceCharged, WithdrawCompleted};
use crate::service;
use crate::state::vault_layout as vlayout;
use crate::state::{ProtocolConfig, UserPosition, WithdrawSession, ESCROW_RENT_WITHDRAW_USDC_WAGON, FUNDING_KIND_WITHDRAW};
use crate::token_io::{derive_live_ata, is_payable_usdc_ata, verify_token_account};

#[derive(Accounts)]
pub struct WithdrawSettle<'info> {
    /// P6 (C-B): quien firma. El inversor SIEMPRE; un TERCERO solo si la sesión
    /// está comprometida (`committed()`: vendió, cobró en especie, aparcó con saldo o es
    /// anterior al upgrade), completa y barrida, o si no tiene patas de token y lleva más
    /// de 10 min abierta (G3; verificado en el handler).
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: pinneado a `session.investor` por el `has_one = investor` del
    /// withdraw_session (abajo). Recibe el USDC del pago; los rents van a
    /// `refund_target` (el inversor salvo sesión patrocinada, §3.3). Ya no firma:
    /// solo es el destinatario. El caller es quien firma.
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
        close = refund_target,
    )]
    pub withdraw_session: Box<Account<'info, WithdrawSession>>,

    /// CHECK: H-3 — la hucha USDC de la sesión (ATA canónica del PDA de
    /// sesión), verificada por derivación + verify_token_account. Contiene
    /// la parte del idle apartada en init + el USDC de las ventas; los pagos
    /// de este settle salen de aquí y la cuenta se cierra al final (rent →
    /// PDA de sesión, D1, y de ahí a `refund_target`).
    #[account(mut)]
    pub session_usdc_escrow: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,

    /// CHECK: Ceremonia USDC (§3.3, B2): registro de financiación de esta sesión en su PDA
    /// canónica (SIEMPRE esa dirección, nunca el centinela; verificada en el handler).
    /// Si existe y empareja se cierra aquí hacia `refund_target`; si la dirección está
    /// vacía es el camino legacy (rent al inversor). Al FINAL de las nombradas (y antes
    /// de `remaining`) para no mover ningún índice que el cliente ya enhebra.
    #[account(mut)]
    pub funding_record: UncheckedAccount<'info>,

    /// CHECK: destino del saldo de la sesión y del registro: `refund_to` del registro
    /// emparejado (o `protocol.authority` como alternativo si firma el inversor o la propia
    /// authority, cinturón «la salida nunca se atasca», B2), o el inversor si no hay registro. Validado en el handler; si no es un
    /// destino admitido, la transacción entera revierte (`FundingRefundTargetMismatch`).
    #[account(mut)]
    pub refund_target: UncheckedAccount<'info>,

    /// CHECK: PR 5B (§3.5, D3): la PDA canónica de `ServiceConfig` (atada por `seeds`, nunca
    /// otra cuenta: si no, un settle podría esquivar el S de salida), leída de forma TOLERANTE
    /// en el handler: si no existe o no es del programa, el S de salida es 0. Un terminal del
    /// retiro nunca depende de que una cuenta nueva exista. ÚLTIMA nombrada (@15), antes del
    /// `remaining` del m2m.
    #[account(seeds = [SERVICE_CONFIG_SEED], bump)]
    pub service_config: UncheckedAccount<'info>,
}

pub fn handler(ctx: Context<WithdrawSettle>) -> Result<()> {
    let session = &ctx.accounts.withdraw_session;
    require!(session.is_complete(), WagonError::SessionNotComplete);

    // P6 (C-B): autorización. El inversor SIEMPRE; un TERCERO solo si la sesión
    // está COMPROMETIDA (sold==1), completa y barrida — el terminal de una sesión
    // que extrajo valor es el SETTLE permissionless (el abort queda vetado, P4).
    // SEGURO: el caller no elige NINGÚN destino (investor por verify_token_account,
    // tesorería/hucha pinneadas por derivación, residuo a vault_usdc_ata pinneado,
    // rents por close=refund_target validado en settle_refund).
    // G1 (2026-10-09): «comprometida» = ya no puede cancelarse (`committed()`: vendió o cobró en
    // especie; aparcó con saldo; o es anterior al upgrade sin cancelación empezada).
    // Antes solo `sold == 1`: una sesión aparcada sin vender quedaba atada a `status != 4` (su
    // única salida independiente de status era el abort, que G1 veta) y solo el inversor podía
    // asentarla. Regla sellada: ningún terminal del retiro depende de status. El caller sigue
    // sin elegir ningún destino.
    // G3 (2026-10-15, F2B-02): una sesión SIN patas de token (`sweepable_mask() == 0`: todas las patas
    // triviales, USDC o peso 0) no tiene nada que vender ni barrer: su settle es neutral para el inversor
    // (cobra su slice de USDC, que ya salió del vault hacia su hucha en el init, menos las comisiones de
    // cualquier settle, sin riesgo de precio) y es el único
    // terminal que no depende de nadie, así que cuenta como comprometida para el settle: el inversor desde
    // el primer instante, también con el vault en reestructuración; un tercero pasados 10 min
    // (`trivial_settle_authorized`, ventana para que el inversor conserve en el acto la opción de cancelar).
    // `can_abort()` no cambia: el inversor sigue pudiendo cancelarla mientras nadie la asiente.
    let now = Clock::get()?.unix_timestamp;
    let caller_is_investor = ctx.accounts.caller.key() == session.investor;
    let committed = (session.committed() || session.trivial_settle_authorized(caller_is_investor, now))
        && session.is_complete()
        && session.fully_swept();
    require!(caller_is_investor || committed, WagonError::WithdrawSettleUnauthorized);

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
    let authority = ctx.accounts.protocol.authority;
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
    // DT-B (#54): la verificación INCONDICIONAL de la hucha del creador y el
    // owner-check INCONDICIONAL de la tesorería se ELIMINAN de aquí — hacían
    // revertir el settle si la hucha no existía (depósitos <10 USDC, exentos de
    // fee) o si esas cuentas se congelaban, aunque no hubiera comisión que pagar.
    // Los pins por pubkey (arriba) se conservan; cada transfer de comisión (abajo)
    // se gatea por `is_payable_usdc_ata` y el importe no pagado cae al vault por el
    // barrido de residuo. Fail-open simétrico con A5: nunca estrangular la salida.

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

    // ---- PR 5B (§3.5, D3 / M-04): S de salida GUARDADO en el registro emparejado -------
    // Se lee ANTES de pagar (nunca como argumento: un tercero que asienta no puede fijarlo) y
    // se acota al tope VIVO y al USDC que realmente sale. Sin registro, rancio o legacy: 0.
    let (stored_exit_service, record_generation) = crate::funding::matched_record(
        &ctx.accounts.funding_record.to_account_info(),
        &session_key,
        session.generation as u64,
        FUNDING_KIND_WITHDRAW,
    )?
    .map(|r| (r.exit_service_usdc, r.generation))
    .unwrap_or((0, 0));
    let (max_exit_service, service_paused) =
        service::read_exit_params_lenient(&ctx.accounts.service_config.to_account_info());

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
    // PR 5B: el S de salida se descuenta DESPUÉS de la comisión de éxito y ANTES del pago al
    // inversor; `saturating_sub` por construcción (nunca supera usdc_to_investor). SOLO si la
    // tesorería es PAGABLE (el mismo gate DT-B de las comisiones): si no lo es, no se descuenta
    // nada al inversor, así descontado ⟺ transferido ⟺ `ServiceCharged` y el S nunca acaba en
    // el vault sin rastro.
    let treasury_payable = is_payable_usdc_ata(
        &ctx.accounts.protocol_treasury_usdc_ata.to_account_info(),
        &usdc_mint_pk,
        None,
    );
    let exit_service: u64 = if treasury_payable {
        service::exit_service_at_settle(
            stored_exit_service,
            max_exit_service,
            service_paused,
            usdc_to_investor,
        )
    } else {
        0
    };
    let usdc_to_investor: u64 = usdc_to_investor.saturating_sub(exit_service);

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
    // DT-B (#54): gatear el cut del protocolo por payability. Tesorería con
    // expected_owner=None (destino ya key-pinned arriba; su authority no se
    // almacena). Si no es payable (inexistente/congelada) se SALTA, y el importe
    // se queda en el escrow y cae al vault por el barrido de residuo de abajo.
    if protocol_fee > 0 && treasury_payable {
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
    // PR 5B (§3.5, D3): el S de salida va a la MISMA tesorería. Ya vale 0 si no es pagable,
    // así que aquí siempre se transfiere lo descontado y se emite el evento: el gateway da S por
    // cobrado exactamente cuando ve `ServiceCharged`.
    if exit_service > 0 {
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
            exit_service,
        )?;
        emit!(ServiceCharged {
            user: investor_pk,
            vault: vault_key,
            kind: SERVICE_KIND_EXIT,
            amount_usdc: exit_service,
            generation: record_generation,
            op_account: session_key,
        });
    }
    // DT-B (#54): gatear el cut del creador por payability. Hucha con
    // expected_owner=Some(creator_rewards_authority) (owner = PDA [creator-rewards,
    // creator], igual que el verify que se eliminó). Si la hucha no existe o está
    // congelada se SALTA y el cut cae al vault por el barrido de residuo.
    if creator_fee > 0
        && is_payable_usdc_ata(
            &ctx.accounts.creator_rewards_ata.to_account_info(),
            &usdc_mint_pk,
            Some(creator_rewards_authority),
        )
    {
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
    // vault; el rent de la cuenta cae en el PDA de sesión (D1, §3.3) y sale con
    // la sesión hacia `refund_target`. Espejo de deposit_settle.
    let residual_usdc =
        crate::token_io::read_token_amount(&ctx.accounts.session_usdc_escrow.to_account_info())?;
    // DT-B (#54, companion): tolerar un vault_usdc_ata CONGELADO. Si no es payable y
    // hay residuo, se SALTAN sweep Y close — el escrow queda abierto con el residuo
    // (lo hereda la siguiente sesión de retiro de la pareja), pero el inversor YA cobró (arriba) y la sesión (PDA
    // WithdrawSession) cierra igual por su `close = refund_target` de Anchor. Así el
    // settle nunca revierte por un freeze de la ATA USDC del vault (fail-open A5). El
    // destino ya está key-pinned a usdc_ata_pk → expected_owner=None.
    let vault_ata_payable = is_payable_usdc_ata(
        &ctx.accounts.vault_usdc_ata.to_account_info(),
        &usdc_mint_pk,
        None,
    );
    if residual_usdc > 0 && vault_ata_payable {
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
    if residual_usdc == 0 || vault_ata_payable {
        token::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.session_usdc_escrow.to_account_info(),
                destination: ctx.accounts.withdraw_session.to_account_info(),
                authority: ctx.accounts.withdraw_session.to_account_info(),
            },
            signer_seeds,
        ))?;
        // G4 (F5A-01): la hucha USDC de la pareja ya no existe: el bit de quién la pagó vuelve a cero (una hucha nueva la paga
        // quien la cree, y la que cree un tercero sin sesión es, como cualquier donación, del inversor).
        ctx.accounts.user_position.escrow_rent_flags &= !ESCROW_RENT_WITHDRAW_USDC_WAGON;
    } else {
        // §3.3.c (B2): la hucha se queda abierta con el residuo; su rent NO viaja con este
        // reembolso (`lamports_sunk` del registro): la hereda la siguiente sesión de la
        // pareja. Se declara para el ledger y la monitorización off-chain; con o sin registro.
        emit!(FundingRefundPartial {
            session: session_key,
            kind: FUNDING_KIND_WITHDRAW,
            session_generation: session.generation as u64,
            escrow: ctx.accounts.session_usdc_escrow.key(),
            escrow_lamports: ctx.accounts.session_usdc_escrow.lamports(),
        });
    }

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
            crate::token_io::read_token_amount(&ctx.accounts.vault_usdc_ata.to_account_info())?;
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

    // G1 (2026-10-09, F1A-01): la sesión se cierra → libera su parte del contador de ENTRADA
    // (solo las que sumaron en el init: `counts_in_revivable`, nacidas con el contador, sin park definitivo y sin nacer cobradas).
    // saturating_sub: un terminal de salida nunca revierte. Cubre la venta Y el cobro en especie
    // (ambos ponen sold = 1 y desembocan aquí): `withdraw_claim_leg_in_kind` no toca el vault.
    {
        let s = &ctx.accounts.withdraw_session;
        if s.counts_in_revivable() {
            let mut data = vault_ai.try_borrow_mut_data()?;
            let cur = vlayout::read_revivable_burned_shares(&data)?;
            vlayout::write_revivable_burned_shares(&mut data, cur.saturating_sub(s.shares_to_burn))?;
        }
    }

    // H4 (ceremonia #45, R2): restar del agregado global el slice pro-rata
    // MARCADO en withdraw_init (valor de vault), NO `exit_value`. Simétrico con
    // el `+I` del depósito y con la Opción B; cierra el lado SALIDA del canal 4
    // — y del 3 (la salida en especie tampoco descontaba nada del agregado). saturating_sub:
    // nunca estrangula. Sesión legacy en vuelo: `marked_slice = 0` → resta 0
    // (no-op), el agregado se reconcilia solo en el siguiente `mark_tvl`.
    let protocol = &mut ctx.accounts.protocol;
    protocol.total_tvl_usdc = protocol.total_tvl_usdc.saturating_sub(marked_slice);

    // ---- Ceremonia USDC (§3.3, B2): reparto del rent temporal ----------------
    // Todas las huchas que se cierran ya lo hicieron hacia el PDA de la sesión; Anchor
    // cierra la sesión al salir hacia `refund_target`. Aquí se decide y valida ese destino
    // (registro emparejado → `refund_to` o la authority; si no, el inversor) y se cierra
    // el registro. Nunca revierte por el registro: sin él, o sin emparejar, legacy.
    crate::funding::settle_refund(
        &ctx.accounts.funding_record.to_account_info(),
        &ctx.accounts.refund_target.to_account_info(),
        &ctx.accounts.withdraw_session.to_account_info(),
        &investor_pk,
        &investor_pk,
        &authority,
        &ctx.accounts.caller.key(),
        ctx.accounts.withdraw_session.generation as u64,
        FUNDING_KIND_WITHDRAW,
        None,
    )?;

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
