//! `deposit_settle` — final step of the fractional deposit flow.
//!
//! Since upgrade #31 (F2b) this runs AFTER `deposit_sweep_batch` moved
//! every escrowed token into the vault. It is PERMISSIONLESS: minting the
//! investor their shares and closing the session only benefits them, so
//! any caller (frontend, crank, us) can finish an abandoned-but-complete
//! session. The temporary rent (session + escrows) goes back to whoever
//! funded it: the investor, or the sponsor's `refund_to` when the session
//! carries a paired `FundingRecord` (ceremonia USDC §3.3, D1).
//!
//! Once every leg of the session has been executed AND swept (verified
//! via the two bitmaps), this instruction:
//!   0. DT-E: pays the entry fee E reserved in the session escrow (its two cuts,
//!      sealed at init) to the treasury and the creator's hucha, each one only if
//!      its destination can receive (DT-B gate); an unpayable cut goes with the rest.
//!      E is charged only on the capital that lands in the vault (none if the escrow
//!      is frozen). The rest goes to the vault; if the vault's USDC ATA cannot receive,
//!      to the investor's canonical USDC ATA; if that cannot either (or the escrow
//!      itself is frozen), it stays in the escrow: the pair's next `deposit_init` or
//!      `deposit_escrow_reclaim` returns it. The settle of a COMMITTED session never
//!      blocks on a USDC account; an uncommitted one (nothing swept into the vault)
//!      whose capital cannot land fails with `DepositUncommittedMustAbort` and is
//!      cancelled with `deposit_abort`, which returns I + E.
//!   1. Computes the shares owed to the investor against the pre-deposit
//!      snapshot frozen at `deposit_init`.
//!   2. Mints those shares to the investor's share ATA. On the very first
//!      deposit into a vault, also mints MIN_INITIAL_SHARES of "dead"
//!      shares to the vault's own share ATA (C1 fix for share inflation).
//!   3. Writes the vault's new total_shares, aggregate_cost_basis,
//!      and a conservative TVL upper bound.
//!   4. Updates the investor's UserPosition (init_if_needed; cost-basis
//!      and last_deposit_at).
//!   5. Closes the DepositSession PDA (and its FundingRecord, if paired),
//!      refunding the rent to `refund_target` (§3.3).
//!
//! Pricing rationale: we use the snapshot rather than the live vault
//! state to guarantee the investor pays the price they committed at init.
//! If the vault appreciated mid-batch (a different investor's deposit, an
//! airdrop, etc.), they don't get diluted; if it depreciated, they don't
//! get bonus shares from someone else's loss.

use anchor_lang::prelude::*;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token::{self, spl_token, CloseAccount, MintTo, Token, Transfer};

use crate::constants::*;
use crate::errors::WagonError;
use crate::entry_fee;
use crate::events::{DepositCompleted, DepositResidualReturned, EntryFeeCharged, EntryFeeDiverted, FundingRefundPartial};
use crate::state::vault_layout as vlayout;
use crate::state::{DepositSession, ProtocolConfig, UserPosition, FUNDING_KIND_DEPOSIT};
use crate::token_io::{derive_live_ata, is_payable_usdc_ata, verify_token_account};

#[derive(Accounts)]
pub struct DepositSettle<'info> {
    /// Upgrade #31 (F2b): permissionless cranker. Pays fees and the
    /// user_position rent if it doesn't exist yet; never receives funds.
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: pinned to `session.investor` via has_one. Receives the shares.
    /// The rent goes to `refund_target` (the investor unless the session is
    /// sponsored, §3.3).
    #[account(mut)]
    pub investor: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        // Ceremonia #49 (A6): el freno de emergencia GLOBAL debe frenar también la
        // ACUÑACIÓN de participaciones nuevas. deposit_settle es el único mint del
        // camino de depósito; la cuenta protocol ya está aquí, así que un constraint
        // no cambia el IDL. Iguala la pausa global a la por-vault (que ya cubría el
        // pipeline vía status==Active). Los RETIROS no pasan por aquí → siguen
        // abiertos.
        constraint = !protocol.paused @ WagonError::ProtocolPaused,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// CHECK: PDA seeds verified manually.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    /// CHECK: pubkey verified against `vault_layout::read_share_mint`.
    #[account(mut)]
    pub share_mint: UncheckedAccount<'info>,

    /// CHECK: SPL Token account, mint == share_mint, owner == investor.
    #[account(mut)]
    pub investor_share_ata: UncheckedAccount<'info>,

    /// CHECK: SPL Token account, mint == share_mint, owner == vault PDA.
    /// Receives dead-shares on first-ever deposit; ignored otherwise.
    #[account(mut)]
    pub vault_share_ata: UncheckedAccount<'info>,

    #[account(
        init_if_needed,
        payer = caller,
        space = UserPosition::LEN,
        seeds = [
            USER_POSITION_SEED,
            vault.key().as_ref(),
            investor.key().as_ref(),
        ],
        bump,
    )]
    pub user_position: Box<Account<'info, UserPosition>>,

    /// CHECK: pubkey verified against `vault_layout::read_usdc_ata`.
    /// Receives the escrow's residual USDC (USDC-as-allocation slice +
    /// rounding dust; DT-E: plus any entry-fee cut whose destination could
    /// not receive) in the final sweep below, only if it can receive (DT-E).
    #[account(mut)]
    pub vault_usdc_ata: UncheckedAccount<'info>,

    /// CHECK: Upgrade #31 (F2b). The session's USDC escrow ATA, verified by
    /// canonical derivation. DT-E: pays the reserved entry fee first, then the
    /// rest (to the vault, or to the investor) and is closed here, its rent
    /// landing on the session PDA (D1); if the rest cannot move, it stays open.
    #[account(mut)]
    pub session_usdc_escrow: UncheckedAccount<'info>,

    /// Session is closed at the end of this ix; its whole balance (own rent +
    /// escrow rents closed into it) flows to `refund_target` (§3.3).
    #[account(
        mut,
        seeds = [
            DEPOSIT_SESSION_SEED,
            vault.key().as_ref(),
            investor.key().as_ref(),
        ],
        bump = deposit_session.bump,
        has_one = investor @ WagonError::DepositSessionWrongInvestor,
        has_one = vault @ WagonError::DepositSessionWrongVault,
        close = refund_target,
    )]
    pub deposit_session: Box<Account<'info, DepositSession>>,

    /// CHECK: Ceremonia USDC (§3.3): registro de financiación de esta sesión en su PDA
    /// canónica (SIEMPRE esa dirección, nunca el centinela; verificada en el handler).
    /// Si existe y empareja se cierra aquí hacia `refund_target`; si la dirección está
    /// vacía es el camino legacy (rent al inversor).
    #[account(mut)]
    pub funding_record: UncheckedAccount<'info>,

    /// CHECK: destino del saldo de la sesión y del registro: `refund_to` del registro
    /// emparejado (o `protocol.authority` como alternativo si firma el inversor o la propia
    /// authority, cinturón «la salida nunca se atasca», B2), o el inversor si no hay registro. Validado en el handler; si no es
    /// un destino admitido, la transacción entera revierte (`FundingRefundTargetMismatch`).
    #[account(mut)]
    pub refund_target: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,

    // ---- DT-E: destinos de la comisión de entrada reservada (opcionales Anchor) ----
    // Obligatorias (Some) si su corte sellado en la sesión es > 0; si vienen, deben ser las
    // canónicas. Con E = 0 el cliente pasa el centinela (program id), como en el init.
    /// CHECK: key == `protocol.treasury_usdc_ata`; recibe el corte del protocolo si es pagable.
    #[account(mut)]
    pub fee_treasury_usdc_ata: Option<UncheckedAccount<'info>>,

    /// CHECK: ATA USDC canónica del PDA [b"creator-rewards", creator]; recibe el corte del
    /// creador si es pagable.
    #[account(mut)]
    pub creator_rewards_ata: Option<UncheckedAccount<'info>>,

    /// CHECK: DT-E. ATA USDC CANÓNICA del inversor (clave atada; no se exige que exista). Solo
    /// se usa si la ATA USDC del vault no puede recibir: entonces lo que iba al vault vuelve aquí
    /// en vez de bloquear el settle (si tampoco puede recibir, se queda en la hucha).
    #[account(mut)]
    pub investor_usdc_ata: UncheckedAccount<'info>,
}

pub fn handler(ctx: Context<DepositSettle>) -> Result<()> {
    let session = &ctx.accounts.deposit_session;

    // ---- Verify the session is complete -----------------------------------
    require!(session.is_complete(), WagonError::SessionNotComplete);
    // Upgrade #31 (F2b): a session on the abort path can never settle, and
    // every escrowed token must already have been swept into the vault.
    require!(session.aborting == 0, WagonError::DepositSessionAborting);
    require!(session.fully_swept(), WagonError::EscrowNotSwept);

    // ---- Read vault for PDA seeds + share_mint pubkey ---------------------
    let vault_ai = ctx.accounts.vault.to_account_info();
    require_keys_eq!(*vault_ai.owner, crate::ID, WagonError::VaultPaused);

    let (creator, nonce, vault_bump, share_mint_pk, max_slippage_bps, usdc_ata_pk) = {
        let data = vault_ai.try_borrow_data()?;
        (
            vlayout::read_creator(&data)?,
            vlayout::read_nonce(&data)?,
            vlayout::read_bump(&data)?,
            vlayout::read_share_mint(&data)?,
            vlayout::read_max_slippage_bps(&data)?,
            vlayout::read_usdc_ata(&data)?,
        )
    };
    let nonce_le = nonce.to_le_bytes();
    let (derived_vault_key, derived_bump) =
        Pubkey::find_program_address(&[VAULT_SEED, creator.as_ref(), &nonce_le], &crate::ID);
    require_keys_eq!(
        ctx.accounts.vault.key(),
        derived_vault_key,
        WagonError::VaultPaused
    );
    require!(vault_bump == derived_bump, WagonError::VaultPaused);

    // Ceremonia #41/#43: sesión COMPROMETIDA = ya barrió TODO su dinero al vault y
    // NO puede abortar (deposit_abort.rs:108-111). El MISMO predicado gobierna tres
    // cosas: (a) saltar la puerta de stale (F4, #41); (b) el asiento inabortable-en-
    // revert (A-FREEZE, #43): para una comprometida los frenos de shares==0 no
    // revierten, donan; (c) el decremento del contador de comprometidas (#43).
    // Hoisteado para usarlo en los tres. Idéntico a deposit_abort.rs:108-111.
    let comprometida = ctx.accounts.deposit_session.fully_swept()
        && ctx.accounts.deposit_session.legs_swept != 0
        && ctx.accounts.deposit_session.aborting == 0;
    // G2-b (F1B-02): una sesión con todas las patas triviales contó +1 en su init (nunca barre): se drena al
    // final (`DepositSession::drain_committed_if_trivial`, drenaje ÚNICO compartido con `deposit_abort`).
    // Disjunta de `comprometida` (esa exige `legs_swept != 0`). NO salta la puerta de fecha y deriva de
    // abajo: puede abortar (no metió dinero en el vault), así que la puerta sigue protegiendo.
    // Upgrade #31: ni settle durante una reestructuración, ni de una sesión
    // previa a la última (la tabla de allocations ya no es la suya).
    //
    // ⚠️ Ceremonia #41: este comentario decía además «deposit_abort sigue
    // disponible para recuperar el USDC». ERA FALSO para una sesión que ya
    // barrió al vault, y esa frase es el origen de F4: afirmaba por escrito la
    // salida de emergencia que hacía inofensivas a estas puertas, y esa salida
    // no existe (deposit_abort.rs veta con
    // `session.aborting == 1 || session.legs_swept == 0`).
    {
        let data = vault_ai.try_borrow_data()?;
        let status = vlayout::read_status(&data)?;
        require!(status != 4u8, WagonError::RestructuringInProgress);
        // M-3: settling a deposit is an ENTRY into the vault (mints shares)
        // — only allowed while the vault is Active. Refunds keep working:
        // deposit_abort and the sweep abort-direction are any-status.
        require!(status == 0u8, WagonError::VaultPaused);

        // F4 (ceremonia #41) — la puerta de la fecha NO se aplica a una sesión
        // que ya metió TODO su dinero en el vault.
        //
        // Por qué: en ese estado `deposit_abort` está vetado, así que el asiento
        // es su ÚNICA salida y esta puerta deja de proteger nada — pasa a ser la
        // forma de matar su dinero. El creador la dispara completando un cambio
        // de cesta: `restructure_settle` estampa `last_restructured_at` y esa
        // fecha solo sube.
        //
        // Por qué es seguro, VERIFICADO (no supuesto — ver el aviso de arriba):
        //   · el valor barrido no puede quedar fuera de la contabilidad del
        //     vault. El guardián real es `deposit_sweep_batch`: todo barrido
        //     POSTERIOR a la reestructuración se fuerza a la dirección de vuelta
        //     y estampa `aborting = 1`, así que nada aterriza en una ATA que la
        //     cesta nueva ya no cuenta. (El chequeo de saldo cero de
        //     `restructure_settle` es PUNTUAL, no un invariante: no apoyarse en
        //     él para razonar esto.)
        //   · este handler no lee la tabla de allocations en ningún punto: las
        //     participaciones salen de las fotos de la sesión
        //     (`total_shares_before`, `tvl_before`), no de la cesta viva.
        //
        // Así un caso de dinero VARADO (F4) pasa a ser uno de PRECIO en la ventana
        // entre barrer y acuñar (ver `phantom_shares` y `pending_committed_shares`,
        // ceremonia #44).
        //
        // El `fully_swept()` es redundante con el require de más arriba y está a
        // propósito: hace este invariante comprobable leyendo SOLO este bloque.
        // Sin él el predicado también sería cierto para una sesión barrida A
        // MEDIAS, para la que «no tiene vuelta atrás» es FALSO. Un comentario que
        // afirma un guard que el código no implementa es el bug C-B de la #39.
        // Y `legs_swept != 0` tampoco sobra: `fully_swept()` es cierto de forma
        // trivial cuando todas las patas son USDC y no hay nada que barrer.
        // (El predicado `comprometida` se computó arriba, hoisteado.)
        if !comprometida {
            let lra = vlayout::read_last_restructured_at(&data)?;
            require!(
                ctx.accounts.deposit_session.created_at >= lra,
                WagonError::StaleSessionAfterRestructure
            );
            // G2-a (F3B-01): la fecha empata en el mismo segundo; la IDENTIDAD de la cesta (número de
            // patas y mint por posición) no. Misma definición que el barrido (`basket_drift`). Solo para
            // una sesión NO comprometida (la comprometida ya metió su dinero y asienta con sus fotos).
            require!(
                !vlayout::basket_drift(
                    &data,
                    ctx.accounts.deposit_session.leg_count,
                    &ctx.accounts.deposit_session.leg_mints,
                )?,
                WagonError::StaleSessionAfterRestructure
            );
        }
    }

    // ---- Validate SPL accounts --------------------------------------------
    let investor_pk = ctx.accounts.investor.key();
    let vault_key_for_check = ctx.accounts.vault.key();
    require_keys_eq!(
        ctx.accounts.share_mint.key(),
        share_mint_pk,
        WagonError::InvalidJupiterRoute
    );
    require_keys_eq!(
        *ctx.accounts.share_mint.owner,
        spl_token::ID,
        WagonError::InvalidJupiterRoute
    );

    verify_token_account(
        &ctx.accounts.investor_share_ata.to_account_info(),
        &share_mint_pk,
        &investor_pk,
    )?;
    verify_token_account(
        &ctx.accounts.vault_share_ata.to_account_info(),
        &share_mint_pk,
        &vault_key_for_check,
    )?;

    // ---- Upgrade #31 (F2b): drain the USDC escrow into the vault ----------
    // G5: el barrido de commit ya metió en el vault el capital de la hucha cuando podía moverse (y lo sumó a lo aterrizado,
    // `received_value_acc` y `landed_value_at_commit`); aquí queda E y, si no pudo moverse entonces, ese capital.
    // Whatever USDC remains in the session escrow (the USDC-as-allocation
    // slice plus rounding dust from the weight math) belongs to the vault
    // the moment the deposit settles; DT-E: except the reserved entry fee E,
    // paid out first (below), and whatever cannot land (it goes back to the
    // investor). Then close the escrow, its rent onto the session PDA (D1,
    // §3.3): the session's close hands everything to `refund_target` at the
    // end of this ix.
    require_keys_eq!(
        ctx.accounts.vault_usdc_ata.key(),
        usdc_ata_pk,
        WagonError::InvalidJupiterRoute
    );
    let usdc_mint_pk = ctx.accounts.protocol.usdc_mint;
    let session_key = ctx.accounts.deposit_session.key();
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

    let session_bump_arr = [ctx.accounts.deposit_session.bump];
    let session_seeds: &[&[u8]] = &[
        DEPOSIT_SESSION_SEED,
        vault_key_for_check.as_ref(),
        investor_pk.as_ref(),
        &session_bump_arr,
    ];
    let session_signer: &[&[&[u8]]] = &[session_seeds];

    // ---- DT-E: repartir la hucha (E reservada + capital sin invertir) --------
    // Los cortes de E vienen SELLADOS del init (un cambio de parámetros a mitad de sesión no
    // los toca). Cada destino se valida si viene y es obligatorio si su corte es > 0. Solo se
    // paga a un destino que puede recibir (`is_payable_usdc_ata`, la puerta DT-B del retiro):
    // si se congeló durante la sesión, su corte sigue al resto. `plan_landing` decide qué
    // capital entra en el vault y qué parte de E se cobra (solo sobre el capital que entró;
    // nada con la hucha congelada, de la que no sale nada); `plan_settle`, el reparto.
    let cut_protocol = ctx.accounts.deposit_session.entry_fee_protocol_cut_usdc;
    let cut_creator = ctx.accounts.deposit_session.entry_fee_creator_cut_usdc;
    let treasury_ai = ctx.accounts.fee_treasury_usdc_ata.as_ref().map(|a| a.to_account_info());
    let rewards_ai = ctx.accounts.creator_rewards_ata.as_ref().map(|a| a.to_account_info());
    let (treasury_payable, creator_payable) = entry_fee_payability(
        treasury_ai.as_ref(),
        rewards_ai.as_ref(),
        &ctx.accounts.protocol.treasury_usdc_ata,
        &creator,
        &usdc_mint_pk,
        cut_protocol,
        cut_creator,
    )?;
    require_keys_eq!(
        ctx.accounts.investor_usdc_ata.key(),
        derive_live_ata(&investor_pk, &usdc_mint_pk, &spl_token::ID),
        WagonError::InvestorUsdcAtaNotCanonical
    );
    let escrow_ai = ctx.accounts.session_usdc_escrow.to_account_info();
    let escrow_usdc = crate::token_io::read_token_amount(&escrow_ai)?;
    let escrow_frozen = crate::token_io::read_token_state(&escrow_ai)? == crate::token_io::TOKEN_STATE_FROZEN;
    let vault_can_receive =
        is_payable_usdc_ata(&ctx.accounts.vault_usdc_ata.to_account_info(), &usdc_mint_pk, None);
    let amount_usdc = session.amount_usdc;
    let landing = entry_fee::plan_landing(
        escrow_usdc,
        cut_protocol,
        cut_creator,
        amount_usdc,
        vault_can_receive,
        escrow_frozen,
    );
    // Una sesión NO comprometida (no barrió nada al vault: todas sus patas son USDC) cuyo capital no
    // puede entrar no acuñaría nada: no se asienta, se cancela (`deposit_abort` devuelve I + E).
    require!(
        comprometida || landing.unlanded_capital_usdc == 0,
        WagonError::DepositUncommittedMustAbort
    );
    let plan = entry_fee::plan_settle(
        escrow_usdc,
        landing.charge_protocol_usdc,
        landing.charge_creator_usdc,
        treasury_payable,
        creator_payable,
    );
    for (dest, amount) in [
        (ctx.accounts.fee_treasury_usdc_ata.as_ref(), plan.pay_protocol_usdc),
        (ctx.accounts.creator_rewards_ata.as_ref(), plan.pay_creator_usdc),
    ] {
        if amount == 0 {
            continue;
        }
        let dest = dest.ok_or(WagonError::MissingEntryFeeAccounts)?; // pagable ⇒ Some
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.session_usdc_escrow.to_account_info(),
                    to: dest.to_account_info(),
                    authority: ctx.accounts.deposit_session.to_account_info(),
                },
                session_signer,
            ),
            amount,
        )?;
    }

    // El resto (capital sin invertir + la parte de E no pagable o no cobrada) va al vault. El
    // settle de una sesión comprometida NUNCA se bloquea por una cuenta USDC (una congelación de
    // Circle): si la ATA del vault no puede recibir, el resto vuelve a la ATA canónica del inversor;
    // si tampoco puede, o si la hucha está congelada, se queda en ella: el siguiente `deposit_init`
    // de la pareja se lo devuelve al inversor antes de empezar, y sin sesión abierta lo devuelve
    // `deposit_escrow_reclaim`. Como en el retiro (DT-B). Lo que no entra no acuña (abajo).
    let lands = vault_can_receive && !escrow_frozen;
    let residual_dest = if plan.to_vault_usdc == 0 || escrow_frozen {
        None
    } else if lands {
        Some(ctx.accounts.vault_usdc_ata.to_account_info())
    } else if is_payable_usdc_ata(&ctx.accounts.investor_usdc_ata.to_account_info(), &usdc_mint_pk, Some(investor_pk)) {
        Some(ctx.accounts.investor_usdc_ata.to_account_info())
    } else {
        None
    };
    if let Some(dest) = residual_dest.as_ref() {
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.session_usdc_escrow.to_account_info(),
                    to: dest.clone(),
                    authority: ctx.accounts.deposit_session.to_account_info(),
                },
                session_signer,
            ),
            plan.to_vault_usdc,
        )?;
    }
    let returned_usdc = if !lands && residual_dest.is_some() { plan.to_vault_usdc } else { 0 };
    let left_in_escrow_usdc = if residual_dest.is_none() { plan.to_vault_usdc } else { 0 };
    if left_in_escrow_usdc == 0 && !escrow_frozen {
        token::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.session_usdc_escrow.to_account_info(),
                destination: ctx.accounts.deposit_session.to_account_info(),
                authority: ctx.accounts.deposit_session.to_account_info(),
            },
            session_signer,
        ))?;
    } else {
        // La hucha se queda abierta (con el resto, o congelada); su rent no viaja con este reembolso.
        emit!(FundingRefundPartial {
            session: session_key,
            kind: FUNDING_KIND_DEPOSIT,
            session_generation: ctx.accounts.deposit_session.generation as u64,
            escrow: ctx.accounts.session_usdc_escrow.key(),
            escrow_lamports: ctx.accounts.session_usdc_escrow.lamports(),
        });
    }
    if returned_usdc > 0 || left_in_escrow_usdc > 0 || landing.waived_usdc > 0 {
        emit!(DepositResidualReturned {
            vault: vault_key_for_check,
            investor: investor_pk,
            returned_usdc,
            left_in_escrow_usdc,
            entry_fee_waived_usdc: landing.waived_usdc,
            session: session_key,
        });
    }

    // ---- Compute shares ---------------------------------------------------
    let total_shares_before = session.total_shares_before;
    let tvl_before = session.tvl_before;
    // DT-E: capital que ENTRÓ en el vault (`plan_landing`). Lo que no entró (volvió al inversor o
    // se quedó en la hucha) ni acuña ni es base de coste.
    let capital_in = landing.capital_in_usdc;
    let landed_capital_residual = landing.landed_capital_residual_usdc;

    // Ceremonia #39 (S-4): acuñar sobre el valor que REALMENTE aterrizó en el
    // vault (Σ received_value de las patas + el USDC residual de CAPITAL de la hucha,
    // DT-E: sin E, ni siquiera la parte desviada al vault), no
    // sobre el USDC bruto. Así quien enrute su swap contra su propio pool cobra
    // participaciones solo por lo que llegó. El min(·, capital_in) lo hace
    // estrictamente conservador (solo puede acuñar MENOS, jamás más → el fix no
    // puede introducir dilución). Sesión legacy o guard apagado
    // (value_tracked == 0) ⇒ value_in == capital_in (== amount_usdc salvo que la ATA
    // del vault no pudiera recibir) ⇒ fórmula idéntica al #38 en el caso normal.
    let value_in: u64 = if session.value_tracked == 1 {
        session
            .received_value_acc
            .saturating_add(landed_capital_residual)
            .min(capital_in) // DT-E: nunca por encima del capital que entró (== I en el caso normal)
    } else {
        capital_in
    };
    // G2-c (auditoría 2026-10-09, F1A-03): el commit re-marcó el DENOMINADOR (`tvl_before`, `tsb`) a mercado
    // (S-1) pero el NUMERADOR seguía al precio del swap: quien elegía CUÁNDO cometer tenía una opción gratuita
    // si el precio bajaba entre el swap y el commit. El barrido de commit valoró lo que ATERRIZÓ con el MISMO
    // oráculo (`landed_value_at_commit`); aquí acota `value_in` por arriba con ese valor más el capital
    // residual de la hucha (USDC, 1:1). Solo puede acuñar MENOS (como S-4); sin valoración
    // (`landed_tracked == 0`: sesiones anteriores al upgrade o migradas, commit con el m2m apagado) nada cambia.
    let value_in = session.cap_by_landed_value(value_in, landed_capital_residual);
    // G2-c (revisión N3, M2): las dos caídas de polvo de abajo acuñaban sobre `capital_in` SIN la cota. Si lo
    // aterrizado vale casi 0 al precio del commit (desplome entre el swap y el commit), la cota deja `value_in`
    // en polvo, `s` sale 0 y la caída acuñaría por TODO el capital: MÁS que sin G2-c y diluyendo a los titulares
    // por tokens sin valor. La base de la caída lleva la MISMA cota: con la cota activa y `s` aún en 0, el
    // depósito comprometido DONA (0 participaciones), el comportamiento ya aceptado en #43.
    let fallback_in = session.cap_by_landed_value(capital_in, landed_capital_residual);

    let (investor_shares, dead_shares): (u64, u64) = if total_shares_before == 0 || tvl_before == 0
    {
        // Ceremonia #43 (A-FREEZE): una sesión NO comprometida puede abortar para
        // recuperar su USDC → rechazar un primer depósito de polvo la protege (#37).
        // Una COMPROMETIDA ya metió el dinero en el vault y NO puede abortar
        // (deposit_abort.rs:108-111): revertir aquí no lo devuelve, solo lo vara Y
        // congela el vault (contador atascado). Falla-ABIERTO → dona su polvo y
        // acuña las MIN dead shares.
        if !comprometida {
            require!(capital_in > MIN_INITIAL_SHARES, WagonError::ZeroDeposit);
        }
        // Primer depósito: no hay holders a los que diluir. Fallar-ABIERTO si el
        // valor medido no cubre las dead shares (esquina de polvo inalcanzable
        // para un depósito real con el guard #37 activo: acota value_in por debajo
        // con el umbral sellado en la sesión).
        let base = if value_in > MIN_INITIAL_SHARES {
            value_in
        } else {
            fallback_in // G2-c (M2): acotado por lo aterrizado (== capital_in sin valoración)
        };
        // saturating_sub (#43): con el freno #37 saltado para una comprometida,
        // `base <= MIN` daría PANIC con la resta cruda. Para una no-comprometida el
        // require de arriba garantiza `base > MIN` → saturating_sub == `-` (idéntico).
        (base.saturating_sub(MIN_INITIAL_SHARES), MIN_INITIAL_SHARES)
    } else {
        let mut s = (value_in as u128)
            .checked_mul(total_shares_before as u128)
            .ok_or(WagonError::MathOverflow)?
            .checked_div(tvl_before as u128)
            .ok_or(WagonError::DivisionByZero)?;
        // Ceremonia #39 (S-4): fallar-ABIERTO en la esquina de polvo. Si acuñar
        // sobre value_in da 0, caer a `fallback_in` (capital_in; G2-c M2: acotado por lo aterrizado) en vez de
        // dejar que reviente el require de más abajo y VARE los fondos (sería la
        // forma de S-3: tras el barrido settle, legs_swept != 0 bloquea el abort).
        // Solo alcanzable con depósitos diminutos: con el guard #37 activo, acota
        // value_in por debajo con el umbral sellado en la sesión, así que value_in nunca colapsa
        // para un depósito real; en esa esquina quien lo provoca se autolesiona.
        if s == 0 {
            // G2-c (M2): `fallback_in` == `capital_in` sin valoración (idéntico a hoy); con la cota activa
            // sigue acotado por lo aterrizado (solo puede acuñar MENOS).
            s = (fallback_in as u128)
                .checked_mul(total_shares_before as u128)
                .ok_or(WagonError::MathOverflow)?
                .checked_div(tvl_before as u128)
                .ok_or(WagonError::DivisionByZero)?;
        }
        (
            u64::try_from(s).map_err(|_| WagonError::MathOverflow)?,
            0u64,
        )
    };

    // Ceremonia #37 (pieza 3): nunca acuñar 0 participaciones al inversor. La
    // división floor de arriba puede dar 0 si el precio por share se ha
    // apreciado muchísimo (≈×10⁶): sin esto, el depósito se quedaría con el
    // USDC del inversor a cambio de nada.
    // Ceremonia #43 (A-FREEZE): el freno solo aplica a NO comprometidas (que pueden
    // abortar y recuperar su USDC). Una COMPROMETIDA con investor_shares==0 DONA
    // (0 shares; su valor sube el NAV de los holders) y cierra+decrementa en vez de
    // revertir para siempre. Donar es AUTOLESIÓN (recaptura ≤ fracción previa < lo
    // donado), nunca robo; solo alcanzable con polvo/precio inflado adrede.
    if !comprometida {
        require!(investor_shares > 0, WagonError::ZeroSharesMinted);
    }

    // ---- Mint shares ------------------------------------------------------
    let bump_arr = [vault_bump];
    let seeds: &[&[u8]] = &[VAULT_SEED, creator.as_ref(), &nonce_le, &bump_arr];
    let signer_seeds: &[&[&[u8]]] = &[seeds];

    // Ceremonia #43: en la DONACIÓN (investor_shares==0) no se acuña al inversor
    // (mint_to(0) sería no-op igualmente; se guarda por claridad/CU).
    if investor_shares > 0 {
        token::mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.share_mint.to_account_info(),
                    to: ctx.accounts.investor_share_ata.to_account_info(),
                    authority: ctx.accounts.vault.to_account_info(),
                },
                signer_seeds,
            ),
            investor_shares,
        )?;
    }
    if dead_shares > 0 {
        token::mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.share_mint.to_account_info(),
                    to: ctx.accounts.vault_share_ata.to_account_info(),
                    authority: ctx.accounts.vault.to_account_info(),
                },
                signer_seeds,
            ),
            dead_shares,
        )?;
    }

    // ---- Update vault state -----------------------------------------------
    let now = Clock::get()?.unix_timestamp;
    // Conservative TVL upper bound (matches the legacy deposit math).
    let slip_bps = max_slippage_bps as u128;
    // DT-E: sobre el capital que ENTRÓ (capital_in; == amount_usdc en el caso normal).
    let haircut = (capital_in as u128)
        .saturating_mul(slip_bps)
        .saturating_div(BPS_DENOMINATOR as u128);
    // Ceremonia #39 (S-4): la cota conservadora del TVL también se capa a lo que
    // realmente aterrizó (value_in), para no sobrestimar el TVL cuando el depósito
    // destruyó valor en la ejecución. Con el guard apagado value_in == capital_in
    // ⇒ sin cambio respecto al #38 en el caso normal.
    let conservative_add =
        ((capital_in as u128).saturating_sub(haircut) as u64).min(value_in);

    // Ceremonia #38 (C1): total_shares / aggregate_cost_basis / tvl se escriben
    // como LIVE + delta, NO snapshot + delta. Los snapshots del init
    // (total_shares_before, tvl_before) se usaron ARRIBA solo para el PRECIO
    // (investor_shares) — el precio comprometido. Pero escribir el AGREGADO
    // desde el snapshot descartaba cualquier cambio que otra sesión hubiera
    // asentado entre este deposit_init y este deposit_settle (depósitos
    // concurrentes de distintos inversores, o el burn de un retiro solapado) →
    // total_shares divergía del supply real del share mint. Leemos LIVE y
    // sumamos el delta, igual que withdraw_init (live - burn).
    let (live_total_shares, live_agg_cost, live_tvl) = {
        let data = vault_ai.try_borrow_data()?;
        (
            vlayout::read_total_shares(&data)?,
            vlayout::read_aggregate_cost_basis_usdc(&data)?,
            vlayout::read_tvl_last_computed_usdc(&data)?,
        )
    };
    let new_total_shares = live_total_shares
        .checked_add(investor_shares)
        .ok_or(WagonError::MathOverflow)?
        .checked_add(dead_shares)
        .ok_or(WagonError::MathOverflow)?;
    // Ceremonia #43: en la DONACIÓN (investor_shares==0) el valor entra al vault
    // pero NO crea una posición → no suma a la base de coste AGREGADA (que es Σ de
    // las bases de las UserPosition; mantenerlo así conserva agg_cost == Σ cost_basis).
    // Con investor_shares>0 (todo depósito real) es idéntico al #42.
    let new_agg_cost = if investor_shares > 0 {
        live_agg_cost
            .checked_add(capital_in) // DT-E: la base de coste es el capital que entró
            .ok_or(WagonError::MathOverflow)?
    } else {
        live_agg_cost
    };
    // `tvl_last_computed` es un valor de CACHÉ: `investor_shares` sale de las fotos de
    // la sesión, no de aquí; `total_shares` / `aggregate_cost_basis` se escriben
    // live+delta; y `mark_tvl` lo recalcula desde los saldos reales del vault.
    let tvl_after = live_tvl
        .checked_add(conservative_add)
        .ok_or(WagonError::MathOverflow)?;

    {
        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::write_total_shares(&mut data, new_total_shares)?;
        vlayout::write_aggregate_cost_basis_usdc(&mut data, new_agg_cost)?;
        vlayout::write_tvl_last_computed_usdc(&mut data, tvl_after)?;
        // Ceremonia #43: decrementa el contador de depósitos COMPROMETIDOS. GUARDADO
        // por `comprometida` (emparejado exactamente con el incremento del sweep).
        // G2-b: una sesión con TODAS las patas triviales de la generación nueva SÍ
        // sumó +1 en `deposit_init` y se drena en el `else` de abajo (drenaje único); solo las de
        // generación 0 (anteriores al upgrade) llegan sin haber sumado y por eso no
        // restan (restarles bajaría el contador de más y reabriría el robo OT-1).
        // saturating_sub: nunca underflow. Se hace incluso en la ruta de DONACIÓN
        // (investor_shares==0): una comprometida siempre cierra y siempre decrementa.
        if comprometida {
            let cur = vlayout::read_committed_deposits(&data)?;
            vlayout::write_committed_deposits(&mut data, cur.saturating_sub(1))?;
            // Ceremonia #44 (F3): libera la reserva de participaciones fantasma de
            // esta sesión. El MISMO `phantom_shares()` sobre los mismos campos
            // inmutables (amount_usdc/total_shares_before/tvl_before, capturados
            // arriba) que el incremento del barrido → resta EXACTA lo que sumó.
            // `saturating_sub`: NUNCA revierte (regla sellada: cero require! nuevo
            // que pueda VARAR en settle). Se ejecuta también en la ruta de DONACIÓN
            // (#43, investor_shares==0): pending subió por P y baja por el MISMO P
            // sea cual sea el resultado del mint → auto-consistente.
            let p = vlayout::phantom_shares(amount_usdc, total_shares_before, tvl_before);
            let cur_pending = vlayout::read_pending_committed_shares(&data)?;
            vlayout::write_pending_committed_shares(&mut data, cur_pending.saturating_sub(p))?;
        } else {
            // G2-b: una sesión con TODAS las patas triviales de la generación nueva sumó +1 en `deposit_init`
            // (sin reserva fantasma que liberar: su USDC nunca estuvo en el vault). Drenaje ÚNICO, compartido
            // con `deposit_abort` (cinturón de Kairo en el #63): `DepositSession::drain_committed_if_trivial`.
            ctx.accounts.deposit_session.drain_committed_if_trivial(&mut data)?;
        }
    }

    // protocol.total_tvl_usdc was advanced at deposit_init. Don't double-add.
    //
    // H4 (ceremonia #45, Opción B): quitar del agregado el slippage de ENTRADA de
    // ESTE depósito. `deposit_init` sumó `session.amount_usdc` (I = D − E, el
    // capital que entra en la cesta: E se descuenta de lo pagado, decisión de Juan
    // del 15-oct-2026) pero
    // solo aterrizó `conservative_add` (<= `amount_usdc` SIEMPRE: `haircut >= 0` y
    // `value_in <= amount_usdc`). El residuo `amount_usdc - conservative_add` nunca
    // salía del global (canal 4): cada ciclo depósito+retiro lo dejaba varado y
    // acumulaba hacia el tope. Se resta SOLO ese residuo → delta <= 0 ESTRICTO:
    // jamás infla ni bloquea. `saturating_sub` interno blinda la cota; el
    // `if > 0` evita el no-op con el guard apagado. Aplica a TODA sesión que
    // asiente (incl. donación), porque `deposit_init` sumó I incondicional.
    let residuo_slip = amount_usdc.saturating_sub(conservative_add);
    if residuo_slip > 0 {
        let protocol = &mut ctx.accounts.protocol;
        protocol.total_tvl_usdc = protocol.total_tvl_usdc.saturating_sub(residuo_slip);
    }

    // ---- Update UserPosition ----------------------------------------------
    let position = &mut ctx.accounts.user_position;
    if position.created_at == 0 {
        position.wallet = investor_pk;
        position.vault = vault_key_for_check;
        position.created_at = now;
        position.bump = ctx.bumps.user_position;
    }
    // Ceremonia #43: en la DONACIÓN (investor_shares==0) NO se añaden shares ni base
    // de coste (evita una posición con coste sin participaciones). La CABECERA sí se
    // escribe arriba, para no dejar una posición huérfana a cero. Con investor_shares>0
    // (todo depósito real) es idéntico al #42.
    if investor_shares > 0 {
        position.shares = position
            .shares
            .checked_add(investor_shares)
            .ok_or(WagonError::MathOverflow)?;
        position.cost_basis_usdc = position
            .cost_basis_usdc
            .checked_add(capital_in) // DT-E: el capital que entró (== I en el caso normal)
            .ok_or(WagonError::MathOverflow)?;
    }
    position.last_deposit_at = now;

    // ---- Ceremonia USDC (§3.3): reparto del rent temporal --------------------
    // Las huchas ya están cerradas hacia el PDA de la sesión (salvo la USDC si se quedó abierta,
    // DT-E: su rent no viaja, lo declara `FundingRefundPartial`); Anchor cierra la
    // sesión al salir hacia `refund_target`. Aquí se decide y se valida ese destino
    // (registro emparejado → `refund_to` o la authority; si no, el inversor) y se cierra
    // el registro.
    let authority = ctx.accounts.protocol.authority;
    crate::funding::settle_refund(
        &ctx.accounts.funding_record.to_account_info(),
        &ctx.accounts.refund_target.to_account_info(),
        &ctx.accounts.deposit_session.to_account_info(),
        &investor_pk,
        &investor_pk,
        &authority,
        &ctx.accounts.caller.key(),
        ctx.accounts.deposit_session.generation as u64,
        FUNDING_KIND_DEPOSIT,
        None,
    )?;

    // DT-E: lo que de verdad llegó a cada destino, y lo que cayó al vault.
    let paid_usdc = plan.pay_protocol_usdc.saturating_add(plan.pay_creator_usdc);
    if paid_usdc > 0 {
        emit!(EntryFeeCharged {
            vault: vault_key_for_check,
            creator,
            investor: investor_pk,
            fee_usdc: paid_usdc,
            creator_cut_usdc: plan.pay_creator_usdc,
            protocol_cut_usdc: plan.pay_protocol_usdc,
        });
    }
    if plan.diverted_protocol_usdc > 0 || plan.diverted_creator_usdc > 0 {
        emit!(EntryFeeDiverted {
            vault: vault_key_for_check,
            creator,
            investor: investor_pk,
            creator_cut_usdc: plan.diverted_creator_usdc,
            protocol_cut_usdc: plan.diverted_protocol_usdc,
        });
    }

    emit!(DepositCompleted {
        vault: vault_key_for_check,
        investor: investor_pk,
        usdc_in: capital_in, // DT-E: el capital que entró (== I salvo ATA del vault congelada)
        shares_minted: investor_shares,
        tvl_before_usdc: tvl_before,
        tvl_after_usdc: tvl_after,
    });

    Ok(())
}

/// DT-E: destinos de la comisión de entrada reservada. Cada destino que viene se ata a su clave
/// canónica; si no viene, su corte debe ser 0. Devuelve si cada uno puede recibir su corte
/// (corte > 0 y cuenta pagable, la puerta DT-B de `withdraw_settle`).
fn entry_fee_payability(
    treasury: Option<&AccountInfo>,
    creator_rewards: Option<&AccountInfo>,
    protocol_treasury: &Pubkey,
    creator: &Pubkey,
    usdc_mint: &Pubkey,
    cut_protocol: u64,
    cut_creator: u64,
) -> Result<(bool, bool)> {
    let treasury_payable = match treasury {
        Some(t) => {
            require_keys_eq!(t.key(), *protocol_treasury, WagonError::EntryFeeTreasuryMismatch);
            cut_protocol > 0 && is_payable_usdc_ata(t, usdc_mint, None)
        }
        None => {
            require!(cut_protocol == 0, WagonError::MissingEntryFeeAccounts);
            false
        }
    };
    let creator_payable = match creator_rewards {
        Some(r) => {
            let (rewards_authority, _) =
                Pubkey::find_program_address(&[CREATOR_REWARDS_SEED, creator.as_ref()], &crate::ID);
            require_keys_eq!(
                r.key(),
                derive_live_ata(&rewards_authority, usdc_mint, &spl_token::ID),
                WagonError::CreatorRewardsAtaMismatch
            );
            cut_creator > 0 && is_payable_usdc_ata(r, usdc_mint, Some(rewards_authority))
        }
        None => {
            require!(cut_creator == 0, WagonError::MissingEntryFeeAccounts);
            false
        }
    };
    Ok((treasury_payable, creator_payable))
}
