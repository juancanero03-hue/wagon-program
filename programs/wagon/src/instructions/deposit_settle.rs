//! `deposit_settle` — final step of the fractional deposit flow.
//!
//! Since upgrade #31 (F2b) this runs AFTER `deposit_sweep_batch` moved
//! every escrowed token into the vault. It is PERMISSIONLESS: minting the
//! investor their shares and closing the session only benefits them, so
//! any caller (frontend, crank, us) can finish an abandoned-but-complete
//! session. Rent always flows back to the investor.
//!
//! Once every leg of the session has been executed AND swept (verified
//! via the two bitmaps), this instruction:
//!   1. Computes the shares owed to the investor against the pre-deposit
//!      snapshot frozen at `deposit_init`.
//!   2. Mints those shares to the investor's share ATA. On the very first
//!      deposit into a vault, also mints MIN_INITIAL_SHARES of "dead"
//!      shares to the vault's own share ATA (C1 fix for share inflation).
//!   3. Writes the vault's new total_shares, aggregate_cost_basis,
//!      and a conservative TVL upper bound.
//!   4. Updates the investor's UserPosition (init_if_needed; cost-basis
//!      and last_deposit_at).
//!   5. Closes the DepositSession PDA, refunding the rent to the investor.
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
use crate::events::DepositCompleted;
use crate::state::vault_layout as vlayout;
use crate::state::{DepositSession, ProtocolConfig, UserPosition};
use crate::token_io::verify_token_account;

#[derive(Accounts)]
pub struct DepositSettle<'info> {
    /// Upgrade #31 (F2b): permissionless cranker. Pays fees and the
    /// user_position rent if it doesn't exist yet; never receives funds.
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: pinned to `session.investor` via has_one. Receives the
    /// shares, the session rent and the escrow-ATA rent.
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
        // abiertos. Residual DECLARADO: el sweep/swap de una sesión en vuelo sigue
        // metiendo dinero al vault durante la pausa (cerrarlo tocaría el IDL).
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
    /// rounding dust) in the final sweep below.
    #[account(mut)]
    pub vault_usdc_ata: UncheckedAccount<'info>,

    /// CHECK: Upgrade #31 (F2b). The session's USDC escrow ATA, verified by
    /// canonical derivation. Drained into the vault and closed here; rent
    /// back to the investor.
    #[account(mut)]
    pub session_usdc_escrow: UncheckedAccount<'info>,

    /// Session is closed at the end of this ix; rent flows back to investor.
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
        close = investor,
    )]
    pub deposit_session: Box<Account<'info, DepositSession>>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
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
        // PEAJE ACEPTADO Y DECLARADO: esto convierte un caso de dinero VARADO
        // (F4) en uno de MAL PRECIO (F3, la ventana entre barrer y acuñar), que
        // sigue abierto hasta la #42. Perder el 100 % de un depósito es peor que
        // un precio mal calculado, pero es un canje, no una cura gratis.
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
    // Whatever USDC remains in the session escrow (the USDC-as-allocation
    // slice plus rounding dust from the weight math) belongs to the vault
    // the moment the deposit settles. Transfer it all, close the escrow,
    // rent back to the investor.
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

    let residual_usdc =
        crate::token_io::read_token_amount(&ctx.accounts.session_usdc_escrow.to_account_info())?;
    if residual_usdc > 0 {
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.session_usdc_escrow.to_account_info(),
                    to: ctx.accounts.vault_usdc_ata.to_account_info(),
                    authority: ctx.accounts.deposit_session.to_account_info(),
                },
                session_signer,
            ),
            residual_usdc,
        )?;
    }
    token::close_account(CpiContext::new_with_signer(
        ctx.accounts.token_program.to_account_info(),
        CloseAccount {
            account: ctx.accounts.session_usdc_escrow.to_account_info(),
            destination: ctx.accounts.investor.to_account_info(),
            authority: ctx.accounts.deposit_session.to_account_info(),
        },
        session_signer,
    ))?;

    // ---- Compute shares ---------------------------------------------------
    let amount_usdc = session.amount_usdc;
    let total_shares_before = session.total_shares_before;
    let tvl_before = session.tvl_before;

    // Ceremonia #39 (S-4): acuñar sobre el valor que REALMENTE aterrizó en el
    // vault (Σ received_value de las patas + el USDC residual de la hucha), no
    // sobre el USDC bruto. Así quien enrute su swap contra su propio pool cobra
    // participaciones solo por lo que llegó. El min(·, amount_usdc) lo hace
    // estrictamente conservador (solo puede acuñar MENOS, jamás más → el fix no
    // puede introducir dilución). Sesión legacy o guard apagado
    // (value_tracked == 0) ⇒ value_in == amount_usdc ⇒ fórmula idéntica al #38.
    let value_in: u64 = if session.value_tracked == 1 {
        session
            .received_value_acc
            .saturating_add(residual_usdc)
            .min(amount_usdc)
    } else {
        amount_usdc
    };

    let (investor_shares, dead_shares): (u64, u64) = if total_shares_before == 0 || tvl_before == 0
    {
        // Ceremonia #43 (A-FREEZE): una sesión NO comprometida puede abortar para
        // recuperar su USDC → rechazar un primer depósito de polvo la protege (#37).
        // Una COMPROMETIDA ya metió el dinero en el vault y NO puede abortar
        // (deposit_abort.rs:108-111): revertir aquí no lo devuelve, solo lo vara Y
        // congela el vault (contador atascado). Falla-ABIERTO → dona su polvo y
        // acuña las MIN dead shares.
        if !comprometida {
            require!(amount_usdc > MIN_INITIAL_SHARES, WagonError::ZeroDeposit);
        }
        // Primer depósito: no hay holders a los que diluir. Fallar-ABIERTO si el
        // valor medido no cubre las dead shares (esquina de polvo inalcanzable
        // para un depósito real — el guard #37 acota value_in ≥ 0,92·amount).
        let base = if value_in > MIN_INITIAL_SHARES {
            value_in
        } else {
            amount_usdc
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
        // sobre value_in da 0, caer a la fórmula legacy (amount_usdc) en vez de
        // dejar que reviente el require de más abajo y VARE los fondos (sería la
        // forma de S-3: tras el barrido settle, legs_swept != 0 bloquea el abort).
        // Solo alcanzable con depósitos diminutos: el guard #37 acota
        // value_in ≥ 0,92·amount, así que value_in nunca colapsa para un depósito
        // real; en esa esquina el atacante se autolesiona, no hay víctima.
        if s == 0 {
            s = (amount_usdc as u128)
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
    let haircut = (amount_usdc as u128)
        .saturating_mul(slip_bps)
        .saturating_div(BPS_DENOMINATOR as u128);
    // Ceremonia #39 (S-4): la cota conservadora del TVL también se capa a lo que
    // realmente aterrizó (value_in), para no sobrestimar el TVL cuando el depósito
    // destruyó valor en la ejecución. Con el guard apagado value_in == amount_usdc
    // ⇒ sin cambio respecto al #38.
    let conservative_add =
        ((amount_usdc as u128).saturating_sub(haircut) as u64).min(value_in);

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
            .checked_add(amount_usdc)
            .ok_or(WagonError::MathOverflow)?
    } else {
        live_agg_cost
    };
    // ⚠️ Ceremonia #41 — descuadre TRANSITORIO y conocido de `tvl_last_computed`:
    // el camino nuevo (sesión comprometida que asienta DESPUÉS de un cambio de
    // cesta) hace por primera vez posible que `live_tvl` YA incluya estos tokens.
    // `restructure_settle` recomputa `tvl_last_computed` desde los saldos vivos
    // del vault, que ya contienen lo barrido por esta sesión; al sumar aquí
    // `conservative_add` otra vez, la cifra queda inflada por este depósito.
    // Es INOFENSIVO y se deja a propósito: (1) `tvl_last_computed` es display-only
    // (decisión sellada: NAV bruto, jamás precio de ejecución) y no alimenta
    // ninguna acuñación ni retiro — `investor_shares` sale de las fotos de la
    // sesión, no de aquí; (2) `total_shares`/`aggregate_cost_basis` NO se
    // descuadran (restructure_settle no los toca; se escriben live+delta);
    // (3) `mark_tvl` y el indexer lo recalculan desde los saldos reales. El
    // arreglo fino (no sumar si la sesión es previa a la última reestructuración)
    // se deja para la #42 con el resto de F4, para no meter una rama nueva en un
    // cálculo de dinero en la ceremonia mínima.
    let tvl_after = live_tvl
        .checked_add(conservative_add)
        .ok_or(WagonError::MathOverflow)?;

    {
        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::write_total_shares(&mut data, new_total_shares)?;
        vlayout::write_aggregate_cost_basis_usdc(&mut data, new_agg_cost)?;
        vlayout::write_tvl_last_computed_usdc(&mut data, tvl_after)?;
        // Ceremonia #43: decrementa el contador de depósitos COMPROMETIDOS. GUARDADO
        // por `comprometida`: una sesión NO comprometida (all-trivial 100% USDC)
        // llega aquí con legs_swept==0 sin haber incrementado NUNCA → decrementar
        // aquí bajaría el contador de más (undercount) y reabriría el robo OT-1.
        // Emparejado exactamente con el incremento del sweep. saturating_sub: nunca
        // underflow. Se hace incluso en la ruta de DONACIÓN (investor_shares==0): una
        // comprometida siempre cierra y siempre decrementa.
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
        }
    }

    // protocol.total_tvl_usdc was advanced at deposit_init. Don't double-add.
    //
    // H4 (ceremonia #45, Opción B): quitar del agregado el slippage de ENTRADA de
    // ESTE depósito. `deposit_init` sumó `net_usdc` (== `amount_usdc` aquí, porque
    // `deposit_init` guarda `session.amount_usdc = net_usdc`) pero solo aterrizó
    // `conservative_add` (<= `amount_usdc` SIEMPRE: `haircut >= 0` y
    // `value_in <= amount_usdc`). El residuo `net_usdc - conservative_add` nunca
    // salía del global (canal 4): cada ciclo depósito+retiro lo dejaba varado y
    // acumulaba hacia el tope. Se resta SOLO ese residuo → delta <= 0 ESTRICTO:
    // jamás infla ni bloquea. `saturating_sub` interno blinda la cota; el
    // `if > 0` evita el no-op con el guard apagado. Aplica a TODA sesión que
    // asiente (incl. donación), porque `deposit_init` sumó `net` incondicional.
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
            .checked_add(amount_usdc)
            .ok_or(WagonError::MathOverflow)?;
    }
    position.last_deposit_at = now;

    emit!(DepositCompleted {
        vault: vault_key_for_check,
        investor: investor_pk,
        usdc_in: amount_usdc,
        shares_minted: investor_shares,
        tvl_before_usdc: tvl_before,
        tvl_after_usdc: tvl_after,
    });

    Ok(())
}
