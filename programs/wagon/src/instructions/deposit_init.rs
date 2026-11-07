//! `deposit_init` — step 1 of the fractional deposit flow.
//!
//! Locks the investor's USDC into the SESSION'S OWN ESCROW ATA (upgrade
//! #31, F2b — before that it went straight into the vault), snapshots the
//! pre-deposit valuation (tvl + total_shares + agg_cost_basis), pre-marks
//! any USDC-as-allocation leg as already-completed (no swap needed), and
//! creates the `DepositSession` PDA that subsequent `deposit_swap_batch`,
//! `deposit_sweep_batch` and `deposit_settle` calls will consume.
//!
//! The escrow keeps unsettled deposits OUT of the vault: the vault's idle
//! USDC and allocation ATAs only ever contain settled funds, so the
//! mark-to-market TVL other depositors see is never polluted by someone
//! else's in-flight session. G4 (F5A-01, 17-oct-2026): the PROGRAM creates the escrow USDC ATA
//! (owner = session PDA) by CPI when it is missing, paid by `payer`; the client no longer creates
//! it. Its rent goes back to whoever paid it: a sponsored session marks the escrow as Wagon's
//! (`close_authority` = the session PDA) and an init of the other class buys it at rent minimum
//! (`crate::escrow_rent`).
//!
//! Why split this off from `deposit_swap_batch`:
//!   - We need the snapshot taken atomically with the USDC transfer, before
//!     any swap can move the price. Doing it inside swap_batch would let
//!     a malicious wallet front-run the snapshot with another deposit's
//!     swap and skew the valuation.
//!   - Init is the natural place to enforce the TVL cap, so we don't end
//!     up half-way through a batch and then have to bail.
//!
//! Comisión de entrada E DESCONTADA de lo que paga el inversor (decisión de Juan, 15-oct-2026,
//! que deroga el «E encima» de la ceremonia USDC §3.9; `crate::entry_fee`): `amount_usdc` es D,
//! lo que paga el inversor (+ S); el capital que entra en la cesta es I = D − E. DT-E: E no se
//! reparte aquí; entra en la hucha dentro de D y sus dos cortes quedan sellados en la sesión
//! hasta `deposit_settle`; `deposit_abort` la devuelve. Con la comisión apagada, I = D.

use anchor_lang::prelude::*;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token::{self, spl_token, Token, Transfer};

use crate::constants::*;
use crate::entry_fee;
use crate::escrow_rent;
use crate::errors::WagonError;
use crate::events::{DepositInitiated, DepositResidualReturned, FundingRecorded, ServiceCharged};
use crate::service;
use crate::state::vault_layout as vlayout;
use crate::state::{DepositSession, FundingRecord, ProtocolConfig, ServiceConfig, FUNDING_KIND_DEPOSIT, SessionPrice};
use crate::token_io::{derive_live_ata, is_payable_usdc_ata, verify_token_account};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct DepositInitArgs {
    pub amount_usdc: u64,
    /// Ceremonia USDC §3.5: servicio S en átomos de USDC, firmado por el inversor (0 sin
    /// patrocinio; obligatorio > 0 con `payer` distinto del inversor; <= tope).
    pub service_usdc: u64,
}

#[derive(Accounts)]
pub struct DepositInit<'info> {
    #[account(mut)]
    pub investor: Signer<'info>,

    /// Ceremonia USDC (§3.2): PAGADOR del rent que crea esta instrucción, separado
    /// del propietario. Sin patrocinio, el cliente pasa la MISMA wallet que el
    /// propietario en los dos papeles (una sola firma y la misma lista de claves;
    /// la instrucción solo lleva un índice de cuenta más, +1 B); con patrocinio,
    /// el sponsor. NUNCA paga comisiones: esas siguen saliendo del propietario.
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        mut,
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        constraint = !protocol.paused @ WagonError::ProtocolPaused,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// CHECK: PDA seeds + status verified manually via byte-level reads.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    /// CHECK: pubkey verified against `vault_layout::read_usdc_ata`.
    #[account(mut)]
    pub vault_usdc_ata: UncheckedAccount<'info>,

    /// CHECK: SPL Token account validated manually: program owner spl_token,
    /// mint == usdc_mint, owner == investor.key(). Con `service_usdc > 0` debe ser
    /// además su ATA CANÓNICA de USDC (5A-bis, `ServiceUserAtaMismatch`).
    #[account(mut)]
    pub investor_usdc_ata: UncheckedAccount<'info>,

    /// CHECK: pubkey verified against `protocol.usdc_mint`.
    pub usdc_mint: UncheckedAccount<'info>,

    #[account(
        init,
        payer = payer,
        space = DepositSession::LEN,
        seeds = [
            DEPOSIT_SESSION_SEED,
            vault.key().as_ref(),
            investor.key().as_ref(),
        ],
        bump,
    )]
    pub deposit_session: Box<Account<'info, DepositSession>>,

    /// CHECK: Upgrade #31 (F2b). ATA de USDC propiedad de la sesión PDA —
    /// el escrow donde queda bloqueado el USDC del inversor hasta el settle.
    /// Verificada por derivación canónica + verify_token_account. G4: si falta, la
    /// crea el programa (CPI al programa de ATAs, paga `payer`).
    #[account(mut)]
    pub session_usdc_escrow: UncheckedAccount<'info>,

    /// Ceremonia USDC (§3.3): registro de financiación de ESTA sesión en su PDA canónica
    /// `[b"funding", session]`. Se crea (pagado por `payer`) si y solo si el pagador NO
    /// es el propietario (patrocinio); sin patrocinio el cliente pasa el centinela `None`
    /// (program id) y no se crea nada: el rent vuelve al inversor como siempre. Si la
    /// dirección ya está ocupada por un registro (rancio) el `init` de Anchor falla en el
    /// System Program: el gateway comprueba la dirección antes de preparar un init
    /// patrocinado (B3 añade el backstop `funding_reclaim_stale`).
    #[account(
        init,
        payer = payer,
        space = FundingRecord::LEN,
        seeds = [FUNDING_SEED, deposit_session.key().as_ref()],
        bump,
    )]
    pub funding_record: Option<Box<Account<'info, FundingRecord>>>,

    /// CHECK: destino del reembolso del rent patrocinado, elegido por el pagador y
    /// acotado en el handler a {payer, protocol.authority} y no ejecutable
    /// (`FundingRefundToNotAllowed`). Sin patrocinio se pasa el propio inversor.
    pub refund_to: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,

    // ---- entry fee (fase 2, 2026-07-01) — OPTIONAL Anchor accounts ---------
    // Required (Some) when the entry fee is ON or when service_usdc > 0 (§3.5: S goes to
    // the same treasury). Otherwise the frontend passes the
    // program id as Anchor's None sentinel while the fee is OFF. They sit
    // AFTER every named account and BEFORE remaining_accounts (which carry
    // the m2m oracle set), so old-shape transactions that omit them would
    // shift the oracle accounts into these slots — that is why the frontend
    // that passes them must ship together with the program upgrade.
    /// CHECK: protocol fee destination. Key-checked == protocol.treasury_usdc_ata
    /// (the canonical ATA stored at initialize). DT-E: con E > 0 solo se VALIDA (pagable);
    /// el corte del protocolo lo transfiere `deposit_settle`. S sigue cobrándose aquí.
    #[account(mut)]
    pub fee_treasury_usdc_ata: Option<UncheckedAccount<'info>>,

    /// CHECK: the creator's rewards vault ("hucha") — canonical USDC ATA of
    /// the per-creator PDA [b"creator-rewards", creator]. Same derivation
    /// `claim_creator_rewards` enforces; verified canonically + mint/owner
    /// in the handler when the fee is ON. DT-E: solo se valida (pagable); cobra en el settle.
    #[account(mut)]
    pub creator_rewards_ata: Option<UncheckedAccount<'info>>,

    /// Ceremonia USDC §3.5: topes y pausa del servicio S (solo lectura). Va DESPUÉS de las
    /// dos opcionales de la comisión (sus centinelas siguen siendo obligatorios) y ANTES
    /// de los `remaining` del oráculo m2m.
    #[account(seeds = [SERVICE_CONFIG_SEED], bump = service_config.bump)]
    pub service_config: Box<Account<'info, ServiceConfig>>,

    /// G4 (F5A-01): el programa de ATAs, para crear la hucha USDC si falta. Tras `service_config`
    /// y antes de los `remaining` del oráculo.
    pub associated_token_program: Program<'info, AssociatedToken>,

    /// CHECK: G4 (F5A-01): `protocol.authority` (el vault de Squads), OPCIONAL (centinela = program
    /// id): solo hace falta cuando un init SIN patrocinio encuentra la hucha marcada como de Wagon y
    /// le compra su rent (6227 si falta o es otra). Opcional para no bloquear en escritura esa cuenta
    /// en cada depósito.
    #[account(mut)]
    pub rent_authority: Option<UncheckedAccount<'info>>,
}

pub fn handler(ctx: Context<DepositInit>, args: DepositInitArgs) -> Result<()> {
    let amount_usdc = args.amount_usdc;
    require!(amount_usdc > 0, WagonError::ZeroDeposit);
    // G3 (2026-10-15): mínimo de 10 USDC en el programa (`MIN_DEPOSIT_USDC`), medido sobre lo que paga el inversor.
    require!(amount_usdc >= MIN_DEPOSIT_USDC, WagonError::DepositBelowMinimum);

    // ---- Read & validate vault (byte-level) --------------------------------
    let vault_ai = ctx.accounts.vault.to_account_info();
    let guard = crate::guards::VaultGuard::load_active(
        &vault_ai,
        &ctx.accounts.vault.key(),
        WagonError::VaultPaused,
    )?;
    let (creator, nonce, vault_bump, status) =
        (guard.creator, guard.nonce, guard.bump, guard.status);
    let nonce_le = nonce.to_le_bytes();
    let (allocation_count, total_shares_before, tvl_before, agg_cost_before, usdc_ata_pk, committed_deposits, stranded_flag, entry_blocked_by_withdraws) = {
        let data = vault_ai.try_borrow_data()?;
        (
            vlayout::read_allocation_count(&data)?,
            vlayout::read_total_shares(&data)?,
            vlayout::read_tvl_last_computed_usdc(&data)?,
            vlayout::read_aggregate_cost_basis_usdc(&data)?,
            vlayout::read_usdc_ata(&data)?,
            vlayout::read_committed_deposits(&data)?,
            vlayout::read_stranded_flag(&data)?,
            vlayout::entry_blocked_by_withdraws(&data)?,
        )
    };

    // ---- Ceremonia #47 (H2): veto con un depósito COMPROMETIDO en vuelo -------
    // La ventana en que otro depósito ya barrió sus tokens al vault pero aún no ha
    // acuñado (committed_deposits > 0) es EXACTAMENTE la ventana de dilución de H2:
    // el m2m de más abajo valora los saldos VIVOS del vault (que ya incluyen esos
    // tokens) pero total_shares_before NO cuenta sus participaciones fantasma → este
    // depositante nuevo pagaría de más por participación y quedaría diluido. Fail-
    // CLOSED antes de tocar un solo lamport (fee/escrow): revierte sin crear sesión.
    // No es bloqueo permanente: committed_deposits > 0 implica sesión swap-completa
    // (el incremento vive en la rama settle del barrido, que exige is_complete()), y
    // barrido + settle son PERMISSIONLESS → cualquiera cierra la ventana. Reusa el
    // error #43 (VaultHasCommittedDeposit): condición semánticamente idéntica; el
    // contexto de instrucción desambigua el mensaje. El retiro NO se toca.
    require!(
        committed_deposits == 0,
        WagonError::VaultHasCommittedDeposit
    );

    // ---- Ceremonia #53: veto con VALOR FUERA DE TABLA en el vault -------------
    // Mientras la bandera stranded esté puesta, el vault sostiene un token que
    // `compute_tvl_m2m_strict` NO ve (fuera de la tabla) → acuñar aquí daría
    // participaciones de más contra un TVL infravalorado y diluiría a los holders
    // previos cuando ese valor aflore (rescate → USDC ocioso). Fail-CLOSED antes de
    // tocar un lamport. NO es bloqueo permanente: se limpia rescatando + close_stranded
    // (permissionless) o admin_clear_stranded. El retiro NO se toca (la salida sigue).
    require!(
        stranded_flag == 0,
        WagonError::VaultHasStrandedValue
    );

    // ---- G1 (auditoría 2026-10-09, F1A-01): veto con retiros EN VUELO ----------
    // Un retiro abierto sin vender conserva shares quemadas que `withdraw_abort` re-acuña
    // enteras: ni la foto de precio de este init ni el commit pueden ser justos (los derechos
    // del retirador están fuera del denominador y cualquier USDC donado dentro del m2m). Lo
    // mismo con una cancelación ya empezada (`pending_burned`, que el abort re-acuñará; cubre
    // una sesión anterior al upgrade, fuera del contador). Fail-CLOSED solo de ENTRADA y
    // reintentable: se levanta cuando ese retiro vende, cobra en especie o cancela. La salida no
    // lo lee nunca. UNA definición: `vault_layout::entry_blocked_by_withdraws`.
    require!(!entry_blocked_by_withdraws, WagonError::VaultHasRevivableBurn);

    // Bitmap caps at 16 legs; the session's leg_mints snapshot (F2b) caps
    // at MAX_TOKENS_PER_VAULT, which is the binding limit (today 10).
    require!(
        allocation_count as usize <= crate::constants::MAX_TOKENS_PER_VAULT,
        WagonError::TooManyAllocations
    );

    // ---- Validate SPL accounts --------------------------------------------
    let usdc_mint_pk = ctx.accounts.protocol.usdc_mint;
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
        ctx.accounts.vault_usdc_ata.key(),
        usdc_ata_pk,
        WagonError::InvalidJupiterRoute
    );
    // DT-E: con la ATA USDC del vault congelada (Circle) no se admiten depósitos nuevos: su USDC
    // entraría en el m2m a la par sin poder moverse, y el settle ya no podría meter nada en ella.
    require!(
        is_payable_usdc_ata(&ctx.accounts.vault_usdc_ata.to_account_info(), &usdc_mint_pk, None),
        WagonError::VaultUsdcAtaNotPayable
    );

    let investor_pk = ctx.accounts.investor.key();
    verify_token_account(
        &ctx.accounts.investor_usdc_ata.to_account_info(),
        &usdc_mint_pk,
        &investor_pk,
    )?;

    // ---- Upgrade #31 (F2b): validate the session's USDC escrow ATA ---------
    // USDC is a classic SPL Token mint, so the escrow derivation is fixed to
    // the classic token program. Owner field must be the session PDA itself.
    let session_key = ctx.accounts.deposit_session.key();
    require_keys_eq!(
        ctx.accounts.session_usdc_escrow.key(),
        crate::token_io::derive_live_ata(&session_key, &usdc_mint_pk, &spl_token::ID),
        WagonError::EscrowAtaMismatch
    );
    // G4 (F5A-01): la hucha la crea el programa si falta (paga `payer`); si ya existía (heredada de una sesión anterior de la
    // pareja, o creada por cualquiera), su marca dice quién pagó su rent: sin marca el inversor, con ella Wagon. Si este init es
    // de la otra clase, su pagador se la compra al anterior por el rent mínimo y la marca pasa a la clase de este init; así el
    // terminal, que la cierra hacia el PDA de la sesión, devuelve ese rent a quien lo pagó. Una hucha congelada no llega aquí con
    // éxito: este init le transfiere D más abajo.
    let payer_pk = ctx.accounts.payer.key();
    let sponsored = payer_pk != investor_pk;
    {
        let escrow_ai = ctx.accounts.session_usdc_escrow.to_account_info();
        let session_ai = ctx.accounts.deposit_session.to_account_info();
        let existed = escrow_rent::account_exists(&escrow_ai);
        if !existed {
            escrow_rent::create_escrow(
                &ctx.accounts.associated_token_program.to_account_info(),
                &ctx.accounts.payer.to_account_info(),
                &escrow_ai,
                &session_ai,
                &ctx.accounts.usdc_mint.to_account_info(),
                &ctx.accounts.system_program.to_account_info(),
                &ctx.accounts.token_program.to_account_info(),
            )?;
        }
        verify_token_account(&escrow_ai, &usdc_mint_pk, &session_key)?;
        let wagon_before = existed && escrow_rent::deposit_escrow_is_wagon(&escrow_ai, &session_key)?;
        if existed && wagon_before != sponsored {
            let to = if wagon_before {
                escrow_rent::wagon_rent_dest(
                    ctx.accounts.rent_authority.as_ref().map(|a| a.as_ref()),
                    &ctx.accounts.protocol.authority,
                )?
                .clone()
            } else {
                ctx.accounts.investor.to_account_info()
            };
            escrow_rent::buy_escrow_rent(
                &ctx.accounts.system_program.to_account_info(),
                &ctx.accounts.payer.to_account_info(),
                &to,
                &escrow_ai,
                session_key,
            )?;
        }
        if wagon_before != sponsored {
            let vault_key = ctx.accounts.vault.key();
            let bump_arr = [ctx.bumps.deposit_session];
            let seeds: &[&[u8]] = &[DEPOSIT_SESSION_SEED, vault_key.as_ref(), investor_pk.as_ref(), &bump_arr];
            escrow_rent::set_deposit_escrow_mark(
                &ctx.accounts.token_program.to_account_info(),
                &escrow_ai,
                &session_ai,
                &[seeds],
                sponsored,
            )?;
        }
    }
    // DT-E: la hucha puede traer el resto que un settle (o, desde G2-b, un abort aplazado) anterior de
    // esta misma pareja vault + inversor no pudo mover (cuentas congeladas). Es del inversor: se le devuelve ANTES de meter
    // I + E, para que cada sesión empiece con la hucha a 0 y nunca se mezcle con dinero nuevo.
    let inherited_usdc = crate::token_io::read_token_amount(&ctx.accounts.session_usdc_escrow.to_account_info())?;
    if inherited_usdc > 0 {
        let vault_key = ctx.accounts.vault.key();
        let bump_arr = [ctx.bumps.deposit_session];
        let seeds: &[&[u8]] = &[DEPOSIT_SESSION_SEED, vault_key.as_ref(), investor_pk.as_ref(), &bump_arr];
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.session_usdc_escrow.to_account_info(),
                    to: ctx.accounts.investor_usdc_ata.to_account_info(),
                    authority: ctx.accounts.deposit_session.to_account_info(),
                },
                &[seeds],
            ),
            inherited_usdc,
        )?;
        emit!(DepositResidualReturned {
            vault: vault_key,
            investor: investor_pk,
            returned_usdc: inherited_usdc,
            left_in_escrow_usdc: 0,
            entry_fee_waived_usdc: 0,
            session: session_key,
        });
    }

    // ---- Entry fee (DESCONTADA de lo que paga el inversor; DT-E: reservada) ----
    // `amount_usdc` es D, lo que paga el inversor y entra ENTERO en la hucha. E = min(D × bps /
    // 10000, tope), solo con la comisión ON y con D desde la exención (tope, exención y el
    // mínimo de arriba se miden sobre D); el corte del protocolo redondea hacia ABAJO (el resto
    // va al creador). El capital que entra en la cesta es I = D − E (con 10 USDC pagados al 2 %
    // entran 9.80): participaciones, tope de TVL, `total_tvl_usdc`, base de coste (D14) y el
    // evento corren sobre I. La fórmula vive en `crate::entry_fee` (probada en unidad).
    let fee = {
        let p = &ctx.accounts.protocol;
        entry_fee::deduct_entry_fee(
            amount_usdc,
            &entry_fee::EntryFeeParams {
                bps: p.entry_fee_bps,
                cap_usdc: p.entry_fee_cap_usdc,
                exempt_below_usdc: p.entry_fee_exempt_below_usdc,
                protocol_share_bps: p.entry_fee_protocol_share_bps,
            },
        )?
    };
    let (capital_usdc, fee_usdc, protocol_cut_usdc, creator_cut_usdc) =
        (fee.capital_usdc, fee.fee_usdc, fee.protocol_cut_usdc, fee.creator_cut_usdc);
    // Cinturón: con el mínimo de 10 USDC y bps <= 5 % el capital nunca es 0 (>= 95 % de D).
    require!(capital_usdc > 0, WagonError::ZeroDeposit);

    // ---- Enforce TVL cap (sobre I, lo que entra en la cesta) ---------------
    {
        let protocol = &ctx.accounts.protocol;
        let projected_tvl = protocol
            .total_tvl_usdc
            .checked_add(capital_usdc)
            .ok_or(WagonError::MathOverflow)?;
        require!(
            projected_tvl <= protocol.tvl_cap_usdc,
            WagonError::TvlCapExceeded
        );
    }

    // ---- Upgrade #30: mark-to-market snapshot ------------------------------
    // Value the basket at market BEFORE the investor's USDC lands, so the
    // share price is fair to both sides. Without oracle accounts the legacy
    // stored TVL is used — allowed only while m2m enforcement is off.
    let tvl_before = if !ctx.remaining_accounts.is_empty() {
        let idle_usdc =
            crate::token_io::read_token_amount(&ctx.accounts.vault_usdc_ata.to_account_info())?;
        let m2m = crate::pricing::compute_tvl_m2m_strict(
            &vault_ai,
            &ctx.accounts.vault.key(),
            idle_usdc,
            &usdc_mint_pk,
            ctx.remaining_accounts,
        )?;
        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::write_tvl_last_computed_usdc(&mut data, m2m)?;
        m2m
    } else {
        require!(
            ctx.accounts.protocol.m2m_enforced == 0,
            WagonError::MissingPriceAccounts
        );
        tvl_before
    };

    // ---- Entry fee destinations (DT-E: se validan, NO se paga nada aquí) ----
    // E entra en la hucha dentro de D (abajo) y la reparte `deposit_settle`, el único
    // final de éxito; `deposit_abort` devuelve D = I + E. Aquí se exige, ANTES de
    // comprometer el depósito, que cada destino con corte > 0 sea el canónico y
    // pueda recibir (un init no es una salida: fail-closed). Si un destino deja de
    // poder recibir DURANTE la sesión, el settle desvía ese corte al vault (DT-B).
    if fee_usdc > 0 {
        let treasury_ai = ctx
            .accounts
            .fee_treasury_usdc_ata
            .as_ref()
            .ok_or(WagonError::MissingEntryFeeAccounts)?;
        let rewards_ai = ctx
            .accounts
            .creator_rewards_ata
            .as_ref()
            .ok_or(WagonError::MissingEntryFeeAccounts)?;

        // Protocol cut can only go to the ONE treasury ATA fixed at init.
        require_keys_eq!(
            treasury_ai.key(),
            ctx.accounts.protocol.treasury_usdc_ata,
            WagonError::EntryFeeTreasuryMismatch
        );

        // Creator cut accrues in the canonical USDC ATA of the per-creator
        // rewards PDA — the exact account `claim_creator_rewards` pays from.
        let (rewards_authority, _) =
            Pubkey::find_program_address(&[CREATOR_REWARDS_SEED, creator.as_ref()], &crate::ID);
        require_keys_eq!(
            rewards_ai.key(),
            derive_live_ata(&rewards_authority, &usdc_mint_pk, &spl_token::ID),
            WagonError::CreatorRewardsAtaMismatch
        );
        verify_token_account(
            &rewards_ai.to_account_info(),
            &usdc_mint_pk,
            &rewards_authority,
        )?;

        if protocol_cut_usdc > 0 {
            require!(
                is_payable_usdc_ata(&treasury_ai.to_account_info(), &usdc_mint_pk, None),
                WagonError::TreasuryNotPayable
            );
        }
        if creator_cut_usdc > 0 {
            require!(
                is_payable_usdc_ata(&rewards_ai.to_account_info(), &usdc_mint_pk, Some(rewards_authority)),
                WagonError::CreatorRewardsNotPayable
            );
        }
    }

    // ---- Transfer USDC investor → session escrow (upgrade #31, F2b) -------
    // The vault sees nothing until deposit_settle sweeps the escrow. An
    // abandoned session can always be unwound with deposit_abort — the
    // funds never mixed with the vault's. Comisión descontada + DT-E: entra D entero,
    // que es I + E; los swaps se cotizan sobre I (la sesión guarda I) y no pueden tocar E
    // (reserva de `deposit_swap_batch`); el settle reparte E y barre el resto al vault.
    token::transfer(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.investor_usdc_ata.to_account_info(),
                to: ctx.accounts.session_usdc_escrow.to_account_info(),
                authority: ctx.accounts.investor.to_account_info(),
            },
        ),
        amount_usdc,
    )?;

    // ---- Pre-mark USDC-as-allocation legs as completed ---------------------
    // If any allocation slot is itself USDC, that "leg" needs no swap — its
    // slice stays in the escrow as USDC and reaches the vault in the settle
    // sweep. We mark its bit at init so deposit_swap_batch never has to
    // handle it and deposit_settle's completeness check passes. We also
    // snapshot the allocation mints into the session (leg_mints) so sweeps
    // and aborts never have to trust the LIVE vault table — which may have
    // restructured to a different basket mid-session.
    let mut legs_completed: u16 = 0;
    let mut leg_mints = [Pubkey::default(); crate::constants::MAX_TOKENS_PER_VAULT];
    for i in 0..(allocation_count as usize) {
        let alloc_mint = {
            let data = vault_ai.try_borrow_data()?;
            vlayout::read_allocation_mint(&data, i)?
        };
        let weight_bps = {
            let data = vault_ai.try_borrow_data()?;
            vlayout::read_allocation_weight_bps(&data, i)?
        };
        leg_mints[i] = alloc_mint;
        // Zero-weight slots are also "completed" — nothing to do.
        if alloc_mint == usdc_mint_pk || weight_bps == 0 {
            legs_completed |= 1u16 << i;
        }
    }

    // ---- Initialise DepositSession ----------------------------------------
    // Ceremonia #37: el umbral del guard de pérdida por compra se SELLA en la
    // sesión (deposit_swap_batch no lleva la cuenta protocol). Las sesiones
    // abiertas antes de encender el guard llevan 0 → nunca quedan atrapadas.
    let swap_max_loss_bps = ctx.accounts.protocol.swap_max_loss_bps;
    let now = Clock::get()?.unix_timestamp;
    let session = &mut ctx.accounts.deposit_session;
    session.investor = investor_pk;
    session.vault = ctx.accounts.vault.key();
    session.amount_usdc = capital_usdc; // I = D − E: el capital que entra en la cesta (E se descuenta de D)
    session.total_shares_before = total_shares_before;
    session.tvl_before = tvl_before;
    session.agg_cost_before = agg_cost_before;
    session.leg_count = allocation_count;
    session.legs_completed = legs_completed;
    session.created_at = now;
    session.bump = ctx.bumps.deposit_session;
    // Upgrade #31 (F2b): escrow bookkeeping.
    session.legs_swept = 0;
    session.aborting = 0;
    session.trivial_mask = legs_completed; // at init, completed == trivial
    session.leg_mints = leg_mints;
    session.max_loss_bps = swap_max_loss_bps;
    // Ceremonia #39 (S-4): acumulador del valor-oráculo recibido. Se sella ON
    // solo si el guard va vivo (sin guard no hay oráculo enhebrado en los
    // swap_batch → no hay medición posible; la sesión usará la fórmula legacy).
    session.received_value_acc = 0;
    session.value_tracked = if swap_max_loss_bps > 0 { 1 } else { 0 };
    // Ceremonia USDC (§3.4): contador del vault +1 (UNA vez por init) y sello en la
    // sesión con sus 32 bits bajos (nunca 0: el bump salta los múltiplos de 2^32).
    let generation = {
        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::bump_session_generation(&mut data)?
    };
    session.generation = generation as u32;
    // G2-c (F1A-03): la valoración de lo que aterriza la hace el barrido de COMMIT con el oráculo del
    // re-precio S-1 (`deposit_sweep_batch`); la sesión nace sin valorar.
    session.landed_tracked = 0;
    session.landed_value_at_commit = 0;
    session.landed_prices = [SessionPrice::default(); MAX_TOKENS_PER_VAULT];
    // DT-E: los dos cortes de E, reservados en el escrow hasta el settle (o devueltos por el abort).
    session.entry_fee_protocol_cut_usdc = protocol_cut_usdc;
    session.entry_fee_creator_cut_usdc = creator_cut_usdc;

    // ---- G2-b (F1B-02): una sesión con TODAS las patas triviales cuenta como COMPROMETIDA ------
    // desde el init (`DepositSession::trivial_committed`, definición única). No pasará por el
    // barrido de commit (nada que barrer), así que el +1 se hace aquí y lo drenan su settle y su
    // abort. El veto H-03 de más arriba (`committed_deposits == 0`) ya corrió: sigue habiendo a lo
    // sumo UNA comprometida por vault. saturating_add: nunca envuelve (falla cerrado).
    if session.trivial_committed() {
        let mut data = vault_ai.try_borrow_mut_data()?;
        let cur = vlayout::read_committed_deposits(&data)?;
        vlayout::write_committed_deposits(&mut data, cur.saturating_add(1))?;
    }

    // ---- Ceremonia USDC (§3.3): registro de financiación ---------------------
    // Patrocinio = el pagador NO es el propietario. Con patrocinio el registro es
    // OBLIGATORIO (Anchor ya lo creó si venía; aquí se sella); sin patrocinio está
    // PROHIBIDO (quien paga su propio SOL no crea nada y su terminal va por legacy).
    // `refund_to` se acota siempre: con patrocinio, el pagador o `protocol.authority`;
    // sin patrocinio SOLO el propio inversor (la authority no vale: no hay registro y
    // el contrato del cliente es «el inversor»).
    require!(
        ctx.accounts.funding_record.is_some() == sponsored,
        WagonError::FundingRecordPresenceMismatch
    );
    let authority = ctx.accounts.protocol.authority;
    crate::funding::check_refund_to(
        &ctx.accounts.refund_to,
        &payer_pk,
        if sponsored { &authority } else { &payer_pk },
    )?;
    if let Some(record) = ctx.accounts.funding_record.as_mut() {
        let bump = ctx
            .bumps
            .funding_record
            .ok_or(WagonError::FundingRecordNotCanonical)?;
        // Rent de las cuentas de esta sesión que existen en el init y un terminal cierra:
        // sesión + hucha USDC + registro, MEDIDO (la hucha USDC la crea el cliente en la
        // misma tx). Las huchas de pata nacen en la tx de cada swap y entran solo en el
        // reembolso EFECTIVO del terminal (`FundingRefunded.lamports`).
        let lamports_refundable = ctx
            .accounts
            .deposit_session
            .to_account_info()
            .lamports()
            .saturating_add(ctx.accounts.session_usdc_escrow.lamports())
            .saturating_add(record.to_account_info().lamports());
        let refund_to = ctx.accounts.refund_to.key();
        record.session = session_key;
        record.payer = payer_pk;
        record.refund_to = refund_to;
        record.generation = generation;
        record.kind = FUNDING_KIND_DEPOSIT;
        record.lamports_refundable = lamports_refundable;
        record.lamports_sunk = 0;
        record.created_at = now;
        record.bump = bump;
        record.exit_service_usdc = 0; // PR 5B: solo el retiro lo usa
        record._reserved = [0u8; 8];
        emit!(FundingRecorded {
            session: session_key,
            vault: ctx.accounts.vault.key(),
            payer: payer_pk,
            refund_to,
            generation,
            kind: FUNDING_KIND_DEPOSIT,
            lamports_refundable,
            lamports_sunk: 0,
        });
    }

    // ---- Ceremonia USDC §3.5: servicio S (argumento firmado por el inversor) ---
    // No toca ninguna cuenta del vault: la foto m2m de arriba sigue válida. Con S > 0 la
    // tesorería opcional de la comisión de entrada pasa a ser OBLIGATORIA (es la misma
    // ATA, D5) y debe ser pagable. Atómico con el init: si algo revierte, no hay cargo.
    {
        let cfg = &ctx.accounts.service_config;
        service::check_service(sponsored, args.service_usdc, cfg.max_for(SERVICE_KIND_DEPOSIT), cfg.paused)?;
        if args.service_usdc > 0 {
            let treasury_ai = ctx
                .accounts
                .fee_treasury_usdc_ata
                .as_ref()
                .ok_or(WagonError::MissingEntryFeeAccounts)?;
            let charged = service::charge_service_usdc(
                &ctx.accounts.protocol,
                args.service_usdc,
                &service::ServiceAccounts {
                    user: &ctx.accounts.investor.to_account_info(),
                    user_usdc_ata: &ctx.accounts.investor_usdc_ata.to_account_info(),
                    treasury_usdc_ata: &treasury_ai.to_account_info(),
                    token_program: &ctx.accounts.token_program.to_account_info(),
                },
            )?;
            emit!(ServiceCharged {
                user: investor_pk,
                vault: ctx.accounts.vault.key(),
                kind: SERVICE_KIND_DEPOSIT,
                amount_usdc: charged,
                generation,
                op_account: session_key,
            });
        }
    }

    // ---- Advance protocol total_tvl optimistically ------------------------
    // We've already taken the USDC from the investor; account for it now so
    // a concurrent init from another investor sees the post-add cap. Sube I (lo
    // que entra en la cesta), no D: E nunca es TVL. deposit_abort resta la misma I
    // (`session.amount_usdc`) if the session never settles.
    let protocol = &mut ctx.accounts.protocol;
    protocol.total_tvl_usdc = protocol
        .total_tvl_usdc
        .checked_add(capital_usdc)
        .ok_or(WagonError::MathOverflow)?;

    // DT-E: `EntryFeeCharged` ya no se emite aquí: E solo se COBRA al asentar (deposit_settle).

    emit!(DepositInitiated {
        vault: ctx.accounts.vault.key(),
        investor: investor_pk,
        // I = D − E, el capital contra el que se acuñan las participaciones (como el «neto» del #55).
        // E se descuenta de D; su desglose sale en EntryFeeCharged / EntryFeeDiverted del settle.
        amount_usdc: capital_usdc,
        tvl_before,
        total_shares_before,
        leg_count: allocation_count,
        legs_pre_completed: legs_completed,
    });

    Ok(())
}
