//! `deposit_abort` — rollback of the fractional deposit flow.
//!
//! Upgrade #31 (F2b) rewrote this around the per-session escrow. Before,
//! abort was only possible if NO swap had executed (the funds were already
//! mixed into the vault); orphan sessions with partial swaps were stuck,
//! and a restructure could strand them forever. Now the session's funds
//! never touch the vault until settle, so abort works at ANY stage:
//!
//!   1. If swaps executed, `deposit_sweep_batch` first returns each leg's
//!      escrowed TOKENS to the investor (in kind — reversing the swaps
//!      would mean another round of slippage) and flags the session
//!      `aborting`, which blocks the swap/settle paths for good.
//!   2. This instruction then refunds whatever USDC remains in the escrow
//!      (DT-E: including the entry fee E reserved there at init — a deposit
//!      that never settles pays no fee; the service fee S is not refunded),
//!      closes the escrow ATA and the session (rent → `refund_target`: the
//!      investor, or the sponsor's `refund_to` when a `FundingRecord` is
//!      paired, ceremonia USDC §3.3), and reverses the optimistic
//!      `protocol.total_tvl_usdc` bump from init. G2-b: si la hucha está
//!      CONGELADA o la cuenta USDC del inversor no puede recibir, el reembolso
//!      se APLAZA (fail-open): la hucha se queda abierta con su saldo y su rent
//!      (`DepositAbortDeferred` + `FundingRefundPartial`), la sesión cierra igual
//!      y `deposit_escrow_reclaim` devuelve el USDC cuando se pueda mover.
//!
//! Authorization: the investor at any time; ANYONE after
//! `DEPOSIT_SESSION_TIMEOUT_SECS` (10 min) — abandoned sessions can always
//! be cleaned up, and the funds can only ever go to the investor.
//!
//! Guard against mixing paths: if any settle-direction sweep already moved
//! tokens INTO the vault (`legs_swept != 0` while not `aborting`), abort is
//! refused — that session is committed and must settle (which is
//! permissionless, so it can always be driven to completion).
//!
//! G3-B1a (decisión 3 de Juan, 16-oct-2026): si la cuenta USDC canónica del inversor no existe, este abort la
//! CREA (idempotente) y la paga con el rent de la hucha que cierra en la misma instrucción (el caller solo
//! adelanta y recupera); solo si hay USDC que devolver y la hucha se puede mover. +2 cuentas al final
//! (`associated_token_program`, `usdc_mint`): la forma anterior cae en 3005.

use anchor_lang::prelude::*;
use anchor_spl::associated_token::{self, AssociatedToken, Create};
use anchor_spl::token::{self, spl_token, CloseAccount, Token, Transfer};

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::{DepositAbortDeferred, DepositAborted, FundingRefundPartial};
use crate::state::deposit_session::DEPOSIT_SESSION_TIMEOUT_SECS;
use crate::state::{DepositSession, ProtocolConfig, FUNDING_KIND_DEPOSIT};
use crate::token_io::{derive_live_ata, is_payable_usdc_ata, read_token_state, verify_token_account, TOKEN_STATE_FROZEN};

#[derive(Accounts)]
pub struct DepositAbort<'info> {
    /// The investor any time; anyone after the timeout. Pays fees only.
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: pinned to `session.investor` via has_one. Receives the USDC
    /// refund (into their canonical USDC ATA). The rent goes to
    /// `refund_target` (the investor unless the session is sponsored, §3.3).
    #[account(mut)]
    pub investor: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// CHECK: PDA seeds + owner verified manually (VaultGuard). The vault never held
    /// this session's funds; G2-b lo hace `mut` SOLO para drenar `committed_deposits`
    /// cuando aborta una sesión con todas las patas triviales (que sumó +1 en su init).
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    /// CHECK: SPL Token account, mint == usdc_mint, owner == investor.
    #[account(mut)]
    pub investor_usdc_ata: UncheckedAccount<'info>,

    /// CHECK: Upgrade #31 (F2b). The session's USDC escrow ATA, verified by
    /// canonical derivation. Fully refunded to the investor and closed here;
    /// its rent lands on the session PDA (D1) and leaves with the session.
    /// G2-b: si está CONGELADA (o el destino no puede recibir) se deja ABIERTA con
    /// su saldo para `deposit_escrow_reclaim` y la sesión se cierra igual (fail-open).
    #[account(mut)]
    pub session_usdc_escrow: UncheckedAccount<'info>,

    /// Closed at the end of this ix; its whole balance flows to `refund_target`.
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
    pub system_program: Program<'info, System>,

    /// G3-B1a (decisión 3 de Juan, 16-oct-2026): para CREAR la cuenta USDC canónica del inversor si falta (la paga
    /// el rent de la hucha que se cierra; el caller solo adelanta y recupera en la misma instrucción). Forma
    /// anterior (11 cuentas): 3005.
    pub associated_token_program: Program<'info, AssociatedToken>,

    /// CHECK: el mint USDC del protocolo (`protocol.usdc_mint`, atado en el handler); solo sirve para crear esa cuenta.
    pub usdc_mint: UncheckedAccount<'info>,
}

pub fn handler(ctx: Context<DepositAbort>) -> Result<()> {
    let session = &ctx.accounts.deposit_session;
    // G3-B1a: saldo del PDA de la sesión al entrar (cinturón del reembolso del adelanto, abajo).
    let session_lamports_inicio = ctx.accounts.deposit_session.to_account_info().lamports();

    // ---- Vault identity (any status — abort works mid-restructure too) ----
    let vault_ai = ctx.accounts.vault.to_account_info();
    let _guard = crate::guards::VaultGuard::load(
        &vault_ai,
        &ctx.accounts.vault.key(),
        WagonError::VaultPaused,
    )?;

    // ---- Authorization ------------------------------------------------------
    let now = Clock::get()?.unix_timestamp;
    let timed_out = now.saturating_sub(session.created_at) > DEPOSIT_SESSION_TIMEOUT_SECS;
    require!(
        ctx.accounts.caller.key() == session.investor || timed_out,
        WagonError::DepositAbortTooEarly
    );

    // ---- Path-mixing guards -------------------------------------------------
    // (a) A session whose tokens were already swept INTO the vault is
    //     committed: it must settle (permissionless), never abort.
    require!(
        session.aborting == 1 || session.legs_swept == 0,
        WagonError::SessionAlreadyStarted
    );
    // (b) Every leg with escrowed tokens must have been returned to the
    //     investor first (abort-direction sweeps). For a session where no
    //     swap ever ran, this is vacuously true.
    if session.aborting == 1 {
        require!(session.fully_swept(), WagonError::EscrowNotSwept);
    } else {
        // No sweeps happened at all: only legal if no non-trivial swap ran.
        require!(
            session.legs_completed == session.trivial_mask,
            WagonError::SessionAlreadyStarted
        );
    }

    // ---- Validate refund accounts ------------------------------------------
    let usdc_mint_pk = ctx.accounts.protocol.usdc_mint;
    let investor_pk = ctx.accounts.investor.key();
    require_keys_eq!(ctx.accounts.usdc_mint.key(), usdc_mint_pk, WagonError::InvalidJupiterRoute);
    // G3-B1a: la cuenta USDC del inversor puede NO existir todavía (se crea más abajo si hace falta). Si existe,
    // tiene que ser una cuenta USDC suya (canónica o no, como siempre); si falta, SOLO la canónica (6212): el
    // caller no elige dónde se crea.
    let investor_ata_ai = ctx.accounts.investor_usdc_ata.to_account_info();
    let investor_ata_missing = investor_ata_ai.data_is_empty();
    if investor_ata_missing {
        require_keys_eq!(
            investor_ata_ai.key(),
            derive_live_ata(&investor_pk, &usdc_mint_pk, &spl_token::ID),
            WagonError::InvestorUsdcAtaNotCanonical
        );
    } else {
        verify_token_account(&investor_ata_ai, &usdc_mint_pk, &investor_pk)?;
    }

    let session_key = session.key();
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

    // ---- Refund the escrowed USDC and close the escrow ----------------------
    let vault_key = ctx.accounts.vault.key();
    let session_bump_arr = [session.bump];
    let session_seeds: &[&[u8]] = &[
        DEPOSIT_SESSION_SEED,
        vault_key.as_ref(),
        investor_pk.as_ref(),
        &session_bump_arr,
    ];
    let session_signer: &[&[&[u8]]] = &[session_seeds];

    let escrow_ai = ctx.accounts.session_usdc_escrow.to_account_info();
    let refund_usdc = crate::token_io::read_token_amount(&escrow_ai)?;
    // ---- G2-b (revisión N3, MED): FAIL-OPEN, espejo del settle de DT-E -------------------
    // Si la hucha está CONGELADA (Circle), ni el transfer ni el close pasan (el close de una
    // cuenta congelada revierte aunque esté a 0); si la cuenta USDC del inversor no puede
    // recibir, el transfer revierte. Antes eso dejaba la sesión abierta PARA SIEMPRE y, con una
    // sesión trivial comprometida (abajo), `committed_deposits` clavado: vault vetado para la
    // entrada, el rebalanceo, el cambio de cesta y el cierre. Ahora la sesión se cierra igual y
    // el USDC se queda en la hucha (ABIERTA, con su rent), de donde lo recupera
    // `deposit_escrow_reclaim` (permissionless, a la ATA canónica del inversor; el rent de la
    // hucha va entonces al inversor, como en DT-E) en cuanto se pueda mover. Nada se pierde: se
    // aplaza. Lecturas PURAS (nunca revierten); el `verify_token_account` de arriba ya ató
    // mint y dueño de las dos cuentas.
    let escrow_frozen = read_token_state(&escrow_ai)? == TOKEN_STATE_FROZEN;
    // ---- G3-B1a (decisión 3 de Juan, 16-oct; patrón de la decisión 4 en `deposit_sweep_batch`) --------------------
    // Si la cuenta USDC canónica del inversor no existe y hay USDC que devolver desde una hucha que SÍ se puede
    // mover, la crea el programa (idempotente, por el programa de ATAs) con el caller como pagador PROVISIONAL: lo
    // adelantado vuelve a su bolsillo al final de la instrucción, del rent de la hucha que se cierra aquí mismo
    // (misma mint, mismo programa de token, mismo tamaño). Sirve para cualquier caller: el inversor, el robot o un
    // tercero pasados los 10 min. Hasta aquí la escotilla esperaba a que alguien se la creara. Con la hucha
    // CONGELADA no se crea nada: el abort se aplaza igual que antes (no habría rent con que pagarla) y
    // `deposit_escrow_reclaim` la exige después. La clave ya está atada a la derivación canónica (arriba).
    let caller_ai = ctx.accounts.caller.to_account_info();
    let mut adelantado: u64 = 0;
    if investor_ata_missing && !escrow_frozen && refund_usdc > 0 {
        let antes = caller_ai.lamports();
        associated_token::create_idempotent(CpiContext::new(
            ctx.accounts.associated_token_program.to_account_info(),
            Create {
                payer: caller_ai.clone(),
                associated_token: investor_ata_ai.clone(),
                authority: ctx.accounts.investor.to_account_info(),
                mint: ctx.accounts.usdc_mint.to_account_info(),
                system_program: ctx.accounts.system_program.to_account_info(),
                token_program: ctx.accounts.token_program.to_account_info(),
            },
        ))?;
        adelantado = antes.saturating_sub(caller_ai.lamports());
        verify_token_account(&investor_ata_ai, &usdc_mint_pk, &investor_pk)?;
    }
    let dest_payable = is_payable_usdc_ata(
        &ctx.accounts.investor_usdc_ata.to_account_info(),
        &usdc_mint_pk,
        Some(investor_pk),
    );
    let deferred = escrow_frozen || (refund_usdc > 0 && !dest_payable);
    if deferred {
        emit!(DepositAbortDeferred {
            vault: vault_key,
            investor: investor_pk,
            session: session_key,
            left_in_escrow_usdc: refund_usdc,
            reason: if escrow_frozen { 1 } else { 2 },
        });
        // La hucha se queda abierta: su rent no viaja con este reembolso (misma señal que el settle de
        // DT-E para la conciliación del sponsor, `FundingRefunded.lamports` ya la excluye).
        emit!(FundingRefundPartial {
            session: session_key,
            kind: FUNDING_KIND_DEPOSIT,
            session_generation: session.generation as u64,
            escrow: escrow_ai.key(),
            escrow_lamports: escrow_ai.lamports(),
        });
    } else {
        if refund_usdc > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from: escrow_ai.clone(),
                        to: ctx.accounts.investor_usdc_ata.to_account_info(),
                        authority: ctx.accounts.deposit_session.to_account_info(),
                    },
                    session_signer,
                ),
                refund_usdc,
            )?;
        }
        // D1 (§3.3): el rent de la hucha cae en el PDA de la sesión y sale con su cierre.
        token::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount {
                account: escrow_ai,
                destination: ctx.accounts.deposit_session.to_account_info(),
                authority: ctx.accounts.deposit_session.to_account_info(),
            },
            session_signer,
        ))?;
        // G3-B1a: devolver al caller lo adelantado por la cuenta nueva del inversor, del rent de la hucha que acaba
        // de caer en el PDA de la sesión (D1): misma mint, mismo programa de token y mismo tamaño, así que el PDA
        // acaba con, como poco, lo que tenía al empezar (lo exige el `require`: nunca paga de su propio rent) y
        // `settle_refund` (abajo) reparte el resto como siempre. Va DESPUÉS de la última CPI a propósito. En una
        // sesión patrocinada el `refund_to` deja de recibir exactamente ese rent (residual declarado, diseño G3 §9.1).
        if adelantado > 0 {
            let session_ai = ctx.accounts.deposit_session.to_account_info();
            let sesion_lamports = session_ai.lamports();
            let caller_lamports = caller_ai.lamports();
            require!(
                sesion_lamports.saturating_sub(session_lamports_inicio) >= adelantado,
                WagonError::MathOverflow
            );
            **session_ai.try_borrow_mut_lamports()? =
                sesion_lamports.checked_sub(adelantado).ok_or(WagonError::MathOverflow)?;
            **caller_ai.try_borrow_mut_lamports()? =
                caller_lamports.checked_add(adelantado).ok_or(WagonError::MathOverflow)?;
        }
    }

    // ---- Reverse the optimistic TVL bump from init -----------------------
    // F8 (ceremonia #40): `saturating_sub`, NUNCA `checked_sub`.
    // `protocol.total_tvl_usdc` es una CACHÉ agregada que se desincroniza sola:
    // `mark_tvl` y `restructure_settle` la reescriben con
    // `saturating_sub(old).saturating_add(new)` usando el TVL almacenado del
    // vault, `withdraw_settle` le resta el valor de salida medido y el cobro en
    // especie (`withdraw_claim_leg_in_kind`) saca valor del vault sin tocarla.
    // Medido en mainnet: el agregado y la suma vault a vault NO coinciden.
    // Con `checked_sub`, un agregado que haya derivado por debajo de este
    // importe hace REVERTIR el abort — es decir, la caché tendría derecho de
    // veto sobre la DEVOLUCIÓN DEL DINERO del inversor. Prioridad: que el
    // dinero salga siempre; que la caché se quede corta es inocuo (la corrige
    // el siguiente `mark_tvl`) y además es el lado conservador: subestimar el
    // TVL agregado solo puede dejar entrar depósitos, nunca robar nada.
    let amount_usdc = ctx.accounts.deposit_session.amount_usdc;
    let protocol = &mut ctx.accounts.protocol;
    protocol.total_tvl_usdc = protocol.total_tvl_usdc.saturating_sub(amount_usdc);

    // ---- Ceremonia USDC (§3.3): reparto del rent temporal --------------------
    // Registro emparejado → `refund_to` (o la authority); si no, el inversor. Valida
    // `refund_target` antes de que Anchor cierre la sesión hacia él al salir.
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

    // ---- G2-b (F1B-02): drenar el contador de una sesión trivial comprometida ----------
    // Drenaje ÚNICO compartido con `deposit_settle` (`DepositSession::drain_committed_if_trivial`, espejo
    // exacto del +1 de `deposit_init`; cinturón de Kairo en el #63: un test fija que estas dos son las únicas
    // salidas de la sesión y que ambas lo llaman). Las sesiones con patas barridas al vault no llegan aquí
    // (veto de arriba): las drena `deposit_settle`.
    {
        let mut data = vault_ai.try_borrow_mut_data()?;
        session.drain_committed_if_trivial(&mut data)?;
    }

    emit!(DepositAborted {
        vault: ctx.accounts.vault.key(),
        investor: investor_pk,
        // G2-b: 0 si el reembolso quedó APLAZADO en la hucha (ver `DepositAbortDeferred`).
        amount_usdc_refunded: if deferred { 0 } else { refund_usdc },
    });

    Ok(())
}
