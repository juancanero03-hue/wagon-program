//! `deposit_force_release` — Ceremonia #50 (A5): salida FAIL-OPEN del contador
//! de depósitos comprometidos cuando un FREEZE externo atasca el asiento.
//!
//! # El problema (A5)
//!
//! `committed_deposits` / `pending_committed_shares` (#43/#44) suben en
//! `deposit_sweep_batch` (primer barrido settle) y SOLO bajan en
//! `deposit_settle`. Una sesión COMPROMETIDA (legs_swept != 0, aborting == 0)
//! no puede abortar (`deposit_abort.rs:108-111`), así que el asiento es su
//! ÚNICA salida — y puede REVERTIR por un freeze de una freeze authority
//! externa (Circle en USDC; el emisor de un token de la cesta):
//!   - CAMINO 1: una pata de la cesta congelada → su barrido revierte → nunca
//!     `fully_swept()` → `deposit_settle` exige `fully_swept()` → no asienta.
//!   - CAMINO 2: `vault_usdc_ata` o el escrow USDC congelado → el transfer/close
//!     del residual de `deposit_settle` revierte.
//! Con el contador clavado, `close_vault`/`restructure_init`/`rebalance` quedan
//! vetados → el vault no se puede cerrar ni reestructurar, para siempre.
//!
//! # La cura (donación, freeze-inmune, CERO CPI)
//!
//! Ix PERMISSIONLESS que, tras un TIMEOUT y una PRUEBA DE FREEZE ligada al
//! bloqueador EXACTO, resta los DOS contadores (espejo exacto del +P del sweep,
//! con el MISMO `phantom_shares` sobre los mismos campos inmutables) y pone
//! `session.aborting = 1`. NO acuña, NO lee oráculo, NO hace ningún CPI (no
//! lleva token_program ni ATAs transferibles → imposible tocar una cuenta
//! congelada). Las patas ya barridas al vault quedan DONADAS a los holders
//! (autolesión del depositante, jamás robo); la sesión queda ABIERTA para que
//! el `deposit_abort`/sweep-abort existente recupere el escrow segregado al
//! inversor si (cuando) se descongela. Decisiones de Juan (2026-08-07): timeout
//! 7 días, prueba de freeze OBLIGATORIA, depositante PIERDE, sin
//! `rescue_session_escrow`, `total_tvl_usdc` se deja sobre-contado (inocuo, cap
//! retirado). Diseño: `dev/docs/DISENO-A5-FREEZE-CONTADOR-2026-08-07.md`.

use anchor_lang::prelude::*;
use anchor_spl::token::spl_token;

use crate::constants::{DEPOSIT_SESSION_SEED, LIQUIDATION_TIMEOUT_SECONDS, PROTOCOL_SEED};
use crate::errors::WagonError;
use crate::guards::VaultGuard;
use crate::state::vault_layout as vlayout;
use crate::state::{DepositSession, ProtocolConfig};
use crate::token_io::{
    derive_live_ata, read_token_amount, read_token_state, verify_token_account, TOKEN_STATE_FROZEN,
};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct DepositForceReleaseArgs {
    /// CAMINO 1 (sesión NO totalmente barrida): índice de la pata bloqueada
    /// cuyo escrow o ATA destino está congelado. IGNORADO en CAMINO 2.
    pub leg_index: u8,
}

#[derive(Accounts)]
pub struct DepositForceRelease<'info> {
    /// Paga la fee; jamás recibe nada. Permissionless.
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: pinneado a `session.investor` vía has_one. No recibe nada aquí
    /// (la ix no hace CPI); es la semilla del PDA de la sesión.
    pub investor: UncheckedAccount<'info>,

    /// CHECK: PDA + owner verificados con `VaultGuard::load`; se le escriben los
    /// dos contadores byte-level.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

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
    )]
    pub deposit_session: Box<Account<'info, DepositSession>>,

    #[account(seeds = [PROTOCOL_SEED], bump = protocol.bump)]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// CHECK: mint del token bloqueado (USDC en CAMINO 2; `leg_mints[leg_index]`
    /// en CAMINO 1). Solo-lectura; su OWNER selecciona el token program para la
    /// derivación canónica de la ATA.
    pub proof_mint: UncheckedAccount<'info>,

    /// CHECK: la ATA CONGELADA que prueba que el asiento está bloqueado.
    /// Verificada canónica (= escrow o destino de la pata/USDC) y `Frozen` en el
    /// handler. Lectura pura, inmune al propio freeze.
    pub frozen_account: UncheckedAccount<'info>,

    /// CHECK: el escrow USDC de la sesión (ATA canónica de (session, usdc)).
    /// SOLO se verifica/usa en CAMINO 2, para exigir `residual_usdc > 0` (con
    /// saldo 0 el `close_account` de una ATA congelada puede NO revertir → no
    /// sería un brick real).
    pub session_usdc_escrow: UncheckedAccount<'info>,
}

pub fn handler(ctx: Context<DepositForceRelease>, args: DepositForceReleaseArgs) -> Result<()> {
    // ---- Vault guard (owner + PDA; NO retiene el borrow) --------------------
    let vault_ai = ctx.accounts.vault.to_account_info();
    let _guard = VaultGuard::load(&vault_ai, &ctx.accounts.vault.key(), WagonError::VaultPaused)?;

    let session = &ctx.accounts.deposit_session;

    // ---- Gate 1: COMPROMETIDA ----------------------------------------------
    // Espejo EXACTO del veto del aborto (deposit_abort.rs:108-111) y del
    // predicado del incremento (deposit_sweep_batch.rs:277, `legs_swept 0→≠0`
    // en dirección settle): es justo el conjunto que subió el contador y no lo
    // ha bajado. Fuera de él, la sesión no está comprometida y NO hay contador
    // que liberar (o el aborto normal ya la resuelve).
    require!(
        session.legs_swept != 0 && session.aborting == 0,
        WagonError::DepositForceReleaseNotEligible
    );

    // ---- Gate 2: TIMEOUT (cinturón; la prueba de freeze es el discriminador) -
    let now = Clock::get()?.unix_timestamp;
    require!(
        now.saturating_sub(session.created_at) > LIQUIDATION_TIMEOUT_SECONDS,
        WagonError::DepositForceReleaseNotEligible
    );

    // ---- Gate 3: PRUEBA DE FREEZE ligada al bloqueador EXACTO ----------------
    // Make-or-break (revisión adversarial): una comprometida NO congelada la
    // asienta CUALQUIERA con el sweep+settle permissionless → NO está atascada →
    // forzar la donación sería griefing. Por eso la prueba se ata al bit/cuenta
    // exacta que bloquea el asiento, y exige que esté REALMENTE `Frozen`.
    let session_key = session.key();
    let vault_key = ctx.accounts.vault.key();
    let proof_mint = ctx.accounts.proof_mint.key();
    let frozen_ai = ctx.accounts.frozen_account.to_account_info();
    let frozen_key = ctx.accounts.frozen_account.key();

    require!(
        read_token_state(&frozen_ai)? == TOKEN_STATE_FROZEN,
        WagonError::DepositForceReleaseNotFrozen
    );

    if session.fully_swept() {
        // CAMINO 2: barrida entera; solo el transfer/close del USDC residual del
        // settle puede bloquear. proof_mint == USDC; el escrow debe tener residual
        // > 0; y la cuenta congelada es el `vault_usdc_ata` o el escrow USDC.
        require_keys_eq!(
            proof_mint,
            ctx.accounts.protocol.usdc_mint,
            WagonError::DepositForceReleaseNotFrozen
        );
        let escrow_ai = ctx.accounts.session_usdc_escrow.to_account_info();
        require_keys_eq!(
            escrow_ai.key(),
            derive_live_ata(&session_key, &proof_mint, &spl_token::ID),
            WagonError::EscrowAtaMismatch
        );
        verify_token_account(&escrow_ai, &proof_mint, &session_key)?;
        require!(
            read_token_amount(&escrow_ai)? > 0,
            WagonError::DepositForceReleaseNotFrozen
        );
        let vault_usdc = {
            let data = vault_ai.try_borrow_data()?;
            vlayout::read_usdc_ata(&data)?
        };
        require!(
            frozen_key == vault_usdc || frozen_key == escrow_ai.key(),
            WagonError::DepositForceReleaseNotFrozen
        );
    } else {
        // CAMINO 1: una pata barrible-no-barrida congelada → el asiento nunca
        // llega a `fully_swept()`. La prueba se ata al escrow o al destino-vault
        // canónico de ESA pata exacta.
        let leg = args.leg_index as usize;
        require!(
            leg < session.leg_count as usize,
            WagonError::LegIndexOutOfRange
        );
        let bit = 1u16 << args.leg_index;
        require!(
            (session.legs_completed & bit) != 0
                && (session.trivial_mask & bit) == 0
                && (session.legs_swept & bit) == 0,
            WagonError::DepositForceReleaseNotFrozen
        );
        let leg_mint = session.leg_mints[leg];
        require_keys_eq!(proof_mint, leg_mint, WagonError::DepositForceReleaseNotFrozen);
        let token_prog_id = *ctx.accounts.proof_mint.to_account_info().owner;
        let escrow_ata = derive_live_ata(&session_key, &leg_mint, &token_prog_id);
        let vault_dest = derive_live_ata(&vault_key, &leg_mint, &token_prog_id);
        require!(
            frozen_key == escrow_ata || frozen_key == vault_dest,
            WagonError::DepositForceReleaseNotFrozen
        );
    }

    // ---- Efecto: liberar los contadores (fail-open) + latch aborting --------
    // Resta el MISMO par (committed, pending) que sumó el barrido de commit, con
    // el MISMO `phantom_shares` sobre los MISMOS campos inmutables de la sesión
    // → espejo exacto, sin almacenar P. `saturating_sub` (nunca envuelve).
    let p = vlayout::phantom_shares(
        session.amount_usdc,
        session.total_shares_before,
        session.tvl_before,
    );
    {
        let mut data = vault_ai.try_borrow_mut_data()?;
        let cur = vlayout::read_committed_deposits(&data)?;
        vlayout::write_committed_deposits(&mut data, cur.saturating_sub(1))?;
        let cur_pending = vlayout::read_pending_committed_shares(&data)?;
        vlayout::write_pending_committed_shares(&mut data, cur_pending.saturating_sub(p))?;
    }

    // Latch `aborting = 1`: las patas ya barridas quedan DONADAS al vault (NAV de
    // los holders); la sesión NO se cierra, para que el `deposit_abort`/sweep-abort
    // existente recupere el escrow segregado al inversor si se descongela.
    let session = &mut ctx.accounts.deposit_session;
    session.aborting = 1;

    Ok(())
}
