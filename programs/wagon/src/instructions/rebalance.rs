//! `rebalance` — creator-only. Updates allocation WEIGHTS on the vault's
//! existing mint set. This is a metadata-only commit: no swaps execute here.
//!
//! The actual token-shuffling happens in the sibling `rebalance_swap`
//! instruction, one Jupiter leg per call. Splitting keeps each transaction
//! comfortably under Solana's 1232-byte size limit.
//!
//! # Constraints
//!   - Caller must equal `vault.creator`.
//!   - Protocol must not be paused.
//!   - Vault must be in `Active` status.
//!   - `new_mints` must exactly equal the current mint set, slot-by-slot. In
//!     v0.1 rebalance cannot add or remove mints — use `close_vault` +
//!     `create_vault` for a different universe. The parameter is kept in the
//!     signature so the frontend encoding doesn't change when this is relaxed
//!     in a later program version.
//!   - `new_weights_bps.len() == vault.allocation_count`.
//!   - Weights must sum to exactly `ALLOCATION_TOTAL_BPS` (10_000).
//!
//! # Fees
//!   Ceremonia #46: si `protocol.rebalance_fee_usd_micros > 0`, el handler cobra
//!   esa comisión al creador (en SOL, al oráculo SOL/USD) al inicio. 0 = apagada
//!   (comportamiento pre-#46). La performance fee se cobra en el retiro; no hay
//!   management fee (removida en H-2). El router fee de Jupiter va dentro de los
//!   swaps de `rebalance_swap`.

use anchor_lang::prelude::*;
use anchor_lang::system_program::{transfer, Transfer};

use crate::constants::{
    ALLOCATION_TOTAL_BPS, PROTOCOL_SEED, VAULT_CREATION_FEE_MAX_LAMPORTS, VAULT_SEED,
};
use crate::errors::WagonError;
use crate::events::{RebalanceFeeCharged, Rebalanced};
use crate::pricing;
use crate::state::{ProtocolConfig, VaultState, VaultStatus};

#[derive(Accounts)]
pub struct Rebalance<'info> {
    #[account(mut)]
    pub creator: Signer<'info>,

    #[account(
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        constraint = !protocol.paused @ WagonError::ProtocolPaused,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    #[account(
        mut,
        seeds = [
            VAULT_SEED,
            vault.creator.as_ref(),
            &vault.nonce.to_le_bytes(),
        ],
        bump = vault.bump,
        has_one = creator @ WagonError::UnauthorizedVaultCreator,
        constraint = vault.status() == VaultStatus::Active @ WagonError::VaultPaused,
    )]
    pub vault: Box<Account<'info, VaultState>>,

    /// Ceremonia #46: cuenta Pyth SOL/USD (`PriceUpdateV2`) para tasar la
    /// comisión de rebalanceo. Solo se lee si la comisión está encendida
    /// (`protocol.rebalance_fee_usd_micros > 0`). El frontend pasa la cuenta
    /// SOL/USD patrocinada por Pyth (la misma que usa create_vault).
    /// CHECK: ownership, feed id, frescura y confianza se validan en el handler
    /// vía `pricing::read_sol_usd_price`.
    pub sol_usd_price_update: UncheckedAccount<'info>,

    /// Ceremonia #46: destino del SOL de la comisión (la tesorería del protocolo).
    /// CHECK: debe ser igual a `protocol.rebalance_fee_treasury`; se exige en el
    /// handler sii la comisión > 0. Ignorada (cualquier writable) si la comisión = 0.
    #[account(mut)]
    pub rebalance_fee_treasury: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx: Context<Rebalance>,
    new_mints: Vec<Pubkey>,
    new_weights_bps: Vec<u16>,
) -> Result<()> {
    // ---- Ceremonia #49 (A3): no rebalancear con un depósito COMPROMETIDO ------
    // Coherencia con el veto de rebalance_swap (donde vive el robo real): rebalance
    // solo comitea pesos (metadata), pero vetarlo ANTES de cobrar la comisión evita
    // comitear pesos que rebalance_swap no podrá ejecutar, y calca restructure_init/
    // close_vault (#43). Fallar-CERRADO antes del fee. El depósito se drena por
    // deposit_settle (permissionless, exige Active). Read byte-level @666 antes de
    // tocar protocol/vault.
    {
        let ai = ctx.accounts.vault.to_account_info();
        let data = ai.try_borrow_data()?;
        require!(
            crate::state::vault_layout::read_committed_deposits(&data)? == 0,
            WagonError::VaultHasCommittedDeposit
        );
    }

    // ---- Ceremonia #46: comisión de rebalanceo (1 USD en SOL) ---------------
    // Mismo método que create_vault (#35): el importe vive en ProtocolConfig en
    // micro-USD y se cobra en SOL al tipo del oráculo SOL/USD del momento. 0 =
    // apagada (cuenta viva lee 0 -> no cobra y las 2 cuentas se ignoran). Se
    // cobra por INVOCACIÓN; un reintento tras un fallo de swap re-cobra (decisión
    // sellada 2026-08-02: se acepta la asimetría con restructure). Atómico: si
    // algo revierte después, el SOL vuelve.
    let fee_usd_micros = ctx.accounts.protocol.rebalance_fee_usd_micros;
    if fee_usd_micros > 0 {
        let expected_treasury = ctx.accounts.protocol.rebalance_fee_treasury;
        require_keys_neq!(
            expected_treasury,
            Pubkey::default(),
            WagonError::RebalanceFeeTreasuryMismatch
        );
        require_keys_eq!(
            ctx.accounts.rebalance_fee_treasury.key(),
            expected_treasury,
            WagonError::RebalanceFeeTreasuryMismatch
        );
        let fee_clock = Clock::get()?;
        let sol = pricing::read_sol_usd_price(
            &ctx.accounts.sol_usd_price_update.to_account_info(),
            &fee_clock,
        )?;
        let lamports = pricing::usd_micros_to_lamports(fee_usd_micros, &sol)?
            .min(VAULT_CREATION_FEE_MAX_LAMPORTS);
        if lamports > 0 {
            transfer(
                CpiContext::new(
                    ctx.accounts.system_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.creator.to_account_info(),
                        to: ctx.accounts.rebalance_fee_treasury.to_account_info(),
                    },
                ),
                lamports,
            )?;
            emit!(RebalanceFeeCharged {
                vault: ctx.accounts.vault.key(),
                creator: ctx.accounts.creator.key(),
                lamports,
                fee_usd_micros,
            });
        }
    }

    let vault = &mut ctx.accounts.vault;
    let count = vault.allocation_count as usize;

    // ---- shape checks -------------------------------------------------------
    require_eq!(
        new_mints.len(),
        count,
        WagonError::RebalanceWeightsLengthMismatch
    );
    require_eq!(
        new_weights_bps.len(),
        count,
        WagonError::RebalanceWeightsLengthMismatch
    );

    // ---- mint set is immutable in v0.1 -------------------------------------
    // Slot-by-slot equality. Ordering matters because weights are positional;
    // the client is expected to pass mints in the same slot order as the
    // current allocation table.
    for i in 0..count {
        require_keys_eq!(
            new_mints[i],
            vault.allocations[i].mint,
            WagonError::RebalanceMintSetImmutable
        );
    }

    // ---- weight validation --------------------------------------------------
    let sum: u32 = new_weights_bps.iter().map(|w| *w as u32).sum();
    require_eq!(
        sum,
        ALLOCATION_TOTAL_BPS as u32,
        WagonError::AllocationSumMismatch
    );

    // Ceremonia #47 (H3): ninguna pata a peso 0. Este es el guarda PRINCIPAL de H3:
    // en rebalanceo el set de mints es INMUTABLE y NO se ejecuta venta, así que un 0%
    // aquí deja una pata FINANCIADA a peso 0 (conserva su saldo) que withdraw_init
    // saltaría como trivial → el que retira pierde su parte = confiscación. Iterar el
    // vec de entrada (ya validado len == allocation_count). `create_vault` NO chequea
    // (una pata creada a 0 nunca se financia; ver el comentario allí).
    for w in new_weights_bps.iter() {
        require!(*w >= 1, WagonError::ZeroWeightAllocation);
    }

    // ---- commit weights -----------------------------------------------------
    for i in 0..count {
        vault.allocations[i].weight_bps = new_weights_bps[i];
    }

    emit!(Rebalanced {
        vault: vault.key(),
        creator: vault.creator,
        new_allocation_count: vault.allocation_count,
    });

    Ok(())
}
