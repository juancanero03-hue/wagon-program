//! `rebalance_swap` — creator-only. Executes one Jupiter swap leg between
//! two of the vault's basket tokens (source slot → destination slot). Called
//! repeatedly — one call per leg — after `rebalance` has updated the target
//! weights, until the actual balances line up with the new allocation.
//!
//! # Flow
//!   1. Validate creator + vault status + slot indices.
//!   2. Validate the passed ATAs match `vault.allocations[i].vault_ata`.
//!   3. Snapshot `source_ata` balance (for the `amount_in` event field).
//!   4. Execute `invoke_jupiter_swap` with vault PDA as signer.
//!   5. Enforce `swap_plan.min_out` against the delta on `dest_ata`.
//!   6. Emit `RebalanceSwap`.
//!
//! # remaining_accounts layout
//!   Exactly the Jupiter route accounts required by `swap_plan.ix_data`.
//!   First account MUST be the destination ATA (so the helper can measure
//!   the balance delta for slippage enforcement). The caller arranges this
//!   off-chain; the handler just hands the slice to the helper.
//!
//! # Why separate from `rebalance`?
//!   - Solana tx size limit is 1232 bytes. One Jupiter route + its accounts
//!     is already large; stacking multiple legs in a single tx is infeasible
//!     for realistic basket shapes.
//!   - Each leg is idempotent and independently retriable. If one leg fails
//!     due to a transient RPC hiccup or slippage tightening, the creator can
//!     retry that leg alone without recomputing the whole rebalance.

use anchor_lang::prelude::*;
use anchor_spl::token::Token;

use crate::constants::{JUPITER_PROGRAM_ID, PROTOCOL_SEED, VAULT_SEED};
use crate::errors::WagonError;
use crate::events::RebalanceSwap;
use crate::jupiter::{check_min_out, invoke_jupiter_swap, SwapPlan};
use crate::state::{ProtocolConfig, VaultState, VaultStatus};

#[derive(Accounts)]
#[instruction(source_index: u8, dest_index: u8)]
pub struct RebalanceSwapCtx<'info> {
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

    /// Vault-owned ATA for the source mint. Validated in the handler against
    /// `vault.allocations[source_index].vault_ata`.
    /// CHECK: validated against the allocation entry in the handler.
    #[account(mut)]
    pub vault_source_ata: AccountInfo<'info>,

    /// Vault-owned ATA for the destination mint. Validated similarly.
    /// CHECK: validated against the allocation entry in the handler.
    #[account(mut)]
    pub vault_dest_ata: AccountInfo<'info>,

    /// CHECK: pubkey verified against `JUPITER_PROGRAM_ID` by the CPI helper.
    #[account(address = JUPITER_PROGRAM_ID)]
    pub jupiter_program: AccountInfo<'info>,

    pub token_program: Program<'info, Token>,
}

pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, RebalanceSwapCtx<'info>>,
    source_index: u8,
    dest_index: u8,
    swap_plan: SwapPlan,
) -> Result<()> {
    // ---- Ceremonia #49 (A3): no mover valor con un depósito COMPROMETIDO ------
    // Con un depósito comprometido en vuelo (tokens barridos al vault, shares sin
    // acuñar), un swap de una pata TRACKED al slot-USDC volcaría valor comprometido
    // a la USDC ociosa, que withdraw_init reparte con denominador CRUDO (sin la
    // fantasma P del #44) → un retiro concurrente sobre-extrae. rebalance_swap es el
    // ÚNICO camino que mueve valor comprometido a la USDC ociosa en Active (censo de
    // escritores de vault_usdc_ata verificado); vetar cierra la ventana en su fuente.
    // Mismo patrón/error que close_vault y restructure_init (#43); el depósito se
    // drena por deposit_settle (permissionless, exige Active, que este candado
    // preserva). Read byte-level @666 ANTES de cualquier borrow del vault.
    {
        let ai = ctx.accounts.vault.to_account_info();
        let data = ai.try_borrow_data()?;
        require!(
            crate::state::vault_layout::read_committed_deposits(&data)? == 0,
            WagonError::VaultHasCommittedDeposit
        );
    }

    // ---- 1. slot validation -------------------------------------------------
    require!(
        source_index != dest_index,
        WagonError::RebalanceSwapSameSlot
    );

    let vault = &ctx.accounts.vault;
    let count = vault.allocation_count as usize;
    let s_idx = source_index as usize;
    let d_idx = dest_index as usize;

    require!(
        s_idx < count && d_idx < count,
        WagonError::RebalanceSwapSlotOutOfRange
    );

    let src_alloc = vault.allocations[s_idx];
    let dst_alloc = vault.allocations[d_idx];
    require!(!src_alloc.is_empty(), WagonError::RebalanceSwapSlotOutOfRange);
    require!(!dst_alloc.is_empty(), WagonError::RebalanceSwapSlotOutOfRange);

    require_keys_eq!(
        ctx.accounts.vault_source_ata.key(),
        src_alloc.vault_ata,
        WagonError::InvalidJupiterRoute
    );
    require_keys_eq!(
        ctx.accounts.vault_dest_ata.key(),
        dst_alloc.vault_ata,
        WagonError::InvalidJupiterRoute
    );

    // ---- 2. snapshot source balance for the event --------------------------
    // We record the pre-swap source balance as `amount_in` (matches the
    // sweep_to_usdc pattern). The exact amount actually consumed by Jupiter
    // can be derived off-chain from post-tx balances if needed.
    let source_balance_before: u64 = {
        let data = ctx.accounts.vault_source_ata.try_borrow_data()?;
        // SPL TokenAccount layout: mint(32) | owner(32) | amount(u64 LE, offset 64)
        require!(data.len() >= 72, WagonError::InvalidJupiterRoute);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[64..72]);
        u64::from_le_bytes(bytes)
    };

    // ---- 3. build vault PDA signer seeds -----------------------------------
    let vault_key = vault.key();
    let dest_mint = dst_alloc.mint;
    let creator_pk = vault.creator;
    let nonce_le = vault.nonce.to_le_bytes();
    let vault_bump = vault.bump;
    let seeds: &[&[u8]] = &[VAULT_SEED, creator_pk.as_ref(), &nonce_le, &[vault_bump]];
    let signer_seeds: &[&[&[u8]]] = &[seeds];

    // ---- 4. execute CPI ----------------------------------------------------
    // Ceremonia #37: guard de pérdida por swap. Aquí no hay pivote USDC (es
    // token→token), así que el piso compara valor-oráculo contra valor-oráculo:
    //   valor(dest_recibido) ≥ valor(src_consumido) × (1 − max_loss)
    // El umbral se lee DIRECTO de ProtocolConfig (esta ix sí lleva la cuenta).
    // Con guard activo el layout de remaining es
    //   [FeedRegistry, ...oraculo_src, ...oraculo_dest, ...ruta_jupiter]
    // y con guard apagado (0) es la ruta a secas, como siempre.
    let max_loss_bps = ctx.accounts.protocol.swap_max_loss_bps;
    let remaining = ctx.remaining_accounts;
    let (guard, route) = if max_loss_bps > 0 {
        require!(!remaining.is_empty(), WagonError::SwapGuardAccountsMissing);
        let registry_ai = &remaining[0];
        let src_len =
            crate::pricing::guard_oracle_account_count(registry_ai, &src_alloc.mint)?;
        let dest_len =
            crate::pricing::guard_oracle_account_count(registry_ai, &dst_alloc.mint)?;
        require!(
            remaining.len() > 1 + src_len + dest_len,
            WagonError::SwapGuardAccountsMissing
        );
        let src_oracle = &remaining[1..1 + src_len];
        let dest_oracle = &remaining[1 + src_len..1 + src_len + dest_len];
        (
            Some((registry_ai, src_oracle, dest_oracle)),
            &remaining[1 + src_len + dest_len..],
        )
    } else {
        (None, remaining)
    };
    require!(!route.is_empty(), WagonError::InvalidJupiterRoute);

    let dest = &ctx.accounts.vault_dest_ata;

    // C3: jupiter.rs validates dest has the expected mint and vault-PDA owner.
    // C-A: declaradas = fuente y destino del rebalanceo (ambas validadas contra
    // la tabla de allocations arriba). Cualquier otra ATA del vault que aparezca
    // en la ruta no puede perder saldo.
    let declared = [
        ctx.accounts.vault_source_ata.key(),
        ctx.accounts.vault_dest_ata.key(),
    ];
    let delta = invoke_jupiter_swap(
        &ctx.accounts.jupiter_program,
        dest,
        &dest_mint,
        &vault_key,
        &vault_key,
        &declared,
        route,
        swap_plan.ix_data,
        signer_seeds,
    )?;
    check_min_out(delta, swap_plan.min_out)?;

    // Ceremonia #37: piso de valor con lo REALMENTE consumido del ATA fuente
    // (medido before/after, no declarado). Decimales de la caché del vault
    // (cache_alloc_decimals, permissionless) — fail-closed si faltan (H-4).
    if let Some((registry_ai, src_oracle, dest_oracle)) = guard {
        let source_balance_after: u64 = {
            let data = ctx.accounts.vault_source_ata.try_borrow_data()?;
            require!(data.len() >= 72, WagonError::InvalidJupiterRoute);
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&data[64..72]);
            u64::from_le_bytes(bytes)
        };
        let src_consumed = source_balance_before.saturating_sub(source_balance_after);
        // Pieza 5 (C-A): error temprano legible.
        require!(src_consumed > 0, WagonError::SwapSourceNotConsumed);
        let (src_dec, dest_dec) = {
            let vault_ai = ctx.accounts.vault.to_account_info();
            let data = vault_ai.try_borrow_data()?;
            (
                crate::state::vault_layout::read_alloc_decimals(&data, s_idx)?
                    .ok_or(error!(WagonError::NoReliablePrice))?,
                crate::state::vault_layout::read_alloc_decimals(&data, d_idx)?
                    .ok_or(error!(WagonError::NoReliablePrice))?,
            )
        };
        let clock = Clock::get()?;
        let spent_value = crate::pricing::guard_oracle_value(
            registry_ai,
            &src_alloc.mint,
            src_dec,
            src_consumed,
            src_oracle,
            &clock,
        )?;
        let received_value = crate::pricing::guard_oracle_value(
            registry_ai,
            &dst_alloc.mint,
            dest_dec,
            delta,
            dest_oracle,
            &clock,
        )?;
        crate::pricing::enforce_value_floor(received_value, spent_value, max_loss_bps)?;
    }

    // ---- 5. emit event -----------------------------------------------------
    emit!(RebalanceSwap {
        vault: vault.key(),
        creator: vault.creator,
        source_index,
        dest_index,
        source_mint: src_alloc.mint,
        dest_mint: dst_alloc.mint,
        amount_in: source_balance_before,
        amount_out: delta,
    });

    Ok(())
}
