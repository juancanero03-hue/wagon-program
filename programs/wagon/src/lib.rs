//! Wagon — Solana vault marketplace program.
//!
//! See README.md for architecture, fee model, lifecycle, and roadmap.
//!
//! Module map:
//!   - constants    — protocol-wide constants, PDA seeds, fee bounds.
//!   - errors       — `WagonError` enum (stable numbering).
//!   - events       — Anchor events emitted by handlers.
//!   - jupiter      — Jupiter v6 CPI helper (`SwapPlan`, `invoke_jupiter_swap`).
//!   - pricing      — upgrade #30: last-swap price cache + m2m valuation utils.
//!   - state        — account definitions (ProtocolConfig, VaultState, UserPosition).
//!   - instructions — one module per entrypoint, all re-exported below.

use anchor_lang::prelude::*;

pub mod constants;
pub mod errors;
pub mod events;
pub mod instructions;
pub mod jupiter;
pub mod metaplex;
pub mod state;
pub mod pricing;
pub mod guards;
pub mod token_io;
pub mod remaining;

use instructions::*;

// Program ID. Fresh keypair generated 2026-04-24 for devnet deployment
// (also used for mainnet-beta — same on-chain program, progressive TVL cap).
// Source keypair stored outside the repo: wagon-devnet-keypair.json.
// Mainnet upgrade authority will be transferred to the Squads multisig vault
// (Wagon Protocol, 2-of-3) before the 50k TVL cap is raised.
declare_id!("2kZqCjGfKgVR8dUkv4PCogFsFgN3EoSSNX41HN1cBfBA");

#[program]
pub mod wagon {
    use super::*;

    // ---- init / lifecycle ---------------------------------------------------

    pub fn initialize_protocol(ctx: Context<InitializeProtocol>) -> Result<()> {
        instructions::initialize::handler(ctx)
    }

    pub fn create_vault(ctx: Context<CreateVault>, args: CreateVaultArgs) -> Result<()> {
        instructions::create_vault::handler(ctx, args)
    }

    // ---- investor actions (Capa 5: fractional deposit/withdraw) ------------
    //
    // The legacy monolithic `deposit` and `withdraw` were retired in upgrade
    // #20. Each high-level action is now driven by 4 entrypoints:
    //   init       → lock funds, snapshot state, create session PDA
    //   swap_batch → run 1-3 Jupiter swaps (called N times until all legs done)
    //   settle     → finalise (mint/transfer/burn shares), close session
    //   abort      → rollback if no leg has executed yet
    //
    // The frontend assembles the sequence and submits all txs in a single
    // `signAllTransactions` so the user sees one wallet approval.

    pub fn deposit_init(ctx: Context<DepositInit>, args: DepositInitArgs) -> Result<()> {
        instructions::deposit_init::handler(ctx, args)
    }

    pub fn deposit_swap_batch<'info>(
        ctx: Context<'_, '_, '_, 'info, DepositSwapBatch<'info>>,
        args: DepositSwapBatchArgs,
    ) -> Result<()> {
        instructions::deposit_swap_batch::handler(ctx, args)
    }

    /// Upgrade #31 (F2b): drains session escrow ATAs — to the vault once
    /// all swaps completed (permissionless), or back to the investor on
    /// the abort path (investor any time; anyone after 30 min).
    pub fn deposit_sweep_batch<'info>(
        ctx: Context<'_, '_, '_, 'info, DepositSweepBatch<'info>>,
        args: DepositSweepBatchArgs,
    ) -> Result<()> {
        instructions::deposit_sweep_batch::handler(ctx, args)
    }

    pub fn deposit_settle(ctx: Context<DepositSettle>) -> Result<()> {
        instructions::deposit_settle::handler(ctx)
    }

    pub fn deposit_abort(ctx: Context<DepositAbort>) -> Result<()> {
        instructions::deposit_abort::handler(ctx)
    }

    /// Ceremonia #50 (A5): salida fail-open del contador de comprometidas ante
    /// un freeze externo que atasca el asiento. Permissionless, CERO CPI.
    pub fn deposit_force_release(
        ctx: Context<DepositForceRelease>,
        args: DepositForceReleaseArgs,
    ) -> Result<()> {
        instructions::deposit_force_release::handler(ctx, args)
    }

    pub fn withdraw_init<'info>(
        ctx: Context<'_, '_, '_, 'info, WithdrawInit<'info>>,
        args: WithdrawInitArgs,
    ) -> Result<()> {
        instructions::withdraw_init::handler(ctx, args)
    }

    pub fn withdraw_swap_batch<'info>(
        ctx: Context<'_, '_, '_, 'info, WithdrawSwapBatch<'info>>,
        args: WithdrawSwapBatchArgs,
    ) -> Result<()> {
        instructions::withdraw_swap_batch::handler(ctx, args)
    }

    /// C2 (ceremonia #38): drains the withdraw session's per-token escrows back
    /// to the vault — settle direction once every leg sold (permissionless), or
    /// abort direction returning the unsold slices (investor any time; anyone
    /// after 30 min). `withdraw_settle` / `withdraw_abort` then finish.
    pub fn withdraw_sweep_batch<'info>(
        ctx: Context<'_, '_, '_, 'info, WithdrawSweepBatch<'info>>,
        args: WithdrawSweepBatchArgs,
    ) -> Result<()> {
        instructions::withdraw_sweep_batch::handler(ctx, args)
    }

    /// Ceremonia #39 (C-B): paga EN ESPECIE al inversor una pata de retiro que no
    /// se puede vender (sustituye a la renuncia). Da salida a sesiones
    /// comprometidas sin depender del vault ni del creador.
    pub fn withdraw_claim_leg_in_kind<'info>(
        ctx: Context<'_, '_, '_, 'info, WithdrawClaimLegInKind<'info>>,
        args: WithdrawClaimLegInKindArgs,
    ) -> Result<()> {
        instructions::withdraw_claim_leg_in_kind::handler(ctx, args)
    }

    pub fn withdraw_settle(ctx: Context<WithdrawSettle>) -> Result<()> {
        instructions::withdraw_settle::handler(ctx)
    }

    pub fn withdraw_abort(ctx: Context<WithdrawAbort>) -> Result<()> {
        instructions::withdraw_abort::handler(ctx)
    }

    /// Creator claims accrued entry-fee rewards from their per-creator rewards
    /// vault into their wallet (accrue-and-claim, pump.fun-style).
    pub fn claim_creator_rewards(ctx: Context<ClaimCreatorRewards>) -> Result<()> {
        instructions::claim_creator_rewards::handler(ctx)
    }

    // ---- creator actions ----------------------------------------------------

    pub fn rebalance(
        ctx: Context<Rebalance>,
        new_mints: Vec<Pubkey>,
        new_weights_bps: Vec<u16>,
    ) -> Result<()> {
        instructions::rebalance::handler(ctx, new_mints, new_weights_bps)
    }

    pub fn rebalance_swap<'info>(
        ctx: Context<'_, '_, '_, 'info, RebalanceSwapCtx<'info>>,
        source_index: u8,
        dest_index: u8,
        swap_plan: jupiter::SwapPlan,
    ) -> Result<()> {
        instructions::rebalance_swap::handler(ctx, source_index, dest_index, swap_plan)
    }

    pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
        instructions::close_vault::handler(ctx)
    }

    pub fn sweep_to_usdc<'info>(
        ctx: Context<'_, '_, '_, 'info, SweepToUsdc<'info>>,
        token_index: u8,
        swap_plan: jupiter::SwapPlan,
    ) -> Result<()> {
        instructions::sweep_to_usdc::handler(ctx, token_index, swap_plan)
    }

    /// Ceremonia #39 (C-A, Pieza 4): vende a USDC un token FUERA DE TABLA del
    /// vault (residuo de un restructure abortado tras compras). Salida para
    /// fondos que hoy quedan inalcanzables por todos los caminos.
    pub fn rescue_untracked_token<'info>(
        ctx: Context<'_, '_, '_, 'info, RescueUntrackedToken<'info>>,
        swap_plan: jupiter::SwapPlan,
    ) -> Result<()> {
        instructions::rescue_untracked_token::handler(ctx, swap_plan)
    }

    pub fn finalize_close<'info>(
        ctx: Context<'_, '_, '_, 'info, FinalizeClose<'info>>,
    ) -> Result<()> {
        instructions::finalize_close::handler(ctx)
    }

    // ---- protocol admin (Squads multisig) -----------------------------------

    /// Retirada del AllowedMintRegistry (2026-07-03): el registro llevaba
    /// muerto desde que el gating pasó al FeedRegistry/liquidez — esta
    /// instrucción admin lo cierra y devuelve el rent a la autoridad (Squads).
    /// Las antiguas init/add/remove_allowed_mint se eliminaron del programa.
    pub fn close_allowed_mint_registry(ctx: Context<CloseAllowedMintRegistry>) -> Result<()> {
        instructions::admin::close_allowed_mint_registry_handler(ctx)
    }

    // ---- upgrade #30: FeedRegistry (TVL mark-to-market) ---------------------

    pub fn init_feed_registry(ctx: Context<InitFeedRegistry>) -> Result<()> {
        instructions::init_feed_registry::handler(ctx)
    }

    pub fn set_feed(
        ctx: Context<SetFeed>,
        mint: Pubkey,
        feed_id: [u8; 32],
        flags: u8,
    ) -> Result<()> {
        instructions::set_feed::handler(ctx, mint, feed_id, flags)
    }

    pub fn remove_feed(ctx: Context<RemoveFeed>, mint: Pubkey) -> Result<()> {
        instructions::remove_feed::handler(ctx, mint)
    }

    pub fn cache_alloc_decimals(ctx: Context<CacheAllocDecimals>) -> Result<()> {
        instructions::cache_alloc_decimals::handler(ctx)
    }

    pub fn mark_tvl(ctx: Context<MarkTvl>) -> Result<()> {
        instructions::mark_tvl::handler(ctx)
    }

    pub fn set_m2m_enforced(ctx: Context<ProtocolAdmin>, enforced: bool) -> Result<()> {
        instructions::admin::set_m2m_enforced_handler(ctx, enforced)
    }

    pub fn set_entry_fee(
        ctx: Context<ProtocolAdmin>,
        bps: u16,
        cap_usdc: u64,
        exempt_below_usdc: u64,
        protocol_share_bps: u16,
    ) -> Result<()> {
        instructions::admin::set_entry_fee_handler(
            ctx,
            bps,
            cap_usdc,
            exempt_below_usdc,
            protocol_share_bps,
        )
    }

    pub fn set_vault_creation_fee(
        ctx: Context<ProtocolAdmin>,
        fee_usd_micros: u64,
        treasury: Pubkey,
    ) -> Result<()> {
        instructions::admin::set_vault_creation_fee_handler(ctx, fee_usd_micros, treasury)
    }

    /// Ceremonia #46: fija la comisión de rebalanceo / cambio de cesta (0 = off).
    pub fn set_rebalance_fee(
        ctx: Context<ProtocolAdmin>,
        fee_usd_micros: u64,
        treasury: Pubkey,
    ) -> Result<()> {
        instructions::admin::set_rebalance_fee_handler(ctx, fee_usd_micros, treasury)
    }

    /// Ceremonia #37: umbral del guard de pérdida máxima por compra (0 = off).
    pub fn set_swap_max_loss(ctx: Context<ProtocolAdmin>, max_loss_bps: u16) -> Result<()> {
        instructions::admin::set_swap_max_loss_handler(ctx, max_loss_bps)
    }

    // ---- upgrade #31: cambio de estrategia ----------------------------------

    pub fn restructure_init(ctx: Context<RestructureInit>, args: RestructureInitArgs) -> Result<()> {
        instructions::restructure_init::handler(ctx, args)
    }

    pub fn restructure_swap_batch<'info>(
        ctx: Context<'_, '_, '_, 'info, RestructureSwapBatch<'info>>,
        args: RestructureSwapBatchArgs,
    ) -> Result<()> {
        instructions::restructure_swap_batch::handler(ctx, args)
    }

    pub fn restructure_settle(ctx: Context<RestructureSettle>) -> Result<()> {
        instructions::restructure_settle::handler(ctx)
    }

    pub fn restructure_abort(ctx: Context<RestructureAbort>) -> Result<()> {
        instructions::restructure_abort::handler(ctx)
    }

    pub fn extend_feed_registry(ctx: Context<ExtendFeedRegistry>, extra_entries: u16) -> Result<()> {
        instructions::extend_feed_registry::handler(ctx, extra_entries)
    }

    pub fn set_tvl_cap(ctx: Context<ProtocolAdmin>, new_cap_usdc: u64) -> Result<()> {
        instructions::admin::set_tvl_cap_handler(ctx, new_cap_usdc)
    }

    pub fn set_liquidity_floor(ctx: Context<ProtocolAdmin>, new_floor_usdc: u64) -> Result<()> {
        instructions::admin::set_liquidity_floor_handler(ctx, new_floor_usdc)
    }

    pub fn pause_protocol(ctx: Context<ProtocolAdmin>) -> Result<()> {
        instructions::admin::pause_protocol_handler(ctx)
    }

    pub fn unpause_protocol(ctx: Context<ProtocolAdmin>) -> Result<()> {
        instructions::admin::unpause_protocol_handler(ctx)
    }

    pub fn pause_vault(ctx: Context<AdminVaultPause>) -> Result<()> {
        instructions::admin::pause_vault_handler(ctx)
    }

    pub fn unpause_vault(ctx: Context<AdminVaultUnpause>) -> Result<()> {
        instructions::admin::unpause_vault_handler(ctx)
    }
}
