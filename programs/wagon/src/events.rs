//! Anchor events emitted by the program. Clients (and indexers) subscribe to these
//! to build on-chain history without scraping transactions.

use anchor_lang::prelude::*;

#[event]
pub struct ProtocolInitialized {
    pub authority: Pubkey,
    pub usdc_mint: Pubkey,
    pub tvl_cap_usdc: u64,
    pub liquidity_floor_usdc: u64,
}

#[event]
pub struct VaultCreated {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub nonce: u64,
    pub performance_fee_bps: u16,
    pub max_slippage_bps: u16,
    pub allocation_count: u8,
}

// Capa 5: the legacy `Deposit` and `Withdraw` events were removed alongside
// the monolithic instructions they served. Off-chain indexers should
// subscribe to the new event family (DepositInitiated/DepositSwapExecuted/
// DepositCompleted/DepositAborted and the Withdraw* counterparts).

// H-2: `ManagementFeeHarvested` was removed together with the
// `harvest_management_fee` instruction (management fee retired; it never
// emitted on mainnet — the handler was a stub).

#[event]
pub struct Rebalanced {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub new_allocation_count: u8,
}

#[event]
pub struct VaultClosed {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub ts: i64,
}

#[event]
pub struct VaultFinalized {
    pub vault: Pubkey,
    pub ts: i64,
}

/// Emitted once per successful `sweep_to_usdc` leg during liquidation.
/// Indexers can use this to reconstruct the liquidation path slot-by-slot.
#[event]
pub struct SweptToUsdc {
    pub vault: Pubkey,
    pub token_index: u8,
    pub mint: Pubkey,
    pub amount_in: u64,
    pub usdc_out: u64,
}

/// Ceremonia #39 (C-A Pieza 4): un token FUERA DE TABLA del vault (p. ej. dejado
/// por un restructure abortado tras compras) se vendió a USDC vía
/// `rescue_untracked_token`. `floor_enforced` = si se aplicó el piso de
/// valor-oráculo (mint con feed) o si fue la vía authority-only.
#[event]
pub struct UntrackedTokenRescued {
    pub vault: Pubkey,
    pub mint: Pubkey,
    pub amount_in: u64,
    pub usdc_out: u64,
    pub floor_enforced: bool,
}

/// Ceremonia #39 (C-B): una pata de retiro se pagó EN ESPECIE al inversor (los
/// tokens de su hucha van a su propia ATA), en vez de venderse a USDC — vía
/// `withdraw_claim_leg_in_kind`. `by_third_party` = si lo disparó un tercero tras
/// el timeout de 24 h (el valor va SIEMPRE al inversor, nunca al caller). El
/// indexer debe añadir este kind al historial (mismo hueco que tuvo SweptToUsdc).
#[event]
pub struct WithdrawLegClaimedInKind {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub leg_index: u8,
    pub mint: Pubkey,
    pub amount: u64,
    pub by_third_party: bool,
}

#[event]
pub struct VaultPauseChanged {
    pub vault: Pubkey,
    pub paused: bool,
}

#[event]
pub struct ProtocolPauseChanged {
    pub paused: bool,
}

#[event]
pub struct TvlCapChanged {
    pub old_cap: u64,
    pub new_cap: u64,
}

#[event]
pub struct LiquidityFloorChanged {
    pub old_floor: u64,
    pub new_floor: u64,
}

#[event]
pub struct RebalanceSwap {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub source_index: u8,
    pub dest_index: u8,
    pub source_mint: Pubkey,
    pub dest_mint: Pubkey,
    pub amount_in: u64,
    pub amount_out: u64,
}

/// Retirada del AllowedMintRegistry (2026-07-03): el registro muerto se
/// cierra vía admin y su rent vuelve a la autoridad. Los eventos antiguos
/// (Initialized/Added/Removed) se eliminaron junto con sus instrucciones.
#[event]
pub struct AllowedMintRegistryClosed {
    pub authority: Pubkey,
    pub lamports_recovered: u64,
}

// ─── Upgrade #30: FeedRegistry (TVL mark-to-market) ─────────────────────────

#[event]
pub struct FeedRegistryInitialized {
    pub authority: Pubkey,
}

#[event]
pub struct FeedSet {
    pub mint: Pubkey,
    pub feed_id: [u8; 32],
    pub flags: u8,
    pub registry_count_after: u16,
}

#[event]
pub struct FeedRemoved {
    pub mint: Pubkey,
    pub registry_count_after: u16,
}

#[event]
pub struct TvlMarked {
    pub vault: Pubkey,
    pub old_tvl_usdc: u64,
    pub new_tvl_usdc: u64,
}

#[event]
pub struct M2mEnforcementChanged {
    pub enforced: bool,
}

// ─── Upgrade #31: cambio de estrategia ──────────────────────────────────────

#[event]
pub struct RestructureStarted {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub old_count: u8,
    pub new_count: u8,
}

#[event]
pub struct RestructureLegExecuted {
    pub vault: Pubkey,
    /// 0 = venta de saliente, 1 = compra de entrante.
    pub kind: u8,
    pub index: u8,
    pub amount_in: u64,
    pub amount_out: u64,
}

#[event]
pub struct VaultRestructured {
    pub vault: Pubkey,
    pub old_count: u8,
    pub new_count: u8,
    pub tvl_after_usdc: u64,
}

#[event]
pub struct RestructureAborted {
    pub vault: Pubkey,
    pub caller: Pubkey,
    pub stranded_buys: bool,
}

// ─── Ceremonia #53: valor fuera de tabla ───────────────────────────────────
/// El vault entró en CUARENTENA (bandera stranded a 1) porque una operación dejó
/// valor fuera de tabla. `producer`: 0 = restructure_abort con compras varadas,
/// 1 = withdraw_sweep_batch de un mint eliminado. La ENTRADA queda vetada hasta limpiar.
#[event]
pub struct StrandedValueQuarantined {
    pub vault: Pubkey,
    pub caller: Pubkey,
    pub producer: u8,
}

/// La bandera stranded volvió a 0: el valor fuera de tabla se rescató y la ENTRADA
/// se reabre. `by_authority`: false = close_stranded permissionless (P2-3),
/// true = admin_clear_stranded (P2-4 / backstop).
#[event]
pub struct StrandedValueCleared {
    pub vault: Pubkey,
    pub caller: Pubkey,
    pub by_authority: bool,
}

// ─── Capa 5: fractional deposit/withdraw events ────────────────────────────

#[event]
pub struct DepositInitiated {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub amount_usdc: u64,
    pub tvl_before: u64,
    pub total_shares_before: u64,
    pub leg_count: u8,
    /// Bits already marked at init (USDC-as-allocation legs, zero-weight slots).
    pub legs_pre_completed: u16,
}

#[event]
pub struct DepositSwapExecuted {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub leg_index: u8,
    pub usdc_in: u64,
    pub tokens_out: u64,
}

#[event]
pub struct DepositCompleted {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub usdc_in: u64,
    pub shares_minted: u64,
    pub tvl_before_usdc: u64,
    pub tvl_after_usdc: u64,
}

#[event]
pub struct DepositAborted {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub amount_usdc_refunded: u64,
}

/// Upgrade #31 (F2b): one escrow ATA drained and closed. `to_vault` tells
/// the direction — true for the settle path, false for an abort refund.
#[event]
pub struct DepositEscrowSwept {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub leg_index: u8,
    pub amount: u64,
    pub to_vault: bool,
}

#[event]
pub struct WithdrawInitiated {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub shares_to_burn: u64,
    pub usdc_slice_from_vault: u64,
    pub tvl_before: u64,
    pub total_shares_before: u64,
    pub leg_count: u8,
    pub legs_pre_completed: u16,
}

#[event]
pub struct WithdrawSwapExecuted {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub leg_index: u8,
    pub tokens_in: u64,
    pub usdc_out: u64,
}

#[event]
pub struct WithdrawCompleted {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub shares_burned: u64,
    pub usdc_out_to_user: u64,
    pub performance_fee_usdc: u64,
    pub profit_realised_usdc: i64,
}

#[event]
pub struct WithdrawAborted {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub shares_restored: u64,
}

/// C2 (ceremonia #38): one withdraw token-escrow ATA drained and closed. The
/// destination is always the vault; `aborting` tells the direction — false on
/// the normal settle path (escrow was empty), true on the deshacer-total path
/// (escrow held the unsold slice, returned to the vault).
#[event]
pub struct WithdrawEscrowSwept {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub leg_index: u8,
    pub amount: u64,
    pub aborting: bool,
}

// Entry fee (front-load) — accrue-and-claim, 2026-06-30

#[event]
pub struct EntryFeeParamsChanged {
    pub bps: u16,
    pub cap_usdc: u64,
    pub exempt_below_usdc: u64,
    pub protocol_share_bps: u16,
}

#[event]
pub struct EntryFeeCharged {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub investor: Pubkey,
    pub fee_usdc: u64,
    pub creator_cut_usdc: u64,
    pub protocol_cut_usdc: u64,
}

#[event]
pub struct CreatorRewardsClaimed {
    pub creator: Pubkey,
    pub amount_usdc: u64,
}

/// Upgrade #35 -- parámetros del fee de creación de vault cambiados (admin).
#[event]
pub struct VaultCreationFeeParamsChanged {
    pub fee_usd_micros: u64,
    pub treasury: Pubkey,
}

/// Upgrade #35 -- fee de creación cobrado (SOL del creador -> tesorería).
#[event]
pub struct VaultCreationFeeCharged {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub lamports: u64,
    pub fee_usd_micros: u64,
}

/// Ceremonia #46 — parámetros de la comisión de rebalanceo cambiados (admin).
#[event]
pub struct RebalanceFeeParamsChanged {
    pub fee_usd_micros: u64,
    pub treasury: Pubkey,
}

/// Ceremonia #46 — comisión de rebalanceo / cambio de cesta cobrada (SOL del
/// creador -> tesorería), en `rebalance` o `restructure_init`.
#[event]
pub struct RebalanceFeeCharged {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub lamports: u64,
    pub fee_usd_micros: u64,
}

/// Ceremonia #37 -- umbral del guard de pérdida por compra cambiado (admin).
#[event]
pub struct SwapMaxLossChanged {
    pub max_loss_bps: u16,
}
