//! Global protocol singleton. PDA seeds: `[b"protocol"]`.
//! Holds authority (Squads multisig), fee splits, caps, pause flag.

use anchor_lang::prelude::*;

#[account]
pub struct ProtocolConfig {
    /// Squads v4 multisig that owns admin ops and is the share recipient
    /// of the protocol's 40% management / 10% performance splits.
    pub authority: Pubkey,

    /// USDC mint used across the protocol. Frozen after init.
    pub usdc_mint: Pubkey,

    /// Destination ATA for protocol fee revenue (owned by the Squads multisig).
    pub treasury_usdc_ata: Pubkey,

    /// Total Value Locked cap across all vaults, in USDC atomic units (6 decimals).
    /// Enforced on every deposit. Raised post-audit by admin op.
    pub tvl_cap_usdc: u64,

    /// Minimum Jupiter-routable liquidity a token must have to be added to any
    /// vault allocation. Enforced off-chain by the frontend; on-chain we rely
    /// on per-swap slippage to reject illiquid routes.
    pub liquidity_floor_usdc: u64,

    /// Annualised management fee in basis points. 100 = 1%.
    pub management_fee_bps: u16,

    /// Split of the management fee. Protocol 4000, creator 6000.
    pub mgmt_fee_protocol_share_bps: u16,
    pub mgmt_fee_creator_share_bps: u16,

    /// Split of the performance fee. Protocol 1000, creator 9000.
    pub perf_fee_protocol_share_bps: u16,
    pub perf_fee_creator_share_bps: u16,

    /// Allowed range for the performance fee a creator can choose on a new vault.
    pub min_perf_fee_bps: u16,
    pub max_perf_fee_bps: u16,

    /// Max basket size. 10 at v0.1. Can be raised in a future program version.
    pub max_tokens_per_vault: u8,

    /// Global pause. When set, deposits / create_vault / rebalance all revert.
    /// Withdrawals remain open — users can always exit.
    pub paused: bool,

    /// Monotonic counter for stats and client-side vault enumeration fallback.
    pub vault_count: u64,

    /// Aggregate TVL across all active vaults, in USDC atomic units.
    /// Best-effort cache; updated on deposit/withdraw. Authoritative only after
    /// `accrue_management_fee` has been touched on all vaults.
    pub total_tvl_usdc: u64,

    /// Last time admin touched a setting. For audit log.
    pub last_admin_action_ts: i64,

    /// PDA bump.
    pub bump: u8,

    /// Upgrade #30: when 1, deposit_init requires the mark-to-market
    /// account set (FeedRegistry + ATAs + price updates) and refuses the
    /// legacy stored-TVL path. Flipped by admin once the frontend ships
    /// the oracle crank. Carved from byte 0 of the former reserved tail,
    /// so existing accounts read 0 (= not enforced) with no migration.
    pub m2m_enforced: u8,

    /// Entry fee (front-load) — accrue-and-claim. Carved from the reserved
    /// tail, so existing accounts read 0 (= fee OFF) with no migration.
    /// Set together via `set_entry_fee` (admin / Squads).
    pub entry_fee_bps: u16,
    pub entry_fee_cap_usdc: u64,
    pub entry_fee_exempt_below_usdc: u64,
    pub entry_fee_protocol_share_bps: u16,

    /// Upgrade #35: vault-creation fee. Denominated in micro-USD (6 dec,
    /// 1_500_000 = 1.50 USD) and charged in SOL at the oracle SOL/USD rate
    /// at creation time. 0 = fee OFF. Carved from the reserved tail, so the
    /// existing mainnet account reads 0 / all-zero pubkey with no migration.
    /// Set together via `set_vault_creation_fee` (admin / Squads).
    pub vault_creation_fee_usd_micros: u64,
    /// Destination system account for the creation fee (the Squads vault --
    /// the protocol's SOL treasury). Validated in create_vault iff fee > 0.
    pub vault_creation_fee_treasury: Pubkey,

    /// Ceremonia #37 (2026-07-09): guard de pérdida máxima por COMPRA en los
    /// swaps — piso de valor-oráculo por leg (`valor_oraculo(recibido) ≥
    /// usdc_gastado × (1 − bps/10000)`). 0 = guard APAGADO (comportamiento
    /// pre-#37). Carved from the reserved tail, so the existing mainnet
    /// account reads 0 with no migration. Set via `set_swap_max_loss`
    /// (admin / Squads). Los init lo SELLAN en la sesión (Deposit/Restructure)
    /// para que las sesiones en vuelo al encenderlo no queden atrapadas.
    pub swap_max_loss_bps: u16,

    /// Ceremonia #46: comisión de rebalanceo / cambio de cesta. En micro-USD
    /// (1_000_000 = 1,00 USD), cobrada en SOL al tipo del oráculo SOL/USD en
    /// `rebalance` y `restructure_init`. 0 = apagada. Tallada de la cola
    /// `reserved`, así que la cuenta viva de mainnet lee 0 (apagada) sin
    /// migración. Se fija vía `set_rebalance_fee` (admin / Squads).
    pub rebalance_fee_usd_micros: u64,
    /// Ceremonia #46: destino del SOL de la comisión de rebalanceo (la tesorería
    /// del protocolo -- el vault Squads). Campo DEDICADO (NO reusa el de
    /// creación) para no acoplar las dos palancas: apagar la comisión de creación
    /// nunca debe tumbar el cobro del rebalanceo. Cuenta viva lee Pubkey::default().
    /// Validado en rebalance/restructure_init sii la comisión > 0.
    pub rebalance_fee_treasury: Pubkey,

    /// Reserved for forward compatibility without breaking account layout.
    pub reserved: [u8; 25],
}

impl ProtocolConfig {
    /// Byte size of the account data. Used with `#[account(init, space = ProtocolConfig::LEN)]`.
    pub const LEN: usize = 8  // discriminator
        + 32 + 32 + 32        // authority, usdc_mint, treasury_usdc_ata
        + 8 + 8               // tvl_cap_usdc, liquidity_floor_usdc
        + 2                   // management_fee_bps
        + 2 + 2               // mgmt splits
        + 2 + 2               // perf splits
        + 2 + 2               // min/max perf fee bps
        + 1                   // max_tokens_per_vault
        + 1                   // paused
        + 8                   // vault_count
        + 8                   // total_tvl_usdc
        + 8                   // last_admin_action_ts
        + 1                   // bump
        + 1                   // m2m_enforced
        + 2                   // entry_fee_bps
        + 8                   // entry_fee_cap_usdc
        + 8                   // entry_fee_exempt_below_usdc
        + 2                   // entry_fee_protocol_share_bps
        + 8                   // vault_creation_fee_usd_micros (upgrade #35)
        + 32                  // vault_creation_fee_treasury (upgrade #35)
        + 2                   // swap_max_loss_bps (ceremonia #37)
        + 8                   // rebalance_fee_usd_micros (ceremonia #46)
        + 32                  // rebalance_fee_treasury (ceremonia #46)
        + 25; // reserved
}
