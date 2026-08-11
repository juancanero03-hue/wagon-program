//! `DepositSession` — intermediate state for the fractional-deposit flow
//! introduced in upgrade #20 (Capa 5), with per-session segregated escrow
//! since upgrade #31 (F2b).
//!
//! # Lifecycle
//!
//! Created by `deposit_init`, mutated by zero-or-more `deposit_swap_batch`
//! calls, drained by `deposit_sweep_batch`, and closed by either
//! `deposit_settle` (success) or `deposit_abort` (rollback). Each `(vault,
//! investor)` pair can have at most one open session at a time — the PDA
//! seeds make collisions impossible.
//!
//! # Segregated escrow (upgrade #31, F2b)
//!
//! Before #31 the investor's USDC moved into the vault's USDC ATA at init
//! and the swap outputs landed directly in the vault's allocation ATAs.
//! That meant an unfinished ("orphan") session left half-bought tokens
//! inside the vault with no shares minted against them — distorting the
//! mark-to-market TVL for everyone else, blocking aborts after the first
//! swap, and (after a restructure) stranding funds entirely.
//!
//! Since #31 every session owns its own escrow: USDC is locked in an ATA
//! owned by the session PDA, every Jupiter route is quoted with
//! `userPublicKey = session PDA`, and the swap outputs land in
//! session-owned ATAs. The vault never holds a single lamport of an
//! unsettled deposit:
//!   - `deposit_sweep_batch` (settle direction) moves escrow → vault once
//!     ALL swaps completed; permissionless, so anyone can finish an
//!     abandoned-but-complete session.
//!   - `deposit_sweep_batch` (abort direction) moves escrow → investor for
//!     incomplete or stale sessions; the investor any time, anyone after
//!     `DEPOSIT_SESSION_TIMEOUT_SECS`.
//!   - `deposit_settle` / `deposit_abort` finish the bookkeeping and close
//!     the session + USDC escrow, refunding rent to the investor.
//!
//! # `legs_completed` / `legs_swept` bitmaps
//!
//! u16 bitmaps, bit `i` set means leg `i` has been swap'd / swept. Cap of
//! 16 legs per vault matches MAX_TOKENS_PER_VAULT comfortably (today 10).
//! Batches can come in any order; bits dedupe double-execution.

use anchor_lang::prelude::*;

use crate::constants::MAX_TOKENS_PER_VAULT;

/// After this many seconds, an unfinished deposit session can be aborted
/// (escrow → investor) by ANYONE, not just the investor. Same philosophy
/// as `RESTRUCTURE_ABORT_TIMEOUT_SECS`: no session may hold the protocol
/// hostage. The funds always go back to the investor, never to the caller.
pub const DEPOSIT_SESSION_TIMEOUT_SECS: i64 = 30 * 60;

#[account]
#[derive(Default)]
pub struct DepositSession {
    /// The investor who opened this session. Swap batches and pre-timeout
    /// aborts require their signature; sweeps in the settle direction and
    /// post-timeout aborts are permissionless but always pay out to them.
    pub investor: Pubkey,

    /// The vault this deposit is targeting. Pinned at init so the user
    /// can't accidentally drain a different vault by swapping vault
    /// accounts in subsequent calls.
    pub vault: Pubkey,

    /// USDC amount the investor committed at `deposit_init`. This is the
    /// number the `swap_batch` calls slice by `weight_bps` and the
    /// `settle` call uses to mint shares.
    pub amount_usdc: u64,

    /// Snapshot of `vault.total_shares` taken at init. Used at settle to
    /// price shares against the pre-deposit valuation, so mid-deposit
    /// price movements don't distort the share/USDC ratio.
    pub total_shares_before: u64,

    /// Snapshot of `vault.tvl_last_computed_usdc` at init. Same purpose
    /// as `total_shares_before` — fixes the price the investor pays at
    /// the moment they committed, not at the moment swap_batches finish.
    pub tvl_before: u64,

    /// Snapshot of `vault.aggregate_cost_basis_usdc` at init. Used at
    /// settle to advance the cost basis monotonically without races.
    pub agg_cost_before: u64,

    /// Vault's `allocation_count` at init. Pinned so a mid-flight admin
    /// vault edit (if we ever add one) can't desync the session's
    /// expectation of how many legs to execute.
    pub leg_count: u8,

    /// Bitmap of completed legs. Bit `i` set ⇒ leg `i` has had its
    /// Jupiter swap executed (or was pre-marked trivial at init).
    /// `deposit_settle` requires `legs_completed == (1 << leg_count) - 1`.
    pub legs_completed: u16,

    /// Unix timestamp at init. Drives the permissionless-abort TTL and the
    /// stale-after-restructure check.
    pub created_at: i64,

    /// PDA bump for `[DEPOSIT_SESSION_SEED, vault, investor]`.
    pub bump: u8,

    /// Upgrade #31 (F2b): bitmap of swept legs. Bit `i` set ⇒ leg `i`'s
    /// escrow ATA has been drained (to the vault on the settle path, to
    /// the investor on the abort path) and closed.
    pub legs_swept: u16,

    /// Upgrade #31 (F2b): 1 once the abort path has started. Blocks any
    /// further `deposit_swap_batch` / settle-direction sweeps so a session
    /// can never mix refunds with deposits.
    pub aborting: u8,

    /// Upgrade #31 (F2b): bits pre-marked at init for USDC-as-allocation
    /// or zero-weight slots — legs that never swap and never have an
    /// escrow ATA. Snapshotted here (instead of being reconstructed from
    /// the live vault table) so aborts keep working even after the vault
    /// restructured to a different basket.
    pub trivial_mask: u16,

    /// Upgrade #31 (F2b): the allocation mints at init, leg-indexed.
    /// Binds each escrow ATA to its leg without trusting the CURRENT
    /// vault table — which may have changed if the vault restructured
    /// mid-session. Slots ≥ leg_count are Pubkey::default().
    pub leg_mints: [Pubkey; MAX_TOKENS_PER_VAULT],

    /// Ceremonia #37: umbral del guard de pérdida por compra, SELLADO desde
    /// `protocol.swap_max_loss_bps` en `deposit_init`. Los swap_batch lo leen
    /// de aquí (no llevan la cuenta protocol) — y las sesiones creadas ANTES
    /// de encender el guard llevan 0, así que completar una operación en
    /// vuelo nunca queda atrapada por el encendido. Carved from _reserved.
    pub max_loss_bps: u16,

    /// Ceremonia #39 (S-4): valor-oráculo REALMENTE recibido, acumulado pata a
    /// pata (`received_value` que el guard del #37 ya calcula, en átomos de USDC
    /// 6 dec). `deposit_settle` acuña sobre `min(este + residual_usdc, amount_usdc)`
    /// en vez de sobre el USDC bruto, así quien enrute su swap contra su propio
    /// pool cobra participaciones solo por lo que llegó de verdad. Carved from
    /// _reserved; ningún offset previo se mueve. Ver `value_tracked`.
    pub received_value_acc: u64,

    /// Ceremonia #39 (S-4): 1 sii el guard iba sellado ON al init
    /// (`max_loss_bps > 0`) — sin guard no hay oráculo enhebrado y no existe
    /// medición posible. Cinturón anti-legacy: una sesión abierta ANTES del
    /// upgrade #39 lleva `_reserved` a ceros ⇒ lee 0 ⇒ `deposit_settle` usa la
    /// fórmula legacy exacta (nunca destruye el dinero de una sesión en vuelo).
    pub value_tracked: u8,

    /// Reserved for forward-compatibility. Always written as zeroes.
    pub _reserved: [u8; 5],
}

impl DepositSession {
    /// 8 (Anchor disc) + 32 + 32 + 8 + 8 + 8 + 8 + 1 + 2 + 8 + 1
    /// + 2 + 1 + 2 + 32*MAX_TOKENS_PER_VAULT + 2 (max_loss_bps)
    /// + 8 (received_value_acc, S-4) + 1 (value_tracked, S-4) + 5 (_reserved)
    /// = 457 bytes. LEN SIN CAMBIO respecto al #38 (2+14 == 2+8+1+5): las
    /// piezas S-4 se carvan del _reserved, ningún offset previo se mueve y el
    /// parser del frontend (DEPOSIT_SESSION_LEN = 457) queda intacto.
    pub const LEN: usize = 8
        + 32
        + 32
        + 8
        + 8
        + 8
        + 8
        + 1
        + 2
        + 8
        + 1
        + 2
        + 1
        + 2
        + 32 * MAX_TOKENS_PER_VAULT
        + 2
        + 8
        + 1
        + 5;

    /// True iff every leg has been executed. Used by `deposit_settle`.
    pub fn is_complete(&self) -> bool {
        self.legs_completed == self.full_mask()
    }

    /// Bitmap with one bit set per leg.
    pub fn full_mask(&self) -> u16 {
        if self.leg_count >= 16 {
            u16::MAX
        } else {
            (1u16 << self.leg_count) - 1
        }
    }

    /// Legs that actually hold escrowed tokens and must be swept before
    /// the session can close: completed AND not trivial.
    pub fn sweepable_mask(&self) -> u16 {
        self.legs_completed & !self.trivial_mask
    }

    /// True iff every escrow token ATA this session created has been
    /// drained and closed (in whichever direction).
    pub fn fully_swept(&self) -> bool {
        (self.sweepable_mask() & !self.legs_swept) == 0
    }
}
