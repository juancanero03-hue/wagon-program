//! `WithdrawSession` — fractional-withdraw counterpart of `DepositSession`.
//! See `deposit_session.rs` for the lifecycle rationale.
//!
//! Withdraw is the inverse of deposit. Since C2 (retiros concurrentes,
//! ceremonia #38) it uses per-session, per-token escrows — the exact mirror
//! of the deposit flow:
//!   - `withdraw_init` burns the shares and MOVES each allocation's pro-rata
//!     slice out of the vault into a session-owned escrow ATA (so the vault
//!     balance auto-reduces and a concurrent withdraw prices its own slice
//!     against the already-reduced pool — this is what closes C2).
//!   - `withdraw_swap_batch` sells each token escrow → the session's USDC
//!     escrow (signed by the SESSION, not the vault).
//!   - `withdraw_sweep_batch` drains every token escrow back to the vault
//!     (empty on the normal path, funded on the abort path) and closes it.
//!   - `withdraw_settle` pays the investor from the USDC escrow and closes it.
//!   - `withdraw_abort` re-mints the shares and returns the USDC escrow to the
//!     vault (deshacer-total).
//!
//! Notes on the snapshot fields:
//!   - `shares_to_burn` is the share amount the investor committed at init.
//!     The burn happens at init (so the user "spends" the shares irrevocably)
//!     and the cost-basis math at settle is driven by this number.
//!   - `usdc_slice_from_vault` is the investor's slice of the vault's idle
//!     USDC, reserved to the USDC escrow at init.
//!   - `total_shares_before` and `tvl_before` pin the valuation at init.
//!   - `leg_mints`, `legs_swept`, `trivial_mask`, `aborting` mirror
//!     `DepositSession`'s escrow bookkeeping (C2).

use anchor_lang::prelude::*;

use crate::constants::MAX_TOKENS_PER_VAULT;

/// C2 (hucha por token): once `withdraw_init` moves each token slice into a
/// session escrow, an UNCOMMITTED orphan session (`sold == 0`, never extracted
/// value) can be recovered — token escrows swept back to the vault, shares
/// re-minted — by ANYONE after this many seconds. Ceremonia #39 (C-B): once the
/// session has extracted value (`sold == 1`), the abort is VETOED — its terminal
/// is SETTLE, not re-mint; a third party finishes it via
/// `withdraw_claim_leg_in_kind` (after `WITHDRAW_INKIND_TIMEOUT_SECS`) +
/// permissionless settle. Same philosophy: no session holds the protocol hostage.
pub const WITHDRAW_SESSION_TIMEOUT_SECS: i64 = 30 * 60;

/// Ceremonia #39 (C-B): tras este tiempo, un TERCERO puede cobrar EN ESPECIE las
/// patas pendientes de una sesión COMPROMETIDA (`sold == 1`) que el inversor
/// abandonó — los tokens van SIEMPRE a la ATA del inversor, nunca al caller. Es
/// el backstop de liveness contra un creador que sostenga el vault en status 4
/// indefinidamente (B-2). Más largo que el timeout del abort (30 min) porque la
/// acción impone exposición a token al inversor, no destruye su valor.
pub const WITHDRAW_INKIND_TIMEOUT_SECS: i64 = 24 * 60 * 60;

#[account]
#[derive(Default)]
pub struct WithdrawSession {
    pub investor: Pubkey,
    pub vault: Pubkey,

    /// Shares the investor committed at `withdraw_init`. Already burned by the
    /// time this struct exists — kept here for the proportional math at settle.
    pub shares_to_burn: u64,

    /// USDC the investor will receive from the vault's idle balance (the part
    /// that wasn't held as any non-USDC allocation). Reserved to the USDC
    /// escrow at init.
    pub usdc_slice_from_vault: u64,

    /// USDC actually produced by swap_batch calls so far. Settle adds this to
    /// `usdc_slice_from_vault` and transfers the total to the investor.
    pub usdc_from_swaps: u64,

    /// Snapshot of `vault.total_shares` BEFORE the burn at init. Used at init
    /// to compute each token slice, and at settle for the state delta.
    pub total_shares_before: u64,

    /// Snapshot of `vault.tvl_last_computed_usdc` at init.
    pub tvl_before: u64,

    /// `vault.allocation_count` at init.
    pub leg_count: u8,

    /// Bitmap of completed legs. Bit `i` set ⇒ leg `i` was swapped, or was
    /// pre-marked at init (USDC-as-alloc / zero-weight / dust / Tier-B-parked).
    /// `is_complete()` requires `legs_completed == full_mask()`.
    pub legs_completed: u16,

    pub created_at: i64,
    pub bump: u8,

    // ---- C2 (hucha por token) — escrow bookkeeping, mirror of DepositSession.
    /// Bitmap of swept legs. Bit `i` set ⇒ leg `i`'s token escrow ATA has been
    /// drained (→ vault, in both the settle and abort directions) and closed.
    pub legs_swept: u16,

    /// 1 once the abort path has started (an abort-direction sweep ran). Blocks
    /// further swaps, the settle-direction sweep and settle, so a session can
    /// never mix a payout with a rollback.
    pub aborting: u8,

    /// Bits pre-marked at init for legs that never get a TOKEN escrow:
    /// USDC-as-allocation and zero-weight slots. NOTE: dust (slice 0) and
    /// Tier-B-parked legs are NOT trivial here — the frontend still creates
    /// their (empty) escrow ATA, so they must be swept/closed. Snapshotted
    /// so aborts keep working even after a mid-session restructure.
    pub trivial_mask: u16,

    /// The allocation mints at init, leg-indexed. Binds each escrow ATA to its
    /// leg without trusting the CURRENT vault table (which may have
    /// restructured to a different basket mid-session). Slots ≥ leg_count are
    /// Pubkey::default().
    pub leg_mints: [Pubkey; MAX_TOKENS_PER_VAULT],

    /// Ceremonia #39 (C-B): 1 una vez que la sesión ha EXTRAÍDO VALOR de una
    /// hucha — vendiendo (`withdraw_swap_batch`) o cobrando en especie
    /// (`withdraw_claim_leg_in_kind`). Vender/cobrar COMPROMETE a asentar: con
    /// `sold == 1` el abort queda vetado (si no, re-acuñaría shares completas
    /// sobre tokens ya pagados = el ataque C-B). Carved from _reserved; sesiones
    /// legacy leen 0 (permisivo, comportamiento del #38).
    pub sold: u8,

    /// Ceremonia #39 (C-B): telemetría de qué patas se cobraron en especie
    /// (bit i). NO load-bearing — la lógica usa `legs_completed`/`legs_swept`;
    /// solo para la UI / el historial.
    pub in_kind_mask: u16,

    /// Ceremonia #45 (H4, R1): valor pro-rata del vault que ESTE retiro saca
    /// (`tvl_before * shares_to_burn / total_shares_before`), fijado en
    /// `withdraw_init`. `withdraw_settle` lo resta del agregado global
    /// `protocol.total_tvl_usdc` EN LUGAR de `exit_value`, para que la
    /// contribución del retiro al tope sea simétrica con el `+net` del depósito
    /// sea la salida en USDC o EN ESPECIE (cierra el lado SALIDA de H4). Carvado
    /// de `_reserved` (13→5): sesiones legacy leen 0 → resta 0 → no-op, legacy-safe.
    pub marked_slice: u64,

    /// Reserved for forward-compatibility. Always written as zeroes.
    pub _reserved: [u8; 5],
}

impl WithdrawSession {
    /// 8 (disc) + 32 + 32 + 8 + 8 + 8 + 8 + 8 + 1 + 2 + 8 + 1
    /// + 2 + 1 + 2 + 32*MAX_TOKENS_PER_VAULT
    /// + 1 (sold, C-B) + 2 (in_kind_mask, C-B) + 8 (marked_slice, H4 #45) + 5 (_reserved) = 465 bytes.
    /// LEN SIN CAMBIO (16 == 1+2+8+5): sold/in_kind_mask (C-B) y marked_slice (H4
    /// #45) se carvan del _reserved, ningún offset previo se mueve y el parser
    /// posicional del frontend queda intacto (último offset O_LEG_MINTS = 129+320 = 449 < 465).
    pub const LEN: usize = 8
        + 32
        + 32
        + 8
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
        + 1
        + 2
        + 8
        + 5;

    /// Bitmap with one bit set per leg.
    pub fn full_mask(&self) -> u16 {
        if self.leg_count >= 16 {
            u16::MAX
        } else {
            (1u16 << self.leg_count) - 1
        }
    }

    /// True iff every leg has been executed (or pre-marked). Used by settle.
    pub fn is_complete(&self) -> bool {
        self.legs_completed == self.full_mask()
    }

    /// Legs that hold a token escrow ATA and must be swept + closed before the
    /// session can settle: every NON-trivial leg. Unlike deposit (where only
    /// swapped legs hold a token escrow), in withdraw EVERY non-trivial leg is
    /// funded at init, so this does NOT depend on `legs_completed`.
    pub fn sweepable_mask(&self) -> u16 {
        self.full_mask() & !self.trivial_mask
    }

    /// True iff every token escrow this session created has been drained and
    /// closed (in whichever direction).
    pub fn fully_swept(&self) -> bool {
        (self.sweepable_mask() & !self.legs_swept) == 0
    }

    /// Ceremonia #39 (C-B): la sesión ha extraído valor de una hucha (vendió o
    /// cobró en especie) ⇒ su único terminal es SETTLE; el abort queda vetado.
    pub fn committed(&self) -> bool {
        self.sold == 1
    }
}
