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

/// Ceremonia #39 (C-B): tras este tiempo, un TERCERO puede cobrar EN ESPECIE las
/// patas pendientes de una sesión COMPROMETIDA (`sold == 1`) que el inversor
/// abandonó — los tokens van SIEMPRE a la ATA del inversor, nunca al caller. Es
/// el backstop de liveness contra un creador que sostenga el vault en status 4
/// indefinidamente (B-2). La acción impone exposición a token al inversor, no
/// destruye su valor; el tercero que CANCELA (re-acuña) espera aún más (48 h, o
/// 10 min si la sesión ya está cancelando: `WITHDRAW_ABORT_FINISH_SECS`).
pub const WITHDRAW_INKIND_TIMEOUT_SECS: i64 = 24 * 60 * 60;

/// Ceremonia #54 (DT-C): reloj EXTERIOR anidado sobre la válvula en especie. Un
/// TERCERO (`caller != investor`) solo puede conducir el barrido en dirección
/// ABORT de una sesión huérfana por encima de ESTE plazo — estrictamente mayor
/// que `WITHDRAW_INKIND_TIMEOUT_SECS` (24 h) para que, en la ventana [24h, 48h],
/// SOLO el inversor pueda actuar y nadie le arrebate el cobro en especie forzando
/// `aborting = 1` (que veta `withdraw_claim_leg_in_kind`). El inversor conserva
/// acceso a cualquier hora. Junto con `WITHDRAW_ABORT_FINISH_SECS` (10 min, solo
/// con `aborting == 1`) es el reloj de la cancelación por un tercero, en UN predicado:
/// `withdraw_sweep_batch` (dirección abort) y `withdraw_abort` lo aplican con el
/// mismo predicado, `abort_authorized` (G3, F2B-03: antes `withdraw_abort` tenía
/// un reloj propio de 30 min que solo quedaba subsumido si faltaban huchas por
/// barrer). G1 (2026-10-09): es también el plazo a partir del cual un TERCERO
/// puede cobrar en especie una sesión que ya no puede cancelarse
/// (`third_party_may_claim_in_kind`).
pub const WITHDRAW_ORPHAN_ABORT_SECS: i64 = 48 * 60 * 60;

/// G3 (decisión de Juan, 16-oct-2026; revisión N3): una sesión de retiro que YA está cancelando (`aborting == 1`: el
/// inversor latcheó la devolución y la abandonó a medias) la puede terminar un TERCERO pasados estos segundos, no las
/// 48 h. Con `aborting == 1` ya no hay cobro en especie que robar (lo veta la propia bandera) y lo que queda es neutral
/// en valor: las huchas vuelven al vault y las participaciones al inversor. Mismo reloj que la devolución de un
/// depósito (10 min; la tabla de verdad ata las dos constantes), para que el robot limpie las dos con la misma
/// cadencia. Es también la ventana del tercero en el settle de una sesión SIN patas de token
/// (`trivial_settle_authorized`, aviso de Kairo del 16-oct): quien la cambie mueve las dos.
/// `#[constant]`: sale en el IDL, como el plazo del depósito.
#[constant]
pub const WITHDRAW_ABORT_FINISH_SECS: i64 = 10 * 60;

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
    /// contribución del retiro al tope sea simétrica con el `+I` del depósito
    /// sea la salida en USDC o EN ESPECIE (cierra el lado SALIDA de H4). Carvado
    /// de `_reserved` (13→5): sesiones legacy leen 0 → resta 0 → no-op, legacy-safe.
    pub marked_slice: u64,

    /// Ceremonia USDC (§3.4): generación de la sesión = 32 bits bajos del contador
    /// `session_generation` del vault en el momento del init (nunca 0 en sesiones
    /// nuevas: el init incrementa antes de sellar). Carved from `_reserved` (5 → 1);
    /// sesiones legacy leen 0 = «sin generación» y jamás emparejan con un
    /// `FundingRecord` (§3.3). LEN sin cambio.
    pub generation: u32,

    /// Auditoría 2026-10-09 (G1, F7A-01/F7B-01): 1 si `withdraw_init` APARCÓ una pata con saldo o
    /// el USDC ocioso congelado (forfeit DT-A(a)). El forfeit es DEFINITIVO: `withdraw_abort` lo
    /// rechaza (WithdrawParkedCannotAbort), la sesión solo asienta o cobra en especie, y sus shares
    /// NO cuentan en `revivable_burned_shares`. Carvado del último byte de `_reserved` (1 → 0);
    /// sesiones legacy leen 0 (permisivo, comportamiento anterior). LEN sin cambio.
    pub had_park: u8,
}

impl WithdrawSession {
    /// 8 (disc) + 32 + 32 + 8 + 8 + 8 + 8 + 8 + 1 + 2 + 8 + 1
    /// + 2 + 1 + 2 + 32*MAX_TOKENS_PER_VAULT
    /// + 1 (sold, C-B) + 2 (in_kind_mask, C-B) + 8 (marked_slice, H4 #45) + 4 (generation, §3.4)
    /// + 1 (had_park, G1 2026-10-09; antes _reserved) = 465 bytes. LEN SIN CAMBIO (16 == 1+2+8+4+1): sold/in_kind_mask (C-B) y marked_slice (H4
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
        + 4 // generation (§3.4)
        + 1; // had_park (G1 2026-10-09; antes _reserved)

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

    /// G1 (2026-10-09): ¿puede esta sesión todavía CANCELARSE (barrido en dirección abort y
    /// `withdraw_abort`, que re-acuña sus shares enteras)? NO si vendió o cobró en especie (C-B,
    /// ceremonia #39); NO si aparcó una pata con saldo (`had_park`, forfeit definitivo); y NO si
    /// es anterior al upgrade de G1 (`generation == 0`: está fuera del contador de la entrada)
    /// salvo que ya hubiera EMPEZADO a cancelar (`aborting == 1`, reservada en `pending_burned`,
    /// que la entrada también exige a 0). Es la ÚNICA definición: el abort y el barrido la hacen
    /// cumplir con sus errores propios (6172, 6217, 6218) y `committed()` es su negación.
    pub fn can_abort(&self) -> bool {
        self.sold == 0 && self.had_park == 0 && (self.generation != 0 || self.aborting == 1)
    }

    /// G3-B2: bit de `in_kind_mask` (las patas usan los bits 0..MAX_TOKENS_PER_VAULT) que marca una sesión que NACIÓ COBRADA:
    /// `withdraw_init` ya pagó algo EN ESPECIE (pata o USDC ocioso con su hucha congelada). Nunca pudo cancelarse, así que nunca
    /// sumó a `revivable`.
    pub const IN_KIND_AT_INIT_BIT: u16 = 1 << 15;

    /// G1 + G3-B2: ¿sumó esta sesión sus shares a `revivable_burned_shares` en el init? Las nacidas con el contador
    /// (`generation != 0`), sin park definitivo y que no nacieron cobradas. Es el ÚNICO predicado con el que la liberan el settle y
    /// `withdraw_force_release` (y con el que suma el init).
    pub fn counts_in_revivable(&self) -> bool {
        self.generation != 0 && self.had_park == 0 && (self.in_kind_mask & Self::IN_KIND_AT_INIT_BIT) == 0
    }

    /// Ceremonia #39 (C-B) + G1: la sesión ya no puede cancelarse ⇒ su único terminal es
    /// SETTLE (permissionless y admitido con el vault en reestructuración) o el cobro en
    /// especie (también por un tercero pasadas 48 h si quedó abandonada).
    pub fn committed(&self) -> bool {
        !self.can_abort()
    }

    /// G1: ¿puede un TERCERO cobrar en especie esta sesión en el instante `now`? Sí si ya extrajo
    /// valor (`sold == 1`, ceremonia #39) o si ya no puede cancelarse y lleva abandonada más de
    /// `WITHDRAW_ORPHAN_ABORT_SECS` (48 h): la limpieza de huérfanas que antes hacía el abort de
    /// tercero (DT-C), neutral en valor porque el destino es la ATA canónica del inversor. El reloj
    /// de 24 h del propio cobro (`WITHDRAW_INKIND_TIMEOUT_SECS`) se exige aparte, a todo caller.
    pub fn third_party_may_claim_in_kind(&self, now: i64) -> bool {
        self.sold == 1
            || (!self.can_abort() && now.saturating_sub(self.created_at) > WITHDRAW_ORPHAN_ABORT_SECS)
    }

    /// G3 (2026-10-15, F2B-03): ¿puede el caller CANCELAR esta sesión (barrido en dirección abort y
    /// `withdraw_abort`) en el instante `now`? El inversor a cualquier hora; un TERCERO solo pasadas
    /// `WITHDRAW_ORPHAN_ABORT_SECS` (48 h), estrictamente por encima de la ventana en especie (DT-C), o pasados
    /// `WITHDRAW_ABORT_FINISH_SECS` (10 min) si la sesión YA está cancelando (`aborting == 1`: no queda cobro en
    /// especie que proteger y terminar la cancelación es neutral en valor). Es el ÚNICO reloj de la cancelación:
    /// las dos instrucciones lo aplican con el mismo error (6167). No mira `can_abort()`: eso lo exigen aparte las
    /// dos con sus errores propios (6172, 6217, 6218).
    pub fn abort_authorized(&self, caller_is_investor: bool, now: i64) -> bool {
        let edad = now.saturating_sub(self.created_at);
        caller_is_investor
            || edad > WITHDRAW_ORPHAN_ABORT_SECS
            || (self.aborting == 1 && edad > WITHDRAW_ABORT_FINISH_SECS)
    }

    /// G3 (F2B-02; aviso de Kairo del 16-oct, decisión de Juan): una sesión SIN patas de token (`sweepable_mask() == 0`:
    /// todas las patas triviales, USDC o peso 0) no tiene nada que vender ni barrer y su settle solo mueve USDC, así que
    /// cuenta como comprometida para el settle: el INVERSOR a cualquier hora (también con el vault en reestructuración);
    /// un TERCERO solo pasados `WITHDRAW_ABORT_FINISH_SECS` (10 min), para que nadie le quite al inversor, en el acto,
    /// la opción de cancelar. Una sesión con patas de token nunca entra por aquí: va por `committed()`.
    pub fn trivial_settle_authorized(&self, caller_is_investor: bool, now: i64) -> bool {
        self.sweepable_mask() == 0
            && (caller_is_investor || now.saturating_sub(self.created_at) > WITHDRAW_ABORT_FINISH_SECS)
    }

    /// G3-B1a (F2B-01): ¿deja este lote (`new_swept`) barridas TODAS las patas barribles? Solo se exige en la
    /// transición `aborting 0 → 1` del barrido (latch ATÓMICO): si la ATA del vault de alguna pata está congelada, la
    /// transferencia revierte la transacción entera y nada latchea, así que la sesión conserva el cobro en especie.
    /// Con `aborting` ya puesto no se exige (lotes parciales de sesiones anteriores al upgrade). Predicado PURO.
    pub fn abort_latch_complete(&self, new_swept: u16) -> bool {
        let sweepable = self.sweepable_mask();
        (self.legs_swept | new_swept) & sweepable == sweepable
    }

    /// G3-B1b (DT-A(b)): el reloj ANIDADO de `withdraw_force_release`: el inversor pasadas 24 h (la ventana en especie,
    /// `WITHDRAW_INKIND_TIMEOUT_SECS`: antes tiene sus terminales normales) y un tercero pasadas 48 h (la de huérfanas,
    /// `WITHDRAW_ORPHAN_ABORT_SECS`): un tercero nunca libera antes que el propio inversor. Predicado PURO; la prueba de
    /// bloqueo (la cuenta exacta congelada) la exige aparte el handler.
    pub fn force_release_authorized(&self, caller_is_investor: bool, now: i64) -> bool {
        let edad = now.saturating_sub(self.created_at);
        if caller_is_investor {
            edad > WITHDRAW_INKIND_TIMEOUT_SECS
        } else {
            edad > WITHDRAW_ORPHAN_ABORT_SECS
        }
    }
}

// Ceremonia USDC (§3.4): el tamaño es un CONTRATO con los filtros `dataSize` de los clientes
// y con los parsers del arnés: fijado en compilación.
const _: () = assert!(WithdrawSession::LEN == 465, "WithdrawSession::LEN debe seguir siendo 465");

#[cfg(test)]
mod g1_tests {
    use super::*;

    fn sesion(sold: u8, had_park: u8, generation: u32, aborting: u8) -> WithdrawSession {
        WithdrawSession { sold, had_park, generation, aborting, created_at: 1_000_000, ..Default::default() }
    }

    /// Tabla de verdad de `can_abort` / `committed`: la ÚNICA definición de «puede cancelarse».
    #[test]
    fn can_abort_tabla_de_verdad() {
        // (sold, had_park, generation, aborting) → puede cancelar
        let casos: [((u8, u8, u32, u8), bool); 8] = [
            ((0, 0, 7, 0), true),  // sesión nueva, sin park, sin vender
            ((0, 0, 7, 1), true),  // nueva, ya cancelando
            ((1, 0, 7, 0), false), // vendió o cobró en especie (C-B)
            ((0, 1, 7, 0), false), // aparcó con saldo (forfeit definitivo)
            ((0, 1, 7, 1), false), // aparcada: ni aunque estuviera latcheada
            ((0, 0, 0, 0), false), // anterior al upgrade sin cancelación empezada
            ((0, 0, 0, 1), true),  // anterior al upgrade que YA estaba cancelando: la termina
            ((1, 0, 0, 0), false), // anterior al upgrade y vendida
        ];
        for ((sold, had_park, generation, aborting), esperado) in casos {
            let s = sesion(sold, had_park, generation, aborting);
            assert_eq!(s.can_abort(), esperado, "can_abort{:?}", (sold, had_park, generation, aborting));
            assert_eq!(s.committed(), !esperado, "committed es la negación");
        }
    }

    /// Tabla del tercero en el cobro en especie: por valor extraído, o por huérfana que ya no puede
    /// cancelar y pasadas 48 h (ni a las 24 h ni a las 47 h; nunca una sesión que aún puede cancelar).
    #[test]
    fn tercero_en_especie_tabla_de_verdad() {
        let h = 60 * 60;
        let t0 = 1_000_000i64;
        let nueva = sesion(0, 0, 7, 0);
        let aparcada = sesion(0, 1, 7, 0);
        let antigua = sesion(0, 0, 0, 0);
        let antigua_latcheada = sesion(0, 0, 0, 1);
        let vendida = sesion(1, 0, 7, 0);
        for edad in [0, 24 * h + 1, 47 * h, 48 * h] {
            assert!(!nueva.third_party_may_claim_in_kind(t0 + edad), "nueva a {edad}s: nunca");
            assert!(!aparcada.third_party_may_claim_in_kind(t0 + edad), "aparcada a {edad}s: aún no");
            assert!(!antigua.third_party_may_claim_in_kind(t0 + edad), "antigua a {edad}s: aún no");
            assert!(!antigua_latcheada.third_party_may_claim_in_kind(t0 + edad), "latcheada: sigue cancelando");
            assert!(vendida.third_party_may_claim_in_kind(t0 + edad), "vendida: siempre (C-B)");
        }
        for edad in [48 * h + 1, 30 * 24 * h] {
            assert!(aparcada.third_party_may_claim_in_kind(t0 + edad), "aparcada a {edad}s: huérfana");
            assert!(antigua.third_party_may_claim_in_kind(t0 + edad), "antigua a {edad}s: huérfana");
            assert!(!nueva.third_party_may_claim_in_kind(t0 + edad), "nueva a {edad}s: puede cancelar, nunca");
            assert!(!antigua_latcheada.third_party_may_claim_in_kind(t0 + edad), "latcheada: nunca");
        }
        // Relojes anidados (DT-C): el plazo del tercero es ESTRICTAMENTE mayor que el del cobro en especie.
        assert!(WITHDRAW_ORPHAN_ABORT_SECS > WITHDRAW_INKIND_TIMEOUT_SECS);
    }

    /// G3 (F2B-03): tabla de verdad del único reloj de la cancelación: el inversor a cualquier hora; el tercero solo
    /// pasadas 48 h (ni a los 31 min del viejo reloj de `withdraw_abort`, ni a las 47 h, ni en las 48 h justas); y si la
    /// sesión YA está cancelando (`aborting == 1`), el tercero la termina pasados 10 min (decisión de Juan, 16-oct), no
    /// a los 10 min justos ni antes.
    #[test]
    fn abort_authorized_tabla_de_verdad() {
        let h = 60 * 60;
        let t0 = 1_000_000i64;
        let s = sesion(0, 0, 7, 0);
        let cancelando = sesion(0, 0, 7, 1);
        assert_eq!(WITHDRAW_ABORT_FINISH_SECS, 10 * 60);
        assert_eq!(WITHDRAW_ABORT_FINISH_SECS, crate::state::deposit_session::DEPOSIT_SESSION_TIMEOUT_SECS, "misma cadencia que la devolución de un depósito");
        assert!(WITHDRAW_ABORT_FINISH_SECS < WITHDRAW_INKIND_TIMEOUT_SECS);
        for edad in [0, 31 * 60, 47 * h, 48 * h] {
            assert!(s.abort_authorized(true, t0 + edad), "inversor a {edad}s: siempre");
            assert!(!s.abort_authorized(false, t0 + edad), "tercero a {edad}s: todavía no");
        }
        for edad in [48 * h + 1, 30 * 24 * h] {
            assert!(s.abort_authorized(true, t0 + edad), "inversor a {edad}s: siempre");
            assert!(s.abort_authorized(false, t0 + edad), "tercero a {edad}s: huérfana");
        }
        for edad in [0, 10 * 60] {
            assert!(!cancelando.abort_authorized(false, t0 + edad), "cancelando a {edad}s: el tercero todavía no");
            assert!(cancelando.abort_authorized(true, t0 + edad), "cancelando: el inversor siempre");
        }
        for edad in [10 * 60 + 1, 47 * h, 30 * 24 * h] {
            assert!(cancelando.abort_authorized(false, t0 + edad), "cancelando a {edad}s: el tercero la termina");
        }
        // Un reloj que retrocede (now < created_at) nunca abre al tercero (saturating_sub).
        assert!(!s.abort_authorized(false, t0 - 1));
        assert!(!cancelando.abort_authorized(false, t0 - 1));
        assert!(!s.abort_authorized(false, i64::MIN));
    }

    /// G3 (F2B-02, aviso de Kairo): tabla de verdad del settle de una sesión SIN patas de token: el inversor siempre; el
    /// tercero solo pasados 10 min (no en el acto ni a los 10 min justos); con patas de token, nunca por esta vía.
    #[test]
    fn trivial_settle_authorized_tabla_de_verdad() {
        let t0 = 1_000_000i64;
        let trivial = WithdrawSession { leg_count: 2, trivial_mask: 0b11, created_at: t0, ..Default::default() };
        let con_patas = WithdrawSession { leg_count: 2, trivial_mask: 0b01, created_at: t0, ..Default::default() };
        assert_eq!(trivial.sweepable_mask(), 0);
        assert_ne!(con_patas.sweepable_mask(), 0);
        for edad in [0, 10 * 60] {
            assert!(trivial.trivial_settle_authorized(true, t0 + edad), "inversor a {edad}s: siempre");
            assert!(!trivial.trivial_settle_authorized(false, t0 + edad), "tercero a {edad}s: todavía no");
        }
        for edad in [10 * 60 + 1, 48 * 60 * 60 + 1, 30 * 24 * 60 * 60] {
            assert!(trivial.trivial_settle_authorized(false, t0 + edad), "tercero a {edad}s: ya");
        }
        assert!(!trivial.trivial_settle_authorized(false, t0 - 1), "un reloj que retrocede nunca abre al tercero");
        for edad in [0, 10 * 60 + 1, 30 * 24 * 60 * 60] {
            assert!(!con_patas.trivial_settle_authorized(true, t0 + edad), "con patas de token: nunca por esta vía");
            assert!(!con_patas.trivial_settle_authorized(false, t0 + edad));
        }
    }

    /// G3 (auditoría 2026-10-09, F2B-03): el rincón I3 (sesión COMPLETA con `sold == 0`, barrida en dirección settle por
    /// cualquiera) dejaba a un TERCERO cancelar a los 30 minutos con `withdraw_abort`, saltándose las 48 h de DT-C que el
    /// barrido sí exige. El validador no adelanta el reloj, así que lo fija este test (revisión N3: cuenta llamadas, no
    /// busca un nombre que ya no existe): el CÓDIGO (sin comentarios) de `withdraw_abort` y de `withdraw_sweep_batch` autoriza
    /// con EXACTAMENTE una llamada a `abort_authorized(` cada uno, y `withdraw_abort` no mira `created_at` por su cuenta (el
    /// único reloj vive en el predicado, con su tabla de verdad arriba).
    #[test]
    fn withdraw_abort_no_usa_el_reloj_de_treinta_minutos_para_un_tercero() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/instructions");
        let sin_comentarios = |src: &str| -> String {
            src.lines()
                .map(|l| match l.find("//") {
                    Some(i) => &l[..i],
                    None => l,
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        for nombre in ["withdraw_abort.rs", "withdraw_sweep_batch.rs"] {
            let codigo = sin_comentarios(&std::fs::read_to_string(dir.join(nombre)).expect("instrucción legible"));
            assert_eq!(
                codigo.matches("abort_authorized(").count(),
                1,
                "{nombre} autoriza la cancelación con exactamente una llamada a abort_authorized("
            );
            assert!(!codigo.contains("WITHDRAW_SESSION_TIMEOUT_SECS"), "{nombre}: el reloj de 30 minutos no existe");
        }
        let abort = sin_comentarios(&std::fs::read_to_string(dir.join("withdraw_abort.rs")).unwrap());
        assert!(!abort.contains("created_at"), "withdraw_abort.rs no puede mirar el reloj por su cuenta (rincón I3 de F2B-03)");
        // Cableado del settle (juez corto del 16-oct): la ventana del tercero sin patas de token se decide con el reloj
        // REAL y por el predicado único, exactamente una vez (el validador no puede fabricar un `now` falso).
        let settle = sin_comentarios(&std::fs::read_to_string(dir.join("withdraw_settle.rs")).unwrap());
        assert_eq!(settle.matches("trivial_settle_authorized(").count(), 1, "withdraw_settle.rs decide la ventana con una sola llamada al predicado");
        assert_eq!(settle.matches("Clock::get()?.unix_timestamp").count(), 1, "withdraw_settle.rs lee el reloj real una vez");
        assert!(!settle.contains("let now = session.created_at"), "withdraw_settle.rs no puede fingir el reloj");
    }
}

#[cfg(test)]
mod g3b_tests {
    use super::*;

    /// G3-B2: tabla de verdad de `counts_in_revivable` (suma en el init, libera el settle y el force_release).
    #[test]
    fn counts_in_revivable_tabla_de_verdad() {
        let s = |generation: u32, had_park: u8, in_kind_mask: u16| WithdrawSession { generation, had_park, in_kind_mask, ..Default::default() };
        assert!(s(1, 0, 0).counts_in_revivable(), "normal");
        assert!(s(1, 0, 0b11).counts_in_revivable(), "patas cobradas en especie DESPUÉS del init: sumó en el init");
        assert!(!s(0, 0, 0).counts_in_revivable(), "anterior al upgrade");
        assert!(!s(1, 1, 0).counts_in_revivable(), "aparcada");
        assert!(!s(1, 0, WithdrawSession::IN_KIND_AT_INIT_BIT).counts_in_revivable(), "nació cobrada");
        assert!(WithdrawSession::IN_KIND_AT_INIT_BIT >> crate::constants::MAX_TOKENS_PER_VAULT != 0, "el bit no pisa ninguna pata");
    }

    fn sesion(leg_count: u8, trivial_mask: u16, legs_swept: u16) -> WithdrawSession {
        WithdrawSession { leg_count, trivial_mask, legs_swept, ..Default::default() }
    }

    /// G3-B1a (F2B-01): tabla de verdad del latch atómico: el lote tiene que completar TODAS las patas barribles
    /// (las no triviales), contando las ya barridas; las triviales no cuentan; una cesta de 7 cabe en un lote.
    #[test]
    fn abort_latch_complete_tabla_de_verdad() {
        // 3 patas, la 1 trivial → barribles 0b101
        assert!(sesion(3, 0b010, 0).abort_latch_complete(0b101), "las dos barribles en el lote");
        assert!(!sesion(3, 0b010, 0).abort_latch_complete(0b001), "falta la pata 2");
        assert!(!sesion(3, 0b010, 0).abort_latch_complete(0b100), "falta la pata 0");
        assert!(sesion(3, 0b010, 0b001).abort_latch_complete(0b100), "la 0 ya barrida + la 2 en el lote");
        assert!(!sesion(3, 0b010, 0b001).abort_latch_complete(0), "lote vacío no completa");
        assert!(sesion(3, 0b010, 0).abort_latch_complete(0b111), "un bit trivial de más no estorba");
        // 7 patas no triviales: solo el lote completo
        assert!(sesion(7, 0, 0).abort_latch_complete(0b111_1111), "cesta máxima en un lote");
        assert!(!sesion(7, 0, 0).abort_latch_complete(0b011_1111), "6 de 7 no basta");
        // Sin patas barribles (vault 100 % USDC): trivialmente completo
        assert!(sesion(1, 0b1, 0).abort_latch_complete(0), "sin patas de token");
    }

    /// G3-B1b: tabla de verdad del reloj anidado de la liberación: inversor desde 24 h, tercero desde 48 h (ni a las 24 h
    /// justas, ni a las 47 h, ni a las 48 h justas).
    #[test]
    fn force_release_authorized_tabla_de_verdad() {
        let h = 60 * 60;
        let t0 = 1_000_000i64;
        let s = WithdrawSession { created_at: t0, ..Default::default() };
        for (edad, inversor, tercero) in [
            (0, false, false), (24 * h, false, false), (24 * h + 1, true, false), (47 * h, true, false), (48 * h, true, false),
            (48 * h + 1, true, true), (30 * 24 * h, true, true),
        ] {
            assert_eq!(s.force_release_authorized(true, t0 + edad), inversor, "inversor a {edad}s");
            assert_eq!(s.force_release_authorized(false, t0 + edad), tercero, "tercero a {edad}s");
        }
        assert!(WITHDRAW_ORPHAN_ABORT_SECS > WITHDRAW_INKIND_TIMEOUT_SECS, "relojes anidados");
    }

    /// G3-B1a: el tope del barrido de RETIRO en el handler es el NUEVO (7, `MAX_WITHDRAW_SWEEP_LEGS_PER_BATCH`), no el del
    /// depósito (4): con el viejo, una cesta de 5 a 7 patas no podría cancelar nunca (6221 con 4 patas, `BatchTooLarge`
    /// con más). El const assert de `constants.rs` ata el valor; esto ata su USO en el require del handler.
    #[test]
    fn el_barrido_de_retiro_usa_el_tope_nuevo() {
        let src = include_str!("../instructions/withdraw_sweep_batch.rs");
        let codigo: String = src.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
        assert!(codigo.contains("args.leg_indices.len() <= MAX_WITHDRAW_SWEEP_LEGS_PER_BATCH as usize"), "el require del tope usa MAX_WITHDRAW_SWEEP_LEGS_PER_BATCH");
        assert!(!codigo.contains("MAX_SWEEP_LEGS_PER_BATCH,"), "el handler del retiro ya no usa el tope del depósito");
    }
}
