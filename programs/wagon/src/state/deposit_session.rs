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

use crate::constants::{DEPOSIT_UNSWEPT_ESCAPE_SECS, DEPOSIT_VETOED_RETURN_SECS, MAX_TOKENS_PER_VAULT};
use crate::pricing::ObservedPrice;
use crate::state::vault_layout;

/// G2-c (revisión N3, M1): el precio de UNA posición de la tabla tal como lo leyó el lote de COMMIT
/// (`LegPrice::effective`: mantisa y exponente de Pyth; en los feeds compuestos, el producto rr × SOL/USD ya
/// multiplicado). `price == 0` = sin precio (slot trivial: USDC o peso 0). 12 bytes. Se guarda en la sesión para
/// que los lotes posteriores del barrido valoren lo que aterriza con el MISMO precio que el re-precio S-1 del
/// commit y SIN volver a leer el oráculo (liveness como antes de G2-c: solo el commit necesita precio fresco).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionPrice {
    pub price: i64,
    pub expo: i32,
}

impl SessionPrice {
    pub fn from_observed(obs: ObservedPrice) -> Self {
        SessionPrice { price: obs.price, expo: obs.expo }
    }
    /// `None` si la posición no tiene precio guardado (slot trivial o sesión sin valorar).
    pub fn observed(&self) -> Option<ObservedPrice> {
        if self.price <= 0 {
            return None;
        }
        Some(ObservedPrice { price: self.price, expo: self.expo })
    }
}

/// After this many seconds, an unfinished deposit session can be aborted
/// (escrow → investor) by ANYONE, not just the investor. Same philosophy
/// as `RESTRUCTURE_ABORT_TIMEOUT_SECS`: no session may hold the protocol
/// hostage. The funds always go back to the investor, never to the caller.
/// G3 (Juan, 13-oct-2026): 10 minutos (antes 30): un depósito a medias se devuelve antes y el robot de
/// sesiones colgadas actúa con el mismo reloj. `#[constant]`: sale en el IDL (los clientes no lo copian).
#[constant]
pub const DEPOSIT_SESSION_TIMEOUT_SECS: i64 = 10 * 60;

// Auditoría CISO (P4, #56; revisión N3): la escotilla la puede conducir CUALQUIERA (su plazo no baja del de un tercero) y la
// devolución a petición del inversor vetado llega antes que ella. Se comprueba al compilar: si alguien cambia un plazo y rompe
// el orden, el build falla en vez de que la dirección del barrido deje de depender solo del reloj sin avisar.
const _: () = {
    assert!(DEPOSIT_UNSWEPT_ESCAPE_SECS >= DEPOSIT_SESSION_TIMEOUT_SECS, "la escotilla la puede conducir cualquiera");
    assert!(DEPOSIT_VETOED_RETURN_SECS < DEPOSIT_UNSWEPT_ESCAPE_SECS, "la devolución del vetado llega antes que la escotilla");
};

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

    /// I, the capital that enters the basket: what the investor paid at `deposit_init`
    /// (D, the `amount_usdc` argument) minus the entry fee E, which is DEDUCTED from D
    /// (Juan, 2026-10-15) and reserved in the session escrow (D = I + E) until the settle.
    /// This is the number the `swap_batch` calls slice by `weight_bps` and the
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
    /// _reserved; ningún offset previo se mueve. Ver `value_tracked`. G5: el USDC de capital que el barrido de COMMIT mete en
    /// el vault (1:1) se suma aquí, porque ya no es residual de la hucha cuando llega el settle.
    pub received_value_acc: u64,

    /// Ceremonia #39 (S-4): 1 sii el guard iba sellado ON al init
    /// (`max_loss_bps > 0`) — sin guard no hay oráculo enhebrado y no existe
    /// medición posible. Cinturón anti-legacy: una sesión abierta ANTES del
    /// upgrade #39 lleva `_reserved` a ceros ⇒ lee 0 ⇒ `deposit_settle` usa la
    /// fórmula legacy exacta (nunca destruye el dinero de una sesión en vuelo).
    pub value_tracked: u8,

    /// Ceremonia USDC (§3.4): generación de la sesión = 32 bits bajos del contador
    /// `session_generation` del vault en el momento del init (nunca 0 en sesiones
    /// nuevas: el init incrementa antes de sellar). Carved from `_reserved` (5 → 1);
    /// sesiones legacy leen 0 = «sin generación» y jamás emparejan con un
    /// `FundingRecord` (§3.3). LEN sin cambio.
    pub generation: u32,

    /// G2-c (auditoría 2026-10-09, F1A-03): 1 sii el barrido de COMMIT valoró lo que aterriza con el oráculo
    /// vivo (`landed_value_at_commit`); 0 = sin valoración (sesión anterior al upgrade o migrada, o commit con
    /// el m2m apagado) y `deposit_settle` acuña como hasta G2-c. Carved del `_reserved` (1 → 0): las sesiones
    /// vivas leen 0, nunca se les aplica una cota que no se midió.
    pub landed_tracked: u8,

    /// DT-E (ceremonia USDC): cortes de la comisión de entrada E del protocolo y del creador,
    /// RESERVADOS en la hucha USDC de la sesión por `deposit_init` (E ya no sale al iniciar).
    /// `deposit_settle`, el único final de éxito, los reparte; `deposit_abort` los devuelve con el
    /// resto de la hucha. Van AL FINAL: ningún offset previo se mueve (`entry_fee_*` @457 y @465).
    pub entry_fee_protocol_cut_usdc: u64,
    pub entry_fee_creator_cut_usdc: u64,

    /// G2-c (F1A-03): valor-oráculo (átomos de USDC) de las patas que ATERRIZARON en el vault, valoradas en
    /// cada lote de barrido en dirección settle con el MISMO `ObservedPrice` que el re-precio S-1 del commit
    /// (el denominador y el numerador de la acuñación, al mismo precio). `deposit_settle` acota `value_in`
    /// por arriba con este valor (+ el capital residual de la hucha): solo puede acuñar MENOS. Va AL FINAL
    /// (ningún offset previo se mueve): 473 → 481 (y 601 con `landed_prices`); `deposit_session_migrate` estira las anteriores.
    /// G5: incluye el USDC de capital que el commit mete en el vault (1:1), por la misma razón que `received_value_acc`.
    pub landed_value_at_commit: u64,

    /// G2-c (revisión N3, M1): el precio efectivo de CADA posición de la tabla leído en el lote de COMMIT
    /// (`SessionPrice`, 12 B × 10 = 120 B; @481). 481 → 601, AL FINAL. Desde G5 el commit trae todas las patas en un
    /// lote (`MAX_DEPOSIT_SWEEP_LEGS_PER_BATCH`), así que no hay lotes posteriores que valorar con ellos: quedan como foto
    /// del precio de cada posición en el commit.
    pub landed_prices: [SessionPrice; MAX_TOKENS_PER_VAULT],
}

impl DepositSession {
    /// 8 (Anchor disc) + 32 + 32 + 8 + 8 + 8 + 8 + 1 + 2 + 8 + 1
    /// + 2 + 1 + 2 + 32*MAX_TOKENS_PER_VAULT + 2 (max_loss_bps)
    /// + 8 (received_value_acc, S-4) + 1 (value_tracked, S-4) + 4 (generation, §3.4)
    /// + 1 (landed_tracked, G2-c; antes _reserved) + 8 + 8 (cortes de E, DT-E)
    /// + 8 (landed_value_at_commit, G2-c) + 12 × MAX_TOKENS_PER_VAULT (landed_prices, G2-c M1) = 601 bytes.
    /// Las piezas S-4, §3.4 y G2-c (el byte) se carvaron del _reserved (457 hasta la #55); DT-E añadió 16 B
    /// AL FINAL y G2-c otros 128, así que ningún offset previo se mueve (layout APPEND-ONLY): los clientes
    /// pasan el filtro a 601 y siguen buscando también las de los tamaños anteriores (457 del #55 vivo) hasta
    /// migrarlas con `deposit_session_migrate`.
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
        + 4 // generation (§3.4)
        + 1 // landed_tracked (G2-c; antes _reserved)
        + 8 // entry_fee_protocol_cut_usdc (DT-E)
        + 8 // entry_fee_creator_cut_usdc (DT-E)
        + 8 // landed_value_at_commit (G2-c)
        + 12 * MAX_TOKENS_PER_VAULT; // landed_prices (G2-c, M1)

    /// DT-E: tamaño de las sesiones creadas hasta la #55 (el programa VIVO). Ninguna instrucción las lee
    /// con el struct nuevo; `deposit_session_migrate` estira a `LEN` CUALQUIER tamaño anterior del layout
    /// (append-only: 457 del #55, 473 de DT-E) con los campos nuevos a 0.
    pub const LEGACY_LEN: usize = 457;

    /// DT-E: E reservada en la hucha USDC (la suma de los dos cortes). Ningún swap puede gastarla.
    pub fn entry_fee_reserved(&self) -> u64 {
        self.entry_fee_protocol_cut_usdc
            .saturating_add(self.entry_fee_creator_cut_usdc)
    }

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

    /// G5 (auditoría 2026-10-09, F1A-04): ¿deja este lote (`new_swept`) barridas TODAS las patas barribles? Se exige en el
    /// COMMIT (primer lote en dirección settle, `legs_swept == 0`): la reserva entera de participaciones fantasma (#44) entra
    /// con todo el depósito dentro del vault. Una sesión comprometida a medias antes del upgrade sigue en lotes. Predicado PURO
    /// (tabla de verdad en `g5_tests`), espejo de `WithdrawSession::abort_latch_complete`.
    pub fn commit_covers_all_legs(&self, new_swept: u16) -> bool {
        let sweepable = self.sweepable_mask();
        (self.legs_swept | new_swept) & sweepable == sweepable
    }

    /// G3 (2026-10-15, `DEPOSIT_UNSWEPT_ESCAPE_SECS`): ¿toca ya la ESCOTILLA? Una sesión que nadie barrió al vault
    /// (`legs_swept == 0`: el mismo cinturón que `dirty` y `drift`, una comprometida sigue asentando) y que lleva más de
    /// `DEPOSIT_UNSWEPT_ESCAPE_SECS` (10 min desde la #56) abierta solo se DEVUELVE a partir de este instante: `deposit_sweep_batch` la manda a dirección abort y la
    /// dirección la fija el reloj, no el caller. ÚNICA definición (tabla de verdad en `g3_tests`); el validador no
    /// adelanta el reloj, así que el umbral exacto lo fija el test de unidad. `saturating_sub`: un reloj que retrocede
    /// nunca abre la escotilla.
    pub fn unswept_escape_due(&self, now: i64) -> bool {
        self.legs_swept == 0 && now.saturating_sub(self.created_at) > DEPOSIT_UNSWEPT_ESCAPE_SECS
    }

    /// Auditoría CISO (P4, #56): ¿puede el INVERSOR pedir ya la devolución de su sesión con la entrada vetada? Sesión sin
    /// barrer (`legs_swept == 0`, el mismo cinturón que la escotilla), la ENTRADA del vault vetada por retiros en vuelo
    /// (`entry_blocked_by_withdraws`) y más de `DEPOSIT_VETOED_RETURN_SECS` desde el init; y solo si la pide el propio
    /// inversor (un tercero espera a la escotilla). Depende del reloj, de quién llama y de que la entrada siga vetada en
    /// ESTE barrido: si el veto ya se levantó, la sesión entra al vault. Predicado PURO (tabla de verdad en `g3_tests`).
    pub fn vetoed_return_due(&self, now: i64, caller_is_investor: bool, entry_vetoed: bool) -> bool {
        caller_is_investor
            && entry_vetoed
            && self.legs_swept == 0
            && now.saturating_sub(self.created_at) > DEPOSIT_VETOED_RETURN_SECS
    }

    /// G2-b (auditoría 2026-10-09, F1B-02; decisión C): una sesión con TODAS las patas triviales (USDC o
    /// peso 0: nada que swapear ni barrer) nunca pasa por el barrido de commit y, hasta G2-b, no contaba en
    /// `committed_deposits`: un rebalanceo entre su init y su settle cambiaba la exposición del vault y ella
    /// asentaba con la foto del init (opción gratuita a costa de los demás). Desde G2-b cuenta como
    /// COMPROMETIDA desde el init: el candado H-03 (#51) veta rebalance, cambio de cesta y cierre mientras
    /// esté abierta; la liberan su settle y su abort (su USDC está en su hucha, no en el vault: no reserva
    /// participaciones fantasma). Solo sesiones de la generación nueva (`generation != 0`): las anteriores
    /// al upgrade nunca sumaron el contador (y el checklist del día D exige 0 sesiones de depósito abiertas).
    /// Definición ÚNICA: la usan `deposit_init` (+1), `deposit_settle` y `deposit_abort` (-1).
    pub fn trivial_committed(&self) -> bool {
        self.leg_count > 0 && self.trivial_mask == self.full_mask() && self.generation != 0
    }

    /// G2-b / G2-c (cinturón de Kairo en el PR #63): el ÚNICO drenaje del +1 que `deposit_init` sumó en
    /// `committed_deposits` por una sesión trivial comprometida. Lo llaman las DOS salidas de una
    /// `DepositSession` (`deposit_settle` y `deposit_abort`); el test
    /// `las_unicas_salidas_de_la_sesion_son_settle_y_abort` fija que no hay otras y que las dos lo llaman
    /// (una salida nueva que no drenara dejaría el vault vetado para siempre, H-03). Devuelve si drenó.
    /// saturating_sub: nunca underflow.
    pub fn drain_committed_if_trivial(&self, vault_data: &mut [u8]) -> Result<bool> {
        if !self.trivial_committed() {
            return Ok(false);
        }
        let cur = vault_layout::read_committed_deposits(vault_data)?;
        vault_layout::write_committed_deposits(vault_data, cur.saturating_sub(1))?;
        Ok(true)
    }

    /// G2-c (F1A-03): cota superior de `value_in` en `deposit_settle` por lo que ATERRIZÓ valorado en el
    /// commit (+ el capital residual de la hucha, que entra en USDC 1:1). Sin valoración
    /// (`landed_tracked != 1`) devuelve `value_in` tal cual: solo puede acuñar MENOS, nunca más.
    pub fn cap_by_landed_value(&self, value_in: u64, landed_capital_residual: u64) -> u64 {
        if self.landed_tracked != 1 {
            return value_in;
        }
        value_in.min(self.landed_value_at_commit.saturating_add(landed_capital_residual))
    }
}

// Ceremonia USDC (§3.4): el tamaño es un CONTRATO con los filtros `dataSize` de los clientes
// y con los parsers del arnés: fijado en compilación. DT-E lo subió a 473; G2-c a 601.
const _: () = assert!(DepositSession::LEN == 601, "DepositSession::LEN debe ser 601 (G2-c)");

#[cfg(test)]
mod trivial_committed_tests {
    use super::*;

    fn sesion(leg_count: u8, trivial_mask: u16, generation: u32) -> DepositSession {
        DepositSession {
            investor: Pubkey::default(),
            vault: Pubkey::default(),
            amount_usdc: 0,
            total_shares_before: 0,
            tvl_before: 0,
            agg_cost_before: 0,
            leg_count,
            legs_completed: trivial_mask,
            created_at: 0,
            bump: 0,
            legs_swept: 0,
            aborting: 0,
            trivial_mask,
            leg_mints: [Pubkey::default(); MAX_TOKENS_PER_VAULT],
            max_loss_bps: 0,
            received_value_acc: 0,
            value_tracked: 0,
            generation,
            landed_tracked: 0,
            entry_fee_protocol_cut_usdc: 0,
            entry_fee_creator_cut_usdc: 0,
            landed_value_at_commit: 0,
            landed_prices: [SessionPrice::default(); MAX_TOKENS_PER_VAULT],
        }
    }

    #[test]
    fn trivial_comprometida_solo_si_todas_triviales_y_generacion_nueva() {
        assert!(sesion(2, 0b11, 7).trivial_committed(), "dos patas triviales, generacion nueva");
        assert!(sesion(1, 0b1, 1).trivial_committed(), "una pata (solo USDC)");
        assert!(!sesion(2, 0b01, 7).trivial_committed(), "una pata NO trivial: no cuenta aqui (cuenta en el barrido)");
        assert!(!sesion(2, 0b11, 0).trivial_committed(), "generacion 0 (anterior al upgrade): nunca sumo el contador");
        assert!(!sesion(0, 0, 7).trivial_committed(), "sin patas: degenerada, no cuenta");
    }

    #[test]
    fn el_drenaje_resta_uno_solo_a_la_trivial_comprometida_y_nunca_envuelve() {
        let mut vault = vec![0u8; crate::state::VaultState::LEN];
        vault_layout::write_committed_deposits(&mut vault, 2).unwrap();
        assert!(sesion(1, 0b1, 3).drain_committed_if_trivial(&mut vault).unwrap(), "trivial comprometida: drena");
        assert_eq!(vault_layout::read_committed_deposits(&vault).unwrap(), 1);
        assert!(!sesion(2, 0b01, 3).drain_committed_if_trivial(&mut vault).unwrap(), "no trivial: no toca");
        assert!(!sesion(1, 0b1, 0).drain_committed_if_trivial(&mut vault).unwrap(), "generación 0: no toca");
        assert_eq!(vault_layout::read_committed_deposits(&vault).unwrap(), 1, "intacto tras las dos que no drenan");
        vault_layout::write_committed_deposits(&mut vault, 0).unwrap();
        assert!(sesion(1, 0b1, 3).drain_committed_if_trivial(&mut vault).unwrap());
        assert_eq!(vault_layout::read_committed_deposits(&vault).unwrap(), 0, "saturating_sub: 0 se queda en 0");
    }

    #[test]
    fn la_cota_por_lo_aterrizado_solo_acuna_menos_y_solo_si_se_midio() {
        let mut s = sesion(1, 0, 3);
        s.landed_value_at_commit = 500;
        assert_eq!(s.cap_by_landed_value(1_000, 0), 1_000, "sin valoración (landed_tracked 0): value_in intacto");
        s.landed_tracked = 1;
        assert_eq!(s.cap_by_landed_value(1_000, 0), 500, "el precio bajó entre el swap y el commit: acota");
        assert_eq!(s.cap_by_landed_value(1_000, 300), 800, "el capital residual de la hucha entra 1:1");
        assert_eq!(s.cap_by_landed_value(400, 0), 400, "el precio subió: nunca acuña MÁS que value_in");
        s.landed_value_at_commit = u64::MAX;
        assert_eq!(s.cap_by_landed_value(1_000, 7), 1_000, "saturating_add: una cota desbordada no revierte ni recorta");
        // Con una cota que SÍ recortaría (500 < 1000): solo el valor 1 la activa (mutante 17, `!= 1` → `== 0`).
        s.landed_value_at_commit = 500;
        s.landed_tracked = 2;
        assert_eq!(s.cap_by_landed_value(1_000, 0), 1_000, "solo el valor 1 activa la cota (fail-safe ante bytes raros)");
    }

    #[test]
    fn el_precio_guardado_solo_vale_si_es_positivo_y_se_indexa_por_posicion() {
        // El mismo acceso que hace `deposit_sweep_batch` en un lote posterior: `snap.get(pos).and_then(|p| p.observed())`.
        let mut s = sesion(2, 0b01, 3);
        s.landed_prices[1] = SessionPrice { price: 2_000, expo: 0 };
        let leer = |s: &DepositSession, pos: usize| s.landed_prices.get(pos).and_then(|p| p.observed());
        assert_eq!(leer(&s, 0), None, "posición sin precio (trivial o no valorada)");
        assert_eq!(leer(&s, 1), Some(ObservedPrice { price: 2_000, expo: 0 }));
        assert_eq!(leer(&s, MAX_TOKENS_PER_VAULT), None, "fuera de la tabla: None, nunca pánico");
        s.landed_prices[1].price = -5;
        assert_eq!(leer(&s, 1), None, "un precio no positivo nunca valora");
        assert_eq!(SessionPrice::from_observed(ObservedPrice { price: 7, expo: -8 }), SessionPrice { price: 7, expo: -8 });
    }
}

#[cfg(test)]
mod g3_tests {
    use super::*;

    /// G3 (decisión de Juan, 13-oct-2026): el plazo tras el que CUALQUIERA puede devolver un depósito a medias baja de
    /// 30 a 10 minutos (el robot de sesiones colgadas cancela a los 10). La web y el robot leen este mismo número del IDL.
    #[test]
    fn el_plazo_de_devolucion_de_un_deposito_es_de_diez_minutos() {
        assert_eq!(DEPOSIT_SESSION_TIMEOUT_SECS, 10 * 60);
    }

    /// Tabla de verdad de la escotilla (revisión N3 de G3, must_fix 1; auditoría CISO P4, #56: 10 min, hasta la #56 24 h): el
    /// umbral es EXACTAMENTE `DEPOSIT_UNSWEPT_ESCAPE_SECS`; justo en el umbral todavía no; un reloj que retrocede nunca; y una
    /// sesión con alguna pata ya en el vault (`legs_swept != 0`) no se devuelve a ninguna edad.
    #[test]
    fn la_escotilla_abre_solo_pasados_10_minutos_y_solo_sin_barrer() {
        let t0 = 1_000_000i64;
        let sin_barrer = DepositSession { legs_swept: 0, created_at: t0, ..Default::default() };
        let barrida = DepositSession { legs_swept: 0b01, created_at: t0, ..Default::default() };
        assert_eq!(DEPOSIT_UNSWEPT_ESCAPE_SECS, 10 * 60);
        for edad in [0, DEPOSIT_VETOED_RETURN_SECS + 1, 9 * 60, DEPOSIT_UNSWEPT_ESCAPE_SECS] {
            assert!(!sin_barrer.unswept_escape_due(t0 + edad), "a {edad}s todavía no: {edad} <= 10 min");
        }
        for edad in [DEPOSIT_UNSWEPT_ESCAPE_SECS + 1, 23 * 60 * 60, 30 * 24 * 60 * 60] {
            assert!(sin_barrer.unswept_escape_due(t0 + edad), "a {edad}s ya toca");
            assert!(!barrida.unswept_escape_due(t0 + edad), "con una pata ya en el vault, nunca ({edad}s)");
        }
        assert!(!sin_barrer.unswept_escape_due(t0 - 1), "un reloj que retrocede nunca abre la escotilla");
        assert!(!sin_barrer.unswept_escape_due(i64::MIN));
    }

    /// Auditoría CISO (P4, #56): la devolución a petición del inversor vetado exige las CUATRO condiciones: que la pida el
    /// inversor, la entrada vetada, la sesión sin barrer y más de 2 min (justo en el umbral, todavía no).
    #[test]
    fn la_devolucion_del_inversor_vetado_exige_las_cuatro_condiciones() {
        assert_eq!(DEPOSIT_VETOED_RETURN_SECS, 2 * 60);
        let t0 = 1_000_000i64;
        let s = DepositSession { legs_swept: 0, created_at: t0, ..Default::default() };
        let barrida = DepositSession { legs_swept: 0b01, created_at: t0, ..Default::default() };
        let pasado = t0 + DEPOSIT_VETOED_RETURN_SECS + 1;
        assert!(s.vetoed_return_due(pasado, true, true));
        assert!(s.vetoed_return_due(t0 + DEPOSIT_UNSWEPT_ESCAPE_SECS + 1, true, true), "también después de la escotilla");
        assert!(!s.vetoed_return_due(t0 + DEPOSIT_VETOED_RETURN_SECS, true, true), "justo a los 2 min todavía no");
        assert!(!s.vetoed_return_due(pasado, false, true), "un tercero, nunca: espera a la escotilla");
        assert!(!s.vetoed_return_due(pasado, true, false), "sin veto de entrada, nunca: el commit entra");
        assert!(!barrida.vetoed_return_due(pasado, true, true), "con una pata ya en el vault, nunca");
        assert!(!s.vetoed_return_due(t0 - 1, true, true), "un reloj que retrocede, nunca");
    }
}

#[cfg(test)]
mod g5_tests {
    use super::*;
    use crate::constants::{MAX_DEPOSIT_SWEEP_LEGS_PER_BATCH, MAX_TOKENS_PER_VAULT_EFFECTIVE};

    /// G5 (auditoría 2026-10-09, F1A-04): tabla de verdad del commit ATÓMICO. Cuenta solo lo barrible (pata completada y no
    /// trivial): la trivial (USDC o peso 0) no tiene hucha, y una pata ya barrida (sesión comprometida a medias antes del
    /// upgrade) ya está en el vault.
    #[test]
    fn el_commit_tiene_que_cubrir_todas_las_patas_barribles() {
        let tres = DepositSession { leg_count: 3, legs_completed: 0b111, trivial_mask: 0b100, ..Default::default() };
        assert!(tres.commit_covers_all_legs(0b011), "las dos barribles");
        assert!(tres.commit_covers_all_legs(0b111), "el bit de la trivial no estorba");
        for parcial in [0b000u16, 0b001, 0b010, 0b100] {
            assert!(!tres.commit_covers_all_legs(parcial), "lote parcial {parcial:#b}: no compromete");
        }
        let siete = DepositSession { leg_count: 7, legs_completed: 0x7f, ..Default::default() };
        assert!(siete.commit_covers_all_legs(0x7f), "la cesta máxima en un lote");
        assert!(!siete.commit_covers_all_legs(0x0f), "el lote de 4 de antes de G5 ya no compromete");
        let a_medias = DepositSession { leg_count: 7, legs_completed: 0x7f, legs_swept: 0x0f, ..Default::default() };
        assert!(a_medias.commit_covers_all_legs(0x70), "con lo ya barrido, el resto completa");
        assert_eq!(MAX_DEPOSIT_SWEEP_LEGS_PER_BATCH as usize, MAX_TOKENS_PER_VAULT_EFFECTIVE, "una cesta entera cabe en un lote");
    }
}

#[cfg(test)]
mod salidas_de_la_sesion_tests {
    /// Cinturón (Kairo, PR #63): las ÚNICAS instrucciones que CIERRAN una `DepositSession` (`close =` en el
    /// `#[account(...)]` de una cuenta tipada `Account<'info, DepositSession>`) son `deposit_settle` y
    /// `deposit_abort`, y las dos llaman al drenaje único `drain_committed_if_trivial`. Una salida nueva que no
    /// drenara el contador dejaría el vault vetado para siempre (H-03): este test la caza en `cargo test`, antes
    /// de la batería. Lee el código fuente del crate (ruta fija del manifiesto); no depende del orden de los módulos.
    #[test]
    fn las_unicas_salidas_de_la_sesion_son_settle_y_abort() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/instructions");
        let mut cierran = Vec::new();
        let mut leidos = 0usize;
        let mut barrido_visto = false;
        let mut abort_visto = false;
        for entry in std::fs::read_dir(&dir).expect("src/instructions legible") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            leidos += 1;
            let nombre = path.file_name().unwrap().to_str().unwrap().to_string();
            // Solo CÓDIGO: un comentario que mencione la llamada o un `close` no cuenta (juez corto de G2-c).
            let src = sin_comentarios(&std::fs::read_to_string(&path).unwrap());
            if cierra_deposit_session(&src) {
                assert!(
                    src.contains("drain_committed_if_trivial("),
                    "{nombre} cierra una DepositSession y no llama al drenaje único del contador"
                );
                cierran.push(nombre.clone());
            }
            // Ninguna otra instrucción vacía ni reasigna la sesión a mano (un «cierre manual» sin `close =`):
            // una línea que nombre `deposit_session` no puede tocar sus lamports ni hacer `assign`.
            if nombre != "deposit_settle.rs" && nombre != "deposit_abort.rs" {
                for linea in src.lines() {
                    if linea.contains("deposit_session")
                        && (linea.contains("try_borrow_mut_lamports") || linea.contains(".assign(") || linea.contains("sub_lamports("))
                    {
                        panic!("{nombre} toca los lamports o el dueño de la DepositSession fuera de settle/abort: {linea}");
                    }
                }
            }
            // G3: el barrido devuelve al caller, del rent de las huchas que cierra, lo que ADELANTÓ por las cuentas de
            // destino que faltaban. Es el ÚNICO movimiento de lamports de la sesión fuera de settle/abort: exactamente
            // DOS escrituras, con estos dos patrones fijos (revisión N3: contar, no buscar una subcadena).
            if nombre == "deposit_sweep_batch.rs" {
                barrido_visto = true;
                let mut escrituras: Vec<&str> = src
                    .lines()
                    .map(str::trim)
                    .filter(|l| {
                        l.contains("try_borrow_mut_lamports")
                            || l.contains("lamports.borrow_mut(")
                            || l.contains("set_lamports(")
                            || l.contains("sub_lamports(")
                            || l.contains("add_lamports(")
                    })
                    .collect();
                escrituras.sort();
                assert_eq!(
                    escrituras,
                    vec![
                        "**caller_ai.try_borrow_mut_lamports()? = caller_lamports.checked_add(adelantado_total).ok_or(WagonError::MathOverflow)?;",
                        "**session_ai.try_borrow_mut_lamports()? = sesion_lamports.checked_sub(adelantado_total).ok_or(WagonError::MathOverflow)?;",
                    ],
                    "deposit_sweep_batch.rs solo puede mover lamports en el reembolso de lo adelantado (dos escrituras fijas)"
                );
            }
            // G3-B1a: `deposit_abort` devuelve al caller lo que ADELANTÓ por la cuenta USDC del inversor que faltaba, del rent
            // de la hucha que cierra. Mismo cinturón que el barrido: exactamente DOS escrituras fijas, ninguna otra.
            if nombre == "deposit_abort.rs" {
                abort_visto = true;
                let mut escrituras: Vec<&str> = src
                    .lines()
                    .map(str::trim)
                    .filter(|l| {
                        l.contains("try_borrow_mut_lamports")
                            || l.contains("lamports.borrow_mut(")
                            || l.contains("set_lamports(")
                            || l.contains("sub_lamports(")
                            || l.contains("add_lamports(")
                    })
                    .collect();
                escrituras.sort();
                assert_eq!(
                    escrituras,
                    vec![
                        "**caller_ai.try_borrow_mut_lamports()? =",
                        "**session_ai.try_borrow_mut_lamports()? =",
                    ],
                    "deposit_abort.rs solo puede mover lamports en el reembolso de lo adelantado (dos escrituras fijas)"
                );
                assert!(
                    src.contains("caller_lamports.checked_add(adelantado).ok_or(WagonError::MathOverflow)?;")
                        && src.contains("sesion_lamports.checked_sub(adelantado).ok_or(WagonError::MathOverflow)?;"),
                    "deposit_abort.rs: el reembolso suma al caller y resta a la sesión EXACTAMENTE `adelantado`"
                );
            }
        }
        assert!(leidos > 30, "se leyeron {leidos} instrucciones: la ruta del manifiesto no es la esperada");
        assert!(barrido_visto, "deposit_sweep_batch.rs no se leyó: el cinturón del reembolso no se ha ejecutado");
        assert!(abort_visto, "deposit_abort.rs no se leyó: el cinturón del reembolso del abort no se ha ejecutado");
        cierran.sort();
        assert_eq!(cierran, vec!["deposit_abort.rs".to_string(), "deposit_settle.rs".to_string()]);
    }

    /// Quita los comentarios de línea (`//…` y `///…`) para que el cinturón mire solo código.
    fn sin_comentarios(src: &str) -> String {
        src.lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// ¿Lleva el texto un `close` seguido (con o sin espacios) de `=`?
    fn tiene_close_eq(texto: &str) -> bool {
        let mut desde = 0usize;
        while let Some(i) = texto[desde..].find("close") {
            let resto = texto[desde + i + 5..].trim_start();
            if resto.starts_with('=') {
                return true;
            }
            desde += i + 5;
        }
        false
    }

    /// ¿Declara el fichero una cuenta `Account<'info, DepositSession>` cuyo `#[account(...)]` lleve `close =`?
    /// El atributo de un campo es el último `#[account(` antes de su declaración; entre los dos no puede
    /// haber otro campo (`pub `), o el atributo sería de otro.
    fn cierra_deposit_session(src: &str) -> bool {
        let mut desde = 0usize;
        while let Some(pos) = src[desde..].find("Account<'info, DepositSession>") {
            let campo = desde + pos;
            if let Some(attr) = src[..campo].rfind("#[account(") {
                let entre = &src[attr..campo];
                if entre.matches("pub ").count() <= 1 && tiene_close_eq(entre) {
                    return true;
                }
            }
            desde = campo + 1;
        }
        false
    }

    #[test]
    fn el_cinturon_distingue_codigo_de_comentarios_y_close_sin_espacios() {
        assert!(tiene_close_eq("mut, close= refund_target"));
        assert!(tiene_close_eq("close =x"));
        assert!(!tiene_close_eq("closed_at = 3"), "`closed` no es `close =`");
        let con_comentario = "// close = aqui no cuenta\n    #[account(mut)]\n    pub deposit_session: Box<Account<'info, DepositSession>>,";
        assert!(!cierra_deposit_session(&sin_comentarios(con_comentario)));
        let real = "#[account(mut, close=refund_target)]\n    pub deposit_session: Box<Account<'info, DepositSession>>,";
        assert!(cierra_deposit_session(real));
    }
}
