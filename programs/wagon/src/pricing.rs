//! Upgrade #30 — pricing utilities for TVL mark-to-market.
//!
//! Last-swap execution-price cache. Every Jupiter leg the
//! vault executes (deposit buys, withdraw sells) writes the realised price
//! into the vault's reserved tail, decimals-agnostically (USDC atoms per
//! 1e9 token atoms). This cache is the valuation fallback for mints without
//! a Pyth feed (META/AVICI/UMBRA & co.) with
//! a 24 h freshness window enforced at read time.
//!
//! TODO(#30): also hook `sweep_to_usdc` / `rebalance_swap` legs into the
//! cache. Deposit/withdraw legs already touch every allocation pro-rata,
//! so those two are an optimisation, not a correctness requirement.

use anchor_lang::prelude::*;

use crate::state::vault_layout as vlayout;

/// Mint decimals live at offset 44 in both classic SPL Token and
/// Token-2022 mint accounts (identical 82-byte base layout).
const MINT_DECIMALS_OFFSET: usize = 44;

/// Compute price_q = usdc_atoms * 1e9 / token_atoms, saturating to None on
/// degenerate inputs (zero amounts, dust swaps that overflow the u64 scale).
/// A None simply skips the cache update — never aborts the swap.
pub fn price_q_from_fill(usdc_atoms: u64, token_atoms: u64) -> Option<u64> {
    if usdc_atoms == 0 || token_atoms == 0 {
        return None;
    }
    let q = (usdc_atoms as u128)
        .checked_mul(vlayout::LAST_SWAP_PRICE_SCALE)?
        .checked_div(token_atoms as u128)?;
    if q == 0 {
        return None;
    }
    u64::try_from(q).ok()
}

/// Best-effort cache update after a filled Jupiter leg. Writes the realised
/// execution price and the mint decimals (read from the already-validated
/// mint AccountInfo the swap batch carries). Failures to compute a sane
/// price are silently skipped; layout errors still propagate.
pub fn cache_leg_fill(
    vault_ai: &AccountInfo,
    leg_idx: usize,
    usdc_atoms: u64,
    token_atoms: u64,
    mint_ai: &AccountInfo,
) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    // u32 unix seconds is fine until 2106; clamp negatives defensively.
    let ts: u32 = u32::try_from(now.max(0)).unwrap_or(u32::MAX);

    let decimals: Option<u8> = {
        let mint_data = mint_ai.try_borrow_data()?;
        if mint_data.len() > MINT_DECIMALS_OFFSET {
            Some(mint_data[MINT_DECIMALS_OFFSET])
        } else {
            None
        }
    };

    let mut data = vault_ai.try_borrow_mut_data()?;
    if let Some(d) = decimals {
        vlayout::write_alloc_decimals(&mut data, leg_idx, d)?;
    }
    if let Some(q) = price_q_from_fill(usdc_atoms, token_atoms) {
        vlayout::write_alloc_last_swap(&mut data, leg_idx, q, ts)?;
    }
    Ok(())
}

// ============================================================================
// Phase 3b — mark-to-market valuation (oracle + cache)
// ============================================================================

use anchor_lang::AccountDeserialize;
use anchor_spl::associated_token::get_associated_token_address_with_program_id;
use pyth_solana_receiver_sdk::price_update::PriceUpdateV2;

use crate::constants::{
    BPS_DENOMINATOR, COMMIT_ORACLE_MAX_AGE_MAX_SECS, COMMIT_ORACLE_MAX_AGE_MIN_SECS, FEED_REGISTRY_SEED,
    LAST_SWAP_MAX_AGE_SECS, ORACLE_MAX_AGE_SECS, ORACLE_MAX_CONF_BPS, PYTH_PUSH_ORACLE_V2, PYTH_PUSH_SHARD,
    PYTH_RECEIVER_V2, USDC_MINT,
};
use crate::errors::WagonError;
use crate::state::feed_registry::{FEED_CLASS_MASK, FEED_FLAG_COMPOSED_RR, FEED_FLAG_NO_ORACLE};
use crate::state::feed_registry_layout as flayout;
use crate::token_io::{
    read_mint_ui_multiplier, read_token_amount, TOKEN_2022_PROGRAM_ID, UI_MULTIPLIER_ONE, UI_MULTIPLIER_SCALE,
};

/// Wrapped SOL mint (needed to resolve the SOL/USD feed for composed
/// redemption-rate pricing, e.g. JupSOL).
pub const WSOL_MINT: Pubkey =
    anchor_lang::solana_program::pubkey!("So11111111111111111111111111111111111111112");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservedPrice {
    pub price: i64,
    pub expo: i32,
}

/// G2-c (auditoría 2026-10-09, F1A-03): el precio de una pata de la tabla TAL COMO lo leyó el m2m ESTRICTO
/// (mismo `read_pyth_price`, mismas puertas de frescura y confianza por clase), para que el commit del
/// depósito valore con ÉL lo que aterriza (numerador y denominador de la acuñación al mismo precio).
/// `sol` solo en los feeds compuestos (redemption rate × SOL/USD). `mult` (G2-d, F6A-01): multiplicador
/// EFECTIVO de `ScaledUiAmount` del mint en punto fijo (`UI_MULTIPLIER_SCALE`), leído en vivo;
/// `UI_MULTIPLIER_ONE` en los mints clásicos o sin la extensión.
pub struct LegPrice {
    pub obs: ObservedPrice,
    pub sol: Option<ObservedPrice>,
    pub mult: u128,
}

impl LegPrice {
    /// `amount` átomos del mint de la pata (`decimals`) → átomos de USDC (6 dec) con este precio y el
    /// multiplicador de la pata (el oráculo cotiza por token MOSTRADO = átomos × m).
    pub fn value(&self, amount: u64, decimals: u8) -> Result<u64> {
        let base = match &self.sol {
            Some(sol) => value_from_composed(amount, &self.obs, sol, decimals)?,
            None => value_from_oracle(amount, &self.obs, decimals)?,
        };
        apply_ui_multiplier(base, self.mult)
    }

    /// G2-c (revisión N3, M1): el precio EFECTIVO de la pata en UNA mantisa y UN exponente, para guardarlo en la
    /// `DepositSession` en el commit y valorar con él los lotes posteriores SIN oráculo. Pyth plano: tal cual.
    /// Compuesto (redemption rate × SOL/USD): el producto de las mantisas en i128 con la suma de los exponentes;
    /// si no cabe en i64 se divide la mantisa por 10 y se sube el exponente (pierde el último dígito de 19 o más:
    /// error relativo menor que 1e-18, irrelevante en átomos de USDC). `value_from_oracle` con el efectivo es la
    /// MISMA fórmula que `value_from_composed` (`scaled_value(amount, rr × sol, 6 + e_rr + e_sol − dec)`).
    /// G2-d: el multiplicador `ScaledUiAmount` entra TAMBIÉN en la mantisa (escala 1e9 ⇒ el exponente baja 9),
    /// así los lotes posteriores valoran átomos crudos con el precio YA multiplicado sin leer nada más; si el
    /// producto no cabe en i128 la mantisa se recorta ANTES (hacia abajo), como en el bucle final. Paridad de
    /// dominio con `value()` (revisión N3): tras plegar m se recuperan los ceros EXACTOS de la mantisa y, si el
    /// exponente sigue por debajo de `EFFECTIVE_MIN_EXPO`, se recorta hacia abajo: así `scaled_value` valora el
    /// precio efectivo de cualquier mint de hasta 18 decimales siempre que valoró el del m2m (el numerador del
    /// commit nunca falla donde el denominador pasó).
    pub fn effective(&self) -> ObservedPrice {
        let mut m: i128 = self.obs.price as i128;
        let mut e = self.obs.expo;
        if let Some(sol) = &self.sol {
            m *= sol.price as i128; // dos i64 positivos: cabe en i128
            e += sol.expo;
        }
        if self.mult != UI_MULTIPLIER_ONE {
            let mult = self.mult as i128; // ≤ UI_MULTIPLIER_MAX × 1e9 = 1e15
            while m.checked_mul(mult).is_none() {
                m /= 10;
                e += 1;
            }
            m *= mult;
            e -= 9;
            while e < EFFECTIVE_MIN_EXPO && m % 10 == 0 {
                m /= 10; // exacto
                e += 1;
            }
            while e < EFFECTIVE_MIN_EXPO {
                m /= 10; // hacia abajo
                e += 1;
            }
        }
        while m > i64::MAX as i128 {
            m /= 10;
            e += 1;
        }
        ObservedPrice { price: m as i64, expo: e }
    }
}

/// G2-d: `value` (átomos de USDC) × multiplicador en punto fijo (escala 1e9), truncado hacia abajo: NUNCA
/// de más; el error viene del truncado de m (absoluto < 1e-9 en m, es decir relativo < 1e-9 / m) más el
/// redondeo previo de `value` multiplicado por m (hasta ceil(m) átomos). Con `UI_MULTIPLIER_ONE` devuelve
/// `value` tal cual: los mints clásicos siguen byte-idénticos a antes de G2-d.
pub fn apply_ui_multiplier(value: u64, mult: u128) -> Result<u64> {
    if mult == UI_MULTIPLIER_ONE {
        return Ok(value);
    }
    let v = (value as u128)
        .checked_mul(mult)
        .ok_or(WagonError::MathOverflow)?
        / UI_MULTIPLIER_SCALE;
    u64::try_from(v).map_err(|_| error!(WagonError::MathOverflow))
}

/// G2-d (revisión N3): exponente MÍNIMO del precio efectivo plegado con m. `scaled_value` exige
/// `6 + expo − decimales ∈ [−30, 30]`; con −18 valora cualquier mint de hasta 18 decimales.
pub const EFFECTIVE_MIN_EXPO: i32 = -18;

/// G2-c: precio observado por POSICIÓN de la tabla de allocations (`None` = pata trivial, USDC o peso 0,
/// que el m2m no valora ni lleva cuenta de precio).
pub type LegPrices = [Option<LegPrice>; crate::constants::MAX_TOKENS_PER_VAULT];

/// CISO-P3 (#56): dirección de la cuenta de precio OFICIAL de un feed, la PDA del programa push de Pyth con
/// `[shard 0, feed_id]` (ver `PYTH_PUSH_ORACLE_V2`). Fuera de línea para no cargar la pila de los handlers (gotcha 69).
#[inline(never)]
fn official_price_account(feed_id: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[&PYTH_PUSH_SHARD.to_le_bytes(), feed_id], &PYTH_PUSH_ORACLE_V2).0
}

/// Auditoría CISO (P3, #56): valores admitidos de `ProtocolConfig::commit_oracle_max_age_secs`: 0 (la edad de la clase) o
/// entre `COMMIT_ORACLE_MAX_AGE_MIN_SECS` y `COMMIT_ORACLE_MAX_AGE_MAX_SECS`.
pub fn commit_oracle_max_age_valid(max_age_secs: u16) -> bool {
    max_age_secs == 0 || (COMMIT_ORACLE_MAX_AGE_MIN_SECS..=COMMIT_ORACLE_MAX_AGE_MAX_SECS).contains(&max_age_secs)
}

/// Auditoría CISO (P3, #56): edad máxima del precio de una lectura. `cap_secs` = 0 → la de la clase (`ORACLE_MAX_AGE_SECS`);
/// si no, la menor de las dos (el re-precio del commit con `commit_oracle_max_age_secs`).
fn effective_max_age(class_idx: usize, cap_secs: u16) -> u64 {
    let class_age = ORACLE_MAX_AGE_SECS[class_idx & 3];
    if cap_secs == 0 {
        class_age
    } else {
        class_age.min(cap_secs as u64)
    }
}

/// Validate a Pyth `PriceUpdateV2` account and extract a usable price.
/// Checks: receiver-program ownership, discriminator, feed id match, full
/// verification + staleness (via the SDK), positive price, confidence width,
/// and that the account is the feed's OFFICIAL price account. `max_age_cap_secs`: 0 = the class staleness
/// window; otherwise the smaller of the two (`effective_max_age`).
fn read_pyth_price(
    price_ai: &AccountInfo,
    feed_id: &[u8; 32],
    class_idx: usize,
    clock: &Clock,
    max_age_cap_secs: u16,
) -> Result<ObservedPrice> {
    // CISO-P3 (#56): solo el receptor de la generación nueva de Pyth (ver constants.rs). Con una sola generación, cada feed
    // tiene una sola cuenta oficial (la comprobación del final de esta función).
    require!(
        *price_ai.owner == PYTH_RECEIVER_V2,
        WagonError::InvalidPriceAccount
    );
    let update = {
        let data = price_ai.try_borrow_data()?;
        PriceUpdateV2::try_deserialize(&mut &data[..])
            .map_err(|_| error!(WagonError::InvalidPriceAccount))?
    };
    let max_age = effective_max_age(class_idx, max_age_cap_secs);
    let p = update
        .get_price_no_older_than(clock, max_age, feed_id)
        .map_err(|_| error!(WagonError::StaleOrUntrustedPrice))?;
    require!(p.price > 0, WagonError::StaleOrUntrustedPrice);

    let lhs = (p.conf as u128).saturating_mul(10_000);
    let rhs = (p.price as u128).saturating_mul(ORACLE_MAX_CONF_BPS[class_idx & 3] as u128);
    require!(lhs <= rhs, WagonError::PriceConfidenceTooWide);

    // CISO-P3 (#56): la cuenta tiene que ser la OFICIAL del feed esperado. Pyth solo la actualiza con una publicación
    // posterior a la que guarda, así que nadie puede pasar una actualización más vieja que la vigente aunque sea válida,
    // fresca y del mismo feed. Va al final para que una cuenta de otro feed, rancia o ancha siga dando su error de siempre.
    require!(
        *price_ai.key == official_price_account(feed_id),
        WagonError::OraclePriceAccountNotCanonical
    );

    Ok(ObservedPrice {
        price: p.price,
        expo: p.exponent,
    })
}

/// SOL/USD for the vault-creation fee (upgrade #35). Class-2 gates
/// (300 s staleness / 200 bps confidence): the fee tolerates a slightly
/// older price, and the wider window avoids blocking vault creation on a
/// brief publisher gap. Real SOL/USD confidence is far tighter anyway.
pub fn read_sol_usd_price(price_ai: &AccountInfo, clock: &Clock) -> Result<ObservedPrice> {
    read_pyth_price(price_ai, &crate::constants::SOL_USD_FEED_ID, 2, clock, 0)
}

/// micro-USD (6 dec) -> lamports (9 dec) at the observed SOL/USD price:
/// lamports = usd_micros * 10^(3 - expo) / price (Pyth SOL/USD expo <= 0).
/// With the ceilings in play (fee <= 10 USD, expo >= -12) the u128 math
/// cannot overflow; checked ops guard the rest.
pub fn usd_micros_to_lamports(usd_micros: u64, sol: &ObservedPrice) -> Result<u64> {
    require!(sol.price > 0, WagonError::StaleOrUntrustedPrice);
    require!((-12..=0).contains(&sol.expo), WagonError::MathOverflow);
    let scale = 10u128.pow((3 - sol.expo) as u32);
    let num = (usd_micros as u128)
        .checked_mul(scale)
        .ok_or(WagonError::MathOverflow)?;
    u64::try_from(num / (sol.price as u128)).map_err(|_| error!(WagonError::MathOverflow))
}

/// balance (token atoms, `decimals` dec) × oracle price → USDC atoms (6 dec).
pub fn value_from_oracle(balance: u64, obs: &ObservedPrice, decimals: u8) -> Result<u64> {
    scaled_value(balance, obs.price as u128, 6 + obs.expo - decimals as i32)
}

/// Composed redemption-rate pricing: balance × RR × SOL/USD → USDC atoms.
pub fn value_from_composed(
    balance: u64,
    rr: &ObservedPrice,
    sol: &ObservedPrice,
    decimals: u8,
) -> Result<u64> {
    let raw = (rr.price as u128)
        .checked_mul(sol.price as u128)
        .ok_or(WagonError::MathOverflow)?;
    scaled_value(balance, raw, 6 + rr.expo + sol.expo - decimals as i32)
}

/// balance × cached last-swap price_q → USDC atoms.
pub fn value_from_cache(balance: u64, price_q: u64) -> Result<u64> {
    let v = (balance as u128)
        .checked_mul(price_q as u128)
        .ok_or(WagonError::MathOverflow)?
        / vlayout::LAST_SWAP_PRICE_SCALE;
    u64::try_from(v).map_err(|_| error!(WagonError::MathOverflow))
}

fn scaled_value(balance: u64, raw_price: u128, net_expo: i32) -> Result<u64> {
    if balance == 0 {
        return Ok(0);
    }
    require!((-30..=30).contains(&net_expo), WagonError::MathOverflow);
    let mut v = (balance as u128)
        .checked_mul(raw_price)
        .ok_or(WagonError::MathOverflow)?;
    if net_expo >= 0 {
        v = v
            .checked_mul(10u128.pow(net_expo as u32))
            .ok_or(WagonError::MathOverflow)?;
    } else {
        v /= 10u128.pow((-net_expo) as u32);
    }
    u64::try_from(v).map_err(|_| error!(WagonError::MathOverflow))
}

/// Verify that `ata_ai` is THE associated token account of (vault, mint).
/// Primero, la cuenta tiene que ser de uno de los dos programas de tokens (SPL Token o Token-2022); una cuenta
/// de cualquier otro programa se rechaza antes de derivar nada. Después, la dirección esperada se deriva con
/// ESE programa de tokens: la derivación ATA ata la dirección al programa, así que una cuenta de tokens
/// falsificada (mint y dueño correctos, dirección distinta) nunca coincide.
fn verify_alloc_ata(ata_ai: &AccountInfo, vault_key: &Pubkey, mint: &Pubkey) -> Result<()> {
    let token_program = ata_ai.owner;
    require!(
        *token_program == anchor_spl::token::spl_token::ID || *token_program == TOKEN_2022_PROGRAM_ID,
        WagonError::LegDestAtaMismatch
    );
    let expected = get_associated_token_address_with_program_id(vault_key, mint, token_program);
    require_keys_eq!(ata_ai.key(), expected, WagonError::LegDestAtaMismatch);
    Ok(())
}

/// STRICT mark-to-market TVL (deposit_init, mark_tvl y, con precios, el commit de deposit_sweep_batch).
///
/// remaining_accounts layout (length is EXACT, derived from registry flags):
///   [0]                        FeedRegistry PDA
///   [1 + 3k, 2 + 3k, 3 + 3k]   (mint_i, vault_ata_i, price_update_i) per allocation with
///                              mint != USDC and weight > 0, in allocation order (k = trio index).
///                              G2-d: el mint viaja como cuenta (pinned por clave a la tabla) para leer
///                              EN VIVO su multiplicador `ScaledUiAmount`; hasta G2-d eran pares (ata, price).
///   [base_len]                 SOL/USD PriceUpdateV2, iff any allocation feed
///                              has the composed-RR flag
///
/// Ceremonia #40: la cola de Switchboard + SlotHashes ya NO viajan al final
/// (el bit 3 pasó a significar «sin oráculo utilizable» y falla cerrado aquí),
/// así que el layout vuelve a ser `base_len` o `base_len + 1`.
///
/// H-4 (auditoría 2026-06-29): el camino ESTRICTO exige ORÁCULO para todo
/// token con balance > 0. El caché last-swap ya NO se acepta aquí: su
/// semilla la controla quien ejecuta el swap (ruta elegida por el caller,
/// min_out propio) ⇒ precio manipulable ⇒ mispricing de shares para el
/// siguiente depositante. Sin entrada en el registry, o sin decimals
/// cacheados, y con balance > 0 ⇒ `NoReliablePrice` — bloquear depósitos es
/// el comportamiento de diseño ("sin precio fiable"). El caché queda SOLO
/// para el camino lenient (writeback de retiros, display), que nunca decide
/// precios de shares. Withdrawals never call this function.
pub fn compute_tvl_m2m_strict(
    vault_ai: &AccountInfo,
    vault_key: &Pubkey,
    idle_usdc: u64,
    usdc_mint: &Pubkey,
    remaining: &[AccountInfo],
) -> Result<u64> {
    m2m_strict_inner(vault_ai, vault_key, idle_usdc, usdc_mint, remaining, None, 0)
}

/// G2-c (F1A-03): como `compute_tvl_m2m_strict` (MISMO layout de `remaining`, MISMAS puertas) y además
/// devuelve el precio observado de CADA pata no trivial, también de las que hoy tienen saldo 0 en el vault:
/// el barrido de commit del depósito valora con él lo que ATERRIZA, que aún no está en la ATA del vault.
/// Única diferencia con el estricto: aquí el precio se lee SIEMPRE, así que una pata sin saldo con precio
/// rancio o cuenta inválida también falla cerrado (el depósito exige oráculo fresco; el barrido es
/// permissionless y reintentable, los tokens siguen en la hucha de la sesión). Los otros dos consumidores
/// del m2m estricto (`deposit_init`, `mark_tvl`) comparten el cuerpo y el layout. Auditoría CISO (P3, #56):
/// `max_age_cap_secs` es `ProtocolConfig::commit_oracle_max_age_secs` (solo lo pasa el commit; 0 = la edad de la clase).
pub fn compute_tvl_m2m_strict_with_prices(
    vault_ai: &AccountInfo,
    vault_key: &Pubkey,
    idle_usdc: u64,
    usdc_mint: &Pubkey,
    remaining: &[AccountInfo],
    max_age_cap_secs: u16,
) -> Result<(u64, LegPrices)> {
    let mut prices: LegPrices = Default::default();
    let m2m = m2m_strict_inner(vault_ai, vault_key, idle_usdc, usdc_mint, remaining, Some(&mut prices), max_age_cap_secs)?;
    Ok((m2m, prices))
}

/// Cuerpo compartido del m2m ESTRICTO. `collect`: G2-c, dónde dejar el precio de cada pata (y entonces
/// leerlo aunque la pata tenga saldo 0); `None` = comportamiento histórico exacto (una pata a 0 no lee precio).
fn m2m_strict_inner(
    vault_ai: &AccountInfo,
    vault_key: &Pubkey,
    idle_usdc: u64,
    usdc_mint: &Pubkey,
    remaining: &[AccountInfo],
    mut collect: Option<&mut LegPrices>,
    max_age_cap_secs: u16,
) -> Result<u64> {
    let clock = Clock::get()?;
    require!(!remaining.is_empty(), WagonError::MissingPriceAccounts);

    // [0] FeedRegistry PDA — address + ownership pinned.
    let registry_ai = &remaining[0];
    let (expected_registry, _) = Pubkey::find_program_address(&[FEED_REGISTRY_SEED], &crate::ID);
    require_keys_eq!(
        registry_ai.key(),
        expected_registry,
        WagonError::InvalidPriceAccount
    );
    require_keys_eq!(
        *registry_ai.owner,
        crate::ID,
        WagonError::InvalidPriceAccount
    );
    let registry_data = registry_ai.try_borrow_data()?;

    let allocation_count = {
        let data = vault_ai.try_borrow_data()?;
        vlayout::read_allocation_count(&data)?
    } as usize;

    // Pre-pass over the basket: trio count plus WHETHER the SOL/USD tail is
    // needed, decided by REGISTRY flags — the same rule the frontend applies
    // when building the list, so the expected length is EXACT. Layout (G2-d):
    //   [0] registry · (mint_i, ata_i, price_i)×k · [SOL/USD]?
    let mut trio_count = 0usize;
    let mut needs_sol = false;
    for i in 0..allocation_count {
        let (mint, weight_bps) = {
            let data = vault_ai.try_borrow_data()?;
            (
                vlayout::read_allocation_mint(&data, i)?,
                vlayout::read_allocation_weight_bps(&data, i)?,
            )
        };
        // Ceremonia #48 (H3, Opción B): una pata a peso 0 es un slot trivial que
        // `deposit_init:373` y `withdraw_init:270` YA saltan; valorarla aquí era la
        // asimetría que dejaba que una DONACIÓN directa a su ATA inflara el TVL y
        // diluyera al que deposita. Se salta igual que la USDC — MISMO predicado y
        // MISMA posición que el bucle de valoración de abajo, o trio_count/k/
        // expected_len se desincronizan. Vaults reales (todas las patas peso>0) →
        // byte-idéntico. Los TRES caminos que FINANCIAN una pata a peso 0 están
        // vetados: `rebalance` (#47, 6179), `restructure_init` (#47, 6179) y
        // `rebalance_swap` (ceremonia 2026-08, 6179) → el único origen de una pata
        // poblada-a-peso-0 es una donación directa, que por eso tampoco se valora aquí.
        if mint == *usdc_mint || weight_bps == 0 {
            continue;
        }
        trio_count += 1;
        if let Some(idx) = flayout::find(&registry_data, &mint)? {
            let flags = flayout::read_entry_flags(&registry_data, idx)?;
            if flags & FEED_FLAG_COMPOSED_RR != 0 {
                needs_sol = true;
            }
        }
    }
    // G2-d: tríos (mint, ata, price) en vez de pares: un cliente con la forma vieja falla aquí por el recuento.
    let base_len = 1 + 3 * trio_count;
    let expected_len = base_len + usize::from(needs_sol);
    require!(
        remaining.len() == expected_len,
        WagonError::MissingPriceAccounts
    );
    let trailing_sol = if needs_sol { remaining.get(base_len) } else { None };

    let mut total: u128 = idle_usdc as u128;
    let mut k = 0usize;
    for i in 0..allocation_count {
        let (mint, weight_bps) = {
            let data = vault_ai.try_borrow_data()?;
            (
                vlayout::read_allocation_mint(&data, i)?,
                vlayout::read_allocation_weight_bps(&data, i)?,
            )
        };
        // Ceremonia #48 (H3, Opción B): salta la pata peso 0 — MISMO predicado y
        // MISMA posición que el pre-paso, o k/expected_len se desincronizan.
        if mint == *usdc_mint || weight_bps == 0 {
            continue;
        }
        let mint_ai = &remaining[1 + 3 * k];
        let ata_ai = &remaining[2 + 3 * k];
        let price_ai = &remaining[3 + 3 * k];
        k += 1;

        // G2-d: el mint del trío es EL de la tabla (pinned por clave): su data es la del mint real.
        require_keys_eq!(mint_ai.key(), mint, WagonError::AllocMintMismatch);
        verify_alloc_ata(ata_ai, vault_key, &mint)?;
        let balance = read_token_amount(ata_ai)?;
        // G2-c: con `collect` el precio se lee también a saldo 0 (ver `compute_tvl_m2m_strict_with_prices`).
        if balance == 0 && collect.is_none() {
            continue;
        }

        // H-4: mint sin feed en el registry ⇒ sin precio fiable. Antes
        // caía al caché last-swap sembrado por el propio usuario.
        let idx = flayout::find(&registry_data, &mint)?.ok_or(error!(WagonError::NoReliablePrice))?;
        // H-4: sin decimals cacheados no hay valoración por oráculo posible; antes caía al caché
        // manipulable. El frontend los rellena con cache_alloc_decimals (permissionless) antes de
        // depositar. Solo hacen falta para VALORAR un saldo (a saldo 0 no se valora nada).
        let decimals: Option<u8> = if balance > 0 {
            let cached = {
                let data = vault_ai.try_borrow_data()?;
                vlayout::read_alloc_decimals(&data, i)?
            };
            Some(cached.ok_or(error!(WagonError::NoReliablePrice))?)
        } else {
            None
        };
        let feed_id = flayout::read_entry_feed_id(&registry_data, idx)?;
        let flags = flayout::read_entry_flags(&registry_data, idx)?;
        // Ceremonia #40: bit 3 = sin oráculo utilizable. Este es el camino ESTRICTO (depósito /
        // mark_tvl): falla cerrado, exactamente igual que un mint sin entrada en el registro (patrón
        // H-4). Sin precio fiable no se acuñan participaciones.
        require!(
            flags & FEED_FLAG_NO_ORACLE == 0,
            WagonError::NoReliablePrice
        );
        let class = (flags & FEED_CLASS_MASK) as usize;
        let obs = read_pyth_price(price_ai, &feed_id, class, &clock, max_age_cap_secs)?;
        let sol = if flags & FEED_FLAG_COMPOSED_RR != 0 {
            let sol_ai = trailing_sol.ok_or(error!(WagonError::MissingPriceAccounts))?;
            let sol_idx = flayout::find(&registry_data, &WSOL_MINT)?
                .ok_or(error!(WagonError::FeedNotFound))?;
            let sol_feed = flayout::read_entry_feed_id(&registry_data, sol_idx)?;
            let sol_flags = flayout::read_entry_flags(&registry_data, sol_idx)?;
            let sol_class = (sol_flags & FEED_CLASS_MASK) as usize;
            Some(read_pyth_price(sol_ai, &sol_feed, sol_class, &clock, max_age_cap_secs)?)
        } else {
            None
        };
        // G2-d (F6A-01): multiplicador EFECTIVO de `ScaledUiAmount` leído EN VIVO del mint (×1 sin la extensión).
        let mult = read_mint_ui_multiplier(mint_ai, clock.unix_timestamp)?;
        let leg = LegPrice { obs, sol, mult };
        if let Some(dec) = decimals {
            let value = leg.value(balance, dec)?;
            total = total
                .checked_add(value as u128)
                .ok_or(WagonError::MathOverflow)?;
        }
        if let Some(c) = collect.as_mut() {
            (*c)[i] = Some(leg);
        }
    }

    u64::try_from(total).map_err(|_| error!(WagonError::MathOverflow))
}

/// LENIENT cache-only TVL writeback (withdraw_settle). Never blocks an
/// exit: allocations without a fresh cached price simply contribute 0
/// (conservative; the next strict mark reconciles).
///
/// remaining_accounts layout: [vault_ata_i] per allocation with mint !=
/// USDC, in allocation order.
pub fn compute_tvl_cache_writeback(
    vault_ai: &AccountInfo,
    vault_key: &Pubkey,
    idle_usdc: u64,
    usdc_mint: &Pubkey,
    remaining: &[AccountInfo],
) -> Result<u64> {
    let now = Clock::get()?.unix_timestamp;
    let allocation_count = {
        let data = vault_ai.try_borrow_data()?;
        vlayout::read_allocation_count(&data)?
    } as usize;

    let mut total: u128 = idle_usdc as u128;
    let mut k = 0usize;
    for i in 0..allocation_count {
        let mint = {
            let data = vault_ai.try_borrow_data()?;
            vlayout::read_allocation_mint(&data, i)?
        };
        if mint == *usdc_mint {
            continue;
        }
        let ata_ai = match remaining.get(k) {
            Some(a) => a,
            None => break,
        };
        k += 1;
        verify_alloc_ata(ata_ai, vault_key, &mint)?;
        let balance = read_token_amount(ata_ai)?;
        if balance == 0 {
            continue;
        }
        let (price_q, ts) = {
            let data = vault_ai.try_borrow_data()?;
            vlayout::read_alloc_last_swap(&data, i)?
        };
        if price_q > 0 && now.saturating_sub(ts as i64) <= LAST_SWAP_MAX_AGE_SECS {
            let v = value_from_cache(balance, price_q)?;
            total = total
                .checked_add(v as u128)
                .ok_or(WagonError::MathOverflow)?;
        }
    }
    u64::try_from(total).map_err(|_| error!(WagonError::MathOverflow))
}

// ─── Ceremonia #37: guard de pérdida máxima por COMPRA ──────────────────────
//
// Piso de valor-oráculo por leg: tras ejecutar un swap de compra, los tokens
// recibidos deben valer (a precio de oráculo, con los gates de frescura y
// confianza de siempre) al menos `spent × (1 − max_loss_bps/10000)`. Es el
// análogo on-chain del `priceImpactPct` del frontend (PR #63): mide el valor
// DESTRUIDO por la compra (impacto + fees + slippage, doblados en el
// «realizado vs mid») exactamente donde ocurre el daño, de forma que una
// llamada directa con `min_out = 1` ya no puede vaciar el vault comprando
// tokens ilíquidos. FAIL-CLOSED (decisión de diseño 2026-07-09): un mint sin feed
// en el registro, o sin decimales legibles, BLOQUEA la compra (coherente con
// H-4: sin precio fiable no hay operación). El umbral viene sellado en la
// sesión (deposit/restructure) o de ProtocolConfig (rebalance); 0 = apagado.

/// Pin del FeedRegistry para el guard: address == PDA canónica + owner ==
/// este programa (misma receta que compute_tvl_m2m_strict).
fn verify_guard_registry(registry_ai: &AccountInfo) -> Result<()> {
    let (expected_registry, _) = Pubkey::find_program_address(&[FEED_REGISTRY_SEED], &crate::ID);
    require_keys_eq!(
        registry_ai.key(),
        expected_registry,
        WagonError::SwapGuardAccountsMissing
    );
    require_keys_eq!(
        *registry_ai.owner,
        crate::ID,
        WagonError::SwapGuardAccountsMissing
    );
    Ok(())
}

/// Nº de cuentas de oráculo que el guard exige para `mint` según sus flags:
/// Pyth plano → 1 `[price]` · Pyth compuesto (RR) → 2 `[price, sol_price]`.
/// Fail-closed si el mint no tiene feed registrado, o si lo tiene marcado
/// «sin oráculo utilizable» (NoReliablePrice, patrón H-4).
pub fn guard_oracle_account_count(registry_ai: &AccountInfo, mint: &Pubkey) -> Result<usize> {
    verify_guard_registry(registry_ai)?;
    // Ceremonia #38 (P5/H3): USDC se valora 1:1 y NUNCA está en el registro.
    // Sin este caso, un leg cuyo lado es USDC (p.ej. rebalance de un vault con
    // USDC en la cesta) revertía con NoReliablePrice al buscar USDC en el
    // registro — bloqueando el rebalanceo con el guard vivo.
    if *mint == USDC_MINT {
        return Ok(0);
    }
    let data = registry_ai.try_borrow_data()?;
    let idx = flayout::find(&data, mint)?.ok_or(error!(WagonError::NoReliablePrice))?;
    let flags = flayout::read_entry_flags(&data, idx)?;
    // Ceremonia #40: el bit 3 (ex-Switchboard) pasa a significar SIN ORACULO
    // UTILIZABLE. Camino ESTRICTO -> falla cerrado, igual que un mint sin feed:
    // no podemos valorar, luego no se entra.
    require!(
        flags & FEED_FLAG_NO_ORACLE == 0,
        WagonError::NoReliablePrice
    );
    Ok(if flags & FEED_FLAG_COMPOSED_RR != 0 {
        2
    } else {
        1
    })
}

/// Como `guard_oracle_account_count`, pero TOLERANTE: devuelve `None` si el mint
/// NO está en el registro (en vez de revertir con NoReliablePrice). Usado SOLO
/// por `sweep_to_usdc` / `rescue_untracked_token`, donde un token deslistado (sin
/// feed) NO debe estrangular la liquidación (restricción 5). La pertenencia al
/// registro sigue siendo un hecho on-chain que el creador NO controla: se
/// verifica `verify_guard_registry` (PDA + owner), así que no puede fingir
/// "sin feed" para saltarse el piso. USDC → Some(0).
pub fn guard_oracle_account_count_opt(
    registry_ai: &AccountInfo,
    mint: &Pubkey,
) -> Result<Option<usize>> {
    verify_guard_registry(registry_ai)?;
    if *mint == USDC_MINT {
        return Ok(Some(0));
    }
    let data = registry_ai.try_borrow_data()?;
    let idx = match flayout::find(&data, mint)? {
        Some(i) => i,
        None => return Ok(None),
    };
    let flags = flayout::read_entry_flags(&data, idx)?;
    // Ceremonia #40: el bit 3 (ex-Switchboard) se trata EXACTAMENTE como un mint
    // que no esta en el registro -> None -> el camino TOLERANTE sigue adelante
    // sin piso de precio. Es lo que permite VENDER esos tokens (y liquidar los
    // vaults que los llevan) sin depender de retirarlos del registro. Si no,
    // quedarian atrapados en el peor sitio: ni depositar ni liquidar.
    if flags & FEED_FLAG_NO_ORACLE != 0 {
        return Ok(None);
    }
    Ok(Some(if flags & FEED_FLAG_COMPOSED_RR != 0 {
        2
    } else {
        1
    }))
}

/// Valor (átomos de USDC, 6 dec) de `token_amount` átomos de `mint` a precio
/// de ORÁCULO, leyendo `oracle_accounts` con el layout de
/// `guard_oracle_account_count`. Reutiliza los lectores con gates de
/// frescura/confianza por clase (`read_pyth_price`). G2-d: `mint_ai` es la
/// cuenta del mint (pinned por clave a `mint`) para leer EN VIVO su
/// multiplicador `ScaledUiAmount`: el piso mide átomos × m × precio, el valor
/// REAL, en los cinco llamadores (compra del depósito y del cambio de cesta,
/// rebalance token→token, barrido y rescate).
pub fn guard_oracle_value(
    registry_ai: &AccountInfo,
    mint_ai: &AccountInfo,
    mint: &Pubkey,
    decimals: u8,
    token_amount: u64,
    oracle_accounts: &[AccountInfo],
    clock: &Clock,
) -> Result<u64> {
    verify_guard_registry(registry_ai)?;
    require_keys_eq!(mint_ai.key(), *mint, WagonError::AllocMintMismatch);
    // Ceremonia #38 (P5/H3): USDC vale 1:1 — sus átomos (6 dec) SON el valor en
    // átomos de USDC. No lleva cuentas de oráculo (guard_oracle_account_count → 0).
    if *mint == USDC_MINT {
        return Ok(token_amount);
    }
    let mult = read_mint_ui_multiplier(mint_ai, clock.unix_timestamp)?;
    let data = registry_ai.try_borrow_data()?;
    let idx = flayout::find(&data, mint)?.ok_or(error!(WagonError::NoReliablePrice))?;
    let feed_id = flayout::read_entry_feed_id(&data, idx)?;
    let flags = flayout::read_entry_flags(&data, idx)?;
    // Ceremonia #40: bit 3 (ex-Switchboard) = sin oraculo utilizable. Este es el
    // camino que EXIGE valor, asi que falla cerrado. El camino tolerante ni
    // siquiera llega aqui (guard_oracle_account_count_opt ya devolvio None).
    require!(
        flags & FEED_FLAG_NO_ORACLE == 0,
        WagonError::NoReliablePrice
    );
    require!(
        !oracle_accounts.is_empty(),
        WagonError::SwapGuardAccountsMissing
    );
    let class = (flags & FEED_CLASS_MASK) as usize;
    let obs = read_pyth_price(&oracle_accounts[0], &feed_id, class, clock, 0)?;
    if flags & FEED_FLAG_COMPOSED_RR != 0 {
        require!(
            oracle_accounts.len() >= 2,
            WagonError::SwapGuardAccountsMissing
        );
        let sol_idx = flayout::find(&data, &WSOL_MINT)?.ok_or(error!(WagonError::FeedNotFound))?;
        let sol_feed = flayout::read_entry_feed_id(&data, sol_idx)?;
        let sol_flags = flayout::read_entry_flags(&data, sol_idx)?;
        let sol_class = (sol_flags & FEED_CLASS_MASK) as usize;
        let sol_obs = read_pyth_price(&oracle_accounts[1], &sol_feed, sol_class, clock, 0)?;
        apply_ui_multiplier(value_from_composed(token_amount, &obs, &sol_obs, decimals)?, mult)
    } else {
        apply_ui_multiplier(value_from_oracle(token_amount, &obs, decimals)?, mult)
    }
}

/// El require del guard: `valor_recibido ≥ valor_gastado × (1 − max_loss)`.
/// `spent_value` = átomos de USDC gastados (compras) o valor-oráculo del
/// token vendido (rebalance token→token). Todo en u128 sin redondeos a favor
/// del que ejecuta.
pub fn enforce_value_floor(received_value: u64, spent_value: u64, max_loss_bps: u16) -> Result<()> {
    // El setter capa max_loss_bps ≤ 2000; el saturating es cinturón extra.
    let keep_bps = (BPS_DENOMINATOR as u128).saturating_sub(max_loss_bps as u128);
    let floor = (spent_value as u128)
        .checked_mul(keep_bps)
        .ok_or(WagonError::MathOverflow)?
        / (BPS_DENOMINATOR as u128);
    require!(
        (received_value as u128) >= floor,
        WagonError::SwapValueLossExceeded
    );
    Ok(())
}

/// Decimales leídos del propio Mint account (offset 44 del layout base, común
/// a SPL Token clásico y Token-2022). El mint ya pasó verify_mint_tier_b
/// (owner = programa de tokens, ≥82 bytes, inicializado) antes de llegar aquí.
pub fn read_mint_decimals(mint_ai: &AccountInfo) -> Result<u8> {
    let data = mint_ai.try_borrow_data()?;
    require!(data.len() >= 82, WagonError::NoReliablePrice);
    Ok(data[44])
}

#[cfg(test)]
mod effective_tests {
    use super::*;

    fn leg(rr: (i64, i32), sol: Option<(i64, i32)>) -> LegPrice {
        LegPrice {
            obs: ObservedPrice { price: rr.0, expo: rr.1 },
            sol: sol.map(|s| ObservedPrice { price: s.0, expo: s.1 }),
            mult: UI_MULTIPLIER_ONE,
        }
    }

    #[test]
    fn plano_y_compuesto_que_cabe_son_identicos_a_la_formula_del_m2m() {
        let plano = leg((2_000, 0), None);
        assert_eq!(plano.effective(), ObservedPrice { price: 2_000, expo: 0 });
        // rr 500 (expo 0) × SOL 100 USD (expo −8): producto 5e12, cabe.
        let comp = leg((500, 0), Some((10_000_000_000, -8)));
        assert_eq!(comp.effective(), ObservedPrice { price: 5_000_000_000_000, expo: -8 });
        for amount in [1u64, 999, 1_000_000_000, 123_456_789_012] {
            assert_eq!(value_from_oracle(amount, &comp.effective(), 9).unwrap(), comp.value(amount, 9).unwrap());
        }
    }

    #[test]
    fn compuesto_que_no_cabe_en_i64_se_escala_y_solo_redondea_hacia_abajo() {
        // rr 1.05 (expo −9) × SOL 90.000 USD (expo −8): producto 9.45e21 > i64::MAX → se divide por 10 cuatro veces.
        let comp = leg((1_050_000_000, -9), Some((9_000_000_000_000, -8)));
        let eff = comp.effective();
        assert_eq!(eff, ObservedPrice { price: 945_000_000_000_000_000, expo: -13 });
        assert!(eff.price <= i64::MAX);
        for amount in [1u64, 7, 999, 1_000_000_000, 123_456_789_012, 1_000_000_000_000] {
            let exacto = comp.value(amount, 9).unwrap();
            let aprox = value_from_oracle(amount, &eff, 9).unwrap();
            assert!(aprox <= exacto, "nunca valora de MÁS: {aprox} > {exacto}");
            assert!(exacto - aprox <= 1, "a lo sumo un átomo de USDC menos: {exacto} vs {aprox}");
        }
    }
}

/// G2-d: tests de unidad del multiplicador `ScaledUiAmount` en la valoración, en el módulo hijo
/// `pricing/g2d_tests.rs` (fichero aparte para que ningún fichero del PR pase de 200 líneas nuevas; solo
/// `cfg(test)`, el `.so` no cambia). Sin `#[path]`: la comprobación de comentarios de seguridad de Anchor
/// (`idl-build`) resuelve los `mod` por la ruta convencional y no entiende `#[path]` (juez corto de G2-d).
#[cfg(test)]
mod g2d_tests;

/// Endurecimiento de la #56 (Kairo F-03): la ATA de una pata tiene que ser de uno de los dos programas de tokens; una cuenta
/// de otro programa no pasa ni en la dirección que su propio dueño derivaría.
#[cfg(test)]
mod alloc_ata_tests {
    use super::*;

    fn comprobar(key: Pubkey, owner: Pubkey, vault: &Pubkey, mint: &Pubkey) -> Result<()> {
        let mut lamports = 0u64;
        let mut data = vec![0u8; 165];
        let ai = AccountInfo::new(&key, false, false, &mut lamports, &mut data, &owner, false, 0);
        verify_alloc_ata(&ai, vault, mint)
    }

    #[test]
    fn ata_canonica_de_los_dos_programas_de_tokens_pasa() {
        let (vault, mint) = (Pubkey::new_unique(), Pubkey::new_unique());
        for programa in [anchor_spl::token::spl_token::ID, TOKEN_2022_PROGRAM_ID] {
            let key = get_associated_token_address_with_program_id(&vault, &mint, &programa);
            assert!(comprobar(key, programa, &vault, &mint).is_ok());
        }
    }

    #[test]
    fn cuenta_de_otro_programa_se_rechaza_aunque_su_direccion_cuadre_con_el() {
        let (vault, mint, otro) = (Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique());
        let key = get_associated_token_address_with_program_id(&vault, &mint, &otro);
        let dbg = format!("{:?}", comprobar(key, otro, &vault, &mint));
        assert!(dbg.contains("LegDestAtaMismatch"), "{dbg}");
    }

    #[test]
    fn cuenta_de_tokens_en_otra_direccion_se_rechaza() {
        let (vault, mint) = (Pubkey::new_unique(), Pubkey::new_unique());
        let dbg = format!("{:?}", comprobar(Pubkey::new_unique(), anchor_spl::token::spl_token::ID, &vault, &mint));
        assert!(dbg.contains("LegDestAtaMismatch"), "{dbg}");
    }
}

/// CISO-P3 (#56): toda lectura de Pyth exige la cuenta OFICIAL v2 del feed. Las direcciones de SOL/USD de mainnet comprueban
/// la receta de semillas contra el dato real (gotcha 53).
#[cfg(test)]
mod official_price_account_tests {
    use super::*;
    use crate::constants::SOL_USD_FEED_ID;
    use pyth_solana_receiver_sdk::price_update::{PriceFeedMessage, VerificationLevel};

    const AHORA: i64 = 1_800_000_000;

    fn datos(feed_id: [u8; 32], edad_secs: i64) -> Vec<u8> {
        let update = PriceUpdateV2 {
            write_authority: Pubkey::new_unique(),
            verification_level: VerificationLevel::Full,
            price_message: PriceFeedMessage {
                feed_id,
                price: 2_000,
                conf: 1,
                exponent: 0,
                publish_time: AHORA - edad_secs,
                prev_publish_time: AHORA - edad_secs - 1,
                ema_price: 2_000,
                ema_conf: 1,
            },
            posted_slot: 1,
        };
        let mut data = Vec::new();
        update.try_serialize(&mut data).unwrap();
        data
    }

    /// Lee una actualización fresca (5 s), verificada y del feed esperado, puesta en `key` con dueño `owner`.
    fn leer(key: Pubkey, owner: Pubkey, feed_id: [u8; 32]) -> Result<ObservedPrice> {
        leer_con(key, owner, feed_id, 3, 5, 0)
    }

    /// Como `leer`, con la clase del feed, la edad de la actualización y el tope de edad (`max_age_cap_secs`) elegidos.
    fn leer_con(key: Pubkey, owner: Pubkey, feed_id: [u8; 32], clase: usize, edad_secs: i64, tope: u16) -> Result<ObservedPrice> {
        let mut lamports = 0u64;
        let mut data = datos(feed_id, edad_secs);
        let ai = AccountInfo::new(&key, false, false, &mut lamports, &mut data, &owner, false, 0);
        let clock = Clock { unix_timestamp: AHORA, ..Clock::default() };
        read_pyth_price(&ai, &feed_id, clase, &clock, tope)
    }

    fn pda(shard: u16, feed_id: &[u8; 32], programa: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(&[&shard.to_le_bytes(), feed_id], programa).0
    }

    #[test]
    fn la_receta_da_las_cuentas_oficiales_de_sol_usd_de_mainnet() {
        assert_eq!(
            official_price_account(&SOL_USD_FEED_ID),
            pubkey!("7AviUf9nL62mcxNbQGKm4nKDQnPjswo6c5MX4D57HmyE")
        );
        // La misma receta con el programa push de la generación vieja da su cuenta oficial, que ya no se acepta.
        assert_eq!(
            pda(0, &SOL_USD_FEED_ID, &pyth_solana_receiver_sdk::PYTH_PUSH_ORACLE_ID),
            pubkey!("7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE")
        );
    }

    #[test]
    fn la_cuenta_oficial_v2_pasa() {
        let feed = [7u8; 32];
        let obs = leer(official_price_account(&feed), PYTH_RECEIVER_V2, feed).unwrap();
        assert_eq!((obs.price, obs.expo), (2_000, 0));
    }

    #[test]
    fn la_misma_actualizacion_en_otra_direccion_revierte() {
        let feed = [7u8; 32];
        let dbg = format!("{:?}", leer(Pubkey::new_unique(), PYTH_RECEIVER_V2, feed));
        assert!(dbg.contains("OraclePriceAccountNotCanonical"), "{dbg}");
    }

    #[test]
    fn la_cuenta_de_otro_shard_revierte() {
        let feed = [7u8; 32];
        let dbg = format!("{:?}", leer(pda(1, &feed, &PYTH_PUSH_ORACLE_V2), PYTH_RECEIVER_V2, feed));
        assert!(dbg.contains("OraclePriceAccountNotCanonical"), "{dbg}");
    }

    #[test]
    fn la_cuenta_oficial_de_otro_feed_no_vale_para_este() {
        let (feed, otro) = ([7u8; 32], [8u8; 32]);
        let dbg = format!("{:?}", leer(official_price_account(&otro), PYTH_RECEIVER_V2, feed));
        assert!(dbg.contains("OraclePriceAccountNotCanonical"), "{dbg}");
    }

    #[test]
    fn la_cuenta_oficial_de_la_generacion_vieja_se_rechaza_por_su_dueno() {
        let feed = [7u8; 32];
        let v1 = pda(0, &feed, &pyth_solana_receiver_sdk::PYTH_PUSH_ORACLE_ID);
        let dbg = format!("{:?}", leer(v1, pyth_solana_receiver_sdk::ID, feed));
        assert!(dbg.contains("InvalidPriceAccount"), "{dbg}");
    }
    // ---- CISO-P3 B (#56): edad máxima del precio en el re-precio del commit ----

    #[test]
    fn el_setter_admite_cero_o_de_diez_a_ciento_veinte_segundos() {
        for v in [0u16, 10, 11, 60, 119, 120] {
            assert!(commit_oracle_max_age_valid(v), "{v} debería valer");
        }
        for v in [1u16, 9, 121, 300, u16::MAX] {
            assert!(!commit_oracle_max_age_valid(v), "{v} no debería valer");
        }
    }

    #[test]
    fn la_edad_es_la_de_la_clase_sin_tope_y_la_menor_con_tope() {
        // [stable, major, xstock, longtail] = [120, 120, 300, 120]
        for clase in 0..4 {
            assert_eq!(effective_max_age(clase, 0), ORACLE_MAX_AGE_SECS[clase]);
        }
        assert_eq!(effective_max_age(3, 60), 60);
        assert_eq!(effective_max_age(3, 120), 120);
        assert_eq!(effective_max_age(2, 60), 60);
        assert_eq!(effective_max_age(2, 120), 120);
    }

    #[test]
    fn con_tope_de_60_s_un_precio_de_70_s_se_rechaza_y_sin_tope_pasa() {
        let feed = [7u8; 32];
        let oficial = official_price_account(&feed);
        assert!(leer_con(oficial, PYTH_RECEIVER_V2, feed, 3, 70, 0).is_ok(), "sin tope: la clase admite 120 s");
        assert!(leer_con(oficial, PYTH_RECEIVER_V2, feed, 3, 70, 120).is_ok());
        assert!(leer_con(oficial, PYTH_RECEIVER_V2, feed, 3, 60, 60).is_ok(), "justo en el tope: pasa");
        let dbg = format!("{:?}", leer_con(oficial, PYTH_RECEIVER_V2, feed, 3, 70, 60));
        assert!(dbg.contains("StaleOrUntrustedPrice"), "{dbg}");
    }

    #[test]
    fn el_tope_tambien_acorta_la_ventana_de_300_s_de_los_xstocks() {
        let feed = [9u8; 32];
        let oficial = official_price_account(&feed);
        assert!(leer_con(oficial, PYTH_RECEIVER_V2, feed, 2, 200, 0).is_ok(), "sin tope: un xStock admite 300 s");
        let dbg = format!("{:?}", leer_con(oficial, PYTH_RECEIVER_V2, feed, 2, 200, 120));
        assert!(dbg.contains("StaleOrUntrustedPrice"), "{dbg}");
    }
}
