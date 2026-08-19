//! Upgrade #30 — pricing utilities for TVL mark-to-market.
//!
//! Commit A scope: last-swap execution-price cache. Every Jupiter leg the
//! vault executes (deposit buys, withdraw sells) writes the realised price
//! into the vault's reserved tail, decimals-agnostically (USDC atoms per
//! 1e9 token atoms). This cache is the valuation fallback for mints without
//! a Pyth feed (META/AVICI/UMBRA & co. — see docs/feeds-mainnet.json) with
//! a 24 h freshness window enforced at read time.
//!
//! The Pyth read path + `compute_tvl_m2m` land in the follow-up commit.
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
    BPS_DENOMINATOR, FEED_REGISTRY_SEED, LAST_SWAP_MAX_AGE_SECS, ORACLE_MAX_AGE_SECS,
    ORACLE_MAX_CONF_BPS, USDC_MINT,
};
use crate::errors::WagonError;
use crate::state::feed_registry::{FEED_CLASS_MASK, FEED_FLAG_COMPOSED_RR, FEED_FLAG_NO_ORACLE};
use crate::state::feed_registry_layout as flayout;

/// Wrapped SOL mint (needed to resolve the SOL/USD feed for composed
/// redemption-rate pricing, e.g. JupSOL).
pub const WSOL_MINT: Pubkey =
    anchor_lang::solana_program::pubkey!("So11111111111111111111111111111111111111112");

pub struct ObservedPrice {
    pub price: i64,
    pub expo: i32,
}

/// Read `amount` (offset 64) from an SPL token account without
/// deserialising the struct.
pub fn read_token_amount(acc: &AccountInfo) -> Result<u64> {
    let data = acc.try_borrow_data()?;
    if data.len() < 72 {
        return err!(WagonError::InvalidPriceAccount);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[64..72]);
    Ok(u64::from_le_bytes(buf))
}

/// Validate a Pyth `PriceUpdateV2` account and extract a usable price.
/// Checks: receiver-program ownership, discriminator, feed id match, full
/// verification + staleness (via the SDK), positive price, confidence width.
fn read_pyth_price(
    price_ai: &AccountInfo,
    feed_id: &[u8; 32],
    class_idx: usize,
    clock: &Clock,
) -> Result<ObservedPrice> {
    // Ceremonia #40: se aceptan las DOS generaciones del receptor de Pyth. La
    // vieja es la del SDK; la nueva (PYTH_RECEIVER_V2) es a la que Pyth movio
    // sus cuentas al actualizar su Price Feed program. Ver constants.rs para el
    // peaje aceptado y el sunset. El resto de la validacion (discriminador,
    // feed id, verificacion completa, frescura, confianza) es IDENTICA para
    // ambas: el formato PriceUpdateV2 no cambia entre generaciones.
    require!(
        *price_ai.owner == pyth_solana_receiver_sdk::ID
            || *price_ai.owner == crate::constants::PYTH_RECEIVER_V2,
        WagonError::InvalidPriceAccount
    );
    let update = {
        let data = price_ai.try_borrow_data()?;
        PriceUpdateV2::try_deserialize(&mut &data[..])
            .map_err(|_| error!(WagonError::InvalidPriceAccount))?
    };
    let max_age = ORACLE_MAX_AGE_SECS[class_idx & 3];
    let p = update
        .get_price_no_older_than(clock, max_age, feed_id)
        .map_err(|_| error!(WagonError::StaleOrUntrustedPrice))?;
    require!(p.price > 0, WagonError::StaleOrUntrustedPrice);

    let lhs = (p.conf as u128).saturating_mul(10_000);
    let rhs = (p.price as u128).saturating_mul(ORACLE_MAX_CONF_BPS[class_idx & 3] as u128);
    require!(lhs <= rhs, WagonError::PriceConfidenceTooWide);

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
    read_pyth_price(price_ai, &crate::constants::SOL_USD_FEED_ID, 2, clock)
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
/// The expected address is derived with the token program that owns the
/// account itself — a forged token account (right mint+owner, wrong address)
/// can never match, because ATA derivation pins address to program id.
fn verify_alloc_ata(ata_ai: &AccountInfo, vault_key: &Pubkey, mint: &Pubkey) -> Result<()> {
    let expected = get_associated_token_address_with_program_id(vault_key, mint, ata_ai.owner);
    require_keys_eq!(ata_ai.key(), expected, WagonError::LegDestAtaMismatch);
    Ok(())
}

/// STRICT mark-to-market TVL (deposit_init, mark_tvl).
///
/// remaining_accounts layout (length is EXACT, derived from registry flags):
///   [0]                  FeedRegistry PDA
///   [1 + 2k, 2 + 2k]     (vault_ata_i, price_update_i) per allocation with
///                        mint != USDC, in allocation order (k = pair index).
///   [base_len]           SOL/USD PriceUpdateV2, iff any allocation feed
///                        has the composed-RR flag
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

    // Pre-pass over the basket: pair count plus WHETHER the SOL/USD tail is
    // needed, decided by REGISTRY flags — the same rule the frontend applies
    // when building the list, so the expected length is EXACT. Layout:
    //   [0] registry · (ata_i, price_i)×k · [SOL/USD]?
    let mut pair_count = 0usize;
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
        // MISMA posición que el bucle de valoración de abajo, o pair_count/k/
        // expected_len se desincronizan. Vaults reales (todas las patas peso>0) →
        // byte-idéntico. Los TRES caminos que FINANCIAN una pata a peso 0 están
        // vetados: `rebalance` (#47, 6179), `restructure_init` (#47, 6179) y
        // `rebalance_swap` (ceremonia 2026-08, 6179) → el único origen de una pata
        // poblada-a-peso-0 es create + donación directa (residual conocido).
        if mint == *usdc_mint || weight_bps == 0 {
            continue;
        }
        pair_count += 1;
        if let Some(idx) = flayout::find(&registry_data, &mint)? {
            let flags = flayout::read_entry_flags(&registry_data, idx)?;
            if flags & FEED_FLAG_COMPOSED_RR != 0 {
                needs_sol = true;
            }
        }
    }
    let base_len = 1 + 2 * pair_count;
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
        let ata_ai = &remaining[1 + 2 * k];
        let price_ai = &remaining[2 + 2 * k];
        k += 1;

        verify_alloc_ata(ata_ai, vault_key, &mint)?;
        let balance = read_token_amount(ata_ai)?;
        if balance == 0 {
            continue;
        }

        let value = match flayout::find(&registry_data, &mint)? {
            Some(idx) => {
                let decimals = {
                    let data = vault_ai.try_borrow_data()?;
                    vlayout::read_alloc_decimals(&data, i)?
                };
                match decimals {
                    // H-4: sin decimals cacheados no hay valoración por
                    // oráculo posible; antes caía al caché manipulable. El
                    // frontend los rellena con cache_alloc_decimals
                    // (permissionless) antes de depositar.
                    None => return err!(WagonError::NoReliablePrice),
                    Some(dec) => {
                        let feed_id = flayout::read_entry_feed_id(&registry_data, idx)?;
                        let flags = flayout::read_entry_flags(&registry_data, idx)?;
                        // Ceremonia #40: bit 3 = sin oráculo utilizable. Este
                        // es el camino ESTRICTO (depósito / mark_tvl): falla
                        // cerrado, exactamente igual que un mint sin entrada
                        // en el registro (patrón H-4). Sin precio fiable no se
                        // acuñan participaciones.
                        require!(
                            flags & FEED_FLAG_NO_ORACLE == 0,
                            WagonError::NoReliablePrice
                        );
                        let class = (flags & FEED_CLASS_MASK) as usize;
                        let obs = read_pyth_price(price_ai, &feed_id, class, &clock)?;
                        if flags & FEED_FLAG_COMPOSED_RR != 0 {
                            let sol_ai =
                                trailing_sol.ok_or(error!(WagonError::MissingPriceAccounts))?;
                            let sol_idx = flayout::find(&registry_data, &WSOL_MINT)?
                                .ok_or(error!(WagonError::FeedNotFound))?;
                            let sol_feed = flayout::read_entry_feed_id(&registry_data, sol_idx)?;
                            let sol_flags = flayout::read_entry_flags(&registry_data, sol_idx)?;
                            let sol_class = (sol_flags & FEED_CLASS_MASK) as usize;
                            let sol_obs = read_pyth_price(sol_ai, &sol_feed, sol_class, &clock)?;
                            value_from_composed(balance, &obs, &sol_obs, dec)?
                        } else {
                            value_from_oracle(balance, &obs, dec)?
                        }
                    }
                }
            }
            // H-4: mint sin feed en el registry ⇒ sin precio fiable. Antes
            // caía al caché last-swap sembrado por el propio usuario.
            None => return err!(WagonError::NoReliablePrice),
        };
        total = total
            .checked_add(value as u128)
            .ok_or(WagonError::MathOverflow)?;
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
// tokens ilíquidos. FAIL-CLOSED (decisión Juan 2026-07-09): un mint sin feed
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
    // sin piso de precio. Es lo que permite VENDER esos 12 tokens (y por tanto
    // liquidar los 16 vaults que los llevan) desde el mismo upgrade, sin tener
    // que esperar al remove_feed. Si no, quedarian atrapados en el peor sitio:
    // ni depositar ni liquidar.
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
/// frescura/confianza por clase (`read_pyth_price`).
pub fn guard_oracle_value(
    registry_ai: &AccountInfo,
    mint: &Pubkey,
    decimals: u8,
    token_amount: u64,
    oracle_accounts: &[AccountInfo],
    clock: &Clock,
) -> Result<u64> {
    verify_guard_registry(registry_ai)?;
    // Ceremonia #38 (P5/H3): USDC vale 1:1 — sus átomos (6 dec) SON el valor en
    // átomos de USDC. No lleva cuentas de oráculo (guard_oracle_account_count → 0).
    if *mint == USDC_MINT {
        return Ok(token_amount);
    }
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
    let obs = read_pyth_price(&oracle_accounts[0], &feed_id, class, clock)?;
    if flags & FEED_FLAG_COMPOSED_RR != 0 {
        require!(
            oracle_accounts.len() >= 2,
            WagonError::SwapGuardAccountsMissing
        );
        let sol_idx = flayout::find(&data, &WSOL_MINT)?.ok_or(error!(WagonError::FeedNotFound))?;
        let sol_feed = flayout::read_entry_feed_id(&data, sol_idx)?;
        let sol_flags = flayout::read_entry_flags(&data, sol_idx)?;
        let sol_class = (sol_flags & FEED_CLASS_MASK) as usize;
        let sol_obs = read_pyth_price(&oracle_accounts[1], &sol_feed, sol_class, clock)?;
        value_from_composed(token_amount, &obs, &sol_obs, decimals)
    } else {
        value_from_oracle(token_amount, &obs, decimals)
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
