//! G2-d (auditoría 2026-10-09, F6A-01; revisión N3 del 11-oct): tests de unidad del multiplicador `ScaledUiAmount` en
//! `LegPrice::value`, `LegPrice::effective` y `apply_ui_multiplier`, contra los valores REALES de SPYx (precio 783.08 USD,
//! multiplicador 1.005714560). Módulo hijo `pricing::g2d_tests` (solo `cfg(test)`; sin `#[path]`, que la comprobación de
//! comentarios de seguridad de Anchor no entiende).
use super::*;

fn leg(rr: (i64, i32), sol: Option<(i64, i32)>) -> LegPrice {
    leg_m(rr, sol, UI_MULTIPLIER_ONE)
}

fn leg_m(rr: (i64, i32), sol: Option<(i64, i32)>, mult: u128) -> LegPrice {
    LegPrice {
        obs: ObservedPrice { price: rr.0, expo: rr.1 },
        sol: sol.map(|s| ObservedPrice { price: s.0, expo: s.1 }),
        mult,
    }
}

/// Valor EXACTO (racional, un solo redondeo final) de `amount` átomos con precio plano `price × 10^expo`,
/// `decimals` decimales y multiplicador `mult` / 1e9, en átomos de USDC: la referencia contra la que se
/// comparan las dos rutas (`value` y `effective`).
fn exacto_plano(amount: u64, price: i64, expo: i32, decimals: u8, mult: u128) -> u128 {
    let num = (amount as u128) * (price as u128) * mult;
    let e = 6 + expo - decimals as i32 - 9; // los 9 de la escala del multiplicador
    if e >= 0 { num * 10u128.pow(e as u32) } else { num / 10u128.pow((-e) as u32) }
}

// ---- G2-d: multiplicador ScaledUiAmount en `value`, `effective` y `apply_ui_multiplier` ----

#[test]
fn apply_ui_multiplier_trunca_hacia_abajo_y_uno_es_identidad() {
    assert_eq!(apply_ui_multiplier(1_000, 1_500_000_000).unwrap(), 1_500);
    assert_eq!(apply_ui_multiplier(1_000, 1_005_714_560).unwrap(), 1_005, "1005.71 → 1005 (nunca 1006)");
    assert_eq!(apply_ui_multiplier(7, 1_000_000_001).unwrap(), 7, "7.000000007 → 7");
    assert_eq!(apply_ui_multiplier(u64::MAX, UI_MULTIPLIER_ONE).unwrap(), u64::MAX, "×1: identidad exacta");
    assert!(apply_ui_multiplier(u64::MAX, 2_000_000_000).is_err(), "no cabe en u64 → MathOverflow");
    assert_eq!(apply_ui_multiplier(0, 3_000_000_000).unwrap(), 0);
}

#[test]
fn con_multiplicador_el_valor_es_atomos_por_m_por_precio_y_uno_no_cambia_nada() {
    // 1.000 átomos (9 dec) a 2000 USD: 2.000 USDC sin extensión; ×1.5 → 3.000 USDC.
    assert_eq!(leg((2_000, 0), None).value(1_000, 9).unwrap(), 2_000);
    assert_eq!(leg_m((2_000, 0), None, 1_500_000_000).value(1_000, 9).unwrap(), 3_000);
    // El efectivo guardado lleva m dentro: valora igual sin leer nada más (lotes posteriores del commit).
    let eff = leg_m((2_000, 0), None, 1_500_000_000).effective();
    assert_eq!(eff, ObservedPrice { price: 3_000_000_000_000, expo: -9 });
    assert_eq!(value_from_oracle(1_000, &eff, 9).unwrap(), 3_000);
    // ×1: `effective` y `value` idénticos a antes de G2-d (regresión de los mints clásicos).
    assert_eq!(leg((2_000, 0), None).effective(), ObservedPrice { price: 2_000, expo: 0 });
    let comp = leg((500, 0), Some((10_000_000_000, -8)));
    assert_eq!(comp.effective(), ObservedPrice { price: 5_000_000_000_000, expo: -8 });
}

#[test]
fn spyx_real_las_dos_rutas_nunca_valoran_de_mas_y_difieren_como_mucho_en_dos_atomos() {
    // SPYx: Pyth 783.08 USD (expo −8), 8 decimales, multiplicador nuevo 1.005714560 (fixture real).
    let (price, expo, dec, mult) = (78_308_000_000i64, -8, 8u8, 1_005_714_560u128);
    let l = leg_m((price, expo), None, mult);
    let eff = l.effective();
    for amount in [1u64, 99, 100_000_000, 123_456_789_012, 1_000_000_000_000_000] {
        let exacto = exacto_plano(amount, price, expo, dec, mult);
        let por_valor = l.value(amount, dec).unwrap() as u128;
        let por_efectivo = value_from_oracle(amount, &eff, dec).unwrap() as u128;
        assert!(por_valor <= exacto, "value de MÁS: {por_valor} > {exacto}");
        assert!(por_efectivo <= exacto, "effective de MÁS: {por_efectivo} > {exacto}");
        assert!(exacto - por_valor <= 2, "value: {exacto} vs {por_valor}");
        assert!(exacto - por_efectivo <= 2, "effective: {exacto} vs {por_efectivo}");
    }
    // Sin el multiplicador la pata vale un 0.57 % MENOS: eso es F6A-01.
    let sin = leg((price, expo), None).value(100_000_000, dec).unwrap();
    let con = l.value(100_000_000, dec).unwrap();
    assert_eq!(sin, 783_080_000, "1 SPYx crudo a 783.08");
    assert_eq!(con, 787_554_957, "1 SPYx × 1.005714560 = 787.554957 USDC (truncado; exacto 787554957.3)");
}

#[test]
fn compuesto_con_multiplicador_que_desborda_se_recorta_antes_y_solo_hacia_abajo() {
    // rr y SOL en el tope de i64 con m = 1e6: el producto no cabe en i128 → la mantisa se recorta antes.
    let l = leg_m((i64::MAX, -18), Some((i64::MAX, -18)), 1_000_000_000_000_000);
    let eff = l.effective();
    assert!(eff.price > 0 && eff.price <= i64::MAX, "mantisa válida tras recortar");
    // Caso realista: LST (rr 1.05, expo −9) × SOL 90.000 USD (expo −8) × 1.5: ambas rutas coinciden ± 2 átomos.
    let l = leg_m((1_050_000_000, -9), Some((9_000_000_000_000, -8)), 1_500_000_000);
    let eff = l.effective();
    for amount in [1u64, 7, 999, 1_000_000_000, 123_456_789_012] {
        let a = l.value(amount, 9).unwrap();
        let b = value_from_oracle(amount, &eff, 9).unwrap();
        let d = if a > b { a - b } else { b - a };
        assert!(d <= 2, "rutas separadas más de 2 átomos: {a} vs {b}");
        assert_eq!(a, (l.value(amount, 9).unwrap()), "determinista");
    }
}

/// Revisión N3 (dinero-invariantes-1): el precio efectivo plegado con m valora en el MISMO dominio que `value()`
/// (numerador y denominador del commit): feeds de exponente muy bajo y mints de hasta 18 decimales.
#[test]
fn paridad_de_dominio_entre_value_y_el_efectivo_con_multiplicador() {
    // Dominio (toda la rejilla, también m = 1e6, el tope): si `value()` valora, el efectivo valora. Cercanía: las dos
    // rutas difieren como mucho en ceil(m) + 2 átomos (el redondeo previo de `value` se multiplica por m).
    for (price, expo, sol, dec) in [
        (5i64, -12i32, None, 18u8),                      // precio minúsculo, muchos decimales
        (5, -12, None, 9),
        (78_308_000_000, -8, None, 18),
        (78_308_000_000, -8, None, 8),
        (783, 0, None, 9),                                // exponente 0
        (78_308, -5, None, 6),                            // exponente −5, 6 decimales
        (1_050_000_000, -9, Some((9_000_000_000_000i64, -8i32)), 18), // LST de 18 decimales
        (1_050_000_000, -9, Some((9_000_000_000_000, -8)), 9),
    ] {
        for mult in [1_500_000_000u128, 1_005_714_560, 500_000_000, 1_000_000_000_000_000] {
            let l = leg_m((price, expo), sol, mult);
            let eff = l.effective();
            assert!(eff.price > 0 && eff.expo >= EFFECTIVE_MIN_EXPO, "efectivo normalizado: {eff:?}");
            let tope = (mult / UI_MULTIPLIER_SCALE) as u64 + 2;
            for amount in [1u64, 999, 1_000_000_000, 1_000_000_000_000] {
                // Fuera de u64 (m = 1e6 con importes grandes) no hay paridad que exigir: el m2m tampoco valora.
                let a = match l.value(amount, dec) { Ok(a) => a, Err(_) => continue };
                let b = value_from_oracle(amount, &eff, dec).expect("el efectivo valora donde el m2m valoró");
                let d = if a > b { a - b } else { b - a };
                assert!(d <= tope, "rutas separadas más de ceil(m) + 2 átomos: {a} vs {b} (price {price} expo {expo} dec {dec} mult {mult})");
            }
        }
    }
}
