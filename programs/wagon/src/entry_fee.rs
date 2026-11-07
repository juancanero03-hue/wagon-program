//! Comisión de entrada E, DESCONTADA de lo que paga el inversor (decisión de Juan, 15-oct-2026,
//! que deroga el «E encima» de la ceremonia USDC §3.9).
//!
//! `amount_usdc` de `deposit_init` es D, lo que PAGA el inversor, y entra ENTERO en la hucha
//! USDC de la sesión. El programa calcula E = min(D × bps / 10000, tope) (0 con la comisión
//! apagada o con D por debajo de la exención: tope y exención se miden sobre D, como el mínimo
//! de 10 USDC) y el capital que entra en la cesta es I = D − E: con 10 USDC pagados al 2 %
//! entran 9.80. Participaciones, tope de TVL, `total_tvl_usdc`, base de coste (D14) y
//! `DepositInitiated.amount_usdc` corren sobre I. Igual que hacía el programa vivo #55 con su
//! «neto», ahora con la contabilidad DT-E de abajo.
//!
//! DT-E: E NO se reparte al iniciar. `deposit_init` la deja RESERVADA en la hucha USDC de la
//! sesión (D = I + E) con sus dos cortes sellados en la sesión; `deposit_swap_batch` no puede
//! gastarla; `deposit_settle` (el único final de éxito) la cobra solo sobre el capital que
//! entró en el vault (`plan_landing`) y la reparte con `plan_settle`; y `deposit_abort`
//! devuelve lo que queda en la hucha (D entero si no hubo swaps). Un depósito que no se
//! completa no paga comisión.
//!
//! Módulo HOJA: la fórmula vive en UN sitio (`deduct_entry_fee`), se prueba en unidad y el
//! frontend la replica: el inversor autoriza D (+ S), el precheck exige D + S y las patas se
//! presupuestan sobre I = D − E (nunca sobre D: ese 2 % se comería la reserva de E, 6209).

use anchor_lang::prelude::*;

use crate::constants::BPS_DENOMINATOR;
use crate::errors::WagonError;

/// Parámetros vivos de `ProtocolConfig` (los fija Squads con `set_entry_fee`).
pub struct EntryFeeParams {
    pub bps: u16,
    pub cap_usdc: u64,
    pub exempt_below_usdc: u64,
    pub protocol_share_bps: u16,
}

/// E y su reparto, en átomos de USDC. `fee_usdc == protocol_cut_usdc + creator_cut_usdc`.
pub struct EntryFeeSplit {
    pub fee_usdc: u64,
    pub protocol_cut_usdc: u64,
    pub creator_cut_usdc: u64,
}

/// E = min(importe × bps / 10000, tope), solo con la comisión ON (`bps > 0`) y desde la
/// exención (`importe >= exempt_below`). El corte del protocolo redondea hacia ABAJO: el resto
/// favorece al creador. u128 en los productos; el setter acota `bps` a
/// `ENTRY_FEE_MAX_BPS` (5 %) y `protocol_share_bps` a 10000, así que `creator_cut` nunca
/// desborda. PURA: no lee cuentas ni mueve dinero. El importe es D, lo que paga el inversor
/// (`deduct_entry_fee` es la entrada que usa `deposit_init`).
pub fn split_entry_fee(amount_usdc: u64, p: &EntryFeeParams) -> Result<EntryFeeSplit> {
    if p.bps == 0 || amount_usdc < p.exempt_below_usdc {
        return Ok(EntryFeeSplit { fee_usdc: 0, protocol_cut_usdc: 0, creator_cut_usdc: 0 });
    }
    let raw = (amount_usdc as u128)
        .checked_mul(p.bps as u128)
        .ok_or(WagonError::MathOverflow)?
        / BPS_DENOMINATOR as u128;
    let fee_usdc = raw.min(p.cap_usdc as u128) as u64;
    let protocol_cut_usdc = ((fee_usdc as u128)
        .checked_mul(p.protocol_share_bps as u128)
        .ok_or(WagonError::MathOverflow)?
        / BPS_DENOMINATOR as u128) as u64;
    let creator_cut_usdc = fee_usdc
        .checked_sub(protocol_cut_usdc)
        .ok_or(WagonError::MathOverflow)?;
    Ok(EntryFeeSplit { fee_usdc, protocol_cut_usdc, creator_cut_usdc })
}

/// Lo que paga el inversor (D), E con sus cortes y el capital I = D − E que entra en la cesta.
/// `paid_usdc == capital_usdc + fee_usdc` y `fee_usdc == protocol_cut_usdc + creator_cut_usdc`.
pub struct EntryFeeDeduction {
    /// D: el `amount_usdc` del init, lo que sale de la cuenta del inversor y entra ENTERO en la hucha.
    pub paid_usdc: u64,
    /// I = D − E: lo que la sesión guarda (`DepositSession::amount_usdc`), acuña y suma al TVL.
    pub capital_usdc: u64,
    pub fee_usdc: u64,
    pub protocol_cut_usdc: u64,
    pub creator_cut_usdc: u64,
}

/// E DESCONTADA de D (decisión de Juan, 15-oct-2026): E = `split_entry_fee(D)` (tope y exención
/// sobre D) y capital = D − E. PURA. Con `bps <= ENTRY_FEE_MAX_BPS` (5 %) el capital es como poco
/// el 95 % de D, así que con el mínimo de 10 USDC nunca es 0; la resta va con `checked_sub` igual.
pub fn deduct_entry_fee(paid_usdc: u64, p: &EntryFeeParams) -> Result<EntryFeeDeduction> {
    let s = split_entry_fee(paid_usdc, p)?;
    let capital_usdc = paid_usdc
        .checked_sub(s.fee_usdc)
        .ok_or(WagonError::MathOverflow)?;
    Ok(EntryFeeDeduction {
        paid_usdc,
        capital_usdc,
        fee_usdc: s.fee_usdc,
        protocol_cut_usdc: s.protocol_cut_usdc,
        creator_cut_usdc: s.creator_cut_usdc,
    })
}

/// DT-E: cómo se reparte la hucha USDC de la sesión al asentar; `deposit_settle` la ejecuta con los
/// cortes a COBRAR de `plan_landing` y nadie más decide ese reparto. Invariantes: pagos + resto =
/// hucha; `capital_residual_usdc` + partes de los cortes recibidos = hucha. El «resto» (`to_vault_usdc`)
/// va al vault, o al inversor si la ATA del vault no puede recibir, o se queda en la hucha.
pub struct EntryFeeSettlePlan {
    /// Lo que se transfiere a la tesorería del protocolo y a la hucha del creador.
    pub pay_protocol_usdc: u64,
    pub pay_creator_usdc: u64,
    /// El resto: capital sin invertir, la parte de E no pagable y la no cobrada. Va a la ATA USDC del
    /// vault (o, si no puede recibir, a la del inversor, o se queda en la hucha; lo decide `deposit_settle`).
    pub to_vault_usdc: u64,
    /// Parte de cada corte recibido cuyo destino no puede recibir (congelado o inexistente): sigue al
    /// resto (al vault si puede recibir, como la comisión de éxito no pagable del retiro, DT-B). El
    /// depósito NUNCA se bloquea por esto.
    pub diverted_protocol_usdc: u64,
    pub diverted_creator_usdc: u64,
    /// Hucha − las partes de los cortes recibidos. Con los cortes SELLADOS (como lo llama
    /// `plan_landing`) es el capital sin invertir; en el settle, con los cortes a cobrar, incluye
    /// además la E no cobrada. El capital que acuña sale de `LandingPlan`, NUNCA de aquí: E nunca
    /// cuenta como capital.
    pub capital_residual_usdc: u64,
}

/// PURA. `escrow_usdc` = saldo de la hucha USDC de la sesión; los cortes, los sellados en la
/// sesión (`plan_landing`) o los que se cobran (`deposit_settle`); `*_payable` = el destino puede
/// recibir (`is_payable_usdc_ata`). La reserva del swap
/// garantiza hucha >= E; si aun así faltara, E se cubre hasta donde llegue (primero el
/// protocolo) y nunca hace revertir el settle. Todas las restas son seguras por construcción.
pub fn plan_settle(
    escrow_usdc: u64,
    protocol_cut_usdc: u64,
    creator_cut_usdc: u64,
    treasury_payable: bool,
    creator_payable: bool,
) -> EntryFeeSettlePlan {
    let protocol_part = protocol_cut_usdc.min(escrow_usdc);
    let creator_part = creator_cut_usdc.min(escrow_usdc - protocol_part);
    let pay_protocol_usdc = if treasury_payable { protocol_part } else { 0 };
    let pay_creator_usdc = if creator_payable { creator_part } else { 0 };
    EntryFeeSettlePlan {
        pay_protocol_usdc,
        pay_creator_usdc,
        to_vault_usdc: escrow_usdc - pay_protocol_usdc - pay_creator_usdc,
        diverted_protocol_usdc: protocol_part - pay_protocol_usdc,
        diverted_creator_usdc: creator_part - pay_creator_usdc,
        capital_residual_usdc: escrow_usdc - protocol_part - creator_part,
    }
}

/// DT-E: cuánto capital entra en el vault al asentar y qué parte de E se intenta cobrar. Se decide ANTES
/// de `plan_settle`, que recibe los cortes a cobrar (`charge_*`).
pub struct LandingPlan {
    /// Capital de I que NO entra en el vault (su ATA USDC no puede recibir o la hucha está congelada):
    /// vuelve al inversor o se queda en la hucha; no acuña ni es base de coste.
    pub unlanded_capital_usdc: u64,
    /// I − lo que no entra: la base de las participaciones, de la base de coste y de E.
    pub capital_in_usdc: u64,
    /// Capital sin invertir de la hucha que SÍ entra en el vault (acuña con lo recibido de las patas).
    pub landed_capital_residual_usdc: u64,
    /// Cortes de E que el settle intenta cobrar: los sellados, escalados por capital_in / I a la baja
    /// (E solo se cobra sobre lo que entró); 0 con la hucha congelada (de ella no sale nada).
    pub charge_protocol_usdc: u64,
    pub charge_creator_usdc: u64,
    /// E reservada que no se cobra: sigue al resto, hacia el inversor.
    pub waived_usdc: u64,
}

/// PURA. `vault_can_receive` = la ATA USDC del vault puede recibir; `escrow_frozen` = la hucha está
/// congelada. Invariantes: capital_in + unlanded = I; cobrado + no cobrado = E presente en la hucha;
/// cada corte cobrado <= su corte sellado. Todas las restas son seguras por construcción.
pub fn plan_landing(
    escrow_usdc: u64,
    protocol_cut_usdc: u64,
    creator_cut_usdc: u64,
    amount_usdc: u64,
    vault_can_receive: bool,
    escrow_frozen: bool,
) -> LandingPlan {
    // Con los dos destinos «no pagables», `diverted_*` = la parte de cada corte presente en la hucha.
    let reserved = plan_settle(escrow_usdc, protocol_cut_usdc, creator_cut_usdc, false, false);
    let lands = vault_can_receive && !escrow_frozen;
    let unlanded = if lands { 0 } else { reserved.capital_residual_usdc.min(amount_usdc) };
    let capital_in = amount_usdc - unlanded;
    let charge = |part: u64| -> u64 {
        if escrow_frozen {
            0
        } else if unlanded == 0 {
            part
        } else {
            // unlanded > 0 ⇒ amount_usdc > 0; el cociente es <= part, así que cabe en u64.
            ((part as u128 * capital_in as u128) / amount_usdc as u128) as u64
        }
    };
    let charge_protocol_usdc = charge(reserved.diverted_protocol_usdc);
    let charge_creator_usdc = charge(reserved.diverted_creator_usdc);
    LandingPlan {
        unlanded_capital_usdc: unlanded,
        capital_in_usdc: capital_in,
        landed_capital_residual_usdc: if lands { reserved.capital_residual_usdc } else { 0 },
        charge_protocol_usdc,
        charge_creator_usdc,
        waived_usdc: reserved.diverted_protocol_usdc - charge_protocol_usdc
            + (reserved.diverted_creator_usdc - charge_creator_usdc),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USDC: u64 = 1_000_000;
    /// Objetivo de la ceremonia USDC (§3.9): 2 %, tope 19.75, sin exención, 70 % protocolo.
    const CEREMONIA: EntryFeeParams = EntryFeeParams { bps: 200, cap_usdc: 19_750_000, exempt_below_usdc: 0, protocol_share_bps: 7_000 };
    /// Parámetros VIVOS del #55: 1.5 %, tope 4.98, exención < 10, 10 % protocolo.
    const VIVOS: EntryFeeParams = EntryFeeParams { bps: 150, cap_usdc: 4_980_000, exempt_below_usdc: 10 * USDC, protocol_share_bps: 1_000 };

    fn split(amount: u64, p: &EntryFeeParams) -> (u64, u64, u64) {
        let s = split_entry_fee(amount, p).unwrap();
        assert_eq!(s.fee_usdc, s.protocol_cut_usdc + s.creator_cut_usdc, "E = corte del protocolo + corte del creador");
        (s.fee_usdc, s.protocol_cut_usdc, s.creator_cut_usdc)
    }

    /// (capital, E, corte protocolo, corte creador) de lo que PAGA el inversor.
    fn deduct(paid: u64, p: &EntryFeeParams) -> (u64, u64, u64, u64) {
        let d = deduct_entry_fee(paid, p).unwrap();
        assert_eq!(d.paid_usdc, paid, "D es lo que se pasa");
        assert_eq!(d.capital_usdc + d.fee_usdc, paid, "capital + E = D: nada se cobra encima");
        assert_eq!(d.fee_usdc, d.protocol_cut_usdc + d.creator_cut_usdc, "E = corte del protocolo + corte del creador");
        let s = split(paid, p);
        assert_eq!((d.fee_usdc, d.protocol_cut_usdc, d.creator_cut_usdc), s, "la misma E que split_entry_fee sobre D");
        (d.capital_usdc, d.fee_usdc, d.protocol_cut_usdc, d.creator_cut_usdc)
    }

    #[test]
    fn e_se_descuenta_de_lo_que_paga_el_inversor() {
        // El ejemplo de Juan (15-oct-2026): con 10 USDC pagados al 2 % entran 9.80.
        assert_eq!(deduct(10 * USDC, &CEREMONIA), (9_800_000, 200_000, 140_000, 60_000), "10 pagados: 9.80 de capital, 0.20 = 0.14 protocolo + 0.06 creador");
        assert_eq!(deduct(10 * USDC, &VIVOS), (9_850_000, 150_000, 15_000, 135_000), "con los parámetros del #55: 9.85 de capital, 0.15 = 0.015 + 0.135");
        assert_eq!(deduct(100 * USDC, &VIVOS), (98_500_000, 1_500_000, 150_000, 1_350_000), "100 pagados al 1.5 %: 98.50 de capital (la suite 10 mide esto)");
        assert_eq!(deduct(20 * USDC, &CEREMONIA), (19_600_000, 400_000, 280_000, 120_000), "20 pagados al 2 %: 19.60 (las suites DT-E miden esto)");
    }

    #[test]
    fn el_tope_la_exencion_y_el_minimo_se_miden_sobre_lo_pagado() {
        assert_eq!(deduct(9 * USDC + 999_999, &VIVOS), (9_999_999, 0, 0, 0), "por debajo de la exención (sobre D): todo es capital");
        assert_eq!(deduct(1_000 * USDC, &VIVOS), (995_020_000, 4_980_000, 498_000, 4_482_000), "#55: 1000 pagados → E = tope 4.98, capital 995.02");
        assert_eq!(deduct(100_000 * USDC, &CEREMONIA), (99_980_250_000, 19_750_000, 13_825_000, 5_925_000), "ceremonia: 100 000 pagados → E = tope 19.75");
        assert_eq!(deduct(1_000 * USDC, &EntryFeeParams { bps: 0, ..CEREMONIA }), (1_000 * USDC, 0, 0, 0), "comisión apagada: D entero es capital");
        // El mínimo del programa (10 USDC) se mide sobre D; con el bps máximo (5 %) y sin tope ni exención
        // el capital sigue siendo el 95 % de D: nunca 0.
        let maximo = EntryFeeParams { bps: 500, cap_usdc: u64::MAX, exempt_below_usdc: 0, protocol_share_bps: 10_000 };
        assert_eq!(deduct(crate::constants::MIN_DEPOSIT_USDC, &maximo), (9_500_000, 500_000, 500_000, 0), "10 pagados al 5 %: 9.50 de capital");
        assert_eq!(deduct(u64::MAX, &maximo).0, u64::MAX - u64::MAX / 20, "sin desbordar en u128");
    }

    #[test]
    fn apagada_o_exenta_no_cobra_y_la_exencion_es_inclusiva() {
        assert_eq!(split(1_000 * USDC, &EntryFeeParams { bps: 0, ..CEREMONIA }), (0, 0, 0), "comisión apagada");
        assert_eq!(split(9 * USDC + 999_999, &VIVOS), (0, 0, 0), "por debajo de la exención");
        assert_eq!(split(10 * USDC, &VIVOS).0, 150_000, "justo en la exención SÍ cobra");
        assert_eq!(split(1, &CEREMONIA), (0, 0, 0), "exención 0 y 1 átomo: 1 × 200 / 10000 redondea a 0");
    }

    #[test]
    fn el_tope_clampa_e() {
        assert_eq!(split(987_500_000, &CEREMONIA).0, 19_750_000, "987.5 USDC al 2 % toca justo el tope");
        assert_eq!(split(987_490_000, &CEREMONIA).0, 19_749_800, "por debajo del tope, E exacta");
        assert_eq!(split(100_000 * USDC, &CEREMONIA), (19_750_000, 13_825_000, 5_925_000), "muy por encima: E = tope y el reparto es sobre el tope");
        assert_eq!(split(1_000 * USDC, &VIVOS), (4_980_000, 498_000, 4_482_000), "#55: 1000 USDC → tope 4.98, 10/90");
    }

    #[test]
    fn el_reparto_redondea_hacia_abajo_a_favor_del_creador() {
        assert_eq!(split(150, &EntryFeeParams { bps: 200, cap_usdc: u64::MAX, exempt_below_usdc: 0, protocol_share_bps: 7_000 }), (3, 2, 1), "3 átomos × 70 % = 2.1 → 2 al protocolo, 1 al creador");
        assert_eq!(split(100 * USDC, &VIVOS), (1_500_000, 150_000, 1_350_000), "#55: 100 USDC al 1.5 % → 1.50 = 0.15 + 1.35 (la suite 10 mide esto)");
        assert_eq!(split(50 * USDC, &EntryFeeParams { protocol_share_bps: 10_000, ..CEREMONIA }), (USDC, USDC, 0), "100 % al protocolo: el creador cobra 0, sin desbordar");
    }

    /// (pago protocolo, pago creador, al vault, desviado protocolo, desviado creador, capital)
    fn plan(escrow: u64, p: u64, c: u64, tp: bool, cp: bool) -> (u64, u64, u64, u64, u64, u64) {
        let x = plan_settle(escrow, p, c, tp, cp);
        assert_eq!(x.pay_protocol_usdc + x.pay_creator_usdc + x.to_vault_usdc, escrow, "pagos + vault = hucha");
        assert_eq!(x.capital_residual_usdc + x.pay_protocol_usdc + x.diverted_protocol_usdc + x.pay_creator_usdc + x.diverted_creator_usdc, escrow, "capital + E = hucha");
        (x.pay_protocol_usdc, x.pay_creator_usdc, x.to_vault_usdc, x.diverted_protocol_usdc, x.diverted_creator_usdc, x.capital_residual_usdc)
    }

    #[test]
    fn el_settle_paga_e_y_el_capital_va_al_vault() {
        // 1019.75 USDC pagados con cesta 100 % USDC: la hucha tiene D = I + E = 1019.75; E = tope 19.75 = 13.825 + 5.925, I = 1000.
        assert_eq!(plan(1_019_750_000, 13_825_000, 5_925_000, true, true), (13_825_000, 5_925_000, 1_000_000_000, 0, 0, 1_000_000_000));
        // Cesta sin USDC y sin polvo: tras los swaps solo queda E; al vault no va nada.
        assert_eq!(plan(200_000, 140_000, 60_000, true, true), (140_000, 60_000, 0, 0, 0, 0));
    }

    #[test]
    fn un_destino_no_pagable_desvia_su_corte_al_vault_sin_bloquear() {
        assert_eq!(plan(1_200_000, 140_000, 60_000, false, true), (0, 60_000, 1_140_000, 140_000, 0, 1_000_000), "tesorería congelada");
        assert_eq!(plan(1_200_000, 140_000, 60_000, true, false), (140_000, 0, 1_060_000, 0, 60_000, 1_000_000), "hucha del creador congelada");
        assert_eq!(plan(200_000, 140_000, 60_000, false, false), (0, 0, 200_000, 140_000, 60_000, 0), "las dos: todo al vault y el capital sigue siendo 0");
    }

    #[test]
    fn sin_comision_es_el_settle_de_siempre() {
        assert_eq!(plan(5_000_000, 0, 0, false, false), (0, 0, 5_000_000, 0, 0, 5_000_000), "E = 0: todo es capital y va al vault");
        assert_eq!(plan(0, 0, 0, true, true), (0, 0, 0, 0, 0, 0), "hucha vacía");
    }

    #[test]
    fn si_faltara_e_se_cubre_hasta_donde_llegue_y_no_revierte() {
        assert_eq!(plan(150_000, 140_000, 60_000, true, true), (140_000, 10_000, 0, 0, 0, 0), "primero el protocolo");
        assert_eq!(plan(100_000, 140_000, 60_000, true, true), (100_000, 0, 0, 0, 0, 0));
        assert_eq!(plan(u64::MAX, u64::MAX, u64::MAX, true, true), (u64::MAX, 0, 0, 0, 0, 0), "sin desbordar");
    }

    /// (sin entrar, capital que entró, capital sin invertir que entra, cobro protocolo, cobro creador, no cobrado)
    fn landing(escrow: u64, p: u64, c: u64, i: u64, vault_ok: bool, frozen: bool) -> (u64, u64, u64, u64, u64, u64) {
        let x = plan_landing(escrow, p, c, i, vault_ok, frozen);
        let e = plan(escrow, p, c, false, false);
        assert_eq!(x.capital_in_usdc + x.unlanded_capital_usdc, i, "capital que entra + el que no = I");
        assert_eq!(x.charge_protocol_usdc + x.charge_creator_usdc + x.waived_usdc, e.3 + e.4, "cobrado + no cobrado = E en la hucha");
        assert!(x.charge_protocol_usdc <= p && x.charge_creator_usdc <= c, "nunca se cobra más que el corte sellado");
        (x.unlanded_capital_usdc, x.capital_in_usdc, x.landed_capital_residual_usdc, x.charge_protocol_usdc, x.charge_creator_usdc, x.waived_usdc)
    }

    #[test]
    fn con_el_vault_pagable_todo_entra_y_se_cobra_e_entera() {
        assert_eq!(landing(1_019_750_000, 13_825_000, 5_925_000, 1_000 * USDC, true, false), (0, 1_000 * USDC, 1_000 * USDC, 13_825_000, 5_925_000, 0), "cesta 100 % USDC");
        assert_eq!(landing(19_750_000, 13_825_000, 5_925_000, 1_000 * USDC, false, false), (0, 1_000 * USDC, 0, 13_825_000, 5_925_000, 0), "sin capital en la hucha nada deja de entrar, aunque el vault no pueda recibir");
    }

    #[test]
    fn e_solo_se_cobra_sobre_el_capital_que_entro() {
        // Cesta 90 % USDC / 10 % token, 1000 USDC y la ATA del vault congelada: entran 100; E se cobra al 10 %.
        assert_eq!(landing(919_750_000, 13_825_000, 5_925_000, 1_000 * USDC, false, false), (900 * USDC, 100 * USDC, 0, 1_382_500, 592_500, 17_775_000));
        // Redondeo a la baja, a favor del inversor: 1 átomo sin entrar de 3.
        assert_eq!(landing(1 + 3, 2, 1, 3, false, false), (1, 2, 0, 1, 0, 2));
        // Un tercero dona a la hucha más que I: todo el capital cuenta como no entrado y E no se cobra.
        assert_eq!(landing(5_000 * USDC + 200_000, 140_000, 60_000, 10 * USDC, false, false), (10 * USDC, 0, 0, 0, 0, 200_000));
    }

    #[test]
    fn con_la_hucha_congelada_no_se_cobra_nada() {
        assert_eq!(landing(19_750_000, 13_825_000, 5_925_000, 1_000 * USDC, true, true), (0, 1_000 * USDC, 0, 0, 0, 19_750_000), "sin capital: todo entró, E se queda dentro");
        assert_eq!(landing(1_200_005, 140_000, 60_000, 10 * USDC, true, true), (1_000_005, 8_999_995, 0, 0, 0, 200_000), "el capital sin invertir tampoco entra");
        assert_eq!(landing(0, 0, 0, 10 * USDC, true, true), (0, 10 * USDC, 0, 0, 0, 0), "comisión apagada y sin polvo: hucha vacía");
    }

    /// Canario TEXTUAL (lee el fuente): caza las formas más probables de volver a cobrar E ENCIMA
    /// en `deposit_init` (sumar `fee_usdc` a lo que se transfiere o guardar D en la sesión), NO
    /// todas. La prueba de INTENCIÓN vive en la batería: suite 10 (el inversor paga D exacto y la
    /// cesta recibe D − E), la 58 (10 pagados → 9.80) y el caso E + S de la 53 (DT-E: la hucha
    /// recibe D con los cortes sellados; TVL y evento sobre I).
    #[test]
    fn deposit_init_descuenta_la_comision_de_lo_pagado() {
        let src = include_str!("instructions/deposit_init.rs");
        assert!(src.contains("deduct_entry_fee("), "deposit_init calcula E y el capital con este módulo");
        assert!(!src.contains("split_entry_fee("), "y no con la función de reparto a secas");
        for suma in ["checked_add(fee_usdc)", "saturating_add(fee_usdc)", "+ fee_usdc", "escrow_in_usdc"] {
            assert!(!src.contains(suma), "E nunca se suma a lo que paga el inversor ({suma})");
        }
        assert!(src.contains("session.amount_usdc = capital_usdc;"), "la sesión guarda I = D − E");
        assert!(!src.contains("session.amount_usdc = amount_usdc;"), "la sesión no guarda D");
        assert!(src.contains(".checked_add(capital_usdc)"), "el TVL del protocolo suma I, no D");
        assert!(!src.contains(".checked_add(amount_usdc)"), "y nunca D");
        // Ningún comentario del programa vuelve a describir el modelo derogado (revisión N3 del PR):
        // los ficheros que lo citaban (constantes, init y settle) hablan de la comisión descontada.
        for (nombre, fuente) in [
            ("constants.rs", include_str!("constants.rs")),
            ("deposit_init.rs", src),
            ("deposit_settle.rs", include_str!("instructions/deposit_settle.rs")),
        ] {
            for rastro in ["va ENCIMA", "cobra ENCIMA", "E ENCIMA"] {
                assert!(!fuente.contains(rastro), "{nombre} aún describe la comisión «encima» ({rastro})");
            }
        }
    }
}
