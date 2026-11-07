//! `FundingRecord` (ceremonia USDC §3.3): quién financió el rent TEMPORAL de una
//! sesión (la sesión, sus huchas y este registro) y a dónde debe volver al cerrarla.
//! Una por sesión ABIERTA y patrocinada, en la PDA `[b"funding", session]`. La
//! dirección es reutilizable como la de la sesión, así que el emparejamiento va por
//! sesión + generación (§3.4) + tipo, nunca por la dirección sola.
//!
//! Se crea DENTRO del init cuando el pagador NO es el propietario (§3.2) y la cierra
//! el terminal de ESA sesión (settle, abort o limpieza), que reparte TODO el saldo del
//! PDA de sesión (rent propio + huchas cerradas hacia él, D1) a `refund_to`; en el
//! cambio de cesta (kind 3) el rent del PROPIO registro va al limpiador AJENO que cierra
//! (abort tras el plazo, `close_stranded`, `admin_clear_stranded`; §3.3.d). Sin registro
//! (sesión legacy o sin patrocinio) el terminal sigue el camino de siempre: el rent
//! vuelve al propietario (o al caller donde ya era así). La decisión vive en `decide_refund` y el destino que el
//! terminal exige en `refund_target_ok`, PUROS y con su tabla completa en tests de
//! unidad; los handlers solo los aplican (`crate::funding`).

use anchor_lang::prelude::*;

/// Tipo de sesión financiada (`kind`).
pub const FUNDING_KIND_DEPOSIT: u8 = 1;
pub const FUNDING_KIND_WITHDRAW: u8 = 2;
pub const FUNDING_KIND_RESTRUCTURE: u8 = 3;

#[account]
#[derive(Default)]
pub struct FundingRecord {
    /// PDA de la sesión financiada.
    pub session: Pubkey,
    /// Quien FIRMÓ y pagó el rent (la clave caliente del sponsor). Solo informativo.
    pub payer: Pubkey,
    /// Destino del reembolso, elegido por el pagador en el init y acotado por el
    /// programa a {payer, protocol.authority} (S22: frío para el sponsor). Rotar la
    /// clave caliente no cambia el destino de ningún reembolso pendiente.
    pub refund_to: Pubkey,
    /// Contador del vault en el momento del init (§3.4). Nunca 0.
    pub generation: u64,
    /// 1 depósito · 2 retiro · 3 cambio de cesta.
    pub kind: u8,
    /// Rent MEDIDO en el init de las cuentas de la sesión que ya existen en él y un
    /// terminal cierra normalmente. Depósito (kind 1): sesión + hucha USDC + este registro
    /// (las huchas de pata nacen en la tx de cada swap y solo entran en el reembolso
    /// EFECTIVO, que por eso es mayor o igual, salvo que el settle (DT-E) o un abort
    /// aplazado (G2-b) dejen la hucha USDC abierta: entonces `FundingRefundPartial` descuenta su rent). Retiro (kind 2): sesión + huchas de pata
    /// (ya existen al llegar al init, en su tx o en una previa del mismo pagador, y el
    /// barrido las cierra todas) + este registro. Cambio de cesta (kind 3): sesión + este
    /// registro (sin huchas); si cierra un limpiador AJENO, el registro va a él y
    /// `FundingRefunded.record_to` lo dice (el efectivo de `refund_to` es solo la sesión).
    pub lamports_refundable: u64,
    /// Rent medido al crear que puede NO cerrarse en el terminal. Depósito: 0 (el cierre de
    /// su hucha USDC en `deposit_settle` también es condicional desde DT-E, y en `deposit_abort`
    /// desde G2-b, pero su rent ya va en `lamports_refundable`: la monitorización off-chain lo
    /// concilia con `FundingRefundPartial`).
    /// Retiro: la hucha USDC, cuyo cierre en `withdraw_settle` es CONDICIONAL (§3.3.c);
    /// cuando sí se cierra, el reembolso EFECTIVO = refundable + sunk.
    pub lamports_sunk: u64,
    pub created_at: i64,
    /// Bump canónico de `[b"funding", session]`.
    pub bump: u8,
    /// PR 5B (§3.5, D3 / M-04): S de SALIDA que el inversor FIRMÓ en `withdraw_init`, ya
    /// ACOTADO allí al tope vivo (0 en pausa; sin patrocinio no hay registro). Solo el
    /// retiro (kind 2) lo usa; depósito y cambio de cesta lo dejan a 0. `withdraw_settle`
    /// cobra `min(este valor, tope vivo, USDC al inversor)` y nunca revierte por él.
    /// Offset 138 (`sizes.js`, `tests/_shared/funding.ts`).
    pub exit_service_usdc: u64,
    /// Reservado; siempre a cero.
    pub _reserved: [u8; 8],
}

impl FundingRecord {
    /// 8 + 32 + 32 + 32 + 8 + 1 + 8 + 8 + 8 + 1 + 8 + 8 = 154 (`FUNDING_RECORD_LEN` en
    /// `sizes.js` del frontend y en `tests/_shared/funding.ts`).
    pub const LEN: usize = 8 + 32 + 32 + 32 + 8 + 1 + 8 + 8 + 8 + 1 + 8 + 8;
}

// Contrato con los filtros `dataSize` y los parsers: fijado en compilación.
const _: () = assert!(FundingRecord::LEN == 154, "FundingRecord::LEN debe ser 154");

/// Resultado de `decide_refund` (a dónde va el saldo de la sesión al cerrarla).
#[derive(Debug, PartialEq, Eq)]
pub enum RefundDecision {
    /// Registro presente y emparejado: el saldo de la sesión y el rent del registro
    /// van a `refund_to`.
    ToRecord { refund_to: Pubkey },
    /// La dirección canónica está vacía (sesión legacy o sin patrocinio): rent al
    /// propietario, como siempre (`FundingRefundLegacy` motivo 0).
    LegacyNoRecord,
    /// Hay registro pero NO empareja (rancio: de otra sesión de la misma pareja
    /// vault + inversor). Rent al propietario, que es quien lo pagó: una sesión
    /// patrocinada nace con su registro emparejado en la misma instrucción, y su init
    /// falla si la dirección ya está ocupada, así que un registro sin emparejar nunca
    /// es el de una sesión patrocinada viva. El registro rancio queda intacto para
    /// `funding_reclaim_stale` (`FundingRefundLegacy` motivo 1).
    LegacyMismatch,
}

/// Tabla de decisión completa, sin tocar ninguna cuenta. `record` es lo que hay en la
/// dirección canónica (`None` = vacía); `sealed_generation` es el sello de la sesión: los
/// 32 bits bajos del contador en DepositSession y WithdrawSession (se comparan solo esos
/// bits) y el contador entero (u64) en RestructureSession (igualdad completa, N3). Un
/// sello 0 es legacy y jamás empareja.
pub fn decide_refund(
    record: Option<&FundingRecord>,
    session: &Pubkey,
    sealed_generation: u64,
    kind: u8,
) -> RefundDecision {
    match record {
        None => RefundDecision::LegacyNoRecord,
        Some(r) => {
            let same_generation = if kind == FUNDING_KIND_RESTRUCTURE {
                r.generation == sealed_generation
            } else {
                (r.generation as u32) == (sealed_generation as u32)
            };
            let pairs = r.session == *session
                && r.kind == kind
                && sealed_generation != 0
                && same_generation;
            if pairs {
                RefundDecision::ToRecord {
                    refund_to: r.refund_to,
                }
            } else {
                RefundDecision::LegacyMismatch
            }
        }
    }
}

/// Destino que el terminal EXIGE en `refund_target` para una decisión dada (pura). Con registro
/// emparejado: `refund_to`, o `authority` (el vault de Squads) como destino ALTERNATIVO, el
/// cinturón «la salida nunca se atasca» (decisión de diseño, 2026-09-24, B2): si `refund_to` se
/// volviera ejecutable y la red aún prohibiera abonarle lamports, settle y abort de esa sesión
/// revertirían para siempre; con la authority el dinero sigue dentro de Wagon y el evento dice
/// quién cobró. El alternativo solo lo puede elegir `owner` o la propia authority (rescate por
/// Squads). En depósito, retiro, asiento y `close_stranded` `owner` es el PROPIETARIO de la
/// sesión (inversor o creador, que así destraba su propia salida): un cranker permissionless
/// NO puede desviar el reembolso del sponsor a Squads (sería una palanca barata para vaciar el
/// carril de salida). ÚNICA EXCEPCIÓN (B3, escotilla de liveness): `restructure_abort` pasa
/// como `owner` al CALLER, así que TRAS EL PLAZO cualquiera puede abortar hacia Squads y un
/// vault nunca se queda en Restructuring por un `refund_to` no pagable (ver el handler).
/// Legacy (sin registro o sin emparejar): SOLO `legacy_dest`, la authority no vale. B3:
/// `legacy_dest` y `owner` van SEPARADOS porque en el abort limpio y en `close_stranded` del
/// cambio de cesta quien cobra en legacy es el `caller` (su incentivo permissionless de
/// siempre); en depósito, retiro y asiento son la misma clave.
pub fn refund_target_ok(
    decision: &RefundDecision,
    target: &Pubkey,
    legacy_dest: &Pubkey,
    owner: &Pubkey,
    authority: &Pubkey,
    caller: &Pubkey,
) -> bool {
    match decision {
        RefundDecision::ToRecord { refund_to } => {
            target == refund_to || (target == authority && (caller == owner || caller == authority))
        }
        _ => target == legacy_dest,
    }
}

#[cfg(test)]
mod tests {
    use super::RefundDecision::*;
    use super::*;

    const DEP: u8 = FUNDING_KIND_DEPOSIT;

    #[test]
    fn el_destino_exigido_sigue_la_tabla_y_la_authority_solo_vale_con_registro() {
        let (owner, authority) = (Pubkey::new_unique(), Pubkey::new_unique());
        let (refund_to, otro) = (Pubkey::new_unique(), Pubkey::new_unique());
        let to = ToRecord { refund_to };
        // Con registro emparejado: refund_to lo puede exigir cualquier caller (cranker incluido).
        for caller in [&owner, &authority, &otro, &refund_to] {
            assert!(refund_target_ok(&to, &refund_to, &owner, &owner, &authority, caller));
            assert!(!refund_target_ok(&to, &owner, &owner, &owner, &authority, caller));
            assert!(!refund_target_ok(&to, &otro, &owner, &owner, &authority, caller));
        }
        // La authority como alternativo (cinturón): SOLO si firma el propietario o la authority;
        // un cranker o el propio sponsor no pueden desviar el reembolso a Squads.
        assert!(refund_target_ok(&to, &authority, &owner, &owner, &authority, &owner));
        assert!(refund_target_ok(&to, &authority, &owner, &owner, &authority, &authority));
        assert!(!refund_target_ok(&to, &authority, &owner, &owner, &authority, &otro));
        assert!(!refund_target_ok(&to, &authority, &owner, &owner, &authority, &refund_to));
        // B3 (close_stranded): quien cobra en legacy es el CALLER, pero el cinturón sigue atado al
        // PROPIETARIO: un tercero no puede desviar a Squads. (En `restructure_abort` el handler pasa
        // el caller como `owner` a propósito, la escotilla de liveness: ahí sí puede, tras el plazo.)
        assert!(!refund_target_ok(&to, &authority, &otro, &owner, &authority, &otro));
        assert!(refund_target_ok(&to, &refund_to, &otro, &owner, &authority, &otro));
        assert!(refund_target_ok(&to, &authority, &otro, &owner, &authority, &owner));
        // Legacy (sin registro o sin emparejar): SOLO `legacy_dest`, firme quien firme.
        for d in [LegacyNoRecord, LegacyMismatch] {
            for caller in [&owner, &authority, &otro] {
                assert!(refund_target_ok(&d, &owner, &owner, &owner, &authority, caller));
                assert!(!refund_target_ok(&d, &authority, &owner, &owner, &authority, caller));
                assert!(!refund_target_ok(&d, &refund_to, &owner, &owner, &authority, caller));
                // legacy_dest = caller (abort limpio por un tercero): cobra el caller, no el creador.
                assert!(refund_target_ok(&d, &otro, &otro, &owner, &authority, caller));
                assert!(!refund_target_ok(&d, &owner, &otro, &owner, &authority, caller));
            }
        }
    }

    fn record(session: Pubkey, generation: u64, kind: u8) -> FundingRecord {
        FundingRecord {
            session,
            payer: Pubkey::new_unique(),
            refund_to: Pubkey::new_unique(),
            generation,
            kind,
            ..Default::default()
        }
    }

    #[test]
    fn tabla_de_decision_completa() {
        let s = Pubkey::new_unique();
        let r = record(s, 7, DEP);
        let to = ToRecord { refund_to: r.refund_to };
        // Sin registro: legacy.
        assert_eq!(decide_refund(None, &s, 7, DEP), LegacyNoRecord);
        // Emparejado: sesión + generación + tipo.
        assert_eq!(decide_refund(Some(&r), &s, 7, DEP), to);
        // Otra sesión (la clave manda, aunque comparta vault e inversor).
        assert_eq!(decide_refund(Some(&r), &Pubkey::new_unique(), 7, DEP), LegacyMismatch);
        // Otro tipo.
        assert_eq!(decide_refund(Some(&r), &s, 7, FUNDING_KIND_WITHDRAW), LegacyMismatch);
        // Generación distinta en cualquier sentido (registro rancio de otra sesión).
        assert_eq!(decide_refund(Some(&r), &s, 6, DEP), LegacyMismatch);
        assert_eq!(decide_refund(Some(&r), &s, 8, DEP), LegacyMismatch);
    }

    #[test]
    fn legacy_nunca_empareja_y_el_sello_compara_los_32_bits_bajos() {
        let s = Pubkey::new_unique();
        // Una sesión legacy (sello 0) no empareja ni con un registro que dijera 0.
        let cero = record(s, 0, DEP);
        assert_eq!(decide_refund(Some(&cero), &s, 0, DEP), LegacyMismatch);
        // El registro guarda el contador entero (u64); Deposit/WithdrawSession, sus 32 bits
        // bajos: el sello llega como u64 con los bits altos a 0 y se comparan solo los bajos.
        let alto = record(s, (1u64 << 32) + 5, DEP);
        let to = ToRecord { refund_to: alto.refund_to };
        assert_eq!(decide_refund(Some(&alto), &s, 5, DEP), to);
        assert_eq!(decide_refund(Some(&alto), &s, 6, DEP), LegacyMismatch);
        assert_eq!(decide_refund(Some(&alto), &s, 5, FUNDING_KIND_WITHDRAW), LegacyMismatch);
    }

    #[test]
    fn el_cambio_de_cesta_exige_la_generacion_completa() {
        // RestructureSession sella el u64 entero: los 32 bits bajos no bastan (N3, §3.3.b).
        let s = Pubkey::new_unique();
        let r = record(s, (1u64 << 32) + 5, FUNDING_KIND_RESTRUCTURE);
        let to = ToRecord { refund_to: r.refund_to };
        assert_eq!(decide_refund(Some(&r), &s, (1u64 << 32) + 5, FUNDING_KIND_RESTRUCTURE), to);
        assert_eq!(decide_refund(Some(&r), &s, 5, FUNDING_KIND_RESTRUCTURE), LegacyMismatch);
        assert_eq!(decide_refund(Some(&r), &s, 0, FUNDING_KIND_RESTRUCTURE), LegacyMismatch);
    }
}
