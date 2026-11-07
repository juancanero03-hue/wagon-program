//! Registro de financiación (ceremonia USDC §3.3): la E/S alrededor de `FundingRecord`
//! que comparten los inits y los terminales. La DECISIÓN es pura y vive en
//! `state::funding_record::decide_refund`; aquí solo se lee la cuenta en su dirección
//! canónica, se acota `refund_to`, se cierra el registro y se emiten los eventos.
//!
//! Regla de oro de los terminales: reciben SIEMPRE la dirección canónica del registro
//! (nunca el centinela `None`), así nadie puede esconder un registro existente; si la
//! dirección está vacía es el camino legacy. Y ninguna sesión se queda sin salida por
//! culpa del registro: sin él, o sin emparejar, el rent va a `legacy_dest` (el
//! propietario; en el abort limpio y en `close_stranded` del cambio de cesta, el caller,
//! como siempre).

use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_program;

use crate::constants::FUNDING_SEED;
use crate::errors::WagonError;
use crate::events::{FundingRefundLegacy, FundingRefunded};
use crate::state::{decide_refund, refund_target_ok, FundingRecord, RefundDecision};

/// Dirección canónica del registro de una sesión y su bump.
pub fn find_record_address(session: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[FUNDING_SEED, session.as_ref()], &crate::ID)
}

/// `refund_to` acotado (decisión de diseño, 23-sep): el pagador o la autoridad del
/// protocolo (`protocol.authority`, el vault de Squads, inmutable desde `initialize`),
/// y no ejecutable EN EL MOMENTO DEL INIT (cinturón: un destino no pagable haría
/// revertir los cierres de esa sesión). Lo que pase después con la clave del pagador
/// es responsabilidad de quien la tiene; el gateway usa `protocol.authority` o su
/// propia clave caliente.
pub fn check_refund_to(refund_to: &AccountInfo, payer: &Pubkey, authority: &Pubkey) -> Result<()> {
    let k = refund_to.key();
    require!(k == *payer || k == *authority, WagonError::FundingRefundToNotAllowed);
    require!(!refund_to.executable, WagonError::FundingRefundToNotAllowed);
    Ok(())
}

/// Lee el registro de `session` en `record_ai`, que DEBE ser su dirección canónica.
/// `Some` si la cuenta está inicializada por este programa con el discriminador, el
/// tamaño y el bump del registro; `None` si la dirección está vacía (cuenta del
/// sistema sin datos, tenga o no lamports donados: solo este programa puede asignarla
/// o darle espacio). Cualquier otra cosa revierte con `FundingRecordNotCanonical`.
pub fn load_record_at(record_ai: &AccountInfo, session: &Pubkey) -> Result<Option<FundingRecord>> {
    let (expected, bump) = find_record_address(session);
    require_keys_eq!(record_ai.key(), expected, WagonError::FundingRecordNotCanonical);
    if record_ai.owner == &crate::ID {
        let data = record_ai.try_borrow_data()?;
        require!(data.len() == FundingRecord::LEN, WagonError::FundingRecordNotCanonical);
        let rec = FundingRecord::try_deserialize(&mut &data[..])
            .map_err(|_| error!(WagonError::FundingRecordNotCanonical))?;
        require!(rec.bump == bump, WagonError::FundingRecordNotCanonical);
        Ok(Some(rec))
    } else {
        require!(
            record_ai.owner == &system_program::ID && record_ai.data_is_empty(),
            WagonError::FundingRecordNotCanonical
        );
        Ok(None)
    }
}

/// PR 5B: el registro de la dirección canónica SOLO si EMPAREJA con la sesión (la misma
/// tabla `decide_refund` que aplica `settle_refund` al cerrar); `None` si la dirección está
/// vacía o el registro es rancio. Revierte únicamente por una cuenta no canónica en el hueco
/// (`FundingRecordNotCanonical`), exactamente como el propio `settle_refund` haría después.
pub fn matched_record(
    record_ai: &AccountInfo,
    session: &Pubkey,
    sealed_generation: u64,
    kind: u8,
) -> Result<Option<FundingRecord>> {
    let record = load_record_at(record_ai, session)?;
    Ok(match decide_refund(record.as_ref(), session, sealed_generation, kind) {
        RefundDecision::ToRecord { .. } => record,
        _ => None,
    })
}

/// Cierra una cuenta de ESTE programa (el registro, o la sesión en los terminales que la
/// cierran a mano: abort limpio y `admin_clear_stranded`) y manda TODO su saldo a `dest`
/// (espejo exacto del `close` de Anchor: lamports a 0, reasignar al system program,
/// realloc 0; Anchor no re-serializa al salir una cuenta cuyo owner ya no es el programa).
/// Devuelve los lamports movidos.
pub fn close_account_to<'info>(
    account_ai: &AccountInfo<'info>,
    dest: &AccountInfo<'info>,
) -> Result<u64> {
    require_keys_neq!(account_ai.key(), dest.key(), WagonError::FundingRefundTargetMismatch);
    let lamports = account_ai.lamports();
    let new_dest = dest
        .lamports()
        .checked_add(lamports)
        .ok_or(WagonError::MathOverflow)?;
    **dest.try_borrow_mut_lamports()? = new_dest;
    **account_ai.try_borrow_mut_lamports()? = 0;
    account_ai.assign(&system_program::ID);
    account_ai.realloc(0, false)?;
    Ok(lamports)
}

/// Reparto del rent temporal en un TERMINAL que cierra la sesión (settle, abort o limpieza).
/// Llamar DESPUÉS de cerrar las huchas hacia el PDA de la sesión y ANTES de salir del
/// handler (el `close = refund_target` de Anchor mueve el saldo de la sesión al salir; los
/// terminales que la cierran a mano llaman a `close_account_to` justo después): decide con
/// la tabla pura, exige que `refund_target` sea un destino admitido (`refund_target_ok`:
/// `refund_to` del registro emparejado, o `authority` como alternativo del cinturón «la
/// salida nunca se atasca» solo si `caller` es `owner` o la authority; `legacy_dest` si
/// legacy), cierra el registro emparejado hacia `record_dest` (`None` = el mismo
/// `refund_target`; el limpiador en el abort limpio, `close_stranded` y
/// `admin_clear_stranded`, §3.3.d) y emite `FundingRefunded` (`lamports` = importe EFECTIVO
/// que recibe `refund_to`: saldo de la sesión ahora, más el registro solo si va al mismo
/// sitio; `record_to` = quien cobra el registro) o `FundingRefundLegacy` (motivo 0 sin
/// registro, 1 sin emparejar; el registro rancio queda intacto para `funding_reclaim_stale`).
/// Un `refund_target` no admitido revierte la transacción entera, así que ningún cierre
/// anterior del handler llega a consolidarse. `sealed_generation` = el sello de la sesión
/// (u32 en depósito y retiro, u64 en cambio de cesta), ver `decide_refund`. `legacy_dest` =
/// quien cobra sin registro (el propietario; el `caller` en el abort limpio y en
/// `close_stranded`); `owner` = quien puede elegir la authority como alternativo: el
/// propietario de la sesión (inversor o creador) en todos los terminales salvo en
/// `restructure_abort`, que pasa al CALLER (escotilla de liveness tras el plazo, B3);
/// `authority` = `protocol.authority` (el vault de Squads, inmutable desde `initialize`);
/// `caller` = quien firma el terminal.
#[allow(clippy::too_many_arguments)]
pub fn settle_refund<'info>(
    record_ai: &AccountInfo<'info>,
    refund_target: &AccountInfo<'info>,
    session_ai: &AccountInfo<'info>,
    legacy_dest: &Pubkey,
    owner: &Pubkey,
    authority: &Pubkey,
    caller: &Pubkey,
    sealed_generation: u64,
    kind: u8,
    record_dest: Option<&AccountInfo<'info>>,
) -> Result<()> {
    let session = session_ai.key();
    let record = load_record_at(record_ai, &session)?;
    let record_generation = record.as_ref().map(|r| r.generation).unwrap_or(0);
    let decision = decide_refund(record.as_ref(), &session, sealed_generation, kind);
    let target = refund_target.key();
    require!(
        refund_target_ok(&decision, &target, legacy_dest, owner, authority, caller),
        WagonError::FundingRefundTargetMismatch
    );
    match decision {
        RefundDecision::ToRecord { .. } => {
            let record_target = record_dest.unwrap_or(refund_target);
            let record_lamports = close_account_to(record_ai, record_target)?;
            let record_to = record_target.key();
            let session_lamports = session_ai.lamports();
            emit!(FundingRefunded {
                session,
                refund_to: target,
                generation: record_generation,
                kind,
                lamports: if record_to == target {
                    session_lamports.saturating_add(record_lamports)
                } else {
                    session_lamports
                },
                record_lamports,
                record_to,
            });
        }
        decision => {
            let reason = if decision == RefundDecision::LegacyNoRecord { 0 } else { 1 };
            emit!(FundingRefundLegacy {
                session,
                kind,
                reason,
                session_generation: sealed_generation,
                record_generation,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
