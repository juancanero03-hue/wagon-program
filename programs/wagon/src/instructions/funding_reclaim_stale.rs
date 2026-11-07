//! `funding_reclaim_stale` — ceremonia USDC §3.3 (B3). Backstop PERMISSIONLESS para un
//! `FundingRecord` HUÉRFANO: la sesión que financiaba ya no existe (o no es de este
//! programa), o la sesión viva en esa dirección lleva OTRO sello (generación o tipo). Un
//! registro así no puede emparejar con nada y solo estorba: bloquea el siguiente init
//! patrocinado de la pareja (que lo crea con `init`). Devuelve TODO su saldo a
//! `record.refund_to` (decisión de diseño, 24-sep: sin incentivo al caller; el gateway lo
//! compone delante de su propio init). Un registro VIVO (su sesión existe con el MISMO
//! sello) revierte con `FundingRecordAlive`: lo cierra su propio terminal.
//!
//! Por construcción ningún terminal deja huérfanos (todos cierran el registro emparejado);
//! la única fuente es un rollback al `.so` anterior con sesiones patrocinadas vivas. La
//! batería lo prueba con fixtures de génesis (suite 50).

use anchor_lang::prelude::*;
use anchor_lang::Discriminator;

use crate::constants::FUNDING_SEED;
use crate::errors::WagonError;
use crate::events::FundingReclaimed;
use crate::state::{
    decide_refund, DepositSession, FundingRecord, RefundDecision, RestructureSession,
    WithdrawSession, FUNDING_KIND_DEPOSIT, FUNDING_KIND_RESTRUCTURE, FUNDING_KIND_WITHDRAW,
};

#[derive(Accounts)]
pub struct FundingReclaimStale<'info> {
    /// Cualquiera. Paga la tx y no cobra nada.
    pub caller: Signer<'info>,

    /// El registro huérfano, en su PDA canónica (seeds + bump). Anchor lo cierra al salir
    /// hacia `refund_to` si el handler no revierte.
    #[account(
        mut,
        seeds = [FUNDING_SEED, funding_record.session.as_ref()],
        bump = funding_record.bump,
        close = refund_to,
    )]
    pub funding_record: Account<'info, FundingRecord>,

    /// CHECK: la dirección que el registro dice financiar (`record.session`), leída SIN tipo:
    /// puede estar vacía, ser de otro programa o llevar una sesión con otro sello.
    #[account(address = funding_record.session @ WagonError::FundingRecordNotCanonical)]
    pub session: UncheckedAccount<'info>,

    /// CHECK: `record.refund_to`, ÚNICO destino admitido.
    #[account(mut, address = funding_record.refund_to @ WagonError::FundingRefundTargetMismatch)]
    pub refund_to: UncheckedAccount<'info>,
}

pub fn handler(ctx: Context<FundingReclaimStale>) -> Result<()> {
    let record = &ctx.accounts.funding_record;
    let session_ai = ctx.accounts.session.to_account_info();
    let seal = if session_ai.owner == &crate::ID {
        let data = session_ai.try_borrow_data()?;
        session_seal(&data)
    } else {
        None
    };
    // reason: 0 = sesión inexistente o ajena · 1 = sesión viva con OTRO sello. Con el MISMO
    // sello el registro está vivo y lo cierra su terminal: aquí se revierte.
    let reason = match seal {
        None => 0u8,
        Some((kind, generation)) => {
            let decision = decide_refund(Some(&**record), &record.session, generation, kind);
            require!(
                !matches!(decision, RefundDecision::ToRecord { .. }),
                WagonError::FundingRecordAlive
            );
            1u8
        }
    };
    emit!(FundingReclaimed {
        record: record.key(),
        session: record.session,
        refund_to: record.refund_to,
        generation: record.generation,
        kind: record.kind,
        lamports: record.to_account_info().lamports(),
        reason,
    });
    Ok(())
}

/// Sello (tipo, generación) de una cuenta de sesión de ESTE programa, por su
/// discriminador; `None` si no es ninguna de las tres sesiones. PURA (sin cuentas).
pub fn session_seal(data: &[u8]) -> Option<(u8, u64)> {
    if let Ok(s) = DepositSession::try_deserialize(&mut &data[..]) {
        return Some((FUNDING_KIND_DEPOSIT, s.generation as u64));
    }
    // G2-c (revisión N3): una `DepositSession` VIVA de un tamaño ANTERIOR del layout append-only (457 del
    // #55, 473 de DT-E) no deserializa con el struct de hoy, y tratarla como «inexistente» (None → reason 0)
    // dejaría cerrar su FundingRecord con la sesión abierta. Se lee por discriminador + generación en su
    // offset FIJO (452, el mismo del arnés y del frontend): nunca None para una sesión real.
    if data.len() >= DepositSession::LEGACY_LEN && data[..8] == DepositSession::DISCRIMINATOR[..] {
        let mut g = [0u8; 4];
        g.copy_from_slice(&data[452..456]);
        return Some((FUNDING_KIND_DEPOSIT, u32::from_le_bytes(g) as u64));
    }
    if let Ok(s) = WithdrawSession::try_deserialize(&mut &data[..]) {
        return Some((FUNDING_KIND_WITHDRAW, s.generation as u64));
    }
    if let Ok(s) = RestructureSession::try_deserialize(&mut &data[..]) {
        return Some((FUNDING_KIND_RESTRUCTURE, s.generation));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::Discriminator;

    /// Cuenta de sesión sintética: discriminador + cuerpo a cero + generación en su offset
    /// (452 / 460 / 588, fijos desde §3.4, los mismos que el arnés y el frontend; DT-E y G2-c añadieron
    /// bytes al FINAL de `DepositSession` sin mover el 452: no derivar estos offsets del LEN).
    fn session_bytes(disc: [u8; 8], len: usize, offset: usize, generation: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; len];
        v[..8].copy_from_slice(&disc);
        v[offset..offset + generation.len()].copy_from_slice(generation);
        v
    }

    #[test]
    fn el_sello_sale_del_discriminador_y_del_offset_de_cada_sesion() {
        let dep = session_bytes(DepositSession::DISCRIMINATOR, DepositSession::LEN, 452, &7u32.to_le_bytes());
        assert_eq!(session_seal(&dep), Some((FUNDING_KIND_DEPOSIT, 7)));
        let wd = session_bytes(WithdrawSession::DISCRIMINATOR, WithdrawSession::LEN, 460, &9u32.to_le_bytes());
        assert_eq!(session_seal(&wd), Some((FUNDING_KIND_WITHDRAW, 9)));
        let g = (1u64 << 32) + 5;
        let rs = session_bytes(RestructureSession::DISCRIMINATOR, RestructureSession::LEN, 588, &g.to_le_bytes());
        assert_eq!(session_seal(&rs), Some((FUNDING_KIND_RESTRUCTURE, g)));
        // Legacy (sello 0) se lee como 0 y jamás empareja (decide_refund).
        let legacy = session_bytes(RestructureSession::DISCRIMINATOR, RestructureSession::LEN, 588, &0u64.to_le_bytes());
        assert_eq!(session_seal(&legacy), Some((FUNDING_KIND_RESTRUCTURE, 0)));
    }

    #[test]
    fn una_deposit_session_de_un_tamano_anterior_sigue_teniendo_sello() {
        // G2-c (revisión N3): 457 (el #55 vivo) y 473 (DT-E) se leen por el offset fijo 452, nunca None.
        for len in [DepositSession::LEGACY_LEN, 473usize] {
            let viva = session_bytes(DepositSession::DISCRIMINATOR, len, 452, &11u32.to_le_bytes());
            assert_eq!(session_seal(&viva), Some((FUNDING_KIND_DEPOSIT, 11)), "len {len}");
            let sin_generacion = session_bytes(DepositSession::DISCRIMINATOR, len, 452, &0u32.to_le_bytes());
            assert_eq!(session_seal(&sin_generacion), Some((FUNDING_KIND_DEPOSIT, 0)), "len {len}: sello 0, jamás empareja");
        }
        // Más corta que el primer layout migrable: no es una sesión (no se inventa un sello).
        let corta = session_bytes(DepositSession::DISCRIMINATOR, DepositSession::LEGACY_LEN - 1, 8, &[0u8; 4]);
        assert_eq!(session_seal(&corta), None);
    }

    #[test]
    fn lo_que_no_es_una_sesion_no_tiene_sello() {
        assert_eq!(session_seal(&[]), None);
        assert_eq!(session_seal(&[0u8; 618]), None);
        let mut rec = vec![0u8; FundingRecord::LEN];
        rec[..8].copy_from_slice(&FundingRecord::DISCRIMINATOR);
        assert_eq!(session_seal(&rec), None);
        // Discriminador de sesión pero cuerpo truncado: no se lee (no se inventa un sello).
        let corto = session_bytes(DepositSession::DISCRIMINATOR, 100, 8, &[0u8; 4]);
        assert_eq!(session_seal(&corto), None);
    }

    #[test]
    fn vivo_o_huerfano_segun_la_tabla_pura() {
        let session = Pubkey::new_unique();
        let rec = FundingRecord { session, generation: (1u64 << 32) + 5, kind: FUNDING_KIND_RESTRUCTURE, ..Default::default() };
        let vivo = decide_refund(Some(&rec), &session, (1u64 << 32) + 5, FUNDING_KIND_RESTRUCTURE);
        assert!(matches!(vivo, RefundDecision::ToRecord { .. }));
        for (gen, kind) in [(5u64, FUNDING_KIND_RESTRUCTURE), ((1u64 << 32) + 5, FUNDING_KIND_DEPOSIT), (0, FUNDING_KIND_RESTRUCTURE)] {
            let d = decide_refund(Some(&rec), &session, gen, kind);
            assert!(!matches!(d, RefundDecision::ToRecord { .. }), "{gen} {kind}");
        }
    }
}
