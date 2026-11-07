//! `WithdrawRight` — G3-B1b (DT-A(b), diseño G3 §3 contrastado el 16-oct-2026): el RECIBO DE DERECHO de un retiro que
//! `withdraw_force_release` cerró sin volver a acuñar participaciones (decisión 2 de Juan del 14-oct). Vive en la MISMA PDA
//! que la `WithdrawSession` que lo originó (`[b"withdraw-session", vault, investor]`), re-tipada EN SU SITIO: otro
//! discriminador, LEN menor (437 B, realloc hacia abajo) y el mismo rent. Por eso, mientras exista: `withdraw_init` no puede abrir
//! otra sesión en esa pareja (init sobre una PDA ocupada), `withdraw_escrow_sweep` no puede llevarse al vault una hucha que
//! es del inversor (la PDA no está vacía) y toda `Account<WithdrawSession>` falla por discriminador. Sin él, con la sesión
//! cerrada, nada distinguiría el derecho del inversor del residuo del vault.
//!
//! Lista las huchas que siguen ABIERTAS como derecho del inversor (`pending_mask` por pata del snapshot `leg_mints`, y
//! `usdc_pending` para la hucha USDC) y a quién devolver su rent al cerrarse (`refund_to`: el destino que `settle_refund`
//! validó en la liberación, el inversor o el `refund_to` del patrocinio). Lo consume `withdraw_escrow_claim`, hucha a hucha,
//! en cuanto cada una se puede mover; el rent de cada hucha cae en el recibo (D1) y sale con él.

use anchor_lang::prelude::*;

use crate::constants::MAX_TOKENS_PER_VAULT;

#[account]
#[derive(Default)]
pub struct WithdrawRight {
    /// Dueño del derecho (semilla de la PDA).
    pub investor: Pubkey,
    /// Vault de la sesión liberada (semilla de la PDA; puede cerrarse después: aquí solo es una clave).
    pub vault: Pubkey,
    /// Quien cobra el rent del recibo al cerrarse (validado por `settle_refund` en la liberación).
    pub refund_to: Pubkey,
    /// Snapshot de mints por pata de la sesión liberada (las huchas se derivan de aquí, nunca de la tabla viva).
    pub leg_mints: [Pubkey; MAX_TOKENS_PER_VAULT],
    /// USDC de la hucha que es DEL INVERSOR: el slice ocioso del init más lo vendido (`usdc_slice_from_vault +
    /// usdc_from_swaps`, la misma cuenta que paga el settle, sin comisiones). Lo que haya por encima en la hucha (el
    /// residuo de un abort aplazado o de un settle anterior de la pareja) es del VAULT: el claim no lo entrega y lo
    /// deja en la hucha para `withdraw_escrow_sweep` en cuanto el recibo se cierra.
    pub usdc_right: u64,
    pub leg_count: u8,
    /// Patas cuya hucha sigue abierta como derecho (bit por índice de pata).
    pub pending_mask: u16,
    /// 1 mientras la hucha USDC de la sesión siga abierta como derecho.
    pub usdc_pending: u8,
    pub bump: u8,
}

impl WithdrawRight {
    pub const LEN: usize = 8 // discriminador
        + 32 // investor
        + 32 // vault
        + 32 // refund_to
        + 32 * MAX_TOKENS_PER_VAULT // leg_mints
        + 8 // usdc_right
        + 1 // leg_count
        + 2 // pending_mask
        + 1 // usdc_pending
        + 1; // bump

    /// Nada pendiente: el recibo se cierra hacia `refund_to`.
    pub fn is_empty(&self) -> bool {
        self.pending_mask == 0 && self.usdc_pending == 0
    }
}

/// Índice de pata que significa «la hucha USDC» en `withdraw_force_release` (prueba (c)) y en `withdraw_escrow_claim`.
pub const WITHDRAW_USDC_LEG_INDEX: u8 = 255;

// El recibo es un CONTRATO con los filtros `dataSize` de los clientes (distinto de los 465 B de la sesión, para que ningún
// filtro por tamaño lo confunda con una sesión viva) y cabe en el rent de la sesión que re-tipa.
const _: () = assert!(WithdrawRight::LEN == 437, "WithdrawRight::LEN debe ser 437");
const _: () = assert!(WithdrawRight::LEN < crate::state::WithdrawSession::LEN, "el recibo cabe en el rent de la sesión");
