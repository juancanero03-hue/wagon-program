//! Convenciones de `remaining_accounts` COMO CÓDIGO — refactor R-1.
//!
//! La lección del 0x1783 (2026-06-11): dos instrucciones esperaban las
//! cuentas de Jupiter con convenciones distintas, documentadas solo en
//! comentarios, y el frontend aplicó la equivocada. Una convención que
//! vive en un tipo con su `parse()` no puede divergir en silencio.
//!
//! Convenciones vigentes:
//! - `LegSegment`  → [mint, ata, ...ruta_jupiter]  (withdraw_swap_batch; su
//!   `finish` cierra también el cursor de deposit_swap_batch y restructure_swap_batch).
//! - `GuardedLegSegment` → [mint, ata, ...oráculo, ...ruta_jupiter]
//!   (deposit_swap_batch, restructure_swap_batch; con 0 cuentas de oráculo
//!   es el `LegSegment` clásico). En ambos el mint se re-valida Tier B; la
//!   ata se valida por derivación; la ruta se reenvía a Jupiter SIN las
//!   cuentas previas (Jupiter ya trae sus propias cuentas).
//! - `RouteOnly`   → [...ruta_jupiter] tal cual (rebalance_swap: la dest
//!   ATA viaja como cuenta nombrada del ix).
//! - `OracleTriples` → [FeedRegistry, (mint, ata, price)×N, ¿SOL/USD?] (#30 +
//!   G2-d: deposit_init, mark_tvl y el commit de deposit_sweep_batch) — parse en
//!   pricing::compute_tvl_m2m_strict (G2-d añadió el mint a cada pata para leer
//!   en vivo su multiplicador ScaledUiAmount; hasta entonces eran pares).
//! - Guard de pérdida con mints (G2-d): `rebalance_swap` → [FeedRegistry,
//!   src_mint, ...oráculo_src, dst_mint, ...oráculo_dst, ...ruta]; `sweep_to_usdc`
//!   → [FeedRegistry, mint, ...oráculo, ...ruta]. Los segmentos de leg ya
//!   llevaban el mint; `rescue_untracked_token` lo tiene como cuenta nombrada.

use anchor_lang::prelude::*;

use crate::errors::WagonError;

/// Un segmento [mint, ata, ...ruta] dentro de remaining_accounts.
pub struct LegSegment<'a, 'info> {
    pub mint_ai: &'a AccountInfo<'info>,
    pub ata_ai: &'a AccountInfo<'info>,
    pub route: &'a [AccountInfo<'info>],
}

impl<'a, 'info> LegSegment<'a, 'info> {
    /// Corta el segmento que empieza en `cursor` con `route_len` cuentas de
    /// ruta. Devuelve (segmento, nuevo_cursor).
    pub fn parse(
        remaining: &'a [AccountInfo<'info>],
        cursor: usize,
        route_len: usize,
    ) -> Result<(Self, usize)> {
        let seg_len = 2usize
            .checked_add(route_len)
            .ok_or(WagonError::InvalidJupiterRoute)?;
        require!(
            cursor.checked_add(seg_len).map(|e| e <= remaining.len()).unwrap_or(false),
            WagonError::InvalidJupiterRoute
        );
        Ok((
            Self {
                mint_ai: &remaining[cursor],
                ata_ai: &remaining[cursor + 1],
                route: &remaining[cursor + 2..cursor + seg_len],
            },
            cursor + seg_len,
        ))
    }

    /// Tras consumir todos los segmentos, el cursor debe agotar la lista
    /// (el caller declaró exactamente lo que envió).
    pub fn finish(remaining: &[AccountInfo], cursor: usize) -> Result<()> {
        require!(cursor == remaining.len(), WagonError::InvalidJupiterRoute);
        Ok(())
    }
}

/// Ceremonia #37 — segmento de leg CON las cuentas de oráculo del guard de
/// pérdida por compra: `[mint, ata, ...oraculo(oracle_len), ...ruta(route_len)]`.
/// Con `oracle_len == 0` es EXACTAMENTE el `LegSegment` clásico (guard apagado
/// o leg de venta) — mismo cursor, misma semántica de `finish`.
pub struct GuardedLegSegment<'a, 'info> {
    pub mint_ai: &'a AccountInfo<'info>,
    pub ata_ai: &'a AccountInfo<'info>,
    pub oracle: &'a [AccountInfo<'info>],
    pub route: &'a [AccountInfo<'info>],
}

impl<'a, 'info> GuardedLegSegment<'a, 'info> {
    pub fn parse(
        remaining: &'a [AccountInfo<'info>],
        cursor: usize,
        oracle_len: usize,
        route_len: usize,
    ) -> Result<(Self, usize)> {
        let seg_len = 2usize
            .checked_add(oracle_len)
            .and_then(|v| v.checked_add(route_len))
            .ok_or(WagonError::InvalidJupiterRoute)?;
        require!(
            cursor
                .checked_add(seg_len)
                .map(|e| e <= remaining.len())
                .unwrap_or(false),
            WagonError::InvalidJupiterRoute
        );
        let oracle_start = cursor + 2;
        let route_start = oracle_start + oracle_len;
        Ok((
            Self {
                mint_ai: &remaining[cursor],
                ata_ai: &remaining[cursor + 1],
                oracle: &remaining[oracle_start..route_start],
                route: &remaining[route_start..cursor + seg_len],
            },
            cursor + seg_len,
        ))
    }
}
