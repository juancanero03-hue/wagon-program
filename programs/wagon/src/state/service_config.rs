//! Ceremonia USDC §3.5 — `ServiceConfig`: singleton (PDA `[b"service-config"]`) con los
//! TOPES on chain del servicio S (gas patrocinado cobrado en USDC como argumento firmado
//! de cada init) y su pausa. Lo crea Squads (`init_service_config`) y lo edita Squads
//! (`set_service_params`). Es una RED contra un gateway comprometido (S nunca supera el
//! tope), no un precio: el precio lo cotiza el gateway en lamports y lo firma el usuario.
//!
//! D5 (2026-09-14): la tesorería de S es la MISMA ATA USDC del protocolo que ya
//! recibe la comisión de entrada y la de éxito (`protocol.treasury_usdc_ata`, la única que
//! el cobro comprueba); aquí queda su espejo informativo para clientes e indexer.
//!
//! Tamaño FIJO 128 B (const assert): `sizes.js` del frontend y `_shared/service.ts`.
use anchor_lang::prelude::*;

#[account]
pub struct ServiceConfig {
    /// Espejo INFORMATIVO de `protocol.treasury_usdc_ata` (D5), fijado en
    /// `init_service_config`; sin setter. El cobro compara contra el ProtocolConfig.
    pub treasury_usdc_ata: Pubkey,
    /// Tope de S por operación de ENTRADA, en átomos de USDC: 0 publicar · 1 depositar ·
    /// 2 rebalancear · 3 cambiar cesta (`SERVICE_KIND_*`). Con patrocinio S > 0 SIEMPRE
    /// (5A-bis): un tope a 0 BLOQUEA el patrocinio de esa operación (ningún S cabe) y así
    /// nace la cuenta hasta que Squads fija topes; con tope > 0 todo S cumple S <= tope.
    pub max_service_usdc: [u64; 4],
    /// Tope del S de SALIDA por exceso (D3; lo cobra `withdraw_settle`, PR 5B). 0 = apagado.
    pub max_exit_service_usdc: u64,
    /// 1 = pausa: ningún S > 0 se acepta y ningún init de ENTRADA patrocinado pasa, con
    /// cualquier tope (interruptor total del patrocinio); sin patrocinio y sin S nada cambia.
    /// La SALIDA nunca se estrangula: `withdraw_init` patrocinado pasa y guarda un S de salida
    /// de 0, y `withdraw_settle` cobra 0 (PR 5B). 0 = activo.
    pub paused: u8,
    /// Bump canónico de `[b"service-config"]`.
    pub bump: u8,
    /// Reservado; siempre a cero.
    pub _reserved: [u8; 46],
}

impl ServiceConfig {
    /// 8 + 32 + 32 + 8 + 1 + 1 + 46 = 128.
    pub const LEN: usize = 8 + 32 + 32 + 8 + 1 + 1 + 46;

    /// Tope del servicio para la operación `kind` (índice de `SERVICE_KIND_*`). Fuera de
    /// la tabla de entrada devuelve 0 (fail-closed: cualquier S > 0 revierte).
    pub fn max_for(&self, kind: u8) -> u64 {
        self.max_service_usdc
            .get(kind as usize)
            .copied()
            .unwrap_or(0)
    }
}

// Contrato con los filtros `dataSize` y los parsers: fijado en compilación.
const _: () = assert!(ServiceConfig::LEN == 128, "ServiceConfig::LEN debe ser 128");

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ServiceConfig {
        ServiceConfig {
            treasury_usdc_ata: Pubkey::default(),
            max_service_usdc: [1, 2, 3, 4],
            max_exit_service_usdc: 5,
            paused: 0,
            bump: 0,
            _reserved: [0u8; 46],
        }
    }

    #[test]
    fn max_for_lee_la_tabla_por_indice() {
        let c = cfg();
        assert_eq!(c.max_for(0), 1);
        assert_eq!(c.max_for(1), 2);
        assert_eq!(c.max_for(2), 3);
        assert_eq!(c.max_for(3), 4);
    }

    #[test]
    fn max_for_fuera_de_rango_es_cero_fail_closed() {
        let c = cfg();
        assert_eq!(c.max_for(4), 0);
        assert_eq!(c.max_for(255), 0);
    }
}
