//! Ceremonia USDC §3.5 — servicio S (gas patrocinado convertido a USDC) como ARGUMENTO
//! firmado de cada init: `create_vault`, `deposit_init`, `rebalance`, `restructure_init`
//! (cobrado en el propio init) y, en la SALIDA (PR 5B), `withdraw_init` (`exit_service_usdc`,
//! guardado en el `FundingRecord` y cobrado por `withdraw_settle` del USDC que sale).
//!
//! Por qué un argumento y no una instrucción suelta: el programa no ve el resto de la
//! transacción; con S dentro del init, una operación con sesión propia = un cobro, atómico
//! con ella (si el init revierte, no hay cargo).
//!
//! Reglas (una sola copia, PURA y con tests). Regla ESTRICTA (5A-bis): patrocinar (`payer !=
//! propietario`) exige S > 0 SIEMPRE (`ServiceRequired`), con cualquier tope: un tope a 0 o la
//! pausa BLOQUEAN el patrocinio de esa operación (S = 0 → `ServiceRequired`; S > 0 →
//! `ServiceAmountAboveMax` / `ServicePaused`); así nace la cuenta hasta que Squads fija los
//! topes antes de activar el patrocinio. Todo `S > 0` exige además `S <= tope` y sin pausa.
//! `S == 0` sin patrocinio pasa siempre y no toca nada. `rebalance` no tiene `payer`: se
//! llama con `sponsored = false` (S opcional; si viene, tope y pausa) y lleva un candado por
//! slot en el vault (`vault_layout::LAST_SERVICE_SLOT_*`) contra varios cobros en un mensaje.
//!
//! Cobro: desde la ATA CANÓNICA de USDC del USUARIO (5A-bis: derivación canónica + mint USDC
//! + dueño = el firmante del init, que así autoriza el débito) a
//! la tesorería del protocolo (`protocol.treasury_usdc_ata`, la ÚNICA fijada en
//! `initialize`, D5; `ServiceConfig.treasury_usdc_ata` es su espejo informativo) y PAGABLE:
//! los inits no son salidas, así que un tesoro no pagable REVIERTE.
use anchor_lang::prelude::*;
use anchor_spl::token::{spl_token, self, Transfer};

use crate::constants::SERVICE_USDC_MAX;
use crate::errors::WagonError;
use crate::state::{ProtocolConfig, ServiceConfig};
use crate::token_io::{derive_live_ata, is_payable_usdc_ata, verify_token_account};

/// Decide si `service_usdc` es admisible para esta llamada. PURA.
///
/// Regla ESTRICTA del diseño §3.5 (5A-bis, decisión de diseño
/// 25-sep): con patrocinio (`payer` distinto del propietario) S debe ser MAYOR que 0 SIEMPRE,
/// sin la excepción «tope 0 = apagado» que había hasta el PR #40. Consecuencia: con un tope a
/// 0 o en pausa ningún init patrocinado pasa (S = 0 → 6199; S > 0 → 6201 o 6202): el
/// patrocinio queda BLOQUEADO hasta que Squads fije los topes. Sin patrocinio S = 0 vale siempre y no valida nada.
pub fn check_service(sponsored: bool, service_usdc: u64, max: u64, paused: u8) -> Result<()> {
    if service_usdc == 0 {
        require!(!sponsored, WagonError::ServiceRequired);
        return Ok(());
    }
    require!(paused == 0, WagonError::ServicePaused);
    require!(service_usdc <= max, WagonError::ServiceAmountAboveMax);
    Ok(())
}

/// PR 5B (§3.5, D3 / M-04): S de SALIDA que `withdraw_init` GUARDA en el `FundingRecord`.
/// El inversor lo firma como argumento y aquí se ACOTA, nunca se rechaza por importe (lado
/// SALIDA: el tope clampa): `min(pedido, tope vivo)`, y 0 en pausa (la pausa apaga todo S).
/// Sin patrocinio no hay registro donde guardarlo: un S > 0 es un cliente roto y revierte
/// (`ExitServiceWithoutSponsor`); con 0 pasa siempre y no lee nada. PURA.
pub fn exit_service_at_init(sponsored: bool, requested: u64, max_exit: u64, paused: u8) -> Result<u64> {
    if requested == 0 {
        return Ok(0);
    }
    require!(sponsored, WagonError::ExitServiceWithoutSponsor);
    if paused != 0 {
        return Ok(0);
    }
    Ok(requested.min(max_exit))
}

/// S de salida que `withdraw_settle` COBRA del USDC que sale: `min(guardado, tope vivo, USDC
/// al inversor)`, 0 en pausa. Jamás revierte: el tope pudo bajar entre el init y el settle, y
/// en una salida en especie solo sale el USDC ocioso del vault (si lo hay), así que el mínimo
/// acota el cobro a eso (sin USDC, 0). PURA.
pub fn exit_service_at_settle(stored: u64, max_exit: u64, paused: u8, usdc_to_investor: u64) -> u64 {
    if paused != 0 {
        return 0;
    }
    stored.min(max_exit).min(usdc_to_investor)
}

/// `(max_exit_service_usdc, paused)` leídos de la cuenta `ServiceConfig` SIN revertir jamás:
/// si la dirección (ya atada por `seeds` en el contexto) no es una cuenta del programa con el
/// tamaño y el discriminador del singleton, devuelve `(0, 0)` = S de salida apagado. Para la
/// SALIDA (`withdraw_init` y `withdraw_settle`): ni la entrada a la salida ni ningún terminal del
/// retiro dependen de que una cuenta nueva exista. Los 4 inits de ENTRADA siguen exigiendo la
/// cuenta tipada.
pub fn read_exit_params_lenient(ai: &AccountInfo) -> (u64, u8) {
    if ai.owner != &crate::ID {
        return (0, 0);
    }
    let data = match ai.try_borrow_data() {
        Ok(d) => d,
        Err(_) => return (0, 0),
    };
    if data.len() != ServiceConfig::LEN {
        return (0, 0);
    }
    match ServiceConfig::try_deserialize(&mut &data[..]) {
        Ok(cfg) => (cfg.max_exit_service_usdc, cfg.paused),
        Err(_) => (0, 0),
    }
}

/// Parámetros de `init_service_config` / `set_service_params`: cada tope hasta
/// `SERVICE_USDC_MAX` (50 USDC) y `paused` 0 o 1. PURA.
pub fn validate_service_params(
    max_service_usdc: &[u64; 4],
    max_exit_service_usdc: u64,
    paused: u8,
) -> Result<()> {
    require!(
        max_service_usdc.iter().all(|m| *m <= SERVICE_USDC_MAX)
            && max_exit_service_usdc <= SERVICE_USDC_MAX
            && paused <= 1,
        WagonError::InvalidServiceParams
    );
    Ok(())
}

/// Cuentas del cobro (referencias a los `AccountInfo` del ctx).
pub struct ServiceAccounts<'a, 'info> {
    /// Quien paga S: FIRMA el init (inversor o creador).
    pub user: &'a AccountInfo<'info>,
    pub user_usdc_ata: &'a AccountInfo<'info>,
    pub treasury_usdc_ata: &'a AccountInfo<'info>,
    pub token_program: &'a AccountInfo<'info>,
}

/// Transfiere `service_usdc` átomos de USDC del usuario a la tesorería del protocolo.
/// Con 0 no toca ni valida ninguna cuenta. Devuelve lo cobrado.
pub fn charge_service_usdc<'info>(
    protocol: &ProtocolConfig,
    service_usdc: u64,
    a: &ServiceAccounts<'_, 'info>,
) -> Result<u64> {
    if service_usdc == 0 {
        return Ok(0);
    }
    let usdc_mint = &protocol.usdc_mint;
    // Origen: la ATA CANÓNICA de USDC del usuario que firma (5A-bis), verificada además
    // como cuenta viva del mint
    // (error PROPIO del servicio, no el genérico `InvalidJupiterRoute`). Mismo patrón que
    // `creator_fee.rs` para la comisión del creador.
    require_keys_eq!(
        a.user_usdc_ata.key(),
        derive_live_ata(a.user.key, usdc_mint, &spl_token::ID),
        WagonError::ServiceUserAtaMismatch
    );
    verify_token_account(a.user_usdc_ata, usdc_mint, a.user.key)
        .map_err(|_| error!(WagonError::ServiceUserAtaMismatch))?;
    // Destino: la ÚNICA tesorería del protocolo (fijada en `initialize`; D5), pagable.
    require_keys_eq!(
        a.treasury_usdc_ata.key(),
        protocol.treasury_usdc_ata,
        WagonError::ServiceTreasuryMismatch
    );
    require!(
        is_payable_usdc_ata(a.treasury_usdc_ata, usdc_mint, None),
        WagonError::TreasuryNotPayable
    );
    token::transfer(
        CpiContext::new(
            a.token_program.clone(),
            Transfer {
                from: a.user_usdc_ata.clone(),
                to: a.treasury_usdc_ata.clone(),
                authority: a.user.clone(),
            },
        ),
        service_usdc,
    )?;
    Ok(service_usdc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::error::ERROR_CODE_OFFSET;

    fn code(r: Result<()>) -> u32 {
        match r {
            Ok(()) => 0,
            Err(Error::AnchorError(e)) => e.error_code_number,
            Err(_) => u32::MAX,
        }
    }
    fn c(e: WagonError) -> u32 {
        e as u32 + ERROR_CODE_OFFSET
    }

    #[test]
    fn sin_patrocinio_s_cero_pasa_siempre() {
        assert_eq!(code(check_service(false, 0, 0, 0)), 0);
        assert_eq!(code(check_service(false, 0, 0, 1)), 0, "ni la pausa ni el tope 0 frenan S = 0");
    }

    #[test]
    fn patrocinio_exige_s_mayor_que_cero() {
        assert_eq!(code(check_service(true, 0, 1_000_000, 0)), c(WagonError::ServiceRequired));
        assert_eq!(code(check_service(true, 1, 1_000_000, 0)), 0);
        // 5A-bis (regla ESTRICTA): tampoco con el tope a 0. Antes del PR «tope 0 = apagado» dejaba
        // pasar el patrocinio sin S; ahora ningún init patrocinado pasa hasta que Squads fija topes.
        assert_eq!(code(check_service(true, 0, 0, 0)), c(WagonError::ServiceRequired), "tope 0: patrocinar sin S ya no es legacy");
    }

    #[test]
    fn s_positivo_respeta_pausa_y_tope_en_ese_orden() {
        assert_eq!(code(check_service(false, 1, 1_000_000, 1)), c(WagonError::ServicePaused));
        assert_eq!(code(check_service(true, 5, 1, 1)), c(WagonError::ServicePaused), "la pausa manda sobre el tope");
        assert_eq!(code(check_service(true, 1_000_001, 1_000_000, 0)), c(WagonError::ServiceAmountAboveMax));
        assert_eq!(code(check_service(false, 1_000_001, 1_000_000, 0)), c(WagonError::ServiceAmountAboveMax), "el tope aplica también sin patrocinio");
        assert_eq!(code(check_service(true, 1_000_000, 1_000_000, 0)), 0, "el tope es inclusivo");
    }

    #[test]
    fn combinaciones_restantes_de_la_tabla_de_dieciseis() {
        assert_eq!(code(check_service(false, 0, 1_000_000, 0)), 0, "sin patrocinio, S = 0, tope > 0, sin pausa");
        assert_eq!(code(check_service(true, 1, 0, 1)), c(WagonError::ServicePaused), "patrocinado, S > 0, tope 0 y pausa: manda la pausa");
        assert_eq!(code(check_service(false, 1, 0, 1)), c(WagonError::ServicePaused), "sin patrocinio, S > 0, tope 0 y pausa: manda la pausa");
        assert_eq!(code(check_service(false, 300_000, 1_000_000, 0)), 0, "sin patrocinio, 0 < S <= tope, sin pausa: pasa y se cobra");
    }

    #[test]
    fn tope_cero_bloquea_el_patrocinio_por_completo_y_no_toca_al_no_patrocinado() {
        assert_eq!(code(check_service(true, 0, 0, 0)), c(WagonError::ServiceRequired), "tope 0 + S = 0 → 6199");
        assert_eq!(code(check_service(true, 1, 0, 0)), c(WagonError::ServiceAmountAboveMax), "tope 0 + S > 0 → 6201");
        assert_eq!(code(check_service(false, 0, 0, 0)), 0, "sin patrocinio S = 0 pasa siempre");
        assert_eq!(code(check_service(false, 1, 0, 0)), c(WagonError::ServiceAmountAboveMax), "sin patrocinio S > 0 respeta el tope");
    }

    #[test]
    fn la_pausa_es_el_interruptor_total_del_patrocinio_con_cualquier_tope() {
        assert_eq!(code(check_service(true, 0, 1_000_000, 1)), c(WagonError::ServiceRequired), "tope > 0");
        assert_eq!(code(check_service(true, 0, 0, 1)), c(WagonError::ServiceRequired), "tope 0: la pausa también corta");
        assert_eq!(code(check_service(true, 1, 1_000_000, 1)), c(WagonError::ServicePaused));
        assert_eq!(code(check_service(false, 0, 1_000_000, 1)), 0, "sin patrocinio y sin S nada se frena");
        assert_eq!(code(check_service(false, 0, 0, 1)), 0);
    }

    #[test]
    fn s_de_salida_en_el_init_clampa_y_solo_revierte_sin_patrocinio() {
        // 0 pasa siempre, patrocinado o no, en pausa o no.
        assert_eq!(exit_service_at_init(false, 0, 0, 1).unwrap(), 0);
        assert_eq!(exit_service_at_init(true, 0, 1_000_000, 0).unwrap(), 0);
        // Sin patrocinio no hay registro: S > 0 es un cliente roto.
        assert_eq!(code(exit_service_at_init(false, 1, 1_000_000, 0).map(|_| ())), c(WagonError::ExitServiceWithoutSponsor));
        // Patrocinado: clamp al tope (inclusivo), nunca revierte por importe.
        assert_eq!(exit_service_at_init(true, 300_000, 1_000_000, 0).unwrap(), 300_000);
        assert_eq!(exit_service_at_init(true, 1_000_000, 1_000_000, 0).unwrap(), 1_000_000);
        assert_eq!(exit_service_at_init(true, 1_000_001, 1_000_000, 0).unwrap(), 1_000_000, "clampa al tope");
        assert_eq!(exit_service_at_init(true, 5, 0, 0).unwrap(), 0, "tope 0 = apagado: guarda 0, no revierte");
        // Pausa: guarda 0, no revierte (la salida nunca se estrangula).
        assert_eq!(exit_service_at_init(true, 300_000, 1_000_000, 1).unwrap(), 0);
        // Sin patrocinio manda el 6206 también en pausa (el orden de las guardas está fijado).
        assert_eq!(code(exit_service_at_init(false, 1, 1_000_000, 1).map(|_| ())), c(WagonError::ExitServiceWithoutSponsor));
        // Sin singleton (ventana de ceremonia): el lector tolerante da (0, 0) y se guarda 0.
        assert_eq!(exit_service_at_init(true, 300_000, 0, 0).unwrap(), 0);
    }

    #[test]
    fn s_de_salida_en_el_settle_es_el_minimo_de_tres_y_cero_en_pausa() {
        assert_eq!(exit_service_at_settle(300_000, 1_000_000, 0, 5_000_000), 300_000, "cobra lo guardado");
        assert_eq!(exit_service_at_settle(300_000, 100_000, 0, 5_000_000), 100_000, "el tope bajó: cobra el vivo");
        assert_eq!(exit_service_at_settle(300_000, 1_000_000, 0, 40_000), 40_000, "no hay más USDC: cobra lo que hay");
        assert_eq!(exit_service_at_settle(300_000, 1_000_000, 0, 0), 0, "en especie: sin USDC, cobra 0");
        assert_eq!(exit_service_at_settle(300_000, 0, 0, 5_000_000), 0, "tope 0 = apagado");
        assert_eq!(exit_service_at_settle(300_000, 1_000_000, 1, 5_000_000), 0, "pausa = 0");
        assert_eq!(exit_service_at_settle(0, 1_000_000, 0, 5_000_000), 0, "sin registro o legacy: 0");
    }

    #[test]
    fn el_lector_tolerante_nunca_revierte_y_cada_negativo_cae_por_su_propia_guarda() {
        use anchor_lang::Discriminator;
        let key = Pubkey::new_unique();
        let cfg = ServiceConfig {
            treasury_usdc_ata: Pubkey::new_unique(),
            max_service_usdc: [0; 4],
            max_exit_service_usdc: 700_000,
            paused: 1,
            bump: 254,
            _reserved: [0u8; 46],
        };
        let mut valid = ServiceConfig::DISCRIMINATOR.to_vec();
        cfg.serialize(&mut valid).unwrap();
        assert_eq!(valid.len(), ServiceConfig::LEN);
        let read = |owner: &Pubkey, data: &mut Vec<u8>| -> (u64, u8) {
            let mut lamports = 1u64;
            let ai = AccountInfo::new(&key, false, false, &mut lamports, &mut data[..], owner, false, 0);
            read_exit_params_lenient(&ai)
        };
        // (d) el singleton real → sus valores.
        assert_eq!(read(&crate::ID, &mut valid.clone()), (700_000, 1));
        // Cada negativo parte de los MISMOS bytes válidos, así que solo su propia guarda lo para:
        // (a) dueño ajeno; (b) 1 B de más con dueño = programa; (c) discriminador corrompido.
        assert_eq!(read(&Pubkey::new_unique(), &mut valid.clone()), (0, 0), "dueño ajeno");
        let mut larga = valid.clone();
        larga.push(0);
        assert_eq!(read(&crate::ID, &mut larga), (0, 0), "tamaño distinto");
        let mut disc = valid.clone();
        disc[0] ^= 0xff;
        assert_eq!(read(&crate::ID, &mut disc), (0, 0), "discriminador distinto");
        // (e) la ventana de ceremonia: la PDA es una cuenta del sistema sin datos → apagado.
        assert_eq!(read(&anchor_lang::solana_program::system_program::ID, &mut Vec::new()), (0, 0), "sin singleton");
    }

    /// Canario del D-1 (juez de 5B): la SALIDA nunca exige el singleton. Si alguien vuelve a tipar
    /// `service_config` en `withdraw_init` o `withdraw_settle` (la «armonización» natural con los
    /// 4 inits de entrada), ninguna suite lo notaría (el singleton nace en la 04, antes de cualquier
    /// retiro) y se reabriría en silencio la ventana en la que nadie puede empezar ni terminar una
    /// salida. Este test lee el FUENTE de las dos instrucciones.
    #[test]
    fn la_salida_no_exige_el_singleton() {
        for (name, src) in [
            ("withdraw_init", include_str!("instructions/withdraw_init.rs")),
            ("withdraw_settle", include_str!("instructions/withdraw_settle.rs")),
        ] {
            assert!(src.contains("pub service_config: UncheckedAccount<'info>,"), "{name}: service_config debe ir SIN tipo");
            assert!(src.contains("read_exit_params_lenient("), "{name}: debe leer el singleton de forma tolerante");
            assert!(!src.contains("Account<'info, ServiceConfig>"), "{name}: no debe exigir la cuenta tipada");
        }
    }

    #[test]
    fn parametros_dentro_del_techo() {
        assert_eq!(code(validate_service_params(&[0, 0, 0, 0], 0, 0)), 0);
        assert_eq!(code(validate_service_params(&[SERVICE_USDC_MAX; 4], SERVICE_USDC_MAX, 1)), 0);
        assert_eq!(code(validate_service_params(&[0, SERVICE_USDC_MAX + 1, 0, 0], 0, 0)), c(WagonError::InvalidServiceParams));
        assert_eq!(code(validate_service_params(&[0; 4], SERVICE_USDC_MAX + 1, 0)), c(WagonError::InvalidServiceParams));
        assert_eq!(code(validate_service_params(&[0; 4], 0, 2)), c(WagonError::InvalidServiceParams));
    }
}
