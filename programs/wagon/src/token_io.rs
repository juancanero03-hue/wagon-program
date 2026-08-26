//! Utilidades canónicas de cuentas SPL — refactor R-1 (2026-06-11).
//!
//! Antes de R-1: `verify_token_account` vivía copiada en 6 instrucciones,
//! `read_token_amount` en 3 y el offset de decimales del mint en 3. Una
//! sola copia, un solo sitio que auditar.

use anchor_lang::prelude::*;
use anchor_spl::token::spl_token;

use crate::errors::WagonError;

/// Programa SPL Token-2022 (los xStocks y mints de MetaDAO viven ahí).
pub const TOKEN_2022_PROGRAM_ID: Pubkey =
    anchor_lang::solana_program::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

/// Offset de `decimals` en el layout de Mint (idéntico en classic y 2022).
pub const MINT_DECIMALS_OFFSET: usize = 44;

/// Valida que `acc` es una token account (classic O Token-2022, upgrade
/// #28) con el mint y owner esperados. Lectura byte-level, sin materializar
/// structs en el stack BPF (ADR 0004).
pub fn verify_token_account(
    acc: &AccountInfo,
    expected_mint: &Pubkey,
    expected_owner: &Pubkey,
) -> Result<()> {
    let prog_owner = acc.owner;
    require!(
        *prog_owner == spl_token::ID || *prog_owner == TOKEN_2022_PROGRAM_ID,
        WagonError::InvalidJupiterRoute
    );
    let data = acc.try_borrow_data()?;
    require!(data.len() >= 165, WagonError::InvalidJupiterRoute);
    let mut mint_buf = [0u8; 32];
    mint_buf.copy_from_slice(&data[0..32]);
    let mut owner_buf = [0u8; 32];
    owner_buf.copy_from_slice(&data[32..64]);
    require_keys_eq!(
        Pubkey::new_from_array(mint_buf),
        *expected_mint,
        WagonError::InvalidJupiterRoute
    );
    require_keys_eq!(
        Pubkey::new_from_array(owner_buf),
        *expected_owner,
        WagonError::InvalidJupiterRoute
    );
    Ok(())
}

/// Lee `amount` (offset 64) de una token account sin deserializarla.
pub fn read_token_amount(acc: &AccountInfo) -> Result<u64> {
    let data = acc.try_borrow_data()?;
    if data.len() < 72 {
        return err!(WagonError::InvalidPriceAccount);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[64..72]);
    Ok(u64::from_le_bytes(buf))
}

/// Offset del byte `state` en el layout de una token account SPL (classic o
/// 2022; los primeros 165 B son idénticos): mint(32)+owner(32)+amount(8)+
/// delegate COption(4+32)=108. 0=Uninitialized, 1=Initialized, 2=Frozen.
pub const TOKEN_STATE_OFFSET: usize = 108;
/// Valor de `state` cuando la token account está CONGELADA por su freeze
/// authority (Circle en USDC, el emisor de un token con freeze).
pub const TOKEN_STATE_FROZEN: u8 = 2;

/// Lee el byte `state` (offset 108) de una token account sin deserializarla.
/// Usado por A5 (`deposit_force_release`, ceremonia #50) como PRUEBA de
/// congelación: es una lectura PURA, inmune al propio freeze (leer una cuenta
/// congelada nunca revierte; solo moverla lo hace). El caller valida además
/// mint+owner con `verify_token_account` antes de fiarse de este byte.
pub fn read_token_state(acc: &AccountInfo) -> Result<u8> {
    let data = acc.try_borrow_data()?;
    if data.len() < 165 {
        return err!(WagonError::InvalidJupiterRoute);
    }
    Ok(data[TOKEN_STATE_OFFSET])
}

/// Fail-open (ceremonia #54, DT-B): `true` SOLO si `acc` es una token account
/// VIVA y NO CONGELADA de `expected_mint` (y, si `Some`, propiedad de
/// `expected_owner`). PURA: nunca revierte — una cuenta inexistente, malformada
/// o congelada devuelve `false` y el caller SALTA el transfer de la comisión en
/// vez de tumbar todo el `withdraw_settle`. Espejo booleano de la lectura pura
/// de A5 (`read_token_state`). El destino ya viene key-pinned por el caller; para
/// la tesorería `expected_owner` es `None` porque el programa no almacena su
/// authority, solo la ATA.
pub fn is_payable_usdc_ata(
    acc: &AccountInfo,
    expected_mint: &Pubkey,
    expected_owner: Option<Pubkey>,
) -> bool {
    let prog_owner = acc.owner;
    if *prog_owner != spl_token::ID && *prog_owner != TOKEN_2022_PROGRAM_ID {
        return false;
    }
    let data = match acc.try_borrow_data() {
        Ok(d) => d,
        Err(_) => return false,
    };
    if data.len() < 165 {
        return false;
    }
    if &data[0..32] != expected_mint.as_ref() {
        return false;
    }
    if let Some(owner) = expected_owner {
        if &data[32..64] != owner.as_ref() {
            return false;
        }
    }
    data[TOKEN_STATE_OFFSET] != TOKEN_STATE_FROZEN
}

// ---------------------------------------------------------------------------
// Tipos de extensión TLV de Token-2022 — FUENTE ÚNICA para todos los walkers
// del programa (este fichero y `create_vault::verify_token2022_extensions`).
//
// Numeración del `ExtensionType` upstream (solana-program/token-2022,
// interface/src/extension/mod.rs). 🔴 Ceremonia #55: verificados contra el
// spec oficial Y contra los bytes TLV reales de mints de mainnet (xStocks)
// el 2026-08-26 — la #54 salió con la tabla corrida en uno desde el 24
// (25 tratado como Pausable cuando es ScaledUiAmount) y `withdraw_init`
// aparcaba en falso patas sanas. NUNCA re-derivar estos números de memoria:
// contra fuente o contra bytes vivos.
// ---------------------------------------------------------------------------
pub const EXT_TRANSFER_FEE_CONFIG: u16 = 1;
pub const EXT_CONFIDENTIAL_TRANSFER_MINT: u16 = 4;
pub const EXT_DEFAULT_ACCOUNT_STATE: u16 = 6;
pub const EXT_NON_TRANSFERABLE: u16 = 9;
pub const EXT_PERMANENT_DELEGATE: u16 = 12;
pub const EXT_TRANSFER_HOOK: u16 = 14;
pub const EXT_CONFIDENTIAL_TRANSFER_FEE: u16 = 16;
pub const EXT_METADATA_POINTER: u16 = 18;
pub const EXT_CONFIDENTIAL_MINT_BURN: u16 = 24;
/// Display-only: escala la UI (dividendos/splits de Backed en los xStocks).
/// NO bloquea transferencias; el programa opera SIEMPRE en cantidades crudas.
pub const EXT_SCALED_UI_AMOUNT: u16 = 25;
pub const EXT_PAUSABLE: u16 = 26;

/// Lector PURO (ceremonia #54, DT-D; enum corregido en la #55): ¿el propio MINT
/// bloquea toda transferencia? Sin CPI, inmune a freeze. Devuelve `true` SOLO si
/// camina el TLV de extensiones Token-2022 y encuentra: `NonTransferable` (9), O
/// `TransferHook` (14) ARMADO (`program_id` != 0), O `Pausable` (26) con el byte
/// `paused` (offset 32 del `ext_data`) == 1 LEÍDO EN VIVO. `ScaledUiAmount` (25)
/// NO bloquea: es display-only (su payload de 56 B lleva un multiplicador f64 en
/// el offset 32 — leerlo como si fuera el bool de pausa fue el incidente Athena
/// del 2026-08-26). A diferencia de `create_vault::verify_token2022_extensions`,
/// NO hace short-circuit para mints TRUSTED: `Pausable` solo existe en mints
/// trusted, así que cortar por confianza dejaría su caso primario sin cubrir. Un
/// mint classic (o 2022 sin TLV) da `false`. Espeja el layout base (82 B +
/// padding + discriminador @165 == 1 + TLV {u16 tipo, u16 len, valor} desde el
/// offset 166) de `create_vault`.
pub fn mint_blocks_transfer(mint_data: &[u8]) -> bool {
    if mint_data.len() < 166 || mint_data[165] != 1 {
        return false;
    }
    let mut cursor: usize = 166;
    while cursor + 4 <= mint_data.len() {
        let ext_type = u16::from_le_bytes([mint_data[cursor], mint_data[cursor + 1]]);
        let ext_len = u16::from_le_bytes([mint_data[cursor + 2], mint_data[cursor + 3]]) as usize;
        let val_start = match cursor.checked_add(4) {
            Some(v) => v,
            None => return false,
        };
        let ext_end = match val_start.checked_add(ext_len) {
            Some(v) => v,
            None => return false,
        };
        if ext_end > mint_data.len() {
            return false;
        }
        let ext_data = &mint_data[val_start..ext_end];
        match ext_type {
            0 => break, // Uninitialized: fin de la lista de extensiones.
            EXT_NON_TRANSFERABLE => return true,
            EXT_TRANSFER_HOOK => {
                // TransferHook: 32 B authority + 32 B program_id. Armado <=> program_id != 0.
                if ext_data.len() >= 64 && ext_data[32..64].iter().any(|&b| b != 0) {
                    return true;
                }
            }
            EXT_PAUSABLE => {
                // Pausable (26): 32 B authority + 1 B paused (PodBool). Bloquea <=> paused != 0
                // (en vivo). #55: hasta la #54 este arm decía 25 (= ScaledUiAmount) y el check
                // leía el byte bajo del multiplicador f64 como si fuera `paused` → aparcaba en
                // falso los xStocks con multiplicador ≠ 1,0 (incidente Athena 2026-08-26).
                if ext_data.len() >= 33 && ext_data[32] != 0 {
                    return true;
                }
            }
            // ScaledUiAmount(25)/TransferFeeConfig(1)/DefaultAccountState(6)/
            // PermanentDelegate(12)/metadata… no bloquean transferencias aquí.
            _ => {}
        }
        cursor = ext_end;
    }
    false
}

/// Lee `decimals` de un mint account (classic o 2022).
pub fn read_mint_decimals(mint_ai: &AccountInfo) -> Result<u8> {
    let data = mint_ai.try_borrow_data()?;
    require!(data.len() > MINT_DECIMALS_OFFSET, WagonError::AllocMintMismatch);
    Ok(data[MINT_DECIMALS_OFFSET])
}

/// ATA canónica de (owner, mint) derivada con el token program VIVO del
/// account pasado (lección del upgrade #27: los vaults pre-#27 guardan ATAs
/// derivadas con el programa equivocado para mints Token-2022).
pub fn derive_live_ata(owner: &Pubkey, mint: &Pubkey, live_token_program: &Pubkey) -> Pubkey {
    anchor_spl::associated_token::get_associated_token_address_with_program_id(
        owner,
        mint,
        live_token_program,
    )
}

// ---------------------------------------------------------------------------
// Upgrade #31 (F2b) — CPIs de movimiento de escrow, válidos para classic Y
// Token-2022. Construimos la instrucción a mano (los tags de TransferChecked
// = 12 y CloseAccount = 9 son idénticos en ambos programas) en lugar de usar
// los wrappers tipados de anchor_spl, que están ligados a un Program<> fijo.
// El program_id se toma del OWNER REAL de la cuenta de escrow, así el mismo
// código mueve xStocks (Token-2022) y SPL clásico.
// ---------------------------------------------------------------------------

/// `TransferChecked` firmado por un PDA del programa. `token_program_ai`
/// debe ser el AccountInfo del programa dueño de `from`/`to` (classic o
/// 2022); el caller ya lo validó vía `verify_token_account`.
#[allow(clippy::too_many_arguments)]
pub fn transfer_checked_signed<'info>(
    token_program_ai: &AccountInfo<'info>,
    from: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
    to: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    signer_seeds: &[&[&[u8]]],
    amount: u64,
    decimals: u8,
) -> Result<()> {
    use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
    use anchor_lang::solana_program::program::invoke_signed;

    require!(
        *token_program_ai.key == spl_token::ID || *token_program_ai.key == TOKEN_2022_PROGRAM_ID,
        WagonError::InvalidJupiterRoute
    );
    require_keys_eq!(*from.owner, *token_program_ai.key, WagonError::InvalidJupiterRoute);

    // Layout spl-token: tag(12) | amount u64 LE | decimals u8
    let mut data = Vec::with_capacity(10);
    data.push(12u8);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);

    let ix = Instruction {
        program_id: *token_program_ai.key,
        accounts: vec![
            AccountMeta::new(*from.key, false),
            AccountMeta::new_readonly(*mint.key, false),
            AccountMeta::new(*to.key, false),
            AccountMeta::new_readonly(*authority.key, true),
        ],
        data,
    };
    invoke_signed(
        &ix,
        &[from.clone(), mint.clone(), to.clone(), authority.clone()],
        signer_seeds,
    )
    .map_err(|e| {
        msg!("transfer_checked CPI failed: {:?}", e);
        error!(WagonError::InvalidJupiterRoute)
    })
}

/// `CloseAccount` firmado por un PDA del programa. La renta va a `dest`.
pub fn close_token_account_signed<'info>(
    token_program_ai: &AccountInfo<'info>,
    account: &AccountInfo<'info>,
    dest: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
    use anchor_lang::solana_program::program::invoke_signed;

    require!(
        *token_program_ai.key == spl_token::ID || *token_program_ai.key == TOKEN_2022_PROGRAM_ID,
        WagonError::InvalidJupiterRoute
    );
    require_keys_eq!(*account.owner, *token_program_ai.key, WagonError::InvalidJupiterRoute);

    let ix = Instruction {
        program_id: *token_program_ai.key,
        accounts: vec![
            AccountMeta::new(*account.key, false),
            AccountMeta::new(*dest.key, false),
            AccountMeta::new_readonly(*authority.key, true),
        ],
        data: vec![9u8],
    };
    invoke_signed(
        &ix,
        &[account.clone(), dest.clone(), authority.clone()],
        signer_seeds,
    )
    .map_err(|e| {
        msg!("close_account CPI failed: {:?}", e);
        error!(WagonError::InvalidJupiterRoute)
    })
}

// ---------------------------------------------------------------------------
// Tests unitarios (#55): el parser TLV contra BYTES REALES de mainnet.
// El incidente Athena (2026-08-26) existió porque las ramas de este lector se
// revisaron pero nunca se ejecutaron contra un mint real con extensiones: la
// fixture de abajo son los bytes VIVOS del mint SPYx capturados ese día, y las
// variantes se fabrican por cirugía localizada (find_ext), no por offsets
// mágicos. Corren con `cargo test -p wagon --lib` (paso BLOQUEANTE del CI).
// ---------------------------------------------------------------------------
#[cfg(test)]
pub mod test_fixtures {
    /// Mint SPYx (`XsoCS1TfEyfFhfvj8EtZ528L3CaKBDBRqRapnBbDF2W`) — bytes REALES
    /// de mainnet (getAccountInfo, 676 B, 2026-08-26). mint_authority = Backed
    /// (`7pt9tkctJPK7PPNQJ77GKg8ZffSF6QxoMiCFYHxrtaCj`, trusted). TLV en orden:
    /// 18 MetadataPointer · 12 PermanentDelegate · 6 DefaultAccountState(=1) ·
    /// 25 ScaledUiAmount (multiplier 1.003909…, byte bajo 0x24 ≠ 0) ·
    /// 26 Pausable (paused = 0) · 4 ConfidentialTransferMint ·
    /// 14 TransferHook (program_id = ceros, desarmado) · 19 TokenMetadata.
    pub const SPYX_MINT_HEX: &str = concat!(
    "01000000656a42422fea891406a419d1d1de08f42a847941b5a1ae95ebce619a",
    "c317293424758c5ba9080000080101000000ffdfec1bcd2cd38393c84daa08c9",
    "1cc0d38d677ff8d0ab7b5d033f00f732cc300000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000011200400043f9f1ee2e37b807ea45cb74e6009722bec009296026",
    "e4e4558b435e24a5e9c607e8dc2cde7b23a0d743f8f1276b657d8a9eea06950b",
    "a67a8d3033c53c4cde4f0c00200043f9f1ee2e37b807ea45cb74e6009722bec0",
    "09296026e4e4558b435e24a5e9c6060001000119003800066f592251cc477478",
    "25a59ad1422ea43573f528da5dee2af7812b314f9945e3240ba0220310f03f40",
    "6d336a00000000d0a598266817f03f1a002100ffdfec1bcd2cd38393c84daa08",
    "c91cc0d38d677ff8d0ab7b5d033f00f732cc30000400410043f9f1ee2e37b807",
    "ea45cb74e6009722bec009296026e4e4558b435e24a5e9c60000000000000000",
    "000000000000000000000000000000000000000000000000000e00400043f9f1",
    "ee2e37b807ea45cb74e6009722bec009296026e4e4558b435e24a5e9c6000000",
    "00000000000000000000000000000000000000000000000000000000001300a3",
    "0043f9f1ee2e37b807ea45cb74e6009722bec009296026e4e4558b435e24a5e9",
    "c607e8dc2cde7b23a0d743f8f1276b657d8a9eea06950ba67a8d3033c53c4cde",
    "4f0c0000005350353030207853746f636b040000005350597843000000687474",
    "70733a2f2f7873746f636b732d6d657461646174612e6261636b65642e66692f",
    "746f6b656e732f536f6c616e612f535059782f6d657461646174612e6a736f6e",
    "00000000"
    );

    /// Decodificador hex mínimo (sin dependencias nuevas: el lockfile del build
    /// oficial no se toca por un dev-dep).
    pub fn hex_decode(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        assert!(bytes.len() % 2 == 0, "hex de longitud impar");
        (0..bytes.len() / 2)
            .map(|i| {
                let hi = (bytes[2 * i] as char).to_digit(16).expect("hex invalido");
                let lo = (bytes[2 * i + 1] as char).to_digit(16).expect("hex invalido");
                (hi * 16 + lo) as u8
            })
            .collect()
    }

    pub fn spyx_bytes() -> Vec<u8> {
        let d = hex_decode(SPYX_MINT_HEX);
        assert_eq!(d.len(), 676, "fixture SPYx corrupta");
        d
    }

    /// Localiza la PRIMERA extensión `ext_type` del TLV y devuelve
    /// `(payload_start, payload_len)`. Camina igual que los lectores del
    /// programa (base 82 + padding + discriminador @165, TLV desde 166).
    pub fn find_ext(data: &[u8], ext_type: u16) -> Option<(usize, usize)> {
        if data.len() < 166 || data[165] != 1 {
            return None;
        }
        let mut cursor = 166usize;
        while cursor + 4 <= data.len() {
            let et = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
            let el = u16::from_le_bytes([data[cursor + 2], data[cursor + 3]]) as usize;
            if et == 0 {
                return None;
            }
            let start = cursor + 4;
            let end = start.checked_add(el)?;
            if end > data.len() {
                return None;
            }
            if et == ext_type {
                return Some((start, el));
            }
            cursor = end;
        }
        None
    }

    /// Sobrescribe el TIPO de la extensión cuyo payload empieza en
    /// `payload_start` (los 2 bytes de tipo van 4 por delante del payload).
    pub fn set_ext_type(data: &mut [u8], payload_start: usize, new_type: u16) {
        let t = new_type.to_le_bytes();
        data[payload_start - 4] = t[0];
        data[payload_start - 3] = t[1];
    }
}

#[cfg(test)]
mod tests {
    use super::test_fixtures::*;
    use super::*;

    /// La aserción que habría cazado el incidente Athena: un mint xStock REAL
    /// (ScaledUiAmount con multiplicador ≠ 1,0 + Pausable con paused = 0 + hook
    /// desarmado) NO bloquea transferencias.
    #[test]
    fn spyx_real_no_bloquea() {
        assert!(!mint_blocks_transfer(&spyx_bytes()));
    }

    /// Pausa REAL de Backed (paused = 1 en la ext 26): SÍ bloquea. Hasta la #54
    /// este caso era invisible (el lector miraba la 25) y habría estrangulado
    /// el retiro entero al reventar el transfer_checked.
    #[test]
    fn pausable_pausado_bloquea() {
        let mut d = spyx_bytes();
        // Aislar el arm 26 (revision adversarial #55): con la tabla VIEJA el arm
        // «25» devolvia true por el byte 0x24 del multiplicador ANTES de llegar a
        // la 26, y este test pasaba por la razon equivocada (gotcha 43). Con el
        // multiplicador en 1,0 exacto (byte bajo 0) el true solo puede venir de
        // leer la pausa REAL en la ext 26.
        let (ps, _) = find_ext(&d, EXT_SCALED_UI_AMOUNT).expect("SPYx trae ScaledUiAmount");
        d[ps + 32..ps + 40].copy_from_slice(&1.0f64.to_le_bytes());
        let (p, l) = find_ext(&d, EXT_PAUSABLE).expect("SPYx trae Pausable");
        assert_eq!(l, 33, "PausableConfig = authority 32 + PodBool 1");
        d[p + 32] = 1;
        assert!(mint_blocks_transfer(&d));
    }

    /// Multiplicador EXACTAMENTE 1,0 (byte bajo del f64 = 0): tampoco bloquea.
    /// Documenta el disparo intermitente del bug viejo: con la tabla corrida,
    /// el falso positivo dependia de si Backed habia aplicado ya un dividendo.
    #[test]
    fn scaled_ui_multiplicador_redondo_no_bloquea() {
        let mut d = spyx_bytes();
        let (p, l) = find_ext(&d, EXT_SCALED_UI_AMOUNT).expect("SPYx trae ScaledUiAmount");
        assert_eq!(l, 56, "ScaledUiAmountConfig = auth 32 + f64 8 + i64 8 + f64 8");
        d[p + 32..p + 40].copy_from_slice(&1.0f64.to_le_bytes());
        assert!(!mint_blocks_transfer(&d));
    }

    #[test]
    fn hook_armado_bloquea() {
        let mut d = spyx_bytes();
        let (p, l) = find_ext(&d, EXT_TRANSFER_HOOK).expect("SPYx trae TransferHook");
        assert_eq!(l, 64, "TransferHook = authority 32 + program_id 32");
        d[p + 32] = 0xAB; // program_id != 0 => hook armado
        assert!(mint_blocks_transfer(&d));
    }

    #[test]
    fn non_transferable_bloquea() {
        let mut d = spyx_bytes();
        let (p, _) = find_ext(&d, EXT_METADATA_POINTER).expect("SPYx trae MetadataPointer");
        set_ext_type(&mut d, p, EXT_NON_TRANSFERABLE);
        assert!(mint_blocks_transfer(&d));
    }

    #[test]
    fn mint_clasico_no_bloquea() {
        assert!(!mint_blocks_transfer(&[0u8; 82]));
    }

    #[test]
    fn t22_sin_extensiones_no_bloquea() {
        let mut d = vec![0u8; 166];
        d[165] = 1;
        assert!(!mint_blocks_transfer(&d));
    }

    #[test]
    fn discriminador_no_mint_no_bloquea() {
        let mut d = spyx_bytes();
        d[165] = 2; // Account, no Mint
        assert!(!mint_blocks_transfer(&d));
    }

    /// Una longitud TLV desbordada no panica ni bloquea (fail-safe del walker).
    #[test]
    fn tlv_len_desbordada_no_panica() {
        let mut d = spyx_bytes();
        let (p, _) = find_ext(&d, EXT_SCALED_UI_AMOUNT).unwrap();
        d[p - 2] = 0xFF;
        d[p - 1] = 0xFF; // len = 65535 > resto del buffer
        assert!(!mint_blocks_transfer(&d));
    }
}
