//! G4 (auditoría 2026-10-09, F5B-01 y F5A-01; diseño `docs/tools-g4-20261017/DISENO-G4-2026-10-17.md`, 17-oct-2026): las huchas
//! de una sesión las crea el PROGRAMA en su init (CPI al programa de ATAs; paga `payer`), y el rent de cada hucha acaba en quien lo
//! pagó. Así ninguna hucha patrocinada nace fuera del init que la ata a su `FundingRecord` (el retiro de siete patas cabe en una
//! sola transacción) y una hucha que ya existía al llegar el init (de una sesión anterior de la pareja, o creada por cualquiera: su
//! dirección es predecible) se COMPRA al que la pagó si es de la otra clase: el pagador de ahora le transfiere el rent mínimo de su
//! tamaño, nunca lo que alguien haya donado de más. Dos clases de pagador: el INVERSOR y WAGON (cualquier `payer` distinto del
//! inversor: el patrocinio). Dentro de su sesión nada cambia: la hucha se cierra hacia el PDA de la sesión y su rent sale con el
//! terminal hacia el destino del registro (`refund_to`). Lo nuevo es la hucha que SOBREVIVE a su sesión (solo pasa tras un
//! congelado) y que después compra un init de la otra clase o cierra una instrucción sin sesión: el registro de aquella sesión ya
//! no existe, así que el rent de una hucha de Wagon va a `protocol.authority` (la tesorería de Squads) y el de una del inversor,
//! al inversor.
//!
//! Dónde se guarda la clase de una hucha USDC que sobrevive a su sesión (solo pasa tras un congelado): la del DEPÓSITO en la propia
//! hucha (`close_authority` = el PDA de su sesión es la marca de Wagon; con ella la hucha se sigue cerrando con la firma de la
//! sesión, y una hucha de depósito nunca está congelada en un init que sale bien); la del RETIRO en `UserPosition`, que se puede
//! escribir aunque la hucha esté congelada.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::{get_return_data, invoke};
use anchor_lang::solana_program::program_option::COption;
use anchor_lang::solana_program::program_pack::Pack;
use anchor_lang::system_program;
use anchor_spl::associated_token::{self, Create};
use anchor_spl::token::spl_token::instruction::AuthorityType;
use anchor_spl::token::{self, spl_token, SetAuthority};

use crate::errors::WagonError;
use crate::events::SessionEscrowRentBought;
use crate::token_io::{EXT_IMMUTABLE_OWNER, T22_IX_GET_ACCOUNT_DATA_SIZE, TOKEN_2022_PROGRAM_ID};

/// ¿Existe ya la cuenta? Una dirección del System Program sin datos no existe, aunque alguien le haya donado lamports (el
/// programa de ATAs la crea encima y completa su rent).
pub fn account_exists(ai: &AccountInfo) -> bool {
    !(*ai.owner == System::id() && ai.data_is_empty())
}

/// Tamaño de la hucha (cuenta asociada) que crearía el programa de ATAs para `mint`: la de SPL clásico es fija; en Token-2022, la
/// que devuelve `GetAccountDataSize` con `ImmutableOwner`, la misma CPI que hace el programa de ATAs.
pub fn escrow_len<'info>(mint: &AccountInfo<'info>, token_program: &AccountInfo<'info>) -> Result<usize> {
    if *token_program.key == spl_token::ID {
        return Ok(spl_token::state::Account::LEN);
    }
    require_keys_eq!(*token_program.key, TOKEN_2022_PROGRAM_ID, WagonError::InvalidJupiterRoute);
    let mut data = vec![T22_IX_GET_ACCOUNT_DATA_SIZE];
    data.extend_from_slice(&EXT_IMMUTABLE_OWNER.to_le_bytes());
    let ix = Instruction { program_id: TOKEN_2022_PROGRAM_ID, accounts: vec![AccountMeta::new_readonly(*mint.key, false)], data };
    invoke(&ix, &[mint.clone(), token_program.clone()])?;
    let (from, ret) = get_return_data().ok_or(error!(WagonError::InvalidJupiterRoute))?;
    require_keys_eq!(from, TOKEN_2022_PROGRAM_ID, WagonError::InvalidJupiterRoute);
    let bytes: [u8; 8] = ret.as_slice().try_into().map_err(|_| error!(WagonError::InvalidJupiterRoute))?;
    usize::try_from(u64::from_le_bytes(bytes)).map_err(|_| error!(WagonError::MathOverflow))
}

/// Lamports con que quedará una hucha que se crea ahora con `len` bytes: como el programa de ATAs, el rent mínimo (al menos 1) o
/// lo que ya tuviera la dirección si es más (solo completa la diferencia).
pub fn lamports_after_create(ai: &AccountInfo, len: usize) -> Result<u64> {
    Ok(ai.lamports().max(Rent::get()?.minimum_balance(len).max(1)))
}

/// Crea la hucha `escrow` (la cuenta asociada de `owner` para `mint`) por CPI al programa de ATAs; paga `payer`.
pub fn create_escrow<'info>(
    ata_program: &AccountInfo<'info>,
    payer: &AccountInfo<'info>,
    escrow: &AccountInfo<'info>,
    owner: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
    system_program: &AccountInfo<'info>,
    token_program: &AccountInfo<'info>,
) -> Result<()> {
    associated_token::create_idempotent(CpiContext::new(
        ata_program.clone(),
        Create {
            payer: payer.clone(),
            associated_token: escrow.clone(),
            authority: owner.clone(),
            mint: mint.clone(),
            system_program: system_program.clone(),
            token_program: token_program.clone(),
        },
    ))
}

/// El pagador de ahora compra a `to` el rent de una hucha que pagó la otra clase: el rent mínimo de su tamaño, nunca más de lo que
/// tiene (lo donado de más no se compra), por el System Program. Emite `SessionEscrowRentBought`.
pub fn buy_escrow_rent<'info>(
    system_program: &AccountInfo<'info>,
    payer: &AccountInfo<'info>,
    to: &AccountInfo<'info>,
    escrow: &AccountInfo<'info>,
    session: Pubkey,
) -> Result<()> {
    let lamports = Rent::get()?.minimum_balance(escrow.data_len()).min(escrow.lamports());
    if lamports > 0 {
        system_program::transfer(
            CpiContext::new(system_program.clone(), system_program::Transfer { from: payer.clone(), to: to.clone() }),
            lamports,
        )?;
    }
    emit!(SessionEscrowRentBought { session, escrow: escrow.key(), from: payer.key(), to: to.key(), lamports });
    Ok(())
}

/// La cuenta a la que va el rent de una hucha de Wagon cuando no hay registro que lo reciba: la opcional `rent_authority`, que
/// tiene que ser `protocol.authority` (6227 si falta o es otra).
pub fn wagon_rent_dest<'a, 'info>(rent_authority: Option<&'a AccountInfo<'info>>, authority: &Pubkey) -> Result<&'a AccountInfo<'info>> {
    let ai = rent_authority.ok_or(error!(WagonError::EscrowRentAuthorityMissing))?;
    require_keys_eq!(*ai.key, *authority, WagonError::EscrowRentAuthorityMissing);
    Ok(ai)
}

/// ¿La hucha USDC del depósito lleva la marca de Wagon (`close_authority` = el PDA de su sesión)?
pub fn deposit_escrow_is_wagon(escrow: &AccountInfo, session: &Pubkey) -> Result<bool> {
    let data = escrow.try_borrow_data()?;
    let acc = spl_token::state::Account::unpack(&data).map_err(|_| error!(WagonError::InvalidJupiterRoute))?;
    Ok(acc.close_authority == COption::Some(*session))
}

/// Pone (`wagon`) o quita la marca de Wagon de la hucha USDC del depósito. Firma el PDA de la sesión, su dueño y su autoridad de
/// cierre en los dos casos.
pub fn set_deposit_escrow_mark<'info>(
    token_program: &AccountInfo<'info>,
    escrow: &AccountInfo<'info>,
    session: &AccountInfo<'info>,
    signer_seeds: &[&[&[u8]]],
    wagon: bool,
) -> Result<()> {
    token::set_authority(
        CpiContext::new_with_signer(
            token_program.clone(),
            SetAuthority { current_authority: session.clone(), account_or_mint: escrow.clone() },
            signer_seeds,
        ),
        AuthorityType::CloseAccount,
        if wagon { Some(session.key()) } else { None },
    )
}
