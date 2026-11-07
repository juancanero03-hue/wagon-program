//! `deposit_session_migrate` — DT-E: salida garantizada para las `DepositSession` ANTIGUAS.
//!
//! El layout de `DepositSession` es APPEND-ONLY: DT-E añadió 16 B al final (los dos cortes de la
//! comisión de entrada reservada; 457 → 473) y G2-c otros 128 (`landed_value_at_commit` y `landed_prices`; 473 → 601).
//! Una sesión creada por el programa anterior mide 457 B (el #55 vivo) y ninguna instrucción puede
//! leerla con el struct nuevo: sin esto, su dinero no tendría salida. La ceremonia exige 0 sesiones
//! de depósito abiertas antes del upgrade; esta instrucción cubre la que se escape o la que no se
//! pudo cerrar antes (por ejemplo, con una cuenta congelada).
//!
//! PERMISSIONLESS: cualquiera estira CUALQUIER tamaño anterior del layout (de `LEGACY_LEN` a `LEN`
//! exclusive) hasta `LEN` con los campos nuevos a 0 (correcto: los cortes a 0 porque esas sesiones ya
//! pagaron la comisión en su init, a la manera anterior; `landed_tracked` a 0 porque nadie valoró lo
//! que aterrizó, así que no se les aplica cota) y paga el rent de los bytes nuevos, que se va con la
//! sesión a su destino de reembolso cuando se cierre. No mueve dinero ni cambia ningún otro byte;
//! después la sesión se asienta o se cancela con normalidad. Un tamaño futuro del layout no exige
//! tocar esta instrucción: solo seguir añadiendo AL FINAL.

use anchor_lang::prelude::*;
use anchor_lang::system_program::{self, Transfer};
use anchor_lang::Discriminator;

use crate::constants::DEPOSIT_SESSION_SEED;
use crate::errors::WagonError;
use crate::events::DepositSessionMigrated;
use crate::state::DepositSession;

#[derive(Accounts)]
pub struct DepositSessionMigrate<'info> {
    /// Paga el rent de los bytes nuevos (hasta `LEN`) y la fee. Cualquiera.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: sesión de depósito de un tamaño ANTERIOR del layout (457 o 473 B) de este programa. Dueño, discriminador,
    /// tamaño y PDA canónica se verifican en el handler (Anchor no puede leerla tipada).
    #[account(mut)]
    pub deposit_session: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<DepositSessionMigrate>) -> Result<()> {
    let session_ai = ctx.accounts.deposit_session.to_account_info();
    require_keys_eq!(*session_ai.owner, crate::ID, WagonError::DepositSessionNotLegacy);
    // Cualquier tamaño ANTERIOR del layout append-only (457 del #55, 473 de DT-E); una sesión ya del
    // tamaño vivo (o mayor, imposible) no es antigua.
    let len = session_ai.data_len();
    require!(
        len >= DepositSession::LEGACY_LEN && len < DepositSession::LEN,
        WagonError::DepositSessionNotLegacy
    );

    // Los campos se leen con el MISMO struct: los bytes antiguos + ceros hasta `LEN` es exactamente la
    // sesión que queda tras estirarla (campos nuevos a 0). Ningún offset escrito a mano.
    let s = {
        let data = session_ai.try_borrow_data()?;
        require!(
            data[..8] == DepositSession::DISCRIMINATOR[..],
            WagonError::DepositSessionNotLegacy
        );
        let mut buf = data.to_vec();
        buf.resize(DepositSession::LEN, 0);
        DepositSession::try_deserialize(&mut &buf[..])?
    };
    let canonical = Pubkey::create_program_address(
        &[DEPOSIT_SESSION_SEED, s.vault.as_ref(), s.investor.as_ref(), &[s.bump]],
        &crate::ID,
    )
    .map_err(|_| error!(WagonError::DepositSessionNotLegacy))?;
    require_keys_eq!(session_ai.key(), canonical, WagonError::DepositSessionNotLegacy);

    // Rent de los bytes nuevos: lo pone quien migra; después, `realloc` rellena con ceros.
    let needed = Rent::get()?.minimum_balance(DepositSession::LEN);
    let lamports_added = needed.saturating_sub(session_ai.lamports());
    if lamports_added > 0 {
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.payer.to_account_info(),
                    to: session_ai.clone(),
                },
            ),
            lamports_added,
        )?;
    }
    session_ai.realloc(DepositSession::LEN, true)?;

    emit!(DepositSessionMigrated {
        session: session_ai.key(),
        vault: s.vault,
        investor: s.investor,
        payer: ctx.accounts.payer.key(),
        lamports_added,
    });
    Ok(())
}
