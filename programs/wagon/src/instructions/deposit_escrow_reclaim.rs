//! `deposit_escrow_reclaim` — DT-E: devuelve al inversor el USDC que un `deposit_settle` (o, desde G2-b,
//! un `deposit_abort` APLAZADO) dejó en la hucha de su sesión porque no podía moverlo (la hucha
//! congelada, o ni la ATA USDC del vault ni la del inversor podían recibir). La sesión ya está cerrada; la hucha (ATA USDC de la PDA de sesión)
//! sigue abierta con ese saldo.
//!
//! PERMISSIONLESS: solo si NO hay sesión abierta en esa PDA (si la hay, su abort o su settle se
//! ocupan, y cada `deposit_init` ya devuelve lo heredado antes de empezar) y solo con saldo: una
//! hucha vacía no se cierra, la reutiliza el siguiente `deposit_init` de la pareja (una vez
//! descongelada). El destino es la ATA
//! USDC CANÓNICA del inversor; si llama el propio inversor, cualquier cuenta USDC suya (como en
//! `deposit_abort`).
//! Sirve también con el vault cerrado (solo usa su clave como semilla). Cierra la hucha: su rent va
//! al inversor, o a `protocol.authority` (la tesorería de Squads) si la hucha lleva la marca de Wagon (G4,
//! F5A-01: la pagó un patrocinio y su sesión se cerró con su registro; `crate::escrow_rent`).

use anchor_lang::prelude::*;
use anchor_spl::token::{self, spl_token, CloseAccount, Token, Transfer};

use crate::constants::{DEPOSIT_SESSION_SEED, PROTOCOL_SEED};
use crate::errors::WagonError;
use crate::escrow_rent;
use crate::events::DepositEscrowReclaimed;
use crate::state::ProtocolConfig;
use crate::token_io::{derive_live_ata, is_payable_usdc_ata, read_token_amount, verify_token_account};

#[derive(Accounts)]
pub struct DepositEscrowReclaim<'info> {
    /// Cualquiera; paga solo la fee.
    pub caller: Signer<'info>,

    /// CHECK: semilla de la PDA de sesión; recibe el rent de la hucha al cerrarla si la pagó él (G4).
    #[account(mut)]
    pub investor: UncheckedAccount<'info>,

    /// CHECK: semilla de la PDA de sesión (puede estar cerrado: solo se usa su clave).
    pub vault: UncheckedAccount<'info>,

    /// CHECK: la PDA [b"deposit-session", vault, investor]; tiene que estar VACÍA (sin sesión abierta).
    pub deposit_session: UncheckedAccount<'info>,

    /// CHECK: la hucha USDC canónica de esa PDA (verificada en el handler).
    #[account(mut)]
    pub session_usdc_escrow: UncheckedAccount<'info>,

    /// CHECK: la ATA USDC CANÓNICA del inversor (si llama él, cualquier cuenta USDC suya); tiene que poder recibir.
    #[account(mut)]
    pub investor_usdc_ata: UncheckedAccount<'info>,

    #[account(seeds = [PROTOCOL_SEED], bump = protocol.bump)]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    pub token_program: Program<'info, Token>,

    /// CHECK: G4 (F5A-01): `protocol.authority` (el vault de Squads), destino del rent de una hucha
    /// con la marca de Wagon. Atada por `address` (6227 si es otra).
    #[account(mut, address = protocol.authority @ WagonError::EscrowRentAuthorityMissing)]
    pub rent_authority: UncheckedAccount<'info>,
}

pub fn handler(ctx: Context<DepositEscrowReclaim>) -> Result<()> {
    let usdc_mint = ctx.accounts.protocol.usdc_mint;
    let investor = ctx.accounts.investor.key();
    let vault = ctx.accounts.vault.key();
    let (session, bump) = Pubkey::find_program_address(
        &[DEPOSIT_SESSION_SEED, vault.as_ref(), investor.as_ref()],
        &crate::ID,
    );
    let session_ai = ctx.accounts.deposit_session.to_account_info();
    require_keys_eq!(session_ai.key(), session, WagonError::DepositEscrowNotReclaimable);
    // Sin sesión abierta: la PDA no tiene datos ni es del programa (lamports donados no cuentan).
    require!(
        session_ai.data_is_empty() && *session_ai.owner == System::id(),
        WagonError::DepositEscrowNotReclaimable
    );

    let escrow_ai = ctx.accounts.session_usdc_escrow.to_account_info();
    require_keys_eq!(
        escrow_ai.key(),
        derive_live_ata(&session, &usdc_mint, &spl_token::ID),
        WagonError::EscrowAtaMismatch
    );
    verify_token_account(&escrow_ai, &usdc_mint, &session)?;
    let amount_usdc = read_token_amount(&escrow_ai)?;
    require!(amount_usdc > 0, WagonError::DepositEscrowNotReclaimable);

    let investor_ata = ctx.accounts.investor_usdc_ata.to_account_info();
    if ctx.accounts.caller.key() == investor {
        verify_token_account(&investor_ata, &usdc_mint, &investor)?;
    } else {
        require_keys_eq!(
            investor_ata.key(),
            derive_live_ata(&investor, &usdc_mint, &spl_token::ID),
            WagonError::InvestorUsdcAtaNotCanonical
        );
    }
    require!(
        is_payable_usdc_ata(&investor_ata, &usdc_mint, Some(investor)),
        WagonError::DepositEscrowNotReclaimable
    );

    // G4 (F5A-01): el rent de la hucha vuelve a quien lo pagó (la marca se lee antes de cerrarla).
    let rent_dest = if escrow_rent::deposit_escrow_is_wagon(&escrow_ai, &session)? {
        ctx.accounts.rent_authority.to_account_info()
    } else {
        ctx.accounts.investor.to_account_info()
    };
    let bump_arr = [bump];
    let seeds: &[&[u8]] = &[DEPOSIT_SESSION_SEED, vault.as_ref(), investor.as_ref(), &bump_arr];
    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer { from: escrow_ai.clone(), to: investor_ata, authority: session_ai.clone() },
            &[seeds],
        ),
        amount_usdc,
    )?;
    token::close_account(CpiContext::new_with_signer(
        ctx.accounts.token_program.to_account_info(),
        CloseAccount {
            account: escrow_ai,
            destination: rent_dest,
            authority: session_ai,
        },
        &[seeds],
    ))?;

    emit!(DepositEscrowReclaimed { session, vault, investor, amount_usdc });
    Ok(())
}
