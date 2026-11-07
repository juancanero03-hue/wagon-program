//! `withdraw_escrow_sweep` — G3 (auditoría 2026-10-09, F2A-03): lleva al VAULT el USDC que un `withdraw_settle`
//! dejó en la hucha USDC de una sesión de retiro ya CERRADA porque la cuenta USDC del vault no podía recibirlo
//! entonces (congelada o inexistente): ese residuo es del vault (de todos sus titulares), no del inversor, y hasta
//! G3 solo lo movía el siguiente `withdraw_init` de la misma pareja. La sesión ya no existe; la hucha (ATA USDC
//! de la PDA de sesión) sigue abierta con ese saldo.
//!
//! PERMISSIONLESS y calcada de `deposit_escrow_reclaim`: solo si NO hay sesión abierta en esa PDA (si la hay, su
//! propio terminal se ocupa), solo con saldo (una hucha vacía no se cierra: la reutiliza el siguiente
//! `withdraw_init`) y solo si la ATA USDC del vault (pinneada en su `VaultState`, nunca elegida por el caller)
//! puede recibir. El vault puede estar en cualquier estado (es USDC que ya era suyo, no un depósito nuevo). Cierra la
//! hucha y su rent va a quien lo pagó (G4, F5A-01, `crate::escrow_rent`): si la pagó el inversor, al inversor (semilla de
//! la PDA); si la pagó un patrocinio (el bit de su `UserPosition`), a `protocol.authority`, la tesorería de Squads,
//! porque la sesión que la abrió se cerró con su registro (que la apuntó como `lamports_sunk`: no volvía con el
//! terminal). Antes de G4 ese rent iba siempre al inversor, también el de una hucha patrocinada.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, spl_token, CloseAccount, Token, Transfer};

use crate::constants::{PROTOCOL_SEED, USER_POSITION_SEED, WITHDRAW_SESSION_SEED};
use crate::errors::WagonError;
use crate::events::WithdrawUsdcEscrowSwept;
use crate::guards::VaultGuard;
use crate::state::vault_layout as vlayout;
use crate::state::{ProtocolConfig, UserPosition, ESCROW_RENT_WITHDRAW_USDC_WAGON};
use crate::token_io::{derive_live_ata, is_payable_usdc_ata, read_token_amount, verify_token_account};

#[derive(Accounts)]
pub struct WithdrawEscrowSweep<'info> {
    /// Cualquiera; paga solo la fee.
    pub caller: Signer<'info>,

    /// CHECK: semilla de la PDA de sesión; recibe el rent de la hucha al cerrarla si la pagó él (G4).
    #[account(mut)]
    pub investor: UncheckedAccount<'info>,

    /// CHECK: VaultState (dueño, semillas y bump por `VaultGuard`, en cualquier estado); da la ATA USDC pinneada.
    pub vault: UncheckedAccount<'info>,

    /// CHECK: la PDA [b"withdraw-session", vault, investor]; tiene que estar VACÍA (sin sesión abierta).
    pub withdraw_session: UncheckedAccount<'info>,

    /// CHECK: la hucha USDC canónica de esa PDA (verificada en el handler).
    #[account(mut)]
    pub session_usdc_escrow: UncheckedAccount<'info>,

    /// CHECK: la ATA USDC del vault pinneada en su VaultState; tiene que poder recibir.
    #[account(mut)]
    pub vault_usdc_ata: UncheckedAccount<'info>,

    #[account(seeds = [PROTOCOL_SEED], bump = protocol.bump)]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    pub token_program: Program<'info, Token>,

    /// G4 (F5A-01): la posición de la pareja; su bit `ESCROW_RENT_WITHDRAW_USDC_WAGON` dice quién pagó la hucha (se limpia al
    /// cerrarla).
    #[account(mut, seeds = [USER_POSITION_SEED, vault.key().as_ref(), investor.key().as_ref()], bump = user_position.bump)]
    pub user_position: Box<Account<'info, UserPosition>>,

    /// CHECK: G4 (F5A-01): `protocol.authority` (el vault de Squads), destino del rent de una hucha que pagó Wagon.
    /// Atada por `address` (6227 si es otra).
    #[account(mut, address = protocol.authority @ WagonError::EscrowRentAuthorityMissing)]
    pub rent_authority: UncheckedAccount<'info>,
}

pub fn handler(ctx: Context<WithdrawEscrowSweep>) -> Result<()> {
    let usdc_mint = ctx.accounts.protocol.usdc_mint;
    let investor = ctx.accounts.investor.key();
    let vault = ctx.accounts.vault.key();

    // El vault, en CUALQUIER estado: dueño, derivación y bump (identidad), y su ATA USDC pinneada.
    let vault_ai = ctx.accounts.vault.to_account_info();
    VaultGuard::load(&vault_ai, &vault, WagonError::WithdrawEscrowNotSweepable)?;
    let pinned_usdc_ata = {
        let data = vault_ai.try_borrow_data()?;
        vlayout::read_usdc_ata(&data)?
    };
    let vault_usdc_ai = ctx.accounts.vault_usdc_ata.to_account_info();
    require_keys_eq!(vault_usdc_ai.key(), pinned_usdc_ata, WagonError::WithdrawEscrowNotSweepable);

    let (session, bump) = Pubkey::find_program_address(
        &[WITHDRAW_SESSION_SEED, vault.as_ref(), investor.as_ref()],
        &crate::ID,
    );
    let session_ai = ctx.accounts.withdraw_session.to_account_info();
    require_keys_eq!(session_ai.key(), session, WagonError::WithdrawEscrowNotSweepable);
    // Sin sesión abierta: la PDA no tiene datos ni es del programa (lamports donados no cuentan).
    require!(
        session_ai.data_is_empty() && *session_ai.owner == System::id(),
        WagonError::WithdrawEscrowNotSweepable
    );

    let escrow_ai = ctx.accounts.session_usdc_escrow.to_account_info();
    require_keys_eq!(
        escrow_ai.key(),
        derive_live_ata(&session, &usdc_mint, &spl_token::ID),
        WagonError::EscrowAtaMismatch
    );
    verify_token_account(&escrow_ai, &usdc_mint, &session)?;
    let amount_usdc = read_token_amount(&escrow_ai)?;
    require!(amount_usdc > 0, WagonError::WithdrawEscrowNotSweepable);

    // La ATA del vault tiene que poder recibir (viva, de USDC, del vault y no congelada): si no, 6220 y el
    // residuo espera en la hucha (reintentable por cualquiera cuando se descongele).
    require!(
        is_payable_usdc_ata(&vault_usdc_ai, &usdc_mint, Some(vault)),
        WagonError::WithdrawEscrowNotSweepable
    );

    // G4 (F5A-01): el rent de la hucha vuelve a quien lo pagó.
    let rent_dest = if ctx.accounts.user_position.escrow_rent_flags & ESCROW_RENT_WITHDRAW_USDC_WAGON != 0 {
        ctx.accounts.rent_authority.to_account_info()
    } else {
        ctx.accounts.investor.to_account_info()
    };
    let bump_arr = [bump];
    let seeds: &[&[u8]] = &[WITHDRAW_SESSION_SEED, vault.as_ref(), investor.as_ref(), &bump_arr];
    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer { from: escrow_ai.clone(), to: vault_usdc_ai, authority: session_ai.clone() },
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
    // G4 (F5A-01): la hucha USDC de la pareja ya no existe: el bit de quién la pagó vuelve a cero (una hucha nueva la paga
    // quien la cree, y la que cree un tercero sin sesión es, como cualquier donación, del inversor).
    ctx.accounts.user_position.escrow_rent_flags &= !ESCROW_RENT_WITHDRAW_USDC_WAGON;

    emit!(WithdrawUsdcEscrowSwept { session, vault, investor, amount_usdc });
    Ok(())
}
