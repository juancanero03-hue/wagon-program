//! `withdraw_init` — step 1 of the fractional withdraw flow.
//!
//! C2 (ceremonia #38): the investor commits a share amount, we immediately
//! burn those shares, and — the key change — we MOVE each allocation's
//! pro-rata slice out of the vault into a session-owned token escrow ATA (the
//! exact mirror of `deposit_init`, inverted). The vault's token balance
//! auto-reduces, so a CONCURRENT withdraw prices its own slice against the
//! already-reduced pool. Moving the slice is what closes C2 (before, the
//! tokens stayed in the vault and `withdraw_swap_batch`'s cap could
//! over-allocate between co-investors). The denominator is
//! `total_shares_before` (live, pre-burn) plus two pending counters added by
//! later ceremonies and applied in the handler to every token leg and to the
//! idle USDC: `pending_committed_shares` (#44) and `pending_burned_shares` (#49).
//!
//! Why the burn happens at init, not at settle:
//!   - The burn is the user's "commitment". After init they can't change
//!     their mind by transferring the shares away.
//!   - If they cancel (`withdraw_abort`), we re-mint the same number of shares
//!     back. The vault PDA is the share mint authority, so this is symmetric.
//!   - It keeps `total_shares` accurate during the flow so another investor's
//!     deposit/withdraw prices against a `total_shares` that already reflects
//!     our exit.
//!
//! # remaining_accounts layout
//!
//! For each NON-trivial leg (non-USDC, weight > 0), in leg-index order:
//!   `[allocation_mint, vault_ata, escrow_ata]`
//! - `allocation_mint` MUST equal `vault.allocations[i].mint` (live AccountInfo,
//!   re-validated Tier B — a mint that flipped a dangerous extension is PARKED,
//!   see below, not moved).
//! - `vault_ata` MUST equal the vault's canonical ATA for the mint (live token
//!   program).
//! - `escrow_ata` MUST equal the session's canonical ATA for the mint. G4 (F5B-01, 17-oct-2026): if
//!   it does not exist yet, the PROGRAM creates it (paid by `payer`) after emitting this ix's events,
//!   and only for a leg that receives a slice; a parked or dust leg without an escrow is born swept.
//!   The slice moves here.
//! USDC-as-allocation and zero-weight legs are TRIVIAL (no escrow, pre-marked).
//!
//! G3-B2 (F6B-01 y §9.6 sin pérdida, decisiones de Juan del 16 y 17-oct-2026): tras los segmentos, UNA cuenta de destino EN
//! ESPECIE por cada hucha que ya esté CONGELADA al empezar el retiro: primero las de las patas (en orden de pata) y, si la hucha
//! USDC de la sesión está congelada, la de USDC la última. El slice de esa pata (o el USDC ocioso) va directamente del vault a esa
//! cuenta, que tiene que ser del inversor para ese mint (cualquiera suya: él firma) y no estar congelada; la sesión nace cobrada
//! (`sold`), como tras un cobro en especie, y no suma a `revivable`. Sin huchas congeladas, ninguna cuenta de más (la forma de
//! siempre). Una posición cuya hucha congelada no paga nada (polvo, pata aparcada o USDC ocioso a 0) no se valida ni se toca:
//! vale cualquier cuenta. Si la cuenta del inversor está congelada y el mint hace nacer congeladas las cuentas nuevas
//! (`DefaultAccountState`, posible en vivo en un mint de emisor de confianza), la pata se aparca como cuando el mint bloquea.
//!
//! Ceremonia USDC §3.3 (B2): con patrocinio (`payer != investor`) el init crea el
//! `FundingRecord` de la sesión y sella su rent: `lamports_refundable` cubre sesión + huchas de
//! pata + registro, y `lamports_sunk` la hucha USDC (cierre condicional en el settle).
//!
//! G4 (F5B-01 y F5A-01, 17-oct-2026, `crate::escrow_rent`): las huchas que falten las crea este init
//! (paga `payer`), así que el retiro de siete patas cabe en una transacción y ninguna hucha patrocinada
//! nace fuera del init que la ata a su registro. Crear una hucha deja unos 1.3 KB de registro y el techo
//! es 10 KB por transacción: las huchas nuevas y las porciones que van a ellas se mueven AL FINAL,
//! después de escribir el estado y emitir todos los eventos, y su rent se sella antes de crearlas con el
//! mismo cálculo que hace el programa de ATAs. Una hucha que ya existía la pagó otro: si es de la otra
//! clase (el inversor o Wagon), el pagador de este init se la compra por el rent mínimo; la clase de la
//! hucha USDC la guarda `UserPosition::escrow_rent_flags`, que se escribe aunque la hucha esté congelada.
//!
//! PR 5B (§3.5, D3 / M-04): el inversor FIRMA `exit_service_usdc` (S de salida por exceso,
//! que solo cobra el gateway cuando la salida patrocinada supera cadencia o mínimo); el init lo
//! ACOTA al tope vivo de `ServiceConfig` (0 en pausa) y lo GUARDA en el `FundingRecord`. Aquí
//! no se cobra nada: lo cobra `withdraw_settle` del USDC que sale, sin revertir jamás.

use anchor_lang::prelude::*;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token::{self, spl_token, Burn, Token, Transfer};

use crate::constants::*;
use crate::errors::WagonError;
use crate::escrow_rent;
use crate::events::{FundingRecorded, WithdrawInitiated, WithdrawLegClaimedInKind};
use crate::instructions::create_vault::verify_mint_tier_b;
use crate::service;
use crate::state::vault_layout as vlayout;
use crate::state::{
    FundingRecord, ProtocolConfig, UserPosition, WithdrawSession, ESCROW_RENT_WITHDRAW_USDC_WAGON, FUNDING_KIND_WITHDRAW,
    WITHDRAW_USDC_LEG_INDEX,
};
use crate::token_io::{
    derive_live_ata, mint_blocks_transfer, mint_default_frozen, read_mint_decimals, read_token_amount, read_token_state,
    transfer_checked_signed, verify_token_account, TOKEN_2022_PROGRAM_ID, TOKEN_STATE_FROZEN,
};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct WithdrawInitArgs {
    pub shares_to_burn: u64,
    /// PR 5B (§3.5, D3): S de salida en átomos de USDC, firmado por el inversor; 0 siempre
    /// admitido. Con patrocinio se acota al tope vivo y se guarda en el registro; sin
    /// patrocinio debe ser 0 (`ExitServiceWithoutSponsor`).
    pub exit_service_usdc: u64,
}

#[derive(Accounts)]
pub struct WithdrawInit<'info> {
    #[account(mut)]
    pub investor: Signer<'info>,

    /// Ceremonia USDC (§3.2): PAGADOR del rent que crea esta instrucción, separado
    /// del propietario. Sin patrocinio, el cliente pasa la MISMA wallet que el
    /// propietario en los dos papeles (una sola firma y la misma lista de claves;
    /// la instrucción solo lleva un índice de cuenta más, +1 B); con patrocinio,
    /// el sponsor. NUNCA paga comisiones: esas siguen saliendo del propietario.
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// CHECK: PDA seeds + status verified manually.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    /// CHECK: pubkey verified against `vault_layout::read_share_mint`.
    #[account(mut)]
    pub share_mint: UncheckedAccount<'info>,

    /// CHECK: SPL Token account, mint == share_mint, owner == investor.
    /// Source of the burn at init.
    #[account(mut)]
    pub investor_share_ata: UncheckedAccount<'info>,

    /// CHECK: pubkey verified against `vault_layout::read_usdc_ata`.
    /// H-3: mutable — la parte proporcional del inversor sale de aquí hacia
    /// la hucha USDC de la sesión en este mismo init.
    #[account(mut)]
    pub vault_usdc_ata: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [
            USER_POSITION_SEED,
            vault.key().as_ref(),
            investor.key().as_ref(),
        ],
        bump = user_position.bump,
    )]
    pub user_position: Box<Account<'info, UserPosition>>,

    #[account(
        init,
        payer = payer,
        space = WithdrawSession::LEN,
        seeds = [
            WITHDRAW_SESSION_SEED,
            vault.key().as_ref(),
            investor.key().as_ref(),
        ],
        bump,
    )]
    pub withdraw_session: Box<Account<'info, WithdrawSession>>,

    /// CHECK: H-3 (auditoría 2026-06-29) — la "hucha" USDC de la sesión:
    /// ATA canónica del PDA de sesión (derivación clásica; USDC es SPL Token
    /// clásico), verificada por derivación + verify_token_account. G4: si falta, la
    /// crea el programa (paga `payer`) tras emitir los eventos.
    #[account(mut)]
    pub session_usdc_escrow: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,

    /// CHECK: pubkey verified == Token-2022 program id. Used for token slices
    /// whose mint lives on Token-2022 (xStocks, MetaDAO); ignored otherwise.
    pub token_program_2022: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,

    /// Ceremonia USDC (§3.3, B2): registro de financiación de ESTA sesión en su PDA canónica
    /// `[b"funding", session]`. Se crea (pagado por `payer`) si y solo si el pagador NO es
    /// el propietario (patrocinio); sin patrocinio el cliente pasa el centinela `None`
    /// (program id) y no se crea nada: el rent vuelve al inversor como siempre. Va DESPUÉS
    /// de `system_program` (y antes de `remaining`) para no mover ningún índice que el
    /// cliente ya enhebra. Dirección ocupada por un registro rancio → el `init` falla en
    /// el System Program (B3 añade el backstop `funding_reclaim_stale`).
    #[account(
        init,
        payer = payer,
        space = FundingRecord::LEN,
        seeds = [FUNDING_SEED, withdraw_session.key().as_ref()],
        bump,
    )]
    pub funding_record: Option<Box<Account<'info, FundingRecord>>>,

    /// CHECK: destino del reembolso del rent patrocinado, elegido por el pagador y
    /// acotado en el handler a {payer, protocol.authority} y no ejecutable
    /// (`FundingRefundToNotAllowed`). Sin patrocinio se pasa el propio inversor.
    pub refund_to: UncheckedAccount<'info>,

    /// CHECK: PR 5B (§3.5, D3): la PDA canónica de `ServiceConfig` (atada por `seeds`, 2006 si
    /// otra), leída de forma TOLERANTE en el handler como en `withdraw_settle`: si el singleton
    /// no existe (ventana entre las dos propuestas de la ceremonia) el S de salida se guarda a
    /// 0 y el retiro EMPIEZA igual. La ENTRADA a la salida no depende de una cuenta nueva (a
    /// diferencia de los 4 inits de entrada, que la exigen tipada). ÚLTIMA nombrada, tras
    /// `refund_to` (@15) y antes de los `remaining` por pata.
    #[account(seeds = [SERVICE_CONFIG_SEED], bump)]
    pub service_config: UncheckedAccount<'info>,

    /// G4 (F5B-01): el programa de ATAs, para crear las huchas que falten. Tras `service_config` y
    /// antes de los `remaining` por pata.
    pub associated_token_program: Program<'info, AssociatedToken>,

    /// CHECK: G4: el mint USDC (`protocol.usdc_mint`, verificado en el handler), para crear la hucha USDC.
    pub usdc_mint: UncheckedAccount<'info>,

    /// CHECK: G4 (F5A-01): `protocol.authority` (el vault de Squads), OPCIONAL (centinela = program
    /// id): solo hace falta cuando un init SIN patrocinio encuentra la hucha USDC de la pareja pagada
    /// por Wagon y le compra su rent (6227 si falta o es otra). Opcional para no bloquear en escritura
    /// esa cuenta en cada retiro.
    #[account(mut)]
    pub rent_authority: Option<UncheckedAccount<'info>>,
}

pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, WithdrawInit<'info>>,
    args: WithdrawInitArgs,
) -> Result<()> {
    let shares_to_burn = args.shares_to_burn;
    require!(shares_to_burn > 0, WagonError::ZeroWithdraw);
    require!(
        ctx.accounts.user_position.shares >= shares_to_burn,
        WagonError::InsufficientShares
    );

    // ---- Read & validate vault --------------------------------------------
    let vault_ai = ctx.accounts.vault.to_account_info();
    let guard = crate::guards::VaultGuard::load(
        &vault_ai,
        &ctx.accounts.vault.key(),
        WagonError::VaultClosed,
    )?;
    let (creator, nonce, vault_bump, status) =
        (guard.creator, guard.nonce, guard.bump, guard.status);
    let nonce_le = nonce.to_le_bytes();
    let (
        allocation_count,
        total_shares_before,
        tvl_before,
        share_mint_pk,
        usdc_ata_pk,
        pending_committed_shares,
        pending_burned_shares,
    ) = {
        let data = vault_ai.try_borrow_data()?;
        (
            vlayout::read_allocation_count(&data)?,
            vlayout::read_total_shares(&data)?,
            vlayout::read_tvl_last_computed_usdc(&data)?,
            vlayout::read_share_mint(&data)?,
            vlayout::read_usdc_ata(&data)?,
            // Ceremonia #44 (F3): participaciones que los depósitos COMPROMETIDOS
            // en vuelo van a recibir. Se suman al denominador de las patas de token
            // (abajo) para que este retiro no reparta el depósito en vuelo. Vault
            // legacy / sin comprometidas ⇒ 0 ⇒ fórmula idéntica al código vivo.
            vlayout::read_pending_committed_shares(&data)?,
            // Ceremonia #49 (A1): participaciones QUEMADAS por retiros que están
            // abortando (tokens ya devueltos al vault, shares aún sin re-acuñar).
            // Se suman al MISMO denominador de las patas de token para que este
            // retiro no sobre-extraiga durante la ventana de un abort concurrente.
            // Vault legacy / sin abortos en vuelo ⇒ 0 ⇒ NO-OP.
            vlayout::read_pending_burned_shares(&data)?,
        )
    };
    require!(status != 3u8 /* Closed */, WagonError::VaultClosed);
    require!(
        status != 4u8, /* Restructuring */
        WagonError::RestructuringInProgress
    );
    require!(total_shares_before > 0, WagonError::InsufficientShares);
    require!(
        allocation_count as usize <= crate::constants::MAX_TOKENS_PER_VAULT,
        WagonError::TooManyAllocations
    );

    let usdc_mint_pk = ctx.accounts.protocol.usdc_mint;
    require_keys_eq!(
        ctx.accounts.share_mint.key(),
        share_mint_pk,
        WagonError::InvalidJupiterRoute
    );
    require_keys_eq!(
        *ctx.accounts.share_mint.owner,
        spl_token::ID,
        WagonError::InvalidJupiterRoute
    );
    require_keys_eq!(
        ctx.accounts.vault_usdc_ata.key(),
        usdc_ata_pk,
        WagonError::InvalidJupiterRoute
    );
    require_keys_eq!(
        ctx.accounts.token_program_2022.key(),
        TOKEN_2022_PROGRAM_ID,
        WagonError::InvalidJupiterRoute
    );

    let investor_pk = ctx.accounts.investor.key();
    let vault_key = ctx.accounts.vault.key();
    verify_token_account(
        &ctx.accounts.investor_share_ata.to_account_info(),
        &share_mint_pk,
        &investor_pk,
    )?;

    // ---- H-3: validar la hucha USDC de la sesión ---------------------------
    let session_key = ctx.accounts.withdraw_session.key();
    require_keys_eq!(
        ctx.accounts.session_usdc_escrow.key(),
        derive_live_ata(&session_key, &usdc_mint_pk, &spl_token::ID),
        WagonError::EscrowAtaMismatch
    );
    require_keys_eq!(ctx.accounts.usdc_mint.key(), usdc_mint_pk, WagonError::InvalidJupiterRoute);
    // G4 (F5A-01): si la hucha USDC ya existía (heredada de una sesión anterior de la pareja, o creada por cualquiera), el bit de
    // `UserPosition` dice quién pagó su rent; si este init es de la otra clase, su pagador se la compra al anterior por el rent
    // mínimo. El bit queda con la clase de este init, que paga la hucha si la crea (tras los eventos, abajo).
    let payer_pk = ctx.accounts.payer.key();
    let sponsored = payer_pk != investor_pk;
    let usdc_escrow_ai = ctx.accounts.session_usdc_escrow.to_account_info();
    let usdc_escrow_existed = escrow_rent::account_exists(&usdc_escrow_ai);
    if usdc_escrow_existed {
        verify_token_account(&usdc_escrow_ai, &usdc_mint_pk, &session_key)?;
        let wagon_before = ctx.accounts.user_position.escrow_rent_flags & ESCROW_RENT_WITHDRAW_USDC_WAGON != 0;
        if wagon_before != sponsored {
            let to = if wagon_before {
                escrow_rent::wagon_rent_dest(
                    ctx.accounts.rent_authority.as_ref().map(|a| a.as_ref()),
                    &ctx.accounts.protocol.authority,
                )?
                .clone()
            } else {
                ctx.accounts.investor.to_account_info()
            };
            escrow_rent::buy_escrow_rent(
                &ctx.accounts.system_program.to_account_info(),
                &ctx.accounts.payer.to_account_info(),
                &to,
                &usdc_escrow_ai,
                session_key,
            )?;
        }
    }
    if sponsored {
        ctx.accounts.user_position.escrow_rent_flags |= ESCROW_RENT_WITHDRAW_USDC_WAGON;
    } else {
        ctx.accounts.user_position.escrow_rent_flags &= !ESCROW_RENT_WITHDRAW_USDC_WAGON;
    }
    // Lamports con que la hucha USDC llega al registro: los que tiene, o los que tendrá al crearla.
    let usdc_escrow_lamports = if usdc_escrow_existed {
        usdc_escrow_ai.lamports()
    } else {
        escrow_rent::lamports_after_create(
            &usdc_escrow_ai,
            escrow_rent::escrow_len(&ctx.accounts.usdc_mint.to_account_info(), &ctx.accounts.token_program.to_account_info())?,
        )?
    };

    // Vault PDA signer seeds — the vault owns the token/USDC ATAs the slices
    // move OUT of, so the vault signs the transfers.
    let bump_arr = [vault_bump];
    let vseeds: &[&[u8]] = &[VAULT_SEED, creator.as_ref(), &nonce_le, &bump_arr];
    let vsigner: &[&[&[u8]]] = &[vseeds];

    // ---- H-3: reservar la parte del inversor del idle USDC → hucha USDC ----
    let vault_usdc_before = read_token_amount(&ctx.accounts.vault_usdc_ata.to_account_info())?;
    // DT-A(a) (#54): si la ATA USDC del vault está CONGELADA, aparcar el slice del
    // idle (forfeit: el inversor renuncia a esa porción, se queda en el vault) en vez
    // de revertir el init entero — espejo del park Tier-B. read_token_state es lectura
    // PURA, inmune al propio freeze (leer una cuenta congelada nunca revierte).
    let vault_usdc_frozen =
        read_token_state(&ctx.accounts.vault_usdc_ata.to_account_info())? == TOKEN_STATE_FROZEN;
    // La hucha USDC de la sesión puede estar YA congelada (heredada de un abort aplazado con la hucha congelada, G3-B1a, o
    // congelada de antemano: su dirección es predecible). Transferirle el slice revertiría el init entero (0x11). G3-B2
    // (decisión de Juan del 17-oct): el slice ocioso se PAGA EN ESPECIE, del vault a una cuenta USDC del inversor (la última
    // de las cuentas de destino), sin pérdida. El residuo heredado de la hucha vuelve al vault cuando se descongela (settle) o,
    // si sigue congelada, por `withdraw_force_release` (c) y el barrido de la hucha (`usdc_right` no lo incluye).
    let session_usdc_frozen = usdc_escrow_existed && read_token_state(&usdc_escrow_ai)? == TOKEN_STATE_FROZEN;
    // Ceremonia 2026-08 (WA-01/WI-01/P2-1/P2-2): el slice de USDC ocioso usa el
    // MISMO denominador aumentado que las patas de token (:336-351):
    // `total_shares_before + pending_committed_shares + pending_burned_shares`.
    // La valoración m2m que genera esas participaciones fantasma INCLUYE el USDC
    // ocioso (pricing.rs `idle_usdc`), pero hasta ahora el ocioso se repartía con
    // el denominador CRUDO → un retiro concurrente sobre-extraía cuando el ocioso
    // superaba el peso de la pata USDC (depósito comprometido) o cuando un
    // inyector volcaba valor de token a la USDC ociosa durante un retiro-abortado
    // (`pending_burned>0`). Bajo el mismo denominador, el retiro toma s/(S+Pc+Pb)
    // del AGREGADO (ocioso + tokens) sea cual sea el reparto de un inyector → nunca
    // sobre-extrae. Los contadores son cotas superiores: en el denominador solo
    // ENCOGEN el slice, jamás lo agrandan → nunca estrangula la salida. NO-OP con
    // pending==0 (todo retiro normal). u128 inline, NUNCA `mul_div_floor` (que hace
    // `u64::try_from` del DIVISOR y revertiría con S+Pc+Pb > u64::MAX — camino
    // sagrado, cero reverts): aquí solo el resultado (≤ vault_usdc_before ≤ u64::MAX)
    // va a u64.
    // G1 (2026-10-09, F7A-01): si se aparca algo CON saldo, el forfeit es DEFINITIVO (`had_park`):
    // la sesión ya no podrá abortar y sus shares no cuentan como revivibles.
    let mut had_park: u8 = 0;
    let usdc_pro_rata = if vault_usdc_frozen {
        if vault_usdc_before > 0 {
            had_park = 1;
        }
        0u64 // DT-A(a): park del idle — forfeit, se queda en la ATA USDC congelada del vault
    } else {
        let denom = (total_shares_before as u128)
            .checked_add(pending_committed_shares as u128)
            .ok_or(WagonError::MathOverflow)?
            .checked_add(pending_burned_shares as u128)
            .ok_or(WagonError::MathOverflow)?; // denom >= total_shares_before > 0
        let num = (vault_usdc_before as u128)
            .checked_mul(shares_to_burn as u128)
            .ok_or(WagonError::MathOverflow)?;
        u64::try_from(num / denom).map_err(|_| error!(WagonError::MathOverflow))?
    };
    // G3-B2: con la hucha USDC de la sesión congelada, el slice no va a la hucha: se paga en especie tras el bucle de patas.
    let (usdc_slice_from_vault, usdc_in_kind) =
        if session_usdc_frozen { (0u64, usdc_pro_rata) } else { (usdc_pro_rata, 0u64) };
    // G4: con la hucha USDC por crear, el slice va a ella al final (tras crearla).
    if usdc_slice_from_vault > 0 && usdc_escrow_existed {
        move_idle_usdc(&ctx, vsigner, usdc_slice_from_vault)?;
    }

    // ---- C2: move each token slice OUT of the vault into its escrow --------
    // Walk the vault's allocation legs; for each NON-trivial leg (non-USDC,
    // weight > 0) consume a [mint, vault_ata, escrow_ata] segment from
    // remaining_accounts (in leg-index order) and move the pro-rata slice.
    //   - Tier-B re-check fails (issuer flipped a dangerous extension) → PARK:
    //     leave the token in the vault, pre-mark the leg completed (the
    //     investor forfeits that token's slice to the remaining holders — an
    //     exit that never blocks beats a stuck one). Its (empty) escrow is
    //     still closed by the sweep.
    //   - slice rounds to 0 (dust) → pre-mark completed, don't move (cierra H2).
    //     Its (empty) escrow is still closed by the sweep.
    //   - slice > 0 → transfer_checked (vault signs). Tier B guarantees the
    //     mint has no transfer-fee extension, so exactly `slice` lands; the
    //     escrow balance is authoritative for the swap regardless.
    let mut legs_completed: u16 = 0;
    let mut trivial_mask: u16 = 0;
    let mut leg_mints = [Pubkey::default(); crate::constants::MAX_TOKENS_PER_VAULT];
    let remaining = ctx.remaining_accounts;
    let mut cursor: usize = 0;
    // §3.3 (B2): rent de las huchas de pata de esta tx (el barrido las cierra TODAS hacia
    // el PDA de sesión, también las aparcadas o con polvo, D1).
    let mut leg_escrow_lamports: u64 = 0;
    // G3 (F6B-01): patas que nacen BARRIDAS (su hucha ya estaba congelada: no se mueve ni se cierra).
    let mut legs_swept_at_init: u16 = 0;
    // G3-B2: huchas de pata congeladas (cada una pide una cuenta de destino al final de `remaining`) y las patas que se pagan
    // EN ESPECIE desde el vault tras el bucle: (pata, índice del mint y de la ATA del vault en `remaining`, posición de su
    // destino, slice).
    let mut frozen_escrows: usize = 0;
    let mut in_kind_mask: u16 = 0;
    let mut in_kind_count: usize = 0;
    // El último campo: el mint hace nacer CONGELADAS las cuentas nuevas (con el destino congelado, se aparca en vez de 6226).
    let mut in_kind_legs = [(0u8, 0usize, 0usize, 0usize, 0u64, false); crate::constants::MAX_TOKENS_PER_VAULT];
    // G4: patas cuya hucha crea este init al FINAL, tras los eventos: (índice del mint en `remaining`, porción, decimales); la
    // ATA del vault y la hucha son las dos cuentas siguientes del segmento.
    let mut deferred_legs = [(0usize, 0u64, 0u8); crate::constants::MAX_TOKENS_PER_VAULT];
    let mut deferred_count: usize = 0;

    for i in 0..(allocation_count as usize) {
        let (alloc_mint, weight_bps) = {
            let data = vault_ai.try_borrow_data()?;
            (
                vlayout::read_allocation_mint(&data, i)?,
                vlayout::read_allocation_weight_bps(&data, i)?,
            )
        };
        leg_mints[i] = alloc_mint;
        let bit = 1u16 << i;

        // Trivial legs (USDC-as-allocation / zero-weight): no token escrow.
        if alloc_mint == usdc_mint_pk || weight_bps == 0 {
            trivial_mask |= bit;
            legs_completed |= bit;
            continue;
        }

        // Non-trivial leg: consume the [mint, vault_ata, escrow_ata] segment.
        require!(
            cursor + 3 <= remaining.len(),
            WagonError::InvalidJupiterRoute
        );
        let mint_ai = &remaining[cursor];
        let vault_ata_ai = &remaining[cursor + 1];
        let escrow_ai = &remaining[cursor + 2];
        cursor += 3;

        // Hard error on a mint mismatch (real bug, not a park case).
        require_keys_eq!(mint_ai.key(), alloc_mint, WagonError::AllocMintMismatch);

        // Live token program of this mint (classic vs Token-2022).
        let token_prog_id = *mint_ai.owner;
        let expected_vault_ata = derive_live_ata(&vault_key, &alloc_mint, &token_prog_id);
        require_keys_eq!(
            vault_ata_ai.key(),
            expected_vault_ata,
            WagonError::LegDestAtaMismatch
        );
        let expected_escrow = derive_live_ata(&session_key, &alloc_mint, &token_prog_id);
        require_keys_eq!(escrow_ai.key(), expected_escrow, WagonError::EscrowAtaMismatch);
        // G4: ¿existe ya la hucha de esta pata? Si no, la crea este init al final, y solo si la pata recibe una porción. Si el mint
        // hace nacer CONGELADAS las cuentas nuevas no se crea (nacería congelada y su rent quedaría varado): cuenta como hucha
        // congelada, por estructura, igual que una que ya existe congelada.
        let escrow_existed = escrow_rent::account_exists(escrow_ai);
        if escrow_existed {
            verify_token_account(escrow_ai, &alloc_mint, &session_key)?;
        }
        // G3 (F6B-01) y G3-B2 (decisión de Juan del 16 y 17-oct): la hucha de esta pata YA está CONGELADA (freeze
        // authority del emisor sobre la ATA de la sesión, cuya dirección es predecible): no se le puede mover el slice ni
        // cerrarla. La pata nace BARRIDA (ningún barrido la tocará y su rent no entra en `leg_escrow_lamports` porque no se
        // cierra) y, en vez de aparcarla con pérdida, su slice se paga EN ESPECIE tras el bucle, del vault a la cuenta de
        // destino del inversor que le toca. Si además la pata no se puede mover desde el vault (abajo), rige el
        // aparcamiento de siempre.
        let escrow_frozen = if escrow_existed {
            read_token_state(escrow_ai)? == TOKEN_STATE_FROZEN
        } else {
            mint_default_frozen(&mint_ai.try_borrow_data()?)
        };
        let in_kind_slot = if escrow_frozen {
            let k = frozen_escrows;
            frozen_escrows += 1;
            legs_swept_at_init |= bit;
            Some(k)
        } else {
            if escrow_existed {
                leg_escrow_lamports = leg_escrow_lamports.saturating_add(escrow_ai.lamports());
                // G4: una hucha de pata viva al llegar aquí la pagó el inversor o un tercero (un sponsor nunca deja una: este
                // init la crea y el barrido la cierra). Con patrocinio, el sponsor se la compra al inversor por el rent mínimo.
                if sponsored {
                    escrow_rent::buy_escrow_rent(
                        &ctx.accounts.system_program.to_account_info(),
                        &ctx.accounts.payer.to_account_info(),
                        &ctx.accounts.investor.to_account_info(),
                        escrow_ai,
                        session_key,
                    )?;
                }
            }
            None
        };

        // Tier-B pre-check. The pubkey already matches (required above), so a
        // failure here means the mint flipped a dangerous extension since vault
        // creation → PARK.
        let tier_ok = verify_mint_tier_b(mint_ai, &alloc_mint).is_ok();
        // DT-A(a) (#54): aparcar (forfeit, se queda en el vault) en vez de revertir el
        // init entero — la salida nunca se estrangula para TODO el vault — cuando una
        // pata no se puede mover. Tres causas, en CORTOCIRCUITO (barato→caro):
        //  - !tier_ok: el mint volcó una extensión peligrosa desde la creación (#53).
        //  - vault_ata CONGELADA (freeze authority del emisor: Circle, un memecoin…).
        //  - el propio MINT bloquea la transferencia sin congelar la cuenta: un mint
        //    Token-2022 de CONFIANZA (xStocks/Backed) PAUSADO, o con TransferHook
        //    armado tras la creación, pasa Tier-B (short-circuit trusted) y NO figura
        //    como Frozen → `mint_blocks_transfer` (mismo lector que A5/DT-D) lo caza.
        // cursor+=3 ya ocurrió antes del gate → el invariante cursor==remaining.len()
        // se conserva.
        if !tier_ok
            || read_token_state(vault_ata_ai)? == TOKEN_STATE_FROZEN
            || mint_blocks_transfer(&mint_ai.try_borrow_data()?)
        {
            // G1 (2026-10-09): pata aparcada CON saldo → forfeit definitivo. Lectura PURA y
            // tolerante (una cuenta ilegible cuenta como 0: la bandera jamás revierte el init).
            if read_token_amount(vault_ata_ai).unwrap_or(0) > 0 {
                had_park = 1;
            }
            legs_completed |= bit; // parked: forfeit this slice, leave it in the vault
            if !escrow_existed && in_kind_slot.is_none() {
                legs_swept_at_init |= bit; // G4: sin hucha, nada que barrer
            }
            continue;
        }

        let balance_i = read_token_amount(vault_ata_ai)?;
        // Ceremonia #44 (F3): denominador = total_shares_before + pending. Durante
        // la ventana entre barrer y acuñar, `balance_i` (saldo VIVO de la ATA del
        // vault) ya incluye los tokens del depósito comprometido; sumar sus
        // participaciones fantasma al denominador hace que este retiro valore
        // contra un pool que ya cuenta ese depósito, en vez de contra uno inflado
        // → no reparte el depósito en vuelo. `pending == 0` (todo retiro normal) ⇒
        // denominador == código vivo (NO-OP). Solo puede ENCOGER el slice, jamás
        // agrandarlo → nunca estrangula (la salida siempre sale). División en u128
        // INLINE, no `mul_div_floor` (que hace `u64::try_from` del DIVISOR y
        // revertiría el retiro con S+P > u64::MAX — camino sagrado, cero reverts):
        // aquí solo el resultado (≤ balance_i ≤ u64::MAX) va a u64.
        let slice_i = {
            let denom = (total_shares_before as u128)
                .checked_add(pending_committed_shares as u128)
                .ok_or(WagonError::MathOverflow)?
                // Ceremonia #49 (A1): + participaciones quemadas de abortos en vuelo.
                // El balance_i VIVO ya incluye los tokens devueltos al vault por un
                // sweep-abort concurrente; sumar sus shares quemadas al denominador
                // restaura el total verdadero (S − s1) + s1 = S. Solo ENCOGE el slice
                // → nunca estrangula. u128, sin u64::try_from del divisor.
                .checked_add(pending_burned_shares as u128)
                .ok_or(WagonError::MathOverflow)?; // denom >= total_shares_before > 0
            let num = (balance_i as u128)
                .checked_mul(shares_to_burn as u128)
                .ok_or(WagonError::MathOverflow)?;
            u64::try_from(num / denom).map_err(|_| error!(WagonError::MathOverflow))?
        };
        if slice_i == 0 {
            legs_completed |= bit; // dust: nothing to move nor sell
            if !escrow_existed && in_kind_slot.is_none() {
                legs_swept_at_init |= bit; // G4: sin hucha, nada que barrer
            }
            continue;
        }
        // G3-B2: hucha congelada → se paga en especie tras el bucle (cuando se sabe dónde empiezan los destinos).
        if let Some(k) = in_kind_slot {
            let default_frozen = mint_default_frozen(&mint_ai.try_borrow_data()?);
            in_kind_legs[in_kind_count] = (i as u8, cursor - 3, cursor - 2, k, slice_i, default_frozen);
            in_kind_count += 1;
            legs_completed |= bit;
            in_kind_mask |= bit;
            continue;
        }

        // Move the slice: vault_ata → escrow, vault signs.
        let prog_ai = if token_prog_id == spl_token::ID {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        };
        let decimals = read_mint_decimals(mint_ai)?;
        if !escrow_existed {
            // G4: hucha nueva: su rent se sella ya (lo que dejará el programa de ATAs al crearla) y se crea al final.
            let len = escrow_rent::escrow_len(mint_ai, &prog_ai)?;
            leg_escrow_lamports = leg_escrow_lamports.saturating_add(escrow_rent::lamports_after_create(escrow_ai, len)?);
            deferred_legs[deferred_count] = (cursor - 3, slice_i, decimals);
            deferred_count += 1;
            continue;
        }
        transfer_checked_signed(
            &prog_ai,
            vault_ata_ai,
            mint_ai,
            escrow_ai,
            &ctx.accounts.vault.to_account_info(),
            vsigner,
            slice_i,
            decimals,
        )?;
    }
    // The caller must have packed exactly one segment per non-trivial leg y, tras ellos (G3-B2), una cuenta de destino en
    // especie por hucha congelada: las de las patas en orden y la USDC la última. Sin huchas congeladas, la forma de siempre.
    let n_dest = frozen_escrows + usize::from(session_usdc_frozen);
    let dests = &remaining[cursor..];
    if n_dest == 0 {
        require!(dests.is_empty(), WagonError::InvalidJupiterRoute);
    } else {
        require!(dests.len() == n_dest, WagonError::WithdrawInKindDestMismatch);
    }
    // G3-B2: pagos EN ESPECIE, del vault (firma por semillas) a la cuenta del inversor. Es lo que habría recibido en la hucha:
    // el mismo slice pro-rata, ya calculado arriba.
    let mut paid_legs: usize = 0;
    for &(leg, mint_idx, vault_ata_idx, k, slice, default_frozen) in in_kind_legs.iter().take(in_kind_count) {
        let mint_ai = &remaining[mint_idx];
        let vault_ata_ai = &remaining[vault_ata_idx];
        let dest_ai = &dests[k];
        let token_prog_id = *mint_ai.owner;
        if check_in_kind_dest(dest_ai, &mint_ai.key(), &token_prog_id, &investor_pk)? {
            // Destino congelado. Si el mint hace nacer congeladas TODAS las cuentas nuevas, el inversor no puede dar otra:
            // revertir estrangularía el retiro entero, así que la pata se APARCA como cuando el mint bloquea (DT-A(a),
            // forfeit definitivo: el slice tenía saldo). Si no, que dé otra cuenta suya (6226).
            require!(default_frozen, WagonError::WithdrawInKindDestFrozen);
            had_park = 1;
            in_kind_mask &= !(1u16 << leg);
            continue;
        }
        let prog_ai = if token_prog_id == spl_token::ID {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        };
        let decimals = read_mint_decimals(mint_ai)?;
        transfer_checked_signed(
            &prog_ai,
            vault_ata_ai,
            mint_ai,
            dest_ai,
            &ctx.accounts.vault.to_account_info(),
            vsigner,
            slice,
            decimals,
        )?;
        emit!(WithdrawLegClaimedInKind {
            vault: vault_key,
            investor: investor_pk,
            leg_index: leg,
            mint: mint_ai.key(),
            amount: slice,
            by_third_party: false,
        });
        paid_legs += 1;
    }
    if usdc_in_kind > 0 {
        let dest_ai = &dests[n_dest - 1];
        let frozen = check_in_kind_dest(dest_ai, &usdc_mint_pk, &spl_token::ID, &investor_pk)?;
        require!(!frozen, WagonError::WithdrawInKindDestFrozen);
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.vault_usdc_ata.to_account_info(),
                    to: dest_ai.clone(),
                    authority: ctx.accounts.vault.to_account_info(),
                },
                vsigner,
            ),
            usdc_in_kind,
        )?;
        emit!(WithdrawLegClaimedInKind {
            vault: vault_key,
            investor: investor_pk,
            leg_index: WITHDRAW_USDC_LEG_INDEX,
            mint: usdc_mint_pk,
            amount: usdc_in_kind,
            by_third_party: false,
        });
    }
    // G3-B2: ¿se pagó algo EN ESPECIE? Entonces la sesión nace cobrada (sin abort ni doble pago) y no suma a `revivable`.
    let paid_in_kind = paid_legs > 0 || usdc_in_kind > 0;

    // ---- Burn the shares NOW (committed) ----------------------------------
    token::burn(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Burn {
                mint: ctx.accounts.share_mint.to_account_info(),
                from: ctx.accounts.investor_share_ata.to_account_info(),
                authority: ctx.accounts.investor.to_account_info(),
            },
        ),
        shares_to_burn,
    )?;

    // Reflect the burn in vault.total_shares so concurrent operations see it.
    let new_total_shares = total_shares_before
        .checked_sub(shares_to_burn)
        .ok_or(WagonError::MathOverflow)?;
    {
        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::write_total_shares(&mut data, new_total_shares)?;
        // G1 (2026-10-09, F1A-01): mientras esta sesión pueda abortar (sin park definitivo), sus
        // shares son REVIVIBLES y la ENTRADA no puede fijar precio: `deposit_init` y el commit
        // exigen el contador a 0. checked_add: fallar CERRADO aquí es inalcanzable
        // (shares_to_burn <= total_shares) y no es un terminal de salida.
        // G3-B2: tampoco una sesión que nace cobrada (ya pagó en especie: nunca puede revivir). Mismo predicado que
        // `WithdrawSession::counts_in_revivable`, con el que la liberan el settle y el force_release.
        if had_park == 0 && !paid_in_kind {
            let cur = vlayout::read_revivable_burned_shares(&data)?;
            vlayout::write_revivable_burned_shares(
                &mut data,
                cur.checked_add(shares_to_burn).ok_or(WagonError::MathOverflow)?,
            )?;
        }
    }
    // Decrement user_position.shares (cost_basis is decremented at settle once
    // we know the actual realised profit; abort restores it).
    let position = &mut ctx.accounts.user_position;
    position.shares = position
        .shares
        .checked_sub(shares_to_burn)
        .ok_or(WagonError::MathOverflow)?;

    // ---- Initialise WithdrawSession ---------------------------------------
    let now = Clock::get()?.unix_timestamp;
    let session = &mut ctx.accounts.withdraw_session;
    session.investor = investor_pk;
    session.vault = ctx.accounts.vault.key();
    session.shares_to_burn = shares_to_burn;
    session.usdc_slice_from_vault = usdc_slice_from_vault;
    session.usdc_from_swaps = 0;
    session.total_shares_before = total_shares_before;
    session.tvl_before = tvl_before;
    session.leg_count = allocation_count;
    session.legs_completed = legs_completed;
    session.created_at = now;
    session.bump = ctx.bumps.withdraw_session;
    session.legs_swept = legs_swept_at_init;
    session.aborting = 0;
    session.trivial_mask = trivial_mask;
    session.leg_mints = leg_mints;
    // Ceremonia #39 (C-B): la sesión nace SIN comprometer (nada vendido/cobrado), salvo que (G3-B2) ya haya pagado algo EN
    // ESPECIE: entonces nace cobrada, como tras `withdraw_claim_leg_in_kind` (un abort re-acuñaría y pagaría dos veces).
    session.sold = u8::from(paid_in_kind);
    session.in_kind_mask =
        if paid_in_kind { in_kind_mask | WithdrawSession::IN_KIND_AT_INIT_BIT } else { in_kind_mask };
    // Ceremonia #45 (H4, R1): valor pro-rata del vault que ESTE retiro saca,
    // medido igual que el +I del depósito (tvl_before * shares / total_shares).
    // `withdraw_settle` lo resta del agregado global EN LUGAR de `exit_value`,
    // para que la contribución del retiro al tope sea simétrica sea la salida en
    // USDC o EN ESPECIE (cierra el lado SALIDA de H4). `total_shares_before > 0`
    // ya lo garantiza el require de arriba → `mul_div_floor` no divide por cero.
    session.marked_slice = mul_div_floor(tvl_before, shares_to_burn, total_shares_before)?;
    // Ceremonia USDC (§3.4): contador del vault +1 (UNA vez por init) y sello en la
    // sesión con sus 32 bits bajos (nunca 0: el bump salta los múltiplos de 2^32).
    let generation = {
        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::bump_session_generation(&mut data)?
    };
    session.generation = generation as u32;
    session.had_park = had_park;

    // ---- Ceremonia USDC (§3.3, B2): registro de financiación -----------------
    // Espejo de `deposit_init`: patrocinio = el pagador NO es el propietario; con él el
    // registro es OBLIGATORIO (Anchor ya lo creó; aquí se sella) y sin él PROHIBIDO.
    // `refund_to` se acota siempre: con patrocinio, el pagador o `protocol.authority`;
    // sin patrocinio SOLO el propio inversor. Rent MEDIDO en esta tx: `lamports_refundable`
    // = sesión + huchas de pata + registro (el barrido cierra cada hucha de pata hacia el
    // PDA de sesión, D1, y el terminal lo reparte todo); `lamports_sunk` = la hucha USDC,
    // cuyo cierre en `withdraw_settle` es CONDICIONAL (§3.3.c: con residuo y la ATA USDC
    // del vault no pagable se queda abierta y la hereda la siguiente sesión de la pareja).
    require!(
        ctx.accounts.funding_record.is_some() == sponsored,
        WagonError::FundingRecordPresenceMismatch
    );
    let authority = ctx.accounts.protocol.authority;
    crate::funding::check_refund_to(
        &ctx.accounts.refund_to,
        &payer_pk,
        if sponsored { &authority } else { &payer_pk },
    )?;
    // PR 5B (§3.5, D3 / M-04): S de salida firmado por el inversor, ACOTADO al tope vivo (0 en
    // pausa y 0 si el singleton aún no existe) y guardado en el registro; lo cobra el settle del
    // USDC que sale. Sin patrocinio no hay registro: solo vale 0.
    let exit_service_usdc = {
        let (max_exit, paused) =
            service::read_exit_params_lenient(&ctx.accounts.service_config.to_account_info());
        service::exit_service_at_init(sponsored, args.exit_service_usdc, max_exit, paused)?
    };
    if let Some(record) = ctx.accounts.funding_record.as_mut() {
        let bump = ctx
            .bumps
            .funding_record
            .ok_or(WagonError::FundingRecordNotCanonical)?;
        let lamports_refundable = ctx
            .accounts
            .withdraw_session
            .to_account_info()
            .lamports()
            .saturating_add(leg_escrow_lamports)
            .saturating_add(record.to_account_info().lamports());
        let lamports_sunk = usdc_escrow_lamports;
        let refund_to = ctx.accounts.refund_to.key();
        record.session = session_key;
        record.payer = payer_pk;
        record.refund_to = refund_to;
        record.generation = generation;
        record.kind = FUNDING_KIND_WITHDRAW;
        record.lamports_refundable = lamports_refundable;
        record.lamports_sunk = lamports_sunk;
        record.created_at = now;
        record.bump = bump;
        record.exit_service_usdc = exit_service_usdc;
        record._reserved = [0u8; 8];
        emit!(FundingRecorded {
            session: session_key,
            vault: vault_key,
            payer: payer_pk,
            refund_to,
            generation,
            kind: FUNDING_KIND_WITHDRAW,
            lamports_refundable,
            lamports_sunk,
        });
    }

    emit!(WithdrawInitiated {
        vault: ctx.accounts.vault.key(),
        investor: investor_pk,
        shares_to_burn,
        usdc_slice_from_vault,
        tvl_before,
        total_shares_before,
        leg_count: allocation_count,
        legs_pre_completed: legs_completed,
    });

    // ---- G4: huchas nuevas, DESPUÉS de los eventos --------------------------
    // Crear una hucha deja unos 1.3 KB de registro: con ocho se pasa el techo de 10 KB por transacción y lo que va detrás se
    // corta, así que aquí solo quedan las CPIs: crearlas (paga `payer`) y mover a cada una su porción. Atómico: si algo falla,
    // revierte todo el init, eventos incluidos.
    let ata_prog_ai = ctx.accounts.associated_token_program.to_account_info();
    let payer_ai = ctx.accounts.payer.to_account_info();
    let session_ai = ctx.accounts.withdraw_session.to_account_info();
    let system_ai = ctx.accounts.system_program.to_account_info();
    if !usdc_escrow_existed {
        escrow_rent::create_escrow(
            &ata_prog_ai,
            &payer_ai,
            &usdc_escrow_ai,
            &session_ai,
            &ctx.accounts.usdc_mint.to_account_info(),
            &system_ai,
            &ctx.accounts.token_program.to_account_info(),
        )?;
        if usdc_slice_from_vault > 0 {
            move_idle_usdc(&ctx, vsigner, usdc_slice_from_vault)?;
        }
    }
    for &(mint_idx, slice, decimals) in deferred_legs.iter().take(deferred_count) {
        let (mint_ai, vault_ata_ai, escrow_ai) = (&remaining[mint_idx], &remaining[mint_idx + 1], &remaining[mint_idx + 2]);
        let prog_ai = if *mint_ai.owner == spl_token::ID {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        };
        escrow_rent::create_escrow(&ata_prog_ai, &payer_ai, escrow_ai, &session_ai, mint_ai, &system_ai, &prog_ai)?;
        transfer_checked_signed(
            &prog_ai,
            vault_ata_ai,
            mint_ai,
            escrow_ai,
            &ctx.accounts.vault.to_account_info(),
            vsigner,
            slice,
            decimals,
        )?;
    }

    Ok(())
}

/// El slice del USDC ocioso, de la ATA USDC del vault a la hucha USDC de la sesión (firma el vault).
fn move_idle_usdc<'info>(
    ctx: &Context<'_, '_, '_, 'info, WithdrawInit<'info>>,
    vsigner: &[&[&[u8]]],
    amount: u64,
) -> Result<()> {
    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.vault_usdc_ata.to_account_info(),
                to: ctx.accounts.session_usdc_escrow.to_account_info(),
                authority: ctx.accounts.vault.to_account_info(),
            },
            vsigner,
        ),
        amount,
    )
}

/// `floor(a * b / c)` in u128, mapped back to u64.
fn mul_div_floor(a: u64, b: u64, c: u64) -> Result<u64> {
    let q = (a as u128)
        .checked_mul(b as u128)
        .ok_or(WagonError::MathOverflow)?
        .checked_div(c as u128)
        .ok_or(WagonError::DivisionByZero)?;
    u64::try_from(q).map_err(|_| error!(WagonError::MathOverflow))
}

/// G3-B2: la cuenta de destino EN ESPECIE tiene que ser una cuenta de token del programa del mint, de ese mint y del inversor
/// (cualquiera suya: él firma el retiro). Devuelve si está CONGELADA (decide quien llama). Leer una cuenta congelada nunca revierte.
fn check_in_kind_dest(dest: &AccountInfo, mint: &Pubkey, token_prog: &Pubkey, investor: &Pubkey) -> Result<bool> {
    require_keys_eq!(*dest.owner, *token_prog, WagonError::WithdrawInKindDestMismatch);
    verify_token_account(dest, mint, investor).map_err(|_| error!(WagonError::WithdrawInKindDestMismatch))?;
    Ok(read_token_state(dest)? == TOKEN_STATE_FROZEN)
}
