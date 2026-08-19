//! `withdraw_init` — step 1 of the fractional withdraw flow.
//!
//! C2 (ceremonia #38): the investor commits a share amount, we immediately
//! burn those shares, and — the key change — we MOVE each allocation's
//! pro-rata slice out of the vault into a session-owned token escrow ATA (the
//! exact mirror of `deposit_init`, inverted). The vault's token balance
//! auto-reduces, so a CONCURRENT withdraw prices its own slice against the
//! already-reduced pool: the denominator is trivially `total_shares_before`
//! (live, pre-burn) in every interleaving. This is what closes C2 (before,
//! the tokens stayed in the vault and `withdraw_swap_batch`'s cap could
//! over-allocate between co-investors).
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
//! - `escrow_ata` MUST equal the session's canonical ATA for the mint (created
//!   idempotently by the frontend before this ix). The slice moves here.
//! USDC-as-allocation and zero-weight legs are TRIVIAL (no escrow, pre-marked).

use anchor_lang::prelude::*;
use anchor_spl::token::{self, spl_token, Burn, Token, Transfer};

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::WithdrawInitiated;
use crate::instructions::create_vault::verify_mint_tier_b;
use crate::state::vault_layout as vlayout;
use crate::state::{ProtocolConfig, UserPosition, WithdrawSession};
use crate::token_io::{
    derive_live_ata, read_mint_decimals, read_token_amount, transfer_checked_signed,
    verify_token_account, TOKEN_2022_PROGRAM_ID,
};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct WithdrawInitArgs {
    pub shares_to_burn: u64,
}

#[derive(Accounts)]
pub struct WithdrawInit<'info> {
    #[account(mut)]
    pub investor: Signer<'info>,

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
        payer = investor,
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
    /// clásico), verificada por derivación + verify_token_account. La crea el
    /// frontend (idempotente) en la misma tx, payer = investor.
    #[account(mut)]
    pub session_usdc_escrow: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,

    /// CHECK: pubkey verified == Token-2022 program id. Used for token slices
    /// whose mint lives on Token-2022 (xStocks, MetaDAO); ignored otherwise.
    pub token_program_2022: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
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
    verify_token_account(
        &ctx.accounts.session_usdc_escrow.to_account_info(),
        &usdc_mint_pk,
        &session_key,
    )?;

    // Vault PDA signer seeds — the vault owns the token/USDC ATAs the slices
    // move OUT of, so the vault signs the transfers.
    let bump_arr = [vault_bump];
    let vseeds: &[&[u8]] = &[VAULT_SEED, creator.as_ref(), &nonce_le, &bump_arr];
    let vsigner: &[&[&[u8]]] = &[vseeds];

    // ---- H-3: reservar la parte del inversor del idle USDC → hucha USDC ----
    let vault_usdc_before = read_token_amount(&ctx.accounts.vault_usdc_ata.to_account_info())?;
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
    let usdc_slice_from_vault = {
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
    if usdc_slice_from_vault > 0 {
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
            usdc_slice_from_vault,
        )?;
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
        verify_token_account(escrow_ai, &alloc_mint, &session_key)?;

        // Tier-B pre-check. The pubkey already matches (required above), so a
        // failure here means the mint flipped a dangerous extension since vault
        // creation → PARK.
        let tier_ok = verify_mint_tier_b(mint_ai, &alloc_mint).is_ok();
        if !tier_ok {
            legs_completed |= bit; // parked: forfeit this slice, leave it in the vault
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
            continue;
        }

        // Move the slice: vault_ata → escrow, vault signs.
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
            escrow_ai,
            &ctx.accounts.vault.to_account_info(),
            vsigner,
            slice_i,
            decimals,
        )?;
    }
    // The caller must have packed exactly one segment per non-trivial leg.
    require!(cursor == remaining.len(), WagonError::InvalidJupiterRoute);

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
    }
    // Decrement user_position.shares (cost_basis is decremented at settle once
    // we know the actual realised profit; abort restores it).
    let position = &mut ctx.accounts.user_position;
    position.shares = position
        .shares
        .checked_sub(shares_to_burn)
        .ok_or(WagonError::MathOverflow)?;

    // ---- Initialise WithdrawSession ---------------------------------------
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
    session.created_at = Clock::get()?.unix_timestamp;
    session.bump = ctx.bumps.withdraw_session;
    session.legs_swept = 0;
    session.aborting = 0;
    session.trivial_mask = trivial_mask;
    session.leg_mints = leg_mints;
    // Ceremonia #39 (C-B): la sesión nace SIN comprometer (nada vendido/cobrado).
    session.sold = 0;
    session.in_kind_mask = 0;
    // Ceremonia #45 (H4, R1): valor pro-rata del vault que ESTE retiro saca,
    // medido igual que el +net del depósito (tvl_before * shares / total_shares).
    // `withdraw_settle` lo resta del agregado global EN LUGAR de `exit_value`,
    // para que la contribución del retiro al tope sea simétrica sea la salida en
    // USDC o EN ESPECIE (cierra el lado SALIDA de H4). `total_shares_before > 0`
    // ya lo garantiza el require de arriba → `mul_div_floor` no divide por cero.
    session.marked_slice = mul_div_floor(tvl_before, shares_to_burn, total_shares_before)?;
    session._reserved = [0u8; 5];

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

    Ok(())
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
