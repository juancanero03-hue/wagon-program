//! `withdraw_swap_batch` — step 2 of the fractional withdraw flow.
//!
//! C2 (ceremonia #38): each leg sells the token from the SESSION's escrow ATA
//! (funded at `withdraw_init`) into the session's USDC escrow. The source is
//! the escrow, not the vault, and the SESSION signs the swap CPI (mirror of
//! `deposit_swap_batch`). Because the escrow only ever holds THIS session's
//! slice, the over-sell vector (C-1/C2) is closed by construction — no cap
//! arithmetic is needed. Accumulates the realised USDC in
//! `session.usdc_from_swaps`.
//!
//! remaining_accounts layout per leg: `[allocation_mint, escrow_ata, ...jupiter_route]`.
//! - `allocation_mint` MUST equal the session's `leg_mints[leg_idx]` snapshot
//!   (NOT the live vault table). It is the live AccountInfo, re-validated Tier B.
//! - `escrow_ata` MUST equal the canonical ATA of (session, mint) — the escrow
//!   the slice was moved into at init.
//!
//! The stale-after-restructure check is KEPT (v3): a session invalidated by a
//! mid-session restructure does NOT sell (it goes to `withdraw_abort` /
//! deshacer-total). Selling a stale session would seed the vault's per-leg
//! price cache under a `leg_idx` that now points at a DIFFERENT mint.

use anchor_lang::prelude::*;
use anchor_spl::token::spl_token;

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::WithdrawSwapExecuted;
use crate::instructions::create_vault::verify_mint_tier_b;
use crate::jupiter::{check_min_out, invoke_jupiter_swap, SwapPlan};
use crate::state::vault_layout as vlayout;
use crate::state::{ProtocolConfig, WithdrawSession};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct WithdrawSwapBatchArgs {
    pub leg_indices: Vec<u8>,
    pub swap_plans: Vec<SwapPlan>,
    /// For each leg in the batch, the amount of the SOURCE token to sell. The
    /// frontend sets this to the escrow's balance. Capped implicitly by the
    /// escrow balance (you can't sell more than the escrow holds).
    pub amounts_in: Vec<u64>,
}

#[derive(Accounts)]
pub struct WithdrawSwapBatch<'info> {
    pub investor: Signer<'info>,

    #[account(
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// CHECK: PDA seeds verified manually.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    /// CHECK: H-3 — la hucha USDC de la sesión (ATA canónica del PDA de
    /// sesión), verificada por derivación. Recibe el USDC de cada venta.
    #[account(mut)]
    pub session_usdc_escrow: UncheckedAccount<'info>,

    /// CHECK: pubkey verified against `protocol.usdc_mint`.
    pub usdc_mint: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [
            WITHDRAW_SESSION_SEED,
            vault.key().as_ref(),
            investor.key().as_ref(),
        ],
        bump = withdraw_session.bump,
        has_one = investor @ WagonError::WithdrawSessionWrongInvestor,
        has_one = vault @ WagonError::WithdrawSessionWrongVault,
    )]
    pub withdraw_session: Box<Account<'info, WithdrawSession>>,

    /// CHECK: pubkey verified against `JUPITER_PROGRAM_ID`.
    #[account(address = JUPITER_PROGRAM_ID)]
    pub jupiter_program: AccountInfo<'info>,
}

pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, WithdrawSwapBatch<'info>>,
    args: WithdrawSwapBatchArgs,
) -> Result<()> {
    require!(!args.leg_indices.is_empty(), WagonError::EmptyBatch);
    require!(
        args.leg_indices.len() <= MAX_LEGS_PER_BATCH,
        WagonError::BatchTooLarge
    );
    require!(
        args.leg_indices.len() == args.swap_plans.len(),
        WagonError::BatchLengthMismatch
    );
    require!(
        args.leg_indices.len() == args.amounts_in.len(),
        WagonError::BatchLengthMismatch
    );

    // ---- Read vault + validate --------------------------------------------
    let vault_ai = ctx.accounts.vault.to_account_info();
    let guard = crate::guards::VaultGuard::load(
        &vault_ai,
        &ctx.accounts.vault.key(),
        WagonError::VaultClosed,
    )?;
    let status = guard.status;
    let allocation_count = {
        let data = vault_ai.try_borrow_data()?;
        vlayout::read_allocation_count(&data)?
    };
    require!(status != 3u8, WagonError::VaultClosed);
    require!(status != 4u8, WagonError::RestructuringInProgress);
    // P7a (ceremonia #39, C-B): se ELIMINA el gate de stale (created_at >= lra) y
    // el check leg_count == allocation_count. Desde C2 los fondos NO dependen de
    // la tabla viva: el mint sale de session.leg_mints y la hucha se deriva de él,
    // así que una sesión invalidada por un restructure sigue vendiendo el token
    // CORRECTO y puede ASENTAR (en vez de quedar condenada al abort, que era la
    // palanca del creador para forzar el deshacer, B-2). Lo único que protegía el
    // gate —el caché de precio— se protege ahora envolviendo cache_leg_fill (más
    // abajo): solo siembra si el leg_idx vivo sigue apuntando al mismo mint.
    // Una sesión en abort no vende (sus huchas ya se devolvieron al vault).
    require!(
        ctx.accounts.withdraw_session.aborting == 0,
        WagonError::WithdrawSessionAborting
    );

    // ---- H-3: validar la hucha USDC + pin del mint USDC --------------------
    let session_key = ctx.accounts.withdraw_session.key();
    let usdc_mint_key = ctx.accounts.usdc_mint.key();
    require_keys_eq!(
        usdc_mint_key,
        ctx.accounts.protocol.usdc_mint,
        WagonError::InvalidJupiterRoute
    );
    require_keys_eq!(
        ctx.accounts.session_usdc_escrow.key(),
        crate::token_io::derive_live_ata(&session_key, &usdc_mint_key, &spl_token::ID),
        WagonError::EscrowAtaMismatch
    );

    // C2: the escrows belong to the SESSION, so the SESSION signs the swap.
    // NB: bind the keys to locals — `key()` returns a Pubkey BY VALUE, and an
    // inline `.key().as_ref()` inside the seed array would dangle (E0716).
    let vault_key = ctx.accounts.vault.key();
    let investor_key = ctx.accounts.investor.key();
    let session_bump_arr = [ctx.accounts.withdraw_session.bump];
    let session_seeds: &[&[u8]] = &[
        WITHDRAW_SESSION_SEED,
        vault_key.as_ref(),
        investor_key.as_ref(),
        &session_bump_arr,
    ];
    let signer_seeds: &[&[&[u8]]] = &[session_seeds];

    let remaining = ctx.remaining_accounts;
    let mut cursor: usize = 0;
    let mut usdc_gained: u64 = 0;
    let mut new_bits: u16 = 0;

    for (batch_pos, &leg_idx) in args.leg_indices.iter().enumerate() {
        let plan = &args.swap_plans[batch_pos];
        let amount_in = args.amounts_in[batch_pos];

        // P7a: acotar contra el leg_count de la SESIÓN (no la tabla viva, que
        // pudo cambiar de tamaño en un restructure). El mint y la hucha se validan
        // contra el snapshot de la sesión más abajo.
        require!(
            (leg_idx as u16) < (ctx.accounts.withdraw_session.leg_count as u16),
            WagonError::LegIndexOutOfRange
        );
        let bit = 1u16 << leg_idx;
        require!(
            (ctx.accounts.withdraw_session.legs_completed & bit) == 0,
            WagonError::LegAlreadyCompleted
        );
        require!((new_bits & bit) == 0, WagonError::LegAlreadyCompleted);
        require!(amount_in > 0, WagonError::LegIndexOutOfRange);

        // Mint from the SESSION snapshot (not the live table). Since C2 the funds
        // depend only on this snapshot; the escrow is derived from it below.
        let leg_mint = ctx.accounts.withdraw_session.leg_mints[leg_idx as usize];

        // Layout: [mint, escrow_ata, ...jupiter_route].
        let (seg, next) =
            crate::remaining::LegSegment::parse(remaining, cursor, plan.account_count as usize)?;

        // [0] mint AccountInfo — Tier B re-check + bind to the session snapshot.
        let mint_ai = seg.mint_ai;
        verify_mint_tier_b(mint_ai, &leg_mint)?;

        // [1] source = the SESSION's escrow ATA for this mint (live program).
        let escrow_ata = seg.ata_ai;
        let expected_escrow = crate::token_io::derive_live_ata(&session_key, &leg_mint, mint_ai.owner);
        require_keys_eq!(escrow_ata.key(), expected_escrow, WagonError::EscrowAtaMismatch);
        crate::token_io::verify_token_account(escrow_ata, &leg_mint, &session_key)?;
        let route = seg.route;

        // Destino = hucha USDC de la sesión. invoke_jupiter_swap re-verifica
        // byte a byte mint y owner del destino; el tope de venta es el propio
        // balance de la hucha (la venta revierte si intenta gastar de más).
        let dest = &ctx.accounts.session_usdc_escrow.to_account_info();
        let src_before = crate::pricing::read_token_amount(escrow_ata)?;

        // C-A: cuentas declaradas = la hucha fuente (token) + la hucha USDC
        // destino, ambas de la sesión. Cualquier OTRA hucha de la sesión que
        // aparezca en la ruta no puede perder saldo.
        let declared = [escrow_ata.key(), ctx.accounts.session_usdc_escrow.key()];
        let delta = invoke_jupiter_swap(
            &ctx.accounts.jupiter_program,
            dest,
            &usdc_mint_key,
            &session_key,
            // C2: la fuente es la hucha de la SESIÓN → firma la SESIÓN.
            &session_key,
            &declared,
            route,
            plan.ix_data.clone(),
            signer_seeds,
        )?;
        check_min_out(delta, plan.min_out)?;

        // Upgrade #30 / H-4: cache realised execution price + mint decimals
        // using the MEASURED amount consumed from the escrow (not the declared
        // amount_in). The stale check above guarantees leg_idx maps to the same
        // mint as the cache slot, so the seed is correct.
        let src_after = crate::pricing::read_token_amount(escrow_ata)?;
        let consumed = src_before
            .checked_sub(src_after)
            .ok_or(WagonError::MathOverflow)?;
        // P7a: sembrar el caché de precio SOLO si el slot vivo `leg_idx` sigue
        // apuntando al mismo mint que acabamos de vender. Si el vault reestructuró,
        // el slot puede apuntar a otro token → sembrarlo lo envenenaría. Se salta
        // SIN revertir: los fondos no dependen del caché (mint/hucha vienen del
        // snapshot). Esto sustituye la protección que daba el gate de stale (P7a).
        {
            let data = vault_ai.try_borrow_data()?;
            let live_mint_ok = (leg_idx as usize) < (allocation_count as usize)
                && vlayout::read_allocation_mint(&data, leg_idx as usize)? == leg_mint;
            drop(data);
            if live_mint_ok {
                crate::pricing::cache_leg_fill(&vault_ai, leg_idx as usize, delta, consumed, mint_ai)?;
            }
        }

        usdc_gained = usdc_gained
            .checked_add(delta)
            .ok_or(WagonError::MathOverflow)?;
        new_bits |= bit;
        cursor = next;

        emit!(WithdrawSwapExecuted {
            vault: vault_key,
            investor: ctx.accounts.investor.key(),
            leg_index: leg_idx,
            tokens_in: consumed,
            usdc_out: delta,
        });
    }

    crate::remaining::LegSegment::finish(remaining, cursor)?;

    let session = &mut ctx.accounts.withdraw_session;
    session.legs_completed |= new_bits;
    // P2 (C-B): vender COMPROMETE a asentar. Incondicional — la instrucción no
    // llega aquí sin ejecutar ≥1 swap (EmptyBatch se rechaza arriba, cada leg
    // exige amount_in>0 y no-completada). Con sold=1 el abort queda vetado (P4):
    // si no, re-acuñaría shares completas sobre tokens ya vendidos = el ataque C-B.
    session.sold = 1;
    session.usdc_from_swaps = session
        .usdc_from_swaps
        .checked_add(usdc_gained)
        .ok_or(WagonError::MathOverflow)?;

    Ok(())
}
