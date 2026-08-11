//! `deposit_swap_batch` — step 2 of the fractional deposit flow.
//!
//! Executes 1-3 Jupiter swaps in a single transaction, sourcing USDC from
//! the SESSION'S ESCROW ATA (upgrade #31, F2b — before that, the vault's
//! idle balance) and depositing the output tokens into session-owned
//! escrow ATAs. The Jupiter route is quoted off-chain with
//! `userPublicKey = session PDA`, and the session PDA signs the CPI. Each
//! call marks the batched legs in the session's `legs_completed` bitmap so
//! subsequent batches don't re-execute the same swap; `deposit_sweep_batch`
//! later moves the escrowed tokens into the vault (or back to the investor
//! on abort) and `deposit_settle` mints the shares.
//!
//! # Why batches of 1-3 and not all-at-once
//!
//! Solana's v0 tx ceiling (1232 wire bytes) caps how many Jupiter swap
//! plans + their remaining_accounts + ALT lookups fit into a single tx.
//! For typical tokens with direct routes, 2-3 swaps fit. For long-tail
//! tokens with multi-hop routes, sometimes only 1. The frontend picks
//! the batch size dynamically; the program just enforces the hard cap.
//!
//! # remaining_accounts layout
//!
//! For each leg in `leg_indices`, the segment is:
//!   [allocation_mint, destination_ata, ...jupiter_route_accounts]
//!
//! Where:
//!   - `allocation_mint` MUST equal `vault.allocations[leg_idx].mint`. This
//!     is the live mint AccountInfo (not just the pubkey) so that Tier B's
//!     extension scanner can re-validate it on every leg execution —
//!     catches issuers who flip a transfer fee / pausable / etc. between
//!     vault creation and the next deposit. Upgrade #23.
//!   - `destination_ata` MUST equal `vault.allocations[leg_idx].vault_ata`.
//!   - The jupiter_route_accounts are forwarded verbatim to the Jupiter CPI.
//!
//! Segments are concatenated in the same order as `leg_indices`.
//!
//! # No double-execute
//!
//! Each leg's bit in `legs_completed` is checked at entry and set after
//! the successful CPI. A retry of the same `(session, leg_idx)` either
//! sees the bit already set (returns `LegAlreadyCompleted`) or, if the
//! Jupiter CPI itself reverted, runs cleanly because the bit was never
//! set in the first place.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::DepositSwapExecuted;
use crate::instructions::create_vault::verify_mint_tier_b;
use crate::jupiter::{check_min_out, invoke_jupiter_swap, SwapPlan};
use crate::state::vault_layout as vlayout;
use crate::state::DepositSession;

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct DepositSwapBatchArgs {
    pub leg_indices: Vec<u8>,
    pub swap_plans: Vec<SwapPlan>,
}

#[derive(Accounts)]
pub struct DepositSwapBatch<'info> {
    pub investor: Signer<'info>,

    /// CHECK: PDA seeds + status verified manually.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [
            DEPOSIT_SESSION_SEED,
            vault.key().as_ref(),
            investor.key().as_ref(),
        ],
        bump = deposit_session.bump,
        has_one = investor @ WagonError::DepositSessionWrongInvestor,
        has_one = vault @ WagonError::DepositSessionWrongVault,
    )]
    pub deposit_session: Box<Account<'info, DepositSession>>,

    /// CHECK: pubkey verified against `JUPITER_PROGRAM_ID`.
    #[account(address = JUPITER_PROGRAM_ID)]
    pub jupiter_program: AccountInfo<'info>,
}

pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, DepositSwapBatch<'info>>,
    args: DepositSwapBatchArgs,
) -> Result<()> {
    // ---- Validate batch shape ----------------------------------------------
    require!(!args.leg_indices.is_empty(), WagonError::EmptyBatch);
    require!(
        args.leg_indices.len() <= MAX_LEGS_PER_BATCH,
        WagonError::BatchTooLarge
    );
    require!(
        args.leg_indices.len() == args.swap_plans.len(),
        WagonError::BatchLengthMismatch
    );

    // ---- Read vault state once (byte-level) --------------------------------
    let vault_ai = ctx.accounts.vault.to_account_info();
    let _guard = crate::guards::VaultGuard::load_active(
        &vault_ai,
        &ctx.accounts.vault.key(),
        WagonError::VaultPaused,
    )?;
    let allocation_count = {
        let data = vault_ai.try_borrow_data()?;
        vlayout::read_allocation_count(&data)?
    };
    // Upgrade #31: sesión anterior a la última reestructuración = tabla vieja.
    {
        let data = vault_ai.try_borrow_data()?;
        let lra = vlayout::read_last_restructured_at(&data)?;
        require!(
            ctx.accounts.deposit_session.created_at >= lra,
            WagonError::StaleSessionAfterRestructure
        );
    }
    // Upgrade #31 (F2b): una sesión en abort no admite más swaps.
    require!(
        ctx.accounts.deposit_session.aborting == 0,
        WagonError::DepositSessionAborting
    );

    // Session must agree with the vault's view of allocation_count. If
    // someone managed to mutate the vault between init and now, refuse.
    require!(
        ctx.accounts.deposit_session.leg_count == allocation_count,
        WagonError::DepositSessionWrongVault
    );

    // Upgrade #31 (F2b): SESSION PDA signer seeds for Jupiter swap CPIs.
    // The escrow ATAs belong to the session, so the session is Jupiter's
    // "user", not the vault.
    let vault_key = ctx.accounts.vault.key();
    let session_key = ctx.accounts.deposit_session.key();
    let investor_key = ctx.accounts.investor.key();
    let session_bump_arr = [ctx.accounts.deposit_session.bump];
    let seeds: &[&[u8]] = &[
        DEPOSIT_SESSION_SEED,
        vault_key.as_ref(),
        investor_key.as_ref(),
        &session_bump_arr,
    ];
    let signer_seeds: &[&[&[u8]]] = &[seeds];

    // ---- Walk remaining_accounts segment-by-segment ----------------------
    let remaining = ctx.remaining_accounts;
    let session_amount_usdc = ctx.accounts.deposit_session.amount_usdc;

    // Ceremonia #37: guard de pérdida por compra. El umbral viene SELLADO en
    // la sesión desde deposit_init (esta ix no lleva la cuenta protocol);
    // 0 = apagado = layout y comportamiento EXACTOS pre-#37. Con guard activo
    // el layout es [FeedRegistry, seg_0, seg_1, ...] y cada segmento lleva las
    // cuentas de oráculo de su mint entre la ata y la ruta. Las sesiones
    // abiertas antes de encender el guard llevan 0 → nunca quedan atrapadas.
    let max_loss_bps = ctx.accounts.deposit_session.max_loss_bps;
    let guard_registry = if max_loss_bps > 0 {
        require!(
            !remaining.is_empty(),
            WagonError::SwapGuardAccountsMissing
        );
        Some(&remaining[0])
    } else {
        None
    };
    let clock = Clock::get()?;
    let mut cursor: usize = if guard_registry.is_some() { 1 } else { 0 };

    // We collect the bitmap updates locally and apply once at the end so
    // partial failures don't leave the bitmap in a half-updated state. If
    // any swap CPI reverts, the whole tx reverts and no bits change.
    let mut new_bits: u16 = 0;
    // Ceremonia #39 (S-4): acumula el valor-oráculo recibido de las patas de
    // ESTE batch (el mismo que el guard ya calcula). Se persiste en la sesión
    // al final. saturating_add deliberado: el min() del settle lo capa a
    // amount_usdc, así que no hace falta un checked_ (que añadiría un revert).
    let mut acc_value: u64 = 0;

    for (batch_pos, &leg_idx) in args.leg_indices.iter().enumerate() {
        let plan = &args.swap_plans[batch_pos];

        require!(
            (leg_idx as u16) < (allocation_count as u16),
            WagonError::LegIndexOutOfRange
        );

        let bit = 1u16 << leg_idx;
        require!(
            (ctx.accounts.deposit_session.legs_completed & bit) == 0,
            WagonError::LegAlreadyCompleted
        );
        // Also refuse if this leg's bit was scheduled twice within the same
        // batch (e.g. leg_indices = [3, 3]).
        require!((new_bits & bit) == 0, WagonError::LegAlreadyCompleted);

        // Read this leg's mint + weight. We INTENTIONALLY ignore the
        // vault_ata stored in state and recompute it below from the mint's
        // actual token program — pre-upgrade-#27 vaults (e.g. Poseidon)
        // stored a classic-derived ATA for Token-2022 mints that does not
        // exist on-chain. Recomputing makes both old and new vaults work.
        let (alloc_mint, weight_bps) = {
            let data = vault_ai.try_borrow_data()?;
            (
                vlayout::read_allocation_mint(&data, leg_idx as usize)?,
                vlayout::read_allocation_weight_bps(&data, leg_idx as usize)?,
            )
        };

        // Defensive: USDC-as-allocation legs and zero-weight legs should
        // already be marked completed at init. If we're seeing one in the
        // batch, the frontend has a bug — refuse with the "out of range"
        // signal so we don't double-charge the user.
        require!(weight_bps > 0, WagonError::LegIndexOutOfRange);

        // leg_usdc = session.amount_usdc * weight_bps / BPS_DENOMINATOR
        let leg_usdc = (session_amount_usdc as u128)
            .checked_mul(weight_bps as u128)
            .ok_or(WagonError::MathOverflow)?
            .checked_div(BPS_DENOMINATOR as u128)
            .ok_or(WagonError::DivisionByZero)?;
        require!(leg_usdc > 0, WagonError::LegIndexOutOfRange);

        // Carve the segment for this leg. Layout: [mint, dest_ata,
        // ...oraculo_del_guard (solo con guard activo), ...jupiter_route].
        // Con guard apagado, oracle_len = 0 y esto es el LegSegment de siempre.
        let oracle_len = match guard_registry {
            Some(reg) => crate::pricing::guard_oracle_account_count(reg, &alloc_mint)?,
            None => 0,
        };
        let (seg, next) = crate::remaining::GuardedLegSegment::parse(
            remaining,
            cursor,
            oracle_len,
            plan.account_count as usize,
        )?;

        // [0] mint AccountInfo — re-validate Tier B (catches issuers who
        // flip a transfer fee / pausable / etc. between vault creation and
        // now). Cheap for classic SPL Token mints (~500 CU), ~5K CU for
        // Token-2022 mints with extensions.
        let mint_ai = seg.mint_ai;
        verify_mint_tier_b(mint_ai, &alloc_mint)?;

        // Upgrade #31 (F2b): the session snapshotted the basket at init;
        // the live vault table must still agree (it does unless something
        // is deeply wrong — restructures are excluded by the stale check).
        require_keys_eq!(
            alloc_mint,
            ctx.accounts.deposit_session.leg_mints[leg_idx as usize],
            WagonError::AllocMintMismatch
        );

        // Upgrade #27: derive expected_dest_ata from the LIVE mint owner
        // (mint_ai.owner is either classic SPL Token or Token-2022 program
        // id, decided at runtime). Upgrade #31 (F2b): the destination is
        // the SESSION's escrow ATA, not the vault's allocation ATA.
        let expected_dest_ata =
            crate::token_io::derive_live_ata(&session_key, &alloc_mint, mint_ai.owner);

        // [1] destination ATA — verify it matches the vault's allocation slot.
        let dest_ata = seg.ata_ai;
        require_keys_eq!(
            dest_ata.key(),
            expected_dest_ata,
            WagonError::LegDestAtaMismatch
        );
        // The destination ATA is preceded in remaining_accounts by convention
        // for Wagon's validation, but Jupiter's instruction layout already
        // includes the destination ATA among the accounts the API returns
        // (visible at index ~3 in a typical USDC→TokenX route). Passing it
        // again at index 0 would shift every account one slot down and
        // trigger Jupiter's IncorrectTokenProgramID (0x1783) at runtime,
        // because account[0] of a Jupiter Route ix MUST be the SPL Token
        // program. Skip the dest_ata when forwarding to Jupiter.
        let route = seg.route;

        // C-A: cuentas declaradas de este swap = la hucha destino (token) + la
        // hucha USDC de la sesión (fuente de todo depósito). La hucha USDC no es
        // cuenta nombrada del struct (viaja dentro de la ruta) → se deriva. El
        // array se liga a un `let` local para no dejar temporales colgantes (E0716).
        let usdc_escrow = crate::token_io::derive_live_ata(
            &session_key,
            &crate::constants::USDC_MINT,
            &anchor_spl::token::spl_token::ID,
        );
        let declared = [dest_ata.key(), usdc_escrow];
        let delta = invoke_jupiter_swap(
            &ctx.accounts.jupiter_program,
            dest_ata,
            &alloc_mint,
            &session_key,
            &session_key,
            &declared,
            route,
            plan.ix_data.clone(),
            signer_seeds,
        )?;
        check_min_out(delta, plan.min_out)?;

        // Ceremonia #37: piso de valor-oráculo — los tokens recibidos deben
        // valer ≥ leg_usdc × (1 − max_loss). Con min_out del caller ya
        // verificado, esto cierra el agujero de la llamada directa con
        // min_out=1 que compra tokens ilíquidos destruyendo valor de TODOS
        // los holders (las shares se acuñan contra el snapshot pre-depósito).
        if let Some(reg) = guard_registry {
            let dec = crate::pricing::read_mint_decimals(mint_ai)?;
            let received_value =
                crate::pricing::guard_oracle_value(reg, &alloc_mint, dec, delta, seg.oracle, &clock)?;
            crate::pricing::enforce_value_floor(received_value, leg_usdc as u64, max_loss_bps)?;
            // Ceremonia #39 (S-4): acumula lo que REALMENTE vale lo comprado.
            acc_value = acc_value.saturating_add(received_value);
        }

        // Upgrade #30: cache realised execution price + mint decimals for
        // the mark-to-market fallback path. Best-effort, never blocks.
        crate::pricing::cache_leg_fill(
            &vault_ai,
            leg_idx as usize,
            leg_usdc as u64,
            delta,
            mint_ai,
        )?;

        new_bits |= bit;
        cursor = next;

        emit!(DepositSwapExecuted {
            vault: vault_key,
            investor: ctx.accounts.investor.key(),
            leg_index: leg_idx,
            usdc_in: leg_usdc as u64,
            tokens_out: delta,
        });
    }

    // Cursor sanity: caller should have packed exactly what they declared.
    crate::remaining::LegSegment::finish(remaining, cursor)?;

    // Persist the bitmap update.
    let session = &mut ctx.accounts.deposit_session;
    session.legs_completed |= new_bits;
    // Ceremonia #39 (S-4): acumula el valor recibido de este batch. Solo suma
    // algo cuando el guard va vivo (con guard apagado acc_value == 0 y
    // value_tracked == 0, así que el settle ignora este campo). Idempotente por
    // batch: cada leg entra una sola vez (bit dedupe en :193).
    session.received_value_acc = session.received_value_acc.saturating_add(acc_value);

    Ok(())
}
