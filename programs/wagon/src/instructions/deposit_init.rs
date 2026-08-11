//! `deposit_init` — step 1 of the fractional deposit flow.
//!
//! Locks the investor's USDC into the SESSION'S OWN ESCROW ATA (upgrade
//! #31, F2b — before that it went straight into the vault), snapshots the
//! pre-deposit valuation (tvl + total_shares + agg_cost_basis), pre-marks
//! any USDC-as-allocation leg as already-completed (no swap needed), and
//! creates the `DepositSession` PDA that subsequent `deposit_swap_batch`,
//! `deposit_sweep_batch` and `deposit_settle` calls will consume.
//!
//! The escrow keeps unsettled deposits OUT of the vault: the vault's idle
//! USDC and allocation ATAs only ever contain settled funds, so the
//! mark-to-market TVL other depositors see is never polluted by someone
//! else's in-flight session. The frontend pre-creates the escrow USDC ATA
//! (owner = session PDA, derivable before init) with a createATA-idempotent
//! instruction in the same transaction.
//!
//! Why split this off from `deposit_swap_batch`:
//!   - We need the snapshot taken atomically with the USDC transfer, before
//!     any swap can move the price. Doing it inside swap_batch would let
//!     a malicious wallet front-run the snapshot with another deposit's
//!     swap and skew the valuation.
//!   - Init is the natural place to enforce the TVL cap, so we don't end
//!     up half-way through a batch and then have to bail.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, spl_token, Token, Transfer};

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::{DepositInitiated, EntryFeeCharged};
use crate::state::vault_layout as vlayout;
use crate::state::{DepositSession, ProtocolConfig};
use crate::token_io::{derive_live_ata, verify_token_account};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct DepositInitArgs {
    pub amount_usdc: u64,
}

#[derive(Accounts)]
pub struct DepositInit<'info> {
    #[account(mut)]
    pub investor: Signer<'info>,

    #[account(
        mut,
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        constraint = !protocol.paused @ WagonError::ProtocolPaused,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// CHECK: PDA seeds + status verified manually via byte-level reads.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    /// CHECK: pubkey verified against `vault_layout::read_usdc_ata`.
    #[account(mut)]
    pub vault_usdc_ata: UncheckedAccount<'info>,

    /// CHECK: SPL Token account validated manually: program owner spl_token,
    /// mint == usdc_mint, owner == investor.key().
    #[account(mut)]
    pub investor_usdc_ata: UncheckedAccount<'info>,

    /// CHECK: pubkey verified against `protocol.usdc_mint`.
    pub usdc_mint: UncheckedAccount<'info>,

    #[account(
        init,
        payer = investor,
        space = DepositSession::LEN,
        seeds = [
            DEPOSIT_SESSION_SEED,
            vault.key().as_ref(),
            investor.key().as_ref(),
        ],
        bump,
    )]
    pub deposit_session: Box<Account<'info, DepositSession>>,

    /// CHECK: Upgrade #31 (F2b). ATA de USDC propiedad de la sesión PDA —
    /// el escrow donde queda bloqueado el USDC del inversor hasta el settle.
    /// Verificada por derivación canónica + verify_token_account. La crea
    /// el frontend (idempotente) en la misma tx, payer = investor.
    #[account(mut)]
    pub session_usdc_escrow: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,

    // ---- entry fee (fase 2, 2026-07-01) — OPTIONAL Anchor accounts ---------
    // Required (Some) only when the entry fee is ON. The frontend passes the
    // program id as Anchor's None sentinel while the fee is OFF. They sit
    // AFTER every named account and BEFORE remaining_accounts (which carry
    // the m2m oracle set), so old-shape transactions that omit them would
    // shift the oracle accounts into these slots — that is why the frontend
    // that passes them must ship together with the program upgrade.
    /// CHECK: protocol fee destination. Key-checked == protocol.treasury_usdc_ata
    /// (the canonical ATA stored at initialize).
    #[account(mut)]
    pub fee_treasury_usdc_ata: Option<UncheckedAccount<'info>>,

    /// CHECK: the creator's rewards vault ("hucha") — canonical USDC ATA of
    /// the per-creator PDA [b"creator-rewards", creator]. Same derivation
    /// `claim_creator_rewards` enforces; verified canonically + mint/owner
    /// in the handler when the fee is ON.
    #[account(mut)]
    pub creator_rewards_ata: Option<UncheckedAccount<'info>>,
}

pub fn handler(ctx: Context<DepositInit>, args: DepositInitArgs) -> Result<()> {
    let amount_usdc = args.amount_usdc;
    require!(amount_usdc > 0, WagonError::ZeroDeposit);

    // ---- Read & validate vault (byte-level) --------------------------------
    let vault_ai = ctx.accounts.vault.to_account_info();
    let guard = crate::guards::VaultGuard::load_active(
        &vault_ai,
        &ctx.accounts.vault.key(),
        WagonError::VaultPaused,
    )?;
    let (creator, nonce, vault_bump, status) =
        (guard.creator, guard.nonce, guard.bump, guard.status);
    let nonce_le = nonce.to_le_bytes();
    let (allocation_count, total_shares_before, tvl_before, agg_cost_before, usdc_ata_pk, committed_deposits) = {
        let data = vault_ai.try_borrow_data()?;
        (
            vlayout::read_allocation_count(&data)?,
            vlayout::read_total_shares(&data)?,
            vlayout::read_tvl_last_computed_usdc(&data)?,
            vlayout::read_aggregate_cost_basis_usdc(&data)?,
            vlayout::read_usdc_ata(&data)?,
            vlayout::read_committed_deposits(&data)?,
        )
    };

    // ---- Ceremonia #47 (H2): veto con un depósito COMPROMETIDO en vuelo -------
    // La ventana en que otro depósito ya barrió sus tokens al vault pero aún no ha
    // acuñado (committed_deposits > 0) es EXACTAMENTE la ventana de dilución de H2:
    // el m2m de más abajo valora los saldos VIVOS del vault (que ya incluyen esos
    // tokens) pero total_shares_before NO cuenta sus participaciones fantasma → este
    // depositante nuevo pagaría de más por participación y quedaría diluido. Fail-
    // CLOSED antes de tocar un solo lamport (fee/escrow): revierte sin crear sesión.
    // No es bloqueo permanente: committed_deposits > 0 implica sesión swap-completa
    // (el incremento vive en la rama settle del barrido, que exige is_complete()), y
    // barrido + settle son PERMISSIONLESS → cualquiera cierra la ventana. Reusa el
    // error #43 (VaultHasCommittedDeposit): condición semánticamente idéntica; el
    // contexto de instrucción desambigua el mensaje. El retiro NO se toca.
    require!(
        committed_deposits == 0,
        WagonError::VaultHasCommittedDeposit
    );

    // Bitmap caps at 16 legs; the session's leg_mints snapshot (F2b) caps
    // at MAX_TOKENS_PER_VAULT, which is the binding limit (today 10).
    require!(
        allocation_count as usize <= crate::constants::MAX_TOKENS_PER_VAULT,
        WagonError::TooManyAllocations
    );

    // ---- Validate SPL accounts --------------------------------------------
    let usdc_mint_pk = ctx.accounts.protocol.usdc_mint;
    require_keys_eq!(
        ctx.accounts.usdc_mint.key(),
        usdc_mint_pk,
        WagonError::InvalidJupiterRoute
    );
    require_keys_eq!(
        *ctx.accounts.usdc_mint.owner,
        spl_token::ID,
        WagonError::InvalidJupiterRoute
    );
    require_keys_eq!(
        ctx.accounts.vault_usdc_ata.key(),
        usdc_ata_pk,
        WagonError::InvalidJupiterRoute
    );

    let investor_pk = ctx.accounts.investor.key();
    verify_token_account(
        &ctx.accounts.investor_usdc_ata.to_account_info(),
        &usdc_mint_pk,
        &investor_pk,
    )?;

    // ---- Upgrade #31 (F2b): validate the session's USDC escrow ATA ---------
    // USDC is a classic SPL Token mint, so the escrow derivation is fixed to
    // the classic token program. Owner field must be the session PDA itself.
    let session_key = ctx.accounts.deposit_session.key();
    require_keys_eq!(
        ctx.accounts.session_usdc_escrow.key(),
        crate::token_io::derive_live_ata(&session_key, &usdc_mint_pk, &spl_token::ID),
        WagonError::EscrowAtaMismatch
    );
    verify_token_account(
        &ctx.accounts.session_usdc_escrow.to_account_info(),
        &usdc_mint_pk,
        &session_key,
    )?;

    // ---- Entry fee (front-load, accrue-and-claim — fase 2) -----------------
    // fee = min(amount * bps / 10000, cap), only while the fee is ON and the
    // deposit reaches the exemption threshold. protocol_cut rounds DOWN, so
    // the remainder favours the creator. u128 throughout; the setter caps
    // bps at ENTRY_FEE_MAX_BPS (5%), so fee < amount always.
    let (fee_usdc, protocol_cut_usdc, creator_cut_usdc) = {
        let p = &ctx.accounts.protocol;
        if p.entry_fee_bps > 0 && amount_usdc >= p.entry_fee_exempt_below_usdc {
            let raw = (amount_usdc as u128)
                .checked_mul(p.entry_fee_bps as u128)
                .ok_or(WagonError::MathOverflow)?
                / BPS_DENOMINATOR as u128;
            let fee = raw.min(p.entry_fee_cap_usdc as u128) as u64;
            let protocol_cut = ((fee as u128)
                .checked_mul(p.entry_fee_protocol_share_bps as u128)
                .ok_or(WagonError::MathOverflow)?
                / BPS_DENOMINATOR as u128) as u64;
            let creator_cut = fee
                .checked_sub(protocol_cut)
                .ok_or(WagonError::MathOverflow)?;
            (fee, protocol_cut, creator_cut)
        } else {
            (0u64, 0u64, 0u64)
        }
    };
    // What actually enters the basket. Shares, cap and TVL all run on net.
    let net_usdc = amount_usdc
        .checked_sub(fee_usdc)
        .ok_or(WagonError::MathOverflow)?;
    require!(net_usdc > 0, WagonError::ZeroDeposit);

    // ---- Enforce TVL cap ---------------------------------------------------
    {
        let protocol = &ctx.accounts.protocol;
        let projected_tvl = protocol
            .total_tvl_usdc
            .checked_add(net_usdc)
            .ok_or(WagonError::MathOverflow)?;
        require!(
            projected_tvl <= protocol.tvl_cap_usdc,
            WagonError::TvlCapExceeded
        );
    }

    // ---- Upgrade #30: mark-to-market snapshot ------------------------------
    // Value the basket at market BEFORE the investor's USDC lands, so the
    // share price is fair to both sides. Without oracle accounts the legacy
    // stored TVL is used — allowed only while m2m enforcement is off.
    let tvl_before = if !ctx.remaining_accounts.is_empty() {
        let idle_usdc =
            crate::pricing::read_token_amount(&ctx.accounts.vault_usdc_ata.to_account_info())?;
        let m2m = crate::pricing::compute_tvl_m2m_strict(
            &vault_ai,
            &ctx.accounts.vault.key(),
            idle_usdc,
            &usdc_mint_pk,
            ctx.remaining_accounts,
        )?;
        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::write_tvl_last_computed_usdc(&mut data, m2m)?;
        m2m
    } else {
        require!(
            ctx.accounts.protocol.m2m_enforced == 0,
            WagonError::MissingPriceAccounts
        );
        tvl_before
    };

    // ---- Entry fee transfers (investor → treasury / creator rewards) ------
    // Both cuts leave the investor's ATA BEFORE the escrow transfer; neither
    // touches any vault account, so the m2m snapshot above is unaffected.
    if fee_usdc > 0 {
        let treasury_ai = ctx
            .accounts
            .fee_treasury_usdc_ata
            .as_ref()
            .ok_or(WagonError::MissingEntryFeeAccounts)?;
        let rewards_ai = ctx
            .accounts
            .creator_rewards_ata
            .as_ref()
            .ok_or(WagonError::MissingEntryFeeAccounts)?;

        // Protocol cut can only go to the ONE treasury ATA fixed at init.
        require_keys_eq!(
            treasury_ai.key(),
            ctx.accounts.protocol.treasury_usdc_ata,
            WagonError::EntryFeeTreasuryMismatch
        );

        // Creator cut accrues in the canonical USDC ATA of the per-creator
        // rewards PDA — the exact account `claim_creator_rewards` pays from.
        let (rewards_authority, _) =
            Pubkey::find_program_address(&[CREATOR_REWARDS_SEED, creator.as_ref()], &crate::ID);
        require_keys_eq!(
            rewards_ai.key(),
            derive_live_ata(&rewards_authority, &usdc_mint_pk, &spl_token::ID),
            WagonError::CreatorRewardsAtaMismatch
        );
        verify_token_account(
            &rewards_ai.to_account_info(),
            &usdc_mint_pk,
            &rewards_authority,
        )?;

        if protocol_cut_usdc > 0 {
            token::transfer(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.investor_usdc_ata.to_account_info(),
                        to: treasury_ai.to_account_info(),
                        authority: ctx.accounts.investor.to_account_info(),
                    },
                ),
                protocol_cut_usdc,
            )?;
        }
        if creator_cut_usdc > 0 {
            token::transfer(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.investor_usdc_ata.to_account_info(),
                        to: rewards_ai.to_account_info(),
                        authority: ctx.accounts.investor.to_account_info(),
                    },
                ),
                creator_cut_usdc,
            )?;
        }
    }

    // ---- Transfer USDC investor → session escrow (upgrade #31, F2b) -------
    // The vault sees nothing until deposit_settle sweeps the escrow. An
    // abandoned session can always be unwound with deposit_abort — the
    // funds never mixed with the vault's.
    token::transfer(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.investor_usdc_ata.to_account_info(),
                to: ctx.accounts.session_usdc_escrow.to_account_info(),
                authority: ctx.accounts.investor.to_account_info(),
            },
        ),
        net_usdc,
    )?;

    // ---- Pre-mark USDC-as-allocation legs as completed ---------------------
    // If any allocation slot is itself USDC, that "leg" needs no swap — its
    // slice stays in the escrow as USDC and reaches the vault in the settle
    // sweep. We mark its bit at init so deposit_swap_batch never has to
    // handle it and deposit_settle's completeness check passes. We also
    // snapshot the allocation mints into the session (leg_mints) so sweeps
    // and aborts never have to trust the LIVE vault table — which may have
    // restructured to a different basket mid-session.
    let mut legs_completed: u16 = 0;
    let mut leg_mints = [Pubkey::default(); crate::constants::MAX_TOKENS_PER_VAULT];
    for i in 0..(allocation_count as usize) {
        let alloc_mint = {
            let data = vault_ai.try_borrow_data()?;
            vlayout::read_allocation_mint(&data, i)?
        };
        let weight_bps = {
            let data = vault_ai.try_borrow_data()?;
            vlayout::read_allocation_weight_bps(&data, i)?
        };
        leg_mints[i] = alloc_mint;
        // Zero-weight slots are also "completed" — nothing to do.
        if alloc_mint == usdc_mint_pk || weight_bps == 0 {
            legs_completed |= 1u16 << i;
        }
    }

    // ---- Initialise DepositSession ----------------------------------------
    // Ceremonia #37: el umbral del guard de pérdida por compra se SELLA en la
    // sesión (deposit_swap_batch no lleva la cuenta protocol). Las sesiones
    // abiertas antes de encender el guard llevan 0 → nunca quedan atrapadas.
    let swap_max_loss_bps = ctx.accounts.protocol.swap_max_loss_bps;
    let session = &mut ctx.accounts.deposit_session;
    session.investor = investor_pk;
    session.vault = ctx.accounts.vault.key();
    session.amount_usdc = net_usdc; // net of the entry fee
    session.total_shares_before = total_shares_before;
    session.tvl_before = tvl_before;
    session.agg_cost_before = agg_cost_before;
    session.leg_count = allocation_count;
    session.legs_completed = legs_completed;
    session.created_at = Clock::get()?.unix_timestamp;
    session.bump = ctx.bumps.deposit_session;
    // Upgrade #31 (F2b): escrow bookkeeping.
    session.legs_swept = 0;
    session.aborting = 0;
    session.trivial_mask = legs_completed; // at init, completed == trivial
    session.leg_mints = leg_mints;
    session.max_loss_bps = swap_max_loss_bps;
    // Ceremonia #39 (S-4): acumulador del valor-oráculo recibido. Se sella ON
    // solo si el guard va vivo (sin guard no hay oráculo enhebrado en los
    // swap_batch → no hay medición posible; la sesión usará la fórmula legacy).
    session.received_value_acc = 0;
    session.value_tracked = if swap_max_loss_bps > 0 { 1 } else { 0 };
    session._reserved = [0u8; 5];

    // ---- Advance protocol total_tvl optimistically ------------------------
    // We've already taken the USDC from the investor; account for it now so
    // a concurrent init from another investor sees the post-add cap.
    // deposit_abort reverses this if the session never settles.
    let protocol = &mut ctx.accounts.protocol;
    protocol.total_tvl_usdc = protocol
        .total_tvl_usdc
        .checked_add(net_usdc)
        .ok_or(WagonError::MathOverflow)?;

    if fee_usdc > 0 {
        emit!(EntryFeeCharged {
            vault: ctx.accounts.vault.key(),
            creator,
            investor: investor_pk,
            fee_usdc,
            creator_cut_usdc,
            protocol_cut_usdc,
        });
    }

    emit!(DepositInitiated {
        vault: ctx.accounts.vault.key(),
        investor: investor_pk,
        // Net of the entry fee — the amount shares are minted against
        // (EntryFeeCharged, above, carries the fee breakdown).
        amount_usdc: net_usdc,
        tvl_before,
        total_shares_before,
        leg_count: allocation_count,
        legs_pre_completed: legs_completed,
    });

    Ok(())
}
