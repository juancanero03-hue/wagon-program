//! `restructure_swap_batch` — upgrade #31, paso 2 del cambio de estrategia.
//!
//! Ejecuta legs de dos tipos, SIEMPRE con USDC como pivote:
//!   kind 0 (SELL): vende el balance completo de un token SALIENTE
//!                  (índice de la tabla VIEJA) a USDC.
//!   kind 1 (BUY):  compra un token ENTRANTE (índice de la tabla NUEVA)
//!                  con USDC. El fill (usdc_in, tokens_out) se anota en la
//!                  sesión para cebar el caché de precios en settle.
//!
//! remaining_accounts por leg: [mint, ata, ...ruta_jupiter] — ata es la
//! fuente en SELL y el destino en BUY (derivada en vivo, lección del #27).

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::RestructureLegExecuted;
use crate::instructions::create_vault::verify_mint_tier_b;
use crate::instructions::restructure_init::RESTRUCTURE_SEED;
use crate::jupiter::{check_min_out, invoke_jupiter_swap, SwapPlan};
use crate::state::vault_layout as vlayout;
use crate::state::RestructureSession;

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct RestructureSwapBatchArgs {
    /// 0 = sell (índice tabla vieja), 1 = buy (índice tabla nueva).
    pub kinds: Vec<u8>,
    pub indices: Vec<u8>,
    pub amounts_in: Vec<u64>,
    pub swap_plans: Vec<SwapPlan>,
}

#[derive(Accounts)]
pub struct RestructureSwapBatch<'info> {
    pub creator: Signer<'info>,

    /// CHECK: PDA verificada byte-level abajo.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    /// CHECK: pubkey verificada contra vault_layout::read_usdc_ata.
    #[account(mut)]
    pub vault_usdc_ata: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [RESTRUCTURE_SEED, vault.key().as_ref()],
        bump = restructure_session.bump,
        has_one = vault @ WagonError::RestructureSessionMismatch,
    )]
    pub restructure_session: Box<Account<'info, RestructureSession>>,

    /// CHECK: id del programa de Jupiter, validado en invoke_jupiter_swap.
    pub jupiter_program: AccountInfo<'info>,
}

pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, RestructureSwapBatch<'info>>,
    args: RestructureSwapBatchArgs,
) -> Result<()> {
    let n = args.kinds.len();
    require!(
        n >= 1
            && n <= MAX_LEGS_PER_BATCH
            && args.indices.len() == n
            && args.amounts_in.len() == n
            && args.swap_plans.len() == n,
        WagonError::BatchLengthMismatch
    );

    let vault_ai = ctx.accounts.vault.to_account_info();
    let guard = crate::guards::VaultGuard::load(
        &vault_ai,
        &ctx.accounts.vault.key(),
        WagonError::VaultPaused,
    )?;
    let (creator, nonce, vault_bump, status) =
        (guard.creator, guard.nonce, guard.bump, guard.status);
    let nonce_le = nonce.to_le_bytes();
    let (old_count, usdc_ata_pk) = {
        let data = vault_ai.try_borrow_data()?;
        (
            vlayout::read_allocation_count(&data)?,
            vlayout::read_usdc_ata(&data)?,
        )
    };
    require!(status == 4u8, WagonError::NotRestructuring);
    require_keys_eq!(
        creator,
        ctx.accounts.creator.key(),
        WagonError::UnauthorizedVaultCreator
    );
    require_keys_eq!(
        ctx.accounts.vault_usdc_ata.key(),
        usdc_ata_pk,
        WagonError::InvalidJupiterRoute
    );

    let vault_key = ctx.accounts.vault.key();
    let bump_arr = [vault_bump];
    let seeds: &[&[u8]] = &[VAULT_SEED, creator.as_ref(), &nonce_le, &bump_arr];
    let signer_seeds: &[&[&[u8]]] = &[seeds];

    let remaining = ctx.remaining_accounts;

    // Ceremonia #37: guard de pérdida por compra (umbral sellado en la sesión
    // por restructure_init; 0 = apagado = layout pre-#37). Con guard activo:
    // [FeedRegistry, seg_0, ...] y los segmentos de COMPRA llevan las cuentas
    // de oráculo de su mint entre la ata y la ruta (los SELL van sin oráculo:
    // vender a USDC no es el vector, y el retiro nunca se estrangula).
    // Además de proteger el valor, esto evita sembrar un caché envenenado:
    // buy_usdc_in/buy_tokens_out alimentan la valoración del settle (H-4).
    let max_loss_bps = ctx.accounts.restructure_session.max_loss_bps;
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
    let mut cursor = if guard_registry.is_some() { 1usize } else { 0usize };

    for pos in 0..n {
        let kind = args.kinds[pos];
        let idx = args.indices[pos] as usize;
        let amount_in = args.amounts_in[pos];
        let plan = &args.swap_plans[pos];
        require!(kind <= 1, WagonError::RestructureLegOutOfRange);
        require!(amount_in > 0, WagonError::RestructureLegOutOfRange);

        let session = &ctx.accounts.restructure_session;
        // Ceremonia #38 (C3): el mint del leg (VENDIDO en SELL = tabla vieja;
        // COMPRADO en BUY = tabla nueva) se resuelve ANTES de cortar el segmento
        // — hace falta para saber cuántas cuentas de oráculo trae. Antes solo el
        // BUY llevaba oráculo; ahora TAMBIÉN el SELL, para poner un piso de valor
        // a la venta (un SELL con min_out=1 a un pool del creador drenaba a los
        // co-inversores sin tope — el hueco que el guard #37 dejó abierto).
        let expected_mint = if kind == 0 {
            require!(
                idx < old_count as usize,
                WagonError::RestructureLegOutOfRange
            );
            let data = vault_ai.try_borrow_data()?;
            vlayout::read_allocation_mint(&data, idx)?
        } else {
            require!(
                idx < session.new_count as usize,
                WagonError::RestructureLegOutOfRange
            );
            session.new_mints[idx]
        };
        // Ceremonia #53 (Fix 3): rechazar COMPRAR un mint que YA está en la tabla viva a
        // PESO 0. Un slot peso-0 lo SALTA `compute_tvl_m2m_strict` (#48), así que
        // financiarlo con una compra crea valor m2m-INVISIBLE que un abort deja EN la
        // tabla (fuera del alcance de `stranded_mask`, que mira presencia no peso, y de
        // `rescue_untracked_token`, que exige mint FUERA de la tabla) → un depósito acuñaría
        // de más y, al re-tabular el slot a peso>0, se materializaría la dilución. Comprar
        // un mint que persiste a peso 0 no tiene uso legítimo (para activarlo se elimina y
        // se re-añade). Un mint NUEVO (fuera de la tabla vieja) NO se ve afectado → el flujo
        // P2-3 normal sigue igual. Reusa 6179 (ZeroWeightAllocation).
        if kind == 1 {
            let mut in_old_zero_weight = false;
            {
                let data = vault_ai.try_borrow_data()?;
                for j in 0..(old_count as usize) {
                    if vlayout::read_allocation_mint(&data, j)? == expected_mint
                        && vlayout::read_allocation_weight_bps(&data, j)? == 0
                    {
                        in_old_zero_weight = true;
                        break;
                    }
                }
            }
            require!(!in_old_zero_weight, WagonError::ZeroWeightAllocation);
        }
        let oracle_len = match guard_registry {
            Some(reg) => crate::pricing::guard_oracle_account_count(reg, &expected_mint)?,
            None => 0,
        };
        let (seg, next) = crate::remaining::GuardedLegSegment::parse(
            remaining,
            cursor,
            oracle_len,
            plan.account_count as usize,
        )?;
        let mint_ai = seg.mint_ai;
        let ata_ai = seg.ata_ai;
        let route = seg.route;

        verify_mint_tier_b(mint_ai, &expected_mint)?;
        let expected_ata =
            crate::token_io::derive_live_ata(&vault_key, &expected_mint, mint_ai.owner);
        require_keys_eq!(ata_ai.key(), expected_ata, WagonError::LegDestAtaMismatch);

        let bit = 1u16 << idx;
        if kind == 0 {
            require!(
                (session.sells_done & bit) == 0,
                WagonError::RestructureLegAlreadyDone
            );
            // Vende token saliente → USDC. Medimos lo CONSUMIDO del ATA fuente
            // (before/after) para el piso; el delta es el USDC ganado.
            let src_before = crate::pricing::read_token_amount(ata_ai)?;
            let dest = &ctx.accounts.vault_usdc_ata.to_account_info();
            let usdc_mint = crate::constants::USDC_MINT;
            // C-A: declaradas = token vendido (fuente) + USDC del vault (destino).
            let declared = [ata_ai.key(), ctx.accounts.vault_usdc_ata.key()];
            let delta = invoke_jupiter_swap(
                &ctx.accounts.jupiter_program,
                dest,
                &usdc_mint,
                &vault_key,
                &vault_key,
                &declared,
                route,
                plan.ix_data.clone(),
                signer_seeds,
            )?;
            check_min_out(delta, plan.min_out)?;
            // Ceremonia #38 (C3): piso de valor de la VENTA — lo recibido (USDC)
            // debe valer ≥ valor-oráculo del token vendido × (1 − max_loss).
            // FAIL-CLOSED si el mint no tiene feed (guard_oracle_value revierte);
            // vías de escape NO estranguladas = withdraw del inversor y
            // liquidateVault del creador (ambos sin guard).
            if let Some(reg) = guard_registry {
                let src_after = crate::pricing::read_token_amount(ata_ai)?;
                let consumed = src_before
                    .checked_sub(src_after)
                    .ok_or(WagonError::MathOverflow)?;
                // Pieza 5 (C-A): error temprano legible.
                require!(consumed > 0, WagonError::SwapSourceNotConsumed);
                let dec = crate::pricing::read_mint_decimals(mint_ai)?;
                let sold_value = crate::pricing::guard_oracle_value(
                    reg,
                    &expected_mint,
                    dec,
                    consumed,
                    seg.oracle,
                    &clock,
                )?;
                crate::pricing::enforce_value_floor(delta, sold_value, max_loss_bps)?;
            }
            let session = &mut ctx.accounts.restructure_session;
            session.sells_done |= bit;
            emit!(RestructureLegExecuted {
                vault: vault_key,
                kind,
                index: idx as u8,
                amount_in,
                amount_out: delta,
            });
        } else {
            require!(
                (session.buys_done & bit) == 0,
                WagonError::RestructureLegAlreadyDone
            );
            // Compra token entrante con USDC: delta del ATA destino.
            // H-4 (auditoría 2026-06-29): el USDC consumido se MIDE en el
            // ATA del vault (before/after) — `amount_in` lo declara el
            // creador sin verificación y sembraba `buy_usdc_in` (la semilla
            // del caché de precios en el settle) a voluntad ⇒ TVL/precio de
            // share manipulables para el siguiente depositante.
            let usdc_before = crate::pricing::read_token_amount(
                &ctx.accounts.vault_usdc_ata.to_account_info(),
            )?;
            // C-A: declaradas = USDC del vault (fuente) + token comprado (destino).
            let declared = [ctx.accounts.vault_usdc_ata.key(), ata_ai.key()];
            let delta = invoke_jupiter_swap(
                &ctx.accounts.jupiter_program,
                ata_ai,
                &expected_mint,
                &vault_key,
                &vault_key,
                &declared,
                route,
                plan.ix_data.clone(),
                signer_seeds,
            )?;
            check_min_out(delta, plan.min_out)?;
            let usdc_after = crate::pricing::read_token_amount(
                &ctx.accounts.vault_usdc_ata.to_account_info(),
            )?;
            let usdc_spent = usdc_before.saturating_sub(usdc_after);
            // Pieza 5 (C-A): error temprano legible — una compra que no gasta
            // USDC no es una compra (no es seguridad; el piso ya cierra el robo).
            require!(usdc_spent > 0, WagonError::SwapSourceNotConsumed);

            // Ceremonia #37: piso de valor-oráculo del BUY — lo recibido debe
            // valer ≥ usdc_spent × (1 − max_loss). Protege el valor del vault
            // Y la semilla del caché que valorará el settle.
            if let Some(reg) = guard_registry {
                let dec = crate::pricing::read_mint_decimals(mint_ai)?;
                let received_value = crate::pricing::guard_oracle_value(
                    reg,
                    &expected_mint,
                    dec,
                    delta,
                    seg.oracle,
                    &clock,
                )?;
                crate::pricing::enforce_value_floor(received_value, usdc_spent, max_loss_bps)?;
            }

            let session = &mut ctx.accounts.restructure_session;
            session.buys_done |= bit;
            session.buy_usdc_in[idx] = session.buy_usdc_in[idx].saturating_add(usdc_spent);
            session.buy_tokens_out[idx] = session.buy_tokens_out[idx].saturating_add(delta);
            emit!(RestructureLegExecuted {
                vault: vault_key,
                kind,
                index: idx as u8,
                // H-4: reportar lo MEDIDO, no lo declarado.
                amount_in: usdc_spent,
                amount_out: delta,
            });
        }
        cursor = next;
    }
    crate::remaining::LegSegment::finish(remaining, cursor)?;
    Ok(())
}
