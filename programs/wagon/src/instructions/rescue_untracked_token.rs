//! `rescue_untracked_token` — ceremonia #39 (C-A, Pieza 4).
//!
//! Vende a USDC un token account propiedad del vault cuyo mint NO está en la
//! tabla de allocations. Ese estado es alcanzable HOY (crítico pre-existente): un
//! BUY de restructure deja el token comprado, luego `restructure_abort`
//! (permissionless a los 1800 s) lo deja FUERA DE TABLA e inalcanzable por todos
//! los demás caminos (rebalance/sweep exigen índice de tabla; el SELL indexa la
//! tabla vieja; withdraw solo recorre 0..allocation_count). El barrido de C-A no
//! lo crea, pero sí lo convierte en consecuencia rutinaria, así que hace falta
//! una salida.
//!
//! El producto aterriza en `vault_usdc_ata`, que SÍ es valor repartible: el
//! settle del restructure lo cuenta como TVL y el withdraw reparte el USDC ocioso
//! pro-rata a cada inversor que sale. Cierra además el griefing pre-existente del
//! abort permissionless SIN tocar `restructure_abort` (la escotilla que nunca
//! bloquea) ni `VaultState`.
//!
//! Autorización idéntica a `sweep_to_usdc` (Pieza 3, dos niveles): mint con feed
//! + oráculo legible → creador o `protocol.authority` con piso DURO; sin feed u
//! oráculo ilegible → solo `protocol.authority` con `min_out > 0`.

use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, Token, TokenAccount};

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::UntrackedTokenRescued;
use crate::jupiter::{check_min_out, invoke_jupiter_swap, SwapPlan};
use crate::state::{ProtocolConfig, VaultState, VaultStatus};

#[derive(Accounts)]
pub struct RescueUntrackedToken<'info> {
    /// Crank signer. Creador o `protocol.authority` (validado en el handler
    /// según si el piso es computable). Paga solo fees de transacción.
    pub cranker: Signer<'info>,

    #[account(seeds = [PROTOCOL_SEED], bump = protocol.bump)]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    #[account(
        mut,
        seeds = [
            VAULT_SEED,
            vault.creator.as_ref(),
            &vault.nonce.to_le_bytes(),
        ],
        bump = vault.bump,
    )]
    pub vault: Box<Account<'info, VaultState>>,

    /// ATA del vault del token a rescatar. Validada en el handler
    /// (derive_live_ata + verify_token_account + NO en la tabla).
    /// CHECK: validada en el handler.
    #[account(mut)]
    pub vault_token_ata: AccountInfo<'info>,

    /// USDC ATA del vault (destino).
    #[account(mut, address = vault.usdc_ata)]
    pub vault_usdc_ata: Box<Account<'info, TokenAccount>>,

    /// Mint del token a rescatar. `AccountInfo` para aceptar SPL clásico Y
    /// Token-2022 (los xStocks). CHECK: owner = programa de tokens y decimales
    /// verificados en el handler.
    /// CHECK: verificado en el handler.
    pub token_mint: AccountInfo<'info>,

    /// USDC mint (para que jupiter.rs verifique el mint del destino).
    #[account(address = protocol.usdc_mint)]
    pub usdc_mint: Box<Account<'info, Mint>>,

    /// CHECK: pubkey verificada contra `JUPITER_PROGRAM_ID` por el helper de CPI.
    #[account(address = JUPITER_PROGRAM_ID)]
    pub jupiter_program: AccountInfo<'info>,

    pub token_program: Program<'info, Token>,
}

pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, RescueUntrackedToken<'info>>,
    swap_plan: SwapPlan,
) -> Result<()> {
    let vault = &ctx.accounts.vault;

    // ---- Gate 1: NO durante un restructure en vuelo -----------------------
    // Ahí esos tokens son trabajo en curso, no residuo; venderlos descuadraría
    // el balance que `restructure_settle` escribe en la tabla. Funciona en
    // Active, Paused y Liquidating — donde vive el problema.
    require!(
        vault.status() != VaultStatus::Restructuring,
        WagonError::RestructuringInProgress
    );

    let mint = ctx.accounts.token_mint.key();

    // ---- Gate 2: el mint NO está en la tabla y NO es USDC -----------------
    // Es lo que impide usar esta instrucción para esquivar el guard de
    // `rebalance_swap` (vender un token de la cesta sin piso).
    require!(mint != USDC_MINT, WagonError::MintStillInAllocations);
    for i in 0..(vault.allocation_count as usize) {
        require!(
            vault.allocations[i].mint != mint,
            WagonError::MintStillInAllocations
        );
    }

    // El token_mint debe ser un mint real (owner = un programa de tokens).
    let token_prog = *ctx.accounts.token_mint.owner;
    const T22: Pubkey =
        anchor_lang::solana_program::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
    require!(
        token_prog == anchor_spl::token::spl_token::ID || token_prog == T22,
        WagonError::InvalidJupiterRoute
    );

    // ---- Gate 3: la ATA es la canónica del vault para este mint -----------
    let vault_key = vault.key();
    let expected_ata = crate::token_io::derive_live_ata(&vault_key, &mint, &token_prog);
    require_keys_eq!(
        ctx.accounts.vault_token_ata.key(),
        expected_ata,
        WagonError::InvalidJupiterRoute
    );
    crate::token_io::verify_token_account(&ctx.accounts.vault_token_ata, &mint, &vault_key)?;

    // ---- Gate 4: allowlist del cranker (NIVEL 1, INCONDICIONAL) -----------
    // Espejo EXACTO de sweep_to_usdc (Pieza 3). Va aquí, ANTES de cualquier CPI.
    // Sin esto la instrucción es permissionless: con el guard vivo y un mint con
    // feed, `floor_enforced` es true y el require! de Nivel 2 (más abajo) NUNCA
    // se evalúa → un tercero cualquiera podía forzar la venta del residuo contra
    // su propio pool y capturar hasta `max_loss_bps` sobre un vault ACTIVO con
    // inversores dentro; y con el guard a 0 (palanca de rollback) no quedaba ni
    // piso ni firmante. Liveness intacta: la authority (Squads) siempre puede
    // crankear aunque el creador desaparezca.
    let authority = ctx.accounts.protocol.authority;
    let cranker = ctx.accounts.cranker.key();
    require!(
        cranker == vault.creator || cranker == authority,
        WagonError::UnauthorizedCranker
    );

    // ---- balance fuente (idempotente: si 0, no-op) ------------------------
    let amount_in = crate::pricing::read_token_amount(&ctx.accounts.vault_token_ata)?;
    if amount_in == 0 {
        return Ok(());
    }

    // Decimales DIRECTOS del mint (a diferencia de sweep, aquí el Mint está en el
    // struct; read_mint_decimals maneja clásico y Token-2022).
    let decimals = crate::pricing::read_mint_decimals(&ctx.accounts.token_mint)?;
    let max_loss_bps = ctx.accounts.protocol.swap_max_loss_bps;

    // ---- layout de remaining (idéntico a sweep) ---------------------------
    let remaining = ctx.remaining_accounts;
    let (registry_ai, oracle_slice, oracle_registered, route) = if max_loss_bps > 0 {
        require!(!remaining.is_empty(), WagonError::SwapGuardAccountsMissing);
        let reg = &remaining[0];
        match crate::pricing::guard_oracle_account_count_opt(reg, &mint)? {
            Some(n) => {
                require!(
                    remaining.len() >= 1 + n,
                    WagonError::SwapGuardAccountsMissing
                );
                (Some(reg), &remaining[1..1 + n], true, &remaining[1 + n..])
            }
            None => (Some(reg), &remaining[1..1], false, &remaining[1..]),
        }
    } else {
        (None, &remaining[0..0], false, &remaining[..])
    };
    require!(!route.is_empty(), WagonError::InvalidJupiterRoute);

    // ---- signer seeds del vault -------------------------------------------
    let usdc_mint_key = ctx.accounts.usdc_mint.key();
    let creator = vault.creator;
    let nonce_le = vault.nonce.to_le_bytes();
    let vault_bump = vault.bump;
    let seeds: &[&[u8]] = &[VAULT_SEED, creator.as_ref(), &nonce_le, &[vault_bump]];
    let signer_seeds: &[&[&[u8]]] = &[seeds];

    // ---- CPI (con barrido de la Pieza 1) ----------------------------------
    let dest = &ctx.accounts.vault_usdc_ata.to_account_info();
    let declared = [
        ctx.accounts.vault_token_ata.key(),
        ctx.accounts.vault_usdc_ata.key(),
    ];
    let delta = invoke_jupiter_swap(
        &ctx.accounts.jupiter_program,
        dest,
        &usdc_mint_key,
        &vault_key,
        &vault_key,
        &declared,
        route,
        swap_plan.ix_data,
        signer_seeds,
    )?;

    // ---- Pieza 3 (dos niveles): piso de valor + autorización --------------
    let src_after = crate::pricing::read_token_amount(&ctx.accounts.vault_token_ata)?;
    let consumed = amount_in
        .checked_sub(src_after)
        .ok_or(WagonError::MathOverflow)?;
    require!(consumed > 0, WagonError::SwapSourceNotConsumed);

    let mut floor_enforced = false;
    if max_loss_bps > 0 {
        if let (Some(reg), true) = (registry_ai, oracle_registered) {
            let clock = Clock::get()?;
            if let Ok(sold_value) =
                crate::pricing::guard_oracle_value(reg, &mint, decimals, consumed, oracle_slice, &clock)
            {
                crate::pricing::enforce_value_floor(delta, sold_value, max_loss_bps)?;
                floor_enforced = true;
            }
        }
        if !floor_enforced {
            require!(cranker == authority, WagonError::SweepFloorNotEnforceable);
        }
    }
    if !floor_enforced {
        require!(swap_plan.min_out > 0, WagonError::SlippageExceeded);
    }
    check_min_out(delta, swap_plan.min_out)?;

    emit!(UntrackedTokenRescued {
        vault: vault_key,
        mint,
        amount_in,
        usdc_out: delta,
        floor_enforced,
    });

    Ok(())
}
