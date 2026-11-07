//! `sweep_to_usdc` — during `Liquidating` status only. Swaps the full balance
//! of one basket token -> USDC via Jupiter. Restricted (upgrade #29) to the
//! vault creator or the protocol authority so an untrusted cranker cannot MEV
//! the liquidation; liveness holds because the protocol authority (Squads)
//! can always crank if the creator goes offline.
//!
//! Flow:
//!   1. Require vault.status() == Liquidating.
//!   2. Validate `token_index` against `vault.allocations`.
//!   3. Read the source vault token ATA balance. If 0, no-op (idempotent —
//!      retries after a successful sweep return Ok without CPI overhead).
//!   4. Execute a Jupiter CPI swap: source = vault_token_ata (full balance) →
//!      destination = vault_usdc_ata. Vault PDA signs.
//!   5. Measure delta on the vault USDC ATA; enforce `min_out`.
//!   6. Emit `SweptToUsdc` event (mint, amount_in, usdc_out).
//!
//! `vault_token_ata` is passed as an `AccountInfo` because its mint varies
//! per call. The handler verifies its key equals
//! `vault.allocations[token_index].vault_ata`, which itself was validated at
//! `create_vault` time to be an ATA owned by the vault PDA with the right mint.
//!
//! remaining_accounts layout:
//!   with the swap guard active (`swap_max_loss_bps > 0`): `[FeedRegistry, mint,
//!   ...oracle accounts of the mint (none if it is not registered), ...route]`
//!   (G2-d: the mint travels as an account, pinned by key to the allocation,
//!   so the floor reads its live `ScaledUiAmount` multiplier; until G2-d the
//!   layout had no mint);
//!   with the guard off, exactly the Jupiter route accounts required by
//!   `swap_plan.ix_data`.
//!   The destination (`vault_usdc_ata`) is a named account: `invoke_jupiter_swap`
//!   snapshots its balance for delta measurement.

use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, Token, TokenAccount};

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::SweptToUsdc;
use crate::jupiter::{check_min_out, invoke_jupiter_swap, SwapPlan};
use crate::state::{ProtocolConfig, VaultState, VaultStatus};

#[derive(Accounts)]
#[instruction(token_index: u8)]
pub struct SweepToUsdc<'info> {
    /// Crank signer. Must be the vault creator or the protocol authority
    /// (validated in the handler, upgrade #29). Pays only transaction fees.
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
        constraint = vault.status() == VaultStatus::Liquidating @ WagonError::VaultNotLiquidating,
    )]
    pub vault: Box<Account<'info, VaultState>>,

    /// Vault-owned USDC ATA (destination for the swap).
    #[account(mut, address = vault.usdc_ata)]
    pub vault_usdc_ata: Box<Account<'info, TokenAccount>>,

    /// Vault-owned ATA for the basket token being swept. Validated in the
    /// handler against `vault.allocations[token_index].vault_ata`.
    /// CHECK: validated against the allocation entry in handler.
    #[account(mut)]
    pub vault_token_ata: AccountInfo<'info>,

    /// USDC mint (needed for jupiter.rs to verify the destination ATA's mint).
    #[account(address = protocol.usdc_mint)]
    pub usdc_mint: Box<Account<'info, Mint>>,

    /// CHECK: pubkey verified against `JUPITER_PROGRAM_ID` by the CPI helper.
    #[account(address = JUPITER_PROGRAM_ID)]
    pub jupiter_program: AccountInfo<'info>,

    pub token_program: Program<'info, Token>,
}

pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, SweepToUsdc<'info>>,
    token_index: u8,
    swap_plan: SwapPlan,
) -> Result<()> {
    // ---- 1. validate slot --------------------------------------------------
    let idx = token_index as usize;
    let vault = &ctx.accounts.vault;
    require!(
        idx < vault.allocation_count as usize,
        WagonError::InvalidJupiterRoute
    );
    let alloc = vault.allocations[idx];
    require!(!alloc.is_empty(), WagonError::InvalidJupiterRoute);
    require_keys_eq!(
        ctx.accounts.vault_token_ata.key(),
        alloc.vault_ata,
        WagonError::InvalidJupiterRoute
    );

    // ---- 1b. cranker allowlist (upgrade #29, security) --------------------
    // Previously fully permissionless. We restrict cranking to the vault
    // creator or the protocol authority (Squads multisig). Without an oracle
    // we cannot compute a fair-value floor for non-stablecoin legs, so an
    // untrusted cranker could pass min_out=1 and let MEV bots sandwich the
    // liquidation. Liveness is preserved: the protocol authority is always
    // available, so liquidation cannot stall even if the creator goes offline.
    {
        let cranker = ctx.accounts.cranker.key();
        require!(
            cranker == vault.creator || cranker == ctx.accounts.protocol.authority,
            WagonError::UnauthorizedCranker
        );
    }

    // ---- 2. read current source balance (idempotent short-circuit) --------
    let amount_in: u64 = {
        let data = ctx.accounts.vault_token_ata.try_borrow_data()?;
        // SPL TokenAccount layout: mint(32) | owner(32) | amount(u64 LE, offset 64)
        require!(data.len() >= 72, WagonError::InvalidJupiterRoute);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[64..72]);
        u64::from_le_bytes(bytes)
    };
    if amount_in == 0 {
        // Nothing to sweep. Already empty (e.g. retry after a successful call,
        // or the slot had been drained by other means). Return Ok so crankers
        // can retry idempotently without reverting.
        return Ok(());
    }

    // ---- 3. Pieza 3 (S-2/H1): umbral, decimales y layout de remaining ------
    let max_loss_bps = ctx.accounts.protocol.swap_max_loss_bps;
    let authority = ctx.accounts.protocol.authority;
    let cranker = ctx.accounts.cranker.key();
    let mint = alloc.mint;

    // Decimales del token vendido, de la caché del vault (cache_alloc_decimals).
    // None = sin cachear → el piso no se podrá computar y se cae al Nivel 2.
    let decimals: Option<u8> = {
        let vault_ai = ctx.accounts.vault.to_account_info();
        let data = vault_ai.try_borrow_data()?;
        crate::state::vault_layout::read_alloc_decimals(&data, idx)?
    };

    // Con el guard vivo, remaining = [FeedRegistry, mint, ...oráculo, ...ruta] (G2-d:
    // el mint, pinned por clave a la allocation, para leer su multiplicador en vivo);
    // con el guard a 0, ruta a secas (byte a byte el layout de hoy). El conteo de
    // oráculo es TOLERANTE (None si el mint no está registrado → deslistado); la
    // PDA del registro se verifica, así que el creador no puede fingir "sin feed".
    let remaining = ctx.remaining_accounts;
    let (registry_ai, mint_ai, oracle_slice, oracle_registered, route) = if max_loss_bps > 0 {
        require!(remaining.len() >= 2, WagonError::SwapGuardAccountsMissing);
        let reg = &remaining[0];
        let mint_ai = &remaining[1];
        require_keys_eq!(mint_ai.key(), mint, WagonError::AllocMintMismatch);
        match crate::pricing::guard_oracle_account_count_opt(reg, &mint)? {
            Some(n) => {
                require!(
                    remaining.len() >= 2 + n,
                    WagonError::SwapGuardAccountsMissing
                );
                (Some(reg), Some(mint_ai), &remaining[2..2 + n], true, &remaining[2 + n..])
            }
            None => (Some(reg), Some(mint_ai), &remaining[2..2], false, &remaining[2..]),
        }
    } else {
        (None, None, &remaining[0..0], false, &remaining[..])
    };
    require!(!route.is_empty(), WagonError::InvalidJupiterRoute);

    // ---- 4. build vault PDA signer seeds ----------------------------------
    let vault_key = vault.key();
    let usdc_mint_key = ctx.accounts.usdc_mint.key();
    let creator = vault.creator;
    let nonce_le = vault.nonce.to_le_bytes();
    let vault_bump = vault.bump;
    let seeds: &[&[u8]] = &[VAULT_SEED, creator.as_ref(), &nonce_le, &[vault_bump]];
    let signer_seeds: &[&[&[u8]]] = &[seeds];

    // ---- 5. execute the CPI -----------------------------------------------
    let dest = &ctx.accounts.vault_usdc_ata.to_account_info();
    // C-A: declaradas = token vendido (fuente) + USDC del vault (destino). El
    // barrido impide que cualquier OTRA ATA del vault en la ruta pierda saldo;
    // la fuente declarada la protege el piso de valor de la Pieza 3, abajo.
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

    // ---- 6. Pieza 3: piso de valor + autorización en dos niveles ----------
    // Consumo REAL de la fuente (no el `amount_in` declarado).
    let src_after: u64 = {
        let data = ctx.accounts.vault_token_ata.try_borrow_data()?;
        require!(data.len() >= 72, WagonError::InvalidJupiterRoute);
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[64..72]);
        u64::from_le_bytes(b)
    };
    let consumed = amount_in
        .checked_sub(src_after)
        .ok_or(WagonError::MathOverflow)?;
    require!(consumed > 0, WagonError::SwapSourceNotConsumed);

    let mut floor_enforced = false;
    if max_loss_bps > 0 {
        // Nivel 1: mint con feed + decimales + oráculo legible → piso DURO
        // (creador o authority). Si algo falla, se cae al Nivel 2.
        if let (Some(reg), Some(mint_ai), true, Some(dec)) = (registry_ai, mint_ai, oracle_registered, decimals) {
            let clock = Clock::get()?;
            if let Ok(sold_value) =
                crate::pricing::guard_oracle_value(reg, mint_ai, &mint, dec, consumed, oracle_slice, &clock)
            {
                crate::pricing::enforce_value_floor(delta, sold_value, max_loss_bps)?;
                floor_enforced = true;
            }
        }
        // Nivel 2: el piso NO se puede computar (sin feed / sin decimales /
        // oráculo rancio) → solo la autoridad del protocolo puede barrer. Liveness
        // vía Squads. Si el piso se saltara dejando pasar al creador, un oráculo
        // rancio lo devolvería al punto de partida.
        if !floor_enforced {
            require!(cranker == authority, WagonError::SweepFloorNotEnforceable);
        }
    }

    // Sin piso duro (guard apagado, o Nivel 2): se conservan los controles de
    // hoy — min_out > 0 + piso de paridad para stables. Con piso duro vivo,
    // min_out = 0 es seguro (H3) y deja de atascar el barrido de polvo.
    if !floor_enforced {
        require!(swap_plan.min_out > 0, WagonError::SlippageExceeded);
    }

    // B4 (#39): el piso de PARIDAD de las stables se aplica SIEMPRE — como en el
    // #38, donde vivía al nivel superior. Meterlo bajo `!floor_enforced` AFLOJABA
    // la cota justo en el caso más medible del protocolo: el piso de paridad
    // (`vault.max_slippage_bps`, como mucho MAX_SLIPPAGE_BPS = 500) y el piso de valor
    // del guard (valor vivo de ProtocolConfig, tope 2000) son independientes y el del
    // guard puede ser más ancho, así que sustituir uno por otro aflojaba la cota sobre
    // las stables a costa de los co-inversores. Se aplica
    // el MÁS ESTRICTO de los dos, no uno u otro. No estrangula el polvo: con
    // amount_in pequeño el floor cae a 0 por división entera.
    if STABLECOIN_USD_MINTS_6DEC.contains(&mint) {
        let max_slip = vault.max_slippage_bps as u128;
        let floor = (amount_in as u128)
            .saturating_mul((BPS_DENOMINATOR as u128).saturating_sub(max_slip))
            .saturating_div(BPS_DENOMINATOR as u128) as u64;
        require!(swap_plan.min_out >= floor, WagonError::SlippageExceeded);
    }
    check_min_out(delta, swap_plan.min_out)?;

    // ---- 5. emit event ----------------------------------------------------
    emit!(SweptToUsdc {
        vault: vault.key(),
        token_index,
        mint: alloc.mint,
        amount_in,
        usdc_out: delta,
    });

    Ok(())
}
