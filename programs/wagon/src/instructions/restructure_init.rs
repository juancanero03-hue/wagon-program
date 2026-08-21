//! `restructure_init` — upgrade #31, paso 1 del cambio de estrategia.
//!
//! El creador declara la cesta objetivo (mints + pesos). Se validan los
//! mints nuevos con Tier B (mismas reglas que create_vault), se crea la
//! `RestructureSession` y el vault pasa a `Restructuring` (status 4):
//! deposits, withdraws y rebalances quedan bloqueados hasta settle/abort.
//!
//! remaining_accounts: el mint account de CADA mint nuevo, en el mismo
//! orden que `args.new_mints` (para la verificación Tier B en vivo).

use anchor_lang::prelude::*;
use anchor_lang::system_program::{transfer, Transfer};

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::{RebalanceFeeCharged, RestructureStarted};
use crate::instructions::create_vault::verify_mint_tier_b;
use crate::pricing;
use crate::state::feed_registry_layout as flayout;
use crate::state::vault_layout as vlayout;
use crate::state::{ProtocolConfig, RestructureSession};

pub const RESTRUCTURE_SEED: &[u8] = b"restructure";

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct RestructureInitArgs {
    pub new_mints: Vec<Pubkey>,
    pub new_weights_bps: Vec<u16>,
}

#[derive(Accounts)]
pub struct RestructureInit<'info> {
    #[account(mut)]
    pub creator: Signer<'info>,

    #[account(
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        constraint = !protocol.paused @ WagonError::ProtocolPaused,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// CHECK: PDA seeds + creator + status verificados byte-level abajo.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    #[account(
        init,
        payer = creator,
        space = RestructureSession::LEN,
        seeds = [RESTRUCTURE_SEED, vault.key().as_ref()],
        bump,
    )]
    pub restructure_session: Box<Account<'info, RestructureSession>>,

    pub system_program: Program<'info, System>,

    /// Ceremonia #46: cuenta Pyth SOL/USD (`PriceUpdateV2`) para tasar la
    /// comisión de cambio de cesta. Solo se lee si la comisión está encendida
    /// (`protocol.rebalance_fee_usd_micros > 0`).
    /// CHECK: ownership, feed id, frescura y confianza se validan en el handler
    /// vía `pricing::read_sol_usd_price`.
    pub sol_usd_price_update: UncheckedAccount<'info>,

    /// Ceremonia #46: destino del SOL de la comisión (la tesorería del protocolo).
    /// CHECK: debe ser igual a `protocol.rebalance_fee_treasury`; se exige en el
    /// handler sii la comisión > 0. Ignorada (cualquier writable) si la comisión = 0.
    #[account(mut)]
    pub rebalance_fee_treasury: UncheckedAccount<'info>,
}

pub fn handler(ctx: Context<RestructureInit>, args: RestructureInitArgs) -> Result<()> {
    let vault_ai = ctx.accounts.vault.to_account_info();
    let guard = crate::guards::VaultGuard::load_active(
        &vault_ai,
        &ctx.accounts.vault.key(),
        WagonError::VaultPaused,
    )?;
    let (creator, nonce, vault_bump, status) =
        (guard.creator, guard.nonce, guard.bump, guard.status);
    let nonce_le = nonce.to_le_bytes();
    let old_count = {
        let data = vault_ai.try_borrow_data()?;
        // Ceremonia #43 (OT-1): no reestructurar con un depósito COMPROMETIDO sin
        // asentar — su valor entraría en la contabilidad de la cesta nueva sin
        // participaciones que lo representen. No congela: el depósito se drena por
        // deposit_settle (permissionless, exige Active, que este candado preserva).
        require!(
            vlayout::read_committed_deposits(&data)? == 0,
            WagonError::VaultHasCommittedDeposit
        );
        // Ceremonia #53: no reestructurar con VALOR FUERA DE TABLA pendiente. Cierra
        // la re-tabulación (que dejaría el contador/manifiesto descuadrado) y evita
        // crear MÁS strand encima de uno vivo → P2-3 y P2-4 quedan mutuamente
        // excluyentes. Defensa en profundidad: un abort con compras varadas deja la
        // RestructureSession ABIERTA, y su PDA `init` ya colisiona aquí.
        require!(
            vlayout::read_stranded_flag(&data)? == 0,
            WagonError::VaultHasStrandedValue
        );
        vlayout::read_allocation_count(&data)?
    };
    require_keys_eq!(
        creator,
        ctx.accounts.creator.key(),
        WagonError::UnauthorizedVaultCreator
    );

    // ---- Cesta nueva --------------------------------------------------------
    // F6 (ceremonia #40): la cesta NUEVA se mide contra el tope EFECTIVO (7), no
    // contra el de almacenamiento (10). Sin esto, el camino de create_vault
    // quedaba capado pero este no, y bastaba reestructurar para fabricar un
    // vault de 8-10 patas cuyo retiro no cabe en una transacción.
    let n = args.new_mints.len();
    require!(
        n >= 1
            && n <= crate::constants::MAX_TOKENS_PER_VAULT_EFFECTIVE
            && args.new_weights_bps.len() == n,
        WagonError::RestructureBadBasket
    );
    let sum: u32 = args.new_weights_bps.iter().map(|w| *w as u32).sum();
    require!(
        sum == BPS_DENOMINATOR as u32,
        WagonError::AllocationSumMismatch
    );
    // Ceremonia #47 (H3): ninguna pata de la cesta NUEVA a peso 0. Este es uno de
    // los dos guardas reales de H3 (el otro es `rebalance`): cierra la vía del mint
    // que PERSISTE en la cesta a peso 0 con saldo (restructure_settle copia estos
    // pesos sin re-chequear) → withdraw_init lo saltaría como trivial y el que retira
    // perdería su parte = confiscación. El vec solo lleva las n patas pobladas; el
    // peso 0 a un slot vacío i>=n (restructure_settle) es un slot genuinamente
    // vacío y no pasa por aquí. `create_vault` NO chequea (una pata creada a 0 nunca
    // se financia; ver el comentario allí).
    for w in args.new_weights_bps.iter() {
        require!(*w >= 1, WagonError::ZeroWeightAllocation);
    }
    for i in 0..n {
        for j in (i + 1)..n {
            require!(
                args.new_mints[i] != args.new_mints[j],
                WagonError::DuplicateToken
            );
        }
    }
    // Tier B en vivo para cada mint nuevo (mismas reglas que create_vault).
    // Ceremonia #42 (pieza D): además de las N cuentas de mint se exige el
    // FeedRegistry al final (remaining[N]) para comprobar el bit 3 «sin oráculo
    // utilizable». Cierra el hueco que la propia #41 dejó dicho: create_vault ya
    // miraba el bit 3, pero ESTE camino no, así que se podía crear con una cesta
    // buena y reestructurar hacia un token que el programa no sabe preciar.
    // Convención (idéntica a create_vault): remaining[0..N] = mints; remaining[N]
    // = FeedRegistry PDA.
    require!(
        ctx.remaining_accounts.len() == n + 1,
        WagonError::AllocMintMismatch
    );
    for (i, mint_ai) in ctx.remaining_accounts.iter().take(n).enumerate() {
        verify_mint_tier_b(mint_ai, &args.new_mints[i])?;
    }
    // FeedRegistry al final: address + ownership pineados (misma receta que
    // create_vault), lectura byte-a-byte (ADR 0004, nunca try_deserialize). Cada
    // mint no-USDC debe estar en el registro y SIN el bit 3.
    let usdc_mint_pk = ctx.accounts.protocol.usdc_mint;
    let registry_ai = &ctx.remaining_accounts[n];
    let (expected_registry, _) =
        Pubkey::find_program_address(&[FEED_REGISTRY_SEED], &crate::ID);
    require_keys_eq!(
        registry_ai.key(),
        expected_registry,
        WagonError::VaultMintNotInFeedRegistry
    );
    require_keys_eq!(
        *registry_ai.owner,
        crate::ID,
        WagonError::VaultMintNotInFeedRegistry
    );
    let registry_data = registry_ai.try_borrow_data()?;
    for mint in args.new_mints.iter() {
        if *mint == usdc_mint_pk {
            continue;
        }
        let idx = flayout::find(&registry_data, mint)?
            .ok_or(WagonError::VaultMintNotInFeedRegistry)?;
        let flags = flayout::read_entry_flags(&registry_data, idx)?;
        require!(
            flags & crate::state::feed_registry::FEED_FLAG_NO_ORACLE == 0,
            WagonError::VaultMintNotInFeedRegistry
        );
    }
    // Suelta el borrow del FeedRegistry antes del CPI de cobro. Defensivo: el
    // transfer toca creator/treasury/system_program (disjuntos del registry PDA),
    // así que no hay conflicto de borrow; pero no dependemos de esa disjunción.
    drop(registry_data);

    // ---- Ceremonia #46: comisión de cambio de cesta (1 USD en SOL) ----------
    // Mismo método que create_vault (#35): importe en ProtocolConfig (micro-USD),
    // cobrado en SOL al tipo del oráculo SOL/USD del momento. Se cobra al INICIAR
    // el cambio; 0 = apagada (cuenta viva lee 0 -> no cobra, las 2 cuentas se
    // ignoran). Atómico: si el init revierte, el SOL vuelve. La sesión NO es
    // idempotente (`#[account(init)]`), así que se cobra UNA sola vez por cambio;
    // el resume salta este init. El $1 se pierde si luego se aborta (equidad,
    // declarado): cobrar al init evita acoplar la finalización/desatasco al oráculo.
    let fee_usd_micros = ctx.accounts.protocol.rebalance_fee_usd_micros;
    if fee_usd_micros > 0 {
        let expected_treasury = ctx.accounts.protocol.rebalance_fee_treasury;
        require_keys_neq!(
            expected_treasury,
            Pubkey::default(),
            WagonError::RebalanceFeeTreasuryMismatch
        );
        require_keys_eq!(
            ctx.accounts.rebalance_fee_treasury.key(),
            expected_treasury,
            WagonError::RebalanceFeeTreasuryMismatch
        );
        let fee_clock = Clock::get()?;
        let sol = pricing::read_sol_usd_price(
            &ctx.accounts.sol_usd_price_update.to_account_info(),
            &fee_clock,
        )?;
        let lamports = pricing::usd_micros_to_lamports(fee_usd_micros, &sol)?
            .min(VAULT_CREATION_FEE_MAX_LAMPORTS);
        if lamports > 0 {
            transfer(
                CpiContext::new(
                    ctx.accounts.system_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.creator.to_account_info(),
                        to: ctx.accounts.rebalance_fee_treasury.to_account_info(),
                    },
                ),
                lamports,
            )?;
            emit!(RebalanceFeeCharged {
                vault: ctx.accounts.vault.key(),
                creator: ctx.accounts.creator.key(),
                lamports,
                fee_usd_micros,
            });
        }
    }

    // ---- Sesión + pausa -----------------------------------------------------
    // Ceremonia #37: sellar el umbral del guard de pérdida por compra (los
    // swap_batch no llevan la cuenta protocol; sesiones pre-encendido = 0).
    let swap_max_loss_bps = ctx.accounts.protocol.swap_max_loss_bps;
    let session = &mut ctx.accounts.restructure_session;
    session.creator = creator;
    session.vault = ctx.accounts.vault.key();
    session.new_count = n as u8;
    session.new_mints = [Pubkey::default(); MAX_TOKENS_PER_VAULT];
    session.new_weights_bps = [0u16; MAX_TOKENS_PER_VAULT];
    for i in 0..n {
        session.new_mints[i] = args.new_mints[i];
        session.new_weights_bps[i] = args.new_weights_bps[i];
    }
    session.sells_done = 0;
    session.buys_done = 0;
    session.buy_usdc_in = [0u64; MAX_TOKENS_PER_VAULT];
    session.buy_tokens_out = [0u64; MAX_TOKENS_PER_VAULT];
    session.created_at = Clock::get()?.unix_timestamp;
    session.bump = ctx.bumps.restructure_session;
    session.max_loss_bps = swap_max_loss_bps;
    session._reserved = [0u8; 30];

    {
        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::write_status(&mut data, 4u8 /* Restructuring */)?;
    }

    emit!(RestructureStarted {
        vault: ctx.accounts.vault.key(),
        creator,
        old_count,
        new_count: n as u8,
    });
    Ok(())
}
