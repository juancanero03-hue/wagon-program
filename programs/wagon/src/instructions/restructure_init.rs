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
use anchor_spl::token::Token;

use crate::constants::*;
use crate::creator_fee;
use crate::service;
use crate::errors::WagonError;
use crate::events::{FundingRecorded, RebalanceFeeCharged, RebalanceFeeChargedUsdc, RestructureStarted, ServiceCharged};
use crate::instructions::create_vault::verify_mint_tier_b;
use crate::pricing;
use crate::state::feed_registry_layout as flayout;
use crate::state::vault_layout as vlayout;
use crate::state::{FundingRecord, ProtocolConfig, RestructureSession, ServiceConfig, FUNDING_KIND_RESTRUCTURE};

pub const RESTRUCTURE_SEED: &[u8] = b"restructure";

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct RestructureInitArgs {
    pub new_mints: Vec<Pubkey>,
    pub new_weights_bps: Vec<u16>,
    /// Ceremonia USDC §3.5: servicio S en átomos de USDC, firmado por el creador (0 sin
    /// patrocinio; obligatorio > 0 con `payer` distinto del creador; <= tope).
    pub service_usdc: u64,
}

#[derive(Accounts)]
pub struct RestructureInit<'info> {
    #[account(mut)]
    pub creator: Signer<'info>,

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
        constraint = !protocol.paused @ WagonError::ProtocolPaused,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// CHECK: PDA seeds + creator + status verificados byte-level abajo.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    #[account(
        init,
        payer = payer,
        space = RestructureSession::LEN,
        seeds = [RESTRUCTURE_SEED, vault.key().as_ref()],
        bump,
    )]
    pub restructure_session: Box<Account<'info, RestructureSession>>,

    pub system_program: Program<'info, System>,

    /// Ceremonia #46: cuenta Pyth SOL/USD (`PriceUpdateV2`) para tasar la
    /// comisión de cambio de cesta. Solo se lee si la comisión está encendida
    /// (`protocol.rebalance_fee_usd_micros > 0`). Tiene que ser la cuenta
    /// SOL/USD OFICIAL de Pyth (#56: `PYTH_PUSH_ORACLE_V2`, shard 0).
    /// CHECK: ownership, dirección, feed id, frescura y confianza se validan en
    /// el handler vía `pricing::read_sol_usd_price`.
    pub sol_usd_price_update: UncheckedAccount<'info>,

    /// Ceremonia #46: destino del SOL de la comisión (la tesorería del protocolo).
    /// CHECK: debe ser igual a `protocol.rebalance_fee_treasury`; se exige en el
    /// handler sii la comisión > 0. Ignorada (cualquier writable) si la comisión = 0.
    #[account(mut)]
    pub rebalance_fee_treasury: UncheckedAccount<'info>,

    /// Ceremonia USDC: ATA USDC canónica del creador, ORIGEN de la comisión cuando
    /// `protocol.fee_currency_mode == 1` (USDC).
    /// CHECK: derivación canónica + mint/owner en el handler (sii modo USDC y
    /// comisión > 0); ignorada (cualquier writable) en modo SOL salvo con S > 0 (§3.5).
    #[account(mut)]
    pub creator_usdc_ata: UncheckedAccount<'info>,

    /// Ceremonia USDC: tesorería USDC del protocolo, DESTINO de la comisión.
    /// CHECK: key == `protocol.treasury_usdc_ata` y PAGABLE en el handler (sii
    /// modo USDC y comisión > 0); ignorada (cualquier writable) en modo SOL salvo con S > 0 (§3.5).
    #[account(mut)]
    pub treasury_usdc_ata: UncheckedAccount<'info>,

    /// Programa SPL Token clásico para el CPI del cobro en USDC. A diferencia de
    /// las dos ATAs, Anchor lo VALIDA SIEMPRE (también en modo SOL): no admite
    /// placeholder; el cliente pasa `TOKEN_PROGRAM_ID` en todos los modos.
    pub token_program: Program<'info, Token>,

    /// Ceremonia USDC (§3.3, B3): registro de financiación de ESTA sesión en su PDA canónica
    /// `[b"funding", session]`. Se crea (pagado por `payer`) si y solo si el pagador NO es
    /// el creador (patrocinio); sin patrocinio el cliente pasa el centinela (program id) y no
    /// se crea nada: el rent vuelve al creador como siempre. Sella `kind = 3` y la generación
    /// ENTERA (u64). Si la dirección ya está ocupada por un registro rancio, el `init` falla
    /// en el System Program: `funding_reclaim_stale` lo limpia delante.
    #[account(
        init,
        payer = payer,
        space = FundingRecord::LEN,
        seeds = [FUNDING_SEED, restructure_session.key().as_ref()],
        bump,
    )]
    pub funding_record: Option<Box<Account<'info, FundingRecord>>>,

    /// CHECK: destino del reembolso del rent patrocinado (sesión + registro), elegido por el
    /// pagador y acotado en el handler a {payer, protocol.authority} y no ejecutable
    /// (`FundingRefundToNotAllowed`). Sin patrocinio se pasa el propio creador.
    pub refund_to: UncheckedAccount<'info>,

    /// Ceremonia USDC §3.5: topes y pausa del servicio S (solo lectura). Última cuenta
    /// nombrada; los `remaining` (mints nuevos + FeedRegistry) van después.
    #[account(seeds = [SERVICE_CONFIG_SEED], bump = service_config.bump)]
    pub service_config: Box<Account<'info, ServiceConfig>>,
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

    // ---- Ceremonia USDC: moneda de la comisión del creador ----------------
    // Manda SOLO `protocol.fee_currency_mode` (decisión de diseño 2026-09-22): 1 = USDC
    // desde la ATA canónica del creador a la tesorería USDC del protocolo; 0 = SOL
    // como hasta ahora (importe en micro-USD al oráculo SOL/USD). Los importes de
    // la otra moneda se IGNORAN (no se borran): nunca doble cobro (cobro cero solo
    // si el importe de la moneda activa es 0), y `mode = 0` es un rollback de UNA
    // propuesta. Un modo desconocido revierte (defensa en profundidad: el setter
    // solo escribe 0 o 1).
    let fee_mode = ctx.accounts.protocol.fee_currency_mode;
    require!(
        fee_mode == FEE_CURRENCY_MODE_SOL || fee_mode == FEE_CURRENCY_MODE_USDC,
        WagonError::InvalidFeeCurrencyParams
    );
    if fee_mode == FEE_CURRENCY_MODE_USDC {
        let amount_usdc = ctx.accounts.protocol.rebalance_fee_usdc;
        if amount_usdc > 0 {
            creator_fee::charge_creator_fee_usdc(
                &ctx.accounts.protocol,
                amount_usdc,
                &creator_fee::CreatorFeeAccounts {
                    creator: &ctx.accounts.creator.to_account_info(),
                    creator_usdc_ata: &ctx.accounts.creator_usdc_ata.to_account_info(),
                    treasury_usdc_ata: &ctx.accounts.treasury_usdc_ata.to_account_info(),
                    token_program: &ctx.accounts.token_program.to_account_info(),
                },
            )?;
            emit!(RebalanceFeeChargedUsdc {
                vault: ctx.accounts.vault.key(),
                creator: ctx.accounts.creator.key(),
                amount_usdc,
                kind: 1,
            });
        }
    }
    // ---- Ceremonia #46: comisión de cambio de cesta (1 USD en SOL) ----------
    // Mismo método que create_vault (#35): importe en ProtocolConfig (micro-USD),
    // cobrado en SOL al tipo del oráculo SOL/USD del momento. Se cobra al INICIAR
    // el cambio; 0 = apagada (cuenta viva lee 0 -> no cobra, las 2 cuentas se
    // ignoran). Atómico: si el init revierte, el SOL vuelve. La sesión NO es
    // idempotente (`#[account(init)]`), así que se cobra UNA sola vez por cambio;
    // el resume salta este init. La comisión no se devuelve si luego se aborta:
    // cobrar al init evita acoplar la finalización/desatasco al oráculo.
    let fee_usd_micros = ctx.accounts.protocol.rebalance_fee_usd_micros;
    if fee_mode == FEE_CURRENCY_MODE_SOL && fee_usd_micros > 0 {
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
    let now = Clock::get()?.unix_timestamp;
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
    session.created_at = now;
    session.bump = ctx.bumps.restructure_session;
    session.max_loss_bps = swap_max_loss_bps;
    session._reserved = [0u8; 22];

    let generation = {
        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::write_status(&mut data, 4u8 /* Restructuring */)?;
        // Ceremonia USDC (§3.4): contador del vault +1 y sello en la sesión (nunca 0).
        vlayout::bump_session_generation(&mut data)?
    };
    session.generation = generation;

    // ---- Ceremonia USDC (§3.3, B3): registro de financiación ------------------
    // Patrocinio = el pagador NO es el creador. Con patrocinio el registro es
    // OBLIGATORIO (Anchor ya lo creó; aquí se sella); sin patrocinio está PROHIBIDO
    // (el creador paga su SOL y su terminal va por legacy). `refund_to` se acota
    // siempre: con patrocinio, el pagador o `protocol.authority`; sin patrocinio SOLO
    // el propio creador. El cambio de cesta no tiene huchas (el dinero nunca sale del
    // vault): el rent temporal es la sesión + este registro, MEDIDO; `lamports_sunk` = 0.
    let payer_pk = ctx.accounts.payer.key();
    let sponsored = payer_pk != creator;
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
    if let Some(record) = ctx.accounts.funding_record.as_mut() {
        let bump = ctx
            .bumps
            .funding_record
            .ok_or(WagonError::FundingRecordNotCanonical)?;
        let session_key = ctx.accounts.restructure_session.key();
        let lamports_refundable = ctx
            .accounts
            .restructure_session
            .to_account_info()
            .lamports()
            .saturating_add(record.to_account_info().lamports());
        let refund_to = ctx.accounts.refund_to.key();
        record.session = session_key;
        record.payer = payer_pk;
        record.refund_to = refund_to;
        record.generation = generation;
        record.kind = FUNDING_KIND_RESTRUCTURE;
        record.lamports_refundable = lamports_refundable;
        record.lamports_sunk = 0;
        record.created_at = now;
        record.bump = bump;
        record.exit_service_usdc = 0; // PR 5B: solo el retiro lo usa
        record._reserved = [0u8; 8];
        emit!(FundingRecorded {
            session: session_key,
            vault: ctx.accounts.vault.key(),
            payer: payer_pk,
            refund_to,
            generation,
            kind: FUNDING_KIND_RESTRUCTURE,
            lamports_refundable,
            lamports_sunk: 0,
        });
    }

    // ---- Ceremonia USDC §3.5: servicio S (argumento firmado por el creador) ---
    // Mismo patrocinio que el registro (`payer` distinto del creador): exige S > 0; todo
    // S > 0 exige servicio activo y S <= tope. Cobro desde la cuenta USDC del creador a la
    // tesorería del protocolo (D5), atómico con el init (el resume salta este init: se
    // cobra UNA sola vez por cambio de cesta, igual que la comisión).
    {
        let cfg = &ctx.accounts.service_config;
        service::check_service(sponsored, args.service_usdc, cfg.max_for(SERVICE_KIND_RESTRUCTURE), cfg.paused)?;
        let charged = service::charge_service_usdc(
            &ctx.accounts.protocol,
            args.service_usdc,
            &service::ServiceAccounts {
                user: &ctx.accounts.creator.to_account_info(),
                user_usdc_ata: &ctx.accounts.creator_usdc_ata.to_account_info(),
                treasury_usdc_ata: &ctx.accounts.treasury_usdc_ata.to_account_info(),
                token_program: &ctx.accounts.token_program.to_account_info(),
            },
        )?;
        if charged > 0 {
            emit!(ServiceCharged {
                user: creator,
                vault: ctx.accounts.vault.key(),
                kind: SERVICE_KIND_RESTRUCTURE,
                amount_usdc: charged,
                generation,
                op_account: ctx.accounts.restructure_session.key(),
            });
        }
    }

    emit!(RestructureStarted {
        vault: ctx.accounts.vault.key(),
        creator,
        old_count,
        new_count: n as u8,
    });
    Ok(())
}
