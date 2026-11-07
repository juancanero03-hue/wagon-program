//! Wagon — Solana vault marketplace program.
//!
//! See README.md for architecture, fee model, lifecycle, and roadmap.
//!
//! Module map:
//!   - constants    — protocol-wide constants, PDA seeds, fee bounds.
//!   - errors       — `WagonError` enum (stable numbering).
//!   - events       — Anchor events emitted by handlers.
//!   - jupiter      — Jupiter v6 CPI helper (`SwapPlan`, `invoke_jupiter_swap`).
//!   - pricing      — upgrade #30: last-swap price cache + m2m valuation utils.
//!   - state        — account definitions (ProtocolConfig, VaultState, UserPosition).
//!   - funding      — ceremonia USDC §3.3: E/S del `FundingRecord` (rent patrocinado).
//!   - instructions — one module per entrypoint, all re-exported below.

use anchor_lang::prelude::*;

// Contacto de seguridad embebido en el binario: el estándar `security_txt!` que muestran los
// exploradores de Solana. Mismo contacto y política que `https://wagon.tech/.well-known/security.txt`.
// Solo en el programa desplegado, no cuando otro programa lo usa como dependencia (CPI).
#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "Wagon",
    project_url: "https://wagon.tech",
    contacts: "email:admin@wagon.tech",
    policy: "https://wagon.tech/.well-known/security.txt",
    preferred_languages: "es,en",
    source_code: "https://github.com/juancanero03-hue/wagon-program"
}

#[cfg(all(test, not(feature = "no-entrypoint")))]
mod security_txt_tests {
    /// Los campos que leen los exploradores, en el formato del estándar (clave\0valor\0) y entre sus
    /// marcadores. Si alguien cambia el contacto o la política, este test obliga a hacerlo a propósito.
    #[test]
    fn el_contacto_de_seguridad_va_embebido_y_completo() {
        // 1.1.2 nombra la estática en mayúsculas (la 1.1.1 la llamaba `security_txt`).
        let s = crate::SECURITY_TXT;
        assert!(s.starts_with("=======BEGIN SECURITY.TXT V1=======\0"));
        assert!(s.ends_with("=======END SECURITY.TXT V1=======\0"));
        for campo in [
            "name\0Wagon\0",
            "project_url\0https://wagon.tech\0",
            "contacts\0email:admin@wagon.tech\0",
            "policy\0https://wagon.tech/.well-known/security.txt\0",
            "source_code\0https://github.com/juancanero03-hue/wagon-program\0",
        ] {
            assert!(s.contains(campo), "falta {campo:?}");
        }
    }
}

pub mod constants;
pub mod errors;
pub mod events;
pub mod instructions;
pub mod jupiter;
pub mod metaplex;
pub mod state;
pub mod pricing;
pub mod guards;
pub mod token_io;
pub mod remaining;
pub mod creator_fee;
pub mod entry_fee;
pub mod funding;
pub mod escrow_rent;
pub mod service;
pub mod vault_table;

use instructions::*;

// Program ID. Fresh keypair generated 2026-04-24; the same id on devnet and
// mainnet-beta. Source keypair stored outside the repo. The mainnet upgrade
// authority is the Squads multisig vault (Wagon Protocol, 2-of-3).
declare_id!("2kZqCjGfKgVR8dUkv4PCogFsFgN3EoSSNX41HN1cBfBA");

#[program]
pub mod wagon {
    use super::*;

    // ---- init / lifecycle ---------------------------------------------------

    pub fn initialize_protocol(ctx: Context<InitializeProtocol>) -> Result<()> {
        instructions::initialize::handler(ctx)
    }

    pub fn create_vault(ctx: Context<CreateVault>, args: CreateVaultArgs) -> Result<()> {
        instructions::create_vault::handler(ctx, args)
    }

    // ---- investor actions (Capa 5: fractional deposit/withdraw) ------------
    //
    // The legacy monolithic `deposit` and `withdraw` were retired in upgrade
    // #20. Each high-level action is now driven by 4 entrypoints:
    //   init       → lock funds, snapshot state, create session PDA
    //   swap_batch → run 1-3 Jupiter swaps (called N times until all legs done)
    //   settle     → finalise (mint/transfer/burn shares), close session
    //   abort      → rollback (each abort instruction documents when it applies)
    //
    // The frontend assembles the sequence and submits all txs in a single
    // `signAllTransactions` so the user sees one wallet approval.

    pub fn deposit_init(ctx: Context<DepositInit>, args: DepositInitArgs) -> Result<()> {
        instructions::deposit_init::handler(ctx, args)
    }

    pub fn deposit_swap_batch<'info>(
        ctx: Context<'_, '_, '_, 'info, DepositSwapBatch<'info>>,
        args: DepositSwapBatchArgs,
    ) -> Result<()> {
        instructions::deposit_swap_batch::handler(ctx, args)
    }

    /// Upgrade #31 (F2b): drains session escrow ATAs — to the vault once
    /// all swaps completed (permissionless), or back to the investor on
    /// the abort path (investor any time; anyone after 10 min).
    pub fn deposit_sweep_batch<'info>(
        ctx: Context<'_, '_, '_, 'info, DepositSweepBatch<'info>>,
        args: DepositSweepBatchArgs,
    ) -> Result<()> {
        instructions::deposit_sweep_batch::handler(ctx, args)
    }

    pub fn deposit_settle(ctx: Context<DepositSettle>) -> Result<()> {
        instructions::deposit_settle::handler(ctx)
    }

    pub fn deposit_abort(ctx: Context<DepositAbort>) -> Result<()> {
        instructions::deposit_abort::handler(ctx)
    }

    /// Ceremonia #50 (A5): salida fail-open del contador de comprometidas ante
    /// un freeze externo que atasca el asiento. Permissionless, CERO CPI.
    pub fn deposit_force_release(
        ctx: Context<DepositForceRelease>,
        args: DepositForceReleaseArgs,
    ) -> Result<()> {
        instructions::deposit_force_release::handler(ctx, args)
    }

    /// DT-E / G2-c: estira una `DepositSession` de un tamaño anterior del layout (457 o 473 B) a `LEN` (601 B) con los campos nuevos a 0.
    pub fn deposit_session_migrate(ctx: Context<DepositSessionMigrate>) -> Result<()> {
        instructions::deposit_session_migrate::handler(ctx)
    }

    /// DT-E: devuelve al inversor lo que un settle dejó en la hucha de una sesión ya cerrada.
    pub fn deposit_escrow_reclaim(ctx: Context<DepositEscrowReclaim>) -> Result<()> {
        instructions::deposit_escrow_reclaim::handler(ctx)
    }

    pub fn withdraw_init<'info>(
        ctx: Context<'_, '_, '_, 'info, WithdrawInit<'info>>,
        args: WithdrawInitArgs,
    ) -> Result<()> {
        instructions::withdraw_init::handler(ctx, args)
    }

    pub fn withdraw_swap_batch<'info>(
        ctx: Context<'_, '_, '_, 'info, WithdrawSwapBatch<'info>>,
        args: WithdrawSwapBatchArgs,
    ) -> Result<()> {
        instructions::withdraw_swap_batch::handler(ctx, args)
    }

    /// C2 (ceremonia #38): drains the withdraw session's per-token escrows back
    /// to the vault — settle direction once every leg sold (permissionless), or
    /// abort direction returning the unsold slices (investor any time; anyone
    /// after `WITHDRAW_ORPHAN_ABORT_SECS`, 48 h, or after `WITHDRAW_ABORT_FINISH_SECS`,
    /// 10 min, once the session is already cancelling). `withdraw_settle` /
    /// `withdraw_abort` then finish.
    pub fn withdraw_sweep_batch<'info>(
        ctx: Context<'_, '_, '_, 'info, WithdrawSweepBatch<'info>>,
        args: WithdrawSweepBatchArgs,
    ) -> Result<()> {
        instructions::withdraw_sweep_batch::handler(ctx, args)
    }

    /// Ceremonia #39 (C-B): paga EN ESPECIE al inversor una pata de retiro que no
    /// se puede vender (sustituye a la renuncia). Da salida a sesiones
    /// comprometidas sin depender del vault ni del creador.
    pub fn withdraw_claim_leg_in_kind<'info>(
        ctx: Context<'_, '_, '_, 'info, WithdrawClaimLegInKind<'info>>,
        args: WithdrawClaimLegInKindArgs,
    ) -> Result<()> {
        instructions::withdraw_claim_leg_in_kind::handler(ctx, args)
    }

    pub fn withdraw_settle(ctx: Context<WithdrawSettle>) -> Result<()> {
        instructions::withdraw_settle::handler(ctx)
    }

    pub fn withdraw_abort(ctx: Context<WithdrawAbort>) -> Result<()> {
        instructions::withdraw_abort::handler(ctx)
    }

    /// G3 (F2A-03): permissionless — sweeps into the vault the USDC a CLOSED withdraw
    /// session left in its escrow (the vault's USDC ATA could not receive it at settle)
    /// and closes that escrow (rent to the investor).
    pub fn withdraw_escrow_sweep(ctx: Context<WithdrawEscrowSweep>) -> Result<()> {
        instructions::withdraw_escrow_sweep::handler(ctx)
    }

    /// G3-B1b (DT-A(b)): permissionless, fail-closed — cierra sin re-acuñar un retiro atascado por una cuenta
    /// congelada (prueba ligada a la cuenta exacta, inversor 24 h / tercero 48 h) y re-tipa la sesión en su sitio
    /// como recibo de derecho (`WithdrawRight`) con las huchas que siguen abiertas para el inversor.
    pub fn withdraw_force_release(
        ctx: Context<WithdrawForceRelease>,
        args: WithdrawForceReleaseArgs,
    ) -> Result<()> {
        instructions::withdraw_force_release::handler(ctx, args)
    }

    /// G3-B1b: permissionless — cobra una hucha pendiente de un recibo de derecho hacia la cuenta canónica del
    /// inversor (creándola si falta, pagada por el rent de la hucha) y cierra el recibo con la última.
    pub fn withdraw_escrow_claim(
        ctx: Context<WithdrawEscrowClaim>,
        args: WithdrawEscrowClaimArgs,
    ) -> Result<()> {
        instructions::withdraw_escrow_claim::handler(ctx, args)
    }

    /// #56: permissionless — crea, amplía o rota la tabla de direcciones del vault (autoridad: la PDA
    /// [b"vault-table", vault]) con las direcciones que el programa saca del propio vault; paga el firmante.
    pub fn vault_table_sync<'info>(
        ctx: Context<'_, '_, '_, 'info, VaultTableSync<'info>>,
        recent_slot: u64,
    ) -> Result<()> {
        instructions::vault_table_sync::handler(ctx, recent_slot)
    }

    /// Creator claims accrued entry-fee rewards from their per-creator rewards
    /// vault into their wallet (accrue-and-claim, pump.fun-style).
    pub fn claim_creator_rewards(ctx: Context<ClaimCreatorRewards>) -> Result<()> {
        instructions::claim_creator_rewards::handler(ctx)
    }

    // ---- creator actions ----------------------------------------------------

    pub fn rebalance(
        ctx: Context<Rebalance>,
        new_mints: Vec<Pubkey>,
        new_weights_bps: Vec<u16>,
        service_usdc: u64,
    ) -> Result<()> {
        instructions::rebalance::handler(ctx, new_mints, new_weights_bps, service_usdc)
    }

    pub fn rebalance_swap<'info>(
        ctx: Context<'_, '_, '_, 'info, RebalanceSwapCtx<'info>>,
        source_index: u8,
        dest_index: u8,
        swap_plan: jupiter::SwapPlan,
    ) -> Result<()> {
        instructions::rebalance_swap::handler(ctx, source_index, dest_index, swap_plan)
    }

    pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
        instructions::close_vault::handler(ctx)
    }

    /// Ceremonia USDC, D8: escribe la descripción y/o los tags de un vault Active,
    /// creator-only, con escritura única POR CAMPO y ventana de publicación de 24 h
    /// desde `created_at`: cadena vacía (o solo NUL) = no tocar ese campo; las dos
    /// vacías = VaultTextsEmpty; mismo contenido que el guardado = no-op sin evento
    /// (también fuera de la ventana); contenido distinto en un campo ya escrito =
    /// VaultTextsAlreadySet; cualquier escritura fuera de la ventana =
    /// VaultTextsWindowClosed.
    pub fn set_vault_texts(
        ctx: Context<SetVaultTexts>,
        description: String,
        tags: String,
    ) -> Result<()> {
        instructions::set_vault_texts::handler(ctx, description, tags)
    }

    pub fn sweep_to_usdc<'info>(
        ctx: Context<'_, '_, '_, 'info, SweepToUsdc<'info>>,
        token_index: u8,
        swap_plan: jupiter::SwapPlan,
    ) -> Result<()> {
        instructions::sweep_to_usdc::handler(ctx, token_index, swap_plan)
    }

    /// Ceremonia #39 (C-A, Pieza 4): vende a USDC un token FUERA DE TABLA del
    /// vault (residuo de un restructure abortado tras compras). Salida para
    /// fondos que hoy quedan inalcanzables por todos los caminos.
    pub fn rescue_untracked_token<'info>(
        ctx: Context<'_, '_, '_, 'info, RescueUntrackedToken<'info>>,
        swap_plan: jupiter::SwapPlan,
    ) -> Result<()> {
        instructions::rescue_untracked_token::handler(ctx, swap_plan)
    }

    pub fn finalize_close<'info>(
        ctx: Context<'_, '_, '_, 'info, FinalizeClose<'info>>,
    ) -> Result<()> {
        instructions::finalize_close::handler(ctx)
    }

    // ---- protocol admin (Squads multisig) -----------------------------------

    /// Retirada del AllowedMintRegistry (2026-07-03): el registro llevaba
    /// muerto desde que el gating pasó al FeedRegistry/liquidez — esta
    /// instrucción admin lo cierra y devuelve el rent a la autoridad (Squads).
    /// Las antiguas init/add/remove_allowed_mint se eliminaron del programa.
    pub fn close_allowed_mint_registry(ctx: Context<CloseAllowedMintRegistry>) -> Result<()> {
        instructions::admin::close_allowed_mint_registry_handler(ctx)
    }

    // ---- upgrade #30: FeedRegistry (TVL mark-to-market) ---------------------

    pub fn init_feed_registry(ctx: Context<InitFeedRegistry>) -> Result<()> {
        instructions::init_feed_registry::handler(ctx)
    }

    pub fn set_feed(
        ctx: Context<SetFeed>,
        mint: Pubkey,
        feed_id: [u8; 32],
        flags: u8,
    ) -> Result<()> {
        instructions::set_feed::handler(ctx, mint, feed_id, flags)
    }

    pub fn remove_feed(ctx: Context<RemoveFeed>, mint: Pubkey) -> Result<()> {
        instructions::remove_feed::handler(ctx, mint)
    }

    pub fn cache_alloc_decimals(ctx: Context<CacheAllocDecimals>) -> Result<()> {
        instructions::cache_alloc_decimals::handler(ctx)
    }

    pub fn mark_tvl(ctx: Context<MarkTvl>) -> Result<()> {
        instructions::mark_tvl::handler(ctx)
    }

    pub fn set_m2m_enforced(ctx: Context<ProtocolAdmin>, enforced: bool) -> Result<()> {
        instructions::admin::set_m2m_enforced_handler(ctx, enforced)
    }

    pub fn set_entry_fee(
        ctx: Context<ProtocolAdmin>,
        bps: u16,
        cap_usdc: u64,
        exempt_below_usdc: u64,
        protocol_share_bps: u16,
    ) -> Result<()> {
        instructions::admin::set_entry_fee_handler(
            ctx,
            bps,
            cap_usdc,
            exempt_below_usdc,
            protocol_share_bps,
        )
    }

    pub fn set_vault_creation_fee(
        ctx: Context<ProtocolAdmin>,
        fee_usd_micros: u64,
        treasury: Pubkey,
    ) -> Result<()> {
        instructions::admin::set_vault_creation_fee_handler(ctx, fee_usd_micros, treasury)
    }

    /// Ceremonia #46: fija la comisión de rebalanceo / cambio de cesta (0 = off).
    pub fn set_rebalance_fee(
        ctx: Context<ProtocolAdmin>,
        fee_usd_micros: u64,
        treasury: Pubkey,
    ) -> Result<()> {
        instructions::admin::set_rebalance_fee_handler(ctx, fee_usd_micros, treasury)
    }

    /// Ceremonia USDC: interruptor de moneda de las comisiones del creador (0 = SOL,
    /// 1 = USDC) + importes en USDC (átomos). NO toca los importes en SOL.
    pub fn set_fee_currency_usdc(
        ctx: Context<ProtocolAdmin>,
        mode: u8,
        vault_creation_fee_usdc: u64,
        rebalance_fee_usdc: u64,
    ) -> Result<()> {
        instructions::admin::set_fee_currency_usdc_handler(
            ctx,
            mode,
            vault_creation_fee_usdc,
            rebalance_fee_usdc,
        )
    }

    /// Ceremonia USDC §3.5: crea el singleton `ServiceConfig` (topes y pausa del servicio S).
    pub fn init_service_config(ctx: Context<InitServiceConfig>, args: ServiceParamsArgs) -> Result<()> {
        instructions::service_config::init_handler(ctx, args)
    }

    /// Ceremonia USDC §3.5: edita los topes y la pausa del servicio S.
    pub fn set_service_params(ctx: Context<SetServiceParams>, args: ServiceParamsArgs) -> Result<()> {
        instructions::service_config::set_handler(ctx, args)
    }

    /// Ceremonia #37: umbral del guard de pérdida máxima por compra (0 = off).
    pub fn set_swap_max_loss(ctx: Context<ProtocolAdmin>, max_loss_bps: u16) -> Result<()> {
        instructions::admin::set_swap_max_loss_handler(ctx, max_loss_bps)
    }

    /// Auditoría CISO (P3, #56): edad máxima del precio de Pyth en el re-precio del commit del depósito (0 = la de la clase;
    /// si no, de 10 a 120 s).
    pub fn set_commit_oracle_max_age(ctx: Context<ProtocolAdmin>, max_age_secs: u16) -> Result<()> {
        instructions::admin::set_commit_oracle_max_age_handler(ctx, max_age_secs)
    }

    // ---- upgrade #31: cambio de estrategia ----------------------------------

    pub fn restructure_init(ctx: Context<RestructureInit>, args: RestructureInitArgs) -> Result<()> {
        instructions::restructure_init::handler(ctx, args)
    }

    pub fn restructure_swap_batch<'info>(
        ctx: Context<'_, '_, '_, 'info, RestructureSwapBatch<'info>>,
        args: RestructureSwapBatchArgs,
    ) -> Result<()> {
        instructions::restructure_swap_batch::handler(ctx, args)
    }

    pub fn restructure_settle(ctx: Context<RestructureSettle>) -> Result<()> {
        instructions::restructure_settle::handler(ctx)
    }

    pub fn restructure_abort(ctx: Context<RestructureAbort>) -> Result<()> {
        instructions::restructure_abort::handler(ctx)
    }

    /// Ceremonia #53: limpieza SELF-SERVICE (permissionless) del valor fuera de
    /// tabla de un cambio de cesta abortado con compras (P2-3). Exige la ATA de cada
    /// mint varado del manifiesto a 0 (rescatado) y baja la bandera stranded.
    pub fn close_stranded<'info>(
        ctx: Context<'_, '_, '_, 'info, CloseStranded<'info>>,
    ) -> Result<()> {
        instructions::close_stranded::handler(ctx)
    }

    /// Ceremonia #53: limpieza por AUTHORITY del valor fuera de tabla del lado
    /// RETIRO (P2-4, sin manifiesto) y backstop de P2-3. Baja la bandera y cierra la
    /// RestructureSession-manifiesto si viene.
    pub fn admin_clear_stranded(ctx: Context<AdminClearStranded>) -> Result<()> {
        instructions::admin_clear_stranded::handler(ctx)
    }

    /// Ceremonia USDC (§3.3, B3): backstop PERMISSIONLESS. Cierra un `FundingRecord`
    /// HUÉRFANO (su sesión ya no existe o lleva otro sello) y devuelve todo su saldo a
    /// `record.refund_to`. Un registro vivo revierte (`FundingRecordAlive`).
    pub fn funding_reclaim_stale(ctx: Context<FundingReclaimStale>) -> Result<()> {
        instructions::funding_reclaim_stale::handler(ctx)
    }

    pub fn extend_feed_registry(ctx: Context<ExtendFeedRegistry>, extra_entries: u16) -> Result<()> {
        instructions::extend_feed_registry::handler(ctx, extra_entries)
    }

    pub fn set_tvl_cap(ctx: Context<ProtocolAdmin>, new_cap_usdc: u64) -> Result<()> {
        instructions::admin::set_tvl_cap_handler(ctx, new_cap_usdc)
    }

    pub fn set_liquidity_floor(ctx: Context<ProtocolAdmin>, new_floor_usdc: u64) -> Result<()> {
        instructions::admin::set_liquidity_floor_handler(ctx, new_floor_usdc)
    }

    pub fn pause_protocol(ctx: Context<ProtocolAdmin>) -> Result<()> {
        instructions::admin::pause_protocol_handler(ctx)
    }

    pub fn unpause_protocol(ctx: Context<ProtocolAdmin>) -> Result<()> {
        instructions::admin::unpause_protocol_handler(ctx)
    }

    pub fn pause_vault(ctx: Context<AdminVaultPause>) -> Result<()> {
        instructions::admin::pause_vault_handler(ctx)
    }

    pub fn unpause_vault(ctx: Context<AdminVaultUnpause>) -> Result<()> {
        instructions::admin::unpause_vault_handler(ctx)
    }
}
