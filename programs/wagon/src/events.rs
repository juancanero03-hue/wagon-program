//! Anchor events emitted by the program. Clients (and indexers) subscribe to these
//! to build on-chain history without scraping transactions.

use anchor_lang::prelude::*;

#[event]
pub struct ProtocolInitialized {
    pub authority: Pubkey,
    pub usdc_mint: Pubkey,
    pub tvl_cap_usdc: u64,
    pub liquidity_floor_usdc: u64,
}

#[event]
pub struct VaultCreated {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub nonce: u64,
    pub performance_fee_bps: u16,
    pub max_slippage_bps: u16,
    pub allocation_count: u8,
}

// Capa 5: the legacy `Deposit` and `Withdraw` events were removed alongside
// the monolithic instructions they served. Off-chain indexers should
// subscribe to the new event family (DepositInitiated/DepositSwapExecuted/
// DepositCompleted/DepositAborted and the Withdraw* counterparts).

// H-2: `ManagementFeeHarvested` was removed together with the
// `harvest_management_fee` instruction (management fee retired; it never
// emitted on mainnet — the handler was a stub).

#[event]
pub struct Rebalanced {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub new_allocation_count: u8,
}

#[event]
pub struct VaultClosed {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub ts: i64,
}

#[event]
pub struct VaultFinalized {
    pub vault: Pubkey,
    pub ts: i64,
}

/// Emitted once per successful `sweep_to_usdc` leg during liquidation.
/// Indexers can use this to reconstruct the liquidation path slot-by-slot.
#[event]
pub struct SweptToUsdc {
    pub vault: Pubkey,
    pub token_index: u8,
    pub mint: Pubkey,
    pub amount_in: u64,
    pub usdc_out: u64,
}

/// Ceremonia #39 (C-A Pieza 4): un token FUERA DE TABLA del vault (p. ej. dejado
/// por un restructure abortado tras compras) se vendió a USDC vía
/// `rescue_untracked_token`. `floor_enforced` = si se aplicó el piso de
/// valor-oráculo (mint con feed) o si fue la vía authority-only.
#[event]
pub struct UntrackedTokenRescued {
    pub vault: Pubkey,
    pub mint: Pubkey,
    pub amount_in: u64,
    pub usdc_out: u64,
    pub floor_enforced: bool,
}

/// Ceremonia #39 (C-B): una pata de retiro se pagó EN ESPECIE al inversor (los
/// tokens de su hucha van a su propia ATA), en vez de venderse a USDC — vía
/// `withdraw_claim_leg_in_kind`. `by_third_party` = si lo disparó un tercero tras
/// el timeout de 24 h (el valor va SIEMPRE al inversor, nunca al caller).
#[event]
pub struct WithdrawLegClaimedInKind {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub leg_index: u8,
    pub mint: Pubkey,
    pub amount: u64,
    pub by_third_party: bool,
}

/// G4 (F5B-01 y F5A-01): un init encontró ya creada una hucha de su sesión pagada por la otra clase (el inversor, o Wagon) y el
/// pagador de ahora se la compró: `lamports` = el rent mínimo de su tamaño (nunca lo donado de más) de `from` (el `payer` del
/// init) a `to` (el inversor, o `protocol.authority` si la pagó Wagon). Así el terminal, que cierra todo hacia el destino de la
/// sesión, devuelve a cada uno lo suyo.
#[event]
pub struct SessionEscrowRentBought {
    pub session: Pubkey,
    pub escrow: Pubkey,
    pub from: Pubkey,
    pub to: Pubkey,
    pub lamports: u64,
}

#[event]
pub struct VaultPauseChanged {
    pub vault: Pubkey,
    pub paused: bool,
}

#[event]
pub struct ProtocolPauseChanged {
    pub paused: bool,
}

#[event]
pub struct TvlCapChanged {
    pub old_cap: u64,
    pub new_cap: u64,
}

#[event]
pub struct LiquidityFloorChanged {
    pub old_floor: u64,
    pub new_floor: u64,
}

#[event]
pub struct RebalanceSwap {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub source_index: u8,
    pub dest_index: u8,
    pub source_mint: Pubkey,
    pub dest_mint: Pubkey,
    pub amount_in: u64,
    pub amount_out: u64,
}

/// Retirada del AllowedMintRegistry (2026-07-03): el registro muerto se
/// cierra vía admin y su rent vuelve a la autoridad. Los eventos antiguos
/// (Initialized/Added/Removed) se eliminaron junto con sus instrucciones.
#[event]
pub struct AllowedMintRegistryClosed {
    pub authority: Pubkey,
    pub lamports_recovered: u64,
}

// ─── Upgrade #30: FeedRegistry (TVL mark-to-market) ─────────────────────────

#[event]
pub struct FeedRegistryInitialized {
    pub authority: Pubkey,
}

#[event]
pub struct FeedSet {
    pub mint: Pubkey,
    pub feed_id: [u8; 32],
    pub flags: u8,
    pub registry_count_after: u16,
}

#[event]
pub struct FeedRemoved {
    pub mint: Pubkey,
    pub registry_count_after: u16,
}

#[event]
pub struct TvlMarked {
    pub vault: Pubkey,
    pub old_tvl_usdc: u64,
    pub new_tvl_usdc: u64,
}

#[event]
pub struct M2mEnforcementChanged {
    pub enforced: bool,
}

// ─── Upgrade #31: cambio de estrategia ──────────────────────────────────────

#[event]
pub struct RestructureStarted {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub old_count: u8,
    pub new_count: u8,
}

#[event]
pub struct RestructureLegExecuted {
    pub vault: Pubkey,
    /// 0 = venta de saliente, 1 = compra de entrante.
    pub kind: u8,
    pub index: u8,
    pub amount_in: u64,
    pub amount_out: u64,
}

#[event]
pub struct VaultRestructured {
    pub vault: Pubkey,
    pub old_count: u8,
    pub new_count: u8,
    pub tvl_after_usdc: u64,
}

#[event]
pub struct RestructureAborted {
    pub vault: Pubkey,
    pub caller: Pubkey,
    pub stranded_buys: bool,
}

// ─── Ceremonia #53: valor fuera de tabla ───────────────────────────────────
/// El vault entró en CUARENTENA (bandera stranded a 1) porque una operación dejó
/// valor fuera de tabla. `producer`: 0 = restructure_abort con compras varadas,
/// 1 = withdraw_sweep_batch de un mint eliminado. La ENTRADA queda vetada hasta limpiar.
#[event]
pub struct StrandedValueQuarantined {
    pub vault: Pubkey,
    pub caller: Pubkey,
    pub producer: u8,
}

/// La bandera stranded volvió a 0: el valor fuera de tabla se rescató y la ENTRADA
/// se reabre. `by_authority`: false = close_stranded permissionless (P2-3),
/// true = admin_clear_stranded (P2-4 / backstop).
#[event]
pub struct StrandedValueCleared {
    pub vault: Pubkey,
    pub caller: Pubkey,
    pub by_authority: bool,
}

// ─── Capa 5: fractional deposit/withdraw events ────────────────────────────

#[event]
pub struct DepositInitiated {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub amount_usdc: u64,
    pub tvl_before: u64,
    pub total_shares_before: u64,
    pub leg_count: u8,
    /// Bits already marked at init (USDC-as-allocation legs, zero-weight slots).
    pub legs_pre_completed: u16,
}

#[event]
pub struct DepositSwapExecuted {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub leg_index: u8,
    pub usdc_in: u64,
    pub tokens_out: u64,
}

#[event]
pub struct DepositCompleted {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub usdc_in: u64,
    pub shares_minted: u64,
    pub tvl_before_usdc: u64,
    pub tvl_after_usdc: u64,
}

#[event]
pub struct DepositAborted {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub amount_usdc_refunded: u64,
}

/// Upgrade #31 (F2b): one escrow ATA drained and closed. `to_vault` tells
/// the direction — true for the settle path, false for an abort refund.
#[event]
pub struct DepositEscrowSwept {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub leg_index: u8,
    pub amount: u64,
    pub to_vault: bool,
}

#[event]
pub struct WithdrawInitiated {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub shares_to_burn: u64,
    pub usdc_slice_from_vault: u64,
    pub tvl_before: u64,
    pub total_shares_before: u64,
    pub leg_count: u8,
    pub legs_pre_completed: u16,
}

#[event]
pub struct WithdrawSwapExecuted {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub leg_index: u8,
    pub tokens_in: u64,
    pub usdc_out: u64,
}

#[event]
pub struct WithdrawCompleted {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub shares_burned: u64,
    pub usdc_out_to_user: u64,
    pub performance_fee_usdc: u64,
    pub profit_realised_usdc: i64,
}

#[event]
pub struct WithdrawAborted {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub shares_restored: u64,
}

/// C2 (ceremonia #38): one withdraw token-escrow ATA drained and closed. The
/// destination is always the vault; `aborting` tells the direction — false on
/// the normal settle path (escrow was empty), true on the deshacer-total path
/// (escrow held the unsold slice, returned to the vault).
#[event]
pub struct WithdrawEscrowSwept {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub leg_index: u8,
    pub amount: u64,
    pub aborting: bool,
}

// Entry fee (front-load) — accrue-and-claim, 2026-06-30

#[event]
pub struct EntryFeeParamsChanged {
    pub bps: u16,
    pub cap_usdc: u64,
    pub exempt_below_usdc: u64,
    pub protocol_share_bps: u16,
}

/// DT-E: se emite en `deposit_settle` (ya no en el init) con lo que DE VERDAD llegó a cada
/// destino; `fee_usdc` = la suma de los dos cortes pagados. Layout sin cambios.
#[event]
pub struct EntryFeeCharged {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub investor: Pubkey,
    pub fee_usdc: u64,
    pub creator_cut_usdc: u64,
    pub protocol_cut_usdc: u64,
}

/// DT-E: parte de la comisión de entrada COBRABLE cuyo destino no pudo recibir al asentar (congelado o
/// inexistente) y cayó al vault con el resto de la hucha, como la comisión de éxito no pagable del
/// retiro (si la ATA del vault tampoco podía recibir, siguió a ese resto hacia el inversor). La E reservada
/// en el init = `EntryFeeCharged` + este evento + `DepositResidualReturned.entry_fee_waived_usdc`.
/// Mismo orden de campos que `EntryFeeCharged` (sin `fee_usdc`), para los parsers a mano.
#[event]
pub struct EntryFeeDiverted {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub investor: Pubkey,
    pub creator_cut_usdc: u64,
    pub protocol_cut_usdc: u64,
}

#[event]
pub struct CreatorRewardsClaimed {
    pub creator: Pubkey,
    pub amount_usdc: u64,
}

/// Upgrade #35 -- parámetros del fee de creación de vault cambiados (admin).
#[event]
pub struct VaultCreationFeeParamsChanged {
    pub fee_usd_micros: u64,
    pub treasury: Pubkey,
}

/// Upgrade #35 -- fee de creación cobrado (SOL del creador -> tesorería).
#[event]
pub struct VaultCreationFeeCharged {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub lamports: u64,
    pub fee_usd_micros: u64,
}

/// Ceremonia #46 — parámetros de la comisión de rebalanceo cambiados (admin).
#[event]
pub struct RebalanceFeeParamsChanged {
    pub fee_usd_micros: u64,
    pub treasury: Pubkey,
}

/// Ceremonia #46 — comisión de rebalanceo / cambio de cesta cobrada (SOL del
/// creador -> tesorería), en `rebalance` o `restructure_init`.
#[event]
pub struct RebalanceFeeCharged {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub lamports: u64,
    pub fee_usd_micros: u64,
}

/// Ceremonia #37 -- umbral del guard de pérdida por compra cambiado (admin).
#[event]
pub struct SwapMaxLossChanged {
    pub max_loss_bps: u16,
}

/// Auditoría CISO (P3, #56) -- edad máxima del precio en el re-precio del commit del depósito cambiada (admin; 0 = la de
/// la clase).
#[event]
pub struct CommitOracleMaxAgeChanged {
    pub max_age_secs: u16,
}

/// Ceremonia USDC — interruptor de moneda y comisiones del creador en USDC
/// cambiados (admin). `mode`: 0 = SOL, 1 = USDC. Los importes en SOL no se tocan.
#[event]
pub struct FeeCurrencyParamsChanged {
    pub mode: u8,
    pub vault_creation_fee_usdc: u64,
    pub rebalance_fee_usdc: u64,
}

/// Ceremonia USDC — comisión de creación cobrada en USDC (ATA del creador ->
/// tesorería USDC del protocolo).
#[event]
pub struct VaultCreationFeeChargedUsdc {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub amount_usdc: u64,
}

/// Ceremonia USDC — comisión de rebalanceo / cambio de cesta cobrada en USDC.
/// `kind`: 0 = rebalance, 1 = restructure_init.
#[event]
pub struct RebalanceFeeChargedUsdc {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub amount_usdc: u64,
    pub kind: u8,
}

/// Ceremonia USDC, D8 — `set_vault_texts` escribió al menos un campo (descripción
/// y/o tags). Se emite en cada llamada que escribe algo (como mucho una vez por
/// campo, así que hasta 2 veces por vault); un reenvío idéntico no emite. Los
/// dos booleanos dicen qué campo se escribió en esta llamada.
#[event]
pub struct VaultTextsSet {
    pub vault: Pubkey,
    pub creator: Pubkey,
    pub description_written: bool,
    pub tags_written: bool,
}

/// Ceremonia USDC §3.3 — registro de financiación creado en un init PATROCINADO
/// (`payer != propietario`). `lamports_refundable` = rent que ESTE init puso y un
/// terminal cierra normalmente (sesión + hucha USDC + registro), medido al crear; si la
/// hucha se queda abierta (settle de DT-E o abort aplazado de G2-b), `FundingRefundPartial` lo dice.
#[event]
pub struct FundingRecorded {
    pub session: Pubkey,
    pub vault: Pubkey,
    pub payer: Pubkey,
    pub refund_to: Pubkey,
    pub generation: u64,
    pub kind: u8,
    pub lamports_refundable: u64,
    pub lamports_sunk: u64,
}

/// Ceremonia USDC §3.3 — un terminal cerró la sesión y su registro emparejado:
/// `lamports` es el importe EFECTIVO que recibe `refund_to` (saldo de la sesión,
/// huchas cerradas hacia ella incluidas, más el rent del registro cuando va al mismo
/// sitio). B3 (§3.3.d): en el abort limpio, `close_stranded` y `admin_clear_stranded`
/// del cambio de cesta el rent del PROPIO registro va al limpiador (`record_to` ≠
/// `refund_to`) y entonces NO está dentro de `lamports`.
#[event]
pub struct FundingRefunded {
    pub session: Pubkey,
    pub refund_to: Pubkey,
    pub generation: u64,
    pub kind: u8,
    /// Total efectivo recibido por `refund_to` (sesión + huchas, y el registro si `record_to == refund_to`).
    pub lamports: u64,
    /// El rent del propio registro (154 B), recibido por `record_to`.
    pub record_lamports: u64,
    /// Quien cobra el rent del registro: `refund_to`, o el limpiador (caller / authority) en B3.
    pub record_to: Pubkey,
}

/// Ceremonia USDC §3.3 (B3) — `funding_reclaim_stale` cerró un registro HUÉRFANO y devolvió
/// TODO su saldo a `refund_to`. `reason`: 0 = la sesión que financiaba ya no existe (o no es de
/// este programa) · 1 = la sesión viva en esa dirección lleva OTRO sello (generación o tipo).
#[event]
pub struct FundingReclaimed {
    pub record: Pubkey,
    pub session: Pubkey,
    pub refund_to: Pubkey,
    pub generation: u64,
    pub kind: u8,
    pub lamports: u64,
    pub reason: u8,
}

/// Ceremonia USDC §3.3 — el terminal siguió el camino LEGACY (rent a `legacy_dest`: el
/// propietario, o el caller en el abort limpio y en `close_stranded` del cambio de cesta,
/// como antes de §3.3). Se emite en TODO cierre sin patrocinio. `reason`: 0 = la dirección
/// canónica del registro está vacía (sesión legacy o sin patrocinio) · 1 = hay un registro
/// pero no empareja (rancio: queda intacto para `funding_reclaim_stale`). Las dos
/// generaciones (la sellada en la sesión y la del registro, 0 si no hay) son la clave del
/// ledger del gateway (sesión + generación).
#[event]
pub struct FundingRefundLegacy {
    pub session: Pubkey,
    pub kind: u8,
    pub reason: u8,
    pub session_generation: u64,
    pub record_generation: u64,
}

/// Ceremonia USDC §3.3.c (B2) — el terminal cerró la sesión pero UNA hucha se quedó ABIERTA
/// y su rent no viajó con el reembolso. `kind` 2: la hucha USDC de `withdraw_settle` cuando
/// hay residuo y la ATA USDC del vault no es pagable (DT-B #54, fail-open: el inversor ya
/// cobró y la sesión cierra igual); la HEREDA la siguiente sesión de retiro de la misma
/// pareja vault + inversor (su init la adopta y su terminal la paga a SU destino).
/// `kind` 1 (DT-E): la hucha USDC de `deposit_settle` cuando está congelada o cuando el resto no
/// pudo ir a ninguna parte (ni la ATA USDC del vault ni la del inversor podían recibir), y (G2-b) la
/// de un `deposit_abort` APLAZADO (hucha congelada o cuenta del inversor no pagable); el
/// siguiente `deposit_init` de la pareja devuelve al inversor lo que quede, y sin sesión abierta
/// lo devuelve `deposit_escrow_reclaim`. `escrow_lamports` = su rent (el USDC sigue dentro).
/// Con registro, `FundingRefunded.lamports` ya lo excluye; sin él, señal para la monitorización off-chain.
#[event]
pub struct FundingRefundPartial {
    pub session: Pubkey,
    pub kind: u8,
    pub session_generation: u64,
    pub escrow: Pubkey,
    pub escrow_lamports: u64,
}

/// Ceremonia USDC §3.5 — `ServiceConfig` creada por Squads (`init_service_config`).
#[event]
pub struct ServiceConfigInitialized {
    pub treasury_usdc_ata: Pubkey,
    pub payer: Pubkey,
    pub max_service_usdc: [u64; 4],
    pub max_exit_service_usdc: u64,
    pub paused: u8,
}

/// Ceremonia USDC §3.5 — parámetros del servicio cambiados (`set_service_params`).
#[event]
pub struct ServiceParamsChanged {
    pub max_service_usdc: [u64; 4],
    pub max_exit_service_usdc: u64,
    pub paused: u8,
}

/// Ceremonia USDC §3.5 — servicio S cobrado en USDC a la tesorería del protocolo. En los inits
/// de ENTRADA (kinds 0 a 3) sale de la cuenta del USUARIO, que lo firmó como argumento del
/// init; en la SALIDA (kind 4, PR 5B) sale de la hucha USDC de la sesión de retiro en
/// `withdraw_settle`, acotado a lo que el inversor firmó en `withdraw_init`. `kind` = la
/// operación (0 publicar · 1 depositar · 2 rebalancear · 3 cambiar cesta · 4 salida);
/// `op_account` = la CUENTA on chain de la operación: la sesión (depósito / cambio de cesta /
/// retiro, con su `generation` ENTERA u64; en el retiro la del `FundingRecord`) o el vault
/// (publicar / rebalancear, `generation` 0). No es el identificador de ningún libro externo:
/// un cobro se identifica por (firma, índice).
#[event]
pub struct ServiceCharged {
    pub user: Pubkey,
    pub vault: Pubkey,
    pub kind: u8,
    pub amount_usdc: u64,
    pub generation: u64,
    pub op_account: Pubkey,
}

/// DT-E (y G2-c): una `DepositSession` antigua (457 o 473 B) se estiró a `LEN` (601 B) con los campos nuevos a 0;
/// `lamports_added` = el rent de los bytes nuevos hasta `LEN` que pagó `payer`.
#[event]
pub struct DepositSessionMigrated {
    pub session: Pubkey,
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub payer: Pubkey,
    pub lamports_added: u64,
}

/// DT-E: dinero de la hucha que es del inversor y no entró en el vault. En `deposit_settle`: la ATA
/// USDC del vault no podía recibir o la hucha estaba congelada; `returned_usdc` volvió a su ATA
/// canónica y `left_in_escrow_usdc` se quedó en la hucha (si esa ATA tampoco podía, o con la hucha
/// congelada); ese resto no acuñó ni es base de coste, y `entry_fee_waived_usdc` es la parte de E que
/// no se cobró (va dentro de esas dos cifras). En `deposit_init`: `returned_usdc` es lo heredado de un
/// settle anterior de la pareja, devuelto antes de empezar (las otras dos cifras a 0).
#[event]
pub struct DepositResidualReturned {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub returned_usdc: u64,
    pub left_in_escrow_usdc: u64,
    pub entry_fee_waived_usdc: u64,
    pub session: Pubkey,
}

/// DT-E: `deposit_escrow_reclaim` devolvió al inversor (a su ATA USDC canónica, o a la cuenta USDC suya
/// que eligió si llamó él) lo que se había quedado en la hucha de una sesión ya cerrada, y cerró la hucha
/// (su rent, al inversor).
#[event]
pub struct DepositEscrowReclaimed {
    pub session: Pubkey,
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub amount_usdc: u64,
}

/// G3 (F2A-03): `withdraw_escrow_sweep` llevó al VAULT el USDC que un `withdraw_settle` dejó en la hucha de una
/// sesión de retiro ya cerrada (la cuenta USDC del vault no podía recibirlo entonces) y cerró la hucha (su rent, al
/// inversor). Gemelo de `DepositEscrowReclaimed`; `WithdrawEscrowSwept` es el barrido POR PATA de una sesión viva.
#[event]
pub struct WithdrawUsdcEscrowSwept {
    pub session: Pubkey,
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub amount_usdc: u64,
}

/// G2-b (revisión N3, MED): `deposit_abort` cerró la sesión SIN mover el USDC de su hucha porque no podía
/// (`reason` 1 = la hucha está CONGELADA; 2 = la cuenta USDC del inversor no puede recibir). El saldo se queda en
/// la hucha y lo recupera `deposit_escrow_reclaim` (permissionless, a la ATA canónica del inversor) cuando se
/// pueda mover. Nada se pierde: se aplaza. Antes, ese abort revertía y la sesión quedaba abierta para siempre
/// (con una sesión trivial comprometida, además, `committed_deposits` quedaba clavado y el vault vetado).
#[event]
pub struct DepositAbortDeferred {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub session: Pubkey,
    pub left_in_escrow_usdc: u64,
    pub reason: u8,
}

/// G3-B1a (F2B-01, caso (d) del diseño G3 §3): `withdraw_abort` cerró la sesión y re-acuñó las participaciones SIN
/// devolver al vault el USDC de su hucha porque no podía (`reason` 1 = la hucha está CONGELADA; 2 = la ATA USDC del
/// vault no puede recibir). Ese saldo es del VAULT (en una cancelación el slice vuelve a los co-inversores): se queda
/// en la hucha (abierta) y lo lleva al vault `withdraw_escrow_sweep` (sin permisos) cuando se pueda mover. Antes ese
/// abort revertía y la sesión quedaba cancelando (`aborting == 1`) para siempre, con `pending_burned` reservado.
#[event]
pub struct WithdrawAbortDeferred {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub session: Pubkey,
    pub left_in_escrow_usdc: u64,
    pub reason: u8,
}

/// G3-B1b (DT-A(b)): `withdraw_force_release` cerró la contabilidad de un retiro atascado por una cuenta congelada SIN
/// volver a acuñar y convirtió la sesión en un recibo de derecho (misma PDA): `pending_mask` = huchas de pata que siguen
/// abiertas como derecho del inversor, `usdc_pending` = la hucha USDC. `proof_leg` = 255 si la prueba fue la hucha USDC.
#[event]
pub struct WithdrawForceReleased {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub session: Pubkey,
    pub shares_to_burn: u64,
    pub pending_mask: u16,
    pub usdc_pending: u8,
    pub proof_leg: u8,
    pub by_third_party: bool,
}

/// G3-B1b: `withdraw_escrow_claim` vació una hucha pendiente del recibo hacia la cuenta canónica del inversor y la cerró;
/// `right_closed` = era la última y el recibo se cerró hacia su `refund_to`. `leg_index` = 255 para la hucha USDC.
#[event]
pub struct WithdrawRightClaimed {
    pub vault: Pubkey,
    pub investor: Pubkey,
    pub right: Pubkey,
    pub leg_index: u8,
    pub mint: Pubkey,
    pub amount: u64,
    pub by_third_party: bool,
    pub right_closed: bool,
}

/// Tabla de direcciones del vault (#56): `vault_table_sync` creó la tabla (`created`), la amplió o la sustituyó por una
/// nueva con solo lo vivo (`rotated`, la anterior se queda como estaba). `slot` = el que guarda el vault desde ahora;
/// `added` = direcciones añadidas; `len` = entradas de la tabla al terminar.
#[event]
pub struct VaultTableSynced {
    pub vault: Pubkey,
    pub table: Pubkey,
    pub slot: u64,
    pub added: u8,
    pub len: u16,
    pub created: bool,
    pub rotated: bool,
}
