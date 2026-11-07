//! Protocol-level constants. All values compile into the program; runtime-configurable
//! parameters live on `ProtocolConfig` instead.

use anchor_lang::constant;
use anchor_lang::prelude::Pubkey;
use anchor_lang::pubkey;

// USDC mint and Jupiter program ID can be swapped at build time via the
// `mock-jupiter` feature so the test suite can exercise deposit/withdraw on a
// local validator without depending on mainnet AMM state. Real mainnet builds
// must NOT pass `--features mock-jupiter` — migrations/deploy scripts leave
// the flag off.

/// Mainnet USDC mint. Hardcoded to prevent the wrong asset being configured by mistake.
#[cfg(not(feature = "mock-jupiter"))]
pub const USDC_MINT: Pubkey = pubkey!("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

/// Test USDC mint (controlled mint authority). Keypair file in
/// `tests/_shared/fixtures/mock-usdc-keypair.json`.
#[cfg(feature = "mock-jupiter")]
pub const USDC_MINT: Pubkey = pubkey!("CVwyhMSTSCxotsRfgT7aRKVkUmVLxD2tPyUsdfLKPout");

/// Jupiter v6 aggregator program id. Used for all CPI swaps.
#[cfg(not(feature = "mock-jupiter"))]
pub const JUPITER_PROGRAM_ID: Pubkey = pubkey!("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");

/// Mock Jupiter router program id (test-only). Keypair file in
/// `tests/_shared/fixtures/mock-jupiter-keypair.json`.
#[cfg(feature = "mock-jupiter")]
pub const JUPITER_PROGRAM_ID: Pubkey = pubkey!("5XTrg9h1vGodDJv71xtv8ghvcVk5vWCaCuxGAi8ZmGww");

// --- PDA seeds ---------------------------------------------------------------

pub const PROTOCOL_SEED: &[u8] = b"protocol";
pub const VAULT_SEED: &[u8] = b"vault";
pub const VAULT_AUTHORITY_SEED: &[u8] = b"vault-authority";
pub const USER_POSITION_SEED: &[u8] = b"user";
pub const SHARE_MINT_SEED: &[u8] = b"share-mint";
pub const TREASURY_SEED: &[u8] = b"treasury";
/// Seed del difunto AllowedMintRegistry — se conserva SOLO para que
/// `close_allowed_mint_registry` derive el PDA y recupere su rent.
pub const ALLOWED_MINTS_SEED: &[u8] = b"allowed-mints";
/// Seed of the FeedRegistry PDA (upgrade #30, TVL mark-to-market).
pub const FEED_REGISTRY_SEED: &[u8] = b"feed-registry";

/// Seed for DepositSession PDAs. One per (vault, investor) — held open
/// between `deposit_init` and `deposit_settle`/`deposit_abort`, then closed.
pub const DEPOSIT_SESSION_SEED: &[u8] = b"deposit-session";

/// Seed for WithdrawSession PDAs. Same lifecycle as DepositSession but for
/// the burn-shares-and-swap-back path.
pub const WITHDRAW_SESSION_SEED: &[u8] = b"withdraw-session";

/// Ceremonia USDC (§3.3): seed del `FundingRecord`, `[b"funding", session_pda]`. Una
/// por sesión ABIERTA y patrocinada; la crea el init y la cierra el terminal de esa
/// misma sesión (ver `state::funding_record`).
pub const FUNDING_SEED: &[u8] = b"funding";

/// Ceremonia USDC (§3.5): seed del `ServiceConfig`, `[b"service-config"]`. Singleton
/// creado por Squads (`init_service_config`): topes del servicio S y su pausa.
pub const SERVICE_CONFIG_SEED: &[u8] = b"service-config";

/// Maximum number of legs a single swap_batch instruction can carry. Three
/// keeps each batch tx well under the v0 1232-byte ceiling even for
/// multi-hop Jupiter routes. Empirically 1-2 fits comfortably; 3 fits when
/// the legs share static accounts (USDC mint, SPL Token program, etc.).
/// The frontend may pack fewer if a particular combination doesn't fit —
/// the program just refuses batches over this hard cap.
pub const MAX_LEGS_PER_BATCH: usize = 3;

/// Maximum legs per `withdraw_claim_leg_in_kind` call (upgrade #31, F2b: era también el tope de `deposit_sweep_batch`). A
/// segment is only [mint, escrow_ata, dest_ata] — no Jupiter route — so four
/// fit comfortably under the 1232-byte v0 ceiling alongside the named
/// accounts, even with Phantom's ~150-byte signing overhead. Desde G5 el barrido del depósito usa
/// `MAX_DEPOSIT_SWEEP_LEGS_PER_BATCH` (7) y el del retiro `MAX_WITHDRAW_SWEEP_LEGS_PER_BATCH` (7).
pub const MAX_SWEEP_LEGS_PER_BATCH: usize = 4;

// --- Fee math ----------------------------------------------------------------

/// Basis point denominator. 10_000 bps = 100%.
pub const BPS_DENOMINATOR: u64 = 10_000;

/// Management fee (annualised). 100 bps = 1%. RETIRED: kept only because
/// `initialize` writes it into the account layout; nothing charges it.
pub const DEFAULT_MANAGEMENT_FEE_BPS: u16 = 100;

/// Mgmt fee split. RETIRED like the fee above: `initialize` writes it, nothing
/// charges it.
pub const MGMT_FEE_PROTOCOL_SHARE_BPS: u16 = 4_000; // 40%
pub const MGMT_FEE_CREATOR_SHARE_BPS: u16 = 6_000;  // 60%

/// Performance fee split.
pub const PERF_FEE_PROTOCOL_SHARE_BPS: u16 = 1_000; // 10%
pub const PERF_FEE_CREATOR_SHARE_BPS: u16 = 9_000;  // 90%

/// Performance fee rate bounds the creator can choose from.
pub const MIN_PERF_FEE_BPS: u16 = 500;  // 5%
pub const MAX_PERF_FEE_BPS: u16 = 2_500; // 25%

// --- entry fee (front-load) — accrue-and-claim, 2026-06-30 ------------------
// The live params live in ProtocolConfig (governance-adjustable) and are set by
// Squads with `set_entry_fee`; the fee ships OFF (all 0). E se DESCUENTA de lo que paga el
// inversor (D) y el capital que entra es I = D − E (`entry_fee::deduct_entry_fee`; decisión
// de Juan del 15-oct-2026, que deroga el «E encima» de §3.9); los parámetros de la ceremonia
// (200 bps · tope 19.75 · exención 0 · 7000 bps al protocolo) los pone Squads en el paso de
// setters, NUNCA este código. (Las ENTRY_FEE_*_TARGET del #55 se retiraron: nadie las leía.)
/// Owner PDA of a creator's rewards vault: `[b"creator-rewards", creator]`.
pub const CREATOR_REWARDS_SEED: &[u8] = b"creator-rewards";
/// Tabla de direcciones del vault (#56): PDA `[b"vault-table", vault]`, autoridad de la tabla. No tiene datos; solo firma,
/// por CPI, las ampliaciones que hace `vault_table_sync`. `#[constant]`: sale en el IDL para que los clientes la deriven.
#[constant]
pub const VAULT_TABLE_SEED: &[u8] = b"vault-table";
/// Hard ceiling the admin setter will accept (<= 5%), a sanity guard.
pub const ENTRY_FEE_MAX_BPS: u16 = 500;

/// Ceremonia #37: tope de cordura del guard de pérdida por compra (20%).
/// El valor operativo vive en ProtocolConfig (`swap_max_loss_bps`) y lo fija `set_swap_max_loss`.
pub const SWAP_MAX_LOSS_MAX_BPS: u16 = 2000;

// --- Vault-creation fee (upgrade #35) ----------------------------------------

/// Fee objetivo al crear un vault: 1.50 USD (decisión de diseño 2026-07-04),
/// cobrado en SOL al tipo del oráculo SOL/USD en el momento de crear.
/// El programa arranca con 0 = apagado; se fija tras el upgrade vía
/// `set_vault_creation_fee` (Squads). Referencia para la propuesta de activación.
pub const VAULT_CREATION_FEE_USD_MICROS_TARGET: u64 = 1_500_000;

/// Sanity ceiling the admin setter will accept (10 USD).
pub const VAULT_CREATION_FEE_MAX_USD_MICROS: u64 = 10_000_000;

/// Hard clamp on the lamports actually charged (1 SOL). Protects creators
/// from a glitched oracle print (a near-zero price would otherwise compute
/// an absurd SOL amount). Normal operation sits orders of magnitude below.
pub const VAULT_CREATION_FEE_MAX_LAMPORTS: u64 = 1_000_000_000;

/// Ceremonia #46 — comisión objetivo al rebalancear / cambiar cesta: 1.00 USD
/// (decisión de diseño 2026-08-02), cobrada en SOL al tipo del oráculo SOL/USD en
/// `rebalance` y `restructure_init`. El programa arranca con 0 = apagada; se
/// fija tras el upgrade vía `set_rebalance_fee` (Squads). Referencia para la
/// propuesta de activación. El techo y el clamp REUSAN VAULT_CREATION_FEE_MAX_USD_MICROS
/// (10 USD) y VAULT_CREATION_FEE_MAX_LAMPORTS (1 SOL).
pub const REBALANCE_FEE_USD_MICROS_TARGET: u64 = 1_000_000;

// --- Ceremonia USDC: moneda de las comisiones del creador --------------------

/// Interruptor `ProtocolConfig::fee_currency_mode`: 0 = las comisiones de
/// creación / rebalanceo se cobran en SOL (legacy; la cuenta viva lee 0),
/// 1 = en USDC. Manda SOLO el interruptor (decisión de diseño 2026-09-22): cada
/// instrucción cobra en UNA moneda según su valor; los importes de la otra se
/// ignoran, no se borran, así `mode = 0` es un rollback de una sola propuesta
/// y nunca hay ventana de doble cobro. Cobro cero solo por configuración: si el
/// importe de la moneda ACTIVA es 0 no se cobra nada (el setter lo permite).
pub const FEE_CURRENCY_MODE_SOL: u8 = 0;
pub const FEE_CURRENCY_MODE_USDC: u8 = 1;

/// Comisiones objetivo en USDC (átomos, 6 dec; decisión de diseño 2026-09-22):
/// 10 USDC al crear un vault y 1 USDC al rebalancear / cambiar la cesta. El
/// programa arranca con 0 y modo SOL; se fijan tras la ceremonia vía
/// `set_fee_currency_usdc` (Squads). Referencia para la propuesta de activación.
pub const VAULT_CREATION_FEE_USDC_TARGET: u64 = 10_000_000;
pub const REBALANCE_FEE_USDC_TARGET: u64 = 1_000_000;

/// Ceremonia USDC, D8: ventana de PUBLICACIÓN de los textos del vault. `set_vault_texts`
/// solo escribe dentro de las 24 h siguientes a `created_at` (decisión de diseño
/// 2026-09-23: la descripción es INMUTABLE; la 2.ª transacción de la publicación,
/// y su recuperación si se quedó a medias, caben de sobra). Un reenvío idéntico
/// sigue siendo un no-op con éxito fuera de la ventana. Cambiarla = ceremonia.
pub const VAULT_TEXTS_WINDOW_SECS: i64 = 24 * 60 * 60;

/// Techo de cordura del setter para cualquiera de las dos comisiones en USDC
/// (50 USDC): protege de un cero de más en una propuesta.
pub const CREATOR_FEE_USDC_MAX: u64 = 50_000_000;

/// Ceremonia USDC (§3.5): techo de cordura de CADA tope del servicio S (50 USDC):
/// `init_service_config` / `set_service_params` rechazan un tope mayor
/// (`InvalidServiceParams`). Un tope on chain es una red contra un gateway
/// comprometido, no un precio: se fija holgado (el coste a SOL 500 $).
pub const SERVICE_USDC_MAX: u64 = 50_000_000;

/// Ceremonia USDC (§3.5): índice de cada operación en `ServiceConfig::max_service_usdc`
/// y `kind` del evento `ServiceCharged`. 4 = salida (S por exceso, D3; PR 5B), fuera de
/// la tabla de entrada (`max_for` devuelve 0).
pub const SERVICE_KIND_CREATE: u8 = 0;
pub const SERVICE_KIND_DEPOSIT: u8 = 1;
pub const SERVICE_KIND_REBALANCE: u8 = 2;
pub const SERVICE_KIND_RESTRUCTURE: u8 = 3;
pub const SERVICE_KIND_EXIT: u8 = 4;

/// Programa RECEPTOR de Pyth dueño de las cuentas de precio que acepta el programa: el de la generación nueva, a la que
/// Pyth movió sus cuentas al actualizar su Price Feed program (ceremonia #40, 2026-07-29).
///
/// Desde la #56 (auditoría CISO, P3) es el ÚNICO receptor aceptado: las cuentas del de la generación vieja
/// (`pyth_solana_receiver_sdk::ID` = rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ) se rechazan con `InvalidPriceAccount`.
/// Con una sola generación, cada feed tiene UNA cuenta de precio válida: la oficial de `PYTH_PUSH_ORACLE_V2`.
pub const PYTH_RECEIVER_V2: Pubkey = pubkey!("rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp");

/// Programa push de Pyth de esa misma generación. La cuenta de precio OFICIAL de un feed es su PDA con las semillas
/// `[PYTH_PUSH_SHARD en little endian, feed_id]` (la cuenta es del receptor `PYTH_RECEIVER_V2`), y Pyth solo la actualiza con
/// una publicación posterior a la que guarda: exigir esa dirección impide pasar una actualización más vieja que la vigente
/// (CISO-P3, #56; `pricing::read_pyth_price`). Contrastado con mainnet el 24-oct-2026: la de SOL/USD es
/// 7AviUf9nL62mcxNbQGKm4nKDQnPjswo6c5MX4D57HmyE (test en pricing.rs).
pub const PYTH_PUSH_ORACLE_V2: Pubkey = pubkey!("pyt2F414BA6dPttK6RddPZUdHfapoBN24GL5wbrPCou");

/// Shard de la cuenta de precio oficial: la que Pyth mantiene es la del shard 0.
pub const PYTH_PUSH_SHARD: u16 = 0;

/// Pyth `Crypto.SOL/USD` feed id (stable identifier, hex
/// ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d).
/// The account passed to create_vault, rebalance and restructure_init must be
/// the OFFICIAL account of this feed (see `PYTH_PUSH_ORACLE_V2`), which Pyth
/// updates continuously.
pub const SOL_USD_FEED_ID: [u8; 32] = [
    0xef, 0x0d, 0x8b, 0x6f, 0xda, 0x2c, 0xeb, 0xa4, 0x1d, 0xa1, 0x5d, 0x40,
    0x95, 0xd1, 0xda, 0x39, 0x2a, 0x0d, 0x2f, 0x8e, 0xd0, 0xc6, 0xc7, 0xbc,
    0x0f, 0x4c, 0xfa, 0xc8, 0xc2, 0x80, 0xb5, 0x6d,
];

/// Per-swap slippage bounds a creator can set on a vault.
pub const MIN_SLIPPAGE_BPS: u16 = 50;  // 0.5%
pub const MAX_SLIPPAGE_BPS: u16 = 500; // 5%

// --- Vault shape -------------------------------------------------------------

/// Hard cap on number of tokens per vault basket. Driven by Solana tx size and
/// Jupiter CPI compute budget. Can be increased in a future program version.
///
/// ⚠️ Este es el tamaño del ALMACENAMIENTO (arrays de VaultState,
/// DepositSession, WithdrawSession, RestructureSession). NO tocarlo: cambiarlo
/// mueve offsets y brickearía todas las cuentas vivas. El tope que se aplica a
/// las cestas NUEVAS es `MAX_TOKENS_PER_VAULT_EFFECTIVE`.
pub const MAX_TOKENS_PER_VAULT: usize = 10;

/// F6 (ceremonia #40) — TOPE EFECTIVO de patas para cestas NUEVAS.
///
/// El retiro se construye en UNA sola transacción indivisible: `withdraw_init`
/// pinnea los mints de la sesión y las patas viajan juntas. A partir de 8 patas
/// deja de caber en el techo de Solana (1.232 B) si los mints no están en la
/// tabla de direcciones (ALT), y en el techo REAL de Phantom (~1.050 B) aún
/// antes. Resultado: dinero CONGELADO — el inversor no puede salir hasta que se
/// amplíe la ALT. Verificado contra transacciones reales de mainnet.
///
/// El tope de 7 existía SOLO en el frontend. Crear un vault no requiere
/// permiso, así que una llamada directa al programa podía fabricar un vault de
/// 8-10 patas cuyos inversores quedaban sin salida. Aquí se hace efectivo
/// on-chain, alineado con la decisión de producto sellada («tope 7 tokens por
/// vault»).
///
/// MEDIDO el 2026-07-29 antes de fijarlo: ningún vault vivo supera 7 patas, así
/// que ninguno queda fuera de la regla ni pierde la posibilidad de reestructurar.
///
/// Se aplica a `create_vault` y a `restructure_init` (cesta nueva). NO se
/// aplica a los caminos que leen una cesta YA existente (`deposit_init`,
/// `withdraw_init`), que siguen tolerando hasta `MAX_TOKENS_PER_VAULT`: si
/// algún día existiera un vault más ancho, debe poder VACIARSE, no quedar
/// atrapado por su propio tope.
pub const MAX_TOKENS_PER_VAULT_EFFECTIVE: usize = 7;

/// Max mint -> Pyth feed mappings in the FeedRegistry.
/// Upgrade #30 introduced this at 64. H-1 (audit 2026-06-29): raised to 115.
/// Upgrade #34 (2026-07-03, extended-catalog battery): raised to 256, aligned
/// with `FEED_REGISTRY_HARD_CAP` (the realloc ceiling of extend_feed_registry).
///
/// The old 115 ceiling existed because `init_feed_registry` created the
/// account at full theoretical size in a single create_account CPI (capped at
/// 10240 bytes; 75 + 88*N <= 10240 -> N <= 115 — raising the constant alone
/// to 150 failed CI for exactly this reason). Since #34, init creates the
/// account SMALL (`FEED_REGISTRY_INITIAL_CAPACITY` entries) and capacity grows
/// on-chain via `extend_feed_registry` (realloc has no such per-create limit).
/// This constant is now only (a) the set_feed count ceiling and (b) the bound
/// of the theoretical-max layout offsets; all writes are bounds-checked
/// against the account's REAL data_len. Entries never move on grow; the
/// stored tail `bump` byte is vestigial (never read), so no data migration.
pub const MAX_PRICE_FEEDS: usize = 256;

/// Upgrade #34 — capacity (in entries) at which `init_feed_registry` creates
/// a FRESH registry account: 42 + 88*96 + 33 = 8523 bytes. Chosen to mirror
/// the live mainnet account (cap 96 after the #31 extend), so tests exercise
/// an exact replica. Must satisfy 42 + 88*K + 33 <= 10240 (single-CPI create
/// cap) -> K <= 115. Growth beyond this is done via `extend_feed_registry`.
pub const FEED_REGISTRY_INITIAL_CAPACITY: usize = 96;

/// Upgrade #30 — oracle gates, indexed by feed class (bits 0-1 of the
/// FeedRegistry entry flags): [stable, major, xstock, longtail].
/// Empirical note: Crypto.*X/USD xStock feeds publish 24/7 (weekend conf
/// ~0.1%), the 300 s window is margin, not a market-hours workaround.
pub const ORACLE_MAX_AGE_SECS: [u64; 4] = [120, 120, 300, 120];

/// Auditoría CISO (P3, #56): límites de `ProtocolConfig::commit_oracle_max_age_secs`, la edad máxima del precio en el
/// re-precio del commit del depósito. 0 = la edad de la clase; si no, entre estos dos valores, que fija
/// `set_commit_oracle_max_age`. `#[constant]`: salen en el IDL para que la botonera valide antes de proponer.
#[constant]
pub const COMMIT_ORACLE_MAX_AGE_MIN_SECS: u16 = 10;
#[constant]
pub const COMMIT_ORACLE_MAX_AGE_MAX_SECS: u16 = 120;
pub const ORACLE_MAX_CONF_BPS: [u64; 4] = [50, 100, 200, 300];

/// Upgrade #30 — freshness window for the last-swap price cache used by
/// mints without a Pyth feed (design decision 2026-06-10: 24 h).
pub const LAST_SWAP_MAX_AGE_SECS: i64 = 86_400;

/// Metadata field budgets (bytes). Fixed so that `VaultState` has predictable
/// account size. Short of this a creator can pad with zeros.
pub const VAULT_NAME_LEN: usize = 32;
pub const VAULT_DESC_LEN: usize = 256;
pub const VAULT_IMAGE_URL_LEN: usize = 128;
pub const VAULT_TAGS_LEN: usize = 64;

// --- Bootstrap caps (mutable via admin ops once deployed) --------------------

/// Initial TVL cap for bootstrap phase. 50_000 USDC, expressed in 6-decimal atomic units.
pub const BOOTSTRAP_TVL_CAP_USDC: u64 = 50_000 * 1_000_000;

/// Liquidity floor a token must meet in routable Jupiter liquidity to be
/// whitelisted into any vault. 500_000 USDC in 6-decimal atomic units.
/// This is enforced off-chain by the frontend plus on-chain via max-slippage.
pub const DEFAULT_LIQUIDITY_FLOOR_USDC: u64 = 500_000 * 1_000_000;

// --- Liquidation ------------------------------------------------------------

/// 7 days: minimum age of a stuck deposit session before `deposit_force_release`.
pub const LIQUIDATION_TIMEOUT_SECONDS: i64 = 7 * 24 * 60 * 60; // 7 days

// --- G3 (liveness, 2026-10-15) ----------------------------------------------

/// G3: mínimo de depósito en el PROGRAMA, 10 USDC medidos sobre `amount_usdc` (lo que paga el
/// inversor, en los dos modelos de comisión). Hasta G3 lo ponía solo la web: por debajo de 10 USDC
/// no se cobra comisión de entrada y ningún automatismo trataba ese polvo. `#[constant]`: sale en el
/// IDL para que los clientes lean el umbral del binario, no una copia.
#[constant]
pub const MIN_DEPOSIT_USDC: u64 = 10_000_000;

/// G3: ESCOTILLA de una sesión de depósito COMPLETA (todas las compras hechas) que nadie barrió al
/// vault a tiempo (vault pausado, oráculo caído, entrada vetada por retiros en vuelo…): a partir de
/// esta edad `deposit_sweep_batch` solo la DEVUELVE (dirección abort, en especie, al inversor, y
/// cualquiera puede conducirla: coincide con `DEPOSIT_SESSION_TIMEOUT_SECS`). La dirección la fija el reloj,
/// no el caller: ninguna sesión completa espera para siempre a un vault que no puede recibirla. Auditoría CISO
/// (P4, #56): 10 min (hasta la #56, 24 h), así que un veto de entrada no retiene un depósito más de 10 min.
/// `#[constant]`: IDL.
#[constant]
pub const DEPOSIT_UNSWEPT_ESCAPE_SECS: i64 = 10 * 60;

/// Auditoría CISO (P4, #56): con la ENTRADA del vault vetada por retiros en vuelo (`entry_blocked_by_withdraws`), el
/// INVERSOR puede pedir la devolución en especie de su sesión completa y sin barrer pasada esta edad, sin esperar a la
/// escotilla (`DepositSession::vetoed_return_due`). 2 min para no devolver por el veto de un retiro normal, que dura
/// segundos. `#[constant]`: IDL.
#[constant]
pub const DEPOSIT_VETOED_RETURN_SECS: i64 = 2 * 60;

/// G3-B1a (F2B-01): tope de patas por instrucción de `withdraw_sweep_batch` = la cesta máxima (7, la misma
/// cifra que `MAX_TOKENS_PER_VAULT_EFFECTIVE`, atada abajo en compilación). El barrido que EMPIEZA una
/// cancelación tiene que traer TODAS las patas pendientes en una sola instrucción (latch atómico), así que
/// una cesta entera tiene que caber en un lote. El de `deposit_sweep_batch` es el mismo desde G5. `#[constant]`: IDL.
#[constant]
pub const MAX_WITHDRAW_SWEEP_LEGS_PER_BATCH: u8 = 7;
const _: () = assert!(
    MAX_WITHDRAW_SWEEP_LEGS_PER_BATCH as usize == MAX_TOKENS_PER_VAULT_EFFECTIVE as usize,
    "el tope del barrido de retiro debe cubrir la cesta máxima"
);

/// G5 (auditoría 2026-10-09, F1A-04): tope de patas por instrucción de `deposit_sweep_batch` = la cesta máxima (7, atada abajo
/// en compilación). El barrido que COMPROMETE un depósito trae TODAS sus patas y el USDC de capital de la hucha en una sola
/// instrucción (6228 si falta alguna pata), así que una cesta entera tiene que caber en un lote (medido el 17-oct: siete patas
/// con el oráculo de las siete y la hucha USDC, 635 B en v0 con tabla de direcciones y unos 245 000 CU). `#[constant]`: IDL.
#[constant]
pub const MAX_DEPOSIT_SWEEP_LEGS_PER_BATCH: u8 = 7;
const _: () = assert!(
    MAX_DEPOSIT_SWEEP_LEGS_PER_BATCH as usize == MAX_TOKENS_PER_VAULT_EFFECTIVE as usize,
    "el tope del barrido de depósito debe cubrir la cesta máxima"
);

// --- Allocation math ---------------------------------------------------------

/// Allocation weights must sum to exactly this value.
pub const ALLOCATION_TOTAL_BPS: u16 = 10_000;

// --- Share-inflation defense ------------------------------------------------

/// Dead shares minted to a vault-owned, unredeemable ATA on the very first
/// deposit. This is the classic Uniswap-v2 / ERC-4626 mitigation for the
/// "share inflation" attack: without it, an attacker can deposit 1 atomic
/// unit, donate a large USDC amount directly to the vault ATA, and skew the
/// shares/tvl ratio so subsequent depositors round down to 0 shares.
/// Locking 1_000 share atoms (== 0.001 USDC at 1:1 first-deposit price)
/// forces the attacker to donate at least 1_000× their mint cost to dilute
/// the ratio, which is economically prohibitive.
pub const MIN_INITIAL_SHARES: u64 = 1_000;

/// 6-decimal USD stablecoins (mainnet). For these the `sweep_to_usdc`
/// liquidation can enforce a hard `min_out` parity floor because the source
/// token's atomic units map ~1:1 to USDC atomic units (both 6 decimals). Used
/// only to gate the floor in `sweep_to_usdc`; not a vault eligibility list.
#[cfg(not(feature = "mock-jupiter"))]
pub const STABLECOIN_USD_MINTS_6DEC: [Pubkey; 3] = [
    pubkey!("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"), // USDC
    pubkey!("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"), // USDT
    pubkey!("2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"), // PYUSD
];

/// Test build: include the controlled test USDC so sweep tests can exercise
/// the stablecoin floor path on a local validator.
#[cfg(feature = "mock-jupiter")]
pub const STABLECOIN_USD_MINTS_6DEC: [Pubkey; 1] = [
    pubkey!("CVwyhMSTSCxotsRfgT7aRKVkUmVLxD2tPyUsdfLKPout"), // test USDC
];

#[cfg(test)]
mod cifras_usdc {
    // Cifras SELLADAS el 2026-09-22 (10 USDC crear, 1 USDC rebalancear,
    // techo 50 USDC). El programa no las consume (arranca en 0 y modo SOL): las
    // lee la propuesta de activación. Fijadas aquí para que un
    // cambio accidental no pase en silencio (`cargo test --lib` es bloqueante).
    #[test]
    fn cifras_selladas_2026_09_22() {
        assert_eq!(super::VAULT_CREATION_FEE_USDC_TARGET, 10_000_000);
        assert_eq!(super::REBALANCE_FEE_USDC_TARGET, 1_000_000);
        assert_eq!(super::CREATOR_FEE_USDC_MAX, 50_000_000);
        assert_eq!(super::FEE_CURRENCY_MODE_SOL, 0);
        assert_eq!(super::FEE_CURRENCY_MODE_USDC, 1);
        // §3.5 (2026-09-25): techo de los topes de S y la tabla de kinds.
        assert_eq!(super::SERVICE_USDC_MAX, 50_000_000);
        assert_eq!(super::SERVICE_CONFIG_SEED, b"service-config");
        assert_eq!(
            [super::SERVICE_KIND_CREATE, super::SERVICE_KIND_DEPOSIT, super::SERVICE_KIND_REBALANCE, super::SERVICE_KIND_RESTRUCTURE, super::SERVICE_KIND_EXIT],
            [0, 1, 2, 3, 4]
        );
    }
}
