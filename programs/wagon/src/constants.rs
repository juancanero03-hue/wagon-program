//! Protocol-level constants. All values compile into the program; runtime-configurable
//! parameters live on `ProtocolConfig` instead.

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

/// Maximum number of legs a single swap_batch instruction can carry. Three
/// keeps each batch tx well under the v0 1232-byte ceiling even for
/// multi-hop Jupiter routes. Empirically 1-2 fits comfortably; 3 fits when
/// the legs share static accounts (USDC mint, SPL Token program, etc.).
/// The frontend may pack fewer if a particular combination doesn't fit —
/// the program just refuses batches over this hard cap.
pub const MAX_LEGS_PER_BATCH: usize = 3;

/// Maximum legs per `deposit_sweep_batch` call (upgrade #31, F2b). A sweep
/// segment is only [mint, escrow_ata, dest_ata] — no Jupiter route — so four
/// fit comfortably under the 1232-byte v0 ceiling alongside the named
/// accounts, even with Phantom's ~150-byte signing overhead.
pub const MAX_SWEEP_LEGS_PER_BATCH: usize = 4;

// --- Fee math ----------------------------------------------------------------

/// Basis point denominator. 10_000 bps = 100%.
pub const BPS_DENOMINATOR: u64 = 10_000;

/// Management fee (annualised). 100 bps = 1%.
pub const DEFAULT_MANAGEMENT_FEE_BPS: u16 = 100;

/// Seconds in a (non-leap) year, used for annualised fee accrual.
pub const SECONDS_PER_YEAR: u64 = 365 * 24 * 60 * 60;

/// Mgmt fee split.
pub const MGMT_FEE_PROTOCOL_SHARE_BPS: u16 = 4_000; // 40%
pub const MGMT_FEE_CREATOR_SHARE_BPS: u16 = 6_000;  // 60%

/// Performance fee split.
pub const PERF_FEE_PROTOCOL_SHARE_BPS: u16 = 1_000; // 10%
pub const PERF_FEE_CREATOR_SHARE_BPS: u16 = 9_000;  // 90%

/// Performance fee rate bounds the creator can choose from.
pub const MIN_PERF_FEE_BPS: u16 = 500;  // 5%
pub const MAX_PERF_FEE_BPS: u16 = 2_500; // 25%

// --- entry fee (front-load) — accrue-and-claim, 2026-06-30 ------------------
// The live params live in ProtocolConfig (governance-adjustable). These are
// only the TARGET values for the admin setter; the fee ships OFF (all 0).
/// Owner PDA of a creator's rewards vault: `[b"creator-rewards", creator]`.
pub const CREATOR_REWARDS_SEED: &[u8] = b"creator-rewards";
pub const ENTRY_FEE_BPS_TARGET: u16 = 150; // 1,5% (decisión Juan 2026-07-01; antes 1%)
pub const ENTRY_FEE_CAP_USDC_TARGET: u64 = 4_980_000;           // 4.98 USDC (6 dec, precio psicológico)
pub const ENTRY_FEE_EXEMPT_BELOW_USDC_TARGET: u64 = 10_000_000; // 10 USDC
pub const ENTRY_FEE_PROTOCOL_SHARE_BPS_TARGET: u16 = 1_000;     // 10% protocol / 90% creator
/// Hard ceiling the admin setter will accept (<= 5%), a sanity guard.
pub const ENTRY_FEE_MAX_BPS: u16 = 500;

/// Ceremonia #37: tope de cordura del guard de pérdida por compra (20%).
/// El valor operativo (decisión Juan: 800 bps) lo fija set_swap_max_loss.
pub const SWAP_MAX_LOSS_MAX_BPS: u16 = 2000;

// --- Vault-creation fee (upgrade #35) ----------------------------------------

/// Fee objetivo al crear un vault: 1.50 USD (decisión Juan 2026-07-04),
/// cobrado en SOL al tipo del oráculo SOL/USD en el momento de crear.
/// El programa arranca con 0 = apagado; se fija tras el upgrade vía
/// `set_vault_creation_fee` (Squads). Referencia para el proposer.
pub const VAULT_CREATION_FEE_USD_MICROS_TARGET: u64 = 1_500_000;

/// Sanity ceiling the admin setter will accept (10 USD).
pub const VAULT_CREATION_FEE_MAX_USD_MICROS: u64 = 10_000_000;

/// Hard clamp on the lamports actually charged (1 SOL). Protects creators
/// from a glitched oracle print (a near-zero price would otherwise compute
/// an absurd SOL amount). Normal operation sits orders of magnitude below.
pub const VAULT_CREATION_FEE_MAX_LAMPORTS: u64 = 1_000_000_000;

/// Ceremonia #46 — comisión objetivo al rebalancear / cambiar cesta: 1.00 USD
/// (decisión Juan 2026-08-02), cobrada en SOL al tipo del oráculo SOL/USD en
/// `rebalance` y `restructure_init`. El programa arranca con 0 = apagada; se
/// fija tras el upgrade vía `set_rebalance_fee` (Squads). Referencia para el
/// proposer. El techo y el clamp REUSAN VAULT_CREATION_FEE_MAX_USD_MICROS
/// (10 USD) y VAULT_CREATION_FEE_MAX_LAMPORTS (1 SOL).
pub const REBALANCE_FEE_USD_MICROS_TARGET: u64 = 1_000_000;

/// Segundo programa RECEPTOR de Pyth, aceptado ADEMAS del que trae el SDK
/// (`pyth_solana_receiver_sdk::ID` = rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ).
///
/// Por que existe (ceremonia #40, 2026-07-29): Pyth actualiza su Price Feed
/// program y, como las cuentas de precio son PDAs derivadas de ese id, CAMBIAN
/// TODAS las direcciones. Las cuentas de la generacion nueva pertenecen a este
/// receptor, asi que el programa las rechazaria con `InvalidPriceAccount`.
///
/// Se aceptan las DOS generaciones a proposito: convierte la migracion de un
/// salto sincronizado sin vuelta atras en un despliegue de web reversible, y
/// permite probar con dinero real ANTES de que Pyth apague la vieja.
/// Medido el 2026-07-29 01:31 UTC: ambas publican en paralelo y su precio
/// difiere en 0,04 %.
///
/// PEAJE ACEPTADO: con dos generaciones validas, quien deposita puede elegir la
/// cuenta que le convenga (0,04 %). Es un primo pequeno de S-1, mitigado porque
/// desde el #39 las shares se acunan sobre `min(valor oraculo, USDC bruto)`.
/// SUNSET: retirar este receptor en una ceremonia posterior, cuando Pyth deje
/// de publicar la generacion vieja (pregunta abierta a su soporte).
pub const PYTH_RECEIVER_V2: Pubkey = pubkey!("rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp");

/// Pyth `Crypto.SOL/USD` feed id (stable identifier, hex
/// ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d).
/// The account passed to create_vault can be ANY receiver-program
/// `PriceUpdateV2` carrying this feed -- the frontend passes Pyth's
/// sponsored SOL/USD account, which is updated continuously.
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
/// amplíe la ALT (botón 42). Verificado contra transacciones reales de mainnet.
///
/// El tope de 7 existía SOLO en el frontend. Crear un vault no requiere
/// permiso, así que una llamada directa al programa podía fabricar un vault de
/// 8-10 patas cuyos inversores quedaban sin salida. Aquí se hace efectivo
/// on-chain, alineado con la decisión de producto sellada («tope 7 tokens por
/// vault»).
///
/// MEDIDO el 2026-07-29 antes de fijarlo: de los 49 vaults vivos, el máximo es
/// 7 patas (12 vaults) — ninguno queda fuera de la regla ni pierde la
/// posibilidad de reestructurar.
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
pub const ORACLE_MAX_CONF_BPS: [u64; 4] = [50, 100, 200, 300];

/// Upgrade #30 — freshness window for the last-swap price cache used by
/// mints without a Pyth feed (decision Juan 2026-06-10: 24 h).
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

/// After this many seconds in `Liquidating`, residually-illiquid tokens can be
/// distributed in kind rather than swept to USDC.
pub const LIQUIDATION_TIMEOUT_SECONDS: i64 = 7 * 24 * 60 * 60; // 7 days

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
