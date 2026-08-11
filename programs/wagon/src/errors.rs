//! Domain-level errors. Every `require!` check in the program cites one of these.
//! Error numbers are stable — do NOT renumber, only append.

use anchor_lang::prelude::*;

#[error_code]
pub enum WagonError {
    // --- protocol state ------------------------------------------------------
    #[msg("Protocol is paused.")]
    ProtocolPaused = 6000,

    #[msg("Caller is not the protocol authority.")]
    UnauthorizedProtocolAdmin = 6001,

    #[msg("Caller is not the vault creator.")]
    UnauthorizedVaultCreator = 6002,

    // --- vault lifecycle -----------------------------------------------------
    #[msg("Vault is paused.")]
    VaultPaused = 6010,

    #[msg("Vault is liquidating; operation not allowed.")]
    VaultLiquidating = 6011,

    #[msg("Vault is closed.")]
    VaultClosed = 6012,

    #[msg("Vault is not in liquidating state.")]
    VaultNotLiquidating = 6013,

    #[msg("Vault still has outstanding shares; cannot finalize close.")]
    SharesStillOutstanding = 6014,

    #[msg("Liquidation timeout has not elapsed yet.")]
    LiquidationTimeoutNotReached = 6015,

    // --- vault creation validation ------------------------------------------
    #[msg("Too many tokens in vault allocations.")]
    TooManyTokens = 6020,

    #[msg("Empty allocation not allowed.")]
    EmptyAllocations = 6021,

    #[msg("Allocation weights must sum to exactly 10_000 bps.")]
    AllocationSumMismatch = 6022,

    #[msg("Duplicate token in allocations.")]
    DuplicateToken = 6023,

    #[msg("Performance fee rate outside allowed bounds (500-2500 bps).")]
    PerformanceFeeOutOfRange = 6024,

    #[msg("Max slippage outside allowed bounds (50-500 bps).")]
    SlippageOutOfRange = 6025,

    #[msg("Vault name too long.")]
    NameTooLong = 6026,

    #[msg("Vault description too long.")]
    DescriptionTooLong = 6027,

    #[msg("Vault image url too long.")]
    ImageUrlTooLong = 6028,

    #[msg("Vault tags too long.")]
    TagsTooLong = 6029,

    // --- deposit / withdraw validation --------------------------------------
    #[msg("Deposit amount must be greater than zero.")]
    ZeroDeposit = 6040,

    #[msg("Withdraw amount must be greater than zero.")]
    ZeroWithdraw = 6041,

    #[msg("Insufficient shares for withdrawal.")]
    InsufficientShares = 6042,

    #[msg("TVL cap exceeded.")]
    TvlCapExceeded = 6043,

    #[msg("Slippage tolerance exceeded during swap.")]
    SlippageExceeded = 6044,

    #[msg("Token below protocol liquidity floor.")]
    BelowLiquidityFloor = 6045,

    // --- allowed-mint registry ----------------------------------------------
    #[msg("Mint is not in the allowed-mint registry.")]
    MintNotAllowed = 6050,

    #[msg("Allowed-mint registry is full; remove an entry before adding a new one.")]
    RegistryFull = 6051,

    #[msg("Mint is already present in the registry.")]
    MintAlreadyInRegistry = 6052,

    #[msg("Mint is not present in the registry.")]
    MintNotInRegistry = 6053,

    #[msg("Mint category discriminant is not recognised.")]
    InvalidMintCategory = 6054,

    // --- math ---------------------------------------------------------------
    #[msg("Arithmetic overflow.")]
    MathOverflow = 6060,

    #[msg("Division by zero.")]
    DivisionByZero = 6061,

    // --- Jupiter CPI --------------------------------------------------------
    #[msg("Jupiter route account missing or malformed.")]
    InvalidJupiterRoute = 6080,

    #[msg("Unexpected Jupiter program id.")]
    InvalidJupiterProgram = 6081,

    // --- Tier B mint validation (anti-rug, programmatic) --------------------
    #[msg("Tier B: mint AccountInfo pubkey does not match the args.mints[i] declared.")]
    TierBMintMismatch = 6090,

    #[msg("Tier B: mint is not owned by the SPL Token program.")]
    TierBNotSPLToken = 6091,

    #[msg("Tier B: mint account data is malformed or not initialised.")]
    TierBMalformedMint = 6092,

    #[msg("Tier B: mint has a freeze_authority set; rejected to protect holders from a freeze rug.")]
    TierBFreezableMint = 6093,

    #[msg("Tier B: mint supply is zero; rejected to avoid empty-vault scams.")]
    TierBEmptyMint = 6094,

    #[msg("Sweep cranker must be the vault creator or the protocol authority.")]
    UnauthorizedCranker = 6095,

    // --- rebalance (creator-only) -------------------------------------------
    #[msg("Rebalance cannot change the mint set; use close_vault + create_vault instead.")]
    RebalanceMintSetImmutable = 6030,

    #[msg("Rebalance weights length must match vault.allocation_count.")]
    RebalanceWeightsLengthMismatch = 6031,

    #[msg("Rebalance swap source and destination slot indices must differ.")]
    RebalanceSwapSameSlot = 6032,

    #[msg("Rebalance swap slot index out of range.")]
    RebalanceSwapSlotOutOfRange = 6033,

    // --- registry low-level (byte-handler errors) ---------------------------
    #[msg("Registry account data is shorter than expected. Account likely uninitialised or wrong layout version.")]
    RegistryDataTooShort = 6055,

    #[msg("Registry header reports a count out of bounds. Likely a corrupted account; do not write more.")]
    RegistryCorrupted = 6056,

    #[msg("Vault account data is shorter than expected. Account likely uninitialised or wrong layout version.")]
    VaultDataTooShort = 6057,

    // --- misc ---------------------------------------------------------------
    #[msg("Unsupported operation in this program version.")]
    Unsupported = 6200,

    #[msg("Symbol must be 1-10 ASCII characters.")]
    SymbolOutOfRange = 6058,
    #[msg("Symbol contains non-alphanumeric characters.")]
    SymbolInvalidChars = 6059,
    #[msg("Metadata URI must be 1-200 bytes.")]
    MetadataUriOutOfRange = 6062,
    #[msg("Invalid UTF-8 in stored vault name.")]
    InvalidUtf8 = 6063,

    // --- Capa 5: fractional deposit/withdraw session errors -----------------
    #[msg("Deposit session does not belong to the calling investor.")]
    DepositSessionWrongInvestor = 6100,
    #[msg("Deposit session does not belong to the referenced vault.")]
    DepositSessionWrongVault = 6101,
    #[msg("Swap batch was empty — must contain at least one leg.")]
    EmptyBatch = 6102,
    #[msg("Swap batch exceeds MAX_LEGS_PER_BATCH.")]
    BatchTooLarge = 6103,
    #[msg("leg_indices and swap_plans length mismatch.")]
    BatchLengthMismatch = 6104,
    #[msg("Leg index is out of range for this vault's allocation_count.")]
    LegIndexOutOfRange = 6105,
    #[msg("Leg already completed in this session; cannot re-execute.")]
    LegAlreadyCompleted = 6106,
    #[msg("Cannot settle until every leg has been executed.")]
    SessionNotComplete = 6107,
    #[msg("Cannot abort after any leg has been executed; complete the remaining batches or wait for support.")]
    SessionAlreadyStarted = 6108,
    #[msg("Allocation count too large for the legs_completed bitmap (max 16).")]
    TooManyAllocations = 6109,
    #[msg("Provided destination ATA does not match the vault's allocation at this index.")]
    LegDestAtaMismatch = 6110,
    #[msg("Withdraw session does not belong to the calling investor.")]
    WithdrawSessionWrongInvestor = 6111,
    #[msg("Withdraw session does not belong to the referenced vault.")]
    WithdrawSessionWrongVault = 6112,

    // Upgrade #23 (Token-2022 support). The vault accepts SPL Token classic
    // OR SPL Token-2022 mints, but for the 2022 variant we statically reject
    // extensions that would let the issuer drain or freeze the vault out of
    // band. The codes below surface when create_vault rejects a 2022 mint.
    #[msg("Tier B: Token-2022 transfer fee extension is not supported.")]
    TierB2022TransferFee = 6113,
    #[msg("Tier B: Token-2022 confidential transfer extension is not supported.")]
    TierB2022ConfidentialTransfer = 6114,
    #[msg("Tier B: Token-2022 default account state is Frozen — depositors would receive a frozen ATA.")]
    TierB2022DefaultFrozen = 6115,
    #[msg("Tier B: Token-2022 non-transferable extension means the vault could never swap.")]
    TierB2022NonTransferable = 6116,
    #[msg("Tier B: Token-2022 permanent delegate extension would let the issuer drain the vault.")]
    TierB2022PermanentDelegate = 6117,
    #[msg("Tier B: Token-2022 transfer hook extension is not supported (would invoke arbitrary program on every swap).")]
    TierB2022TransferHook = 6118,
    #[msg("Tier B: Token-2022 pausable extension would let the issuer freeze all transfers.")]
    TierB2022Pausable = 6119,
    #[msg("Tier B: failed to parse Token-2022 extension TLV (malformed account data).")]
    TierBExtensionParseError = 6120,

    // Upgrade #30 (TVL mark-to-market with Pyth). FeedRegistry maps each
    // mint to the only Pyth feed id the program will accept for it.
    #[msg("Feed registry account data is shorter than the expected layout.")]
    FeedRegistryDataTooShort = 6121,
    #[msg("Feed registry account data failed an internal consistency check.")]
    FeedRegistryCorrupted = 6122,
    #[msg("Feed registry is full (MAX_PRICE_FEEDS).")]
    FeedRegistryFull = 6123,
    #[msg("No feed registered for this mint.")]
    FeedNotFound = 6124,
    #[msg("Feed flags use reserved bits that must be zero.")]
    InvalidFeedFlags = 6125,
    #[msg("Feed id must not be all zeros.")]
    InvalidFeedId = 6126,
    #[msg("Remaining accounts do not match the vault's allocation mints.")]
    AllocMintMismatch = 6127,
    #[msg("Account is not a valid Pyth PriceUpdateV2 for the expected feed.")]
    InvalidPriceAccount = 6128,
    #[msg("Pyth price is stale, unverified, or for the wrong feed.")]
    StaleOrUntrustedPrice = 6129,
    #[msg("Pyth price confidence interval is too wide to trust.")]
    PriceConfidenceTooWide = 6130,
    #[msg("No reliable price for an allocation (no feed and no fresh last-swap cache). Deposits are blocked; withdrawals remain open.")]
    NoReliablePrice = 6131,
    #[msg("Mark-to-market price accounts are required but were not provided.")]
    MissingPriceAccounts = 6132,

    // Upgrade #31 (cambio de estrategia / restructure)
    #[msg("Vault en reestructuración: deposits/withdraws bloqueados unos instantes. Reintenta en breve.")]
    RestructuringInProgress = 6133,
    #[msg("El vault no está en reestructuración.")]
    NotRestructuring = 6134,
    #[msg("La sesión de reestructuración no corresponde a este vault.")]
    RestructureSessionMismatch = 6135,
    #[msg("Índice de leg fuera de rango para la reestructuración.")]
    RestructureLegOutOfRange = 6136,
    #[msg("Ese leg de la reestructuración ya se ejecutó.")]
    RestructureLegAlreadyDone = 6137,
    #[msg("Faltan ventas o compras por completar antes del settle.")]
    RestructureIncomplete = 6138,
    #[msg("Un token saliente todavía tiene balance; véndelo por completo antes del settle.")]
    RestructureResidualBalance = 6139,
    #[msg("Solo el creador puede abortar antes del timeout.")]
    RestructureAbortTooEarly = 6140,
    #[msg("Sesión anterior a la última reestructuración del vault: inválida. Usa abort para recuperar los fondos.")]
    StaleSessionAfterRestructure = 6141,
    #[msg("Cesta nueva inválida (tamaño, longitudes o pesos).")]
    RestructureBadBasket = 6142,

    // Upgrade #31 F2b (escrow segregado por sesión de depósito)
    #[msg("La sesión de depósito está en proceso de abort: no admite más swaps ni settle.")]
    DepositSessionAborting = 6143,
    #[msg("La cuenta de escrow no es la ATA canónica de la sesión para ese mint.")]
    EscrowAtaMismatch = 6144,
    #[msg("Faltan barridos de escrow por completar antes de cerrar la sesión.")]
    EscrowNotSwept = 6145,
    #[msg("Ese leg no se puede barrer (trivial, sin swap ejecutado, o ya barrido).")]
    LegNotSweepable = 6146,
    #[msg("Solo el inversor puede abortar la sesión antes del timeout de 30 minutos.")]
    DepositAbortTooEarly = 6147,

    // Fix C-1 (auditoría 2026-06-29): el retiro no acotaba la cantidad vendida por leg.
    #[msg("La cantidad vendida en este leg supera la parte proporcional del inversor.")]
    WithdrawLegExceedsShare = 6148,

    // Fee de entrada + recompensas del creador (accrue & claim) — 2026-06-30
    #[msg("Parámetros de fee de entrada inválidos (bps > máximo o reparto > 100%).")]
    InvalidEntryFeeParams = 6149,
    #[msg("El fee de entrada está activo pero faltan las cuentas de destino (tesorería / hucha del creador).")]
    MissingEntryFeeAccounts = 6150,
    #[msg("La cuenta de recompensas no es la ATA canónica de la hucha del creador.")]
    CreatorRewardsAtaMismatch = 6151,
    #[msg("No hay recompensas que reclamar.")]
    NoRewardsToClaim = 6152,
    #[msg("La cuenta de tesorería del fee de entrada no coincide con la registrada en el protocolo.")]
    EntryFeeTreasuryMismatch = 6153,

    // Warm-up M-5 (auditoría 2026-06-29).
    #[msg("La cuenta de mint no coincide con el argumento o no es un mint SPL inicializado.")]
    SetFeedMintInvalid = 6154,
    #[msg("Ese feed_id ya está asignado a otro mint del registro.")]
    DuplicateFeedId = 6155,

    // Warm-up M-4: finalize_close puede cerrar las ATAs vacías del vault.
    #[msg("La ATA del vault aún tiene saldo: no se puede cerrar en finalize_close.")]
    AtaNotEmpty = 6156,

    // Retirada del AllowedMintRegistry (2026-07-03).
    #[msg("El registro de mints permitidos no existe o ya está cerrado.")]
    AllowedMintRegistryNotOpen = 6157,

    // Fee de creación de vault (upgrade #35).
    #[msg("Parámetros del fee de creación inválidos (importe > máximo o tesorería vacía).")]
    InvalidVaultCreationFeeParams = 6158,
    #[msg("La tesorería del fee de creación no coincide con la registrada en el protocolo.")]
    VaultCreationFeeTreasuryMismatch = 6159,

    // 6160 y 6161 RETIRADOS en la ceremonia #40 (2026-07-29): eran
    // InvalidSwitchboardQuote y SwitchboardQueueMismatch del 2º oráculo
    // (upgrade #36). Switchboard salió del protocolo — el bit 3 del registro
    // pasó a significar «sin oráculo utilizable» y no hay ningún camino que
    // pueda emitirlos. NO REUTILIZAR estos dos números: la numeración de
    // WagonError es estable y un código reciclado haría que un historial
    // viejo se lea como un error nuevo.

    // Ceremonia #37 — cinturones on-chain (2026-07-09).
    // Pieza 1: create_vault exige que cada mint no-USDC tenga oráculo registrado.
    #[msg("Un mint del vault no tiene oráculo registrado en el FeedRegistry.")]
    VaultMintNotInFeedRegistry = 6162,
    // Pieza 3: deposit_settle exige acuñar al menos 1 participación al inversor.
    #[msg("El depósito no acuñaría ninguna participación (precio por share demasiado alto); revierte para no perder el USDC.")]
    ZeroSharesMinted = 6163,
    // Pieza 2: guard de pérdida máxima por compra (piso de valor-oráculo por leg).
    #[msg("La compra destruiría demasiado valor: los tokens recibidos valen (a precio de oráculo) menos que el USDC gastado menos el margen permitido.")]
    SwapValueLossExceeded = 6164,
    #[msg("El layout de cuentas del swap no trae los oráculos que el guard de pérdida exige.")]
    SwapGuardAccountsMissing = 6165,

    // C2 — retiro concurrente con hucha por token (ceremonia #38).
    #[msg("La sesión de retiro está en proceso de abort: no admite más ventas.")]
    WithdrawSessionAborting = 6166,
    #[msg("Solo el inversor puede recuperar la sesión de retiro antes del timeout de 30 minutos.")]
    WithdrawAbortTooEarly = 6167,

    // C-A — barrido de sustitución de cuenta en la ruta de Jupiter (ceremonia #39).
    #[msg("La ruta del swap vació una cuenta de tokens del vault que no era la fuente declarada.")]
    VaultAtaDrainedInRoute = 6168,
    #[msg("El swap no consumió nada de la cuenta de origen declarada.")]
    SwapSourceNotConsumed = 6169,
    #[msg("No se puede verificar el precio de este token: solo la autoridad del protocolo puede venderlo.")]
    SweepFloorNotEnforceable = 6170,
    #[msg("Ese token forma parte de la estrategia del vault: usa rebalanceo o cambio de estrategia.")]
    MintStillInAllocations = 6171,

    // C-B — vender COMPROMETE a asentar + pago en especie (ceremonia #39).
    #[msg("La sesión de retiro ya extrajo valor de una hucha: debe asentarse, no puede cancelarse.")]
    WithdrawAlreadySold = 6172,
    #[msg("Solo el inversor puede cobrar una pata en especie antes del timeout de 24 horas.")]
    WithdrawInKindTooEarly = 6173,
    #[msg("Solo el inversor puede asentar este retiro; un tercero solo si la sesión ya está comprometida, completa y barrida.")]
    WithdrawSettleUnauthorized = 6174,

    // F5 — comisión de plataforma de Jupiter (ceremonia #40).
    #[msg("La orden de Jupiter lleva comisión de plataforma: solo se aceptan rutas con platform_fee_bps = 0.")]
    JupiterPlatformFeeNotZero = 6175,

    // OT-1 — robo del creador (ceremonia #43). No se puede sacar el vault de Active
    // (cerrar / reestructurar / finalizar) mientras haya un depósito COMPROMETIDO
    // sin asentar: su valor está dentro del vault sin participaciones y se repartiría
    // a los demás titulares.
    #[msg("El vault tiene un depósito comprometido sin asentar: espera a que se asiente antes de cerrar o reestructurar.")]
    VaultHasCommittedDeposit = 6176,

    // Ceremonia #46 — comisión de rebalanceo / cambio de cesta (1 USD en SOL).
    #[msg("Parámetros de la comisión de rebalanceo inválidos: el importe supera el máximo (10 USD) o la tesorería es la cuenta cero con la comisión encendida.")]
    InvalidRebalanceFeeParams = 6177,
    #[msg("La tesorería pasada no coincide con la configurada para la comisión de rebalanceo.")]
    RebalanceFeeTreasuryMismatch = 6178,

    // Ceremonia #47 (H3) — confiscación por pata de peso 0. Una pata poblada NO
    // puede tener peso 0 (create_vault / restructure_init / rebalance): con saldo,
    // withdraw_init la saltaría como trivial y el que retira perdería su parte de
    // ese token. Prevención en origen; los vaults vivos (todas las patas peso>0)
    // no se ven afectados.
    #[msg("Una pata del vault no puede tener peso 0: quítala con un cambio de cesta o dale peso.")]
    ZeroWeightAllocation = 6179,

    // Ceremonia #50 (A5) — salida fail-open del contador de comprometidas.
    // `deposit_force_release` solo procede sobre una sesión COMPROMETIDA
    // (legs_swept != 0 && aborting == 0) y pasado el timeout: si no, revierte.
    #[msg("La sesión de depósito no es elegible para liberación forzada (no comprometida o timeout no cumplido).")]
    DepositForceReleaseNotEligible = 6180,

    // Ceremonia #50 (A5) — la prueba de congelación no es válida: ninguna de las
    // cuentas de prueba (escrow o destino de la pata bloqueada, o USDC en el
    // camino del asiento) está realmente CONGELADA (state byte @108 == 2). Sin
    // freeze real la sesión NO está atascada (settle es permissionless) → forzar
    // la donación sería griefing; se revierte.
    #[msg("La prueba de congelación no es válida: ninguna cuenta de prueba está congelada.")]
    DepositForceReleaseNotFrozen = 6181,
}
