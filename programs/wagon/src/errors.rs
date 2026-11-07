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

    // 6011 RETIRADO (VaultLiquidating): ningún camino lo emite. NO REUTILIZAR el número: la numeración de WagonError es estable.

    #[msg("Vault is closed.")]
    VaultClosed = 6012,

    #[msg("Vault is not in liquidating state.")]
    VaultNotLiquidating = 6013,

    #[msg("Vault still has outstanding shares; cannot finalize close.")]
    SharesStillOutstanding = 6014,

    // 6015 RETIRADO (LiquidationTimeoutNotReached): ningún camino lo emite. NO REUTILIZAR el número: la numeración de WagonError es estable.

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

    // 6045 RETIRADO (BelowLiquidityFloor): ningún camino lo emite. NO REUTILIZAR el número: la numeración de WagonError es estable.

    // 6050 a 6056 RETIRADOS con el AllowedMintRegistry (2026-07-03): ningún camino los
    // emite. NO REUTILIZAR estos números: la numeración de WagonError es estable y un código
    // reciclado haría que un historial viejo se lea como un error nuevo.

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

    // 6093 RETIRADO (TierBFreezableMint): ningún camino lo emite. NO REUTILIZAR el número: la numeración de WagonError es estable.

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

    // (6055 y 6056: RETIRADOS con el AllowedMintRegistry, ver arriba.)

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
    // 6063 RETIRADO (InvalidUtf8): ningún camino lo emite. NO REUTILIZAR el número: la numeración de WagonError es estable.

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
    #[msg("Solo el inversor puede abortar la sesión antes del timeout de 10 minutos.")]
    DepositAbortTooEarly = 6147,

    // 6148 RETIRADO (WithdrawLegExceedsShare): ningún camino lo emite. NO REUTILIZAR el número: la numeración de WagonError es estable.

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
    #[msg("Un tercero solo puede cancelar la sesión de retiro pasadas 48 horas (10 minutos si ya está cancelando); el inversor, a cualquier hora.")]
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
    #[msg("Solo el inversor puede asentar este retiro; un tercero solo si la sesión ya está comprometida, completa y barrida (o, sin patas de token, pasados 10 minutos).")]
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
    // puede quedar a peso 0 (restructure_init / rebalance / rebalance_swap / la
    // compra de restructure_swap_batch; create_vault lo admite a propósito como
    // slot trivial que nunca se financia): con saldo,
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

    // Ceremonia #53 — el vault sostiene VALOR FUERA DE TABLA (un token creado por
    // un producer conocido: cambio de cesta abortado con compras, o retiro-abort de
    // un mint eliminado). La ENTRADA queda vetada hasta rescatar ese valor y bajar la
    // bandera (close_stranded permissionless, o admin_clear_stranded). La SALIDA sigue
    // abierta. No es «reintenta»: exige limpieza. Reusa esta condición en deposit_init,
    // el commit de deposit_sweep_batch y restructure_init.
    #[msg("El vault tiene valor fuera de tabla pendiente de rescatar: los depósitos están en pausa hasta limpiarlo.")]
    VaultHasStrandedValue = 6182,

    // Ceremonia #53 — close_stranded exige que la ATA de cada mint varado del
    // manifiesto esté a 0 (rescatada) antes de bajar la bandera.
    #[msg("La cuenta del token varado aún no está vacía: rescátalo antes de limpiar.")]
    StrandedAtaNotEmpty = 6183,

    // Ceremonia #53 — close_stranded / admin_clear_stranded exigen la bandera puesta.
    #[msg("El vault no tiene valor fuera de tabla marcado.")]
    NotStranded = 6184,

    // Ceremonia #54 (DT-D) — A5 modo (c): la prueba del CAMINO 1 no congelado exige
    // que el propio MINT bloquee la transferencia (NonTransferable / TransferHook
    // armado / Pausable pausado). Si no bloquea, no hay brick que liberar.
    #[msg("El mint de la pata no bloquea la transferencia: no hay brick que liberar.")]
    DepositForceReleaseMintNotBlocking = 6185,

    // Ceremonia #54 (DT-D) — A5 modos (b)/(c): exigen que el escrow de la pata tenga
    // saldo > 0 (una transferencia realmente pendiente que el brick impide).
    #[msg("El escrow de la pata no tiene transferencia pendiente: nada que liberar.")]
    DepositForceReleaseNoPendingTransfer = 6186,

    // Ceremonia USDC (2026-09-22) — comisiones del creador en USDC. Estas tres
    // operaciones NO son salidas: un tesoro no pagable REVIERTE (fail-closed), a
    // diferencia del DT-B del retiro.
    #[msg("La tesorería USDC del protocolo no puede recibir la comisión (congelada o inexistente).")]
    TreasuryNotPayable = 6187,

    #[msg("Parámetros de la moneda de comisiones inválidos: modo 0 (SOL) o 1 (USDC) e importes dentro del máximo.")]
    InvalidFeeCurrencyParams = 6188,

    #[msg("La cuenta USDC del creador no existe o no es su ATA canónica.")]
    CreatorUsdcAtaMismatch = 6189,

    #[msg("La cuenta de tesorería USDC no es la del protocolo.")]
    FeeTreasuryUsdcMismatch = 6190,

    // Ceremonia USDC, D8 (2026-09-22) — `set_vault_texts`: escritura única POR CAMPO
    // de la descripción y los tags del vault (cada campo, una vez).
    #[msg("Ese texto del vault ya está escrito con otro contenido: la descripción y los tags son de escritura única por campo.")]
    VaultTextsAlreadySet = 6191,

    #[msg("Nada que escribir: la descripción y los tags vienen vacíos.")]
    VaultTextsEmpty = 6192,

    #[msg("La ventana para escribir los textos del vault ha vencido (24 h desde la creación): la descripción es inmutable.")]
    VaultTextsWindowClosed = 6193,

    // Ceremonia USDC, §3.3 (2026-09-24) — `FundingRecord`: quién financió el rent temporal
    // de una sesión patrocinada y a dónde vuelve al cerrarla. Los terminales NUNCA se
    // quedan sin salida por el registro (sin él, o sin emparejar, el rent va al propietario).
    #[msg("La cuenta del registro de financiación no es su PDA canónica o no es un registro válido.")]
    FundingRecordNotCanonical = 6194,

    #[msg("El destino del reembolso debe ser el pagador o la autoridad del protocolo (vault de Squads), y no ejecutable.")]
    FundingRefundToNotAllowed = 6195,

    #[msg("El registro de financiación va si y solo si el pagador no es el propietario (patrocinio).")]
    FundingRecordPresenceMismatch = 6196,

    #[msg("La cuenta de reembolso no es un destino admitido: refund_to del registro emparejado (o la autoridad del protocolo), o el propietario si no hay registro.")]
    FundingRefundTargetMismatch = 6197,

    // Ceremonia USDC, §3.3 B3 (2026-09-24) — `funding_reclaim_stale` solo reclama HUÉRFANOS.
    #[msg("El registro de financiación sigue vivo: su sesión existe con el mismo sello; lo cierra su propio terminal.")]
    FundingRecordAlive = 6198,

    // Ceremonia USDC, §3.5 (2026-09-25) — servicio S (gas patrocinado cobrado en USDC) como
    // ARGUMENTO firmado de cada init. 6200 está ocupado por `Unsupported`: se salta.
    #[msg("Operación patrocinada sin servicio: un pagador distinto del propietario exige service_usdc mayor que 0 con cualquier tope (con el tope a 0 o en pausa el patrocinio queda bloqueado).")]
    ServiceRequired = 6199,

    #[msg("El servicio S supera el tope on chain de esa operación (ServiceConfig.max_service_usdc).")]
    ServiceAmountAboveMax = 6201,

    #[msg("El servicio S está en pausa: no se acepta ningún S mayor que 0 hasta que Squads lo reactive.")]
    ServicePaused = 6202,

    #[msg("La tesorería del servicio no es la tesorería USDC del protocolo (protocol.treasury_usdc_ata).")]
    ServiceTreasuryMismatch = 6203,

    #[msg("La cuenta USDC del usuario que paga el servicio no es su ATA canónica de USDC, no es suya o no es de USDC.")]
    ServiceUserAtaMismatch = 6204,

    #[msg("Parámetros del servicio inválidos: cada tope hasta 50 USDC y paused 0 o 1.")]
    InvalidServiceParams = 6205,

    // PR 5B (§3.5, D3 / M-04, 2026-09-25) — S de SALIDA. Solo tiene dónde guardarse con
    // patrocinio (el `FundingRecord` de la sesión): sin él, un S > 0 es un cliente roto.
    #[msg("Servicio de salida sin patrocinio: exit_service_usdc solo puede ser mayor que 0 cuando un pagador distinto del inversor crea el registro de financiación.")]
    ExitServiceWithoutSponsor = 6206,

    // Ceremonia USDC, §3.8 (S1, 2026-09-25) — ningún firmante en la ruta de Jupiter salvo el
    // PDA que firma por semillas: una firma de la TRANSACCIÓN (pagador del gas, inversor,
    // cofirmante) nunca se presta a la CPI.
    #[msg("La ruta de Jupiter lleva una cuenta firmante: ninguna firma de la transacción (pagador, inversor o cofirmante) se presta a la CPI; solo firma el PDA del vault o de la sesión, por semillas.")]
    SignerInJupiterRoute = 6207,

    // 5A-bis (2026-09-26) — `rebalance` no tiene sesión, así
    // que N instrucciones en un mensaje cobrarían S N veces: candado por slot en el vault.
    #[msg("El servicio S de rebalanceo ya se cobró en este slot para este vault: una sola instrucción rebalance con S por slot.")]
    ServiceAlreadyChargedThisSlot = 6208,

    // DT-E (ceremonia USDC, 2026-09-28) — la comisión de entrada E queda reservada en la hucha USDC
    // de la sesión hasta el settle: un swap del depósito no puede gastarla.
    #[msg("Un swap del depósito no puede gastar la comisión de entrada reservada en la hucha de la sesión.")]
    EntryFeeReserveSpent = 6209,

    // DT-E: el init comprueba que la hucha del creador puede recibir su corte antes de comprometer
    // el depósito (la tesorería usa `TreasuryNotPayable`). Al asentar, un destino no pagable desvía.
    #[msg("La hucha USDC del creador no puede recibir la comisión de entrada (congelada o inexistente).")]
    CreatorRewardsNotPayable = 6210,

    // DT-E / G2-c: `deposit_session_migrate` solo estira sesiones de un tamaño ANTERIOR del layout (457, 473).
    #[msg("La cuenta no es una sesión de depósito de un tamaño anterior del layout de este programa: no hay nada que migrar.")]
    DepositSessionNotLegacy = 6211,

    // DT-E: el settle devuelve al inversor lo que no puede entrar en el vault (ATA congelada):
    // solo a su ATA CANÓNICA de USDC.
    #[msg("La cuenta USDC del inversor no es su ATA canónica de USDC.")]
    InvestorUsdcAtaNotCanonical = 6212,

    // DT-E: un init no es una salida: con la ATA USDC del vault congelada no se admiten depósitos.
    #[msg("La cuenta USDC del vault no puede recibir (congelada o inexistente): no se admiten depósitos nuevos.")]
    VaultUsdcAtaNotPayable = 6213,

    // DT-E: `deposit_escrow_reclaim` solo recupera una hucha de depósito CON saldo y SIN sesión abierta
    // en su PDA (la cuenta de sesión tiene que ser esa PDA), hacia una cuenta USDC del inversor que pueda recibir.
    #[msg("La hucha no se puede recuperar ahora: la cuenta de sesión no es la de la pareja o tiene una sesión abierta, la hucha está vacía o la cuenta USDC del inversor no puede recibir.")]
    DepositEscrowNotReclaimable = 6214,

    // DT-E: una sesión que no barrió nada al vault (todas sus patas son USDC) y cuyo capital no puede
    // entrar en él no se asienta: se cancela con `deposit_abort`, que devuelve I + E.
    #[msg("Este depósito no invirtió nada y su USDC no puede entrar en el vault: se cancela con deposit_abort, que devuelve el capital y la comisión.")]
    DepositUncommittedMustAbort = 6215,

    // G1 (auditoría 2026-10-09, F1A-01): la ENTRADA espera mientras un retiro abierto sin vender
    // conserve shares revivibles (`withdraw_abort` las re-acuñaría enteras): no hay precio justo posible.
    #[msg("Hay un retiro en curso en este vault con participaciones aún recuperables: no se admiten depósitos ni commits hasta que venda, cobre en especie o cancele.")]
    VaultHasRevivableBurn = 6216,

    // G1 (auditoría 2026-10-09, F7A-01/F7B-01): una sesión que aparcó una pata con saldo (forfeit DT-A(a))
    // no se deshace: el forfeit es definitivo; su terminal es el asiento o el cobro en especie.
    #[msg("Este retiro aparcó una pata bloqueada y renunció a ella: no se puede cancelar, solo asentar o cobrar en especie.")]
    WithdrawParkedCannotAbort = 6217,

    // G1 (2026-10-09, transición): una sesión de retiro anterior al upgrade (`generation == 0`) no está en
    // el contador de la entrada; no puede EMPEZAR una cancelación (sí terminar una ya empezada, reservada
    // en `pending_burned`, que la entrada también mira).
    #[msg("Este retiro es anterior a la actualización del programa y ya no se puede cancelar: véndelo, cóbralo en especie o asiéntalo.")]
    LegacyWithdrawCannotAbort = 6218,

    // G3 (2026-10-15): mínimo de depósito en el PROGRAMA (`MIN_DEPOSIT_USDC`, 10 USDC medidos sobre lo que
    // paga el inversor). Hasta aquí lo ponía solo la web.
    #[msg("El depósito mínimo es de 10 USDC.")]
    DepositBelowMinimum = 6219,

    // G3 (F2A-03): la hucha USDC de un retiro ya CERRADO solo se barre al vault si está huérfana (sin sesión
    // abierta en esa pareja), con saldo y con una cuenta USDC del vault que pueda recibir.
    #[msg("La hucha USDC de este retiro no se puede barrer: la sesión sigue abierta, está vacía o la cuenta USDC del vault no puede recibir.")]
    WithdrawEscrowNotSweepable = 6220,

    // G3-B1a (F2B-01): el barrido que EMPIEZA una cancelación (`aborting` 0 → 1) tiene que dejar barridas TODAS las
    // patas pendientes en una sola instrucción (latch atómico): con lotes parciales, el primero latcheaba y reservaba
    // `pending_burned` y, con la ATA del vault de una pata congelada, el segundo no pasaba nunca.
    #[msg("Para cancelar un retiro, el primer barrido de vuelta tiene que traer todas las patas pendientes en una sola instrucción.")]
    WithdrawAbortSweepMustCoverAllLegs = 6221,

    // G3-B1b (DT-A(b)): `withdraw_force_release` solo libera una WithdrawSession VIVA de su PDA canónica, pasado el plazo
    // (inversor 24 h, tercero 48 h). Un recibo ya liberado, otra cuenta en la PDA o una sesión dentro de plazo: 6222.
    #[msg("Este retiro no se puede liberar: no es una sesión viva de esta pareja o todavía no ha pasado el plazo.")]
    WithdrawForceReleaseNotEligible = 6222,

    // G3-B1b: la prueba de bloqueo tiene que ser la cuenta EXACTA congelada que impide el terminal: la hucha de la pata, la
    // cuenta del vault de esa pata (con saldo en la hucha y sin cobro en especie posible) o la hucha USDC (sin cancelar).
    #[msg("La prueba de bloqueo no vale: la cuenta no está congelada, no es la de esa pata o la pata todavía tiene salida.")]
    WithdrawForceReleaseNotFrozen = 6223,

    // G3-B1b: `withdraw_escrow_claim` solo cobra una hucha PENDIENTE del recibo cuando la hucha y el destino se pueden mover.
    #[msg("Esta hucha no se puede cobrar: no está pendiente en el recibo, sigue congelada o el destino no puede recibir.")]
    WithdrawRightNotClaimable = 6224,

    // G3-B2: con una hucha ya congelada al empezar el retiro, `withdraw_init` paga ese slice EN ESPECIE a una cuenta del inversor
    // que el cliente añade al final de las cuentas: una por hucha congelada (las patas en orden y la USDC la última). Solo se
    // valida la de una posición que paga algo: en una sin pago (polvo, pata aparcada, USDC ocioso a 0) vale cualquier cuenta.
    #[msg("Falta o sobra la cuenta de destino en especie, o no es una cuenta del inversor para ese token.")]
    WithdrawInKindDestMismatch = 6225,

    // G3-B2: el inversor firma el retiro y puede dar cualquier cuenta suya; una congelada no puede recibir. (Si el mint hace nacer
    // congeladas las cuentas nuevas, la pata se aparca en vez de revertir.)
    #[msg("La cuenta de destino en especie está congelada: usa otra cuenta tuya para ese token.")]
    WithdrawInKindDestFrozen = 6226,

    // G4 (F5A-01): un init SIN patrocinio que encuentra la hucha USDC de la pareja pagada por Wagon se la compra (el rent mínimo
    // va a `protocol.authority`): esa cuenta opcional tiene que venir y ser la authority. En los cierres sin sesión, el destino
    // del rent de una hucha de Wagon tiene que ser la authority.
    #[msg("Falta la cuenta rent_authority (protocol.authority) o no es la del protocolo: la hucha de la sesión la pagó Wagon.")]
    EscrowRentAuthorityMissing = 6227,

    // G5 (auditoría 2026-10-09, F1A-04): el barrido que COMPROMETE un depósito (el primero en dirección settle) trae TODAS sus
    // patas barribles en una instrucción, junto con el USDC de capital de la hucha: la reserva entera de participaciones
    // fantasma entra a la vez que todo el depósito. Un lote parcial no compromete nada y se repite con todas las patas.
    #[msg("El commit de un depósito tiene que traer todas sus patas en una sola instrucción.")]
    DepositCommitMustCoverAllLegs = 6228,

    // Endurecimiento de la #56 (residual #45): con el re-precio a mercado del commit apagado (`m2m_enforced == 0`) la foto de
    // la sesión sigue siendo la del init. Si se tomó con el vault vacío y el vault ya tiene participaciones, el commit se niega.
    // Reintentable: con el m2m encendido el commit re-marca la foto (S-1, #50); si no, la sesión se devuelve en especie por la
    // escotilla de 24 h. Los tokens siguen en la hucha de la sesión.
    #[msg("Este depósito se preparó con el vault vacío y el vault ya tiene participaciones: solo puede entrar con el precio a mercado activo.")]
    DepositCommitEmptySnapshot = 6229,

    // Tabla de direcciones del vault (#56): `vault_table_sync` solo escribe en la tabla que sale de la PDA del vault y del
    // slot guardado (o del slot nuevo al crearla), y comprueba tras cada CPI que es del programa de tablas, que su autoridad
    // es esa PDA, que está activa y que contiene lo que el programa saca del vault.
    #[msg("La tabla de direcciones no es la de este vault o no está en el estado esperado.")]
    VaultTableMismatch = 6230,

    // La tabla ya tiene todas las direcciones que el programa saca del vault: no hay nada que añadir (nadie paga una
    // transacción vacía). Los clientes lo tratan como «la tabla está al día».
    #[msg("La tabla de direcciones del vault ya está al día.")]
    VaultTableUpToDate = 6231,

    // Auditoría CISO (P3, #56): toda lectura de Pyth exige la cuenta de precio OFICIAL del feed, la que el programa push de
    // Pyth deriva con [shard 0, feed id] (`PYTH_PUSH_ORACLE_V2`) y que Pyth solo deja avanzar en el tiempo. Una cuenta del
    // receptor de Pyth en cualquier otra dirección revierte aquí aunque su precio sea válido y fresco.
    #[msg("La cuenta de precio no es la oficial de Pyth para este feed.")]
    OraclePriceAccountNotCanonical = 6232,

    // Auditoría CISO (P3, #56): `set_commit_oracle_max_age` acepta 0 (la edad de la clase) o un valor entre
    // `COMMIT_ORACLE_MAX_AGE_MIN_SECS` y `COMMIT_ORACLE_MAX_AGE_MAX_SECS`; cualquier otro revierte aquí sin escribir nada.
    #[msg("La edad máxima del precio en el commit tiene que ser 0 o estar entre 10 y 120 segundos.")]
    CommitOracleMaxAgeOutOfRange = 6233,
}
