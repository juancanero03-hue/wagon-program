//! `deposit_sweep_batch` — upgrade #31 (F2b): drains the session's escrow
//! ATAs, 1-7 legs per call (G5: `MAX_DEPOSIT_SWEEP_LEGS_PER_BATCH`, la cesta máxima), in one of two directions:
//!
//! - **Settle direction** (escrow → vault): only once ALL swaps completed
//!   (`session.is_complete()`), the session is not stale and the vault is
//!   not mid-restructure. PERMISSIONLESS — once the swaps ran, the deposit
//!   is economically committed and finishing it only benefits the
//!   investor, so anyone (the frontend, a crank, ourselves) can drive an
//!   abandoned-but-complete session to settlement.
//!
//! - **Abort direction** (escrow → investor): for incomplete sessions,
//!   sessions made stale by a restructure, sessions already flagged
//!   `aborting` and, since G3 (`DEPOSIT_UNSWEPT_ESCAPE_SECS`), COMPLETE
//!   sessions that nobody swept into the vault within that window (10 min
//!   since the #56; 24 h before): past that age the only direction is the
//!   refund, so no complete session waits forever on a vault that cannot
//!   receive it. Separately (CISO P4, #56), the INVESTOR alone can ask for
//!   the refund of an unswept session whose entry is vetoed by withdrawals in
//!   flight after `DEPOSIT_VETOED_RETURN_SECS`. The investor any time; ANYONE
//!   after `DEPOSIT_SESSION_TIMEOUT_SECS` (10 min) — the orphan-session
//!   guarantee. The first abort-direction sweep sets `session.aborting`,
//!   which permanently blocks further swaps and the settle path.
//!
//! G3 (2026-10-15): a canonical destination ATA that does not exist yet is
//! CREATED by the program (idempotent, through the Associated Token program)
//! when the leg has something to move, whoever the caller is. The caller
//! advances its rent and gets it back at the end of the SAME instruction out
//! of the rent of the escrows that close (create → transfer → close per leg,
//! one refund after the last leg): the session PDA never ends the instruction
//! below what it had, and the caller only pays the tx fee. A leg with
//! `amount == 0` needs no destination account at all (its key is still pinned
//! to the canonical derivation).
//!
//! G5 (auditoría 2026-10-09, F1A-04): el lote que COMPROMETE la sesión (el primero en dirección settle) trae TODAS sus
//! patas barribles en esta instrucción (6228 si falta alguna) y mete en el vault, también aquí, el USDC de capital de la
//! hucha USDC de la sesión (la comisión de entrada sigue reservada en ella hasta el settle): la reserva entera de
//! participaciones fantasma (#44) entra a la vez que todo el depósito. Con la hucha congelada o la ATA USDC del vault sin
//! poder recibir, ese USDC se queda en la hucha y lo reparte `deposit_settle`, como siempre.
//!
//! Either way each swept escrow ATA is emptied IN FULL and closed, with
//! its rent landing on the SESSION PDA (ceremonia USDC §3.3, D1): the
//! terminal that closes the session (`deposit_settle` / `deposit_abort`)
//! hands the whole balance to whoever funded it — the investor, or the
//! sponsor's `refund_to` when a `FundingRecord` is paired. The
//! direction is decided ON-CHAIN from session + vault state — the caller
//! only supplies accounts, so a malicious caller can never choose where
//! the funds go.
//!
//! # remaining_accounts layout
//!
//! For each leg in `leg_indices`: `[mint, escrow_ata, dest_ata]`.
//! `mint` must match the session's `leg_mints` snapshot (NOT the live
//! vault table — the vault may have restructured); `escrow_ata` must be
//! the canonical ATA of (session, mint); `dest_ata` the canonical ATA of
//! (vault, mint) or (investor, mint) depending on direction.

use anchor_lang::prelude::*;
use anchor_spl::associated_token::{self, AssociatedToken, Create};
use anchor_spl::token::{self, spl_token, Token, Transfer};

use crate::constants::*;
use crate::entry_fee;
use crate::errors::WagonError;
use crate::events::DepositEscrowSwept;
use crate::state::deposit_session::DEPOSIT_SESSION_TIMEOUT_SECS;
use crate::state::vault_layout as vlayout;
use crate::state::{DepositSession, ProtocolConfig, SessionPrice};
use crate::pricing::value_from_oracle;
use crate::token_io::{
    close_token_account_signed, derive_live_ata, is_payable_usdc_ata, read_mint_decimals, read_token_amount,
    read_token_state, transfer_checked_signed, verify_token_account, TOKEN_2022_PROGRAM_ID, TOKEN_STATE_FROZEN,
};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct DepositSweepBatchArgs {
    pub leg_indices: Vec<u8>,
}

#[derive(Accounts)]
pub struct DepositSweepBatch<'info> {
    /// Settle direction: anyone. Abort direction: the investor, or anyone
    /// after the 10-minute timeout. Pays the tx fee; never receives funds
    /// (G3: it only ADVANCES the rent of a missing destination account and
    /// gets it back at the end of the same instruction).
    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: pinned to `session.investor` via has_one; destination owner of
    /// the abort-direction sweeps. The escrow rents no longer come here: they
    /// land on the session PDA (D1, §3.3) and leave with the session's close.
    #[account(mut)]
    pub investor: UncheckedAccount<'info>,

    /// CHECK: PDA seeds + owner verified manually (VaultGuard).
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [
            DEPOSIT_SESSION_SEED,
            vault.key().as_ref(),
            investor.key().as_ref(),
        ],
        bump = deposit_session.bump,
        has_one = investor @ WagonError::DepositSessionWrongInvestor,
        has_one = vault @ WagonError::DepositSessionWrongVault,
    )]
    pub deposit_session: Box<Account<'info, DepositSession>>,

    pub token_program: Program<'info, Token>,

    /// CHECK: pubkey verified == Token-2022 program id. Used for legs whose
    /// mint lives on Token-2022 (xStocks, MetaDAO); ignored otherwise.
    pub token_program_2022: UncheckedAccount<'info>,

    /// Ceremonia #50 (S-1): da `m2m_enforced` (para el fail-closed del re-precio
    /// en el commit) y `usdc_mint`. Se pasa en TODO barrido; solo se usa para
    /// re-marcar en el barrido de COMMIT con `m2m_enforced==1`.
    #[account(seeds = [PROTOCOL_SEED], bump = protocol.bump)]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// G3 (2026-10-15): para crear (idempotente) la cuenta de destino canónica que falte;
    /// la paga el rent de la hucha que se cierra en la misma pata.
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,

    /// G5 (F1A-04): la hucha USDC de la sesión; el barrido de COMMIT mete en el vault su USDC de capital.
    /// CHECK: atada en todo barrido a la derivación canónica (sesión, USDC); en el commit, además `verify_token_account`.
    #[account(mut)]
    pub session_usdc_escrow: UncheckedAccount<'info>,

    /// G5 (F1A-04): la ATA USDC del vault, destino de ese USDC. En el commit con re-precio va también en `remaining[3n]`
    /// (cabeza de la cola del oráculo): las dos se atan a la misma clave pinneada.
    /// CHECK: atada en todo barrido a la clave pinneada en el VaultState.
    #[account(mut)]
    pub vault_usdc_ata: UncheckedAccount<'info>,
}

pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, DepositSweepBatch<'info>>,
    args: DepositSweepBatchArgs,
) -> Result<()> {
    // ---- Validate batch shape ----------------------------------------------
    require!(!args.leg_indices.is_empty(), WagonError::EmptyBatch);
    require!(
        args.leg_indices.len() <= MAX_DEPOSIT_SWEEP_LEGS_PER_BATCH as usize,
        WagonError::BatchTooLarge
    );
    require_keys_eq!(
        ctx.accounts.token_program_2022.key(),
        TOKEN_2022_PROGRAM_ID,
        WagonError::InvalidJupiterRoute
    );

    // ---- Vault guard (owner + PDA derivation; status read, not gated) -----
    let vault_ai = ctx.accounts.vault.to_account_info();
    let guard = crate::guards::VaultGuard::load(
        &vault_ai,
        &ctx.accounts.vault.key(),
        WagonError::VaultPaused,
    )?;
    // G5 (F1A-04, revisión N3): las dos cuentas USDC se atan en TODO barrido, aunque solo las use el commit: una sola forma
    // válida de transacción para el cliente.
    bind_usdc_accounts(
        &vault_ai,
        &ctx.accounts.vault_usdc_ata.to_account_info(),
        &ctx.accounts.session_usdc_escrow.to_account_info(),
        &ctx.accounts.deposit_session.key(),
        &ctx.accounts.protocol.usdc_mint,
    )?;

    let session = &ctx.accounts.deposit_session;
    let now = Clock::get()?.unix_timestamp;
    let (stale, dirty, drift, entry_vetoed) = {
        let data = vault_ai.try_borrow_data()?;
        (
            session.created_at < vlayout::read_last_restructured_at(&data)?,
            // Ceremonia #53: el vault sostiene valor FUERA DE TABLA → no COMMITear un
            // depósito contra un TVL infravalorado. Fuerza el camino de ABORTO
            // (reembolso EN ESPECIE al inversor), que hace `is_commit=false` → el
            // re-precio S-1 del #50 y el incremento de committed NO corren. La entrada
            // fresca ya la veta deposit_init; esto cubre una sesión en vuelo cuyo commit
            // cae DENTRO de la ventana sucia (strand permissionless posterior a su init).
            vlayout::read_stranded_flag(&data)? != 0,
            // G2-a (auditoría 2026-10-09, F3B-01): la cesta que fotografió la sesión ya no es la viva
            // (número de patas o mint por posición). `stale` compara FECHAS y empata en el mismo
            // segundo (bundle de `deposit_init` + `restructure_settle`); la identidad no empata.
            // Definición ÚNICA en `vault_layout::basket_drift` (la comparte `deposit_settle`).
            vlayout::basket_drift(&data, session.leg_count, &session.leg_mints)?,
            // Auditoría CISO (P4, #56): la entrada vetada por retiros en vuelo (la MISMA lectura que veta el commit, 6216).
            vlayout::entry_blocked_by_withdraws(&data)?,
        )
    };

    // ---- Decide the direction ON-CHAIN -------------------------------------
    // The caller has no say: complete + fresh sessions settle into the
    // vault; everything else unwinds to the investor. One exception since the
    // #56 (CISO P4): the INVESTOR of a session whose entry is vetoed by
    // withdrawals in flight can ask for the refund after 2 min (last clause).
    // Ceremonia #42 (Change 2 / OT-3): una sesión COMPLETA y SIN barrer
    // (`legs_swept == 0`: sus tokens siguen en el escrow de la propia sesión) en
    // un vault que ya pasó a un estado TERMINAL (Liquidating/Closed) no puede
    // asentar —settle exige Active (más abajo)— y hoy quedaba ATASCADA: ni entra
    // ni se reembolsa. Se la manda al camino de ABORTO (reembolso EN ESPECIE de
    // su propio escrow al inversor). El `legs_swept == 0` es CRÍTICO: una sesión
    // con patas YA barridas al vault (OT-1/OT-2) NO entra aquí —reembolsarla
    // tocaría fondos que ya son de los demás titulares—; ese caso lo impide el
    // contador de la #43 (`committed_deposits`). Paused (transitorio, se recupera al
    // despausar) y Restructuring (lo veta el else) se dejan esperar a propósito.
    let abort_direction = session.aborting == 1
        || !session.is_complete()
        || stale
        // Ceremonia #53: valor fuera de tabla → reembolsa (NO committea) SOLO una
        // sesión FRESCA (legs_swept == 0). El `&& legs_swept == 0` es CRÍTICO (espejo
        // del clause hermano del #42, abajo): un depósito YA COMPROMETIDO (legs_swept
        // != 0) que reciba un strand entre lotes DEBE seguir asentando —su precio se
        // fijó en el commit del lote 1 contra el TVL limpio pre-strand, sin dilución— y
        // decrementar committed/pending; forzarlo a abort los dejaría CLAVADOS (los 3
        // decrementadores exigen aborting==0) → brick + recorte permanente de toda
        // salida = estrangular la salida. La ENTRADA fresca sigue bloqueada por dirty.
        || (dirty && session.legs_swept == 0)
        // G2-a: sesión de OTRA cesta → reembolso EN ESPECIE, nunca aterriza en una ATA que la tabla
        // viva no cuenta. El `&& legs_swept == 0` es el mismo cinturón que `dirty`: una sesión YA
        // comprometida no puede ver cambiar la cesta (`restructure_init` veta con
        // `committed_deposits > 0`, #43), y si un día lo viera, forzarla a abort tocaría fondos que
        // ya son de todos; sigue asentando con sus fotos, como hoy.
        || (drift && session.legs_swept == 0)
        || ((guard.status == 2u8 || guard.status == 3u8) && session.legs_swept == 0)
        // G3 (2026-10-15, `DEPOSIT_UNSWEPT_ESCAPE_SECS`): una sesión COMPLETA que nadie barrió al vault en
        // 10 min (24 h hasta la #56; vault pausado, oráculo caído, entrada vetada por retiros en vuelo…) solo se DEVUELVE a partir
        // de ahí: la dirección la fija el reloj, no el caller, y el inversor recupera sus tokens sin depender
        // de nadie. El `legs_swept == 0` es el mismo cinturón que `dirty` y `drift`: una sesión ya
        // comprometida sigue asentando (sus tokens ya son de todos los titulares).
        || session.unswept_escape_due(now)
        // Auditoría CISO (P4, #56): con la entrada vetada por retiros en vuelo, el propio INVERSOR puede pedir la devolución
        // en especie de su sesión sin barrer pasados `DEPOSIT_VETOED_RETURN_SECS` (2 min), sin esperar a la escotilla. Depende
        // del reloj, de quién llama y de que la entrada siga vetada en este barrido (la tabla de verdad, en
        // `DepositSession::vetoed_return_due`). Un tercero sigue esperando a la escotilla.
        || session.vetoed_return_due(now, ctx.accounts.caller.key() == session.investor, entry_vetoed);
    if abort_direction {
        let timed_out = now.saturating_sub(session.created_at) > DEPOSIT_SESSION_TIMEOUT_SECS;
        require!(
            ctx.accounts.caller.key() == session.investor || timed_out,
            WagonError::DepositAbortTooEarly
        );
    } else {
        // Never land tokens in the vault while a restructure is selling the
        // outgoing set — it would corrupt the restructure's dust check.
        require!(guard.status != 4u8, WagonError::RestructuringInProgress);
        // M-3: the settle direction is an ENTRY into the vault — only an
        // Active vault may receive it. A COMPLETE unswept session in
        // Liquidating/Closed unwinds via the abort clause above (Ceremonia #42);
        // Paused waits for unpause (transient); Restructuring is rejected above.
        // A COMMITTED session cannot meet a Liquidating/Closed vault: close_vault,
        // restructure_init and finalize_close refuse while `committed_deposits > 0`
        // (ceremonia #43).
        require!(guard.status == 0u8, WagonError::VaultPaused);
    }

    // Ceremonia #50 (S-1): el barrido de COMMIT (primer settle, `legs_swept == 0`
    // en dirección settle) es el punto de no retorno y donde re-marcamos el precio
    // a mercado vivo (más abajo). `session.legs_swept` aquí es el valor PRE-batch.
    let is_commit = !abort_direction && session.legs_swept == 0;

    // ---- Session PDA signer seeds ------------------------------------------
    let vault_key = ctx.accounts.vault.key();
    let session_key = session.key();
    let investor_pk = session.investor;
    let session_ai = ctx.accounts.deposit_session.to_account_info();
    // G3: para crear la cuenta de destino que falte (la paga el rent de la hucha; el caller solo adelanta).
    let caller_ai = ctx.accounts.caller.to_account_info();
    let investor_ai = ctx.accounts.investor.to_account_info();
    let ata_program_ai = ctx.accounts.associated_token_program.to_account_info();
    let system_program_ai = ctx.accounts.system_program.to_account_info();
    let session_bump_arr = [session.bump];
    let seeds: &[&[u8]] = &[
        DEPOSIT_SESSION_SEED,
        vault_key.as_ref(),
        investor_pk.as_ref(),
        &session_bump_arr,
    ];
    let signer_seeds: &[&[&[u8]]] = &[seeds];

    // ---- Walk the [mint, escrow, dest] triples ------------------------------
    let remaining = ctx.remaining_accounts;
    let triples_len = 3 * args.leg_indices.len();
    require!(remaining.len() >= triples_len, WagonError::InvalidJupiterRoute);
    // Ceremonia #50 (S-1): en el barrido de COMMIT con m2m enforcement ON se
    // RE-MARCA el precio a mercado vivo, y para eso el caller enhebra cuentas EXTRA
    // tras los triples (vault_usdc_ata + grupo de oráculo). Fail-closed: con m2m ON
    // el oráculo es OBLIGATORIO (el `require` de `reprice_commit`, más abajo),
    // si no el fallback congelado reabriría S-1. Cuando NO se re-marca, cualquier
    // cuenta tras los 3n triples se IGNORA (el bucle solo usa las 3n primeras) → el
    // frontend puede enhebrar el oráculo sin romper los barridos no-commit / abort.
    let reprice = is_commit && ctx.accounts.protocol.m2m_enforced != 0;

    let legs_completed = session.legs_completed;
    let trivial_mask = session.trivial_mask;
    let legs_swept = session.legs_swept;
    let leg_count = session.leg_count;

    // ---- Ceremonia #50 (S-1): re-precio M2M en el COMMIT (PRE-transferencia) ----
    // Se calcula ANTES del bucle de transferencia: las ATAs del vault todavía NO
    // tienen los tokens de esta sesión, así que el M2M es la valoración
    // pre-depósito limpia. Sobrescribe la foto de la sesión más abajo (antes del
    // phantom_shares del incremento) -> el precio deja de estar congelado del init
    // -> la opción gratuita init->commit se colapsa. deposit_settle sigue puro.
    // Layout de remaining aquí: triples | vault_usdc_ata | (grupo de oráculo EXACTO
    // que exige compute_tvl_m2m_strict: registry · (mint,ata,price)×k · [SOL]?; G2-d: con el mint).
    // Una sesión con restructure entre init y commit es `stale` (fecha) o, en un empate de segundo,
    // `drift` (identidad, G2-a) -> abort_direction -> NO llega aquí; `basket_drift` garantiza que la
    // cesta del vault == la de la sesión por número, mint y posición (m2m coherente).
    // G2-c (auditoría 2026-10-09, F1A-03): el commit re-marcaba el DENOMINADOR a mercado (S-1) pero el
    // NUMERADOR (`received_value_acc`) seguía sellado al precio del SWAP: quien controla CUÁNDO comete tenía
    // una opción gratuita si el precio bajaba entre el swap y el commit. Desde G2-c el lote de COMMIT valora
    // las patas que ATERRIZAN con el MISMO oráculo que el re-precio y GUARDA en la sesión el precio efectivo de
    // CADA posición de la tabla (`landed_prices`, también de las patas a saldo 0: lo que aterriza aún no está
    // en la ATA). Desde G5 el commit trae TODAS las patas en un lote (abajo), así que numerador y denominador salen
    // siempre del mismo instante y no hay lotes posteriores que valorar (una sesión comprometida a medias antes del
    // upgrade no estaba valorada: `landed_tracked == 0`). Con el m2m apagado en el commit la sesión nace sin valorar y
    // asienta como hasta G2-c.
    let mut snapshot: Option<[SessionPrice; MAX_TOKENS_PER_VAULT]> = None;
    let repriced: Option<(u64, u64)> = if reprice {
        let (m2m, ts_live, snap) =
            reprice_commit(
                &vault_ai,
                &vault_key,
                &ctx.accounts.protocol.usdc_mint,
                &remaining[triples_len..],
                ctx.accounts.protocol.commit_oracle_max_age_secs,
            )?;
        snapshot = Some(snap);
        Some((m2m, ts_live))
    } else {
        None
    };

    let mut new_swept: u16 = 0;
    let mut fuera_de_tabla = false;
    // G3: lo que el caller adelanta por las cuentas de destino que faltan (se le devuelve al final) y el saldo del
    // PDA de la sesión al empezar (nunca acaba por debajo).
    let mut adelantado_total: u64 = 0;
    let session_lamports_inicio = session_ai.lamports();
    // G2-c: valor-oráculo de lo que aterriza en ESTE lote (se acumula en la sesión al final).
    let mut landed_acc: u64 = 0;
    for (pos, &leg_idx) in args.leg_indices.iter().enumerate() {
        require!(
            (leg_idx as usize) < (leg_count as usize),
            WagonError::LegIndexOutOfRange
        );
        let bit = 1u16 << leg_idx;
        // Sweepable = swap executed, not a trivial (USDC / zero-weight) leg,
        // not already swept (including within this same batch).
        require!((legs_completed & bit) != 0, WagonError::LegNotSweepable);
        require!((trivial_mask & bit) == 0, WagonError::LegNotSweepable);
        require!(
            (legs_swept & bit) == 0 && (new_swept & bit) == 0,
            WagonError::LegNotSweepable
        );

        let mint_ai = &remaining[3 * pos];
        let escrow_ai = &remaining[3 * pos + 1];
        let dest_ai = &remaining[3 * pos + 2];

        // Mint binding comes from the session's init-time snapshot.
        let leg_mint = session.leg_mints[leg_idx as usize];
        require_keys_eq!(mint_ai.key(), leg_mint, WagonError::AllocMintMismatch);

        // Escrow: canonical ATA of (session, mint) on the mint's live
        // token program.
        let token_prog_id = *mint_ai.owner;
        require_keys_eq!(
            escrow_ai.key(),
            derive_live_ata(&session_key, &leg_mint, &token_prog_id),
            WagonError::EscrowAtaMismatch
        );
        verify_token_account(escrow_ai, &leg_mint, &session_key)?;

        // Destination: vault ATA (settle) or investor ATA (abort), always
        // the canonical derivation — no caller-chosen destinations.
        let expected_owner = if abort_direction { investor_pk } else { vault_key };
        require_keys_eq!(
            dest_ai.key(),
            derive_live_ata(&expected_owner, &leg_mint, &token_prog_id),
            WagonError::LegDestAtaMismatch
        );

        // Pick the right token program AccountInfo for the CPI.
        let prog_ai = if token_prog_id == spl_token::ID {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        };

        let amount = read_token_amount(escrow_ai)?;
        // G3 (2026-10-15): si la cuenta de destino canónica no existe y hay algo que mover, la crea el programa
        // (idempotente, por el programa de ATAs) con el caller como pagador PROVISIONAL: lo adelantado vuelve a
        // su bolsillo al final de la instrucción, del rent de la hucha que se cierra en esta misma pata (misma
        // mint, mismo programa de token, mismo tamaño). Sirve para CUALQUIER caller: el inversor sin la cuenta del token,
        // el robot, un tercero pasados los 10 min o las 24 h. La clave ya está pinneada a la derivación canónica
        // (arriba): el caller no elige ningún destino. Con `amount == 0` la pata no necesita destino (nada que
        // mover; la hucha vacía se cierra igual).
        let mut adelantado: u64 = 0;
        if amount > 0 && dest_ai.data_is_empty() {
            let antes = caller_ai.lamports();
            let authority_ai = if abort_direction { investor_ai.clone() } else { vault_ai.clone() };
            associated_token::create_idempotent(CpiContext::new(
                ata_program_ai.clone(),
                Create {
                    payer: caller_ai.clone(),
                    associated_token: dest_ai.clone(),
                    authority: authority_ai,
                    mint: mint_ai.clone(),
                    system_program: system_program_ai.clone(),
                    token_program: prog_ai.clone(),
                },
            ))?;
            adelantado = antes.saturating_sub(caller_ai.lamports());
        }
        if amount > 0 {
            verify_token_account(dest_ai, &leg_mint, &expected_owner)?;
        }
        if amount > 0 && !abort_direction {
            // G2-a, CINTURÓN (sin `require`, como el land-and-mark del retiro): con `drift` esta rama es
            // inalcanzable para un mint fuera de tabla; si un bug futuro la alcanzara, el valor queda
            // MARCADO (`stranded_flag = 2`: bloquea la ENTRADA, nunca la salida) en vez de invisible.
            let data = vault_ai.try_borrow_data()?;
            if !vlayout::mint_in_allocations(&data, &leg_mint)? {
                fuera_de_tabla = true;
            }
            // G2-c (F1A-03): valorar lo que aterriza con el precio de SU posición en la tabla (G2-a garantiza
            // que sin deriva la pata i de la sesión ES la allocation i). CINTURÓN fail-open, como el de arriba:
            // si el mint de la posición no cuadra o la posición no tiene precio (slot trivial, fuera de tabla),
            // la pata se MARCA (`stranded_flag = 2`) y suma 0 (la cota solo puede acuñar MENOS): ningún lote en
            // dirección settle revierte por esto, la salida no se estrangula. Hoy inalcanzable con `basket_drift`.
            if let Some(snap) = snapshot.as_ref() {
                let mint_en_tabla = vlayout::read_allocation_mint(&data, leg_idx as usize)? == leg_mint;
                let valor = match snap.get(leg_idx as usize).and_then(|p| p.observed()) {
                    Some(obs) if mint_en_tabla => value_from_oracle(amount, &obs, read_mint_decimals(mint_ai)?).ok(),
                    _ => None,
                };
                // Fail-open ENTERO: también un error aritmético (inalcanzable con feeds reales) marca y suma 0.
                match valor {
                    Some(v) => landed_acc = landed_acc.saturating_add(v),
                    None => fuera_de_tabla = true,
                }
            }
        }
        if amount > 0 {
            let decimals = read_mint_decimals(mint_ai)?;
            transfer_checked_signed(
                &prog_ai,
                escrow_ai,
                mint_ai,
                dest_ai,
                &session_ai,
                signer_seeds,
                amount,
                decimals,
            )?;
        }
        // Close the emptied escrow ATA; its rent lands on the session PDA (D1,
        // §3.3) so the terminal can refund whoever funded it (sponsor-aware).
        close_token_account_signed(&prog_ai, escrow_ai, &session_ai, &session_ai, signer_seeds)?;
        // G3: lo adelantado se devuelve al caller UNA sola vez, al final de la instrucción (abajo): un movimiento
        // directo de lamports entre dos cuentas solo cuadra para el runtime cuando ya no queda ninguna CPI por
        // delante (antes de cada CPI el runtime comprueba el balance SOLO sobre las cuentas de esa CPI, y la
        // sesión no va en la creación del destino de la pata siguiente).
        adelantado_total = adelantado_total.checked_add(adelantado).ok_or(WagonError::MathOverflow)?;

        new_swept |= bit;

        emit!(DepositEscrowSwept {
            vault: vault_key,
            investor: investor_pk,
            leg_index: leg_idx,
            amount,
            to_vault: !abort_direction,
        });
    }

    // ---- G5 (auditoría 2026-10-09, F1A-04): el COMMIT es ATÓMICO ----------------
    // El lote que compromete trae TODAS las patas barribles de la sesión y mete en el vault, en esta misma instrucción, el
    // USDC de capital que espera en su hucha: todo lo que no es la comisión de entrada reservada, con el mismo reparto que
    // hace el settle (`entry_fee::plan_settle`). Así la reserva entera de participaciones fantasma (#44, abajo) entra a la
    // vez que TODO el depósito. Ese USDC cuenta como aterrizado en el commit (1:1, en `landed_value_at_commit` y en
    // `received_value_acc`): el settle acuña lo mismo que si lo hubiera movido él. Con la hucha congelada, o si la ATA USDC
    // del vault no puede recibir, se queda en la hucha y lo reparte `deposit_settle`, como siempre: el commit nunca revierte
    // por una cuenta USDC. Va ANTES del reembolso de lo adelantado, que tiene que ser lo último tras la última CPI.
    let mut usdc_aterrizado: u64 = 0;
    if is_commit {
        require!(
            session.commit_covers_all_legs(new_swept),
            WagonError::DepositCommitMustCoverAllLegs
        );
        usdc_aterrizado = land_commit_usdc(
            &ctx.accounts.token_program.to_account_info(),
            &ctx.accounts.session_usdc_escrow.to_account_info(),
            &ctx.accounts.vault_usdc_ata.to_account_info(),
            &session_ai,
            signer_seeds,
            &session_key,
            &ctx.accounts.protocol.usdc_mint,
            session.entry_fee_protocol_cut_usdc,
            session.entry_fee_creator_cut_usdc,
        )?;
        landed_acc = landed_acc.saturating_add(usdc_aterrizado);
    }

    // ---- G3: reembolso de lo adelantado por las cuentas de destino ----------
    // Del rent de las huchas que se acaban de cerrar hacia el PDA de la sesión (D1): mismo mint, mismo programa
    // de token y mismo tamaño que la cuenta creada, así que el PDA acaba la instrucción con, como poco, lo que
    // tenía al empezarla (lo exige el `require`: nunca paga de su propio rent) y el caller recupera todo lo que
    // adelantó. Es el ÚNICO sitio donde el barrido toca los lamports de la sesión: el cinturón
    // `las_unicas_salidas_de_la_sesion_son_settle_y_abort` exige que estas sean exactamente las dos escrituras de
    // lamports de este fichero. Va DESPUÉS de la última CPI a propósito (ver el bucle).
    if adelantado_total > 0 {
        let sesion_lamports = session_ai.lamports();
        let caller_lamports = caller_ai.lamports();
        // Inalcanzable con cuentas reales (hucha y destino son ATAs gemelas: misma mint, mismo programa de token,
        // mismo tamaño y mismo rent); si un día dejara de serlo, revierte con `MathOverflow` (el PDA se quedaría por
        // debajo de su saldo inicial) en vez de pagar de su propio rent.
        require!(
            sesion_lamports.saturating_sub(session_lamports_inicio) >= adelantado_total,
            WagonError::MathOverflow
        );
        **session_ai.try_borrow_mut_lamports()? = sesion_lamports.checked_sub(adelantado_total).ok_or(WagonError::MathOverflow)?;
        **caller_ai.try_borrow_mut_lamports()? = caller_lamports.checked_add(adelantado_total).ok_or(WagonError::MathOverflow)?;
    }

    // ---- Persist ------------------------------------------------------------
    let session = &mut ctx.accounts.deposit_session;
    session.legs_swept |= new_swept;
    if abort_direction {
        session.aborting = 1;
    }
    // G5: el USDC de capital que entró con el commit ya no es residual de la hucha en el settle: cuenta como recibido (S-4).
    if usdc_aterrizado > 0 && session.value_tracked == 1 {
        session.received_value_acc = session.received_value_acc.saturating_add(usdc_aterrizado);
    }
    // Ceremonia #50 (S-1): fijar la foto RE-MARCADA (calculada arriba, pre-
    // transferencia) ANTES del phantom_shares del incremento de abajo, para que la
    // reserva #44 y la acuñación del settle usen el precio de commit, no el de init.
    if let Some((m2m, ts_live)) = repriced {
        session.tvl_before = m2m;
        session.total_shares_before = ts_live;
    }
    // G2-c: en el COMMIT la sesión queda VALORADA y guarda los precios de la tabla; cada lote acumula lo
    // aterrizado valorado con ellos. saturating_add: nunca revierte; una cota saturada solo deja `value_in`
    // como hasta G2-c (es un min).
    if let Some(snap) = snapshot {
        if reprice {
            session.landed_prices = snap;
            session.landed_tracked = 1;
        }
        session.landed_value_at_commit = session.landed_value_at_commit.saturating_add(landed_acc);
    }
    if fuera_de_tabla {
        // G2-a, cinturón: valor aterrizado fuera de la tabla viva → bandera 2 (mezclable sobre un 1;
        // la limpia `admin_clear_stranded`). Solo marca: la sesión sigue su curso.
        let mut data = vault_ai.try_borrow_mut_data()?;
        vlayout::write_stranded_flag(&mut data, 2)?;
    }

    // ---- Ceremonia #43: contador de depósitos COMPROMETIDOS -----------------
    // Incrementa en la transición `legs_swept 0→≠0` en dirección SETTLE: el
    // instante EXACTO en que este depósito pasa a estar DENTRO del vault sin
    // acuñar (comprometido). `legs_swept` (local, arriba) es el valor PRE-batch,
    // así que N barridos de la misma sesión incrementan UNA sola vez. Un barrido
    // en dirección ABORTO también pone `legs_swept != 0` pero NO compromete valor
    // al vault → excluido por `!abort_direction`. saturating_add: nunca envuelve a
    // 0 (falla-CERRADO). Lo drena `deposit_settle` (decremento) — ver vault_layout.
    if !abort_direction && legs_swept == 0 && new_swept != 0 {
        let mut data = vault_ai.try_borrow_mut_data()?;
        // Ceremonia #50 (S-1): persistir el m2m re-marcado en el vault (coherencia
        // con deposit_init:261). `repriced` es Some sii m2m enforcement está ON.
        if let Some((m2m, _)) = repriced {
            vlayout::write_tvl_last_computed_usdc(&mut data, m2m)?;
        }
        let cur = vlayout::read_committed_deposits(&data)?;
        // Ceremonia #51 (H-03): CANDADO DE SERIALIZACIÓN. Rechaza cometer si YA hay
        // otra sesión comprometida (`committed_deposits != 0`) → a lo sumo UN depósito
        // comprometido por vault a la vez. Es el veto de `deposit_init.rs:151` (que solo
        // corre al INIT) reforzado también en el COMMIT, para que la re-marcación a
        // mercado del precio en el commit (#50) opere siempre sobre un par
        // (m2m, total_shares) consistente. `cur` es el valor PRE-incremento (esta sesión
        // aún no ha comprometido) → cuenta solo OTRAS comprometidas. Reusa el MISMO error
        // que el veto de init (los clientes ya lo mapean). El `deposit_settle` de la comprometida
        // es permissionless → el rechazo es reintentable, nunca vara.
        require!(cur == 0, WagonError::VaultHasCommittedDeposit);
        // G1 (auditoría 2026-10-09, F1A-01): el COMMIT fija el precio de acuñación (S-1): con
        // retiros en vuelo (shares revivibles o una cancelación ya empezada) ese precio no puede
        // ser justo → el MISMO veto que `deposit_init` (una definición: `entry_blocked_by_withdraws`),
        // fail-closed de ENTRADA y reintentable (el barrido de commit es permissionless y los
        // tokens siguen a salvo en la hucha de la sesión).
        require!(
            !vlayout::entry_blocked_by_withdraws(&data)?,
            WagonError::VaultHasRevivableBurn
        );
        // Endurecimiento de la #56 (residual #45): sin re-precio, una foto vacía solo vale si el vault sigue vacío.
        require_commit_snapshot_fresh(&data, repriced.is_some(), session.total_shares_before)?;
        vlayout::write_committed_deposits(&mut data, cur.saturating_add(1))?;

        // ---- Ceremonia #44: reserva de participaciones fantasma (F3) --------
        // Reserva las participaciones que este depósito comprometido va a recibir
        // al asentar, para que un retiro concurrente en la ventana no reparta su
        // valor: `withdraw_init` las SUMA a su denominador. `checked_add` (NO
        // saturating): clampar `pending` a u64::MAX inflaría el denominador del
        // retiro y ESTRANGULARÍA la salida (regla sellada); falla-CERRADO
        // revirtiendo ESTE barrido (permissionless, reintentable, tokens a salvo
        // en el escrow), jamás el retiro. Emparejado en `deposit_settle` con el
        // MISMO `phantom_shares()` sobre los mismos campos inmutables de la
        // sesión → sube/baja cuadra exacto. Overflow inalcanzable (~$1,8e13).
        let p = vlayout::phantom_shares(
            session.amount_usdc,
            session.total_shares_before,
            session.tvl_before,
        );
        let cur_pending = vlayout::read_pending_committed_shares(&data)?;
        vlayout::write_pending_committed_shares(
            &mut data,
            cur_pending.checked_add(p).ok_or(WagonError::MathOverflow)?,
        )?;
    }

    Ok(())
}

/// Endurecimiento de la #56 (residual #45): con el re-precio del commit apagado (`m2m_enforced == 0`, `repriced == false`) la
/// foto de la sesión sigue siendo la del init. Si se tomó con el vault vacío (`total_shares_before == 0`) y el vault ya tiene
/// participaciones, el commit se niega (6229): con esa foto la reserva fantasma saldría 0 y el settle acuñaría como primer
/// depósito, y ninguna de las dos cosas sería justa con los titulares que ya hay. Con la foto vacía y el vault vacío el commit
/// sigue: no hay titulares, y el candado de serialización (`committed_deposits == 0` en el init y en el commit) impide que
/// aparezca uno antes del settle. Reintentable: con el m2m encendido el commit re-marca la foto (S-1, #50); si no, la sesión
/// se devuelve en especie por la escotilla de 24 h. En su propia función (`inline(never)`): la pila del handler va llena (G5).
#[inline(never)]
fn require_commit_snapshot_fresh(data: &[u8], repriced: bool, total_shares_before: u64) -> Result<()> {
    if !repriced && total_shares_before == 0 {
        require!(vlayout::read_total_shares(data)? == 0, WagonError::DepositCommitEmptySnapshot);
    }
    Ok(())
}

/// G5 (F1A-04, revisión N3): ata las dos cuentas USDC del barrido: la del vault, a la pinneada en el VaultState; la hucha, a
/// la derivación canónica (sesión, USDC). En todo barrido, aunque solo las use el commit.
#[inline(never)]
fn bind_usdc_accounts<'info>(
    vault_ai: &AccountInfo<'info>,
    vault_usdc: &AccountInfo<'info>,
    hucha: &AccountInfo<'info>,
    session_key: &Pubkey,
    usdc_mint: &Pubkey,
) -> Result<()> {
    let pinned_usdc_ata = {
        let data = vault_ai.try_borrow_data()?;
        vlayout::read_usdc_ata(&data)?
    };
    require_keys_eq!(vault_usdc.key(), pinned_usdc_ata, WagonError::InvalidJupiterRoute);
    require_keys_eq!(
        hucha.key(),
        derive_live_ata(session_key, usdc_mint, &spl_token::ID),
        WagonError::EscrowAtaMismatch
    );
    Ok(())
}

/// Ceremonia #50 (S-1) y G2-c: el re-precio M2M del COMMIT (antes de mover nada) y el precio efectivo de cada posición de la
/// tabla. `tail` = las cuentas tras los triples: la ATA USDC del vault y el grupo de oráculo EXACTO de
/// `compute_tvl_m2m_strict` (registry · (mint, ata, price)×k · [SOL]?). Devuelve (m2m, total_shares vivo, precios). En su
/// propia función (`inline(never)`) para que sus temporales no vivan en el marco de pila del handler (revisión N3 de G5).
#[inline(never)]
fn reprice_commit<'info>(
    vault_ai: &AccountInfo<'info>,
    vault_key: &Pubkey,
    usdc_mint: &Pubkey,
    tail: &[AccountInfo<'info>],
    max_age_cap_secs: u16,
) -> Result<(u64, u64, [SessionPrice; MAX_TOKENS_PER_VAULT])> {
    require!(!tail.is_empty(), WagonError::MissingPriceAccounts);
    let vault_usdc_ai = &tail[0];
    let pinned_usdc_ata = {
        let data = vault_ai.try_borrow_data()?;
        vlayout::read_usdc_ata(&data)?
    };
    require_keys_eq!(vault_usdc_ai.key(), pinned_usdc_ata, WagonError::InvalidJupiterRoute);
    verify_token_account(vault_usdc_ai, usdc_mint, vault_key)?;
    let idle_usdc = read_token_amount(vault_usdc_ai)?;
    let (m2m, prices) =
        crate::pricing::compute_tvl_m2m_strict_with_prices(vault_ai, vault_key, idle_usdc, usdc_mint, &tail[1..], max_age_cap_secs)?;
    let ts_live = {
        let data = vault_ai.try_borrow_data()?;
        vlayout::read_total_shares(&data)?
    };
    let mut snap = [SessionPrice::default(); MAX_TOKENS_PER_VAULT];
    for (i, p) in prices.iter().enumerate() {
        if let Some(p) = p {
            snap[i] = SessionPrice::from_observed(p.effective());
        }
    }
    Ok((m2m, ts_live, snap))
}

/// G5 (F1A-04): mueve a la ATA USDC del vault el USDC de CAPITAL de la hucha de la sesión (todo menos la comisión de entrada
/// reservada, con el reparto de `entry_fee::plan_settle`, el mismo que hace el settle) y devuelve cuánto movió. Las dos cuentas
/// ya las ató `bind_usdc_accounts`. No mueve nada si la hucha no existe o está congelada, o si la ATA del vault no puede
/// recibir: el settle la reparte como siempre. Va en su propia función (`inline(never)`, con su marco de pila): el handler
/// estaba lleno (revisión N3 de G5: con este bloque dentro, un valor de su pila se pisaba sin aviso del compilador).
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn land_commit_usdc<'info>(
    token_program: &AccountInfo<'info>,
    hucha: &AccountInfo<'info>,
    vault_usdc: &AccountInfo<'info>,
    session_ai: &AccountInfo<'info>,
    signer_seeds: &[&[&[u8]]],
    session_key: &Pubkey,
    usdc_mint: &Pubkey,
    cut_protocol: u64,
    cut_creator: u64,
) -> Result<u64> {
    if hucha.data_is_empty() {
        return Ok(0);
    }
    verify_token_account(hucha, usdc_mint, session_key)?;
    let capital = entry_fee::plan_settle(read_token_amount(hucha)?, cut_protocol, cut_creator, false, false)
        .capital_residual_usdc;
    let movible = read_token_state(hucha)? != TOKEN_STATE_FROZEN && is_payable_usdc_ata(vault_usdc, usdc_mint, None);
    if capital == 0 || !movible {
        return Ok(0);
    }
    token::transfer(
        CpiContext::new_with_signer(
            token_program.clone(),
            Transfer { from: hucha.clone(), to: vault_usdc.clone(), authority: session_ai.clone() },
            signer_seeds,
        ),
        capital,
    )?;
    Ok(capital)
}

/// Endurecimiento de la #56: la foto vacía del init solo vale en el commit sin re-precio si el vault sigue vacío.
#[cfg(test)]
mod commit_snapshot_tests {
    use super::require_commit_snapshot_fresh;
    use crate::state::vault_layout::{write_total_shares, VAULT_TOTAL_LEN};

    fn vault_con_shares(total_shares: u64) -> Vec<u8> {
        let mut data = vec![0u8; VAULT_TOTAL_LEN];
        write_total_shares(&mut data, total_shares).unwrap();
        data
    }

    fn es_6229(res: anchor_lang::Result<()>) -> bool {
        format!("{:?}", res).contains("DepositCommitEmptySnapshot")
    }

    #[test]
    fn sin_re_precio_foto_vacia_y_vault_con_titulares_se_niega() {
        assert!(es_6229(require_commit_snapshot_fresh(&vault_con_shares(1), false, 0)));
        assert!(es_6229(require_commit_snapshot_fresh(&vault_con_shares(1_000_000), false, 0)));
    }

    #[test]
    fn sin_re_precio_foto_vacia_y_vault_vacio_sigue() {
        assert!(require_commit_snapshot_fresh(&vault_con_shares(0), false, 0).is_ok());
    }

    #[test]
    fn sin_re_precio_foto_con_titulares_sigue() {
        assert!(require_commit_snapshot_fresh(&vault_con_shares(5_000), false, 1_000).is_ok());
    }

    #[test]
    fn con_re_precio_no_mira_la_foto_del_init() {
        assert!(require_commit_snapshot_fresh(&vault_con_shares(5_000), true, 0).is_ok());
        assert!(require_commit_snapshot_fresh(&vault_con_shares(0), true, 0).is_ok());
    }
}
