//! Jupiter v6 CPI helper.
//!
//! The program doesn't know how to route swaps — that's Jupiter's job. Instead,
//! the off-chain client calls Jupiter's `/swap-instructions` API (or equivalent)
//! to obtain:
//!   - `instruction_data`: the raw bytes of the Jupiter instruction to call
//!   - `accounts`: the AccountMeta list required by that instruction
//!
//! Those accounts are passed to our handler via `remaining_accounts`, and the
//! raw instruction data in a `SwapPlan`. We then build a `solana_program::instruction::Instruction`
//! and fire an `invoke_signed` with the vault PDA as the signer (so Jupiter
//! treats the vault as the user).
//!
//! The caller is responsible for ordering `remaining_accounts` correctly and
//! for sizing each segment via `SwapPlan::account_count`.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::invoke_signed;
use anchor_spl::token::spl_token;

use crate::constants::JUPITER_PROGRAM_ID;
use crate::errors::WagonError;

/// One swap leg. Client fills this in from Jupiter's `/swap-instructions` response.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct SwapPlan {
    /// Raw Jupiter instruction data bytes (the `data` field of the instruction).
    pub ix_data: Vec<u8>,
    /// Number of accounts in `remaining_accounts` that belong to this swap leg's
    /// Jupiter route (not counting the destination ATA, which is passed as the
    /// first account of the segment by convention).
    pub account_count: u8,
    /// Minimum acceptable output (in output-token atomic units). The program
    /// verifies this against the delta in the destination token account and
    /// returns `SlippageExceeded` if not met. This is the on-chain backstop
    /// in addition to the slippage limit baked into `ix_data`.
    pub min_out: u64,
}

/// Execute a Jupiter swap as a CPI signed by the vault PDA.
///
/// * `jupiter_program` – must equal `JUPITER_PROGRAM_ID`.
/// * `destination_token_account` – the destination SPL token account. Must be
///   owned by the SPL Token program, have `mint == expected_dest_mint`, and
///   have its internal `owner` field equal to `expected_dest_owner` (i.e. the
///   vault PDA). This prevents an attacker from steering swap proceeds into
///   an attacker-controlled account.
/// * `expected_dest_mint` – mint of the token we expect to receive.
/// * `expected_dest_owner` – authority (owner_field) of the destination ATA.
///   For deposit/rebalance/sweep this is always the vault PDA.
/// * `route_accounts` – the slice of `remaining_accounts` Jupiter needs. First
///   entry must be the destination token account (same as the arg above).
/// * `ix_data` – raw instruction data from the Jupiter API.
/// * `signer_seeds` – vault PDA signer seeds (`[VAULT_SEED, creator, nonce, &[bump]]`).
///
/// Returns the balance delta on the destination account.
pub fn invoke_jupiter_swap<'info>(
    jupiter_program: &AccountInfo<'info>,
    destination_token_account: &AccountInfo<'info>,
    expected_dest_mint: &Pubkey,
    expected_dest_owner: &Pubkey,
    // H-3: dueño del destino y autoridad firmante ya NO son siempre la misma
    // cuenta. En el retiro con hucha, el destino pertenece a la SESIÓN pero
    // quien firma la venta (fuente = ATAs del vault) es el VAULT. Este
    // parámetro dice QUÉ pubkey debe recuperar is_signer=true en las metas
    // de la CPI (debe casar con los signer_seeds que se pasan).
    signing_authority: &Pubkey,
    // C-A (ceremonia #39): las cuentas de tokens que el handler DECLARA y valida
    // como fuente/destino de este swap (fuente Y destino, siempre ≥1). Toda otra
    // token account cuyo owner-SPL sea `signing_authority` y que aparezca en la
    // ruta NO puede perder saldo — el barrido de abajo lo verifica. Cierra la
    // sustitución de cuenta: la firma del PDA autoriza a Jupiter a tocar
    // CUALQUIER ATA de esa autoridad, no solo la declarada.
    declared_atas: &[Pubkey],
    route_accounts: &[AccountInfo<'info>],
    ix_data: Vec<u8>,
    signer_seeds: &[&[&[u8]]],
) -> Result<u64> {
    require_keys_eq!(
        *jupiter_program.key,
        JUPITER_PROGRAM_ID,
        WagonError::InvalidJupiterProgram
    );
    require!(!route_accounts.is_empty(), WagonError::InvalidJupiterRoute);

    // ---- Upgrade #29 (security): Jupiter instruction allowlist --------------
    // The vault PDA signs this CPI via `invoke_signed`. Both `ix_data` and the
    // route accounts are supplied by an untrusted client, so without a guard a
    // malicious caller could make the vault sign an *arbitrary* instruction to
    // the Jupiter program (not a swap) and abuse the vault's authority. Gate on
    // the Anchor discriminator (first 8 bytes of `ix_data`) against the full
    // set of Jupiter v6 swap entrypoints. A genuine swap has a Jupiter-enforced
    // account layout in which the vault PDA can only be the swap authority, so
    // this also closes the "vault PDA placed in an unexpected authority slot"
    // concern. Discriminators = sha256("global:<name>")[..8]; validated against
    // live routes from api.jup.ag.
    require!(ix_data.len() >= 8, WagonError::InvalidJupiterRoute);
    {
        const JUP_ROUTE: [u8; 8] = [229, 23, 203, 151, 122, 227, 173, 42];
        const JUP_ROUTE_TOKEN_LEDGER: [u8; 8] = [150, 86, 71, 116, 167, 93, 14, 104];
        const JUP_EXACT_OUT_ROUTE: [u8; 8] = [208, 51, 239, 151, 123, 43, 237, 92];
        const JUP_SHARED_ACCOUNTS_ROUTE: [u8; 8] = [193, 32, 155, 51, 65, 214, 156, 129];
        const JUP_SHARED_ACCOUNTS_ROUTE_TOKEN_LEDGER: [u8; 8] = [230, 121, 143, 80, 119, 159, 106, 170];
        const JUP_SHARED_ACCOUNTS_EXACT_OUT_ROUTE: [u8; 8] = [176, 209, 105, 168, 154, 125, 69, 62];
        let disc: &[u8] = &ix_data[0..8];
        let allowed = disc == JUP_ROUTE.as_slice()
            || disc == JUP_ROUTE_TOKEN_LEDGER.as_slice()
            || disc == JUP_EXACT_OUT_ROUTE.as_slice()
            || disc == JUP_SHARED_ACCOUNTS_ROUTE.as_slice()
            || disc == JUP_SHARED_ACCOUNTS_ROUTE_TOKEN_LEDGER.as_slice()
            || disc == JUP_SHARED_ACCOUNTS_EXACT_OUT_ROUTE.as_slice();
        require!(allowed, WagonError::InvalidJupiterRoute);
    }

    // ---- F5 (ceremonia #40): platform_fee_bps DEBE ser 0 -------------------
    // El allowlist de arriba valida los 8 primeros bytes y el resto de
    // `ix_data` se reenvía TAL CUAL a Jupiter. En esa cola viaja
    // `platform_fee_bps: u8`, que desvía hasta 255 bps (2,55 %) de CADA swap a
    // una cuenta de comisión que elige quien construye la ruta — invisible para
    // el piso de valor del guard (que compara valor recibido contra gastado
    // DESPUÉS del desvío), para el barrido C-A (la cuenta de comisión no es del
    // vault) y para los eventos. Lo puede poner el creador en cada rebalanceo o
    // cambio de cesta sobre dinero de sus inversores, y convierte la evasión de
    // la comisión de éxito en gratuita.
    //
    // Es el ÚLTIMO byte en las SEIS instrucciones del allowlist: en la IDL v6
    // `platform_fee_bps` es el último argumento de route / routeWithTokenLedger
    // / exactOutRoute y de las tres variantes sharedAccounts*.
    // MEDIDO contra la API en vivo el 2026-07-29 (no deducido):
    //   sharedAccountsRoute USDC→SOL  len 42 · último byte 0
    //   sharedAccountsRoute USDC→BONK len 51 · último byte 0
    //   route SOL→USDC                len 35 · último byte 0
    //   exactOutRoute USDC→SOL        len 35 · último byte 0
    //   las mismas rutas pidiendo platformFeeBps=255 → último byte 255
    // Es decir: una ruta honesta ya trae 0 y este require no rompe nada.
    //
    // ⚠️ ALCANCE HONESTO DE ESTE CANDADO — es DEFENSA EN PROFUNDIDAD, no un
    // sello hermético. Comprueba una POSICIÓN, no el campo borsh:
    //   - Cierra el camino de coste CERO: la respuesta cruda de la API de
    //     Jupiter con feeBps puesto. Es la única forma en que esto podía pasar
    //     desde un cliente normal, y la que hoy funciona gratis.
    //   - NO cierra un `ix_data` fabricado a mano con UN byte 0x00 de más al
    //     final: entonces `platform_fee_bps` queda en len-2 y este require mira
    //     el relleno. Depende de si el dispatcher de Jupiter v6 (código cerrado)
    //     tolera cola sobrante, cosa que NO hemos medido. Asumir que sí.
    // Por qué se acepta igualmente: el techo real de extracción no lo pone este
    // require, lo pone el guard `swap_max_loss_bps` (HOY 800 bps), que ya tolera
    // más que los 255 bps máximos de la comisión de plataforma — y el mismo
    // firmante puede enrutar por un pool propio y sacar más sin tocar este campo.
    // El freno efectivo es BAJAR EL GUARD (botón 43, parámetro reversible;
    // tarea PRE-BETA ⑭). Endurecer esto de verdad = validar el CAMPO borsh
    // (parsear `route_plan`, que es un Vec de longitud variable) o fijar la
    // longitud exacta esperada por discriminador → trabajo para la #41.
    //
    // Y si algún día se añade un discriminador NUEVO al allowlist de arriba:
    // comprobar que su último argumento sigue siendo `platform_fee_bps`.
    require!(
        ix_data[ix_data.len() - 1] == 0,
        WagonError::JupiterPlatformFeeNotZero
    );

    // ---- C3 fix: validate destination token account ------------------------
    // Guard against an attacker passing in a spoofed destination that either
    // (a) is owned by a program other than SPL Token, (b) has the wrong mint,
    // or (c) is owned (in the SPL sense) by someone other than the vault PDA.
    // Without these checks a malicious client could route swap proceeds to an
    // attacker-controlled ATA.
    // Upgrade #28: accept classic SPL Token OR Token-2022. For Token-2022
    // basket mints (xStocks, MetaDAO), the destination ATA is owned by
    // the Token-2022 program — same shape (165 bytes header), same mint/
    // owner offsets we read below, but a different program id.
    let dest_owner = destination_token_account.owner;
    require!(
        *dest_owner == spl_token::ID
            || *dest_owner == anchor_lang::solana_program::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"),
        WagonError::InvalidJupiterRoute
    );
    {
        let data = destination_token_account.try_borrow_data()?;
        // SPL TokenAccount layout: mint(32) | owner(32) | amount(u64, offset 64) | ...
        require!(data.len() >= 165, WagonError::InvalidJupiterRoute);
        let mint_bytes: [u8; 32] = data[0..32]
            .try_into()
            .map_err(|_| error!(WagonError::InvalidJupiterRoute))?;
        let owner_bytes: [u8; 32] = data[32..64]
            .try_into()
            .map_err(|_| error!(WagonError::InvalidJupiterRoute))?;
        let actual_mint = Pubkey::new_from_array(mint_bytes);
        let actual_owner = Pubkey::new_from_array(owner_bytes);
        require_keys_eq!(
            actual_mint,
            *expected_dest_mint,
            WagonError::InvalidJupiterRoute
        );
        require_keys_eq!(
            actual_owner,
            *expected_dest_owner,
            WagonError::InvalidJupiterRoute
        );
    }
    // Note: deposit and sweep_to_usdc pass route[0] == destination by
    // convention, but withdraw measures USDC delta on vault_usdc_ata while
    // route[0] is the basket-side source account. We do NOT require the two to
    // be equal — the destination validation above only pins WHERE the proceeds
    // land, not WHERE Jupiter debits from. The account-substitution barrido
    // below is what actually closes the drain surface.

    // ---- C-A (ceremonia #39): barrido de sustitución de cuenta -------------
    // La firma del vault/sesión que se presta a `invoke_signed` autoriza a
    // Jupiter a debitar CUALQUIER token account propiedad de `signing_authority`,
    // no solo la fuente/destino declaradas. Ataque: meter en la ruta una ATA
    // valiosa del vault con destino la cuenta del atacante y `min_out=0` → la
    // cuenta declarada queda intacta (delta 0) y el piso de valor pasa con 0.
    // Aquí censamos toda token account de la autoridad firmante que aparezca en
    // la ruta y NO esté declarada, y tras la CPI exigimos que ninguna pierda
    // saldo. Completitud: el runtime obliga a que toda cuenta tocada por la CPI
    // viaje en `route_accounts` (el `infos` de abajo se construye SOLO desde
    // ahí), así que el barrido es exhaustivo, no heurística.
    const T22: Pubkey =
        anchor_lang::solana_program::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
    let mut watched: Vec<(usize, u64)> = Vec::new();
    for (i, ai) in route_accounts.iter().enumerate() {
        let prog_owner = *ai.owner;
        // Salta pronto lo que no sea de un token program (pools, AMM state,
        // sysvars…): la mayoría de la ruta, sin ningún borrow.
        if prog_owner != spl_token::ID && prog_owner != T22 {
            continue;
        }
        // Las cuentas declaradas están exentas (fuente/destino legítimos) — y su
        // borrow puede estar ya prestado por el handler: comprobar ANTES del borrow.
        if declared_atas.contains(ai.key) {
            continue;
        }
        // Dedup: la misma ATA puede aparecer varias veces en la ruta.
        if watched.iter().any(|(j, _)| route_accounts[*j].key == ai.key) {
            continue;
        }
        // Fallo de borrow sobre una CANDIDATA = REVERT (fail-closed): un
        // `continue` aquí sería un bypass trivial.
        let data = ai
            .try_borrow_data()
            .map_err(|_| error!(WagonError::VaultAtaDrainedInRoute))?;
        // Discriminar token ACCOUNT de MINT (mismo program owner):
        //   classic o T22-sin-extensiones: exactamente 165 bytes.
        //   T22-con-extensiones: base 165 + data[165] = AccountType (1=Mint, 2=Account).
        //   Mint clásico (82 B) o cuentas cortas: < 165 → se excluyen.
        let is_token_account = match data.len() {
            165 => true,
            n if n > 165 => data[165] == 2u8,
            _ => false,
        };
        if !is_token_account {
            continue;
        }
        let owner_bytes: [u8; 32] = data[32..64]
            .try_into()
            .map_err(|_| error!(WagonError::VaultAtaDrainedInRoute))?;
        if Pubkey::new_from_array(owner_bytes) != *signing_authority {
            continue;
        }
        let mut amt = [0u8; 8];
        amt.copy_from_slice(&data[64..72]);
        watched.push((i, u64::from_le_bytes(amt)));
        // `data` (el borrow) se suelta al final de esta iteración → los accounts
        // quedan libres para la CPI de abajo.
    }

    // Snapshot destination balance before the swap.
    let before = token_account_balance(destination_token_account)?;

    // Build AccountMeta list from the route accounts. Preserve is_signer /
    // is_writable from the AccountInfo — they are set by the client per
    // Jupiter's requirements.
    // Override is_signer=true when the account pubkey equals the
    // signing_authority (the PDA that signs this CPI via signer_seeds). The
    // frontend marks that PDA is_signer=false in remaining_accounts because
    // PDAs cannot sign top-level — Solana would reject the tx with "did not
    // pass signature verification". We restore is_signer=true here so that
    // invoke_signed satisfies the inner signer requirement that Jupiter's
    // swap instruction expects from userPublicKey.
    let metas: Vec<AccountMeta> = route_accounts
        .iter()
        .map(|ai| AccountMeta {
            pubkey: *ai.key,
            is_signer: ai.is_signer || *ai.key == *signing_authority,
            is_writable: ai.is_writable,
        })
        .collect();

    let ix = Instruction {
        program_id: JUPITER_PROGRAM_ID,
        accounts: metas,
        data: ix_data,
    };

    // Jupiter CPI. Vault PDA is the signer (via seeds); Jupiter also needs the
    // program account itself in the invoke call, so we prepend it.
    let mut infos: Vec<AccountInfo<'info>> = Vec::with_capacity(route_accounts.len() + 1);
    infos.push(jupiter_program.clone());
    for a in route_accounts {
        infos.push(a.clone());
    }

    invoke_signed(&ix, &infos, signer_seeds)
        .map_err(|e| {
            msg!("Jupiter CPI failed: {:?}", e);
            error!(WagonError::InvalidJupiterRoute)
        })?;

    // C-A: ninguna ATA vigilada de la autoridad firmante puede haber perdido
    // saldo. NO-DECRECIMIENTO (no "prohibición de aparecer"): un intermedio
    // multi-hop legítimo netea 0 dentro de la instrucción atómica y pasa —
    // verificado empíricamente con 40 rutas vivas de Jupiter (0 casos).
    for (i, before_bal) in &watched {
        let after_bal = token_account_balance(&route_accounts[*i])?;
        require!(
            after_bal >= *before_bal,
            WagonError::VaultAtaDrainedInRoute
        );
    }

    let after = token_account_balance(destination_token_account)?;
    let delta = after.checked_sub(before).ok_or(WagonError::MathOverflow)?;
    Ok(delta)
}

/// Read the `amount` field of an SPL `TokenAccount` directly from its raw data.
/// We don't deserialize the full `Account` because `remaining_accounts` come in
/// as raw `AccountInfo` and we want to avoid the overhead of a full
/// `Account<'info, TokenAccount>` unpack when we're only measuring balance.
fn token_account_balance(acc: &AccountInfo) -> Result<u64> {
    let data = acc.try_borrow_data()?;
    // SPL TokenAccount layout: mint(32) | owner(32) | amount(u64, offset 64) | ...
    require!(data.len() >= 72, WagonError::InvalidJupiterRoute);
    let mut amount_bytes = [0u8; 8];
    amount_bytes.copy_from_slice(&data[64..72]);
    Ok(u64::from_le_bytes(amount_bytes))
}

/// Verify that a swap leg met its minimum output. Call once per leg after
/// `invoke_jupiter_swap` returns the delta.
pub fn check_min_out(delta: u64, min_out: u64) -> Result<()> {
    require!(delta >= min_out, WagonError::SlippageExceeded);
    Ok(())
}
