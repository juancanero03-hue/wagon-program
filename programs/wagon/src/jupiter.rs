//! Jupiter v6 CPI helper.
//!
//! The program doesn't know how to route swaps — that's Jupiter's job. Instead,
//! the off-chain client calls Jupiter's `/swap-instructions` (Swap API V1) or `/build` (Swap API V2)
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

/// One swap leg. Client fills this in from Jupiter's `/swap-instructions` (V1) or `/build` (V2) response.
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
/// * `route_accounts` – the slice of `remaining_accounts` Jupiter needs, in the
///   order its instruction (V1 or V2) requires. Wagon reads no position inside it:
///   the destination is the named account above.
/// * `ix_data` – raw instruction data from the Jupiter API.
/// * `signer_seeds` – vault PDA signer seeds (`[VAULT_SEED, creator, nonce, &[bump]]`).
///
/// Returns the balance delta on the destination account.
pub fn invoke_jupiter_swap<'info>(
    jupiter_program: &AccountInfo<'info>,
    destination_token_account: &AccountInfo<'info>,
    expected_dest_mint: &Pubkey,
    expected_dest_owner: &Pubkey,
    // H-3: dueño del destino y autoridad firmante no tienen por qué ser la
    // misma cuenta (se pasan por separado). Desde C2 (ceremonia #38) el retiro
    // vende desde las huchas de la SESIÓN y firma la SESIÓN; el depósito
    // también firma la sesión; rebalanceo, cambio de cesta, liquidación y
    // rescate firman el VAULT. Este parámetro dice QUÉ PDA va como firmante
    // en las metas de la CPI (debe casar con los signer_seeds que se pasan).
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
    // ---- §3.8 (S1, ceremonia USDC): NINGÚN firmante en la ruta -------------------
    // ANTES de mirar nada más de la ruta (es la guarda más barata y la más importante
    // con un pagador ajeno firmando la transacción, §3.2). El PDA que firma por semillas
    // nunca llega firmante (no puede firmar una transacción): lo añade `route_metas`.
    check_route_signers(route_accounts)?;

    // ---- Upgrade #29 (allowlist) y F5 (comisión a 0): ver `check_route_data` ----
    check_route_data(&ix_data)?;

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
    // Note: the destination is a NAMED account of each handler and Wagon reads no
    // position inside the route (its order is the one of the Jupiter instruction,
    // V1 or V2). The destination validation above only pins WHERE the proceeds
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

    // Build AccountMeta list from the route accounts (§3.8: SOLO el PDA firmante va
    // como firmante, de forma estructural; `is_writable` se conserva tal cual lo pide
    // Jupiter). The frontend marks that PDA is_signer=false in remaining_accounts
    // because PDAs cannot sign top-level — Solana would reject the tx with "did not
    // pass signature verification". We set is_signer=true here so that invoke_signed
    // satisfies the inner signer requirement that Jupiter's swap instruction expects
    // from userPublicKey.
    let metas: Vec<AccountMeta> = route_metas(route_accounts, signing_authority);

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

// Discriminadores de las instrucciones de swap del agregador v6 que Wagon acepta:
// sha256("global:<name>")[..8], contrastados con el IDL del agregador publicado en cadena
// y con rutas reales.
const JUP_V1: [[u8; 8]; 6] = [
    [229, 23, 203, 151, 122, 227, 173, 42],   // route
    [150, 86, 71, 116, 167, 93, 14, 104],     // route_with_token_ledger
    [208, 51, 239, 151, 123, 43, 237, 92],    // exact_out_route
    [193, 32, 155, 51, 65, 214, 156, 129],    // shared_accounts_route
    [230, 121, 143, 80, 119, 159, 106, 170],  // shared_accounts_route_with_token_ledger
    [176, 209, 105, 168, 154, 125, 69, 62],   // shared_accounts_exact_out_route
];
const JUP_ROUTE_V2: [u8; 8] = [187, 100, 250, 204, 49, 196, 175, 20];
const JUP_SHARED_ACCOUNTS_ROUTE_V2: [u8; 8] = [209, 152, 83, 147, 124, 254, 216, 233];

/// Formato de los datos de una ruta de Jupiter: solo instrucciones de swap, y sin comisión de
/// plataforma. PURA sobre `ix_data`; una sola copia para todas las llamadas a `invoke_jupiter_swap`.
///
/// Upgrade #29 (allowlist): el PDA del vault firma esta CPI con `invoke_signed` y tanto `ix_data`
/// como las cuentas de la ruta las aporta un cliente no confiable: sin esta guarda, un llamante
/// malicioso haría firmar al vault una instrucción ARBITRARIA del programa de Jupiter (no un swap).
/// Se compara el discriminador Anchor (8 primeros bytes) con los puntos de entrada de swap del
/// agregador v6. En un swap genuino el orden de cuentas lo impone Jupiter y el PDA solo puede ir
/// como autoridad del swap.
///
/// F5 (ceremonia #40): la comisión de plataforma desviaría parte de cada swap a una cuenta ajena al
/// vault. Wagon no la usa: una ruta honesta la trae a 0 y aquí se exige 0 (6175).
/// - V1 (las SEIS instrucciones de la IDL v6: route, route_with_token_ledger, exact_out_route y las
///   tres shared_accounts_*): `platform_fee_bps: u8` es el ÚLTIMO argumento.
/// - V2 (ceremonia #56, las rutas de la Swap API V2 `/build`, solo ExactIn): `route_v2` lleva
///   `in_amount u64 | quoted_out_amount u64 | slippage_bps u16 | platform_fee_bps u16 |
///   positive_slippage_bps u16 | route_plan`, y `shared_accounts_route_v2` lo mismo tras `id: u8`.
///   Los dos campos de comisión van en posición FIJA, antes de la parte variable: los 4 bytes a 0.
///   Wagon tampoco usa `positive_slippage_bps`.
/// Un discriminador NUEVO en esta lista exige ubicar antes su comisión en la IDL.
pub fn check_route_data(ix_data: &[u8]) -> Result<()> {
    require!(ix_data.len() >= 8, WagonError::InvalidJupiterRoute);
    let disc = &ix_data[0..8];
    if JUP_V1.iter().any(|d| d.as_slice() == disc) {
        // Sin argumentos no es una ruta (y el «último byte» sería el del discriminador).
        require!(ix_data.len() > 8, WagonError::InvalidJupiterRoute);
        require!(
            ix_data[ix_data.len() - 1] == 0,
            WagonError::JupiterPlatformFeeNotZero
        );
        return Ok(());
    }
    // Posición de `platform_fee_bps` en las V2: 8 (discriminador) + 8 + 8 + 2, más el `id` en la
    // variante de cuentas compartidas.
    let comision = if disc == JUP_ROUTE_V2.as_slice() {
        26
    } else if disc == JUP_SHARED_ACCOUNTS_ROUTE_V2.as_slice() {
        27
    } else {
        return err!(WagonError::InvalidJupiterRoute);
    };
    require!(ix_data.len() >= comision + 4, WagonError::InvalidJupiterRoute);
    require!(
        ix_data[comision..comision + 4].iter().all(|b| *b == 0),
        WagonError::JupiterPlatformFeeNotZero
    );
    Ok(())
}

/// §3.8 (S1, ceremonia USDC): NINGÚN firmante en la ruta de Jupiter. El runtime marca
/// `is_signer` en toda cuenta cuya clave firmó la TRANSACCIÓN (el pagador del gas, el
/// inversor, un cofirmante), esté en la instrucción que esté: si un cliente mete una de esas
/// claves en la ruta, la CPI le prestaría esa firma a Jupiter (p. ej. como autoridad de
/// transferencia de las cuentas del sponsor). La única firma legítima de un swap es la del PDA
/// (vault o sesión), que no puede firmar una transacción y por tanto nunca llega firmante: la
/// pone `route_metas` por semillas. Sin excepciones. PURA sobre los `AccountInfo`; una sola
/// copia para todas las llamadas a `invoke_jupiter_swap`.
pub fn check_route_signers(route_accounts: &[AccountInfo]) -> Result<()> {
    for ai in route_accounts {
        require!(!ai.is_signer, WagonError::SignerInJupiterRoute);
    }
    Ok(())
}

/// §3.8: metas de la CPI. SOLO el PDA que firma por semillas va como firmante, de forma
/// ESTRUCTURAL (no se copia el `is_signer` que traiga la cuenta): `check_route_signers` ya
/// rechazó cualquier firmante, y así ni un cambio futuro del orden de las guardas podría
/// prestar una firma ajena a Jupiter. `is_writable` se conserva (lo fija el cliente por Jupiter).
fn route_metas(route_accounts: &[AccountInfo], signing_authority: &Pubkey) -> Vec<AccountMeta> {
    route_accounts
        .iter()
        .map(|ai| AccountMeta {
            pubkey: *ai.key,
            is_signer: *ai.key == *signing_authority,
            is_writable: ai.is_writable,
        })
        .collect()
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

#[cfg(test)]
mod route_signer_tests {
    use super::*;
    use anchor_lang::error::ERROR_CODE_OFFSET;

    fn code(r: Result<()>) -> u32 {
        match r {
            Ok(()) => 0,
            Err(Error::AnchorError(e)) => e.error_code_number,
            Err(_) => u32::MAX,
        }
    }
    /// Ruta sintética: (clave, ¿firmó la transacción?) por cuenta.
    fn run(entries: &[(Pubkey, bool)]) -> u32 {
        let owner = Pubkey::new_unique();
        let mut lam: Vec<u64> = vec![1; entries.len()];
        let mut dat: Vec<[u8; 0]> = vec![[]; entries.len()];
        let infos: Vec<AccountInfo> = lam
            .iter_mut()
            .zip(dat.iter_mut())
            .zip(entries.iter())
            .map(|((l, d), (k, s))| AccountInfo::new(k, *s, false, l, d, &owner, false, 0))
            .collect();
        code(check_route_signers(&infos))
    }

    #[test]
    fn ningun_firmante_en_la_ruta_sin_excepciones() {
        let (pda, pool, sponsor) = (Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique());
        let err = WagonError::SignerInJupiterRoute as u32 + ERROR_CODE_OFFSET;
        // Sin firmantes: pasa (el PDA llega sin firma; `route_metas` se la pone por semillas).
        assert_eq!(run(&[(pda, false), (pool, false)]), 0);
        // Cualquier clave firmante (el sponsor pagador, el inversor, un cofirmante): 6207. También si
        // fuera la propia autoridad: un PDA no puede llegar firmante y no hay excepción que abrir.
        assert_eq!(run(&[(pda, false), (sponsor, true)]), err);
        assert_eq!(run(&[(sponsor, true), (pda, false), (pool, false)]), err, "firmante antes del PDA");
        assert_eq!(run(&[(pda, true), (pool, false)]), err, "ni siquiera la autoridad");
        assert_eq!(run(&[(pool, false), (pool, true)]), err, "la misma clave repetida, una vez firmante");
        // Ruta vacía: nada que rechazar (el `require` de ruta no vacía es de `invoke_jupiter_swap`).
        assert_eq!(run(&[]), 0);
    }

    #[test]
    fn las_metas_solo_marcan_firmante_al_pda_y_conservan_writable() {
        let (pda, otra, owner) = (Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique());
        let (mut l1, mut l2) = (1u64, 1u64);
        let (mut d1, mut d2): ([u8; 0], [u8; 0]) = ([], []);
        // El PDA llega SIN firma (no puede firmar la tx) y writable; `otra` llega marcada firmante
        // (nunca debería llegar aquí, pero las metas no la copian) y de solo lectura.
        let infos = [
            AccountInfo::new(&pda, false, true, &mut l1, &mut d1, &owner, false, 0),
            AccountInfo::new(&otra, true, false, &mut l2, &mut d2, &owner, false, 0),
        ];
        let metas = route_metas(&infos, &pda);
        assert_eq!((metas[0].pubkey, metas[0].is_signer, metas[0].is_writable), (pda, true, true));
        assert_eq!((metas[1].pubkey, metas[1].is_signer, metas[1].is_writable), (otra, false, false));
    }
}

#[cfg(test)]
mod route_data_tests {
    use super::*;
    use anchor_lang::error::ERROR_CODE_OFFSET;
    use anchor_lang::solana_program::hash::hash;

    fn code(r: Result<()>) -> u32 {
        match r {
            Ok(()) => 0,
            Err(Error::AnchorError(e)) => e.error_code_number,
            Err(_) => u32::MAX,
        }
    }
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
    const RUTA: u32 = WagonError::InvalidJupiterRoute as u32 + ERROR_CODE_OFFSET;
    const COMISION: u32 = WagonError::JupiterPlatformFeeNotZero as u32 + ERROR_CODE_OFFSET;

    // Datos REALES de instrucciones del agregador en mainnet (getTransaction, 20-oct-2026).
    // `route` (V1) sin comisión, tx 2To837KE9QKT2MKziUG6T4dBZC6bWGT5urG1XMriHsG4ZFng7iSVkXiET2c4Wu724zhQwRaSLKHPBnRprwqFX2s4.
    const ROUTE_V1: &str = "e517cb977ae3ad2a01000000c10064000115170b0000000000aa725e1b06000000640000";
    // `route_v2` con comisión 50 (bytes 26-27 = 3200), tx 5dPdMVeE8YQVvcuDxLodPwbpimMnGx9ZBYsdYNLQMqi8dNAPwcy3VQec3pUhRj87xsdE86Xxm6dH2eFF8et9iYhT.
    const ROUTE_V2: &str = "bb64facc31c4af143f2851f800000000eeb5060000000000c2013200000002000000c00110270001740110270102";
    // `shared_accounts_route_v2` con comisión 20 (bytes 27-28 = 1400), tx 36gBvL2MuAtja6v6UCRNKUTNNaRuSdbMq9rGEcx6c3qRNA3k3mfT3MP4dcZCTnJXGzAkkW15z7NPbkZgp6SzZkPD.
    const SHARED_V2: &str = "d19853937cfed8e90d004429353a00000062c1b4b200000000e5001400000003000000263024000326e0020002c310270203";

    #[test]
    fn los_discriminadores_son_los_de_la_idl_y_los_de_las_rutas_reales() {
        let disc = |n: &str| hash(format!("global:{n}").as_bytes()).to_bytes()[..8].to_vec();
        let v1 = ["route", "route_with_token_ledger", "exact_out_route", "shared_accounts_route",
                  "shared_accounts_route_with_token_ledger", "shared_accounts_exact_out_route"];
        for (n, d) in v1.iter().zip(JUP_V1.iter()) {
            assert_eq!(disc(n), d.to_vec(), "{n}");
        }
        assert_eq!(disc("route_v2"), JUP_ROUTE_V2.to_vec());
        assert_eq!(disc("shared_accounts_route_v2"), JUP_SHARED_ACCOUNTS_ROUTE_V2.to_vec());
        assert_eq!(hex(ROUTE_V1)[..8], JUP_V1[0]);
        assert_eq!(hex(ROUTE_V2)[..8], JUP_ROUTE_V2);
        assert_eq!(hex(SHARED_V2)[..8], JUP_SHARED_ACCOUNTS_ROUTE_V2);
    }

    #[test]
    fn v1_sin_comision_pasa_y_con_ella_no() {
        let mut d = hex(ROUTE_V1);
        assert_eq!(code(check_route_data(&d)), 0);
        *d.last_mut().unwrap() = 1;
        assert_eq!(code(check_route_data(&d)), COMISION);
    }

    #[test]
    fn las_seis_v1_siguen_aceptadas_sin_comision_y_rechazadas_con_ella() {
        // Revisión N3: la lista V1 se reescribió como array; cada una de las seis tiene que seguir pasando (la web usa hoy
        // `shared_accounts_route`) y la comisión (último byte) seguir mordiendo en todas.
        let v1 = ["route", "route_with_token_ledger", "exact_out_route", "shared_accounts_route",
                  "shared_accounts_route_with_token_ledger", "shared_accounts_exact_out_route"];
        for n in v1 {
            let mut d = hash(format!("global:{n}").as_bytes()).to_bytes()[..8].to_vec();
            d.extend_from_slice(&[7u8, 7, 7, 0]); // argumentos cualesquiera; el último, la comisión, a 0
            assert_eq!(code(check_route_data(&d)), 0, "{n}");
            *d.last_mut().unwrap() = 1;
            assert_eq!(code(check_route_data(&d)), COMISION, "{n} con comisión");
            assert_eq!(code(check_route_data(&d[..8])), RUTA, "{n}: solo el discriminador no es una ruta");
        }
    }

    #[test]
    fn route_v2_real_con_comision_se_rechaza_y_a_cero_pasa() {
        let mut d = hex(ROUTE_V2);
        assert_eq!(u16::from_le_bytes([d[26], d[27]]), 50, "la comisión real está en 26-27");
        assert_eq!(code(check_route_data(&d)), COMISION);
        d[26] = 0;
        d[27] = 0;
        assert_eq!(code(check_route_data(&d)), 0);
        // El byte alto de la comisión y los dos de `positive_slippage_bps` también cuentan.
        for i in [27usize, 28, 29] {
            let mut x = d.clone();
            x[i] = 1;
            assert_eq!(code(check_route_data(&x)), COMISION, "byte {i}");
        }
        // Lo que va antes (cantidades, slippage) y la ruta no son comisión.
        for i in [24usize, 25, 30, d.len() - 1] {
            let mut x = d.clone();
            x[i] ^= 0xff;
            assert_eq!(code(check_route_data(&x)), 0, "byte {i}");
        }
    }

    #[test]
    fn shared_accounts_route_v2_real_con_comision_se_rechaza_y_a_cero_pasa() {
        let mut d = hex(SHARED_V2);
        assert_eq!(u16::from_le_bytes([d[27], d[28]]), 20, "la comisión real está en 27-28");
        assert_eq!(code(check_route_data(&d)), COMISION);
        d[27] = 0;
        d[28] = 0;
        assert_eq!(code(check_route_data(&d)), 0);
        for i in [28usize, 29, 30] {
            let mut x = d.clone();
            x[i] = 1;
            assert_eq!(code(check_route_data(&x)), COMISION, "byte {i}");
        }
        for i in [8usize, 25, 26, 31] {
            let mut x = d.clone();
            x[i] ^= 0xff;
            assert_eq!(code(check_route_data(&x)), 0, "byte {i}");
        }
    }

    #[test]
    fn corta_exact_out_v2_o_desconocida_es_ruta_invalida() {
        let d = hex(ROUTE_V2);
        assert_eq!(code(check_route_data(&d[..29])), RUTA, "le falta un byte de los campos de comisión");
        let mut cero = d.clone();
        cero[26] = 0;
        cero[27] = 0;
        assert_eq!(code(check_route_data(&cero[..30])), 0, "con los 4 bytes basta");
        let s = hex(SHARED_V2);
        assert_eq!(code(check_route_data(&s[..30])), RUTA);
        // ExactOut V2: `/build` no lo da y la web no lo usa; fuera del allowlist.
        for n in ["exact_out_route_v2", "shared_accounts_exact_out_route_v2", "claim", "set_token_ledger"] {
            let mut x = hash(format!("global:{n}").as_bytes()).to_bytes()[..8].to_vec();
            x.extend_from_slice(&[0u8; 40]);
            assert_eq!(code(check_route_data(&x)), RUTA, "{n}");
        }
        assert_eq!(code(check_route_data(&d[..7])), RUTA, "menos de 8 bytes");
    }
}
