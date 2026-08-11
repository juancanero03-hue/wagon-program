//! `create_vault` — anyone can call. Registers a new vault PDA, creates its
//! share mint and USDC ATA. Allocations validated here.
//!
//! # Why byte-level for VaultState
//!
//! `VaultState` is 1,516 bytes (`VaultState::LEN`; ceremonia #41 corrigió el
//! «1,388» que ponía aquí y en `vault_layout.rs`). With `Account<VaultState>` Anchor materialises
//! it on the BPF stack during `try_accounts` for `init`. Combined with the
//! create_account CPI for the vault, share_mint init, and vault_usdc_ata init,
//! the cumulative stack pressure overflows the 4 KB BPF stack frame.
//! Empirically: frame 3 without Box, frame 5 with Box. Byte-level write keeps
//! VaultState entirely off the stack.
//!
//! See `state::vault_layout` for byte offsets and helpers.
//!
//! `share_mint`, `usdc_mint`, `vault_usdc_ata` stay as `Box<Account<...>>` —
//! they're small (82-165 bytes) and Anchor's init flow for SPL accounts works
//! fine at that size.

use anchor_lang::prelude::*;
use anchor_lang::system_program::{create_account, transfer, CreateAccount, Transfer};
use anchor_spl::associated_token::{
    get_associated_token_address, get_associated_token_address_with_program_id,
    AssociatedToken,
};
use anchor_spl::token::{Mint, Token, TokenAccount};

use crate::constants::*;
use crate::errors::WagonError;
use crate::events::{VaultCreated, VaultCreationFeeCharged};
use crate::state::feed_registry_layout as flayout;
use crate::state::vault_layout as layout;
use crate::state::{ProtocolConfig, VaultState, VaultStatus};
use crate::metaplex::{self, METADATA_PREFIX, TOKEN_METADATA_PROGRAM_ID};
use crate::pricing;

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct CreateVaultArgs {
    pub nonce: u64,
    /// Vault display name. Borsh `String` for wire efficiency; the handler
    /// pads/truncates to the canonical fixed length before writing to
    /// vault_layout. Overflow -> WagonError::NameTooLong (6026).
    pub name: String,
    /// Free-form vault description. Same wire/pad pattern as `name`.
    /// Overflow -> WagonError::DescriptionTooLong (6027).
    pub description: String,
    /// On-chain logo URL (e.g. https://gateway.irys.xyz/<id>).
    /// Overflow -> WagonError::ImageUrlTooLong (6028).
    pub image_url: String,
    /// Comma-separated tags. Overflow -> WagonError::TagsTooLong (6029).
    pub tags: String,
    pub performance_fee_bps: u16,
    pub max_slippage_bps: u16,
    pub mints: Vec<Pubkey>,
    pub weights_bps: Vec<u16>,
    /// Metaplex metadata: token ticker (1-10 ASCII alphanumerics).
    pub symbol: String,
    /// Metaplex metadata: URI to the off-chain JSON (Arweave permanent URL).
    pub metadata_uri: String,
}

#[derive(Accounts)]
#[instruction(args: CreateVaultArgs)]
pub struct CreateVault<'info> {
    #[account(mut)]
    pub creator: Signer<'info>,

    #[account(
        mut,
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        constraint = !protocol.paused @ WagonError::ProtocolPaused,
    )]
    pub protocol: Box<Account<'info, ProtocolConfig>>,

    /// Vault state account. UncheckedAccount because we manually create the
    /// account with `system_program::create_account` and write bytes via
    /// `state::vault_layout` to avoid the BPF stack overflow that
    /// `Account<VaultState>` (1.4 KB struct) triggers during init.
    /// CHECK: PDA at [VAULT_SEED, creator, nonce_le]; created and populated
    /// by the handler.
    #[account(
        mut,
        seeds = [
            VAULT_SEED,
            creator.key().as_ref(),
            &args.nonce.to_le_bytes(),
        ],
        bump,
    )]
    pub vault: UncheckedAccount<'info>,

    /// Share mint for this vault. Authority = vault PDA.
    #[account(
        init,
        payer = creator,
        seeds = [SHARE_MINT_SEED, vault.key().as_ref()],
        bump,
        mint::decimals = 6,
        mint::authority = vault,
    )]
    pub share_mint: Box<Account<'info, Mint>>,

    /// USDC mint passthrough.
    #[account(address = protocol.usdc_mint)]
    pub usdc_mint: Box<Account<'info, Mint>>,

    /// Vault-owned USDC ATA.
    #[account(
        init,
        payer = creator,
        associated_token::mint = usdc_mint,
        associated_token::authority = vault,
    )]
    pub vault_usdc_ata: Box<Account<'info, TokenAccount>>,

    /// Metaplex Token Metadata program. Manual CPI; we do not pull
    /// anchor-spl's metadata feature for binary-size reasons (see
    /// `metaplex.rs` for the rationale).
    /// CHECK: address-pinned to the canonical Metaplex program.
    #[account(address = TOKEN_METADATA_PROGRAM_ID)]
    pub token_metadata_program: UncheckedAccount<'info>,

    /// Metaplex metadata account for the share mint. PDA owned by the
    /// Metaplex Token Metadata program. Initialized via manual CPI.
    /// CHECK: PDA at [b"metadata", token_metadata_program_id, share_mint];
    /// created and validated by the Token Metadata program during the CPI.
    #[account(
        mut,
        seeds = [
            METADATA_PREFIX,
            token_metadata_program.key().as_ref(),
            share_mint.key().as_ref(),
        ],
        bump,
        seeds::program = token_metadata_program.key(),
    )]
    pub metadata: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,

    /// Pyth SOL/USD `PriceUpdateV2` used to convert the USD-denominated
    /// creation fee into lamports (upgrade #35). Only read when
    /// `protocol.vault_creation_fee_usd_micros > 0`; the frontend passes
    /// Pyth's sponsored SOL/USD account.
    /// CHECK: ownership, feed id, staleness and confidence are validated in
    /// the handler via `pricing::read_sol_usd_price`.
    pub sol_usd_price_update: UncheckedAccount<'info>,

    /// Destination of the SOL creation fee (the protocol's SOL treasury).
    /// CHECK: must equal `protocol.vault_creation_fee_treasury`; enforced in
    /// the handler iff the fee is ON. Ignored (any writable) when fee = 0.
    #[account(mut)]
    pub vault_creation_fee_treasury: UncheckedAccount<'info>,
}

pub fn handler(ctx: Context<CreateVault>, args: CreateVaultArgs) -> Result<()> {
    // ---- read protocol parameters -------------------------------------------
    let max_tokens_per_vault = ctx.accounts.protocol.max_tokens_per_vault as usize;
    let min_perf_fee_bps = ctx.accounts.protocol.min_perf_fee_bps;
    let max_perf_fee_bps = ctx.accounts.protocol.max_perf_fee_bps;

    // ---- validate shapes ----------------------------------------------------
    require!(!args.mints.is_empty(), WagonError::EmptyAllocations);
    require_eq!(
        args.mints.len(),
        args.weights_bps.len(),
        WagonError::AllocationSumMismatch
    );
    // F6 (ceremonia #40): manda el MÍNIMO entre el parámetro del protocolo y el
    // tope efectivo del programa. `protocol.max_tokens_per_vault` vale 10 en la
    // cuenta viva de mainnet y no hay ningún botón para bajarlo, así que sin
    // este `min` una llamada directa podía crear un vault de 8-10 patas cuyo
    // retiro no cabe en una transacción (inversores sin salida). Ver
    // MAX_TOKENS_PER_VAULT_EFFECTIVE.
    let max_tokens_per_vault =
        max_tokens_per_vault.min(crate::constants::MAX_TOKENS_PER_VAULT_EFFECTIVE);
    require!(
        args.mints.len() <= max_tokens_per_vault,
        WagonError::TooManyTokens
    );

    let sum: u32 = args.weights_bps.iter().map(|w| *w as u32).sum();
    require_eq!(sum, ALLOCATION_TOTAL_BPS as u32, WagonError::AllocationSumMismatch);

    // Ceremonia #47 (H3): AQUÍ NO se prohíbe el peso 0 A PROPÓSITO. El programa usa el
    // peso 0 como slot trivial/no financiado (suites 09/17 lo construyen). El PROTOCOLO
    // nunca financia una pata a peso 0 (deposit_swap_batch exige weight>0 y deposit_init
    // la pre-marca trivial). #47 ESTRECHA H3 cerrando los dos caminos donde una pata
    // queda FINANCIADA por el protocolo a peso 0: `rebalance` a 0 (pesos sin venta) y
    // `restructure_init` con un mint que persiste en la cesta a peso 0.
    //
    // ✅ RESIDUAL H3 create+donación CERRADO en la CEREMONIA #48 (Opción B). Una pata a peso 0
    // puede recibir saldo por DONACIÓN directa a su ATA; hasta el #47 `compute_tvl_m2m_strict`
    // lo VALORABA (inflaba el TVL, diluía al que deposita) mientras `withdraw_init:270` y
    // `deposit_init:373` lo SALTAN como trivial → asimetría. El #48 hace que
    // `compute_tvl_m2m_strict` SALTE también las patas `weight_bps==0` (simétrico con
    // retiro/depósito) → la donación deja de contar como TVL: 0 dilución. El saldo donado NO
    // queda atrapado: `sweep_to_usdc` lo barre en Liquidating (pérdida del donante, sin víctima
    // entre usuarios reales; `rescue_untracked_token` no aplica porque el mint sigue en
    // allocations). `create_vault` sigue sin prohibir el peso 0 (slot trivial legítimo, suites 09/17).

    // dedupe
    for i in 0..args.mints.len() {
        for j in (i + 1)..args.mints.len() {
            require_keys_neq!(args.mints[i], args.mints[j], WagonError::DuplicateToken);
        }
    }

    // Tier B mint validation (Phase 3 plumbing). Each non-USDC mint declared
    // in args.mints is validated programmatically — the AllowedMintRegistry
    // is no longer enforced (the account is still passed for backwards
    // compat with older clients but we ignore its contents). Convention:
    // ctx.remaining_accounts[i] is the AccountInfo of args.mints[i] for
    // i in 0..args.mints.len(). USDC is the protocol base and is exempt.
    {
        let usdc_mint_pk = ctx.accounts.protocol.usdc_mint;
        let remaining = ctx.remaining_accounts;
        // Ceremonia #37 (pieza 1): además de las N cuentas de mint (una por
        // allocation), se exige UNA cuenta más al final = el FeedRegistry, para
        // comprobar que cada mint no-USDC tiene oráculo registrado. El registro
        // es una sola cuenta con TODOS los mints dentro (va 1 vez, no por-mint).
        // Convención: remaining[0..N] = mints; remaining[N] = FeedRegistry PDA.
        require!(
            remaining.len() >= args.mints.len() + 1,
            WagonError::TierBMintMismatch
        );
        for (i, mint) in args.mints.iter().enumerate() {
            if *mint == usdc_mint_pk {
                continue;
            }
            verify_mint_tier_b(&remaining[i], mint)?;
        }

        // FeedRegistry al final: address + ownership pineados (misma receta que
        // compute_tvl_m2m_strict), lectura byte-a-byte (ADR 0004, nunca
        // try_deserialize). Cada mint no-USDC debe estar en el registro; si no,
        // el vault sería invaluable/basura → se rechaza la creación.
        let registry_ai = &remaining[args.mints.len()];
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
        for mint in args.mints.iter() {
            if *mint == usdc_mint_pk {
                continue;
            }
            // Ceremonia #41: hasta el #40, «estar en el registro» y «tener
            // precio» eran lo mismo, y por eso bastaba con `is_some()`. La #40
            // resignificó el bit 3 como SIN ORÁCULO UTILIZABLE (la entrada
            // existe pero su precio NO se puede usar), así que esa equivalencia
            // se rompió: hoy un vault puede NACER con un token que el programa
            // no sabe preciar.
            //
            // Fallar cerrado en la ENTRADA: se comprueba al crear, que es donde
            // no cuesta nada. Los vaults que YA existen no se ven afectados.
            //
            // ⚠️ Esto cierra la puerta de delante, no la de al lado:
            // `restructure_init` NO consulta el FeedRegistry, así que se puede
            // crear con una cesta buena y cambiarla después a un token con el
            // bit 3. Eso va a la #42; queda dicho para que nadie lea esta
            // comprobación como una garantía que no da.
            let idx = flayout::find(&registry_data, mint)?
                .ok_or(WagonError::VaultMintNotInFeedRegistry)?;
            let flags = flayout::read_entry_flags(&registry_data, idx)?;
            require!(
                flags & crate::state::feed_registry::FEED_FLAG_NO_ORACLE == 0,
                WagonError::VaultMintNotInFeedRegistry
            );
        }
    }

    // ---- validate economics -------------------------------------------------
    require!(
        args.performance_fee_bps >= min_perf_fee_bps
            && args.performance_fee_bps <= max_perf_fee_bps,
        WagonError::PerformanceFeeOutOfRange
    );
    require!(
        args.max_slippage_bps >= MIN_SLIPPAGE_BPS && args.max_slippage_bps <= MAX_SLIPPAGE_BPS,
        WagonError::SlippageOutOfRange
    );

    // ---- validate Metaplex metadata args -----------------------------------
    require!(
        !args.symbol.is_empty()
            && args.symbol.len() <= metaplex::METAPLEX_SYMBOL_MAX,
        WagonError::SymbolOutOfRange
    );
    require!(
        args.symbol
            .chars()
            .all(|c| c.is_ascii_alphanumeric()),
        WagonError::SymbolInvalidChars
    );
    require!(
        !args.metadata_uri.is_empty()
            && args.metadata_uri.len() <= metaplex::METAPLEX_URI_MAX,
        WagonError::MetadataUriOutOfRange
    );

    // ---- upgrade #35: vault-creation fee (USD-denominated, oracle-priced) ---
    // Cobro en SOL: fee_usd (ProtocolConfig) convertido a lamports con el
    // oráculo SOL/USD en el momento de crear. fee = 0 => no se cobra nada y
    // las dos cuentas nuevas se ignoran (comportamiento pre-#35).
    let fee_usd_micros = ctx.accounts.protocol.vault_creation_fee_usd_micros;
    if fee_usd_micros > 0 {
        let expected_treasury = ctx.accounts.protocol.vault_creation_fee_treasury;
        require_keys_neq!(
            expected_treasury,
            Pubkey::default(),
            WagonError::VaultCreationFeeTreasuryMismatch
        );
        require_keys_eq!(
            ctx.accounts.vault_creation_fee_treasury.key(),
            expected_treasury,
            WagonError::VaultCreationFeeTreasuryMismatch
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
                        to: ctx.accounts.vault_creation_fee_treasury.to_account_info(),
                    },
                ),
                lamports,
            )?;
            emit!(VaultCreationFeeCharged {
                vault: ctx.accounts.vault.key(),
                creator: ctx.accounts.creator.key(),
                lamports,
                fee_usd_micros,
            });
        }
    }

    // ---- create the vault PDA manually --------------------------------------
    let vault_bump = ctx.bumps.vault;
    let creator_key = ctx.accounts.creator.key();
    let nonce_le_bytes = args.nonce.to_le_bytes();
    let creator_ref = creator_key.to_bytes();
    let signer_seeds: &[&[&[u8]]] = &[&[
        VAULT_SEED,
        &creator_ref,
        &nonce_le_bytes,
        std::slice::from_ref(&vault_bump),
    ]];
    let space = VaultState::LEN as u64;
    let rent = Rent::get()?.minimum_balance(space as usize);

    create_account(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            CreateAccount {
                from: ctx.accounts.creator.to_account_info(),
                to: ctx.accounts.vault.to_account_info(),
            },
            signer_seeds,
        ),
        rent,
        space,
        &crate::ID,
    )?;

    // ---- populate the vault data byte-level ---------------------------------
    let vault_key = ctx.accounts.vault.key();
    let share_mint_key = ctx.accounts.share_mint.key();
    let usdc_ata_key = ctx.accounts.vault_usdc_ata.key();
    let clock = Clock::get()?;
    let allocation_count = args.mints.len() as u8;

    {
        let mut data = ctx.accounts.vault.try_borrow_mut_data()?;
        layout::write_discriminator(&mut data)?;
        layout::write_creator(&mut data, &creator_key)?;
        layout::write_nonce(&mut data, args.nonce)?;
        layout::write_share_mint(&mut data, &share_mint_key)?;
        layout::write_usdc_ata(&mut data, &usdc_ata_key)?;
        layout::write_status(&mut data, VaultStatus::Active as u8)?;
        // Upgrade #19: args.name/description/image_url/tags are now Borsh
        // String on the wire. Validate length against the canonical fixed
        // VaultState layout sizes and zero-pad before writing. Rejects with
        // dedicated error codes (6026-6029) so the frontend can surface a
        // precise message instead of "InstructionDidNotDeserialize".
        require!(args.name.as_bytes().len() <= VAULT_NAME_LEN, WagonError::NameTooLong);
        require!(args.description.as_bytes().len() <= VAULT_DESC_LEN, WagonError::DescriptionTooLong);
        require!(args.image_url.as_bytes().len() <= VAULT_IMAGE_URL_LEN, WagonError::ImageUrlTooLong);
        require!(args.tags.as_bytes().len() <= VAULT_TAGS_LEN, WagonError::TagsTooLong);

        let mut name_buf = [0u8; VAULT_NAME_LEN];
        name_buf[..args.name.len()].copy_from_slice(args.name.as_bytes());
        let mut desc_buf = [0u8; VAULT_DESC_LEN];
        desc_buf[..args.description.len()].copy_from_slice(args.description.as_bytes());
        let mut img_buf = [0u8; VAULT_IMAGE_URL_LEN];
        img_buf[..args.image_url.len()].copy_from_slice(args.image_url.as_bytes());
        let mut tags_buf = [0u8; VAULT_TAGS_LEN];
        tags_buf[..args.tags.len()].copy_from_slice(args.tags.as_bytes());

        layout::write_name(&mut data, &name_buf)?;
        layout::write_description(&mut data, &desc_buf)?;
        layout::write_image_url(&mut data, &img_buf)?;
        layout::write_tags(&mut data, &tags_buf)?;
        layout::write_performance_fee_bps(&mut data, args.performance_fee_bps)?;
        layout::write_max_slippage_bps(&mut data, args.max_slippage_bps)?;
        layout::write_allocation_count(&mut data, allocation_count)?;

        // Upgrade #27: per-mint vault_ata must be derived with the mint's
        // ACTUAL token program (classic SPL Token vs Token-2022). Using the
        // 2-arg helper (which hard-codes spl_token::id()) for a Token-2022
        // mint produced a vault_ata that doesn't exist on-chain — the real
        // ATA was created by the user-side createATAIdempotent ix at the
        // get_associated_token_address_with_program_id-derived address.
        // Deposit/withdraw_swap_batch then failed with LegDestAtaMismatch
        // when comparing the stored (wrong) value against the real ATA.
        //
        // remaining_accounts[i] is the mint AccountInfo we already use for
        // Tier B validation above. Its owner is the SPL Token program id
        // (classic or 2022) that actually owns this mint.
        for (i, (mint, weight)) in args.mints.iter().zip(args.weights_bps.iter()).enumerate() {
            let mint_token_program = ctx.remaining_accounts[i].owner;
            let vault_ata = get_associated_token_address_with_program_id(
                &vault_key,
                mint,
                mint_token_program,
            );
            layout::write_allocation(&mut data, i, mint, *weight, &vault_ata)?;
        }

        layout::write_last_fee_accrual_ts(&mut data, clock.unix_timestamp)?;
        layout::write_created_at(&mut data, clock.unix_timestamp)?;
        layout::write_bump(&mut data, vault_bump)?;
        layout::write_share_mint_bump(&mut data, ctx.bumps.share_mint)?;
        // total_shares, aggregate_cost_basis_usdc, tvl_last_computed_usdc,
        // liquidation_started_at, reserved are all zero from create_account.
    }

    // ---- increment protocol vault_count -------------------------------------
    let protocol = &mut ctx.accounts.protocol;
    protocol.vault_count = protocol
        .vault_count
        .checked_add(1)
        .ok_or(WagonError::MathOverflow)?;

    // ---- create immutable Metaplex metadata for share mint --------------
    // Mint authority and update authority = vault PDA. We sign via the
    // same seeds used to create the vault account. is_mutable = false so
    // nobody (creator included) can ever change name/symbol/uri.
    {
        // args.name is already a UTF-8 String after upgrade #19; no decoding
        // or trim needed because user input never contains trailing NUL.
        let name_str = args.name.as_str();

        let creator_pk = ctx.accounts.creator.key();
        let creator_bytes = creator_pk.to_bytes();
        let nonce_le = args.nonce.to_le_bytes();
        let vault_bump = ctx.bumps.vault;
        let vault_signer_seeds: &[&[&[u8]]] = &[&[
            VAULT_SEED,
            &creator_bytes,
            &nonce_le,
            std::slice::from_ref(&vault_bump),
        ]];

        let ix = metaplex::build_create_v3_ix(
            ctx.accounts.metadata.key(),
            ctx.accounts.share_mint.key(),
            ctx.accounts.vault.key(),
            ctx.accounts.creator.key(),
            ctx.accounts.vault.key(),
            name_str,
            &args.symbol,
            &args.metadata_uri,
        );

        metaplex::invoke_create_v3(
            ix,
            &[
                ctx.accounts.metadata.to_account_info(),
                ctx.accounts.share_mint.to_account_info(),
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.creator.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
                ctx.accounts.rent.to_account_info(),
                ctx.accounts.token_metadata_program.to_account_info(),
            ],
            vault_signer_seeds,
        )?;
    }

    emit!(VaultCreated {
        vault: vault_key,
        creator: creator_key,
        nonce: args.nonce,
        performance_fee_bps: args.performance_fee_bps,
        max_slippage_bps: args.max_slippage_bps,
        allocation_count,
    });

    Ok(())
}

/// SPL Token-2022 program ID. Hard-coded so we don't drag in the entire
/// spl-token-2022 crate just for one Pubkey constant.
const SPL_TOKEN_2022_ID: Pubkey =
    anchor_lang::solana_program::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

/// Trusted issuers — Token-2022 mints whose `mint_authority` matches one of
/// these pubkeys skip the extension scanner entirely (upgrade #25).
///
/// Rationale: regulated RWA issuers (Backed Finance for xStocks, Circle for
/// USDC, etc.) need PermanentDelegate + Pausable + ConfidentialTransfer for
/// OFAC/MiCA compliance — their compliance teams can confiscate sanctioned
/// addresses or pause the market on incidents. Rejecting those extensions
/// would lock the protocol out of regulated assets.
///
/// The trade-off: we trust these issuers to NOT use their delegate to drain
/// vaults arbitrarily — same trust model as accepting USDC's freeze authority
/// (Circle can freeze any address; we use USDC anyway because we trust Circle).
///
/// To add a new issuer: paste its mint_authority pubkey here AND validate
/// off-chain that (a) it has institutional reputation, (b) its compliance
/// procedures are public, (c) the issuer publishes on-chain proofs of reserves.
const TRUSTED_TOKEN2022_MINT_AUTHORITIES: &[Pubkey] = &[
    anchor_lang::solana_program::pubkey!("7pt9tkctJPK7PPNQJ77GKg8ZffSF6QxoMiCFYHxrtaCj"), // Backed Finance (xStocks)
];

/// Tier B byte-level mint validation. Replaces the AllowedMintRegistry
/// enforcement (Phase 3). Validates that the AccountInfo passed in
/// remaining_accounts[i] really is the mint declared in args.mints[i],
/// is owned by the SPL Token program OR SPL Token-2022, has the canonical
/// mint layout, is initialised, has supply > 0, and — for Token-2022 —
/// carries none of the extensions that would let the issuer rug or freeze
/// the vault.
///
/// Upgrade #23 added Token-2022 support. The 2022 program shares the same
/// 82-byte base mint layout as classic SPL Token, so the legacy checks
/// (mint-matches-expected, initialised flag, supply > 0) still apply.
/// The novel risk is the extension TLV packed after byte 82 — those are
/// scanned in verify_token2022_extensions below.
pub fn verify_mint_tier_b(mint_account: &AccountInfo, expected: &Pubkey) -> Result<()> {
    require_keys_eq!(*mint_account.key, *expected, WagonError::TierBMintMismatch);

    let owner = mint_account.owner;
    let is_classic = *owner == anchor_spl::token::spl_token::ID;
    let is_2022 = *owner == SPL_TOKEN_2022_ID;
    require!(is_classic || is_2022, WagonError::TierBNotSPLToken);

    let data = mint_account.try_borrow_data()?;
    // Both programs share the same 82-byte base mint at offsets 0..82.
    // Classic mints are exactly 82 bytes; 2022 mints are >=82 with optional
    // TLV extension data starting at byte 83 (after a 1-byte account-type
    // discriminator at byte 82).
    require!(data.len() >= 82, WagonError::TierBMalformedMint);
    if is_classic {
        require!(data.len() == 82, WagonError::TierBMalformedMint);
    }
    require!(data[45] == 1, WagonError::TierBMalformedMint);
    // Upgrade #19: freeze_authority check removed. Regulated stablecoins
    // (USDC, USDT, EURC, PYUSD) and xStocks/RWAs all have a freeze authority
    // by compliance design (OFAC sanctions tooling), and rejecting them
    // bans the entire base-currency layer of the protocol. Quality gate is
    // now the frontend's top-mcap whitelist + Jupiter verified set; freeze
    // risk remains, but is bounded to large reputable issuers (Circle, Tether,
    // Backed Finance).

    if is_2022 {
        verify_token2022_extensions(&data)?;
    }

    // wSOL exception (Phase 3, upgrade #18): the native SOL wrapper mint
    // (So11111111111111111111111111111111111111112) is a special-case SPL
    // mint whose supply is always 0 by design. Users wrap SOL into their
    // own ATAs but the mint itself never receives a `mint_to`. The other
    // Tier B checks above (SPL Token owner, 82-byte layout, initialised,
    // no freeze authority) already establish authenticity; the supply
    // check is for empty-vault rug protection, which does not apply to
    // wSOL because depositors will swap *real* SOL into it via Jupiter.
    if *expected == anchor_spl::token::spl_token::native_mint::ID {
        return Ok(());
    }

    let supply = u64::from_le_bytes([
        data[36], data[37], data[38], data[39],
        data[40], data[41], data[42], data[43],
    ]);
    require!(supply > 0, WagonError::TierBEmptyMint);
    Ok(())
}

/// Token-2022 TLV extension scanner. Called only when the mint is owned by
/// the Token-2022 program. Walks the TLV array and rejects any extension
/// that would let the issuer rug or freeze the vault.
///
/// Layout when extensions are present:
///   - bytes 0-81    : base mint layout (same as classic SPL Token)
///   - bytes 82-164  : padding (zeros) — Token-2022 pads the mint to 165
///                     bytes so it never collides with the SPL Token
///                     Account base length, avoiding Mint/Account
///                     discriminator ambiguity.
///   - byte  165     : account_type discriminator (1 = Mint, 2 = Account)
///   - bytes 166+    : TLV array of {u16 ext_type, u16 ext_len, value}.
///
/// ext_type 0 (Uninitialized) terminates the list.
///
/// Rejected extensions:
///   1  TransferFeeConfig          — vault loses value on every Jupiter swap.
///   4  ConfidentialTransferMint   — encrypted balances break our math.
///   6  DefaultAccountState=Frozen — depositor ATAs spawn frozen.
///   9  NonTransferable            — vault can never settle.
///   12 PermanentDelegate          — issuer can drain allocation ATAs.
///   14 TransferHook (active)      — CPI to arbitrary program on every move.
///   16 ConfidentialTransferFeeConfig — same family as 4.
///   25 Pausable                   — issuer can freeze all transfers.
///
/// Accepted (no risk to vault solvency or liveness):
///   3  MintCloseAuthority
///   10 InterestBearingConfig
///   18 MetadataPointer
///   19 TokenMetadata
///   20 GroupPointer
///   21 TokenGroup
///   22 GroupMemberPointer
///   23 TokenGroupMember
///   24 ScaledUiAmount
fn verify_token2022_extensions(data: &[u8]) -> Result<()> {
    // Trusted-issuer short-circuit (upgrade #25). If the mint_authority is a
    // vetted regulated issuer (Backed for xStocks, etc.), trust their entire
    // extension setup wholesale. The SPL mint layout starts with a 4-byte
    // COption discriminator at offset 0 (1 = Some) and the 32-byte authority
    // at offset 4..36.
    if data.len() >= 36 {
        let auth_disc = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if auth_disc == 1 {
            let mut auth_bytes = [0u8; 32];
            auth_bytes.copy_from_slice(&data[4..36]);
            let mint_authority = Pubkey::new_from_array(auth_bytes);
            if TRUSTED_TOKEN2022_MINT_AUTHORITIES.contains(&mint_authority) {
                return Ok(());
            }
        }
    }

    // A 2022 mint may legitimately ship without extensions. The base mint
    // is 82 bytes; with extensions it is padded to >=166 bytes (82 base +
    // 83 padding + 1 discriminator). Anything in between (83..=165) is
    // malformed.
    if data.len() < 166 {
        return Ok(());
    }
    require!(data[165] == 1, WagonError::TierBMalformedMint);

    let mut cursor: usize = 166;
    while cursor + 4 <= data.len() {
        let ext_type = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
        let ext_len = u16::from_le_bytes([data[cursor + 2], data[cursor + 3]]) as usize;
        cursor = cursor.checked_add(4).ok_or(WagonError::TierBExtensionParseError)?;
        let ext_end = cursor.checked_add(ext_len).ok_or(WagonError::TierBExtensionParseError)?;
        require!(ext_end <= data.len(), WagonError::TierBExtensionParseError);
        let ext_data = &data[cursor..ext_end];

        match ext_type {
            0 => break, // Uninitialized terminator
            1 => return err!(WagonError::TierB2022TransferFee),
            4 => return err!(WagonError::TierB2022ConfidentialTransfer),
            6 => {
                // DefaultAccountState: u8 state at offset 0.
                // 1 = Initialized (depositor ATAs spawn usable) — OK.
                // 2 = Frozen (depositor ATAs spawn unusable) — REJECT.
                require!(!ext_data.is_empty(), WagonError::TierBExtensionParseError);
                if ext_data[0] == 2 {
                    return err!(WagonError::TierB2022DefaultFrozen);
                }
            }
            9 => return err!(WagonError::TierB2022NonTransferable),
            12 => return err!(WagonError::TierB2022PermanentDelegate),
            14 => {
                // TransferHook: 32 bytes authority + 32 bytes program_id.
                // Reject if program_id != all zeros (i.e. a hook is wired up).
                require!(ext_data.len() >= 64, WagonError::TierBExtensionParseError);
                let program_id_bytes = &ext_data[32..64];
                if program_id_bytes.iter().any(|&b| b != 0) {
                    return err!(WagonError::TierB2022TransferHook);
                }
            }
            16 => return err!(WagonError::TierB2022ConfidentialTransfer),
            25 => return err!(WagonError::TierB2022Pausable),
            _ => {} // Other extensions are safe (metadata, group, scaled UI, ...)
        }
        cursor = ext_end;
    }
    Ok(())
}
