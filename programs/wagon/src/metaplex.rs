//! Manual CPI to the Metaplex Token Metadata program (`mpl-token-metadata` v4).
//!
//! We hand-craft the `CreateMetadataAccountV3` instruction the same way
//! `jupiter.rs` hand-crafts a Jupiter swap call. The reason is binary size:
//! pulling the `anchor-spl` "metadata" feature transitively brings in
//! `mpl-token-metadata` as a real dependency and adds 10-30 KB to the BPF
//! binary. ProgramData currently has ~15 KB of headroom so the safe play is a
//! manual encoder.
//!
//! Reference: https://github.com/metaplex-foundation/mpl-token-metadata
//! Instruction enum variant for `CreateMetadataAccountV3` is `33` (0x21) in
//! the Token Metadata v4 instruction layout.
//!
//! All metadata produced via this helper is written with `is_mutable = false`
//! and `seller_fee_basis_points = 0`. The `update_authority` is set to the
//! vault PDA but is vestigial — once `is_mutable` is false the only operation
//! the metadata program will accept is a no-op authority transfer, which we
//! never call. This matches the pump.fun / immutable-fair-launch model.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::invoke_signed;
use anchor_lang::solana_program::sysvar;

/// Metaplex Token Metadata program ID. Same on mainnet, devnet, and testnet.
pub const TOKEN_METADATA_PROGRAM_ID: Pubkey =
    pubkey!("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s");

/// PDA seed prefix for metadata accounts. The metadata PDA is derived from
/// `[METADATA_PREFIX, TOKEN_METADATA_PROGRAM_ID, mint]` under the metadata
/// program.
pub const METADATA_PREFIX: &[u8] = b"metadata";

/// Discriminator for `CreateMetadataAccountV3` in the Token Metadata
/// instruction enum (mpl-token-metadata v4.x).
const CREATE_V3_DISCRIMINATOR: u8 = 33;

/// Maximum lengths enforced by the Token Metadata program for `DataV2` fields.
pub const METAPLEX_NAME_MAX: usize = 32;
pub const METAPLEX_SYMBOL_MAX: usize = 10;
pub const METAPLEX_URI_MAX: usize = 200;

/// Find the canonical metadata PDA for a given mint.
pub fn find_metadata_pda(mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            METADATA_PREFIX,
            TOKEN_METADATA_PROGRAM_ID.as_ref(),
            mint.as_ref(),
        ],
        &TOKEN_METADATA_PROGRAM_ID,
    )
}

/// Borsh-encode a string into the buffer (`u32` length prefix + UTF-8 bytes).
fn write_borsh_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// Build the `CreateMetadataAccountV3` instruction with our fixed config:
/// - `seller_fee_basis_points = 0`
/// - `creators = None`, `collection = None`, `uses = None`
/// - `is_mutable = false`
/// - `collection_details = None`
///
/// Account ordering (v4):
///   0. `[writable]`            metadata account
///   1. `[]`                    mint
///   2. `[signer]`              mint authority
///   3. `[writable, signer]`    payer
///   4. `[]`                    update authority (signer flag depends on the
///                              `update_authority_is_signer` field; we pass
///                              false since we set is_mutable = false)
///   5. `[]`                    system program
///   6. `[]`                    rent sysvar
pub fn build_create_v3_ix(
    metadata: Pubkey,
    mint: Pubkey,
    mint_authority: Pubkey,
    payer: Pubkey,
    update_authority: Pubkey,
    name: &str,
    symbol: &str,
    uri: &str,
) -> Instruction {
    let mut data = Vec::with_capacity(256);
    data.push(CREATE_V3_DISCRIMINATOR);

    // DataV2 borsh layout:
    //   name: String
    //   symbol: String
    //   uri: String
    //   seller_fee_basis_points: u16
    //   creators: Option<Vec<Creator>>
    //   collection: Option<Collection>
    //   uses: Option<Uses>
    write_borsh_string(&mut data, name);
    write_borsh_string(&mut data, symbol);
    write_borsh_string(&mut data, uri);
    data.extend_from_slice(&0u16.to_le_bytes()); // seller_fee_basis_points
    data.push(0); // creators: None
    data.push(0); // collection: None
    data.push(0); // uses: None

    // Trailing args of CreateMetadataAccountV3:
    //   is_mutable: bool
    //   collection_details: Option<CollectionDetails>
    data.push(0); // is_mutable = false (immutable forever)
    data.push(0); // collection_details: None

    Instruction {
        program_id: TOKEN_METADATA_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(metadata, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(mint_authority, true),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(update_authority, false),
            AccountMeta::new_readonly(
                anchor_lang::solana_program::system_program::ID,
                false,
            ),
            AccountMeta::new_readonly(sysvar::rent::ID, false),
        ],
        data,
    }
}

/// Invoke `CreateMetadataAccountV3` with vault PDA signer seeds for
/// `mint_authority`. The caller provides `accounts` in this order:
///   0: metadata
///   1: mint
///   2: mint_authority (vault PDA)
///   3: payer
///   4: update_authority
///   5: system_program
///   6: rent
///   7: token_metadata_program (the program account itself, required by
///      `invoke_signed`)
pub fn invoke_create_v3<'info>(
    ix: Instruction,
    accounts: &[AccountInfo<'info>],
    vault_signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    invoke_signed(&ix, accounts, vault_signer_seeds).map_err(Into::into)
}
