//! Byte-level layout of `FeedRegistry` + read/write helpers.
//!
//! Same rationale and structure as the late allowed_mints_layout: the struct is
//! ~5.7 KB, so handlers access the account bytes directly and never
//! deserialise it (BPF stack frame is 4 KB; see ADR 0004).
//!
//! # Layout (Anchor-Borsh, packed, little-endian)
//!
//! ```text
//! offset  size  field
//! ------  ----  -------------------------------------------------------
//!     0     8   discriminator (sha256("account:FeedRegistry")[..8])
//!     8    32   authority (Pubkey)
//!    40     2   count (u16)
//!    42  88*N   entries (N = MAX_PRICE_FEEDS)
//!    P      1   bump (u8)            P = 42 + 88*N
//!   P+1    32   reserved             [u8; 32]
//!
//! Total: 75 + 88*N bytes
//!
//! Each entry (88 bytes):
//!     0    32   mint (Pubkey)
//!    32    32   feed_id ([u8; 32])
//!    64     1   flags (u8)
//!    65     8   added_at (i64)
//!    73    15   reserved
//! ```

use anchor_lang::prelude::*;
use anchor_lang::Discriminator;

use crate::constants::MAX_PRICE_FEEDS;
use crate::state::feed_registry::{FeedEntry, FeedRegistry};

// ---- top-level offsets ------------------------------------------------------

pub const DISC_OFFSET: usize = 0;
pub const DISC_LEN: usize = 8;

pub const AUTHORITY_OFFSET: usize = 8;
pub const AUTHORITY_LEN: usize = 32;

pub const COUNT_OFFSET: usize = 40;
pub const COUNT_LEN: usize = 2;

pub const ENTRIES_OFFSET: usize = 42;
pub const ENTRY_LEN: usize = 88;
pub const ENTRIES_LEN: usize = ENTRY_LEN * MAX_PRICE_FEEDS;

pub const BUMP_OFFSET: usize = ENTRIES_OFFSET + ENTRIES_LEN;
pub const BUMP_LEN: usize = 1;

pub const RESERVED_OFFSET: usize = BUMP_OFFSET + BUMP_LEN;
pub const RESERVED_LEN: usize = 32;

pub const FEED_REGISTRY_TOTAL_LEN: usize = RESERVED_OFFSET + RESERVED_LEN;

// ---- entry-level offsets ----------------------------------------------------

pub const ENTRY_MINT_OFFSET: usize = 0;
pub const ENTRY_MINT_LEN: usize = 32;
pub const ENTRY_FEED_ID_OFFSET: usize = 32;
pub const ENTRY_FEED_ID_LEN: usize = 32;
pub const ENTRY_FLAGS_OFFSET: usize = 64;
pub const ENTRY_FLAGS_LEN: usize = 1;
pub const ENTRY_ADDED_AT_OFFSET: usize = 65;
pub const ENTRY_ADDED_AT_LEN: usize = 8;
pub const ENTRY_RESERVED_OFFSET: usize = 73;
pub const ENTRY_RESERVED_LEN: usize = 15;

// ---- compile-time invariants ------------------------------------------------

const _: () = {
    assert!(
        FEED_REGISTRY_TOTAL_LEN == FeedRegistry::LEN,
        "feed registry layout total len drifted from struct LEN"
    );
    assert!(
        ENTRY_LEN == FeedEntry::LEN,
        "entry size changed; update offsets"
    );
    assert!(
        ENTRY_LEN == 32 + 32 + 1 + 8 + 15,
        "entry size changed; update offsets"
    );
};

// ---- byte read helpers ------------------------------------------------------

pub fn read_count(data: &[u8]) -> Result<u16> {
    if data.len() < COUNT_OFFSET + COUNT_LEN {
        return err!(crate::errors::WagonError::FeedRegistryDataTooShort);
    }
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&data[COUNT_OFFSET..COUNT_OFFSET + COUNT_LEN]);
    Ok(u16::from_le_bytes(buf))
}

pub fn read_authority(data: &[u8]) -> Result<Pubkey> {
    if data.len() < AUTHORITY_OFFSET + AUTHORITY_LEN {
        return err!(crate::errors::WagonError::FeedRegistryDataTooShort);
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&data[AUTHORITY_OFFSET..AUTHORITY_OFFSET + AUTHORITY_LEN]);
    Ok(Pubkey::new_from_array(buf))
}

pub fn read_bump(data: &[u8]) -> Result<u8> {
    if data.len() < BUMP_OFFSET + BUMP_LEN {
        return err!(crate::errors::WagonError::FeedRegistryDataTooShort);
    }
    Ok(data[BUMP_OFFSET])
}

pub fn read_entry_mint(data: &[u8], entry_index: usize) -> Result<Pubkey> {
    let entry_start = ENTRIES_OFFSET + entry_index * ENTRY_LEN;
    if data.len() < entry_start + ENTRY_MINT_LEN {
        return err!(crate::errors::WagonError::FeedRegistryDataTooShort);
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&data[entry_start..entry_start + ENTRY_MINT_LEN]);
    Ok(Pubkey::new_from_array(buf))
}

pub fn read_entry_feed_id(data: &[u8], entry_index: usize) -> Result<[u8; 32]> {
    let start = ENTRIES_OFFSET + entry_index * ENTRY_LEN + ENTRY_FEED_ID_OFFSET;
    // (offset arithmetic kept on one binding to stay under max_width)
    if data.len() < start + ENTRY_FEED_ID_LEN {
        return err!(crate::errors::WagonError::FeedRegistryDataTooShort);
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&data[start..start + ENTRY_FEED_ID_LEN]);
    Ok(buf)
}

pub fn read_entry_flags(data: &[u8], entry_index: usize) -> Result<u8> {
    let start = ENTRIES_OFFSET + entry_index * ENTRY_LEN + ENTRY_FLAGS_OFFSET;
    if data.len() < start + ENTRY_FLAGS_LEN {
        return err!(crate::errors::WagonError::FeedRegistryDataTooShort);
    }
    Ok(data[start])
}

/// Linear scan for `mint`. O(count), bounded by MAX_PRICE_FEEDS.
pub fn find(data: &[u8], mint: &Pubkey) -> Result<Option<usize>> {
    let count = read_count(data)? as usize;
    if count > 256 {
        return err!(crate::errors::WagonError::FeedRegistryCorrupted);
    }
    let mint_bytes = mint.to_bytes();
    for i in 0..count {
        let entry_start = ENTRIES_OFFSET + i * ENTRY_LEN;
        if data.len() < entry_start + ENTRY_MINT_LEN {
            return err!(crate::errors::WagonError::FeedRegistryDataTooShort);
        }
        if data[entry_start..entry_start + ENTRY_MINT_LEN] == mint_bytes {
            return Ok(Some(i));
        }
    }
    Ok(None)
}

// ---- byte write helpers -----------------------------------------------------

pub fn write_discriminator(data: &mut [u8]) -> Result<()> {
    if data.len() < DISC_LEN {
        return err!(crate::errors::WagonError::FeedRegistryDataTooShort);
    }
    data[..DISC_LEN].copy_from_slice(&FeedRegistry::DISCRIMINATOR);
    Ok(())
}

pub fn write_authority(data: &mut [u8], authority: &Pubkey) -> Result<()> {
    if data.len() < AUTHORITY_OFFSET + AUTHORITY_LEN {
        return err!(crate::errors::WagonError::FeedRegistryDataTooShort);
    }
    data[AUTHORITY_OFFSET..AUTHORITY_OFFSET + AUTHORITY_LEN].copy_from_slice(&authority.to_bytes());
    Ok(())
}

pub fn write_count(data: &mut [u8], count: u16) -> Result<()> {
    if data.len() < COUNT_OFFSET + COUNT_LEN {
        return err!(crate::errors::WagonError::FeedRegistryDataTooShort);
    }
    data[COUNT_OFFSET..COUNT_OFFSET + COUNT_LEN].copy_from_slice(&count.to_le_bytes());
    Ok(())
}

pub fn write_bump(data: &mut [u8], bump: u8) -> Result<()> {
    if data.len() < BUMP_OFFSET + BUMP_LEN {
        return err!(crate::errors::WagonError::FeedRegistryDataTooShort);
    }
    data[BUMP_OFFSET] = bump;
    Ok(())
}

/// Write a full entry at `entry_index` (used by set_feed for both insert and
/// overwrite, and by remove_feed when swapping the tail).
pub fn write_entry(
    data: &mut [u8],
    entry_index: usize,
    mint: &Pubkey,
    feed_id: &[u8; 32],
    flags: u8,
    added_at: i64,
) -> Result<()> {
    // Upgrade #31: límite dinámico — la capacidad real la fija data_len
    // (extend_feed_registry amplía con realloc; tope duro 256).
    if entry_index >= 256 {
        return err!(crate::errors::WagonError::FeedRegistryFull);
    }
    let entry_start = ENTRIES_OFFSET + entry_index * ENTRY_LEN;
    if data.len() < entry_start + ENTRY_LEN {
        return err!(crate::errors::WagonError::FeedRegistryFull);
    }
    data[entry_start..entry_start + ENTRY_MINT_LEN].copy_from_slice(&mint.to_bytes());
    let fid_start = entry_start + ENTRY_FEED_ID_OFFSET;
    data[fid_start..fid_start + ENTRY_FEED_ID_LEN].copy_from_slice(feed_id);
    data[entry_start + ENTRY_FLAGS_OFFSET] = flags;
    data[entry_start + ENTRY_ADDED_AT_OFFSET
        ..entry_start + ENTRY_ADDED_AT_OFFSET + ENTRY_ADDED_AT_LEN]
        .copy_from_slice(&added_at.to_le_bytes());
    data[entry_start + ENTRY_RESERVED_OFFSET..entry_start + ENTRY_LEN]
        .copy_from_slice(&[0u8; ENTRY_RESERVED_LEN]);
    Ok(())
}

/// Copy entry `src_index` over `dst_index` (swap-and-pop in remove_feed).
pub fn copy_entry(data: &mut [u8], src_index: usize, dst_index: usize) -> Result<()> {
    if src_index >= MAX_PRICE_FEEDS || dst_index >= MAX_PRICE_FEEDS {
        return err!(crate::errors::WagonError::FeedRegistryCorrupted);
    }
    let src = ENTRIES_OFFSET + src_index * ENTRY_LEN;
    let dst = ENTRIES_OFFSET + dst_index * ENTRY_LEN;
    if data.len() < src + ENTRY_LEN || data.len() < dst + ENTRY_LEN {
        return err!(crate::errors::WagonError::FeedRegistryDataTooShort);
    }
    data.copy_within(src..src + ENTRY_LEN, dst);
    Ok(())
}

/// Zero the entry at `entry_index` (scrub the tail after swap-and-pop).
pub fn zero_entry(data: &mut [u8], entry_index: usize) -> Result<()> {
    if entry_index >= MAX_PRICE_FEEDS {
        return err!(crate::errors::WagonError::FeedRegistryCorrupted);
    }
    let entry_start = ENTRIES_OFFSET + entry_index * ENTRY_LEN;
    if data.len() < entry_start + ENTRY_LEN {
        return err!(crate::errors::WagonError::FeedRegistryDataTooShort);
    }
    data[entry_start..entry_start + ENTRY_LEN].fill(0);
    Ok(())
}
