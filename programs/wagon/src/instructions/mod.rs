//! All instruction handlers, one per module. Each module defines the
//! `Accounts` struct consumed by the `#[program]` entrypoint in `lib.rs`
//! plus the handler function.
//!
//! Capa 5 (upgrade #20): the monolithic `deposit` and `withdraw` were
//! retired and replaced by 4-instruction fractional flows that fit any
//! vault size in a v0 transaction packet. See `deposit_*.rs` and
//! `withdraw_*.rs`.

pub mod admin;
pub mod cache_alloc_decimals;
pub mod claim_creator_rewards;
pub mod extend_feed_registry;
pub mod close_vault;
pub mod create_vault;
pub mod deposit_init;
pub mod deposit_swap_batch;
pub mod deposit_sweep_batch;
pub mod deposit_settle;
pub mod deposit_abort;
pub mod deposit_force_release;
pub mod finalize_close;
pub mod init_feed_registry;
pub mod initialize;
pub mod mark_tvl;
pub mod rebalance;
pub mod rebalance_swap;
pub mod remove_feed;
pub mod restructure_abort;
pub mod restructure_init;
pub mod restructure_settle;
pub mod restructure_swap_batch;
pub mod set_feed;
pub mod sweep_to_usdc;
pub mod rescue_untracked_token;
pub mod withdraw_init;
pub mod withdraw_swap_batch;
pub mod withdraw_sweep_batch;
pub mod withdraw_claim_leg_in_kind;
pub mod withdraw_settle;
pub mod withdraw_abort;

#[allow(ambiguous_glob_reexports)]
#[allow(ambiguous_glob_reexports)]
pub use admin::*;
#[allow(ambiguous_glob_reexports)]
pub use cache_alloc_decimals::*;
#[allow(ambiguous_glob_reexports)]
pub use claim_creator_rewards::*;
#[allow(ambiguous_glob_reexports)]
pub use extend_feed_registry::*;
#[allow(ambiguous_glob_reexports)]
pub use close_vault::*;
#[allow(ambiguous_glob_reexports)]
pub use create_vault::*;
#[allow(ambiguous_glob_reexports)]
pub use deposit_init::*;
#[allow(ambiguous_glob_reexports)]
pub use deposit_swap_batch::*;
#[allow(ambiguous_glob_reexports)]
pub use deposit_sweep_batch::*;
#[allow(ambiguous_glob_reexports)]
pub use deposit_settle::*;
pub use deposit_force_release::*;
#[allow(ambiguous_glob_reexports)]
pub use deposit_abort::*;
#[allow(ambiguous_glob_reexports)]
pub use finalize_close::*;
#[allow(ambiguous_glob_reexports)]
#[allow(ambiguous_glob_reexports)]
pub use init_feed_registry::*;
#[allow(ambiguous_glob_reexports)]
pub use initialize::*;
#[allow(ambiguous_glob_reexports)]
pub use mark_tvl::*;
#[allow(ambiguous_glob_reexports)]
pub use rebalance::*;
#[allow(ambiguous_glob_reexports)]
pub use rebalance_swap::*;
#[allow(ambiguous_glob_reexports)]
#[allow(ambiguous_glob_reexports)]
pub use remove_feed::*;
#[allow(ambiguous_glob_reexports)]
pub use restructure_abort::*;
#[allow(ambiguous_glob_reexports)]
pub use restructure_init::*;
#[allow(ambiguous_glob_reexports)]
pub use restructure_settle::*;
#[allow(ambiguous_glob_reexports)]
pub use restructure_swap_batch::*;
#[allow(ambiguous_glob_reexports)]
pub use set_feed::*;
#[allow(ambiguous_glob_reexports)]
pub use sweep_to_usdc::*;
pub use rescue_untracked_token::*;
#[allow(ambiguous_glob_reexports)]
pub use withdraw_init::*;
#[allow(ambiguous_glob_reexports)]
pub use withdraw_swap_batch::*;
#[allow(ambiguous_glob_reexports)]
pub use withdraw_sweep_batch::*;
pub use withdraw_claim_leg_in_kind::*;
#[allow(ambiguous_glob_reexports)]
pub use withdraw_settle::*;
#[allow(ambiguous_glob_reexports)]
pub use withdraw_abort::*;
