//! Per-node protocol drivers (`PartyNode`) and the H5 pool manager.

// Folder organization only: the drivers stay in one file, so the module
// keeps the pre-layering name (`crate::party::party` would be noise).
#[allow(clippy::module_inception)]
pub mod party;
pub mod pool;

pub use self::party::{Cheat, NodePayload, PartyNode};
