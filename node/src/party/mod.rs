//! Per-node protocol drivers (`PartyNode`), the H5 pool manager, and
//! the A6 metrics snapshot.

// Folder organization only: the drivers stay in one file, so the module
// keeps the pre-layering name (`crate::party::party` would be noise).
pub mod metrics;
#[allow(clippy::module_inception)]
pub mod party;
pub mod pool;

pub use self::party::{Cheat, NodePayload, PartyNode};
