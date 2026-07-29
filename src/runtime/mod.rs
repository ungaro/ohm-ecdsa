//! Runtime layer: transport seam (SPEC §13.1/§13.2), reference orchestrator (§4.7, §13.2), single-use presignature store (§8.6), expel-and-restart policy (§10.3).

pub mod policy;
pub mod sim;
pub mod store;
pub mod transport;
