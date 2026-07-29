//! Cryptographic primitives layer: Shamir sharing (SPEC §4.1), Feldman VSS (§4.2), Chaum–Pedersen DLEQ proofs (§4.4), and the verified-opening subprotocol (§4.6, §10.4).

pub mod dleq;
pub mod open;
pub mod shamir;
pub mod vss;
