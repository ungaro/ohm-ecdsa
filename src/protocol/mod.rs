//! Protocol layer: commit-reveal Pedersen DKG (SPEC §6, §6.1, §7.3), Beaver triple factory (§7, §7.3, §7.4), presignatures (§8, §8.5, §7.4.3), online signing (§9, §10.4), committee maintenance (§13.4).

pub mod dkg;
pub mod presign;
pub mod refresh;
pub mod sign;
pub mod triples;
