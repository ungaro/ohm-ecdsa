//! Durability and key-material protection: the persistent presignature
//! store + transcript archive, AEAD sealing at rest, and page-locked
//! secrets.

pub mod locked;
pub mod persist;
pub mod seal;
