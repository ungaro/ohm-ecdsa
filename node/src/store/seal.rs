//! H5 (SPEC §8.6(2), §13.3): authenticated encryption at rest — the
//! on-disk half of key-material protection. Presignature store records
//! (key-equivalent, §8.6(2)) and the identity/seed secret files no
//! longer sit on disk in cleartext: the canonical [`Encode`] bytes go
//! INSIDE a ChaCha20-Poly1305 AEAD envelope (RustCrypto
//! `chacha20poly1305`, node crate only — the core stays
//! dependency-pure).
//!
//! File format (versioned): `MAGIC(8) ‖ nonce(12) ‖ ciphertext ‖
//! Poly1305 tag(16)`, where `MAGIC` is [`SEAL_MAGIC`] — its last byte is
//! the format version and rides in the AAD, so a version downgrade fails
//! authentication. The AAD also carries a per-artifact `purpose` tag
//! (e.g. `b"identity"`, `b"presig-record" ‖ id`), binding a sealed file
//! to its role. Migration policy — FAIL CLOSED: a file without the magic
//! is a LEGACY CLEARTEXT file and is rejected with an explicit error
//! ([`SealError::LegacyCleartext`]); there is no silent downgrade and no
//! mixed-format directory.
//!
//! Key management: the AEAD key is DERIVED (`SHA-256(tag ‖ secret)`) from
//! a per-node 32-byte storage secret, resolved in order:
//!
//! 1. `OHM_STORAGE_KEY` — 64 hex chars in the environment;
//! 2. `OHM_STORAGE_KEY_FILE` — path of a key file (hex, `0600`);
//! 3. `storage.key` beside the secret material (per seed/identity dir,
//!    per store `--data-dir`) — created on first write with `0600` when
//!    nothing else is configured (the DEV default, warned about below).
//!
//! This module provides the INTERFACE, not a KMS: real deployments wire
//! the storage secret to their KMS/HSM (set `OHM_STORAGE_KEY` from a
//! secrets agent, never commit the key file). The derived key lives in a
//! page-locked buffer ([`crate::locked::LockedBytes`]) and is erased on
//! drop.
//!
//! File permissions: every secret file the node writes goes through
//! [`write_secret_file`] (`0600`, enforced even when the file already
//! exists with looser permissions), and readers warn loudly on startup
//! when an existing secret file is group/world-accessible
//! ([`warn_if_loose`]).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use k256::sha2::{Digest, Sha256};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::locked::LockedBytes;
use crate::seed;

/// Sealed-file magic: `OHMSEAL` + one format-version byte. The version
/// is authenticated (it prefixes the AAD), so a downgraded file fails
/// the AEAD open rather than being misparsed.
pub const SEAL_MAGIC: &[u8; 8] = b"OHMSEAL1";

/// Environment variable holding the storage secret as 64 hex chars.
pub const ENV_STORAGE_KEY: &str = "OHM_STORAGE_KEY";

/// Environment variable holding the PATH of a storage-key file.
pub const ENV_STORAGE_KEY_FILE: &str = "OHM_STORAGE_KEY_FILE";

/// The default storage-key file name within a secret directory.
pub const STORAGE_KEY_FILE: &str = "storage.key";

/// Domain-separation tag for the storage-key derivation.
const KEY_DERIVE_TAG: &[u8] = b"OHM-ECDSA-node/v0.1/storage-key";

/// AEAD failures. At-rest integrity FAILS CLOSED: a wrong key, a
/// tampered byte, and a legacy cleartext file are all hard errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    /// No [`SEAL_MAGIC`] prefix: a legacy cleartext file (pre-H5) —
    /// rejected, no silent downgrade. Re-run `setup`/`init` (or re-key
    /// the store) to regenerate the file sealed.
    LegacyCleartext,
    /// The AEAD open failed: wrong storage key or a tampered file.
    AuthFailed,
    /// Too short to be a sealed file.
    Malformed,
}

impl core::fmt::Display for SealError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LegacyCleartext => write!(
                f,
                "not an H5-sealed file (legacy cleartext is rejected — no silent downgrade; \
                 re-run setup/init to regenerate it sealed)"
            ),
            Self::AuthFailed => write!(
                f,
                "sealed file failed AEAD authentication (wrong storage key or tampered file)"
            ),
            Self::Malformed => write!(f, "truncated sealed file"),
        }
    }
}

impl std::error::Error for SealError {}

impl Clone for StorageKey {
    /// A second page-locked copy of the derived key (e.g. the store keeps
    /// its own); both copies are erased on drop.
    fn clone(&self) -> Self {
        Self {
            key: LockedBytes::new(self.key.as_slice().to_vec()),
        }
    }
}

/// The derived at-rest AEAD key, held page-locked ([`LockedBytes`]) and
/// erased on drop. Construct from the per-node storage secret via
/// [`StorageKey::from_secret`]; resolve the secret from the environment
/// / key file via [`StorageKey::resolve`] / [`StorageKey::resolve_or_generate`].
pub struct StorageKey {
    key: LockedBytes,
}

impl StorageKey {
    /// Derive the AEAD key from a per-node 32-byte storage secret:
    /// `SHA-256(KEY_DERIVE_TAG ‖ secret)` (domain-separated, so the raw
    /// secret can be reused by a deployment's KMS for other purposes
    /// without key-collision across applications).
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        let mut h = Sha256::new();
        h.update(KEY_DERIVE_TAG);
        h.update(secret);
        let derived: [u8; 32] = h.finalize().into();
        Self {
            key: LockedBytes::new(derived.to_vec()),
        }
    }

    /// Load the storage secret from a key FILE (hex of 32 bytes, expected
    /// `0600` — a looser file logs a loud WARNING, fail-open for
    /// availability as with `mlock`; the file's CONTENTS stay
    /// authenticated regardless).
    pub fn load(path: &Path) -> io::Result<Self> {
        warn_if_loose(path, "storage key file");
        let bytes = seed::hex_decode(&fs::read_to_string(path)?)?;
        let secret: [u8; 32] = bytes
            .try_into()
            .map_err(|_| seed::invalid("storage key file must be 32 bytes (64 hex chars)"))?;
        Ok(Self::from_secret(&secret))
    }

    /// Resolve the storage key without creating anything: `OHM_STORAGE_KEY`
    /// → `OHM_STORAGE_KEY_FILE` → `<beside>/storage.key`. `Ok(None)` when
    /// nothing is configured (readers then reject sealed files with a
    /// clear "no storage key configured" error).
    pub fn resolve(beside: &Path) -> io::Result<Option<Self>> {
        if let Ok(hex) = std::env::var(ENV_STORAGE_KEY) {
            let bytes = seed::hex_decode(&hex)?;
            let secret: [u8; 32] = bytes
                .try_into()
                .map_err(|_| seed::invalid("OHM_STORAGE_KEY must be 32 bytes (64 hex chars)"))?;
            return Ok(Some(Self::from_secret(&secret)));
        }
        if let Ok(path) = std::env::var(ENV_STORAGE_KEY_FILE) {
            return Ok(Some(Self::load(Path::new(&path))?));
        }
        let default = beside.join(STORAGE_KEY_FILE);
        if default.exists() {
            return Ok(Some(Self::load(&default)?));
        }
        Ok(None)
    }

    /// Resolve the storage key, generating the DEV default
    /// (`<dir>/storage.key`, random, `0600`) when nothing is configured.
    /// For WRITERS only (setup/init/store open): the generated key
    /// persists, so later reads of the same directory resolve it back.
    /// Real deployments set `OHM_STORAGE_KEY`/`OHM_STORAGE_KEY_FILE`
    /// from their KMS instead — the generated file is convenience, not
    /// key management.
    pub fn resolve_or_generate(dir: &Path) -> io::Result<Self> {
        if let Some(key) = Self::resolve(dir)? {
            return Ok(key);
        }
        fs::create_dir_all(dir)?;
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let path = dir.join(STORAGE_KEY_FILE);
        write_secret_file(&path, seed::hex_encode(&secret).as_bytes())?;
        eprintln!(
            "WARNING [H5]: generated a DEV storage key at {} (0600). Set {ENV_STORAGE_KEY} or \
             {ENV_STORAGE_KEY_FILE} from your KMS/secrets agent for a real deployment — \
             a key file next to the data only defends against offline disk theft.",
            path.display()
        );
        Ok(Self::from_secret(&secret))
    }

    /// Seal `plaintext` for `purpose`: `MAGIC ‖ nonce ‖ AEAD(key,
    /// AAD = MAGIC ‖ purpose, plaintext)`. The nonce is fresh random per
    /// call (OsRng), so sealing the same record twice yields different
    /// bytes.
    pub fn seal(&self, purpose: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let cipher =
            ChaCha20Poly1305::new_from_slice(self.key.as_slice()).expect("derived key is 32 bytes");
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let mut aad = SEAL_MAGIC.to_vec();
        aad.extend_from_slice(purpose);
        let ct = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("AEAD encrypt with a valid key/nonce cannot fail");
        let mut out = Vec::with_capacity(SEAL_MAGIC.len() + nonce.len() + ct.len());
        out.extend_from_slice(SEAL_MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// Whether `bytes` carries the sealed-file magic (cleartext
    /// detection — NOT authentication; [`StorageKey::open`] is that).
    pub fn is_sealed(bytes: &[u8]) -> bool {
        bytes.starts_with(SEAL_MAGIC)
    }

    /// Inverse of [`StorageKey::seal`]; fails closed on a legacy
    /// cleartext file, a truncated file, a wrong key, or any tampering.
    pub fn open(&self, purpose: &[u8], sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        if !Self::is_sealed(sealed) {
            return Err(SealError::LegacyCleartext);
        }
        let rest = sealed.get(SEAL_MAGIC.len()..).ok_or(SealError::Malformed)?;
        if rest.len() < 12 {
            return Err(SealError::Malformed);
        }
        let (nonce, ct) = rest.split_at(12);
        let nonce: [u8; 12] = nonce.try_into().map_err(|_| SealError::Malformed)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(self.key.as_slice()).expect("derived key is 32 bytes");
        let mut aad = SEAL_MAGIC.to_vec();
        aad.extend_from_slice(purpose);
        cipher
            .decrypt(&Nonce::from(nonce), Payload { msg: ct, aad: &aad })
            .map_err(|_| SealError::AuthFailed)
    }
}

/// Write a SECRET file with `0600` permissions — enforced even when the
/// file already exists with looser permissions (`OpenOptions::mode`
/// applies only at creation, so the mode is set explicitly afterwards).
pub fn write_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        io::Write::write_all(&mut f, bytes)?;
        f.sync_all()?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes)
    }
}

/// The `0600` check for an existing secret file: warn loudly (on
/// startup/read) when group or other has ANY access. Fail-open for
/// availability, like `mlock` — the contents stay authenticated either
/// way; fix the mode at the ops level.
pub fn warn_if_loose(path: &Path, what: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                eprintln!(
                    "WARNING [H5]: {what} {} has permissions {mode:04o} — secret files must be \
                     0600; run `chmod 600` on it.",
                    path.display()
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (path, what);
}

/// The default storage-key file path within a secret directory.
pub fn storage_key_file(dir: &Path) -> PathBuf {
    dir.join(STORAGE_KEY_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "ohm-seal-test-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_key() -> StorageKey {
        StorageKey::from_secret(&[0x42u8; 32])
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = test_key();
        let sealed = key.seal(b"test-purpose", b"canonical bytes inside");
        assert!(StorageKey::is_sealed(&sealed));
        // A second seal of the same plaintext differs (fresh nonce).
        assert_ne!(sealed, key.seal(b"test-purpose", b"canonical bytes inside"));
        let back = key.open(b"test-purpose", &sealed).unwrap();
        assert_eq!(back, b"canonical bytes inside");
    }

    #[test]
    fn wrong_key_is_an_error_not_garbage() {
        let sealed = test_key().seal(b"p", b"secret record");
        let other = StorageKey::from_secret(&[0x43u8; 32]);
        assert_eq!(other.open(b"p", &sealed), Err(SealError::AuthFailed));
    }

    #[test]
    fn tampering_and_wrong_purpose_fail_closed() {
        let key = test_key();
        let sealed = key.seal(b"purpose-a", b"record");
        // One flipped ciphertext byte.
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert_eq!(
            key.open(b"purpose-a", &tampered),
            Err(SealError::AuthFailed)
        );
        // The same bytes under a different purpose tag.
        assert_eq!(key.open(b"purpose-b", &sealed), Err(SealError::AuthFailed));
        // Truncation.
        assert_eq!(
            key.open(b"purpose-a", &sealed[..10]),
            Err(SealError::Malformed)
        );
    }

    #[test]
    fn legacy_cleartext_is_rejected_explicitly() {
        let key = test_key();
        // Anything without the magic — a pre-H5 cleartext file — is a
        // hard error, never a silent downgrade.
        assert_eq!(
            key.open(b"p", b"\x00\x00\x00\x00legacy canonical bytes"),
            Err(SealError::LegacyCleartext)
        );
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_are_written_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("perms");
        let path = dir.join("secret.bin");
        write_secret_file(&path, b"sekrit").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "fresh file: {mode:04o}");
        // A pre-existing LOOSER file is tightened on rewrite.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_secret_file(&path, b"sekrit2").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "rewritten file: {mode:04o}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn generated_storage_key_roundtrips_and_is_0600() {
        let dir = tmpdir("keygen");
        let key = StorageKey::resolve_or_generate(&dir).unwrap();
        let path = storage_key_file(&dir);
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // A fresh resolve on the same directory loads the SAME key:
        // what one instance seals, the reopened one opens.
        let sealed = key.seal(b"p", b"record");
        let reopened = StorageKey::resolve(&dir).unwrap().expect("key file exists");
        assert_eq!(reopened.open(b"p", &sealed).unwrap(), b"record");
        fs::remove_dir_all(&dir).ok();
    }
}
