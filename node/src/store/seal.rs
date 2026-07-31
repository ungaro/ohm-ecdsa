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
//! a per-node 32-byte storage secret, resolved ([`StorageKeySource`], A5)
//! in order:
//!
//! 1. `OHM_STORAGE_KEY_CMD` — an external helper command (a Vault agent
//!    wrapper, a cloud-KMS CLI, a sops/age decryptor, …) printing the
//!    32-byte secret as hex on stdout — the KMS/HSM plug-in point; a
//!    failing helper is a HARD error, never a silent fallback;
//! 2. `OHM_STORAGE_KEY` — 64 hex chars in the environment;
//! 3. `OHM_STORAGE_KEY_FILE` — path of a key file (hex, `0600`);
//! 4. `storage.key` beside the secret material (per seed/identity dir,
//!    per store `--data-dir`) — created on first write with `0600` when
//!    nothing else is configured (the DEV default, warned about below).
//!
//! This module provides the INTERFACE, not a KMS: real deployments plug
//! their KMS/HSM agent in via the helper command (or export
//! `OHM_STORAGE_KEY` from a secrets agent; never commit the key file).
//! The helper runs as the node's OS user, its stdout is secret, and the
//! node never logs it. Key rotation = rotate the secret in the KMS and
//! restart the node — records sealed under the old key no longer open
//! (re-sealing tooling is NOT built; see node/README.md, H5). The
//! derived key lives in a page-locked buffer
//! ([`crate::locked::LockedBytes`]) and is erased on drop.
//!
//! File permissions: every secret file the node writes goes through
//! [`write_secret_file`] (`0600`, enforced even when the file already
//! exists with looser permissions), and readers warn loudly on startup
//! when an existing secret file is group/world-accessible
//! ([`warn_if_loose`]).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

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

/// Environment variable holding the storage-key helper COMMAND (A5).
/// The value is split on whitespace — simple tokenization, NOT a shell
/// (no quoting, pipes, redirects, or expansion). The first token is the
/// program (resolved via `PATH`), the rest its arguments; the helper
/// must print the 32-byte storage secret as hex on stdout and exit 0.
pub const ENV_STORAGE_KEY_CMD: &str = "OHM_STORAGE_KEY_CMD";

/// Default deadline for a [`StorageKeySource::Command`] helper run.
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

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

    /// Resolve the storage key without creating anything:
    /// `OHM_STORAGE_KEY_CMD` (A5 helper) → `OHM_STORAGE_KEY` →
    /// `OHM_STORAGE_KEY_FILE` → `<beside>/storage.key`. `Ok(None)` when
    /// nothing is configured (readers then reject sealed files with a
    /// clear "no storage key configured" error). A CONFIGURED source
    /// that fails is a hard error — never a silent fall-through.
    pub fn resolve(beside: &Path) -> io::Result<Option<Self>> {
        match configured_source(beside)? {
            Some(source) => Ok(Some(source.resolve_key()?)),
            None => Ok(None),
        }
    }

    /// Resolve the storage key, falling back to the DEV default
    /// ([`StorageKeySource::Generated`] — random `<dir>/storage.key`,
    /// `0600`, loudly warned) ONLY when nothing is configured. For
    /// WRITERS only (setup/init/store open): the generated key
    /// persists, so later reads of the same directory resolve it back.
    /// Real deployments plug their KMS in via `OHM_STORAGE_KEY_CMD` (or
    /// set `OHM_STORAGE_KEY`/`OHM_STORAGE_KEY_FILE`) — the generated
    /// file is convenience, not key management. An explicitly
    /// configured source that fails is a hard error: this function
    /// NEVER silently generates when a source was configured.
    pub fn resolve_or_generate(dir: &Path) -> io::Result<Self> {
        resolve_or_generate_source(dir, configured_source(dir)?)
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

/// A5 (SPEC §13.3): WHERE the per-node storage secret comes from — the
/// storage-key source abstraction. The crate ships this interface, not
/// a KMS: real deployments plug their KMS/HSM agent in via
/// [`StorageKeySource::Command`] (or export `OHM_STORAGE_KEY` from
/// their secrets agent) with no code changes.
///
/// Resolution order ([`configured_source`]): an explicitly configured
/// [`StorageKeySource::Command`] wins whenever set →
/// [`StorageKeySource::EnvVar`] → [`StorageKeySource::KeyFile`]
/// (`OHM_STORAGE_KEY_FILE`, then `<dir>/storage.key` when it exists) →
/// [`StorageKeySource::Generated`] (writers only, loudly warned). A
/// configured source that fails is a HARD error — resolution never
/// falls through to a weaker source, and never silently generates.
pub enum StorageKeySource {
    /// `OHM_STORAGE_KEY` — 64 hex chars in the environment.
    EnvVar,
    /// A key FILE (hex, expected `0600` — looser logs a loud warning):
    /// `OHM_STORAGE_KEY_FILE` or the default `<dir>/storage.key`.
    KeyFile(PathBuf),
    /// An external helper (a Vault agent wrapper, a cloud-KMS CLI, a
    /// sops/age decryptor, …) printing the secret as hex on stdout.
    /// Operational contract: the helper runs as the node's OS user with
    /// the node's privileges (its own auth to the KMS is the
    /// deployment's business); its stdout is SECRET — the node reads it
    /// into memory and never logs it; its stderr is inherited, so the
    /// helper must keep the secret out of its own diagnostics.
    Command {
        /// The program to execute (resolved via `PATH`).
        program: String,
        /// Its arguments — passed verbatim, NO shell interpretation.
        args: Vec<String>,
        /// Deadline for the whole run; on expiry the helper is KILLED
        /// and resolution fails closed.
        timeout: Duration,
    },
    /// The DEV fallback: generate a random `<dir>/storage.key` (`0600`)
    /// with a loud warning. Convenience, not key management.
    Generated(PathBuf),
}

impl StorageKeySource {
    /// Resolve the storage key from this source. Every failure is a
    /// hard `io::Error` — callers never fall through to another source
    /// once one is explicitly configured (fail closed).
    pub fn resolve_key(&self) -> io::Result<StorageKey> {
        match self {
            Self::EnvVar => {
                let hex = std::env::var(ENV_STORAGE_KEY).map_err(|_| {
                    seed::invalid("OHM_STORAGE_KEY source configured but the variable is unset")
                })?;
                let bytes = seed::hex_decode(&hex)?;
                let secret: [u8; 32] = bytes.try_into().map_err(|_| {
                    seed::invalid("OHM_STORAGE_KEY must be 32 bytes (64 hex chars)")
                })?;
                Ok(StorageKey::from_secret(&secret))
            }
            Self::KeyFile(path) => StorageKey::load(path),
            Self::Command {
                program,
                args,
                timeout,
            } => {
                let secret = run_helper(program, args, *timeout)?;
                Ok(StorageKey::from_secret(&secret))
            }
            Self::Generated(dir) => generate_dev_key(dir),
        }
    }
}

/// The configured source from already-read environment values, in
/// precedence order: explicit Command → EnvVar → KeyFile
/// (`OHM_STORAGE_KEY_FILE`, then `<beside>/storage.key` when it exists)
/// → `None` (writers then use [`StorageKeySource::Generated`]). Split
/// from the env reads so precedence is testable without mutating the
/// process environment. A whitespace-only Command string is a hard
/// error, not a skip — explicit configuration must fail loudly.
fn source_from_env(
    cmd: Option<String>,
    key_hex: Option<String>,
    key_file: Option<String>,
    beside: &Path,
) -> io::Result<Option<StorageKeySource>> {
    if let Some(cmd) = cmd {
        let mut tokens = cmd.split_whitespace();
        let program = tokens
            .next()
            .ok_or_else(|| seed::invalid("OHM_STORAGE_KEY_CMD is empty (whitespace-only)"))?;
        return Ok(Some(StorageKeySource::Command {
            program: program.to_string(),
            args: tokens.map(str::to_string).collect(),
            timeout: DEFAULT_COMMAND_TIMEOUT,
        }));
    }
    if key_hex.is_some() {
        return Ok(Some(StorageKeySource::EnvVar));
    }
    if let Some(path) = key_file {
        return Ok(Some(StorageKeySource::KeyFile(PathBuf::from(path))));
    }
    let default = beside.join(STORAGE_KEY_FILE);
    if default.exists() {
        return Ok(Some(StorageKeySource::KeyFile(default)));
    }
    Ok(None)
}

/// Read the process environment and return the configured
/// [`StorageKeySource`] (precedence: Command → EnvVar → KeyFile →
/// `None`). A5: `OHM_STORAGE_KEY_CMD` wins whenever set — an explicit
/// KMS plug-in configuration must never be overridden by accident, and
/// its failure must never fall back silently.
pub fn configured_source(beside: &Path) -> io::Result<Option<StorageKeySource>> {
    source_from_env(
        std::env::var(ENV_STORAGE_KEY_CMD).ok(),
        std::env::var(ENV_STORAGE_KEY).ok(),
        std::env::var(ENV_STORAGE_KEY_FILE).ok(),
        beside,
    )
}

/// The composed writer path behind [`StorageKey::resolve_or_generate`]
/// (split out so tests can drive it with an explicit source).
fn resolve_or_generate_source(
    dir: &Path,
    source: Option<StorageKeySource>,
) -> io::Result<StorageKey> {
    match source {
        Some(source) => source.resolve_key(),
        None => StorageKeySource::Generated(dir.to_path_buf()).resolve_key(),
    }
}

/// The DEV fallback ([`StorageKeySource::Generated`]): a random
/// `<dir>/storage.key` (`0600`) with a loud warning.
fn generate_dev_key(dir: &Path) -> io::Result<StorageKey> {
    fs::create_dir_all(dir)?;
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let path = dir.join(STORAGE_KEY_FILE);
    write_secret_file(&path, seed::hex_encode(&secret).as_bytes())?;
    eprintln!(
        "WARNING [H5]: generated a DEV storage key at {} (0600). Set {ENV_STORAGE_KEY}, \
         {ENV_STORAGE_KEY_FILE}, or {ENV_STORAGE_KEY_CMD} from your KMS/secrets agent for a \
         real deployment — a key file next to the data only defends against offline disk theft.",
        path.display()
    );
    Ok(StorageKey::from_secret(&secret))
}

/// Run a [`StorageKeySource::Command`] helper: stdout (trimmed) must be
/// the 32-byte secret as hex, exit status 0, within `timeout` — any
/// deviation is a HARD error (fail closed). stdout is drained on a
/// helper thread so a blocking read cannot stall the deadline; on
/// timeout the helper is KILLED. The secret is never logged.
fn run_helper(program: &str, args: &[String], timeout: Duration) -> io::Result<[u8; 32]> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| {
            seed::invalid(&format!(
                "storage-key helper `{program}` failed to start: {e}"
            ))
        })?;
    let mut stdout = child.stdout.take().expect("stdout piped");
    let drain = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = io::Read::read_to_end(&mut stdout, &mut buf);
        buf
    });
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(seed::invalid(&format!(
                        "storage-key helper `{program}` exceeded its {timeout:?} deadline (killed)"
                    )));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        }
    };
    if !status.success() {
        return Err(seed::invalid(&format!(
            "storage-key helper `{program}` exited with {status}"
        )));
    }
    // Exit 0: stdout is at EOF, so the drain thread has finished.
    let out = drain.join().unwrap_or_default();
    let text = String::from_utf8(out)
        .map_err(|_| seed::invalid("storage-key helper stdout is not UTF-8 hex"))?;
    let bytes = seed::hex_decode(text.trim())
        .map_err(|_| seed::invalid("storage-key helper stdout must be hex"))?;
    bytes
        .try_into()
        .map_err(|_| seed::invalid("storage-key helper stdout must be 32 bytes (64 hex chars)"))
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

    /// Write an executable fixture helper script (A5 tests).
    #[cfg(unix)]
    fn write_helper(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[cfg(unix)]
    fn command_source(program: &Path, timeout: Duration) -> StorageKeySource {
        StorageKeySource::Command {
            program: program.to_string_lossy().into_owned(),
            args: Vec::new(),
            timeout,
        }
    }

    #[cfg(unix)]
    #[test]
    fn command_source_valid_hex_resolves() {
        let dir = tmpdir("cmd-ok");
        let helper = write_helper(
            &dir,
            "emit-key.sh",
            &format!("#!/bin/sh\necho {}\n", "42".repeat(32)),
        );
        let key = command_source(&helper, Duration::from_secs(5))
            .resolve_key()
            .unwrap();
        // The same secret derives the same key as `from_secret` directly.
        let reference = StorageKey::from_secret(&[0x42u8; 32]);
        let sealed = reference.seal(b"p", b"record");
        assert_eq!(key.open(b"p", &sealed).unwrap(), b"record");
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn command_source_nonzero_exit_is_a_hard_error() {
        let dir = tmpdir("cmd-exit");
        let helper = write_helper(&dir, "fail.sh", "#!/bin/sh\nexit 1\n");
        let err = command_source(&helper, Duration::from_secs(5))
            .resolve_key()
            .err()
            .expect("non-zero exit must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn command_source_garbage_stdout_is_a_hard_error() {
        let dir = tmpdir("cmd-garbage");
        let garbage = write_helper(&dir, "garbage.sh", "#!/bin/sh\necho not-hex-at-all\n");
        assert!(command_source(&garbage, Duration::from_secs(5))
            .resolve_key()
            .is_err());
        // Valid hex but the wrong length is equally refused.
        let short = write_helper(&dir, "short.sh", "#!/bin/sh\necho abcd\n");
        assert!(command_source(&short, Duration::from_secs(5))
            .resolve_key()
            .is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn command_source_timeout_is_a_hard_error() {
        let dir = tmpdir("cmd-timeout");
        let helper = write_helper(&dir, "hang.sh", "#!/bin/sh\nsleep 10\n");
        let start = std::time::Instant::now();
        let err = command_source(&helper, Duration::from_millis(200))
            .resolve_key()
            .err()
            .expect("a hanging helper must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "timeout path took {:?}",
            start.elapsed()
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn source_precedence_command_env_keyfile_generated() {
        let dir = tmpdir("precedence");
        // Command beats everything whenever set.
        let src = source_from_env(
            Some("vault kv get -field=hex secret/ohm/node1".to_string()),
            Some("ab".repeat(32)),
            Some("/tmp/key".to_string()),
            &dir,
        )
        .unwrap()
        .expect("command configured");
        match src {
            StorageKeySource::Command {
                program,
                args,
                timeout,
            } => {
                assert_eq!(program, "vault");
                assert_eq!(args, ["kv", "get", "-field=hex", "secret/ohm/node1"]);
                assert_eq!(timeout, DEFAULT_COMMAND_TIMEOUT);
            }
            _ => panic!("command must win"),
        }
        // A whitespace-only command config is a hard error, not a skip.
        assert!(source_from_env(Some("   ".to_string()), None, None, &dir).is_err());
        // EnvVar beats both file sources.
        assert!(matches!(
            source_from_env(
                None,
                Some("ab".repeat(32)),
                Some("/tmp/key".to_string()),
                &dir
            )
            .unwrap(),
            Some(StorageKeySource::EnvVar)
        ));
        // `OHM_STORAGE_KEY_FILE` beats the default beside the dir...
        fs::write(dir.join(STORAGE_KEY_FILE), "ab".repeat(32)).unwrap();
        match source_from_env(None, None, Some("/tmp/key".to_string()), &dir)
            .unwrap()
            .unwrap()
        {
            StorageKeySource::KeyFile(p) => assert_eq!(p, Path::new("/tmp/key")),
            _ => panic!("explicit key file must win"),
        }
        // ...and the default is picked up only when it exists.
        match source_from_env(None, None, None, &dir).unwrap().unwrap() {
            StorageKeySource::KeyFile(p) => assert_eq!(p, dir.join(STORAGE_KEY_FILE)),
            _ => panic!("default key file expected"),
        }
        // Nothing configured anywhere → None (writers use Generated).
        let empty = tmpdir("precedence-empty");
        assert!(source_from_env(None, None, None, &empty).unwrap().is_none());
        fs::remove_dir_all(&dir).ok();
        fs::remove_dir_all(&empty).ok();
    }

    #[cfg(unix)]
    #[test]
    fn failing_command_source_never_falls_back_to_generated() {
        let dir = tmpdir("cmd-no-fallback");
        let helper = write_helper(&dir, "fail.sh", "#!/bin/sh\nexit 1\n");
        let source = command_source(&helper, Duration::from_secs(5));
        // The composed writer path: a configured-but-failing source is a
        // hard error, and NO dev key file appears.
        let err = resolve_or_generate_source(&dir, Some(source))
            .err()
            .expect("a failing configured source must fail closed");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            !storage_key_file(&dir).exists(),
            "no silent generated dev key"
        );
        fs::remove_dir_all(&dir).ok();
    }
}
