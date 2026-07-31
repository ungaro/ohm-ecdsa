//! M3b persistence (SPEC §8.6, §10.2, §13.1, §A.4): a durable
//! presignature store, an accepted-message transcript archive, and
//! blame-token files with an offline auditor.
//!
//! Everything on disk uses the core's canonical [`Encode`]/[`Decode`]
//! wire format (no serde, std only). Three artifacts:
//!
//! * [`DiskPresigStore`] — the §8.6 single-use presignature store, file
//!   backed: one directory per node per long-term key, one file per
//!   record. Durability model (the fsync points):
//!   - `insert` writes `<id>.tmp`, fsyncs the FILE, renames to
//!     `<id>.presig`, then fsyncs the DIRECTORY. A crash before the
//!     rename leaves a `.tmp` file that `open` deletes — the insert was
//!     never acknowledged, so dropping it is safe.
//!   - `consume` reads and decodes the record, renames
//!     `<id>.presig` → `<id>.consumed`, fsyncs the DIRECTORY, and only
//!     THEN returns the record. The tombstone is durable before the
//!     caller can use the nonce, so a killed-and-restarted node can
//!     never hand the same presignature out twice (§8.6(1) atomic
//!     consume across a crash). A crash between the rename and the
//!     return loses the record — safe direction (a lost presignature,
//!     never a reused one).
//!   - `open` replays the directory: `.presig` files are live,
//!     `.consumed` files stay consumed, `.expired` files are expiry
//!     tombstones (H5 pool TTL — the id stays burned, never re-issuable),
//!     stray `.tmp` files are deleted. A `key.bin` file (canonical bytes
//!     of `X`) written and fsync'd on first open binds the directory to
//!     one long-term key (§8.6(4)); reopening under a different key is
//!     rejected.
//!   - H5: records are key-equivalent (§8.6(2)), so every `.presig`
//!     file is SEALED — canonical bytes inside a ChaCha20-Poly1305
//!     envelope under the node's storage key ([`crate::seal`]), written
//!     `0600`. `open` rejects a legacy cleartext record and any record
//!     this storage key cannot authenticate (fail closed).
//!   - H5 pool TTL (§8.6(3)): the sealed payload is versioned — v2
//!     prepends a version byte and a created-at timestamp (unix
//!     seconds). A legacy SEALED v1 record (no version byte) is still
//!     accepted, with the created-at taken from the file mtime (records
//!     are immutable after the atomic rename, so mtime ≈ insert time);
//!     an unreadable mtime stamps 0, expiring FIRST under any TTL — the
//!     safe direction. Legacy CLEARTEXT stays rejected. [`DiskPresigStore::expire`]
//!     erases an aged record: the empty `<id>.expired` tombstone is
//!     fsync'd FIRST (the id is durably burned before the record leaves
//!     the filesystem — the same discipline as the consume tombstone),
//!     then the sealed file is removed; the id can never be re-issued.
//!
//!   Limits, honestly: this survives process kill and — on a
//!   cooperating filesystem/OS — machine crash at exactly the fsync
//!   points above. At-rest confidentiality reduces to the storage key
//!   (wire it to a KMS/HSM in real deployments — [`crate::seal`] is the
//!   interface, not a KMS); it is not HSM-backed share storage, it does
//!   no wear leveling, and it does not defend against a malicious host
//!   rolling back the directory. Localhost demo and test scaffolding
//!   only.
//! * [`Archive`] — the §4.7/§10.2 accepted-message-set transcript: every
//!   signed envelope a driver ACCEPTS is appended (once) to
//!   `transcript.log` as `u32 BE length ‖ canonical SignedEnvelope
//!   bytes`, fsync'd per entry. Append-only, at-least-once across a
//!   restart (the dedup set is in memory).
//! * [`BlameEvidence`] / [`audit_token`] — the §10.2/§A.4 evidence flow:
//!   on an abort with identifiable blame the drivers archive a token
//!   file where cryptographic evidence exists (F2 dealt-share faults and
//!   F6 sign-share faults); other fault classes are logged to
//!   `aborts.log` with `token: none` (documented below at
//!   [`BlameEvidence`]). [`audit_token`] re-verifies a token OFFLINE —
//!   the envelope signature under the blamed party's transport key plus
//!   the recomputed commitment check — reusing the core's
//!   `BlameToken::verify` where the shape fits (the `Core` variant).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use k256::ecdsa::VerifyingKey;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use ohm_ecdsa::presign::Presignature;
use ohm_ecdsa::transport::{BlameToken, Decode, Encode, SignedEnvelope};
use ohm_ecdsa::vss::FeldmanCommitment;
use ohm_ecdsa::{Error, IdentifiableAbort, PartyId, Phase};

use crate::party::NodePayload;
use crate::seal::{SealError, StorageKey};

/// Persistence-layer failures: I/O errors stay `io::Error`s; protocol-
/// semantic failures (duplicate id, unknown/consumed id, key mismatch)
/// carry the core's [`Error`] — same variants and messages as the
/// in-memory `PresigStore` (SPEC §8.6); at-rest integrity failures (H5:
/// legacy cleartext, wrong storage key, tampered record) carry
/// [`SealError`] and ALWAYS fail closed.
#[derive(Debug)]
pub enum PersistError {
    /// Filesystem failure (the operation's fsync point is documented
    /// with each method).
    Io(io::Error),
    /// Protocol-semantics failure mirroring the core store.
    Protocol(Error),
    /// H5 at-rest integrity failure ([`SealError`] — fail closed).
    Seal(SealError),
}

impl core::fmt::Display for PersistError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "persistence I/O: {e}"),
            Self::Protocol(e) => write!(f, "{e}"),
            Self::Seal(e) => write!(f, "at-rest integrity: {e}"),
        }
    }
}

impl std::error::Error for PersistError {}

impl From<io::Error> for PersistError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<Error> for PersistError {
    fn from(e: Error) -> Self {
        Self::Protocol(e)
    }
}

impl From<SealError> for PersistError {
    fn from(e: SealError) -> Self {
        Self::Seal(e)
    }
}

// --- canonical encoding helpers (the core's Encode is a foreign trait
// for Presignature/IdentifiableAbort, so free functions, as in seed.rs) --

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn take_u64(b: &[u8]) -> Option<(u64, usize)> {
    let a: [u8; 8] = b.get(..8)?.try_into().ok()?;
    Some((u64::from_be_bytes(a), 8))
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u64(out, b.len() as u64);
    out.extend_from_slice(b);
}

fn take_bytes(b: &[u8]) -> Option<(Vec<u8>, usize)> {
    let (n, used) = take_u64(b)?;
    let n = usize::try_from(n).ok()?;
    let end = used.checked_add(n)?;
    Some((b.get(used..end)?.to_vec(), end))
}

fn put_presig(out: &mut Vec<u8>, p: &Presignature) {
    put_u64(out, p.id);
    put_u64(out, p.index as u64);
    p.r.encode(out);
    ProjectivePoint::from(p.big_r).encode(out);
    p.u_share.encode(out);
    p.z_share.encode(out);
    p.u_com.encode(out);
    p.z_com.encode(out);
}

/// Store-record payload version 2 (H5 pool TTL, §8.6(3)): a version byte
/// plus the created-at timestamp (unix seconds) prepended to the v1
/// fields. The version byte rides INSIDE the sealed payload; the outer
/// AEAD envelope format is unchanged.
const RECORD_V2: u8 = 2;

fn put_record(out: &mut Vec<u8>, p: &Presignature, created_at: u64) {
    out.push(RECORD_V2);
    put_u64(out, created_at);
    put_presig(out, p);
}

/// Decode a store record, exactly (no trailing bytes): v2 (`RECORD_V2`
/// byte + created-at + v1 fields) yields `Some(created_at)`; a legacy
/// SEALED v1 payload (no version byte) yields `None` (the caller falls
/// back to the file mtime). A payload that starts with the v2 byte but
/// does not parse as v2 exactly is CORRUPT, not a v1 record (a v1
/// payload's first byte is the top byte of the u64 id — `2` there would
/// mean an id ≥ 2^57, which the id allocation never produces).
fn take_record(b: &[u8]) -> Option<(Presignature, Option<u64>)> {
    if b.first() == Some(&RECORD_V2) {
        let (created_at, u) = take_u64(b.get(1..)?)?;
        let (p, used) = take_presig(b.get(1 + u..)?)?;
        return (1 + u + used == b.len()).then_some((p, Some(created_at)));
    }
    let (p, used) = take_presig(b)?;
    (used == b.len()).then_some((p, None))
}

fn take_presig(b: &[u8]) -> Option<(Presignature, usize)> {
    let (id, mut used) = take_u64(b)?;
    let (index, u) = take_u64(b.get(used..)?)?;
    used += u;
    let (r, u) = Scalar::decode(b.get(used..)?)?;
    used += u;
    let (big_r, u) = ProjectivePoint::decode(b.get(used..)?)?;
    used += u;
    let (u_share, u) = Scalar::decode(b.get(used..)?)?;
    used += u;
    let (z_share, u) = Scalar::decode(b.get(used..)?)?;
    used += u;
    let (u_com, u) = FeldmanCommitment::decode(b.get(used..)?)?;
    used += u;
    let (z_com, u) = FeldmanCommitment::decode(b.get(used..)?)?;
    used += u;
    Some((
        Presignature {
            id,
            index: usize::try_from(index).ok()?,
            r,
            big_r: big_r.to_affine(),
            u_share,
            z_share,
            u_com,
            z_com,
        },
        used,
    ))
}

fn phase_code(p: Phase) -> u8 {
    match p {
        Phase::KeyGen => 1,
        Phase::Triples => 2,
        Phase::Presign => 3,
        Phase::Sign => 4,
        Phase::Refresh => 5,
    }
}

fn phase_decode(c: u8) -> Option<Phase> {
    match c {
        1 => Some(Phase::KeyGen),
        2 => Some(Phase::Triples),
        3 => Some(Phase::Presign),
        4 => Some(Phase::Sign),
        5 => Some(Phase::Refresh),
        _ => None,
    }
}

fn put_abort(out: &mut Vec<u8>, a: &IdentifiableAbort) {
    out.push(phase_code(a.phase));
    put_u64(out, a.blamed.len() as u64);
    for id in &a.blamed {
        put_u64(out, *id as u64);
    }
    put_bytes(out, a.detail.as_bytes());
}

fn take_abort(b: &[u8]) -> Option<(IdentifiableAbort, usize)> {
    let phase = phase_decode(*b.first()?)?;
    let mut used = 1;
    let (n, u) = take_u64(b.get(used..)?)?;
    used += u;
    let mut blamed = Vec::new();
    for _ in 0..n {
        let (id, u) = take_u64(b.get(used..)?)?;
        used += u;
        blamed.push(usize::try_from(id).ok()?);
    }
    let (detail, u) = take_bytes(b.get(used..)?)?;
    used += u;
    Some((
        IdentifiableAbort {
            phase,
            blamed,
            detail: String::from_utf8(detail).ok()?,
        },
        used,
    ))
}

fn put_core_token(out: &mut Vec<u8>, t: &BlameToken) {
    put_abort(out, &t.abort);
    t.envelope.encode(out);
    t.com.encode(out);
}

fn take_core_token(b: &[u8]) -> Option<(BlameToken, usize)> {
    let (abort, mut used) = take_abort(b)?;
    let (envelope, u) = SignedEnvelope::decode(b.get(used..)?)?;
    used += u;
    let (com, u) = FeldmanCommitment::decode(b.get(used..)?)?;
    used += u;
    Some((
        BlameToken {
            abort,
            envelope,
            com,
        },
        used,
    ))
}

/// fsync the directory itself so a rename/create inside it is durable.
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Write `bytes` to `dir/<name>` atomically: write to a temp file,
/// fsync the file, rename, fsync the directory. A crash before the
/// rename leaves only the temp file. `secret` files are written `0600`
/// (H5 — enforced even if the temp file pre-existed looser).
fn write_atomic(
    dir: &Path,
    tmp_name: &str,
    name: &str,
    bytes: &[u8],
    secret: bool,
) -> io::Result<()> {
    let tmp = dir.join(tmp_name);
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        if secret {
            opts.mode(0o600);
        }
        let f = opts.open(&tmp)?;
        if secret {
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        }
        f
    };
    #[cfg(not(unix))]
    let mut f = {
        let _ = secret;
        File::create(&tmp)?
    };
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::rename(&tmp, dir.join(name))?;
    sync_dir(dir)
}

// --- the durable presignature store (SPEC §8.6) -------------------------

/// The H5 seal purpose for one store record (binds the AEAD to the
/// artifact AND the record id — a renamed file fails authentication).
fn record_purpose(id: u64) -> Vec<u8> {
    let mut p = b"presig-record".to_vec();
    p.extend_from_slice(&id.to_be_bytes());
    p
}

/// The current unix time in seconds (the default created-at stamp).
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// File-backed single-use presignature store: one directory per node
/// per long-term key, one file per record. Records are KEY-EQUIVALENT
/// (§8.6(2)), so every file on disk is H5-SEALED — the canonical bytes
/// inside a ChaCha20-Poly1305 envelope under the node's storage key
/// ([`crate::seal`]), written `0600`; a legacy cleartext record is
/// rejected at `open` (fail closed, no silent downgrade). The
/// durability/crash-safety model is documented in the module docs —
/// the short version: a consumed id stays consumed across a
/// kill/restart, because the tombstone rename is fsync'd BEFORE the
/// record is handed to the caller.
pub struct DiskPresigStore {
    dir: PathBuf,
    public_key: AffinePoint,
    /// H5: this node's at-rest AEAD key (its own locked copy).
    storage_key: StorageKey,
    live: BTreeSet<u64>,
    consumed: BTreeSet<u64>,
    /// H5 pool TTL (§8.6(3)): ids expired via [`Self::expire`] — burned
    /// forever (an expiry tombstone on disk), never re-issuable.
    expired: BTreeSet<u64>,
    /// H5 pool TTL: created-at (unix seconds) per LIVE record.
    created: BTreeMap<u64, u64>,
}

impl std::fmt::Debug for DiskPresigStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiskPresigStore")
            .field("dir", &self.dir)
            .field("public_key", &self.public_key)
            .field("live", &self.live)
            .field("consumed", &self.consumed)
            .finish_non_exhaustive()
    }
}

impl DiskPresigStore {
    /// Open (or create) the store at `dir`, bound to `public_key` (the
    /// DKG output `X`, §8.6(4)) and sealed under `storage_key` (H5).
    /// Replays the directory: live records, consumed tombstones, stray
    /// `.tmp` files (crash mid-insert — deleted, the insert was never
    /// acknowledged). Reopening under a different key is rejected, and
    /// so is any record that is not H5-sealed (a legacy cleartext file —
    /// fail closed) or fails authentication under THIS storage key
    /// (wrong key or tampered).
    pub fn open(
        dir: &Path,
        public_key: &AffinePoint,
        storage_key: &StorageKey,
    ) -> Result<Self, PersistError> {
        fs::create_dir_all(dir)?;
        let key_bytes = {
            let mut b = Vec::new();
            ProjectivePoint::from(*public_key).encode(&mut b);
            b
        };
        let key_file = dir.join("key.bin");
        if key_file.exists() {
            if fs::read(&key_file)? != key_bytes {
                return Err(Error::PresigStore("store bound to a different key").into());
            }
        } else {
            write_atomic(dir, "key.tmp", "key.bin", &key_bytes, false)?;
        }
        let mut live = BTreeSet::new();
        let mut consumed = BTreeSet::new();
        let mut expired = BTreeSet::new();
        let mut created = BTreeMap::new();
        let mut entries = Vec::new();
        for entry in fs::read_dir(dir)? {
            let name = entry?.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some((id, kind)) = name.split_once('.') else {
                continue;
            };
            let Ok(id) = id.parse::<u64>() else { continue };
            entries.push((id, kind.to_string(), name.to_string()));
        }
        // Tombstones first: a crash mid-expire (tombstone durable, sealed
        // file not yet removed) leaves BOTH — the tombstone wins and the
        // stray record is deleted in the second pass (never served).
        for (id, kind, _) in &entries {
            match kind.as_str() {
                "consumed" => {
                    consumed.insert(*id);
                }
                "expired" => {
                    expired.insert(*id);
                }
                _ => {}
            }
        }
        for (id, kind, name) in &entries {
            match kind.as_str() {
                "presig" => {
                    if expired.contains(id) {
                        fs::remove_file(dir.join(name))?;
                        continue;
                    }
                    // H5: reject a legacy cleartext record at STARTUP
                    // (fail closed — the error names the file), and any
                    // record this storage key cannot authenticate.
                    let bytes = fs::read(dir.join(name))?;
                    if !StorageKey::is_sealed(&bytes) {
                        return Err(PersistError::Seal(SealError::LegacyCleartext));
                    }
                    let plain = storage_key
                        .open(&record_purpose(*id), &bytes)
                        .map_err(PersistError::Seal)?;
                    let (_, stamped) = take_record(&plain)
                        .ok_or(Error::PresigStore("corrupt presignature file"))?;
                    let created_at = match stamped {
                        Some(ts) => ts,
                        // Legacy v1 SEALED record (pre-TTL, no timestamp
                        // inside): fall back to the file mtime (records
                        // are immutable after the atomic rename, so
                        // mtime ≈ insert time); an unreadable mtime
                        // stamps 0 — expires FIRST under any TTL, the
                        // safe direction.
                        None => fs::metadata(dir.join(name))
                            .and_then(|m| m.modified())
                            .ok()
                            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    };
                    live.insert(*id);
                    created.insert(*id, created_at);
                }
                "tmp" => {
                    // Crash between write and rename: the insert was
                    // never acknowledged — drop the partial file.
                    fs::remove_file(dir.join(name))?;
                }
                _ => {}
            }
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            public_key: *public_key,
            storage_key: storage_key.clone(),
            live,
            consumed,
            expired,
            created,
        })
    }

    /// The long-term public key this store is bound to (§8.6(4)).
    pub fn public_key(&self) -> &AffinePoint {
        &self.public_key
    }

    /// Persist a presignature (the caller keeps the in-memory record —
    /// the file is the durable copy); rejects a duplicate id, including
    /// an id that was already CONSUMED or EXPIRED (nonce-reuse guard,
    /// §8.6(1)). The record is SEALED (H5, v2 payload stamped with the
    /// current time) and written `0600`. fsync points: file, then
    /// directory after the rename.
    pub fn insert(&mut self, presig: &Presignature) -> Result<(), PersistError> {
        self.insert_at(presig, unix_now())
    }

    /// [`Self::insert`] with an explicit created-at timestamp (unix
    /// seconds) — the H5 pool manager stamps records from its injectable
    /// clock so TTL expiry is deterministic in tests.
    pub fn insert_at(
        &mut self,
        presig: &Presignature,
        created_at: u64,
    ) -> Result<(), PersistError> {
        let id = presig.id;
        if self.live.contains(&id) || self.consumed.contains(&id) || self.expired.contains(&id) {
            return Err(Error::PresigStore("duplicate presignature id").into());
        }
        let mut bytes = Vec::new();
        put_record(&mut bytes, presig, created_at);
        let sealed = self.storage_key.seal(&record_purpose(id), &bytes);
        write_atomic(
            &self.dir,
            &format!("{id}.tmp"),
            &format!("{id}.presig"),
            &sealed,
            true,
        )?;
        self.live.insert(id);
        self.created.insert(id, created_at);
        Ok(())
    }

    /// Atomically consume the record for `id` — exactly once, across
    /// restarts (§8.6(1)): the tombstone rename is fsync'd BEFORE the
    /// record is returned, so a crash can lose the record but can never
    /// hand it out twice. Unknown or consumed ids mirror the core
    /// store's error; a record that fails H5 authentication (wrong
    /// storage key or tampered) fails closed.
    pub fn consume(&mut self, id: u64) -> Result<Presignature, PersistError> {
        if !self.live.contains(&id) {
            return Err(Error::PresigStore("unknown or consumed presignature id").into());
        }
        let sealed = fs::read(self.dir.join(format!("{id}.presig")))?;
        let bytes = self
            .storage_key
            .open(&record_purpose(id), &sealed)
            .map_err(PersistError::Seal)?;
        let (presig, _) =
            take_record(&bytes).ok_or(Error::PresigStore("corrupt presignature file"))?;
        fs::rename(
            self.dir.join(format!("{id}.presig")),
            self.dir.join(format!("{id}.consumed")),
        )?;
        sync_dir(&self.dir)?;
        self.live.remove(&id);
        self.created.remove(&id);
        self.consumed.insert(id);
        Ok(presig)
    }

    /// Number of stored (unconsumed) presignatures.
    pub fn len(&self) -> usize {
        self.live.len()
    }

    /// Whether the store holds no live presignatures.
    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }

    /// Whether `id` is present and unconsumed.
    pub fn contains(&self, id: u64) -> bool {
        self.live.contains(&id)
    }

    /// The created-at stamp (unix seconds) of a LIVE record (H5 pool
    /// TTL); `None` for unknown/consumed/expired ids.
    pub fn created_at(&self, id: u64) -> Option<u64> {
        self.created.get(&id).copied()
    }

    /// The smallest live id — the FIFO drain order for signing (oldest
    /// record first, the same order at every node).
    pub fn oldest_live_id(&self) -> Option<u64> {
        self.live.iter().next().copied()
    }

    /// The largest id this store has EVER seen (live, consumed, or
    /// expired) — the H5 pool manager restarts id allocation above it,
    /// so an id is never re-issued across a crash/restart.
    pub fn max_seen_id(&self) -> u64 {
        self.live
            .iter()
            .chain(&self.consumed)
            .chain(&self.expired)
            .max()
            .copied()
            .unwrap_or(0)
    }

    /// Live ids stamped at or before `threshold` (unix seconds) — the
    /// TTL expiry candidates (§8.6(3)): with `threshold = now − ttl`,
    /// exactly the records older than the TTL.
    pub fn expired_before(&self, threshold: u64) -> Vec<u64> {
        self.created
            .iter()
            .filter(|(_, ts)| **ts <= threshold)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Erase a live record (§8.6(3) secure erase on expiry): the empty
    /// `<id>.expired` tombstone is written and fsync'd FIRST — the id is
    /// durably burned before the record leaves the filesystem (the same
    /// discipline as the consume tombstone; a crash between the two
    /// steps is resolved in favor of the tombstone at `open`) — then the
    /// sealed file is removed and the directory fsync'd. The id is never
    /// re-issuable and the record is never served again; the caller's
    /// in-memory copy erases itself on drop (zeroize). `Ok(false)` when
    /// `id` is not live (unknown, consumed, or already expired). Note on
    /// "secure": at-rest confidentiality reduces to the AEAD key (the
    /// tombstone is empty, but filesystem block reuse is not guaranteed
    /// — no wear leveling, no rollback defense; see the module docs).
    pub fn expire(&mut self, id: u64) -> Result<bool, PersistError> {
        if !self.live.contains(&id) {
            return Ok(false);
        }
        write_atomic(
            &self.dir,
            &format!("{id}.tmp"),
            &format!("{id}.expired"),
            &[],
            false,
        )?;
        fs::remove_file(self.dir.join(format!("{id}.presig")))?;
        sync_dir(&self.dir)?;
        self.live.remove(&id);
        self.created.remove(&id);
        self.expired.insert(id);
        Ok(true)
    }
}

// --- blame-token evidence (SPEC §10.2, §A.4) -----------------------------

/// Archived blame evidence (SPEC §10.2, §A.4). The M2/M3a drivers write
/// a token file where a fault leaves cryptographic evidence on the
/// wire; fault classes without a token-shaped artifact (false
/// accusations — the evidence is the ABSENCE of a valid complaint;
/// bad DLEQ proofs, bad nonce points, bad opening shares — signed but
/// not tokenized here; bad re-shares — a `Reshare` envelope does not
/// fit the share-token shape) are logged to `aborts.log` with
/// `token: none`. Tokenized classes: F2 dealt shares, F6 sign shares,
/// F8 broadcast equivocation (§4.7 rule (3) — two conflicting
/// sender-signed envelopes of one slot).
#[derive(Clone, Debug)]
pub enum BlameEvidence {
    /// The core's [`BlameToken`] (M1 orchestrator path,
    /// `drive_dkg_signed`): audited by the core's `BlameToken::verify`.
    Core(Box<BlameToken>),
    /// F2 over the M2 wire: the blamed dealer's signed P2P dealt share
    /// (a [`NodePayload`] envelope, as it went over the mesh) plus the
    /// dealer's revealed Feldman commitment — the accuser's local
    /// evidence from the §6.1 complaint subprotocol.
    DealtShare {
        /// The abort the token substantiates (names the dealer).
        abort: IdentifiableAbort,
        /// The offending signed share envelope.
        envelope: SignedEnvelope<NodePayload>,
        /// The blamed dealer's revealed commitment vector.
        com: FeldmanCommitment,
    },
    /// F6: the blamed signer's signed `SignShare` broadcast plus the
    /// public data the failed check is recomputed from: the signed
    /// message, `r`, `A[u]`, `A[z]` (the check is
    /// `s_j·G == EvalCom(m·A[u] + r·A[z], j)`, SPEC §9).
    SignShare {
        /// The blame event (names the signer).
        abort: IdentifiableAbort,
        /// The offending signed sign-share envelope.
        envelope: SignedEnvelope<NodePayload>,
        /// The message that was signed.
        message: Vec<u8>,
        /// The presignature's public nonce `r`.
        r: Scalar,
        /// `A[u]`.
        u_com: FeldmanCommitment,
        /// `A[z]`.
        z_com: FeldmanCommitment,
    },
    /// F8 (§4.7 rule (3)): broadcast equivocation — two CONFLICTING
    /// values in the same broadcast slot, each in an envelope carrying
    /// the blamed sender's valid §10.2 signature. The pair is the
    /// public, offline-verifiable proof of equivocation.
    Equivocation {
        /// The blame event (names the equivocating sender).
        abort: IdentifiableAbort,
        /// The first conflicting signed broadcast envelope.
        first: SignedEnvelope<NodePayload>,
        /// The second conflicting signed broadcast envelope (same slot,
        /// different value).
        second: SignedEnvelope<NodePayload>,
    },
}

impl BlameEvidence {
    /// Short label for logs and the auditor output.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Core(_) => "core blame token (M1 drive_dkg_signed, F2)",
            Self::DealtShare { .. } => "dealt-share evidence (M2 wire, F2)",
            Self::SignShare { .. } => "sign-share evidence (M2 wire, F6)",
            Self::Equivocation { .. } => "broadcast-equivocation evidence (M2 wire, F8)",
        }
    }

    /// The abort this evidence substantiates.
    pub fn abort(&self) -> &IdentifiableAbort {
        match self {
            Self::Core(t) => &t.abort,
            Self::DealtShare { abort, .. }
            | Self::SignShare { abort, .. }
            | Self::Equivocation { abort, .. } => abort,
        }
    }

    /// Canonical encoding (variant tag ‖ fields).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Core(t) => {
                out.push(1);
                put_core_token(&mut out, t);
            }
            Self::DealtShare {
                abort,
                envelope,
                com,
            } => {
                out.push(2);
                put_abort(&mut out, abort);
                envelope.encode(&mut out);
                com.encode(&mut out);
            }
            Self::SignShare {
                abort,
                envelope,
                message,
                r,
                u_com,
                z_com,
            } => {
                out.push(3);
                put_abort(&mut out, abort);
                envelope.encode(&mut out);
                put_bytes(&mut out, message);
                r.encode(&mut out);
                u_com.encode(&mut out);
                z_com.encode(&mut out);
            }
            Self::Equivocation {
                abort,
                first,
                second,
            } => {
                out.push(4);
                put_abort(&mut out, abort);
                first.encode(&mut out);
                second.encode(&mut out);
            }
        }
        out
    }

    /// Inverse of [`Self::encode`]; rejects trailing bytes.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (ev, used) = Self::decode_prefix(bytes)?;
        (used == bytes.len()).then_some(ev)
    }

    fn decode_prefix(bytes: &[u8]) -> Option<(Self, usize)> {
        let tag = *bytes.first()?;
        let mut used = 1;
        match tag {
            1 => {
                let (t, u) = take_core_token(bytes.get(used..)?)?;
                used += u;
                Some((Self::Core(Box::new(t)), used))
            }
            2 => {
                let (abort, u) = take_abort(bytes.get(used..)?)?;
                used += u;
                let (envelope, u) = SignedEnvelope::decode(bytes.get(used..)?)?;
                used += u;
                let (com, u) = FeldmanCommitment::decode(bytes.get(used..)?)?;
                used += u;
                Some((
                    Self::DealtShare {
                        abort,
                        envelope,
                        com,
                    },
                    used,
                ))
            }
            3 => {
                let (abort, u) = take_abort(bytes.get(used..)?)?;
                used += u;
                let (envelope, u) = SignedEnvelope::decode(bytes.get(used..)?)?;
                used += u;
                let (message, u) = take_bytes(bytes.get(used..)?)?;
                used += u;
                let (r, u) = Scalar::decode(bytes.get(used..)?)?;
                used += u;
                let (u_com, u) = FeldmanCommitment::decode(bytes.get(used..)?)?;
                used += u;
                let (z_com, u) = FeldmanCommitment::decode(bytes.get(used..)?)?;
                used += u;
                Some((
                    Self::SignShare {
                        abort,
                        envelope,
                        message,
                        r,
                        u_com,
                        z_com,
                    },
                    used,
                ))
            }
            4 => {
                let (abort, u) = take_abort(bytes.get(used..)?)?;
                used += u;
                let (first, u) = SignedEnvelope::decode(bytes.get(used..)?)?;
                used += u;
                let (second, u) = SignedEnvelope::decode(bytes.get(used..)?)?;
                used += u;
                Some((
                    Self::Equivocation {
                        abort,
                        first,
                        second,
                    },
                    used,
                ))
            }
            _ => None,
        }
    }
}

/// Write a blame-token file into `dir` (canonical bytes, atomic
/// write-tmp-rename + fsync) and return its path.
pub fn write_token(dir: &Path, evidence: &BlameEvidence) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let abort = evidence.abort();
    let ids = abort
        .blamed
        .iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let name = format!("blame-{}-{ids}.tok", abort.phase);
    write_atomic(
        dir,
        &format!("{name}.tmp"),
        &name,
        &evidence.encode(),
        false,
    )?;
    Ok(dir.join(name))
}

/// The auditor's report: one line per check, plus the verdict.
#[derive(Debug)]
pub struct AuditReport {
    /// `(description, passed)` per check, in evaluation order.
    pub checks: Vec<(String, bool)>,
    /// What the token claims, for the verdict line.
    pub blamed: Vec<PartyId>,
    /// The claimed phase.
    pub phase: Phase,
}

impl AuditReport {
    /// The final verdict: every check passed.
    pub fn verdict(&self) -> bool {
        !self.checks.is_empty() && self.checks.iter().all(|(_, ok)| *ok)
    }
}

/// The §A.4 offline audit: decode a blame-token file and re-verify it
/// against the committee's PUBLIC transport keys — no secret material.
/// Every token is checked for (a) the envelope signature under the
/// blamed party's transport key, (b) the recomputed commitment check
/// really failing, and (c) blame/phase consistency. The `Core` variant
/// additionally cross-checks the core's `BlameToken::verify`.
pub fn audit_token(bytes: &[u8], party_keys: &[(PartyId, VerifyingKey)]) -> AuditReport {
    let fail = |what: &str| AuditReport {
        checks: vec![(what.to_string(), false)],
        blamed: Vec::new(),
        phase: Phase::KeyGen,
    };
    let Some(evidence) = BlameEvidence::decode(bytes) else {
        return fail("token file decodes (canonical wire format, no trailing bytes)");
    };
    let abort = evidence.abort().clone();
    let mut report = AuditReport {
        checks: Vec::new(),
        blamed: abort.blamed.clone(),
        phase: abort.phase,
    };
    let mut check = |what: String, ok: bool| report.checks.push((what, ok));

    // Shared facts: the blamed party's registered key, the envelope's
    // sender, and the signature check (a).
    let key_of = |from: PartyId| party_keys.iter().find(|(p, _)| *p == from).map(|(_, k)| k);
    match &evidence {
        BlameEvidence::Core(token) => {
            let env = &token.envelope;
            let from = env.envelope.from;
            let share_ok = matches!(
                &env.envelope.payload,
                ohm_ecdsa::transport::DkgMessage::Share(s) if s.from == from
            );
            check(
                format!("blame consistency: abort names exactly the sender {from} in its phase"),
                abort.blamed == [from] && abort.phase == env.envelope.phase && share_ok,
            );
            let sig_ok = key_of(from).is_some_and(|k| env.verify_signature(k));
            check(
                format!("envelope signature verifies under party {from}'s transport key"),
                sig_ok,
            );
            let dealt_fails = match &env.envelope.payload {
                ohm_ecdsa::transport::DkgMessage::Share(s) => {
                    !token.com.verify_share(s.to, &s.share)
                }
                _ => false,
            };
            check(
                "recomputed check really fails: dealt share does not match EvalCom(com, to)"
                    .to_string(),
                dealt_fails,
            );
            check(
                "core BlameToken::verify agrees (the core's auditor)".to_string(),
                token.verify(party_keys),
            );
        }
        BlameEvidence::DealtShare { envelope, com, .. } => {
            let from = envelope.envelope.from;
            let share = match &envelope.envelope.payload {
                NodePayload::Dkg(ohm_ecdsa::transport::DkgMessage::Share(s)) if s.from == from => {
                    Some(s.clone())
                }
                _ => None,
            };
            check(
                format!("blame consistency: abort names exactly the sender {from} in its phase"),
                abort.blamed == [from] && abort.phase == envelope.envelope.phase && share.is_some(),
            );
            let sig_ok = key_of(from).is_some_and(|k| envelope.verify_signature(k));
            check(
                format!("envelope signature verifies under party {from}'s transport key"),
                sig_ok,
            );
            let dealt_fails = share.is_some_and(|s| !com.verify_share(s.to, &s.share));
            check(
                "recomputed check really fails: dealt share does not match EvalCom(com, to)"
                    .to_string(),
                dealt_fails,
            );
        }
        BlameEvidence::Equivocation { first, second, .. } => {
            let from = first.envelope.from;
            let same_slot = first.envelope.to.is_none()
                && second.envelope.to.is_none()
                && second.envelope.from == from
                && second.envelope.sid == first.envelope.sid
                && second.envelope.phase == first.envelope.phase
                && second.envelope.round == first.envelope.round;
            check(
                format!(
                    "blame consistency: abort names exactly the sender {from} in its phase, \
                         both envelopes are broadcasts of the same slot"
                ),
                abort.blamed == [from] && abort.phase == first.envelope.phase && same_slot,
            );
            let sigs_ok = key_of(from)
                .is_some_and(|k| first.verify_signature(k) && second.verify_signature(k));
            check(
                format!("both envelope signatures verify under party {from}'s transport key"),
                sigs_ok,
            );
            let (mut fa, mut fb) = (Vec::new(), Vec::new());
            first.encode(&mut fa);
            second.encode(&mut fb);
            check(
                "the two signed values really conflict (distinct payloads in one slot)".to_string(),
                fa != fb,
            );
        }
        BlameEvidence::SignShare {
            envelope,
            message,
            r,
            u_com,
            z_com,
            ..
        } => {
            let from = envelope.envelope.from;
            let s = match &envelope.envelope.payload {
                NodePayload::SignShare { s, .. } => Some(*s),
                _ => None,
            };
            check(
                format!("blame consistency: abort names exactly the sender {from} in phase sign"),
                abort.blamed == [from]
                    && abort.phase == Phase::Sign
                    && envelope.envelope.phase == Phase::Sign
                    && s.is_some(),
            );
            let sig_ok = key_of(from).is_some_and(|k| envelope.verify_signature(k));
            check(
                format!("envelope signature verifies under party {from}'s transport key"),
                sig_ok,
            );
            let share_fails = s.is_some_and(|s| {
                let m = ohm_ecdsa::sim::message_scalar(message);
                let s_com = u_com.scale(&m).add(&z_com.scale(r));
                !s_com.verify_share(from, &s)
            });
            check(
                "recomputed check really fails: s_j·G != EvalCom(m·A[u] + r·A[z], j)".to_string(),
                share_fails,
            );
        }
    }
    report
}

// --- the transcript + abort archive (SPEC §4.7, §10.2) -------------------

/// A transcript dedup slot: `(sid, phase, round, from, to)` (`to` is
/// `None` for broadcasts).
type TranscriptSlot = (Vec<u8>, Phase, u8, PartyId, Option<PartyId>);

/// The per-node evidence archive: an append-only transcript of every
/// ACCEPTED signed envelope (§4.7 accepted message sets, fsync'd per
/// entry), plus blame-token files and an `aborts.log` naming the token
/// file (or `token: none`) per identifiable abort.
pub struct Archive {
    dir: PathBuf,
    transcript: File,
    logged: BTreeSet<TranscriptSlot>,
    aborts: File,
}

impl Archive {
    /// Open (or create) the archive at `dir`. An existing transcript is
    /// appended to (the dedup set is in memory: at-least-once across a
    /// restart, documented in the module docs).
    pub fn create(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let transcript = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("transcript.log"))?;
        let aborts = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("aborts.log"))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            transcript,
            logged: BTreeSet::new(),
            aborts,
        })
    }

    /// Append one accepted signed envelope to the transcript (once per
    /// `(sid, phase, round, from, to)` slot): `u32 BE length ‖ canonical
    /// SignedEnvelope bytes`, fsync'd per entry — a crash loses at most
    /// the in-flight entry.
    pub fn log_accepted(&mut self, se: &SignedEnvelope<NodePayload>) -> io::Result<()> {
        let env = &se.envelope;
        let slot = (env.sid.clone(), env.phase, env.round, env.from, env.to);
        if !self.logged.insert(slot) {
            return Ok(());
        }
        let mut bytes = Vec::new();
        se.encode(&mut bytes);
        let len = u32::try_from(bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "envelope too large"))?;
        self.transcript.write_all(&len.to_be_bytes())?;
        self.transcript.write_all(&bytes)?;
        self.transcript.sync_all()
    }

    /// Record an identifiable abort: one line in `aborts.log` naming the
    /// token file when evidence exists (`token: <file>`) or
    /// `token: none` when it does not (see [`BlameEvidence`]).
    pub fn record_abort(
        &mut self,
        abort: &IdentifiableAbort,
        evidence: Option<&BlameEvidence>,
    ) -> io::Result<()> {
        let ids = abort
            .blamed
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let token = match evidence {
            Some(ev) => {
                let path = write_token(&self.dir, ev)?;
                path.file_name()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or_default()
            }
            None => "none".to_string(),
        };
        writeln!(
            self.aborts,
            "{} blamed {ids} token: {token} ({})",
            abort.phase, abort.detail
        )?;
        self.aborts.sync_all()
    }
}

/// Read back a transcript log (tests and tooling): every entry decoded
/// as a canonical signed envelope. Truncated tails (a crash mid-append)
/// surface as an error.
pub fn read_transcript(path: &Path) -> io::Result<Vec<SignedEnvelope<NodePayload>>> {
    let mut buf = Vec::new();
    File::open(path)?.read_to_end(&mut buf)?;
    let mut out = Vec::new();
    let mut rest = &buf[..];
    while !rest.is_empty() {
        let hdr: [u8; 4] = rest
            .get(..4)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated entry"))?
            .try_into()
            .expect("4 bytes");
        let len = u32::from_be_bytes(hdr) as usize;
        let body = rest
            .get(4..4 + len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated entry"))?;
        let (se, _) = SignedEnvelope::<NodePayload>::decode(body)
            .filter(|(_, used)| *used == body.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed entry"))?;
        out.push(se);
        rest = &rest[4 + len..];
    }
    Ok(out)
}
