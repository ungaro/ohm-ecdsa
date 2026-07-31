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
//!   - A4 ROLLBACK DETECTION (§13.3): every mutation (insert, consume,
//!     expire) is also appended to `journal.log` — one canonical-encoded
//!     entry `(seq, op, id, prev_hash, payload_hash, entry_hash)` per
//!     mutation, fsync'd per append, hash-chained (`entry_hash =
//!     H(tag ‖ seq ‖ op ‖ id ‖ prev_hash ‖ payload_hash)`). `open`
//!     replays the journal and verifies it against the directory (chain
//!     links, op transitions, every journaled artifact present with
//!     matching bytes; crash windows — artifact fsync'd, journal append
//!     not — heal in the safe direction), then cross-checks the
//!     transcript archive (`<store>/../archive/transcript.log`): a
//!     presignature id evidenced as SPENT by an accepted Sign-phase
//!     envelope must not be LIVE. Any break fails closed with
//!     [`PersistError::Integrity`] naming the divergence point — a store
//!     backup restored over an intact archive is REFUSED as a detected
//!     rollback. `--allow-unverified-store` (dev only) downgrades every
//!     refusal to a loud warning. The limitation is honest: the journal
//!     and the transcript live in the SAME rollback-able directory, so a
//!     WHOLE-DIRECTORY restore to an older self-consistent state remains
//!     undetectable (a startup warning says so); true prevention needs
//!     state outside the directory (HSM monotonic counter, peer
//!     attestation — SPEC §13.3; ship `transcript.log` off-box for real
//!     independence). A pre-A4 store (records, no journal) is adopted
//!     into a fresh journal with a loud warning.
//!
//!   Limits, honestly: this survives process kill and — on a
//!   cooperating filesystem/OS — machine crash at exactly the fsync
//!   points above, and it DETECTS (and refuses) the common rollback
//!   shape via the journal + transcript cross-check — it does not
//!   PREVENT rollback: a whole-directory restore is undetectable without
//!   state outside the directory (SPEC §13.3). At-rest confidentiality
//!   reduces to the storage key
//!   (wire it to a KMS/HSM in real deployments — [`crate::seal`] is the
//!   interface, not a KMS); it is not HSM-backed share storage, it does
//!   no wear leveling, and it does not defend against a malicious host
//!   with write access beyond what the checks above catch. Localhost
//!   demo and test scaffolding only.
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
use k256::sha2::{Digest, Sha256};
use k256::{AffinePoint, ProjectivePoint, Scalar};
use ohm_ecdsa::presign::{KeyShare, Presignature};
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
    /// A4 store-integrity failure (journal chain, journal-vs-directory
    /// divergence, or the transcript cross-check — ROLLBACK DETECTED):
    /// ALWAYS fails closed, the message names the divergence point.
    Integrity(String),
}

impl core::fmt::Display for PersistError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "persistence I/O: {e}"),
            Self::Protocol(e) => write!(f, "{e}"),
            Self::Seal(e) => write!(f, "at-rest integrity: {e}"),
            Self::Integrity(m) => write!(f, "store integrity: {m}"),
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

// --- A4: the chained store journal (rollback detection, SPEC §8.6/§13.3) -----

/// The journal file name within the store directory.
const JOURNAL_FILE: &str = "journal.log";

/// Domain-separation tag for the journal entry hash chain.
const JOURNAL_TAG: &[u8] = b"OHM-ECDSA-node/v0.1/store-journal";

/// Domain-separation tag for per-entry payload digests (the hash of the
/// on-disk artifact the journal entry accounts for).
const PAYLOAD_TAG: &[u8] = b"OHM-ECDSA-node/v0.1/store-payload";

/// Journal op codes.
const OP_INSERT: u8 = 1;
const OP_CONSUME: u8 = 2;
const OP_EXPIRE: u8 = 3;
/// Burn a NEVER-INSERTED id (a failed production session — A7): the
/// same on-disk end state as [`OP_EXPIRE`] (an empty `<id>.expired`
/// tombstone), but valid only for an id with no prior journal entry.
const OP_BURN: u8 = 4;

const ZERO_HASH: [u8; 32] = [0u8; 32];

/// The digest of the on-disk artifact a journal entry accounts for
/// (the sealed record/tombstone bytes; the empty tombstone for an
/// expire).
fn payload_digest(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PAYLOAD_TAG);
    h.update(bytes);
    h.finalize().into()
}

/// `entry_hash = H(JOURNAL_TAG ‖ seq ‖ op ‖ id ‖ prev_hash ‖
/// payload_hash)` — one link of the journal hash chain.
fn entry_digest(seq: u64, op: u8, id: u64, prev: &[u8; 32], payload: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(JOURNAL_TAG);
    h.update(seq.to_be_bytes());
    h.update([op]);
    h.update(id.to_be_bytes());
    h.update(prev);
    h.update(payload);
    h.finalize().into()
}

/// One journal entry: every store mutation (insert / consume / expire)
/// is logged as `(seq, op, id, prev_hash, payload_hash, entry_hash)`,
/// canonical-encoded and framed as `u32 BE length ‖ entry bytes` (the
/// transcript's framing), fsync'd per append. `entry_hash` chains each
/// entry to its predecessor, so rewriting or reordering HISTORY breaks
/// the chain at replay.
#[derive(Clone, Copy, Debug)]
struct JournalEntry {
    seq: u64,
    op: u8,
    id: u64,
    prev: [u8; 32],
    payload: [u8; 32],
    hash: [u8; 32],
}

impl JournalEntry {
    fn new(seq: u64, op: u8, id: u64, prev: [u8; 32], payload: [u8; 32]) -> Self {
        let hash = entry_digest(seq, op, id, &prev, &payload);
        Self {
            seq,
            op,
            id,
            prev,
            payload,
            hash,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 1 + 8 + 32 * 3);
        put_u64(&mut out, self.seq);
        out.push(self.op);
        put_u64(&mut out, self.id);
        out.extend_from_slice(&self.prev);
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.hash);
        out
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let (seq, mut used) = take_u64(b)?;
        let op = *b.get(used)?;
        used += 1;
        let (id, u) = take_u64(b.get(used..)?)?;
        used += u;
        let prev: [u8; 32] = b.get(used..used + 32)?.try_into().ok()?;
        used += 32;
        let payload: [u8; 32] = b.get(used..used + 32)?.try_into().ok()?;
        used += 32;
        let hash: [u8; 32] = b.get(used..used + 32)?.try_into().ok()?;
        used += 32;
        (used == b.len()).then_some(Self {
            seq,
            op,
            id,
            prev,
            payload,
            hash,
        })
    }
}

/// Replay the journal bytes: strict framing (`u32 BE length ‖ entry`),
/// sequential seqs from 1, `prev_hash` links, recomputed entry hashes,
/// and op-transition validity (an id is inserted once; consume/expire
/// need a live insert). Returns the verified entries; any break is an
/// error naming the divergence point.
fn journal_replay(bytes: &[u8]) -> Result<Vec<JournalEntry>, String> {
    let mut entries = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let n = entries.len() as u64 + 1;
        let hdr: [u8; 4] = rest
            .get(..4)
            .ok_or_else(|| format!("journal truncated before entry {n}"))?
            .try_into()
            .expect("4 bytes");
        let len = u32::from_be_bytes(hdr) as usize;
        let body = rest
            .get(4..4 + len)
            .ok_or_else(|| format!("journal truncated inside entry {n}"))?;
        let e = JournalEntry::decode(body)
            .ok_or_else(|| format!("journal entry {n} is not canonical"))?;
        if e.seq != n {
            return Err(format!(
                "journal entry seq {} out of order (expected {n})",
                e.seq
            ));
        }
        let prev = entries
            .last()
            .map(|l: &JournalEntry| l.hash)
            .unwrap_or(ZERO_HASH);
        if e.prev != prev {
            return Err(format!(
                "journal entry {n} breaks the hash chain (prev_hash)"
            ));
        }
        if e.hash != entry_digest(e.seq, e.op, e.id, &e.prev, &e.payload) {
            return Err(format!("journal entry {n} has a wrong entry_hash"));
        }
        let known = entries.iter().any(|l: &JournalEntry| l.id == e.id);
        let live = entries.iter().rev().find(|l| l.id == e.id).map(|l| l.op) == Some(OP_INSERT);
        match e.op {
            OP_INSERT if !known => {}
            OP_CONSUME | OP_EXPIRE if live => {}
            OP_BURN if !known => {}
            OP_INSERT => return Err(format!("journal entry {n} re-inserts id {}", e.id)),
            OP_CONSUME | OP_EXPIRE => {
                return Err(format!("journal entry {n} mutates non-live id {}", e.id))
            }
            OP_BURN => return Err(format!("journal entry {n} re-burns id {}", e.id)),
            op => return Err(format!("journal entry {n} has unknown op {op}")),
        }
        entries.push(e);
        rest = &rest[4 + len..];
    }
    Ok(entries)
}

/// The journal writer: appends canonical-framed entries, fsync'd per
/// entry (a crash loses at most the in-flight entry — resolved in the
/// safe direction at `open`, see the reconciliation rules).
struct Journal {
    file: File,
    next_seq: u64,
    tip: [u8; 32],
}

impl Journal {
    fn append(&mut self, op: u8, id: u64, payload: [u8; 32]) -> io::Result<()> {
        let e = JournalEntry::new(self.next_seq, op, id, self.tip, payload);
        let body = e.encode();
        let len = u32::try_from(body.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "journal entry too large"))?;
        self.file.write_all(&len.to_be_bytes())?;
        self.file.write_all(&body)?;
        self.file.sync_all()?;
        self.next_seq += 1;
        self.tip = e.hash;
        Ok(())
    }
}

/// The on-disk final state of one id, as the directory scan sees it
/// (tombstones win over a live record — the safe direction).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiskState {
    /// `<id>.presig` present (payload = the sealed file digest).
    Live([u8; 32]),
    /// `<id>.consumed` present (payload = the sealed file digest — the
    /// same bytes as the record had, the consume is a rename).
    Consumed([u8; 32]),
    /// `<id>.expired` present (empty tombstone).
    Expired,
}

/// The journal's final state of one id after replay.
#[derive(Clone, Copy, Debug)]
enum JournalState {
    Live([u8; 32]),
    Consumed([u8; 32]),
    Expired,
}

/// A healing journal append for a crash window: `(op, id, payload)`.
type HealOp = (u8, u64, [u8; 32]);

/// The outcome of reconciling the journal's final state against the
/// directory: the healing appends needed for crash windows (a mutation
/// whose artifact was fsync'd but whose journal append was not — the
/// mutation never returned, so the artifact's safe-direction state is
/// adopted and journaled now), plus warnings for safe-direction
/// divergences (unaccounted tombstones honored, unacknowledged inserts
/// dropped). A hard divergence (missing/mismatched artifact, a live
/// record for an id the journal shows consumed — the rollback shape) is
/// `Err` naming the divergence point.
fn reconcile_journal(
    journaled: &BTreeMap<u64, JournalState>,
    disk: &BTreeMap<u64, DiskState>,
) -> Result<(Vec<HealOp>, Vec<String>), String> {
    let mut heals = Vec::new();
    let mut warnings = Vec::new();
    for (id, js) in journaled {
        match (js, disk.get(id)) {
            (JournalState::Live(ph), Some(DiskState::Live(dh))) if ph == dh => {}
            (JournalState::Live(ph), Some(DiskState::Consumed(dh))) if ph == dh => {
                // Crash mid-consume (tombstone fsync'd, journal append
                // not): the record was never handed out — adopt the
                // consumed state (safe direction) and journal it now.
                heals.push((OP_CONSUME, *id, *dh));
            }
            (JournalState::Live(_), Some(DiskState::Expired)) => {
                // Crash mid-expire, same discipline.
                heals.push((OP_EXPIRE, *id, payload_digest(&[])));
            }
            (JournalState::Live(_), found) => {
                return Err(format!(
                    "record <{id}.presig> is missing or does not match the journal \
                     (on disk: {})",
                    disk_label(found)
                ));
            }
            (JournalState::Consumed(ph), Some(DiskState::Consumed(dh))) if ph == dh => {}
            (JournalState::Consumed(_), found) => {
                // A LIVE record here is exactly the rollback shape: the
                // consume tombstone was undone.
                return Err(format!(
                    "the tombstone for consumed id {id} is missing or does not match the \
                     journal (on disk: {})",
                    disk_label(found)
                ));
            }
            (JournalState::Expired, Some(DiskState::Expired)) => {}
            (JournalState::Expired, found) => {
                return Err(format!(
                    "the expiry tombstone for id {id} is missing (on disk: {})",
                    disk_label(found)
                ));
            }
        }
    }
    for (id, ds) in disk {
        if journaled.contains_key(id) {
            continue;
        }
        match ds {
            // Crash mid-insert (record fsync'd, journal append not): the
            // insert was never acknowledged — drop the record, like a
            // stray `.tmp` (never serve an unaccounted record).
            DiskState::Live(_) => warnings.push(format!(
                "dropping <{id}.presig>: no journal entry accounts for it \
                 (crash mid-insert or manual copy — never acknowledged)"
            )),
            // An unaccounted tombstone only BURNS an id — safe direction,
            // honor it (and it stays honored via the in-memory state).
            DiskState::Consumed(_) => warnings.push(format!(
                "honoring unaccounted consume tombstone <{id}.consumed> (id burned)"
            )),
            DiskState::Expired => warnings.push(format!(
                "honoring unaccounted expiry tombstone <{id}.expired> (id burned)"
            )),
        }
    }
    Ok((heals, warnings))
}

fn disk_label(found: Option<&DiskState>) -> String {
    match found {
        None => "absent".to_string(),
        Some(DiskState::Live(_)) => "live record".to_string(),
        Some(DiskState::Consumed(_)) => "consume tombstone".to_string(),
        Some(DiskState::Expired) => "expiry tombstone".to_string(),
    }
}

/// The default transcript location for the A4 cross-check: the store
/// lives at `<data-dir>/store`, the archive at `<data-dir>/archive` (the
/// `--data-dir` layout). `None` when the store has no parent.
fn default_transcript(store_dir: &Path) -> Option<PathBuf> {
    store_dir
        .parent()
        .map(|p| p.join("archive").join("transcript.log"))
}

/// Ids evidenced as SPENT by a transcript's Sign-phase envelopes (every
/// accepted `SignShare` broadcast names the presignature it belongs to).
/// `None` when the transcript is missing or unreadable.
fn sign_evidence_ids(transcript: &Path) -> Option<BTreeSet<u64>> {
    let entries = read_transcript(transcript).ok()?;
    Some(
        entries
            .iter()
            .filter_map(|se| match (&se.envelope.phase, &se.envelope.payload) {
                (Phase::Sign, NodePayload::SignShare { presig, .. }) => Some(*presig),
                _ => None,
            })
            .collect(),
    )
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
    /// A4: the chained mutation journal (every insert/consume/expire is
    /// appended, fsync'd per entry).
    journal: Journal,
    /// A4: integrity warnings collected at `open` (printed there too).
    warnings: Vec<String>,
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
    ///
    /// A4 integrity checks (ON by default — [`Self::open_unverified`] is
    /// the dev escape hatch): replay the chained journal and verify it
    /// against the directory (every journaled mutation's artifact
    /// present and matching; a live record for an id the journal shows
    /// consumed — the ROLLBACK shape — is a hard failure), then
    /// cross-check the transcript archive at `<dir>/../archive/
    /// transcript.log` when present: a presignature id evidenced as
    /// spent by an accepted Sign-phase envelope must not be live in the
    /// store. Any break fails closed with [`PersistError::Integrity`]
    /// naming the divergence point.
    pub fn open(
        dir: &Path,
        public_key: &AffinePoint,
        storage_key: &StorageKey,
    ) -> Result<Self, PersistError> {
        Self::open_mode(dir, public_key, storage_key, false)
    }

    /// [`Self::open`] with the A4 integrity checks downgraded to loud
    /// warnings (the `--allow-unverified-store` dev escape hatch): a
    /// detected rollback does NOT stop the node — this is exactly the
    /// dangerous path (a rolled-back store will happily sign twice with
    /// one presignature id, which extracts the long-term key). Never use
    /// outside development.
    pub fn open_unverified(
        dir: &Path,
        public_key: &AffinePoint,
        storage_key: &StorageKey,
    ) -> Result<Self, PersistError> {
        Self::open_mode(dir, public_key, storage_key, true)
    }

    #[allow(clippy::too_many_lines)] // startup verification is one sequential audit
    fn open_mode(
        dir: &Path,
        public_key: &AffinePoint,
        storage_key: &StorageKey,
        allow_unverified: bool,
    ) -> Result<Self, PersistError> {
        let mut warnings: Vec<String> = Vec::new();
        if allow_unverified {
            warnings.push(
                "WARNING [A4]: store integrity checks are DISABLED (--allow-unverified-store) — \
                 a rolled-back presignature store will NOT be refused, and signing twice with one \
                 presignature id extracts the long-term key. DEV ONLY."
                    .to_string(),
            );
        }
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
        // Directory scan → the on-disk final state per id. Tombstones
        // first: a crash mid-expire (tombstone durable, sealed file not
        // yet removed) leaves BOTH — the tombstone wins and the stray
        // record is deleted in the second pass (never served). A consume
        // tombstone wins over a live record for the same reason.
        let mut disk: BTreeMap<u64, DiskState> = BTreeMap::new();
        for (id, kind, name) in &entries {
            match kind.as_str() {
                "consumed" => {
                    let bytes = fs::read(dir.join(name))?;
                    disk.insert(*id, DiskState::Consumed(payload_digest(&bytes)));
                }
                "expired" => {
                    disk.insert(*id, DiskState::Expired);
                }
                _ => {}
            }
        }
        for (id, kind, name) in &entries {
            match kind.as_str() {
                "presig" => {
                    if disk.contains_key(id) {
                        // A tombstone (consumed or expired) exists for
                        // this id: it wins; the stray record is deleted.
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
                    disk.insert(*id, DiskState::Live(payload_digest(&bytes)));
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

        // --- A4: the chained journal ----------------------------------
        let journal_path = dir.join(JOURNAL_FILE);
        let journal_existed = journal_path.exists();
        let mut journal = Journal {
            file: OpenOptions::new()
                .create(true)
                .append(true)
                .open(&journal_path)?,
            next_seq: 1,
            tip: ZERO_HASH,
        };
        // The final truth per id after journal reconciliation.
        let mut truth: BTreeMap<u64, DiskState> = disk.clone();
        if !journal_existed && !disk.is_empty() {
            // LEGACY store (pre-A4: records but no journal): there is no
            // history to verify — adopt the current state as the journal
            // genesis, loudly. Rollback of such a store is undetectable
            // until the first journaled mutation.
            warnings.push(format!(
                "WARNING [A4]: {} predates the store journal — adopting the current state \
                 as the journal genesis; history before this point is unverifiable",
                dir.display()
            ));
            for (id, ds) in &disk {
                match ds {
                    DiskState::Live(h) => journal.append(OP_INSERT, *id, *h)?,
                    DiskState::Consumed(h) => {
                        journal.append(OP_INSERT, *id, *h)?;
                        journal.append(OP_CONSUME, *id, *h)?;
                    }
                    DiskState::Expired => {
                        journal.append(OP_INSERT, *id, ZERO_HASH)?;
                        journal.append(OP_EXPIRE, *id, payload_digest(&[]))?;
                    }
                }
            }
        } else if journal_existed {
            let bytes = fs::read(&journal_path)?;
            match journal_replay(&bytes) {
                Ok(jentries) => {
                    if let Some(last) = jentries.last() {
                        journal.next_seq = last.seq + 1;
                        journal.tip = last.hash;
                    }
                    let mut journaled: BTreeMap<u64, JournalState> = BTreeMap::new();
                    for e in &jentries {
                        let js = match e.op {
                            OP_INSERT => JournalState::Live(e.payload),
                            OP_CONSUME => JournalState::Consumed(e.payload),
                            _ => JournalState::Expired,
                        };
                        journaled.insert(e.id, js);
                    }
                    match reconcile_journal(&journaled, &disk) {
                        Ok((heals, warns)) => {
                            warnings.extend(warns);
                            for (op, id, payload) in heals {
                                journal.append(op, id, payload)?;
                                let healed = match op {
                                    OP_CONSUME => DiskState::Consumed(payload),
                                    OP_EXPIRE => DiskState::Expired,
                                    _ => unreachable!("only consume/expire heal"),
                                };
                                truth.insert(id, healed);
                            }
                            // Unaccounted live records were dropped by the
                            // caller of reconcile (the warnings say which);
                            // remove them from the truth and the disk.
                            for (id, ds) in &disk {
                                if !journaled.contains_key(id) && matches!(ds, DiskState::Live(_)) {
                                    fs::remove_file(dir.join(format!("{id}.presig")))?;
                                    truth.remove(id);
                                }
                            }
                        }
                        Err(divergence) if allow_unverified => {
                            warnings.push(format!(
                                "WARNING [A4]: integrity divergence IGNORED \
                                 (--allow-unverified-store): {divergence}"
                            ));
                        }
                        Err(divergence) => {
                            return Err(PersistError::Integrity(divergence));
                        }
                    }
                }
                Err(chain_break) if allow_unverified => {
                    warnings.push(format!(
                        "WARNING [A4]: journal chain broken, IGNORED \
                         (--allow-unverified-store): {chain_break}"
                    ));
                }
                Err(chain_break) => {
                    return Err(PersistError::Integrity(chain_break));
                }
            }
        }
        // A journal that exists but is empty while records exist is the
        // same shape as a deleted journal: unaccounted live records are
        // dropped (safe direction), tombstones honored — handled above
        // via the (empty) replay.

        // --- A4: the transcript cross-check (the rollback detector) ----
        // The archive is append-only and its writes are independent of
        // the store's: a consume leaves accepted Sign-phase envelopes
        // naming the presignature id. A store backup restored over an
        // intact archive shows a spent id as LIVE — fail closed.
        let has_history = journal.next_seq > 1;
        match default_transcript(dir).and_then(|t| sign_evidence_ids(&t).map(|ids| (t, ids))) {
            Some((path, ids)) => {
                for id in &ids {
                    if matches!(truth.get(id), Some(DiskState::Live(_))) {
                        let divergence = format!(
                            "ROLLBACK DETECTED: presignature id {id} is evidenced as SPENT by \
                             the sign transcript {} but the store shows it LIVE — the store \
                             directory was restored from a stale backup; refusing to operate \
                             (§8.6/§13.3). Wipe the store or restore a consistent backup.",
                            path.display()
                        );
                        if allow_unverified {
                            warnings.push(format!(
                                "WARNING [A4]: {divergence} — IGNORED (dev mode): signing with \
                                 id {id} again would reuse a nonce and EXTRACT THE LONG-TERM KEY"
                            ));
                        } else {
                            return Err(PersistError::Integrity(divergence));
                        }
                    }
                }
                if has_history {
                    warnings.push(
                        "NOTE [A4]: journal + transcript cross-checks passed; the journal and \
                         the transcript live in the SAME rollback-able directory — a \
                         whole-directory restore to an older self-consistent state remains \
                         undetectable. True rollback prevention needs state outside this \
                         directory (HSM monotonic counter, peer attestation — SPEC §13.3); \
                         ship transcript.log off-box for real independence."
                            .to_string(),
                    );
                }
            }
            None => {
                if has_history {
                    warnings.push(
                        "WARNING [A4]: no transcript archive found next to the store — store \
                         integrity is only self-consistent (journal chain); a rollback of the \
                         whole directory is UNDETECTABLE without the sign transcript. True \
                         prevention needs state outside this directory (SPEC §13.3)."
                            .to_string(),
                    );
                }
            }
        }
        for w in &warnings {
            eprintln!("{w}");
        }

        let mut live = BTreeSet::new();
        let mut consumed = BTreeSet::new();
        let mut expired = BTreeSet::new();
        for (id, ds) in &truth {
            match ds {
                DiskState::Live(_) => {
                    live.insert(*id);
                }
                DiskState::Consumed(_) => {
                    consumed.insert(*id);
                }
                DiskState::Expired => {
                    expired.insert(*id);
                }
            }
        }
        // The created-at map covers exactly the surviving live records.
        created.retain(|id, _| live.contains(id));
        Ok(Self {
            dir: dir.to_path_buf(),
            public_key: *public_key,
            storage_key: storage_key.clone(),
            live,
            consumed,
            expired,
            created,
            journal,
            warnings,
        })
    }

    /// A4: the integrity warnings collected at `open` (already printed
    /// to stderr there; exposed for tests and tooling).
    pub fn integrity_warnings(&self) -> &[String] {
        &self.warnings
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
        // A4: journal the mutation (fsync'd) BEFORE acknowledging the
        // insert — a crash in between leaves an unaccounted record that
        // `open` drops (never acknowledged, like a stray `.tmp`).
        self.journal
            .append(OP_INSERT, id, payload_digest(&sealed))?;
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
        // A4: journal the consume BEFORE handing the record out — a
        // crash in between loses the record (never returned) and `open`
        // heals the journal from the durable tombstone (safe direction).
        self.journal
            .append(OP_CONSUME, id, payload_digest(&sealed))?;
        self.live.remove(&id);
        self.created.remove(&id);
        self.consumed.insert(id);
        Ok(presig)
    }

    /// Number of stored (unconsumed) presignatures.
    pub fn len(&self) -> usize {
        self.live.len()
    }

    /// Number of consumed presignatures (tombstoned, never re-issuable).
    pub fn consumed_count(&self) -> usize {
        self.consumed.len()
    }

    /// Number of TTL-expired presignatures (§8.6(3), burned forever).
    pub fn expired_count(&self) -> usize {
        self.expired.len()
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
        // A4: journal the expiry (the tombstone is durable first, so a
        // crash in between is healed at `open` — the id stays burned).
        self.journal.append(OP_EXPIRE, id, payload_digest(&[]))?;
        self.live.remove(&id);
        self.created.remove(&id);
        self.expired.insert(id);
        Ok(true)
    }

    /// Burn an id whose PRODUCTION session failed before any record was
    /// inserted (A7 — the fault-tolerant pool loop, `pool::PoolManager::tick_tolerant`):
    /// the empty `<id>.expired` tombstone is written and fsync'd, then a
    /// journal `OP_BURN` entry is appended, so the id is DURABLY
    /// never-re-issuable. A restarted pool manager re-seeds id
    /// allocation from `max_seen_id` (which covers burned ids), so a
    /// retried session can never reuse a presignature id — hence a sid —
    /// the wire may still hold acceptor/journal state for (a fresh
    /// payload in a stale slot would look like an equivocation).
    /// `Ok(false)` when the id is already known (live, consumed, or
    /// burned) — burning an INSERTED id is a caller bug (use
    /// [`Self::expire`]).
    pub fn burn(&mut self, id: u64) -> Result<bool, PersistError> {
        if self.live.contains(&id) || self.consumed.contains(&id) || self.expired.contains(&id) {
            return Ok(false);
        }
        write_atomic(
            &self.dir,
            &format!("{id}.tmp"),
            &format!("{id}.expired"),
            &[],
            false,
        )?;
        self.journal.append(OP_BURN, id, payload_digest(&[]))?;
        self.expired.insert(id);
        Ok(true)
    }
}

// --- A7: the node's long-term key share at rest (soak process-restart) --------

/// The sealed key-share file name inside a node's `--data-dir` (A7
/// soak): written once after the node's first keygen, loaded instead of
/// re-running keygen when the process is restarted into the SAME
/// committee (the kill/restart soak cycle).
pub const KEYSHARE_FILE: &str = "keyshare.sealed";

/// The H5 seal purpose for the key-share file (binds the AEAD).
fn keyshare_purpose() -> Vec<u8> {
    b"ohm-ecdsa-node/keyshare-v1".to_vec()
}

/// Persist the node's long-term key share, SEALED under the node's
/// storage key (resolved/generated at `dir`, the same source
/// abstraction as the store — [`crate::seal`]) and written `0600`. The
/// share is as secret as it gets — this file gets exactly the H5
/// at-rest treatment the seed/identity files get; it exists so a killed
/// node process can REJOIN its committee (the A7 soak restart cycle),
/// not as a general key-backup mechanism.
pub fn save_keyshare(dir: &Path, share: &KeyShare) -> Result<(), PersistError> {
    fs::create_dir_all(dir)?;
    let key = StorageKey::resolve_or_generate(dir)?;
    let mut plain = Vec::new();
    put_u64(&mut plain, share.index as u64);
    share.share.encode(&mut plain);
    share.com.encode(&mut plain);
    let sealed = key.seal(&keyshare_purpose(), &plain);
    crate::seal::write_secret_file(&dir.join(KEYSHARE_FILE), &sealed)?;
    Ok(())
}

/// The inverse of [`save_keyshare`]: `Ok(None)` when no key-share file
/// exists (first boot — the node runs keygen); a present file that
/// cannot be authenticated/decoded fails CLOSED (wrong storage key,
/// tampering, legacy cleartext), never a silent re-keygen.
pub fn load_keyshare(dir: &Path) -> Result<Option<KeyShare>, PersistError> {
    let path = dir.join(KEYSHARE_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let Some(key) = StorageKey::resolve(dir)? else {
        return Err(
            Error::PresigStore("a key-share file exists but no storage key is configured").into(),
        );
    };
    let sealed = fs::read(&path)?;
    let plain = key.open(&keyshare_purpose(), &sealed)?;
    let (index, used) = take_u64(&plain).ok_or(Error::PresigStore("corrupt key-share file"))?;
    let (share, used2) =
        Scalar::decode(&plain[used..]).ok_or(Error::PresigStore("corrupt key-share file"))?;
    let (com, used3) = FeldmanCommitment::decode(&plain[used + used2..])
        .ok_or(Error::PresigStore("corrupt key-share file"))?;
    if used + used2 + used3 != plain.len() || index == 0 {
        return Err(Error::PresigStore("corrupt key-share file").into());
    }
    let index =
        PartyId::try_from(index).map_err(|_| Error::PresigStore("corrupt key-share file"))?;
    Ok(Some(KeyShare { index, share, com }))
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
