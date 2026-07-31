//! H3: the DISTRIBUTED committee ceremony — the standard setup path.
//!
//! The demo ceremony ([`crate::seed`], the `setup` subcommand) generates
//! EVERY party's transport keypair in one process and distributes secret
//! files — one machine momentarily holds the whole committee's transport
//! secrets. Fine for demos, unacceptable for a real committee. This
//! module is the distributed replacement:
//!
//! 1. **Per-party [`init`]** — each party, on its OWN machine, generates
//!    its own transport keypair (plus a self-signed certificate with
//!    `--tls`), writes the SECRET material to its own directory
//!    (`party-<id>.identity`, and `party-<id>.key.pem` with `--tls`) and
//!    a PUBLIC bundle `party-<id>.pub` holding its id, transport
//!    verifying key, listen-address hint, and certificate. No secret
//!    ever leaves the party's machine.
//! 2. **Out-of-band exchange** — the `.pub` bundles travel over an
//!    authenticated channel. That channel is an OPS concern, not code
//!    (signed email, a verified read-out); [`fingerprint`] prints a short
//!    hex fingerprint of each bundle for exactly that second-channel
//!    cross-check.
//! 3. **Public [`assemble`]** — anyone, including an untrusted machine,
//!    validates the collected bundles (ids exactly `1..=n`, consistent
//!    TLS posture, parseable keys/certs) and writes the shared PUBLIC
//!    committee file (`committee.hex` — the exact format every existing
//!    [`crate::seed`] consumer reads) plus, with TLS, the pinned
//!    certificate set (`party-<id>.crt.pem`) for `--pinned DIR`.
//!    Assembly touches public data only and is re-runnable anywhere —
//!    every party can re-assemble and compare.
//!
//! The assembled committee file carries NO ceremony key: `x` is the
//! identity point as an explicit marker, so the M2 `--seeded` fallback
//! (ceremony-seeded presignatures) is impossible — the full arc (fresh
//! keygen → presign → sign under the nodes' own key) is the only mode,
//! and `node` takes `--identity` instead of `--seed`.
//!
//! Trust model, honestly: `init` is self-sovereign (each party vouches
//! for its own key) and `assemble` is public — but no code can
//! authenticate the out-of-band channel that distributes the bundles. A
//! swapped bundle means the committee bootstraps with an attacker's key
//! in the registry; the fingerprints exist so the committee confirms
//! every bundle over a second channel BEFORE assembling. Fail-closed
//! backstops at node startup: a node refuses to boot when its own
//! transport key does not match its registry entry, and (M3c) when its
//! own certificate does not match the pinned set.
//!
//! File format: hex of the canonical byte encoding below (no serde, as
//! everywhere in this workspace); the SECRET identity file is H5-SEALED
//! (ChaCha20-Poly1305 under the node's storage key, [`crate::seal`]) and
//! written `0600`, as is the TLS key PEM. Legacy cleartext identity
//! files are rejected with an explicit error (no silent downgrade).

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::{ProjectivePoint, SecretKey};
use rand::rngs::OsRng;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;

use ohm_ecdsa::{Params, PartyId};

use crate::seal::{self, StorageKey};
use crate::seed::{self, CommitteeInfo};
use crate::tls;

/// The H5 seal purpose for party identity files.
const IDENTITY_PURPOSE: &[u8] = b"party-identity";

/// Domain-separation tag for the out-of-band fingerprint (hex of
/// `H(tag ‖ id ‖ transport verifying key ‖ cert)`, truncated).
const FINGERPRINT_TAG: &[u8] = b"OHM-ECDSA-node/v0.1/party-fingerprint";

/// One party's SECRET identity: its id and its transport secret key.
/// Everything and only what the distributed ceremony leaves on the
/// party's own machine (the TLS certificate key lives in the M3c PEM
/// layout, `party-<id>.key.pem`).
#[derive(Debug)]
pub struct Identity {
    /// This party's id.
    pub id: PartyId,
    /// This party's transport secret key (SPEC §13.1 deployment PKI).
    pub transport_key: SecretKey,
}

/// One party's PUBLIC bundle: everything `assemble` needs from that
/// party, and nothing else. Safe to publish — the security requirement
/// is AUTHENTICITY (see the module docs), not confidentiality.
#[derive(Clone, Debug)]
pub struct PubBundle {
    /// This party's id.
    pub id: PartyId,
    /// This party's transport verifying key.
    pub verifying_key: VerifyingKey,
    /// The party's listen-address hint (`host:port`) — ops convenience;
    /// `assemble` prints a suggested `--peers` line from these.
    pub addr: String,
    /// The party's self-signed certificate (PEM) for the M3c mTLS mesh;
    /// empty when the committee runs plain TCP.
    pub cert_pem: String,
}

/// `party-<id>.identity` — one party's SECRET identity file.
pub fn identity_file(dir: &Path, id: PartyId) -> PathBuf {
    dir.join(format!("party-{id}.identity"))
}

/// `party-<id>.pub` — one party's PUBLIC bundle file.
pub fn pub_file(dir: &Path, id: PartyId) -> PathBuf {
    dir.join(format!("party-{id}.pub"))
}

/// A short hex fingerprint of a bundle — `H(tag ‖ id ‖ key ‖ cert)`
/// truncated to 16 bytes — for out-of-band (voice/second-channel)
/// verification before assembly.
pub fn fingerprint(bundle: &PubBundle) -> String {
    use k256::sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(FINGERPRINT_TAG);
    h.update((bundle.id as u64).to_be_bytes());
    h.update(bundle.verifying_key.to_encoded_point(true).as_bytes());
    h.update((bundle.cert_pem.len() as u64).to_be_bytes());
    h.update(bundle.cert_pem.as_bytes());
    seed::hex_encode(&h.finalize()[..16])
}

// --- canonical byte encoding (hex on disk) ---------------------------------

fn encode_identity(identity: &Identity) -> Vec<u8> {
    let mut out = Vec::new();
    seed::put_u64(&mut out, identity.id as u64);
    out.extend_from_slice(&identity.transport_key.to_bytes());
    out
}

fn decode_identity(b: &[u8]) -> Option<Identity> {
    let (id, used) = seed::take_u64(b)?;
    let key_bytes: [u8; 32] = b.get(used..used.checked_add(32)?)?.try_into().ok()?;
    Some(Identity {
        id: usize::try_from(id).ok()?,
        transport_key: SecretKey::from_bytes(&key_bytes.into()).ok()?,
    })
}

fn encode_pub(bundle: &PubBundle) -> Vec<u8> {
    let mut out = Vec::new();
    seed::put_u64(&mut out, bundle.id as u64);
    out.extend_from_slice(bundle.verifying_key.to_encoded_point(true).as_bytes());
    seed::put_u64(&mut out, bundle.addr.len() as u64);
    out.extend_from_slice(bundle.addr.as_bytes());
    seed::put_u64(&mut out, bundle.cert_pem.len() as u64);
    out.extend_from_slice(bundle.cert_pem.as_bytes());
    out
}

fn decode_pub(b: &[u8]) -> Option<PubBundle> {
    let (id, mut used) = seed::take_u64(b)?;
    let key = VerifyingKey::from_sec1_bytes(b.get(used..used.checked_add(33)?)?).ok()?;
    used += 33;
    let (addr_len, u) = seed::take_u64(b.get(used..)?)?;
    used += u;
    let addr = String::from_utf8(
        b.get(used..used.checked_add(usize::try_from(addr_len).ok()?)?)?
            .into(),
    )
    .ok()?;
    used += addr.len();
    let (cert_len, u) = seed::take_u64(b.get(used..)?)?;
    used += u;
    let cert_pem = String::from_utf8(
        b.get(used..used.checked_add(usize::try_from(cert_len).ok()?)?)?
            .into(),
    )
    .ok()?;
    Some(PubBundle {
        id: usize::try_from(id).ok()?,
        verifying_key: key,
        addr,
        cert_pem,
    })
}

/// Read ONE party's secret identity file — the only secret material a
/// node process loads under the distributed ceremony. The storage key
/// is resolved from the environment or `<identity dir>/storage.key`;
/// use [`read_identity_with`] to supply it explicitly. A legacy
/// cleartext identity file is REJECTED (fail closed).
pub fn read_identity(path: &Path) -> io::Result<Identity> {
    let beside = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let key = StorageKey::resolve(&beside)?.ok_or_else(|| {
        seed::invalid(&format!(
            "no storage key configured for {} (set {} or {}, or place {} beside it)",
            path.display(),
            seal::ENV_STORAGE_KEY,
            seal::ENV_STORAGE_KEY_FILE,
            seal::STORAGE_KEY_FILE
        ))
    })?;
    read_identity_with(path, &key)
}

/// [`read_identity`] with an explicit storage key.
pub fn read_identity_with(path: &Path, key: &StorageKey) -> io::Result<Identity> {
    seal::warn_if_loose(path, "identity file");
    let bytes = seed::hex_decode(&fs::read_to_string(path)?)?;
    let plain = key
        .open(IDENTITY_PURPOSE, &bytes)
        .map_err(|e| seed::invalid(&format!("identity file {}: {e}", path.display())))?;
    decode_identity(&plain).ok_or_else(|| seed::invalid("malformed identity file"))
}

/// Read a PUBLIC bundle file.
pub fn read_pub(path: &Path) -> io::Result<PubBundle> {
    let bytes = seed::hex_decode(&fs::read_to_string(path)?)?;
    decode_pub(&bytes).ok_or_else(|| seed::invalid("malformed pub bundle"))
}

/// Write a PUBLIC bundle file (used by [`init`]; tests use it to build
/// tampered bundles).
pub fn write_pub(path: &Path, bundle: &PubBundle) -> io::Result<()> {
    fs::write(path, seed::hex_encode(&encode_pub(bundle)))
}

// --- the two ceremony steps -------------------------------------------------

/// Per-party step: generate this party's transport keypair (and, with
/// `with_tls`, its self-signed M3c certificate) on its OWN machine;
/// write the SECRET identity (+ TLS key) and the PUBLIC bundle into
/// `dir`. Returns the bundle (the caller prints its [`fingerprint`]).
pub fn init(id: PartyId, dir: &Path, addr: &str, with_tls: bool) -> io::Result<PubBundle> {
    if id == 0 {
        return Err(seed::invalid("party ids are 1-based"));
    }
    fs::create_dir_all(dir)?;
    let transport_key = SecretKey::random(&mut OsRng);
    // H5: the identity is sealed under this party's storage key
    // (env/key-file, else a generated `<dir>/storage.key` — the dev
    // default) and written 0600.
    let storage_key = StorageKey::resolve_or_generate(dir)?;
    let sealed = storage_key.seal(
        IDENTITY_PURPOSE,
        &encode_identity(&Identity {
            id,
            transport_key: transport_key.clone(),
        }),
    );
    seal::write_secret_file(
        &identity_file(dir, id),
        seed::hex_encode(&sealed).as_bytes(),
    )?;
    let cert_pem = if with_tls {
        let (cert_pem, key_pem) = tls::generate_party(id)?;
        fs::write(tls::cert_file(dir, id), &cert_pem)?;
        // The TLS key is secret (0600); sealing PEM material is the
        // same interface as the identity — left cleartext-but-0600 here
        // because the M3c loader reads PEM (see node/README's H5 gaps).
        seal::write_secret_file(&tls::key_file(dir, id), key_pem.as_bytes())?;
        cert_pem
    } else {
        String::new()
    };
    let bundle = PubBundle {
        id,
        verifying_key: *SigningKey::from(&transport_key).verifying_key(),
        addr: addr.to_string(),
        cert_pem,
    };
    write_pub(&pub_file(dir, id), &bundle)?;
    Ok(bundle)
}

/// Assembly step (PUBLIC data only — safe to run anywhere): validate
/// the collected bundles and write the shared committee file into `dir`
/// (the exact format [`crate::seed`] consumers read) plus, when every
/// bundle carries a certificate, the pinned M3c certificate set. The
/// committee ids must be exactly `1..=n`; `t` defaults to `(n+1)/2`
/// (the maximal honest-majority threshold). The committee file's `x` is
/// the IDENTITY point — a distributed ceremony has no ceremony key.
pub fn assemble(bundles: &[PubBundle], t: Option<usize>, dir: &Path) -> io::Result<CommitteeInfo> {
    if bundles.is_empty() {
        return Err(seed::invalid("assemble: no input bundles"));
    }
    let mut seen = BTreeSet::new();
    for b in bundles {
        if !seen.insert(b.id) {
            return Err(seed::invalid("assemble: duplicate party id"));
        }
    }
    // The committee must be exactly the ids 1..=n (the core numbers
    // parties 1..=n; gaps would leave a node without a registry entry).
    let mut sorted = bundles.to_vec();
    sorted.sort_by_key(|b| b.id);
    if sorted.iter().enumerate().any(|(i, b)| b.id != i + 1) {
        return Err(seed::invalid(
            "assemble: party ids must be exactly 1..=n, one bundle per id",
        ));
    }
    // TLS posture must be uniform, and every certificate must parse.
    let with_tls = !sorted[0].cert_pem.is_empty();
    for b in &sorted {
        if b.cert_pem.is_empty() == with_tls {
            return Err(seed::invalid(
                "assemble: inconsistent TLS posture (some bundles carry a certificate, some do not)",
            ));
        }
        if with_tls && CertificateDer::from_pem_slice(b.cert_pem.as_bytes()).is_err() {
            return Err(seed::invalid("assemble: unparseable certificate"));
        }
    }
    let n = sorted.len();
    let t = t.unwrap_or(n.div_ceil(2));
    let params = Params::new(n, t).map_err(|_| seed::invalid("assemble: invalid (n, t)"))?;
    let info = CommitteeInfo {
        params,
        x: ProjectivePoint::IDENTITY,
        registry: sorted.iter().map(|b| (b.id, b.verifying_key)).collect(),
    };
    seed::write_committee(dir, &info)?;
    if with_tls {
        for b in &sorted {
            fs::write(tls::cert_file(dir, b.id), &b.cert_pem)?;
        }
    }
    Ok(info)
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
            "ohm-ceremony-test-{name}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn identity_and_pub_roundtrip() {
        let dir = tmpdir("roundtrip");
        let bundle = init(2, &dir, "127.0.0.1:7701", false).unwrap();
        let read = read_pub(&pub_file(&dir, 2)).unwrap();
        assert_eq!(read.id, 2);
        assert_eq!(read.verifying_key, bundle.verifying_key);
        assert_eq!(read.addr, "127.0.0.1:7701");
        assert!(read.cert_pem.is_empty());
        let identity = read_identity(&identity_file(&dir, 2)).unwrap();
        assert_eq!(identity.id, 2);
        // The identity's secret key matches the bundle's verifying key.
        assert_eq!(
            *SigningKey::from(&identity.transport_key).verifying_key(),
            bundle.verifying_key
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fingerprint_depends_on_every_field() {
        let dir = tmpdir("fingerprint");
        let a = init(1, &dir, "127.0.0.1:7700", false).unwrap();
        let mut b = a.clone();
        b.id = 2;
        assert_ne!(fingerprint(&a), fingerprint(&b));
        let mut c = a.clone();
        c.cert_pem = "cert".into();
        assert_ne!(fingerprint(&a), fingerprint(&c));
        // The address hint is ops metadata, NOT part of the identity.
        let mut d = a.clone();
        d.addr = "elsewhere:9".into();
        assert_eq!(fingerprint(&a), fingerprint(&d));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn assemble_validates_the_committee_shape() {
        let dir = tmpdir("assemble");
        let b1 = init(1, &dir.join("p1"), "a:1", false).unwrap();
        let b2 = init(2, &dir.join("p2"), "a:2", false).unwrap();
        let b3 = init(3, &dir.join("p3"), "a:3", false).unwrap();
        let out = dir.join("committee");
        let info = assemble(&[b3.clone(), b1.clone(), b2.clone()], None, &out).unwrap();
        assert_eq!((info.params.n, info.params.t), (3, 2));
        assert_eq!(info.x, ProjectivePoint::IDENTITY);
        assert_eq!(info.registry.len(), 3);
        // The file decodes through the EXISTING committee reader.
        let read = seed::read_committee(&out.join(seed::COMMITTEE_FILE)).unwrap();
        assert_eq!(read.registry, info.registry);
        // Duplicate id.
        assert!(assemble(&[b1.clone(), b1.clone(), b2.clone()], None, &out).is_err());
        // A gap (ids 1 and 3 only).
        assert!(assemble(&[b1.clone(), b3.clone()], None, &out).is_err());
        // Bad threshold (violates n >= 2t - 1).
        assert!(assemble(&[b1, b2, b3], Some(3), &out).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn assemble_mixed_tls_posture_rejected() {
        let dir = tmpdir("mixed-tls");
        let b1 = init(1, &dir.join("p1"), "a:1", true).unwrap();
        let b2 = init(2, &dir.join("p2"), "a:2", false).unwrap();
        assert!(assemble(&[b1, b2], None, &dir.join("committee")).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
