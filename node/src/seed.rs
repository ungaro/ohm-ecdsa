//! M2 demo seed files — transport keys, plus the ceremony that remains
//! as the `--seeded` presignature-distribution fallback (SPEC §8.6,
//! §13.1).
//!
//! With M3a the default demo presigns through the mesh under the key its
//! own keygen produced (`party::PartyNode::presign`). The ceremony is
//! kept as a FALLBACK (`--seeded`): a PRIOR ORCHESTRATED RUN — one
//! process runs the core's reference orchestrator (sim keygen +
//! presign) and writes one seed file per party plus one public committee
//! file. In BOTH modes the per-party transport secret keys come from
//! these seed files (the demo's §13.1 deployment-PKI stand-in); only the
//! key share and presignature records are fallback material.
//!
//! Key separation is by construction: a [`PartySeed`] file contains only
//! ONE party's material (its transport secret key, its key share of the
//! ceremony key, its presignature records); the committee file contains
//! only PUBLIC material (threshold params, the joint public key, the
//! transport verifying-key registry). A node process reads exactly its
//! own seed file plus the public committee file.
//!
//! File format: hex of the canonical byte encoding below (no serde, as
//! everywhere in this workspace). Seed files are secret material on disk
//! — retention/zeroization of files is a deployment concern (SPEC §13.3),
//! accepted here for localhost demos and tests.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar, SecretKey};
use rand::rngs::StdRng;
use rand::SeedableRng;

use ohm_ecdsa::dkg::DkgOutput;
use ohm_ecdsa::presign::Presignature;
use ohm_ecdsa::sim;
use ohm_ecdsa::transport::{Decode, Encode};
use ohm_ecdsa::vss::FeldmanCommitment;
use ohm_ecdsa::{Params, PartyId};

/// The public committee file: threshold params, the ceremony joint public
/// key `X`, and the transport verifying-key registry. No secrets.
#[derive(Clone, Debug)]
pub struct CommitteeInfo {
    /// The threshold parameters the ceremony ran with.
    pub params: Params,
    /// The ceremony joint public key `X`.
    pub x: ProjectivePoint,
    /// `(id, transport verifying key)` per committee member.
    pub registry: Vec<(PartyId, k256::ecdsa::VerifyingKey)>,
}

/// One party's secret seed: everything and ONLY what that party holds.
#[derive(Debug)]
pub struct PartySeed {
    /// This party's id.
    pub id: PartyId,
    /// This party's transport secret key (SPEC §13.1 deployment PKI).
    pub transport_key: SecretKey,
    /// This party's key share of the ceremony key.
    pub key_share: DkgOutput,
    /// This party's presignature records (single-use, key-equivalent —
    /// SPEC §8.6), bound to the ceremony key.
    pub presigs: Vec<Presignature>,
}

/// Run the ceremony: orchestrated keygen + `n_presigs` presignatures
/// (deterministic under `seed`, as the repo's tests require) plus fresh
/// per-party transport keys. Returns the public committee info and one
/// secret seed per party.
pub fn ceremony(params: &Params, n_presigs: u64, seed: u64) -> (CommitteeInfo, Vec<PartySeed>) {
    let mut key_rng = StdRng::seed_from_u64(seed ^ 0x5EED);
    let transport_keys: Vec<SecretKey> = (0..params.n)
        .map(|_| SecretKey::random(&mut key_rng))
        .collect();
    let mut rngs = sim::make_rngs(params.n, seed);
    let keys = sim::run_keygen(params, b"ohm-ecdsa-node/ceremony/keygen", &mut rngs)
        .expect("ceremony keygen");
    let mut presigs: Vec<Vec<Presignature>> = (0..params.n).map(|_| Vec::new()).collect();
    for id in 0..n_presigs {
        let records =
            sim::run_presign(params, &keys, id, &mut rngs, None).expect("ceremony presign");
        for (slot, record) in presigs.iter_mut().zip(records) {
            slot.push(record);
        }
    }
    let info = CommitteeInfo {
        params: *params,
        x: keys[0].com.points[0],
        registry: transport_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| (i + 1, *k256::ecdsa::SigningKey::from(sk).verifying_key()))
            .collect(),
    };
    let seeds = (0..params.n)
        .map(|k| PartySeed {
            id: k + 1,
            transport_key: transport_keys[k].clone(),
            key_share: keys[k].clone(),
            presigs: std::mem::take(&mut presigs[k]),
        })
        .collect();
    (info, seeds)
}

// --- canonical byte encoding (hex on disk) ---------------------------------

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn take_u64(b: &[u8]) -> Option<(u64, usize)> {
    let a: [u8; 8] = b.get(..8)?.try_into().ok()?;
    Some((u64::from_be_bytes(a), 8))
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

fn encode_committee(info: &CommitteeInfo) -> Vec<u8> {
    let mut out = Vec::new();
    put_u64(&mut out, info.params.n as u64);
    put_u64(&mut out, info.params.t as u64);
    info.x.encode(&mut out);
    put_u64(&mut out, info.registry.len() as u64);
    for (id, key) in &info.registry {
        put_u64(&mut out, *id as u64);
        out.extend_from_slice(key.to_encoded_point(true).as_bytes());
    }
    out
}

fn decode_committee(b: &[u8]) -> Option<CommitteeInfo> {
    let (n, mut used) = take_u64(b)?;
    let (t, u) = take_u64(b.get(used..)?)?;
    used += u;
    let (x, u) = ProjectivePoint::decode(b.get(used..)?)?;
    used += u;
    let (count, u) = take_u64(b.get(used..)?)?;
    used += u;
    let mut registry = Vec::new();
    for _ in 0..count {
        let (id, u) = take_u64(b.get(used..)?)?;
        used += u;
        let ep = k256::EncodedPoint::from_bytes(b.get(used..used.checked_add(33)?)?).ok()?;
        used += 33;
        let aff = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep))?;
        registry.push((
            usize::try_from(id).ok()?,
            k256::ecdsa::VerifyingKey::from_affine(aff).ok()?,
        ));
    }
    Some(CommitteeInfo {
        params: Params::new(usize::try_from(n).ok()?, usize::try_from(t).ok()?).ok()?,
        x,
        registry,
    })
}

fn encode_seed(seed: &PartySeed) -> Vec<u8> {
    let mut out = Vec::new();
    put_u64(&mut out, seed.id as u64);
    out.extend_from_slice(&seed.transport_key.to_bytes());
    put_u64(&mut out, seed.key_share.index as u64);
    seed.key_share.share.encode(&mut out);
    seed.key_share.com.encode(&mut out);
    put_u64(&mut out, seed.presigs.len() as u64);
    for p in &seed.presigs {
        put_presig(&mut out, p);
    }
    out
}

fn decode_seed(b: &[u8]) -> Option<PartySeed> {
    let (id, mut used) = take_u64(b)?;
    let key_bytes: [u8; 32] = b.get(used..used.checked_add(32)?)?.try_into().ok()?;
    used += 32;
    let transport_key = SecretKey::from_bytes(&key_bytes.into()).ok()?;
    let (index, u) = take_u64(b.get(used..)?)?;
    used += u;
    let (share, u) = Scalar::decode(b.get(used..)?)?;
    used += u;
    let (com, u) = FeldmanCommitment::decode(b.get(used..)?)?;
    used += u;
    let (count, u) = take_u64(b.get(used..)?)?;
    used += u;
    let mut presigs = Vec::new();
    for _ in 0..count {
        let (p, u) = take_presig(b.get(used..)?)?;
        used += u;
        presigs.push(p);
    }
    Some(PartySeed {
        id: usize::try_from(id).ok()?,
        transport_key,
        key_share: DkgOutput {
            index: usize::try_from(index).ok()?,
            share,
            com,
        },
        presigs,
    })
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> io::Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad hex"));
    }
    Ok((0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hexdigits checked"))
        .collect())
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_string())
}

/// The committee file name within a seed directory.
pub const COMMITTEE_FILE: &str = "committee.hex";

/// The per-party seed file name within a seed directory.
pub fn seed_file(dir: &Path, id: PartyId) -> PathBuf {
    dir.join(format!("party-{id}.seed"))
}

/// Write the public committee file and every party's secret seed file.
pub fn write_all(dir: &Path, info: &CommitteeInfo, seeds: &[PartySeed]) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::write(
        dir.join(COMMITTEE_FILE),
        hex_encode(&encode_committee(info)),
    )?;
    for seed in seeds {
        fs::write(seed_file(dir, seed.id), hex_encode(&encode_seed(seed)))?;
    }
    Ok(())
}

/// Read the public committee file.
pub fn read_committee(path: &Path) -> io::Result<CommitteeInfo> {
    let bytes = hex_decode(&fs::read_to_string(path)?)?;
    decode_committee(&bytes).ok_or_else(|| invalid("malformed committee file"))
}

/// Read ONE party's secret seed file — the only secret material a node
/// process ever loads.
pub fn read_seed(path: &Path) -> io::Result<PartySeed> {
    let bytes = hex_decode(&fs::read_to_string(path)?)?;
    decode_seed(&bytes).ok_or_else(|| invalid("malformed seed file"))
}
