//! Single-threaded reference orchestrator (SPEC §4.7, §13.2).
//!
//! Models the echo-broadcast channel by delivering identical message sets
//! to every party. A deployment swaps this driver for a real transport
//! (mutually authenticated channels + echo broadcast + message signatures)
//! while keeping the per-party protocol logic unchanged.

use std::collections::BTreeMap;

use k256::ecdsa::Signature;
use k256::Scalar;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};

use crate::dkg::{DkgInstance, DkgOutput, DkgTamper};
use crate::presign::{self, KeyShare, PresignTamper, Presignature};
use crate::sign::{self, SignShare};
use crate::store::PresigStore;
use crate::{scalar_from_digest, tags, Params, PartyId, Phase, Result};

/// Deterministic per-party RNGs (tests / reproducible runs).
pub fn make_rngs(n: usize, seed: u64) -> Vec<StdRng> {
    (0..n)
        .map(|i| {
            StdRng::seed_from_u64(
                seed.wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .wrapping_add(i as u64 + 1),
            )
        })
        .collect()
}

/// KeyGen (SPEC §6): returns one [`KeyShare`] per party.
pub fn run_keygen(params: &Params, sid: &[u8], rngs: &mut [StdRng]) -> Result<Vec<KeyShare>> {
    run_keygen_with_tamper(params, sid, rngs, None)
}

/// [`run_keygen`] with fault-injection hooks (tests).
pub fn run_keygen_with_tamper(
    params: &Params,
    sid: &[u8],
    rngs: &mut [StdRng],
    tamper: Option<&DkgTamper>,
) -> Result<Vec<KeyShare>> {
    let mut r1 = BTreeMap::new();
    let mut insts = Vec::new();
    for (k, &i) in params.parties().iter().enumerate() {
        let (mut inst, b1) = DkgInstance::start(*params, sid, tags::DKG_COMMIT, i, &mut rngs[k]);
        if let Some((dealer, victim)) = tamper.and_then(|t| t.bad_deal) {
            if dealer == i {
                // Cheating dealer: wrong share *and* wrong §6.1 defense.
                inst.bad_deal = Some(victim);
            }
        }
        r1.insert(i, b1);
        insts.push(inst);
    }
    let mut r2 = BTreeMap::new();
    let mut p2p = Vec::new();
    for inst in &insts {
        let (b2, shares) = inst.reveal();
        r2.insert(inst.me, b2);
        p2p.extend(shares);
    }
    if let Some((dealer, victim)) = tamper.and_then(|t| t.corrupt_share) {
        // Corrupt the share in transit: the dealer's §6.1 defense still
        // verifies, so the victim's complaint is a false accusation.
        for m in p2p.iter_mut() {
            if m.from == dealer && m.to == victim {
                m.share += Scalar::ONE;
            }
        }
    }
    let mut outs: Vec<DkgOutput> = Vec::with_capacity(params.n);
    for inst in &insts {
        let me = inst.me;
        let mine: BTreeMap<PartyId, Scalar> = p2p
            .iter()
            .filter(|m| m.to == me)
            .map(|m| (m.from, m.share))
            .collect();
        let defenses: BTreeMap<PartyId, Scalar> =
            insts.iter().map(|d| (d.me, d.defend(me))).collect();
        outs.push(inst.finalize(Phase::KeyGen, &r1, &r2, &mine, &defenses)?);
    }
    Ok(outs)
}

/// Presign one presignature (SPEC §8).
pub fn run_presign(
    params: &Params,
    keys: &[KeyShare],
    id: u64,
    rngs: &mut [StdRng],
    tamper: Option<&PresignTamper>,
) -> Result<Vec<Presignature>> {
    presign::presign(params, keys, id, rngs, tamper)
}

/// Presign a batch of presignatures in one session (SPEC §8.5): returns,
/// per party, `ids.len()` presignatures in `ids` order.
pub fn run_presign_batch(
    params: &Params,
    keys: &[KeyShare],
    ids: &[u64],
    rngs: &mut [StdRng],
    tamper: Option<&PresignTamper>,
) -> Result<Vec<Vec<Presignature>>> {
    presign::presign_batch(params, keys, ids, rngs, tamper)
}

/// Message hash as a scalar: `m = H(M) mod q` (SPEC §3).
pub fn message_scalar(msg: &[u8]) -> Scalar {
    scalar_from_digest(&Sha256::digest(msg))
}

/// Online signing (SPEC §9): one local share per party, verified combine,
/// low-`s` normalization. `tamper` replaces one party's broadcast share
/// (fault injection for tests).
pub fn run_sign(
    params: &Params,
    presigs: &[Presignature],
    msg: &[u8],
    tamper: Option<(PartyId, Scalar)>,
) -> Result<Signature> {
    let m = message_scalar(msg);
    let mut shares: Vec<SignShare> = presigs.iter().map(|p| sign::sign_share(p, &m)).collect();
    if let Some((party, fake)) = tamper {
        for sh in shares.iter_mut() {
            if sh.from == party {
                sh.s = fake;
            }
        }
    }
    let (r, s) = sign::combine(params, &presigs[0], &m, &shares)?;
    let sig = Signature::from_scalars(r, s)?;
    Ok(sig.normalize_s().unwrap_or(sig))
}

/// Online signing through per-party single-use stores (SPEC §8.6, §9).
///
/// Each participating party's store atomically consumes `id` (§8.6(1))
/// before its share is computed; signing then proceeds as in
/// [`run_sign`]. If any store fails to consume, no signature is produced
/// and already-consumed records stay consumed — abort-after-consume still
/// poisons the id (SPEC §10.3(2)).
pub fn run_sign_stored(
    params: &Params,
    stores: &mut [PresigStore],
    id: u64,
    msg: &[u8],
    tamper: Option<(PartyId, Scalar)>,
) -> Result<Signature> {
    let mut presigs = Vec::with_capacity(stores.len());
    for store in stores.iter_mut() {
        presigs.push(store.consume(id)?);
    }
    run_sign(params, &presigs, msg, tamper)
}

/// Robust online signing (SPEC §10.4): like [`run_sign`], but shares that
/// fail verification are excluded and blamed, and the signature is still
/// delivered from the remaining `≥ t` honest shares (guaranteed output
/// delivery). `tamper` replaces the listed parties' broadcast shares
/// (fault injection for tests). Returns the signature and the blamed
/// parties.
pub fn run_sign_robust(
    params: &Params,
    presigs: &[Presignature],
    msg: &[u8],
    tamper: &[(PartyId, Scalar)],
) -> Result<(Signature, Vec<PartyId>)> {
    let m = message_scalar(msg);
    let mut shares: Vec<SignShare> = presigs.iter().map(|p| sign::sign_share(p, &m)).collect();
    for (party, fake) in tamper {
        for sh in shares.iter_mut() {
            if sh.from == *party {
                sh.s = *fake;
            }
        }
    }
    let ((r, s), blamed) = sign::combine_robust(params, &presigs[0], &m, &shares)?;
    let sig = Signature::from_scalars(r, s)?;
    Ok((sig.normalize_s().unwrap_or(sig), blamed))
}
