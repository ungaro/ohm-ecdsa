//! Single-threaded reference orchestrator (SPEC §4.7, §13.2).
//!
//! Models the echo-broadcast channel by delivering identical message sets
//! to every party. Keygen delivery routes through the explicit transport
//! seam ([`crate::transport`]: [`SimTransport`] + [`drive_dkg`]); the
//! other phases deliver message vectors directly (incremental migration —
//! see the `transport` module docs). A deployment swaps the reference
//! transport for a real one (mutually authenticated channels + echo
//! broadcast + message signatures) while keeping the per-party protocol
//! logic unchanged. The `*_with_restart` wrappers implement the §10.3
//! expel-and-restart policy after an identifiable abort.

use k256::ecdsa::Signature;
use k256::Scalar;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};

use crate::dkg::DkgTamper;
use crate::policy::restart_committee;
use crate::presign::{self, KeyShare, PresignTamper, Presignature};
use crate::sign::{self, SignShare};
use crate::store::PresigStore;
use crate::transport::{drive_dkg, SimTransport};
use crate::triples::{self, TriplePublic, TripleShare, TripleTamper};
use crate::{scalar_from_digest, tags, Committee, Error, Params, PartyId, Phase, Result};

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
    // Keygen message delivery routes through the transport seam (§13.2):
    // SimTransport models the echo-broadcast channel (§4.7).
    let mut transport = SimTransport::new();
    drive_dkg(
        params,
        sid,
        tags::DKG_COMMIT,
        Phase::KeyGen,
        rngs,
        &mut transport,
        tamper,
    )
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

/// Robust presign (SPEC §8, §10.4): like [`run_presign`], but after the
/// dealing phases the openings and nonce points are blame-and-continue —
/// returns the records of the non-blamed parties and the blame list.
pub fn run_presign_robust(
    params: &Params,
    keys: &[KeyShare],
    id: u64,
    rngs: &mut [StdRng],
    tamper: Option<&PresignTamper>,
) -> Result<(Vec<Presignature>, Vec<PartyId>)> {
    presign::presign_robust(params, keys, id, rngs, tamper)
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

// --- §10.3 expel-and-restart policy -------------------------------------
//
// Dealing-phase failures (commit-reveal mismatch F1, bad dealt share F2,
// bad DLEQ proof F3) abort the instance — continuation is impossible
// there. The §10.3(1) answer is to expel the blamed and RESTART the
// instance over the surviving committee, poisoning the aborted sid/id
// (§10.3(2)). Retries are inherently bounded: every abort expels at
// least one party, and the policy refuses (propagating the abort) once
// the remainder would drop below `2t - 1` — `t` is never silently
// lowered; below the bound, committee re-sharing (§13.4) is required.
//
// Common conventions of the `*_with_restart` wrappers: `rngs` are CLONED
// per attempt (the caller's streams are not advanced); `tamper` (fault
// injection, tests) applies to the FIRST attempt only, retries run
// clean; the returned blame list is cumulative and in ORIGINAL party
// ids.

/// §10.3(2): the sid of a failed attempt is poisoned — never reused.
fn poison_sid(sid: &[u8], attempt: u64) -> Vec<u8> {
    if attempt == 0 {
        return sid.to_vec();
    }
    [sid, b"/retry-", &attempt.to_be_bytes()].concat()
}

/// Positions of `survivors` within `current` (per-party arrays are
/// indexed by position in the id list).
fn survivor_positions(current: &[PartyId], survivors: &[PartyId]) -> Vec<usize> {
    survivors
        .iter()
        .map(|s| {
            current
                .iter()
                .position(|p| p == s)
                .expect("survivors ⊆ current")
        })
        .collect()
}

/// KeyGen with the §10.3 expel-and-restart policy.
///
/// The first attempt runs over the full committee; on `Error::Abort` the
/// blamed parties are expelled via [`restart_committee`] and a FRESH
/// instance runs over the survivors — keygen may renumber freely (no
/// long-term shares exist yet), so each attempt runs `Params(n', t)`
/// over `1..=n'`. Returns the final keyshares (indexed `1..=n'`) and the
/// cumulative blame list in ORIGINAL ids.
pub fn run_keygen_with_restart(
    params: &Params,
    sid: &[u8],
    rngs: &mut [StdRng],
    tamper: Option<&DkgTamper>,
) -> Result<(Vec<KeyShare>, Vec<PartyId>)> {
    let mut current = params.parties();
    let mut cur_rngs: Vec<StdRng> = rngs.to_vec();
    let mut blamed_all: Vec<PartyId> = Vec::new();
    let mut attempt = 0u64;
    loop {
        let attempt_params = Params::new(current.len(), params.t)?;
        let attempt_sid = poison_sid(sid, attempt);
        let tamp = if attempt == 0 { tamper } else { None };
        match run_keygen_with_tamper(&attempt_params, &attempt_sid, &mut cur_rngs, tamp) {
            Ok(keys) => return Ok((keys, blamed_all)),
            Err(Error::Abort { abort }) => {
                // Blame arrives in the attempt's renumbered ids; map back
                // to the original ids.
                let blamed: Vec<PartyId> = abort.blamed.iter().map(|&b| current[b - 1]).collect();
                for &b in &blamed {
                    if !blamed_all.contains(&b) {
                        blamed_all.push(b);
                    }
                }
                blamed_all.sort_unstable();
                let survivors = match restart_committee(&current, &blamed, params.t) {
                    Ok(s) => s,
                    // Policy refusal: n' < 2t-1 needs §13.4 re-sharing.
                    Err(_) => return Err(Error::Abort { abort }),
                };
                let positions = survivor_positions(&current, &survivors);
                cur_rngs = positions.iter().map(|&p| cur_rngs[p].clone()).collect();
                current = survivors;
            }
            Err(e) => return Err(e),
        }
        attempt += 1;
    }
}

/// Triple generation with the §10.3 expel-and-restart policy, for faults
/// the §10.4 robust path cannot continue (dealing-phase F1/F2 aborts and
/// F3 bad product proofs). Triples are key-independent, so retries
/// renumber freely as in [`run_keygen_with_restart`]. Returns the final
/// per-party triples and the cumulative blame list in ORIGINAL ids.
#[allow(clippy::type_complexity)] // (records, blame) mirrors the other robust APIs
pub fn run_triples_with_restart(
    params: &Params,
    sid: &[u8],
    rngs: &mut [StdRng],
    tamper: Option<&TripleTamper>,
) -> Result<(Vec<(TripleShare, TriplePublic)>, Vec<PartyId>)> {
    let mut current = params.parties();
    let mut cur_rngs: Vec<StdRng> = rngs.to_vec();
    let mut blamed_all: Vec<PartyId> = Vec::new();
    let mut attempt = 0u64;
    loop {
        let attempt_params = Params::new(current.len(), params.t)?;
        let attempt_sid = poison_sid(sid, attempt);
        let tamp = if attempt == 0 { tamper } else { None };
        match triples::generate_with_tamper(&attempt_params, &attempt_sid, &mut cur_rngs, tamp) {
            Ok(triple) => return Ok((triple, blamed_all)),
            Err(Error::Abort { abort }) => {
                let blamed: Vec<PartyId> = abort.blamed.iter().map(|&b| current[b - 1]).collect();
                for &b in &blamed {
                    if !blamed_all.contains(&b) {
                        blamed_all.push(b);
                    }
                }
                blamed_all.sort_unstable();
                let survivors = match restart_committee(&current, &blamed, params.t) {
                    Ok(s) => s,
                    Err(_) => return Err(Error::Abort { abort }),
                };
                let positions = survivor_positions(&current, &survivors);
                cur_rngs = positions.iter().map(|&p| cur_rngs[p].clone()).collect();
                current = survivors;
            }
            Err(e) => return Err(e),
        }
        attempt += 1;
    }
}

/// Presign with the §10.3 expel-and-restart policy, for DEALING-phase
/// aborts (the §10.4 robust continuations are handled inside
/// [`presign::presign_robust`]; this wrapper drives the fail-fast
/// [`presign::presign`]).
///
/// Unlike keygen, presign P4 mixes `[x]` with fresh sharings, so the
/// survivors keep their ORIGINAL ids (their key shares `x_j` live at
/// those evaluation points): each attempt runs
/// [`presign::presign_with_committee`] over the surviving id set with the
/// survivors' key shares. The presignature id is poisoned per attempt
/// (§10.3(2)): attempt `k` uses `first_id + k`. If expulsion would leave
/// `n' < 2t - 1`, the abort is propagated unchanged.
///
/// `keys[i]`/`rngs[i]` belong to party `i + 1` (the full committee).
/// Returns the survivors' presignatures, the cumulative blame list, and
/// the id actually used.
pub fn run_presign_with_restart(
    params: &Params,
    keys: &[KeyShare],
    first_id: u64,
    rngs: &mut [StdRng],
    tamper: Option<&PresignTamper>,
) -> Result<(Vec<Presignature>, Vec<PartyId>, u64)> {
    let mut current: Vec<PartyId> = keys.iter().map(|k| k.index).collect();
    let mut cur_keys: Vec<KeyShare> = keys.to_vec();
    let mut cur_rngs: Vec<StdRng> = rngs.to_vec();
    let mut blamed_all: Vec<PartyId> = Vec::new();
    let mut attempt = 0u64;
    loop {
        let id = first_id + attempt; // §10.3(2): a poisoned id is never reused
        let committee = Committee::new(current.clone(), params.t)?;
        let tamp = if attempt == 0 { tamper } else { None };
        match presign::presign_with_committee(&committee, &cur_keys, id, &mut cur_rngs, tamp) {
            Ok(presigs) => return Ok((presigs, blamed_all, id)),
            Err(Error::Abort { abort }) => {
                // Blame is already in original ids (no renumbering here).
                for &b in &abort.blamed {
                    if !blamed_all.contains(&b) {
                        blamed_all.push(b);
                    }
                }
                blamed_all.sort_unstable();
                let survivors = match restart_committee(&current, &abort.blamed, params.t) {
                    Ok(s) => s,
                    // Policy refusal: n' < 2t-1 needs §13.4 re-sharing.
                    Err(_) => return Err(Error::Abort { abort }),
                };
                let positions = survivor_positions(&current, &survivors);
                cur_keys = positions.iter().map(|&p| cur_keys[p].clone()).collect();
                cur_rngs = positions.iter().map(|&p| cur_rngs[p].clone()).collect();
                current = survivors;
            }
            Err(e) => return Err(e),
        }
        attempt += 1;
    }
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
