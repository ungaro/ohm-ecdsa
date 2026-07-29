//! Key-dependent presignatures (SPEC §8): `([u] = [k⁻¹], [z] = [k⁻¹x], R, r)`.
//!
//! The inverse is *generated directly*: `u` is dealt as a random value and
//! defined to be `k⁻¹`; `k` is derived publicly as `k = v⁻¹·a` where
//! `v = a·u` is opened through a Beaver triple. No inversion protocol, no
//! zero-sharing-blinded products (SPEC §12).
//!
//! [`presign_batch`] generates `B` records per session (SPEC §8.5): one
//! commit-reveal covers all `2B` ephemeral VSS instances.
//!
//! [`presign_robust`] is the §10.4 blame-and-continue variant: once the
//! commit-reveal dealing phases have bound everyone to the same
//! polynomials, bad opening shares and bad nonce points are filtered out
//! and blamed, and the remaining `≥ t` honest parties finish the instance.
//!
//! All entry points have `*_with_committee` variants that run over an
//! explicit party-id set (the surviving original ids of a §10.3 restart)
//! instead of the default `1..=n`; per-party arrays (`keys`, `rngs`,
//! outputs) are positional in the id list.

use std::collections::BTreeMap;

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand::rngs::StdRng;

use crate::dkg::DkgOutput;
use crate::open::{open, open_robust};
use crate::shamir::lagrange_coeffs;
use crate::triples::{self, TripleTamper};
use crate::vss::FeldmanCommitment;
use crate::{
    scalar_from_digest, Committee, Error, IdentifiableAbort, Params, PartyId, Phase, Result,
};

/// Long-term key share = DKG output.
pub type KeyShare = DkgOutput;

/// One party's presignature record (single-use; key-equivalent — SPEC §8.6).
#[derive(Debug)]
pub struct Presignature {
    pub id: u64,
    pub index: PartyId,
    pub r: Scalar,
    pub big_r: AffinePoint,
    /// Share of `u = k⁻¹`.
    pub u_share: Scalar,
    /// Share of `z = k⁻¹·x`.
    pub z_share: Scalar,
    pub u_com: FeldmanCommitment,
    pub z_com: FeldmanCommitment,
}

impl Drop for Presignature {
    fn drop(&mut self) {
        self.u_share = Scalar::ZERO;
        self.z_share = Scalar::ZERO;
    }
}

impl Presignature {
    /// Additive key derivation (SPEC §9.4): rebind this presignature to
    /// `x' = x + τ` with a local linear update.
    pub fn apply_tweak(&mut self, tau: &Scalar) {
        self.z_share += *tau * self.u_share;
        self.z_com = self.z_com.add(&self.u_com.scale(tau));
    }
}

/// Fault-injection hooks for testing identifiable abort.
#[derive(Debug, Default)]
pub struct PresignTamper {
    /// This party broadcasts a wrong nonce point `R_j` (P3): the fail-fast
    /// paths abort blaming it; [`presign_robust`] filters the point,
    /// blames the sender, and interpolates `R` over the valid points.
    pub bad_nonce_point: Option<PartyId>,
    /// This party broadcasts a wrong opening share in the P2 `v` opening
    /// (in `presign_batch`, of batch item 0): the fail-fast paths abort
    /// blaming it; [`presign_robust`] filters the share, blames the
    /// sender, and continues (SPEC §10.4).
    pub bad_open_share: Option<PartyId>,
    /// Dealing-phase hook (F1/F2/F3): forwarded to the FIRST triple
    /// session of the instance. A dealing failure is fail-fast — the
    /// instance aborts and recovery is the §10.3 expel-and-restart policy
    /// (see [`crate::sim::run_presign_with_restart`]).
    pub triple_tamper: Option<TripleTamper>,
}

/// §10.4 blame bookkeeping: add `new` to the blame list (deduplicated)
/// and expel them from the active set — a blamed party's later shares are
/// ignored even if they look valid, and it gets no output record.
fn expel(blamed: &mut Vec<PartyId>, active: &mut Vec<PartyId>, new: Vec<PartyId>) {
    for j in new {
        if !blamed.contains(&j) {
            blamed.push(j);
        }
        active.retain(|&p| p != j);
    }
}

/// Broadcast shares of the currently active parties: `pick(k)` is the
/// share the party at committee position `k` would broadcast.
fn active_shares(
    committee: &Committee,
    active: &[PartyId],
    pick: impl Fn(usize) -> Scalar,
) -> BTreeMap<PartyId, Scalar> {
    active
        .iter()
        .map(|&j| {
            let k = committee.position(j).expect("active ⊆ committee");
            (j, pick(k))
        })
        .collect()
}

/// Check that per-party arrays match the committee positionally:
/// `keys[k]` must belong to `committee.ids()[k]` (SPEC §10.3 restarts run
/// over non-contiguous original ids). Extra trailing `rngs` are ignored,
/// as in the `1..=n` entry points.
fn check_committee_inputs(committee: &Committee, keys: &[KeyShare], rngs: &[StdRng]) -> Result<()> {
    if keys.len() != committee.n()
        || rngs.len() < committee.n()
        || keys
            .iter()
            .zip(committee.ids())
            .any(|(key, &i)| key.index != i)
    {
        return Err(Error::InvalidParams(
            "keys/rngs must match the committee positionally (keys[k].index == ids[k])",
        ));
    }
    Ok(())
}

/// Run the presign protocol for one presignature id (SPEC §8, P1–P4).
///
/// `keys[i]`, `rngs[i]` belong to party `i + 1`. Returns one
/// [`Presignature`] per party.
pub fn presign(
    params: &Params,
    keys: &[KeyShare],
    id: u64,
    rngs: &mut [StdRng],
    tamper: Option<&PresignTamper>,
) -> Result<Vec<Presignature>> {
    presign_with_committee(&Committee::full(params), keys, id, rngs, tamper)
}

/// [`presign`] over an explicit committee (SPEC §10.3 restart): the fresh
/// sharings `[u]`, `[a]` and the triples are dealt at the committee's
/// original ids — the same evaluation points at which the long-term key
/// shares `x_j` live. `keys[k]`/`rngs[k]` belong to `committee.ids()[k]`
/// (positionally; `keys[k].index` is checked). Tamper hooks name ids.
pub fn presign_with_committee(
    committee: &Committee,
    keys: &[KeyShare],
    id: u64,
    rngs: &mut [StdRng],
    tamper: Option<&PresignTamper>,
) -> Result<Vec<Presignature>> {
    check_committee_inputs(committee, keys, rngs)?;
    let ids = committee.ids();
    let n = ids.len();
    let t = committee.t();
    let sid = format!("ohm-ecdsa/presign/{id}").into_bytes();

    // Two fresh triples (SPEC §7). The `triple_tamper` fault-injection
    // hook (tests) targets the FIRST triple session's dealing phase.
    let t_tamper = tamper.and_then(|tamp| tamp.triple_tamper);
    let t1 = triples::generate_with_committee(
        committee,
        &[sid.as_slice(), b"/t1"].concat(),
        rngs,
        t_tamper.as_ref(),
    )?;
    let t2 = triples::generate_with_committee(
        committee,
        &[sid.as_slice(), b"/t2"].concat(),
        rngs,
        None,
    )?;
    let pub1 = &t1[0].1;
    let pub2 = &t2[0].1;

    // P1: ephemeral joint randomness [u] (:= k⁻¹) and [a].
    let u_out = triples::joint_random(
        committee,
        &[sid.as_slice(), b"/u"].concat(),
        rngs,
        Phase::Presign,
    )?;
    let a_out = triples::joint_random(
        committee,
        &[sid.as_slice(), b"/a"].concat(),
        rngs,
        Phase::Presign,
    )?;
    let u_shares: Vec<Scalar> = u_out.iter().map(|o| o.share).collect();
    let a_shares: Vec<Scalar> = a_out.iter().map(|o| o.share).collect();
    let u_com = u_out[0].com.clone();
    let a_com = a_out[0].com.clone();

    // P2: open δ = u − α, ε = a − β; form and open v = a·u via triple 1.
    let neg = -Scalar::ONE;
    let delta_com = u_com.add(&pub1.ca.scale(&neg));
    let eps_com = a_com.add(&pub1.cb.scale(&neg));
    let deltas: BTreeMap<PartyId, Scalar> = ids
        .iter()
        .enumerate()
        .map(|(k, &j)| (j, u_shares[k] - t1[k].0.a))
        .collect();
    let epsilons: BTreeMap<PartyId, Scalar> = ids
        .iter()
        .enumerate()
        .map(|(k, &j)| (j, a_shares[k] - t1[k].0.b))
        .collect();
    let delta = open(t, &delta_com, &deltas, Phase::Presign)?;
    let eps = open(t, &eps_com, &epsilons, Phase::Presign)?;

    let v_com = pub1
        .cc
        .clone()
        .add(&pub1.cb.scale(&delta))
        .add(&pub1.ca.scale(&eps))
        .add_const(&(delta * eps));
    let mut v_shares: BTreeMap<PartyId, Scalar> = ids
        .iter()
        .enumerate()
        .map(|(k, &j)| {
            (
                j,
                t1[k].0.c + delta * t1[k].0.b + eps * t1[k].0.a + delta * eps,
            )
        })
        .collect();
    if let Some(tamp) = tamper {
        if let Some(j) = tamp.bad_open_share {
            if let Some(s) = v_shares.get_mut(&j) {
                *s += Scalar::ONE; // malicious: wrong opening share
            }
        }
    }
    let v = open(t, &v_com, &v_shares, Phase::Presign)?;
    if v == Scalar::ZERO {
        return Err(Error::ZeroValue("v = 0".into())); // restart with fresh randomness
    }
    let v_inv =
        Option::<Scalar>::from(v.invert()).ok_or_else(|| Error::ZeroValue("v = 0".into()))?;

    // P3: [k] = v⁻¹·[a]; nonce point R with per-share point checks.
    let k_com = a_com.scale(&v_inv);
    let mut r_points = Vec::with_capacity(n);
    for (k, &j) in ids.iter().enumerate() {
        let k_share = v_inv * a_shares[k];
        let mut r_j = ProjectivePoint::GENERATOR * k_share;
        if let Some(tamp) = tamper {
            if tamp.bad_nonce_point == Some(j) {
                r_j += ProjectivePoint::GENERATOR; // malicious: wrong point
            }
        }
        if r_j != k_com.eval_at(j) {
            return Err(Error::Abort {
                abort: IdentifiableAbort {
                    phase: Phase::Presign,
                    blamed: vec![j],
                    detail: "invalid nonce point R_j".into(),
                },
            });
        }
        r_points.push(r_j);
    }
    let lambdas = lagrange_coeffs(ids);
    let mut big_r_proj = ProjectivePoint::IDENTITY;
    for (l, rp) in lambdas.iter().zip(r_points.iter()) {
        big_r_proj += *rp * l;
    }
    let big_r = big_r_proj.to_affine();
    let r_encoded = big_r.to_encoded_point(false);
    let r_scalar = scalar_from_digest(r_encoded.x().expect("uncompressed point has x"));
    if r_scalar == Scalar::ZERO {
        return Err(Error::ZeroValue("r = 0".into()));
    }

    // P4: z = u·x via triple 2 (binds the presignature to the key).
    let d2_com = u_com.add(&pub2.ca.scale(&neg));
    let e2_com = keys[0].com.add(&pub2.cb.scale(&neg));
    let d2: BTreeMap<PartyId, Scalar> = ids
        .iter()
        .enumerate()
        .map(|(k, &j)| (j, u_shares[k] - t2[k].0.a))
        .collect();
    let e2: BTreeMap<PartyId, Scalar> = ids
        .iter()
        .enumerate()
        .map(|(k, &j)| (j, keys[k].share - t2[k].0.b))
        .collect();
    let d2v = open(t, &d2_com, &d2, Phase::Presign)?;
    let e2v = open(t, &e2_com, &e2, Phase::Presign)?;
    let z_com = pub2
        .cc
        .clone()
        .add(&pub2.cb.scale(&d2v))
        .add(&pub2.ca.scale(&e2v))
        .add_const(&(d2v * e2v));

    let presigs = (0..n)
        .map(|k| {
            let j = ids[k];
            let z_share = t2[k].0.c + d2v * t2[k].0.b + e2v * t2[k].0.a + d2v * e2v;
            Presignature {
                id,
                index: j,
                r: r_scalar,
                big_r,
                u_share: u_shares[k],
                z_share,
                u_com: u_com.clone(),
                z_com: z_com.clone(),
            }
        })
        .collect();
    Ok(presigs)
}

/// Robust variant of [`presign`] (SPEC §10.4) for one presignature id.
///
/// The §10.4 invariant applies once everything is committed: the
/// commit-reveal dealing phases (joint VSS for `u`/`a`, triple inputs)
/// bind every party to the same polynomials, so honest shares suffice —
/// the openings and nonce points are reconstruct-and-continue instead of
/// abort:
///
/// * P2/P4 openings (`δ, ε, v, δ′, ε′`) go through [`open_robust`]: bad
///   shares are filtered and their senders blamed; any `t` valid shares
///   interpolate the same committed value, so the opened values are
///   unaffected. Openings riding in the same broadcast round (`δ, ε` and
///   `δ′, ε′`) share one expulsion step.
/// * P3 nonce points are checked individually (`R_j == EvalCom(A[k], j)`)
///   as in [`presign`]; bad `R_j` are filtered and blamed, and `R` is
///   interpolated over the subset `S` of valid senders with
///   `lagrange_coeffs(&S)` in the exponent (`|S| ≥ t` required, else
///   `Error::NotEnoughShares`).
/// * A blamed party is expelled from the instance: its later shares are
///   ignored and it receives no [`Presignature`] record.
///
/// Failures in the commit-reveal DEALING phases themselves still abort —
/// restarting those without the cheater is the separate §10.3 work item.
/// `v == 0` / `r == 0` handling is unchanged (`Error::ZeroValue`).
///
/// Returns the records of the non-blamed parties (`index` identifies the
/// party) and the accumulated blame list.
pub fn presign_robust(
    params: &Params,
    keys: &[KeyShare],
    id: u64,
    rngs: &mut [StdRng],
    tamper: Option<&PresignTamper>,
) -> Result<(Vec<Presignature>, Vec<PartyId>)> {
    presign_robust_with_committee(&Committee::full(params), keys, id, rngs, tamper)
}

/// [`presign_robust`] over an explicit committee (SPEC §10.3 restart).
/// `keys[k]`/`rngs[k]` belong to `committee.ids()[k]` (positionally;
/// `keys[k].index` is checked). Tamper hooks name ids.
pub fn presign_robust_with_committee(
    committee: &Committee,
    keys: &[KeyShare],
    id: u64,
    rngs: &mut [StdRng],
    tamper: Option<&PresignTamper>,
) -> Result<(Vec<Presignature>, Vec<PartyId>)> {
    check_committee_inputs(committee, keys, rngs)?;
    let t = committee.t();
    let sid = format!("ohm-ecdsa/presign/{id}").into_bytes();

    // Dealing phases stay fail-fast (see doc comment): two fresh triples
    // (SPEC §7) and the P1 ephemeral joint randomness [u] (:= k⁻¹), [a].
    let t_tamper = tamper.and_then(|tamp| tamp.triple_tamper);
    let t1 = triples::generate_with_committee(
        committee,
        &[sid.as_slice(), b"/t1"].concat(),
        rngs,
        t_tamper.as_ref(),
    )?;
    let t2 = triples::generate_with_committee(
        committee,
        &[sid.as_slice(), b"/t2"].concat(),
        rngs,
        None,
    )?;
    let pub1 = &t1[0].1;
    let pub2 = &t2[0].1;
    let u_out = triples::joint_random(
        committee,
        &[sid.as_slice(), b"/u"].concat(),
        rngs,
        Phase::Presign,
    )?;
    let a_out = triples::joint_random(
        committee,
        &[sid.as_slice(), b"/a"].concat(),
        rngs,
        Phase::Presign,
    )?;
    let u_shares: Vec<Scalar> = u_out.iter().map(|o| o.share).collect();
    let a_shares: Vec<Scalar> = a_out.iter().map(|o| o.share).collect();
    let u_com = u_out[0].com.clone();
    let a_com = a_out[0].com.clone();

    // §10.4 state: blame accumulates; the blamed are expelled from all
    // subsequent share sets.
    let mut blamed: Vec<PartyId> = Vec::new();
    let mut active: Vec<PartyId> = committee.ids().to_vec();

    // P2: open δ = u − α, ε = a − β (one broadcast round — the blame of
    // both openings is unioned), then form and open v = a·u via triple 1.
    let neg = -Scalar::ONE;
    let delta_com = u_com.add(&pub1.ca.scale(&neg));
    let eps_com = a_com.add(&pub1.cb.scale(&neg));
    let deltas = active_shares(committee, &active, |k| u_shares[k] - t1[k].0.a);
    let epsilons = active_shares(committee, &active, |k| a_shares[k] - t1[k].0.b);
    let (delta, b_d) = open_robust(t, &delta_com, &deltas, Phase::Presign)?;
    let (eps, b_e) = open_robust(t, &eps_com, &epsilons, Phase::Presign)?;
    expel(&mut blamed, &mut active, b_d);
    expel(&mut blamed, &mut active, b_e);

    let v_com = pub1
        .cc
        .clone()
        .add(&pub1.cb.scale(&delta))
        .add(&pub1.ca.scale(&eps))
        .add_const(&(delta * eps));
    let mut v_shares = active_shares(committee, &active, |k| {
        t1[k].0.c + delta * t1[k].0.b + eps * t1[k].0.a + delta * eps
    });
    if let Some(tamp) = tamper {
        if let Some(j) = tamp.bad_open_share {
            if let Some(s) = v_shares.get_mut(&j) {
                *s += Scalar::ONE; // malicious: wrong opening share
            }
        }
    }
    let (v, b_v) = open_robust(t, &v_com, &v_shares, Phase::Presign)?;
    expel(&mut blamed, &mut active, b_v);
    if v == Scalar::ZERO {
        return Err(Error::ZeroValue("v = 0".into())); // restart with fresh randomness
    }
    let v_inv =
        Option::<Scalar>::from(v.invert()).ok_or_else(|| Error::ZeroValue("v = 0".into()))?;

    // P3: [k] = v⁻¹·[a]; nonce points checked individually — bad R_j are
    // filtered and blamed, R is interpolated over the valid senders S.
    let k_com = a_com.scale(&v_inv);
    let mut valid_senders = Vec::new();
    let mut r_points = Vec::new();
    let mut bad_points = Vec::new();
    for &j in &active {
        let k = committee.position(j).expect("active ⊆ committee");
        let k_share = v_inv * a_shares[k];
        let mut r_j = ProjectivePoint::GENERATOR * k_share;
        if let Some(tamp) = tamper {
            if tamp.bad_nonce_point == Some(j) {
                r_j += ProjectivePoint::GENERATOR; // malicious: wrong point
            }
        }
        if r_j == k_com.eval_at(j) {
            valid_senders.push(j);
            r_points.push(r_j);
        } else {
            bad_points.push(j);
        }
    }
    expel(&mut blamed, &mut active, bad_points);
    if valid_senders.len() < t {
        return Err(Error::NotEnoughShares {
            got: valid_senders.len(),
            need: t,
        });
    }
    let lambdas = lagrange_coeffs(&valid_senders);
    let mut big_r_proj = ProjectivePoint::IDENTITY;
    for (l, rp) in lambdas.iter().zip(r_points.iter()) {
        big_r_proj += *rp * l;
    }
    let big_r = big_r_proj.to_affine();
    let r_encoded = big_r.to_encoded_point(false);
    let r_scalar = scalar_from_digest(r_encoded.x().expect("uncompressed point has x"));
    if r_scalar == Scalar::ZERO {
        return Err(Error::ZeroValue("r = 0".into()));
    }

    // P4: z = u·x via triple 2 (binds the presignature to the key).
    let d2_com = u_com.add(&pub2.ca.scale(&neg));
    let e2_com = keys[0].com.add(&pub2.cb.scale(&neg));
    let d2 = active_shares(committee, &active, |k| u_shares[k] - t2[k].0.a);
    let e2 = active_shares(committee, &active, |k| keys[k].share - t2[k].0.b);
    let (d2v, b_d2) = open_robust(t, &d2_com, &d2, Phase::Presign)?;
    let (e2v, b_e2) = open_robust(t, &e2_com, &e2, Phase::Presign)?;
    expel(&mut blamed, &mut active, b_d2);
    expel(&mut blamed, &mut active, b_e2);
    let z_com = pub2
        .cc
        .clone()
        .add(&pub2.cb.scale(&d2v))
        .add(&pub2.ca.scale(&e2v))
        .add_const(&(d2v * e2v));

    // Records only for the non-blamed survivors of the instance.
    let presigs = active
        .iter()
        .map(|&j| {
            let k = committee.position(j).expect("active ⊆ committee");
            Presignature {
                id,
                index: j,
                r: r_scalar,
                big_r,
                u_share: u_shares[k],
                z_share: t2[k].0.c + d2v * t2[k].0.b + e2v * t2[k].0.a + d2v * e2v,
                u_com: u_com.clone(),
                z_com: z_com.clone(),
            }
        })
        .collect();
    blamed.sort_unstable();
    Ok((presigs, blamed))
}

/// Run the presign protocol for a batch of presignature ids (SPEC §8.5).
///
/// One batch joint VSS (§7.3 machinery) covers all `u⁽¹..B⁾, a⁽¹..B⁾`;
/// the `2B` triples come from one [`triples::generate_batch`] session; and
/// the per-`b` Beaver openings (P2, P4) and nonce points `R_j⁽ᵇ⁾` (P3,
/// same `EvalCom(A[k], j)` point-equality check and blame) are grouped so
/// each logical broadcast round carries the whole batch.
///
/// Returns, per party, `B` presignatures in `ids` order. A zero `v` or `r`
/// at batch index `b` is `Error::ZeroValue` naming `b` (restart policy
/// stays with the caller, as in [`presign`]). `tamper` (tests) applies to
/// batch item 0.
pub fn presign_batch(
    params: &Params,
    keys: &[KeyShare],
    ids: &[u64],
    rngs: &mut [StdRng],
    tamper: Option<&PresignTamper>,
) -> Result<Vec<Vec<Presignature>>> {
    presign_batch_with_committee(&Committee::full(params), keys, ids, rngs, tamper)
}

/// [`presign_batch`] over an explicit committee (SPEC §10.3 restart).
/// `keys[k]`/`rngs[k]` belong to `committee.ids()[k]` (positionally;
/// `keys[k].index` is checked). Tamper hooks name party ids.
pub fn presign_batch_with_committee(
    committee: &Committee,
    keys: &[KeyShare],
    ids: &[u64],
    rngs: &mut [StdRng],
    tamper: Option<&PresignTamper>,
) -> Result<Vec<Vec<Presignature>>> {
    check_committee_inputs(committee, keys, rngs)?;
    let cids = committee.ids();
    let n = cids.len();
    let t = committee.t();
    let count = ids.len();
    if count == 0 {
        return Err(Error::InvalidParams("empty presignature batch"));
    }
    let mut sid = b"ohm-ecdsa/presign-batch".to_vec();
    for id in ids {
        sid.extend_from_slice(&id.to_be_bytes());
    }

    // 2B fresh triples from one batched session (SPEC §7.3): triples 2b
    // and 2b+1 serve as t1/t2 of item b.
    let triples = triples::generate_batch_with_committee(
        committee,
        &[sid.as_slice(), b"/triples"].concat(),
        2 * count,
        rngs,
    )?;

    // P1: one batch joint VSS for u⁽¹..B⁾ (indices 0..B) and a⁽¹..B⁾ (B..2B).
    let joint = triples::joint_random_batch(
        committee,
        &[sid.as_slice(), b"/ua"].concat(),
        rngs,
        Phase::Presign,
        2 * count,
    )?;
    let u_shares: Vec<Vec<Scalar>> = (0..n)
        .map(|k| (0..count).map(|b| joint[k][b].share).collect())
        .collect();
    let a_shares: Vec<Vec<Scalar>> = (0..n)
        .map(|k| (0..count).map(|b| joint[k][count + b].share).collect())
        .collect();
    let u_coms: Vec<FeldmanCommitment> = (0..count).map(|b| joint[0][b].com.clone()).collect();
    let a_coms: Vec<FeldmanCommitment> = (0..count)
        .map(|b| joint[0][count + b].com.clone())
        .collect();

    let neg = -Scalar::ONE;
    let lambdas = lagrange_coeffs(cids);

    // P2 (all Beaver openings ride in the same broadcast rounds): per b,
    // open δ = u − α, ε = a − β, then v = a·u via triple 2b.
    let mut v_invs = Vec::with_capacity(count);
    for b in 0..count {
        let pub1 = &triples[0][2 * b].1;
        let delta_com = u_coms[b].add(&pub1.ca.scale(&neg));
        let eps_com = a_coms[b].add(&pub1.cb.scale(&neg));
        let deltas: BTreeMap<PartyId, Scalar> = cids
            .iter()
            .enumerate()
            .map(|(k, &j)| (j, u_shares[k][b] - triples[k][2 * b].0.a))
            .collect();
        let epsilons: BTreeMap<PartyId, Scalar> = cids
            .iter()
            .enumerate()
            .map(|(k, &j)| (j, a_shares[k][b] - triples[k][2 * b].0.b))
            .collect();
        let delta = open(t, &delta_com, &deltas, Phase::Presign)?;
        let eps = open(t, &eps_com, &epsilons, Phase::Presign)?;

        let v_com = pub1
            .cc
            .clone()
            .add(&pub1.cb.scale(&delta))
            .add(&pub1.ca.scale(&eps))
            .add_const(&(delta * eps));
        let mut v_shares: BTreeMap<PartyId, Scalar> = cids
            .iter()
            .enumerate()
            .map(|(k, &j)| {
                (
                    j,
                    triples[k][2 * b].0.c
                        + delta * triples[k][2 * b].0.b
                        + eps * triples[k][2 * b].0.a
                        + delta * eps,
                )
            })
            .collect();
        if let Some(tamp) = tamper {
            if b == 0 {
                if let Some(j) = tamp.bad_open_share {
                    if let Some(s) = v_shares.get_mut(&j) {
                        *s += Scalar::ONE; // malicious: wrong opening share (batch item 0)
                    }
                }
            }
        }
        let v = open(t, &v_com, &v_shares, Phase::Presign)?;
        if v == Scalar::ZERO {
            return Err(Error::ZeroValue(format!("v = 0 at batch index {b}")));
        }
        v_invs.push(
            Option::<Scalar>::from(v.invert())
                .ok_or_else(|| Error::ZeroValue(format!("v = 0 at batch index {b}")))?,
        );
    }

    // P3 (all R_j⁽ᵇ⁾ ride in one round): [k] = v⁻¹·[a]; nonce points with
    // per-share point checks.
    let mut big_rs = Vec::with_capacity(count);
    let mut r_scalars = Vec::with_capacity(count);
    for b in 0..count {
        let k_com = a_coms[b].scale(&v_invs[b]);
        let mut r_points = Vec::with_capacity(n);
        for (k, a_shares_k) in a_shares.iter().enumerate() {
            let j = cids[k];
            let k_share = v_invs[b] * a_shares_k[b];
            let mut r_j = ProjectivePoint::GENERATOR * k_share;
            if let Some(tamp) = tamper {
                if b == 0 && tamp.bad_nonce_point == Some(j) {
                    r_j += ProjectivePoint::GENERATOR; // malicious: wrong point
                }
            }
            if r_j != k_com.eval_at(j) {
                return Err(Error::Abort {
                    abort: IdentifiableAbort {
                        phase: Phase::Presign,
                        blamed: vec![j],
                        detail: format!("invalid nonce point R_j (batch index {b})"),
                    },
                });
            }
            r_points.push(r_j);
        }
        let mut big_r_proj = ProjectivePoint::IDENTITY;
        for (l, rp) in lambdas.iter().zip(r_points.iter()) {
            big_r_proj += *rp * l;
        }
        let big_r = big_r_proj.to_affine();
        let r_encoded = big_r.to_encoded_point(false);
        let r_scalar = scalar_from_digest(r_encoded.x().expect("uncompressed point has x"));
        if r_scalar == Scalar::ZERO {
            return Err(Error::ZeroValue(format!("r = 0 at batch index {b}")));
        }
        big_rs.push(big_r);
        r_scalars.push(r_scalar);
    }

    // P4: z = u·x via triple 2b+1 (binds each record to the key).
    let mut z_coms = Vec::with_capacity(count);
    let mut d2e2 = Vec::with_capacity(count);
    for b in 0..count {
        let pub2 = &triples[0][2 * b + 1].1;
        let d2_com = u_coms[b].add(&pub2.ca.scale(&neg));
        let e2_com = keys[0].com.add(&pub2.cb.scale(&neg));
        let d2: BTreeMap<PartyId, Scalar> = cids
            .iter()
            .enumerate()
            .map(|(k, &j)| (j, u_shares[k][b] - triples[k][2 * b + 1].0.a))
            .collect();
        let e2: BTreeMap<PartyId, Scalar> = cids
            .iter()
            .enumerate()
            .map(|(k, &j)| (j, keys[k].share - triples[k][2 * b + 1].0.b))
            .collect();
        let d2v = open(t, &d2_com, &d2, Phase::Presign)?;
        let e2v = open(t, &e2_com, &e2, Phase::Presign)?;
        z_coms.push(
            pub2.cc
                .clone()
                .add(&pub2.cb.scale(&d2v))
                .add(&pub2.ca.scale(&e2v))
                .add_const(&(d2v * e2v)),
        );
        d2e2.push((d2v, e2v));
    }

    let presigs = (0..n)
        .map(|k| {
            let j = cids[k];
            (0..count)
                .map(|b| {
                    let t2 = &triples[k][2 * b + 1].0;
                    let (d2v, e2v) = d2e2[b];
                    Presignature {
                        id: ids[b],
                        index: j,
                        r: r_scalars[b],
                        big_r: big_rs[b],
                        u_share: u_shares[k][b],
                        z_share: t2.c + d2v * t2.b + e2v * t2.a + d2v * e2v,
                        u_com: u_coms[b].clone(),
                        z_com: z_coms[b].clone(),
                    }
                })
                .collect()
        })
        .collect();
    Ok(presigs)
}
