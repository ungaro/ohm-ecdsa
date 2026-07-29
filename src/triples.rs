//! Beaver triple factory (SPEC §7).
//!
//! 1. Jointly generate random `[α]`, `[β]` via commit-reveal VSS
//!    (all `n` parties deal; sum).
//! 2. Each party locally multiplies its shares `γ_j = α_j·β_j` (a share on
//!    the degree-`2t−2` product polynomial) and *re-shares* `γ_j` with a
//!    fresh degree-`t−1` polynomial, proving with a DLEQ product proof that
//!    the reshared constant equals `α_j·β_j` w.r.t. the public commitments.
//! 3. `[γ] = Σ_j λ_j·[g_j]` (Lagrange-weighted, GJKR96-style degree
//!    reduction). Correct because `n ≥ 2t−1` points interpolate the
//!    degree-`2t−2` product polynomial at 0: `Σ λ_j·α_j·β_j = α·β`.
//!
//! [`generate_robust`] is the §10.4 blame-and-continue variant: a bad
//! re-shared share does not abort — the honest majority publicly
//! reconstructs the cheater's committed re-sharing polynomial.
//!
//! All entry points have `*_with_committee` variants that run over an
//! explicit party-id set (the surviving original ids of a §10.3 restart)
//! instead of the default `1..=n`.

use std::collections::BTreeMap;

use k256::{ProjectivePoint, Scalar};
use rand::rngs::StdRng;
use zeroize::Zeroize;

use crate::dkg::{resolve_complaint, DkgBatchInstance, DkgInstance, DkgOutput};
use crate::shamir::{interpolate_at, lagrange_coeffs, ShamirPoly};
use crate::vss::FeldmanCommitment;
use crate::{dleq, tags, Committee, Error, IdentifiableAbort, Params, PartyId, Phase, Result};

/// One party's share of a Beaver triple `(α, β, γ = αβ)`.
#[derive(Clone, Debug)]
pub struct TripleShare {
    pub index: PartyId,
    pub a: Scalar,
    pub b: Scalar,
    pub c: Scalar,
}

impl Drop for TripleShare {
    fn drop(&mut self) {
        // Compiler-fenced erasure via `zeroize` (k256's `Scalar` implements
        // `DefaultIsZeroes`, so `zeroize()` is a volatile write, not an
        // elidable plain store). See SPEC §13.3.
        self.a.zeroize();
        self.b.zeroize();
        self.c.zeroize();
    }
}

/// Public commitments to a triple's three sharing polynomials.
#[derive(Clone, Debug)]
pub struct TriplePublic {
    pub ca: FeldmanCommitment,
    pub cb: FeldmanCommitment,
    pub cc: FeldmanCommitment,
}

/// Joint random sharing via commit-reveal VSS over the committee.
/// `rngs[i]` belongs to `committee.ids()[i]` (positional). Returns the
/// per-party outputs in committee order.
pub(crate) fn joint_random(
    committee: &Committee,
    sid: &[u8],
    rngs: &mut [StdRng],
    phase: Phase,
) -> Result<Vec<DkgOutput>> {
    let mut r1 = BTreeMap::new();
    let mut insts = Vec::new();
    for (k, &i) in committee.ids().iter().enumerate() {
        let (inst, b1) =
            DkgInstance::start_committee(committee, sid, tags::DKG_COMMIT, i, &mut rngs[k]);
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
    let mut outs = Vec::with_capacity(committee.n());
    for inst in &insts {
        let me = inst.me;
        let mine: BTreeMap<PartyId, Scalar> = p2p
            .iter()
            .filter(|m| m.to == me)
            .map(|m| (m.from, m.share))
            .collect();
        let defenses: BTreeMap<PartyId, Scalar> =
            insts.iter().map(|d| (d.me, d.defend(me))).collect();
        outs.push(inst.finalize(phase, &r1, &r2, &mine, &defenses)?);
    }
    Ok(outs)
}

/// Batch joint random sharing via ONE commit-reveal VSS session covering
/// `count` secrets (SPEC §7.3). `rngs[i]` belongs to `committee.ids()[i]`.
/// Returns, per party (committee order), `count` outputs in index order.
pub(crate) fn joint_random_batch(
    committee: &Committee,
    sid: &[u8],
    rngs: &mut [StdRng],
    phase: Phase,
    count: usize,
) -> Result<Vec<Vec<DkgOutput>>> {
    let mut r1 = BTreeMap::new();
    let mut insts = Vec::new();
    for (k, &i) in committee.ids().iter().enumerate() {
        let (inst, b1) = DkgBatchInstance::start_committee(
            committee,
            sid,
            tags::DKG_BATCH_COMMIT,
            i,
            count,
            &mut rngs[k],
        );
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
    let mut outs = Vec::with_capacity(committee.n());
    for inst in &insts {
        let me = inst.me;
        let mine: BTreeMap<PartyId, Vec<Scalar>> = p2p
            .iter()
            .filter(|m| m.to == me)
            .map(|m| (m.from, m.shares.clone()))
            .collect();
        let defenses: BTreeMap<PartyId, Vec<Scalar>> =
            insts.iter().map(|d| (d.me, d.defend(me))).collect();
        outs.push(inst.finalize(phase, &r1, &r2, &mine, &defenses)?);
    }
    Ok(outs)
}

/// Fault-injection hooks for the triple factory (tests only).
#[derive(Debug, Default, Clone, Copy)]
pub struct TripleTamper {
    /// This party deals a wrong re-shared share to this victim in T2; the
    /// §6.1 defense does not verify, so the dealer is blamed.
    pub bad_reshare: Option<(PartyId, PartyId)>,
    /// This party broadcasts an invalid DLEQ product proof in T2 (F3); the
    /// prover is blamed.
    pub bad_product_proof: Option<PartyId>,
}

/// Generate one Beaver triple shared across the `1..=n` committee.
pub fn generate(
    params: &Params,
    sid: &[u8],
    rngs: &mut [StdRng],
) -> Result<Vec<(TripleShare, TriplePublic)>> {
    generate_with_tamper(params, sid, rngs, None)
}

/// [`generate`] with fault-injection hooks (tests).
pub fn generate_with_tamper(
    params: &Params,
    sid: &[u8],
    rngs: &mut [StdRng],
    tamper: Option<&TripleTamper>,
) -> Result<Vec<(TripleShare, TriplePublic)>> {
    generate_with_committee(&Committee::full(params), sid, rngs, tamper)
}

/// [`generate`] over an explicit committee (SPEC §10.3 restart): shares
/// are dealt and Lagrange-combined at the committee's original ids.
/// `rngs[i]` belongs to `committee.ids()[i]`; tamper hooks name ids.
pub fn generate_with_committee(
    committee: &Committee,
    sid: &[u8],
    rngs: &mut [StdRng],
    tamper: Option<&TripleTamper>,
) -> Result<Vec<(TripleShare, TriplePublic)>> {
    let ids = committee.ids();
    let n = ids.len();
    let t = committee.t();

    // T1: joint random [α], [β]
    let a_out = joint_random(committee, &[sid, b"/alpha"].concat(), rngs, Phase::Triples)?;
    let b_out = joint_random(committee, &[sid, b"/beta"].concat(), rngs, Phase::Triples)?;
    let a_shares: Vec<Scalar> = a_out.iter().map(|o| o.share).collect();
    let b_shares: Vec<Scalar> = b_out.iter().map(|o| o.share).collect();
    let ca = a_out[0].com.clone();
    let cb = b_out[0].com.clone();

    let lambdas = lagrange_coeffs(ids);

    // T2: reshare the local products with product proofs
    let mut resh_coms: Vec<FeldmanCommitment> = Vec::with_capacity(n);
    let mut resh_shares: Vec<Vec<Scalar>> = Vec::with_capacity(n); // [dealer pos][receiver pos]
    let mut proofs = Vec::with_capacity(n);
    for (k, &j) in ids.iter().enumerate() {
        let gamma_j = a_shares[k] * b_shares[k];
        let g = ShamirPoly::random(gamma_j, t, &mut rngs[k]);
        let c_j = FeldmanCommitment::from_poly(&g);
        let base_b = cb.eval_at(j); // β_j·G
        let (x1, x2, proof) = dleq::prove(
            sid,
            tags::TRIPLE_PRODUCT,
            &a_shares[k],
            &ProjectivePoint::GENERATOR,
            &base_b,
            &mut rngs[k],
        );
        resh_coms.push(c_j);
        proofs.push((x1, x2, proof));
        resh_shares.push(ids.iter().map(|&i| g.eval(i)).collect());
    }

    // Fault injection (tests).
    if let Some(tamp) = tamper {
        if let Some((dealer, victim)) = tamp.bad_reshare {
            if let (Some(d), Some(v)) = (committee.position(dealer), committee.position(victim)) {
                resh_shares[d][v] += Scalar::ONE; // cheating dealer, T2
            }
        }
        if let Some(j) = tamp.bad_product_proof {
            if let Some(p) = committee.position(j) {
                proofs[p].2.z += Scalar::ONE; // invalid DLEQ proof (F3)
            }
        }
    }

    // T3: verify proofs and reshares; combine with Lagrange weights
    let mut cc: Option<FeldmanCommitment> = None;
    for (k, &j) in ids.iter().enumerate() {
        let base_a = ca.eval_at(j); // α_j·G
        let base_b = cb.eval_at(j); // β_j·G
        let (x1, x2, proof) = &proofs[k];
        let c_j = &resh_coms[k];
        if *x1 != base_a
            || *x2 != c_j.points[0]
            || !dleq::verify(
                sid,
                tags::TRIPLE_PRODUCT,
                &ProjectivePoint::GENERATOR,
                x1,
                &base_b,
                x2,
                proof,
            )
        {
            // F3: invalid DLEQ product proof — the prover is blamed.
            return Err(Error::Abort {
                abort: IdentifiableAbort {
                    phase: Phase::Triples,
                    blamed: vec![j],
                    detail: "invalid DLEQ product proof".into(),
                },
            });
        }
        for (v, &s) in resh_shares[k].iter().enumerate() {
            let i = ids[v];
            if !c_j.verify_share(i, &s) {
                // §6.1 complaint on the re-shared share (F2): the dealer's
                // defense is the share it computed. The sim delivers
                // dealer-computed shares directly, so a failure here means
                // the dealer dealt bad.
                return Err(resolve_complaint(
                    Phase::Triples,
                    c_j,
                    j,
                    i,
                    &resh_shares[k][v],
                ));
            }
        }
        let scaled = c_j.scale(&lambdas[k]);
        cc = Some(match cc {
            None => scaled,
            Some(acc) => acc.add(&scaled),
        });
    }
    let cc = cc.expect("n >= 1");
    let public = TriplePublic { ca, cb, cc };

    let out = (0..n)
        .map(|k| {
            let i = ids[k];
            let c_share = (0..n)
                .map(|d| lambdas[d] * resh_shares[d][k])
                .fold(Scalar::ZERO, |acc, x| acc + x);
            (
                TripleShare {
                    index: i,
                    a: a_shares[k],
                    b: b_shares[k],
                    c: c_share,
                },
                public.clone(),
            )
        })
        .collect();
    Ok(out)
}

/// Robust variant of [`generate`] (SPEC §10.4): a T3 share-check failure
/// does not abort the instance.
///
/// Excluding the dealer can NEVER work here: `γ = Σ_j λ_j·g_j(0)` needs
/// `2t−1` correct product points on the degree-`2t−2` product polynomial,
/// and `n − f` can be as low as `t`. Continuation therefore means
/// *publicly reconstructing the cheater's committed re-sharing
/// polynomial* — `C_j` binds everyone to the same polynomial and the
/// `≥ t` valid shares honest parties received suffice to interpolate it
/// (the sim sees every P2P message; this models the §10.4 reconstruction
/// round where honest parties broadcast their valid received shares). The
/// contaminated `g_j(i)` are recomputed, the dealer is blamed and
/// expelled (no output record), and its `C_j` still enters `A[γ]` — the
/// DLEQ proof already bound `g_j(0) = α_j·β_j`.
///
/// A bad DLEQ product proof (F3) still aborts blaming the prover: the
/// dealer's `C_j` commits to a wrong product, so reconstruction would
/// recover a wrong-but-committed polynomial and continuation is
/// impossible. Returns the triple shares of the non-blamed parties and
/// the accumulated blame list.
#[allow(clippy::type_complexity)] // (records, blame) mirrors the other robust APIs
pub fn generate_robust(
    params: &Params,
    sid: &[u8],
    rngs: &mut [StdRng],
    tamper: Option<&TripleTamper>,
) -> Result<(Vec<(TripleShare, TriplePublic)>, Vec<PartyId>)> {
    generate_robust_with_committee(&Committee::full(params), sid, rngs, tamper)
}

/// [`generate_robust`] over an explicit committee (SPEC §10.3 restart).
/// `rngs[i]` belongs to `committee.ids()[i]`; tamper hooks name ids.
#[allow(clippy::type_complexity)] // (records, blame) mirrors the other robust APIs
pub fn generate_robust_with_committee(
    committee: &Committee,
    sid: &[u8],
    rngs: &mut [StdRng],
    tamper: Option<&TripleTamper>,
) -> Result<(Vec<(TripleShare, TriplePublic)>, Vec<PartyId>)> {
    let ids = committee.ids();
    let n = ids.len();
    let t = committee.t();

    // T1: joint random [α], [β] (the dealing phase stays fail-fast —
    // restarting it without a cheater is the separate §10.3 work item).
    let a_out = joint_random(committee, &[sid, b"/alpha"].concat(), rngs, Phase::Triples)?;
    let b_out = joint_random(committee, &[sid, b"/beta"].concat(), rngs, Phase::Triples)?;
    let a_shares: Vec<Scalar> = a_out.iter().map(|o| o.share).collect();
    let b_shares: Vec<Scalar> = b_out.iter().map(|o| o.share).collect();
    let ca = a_out[0].com.clone();
    let cb = b_out[0].com.clone();

    let lambdas = lagrange_coeffs(ids);

    // T2: reshare the local products with product proofs
    let mut resh_coms: Vec<FeldmanCommitment> = Vec::with_capacity(n);
    let mut resh_shares: Vec<Vec<Scalar>> = Vec::with_capacity(n); // [dealer pos][receiver pos]
    let mut proofs = Vec::with_capacity(n);
    for (k, &j) in ids.iter().enumerate() {
        let gamma_j = a_shares[k] * b_shares[k];
        let g = ShamirPoly::random(gamma_j, t, &mut rngs[k]);
        let c_j = FeldmanCommitment::from_poly(&g);
        let base_b = cb.eval_at(j); // β_j·G
        let (x1, x2, proof) = dleq::prove(
            sid,
            tags::TRIPLE_PRODUCT,
            &a_shares[k],
            &ProjectivePoint::GENERATOR,
            &base_b,
            &mut rngs[k],
        );
        resh_coms.push(c_j);
        proofs.push((x1, x2, proof));
        resh_shares.push(ids.iter().map(|&i| g.eval(i)).collect());
    }

    // Fault injection (tests).
    if let Some(tamp) = tamper {
        if let Some((dealer, victim)) = tamp.bad_reshare {
            if let (Some(d), Some(v)) = (committee.position(dealer), committee.position(victim)) {
                resh_shares[d][v] += Scalar::ONE; // cheating dealer, T2
            }
        }
        if let Some(j) = tamp.bad_product_proof {
            if let Some(p) = committee.position(j) {
                proofs[p].2.z += Scalar::ONE; // invalid DLEQ proof (F3)
            }
        }
    }

    // T3: verify proofs (fail-fast); on share failures, reconstruct g_j
    // from the ≥ t valid shares and continue (§10.4).
    let mut blamed: Vec<PartyId> = Vec::new();
    let mut cc: Option<FeldmanCommitment> = None;
    for (k, &j) in ids.iter().enumerate() {
        let base_a = ca.eval_at(j); // α_j·G
        let base_b = cb.eval_at(j); // β_j·G
        let (x1, x2, proof) = &proofs[k];
        let c_j = &resh_coms[k];
        if *x1 != base_a
            || *x2 != c_j.points[0]
            || !dleq::verify(
                sid,
                tags::TRIPLE_PRODUCT,
                &ProjectivePoint::GENERATOR,
                x1,
                &base_b,
                x2,
                proof,
            )
        {
            // F3: invalid DLEQ product proof — the prover is blamed and
            // the instance aborts (continuation impossible, see above).
            return Err(Error::Abort {
                abort: IdentifiableAbort {
                    phase: Phase::Triples,
                    blamed: vec![j],
                    detail: "invalid DLEQ product proof".into(),
                },
            });
        }
        let mut valid_parties = Vec::new();
        let mut valid_shares = Vec::new();
        let mut victims = Vec::new();
        for (v, &s) in resh_shares[k].iter().enumerate() {
            let i = ids[v];
            if c_j.verify_share(i, &s) {
                valid_parties.push(i);
                valid_shares.push(s);
            } else {
                victims.push(i);
            }
        }
        if !victims.is_empty() {
            // The dealer's re-share failed verification against its own
            // commitment — the dealer is blamed (as in the §6.1 complaint
            // logic, where the defense share is the dealt value).
            if valid_parties.len() < t {
                // The dealer validly shared with fewer than t parties:
                // the committed polynomial is unrecoverable, continuation
                // impossible (restarting without the dealer is the
                // separate §10.3 work item).
                return Err(Error::Abort {
                    abort: IdentifiableAbort {
                        phase: Phase::Triples,
                        blamed: vec![j],
                        detail: "fewer than t valid re-shared shares; committed \
                                 re-sharing polynomial unrecoverable"
                            .into(),
                    },
                });
            }
            valid_parties.truncate(t);
            valid_shares.truncate(t);
            for &i in &victims {
                // Recompute the contaminated g_j(i) from the valid shares.
                let v = committee.position(i).expect("victim is a member");
                resh_shares[k][v] =
                    interpolate_at(&Scalar::from(i as u64), &valid_parties, &valid_shares);
            }
            blamed.push(j);
        }
        let scaled = c_j.scale(&lambdas[k]);
        cc = Some(match cc {
            None => scaled,
            Some(acc) => acc.add(&scaled),
        });
    }
    let cc = cc.expect("n >= 1");
    let public = TriplePublic { ca, cb, cc };

    let out = (0..n)
        .filter(|&k| !blamed.contains(&ids[k]))
        .map(|k| {
            let i = ids[k];
            let c_share = (0..n)
                .map(|d| lambdas[d] * resh_shares[d][k])
                .fold(Scalar::ZERO, |acc, x| acc + x);
            (
                TripleShare {
                    index: i,
                    a: a_shares[k],
                    b: b_shares[k],
                    c: c_share,
                },
                public.clone(),
            )
        })
        .collect();
    Ok((out, blamed))
}

/// Generate `count` Beaver triples in one batched session (SPEC §7.3).
///
/// The batch structure is per-batch, not per-value: one commit-reveal
/// session deals all `2·count` secrets (`α⁽¹..B⁾` at indices `0..B`,
/// `β⁽¹..B⁾` at indices `B..2B`), and the re-sharing pass carries all `B`
/// Feldman vectors plus `B` DLEQ product proofs per party — broadcast
/// rounds stay 3 per batch, independent of `B` (wire-level chunking is a
/// transport concern).
///
/// Returns, per party, `count` triples in index order.
pub fn generate_batch(
    params: &Params,
    sid: &[u8],
    count: usize,
    rngs: &mut [StdRng],
) -> Result<Vec<Vec<(TripleShare, TriplePublic)>>> {
    generate_batch_with_committee(&Committee::full(params), sid, count, rngs)
}

/// [`generate_batch`] over an explicit committee (SPEC §10.3 restart).
/// `rngs[i]` belongs to `committee.ids()[i]`.
pub fn generate_batch_with_committee(
    committee: &Committee,
    sid: &[u8],
    count: usize,
    rngs: &mut [StdRng],
) -> Result<Vec<Vec<(TripleShare, TriplePublic)>>> {
    let ids = committee.ids();
    let n = ids.len();
    let t = committee.t();

    // T1: one commit-reveal session for all 2B secrets.
    let joint = joint_random_batch(committee, sid, rngs, Phase::Triples, 2 * count)?;
    let a_shares: Vec<Vec<Scalar>> = (0..n)
        .map(|k| (0..count).map(|b| joint[k][b].share).collect())
        .collect();
    let b_shares: Vec<Vec<Scalar>> = (0..n)
        .map(|k| (0..count).map(|b| joint[k][count + b].share).collect())
        .collect();
    let cas: Vec<FeldmanCommitment> = (0..count).map(|b| joint[0][b].com.clone()).collect();
    let cbs: Vec<FeldmanCommitment> = (0..count)
        .map(|b| joint[0][count + b].com.clone())
        .collect();

    let lambdas = lagrange_coeffs(ids);

    // T2: reshare the local products — one message per party carrying all
    // B re-sharing vectors and all B product proofs.
    let mut resh_coms: Vec<Vec<FeldmanCommitment>> = Vec::with_capacity(n); // [dealer pos][b]
    let mut resh_shares: Vec<Vec<Vec<Scalar>>> = Vec::with_capacity(n); // [dealer pos][b][receiver pos]
    let mut proofs: Vec<Vec<(ProjectivePoint, ProjectivePoint, dleq::DleqProof)>> =
        Vec::with_capacity(n); // [dealer pos][b]
    for (k, &j) in ids.iter().enumerate() {
        let mut d_coms = Vec::with_capacity(count);
        let mut d_shares = Vec::with_capacity(count);
        let mut d_proofs = Vec::with_capacity(count);
        for b in 0..count {
            let gamma_j = a_shares[k][b] * b_shares[k][b];
            let g = ShamirPoly::random(gamma_j, t, &mut rngs[k]);
            let c_j = FeldmanCommitment::from_poly(&g);
            let base_b = cbs[b].eval_at(j); // β_j⁽ᵇ⁾·G
            let (x1, x2, proof) = dleq::prove(
                sid,
                tags::TRIPLE_PRODUCT,
                &a_shares[k][b],
                &ProjectivePoint::GENERATOR,
                &base_b,
                &mut rngs[k],
            );
            d_coms.push(c_j);
            d_proofs.push((x1, x2, proof));
            d_shares.push(ids.iter().map(|&i| g.eval(i)).collect::<Vec<Scalar>>());
        }
        resh_coms.push(d_coms);
        proofs.push(d_proofs);
        resh_shares.push(d_shares);
    }

    // T3: verify all proofs and re-shared shares; Lagrange-combine per b.
    let mut ccs: Vec<Option<FeldmanCommitment>> = (0..count).map(|_| None).collect();
    for (k, &j) in ids.iter().enumerate() {
        for b in 0..count {
            let base_a = cas[b].eval_at(j); // α_j⁽ᵇ⁾·G
            let base_b = cbs[b].eval_at(j); // β_j⁽ᵇ⁾·G
            let (x1, x2, proof) = &proofs[k][b];
            let c_j = &resh_coms[k][b];
            if *x1 != base_a
                || *x2 != c_j.points[0]
                || !dleq::verify(
                    sid,
                    tags::TRIPLE_PRODUCT,
                    &ProjectivePoint::GENERATOR,
                    x1,
                    &base_b,
                    x2,
                    proof,
                )
            {
                // F3: invalid DLEQ product proof — the prover is blamed.
                return Err(Error::Abort {
                    abort: IdentifiableAbort {
                        phase: Phase::Triples,
                        blamed: vec![j],
                        detail: format!("invalid DLEQ product proof (batch index {b})"),
                    },
                });
            }
            for (v, &s) in resh_shares[k][b].iter().enumerate() {
                let i = ids[v];
                if !c_j.verify_share(i, &s) {
                    // §6.1 complaint on the re-shared share (F2), as in
                    // `generate_with_committee`.
                    return Err(resolve_complaint(
                        Phase::Triples,
                        c_j,
                        j,
                        i,
                        &resh_shares[k][b][v],
                    ));
                }
            }
            let scaled = c_j.scale(&lambdas[k]);
            ccs[b] = Some(match ccs[b].take() {
                None => scaled,
                Some(acc) => acc.add(&scaled),
            });
        }
    }
    let publics: Vec<TriplePublic> = (0..count)
        .map(|b| TriplePublic {
            ca: cas[b].clone(),
            cb: cbs[b].clone(),
            cc: ccs[b].clone().expect("n >= 1"),
        })
        .collect();

    let out = (0..n)
        .map(|k| {
            let i = ids[k];
            (0..count)
                .map(|b| {
                    let c_share = (0..n)
                        .map(|d| lambdas[d] * resh_shares[d][b][k])
                        .fold(Scalar::ZERO, |acc, x| acc + x);
                    (
                        TripleShare {
                            index: i,
                            a: a_shares[k][b],
                            b: b_shares[k][b],
                            c: c_share,
                        },
                        publics[b].clone(),
                    )
                })
                .collect()
        })
        .collect();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::open::open;
    use crate::Phase;
    use rand::SeedableRng;

    #[test]
    fn triple_is_multiplicative() {
        let params = Params::new(3, 2).unwrap();
        let mut rngs: Vec<StdRng> = (0..3)
            .map(|i| StdRng::seed_from_u64(300 + i as u64))
            .collect();
        let triple = generate(&params, b"triple-test", &mut rngs).unwrap();
        let pubc = &triple[0].1;
        let open_of = |pick: fn(&TripleShare) -> Scalar, com: &FeldmanCommitment| {
            let shares: BTreeMap<PartyId, Scalar> =
                triple.iter().map(|(s, _)| (s.index, pick(s))).collect();
            open(params.t, com, &shares, Phase::Triples).unwrap()
        };
        let a = open_of(|s| s.a, &pubc.ca);
        let b = open_of(|s| s.b, &pubc.cb);
        let c = open_of(|s| s.c, &pubc.cc);
        assert_eq!(c, a * b);
    }
}
