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
//! [`generate_packed`] is the Franklin–Yung packed variant (SPEC §7.4.2,
//! Protocol 7.2′): `B` triples travel in ONE pair of degree-`d` packed
//! sharings (`d = t + B − 2`, slot points `e_b = -(b)`), each party
//! re-shares its ONE local product with a constant-pack polynomial (the
//! product value at every slot, bound by public slot-point `EvalCom`
//! checks) with ONE DLEQ proof per party, and slot recombination yields
//! constant-pack `⟦γ_b⟧` outputs. It needs the FY constraint
//! `n ≥ 2t + 2B − 3` (§7.4.1) and outputs degree-`d` sharings (online
//! quorum `t + B − 1`, §7.4.3).
//!
//! All entry points have `*_with_committee` variants that run over an
//! explicit party-id set (the surviving original ids of a §10.3 restart)
//! instead of the default `1..=n`.

use std::collections::BTreeMap;

use k256::{ProjectivePoint, Scalar};
use rand::rngs::StdRng;
use zeroize::Zeroize;

use crate::dkg::{resolve_complaint, DkgBatchBcast2, DkgBatchInstance, DkgInstance, DkgOutput};
use crate::shamir::{interpolate_at, lagrange_coeffs, lagrange_coeffs_at, slot_point, ShamirPoly};
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

/// Joint dealing of EXPLICIT per-party polynomials in ONE commit-reveal
/// session (SPEC §7.4: packed dealing, where a dealt polynomial's slot
/// values may be constrained — e.g. the §7.4.3 P4 constant-pack key
/// re-sharing). `polys[k]` is the vector dealt by `committee.ids()[k]`;
/// every dealer deals the same number of polynomials of one uniform
/// degree. Returns, per party (committee order), the per-index outputs,
/// plus the revealed per-dealer commitment vectors (callers performing
/// public slot-binding checks need them).
#[allow(clippy::type_complexity)] // (outputs, revealed commitments) — the dealing session's two artifacts
pub(crate) fn joint_deal(
    committee: &Committee,
    sid: &[u8],
    phase: Phase,
    polys: Vec<Vec<ShamirPoly>>,
) -> Result<(Vec<Vec<DkgOutput>>, BTreeMap<PartyId, DkgBatchBcast2>)> {
    debug_assert_eq!(polys.len(), committee.n());
    let mut r1 = BTreeMap::new();
    let mut insts = Vec::new();
    for (&i, dealer_polys) in committee.ids().iter().zip(polys) {
        let (inst, b1) = DkgBatchInstance::start_with_polys(
            committee,
            sid,
            tags::DKG_PACKED_COMMIT,
            i,
            dealer_polys,
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
    Ok((outs, r2))
}

/// Packed joint random sharing (SPEC §7.4.2 PT1): ONE commit-reveal
/// session dealing `count` uniform random degree-`degree` polynomials —
/// packed sharings whose slot values are whatever the polynomials
/// evaluate to at the slot points. `rngs[i]` belongs to
/// `committee.ids()[i]`. Returns, per party (committee order), `count`
/// outputs in index order.
pub(crate) fn joint_random_packed(
    committee: &Committee,
    sid: &[u8],
    rngs: &mut [StdRng],
    phase: Phase,
    count: usize,
    degree: usize,
) -> Result<Vec<Vec<DkgOutput>>> {
    let mut r1 = BTreeMap::new();
    let mut insts = Vec::new();
    for (k, &i) in committee.ids().iter().enumerate() {
        let (inst, b1) = DkgBatchInstance::start_committee_with_degree(
            committee,
            sid,
            tags::DKG_PACKED_COMMIT,
            i,
            count,
            degree,
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
    /// Batch sessions only ([`generate_batch_with_tamper`]): this party
    /// broadcasts an invalid DLEQ product proof at the given batch index
    /// in T2 (F3); the prover is blamed with per-triple attribution after
    /// the aggregate-verification fallback.
    pub bad_product_proof_at: Option<(PartyId, usize)>,
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
    generate_batch_with_tamper(params, sid, count, rngs, None)
}

/// [`generate_batch`] with fault-injection hooks (tests).
pub fn generate_batch_with_tamper(
    params: &Params,
    sid: &[u8],
    count: usize,
    rngs: &mut [StdRng],
    tamper: Option<&TripleTamper>,
) -> Result<Vec<Vec<(TripleShare, TriplePublic)>>> {
    generate_batch_with_committee(&Committee::full(params), sid, count, rngs, tamper)
}

/// [`generate_batch`] over an explicit committee (SPEC §10.3 restart).
/// `rngs[i]` belongs to `committee.ids()[i]`; tamper hooks name ids.
pub fn generate_batch_with_committee(
    committee: &Committee,
    sid: &[u8],
    count: usize,
    rngs: &mut [StdRng],
    tamper: Option<&TripleTamper>,
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

    // Fault injection (tests).
    if let Some(tamp) = tamper {
        if let Some((j, idx)) = tamp.bad_product_proof_at {
            if let Some(p) = committee.position(j) {
                if let Some(proof) = proofs[p].get_mut(idx) {
                    proof.2.z += Scalar::ONE; // invalid DLEQ proof (F3)
                }
            }
        }
    }

    // T3: verify all proofs and re-shared shares; Lagrange-combine per b.
    let mut ccs: Vec<Option<FeldmanCommitment>> = (0..count).map(|_| None).collect();
    for (k, &j) in ids.iter().enumerate() {
        // SPEC §7.3 "batch proof verification" (fast path): all B product
        // proofs of this prover are checked with ONE aggregate
        // verification — two multi-scalar multiplications instead of 2B
        // individual ones. The aggregate accepts an all-valid batch iff
        // per-proof `dleq::verify` would, so the accept/reject decision is
        // unchanged. On aggregate failure the per-b loop re-verifies each
        // proof individually, blaming the exact failing proof (per-triple
        // blame, F3).
        let statements: Vec<(
            ProjectivePoint,
            ProjectivePoint,
            ProjectivePoint,
            ProjectivePoint,
        )> = (0..count)
            .map(|b| {
                let (x1, x2, _) = &proofs[k][b];
                (
                    ProjectivePoint::GENERATOR,
                    *x1,
                    cbs[b].eval_at(j), // β_j⁽ᵇ⁾·G
                    *x2,
                )
            })
            .collect();
        let pfs: Vec<&dleq::DleqProof> = proofs[k].iter().map(|(_, _, p)| p).collect();
        let aggregate_ok = dleq::verify_batch(sid, tags::TRIPLE_PRODUCT, j, &statements, &pfs);
        for b in 0..count {
            let base_a = cas[b].eval_at(j); // α_j⁽ᵇ⁾·G
            let (x1, x2, proof) = &proofs[k][b];
            let c_j = &resh_coms[k][b];
            let proof_ok = aggregate_ok || {
                // Fallback after aggregate failure: individual
                // verification for per-triple blame attribution.
                let base_b = cbs[b].eval_at(j); // β_j⁽ᵇ⁾·G
                dleq::verify(
                    sid,
                    tags::TRIPLE_PRODUCT,
                    &ProjectivePoint::GENERATOR,
                    x1,
                    &base_b,
                    x2,
                    proof,
                )
            };
            if *x1 != base_a || *x2 != c_j.points[0] || !proof_ok {
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

/// Generate `b_pack` Beaver triples in ONE packed session (SPEC §7.4.2,
/// Protocol 7.2′ — PackedTriple).
///
/// * PT1: one commit-reveal session deals TWO degree-`d` packed sharings
///   `⟦α⟧_pack`, `⟦β⟧_pack` (`d = t + B − 2`; the dealer's hash covers
///   both commitment vectors).
/// * PT2: each party computes ONE local product `h_j = α_j·β_j` (a point
///   of the degree-`2d` product polynomial), re-shares it with ONE fresh
///   degree-`d` CONSTANT-PACK polynomial `g_j` — `g_j(e_b) = h_j` at every
///   slot (and `g_j(0) = h_j`, since `e_0 = 0`) — and broadcasts
///   `FeldCommit(g_j)` plus ONE DLEQ product proof binding `g_j(0)` to
///   `α_j·β_j` (`n` proofs total, not `B·n`). The constant-pack form is
///   what lets the PT3 recombination below serve every slot: any linear
///   combination of constant-packs is constant on the slots.
/// * PT3: proofs and re-shared shares are verified exactly as in
///   [`generate_with_committee`] (F2 complaints, F3 proof aborts), plus a
///   SLOT-BINDING check per dealer — `EvalCom(C_j, e_b) == C_j.points[0]`
///   for every slot `b` (the DLEQ proof binds point 0 only; this pure
///   point-equality check binds the remaining slots and blames the
///   dealer). Slot `b`'s triple is then recombined with the slot Lagrange
///   weights `λ_j^{(b)}` interpolating the product polynomial at
///   `e_b = -(b)` over all `n` party points — correct because
///   `n ≥ 2d + 1`. The output `⟦γ_b⟧` is itself a constant-pack: the
///   value `γ_b = α_b·β_b` sits at EVERY slot point (including 0), so
///   downstream packed Beaver combinations open consistently at `e_b`.
///
/// The committee must satisfy the FY multiplication constraint
/// `n ≥ 2t + 2B − 3` (SPEC §7.4.1); violations are `Error::InvalidParams`.
///
/// Returns, per party (committee order), `b_pack` triples in slot order.
/// Per the crate convention a [`TripleShare`] holds the party's SHARE —
/// the packed polynomials' evaluations at the party's point, so `a`/`b`
/// are the same scalar for every slot and the slot values `α_b`, `β_b`
/// are recoverable only by interpolation at `slot_point(b)`. Outputs are
/// DEGREE-`d` sharings: downstream openings and online signing need
/// quorum `d + 1 = t + B − 1` and interpolate at the slot point (SPEC
/// §7.4.3 — the online-quorum trade-off; privacy is unchanged at `t − 1`).
pub fn generate_packed(
    params: &Params,
    sid: &[u8],
    b_pack: usize,
    rngs: &mut [StdRng],
    tamper: Option<&TripleTamper>,
) -> Result<Vec<Vec<(TripleShare, TriplePublic)>>> {
    generate_packed_with_committee(&Committee::full(params), sid, b_pack, rngs, tamper)
}

/// [`generate_packed`] over an explicit committee (SPEC §10.3 restart).
/// `rngs[i]` belongs to `committee.ids()[i]`; tamper hooks name ids.
pub fn generate_packed_with_committee(
    committee: &Committee,
    sid: &[u8],
    b_pack: usize,
    rngs: &mut [StdRng],
    tamper: Option<&TripleTamper>,
) -> Result<Vec<Vec<(TripleShare, TriplePublic)>>> {
    let ids = committee.ids();
    let n = ids.len();
    let t = committee.t();
    if b_pack < 1 {
        return Err(Error::InvalidParams("packed batch size B must be >= 1"));
    }
    if n < 2 * t + 2 * b_pack - 3 {
        return Err(Error::InvalidParams(
            "packed mode requires n >= 2t + 2B - 3 (SPEC §7.4.1)",
        ));
    }
    let d = t + b_pack - 2; // packed sharing degree (§7.4.1)

    // PT1: ONE commit-reveal session dealing ⟦α⟧_pack, ⟦β⟧_pack.
    let joint = joint_random_packed(committee, sid, rngs, Phase::Triples, 2, d)?;
    let a_shares: Vec<Scalar> = joint.iter().map(|o| o[0].share).collect();
    let b_shares: Vec<Scalar> = joint.iter().map(|o| o[1].share).collect();
    let ca = joint[0][0].com.clone();
    let cb = joint[0][1].com.clone();

    // PT2: ONE local product, ONE degree-d constant-pack re-sharing (value
    // h_j at every slot), ONE DLEQ proof per party (the §4.4 form is
    // unchanged — the shares at j are scalars, and slot 0 is point 0).
    let mut resh_coms: Vec<FeldmanCommitment> = Vec::with_capacity(n);
    let mut resh_shares: Vec<Vec<Scalar>> = Vec::with_capacity(n); // [dealer pos][receiver pos]
    let mut proofs = Vec::with_capacity(n);
    for (k, &j) in ids.iter().enumerate() {
        let gamma_j = a_shares[k] * b_shares[k];
        let g = ShamirPoly::random_packed_const(gamma_j, b_pack, t, &mut rngs[k]);
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

    // Fault injection (tests): the PT2 hooks of `TripleTamper` apply
    // unchanged — there is exactly one re-sharing and one proof per party.
    if let Some(tamp) = tamper {
        if let Some((dealer, victim)) = tamp.bad_reshare {
            if let (Some(d), Some(v)) = (committee.position(dealer), committee.position(victim)) {
                resh_shares[d][v] += Scalar::ONE; // cheating dealer, PT2
            }
        }
        if let Some(j) = tamp.bad_product_proof {
            if let Some(p) = committee.position(j) {
                proofs[p].2.z += Scalar::ONE; // invalid DLEQ proof (F3)
            }
        }
    }

    // PT3: verify proofs and shares (F2/F3 as in `generate_with_committee`),
    // then recombine per slot with the slot Lagrange weights λ_j^{(b)}.
    let slot_lambdas: Vec<Vec<Scalar>> = (0..b_pack)
        .map(|b| lagrange_coeffs_at(&slot_point(b), ids))
        .collect();
    let mut ccs: Vec<Option<FeldmanCommitment>> = (0..b_pack).map(|_| None).collect();
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
                    detail: "invalid DLEQ product proof (packed)".into(),
                },
            });
        }
        // Slot binding (§7.4.2 PT2): the dealt re-sharing must be a
        // constant-pack — `g_j(e_b) = h_j` at EVERY slot. The DLEQ proof
        // binds point 0 (= slot 0) only; this point-equality check binds
        // the remaining slots against the same committed value, blaming
        // the dealer on mismatch. Without it a dealer could keep every
        // party share valid while poisoning a slot `b ≥ 1` — the degree
        // argument (`n ≥ 2d+1` party points) does not cover slot points.
        for b in 1..b_pack {
            if c_j.eval_at_point(&slot_point(b)) != c_j.points[0] {
                return Err(Error::Abort {
                    abort: IdentifiableAbort {
                        phase: Phase::Triples,
                        blamed: vec![j],
                        detail: format!(
                            "re-sharing polynomial violates the slot binding (slot {b})"
                        ),
                    },
                });
            }
        }
        for (v, &s) in resh_shares[k].iter().enumerate() {
            let i = ids[v];
            if !c_j.verify_share(i, &s) {
                // §6.1 complaint on the re-shared share (F2), as in
                // `generate_with_committee`.
                return Err(resolve_complaint(
                    Phase::Triples,
                    c_j,
                    j,
                    i,
                    &resh_shares[k][v],
                ));
            }
        }
        for (b, acc) in ccs.iter_mut().enumerate() {
            let scaled = c_j.scale(&slot_lambdas[b][k]);
            *acc = Some(match acc.take() {
                None => scaled,
                Some(acc) => acc.add(&scaled),
            });
        }
    }
    let publics: Vec<TriplePublic> = ccs
        .into_iter()
        .map(|cc| TriplePublic {
            ca: ca.clone(),
            cb: cb.clone(),
            cc: cc.expect("n >= 1"),
        })
        .collect();

    let out = (0..n)
        .map(|k| {
            let i = ids[k];
            (0..b_pack)
                .map(|b| {
                    let c_share = (0..n)
                        .map(|d| slot_lambdas[b][d] * resh_shares[d][k])
                        .fold(Scalar::ZERO, |acc, x| acc + x);
                    (
                        TripleShare {
                            index: i,
                            a: a_shares[k],
                            b: b_shares[k],
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
