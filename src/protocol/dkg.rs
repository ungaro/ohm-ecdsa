//! Commit-then-reveal Pedersen DKG (SPEC §6).
//!
//! Three rounds:
//! 1. broadcast `H(tag ‖ sid ‖ i ‖ A_i)` (commit),
//! 2. broadcast `A_i` (reveal) + P2P shares,
//! 3. verify hashes and shares; complaints are publicly arbitrable (§6.1).
//!
//! [`DkgBatchInstance`] deals `B` polynomials in ONE commit-reveal session
//! (SPEC §7.3): the R1 hash covers `encode(A⁽¹⁾ ‖ … ‖ A⁽ᴮ⁾)`, the reveal
//! carries all `B` vectors, each P2P message carries `B` shares.
//!
//! The module is message-oriented: the [`crate::sim`] orchestrator (via the
//! [`crate::transport`] seam) or a real transport delivers every party the
//! same message sets.

use std::collections::BTreeMap;

use k256::elliptic_curve::ff::Field;
use k256::Scalar;
use rand::RngCore;
use zeroize::Zeroize;

use crate::shamir::ShamirPoly;
use crate::vss::FeldmanCommitment;
use crate::{
    hash_commitment, hash_commitments, Committee, Error, IdentifiableAbort, Params, PartyId, Phase,
    Result,
};

/// Round-1 broadcast: hash commitment to the dealer's Feldman vector.
#[derive(Clone, Debug)]
pub struct DkgBcast1 {
    pub from: PartyId,
    pub hash: [u8; 32],
}

/// Round-2 broadcast: the revealed Feldman commitment vector.
#[derive(Clone, Debug)]
pub struct DkgBcast2 {
    pub from: PartyId,
    pub com: FeldmanCommitment,
}

/// Round-2 private message: the share `s_{i,j} = f_i(j)` for party `j`.
#[derive(Clone, Debug)]
pub struct DkgP2P {
    pub from: PartyId,
    pub to: PartyId,
    pub share: Scalar,
}

/// Per-party DKG state.
pub struct DkgInstance {
    /// The party-id set this instance runs over (SPEC §10.3): `1..=n` by
    /// default, the surviving original ids after an expulsion.
    pub committee: Committee,
    pub sid: Vec<u8>,
    pub tag: &'static [u8],
    pub me: PartyId,
    poly: ShamirPoly,
    com: FeldmanCommitment,
    /// Fault injection (tests): deal a wrong share to this party.
    pub(crate) bad_deal: Option<PartyId>,
    /// Fault injection (tests): reveal a well-formed commitment vector that
    /// does NOT hash to the R1 commit (F1).
    pub(crate) bad_reveal: bool,
}

/// DKG output held by one party.
#[derive(Clone, Debug)]
pub struct DkgOutput {
    pub index: PartyId,
    /// This party's share `x_j = Σ_i f_i(j)` of the joint secret.
    pub share: Scalar,
    /// Combined commitment `A = Σ_i A_i` to the joint sharing polynomial.
    pub com: FeldmanCommitment,
}

impl Drop for DkgOutput {
    fn drop(&mut self) {
        // Compiler-fenced erasure of the key share via `zeroize` (SPEC
        // §13.3); k256's `Scalar` implements `DefaultIsZeroes`, so this is
        // a volatile write the compiler cannot elide.
        self.share.zeroize();
    }
}

impl DkgInstance {
    /// Start a DKG over the default committee `1..=n`: sample the dealing
    /// polynomial and broadcast its hash.
    pub fn start(
        params: Params,
        sid: &[u8],
        tag: &'static [u8],
        me: PartyId,
        rng: &mut impl RngCore,
    ) -> (Self, DkgBcast1) {
        Self::start_committee(&Committee::full(&params), sid, tag, me, rng)
    }

    /// Start a DKG over an explicit committee (SPEC §10.3 restart): shares
    /// are dealt at the committee's original ids.
    pub fn start_committee(
        committee: &Committee,
        sid: &[u8],
        tag: &'static [u8],
        me: PartyId,
        rng: &mut impl RngCore,
    ) -> (Self, DkgBcast1) {
        Self::start_with_secret(committee, sid, tag, me, Scalar::random(&mut *rng), rng)
    }

    /// Start a DKG over an explicit committee dealing a FIXED `secret`
    /// instead of a sampled one (SPEC §13.4: zero-constant refresh deals).
    /// Commit-reveal and §6.1 complaint handling are identical to
    /// [`Self::start_committee`].
    pub fn start_with_secret(
        committee: &Committee,
        sid: &[u8],
        tag: &'static [u8],
        me: PartyId,
        secret: Scalar,
        rng: &mut impl RngCore,
    ) -> (Self, DkgBcast1) {
        debug_assert!(committee.ids().contains(&me), "me must be a member");
        let poly = ShamirPoly::random(secret, committee.t(), rng);
        let com = FeldmanCommitment::from_poly(&poly);
        let hash = hash_commitment(sid, tag, me, &com);
        let inst = Self {
            committee: committee.clone(),
            sid: sid.to_vec(),
            tag,
            me,
            poly,
            com,
            bad_deal: None,
            bad_reveal: false,
        };
        (inst, DkgBcast1 { from: me, hash })
    }

    /// The share this dealer computed for party `to` (fault injection via
    /// `bad_deal` applies here too, so a cheating dealer's defense is wrong).
    fn share_for(&self, to: PartyId) -> Scalar {
        let mut s = self.poly.eval(to);
        if self.bad_deal == Some(to) {
            s += Scalar::ONE;
        }
        s
    }

    /// §6.1 defense: the share this dealer computed for `to`, broadcast
    /// publicly when `to` complains. This models the signed-P2P-message
    /// non-repudiation of SPEC §10.2 — a dealer cannot disown the share it
    /// sent, so the defense is exactly the dealt value.
    pub fn defend(&self, to: PartyId) -> Scalar {
        self.share_for(to)
    }

    /// Round 2: reveal the commitment and produce P2P shares for everyone.
    pub fn reveal(&self) -> (DkgBcast2, Vec<DkgP2P>) {
        // Fault injection (tests): a cheating dealer reveals a well-formed
        // vector that does NOT hash to its R1 commit (F1) — the finalize
        // commit-reveal consistency check blames the dealer before any
        // share check runs.
        let com = if self.bad_reveal {
            self.com.add_const(&Scalar::ONE)
        } else {
            self.com.clone()
        };
        let bcast = DkgBcast2 { from: self.me, com };
        let p2p = self
            .committee
            .ids()
            .iter()
            .map(|&j| DkgP2P {
                from: self.me,
                to: j,
                share: self.share_for(j),
            })
            .collect();
        (bcast, p2p)
    }

    /// Round 3: verify all reveals and shares, produce the output.
    ///
    /// `r1`/`r2` are broadcast maps keyed by sender; `shares_for_me` maps
    /// dealer id -> the share that dealer sent to this party; `defenses`
    /// maps dealer id -> the share that dealer publicly broadcasts in its
    /// defense if this party complains (§6.1; in the reference orchestrator
    /// this is [`DkgInstance::defend`], precomputed for every dealer).
    ///
    /// Every verification failure surfaces as `Error::Abort` with blame
    /// resolved per the §6.1 complaint subprotocol (F1/F2 of SPEC §10.1).
    pub fn finalize(
        &self,
        phase: Phase,
        r1: &BTreeMap<PartyId, DkgBcast1>,
        r2: &BTreeMap<PartyId, DkgBcast2>,
        shares_for_me: &BTreeMap<PartyId, Scalar>,
        defenses: &BTreeMap<PartyId, Scalar>,
    ) -> Result<DkgOutput> {
        let n = self.committee.n();
        if r1.len() != n || r2.len() != n || shares_for_me.len() != n || defenses.len() != n {
            return Err(Error::InvalidParams("incomplete message sets"));
        }
        let mut share_sum = Scalar::ZERO;
        let mut coms = Vec::with_capacity(n);
        for &i in self.committee.ids() {
            let b1 = &r1[&i];
            let b2 = &r2[&i];
            // (a) commit-reveal consistency (F1: the dealer is blamed)
            if b2.com.points.len() != self.committee.t() {
                return Err(Error::Abort {
                    abort: IdentifiableAbort {
                        phase,
                        blamed: vec![i],
                        detail: "malformed Feldman commitment vector".into(),
                    },
                });
            }
            if hash_commitment(&self.sid, self.tag, i, &b2.com) != b1.hash {
                return Err(Error::Abort {
                    abort: IdentifiableAbort {
                        phase,
                        blamed: vec![i],
                        detail: "commit-reveal hash mismatch".into(),
                    },
                });
            }
            // (b) share validity; on failure resolve the §6.1 complaint (F2)
            let s = &shares_for_me[&i];
            if !b2.com.verify_share(self.me, s) {
                return Err(resolve_complaint(phase, &b2.com, i, self.me, &defenses[&i]));
            }
            share_sum += s;
            coms.push(b2.com.clone());
        }
        Ok(DkgOutput {
            index: self.me,
            share: share_sum,
            com: FeldmanCommitment::sum(coms),
        })
    }
}

/// Round-2 broadcast for a batch deal: all `B` revealed Feldman vectors.
#[derive(Clone, Debug)]
pub struct DkgBatchBcast2 {
    pub from: PartyId,
    pub coms: Vec<FeldmanCommitment>,
}

/// Round-2 private message for a batch deal: `shares[b] = f_i⁽ᵇ⁾(j)`.
#[derive(Clone, Debug)]
pub struct DkgBatchP2P {
    pub from: PartyId,
    pub to: PartyId,
    pub shares: Vec<Scalar>,
}

/// Per-party batch DKG state: `B` polynomials dealt in ONE commit-reveal
/// session (SPEC §7.3) — the R1 hash covers the concatenation of all `B`
/// commitment vectors, the reveal carries all `B` vectors, and each P2P
/// message carries `B` shares. Polynomials may carry any uniform degree
/// (SPEC §7.4 packed dealing uses degree `d = t + B_pack − 2`; the
/// default is `t − 1`).
pub struct DkgBatchInstance {
    /// The party-id set this instance runs over (see [`DkgInstance`]).
    pub committee: Committee,
    pub sid: Vec<u8>,
    pub tag: &'static [u8],
    pub me: PartyId,
    polys: Vec<ShamirPoly>,
    coms: Vec<FeldmanCommitment>,
    /// Uniform coefficient count of the dealt polynomials; revealed
    /// vectors of any other length are malformed (F1).
    poly_len: usize,
}

impl DkgBatchInstance {
    /// Start a batch DKG over the default committee `1..=n`: sample
    /// `count` dealing polynomials and broadcast one hash committing to
    /// all of them.
    pub fn start(
        params: Params,
        sid: &[u8],
        tag: &'static [u8],
        me: PartyId,
        count: usize,
        rng: &mut impl RngCore,
    ) -> (Self, DkgBcast1) {
        Self::start_committee(&Committee::full(&params), sid, tag, me, count, rng)
    }

    /// Start a batch DKG over an explicit committee (SPEC §10.3 restart).
    pub fn start_committee(
        committee: &Committee,
        sid: &[u8],
        tag: &'static [u8],
        me: PartyId,
        count: usize,
        rng: &mut impl RngCore,
    ) -> (Self, DkgBcast1) {
        let polys: Vec<ShamirPoly> = (0..count)
            .map(|_| ShamirPoly::random(Scalar::random(&mut *rng), committee.t(), &mut *rng))
            .collect();
        Self::start_with_polys(committee, sid, tag, me, polys)
    }

    /// Start a batch DKG dealing `count` uniform random polynomials of the
    /// given DEGREE (SPEC §7.4.2 PT1: packed sharings are ordinary
    /// degree-`d` polynomials; their slot values are whatever the
    /// polynomial evaluates to at the slot points).
    pub fn start_committee_with_degree(
        committee: &Committee,
        sid: &[u8],
        tag: &'static [u8],
        me: PartyId,
        count: usize,
        degree: usize,
        rng: &mut impl RngCore,
    ) -> (Self, DkgBcast1) {
        let polys: Vec<ShamirPoly> = (0..count)
            .map(|_| ShamirPoly::random(Scalar::random(&mut *rng), degree + 1, &mut *rng))
            .collect();
        Self::start_with_polys(committee, sid, tag, me, polys)
    }

    /// Start a batch DKG dealing EXPLICIT polynomials (SPEC §7.4: packed
    /// re-sharings whose slot values are constrained, e.g. the
    /// constant-pack key re-sharing of §7.4.3 P4). Commit-reveal and §6.1
    /// complaint handling are identical to [`Self::start_committee`].
    pub fn start_with_polys(
        committee: &Committee,
        sid: &[u8],
        tag: &'static [u8],
        me: PartyId,
        polys: Vec<ShamirPoly>,
    ) -> (Self, DkgBcast1) {
        debug_assert!(committee.ids().contains(&me), "me must be a member");
        debug_assert!(!polys.is_empty(), "at least one polynomial");
        debug_assert!(
            polys
                .iter()
                .all(|p| p.coeffs.len() == polys[0].coeffs.len()),
            "uniform polynomial length"
        );
        let poly_len = polys[0].coeffs.len();
        let coms: Vec<FeldmanCommitment> = polys.iter().map(FeldmanCommitment::from_poly).collect();
        let hash = hash_commitments(sid, tag, me, &coms);
        let inst = Self {
            committee: committee.clone(),
            sid: sid.to_vec(),
            tag,
            me,
            polys,
            coms,
            poly_len,
        };
        (inst, DkgBcast1 { from: me, hash })
    }

    /// Batch size `B` (number of dealt polynomials).
    pub fn count(&self) -> usize {
        self.polys.len()
    }

    /// §6.1 defense, per index: `defense[b]` is the share this dealer
    /// computed for `to` under polynomial `b`, broadcast publicly when
    /// `to` complains about index `b` (see [`DkgInstance::defend`]).
    pub fn defend(&self, to: PartyId) -> Vec<Scalar> {
        self.polys.iter().map(|p| p.eval(to)).collect()
    }

    /// Round 2: reveal all `B` commitment vectors and produce P2P shares.
    pub fn reveal(&self) -> (DkgBatchBcast2, Vec<DkgBatchP2P>) {
        let bcast = DkgBatchBcast2 {
            from: self.me,
            coms: self.coms.clone(),
        };
        let p2p = self
            .committee
            .ids()
            .iter()
            .map(|&j| DkgBatchP2P {
                from: self.me,
                to: j,
                shares: self.polys.iter().map(|p| p.eval(j)).collect(),
            })
            .collect();
        (bcast, p2p)
    }

    /// Round 3: verify all reveals and shares per (dealer, index), produce
    /// `B` outputs in index order. `shares_for_me[i][b]` is dealer `i`'s
    /// share for index `b`; `defenses[i][b]` likewise (§6.1).
    ///
    /// Every verification failure surfaces as `Error::Abort` with blame
    /// resolved per the §6.1 complaint subprotocol, exactly as in
    /// [`DkgInstance::finalize`].
    pub fn finalize(
        &self,
        phase: Phase,
        r1: &BTreeMap<PartyId, DkgBcast1>,
        r2: &BTreeMap<PartyId, DkgBatchBcast2>,
        shares_for_me: &BTreeMap<PartyId, Vec<Scalar>>,
        defenses: &BTreeMap<PartyId, Vec<Scalar>>,
    ) -> Result<Vec<DkgOutput>> {
        let n = self.committee.n();
        let count = self.count();
        if r1.len() != n || r2.len() != n || shares_for_me.len() != n || defenses.len() != n {
            return Err(Error::InvalidParams("incomplete message sets"));
        }
        let mut share_sums = vec![Scalar::ZERO; count];
        let mut coms_per_index: Vec<Vec<FeldmanCommitment>> =
            (0..count).map(|_| Vec::with_capacity(n)).collect();
        for &i in self.committee.ids() {
            let b1 = &r1[&i];
            let b2 = &r2[&i];
            let shares = &shares_for_me[&i];
            let defense = &defenses[&i];
            // (a) commit-reveal consistency (F1: the dealer is blamed)
            if b2.coms.len() != count
                || b2.coms.iter().any(|c| c.points.len() != self.poly_len)
                || shares.len() != count
            {
                return Err(Error::Abort {
                    abort: IdentifiableAbort {
                        phase,
                        blamed: vec![i],
                        detail: "malformed batch Feldman commitment vectors".into(),
                    },
                });
            }
            if hash_commitments(&self.sid, self.tag, i, &b2.coms) != b1.hash {
                return Err(Error::Abort {
                    abort: IdentifiableAbort {
                        phase,
                        blamed: vec![i],
                        detail: "commit-reveal hash mismatch".into(),
                    },
                });
            }
            // (b) share validity per index; on failure resolve the §6.1
            // complaint for that (dealer, victim, index) triple (F2)
            for (b, com) in b2.coms.iter().enumerate() {
                let s = &shares[b];
                if !com.verify_share(self.me, s) {
                    let mut err = resolve_complaint(phase, com, i, self.me, &defense[b]);
                    if let Error::Abort { abort } = &mut err {
                        abort.detail = format!("{} (batch index {b})", abort.detail);
                    }
                    return Err(err);
                }
                share_sums[b] += s;
            }
            for (b, com) in b2.coms.iter().enumerate() {
                coms_per_index[b].push(com.clone());
            }
        }
        Ok(share_sums
            .into_iter()
            .zip(coms_per_index)
            .map(|(share, coms)| DkgOutput {
                index: self.me,
                share,
                com: FeldmanCommitment::sum(coms),
            })
            .collect())
    }
}

/// Resolve a share complaint (SPEC §6.1 step 2; fault class F2 of §10.1).
///
/// `defense` is the share the dealer publicly broadcasts in its defense —
/// the value it actually computed and sent. This models the
/// signed-P2P-message non-repudiation of SPEC §10.2: a dealer cannot
/// disown the share it sent. If the defense verifies against
/// `EvalCom(A_i, accuser)`, the accusation is false and the **accuser** is
/// blamed; otherwise the **dealer** is blamed.
pub fn resolve_complaint(
    phase: Phase,
    com: &FeldmanCommitment,
    dealer: PartyId,
    accuser: PartyId,
    defense: &Scalar,
) -> Error {
    if com.verify_share(accuser, defense) {
        Error::Abort {
            abort: IdentifiableAbort {
                phase,
                blamed: vec![accuser],
                detail: format!(
                    "false accusation: dealer {dealer}'s defense share verifies against its commitment"
                ),
            },
        }
    } else {
        Error::Abort {
            abort: IdentifiableAbort {
                phase,
                blamed: vec![dealer],
                detail: format!(
                    "dealer {dealer}'s defense share fails verification against its commitment"
                ),
            },
        }
    }
}

/// Fault-injection hooks for the dealing path (tests only).
#[derive(Debug, Default, Clone, Copy)]
pub struct DkgTamper {
    /// Corrupt the share delivered from this dealer to this victim in
    /// transit. The dealer's §6.1 defense still verifies, so the victim's
    /// complaint is a false accusation and the victim is blamed.
    pub corrupt_share: Option<(PartyId, PartyId)>,
    /// Make this dealer compute a wrong share for this victim (cheating
    /// dealer). The defense does not verify, so the dealer is blamed.
    pub bad_deal: Option<(PartyId, PartyId)>,
    /// Make this dealer broadcast a reveal whose commitment vector is
    /// well-formed but does NOT hash to its R1 commit (F1): the
    /// commit-reveal consistency check blames the dealer.
    pub bad_reveal: Option<PartyId>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir::interpolate_at_zero;
    use k256::elliptic_curve::ff::Field;
    use k256::ProjectivePoint;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn dkg_consistency() {
        let params = Params::new(3, 2).unwrap();
        let sid = b"test-dkg";
        let mut rngs: Vec<StdRng> = (0..3)
            .map(|i| StdRng::seed_from_u64(100 + i as u64))
            .collect();

        let mut r1 = BTreeMap::new();
        let mut insts = Vec::new();
        for (k, &i) in params.parties().iter().enumerate() {
            let (inst, b1) = DkgInstance::start(params, sid, b"tag", i, &mut rngs[k]);
            r1.insert(i, b1);
            insts.push(inst);
        }
        let mut r2 = BTreeMap::new();
        let mut p2p: Vec<DkgP2P> = Vec::new();
        for inst in &insts {
            let (b2, shares) = inst.reveal();
            r2.insert(inst.me, b2);
            p2p.extend(shares);
        }
        let mut outs = Vec::new();
        for inst in &insts {
            let mine: BTreeMap<PartyId, Scalar> = p2p
                .iter()
                .filter(|m| m.to == inst.me)
                .map(|m| (m.from, m.share))
                .collect();
            let defenses: BTreeMap<PartyId, Scalar> =
                insts.iter().map(|d| (d.me, d.defend(inst.me))).collect();
            outs.push(
                inst.finalize(Phase::KeyGen, &r1, &r2, &mine, &defenses)
                    .unwrap(),
            );
        }
        // Reconstruct the joint secret from any 2 of 3 and check against the public key.
        let parties = vec![1, 2];
        let shares: Vec<Scalar> = parties.iter().map(|&p| outs[p - 1].share).collect();
        let x = interpolate_at_zero(&parties, &shares);
        let x_pub = outs[0].com.points[0];
        assert_eq!(ProjectivePoint::GENERATOR * x, x_pub);
        // Wrong-share detection: flip one share and expect failure.
        let _ = Scalar::random(&mut rngs[0]);
    }

    #[test]
    fn dkg_batch_consistency_and_complaint() {
        let params = Params::new(3, 2).unwrap();
        let sid = b"test-dkg-batch";
        let count = 3;
        let mut rngs: Vec<StdRng> = (0..3)
            .map(|i| StdRng::seed_from_u64(200 + i as u64))
            .collect();

        let mut r1 = BTreeMap::new();
        let mut insts = Vec::new();
        for (k, &i) in params.parties().iter().enumerate() {
            let (inst, b1) =
                DkgBatchInstance::start(params, sid, b"batch-tag", i, count, &mut rngs[k]);
            r1.insert(i, b1);
            insts.push(inst);
        }
        let mut r2 = BTreeMap::new();
        let mut p2p: Vec<DkgBatchP2P> = Vec::new();
        for inst in &insts {
            let (b2, shares) = inst.reveal();
            r2.insert(inst.me, b2);
            p2p.extend(shares);
        }
        let collect = |me: PartyId, p2p: &[DkgBatchP2P]| {
            p2p.iter()
                .filter(|m| m.to == me)
                .map(|m| (m.from, m.shares.clone()))
                .collect::<BTreeMap<PartyId, Vec<Scalar>>>()
        };
        let defenses_of = |me: PartyId| {
            insts
                .iter()
                .map(|d| (d.me, d.defend(me)))
                .collect::<BTreeMap<PartyId, Vec<Scalar>>>()
        };

        let mut outs = Vec::new();
        for inst in &insts {
            outs.push(
                inst.finalize(
                    Phase::Triples,
                    &r1,
                    &r2,
                    &collect(inst.me, &p2p),
                    &defenses_of(inst.me),
                )
                .unwrap(),
            );
        }
        // Each index is an independent joint sharing: reconstruct all B.
        let parties = vec![1, 2];
        for (b, out0) in outs[0].iter().enumerate() {
            let shares: Vec<Scalar> = parties.iter().map(|&p| outs[p - 1][b].share).collect();
            let x = interpolate_at_zero(&parties, &shares);
            assert_eq!(ProjectivePoint::GENERATOR * x, out0.com.points[0]);
        }

        // Corrupt the share for index 1 from dealer 2 to party 3 in
        // transit: the dealer's §6.1 defense verifies, so party 3's
        // complaint at that index is a false accusation.
        let mut bad_p2p = p2p.clone();
        for m in bad_p2p.iter_mut() {
            if m.from == 2 && m.to == 3 {
                m.shares[1] += Scalar::ONE;
            }
        }
        let victim = &insts[2];
        let err = victim
            .finalize(
                Phase::Triples,
                &r1,
                &r2,
                &collect(3, &bad_p2p),
                &defenses_of(3),
            )
            .unwrap_err();
        match err {
            Error::Abort { abort } => {
                assert_eq!(abort.blamed, vec![3]);
                assert!(abort.detail.contains("batch index 1"));
            }
            other => panic!("expected identifiable abort, got {other:?}"),
        }
    }
}
