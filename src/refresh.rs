//! Committee maintenance (SPEC §13.4).
//!
//! Both operations keep the long-term public key `X` fixed — key rotation
//! (changing `X`) is out of scope (§13.4):
//!
//! * [`refresh`] — proactive refresh: same committee, new epoch. Every
//!   party deals a zero-constant polynomial `z_i` (`z_i(0) = 0`) through
//!   the §6 commit-reveal DKG machinery
//!   ([`DkgInstance::start_with_secret`]); each party adds the dealt shares
//!   to its key share, `x'_j = x_j + Σ_i z_i(j)`, and everyone updates the
//!   commitment componentwise, `A'[x] = A[x] + Σ_i A[z_i]` — so
//!   `A'[x].points[0] = X` while every share is new.
//! * [`reshare`] — committee change: each old-committee party `j` re-deals
//!   its share `x_j` over the NEW committee under a fresh degree-`(t'−1)`
//!   polynomial `p_j` with Feldman commitment `C_j`, publicly bound to its
//!   old share by the check `C_j.points[0] == EvalCom(A[x], j)`; new member
//!   `m` sets `x'_m = Σ_j λ_j^S · p_j(m)` (λ over the OLD id set `S`) and
//!   `A'[x] = Σ_j λ_j^S · C_j` componentwise, whence `A'[x].points[0] = X`.
//!
//! §13.4 mandates invalidating all outstanding presignatures on either
//! operation (they are key-equivalent, §8.6): deployments MUST call
//! [`PresigStore::clear`](crate::PresigStore::clear) on every epoch change.
//! These functions do not touch stores — stores are owned by the caller.

use std::collections::BTreeMap;

use k256::{ProjectivePoint, Scalar};
use rand::rngs::StdRng;

use crate::dkg::{resolve_complaint, DkgBcast1, DkgBcast2, DkgInstance, DkgP2P, DkgTamper};
use crate::presign::KeyShare;
use crate::shamir::{lagrange_coeffs, ShamirPoly};
use crate::vss::FeldmanCommitment;
use crate::{hash_commitment, tags, Committee, Error, IdentifiableAbort, PartyId, Phase, Result};

/// Positional input check (see `presign::check_committee_inputs`):
/// `keys[k]` must belong to `committee.ids()[k]`.
fn check_inputs(committee: &Committee, keys: &[KeyShare], rngs_len: usize) -> Result<()> {
    if keys.len() != committee.n()
        || rngs_len < committee.n()
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

/// Drive one commit-reveal DKG over `committee` in which every member deals
/// a caller-FIXED secret (§13.4; commit-reveal and §6.1 complaints are the
/// stock [`DkgInstance`] ones). Returns the per-party outputs and the
/// revealed Feldman vectors (`refresh` needs them for the zero-constant
/// check).
fn deal_fixed_secrets(
    committee: &Committee,
    sid: &[u8],
    tag: &'static [u8],
    secrets: &[Scalar],
    rngs: &mut [StdRng],
    tamper: Option<&DkgTamper>,
) -> Result<(Vec<KeyShare>, BTreeMap<PartyId, DkgBcast2>)> {
    let n = committee.n();
    if secrets.len() != n {
        return Err(Error::InvalidParams("secrets must match the committee"));
    }
    // Round 1: every party commits to its dealing polynomial.
    let mut r1 = BTreeMap::new();
    let mut insts = Vec::with_capacity(n);
    for (k, &i) in committee.ids().iter().enumerate() {
        let (mut inst, b1) =
            DkgInstance::start_with_secret(committee, sid, tag, i, secrets[k], &mut rngs[k]);
        if let Some((dealer, victim)) = tamper.and_then(|t| t.bad_deal) {
            if dealer == i {
                // Cheating dealer: wrong share *and* wrong §6.1 defense.
                inst.bad_deal = Some(victim);
            }
        }
        r1.insert(i, b1);
        insts.push(inst);
    }
    // Round 2: reveal broadcasts + P2P shares.
    let mut r2 = BTreeMap::new();
    let mut p2p: Vec<DkgP2P> = Vec::new();
    for inst in &insts {
        let (b2, shares) = inst.reveal();
        r2.insert(inst.me, b2);
        p2p.extend(shares);
    }
    if let Some((from, to)) = tamper.and_then(|t| t.corrupt_share) {
        // Corrupt a share in transit: the dealer's §6.1 defense still
        // verifies, so the victim's complaint is a false accusation.
        for m in p2p.iter_mut() {
            if m.from == from && m.to == to {
                m.share += Scalar::ONE;
            }
        }
    }
    // Round 3 (local): every party finalizes over the accepted sets.
    let mut outs = Vec::with_capacity(n);
    for inst in &insts {
        let mine: BTreeMap<PartyId, Scalar> = p2p
            .iter()
            .filter(|m| m.to == inst.me)
            .map(|m| (m.from, m.share))
            .collect();
        let defenses: BTreeMap<PartyId, Scalar> =
            insts.iter().map(|d| (d.me, d.defend(inst.me))).collect();
        outs.push(inst.finalize(Phase::Refresh, &r1, &r2, &mine, &defenses)?);
    }
    Ok((outs, r2))
}

/// Proactive refresh (SPEC §13.4): re-share `x` with zero-constant
/// polynomials over the SAME committee. The public key `X` is unchanged
/// (asserted against `A'[x].points[0]`), every share is new, and each
/// dealer's commitment is checked to bind a zero constant term — a dealer
/// that commits to anything else shifts `X` and is blamed identifiably.
///
/// `keys[k]`/`rngs[k]` belong to `committee.ids()[k]` (positionally;
/// `keys[k].index` is checked). Tamper hooks are the stock [`DkgTamper`]
/// dealing faults.
pub fn refresh(
    committee: &Committee,
    keys: &[KeyShare],
    sid: &[u8],
    rngs: &mut [StdRng],
    tamper: Option<&DkgTamper>,
) -> Result<Vec<KeyShare>> {
    check_inputs(committee, keys, rngs.len())?;
    let zeros = vec![Scalar::ZERO; committee.n()];
    let (z_outs, reveals) =
        deal_fixed_secrets(committee, sid, tags::REFRESH_COMMIT, &zeros, rngs, tamper)?;
    // Every dealt [z_i] must commit to a zero constant term; identifiable
    // on public data (the revealed Feldman vector).
    for &i in committee.ids() {
        if reveals[&i].com.points[0] != ProjectivePoint::IDENTITY {
            return Err(Error::Abort {
                abort: IdentifiableAbort {
                    phase: Phase::Refresh,
                    blamed: vec![i],
                    detail: "refresh dealer committed to a non-zero constant term".into(),
                },
            });
        }
    }
    let mut new_keys = Vec::with_capacity(committee.n());
    for (k, z) in z_outs.into_iter().enumerate() {
        // x'_j = x_j + Σ_i z_i(j); A'[x] = A[x] + Σ_i A[z_i] componentwise.
        let com = keys[k].com.add(&z.com);
        assert_eq!(
            com.points[0], keys[k].com.points[0],
            "refresh must preserve the public key X"
        );
        new_keys.push(KeyShare {
            index: keys[k].index,
            share: keys[k].share + z.share,
            com,
        });
    }
    Ok(new_keys)
}

/// Fault-injection hooks for committee re-sharing (tests only).
#[derive(Debug, Default, Clone, Copy)]
pub struct ReshareTamper {
    /// Make this old-committee dealer compute a wrong sub-share for this
    /// new-committee member (cheating dealer). The §6.1 defense does not
    /// verify either, so the dealer is blamed.
    pub bad_deal: Option<(PartyId, PartyId)>,
    /// Make this old-committee dealer broadcast a commitment whose constant
    /// term is NOT its true old share (`C_j.points[0] != EvalCom(A[x], j)`);
    /// the public binding check blames the dealer.
    pub bad_commitment: Option<PartyId>,
}

/// One old-committee party's re-sharing deal over the new committee.
struct ReshareDealer {
    from: PartyId,
    poly: ShamirPoly,
    com: FeldmanCommitment,
    /// Fault injection (tests): deal a wrong sub-share to this new member.
    bad_deal: Option<PartyId>,
}

impl ReshareDealer {
    /// The sub-share this dealer computed for new member `to` — also its
    /// §6.1 defense when `to` complains (the `bad_deal` fault injection
    /// applies here too, so a cheating dealer's defense is wrong; see
    /// [`DkgInstance::defend`]).
    fn share_for(&self, to: PartyId) -> Scalar {
        let mut s = self.poly.eval(to);
        if self.bad_deal == Some(to) {
            s += Scalar::ONE;
        }
        s
    }
}

/// Committee change (SPEC §13.4): re-share `x` from the `old` committee to
/// the `new` one (possibly different ids and size — overlap is fine, the
/// polynomials are fresh). The public key `X` is unchanged (asserted
/// against `A'[x].points[0]`); key rotation is out of scope.
///
/// The new committee must already be validated by [`Committee::new`] (which
/// enforces `n' >= 2t' - 1`); if it cannot be constructed, the caller's
/// only recourse is full re-DKG with key rotation (§13.4, out of scope).
/// §13.4 deployments keep the threshold `T` fixed; the reference
/// implementation permits a different `t'` on the new committee (validated
/// as usual) — lowering it is a policy decision for the caller, not
/// policed here.
///
/// `old_keys[k]`/`rngs_old[k]` belong to `old.ids()[k]` (positionally;
/// `old_keys[k].index` is checked). Only the old committee deals, so the
/// new members need no randomness. Every verification failure surfaces as
/// `Error::Abort` blaming the dealer (§10).
pub fn reshare(
    old: &Committee,
    new: &Committee,
    old_keys: &[KeyShare],
    sid: &[u8],
    rngs_old: &mut [StdRng],
    tamper: Option<&ReshareTamper>,
) -> Result<Vec<KeyShare>> {
    check_inputs(old, old_keys, rngs_old.len())?;
    let x_com = &old_keys[0].com;

    // Round 1 (dealers): each old party j samples a fresh degree-(t'-1)
    // polynomial p_j with p_j(0) = x_j and commits to its Feldman vector.
    let mut commits = BTreeMap::new();
    let mut dealers = Vec::with_capacity(old.n());
    for (k, &j) in old.ids().iter().enumerate() {
        let poly = ShamirPoly::random(old_keys[k].share, new.t(), &mut rngs_old[k]);
        let mut com = FeldmanCommitment::from_poly(&poly);
        let mut bad_deal = None;
        if let Some(tamp) = tamper {
            if tamp.bad_commitment == Some(j) {
                // Cheating dealer: the commitment no longer binds to x_j.
                com = com.add_const(&Scalar::ONE);
            }
            if let Some((dealer, victim)) = tamp.bad_deal {
                if dealer == j {
                    bad_deal = Some(victim);
                }
            }
        }
        let hash = hash_commitment(sid, tags::RESHARE_COMMIT, j, &com);
        commits.insert(j, DkgBcast1 { from: j, hash });
        dealers.push(ReshareDealer {
            from: j,
            poly,
            com,
            bad_deal,
        });
    }

    // Round 2: reveal the commitments; deal sub-shares to the new members.
    let mut reveals = BTreeMap::new();
    let mut p2p: Vec<DkgP2P> = Vec::new();
    for d in &dealers {
        reveals.insert(
            d.from,
            DkgBcast2 {
                from: d.from,
                com: d.com.clone(),
            },
        );
        for &m in new.ids() {
            p2p.push(DkgP2P {
                from: d.from,
                to: m,
                share: d.share_for(m),
            });
        }
    }

    // Round 3 (each new member m): verify every deal, then
    // x'_m = Σ_j λ_j^S · p_j(m) and A'[x] = Σ_j λ_j^S · C_j.
    let lambdas = lagrange_coeffs(old.ids());
    let mut new_keys = Vec::with_capacity(new.n());
    for &m in new.ids() {
        let mine: BTreeMap<PartyId, Scalar> = p2p
            .iter()
            .filter(|p| p.to == m)
            .map(|p| (p.from, p.share))
            .collect();
        let mut share = Scalar::ZERO;
        let mut com = FeldmanCommitment {
            points: vec![ProjectivePoint::IDENTITY; new.t()],
        };
        for (pos, &j) in old.ids().iter().enumerate() {
            let b1 = &commits[&j];
            let b2 = &reveals[&j];
            // (a) commit-reveal consistency (F1: the dealer is blamed)
            if b2.com.points.len() != new.t() {
                return Err(Error::Abort {
                    abort: IdentifiableAbort {
                        phase: Phase::Refresh,
                        blamed: vec![j],
                        detail: "malformed Feldman commitment vector".into(),
                    },
                });
            }
            if hash_commitment(sid, tags::RESHARE_COMMIT, j, &b2.com) != b1.hash {
                return Err(Error::Abort {
                    abort: IdentifiableAbort {
                        phase: Phase::Refresh,
                        blamed: vec![j],
                        detail: "commit-reveal hash mismatch".into(),
                    },
                });
            }
            // (b) public binding: the dealer re-shares its TRUE old share,
            // C_j.points[0] == EvalCom(A[x], j) — identifiable on public data.
            if b2.com.points[0] != x_com.eval_at(j) {
                return Err(Error::Abort {
                    abort: IdentifiableAbort {
                        phase: Phase::Refresh,
                        blamed: vec![j],
                        detail: "re-sharing commitment does not bind to the dealer's old share"
                            .into(),
                    },
                });
            }
            // (c) sub-share validity; §6.1 complaint on failure (F2)
            let s = &mine[&j];
            if !b2.com.verify_share(m, s) {
                return Err(resolve_complaint(
                    Phase::Refresh,
                    &b2.com,
                    j,
                    m,
                    &dealers[pos].share_for(m),
                ));
            }
            share += lambdas[pos] * *s;
            com = com.add(&b2.com.scale(&lambdas[pos]));
        }
        // Σ_j λ_j^S · EvalCom(A[x], j) = X (Lagrange interpolation at 0).
        assert_eq!(
            com.points[0], x_com.points[0],
            "re-sharing must preserve the public key X"
        );
        new_keys.push(KeyShare {
            index: m,
            share,
            com,
        });
    }
    Ok(new_keys)
}
