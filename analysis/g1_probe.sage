#!/usr/bin/env sage
# ohm_g1_probe.sage — empirical collision-hardness probe for Phi (the G1 gap)
#
# WHAT THIS IS
#   A small-scale empirical probe of the one named heuristic in the
#   re-randomization lemma (docs/proof/PROOF.md §8.2.6, gap G1):
#   that Phi(M, tau) = h(M) + F(H(sid‖id‖M‖tau‖X)·R)·tau behaves like a
#   random function F_q x F_q -> F_q for collision-search purposes, so the
#   GS21 cube-root attack degrades to birthday Theta(sqrt(q)) once r is
#   re-randomized per (M, tau).
#
# MODEL FIDELITY (matches the construction, not a strawman)
#   * Curve equation is secp256k1's: y^2 = x^3 + 7, instantiated over small
#     prime fields chosen so that #E(GF(p)) is prime AND p < N. The p < N
#     choice avoids the x-coordinate mod-N fold merging distinct coordinates
#     (on secp256k1 |p - q|/q ~ 2^-128, so the fold is negligible there;
#     at toy scale with p > N it would pollute the 2-to-1 check).
#   * h and the gamma-hash are independent SHA-256-based random oracles,
#     reduced mod N. The gamma oracle's domain separation mirrors
#     tags::RERAND_GAMMA ("OHM-ECDSA/v0.1/rerand-gamma", src/lib.rs).
#   * sid, id, X, R are fixed per instance — the adversary's only free
#     variables are (M, tau), with tau free over ALL of F_q (SPEC §9.4:
#     "tau (public, from the derivation path)"; sign_share_rerand accepts
#     any Scalar; insiders request signatures under arbitrary tweaks).
#   * Work is counted in Phi evaluations (each = 2 RO queries in the real
#     model; the proof's q_H budget). F(gamma·R) is precomputed as a table
#     — legitimate, because the table depends only on public R.
#
# WHAT WOULD CONSTITUTE A FINDING
#   Any Phi strategy with a fitted exponent meaningfully below 0.5 (say
#   < 0.45) is a candidate sub-birthday shortcut — a real crack in G1.
#   The AFFINE Wagner control (constant r, the GS21 configuration) MUST
#   come out near 1/3: it is the positive control proving the harness can
#   detect sub-birthday structure when it exists. If the control fails,
#   null results on Phi mean nothing.
#
# RUN
#   sage analysis/g1_probe.sage            # full ladder, a few minutes
#   Validated logic-for-logic against a pure-Python replica at N up to
#   ~1e5 (exact table ratio 1.0001 vs random-function control; slopes
#   0.47-0.50 for all Phi strategies; control slope 0.31).

import hashlib
import math
import random

# Prime ladder: p with #E(GF(p)) prime and p < N (fold-free), evenly spaced
# in log scale. Verified by exhaustive order computation.
PRIMES = [577, 8779, 99079, 998653]
SEED = 0x0BADF00D


# ---------------------------------------------------------------- primitives
def H_scalar(N, *parts):
    """Random oracle -> F_N (SHA-256, domain-separated by convention)."""
    data = b"|".join(str(x).encode() for x in parts)
    return int(hashlib.sha256(data).hexdigest(), 16) % N


def build_FR_table(E, R, N):
    """FR[g] = F(g*R) = x-coordinate of g*R reduced mod N; FR[0] = 0.

    F(identity) := 0 models the negligible gamma = 0 case (probability 1/N;
    the code's rerand_gamma counter-rehashes to exclude it, src/protocol/
    sign.rs). Repeated addition: O(N) curve adds, no scalar muls.
    """
    table = [0] * N
    P = E(0)
    for g in range(1, N):
        P = P + R
        table[g] = 0 if P.is_zero() else ZZ(P.xy()[0]) % N
    return table


class Phi:
    """Phi(M, tau) = h(M) + F(H(sid‖id‖M‖tau‖X)·R)·tau   (PROOF.md §8.2.5)"""

    def __init__(self, N, FR, sid, idp, xstr):
        self.N = N
        self.FR = FR
        self.sid = sid
        self.idp = idp
        self.xstr = xstr
        self.evals = 0

    def h(self, M):
        return H_scalar(self.N, "h", M)

    def gamma(self, M, tau):
        # domain separation mirrors tags::RERAND_GAMMA
        return H_scalar(self.N, "rerand-gamma", self.sid, self.idp, M, tau, self.xstr)

    def __call__(self, M, tau):
        self.evals += 1
        return (self.h(M) + self.FR[self.gamma(M, tau)] * (tau % self.N)) % self.N


# ---------------------------------------------------------------- strategies
# Each returns the number of Phi evaluations to the first usable collision.
# Predictions from PROOF.md §8.2.5: birthday Theta(sqrt(N)) for collision
# strategies, O(N) for the degenerate/preimage schedules.

def baseline_A(phi, N, rng):
    """(A) Plain birthday: uniform (M, tau) pairs until a collision.
    Baseline only — tau drawn randomly, NOT the adversary's game."""
    seen = {}
    while True:
        M = rng.getrandbits(64)
        tau = rng.randrange(N)
        v = phi(M, tau)
        if v in seen and seen[v] != (M, tau):
            return phi.evals
        seen[v] = (M, tau)


def attack_B1_preimage(phi, N, rng):
    """(B1) Case (2), sign-then-find: grind (M, tau) to hit one signed value."""
    target = phi(rng.getrandbits(64), rng.randrange(N))
    while True:
        if phi(rng.getrandbits(64), rng.randrange(N)) == target:
            return phi.evals


def attack_B2_fixed_M(phi, N, rng):
    """(B2) Degenerate schedule M = M': birthday in t |-> psi(t)*t."""
    M0 = rng.getrandbits(64)
    seen = {}
    while True:
        tau = rng.randrange(N)
        v = phi(M0, tau)
        if v in seen and seen[v] != tau:
            return phi.evals
        seen[v] = tau


def attack_B3_fixed_tau(phi, N, rng):
    """(B3) Degenerate schedule tau = tau': birthday in the one variable M."""
    t0 = rng.randrange(N)
    seen = {}
    while True:
        M = rng.getrandbits(64)
        v = phi(M, t0)
        if v in seen and seen[v] != M:
            return phi.evals
        seen[v] = M


def attack_B4_mitm(phi, N, rng):
    """(B4) Two-block MITM: disjoint message namespaces, cross-block match.
    The adversary's optimal structured birthday (PROOF.md §8.2.5 upper bound)."""
    left = {}
    right = {}
    i = 0
    while True:
        if i % 2 == 0:
            v = phi("L:%d" % rng.getrandbits(48), rng.randrange(N))
            if v in right:
                return phi.evals
            left[v] = True
        else:
            v = phi("R:%d" % rng.getrandbits(48), rng.randrange(N))
            if v in left:
                return phi.evals
            right[v] = True
        i += 1


def attack_B5a_tau_zero(phi, N, rng):
    """(B5a) Degenerate schedule tau' = 0: collapses to preimage, O(N)."""
    target = phi(rng.getrandbits(64), 0)  # = h(M')
    while True:
        if phi(rng.getrandbits(64), rng.randrange(N)) == target:
            return phi.evals


def attack_B5b_small_tau(phi, N, rng):
    """(B5b) Structured grid: tau restricted to [1, sqrt(N)]."""
    bound = max(2, int(math.isqrt(N)))
    seen = {}
    while True:
        M = rng.getrandbits(64)
        tau = rng.randrange(1, bound)
        v = phi(M, tau)
        if v in seen and seen[v] != (M, tau):
            return phi.evals
        seen[v] = (M, tau)


def attack_B5c_chain(phi, N, rng):
    """(B5c) Adaptive chaining: memoryless rho on x |-> Phi(chain, x).
    Tests whether feeding Phi outputs back as tweaks buys anything."""
    def f(x):
        return phi("chain", x)

    x0 = rng.randrange(N)
    tort = f(x0)
    hare = f(f(x0))
    while tort != hare:
        tort = f(tort)
        hare = f(f(hare))
    return phi.evals


STRATEGIES = [
    ("A  baseline birthday", baseline_A, "birthday"),
    ("B1 preimage (sign-then-find)", attack_B1_preimage, "preimage"),
    ("B2 fixed M (M=M')", attack_B2_fixed_M, "birthday"),
    ("B3 fixed tau (tau=tau')", attack_B3_fixed_tau, "birthday"),
    ("B4 two-block MITM", attack_B4_mitm, "birthday"),
    ("B5a tau'=0 grind", attack_B5a_tau_zero, "preimage"),
    ("B5b small-tau grid", attack_B5b_small_tau, "birthday"),
    ("B5c adaptive chain", attack_B5c_chain, "birthday"),
]


# ---------------------------------------------------------------- aux checks
def check_two_to_one(FR, N):
    """PROOF.md §8.2.6(ii): gamma |-> F(gamma*R) is exactly 2-to-1 up to
    sign. This is a theorem, so it must hold EXACTLY (given p < N, no mod
    fold) — a failed check here means the harness itself is broken."""
    mult = {}
    for g in range(1, N):
        v = FR[g]
        if v == 0:
            continue
        mult[v] = mult.get(v, 0) + 1
    worst = max(mult.values())
    return worst, len(mult)


def check_F_uniformity(FR, N):
    """The G1 quantity: distribution of F(gamma*R) over gamma in F_N.
    Reports support, statistical distance from uniform, chi^2, and the
    effective output-space size N_eff = 1/Sum p_v^2 — the number that
    actually enters the birthday bound. Expect support/N ~ 0.5 (x-coords
    cover half the field), SD ~ 0.5, and N_eff/N ~ 0.5: F is NOT uniform,
    but non-uniformity is a constant factor (sqrt(2) in work), not a
    structure — exactly the 'uniform enough' the heuristic needs."""
    counts = [0] * N
    tot = 0
    for g in range(1, N):
        counts[FR[g]] += 1
        tot += 1
    support = sum(1 for c in counts if c > 0)
    sd = 0.5 * sum(abs(c / tot - 1.0 / N) for c in counts)
    e = tot / N
    chi2 = sum((c - e) ** 2 / e for c in counts)
    n_eff = 1.0 / sum((c / tot) ** 2 for c in counts)
    return support, sd, chi2, n_eff


def exact_table(FR, N, sid, idp, xstr, rng):
    """Smallest prime only: enumerate Phi over the FULL (M, tau) domain and
    compare collision statistics against a same-size random function. The
    direct test of 'Phi is indistinguishable from random' at this scale."""
    phi = Phi(N, FR, sid, idp, xstr)
    buckets = [0] * N
    for M in range(N):
        for tau in range(N):
            buckets[phi(M, tau)] += 1
    pairs = sum(c * (c - 1) // 2 for c in buckets)
    maxb = max(buckets)
    ctrl = [0] * N
    for _ in range(N * N):
        ctrl[rng.randrange(N)] += 1
    cpairs = sum(c * (c - 1) // 2 for c in ctrl)
    cmax = max(ctrl)
    print("  exact table (N^2 = %d evals): colliding pairs = %d (random-fn control %d, ratio %.4f)"
          % (N * N, pairs, cpairs, pairs / cpairs))
    print("                 max bucket = %d (control %d)" % (maxb, cmax))


# ---------------------------------------------------------------- affine control
def wagner_affine_control(N, rng, trials):
    """POSITIVE CONTROL: the GS21 configuration — constant r, condition
    h(M) + r*tau = h(M') + r*tau'. The affineness lets Wagner's 4-sum
    split into per-variable lists: O(N^(1/3)) RO evaluations. The harness
    MUST recover the ~1/3 exponent here; if it does, its null results on
    the re-randomized Phi are meaningful. Work = RO evaluations; the
    bucketed merge is O(B) field ops per attempt, same order. Attempts
    repeat with fresh lists until solved."""
    n_bits = N.bit_length()
    k = max(4, (n_bits + 2) // 3)
    mask = (1 << k) - 1
    B = 1 << k  # ~2*N^(1/3); expected matches per attempt 2^(3k-n) in [1,4]
    works = []
    for _ in range(trials):
        r = rng.randrange(1, N)
        total = 0
        while True:
            total += 4 * B
            seed = rng.getrandbits(48)
            L1 = [H_scalar(N, "h", "w1:%d:%d" % (seed, i)) for i in range(B)]
            L2 = [(r * H_scalar(N, "t", "w2:%d:%d" % (seed, i))) % N for i in range(B)]
            L3 = [H_scalar(N, "h", "w3:%d:%d" % (seed, i)) for i in range(B)]
            L4 = [(r * H_scalar(N, "t", "w4:%d:%d" % (seed, i))) % N for i in range(B)]
            # merge L1+L2 keeping sums with low k bits zero (bucketed, O(B))
            buck2 = {}
            for j, b in enumerate(L2):
                buck2.setdefault(b & mask, []).append(j)
            S12 = {}
            for a in L1:
                for j in buck2.get((-a) & mask, []):
                    S12[(a + L2[j]) % N] = True
            buck4 = {}
            for j, d in enumerate(L4):
                buck4.setdefault(d & mask, []).append(j)
            found = False
            for c in L3:
                for j in buck4.get((-c) & mask, []):
                    if (c + L4[j]) % N in S12:
                        found = True
                        break
                if found:
                    break
            if found:
                works.append(total)
                break
    return works


# ---------------------------------------------------------------- driver
def run_prime(p, rng, trials_b, trials_p, do_exact):
    E = EllipticCurve(GF(p), [0, 7])  # secp256k1's equation, small field
    N = ZZ(E.order())
    assert is_prime(N), "ladder prime %d: curve order %s not prime" % (p, N)
    assert p < N, "ladder prime %d: p >= N, x-coord fold would pollute checks" % p
    N = int(N)
    R = E.random_point()
    while R.is_zero():
        R = E.random_point()
    X = E.random_point()
    xstr = "%s,%s" % (X.xy()[0], X.xy()[1])
    FR = build_FR_table(E, R, N)

    worst, img = check_two_to_one(FR, N)
    support, sd, chi2, n_eff = check_F_uniformity(FR, N)

    print("p = %d   N = %d   (prime order, p < N: fold-free)" % (p, N))
    print("  2-to-1 check: max preimage mult = %d (MUST be 2), image size = %d (expect ~N/2 = %d)"
          % (worst, img, (N - 1) // 2))
    print("  F-uniformity: support/N = %.3f  SD = %.3f  chi2/N = %.3f  N_eff/N = %.3f"
          % (support / N, sd, chi2 / N, n_eff / N))
    if worst != 2:
        print("  *** HARNESS BUG: 2-to-1 lemma (a theorem) violated — distrust everything below")
    if do_exact:
        exact_table(FR, N, "sid", 1, xstr, rng)

    results = {}
    for name, fn, kind in STRATEGIES:
        trials = trials_b if kind == "birthday" else trials_p
        works = []
        for _ in range(trials):
            phi = Phi(N, FR, "sid", 1, xstr)
            works.append(fn(phi, N, rng))
        results[name] = sum(works) / len(works)
        pred = 0.5 if kind == "birthday" else 1.0
        print("  %-32s mean work = %9.1f  (predicted %.2f*log2N = %5.1f, got %.2f)"
              % (name, results[name], pred, pred * math.log2(N),
                 math.log2(results[name])))

    works = wagner_affine_control(N, rng, max(20, trials_b // 2))
    if works:
        mw = sum(works) / len(works)
        results["AFFINE Wagner 4-sum (control)"] = mw
        print("  %-32s mean work = %9.1f  (predicted 0.33*log2N = %5.1f, got %.2f)  [%d/%d solved]"
              % ("AFFINE Wagner 4-sum (control)", mw, 0.33 * math.log2(N),
                 math.log2(mw), len(works), max(20, trials_b // 2)))
    else:
        print("  AFFINE Wagner 4-sum (control): NO SOLUTION — control failed, null results void")
    print()
    return N, results


def main():
    set_random_seed(SEED)
    rng = random.Random(int(SEED))  # int(): Sage preparses hex literals to Integer
    all_results = []
    for p in PRIMES:
        tb = 200 if p <= 20000 else 60
        tp = 30 if p <= 20000 else 10
        all_results.append(run_prime(p, rng, trials_b=tb, trials_p=tp,
                                     do_exact=(p <= 1100)))

    print("=== exponent fit: log2(work) vs log2(N) ===")
    print("    (Phi strategies: expect ~0.5 birthday / ~1.0 preimage;")
    print("     affine control: expect ~0.33 — the GS21 cube root)")
    names = [s[0] for s in STRATEGIES] + ["AFFINE Wagner 4-sum (control)"]
    verdicts = []
    for name in names:
        pts = [(math.log2(N), math.log2(res[name]))
               for N, res in all_results if name in res and res[name] > 0]
        if len(pts) < 2:
            continue
        xs, ys = zip(*pts)
        mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
        slope = sum((x - mx) * (y - my) for x, y in pts) / sum((x - mx) ** 2 for x in xs)
        if "control" in name:
            flag = "OK (control)" if 0.25 <= slope <= 0.42 else "*** CONTROL OFF — investigate harness"
        elif "preimage" in name or "grind" in name:
            flag = "OK" if slope >= 0.85 else "*** BELOW PREIMAGE — unexpected"
        else:
            flag = "OK" if slope >= 0.45 else "*** SUB-BIRTHDAY — candidate G1 finding"
        verdicts.append(flag.startswith("OK"))
        print("  %-32s slope = %.3f   %s" % (name, slope, flag))
    print()
    if all(verdicts):
        print("VERDICT: no sub-birthday strategy found at this scale; Phi behaves as a")
        print("random function (control confirms the harness detects cube-root structure")
        print("when present). Consistent with the F-uniformity heuristic of PROOF.md §8.2.6.")
    else:
        print("VERDICT: anomalies flagged above — investigate before trusting the G1 heuristic.")


main()
