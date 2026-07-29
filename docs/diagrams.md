# OHM-ECDSA — visual walkthrough

The protocol in pictures. Cast: **Alice**, **Bob**, **Carol** (honest
parties), **Mallory** (a faulty or malicious party). Every diagram is a
2-of-3 or 3-of-5 committee; the same patterns scale to any `n ≥ 2T−1`.

Normative text and per-phase detail: [`SPEC.md`](../SPEC.md) §5–§10.

## 1. KeyGen ceremony — one public key, no key anywhere (§6)

Three rounds. Commit-reveal exists so no one can pick their contribution
after seeing the others' (rushing attack):

```mermaid
sequenceDiagram
    participant A as Alice
    participant B as Bob
    participant C as Carol
    Note over A,C: Round 1 — commit: hashes first, no backing out
    A->>B: h_A = H(commitments_A)
    A->>C: h_A
    B->>A: h_B
    B->>C: h_B
    C->>A: h_C
    C->>B: h_C
    Note over A,C: Round 2 — reveal commitments, deliver shares privately
    A->>B: commitments_A , share s_{A→B}
    A->>C: commitments_A , share s_{A→C}
    B->>A: commitments_B , share s_{B→A}
    B->>C: commitments_B , share s_{B→C}
    C->>A: commitments_C , share s_{C→A}
    C->>B: commitments_C , share s_{C→B}
    Note over A,C: Round 3 — verify each reveal against its hash,<br/>each share against its commitment (point equality)
    Note over A,C: key share x_i = Σ_j s_{j→i}  ·  public key X = Σ_j A_{j,0}<br/>the secret x itself exists NOWHERE
```

A wrong reveal or a wrong share doesn't just fail — the public
commitments name who sent it (§6.1 complaint arbitration).

## 2. Offline factories — stockpiling presignatures (§7, §8)

Run ahead of time, in bulk (batched §7.3/§8.5 or packed §7.4), whenever
load is low:

```mermaid
sequenceDiagram
    participant A as Alice
    participant B as Bob
    participant C as Carol
    Note over A,C: Triple factory (§7): joint random [α], [β]<br/>→ local products → verifiable degree reduction<br/>(one DLEQ proof per party) → Beaver triples
    Note over A,C: Presign factory (§8): 2 triples + joint randomness<br/>→ ([k⁻¹], [k⁻¹x], R, r) bound to the key
    loop bulk production (batched / packed)
        A->>A: restock pool
        B->>B: restock pool
        C->>C: restock pool
    end
    Note over A,C: presignature pool: single-use, key-equivalent,<br/>stored like key shares (§8.6)
```

## 3. Signing — one round (§9)

See the README's 2-of-3 wallet diagram. The short version: pick an
unused presignature, every party computes `s_i = m·u_i + r·z_i` locally,
shares are exchanged once, verified against public commitments, and
interpolated into an ordinary ECDSA signature. The presignature id is
consumed forever.

## 4. Mallory cheats — and gets named (§10)

Every broadcast value is checked against public commitments by pure
point equality, so a wrong share is not merely rejected — it accuses
its sender:

```mermaid
sequenceDiagram
    participant A as Alice (honest)
    participant M as Mallory (faulty)
    participant B as Bob (honest)
    Note over A,B: Sign round, presig #7
    M->>A: s̃_M  (a wrong share!)
    M->>B: s̃_M
    Note over A: s̃_M·G ≠ EvalCom(A[s], M) ✗
    Note over B: same check fails ✗
    Note over A,B: Mallory is NAMED — no judge, no logs:<br/>the public commitment is the evidence (§11 C3)
    Note over A,B: robust mode (§10.4): exclude Mallory,<br/>s = λ_A·s_A + λ_B·s_B — signature still delivered ✓
```

Detection is *unconditional*: a Feldman check has exactly one passing
scalar per position, so a wrong share fails with probability 1.

## 5. Lost phone — recovery without changing the wallet (§13.4)

Committee maintenance keeps the public key (the address) fixed while
shares rotate:

```mermaid
sequenceDiagram
    participant P as 📱 Old phone (lost)
    participant S as ☁️ Service
    participant R as 🏦 Recovery
    participant N as 📱 New phone
    P--xS: (gone)
    Note over S,R: 1. reshare (§13.4): the remaining committee<br/>re-shares x to {Service, Recovery, New phone}
    S->>N: sub-share (verified vs public commitments)
    R->>N: sub-share (verified vs public commitments)
    Note over N: new share — SAME public key X<br/>wallet address unchanged
    Note over S,R: 2. presignature stores cleared (§8.6),<br/>pool restocked for the new epoch
    Note over P: the lost phone's shares are now useless
```

The same machinery covers proactive **refresh** (same committee, new
shares every epoch) and **committee change** (new operators, same key).

---

*Diagrams are Mermaid; they render natively on GitHub. Runnable versions
of stories 3–5: `cargo run --example wallet_2_of_3`,
`identifiable_abort`, `epoch_refresh`.*
