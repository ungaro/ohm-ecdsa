//! §4.7 signed-echo consistent broadcast — regression tests for the
//! reviewer attack on the superseded `⌈(n+1)/2⌉` majority-echo rule
//! (inconsistent at `T ≥ 3`: two size-`T` quorums of `n = 2T−1` may
//! intersect only in corrupt parties). The corrupt committee members
//! are driven by hand-crafted frames over raw TCP (the test holds their
//! keys); the honest parties run unmodified `PartyNode`s.

use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::Duration;

use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::SecretKey;
use ohm_ecdsa::dkg::DkgBcast1;
use ohm_ecdsa::transport::{DkgMessage, Encode, Envelope, SignedEnvelope};
use ohm_ecdsa::{IdentifiableAbort, Params, PartyId, Phase};
use ohm_ecdsa_node::persist::audit_token;
use ohm_ecdsa_node::wire::write_frame;
use ohm_ecdsa_node::{BlameEvidence, NodePayload, PartyNode, WireMessage};
use rand::rngs::StdRng;
use rand::SeedableRng;

const ROUND_TIMEOUT: Duration = Duration::from_secs(3);

/// Deterministic transport keys + the public registry.
fn keys(seed: u64, n: usize) -> (Vec<SecretKey>, BTreeMap<PartyId, VerifyingKey>) {
    let mut kr = StdRng::seed_from_u64(seed);
    let keys: Vec<SecretKey> = (0..n).map(|_| SecretKey::random(&mut kr)).collect();
    let registry = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (i + 1, *SigningKey::from(k).verifying_key()))
        .collect();
    (keys, registry)
}

fn commit_payload(from: PartyId, byte: u8) -> NodePayload {
    NodePayload::Dkg(DkgMessage::Commit(DkgBcast1 {
        from,
        hash: [byte; 32],
    }))
}

/// The canonical encoding of one accepted set, for cross-node comparison.
#[allow(clippy::type_complexity)]
fn encoded_set(set: &BTreeMap<PartyId, SignedEnvelope<NodePayload>>) -> Vec<(PartyId, Vec<u8>)> {
    set.iter()
        .map(|(&id, se)| {
            let mut bytes = Vec::new();
            se.encode(&mut bytes);
            (id, bytes)
        })
        .collect()
}

/// The reviewer attack (n = 5, T = 3, f = 2): corrupt sender 1 signs two
/// conflicting broadcast values `v`/`v′` for the same slot and sends `v`
/// to honest 3,4 and `v′` to honest 5; corrupt echoer 2 echoes `v` to 3
/// and `v′` to 5. Under the old majority-echo rule, honest 3 could
/// accept `v` (echoes {3,4,2}) while honest 5 accepted nothing — the
/// accepted sets silently split. Under the §4.7 signed-echo rule every
/// honest node sees both sender-signed values (honest 5 echoes `v′` to
/// all, honest 3,4 echo `v` to all), poisons sender 1 for the session,
/// and outputs ⊥ for its slot — with the two signed envelopes kept as
/// offline-verifiable blame evidence (§10.1 F8).
#[test]
fn equivocating_sender_never_splits_honest_acceptance() {
    let params = Params::new(5, 3).unwrap();
    let (keys, registry) = keys(700, 5);
    let sid = b"sid/echo-attack".to_vec();

    // Honest nodes 3, 4, 5: unmodified PartyNodes, meshed among
    // themselves (the corrupt 1,2 never run a node — the test injects
    // their frames over raw TCP below).
    let nodes: Vec<PartyNode> = (3..=5usize)
        .map(|id| {
            PartyNode::bind(
                id,
                params,
                &keys[id - 1],
                registry.clone(),
                SocketAddr::from(([127, 0, 0, 1], 0)),
                ROUND_TIMEOUT,
            )
            .unwrap()
        })
        .collect();
    let addrs: Vec<(PartyId, SocketAddr)> =
        nodes.iter().map(|n| (n.id(), n.local_addr())).collect();
    for node in &nodes {
        node.connect(&addrs).unwrap();
    }

    // Honest driver threads: broadcast the node's own round-1 value and
    // collect the round's accepted set (party 2 is silent, so the round
    // ends on the timeout path — by which every echo has propagated).
    let mut threads = Vec::new();
    for node in nodes.into_iter() {
        let sid = sid.clone();
        threads.push(thread::spawn(move || {
            let id = node.id();
            node.broadcast(&sid, Phase::KeyGen, 1, commit_payload(id, id as u8));
            let set = node.accepted_broadcasts(&sid, Phase::KeyGen, 1);
            let evidence = node.equivocation_evidence(&sid);
            (id, set, evidence)
        }));
    }

    // Let the mesh and the honest broadcasts settle, then inject the
    // attack: sender 1's conflicting signed values + echoer 2's
    // colluding echoes.
    thread::sleep(Duration::from_millis(500));
    let k1 = SigningKey::from(&keys[0]);
    let k2 = SigningKey::from(&keys[1]);
    let env_v = SignedEnvelope::sign(
        Envelope::broadcast(&sid, Phase::KeyGen, 1, 1, commit_payload(1, 0xAA)),
        &k1,
    );
    let env_w = SignedEnvelope::sign(
        Envelope::broadcast(&sid, Phase::KeyGen, 1, 1, commit_payload(1, 0xBB)),
        &k1,
    );
    let mut socks = Vec::new();
    let mut inject = |to: SocketAddr, msg: WireMessage<NodePayload>| {
        let mut sock = TcpStream::connect(to).unwrap();
        write_frame(&mut sock, &msg).unwrap();
        socks.push(sock);
    };
    inject(addrs[0].1, WireMessage::Original(env_v.clone())); // → 3
    inject(addrs[1].1, WireMessage::Original(env_v.clone())); // → 4
    inject(addrs[2].1, WireMessage::Original(env_w.clone())); // → 5
    inject(addrs[0].1, WireMessage::echo(2, env_v.clone(), &k2)); // → 3
    inject(addrs[2].1, WireMessage::echo(2, env_w.clone(), &k2)); // → 5

    let outcomes: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    drop(socks);

    // (1) Consistency: all three honest nodes hold the SAME accepted
    //     set — no two honest parties accepted different values, and the
    //     equivocating sender is ⊥ everywhere (party 2 is silent).
    let reference = encoded_set(&outcomes[0].1);
    for (id, set, _) in &outcomes {
        assert_eq!(
            encoded_set(set),
            reference,
            "honest node {id} accepted a different set than node {}",
            outcomes[0].0
        );
        assert!(
            !set.contains_key(&1),
            "node {id} accepted a value from the equivocating sender"
        );
        assert!(
            !set.contains_key(&2),
            "node {id} accepted a value from the silent party"
        );
        // Positive path under attack: the honest 3,4,5 values ARE accepted.
        for honest in 3..=5 {
            assert!(
                set.contains_key(&honest),
                "node {id} lost honest party {honest}"
            );
        }
    }

    // (2) Blame with evidence: every honest node detected the
    //     equivocation and kept the two conflicting sender-signed
    //     envelopes — same slot, distinct values, both verifying under
    //     party 1's key.
    let party_keys: Vec<(PartyId, VerifyingKey)> = registry.iter().map(|(p, k)| (*p, *k)).collect();
    for (id, _, evidence) in &outcomes {
        let equivocations: Vec<_> = evidence.iter().filter(|(from, _)| *from == 1).collect();
        assert_eq!(
            equivocations.len(),
            1,
            "node {id} holds no equivocation evidence for party 1"
        );
        let (_, (first, second)) = equivocations[0];
        let k1v = &registry[&1];
        assert!(first.verify_signature(k1v));
        assert!(second.verify_signature(k1v));
        assert_eq!(first.envelope.sid, second.envelope.sid);
        assert_eq!(first.envelope.phase, second.envelope.phase);
        assert_eq!(first.envelope.round, second.envelope.round);
        assert_eq!(first.envelope.from, 1);
        assert_eq!(second.envelope.from, 1);
        let (mut fa, mut fb) = (Vec::new(), Vec::new());
        first.encode(&mut fa);
        second.encode(&mut fb);
        assert_ne!(fa, fb, "the two signed values must conflict");

        // (3) Offline-verifiable (§10.2/§A.4): the blame token audits VALID.
        let abort = IdentifiableAbort {
            phase: Phase::KeyGen,
            blamed: vec![1],
            detail: "broadcast equivocation (§4.7 rule (3))".to_string(),
        };
        let token = BlameEvidence::Equivocation {
            abort,
            first: first.clone(),
            second: second.clone(),
        };
        let report = audit_token(&token.encode(), &party_keys);
        for (what, ok) in &report.checks {
            assert!(ok, "node {id}'s token failed audit check: {what}");
        }
        assert!(report.verdict());
        assert_eq!(report.blamed, vec![1]);
    }
}

/// Non-sender "equivocation": a corrupt party echoes a value the sender
/// never signed. The echo embeds the claimed original, so the sender's
/// missing/invalid signature fails verification at the mesh — the frame
/// is dropped and counted, and the honest session completes unaffected.
#[test]
fn echo_of_unsigned_value_is_dropped_and_honest_keygen_completes() {
    let params = Params::new(3, 2).unwrap();
    let (keys, registry) = keys(701, 3);
    let nodes: Vec<PartyNode> = (1..=3usize)
        .map(|id| {
            PartyNode::bind(
                id,
                params,
                &keys[id - 1],
                registry.clone(),
                SocketAddr::from(([127, 0, 0, 1], 0)),
                ROUND_TIMEOUT,
            )
            .unwrap()
        })
        .collect();
    let addrs: Vec<(PartyId, SocketAddr)> =
        nodes.iter().map(|n| (n.id(), n.local_addr())).collect();
    for node in &nodes {
        node.connect(&addrs).unwrap();
    }

    // Party 3 "echoes" a round-1 commit claiming to be from party 1 but
    // signed with PARTY 3's key — the embedded original fails the
    // sender-signature check, so the echo is dropped + counted (the
    // echoer's signature on the frame makes it attributable).
    let forged_original = SignedEnvelope::sign(
        Envelope::broadcast(
            b"sid/echo-forge",
            Phase::KeyGen,
            1,
            1,
            commit_payload(1, 0xCC),
        ),
        &SigningKey::from(&keys[2]),
    );
    let forged_echo = WireMessage::echo(3, forged_original, &SigningKey::from(&keys[2]));
    let mut socks = Vec::new();
    for (_, addr) in &addrs {
        let mut sock = TcpStream::connect(addr).unwrap();
        write_frame(&mut sock, &forged_echo).unwrap();
        socks.push(sock);
    }

    // The honest keygen completes: forged echoes never reach the acceptor.
    let mut threads = Vec::new();
    for (k, node) in nodes.into_iter().enumerate() {
        let id = k + 1;
        threads.push(thread::spawn(move || {
            let mut rng = StdRng::seed_from_u64(702 + id as u64);
            let result = node.keygen(b"sid/echo-forge", b"echo-test/dkg", &mut rng, None);
            let metrics = node.metrics();
            (id, result.map(|_| ()), metrics)
        }));
    }
    let outcomes: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    drop(socks);
    for (id, result, metrics) in &outcomes {
        assert!(
            result.is_ok(),
            "honest keygen failed at node {id}: {result:?}"
        );
        assert!(
            metrics.dropped_bad_signature >= 1,
            "node {id} did not drop the echo of the unsigned value"
        );
    }
}
