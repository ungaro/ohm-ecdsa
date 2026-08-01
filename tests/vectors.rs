//! Deterministic test-vector suite (SPEC §6/§8/§9).
//!
//! Every case regenerates its outputs from fixed `sim::make_rngs` seeds
//! (never OS randomness) through the reference sim drivers
//! (`sim::run_keygen` / `sim::run_presign` / `sim::run_sign`) and compares
//! the result BYTE-FOR-BYTE against a committed vector file under
//! `tests/vectors/`. The pinned surface is serialized with the crate's
//! canonical `Encode` wire format (length-prefixed, no serde): public key,
//! Feldman commitments, nonce points, the signature, presignature
//! metadata — and the per-party secret SHARES, which are the strongest
//! regression catch (a share byte flip is caught here before any protocol
//! property test notices).
//!
//! A second implementation can verify against the committed files: the
//! format is one `field=value` line per entry (hex values are lowercase,
//! multi-byte values in the canonical `Encode` form), `#` lines are
//! comments.
//!
//! Bless/update mode: when the environment variable
//! `OHM_BLESS_VECTORS=1` is set, the tests REWRITE the committed files
//! instead of comparing:
//!
//! ```sh
//! OHM_BLESS_VECTORS=1 cargo test -p ohm-ecdsa --test vectors
//! ```
//!
//! Every sign vector is additionally verified with k256's ECDSA verifier
//! against the vector's own public key and asserted low-s (BIP-62/EIP-2),
//! the independent verification path.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;
use k256::ProjectivePoint;

use ohm_ecdsa::presign::{KeyShare, Presignature};
use ohm_ecdsa::sim;
use ohm_ecdsa::transport::Encode;
use ohm_ecdsa::Params;

// --- case parameters (fixed forever — changing them changes the vectors) ---

const KEYGEN_2OF3_SEED: u64 = 42;
const KEYGEN_2OF3_SID: &[u8] = b"vectors/keygen/2of3/42";
const KEYGEN_3OF5_SEED: u64 = 7;
const KEYGEN_3OF5_SID: &[u8] = b"vectors/keygen/3of5/7";
const PRESIGN_SEED_ID1: u64 = 43;
const PRESIGN_SEED_ID2: u64 = 44;
const MSG1: &[u8] = b"ohm-ecdsa test vector";
const MSG2: &[u8] = b"ohm-ecdsa test vector #2";

const HEADER: &str = "# ohm-ecdsa test vector — DO NOT EDIT BY HAND\n\
                      # regenerate: OHM_BLESS_VECTORS=1 cargo test -p ohm-ecdsa --test vectors\n";

// --- hex + canonical-encode helpers -----------------------------------------

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex value must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex value must be valid hex"))
        .collect()
}

/// Canonical `Encode` serialization as lowercase hex.
fn enc_hex<T: Encode>(v: &T) -> String {
    let mut buf = Vec::new();
    v.encode(&mut buf);
    to_hex(&buf)
}

// --- vector file rendering / comparing / blessing ----------------------------

fn vector_path(case: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(format!("{case}.vec"))
}

fn render(fields: &[(String, String)]) -> String {
    let mut out = String::from(HEADER);
    for (k, v) in fields {
        out.push_str(k);
        out.push('=');
        out.push_str(v);
        out.push('\n');
    }
    out
}

fn parse(rendered: &str) -> BTreeMap<String, String> {
    rendered
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (k, v) = l.split_once('=').expect("vector lines are field=value");
            (k.to_string(), v.to_string())
        })
        .collect()
}

/// Compare `rendered` byte-for-byte with the committed file; with
/// `OHM_BLESS_VECTORS=1` rewrite the file instead.
fn check_or_bless(case: &str, rendered: &str) {
    let path = vector_path(case);
    if std::env::var_os("OHM_BLESS_VECTORS").is_some() {
        fs::write(&path, rendered)
            .unwrap_or_else(|e| panic!("cannot bless {}: {e}", path.display()));
        eprintln!("blessed {}", path.display());
        return;
    }
    let committed = fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "missing vector file {}; create it with \
             OHM_BLESS_VECTORS=1 cargo test -p ohm-ecdsa --test vectors",
            path.display()
        )
    });
    if committed != rendered {
        let diff = committed
            .lines()
            .zip(rendered.lines())
            .enumerate()
            .find(|(_, (a, b))| a != b)
            .map(|(i, (a, b))| {
                format!(
                    "first differing line {}:\ncommitted: {a}\nregenerated: {b}",
                    i + 1
                )
            })
            .unwrap_or_else(|| "line count differs".to_string());
        panic!(
            "test vector mismatch for case {case} ({diff})\n\
             if this change is intended, re-bless with \
             OHM_BLESS_VECTORS=1 cargo test -p ohm-ecdsa --test vectors"
        );
    }
}

// --- case builders ------------------------------------------------------------

fn keygen_2of3() -> (Params, Vec<KeyShare>) {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, KEYGEN_2OF3_SEED);
    let keys = sim::run_keygen(&params, KEYGEN_2OF3_SID, &mut rngs).unwrap();
    (params, keys)
}

fn keygen_fields(
    case: &str,
    n: usize,
    t: usize,
    seed: u64,
    sid: &[u8],
    keys: &[KeyShare],
) -> Vec<(String, String)> {
    let mut f: Vec<(String, String)> = vec![
        ("case".into(), case.into()),
        ("n".into(), n.to_string()),
        ("t".into(), t.to_string()),
        ("seed".into(), seed.to_string()),
        ("sid".into(), to_hex(sid)),
        ("pubkey".into(), enc_hex(&keys[0].com.points[0])),
    ];
    for k in keys {
        let p = format!("party{}", k.index);
        f.push((format!("{p}.index"), k.index.to_string()));
        // Secret share bytes: the strongest regression catch.
        f.push((format!("{p}.share"), enc_hex(&k.share)));
        f.push((format!("{p}.commitment"), enc_hex(&k.com)));
    }
    f
}

fn presign_2of3(id: u64, seed: u64) -> (Params, Vec<KeyShare>, Vec<Presignature>) {
    let (params, keys) = keygen_2of3();
    let mut rngs = sim::make_rngs(3, seed);
    let presigs = sim::run_presign(&params, &keys, id, &mut rngs, None).unwrap();
    (params, keys, presigs)
}

fn presign_fields(
    case: &str,
    id: u64,
    seed: u64,
    keys: &[KeyShare],
    presigs: &[Presignature],
) -> Vec<(String, String)> {
    let mut f: Vec<(String, String)> = vec![
        ("case".into(), case.into()),
        ("keygen_seed".into(), KEYGEN_2OF3_SEED.to_string()),
        ("keygen_sid".into(), to_hex(KEYGEN_2OF3_SID)),
        ("presign_seed".into(), seed.to_string()),
        ("presign_id".into(), id.to_string()),
        ("pubkey".into(), enc_hex(&keys[0].com.points[0])),
    ];
    for p in presigs {
        let q = format!("party{}", p.index);
        f.push((format!("{q}.id"), p.id.to_string()));
        f.push((format!("{q}.index"), p.index.to_string()));
        f.push((format!("{q}.r"), enc_hex(&p.r)));
        f.push((
            format!("{q}.big_r"),
            enc_hex(&ProjectivePoint::from(p.big_r)),
        ));
        // Secret share bytes: the strongest regression catch.
        f.push((format!("{q}.u_share"), enc_hex(&p.u_share)));
        f.push((format!("{q}.z_share"), enc_hex(&p.z_share)));
        f.push((format!("{q}.u_com"), enc_hex(&p.u_com)));
        f.push((format!("{q}.z_com"), enc_hex(&p.z_com)));
    }
    f
}

fn sign_fields(
    case: &str,
    presign_id: u64,
    msg: &[u8],
    keys: &[KeyShare],
    sig: &Signature,
) -> Vec<(String, String)> {
    vec![
        ("case".into(), case.into()),
        ("presign_id".into(), presign_id.to_string()),
        ("message".into(), to_hex(msg)),
        ("pubkey".into(), enc_hex(&keys[0].com.points[0])),
        ("signature".into(), enc_hex(sig)),
        ("r".into(), to_hex(&sig.r().to_bytes())),
        ("s".into(), to_hex(&sig.s().to_bytes())),
    ]
}

/// The independent verification path: parse the vector's own public key and
/// signature back and verify with k256, asserting low-s (BIP-62/EIP-2).
fn verify_sign_vector(case: &str, rendered: &str) {
    let v = parse(rendered);
    let vk =
        VerifyingKey::from_sec1_bytes(&from_hex(&v["pubkey"])).expect("vector pubkey must decode");
    let sig =
        Signature::from_slice(&from_hex(&v["signature"])).expect("vector signature must decode");
    let msg = from_hex(&v["message"]);
    vk.verify(&msg, &sig)
        .unwrap_or_else(|e| panic!("vector {case} signature must verify under its pubkey: {e}"));
    assert!(
        !bool::from(sig.s().is_high()),
        "vector {case} signature must be low-s (BIP-62/EIP-2)"
    );
}

// --- cases ---------------------------------------------------------------------

#[test]
fn vector_keygen_2_of_3() {
    let (_, keys) = keygen_2of3();
    let fields = keygen_fields(
        "keygen-2of3-seed42",
        3,
        2,
        KEYGEN_2OF3_SEED,
        KEYGEN_2OF3_SID,
        &keys,
    );
    check_or_bless("keygen-2of3-seed42", &render(&fields));
}

#[test]
fn vector_keygen_3_of_5() {
    let params = Params::new(5, 3).unwrap();
    let mut rngs = sim::make_rngs(5, KEYGEN_3OF5_SEED);
    let keys = sim::run_keygen(&params, KEYGEN_3OF5_SID, &mut rngs).unwrap();
    let fields = keygen_fields(
        "keygen-3of5-seed7",
        5,
        3,
        KEYGEN_3OF5_SEED,
        KEYGEN_3OF5_SID,
        &keys,
    );
    check_or_bless("keygen-3of5-seed7", &render(&fields));
}

#[test]
fn vector_presign_2_of_3_id1() {
    let (_, keys, presigs) = presign_2of3(1, PRESIGN_SEED_ID1);
    let fields = presign_fields("presign-2of3-id1", 1, PRESIGN_SEED_ID1, &keys, &presigs);
    check_or_bless("presign-2of3-id1", &render(&fields));
}

#[test]
fn vector_presign_2_of_3_id2() {
    let (_, keys, presigs) = presign_2of3(2, PRESIGN_SEED_ID2);
    let fields = presign_fields("presign-2of3-id2", 2, PRESIGN_SEED_ID2, &keys, &presigs);
    check_or_bless("presign-2of3-id2", &render(&fields));
}

#[test]
fn vector_sign_2_of_3_msg1() {
    let (params, keys, presigs) = presign_2of3(1, PRESIGN_SEED_ID1);
    let sig = sim::run_sign(&params, &presigs, MSG1, None).unwrap();
    let fields = sign_fields("sign-2of3-msg1", 1, MSG1, &keys, &sig);
    let rendered = render(&fields);
    check_or_bless("sign-2of3-msg1", &rendered);
    verify_sign_vector("sign-2of3-msg1", &rendered);
}

#[test]
fn vector_sign_2_of_3_msg2() {
    let (params, keys, presigs) = presign_2of3(2, PRESIGN_SEED_ID2);
    let sig = sim::run_sign(&params, &presigs, MSG2, None).unwrap();
    let fields = sign_fields("sign-2of3-msg2", 2, MSG2, &keys, &sig);
    let rendered = render(&fields);
    check_or_bless("sign-2of3-msg2", &rendered);
    verify_sign_vector("sign-2of3-msg2", &rendered);
}
