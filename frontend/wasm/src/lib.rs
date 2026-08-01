//! wasm-bindgen wrapper over the `ohm-ecdsa` core for the no-build
//! explainer site (`frontend/`). Exposes REAL protocol values (no canned
//! data) under deterministic seeds, mirroring the repo's test convention
//! (`sim::make_rngs`) so page runs are reproducible.
//!
//! The core is serde-free, so return values are built as `js_sys`
//! objects by hand. All curve arithmetic stays in Rust/k256 — the page
//! never re-implements secp256k1.

#![forbid(unsafe_code)]

use js_sys::{Array, Object, Reflect};
use k256::ecdsa::signature::Verifier;
use k256::ecdsa::VerifyingKey;
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use ohm_ecdsa::dkg::DkgTamper;
use ohm_ecdsa::presign::PresignTamper;
use ohm_ecdsa::shamir::{interpolate_at_zero, ShamirPoly};
use ohm_ecdsa::triples::{self, TripleTamper};
use ohm_ecdsa::vss::FeldmanCommitment;
use ohm_ecdsa::{sign, sim, Error, Params, PartyId, Phase};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use wasm_bindgen::prelude::*;

// --- hex + scalar helpers ---------------------------------------------------

fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>, JsError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err(JsError::new("odd-length hex"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| JsError::new("non-hex character"))
        })
        .collect()
}

fn scalar_to_hex(s: &Scalar) -> String {
    hex_encode(&s.to_bytes())
}

fn scalar_from_hex(hex: &str) -> Result<Scalar, JsError> {
    let bytes = hex_decode(hex)?;
    if bytes.len() != 32 {
        return Err(JsError::new("a scalar is exactly 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Option::<Scalar>::from(Scalar::from_repr(arr.into()))
        .ok_or_else(|| JsError::new("not a canonical secp256k1 scalar"))
}

fn point_to_hex(p: &ProjectivePoint) -> String {
    hex_encode(p.to_affine().to_encoded_point(true).as_bytes())
}

fn point_from_hex(hex: &str) -> Result<ProjectivePoint, JsError> {
    let bytes = hex_decode(hex)?;
    let ep = EncodedPoint::from_bytes(&bytes).map_err(|_| JsError::new("bad SEC1 point"))?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep))
        .ok_or_else(|| JsError::new("point not on secp256k1"))?;
    Ok(ProjectivePoint::from(affine))
}

/// Low 64 bits as f64 — DISPLAY PROJECTION ONLY for the plot (exact for
/// values < 2^53; the small-coefficient demo dealing stays far below).
fn scalar_to_f64(s: &Scalar) -> f64 {
    let bytes = s.to_bytes();
    let mut v = 0u64;
    for b in &bytes[24..] {
        v = (v << 8) | *b as u64;
    }
    v as f64
}

fn set(obj: &Object, key: &str, value: &JsValue) {
    Reflect::set(obj, &JsValue::from_str(key), value).expect("Reflect::set on a plain object");
}

fn hex_array(items: &[String]) -> Array {
    let out = Array::new();
    for h in items {
        out.push(&JsValue::from_str(h));
    }
    out
}

// --- the 2-of-3 committee keygen (real protocol code) ------------------------

/// Run the REAL 2-of-3 keygen (SPEC §6 via `sim::run_keygen`) under a
/// deterministic seed. Returns `{ x, commitment, parties }`: the joint
/// key X (SEC1 compressed hex), the Feldman commitment points to the
/// joint sharing polynomial, and each party's `{ index, share }`.
#[wasm_bindgen]
pub fn keygen(seed: u64) -> Result<JsValue, JsError> {
    let params = Params::new(3, 2).map_err(|e| JsError::new(&e.to_string()))?;
    let mut rngs = sim::make_rngs(3, seed);
    let keys = sim::run_keygen(&params, b"frontend/keygen", &mut rngs)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let out = Object::new();
    set(
        &out,
        "x",
        &JsValue::from_str(&point_to_hex(&keys[0].com.points[0])),
    );
    set(
        &out,
        "commitment",
        &hex_array(
            &keys[0]
                .com
                .points
                .iter()
                .map(point_to_hex)
                .collect::<Vec<_>>(),
        ),
    );
    let parties = Array::new();
    for k in &keys {
        let p = Object::new();
        set(&p, "index", &JsValue::from(k.index as u32));
        set(&p, "share", &JsValue::from_str(&scalar_to_hex(&k.share)));
        parties.push(&p);
    }
    set(&out, "parties", &parties);
    Ok(out.into())
}

// --- Shamir + Feldman demo ---------------------------------------------------

/// Deal a Shamir sharing (SPEC §4.1) of `secret_hex` with threshold `t`
/// over parties `1..=n`, plus its Feldman commitment (§4.2).
///
/// PLOT PROJECTION (documented on the page): the non-constant
/// coefficients are dealt SMALL (32-bit) scalars so the polynomial is
/// drawable over the reals — every check (Feldman verify, Lagrange
/// reconstruct) still runs over the full secp256k1 field. An empty
/// `secret_hex` derives a small secret from `seed` (also plot-friendly).
///
/// Returns `{ secret, coeffs, coeffsNum, commitment, shares }` with
/// shares as `{ id, hex, num }`; the `*Num` fields are the f64 display
/// projection (see `scalar_to_f64`).
#[wasm_bindgen]
pub fn shamir_demo(secret_hex: &str, t: usize, n: usize, seed: u64) -> Result<JsValue, JsError> {
    if t < 1 || t > n || n > 12 {
        return Err(JsError::new("need 1 <= t <= n <= 12"));
    }
    let mut rng = StdRng::seed_from_u64(seed);
    let secret = if secret_hex.is_empty() {
        Scalar::from(rng.next_u32() as u64) // small, plot-friendly
    } else {
        scalar_from_hex(secret_hex)?
    };
    // Small non-constant coefficients (see the doc header) — dealt via
    // the core's ShamirPoly type; the math is the full field's.
    let mut coeffs = Vec::with_capacity(t);
    coeffs.push(secret);
    for _ in 1..t {
        coeffs.push(Scalar::from(rng.next_u32() as u64));
    }
    let poly = ShamirPoly { coeffs };
    let com = FeldmanCommitment::from_poly(&poly);

    let out = Object::new();
    set(&out, "secret", &JsValue::from_str(&scalar_to_hex(&secret)));
    set(
        &out,
        "coeffs",
        &hex_array(&poly.coeffs.iter().map(scalar_to_hex).collect::<Vec<_>>()),
    );
    let coeffs_num = Array::new();
    for c in &poly.coeffs {
        coeffs_num.push(&JsValue::from(scalar_to_f64(c)));
    }
    set(&out, "coeffsNum", &coeffs_num);
    set(
        &out,
        "commitment",
        &hex_array(&com.points.iter().map(point_to_hex).collect::<Vec<_>>()),
    );
    let shares = Array::new();
    for j in 1..=n {
        let share = poly.eval(j);
        let s = Object::new();
        set(&s, "id", &JsValue::from(j as u32));
        set(&s, "hex", &JsValue::from_str(&scalar_to_hex(&share)));
        set(&s, "num", &JsValue::from(scalar_to_f64(&share)));
        shares.push(&s);
    }
    set(&out, "shares", &shares);
    Ok(out.into())
}

/// Feldman share verification (SPEC §4.2): `share·G == EvalCom(A, id)`
/// by point equality against the commitment (SEC1 hex array). This is
/// the primitive behind identifiable abort (§10) — a wrong share fails
/// publicly.
#[wasm_bindgen]
pub fn verify_share(commitment: JsValue, id: u32, share_hex: &str) -> Result<bool, JsError> {
    let arr: Array = commitment
        .dyn_into()
        .map_err(|_| JsError::new("commitment must be an array of SEC1 hex strings"))?;
    let mut points = Vec::with_capacity(arr.length() as usize);
    for h in arr.iter() {
        let h = h
            .as_string()
            .ok_or_else(|| JsError::new("commitment entry not a string"))?;
        points.push(point_from_hex(&h)?);
    }
    if id < 1 {
        return Err(JsError::new("party indices start at 1; 0 is the secret"));
    }
    let com = FeldmanCommitment { points };
    let share = scalar_from_hex(share_hex)?;
    Ok(com.verify_share(id as PartyId, &share))
}

/// Lagrange interpolation at 0 (SPEC §4.1): reconstruct the secret
/// from the given `(id, share)` pairs. Errors when fewer than `t`
/// shares are selected — below the threshold the secret is
/// information-theoretically hidden.
#[wasm_bindgen]
pub fn reconstruct(t: usize, ids: Vec<u32>, shares_hex: Vec<String>) -> Result<String, JsError> {
    if ids.len() != shares_hex.len() {
        return Err(JsError::new("ids and shares must pair up"));
    }
    if ids.len() < t {
        return Err(JsError::new("cannot reconstruct: need t shares"));
    }
    let parties: Vec<PartyId> = ids.iter().map(|i| *i as PartyId).collect();
    if parties.iter().any(|&j| j < 1) {
        return Err(JsError::new("party indices start at 1; 0 is the secret"));
    }
    let mut shares = Vec::with_capacity(shares_hex.len());
    for h in &shares_hex {
        shares.push(scalar_from_hex(h)?);
    }
    Ok(scalar_to_hex(&interpolate_at_zero(&parties, &shares)))
}

// --- F2: the full protocol arc ----------------------------------------------

/// Demo message signed by the arc (fixed so the page can narrate it).
const ARC_MESSAGE: &[u8] = b"OHM-ECDSA protocol arc demo message";

fn phase_name(phase: Phase) -> &'static str {
    match phase {
        Phase::KeyGen => "keygen",
        Phase::Triples => "triples",
        Phase::Presign => "presign",
        Phase::Sign => "sign",
        _ => "other",
    }
}

fn abort_object(
    fault: &str,
    fault_class: &str,
    check: &str,
    abort: &ohm_ecdsa::IdentifiableAbort,
) -> JsValue {
    let out = Object::new();
    set(&out, "fault", &JsValue::from_str(fault));
    set(&out, "faultClass", &JsValue::from_str(fault_class));
    set(&out, "check", &JsValue::from_str(check));
    set(&out, "phase", &JsValue::from_str(phase_name(abort.phase)));
    let blamed = Array::new();
    for b in &abort.blamed {
        blamed.push(&JsValue::from(*b as u32));
    }
    set(&out, "blamed", &blamed);
    set(&out, "detail", &JsValue::from_str(&abort.detail));
    out.into()
}

fn parties_shares(entries: &[(u32, String)]) -> Array {
    let out = Array::new();
    for (index, hex) in entries {
        let p = Object::new();
        set(&p, "index", &JsValue::from(*index));
        set(&p, "share", &JsValue::from_str(hex));
        out.push(&p);
    }
    out
}

fn com_hex(com: &FeldmanCommitment) -> Array {
    hex_array(&com.points.iter().map(point_to_hex).collect::<Vec<_>>())
}

/// The honest 2-of-3 full arc (SPEC §6 → §7 → §8 → §9) under one seed:
/// keygen, one Beaver triple, one presignature, one signature — all via
/// the core's sim drivers. Returns one object with a key per phase;
/// every value is a truncated-display hex string (full 32-byte hex) or
/// a boolean computed by the core's own checks. Marshalling only.
#[wasm_bindgen]
pub fn full_arc(seed: u64) -> Result<JsValue, JsError> {
    let params = Params::new(3, 2).map_err(|e| JsError::new(&e.to_string()))?;
    let mut rngs = sim::make_rngs(3, seed);

    // §6 keygen.
    let keys = sim::run_keygen(&params, b"frontend/arc/keygen", &mut rngs)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let x = keys[0].com.points[0];
    let keygen = Object::new();
    set(&keygen, "x", &JsValue::from_str(&point_to_hex(&x)));
    set(&keygen, "commitment", &com_hex(&keys[0].com));
    set(
        &keygen,
        "parties",
        &parties_shares(
            &keys
                .iter()
                .map(|k| (k.index as u32, scalar_to_hex(&k.share)))
                .collect::<Vec<_>>(),
        ),
    );

    // §7 one Beaver triple.
    let triple = triples::generate(&params, b"frontend/arc/triples", &mut rngs)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let parties: Vec<PartyId> = vec![1, 2, 3];
    let a0 = interpolate_at_zero(
        &parties,
        &triple.iter().map(|(s, _)| s.a).collect::<Vec<_>>(),
    );
    let b0 = interpolate_at_zero(
        &parties,
        &triple.iter().map(|(s, _)| s.b).collect::<Vec<_>>(),
    );
    let c0 = interpolate_at_zero(
        &parties,
        &triple.iter().map(|(s, _)| s.c).collect::<Vec<_>>(),
    );
    let triples_obj = Object::new();
    // The T3 DLEQ product proofs all verified — generate() aborts
    // otherwise (§7.3); the multiplicativity badge is the recombined
    // identity a·b == c.
    set(&triples_obj, "proofsVerified", &JsValue::from(true));
    set(
        &triples_obj,
        "multiplicative",
        &JsValue::from(a0 * b0 == c0),
    );
    set(
        &triples_obj,
        "parties",
        &triple
            .iter()
            .map(|(s, _)| {
                let p = Object::new();
                set(&p, "index", &JsValue::from(s.index as u32));
                set(&p, "a", &JsValue::from_str(&scalar_to_hex(&s.a)));
                set(&p, "b", &JsValue::from_str(&scalar_to_hex(&s.b)));
                set(&p, "c", &JsValue::from_str(&scalar_to_hex(&s.c)));
                JsValue::from(p)
            })
            .collect::<Array>(),
    );
    set(&triples_obj, "ca", &com_hex(&triple[0].1.ca));
    set(&triples_obj, "cb", &com_hex(&triple[0].1.cb));
    set(&triples_obj, "cc", &com_hex(&triple[0].1.cc));

    // §8 one presignature.
    let presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let meta = &presigs[0];
    let presign = Object::new();
    set(&presign, "id", &JsValue::from(meta.id as u32));
    set(&presign, "r", &JsValue::from_str(&scalar_to_hex(&meta.r)));
    set(
        &presign,
        "bigR",
        &JsValue::from_str(&point_to_hex(&meta.big_r.into())),
    );
    set(&presign, "uCom", &com_hex(&meta.u_com));
    set(&presign, "zCom", &com_hex(&meta.z_com));
    set(
        &presign,
        "parties",
        &presigs
            .iter()
            .map(|p| {
                let o = Object::new();
                set(&o, "index", &JsValue::from(p.index as u32));
                set(&o, "uShare", &JsValue::from_str(&scalar_to_hex(&p.u_share)));
                set(&o, "zShare", &JsValue::from_str(&scalar_to_hex(&p.z_share)));
                JsValue::from(o)
            })
            .collect::<Array>(),
    );

    // §9 one-round sign.
    let m = sim::message_scalar(ARC_MESSAGE);
    let sig = sim::run_sign(&params, &presigs, ARC_MESSAGE, None)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let vk = VerifyingKey::from_sec1_bytes(x.to_affine().to_encoded_point(false).as_bytes())
        .map_err(|_| JsError::new("joint key not a valid point"))?;
    let verified = vk.verify(ARC_MESSAGE, &sig).is_ok();
    let low_s = !bool::from(sig.s().is_high());
    let sign_obj = Object::new();
    set(
        &sign_obj,
        "message",
        &JsValue::from_str(std::str::from_utf8(ARC_MESSAGE).unwrap()),
    );
    set(&sign_obj, "m", &JsValue::from_str(&scalar_to_hex(&m)));
    set(
        &sign_obj,
        "shares",
        &presigs
            .iter()
            .map(|p| {
                let sh = sign::sign_share(p, &m);
                let o = Object::new();
                set(&o, "index", &JsValue::from(sh.from as u32));
                set(&o, "s", &JsValue::from_str(&scalar_to_hex(&sh.s)));
                JsValue::from(o)
            })
            .collect::<Array>(),
    );
    set(
        &sign_obj,
        "r",
        &JsValue::from_str(&hex_encode(&sig.r().to_bytes())),
    );
    set(
        &sign_obj,
        "s",
        &JsValue::from_str(&hex_encode(&sig.s().to_bytes())),
    );
    set(&sign_obj, "verified", &JsValue::from(verified));
    set(&sign_obj, "lowS", &JsValue::from(low_s));

    let out = Object::new();
    set(&out, "keygen", &keygen);
    set(&out, "triples", &triples_obj);
    set(&out, "presign", &presign);
    set(&out, "sign", &sign_obj);
    Ok(out.into())
}

/// The same arc with ONE injected fault (SPEC §10 blame matrix — the
/// blamed ids mirror `tests/blame_matrix.rs` ground truth):
/// `bad-deal` (F2, keygen), `bad-product-proof` (F3, triples),
/// `bad-open-share` (F4, presign P2), `bad-nonce-point` (F5, presign
/// P3), `bad-sign-share` (F6, sign). Returns the abort the core raises:
/// `{ fault, faultClass, check, phase, blamed, detail }`.
#[wasm_bindgen]
pub fn arc_with_tamper(seed: u64, phase: String, party: usize) -> Result<JsValue, JsError> {
    if !(1..=3).contains(&party) {
        return Err(JsError::new("party must be 1, 2, or 3"));
    }
    let params = Params::new(3, 2).map_err(|e| JsError::new(&e.to_string()))?;
    let mut rngs = sim::make_rngs(3, seed);

    let honest_keygen =
        |rngs: &mut Vec<StdRng>| -> Result<Vec<ohm_ecdsa::presign::KeyShare>, JsError> {
            sim::run_keygen(&params, b"frontend/arc/keygen", rngs)
                .map_err(|e| JsError::new(&e.to_string()))
        };

    match phase.as_str() {
        // F2 (SPEC §10.1): a dealer computes a wrong share; its §6.1
        // defense fails verification, so the DEALER is blamed.
        "bad-deal" => {
            let victim = party % 3 + 1;
            let tamper = DkgTamper {
                bad_deal: Some((party, victim)),
                ..Default::default()
            };
            let abort = expect_abort(
                sim::run_keygen_with_tamper(&params, b"frontend/arc/keygen", &mut rngs, Some(&tamper)),
                "bad-deal",
            )?;
            Ok(abort_object(
                "bad-deal",
                "F2",
                "share·G == EvalCom(A, victim) — the §6.1 complaint/defense check",
                &abort,
            ))
        }
        // F3: an invalid DLEQ product proof in T2; the prover is blamed.
        "bad-product-proof" => {
            let tamper = TripleTamper {
                bad_product_proof: Some(party),
                ..Default::default()
            };
            let abort = expect_abort(
                triples::generate_with_tamper(&params, b"frontend/arc/triples", &mut rngs, Some(&tamper)),
                "bad-product-proof",
            )?;
            Ok(abort_object(
                "bad-product-proof",
                "F3",
                "Chaum–Pedersen DLEQ product proof verification (T3, §7.3)",
                &abort,
            ))
        }
        // F4: a wrong opening share in the P2 v opening; the sender is blamed.
        "bad-open-share" => {
            let keys = honest_keygen(&mut rngs)?;
            let tamper = PresignTamper {
                bad_open_share: Some(party),
                ..Default::default()
            };
            let abort = expect_abort(
                sim::run_presign(&params, &keys, 1, &mut rngs, Some(&tamper)),
                "bad-open-share",
            )?;
            Ok(abort_object(
                "bad-open-share",
                "F4",
                "opening share vs commitment: v_j·G == EvalCom(A, j) (P2 opening of v)",
                &abort,
            ))
        }
        // F5: a wrong nonce point in P3; R_j ≠ EvalCom(A[k], j) names the sender.
        "bad-nonce-point" => {
            let keys = honest_keygen(&mut rngs)?;
            let tamper = PresignTamper {
                bad_nonce_point: Some(party),
                ..Default::default()
            };
            let abort = expect_abort(
                sim::run_presign(&params, &keys, 1, &mut rngs, Some(&tamper)),
                "bad-nonce-point",
            )?;
            Ok(abort_object(
                "bad-nonce-point",
                "F5",
                "nonce point check: R_j == EvalCom(A[k], j) (P3)",
                &abort,
            ))
        }
        // F6: a wrong signature share; s_j·G ≠ EvalCom(m·A[u]+r·A[z], j)
        // names the sender.
        "bad-sign-share" => {
            let keys = honest_keygen(&mut rngs)?;
            let presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None)
                .map_err(|e| JsError::new(&e.to_string()))?;
            let m = sim::message_scalar(ARC_MESSAGE);
            let real = sign::sign_share(&presigs[party - 1], &m).s;
            let abort = expect_abort(
                sim::run_sign(&params, &presigs, ARC_MESSAGE, Some((party, real + Scalar::ONE))),
                "bad-sign-share",
            )?;
            Ok(abort_object(
                "bad-sign-share",
                "F6",
                "signature share check: s_j·G == EvalCom(m·A[u] + r·A[z], j) (S2)",
                &abort,
            ))
        }
        other => Err(JsError::new(&format!(
            "unknown fault {other:?}; use bad-deal | bad-product-proof | bad-open-share | bad-nonce-point | bad-sign-share"
        ))),
    }
}

/// Extract the [`ohm_ecdsa::IdentifiableAbort`] from a tampered run, or
/// explain why it did not abort (a test would catch this — the blame
/// matrix is the ground truth).
fn expect_abort<T>(
    r: Result<T, Error>,
    what: &str,
) -> Result<ohm_ecdsa::IdentifiableAbort, JsError> {
    match r {
        Err(Error::Abort { abort }) => Ok(abort),
        Err(e) => Err(JsError::new(&format!(
            "{what}: expected identifiable abort, got {e}"
        ))),
        Ok(_) => Err(JsError::new(&format!(
            "{what}: expected abort, the run completed"
        ))),
    }
}
