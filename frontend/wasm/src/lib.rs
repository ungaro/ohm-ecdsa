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
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use ohm_ecdsa::shamir::{interpolate_at_zero, ShamirPoly};
use ohm_ecdsa::vss::FeldmanCommitment;
use ohm_ecdsa::{sim, Params, PartyId};
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
    set(&out, "x", &JsValue::from_str(&point_to_hex(&keys[0].com.points[0])));
    set(
        &out,
        "commitment",
        &hex_array(&keys[0].com.points.iter().map(point_to_hex).collect::<Vec<_>>()),
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
pub fn shamir_demo(
    secret_hex: &str,
    t: usize,
    n: usize,
    seed: u64,
) -> Result<JsValue, JsError> {
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
        let h = h.as_string().ok_or_else(|| JsError::new("commitment entry not a string"))?;
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
pub fn reconstruct(
    t: usize,
    ids: Vec<u32>,
    shares_hex: Vec<String>,
) -> Result<String, JsError> {
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
