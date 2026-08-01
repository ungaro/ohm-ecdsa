// Smoke test for the wasm wrapper (run: `node smoke.mjs` from
// frontend/, after `wasm-pack build --target web --out-dir pkg wasm`).
// Asserts the F1 protocol surface end to end against the REAL core:
// keygen shape, Feldman verify (positive + perturbed), Lagrange
// reconstruct at t, and the below-threshold error.

import { readFileSync } from 'node:fs';
import init, * as wasm from './pkg/ohm_ecdsa_wasm.js';

await init({
  module_or_path: readFileSync(new URL('./pkg/ohm_ecdsa_wasm_bg.wasm', import.meta.url)),
});

let failures = 0;
function check(name, cond) {
  console.log(`${cond ? 'ok' : 'FAIL'}  ${name}`);
  if (!cond) failures++;
}

// --- keygen: 2-of-3 committee, X + 3 shares -------------------------------
const kg = wasm.keygen(42n);
check('keygen returns X (SEC1 compressed)', typeof kg.x === 'string' && /^(02|03)[0-9a-f]{64}$/.test(kg.x));
check('keygen returns 3 parties', kg.parties.length === 3);
check('keygen commitment has t=2 points', kg.commitment.length === 2);
check('keygen is deterministic', wasm.keygen(42n).x === kg.x);
check('keygen differs by seed', wasm.keygen(43n).x !== kg.x);

// --- shamir_demo + Feldman verify ------------------------------------------
const demo = wasm.shamir_demo('', 2, 3, 42n);
check('demo deals 3 shares', demo.shares.length === 3);
check('demo secret is 32-byte hex', /^[0-9a-f]{64}$/.test(demo.secret));

for (const s of demo.shares) {
  check(`share ${s.id} verifies`, wasm.verify_share(demo.commitment, s.id, s.hex) === true);
}
// Perturb share 1: flip the last byte — the Feldman check must FIRE.
const bad = demo.shares[0].hex.slice(0, -2) + (demo.shares[0].hex.endsWith('00') ? '01' : '00');
check('perturbed share fails verification', wasm.verify_share(demo.commitment, 1, bad) === false);

// --- reconstruct ------------------------------------------------------------
const rec = wasm.reconstruct(2, [1, 2], [demo.shares[0].hex, demo.shares[1].hex]);
check('reconstruct([1,2]) == dealt secret', rec === demo.secret);
const rec13 = wasm.reconstruct(2, [1, 3], [demo.shares[0].hex, demo.shares[2].hex]);
check('reconstruct([1,3]) == dealt secret', rec13 === demo.secret);
let errored = false;
try {
  wasm.reconstruct(2, [1], [demo.shares[0].hex]);
} catch (e) {
  errored = /need t shares/.test(String(e));
}
check('reconstruct([1]) errors "need t shares"', errored);
// A cheated share reconstructs a DIFFERENT secret (the §10 intuition).
const recBad = wasm.reconstruct(2, [1, 2], [bad, demo.shares[1].hex]);
check('cheated share yields a different secret', recBad !== demo.secret);

if (failures) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log('\nall smoke checks passed');

// --- F2: the full protocol arc -----------------------------------------------
const arc = wasm.full_arc(42n);
check('arc keygen: X + 3 parties', /^(02|03)/.test(arc.keygen.x) && arc.keygen.parties.length === 3);
check('arc triples: multiplicative a·b == c', arc.triples.multiplicative === true);
check('arc triples: DLEQ proofs verified', arc.triples.proofsVerified === true);
check('arc presign: id + R + r', arc.presign.id === 1 && /^[0-9a-f]{64}$/.test(arc.presign.r) && /^(02|03)/.test(arc.presign.bigR));
check('arc sign: 3 shares + (r, s)', arc.sign.shares.length === 3 && /^[0-9a-f]{64}$/.test(arc.sign.r) && /^[0-9a-f]{64}$/.test(arc.sign.s));
check('arc sign: k256-verified + low-s', arc.sign.verified === true && arc.sign.lowS === true);
check('arc is deterministic', wasm.full_arc(42n).sign.s === arc.sign.s);

// --- F2: sabotage — the blame matrix ground truth -----------------------------
const tampers = [
  ['bad-deal', 2, 'F2', 'keygen', [2]],
  ['bad-deal', 3, 'F2', 'keygen', [3]],
  ['bad-product-proof', 1, 'F3', 'triples', [1]],
  ['bad-open-share', 2, 'F4', 'presign', [2]],
  ['bad-nonce-point', 3, 'F5', 'presign', [3]],
  ['bad-sign-share', 1, 'F6', 'sign', [1]],
  ['bad-sign-share', 3, 'F6', 'sign', [3]],
];
for (const [fault, party, fclass, phase, blamed] of tampers) {
  const a = wasm.arc_with_tamper(42n, fault, party);
  check(
    `${fault} by P${party}: ${fclass} ${phase} blames [${blamed}]`,
    a.faultClass === fclass &&
      a.phase === phase &&
      a.blamed.length === blamed.length &&
      a.blamed.every((b, i) => b === blamed[i]) &&
      typeof a.detail === 'string' && a.detail.length > 0,
  );
}
let badFaultErrored = false;
try { wasm.arc_with_tamper(42n, "nonsense", 1); } catch { badFaultErrored = true; }
check('unknown fault errors', badFaultErrored);
