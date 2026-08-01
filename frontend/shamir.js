// OHM-ECDSA explainer — F1: Shamir + Feldman VSS, live via the Rust
// core compiled to wasm (frontend/wasm). No canned values: every number
// on this page comes out of the real protocol code under the seed.

import init, * as wasm from './pkg/ohm_ecdsa_wasm.js';

const $ = (sel) => document.querySelector(sel);
const status = $('#wasm-status');

let demo = null;           // current shamir_demo result
let cheated = new Set();   // party ids whose share is flipped
let selected = new Set();  // party ids picked for reconstruction

const trunc = (h) => `0x${h.slice(0, 10)}…${h.slice(-6)}`;
const full = (h) => `0x${h}`;

// Flip the last byte of a share — the "cheat" a malicious party would send.
const perturb = (h) => h.slice(0, -2) + (h.endsWith('00') ? '01' : '00');

function inputs() {
  return {
    seed: BigInt($('#seed').value || '0'),
    t: Number($('#t').value || '2'),
    n: Number($('#n').value || '3'),
  };
}

// --- the deal ----------------------------------------------------------------

function deal() {
  const { seed, t, n } = inputs();
  try {
    demo = wasm.shamir_demo('', t, n, seed);
  } catch (e) {
    status.textContent = `deal failed: ${e}`;
    return;
  }
  cheated = new Set();
  selected = new Set(demo.shares.slice(0, t).map((s) => s.id));
  status.textContent = `wasm live · dealt p(X) with t=${t}, n=${n} under seed ${seed}`;
  renderPlot();
  renderTable();
  renderRecon();
}

// --- the plot ----------------------------------------------------------------
// The curve is evaluated in JS from the wasm-returned f64 coefficient
// projection (coeffsNum). Documented choice: the demo deals small
// coefficients so the REAL polynomial is drawable; all cryptographic
// checks run in Rust over the full field.

function polyAt(coeffs, x) {
  let acc = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) acc = acc * x + coeffs[i];
  return acc;
}

function renderPlot() {
  const canvas = $('#plot');
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const pad = { l: 60, r: 24, t: 20, b: 40 };
  const n = demo.shares.length;
  const xMax = n + 1;
  const coeffs = demo.coeffsNum;

  const xs = [];
  for (let i = 0; i <= 240; i++) xs.push((xMax * i) / 240);
  const curve = xs.map((x) => polyAt(coeffs, x));
  const ys = curve.concat(demo.shares.map((s) => s.num));
  let yMin = Math.min(...ys), yMax = Math.max(...ys);
  if (yMax - yMin < 1e-9) { yMax += 1; yMin -= 1; }
  const span = yMax - yMin;
  yMin -= span * 0.08; yMax += span * 0.08;

  const X = (x) => pad.l + ((W - pad.l - pad.r) * x) / xMax;
  const Y = (y) => H - pad.b - ((H - pad.t - pad.b) * (y - yMin)) / (yMax - yMin);

  ctx.clearRect(0, 0, W, H);

  // axes
  ctx.strokeStyle = '#2d333b';
  ctx.fillStyle = '#8b949e';
  ctx.lineWidth = 1;
  ctx.font = '12px ui-monospace, Menlo, monospace';
  ctx.beginPath();
  ctx.moveTo(X(0), pad.t); ctx.lineTo(X(0), H - pad.b); ctx.lineTo(W - pad.r, H - pad.b);
  ctx.stroke();
  for (let j = 0; j <= xMax; j++) {
    ctx.fillText(j === 0 ? '0 (secret)' : `${j}`, X(j) - 18, H - pad.b + 18);
  }
  ctx.fillText('p(X) over the secp256k1 scalar field (f64 projection)', pad.l, pad.t - 6);

  // the polynomial
  ctx.strokeStyle = '#79c0ff';
  ctx.lineWidth = 2;
  ctx.beginPath();
  xs.forEach((x, i) => (i === 0 ? ctx.moveTo(X(x), Y(curve[i])) : ctx.lineTo(X(x), Y(curve[i]))));
  ctx.stroke();

  // the secret at 0
  ctx.fillStyle = '#d29922';
  ctx.beginPath();
  ctx.arc(X(0), Y(coeffs[0]), 7, 0, 2 * Math.PI);
  ctx.fill();
  ctx.fillText('secret p(0)', X(0) + 10, Y(coeffs[0]) - 10);

  // party shares (cheated ones off-curve, in red)
  for (const s of demo.shares) {
    const isCheat = cheated.has(s.id);
    const y = isCheat ? s.num + (yMax - yMin) * 0.07 : s.num;
    ctx.fillStyle = isCheat ? '#f85149' : '#7ee787';
    ctx.beginPath();
    ctx.arc(X(s.id), Y(y), 6, 0, 2 * Math.PI);
    ctx.fill();
    ctx.fillText(isCheat ? `p${s.id} CHEATED` : `p${s.id}`, X(s.id) - 8, Y(y) + 20);
  }
}

// --- the shares table ----------------------------------------------------------

function currentHex(id) {
  const s = demo.shares.find((s) => s.id === id);
  return cheated.has(id) ? perturb(s.hex) : s.hex;
}

function renderTable() {
  const tbody = $('#shares tbody');
  tbody.innerHTML = '';
  for (const s of demo.shares) {
    const tr = document.createElement('tr');
    if (cheated.has(s.id)) tr.classList.add('cheated');

    const tdPick = document.createElement('td');
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = selected.has(s.id);
    cb.onchange = () => {
      cb.checked ? selected.add(s.id) : selected.delete(s.id);
      renderRecon();
    };
    tdPick.append(cb);

    const tdId = document.createElement('td');
    tdId.textContent = s.id;

    const tdHex = document.createElement('td');
    tdHex.className = 'share-hex';
    tdHex.textContent = trunc(currentHex(s.id));
    tdHex.title = full(currentHex(s.id));

    const tdBadge = document.createElement('td');
    // The Feldman check runs in RUST (wasm) — point equality against the
    // public commitment, SPEC §4.2. The page never touches curve math.
    const ok = wasm.verify_share(demo.commitment, s.id, currentHex(s.id));
    tdBadge.textContent = ok ? '✓ share·G == EvalCom(A, j)' : '✗ FAILS the commitment check';
    tdBadge.className = ok ? 'badge-ok' : 'badge-bad';

    const tdCheat = document.createElement('td');
    const btn = document.createElement('button');
    btn.className = 'cheat-btn';
    btn.textContent = cheated.has(s.id) ? 'uncheat' : 'cheat';
    btn.onclick = () => {
      cheated.has(s.id) ? cheated.delete(s.id) : cheated.add(s.id);
      renderPlot();
      renderTable();
      renderRecon();
    };
    tdCheat.append(btn);

    tr.append(tdPick, tdId, tdHex, tdBadge, tdCheat);
    tbody.append(tr);
  }
}

// --- reconstruction --------------------------------------------------------------

function renderRecon() {
  const el = $('#recon');
  const t = demo.coeffs.length;
  const sel = [...selected].sort((a, b) => a - b);
  if (sel.length < t) {
    el.className = 'recon need';
    el.textContent = `cannot reconstruct: need ${t} shares, ${sel.length} selected — below t the secret is information-theoretically hidden (SPEC §4.1)`;
    return;
  }
  const rec = wasm.reconstruct(t, sel, sel.map(currentHex));
  if (rec === demo.secret) {
    el.className = 'recon ok';
    el.textContent = `reconstructed p(0) = ${trunc(rec)} — matches the dealt secret ✓ (${sel.length} shares via Lagrange at 0)`;
    el.title = full(rec);
  } else {
    el.className = 'recon bad';
    el.textContent = `reconstruction produced a DIFFERENT value ${trunc(rec)} — a cheated share is in the set. In the protocol the cheater would be NAMED (SPEC §10); here, watch the ✗ badge above.`;
    el.title = full(rec);
  }
}

// --- the keygen card -----------------------------------------------------------

function keygenCard() {
  const { seed } = inputs();
  const kg = wasm.keygen(seed);
  const out = $('#keygen-out');
  out.classList.remove('muted');
  out.innerHTML = '';
  const lines = [
    ['joint key X', kg.x, 'x'],
    ['Feldman A₀ (= X)', kg.commitment[0], 'share-row'],
    ['Feldman A₁', kg.commitment[1], 'share-row'],
    ...kg.parties.map((p) => [`party ${p.index} share`, p.share, 'share-row']),
  ];
  for (const [label, hex, cls] of lines) {
    const div = document.createElement('div');
    const lab = document.createElement('span');
    lab.className = 'label';
    lab.textContent = `${label.padEnd(18, ' ')} `;
    const val = document.createElement('span');
    val.className = cls;
    val.textContent = trunc(hex);
    val.title = full(hex);
    div.append(lab, val);
    out.append(div);
  }
}

// --- boot ------------------------------------------------------------------------

(async () => {
  try {
    await init();
  } catch (e) {
    status.textContent =
      'wasm module not built — run: cd frontend/wasm && wasm-pack build --target web --out-dir ../pkg';
    $('#keygen-out').textContent = 'waiting for the wasm build…';
    return;
  }
  $('#redeal').onclick = () => { deal(); keygenCard(); };
  for (const id of ['#seed', '#t', '#n']) {
    $(id).onchange = () => { deal(); keygenCard(); };
  }
  deal();
  keygenCard();
})();
