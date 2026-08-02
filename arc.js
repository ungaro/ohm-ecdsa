// OHM-ECDSA explainer — F2: the protocol arc + sabotage mode.
// Every value comes from the real Rust core via wasm (full_arc /
// arc_with_tamper); the page only renders and flips badges.

import init, * as wasm from './pkg/ohm_ecdsa_wasm.js';
import * as fig from './figures.js';

const $ = (sel) => document.querySelector(sel);
const status = $('#wasm-status');

const trunc = (h) => `0x${h.slice(0, 10)}…${h.slice(-6)}`;
const full = (h) => `0x${h}`;

// Phase order and which check each sabotage fires inside its card.
const PHASES = ['keygen', 'triples', 'presign', 'sign'];
const FAULT_PHASE = {
  'bad-deal': 'keygen',
  'bad-product-proof': 'triples',
  'bad-open-share': 'presign',
  'bad-nonce-point': 'presign',
  'bad-sign-share': 'sign',
};
// The check id (data-check attribute) each fault flips red.
const FAULT_CHECK = {
  'bad-deal': 'vss',
  'bad-product-proof': 'dleq',
  'bad-open-share': 'openings',
  'bad-nonce-point': 'nonce',
  'bad-sign-share': 'signshare',
};

let arc = null;
let tamper = null; // null = honest run

function hexRow(label, hex, cls = '') {
  return `<div class="kv ${cls}"><span class="k">${label}</span><span class="v" title="${full(hex)}">${trunc(hex)}</span></div>`;
}

function checkLine(id, label) {
  return `<div class="check-line" data-check="${id}"><span class="check-badge">✓</span> ${label}</div>`;
}

function figureBlock(id, caption, controls = '') {
  return `<div class="figure" id="${id}">
    ${controls}
    <div class="figure-canvas"></div>
    <p class="caption figure-note">${caption}</p>
  </div>`;
}

// --- card bodies ---------------------------------------------------------------

function renderKeygen() {
  const k = arc.keygen;
  const sabotaged = tamper && FAULT_PHASE[tamper.fault] === 'keygen';
  return `
    ${checkLine('commit', 'R1 commit-reveal consistent (hash ↔ reveal)')}
    ${checkLine('vss', `every dealt share verifies: share·G == EvalCom(A, j) — the §6.1 complaint check${sabotaged ? ` — P${tamper.blamed[0]}'s defense FAILED` : ''}`)}
    ${hexRow('A₀ (= X, joint key)', k.commitment[0], 'hl')}
    ${hexRow('A₁', k.commitment[1])}
    ${k.parties.map((p) => hexRow(`party ${p.index} share x_${p.index}`, p.share, tamper && tamper.blamed.includes(p.index) && sabotaged ? 'cheater' : '')).join('')}
    ${hexRow('X (SEC1 compressed)', k.x, 'hl')}
    ${figureBlock('fig-lagrange', 'The real shares as points; the fitted curve is a normalized projection of 𝔽_q (display only — the protocol interpolates exactly). Click a share to hide it. SPEC §4.1')}
    ${figureBlock('fig-commit', 'Commit-reveal: hashes bind every dealer before any reveal — anti-rushing (SPEC §6, §4.3)')}`;
}

function renderTriples() {
  const t = arc.triples;
  const sabotaged = tamper && FAULT_PHASE[tamper.fault] === 'triples';
  return `
    ${checkLine('dleq', `Chaum–Pedersen DLEQ product proofs (T3, §7.3)${sabotaged ? ` — P${tamper.blamed[0]}'s proof FAILED` : ' — all verified'}`)}
    ${checkLine('mult', 'recombined identity a·b == c at the commitments')}
    ${hexRow('A[a] (A₀)', t.ca[0])}
    ${hexRow('A[b] (A₀)', t.cb[0])}
    ${hexRow('A[c] (A₀)', t.cc[0])}
    ${t.parties.map((p) => `
      <div class="party-row ${tamper && tamper.blamed.includes(p.index) && sabotaged ? 'cheater' : ''}">
        <span class="k">P${p.index}</span>
        <span class="v">a: ${trunc(p.a)}</span>
        <span class="v">b: ${trunc(p.b)}</span>
        <span class="v">c: ${trunc(p.c)}</span>
      </div>`).join('')}
    ${figureBlock('fig-shutters', 'The masked opening as shutters — illustrative schematic (δ/ε values stay inside the driver). SPEC §7.2/§8')}
    ${figureBlock('fig-ladders', 'DLEQ as parallel ladders — illustrative small exponent. SPEC §7.3/§4.4')}`;
}

function renderPresign() {
  const p = arc.presign;
  const sabotaged = tamper && FAULT_PHASE[tamper.fault] === 'presign';
  return `
    ${checkLine('openings', `P2/P4 openings: share·G == EvalCom(A, j) on v, δ, ε${tamper && tamper.fault === 'bad-open-share' ? ` — P${tamper.blamed[0]}'s v share FAILED` : ''}`)}
    ${checkLine('nonce', `P3 nonce points: R_j == EvalCom(A[k], j)${tamper && tamper.fault === 'bad-nonce-point' ? ` — P${tamper.blamed[0]}'s R FAILED` : ''}`)}
    ${hexRow('id', String(p.id))}
    ${hexRow('R (nonce point)', p.bigR, 'hl')}
    ${hexRow('r = F(R)', p.r)}
    ${hexRow('A[u] (A₀), u = k⁻¹ dealt directly', p.uCom[0])}
    ${hexRow('A[z] (A₀), z = k⁻¹·x', p.zCom[0])}
    ${p.parties.map((q) => `
      <div class="party-row ${tamper && tamper.blamed.includes(q.index) && sabotaged ? 'cheater' : ''}">
        <span class="k">P${q.index}</span>
        <span class="v">u_share: ${trunc(q.uShare)}</span>
        <span class="v">z_share: ${trunc(q.zShare)}</span>
      </div>`).join('')}
    ${figureBlock('fig-inverse', 'The inverse-dealing chain — no inversion protocol (SPEC §8, §12)')}
    ${figureBlock('fig-scatter', '', `<div class="figure-controls mono"><label>field <select><option>53</option><option>251</option><option>997</option></select></label><button class="cheat-btn">▶</button> <span class="muted">hop R = k·G</span></div>`)}`;
}

function renderSign() {
  const s = arc.sign;
  const sabotaged = tamper && FAULT_PHASE[tamper.fault] === 'sign';
  return `
    ${checkLine('signshare', `S2 share check: s_j·G == EvalCom(m·A[u] + r·A[z], j)${sabotaged ? ` — P${tamper.blamed[0]}'s share FAILED` : ''}`)}
    ${hexRow('message', s.message)}
    ${hexRow('m = SHA-256(message) mod q', s.m)}
    ${s.shares.map((q) => hexRow(`s_${q.index} = m·u_${q.index} + r·z_${q.index}`, q.s, tamper && tamper.blamed.includes(q.index) && sabotaged ? 'cheater' : '')).join('')}
    ${hexRow('r', s.r, 'hl')}
    ${hexRow('s', s.s, 'hl')}
    <div class="check-line" data-check="final"><span class="check-badge">✓</span> k256 verifies under X · low-s (BIP-62/EIP-2)</div>
    ${figureBlock('fig-equation', '', '<div class="figure-check mono" id="eq-check"></div>')}`;
}

const RENDER = { keygen: renderKeygen, triples: renderTriples, presign: renderPresign, sign: renderSign };

// --- figures (F2.5) ------------------------------------------------------------

function drawFigures(phase, body) {
  const canvasIn = (id) => {
    const wrap = body.querySelector(`#${id} .figure-canvas`);
    if (!wrap) return null;
    const c = document.createElement('canvas');
    wrap.append(c);
    return c;
  };
  const noteIn = (id) => body.querySelector(`#${id} .figure-note`);
  const wrapIn = (id) => body.querySelector(`#${id} .figure-canvas`);

  if (phase === 'keygen') {
    fig.keygenLagrange(
      canvasIn('fig-lagrange'),
      noteIn('fig-lagrange'),
      arc.keygen.parties.map((p) => ({ index: p.index, shareHex: p.share })),
    );
    fig.commitReveal(wrapIn('fig-commit'));
  } else if (phase === 'triples') {
    fig.shutters(wrapIn('fig-shutters'));
    fig.ladders(wrapIn('fig-ladders'));
  } else if (phase === 'presign') {
    fig.inverseChain(wrapIn('fig-inverse'));
    fig.ffScatter(
      canvasIn('fig-scatter'),
      noteIn('fig-scatter'),
      body.querySelector('#fig-scatter .figure-controls'),
    );
  } else if (phase === 'sign') {
    fig.equationBoard(canvasIn('fig-equation'), body.querySelector('#eq-check'), arc.sign);
  }
}

// --- rendering the run -----------------------------------------------------------

function render() {
  const sabotagePhase = tamper ? tamper.phase : null;
  const stopAt = sabotagePhase ? PHASES.indexOf(sabotagePhase) : PHASES.length;

  for (const phase of PHASES) {
    const card = $(`#card-${phase}`);
    const body = card.querySelector('[data-body]');
    const badge = card.querySelector('[data-badge]');
    card.classList.remove('sabotaged', 'unreached');
    const idx = PHASES.indexOf(phase);

    if (idx > stopAt) {
      card.classList.add('unreached');
      badge.textContent = '⊘ not reached — aborted upstream';
      badge.className = 'phase-badge badge-unreached';
      body.innerHTML = '';
      card.open = false;
      continue;
    }

    body.innerHTML = RENDER[phase]();
    if (idx === stopAt && tamper) {
      card.classList.add('sabotaged');
      badge.textContent = `✗ ${tamper.faultClass} abort — P${tamper.blamed[0]} blamed`;
      badge.className = 'phase-badge badge-bad';
      const fired = body.querySelector(`[data-check="${FAULT_CHECK[tamper.fault]}"]`);
      if (fired) {
        fired.classList.add('fired');
        fired.querySelector('.check-badge').textContent = '✗';
      }
      const note = document.createElement('p');
      note.className = 'caption sabotage-note';
      note.textContent =
        'values shown are the HONEST run\u2019s — the sabotaged run aborted at the red check above; figures greyed.';
      body.prepend(note);
      card.open = true;
    } else {
      badge.textContent = '✓ complete';
      badge.className = 'phase-badge badge-ok';
    }
    // Figures (F2.5) — real arc values where available.
    drawFigures(phase, body);
  }

  // The abort panel — the REAL abort from the core.
  const panel = $('#abort-panel');
  if (!tamper) {
    panel.className = 'recon ok';
    panel.textContent = 'no abort — no one blamed (honest run; every check above is live)';
  } else {
    panel.className = 'recon bad';
    panel.innerHTML =
      `<strong>${tamper.faultClass} identifiable abort</strong> · phase <code>${tamper.phase}</code> · ` +
      `blamed: <code>[${tamper.blamed.join(', ')}]</code> (party ${tamper.blamed[0]} is NAMED) · ` +
      `${tamper.detail} — the check that fired: ${tamper.check}. ` +
      `Same ground truth as <code>tests/blame_matrix.rs</code>.`;
  }
}

function run() {
  const seed = BigInt($('#seed').value || '0');
  const fault = $('#fault').value;
  const party = Number($('#cheater').value);
  arc = wasm.full_arc(seed);
  tamper = fault === 'off' ? null : wasm.arc_with_tamper(seed, fault, party);
  status.textContent =
    tamper === null
      ? `wasm live · honest arc under seed ${seed}`
      : `wasm live · ${tamper.fault} armed on P${party}, seed ${seed}`;
  render();
}

// ▶ play: collapse everything, then walk the arc card by card.
async function play() {
  const cards = PHASES.map((p) => $(`#card-${p}`));
  for (const c of cards) c.open = false;
  $('#abort-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
  for (const c of cards) {
    if (c.classList.contains('unreached')) continue;
    await new Promise((r) => setTimeout(r, 900));
    c.open = true;
    c.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
}

(async () => {
  try {
    await init();
  } catch (e) {
    status.textContent =
      'wasm module not built — run: cd frontend/wasm && wasm-pack build --target web --out-dir ../pkg';
    return;
  }
  $('#run').onclick = run;
  $('#play').onclick = play;
  run();
})();
