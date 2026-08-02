// OHM-ECDSA explainer — F2.5: per-phase figures for the arc page.
// Everything is hand-rolled 2D canvas or inline SVG (no dependencies).
// Field arithmetic for the exact checks is JS BigInt mod q (the
// secp256k1 group order); projections to the display plane are labeled
// "normalized projection of 𝔽_q" wherever they are not exact.

// secp256k1 group order q.
export const Q = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

const ACCENT = '#7ee787';
const BLUE = '#79c0ff';
const AMBER = '#d29922';
const RED = '#f85149';
const MUTED = '#8b949e';
const BORDER = '#2d333b';

export function hexToBig(h) {
  return BigInt(`0x${h}`);
}

// Normalized projection of 𝔽_q into [0,1): v ↦ v/q (1e-6 resolution —
// display only, the field math it comes from is exact).
function proj(v) {
  const r = ((v % Q) + Q) % Q;
  return Number((r * 1000000n) / Q) / 1000000;
}

// Centered projection into [-0.5, 0.5).
function projC(v) {
  const r = ((v % Q) + Q) % Q;
  const p = proj(r);
  return r > Q / 2n ? p - 1 : p;
}

function mod(v, p) {
  return ((v % p) + p) % p;
}

function setupCanvas(canvas, w, h) {
  canvas.width = w;
  canvas.height = h;
  canvas.style.width = '100%';
  canvas.style.height = 'auto';
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, w, h);
  return ctx;
}

function axes(ctx, pad, W, H, xLabel, yLabel) {
  ctx.strokeStyle = BORDER;
  ctx.fillStyle = MUTED;
  ctx.lineWidth = 1;
  ctx.font = '12px ui-monospace, Menlo, monospace';
  ctx.beginPath();
  ctx.moveTo(pad.l, pad.t);
  ctx.lineTo(pad.l, H - pad.b);
  ctx.lineTo(W - pad.r, H - pad.b);
  ctx.stroke();
  ctx.fillText(xLabel, pad.l + 8, H - 8);
  ctx.fillText(yLabel, pad.l + 8, pad.t - 6);
}

/* =============== 1a. Keygen — Lagrange through the REAL shares =============== */
// The real keygen shares as 3 points. As GEOMETRY, 3 points pin a
// parabola; dropping one leaves a fan (each candidate hitting a
// different "secret" at 0). The caption notes the Shamir truth for
// 2-of-3: the sharing poly is a LINE — 2 shares reconstruct exactly,
// 1 share hides everything.

export function keygenLagrange(canvas, noteEl, shares) {
  // shares: [{index, shareHex}]
  const pts = shares.map((s) => ({ id: s.index, x: s.index, y: projC(hexToBig(s.shareHex)) }));
  const state = { dropped: new Set() };

  function parabolaThrough(p1, p2, p3) {
    // Solve p(x) = a x^2 + b x + c through three points (real solve —
    // display projection of the exact field values).
    const [x1, y1] = [p1.x, p1.y];
    const [x2, y2] = [p2.x, p2.y];
    const [x3, y3] = [p3.x, p3.y];
    const d = (x1 - x2) * (x1 - x3) * (x2 - x3);
    const a = (x3 * (y2 - y1) + x2 * (y1 - y3) + x1 * (y3 - y2)) / d;
    const b = (x3 * x3 * (y1 - y2) + x1 * x1 * (y2 - y3) + x2 * x2 * (y3 - y1)) / d;
    const c =
      (x2 * x3 * (x2 - x3) * y1 + x3 * x1 * (x3 - x1) * y2 + x1 * x2 * (x1 - x2) * y3) / d;
    return (x) => a * x * x + b * x + c;
  }

  function lineThrough(p1, p2) {
    const m = (p2.y - p1.y) / (p2.x - p1.x);
    return (x) => p1.y + m * (x - p1.x);
  }

  function draw() {
    const W = 880, H = 340;
    const pad = { l: 56, r: 20, t: 26, b: 34 };
    const ctx = setupCanvas(canvas, W, H);
    const kept = pts.filter((p) => !state.dropped.has(p.id));

    const xs = [];
    for (let i = 0; i <= 200; i++) xs.push((3.6 * i) / 200);
    const curves = [];
    if (kept.length === 3) {
      const f = parabolaThrough(kept[0], kept[1], kept[2]);
      curves.push({ f, color: BLUE, width: 2 });
    } else if (kept.length === 2) {
      // A fan of parabolas through the two kept points: p(x) = line +
      // c·(x−x1)(x−x2) — each c hits a different secret at 0.
      const line = lineThrough(kept[0], kept[1]);
      for (const c of [-0.16, -0.08, 0, 0.08, 0.16]) {
        const f = (x) => line(x) + c * (x - kept[0].x) * (x - kept[1].x);
        curves.push({ f, color: c === 0 ? BLUE : MUTED, width: c === 0 ? 2 : 1 });
      }
    } else if (kept.length === 1) {
      for (const m of [-0.5, -0.25, 0, 0.25, 0.5]) {
        const f = (x) => kept[0].y + m * (x - kept[0].x);
        curves.push({ f, color: MUTED, width: 1 });
      }
    }

    let yMin = -0.6, yMax = 0.6;
    for (const { f } of curves) {
      for (const x of xs.concat([0])) {
        const y = f(x);
        if (isFinite(y)) {
          yMin = Math.min(yMin, y);
          yMax = Math.max(yMax, y);
        }
      }
    }
    const X = (x) => pad.l + ((W - pad.l - pad.r) * x) / 3.6;
    const Y = (y) => H - pad.b - ((H - pad.t - pad.b) * (y - yMin)) / (yMax - yMin);

    axes(ctx, pad, W, H, 'party index (0 = secret)', 'share value — normalized projection of 𝔽_q');

    for (const { f, color, width } of curves) {
      ctx.strokeStyle = color;
      ctx.lineWidth = width;
      ctx.beginPath();
      let started = false;
      for (const x of xs) {
        const y = f(x);
        if (!isFinite(y) || y < yMin || y > yMax) {
          started = false;
          continue;
        }
        if (!started) {
          ctx.moveTo(X(x), Y(y));
          started = true;
        } else ctx.lineTo(X(x), Y(y));
      }
      ctx.stroke();
    }

    // secret marker at 0 (the fitted curve's value)
    const f0 = curves[Math.floor(curves.length / 2)].f;
    ctx.fillStyle = AMBER;
    ctx.beginPath();
    ctx.arc(X(0), Y(f0(0)), 7, 0, 2 * Math.PI);
    ctx.fill();
    ctx.fillText('candidate secret at 0', X(0) + 10, Y(f0(0)) - 10);

    for (const p of pts) {
      const dropped = state.dropped.has(p.id);
      ctx.fillStyle = dropped ? BORDER : ACCENT;
      ctx.beginPath();
      ctx.arc(X(p.x), Y(p.y), 6, 0, 2 * Math.PI);
      ctx.fill();
      ctx.fillStyle = dropped ? MUTED : ACCENT;
      ctx.fillText(dropped ? `P${p.id} (hidden)` : `P${p.id}`, X(p.x) - 12, Y(p.y) + 20);
    }

    noteEl.textContent =
      kept.length === 3
        ? 'Three real keygen shares pin one curve — click a share to hide it.'
        : kept.length === 2
          ? 'Two points: a FAN of curves, each hitting a different "secret" at 0. (In 2-of-3 Shamir the sharing polynomial is a LINE — two real shares reconstruct exactly; privacy starts below t.)'
          : 'One share: every line through it, every secret equally likely — Shamir privacy (SPEC §4.1).';
  }

  canvas.onclick = (ev) => {
    const rect = canvas.getBoundingClientRect();
    const mx = ((ev.clientX - rect.left) / rect.width) * 880;
    for (const p of pts) {
      const px = 56 + ((880 - 56 - 20) * p.x) / 3.6;
      if (Math.abs(mx - px) < 40) {
        state.dropped.has(p.id) ? state.dropped.delete(p.id) : state.dropped.add(p.id);
        if (state.dropped.size === pts.length) state.dropped.delete(p.id); // keep ≥1
        draw();
        return;
      }
    }
  };
  draw();
}

/* =============== 1b. Keygen — commit-reveal timeline (SVG) =============== */

function lock(x, y, open, label, color) {
  const shackle = open
    ? `<path d="M ${x + 4} ${y} v-8 a8 8 0 0 1 14 -6" stroke="${color}" stroke-width="3" fill="none"/>`
    : `<path d="M ${x + 4} ${y} v-6 a8 8 0 0 1 16 0 v6" stroke="${color}" stroke-width="3" fill="none"/>`;
  return `${shackle}<rect x="${x}" y="${y}" width="24" height="20" rx="3" fill="none" stroke="${color}" stroke-width="2"/>
    <text x="${x + 30}" y="${y + 15}" fill="#e6edf3" font-size="13" font-family="ui-monospace,Menlo,monospace">${label}</text>`;
}

export function commitReveal(container) {
  container.innerHTML = `
  <svg viewBox="0 0 880 190" style="width:100%;height:auto" role="img" aria-label="commit-reveal timeline">
    <text x="10" y="24" fill="${MUTED}" font-size="13" font-family="ui-monospace,Menlo,monospace">R1 · commit (broadcast)</text>
    <text x="10" y="114" fill="${MUTED}" font-size="13" font-family="ui-monospace,Menlo,monospace">R2 · reveal (broadcast + p2p shares)</text>
    ${lock(160, 30, false, 'h₁ = H(sid ‖ 1 ‖ A₁)', AMBER)}
    ${lock(400, 30, false, 'h₂ = H(sid ‖ 2 ‖ A₂)', AMBER)}
    ${lock(640, 30, false, 'h₃ = H(sid ‖ 3 ‖ A₃)', AMBER)}
    ${lock(160, 120, true, 'A₁ revealed — hash must match h₁', ACCENT)}
    ${lock(400, 120, true, 'A₂ revealed — hash must match h₂', ACCENT)}
    ${lock(640, 120, true, 'A₃ revealed — hash must match h₃', ACCENT)}
    <line x1="150" y1="85" x2="730" y2="85" stroke="${BORDER}" stroke-dasharray="4 4"/>
  </svg>`;
}

/* =============== 2a. Triples — the masked opening as shutters (SVG) =============== */

function window_(x, y, label, open, color) {
  const slats = open
    ? ''
    : [0, 1, 2, 3].map((i) => `<line x1="${x}" y1="${y + 8 + i * 9}" x2="${x + 90}" y2="${y + 8 + i * 9}" stroke="${MUTED}" stroke-width="3"/>`).join('');
  return `<rect x="${x}" y="${y}" width="90" height="44" rx="4" fill="${open ? 'rgba(126,231,135,0.12)' : '#161b22'}" stroke="${color}" stroke-width="2"/>
    ${slats}
    <text x="${x + 45}" y="${y + 66}" fill="#e6edf3" font-size="14" text-anchor="middle" font-family="ui-monospace,Menlo,monospace">${label}</text>`;
}

export function shutters(container) {
  container.innerHTML = `
  <svg viewBox="0 0 880 190" style="width:100%;height:auto" role="img" aria-label="masked opening">
    <text x="30" y="24" fill="${ACCENT}" font-size="13" font-family="ui-monospace,Menlo,monospace">OPENED (public) — reveals nothing</text>
    <text x="470" y="24" fill="${MUTED}" font-size="13" font-family="ui-monospace,Menlo,monospace">MASKED (uniform, never opened together)</text>
    ${window_(60, 45, 'δ = u − α', true, ACCENT)}
    ${window_(200, 45, 'ε = x − β', true, ACCENT)}
    ${window_(500, 45, 'α (mask)', false, BORDER)}
    ${window_(640, 45, 'β (mask)', false, BORDER)}
    <text x="30" y="160" fill="${MUTED}" font-size="12" font-family="ui-monospace,Menlo,monospace">δ, ε are public in P4; the uniform masks α, β hide a = k, x — subtracting removes the mask, keeps the secret (§7.2/§8).</text>
  </svg>`;
}

/* =============== 2b. Triples — DLEQ as parallel ladders (SVG) =============== */

export function ladders(container) {
  const rungs = ['g', 'g²', 'g³', 'g⁴', 'A = gˣ'];
  const rungsR = ['h', 'h²', 'h³', 'h⁴', 'C = hˣ'];
  const y0 = 150, dy = 30;
  const ladder = (x, rs, base) =>
    rs
      .map((r, i) => {
        const top = i === rs.length - 1;
        const y = y0 - i * dy;
        return `<line x1="${x}" y1="${y}" x2="${x + 110}" y2="${y}" stroke="${top ? ACCENT : BORDER}" stroke-width="${top ? 3 : 2}"/>
        <text x="${x + 118}" y="${y + 4}" fill="${top ? ACCENT : MUTED}" font-size="13" font-family="ui-monospace,Menlo,monospace">${top ? r : ''}</text>
        <text x="${x - 30}" y="${y + 4}" fill="${MUTED}" font-size="12" font-family="ui-monospace,Menlo,monospace">${r === base ? '' : ''}</text>`;
      })
      .join('') +
    `<line x1="${x + 55}" y1="${y0 + 10}" x2="${x + 55}" y2="${y0 - (rs.length - 1) * dy - 6}" stroke="${BORDER}" stroke-width="1" stroke-dasharray="3 3"/>
     <text x="${x + 55}" y="${y0 + 28}" fill="#e6edf3" font-size="13" text-anchor="middle" font-family="ui-monospace,Menlo,monospace">base ${base}</text>`;
  container.innerHTML = `
  <svg viewBox="0 0 880 210" style="width:100%;height:auto" role="img" aria-label="DLEQ parallel ladders">
    ${ladder(150, rungs, 'g')}
    ${ladder(560, rungsR, 'h')}
    <text x="440" y="40" fill="${ACCENT}" font-size="16" text-anchor="middle" font-family="ui-monospace,Menlo,monospace">same exponent x — matching rungs</text>
    <text x="440" y="190" fill="${MUTED}" font-size="12" text-anchor="middle" font-family="ui-monospace,Menlo,monospace">Chaum–Pedersen proves log_g A = log_h C without revealing x (§7.3/§4.4) — illustrative small exponent</text>
  </svg>`;
}

/* =============== 3a. Presign — the inverse-dealing chain (SVG) =============== */

function flowBox(x, y, w, title, sub, color) {
  return `<rect x="${x}" y="${y}" width="${w}" height="64" rx="8" fill="#161b22" stroke="${color}" stroke-width="2"/>
    <text x="${x + w / 2}" y="${y + 26}" fill="#e6edf3" font-size="14" text-anchor="middle" font-family="ui-monospace,Menlo,monospace">${title}</text>
    <text x="${x + w / 2}" y="${y + 46}" fill="${MUTED}" font-size="11" text-anchor="middle" font-family="ui-monospace,Menlo,monospace">${sub}</text>`;
}

export function inverseChain(container) {
  container.innerHTML = `
  <svg viewBox="0 0 880 150" style="width:100%;height:auto" role="img" aria-label="inverse-dealing chain">
    ${flowBox(20, 40, 240, '[u] = [k⁻¹] dealt directly', 'P1 — the inverse is SAMPLED, never computed', ACCENT)}
    <path d="M 268 72 h 34" stroke="${BORDER}" stroke-width="2" marker-end="url(#arr)"/>
    ${flowBox(310, 40, 240, 'R = u⁻¹·G', 'P3 — the nonce point, pinned to A[k]', BLUE)}
    <path d="M 558 72 h 34" stroke="${BORDER}" stroke-width="2" marker-end="url(#arr)"/>
    ${flowBox(600, 40, 260, '[z] = [u·x]', 'P4 — bound to the key via one Beaver triple', AMBER)}
    <defs><marker id="arr" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 z" fill="${BORDER}"/></marker></defs>
    <text x="440" y="136" fill="${MUTED}" font-size="12" text-anchor="middle" font-family="ui-monospace,Menlo,monospace">no inversion protocol anywhere — the design-around (§8, §12)</text>
  </svg>`;
}

/* =============== 3b. Presign — finite-field scatter (canvas, animated) =============== */
// The REAL secp256k1 equation y² = x³ + 7 over a toy prime field,
// enumerated exactly in BigInt. The "hops" animate R = k·G by real toy
// curve addition — the discrete-log story (SPEC §3).

const PRIMES = [53, 251, 997];

function curvePoints(p) {
  const pts = [];
  for (let x = 0n; x < p; x++) {
    const rhs = mod(x * x * x + 7n, p);
    for (let y = 0n; y < p; y++) {
      if (mod(y * y, p) === rhs) pts.push({ x, y });
    }
  }
  return pts;
}

function ecAdd(P1, P2, p) {
  if (!P1) return P2;
  if (!P2) return P1;
  if (P1.x === P2.x && mod(P1.y + P2.y, p) === 0n) return null; // point at infinity
  let m;
  if (P1.x === P2.x && P1.y === P2.y) {
    if (P1.y === 0n) return null;
    m = mod(3n * P1.x * P1.x * modInv(2n * P1.y, p), p);
  } else {
    m = mod((P2.y - P1.y) * modInv(P2.x - P1.x, p), p);
  }
  const x = mod(m * m - P1.x - P2.x, p);
  const y = mod(m * (P1.x - x) - P1.y, p);
  return { x, y };
}

function egcd(a, b) {
  if (b === 0n) return [a, 1n, 0n];
  const [g, x1, y1] = egcd(b, mod(a, b));
  return [g, y1, x1 - (a / b) * y1];
}

function modInv(a, p) {
  return mod(egcd(mod(a, p), p)[1], p);
}

export function ffScatter(canvas, noteEl, controlsEl) {
  const state = { p: BigInt(PRIMES[1]), k: 0, playing: false, timer: null };
  const select = controlsEl.querySelector('select');
  const playBtn = controlsEl.querySelector('button');
  select.value = String(PRIMES[1]);

  function draw() {
    const p = state.p;
    const pts = curvePoints(p);
    const W = 880, H = 340;
    const pad = { l: 40, r: 20, t: 26, b: 30 };
    const ctx = setupCanvas(canvas, W, H);
    axes(ctx, pad, W, H, `x ∈ GF(${p})`, `y² = x³ + 7 (mod ${p}) — ${pts.length} points`);
    const X = (x) => pad.l + ((W - pad.l - pad.r) * Number(x)) / (Number(p) - 1);
    const Y = (y) => H - pad.b - ((H - pad.t - pad.b) * Number(y)) / (Number(p) - 1);

    ctx.fillStyle = BLUE;
    for (const pt of pts) {
      ctx.fillRect(X(pt.x) - 1.5, Y(pt.y) - 1.5, 3, 3);
    }

    // hops: R_k = k·G from the first point found
    const G = pts[0];
    let R = null;
    const hops = [];
    for (let k = 1; k <= 20; k++) {
      R = ecAdd(R, G, p);
      hops.push(R);
      if (!R) break;
    }
    ctx.strokeStyle = 'rgba(210,153,34,0.4)';
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    hops.forEach((h, i) => {
      if (!h) return;
      if (i === 0 || !hops[i - 1]) ctx.moveTo(X(h.x), Y(h.y));
      else ctx.lineTo(X(h.x), Y(h.y));
    });
    ctx.stroke();
    hops.forEach((h, i) => {
      if (!h) return;
      const current = i + 1 === state.k;
      ctx.fillStyle = current ? RED : AMBER;
      ctx.beginPath();
      ctx.arc(X(h.x), Y(h.y), current ? 7 : 4, 0, 2 * Math.PI);
      ctx.fill();
      if (current) {
        ctx.fillText(`R = ${i + 1}·G`, X(h.x) + 10, Y(h.y) - 10);
      }
    });

    noteEl.textContent =
      state.k === 0
        ? `y² = x³ + 7 over GF(${p}) — secp256k1's real equation, toy field. Press ▶ to hop R = k·G.`
        : `R = ${state.k}·G landed somewhere in the cloud — given only the endpoint, count the hops: that's the discrete logarithm problem (SPEC §3).`;
  }

  select.onchange = () => {
    state.p = BigInt(select.value);
    state.k = 0;
    draw();
  };
  playBtn.onclick = () => {
    state.playing = !state.playing;
    playBtn.textContent = state.playing ? '⏸' : '▶';
    if (state.playing) {
      state.timer = setInterval(() => {
        state.k = (state.k % 20) + 1;
        draw();
      }, 500);
    } else {
      clearInterval(state.timer);
      state.k = 0;
      draw();
    }
  };
  draw();
}

/* =============== 4. Sign — the one-round equation board (canvas) =============== */
// Three real s_j bars with their Lagrange weights, plus the EXACT
// BigInt check Σ λ_j·s_j ≡ s (mod q) — the same interpolation the core
// runs, recomputed in JS for display.

export function equationBoard(canvas, checkEl, sign) {
  const shares = sign.shares.map((s) => ({ id: s.index, v: hexToBig(s.s) }));
  const sFinal = hexToBig(sign.s);
  // Lagrange at 0 for parties [1,2,3]: λ = 3, −3, 1.
  const lambdas = shares.map((s) => {
    let lam = 1n;
    for (const m of shares) {
      if (m.id === s.id) continue;
      lam = mod(lam * BigInt(m.id) * modInv(BigInt(m.id - s.id), Q), Q);
    }
    return lam;
  });
  let sum = 0n;
  shares.forEach((s, i) => {
    sum = mod(sum + lambdas[i] * s.v, Q);
  });
  const exact = sum === sFinal;
  const lowSFlipped = !exact && mod(Q - sum, Q) === sFinal;
  checkEl.innerHTML =
    exact || lowSFlipped
      ? `<span class="badge-ok">✓ exact BigInt check:</span> Σ λⱼ·sⱼ ≡ ${lowSFlipped ? 'q − s (low-s normalized)' : 's'} (mod q) — λ = (${shares.map((_, i) => (lambdas[i] > Q / 2n ? lambdas[i] - Q : lambdas[i]).toString()).join(', ')})`
      : `<span class="badge-bad">✗ Σ λⱼ·sⱼ ≢ s — interpolation mismatch?!</span>`;

  const W = 880, H = 300;
  const pad = { l: 60, r: 20, t: 26, b: 34 };
  const ctx = setupCanvas(canvas, W, H);
  axes(ctx, pad, W, H, '', 'signature shares s_j (normalized projection)');
  const bw = 110;
  shares.forEach((s, i) => {
    const px = pad.l + 90 + i * 240;
    const hgt = Math.abs(projC(s.v)) * (H - pad.t - pad.b) * 1.6;
    const neg = projC(s.v) < 0;
    ctx.fillStyle = 'rgba(121,192,255,0.5)';
    ctx.fillRect(px, neg ? H / 2 : H / 2 - hgt, bw, hgt);
    ctx.fillStyle = '#e6edf3';
    ctx.font = '13px ui-monospace, Menlo, monospace';
    ctx.fillText(`s${s.id}`, px + bw / 2 - 10, H - pad.b + 18);
    ctx.fillStyle = AMBER;
    const lam = lambdas[i] > Q / 2n ? lambdas[i] - Q : lambdas[i];
    ctx.fillText(`λ = ${lam}`, px + bw / 2 - 16, pad.t + (i % 2) * 18 + 6);
  });
  ctx.strokeStyle = BORDER;
  ctx.beginPath();
  ctx.moveTo(pad.l, H / 2);
  ctx.lineTo(W - pad.r, H / 2);
  ctx.stroke();
}
