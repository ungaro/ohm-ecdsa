// OHM-ECDSA explainer — F3: live demo page.
// Scene: three.js (vendored locally). On-chain: public keyless JSON-RPC
// endpoints only — no tokens anywhere in this tree.

import * as THREE from './vendor/three.module.js';
import init, * as wasm from './pkg/ohm_ecdsa_wasm.js';

const $ = (sel) => document.querySelector(sel);
const trunc = (h) => `0x${h.slice(0, 10)}…${h.slice(-6)}`;

/* ============================ part 1: the mesh scene ========================= */
// The rounds reenact one real mesh arc (SPEC §6 → §8 → §9): DKG R1
// commits broadcast all-to-all, R2 reveals broadcast + P2P shares,
// presign offline rounds, then ONE online sign round. Broadcast packets
// are blue, P2P shares green — the §4.7 echo-broadcast vs signed
// point-to-point channels.

const ROUNDS = [
  {
    name: 'KeyGen R1 — commit',
    spec: 'SPEC §6 / §4.3',
    caption:
      'Every party hash-commits its Feldman commitment vector BEFORE seeing the others\u2019 — anti-rushing (§4.3): no one can bias the joint key after peeking.',
    packets: 'all-broadcast',
  },
  {
    name: 'KeyGen R2 — reveal + shares',
    spec: 'SPEC §6.1',
    caption:
      'Reveals broadcast (blue); the secret shares travel point-to-point (green). Each share is defended publicly against the commitment — a wrong deal is an indefensible complaint.',
    packets: 'broadcast+p2p',
  },
  {
    name: 'Presign — the offline factory',
    spec: 'SPEC §8',
    caption:
      'Triples and [u] = [k⁻¹] dealt through verified openings; the nonce point R is pinned to the sharing of k. All of this runs BEFORE any message exists — that is why signing is one round.',
    packets: 'broadcast+p2p',
  },
  {
    name: 'Sign — ONE online round',
    spec: 'SPEC §9',
    caption: '', // filled from the real wasm arc
    packets: 'all-broadcast',
  },
];

const NODES = [
  { id: 1, pos: new THREE.Vector3(-3.2, -1.6, 0) },
  { id: 2, pos: new THREE.Vector3(3.2, -1.6, 0) },
  { id: 3, pos: new THREE.Vector3(0, 2.4, 0.6) },
];

const COLOR_BROADCAST = 0x79c0ff;
const COLOR_P2P = 0x7ee787;

let sceneTime = 0; // 0..ROUNDS.length (continuous)
let playing = false;
let arc = null;

function makeLabel(text) {
  const c = document.createElement('canvas');
  c.width = 256;
  c.height = 128;
  const g = c.getContext('2d');
  g.fillStyle = '#e6edf3';
  g.font = 'bold 72px ui-monospace, Menlo, monospace';
  g.textAlign = 'center';
  g.textBaseline = 'middle';
  g.fillText(text, 128, 64);
  const tex = new THREE.CanvasTexture(c);
  const sprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true }));
  sprite.scale.set(1.4, 0.7, 1);
  return sprite;
}

function packetList(kind) {
  const pairs = [];
  for (let i = 0; i < NODES.length; i++) {
    for (let j = 0; j < NODES.length; j++) {
      if (i === j) continue;
      if (kind === 'all-broadcast') pairs.push({ from: i, to: j, color: COLOR_BROADCAST });
      else if (kind === 'broadcast+p2p') {
        pairs.push({ from: i, to: j, color: i < j ? COLOR_BROADCAST : COLOR_P2P });
      }
    }
  }
  return pairs;
}

function initScene() {
  const container = $('#scene-container');
  const W = container.clientWidth || 960;
  const H = 440;
  const renderer = new THREE.WebGLRenderer({ antialias: true });
  renderer.setSize(W, H);
  renderer.setClearColor(0x0d1117);
  container.append(renderer.domElement);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(50, W / H, 0.1, 100);
  camera.position.set(0, 0.4, 9.5);
  scene.add(new THREE.AmbientLight(0xffffff, 0.9));
  const key = new THREE.DirectionalLight(0xffffff, 1.2);
  key.position.set(2, 4, 6);
  scene.add(key);

  const group = new THREE.Group();
  scene.add(group);

  // edges (the full mesh)
  for (let i = 0; i < NODES.length; i++) {
    for (let j = i + 1; j < NODES.length; j++) {
      const geo = new THREE.BufferGeometry().setFromPoints([NODES[i].pos, NODES[j].pos]);
      group.add(new THREE.Line(geo, new THREE.LineBasicMaterial({ color: 0x2d333b })));
    }
  }

  // node spheres + labels
  for (const n of NODES) {
    const sphere = new THREE.Mesh(
      new THREE.SphereGeometry(0.45, 48, 32),
      new THREE.MeshStandardMaterial({ color: 0x1f6feb, roughness: 0.35, metalness: 0.15 }),
    );
    sphere.position.copy(n.pos);
    group.add(sphere);
    const label = makeLabel(`P${n.id}`);
    label.position.copy(n.pos).add(new THREE.Vector3(0, 0.85, 0));
    group.add(label);
  }

  // packet pool
  const packetGeo = new THREE.SphereGeometry(0.13, 16, 12);
  const packets = [];
  for (let i = 0; i < 6; i++) {
    const p = new THREE.Mesh(packetGeo, new THREE.MeshBasicMaterial({ color: 0xffffff }));
    p.visible = false;
    group.add(p);
    packets.push(p);
  }

  function render() {
    const roundIdx = Math.min(Math.floor(sceneTime), ROUNDS.length - 1);
    const frac = sceneTime - Math.floor(sceneTime);
    const round = ROUNDS[roundIdx];
    const defs = packetList(round.packets);
    packets.forEach((p, i) => {
      if (i >= defs.length) {
        p.visible = false;
        return;
      }
      const d = defs[i];
      p.visible = true;
      p.material.color.setHex(d.color);
      // stagger: each packet sweeps its edge over the round window
      const t = Math.min(Math.max(frac * 1.6 - i * 0.1, 0), 1);
      p.position.lerpVectors(NODES[d.from].pos, NODES[d.to].pos, t);
    });
    group.rotation.y = 0.08 * Math.sin(performance.now() / 4000);
    renderer.render(scene, camera);
  }

  const scrub = $('#scene-scrub');
  const roundLabel = $('#scene-round');
  const caption = $('#scene-caption');

  function syncUi() {
    const roundIdx = Math.min(Math.floor(sceneTime), ROUNDS.length - 1);
    const round = ROUNDS[roundIdx];
    scrub.value = String(Math.round((sceneTime / ROUNDS.length) * 1000));
    roundLabel.textContent = `${roundIdx + 1}/${ROUNDS.length} · ${round.name} (${round.spec})`;
    caption.innerHTML = round.caption;
  }

  scrub.oninput = () => {
    playing = false;
    $('#scene-play').textContent = '▶ play';
    sceneTime = (Number(scrub.value) / 1000) * ROUNDS.length;
    syncUi();
    render();
  };

  $('#scene-play').onclick = () => {
    playing = !playing;
    if (playing && sceneTime >= ROUNDS.length) sceneTime = 0;
    $('#scene-play').textContent = playing ? '⏸ pause' : '▶ play';
  };

  function tick() {
    if (playing) {
      sceneTime += 0.008;
      if (sceneTime >= ROUNDS.length) {
        sceneTime = ROUNDS.length;
        playing = false;
        $('#scene-play').textContent = '▶ play';
      }
      syncUi();
    }
    render();
    requestAnimationFrame(tick);
  }
  syncUi();
  tick();
}

/* ========================= part 2: the on-chain record ========================= */
// Public KEYLESS endpoints only.
const SEPOLIA_RPC = 'https://ethereum-sepolia-rpc.publicnode.com';
const PLUME_RPC = 'https://testnet-rpc.plume.org';

const COMMITTEES = [
  { label: 'sim committee (BURNED key — educational)', address: '0x729BB22d46A1790708a3cfB2AAe7F74dE8c9e970', rpc: SEPOLIA_RPC, chain: 'Sepolia', explorer: 'https://sepolia.etherscan.io' },
  { label: 'mesh committee', address: '0x27D8C9e7D340b4c38c769b14E239e61BF2E35d7c', rpc: SEPOLIA_RPC, chain: 'Sepolia', explorer: 'https://sepolia.etherscan.io' },
  { label: 'mesh committee (same key)', address: '0x27D8C9e7D340b4c38c769b14E239e61BF2E35d7c', rpc: PLUME_RPC, chain: 'Plume', explorer: 'https://testnet-explorer.plume.org' },
];

const TXS = [
  { n: 1, driver: 'sim', chain: 'Sepolia', block: 11398872, hash: '0x96914c199b8efee5d4e5376e110330ea2808651830210444a6b985ad9e1b9fb9', rpc: SEPOLIA_RPC, explorer: 'https://sepolia.etherscan.io', note: 'the incident broadcast' },
  { n: 2, driver: 'sim', chain: 'Sepolia', block: 11398940, hash: '0x000e08d68f3070c60d50f66cbcf18cc7d40154a61b9ae6e2578d5d3e303aabba', rpc: SEPOLIA_RPC, explorer: 'https://sepolia.etherscan.io', note: 'first run after the fix: fresh r' },
  { n: 3, driver: 'sim', chain: 'Sepolia', block: 11399127, hash: '0x204663f023efe00182125d79ada865bafb0e61ba8a983dc788f1f61a0604899d', rpc: SEPOLIA_RPC, explorer: 'https://sepolia.etherscan.io', note: '0.5 ETH: sim funds mesh' },
  { n: 4, driver: 'mesh', chain: 'Sepolia', block: 11399133, hash: '0x14eda1bb440b9a993487b76064fe10c43845a7be214f0ec969adc8dc88f4d916', rpc: SEPOLIA_RPC, explorer: 'https://sepolia.etherscan.io', note: 'three real PartyNodes, durable stores' },
  { n: 5, driver: 'mesh', chain: 'Plume', block: 23846211, hash: '0xf5e71e425ab60056ec708000fe3f196cc621554c3cf3d3884ea01ab05f629258', rpc: PLUME_RPC, explorer: 'https://testnet-explorer.plume.org', note: 'same committee, second chain — the RWA-narrative chain, not just the well-lit one' },
];

async function rpc(url, method, params) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(body.error.message || 'rpc error');
  return body.result;
}

function chainBadge(chain) {
  const cls = chain === 'Plume' ? 'plume' : 'sepolia';
  return `<span class="chain-badge ${cls}">${chain}</span>`;
}

function renderChainStatic() {
  $('#balances').innerHTML = COMMITTEES.map(
    (c) => `<div class="kv"><span class="k">${c.label} (${c.chain})</span><span class="v"><a class="tx-link" href="${c.explorer}/address/${c.address}" title="${c.address}">${trunc(c.address.slice(2))} ↗</a> — balance n/a (offline)</span></div>`,
  ).join('');
  $('#tx-cards').innerHTML = TXS.map(
    (t) => `<div class="tx-card">
      <div class="tx-head">#${t.n} · ${t.driver} · ${chainBadge(t.chain)} · block ${t.block}</div>
      <div class="tx-note">${t.note}</div>
      <div class="tx-status mono">status 1 ✓ (repo record)</div>
      <a class="tx-link" href="${t.explorer}/tx/${t.hash}">${trunc(t.hash.slice(2))} ↗</a>
    </div>`,
  ).join('');
}

async function renderChainLive() {
  const badge = $('#live-badge');
  badge.textContent = 'fetching…';
  badge.className = 'live-badge off';
  try {
    const balances = await Promise.all(
      COMMITTEES.map(async (c) => ({ ...c, balance: await rpc(c.rpc, 'eth_getBalance', [c.address, 'latest']) })),
    );
    const receipts = await Promise.all(
      TXS.map(async (t) => ({ ...t, receipt: await rpc(t.rpc, 'eth_getTransactionReceipt', [t.hash]) })),
    );
    $('#balances').innerHTML = balances
      .map((c) => {
        const eth = (Number(BigInt(c.balance)) / 1e18).toFixed(4);
        return `<div class="kv"><span class="k">${c.label} (${c.chain})</span><span class="v"><a class="tx-link" href="${c.explorer}/address/${c.address}" title="${c.address}">${trunc(c.address.slice(2))} ↗</a> — ${eth} ETH live</span></div>`;
      })
      .join('');
    $('#tx-cards').innerHTML = receipts
      .map((t) => {
        const ok = t.receipt && t.receipt.status === '0x1';
        return `<div class="tx-card">
          <div class="tx-head">#${t.n} · ${t.driver} · ${chainBadge(t.chain)} · block ${Number(BigInt(t.receipt.blockNumber))}</div>
          <div class="tx-note">${t.note}</div>
          <div class="tx-status mono">${ok ? 'status 1 ✓ live' : 'status 0 ✗ LIVE — reverted?'} · gas ${Number(BigInt(t.receipt.gasUsed))}</div>
          <a class="tx-link" href="${t.explorer}/tx/${t.hash}">${trunc(t.hash.slice(2))} ↗</a>
        </div>`;
      })
      .join('');
    badge.textContent = 'live';
    badge.className = 'live-badge on';
  } catch (e) {
    console.warn('live fetch failed, staying static:', e);
    badge.textContent = 'static (fetch failed)';
    badge.className = 'live-badge off';
    renderChainStatic();
  }
}

/* ========================= part 3: the incident timeline ========================= */

const TIMELINE = [
  {
    n: 1,
    title: 'the incident',
    lesson:
      'A dry run printed a full signature over m1; the broadcast signed m2 with the SAME deterministic k. Two transcripts, one nonce: k = (m1−m2)/(s1−s2), key gone. Same r on both txs — see it on-chain.',
  },
  {
    n: 2,
    title: 'the fix',
    lesson:
      'Dry runs stopped signing entirely (the report type has no signature fields), and every broadcast mints a FRESH presignature from OS entropy. Different r — visibly, immediately.',
  },
  {
    n: 3,
    title: 'committee funds committee',
    lesson:
      'The burned sim committee sends 0.5 ETH to the fresh mesh committee — the only correct use of a key you must treat as public: spending down, on testnet, for the record.',
  },
  {
    n: 4,
    title: 'the real mesh signs',
    lesson:
      'Three PartyNodes, per-node durable stores, the consume tombstone fsync\u2019d before any share is broadcast — single-use enforced by the disk, not by discipline.',
  },
  {
    n: 5,
    title: 'second chain, same committee',
    lesson:
      'One threshold key, two chains: the signature is chain-agnostic; only the sighash changes. Plume testnet, keyless public endpoint.',
  },
];

function renderTimeline() {
  $('#timeline').innerHTML = TIMELINE.map(
    (e, i) => `
    ${i > 0 ? '<div class="tl-edge"></div>' : ''}
    <details class="tl-node">
      <summary><span class="tl-dot">#${e.n}</span>${e.title}</summary>
      <p>${e.lesson}</p>
    </details>`,
  ).join('');
}

/* ========================= boot ========================= */

(async () => {
  renderChainStatic();
  renderTimeline();
  $('#refresh-live').onclick = renderChainLive;

  try {
    await init();
    arc = wasm.full_arc(42n);
    ROUNDS[3].caption =
      `Every party broadcasts one share — s_j = m·u_j + r·z_j (real values from the wasm arc: ` +
      `s₁ ${trunc(arc.sign.shares[0].s)}, s₂ ${trunc(arc.sign.shares[1].s)}, s₃ ${trunc(arc.sign.shares[2].s)}) — ` +
      `verified against m·A[u] + r·A[z] by point equality, interpolated, done. X = ${trunc(arc.keygen.x)}.`;
  } catch (e) {
    ROUNDS[3].caption =
      'Every party broadcasts one share — s_j = m·u_j + r·z_j — verified against m·A[u] + r·A[z] by point equality, interpolated, done. (wasm not built — values hidden)';
  }
  initScene();
  renderChainLive();
})();
