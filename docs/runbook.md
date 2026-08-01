# OHM-ECDSA deployment runbook (operator-facing)

**Unaudited research code — do NOT secure real assets with it** (SPEC
§13.6). This runbook describes how to *operate* the reference node; it
does not make the code production-grade. Commands assume the workspace
binary (`cargo build --release -p ohm-ecdsa-node`; below
`ohm-ecdsa-node` stands for `target/release/ohm-ecdsa-node`).

## 1. Topologies recap (SPEC Appendix A)

| Topology | T | n | slack (`n−(2T−1)`) | packed B | Notes |
|---|---|---|---|---|---|
| Consumer wallet (A.2) | 2 | 3 | 0 | — | any 2 sign; lost device → §13.4 reshare |
| Institutional custody (A.1) | 3 | 5 | 0 | — | five roles; expulsion ⇒ reshare |
| Custody with restart slack | 3 | 6 | 1 | — | absorbs one §10.3 expulsion |
| Validator committee (A.3) | per chain | `n ≥ 2T−1` | churn budget | `n ≥ 2T+2B−3` | refresh per epoch |

Rules that size every deployment: `n ≥ 2T−1` always (the node enforces
it); slack is what the §10.3 expel-and-restart policy spends — **zero
slack means every expulsion is a §13.4 re-sharing event**; packed mode
(§7.4) moves the online quorum to `T+B−1`.

## 2. Committee ceremony (H3)

The one-process `setup`/`spawn-demo` ceremony is DEMO-ONLY (one machine
holds every transport secret). Real committees use the distributed
ceremony — no secret leaves its party's machine:

```sh
# Each party on its OWN machine (party 1 shown):
ohm-ecdsa-node init --id 1 --dir ./party1 --addr 10.0.0.1:7700 --tls
#   → SECRET  ./party1/party-1.identity  (transport key; guard + back up)
#   → SECRET  ./party1/party-1.key.pem   (TLS key, with --tls)
#   → PUBLIC  ./party1/party-1.pub, ./party1/party-1.crt.pem
#   → stdout: FINGERPRINT <hex>

# Out of band: exchange the .pub bundles over an AUTHENTICATED channel;
# confirm EVERY party's fingerprint on a second channel. This step is
# the trust root — ops, not code.

# Assembly (PUBLIC data only, safe to run anywhere):
ohm-ecdsa-node assemble --committee ./committee \
    --inputs party-1.pub,party-2.pub,party-3.pub
#   → ./committee/committee.hex + the pinned cert set; prints all
#     fingerprints and a suggested --peers line. Re-runnable: compare
#     committee.hex byte for byte.
```

File permissions: everything secret the node writes is `0600`;
`init`/`assemble` output should be checked with `ls -l` before moving
on. Common mistakes, and the expected fail-closed behavior:

- **Duplicate id / id gap** — `assemble` exits non-zero with
  `assemble: duplicate party id` / `party ids must be exactly 1..=n`.
- **Mixed TLS posture** (some bundles with certs, some without) —
  rejected at `assemble`. Regenerate the odd bundle with/without `--tls`.
- **Tampered `.pub`** that survives the out-of-band check — the node
  refuses to boot: `own transport key does not match the committee
  registry entry` or `own certificate does not match its pinned entry`.
  There is no override; re-run the ceremony.

## 3. Running a node

```sh
# 2-of-3 wallet node (party 1):
ohm-ecdsa-node node --identity ./party1/party-1.identity \
    --committee ./committee/committee.hex --bind 10.0.0.1:7700 \
    --peers 1@10.0.0.1:7700,2@10.0.0.2:7700,3@10.0.0.3:7700 \
    --tls ./party1/party-1.crt.pem ./party1/party-1.key.pem --pinned ./committee \
    --factory 2 --pool-ttl 86400 \
    --data-dir /var/lib/ohm/node1 \
    --metrics-file /var/lib/ohm/node1/metrics.log
```

TLS is mandatory off localhost; plain TCP is for dev only. `--tls` and
`--pinned` must be given together — partial flags are a usage error,
never a silent plaintext fallback. A node that cannot verify its own
material exits non-zero at startup (fail closed).

Environment variables (H5/A5 storage-key resolution, in precedence
order; a configured-but-failing source is a hard error, never a silent
fallback to the dev key):

- `OHM_STORAGE_KEY_CMD` — helper command printing the 32-byte storage
  secret as hex on stdout, e.g.
  `OHM_STORAGE_KEY_CMD="vault kv get -field=hex secret/ohm/node1"`.
  Split on whitespace (NOT a shell: no quoting/pipes/redirects); must
  exit 0 within 5 s. This is the KMS plug-in point — not a KMS.
- `OHM_STORAGE_KEY` — 64 hex chars in the environment.
- `OHM_STORAGE_KEY_FILE` — path of a hex key file (`0600`).
- unset → a generated `storage.key` (`0600`) beside the store — DEV
  default, loudly warned about.
- `OHM_ALLOW_UNVERIFIED_STORE=1` (or `--allow-unverified-store`) —
  A4 dev escape hatch: rollback checks become warnings. NEVER in
  production (see §6).

What the node writes under `--data-dir DIR`: `DIR/store/` (`<id>.presig`
sealed records, `<id>.consumed` / `<id>.expired` tombstones,
`journal.log` — the A4 chained mutation journal, `key.bin` binding the
store to ONE long-term key), `DIR/archive/` (`transcript.log` — every
accepted signed envelope, `aborts.log`, `blame-*.tok` evidence files),
and `DIR/metrics.log` when `--metrics-file` points there.

## 4. Pool management

`--factory N` runs the pool manager: it keeps `N` live presignatures in
the durable store (single writer; signing only consumes through the
atomic consume) and refills as signing drains. Sizing is a SECURITY
decision, not a performance one (SPEC §8.6/§9.4): presignature records
are **key-equivalent** — `t` records reveal the long-term key — and a
record's nonce is disclosed at signing time, so the pool is a standing
stock of key-grade secrets awaiting one-round use. Keep pools SMALL (a
few records), never "as many as disk allows".

`--pool-ttl SECS` (§8.6(3)) expires records older than SECS: the
`<id>.expired` tombstone is fsync'd first (the id is burned forever,
never re-issued), then the sealed file is erased. Expiry is a LOCAL
per-node policy — nothing synchronizes node clocks, so set the TTL well
above the expected residence time; a sign racing expiry fails loudly
(unknown id) rather than serving a stale record. `0` = never expire.

§8.7 KI mode (yellow flag): key-free pool records are NOT key-equivalent
(`t` shares reveal no key), so the pool may be larger — but records are
still strictly single-use, still in-memory only (a restart loses unspent
records), and KI signing costs one extra online round + one extra triple
per signature.

## 5. Monitoring

`--metrics-file PATH` appends one snapshot block every 15 s plus a final
block at clean shutdown: a `#`-prefixed header
(`node= committee= pid= uptime_s=`) then one `name value` pair per line
— no ANSI, no timestamps in counter names; scrape the LAST block (e.g.
cron `awk '/^#/{h=$0} END{...}'` or `tail -25`) into any monitoring
stack. Pull-based by design: no HTTP endpoint; wrap the file with your
own exporter if you need one. Sample (3-node factory run):

```
# ohm-ecdsa-node metrics node=2 committee=1,2,3 pid=22417 uptime_s=2
tls_enabled 0
frames_sent 1144
frames_received 1144
frames_dropped_bad_signature 0
frames_dropped_misrouted 0
frames_dropped_rate_limited 0
frames_dropped_oversize 0
frames_dropped_inbox_full 0
acceptor_drops 0
equivocations 0
accepts_rate_limited 0
handshake_rejects 0
reconnects 0
sessions_active 0
sessions_completed 49
pool_target 2
pool_stored 2
pool_produced 5
pool_expired 0
store_live 2
store_consumed 3
store_expired 0
store_integrity_warnings 0
```

Alert on (all are zero in a healthy committee):

- `frames_dropped_bad_signature > 0` — unknown sender or forged frame:
  active interference or a misconfigured peer. Investigate source IPs.
- `acceptor_drops > 0` with equivocation evidence in `aborts.log` — a
  committee member signed two conflicting values (F8); see §6.
- `equivocations > 0` — the node's acceptor detected a broadcast
  equivocation (§4.7 rule (3), fault class F8): the sender signed two
  conflicting values for one slot. The two signed envelopes are
  archived as offline-verifiable evidence; see §6.
- `store_integrity_warnings > 0` — the A4 startup checks could not fully
  verify the store; a whole-directory rollback is possible. See §6.
- `reconnects` climbing fast (reconnect storm) — a flapping peer or
  link; rounds still complete but round timeouts are the next symptom.
- `handshake_rejects > 0` (TLS) — unpinned/plaintext peers probing the
  listener; expected at low rates on exposed ports, a spike is a scan.
- `pool_stored < pool_target` persistently — production is failing:
  check stderr for `pool maintenance failed` and blame lines.
- `frames_dropped_rate_limited` / `accepts_rate_limited` /
  `frames_dropped_inbox_full` — flood or an overloaded acceptor.

### 5.1 Soak-testing a deployment before go-live (A7)

Before trusting a topology, soak it: `spawn-demo --soak` runs the whole
committee continuously — the factory keeps each node's pool at target
while the demo parent drives jittered sign ticks, per-session fault
injection, and process kill/restart cycles:

```
ohm-ecdsa-node spawn-demo --dir /tmp/soak --persist --metrics \
    --soak 3600 --factory 4 --pool-ttl 900 \
    --fault-rate 0.05 --restart-every 60 --seed 1
```

Run it for hours (days for a pre-launch soak), then judge it by the
exit contract: exit 0 iff `signs_failed == 0`, no UNARMED party was
ever blamed, the end-of-soak A4 store audit passed at every node, and
every child shut down cleanly. While it runs, watch:

- the per-node `SOAK-STATS` lines (stdout) — `signs_failed` must stay
  0; `pfailed` (failed production sessions, ids burned) climbs only
  with injected faults and restart windows; `reconnects` steps once per
  kill cycle; `equivocations` must stay 0;
- the per-node metrics files (`--metrics`, §5) — same counters over
  time; `pool_stored` should sit at `pool_target` between ticks;
- the final `SOAK-STORE node=K … integrity=ok` lines and
  `SOAK-SUMMARY`/`RESULT soak` verdict.

Anything suspicious reproduces deterministically from `--seed` (same
jitter, faults, and kill schedule). The soak uses the DEMO-ONLY
one-process ceremony — it is a test harness, not a deployment shape;
the kill/restart cycle exercises the same H2 reconnection and M3b
recovery paths a real restart would.

## 6. Incident response

1. **Blame arrives** (`BLAME <phase> <ids>` on stdout, an entry in
   `aborts.log`, possibly a `blame-*.tok`). Blame is deterministic and
   identical at every honest node — collect the reports.
2. **Verify the token offline** before acting on it:
   `ohm-ecdsa-node auditor DIR/archive/blame-<phase>-<id>.tok committee.hex`
   — exit 0 with `VERDICT: VALID — the token substantiates the blame
   (SPEC §A.4)`. Only F2 (dealt shares) and F6 (sign shares) classes
   produce token files; other classes log `token: none` and the
   transcript is the evidence.
3. **Expel-and-restart (§10.3).** With `--restart` the node does this
   itself: the blamed party is expelled, the sid/id poisoned
   (§10.3(2)), the session re-runs over the survivors' ORIGINAL ids.
   **Zero-slack caveat:** the policy refuses when the remainder would
   drop below `2t−1` — `t` is NEVER lowered. A 2-of-3 committee cannot
   expel anyone; a dealing-phase cheater there means a consistent abort
   and a committee rebuild (step 5).
4. **Refresh (§13.4)** re-randomizes shares (X unchanged) — run it at
   epoch boundaries and after any suspected share compromise; it
   invalidates ALL outstanding presignatures (stores are cleared; pools
   rebuild from the new epoch's shares).
5. **Reshare (§13.4)** moves the key to a NEW committee (X unchanged) —
   the path for committee changes: expelling a role, replacing a lost
   device, onboarding. In custody topologies this doubles as the
   compliance process for removing a member.
6. **Suspected rollback.** Startup refusing with
   `store integrity: ROLLBACK DETECTED: presignature id <id> is
   evidenced as SPENT by the sign transcript …` means the store
   directory was restored from a stale backup over an intact archive —
   signing on would reuse a nonce and EXTRACT THE LONG-TERM KEY. Do NOT
   reach for `--allow-unverified-store`: it downgrades exactly this
   refusal to a warning. Investigate first: confirm the backup/restore
   event, then wipe the store directory (presignatures are replaceable;
   the key is not) and let the factory rebuild the pool. If you cannot
   explain the divergence, treat the key as compromised: refresh/reshare
   and rotate off it.

## 7. Backup & upgrade policy

- **Back up freely:** `archive/` (transcript, aborts, blame tokens) —
  public evidence (commitments, masked openings, public values per
  §10.5); safe for compliance retention. Ship `transcript.log` OFF-BOX:
  it is what makes the A4 rollback cross-check independent.
- **Back up with extreme care:** `store/` and the identity/seed files —
  key-equivalent material (§8.6(2), §A.5). Sealed under the storage
  key, but custody of that key is YOUR problem (§3).
- **Never restore `store/` blindly.** A stale store restore un-consumes
  spent records — the exact nonce-reuse trap. Restores go through a
  startup with the A4 checks ON and are abandoned on `ROLLBACK
  DETECTED`; a whole-directory restore is undetectable (the journal and
  transcript roll back together), which is why off-box transcripts and
  HSM monotonic counters stay deployment duties (§13.3).
- **Upgrades.** The wire format is the core's canonical length-prefixed
  `Encode`/`Decode`, versioned by domain-separation tags
  (`OHM-ECDSA/v0.1/…`): mixed-version committees do not interoperate —
  upgrade the whole committee together. On-disk formats are versioned
  (sealed v2 records; legacy v1 sealed records accepted, legacy
  CLEARTEXT rejected fail-closed). No rekey tooling exists: rotating
  the storage secret makes old sealed files unreadable — drain the pool
  first.

## 8. Security checklist (pre-launch sign-off)

Distilled from SPEC §13.3, §8.6, §9.4 — every box is a real failure
mode when unchecked:

- [ ] Distributed ceremony used (`init`/`assemble`); the one-process
      `setup` was never run against the real committee.
- [ ] Every party's fingerprint confirmed out-of-band before `assemble`.
- [ ] mTLS on every link (`--tls … --pinned …`); no node reachable in
      plaintext from outside the committee.
- [ ] Storage secret from the KMS helper (`OHM_STORAGE_KEY_CMD`) or
      equivalent — NOT the generated dev key; a failing helper is
      expected to stop the node.
- [ ] `--allow-unverified-store` / `OHM_ALLOW_UNVERIFIED_STORE` absent
      everywhere.
- [ ] Secret files `0600`; identity files backed up per party on its
      own machine only.
- [ ] Pool target small (key-equivalent standing stock); TTL set well
      above expected residence time, or 0 with a documented reason.
- [ ] Metrics file scraped; alerts wired for
      `frames_dropped_bad_signature`, `acceptor_drops`,
      `store_integrity_warnings`, `reconnects`, `handshake_rejects`,
      pool-below-target (§5).
- [ ] `transcript.log` shipped off-box (rollback-detection
      independence).
- [ ] Restart policy chosen per slack: `--restart` only on committees
      with slack (`n > 2T−1`); zero-slack committees have a documented
      reshare runbook instead.
- [ ] Epoch plan: refresh cadence, store clearing on epoch change
      (§13.4), reshare procedure for membership changes.
- [ ] Blame playbook rehearsed: collect `BLAME` lines → `auditor`
      verification → expel/reshare decision (§6).
- [ ] Everyone involved has read SPEC §13.6: unaudited research code.

## 9. EVM testnet demo (`demo-evm/`)

The workspace-excluded demo crate (`demo-evm/`) proves the "threshold
signature → on-chain-verifiable EVM signature" path end to end: a
2-of-3 committee signs a real EIP-1559 transfer and broadcasts it to a
testnet. **Testnet/fake funds only** — the same SPEC §13.6 disclaimer
applies, and the demo's deterministic committees are public by
construction (see the k-reuse incident in `demo-evm/README.md`; the M2
sim committee key is BURNED and kept only for testnet continuity).

Endpoints come from an environment variable ONLY — never a flag, never
a default, never written to any file:

```sh
export OHM_DEMO_RPC_URL="https://<your-testnet-endpoint>"
```

Chains: Sepolia by default (`--chain-id 11155111`); Plume testnet via
`--chain-id 98867` (with a Plume endpoint in the env var). The
endpoint's `eth_chainId` must match or the run refuses before anything
else.

Workflow — dry run first, always:

```sh
cd demo-evm
cargo run                          # dry run: chain-id sanity, balance
                                   # gate, live nonce/fees, UNSIGNED tx.
                                   # No signature is produced by design
                                   # (SPEC §8.6 single-use).
cargo run -- --broadcast           # signs (fresh presignature) + sends,
                                   # polls the receipt, prints the
                                   # explorer link.
```

Faucets (Sepolia; the run prints the committee address and this list
when unfunded): sepoliafaucet.com, the Google Cloud web3 faucet, the
QuickNode faucet. Fund the committee address, re-run the dry run, then
broadcast.

Drivers (`--driver sim|mesh`, default `sim`):

- `sim` — the in-process reference committee (M1/M2 arc).
- `mesh` — three REAL per-node `PartyNode` drivers on loopback TCP with
  per-node durable single-use stores (`demo-evm/data/mesh/node-<id>/`,
  gitignored — sealed records, never commit). Deterministic keygen keeps
  the mesh address stable across runs; presignature ids come from
  monotonic counter files in the data dir, and the durable store's
  consume tombstone enforces single-use — a failed broadcast attempt is
  never retried with the same presignature. The mesh committee is a
  FRESH key with its own address (fund it separately).

Single-use posture (§8.6), restated for operators: one presignature
signs exactly one transaction, ever; dry runs sign nothing; broadcast
attempts burn their record whether or not the tx lands. If a run dies
mid-broadcast, re-run — the driver moves to the next record on its own.
