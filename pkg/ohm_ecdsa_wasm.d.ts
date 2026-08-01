/* tslint:disable */
/* eslint-disable */

/**
 * The same arc with ONE injected fault (SPEC §10 blame matrix — the
 * blamed ids mirror `tests/blame_matrix.rs` ground truth):
 * `bad-deal` (F2, keygen), `bad-product-proof` (F3, triples),
 * `bad-open-share` (F4, presign P2), `bad-nonce-point` (F5, presign
 * P3), `bad-sign-share` (F6, sign). Returns the abort the core raises:
 * `{ fault, faultClass, check, phase, blamed, detail }`.
 */
export function arc_with_tamper(seed: bigint, phase: string, party: number): any;

/**
 * The honest 2-of-3 full arc (SPEC §6 → §7 → §8 → §9) under one seed:
 * keygen, one Beaver triple, one presignature, one signature — all via
 * the core's sim drivers. Returns one object with a key per phase;
 * every value is a truncated-display hex string (full 32-byte hex) or
 * a boolean computed by the core's own checks. Marshalling only.
 */
export function full_arc(seed: bigint): any;

/**
 * Run the REAL 2-of-3 keygen (SPEC §6 via `sim::run_keygen`) under a
 * deterministic seed. Returns `{ x, commitment, parties }`: the joint
 * key X (SEC1 compressed hex), the Feldman commitment points to the
 * joint sharing polynomial, and each party's `{ index, share }`.
 */
export function keygen(seed: bigint): any;

/**
 * Lagrange interpolation at 0 (SPEC §4.1): reconstruct the secret
 * from the given `(id, share)` pairs. Errors when fewer than `t`
 * shares are selected — below the threshold the secret is
 * information-theoretically hidden.
 */
export function reconstruct(t: number, ids: Uint32Array, shares_hex: string[]): string;

/**
 * Deal a Shamir sharing (SPEC §4.1) of `secret_hex` with threshold `t`
 * over parties `1..=n`, plus its Feldman commitment (§4.2).
 *
 * PLOT PROJECTION (documented on the page): the non-constant
 * coefficients are dealt SMALL (32-bit) scalars so the polynomial is
 * drawable over the reals — every check (Feldman verify, Lagrange
 * reconstruct) still runs over the full secp256k1 field. An empty
 * `secret_hex` derives a small secret from `seed` (also plot-friendly).
 *
 * Returns `{ secret, coeffs, coeffsNum, commitment, shares }` with
 * shares as `{ id, hex, num }`; the `*Num` fields are the f64 display
 * projection (see `scalar_to_f64`).
 */
export function shamir_demo(secret_hex: string, t: number, n: number, seed: bigint): any;

/**
 * Feldman share verification (SPEC §4.2): `share·G == EvalCom(A, id)`
 * by point equality against the commitment (SEC1 hex array). This is
 * the primitive behind identifiable abort (§10) — a wrong share fails
 * publicly.
 */
export function verify_share(commitment: any, id: number, share_hex: string): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly arc_with_tamper: (a: bigint, b: number, c: number, d: number) => [number, number, number];
    readonly full_arc: (a: bigint) => [number, number, number];
    readonly keygen: (a: bigint) => [number, number, number];
    readonly reconstruct: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly shamir_demo: (a: number, b: number, c: number, d: number, e: bigint) => [number, number, number];
    readonly verify_share: (a: any, b: number, c: number, d: number) => [number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
