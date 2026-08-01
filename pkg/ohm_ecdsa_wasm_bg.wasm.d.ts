/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const arc_with_tamper: (a: bigint, b: number, c: number, d: number) => [number, number, number];
export const full_arc: (a: bigint) => [number, number, number];
export const keygen: (a: bigint) => [number, number, number];
export const reconstruct: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
export const shamir_demo: (a: number, b: number, c: number, d: number, e: bigint) => [number, number, number];
export const verify_share: (a: any, b: number, c: number, d: number) => [number, number, number];
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_externrefs: WebAssembly.Table;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_start: () => void;
