//! Wall-clock micro-benchmarks for the SPEC §13.5 performance-model rows
//! (single-threaded reference sim, `std::time::Instant` only — no external
//! benchmarking crates).
//!
//! Run: `cargo run --release --example perf`

use std::time::{Duration, Instant};

use k256::elliptic_curve::ff::Field;
use k256::{ProjectivePoint, Scalar};
use ohm_ecdsa::{dleq, sim, triples, Params};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn median<F: FnMut()>(iters: usize, mut f: F) -> Duration {
    let mut v: Vec<Duration> = (0..iters)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed()
        })
        .collect();
    v.sort_unstable();
    v[v.len() / 2]
}

fn ms(d: Duration) -> String {
    format!("{:.3}", d.as_secs_f64() * 1e3)
}

fn bench_group(n: usize, t: usize, iters: usize) {
    let params = Params::new(n, t).unwrap();
    let mut seed = 0xC0FFEEu64;
    let mut rngs = move || {
        seed += 1;
        sim::make_rngs(n, seed)
    };
    println!("### {t}-of-{n} (median, ms; slow rows over fewer iters)");
    let keygen = median(iters, || {
        sim::run_keygen(&params, b"perf/key", &mut rngs()).unwrap();
    });
    let triple = median(iters, || {
        triples::generate(&params, b"perf/triple", &mut rngs()).unwrap();
    });
    let triple_b = median(iters / 2, || {
        triples::generate_batch(&params, b"perf/triple-batch", 10, &mut rngs()).unwrap();
    });
    let keys = sim::run_keygen(&params, b"perf/keys", &mut rngs()).unwrap();
    let presign = median(iters / 2, || {
        sim::run_presign(&params, &keys, 1, &mut rngs(), None).unwrap();
    });
    let ids: Vec<u64> = (1..=10).collect();
    let presign_b = median(iters / 5, || {
        sim::run_presign_batch(&params, &keys, &ids, &mut rngs(), None).unwrap();
    });
    let presigs = sim::run_presign(&params, &keys, 2, &mut rngs(), None).unwrap();
    let sign = median(iters * 5, || {
        sim::run_sign(&params, &presigs, b"perf message", None).unwrap();
    });
    println!("| Operation | wall-clock | amortized |");
    println!("|---|---|---|");
    println!("| KeyGen | {} ms | — |", ms(keygen));
    println!("| Triple (single) | {} ms | — |", ms(triple));
    println!(
        "| Triple batch B=10 | {} ms | {} ms/triple |",
        ms(triple_b),
        ms(triple_b / 10)
    );
    println!("| Presign (single) | {} ms | — |", ms(presign));
    println!(
        "| Presign batch B=10 | {} ms | {} ms/presig |",
        ms(presign_b),
        ms(presign_b / 10)
    );
    println!("| Sign (online) | {} ms | — |", ms(sign));
    println!();
}

/// DLEQ product-proof verification, B=10 proofs of one prover: 10
/// individual verifications vs the §7.3 aggregate fast path (the two paths
/// are what `triples::generate_batch` runs on failure / success).
fn bench_dleq() {
    let mut rng = StdRng::seed_from_u64(7);
    let g1 = ProjectivePoint::GENERATOR;
    let g2 = g1 * Scalar::random(&mut rng);
    let mut stmts = Vec::new();
    let mut proofs = Vec::new();
    for _ in 0..10 {
        let x = Scalar::random(&mut rng);
        let (x1, x2, p) = dleq::prove(b"perf", b"perf", &x, &g1, &g2, &mut rng);
        stmts.push((g1, x1, g2, x2));
        proofs.push(p);
    }
    let prefs: Vec<&dleq::DleqProof> = proofs.iter().collect();
    let individual = median(200, || {
        for ((g1, x1, g2, x2), p) in stmts.iter().zip(&proofs) {
            assert!(dleq::verify(b"perf", b"perf", g1, x1, g2, x2, p));
        }
    });
    let aggregate = median(200, || {
        assert!(dleq::verify_batch(b"perf", b"perf", 1, &stmts, &prefs))
    });
    println!("### Batch DLEQ verification, B=10 (median of 200 runs)");
    println!("| Path | wall-clock |");
    println!("|---|---|");
    println!("| 10× individual `dleq::verify` | {} ms |", ms(individual));
    println!("| aggregate `dleq::verify_batch` | {} ms |", ms(aggregate));
}

fn main() {
    println!(
        "OHM-ECDSA perf — single-threaded sim, arch {}",
        std::env::consts::ARCH
    );
    println!();
    bench_group(3, 2, 50);
    bench_group(5, 3, 20);
    bench_dleq();
}
