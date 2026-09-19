//! Measurement spike for the ADR-005 join proof-of-work (Tier 2 #8,
//! 2026-09-19): times the pure-Rust generalized-Wagner Equihash solver at a
//! given `(n, k)` over a number of nonces and reports solve time and solutions
//! per nonce, so difficulty defaults are set from data, not prose.
//!
//! Usage: `cargo run --release --example spike_pow -- <n> <k> <nonces>`
//! Wrap in `/usr/bin/time -l` (macOS) / `-v` (Linux) for peak RSS.

use std::time::Instant;

use vox_core::join::pow::{wagner, PowParams};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(200);
    let k: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(9);
    let nonces: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3);
    let params = match PowParams::new(n, k) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("invalid params ({n},{k}): {e}");
            std::process::exit(2);
        }
    };
    let seed = [0x5Au8; 32];
    println!("equihash ({n},{k}) pure-Rust Wagner, {nonces} nonce(s)");
    let mut total_solutions = 0usize;
    let mut total_secs = 0f64;
    for counter in 0..nonces {
        let nonce = wagner::nonce_bytes(counter);
        let t0 = Instant::now();
        let sols = match wagner::solve(params, &seed, &nonce) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("solve error: {e}");
                std::process::exit(1);
            }
        };
        let dt = t0.elapsed().as_secs_f64();
        total_secs += dt;
        total_solutions += sols.len();
        println!("nonce {counter}: {dt:.3} s, {} solution(s)", sols.len());
    }
    println!(
        "mean {:.3} s/nonce, {:.2} solutions/nonce",
        total_secs / f64::from(nonces),
        total_solutions as f64 / f64::from(nonces)
    );
}
