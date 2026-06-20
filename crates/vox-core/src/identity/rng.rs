//! CSPRNG access for identity key generation.
//!
//! Vox derives every key from a fixed-size random *seed* and then uses the
//! library's deterministic-from-seed key generation, rather than threading a
//! `rand_core` RNG object through the cryptographic crates. This keeps a single,
//! auditable randomness source ([`getrandom`], the OS CSPRNG) and sidesteps the
//! two coexisting `rand_core` major versions in the dependency tree (the dalek
//! crates use 0.6, the RustCrypto PQ crates use 0.10).

use crate::error::{Error, Result};

/// Fill `dst` with cryptographically-secure random bytes from the OS CSPRNG.
///
/// Returns [`Error::Rng`] if the platform RNG is unavailable — this is a hard
/// failure (Vox never falls back to a weaker source).
pub fn fill_random(dst: &mut [u8]) -> Result<()> {
    getrandom::fill(dst).map_err(|_| Error::Rng)
}

/// Allocate and return `N` random bytes from the OS CSPRNG.
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill_random(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_changes_buffer_and_differs_across_calls() {
        let a = random_array::<32>().unwrap();
        let b = random_array::<32>().unwrap();
        // Astronomically improbable to collide; a real failure here means the
        // RNG is broken.
        assert_ne!(a, b);
        // Not all-zero.
        assert_ne!(a, [0u8; 32]);
    }
}
