//! Ephemeral Diffie-Hellman shares and the Burmester–Desmedt combiner (ADR-009
//! §"Concrete protocol", steps 1–2).
//!
//! Each member `i` holds a fresh ephemeral DH secret `x_i` and publishes the
//! share `z_i = g^{x_i}` (here over Ristretto255: `z_i = x_i · G`). The epoch key
//! is the **classical Burmester–Desmedt** combination over the shares in
//! ascending-composite-pubkey order:
//!
//! ```text
//! K = g^{ x_1 x_2 + x_2 x_3 + … + x_{m-1} x_m + x_m x_1 }
//! ```
//!
//! i.e. `K = g^{Σ_i x_i · x_{i+1 mod m}}`, the sum of all consecutive-pair products
//! around the ring (Burmester & Desmedt, EUROCRYPT '94; Katz–Yung, CRYPTO '03).
//! Every member derives the **same** group element from public values plus its own
//! secret, via the per-member combiner (`bd_member_key`):
//!
//! ```text
//! K_i = n·x_i · z_{i-1}  +  (n-1)·X_i  +  (n-2)·X_{i+1}  +  …  +  1·X_{i+n-2}
//! ```
//!
//! where `X_i = x_i · (z_{i+1} − z_{i-1})` is member `i`'s round-2 value and all
//! indices are taken modulo `n` over the sorted ring (additive notation, so `g^a`
//! ↦ `a · G` and the product becomes a sum). The two-party case (`n = 2`) is the
//! BD degeneracy where both round-2 values vanish; we follow the universal
//! implementation convention and use plain ECDH `K = x_a · z_b` (see
//! `bd_group_key_from_secrets` and the module tests).
//!
//! `K` here is a Ristretto group element, compressed to 32 bytes and fed as IKM to
//! HKDF in [`crate::deniable::dgka`]. It is used **only** for key
//! confirmation/binding — never to encrypt content (ADR-009). A classical `K` is
//! therefore acceptable: it carries no harvest-now-decrypt-later exposure.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::identity::rng::random_array;

/// Length of a serialized ephemeral DH share (compressed Ristretto255 point).
pub const SHARE_LEN: usize = 32;

/// A member's ephemeral Diffie-Hellman keypair for one epoch: the secret scalar
/// `x_i` (zeroized) and the public share `z_i = x_i · G`.
///
/// The secret is held only until the epoch key `K` has been derived; like the
/// other ephemeral key material it never persists. (The DH *secret* is unrelated
/// to the ephemeral *signing* secret `esk_i` — that lives in
/// [`crate::deniable::epoch`].)
pub struct EphemeralShare {
    /// The secret scalar `x_i`. Held in its canonical bytes so it can be wiped;
    /// the live `Scalar` is reconstructed on demand (`Scalar` is `Copy` and short
    /// lived, the bytes are the durable secret — same pattern as M3 CPace).
    secret: SecretScalar,
    /// The public share `z_i = x_i · G`, compressed.
    public: [u8; SHARE_LEN],
}

/// A 32-byte secret scalar that zeroizes on drop. Stored as canonical bytes; the
/// live [`Scalar`] is re-derived when needed (mirrors M3 CPace's `SecretScalar`).
struct SecretScalar {
    bytes: [u8; 32],
}

impl SecretScalar {
    fn new(s: &Scalar) -> Self {
        Self {
            bytes: s.to_bytes(),
        }
    }

    fn scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.bytes)
    }
}

impl Drop for SecretScalar {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl core::fmt::Debug for EphemeralShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never render the secret; the public share is safe to show.
        f.debug_struct("EphemeralShare")
            .field("public", &crate::hash::Hex(&self.public))
            .finish_non_exhaustive()
    }
}

impl EphemeralShare {
    /// Sample a fresh ephemeral DH keypair from the OS CSPRNG. The secret scalar
    /// is sampled the same way M3 CPace samples its scalar (252-bit uniform,
    /// reduced mod the group order) so the share distribution matches the rest of
    /// the Ristretto stack.
    pub fn generate() -> Result<Self> {
        let mut bytes = random_array::<32>()?;
        bytes[31] &= 0x0f; // clear bits 252..256 (group_size_bits = 252)
        let secret = Scalar::from_bytes_mod_order(bytes);
        bytes.zeroize();
        let public = (&secret * RISTRETTO_BASEPOINT_TABLE).compress().to_bytes();
        Ok(Self {
            secret: SecretScalar::new(&secret),
            public,
        })
    }

    /// The public share `z_i = x_i · G` (compressed Ristretto255, 32 bytes).
    #[must_use]
    pub fn public_bytes(&self) -> [u8; SHARE_LEN] {
        self.public
    }

    /// This member's round-2 value `X_i = x_i · (z_{i+1} − z_{i-1})` (ADR-009 step
    /// 2 / Burmester–Desmedt round 2). `left` is `z_{i-1}` and `right` is
    /// `z_{i+1}`, the cyclic neighbors in the sorted ring. Returns the compressed
    /// point. Rejects a degenerate (identity) `X_i`, which would signal a
    /// neighbor's malformed share.
    pub fn round2_value(
        &self,
        left: &[u8; SHARE_LEN],
        right: &[u8; SHARE_LEN],
    ) -> Result<[u8; SHARE_LEN]> {
        let z_left = decompress(left)?;
        let z_right = decompress(right)?;
        let x = self.secret.scalar();
        let diff = z_right - z_left;
        let xi = x * diff;
        Ok(xi.compress().to_bytes())
    }

    /// Derive the Burmester–Desmedt epoch key `K` as this member (index `i` in the
    /// sorted ring of size `n`), from all members' shares `z_*` and round-2 values
    /// `x_*`. `shares` and `round2` are indexed by ring position (0-based here);
    /// `i` is this member's position. Returns the compressed group element `K`.
    ///
    /// For `n == 2` the BD ring degenerates (both round-2 values are the identity)
    /// so we use plain ECDH `K = x_i · z_{other}` — the universal convention. For
    /// `n == 1` there is no agreement to combine (a single-member deniable epoch is
    /// rejected upstream in [`crate::deniable::dgka`]).
    pub fn group_key(
        &self,
        i: usize,
        shares: &[[u8; SHARE_LEN]],
        round2: &[[u8; SHARE_LEN]],
    ) -> Result<[u8; SHARE_LEN]> {
        let n = shares.len();
        if n < 2 || round2.len() != n || i >= n {
            return Err(Error::MalformedBundle("dgka group-key inputs"));
        }
        let x = self.secret.scalar();
        if n == 2 {
            // BD degeneracy → plain ECDH with the single other member.
            let other = decompress(&shares[1 - i])?;
            let k = x * other;
            if k.is_identity() {
                return Err(Error::MalformedBundle("dgka degenerate group key"));
            }
            return Ok(k.compress().to_bytes());
        }
        bd_member_key(i, &x, shares, round2)
    }
}

/// Decompress a 32-byte compressed Ristretto share, rejecting a non-canonical or
/// identity point (a peer's degenerate/forged share, ADR-009 anti-abuse — mirrors
/// the CPace `scalar_mult_vfy` MUST-abort).
fn decompress(bytes: &[u8; SHARE_LEN]) -> Result<RistrettoPoint> {
    let p = CompressedRistretto(*bytes)
        .decompress()
        .ok_or(Error::MalformedBundle("dgka invalid share encoding"))?;
    if p.is_identity() {
        return Err(Error::MalformedBundle("dgka identity share"));
    }
    Ok(p)
}

/// The per-member Burmester–Desmedt key combiner (additive notation), for `n ≥ 3`:
///
/// ```text
/// K_i = n·x_i · z_{i-1}  +  Σ_{j=0}^{n-2} (n-1-j) · X_{(i+j) mod n}
/// ```
///
/// The exponent chain on the `X` terms is `n-1, n-2, …, 1` (Burmester & Desmedt,
/// EUROCRYPT '94). All members compute the **same** group element
/// `K = Σ_i x_i x_{i+1}` (telescoping ring exponent). Indices are cyclic mod `n`.
fn bd_member_key(
    i: usize,
    x_i: &Scalar,
    shares: &[[u8; SHARE_LEN]],
    round2: &[[u8; SHARE_LEN]],
) -> Result<[u8; SHARE_LEN]> {
    let n = shares.len();
    // n·x_i · z_{i-1}: the "left neighbor" contribution, weighted by n.
    let n_scalar = Scalar::from(n as u64);
    let z_left = decompress(&shares[(i + n - 1) % n])?;
    let mut acc = (n_scalar * x_i) * z_left;
    // Σ_{j=0}^{n-2} (n-1-j) · X_{(i+j) mod n}, exponents n-1 .. 1.
    for j in 0..(n - 1) {
        let coeff = Scalar::from((n - 1 - j) as u64);
        let x_term = decompress(&round2[(i + j) % n])?;
        acc += coeff * x_term;
    }
    if acc.is_identity() {
        return Err(Error::MalformedBundle("dgka degenerate group key"));
    }
    Ok(acc.compress().to_bytes())
}

/// Compute the canonical Burmester–Desmedt group key `K = g^{Σ x_i x_{i+1}}`
/// directly from all members' **secret** scalars, for the `n ≥ 3` correctness
/// check (test-only oracle and the shared-value reference). Not used in the
/// protocol — members never hold each other's secrets — but it pins the value
/// every member's [`EphemeralShare::group_key`] must equal.
#[cfg(test)]
#[must_use]
pub(crate) fn bd_group_key_from_secrets(secrets: &[Scalar]) -> RistrettoPoint {
    let n = secrets.len();
    let mut exp = Scalar::ZERO;
    for i in 0..n {
        exp += secrets[i] * secrets[(i + 1) % n];
    }
    &exp * RISTRETTO_BASEPOINT_TABLE
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::traits::Identity;

    fn secret_of(s: &EphemeralShare) -> Scalar {
        s.secret.scalar()
    }

    /// Build the sorted ring of `n` members, run the (in-test) two BD rounds, and
    /// assert every member derives the identical `K` equal to the secret-oracle.
    fn run_bd(n: usize) {
        let members: Vec<EphemeralShare> = (0..n)
            .map(|_| EphemeralShare::generate().unwrap())
            .collect();
        let shares: Vec<[u8; SHARE_LEN]> = members.iter().map(|m| m.public_bytes()).collect();
        // Round 2: each member computes X_i against its cyclic neighbors.
        let round2: Vec<[u8; SHARE_LEN]> = (0..n)
            .map(|i| {
                let left = shares[(i + n - 1) % n];
                let right = shares[(i + 1) % n];
                members[i].round2_value(&left, &right).unwrap()
            })
            .collect();
        // Every member derives the same K.
        let keys: Vec<[u8; SHARE_LEN]> = (0..n)
            .map(|i| members[i].group_key(i, &shares, &round2).unwrap())
            .collect();
        for k in &keys {
            assert_eq!(k, &keys[0], "all members must derive the same K (n={n})");
        }
        // For n >= 3, K must equal the canonical secret-oracle value.
        if n >= 3 {
            let secrets: Vec<Scalar> = members.iter().map(secret_of).collect();
            let oracle = bd_group_key_from_secrets(&secrets).compress().to_bytes();
            assert_eq!(
                keys[0], oracle,
                "K must equal g^{{Σ x_i x_{{i+1}}}} (n={n})"
            );
        }
    }

    #[test]
    fn bd_three_members_agree() {
        run_bd(3);
    }

    #[test]
    fn bd_five_members_agree() {
        run_bd(5);
    }

    #[test]
    fn bd_seven_members_agree() {
        run_bd(7);
    }

    #[test]
    fn two_member_degeneracy_is_plain_ecdh() {
        // n=2: K = x_a · z_b = x_b · z_a = x_a x_b · G, and both members agree.
        let a = EphemeralShare::generate().unwrap();
        let b = EphemeralShare::generate().unwrap();
        let shares = [a.public_bytes(), b.public_bytes()];
        // round2 values are unused for n=2 but pass placeholders of correct len.
        let r2 = [a.public_bytes(), b.public_bytes()];
        let ka = a.group_key(0, &shares, &r2).unwrap();
        let kb = b.group_key(1, &shares, &r2).unwrap();
        assert_eq!(ka, kb);
        // And it equals plain ECDH x_a x_b G.
        let prod = secret_of(&a) * secret_of(&b);
        let expect = (&prod * RISTRETTO_BASEPOINT_TABLE).compress().to_bytes();
        assert_eq!(ka, expect);
    }

    #[test]
    fn rejects_identity_share() {
        let m = EphemeralShare::generate().unwrap();
        let identity = RistrettoPoint::identity().compress().to_bytes();
        let shares = [m.public_bytes(), identity, m.public_bytes()];
        let r2 = shares;
        assert!(matches!(
            m.group_key(0, &shares, &r2),
            Err(Error::MalformedBundle(_))
        ));
    }

    #[test]
    fn rejects_bad_inputs() {
        let m = EphemeralShare::generate().unwrap();
        let shares = [m.public_bytes()];
        let r2 = [m.public_bytes()];
        // n < 2 rejected.
        assert!(m.group_key(0, &shares, &r2).is_err());
    }

    #[test]
    fn round2_round_trips_a_point() {
        // X_i must be a valid, decompressible point.
        let m = EphemeralShare::generate().unwrap();
        let l = EphemeralShare::generate().unwrap().public_bytes();
        let r = EphemeralShare::generate().unwrap().public_bytes();
        let x = m.round2_value(&l, &r).unwrap();
        assert!(CompressedRistretto(x).decompress().is_some());
    }
}
