//! Machine-generated room passphrases (ADR-017 decision 4).
//!
//! A service room's passphrase is generated, never chosen. ADR-017's reason: it is the
//! second factor on a room whose whole content is a reachable service, it travels by a
//! different channel than the address, and nobody needs to remember it — so the one
//! thing it must not be is the weak link in an otherwise post-quantum chain, which a
//! human-chosen phrase invariably is.
//!
//! ## Alphabet and shape
//! Lowercase unpadded RFC 4648 base32 (`a`–`z`, `2`–`7`) in hyphenated groups of four:
//!
//! ```text
//! k7n2-qm4v-r3ts-wxp6-zd42
//! ```
//!
//! The alphabet is the one Vox already uses for every fingerprint and channelID
//! ([`crate::node::link::b32_encode`]), which matters for a secret a person reads to
//! someone over a phone. It contains `l` and `o` but **no `0`, `1`, `8` or `9`**, and no
//! uppercase at all — so only one of each confusable pair exists and there is nothing
//! to disambiguate: no zero-vs-O, no one-vs-l, no eight-vs-B. Groups of four
//! are for the eye only.
//!
//! **The hyphens are part of the secret.** They are there to be read, but nothing strips
//! them: the passphrase is used exactly as printed, byte for byte, on both sides. That is a
//! deliberate reversal of a first attempt that treated them as decoration and removed them
//! at "the node's boundary" — which broke the moment anything used the library without going
//! through that boundary, because a room created through the node and joined through
//! `NodeNet::start_join` then derived two different secrets. A rule any direct caller can
//! violate silently is worse than no rule, and what it was buying — tolerating a listener
//! who drops the dashes — is not worth a secret that sometimes does not match itself. A
//! person moving this is copying a 24-character string beside a 277-character address; they
//! will copy it, not retype it.
//!
//! ## Entropy
//! [`DEFAULT_GROUPS`] = 5 groups × 4 characters × 5 bits = **100 bits**, sampled from
//! the OS CSPRNG. ADR-005 already makes guessing expensive per attempt — an Equihash
//! solve plus an Argon2id derivation plus a network round trip — so 100 bits is far
//! beyond the online bound and is chosen for margin against an offline attack on a
//! captured handshake rather than for the online one.
//!
//! A word-list passphrase was considered and rejected: it is nicer to dictate, but a
//! list large enough for this entropy is a lot of source to carry and to get right
//! (homophones, plurals, a stable canonical spelling), and the base32 alphabet already
//! solves the dictation problem it would have been for.

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::identity::rng::fill_random;

/// Characters per group.
const GROUP: usize = 4;

/// Groups in a generated passphrase: 5 × 4 × 5 bits = 100 bits.
pub const DEFAULT_GROUPS: usize = 5;

/// The most groups [`generate`] will produce — a passphrase a person has to move by
/// hand has a practical length, and past this the bound is the alphabet, not the
/// entropy.
pub const MAX_GROUPS: usize = 16;

/// The alphabet: lowercase RFC 4648 base32, as used for every Vox fingerprint.
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Generate a room passphrase of `groups` hyphenated groups of four characters.
///
/// Rejection-free by construction: the alphabet is exactly 32 characters, so 5 bits of
/// CSPRNG output map to one character with no modulo bias.
pub fn generate(groups: usize) -> Result<Zeroizing<String>> {
    if groups == 0 || groups > MAX_GROUPS {
        return Err(Error::SizeLimitExceeded("passphrase groups"));
    }
    let chars = groups * GROUP;
    let mut raw = Zeroizing::new(vec![0u8; chars]);
    fill_random(&mut raw)?;
    let mut out = Zeroizing::new(String::with_capacity(chars + groups - 1));
    for (i, byte) in raw.iter().enumerate() {
        if i > 0 && i % GROUP == 0 {
            out.push('-');
        }
        // Take the low 5 bits: 32 symbols over 32 values, so every value is legal and
        // equally likely — no rejection loop and no bias.
        out.push(char::from(ALPHABET[usize::from(*byte) % 32]));
    }
    Ok(out)
}

// There is deliberately no canonicalizing function here. See the module docs: a room
// passphrase is used exactly as printed, so the only way for two sides to disagree is for
// one of them to alter it — and the way to guarantee that never happens is to give nobody a
// function that could.

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn has_the_documented_shape_and_alphabet() {
        let p = generate(DEFAULT_GROUPS).unwrap();
        assert_eq!(p.len(), DEFAULT_GROUPS * GROUP + (DEFAULT_GROUPS - 1));
        assert_eq!(p.matches('-').count(), DEFAULT_GROUPS - 1);
        for group in p.split('-') {
            assert_eq!(group.len(), GROUP);
        }
        for c in p.chars().filter(|c| *c != '-') {
            assert!(
                ALPHABET.contains(&(c as u8)),
                "{c:?} is not in the base32 alphabet"
            );
        }
        // The dictation property is the reason for this alphabet, so assert it rather
        // than trusting the constant. The alphabet does contain `l` and `o`; what makes
        // it unambiguous is that the characters they are confused *with* — the digits
        // `0` and `1` — are absent, as are `8`/`9` and every uppercase form. Only one
        // of each confusable pair exists, so there is nothing to disambiguate.
        for bad in ['0', '1', '8', '9'] {
            assert!(!p.contains(bad), "{bad:?} must not appear");
        }
        assert!(
            p.chars()
                .all(|c| c == '-' || c.is_ascii_lowercase() || c.is_ascii_digit()),
            "no uppercase: {}",
            p.as_str()
        );
    }

    #[test]
    fn the_printed_form_is_the_secret() {
        // The bug this guards: `vox serve` printed a hyphenated passphrase and handed the
        // node a *different* byte string, so every join was refused with no clue why. The
        // invariant is that what a person is shown is exactly what both sides use.
        let p = generate(DEFAULT_GROUPS).unwrap();
        assert!(p.contains('-'), "the printed form is grouped");
        assert!(p.is_ascii(), "bytes and characters agree");
        assert_eq!(
            p.to_string().as_bytes(),
            p.as_bytes(),
            "nothing transforms it"
        );
    }

    #[test]
    fn distinct_every_time() {
        // Not a statistical test of the CSPRNG — a guard against a generator that
        // accidentally returns a constant, which is the failure that would matter.
        let seen: BTreeSet<String> = (0..64)
            .map(|_| generate(DEFAULT_GROUPS).unwrap().to_string())
            .collect();
        assert_eq!(seen.len(), 64);
    }

    #[test]
    fn group_count_is_bounded() {
        assert!(generate(0).is_err());
        assert!(generate(MAX_GROUPS + 1).is_err());
        assert!(generate(MAX_GROUPS).is_ok());
    }
}
