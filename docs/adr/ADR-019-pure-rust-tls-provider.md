# ADR-019: A pure-Rust TLS crypto provider

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: proposed (2026-09-21). Nothing in this ADR is built. On integrate/v0.3.0 the
transport still uses rustls's `aws_lc_rs` provider (`transport/provider.rs`),
`rustls-post-quantum` for X25519MLKEM768, quinn's `rustls-aws-lc-rs` feature and `rcgen`'s
`aws_lc_rs` feature (workspace `Cargo.toml`).
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: transport, tls, quic, rust-maximal, supply-chain, post-quantum

## Context

ADR-001 principle 10 makes Vox Rust-maximal. ADR-011 and `transport/provider.rs` justify one
exception, the C/assembly AWS-LC backend, on the grounds that no pure-Rust provider for the
X25519MLKEM768 group exists. That premise is false: every primitive a Vox-only TLS 1.3 provider needs
is already a pure-Rust dependency (`x25519-dalek`, `ml-kem`, `aes-gcm`, `sha2`, `hkdf`, `hmac`,
`ed25519-dalek`, `getrandom`), and Vox uses exactly one signature algorithm (Ed25519, self-signed
leaf, custom verifier). The AWS-LC code sits on an internet-reachable, pre-authentication path (the
node maps its QUIC port by UPnP-IGD/PCP), and `#![forbid(unsafe_code)]` covers Vox's crates, not
`aws-lc-sys`.

The blocker is a Cargo feature graph, not cryptography: quinn-proto has no feature that takes
`dep:rustls` without `ring` or `aws-lc-rs`, and its only direct C use is the RFC 9001 Retry
Integrity Tag (AES-128-GCM under a published constant key and nonce). `aws-lc-rs` enters the tree
through `rustls`, `rustls-post-quantum`, `quinn-proto` and `rcgen`.

## Requirements

### The provider

Requirements 2–7 apply if Vox builds the provider (requirement 1).

1. Vox SHOULD build and use its own pure-Rust `rustls::crypto::CryptoProvider`, scoped to exactly
   what Vox negotiates, and SHOULD remove `aws-lc-rs` from the dependency tree.
2. **Key exchange.** The provider MUST implement `X25519MLKEM768` as its own
   `SupportedKxGroup`/`ActiveKeyExchange` from `x25519-dalek` and `ml-kem`. The share MUST be the
   ML-KEM-768 encapsulation key concatenated with the X25519 public key, and the shared secret the
   ML-KEM shared secret concatenated with the X25519 shared secret, in the order the draft fixes.
3. The group MUST be tested against `rustls-post-quantum` as a known-answer oracle (same shares in,
   same secret out, across many random runs) before `rustls-post-quantum` is removed.
4. **Cipher suites.** The provider MUST supply TLS 1.3 cipher suites from `aes-gcm` (and
   `chacha20poly1305` if kept) with each suite's `quic` field populated, so quinn's packet and
   header protection keep working.
5. **Signatures.** The provider MUST verify Ed25519 only, via `ed25519-dalek`, and MUST reject every
   other signature algorithm.
6. **Leaf certificate.** Vox SHOULD emit the self-signed leaf's DER itself and drop `rcgen`.
7. **quinn-proto.** Vox SHOULD upstream a quinn-proto feature that takes `dep:rustls` without
   `ring` or `aws-lc-rs` and takes the Retry Integrity Tag from the provider (or from `aes-gcm`).
   Vox MAY carry a vendored patch if upstream is slow. This is the only change outside Vox's own
   code.

### Claims

8. Vox MUST NOT claim that "pure Rust" means "no `unsafe`" or that the transport is memory-safe end
   to end: `aes` reaches AES-NI through `unsafe` intrinsics and other dependencies use `unsafe`.
   The claim is limited to removing C/assembly from what an unauthenticated remote party reaches.
   ADR-011 MUST NOT say otherwise.
9. Performance against the AWS-LC provider MUST be measured, not assumed.

### Milestones

Each milestone is one branch with the six gates, and MUST be proved before the next begins.

10. **M19.1 — the group.** Requirements 2 and 3. Gate: a real Vox handshake completes with Vox's
    group while the `aws_lc_rs` provider still supplies everything else.
11. **M19.2 — the suites and the provider.** Requirements 4 and 5, with `aws-lc-rs` present but
    unused. Gate: a real loopback QUIC handshake between two Vox nodes, then the existing M14, M15
    and M17 gates, unchanged and green.
12. **M19.3 — the leaf.** Requirement 6. Gate: the existing identity-certificate proofs, plus a
    byte comparison against an `rcgen`-produced leaf for the same key.
13. **M19.4 — quinn.** Requirement 7. Gate: `cargo tree` shows neither `aws-lc-sys` nor `ring`, and
    every gate above stays green.
14. **M19.5 — the claim.** ADR-011 and ADR-001 principle 10 MUST be amended to delete the exception
    and state, per requirement 8, what "pure Rust" does and does not mean.
15. **Abort condition.** If M19.1 cannot be proved equivalent to a known-good implementation, this
    ADR MUST be abandoned, `aws-lc-rs` stays, and ADR-011's justification MUST be corrected to the
    true reason ("we chose not to own this crypto") instead of "it does not exist".

## Consequences

- **Positive.** The Rust-maximal exception and its false premise go away; the pre-authentication
  attack surface holds less foreign-language code; `aws-lc-sys` and its build machinery (cmake,
  nasm, prebuilt objects) leave the supply chain, which simplifies cross-compiling the release
  targets; the provider offers one group and one signature algorithm.
- **Negative.** Vox owns TLS-adjacent crypto glue in its highest-consequence code, without
  AWS-LC's review history, FIPS validation or constant-time scrutiny; a mistake in nonce
  construction, the key schedule or constant-time comparison is a full break of the transport. An
  upstream dependency has to change or be vendored, a recurring cost. Dropping `rcgen` means owning
  X.509 DER emission (emitting, not parsing).

## Related ADRs

- **Depends on:** ADR-001 (principle 10, Rust-maximal), ADR-003 (suite policy), ADR-011 (transport
  substrate).
- **Supersedes,** if and only if M19.4 completes: the single Rust-maximal exception recorded in
  ADR-011 and `transport/provider.rs`.
