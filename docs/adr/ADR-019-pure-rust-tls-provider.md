# ADR-019: A pure-Rust TLS crypto provider — removing the last C/assembly dependency

**Status**: **proposed** (2026-09-21) — written to be reviewed and refined before any code is
written. Nothing in this ADR is implemented.
**Date**: 2026-09-21
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: transport, tls, quic, rust-maximal, supply-chain, post-quantum

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT** and **MAY** in this
document are to be interpreted as described in BCP 14 (RFC 2119 and RFC 8174).

## Context

ADR-001 principle 10 makes vox Rust-maximal. ADR-011 carves out exactly one exception, and
`transport/provider.rs` states it:

> the `aws-lc-rs` provider (a C/asm AWS-LC backend) is what currently supplies the X25519MLKEM768
> hybrid group named by ADR-011, and **a Rust-pure provider for that group does not exist in the
> ecosystem**.

**That premise is wrong**, and the exception rests on it. "No crate ships it" is not "we cannot have
it". This matters beyond purity: the node performs UPnP-IGD/PCP mapping of its QUIC port, so this C
code sits on an **internet-reachable, pre-authentication** path. `#![forbid(unsafe_code)]` covers our
crates, not `aws-lc-sys`.

### What the spike found (2026-09-21)

1. **Every primitive a vox-only TLS 1.3 provider needs is already a dependency, in pure Rust:**
   `x25519-dalek`, `ml-kem`, `aes-gcm`, `sha2`, `hkdf`, `hmac`, `ed25519-dalek`, `getrandom`.
2. **vox needs exactly one signature algorithm.** The leaf is `PKCS_ED25519`
   (`identity_cert.rs:125`) and the chain is self-signed with a custom verifier. The breadth that
   makes general-purpose pure-Rust TLS hard (RSA, ECDSA P-256/384) is not needed.
3. **quinn-proto's handshake crypto already goes through rustls's provider** —
   `rustls::quic::{HeaderProtectionKey, PacketKey, Secrets, Suite}` (`crypto/rustls.rs:15`),
   `rustls::quic::{Client,Server}Connection::new` (`:368`, `:524`). Packet protection and header
   protection come from the negotiated `Tls13CipherSuite`'s `quic` field, which any provider
   populates.
4. **quinn-proto's only direct C use is the RFC 9001 Retry Integrity Tag** — AES-128-GCM under the
   spec's *published constant* key and nonce (`crypto/rustls.rs:188-198`, `:549-559`). It
   authenticates Retry packets; it protects no secret and negotiates nothing.
5. **But quinn-proto's Cargo features make the C unavoidable today**: `rustls = ["rustls-ring"]`,
   `rustls-ring = ["dep:rustls", "rustls?/ring", "ring"]`,
   `rustls-aws-lc-rs = ["dep:rustls", "rustls?/aws-lc-rs", "aws-lc-rs"]`. There is no feature
   combination yielding `dep:rustls` without `ring` or `aws-lc-rs`.
6. Four crates pull `aws-lc-rs` into the tree: `rustls` (feature), `rustls-post-quantum`
   (the X25519MLKEM768 impl), `quinn-proto` (feature), `rcgen` (leaf generation).

So the blocker is **not cryptographic**. It is one Cargo feature graph plus ten lines using a
published constant.

## Decision (proposed)

Vox SHOULD build and use its own pure-Rust `rustls::crypto::CryptoProvider`, scoped to exactly what
vox negotiates, and SHOULD remove `aws-lc-rs` from the dependency tree.

1. **`X25519MLKEM768` as our own `SupportedKxGroup`/`ActiveKeyExchange`**, from `x25519-dalek` +
   `ml-kem`. The share is the ML-KEM-768 encapsulation key concatenated with the X25519 public key;
   the shared secret is the ML-KEM shared secret concatenated with the X25519 shared secret, in the
   order the draft fixes. It MUST be tested against `rustls-post-quantum`'s existing implementation
   as a known-answer oracle before the latter is removed.
2. **TLS 1.3 cipher suites** from `aes-gcm` (+ `chacha20poly1305` if kept), with the `quic` field
   populated so quinn keeps working.
3. **Ed25519-only signature verification** via `ed25519-dalek`. Anything else MUST be rejected, not
   merely unsupported — a narrower surface than today.
4. **Replace `rcgen`** by emitting the self-signed leaf DER directly. vox already hand-builds the
   custom extension and its CBOR body, so this is adjacent work, not new competence.
5. **quinn-proto**: upstream a feature that takes `dep:rustls` without `ring`/`aws-lc-rs` and sources
   the Retry tag from the provider (or from `aes-gcm`). A vendored patch is the fallback if upstream
   is slow. This is the only change outside our own code.

### What MUST NOT be claimed

"Pure Rust" is **not** "no `unsafe`". `aes` reaches AES-NI through `unsafe` intrinsics internally;
`x25519-dalek` and others use `unsafe` in places. This change reduces **C/assembly** and shrinks what
an unauthenticated remote party reaches in a foreign-language codebase. It does not make the
transport memory-safe end to end, and ADR-011 MUST NOT say otherwise.

## The argument against, stated fairly

This is the part a reviewer should attack hardest.

- **We would be replacing FIPS-validated, widely-reviewed code with code reviewed by us.** AWS-LC is
  audited and deployed at scale. A provider we assemble is not. Nonce construction, the TLS 1.3 key
  schedule, and constant-time comparison are exactly where hand-wiring goes wrong, and a mistake here
  is a full break of the transport — not a degradation.
- **Memory safety is not the only failure mode.** Trading C for Rust removes a class of bug and adds
  a class of *our own* bugs, in code with far fewer eyes.
- **Side channels.** AWS-LC's assembly is tuned for constant time and reviewed for it. RustCrypto is
  generally constant-time but not equivalently scrutinised for this use.
- **`ring` is the cheap partial win**: also C, but far smaller than AWS-LC and without the FIPS build
  machinery. It reduces the C surface for one line of Cargo config and no new crypto code.
- **Doing nothing is defensible.** The C is confined to the transport handshake; no application key,
  message key or log authenticator touches it.

## Consequences

### Positive
- The Rust-maximal principle stops having an exception justified by a false premise.
- The pre-auth, internet-reachable attack surface contains less foreign-language code.
- `aws-lc-sys` and its build machinery (cmake, nasm, prebuilt objects) leave the supply chain,
  which also simplifies cross-compilation for the three release targets.
- The provider offers exactly one group and one signature algorithm, so there is less to get wrong
  than a general-purpose provider.

### Negative
- We own TLS-adjacent crypto glue we did not own before, in the highest-consequence code in the
  project, and it will not have AWS-LC's review history.
- An upstream dependency (quinn) must change, or be vendored — a maintenance cost that recurs.
- Removing `rcgen` means owning X.509 DER emission, a format with a long history of parser bugs
  (we would be emitting, not parsing, which is the safer half).

### Neutral
- Performance is expected to be comparable (`aes` uses AES-NI; ChaCha20 is fast in Rust), but this
  MUST be measured, not assumed.

## Implementation plan (proposed — not started)

Each step is one branch with the six gates, and **each MUST be provable before the next begins**.

- **M19.1 — the group.** Implement X25519MLKEM768 and prove it against `rustls-post-quantum` as a
  known-answer oracle: same shares in, same secret out, across many random runs. Gate: a real vox
  handshake completes with our group and the aws-lc-rs provider still supplying everything else.
- **M19.2 — the suites and the provider.** Assemble the provider; keep `aws-lc-rs` present but
  unused. Gate: a real loopback QUIC handshake between two vox nodes, then the existing M14/M15/M17
  gates, unchanged and green.
- **M19.3 — the leaf.** Emit the DER ourselves; drop `rcgen`. Gate: the existing identity-cert tests,
  plus a byte-comparison against an `rcgen`-produced leaf for the same key.
- **M19.4 — quinn.** Upstream or vendor the feature. Gate: `cargo tree` shows no `aws-lc-sys` and no
  `ring`, and every gate above is still green.
- **M19.5 — the claim.** Amend ADR-011 and ADR-001 #10, delete the exception, and state precisely
  what "pure Rust" does and does not mean.

**Abort condition.** If M19.1 cannot be proved equivalent to a known-good implementation, this ADR is
abandoned and `aws-lc-rs` stays, with ADR-011's justification corrected to the true reason
(*"we chose not to own this crypto"*) rather than the false one (*"it does not exist"*).

## Links
**Depends on**: ADR-001 (#10 Rust-maximal), ADR-003 (suite policy), ADR-011 (transport substrate).
**Supersedes**: the single Rust-maximal exception recorded in ADR-011 and `transport/provider.rs`,
if and only if M19.4 completes.
