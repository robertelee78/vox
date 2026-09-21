
**No. This analysis does not justify enabling deniability mode.** C4 fails for the proposed messenger composition, C1 is false under the standard key-indistinguishability definition, and several claimed protocol checks depend on an unenforced caller contract.

I reviewed all nine named implementation files and followed their dependencies into the log and sender-key layers. ADR-009 itself remains **implemented but not enabled for shipping**, updated September 21. [ADR-009-deniability-mode.md:3](/opt/vox/docs/adr/ADR-009-deniability-mode.md:3)

| Claim | Assessment |
|---|---|
| **C1 — Key secrecy** | **False as stated** for transcript-visible key indistinguishability. Key unrecoverability is a different, potentially defensible claim. |
| **C2 — Agreement** | **Conditionally plausible, overclaimed for this implementation.** The transcript checks work, but the required membership and acceptance state machine is missing. |
| **C3 — Live origin authentication** | **Sound in a narrower form:** an uncompromised, unpublished signing key authenticates new messages under a correctly registered public key. A2 alone does not establish the entire claimed lifecycle. |
| **C4 — Content repudiation** | **False as stated.** Publishing `esk` makes its signatures forgeable; it does not erase other transferable evidence. |
| **C5 — Participation non-deniability** | **Essentially correct for signed key registration**, while the static key remains uncompromised. Registration does not prove completion, and “forever” needs qualification. |

**1. C4 misses two concrete sources of surviving authorship evidence.**

**The root-signed log commits to deniable content.** Every entry skeleton includes `prev_hash`, `lipmaa_backlink`, and `payload_hash`. Those fields are covered by the signing input, and the entry hash commits to that skeleton. Root-signed governance entries therefore authenticate their preceding content ancestry. [log/entry.rs:224](/opt/vox/crates/vox-core/src/log/entry.rs:224), [log/entry.rs:428](/opt/vox/crates/vox-core/src/log/entry.rs:428)

A concrete trace is:

1. Alice emits deniable content entry `M`.
2. Alice emits root-signed governance entry `G`, with `G.prev_hash = hash(M)`.
3. Alice publishes the ephemeral signing key.
4. A recipient presents `M`, `G`, and Alice’s static public key.

Changing `M` changes its hash. The published ephemeral key cannot produce Alice’s root signature on a replacement `G`. The recipient retains a static-key commitment to the exact content entry under Alice’s identity. A longer intervening chain changes nothing.

This is ordinary supported log behavior: feeds enforce these backlinks, and the publication is itself intended to be a root-signed entry in the publisher’s feed. **The publication intended to provide repudiation can itself anchor the preceding content.** [log/feed.rs:228](/opt/vox/crates/vox-core/src/log/feed.rs:228), [esk_publication.rs:23](/opt/vox/crates/vox-core/src/deniable/esk_publication.rs:23)

For encrypted content, a recipient can supply its decryption material alongside the evidence. Confidentiality from outsiders does not establish repudiation against recipients.

**The sender-key layer retains a separate content signature.** `SenderChain` generates its own signing key. `GroupMessage::seal` signs the header and ciphertext with that key; the root-signed SKDM certifies its public key. Publishing the DGKA `esk` does not publish this independently generated sender signing key. Wrapping that payload in a forgeable outer signature leaves the inner signature intact. [group/state.rs:84](/opt/vox/crates/vox-core/src/group/state.rs:84), [group/message.rs:138](/opt/vox/crates/vox-core/src/group/message.rs:138), [group/skdm.rs:198](/opt/vox/crates/vox-core/src/group/skdm.rs:198), [esk_publication.rs:73](/opt/vox/crates/vox-core/src/deniable/esk_publication.rs:73)

Consequently, the analysis’s “content … signed **only** with `esk_i`” is not established for actual messenger content. [ADR-009-security-analysis.md:56](/opt/vox/docs/adr/ADR-009-security-analysis.md:56)

The isolated key-publication mechanism is real; [mpENC §5.2.2](https://arxiv.org/pdf/1606.04598) describes it. That does not prove deniability of Vox’s additional signatures and hash-linked governance.

**2. The missing attack in §6 is preserving evidence before publication.**

A malicious recipient obtains an independently verifiable timestamp or public commitment to the signed message **while the ephemeral key remains secret**, then presents it after publication.

The judge can distinguish “this signature existed before disclosure” from “someone forged it afterward.” The judge need not participate live; the evidence can be collected earlier and evaluated offline. C4’s argument ignores this distinction. [ADR-009-security-analysis.md:95](/opt/vox/docs/adr/ADR-009-security-analysis.md:95)

Vox additionally creates its own content commitments through root-signed log ancestry, as above. This attack requires neither adaptive corruption nor withholding publication.

A defensible claim must explicitly restrict the judge’s auxiliary evidence. “No transferable proof survives” is much broader than “a standalone signature becomes forgeable.”

**3. C1 has a direct distinguisher, not merely an incomplete reduction.**

The implementation computes:

```text
K_confirm = HKDF(K, confirmation_info)
tag       = HMAC(K_confirm, T_bind)
```

Both `confirmation_info` and `T_bind` are available from the public transcript. [key.rs:74](/opt/vox/crates/vox-core/src/deniable/key.rs:74), [key.rs:89](/opt/vox/crates/vox-core/src/deniable/key.rs:89)

In the standard indistinguishability experiment, give the outsider a candidate `Q`, either the real `K` or an independent random key. It computes:

```text
HMAC(HKDF(Q, confirmation_info), T_bind) == recorded_tag
```

The real key passes; an independent random key passes only with negligible probability. No DH problem is solved. Deriving the confirmation key *from the tested key* does not prevent this.

This **does not demonstrate practical recovery of `K`**, or a break of content encryption. It disproves the particular indistinguishability claim at [analysis:75](/opt/vox/docs/adr/ADR-009-security-analysis.md:75).

The reduction sketch also has these gaps:

- Commitments are unnecessary for passive, all-honest BD secrecy. For malicious participants, commitments alone do not establish honest BD contributions or correctness of `X_i`.
- “Embed the challenge in an honest share” does not explain simulation of the correlated round values, confirmations, or adversarial scheduling.
- HKDF `info` contains the label, channel, and epoch—**not** `T`, `T_bind`, or the membership list. Calling it transcript-bound is misleading. [key.rs:105](/opt/vox/crates/vox-core/src/deniable/key.rs:105)

The [Katz–Yung treatment](https://eprint.iacr.org/2003/171.pdf) separates passive BD security from the authenticated compiler and defines freshness and partnering. This analysis has not supplied an equivalent argument for its modified construction.

**4. C2 and the adaptive-share defense assume a state machine the code does not enforce.**

The claimed barrier is “every member commits before anyone reveals.” The actual API permits:

- `reveal()` immediately after construction;
- new `recv_commit()` calls after reveals have arrived;
- receiving a reveal after checking only **that author’s** earlier commitment.

There is no frozen expected roster or global commit-phase barrier. A malicious member can wait for honest reveals and then submit its own commitment and reveal; these methods accept that ordering. [dgka.rs:187](/opt/vox/crates/vox-core/src/deniable/dgka.rs:187), [dgka.rs:202](/opt/vox/crates/vox-core/src/deniable/dgka.rs:202), [dgka.rs:237](/opt/vox/crates/vox-core/src/deniable/dgka.rs:237)

Likewise, `epoch_context()` requires equality of the *locally observed* commitment and reveal counts, not equality with the admitted membership. An exact-membership constructor exists, but this path does not use it. [dgka.rs:264](/opt/vox/crates/vox-core/src/deniable/dgka.rs:264), [epoch.rs:278](/opt/vox/crates/vox-core/src/deniable/epoch.rs:278)

`DgkaSession::new` does not require evidence that anyone’s confirmation was checked. An external driver must enforce that. [dgka.rs:438](/opt/vox/crates/vox-core/src/deniable/dgka.rs:438)

The cryptographic checks in `verify_confirm` are useful: they check the recorded `X`, signature, and MAC. With a fixed membership, matching session, and all required confirmations, I see no reason to reject their intended agreement property. But those preconditions are load-bearing and absent from the implemented acceptance mechanism. [dgka.rs:364](/opt/vox/crates/vox-core/src/deniable/dgka.rs:364)

**A5 is also not supplied by ADR-008 as asserted.** ADR-008 promises causal ordering and eventual convergence, explicitly permits partition-time equivocation, and detects it afterward. That is not a guarantee of a common, complete round view before DGKA acceptance. Total ordering is not necessarily required; an agreed roster and safe round-completion rule are. [analysis:68](/opt/vox/docs/adr/ADR-009-security-analysis.md:68), [ADR-008:20](/opt/vox/docs/adr/ADR-008-replicated-authenticated-log-and-sync.md:20), [ADR-008:190](/opt/vox/docs/adr/ADR-008-replicated-authenticated-log-and-sync.md:190)

**5. Additional document/code mismatches are material.**

- **The transcript does not directly bind member identities.** It hashes channel, epoch, ordered ephemeral keys, and shares. Static public keys and author IDs determine ordering but are not hashed. Different identities reusing the same contributions in the same positions need not change `T`. Thus C2’s “any disagreement about the member set” and C3’s “full member set” are unsupported as written. This is a false proof step, not by itself proof of honest-user impersonation. [epoch.rs:369](/opt/vox/crates/vox-core/src/deniable/epoch.rs:369)

- **The codec does not provide the complete four-round exchange.** `X_i` first appears inside `Confirm`, but producing `Confirm` already requires every peer’s `X_i`. There is no standalone round-value message. The tests bypass this dependency by gathering `own_round2()` directly in memory before serializing confirmations. `ReKey` is the fourth enum variant, not the missing initial-setup broadcast. [wire.rs:54](/opt/vox/crates/vox-core/src/deniable/wire.rs:54), [dgka.rs:313](/opt/vox/crates/vox-core/src/deniable/dgka.rs:313), [tests.rs:119](/opt/vox/crates/vox-core/src/deniable/tests.rs:119)

- **The two-member exception is described incorrectly.** Only the DH combiner ignores `X`. `bind_transcript` still hashes both values, and `verify_confirm` still checks them. Split-view detection is therefore not “vacuous” as §7 claims. This **underclaims** the implemented binding. [share.rs:156](/opt/vox/crates/vox-core/src/deniable/share.rs:156), [dgka.rs:377](/opt/vox/crates/vox-core/src/deniable/dgka.rs:377), [dgka.rs:403](/opt/vox/crates/vox-core/src/deniable/dgka.rs:403)

- **Mid-epoch re-key cannot update the existing verifier.** Re-key produces fresh ephemeral keys, but `EpochVerifier::release` rejects a different key for the same `(channel, epoch, author)`. There is no re-key generation selector. The new test uses `EPOCH + 1` and never installs the returned keys into an existing verifier, so it does not exercise the advertised mid-epoch transition. [verifier.rs:91](/opt/vox/crates/vox-core/src/deniable/verifier.rs:91), [tests.rs:429](/opt/vox/crates/vox-core/src/deniable/tests.rs:429), [tests.rs:458](/opt/vox/crates/vox-core/src/deniable/tests.rs:458)

- **`verify_rekey` does not check the transmitted `share` against the context’s share.** It checks the ephemeral public key, round value, signature, and MAC; the received share field is unused. [rekey.rs:180](/opt/vox/crates/vox-core/src/deniable/rekey.rs:180)

- **The production content path remains attributable.** `append_text` encrypts/signs through `SenderChain`, then root-signs the outer log entry. Enabling a policy flag would not implement the analyzed deniable path. [node/channel.rs:2123](/opt/vox/crates/vox-core/src/node/channel.rs:2123)

**6. A1–A6 are insufficient.**

Beyond the failed claims above, the analysis needs explicit assumptions about:

- **The adversary and freshness:** passive versus active outsiders; no corrupted target-group member leaking `K`; no session-key exposure; precise treatment of malicious insiders. Static corruption alone does not establish these.
- **The cryptographic model:** “Gap-DH / DDH” is not a precise interchangeable assumption. PQ authentication needs quantum-resistant unforgeability; the classical ROM sketches do not themselves establish a quantum theorem.
- **The driver:** fixed authenticated membership, round barriers, unique session/re-key identifiers, full confirmation checking, and authenticated verifier registration.
- **Key lifecycle:** fresh independent randomness, no cross-epoch key reuse, protection until disclosure, and authoritative closure handling—including lagging recipients.
- **The judge’s evidence:** whether timestamps, signed log anchors, recipient-held decryption material, and other signature layers are allowed.

C3’s core signature reasoning is sound under these narrower conditions. Composite verification requires both signature components, and content verification uses the exact channel/epoch/author lookup. However, registration itself accepts caller-supplied `MemberEpk`; it does not verify a setup certificate or completed DSKE. [identity/composite.rs:127](/opt/vox/crates/vox-core/src/identity/composite.rs:127), [verifier.rs:91](/opt/vox/crates/vox-core/src/deniable/verifier.rs:91), [verifier.rs:137](/opt/vox/crates/vox-core/src/deniable/verifier.rs:137)

C5 correctly observes that publishing `esk` does not weaken the static reveal signature. It proves authorization of that registration, not necessarily successful session completion, and remains conditional on static-key security. [dgka.rs:232](/opt/vox/crates/vox-core/src/deniable/dgka.rs:232)

**Section 7 is candid, but not complete enough to support release.**

The publication-liveness warning, unreviewed status, re-key authentication gap, caller-supplied closure state, and missing vectors are legitimate disclosures. The classical confirmation key also does **not**, by itself, demonstrate a break of separately encrypted PQ content.

But “composability not covered” conceals concrete incompatibilities essential to the promised product property: root-signed content ancestry and an unpublished inner signing key. It also omits the incomplete wire exchange, unenforced setup phases, and unusable mid-epoch verifier transition. Those are not merely future proof obligations.

This was a source review; I did not modify files or execute tests.

## VERDICT

**BLOCK — do not enable.**

The analysis proves, at most, forgeability of isolated ephemeral signatures after disclosure. It does not prove content repudiation for the messenger, and the surrounding code preserves evidence that defeats that claim.

Redesign the content/log signature composition, complete and enforce the setup and re-key lifecycle, and replace the sketches with precise claims and adversarial security arguments before enabling the mode.
hook: Stop
hook: Stop
hook: Stop
hook: Stop Completed
hook: Stop Completed
hook: Stop Completed
tokens used
146,050
**No. This analysis does not justify enabling deniability mode.** C4 fails for the proposed messenger composition, C1 is false under the standard key-indistinguishability definition, and several claimed protocol checks depend on an unenforced caller contract.

I reviewed all nine named implementation files and followed their dependencies into the log and sender-key layers. ADR-009 itself remains **implemented but not enabled for shipping**, updated September 21. [ADR-009-deniability-mode.md:3](/opt/vox/docs/adr/ADR-009-deniability-mode.md:3)

| Claim | Assessment |
|---|---|
| **C1 — Key secrecy** | **False as stated** for transcript-visible key indistinguishability. Key unrecoverability is a different, potentially defensible claim. |
| **C2 — Agreement** | **Conditionally plausible, overclaimed for this implementation.** The transcript checks work, but the required membership and acceptance state machine is missing. |
| **C3 — Live origin authentication** | **Sound in a narrower form:** an uncompromised, unpublished signing key authenticates new messages under a correctly registered public key. A2 alone does not establish the entire claimed lifecycle. |
| **C4 — Content repudiation** | **False as stated.** Publishing `esk` makes its signatures forgeable; it does not erase other transferable evidence. |
| **C5 — Participation non-deniability** | **Essentially correct for signed key registration**, while the static key remains uncompromised. Registration does not prove completion, and “forever” needs qualification. |

**1. C4 misses two concrete sources of surviving authorship evidence.**

**The root-signed log commits to deniable content.** Every entry skeleton includes `prev_hash`, `lipmaa_backlink`, and `payload_hash`. Those fields are covered by the signing input, and the entry hash commits to that skeleton. Root-signed governance entries therefore authenticate their preceding content ancestry. [log/entry.rs:224](/opt/vox/crates/vox-core/src/log/entry.rs:224), [log/entry.rs:428](/opt/vox/crates/vox-core/src/log/entry.rs:428)

A concrete trace is:

1. Alice emits deniable content entry `M`.
2. Alice emits root-signed governance entry `G`, with `G.prev_hash = hash(M)`.
3. Alice publishes the ephemeral signing key.
4. A recipient presents `M`, `G`, and Alice’s static public key.

Changing `M` changes its hash. The published ephemeral key cannot produce Alice’s root signature on a replacement `G`. The recipient retains a static-key commitment to the exact content entry under Alice’s identity. A longer intervening chain changes nothing.

This is ordinary supported log behavior: feeds enforce these backlinks, and the publication is itself intended to be a root-signed entry in the publisher’s feed. **The publication intended to provide repudiation can itself anchor the preceding content.** [log/feed.rs:228](/opt/vox/crates/vox-core/src/log/feed.rs:228), [esk_publication.rs:23](/opt/vox/crates/vox-core/src/deniable/esk_publication.rs:23)

For encrypted content, a recipient can supply its decryption material alongside the evidence. Confidentiality from outsiders does not establish repudiation against recipients.

**The sender-key layer retains a separate content signature.** `SenderChain` generates its own signing key. `GroupMessage::seal` signs the header and ciphertext with that key; the root-signed SKDM certifies its public key. Publishing the DGKA `esk` does not publish this independently generated sender signing key. Wrapping that payload in a forgeable outer signature leaves the inner signature intact. [group/state.rs:84](/opt/vox/crates/vox-core/src/group/state.rs:84), [group/message.rs:138](/opt/vox/crates/vox-core/src/group/message.rs:138), [group/skdm.rs:198](/opt/vox/crates/vox-core/src/group/skdm.rs:198), [esk_publication.rs:73](/opt/vox/crates/vox-core/src/deniable/esk_publication.rs:73)

Consequently, the analysis’s “content … signed **only** with `esk_i`” is not established for actual messenger content. [ADR-009-security-analysis.md:56](/opt/vox/docs/adr/ADR-009-security-analysis.md:56)

The isolated key-publication mechanism is real; [mpENC §5.2.2](https://arxiv.org/pdf/1606.04598) describes it. That does not prove deniability of Vox’s additional signatures and hash-linked governance.

**2. The missing attack in §6 is preserving evidence before publication.**

A malicious recipient obtains an independently verifiable timestamp or public commitment to the signed message **while the ephemeral key remains secret**, then presents it after publication.

The judge can distinguish “this signature existed before disclosure” from “someone forged it afterward.” The judge need not participate live; the evidence can be collected earlier and evaluated offline. C4’s argument ignores this distinction. [ADR-009-security-analysis.md:95](/opt/vox/docs/adr/ADR-009-security-analysis.md:95)

Vox additionally creates its own content commitments through root-signed log ancestry, as above. This attack requires neither adaptive corruption nor withholding publication.

A defensible claim must explicitly restrict the judge’s auxiliary evidence. “No transferable proof survives” is much broader than “a standalone signature becomes forgeable.”

**3. C1 has a direct distinguisher, not merely an incomplete reduction.**

The implementation computes:

```text
K_confirm = HKDF(K, confirmation_info)
tag       = HMAC(K_confirm, T_bind)
```

Both `confirmation_info` and `T_bind` are available from the public transcript. [key.rs:74](/opt/vox/crates/vox-core/src/deniable/key.rs:74), [key.rs:89](/opt/vox/crates/vox-core/src/deniable/key.rs:89)

In the standard indistinguishability experiment, give the outsider a candidate `Q`, either the real `K` or an independent random key. It computes:

```text
HMAC(HKDF(Q, confirmation_info), T_bind) == recorded_tag
```

The real key passes; an independent random key passes only with negligible probability. No DH problem is solved. Deriving the confirmation key *from the tested key* does not prevent this.

This **does not demonstrate practical recovery of `K`**, or a break of content encryption. It disproves the particular indistinguishability claim at [analysis:75](/opt/vox/docs/adr/ADR-009-security-analysis.md:75).

The reduction sketch also has these gaps:

- Commitments are unnecessary for passive, all-honest BD secrecy. For malicious participants, commitments alone do not establish honest BD contributions or correctness of `X_i`.
- “Embed the challenge in an honest share” does not explain simulation of the correlated round values, confirmations, or adversarial scheduling.
- HKDF `info` contains the label, channel, and epoch—**not** `T`, `T_bind`, or the membership list. Calling it transcript-bound is misleading. [key.rs:105](/opt/vox/crates/vox-core/src/deniable/key.rs:105)

The [Katz–Yung treatment](https://eprint.iacr.org/2003/171.pdf) separates passive BD security from the authenticated compiler and defines freshness and partnering. This analysis has not supplied an equivalent argument for its modified construction.

**4. C2 and the adaptive-share defense assume a state machine the code does not enforce.**

The claimed barrier is “every member commits before anyone reveals.” The actual API permits:

- `reveal()` immediately after construction;
- new `recv_commit()` calls after reveals have arrived;
- receiving a reveal after checking only **that author’s** earlier commitment.

There is no frozen expected roster or global commit-phase barrier. A malicious member can wait for honest reveals and then submit its own commitment and reveal; these methods accept that ordering. [dgka.rs:187](/opt/vox/crates/vox-core/src/deniable/dgka.rs:187), [dgka.rs:202](/opt/vox/crates/vox-core/src/deniable/dgka.rs:202), [dgka.rs:237](/opt/vox/crates/vox-core/src/deniable/dgka.rs:237)

Likewise, `epoch_context()` requires equality of the *locally observed* commitment and reveal counts, not equality with the admitted membership. An exact-membership constructor exists, but this path does not use it. [dgka.rs:264](/opt/vox/crates/vox-core/src/deniable/dgka.rs:264), [epoch.rs:278](/opt/vox/crates/vox-core/src/deniable/epoch.rs:278)

`DgkaSession::new` does not require evidence that anyone’s confirmation was checked. An external driver must enforce that. [dgka.rs:438](/opt/vox/crates/vox-core/src/deniable/dgka.rs:438)

The cryptographic checks in `verify_confirm` are useful: they check the recorded `X`, signature, and MAC. With a fixed membership, matching session, and all required confirmations, I see no reason to reject their intended agreement property. But those preconditions are load-bearing and absent from the implemented acceptance mechanism. [dgka.rs:364](/opt/vox/crates/vox-core/src/deniable/dgka.rs:364)

**A5 is also not supplied by ADR-008 as asserted.** ADR-008 promises causal ordering and eventual convergence, explicitly permits partition-time equivocation, and detects it afterward. That is not a guarantee of a common, complete round view before DGKA acceptance. Total ordering is not necessarily required; an agreed roster and safe round-completion rule are. [analysis:68](/opt/vox/docs/adr/ADR-009-security-analysis.md:68), [ADR-008:20](/opt/vox/docs/adr/ADR-008-replicated-authenticated-log-and-sync.md:20), [ADR-008:190](/opt/vox/docs/adr/ADR-008-replicated-authenticated-log-and-sync.md:190)

**5. Additional document/code mismatches are material.**

- **The transcript does not directly bind member identities.** It hashes channel, epoch, ordered ephemeral keys, and shares. Static public keys and author IDs determine ordering but are not hashed. Different identities reusing the same contributions in the same positions need not change `T`. Thus C2’s “any disagreement about the member set” and C3’s “full member set” are unsupported as written. This is a false proof step, not by itself proof of honest-user impersonation. [epoch.rs:369](/opt/vox/crates/vox-core/src/deniable/epoch.rs:369)

- **The codec does not provide the complete four-round exchange.** `X_i` first appears inside `Confirm`, but producing `Confirm` already requires every peer’s `X_i`. There is no standalone round-value message. The tests bypass this dependency by gathering `own_round2()` directly in memory before serializing confirmations. `ReKey` is the fourth enum variant, not the missing initial-setup broadcast. [wire.rs:54](/opt/vox/crates/vox-core/src/deniable/wire.rs:54), [dgka.rs:313](/opt/vox/crates/vox-core/src/deniable/dgka.rs:313), [tests.rs:119](/opt/vox/crates/vox-core/src/deniable/tests.rs:119)

- **The two-member exception is described incorrectly.** Only the DH combiner ignores `X`. `bind_transcript` still hashes both values, and `verify_confirm` still checks them. Split-view detection is therefore not “vacuous” as §7 claims. This **underclaims** the implemented binding. [share.rs:156](/opt/vox/crates/vox-core/src/deniable/share.rs:156), [dgka.rs:377](/opt/vox/crates/vox-core/src/deniable/dgka.rs:377), [dgka.rs:403](/opt/vox/crates/vox-core/src/deniable/dgka.rs:403)

- **Mid-epoch re-key cannot update the existing verifier.** Re-key produces fresh ephemeral keys, but `EpochVerifier::release` rejects a different key for the same `(channel, epoch, author)`. There is no re-key generation selector. The new test uses `EPOCH + 1` and never installs the returned keys into an existing verifier, so it does not exercise the advertised mid-epoch transition. [verifier.rs:91](/opt/vox/crates/vox-core/src/deniable/verifier.rs:91), [tests.rs:429](/opt/vox/crates/vox-core/src/deniable/tests.rs:429), [tests.rs:458](/opt/vox/crates/vox-core/src/deniable/tests.rs:458)

- **`verify_rekey` does not check the transmitted `share` against the context’s share.** It checks the ephemeral public key, round value, signature, and MAC; the received share field is unused. [rekey.rs:180](/opt/vox/crates/vox-core/src/deniable/rekey.rs:180)

- **The production content path remains attributable.** `append_text` encrypts/signs through `SenderChain`, then root-signs the outer log entry. Enabling a policy flag would not implement the analyzed deniable path. [node/channel.rs:2123](/opt/vox/crates/vox-core/src/node/channel.rs:2123)

**6. A1–A6 are insufficient.**

Beyond the failed claims above, the analysis needs explicit assumptions about:

- **The adversary and freshness:** passive versus active outsiders; no corrupted target-group member leaking `K`; no session-key exposure; precise treatment of malicious insiders. Static corruption alone does not establish these.
- **The cryptographic model:** “Gap-DH / DDH” is not a precise interchangeable assumption. PQ authentication needs quantum-resistant unforgeability; the classical ROM sketches do not themselves establish a quantum theorem.
- **The driver:** fixed authenticated membership, round barriers, unique session/re-key identifiers, full confirmation checking, and authenticated verifier registration.
- **Key lifecycle:** fresh independent randomness, no cross-epoch key reuse, protection until disclosure, and authoritative closure handling—including lagging recipients.
- **The judge’s evidence:** whether timestamps, signed log anchors, recipient-held decryption material, and other signature layers are allowed.

C3’s core signature reasoning is sound under these narrower conditions. Composite verification requires both signature components, and content verification uses the exact channel/epoch/author lookup. However, registration itself accepts caller-supplied `MemberEpk`; it does not verify a setup certificate or completed DSKE. [identity/composite.rs:127](/opt/vox/crates/vox-core/src/identity/composite.rs:127), [verifier.rs:91](/opt/vox/crates/vox-core/src/deniable/verifier.rs:91), [verifier.rs:137](/opt/vox/crates/vox-core/src/deniable/verifier.rs:137)

C5 correctly observes that publishing `esk` does not weaken the static reveal signature. It proves authorization of that registration, not necessarily successful session completion, and remains conditional on static-key security. [dgka.rs:232](/opt/vox/crates/vox-core/src/deniable/dgka.rs:232)

**Section 7 is candid, but not complete enough to support release.**

The publication-liveness warning, unreviewed status, re-key authentication gap, caller-supplied closure state, and missing vectors are legitimate disclosures. The classical confirmation key also does **not**, by itself, demonstrate a break of separately encrypted PQ content.

But “composability not covered” conceals concrete incompatibilities essential to the promised product property: root-signed content ancestry and an unpublished inner signing key. It also omits the incomplete wire exchange, unenforced setup phases, and unusable mid-epoch verifier transition. Those are not merely future proof obligations.

This was a source review; I did not modify files or execute tests.

## VERDICT

**BLOCK — do not enable.**

The analysis proves, at most, forgeability of isolated ephemeral signatures after disclosure. It does not prove content repudiation for the messenger, and the surrounding code preserves evidence that defeats that claim.

Redesign the content/log signature composition, complete and enforce the setup and re-key lifecycle, and replace the sketches with precise claims and adversarial security arguments before enabling the mode.
