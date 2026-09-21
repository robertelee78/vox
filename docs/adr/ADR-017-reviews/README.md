# ADR-017 third revision — independent review round, 2026-09-21

The first draft of ADR-017's third revision (consent-bound services) was reviewed by three models
**before any code was written**, under the house rule that a plan is reviewed by someone other than
its author. `prompt.txt` is what each was given, verbatim; each read the revised ADRs, the code they
govern, and Tor's `/opt/tor` hidden-service implementation.

| Reviewer | Verdict |
|---|---|
| gpt-6-astra (`codex exec`) | **REVISE** — 6 issues in priority order |
| glm-5.3 (`opencode run`) | **REVISE** — 7 issues in priority order |
| kimi-k3 (`opencode run`) | **REVISE** — 9 issues in priority order |

All three agreed the **core direction is sound** and verified it against the tree. All three found
defects that would otherwise have shipped. The two that mattered most were found independently by
more than one reviewer:

1. **Joining a room auto-consented to the responder** (`node/actor.rs:1764` → `:1835`, responder
   chosen at `:1603`), so the proposed `readers_of(host)` gate would have granted reach to a party no
   human approved — reintroducing the hole the revision exists to close. Found by two.
2. **The `bind:` capability was orphaned** (`governance/channel.rs:1232`), so `vox serve` would have
   worked only for a room's creator. Found by all three.

Also found: the name needed no keypair (two reviewers proposed the same host-committed label); a
governance frame would have leaked the descriptor's existence; `chain_id` alone is an insufficient
publication trigger; the genesis field cannot simply be deleted without changing existing channelIDs;
a pending-request race survives connection teardown; `vox up` cannot resolve cross-room names; and
**three claims about the tree were stated in the past tense before being true.**

Two claims were corrected *in the author's favour being refused*: `vox grant` could not reach a
non-member, and verified finding #5 does not follow from the evaluator as asserted.

Every item above is addressed in the ADR, in place, with the reasoning kept rather than quietly
dropped. kimi's first run died mid-file-read and produced no verdict; the transcript here is its
rerun.
