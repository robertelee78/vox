# ADR-051: The Linux Build Runs Where It Installs

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

- **Status**: Accepted (2026-11-13), revision 5, for v0.4.31, under the decider's authorization
  of 2026-11-13 ("post review can accept them too"), after the fifth independent review by
  GPT-6.1-Sol passed it (`adr-051-sol-review-5.md`); proposed 2026-11-13. Revision 2 answered the first
  independent review by GPT-6.1-Sol (`adr-051-sol-review-1.md`, five P1 and six P2);
  revision 3 answers the second (`adr-051-sol-review-2.md`, three P1 and five P2, "needs
  revision"; the floor "remains sound", the build method "still boring and standard") and takes
  its three cuts; revision 4 answers the third (`adr-051-sol-review-3.md`, one P1: the
  update journey's fixture version) and passed the fourth re-check
  (`adr-051-sol-review-4.md`); revision 5 answers the nine defects the task cut found
  (`v0431-tasks-ADR-051.md`) and changes nothing else. The Review record names each
  finding and the text that answers it.
  Requirements changed in revision 5 are marked **(r5)**, in revision 4 **(r4)**, in revision 3 **(r3)**, in revision 2 **(r2)**. Nothing here
  is built: each requirement is to land in v0.4.31 with its proof, and implementation,
  acceptance and delivery are recorded on the source-bound issues, separately from decision
  status. The former Q1 (the floor) is answered and recorded under "The decider's answers"; no
  question is open.
- **Date**: 2026-11-13
- **Deciders**: Robert E. Lee
- **Tags**: linux, glibc, installer, updater, rollback, release, build
- **Related**: ADR-014, ADR-015, ADR-018; in this release ADR-041, ADR-044, ADR-045
- **Source**: fix-list item 91 (the item's evidence folder under `/opt/vox-evidence/v0431/`,
  its `README.md`; cited below as "the evidence folder"); the published v0.4.30 Linux asset,
  read on this Mac (`vox-x86_64-unknown-linux-gnu`, SHA-256
  `b0435b2b4e128de87d790f1a7318b39b8b20272b11cbf6fe4315de2e1afd86d6`, equal to the published
  `.sha256` and to `stable-x86_64-unknown-linux-gnu.json`), its ELF version tables recorded in
  the evidence folder as `elf-version-needs.txt`, produced by `elf-version-needs.py` beside it
  (standard-library Python, read-only, nothing executed from the asset); code read at tag
  v0.4.30 (commit 8d71ab337). Nothing was run: no `vox`, no installer, no build, no container,
  no VM. Every statement about a v0.4.30 file cites its line at the tag; a statement not read
  is marked INFERRED.

## What this ADR sets out to do, and the rulings it carries

**The goal.** A person on a Linux machine that Vox says it supports runs the one-line installer
and gets a `vox` that runs. A person on a machine Vox does not support is told so, in plain
words, and where the machine can be recognised before anything is downloaded. Neither the
installer, nor `vox update`, nor `vox update --rollback` ever leaves a `vox` on disk that
cannot run, and none of them ever replaces a working `vox` with one that cannot.

**The decider's rulings this ADR carries:**

1. 2026-11-13, ledger row 73: the Linux build's floor and the installer's two faults (it hides
   the loader's error; it replaces before it checks) are fixed inside v0.4.31; no separate
   corrective release. (LB-1 to LB-5; Implementation order)
2. 2026-11-13, ledger row 77 (within the decider's answers): the floor is **Ubuntu 20.04,
   Debian 10, RHEL 8 and newer** (glibc 2.28); he was told it in plain words when the defect was
   reported and raised no objection, then ruled the fix into v0.4.31; it can change at task
   review. (LB-1; "The decider's answers")
3. 2026-11-13, ledger row 69 (ADR-045 FG-4): the proof apparatus MAY act as root inside a
   disposable Linux test VM or container only; never `sudo` on the host or on any machine he
   owns. (LB-6)
4. 2026-11-13, ledger row 32: the whole release gate runs inside the VMs. (LB-6)
5. AGENTS.md "Releases": every known defect is fixed in the current release; there is no
   prior-release compatibility requirement. (LB-5; Alternatives)
6. AGENTS.md "Tests": a test exists only to prove a feature works for a user; a gate that grows
   CI without proving a user outcome is invalid; every red names PRODUCT or APPARATUS; every
   proof has a mutant; extend before adding; no knob in the shipped binary. (LB-2's
   precondition is not a proof; LB-6)
7. 2026-10-12, AGENTS.md "Releases": "don't over engineer things". (Revision 3's cuts: no new
   release asset, no stand-in mode, no one-purpose script, no hand-written watchdog.)

## The design in one paragraph

The Linux release asset is built inside a pinned container whose C library is glibc 2.28
(`quay.io/pypa/manylinux_2_28_x86_64`, AlmaLinux 8), with the same `cargo build --release --bin
vox` and `strip` the release job runs today, so every symbol the binary asks for is one that
glibc 2.28 and everything newer has (LB-2). The floor is stated once, in words, in the manual,
the README and the installer (LB-1). Producing the asset includes one precondition, measured
once per build inside that image and recorded in the build log: the asset's highest `GLIBC_`
version need is at or below the floor, or no asset is produced; the user-facing proof that the
asset runs on the floor is the install journey on the floor image (LB-2, LB-6 (a)). The
installer runs the downloaded candidate from its partial name, under coreutils `timeout`,
**before** it touches `vox` or `.vox-previous`; a candidate that does not run is deleted, the
person is shown the loader's own words and one plain sentence naming what is known of the cause
and the supported systems, and the installer exits non-zero with the previous `vox` untouched
(LB-3, LB-4). Where the installer can read the system's glibc version it says so before
downloading; the run is the check that decides (LB-4). `vox update` already refuses a
downloaded candidate that does not run before it publishes and is to say why in the same words;
`vox update --rollback` is to run the retained previous before its first rename, which it does
not do today (LB-5). Every proof drives the shipped `install.sh`, the shipped `vox` and the
release asset as x86_64 in the fleet's Linux VM, as arms of ADR-045's J11 and J7 and of the two
in-tree install and update journeys; the v0.4.30 asset on an Ubuntu 22.04 image is the red
baseline (LB-6).

## Context

### What the person saw (item 91)

On 2026-11-13 the operator ran the published installer on a machine running Pop!_OS 22.04
(glibc 2.35), x86_64 (the evidence folder's `README.md:3-6`):

```
$ curl -fsSL https://voxlucis.us/install.sh | sh
vox 0.4.30 for x86_64-unknown-linux-gnu
vox install: the installed binary did not run
```

Read on that machine before anything was changed (the evidence folder's `README.md:8-15`):

- `~/.local/bin/vox --version` exits 1 and prints
  ```
  /home/user/.local/bin/vox: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found (required by /home/user/.local/bin/vox)
  /home/user/.local/bin/vox: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.39' not found (required by /home/user/.local/bin/vox)
  ```
- The file is the published asset: SHA-256 `b0435b2b…86d6`, equal to the release's
  `vox-x86_64-unknown-linux-gnu.sha256`.
- `~/.local/bin` held `vox`, `.vox-previous` (same size, same minute: a second installer run) and
  `.vox-standalone.json`. **A dead binary was installed, and the second run copied it over the
  retained previous as well.**

The only change made on that machine was `rm ~/.local/bin/vox`, on the operator's word
(the evidence folder's `README.md:21`). That machine now holds a dead `.vox-previous` beside no
`vox`; the operator said he would fix it himself (ledger row 73), and C6 below is the hazard it
illustrates for every machine in that state.

### Causes at v0.4.30

Status: KNOWN = read from the tag, the asset or the evidence folder; INFERRED = fits the
evidence, not reproduced.

**C1. The release build has no floor (KNOWN).** `.github/workflows/release.yml:78-102` is the job
`build-linux-x64`: `runs-on: ubuntu-latest` (`:80`), `cargo build --release --bin vox` then
`strip` (`:86-92`), `scripts/package-release.sh target/release/vox x86_64-unknown-linux-gnu`
(`:94-97`). Nothing in the job, in `scripts/package-release.sh` or in `scripts/check-release-assets.sh`
names a C library version. The binary therefore asks for whatever the runner's glibc offered at
link time. GitHub's `ubuntu-latest` was Ubuntu 24.04 (glibc 2.39) when v0.4.30 was built, and the
label is moving to Ubuntu 26.04 between 2026-10-19 and 2026-11-19 (GitHub changelog, 2026-09-17):
the floor moves whenever GitHub moves the label, and nobody decides it. No document states which
Linux systems Vox supports: `README.md:49-50` says only `Targets: x86_64-unknown-linux-gnu`;
`docs/manual/install.md:5` says only "Vox runs on Linux on x86_64". **The measured v0.4.30 asset
does not start on any system whose glibc is older than 2.39** (C5); earlier releases were not
measured.

**C2. The installer discards the reason (KNOWN).** `install.sh:379-380`:

```sh
installed=$("$INSTALL_DIR/vox" --version 2>/dev/null || true)
[ -n "$installed" ] || fail "the installed binary did not run"
```

The loader's message goes to `/dev/null`; the person reads one sentence with no cause and no
remedy. The run is also unbounded: `$(…)` waits for ever on a candidate that hangs.

**C3. The installer replaces before it checks (KNOWN).** `install.sh:366-377`, the Linux arm:
partials removed (`:366`), the download copied to `.vox-candidate.partial` (`:367-368`), the
existing `vox` copied to `.vox-previous` (`:369-372`), the marker written (`:375-376`), the
candidate renamed to `vox` (`:377`); only then the check of C2 (`:379`). A candidate that cannot
run is left installed under `vox`, and a second run copies that dead `vox` to `.vox-previous`
(`:370-371`) before installing the same dead candidate again: exactly the two equal files found
on the machine. The macOS arm has the order right: the helper inside the downloaded app is run
with `--version` "before anything already installed is touched" (`install.sh:227-230`); the
Linux arm never got that step.

**C4. `vox update`'s download path does not have the defect, but has C2's words (KNOWN).** Off
macOS, `verify_candidate` (`crates/vox-tui/src/update.rs:1079-1090`) calls `verify_apple_release`
(`:788-805`), which runs the downloaded candidate with `--version` and requires exit 0, exactly
`vox <version>\n` on stdout and **nothing on stderr**, before `update-apply` is started (`:1057`)
and again (`:1183`) before `publish` (`:1222`, `:882-896`). The candidate lives in a private
temporary directory (`:998-1009`); nothing under the install directory is touched before the
check. A candidate the loader refuses therefore fails at `:795-802` with
`release trust check failed: the candidate's version is not the one the record named`: the
working `vox` is kept, but the sentence names the wrong cause and hides the loader's words
(stderr is captured and only tested for emptiness, `:797`). Note also that the engine that
publishes is the candidate itself (`update-apply`, `:1057-1061`; `apply_request`, `:1093`,
`publish` at `:1222`): a candidate the loader refuses cannot publish anything, whatever the
verifier says. `runs_as_vox` (`:1357-1402`) sends stderr to null too (`:1365`); it judges
leftovers, not downloads, and is not changed here.

**C5. What the v0.4.30 asset needs (KNOWN: the evidence folder's `elf-version-needs.txt`,
read from the asset's `.dynamic`, `.gnu.version_r`, `.dynsym` and `.gnu.version` tables on this
Mac; nothing was run).** `NEEDED`: `libgcc_s.so.1`, `libm.so.6`, `libc.so.6`,
`ld-linux-x86-64.so.2` (`:7`). Version needs on `libc.so.6` from `GLIBC_2.2.5` up to `GLIBC_2.39`
(`:9`). The undefined symbols above glibc 2.28, as recorded, and what a link on a glibc 2.28 host
is expected to do with each. **Every entry of the last column is INFERRED** from glibc 2.28's
headers and ABI lists and is to be measured on the first floor build; no requirement rests on
it. The floor's soundness rests on the first column (measured) and on the fact that nothing Vox
links needs a symbol that glibc 2.28 lacks (the Rust toolchain supports glibc 2.17 and newer on
this target; the C code below compiled on glibc 2.28 systems for years).

| Version need (measured) | Symbols (measured) | Where from | On a glibc 2.28 link (INFERRED) |
|---|---|---|---|
| `GLIBC_2.39` (`:39`) | `pidfd_spawnp`, `pidfd_getpid` (both **weak**) | Rust std's process spawning: weak references, versioned by the libc present at link time. The loader checks the version-need table before it resolves any symbol, so a weak reference still makes the whole binary need 2.39 (drasi-project/drasi-core#601, the same two symbols; rust-lang/rust#121012). | glibc 2.28 has no such symbols: the weak references stay unversioned and resolve to null at run time; Rust std handles absent pidfd support. |
| `GLIBC_2.38` (`:38`) | `__isoc23_sscanf`, `__isoc23_strtol` | C code compiled on the runner against glibc 2.38+ headers, which redirect `sscanf` and `strtol` to their C23 forms. Attributed **by elimination** to `aws-lc-sys` 0.41.0: Vox's only C on Linux is `aws-lc-sys` and `ring` 0.17.14, both built by `cc` (`Cargo.lock`: `aws-lc-rs 1.17.0 → aws-lc-sys`; `rustls`, `rustls-webpki` and `quinn-proto → ring`; `vox-sockdrops → cc` compiles only on macOS, `crates/vox-sockdrops/build.rs`); `aws-lc` calls `sscanf` in `crypto/fipsmodule/cpucap/cpu_intel.c:105-107` and `strtol` in `crypto/evp_extra/p_dh.c:178-199` and `crypto/fipsmodule/evp/p_rsa.c:692-703` (read in the cargo registry on this Mac); `ring`'s C has neither. | `strtol@GLIBC_2.2.5`; `sscanf` becomes `__isoc99_sscanf@GLIBC_2.7` under C99 and later (glibc 2.28 `libio/stdio.h`'s redirection), not plain `sscanf`. Both are below the floor. |
| `GLIBC_2.34` (`:37`) | `__libc_start_main`, `dlsym`, 17 `pthread_*` | glibc 2.34 folded libpthread and libdl into libc; a link on 2.34+ versions them 2.34. | `__libc_start_main@GLIBC_2.2.5` from libc; `dlsym@GLIBC_2.2.5` from `libdl`; the `pthread_*` names from `libpthread` at `GLIBC_2.2.5`, **except `pthread_setname_np`, which `libpthread` exports at `GLIBC_2.12`** (glibc 2.28 `x86_64/64/libpthread.abilist`) **(r3)**; `libdl.so.2` and `libpthread.so.0` join `NEEDED`. All below the floor. |
| `GLIBC_2.33` (`:36`) | `stat`, `stat64`, `fstat64`, `fstatat64`, `lstat64` | glibc 2.33 exported them; before, they were wrappers in `libc_nonshared.a`. | The wrappers: `stat`/`stat64` → `__xstat64@GLIBC_2.2.5`, `lstat64` → `__lxstat64@GLIBC_2.2.5`, `fstat64` → `__fxstat64@GLIBC_2.2.5`, `fstatat64` → `__fxstatat64@GLIBC_2.4` (glibc 2.28 `io/fstatat64.c`). |
| `GLIBC_2.32` (`:35`) | `pthread_getattr_np` | as 2.34 | `libpthread`, `GLIBC_2.2.5`. |
| `GLIBC_2.30`, `2.29` (`:33-34`, `:45`) | `gettid` (weak), `posix_spawn_file_actions_addchdir_np` (weak); `pow@2.29`, `expf`/`powf@2.27` on `libm` | Rust std (weak) and `libm`'s newer exports | the weak ones unversioned; `pow@GLIBC_2.2.5`; `expf`/`powf@GLIBC_2.27` stay (below the floor). |

Everything at or below `GLIBC_2.28` (`statx`, `copy_file_range`, `getrandom`, `clock_gettime`,
`getauxval`, `memcpy@2.14`, the epoll and socket calls) is unchanged. The Rust toolchain is pinned
(`rust-toolchain.toml:1-3`, 1.94.0) and supports glibc 2.17 and newer on
`x86_64-unknown-linux-gnu` (Rust blog, "Increasing the glibc and Linux kernel requirements",
2022-08-01; the rustc platform-support table). `redb` (vendored, `Cargo.toml:235`), `rustix`
1.1.4, `zlib-rs` 0.6.8 and `region` 3.0.2 are pure Rust over syscalls or over the libc calls
listed above; none links its own C. No symbol in the table needs a kernel newer than the glibc it
comes from.

**C6. `vox update --rollback` renames `.vox-previous` over `vox` without running it (KNOWN).**
`do_rollback` (`update.rs:1284-1337`): after the interrupted-rollback branch (`:1295-1313`,
which does run the scratch copy, `runs_as_vox(&scratch)` at `:1296`), it checks only
`previous.is_file()` (`:1314`), copies the active binary to the scratch (`:1323`), and renames
`.vox-previous` to `vox` (`:1324`). A dead `.vox-previous` (the one C3 writes; the one left on
the operator's machine) becomes the active `vox` on the next rollback: a working binary replaced
by one that cannot run, by the command that exists to undo exactly that. The bundle path on
macOS checks the replacement helper before publication (`update/bundle.rs:986-1003`,
`:1052-1066`, `:2656-2694`, `:3643-3665`, `:3801-3802`; first review, "Facts retraced") and is
not changed.

### Why no proof caught it

- `install_sh_proof.rs` (`crates/vox-tui/tests/install_sh_proof.rs:343`,
  `install_sh_installs_what_it_verified_and_refuses_what_it_could_not`) serves the binary cargo
  just built from a loopback release server (`:1-11`, `:291-340`) and runs it where it built it;
  the served binary always runs on the proof's own system. Its refusal acts (`:729-778`) check
  digest, size and record identity, all before any candidate is run.
- The update journey's rollback claim (`update_proof.rs:1210`) rolls back to a previous that
  runs; no act plants one that does not.
- The post-release smoke runs the published asset on a runner or a container of the same age as
  the build runner (ADR-045 FG-2 "the post-release smoke runs the published asset once"; no
  image is named).
- Nothing in the release job reads the asset's version needs (C1).

## Terms

- **The floor**: the oldest C library a Linux release asset is built to run on. In this ADR:
  glibc 2.28 (ruling 2).
- **In words**: "Vox needs glibc 2.28 or newer (Ubuntu 20.04, Debian 10, RHEL 8 and newer)".
  Said the same way in the manual, the README, the installer and `vox update`.
- **The candidate**: the downloaded binary before it is named `vox`. In the installer it is
  `.vox-candidate.partial` in the install directory (`install.sh:367`, `update.rs:76`); in `vox
  update` it is `vox` in a private temporary directory (`update.rs:1003`). **The retained
  previous** is `.vox-previous` (`update.rs:71`); in a rollback it plays the candidate's part.
- **The loader's words**: what `ld-linux-x86-64.so.2` prints on stderr when it refuses to start
  a program; for this defect, lines of the form
  ``<path>: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.39' not found (required by <path>)``.
  **A version name** in such a line is `GLIBC_` followed by dot-separated decimal numbers of any
  count (`GLIBC_2.28`, `GLIBC_2.2.5`, `GLIBC_9.2.5`); names are compared numerically, component
  by component, the shorter padded with zeros (`2.28` > `2.2.5`; `9.2.5` > `2.28`) **(r3)**.
- **The run check** **(r3)**: starting a binary with `--version`, with no inherited environment
  beyond `PATH`, `HOME`, `VOX_DATA_DIR` and `VOX_CONFIG_DIR`, its stdout and stderr captured,
  under `timeout --kill-after=2 20` (GNU coreutils) where that is available; accepted only when
  the exit status is 0 and stdout is exactly `vox <version>`; **where no version is expected**
  (the existing `vox` LB-4's last line names; the retained previous in a rollback, LB-5) any
  `vox <x>` answer with exit 0 is *ran* **(r5)**. The loader is the judge of
  whether the binary starts; the installer and the updater only read the verdict. Four verdicts,
  derived from `timeout`'s own exit status (GNU `timeout(1)`: 124 when the command timed out,
  137 when it had to be killed with KILL, 126 when it could not be invoked, 127 when it was not
  found; otherwise the command's status): *ran* (0 and the right stdout), *did not answer* (124
  or 137), *could not start* (126 or 127), *did not run* (anything else). `vox update` derives
  the same four verdicts from its own bounded spawn (`runs_as_vox`'s shape, `update.rs:1357-1402`,
  which records the expiry itself).
- **The floor precondition**: the one measurement in producing the Linux asset (LB-2): the
  highest version name in the built binary's version-need table is at or below the floor. A
  release precondition, recorded in the build log; not a proof, not an asset.

## Requirements

Each requirement gives the rule, why, what changes (files and functions at the tag), what is
deleted, and its proof. "The install journey" is
`install_sh_installs_what_it_verified_and_refuses_what_it_could_not`
(`crates/vox-tui/tests/install_sh_proof.rs:343`; its Linux arm `:842-879`, claim
`install.reruns_after_a_cut_short_run` `:868`); it is not ignored and runs in the suite's debug
pass (`release-gate.sh:56`). "The update journey" is
`an_update_restarts_its_daemon_and_refuses_a_different_local_version`
(`crates/vox-tui/tests/update_proof.rs:938`; `#[ignore = "real update, production Argon2id; run
in release with test-knobs"]` at `:936-937`, so it runs only in the release pass's `-- --ignored`
selection, `release-gate.sh:65-66`; it serves a standalone release from loopback through
`standalone_release_of` `:867` and `vox_saying` `:850-864`, which needs
`VOX_PROOF_NEXT_BINARY`, a genuinely compiled `vox` saying the version the journey computes at `:961-963` (the workspace version with its first character replaced by `9`: `9.4.31` for v0.4.31); its rollback claim is
`update.rollback_restores_the_previous_binary_and_ready_node` `:1210`, followed by the daemon
cleanup at `:1223-1227`). Both are blocking proofs of the release suite, which runs inside the
fleet's VMs (ruling 4); **where the Linux arms of this ADR run, and the two invocations, are
LB-6's first paragraph (r3)**. "J11" and "J7" are ADR-045's journeys *Linux install and buffers*
and *Restart and update need no human* (ADR-045 r18, `/opt/vox-evidence/v0431/adr-snapshots/ADR-045.1e2bee466.md`;
the rows as at r14 `ADR-045.6503326f6.md:794`, `:790`). A red says PRODUCT and quotes what the
installer or `vox` printed, or APPARATUS when staging failed (an image that would not pull, a
server that would not start, a dead candidate that did not fail the way the apparatus requires).

### 1. The floor

- **LB-1. One floor, in words, where a person installing reads it.** The Linux release asset
  MUST run on any x86_64 Linux whose C library is glibc 2.28 or newer, and the floor MUST be
  stated in words in three places that say the same thing: `docs/manual/install.md` (the line that
  today reads "Vox runs on Linux on x86_64, and on Macs with Apple Silicon and macOS 13 or later",
  `:5`), `README.md` under "Install" (`:49-50`, beside the macOS floor it already states), and
  `install.sh`'s header comment (`:10`, beside "macOS needs Apple Silicon and macOS 13 or later").
  The words are: **"On Linux, Vox needs glibc 2.28 or newer: Ubuntu 20.04, Debian 10, RHEL 8,
  and everything newer. On an older system the installer says so and installs nothing; where it
  can tell before downloading, it downloads nothing."** The manual's "Applies to Vox v0.4.24"
  (`install.md:3`) is to say v0.4.31. The floor is a decision recorded here (ruling 2); a build
  failure does not change it (LB-2).
  - *Why*: C1. The decider's machine is Pop!_OS 22.04; ruling 2 names the floor. 2.28 is the
    floor of RHEL 8, Debian 10 and Ubuntu 18.10, and the floor GitHub's own actions need inside
    a container (Node 20 and later refuse below 2.28, actions/checkout#1590), so it is the lowest
    floor on which the standard build method of LB-2 can run at all. A document is the only
    place a person can learn the answer before trying.
  - *What changes*: the three documents; nothing in code (the floor's value in code is LB-2's
    and LB-4's).
  - *Deleted*: nothing.
  - *Proof*: LB-6 (a) is the proof that the asset runs on the floor; the documents are reviewed,
    not tested (a test of prose proves nothing for a user).

### 2. The build

- **LB-2. The release build achieves the floor by building on it; producing the asset includes
  measuring it. (changed r3)** `build-linux-x64` MUST build inside the container
  `quay.io/pypa/manylinux_2_28_x86_64` (AlmaLinux 8, glibc 2.28, GCC 14 toolset on `PATH`),
  pinned by image digest, with the same commands as today: `cargo build --release --bin vox`,
  copy to `vox-symbols`, `strip`, `scripts/package-release.sh` for both files
  (`release.yml:86-97`). The Rust toolchain is installed inside the container by `rustup` at the
  pinned `rust-toolchain.toml` version (1.94.0), as on the runner today.

  **One script for the Linux steps.** All the Linux steps (toolchain, build, strip, the floor
  precondition, packaging) live in `scripts/linux-release-steps.sh <out-dir>`, which
  `release.yml`'s container job runs, and which `scripts/build-linux-release.sh <out-dir>` runs
  inside the same pinned image through `podman run --platform linux/amd64` (or `docker run`)
  with the repository mounted, for everyone who is not the release job: the fleet (ADR-045
  FG-2's Linux `vox`) and the dry run. Both paths produce the same packaged `dist/` set, exactly
  the tag's: `vox-<triple>`, its `.sha256`, `stable-`/`proof-<triple>.json`, `vox-<triple>-symbols`
  and its `.sha256`. **No new asset (r3).**

  **The floor precondition**, five lines of that script, run on the stripped `vox` before
  `package-release.sh`: `readelf -V` (the image's binutils) lists the version needs; the highest
  `GLIBC_` name by numeric comparison is taken; the floor is read from `LINUX_GLIBC_FLOOR=` in
  `install.sh` **resolved from the script's own location** (`$(dirname "$0")/../install.sh`),
  never from the working directory; the script prints one line
  `linux-release-steps: vox needs glibc <x.y>; floor <floor>: ok` and goes on, or
  `… : above the floor` and exits 1 with nothing packaged. The line is in the release run's log
  and, for the fleet, in the manifest beside the binary's hash (FG-2); nothing installed ever
  reads it. `package-release.sh` is unchanged and never measures anything: it runs on the macOS
  runner and in the guest too, where there is no `readelf`.

  **The dry run's cutover (r3: finding 6).** `scripts/release-dry-run.sh` takes **two required
  arguments**, `OUTPUT_DIRECTORY LINUX_DIST`, the second being the `dist/` directory
  `build-linux-release.sh` produced (`:7`, `:26-31`, `:45`); it refuses a directory that does not
  hold exactly the Linux files named above (`release dry run: LINUX_DIST must be the dist/
  directory scripts/build-linux-release.sh wrote; it lacks <name>`), copies them into its own
  `dist/` in place of packaging a Linux binary itself (`:117-122` deleted), and keeps everything
  else (`:123-156`). **The Mach-O stand-in mode is deleted** (`:18`, `:120`, `:157`): there is no
  dry run without a real Linux dist, so ADR-045 FG-2's "the Linux asset is the macOS stand-in"
  refusal has nothing left to refuse and is retired by the sibling paste. `check-release-assets.sh`
  is unchanged.

  **What the precondition is, and is not.** It is part of producing the asset, like the
  `VOX-MUTANT-SENDER` and `VOX_TEST_` refusals at `package-release.sh:85-101`: a release that
  fails it produces no asset. It is **not a proof**: it reads metadata, drives nothing a person
  drives, and never reads the manual. The proof that the asset runs on the floor is LB-6 (a);
  the proof that an incompatible asset is refused where a person would meet it is LB-6 (a)'s
  mutant, which never passes through this precondition (LB-6). The precondition is not counted
  in any proof ledger.

  **If the first build in the image fails.** The failure is investigated and recorded (what
  broke, in which crate, with the log); it is not evidence that the floor is unsound. Acceptance
  of this ADR's build requirement remains **a successful build in the 2.28 image plus a green
  LB-6 (a) on the floor image**. A higher floor is never taken at implementation time: it would
  be an explicit revision of LB-1's words, LB-4's constant, LB-6's images, the sibling pastes
  and ruling 2, put to the coordinator and the decider (the recorded answer reopens). The
  candidates for such a revision, named so nobody has to invent them under pressure, are
  `debian:11` (glibc 2.31) and `ubuntu:22.04` (glibc 2.35, the ceiling the coordinator set);
  each is the same one-line image change.

  **The methods compared.** Evidence, not preference; "unchanged" means the `cargo build` line
  and the crates it compiles stay as at the tag.

  | Method | Changes in `release.yml` / scripts | What it does to the crates Vox links | Reproducible? | Risk |
  |---|---|---|---|---|
  | **A. Build inside a glibc 2.28 container** (`manylinux_2_28_x86_64`; chosen) | `container:` on the job with a pinned digest; the steps script; the dry run takes a `dist/` directory. Build line unchanged. | `aws-lc-sys` and `ring` compile with the image's GCC 14 against 2.28 headers: no C23 redirect; Rust std's weak `pidfd_*` stay unversioned; everything else binds as in C5's table (INFERRED). `aws-lc-sys` 0.41.0 selects its `cc` builder for this triple (prebuilt bindings, no cmake, no clang; `builder/main.rs:534-576` in the registry). | Yes: image digest, GCC, glibc fixed; the toolchain pinned as today. | The first build in the image is unobserved (nothing was run for this ADR). What could break: a `cc` flag GCC 14 rejects (none known), or `Swatinem/rust-cache@v2` inside a container (INFERRED to work; a cache miss costs time, not correctness). "If the first build fails" applies. |
  | **B. `cargo zigbuild --target x86_64-unknown-linux-gnu.2.28`** on `ubuntu-latest` | Install `zig` and `cargo-zigbuild` (two more pinned tools); `cargo zigbuild` replaces `cargo build`; `CC`/`AR` become `zig cc`/`zig ar` for `cc`-built crates; the same precondition. | `aws-lc-sys` and `ring` are compiled and archived by zig's clang and LLVM `ar`; the link is zig's lld against zig's generated glibc 2.28 stubs, not a glibc. `aws-lc-rs` 1.17.0 (in the lock) is the first release that builds under zig (aws/aws-lc-rs#993, closed 2026-05-13 by 1.17.0); a zig 0.16 `ar` regression broke `ring` and `aws-lc-sys` archives in 2026-04 (#993, comment of 2026-04-21). | Only with `zig` and `cargo-zigbuild` versions pinned; a zig bump changes the linker and libc stubs under the release. | Viable, but a second toolchain nobody on this project has run; the binary is linked by a linker and C library stubs no proof ever executes. Not boring. Rejected. |
  | **C. Static musl** (`x86_64-unknown-linux-musl`) | A new target triple everywhere: the asset name, both records' `target`, `install.sh:54` (`os_t`), `update.rs:237` (`target_triple`), `check-release-assets.sh:25`, both proofs' `target_triple()`; `musl-tools`; `aws-lc-sys` and `ring` both support the target (INFERRED from their platform lists). | No glibc at all; musl's resolver (no NSS: no `.local` or LDAP names), musl's allocator, musl's `getaddrinfo`; `region`'s `mlock` and `rustix`'s raw syscalls unchanged. | Yes. | A new platform in a stabilization release, with behaviours no journey has run; and v0.4.30's updater asks for `stable-x86_64-unknown-linux-gnu.json`, so the one-time update (ADR-041 RS-2) would still need a gnu asset. Rejected. |
  | **D. `runs-on: ubuntu-22.04`** (glibc 2.35) | One line. | Unchanged. | Until GitHub retires the label: deprecated 2026-09-17, brownouts 2027-03-23 to 2027-04-13, removed 2027-04-17 (actions/runner-images#14254). | The workflow must change again within months, by GitHub's calendar, and 2.35 excludes RHEL 9, Alma 9, Amazon Linux 2023 (2.34), Debian 11 and Ubuntu 20.04 (2.31): it does not meet ruling 2. Rejected. |

  - *Why*: C1, C5. A is the standard method for Linux binaries that must run on older systems
    (the manylinux images exist for this) and changes nothing about what is compiled. The
    precondition would have stopped v0.4.30's asset (`needs glibc 2.39; floor 2.28: above the
    floor`) before it was packaged.
  - *What changes*: `release.yml:78-102` (`container:`, the steps script); new
    `scripts/linux-release-steps.sh` and `scripts/build-linux-release.sh`;
    `scripts/release-dry-run.sh:7`, `:18`, `:26-31`, `:45`, `:117-122`, `:157`; ADR-045's
    Terms, FG-2 and FG-11 (Sibling changes). `ci.yml:32`, `:85-86` stay on `ubuntu-latest`: CI
    compiles and lints; it publishes nothing (ADR-045 FG-3).
  - *Deleted*: the dry run's own Linux packaging step and its Mach-O stand-in
    (`release-dry-run.sh:18`, `:117-122`, `:157`).
  - *Proof*: LB-6 (a); its mutant is an incompatible asset served as the release, staged as
    LB-6 (a) says. The precondition has no proof entry (it is not one); that it refuses
    v0.4.30's asset is a fact the implementer checks once on the downloaded asset and records in
    the post, not a gate.

### 3. The installer checks before it replaces

- **LB-3. The candidate runs from its partial name, bounded, before anything is replaced.
  (changed r5)** On Linux the installer MUST run the candidate as
  `env -i PATH="$PATH" HOME="$HOME" VOX_DATA_DIR="${VOX_DATA_DIR:-}" VOX_CONFIG_DIR="${VOX_CONFIG_DIR:-}"
  timeout --kill-after=2 20 "$INSTALL_DIR/.vox-candidate.partial" --version` (Terms' environment
  and nothing else of the installer's; an unset `VOX_*` is passed empty and read as unset) with
  stdout and stderr redirected to two files under `$tmp`, and derive the verdict from the exit status as
  Terms says. `timeout` with `--kill-after` is in GNU coreutils 8.30, the coreutils of every
  floor system: Ubuntu 20.04 (`coreutils 8.30-3ubuntu2`, the focal `timeout(1)` page), Debian 10
  (`coreutils 8.30`, the buster `timeout(1)` page, February 2019, which documents `-k,
  --kill-after`, exit 124 and 128+9), RHEL 8 (`coreutils-8.30-*.el8`; INFERRED from the package
  name, not read from Red Hat's index). **The bound is `timeout`'s, not the installer's**: TERM
  at 20 s, KILL 2 s later; a candidate that ignores TERM is killed; the expiry is recorded by
  `timeout`'s own status (124 or 137), never inferred from empty output. Before downloading, in
  the tools section (`install.sh:88-95`), the installer runs `timeout --kill-after=1 5 true`
  once; when that fails (no `timeout`, or a busybox `timeout` without `--kill-after`: a system
  outside the floor's distributions) the run check is made **without a bound**, and the installer
  prints one sentence before it: `vox install: this system has no GNU timeout; the check of the
  downloaded vox is not time-limited.` No watchdog is written by hand (finding 3). The same
  bounded run is used for **every** `--version` the Linux arm performs: the candidate, the
  existing `vox` whose version LB-4's last line names, and step 9's report. The candidate is
  accepted only on *ran*; on any other verdict the installer MUST print LB-4's lines, remove
  `.vox-candidate.partial`, and exit 1, with `vox`, `.vox-previous` and the marker exactly as
  they were. The order of file operations in the Linux arm becomes:

  | Step | Operation | At the tag | After |
  |---|---|---|---|
  | 1 | download to `$tmp/vox-x86_64-unknown-linux-gnu`; size and SHA-256 checked | `:350-351` | unchanged |
  | 2 | `mkdir -p "$INSTALL_DIR"`; refuse a `vox` this installer did not make | `:354-357` | unchanged |
  | 3 | `rm -f .vox-candidate.partial .vox-previous.partial` | `:366` | unchanged |
  | 4 | `cp` the download to `.vox-candidate.partial`; `chmod 0755` | `:367-368` | unchanged |
  | **5** | **the run check on `.vox-candidate.partial`; on any verdict but *ran*: LB-4's lines, `rm -f .vox-candidate.partial`, exit 1** | — | **new** |
  | 6 | `cp -p vox .vox-previous.partial`; `mv -f` to `.vox-previous` (only if `vox` exists) | `:369-372` | unchanged, now after 5 |
  | 7 | write `.vox-standalone.json` | `:375-376` | unchanged |
  | 8 | `mv -f .vox-candidate.partial vox` | `:377` | unchanged |
  | 9 | the run check on `"$INSTALL_DIR/vox"`; on failure its stderr is printed and the installer exits 1 | `:379-380` | kept as a report of the final name; stderr shown; bounded |
  | 10 | `vox shell-setup`; ADR-044 RD-12's buffer step | `:398`; RD-12 | unchanged; never reached by a refused candidate |

  What is on disk after each failure point, for an existing install (`vox` = 0.4.30 running,
  `.vox-previous` = 0.4.29, marker present) and for a first install (nothing of Vox present).
  "Untouched" means byte-identical to before the run:

  | Failure point | Existing install: `vox` / `.vox-previous` / partials | First install | Exit |
  |---|---|---|---|
  | LB-4 (i)'s pre-download refusal | untouched / untouched / none | nothing downloaded, `$INSTALL_DIR` not created | 1 |
  | step 1 (size, digest, origin) | untouched / untouched / none (`$tmp` removed by the `EXIT` trap, `:106`) | nothing written | 1 |
  | step 2 (foreign `vox`) | untouched / untouched / none | — | 1 |
  | step 3 fails (the partial cannot be unlinked: directory not writable) | untouched / untouched / the old partial remains; `set -e` (`:19`) stops the run | the same | 1 |
  | step 4 fails (`cp` or `chmod`: disk full, directory not writable) | untouched / untouched / `.vox-candidate.partial` may remain, short; step 3 of the next run removes it | the same | 1 |
  | step 5 (any verdict but *ran*) | untouched / untouched / **none** (the partial removed); a killed candidate is `timeout`'s to reap, and it does | `$INSTALL_DIR` exists and holds nothing of Vox (the marker is step 7) | 1 |
  | interrupted (`INT`/`TERM`, `:107`) during 4–5 | untouched / untouched / `.vox-candidate.partial` may remain; the next run removes it | the same | 130 |
  | step 6 fails (`cp -p` of the previous: disk full) | untouched / untouched (the `mv -f` was not reached) / `.vox-previous.partial` and `.vox-candidate.partial` may remain; the next run removes both | — | 1 |
  | interrupted between 6 and 8 | 0.4.30 / 0.4.30 (a copy of the still-current `vox`) / `.vox-candidate.partial` remains; the next run removes it, re-runs the check, and copies the same 0.4.30 to `.vox-previous` again | — | 130 |
  | step 7 fails or is interrupted (first install) | — | the marker may exist, possibly truncated, beside `.vox-candidate.partial` and no `vox`; the next run removes the partial (step 3), finds no `vox` (step 2 passes), and rewrites the marker (step 7) | 1 or 130 |
  | step 8 fails (`mv -f` refused: directory not writable between 4 and 8) | 0.4.30 / 0.4.30 / `.vox-candidate.partial` remains | marker present, no `vox`, the partial remains | 1 |
  | after step 8 | 0.4.31 / 0.4.30 / none: the install is complete; step 9 is a report | 0.4.31 / — / none | 0 or 1 |

  A second run on a system where the candidate does not run reaches step 5 again and stops
  there: `.vox-previous` is never written from a dead `vox`, because no dead `vox` is ever
  installed. `install.sh` has no `fsync` at the tag and gains none; durability across power loss
  stays `vox update`'s (`update.rs:875-896`, V210-56).
  - *Why*: C2, C3; the two equal dead files on the operator's machine; the macOS arm's order
    (`install.sh:227-230`) already is this.
  - *What changes*: `install.sh:349-382`, the Linux arm: one function `run_check <path>
    <version>` (the `timeout` run or the unbounded one, its four verdicts, its two output files)
    used at steps 5 and 9 and by LB-4's last line; the `timeout` probe in the tools section
    (`:88-95`); the run check inserted between `:368` and `:369`; `2>/dev/null` removed at
    `:379`. The file names stay (`uninstall.rs:612-620` lists them; nothing new to remove).
  - *Deleted*: the tag's post-rename check as the only check (`:379-380` becomes step 9's
    report).
  - *Proof*: LB-6 (c) and (g), in the install journey; the fleet arm LB-6 (b).

### 4. The installer says why

- **LB-4. The person is shown the loader's words and one plain sentence; the run is the check
  that decides. (changed r3)** Two checks, in this order:

  **(i) Before downloading** (immediately after the target is chosen, `install.sh:79-85`, and
  before the tools check `:88`, the temporary directory `:104` and the record request `:108`;
  beside the macOS checks at `:57-73`): on Linux the installer reads the system's C library
  version with `getconf GNU_LIBC_VERSION` (prints `glibc 2.35`; part of glibc). When the command
  succeeds and prints `glibc <major>.<minor>` with `<major>.<minor>` below `LINUX_GLIBC_FLOOR`,
  the installer MUST print, to stderr, exactly

  ```
  vox install: this Linux is not supported: Vox needs glibc 2.28 or newer (Ubuntu 20.04, Debian 10, RHEL 8 and newer), and this system has glibc 2.27. Nothing was downloaded or installed.
  ```

  and exit 1, having made **no request and written nothing** (the same shape as the macOS lines
  at `:68` and `:71`). When the command is absent, fails, or prints anything else (a musl system,
  a container without `getconf`), the installer prints nothing and goes on: **this check is
  advisory**. It exists so the person is told before a 60 MB download, not to decide.

  **(ii) The run check** (LB-3 step 5) **is authoritative**: the loader decides, with the real
  binary on the real system. When the verdict is not *ran* the installer MUST print, to stderr,
  four parts in this order:

  1. The first line, by verdict: *did not run* and *could not start*: `vox install: vox 0.4.31
     did not run on this machine. It said:` (the version the record named, `:116`); *did not
     answer*: `vox install: vox 0.4.31 did not answer \`--version\` within 20 seconds and was
     stopped. Before that it said:`.
  2. What it said: every line the candidate wrote to stderr, indented two spaces, at most 20
     lines; when stderr was empty and stdout was not `vox <version>`, instead `  it printed:
     <stdout, first 256 bytes>`; when both were empty, `  (nothing)`.
  3. **The cause sentence**, chosen by the first rule that applies:
     - stderr holds at least one ``version `<name>' not found`` whose `<name>` is a version name
       (Terms): let `<need>` be the numerically highest such name, shown as written without the
       `GLIBC_` prefix (`2.39`; `9.2.5`); "this system has glibc `<y>`" from `getconf
       GNU_LIBC_VERSION`, or the clause `and this system's glibc version could not be read` when
       unreadable. When `<need>` compares **at or below** the floor: `vox install: this build
       needs glibc <need> and this system has glibc <y>. Vox supports glibc 2.28 or newer (Ubuntu
       20.04, Debian 10, RHEL 8 and newer); this system is older than that.` When `<need>`
       compares **above** the floor (an incompatible build, which LB-2 exists to prevent): `vox
       install: this build needs glibc <need> and this system has glibc <y>. Vox supports glibc
       2.28 or newer (Ubuntu 20.04, Debian 10, RHEL 8 and newer); a release that needs more than
       that is a defect in Vox, not in this machine: please report it.`
     - the verdict is *could not start* and `/lib64/ld-linux-x86-64.so.2` does not exist: `vox
       install: the program loader this build needs, /lib64/ld-linux-x86-64.so.2, is not on this
       system. Vox supports glibc 2.28 or newer (Ubuntu 20.04, Debian 10, RHEL 8 and newer).`
       (It says the path is absent and no more **(r3)**.)
     - the verdict is *did not answer*: `vox install: a vox that does not answer \`--version\` is
       not installed. Vox supports glibc 2.28 or newer (Ubuntu 20.04, Debian 10, RHEL 8 and
       newer); if this system is one of those, this is a defect in Vox: please report it with the
       lines above.`
     - anything else: `vox install: the cause is not one this installer can name. Vox supports
       glibc 2.28 or newer (Ubuntu 20.04, Debian 10, RHEL 8 and newer); if this system is one of
       those, this is a defect in Vox: please report it with the lines above.` No libc version is
       invented.
  4. The last line: `vox install: nothing was changed: /home/user/.local/bin/vox is still vox
     0.4.30.` for an existing install (the version from the run check on the existing `vox`,
     which expects no particular version: any `vox <x>` with exit 0 is *ran*, Terms **(r5)**;
     `is still the vox that was there` when that verdict is not *ran*), or `vox install: nothing
     was installed.` for a first install.

  Sample, the operator's case had v0.4.30's asset been installed by this installer:

  ```
  vox install: vox 0.4.30 did not run on this machine. It said:
    /home/user/.local/bin/.vox-candidate.partial: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found (required by /home/user/.local/bin/.vox-candidate.partial)
    /home/user/.local/bin/.vox-candidate.partial: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.39' not found (required by /home/user/.local/bin/.vox-candidate.partial)
  vox install: this build needs glibc 2.39 and this system has glibc 2.35. Vox supports glibc 2.28 or newer (Ubuntu 20.04, Debian 10, RHEL 8 and newer); a release that needs more than that is a defect in Vox, not in this machine: please report it.
  vox install: nothing was installed.
  ```

  **The promise, qualified:** a system whose glibc is identifiably below the floor is refused
  before anything is requested or written; every other refusal happens after the download,
  preserves the published installation byte for byte, and removes its own staging. The lines use
  the installer's `vox install:` prefix (`:48`) and no other wording.
  - *Why*: C2; the decider read `the installed binary did not run` and had to ssh in to learn
    why. A person who is told "glibc 2.27, needs 2.28" knows what to do; one who is told "this
    build needs 2.39" knows it is Vox's fault; one on a system without the loader is told which
    file is missing, not left with a bare `not found`.
  - *What changes*: `install.sh`: a constant `LINUX_GLIBC_FLOOR=2.28` beside `APPLE_TEAM_ID`
    (`:26-28`), the supported-systems words in one variable so (i), (ii) and the header comment
    (`:10`) share them; check (i) after `:85`; the lines of (ii) in LB-3's step 5. No new
    environment variable; no knob.
  - *Deleted*: `fail "the installed binary did not run"` (`:380`).
  - *Proof*: LB-6 (c), (d), (g), (i) and (j); the fleet arm LB-6 (b).

### 5. `vox update` and `vox update --rollback`

- **LB-5. Neither an update nor a rollback replaces a working `vox` with one that cannot run,
  and each says why in the same words. (changed r3: the verdicts)**

  **The download path.** The order at the tag is kept: download to a private directory
  (`update.rs:998-1037`), `verify_candidate` (`:1038`, `:1079-1090` → `:788-805` off macOS),
  `update-apply` by the candidate (`:1057-1061`), `verify_candidate` again (`:1183`), `publish`
  (`:1222`, `:882-896`). What changes is the verdict's words: `verify_apple_release` off macOS is
  to run the candidate the way `runs_as_vox` does (`:1357-1402`: its own 5 s bound raised to 20 s
  for this use, the process group killed on expiry, the expiry recorded by the code that waited)
  but with stderr captured and bounded to 64 KiB rather than discarded, and to derive Terms'
  four verdicts from what it observed (expiry = *did not answer*; spawn error ENOENT/EACCES =
  *could not start*; non-zero or wrong stdout = *did not run*). On any verdict but *ran* it MUST
  return a usage error whose text is LB-4 (ii)'s four parts with the prefix `vox update:` in
  place of `vox install:`, the candidate's path in place of the partial's, and the last line
  `nothing was changed: <install dir>/vox is still vox <current>`; the cause sentence is computed
  by LB-4's rule, in Rust, from the candidate's stderr, the verdict and `getconf
  GNU_LIBC_VERSION` (run as a child, as `--version` is); **the missing-loader form is not
  computed here (r5)**: a running `vox` was started by that loader, so the path exists, and a
  *could not start* verdict takes the generic sentence with the OS error quoted in part 2.
  `/lib64/ld-linux-x86-64.so.2` is checked by `install.sh` only.
  On macOS the Apple checks and their words stay. The `release trust check failed: the
  candidate's version is not the one the record named` sentence (`:801`) stays only for the case
  it names: exit 0, stderr empty, stdout a different `vox <other>`.

  **The rollback (C6).** `do_rollback` MUST run the retained previous under the same run check
  (no version is expected of it: any `vox <x>` with exit 0 is *ran*, Terms **(r5)**)
  **before** `copy_durably(&active, &scratch)` (`:1323`), that is, after the `previous.is_file()`
  refusal (`:1314-1319`) and before any write. When the verdict is not *ran* it MUST return a
  usage error: LB-4 (ii)'s parts with the prefix `vox update:`, the first line `vox update: the
  retained previous vox (<dir>/.vox-previous) does not run on this machine; it is not put back.
  It said:`, the cause sentence by the same rule, and the last line `vox update: nothing was
  changed: <dir>/vox is still vox <current>; there is nothing to roll back to.` The dead
  `.vox-previous` is left where it is (it is the person's file to remove; `vox uninstall` lists
  it, `uninstall.rs:612-620`); the next successful update or installer run replaces it with a
  copy of the running `vox` (`publish`, `:885-886`; LB-3 step 6). The interrupted-rollback branch
  (`:1295-1313`) already runs the scratch copy and is unchanged; a rollback to a previous that
  runs stays as it is and its existing claim stays green.

  Note on the one-time update: every machine running v0.4.30 has glibc 2.39 or newer, because
  v0.4.30 does not start otherwise (C5); a v0.4.31 asset at floor 2.28 runs on all of them, so
  the one-time update (ADR-041 RS-2, J7(c′)) always finds a runnable candidate. The download
  path's refusal is for the day a future release is wrongly built; the rollback's refusal is for
  every machine the v0.4.30 installer left a dead `.vox-previous` on (one is known).
  - *Why*: C4, C6; the assignment's rule that an update must never replace a working binary with
    one that cannot run; the first review's finding that rollback does exactly that.
  - *What changes*: `update.rs:788-805` (`verify_apple_release`, the non-macOS arm: the bounded
    spawn with captured stderr, the verdict, the message); `do_rollback` (`:1284-1337`): the run
    check after `:1319`; one private function `explain_not_running(verdict, stderr: &[u8],
    system_glibc: Option<&str>, floor: &str) -> String` holds LB-4's rule without the
    missing-loader branch **(r5)**, because a running glibc `vox` was started by that loader;
    the floor is the same string as `install.sh`'s, kept in `update.rs` as a constant beside
    `REPO` (`:48`) with a comment naming `install.sh`'s constant. `cli.rs:2545-2549` (the
    `Update` help) gains one sentence: "A download, or a retained previous, that does not run on
    this machine is refused and the reason is shown; the installed vox is never replaced by it."
  - *Deleted*: the misnamed refusal for the does-not-run case (the words at `:801` for that
    case).
  - *Proof*: LB-6 (e), (h) and (k), in the update journey; the fleet arm LB-6 (f).

### 6. The proofs as one journey

- **LB-6. Eleven arms, no new file. (changed r5)**

  **Where they run, and the two invocations (r3: finding 2).** The in-tree Linux arms (c), (d),
  (e), (g), (h), (j) need an x86_64 Linux: `install.sh:79-82` refuses aarch64 Linux, the install
  journey's `target_triple()` (`install_sh_proof.rs:104-113`) and `update.rs:230-242` have no
  aarch64 Linux release target, so on the fleet's aarch64 Linux VM run natively they never reach
  their checks. They MUST be compiled and run **as x86_64 inside an emulated x86_64 container in
  the fleet's Linux VM** (`podman run --platform linux/amd64`, the VM's binfmt emulation; the
  image carries the pinned toolchain, GNU coreutils and `curl`; a persistent target cache on a VM
  volume), `vox` run as an ordinary user (the daemon refuses every control connection from root:
  "set a non-root USER"). The VM suite instructions (`docs/release/`, the fleet's `fleet/`
  README) MUST name two executions in that container, as the gate's two passes do
  (`release-gate.sh:56`, `:65-66`):

  ```
  # the install journey (not ignored; the debug pass)
  cargo test -p vox-tui --features test-knobs --test install_sh_proof
  # the update journey (ignored; the release pass), with the compiled 9.x fixture
  VOX_PROOF_NEXT_BINARY=<path> cargo test --release -p vox-tui --features test-knobs \
      --test update_proof -- --ignored an_update_restarts_its_daemon_and_refuses_a_different_local_version
  ```

  where `<path>` is a `vox` built in the same container from a copy of the tree whose workspace
  version (`Cargo.toml:14`) is the journey's own convention **(r4)**: the version with its
  initial `0` replaced by `9` and the other components kept (`update_proof.rs:961-963`:
  `std::iter::once('9').chain(VERSION.chars().skip(1))`; for v0.4.31 the fixture is compiled as
  **9.4.31**), `cargo build --release --bin vox --features vox-tui/test-knobs`, as `vox_saying`
  requires (`update_proof.rs:850-864`: it copies the fixture and refuses one that does not say
  `vox <next>`); compiling is not executing, and
  the receipt MUST show both executions' claim lists. The receipt records the image digest,
  `uname -m` (`x86_64`), the VM's kernel line and each build's wall clock, which is unmeasured
  today and is recorded at the first run. That this placement runs the x86_64 asset was shown on
  2026-11-13: in the fleet's Linux VM (Fedora kernel 7.2.7, aarch64) the v0.4.30 asset ran under
  emulation in `python:3.12-slim-trixie` (glibc 2.41) as uid 1000 and its daemons answered
  within 7 s (`/opt/vox-evidence/v0431/fleet-exp/receipts/E9a-attempt6-MEASURED/container-facts.txt`, `run.log`);
  that the Rust journeys compile and run there is not yet shown. Where the suite runs natively on
  aarch64 these claims print `CANNOT MEASURE: ADR-051's Linux arms run as x86_64 in an emulated
  container; this is aarch64` and are not green. The asset arms (a), (b), (f), (i) are acts of
  ADR-045's J11 and J7 on `x86_64` containers under the same emulation, as J11 already runs
  `install.sh` (ADR-045 r14 `:794`).

  **The images.** The floor image `almalinux:8` (glibc 2.28; supported until 2029); the
  operator's image `ubuntu:22.04` (glibc 2.35); the below-floor image `ubuntu:18.04` (glibc 2.27;
  on Docker Hub though past its end of life, INFERRED; `amazonlinux:2`, glibc 2.26, is the
  stand-by); **the non-glibc image `alpine:3.20`** (musl; busybox `sh`; `curl` added by the
  container build) **(r3)**. Each is pinned by digest in `fleet/containers/` and named in the
  manifest with its C library as read in the run (`getconf GNU_LIBC_VERSION`, or `ldd --version`'s
  first line where `getconf` has no answer; FG-4's "the OS build in every receipt"). The installer
  in every asset arm is the release's own `install.sh` (`release.yml:317`), pointed at **the
  fleet's stand-in release server** the way J11 already points it (`VOX_RELEASE_BASE`,
  `install.sh:29-31`; a documented hook of the installer, not a knob in the binary). That server
  serves whatever the arm stages: the candidate `dist/`, or, for a mutant, another binary with
  records written for it (`package-release.sh`'s schema-1 shape, `:117-123`, the size and digest
  of the staged file).

  **The dead candidate.** The apparatus for (c), (e), (f) and (h) makes a copy of the binary
  under test (the built `vox` in-tree; the candidate asset on the fleet) that the loader refuses
  on every glibc, by the loader's own rule: it **parses the copy's `.gnu.version_r`**, chooses
  the `libc.so.6` entry that the most non-weak undefined symbols reference (on any x86_64 glibc
  binary this is `GLIBC_2.2.5`; the apparatus does not assume it), and applies **one
  transformation (r3)**: the first numeric component after `GLIBC_` is replaced by `9`, in
  place, same length (`GLIBC_2.2.5` → **`GLIBC_9.2.5`**; were the entry `GLIBC_2.28`, →
  `GLIBC_9.28`). The loader compares the name as well as the hash (glibc `elf/dl-version.c`),
  finds no such version in `libc.so.6`, and refuses with ``version `GLIBC_9.2.5' not found``; by
  Terms that name compares above the floor, so LB-4's "defect in Vox" sentence shows `needs
  glibc 9.2.5`. **Staging is established before any claim**: the untouched source must run
  (`--version` prints its version) and the altered copy must fail with that exact diagnostic; a
  missing entry, a copy that runs, or a different failure is `APPARATUS: the dead candidate was
  not staged: <why>` and the arm is not green. In-tree the helper lives in
  `crates/vox-tui/tests/support/dead_candidate.rs` and is shared by both journeys; **on the
  fleet (r5)** the same parse-and-rewrite is `fleet/dead_candidate.py`, standard-library
  Python derived from the evidence folder's `elf-version-needs.py` (which already walks
  `.dynstr` and `.gnu.version_r`), run by the driver inside the guest with the same staging
  rule. The record served for the copy carries the copy's size and digest.

  | Arm | Extends | Act | Assertion (PRODUCT quotes what was printed) | v0.4.30 baseline | Mutant |
  |---|---|---|---|---|---|
  | **(a) install on the floor** | J11, new act (e) | on `almalinux:8` and on `ubuntu:22.04`, as a non-root user with `curl`: `sh install.sh` against the candidate `dist/` on the stand-in server | exit 0; `~/.local/bin/vox --version` prints `vox <candidate>`; stdout holds `installed: /home/user/.local/bin/vox (vox <candidate>)` (`install.sh:381`); the daemon J11 then starts is this binary | RED, PRODUCT, KNOWN on `ubuntu:22.04` (the evidence folder: `vox install: the installed binary did not run`, and the loader's two lines from the installed file); UNVERIFIED on `almalinux:8` (the same by C5; the run that verifies it is this arm's first baseline run) | **(r3: finding 5)** the stand-in server serves an **incompatible binary** under records written for it: the published v0.4.30 asset (hash above; it needs 2.39, a ready incompatible input), or a `vox` of the candidate commit built outside the container on the runner's own glibc; neither passes through `linux-release-steps.sh`, so no precondition is involved and no knob exists; staging must show the record's digest equals the file's. On both images the installer exits 1 with LB-4 (ii)'s lines and the loader's ``GLIBC_2.39' not found``: (a)'s "exit 0 and `vox --version` prints" turns red |
  | **(b) install below the floor** **(changed r5)** | J11, new act (f) | on `ubuntu:18.04`: `sh install.sh` against the candidate `dist/`, once as the image is, once with a **`getconf` shim first on `PATH` that exits 1** | first run: exit 1, stderr is exactly LB-4 (i)'s line with `glibc 2.27`, `~/.local/bin` does not exist, and the stand-in server's log shows **no request at all**; second run: exit 1, stderr holds LB-4 (ii)'s first line, a ``GLIBC_2.28' not found`` line from the loader (**INFERRED** from the v0.4.30 asset's weak `statx@GLIBC_2.28` need, `elf-version-needs.txt:32`, which a floor build keeps; the floor-built asset's actual highest need is measured by experiment -01 of the task cut, and the act asserts the name that measurement records), the cause sentence's "this system is older than that" form (that need compares at or below the floor), `nothing was installed.`; `~/.local/bin` holds no `vox`, no `.vox-previous`, no `.partial`, no marker | RED, PRODUCT, UNVERIFIED (v0.4.30 installs its dead binary and says `the installed binary did not run`; verified by the arm's baseline run) | skip check (i): the first run's "no request" turns red; `2>/dev/null` on the run check: the loader line turns red |
  | **(c) the order of operations** | the install journey's Linux arm (`:842-879`), new claims `install.refuses_a_candidate_that_does_not_run` and `install.keeps_the_previous_when_the_candidate_does_not_run` | the loopback release serves the dead candidate made from the built `vox`. First on a scratch home with a working install (the journey's own earlier install, `vox` = the built binary, `.vox-previous` planted as `cut short` 0555 as `:849-856` does); then on an empty scratch home | existing: exit 1; `vox --version` still prints the version it printed before; `.vox-previous` still reads `cut short`; no `.partial` in the directory; stderr holds LB-4 (ii)'s first line, a line containing ``version `GLIBC_9.2.5' not found``, the "defect in Vox" sentence with `needs glibc 9.2.5`, and `nothing was changed: <dir>/vox is still vox <version>`. Empty home: exit 1, the install directory holds no file, stderr ends `nothing was installed.` | RED, PRODUCT, KNOWN by C3 on the existing-install act (`vox` replaced by the dead copy, `.vox-previous` replaced) | move the run check after step 8 (the tag's order): `vox --version` turns red; `2>/dev/null` on the run check: the `GLIBC_9.2.5` line turns red |
  | **(d) the pre-download check** | the install journey, new claim `install.refuses_an_old_glibc_before_downloading` | a `getconf` shim first on `PATH` that answers `glibc 2.27` to `GNU_LIBC_VERSION`; the loopback server counts requests (as the Intel-Mac act does, `:943`); the proof snapshots the scratch home's installer-owned paths (`bin/`, `data/`, `config/`, the rc file's contents) before the run | exit 1; stderr exactly LB-4 (i)'s line; **the server saw zero requests**; every installer-owned path is as in the snapshot (`bin/` absent, the rc file unchanged; the apparatus's own `.zshrc` and applications stand-in, written by `run_installer_env` `:302-305`, are not the installer's) | RED, PRODUCT, KNOWN (the tag has no such check: it downloads and installs) | compare against `2.0` instead of the floor: the shim's run installs; red |
  | **(e) an update to a candidate that cannot run** **(changed r5)** | the update journey (`update_proof.rs:938`), new claim `update.refuses_a_candidate_that_does_not_run_and_says_why`, **placed after `daemon.version_mismatch_refused` (`:1155-1163`) and before the journey's own `vox update` (`:1165`)**: at that point the standalone install is the journey's own (`vox` = the built binary, `.vox-standalone.json` present, no `.vox-previous` yet) and the loopback release tree is `tree.path()` (`:989`) | the tree's `stable` asset and record are swapped for the dead candidate at the journey's next version (`9.x`) and its size and digest; the installed `vox` runs `vox update`; the tree is restored before the journey's own update | exit non-zero; stderr holds LB-5's four parts with `vox update:`, a ``GLIBC_9.2.5' not found`` line, the "defect in Vox" sentence with `needs glibc 9.2.5` and `nothing was changed`; and, as the context the words describe: `vox --version` unchanged, no `.vox-previous` created, no `.partial`, the journey's daemon still running the old binary | GREEN on preservation at v0.4.30 (C4: the candidate is the engine, and it cannot start), RED on the words, PRODUCT, KNOWN by C4 | **the explanation removed** (the non-macOS `verify_apple_release` returns the tag's one sentence): the words assertion turns red. There is no product mutant that publishes this candidate through the download path, because the engine that publishes is the candidate itself (C4): the preservation part of this claim is context; the mutated preservation claim of this ADR is (h) |
  | **(f) the update on the asset** **(changed r5)** | J7, its `vox update` act on B (stage 3) | the same as (e) with the release's `vox` and the dead candidate made from the candidate asset by `fleet/dead_candidate.py` in the guest, served the way J7 serves its candidate-to-candidate release (ADR-045 does not name that source; the J7 owner is to name it; where J7 can reach only GitHub, this arm is CANNOT MEASURE on the fleet, is **not counted as asset coverage and never appears as a passed J7 claim**, and (e) is the blocking proof) | as (e) | as (e) | as (e) |
  | **(g) a candidate that does not answer** **(changed r3)** | the install journey's Linux arm, new claim `install.stops_a_candidate_that_does_not_answer` | the loopback release serves, as the asset, the three-line script `#!/bin/sh`, `echo starting >&2`, `trap '' TERM; exec sleep 600` (one process, which ignores TERM; its size and digest in the record); the proof waits at most 40 s for the installer and kills it after that | the installer exits 1 within 40 s (`timeout` fired at 20 s, KILL at 22 s); stderr holds `did not answer \`--version\` within 20 seconds and was stopped. Before that it said:`, the line `  starting`, the *did not answer* cause sentence and `nothing was changed`/`nothing was installed.`; no `.partial`, `vox` untouched; **the `sleep 600` process is gone** (`timeout` killed it and reaped it; the proof checks by pid from the installer's process table before and after) | RED, PRODUCT, KNOWN (the tag has no bound; `$(... --version)` waits for ever) | raise the bound to 600 s: the installer is still running at 40 s; the proof kills it and the claim is red naming that the installer had not returned (a PRODUCT red; a harness failure to start the server or the shim stays APPARATUS) |
  | **(h) a rollback to a previous that cannot run** | the update journey's rollback claim (`update_proof.rs:1210`), new claim `rollback.refuses_a_previous_that_does_not_run`, **placed after the rollback act and before the journey's daemon cleanup (`:1223-1227`) (r3)** | plant the dead candidate as `.vox-previous`; run `vox update --rollback` | exit non-zero; `vox --version` unchanged; `.vox-previous` still the planted file; no `.vox-rollback.partial`; the daemon still running the same binary; stderr holds LB-5's rollback lines with ``GLIBC_9.2.5' not found`` and `there is nothing to roll back to` | RED, PRODUCT, KNOWN by C6 (`vox` becomes the dead file; `vox --version` fails) | skip the run check before `copy_durably`: `vox --version` turns red (the dead file is now `vox`) |
  | **(i) install where the loader is absent** **(new r3)** | J11, new act (g) | on `alpine:3.20` (musl, busybox `sh`), as a non-root user: `sh install.sh` against the candidate `dist/`; staging first shows `/lib64/ld-linux-x86-64.so.2` is absent in the image, else APPARATUS | exit 1; stderr holds (in order) the `no GNU timeout` sentence (busybox `timeout` has no `--kill-after`; INFERRED, and if the image's `timeout` accepts it the sentence is simply absent and not asserted), LB-4 (ii)'s first line, the shell's own line (busybox: `sh: …/.vox-candidate.partial: not found`), the missing-loader sentence naming `/lib64/ld-linux-x86-64.so.2`, `nothing was installed.`; `~/.local/bin` holds no file | RED, PRODUCT, UNVERIFIED (v0.4.30 installs the dead file and says `the installed binary did not run`; the arm's baseline run verifies it) | the missing-loader sentence replaced by the generic one (the `loader_present` test dropped): the "names `/lib64/ld-linux-x86-64.so.2`" assertion turns red |
  | **(j) a candidate that fails for a reason the installer cannot name** **(new r3)** | the install journey's Linux arm, new claim `install.says_what_an_unexplained_candidate_said` | the loopback release serves, as the asset, the script `#!/bin/sh`, `echo 'boom: no such table' >&2`, `exit 3`, on a scratch home with a working install | exit 1; `vox --version` unchanged; no `.partial`; stderr holds LB-4 (ii)'s first line, `  boom: no such table`, the generic cause sentence (`the cause is not one this installer can name`) and `nothing was changed: <dir>/vox is still vox <version>` | RED, PRODUCT, KNOWN by C2/C3 (the tag installs the script as `vox`, then says `the installed binary did not run`) | the generic sentence replaced by the loader-form sentence with an invented version (`needs glibc 2.28`): the "generic sentence, no version named" assertion turns red |
  | **(k) `vox update` on a candidate that does not answer, and on one it cannot explain** **(new r5)** | the update journey, in (e)'s place (between `:1163` and `:1165`), new claims `update.stops_a_candidate_that_does_not_answer` and `update.says_what_an_unexplained_candidate_said` | the tree's stable asset is, in turn, arm (g)'s three-line script (`echo starting >&2`, `trap '' TERM; exec sleep 600`) and arm (j)'s script (`echo 'boom: no such table' >&2; exit 3`), each with its own size and digest in the record; the proof waits at most 40 s for each `vox update` and kills it after that; the tree is restored before the journey's own update | hanging script: `vox update` exits non-zero within 40 s; stderr holds `vox update: vox <next> did not answer \`--version\` within 20 seconds and was stopped. Before that it said:`, `  starting`, the *did not answer* sentence and `nothing was changed: <dir>/vox is still vox <current>`; the `sleep 600` process is gone (`runs_as_vox`'s group kill, `:1370-1393`); failing script: exit non-zero, stderr holds `  boom: no such table`, the generic sentence and `nothing was changed`; in both, `vox --version` unchanged and the daemon still running | RED, PRODUCT, KNOWN by C4 on the words (the tag says `release trust check failed: the candidate's version is not the one the record named`); on the bound: the tag's `verify_apple_release` uses `Command::output()` (`:790-794`), unbounded, so the hanging script never returns: RED, KNOWN | raise the bound to 600 s: the proof kills `vox update` at 40 s and the claim is red naming that it had not returned; the generic sentence replaced by the loader-form with an invented version: the "no version named" assertion turns red |

  - *Why*: AGENTS.md "Extend before adding"; every arm is a person's act with the shipped
    installer or binary; the dead candidate, the hanging script, the failing script and the
    incompatible asset are apparatus input to the real product, which AGENTS.md allows ("a
    test-side attacker is apparatus"), and the real asset on the real images is the asset-level
    claim.
  - *What changes*: `install_sh_proof.rs` (the Linux arm gains (c), (d), (g), (j)),
    `update_proof.rs` ((e), (h)), `tests/support/dead_candidate.rs`, ADR-045's J11 and J7 rows and
    `fleet/containers/` (Sibling changes), the suite instructions for the x86_64 placement and
    the two invocations.
  - *Deleted*: nothing. `install.reruns_after_a_cut_short_run` (`:868`) stays: it proves the
    0555 leftover case, which LB-3 keeps.

## Implementation order and related work

1. LB-2 and LB-1 (the asset and the words): the two scripts, `release.yml`, the dry run's
   cutover, the three documents. The first run of the build in the image is the experiment that
   settles "works unchanged"; its log, with the floor line, is the receipt. If it fails, LB-2's
   rule: investigate and record; a higher floor goes back to the coordinator and the decider.
2. LB-3 and LB-4 (one change to `install.sh`'s Linux arm), with arms (c), (d), (g), (j).
3. LB-5 (`update.rs`: the download path's words and verdicts, the rollback's check), with arms
   (e), (h), (k).
4. The x86_64 placement of the in-tree Linux arms in the Linux VM with its two invocations
   (LB-6's first paragraph), and ADR-045 J11 (e), (f), (g) on the fleet's stage 2 with the four
   images; J7's arm (f) in stage 3.

Dependencies on other lanes: ADR-045 (the images, J11, J7, Terms, FG-2, FG-11, FG-17's stages);
ADR-044 RD-12 (its installer step comes after LB-3's step 8); ADR-041 (no change: it has no
installer text; its one-time update RS-2 is the path LB-5 keeps, and the note under LB-5 shows
it always finds a runnable candidate).

## Changes this ADR asks of siblings

Exact words to paste; each sibling's owner applies them. Line numbers are the frozen ADR-045
r18, `ADR-045.1e2bee466.md`.

- **ADR-045 Terms, "Candidate"** (`:297-299`), replace "**Candidate assets**: what
  `scripts/release-dry-run.sh <dir> <linux vox>` builds from it, the Linux argument being the
  real Linux build (FG-2)." with: "**Candidate assets**: what `scripts/release-dry-run.sh <dir>
  <linux dist>` builds from it, the second argument being the `dist/` directory
  `scripts/build-linux-release.sh` wrote from the same commit inside the pinned glibc 2.28 image
  (FG-2; ADR-051 LB-2)."
- **ADR-045 FG-2, the opening** (`:434-438`), replace "the Mac `vox` and app zip that
  `scripts/release-dry-run.sh` builds, and a Linux `vox` built from the candidate commit the way
  `release.yml:86-92` builds it (`cargo build --release --bin vox` then `strip`, in an `ubuntu`
  `linux/amd64` container), given to the dry run as its second argument:
  `scripts/release-dry-run.sh <out> <linux vox>`." with: "the Mac `vox` and app zip that
  `scripts/release-dry-run.sh` builds, and the Linux `dist/` that `scripts/build-linux-release.sh
  <dist>` writes from the candidate commit by running the release's own Linux steps
  (`scripts/linux-release-steps.sh`: build, strip, the glibc-floor precondition, packaging)
  inside the `quay.io/pypa/manylinux_2_28_x86_64` `linux/amd64` container at the digest
  `release.yml` pins, so the fleet's Linux `vox` needs the same glibc the release asset needs;
  that directory is the dry run's required second argument: `scripts/release-dry-run.sh <out>
  <linux dist>` (ADR-051 LB-2). The manifest records the floor line that script printed beside
  the binary's hash." After "the asset itself MUST carry the install, update and passphrase
  claims (J7, J11)" add: "and ADR-051's install arms J11(e), J11(f) and J11(g) on the floor,
  operator, below-floor and non-glibc images". Under *Changes*, replace "the driver refuses
  assets whose Linux binary is a Mach-O file (`CANNOT MEASURE: the Linux asset is the macOS
  stand-in; give release-dry-run.sh the Linux vox as its second argument`). This refusal is an
  apparatus self-check, not a mutant." with: "the dry run has no stand-in mode: it refuses to
  run without the Linux `dist/` (ADR-051 LB-2), so the driver's Mach-O refusal is retired; the
  driver still records the SHA-256 of the Linux `vox` it ran."
- **ADR-045 FG-4**, host B row, append: "ADR-051's in-tree Linux arms (its install and update
  journeys' new claims) compile and run as x86_64 inside an emulated `linux/amd64` container in
  this VM, `vox` as an ordinary user, by the two invocations ADR-051 LB-6 gives (the install
  journey in the debug pass; the ignored update journey in the release pass with
  `VOX_PROOF_NEXT_BINARY`), with the image digest, `uname -m` and each build's wall clock in the
  receipt; run natively on aarch64 they print CANNOT MEASURE."
- **ADR-045 FG-11** (`:862-864`), replace "build the fix's commit into assets
  (`scripts/release-dry-run.sh <out> <linux vox>`)" with: "build the fix's commit into assets
  (`scripts/build-linux-release.sh <dist>` in the Linux VM, then `scripts/release-dry-run.sh
  <out> <dist>` in the guest; ADR-051 LB-2)".
- **ADR-045 J11 row**, Setup, append: "ADR-051's four install images, each `x86_64` under
  emulation and pinned by digest: `almalinux:8` (glibc 2.28, the floor), `ubuntu:22.04` (glibc
  2.35, the operator's Pop!_OS 22.04), `ubuntu:18.04` (glibc 2.27, below the floor),
  `alpine:3.20` (musl, no GNU loader); the manifest records each image's C library as read in
  the run; the installer acts run as an ordinary user, apart from RD-12's kernel arm." Claims,
  append: "(e) F: on `almalinux:8` and on `ubuntu:22.04`, `install.sh` against the candidate
  `dist/` exits 0 and `~/.local/bin/vox --version` prints the candidate's version (ADR-051 LB-1,
  LB-2; the v0.4.30 asset on `ubuntu:22.04` is the red baseline: ``version `GLIBC_2.39' not
  found``); (f) F: on `ubuntu:18.04`, with `getconf` present it exits 1 before any request with
  ADR-051 LB-4 (i)'s line, and with a failing `getconf` shim it exits 1 after the run check with
  LB-4 (ii)'s lines and leaves nothing under `~/.local/bin` (LB-3, LB-4); (g) F: on `alpine:3.20`
  it exits 1 with LB-4's missing-loader sentence naming `/lib64/ld-linux-x86-64.so.2` and leaves
  nothing under `~/.local/bin` (LB-4)." Mutants column, append: "(e) the stand-in server serves
  an incompatible binary (the published v0.4.30 asset) under records written for it; (f) the
  pre-download check skipped, and `2>/dev/null` restored on the run check; (g) the missing-loader
  sentence replaced by the generic one". Items column: add 91.
- **ADR-045 J7 row**, Setup, after "`vox update` candidate → candidate on both" add: "; on B,
  one `vox update` whose candidate is a copy of the release `vox` with one version-need name
  rewritten by `fleet/dead_candidate.py` in the guest (ADR-051 LB-6's dead-candidate apparatus, `GLIBC_9.2.5`), served the way this act
  serves its candidate release; where that source is GitHub only, the act is CANNOT MEASURE, is
  not counted as asset coverage and never appears as a passed claim, and ADR-051's in-tree arm
  (e) is the blocking proof". Claims, append: "(l) F: that update exits non-zero, prints ADR-051
  LB-5's lines, and B's daemon and `vox --version` are unchanged (91)".
- **ADR-045 FG-17**, stage 2's `fleet/containers/` list, add: "the four install images of
  ADR-051 LB-6 by digest, and the emulated x86_64 build container for ADR-051's in-tree Linux
  arms"; stage 3's J7 carries ADR-051's act (l).
- **ADR-044 RD-12**, *What changes*, replace "`install.sh` gains a Linux step after the binary is
  in place." with: "`install.sh` gains a Linux step after the binary is in place, that is, after
  ADR-051 LB-3's run check has accepted the candidate and step 8 has renamed it to `vox`; a
  candidate LB-3 refuses never reaches this step and none of its text is printed for it."
- **ADR-041**: no change.
- **`docs/adr/README.md`**: one index line for ADR-051 (owned by the index's owner).

## Alternatives rejected

- *A separate corrective release before v0.4.31.* Ruled out by the decider (ruling 1).
- *Keep the tag's order and only improve the message.* A person would still be left with a dead
  `vox` and, on a second try, a dead `.vox-previous`; the retained previous exists to be rolled
  back to (`update.rs:1284-1337`), and a dead one defeats it (C6).
- *Check the floor only before downloading, and trust it.* `getconf` can be absent or wrong
  (musl, a stripped container, a `PATH` shim); the loader is the only judge that is never wrong
  about the binary it is asked to load. So (i) is advisory and (ii) decides.
- *A hand-written POSIX-sh watchdog* (revision 2). It leaked its sleeper, could not reap what it
  killed, and inferred expiry from empty output; coreutils `timeout` is on every floor system,
  reaps, and reports expiry in its status (r3).
- *Remove a dead `.vox-previous` in the rollback or on a first install.* The rollback's job is
  to put a binary back, not to delete files; a first install that deletes a retained file it did
  not write is a surprise. The dead file is named, harmless (nothing runs it after LB-5), listed
  by `vox uninstall`, and replaced by the next update's copy of the running `vox`.
- *Put the floor in the release record, or publish it as an asset* (revision 2's
  `.glibc-floor`). `ReleaseRecord` is `deny_unknown_fields` (`update.rs:102-106`); and nothing
  installed reads a floor file, so a new asset is release-format surface for nobody. The
  measurement lives in the build log and the fleet manifest (r3).
- *Measure the floor in `package-release.sh`, or in a one-purpose script.* `package-release.sh`
  runs on the macOS runner and in the guest's dry run (`release-dry-run.sh:115-124`), where
  there is no `readelf`; and five lines do not need their own file. The measurement is part of
  the shared Linux steps (r3).
- *Keep a dry run without a Linux dist (the Mach-O stand-in).* It could only produce an asset
  set the fleet refuses; one required argument is simpler (r3).
- *Let `vox --version` print the floor it was built for.* The information is in the asset's
  version-need table already; a person never needs to ask the binary, because the installer
  tells them.
- *A static musl asset, `cargo zigbuild`, `runs-on: ubuntu-22.04`.* LB-2's table.
- *Drop the `pidfd` path in Rust std by a flag.* There is no stable flag; the weak references are
  harmless on a 2.28 link (C5, INFERRED, measured at the first build).
- *Cross-compile the x86_64 test binaries from the aarch64 VM.* An x86_64 C cross toolchain for
  `aws-lc-sys` and `ring`: a second toolchain again. Emulation is what the fleet already uses for
  the asset.

## Unchanged rulings

- `install.sh` stays POSIX `sh` and GitHub-only (`install.sh:16-18`), and nothing needs `sudo`
  (`README.md:57`); ADR-015. `timeout` is the one coreutils command it newly calls, probed
  first and done without where absent.
- The macOS arm of the installer and `vox update`'s Apple checks and bundle rollback are
  untouched (ADR-014 M-26a, M-28).
- No aarch64 Linux release (`install.sh:81`); this ADR adds no target.
- CI compiles and lints only; the gates and the fleet run on the candidate assets in the VMs
  (ADR-045 FG-1, FG-3; ADR-018 as amended there).
- No `VOX_TEST_*` knob in the shipped binary; `VOX_RELEASE_BASE` is the installer's documented
  test hook (`install.sh:29-31`), as before.
- `vox update`'s durable publish and the interrupted-rollback recovery (`update.rs:875-896`,
  `:1295-1313`; V210-56, #242) are unchanged. The release's asset set is the tag's
  (`check-release-assets.sh:32-46`).

## Consequences

### Positive

- A person on any x86_64 Linux from Ubuntu 20.04, Debian 10 or RHEL 8 on can install Vox; the
  manual says so; the release cannot produce an asset that contradicts it.
- The installer never installs what cannot run, never waits for ever on it, and says why in the
  loader's words and one sentence of its own; a rollback never puts back a binary that cannot
  run.
- The floor stops moving with GitHub's runner labels.

### Negative

- The build job runs in a container: a `rustup` step and, until the cache warms, a longer first
  build. The first build in the image is unobserved until it runs.
- The in-tree Linux arms are compiled under emulation in the Linux VM, twice (the journeys and
  the `9.x` fixture); the cost is unmeasured and is recorded at the first run. Four more
  container images in the fleet, under emulation; about one minute per install act (INFERRED
  from ADR-045's 1.7 s per emulated CLI call and the installer's dozen calls).
- The dry run needs a Linux dist built first; there is no quick macOS-only dry run any more.

### Neutral

- Symbols that bound to `GLIBC_2.34`, `2.33` and `2.32` versions bind to their older forms, and
  `libpthread.so.0`/`libdl.so.2` join `NEEDED`: the ordinary shape of a binary built on an older
  glibc (INFERRED; measured at the first build).
- `pow` binds to `pow@GLIBC_2.2.5` rather than `@2.29`; a different implementation of the same
  function (INFERRED).
- On a system without GNU `timeout` the installer's check is unbounded, as the tag's always was,
  and says so.

## Review record

### First review (`adr-051-sol-review-1.md`, revision 1 frozen at 5b6d3064a)

Verdict "needs revision"; the floor "sound", the build method "reasonable". Each finding, its
retrace at v0.4.30, and the text that answered it in revision 2 (as it now stands in revision 3):

| # | Finding | Retrace | Answer |
|---|---|---|---|
| 1 (P1) | The packaging gate assumed `readelf` and a cwd-relative floor; the dry run calls `package-release.sh` in the macOS guest from a scratch directory holding only `Cargo.toml` | CONFIRMED: `release-dry-run.sh:41` (macOS only), `:115-116` (`cd "$out/repo"`, `cp Cargo.toml`), `:117-124` (the three package calls) | LB-2: the measurement lives in the Linux steps run inside the image; the floor resolved from the script's location; the dry run takes the image-built `dist/` (required since r3) |
| 2 (P1) | The apparatus rewrote `GLIBC_2.34`, which the floor-built asset must not need | CONFIRMED by LB-2's own rule | LB-6 "The dead candidate": parse `.gnu.version_r`, take the most-referenced non-weak `libc.so.6` entry, one transformation (r3: `GLIBC_9.2.5`); staging must show the source runs and the copy fails with that diagnostic, else APPARATUS |
| 3 (P1) | The update proof's mutant (verifier returns `Ok`) cannot publish the dead copy: the candidate is the engine | CONFIRMED: `update.rs:1057-1061`; `publish` only inside it (`:1222`) | (e) is one claim mutated on the words; preservation is its context; the mutated preservation claim is (h); C4 notes the engine fact |
| 4 (P1) | Standalone rollback renames `.vox-previous` over `vox` after checking only existence | CONFIRMED: `update.rs:1314-1319`, `:1323-1324`; the interrupted branch does run its scratch (`:1296`) | C6; LB-5's rollback run check before `copy_durably`, its words; arm (h) |
| 5 (P1) | No executable architecture named for the in-tree Linux arms | CONFIRMED: `install.sh:79-82`, `install_sh_proof.rs:104-113`, `update.rs:230-242`; the E9a receipt | LB-6's first paragraph: emulated x86_64 container, non-root `vox`, CANNOT MEASURE natively; FG-4's paste |
| 6 (P2) | Arm (d) required a record request although (i) sits before it | CONFIRMED (`run_installer_env` writes files first, `install_sh_proof.rs:302-305`; (i) before `:88`) | (d): zero requests; installer-owned paths against a snapshot; (b): a failing `getconf` shim |
| 7 (P2) | The fallback ladder changed the floor silently | CONFIRMED | LB-2 "If the first build in the image fails" |
| 8 (P2) | `timeout 20` sends TERM and may be absent; other probes unbounded | CONFIRMED | r2's hand-written watchdog, replaced in r3 by coreutils `timeout --kill-after` (second review, findings 3 and 4) |
| 9 (P2) | No explanation for musl or a missing interpreter; the no-write promise overstated | CONFIRMED | LB-4 (ii)'s cause-sentence rule; the promise qualified; LB-1's words; proofs (i) and (j) in r3 |
| 10 (P2) | The ELF scan counted as a proof | CONFIRMED | Terms "the floor precondition"; LB-2 "What the precondition is, and is not" |
| 11 (P2) | C5's older bindings wrong; the symbol map unconfirmed | CONFIRMED (glibc 2.28 `libio/stdio.h`, `libc.abilist`, `io/fstatat64.c`) | C5 corrected; every binding INFERRED; the receipt recorded in the evidence folder |
| scheduling | J7 is stage 3 | CONFIRMED: ADR-045 FG-17 | Implementation order 4 |
| prose | "no Vox release has ever run on older Linux" not established | CONFIRMED | C1 limited to the measured asset |
| Q1 | The floor is answered (ledger row 77) | — | "The decider's answers"; ruling 2 |

### Second review (`adr-051-sol-review-2.md`, revision 2 frozen at c6f70f421)

Verdict "needs revision"; the floor "remains sound", the method "still boring and standard";
first-review findings 3, 4, 6, 7, 10 closed, 1, 2, 5, 8, 9, 11 partly. Each new finding, its
retrace, and the revision-3 text:

| # | Finding | Retrace | Answer |
|---|---|---|---|
| 1 (P1) | LB-4 matched only two-component names, so `GLIBC_9.9.5` fell to the generic branch; line 609's "every digit to 9" contradicted `9.9.5` | CONFIRMED (revision 2's own text) | Terms "a version name" (any count of components, numeric comparison, zero-padded); LB-4 (ii) rule 1 uses it and shows the name as written; one transformation, first component → 9, output `GLIBC_9.2.5`, quoted in (c), (e), (h) and J7's paste |
| 2 (P1) | The documented `cargo test` did not select the ignored update journey; `vox_saying` needs a compiled next-version fixture | CONFIRMED: `update_proof.rs:936-938` (`#[ignore]`), `:850-864` (`VOX_PROOF_NEXT_BINARY`); `release-gate.sh:56`, `:65-66` (the two passes) | LB-6's first paragraph: the two invocations, the fixture's build, "compiling is not executing", both claim lists in the receipt; FG-4's paste |
| 3 (P1) | The sh watchdog leaked its sleeper and could not guarantee the fixture's child was gone | CONFIRMED (the design) | LB-3: coreutils `timeout --kill-after=2 20`, present on every floor system (cited), probed before download, unbounded with one sentence where absent; arm (g)'s fixture is one process (`trap '' TERM; exec sleep 600`) and the arm asserts it is gone; the cut of the watchdog |
| 4 (P2) | *did not answer* inferred from 137 + empty stderr | CONFIRMED | Terms: four verdicts from `timeout`'s own status (124/137 expiry, 126/127 could not start); (g) writes `starting` before it hangs and asserts the timeout explanation with that output; `vox update` derives the same verdicts from its own recorded expiry |
| 5 (P2) | Arm (a)'s mutant (no container) could not produce assets past the precondition | CONFIRMED by LB-2 | (a)'s mutant: the stand-in server serves an incompatible binary (the published v0.4.30 asset, or an outside-the-container build) under records written for it; no precondition, no knob; staging checked first |
| 6 (P2) | The retained no-Linux dry run failed the enlarged asset set; FG-11 (`:864`) and the candidate definition (`:298-299`) still passed a Linux file | CONFIRMED: `release-dry-run.sh:140-156` (the asset check runs before success), frozen ADR-045 `:297-299`, `:862-864` | The `.glibc-floor` asset cut (the set is the tag's); the stand-in mode deleted, `LINUX_DIST` required; pastes for Terms, FG-2's opening and *Changes*, FG-11 |
| 7 (P2) | No act exercised the missing-loader or generic form | CONFIRMED: `install_sh_proof.rs:729-778` refuse before any candidate runs | Arms (i) (J11 act (g), `alpine:3.20`) and (j) (the install journey, a failing script), each with a wording mutant; the missing-loader sentence says only that the path is absent |
| 8 (P2) | `pthread_setname_np` binds at `GLIBC_2.12`, not 2.2.5 | CONFIRMED: `elf-version-needs.txt:37`; glibc 2.28 `x86_64/64/libpthread.abilist` | C5's 2.34 row states the exception; the column stays INFERRED |
| cuts | the published floor asset, the stand-in mode, the one-purpose script | — | all three taken (LB-2; Alternatives); the measurement is five lines of `linux-release-steps.sh` |
| (h) placement | before the journey's daemon cleanup | CONFIRMED: `update_proof.rs:1223-1227` | (h)'s "Extends" column |

### Third review (`adr-051-sol-review-3.md`, revision 3)

Verdict "needs revision", one finding; everything else closed ("I would not add another
mechanism").

| # | Finding | Retrace | Answer |
|---|---|---|---|
| 1 (P1) | LB-6 told the implementer to build the update journey's fixture at the workspace version "raised one patch"; the journey expects the version with its first character replaced by `9` and `vox_saying` refuses any other, so a 0.4.32 fixture fails as APPARATUS before the update and rollback acts | CONFIRMED: `update_proof.rs:961-963` (`std::iter::once('9').chain(VERSION.chars().skip(1))`), `:850-864` (the refusal) | LB-6's first paragraph (r4): the fixture is compiled as the journey's convention, `9.4.31` for v0.4.31; the Requirements preamble says the same; the FG-4 paste names no version and needs no change |

### Task cut (`v0431-tasks-ADR-051.md`, revision 4 frozen at dbbde83d8)

Revision 4 passed the fourth re-check (`adr-051-sol-review-4.md`); cutting it into
twenty tasks found nine defects, answered in revision 5 and nothing else:

| # | Defect | Retrace | Answer (r5) |
|---|---|---|---|
| 1 | `fleet-exp/receipts/E9a/` does not exist | CONFIRMED: the folder holds `E9a-attempt1-APPARATUS` … `E9a-attempt6-MEASURED` | LB-6 and Links cite `E9a-attempt6-MEASURED/` |
| 2 | LB-3's command passed the installer's whole environment; Terms allows four variables | CONFIRMED (revision 4's text) | LB-3: the run uses Terms' environment, `env -i` with the four |
| 3 | No expected version for the existing `vox` or the retained previous | CONFIRMED (revision 4's text) | Terms: where no version is expected, any `vox <x>` with exit 0 is *ran*; LB-4 part 4 and LB-5's rollback say so |
| 4 | Arm (e) had no place in the update journey; "no `.vox-previous` created" holds only before the journey's own update | CONFIRMED: the journey's update is `update_proof.rs:1165`, after `daemon.version_mismatch_refused` (`:1155-1163`); the release tree is `tree.path()` (`:989`) | (e) placed between `:1163` and `:1165`, the tree's stable asset swapped for the act and restored |
| 5 | The fleet had no named way to make J7's dead copy; the helper is a Rust test module | CONFIRMED | LB-6 "The dead candidate": `fleet/dead_candidate.py`, the same parse-and-rewrite in standard-library Python derived from the evidence folder's `elf-version-needs.py`, run in the guest; the J7 paste names it; (f) stays CANNOT MEASURE where J7 cannot serve a stand-in release |
| 6 | ADR-045 FG-5 cited for an allowance it does not state | CONFIRMED: FG-5 r18 `:637-639` is about claims the fleet cannot stage without a knob | The citation dropped from (f) |
| 7 | `loader_present` is always true inside `vox update` | CONFIRMED: `vox update` is a running glibc `vox`, started by that loader | The parameter dropped; in `vox update` *could not start* takes the generic sentence with the OS error quoted in part 2 |
| 8 | No arm proved `vox update`'s did-not-answer wording, generic wording or 20 s bound | CONFIRMED | New act (k), extending (e)'s place in the update journey with the hanging and the failing scripts, each with a mutant |
| 9 | `release-dry-run.sh:156` is the general stand-in line, which stays; the Linux echo is `:157` | CONFIRMED: `:156` "STAND-INS: ad-hoc signatures…", `:157` `[[ -n "$linux_vox" ]] \|\| echo … is the macOS vox` | LB-2's three citations read `:157` |
| — | Arm (b)'s ``GLIBC_2.28' not found`` is INFERRED until measured | `elf-version-needs.txt:32` (`statx [weak]` at `GLIBC_2.28`) | (b) says so, naming experiment -01 |

## The decider's answers (2026-11-13)

- **Q1 (LB-1, LB-2): which Linux machines can install Vox.** Answered: **any x86_64 Linux from
  Ubuntu 20.04, Debian 10 or RHEL 8 on** (glibc 2.28); ledger row 77, within the decider's
  answers: he was told this floor in plain words at 15:20 PST when the defect was reported, raised
  no objection, and ruled the fix into v0.4.31 (row 73). The alternatives put to him for the
  record: (b) only machines from 2022 on (glibc 2.35; excludes RHEL 9, Alma 9, Amazon Linux 2023,
  Ubuntu 20.04, Debian 11; the runner that gives it retires in April 2027); (c) every Linux,
  Alpine included, by a static binary (a new platform; rejected in LB-2). The answer reopens only
  under LB-2's "If the first build in the image fails".

## Links

- Fix-list item 91; the evidence folder under `/opt/vox-evidence/v0431/` (`README.md`,
  `install.sh.live`, `vox-x86_64-unknown-linux-gnu.sha256`, `elf-version-needs.txt`,
  `elf-version-needs.py`); `adr-051-revision.md` (what was read, the method evidence,
  every INFERRED line, the open points); `adr-051-sol-review-1.md`,
  `adr-051-sol-review-2.md`; `adr-cross-changes.md` rows 69, 73, 77.
- The fleet receipt `/opt/vox-evidence/v0431/fleet-exp/receipts/E9a-attempt6-MEASURED/` (the x86_64 asset under
  emulation in the Linux VM).
- The published v0.4.30 Linux asset and its records
  (`https://github.com/robertelee78/vox/releases/download/v0.4.30/…`): read on this Mac, SHA-256
  as above.
- [ADR-014](ADR-014-macos-client.md) (the macOS floor, M-26a),
  [ADR-015](ADR-015-rust-tui-client.md) (install and update),
  [ADR-018](ADR-018-quality-bar-and-product-proof.md); in this release
  [ADR-041](ADR-041-a-restart-needs-no-human.md),
  [ADR-044](ADR-044-the-daemon-stays-responsive-under-agent-load.md) (RD-12),
  [ADR-045](ADR-045-the-fleet-release-gate.md) (Terms, J7, J11, FG-2, FG-4, FG-11, FG-17).
- GitHub changelog, "Ubuntu 26 generally available and latest migration", 2026-09-17
  (`ubuntu-latest` moves from 24.04 to 26.04 between 2026-10-19 and 2026-11-19);
  actions/runner-images#14254 (`ubuntu-22.04` retired 2027-04-17); actions/checkout#1590 (Node
  20 needs glibc 2.28 inside a container).
- pypa/manylinux (`quay.io/pypa/manylinux_2_28_x86_64`: AlmaLinux 8, glibc 2.28, GCC 14).
- GNU coreutils `timeout(1)`: the Debian buster page (coreutils 8.30, February 2019: `-k,
  --kill-after`, exit 124, 128+9) and the Ubuntu focal page (coreutils 8.30-3ubuntu2); the GNU
  manual, "timeout invocation" (exit 124, 125, 126, 127, 137).
- drasi-project/drasi-core#601 (`pidfd_spawnp`/`pidfd_getpid` weak references make a Rust binary
  need `GLIBC_2.39`); rust-lang/rust#121012.
- aws/aws-lc-rs#993 (zig support arrived in aws-lc-rs 1.17.0; the zig 0.16 `ar` regression).
- Rust blog, "Increasing the glibc and Linux kernel requirements", 2022-08-01 (glibc 2.17 floor
  for the toolchain).
- glibc 2.28: `elf/dl-version.c` (the loader matches a version need by hash and name),
  `libio/stdio.h` (the `__isoc99_sscanf` redirection), `io/fstatat64.c`,
  `sysdeps/unix/sysv/linux/x86_64/64/libc.abilist` and `libpthread.abilist`
  (`pthread_setname_np@GLIBC_2.12`).
