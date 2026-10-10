//! **A room admits whoever holds the passphrase, and each author decides who may read them** —
//! proved with nothing but the shipped `vox`: a `vox node` anchor and three `vox daemon`s, every
//! step typed as an operator would.
//!
//! This replaces `node_m14_gate`, which proved the same claims with in-process nodes (V29-17:
//! a test counts only if it drives the shipped product). Its claims, now through real binaries:
//!
//! 1. **A wrong passphrase is refused**, and the refusal says so — Carol's first join, with the
//!    wrong passphrase, fails while the room's creator is up to check it.
//! 2. **The right passphrase joins**, through the anchor, in another process.
//! 3. **Two members who trust each other read each other, both ways.**
//! 4. **A member nobody consented to reads nothing of theirs** — Carol, joined and synced, never
//!    renders what Alice said, because Alice never trusted her.
//! 5. **A message's tags make a thread, and only its readers see them** (#636). Alice and Bob tag
//!    posts with `--task`, `--project`; Bob's `vox room read --tag` shows exactly the messages
//!    carrying every tag named, `--from` only one member's of them, `--json` carries each row's
//!    tags and the plain read says them. Carol, whom Alice never trusted, finds none of Alice's
//!    tags: `--tag` on a tag only Alice used shows nothing, and her whole `--json` read never
//!    names it, while Bob's tagged message, which she may read, is in her thread.
//!
//! **Mutants for claim 5**, each red on its own assertion: the node's `Tagged` answer ignoring the
//! tags (Bob's thread holds his untagged posts); ignoring `--from` (Alice's thread holds Bob's);
//! and Alice's node sealing for a member she does not trust, as a tag carried outside what she
//! seals would be read (Carol's thread holds Alice's tag).
//!
//! **Claim 4 carries a positive control, or it would prove nothing.** An absence passes just as
//! well when Carol's node never synced at all. So Bob *does* trust Carol, and she must render
//! Bob's message: that proves her node is receiving the room, and only then does Alice's
//! message staying absent mean the refusal works rather than the plumbing failing.
//!
//! No escape hatch: every join here must succeed. A failed join is a failed proof, not an
//! "unproven" pass.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/attach.rs"]
mod attach;

#[path = "support/typed.rs"]
mod typed;

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};

const VOX: &str = env!("CARGO_BIN_EXE_vox");

/// A long-running `vox` child, killed however the test ends.
struct Proc {
    name: &'static str,
    child: Child,
    out: Option<BufReader<ChildStdout>>,
    /// Everything the child wrote to stderr, drained continuously — see `spawn`.
    err: Arc<Mutex<String>>,
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Proc {
    fn spawn(
        name: &'static str,
        dir: &std::path::Path,
        args: &[String],
        stdin: Option<&str>,
    ) -> Self {
        let mut cmd = Command::new(VOX);
        cmd.args(args)
            .env("VOX_DATA_DIR", dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .env_remove("VOX_ROOM")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn {name}: {e}"));
        if let Some(text) = stdin {
            child
                .stdin
                .as_mut()
                .expect("APPARATUS: no stdin pipe")
                .write_all(text.as_bytes())
                .unwrap_or_else(|e| panic!("APPARATUS: cannot write {name}'s stdin: {e}"));
            drop(child.stdin.take());
        }
        let out = child.stdout.take().map(BufReader::new);
        // **stderr is piped, so it must be read.** It was piped and never read, which is a
        // 64 KiB fuse on the child: once the pipe buffer fills, the daemon blocks in `write` and
        // the proof sees a node that has stopped doing anything, with no failure and no output —
        // a hang, and bimodal in exactly the shape ADR-018 recorded for this gate's own flake.
        // `vox daemon` now reports every event that explains a failure, so it writes more than it
        // used to and this fuse got shorter, not longer. Drained on a thread into a string the
        // panic below prints, so the bytes that were the hazard become the diagnosis.
        let err = Arc::new(Mutex::new(String::new()));
        if let Some(mut pipe) = child.stderr.take() {
            let sink = Arc::clone(&err);
            std::thread::spawn(move || {
                let mut buf = String::new();
                let _ = pipe.read_to_string(&mut buf);
                if let Ok(mut guard) = sink.lock() {
                    guard.push_str(&buf);
                }
            });
        }
        Self {
            name,
            child,
            out,
            err,
        }
    }

    /// Wait for a line matching `want`, so readiness is observed rather than slept on.
    fn expect_line(&mut self, what: &str, want: impl Fn(&str) -> bool) -> String {
        let reader = self.out.as_mut().expect("APPARATUS: no stdout pipe");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        let mut seen = Vec::new();
        while std::time::Instant::now() < deadline {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let l = line.trim_end().to_owned();
                    if want(&l) {
                        return l;
                    }
                    seen.push(l);
                }
                Err(_) => break,
            }
        }
        let err = self
            .err
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|e| e.into_inner().clone());
        panic!(
            "PRODUCT (staging): {} never printed {what}; saw: {seen:#?}\nits stderr:\n{err}",
            self.name
        );
    }
}

/// One `vox` command, run to completion.
/// A verb as a person runs it since ADR-026 L-2: one that needs its node attached, run while no
/// daemon holds the data root, runs with the node attached by `vox node attach` and let go after.
fn vox(dir: &std::path::Path, args: &[String], stdin: Option<&str>) -> (bool, String, String) {
    let verb: Vec<&str> = args.iter().map(String::as_str).collect();
    match attach::needs(dir, &verb) {
        Some(node) => attach::Root::at(dir, "an identity passphrase")
            .attached(&node, || vox_plain(dir, args, stdin)),
        None => vox_plain(dir, args, stdin),
    }
}

fn vox_plain(
    dir: &std::path::Path,
    args: &[String],
    stdin: Option<&str>,
) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        // Not `--identity-passphrase`: a command line is world-readable while the process
        // runs, so the flag is refused (ADR-015).
        .env("VOX_IDENTITY_PASSPHRASE", "an identity passphrase")
        .env_remove("VOX_ROOM")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028 K-13).
    if typed::is_keyring_change(args) {
        let (ok, shown) = typed::keyring(&cmd);
        return (ok, shown.clone(), shown);
    }
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn vox: {e}"));
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("APPARATUS: no stdin pipe")
            .write_all(text.as_bytes())
            .unwrap_or_else(|e| panic!("APPARATUS: cannot write vox's stdin: {e}"));
        drop(child.stdin.take());
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot wait for vox: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Poll a command until its stdout satisfies `ok`.
fn until(
    dir: &std::path::Path,
    what: &str,
    args: &[String],
    secs: u64,
    ok: impl Fn(&str) -> bool,
) -> Result<String, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let (_, out, err) = vox(dir, args, None);
        last = format!("stdout={out:?} stderr={err:?}");
        if ok(&out) {
            return Ok(out);
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(format!("timed out waiting for {what}; last saw {last}"))
}

const IDPASS: &str = "an identity passphrase\n";
const ROOMPASS: &str = "the room passphrase";

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_owned()).collect()
}

#[test]
#[ignore = "four real vox processes, a real anchor and production Argon2id; CI runs it in release"]
fn a_room_admits_the_passphrase_and_each_author_decides_who_reads_them() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: cannot make a profile directory");
        d
    };
    let (anchor_dir, alice, bob, carol) = (dir("anchor"), dir("alice"), dir("bob"), dir("carol"));

    let mut anchor = Proc::spawn(
        "anchor",
        &anchor_dir,
        &s(&["node", "--listen", "127.0.0.1:0"]),
        None,
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains('@')
                && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
        })
        .trim()
        .to_owned();

    // ---- identities, headless ----
    let fp = |d: &std::path::Path| {
        let (ok, out, err) = vox(d, &s(&["id"]), None);
        assert!(ok, "PRODUCT (staging): vox id failed: {err}");
        out.trim().to_owned()
    };
    let (alice_fp, bob_fp, carol_fp) = (fp(&alice), fp(&bob), fp(&carol));

    // ---- the decisions, made before any daemon holds a profile ----
    // Alice and Bob trust each other. Bob trusts Carol. Alice does NOT trust Carol.
    for (d, who, name) in [
        (&alice, &bob_fp, "bob"),
        (&bob, &alice_fp, "alice"),
        (&bob, &carol_fp, "carol"),
        (&carol, &bob_fp, "bob"),
        (&carol, &alice_fp, "alice"),
    ] {
        let (ok, _, err) = vox(d, &s(&["trust", "add", who, "--name", name]), None);
        assert!(ok, "PRODUCT (staging): vox trust add {name} failed: {err}");
    }

    let mut daemons = Vec::new();
    for (name, d) in [("alice", &alice), ("bob", &bob), ("carol", &carol)] {
        let mut p = Proc::spawn(
            name,
            d,
            &s(&["daemon", "--listen", "127.0.0.1:0", "--anchor", &spec]),
            Some(IDPASS),
        );
        p.expect_line("its control socket", |l| l.contains("control socket"));
        daemons.push(p);
    }

    // ---- Alice makes the room and its address ----
    let (ok, _, err) = vox(
        &alice,
        &s(&[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "mission",
        ]),
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): room create failed: {err}");
    let listed = until(&alice, "the room", &s(&["room", "list"]), 30, |o| {
        o.contains("mission")
    })
    .unwrap_or_else(|e| panic!("PRODUCT (staging): alice's room never listed: {e}"));
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| panic!("PRODUCT (staging): no room id in `vox room list`: {listed:?}"))
        .to_owned();
    let (ok, link, err) = vox(&alice, &s(&["room", "link", &room]), None);
    assert!(ok, "PRODUCT (staging): room link failed: {err}");
    let link = link.trim().to_owned();

    // ---- claim 1: a wrong passphrase is refused, and the refusal names the passphrase ----
    let (ok, out, err) = vox(
        &carol,
        &s(&["room", "join", "--passphrase-file", "-", &link]),
        Some("not the passphrase\n"),
    );
    assert!(
        !ok,
        "PRODUCT: a wrong passphrase joined: stdout={out:?} stderr={err:?}"
    );
    assert!(
        err.to_lowercase().contains("passphrase"),
        "PRODUCT: the refusal must say the passphrase is the likely problem, since the creator is up to check it: {err:?}"
    );

    // ---- claim 2: the right passphrase joins, through the anchor ----
    for (name, d) in [("bob", &bob), ("carol", &carol)] {
        let (ok, out, err) = vox(
            d,
            &s(&["room", "join", "--passphrase-file", "-", &link]),
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(
            ok,
            "PRODUCT: {name} could not join with the right passphrase: stdout={out:?} stderr={err:?}"
        );
    }

    // ---- claim 3: two members who trust each other read each other, both ways ----
    let post = |d: &std::path::Path, text: &str| {
        let (ok, _, err) = vox(d, &s(&["room", "post", &room, text]), None);
        assert!(ok, "PRODUCT: vox room post {text} failed: {err}");
    };
    post(&alice, "FROM-ALICE");
    post(&bob, "FROM-BOB");
    let read = s(&["room", "read", &room]);
    until(&bob, "bob to read alice", &read, 90, |o| {
        o.contains("FROM-ALICE")
    })
    .unwrap_or_else(|e| panic!("PRODUCT: claim 3: bob never read alice: {e}"));
    until(&alice, "alice to read bob", &read, 90, |o| {
        o.contains("FROM-BOB")
    })
    .unwrap_or_else(|e| panic!("PRODUCT: claim 3: alice never read bob: {e}"));

    // ---- claim 4, positive control first: Carol receives the member who trusts her ----
    //
    // A sender key is forward-only: Bob's key reaches Carol at some point after she joins, and
    // only what Bob writes after that is readable to her, by design. So the control is not "Carol
    // reads FROM-BOB" (posted before the release, it may never render) but "Carol reads *a* Bob
    // post made after the release": Bob keeps posting until one arrives.
    let control_deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let mut n = 0;
    loop {
        n += 1;
        post(&bob, &format!("FROM-BOB-LATE-{n}"));
        if until(&carol, "carol to read a late bob post", &read, 5, |o| {
            o.contains("FROM-BOB-LATE-")
        })
        .is_ok()
        {
            break;
        }
        assert!(
            std::time::Instant::now() < control_deadline,
            "PRODUCT: claim 4's control failed: in 120s Carol never rendered any post from Bob, who trusts \
             her, so an absence of Alice below would prove nothing"
        );
    }
    // ...and only now does Alice's absence mean something. She posts *after* Carol is provably
    // receiving keys, then Bob posts once more: once Carol renders Bob's last post she has synced
    // past Alice's, so Alice's absence is her decision and not an unsynced log.
    //
    // Claim 5 rides on these: each is tagged as an agent tags its work (#636), and Bob adds one
    // tagged with another task, so a filter that ignored the tag would show it.
    let tagged = |d: &std::path::Path, text: &str, tags: &[&str]| {
        let mut args = s(&["room", "post", &room]);
        args.extend(s(tags));
        args.push(text.to_owned());
        let (ok, _, err) = vox(d, &args, None);
        assert!(ok, "PRODUCT: vox room post {tags:?} {text} failed: {err}");
    };
    tagged(
        &alice,
        "FROM-ALICE-LATE",
        &["--task", "#636", "--project", "vox-tags"],
    );
    tagged(&bob, "FROM-BOB-OTHER", &["--task", "#999"]);
    tagged(&bob, "FROM-BOB-FINAL", &["--task", "#636"]);
    let carol_view = until(&carol, "carol to read bob's final post", &read, 90, |o| {
        o.contains("FROM-BOB-FINAL")
    })
    .unwrap_or_else(|e| panic!("PRODUCT: claim 4's control failed after it had passed once: {e}"));

    // ---- claim 5: tags make a thread, by tag and by tag and sender ----
    until(&bob, "bob to read alice's tagged post", &read, 90, |o| {
        o.contains("FROM-ALICE-LATE") && o.contains("FROM-BOB-FINAL")
    })
    .unwrap_or_else(|e| panic!("PRODUCT (staging): bob never read both tagged posts: {e}"));
    // The `FROM-…` markers a read shows, in its order.
    let markers = |out: &str| -> Vec<String> {
        out.split_whitespace()
            .filter(|w| w.starts_with("FROM-"))
            .map(str::to_owned)
            .collect()
    };
    let read_tag = |d: &std::path::Path, extra: &[&str]| {
        let mut args = s(&["room", "read", &room]);
        args.extend(s(extra));
        let (ok, out, err) = vox(d, &args, None);
        assert!(
            ok,
            "PRODUCT: claim 5: vox room read {extra:?} failed: {err}"
        );
        out
    };
    for (extra, want) in [
        (
            &["--tag", "task:#636"][..],
            &["FROM-ALICE-LATE", "FROM-BOB-FINAL"][..],
        ),
        (
            &["--tag", "task:#636", "--from", "alice"],
            &["FROM-ALICE-LATE"],
        ),
        (
            &["--tag", "task:#636", "--from", "you"],
            &["FROM-BOB-FINAL"],
        ),
        (
            &["--tag", "task:#636", "--tag", "project:vox-tags"],
            &["FROM-ALICE-LATE"],
        ),
        (&["--tag", "task:#999"], &["FROM-BOB-OTHER"]),
    ] {
        let out = read_tag(&bob, extra);
        assert_eq!(
            markers(&out),
            want,
            "PRODUCT: claim 5: bob's `vox room read {extra:?}` showed other messages than those \
             tagged so: {out:?}"
        );
    }
    let out = read_tag(&bob, &["--tag", "task:#636", "--from", "alice"]);
    assert!(
        out.contains("tags: project:vox-tags task:#636"),
        "PRODUCT: claim 5: bob's read does not say the tags alice gave her message: {out:?}"
    );
    let out = read_tag(&bob, &["--tag", "task:#636", "--json"]);
    let rows: Vec<serde_json::Value> = out
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("PRODUCT: bad row ({e}): {l}")))
        .collect();
    assert!(
        rows.len() == 2
            && rows.iter().all(|r| r["tags"]
                .as_array()
                .is_some_and(|t| t.iter().any(|t| t == "task:#636"))),
        "PRODUCT: claim 5: `--json --tag task:#636` rows do not each carry the tag: {out:?}"
    );
    // ...and Carol, whom Alice never trusted, holds none of Alice's tags, while the tagged message
    // of Bob's, which she may read, is in her thread: the control that her index is built. Watched
    // as long as claim 4 watches her, and before it each time: a key released late is a tag read
    // late.
    let carol_holds_no_tag_of_alice = || {
        let out = read_tag(&carol, &["--tag", "task:#636"]);
        assert_eq!(
            markers(&out),
            ["FROM-BOB-FINAL"],
            "PRODUCT: claim 5: carol's thread of task:#636 is not bob's message alone: {out:?}"
        );
        let out = read_tag(&carol, &["--tag", "project:vox-tags"]);
        assert!(
            markers(&out).is_empty(),
            "PRODUCT: claim 5: carol found alice's tag, though alice never trusted her: {out:?}"
        );
        let out = read_tag(&carol, &["--json"]);
        assert!(
            !out.contains("vox-tags"),
            "PRODUCT: claim 5: carol's read names alice's tag, though alice never trusted her: \
             {out:?}"
        );
    };
    carol_holds_no_tag_of_alice();
    assert!(
        !carol_view.contains("FROM-ALICE"),
        "PRODUCT: claim 4: Carol rendered Alice, who never trusted her: {carol_view:?}"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        carol_holds_no_tag_of_alice();
        let (_, out, _) = vox(&carol, &read, None);
        assert!(
            !out.contains("FROM-ALICE"),
            "PRODUCT: claim 4: Carol rendered Alice, who never trusted her: {out:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    drop(daemons);
    drop(anchor);
}
