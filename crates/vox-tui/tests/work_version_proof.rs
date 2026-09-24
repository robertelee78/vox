//! ADR-021 M21.1 — **workers must run the same Vox version, enforced**, through the
//! shipped `vox` binary and a **published older release** in one room.
//!
//! Mixed-version coordination is not supported: the operator upgrades every worker
//! together. What must therefore be proved is not compatibility but **refusal** — a
//! worker that would coordinate with another version stops, before it posts anything
//! that participates, and says exactly who and what:
//!
//! 1. **missing** — the real published `vox` v0.2.6, attached to a current node, posts
//!    a claim with no version stamp, because it predates ADR-021. A current worker that
//!    has **never posted in the room** then has its first `claim` refused with exit 3,
//!    naming that worker, "no version", and the required version — and the claim is
//!    never posted;
//! 2. **unknown** and **different** — a stamp that is not a version (`banana`) and one
//!    that is another version (`0.2.9`) are each refused and named;
//! 3. `post --work` is refused the same way, `board --json` says `refused` with the
//!    table, and the drain hook tells the session plainly;
//! 4. **plain conversation survives** a refusal, so the operator can still talk;
//! 5. **recovery needs nobody**: once the stale worker runs the current binary, its
//!    first participating verb announces the current version, and coordination
//!    resumes for everyone.
//!
//! The unknown and different stamps are written onto the control socket as exactly the
//! bytes a foreign binary would write — a `hello` carrying that version — because this
//! build cannot be made to *be* another version.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use support::{post_raw, until, Out, Worker};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PUBLISHED: &str = "0.2.6";
const REPO: &str = "robertelee78/vox";

fn allow_unproven(name: &str) -> bool {
    std::env::var("VOX_PROOF_ALLOW_UNPROVEN")
        .unwrap_or_default()
        .split(',')
        .any(|s| s.trim().eq_ignore_ascii_case(name))
}

fn triple() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        other => panic!("no published vox for {other:?}"),
    }
}

/// The published release binary, fetched once and verified against its published
/// SHA-256. `None` when it cannot be fetched.
fn published_vox() -> Option<std::path::PathBuf> {
    let dir = std::env::temp_dir().join(format!("vox-published-v{PUBLISHED}"));
    let bin = dir.join("vox");
    if bin.is_file() {
        return Some(bin);
    }
    std::fs::create_dir_all(&dir).ok()?;
    let base = format!(
        "https://github.com/{REPO}/releases/download/v{PUBLISHED}/vox-{}",
        triple()
    );
    let fetch = |url: &str, out: &std::path::Path| {
        std::process::Command::new("curl")
            .args(["-fsSL", "-o"])
            .arg(out)
            .arg(url)
            .status()
            .is_ok_and(|s| s.success())
    };
    let part = dir.join("vox.part");
    let sum = dir.join("vox.sha256");
    if !fetch(&base, &part) || !fetch(&format!("{base}.sha256"), &sum) {
        return None;
    }
    let want = std::fs::read_to_string(&sum)
        .ok()?
        .split_whitespace()
        .next()?
        .to_owned();
    let got = {
        use sha2::{Digest as _, Sha256};
        let bytes = std::fs::read(&part).ok()?;
        Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    assert_eq!(
        got, want,
        "the published v{PUBLISHED} binary does not match its published SHA-256"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&part, std::fs::Permissions::from_mode(0o755)).ok()?;
    }
    std::fs::rename(&part, &bin).ok()?;
    Some(bin)
}

fn refused_naming(o: &Out, who: &Worker, what: &str) {
    assert_eq!(o.code, Some(3), "a version refusal must exit 3: {o:?}");
    for needle in [&who.b32()[..12], what, &format!("required {VERSION}")] {
        assert!(
            o.stderr.contains(needle),
            "the refusal must name {needle:?}: {}",
            o.stderr
        );
    }
}

fn claims_by(w: &Worker, reader: &Worker, r: &str) -> usize {
    let o = reader.vox(None, &["room", "read", r, "--json"]);
    assert!(o.ok, "{o:?}");
    o.ndjson()
        .iter()
        .filter(|x| x["author"] == w.b32() && x["envelope"]["type"] == "claim")
        .count()
}

#[test]
#[ignore = "two networked nodes, production Argon2id, and a published release; CI runs it in release"]
fn a_worker_on_another_version_is_refused_by_name() {
    watchdog::arm();
    let Some(old) = published_vox() else {
        assert!(
            allow_unproven("published-release"),
            "UNPROVEN: the published v{PUBLISHED} binary could not be fetched, so the \
             missing-stamp case cannot be measured. Set \
             VOX_PROOF_ALLOW_UNPROVEN=published-release to accept that gap deliberately."
        );
        return;
    };
    let old = old.to_string_lossy().into_owned();
    let v = std::process::Command::new(&old)
        .arg("--version")
        .output()
        .expect("old vox runs");
    eprintln!(
        "[receipt] {old} --version -> {}",
        String::from_utf8_lossy(&v.stdout).trim()
    );
    assert!(
        String::from_utf8_lossy(&v.stdout).contains(PUBLISHED),
        "not the published binary"
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let r = room.id.as_str();

    // ---- (1) missing: the published v0.2.6 claims, and a fresh current worker is refused ----
    let o = bob.vox_bin(&old, None, &["room", "claim", r, "old-work"], None);
    eprintln!(
        "[receipt] published v{PUBLISHED} claim -> exit {:?}",
        o.code
    );
    until(
        alice,
        None,
        "the old worker's claim to reach alice",
        &["room", "read", r, "--json"],
        |o: &Out| {
            o.ok && o
                .ndjson()
                .iter()
                .any(|x| x["envelope"]["type"] == "claim" && x["envelope"]["data"]["vox"].is_null())
        },
    );
    assert_eq!(
        claims_by(alice, alice, r),
        0,
        "precondition: alice has never claimed"
    );
    let o = alice.vox(Some("a1"), &["room", "claim", r, "new-work"]);
    refused_naming(&o, bob, "no version");
    assert_eq!(
        claims_by(alice, alice, r),
        0,
        "a refused claim must never be posted"
    );

    // ---- (3) post --work, board --json and the drain hook all refuse ----
    let o = alice.vox_in(
        Some("a1"),
        &[
            "room",
            "post",
            r,
            "--type",
            "working",
            "--work",
            "gh:IOMachines/repo-to-cve#1237",
            "-",
        ],
        Some("starting"),
    );
    refused_naming(&o, bob, "no version");
    let b = alice
        .vox(Some("a1"), &["room", "board", r, "--json"])
        .json();
    assert_eq!(b["coordination"], "refused", "{b}");
    let p = b["participants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["author"] == bob.b32())
        .expect("bob in the table");
    assert_eq!(p["stamp"], "missing", "{b}");
    let hook = alice.vox(
        Some("a1"),
        &[
            "agent",
            "hook",
            "--room",
            r,
            "--format",
            "text",
            "--session",
            "a1",
        ],
    );
    assert!(
        hook.stdout.contains("work coordination refused") && hook.stdout.contains(&bob.b32()[..12]),
        "the drain hook must say it plainly: {hook:?}"
    );

    // ---- (4) conversation survives ----
    let o = alice.vox(
        Some("a1"),
        &["room", "post", r, "who is still on the old vox?"],
    );
    assert!(o.ok, "plain conversation must never be refused: {o:?}");

    // ---- (2) unknown, then different ----
    for (stamp, named) in [("banana", "banana"), ("0.2.9", "0.2.9")] {
        let hello = serde_json::json!({
            "v": 1, "type": "hello", "from": "b-foreign", "body": "a foreign worker",
            "data": { "vox": stamp, "op": format!("op-foreign-{}", stamp.replace('.', "-")) }
        })
        .to_string();
        rt.block_on(post_raw(bob, room.cid, &hello));
        let o = until(
            alice,
            Some("a1"),
            "alice to see the foreign stamp",
            &["room", "claim", r, "new-work"],
            |o: &Out| o.code == Some(3) && o.stderr.contains(named),
        );
        refused_naming(&o, bob, named);
    }

    // ---- (5) recovery: the stale worker runs the current binary ----
    let o = bob.vox(Some("b1"), &["room", "claim", r, "bob-work"]);
    assert!(
        o.ok && o.stdout.contains("you hold bob-work"),
        "a current worker among current workers coordinates: {o:?}"
    );
    let o = until(
        alice,
        Some("a1"),
        "coordination to resume for alice",
        &["room", "claim", r, "new-work"],
        |o: &Out| o.ok,
    );
    assert!(o.stdout.contains("you hold new-work"), "{o:?}");
    let b = alice
        .vox(Some("a1"), &["room", "board", r, "--json"])
        .json();
    assert_eq!(b["coordination"], "ok", "{b}");
}
