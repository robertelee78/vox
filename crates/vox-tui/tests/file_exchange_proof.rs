//! ADR-020 §11 / M19.8 — **a file crossing between two agents**, driven as real
//! binaries against two real nodes.
//!
//! The decision this proves is the decider's, and it replaced a draft of §11 that
//! would have carried file bytes through the log as chunked payloads:
//!
//! > "nc over vox over room bound service is the answer for files."
//!
//! So the bytes ride a room-bound service — the ADR-013/017 machinery that already
//! carries arbitrary TCP between members, encrypted and through NAT on both sides —
//! and the log carries only a **signed announcement** naming the file, its size and
//! its SHA-256. No new struct tag, no codec, no wire change.
//!
//! What it proves:
//!
//! 1. **A file crosses.** `vox room send` offers it and announces it; `vox room
//!    get` on a *different node with a different identity* collects it, and the
//!    bytes are identical.
//! 2. **The announcement is durable and the bytes are live.** The offer is
//!    discoverable from the log by name.
//! 3. **A transfer that does not match what was announced is refused, and the
//!    partial file is removed.** This is the property the hash exists for, and it
//!    has nothing to do with secrecy: `cat | nc` **truncates silently** — the
//!    connection drops, the receiver gets a partial file, and `nc` exits 0. A
//!    receiver that kept those bytes would reproduce that failure with extra steps.
//! 4. **Asking for something nobody offered says so**, rather than hanging or
//!    producing an empty file.
//! 5. **Where the file lands is the receiver's decision** (PRD-001 R18, D4). It goes to
//!    `~/Downloads` by default; a file already there is never overwritten; and an
//!    announcement naming `../../x` or an absolute path — text another member wrote —
//!    lands as a bare name inside the download directory, never where it points. A failed
//!    transfer leaves nothing behind and never touches a file that was already there,
//!    which the old code did twice over: `File::create` truncated it before a byte was
//!    verified, and the mismatch path then deleted it.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::process::{Child, Command, Stdio};

use std::sync::{Arc, Mutex};
use vox_core::node::actor::{Node, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};

use vox_core::node::paths::Paths;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

/// A long-running child, killed however the test ends, with its pipes drained.
struct Running(Child, Arc<Mutex<String>>);

impl Running {
    /// Whatever the child has said so far, for an assertion message.
    #[allow(dead_code)]
    fn said(&self) -> String {
        self.1.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Drain a long-lived child's pipes on threads, into a string the test can print.
///
/// **A piped stream nobody reads is a fuse, not a convenience.** The pipe buffer is
/// 64 KiB; when it fills, the child blocks on `write` and stops making progress, and
/// that looks exactly like a hang with no output to explain it. It was harmless only
/// while these children said nothing — `vox daemon` measured **0 bytes** of stderr over
/// a 40s run, which is the reporting blindness this codebase has been fixing all week.
/// Now that a node reports unreachable peers, refused publishes and stalls, the same
/// run produces kilobytes, and at ~140 B/s a 64 KiB pipe fills in about eight minutes.
/// So the bytes that were the hazard become the diagnosis instead.
fn drain(stream: Option<impl std::io::Read + Send + 'static>, into: &Arc<Mutex<String>>) {
    let Some(mut stream) = stream else { return };
    let sink = Arc::clone(into);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if let Ok(mut s) = sink.lock() {
                        s.push_str(&String::from_utf8_lossy(&buf[..n]));
                    }
                }
            }
        }
    });
}

struct Agent {
    data: std::path::PathBuf,
    cfg: std::path::PathBuf,
    paths: Paths,
    node: NodeHandle,
}

impl Agent {
    fn vox(&self, args: &[&str]) -> (bool, String, String) {
        let out = Command::new(VOX)
            .args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env_remove("VOX_ROOM")
            .stdin(Stdio::null())
            .output()
            .expect("spawn vox");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// `vox` as a person runs it from a shell: with a home directory of its own (so the
    /// `~/Downloads` default is observable) and from a working directory of its own (so a
    /// relative path the sender wrote would resolve somewhere this proof can look).
    fn vox_at(
        &self,
        args: &[&str],
        home: &std::path::Path,
        cwd: &std::path::Path,
    ) -> (bool, String, String) {
        let out = Command::new(VOX)
            .args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env("HOME", home)
            .env_remove("VOX_ROOM")
            .current_dir(cwd)
            .stdin(Stdio::null())
            .output()
            .expect("spawn vox");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn spawn(&self, args: &[&str]) -> Running {
        let mut child = {
            Command::new(VOX)
                .args(args)
                .env("VOX_DATA_DIR", &self.data)
                .env("VOX_CONFIG_DIR", &self.cfg)
                .env_remove("VOX_ROOM")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn vox")
        };
        let said = Arc::new(Mutex::new(String::new()));
        drain(child.stdout.take(), &said);
        drain(child.stderr.take(), &said);
        Running(child, said)
    }
}

async fn agent(tmp: &tempfile::TempDir, name: &str) -> Agent {
    let data = tmp.path().join(name).join("data");
    let cfg = tmp.path().join(name).join("cfg");
    let paths = Paths::resolve("default", Some(&data), Some(&cfg)).unwrap();
    let node = Node::spawn_networked(paths.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    assert!(node
        .apply(NodeCommand::CreateIdentity {
            passphrase: secret("identity passphrase"),
        })
        .await
        .is_done());
    Agent {
        data,
        cfg,
        paths,
        node,
    }
}

async fn wait_for<T>(h: &NodeHandle, mut f: impl FnMut(NodeEvent) -> Option<T>) -> T {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            match h.next_event().await {
                Some(e) => {
                    if let Some(v) = f(e) {
                        return v;
                    }
                }
                None => panic!("event stream ended"),
            }
        }
    })
    .await
    .expect("timed out waiting for an event")
}

fn until(who: &Agent, what: &str, args: &[&str], ok: impl Fn(&str) -> bool) -> String {
    let deadline = std::time::Instant::now() + TIMEOUT;
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let (_, out, err) = who.vox(args);
        last = format!("stdout={out:?} stderr={err:?}");
        if ok(&out) {
            return out;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    panic!("timed out waiting for {what}; last saw {last}");
}

#[test]
#[ignore = "two networked nodes and real child processes; CI runs it in release"]
fn a_file_crosses_between_two_agents_and_a_mismatch_is_refused() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();

    // Big enough to cross several 64 KiB reads, so a truncation is possible at all.
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let source = tmp.path().join("artifact.bin");
    std::fs::write(&source, &payload).unwrap();

    let (alice, bob, room, _a_sock, _b_sock) = rt.block_on(async {
        let alice = agent(&tmp, "alice").await;
        let bob = agent(&tmp, "bob").await;
        let alice_fp = alice.node.view().identity.unwrap().fingerprint;
        let bob_fp = bob.node.view().identity.unwrap().fingerprint;

        assert!(alice
            .node
            .apply(NodeCommand::CreateChannel {
                local_name: "mission".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
        let cid = alice.node.view().channels[0].channel_id;
        assert!(alice
            .node
            .apply(NodeCommand::Invite { channel_id: cid })
            .await
            .is_done());
        let url = wait_for(&alice.node, |e| match e {
            NodeEvent::InviteLink { channel_id, url } if channel_id == cid => Some(url),
            _ => None,
        })
        .await;
        assert!(bob
            .node
            .apply(NodeCommand::JoinChannel {
                link: url,
                local_name: "mission".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());

        // Joining grants nothing: each admits the other before either can read what
        // the other writes, which is also what makes the announcement's audience and
        // the transfer's audience the same set.
        for (who, peer, name) in [(&alice, bob_fp, "bob"), (&bob, alice_fp, "alice")] {
            assert!(who
                .node
                .apply(NodeCommand::Trust {
                    fingerprint: peer,
                    petname: name.into(),
                })
                .await
                .is_done());
        }
        for (who, peer) in [(&alice, bob_fp), (&bob, alice_fp)] {
            wait_for(&who.node, |e| match e {
                NodeEvent::SenderKeyReceived {
                    channel_id,
                    peer: p,
                    ..
                } if channel_id == cid && p == peer => Some(()),
                _ => None,
            })
            .await;
        }

        let a_sock = vox_core::node::ipc::bind(alice.node.clone(), &alice.paths).expect("alice");
        let b_sock = vox_core::node::ipc::bind(bob.node.clone(), &bob.paths).expect("bob");
        let room = vox_core::node::link::b32_encode(&cid);
        (alice, bob, room, a_sock, b_sock)
    });

    // ---- (4) nothing offered yet: asking says so ----
    let (ok, _, err) = bob.vox(&["room", "get", &room, "artifact.bin"]);
    assert!(!ok, "collecting something nobody offered must fail");
    assert!(
        err.contains("no offer in this room matches"),
        "it must say why: {err:?}"
    );

    // ---- (1) and (2) alice offers; the announcement reaches bob; bob collects ----
    let _offer = alice.spawn(&["room", "send", &room, source.to_str().unwrap()]);
    until(
        &bob,
        "the announcement to reach bob",
        &["room", "read", &room],
        |o| o.contains("artifact.bin"),
    );

    let dest = tmp.path().join("collected.bin");
    let (ok, out, err) = bob.vox(&[
        "room",
        "get",
        &room,
        "artifact.bin",
        "--out",
        dest.to_str().unwrap(),
    ]);
    assert!(
        ok,
        "bob could not collect the file: stdout={out:?} stderr={err:?}"
    );
    assert!(out.contains("verified"), "{out:?}");
    let got = std::fs::read(&dest).expect("the collected file");
    assert_eq!(
        got.len(),
        payload.len(),
        "the collected file is a different length"
    );
    assert!(
        got == payload,
        "the collected bytes differ from what was sent"
    );

    // ---- (5) where it lands is the receiver's decision, never the sender's (PRD-001 D4) ----
    //
    // A home directory and a working directory of bob's own, three levels deep, so that a
    // sender-chosen `../../x` would resolve to `work/x` — somewhere this proof can look.
    let home = tmp.path().join("home");
    let downloads = home.join("Downloads");
    let cwd = tmp.path().join("work").join("a").join("b");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::create_dir_all(&downloads).unwrap();
    // Where `../../x` would land if honoured — resolved against the working directory (the
    // old code) or against the download directory (a join without sanitising).
    let escaped = tmp.path().join("work").join("x");
    let escaped_from_downloads = tmp.path().join("x");
    let absolute = tmp.path().join("absolute-target.bin");

    // (5a) the default is ~/Downloads, and a file already there is never overwritten: the
    // collected one takes the next free name and the old bytes stay exactly as they were.
    let precious = b"bob's own artifact.bin, which nobody may overwrite".to_vec();
    std::fs::write(downloads.join("artifact.bin"), &precious).unwrap();
    let (ok, out, err) = bob.vox_at(&["room", "get", &room, "artifact.bin"], &home, &cwd);
    assert!(
        ok,
        "collecting into ~/Downloads: stdout={out:?} stderr={err:?}"
    );
    let now = std::fs::read(downloads.join("artifact.bin")).unwrap_or_default();
    assert!(
        now == precious,
        "a file already in the download directory must be untouched — it holds {} bytes, it held {}",
        now.len(),
        precious.len()
    );
    assert!(
        std::fs::read(downloads.join("artifact (1).bin")).is_ok_and(|b| b == payload),
        "the collected file must land beside it under the next free name: {out:?}"
    );

    // (5b) a hostile sender: announcements naming a path outside the download directory,
    // relative and absolute, for bytes that are genuinely on offer (the same service, size
    // and hash as the real offer), so the only thing wrong with them is the name.
    let sha = {
        use sha2::{Digest as _, Sha256};
        Sha256::digest(&payload)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let tag = format!("file-{}", &sha[..16]);
    // AGENT_COMMS-EXTRA: Windows-style names, and symlinks already in Downloads.
    let victim = tmp.path().join("victim.bin");
    let victim_bytes = b"a file the symlink points at, which nobody may touch".to_vec();
    std::fs::write(&victim, &victim_bytes).unwrap();
    std::os::unix::fs::symlink(&victim, downloads.join("link.bin")).unwrap();
    let dangle_target = tmp.path().join("dangle-target.bin");
    std::os::unix::fs::symlink(&dangle_target, downloads.join("dangle.bin")).unwrap();
    for (hostile, lands_as) in [
        ("../../x", "x"),
        (absolute.to_str().unwrap(), "absolute-target.bin"),
        ("..\\..\\y", "y"),
        ("C:\\z", "z"),
        ("link.bin", "link (1).bin"),
        ("dangle.bin", "dangle (1).bin"),
    ] {
        let forged = serde_json::json!({
            "v": 1,
            "type": "file",
            "body": "offering something",
            "data": { "name": hostile, "size": payload.len(), "sha256": sha, "tag": tag },
        })
        .to_string();
        let (ok, _, err) = alice.vox(&["room", "post", &room, &forged]);
        assert!(ok, "alice announces {hostile:?}: {err}");
        until(
            &bob,
            "the hostile announcement to reach bob",
            &["room", "read", &room],
            |o| {
                let escaped = serde_json::to_string(hostile).unwrap();
                o.contains(hostile) || o.contains(escaped.trim_matches('"'))
            },
        );
        let (ok, out, err) = bob.vox_at(&["room", "get", &room, hostile], &home, &cwd);
        assert!(ok, "collecting {hostile:?}: stdout={out:?} stderr={err:?}");
        assert!(
            !escaped.exists() && !escaped_from_downloads.exists() && !absolute.exists(),
            "a sender-chosen name {hostile:?} must never place a file outside the download \
             directory (escaped via cwd: {}, via the download dir: {}, absolute: {})",
            escaped.exists(),
            escaped_from_downloads.exists(),
            absolute.exists()
        );
        assert!(
            std::fs::read(&victim).is_ok_and(|b| b == victim_bytes) && !dangle_target.exists(),
            "EXTRA: a symlink already in Downloads must not be followed ({hostile:?}): victim intact={}, dangling target created={}",
            std::fs::read(&victim).is_ok_and(|b| b == victim_bytes),
            dangle_target.exists()
        );
        assert!(
            !tmp.path().join("y").exists() && !tmp.path().join("work").join("y").exists(),
            "EXTRA: a Windows-style ..\\ name escaped the download directory"
        );
        assert!(
            std::fs::read(downloads.join(lands_as)).is_ok_and(|b| b == payload),
            "{hostile:?} must land in the download directory as {lands_as:?}: {out:?}"
        );
    }
    let listed = |dir: &std::path::Path| -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };
    let before = listed(&downloads);
    assert_eq!(
        before,
        [
            "absolute-target.bin",
            "artifact (1).bin",
            "artifact.bin",
            "dangle (1).bin",
            "dangle.bin",
            "link (1).bin",
            "link.bin",
            "x",
            "y",
            "z"
        ],
        "exactly the four files, and no leftover `.part`"
    );

    // ---- (3) a real truncation is refused, and the partial file is removed ----
    //
    // Not a hand-written announcement claiming the wrong hash — an actual short
    // transfer, which is the failure this exists to catch. `cat | nc` truncates
    // silently: the connection drops, the receiver gets a partial file, and `nc`
    // exits 0. Here the offered file is shortened on disk **after** it was
    // announced, so the sender serves fewer bytes than it signed for, exactly as a
    // dropped connection would.
    let flaky = tmp.path().join("flaky.bin");
    std::fs::write(&flaky, &payload).unwrap();
    let _flaky_offer = alice.spawn(&["room", "send", &room, flaky.to_str().unwrap()]);
    until(
        &bob,
        "the second announcement to reach bob",
        &["room", "read", &room],
        |o| o.contains("flaky.bin"),
    );

    // The offer re-opens the path for each collector, so shortening it now means the
    // next transfer is short — while the announced size and hash still describe the
    // whole file.
    std::fs::write(&flaky, &payload[..100_000]).unwrap();

    let bad = tmp.path().join("truncated.bin");
    let (ok, out, err) = bob.vox(&[
        "room",
        "get",
        &room,
        "flaky.bin",
        "--out",
        bad.to_str().unwrap(),
    ]);
    assert!(
        !ok,
        "a short transfer must be refused, not accepted silently: stdout={out:?}"
    );
    assert!(
        err.contains("does not match what was announced"),
        "it must say why: {err:?}"
    );
    assert!(
        !bad.exists(),
        "the partial file must be removed, not left looking complete"
    );

    // (3b) the same short transfer into the download directory, where a file of that name
    // already exists: refused, nothing new is left behind, and — the old code's worst case —
    // the file that was already there is neither truncated nor deleted.
    let theirs = b"bob's own flaky.bin, which a failed transfer must not touch".to_vec();
    std::fs::write(downloads.join("flaky.bin"), &theirs).unwrap();
    let before = listed(&downloads);
    let (ok, out, err) = bob.vox_at(&["room", "get", &room, "flaky.bin"], &home, &cwd);
    assert!(!ok, "a short transfer must be refused: stdout={out:?}");
    assert!(
        err.contains("does not match what was announced"),
        "it must say why: {err:?}"
    );
    let now = std::fs::read(downloads.join("flaky.bin")).unwrap_or_default();
    assert!(
        now == theirs,
        "a failed transfer must not truncate or delete the file already there — it holds {} bytes, it held {}",
        now.len(),
        theirs.len()
    );
    assert_eq!(
        listed(&downloads),
        before,
        "a failed transfer must leave nothing behind — no partial, no `.part`"
    );

    // (3c) an explicit --out that already exists is refused before a byte moves.
    let (ok, _, err) = bob.vox_at(
        &[
            "room",
            "get",
            &room,
            "artifact.bin",
            "--out",
            downloads.join("flaky.bin").to_str().unwrap(),
        ],
        &home,
        &cwd,
    );
    assert!(!ok, "--out onto an existing file must be refused");
    assert!(err.contains("never overwrites"), "it must say why: {err:?}");
    let now = std::fs::read(downloads.join("flaky.bin")).unwrap_or_default();
    assert!(
        now == theirs,
        "--out must not touch the file it refused — it holds {} bytes, it held {}",
        now.len(),
        theirs.len()
    );
    // (3d) a sender that serves MORE than it announced — it under-announced — is cut off on the
    // bytes actually received, not believed: our `.part` is removed, nothing is placed, and the
    // file already under that name is untouched. The offered file grows on disk after the
    // announcement, exactly as (3) shrinks it.
    let extra = 200_000usize;
    let mut longer = payload.clone();
    longer.extend(std::iter::repeat_n(0x5a_u8, extra));
    std::fs::write(&flaky, &longer).unwrap();
    let before = listed(&downloads);
    let (ok, out, err) = bob.vox_at(&["room", "get", &room, "flaky.bin"], &home, &cwd);
    eprintln!(
        "under-announced: {} bytes announced, {} served — refused={} ({})",
        payload.len(),
        longer.len(),
        !ok,
        err.trim()
    );
    assert!(!ok, "more bytes than announced must be refused: stdout={out:?}");
    assert!(
        err.contains("sent more than"),
        "it must say the sender sent more than it announced: {err:?}"
    );
    assert!(
        std::fs::read(downloads.join("flaky.bin")).is_ok_and(|b| b == theirs),
        "an over-long transfer must not touch the file already there"
    );
    assert_eq!(
        listed(&downloads),
        before,
        "an over-long transfer must leave nothing behind — no partial, no `.part`"
    );
    // Back to the announced bytes: this offer and `artifact.bin` carry the same content, so they
    // share one service tag, and the next case collects through it.
    std::fs::write(&flaky, &payload).unwrap();

    // (5c) a download directory on a volume with no hard links — FAT, as on a USB stick.
    // `link()` and the no-replace rename are both refused there, so this is the third way
    // (claim the name with O_EXCL, then move over the claim), and it must keep the same
    // guarantee: the file already there is untouched and the new one takes the next name.
    // macOS attaches a FAT image without privileges; elsewhere this needs root, so it is not
    // run there, and says so.
    #[cfg(target_os = "macos")]
    {
        struct Detach(String);
        impl Drop for Detach {
            fn drop(&mut self) {
                let _ = std::process::Command::new("hdiutil")
                    .args(["detach", "-force", &self.0])
                    .output();
            }
        }
        let img = tmp.path().join("fat.dmg");
        let made = std::process::Command::new("hdiutil")
            .args(["create", "-size", "20m", "-fs", "MS-DOS", "-volname", "VOXFAT"])
            .arg(&img)
            .output()
            .unwrap();
        assert!(made.status.success(), "CANNOT MEASURE (5c): hdiutil create: {made:?}");
        let attached = std::process::Command::new("hdiutil")
            .args(["attach", "-nobrowse", "-mountrandom"])
            .arg(tmp.path())
            .arg(&img)
            .output()
            .unwrap();
        assert!(attached.status.success(), "CANNOT MEASURE (5c): hdiutil attach: {attached:?}");
        let mount = String::from_utf8_lossy(&attached.stdout)
            .lines()
            .filter_map(|l| l.split('\t').next_back().map(|m| m.trim().to_owned()))
            .find(|m| m.starts_with('/'))
            .expect("the FAT volume's mount point");
        let _detach = Detach(mount.clone());
        let fat = std::path::PathBuf::from(&mount);
        // The precondition, measured: a hard link of a real file must be refused here, or this
        // arm would pass through the second way and prove nothing about the third.
        std::fs::write(fat.join("probe"), b"p").unwrap();
        let linked = std::fs::hard_link(fat.join("probe"), fat.join("probe-link"));
        eprintln!("FAT volume at {mount}: hard link of a file -> {linked:?}");
        assert!(linked.is_err(), "CANNOT MEASURE (5c): this volume allows hard links");
        std::fs::remove_file(fat.join("probe")).unwrap();
        let on_stick = b"bob's own artifact.bin on the stick".to_vec();
        std::fs::write(fat.join("artifact.bin"), &on_stick).unwrap();
        let (ok, out, err) = bob.vox_at(
            &["room", "get", &room, "artifact.bin", "--dir", &mount],
            &home,
            &cwd,
        );
        let files = listed(&fat);
        eprintln!("FAT volume: collected ok={ok}; it holds {files:?}");
        assert!(ok, "collecting onto a FAT volume must work: stdout={out:?} stderr={err:?}");
        assert!(
            std::fs::read(fat.join("artifact.bin")).is_ok_and(|b| b == on_stick),
            "the file already on the FAT volume must be untouched"
        );
        assert!(
            std::fs::read(fat.join("artifact (1).bin")).is_ok_and(|b| b == payload),
            "the collected file must land beside it under the next free name: {out:?}"
        );
        assert!(
            !files.iter().any(|f| f.ends_with(".part")),
            "no `.part` may be left on the FAT volume: {files:?}"
        );
    }
    #[cfg(not(target_os = "macos"))]
    eprintln!("FAT volume (5c): not run — attaching a FAT image needs root on this OS");

    eprintln!(
        "downloads after every case: {} files, {:?}",
        listed(&downloads).len(),
        listed(&downloads)
    );
}
