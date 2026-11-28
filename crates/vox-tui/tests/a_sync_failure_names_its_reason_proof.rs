//! Concurrent posts are accepted, and a full disk can recover without stranding another room.

#![cfg(unix)]
// Both harness supports carry their own copies of the data-root helpers.
#![cfg_attr(target_os = "macos", allow(clippy::duplicate_mod))]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[cfg(target_os = "macos")]
#[path = "support/room.rs"]
mod disk_room;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use world::{args, vox_once, VoxProc, IDENTITY, VOX};

/// Rounds of both members posting at once.
const ROUNDS: usize = 40;
const TIMEOUT: Duration = Duration::from_secs(90);

fn vox_in(data: &Path, argv: &[&str], stdin: &str) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot start vox {argv:?}: {e}"));
    child
        .stdin
        .take()
        .expect("APPARATUS: vox was started without a stdin pipe")
        .write_all(stdin.as_bytes())
        .unwrap_or_else(|e| panic!("APPARATUS: cannot write vox {argv:?}'s stdin: {e}"));
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot wait for vox {argv:?}: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn daemon(name: &str, data: &Path, spec: &str, pass_file: &Path) -> VoxProc {
    let mut p = VoxProc::spawn(
        name,
        data,
        &args(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--anchor",
            spec,
            "--passphrase-file",
            pass_file
                .to_str()
                .expect("APPARATUS: the passphrase file's path is not UTF-8"),
        ]),
    );
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!(
        "PRODUCT: {name}'s `vox daemon` never answered `vox room list` within {TIMEOUT:?}\n{}",
        p.transcript()
    );
}

#[test]
#[ignore = "real vox processes with production Argon2id; CI runs it in release"]
fn concurrent_posts_are_accepted() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg"))
            .unwrap_or_else(|e| panic!("APPARATUS: cannot make {}: {e}", d.display()));
        d
    };
    let (anchor_dir, alice_dir, bob_dir) = (dir("anchor"), dir("alice"), dir("bob"));
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).expect("APPARATUS: cannot write the passphrase file");

    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains("@/ip4/127.0.0.1/udp/")
        })
        .trim()
        .to_owned();

    let fp = |d: &Path| {
        let (ok, out, err) = vox_once(d, &args(&["id"]));
        assert!(ok, "PRODUCT (staging): vox id: {err}");
        out.trim().to_owned()
    };
    let (alice_fp, bob_fp) = (fp(&alice_dir), fp(&bob_dir));
    for (d, other, name) in [(&alice_dir, &bob_fp, "bob"), (&bob_dir, &alice_fp, "alice")] {
        let (ok, out, err) = vox_once(d, &args(&["trust", "add", other, "--name", name]));
        assert!(ok, "PRODUCT (staging): vox trust add {name}: {out}{err}");
    }

    let _alice = daemon("alice", &alice_dir, &spec, &idpass);
    let _bob = daemon("bob", &bob_dir, &spec, &idpass);

    let (ok, out, err) = vox_in(
        &alice_dir,
        &["room", "create", "--passphrase-file", "-", "--name", "pair"],
        "room pass",
    );
    assert!(ok, "PRODUCT (staging): vox room create: {out}{err}");
    let (ok, list, err) = vox_once(&alice_dir, &args(&["room", "list"]));
    assert!(ok, "PRODUCT (staging): vox room list: {err}");
    let room = list
        .lines()
        .find(|l| l.contains("pair"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| {
            panic!("PRODUCT: the room alice created is not in `vox room list`: {list}")
        })
        .to_owned();
    let (ok, link, err) = vox_once(&alice_dir, &args(&["room", "link", &room]));
    assert!(ok, "PRODUCT (staging): vox room link: {err}");
    let (ok, out, err) = vox_in(
        &bob_dir,
        &["room", "join", "--passphrase-file", "-", link.trim()],
        "room pass",
    );
    assert!(ok, "PRODUCT (staging): bob's `vox room join`: {out}{err}");

    // Both members read each other before the rounds, so every failure below is between two
    // members that can sync, not a join still settling.
    let deadline = Instant::now() + TIMEOUT;
    let (ok, _, err) = vox_once(
        &alice_dir,
        &args(&["room", "post", &room, "hello from alice"]),
    );
    assert!(ok, "PRODUCT (staging): alice's first post: {err}");
    loop {
        let (_, read, _) = vox_once(&bob_dir, &args(&["room", "read", &room]));
        if read.contains("hello from alice") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): bob never read alice before the rounds"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // ---- both post at the same moment, ROUNDS times ----------------------------------------
    let barrier = Arc::new(Barrier::new(2));
    let poster = |data: std::path::PathBuf, who: &'static str| {
        let (barrier, room) = (Arc::clone(&barrier), room.clone());
        std::thread::spawn(move || {
            let mut refused = Vec::new();
            for i in 0..ROUNDS {
                barrier.wait();
                let (ok, out, err) = vox_once(
                    &data,
                    &args(&["room", "post", &room, &format!("{who} {i}")]),
                );
                if !ok {
                    refused.push(format!("{who}'s post {i}: {}{}", out.trim(), err.trim()));
                }
            }
            refused
        })
    };
    let a = poster(alice_dir.clone(), "alice");
    let b = poster(bob_dir.clone(), "bob");
    let mut refused_posts = a.join().expect("APPARATUS: alice's poster thread panicked");
    refused_posts.extend(b.join().expect("APPARATUS: bob's poster thread panicked"));
    assert!(
        refused_posts.is_empty(),
        "PRODUCT: {} post(s) were refused while both members posted at once: {refused_posts:?}",
        refused_posts.len()
    );

    drop(anchor);
}

/// RG-14: two real ENOSPC/recovery cycles must not strand another room or a leave.
/// If detaching fails or this process is killed, the image may remain mounted at
/// `<temporary directory>/rg14-*/disk`; the rg14 evidence runner also cleans up its own images.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "real daemons and a disposable 64 MiB macOS disk image; run in release"]
fn a_full_disk_recovers_without_stranding_sync_or_leave() {
    watchdog::arm();
    let tmp = tempfile::Builder::new()
        .prefix("rg14-")
        .tempdir_in(std::env::temp_dir())
        .expect("APPARATUS: scratch directory");
    let mount = tmp.path().join("disk");
    std::fs::create_dir(&mount).expect("APPARATUS: mount directory");
    let image = tmp.path().join("scratch.sparseimage");
    let created = Command::new("/usr/bin/hdiutil")
        .args([
            "create", "-size", "64m", "-fs", "HFS+", "-volname", "VoxRG14", "-type", "SPARSE",
        ])
        .arg(&image)
        .output()
        .expect("APPARATUS: hdiutil create");
    assert!(
        created.status.success(),
        "APPARATUS: image creation: {}",
        String::from_utf8_lossy(&created.stderr)
    );
    struct Disk(std::path::PathBuf);
    impl Drop for Disk {
        fn drop(&mut self) {
            // Apparatus only (`VOX_PROOF_KEEP_DIRS`): every node's daemon log survives the image,
            // copied next to the scratch directory before the image is detached.
            if std::env::var_os("VOX_PROOF_KEEP_DIRS").is_some() {
                let kept = std::env::temp_dir().join(format!("rg14-logs-{}", std::process::id()));
                let scratch = self.0.parent().map(std::path::Path::to_path_buf);
                for (name, root) in [
                    ("bob", Some(self.0.join("bob"))),
                    ("alice", scratch.map(|s| s.join("alice"))),
                ] {
                    let Some(daemon) = root.map(|root| root.join("data").join(".daemon")) else {
                        continue;
                    };
                    for entry in std::fs::read_dir(&daemon).into_iter().flatten().flatten() {
                        let file = entry.file_name().to_string_lossy().into_owned();
                        if file.starts_with("log") {
                            let _ = std::fs::create_dir_all(&kept);
                            let _ =
                                std::fs::copy(entry.path(), kept.join(format!("{name}-{file}")));
                        }
                    }
                }
            }
            let detached = Command::new("/usr/bin/hdiutil")
                .arg("detach")
                .arg(&self.0)
                .output();
            if !detached.is_ok_and(|out| out.status.success()) {
                let out = Command::new("/usr/bin/hdiutil")
                    .args(["detach", "-force"])
                    .arg(&self.0)
                    .output();
                if !out.is_ok_and(|out| out.status.success()) {
                    eprintln!(
                        "APPARATUS: disk image could not be detached; possible leftover mount: {}",
                        self.0.display()
                    );
                }
            }
        }
    }
    let attached = Command::new("/usr/bin/hdiutil")
        .args(["attach", "-nobrowse", "-mountpoint"])
        .arg(&mount)
        .arg(&image)
        .output()
        .expect("APPARATUS: hdiutil attach");
    assert!(
        attached.status.success(),
        "APPARATUS: image attach: {}",
        String::from_utf8_lossy(&attached.stderr)
    );
    let _disk = Disk(mount.clone());
    std::fs::create_dir(mount.join("bob")).expect("APPARATUS: disk profile directory");
    std::os::unix::fs::symlink(mount.join("bob"), tmp.path().join("bob"))
        .expect("APPARATUS: place only Bob's profile on the small disk");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("APPARATUS: runtime");
    let room = rt.block_on(disk_room::room(tmp.path(), &["alice", "bob"]));
    let alice = &room.workers[0];
    let bob = &room.workers[1];
    let mut rooms = vec![room.id.clone()];
    for name in ["second", "third"] {
        alice
            .vox_in(
                None,
                &["room", "create", "--name", name, "--passphrase-file", "-"],
                Some(disk_room::ROOM_PASS),
            )
            .expect_ok("create another room");
        let list = alice.vox(None, &["room", "list"]);
        list.expect_ok("list rooms");
        let id = list
            .stdout
            .lines()
            .find(|line| line.contains(name))
            .and_then(|line| line.split_whitespace().next())
            .expect("APPARATUS: new room id")
            .to_owned();
        let link = alice.vox(None, &["room", "link", &id]);
        link.expect_ok("room link");
        bob.vox_in(
            None,
            &["room", "join", "--passphrase-file", "-", link.stdout.trim()],
            Some(disk_room::ROOM_PASS),
        )
        .expect_ok("join another room");
        rooms.push(id);
    }
    let mut problems = Vec::new();
    for cycle in 0..2 {
        let filler = mount.join("filler");
        let mut file = std::fs::File::create(&filler).expect("APPARATUS: create filler");
        let block = vec![0x5a; 1024 * 1024];
        for size in [block.len(), 4096] {
            loop {
                match file.write_all(&block[..size]) {
                    Ok(()) => {}
                    Err(error) => {
                        assert_eq!(
                            error.raw_os_error(),
                            Some(28),
                            "APPARATUS: filling disk: {error}"
                        );
                        break;
                    }
                }
            }
        }
        drop(file);
        let mut failure = String::new();
        for n in 0..128 {
            let out = bob.vox(
                None,
                &[
                    "room",
                    "post",
                    &rooms[0],
                    &format!("disk write {cycle}/{n} {}", "x".repeat(60_000)),
                ],
            );
            if !out.ok {
                failure = format!("{}{}", out.stdout, out.stderr);
                break;
            }
        }
        assert!(
            !failure.is_empty(),
            "APPARATUS: no write failed on the full disk"
        );
        // Generate failed inbound/outbound cleanup in all three rooms, as in C-12.
        for n in 0..24 {
            for id in &rooms {
                alice
                    .vox(
                        None,
                        &["room", "post", id, &format!("while full {cycle}/{n}")],
                    )
                    .expect_ok("post from the member with free disk");
            }
        }
        let status = bob.vox(None, &["status"]);
        let named_full = format!("{}{}{}", failure, status.stdout, status.stderr);
        std::fs::remove_file(&filler).expect("APPARATUS: free the disk");
        // A prior cycle's recovery notice can coexist with a fresh write failure.
        // All rooms must be writable before fresh reception or leave is judged.
        disk_room::until(bob, None, "store writable again", &["status"], |out| {
            out.ok && out.stdout.contains("recovered") && !out.stdout.contains("cannot save")
        });
        if !named_full.contains("disk is full") {
            problems.push(format!(
                "cycle {cycle}: full disk was not named: {named_full}"
            ));
        }
        let marker = format!("after freeing cycle {cycle}");
        alice
            .vox(None, &["room", "post", &rooms[1], &marker])
            .expect_ok("post after freeing");
        let mut received = false;
        for n in 0..100 {
            let out = bob.vox(None, &["room", "read", &rooms[1]]);
            if out.ok
                && (out.stdout.contains(&marker)
                    || out.stdout.contains(&format!("recovery progress {cycle}/")))
            {
                received = true;
                break;
            }
            alice
                .vox(
                    None,
                    &[
                        "room",
                        "post",
                        &rooms[1],
                        &format!("recovery progress {cycle}/{n}"),
                    ],
                )
                .expect_ok("post counted recovery progress");
        }
        if !received {
            // Apparatus only: what bob and alice say of the room when it is not received.
            let _ = bob.vox(None, &["status"]);
            let _ = alice.vox(None, &["status"]);
            problems.push(format!(
                "cycle {cycle}: Bob reported recovery but received none of 100 further posts"
            ));
        }
        if std::fs::read_dir(&bob.paths.profile_dir)
            .expect("APPARATUS: profile directory")
            .any(|entry| {
                entry
                    .expect("APPARATUS: profile entry")
                    .file_name()
                    .to_string_lossy()
                    .contains(".failed")
            })
        {
            problems.push(format!("cycle {cycle}: recovery kept a .failed store copy"));
        }
    }
    let left = bob.vox(None, &["room", "leave", &rooms[0]]);
    if !left.ok {
        problems.push(format!("leave after two disk failures: {left:?}"));
    }
    let list = bob.vox(None, &["room", "list"]);
    if !list.ok || list.stdout.contains(&rooms[0][..12]) {
        problems.push(format!("left room still listed: {list:?}"));
    }
    assert!(problems.is_empty(), "PRODUCT: {}", problems.join("\n"));
}
