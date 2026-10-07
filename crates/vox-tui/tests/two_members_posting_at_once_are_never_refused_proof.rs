//! **A push that keeps colliding is never left to the 30 s interval** (#41), through the shipped
//! binaries: a real `vox node` anchor and two real `vox daemon`s.
//!
//! When two members push to each other at the same moment, each refuses the other's inbound
//! session because its own is running, and both fail. A failed push was retried three times after
//! a random 20–100 ms wait and then left to the periodic interval, so a collision that outlasted
//! three retries left the message for ~30 s. Measured with instrumented shipped daemons
//! (`dbg/180-sessions`): alice and bob failing on each other in lockstep past three retries in
//! about one warm-up in ten, hidden only because the next post re-pushed.
//!
//! Here both post at once, then nothing is posted until every member has read every other's
//! post, and each crossing is timed. Nothing re-pushes, so a push abandoned to the interval shows.
//!
//! ## Which side a late crossing is on
//! A crossing is timed by `vox room read`s in a loop, so it is only known to lie between the last
//! read that missed it and the first that saw it. It is **PRODUCT** late only when a read that
//! *started* past [`BOUND`] — plus whatever the runner itself stalled meanwhile, measured on the
//! same timeline by a thread that sleeps 10 ms at a time — still did not show it. A crossing whose
//! window straddles the bound only because of the poll gap or a runner stall is **CANNOT
//! MEASURE**, never a pass and never a product verdict.
//!
//! The warm-up (everyone reads everyone) can meet #200's pairwise-session race, which fails as
//! `PRODUCT (staging)`, never as a pass: it is `vox` that did not deliver.
//!
//! ## ADR-025 P6
//! vox-0e's gate (3bb6ca1, on `test/two-member-collisions`), adapted as ADR-025's P6: besides
//! every crossing landing within its bound, **neither daemon refuses the other** over the rounds —
//! `busy_refused = 0` on both, from the shipped `vox status --json`. Under ADR-025 option C an
//! inbound session is admitted beside this side's own (up to three per room and peer), so two
//! members posting at once no longer collide at all.
//!
//! Mutation: restore the busy refusal at the inbound check; `busy_refused` rises and this is red.

#![cfg(unix)]

#[path = "support/attach.rs"]
mod attach;
#[path = "support/typed.rs"]
mod typed;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const ID_PASS: &str = "an identity passphrase";
const ROOM_PASS: &str = "the room passphrase";

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Member {
    name: &'static str,
    data: PathBuf,
    cfg: PathBuf,
    pass: PathBuf,
}

impl Member {
    fn new(root: &Path, name: &'static str) -> Self {
        let (data, cfg) = (root.join(name).join("data"), root.join(name).join("cfg"));
        std::fs::create_dir_all(&cfg)
            .unwrap_or_else(|e| panic!("APPARATUS: could not make {}: {e}", cfg.display()));
        let pass = root.join(format!("{name}.pass"));
        std::fs::write(&pass, ID_PASS)
            .unwrap_or_else(|e| panic!("APPARATUS: could not write {}: {e}", pass.display()));
        Self {
            name,
            data,
            cfg,
            pass,
        }
    }

    fn vox(&self, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
        let mut cmd = Command::new(VOX);
        cmd.args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env_remove("VOX_ROOM")
            .env_remove("VOX_SESSION")
            .env_remove("CLAUDE_CODE_SESSION_ID")
            .env_remove("CODEX_THREAD_ID")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028
        // K-13).
        if typed::is_keyring_change(args) {
            let (ok, shown) = typed::keyring(&cmd);
            return (ok, shown.clone(), shown);
        }
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: could not spawn {VOX}: {e}"));
        if let Some(s) = stdin {
            child
                .stdin
                .take()
                .expect("APPARATUS: the child's stdin was not piped")
                .write_all(s.as_bytes())
                .unwrap_or_else(|e| panic!("PRODUCT (staging): vox exited without reading its stdin (could not write vox's stdin): {e}"));
        }
        let out = child
            .wait_with_output()
            .unwrap_or_else(|e| panic!("APPARATUS: could not wait for vox: {e}"));
        let r = (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        );
        eprintln!(
            "[receipt] {} vox {} -> {} {}",
            self.name,
            args.join(" "),
            r.0,
            r.2.trim()
        );
        r
    }

    /// This member's busy refusals, summed over its sync rows, from the shipped
    /// `vox status --json`. A missing field is not a zero: it cannot say whether anything was
    /// refused.
    fn busy_refused(&self) -> u64 {
        let (ok, out, err) = self.vox(&["status", "--json"], None);
        assert!(
            ok,
            "PRODUCT: {}'s `vox status --json` failed: {err}",
            self.name
        );
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap_or_else(|e| {
            panic!(
                "PRODUCT: {}'s `vox status --json` is not JSON ({e}): {out}",
                self.name
            )
        });
        let Some(rows) = v["sync"].as_array() else {
            panic!(
                "PRODUCT (staging): {}'s `vox status --json` has no `sync` rows: {out}",
                self.name
            );
        };
        rows.iter()
            .map(|r| {
                r["busy_refused"].as_u64().unwrap_or_else(|| {
                    panic!(
                        "PRODUCT (staging): a sync row in {}'s `vox status --json` has no \
                         `busy_refused`: {r}",
                        self.name
                    )
                })
            })
            .sum()
    }

    fn fingerprint(&self) -> String {
        let (ok, out, err) = self.vox(
            &[
                "id",
                "--identity-passphrase-file",
                self.pass
                    .to_str()
                    .expect("APPARATUS: a non-UTF-8 temp path"),
            ],
            None,
        );
        assert!(
            ok,
            "PRODUCT (staging): {}'s `vox id` failed: {err}",
            self.name
        );
        out.trim().to_owned()
    }

    fn daemon(&self, anchor: &str, err: &Path) -> Proc {
        let child = Command::new(VOX)
            .args([
                "daemon",
                "--listen",
                "127.0.0.1:0",
                "--anchor",
                anchor,
                "--passphrase-file",
            ])
            .arg(&self.pass)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(err).unwrap_or_else(
                |e| panic!("APPARATUS: could not create {}: {e}", err.display()),
            )))
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: could not spawn {VOX} daemon: {e}"));
        let started = Instant::now();
        while !self.vox(&["room", "list"], None).0 {
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "PRODUCT (staging): {}'s daemon never answered `vox room list` \
                 in {:?}; its stderr:\n{}",
                self.name,
                started.elapsed(),
                std::fs::read_to_string(err).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(500));
        }
        Proc(child)
    }
}

fn spawn_anchor(root: &Path) -> (Proc, String) {
    let (a_data, a_cfg) = (root.join("anchor/data"), root.join("anchor/cfg"));
    std::fs::create_dir_all(&a_cfg)
        .unwrap_or_else(|e| panic!("APPARATUS: could not make {}: {e}", a_cfg.display()));
    let anchor_out = root.join("anchor.out");
    let anchor_err = root.join("anchor.err");
    let file = |p: &Path| {
        std::fs::File::create(p)
            .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", p.display()))
    };
    let anchor = Proc(
        Command::new(VOX)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &a_data)
            .env("VOX_CONFIG_DIR", &a_cfg)
            .stdout(Stdio::from(file(&anchor_out)))
            .stderr(Stdio::from(file(&anchor_err)))
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: could not spawn {VOX} node: {e}")),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let text = std::fs::read_to_string(&anchor_out).unwrap_or_default();
        if let Some(s) = text
            .split_whitespace()
            .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        {
            return (anchor, s.to_owned());
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): the anchor never printed its spec in 60 s; \
             it said:\n{text}\n{}",
            std::fs::read_to_string(&anchor_err).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// A crossing must land far inside the 30 s interval a push used to be left to. The backoff past
/// the quick retries waits at most `MAX_PUSH_RETRY_WAIT` (8 s) between tries, so a message caught
/// in a long collision still lands within this; one left to the interval takes ~30 s.
const BOUND: Duration = Duration::from_secs(12);
/// Rounds in which both post at once. A collision long enough to exhaust the old three quick
/// retries came up in about one warm-up in ten (measured, dbg/180-sessions); this many rounds
/// gives the old code many chances to show it.
const ROUNDS: usize = 60;

/// The runner's own stalls, on the proof's timeline: a thread that sleeps [`TICK`] at a time and
/// records how late each wake was. Time the runner lost is time no `vox` could have used either.
struct Stalls {
    late: Arc<Mutex<Vec<(Instant, Duration)>>>,
    stop: Arc<AtomicBool>,
}

const TICK: Duration = Duration::from_millis(10);

impl Stalls {
    fn start() -> Self {
        let late = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (l, s) = (Arc::clone(&late), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                let before = Instant::now();
                std::thread::sleep(TICK);
                let woke = Instant::now();
                let over = woke.duration_since(before).saturating_sub(TICK);
                if over > Duration::from_millis(2) {
                    if let Ok(mut v) = l.lock() {
                        v.push((woke, over));
                    }
                }
            }
        });
        Self { late, stop }
    }

    /// How long the runner stalled between `from` and `to`.
    fn within(&self, from: Instant, to: Instant) -> Duration {
        self.late
            .lock()
            .map(|v| {
                v.iter()
                    .filter(|(at, _)| *at >= from && *at <= to)
                    .map(|(_, d)| *d)
                    .sum()
            })
            .unwrap_or_default()
    }
}

impl Drop for Stalls {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

#[test]
#[ignore = "a real anchor and two real daemons with production Argon2id, 60 rounds; CI runs it in release"]
fn two_members_posting_at_once_are_never_refused() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: could not make a temporary directory");
    let root = tmp.path();
    let (anchor, spec) = spawn_anchor(root);
    let members = [Member::new(root, "alice"), Member::new(root, "bob")];
    let fps: Vec<String> = members.iter().map(Member::fingerprint).collect();
    for (i, m) in members.iter().enumerate() {
        // Trust is a one-shot verb: its node is attached for it and let go after, before the
        // member's own daemon starts (ADR-026 L-2).
        let root = attach::Root {
            data: m.data.clone(),
            cfg: m.cfg.clone(),
            passphrase: ID_PASS.trim_end_matches('\n').to_owned(),
        };
        root.attached("default", || {
            for (j, other) in members.iter().enumerate() {
                if i != j {
                    let (ok, _, err) = m.vox(
                        &[
                            "trust",
                            "add",
                            &fps[j],
                            "--name",
                            other.name,
                            "--identity-passphrase-file",
                            m.pass.to_str().expect("APPARATUS: a non-UTF-8 temp path"),
                        ],
                        None,
                    );
                    assert!(
                        ok,
                        "PRODUCT (staging): {} could not trust {}: {err}",
                        m.name, other.name
                    );
                }
            }
        });
    }
    let daemons: Vec<Proc> = members
        .iter()
        .map(|m| m.daemon(&spec, &root.join(format!("{}.err", m.name))))
        .collect();
    let [alice, bob] = &members;
    let (ok, _, err) = alice.vox(
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "mission",
        ],
        Some(ROOM_PASS),
    );
    assert!(
        ok,
        "PRODUCT (staging): alice's `vox room create` failed: {err}"
    );
    let (_, list, err) = alice.vox(&["room", "list"], None);
    let Some(room) = list.split_whitespace().next().map(str::to_owned) else {
        panic!("PRODUCT (staging): alice's `vox room list` names no room: {list}{err}");
    };
    let (ok, link, err) = alice.vox(&["room", "link", &room], None);
    assert!(
        ok,
        "PRODUCT (staging): alice's `vox room link` failed: {err}"
    );
    let link = link.trim().to_owned();
    // One join, no retry: a join that fails is a defect in joining, which is not what this proves,
    // and retrying would hide it.
    let (ok, out, err) = bob.vox(
        &["room", "join", "--passphrase-file", "-", &link],
        Some(ROOM_PASS),
    );
    assert!(
        ok,
        "PRODUCT (staging): bob's `vox room join` failed: {out}{err}"
    );
    // Everyone reads everyone before the anchor stops: keys have flowed and every pair has a session.
    let mut pending: Vec<(&str, &str)> = Vec::new();
    for r in &members {
        for w in &members {
            if r.name != w.name {
                pending.push((r.name, w.name));
            }
        }
    }
    let start = Instant::now();
    let mut round = 0u32;
    while !pending.is_empty() {
        assert!(
            start.elapsed() < Duration::from_secs(90),
            "PRODUCT (staging): {pending:?} still unread after 90 s, before anyone died"
        );
        round += 1;
        for w in &members {
            if pending.iter().any(|(_, pw)| *pw == w.name) {
                let (ok, _, err) = w.vox(
                    &["room", "post", &room, &format!("warm-{}-{round}", w.name)],
                    None,
                );
                assert!(
                    ok,
                    "PRODUCT (staging): {}'s warm-up post failed: {err}",
                    w.name
                );
            }
        }
        std::thread::sleep(Duration::from_secs(1));
        for r in &members {
            let (_, out, _) = r.vox(&["room", "read", &room], None);
            pending.retain(|(pr, pw)| !(*pr == r.name && out.contains(&format!("warm-{pw}-"))));
        }
    }
    eprintln!("everyone reads everyone after {:?}", start.elapsed());
    // The two now hold a direct connection. The anchor keeps the room's log and would carry a post
    // the pair failed to exchange, which hides a push left to the interval: measured, streaks of
    // 5–7 failed sessions between members went unseen in a room of three with an anchor. Without
    // it, the pair's own push is the only way a post crosses.
    drop(anchor);
    eprintln!("[test] the anchor is stopped; alice and bob are each other's only path");

    // Both post at the same instant, then nothing more is posted until every member has
    // read every other's post. A push that collides past the quick retries is then carried only by
    // its own retry: with the old code, left to the 30 s interval; with the fix, backed off.
    let refused_before: Vec<u64> = members.iter().map(Member::busy_refused).collect();
    let stalls = Stalls::start();
    let mut worst = Duration::ZERO;
    let mut late: Vec<String> = Vec::new();
    let mut unmeasured: Vec<String> = Vec::new();
    for r in 1..=ROUNDS {
        std::thread::scope(|s| {
            for m in &members {
                let room = &room;
                s.spawn(move || {
                    let (ok, _, err) = m.vox(
                        &["room", "post", room, &format!("round-{r}-{}", m.name)],
                        None,
                    );
                    assert!(
                        ok,
                        "PRODUCT: {}'s `vox room post` in round {r} failed: {err}",
                        m.name
                    );
                });
            }
        });
        let posted = Instant::now();
        let mut unseen: Vec<(&str, &str)> = Vec::new();
        for rd in &members {
            for w in &members {
                if rd.name != w.name {
                    unseen.push((rd.name, w.name));
                }
            }
        }
        // Per crossing: when it was seen (the end of the read that showed it), and when the last
        // read that did not show it started — the crossing lies between the two.
        let mut seen_at: Vec<(String, &str, Duration, Duration)> = Vec::new();
        let mut missed_at: std::collections::HashMap<(&str, &str), Duration> =
            std::collections::HashMap::new();
        // Every `vox room read` this round, per reader: when it started and when it returned. A
        // read that itself took past the bound is a person waiting that long, whatever the poll.
        let mut reads: Vec<(&str, Duration, Duration)> = Vec::new();
        while !unseen.is_empty() && posted.elapsed() < Duration::from_secs(45) {
            for rd in &members {
                if !unseen.iter().any(|(x, _)| *x == rd.name) {
                    continue;
                }
                let asked = posted.elapsed();
                let (ok, out, err) = rd.vox(&["room", "read", &room], None);
                assert!(
                    ok,
                    "PRODUCT: {}'s `vox room read` in round {r} failed: {err}",
                    rd.name
                );
                let at = posted.elapsed();
                reads.push((rd.name, asked, at));
                unseen.retain(|(x, w)| {
                    if *x != rd.name {
                        return true;
                    }
                    if out.contains(&format!("round-{r}-{w}")) {
                        let missed = missed_at.get(&(*x, *w)).copied().unwrap_or_default();
                        seen_at.push((format!("{w}->{x}"), x, at, missed));
                        false
                    } else {
                        missed_at.insert((*x, *w), asked);
                        true
                    }
                });
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let slowest = seen_at
            .iter()
            .map(|(_, _, d, _)| *d)
            .max()
            .unwrap_or(Duration::MAX);
        eprintln!(
            "round {r}: slowest crossing {slowest:?}{}",
            if unseen.is_empty() {
                String::new()
            } else {
                format!(", never within 45 s: {unseen:?}")
            }
        );
        worst = worst.max(slowest);
        // A crossing past the bound is the product's if a read that started past the bound, plus
        // what the runner stalled meanwhile, still missed it; or if one of the reader's own `vox
        // room read`s took past the bound, less what the runner stalled during it, since a person
        // waits on that read. Otherwise the poll gap or the runner may have made it look late.
        let mut judge = |who: String, reader: &str, missed: Duration, seen: Option<Duration>| {
            let stalled = stalls.within(posted, posted + missed);
            let shown = match seen {
                Some(d) => format!("seen at {d:?}"),
                None => "never seen within 45 s".to_owned(),
            };
            let slow_read = reads
                .iter()
                .filter(|(n, asked, _)| *n == reader && seen.is_none_or(|d| *asked < d))
                .map(|(_, asked, at)| {
                    let stall = stalls.within(posted + *asked, posted + *at);
                    ((*at - *asked).saturating_sub(stall), *at - *asked, stall)
                })
                .max();
            if missed > BOUND + stalled {
                late.push(format!(
                    "round {r} {who}: still unread by a read started at {missed:?}, {shown} \
                     (runner stalled {stalled:?})"
                ));
            } else if let Some((net, took, stall)) = slow_read.filter(|(net, _, _)| *net > BOUND) {
                late.push(format!(
                    "round {r} {who}: {shown}; one of {reader}'s `vox room read`s itself took \
                     {took:?} (runner stalled {stall:?} during it, so {net:?} was vox's)"
                ));
            } else {
                unmeasured.push(format!(
                    "round {r} {who}: {shown}, but the last read that missed it started at \
                     {missed:?} and the runner stalled {stalled:?}, so it may have landed within \
                     {BOUND:?}"
                ));
            }
        };
        for (who, reader, d, missed) in &seen_at {
            if *d > BOUND {
                judge(who.clone(), reader, *missed, Some(*d));
            }
        }
        for (x, w) in &unseen {
            let missed = missed_at.get(&(*x, *w)).copied().unwrap_or_default();
            judge(format!("{w}->{x}"), x, missed, None);
        }
    }
    std::thread::sleep(Duration::from_secs(1));
    let refused: Vec<u64> = members
        .iter()
        .zip(&refused_before)
        .map(|(m, b)| {
            let now = m.busy_refused();
            now.checked_sub(*b).unwrap_or_else(|| {
                panic!(
                    "PRODUCT: {}'s busy_refused went backwards ({b} -> {now}); this proof never \
                     restarts a daemon, so vox restarted it or reset its counters",
                    m.name
                )
            })
        })
        .collect();
    eprintln!(
        "{ROUNDS} rounds, slowest crossing {worst:?}, {} late, {} unmeasurable",
        late.len(),
        unmeasured.len()
    );
    println!(
        "[proof] P6: {ROUNDS} rounds, slowest crossing {worst:?}, {} late, {} unmeasurable; \
         busy_refused alice {} bob {}",
        late.len(),
        unmeasured.len(),
        refused[0],
        refused[1]
    );
    assert_eq!(
        refused.iter().sum::<u64>(),
        0,
        "PRODUCT: two members posting at once refused each other (SessionBusy, from \
         `vox status --json`): alice {}, bob {}",
        refused[0],
        refused[1]
    );
    assert!(
        late.is_empty(),
        "PRODUCT: with every member posting at once, a post crossed later than {BOUND:?}: \
         {late:?} (a push that kept colliding was left to the 30 s interval, or `vox room read` \
         itself kept the reader waiting)"
    );
    assert!(
        unmeasured.is_empty(),
        "APPARATUS, CANNOT MEASURE: a crossing's window straddled {BOUND:?} only through the poll gap or a \
         runner stall: {unmeasured:?}"
    );
    drop(daemons);
}
