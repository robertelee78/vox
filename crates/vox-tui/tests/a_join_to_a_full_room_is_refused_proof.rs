//! **A join to a full room is refused, and says so**, through the shipped binary.
//!
//! **The defect.** A room admits at most `MAX_AUTHORS` members (1,024). The member answering a
//! join admits the joiner just before telling it it is in, and that admission's result was
//! dropped: past the cap the admission failed, the joiner was told `Accepted` anyway, and
//! `vox room join` printed "joined" and exited 0. The joiner was a member of nothing: the room's
//! roster did not list it, and the members' boards refused its records. Found by PRD-001 R2's
//! many-member proof run against a lowered cap, on v0.2.10 and v0.3.0 alike.
//!
//! **Staging**, every node the shipped `vox`, built with the `test-knobs` feature: an anchor; the
//! host's `vox daemon` with `VOX_TEST_MAX_AUTHORS` = [`CAP`], so the room is full at [`CAP`]
//! members, not 1,024; the host creates the room, and [`CAP`] − 1 members join it through their own
//! daemons, which are then stopped (SIGINT, as a person stops one), so the host is the only member
//! left to answer a join (a member
//! that had not yet learned every other would count fewer). The room is now full.
//!
//! **Asserted:** one more person's `vox room join`, asked once,
//! - exits non-zero (`PRODUCT:` if it says it joined);
//! - says the room is full with the cap in force, in its headline ("the room is full: it has
//!   [`CAP`] members, and a room takes [`CAP`]") and in its detail ("… [`CAP`] members, cap
//!   [`CAP`]");
//! - leaves the room out of that person's `vox room list`;
//! - and the host's `vox room roster` still lists exactly [`CAP`], the newcomer not among them.
//!
//! The joins that filled it are claims too: each exited 0 and the host answered it, admitting
//! before accepting into the store its roster reads, so a member it does not list is `PRODUCT:`.
//!
//! **A member that accepts the passphrase and then cannot admit the joiner says so**
//! ([`a_join_a_member_cannot_admit_says_why`]): a host that was locked or closing mid-join, or
//! could not write its store, refused its joiner with the refusal a wrong passphrase gets, so the
//! joiner was told "usually the room passphrase is wrong" about a passphrase that had been
//! accepted. Staged with `VOX_TEST_ADMISSION_FAILS` on the host (test-knobs only), which fails
//! each joiner's admission as a host locked mid-join does, admitting nothing. Asserted: the join
//! exits non-zero, says the passphrase was accepted and the member could not admit it, never
//! that the passphrase is likely wrong, and the host's roster lists the host alone.
//!
//! **Every red says which it is:** `PRODUCT:` quotes what `vox` said or did; `CANNOT MEASURE:`
//! names staging that was not achieved (a `vox` without the knob, a room not full when asked).
//!
//! **Joins at once never take a room past its cap** ([`joins_at_once_never_take_a_room_past_its_cap`],
//! V210-128; the decider ruled the cap strict): a newcomer is admitted only once every member
//! online to the one answering it agreed. Staged with the cap at [`STRICT_CAP`]: the host, bob
//! and carol all up and answering, dave offline (his daemon stopped), the room one place short.
//! Three newcomers join at once, one through each answering member's invite (an invite names its
//! member as the first to answer), each answering member holding a place for its newcomer at
//! `VOX_TEST_ADMISSION_GATE` (test-knobs only) until all three have reserved, then all asking at
//! once — the symmetric race where every one of them loses the last place. Asserted:
//! - at most one gets in;
//! - each refused newcomer exits non-zero, refused as full or as losing the last place to another
//!   join — anything else is `PRODUCT:`, quoted;
//! - **liveness**: when every racer lost the last place, a lone retry gets in (offline dave blocks
//!   nothing); the others are then refused as full;
//! - every answering member's roster lists exactly the cap, the same members, within
//!   [`CONVERGE_WITHIN`], and never more.
//!
//! **An online member that does not answer fails the join in time**
//! ([`a_member_that_does_not_answer_fails_the_join_in_time`]): bob is up and heard from, and never
//! answers whether a newcomer may join (`VOX_TEST_ADMIT_SILENT`, test-knobs only); a newcomer's
//! join fails non-zero, says a member did not answer in time, within a minute.
//!
//! **A frozen member is offline and blocks no join** ([`a_frozen_member_is_offline_and_blocks_no_join`]):
//! bob frozen (SIGSTOP), his connection still open and carrying nothing back, is what a member
//! that died without a word or a machine asleep looks like; a newcomer's join gets in.
//!
//! **Mutations that must turn it red:** the admission's result dropped again (in
//! `NetEvent::JoinAdmit`, the ack answered `Ok(())` whatever `admit_author` returned): the
//! newcomer is told it joined. A failed admission answered with `JoinReject::Refused` again (in
//! `run_responder`): the second arm's joiner is told its passphrase is likely wrong. Admission on
//! the answering member's own view only (`admit_agreed` asks nobody): the race lets all three in,
//! `PRODUCT:` at "at most one gets in".

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "support/test_knobs.rs"]
mod test_knobs;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use sync_pair::{anchor, Member, Proc, ROOM_PASS};

/// Stop a member's daemon as a person does (SIGINT), and wait for it to exit: it says goodbye on
/// every connection, so the others count it offline at once (a SIGKILLed one stays "online" to
/// them until its silence shows, and a join asking it then fails as unanswered).
fn stop(mut d: Proc) {
    d.signal("-INT");
    let t = std::time::Instant::now();
    while d.child.try_wait().ok().flatten().is_none() {
        assert!(
            t.elapsed() < std::time::Duration::from_secs(30),
            "PRODUCT: a daemon did not stop within 30 s of SIGINT"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// How many members the room holds when full, the host among them.
const CAP: usize = 3;
/// The knob that lowers the room's cap.
const KNOB: &str = "VOX_TEST_MAX_AUTHORS";
/// How soon every answering member's roster must agree at the cap.
const CONVERGE_WITHIN: std::time::Duration = std::time::Duration::from_secs(90);
/// The cap the strict-cap arms stage: three answering members, one offline, one place short.
const STRICT_CAP: usize = 5;
/// The knob that holds a member's admissions until a file appears.
const GATE: &str = "VOX_TEST_ADMISSION_GATE";
/// The knob that makes a member take every admission question and never answer it.
const SILENT: &str = "VOX_TEST_ADMIT_SILENT";
/// The knob that fails every joiner's admission on the member answering it.
const FAILS: &str = "VOX_TEST_ADMISSION_FAILS";

#[test]
#[ignore = "real binaries and production Argon2id: the release gate runs it"]
fn a_join_to_a_full_room_is_refused() {
    // A debug build's budget: three joins; an unlock for each `vox id` and daemon.
    watchdog::arm_for_setup(CAP as u32, (2 * CAP + 2) as u32);
    test_knobs::require(&[KNOB]);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let root = tmp.path();
    let (_anchor, spec) = anchor(root);
    let cap = CAP.to_string();
    let knob = [(KNOB, cap.as_str())];

    let host = Member::new(root, "host");
    let _host_d = host.daemon_with_anchor(Some(&spec), &knob);
    let room = host.create("full");
    let link = host.invite(&room);

    // ---- the room filled: CAP - 1 members besides the host, their daemons then stopped --------
    for name in ["m1", "m2"].into_iter().take(CAP - 1) {
        let m = Member::new(root, name);
        let d = m.daemon_with_anchor(Some(&spec), &knob);
        m.join(&link, "full");
        stop(d);
    }
    let roster = |who: &str| -> Vec<String> {
        let (ok, out, err) = host.vox(&["room", "roster", &room], None);
        assert!(
            ok,
            "PRODUCT: the host's `vox room roster` ({who}) failed: {err}"
        );
        out.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect()
    };
    let before = roster("before");
    assert_eq!(
        before.len(),
        CAP,
        // The host answered those joins and admits before it accepts, into the store the roster
        // reads: a join that exited 0 and is not listed is this defect, not the staging's.
        "PRODUCT: m1 and m2's joins exited 0, but the host's roster lists {} of {CAP}\n{before:?}",
        before.len()
    );

    // ---- one more: refused, and told why ------------------------------------------------------
    let late = Member::new(root, "late");
    let _late_d = late.daemon(Some(&spec));
    let (ok, out, err) = late.vox(&["room", "join", &link, "--name", "full"], Some(ROOM_PASS));
    let said = format!("{out}{err}");
    println!("[proof] the join to the full room exited ok={ok} and said:\n{said}");
    assert!(
        !ok,
        "PRODUCT: a join to a room already holding {CAP} members (its cap) exited 0:\n{said}"
    );
    // The headline states the cap in force, and the detail the count the member gave: both are
    // CAP here, never the shipped 1,024 a constant would say.
    for want in [
        format!("the room is full: it has {CAP} members, and a room takes {CAP}"),
        format!("the room is full: {CAP} members, cap {CAP}"),
    ] {
        assert!(
            said.contains(&want),
            "PRODUCT: the refused join did not say {want:?}:\n{said}"
        );
    }
    let (ok, list, err) = late.vox(&["room", "list"], None);
    assert!(ok, "PRODUCT: the newcomer's `vox room list` failed: {err}");
    let prefix = &room[..room.len().min(12)];
    assert!(
        !list.contains(prefix),
        "PRODUCT: the refused newcomer's `vox room list` lists the room it was refused:\n{list}"
    );
    let after = roster("after");
    assert!(
        after.len() == CAP && !after.contains(&late.fp),
        "PRODUCT: after the refused join the host's roster lists {} (want {CAP}, the newcomer not \
         among them)\n{after:?}",
        after.len()
    );
}

#[test]
#[ignore = "real binaries and production Argon2id: the release gate runs it"]
fn a_join_a_member_cannot_admit_says_why() {
    // A debug build's budget: one join; an unlock for each `vox id` and daemon.
    watchdog::arm_for_setup(1, 4);
    test_knobs::require(&[FAILS]);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let root = tmp.path();
    let (_anchor, spec) = anchor(root);
    let host = Member::new(root, "host");
    let _host_d = host.daemon_with_anchor(Some(&spec), &[(FAILS, "1")]);
    let room = host.create("locked");
    let link = host.invite(&room);

    let joiner = Member::new(root, "joiner");
    let _joiner_d = joiner.daemon(Some(&spec));
    let (ok, out, err) = joiner.vox(
        &["room", "join", &link, "--name", "locked"],
        Some(ROOM_PASS),
    );
    let said = format!("{out}{err}");
    println!("[proof] the join the host could not admit exited ok={ok} and said:\n{said}");
    assert!(
        !ok,
        "PRODUCT: a join the host could not admit exited 0:\n{said}"
    );
    let accepted = "a member accepted your passphrase, then could not admit you";
    assert!(
        said.contains(accepted),
        "PRODUCT: the refused join did not say {accepted:?}:\n{said}"
    );
    assert!(
        !said.contains("passphrase is wrong"),
        "PRODUCT: a join whose passphrase was accepted was told it is likely wrong:\n{said}"
    );
    let (ok, list, err) = joiner.vox(&["room", "list"], None);
    assert!(ok, "PRODUCT: the joiner's `vox room list` failed: {err}");
    assert!(
        !list.contains(&room[..room.len().min(12)]),
        "PRODUCT: the refused joiner's `vox room list` lists the room:\n{list}"
    );
    let (ok, roster, err) = host.vox(&["room", "roster", &room], None);
    assert!(ok, "PRODUCT: the host's `vox room roster` failed: {err}");
    let listed: Vec<&str> = roster
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    assert!(
        listed == [host.fp.as_str()],
        "PRODUCT: the host admitted nobody, yet its roster lists {listed:?}"
    );
}

/// Run `vox room join` for each `(member, link)` at once, as many people would; what each said.
fn join_all<'a>(joins: &[(&'a Member, &str)], room: &str) -> Vec<(&'a Member, bool, String)> {
    std::thread::scope(|s| {
        let handles: Vec<_> = joins
            .iter()
            .map(|(m, link)| {
                let m: &Member = m;
                s.spawn(move || m.vox(&["room", "join", link, "--name", room], Some(ROOM_PASS)))
            })
            .collect();
        joins
            .iter()
            .zip(handles)
            .map(|((m, _), h)| {
                let (ok, out, err) = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
                (*m, ok, format!("{out}{err}"))
            })
            .collect()
    })
}

/// A refused join says why, as one of the two refusals a racing join may get; anything else is
/// the product's, quoted.
fn refused_as_full_or_busy(m: &Member, said: &str) -> bool {
    let full = said.contains("the room is full");
    let busy = said.contains("the room's last place is being taken by another join; try again");
    assert!(
        full || busy,
        "PRODUCT: {}'s join was refused, and not as full or as losing the last place to another \
         join:\n{said}",
        m.name
    );
    busy
}

/// A member's `vox room roster`, one fingerprint per entry.
fn roster_of(m: &Member, room: &str) -> Vec<String> {
    let (ok, out, err) = m.vox(&["room", "roster", room], None);
    assert!(ok, "PRODUCT: {}'s `vox room roster` failed: {err}", m.name);
    out.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

#[test]
#[ignore = "real binaries and production Argon2id: the release gate runs it"]
fn joins_at_once_never_take_a_room_past_its_cap() {
    // A debug build's budget: seven joins; an unlock for each `vox id` and daemon.
    watchdog::arm_for_setup(9, 20);
    test_knobs::require(&[KNOB, GATE]);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let root = tmp.path();
    let (_anchor, spec) = anchor(root);
    let cap = STRICT_CAP.to_string();
    // The admission gate, open (the file is there) until the race: see below.
    let gate = root.join("gate");
    std::fs::write(&gate, b"").expect("APPARATUS: cannot open the admission gate");
    let gate_s = gate
        .to_str()
        .expect("APPARATUS: a UTF-8 temp dir")
        .to_owned();
    let knob = [(KNOB, cap.as_str()), (GATE, gate_s.as_str())];

    // ---- three members answering, all up; a fourth offline: the room one place short ----------
    let host = Member::new(root, "host");
    let _host_d = host.daemon_with_anchor(Some(&spec), &knob);
    let room = host.create("strict");
    let host_link = host.invite(&room);
    let bob = Member::new(root, "bob");
    let _bob_d = bob.daemon_with_anchor(Some(&spec), &knob);
    bob.join(&host_link, "strict");
    let carol = Member::new(root, "carol");
    let _carol_d = carol.daemon_with_anchor(Some(&spec), &knob);
    carol.join(&host_link, "strict");
    // Offline from here on: its daemon is stopped, so nobody holds a connection to it and it
    // blocks no join (the ruling: an offline member does not block).
    let dave = Member::new(root, "dave");
    let dave_d = dave.daemon_with_anchor(Some(&spec), &knob);
    dave.join(&host_link, "strict");
    stop(dave_d);
    let answerers = [&host, &bob, &carol];
    let links: Vec<String> = answerers.iter().map(|m| m.invite(&room)).collect();
    let before = roster_of(&host, &room);
    assert_eq!(
        before.len(),
        STRICT_CAP - 1,
        "PRODUCT: three joins exited 0, but the host's roster lists {} of {} before the race\n\
         {before:?}",
        before.len(),
        STRICT_CAP - 1
    );

    // ---- three newcomers at once, one through each answering member, held and let go together --
    let newcomers: Vec<Member> = ["x", "y", "z"]
        .iter()
        .map(|n| Member::new(root, n))
        .collect();
    let _newcomer_ds: Vec<_> = newcomers
        .iter()
        .map(|m| m.daemon_with_anchor(Some(&spec), &knob))
        .collect();
    std::fs::remove_file(&gate).expect("APPARATUS: cannot close the admission gate");
    let reached = || {
        std::fs::read_dir(root)
            .expect("APPARATUS: cannot list the temp dir")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("gate.reached."))
            .count()
    };
    let joins: Vec<(&Member, &str)> = newcomers
        .iter()
        .zip(links.iter())
        .map(|(m, l)| (m, l.as_str()))
        .collect();
    let raced = std::thread::scope(|s| {
        let opener = s.spawn(|| {
            let t0 = std::time::Instant::now();
            while reached() < 3 && t0.elapsed() < std::time::Duration::from_secs(50) {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            let held = reached();
            std::fs::write(&gate, b"").expect("APPARATUS: cannot open the admission gate");
            held
        });
        let raced = join_all(&joins, "strict");
        let held = opener
            .join()
            .unwrap_or_else(|e| std::panic::resume_unwind(e));
        assert!(
            held == 3,
            "CANNOT MEASURE: {held} of the 3 answering members reached the admission gate within \
             50 s, so the joins were not held to race"
        );
        raced
    });
    for (m, ok, said) in &raced {
        println!("[proof] race: {}'s join exited ok={ok}:\n{said}", m.name);
    }
    let got_in: Vec<&Member> = raced.iter().filter(|r| r.1).map(|r| r.0).collect();
    assert!(
        got_in.len() <= 1,
        "PRODUCT: {} newcomers got into a room one place short of its cap of {STRICT_CAP}: {:?}",
        got_in.len(),
        got_in.iter().map(|m| m.name).collect::<Vec<_>>()
    );
    let mut busy: Vec<&Member> = Vec::new();
    for (m, ok, said) in &raced {
        if !ok && refused_as_full_or_busy(m, said) {
            busy.push(m);
        }
    }
    println!(
        "[proof] race: {} got in, {} told the last place was being taken",
        got_in.len(),
        busy.len()
    );

    // ---- liveness: when every racer lost the last place, a retry gets one of them in ----------
    if got_in.is_empty() {
        let first = busy
            .first()
            .copied()
            .expect("PRODUCT: no newcomer got in and none was told to try again");
        let link = &links[newcomers
            .iter()
            .position(|n| n.name == first.name)
            .expect("APPARATUS: a newcomer of the race")];
        let (ok, out, err) =
            first.vox(&["room", "join", link, "--name", "strict"], Some(ROOM_PASS));
        println!(
            "[proof] liveness: {}'s retry exited ok={ok}:\n{out}{err}",
            first.name
        );
        assert!(
            ok,
            "PRODUCT: every racer lost the last place, and a lone retry still did not get in:\n\
             {out}{err}"
        );
    }
    // The others, asked again, are told the room is full: it is now.
    let inside = |m: &Member| roster_of(&host, &room).contains(&m.fp);
    for m in &newcomers {
        if inside(m) {
            continue;
        }
        let link = &links[newcomers.iter().position(|n| n.name == m.name).unwrap()];
        let (ok, out, err) = m.vox(&["room", "join", link, "--name", "strict"], Some(ROOM_PASS));
        let said = format!("{out}{err}");
        assert!(
            !ok && said.contains("the room is full"),
            "PRODUCT: a join to the room at its cap, after the race, was not refused as full \
             (exit ok: {ok}):\n{said}"
        );
    }

    // ---- every answering member's roster: the cap exactly, and the same members ---------------
    let t0 = std::time::Instant::now();
    loop {
        let rosters: Vec<Vec<String>> = answerers.iter().map(|m| roster_of(m, &room)).collect();
        for (m, r) in answerers.iter().zip(&rosters) {
            assert!(
                r.len() <= STRICT_CAP,
                "PRODUCT: {}'s roster lists {} members, past the cap of {STRICT_CAP}\n{r:?}",
                m.name,
                r.len()
            );
        }
        let agree = rosters
            .iter()
            .all(|r| r.len() == STRICT_CAP && sorted(r) == sorted(&rosters[0]));
        if agree {
            println!(
                "[proof] every answering member's roster lists the cap, {STRICT_CAP}, and the same \
                 members, {:?} after the joins",
                t0.elapsed()
            );
            break;
        }
        assert!(
            t0.elapsed() < CONVERGE_WITHIN,
            "PRODUCT: {CONVERGE_WITHIN:?} after the joins, the answering members' rosters do not \
             agree at the cap of {STRICT_CAP}: {rosters:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

fn sorted(v: &[String]) -> Vec<String> {
    let mut v = v.to_vec();
    v.sort();
    v
}

/// A room of `host` and `bob`, bob's daemon started with `bob_env`, and bob on the host's roster.
fn host_and_bob(
    root: &std::path::Path,
    spec: &str,
    bob_env: &[(&str, &str)],
) -> (Member, Proc, Member, Proc, String, String) {
    let cap = STRICT_CAP.to_string();
    let knob = [(KNOB, cap.as_str())];
    let host = Member::new(root, "host");
    let host_d = host.daemon_with_anchor(Some(spec), &knob);
    let room = host.create("bound");
    let link = host.invite(&room);
    let bob = Member::new(root, "bob");
    let mut env: Vec<(&str, &str)> = knob.to_vec();
    env.extend_from_slice(bob_env);
    let bob_d = bob.daemon_with_anchor(Some(spec), &env);
    bob.join(&link, "bound");
    let t0 = std::time::Instant::now();
    while !roster_of(&host, &room).contains(&bob.fp) {
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(30),
            "PRODUCT: bob's join exited 0, but the host's roster never listed him"
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    (host, host_d, bob, bob_d, room, link)
}

#[test]
#[ignore = "real binaries and production Argon2id: the release gate runs it"]
fn a_member_that_does_not_answer_fails_the_join_in_time() {
    // A debug build's budget: three joins; an unlock for each `vox id` and daemon.
    watchdog::arm_for_setup(3, 8);
    test_knobs::require(&[KNOB, SILENT]);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let root = tmp.path();
    let (_anchor, spec) = anchor(root);
    // Bob is up, his connection heard from, and he never answers whether a newcomer may join.
    let (_host, _host_d, _bob, _bob_d, _room, link) = host_and_bob(root, &spec, &[(SILENT, "1")]);
    let late = Member::new(root, "late");
    let _late_d = late.daemon_with_anchor(Some(&spec), &[]);
    let t = std::time::Instant::now();
    let (ok, out, err) = late.vox(&["room", "join", &link, "--name", "bound"], Some(ROOM_PASS));
    let took = t.elapsed();
    let said = format!("{out}{err}");
    println!("[proof] the join with bob never answering exited ok={ok} after {took:?}:\n{said}");
    assert!(
        !ok,
        "PRODUCT: a join was admitted while an online member (bob, up and not answering) never \
         agreed:\n{said}"
    );
    assert!(
        said.contains("did not answer in time"),
        "PRODUCT: the join refused while bob did not answer did not say a member did not answer \
         in time:\n{said}"
    );
    assert!(
        took < std::time::Duration::from_secs(60),
        "PRODUCT: the join took {took:?} to fail: an unanswering member must end it within its \
         bound, not hang"
    );
}

#[test]
#[ignore = "real binaries and production Argon2id: the release gate runs it"]
fn a_frozen_member_is_offline_and_blocks_no_join() {
    // A debug build's budget: two joins; an unlock for each `vox id` and daemon.
    watchdog::arm_for_setup(2, 6);
    test_knobs::require(&[KNOB]);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let root = tmp.path();
    let (_anchor, spec) = anchor(root);
    let (host, _host_d, bob, bob_d, room, link) = host_and_bob(root, &spec, &[]);
    // Bob frozen: his connection to the host is still open, and carries nothing back — as a
    // process that died without a word, or a machine asleep. Offline: it blocks nothing.
    let late = Member::new(root, "late");
    let _late_d = late.daemon_with_anchor(Some(&spec), &[]);
    bob_d.signal("-STOP");
    let t = std::time::Instant::now();
    let (ok, out, err) = late.vox(&["room", "join", &link, "--name", "bound"], Some(ROOM_PASS));
    let took = t.elapsed();
    bob_d.signal("-CONT");
    let said = format!("{out}{err}");
    println!("[proof] the join with bob frozen exited ok={ok} after {took:?}:\n{said}");
    assert!(
        ok,
        "PRODUCT: a frozen member (bob, his connection carrying nothing back) blocked a join; an \
         offline member must not:\n{said}"
    );
    assert!(
        roster_of(&host, &room).contains(&late.fp),
        "PRODUCT: the join exited 0 and the host's roster does not list the newcomer"
    );
    let _ = bob;
}
