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
//! daemons, which are then stopped, so the host is the only member left to answer a join (a member
//! that had not yet learned every other would count fewer). The room is now full.
//!
//! **Asserted:** one more person's `vox room join`, asked once,
//! - exits non-zero (`PRODUCT:` if it says it joined);
//! - says the room is full, with the count the refusing member gave ("the room is full: [`CAP`]
//!   members"), and that the newcomer was not admitted; it promises no cap;
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
//! **A room never exceeds its cap: every member online agrees** (V030-30, #366; the decider,
//! 2026-10-02). The member answering a join holds a place, asks every member it holds a connection
//! to, and admits only once each has promised it (`node::seatstream`).
//!
//! - **Strict** ([`three_members_answering_at_once_never_take_the_room_past_its_cap`]): the cap at
//!   [`STRICT_CAP`], three members at the cap less one, three newcomers each joining by a different
//!   member's invite, each held by `VOX_TEST_ADMISSION_GATE` until all three members are about to
//!   decide, then let go together. Asserted: at most one is told it joined; each other is told the
//!   room is full or that its last place went to another newcomer; every member's roster is the same
//!   and within the cap; and a refused newcomer that tries again gets the place if nobody took it
//!   (an aborted promise frees it), or is told the room is full. Fewer than three members at the
//!   gate: CANNOT MEASURE.
//! - **Bound** ([`a_member_online_that_does_not_answer_fails_the_join_and_is_named`]): bob, whom
//!   the host holds a connection to and hears from (checked in the host's `vox status`), never
//!   answers a seat question (`VOX_TEST_SEAT_SILENT`); a newcomer the host answers is refused, told
//!   "member bob did not answer within 5s", bob named by the newcomer's own name for him, and is
//!   not on the host's roster. A member whose process is gone is offline and blocks nothing (RP-02).
//! - **Split** ([`a_split_room_keeps_both_newcomers_and_says_it_passed_its_cap`]): no anchor between
//!   them; the host admits a newcomer while bob is down, and bob one while the host is down, each
//!   checked from its own `vox status` to hold no connection to the other, and each at the cap less
//!   one: an offline member blocks nothing. x goes down after its join and stays down to the end
//!   (it would otherwise tell bob of itself), and bob is checked not to know x. The host and bob up
//!   together again, both rosters list both newcomers, one past the cap, and a member's log says
//!   so (the decider's ruling (a)): bob learns of x, offline, from the admission notice the host
//!   keeps (#520).
//!
//! **Mutations that must turn it red:** the admission's result dropped again (in
//! `NetEvent::JoinAdmit`, the ack answered `Ok(())` whatever `admit_author` returned): the
//! newcomer is told it joined. A failed admission answered with `JoinReject::Refused` again (in
//! `run_responder`): the second arm's joiner is told its passphrase is likely wrong. The seat round
//! skipped, so the answering member admits on its own view (`seat_round` not run): the strict arm's
//! three newcomers are all told they joined, `PRODUCT:`. The admitting member keeping no admission
//! notice (#520, in `NetEvent::JoinAdmit` and `admit_from_board`): the split arm's bob never lists
//! x, offline, `PRODUCT:`.
#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "support/test_knobs.rs"]
mod test_knobs;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use sync_pair::{anchor, Member, ROOM_PASS};

/// How many members the room holds when full, the host among them.
const CAP: usize = 3;
/// The knob that makes a member read each seat question and never answer.
const SILENT: &str = "VOX_TEST_SEAT_SILENT";
/// The strict and bound arms' cap: three members answering, one place left.
const STRICT_CAP: usize = 4;
/// The knob that lowers the room's cap.
const KNOB: &str = "VOX_TEST_MAX_AUTHORS";
/// How soon both members' rosters must list every newcomer told it joined.
const CONVERGE_WITHIN: std::time::Duration = std::time::Duration::from_secs(90);
/// The knob that holds a member's admissions until a file appears.
const GATE: &str = "VOX_TEST_ADMISSION_GATE";
/// The knob that fails every joiner's admission on the member answering it.
const FAILS: &str = "VOX_TEST_ADMISSION_FAILS";
/// What a member logs when it admits a member past the room's cap ([`CAP`] = 3).
const PAST_CAP: &str = "past its cap of 3, now 4 members: another member admitted it";

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
        drop(d);
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
    let (ok, out, err) = late.vox(
        &["room", "join", "--passphrase-file", "-", &link],
        Some(ROOM_PASS),
    );
    let said = format!("{out}{err}");
    println!("[proof] the join to the full room exited ok={ok} and said:\n{said}");
    assert!(
        !ok,
        "PRODUCT: a join to a room already holding {CAP} members (its cap) exited 0:\n{said}"
    );
    // The count the refusing member gave (CAP here, never the shipped 1,024 a constant would say),
    // and that the newcomer was not admitted. No cap is promised (decider, plan 21874119).
    for want in [
        format!("the room is full: {CAP} members"),
        "the room is full, so you were not admitted".to_owned(),
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
        &["room", "join", "--passphrase-file", "-", &link],
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

/// `who`'s `vox room roster` of `room`, one member per line.
fn roster(who: &Member, room: &str) -> Vec<String> {
    let (ok, out, err) = who.vox(&["room", "roster", room], None);
    assert!(
        ok,
        "PRODUCT: {}'s `vox room roster` failed: {err}",
        who.name
    );
    out.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// `who`'s `vox room join` of `link`, asked once: whether it exited 0, and what it said.
fn join(who: &Member, link: &str) -> (bool, String) {
    let (ok, out, err) = who.vox(
        &["room", "join", "--passphrase-file", "-", link],
        Some(ROOM_PASS),
    );
    (ok, format!("{out}{err}"))
}

/// Whether `who`'s `vox status --json` shows a connection to `other` in any room: what the node
/// itself holds, the one view a staging of "online" or "offline" is checked against.
fn connected(who: &Member, other: &Member) -> bool {
    who.status()["rooms"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r["members"].as_array())
        .flatten()
        .any(|m| m["id"].as_str() == Some(other.fp.as_str()) && m["connected"] == true)
}

/// Wait until every member in `members` lists exactly `want` on its roster of `room`, or say
/// CANNOT MEASURE: the members did not all know each other before the race, so it measured nothing.
fn all_know(members: &[&Member], room: &str, want: usize) {
    let t0 = std::time::Instant::now();
    loop {
        let counts: Vec<usize> = members.iter().map(|m| roster(m, room).len()).collect();
        if counts.iter().all(|c| *c == want) {
            return;
        }
        assert!(
            t0.elapsed() < CONVERGE_WITHIN,
            "CANNOT MEASURE: the members' rosters list {counts:?}, not {want} each, \
             {CONVERGE_WITHIN:?} after they joined: a member not knowing every other counts fewer"
        );
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// **A room never exceeds its cap: every member online agrees** (V030-30, #366). Three members at
/// the cap less one, each answering its own newcomer, all held at the admission gate and let go
/// together.
#[test]
#[ignore = "real binaries and production Argon2id: the release gate runs it"]
fn three_members_answering_at_once_never_take_the_room_past_its_cap() {
    // A debug build's budget: six joins; an unlock for each `vox id` and daemon.
    watchdog::arm_for_setup(6, 14);
    test_knobs::require(&[KNOB, GATE]);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let root = tmp.path();
    let (_anchor, spec) = anchor(root);
    let cap = STRICT_CAP.to_string();
    let gate = root.join("gate");
    std::fs::write(&gate, b"").expect("APPARATUS: cannot open the admission gate");
    let gate_s = gate
        .to_str()
        .expect("APPARATUS: a UTF-8 temp dir")
        .to_owned();
    let knob = [(KNOB, cap.as_str()), (GATE, gate_s.as_str())];

    // ---- three members, the room one place short of STRICT_CAP = 4 ----------------------------
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
    all_know(&[&host, &bob, &carol], &room, STRICT_CAP - 1);
    let links = [host_link, bob.invite(&room), carol.invite(&room)];

    // ---- three newcomers at once, each from a different member's invite ------------------------
    let newcomers = [
        Member::new(root, "x"),
        Member::new(root, "y"),
        Member::new(root, "z"),
    ];
    let _newcomer_d: Vec<_> = newcomers
        .iter()
        .map(|n| n.daemon_with_anchor(Some(&spec), &knob))
        .collect();
    std::fs::remove_file(&gate).expect("APPARATUS: cannot close the admission gate");
    let reached = || {
        std::fs::read_dir(root)
            .expect("APPARATUS: cannot list the temp dir")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("gate.reached."))
            .count()
    };
    let joined: Vec<(&Member, bool, String)> = std::thread::scope(|s| {
        let opener = s.spawn(|| {
            let t0 = std::time::Instant::now();
            while reached() < 3 && t0.elapsed() < std::time::Duration::from_secs(50) {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            let held = reached();
            std::fs::write(&gate, b"").expect("APPARATUS: cannot open the admission gate");
            held
        });
        let handles: Vec<_> = newcomers
            .iter()
            .zip(&links)
            .map(|(n, l)| (n, s.spawn(move || join(n, l))))
            .collect();
        let held = opener
            .join()
            .unwrap_or_else(|e| std::panic::resume_unwind(e));
        assert!(
            held == 3,
            "CANNOT MEASURE: {held} of the 3 members reached the admission gate within 50 s, so the \
             joins were not answered at once"
        );
        handles
            .into_iter()
            .map(|(n, h)| {
                let (ok, said) = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
                (n, ok, said)
            })
            .collect()
    });
    for (n, ok, said) in &joined {
        println!("[proof] {}'s join exited ok={ok}:\n{said}", n.name);
    }
    let admitted: Vec<&Member> = joined.iter().filter(|j| j.1).map(|j| j.0).collect();
    // A refusal says the room is full, or that the last place went to another newcomer; anything
    // else is the product's, quoted.
    for (n, ok, said) in &joined {
        if !ok && !said.contains("the room is full") && !said.contains("took the room's last place")
        {
            panic!(
                "PRODUCT: {}'s join was refused for something other than a full room or a place \
                 taken at the same moment:\n{said}",
                n.name
            );
        }
    }
    assert!(
        admitted.len() <= 1,
        "PRODUCT: the room held {} with one place left, and {} newcomers answered at once by \
         different members were told they joined: {:?}",
        STRICT_CAP - 1,
        admitted.len(),
        admitted.iter().map(|m| m.name).collect::<Vec<_>>()
    );

    // ---- every member's roster: the same, and never past the cap -------------------------------
    std::thread::sleep(std::time::Duration::from_secs(5));
    let want = STRICT_CAP - 1 + admitted.len();
    all_know(&[&host, &bob, &carol], &room, want);
    let rosters: Vec<Vec<String>> = [&host, &bob, &carol]
        .iter()
        .map(|m| roster(m, &room))
        .collect();
    assert!(
        rosters
            .iter()
            .all(|r| r == &rosters[0] && r.len() <= STRICT_CAP),
        "PRODUCT: the members' rosters differ or pass the cap of {STRICT_CAP}: {rosters:?}"
    );
    println!(
        "[proof] {} of 3 newcomers admitted; every roster lists {want} (cap {STRICT_CAP})",
        admitted.len()
    );

    // ---- told to try again, and it works: no place is kept for a newcomer that lost ------------
    let again = joined
        .iter()
        .find(|j| !j.1)
        .map(|j| j.0)
        .expect("CANNOT MEASURE: every newcomer was told it joined (already PRODUCT above)");
    let (ok, said) = join(again, &links[0]);
    println!("[proof] {} tried again: ok={ok}:\n{said}", again.name);
    if admitted.is_empty() {
        assert!(
            ok,
            "PRODUCT: no newcomer was admitted, so the place is free, and {}'s second try was \
             refused: an aborted promise kept it:\n{said}",
            again.name
        );
    } else {
        assert!(
            !ok && said.contains("the room is full"),
            "PRODUCT: the room is at its cap of {STRICT_CAP}, and {}'s second try did not say it \
             is full (ok={ok}):\n{said}",
            again.name
        );
    }
}

/// **A member online that does not answer fails the join, named** (V030-30, #366): bob, whom the
/// host holds a connection to and hears from, reads the seat question and never answers
/// (`VOX_TEST_SEAT_SILENT`, test-knobs only, as a member whose node is stuck); a newcomer the host
/// answers is refused within the bound, and told which member by its own name for it. (A member
/// whose process is gone, crashed or stopped, is offline and blocks nothing: RP-02,
/// `a_join_is_not_hostage_to_one_member_proof`.)
#[test]
#[ignore = "real binaries and production Argon2id: the release gate runs it"]
fn a_member_online_that_does_not_answer_fails_the_join_and_is_named() {
    watchdog::arm_for_setup(2, 8);
    test_knobs::require(&[KNOB, SILENT]);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let root = tmp.path();
    let (_anchor, spec) = anchor(root);
    let cap = STRICT_CAP.to_string();
    let knob = [(KNOB, cap.as_str())];
    let host = Member::new(root, "host");
    let _host_d = host.daemon_with_anchor(Some(&spec), &knob);
    let room = host.create("bound");
    let link = host.invite(&room);
    let bob = Member::new(root, "bob");
    let _bob_d = bob.daemon_with_anchor(Some(&spec), &[(KNOB, cap.as_str()), (SILENT, "1")]);
    bob.join(&link, "bound");
    let late = Member::new(root, "late");
    // The newcomer's own name for bob, which it is to be told.
    late.trust(&bob);
    let _late_d = late.daemon_with_anchor(Some(&spec), &knob);

    // ---- staged, from the host's own view: it holds a connection to bob --------------------------
    let t0 = std::time::Instant::now();
    while !connected(&host, &bob) {
        assert!(
            t0.elapsed() < CONVERGE_WITHIN,
            "CANNOT MEASURE: the host's `vox status` shows no connection to bob after \
             {CONVERGE_WITHIN:?}, so bob is not a member it would ask"
        );
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    let t1 = std::time::Instant::now();
    let (ok, said) = join(&late, &link);
    let took = t1.elapsed();
    println!("[proof] the join with bob not answering exited ok={ok} after {took:?}:\n{said}");
    assert!(
        !ok,
        "PRODUCT: a member online (bob) never answered, so it never agreed, and the newcomer was \
         told it joined:\n{said}"
    );
    assert!(
        said.contains("member bob did not answer within 5s"),
        "PRODUCT: the refused join did not name bob, by the newcomer's own name for him, as the \
         member that did not answer within 5s:\n{said}"
    );
    assert!(
        !roster(&host, &room).contains(&late.fp),
        "PRODUCT: the refused newcomer is on the host's roster"
    );
}

/// **The only way past the cap is a split, and it is said** (V030-30, #366; the decider's ruling
/// (a)). With no anchor between them, the host admits a newcomer while bob is down, and bob one
/// while the host and x are down, each at the cap less one: an offline member blocks nothing. The
/// host and bob up together again, x still down, both keep both newcomers, one past the cap, and a
/// member says so: every member learns of a newcomer while it is offline (#520).
#[test]
#[ignore = "real binaries and production Argon2id: the release gate runs it"]
fn a_split_room_keeps_both_newcomers_and_says_it_passed_its_cap() {
    watchdog::arm_for_setup(3, 10);
    test_knobs::require(&[KNOB]);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let root = tmp.path();
    let cap = CAP.to_string();
    let knob = [(KNOB, cap.as_str())];
    let host = Member::new(root, "host");
    let host_d = host.daemon_with(&knob);
    let room = host.create("split");
    let host_link = host.invite(&room);
    let bob = Member::new(root, "bob");
    let bob_d = bob.daemon_with(&knob);
    bob.join(&host_link, "split");
    all_know(&[&host, &bob], &room, CAP - 1);
    let bob_link = bob.invite(&room);
    let (x, y) = (Member::new(root, "x"), Member::new(root, "y"));
    let x_d = x.daemon_with(&knob);
    let _y_d = y.daemon_with(&knob);

    // ---- bob down: the host admits x, and, from its own view, asked nobody ----------------------
    drop(bob_d);
    let t0 = std::time::Instant::now();
    while connected(&host, &bob) {
        assert!(
            t0.elapsed() < CONVERGE_WITHIN,
            "CANNOT MEASURE: the host's `vox status` still shows a connection to bob, stopped \
             {CONVERGE_WITHIN:?} ago"
        );
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    let (ok, said) = join(&x, &host_link);
    assert!(
        ok,
        "PRODUCT: with bob offline, x's join through the host was refused:\n{said}"
    );

    // ---- the host down, bob up: bob admits y, knowing nothing of x -------------------------------
    // x goes down with the host and stays down: x, a member now, would dial bob once he is back and
    // tell him of itself, and the two sides would not be split. Bob learns of x, offline, from the
    // admission notice the host keeps (#520).
    drop(x_d);
    let host_said = host_d.transcript();
    drop(host_d);
    let bob_d = bob.daemon_with(&knob);
    assert!(
        !connected(&bob, &host),
        "CANNOT MEASURE: bob's `vox status` shows a connection to the host, which is stopped"
    );
    assert!(
        !roster(&bob, &room).contains(&x.fp),
        "CANNOT MEASURE: bob already knows x, so the two sides did not split"
    );
    let (ok, said) = join(&y, &bob_link);
    assert!(
        ok || !roster(&bob, &room).contains(&x.fp),
        "CANNOT MEASURE: y's join through bob was refused, and bob now knows x, so the two sides \
         did not stay split:\n{said}"
    );
    assert!(
        ok,
        "PRODUCT: with the host and x offline, y's join through bob was refused, and bob does \
         not know x:\n{said}"
    );

    // ---- the host and bob up, x still down: both keep both newcomers, and say the room passed its
    // cap ------------------------------------------------------------------------------------------
    let host_d = host.daemon_with(&knob);
    let want: Vec<&str> = [&host, &bob, &x, &y]
        .iter()
        .map(|m| m.fp.as_str())
        .collect();
    let t1 = std::time::Instant::now();
    loop {
        let (on_host, on_bob) = (roster(&host, &room), roster(&bob, &room));
        let has_all = |r: &Vec<String>| want.iter().all(|w| r.iter().any(|m| m == w));
        if has_all(&on_host) && has_all(&on_bob) {
            break;
        }
        assert!(
            t1.elapsed() < CONVERGE_WITHIN,
            "PRODUCT: after the split healed, the host lists {} and bob {} of the 4 members \
             {CONVERGE_WITHIN:?} later: the room did not converge\nhost: {on_host:?}\nbob: {on_bob:?}",
            on_host.len(),
            on_bob.len()
        );
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    let t2 = std::time::Instant::now();
    let said = loop {
        let said = format!("{host_said}{}{}", host_d.transcript(), bob_d.transcript());
        if said.contains(PAST_CAP) || t2.elapsed() > CONVERGE_WITHIN {
            break said;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    };
    assert!(
        said.contains(PAST_CAP),
        "PRODUCT: the split room holds 4 at a cap of {CAP} and neither member's log says so:\n{said}"
    );
    println!(
        "[proof] the split healed: both list all 4, one past the cap of {CAP}, and it is said"
    );
}
