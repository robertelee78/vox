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
//! **Joins that race converge** ([`joins_answered_at_once_by_two_members_converge`], V210-128):
//! each member checks the cap against its own view, so two newcomers answered at the same moment
//! by two different members can each take the room's last place. Before, each member then
//! refused the newcomer the other had admitted, as over the cap: the room split, each newcomer a
//! member on one side only, told it had joined. Now a member admits what another admitted, up to
//! the cap plus the join slots (`AUTHORS_CEILING`): the cap is soft by at most that. Staged with
//! the cap at [`CAP`]: the host and one member, both up, and the room one place short; two
//! newcomers join at once, one from each member's invite (an invite names its member as the
//! first to answer), each held by `VOX_TEST_ADMISSION_GATE` (test-knobs only) at its admission
//! until both members are about to admit, then let go together. Asserted: every newcomer told it joined is on **both** members' rosters
//! within [`CONVERGE_WITHIN`], and neither roster ever lists more than the ceiling. If only one
//! newcomer got in, the joins did not race: CANNOT MEASURE.
//!
//! **Mutations that must turn it red:** the admission's result dropped again (in
//! `NetEvent::JoinAdmit`, the ack answered `Ok(())` whatever `admit_author` returned): the
//! newcomer is told it joined. A failed admission answered with `JoinReject::Refused` again (in
//! `run_responder`): the second arm's joiner is told its passphrase is likely wrong. A member
//! learned from a board refused past the cap again (`admit_from_board` limited to the cap, not
//! the ceiling): the racing arm's rosters never converge.

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
/// The knob that lowers the room's cap.
const KNOB: &str = "VOX_TEST_MAX_AUTHORS";
/// How soon both members' rosters must list every newcomer told it joined.
const CONVERGE_WITHIN: std::time::Duration = std::time::Duration::from_secs(90);
/// How far past the cap joins answered at once can take a room (`JOIN_OVERSHOOT`).
const OVERSHOOT: usize = 16;
/// The knob that holds a member's admissions until a file appears.
const GATE: &str = "VOX_TEST_ADMISSION_GATE";
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

#[test]
#[ignore = "real binaries and production Argon2id: the release gate runs it"]
fn joins_answered_at_once_by_two_members_converge() {
    // A debug build's budget: three joins; an unlock for each `vox id` and daemon.
    watchdog::arm_for_setup(3, 8);
    test_knobs::require(&[KNOB, GATE]);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let root = tmp.path();
    let (_anchor, spec) = anchor(root);
    let cap = CAP.to_string();
    // The admission gate, open (the file is there) until the race: see below.
    let gate = root.join("gate");
    std::fs::write(&gate, b"").expect("APPARATUS: cannot open the admission gate");
    let gate_s = gate
        .to_str()
        .expect("APPARATUS: a UTF-8 temp dir")
        .to_owned();
    let knob = [(KNOB, cap.as_str()), (GATE, gate_s.as_str())];

    // ---- the host and one member, both up: the room one place short of CAP = 3 ---------------
    let host = Member::new(root, "host");
    let _host_d = host.daemon_with_anchor(Some(&spec), &knob);
    let room = host.create("race");
    let host_link = host.invite(&room);
    let bob = Member::new(root, "bob");
    let _bob_d = bob.daemon_with_anchor(Some(&spec), &knob);
    bob.join(&host_link, "race");
    let bob_link = bob.invite(&room);

    // ---- two newcomers at once: x from the host's invite, y from bob's -------------------------
    let x = Member::new(root, "x");
    let y = Member::new(root, "y");
    let _x_d = x.daemon_with_anchor(Some(&spec), &knob);
    let _y_d = y.daemon_with_anchor(Some(&spec), &knob);
    // **Held at the gate until both members are about to admit**, then let go together: a join
    // finished a second ahead is mirrored to the other member before that one decides, and the
    // two would never race (measured: the first run, ungated, admitted one and refused the
    // other as full).
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
            while reached() < 2 && t0.elapsed() < std::time::Duration::from_secs(50) {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            let held = reached();
            std::fs::write(&gate, b"").expect("APPARATUS: cannot open the admission gate");
            held
        });
        let hx = s.spawn(|| {
            x.vox(
                &["room", "join", &host_link, "--name", "race"],
                Some(ROOM_PASS),
            )
        });
        let hy = s.spawn(|| {
            y.vox(
                &["room", "join", &bob_link, "--name", "race"],
                Some(ROOM_PASS),
            )
        });
        let held = opener
            .join()
            .unwrap_or_else(|e| std::panic::resume_unwind(e));
        assert!(
            held == 2,
            "CANNOT MEASURE: {held} of the 2 members reached the admission gate within 50 s, so the \
             joins were not held to race"
        );
        [(&x, hx), (&y, hy)]
            .into_iter()
            .map(|(m, h)| {
                let (ok, out, err) = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
                (m, ok, format!("{out}{err}"))
            })
            .collect()
    });
    for (m, ok, said) in &joined {
        println!("[proof] {}'s join exited ok={ok}:\n{said}", m.name);
    }
    // A newcomer that did not get in is the staging's only when **every** member that answered
    // it refused it as full: then one member learned of the other's newcomer before deciding,
    // and the joins did not race. Refused by any member for anything else, it is the product's,
    // quoted (ac-fix93 on c3) — even when a later member then found the room full.
    let only_full = |said: &str| {
        said.contains("the room is full")
            && said
                .lines()
                .filter_map(|l| l.trim_start().strip_prefix("said: "))
                .flat_map(|l| l.split("; "))
                .filter(|r| r.contains(": exchange"))
                .all(|r| r.contains("the room is full"))
    };
    for (m, ok, said) in &joined {
        if !ok && !only_full(said) {
            panic!(
                "PRODUCT: {}'s join failed, and a member refused it for something other than a full \
                 room:\n{said}",
                m.name
            );
        }
    }
    let told_joined: Vec<&Member> = joined.iter().filter(|j| j.1).map(|j| j.0).collect();
    assert!(
        told_joined.len() == 2,
        "CANNOT MEASURE: only {} of the 2 newcomers got in, and every member refused the other \
         as full, so the joins did not race (one member learned of the other's newcomer before it \
         answered its own): nothing measured whether raced joins converge",
        told_joined.len()
    );

    // ---- both rosters converge on every member told it joined, never past the ceiling ---------
    let roster = |m: &Member| -> Vec<String> {
        let (ok, out, err) = m.vox(&["room", "roster", &room], None);
        assert!(ok, "PRODUCT: {}'s `vox room roster` failed: {err}", m.name);
        out.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect()
    };
    let want: Vec<&str> = [&host, &bob, &x, &y]
        .iter()
        .map(|m| m.fp.as_str())
        .collect();
    let t0 = std::time::Instant::now();
    let (mut on_host, mut on_bob);
    loop {
        on_host = roster(&host);
        on_bob = roster(&bob);
        for (who, r) in [("host", &on_host), ("bob", &on_bob)] {
            assert!(
                r.len() <= CAP + OVERSHOOT,
                "PRODUCT: {who}'s roster lists {} members, past the ceiling of {} (cap {CAP} + \
                 {OVERSHOOT})",
                r.len(),
                CAP + OVERSHOOT
            );
        }
        let has_all = |r: &Vec<String>| want.iter().all(|w| r.iter().any(|m| m == w));
        if has_all(&on_host) && has_all(&on_bob) {
            break;
        }
        assert!(
            t0.elapsed() < CONVERGE_WITHIN,
            "PRODUCT: both newcomers were told they joined, but {CONVERGE_WITHIN:?} later the room \
             is split: the host lists {} and bob lists {} (want all 4 of {want:?} on both)\nhost: \
             {on_host:?}\nbob: {on_bob:?}",
            on_host.len(),
            on_bob.len()
        );
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    println!(
        "[proof] both rosters list all 4 ({} past the cap of {CAP}) {:?} after the joins",
        4 - CAP,
        t0.elapsed()
    );
}
