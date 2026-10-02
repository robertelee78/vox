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
//! - says the room is full with the cap in force, in its headline ("… as many members as a room
//!   can ([`CAP`])") and in its detail ("the room is full: [`CAP`] members");
//! - leaves the room out of that person's `vox room list`;
//! - and the host's `vox room roster` still lists exactly [`CAP`], the newcomer not among them.
//!
//! **Every red says which it is:** `PRODUCT:` quotes what `vox` said or did; `CANNOT MEASURE:`
//! names staging that was not achieved (a `vox` without the knob, a room not full when asked).
//!
//! **Mutation that must turn it red:** the admission's result dropped again (in `NetEvent::JoinAdmit`,
//! the ack answered `Ok(())` whatever `admit_author` returned): the newcomer is told it joined.

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
        "CANNOT MEASURE: the room is not full: the host's roster lists {} of {CAP} before the \
         last join\n{before:?}",
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
        format!("the room is full: it holds as many members as a room can ({CAP})"),
        format!("the room is full: {CAP} members"),
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
