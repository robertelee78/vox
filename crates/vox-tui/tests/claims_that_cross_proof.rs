//! V210-168 — **of two claims made at once, exactly one is told it holds the item**, through the
//! shipped `vox` binary on two real nodes. Run on demand; not a gate.
//!
//! A claim is a post, and each node folds its own claim as won until the other's arrives, so two
//! `vox room claim`s made at the same moment were both told "you hold X", and the loser learned
//! otherwise only on a later turn, told that its claim had "lapsed". A claim now says "you hold
//! it" only once every other member agrees. Each round here has two agents on two nodes claim one
//! item at the same moment:
//!
//! 1. exactly one is told "you hold" it, exit 0;
//! 2. the other is told at once who got it, exit 1;
//! 3. both nodes' boards name the same holder;
//! 4. the loser's next drain says nothing about it: it never held it, so nothing "lapsed".

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use support::{Out, Worker};

/// Rounds of two claims at once. Which claim the room orders first varies by round.
const ROUNDS: usize = 5;

fn claim_at_once(workers: &[&Worker], room: &str, item: &str) -> Vec<Out> {
    let go = std::sync::Barrier::new(workers.len());
    std::thread::scope(|s| {
        let running: Vec<_> = workers
            .iter()
            .map(|w| {
                let go = &go;
                s.spawn(move || {
                    let session = format!("agent-{}", w.name);
                    go.wait();
                    w.vox(Some(&session), &["room", "claim", room, item])
                })
            })
            .collect();
        running
            .into_iter()
            .map(|t| t.join().expect("APPARATUS: a claiming thread panicked"))
            .collect()
    })
}

fn holder(w: &Worker, room: &str, item: &str) -> Option<String> {
    let o = w.vox(
        Some(&format!("agent-{}", w.name)),
        &["room", "board", room, "--json"],
    );
    o.expect_ok(&format!("{}'s `vox room board`", w.name));
    support::resource(&o.json(), item)
        .and_then(|r| r.get("owner_fp"))
        .and_then(|f| f.as_str())
        .map(str::to_owned)
}

#[test]
#[ignore = "on demand: two networked nodes with production Argon2id"]
fn of_two_claims_made_at_once_exactly_one_is_told_it_holds_the_item() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("APPARATUS: a tokio runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: a tempdir");
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let r = room.id.as_str();
    let both: Vec<&Worker> = room.workers.iter().collect();

    for k in 0..ROUNDS {
        let item = format!("item-{k}");
        let outs = claim_at_once(&both, r, &item);
        let won: Vec<usize> = (0..outs.len()).filter(|i| outs[*i].ok).collect();
        assert_eq!(
            won.len(),
            1,
            "PRODUCT: {} of two claims made at once on {item} were told they won, not one:\n{outs:#?}",
            won.len()
        );
        let (w, l) = (won[0], 1 - won[0]);
        let (winner, loser) = (both[w], both[l]);
        assert!(
            outs[w].stdout.contains(&format!("you hold {item}")),
            "PRODUCT: {}'s claim exited 0 without saying it holds {item}: {:?}",
            winner.name,
            outs[w]
        );
        let told = &outs[l].stderr;
        // The loser names the winner by its own name for it, the one `vox trust add --name`
        // gave (V210-162), not by a fingerprint.
        let winner_id = format!("went to {}/", winner.name);
        assert!(
            outs[l].code == Some(1)
                && told.contains(&winner_id)
                && told.contains("you did not get it"),
            "PRODUCT: the losing claim ({}) must exit 1 naming the winner {} ({winner_id:?}) at \
             once: {:?}",
            loser.name,
            winner.name,
            outs[l]
        );
        let full = winner.b32();
        for w in &both {
            let h = holder(w, r, &item);
            assert_eq!(
                h.as_deref(),
                Some(full.as_str()),
                "PRODUCT: {}'s board does not name {} as {item}'s holder, which {} was told it is",
                w.name,
                winner.name,
                winner.name
            );
        }
        let session = format!("agent-{}", loser.name);
        let drain = loser.vox(
            Some(&session),
            &[
                "agent",
                "hook",
                "--room",
                r,
                "--format",
                "text",
                "--session",
                &session,
            ],
        );
        drain.expect_ok(&format!("{}'s drain", loser.name));
        assert!(
            !drain.stdout.contains(&format!("`{item}`")),
            "PRODUCT: {} never held {item}, and its drain speaks of losing it: {:?}",
            loser.name,
            drain.stdout
        );
    }
}
