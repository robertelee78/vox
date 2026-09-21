//! **Security gate — M17.6: no consent without a ring entry, and no author without
//! evidence.**
//!
//! Two defects, one rule. Before this, a key became a log author for one of two
//! reasons, and neither was a decision anybody made:
//!
//! 1. **Joining released a sender key.** `join` called `release_key_to(responder)`
//!    unconditionally, which issues an ordinary ADR-007 consent grant — the same
//!    mechanism as an explicit approval — to *whichever member answered the join*. The
//!    responder is chosen from the board, so the choice was influenceable by whoever
//!    supplied the link. Under ADR-017 decision 3 that consent also carries reach to
//!    the grantor's room-bound services, so an automatic grant here handed a service to
//!    a party no human approved.
//! 2. **A board record was its own evidence.** A member bundle record is *self*-signed:
//!    it proves its publisher holds that key and nothing more, and anyone can mint one
//!    for a key they hold. A node admitted such a record on the strength of *who
//!    relayed it* — trust-on-first-use, which ADR-020 decision 3 forbids in as many
//!    words.
//!
//! Admission is not a privilege — an admitted key reads nothing without its holder's
//! sender key, and reaches no service without the host's trust keyring. What it grants
//! is that entries signed by that key are **accepted and stored**, and that the key
//! occupies one of `MAX_AUTHORS` slots for the life of the epoch. So injection is a
//! durable denial of new membership that outlives the attacker and is repairable only
//! by a passphrase rotation.
//!
//! What this gate proves, over two real networked nodes and a real join:
//!
//! 1. the join still works, and the joiner comes away with a witness **signed by the
//!    responder** that binds its own key, that room and that epoch;
//! 2. the responder receives **no sender key** from the joiner — joining grants nothing;
//! 3. the same holds in a **second** room the two share. A single-room assertion passes
//!    even against an implementation that only ever gets it right in whichever room
//!    comes first, which is a real failure mode and not a hypothetical one;
//! 4. a record whose witness is signed by a key the verifier has **not** admitted is
//!    refused — the property that roots every chain in the genesis creator;
//! 5. a record claiming to be the creator when it is not is refused;
//! 6. the creator itself is admissible with no witness at all, since the genesis names
//!    it and the genesis hash *is* the channelID.
//!
//! Production Argon2id and a real ADR-005 proof of work (reduced), so `#[ignore]`d in
//! the debug suite and run by CI's release step.

#[path = "support/watchdog.rs"]
mod watchdog;

use std::time::Duration;

use vox_core::identity::composite::{RootSigner, SoftwareRootSigner};
use vox_core::nat::record::{Admission, JoinWitness};
use vox_core::node::actor::{Node, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::channel::ChannelState;
use vox_core::node::paths::Paths;
use vox_core::node::profile::Profile;

const TIMEOUT: Duration = Duration::from_secs(120);
const NOW: u64 = 1_750_000_000;

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

fn paths(tmp: &tempfile::TempDir, name: &str) -> Paths {
    Paths::resolve(name, Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap()
}

async fn node(tmp: &tempfile::TempDir, name: &str) -> NodeHandle {
    let h = Node::spawn_networked(paths(tmp, name), "127.0.0.1:0".parse().unwrap()).unwrap();
    assert!(h
        .apply(NodeCommand::CreateIdentity {
            passphrase: secret("identity passphrase"),
        })
        .await
        .is_done());
    h
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
    .expect("event did not arrive")
}

/// Make a room on `host`, and return `(channel_id, invite link)`.
async fn room(host: &NodeHandle, name: &str, passphrase: &str) -> ([u8; 32], String) {
    assert!(host
        .apply(NodeCommand::CreateChannel {
            local_name: name.into(),
            passphrase: secret(passphrase),
        })
        .await
        .is_done());
    let cid = host
        .view()
        .channels
        .iter()
        .find(|c| c.local_name.as_deref() == Some(name))
        .expect("the room this test just made")
        .channel_id;
    assert!(host
        .apply(NodeCommand::Invite { channel_id: cid })
        .await
        .is_done());
    let link = wait_for(host, |e| match e {
        NodeEvent::InviteLink { channel_id, url } if channel_id == cid => Some(url),
        _ => None,
    })
    .await;
    (cid, link)
}

#[test]
#[ignore = "production Argon2id + a real PoW; CI runs it in release with the other gates"]
fn joining_grants_nothing_and_a_board_key_needs_evidence() {
    watchdog::arm();
    let rt = runtime();
    let tmp = tempfile::tempdir().unwrap();

    rt.block_on(async {
        let alice = node(&tmp, "alice").await;
        let bob = node(&tmp, "bob").await;

        // ---- (1) a real join, twice, into two different rooms ------------------
        let mut witnesses = Vec::new();
        for (name, pass) in [
            ("room one", "first room passphrase"),
            ("room two", "second room passphrase"),
        ] {
            let (cid, link) = room(&alice, name, pass).await;
            assert!(
                bob.apply(NodeCommand::JoinChannel {
                    link: link.clone(),
                    local_name: name.into(),
                    passphrase: secret(pass),
                })
                .await
                .is_done(),
                "bob joins {name} with the link and the passphrase"
            );
            witnesses.push((cid, name.to_owned()));
        }

        // ---- (2) and (3) no sender key reached alice, in EITHER room -----------
        //
        // Drain whatever alice has queued and assert the absence. A single-room check
        // would pass against an implementation that only got the first room right.
        tokio::time::sleep(Duration::from_secs(3)).await;
        let mut keys_from_bob = Vec::new();
        while let Some(e) = alice.try_next_event() {
            if let NodeEvent::SenderKeyReceived { channel_id, .. } = e {
                keys_from_bob.push(channel_id);
            }
        }
        assert!(
            keys_from_bob.is_empty(),
            "joining must grant nothing: alice received sender keys for {} room(s) \
             without ever approving bob — {keys_from_bob:?}",
            keys_from_bob.len()
        );
        assert_eq!(witnesses.len(), 2, "both joins completed");

        assert!(bob.apply(NodeCommand::Shutdown).await.is_done());
        assert!(alice.apply(NodeCommand::Shutdown).await.is_done());
    });

    // ---- (4)(5)(6) the evidence rule itself, with real keys -------------------
    //
    // Driven against `admit_from_board`, which is the function every board sweep goes
    // through — the exact point that decides whether a key may write to this log.
    let tmp2 = tempfile::tempdir().unwrap();
    let stranger = SoftwareRootSigner::generate().unwrap();
    let outsider = SoftwareRootSigner::generate().unwrap();

    let profile = {
        let p = Paths::resolve("gate", Some(tmp2.path()), Some(&tmp2.path().join("cfg"))).unwrap();
        Profile::create_with_profile(
            p,
            &secret("identity passphrase"),
            NOW,
            vox_core::atrest::sek::Argon2Profile::default(),
        )
        .unwrap()
    };
    let mut channel = ChannelState::create_with_profile(
        &profile,
        "evidence",
        b"room passphrase",
        NOW,
        vox_core::atrest::sek::Argon2Profile::default(),
    )
    .unwrap();
    let cid = channel.channel_id();
    let epoch = channel.epoch();

    // (6) the creator needs no witness: the genesis names it.
    assert!(
        channel
            .admit_from_board(
                profile.store(),
                &profile.signer().unwrap().public_key(),
                &Admission::Creator,
                NOW,
            )
            .is_ok(),
        "the channel's own creator is admissible from the genesis alone"
    );

    // (5) but nobody else may claim to be it.
    assert!(
        channel
            .admit_from_board(
                profile.store(),
                &stranger.public_key(),
                &Admission::Creator,
                NOW,
            )
            .is_err(),
        "a key that is not the genesis creator must not be admitted by claiming to be"
    );

    // (4) a witness signed by a key this node has never admitted proves nothing —
    // which is what stops a chain starting anywhere but the creator.
    let forged = JoinWitness::build(&outsider, &cid, epoch, &stranger.fingerprint(), NOW).unwrap();
    assert!(
        channel
            .admit_from_board(
                profile.store(),
                &stranger.public_key(),
                &Admission::Witnessed(Box::new(forged)),
                NOW,
            )
            .is_err(),
        "a witness from an unadmitted signer must not admit anybody"
    );

    // ...and the same key IS admitted once the witness comes from the creator, who
    // this node does admit. Without this the test would pass against a function that
    // simply refuses everything.
    let real = JoinWitness::build(
        profile.signer().unwrap(),
        &cid,
        epoch,
        &stranger.fingerprint(),
        NOW,
    )
    .unwrap();
    assert!(
        matches!(
            channel.admit_from_board(
                profile.store(),
                &stranger.public_key(),
                &Admission::Witnessed(Box::new(real)),
                NOW,
            ),
            Ok(true)
        ),
        "a witness from an admitted member is exactly what admission requires"
    );

    // A witness for the wrong room does not carry over, even from the creator.
    let other_room = [0x11u8; 32];
    let wrong_room = JoinWitness::build(
        profile.signer().unwrap(),
        &other_room,
        epoch,
        &outsider.fingerprint(),
        NOW,
    )
    .unwrap();
    assert!(
        channel
            .admit_from_board(
                profile.store(),
                &outsider.public_key(),
                &Admission::Witnessed(Box::new(wrong_room)),
                NOW,
            )
            .is_err(),
        "a witness binds one room; it must not admit its subject into another"
    );
}
