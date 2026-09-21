//! ADR-016 **M13 gate** — the single-device node, end to end, on the production
//! Argon2id profile (this is an integration test: `vox-core` is linked without
//! `cfg(test)`, so the reduced test profile does not exist here).
//!
//! "An integration test creates a profile, creates a channel, appends and renders
//! messages, locks, unlocks, and finds the same state after a process restart."
//! The restart is a fresh tokio runtime and a fresh `Node` over the same profile
//! directory — the store file is reopened from disk and the DAG is rebuilt through
//! the acceptance predicate.
//!
//! Six production Argon2id derivations ≈ 2 s in release, ≈ 30 s unoptimized:
//! `#[ignore]`d in the debug suite; CI runs it in release with the other
//! real-parameter gates.

#[path = "support/watchdog.rs"]
mod watchdog;

use std::sync::Arc;

use vox_core::identity::composite::RootSigner;
use vox_core::node::actor::{Clock, Node, NodeHandle};
use vox_core::node::api::{Fault, NodeCommand, NodeEvent, Outcome, Secret};
use vox_core::node::paths::Paths;
use vox_core::node::prekeys;
use vox_core::node::profile::Profile;

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn spawn(rt: &tokio::runtime::Runtime, paths: &Paths, t: u64) -> NodeHandle {
    // Fixed clock + the PRODUCTION Argon2id profile (the point of this gate).
    let clock: Clock = Arc::new(move || t);
    rt.block_on(async {
        Node::spawn_with(
            paths.clone(),
            clock,
            vox_core::atrest::sek::Argon2Profile::default(),
        )
    })
    .unwrap()
}

#[test]
#[ignore = "production Argon2id (≈2 s release / ≈30 s debug); CI runs it in release"]
fn m13_single_device_node_survives_a_restart() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::resolve("gate", Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap();

    let texts = ["first message", "second message", "third message"];
    let (cid, fp) = {
        // ---- process 1 ----
        let rt = runtime();
        let h = spawn(&rt, &paths, 1_800_000_000);
        let ids = rt.block_on(async {
            let v = h.view();
            assert!(v.identity.is_none() && v.locked && v.channels.is_empty());

            assert!(h
                .apply(NodeCommand::CreateIdentity {
                    passphrase: secret("identity passphrase")
                })
                .await
                .is_done());
            let v = h.view();
            let fp = v.identity.as_ref().unwrap().fingerprint;
            assert!(!v.locked);
            assert!(paths.vault_file().is_file() && paths.store_file().is_file());

            assert!(h
                .apply(NodeCommand::CreateChannel {
                    local_name: "gate channel".into(),
                    passphrase: secret("channel passphrase")
                })
                .await
                .is_done());
            let cid = h.view().channels[0].channel_id;
            for t in texts {
                assert!(h
                    .apply(NodeCommand::SendText {
                        channel_id: cid,
                        text: t.into()
                    })
                    .await
                    .is_done());
            }
            // Events arrived in order, then the view renders all three.
            let mut seen = Vec::new();
            while let Some(ev) = h.try_next_event() {
                if let NodeEvent::NewEntry { row, .. } = ev {
                    seen.push(row.text);
                }
            }
            assert_eq!(seen, texts);
            let v = h.view();
            assert_eq!(
                v.open_channels[0]
                    .timeline
                    .iter()
                    .map(|r| r.text.as_str())
                    .collect::<Vec<_>>(),
                texts
            );
            assert_eq!(v.open_channels[0].members, vec![fp]);

            // Lock → closed, name hidden; unlock + reopen → restored.
            assert!(h.apply(NodeCommand::Lock).await.is_done());
            let v = h.view();
            assert!(
                v.locked
                    && v.open_channels.is_empty()
                    && !v.channels[0].open
                    && v.channels[0].local_name.is_none()
            );
            assert_eq!(
                h.apply(NodeCommand::Unlock {
                    passphrase: secret("wrong")
                })
                .await,
                Outcome::Failed(Fault::WrongPassphrase)
            );
            assert!(h
                .apply(NodeCommand::Unlock {
                    passphrase: secret("identity passphrase")
                })
                .await
                .is_done());
            assert!(h
                .apply(NodeCommand::OpenChannel {
                    channel_id: cid,
                    passphrase: secret("channel passphrase")
                })
                .await
                .is_done());
            assert_eq!(h.view().open_channels[0].timeline.len(), 3);
            assert!(h.apply(NodeCommand::Shutdown).await.is_done());
            (cid, fp)
        });
        // Runtime dropped: process 1 is gone.
        ids
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in [paths.vault_file(), paths.store_file()] {
            let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", f.display());
        }
        let mode = std::fs::metadata(&paths.profile_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    {
        // ---- process 2: same directory, everything from disk ----
        let rt = runtime();
        let h = spawn(&rt, &paths, 1_800_000_100);
        rt.block_on(async {
            let v = h.view();
            assert_eq!(
                v.identity.as_ref().unwrap().fingerprint,
                fp,
                "same identity"
            );
            assert!(v.locked, "restart starts locked");
            assert_eq!(v.channels.len(), 1);
            assert_eq!(v.channels[0].channel_id, cid);
            assert!(!v.channels[0].open);
            assert_eq!(
                h.apply(NodeCommand::SendText {
                    channel_id: cid,
                    text: "x".into()
                })
                .await,
                Outcome::Failed(Fault::ChannelNotOpen)
            );
            assert!(h
                .apply(NodeCommand::Unlock {
                    passphrase: secret("identity passphrase")
                })
                .await
                .is_done());
            assert_eq!(
                h.apply(NodeCommand::OpenChannel {
                    channel_id: cid,
                    passphrase: secret("nope")
                })
                .await,
                Outcome::Failed(Fault::WrongPassphrase)
            );
            assert!(h
                .apply(NodeCommand::OpenChannel {
                    channel_id: cid,
                    passphrase: secret("channel passphrase")
                })
                .await
                .is_done());
            let v = h.view();
            let d = &v.open_channels[0];
            assert_eq!(d.local_name, "gate channel");
            assert_eq!(d.members, vec![fp]);
            assert_eq!(
                d.timeline
                    .iter()
                    .map(|r| r.text.as_str())
                    .collect::<Vec<_>>(),
                texts
            );
            // The sender chain continued: a fourth message appends cleanly.
            assert!(h
                .apply(NodeCommand::SendText {
                    channel_id: cid,
                    text: "after restart".into()
                })
                .await
                .is_done());
            assert_eq!(h.view().open_channels[0].timeline.len(), 4);
            assert!(h.apply(NodeCommand::Shutdown).await.is_done());
        });

        // Drop the runtime so the node task — and with it the redb store — is
        // released before this process reopens the same profile directory.
        drop(rt);

        // The prekey ring (ADR-016 M14.3) survived the same restart, through the
        // whole composed path at production parameters: Argon2id vault unlock →
        // deterministic identity factor → HKDF ring key → sealed segment. The
        // reloaded ring is the one the node created, so bundles already published
        // are still answerable.
        let mut profile = Profile::open(paths.clone()).unwrap();
        profile.unlock(b"identity passphrase").unwrap();
        let signer = profile.signer().unwrap();
        let ring = prekeys::load(profile.store(), signer)
            .unwrap()
            .expect("the node persisted a prekey ring");
        let bundle = ring.bundle(&RootSigner::public_key(signer)).unwrap();
        bundle.verify().unwrap();
        assert_eq!(bundle.root_pub, RootSigner::public_key(signer).to_bytes());
        assert_eq!(bundle.signed_prekey.prekey_id, ring.signed_prekey_id());
        assert!(bundle.one_time_prekey.is_some(), "pool was generated");
        assert_eq!(ring.one_time_len(), prekeys::ONE_TIME_PREKEY_TARGET);
        // A different identity cannot open it.
        let stranger = vox_core::identity::composite::SoftwareRootSigner::from_component_seeds(
            &[9; 32], &[8; 32],
        )
        .unwrap();
        assert!(prekeys::load(profile.store(), &stranger).is_err());
    }
}
