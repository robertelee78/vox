//! Identity and endpoint helpers for test-side wire peers.

#![allow(dead_code)]

use vox_core::node::paths::Paths;
use vox_core::node::profile::Profile;
use vox_core::transport::quic::VoxEndpoint;

/// The unix time now, in milliseconds (what a dial stamps its session record with).
pub fn now() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// Open a member's profile — its node must already be shut down — and bind an endpoint as that
/// member. Retries while the old node's store is still being released.
pub async fn endpoint_as_member(paths: &Paths, passphrase: &[u8]) -> VoxEndpoint {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut profile = loop {
        match Profile::open(paths.clone()) {
            Ok(p) => break p,
            Err(e) if std::time::Instant::now() < deadline => {
                let _ = e;
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            Err(e) => panic!("the member's profile did not open: {e:?}"),
        }
    };
    profile
        .unlock(passphrase)
        .expect("the member's identity unlocks");
    let signer = profile.signer_arc().expect("the member's signer");
    VoxEndpoint::bind(signer, "127.0.0.1:0".parse().unwrap()).expect("bind as the member")
}
