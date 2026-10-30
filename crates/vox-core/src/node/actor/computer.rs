//! Computer policy is daemon-owned. No public node command can forge a management binding.
use super::*;

/// **Test-only** (`test-knobs`): `<arm>\t<receipt>\t<release socket>\t<fault>`. `arm` contains
/// the exact grant fingerprint. Startup publishes `receipt` only after the matching applied
/// receipt removed its recovery record, then waits before actor startup returns to the daemon's
/// final physical-publication Ready fence.
/// Shipped builds neither name nor read this variable.
#[cfg(feature = "test-knobs")]
const TEST_HOLD_AFTER_COMPUTER_APPLICATION_RECEIPT_ENV: &str =
    "VOX_TEST_HOLD_AFTER_COMPUTER_APPLICATION_RECEIPT_FILE";
use crate::identity::composite::RootSigner;

pub(super) struct OwnKeyPolicyWork {
    pub(super) owner: Arc<()>,
    pub(super) guard: ComputerPolicyGuard,
    pub(super) reply: tokio::sync::oneshot::Sender<crate::error::Result<()>>,
    pub(super) targets: Vec<Digest32>,
}

pub(super) struct KeyringApplication {
    pub(super) settled: bool,
}

/// Causal cancellation of one host-owned Computer reconciliation.
#[derive(Debug, Default)]
pub struct PolicySupersession {
    retired: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

impl PolicySupersession {
    /// Retire this exact policy owner and wake any admission or drain wait.
    pub fn retire(&self) {
        self.retired
            .store(true, std::sync::atomic::Ordering::Release);
        self.notify.notify_waiters();
    }
    pub(crate) fn is_retired(&self) -> bool {
        self.retired.load(std::sync::atomic::Ordering::Acquire)
    }
    async fn retired(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_retired() {
                return;
            }
            notified.await;
        }
    }
}

/// Ownership of an accepted Computer application. Only an exact policy or lifecycle
/// supersession retires it; elapsed observation time never cancels its continuation.
#[derive(Clone)]
pub(super) struct ComputerPolicyGuard {
    pub(super) change: crate::node::computer::ComputerChange,
    pub(super) superseded: Arc<PolicySupersession>,
}

impl ComputerPolicyGuard {
    pub(super) fn active(
        &self,
        computer: Option<&Arc<crate::node::computer::Computer>>,
    ) -> crate::error::Result<()> {
        if self.superseded.is_retired()
            || computer.is_some_and(|computer| !computer.policy_target_is(self.change.target()))
        {
            Err(Error::ComputerPolicySuperseded)
        } else {
            Ok(())
        }
    }

    /// The one-shot late-follower inverse remains confined to its explicit proof arm.
    #[cfg(feature = "test-knobs")]
    fn abandon_late_application_for_proof(&self) {
        if crate::node::computer::fx28_mutant("late-application-abandons-work")
            && std::time::Instant::now() >= self.change.apply_deadline()
        {
            self.superseded.retire();
        }
    }
}

/// A captured actor projection whose final use is checked against durable Computer state. The
/// token is not itself authority: publication first takes a physical reader lease and then
/// revalidates under short state ownership, retaining no Computer state lock through I/O.
#[derive(Clone)]
pub(super) enum ComputerAuthority {
    Unmanaged,
    Managed {
        computer: Arc<crate::node::computer::Computer>,
        applied: u64,
        expired: bool,
        node: Digest32,
    },
}

pub(super) struct ComputerPublication {
    _managed: Option<crate::node::computer::ComputerPublication>,
}

impl ComputerAuthority {
    /// Acquire off actor, before room or Store writer ownership, and retain through the actual
    /// durable outcome. A later policy change cannot cancel or relabel a successful commit.
    pub(super) async fn acquire_publication(&self) -> Option<ComputerPublication> {
        let managed = match self {
            Self::Unmanaged => None,
            Self::Managed {
                computer,
                applied,
                expired,
                node,
            } => Some(
                computer
                    .acquire_publication(*applied, *expired, *node)
                    .await?,
            ),
        };
        Some(ComputerPublication { _managed: managed })
    }

    pub(super) fn publish<T>(&self, publish: impl FnOnce() -> T) -> Option<T> {
        #[cfg(feature = "test-knobs")]
        if crate::node::computer::fx28_mutant("stale-join-authority") {
            return Some(publish());
        }
        match self {
            Self::Unmanaged => Some(publish()),
            Self::Managed {
                computer,
                applied,
                expired,
                node,
            } => computer.publish_with_current_authority(*applied, *expired, *node, publish),
        }
    }

    pub(super) fn publish_room_creation<T>(&self, publish: impl FnOnce() -> T) -> Option<T> {
        #[cfg(feature = "test-knobs")]
        if crate::node::computer::fx28_mutant("stale-room-create-authority") {
            return Some(publish());
        }
        self.publish(publish)
    }

    /// The pause mutant changes only this publication, so earlier join assertions cannot mask it.
    pub(super) fn publish_room_pause<T>(&self, publish: impl FnOnce() -> T) -> Option<T> {
        #[cfg(feature = "test-knobs")]
        if crate::node::computer::fx28_mutant("stale-tick-authority") {
            return Some(publish());
        }
        self.publish(publish)
    }

    /// Revalidate this exact captured projection without publishing anything. This is used at
    /// asynchronous hand-offs whose irreversible operation belongs to another component; the
    /// operation is not even constructed unless the same authority still exists.
    pub(super) fn current(&self) -> bool {
        #[cfg(feature = "test-knobs")]
        if crate::node::computer::fx28_mutant("stale-join-authority") {
            return true;
        }
        match self {
            Self::Unmanaged => true,
            Self::Managed {
                computer,
                applied,
                expired,
                node,
            } => computer.policy_current(*applied, *expired, *node),
        }
    }
}

/// **Test-only** (`test-knobs`): `<node>\t<arm>\t<engaged>\t<release socket>`. The actor consumes
/// `arm`, creates `engaged`, and waits for one connection to `release`. The shipped-binary proof
/// can therefore hold and release the exact actor message causally, without a sleep standing in
/// for product behavior. Shipped builds neither name nor read this variable (V210-105).
#[cfg(feature = "test-knobs")]
const TEST_HOLD_COMPUTER_POLICY_ENV: &str = "VOX_TEST_HOLD_COMPUTER_POLICY";
#[cfg(feature = "test-knobs")]
const TEST_HOLD_COMPUTER_POLICY_REPLY_ENV: &str = "VOX_TEST_HOLD_COMPUTER_POLICY_REPLY";
#[cfg(feature = "test-knobs")]
const TEST_HOLD_COMPUTER_RECONCILE_SEND_ENV: &str = "VOX_TEST_HOLD_COMPUTER_RECONCILE_SEND_FILE";
#[cfg(feature = "test-knobs")]
const TEST_HOLD_ROOM_PAUSE_PUBLICATION_ENV: &str = "VOX_TEST_HOLD_ROOM_PAUSE_PUBLICATION";
#[cfg(feature = "test-knobs")]
const TEST_HOLD_TEXT_APPEND_PUBLICATION_ENV: &str = "VOX_TEST_HOLD_TEXT_APPEND_PUBLICATION";
#[cfg(feature = "test-knobs")]
const TEST_HOLD_ROOM_CREATE_PUBLICATION_ENV: &str = "VOX_TEST_HOLD_ROOM_CREATE_PUBLICATION";
#[cfg(feature = "test-knobs")]
const TEST_HOLD_ROOM_JOIN_AFTER_BOARD_ENV: &str = "VOX_TEST_HOLD_ROOM_JOIN_AFTER_BOARD";
#[cfg(feature = "test-knobs")]
const TEST_HOLD_REKEY_ENQUEUE_ENV: &str = "VOX_TEST_HOLD_REKEY_ENQUEUE";
#[cfg(feature = "test-knobs")]
const TEST_END_KEY_UNANSWERED_ENV: &str = "VOX_TEST_FX28_END_KEY_UNANSWERED_FILE";
#[cfg(feature = "test-knobs")]
const TEST_MARK_ENDED_UNANSWERED_ENV: &str = "VOX_TEST_FX28_MARK_ENDED_UNANSWERED_FILE";
#[cfg(feature = "test-knobs")]
const TEST_MARK_DELIVERY_DRAINED_ENV: &str = "VOX_TEST_FX28_MARK_DELIVERY_DRAINED_FILE";

#[cfg(feature = "test-knobs")]
impl Node {
    /// Test apparatus: emulate a pre-v0.4.3 peer for one exact sender and room while armed.
    /// `<node>\t<arm>\t<marker>`; `arm` contains the expected authenticated sender fingerprint
    /// and room fingerprint, separated by a tab.
    /// Every matching modern delivery closes without an answer throughout the staged phase;
    /// legacy Hello/Skdm traffic is unaffected. The first marker names the exact pair. A one-shot
    /// EOF would let overlapping modern deliveries succeed and truthfully supersede the older
    /// inference, so the arm remains present until the proof's daemon teardown. No shipped build
    /// names this knob.
    pub(super) fn end_key_unanswered_for_proof(
        &self,
        peer: Digest32,
        room: Option<Digest32>,
    ) -> bool {
        let Some(room) = room else { return false };
        let Ok(spec) = std::env::var(TEST_END_KEY_UNANSWERED_ENV) else {
            return false;
        };
        let mut fields = spec.splitn(3, '\t');
        let (Some(node), Some(arm), Some(marker)) = (fields.next(), fields.next(), fields.next())
        else {
            return false;
        };
        let mine = self
            .paths
            .profile_dir
            .file_name()
            .and_then(|name| name.to_str());
        let peer = crate::node::link::b32_encode(&peer);
        let room = crate::node::link::b32_encode(&room);
        let expected = format!("{peer}\t{room}");
        if mine != Some(node)
            || std::fs::read_to_string(arm).ok().as_deref().map(str::trim)
                != Some(expected.as_str())
        {
            return false;
        }
        let marker = std::path::Path::new(marker);
        let contents = format!("{node}\t{peer}\t{room}\n");
        if marker.is_file() {
            if std::fs::read_to_string(marker).ok().as_deref() != Some(contents.as_str()) {
                crate::node::computer::publish_proof_fault(
                    &marker.with_extension("fault"),
                    "legacy-peer apparatus marker did not name the armed sender and room",
                );
                std::process::exit(70);
            }
        } else if let Err(error) =
            crate::node::computer::publish_proof_marker(marker, contents.as_bytes())
        {
            crate::node::computer::publish_proof_fault(
                &marker.with_extension("fault"),
                &format!("could not publish the exact legacy-peer apparatus marker: {error}"),
            );
            std::process::exit(70);
        }
        true
    }

    /// Test apparatus: arm a marker after the sender has admitted the exact authenticated peer's
    /// `ENDED_UNANSWERED` result. `<node>\t<arm>\t<marker>`; `arm` contains that peer and room,
    /// separated by a tab. The exact pair's automatic re-key is paused at that causal boundary;
    /// the marker is emitted after the actor publishes the changed user view. A later exact
    /// post-side apparatus release drives the owed key into the ordinary durable-authority fence.
    pub(super) fn mark_ended_unanswered_for_proof(&mut self, room: Digest32, peer: Digest32) {
        let Ok(spec) = std::env::var(TEST_MARK_ENDED_UNANSWERED_ENV) else {
            return;
        };
        let mut fields = spec.splitn(3, '\t');
        let (Some(node), Some(arm), Some(marker)) = (fields.next(), fields.next(), fields.next())
        else {
            return;
        };
        let mine = self
            .paths
            .profile_dir
            .file_name()
            .and_then(|name| name.to_str());
        let peer_id = peer;
        let room_id = room;
        let peer = crate::node::link::b32_encode(&peer);
        let room = crate::node::link::b32_encode(&room);
        let expected = format!("{peer}\t{room}");
        if mine != Some(node)
            || std::fs::read_to_string(arm).ok().as_deref().map(str::trim)
                != Some(expected.as_str())
            || std::fs::remove_file(arm).is_err()
        {
            return;
        }
        self.fx28_rekey_pause = Some((room_id, peer_id));
        self.fx28_ended_unanswered_marker = Some((
            std::path::PathBuf::from(marker),
            format!("{node}\t{peer}\t{room}\n").into_bytes(),
        ));
    }

    /// Test apparatus: the exact baseline key was durably recorded and no key/history batch for
    /// this pair remains in flight. `<node>\t<arm>\t<marker>`; the arm contains `peer\troom`.
    /// This is a staging precondition only, never a product verdict.
    pub(super) fn mark_delivery_drained_for_proof(
        &mut self,
        room: Digest32,
        peer: Digest32,
        history: bool,
        whole_history: bool,
        durably_recorded: bool,
    ) {
        let pair = (room, peer);
        if !durably_recorded
            || (history && !whole_history)
            || self.keys_in_flight.contains_key(&pair)
            || self.history_in_flight.contains_key(&pair)
            || self
                .deliveries
                .keys()
                .any(|(held_room, held_peer, _)| (*held_room, *held_peer) == pair)
            || self
                .delivery_reserved
                .keys()
                .any(|(held_room, held_peer, _)| (*held_room, *held_peer) == pair)
        {
            return;
        }
        let Ok(spec) = std::env::var(TEST_MARK_DELIVERY_DRAINED_ENV) else {
            return;
        };
        let mut fields = spec.splitn(3, '\t');
        let (Some(node), Some(arm), Some(marker)) = (fields.next(), fields.next(), fields.next())
        else {
            return;
        };
        let mine = self
            .paths
            .profile_dir
            .file_name()
            .and_then(|name| name.to_str());
        let peer = crate::node::link::b32_encode(&peer);
        let room = crate::node::link::b32_encode(&room);
        let expected = format!("{peer}\t{room}");
        if mine != Some(node)
            || std::fs::read_to_string(arm).ok().as_deref().map(str::trim)
                != Some(expected.as_str())
            || std::fs::remove_file(arm).is_err()
        {
            return;
        }
        let _ = crate::node::computer::publish_proof_marker(
            std::path::Path::new(marker),
            format!("{node}\t{peer}\t{room}\n").as_bytes(),
        );
    }

    async fn hold_authority_use_for_proof(&self, variable: &str, action: &str) {
        let Ok(spec) = std::env::var(variable) else {
            return;
        };
        let mut fields = spec.splitn(4, '\t');
        let (Some(node), Some(arm), Some(engaged), Some(release)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return;
        };
        let mine = self
            .paths
            .profile_dir
            .file_name()
            .and_then(|name| name.to_str());
        if mine != Some(node) || std::fs::remove_file(arm).is_err() {
            return;
        }
        let _ = std::fs::remove_file(release);
        let Ok(listener) = tokio::net::UnixListener::bind(release) else {
            return;
        };
        if std::fs::write(engaged, format!("{action} held\n")).is_err() {
            return;
        }
        let _ = listener.accept().await;
        let _ = std::fs::remove_file(engaged);
        let _ = std::fs::remove_file(release);
    }

    pub(super) async fn hold_computer_policy_for_proof(&self, guard: &ComputerPolicyGuard) {
        let Ok(spec) = std::env::var(TEST_HOLD_COMPUTER_POLICY_ENV) else {
            return;
        };
        let mut fields = spec.splitn(4, '\t');
        let (Some(node), Some(arm), Some(engaged), Some(release)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return;
        };
        let mine = self
            .paths
            .profile_dir
            .file_name()
            .and_then(|name| name.to_str());
        if mine != Some(node) || std::fs::remove_file(arm).is_err() {
            return;
        }
        let _ = std::fs::remove_file(release);
        let Ok(listener) = tokio::net::UnixListener::bind(release) else {
            return;
        };
        if std::fs::write(engaged, b"computer policy actor held\n").is_err() {
            return;
        }
        let _ = listener.accept().await;
        guard.abandon_late_application_for_proof();
        let _ = std::fs::remove_file(engaged);
        let _ = std::fs::remove_file(release);
    }

    /// Test apparatus: delay only the reply to an applied policy event, leaving the actor free
    /// to detach. This stages a replacement attachment before an old reconciliation resolves.
    #[cfg(feature = "test-knobs")]
    pub(super) fn hold_computer_policy_reply_for_proof(&self) -> Option<Duration> {
        let spec = std::env::var(TEST_HOLD_COMPUTER_POLICY_REPLY_ENV).ok()?;
        let mut fields = spec.splitn(3, '\t');
        let (node, milliseconds, marker) = (fields.next()?, fields.next()?, fields.next()?);
        let mine = self.paths.profile_dir.file_name()?.to_str()?;
        if mine != node || !std::path::Path::new(marker).is_file() {
            return None;
        }
        let delay = milliseconds
            .parse::<u64>()
            .ok()
            .map(Duration::from_millis)?;
        // One-shot, and observable by the apparatus: its disappearance proves the old actor
        // accepted the event before the proof replaces that attachment.
        std::fs::remove_file(marker).ok()?;
        Some(delay)
    }

    /// Test apparatus: hold a real remote pause after all asynchronous admission and immediately
    /// before its current-authority publication fence. A shipped-binary journey moves durable
    /// Computer policy while this exact request is held, then releases it and judges the command's
    /// user-visible answer. The knob creates no publication of its own.
    pub(super) async fn hold_room_pause_publication_for_proof(&self) {
        let Ok(spec) = std::env::var(TEST_HOLD_ROOM_PAUSE_PUBLICATION_ENV) else {
            return;
        };
        let mut fields = spec.splitn(4, '\t');
        let (Some(node), Some(arm), Some(engaged), Some(release)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return;
        };
        let mine = self
            .paths
            .profile_dir
            .file_name()
            .and_then(|name| name.to_str());
        if mine != Some(node) || std::fs::remove_file(arm).is_err() {
            return;
        }
        let _ = std::fs::remove_file(release);
        let Ok(listener) = tokio::net::UnixListener::bind(release) else {
            return;
        };
        if std::fs::write(engaged, b"room pause publication held\n").is_err() {
            return;
        }
        let _ = listener.accept().await;
        let _ = std::fs::remove_file(engaged);
        let _ = std::fs::remove_file(release);
    }

    /// Test apparatus: hold an ordinary text command after its room lock and every await, at the
    /// final durable-policy fence before append. The marker stages only; shipped output judges.
    pub(super) async fn hold_text_append_publication_for_proof(&self) {
        self.hold_authority_use_for_proof(
            TEST_HOLD_TEXT_APPEND_PUBLICATION_ENV,
            "text append publication",
        )
        .await;
    }

    /// Test apparatus: hold one completed room seal after all off-actor work and immediately
    /// before the durable room commit. The marker stages only; shipped create/list output judges.
    pub(super) async fn hold_room_create_publication_for_proof(&self) {
        self.hold_authority_use_for_proof(
            TEST_HOLD_ROOM_CREATE_PUBLICATION_ENV,
            "room create publication",
        )
        .await;
    }

    /// Test apparatus: hold a completed join after its records were queued to the answering
    /// member's real board and immediately before the final durable-policy fence. The marker
    /// stages only; shipped join/list output and the remote board judge the result.
    pub(super) async fn hold_room_join_after_board_for_proof(&self) {
        self.hold_authority_use_for_proof(
            TEST_HOLD_ROOM_JOIN_AFTER_BOARD_ENV,
            "room join after board publication",
        )
        .await;
    }

    /// Test apparatus: hold a prepared sender/history-key batch after every await and immediately
    /// before its final durable-policy fence and queue admission.
    pub(super) async fn hold_rekey_enqueue_for_proof(
        &self,
        room: Digest32,
        target: Digest32,
        legacy: bool,
        all_sent: bool,
        live_generation: u64,
        prepared_generations: &[u64],
    ) -> bool {
        let Ok(spec) = std::env::var(TEST_HOLD_REKEY_ENQUEUE_ENV) else {
            return false;
        };
        let mut fields = spec.splitn(5, '\t');
        let (Some(node), Some(arm), Some(engaged), Some(release), Some(_decision)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return false;
        };
        let mine = self
            .paths
            .profile_dir
            .file_name()
            .and_then(|name| name.to_str());
        let armed_target = std::fs::read_to_string(arm).ok();
        let target = crate::node::link::b32_encode(&target);
        let room = crate::node::link::b32_encode(&room);
        let expected = format!("{target}\t{room}");
        if mine != Some(node) || armed_target.as_deref().map(str::trim) != Some(expected.as_str()) {
            return false;
        }
        if !legacy || !all_sent || !prepared_generations.contains(&live_generation) {
            crate::node::computer::publish_proof_fault(
                &std::path::Path::new(engaged).with_extension("fault"),
                &format!(
                    "exact sender-key batch could not stage: node={node} peer={target} room={room} legacy={legacy} complete={all_sent} live_generation={live_generation} prepared_generations={prepared_generations:?}"
                ),
            );
            return false;
        }
        if std::fs::remove_file(arm).is_err() {
            return false;
        }
        let _ = std::fs::remove_file(release);
        let Ok(listener) = tokio::net::UnixListener::bind(release) else {
            return false;
        };
        if std::fs::write(engaged, b"rekey enqueue held\n").is_err() {
            return false;
        }
        let _ = listener.accept().await;
        let _ = std::fs::remove_file(engaged);
        let _ = std::fs::remove_file(release);
        true
    }

    pub(super) fn mark_rekey_authority_decision_for_proof(&self, published: bool) {
        let Ok(spec) = std::env::var(TEST_HOLD_REKEY_ENQUEUE_ENV) else {
            return;
        };
        let Some(decision) = spec.splitn(5, '\t').nth(4) else {
            return;
        };
        if let Err(error) = crate::node::computer::publish_proof_marker(
            std::path::Path::new(decision),
            if published {
                b"enqueued\n"
            } else {
                b"rejected\n"
            },
        ) {
            crate::node::computer::publish_proof_fault(
                &std::path::Path::new(decision).with_extension("fault"),
                &format!("could not publish rekey authority decision: {error}"),
            );
        }
    }
}

impl NodeHandle {
    /// The actor-owned startup boundary, read once by the daemon after Unlock/startup completes.
    /// Its identity is authoritative for headless actors whose `NodeView` intentionally has no
    /// vault identity.
    pub fn startup_computer_boundary(&self) -> Option<(std::time::Instant, Digest32)> {
        *self
            .startup_computer_boundary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Test apparatus: hold the later Attached-event reconciliation before it reaches the actor.
    /// The arm and marker both name the actor's authenticated identity and exact policy revision,
    /// so the shipped trust observation cannot accidentally follow asynchronous repair.
    #[cfg(feature = "test-knobs")]
    async fn hold_computer_reconcile_send_for_proof(&self) -> crate::error::Result<()> {
        let Ok(spec) = std::env::var(TEST_HOLD_COMPUTER_RECONCILE_SEND_ENV) else {
            return Ok(());
        };
        let mut fields = spec.splitn(4, '\t');
        let (Some(arm), Some(engaged), Some(release), Some(fault)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(Error::Profile(
                "computer reconciliation proof hold is malformed",
            ));
        };
        let Some(computer) = &self.computer else {
            return Ok(());
        };
        let Some(identity) = self
            .view_rx
            .borrow()
            .identity
            .as_ref()
            .map(|identity| identity.fingerprint)
        else {
            return Ok(());
        };
        let exact = format!(
            "{}\t{}",
            crate::node::link::b32_encode(&identity),
            computer.policy_revision()
        );
        let arm = std::path::Path::new(arm);
        let expected = match std::fs::read_to_string(arm) {
            Ok(expected) => expected,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                crate::node::computer::publish_proof_fault(
                    std::path::Path::new(fault),
                    &format!("could not read exact reconciliation arm: {error}"),
                );
                return Err(Error::Profile("computer reconciliation proof hold failed"));
            }
        };
        if expected.trim() != exact {
            return Ok(());
        }
        let fail = |detail: String| {
            crate::node::computer::publish_proof_fault(std::path::Path::new(fault), &detail);
            Error::Profile("computer reconciliation proof hold failed")
        };
        std::fs::remove_file(arm).map_err(|error| {
            fail(format!(
                "could not consume exact reconciliation arm: {error}"
            ))
        })?;
        let release = std::path::Path::new(release);
        match std::fs::remove_file(release) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(fail(format!(
                    "could not clear reconciliation release socket: {error}"
                )))
            }
        }
        let listener = tokio::net::UnixListener::bind(release)
            .map_err(|error| fail(format!("could not bind reconciliation release: {error}")))?;
        crate::node::computer::publish_proof_marker(
            std::path::Path::new(engaged),
            exact.as_bytes(),
        )
        .map_err(|error| fail(format!("could not publish reconciliation marker: {error}")))?;
        listener
            .accept()
            .await
            .map_err(|error| fail(format!("reconciliation release failed: {error}")))?;
        let _ = std::fs::remove_file(release);
        Ok(())
    }

    /// Current daemon policy for rendering individual Trust actions. This is an observation,
    /// never an authorization token: every mutation reconciles and checks policy again.
    pub fn individual_trust_eligibility(&self, peer: Digest32) -> (bool, String) {
        let view = self.view();
        let Some(me) = view.identity.as_ref().map(|id| id.fingerprint) else {
            return (
                false,
                "make this node Ready before changing individual trust".into(),
            );
        };
        if self.cmd_tx.is_closed() || view.locked || view.locking {
            return (
                false,
                "make this node Ready before changing individual trust".into(),
            );
        }
        if me == peer {
            return (false, "a node does not grant trust to itself".into());
        }
        let Some(computer) = &self.computer else {
            return (true, String::new());
        };
        let Some((applied, expired)) = view.computer_policy else {
            return (
                false,
                "computer policy is pending application on this node".into(),
            );
        };
        if !computer.policy_current(applied, expired, me) {
            return (
                false,
                "computer policy is pending application on this node".into(),
            );
        }
        let result = match computer.capability(me, &peer) {
            Ok(Some(_)) => (false, "this node's trust is managed by My computers".into()),
            Ok(None) => (true, String::new()),
            Err(e) => (false, e.to_string()),
        };
        if !computer.policy_current(applied, expired, me) {
            return (
                false,
                "computer policy changed; refresh before changing individual trust".into(),
            );
        }
        result
    }

    /// Whether this node stands at the current computer policy: its binding derived at the
    /// current revision and its keyring applied at it (ADR-038 FX-28). A node that does has
    /// nothing to reconcile; the daemon asks it to only when a change moved the revision.
    pub fn computer_current(&self) -> bool {
        let Some(computer) = &self.computer else {
            return true;
        };
        if !computer.grouped() && computer.binding_group().is_none() {
            return true;
        }
        let (me, policy) = {
            let view = self.view_rx.borrow();
            (
                view.identity.as_ref().map(|id| id.fingerprint),
                view.computer_policy,
            )
        };
        me.zip(policy)
            .is_some_and(|(me, (applied, expired))| computer.policy_current(applied, expired, me))
    }

    /// An authenticated selection waits for this exact actor's actual policy application.
    /// Keep its original observation boundary across real target movement; only the
    /// request's lifecycle owner may retire it, never an elapsed-time state transition.
    pub async fn reconcile_computer(
        &self,
        superseded: Arc<PolicySupersession>,
    ) -> crate::error::Result<()> {
        let Some(computer) = &self.computer else {
            return Ok(());
        };
        // The authenticated host boundary includes headless actors, whose public view
        // deliberately has no vault Profile identity.
        let (_, identity) = self.startup_computer_boundary().ok_or(Error::Profile(
            "the selected node has no owned computer-trust identity",
        ))?;
        let observed =
            crate::node::computer::ComputerChange::now(computer.policy_target_after_writer()?);
        loop {
            if superseded.is_retired() {
                return Err(Error::ComputerPolicySuperseded);
            }
            let change = crate::node::computer::ComputerChange::at(
                computer.policy_target_after_writer()?,
                observed.apply_deadline(),
                observed.return_deadline(),
            );
            match self
                .reconcile_computer_current(change, Arc::clone(&superseded))
                .await
            {
                Err(Error::ComputerPolicySuperseded) if !superseded.is_retired() => continue,
                Err(error) => return Err(error),
                Ok(()) => {}
            }
            // Copy the projection and drop its watch borrow before taking Computer state.
            let applied = self.view_rx.borrow().computer_policy;
            let current = applied.is_some_and(|(revision, expired)| {
                computer.policy_current(revision, expired, identity)
            });
            if computer.policy_target_is(change.target()) && current {
                return Ok(());
            }
        }
    }

    /// Startup's final Ready fence may discover that policy moved after the actor opened its
    /// network. Reconcile that same actor without invoking the later-Attached-event proof hold;
    /// Ready remains unpublished until the exact durable application is settled again.
    pub async fn reconcile_computer_startup(
        &self,
        observation_end: std::time::Instant,
    ) -> crate::error::Result<()> {
        let Some(computer) = &self.computer else {
            return Ok(());
        };
        let (_, identity) = self.startup_computer_boundary().ok_or(Error::Profile(
            "startup has no owned computer-trust boundary",
        ))?;
        loop {
            let change = crate::node::computer::ComputerChange::at(
                computer.policy_target_after_writer()?,
                observation_end,
                observation_end,
            );
            // This is the same accepted startup, including after a real target change. Its
            // original observation end can report lateness but never cancels its continuation.
            let application = self
                .reconcile_computer_current_inner(change, Arc::new(PolicySupersession::default()));
            tokio::pin!(application);
            let result = tokio::select! {
                result = &mut application => result,
                () = tokio::time::sleep_until(observation_end.into()) => {
                    if computer.grouped() {
                        computer.record_application_miss(identity, change)?;
                    }
                    application.await
                }
            };
            match result {
                Err(Error::ComputerPolicySuperseded) => continue,
                Err(error) => return Err(error),
                Ok(()) => {}
            }
            match computer.require_startup_binding(identity, change.target()) {
                Err(Error::ComputerPolicySuperseded) => continue,
                result => return result,
            }
        }
    }

    /// Keep the accepted live follower event alive past its observation boundary. Only exact
    /// policy movement, detach/shutdown, or a stopped actor can supersede this future.
    pub async fn reconcile_computer_current(
        &self,
        change: crate::node::computer::ComputerChange,
        superseded: Arc<PolicySupersession>,
    ) -> crate::error::Result<()> {
        #[cfg(feature = "test-knobs")]
        self.hold_computer_reconcile_send_for_proof().await?;
        self.reconcile_computer_current_inner(change, superseded)
            .await
    }

    /// Wait for this exact target to cease being current, including a host detach.
    async fn current_policy_invalidated(
        &self,
        change: crate::node::computer::ComputerChange,
        superseded: &PolicySupersession,
    ) -> Error {
        let Some(computer) = self.computer.as_ref() else {
            superseded.retired().await;
            return Error::ComputerPolicySuperseded;
        };
        let mut changes = computer.changes();
        loop {
            if superseded.is_retired() || !computer.policy_target_is(change.target()) {
                return Error::ComputerPolicySuperseded;
            }
            tokio::select! {
                biased;
                () = superseded.retired() => return Error::ComputerPolicySuperseded,
                changed = changes.recv() => match changed {
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {},
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Error::Unreachable("computer policy notifications stopped"),
                },
            }
        }
    }

    /// Startup uses the same owned actor work without the later-Attached proof hold.
    async fn reconcile_computer_current_inner(
        &self,
        change: crate::node::computer::ComputerChange,
        superseded: Arc<PolicySupersession>,
    ) -> crate::error::Result<()> {
        if superseded.is_retired() {
            return Err(Error::ComputerPolicySuperseded);
        }
        let permit = tokio::select! {
            biased;
            error = self.current_policy_invalidated(change, &superseded) => return Err(error),
            permit = Arc::clone(&self.computer_policy_slots).acquire_owned() =>
                permit.map_err(|_| Error::Unreachable("the node has stopped"))?,
        };
        let (reply, rx) = oneshot::channel();
        let send = self.net_tx.send(NetEvent::ComputerPolicy {
            guard: ComputerPolicyGuard {
                change,
                superseded: Arc::clone(&superseded),
            },
            reply,
            permit,
        });
        tokio::select! {
            biased;
            error = self.current_policy_invalidated(change, &superseded) => return Err(error),
            result = send => result.map_err(|_| Error::Unreachable("the node has stopped"))?,
        }
        tokio::select! {
            biased;
            error = self.current_policy_invalidated(change, &superseded) => Err(error),
            result = rx => result.map_err(|_| Error::Unreachable("the node has stopped"))?,
        }
    }

    /// Run the daemon's synchronous Ready publication only while the exact durable application
    /// remains settled. This closes the gap between the actor's applied receipt and host Ready.
    pub fn with_computer_application_settled<T>(
        &self,
        identity: Digest32,
        ready: impl FnOnce() -> T,
    ) -> Option<T> {
        let Some(computer) = &self.computer else {
            return Some(ready());
        };
        let (revision, expired) = self.view_rx.borrow().computer_policy?;
        computer.with_application_settled(&identity, revision, expired, ready)
    }
}

impl Node {
    /// The policy of the actor's settled keyring, never a newly sampled durable policy. Views
    /// carry this pair with their rows so a same-revision expiry cannot certify an old grant.
    pub(super) fn applied_computer_policy(&self) -> Option<(u64, bool)> {
        self.computer.as_ref().map(|_| {
            (
                self.computer_revision
                    .load(std::sync::atomic::Ordering::Acquire),
                self.computer_expired,
            )
        })
    }

    /// Try one synchronous irreversible room write under a concurrent physical publication
    /// lease. Admission and state revalidation do not wait; closures must not acquire a Computer
    /// authority transition. Retained post work uses `acquire_publication` off actor instead.
    pub(super) fn with_current_computer_authority<T>(
        &self,
        publish: impl FnOnce() -> T,
    ) -> Option<T> {
        self.computer_authority()?.publish(publish)
    }

    /// Capture the actor's exact applied revision and node identity before asynchronous
    /// preparation. The token may cross awaits because its physical lease admission revalidates
    /// current durable authority before any irreversible publication begins.
    pub(super) fn computer_authority(&self) -> Option<ComputerAuthority> {
        let Some(computer) = &self.computer else {
            return Some(ComputerAuthority::Unmanaged);
        };
        let applied = self
            .computer_revision
            .load(std::sync::atomic::Ordering::Acquire);
        let me = self
            .profile
            .as_ref()
            .filter(|profile| profile.is_unlocked())
            .map(Profile::fingerprint)
            .or_else(|| self.headless.as_ref().map(|signer| signer.fingerprint()))?;
        Some(ComputerAuthority::Managed {
            computer: Arc::clone(computer),
            applied,
            expired: self.computer_expired,
            node: me,
        })
    }

    /// Whether this actor's live projection still names current durable policy. This read-side
    /// check never waits for physical publications. Every subsequent irreversible write also
    /// needs its publication lease; a freshness observation cannot authorize a later write.
    pub(super) fn computer_authority_current(&self) -> bool {
        self.computer_authority()
            .is_some_and(|authority| authority.current())
    }

    /// Publish rows and their exact application tag under only the watch write lock. Readers
    /// drop their watch borrow before validating the copied tag under the Computer state lock.
    pub(super) fn publish_computer_trust_projection(&self) {
        self.view_tx.send_modify(|view| {
            view.computer_policy = self.applied_computer_policy();
            view.trusted = self.trust_rows();
            view.drive = self
                .trust
                .iter()
                .map(|(fp, _)| *fp)
                .filter(|fp| self.trust.has_drive(fp))
                .collect();
        });
    }

    /// Hold startup after the exact applied receipt succeeded and before the daemon's final
    /// physical-publication Ready fence. The arm names authenticated semantic content; a prior receipt or
    /// another node cannot satisfy it.
    #[cfg(feature = "test-knobs")]
    pub(super) fn hold_after_computer_application_receipt_for_proof(
        &self,
        node: Digest32,
        revision: u64,
    ) -> crate::error::Result<()> {
        let Ok(spec) = std::env::var(TEST_HOLD_AFTER_COMPUTER_APPLICATION_RECEIPT_ENV) else {
            return Ok(());
        };
        let mut fields = spec.splitn(4, '\t');
        let (Some(arm), Some(receipt), Some(release), Some(fault)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(Error::Profile("computer receipt proof hold is malformed"));
        };
        let arm = std::path::Path::new(arm);
        let target = match std::fs::read_to_string(arm) {
            Ok(target) => target,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                crate::node::computer::publish_proof_fault(
                    std::path::Path::new(fault),
                    &format!("could not read exact applied-receipt arm: {error}"),
                );
                return Err(Error::Profile("computer receipt proof hold failed"));
            }
        };
        let target = crate::node::link::b32_decode(target.trim(), "applied-receipt proof grant")
            .map_err(|error| {
                crate::node::computer::publish_proof_fault(
                    std::path::Path::new(fault),
                    &format!("exact applied-receipt arm is not a fingerprint: {error}"),
                );
                Error::Profile("computer receipt proof hold failed")
            })?;
        let Some(computer) = &self.computer else {
            return Ok(());
        };
        if !computer.application_recorded_grant(&node, revision, &target) {
            return Ok(());
        }
        let fail = |detail: String| {
            crate::node::computer::publish_proof_fault(std::path::Path::new(fault), &detail);
            Error::Profile("computer receipt proof hold failed")
        };
        std::fs::remove_file(arm).map_err(|error| {
            fail(format!(
                "could not consume exact applied-receipt arm: {error}"
            ))
        })?;
        let release = std::path::Path::new(release);
        match std::fs::remove_file(release) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(fail(format!(
                    "could not clear applied-receipt release socket: {error}"
                )))
            }
        }
        let listener = std::os::unix::net::UnixListener::bind(release)
            .map_err(|error| fail(format!("could not bind applied-receipt release: {error}")))?;
        let marker = format!(
            "{}\t{revision}\t{}",
            crate::node::link::b32_encode(&node),
            crate::node::link::b32_encode(&target)
        );
        crate::node::computer::publish_proof_marker(
            std::path::Path::new(receipt),
            marker.as_bytes(),
        )
        .map_err(|error| fail(format!("could not publish applied-receipt marker: {error}")))?;
        listener
            .accept()
            .map_err(|error| fail(format!("applied-receipt release failed: {error}")))?;
        let _ = std::fs::remove_file(release);
        Ok(())
    }

    pub(super) fn computer_change_refused(&self, command: &NodeCommand) -> bool {
        let Some(computer) = &self.computer else {
            return false;
        };
        if !computer.grouped() {
            return false;
        }
        let Some(me) = self.profile.as_ref().map(Profile::fingerprint) else {
            return false;
        };
        let (peer, requested) = match command {
            NodeCommand::Proved { change, .. } => return self.computer_change_refused(change),
            NodeCommand::Untrust { fingerprint } => (*fingerprint, None),
            NodeCommand::SetCapability {
                fingerprint,
                capability,
            } => (*fingerprint, Some(*capability)),
            NodeCommand::TrustWith {
                fingerprint,
                capability,
                ..
            } => (*fingerprint, Some(capability.unwrap_or_default())),
            NodeCommand::Trust { fingerprint, .. } => {
                (*fingerprint, Some(crate::node::trust::Capability::Read))
            }
            _ => return false,
        };
        match computer.capability(me, &peer) {
            Ok(Some(expected)) => requested != Some(expected),
            Ok(None) => false,
            Err(_) => true,
        }
    }
}
