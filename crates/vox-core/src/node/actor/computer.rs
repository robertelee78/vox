//! Computer policy is daemon-owned. No public node command can forge a management binding.
use super::*;

/// **Test-only** (`test-knobs`): `<arm>\t<receipt>\t<release socket>\t<fault>`. `arm` contains
/// the exact grant fingerprint. Startup publishes `receipt` only after the matching applied
/// receipt removed its recovery record, then waits before actor startup returns to the daemon's
/// final state-locked Ready fence.
/// Shipped builds neither name nor read this variable.
#[cfg(feature = "test-knobs")]
const TEST_HOLD_AFTER_COMPUTER_APPLICATION_RECEIPT_ENV: &str =
    "VOX_TEST_HOLD_AFTER_COMPUTER_APPLICATION_RECEIPT_FILE";
use crate::identity::composite::RootSigner;
use crate::node::trust::HistoryGrant;

pub(super) struct KeyringApplication {
    pub(super) changes: Vec<(Digest32, crate::node::consent_order::Stamp)>,
    pub(super) settled: bool,
}

/// A captured actor projection whose final use is checked against durable Computer state. The
/// token contains no authority by itself: [`ComputerAuthority::publish`] takes the state lock and
/// revalidates the exact revision and binding through the synchronous irreversible operation.
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

impl ComputerAuthority {
    pub(super) fn publish<T>(&self, publish: impl FnOnce() -> T) -> Option<T> {
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
        self.publish(|| ()).is_some()
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

    pub(super) async fn hold_computer_policy_for_proof(&self) {
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

    /// Ask the already attached node to sign its management binding and durably apply policy.
    pub async fn reconcile_computer(
        &self,
        deadline: std::time::Instant,
    ) -> crate::error::Result<()> {
        #[cfg(feature = "test-knobs")]
        self.hold_computer_reconcile_send_for_proof().await?;
        self.reconcile_computer_inner(deadline).await
    }

    /// Startup's final Ready fence may discover that policy moved after the actor opened its
    /// network. Reconcile that same actor without invoking the later-Attached-event proof hold;
    /// Ready remains unpublished until the exact durable application is settled again.
    pub async fn reconcile_computer_startup(
        &self,
        deadline: std::time::Instant,
    ) -> crate::error::Result<()> {
        self.reconcile_computer_inner(deadline).await
    }

    async fn reconcile_computer_inner(
        &self,
        deadline: std::time::Instant,
    ) -> crate::error::Result<()> {
        let (reply, rx) = oneshot::channel();
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let send = self.net_tx.send(NetEvent::ComputerPolicy {
            deadline,
            cancelled: Arc::clone(&cancelled),
            reply,
        });
        tokio::pin!(send);
        tokio::select! {
            result = &mut send => {
                result.map_err(|_| Error::Unreachable("the node has stopped"))?;
            }
            () = tokio::time::sleep_until(deadline.into()) => {
                cancelled.store(true, std::sync::atomic::Ordering::Release);
                return Err(Error::Profile("computer trust did not enter the actor before its causal deadline"));
            }
        }
        tokio::pin!(rx);
        tokio::select! {
            biased;
            result = &mut rx => {
                let result = result.map_err(|_| Error::Unreachable("the node has stopped"))?;
                if std::time::Instant::now() >= deadline {
                    cancelled.store(true, std::sync::atomic::Ordering::Release);
                    Err(Error::Profile("computer trust did not apply before its causal deadline"))
                } else {
                    result
                }
            }
            () = tokio::time::sleep_until(deadline.into()) => {
                cancelled.store(true, std::sync::atomic::Ordering::Release);
                Err(Error::Profile("computer trust did not apply before its causal deadline"))
            }
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

    /// Journal an explicit per-node trust choice only when retired Computer history would
    /// otherwise remove it. This is local node policy, not a new Computer policy revision: it
    /// neither wakes the other nodes nor creates an exchange obligation to another machine.
    pub(super) async fn choose_individual_trust(
        &mut self,
        peer: Digest32,
    ) -> crate::error::Result<()> {
        let Some(computer) = self.computer.clone() else {
            return Ok(());
        };
        if !computer.grouped() {
            return Ok(());
        }
        let node = self
            .profile
            .as_ref()
            .filter(|profile| profile.is_unlocked())
            .map(Profile::fingerprint)
            .or_else(|| self.headless.as_ref().map(|signer| signer.fingerprint()))
            .ok_or(Error::Profile("managed node has no unlocked identity"))?;
        computer.individual_choice(node, peer)
    }

    /// Run one synchronous irreversible room write while this actor's computer-policy projection
    /// is current. Callers finish every await and take the room lock first. Computer mutations
    /// never take a room lock while holding their state lock, so this room -> policy order cannot
    /// invert.
    pub(super) fn with_current_computer_authority<T>(
        &self,
        publish: impl FnOnce() -> T,
    ) -> Option<T> {
        self.computer_authority()?.publish(publish)
    }

    /// Capture the actor's exact applied revision and node identity before asynchronous
    /// preparation. The returned token must span only the final synchronous write/queue boundary;
    /// it deliberately remains valid to carry across awaits because `publish` rechecks it.
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

    /// Whether this actor's live trust/key projection belongs to the current durable computer
    /// policy. Periodic work is an authorization path too: a queued policy event must fence the
    /// old projection before the next tick can publish consent, drive keys, or private attention.
    pub(super) fn computer_authority_current(&self) -> bool {
        self.with_current_computer_authority(|| ()).is_some()
    }

    pub(super) fn computer_policy_active(
        deadline: std::time::Instant,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> crate::error::Result<()> {
        if cancelled.load(std::sync::atomic::Ordering::Acquire)
            || std::time::Instant::now() >= deadline
        {
            Err(Error::Profile(
                "computer trust did not apply before its causal deadline",
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn prepare_computer_binding_until(
        &self,
        deadline: std::time::Instant,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> crate::error::Result<()> {
        self.prepare_computer_binding_causal(deadline, cancelled, false)
    }

    pub(super) fn prepare_computer_binding_causal(
        &self,
        deadline: std::time::Instant,
        cancelled: &std::sync::atomic::AtomicBool,
        may_replace_expired: bool,
    ) -> crate::error::Result<()> {
        Self::computer_policy_active(deadline, cancelled)?;
        let Some(computer) = &self.computer else {
            return Ok(());
        };
        if computer.binding_group().is_none() {
            return Ok(());
        }
        let name = self
            .paths
            .profile_dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(Error::Profile("managed node name is unreadable"))?;
        let signer: &(dyn RootSigner + Send + Sync) = if let Some(p) = &self.profile {
            if p.is_unlocked() {
                p.signer()?
            } else if let Some(s) = &self.headless {
                s.as_ref()
            } else {
                return Err(Error::Profile(
                    "managed node needs its passphrase to become Ready",
                ));
            }
        } else if let Some(s) = &self.headless {
            s.as_ref()
        } else {
            return Err(Error::Profile(
                "managed node needs its passphrase to become Ready",
            ));
        };
        if !may_replace_expired && computer.current_revision_expired() {
            // Reconciliation must enter `apply_computer_keyring_until` to remove the expired
            // revision's managed grants in place. Refusing here detached the node before the
            // only revocation path could run. Startup may deliberately replace an expired cause
            // by binding a newly attached node; an already-running actor may not.
            return Ok(());
        }
        computer.bind_node_until(signer, name, deadline)
    }

    /// Reconcile the durable plan under the causal boundary owned by the change that woke it.
    /// Persist the keyring before its journal receipt; repeat safely after a crash.
    pub(super) async fn apply_computer_keyring_until(
        &mut self,
        deadline: std::time::Instant,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> crate::error::Result<()> {
        Self::computer_policy_active(deadline, cancelled)?;
        let Some(c) = self.computer.clone() else {
            return Ok(());
        };
        let revision = c.policy_revision();
        let identity = self
            .profile
            .as_ref()
            .filter(|profile| profile.is_unlocked())
            .map(Profile::fingerprint)
            .or_else(|| self.headless.as_ref().map(|signer| signer.fingerprint()));
        if c.grouped() {
            c.storage_ready()?;
        }
        if !c.grouped()
            || identity.is_some_and(|identity| {
                self.computer_revision
                    .load(std::sync::atomic::Ordering::Acquire)
                    == revision
                    && c.application_settled(&identity, revision, self.computer_expired)
            })
        {
            return Ok(());
        }
        'policy: loop {
            Self::computer_policy_active(deadline, cancelled)?;
            // Binding and keyring are one policy projection. A remote roster can move policy
            // after the event's initial binding preparation while this loop is committing an
            // older keyring plan. Re-derive the binding on every retry within the same causal
            // boundary; otherwise the keyring reaches revision N while its binding remains at
            // N-1, making `policy_current` impossible and spinning until the deadline.
            self.prepare_computer_binding_until(deadline, cancelled)?;
            let mut floor = 0;
            for room in self.channels.values() {
                floor = floor.max(room.lock().await.newest_mint_seq());
                Self::computer_policy_active(deadline, cancelled)?;
            }
            let application = self.apply_computer_keyring_at_until(floor, deadline, cancelled)?;
            if !application.settled {
                continue;
            }
            if c.current_revision_expired() {
                // `apply_computer_keyring_at_until` has durably removed every grant from this
                // missed revision and published the empty projection.  Drive-key maintenance
                // requires a live management policy and used to fail here, turning successful
                // fail-closed recovery into a daemon-wide outage.
                self.publish().await;
                return Ok(());
            }
            // A policy revision can grant an already admitted member read or drive. That member
            // may not have received the live capability record before this boundary, so publish
            // discovery again. It carries no authority; rooms coalesce it to one signed record.
            self.owe_private_support_in_open_rooms().await;
            Self::computer_policy_active(deadline, cancelled)?;
            for (id, stamp) in application.changes {
                if !self.mark_trust_decision(id, stamp).await? {
                    continue 'policy;
                }
                Self::computer_policy_active(deadline, cancelled)?;
            }
            // The existing room machinery performs pending removals, sender-key rotation, and
            // consent delivery. Computer policy does not create a second room authorization path.
            self.refresh_reachers_until(deadline, cancelled).await?;
            for prepared in self.preparing_rooms.values_mut() {
                prepared.channel.get_mut().release_held_packages();
            }
            let rooms: Vec<_> = self.channels.keys().copied().collect();
            for room in rooms {
                self.act_on_removals_while_closed(&room).await?;
                Self::computer_policy_active(deadline, cancelled)?;
                if let Err(error) = self.mark_decisions_on_open(&room).await {
                    let applied = self
                        .computer_revision
                        .load(std::sync::atomic::Ordering::Acquire);
                    if identity
                        .is_some_and(|node| !c.policy_current(applied, self.computer_expired, node))
                    {
                        continue 'policy;
                    }
                    return Err(error);
                }
                Self::computer_policy_active(deadline, cancelled)?;
                if let Some(channel) = self.channels.get(&room) {
                    channel.lock().await.release_held_packages();
                }
                self.install_key_packages(&room).await;
                Self::computer_policy_active(deadline, cancelled)?;
            }
            self.deliver_owed_consents(None).await;
            Self::computer_policy_active(deadline, cancelled)?;
            if let Err(error) = self.tend_drive_keys_until(deadline, cancelled).await {
                let applied = self
                    .computer_revision
                    .load(std::sync::atomic::Ordering::Acquire);
                if identity
                    .is_some_and(|node| !c.policy_current(applied, self.computer_expired, node))
                {
                    continue 'policy;
                }
                return Err(error);
            }
            if let Err(error) = Self::computer_policy_active(deadline, cancelled) {
                c.invalidate_reachers();
                return Err(error);
            }
            self.publish().await;
            if let Err(error) = Self::computer_policy_active(deadline, cancelled) {
                c.invalidate_reachers();
                return Err(error);
            }
            let applied_revision = self
                .computer_revision
                .load(std::sync::atomic::Ordering::Acquire);
            let identity = self
                .profile
                .as_ref()
                .map(Profile::fingerprint)
                .or_else(|| self.headless.as_ref().map(|signer| signer.fingerprint()));
            if self.computer.as_ref().is_none_or(|computer| {
                identity.is_some_and(|identity| {
                    computer.application_settled(&identity, applied_revision, self.computer_expired)
                })
            }) {
                return Ok(());
            }
        }
    }

    pub(super) fn apply_computer_keyring_at_until(
        &mut self,
        floor: u64,
        deadline: std::time::Instant,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> crate::error::Result<KeyringApplication> {
        Self::computer_policy_active(deadline, cancelled)?;
        let Some(computer) = self.computer.clone() else {
            return Ok(KeyringApplication {
                changes: Vec::new(),
                settled: true,
            });
        };
        if !computer.grouped() {
            return Ok(KeyringApplication {
                changes: Vec::new(),
                settled: true,
            });
        }
        computer.storage_ready()?;
        let revision = computer.policy_revision();
        let Some(profile) = &self.profile else {
            if let Some(signer) = &self.headless {
                let expired = computer.current_revision_expired();
                let receipt = if expired {
                    computer.mark_expired_until(signer.fingerprint(), revision, deadline)?
                } else if !computer.applied(&signer.fingerprint(), revision) {
                    computer.mark_applied_until(signer.fingerprint(), revision, &[], deadline)?
                } else {
                    crate::node::computer::ApplicationReceipt::Current
                };
                if receipt == crate::node::computer::ApplicationReceipt::Current {
                    self.computer_expired = expired;
                    self.computer_revision
                        .store(revision, std::sync::atomic::Ordering::Release);
                    self.view_tx.send_modify(|view| {
                        view.computer_policy = self.applied_computer_policy();
                    });
                }
                return Ok(KeyringApplication {
                    changes: Vec::new(),
                    settled: receipt == crate::node::computer::ApplicationReceipt::Current,
                });
            }
            return Ok(KeyringApplication {
                changes: Vec::new(),
                settled: true,
            });
        };
        if !profile.is_unlocked() {
            return Ok(KeyringApplication {
                changes: Vec::new(),
                settled: true,
            });
        }
        let me = profile.fingerprint();
        // Applied at this revision already: recorded after the keyring was saved, and kept
        // across a restart, so nothing is derived or written again (ADR-038 FX-28).
        if computer.applied(&me, revision) {
            self.computer_expired = false;
            self.computer_revision
                .store(revision, std::sync::atomic::Ordering::Release);
            self.publish_computer_trust_projection();
            return Ok(KeyringApplication {
                changes: Vec::new(),
                settled: true,
            });
        }
        let Some(plan) = computer.plan(me)? else {
            return Ok(KeyringApplication {
                changes: Vec::new(),
                settled: true,
            });
        };
        let expired = plan.expired;
        let revision = plan.revision;
        let covered: Vec<_> = plan
            .grants
            .iter()
            .map(|(id, _, _)| *id)
            .chain(plan.denied.iter().copied())
            .collect();
        Self::computer_policy_active(deadline, cancelled)?;
        // Prepare before any node-store effect, including pending key/removal metadata and
        // trust-decision stamps. If a newer revision already won, none of this plan is applied.
        // Expiry prepares its retained rollback set too: a crash after revocation must not leave
        // an older live applied receipt able to certify the changed keyring after repair.
        if !computer.prepare_application_until(me, revision, expired, &covered, deadline)? {
            return Ok(KeyringApplication {
                changes: Vec::new(),
                settled: false,
            });
        }
        let aliases: Vec<_> = covered
            .iter()
            .filter_map(|peer| {
                self.trust
                    .petname(peer)
                    .map(|name| (*peer, name.to_owned()))
            })
            .collect();
        computer.retain_aliases_until(me, &aliases, deadline)?;
        let mut next = self.trust.clone();
        let mut newly = Vec::new();
        let mut removed = Vec::new();
        let mut changed_drive = Vec::new();
        // Stage closed/open room removal work with the keyring removal. Their single commit
        // leaves restart either the old grant and its delivery work, or the removed grant and
        // the pending room work which must finish before authorizing new room activity.
        let mut locks =
            crate::node::pending_lock::PendingLocks::load(profile.store(), profile.signer()?)?;
        let mut pending = self.consent_keys.clone();
        let rooms = profile.store().channels()?;
        for id in &plan.denied {
            if !next.is_trusted(id) {
                continue;
            }
            for room in &rooms {
                if !locks.insert(*room, *id) {
                    return Err(Error::Profile(
                        "computer trust removal could not be recorded",
                    ));
                }
            }
            pending.forget(id);
            changed_drive.push((*id, next.has_drive(id)));
            next.untrust(id);
            removed.push(*id);
        }
        for (id, name, capability) in plan.grants {
            locks.forget(&id);
            if self.trust.capability(&id) == Some(capability) {
                continue;
            }
            if !self.trust.is_trusted(&id) {
                newly.push(id);
            }
            changed_drive.push((id, self.trust.has_drive(&id)));
            let name = self
                .trust
                .petname(&id)
                .map(str::to_owned)
                .or_else(|| computer.alias(&me, &id))
                .unwrap_or(name);
            let history = if self.trust.is_trusted(&id) {
                self.trust.history(&id)
            } else {
                HistoryGrant::Now
            };
            // Exact replacement consumes a stronger manual drive grant. There is no shadow grant.
            next.trust_as(id, &name, history, capability)?;
        }
        let profile = self
            .profile
            .as_ref()
            .ok_or(Error::Profile("managed profile disappeared"))?;
        Self::computer_policy_active(deadline, cancelled)?;
        // The staged plan may lose to a durable expiry or newer policy before taking its writer
        // fence. The exact fence below commits all node effects together or none; there is no
        // pending-key deletion with an unchanged live keyring.
        let Some(changes) = computer.commit_application_if_current(revision, expired, || {
            Self::computer_policy_active(deadline, cancelled)?;
            let signer = profile.signer()?;
            let mut batch = profile.store().batch()?;
            next.queue_save(&mut batch, signer)?;
            locks.queue_save(&mut batch, signer)?;
            pending.queue_save(&mut batch, signer)?;
            let changes = crate::node::consent_order::ConsentOrder::queue_policy(
                &mut batch, signer, &removed, &newly, floor,
            )?;
            Self::computer_policy_active(deadline, cancelled)?;
            batch.commit()?;
            Ok(changes)
        })?
        else {
            return Ok(KeyringApplication {
                changes: Vec::new(),
                settled: false,
            });
        };
        // The keyring commit is now irreversible. Always classify it against durable Computer
        // policy and, when needed, perform its rollback before consulting the caller's deadline.
        // The previous applied marker no longer describes this changed keyring. Invalidate it
        // until a Current receipt installs the exact new projection; otherwise a same-revision
        // expiry repair can make the old marker short-circuit the required grant restoration.
        self.computer_revision
            .store(u64::MAX, std::sync::atomic::Ordering::Release);
        self.trust = next;
        self.consent_keys = pending;
        let receipt = if expired {
            computer.mark_expired_until(me, revision, deadline)?
        } else {
            computer.mark_applied_until(me, revision, &covered, deadline)?
        };
        if receipt == crate::node::computer::ApplicationReceipt::Reconcile {
            // `next` is the keyring now on disk. Keep the actor's private projection aligned with
            // that durable fact, but publish none of its transient authority; the prepared record
            // makes the immediately repeated pass revoke or supersede it after a crash too.
            return Ok(KeyringApplication {
                changes: Vec::new(),
                settled: false,
            });
        }
        // The durable keyring and its application receipt are now one settled projection.
        // Publish its exact revision, notifications and live view before checking elapsed time:
        // a deadline crossed during the receipt write must not strand a completed application
        // behind the actor's old revision or an old trust view. The timing verdict still fails
        // below. A later durable policy change still fences every irreversible publication
        // because `policy_current` compares this exact revision with durable state.
        self.computer_expired = expired;
        self.computer_revision
            .store(revision, std::sync::atomic::Ordering::Release);
        for (id, was) in changed_drive {
            self.note_capability(id, was);
        }
        self.publish_computer_trust_projection();
        if let Err(error) = Self::computer_policy_active(deadline, cancelled) {
            computer.invalidate_reachers();
            return Err(error);
        }
        Ok(KeyringApplication {
            changes,
            settled: true,
        })
    }

    /// Publish rows and their exact application tag under only the watch write lock. Readers
    /// drop their watch borrow before validating the copied tag under the Computer state lock.
    fn publish_computer_trust_projection(&self) {
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
    /// state-locked Ready fence. The arm names authenticated semantic content; a prior receipt or
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
