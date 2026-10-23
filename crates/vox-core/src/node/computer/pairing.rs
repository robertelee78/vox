//! The bounded computer-group enrollment ceremony on the daemon's existing authenticated QUIC presence.
use super::*;
use crate::join::{cpace, pop};
use crate::nat::bootstrap::BootstrapSet;
use crate::nat::multiaddr::{EndpointList, Multiaddr};
use crate::node::network::NodeNet;
use crate::node::presence::NetPresence;
use crate::transport::{
    framing::{read_frame_until as read_frame_before, write_frame},
    quic::VoxConnection,
    streams::{self, StreamKind},
};
use base64::Engine as _;
use quinn::{RecvStream, SendStream};
use std::time::Duration;

const PAIR_DOMAIN: &[u8] = b"vox/computer-pair/v1\0";
const PATIENCE: Duration = Duration::from_secs(15);
const MANAGEMENT_SLOTS: usize = 8;
/// **Test-only** (`test-knobs`): `<arm path>\t<engaged path>`. The arm contains the policy revision
/// before the proof's change. The later exchange that atomically consumes it creates the engaged
/// marker after the source-owned local-apply interval and parks until superseded. This gives the
/// shipped journey a causal stale-flight boundary without copying a sleep or product timeout.
/// Shipped builds neither name nor read this variable.
#[cfg(feature = "test-knobs")]
const TEST_HOLD_FIRST_COMPUTER_EXCHANGE_ENV: &str = "VOX_TEST_HOLD_FIRST_COMPUTER_EXCHANGE_FILE";
/// **Test-only** (`test-knobs`): `<arm>\t<engaged>\t<release socket>\t<fault>`. Once a superseded
/// exchange has released its reservation and left only its causal retry mark, the scheduler
/// creates `engaged` and waits for one connection to `release`. This lets a shipped-binary
/// journey place an operator takeover at that exact boundary; no verdict reads this apparatus.
#[cfg(feature = "test-knobs")]
const TEST_HOLD_COMPUTER_RETRY_READY_ENV: &str = "VOX_TEST_HOLD_COMPUTER_RETRY_READY_FILE";
/// **Test-only** (`test-knobs`): `<arm>\t<engaged>\t<superseded>\t<release socket>`. An operator
/// pairing parks after reserving its exact flight but before spawning/installing its task. When a
/// later policy revision supersedes that handle-less flight, the scheduler creates `superseded`.
/// A shipped-binary journey can therefore release the operator only after causally staging the
/// reserve-to-handle-install race; shipped builds neither name nor read this variable.
#[cfg(feature = "test-knobs")]
const TEST_HOLD_COMPUTER_OPERATOR_RESERVED_ENV: &str =
    "VOX_TEST_HOLD_COMPUTER_OPERATOR_RESERVED_FILE";
/// **Test-only** (`test-knobs`): `<arm>\t<engaged>\t<release socket>`. The answerer parks only
/// after atomically merging the request and before writing its reply. A shipped-binary journey
/// can observe the resulting effective keyring, let the initiator's causal deadline expire, then
/// release this exact answer so the later marker must revoke the already-published grant.
#[cfg(feature = "test-knobs")]
const TEST_HOLD_COMPUTER_ANSWER_AFTER_MERGE_ENV: &str =
    "VOX_TEST_HOLD_COMPUTER_ANSWER_AFTER_MERGE_FILE";
/// Test-only exact management-path partition. Room streams are unaffected. The arm contains the
/// authenticated peer fingerprint; `<arm>\t<marker>` stays armed through the diagnostic phase.
#[cfg(feature = "test-knobs")]
const TEST_PARTITION_COMPUTER_PEER_ENV: &str = "VOX_TEST_PARTITION_COMPUTER_PEER_FILE";
/// **Test-only** (`test-knobs`): `<arm>\t<generation>\t<release>\t<answered>`. The arm is consumed
/// by an enrolled real Vox peer, which clears earlier apparatus state and creates a unique
/// generation. It retains only requests whose authenticated hello was echoed (so admission, not
/// an attempted stream, is counted), then releases all admitted answers together and stops
/// reading. This is peer apparatus; the verdict still comes from the other shipped daemon's
/// status/trust projection.
#[cfg(feature = "test-knobs")]
const TEST_STOPPED_READER_ARM_ENV: &str = "VOX_TEST_FX28_STOPPED_READER_ARM_FILE";
/// **Test-only** (`test-knobs`): `<generation>\t<release>\t<answered>`. The answering shipped
/// daemon counts only errors in the exact generation created when the peer consumed its arm. Each
/// admitted request waits at a causal release boundary after echoing its hello, then the daemon
/// creates the answered marker after every bounded slot reaches the unread error-response boundary.
#[cfg(feature = "test-knobs")]
const TEST_STOPPED_READER_ANSWERED_ENV: &str = "VOX_TEST_FX28_STOPPED_READER_ANSWERED_FILE";

// An exchange carries retained records from the same bounded transaction, never a smaller
// unrelated limit that would strand an otherwise valid roster as nodes are added.
const MAX_FRAME: usize = MAX_STATE as usize;
pub(super) fn now() -> u64 {
    static CLOCK: std::sync::OnceLock<crate::time::Clock> = std::sync::OnceLock::new();
    CLOCK.get_or_init(crate::time::clock_with_test_skew)()
}
fn text_id(id: &Digest32) -> String {
    crate::node::link::b32_encode(id)
}

/// Identity facts shown before approval; the fingerprint is authority, the name is presentation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComputerIdentity {
    /// Presented computer name.
    pub name: String,
    /// Full management fingerprint.
    pub fingerprint: String,
    /// Stable data-root discriminator; not physical hardware attestation.
    pub installation: String,
}
impl ComputerIdentity {
    fn of(d: &Description) -> Result<Self> {
        Ok(Self {
            name: d.name.clone(),
            fingerprint: text_id(&d.fingerprint()?),
            installation: text_id(&d.installation),
        })
    }
}
/// A PAKE-authenticated enrollment awaiting its exact operator approval or peer confirmation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PairingPreview {
    /// Exact immutable genesis operation being displayed and approved.
    pub operation_id: String,
    /// The other authenticated installation.
    pub peer: ComputerIdentity,
    /// This operator's approval is already durably recorded.
    pub approved_here: bool,
    /// The peer's composite approval is already durably recorded.
    pub approved_there: bool,
    /// Invitation expiry, Unix milliseconds.
    pub expires_ms: u64,
}
/// One completed exchange of pairing state with a computer, as `vox computer status` dates it
/// (ADR-038 FX-28): when it completed, this daemon's policy revision it sent, and this daemon's
/// revision after merging what the computer sent (the same number when the merge moved nothing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExchangeRecord {
    /// When the exchange completed, Unix milliseconds.
    pub at_ms: u64,
    /// This daemon's policy revision in the state it sent.
    pub sent_revision: u64,
    /// This daemon's policy revision after merging the computer's state.
    pub merged_revision: u64,
}
/// Signed application of the exact current group frontier, independent of present reachability.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComputerApplication {
    /// Enrolled installation.
    pub computer: ComputerIdentity,
    /// This member signed a complete applied receipt for the current frontier.
    pub confirmed: bool,
    /// When this node last exchanged pairing state with it, Unix milliseconds; `None` before the
    /// first exchange since the daemon started.
    pub last_exchange_ms: Option<u64>,
    /// Exchanges since the daemon started: with nothing to settle, a few per hour, not one every
    /// two seconds (ADR-038 FX-15; #989).
    pub exchanges: u64,
    /// Attempts since the daemon started, completed or not: every round the retry ran toward
    /// it, so a proof can count rounds per computer (ADR-038 FX-15).
    pub exchange_attempts: u64,
    /// Whether this daemon currently owns the peer's exchange reservation, from reservation
    /// through completion. Together with attempts and completions this distinguishes active work
    /// from a wedged attempt without guessing from elapsed wall-clock time.
    #[serde(default)]
    pub exchange_in_flight: bool,
    /// Attempts in a row that could not reach it; the retry backs off with each.
    pub exchange_failures: u32,
    /// Exact policy revision whose convergence contract was missed, retained after replacement.
    #[serde(default)]
    pub missed_revision: Option<u64>,
    /// Whether the missed revision's state was eventually exchanged after its deadline.
    #[serde(default)]
    pub repaired_late: bool,
    /// Current structural outcome: pending, expired, repaired-late, replaced, or converged.
    #[serde(default)]
    pub convergence_state: String,
    /// The last exchange this daemon started with it that completed: a change made here
    /// travels in one of these (ADR-038 FX-28).
    #[serde(default)]
    pub last_started_exchange: Option<ExchangeRecord>,
    /// The last exchange it started that this daemon answered: a change made there arrives in
    /// one of these, or in the reply to one this daemon started.
    #[serde(default)]
    pub last_answered_exchange: Option<ExchangeRecord>,
}
/// A node identity proved by its node and managing computer, with current policy role.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComputerNode {
    /// Full management identity.
    pub computer: String,
    /// Full node identity, never inferred from its name.
    pub fingerprint: String,
    /// Authenticated presented name; local keyring aliases are separate.
    pub name: String,
    /// Saved selected personal node; drives non-personal nodes while enrolled.
    pub personal: bool,
    /// For a node of this computer: the policy revision its binding was last derived at since
    /// the daemon started, so a person can tell a stale binding from a current one (ADR-038
    /// FX-28); `None` for another computer's node, or one not Ready since the daemon started.
    #[serde(default)]
    pub binding_revision: Option<u64>,
    /// When that binding was derived, Unix milliseconds.
    #[serde(default)]
    pub binding_derived_ms: Option<u64>,
}
/// One available explicit operation derived from retained authenticated binding evidence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComputerBindingAction {
    /// Full node identity.
    pub node: String,
    /// Authenticated presented node name.
    pub name: String,
    /// Previous/current managing computer identity.
    pub computer: String,
    /// release / transfer / recover.
    pub action: String,
}
/// Daemon-wide public state. A failed reach is not a rejection of the pairing code.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComputerStatus {
    /// This installation's persistent identity.
    pub this_computer: ComputerIdentity,
    /// Exact fixed-policy explanation used by both app and CLI.
    pub policy: String,
    /// Individual, waiting, needs-approval, applying, expired, or confirmed.
    pub state: String,
    /// This daemon's policy revision: it moves with every change to computer trust, made here or
    /// merged from an exchange; a node's binding is current when it names the same revision.
    #[serde(default)]
    pub revision: u64,
    /// Current one-time link, returned only over the account's private control socket.
    pub invite_link: Option<String>,
    /// Identifier used to cancel before a peer has presented itself.
    pub invite_id: Option<String>,
    /// Its expiry, Unix milliseconds.
    pub invite_expires_ms: Option<u64>,
    /// Authenticated candidate, never populated from an unproved name or fingerprint.
    pub pairing: Option<PairingPreview>,
    /// Explicitly enrolled computers.
    pub computers: Vec<ComputerIdentity>,
    /// Per-member application; unreachable members never get a fabricated acknowledgement.
    pub applications: Vec<ComputerApplication>,
    /// Current authenticated roster and personal roles.
    pub nodes: Vec<ComputerNode>,
    /// Explicit binding operations supported by retained signed evidence.
    pub binding_actions: Vec<ComputerBindingAction>,
    /// Former members retained as removal history, never acknowledgement of remote erasure.
    pub removed: Vec<ComputerIdentity>,
    /// Exact frontier to confirm when removing a computer; stale confirmations are refused.
    pub frontier: String,
    /// Saved local selection, including before a group is formed.
    pub selected_node: Option<String>,
    /// Local name captured from the same verified actor as the selection.
    pub selected_name: Option<String>,
    /// Managed nodes still needing attach/unlock or policy reconciliation.
    pub pending_nodes: Vec<String>,
    /// Last reach or protocol failure, without any secret or full link.
    pub problem: Option<String>,
}

struct Link {
    target: Digest32,
    invite: Digest32,
    secret: Zeroizing<[u8; 16]>,
    transport: Zeroizing<Digest32>,
    expires: u64,
    endpoints: EndpointList,
    anchors: BootstrapSet,
}
impl Link {
    fn url(&self) -> String {
        let mut e = Encoder::for_secrets();
        e.array(8)
            .uint(PROTOCOL)
            .bytes(&self.target)
            .bytes(&self.invite)
            .bytes(self.secret.as_ref())
            .uint(self.expires)
            .array(self.endpoints.len());
        for a in self.endpoints.addrs() {
            e.text(&a.to_string());
        }
        e.bytes(&self.anchors.to_bytes())
            .bytes(self.transport.as_ref());
        format!(
            "vox-computer://{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(e.finish())
        )
    }
    fn parse(text: &str) -> Result<Self> {
        let fail = || Error::Profile("invalid computer pairing link");
        let text = text.strip_prefix("vox-computer://").ok_or_else(fail)?;
        if text.len() > 16384 {
            return Err(fail());
        }
        let bytes = Zeroizing::new(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(text)
                .map_err(|_| fail())?,
        );
        let mut d = Decoder::new(&bytes);
        arity(&mut d, 8)?;
        if d.uint()? != PROTOCOL {
            return Err(fail());
        }
        let target = digest(&mut d)?;
        let invite = digest(&mut d)?;
        let secret = Zeroizing::new(d.bytes()?.try_into().map_err(|_| fail())?);
        let expires = d.uint()?;
        let n = d.array()?;
        if n > 8 {
            return Err(fail());
        }
        let mut addrs = Vec::new();
        for _ in 0..n {
            addrs.push(Multiaddr::parse(d.text()?)?);
        }
        let endpoints = EndpointList::new(addrs)?;
        let anchors = BootstrapSet::from_bytes(d.bytes()?)?;
        let transport = Zeroizing::new(digest(&mut d)?);
        d.finish()?;
        Ok(Self {
            target,
            invite,
            secret,
            transport,
            expires,
            endpoints,
            anchors,
        })
    }
}

#[derive(Clone)]
struct TransportLease {
    registration: Digest32,
    token: Zeroizing<Digest32>,
    expires: u64,
    peer: Option<Digest32>,
    anchors: BootstrapSet,
    /// Established transport is renewed; one-time transport simply expires with its invite.
    renewable: bool,
}

#[derive(Clone, Copy)]
struct RegisteredLease {
    connection: u64,
    expires: u64,
    peer: Option<Digest32>,
}

/// Management network and ceremony. It never dispatches room streams, even for enrolled peers.
pub struct Management {
    /// The sole persistent transaction domain.
    pub computer: Arc<Computer>,
    net: Arc<NodeNet>,
    anchors: BootstrapSet,
    serving: Mutex<std::collections::BTreeSet<u64>>,
    /// Computers an exchange is in flight with: one at a time per computer, never a round that
    /// waits for every computer, so a slow one delays no other (#989).
    inflight: Mutex<BTreeMap<Digest32, Flight>>,
    slots: Arc<tokio::sync::Semaphore>,
    problem: Mutex<Option<String>>,
    pending_nodes: Mutex<Vec<String>>,
    transport_cache: Mutex<BTreeMap<(Digest32, Digest32), RegisteredLease>>,
    revoked_transport: Mutex<std::collections::BTreeSet<(Digest32, Digest32, u64)>>,
    /// Per computer: when this node last exchanged state with it, and how many exchanges in a row
    /// failed since one succeeded. What `retry` keys its cadence on (ADR-038 FX-15; #989).
    exchanged: Mutex<BTreeMap<Digest32, Exchanged>>,
    /// Serializes outcome persistence without nesting the flight lock with computer state.
    recording: Mutex<()>,
    /// Coalesced reasons to reconsider the exact next exchange deadline: local state, a real
    /// network change, an authenticated peer connection/stream, or an attempt ending.
    retry_wake: Arc<tokio::sync::Notify>,
    /// Failed peers whose authenticated reachability or machine path changed since their last
    /// attempt. Consumed once by `retry`, bypassing only that attempt's time backoff.
    retry_ready: Mutex<BTreeMap<Digest32, RetryMark>>,
    /// Coalesced causes for transport registration: durable policy, a real network transition,
    /// an authenticated anchor connection ending, or an exact lease-renewal deadline.
    transport_wake: Arc<tokio::sync::Notify>,
    /// At most one authenticated reachability waiter per failing computer. Its one stream is
    /// retained by QUIC through a transient path outage and wakes retry when the path carries it.
    reachability_waiters: Mutex<BTreeMap<Digest32, (u64, tokio::task::AbortHandle)>>,
}

/// One computer's exchange record.
#[derive(Clone, Debug, Default)]
struct Exchanged {
    /// Newest flight whose outcome was recorded; a torn older task cannot overwrite it.
    last_serial: u64,
    /// The last attempt, succeeded or not.
    last: Option<std::time::Instant>,
    /// The last completed exchange, Unix milliseconds, for the status a person reads.
    last_ms: Option<u64>,
    /// Exchanges completed since the daemon started.
    count: u64,
    /// Attempts since the daemon started, counted when each starts: completed or not, in
    /// flight or cut.
    attempts: u64,
    /// Failures in a row since the last success; the backoff doubles with each.
    failures: u32,
    /// End of the one return contract that began at the last failed attempt. The next backoff
    /// and exchange share it; neither gets a fresh timeout.
    deadline: Option<std::time::Instant>,
    /// Operator-policy revision which owns `deadline`. A newer policy owns a fresh causal clock;
    /// an expired deadline without this matching owner cannot expire that newer policy.
    deadline_policy_revision: Option<u64>,
    /// This node's state revision at the last attempt, and whether a pairing operation
    /// involving the computer was open then: a change in either is tried at once, backoff or
    /// not; the same state waits the backoff out.
    revision: u64,
    involved: bool,
    /// The last failure's words, while failures stand.
    problem: Option<String>,
    /// Revision whose causal deadline was missed, whether or not repair has completed yet.
    missed_revision: Option<u64>,
    /// The state which was repaired only after its causal deadline. Its completed exchange is
    /// still useful evidence and stops redundant retries, but the missed contract remains a
    /// visible failure until a newer state creates a new cause and deadline.
    repaired_late: Option<u64>,
    /// The last completed exchange this node started, and the last one it answered.
    last_started: Option<ExchangeRecord>,
    last_answered: Option<ExchangeRecord>,
}

#[derive(Clone, Copy, Debug)]
struct RetryMark {
    token: u64,
    /// Operator-policy revision which owns this causal clock. Journal movement may update the
    /// payload revision without turning an older policy clock into the owner of a newer policy.
    policy_revision: u64,
    revision: u64,
    deadline: std::time::Instant,
}

/// One exchange attempt's bookkeeping: records its outcome when done, and a failure if the
/// task is torn down before (a panic), so a computer never stays in flight forever.
struct Attempt {
    me: Arc<Management>,
    peer: Digest32,
    serial: u64,
    revision: u64,
    policy_revision: u64,
    involved: bool,
    causal: bool,
    deadline: std::time::Instant,
    recorded: bool,
}

impl Attempt {
    fn done(mut self, outcome: std::result::Result<(u64, u64, u64), String>) {
        self.recorded = true;
        let (outcome, covered_payload) = match outcome {
            Ok((sent_revision, sent_policy_revision, merged_revision)) => (
                Ok((sent_revision, merged_revision)),
                Some((sent_revision, sent_policy_revision)),
            ),
            Err(error) => (Err(error), None),
        };
        self.me.record_exchange(
            self.peer,
            self.serial,
            self.revision,
            self.policy_revision,
            self.involved,
            self.causal,
            self.deadline,
            outcome,
            covered_payload,
        );
        // Dropped here: the reservation is released by its owner, after the record.
    }
}

/// One exchange in flight: the state it carries, so a later change can cut it, and how.
struct Flight {
    /// This flight, as distinct from any later one with the same computer: an abort handle is
    /// installed, and a reservation released, only for the flight that owns them.
    serial: u64,
    /// Operator-policy revision which owns this flight's causal clock. `revision` still decides
    /// whether its actual exchange payload was superseded; keeping both prevents a larger
    /// transport/pairing journal number from making an older policy own a newer policy's clock.
    policy_revision: u64,
    revision: u64,
    involved: bool,
    /// This flight discharges a policy/receipt/failure obligation. A quiet fallback is false: an
    /// overlapping inbound fallback must not cancel it and manufacture a second local attempt.
    causal: bool,
    /// Earliest causal return deadline among the changes this flight is responsible for. A
    /// superseding revision inherits it before this task is cut, so coalescing never restarts the
    /// user's convergence clock.
    deadline: std::time::Instant,
    /// Who started it: the retry, or the operator's pairing command.
    origin: Origin,
    abort: Option<tokio::task::AbortHandle>,
    /// A complete inbound exchange replied with at least this noncausal flight's snapshot. Its
    /// later success may still count; its later failure cannot overwrite that completed success.
    covered: bool,
    /// Cut because this node changed meanwhile: its end is no failure, and the next tick
    /// exchanges again. Read and cleared with the flight's removal, under the one lock.
    superseded: bool,
}

/// The next flight's serial.
fn next_flight() -> u64 {
    static SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Who started an exchange in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Origin {
    Retry,
    Operator,
}

/// A computer reserved as in flight by the operator's pairing: released on drop, and the
/// handshake task cut with it, so a pairing command that is dropped (its request cancelled)
/// leaves no handshake running unreserved.
struct Reserved {
    me: Arc<Management>,
    peer: Digest32,
    serial: u64,
    abort: Option<tokio::task::AbortHandle>,
}

impl Drop for Reserved {
    fn drop(&mut self) {
        if let Some(abort) = &self.abort {
            abort.abort();
        }
        let mut inflight = lock(&self.me.inflight);
        if inflight
            .get(&self.peer)
            .is_some_and(|f| f.serial == self.serial)
        {
            inflight.remove(&self.peer);
        }
        // Flight release is useful to both the scheduler and an operator command taking over
        // this exact peer. Wake every already-registered waiter, then leave one coalesced permit
        // for the scheduler if release landed between its retry turn and its next registration.
        self.me.retry_wake.notify_waiters();
        self.me.retry_wake.notify_one();
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        // Remove and read in one step under the flight lock, then release that lock before an
        // outcome can acquire durable computer state. Outcome recording is serial-ordered, so a
        // newer flight which finishes in between cannot be overwritten by this torn older task.
        let should_record = {
            let mut inflight = lock(&self.me.inflight);
            let Some(flight) = inflight.get(&self.peer) else {
                return;
            };
            if flight.serial != self.serial {
                return;
            }
            // A covered quiet flight may still record a normal success through `done`, but if its
            // task tears down the inbound full exchange has already won. Do not lose the coverage
            // bit with this removal and then manufacture a failure from the guard path.
            let should_record = !self.recorded && !flight.superseded && !flight.covered;
            inflight.remove(&self.peer);
            should_record
        };
        if should_record {
            self.me.record_exchange(
                self.peer,
                self.serial,
                self.revision,
                self.policy_revision,
                self.involved,
                self.causal,
                self.deadline,
                Err("the exchange task failed".to_owned()),
                None,
            );
        }
        // See `Reserved::drop`: a takeover and the scheduler can both be waiting for this one
        // causal release.
        self.me.retry_wake.notify_waiters();
        self.me.retry_wake.notify_one();
    }
}

/// Without a need, a computer whose receipt covers this node's current state is exchanged with
/// this often, so a lost message never leaves two computers apart for long.
const EXCHANGE_FALLBACK: Duration = COMPUTER_QUIET_EXCHANGE_AFTER;
/// An authenticated no-state-change request held on a failed peer's QUIC connection. Its stream
/// is written once; QUIC wakes it on delivery when a transient path becomes reachable again.
const REACHABILITY_WAKE_OP: u64 = 3;
/// An operator's enrollment ceremony may carry a long retained history, but never holds its
/// explicit command forever. Ordinary convergence uses [`COMPUTER_RETURN_SHOWN_WITHIN`].
pub const COMPUTER_PAIR_WITHIN: Duration = Duration::from_secs(600);
impl Management {
    /// Register and renew rendezvous leases only for a real cause. The only timer is derived
    /// from the expiry returned by the registration itself; a quiet daemon has no refresh tick.
    fn start_transport_refresh(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let Some(me) = weak.upgrade() else { return };
            let mut policy = me.computer.changes();
            let mut network = me.net.presence().changes();
            let wake = Arc::clone(&me.transport_wake);
            drop(me);
            loop {
                let Some(me) = weak.upgrade() else { return };
                // An optional unreachable anchor never holds up direct pairing, status or retry.
                let next = match me.refresh_transport().await {
                    Ok(next) => next,
                    // A failed transport registration or cancellation is unfinished durable
                    // work. Retry from that failure itself; it must not wait for unrelated
                    // policy or network traffic.
                    Err(_) => Some(std::time::Instant::now() + COMPUTER_CHANGE_SHOWN_WITHIN),
                };
                drop(me);
                let deadline = async {
                    match next {
                        Some(at) => tokio::time::sleep_until(at.into()).await,
                        None => std::future::pending::<()>().await,
                    }
                };
                tokio::select! {
                    () = deadline => {}
                    () = wake.notified() => {}
                    changed = policy.recv() => {
                        if matches!(changed, Err(tokio::sync::broadcast::error::RecvError::Closed)) {
                            return;
                        }
                    }
                    changed = network.recv() => {
                        if matches!(changed, Err(tokio::sync::broadcast::error::RecvError::Closed)) {
                            return;
                        }
                    }
                }
            }
        });
    }

    /// The account's explicit host:port lookup uses its existing socket, but no management
    /// identity or authority. The returned fingerprint is proved; lookup persists no anchor source.
    pub async fn lookup_anchor(&self, input: &str) -> Result<String> {
        let input = input.to_owned();
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            let resolve = input.clone();
            let addresses = tokio::task::spawn_blocking(move || {
                crate::node::link::parse_anchor_addrs(&resolve)
            })
            .await
            .map_err(|error| {
                Error::Handshake(format!("anchor address lookup stopped: {error}"))
            })??;
            let mut errors = Vec::new();
            for address in addresses.iter().filter_map(|a| a.socket_addr()).take(8) {
                match self
                    .net
                    .manager()
                    .endpoint()
                    .shared()
                    .lookup_anchor(address)
                    .await
                {
                    Ok(id) => return Ok(format!("{}@{input}", crate::node::link::b32_encode(&id))),
                    Err(error) => errors.push(format!("{address}: {error}")),
                }
            }
            Err(Error::Handshake(format!(
                "no anchor was verified at {input}: {}",
                errors.join("; ")
            )))
        })
        .await
        .map_err(|_| {
            Error::Handshake("anchor lookup did not finish within 20 s; nothing was added".into())
        })?
    }

    /// Record transport reach without creating a policy-application event or receipt. An
    /// endpoint change cannot renew an expired node application's causal deadline.
    pub fn record_reach(&self) -> Result<()> {
        let local = self.computer.signer.fingerprint();
        let endpoints = self.net.local_endpoints()?;
        self.computer
            .change(|s| self.record_reach_in(s, local, endpoints))
    }

    fn record_reach_in(
        &self,
        s: &mut State,
        local: Digest32,
        endpoints: EndpointList,
    ) -> Result<()> {
        if s.genesis.is_some() && s.grant(&local).is_some() && s.quarantined.is_empty() {
            let reach = Reach {
                endpoints,
                anchors: self.anchors.clone(),
                token: s
                    .reaches
                    .get(&local)
                    .map(|r| r.token)
                    .unwrap_or(random_array()?),
            };
            if s.reaches.get(&local) != Some(&reach) {
                let mut body = Encoder::new();
                body.array(1).bytes(&reach.encode());
                let event =
                    Control::sign(s, "reach", body.finish(), self.computer.signer.as_ref())?;
                s.retain_roster(event)?;
            }
        }
        Ok(())
    }

    /// Sign a receipt only for the exact locally applied policy and authenticated roster frontier.
    /// The remote receipt is a separate statement: offline peers remain pending.
    pub fn record_application(&self) -> Result<()> {
        if !lock(&self.pending_nodes).is_empty() {
            return Ok(());
        }
        let local = self.computer.signer.fingerprint();
        let endpoints = self.net.local_endpoints()?;
        self.computer.change(|s| {
            self.record_reach_in(s, local, endpoints)?;
            // A reach record is transport state, not a later operator-policy cause. It must not
            // make an expired policy current again or recreate the computer's applied receipt.
            if Computer::revision_expired(s) {
                s.receipts.remove(&local);
                return Ok(());
            }
            let Some(g) = &s.genesis else {
                return Ok(());
            };
            if !s.quarantined.is_empty() || !s.history_complete() || !s.binding_approvals.is_empty()
            {
                return Ok(());
            }
            if s.rosters.len() != s.descriptions().len() {
                return Ok(());
            }
            let Some(roster) = s.rosters.get(&local) else {
                return Ok(());
            };
            for b in roster.read(&local, &g.incarnation())?.2 {
                let node = b.verify(&local, &g.incarnation())?;
                if !Computer::application_settled_in(s, &node, s.policy_revision)
                    || !s.applied.get(&node).is_some_and(|a| {
                        a.revision == s.policy_revision && a.interval == g.incarnation()
                    })
                {
                    return Ok(());
                }
            }
            let body = receipt_body(s, s.policy_revision)?;
            if s.receipts.get(&local).is_some_and(|r| r.body == body) {
                return Ok(());
            }
            s.receipts.insert(
                local,
                Signed::create(
                    b"vox/computer-applied/v1\0",
                    body,
                    self.computer.signer.as_ref(),
                )?,
            );
            // This receipt is new exchange payload even though it changes no operator policy.
            // Give it a journal identity so the event-driven scheduler sends it once; do not use
            // `advance_journal`, whose purpose is a new management cause and clears receipts.
            s.revision = s.revision.checked_add(1).ok_or_else(bad)?;
            Ok(())
        })
    }
    /// Attach the management role to the existing presence, including a daemon with zero nodes.
    pub fn start(
        computer: Arc<Computer>,
        presence: Arc<NetPresence>,
        anchors: BootstrapSet,
    ) -> Result<Arc<Self>> {
        computer.recover_pending_exchanges()?;
        let mut link = presence.attach_management(Arc::clone(&computer.signer))?;
        let net = Arc::new(NodeNet::new(
            link.endpoint,
            presence,
            crate::time::clock_with_test_skew(),
        ));
        let mut policy = crate::node::net::PeerPolicy::new();
        for a in anchors.nodes() {
            policy.add_anchor(a.id);
        }
        net.policy().replace(policy);
        let (current_policy_revision, durable_misses) = computer.missed_exchanges();
        let exchanged: BTreeMap<_, _> = durable_misses
            .into_iter()
            .filter(|(_, (revision, _))| *revision == current_policy_revision)
            .map(|(peer, (revision, repaired))| {
                (
                    peer,
                    Exchanged {
                        attempts: 1,
                        failures: 1,
                        revision,
                        problem: Some(if repaired {
                            "the exchange repaired state only after its causal convergence deadline"
                                .into()
                        } else {
                            "the exchange did not finish before its causal convergence deadline"
                                .into()
                        }),
                        missed_revision: Some(revision),
                        repaired_late: repaired.then_some(revision),
                        ..Exchanged::default()
                    },
                )
            })
            .collect();
        let problem = exchanged.values().find_map(|record| record.problem.clone());
        let me = Arc::new(Self {
            computer,
            net,
            anchors,
            serving: Mutex::new(Default::default()),
            inflight: Mutex::new(BTreeMap::new()),
            slots: Arc::new(tokio::sync::Semaphore::new(MANAGEMENT_SLOTS)),
            problem: Mutex::new(problem),
            pending_nodes: Mutex::new(Vec::new()),
            transport_cache: Mutex::new(BTreeMap::new()),
            revoked_transport: Mutex::new(Default::default()),
            exchanged: Mutex::new(exchanged),
            recording: Mutex::new(()),
            retry_wake: Arc::new(tokio::sync::Notify::new()),
            retry_ready: Mutex::new(BTreeMap::new()),
            transport_wake: Arc::new(tokio::sync::Notify::new()),
            reachability_waiters: Mutex::new(BTreeMap::new()),
        });
        let weak = Arc::downgrade(&me);
        tokio::spawn(async move {
            while let Some(c) = link.inbound.recv().await {
                let Some(me) = weak.upgrade() else {
                    return;
                };
                let filed = me.net.manager().take_inbound(c).await;
                me.serve(filed.kept);
                if let Some(c) = filed.also_serve {
                    me.serve(c);
                }
            }
        });
        let weak = Arc::downgrade(&me);
        tokio::spawn(async move {
            let Some(me) = weak.upgrade() else { return };
            let mut changes = me.computer.changes();
            let mut journal = me.computer.journal_changes();
            let mut network = me.net.presence().changes();
            let wake = Arc::clone(&me.retry_wake);
            drop(me);
            loop {
                let Some(me) = weak.upgrade() else {
                    return;
                };
                // Register before retry inspects/spawns. An attempt may finish on another worker
                // before retry returns; this enabled permit preserves that exact release edge.
                let released = wake.notified();
                tokio::pin!(released);
                released.as_mut().enable();
                let next = match me.retry().await {
                    Ok(next) => next,
                    Err(e) => {
                        *lock(&me.problem) = Some(e.to_string());
                        Some(std::time::Instant::now() + EXCHANGE_FALLBACK)
                    }
                };
                drop(me);
                let deadline = async {
                    match next {
                        Some(at) => tokio::time::sleep_until(at.into()).await,
                        None => std::future::pending::<()>().await,
                    }
                };
                tokio::select! {
                    () = deadline => {}
                    () = &mut released => {}
                    changed = changes.recv() => {
                        match changed {
                            Ok(event) => {
                                if let Some(me) = weak.upgrade() {
                                    me.retry_changed_now(event);
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                if let Some(me) = weak.upgrade() {
                                    // Never extend a missed cause: an immediate deadline is the
                                    // conservative failure boundary.
                                    let now = std::time::Instant::now();
                                    me.retry_changed_now(ComputerChange::at(
                                        me.computer.policy_revision(),
                                        now,
                                        now,
                                    ));
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                        }
                    }
                    changed = journal.recv() => {
                        if matches!(changed, Err(tokio::sync::broadcast::error::RecvError::Closed)) {
                            return;
                        }
                        if let Some(me) = weak.upgrade() {
                            // Node application can finish before the exchange carrying the last
                            // remote roster fact. It correctly cannot sign a receipt then; this
                            // exact later journal edge is what makes the receipt eligible. The
                            // operation is idempotent, and a newly created receipt advances the
                            // journal once so it is sent rather than polled for.
                            if let Err(error) = me.record_application() {
                                *lock(&me.problem) = Some(error.to_string());
                            }
                        }
                        // A durable receipt/reach/pairing payload moved without changing node
                        // authority. Re-evaluate the exchange need at that exact edge; the
                        // unchanged-success filter above still prevents sending the same state.
                    }
                    changed = network.recv() => {
                        if matches!(changed, Err(tokio::sync::broadcast::error::RecvError::Closed)) {
                            return;
                        }
                        if let Some(me) = weak.upgrade() {
                            // Presence is not authenticated proof that a computer-management
                            // exchange can succeed. Re-evaluate due work without bypassing its
                            // backoff; the transport loop receives the same network event.
                            me.retry_wake.notify_one();
                        }
                    }
                }
            }
        });
        me.start_transport_refresh();
        Ok(me)
    }
    fn serve(self: &Arc<Self>, conn: Arc<VoxConnection>) {
        if !lock(&self.serving).insert(conn.serial()) {
            return;
        }
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let Ok((kind, mut send, mut recv)) = streams::accept_typed(&conn).await else {
                    break;
                };
                let Some(me) = weak.upgrade() else {
                    break;
                };
                if kind == StreamKind::Goodbye {
                    conn.mark_peer_stopped();
                    conn.close(crate::wire::WireError::ShuttingDown);
                    break;
                }
                if matches!(kind, StreamKind::Coord | StreamKind::Circuit)
                    && me.net.policy().snapshot().is_anchor(&conn.peer_id())
                {
                    let Ok(slot) = Arc::clone(&me.slots).try_acquire_owned() else {
                        streams::refuse(&mut send, &mut recv);
                        continue;
                    };
                    let c = Arc::clone(&conn);
                    tokio::spawn(async move {
                        let _slot = slot;
                        let _ = tokio::time::timeout(
                            COMPUTER_RETURN_SHOWN_WITHIN,
                            me.transport_incoming(&c, kind, send, recv),
                        )
                        .await;
                    });
                    continue;
                }
                if kind != StreamKind::Computer {
                    streams::refuse(&mut send, &mut recv);
                    continue;
                }
                let Ok(slot) = Arc::clone(&me.slots).try_acquire_owned() else {
                    streams::refuse(&mut send, &mut recv);
                    continue;
                };
                let c = Arc::clone(&conn);
                tokio::spawn(async move {
                    let _slot = slot;
                    // `answer` derives its one host-local deadline from the hello as soon as the
                    // hello arrives. A second outer timeout would either truncate pairing's
                    // longer public contract or mint a fresh ordinary-exchange clock.
                    let mut response_deadline = std::time::Instant::now() + PATIENCE;
                    #[cfg(feature = "test-knobs")]
                    let mut stopped_reader_generation = None;
                    let result = me
                        .answer(
                            &c,
                            &mut send,
                            &mut recv,
                            &mut response_deadline,
                            #[cfg(feature = "test-knobs")]
                            &mut stopped_reader_generation,
                        )
                        .await;
                    // Only a fully parsed and meaningfully answered request on this
                    // authenticated computer stream proves the path is usable. A typed but
                    // malformed/refused/timed-out stream cannot bypass retry backoff.
                    if matches!(result, Ok(())) {
                        me.retry_peer_now(c.peer_id());
                    }
                    if let Err(e) = result {
                        let mut f = Encoder::new();
                        let problem = e.to_string();
                        #[cfg(feature = "test-knobs")]
                        let problem = {
                            let mut problem = problem;
                            if let Some(generation) = stopped_reader_generation
                                .filter(|_| problem.contains("causal convergence deadline"))
                            {
                                if Self::mark_stopped_reader_answer_for_proof(generation) {
                                    // Each response exceeds one eighth of the transaction cap.
                                    // Eight unread streams therefore exceed the connection's
                                    // whole bounded transaction allowance without inventing
                                    // another size constant. This is invariant apparatus for
                                    // both product and mutant runs; the mutant changes only the
                                    // response deadline's ownership.
                                    problem.push_str(&"x".repeat(MAX_FRAME / MANAGEMENT_SLOTS));
                                }
                            }
                            problem
                        };
                        f.array(2).uint(0).text(&problem);
                        // A peer which stopped reading cannot retain one of the bounded answer
                        // slots forever merely because its error response is backpressured.
                        #[cfg(feature = "test-knobs")]
                        let response_deadline =
                            if crate::node::computer::fx28_mutant("stopped-reader-fresh-write") {
                                std::time::Instant::now() + PATIENCE
                            } else {
                                response_deadline
                            };
                        let _ = write_frame_until(&mut send, &f.finish(), response_deadline).await;
                    }
                    let _ = send.finish();
                });
            }
            if let Some(me) = weak.upgrade() {
                lock(&me.serving).remove(&conn.serial());
                // A held anchor connection ending is a real transport event. Registration may
                // move to another configured endpoint; direct peer reachability remains usable.
                me.transport_wake.notify_one();
            }
        });
    }
    /// Follow the endpoints this daemon advertises: `changed()` resolves when they moved, and
    /// the daemon then records its reach for the other computers (ADR-038 FX-28: on no timer).
    pub fn endpoint_changes(&self) -> tokio::sync::watch::Receiver<Option<EndpointList>> {
        self.net.presence().advertised()
    }
    /// An active invitation or enrolled management endpoint keeps a zero-node daemon available.
    pub fn keeps_daemon_alive(&self) -> bool {
        let s = lock(&self.computer.state);
        s.genesis.is_some()
            || s.pending.is_some()
            || s.invitations
                .iter()
                .any(|i| !i.cancelled && i.expires > now())
    }
    /// Begin one bounded invitation. Existing pending approval must be cancelled explicitly first.
    pub fn begin(&self) -> Result<ComputerStatus> {
        let endpoints = self.net.local_endpoints()?;
        let id = random_array()?;
        let secret = Zeroizing::new(random_array()?);
        let transport = Zeroizing::new(random_array()?);
        let expires = now().saturating_add(INVITE_LIFETIME_MS);
        let nonce = random_array()?;
        let grants = [random_array()?, random_array()?];
        self.computer.change(|s| {
            if s.genesis.is_some()
                && (s.grant(&self.computer.signer.fingerprint()).is_none()
                    || !s.quarantined.is_empty())
            {
                return Err(Error::Profile(
                    "this computer cannot enroll another member while its authority is suspended",
                ));
            }
            if s.pending.as_ref().is_some_and(|p| !enrolled(s, p))
                || s.invitations
                    .iter()
                    .any(|i| !i.cancelled && i.expires > now() && i.target.is_none())
            {
                return Err(Error::Profile(
                    "a computer pairing is already pending; cancel it before making another code",
                ));
            }
            if s.invitations.len() >= MAX_RECORDS {
                return Err(Error::Profile(
                    "retained computer invitation history is full",
                ));
            }
            if let Some(link) = s.pair_link.take() {
                s.links.push(link);
            }
            s.pending = None;
            s.group_genesis = None;
            s.pending_expires = 0;
            s.invitations.push(Invitation {
                id,
                secret: secret.clone(),
                transport: transport.clone(),
                expires,
                nonce,
                grants,
                cancelled: false,
                target: None,
            });
            Ok(())
        })?;
        // An invitation changes transport leases even when it does not move policy revision.
        self.transport_wake.notify_one();
        let mut status = self.status()?;
        status.invite_link = Some(
            Link {
                target: self.computer.signer.fingerprint(),
                invite: id,
                secret,
                transport,
                expires,
                endpoints,
                anchors: self.anchors.clone(),
            }
            .url(),
        );
        status.invite_expires_ms = Some(expires);
        Ok(status)
    }
    /// Cancel a current uncommitted operation. Signed completed enrollment is never undone here.
    pub fn cancel(&self, operation: &str) -> Result<ComputerStatus> {
        let id = crate::node::link::b32_decode(operation, "computer pairing operation")?;
        let closed_expired = self.computer.change(|s| {
            if s.pending.as_ref().is_some_and(|g| (g.operation()==id || s.invitations.iter().any(|i| i.id==id && i.nonce==g.nonce)) && enrolled(s,g)) || s.genesis.as_ref().is_some_and(|g|g.operation()==id) {
                return Err(Error::Profile("this pairing is established; cancellation does not remove computer trust"));
            }
            if s.cancelled.contains_key(&id) {
                return Ok(false);
            }
            let pending_nonce = s.pending.as_ref().and_then(|g| {
                (g.operation() == id || s.invitations.iter().any(|i| i.id == id && i.nonce == g.nonce))
                    .then_some(g.nonce)
            });
            let pending = pending_nonce.is_some();
            if s.invitations.iter().any(|i| i.id == id && i.cancelled) {
                return Ok(false);
            }
            let locally_approved = pending && s.pending.as_ref().is_some_and(|g| {
                side(g, &self.computer.signer.fingerprint())
                    .ok().is_some_and(|at| g.approvals[at].is_some())
            });
            if locally_approved && s.pending_expires > now() {
                return Err(Error::Profile("this approval is already signed and the other computer may complete it; wait for its result or close the incomplete attempt after it expires"));
            }
            let mut found = pending;
            for i in &mut s.invitations {
                if (i.id == id || pending_nonce == Some(i.nonce)) && !i.cancelled {
                    found = true;
                    i.cancelled = true;
                }
            }
            if !found {
                return Err(Error::Profile("that computer pairing is no longer current"));
            }
            if pending {
                if let Some(g) = s.pending.take() {
                    s.cancelled.insert(g.operation(), g);
                }
                if let Some(link) = s.pair_link.take() {
                    s.cancelled_links.push(link);
                }
                s.pending_expires = 0;
                if s.genesis.is_none() { s.rosters.clear(); s.members.clear(); s.reaches.clear(); s.group_genesis=None; }
                // Fault exclusion is permanent within this retired incarnation. Retain its
                // signed evidence, but do not carry its derived fault into a fresh enrollment.
                if s.genesis.is_none() { s.quarantined.clear(); s.receipts.clear(); }
            }
            Ok(locally_approved)
        })?;
        if closed_expired {
            *lock(&self.problem) = Some("Expired attempt closed on this computer. Its signed intent remains retained and cannot activate here. The other computer may have recorded approval; this does not remove trust there.".into());
        }
        // Cancellation revokes transport even when no policy revision moved.
        self.transport_wake.notify_one();
        self.status()
    }
    /// Authenticate a supplied code before exposing the peer as an approval candidate.
    pub async fn preview(self: &Arc<Self>, url: &str) -> Result<ComputerStatus> {
        let link = Link::parse(url)?;
        if lock(&self.computer.state)
            .pair_link
            .as_ref()
            .is_some_and(|l| l.as_str() == url)
        {
            return self.status();
        }
        if link.expires <= now() {
            return Err(Error::Profile(
                "computer pairing code expired; no trust was established",
            ));
        }
        if link.target == self.computer.signer.fingerprint() {
            return Err(Error::Profile(
                "that pairing code belongs to this installation",
            ));
        }
        {
            let s = lock(&self.computer.state);
            // A fresh authenticated invitation can carry a removal this offline computer
            // has not learned yet. The merge below still refuses an already-active target,
            // another group, and every unapproved enrollment.
            if s.genesis.is_none()
                && (s.pair_link.as_ref().is_some_and(|l| l.as_str() != url)
                    || (s.pending.is_some() && s.pair_link.is_none()))
            {
                return Err(Error::Profile(
                    "another computer pairing is pending; cancel it first",
                ));
            }
        }
        // The pairing handshake with the link's computer is this computer's exchange with it
        // for now: the retry leaves it alone meanwhile, and the reservation ends with the
        // handshake however it ends (a drop guard), so the computer never stays in flight.
        let target = link.target;
        // The state this handshake carries, read before the reservation: the state lock is
        // never taken under the in-flight lock (the retry takes them the other way round).
        let (revision, policy_revision) = {
            let state = lock(&self.computer.state);
            (state.revision, state.policy_revision)
        };
        // The operator's action comes first: a retry exchange in flight with that computer
        // is cut (as no failure) and its reservation waited for, briefly; another operator
        // pairing in flight is reported.
        let mut causal_deadline = std::time::Instant::now() + COMPUTER_PAIR_WITHIN;
        let serial = next_flight();
        loop {
            // Register before inspecting the reservation. `notify_waiters` carries no saved
            // permit, so enabling first closes the release-between-check-and-wait race.
            let released = self.retry_wake.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            {
                let mut inflight = lock(&self.inflight);
                match inflight.get_mut(&target) {
                    None => {
                        // A failed retry can record and release between the operator reading the
                        // link and taking this reservation. Its first causal deadline remains the
                        // pairing command's deadline too; a later failure may not replace it.
                        if let Some(deadline) = lock(&self.exchanged)
                            .get(&target)
                            .filter(|record| record.failures > 0)
                            .and_then(|record| record.deadline)
                        {
                            causal_deadline = causal_deadline.min(deadline);
                        }
                        // Supersession transfers the earliest causal deadline into retry_ready
                        // before aborting. The old flight can disappear before this operator wins
                        // the slot, so the retained mark is part of takeover state too.
                        if let Some(deadline) = lock(&self.retry_ready)
                            .get(&target)
                            .map(|mark| mark.deadline)
                        {
                            causal_deadline = causal_deadline.min(deadline);
                        }
                        inflight.insert(
                            target,
                            Flight {
                                serial,
                                policy_revision,
                                revision,
                                involved: true,
                                causal: true,
                                deadline: causal_deadline,
                                origin: Origin::Operator,
                                abort: None,
                                covered: false,
                                superseded: false,
                            },
                        );
                        let mut exchanged = lock(&self.exchanged);
                        let record = exchanged.entry(target).or_default();
                        record.attempts = record.attempts.saturating_add(1);
                        break;
                    }
                    Some(flight) if flight.origin == Origin::Operator && !flight.superseded => {
                        return Err(Error::Profile(
                            "a computer pairing with that computer is in progress; try again \
                             in a moment",
                        ));
                    }
                    Some(flight) => {
                        causal_deadline = causal_deadline.min(flight.deadline);
                        if !flight.superseded {
                            flight.superseded = true;
                            if let Some(abort) = &flight.abort {
                                abort.abort();
                            }
                        }
                    }
                }
            }
            // The inherited absolute deadline is the only bound. Release normally wakes this
            // branch; reaching the deadline is a truthful failure of the already-open cause, not
            // a fresh command-local timeout.
            tokio::select! {
                () = &mut released => {}
                () = tokio::time::sleep_until(causal_deadline.into()) => {
                    return Err(Error::Profile(
                        "the existing computer exchange did not yield before its causal convergence deadline; try again",
                    ));
                }
            }
        }
        #[cfg(feature = "test-knobs")]
        self.hold_operator_reserved_for_proof(target, serial).await;
        let mut reserved = Reserved {
            me: Arc::clone(self),
            peer: target,
            serial,
            abort: None,
        };
        // Bounded like any exchange, by the same generous bound: a slow but valid handshake
        // of a long history completes, and a hung one never holds the reservation for good.
        // Run as a task the retry can cut like any exchange: should this node change
        // meanwhile, the handshake carries stale state, the retry supersedes it, and the
        // operator is told to try again (the next tick exchanges the current state).
        let me = Arc::clone(self);
        let (link_owned, url_owned) = (link, url.to_owned());
        let task = tokio::spawn(async move {
            // An explicit pairing owns this one causal deadline. Once it has elapsed the command
            // fails; it cannot turn a retained, already-missed contract into a later success.
            tokio::time::timeout_at(
                causal_deadline.into(),
                me.pair(&link_owned, &url_owned, causal_deadline),
            )
            .await
        });
        reserved.abort = Some(task.abort_handle());
        if let Some(flight) = lock(&self.inflight).get_mut(&target) {
            if flight.serial == serial {
                flight.abort = Some(task.abort_handle());
                // Retry supersession can land after this operator reserved the flight but before
                // its task handle existed. Installing the handle must observe that decision, as
                // retry-owned flights do, or stale operator work can hold the peer until
                // PAIR_WITHIN and exclude the current revision's replacement.
                if flight.superseded {
                    task.abort();
                }
            }
        }
        let (paired, superseded) = match task.await {
            Ok(Ok(paired)) => (paired, false),
            Ok(Err(_)) => (
                Err(Error::Profile(
                    "the computer pairing did not finish before its causal convergence deadline; try again",
                )),
                false,
            ),
            // Cut by the retry because this node changed: no failure of anyone's.
            Err(e) if e.is_cancelled() => (
                Err(Error::Profile(
                    "this computer changed while the pairing ran, so the pairing was \
                     superseded; try again",
                )),
                true,
            ),
            Err(_) => (
                Err(Error::Profile(
                    "the computer pairing task failed; try again",
                )),
                false,
            ),
        };
        // Recorded while still reserved, with the state it carried, so the record never
        // touches a reservation the retry may have taken meanwhile; the guard releases this
        // one after. A superseded handshake is recorded as nothing.
        if !superseded {
            let outcome = match &paired {
                // The handshake exchanged state: counted and dated like any exchange, with
                // the revisions it carried, and the status's problem follows from every
                // computer's record.
                Ok(revisions) => Ok(*revisions),
                Err(e) => Err(e.to_string()),
            };
            self.record_exchange(
                target,
                serial,
                revision,
                policy_revision,
                true,
                true,
                causal_deadline.min(std::time::Instant::now() + COMPUTER_RETURN_SHOWN_WITHIN),
                outcome,
                None,
            );
        }
        drop(reserved);
        paired?;
        self.status()
    }
    /// Record this operator's signature of exactly the previewed operation; retry is idempotent.
    pub fn approve(&self, operation: &str) -> Result<ComputerStatus> {
        let id = crate::node::link::b32_decode(operation, "computer pairing operation")?;
        let local = self.computer.signer.fingerprint();
        self.computer.change(|s| {
            let before_revision = s.revision;
            let before_pending = s.pending.as_ref().map(Enrollment::encode);
            if s.genesis.as_ref().is_some_and(|g| g.operation() == id)
                || s.history.values().any(|r| {
                    r.event()
                        .ok()
                        .and_then(|e| e.addition)
                        .is_some_and(|a| a.operation() == id)
                })
            {
                return Ok(());
            }
            if s.pending.as_ref().is_some_and(|g| {
                g.operation() == id
                    && side(g, &local)
                        .ok()
                        .is_some_and(|at| g.approvals[at].is_some())
            }) {
                return Ok(());
            }
            if s.pending_expires <= now() {
                return Err(Error::Profile(
                    "computer pairing code expired; no trust was established",
                ));
            }
            let g = s.pending.as_mut().ok_or(Error::Profile(
                "no authenticated computer pairing is awaiting approval",
            ))?;
            if g.operation() != id {
                return Err(Error::Profile(
                    "the displayed computer pairing has changed; review it again",
                ));
            }
            let at = side(g, &local)?;
            if g.approvals[at].is_none() {
                g.approvals[at] = Some(Signed::create(
                    b"vox/computer-genesis/v1\0",
                    g.body(),
                    self.computer.signer.as_ref(),
                )?);
            }
            activate(s, self.computer.signer.as_ref())?;
            if s.pending.as_ref().map(Enrollment::encode) != before_pending
                && s.revision == before_revision
            {
                s.advance_journal()?;
            }
            Ok(())
        })?;
        self.status()
    }
    /// Explicit source release or destination approval. The destination's ordinary Unlock
    /// supplies the node signature later; no secret or copied fingerprint acts as a transfer.
    pub fn binding_update(
        &self,
        action: &str,
        node: &str,
        destination: &str,
        expected: &str,
    ) -> Result<ComputerStatus> {
        if action == "recover-group" {
            return self.recover_group(expected);
        }
        let node = crate::node::link::fingerprint_input(node, "node fingerprint")?;
        let local = self.computer.signer.fingerprint();
        self.computer.change(|s| {
            if frontier(s) != expected { return Err(Error::Profile("computer trust changed; review the binding operation again")); }
            let group = s.genesis.as_ref().map(Enrollment::incarnation).ok_or(Error::Profile("computer enrollment must finish before changing a management binding"))?;
            if s.grant(&local).is_none() { return Err(Error::Profile("an active computer manager must approve this binding operation")); }
            let bindings: Vec<_> = s.terminal_bindings()?.into_iter().filter(|(manager, binding)|
                binding.verify(manager, &group).ok() == Some(node)).collect();
            if bindings.len() != 1 { return Err(Error::Profile("the node has no unambiguous retained management binding; use a fresh node identity or resolve conflicting managers")); }
            let (manager, binding) = &bindings[0];
            match action {
                "release" => {
                    let destination = crate::node::link::fingerprint_input(destination, "destination computer fingerprint")?;
                    if *manager != local || destination == local || s.grant(&destination).is_none() {
                        return Err(Error::Profile("release requires this node's current manager and another active destination computer"));
                    }
                    let (_, personal, mut roster) = s.rosters.get(&local).ok_or_else(bad)?.read(&local, &group)?;
                    if !roster.iter().any(|b| b.id() == binding.id()) { return Err(Error::Profile("this node was already released")); }
                    let mut body = Encoder::new();
                    body.array(4).bytes(&node).bytes(&binding.id()).bytes(&destination).bytes(&random_array::<32>()?);
                    let release = Control::sign(s, "release", body.finish(), self.computer.signer.as_ref())?;
                    s.retain_roster(release)?;
                    roster.retain(|b| b.id() != binding.id());
                    let personal = personal.filter(|p| *p != node);
                    let update = Control::create(s, &roster, personal, self.computer.signer.as_ref())?;
                    s.retain_roster(update)?;
                    if s.selected == Some(node) { s.selected = None; s.selected_name.clear(); }
                }
                "transfer" | "recover" => {
                    if *manager == local { return Err(Error::Profile("this computer already holds this node's binding")); }
                    let authority = s.derive()?;
                    let proof = if action == "transfer" {
                        let releases: Vec<_> = authority.valid_releases.iter().filter(|id|
                            s.history[*id].event().ok().and_then(|e| e.release).is_some_and(|r|
                                r.previous == binding.id() && r.node == node && r.destination == local)).copied().collect();
                        if releases.len() != 1 { return Err(Error::Profile("no unique effective signed release names this destination; ask the previous manager to release it or explicitly recover after removal")); }
                        releases[0]
                    } else {
                        if s.grant(manager).is_some() { return Err(Error::Profile("recovery requires retained removal or fault evidence for the previous manager; an active manager must release the node")); }
                        [0; 32]
                    };
                    s.binding_approvals.insert(node, BindingApproval { kind: if action == "transfer" { 1 } else { 2 },
                        previous: binding.id(), proof, heads: s.heads() });
                }
                _ => return Err(Error::Profile("unknown computer binding operation")),
            }
            Ok(())
        })?;
        self.status()
    }

    /// Deliberate local abandonment after removal/fault. Retired history remains pinned against
    /// replay. Every old covered grant is journalled for purge before any new group can apply.
    fn recover_group(&self, expected: &str) -> Result<ComputerStatus> {
        let local = self.computer.signer.fingerprint();
        self.computer.change(|s| {
            if frontier(s) != expected {
                return Err(Error::Profile(
                    "computer trust changed; review local recovery again",
                ));
            }
            if s.grant(&local).is_some() {
                return Err(Error::Profile(
                    "remove this computer from the group before abandoning its incarnation",
                ));
            }
            let genesis = s
                .genesis
                .take()
                .ok_or(Error::Profile("there is no established group to retire"))?;
            s.revision = s.revision.checked_add(1).ok_or_else(bad)?;
            s.policy_revision = s.revision;
            for intervals in s.intervals.values_mut() {
                if let Some(interval) = intervals.last_mut().filter(|i| i.retirement.is_none()) {
                    interval.retirement = Some(s.revision);
                }
            }
            s.retired_groups.insert(genesis.incarnation(), genesis);
            s.members.clear();
            s.rosters.clear();
            s.reaches.clear();
            s.quarantined.clear();
            s.receipts.clear();
            s.pending = None;
            s.group_genesis = None;
            s.pair_link = None;
            s.links.clear();
            s.pending_expires = 0;
            s.binding_approvals.clear();
            for invitation in &mut s.invitations {
                invitation.cancelled = true;
            }
            Ok(())
        })?;
        self.status()
    }

    /// Confirm removal against the exact displayed signed frontier and affected roster.
    pub fn remove(&self, target: &str, expected: &str) -> Result<ComputerStatus> {
        let target = crate::node::link::fingerprint_input(target, "computer fingerprint")?;
        self.computer.change(|s| {
            if frontier(s) != expected { return Err(Error::Profile("computer trust changed; review the computer and affected nodes again before removing it")); }
            if s.genesis.is_none() { return Err(Error::Profile("computer enrollment must finish before removing a member")); }
            let mut grants: Vec<_> = s.members.iter().filter_map(|(id, g)|
                (g.computer.fingerprint().ok() == Some(target)).then_some(*id)).collect();
            grants.sort();
            if grants.is_empty() { return Err(Error::Profile("this computer is not an active group member")); }
            let mut body = Encoder::new();
            body.array(3).bytes(&target).array(grants.len());
            for grant in grants { body.bytes(&grant); }
            body.bytes(&s.rosters.get(&target).map(Control::id).unwrap_or([0; 32]));
            let event = Control::sign(s, "remove", body.finish(), self.computer.signer.as_ref())?;
            s.retain_roster(event)?;
            Ok(())
        })?;
        self.status()
    }

    /// Public readback; never treats a timeout or missing receipt as established policy.
    pub fn status(&self) -> Result<ComputerStatus> {
        let s = lock(&self.computer.state);
        let local = self.computer.signer.fingerprint();
        let pairing = s
            .pending
            .as_ref()
            .filter(|g| !enrolled(&s, g))
            .map(|g| -> Result<PairingPreview> {
                let at = side(g, &local)?;
                Ok(PairingPreview {
                    operation_id: text_id(&g.operation()),
                    peer: ComputerIdentity::of(&g.computers[1 - at])?,
                    approved_here: g.approvals[at].is_some(),
                    approved_there: g.approvals[1 - at].is_some(),
                    expires_ms: g.expires,
                })
            })
            .transpose()?;
        let busy = s.pending.as_ref().is_some_and(|g| !enrolled(&s, g));
        let invitation = s
            .invitations
            .iter()
            .rev()
            .find(|i| !busy && !i.cancelled && i.expires > now() && i.target.is_none());
        let invite_link = invitation
            .map(|i| {
                self.net.local_endpoints().map(|endpoints| {
                    Link {
                        target: local,
                        invite: i.id,
                        secret: i.secret.clone(),
                        transport: i.transport.clone(),
                        expires: i.expires,
                        endpoints,
                        anchors: self.anchors.clone(),
                    }
                    .url()
                })
            })
            .transpose()?;
        let mut pending_nodes = lock(&self.pending_nodes).clone();
        for node in s.binding_approvals.keys() {
            pending_nodes.push(format!(
                "{}: binding approved here; unlock its local vault to sign and apply it",
                text_id(node)
            ));
        }
        let storage_failed = self.computer.storage_ready().is_err();
        let descriptions = if s.genesis.is_some() {
            s.descriptions()
        } else {
            BTreeMap::new()
        };
        let exchanged = lock(&self.exchanged).clone();
        // Snapshot sequentially, never while holding `exchanged`: operator pairing reserves
        // under `inflight` and then consults `exchanged`. The state lock held by this status call
        // prevents a policy snapshot from being paired with reservations for another revision.
        let inflight: BTreeSet<_> = lock(&self.inflight).keys().copied().collect();
        let applications: Vec<_> = descriptions
            .iter()
            .map(|(id, d)| {
                let record = exchanged.get(id).cloned().unwrap_or_default();
                let missed = s.missed_exchanges.get(id).copied();
                let confirmed = !storage_failed
                    && s.receipts
                        .get(id)
                        .is_some_and(|r| valid_receipt(&s, id, r).unwrap_or(false));
                let convergence_state = match missed {
                    Some((revision, true)) if revision == s.policy_revision => "repaired-late",
                    Some((revision, false)) if revision == s.policy_revision => "expired",
                    Some((revision, _)) if revision < s.policy_revision && !confirmed => "replaced",
                    _ if confirmed => "converged",
                    _ => "pending",
                };
                Ok(ComputerApplication {
                    computer: ComputerIdentity::of(d)?,
                    confirmed,
                    last_exchange_ms: record.last_ms,
                    exchanges: record.count,
                    exchange_attempts: record.attempts,
                    exchange_in_flight: inflight.contains(id),
                    exchange_failures: record.failures,
                    missed_revision: missed.map(|(revision, _)| revision),
                    repaired_late: missed.is_some_and(|(_, repaired)| repaired),
                    convergence_state: convergence_state.into(),
                    last_started_exchange: record.last_started,
                    last_answered_exchange: record.last_answered,
                })
            })
            .collect::<Result<_>>()?;
        let mut nodes = Vec::new();
        let authority = s.derive()?;
        for (manager, roster) in &s.rosters {
            let e = roster.event()?;
            for binding in &e.bindings {
                let id = binding.verify(manager, &e.group)?;
                if authority.binding_owners.get(&id) != Some(&binding.id()) {
                    continue;
                }
                // Read from the state this status already holds: a second lock of it here
                // would wait on itself and hang every `vox computer status`.
                let derived = (*manager == local)
                    .then(|| s.derived.get(&id).copied())
                    .flatten();
                nodes.push(ComputerNode {
                    computer: text_id(manager),
                    fingerprint: text_id(&id),
                    name: binding.name.clone(),
                    personal: e.personal == Some(id),
                    binding_revision: derived.map(|d| d.revision),
                    binding_derived_ms: derived.map(|d| d.at_ms),
                });
            }
        }
        let mut binding_actions = Vec::new();
        if s.genesis.is_some() && s.grant(&local).is_some() {
            for (manager, binding) in s.terminal_bindings()? {
                let node = binding.verify(&manager, &s.group().ok_or_else(bad)?)?;
                let released_here = authority.valid_releases.iter().any(|id| {
                    s.history[id]
                        .event()
                        .ok()
                        .and_then(|e| e.release)
                        .is_some_and(|r| r.previous == binding.id() && r.destination == local)
                });
                let action = if manager == local
                    && authority.binding_owners.get(&node) == Some(&binding.id())
                {
                    Some("release")
                } else if manager != local && released_here {
                    Some("transfer")
                } else if manager != local && s.grant(&manager).is_none() {
                    Some("recover")
                } else {
                    None
                };
                if let Some(action) = action {
                    binding_actions.push(ComputerBindingAction {
                        node: text_id(&node),
                        name: binding.name,
                        computer: text_id(&manager),
                        action: action.into(),
                    });
                }
            }
        }
        let mut former = BTreeMap::new();
        if let Some(g) = &s.genesis {
            for description in &g.computers {
                former.insert(description.fingerprint()?, description.clone());
            }
            for record in s.history.values() {
                if let Some(add) = record.event()?.addition {
                    former.insert(add.computers[1].fingerprint()?, add.computers[1].clone());
                }
            }
        }
        former.retain(|id, _| !descriptions.contains_key(id));
        let expired = applications
            .iter()
            .any(|application| application.convergence_state == "expired");
        let state = if storage_failed || !s.quarantined.is_empty() {
            "quarantined"
        } else if s.genesis.is_some() && s.grant(&local).is_none() && !busy {
            "removed"
        } else if busy && pairing.as_ref().is_some_and(|p| !p.approved_here) {
            "needs-approval"
        } else if busy || invitation.is_some() {
            "waiting"
        } else if expired {
            "expired"
        } else if s.genesis.is_some() {
            if !applications.is_empty()
                && applications.iter().all(|a| a.confirmed)
                && pending_nodes.is_empty()
            {
                "confirmed"
            } else {
                "applying"
            }
        } else {
            "individual"
        };
        Ok(ComputerStatus {
            this_computer: ComputerIdentity::of(&s.description)?,
            policy: POLICY.into(),
            state: state.into(),
            revision: s.policy_revision,
            invite_link,
            invite_id: invitation.map(|i| text_id(&i.id)),
            invite_expires_ms: invitation.map(|i| i.expires),
            pairing,
            computers: descriptions
                .values()
                .map(ComputerIdentity::of)
                .collect::<Result<_>>()?,
            applications,
            nodes,
            binding_actions,
            removed: former
                .values()
                .map(ComputerIdentity::of)
                .collect::<Result<_>>()?,
            frontier: frontier(&s),
            selected_node: s.selected.as_ref().map(text_id),
            selected_name: s.selected.map(|_| s.selected_name.clone()),
            pending_nodes,
            problem: if storage_failed {
                Some(STORAGE_FAILED.into())
            } else if !s.quarantined.is_empty() {
                Some("Conflicting computer authority is quarantined; retained signed evidence requires operator recovery.".into())
            } else {
                lock(&self.problem).clone()
            },
        })
    }
    /// Report outstanding current-node application, never claiming success for detached vaults.
    pub fn pending_nodes(&self, nodes: Vec<String>) {
        *lock(&self.pending_nodes) = nodes;
    }
    /// One node's application failed or did not finish: said in the status, in place of any
    /// earlier word about that node.
    pub fn node_pending(&self, node: &str, why: &str) {
        let mut pending = lock(&self.pending_nodes);
        let prefix = format!("{node}: ");
        pending.retain(|entry| !entry.starts_with(&prefix));
        pending.push(format!("{prefix}{why}"));
    }
    /// The exact current reconciliation pass completed: clear only that node's pending result.
    /// The daemon owns pass ordering and calls this while holding the attachment's ownership lock.
    pub fn node_applied(&self, node: &str) {
        let prefix = format!("{node}: ");
        lock(&self.pending_nodes).retain(|entry| !entry.starts_with(&prefix));
    }
    fn transport_leases(&self, supplied: Option<&Link>) -> Result<Vec<TransportLease>> {
        let s = lock(&self.computer.state);
        let local = s.description.fingerprint()?;
        let mut leases = Vec::new();
        if let (Some(group), Some(here)) = (s.group(), s.reaches.get(&local)) {
            for (peer, there) in &s.reaches {
                if *peer == local
                    || s.grant(peer).is_none()
                    || s.grant(&local).is_none()
                    || s.quarantined.contains(peer)
                {
                    continue;
                }
                let (first, second, t1, t2) = if local < *peer {
                    (local, *peer, here.token, there.token)
                } else {
                    (*peer, local, there.token, here.token)
                };
                let registration =
                    sha256_concat(&[b"vox/computer-transport-pair/v1\0", &group, &first, &second]);
                let token = Zeroizing::new(sha256_concat(&[
                    b"vox/computer-transport-capability/v1\0",
                    &group,
                    &first,
                    &second,
                    &t1,
                    &t2,
                ]));
                let mut anchors = here.anchors.clone();
                for a in there.anchors.nodes() {
                    anchors.add(a.clone())?;
                }
                leases.push(TransportLease {
                    registration,
                    token,
                    expires: now()
                        .saturating_add(crate::nat::service::COMPUTER_TRANSPORT_TTL_MS / 2),
                    peer: Some(*peer),
                    anchors,
                    renewable: true,
                });
            }
        }
        let mut links: Vec<_> = s
            .links
            .iter()
            .chain(s.pair_link.iter())
            .map(|l| Link::parse(l))
            .collect::<Result<_>>()?;
        if let Some(l) = supplied {
            links.push(Link::parse(&l.url())?);
        }
        for link in links {
            if leases.iter().any(|l| l.peer == Some(link.target)) {
                continue;
            }
            let established = s.grant(&link.target).is_some() && s.genesis.is_some();
            if !established && link.expires <= now() {
                continue;
            }
            let mut anchors = self.anchors.clone();
            for a in link.anchors.nodes() {
                anchors.add(a.clone())?;
            }
            leases.push(TransportLease {
                registration: link.invite,
                token: link.transport,
                expires: if established {
                    now().saturating_add(crate::nat::service::COMPUTER_TRANSPORT_TTL_MS / 2)
                } else {
                    link.expires
                },
                peer: Some(link.target),
                anchors,
                renewable: established,
            });
        }
        for i in &s.invitations {
            if i.cancelled
                || i.target
                    .is_some_and(|p| leases.iter().any(|l| l.peer == Some(p)))
            {
                continue;
            }
            let established =
                i.target.is_some_and(|p| s.grant(&p).is_some()) && s.genesis.is_some();
            if !established && i.expires <= now() {
                continue;
            }
            leases.push(TransportLease {
                registration: i.id,
                token: i.transport.clone(),
                expires: if established {
                    now().saturating_add(crate::nat::service::COMPUTER_TRANSPORT_TTL_MS / 2)
                } else {
                    i.expires
                },
                peer: i.target,
                anchors: self.anchors.clone(),
                renewable: established,
            });
        }
        Ok(leases)
    }
    fn configure_transport_anchors(&self, anchors: &BootstrapSet) {
        let mut policy = self.net.policy().snapshot();
        for a in anchors.nodes() {
            policy.add_anchor(a.id);
        }
        self.net.policy().replace(policy);
    }

    async fn transport_at(
        self: &Arc<Self>,
        anchor: crate::nat::bootstrap::BootstrapNode,
        lease: TransportLease,
        redeem: bool,
    ) -> Result<Arc<VoxConnection>> {
        let conn = self
            .net
            .manager()
            .connect(anchor.id, &anchor.endpoints)
            .await?;
        self.serve(Arc::clone(&conn));
        let cached = lock(&self.transport_cache)
            .get(&(anchor.id, lease.registration))
            .copied();
        if cached.is_none_or(|old| {
            old.connection != conn.serial()
                || old.expires
                    <= now().saturating_add(crate::nat::service::COMPUTER_TRANSPORT_TTL_MS / 10)
                || old.peer != lease.peer
        }) {
            self.net
                .register_computer_transport(
                    &conn,
                    lease.registration,
                    &lease.token,
                    lease.expires,
                    lease.peer,
                )
                .await?;
            lock(&self.transport_cache).insert(
                (anchor.id, lease.registration),
                RegisteredLease {
                    connection: conn.serial(),
                    expires: lease.expires,
                    peer: lease.peer,
                },
            );
        }
        if redeem {
            if let Some(peer) = lease.peer {
                self.net
                    .redeem_computer_transport(&conn, peer, lease.registration, &lease.token)
                    .await?;
            }
        }
        Ok(conn)
    }

    async fn refresh_transport(self: &Arc<Self>) -> Result<Option<std::time::Instant>> {
        let mut work = tokio::task::JoinSet::new();
        let leases = self.transport_leases(None)?;
        for lease in leases.iter().cloned() {
            self.configure_transport_anchors(&lease.anchors);
            for anchor in lease.anchors.nodes() {
                let me = Arc::clone(self);
                let anchor = anchor.clone();
                let lease = lease.clone();
                work.spawn(async move { me.transport_at(anchor, lease, true).await.map(|_| ()) });
            }
        }
        // Cancellation remains retryable after either daemon or anchor restarts. These are
        // retained tombstones in the same management state, not another credential store.
        let revoked = {
            let s = lock(&self.computer.state);
            let mut revoked: Vec<_> = s
                .invitations
                .iter()
                .filter(|i| i.cancelled && i.expires > now())
                .map(|i| (i.id, self.anchors.clone()))
                .collect();
            for url in &s.cancelled_links {
                let link = Link::parse(url)?;
                if link.expires <= now() {
                    continue;
                }
                let mut anchors = self.anchors.clone();
                for a in link.anchors.nodes() {
                    anchors.add(a.clone())?;
                }
                revoked.push((link.invite, anchors));
            }
            revoked
        };
        for (registration, anchors) in revoked {
            self.configure_transport_anchors(&anchors);
            for anchor in anchors.nodes() {
                let me = Arc::clone(self);
                let anchor = anchor.clone();
                work.spawn(async move {
                    let conn = me
                        .net
                        .manager()
                        .connect(anchor.id, &anchor.endpoints)
                        .await?;
                    me.serve(Arc::clone(&conn));
                    let key = (anchor.id, registration, conn.serial());
                    if !lock(&me.revoked_transport).contains(&key) {
                        me.net
                            .revoke_computer_transport(&conn, registration)
                            .await?;
                        lock(&me.revoked_transport).insert(key);
                    }
                    Ok(())
                });
            }
        }
        let mut failed = false;
        while let Some(result) = work.join_next().await {
            if !matches!(result, Ok(Ok(()))) {
                failed = true;
            }
        }

        // The cached registration is the source of truth for an established lease's expiry. A
        // failed registration/cancellation remains causal work and supplies the retry boundary;
        // a successful renewable registration wakes at its exact renewal boundary.
        let cached = lock(&self.transport_cache);
        let renewal_margin = crate::nat::service::COMPUTER_TRANSPORT_TTL_MS / 10;
        let next_ms = leases
            .iter()
            .filter(|lease| lease.renewable)
            .flat_map(|lease| {
                lease.anchors.nodes().iter().filter_map(|anchor| {
                    cached
                        .get(&(anchor.id, lease.registration))
                        .filter(|registered| registered.peer == lease.peer)
                        .map(|registered| registered.expires.saturating_sub(renewal_margin))
                })
            })
            .min();
        let renewal = next_ms
            .map(|at| std::time::Instant::now() + Duration::from_millis(at.saturating_sub(now())));
        let retry = failed.then(|| std::time::Instant::now() + COMPUTER_CHANGE_SHOWN_WITHIN);
        Ok(match (renewal, retry) {
            (Some(renewal), Some(retry)) => Some(renewal.min(retry)),
            (renewal, retry) => renewal.or(retry),
        })
    }

    async fn transport_incoming(
        self: &Arc<Self>,
        conn: &Arc<VoxConnection>,
        kind: StreamKind,
        send: SendStream,
        recv: RecvStream,
    ) -> Result<()> {
        let mut origins = Vec::new();
        for lease in self.transport_leases(None)? {
            if lease.anchors.get(&conn.peer_id()).is_none() {
                continue;
            }
            if let Some(peer) = lease.peer {
                origins.push(peer);
            }
            if let Some(peer) = self
                .net
                .computer_transport_peer(conn, lease.registration)
                .await?
            {
                if lease.peer.is_none_or(|expected| expected == peer) {
                    origins.push(peer);
                }
            }
        }
        origins.sort();
        origins.dedup();
        let result = self
            .net
            .dispatch_computer_transport(conn, kind, send, recv, &origins)
            .await?;
        if let crate::node::network::Inbound::Punch {
            peer,
            coordinator,
            send,
            recv,
        } = result
        {
            let reached = self.net.answer_punch(peer, coordinator, send, recv).await?;
            self.serve(reached);
        }
        Ok(())
    }

    async fn connect(
        self: &Arc<Self>,
        target: Digest32,
        endpoints: &EndpointList,
        supplied: Option<&Link>,
    ) -> Result<Arc<VoxConnection>> {
        if let Some(conn) = self.net.manager().existing(&target) {
            return Ok(conn);
        }
        // The direct dial starts immediately. Anchor registration is a separate raced path and
        // neither its absence nor its refusal can delay or fail a directly reachable computer.
        let direct = self.net.manager().connect(target, endpoints);
        let relay = async {
            let lease = self
                .transport_leases(supplied)?
                .into_iter()
                .find(|l| l.peer == Some(target))
                .ok_or(Error::Unreachable(
                    "no current computer transport invitation or enrolled pair",
                ))?;
            self.configure_transport_anchors(&lease.anchors);
            let mut attempts = tokio::task::JoinSet::new();
            for anchor in lease.anchors.nodes() {
                let me = Arc::clone(self);
                let anchor = anchor.clone();
                let lease = lease.clone();
                attempts.spawn(async move {
                    // This transport lease authorizes its anchor for this computer reach only;
                    // it is neither a room source nor a machine-wide manual anchor.
                    let helpers = crate::node::network::HelperContext {
                        extra_helpers: [anchor.id].into_iter().collect(),
                        ..crate::node::network::HelperContext::default()
                    };
                    me.transport_at(anchor, lease, true).await?;
                    me.net
                        .reach(target, &EndpointList::default(), &helpers)
                        .await
                });
            }
            let mut last = Error::Unreachable("no anchor configured for this computer pairing");
            while let Some(result) = attempts.join_next().await {
                match result {
                    Ok(Ok(conn)) => return Ok(conn),
                    Ok(Err(e)) => last = e,
                    Err(_) => {}
                }
            }
            Err(last)
        };
        tokio::pin!(direct, relay);
        let result = tokio::select! {
            d = &mut direct => match d { Ok(c) => Ok(c), Err(d) => relay.await.map_err(|r| Error::Handshake(format!("direct: {d}; computer relay: {r}"))) },
            r = &mut relay => match r { Ok(c) => Ok(c), Err(r) => direct.await.map_err(|d| Error::Handshake(format!("direct: {d}; computer relay: {r}"))) },
        };
        let conn = result.map_err(|e| {
            Error::Handshake(format!(
                "computer could not be reached; the pairing code was not checked: {e}"
            ))
        })?;
        self.serve(Arc::clone(&conn));
        Ok(conn)
    }
    /// The operator's pairing handshake with the inviting computer: this node's revision as it
    /// stood when the handshake began, and after the computer's state was merged.
    async fn pair(
        self: &Arc<Self>,
        link: &Link,
        url: &str,
        deadline: std::time::Instant,
    ) -> Result<(u64, u64)> {
        let conn = self
            .connect(link.target, &link.endpoints, Some(link))
            .await?;
        let (mut send, mut recv) = streams::open_typed(&conn, StreamKind::Computer).await?;
        let remaining_ms = wire_budget(deadline);
        write_frame_until(
            &mut send,
            &hello(1, &self.computer.description(), &link.invite, remaining_ms),
            deadline,
        )
        .await?;
        let (op, peer, _, echoed_remaining_ms) =
            read_hello_until(&mut recv, &conn, deadline).await?;
        if op != 1 || echoed_remaining_ms != remaining_ms {
            return Err(bad());
        }
        let f = frame_until(&mut recv, deadline).await?;
        let mut d = Decoder::new(&f);
        arity(&mut d, 3)?;
        let sid = d.bytes()?.to_vec();
        if sid.len() != 16 {
            return Err(bad());
        }
        let mut g = Enrollment::decode(d.bytes()?)?;
        let remote_share: [u8; 32] = d.bytes()?.try_into().map_err(|_| bad())?;
        d.finish()?;
        if g.expires != link.expires
            || g.computers[0] != peer
            || g.computers[1] != self.computer.description()
            || g.approvals.iter().any(Option::is_some)
        {
            return Err(bad());
        }
        let ci = context(&link.invite, &link.transport, &g);
        let (state, share) = cpace::CpaceState::start_with_context(
            link.secret.as_ref(),
            &ci,
            conn.session().suite_id,
            &sid,
        )?;
        let isk = state.finish(&remote_share)?;
        let transcript = pop::transcript_hash(
            &[ci.as_slice(), &sid].concat(),
            isk.as_ref(),
            &share,
            &remote_share,
        );
        let proof = pop::IdentityProof::create(self.computer.signer.as_ref(), &ci, &transcript)?;
        let mut e = Encoder::new();
        e.array(2)
            .bytes(&share)
            .bytes(&pop::seal_pop(isk.as_ref(), &proof)?);
        write_frame_until(&mut send, &e.finish(), deadline).await?;
        let f = frame_until(&mut recv, deadline).await?;
        let mut d = Decoder::new(&f);
        arity(&mut d, 2)?;
        let proof = pop::open_pop(isk.as_ref(), d.bytes()?)?;
        pop::verify(&proof, &ci, &transcript, &link.target)?;
        let exchange = d.bytes()?.to_vec();
        d.finish()?;
        let revisions = self.computer.change_until(deadline, |s| {
            // The revision this node stood at when it accepted the pairing, read in the
            // transaction that merges the computer's state, and the revision after.
            let before = s.revision;
            let before_pending = s.pending.as_ref().map(Enrollment::encode);
            if s.pending
                .as_ref()
                .is_some_and(|p| !enrolled(s, p) && p.body() != g.body())
            {
                return Err(Error::Profile(
                    "the pairing identity or policy changed; no approval was reused",
                ));
            }
            if let Some(p) = &s.pending {
                if p.body() == g.body() {
                    g.approvals = p.approvals.clone();
                }
            }
            s.pending = Some(g);
            s.pending_expires = link.expires;
            s.pair_link = Some(Zeroizing::new(url.to_owned()));
            merge(s, &exchange, link.target, self.computer.signer.as_ref())?;
            if s.pending.as_ref().map(Enrollment::encode) != before_pending && s.revision == before
            {
                s.advance_journal()?;
            }
            Ok((before, s.revision))
        })?;
        let _ = send.finish();
        Ok(revisions)
    }
    async fn answer(
        &self,
        conn: &VoxConnection,
        send: &mut SendStream,
        recv: &mut RecvStream,
        response_deadline: &mut std::time::Instant,
        #[cfg(feature = "test-knobs")] stopped_reader_generation: &mut Option<Digest32>,
    ) -> Result<()> {
        let (op, peer, id, remaining_ms) = read_hello_until(recv, conn, *response_deadline).await?;
        #[cfg(feature = "test-knobs")]
        {
            // Bind the exact arm generation when this authenticated request is admitted. A
            // pre-arm request, an earlier generation, or an ordinary one-millisecond exchange
            // cannot acquire whichever generation happens to exist when its later error is sent.
            *stopped_reader_generation =
                Self::admit_stopped_reader_generation_for_proof(op, &id, remaining_ms);
        }
        let deadline = match op {
            REACHABILITY_WAKE_OP => std::time::Instant::now() + PATIENCE,
            1 if remaining_ms > 0 => local_deadline(remaining_ms, COMPUTER_PAIR_WITHIN),
            2 if remaining_ms > 0 => local_deadline(remaining_ms, COMPUTER_RETURN_SHOWN_WITHIN),
            1 | 2 => return Err(bad()),
            _ => return Err(bad()),
        };
        // An error response belongs to the request's already-owned clock. The server must not
        // mint another PATIENCE interval after the operation has exhausted that clock.
        *response_deadline = deadline;
        let echo = hello(op, &self.computer.description(), &id, remaining_ms);
        write_frame_until(send, &echo, deadline).await?;
        #[cfg(feature = "test-knobs")]
        if let Some(generation) = *stopped_reader_generation {
            return Self::release_stopped_reader_answer_for_proof(generation, response_deadline)
                .await;
        }
        if op == REACHABILITY_WAKE_OP {
            return Ok(());
        }
        if op == 2 {
            let payload = frame_until(recv, deadline).await?;
            #[cfg(feature = "test-knobs")]
            self.partition_computer_peer_for_proof(conn.peer_id())?;
            // A merge that moves this daemon's revision is a change here (ADR-038 FX-28). The
            // reply is the merged state, encoded under the same lock, so the revision the
            // record names is the revision the reply carries.
            let local = self.computer.signer.fingerprint();
            let (merged, policy_revision, involved, reply) =
                self.computer.change_until(deadline, |s| {
                    merge(s, &payload, conn.peer_id(), self.computer.signer.as_ref())?;
                    Ok((
                        s.revision,
                        s.policy_revision,
                        pending_involves(s, &local, &conn.peer_id()),
                        exchange(s, &conn.peer_id())?,
                    ))
                })?;
            #[cfg(feature = "test-knobs")]
            self.hold_answer_after_merge_for_proof(conn.peer_id()).await;
            write_frame_until(send, &reply, deadline).await?;
            self.record_answered(conn.peer_id(), merged, policy_revision, involved)?;
            return Ok(());
        }
        let (invite, mut g) = {
            let s = lock(&self.computer.state);
            let i=s.invitations.iter().find(|i|i.id==id&&!i.cancelled&&i.expires>now()).ok_or(Error::Profile("computer pairing code expired, cancelled, or unknown; no new trust was established"))?;
            if i.target.is_some_and(|t| t != conn.peer_id()) {
                return Err(Error::Profile(
                    "computer pairing code was already consumed by another identity",
                ));
            }
            let g = Enrollment {
                group: s.genesis.as_ref().map(Enrollment::incarnation),
                expires: i.expires,
                nonce: i.nonce,
                computers: [s.description.clone(), peer],
                grants: [
                    s.grant(&self.computer.signer.fingerprint())
                        .unwrap_or(i.grants[0]),
                    i.grants[1],
                ],
                approvals: [None, None],
            };
            if s.pending
                .as_ref()
                .is_some_and(|p| p.body() != g.body() && !enrolled(&s, p))
            {
                return Err(Error::Profile(
                    "another computer enrollment is already recorded",
                ));
            }
            (i.clone(), g)
        };
        let sid = cpace::fresh_sid()?;
        let ci = context(&id, &invite.transport, &g);
        let (state, share) = cpace::CpaceState::start_with_context(
            invite.secret.as_ref(),
            &ci,
            conn.session().suite_id,
            &sid,
        )?;
        let mut e = Encoder::new();
        e.array(3).bytes(&sid).bytes(&g.encode()).bytes(&share);
        write_frame_until(send, &e.finish(), deadline).await?;
        let f = frame_until(recv, deadline).await?;
        let mut d = Decoder::new(&f);
        arity(&mut d, 2)?;
        let remote_share: [u8; 32] = d.bytes()?.try_into().map_err(|_| bad())?;
        let sealed = d.bytes()?;
        d.finish()?;
        let isk = state.finish(&remote_share)?;
        let transcript = pop::transcript_hash(
            &[ci.as_slice(), &sid].concat(),
            isk.as_ref(),
            &share,
            &remote_share,
        );
        let proof = pop::open_pop(isk.as_ref(), sealed)?;
        pop::verify(&proof, &ci, &transcript, &conn.peer_id())?;
        let recorded = self.computer.change_until(deadline, |s| {
            let before_revision = s.revision;
            let before_pending = s.pending.as_ref().map(Enrollment::encode);
            let i = s
                .invitations
                .iter_mut()
                .find(|i| i.id == id && !i.cancelled && i.expires > now())
                .ok_or(Error::Profile(
                    "computer pairing code expired or was cancelled",
                ))?;
            if i.target.is_some_and(|t| t != conn.peer_id()) {
                return Err(Error::Profile("computer pairing code was already consumed"));
            }
            if s.pending.as_ref().is_some_and(|p| p.body() != g.body()) {
                return Err(Error::Profile("another enrollment is already recorded"));
            }
            i.target = Some(conn.peer_id());
            if let Some(p) = s.pending.as_ref() {
                g.approvals = p.approvals.clone();
            }
            s.pending = Some(g);
            s.pending_expires = invite.expires;
            if s.pending.as_ref().map(Enrollment::encode) != before_pending
                && s.revision == before_revision
            {
                s.advance_journal()?;
            }
            // The state sent back, encoded with the pairing just recorded, and its revision.
            Ok((
                s.revision,
                s.policy_revision,
                pending_involves(s, &self.computer.signer.fingerprint(), &conn.peer_id()),
                exchange(s, &conn.peer_id())?,
            ))
        })?;
        let (revision, policy_revision, involved, payload) = recorded;
        let proof = pop::IdentityProof::create(self.computer.signer.as_ref(), &ci, &transcript)?;
        let mut e = Encoder::new();
        e.array(2)
            .bytes(&pop::seal_pop(isk.as_ref(), &proof)?)
            .bytes(&payload);
        write_frame_until(send, &e.finish(), deadline).await?;
        // The enrollment handshake is an exchange this daemon answered (ADR-038 FX-28).
        self.record_answered(conn.peer_id(), revision, policy_revision, involved)?;
        Ok(())
    }
    /// Wake one failed peer from authenticated connection/application activity. A peer that has
    /// no failed exchange cannot spend work by sending streams: it is not put on this set.
    fn retry_peer_now(&self, peer: Digest32) {
        // Keep the state snapshot locked through mark insertion. Otherwise P2 can commit and its
        // ComputerChange can be fully consumed after this function reads P1 but before it inserts
        // the P1 mark, leaving a stale barrier with no remaining P2 event able to replace it.
        // This is the scheduler's established state -> exchanged -> retry_ready lock order.
        let state = lock(&self.computer.state);
        let revision = state.revision;
        let policy_revision = state.policy_revision;
        let deadline = lock(&self.exchanged).get(&peer).and_then(|record| {
            (record.failures > 0 && record.deadline_policy_revision == Some(policy_revision)).then(
                || {
                    record
                        .deadline
                        .unwrap_or(std::time::Instant::now() + COMPUTER_RETURN_SHOWN_WITHIN)
                },
            )
        });
        if let Some(deadline) = deadline {
            self.mark_retry(peer, revision, policy_revision, deadline);
            drop(state);
            self.retry_wake.notify_one();
        } else {
            drop(state);
        }
    }

    fn mark_retry(
        &self,
        peer: Digest32,
        revision: u64,
        policy_revision: u64,
        deadline: std::time::Instant,
    ) {
        let mut ready = lock(&self.retry_ready);
        match ready.entry(peer) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(RetryMark {
                    token: next_flight(),
                    policy_revision,
                    revision,
                    deadline,
                });
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                // An older torn flight cannot shorten a replacement already registered for a
                // newer state. At the same/newer journal revision, transport-only supersession
                // retains the earliest unfinished clock; policy supersession uses
                // `mark_policy_retry` below and deliberately replaces it.
                if policy_revision < entry.get().policy_revision
                    || (policy_revision == entry.get().policy_revision
                        && revision < entry.get().revision)
                {
                    return;
                }
                if policy_revision > entry.get().policy_revision {
                    entry.insert(RetryMark {
                        token: next_flight(),
                        policy_revision,
                        revision,
                        deadline,
                    });
                    return;
                }
                let merged_revision = revision;
                let merged_deadline = entry.get().deadline.min(deadline);
                if merged_revision != entry.get().revision
                    || merged_deadline != entry.get().deadline
                {
                    entry.insert(RetryMark {
                        token: next_flight(),
                        policy_revision,
                        revision: merged_revision,
                        deadline: merged_deadline,
                    });
                }
            }
        }
    }

    /// Register a durable operator-policy event. Unlike a later transport-only journal movement,
    /// a newer policy revision is a new user cause with its own already-created deadline; it
    /// replaces every older cause instead of inheriting an expired clock (ADR-038 FX-28).
    fn mark_policy_retry(
        &self,
        peer: Digest32,
        revision: u64,
        policy_revision: u64,
        deadline: std::time::Instant,
    ) {
        let mut ready = lock(&self.retry_ready);
        match ready.entry(peer) {
            std::collections::btree_map::Entry::Occupied(mut entry)
                if entry.get().policy_revision < policy_revision =>
            {
                entry.insert(RetryMark {
                    token: next_flight(),
                    policy_revision,
                    revision,
                    deadline,
                });
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if entry.get().policy_revision > policy_revision || revision < entry.get().revision
                {
                    return;
                }
                let merged_deadline = entry.get().deadline.min(deadline);
                if revision != entry.get().revision || merged_deadline != entry.get().deadline {
                    entry.insert(RetryMark {
                        token: next_flight(),
                        policy_revision,
                        revision,
                        deadline: merged_deadline,
                    });
                }
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(RetryMark {
                    token: next_flight(),
                    policy_revision,
                    revision,
                    deadline,
                });
            }
        }
    }

    /// A durable state event owns its deadline before scheduling. Every peer selected because
    /// of that revision uses the same absolute end through exchange and local reconciliation.
    fn retry_changed_now(&self, change: ComputerChange) {
        let local = self.computer.signer.fingerprint();
        let (revision, peers): (u64, Vec<_>) = {
            let state = lock(&self.computer.state);
            (
                state.revision,
                state
                    .exchange_peers()
                    .unwrap_or_else(|_| state.descriptions().into_keys().collect())
                    .into_iter()
                    .filter(|peer| *peer != local)
                    .collect(),
            )
        };
        if !peers.is_empty() {
            for peer in peers {
                self.mark_policy_retry(peer, revision, change.revision(), change.return_deadline());
            }
            self.retry_wake.notify_one();
        }
    }

    async fn retry(self: &Arc<Self>) -> Result<Option<std::time::Instant>> {
        #[cfg(feature = "test-knobs")]
        self.hold_retry_ready_for_proof().await;
        let (peers, attempted, revision, policy_revision, mut next) = {
            let s = lock(&self.computer.state);
            let policy_revision = s.policy_revision;
            let local = self.computer.signer.fingerprint();
            let mut peers: std::collections::BTreeSet<_> = s
                .descriptions()
                .into_keys()
                .filter(|p| *p != local)
                .collect();
            if let Some(g) = &s.pending {
                peers.insert(g.computers[1 - side(g, &local)?].fingerprint()?);
            }
            // A computer needs an exchange when it has not acknowledged this node's current
            // state (it holds no valid receipt for this node's incarnation, rosters and heads;
            // each side counts its own revision, so the numbers are never compared), when a
            // pending operation involves it, or when the fallback interval passed; a computer
            // that could not be reached waits out its backoff. Measured before this (2026-10-20): every computer
            // was exchanged with every 2 s, the whole signed history sent and re-verified each
            // time, 47–95% of a core on the decider's daemon while nothing changed.
            // A pairing stays recorded as `pending` after it completes (its intent is part of
            // every exchange), so the other computer counts as involved only while the
            // operation is open: an approval is missing, or it has not activated here yet.
            let involved: Option<Digest32> = s
                .pending
                .as_ref()
                .filter(|g| {
                    g.approvals.iter().any(Option::is_none)
                        || (g.group.is_none() && s.genesis.is_none())
                        || (g.group.is_some() && !enrolled(&s, g))
                })
                .and_then(|g| {
                    side(g, &local)
                        .ok()
                        .map(|i| g.computers[1 - i].fingerprint().ok())
                })
                .flatten();
            let now = std::time::Instant::now();
            let mut next: Option<std::time::Instant> = None;
            let revision = s.revision;
            let mut exchanged = lock(&self.exchanged);
            let mut retry_ready = lock(&self.retry_ready);
            let mut selected_deadlines = BTreeMap::new();
            let mut selected_tokens = BTreeMap::new();
            let mut selected_causal = BTreeSet::new();
            // A computer no longer paired (removed, or its pairing cancelled) keeps its
            // counts, which are "since the daemon started" and survive its re-enrollment, but
            // not its failure: that must not stand in the status for good.
            let known: std::collections::BTreeSet<Digest32> = peers.iter().copied().collect();
            // A later journal revision changes the payload, not the deadline owned by an older
            // unfinished cause. `mark_retry` carries that earliest clock onto the current state.
            retry_ready.retain(|peer, _| known.contains(peer));
            let mut changed = false;
            for (peer, record) in exchanged.iter_mut() {
                if !known.contains(peer) && (record.failures > 0 || record.problem.is_some()) {
                    record.failures = 0;
                    record.deadline = None;
                    record.deadline_policy_revision = None;
                    record.problem = None;
                    changed = true;
                }
            }
            if changed {
                *lock(&self.problem) = exchanged
                    .values()
                    .filter(|r| r.failures > 0)
                    .find_map(|r| r.problem.clone());
            }
            peers.retain(|peer| {
                // A repair which completed after its deadline remains a visible miss for that
                // exact state and needs no periodic retry. A later policy state is a new cause;
                // it may make one attempt under its own already-created retry mark.
                if let Some(record) = exchanged.get_mut(peer) {
                    let replaced_miss = record.missed_revision.is_some()
                        && record.missed_revision != Some(policy_revision);
                    let replaced_failure = record.failures > 0
                        && record
                            .deadline_policy_revision
                            .is_some_and(|owner| owner != policy_revision);
                    if replaced_miss || replaced_failure {
                        record.failures = 0;
                        record.deadline = None;
                        record.deadline_policy_revision = None;
                        record.problem = None;
                        if replaced_miss {
                            record.missed_revision = None;
                            record.repaired_late = None;
                        }
                        changed = true;
                    }
                }
                let record = exchanged.get(peer).cloned().unwrap_or_default();
                let causal_mark = retry_ready.get(peer).copied();
                if causal_mark.is_some_and(|mark| mark.policy_revision != policy_revision) {
                    // A reachability wake can snapshot P1 immediately before P2 commits. Never
                    // lend P1's (possibly expired) clock to P2, and do not invent a default clock
                    // for P2. Keep this stale mark only as a barrier for this turn; the already
                    // queued ComputerChange is the sole owner of P2's original deadline and
                    // `mark_policy_retry` replaces the mark when that event is consumed.
                    return false;
                }
                let reachability_restored = causal_mark.is_some();
                let causal_deadline = match (causal_mark.map(|mark| mark.deadline), record.deadline)
                {
                    (Some(mark), Some(failure)) => mark.min(failure),
                    (Some(deadline), None) | (None, Some(deadline)) => deadline,
                    (None, None) => now + COMPUTER_RETURN_SHOWN_WITHIN,
                };
                selected_deadlines.insert(*peer, causal_deadline);
                if let Some(last) = record.last {
                    if record.failures > 0 {
                        // The backoff is inside the return contract begun by the failure. Leave
                        // the real apply-or-detach interval before its one absolute end; no stage
                        // starts another clock.
                        let wait = computer_exchange_backoff(record.failures).min(
                            COMPUTER_RETURN_SHOWN_WITHIN
                                .saturating_sub(COMPUTER_CHANGE_SHOWN_WITHIN),
                        );
                        let unchanged = record.revision == revision
                            && record.involved == (involved == Some(*peer));
                        if unchanged && !reachability_restored {
                            // Leave the apply interval before the causal return deadline. When
                            // exponential backoff would pass that boundary, the deadline wins;
                            // a reachable peer is actually dialled rather than merely timing out.
                            let due = if causal_deadline > now {
                                let backstop = causal_deadline
                                    .checked_sub(COMPUTER_CHANGE_SHOWN_WITHIN)
                                    .unwrap_or(now);
                                (last + wait).min(backstop)
                            } else {
                                // The product already missed this cause's return contract. Keep
                                // repairing it at bounded backoff without spinning or pretending
                                // a later retry started a new user-visible clock.
                                last + wait
                            };
                            if now >= due {
                                return true;
                            }
                            next = Some(next.map_or(due, |held| held.min(due)));
                            return false;
                        }
                    } else {
                        // A successful exchange delivered this exact payload. A missing applied
                        // receipt means the peer is still doing local work, not that sending the
                        // same signed history again can help it. Its authenticated state change
                        // wakes us; the quiet fallback covers a lost wake. Retrying immediately
                        // here completed 585 full exchanges in one minute and starved the peer's
                        // node reconciliation—the idle CPU/network storm FX-29 measures.
                        let unchanged = record.revision == revision
                            && record.involved == (involved == Some(*peer));
                        if unchanged
                            && !reachability_restored
                            && now.duration_since(last) < EXCHANGE_FALLBACK
                        {
                            let due = last + EXCHANGE_FALLBACK;
                            next = Some(next.map_or(due, |held| held.min(due)));
                            return false;
                        }
                    }
                }
                if let Some(mark) = causal_mark {
                    selected_tokens.insert(*peer, mark.token);
                }
                let acknowledged = s
                    .receipts
                    .get(peer)
                    .is_some_and(|receipt| valid_receipt(&s, peer, receipt).unwrap_or(false));
                if causal_mark.is_some()
                    || !acknowledged
                    || involved == Some(*peer)
                    || record.failures > 0
                {
                    selected_causal.insert(*peer);
                }
                true
            });
            if changed {
                *lock(&self.problem) = exchanged
                    .values()
                    .filter(|r| r.failures > 0)
                    .find_map(|r| r.problem.clone());
            }
            drop(retry_ready);
            drop(exchanged);
            // Reserved under one lock, after every other filter: a computer already in
            // flight (with the retry or with the operator's pairing) is left alone, and no
            // two exchanges with one computer ever overlap. An exchange in flight that
            // carries state this node has since changed is cut: its payload is stale, its end
            // counts as no failure, and the next tick exchanges the current state.
            {
                let mut inflight = lock(&self.inflight);
                for (peer, flight) in inflight.iter_mut() {
                    // Stale: this node's state moved on, or (a retry flight) whether the
                    // computer is involved in a pending operation changed.
                    let stale = flight.revision != revision
                        || (flight.origin == Origin::Retry
                            && flight.involved != (involved == Some(*peer)));
                    if stale && !flight.superseded {
                        // Transfer the first unfinished change's end before cutting the stale
                        // work. The replacement may carry newer state, but never gets a newer
                        // convergence clock.
                        self.mark_retry(
                            *peer,
                            flight.revision,
                            flight.policy_revision,
                            flight.deadline,
                        );
                        flight.superseded = true;
                        #[cfg(feature = "test-knobs")]
                        if flight.origin == Origin::Operator && flight.abort.is_none() {
                            self.mark_operator_superseded_for_proof(*peer);
                        }
                        if let Some(abort) = &flight.abort {
                            abort.abort();
                        }
                    }
                }
                peers.retain(|peer| {
                    if inflight.contains_key(peer) {
                        return false;
                    }
                    inflight.insert(
                        *peer,
                        Flight {
                            serial: next_flight(),
                            policy_revision,
                            revision,
                            involved: involved == Some(*peer),
                            causal: selected_causal.contains(peer),
                            deadline: selected_deadlines
                                .get(peer)
                                .copied()
                                .unwrap_or(now + COMPUTER_RETURN_SHOWN_WITHIN),
                            origin: Origin::Retry,
                            abort: None,
                            covered: false,
                            superseded: false,
                        },
                    );
                    // Consume a reachability event only after it has actually reserved the
                    // replacement attempt. If an older attempt is still in flight, its drop
                    // wakes the scheduler and the event remains ready for that next pass.
                    if let Some(token) = selected_tokens.get(peer) {
                        let mut ready = lock(&self.retry_ready);
                        if ready.get(peer).is_some_and(|mark| mark.token == *token) {
                            ready.remove(peer);
                        }
                    }
                    // A round counts from its start: one in flight, or cut, is a round too.
                    let mut exchanged = lock(&self.exchanged);
                    let record = exchanged.entry(*peer).or_default();
                    record.attempts = record.attempts.saturating_add(1);
                    true
                });
            }
            let attempted: Vec<(Digest32, bool, u64, std::time::Instant, bool)> = {
                let inflight = lock(&self.inflight);
                peers
                    .iter()
                    .map(|p| {
                        (
                            *p,
                            involved == Some(*p),
                            inflight.get(p).map_or(0, |f| f.serial),
                            selected_deadlines
                                .get(p)
                                .copied()
                                .unwrap_or(now + COMPUTER_RETURN_SHOWN_WITHIN),
                            selected_causal.contains(p),
                        )
                    })
                    .collect()
            };
            let peers = peers
                .into_iter()
                .map(|peer| {
                    let endpoints = s
                        .reaches
                        .get(&peer)
                        .map(|r| r.endpoints.clone())
                        .unwrap_or_default();
                    let url = s
                        .pair_link
                        .as_ref()
                        .filter(|l| Link::parse(l).ok().is_some_and(|l| l.target == peer))
                        .cloned()
                        .or_else(|| {
                            s.links
                                .iter()
                                .find(|l| Link::parse(l).ok().is_some_and(|l| l.target == peer))
                                .cloned()
                        });
                    (peer, endpoints, url)
                })
                .collect::<Vec<_>>();
            (peers, attempted, revision, policy_revision, next)
        };
        for (peer, endpoints, url) in peers {
            let me = Arc::clone(self);
            let (involved, serial, deadline, causal) =
                attempted.iter().find(|(p, _, _, _, _)| *p == peer).map_or(
                    (false, 0, std::time::Instant::now(), false),
                    |(_, involved, serial, deadline, causal)| {
                        (*involved, *serial, *deadline, *causal)
                    },
                );
            let mut attempt_revision = revision;
            if causal {
                match self.computer.record_pending_exchange(peer, policy_revision) {
                    Ok(Some(current_revision)) => {
                        attempt_revision = current_revision;
                        if let Some(flight) = lock(&self.inflight).get_mut(&peer) {
                            if flight.serial == serial {
                                flight.revision = current_revision;
                            }
                        }
                    }
                    Ok(None) => {
                        if let Some(flight) = lock(&self.inflight).get_mut(&peer) {
                            if flight.serial == serial {
                                flight.superseded = true;
                            }
                        }
                        // Release this exact superseded reservation. The ordinary guard is built
                        // below only after durable reservation succeeds; without a guard here the
                        // map would retain a flight which owns no task forever.
                        drop(Attempt {
                            me: Arc::clone(self),
                            peer,
                            serial,
                            revision: attempt_revision,
                            policy_revision,
                            involved,
                            causal,
                            deadline,
                            recorded: false,
                        });
                        continue;
                    }
                    Err(error) => {
                        let guard = Attempt {
                            me: Arc::clone(self),
                            peer,
                            serial,
                            revision: attempt_revision,
                            policy_revision,
                            involved,
                            causal,
                            deadline,
                            recorded: false,
                        };
                        guard.done(Err(format!(
                            "the exchange obligation could not be recorded durably: {error}"
                        )));
                        continue;
                    }
                }
            }
            // The guard exists before the task does and travels with it: a task cut before
            // its first poll drops the guard all the same, so no reservation ever leaks.
            let guard = Attempt {
                me: Arc::clone(self),
                peer,
                serial,
                revision: attempt_revision,
                policy_revision,
                involved,
                causal,
                deadline,
                recorded: false,
            };
            let task = tokio::spawn(async move {
                // Each computer's outcome is recorded by its own task the moment it ends,
                // dated then: a slow computer never delays another's record, status or next
                // attempt. Exchange and reconciliation share the causal return deadline; this
                // stage neither subtracts a private budget nor starts a new one.
                let outcome = if deadline <= std::time::Instant::now() {
                    if causal {
                        let _recording = lock(&me.recording);
                        if lock(&me.inflight)
                            .get(&peer)
                            .is_some_and(|flight| flight.serial == serial && flight.superseded)
                        {
                            return;
                        }
                        if let Err(error) =
                            me.computer
                                .record_missed_exchange(peer, attempt_revision, false)
                        {
                            drop(_recording);
                            guard.done(Err(format!(
                                "the missed exchange could not be recorded durably: {error}"
                            )));
                            return;
                        }
                    }
                    // The product already missed the causal contract, but repair must continue.
                    // A local operational bound prevents the transport from being held forever;
                    // `guard` still records the original deadline, so completion remains a
                    // visible miss and can never be reported as satisfying the original cause.
                    me.sync_peer(
                        peer,
                        endpoints,
                        url,
                        serial,
                        std::time::Instant::now() + COMPUTER_RETURN_SHOWN_WITHIN,
                    )
                    .await
                    .map_err(|e| e.to_string())
                } else {
                    let exchange = me.sync_peer(peer, endpoints, url, serial, deadline);
                    tokio::pin!(exchange);
                    tokio::select! {
                        // Poll the exchange first at the boundary. This starts the real dial;
                        // an already-ready timer must not manufacture a timeout without touching
                        // a reachable peer.
                        biased;
                        result = &mut exchange => result.map_err(|e| e.to_string()),
                        () = tokio::time::sleep_until(deadline.into()) => {
                            Err(if causal {
                                "the exchange did not finish before its causal convergence deadline".into()
                            } else {
                                "the quiet fallback exchange did not finish before its operational return bound".into()
                            })
                        },
                    }
                };
                guard.done(outcome);
            });
            // Installed on this flight only: a flight that ended and was replaced meanwhile
            // never receives a handle to a task that is not its own.
            if let Some(flight) = lock(&self.inflight).get_mut(&peer) {
                if flight.serial == serial {
                    flight.abort = Some(task.abort_handle());
                    if flight.superseded {
                        task.abort();
                    }
                }
            }
        }
        // A spawned attempt wakes this scheduler when its reservation ends. Until then the exact
        // deadline of another peer (if any) is the only timer; with no work there is no polling.
        if next.is_some_and(|at| at <= std::time::Instant::now()) {
            next = Some(std::time::Instant::now());
        }
        Ok(next)
    }
    /// Record one attempt's outcome for `peer`, now: `last` paces the next attempt whether it
    /// succeeded or not; `last_ms`, what a person reads as the last exchange, is set only by a
    /// completed one. The status's problem is then the words of a computer still failing, or
    /// none: it never clears while a failure stands, and never stands once every computer is
    /// exchanged with again.
    // Every outcome retains the cause captured by its own flight, including teardown after that
    // flight has left `inflight`; reading those fields from a newer reservation would be wrong.
    #[allow(clippy::too_many_arguments)]
    fn record_exchange(
        self: &Arc<Self>,
        peer: Digest32,
        serial: u64,
        revision: u64,
        policy_revision: u64,
        involved: bool,
        causal: bool,
        deadline: std::time::Instant,
        mut outcome: std::result::Result<(u64, u64), String>,
        covered_payload: Option<(u64, u64)>,
    ) {
        let _recording = lock(&self.recording);
        // An inbound full exchange can cover and supersede this exact outbound snapshot while its
        // task is finishing. It records the successful coverage under `recording`; the older
        // outbound outcome must not recreate a miss afterward.
        let (superseded, covered) = lock(&self.inflight)
            .get(&peer)
            .filter(|flight| flight.serial == serial)
            .map_or((false, false), |flight| (flight.superseded, flight.covered));
        if superseded || (covered && outcome.is_err()) {
            return;
        }
        if lock(&self.exchanged)
            .get(&peer)
            .is_some_and(|record| record.last_serial > serial)
        {
            return;
        }
        let completed = std::time::Instant::now();
        let (retained_miss, was_repaired) =
            lock(&self.exchanged)
                .get(&peer)
                .map_or((false, false), |record| {
                    (
                        record.missed_revision == Some(policy_revision),
                        record.repaired_late == Some(policy_revision),
                    )
                });
        let missed = retained_miss || (causal && completed >= deadline);
        // Only the snapshot this flight actually sent can acknowledge a local obligation. The
        // merged revision may include a newer local cause which arose while this flight was away.
        let durable_revision = outcome.as_ref().map_or(revision, |(sent, merged)| {
            #[cfg(feature = "test-knobs")]
            if crate::node::computer::fx28_mutant("stale-flight-clears-newer") {
                *merged
            } else {
                *sent
            }
            #[cfg(not(feature = "test-knobs"))]
            {
                let _ = merged;
                *sent
            }
        });
        let mut missed_cause = None;
        let durable = if covered {
            Ok(())
        } else if missed {
            self.computer
                .record_missed_exchange(peer, durable_revision, outcome.is_ok() || was_repaired)
                .map(|cause| {
                    missed_cause = Some(cause);
                })
        } else if outcome.is_ok() {
            self.computer.record_timely_exchange(peer, durable_revision)
        } else {
            Ok(())
        };
        if let Err(error) = durable {
            outcome = Err(format!(
                "the exchange result could not be recorded durably: {error}"
            ));
        }
        // Authenticated traffic from this very sync can complete the reachability waiter and
        // enqueue a retry while the exchange is still in flight. A successful payload has already
        // discharged every such cause through both revisions it actually carried. Consume only a
        // mark covered on both axes: `retry_peer_now` can otherwise combine an older journal
        // revision with a policy revision which committed while this flight was away. Operator
        // pairing has no coverage tuple because its reported pre-merge revision is not a sent
        // ordinary-sync snapshot.
        let covered_retry = outcome.as_ref().ok().and(covered_payload);
        let mut exchanged = lock(&self.exchanged);
        let record = exchanged.entry(peer).or_default();
        record.last_serial = serial;
        record.last = Some(completed);
        record.revision = revision;
        record.involved = involved;
        let failed = outcome.is_err() && !was_repaired;
        match outcome {
            Ok((sent_revision, merged_revision)) => {
                let at_ms = now();
                record.last_ms = Some(at_ms);
                record.count = record.count.saturating_add(1);
                if missed {
                    let missed_revision = missed_cause.unwrap_or(policy_revision);
                    // The original cause remains durably late, but this exchange succeeded now.
                    // Current consecutive failures and their backoff are operational state, not
                    // historical verdicts: clear them and resume the ordinary quiet fallback.
                    record.failures = 0;
                    record.deadline = None;
                    record.deadline_policy_revision = None;
                    record.problem = None;
                    record.repaired_late = Some(missed_revision);
                    record.missed_revision = Some(missed_revision);
                } else {
                    record.failures = 0;
                    record.deadline = None;
                    record.deadline_policy_revision = None;
                    record.problem = None;
                    record.missed_revision = None;
                    record.repaired_late = None;
                }
                record.last_started = Some(ExchangeRecord {
                    at_ms,
                    sent_revision,
                    merged_revision,
                });
            }
            Err(text) => {
                record.failures = record.failures.saturating_add(1);
                record.deadline = Some(
                    record
                        .deadline
                        .filter(|_| record.deadline_policy_revision == Some(policy_revision))
                        .map_or(deadline, |held| held.min(deadline)),
                );
                record.deadline_policy_revision = Some(policy_revision);
                record.problem = Some(if was_repaired {
                    "the exchange repaired state only after its causal convergence deadline".into()
                } else if missed {
                    "the exchange did not finish before its causal convergence deadline".into()
                } else {
                    text
                });
                if missed {
                    record.missed_revision = Some(missed_cause.unwrap_or(policy_revision));
                }
                if record
                    .repaired_late
                    .is_none_or(|held| held != missed_cause.unwrap_or(policy_revision))
                {
                    record.repaired_late = None;
                }
            }
        }
        *lock(&self.problem) = exchanged
            .values()
            .filter(|r| r.failures > 0)
            .find_map(|r| r.problem.clone());
        drop(exchanged);
        if let Some((covered_revision, covered_policy_revision)) = covered_retry {
            let mut ready = lock(&self.retry_ready);
            if ready.get(&peer).is_some_and(|mark| {
                mark.revision <= covered_revision && mark.policy_revision <= covered_policy_revision
            }) {
                ready.remove(&peer);
            }
        }
        if failed {
            self.arm_reachability_waiter(peer);
        } else if let Some((_, waiter)) = lock(&self.reachability_waiters).remove(&peer) {
            waiter.abort();
        }
    }

    /// After an exchange has failed on a still-held authenticated connection, put one computer
    /// hello on that connection and leave it there. QUIC retransmits the one write; no timer and
    /// no repeated probe is needed. When the path carries authenticated packets again, the peer's
    /// computer-stream answer completes this waiter and directly wakes the scheduler.
    fn arm_reachability_waiter(self: &Arc<Self>, peer: Digest32) {
        let Some(conn) = self.net.manager().held(&peer) else {
            return;
        };
        let mut waiters = lock(&self.reachability_waiters);
        if waiters.contains_key(&peer) {
            return;
        }
        let Some(deadline) = lock(&self.exchanged)
            .get(&peer)
            .and_then(|record| record.deadline)
        else {
            return;
        };
        let serial = next_flight();
        let start = Arc::new(tokio::sync::Notify::new());
        let started = Arc::clone(&start);
        let weak = Arc::downgrade(self);
        let description = self.computer.description();
        let task = tokio::spawn(async move {
            started.notified().await;
            let result = async {
                let (mut send, mut recv) = streams::open_typed(&conn, StreamKind::Computer).await?;
                write_frame_until(
                    &mut send,
                    &hello(REACHABILITY_WAKE_OP, &description, &[0; 32], 0),
                    deadline,
                )
                .await?;
                let response = read_frame_before(&mut recv, MAX_FRAME, deadline)
                    .await?
                    .ok_or(Error::Profile(
                        "computer reachability peer closed before answering",
                    ))?;
                let (op, _, _, _) = parse_hello(&response, &conn)?;
                if op != REACHABILITY_WAKE_OP {
                    return Err(bad());
                }
                Result::<()>::Ok(())
            }
            .await;
            if let Some(me) = weak.upgrade() {
                let mut held = lock(&me.reachability_waiters);
                if held.get(&peer).is_some_and(|(held, _)| *held == serial) {
                    held.remove(&peer);
                }
                drop(held);
                // Only a successfully parsed response on this authenticated computer stream is
                // evidence that reachability returned. Timeout, closure and protocol failure do
                // not create a fresh convergence clock.
                if result.is_ok() {
                    me.retry_peer_now(peer);
                }
            }
        });
        waiters.insert(peer, (serial, task.abort_handle()));
        start.notify_one();
    }
    /// One exchange this node starts with `peer`: this node's revision as sent, and after the
    /// computer's state was merged.
    async fn sync_peer(
        self: &Arc<Self>,
        peer: Digest32,
        endpoints: EndpointList,
        url: Option<Zeroizing<String>>,
        _serial: u64,
        deadline: std::time::Instant,
    ) -> Result<(u64, u64, u64)> {
        #[cfg(feature = "test-knobs")]
        self.hold_first_computer_exchange_for_proof(peer, _serial)
            .await;
        let link = url.as_ref().map(|l| Link::parse(l)).transpose()?;
        let endpoints = link.as_ref().map(|l| &l.endpoints).unwrap_or(&endpoints);
        let conn = self.connect(peer, endpoints, link.as_ref()).await?;
        self.serve(Arc::clone(&conn));
        #[cfg(feature = "test-knobs")]
        self.stage_stopped_reader_for_proof(&conn, deadline).await?;
        let (payload, sent, sent_policy) = {
            let s = lock(&self.computer.state);
            (exchange(&s, &peer)?, s.revision, s.policy_revision)
        };
        let (mut send, mut recv) = streams::open_typed(&conn, StreamKind::Computer).await?;
        let remaining_ms = wire_budget(deadline);
        write_frame_until(
            &mut send,
            &hello(2, &self.computer.description(), &[0; 32], remaining_ms),
            deadline,
        )
        .await?;
        let (op, _, _, echoed_remaining_ms) = read_hello_until(&mut recv, &conn, deadline).await?;
        if op != 2 || echoed_remaining_ms != remaining_ms {
            return Err(bad());
        }
        write_frame_until(&mut send, &payload, deadline).await?;
        let f = frame_until(&mut recv, deadline).await?;
        #[cfg(feature = "test-knobs")]
        self.partition_computer_peer_for_proof(peer)?;
        // A merge that moves this daemon's revision is a change here: `change` wakes the
        // daemon's follower on it (ADR-038 FX-28).
        let merged = self.computer.change_until(deadline, |s| {
            merge(s, &f, peer, self.computer.signer.as_ref())?;
            Ok(s.revision)
        })?;
        let _ = send.finish();
        Ok((sent, sent_policy, merged))
    }

    /// Have this real shipped daemon act as the stopped reader. The peer sees ordinary
    /// authenticated Computer streams. An echoed hello causally proves that a request, rather than
    /// unrelated management traffic, owns a bounded answer slot. After exactly all slots are
    /// admitted, one release makes their request-owned deadlines expired and the receive halves
    /// remain alive but unread for the production response patience. Correct code frees each slot;
    /// the mutant gives each error write a fresh interval and strands all slots behind QUIC flow
    /// control. No sender-side sleep or assumed free-slot count stages the claim.
    #[cfg(feature = "test-knobs")]
    async fn stage_stopped_reader_for_proof(
        &self,
        conn: &Arc<VoxConnection>,
        deadline: std::time::Instant,
    ) -> Result<()> {
        let Ok(spec) = std::env::var(TEST_STOPPED_READER_ARM_ENV) else {
            return Ok(());
        };
        let mut fields = spec.split('\t');
        let (Some(arm), Some(generation), Some(release), Some(answered), None) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return Ok(());
        };
        if std::fs::remove_file(arm).is_err() {
            return Ok(());
        }
        // The answerer is a separate shipped process, so the generation file is the causal reset
        // shared across that boundary. Clear an earlier completed marker first, then publish a
        // generation unique to this armed connection before any attack stream can be answered.
        let _ = std::fs::remove_file(generation);
        let _ = std::fs::remove_file(release);
        let _ = std::fs::remove_file(answered);
        let generation_id = random_array::<32>()?;
        if std::fs::write(generation, generation_id).is_err() {
            return Ok(());
        }
        let mut held = Vec::with_capacity(MANAGEMENT_SLOTS);
        while held.len() < MANAGEMENT_SLOTS {
            if std::time::Instant::now() >= deadline {
                return Err(Error::Profile(
                    "stopped-reader apparatus could not causally admit every bounded management slot",
                ));
            }
            let Ok((mut send, mut recv)) = streams::open_typed(conn, StreamKind::Computer).await
            else {
                continue;
            };
            let remaining_ms = wire_budget(deadline);
            if write_frame_until(
                &mut send,
                &hello(
                    2,
                    &self.computer.description(),
                    &generation_id,
                    remaining_ms,
                ),
                deadline,
            )
            .await
            .is_err()
            {
                continue;
            }
            match read_hello_until(&mut recv, conn, deadline).await {
                Ok((2, _, echoed, echoed_remaining_ms))
                    if echoed == generation_id && echoed_remaining_ms == remaining_ms =>
                {
                    held.push((send, recv));
                }
                _ => continue,
            }
        }
        if std::fs::write(release, b"release every causally admitted answer\n").is_err() {
            return Err(Error::Profile(
                "stopped-reader apparatus could not publish its causal release",
            ));
        }
        tokio::spawn(async move {
            let _unread = held;
            tokio::time::sleep(PATIENCE).await;
        });
        Ok(())
    }

    #[cfg(feature = "test-knobs")]
    fn admit_stopped_reader_generation_for_proof(
        op: u64,
        request_id: &Digest32,
        remaining_ms: u64,
    ) -> Option<Digest32> {
        if op != 2 || remaining_ms == 0 {
            return None;
        }
        let spec = std::env::var(TEST_STOPPED_READER_ANSWERED_ENV).ok()?;
        let mut fields = spec.split('\t');
        let (Some(generation), Some(_release), Some(_marker), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return None;
        };
        let generation: Digest32 = std::fs::read(generation).ok()?.try_into().ok()?;
        (generation == *request_id).then_some(generation)
    }

    #[cfg(feature = "test-knobs")]
    fn mark_stopped_reader_answer_for_proof(generation: Digest32) -> bool {
        use std::sync::{Mutex, OnceLock};
        static ANSWERS: OnceLock<Mutex<(Digest32, usize)>> = OnceLock::new();
        let Ok(spec) = std::env::var(TEST_STOPPED_READER_ANSWERED_ENV) else {
            return false;
        };
        let mut fields = spec.split('\t');
        let (Some(generation_file), Some(_release), Some(marker), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return false;
        };
        // Admission already bound the request to `generation`; this check only proves that the
        // same arm is still current. It never assigns a later file's generation to the request.
        if std::fs::read(generation_file).ok().as_deref() != Some(generation.as_slice()) {
            return false;
        }
        let mut answers = ANSWERS
            .get_or_init(|| Mutex::new(([0; 32], 0)))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if answers.0 != generation {
            *answers = (generation, 0);
        }
        let completed = answers.1 + 1 == MANAGEMENT_SLOTS;
        if answers.1 < MANAGEMENT_SLOTS {
            answers.1 += 1;
        }
        if completed {
            if std::fs::read(generation_file).ok().as_deref() != Some(generation.as_slice()) {
                return false;
            }
            let _ = std::fs::write(
                marker,
                b"all bounded management slots reached unread replies\n",
            );
        }
        true
    }

    /// Hold an admitted stopped-reader request at a causal boundary. The sender releases only
    /// after it has read all eight echoed hellos, so reaching this helper proves that all bounded
    /// slots are occupied by this generation. Expiring the already-owned request clock is the
    /// apparatus condition under test: production code must not mint another clock for its error
    /// response.
    #[cfg(feature = "test-knobs")]
    async fn release_stopped_reader_answer_for_proof(
        generation: Digest32,
        response_deadline: &mut std::time::Instant,
    ) -> Result<()> {
        let Ok(spec) = std::env::var(TEST_STOPPED_READER_ANSWERED_ENV) else {
            return Ok(());
        };
        let mut fields = spec.split('\t');
        let (Some(generation_file), Some(release), Some(_marker), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Ok(());
        };
        while !std::path::Path::new(release).is_file() {
            if std::time::Instant::now() >= *response_deadline {
                return Err(Error::Profile(
                    "stopped-reader apparatus was not causally released before its request clock",
                ));
            }
            tokio::task::yield_now().await;
        }
        if std::fs::read(generation_file).ok().as_deref() != Some(generation.as_slice()) {
            return Err(Error::Profile(
                "stopped-reader apparatus generation changed before its causal release",
            ));
        }
        *response_deadline = std::time::Instant::now();
        Err(Error::Profile(
            "the computer exchange reached its causal convergence deadline",
        ))
    }

    /// Park exactly the first selected exchange after its source-owned local-apply interval. The
    /// state revision that supersedes it aborts this future through the production flight handle.
    /// A marker is apparatus evidence only; every verdict still comes from shipped status and
    /// trust commands.
    #[cfg(feature = "test-knobs")]
    async fn hold_first_computer_exchange_for_proof(&self, peer: Digest32, serial: u64) {
        let Ok(spec) = std::env::var(TEST_HOLD_FIRST_COMPUTER_EXCHANGE_ENV) else {
            return;
        };
        let Some((arm, engaged)) = spec.split_once('\t') else {
            return;
        };
        // The arm names the exact peer and policy revision observed before the change. Claim
        // only this still-owned causal retry flight, without a cancellable gap before marking
        // its entry. Journal movement may supersede it normally and retains its original clock.
        let Ok(armed) = std::fs::read_to_string(arm) else {
            return;
        };
        let Some((expected_peer, after)) = armed.trim().split_once('\t') else {
            return;
        };
        let Ok(after) = after.parse::<u64>() else {
            return;
        };
        {
            let inflight = lock(&self.inflight);
            let Some(flight) = inflight.get(&peer) else {
                return;
            };
            if expected_peer != text_id(&peer)
                || flight.serial != serial
                || flight.origin != Origin::Retry
                || flight.superseded
                || !flight.causal
                || flight.deadline <= std::time::Instant::now()
                || flight.policy_revision <= after
            {
                return;
            }
            let marker = std::path::Path::new(engaged);
            if let Err(error) = std::fs::remove_file(arm) {
                super::publish_proof_fault(
                    &marker.with_extension("fault"),
                    &format!("claim exact first flight arm: {error}"),
                );
                return;
            }
            if flight.deadline <= std::time::Instant::now() {
                super::publish_proof_fault(
                    &marker.with_extension("fault"),
                    "first flight reached its owned deadline while claiming the apparatus arm",
                );
                return;
            }
            let body = format!("{}\t{serial}\t{}", text_id(&peer), flight.policy_revision);
            if let Err(error) = super::publish_proof_marker(marker, body.as_bytes()) {
                super::publish_proof_fault(
                    &marker.with_extension("fault"),
                    &format!("mark exact first flight: {error}"),
                );
                return;
            }
        }
        std::future::pending::<()>().await;
    }

    /// Park the scheduler only at the state in which a superseded flight is gone and its causal
    /// retry mark is the sole owner of the deadline. The release is an exact Unix-socket event,
    /// not a polling interval or a second correctness clock.
    #[cfg(feature = "test-knobs")]
    async fn hold_retry_ready_for_proof(&self) {
        let Ok(spec) = std::env::var(TEST_HOLD_COMPUTER_RETRY_READY_ENV) else {
            return;
        };
        let mut fields = spec.splitn(4, '\t');
        let (Some(arm), Some(engaged), Some(release), Some(fault)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return;
        };
        if !std::path::Path::new(arm).is_file() {
            return;
        }
        let peer = loop {
            // Register before inspecting the reservation: `Attempt::drop` removes the exact
            // superseded flight and then notifies. Enabling first preserves that release edge if
            // it races this inspection, without a sleep or a second deadline.
            let released = self.retry_wake.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            let ready = lock(&self.retry_ready).clone();
            if ready.is_empty() {
                return;
            }
            let sole = (ready.len() == 1)
                .then(|| ready.iter().next().map(|(peer, mark)| (*peer, *mark)))
                .flatten();
            let (inflight, pending_supersession, retiring_source) = {
                let flights = lock(&self.inflight);
                let pending = sole.is_some_and(|(peer, mark)| {
                    flights.len() == 1
                        && flights.get(&peer).is_some_and(|flight| {
                            !flight.superseded && flight.revision < mark.revision
                        })
                });
                let retiring = sole.is_some_and(|(peer, _)| {
                    flights.len() == 1 && flights.get(&peer).is_some_and(|flight| flight.superseded)
                });
                (flights.len(), pending, retiring)
            };
            if pending_supersession {
                // This invocation is what will transfer the old flight's deadline and abort it
                // in the production stale-flight pass below. Leave the arm intact and let that
                // source-owned transition run; the release notification invokes this hook again.
                return;
            }
            if retiring_source {
                released.await;
                continue;
            }
            let exact = (inflight == 0)
                .then_some(sole)
                .flatten()
                .filter(|(peer, _)| {
                    lock(&self.exchanged)
                        .get(peer)
                        .is_none_or(|record| record.failures == 0 && record.deadline.is_none())
                });
            if let Some((peer, _)) = exact {
                break peer;
            }
            if std::fs::remove_file(arm).is_ok() {
                let detail = if inflight != 0 {
                    format!("retry-ready still had {inflight} non-retiring in-flight source(s)")
                } else {
                    match sole {
                        None => format!(
                            "retry-ready held {} peers instead of exactly one",
                            ready.len()
                        ),
                        Some((peer, _)) => {
                            let record = lock(&self.exchanged)
                                .get(&peer)
                                .cloned()
                                .unwrap_or_default();
                            format!(
                                "{} also had failure count {} and a retained failure deadline {}",
                                text_id(&peer),
                                record.failures,
                                record.deadline.is_some()
                            )
                        }
                    }
                };
                publish_proof_fault(std::path::Path::new(fault), &detail);
            }
            return;
        };
        let _ = std::fs::remove_file(release);
        let Ok(listener) = tokio::net::UnixListener::bind(release) else {
            return;
        };
        if std::fs::remove_file(arm).is_err() {
            let _ = std::fs::remove_file(release);
            return;
        }
        if let Err(detail) =
            publish_proof_marker(std::path::Path::new(engaged), text_id(&peer).as_bytes())
        {
            let _ = std::fs::remove_file(release);
            let message = format!("retry-ready marker publication failed: {detail}");
            publish_proof_fault(std::path::Path::new(fault), &message);
            return;
        }
        let _ = listener.accept().await;
        let _ = std::fs::remove_file(release);
    }

    /// Park an operator after it owns the exact peer reservation and before its task or abort
    /// handle exists. A later policy revision can therefore supersede the handle-less flight.
    #[cfg(feature = "test-knobs")]
    async fn hold_operator_reserved_for_proof(&self, peer: Digest32, serial: u64) {
        let Ok(spec) = std::env::var(TEST_HOLD_COMPUTER_OPERATOR_RESERVED_ENV) else {
            return;
        };
        let mut fields = spec.splitn(4, '\t');
        let (Some(arm), Some(engaged), Some(_superseded), Some(release)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return;
        };
        if !lock(&self.inflight).get(&peer).is_some_and(|flight| {
            flight.serial == serial
                && flight.origin == Origin::Operator
                && flight.abort.is_none()
                && !flight.superseded
        }) {
            return;
        }
        let _ = std::fs::remove_file(release);
        let Ok(listener) = tokio::net::UnixListener::bind(release) else {
            return;
        };
        if std::fs::remove_file(arm).is_err() {
            let _ = std::fs::remove_file(release);
            return;
        }
        if std::fs::write(engaged, text_id(&peer)).is_err() {
            let _ = std::fs::remove_file(release);
            return;
        }
        let _ = listener.accept().await;
        let _ = std::fs::remove_file(release);
    }

    /// Delay one exact peer's management updates while room traffic remains available. The
    /// existing run's peer/room reads decide behavior; this marker only establishes the selective
    /// path loss. Every matching ordinary exchange is refused until teardown, including an
    /// outbound response which was already in flight when the arm was written.
    #[cfg(feature = "test-knobs")]
    fn partition_computer_peer_for_proof(&self, peer: Digest32) -> Result<()> {
        let Ok(spec) = std::env::var(TEST_PARTITION_COMPUTER_PEER_ENV) else {
            return Ok(());
        };
        let mut fields = spec.splitn(2, '\t');
        let (Some(arm), Some(marker)) = (fields.next(), fields.next()) else {
            return Ok(());
        };
        let expected = text_id(&peer);
        if std::fs::read_to_string(arm).ok().as_deref().map(str::trim) != Some(expected.as_str()) {
            return Ok(());
        }
        let marker = std::path::Path::new(marker);
        if std::fs::read_to_string(marker).ok().as_deref() != Some(expected.as_str()) {
            if let Err(error) = super::publish_proof_marker(marker, expected.as_bytes()) {
                // Two already-authenticated exchanges may arrive together. Only an identical
                // successful publication by the other one can satisfy this shared boundary.
                if std::fs::read_to_string(marker).ok().as_deref() != Some(expected.as_str()) {
                    super::publish_proof_fault(
                        &marker.with_extension("fault"),
                        &format!("could not mark the exact management-path partition: {error}"),
                    );
                }
            }
        }
        Err(Error::Profile(
            "computer peer path is partitioned by proof apparatus",
        ))
    }

    /// Park an answer only after its policy merge is durable. The marker and socket are staging
    /// apparatus; all verdicts in the journey come from shipped status and trust commands.
    #[cfg(feature = "test-knobs")]
    async fn hold_answer_after_merge_for_proof(&self, peer: Digest32) {
        let Ok(spec) = std::env::var(TEST_HOLD_COMPUTER_ANSWER_AFTER_MERGE_ENV) else {
            return;
        };
        let mut fields = spec.splitn(3, '\t');
        let (Some(arm), Some(engaged), Some(release)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return;
        };
        let _ = std::fs::remove_file(release);
        let Ok(listener) = tokio::net::UnixListener::bind(release) else {
            return;
        };
        if std::fs::remove_file(arm).is_err() {
            let _ = std::fs::remove_file(release);
            return;
        }
        if std::fs::write(engaged, text_id(&peer)).is_err() {
            let _ = std::fs::remove_file(release);
            return;
        }
        let _ = listener.accept().await;
        let _ = std::fs::remove_file(engaged);
        let _ = std::fs::remove_file(release);
    }

    /// Mark the exact event the reserve-to-handle-install proof waits for: the scheduler has
    /// observed a newer policy revision and marked the parked operator flight superseded while it
    /// still has no abort handle.
    #[cfg(feature = "test-knobs")]
    fn mark_operator_superseded_for_proof(&self, peer: Digest32) {
        let Ok(spec) = std::env::var(TEST_HOLD_COMPUTER_OPERATOR_RESERVED_ENV) else {
            return;
        };
        let mut fields = spec.splitn(4, '\t');
        let (Some(_arm), Some(engaged), Some(superseded), Some(_release)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return;
        };
        if std::path::Path::new(engaged).is_file() {
            let _ = std::fs::write(superseded, text_id(&peer));
        }
    }

    /// Record an exchange `peer` started and this node answered, now: what a person reads as
    /// the last exchange answered, with this daemon's revision after the merge (what it sent).
    fn record_answered(
        &self,
        peer: Digest32,
        revision: u64,
        policy_revision: u64,
        involved: bool,
    ) -> Result<()> {
        let _recording = lock(&self.recording);
        let completed = std::time::Instant::now();
        {
            let mut inflight = lock(&self.inflight);
            if let Some(flight) = inflight.get_mut(&peer) {
                // This reply sent a snapshot at least as new on both causal axes as the outbound
                // flight. Cut causal work so it cannot recreate a cleared miss. Let a simultaneous
                // quiet fallback finish, but mark it covered so only its success can be recorded.
                if flight.origin == Origin::Retry
                    && flight.revision <= revision
                    && flight.policy_revision <= policy_revision
                    && !flight.superseded
                {
                    if flight.causal {
                        flight.superseded = true;
                        if let Some(abort) = &flight.abort {
                            abort.abort();
                        }
                    } else {
                        flight.covered = true;
                    }
                }
            }
        }
        let retained_miss = lock(&self.exchanged).get(&peer).is_some_and(|record| {
            record.missed_revision == Some(policy_revision)
                || (record.deadline_policy_revision == Some(policy_revision)
                    && record
                        .deadline
                        .is_some_and(|deadline| completed >= deadline))
        });
        // A policy merge records its obligation in the same transaction. Only a complete reply
        // proves the initiating peer received this state and can clear that durable obligation.
        // If this daemon's own causal clock already expired, retain that historical miss while
        // recording the inbound full exchange as its eventual repair.
        let missed_cause = if retained_miss {
            Some(self.computer.record_missed_exchange(peer, revision, true)?)
        } else {
            self.computer.record_timely_exchange(peer, revision)?;
            None
        };
        let mut exchanged = lock(&self.exchanged);
        let record = exchanged.entry(peer).or_default();
        record.last = Some(completed);
        record.revision = revision;
        record.involved = involved;
        record.failures = 0;
        record.deadline = None;
        record.deadline_policy_revision = None;
        record.problem = None;
        record.missed_revision = missed_cause;
        record.repaired_late = missed_cause;
        record.last_answered = Some(ExchangeRecord {
            at_ms: now(),
            sent_revision: revision,
            merged_revision: revision,
        });
        *lock(&self.problem) = exchanged
            .values()
            .filter(|record| record.failures > 0)
            .find_map(|record| record.problem.clone());
        drop(exchanged);
        let mut ready = lock(&self.retry_ready);
        if ready.get(&peer).is_some_and(|mark| {
            mark.revision <= revision && mark.policy_revision <= policy_revision
        }) {
            ready.remove(&peer);
        }
        drop(ready);
        if let Some((_, waiter)) = lock(&self.reachability_waiters).remove(&peer) {
            waiter.abort();
        }
        Ok(())
    }
}
fn pending_involves(s: &State, local: &Digest32, peer: &Digest32) -> bool {
    s.pending
        .as_ref()
        .filter(|g| {
            g.approvals.iter().any(Option::is_none)
                || (g.group.is_none() && s.genesis.is_none())
                || (g.group.is_some() && !enrolled(s, g))
        })
        .and_then(|g| {
            side(g, local)
                .ok()
                .map(|i| g.computers[1 - i].fingerprint())
        })
        .is_some_and(|id| id.ok().as_ref() == Some(peer))
}
fn side(g: &Enrollment, id: &Digest32) -> Result<usize> {
    g.computers
        .iter()
        .position(|d| d.fingerprint().ok() == Some(*id))
        .ok_or(Error::SignatureInvalid)
}
fn context(invite: &Digest32, transport: &Digest32, g: &Enrollment) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(5)
        .bytes(invite)
        .bytes(&sha256(transport))
        .bytes(&g.body())
        .uint(u64::from(crate::suite::VOX_SUITE_1.id))
        .uint(PROTOCOL);
    [PAIR_DOMAIN, &sha256(&e.finish())].concat()
}
/// Advertise only the work budget left on this process's monotonic causal deadline. An `Instant`
/// is process-local and a Unix timestamp assumes clocks are synchronized, so neither can be a
/// cross-daemon deadline. The initiator continues to enforce `deadline` itself; this budget only
/// prevents the answerer from giving its local merge a fresh full interval. Zero remains reserved
/// for the reachability wake hello, so an already-expired repair advertises the smallest budget.
fn wire_budget(deadline: std::time::Instant) -> u64 {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    u64::try_from(remaining.as_millis())
        .unwrap_or(u64::MAX)
        .max(1)
}

/// Bound remote work on this process's monotonic clock. The sender's remaining duration is capped
/// by the operation's public contract; it is never compared with this host's Unix clock. Network
/// transit still consumes the initiator's original deadline because that process keeps enforcing
/// it while this answer is prepared.
fn local_deadline(remaining_ms: u64, contract: Duration) -> std::time::Instant {
    std::time::Instant::now() + Duration::from_millis(remaining_ms).min(contract)
}

fn hello(op: u64, d: &Description, id: &Digest32, remaining_ms: u64) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(6)
        .uint(PROTOCOL)
        .uint(u64::from(crate::suite::VOX_SUITE_1.id))
        .uint(op)
        .bytes(&d.encode())
        .bytes(id)
        .uint(remaining_ms);
    e.finish()
}
async fn read_hello_until(
    recv: &mut RecvStream,
    conn: &VoxConnection,
    deadline: std::time::Instant,
) -> Result<(u64, Description, Digest32, u64)> {
    let f = frame_until(recv, deadline).await?;
    parse_hello(&f, conn)
}
fn parse_hello(f: &[u8], conn: &VoxConnection) -> Result<(u64, Description, Digest32, u64)> {
    let mut d = Decoder::new(f);
    arity(&mut d, 6)?;
    if d.uint()? != PROTOCOL || d.uint()? != u64::from(conn.session().suite_id) {
        return Err(Error::Profile(
            "computer management protocol or suite is unsupported",
        ));
    }
    let op = d.uint()?;
    let desc = Description::decode(d.bytes()?)?;
    let id = digest(&mut d)?;
    let remaining_ms = d.uint()?;
    d.finish()?;
    if desc.fingerprint()? != conn.peer_id() {
        return Err(Error::SignatureInvalid);
    }
    Ok((op, desc, id, remaining_ms))
}
async fn frame_until(recv: &mut RecvStream, deadline: std::time::Instant) -> Result<Vec<u8>> {
    if std::time::Instant::now() >= deadline {
        return Err(Error::Profile(
            "the computer exchange reached its causal convergence deadline",
        ));
    }
    read_frame_before(recv, MAX_FRAME, deadline)
        .await?
        .ok_or(Error::Profile(
            "computer pairing peer closed before answering",
        ))
}
async fn write_frame_until(
    send: &mut SendStream,
    body: &[u8],
    deadline: std::time::Instant,
) -> Result<()> {
    if std::time::Instant::now() >= deadline {
        return Err(Error::Profile(
            "the computer exchange reached its causal convergence deadline",
        ));
    }
    tokio::time::timeout_at(deadline.into(), write_frame(send, body))
        .await
        .map_err(|_| {
            Error::Profile("the computer exchange reached its causal convergence deadline")
        })??;
    Ok(())
}
fn enrolled(s: &State, g: &Enrollment) -> bool {
    if g.group.is_none() {
        s.genesis
            .as_ref()
            .is_some_and(|v| v.operation() == g.operation())
    } else {
        s.history.values().any(|r| {
            r.event()
                .ok()
                .and_then(|e| e.addition)
                .is_some_and(|a| a.operation() == g.operation())
        })
    }
}
fn activate(s: &mut State, signer: &dyn RootSigner) -> Result<()> {
    let Some(g) = s.pending.clone() else {
        return Ok(());
    };
    if s.cancelled.contains_key(&g.operation()) {
        return Err(Error::Profile(
            "this enrollment attempt was closed locally; its retained intent cannot activate",
        ));
    }
    if g.approvals.iter().any(Option::is_none) {
        return Ok(());
    }
    g.verify(true)?;
    if g.group.is_none() {
        if s.genesis.is_none() {
            s.genesis = Some(g);
            s.fold_history()?;
            s.revision = s.revision.checked_add(1).ok_or_else(bad)?;
            s.policy_revision = s.revision;
            s.receipts.clear();
        }
    } else {
        if !enrolled(s, &g) && signer.fingerprint() == g.computers[0].fingerprint()? {
            let mut body = Encoder::new();
            body.array(1).bytes(&g.encode());
            let event = Control::sign(s, "add", body.finish(), signer)?;
            s.retain_roster(event)?;
        }
        if enrolled(s, &g) && s.genesis.is_none() {
            s.genesis = s.group_genesis.take();
            if s.genesis.is_none() {
                return Err(bad());
            }
            s.fold_history()?;
            s.revision = s.revision.checked_add(1).ok_or_else(bad)?;
            s.policy_revision = s.revision;
            s.receipts.clear();
        }
    }
    Ok(())
}
fn exchange(s: &State, peer: &Digest32) -> Result<Vec<u8>> {
    let group = s
        .group()
        .ok_or(Error::Profile("no computer pairing intent"))?;
    let mut e = Encoder::new();
    e.array(5)
        .bytes(
            &s.genesis
                .as_ref()
                .or(s.group_genesis.as_ref())
                .map(Enrollment::encode)
                .unwrap_or_default(),
        )
        .bytes(
            &s.pending
                .as_ref()
                .map(Enrollment::encode)
                .unwrap_or_default(),
        );
    let current: Vec<_> = s
        .history
        .iter()
        .filter(|(_, r)| r.event().ok().is_some_and(|v| v.group == group))
        .collect();
    e.array(current.len());
    for (id, r) in current {
        e.array(2).bytes(id).bytes(&r.signed.encode());
    }
    e.array(s.receipts.len());
    for (id, r) in &s.receipts {
        e.array(2).bytes(id).bytes(&r.encode());
    }
    if let Some((revision, repaired)) = s
        .missed_exchanges
        .get(peer)
        .filter(|(revision, _)| *revision == s.policy_revision)
    {
        e.array(1)
            .array(3)
            .uint(*revision)
            .uint(u64::from(*repaired))
            .bytes(&policy_frontier(s)?);
    } else {
        e.array(0);
    }
    Ok(e.finish())
}
fn merge(s: &mut State, bytes: &[u8], peer: Digest32, signer: &dyn RootSigner) -> Result<()> {
    let mut d = Decoder::new(bytes);
    arity(&mut d, 5)?;
    let read = |bytes: &[u8]| -> Result<Option<Enrollment>> {
        if bytes.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Enrollment::decode(bytes)?))
        }
    };
    let genesis = read(d.bytes()?)?;
    let incoming = read(d.bytes()?)?;
    if genesis
        .iter()
        .chain(incoming.iter())
        .any(|g| s.retired_groups.contains_key(&g.incarnation()))
    {
        return Err(Error::Profile(
            "this group was retired locally; old signed state cannot reactivate it",
        ));
    }
    // A fresh invitation has no current intent to compare with. Recognize an exact retired
    // operation before the group/current-intent checks so its late result keeps the truthful
    // local-close outcome instead of turning into an unexplained authentication refusal.
    if genesis
        .iter()
        .chain(incoming.iter())
        .any(|g| s.cancelled.contains_key(&g.operation()))
    {
        return Err(Error::Profile(
            "this enrollment attempt was closed locally; its retained intent cannot activate",
        ));
    }
    let local = s.description.fingerprint()?;
    let candidate = s.pending.as_ref().is_some_and(|p| side(p, &peer).is_ok());
    // Former managers may carry retained negative/fork evidence and receive their removal.
    // This grants no positive authority: every event is independently checked at its prefix.
    let previously_enrolled = s.was_enrolled(&peer);
    if let Some(g) = genesis {
        g.verify(true)?;
        if g.group.is_some() || Some(g.incarnation()) != s.group() {
            return Err(Error::SignatureInvalid);
        }
        if let Some(current) = &s.genesis {
            if current != &g {
                return Err(Error::SignatureInvalid);
            }
        } else if s
            .pending
            .as_ref()
            .is_some_and(|p| p.group == Some(g.incarnation()))
        {
            s.group_genesis = Some(g);
        }
    }
    if let (Some(current), Some(incoming)) = (s.pending.clone(), incoming) {
        if incoming.operation() == current.operation() {
            if s.cancelled.contains_key(&incoming.operation()) {
                return Err(Error::Profile("this enrollment attempt was closed locally"));
            }
            let at = side(&current, &peer)?;
            let here = side(&current, &local)?;
            let mut g = current;
            if let Some(a) = &incoming.approvals[at] {
                if g.approvals[at].is_none() && g.expires <= now() {
                    return Err(Error::Profile("computer pairing expired before approval arrived; no new trust was established"));
                }
                g.approvals[at] = Some(a.clone());
            }
            if incoming.approvals[here].is_some() && incoming.approvals[here] != g.approvals[here] {
                return Err(Error::SignatureInvalid);
            }
            g.verify(false)?;
            s.pending = Some(g);
        }
    }
    // Union first, then fold once: wire order is not causal order.
    let group = s.group().ok_or_else(bad)?;
    let previous_len = s.history.len();
    let previous_revision = s.revision;
    for _ in 0..count(&mut d)? {
        arity(&mut d, 2)?;
        let id = digest(&mut d)?;
        let r = Control {
            signed: Signed::decode(d.bytes()?)?,
        };
        if id != r.id() {
            return Err(bad());
        }
        r.verify(&group)?;
        if !s.history.contains_key(&id) && s.history.len() >= MAX_RECORDS {
            return Err(Error::Profile(if previously_enrolled {
                HISTORY_FULL
            } else {
                "incoming computer history exceeds admission limit"
            }));
        }
        s.history.insert(id, r);
    }
    s.fold_history()?;
    if s.history.len() != previous_len && s.revision == previous_revision {
        s.revision = s.revision.checked_add(1).ok_or_else(bad)?;
        s.receipts.clear();
    }
    if s.grant(&peer).is_none() && !candidate && !previously_enrolled {
        return Err(Error::SignatureInvalid);
    }
    // An unrelated active member may carry another member's signed receipt verbatim.
    let mut receipts = Vec::new();
    for _ in 0..count(&mut d)? {
        arity(&mut d, 2)?;
        receipts.push((digest(&mut d)?, Signed::decode(d.bytes()?)?));
    }
    let missed = match count(&mut d)? {
        0 => None,
        1 => {
            arity(&mut d, 3)?;
            let revision = d.uint()?;
            let repaired = match d.uint()? {
                0 => false,
                1 => true,
                _ => return Err(bad()),
            };
            Some((revision, repaired, digest(&mut d)?))
        }
        _ => return Err(bad()),
    };
    d.finish()?;
    activate(s, signer)?;
    if let Some((_sender_revision, _repaired, sender_frontier)) = missed {
        // Revision numbers are local journal order. Only an identical canonical policy frontier
        // can translate the peer's marker onto this daemon's current local revision. A receiver
        // with independent newer policy therefore cannot have that policy poisoned by an older
        // remote miss.
        if sender_frontier == policy_frontier(s)? {
            // The complete authenticated exchange being merged now is the repair. The marker
            // says only that the sender did not complete its original cause on time; making its
            // pre-exchange `repaired` bit an authorization gate required a second exchange which
            // the repaired sender deliberately suppresses, leaving this receiver revoked for
            // good. Preserve lateness in the sender's durable status, and clear any expiry an
            // earlier FX-28 development build persisted for this matching peer/frontier.
            s.received_misses.remove(&peer);
        }
    }
    for (author, receipt) in receipts {
        if author != local && valid_receipt(s, &author, &receipt)? {
            s.receipts.insert(author, receipt);
        }
    }
    // Receiving the retained genesis is not enrollment: require the local operator's exact ADD.
    if let Some(p) = &s.pending {
        if p.group.is_some() && p.approvals[side(p, &local)?].is_none() && s.grant(&local).is_some()
        {
            return Err(Error::SignatureInvalid);
        }
    }
    Ok(())
}

/// Stable identity of operator-policy content shared by paired computers. Receipts, reachability
/// records and operational convergence markers are deliberately excluded: they are observations
/// about this policy, not replacements for it. Local revision numbers are excluded because they
/// are not distributed clocks.
fn policy_frontier(s: &State) -> Result<Digest32> {
    let group = s.group().ok_or_else(bad)?;
    let mut e = Encoder::new();
    e.array(3)
        .bytes(
            &s.genesis
                .as_ref()
                .or(s.group_genesis.as_ref())
                .map(Enrollment::encode)
                .unwrap_or_default(),
        )
        .bytes(
            &s.pending
                .as_ref()
                .map(Enrollment::encode)
                .unwrap_or_default(),
        );
    let current: Vec<_> = s
        .history
        .iter()
        .filter(|(_, record)| {
            record
                .event()
                .ok()
                .is_some_and(|event| event.group == group && event.reach.is_none())
        })
        .collect();
    e.array(current.len());
    for (id, record) in current {
        e.array(2).bytes(id).bytes(&record.signed.encode());
    }
    Ok(sha256(&e.finish()))
}

fn receipt_body(s: &State, revision: u64) -> Result<Vec<u8>> {
    let g = s
        .genesis
        .as_ref()
        .ok_or(Error::Profile("computer enrollment is not established"))?;
    let mut e = Encoder::new();
    e.array(7)
        .uint(PROTOCOL)
        .bytes(&g.incarnation())
        .bytes(&sha256(&g.encode()))
        .array(s.rosters.len());
    for (id, r) in &s.rosters {
        e.array(2).bytes(id).bytes(&sha256(&r.signed.encode()));
    }
    let heads = s.heads();
    e.array(heads.len());
    for h in heads {
        e.bytes(&h);
    }
    e.uint(revision).array(0);
    Ok(e.finish())
}
fn valid_receipt(s: &State, author: &Digest32, r: &Signed) -> Result<bool> {
    r.verify(b"vox/computer-applied/v1\0", author)?;
    if !s.history_complete() || !s.quarantined.is_empty() {
        return Ok(false);
    }
    let Some(g) = s.genesis.as_ref() else {
        return Ok(false);
    };
    if s.grant(author).is_none() {
        return Ok(false);
    }
    let mut d = Decoder::new(&r.body);
    arity(&mut d, 7)?;
    if d.uint()? != PROTOCOL
        || digest(&mut d)? != g.incarnation()
        || digest(&mut d)? != sha256(&g.encode())
    {
        return Ok(false);
    }
    let n = count(&mut d)?;
    if n != s.rosters.len() || n != s.descriptions().len() {
        return Ok(false);
    }
    for (id, roster) in &s.rosters {
        arity(&mut d, 2)?;
        if digest(&mut d)? != *id || digest(&mut d)? != sha256(&roster.signed.encode()) {
            return Ok(false);
        }
    }
    let heads = s.heads();
    if count(&mut d)? != heads.len() {
        return Ok(false);
    }
    for head in heads {
        if digest(&mut d)? != head {
            return Ok(false);
        }
    }
    let revision = d.uint()?;
    if revision == 0 {
        return Err(bad());
    }
    if d.array()? != 0 {
        return Ok(false);
    }
    d.finish()?;
    Ok(true)
}

fn frontier(s: &State) -> String {
    let mut e = Encoder::new();
    e.array(2)
        .bytes(&s.group().unwrap_or([0; 32]))
        .array(s.heads().len());
    for head in s.heads() {
        e.bytes(&head);
    }
    text_id(&sha256(&e.finish()))
}
