//! **The identity exchange** (ADR-011 requirements 27–40, 38a; ADR-026 §6): which node a
//! connection is to, proved inside the connection after a neutral TLS handshake.
//!
//! One daemon's endpoint serves every node it hosts, so the TLS handshake cannot say which node a
//! dialler wants without showing it on the path (SNI and ALPN are readable by any observer, a QUIC
//! connection id is the client's random choice). The handshake therefore authenticates only the
//! daemon — a neutral leaf ([`crate::transport::identity_cert::build_neutral_leaf`]) — and the
//! node is proved here, bound to the TLS session by its exporter, in three flights on the first
//! client-opened bidirectional stream, typed [`StreamKind::Identity`]:
//!
//! 1. dialler → `ASK { target_fp }`;
//! 2. listener → `PROVE { target_pubkey, instance_t, sig_target(RESP ‖ E ‖ target_fp ‖ instance_t) }`,
//!    or the refusal: the connection closed with [`REFUSAL`], no reason, no flight;
//! 3. dialler, only once flight 2 verified against the node it pinned →
//!    `CLAIM { dialler_pubkey, instance_d, sig_dialler(INIT ‖ E ‖ target_fp ‖ dialler_fp ‖ instance_d) }`.
//!
//! `E` is the TLS exporter ([`EXPORTER_LABEL`], 64 bytes), so a flight signed on one connection
//! verifies on no other; the direction labels ([`RESP_LABEL`], [`INIT_LABEL`]) keep a flight from
//! verifying in the other role. The responder proves first: a dialler shows who it is only to a
//! party that has just proved, on this very TLS session, to be the node the dialler pinned.
//!
//! **Each flight** is one canonical CBOR array in one length-prefixed frame
//! ([`crate::transport::framing`]): `[tag, 2, …]` with the tags `0x001C`–`0x001E` of
//! [`crate::wire::StructTag`]. A frame over [`MAX_FLIGHT`] is not read past its length and is
//! refused as malformed.
//!
//! **The listener's order** is the cost discipline of requirement 34: the per-source rate limit
//! ([`AskLimiter`]) runs before the target is looked up, and a node's long-term key signs only
//! after both admitted the `ASK`. Every outcome of an `ASK` — a `PROVE` or the refusal — leaves no
//! earlier than [`ANSWER_FLOOR`] plus a uniformly random 0–[`ANSWER_JITTER`] after the `ASK`
//! arrived, so a refusal is not told from a `PROVE` by the time an ML-DSA signature takes. Until
//! the `PROVE` is sent a datagram closes the connection; a second flight, a malformed one, or an
//! exchange not done within [`EXCHANGE_TIMEOUT`] closes it too. QUIC's own limits hold the
//! connection to the exchange meanwhile (see `quic::pre_identity_transport_config`), and
//! [`open_post_identity`] raises them once `CLAIM` verified.
//!
//! This module is pure: it runs the exchange on a [`quinn::Connection`] it is handed and returns
//! who was proved. Wiring it into `connect` / `finish_incoming`, the accept gate's cap and the
//! session record is the shared endpoint's work.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use quinn::{Connection, RecvStream};
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{Digest32, COMPOSITE_PUB_LEN, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::transport::framing::{read_frame_within, write_frame};
use crate::transport::quic::{close_code, CONNECTION_WINDOW, MAX_CONCURRENT_BIDI_STREAMS};
use crate::transport::streams::StreamKind;
use crate::wire::{StructTag, WireError};

/// The TLS exporter label `E` is read under (ADR-011 requirement 30).
pub const EXPORTER_LABEL: &[u8] = b"vox/identity/v2";
/// How many bytes of exporter output `E` is.
pub const EXPORTER_LEN: usize = 64;
/// The label the **listener** signs `PROVE` under (ADR-011 requirement 31).
pub const RESP_LABEL: &[u8] = b"vox-id/v2/resp";
/// The label the **dialler** signs `CLAIM` under (ADR-011 requirement 31).
pub const INIT_LABEL: &[u8] = b"vox-id/v2/init";
/// The version every flight carries.
pub const VERSION: u64 = 2;
/// The largest flight read; a longer one is refused as malformed without being read.
pub const MAX_FLIGHT: usize = 16 * 1024;
/// The whole exchange, from the listener's first look at the connection to `CLAIM` verified, or
/// from the dialler's `ASK` to `PROVE` checked and `CLAIM` sent (ADR-011 requirements 33, 34).
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
/// The earliest any outcome of an `ASK` leaves the listener, after the `ASK` arrived
/// (ADR-011 requirement 32)…
pub const ANSWER_FLOOR: Duration = Duration::from_millis(50);
/// …plus a uniformly random delay up to this.
pub const ANSWER_JITTER: Duration = Duration::from_millis(50);
/// `ASK`s per second each source may make (ADR-011 requirement 34).
pub const ASKS_PER_SECOND: u32 = 8;
/// How many `ASK`s a source may make at once before its rate applies.
pub const ASK_BURST: u32 = 16;
/// Client-opened bidirectional streams a connection may hold before `CLAIM` verified: the
/// identity stream and one more, so flight 3 may carry the dialler's first application bytes.
pub const PRE_IDENTITY_BIDI: u32 = 2;
/// Unidirectional streams before `CLAIM` verified. Vox opens none anywhere.
pub const PRE_IDENTITY_UNI: u32 = 0;
/// The connection receive window before `CLAIM` verified.
pub const PRE_IDENTITY_WINDOW: u32 = 64 * 1024;
/// The one refusal: the connection closed with this code, no reason text, no flight.
pub const REFUSAL: WireError = WireError::NotAvailable;
/// What a dialler closes with when the `PROVE` it got does not verify.
pub const BAD_PROVE: WireError = WireError::AuthenticatorInvalid;

/// A node's per-attach value, signed in its flight (ADR-026 I-3): drawn anew each time the node
/// attaches, so a node that re-attaches is a new remote process to its peers.
pub type Instance = [u8; 16];

/// A fresh [`Instance`] from the OS CSPRNG.
///
/// # Errors
/// [`Error::SigningFailed`] if the CSPRNG is unavailable.
pub fn new_instance() -> Result<Instance> {
    let mut i = [0u8; 16];
    getrandom::fill(&mut i).map_err(|_| Error::SigningFailed)?;
    Ok(i)
}

// ---------------------------------------------------------------------------
// Flights.
// ---------------------------------------------------------------------------

/// Flight 1: the dialler names the node it wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ask {
    /// The fingerprint of the node asked for.
    pub target: Digest32,
}

/// Flight 2: the named node proves it holds its key, on this TLS session.
#[derive(Clone)]
pub struct Prove {
    /// The node's composite public key; its fingerprint must be the one asked for.
    pub target: CompositePublicKey,
    /// The node's per-attach instance.
    pub instance: Instance,
    /// `sig_target(RESP_LABEL ‖ E ‖ target_fp ‖ instance)`.
    pub sig: CompositeSignature,
}

/// Flight 3: the dialler proves who it is, on this TLS session, to the node it asked for.
#[derive(Clone)]
pub struct Claim {
    /// The dialler's composite public key.
    pub dialler: CompositePublicKey,
    /// The dialler's per-attach instance.
    pub instance: Instance,
    /// `sig_dialler(INIT_LABEL ‖ E ‖ target_fp ‖ dialler_fp ‖ instance)`.
    pub sig: CompositeSignature,
}

fn malformed(why: &'static str) -> Error {
    Error::MalformedBundle(why)
}

/// Read `[tag, version, …]`'s head and require `tag` and [`VERSION`]; the caller reads the rest.
fn head<'a>(bytes: &'a [u8], tag: StructTag, arity: usize) -> Result<Decoder<'a>> {
    let mut d = Decoder::new(bytes);
    if d.array()? != arity {
        return Err(malformed("identity flight arity"));
    }
    if d.uint()? != u64::from(tag.as_u16()) {
        return Err(malformed("identity flight tag"));
    }
    if d.uint()? != VERSION {
        return Err(malformed("identity flight version"));
    }
    Ok(d)
}

fn key_and_sig(d: &mut Decoder<'_>) -> Result<(CompositePublicKey, Instance, CompositeSignature)> {
    let key: &[u8; COMPOSITE_PUB_LEN] = d
        .bytes()?
        .try_into()
        .map_err(|_| malformed("identity flight key length"))?;
    let instance: Instance = d
        .bytes()?
        .try_into()
        .map_err(|_| malformed("identity flight instance length"))?;
    let sig: &[u8; COMPOSITE_SIG_LEN] = d
        .bytes()?
        .try_into()
        .map_err(|_| malformed("identity flight signature length"))?;
    Ok((
        CompositePublicKey::from_bytes(key)?,
        instance,
        CompositeSignature::from_bytes(sig)?,
    ))
}

impl Ask {
    /// The canonical flight `[0x001C, 2, target_fp]`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(3)
            .uint(u64::from(StructTag::IdentityAsk.as_u16()))
            .uint(VERSION)
            .bytes(&self.target);
        e.finish()
    }

    /// Parse a flight 1, strictly.
    ///
    /// # Errors
    /// Anything but the exact canonical shape.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut d = head(bytes, StructTag::IdentityAsk, 3)?;
        let target: Digest32 = d
            .bytes()?
            .try_into()
            .map_err(|_| malformed("identity ASK target length"))?;
        d.finish()?;
        Ok(Self { target })
    }
}

impl Prove {
    /// The canonical flight `[0x001D, 2, target_pubkey, instance, sig]`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode_signed(
            StructTag::IdentityProve,
            &self.target,
            &self.instance,
            &self.sig,
        )
    }

    /// Parse a flight 2, strictly. Does not verify the signature.
    ///
    /// # Errors
    /// Anything but the exact canonical shape, or a key or signature that does not decode.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut d = head(bytes, StructTag::IdentityProve, 5)?;
        let (target, instance, sig) = key_and_sig(&mut d)?;
        d.finish()?;
        Ok(Self {
            target,
            instance,
            sig,
        })
    }
}

impl Claim {
    /// The canonical flight `[0x001E, 2, dialler_pubkey, instance, sig]`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode_signed(
            StructTag::IdentityClaim,
            &self.dialler,
            &self.instance,
            &self.sig,
        )
    }

    /// Parse a flight 3, strictly. Does not verify the signature.
    ///
    /// # Errors
    /// Anything but the exact canonical shape, or a key or signature that does not decode.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut d = head(bytes, StructTag::IdentityClaim, 5)?;
        let (dialler, instance, sig) = key_and_sig(&mut d)?;
        d.finish()?;
        Ok(Self {
            dialler,
            instance,
            sig,
        })
    }
}

fn encode_signed(
    tag: StructTag,
    key: &CompositePublicKey,
    instance: &Instance,
    sig: &CompositeSignature,
) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(5)
        .uint(u64::from(tag.as_u16()))
        .uint(VERSION)
        .bytes(&key.to_bytes())
        .bytes(instance)
        .bytes(&sig.to_bytes());
    e.finish()
}

/// What the listener's node signs: `RESP_LABEL ‖ E ‖ target_fp ‖ instance_t`.
#[must_use]
pub fn resp_input(e: &[u8; EXPORTER_LEN], target: &Digest32, instance: &Instance) -> Vec<u8> {
    [RESP_LABEL, e.as_slice(), target, instance].concat()
}

/// What the dialler's node signs: `INIT_LABEL ‖ E ‖ target_fp ‖ dialler_fp ‖ instance_d`.
#[must_use]
pub fn init_input(
    e: &[u8; EXPORTER_LEN],
    target: &Digest32,
    dialler: &Digest32,
    instance: &Instance,
) -> Vec<u8> {
    [INIT_LABEL, e.as_slice(), target, dialler, instance].concat()
}

/// `E`: this connection's TLS exporter under [`EXPORTER_LABEL`], 64 bytes, empty context.
///
/// Mandatory (ADR-011 requirement 30): an error here refuses the connection. There is no
/// fallback, unlike the connection tie-break's.
///
/// # Errors
/// [`Error::SignatureInvalid`] if the TLS session cannot export.
pub fn exporter(c: &Connection) -> Result<Zeroizing<[u8; EXPORTER_LEN]>> {
    let mut out = Zeroizing::new([0u8; EXPORTER_LEN]);
    c.export_keying_material(out.as_mut_slice(), EXPORTER_LABEL, b"")
        .map_err(|_| Error::SignatureInvalid)?;
    Ok(out)
}

/// The exporter a side of the exchange reads `E` with: [`exporter`] in the product; a stand-in
/// that fails, in the proof that a failing exporter refuses.
pub(crate) type Exporter = dyn Fn(&Connection) -> Result<Zeroizing<[u8; EXPORTER_LEN]>> + Sync;

/// Raise a connection's limits from the pre-identity values to the normal ones (ADR-011
/// requirement 33): call once the exchange is done. The listener does it after `CLAIM` verified
/// ([`listen`] does it itself); the dialler after `PROVE` verified ([`dial`] does too).
///
/// Unidirectional streams stay at [`PRE_IDENTITY_UNI`] (zero): Vox opens none.
pub fn open_post_identity(c: &Connection) {
    c.set_max_concurrent_bi_streams(quinn::VarInt::from_u32(MAX_CONCURRENT_BIDI_STREAMS));
    c.set_receive_window(quinn::VarInt::from_u32(CONNECTION_WINDOW));
}

// ---------------------------------------------------------------------------
// Who answers: the listener's view of the nodes it hosts.
// ---------------------------------------------------------------------------

/// A node the listener answers for: its fingerprint, its per-attach instance and its signer.
#[derive(Clone)]
pub struct Hosted {
    /// The node's fingerprint.
    pub id: Digest32,
    /// The node's per-attach instance (ADR-026 I-3).
    pub instance: Instance,
    /// The node's long-term key, which signs one `PROVE` per accepted connection.
    pub signer: Arc<dyn RootSigner + Send + Sync>,
}

impl std::fmt::Debug for Hosted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hosted")
            .field("id", &crate::hash::Hex(&self.id))
            .finish_non_exhaustive()
    }
}

/// The nodes a listener answers for. A detached node is simply not hosted: its signer is
/// unregistered before its keys are wiped (ADR-011 requirement 34, ADR-026 L-3), and it gets the
/// same refusal as a node that was never here.
pub trait Hosts: Send + Sync {
    /// The node `target` names, if it is attached here now.
    fn host(&self, target: &Digest32) -> Option<Hosted>;
}

/// What the exchange proved about the other end.
#[derive(Clone)]
pub struct Proven {
    /// The other node's fingerprint.
    pub peer: Digest32,
    /// The other node's composite public key.
    pub peer_key: CompositePublicKey,
    /// The other node's per-attach instance: its remote-process identity is
    /// `sha256(its daemon leaf ‖ instance)` (ADR-011 requirement 35).
    pub instance: Instance,
}

impl std::fmt::Debug for Proven {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proven")
            .field("peer", &crate::hash::Hex(&self.peer))
            .field("instance", &crate::hash::Hex(&self.instance))
            .finish_non_exhaustive()
    }
}

/// The remote-process identity of a proved peer: `sha256(remote daemon leaf ‖ instance)`
/// (ADR-011 requirement 35, ADR-026 I-3). `leaf` is the DER of the leaf the peer's daemon
/// presented in the TLS handshake.
#[must_use]
pub fn remote_process(leaf: &[u8], instance: &Instance) -> Digest32 {
    crate::hash::sha256_concat(&[leaf, instance])
}

// ---------------------------------------------------------------------------
// The per-source rate limit (ADR-011 requirement 34).
// ---------------------------------------------------------------------------

/// Where an `ASK` came from, for the rate limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKey {
    /// A direct path: the source IP address (an IPv4-mapped IPv6 address counts as its IPv4).
    Ip(IpAddr),
    /// A relay circuit: the relay carrying it, whose address this end never sees.
    Circuit(Digest32),
}

impl SourceKey {
    /// The key for a direct path from `addr`.
    #[must_use]
    pub fn of_addr(addr: SocketAddr) -> Self {
        Self::Ip(addr.ip().to_canonical())
    }
}

/// How many sources the limiter tracks before it forgets the ones back at a full burst, which
/// it can do without changing any answer.
const TRACKED_SOURCES: usize = 4096;

/// A token bucket per source: [`ASKS_PER_SECOND`] with a burst of [`ASK_BURST`]. An `ASK` over
/// the limit gets the refusal (ADR-011 requirements 32, 34). It knows nothing of targets, so
/// whether it is exhausted says nothing about who is hosted.
pub struct AskLimiter {
    per_second: f64,
    burst: f64,
    buckets: Mutex<HashMap<SourceKey, (f64, Instant)>>,
}

impl AskLimiter {
    /// A limiter of `per_second` `ASK`s per source, with a burst of `burst`.
    #[must_use]
    pub fn new(per_second: u32, burst: u32) -> Self {
        Self {
            per_second: f64::from(per_second),
            burst: f64::from(burst),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// The limiter ADR-011 requirement 34 names: 8 per second, burst 16.
    #[must_use]
    pub fn standard() -> Self {
        Self::new(ASKS_PER_SECOND, ASK_BURST)
    }

    /// Take one `ASK` from `source`, or say it is over its limit.
    pub fn admit(&self, source: SourceKey) -> bool {
        let now = Instant::now();
        let mut b = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        if b.len() >= TRACKED_SOURCES && !b.contains_key(&source) {
            let (rate, burst) = (self.per_second, self.burst);
            b.retain(|_, (tokens, at)| {
                *tokens + now.duration_since(*at).as_secs_f64() * rate < burst
            });
        }
        let (tokens, at) = b.entry(source).or_insert((self.burst, now));
        *tokens =
            (*tokens + now.duration_since(*at).as_secs_f64() * self.per_second).min(self.burst);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// The listener.
// ---------------------------------------------------------------------------

/// Why a listener refused a connection. **For this end only**: on the wire every one of them is
/// the same close ([`REFUSAL`], no reason, no flight), at the same time after the `ASK`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// No node by the name asked for is attached here (never was, or detached).
    Unknown,
    /// A flight was malformed or oversize, the identity stream was not the first, or a second
    /// flight followed `CLAIM`.
    Malformed(&'static str),
    /// The source was over its rate limit.
    RateLimited,
    /// A relay circuit asked for a node other than the one that circuit belongs to.
    NotTheCircuitsNode,
    /// The TLS exporter could not be read.
    Exporter,
    /// The asked-for node's key would not sign.
    Signing,
    /// `CLAIM` did not verify: wrong signature, another connection's, or a reflected `PROVE`.
    BadClaim,
    /// A datagram arrived before `PROVE` was sent.
    Datagram,
    /// The exchange did not finish within [`EXCHANGE_TIMEOUT`].
    TimedOut,
    /// The connection closed during the exchange.
    Closed,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "the node asked for is not attached here"),
            Self::Malformed(why) => write!(f, "a malformed identity flight ({why})"),
            Self::RateLimited => write!(f, "the source is over its rate limit"),
            Self::NotTheCircuitsNode => write!(f, "a circuit asked for a node it does not lead to"),
            Self::Exporter => write!(f, "the TLS exporter could not be read"),
            Self::Signing => write!(f, "the node's key would not sign"),
            Self::BadClaim => write!(f, "the dialler's CLAIM did not verify"),
            Self::Datagram => write!(f, "a datagram arrived before PROVE"),
            Self::TimedOut => write!(
                f,
                "the identity exchange did not finish within {}s",
                EXCHANGE_TIMEOUT.as_secs()
            ),
            Self::Closed => write!(f, "the connection closed during the identity exchange"),
        }
    }
}

/// Close `c` with the one refusal: [`REFUSAL`], no reason text.
pub fn refuse(c: &Connection) {
    c.close(close_code(REFUSAL), b"");
}

/// **The listener's side** of the exchange on a connection that has just finished its neutral
/// handshake: read the `ASK`, answer for a hosted node or refuse, verify the `CLAIM`.
///
/// - `source` keys the rate limit: [`SourceKey::of_addr`] of the remote address, or
///   [`SourceKey::Circuit`] of the relay for a circuit.
/// - `circuit_owner` is the local node a relay circuit belongs to, if the connection runs over
///   one: an `ASK` for any other node is refused.
///
/// On success the connection's limits are raised ([`open_post_identity`]) and the caller gets the
/// node asked for and who dialled it. On any failure the connection is already closed with the
/// refusal; the [`Refused`] is for this end's own log.
///
/// # Errors
/// [`Refused`], as above.
pub async fn listen(
    conn: &Connection,
    source: SourceKey,
    circuit_owner: Option<Digest32>,
    hosts: &dyn Hosts,
    limiter: &AskLimiter,
) -> std::result::Result<(Hosted, Proven), Refused> {
    listen_with(conn, source, circuit_owner, hosts, limiter, &exporter).await
}

pub(crate) async fn listen_with(
    conn: &Connection,
    source: SourceKey,
    circuit_owner: Option<Digest32>,
    hosts: &dyn Hosts,
    limiter: &AskLimiter,
    export: &Exporter,
) -> std::result::Result<(Hosted, Proven), Refused> {
    let deadline = Instant::now() + EXCHANGE_TIMEOUT;
    let outcome = tokio::time::timeout_at(
        deadline,
        listener_exchange(
            conn,
            source,
            circuit_owner,
            hosts,
            limiter,
            export,
            deadline,
        ),
    )
    .await
    .unwrap_or(Err(Refused::TimedOut));
    match outcome {
        Ok(done) => {
            open_post_identity(conn);
            Ok(done)
        }
        Err(why) => {
            refuse(conn);
            Err(why)
        }
    }
}

/// When the answer to an `ASK` that arrived at `asked` may leave: the floor plus a uniform draw
/// from the jitter. A CSPRNG failure takes the whole window, never less.
fn answer_at(asked: Instant) -> Instant {
    let mut b = [0u8; 4];
    let jitter_us = u64::try_from(ANSWER_JITTER.as_micros()).unwrap_or(u64::MAX);
    let draw = match getrandom::fill(&mut b) {
        Ok(()) => u64::from(u32::from_be_bytes(b)) % (jitter_us + 1),
        Err(_) => jitter_us,
    };
    asked + ANSWER_FLOOR + Duration::from_micros(draw)
}

/// What the listener does with an `ASK`: answer with this `PROVE` for this node, or refuse.
type Answer = std::result::Result<(Vec<u8>, Hosted, Zeroizing<[u8; EXPORTER_LEN]>), Refused>;

async fn listener_exchange(
    conn: &Connection,
    source: SourceKey,
    circuit_owner: Option<Digest32>,
    hosts: &dyn Hosts,
    limiter: &AskLimiter,
    export: &Exporter,
    deadline: Instant,
) -> std::result::Result<(Hosted, Proven), Refused> {
    // Until PROVE is sent, a datagram closes the connection (ADR-011 requirement 33). The race
    // covers the wait for the answer floor too: PROVE has not left until it has.
    let before_prove = async {
        let (send, mut recv) = conn.accept_bi().await.map_err(|_| Refused::Closed)?;
        // The first client-opened bidirectional stream, and nothing else.
        if recv.id().index() != 0 {
            return Err(Refused::Malformed("the identity stream was not the first"));
        }
        let (asked, answer) = ask(
            conn,
            &mut recv,
            source,
            circuit_owner,
            hosts,
            limiter,
            export,
            deadline,
        )
        .await?;
        tokio::time::sleep_until(answer_at(asked)).await;
        let (prove, hosted, e) = answer?;
        Ok((send, recv, prove, hosted, e))
    };
    let (mut send, mut recv, prove, hosted, e) = tokio::select! {
        biased;
        r = before_prove => r?,
        d = conn.read_datagram() => {
            return Err(if d.is_ok() { Refused::Datagram } else { Refused::Closed });
        }
    };
    write_frame(&mut send, &prove)
        .await
        .map_err(|_| Refused::Closed)?;

    // Flight 3, then the end of the stream: a second flight is a second exchange.
    let claim = flight(&mut recv, deadline).await?;
    if flight_or_end(&mut recv, deadline).await?.is_some() {
        return Err(Refused::Malformed("a second flight after CLAIM"));
    }
    let claim = Claim::decode(&claim).map_err(|_| Refused::Malformed("CLAIM"))?;
    let dialler = claim.dialler.fingerprint();
    claim
        .dialler
        .verify(
            &init_input(&e, &hosted.id, &dialler, &claim.instance),
            &claim.sig,
        )
        .map_err(|_| Refused::BadClaim)?;
    let _ = send.finish();
    let proven = Proven {
        peer: dialler,
        peer_key: claim.dialler,
        instance: claim.instance,
    };
    Ok((hosted, proven))
}

/// Read the identity stream's kind and `ASK`, and decide the answer. Returns when the `ASK`
/// arrived — every answer is timed from then — and the answer.
#[allow(clippy::too_many_arguments)]
async fn ask(
    conn: &Connection,
    recv: &mut RecvStream,
    source: SourceKey,
    circuit_owner: Option<Digest32>,
    hosts: &dyn Hosts,
    limiter: &AskLimiter,
    export: &Exporter,
    deadline: Instant,
) -> std::result::Result<(Instant, Answer), Refused> {
    let kind = flight(recv, deadline).await?;
    if StreamKind::parse(&kind).ok() != Some(StreamKind::Identity) {
        return Ok((Instant::now(), Err(Refused::Malformed("stream kind"))));
    }
    let ask = flight(recv, deadline).await;
    let asked = Instant::now();
    let ask = match ask {
        Ok(a) => a,
        Err(Refused::Malformed(why)) => return Ok((asked, Err(Refused::Malformed(why)))),
        Err(other) => return Err(other),
    };
    // The rate limit first, before anything about the target is looked at (requirement 34).
    if !limiter.admit(source) {
        return Ok((asked, Err(Refused::RateLimited)));
    }
    let Ok(Ask { target }) = Ask::decode(&ask) else {
        return Ok((asked, Err(Refused::Malformed("ASK"))));
    };
    let Some(hosted) = hosts.host(&target) else {
        return Ok((asked, Err(Refused::Unknown)));
    };
    if circuit_owner.is_some_and(|owner| owner != target) {
        return Ok((asked, Err(Refused::NotTheCircuitsNode)));
    }
    let Ok(e) = export(conn) else {
        return Ok((asked, Err(Refused::Exporter)));
    };
    let Ok(sig) = hosted
        .signer
        .sign(&resp_input(&e, &target, &hosted.instance))
    else {
        return Ok((asked, Err(Refused::Signing)));
    };
    let prove = Prove {
        target: hosted.signer.public_key(),
        instance: hosted.instance,
        sig,
    }
    .encode();
    Ok((asked, Ok((prove, hosted, e))))
}

/// One flight, before `deadline`. The end of the stream, a reset or a closed connection is
/// [`Refused::Closed`]; an oversize frame is malformed and is not read past its length.
async fn flight(recv: &mut RecvStream, deadline: Instant) -> std::result::Result<Vec<u8>, Refused> {
    flight_or_end(recv, deadline)
        .await?
        .ok_or(Refused::Malformed("the stream ended before its flight"))
}

async fn flight_or_end(
    recv: &mut RecvStream,
    deadline: Instant,
) -> std::result::Result<Option<Vec<u8>>, Refused> {
    let patience = deadline.saturating_duration_since(Instant::now());
    match read_frame_within(recv, MAX_FLIGHT, patience).await {
        Ok(f) => Ok(f),
        Err(Error::SizeLimitExceeded(_)) => Err(Refused::Malformed("an oversize flight")),
        Err(_) => Err(Refused::Closed),
    }
}

// ---------------------------------------------------------------------------
// The dialler.
// ---------------------------------------------------------------------------

/// Why a dial's exchange failed, for this end. Only [`DialFailed::NotAnswered`] and
/// [`DialFailed::BadProve`] are about the other end, and neither names anyone (ADR-011 38a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialFailed {
    /// The listener refused: the node is not attached there (or will not say more).
    NotAnswered,
    /// Something answered, but its `PROVE` did not verify against the node pinned. No `CLAIM`
    /// was sent, and the connection is closed with [`BAD_PROVE`].
    BadProve(&'static str),
    /// No `PROVE` within [`EXCHANGE_TIMEOUT`].
    TimedOut,
    /// The TLS exporter could not be read; nothing was sent.
    Exporter,
    /// This node's key would not sign its `CLAIM`.
    Signing,
    /// The connection closed during the exchange, otherwise than by the refusal.
    Closed(String),
}

impl DialFailed {
    /// What the dial reports (ADR-011 38a): a refusal, a `PROVE` that does not verify and a
    /// silence all say "nothing at `<address>` answers as `<expected>`", and name no one else.
    #[must_use]
    pub fn into_error(self, addr: SocketAddr, expected: &Digest32) -> Error {
        match self {
            Self::NotAnswered | Self::BadProve(_) | Self::TimedOut => {
                Error::HandshakeAuth(format!("nothing at {addr} answers as {}", short(expected)))
            }
            Self::Exporter => {
                Error::Handshake("the TLS session could not export its identity binding".into())
            }
            Self::Signing => Error::SigningFailed,
            Self::Closed(why) => Error::Handshake(why),
        }
    }
}

/// The first 26 base32 characters of a fingerprint, as the node's messages name a peer.
fn short(fp: &Digest32) -> String {
    crate::node::link::b32_encode(fp).chars().take(26).collect()
}

/// **The dialler's side** of the exchange on a connection that has just finished its neutral
/// handshake: ask for `expected`, check its `PROVE`, and only then send this node's `CLAIM`
/// (ADR-011 requirement 29).
///
/// On success the connection's limits are raised and the caller gets who was proved. On failure
/// nothing about this node has left: a `PROVE` that does not verify closes the connection with
/// [`BAD_PROVE`] before any `CLAIM` is written.
///
/// # Errors
/// [`DialFailed`]; [`DialFailed::into_error`] gives the dial's message.
pub async fn dial(
    conn: &Connection,
    signer: &(dyn RootSigner + Send + Sync),
    instance: Instance,
    expected: Digest32,
) -> std::result::Result<Proven, DialFailed> {
    dial_with(conn, signer, instance, expected, &exporter).await
}

pub(crate) async fn dial_with(
    conn: &Connection,
    signer: &(dyn RootSigner + Send + Sync),
    instance: Instance,
    expected: Digest32,
    export: &Exporter,
) -> std::result::Result<Proven, DialFailed> {
    let Ok(e) = export(conn) else {
        conn.close(close_code(BAD_PROVE), b"");
        return Err(DialFailed::Exporter);
    };
    let deadline = Instant::now() + EXCHANGE_TIMEOUT;
    let exchange = async {
        let (mut send, mut recv) = conn.open_bi().await.map_err(|_| closed(conn))?;
        write_frame(&mut send, &StreamKind::Identity.frame())
            .await
            .map_err(|_| closed(conn))?;
        write_frame(&mut send, &Ask { target: expected }.encode())
            .await
            .map_err(|_| closed(conn))?;
        let patience = deadline.saturating_duration_since(Instant::now());
        let prove = match read_frame_within(&mut recv, MAX_FLIGHT, patience).await {
            Ok(Some(f)) => f,
            Ok(None) => return Err(closed(conn)),
            Err(Error::SizeLimitExceeded(_)) => return Err(bad_prove(conn, "an oversize PROVE")),
            Err(_) => return Err(closed(conn)),
        };
        let Ok(prove) = Prove::decode(&prove) else {
            return Err(bad_prove(conn, "a malformed PROVE"));
        };
        if prove.target.fingerprint() != expected {
            return Err(bad_prove(conn, "a PROVE for another node"));
        }
        if prove
            .target
            .verify(&resp_input(&e, &expected, &prove.instance), &prove.sig)
            .is_err()
        {
            return Err(bad_prove(conn, "a PROVE whose signature does not verify"));
        }
        // Only now does anything about this node leave.
        let me = signer.fingerprint();
        let sig = signer
            .sign(&init_input(&e, &expected, &me, &instance))
            .map_err(|_| DialFailed::Signing)?;
        let claim = Claim {
            dialler: signer.public_key(),
            instance,
            sig,
        };
        write_frame(&mut send, &claim.encode())
            .await
            .map_err(|_| closed(conn))?;
        let _ = send.finish();
        Ok(Proven {
            peer: expected,
            peer_key: prove.target,
            instance: prove.instance,
        })
    };
    match tokio::time::timeout_at(deadline, exchange).await {
        Ok(Ok(p)) => {
            open_post_identity(conn);
            Ok(p)
        }
        Ok(Err(f)) => Err(f),
        Err(_) => {
            conn.close(close_code(BAD_PROVE), b"");
            Err(DialFailed::TimedOut)
        }
    }
}

fn bad_prove(conn: &Connection, why: &'static str) -> DialFailed {
    conn.close(close_code(BAD_PROVE), b"");
    DialFailed::BadProve(why)
}

/// Why the connection ended under a dial: the listener's refusal, or something else.
fn closed(conn: &Connection) -> DialFailed {
    match conn.close_reason() {
        Some(quinn::ConnectionError::ApplicationClosed(a))
            if a.error_code == close_code(REFUSAL) =>
        {
            DialFailed::NotAnswered
        }
        Some(other) => DialFailed::Closed(crate::transport::quic::closed_text(&other)),
        None => DialFailed::Closed("the identity stream failed".to_owned()),
    }
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;
