//! A Range bundle as its reader assembles and checks it (design simple-sync §1). The frames of
//! one answer are held in the connection's private assembly; each proof is then checked with the
//! existing verifiers and kept in the existing row kinds, exactly what admission keeps for those
//! proofs. No body is stored here: a checked body goes to the frontier, or is dropped and stays
//! owed. A root that checked out grants no authority; the validator still decides.

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::log::entry::Entry;
use crate::log::history::{
    consistency_ranges, inclusion_ranges, ConsistencyProof, ConsistencyVerifier, ContextSource,
    ControlContext, ControlRangeProof, ControlRangeVerifier, Descriptor, HistoryStep,
    InclusionProof, InclusionVerifier, LogScope, SignedHead, TreeBinding, TreeRange, VerifiedHead,
    VerifiedHeader, WorkBudget, MAX_PAYLOAD_BYTES,
};
use crate::node::channel::{entry_store, HistoryAdmissionRoom};
use crate::node::store::Store;

use super::credit::Response;
use super::transport::{Private, Read};
use super::{Continuation, Frame, Object, Preamble, Proof, Query, RangeWant, Status};

fn invalid(reason: &'static str) -> Error {
    Error::MalformedBundle(reason)
}

/// One answer as it came: its terminal status and continuation, and its frames, unchecked.
pub(crate) struct Reply {
    pub(crate) status: Status,
    pub(crate) continuation: Option<Continuation>,
    pub(crate) answer: Answer,
}

/// Ask one Range bundle on its own stream of `conn` and hold its frames until its Done and the
/// end of the holder's stream. There is no frame deadline: this connection's loop waits for its
/// own peer while the connection lives, and nothing else waits on it. The request and the
/// answer are this connection's private assembly: no job and no shared byte admission is held
/// while the peer answers. MP-9's two object asks of a listing peer (`Query::Fork`,
/// `Query::HeadById`) are asked the same way, with no head target; their one object is held in
/// the answer like a bundle's head.
pub(crate) async fn ask(
    conn: &crate::transport::quic::VoxConnection,
    me: Digest32,
    preamble: Preamble,
    query: Query,
    target: Option<crate::log::history::HeadTarget>,
    fence: std::sync::Arc<crate::transport::stream_transport::Fence>,
) -> Result<Reply> {
    use crate::transport::streams::{open_typed, StreamKind};
    query.validate()?;
    if query.target_head() != target.as_ref().map(crate::log::history::HeadTarget::id)
        || !matches!(
            query,
            Query::Range { .. } | Query::Fork(_) | Query::HeadById(_) | Query::Head(_)
        )
    {
        return Err(Error::Profile("range ask names another head"));
    }
    let streams = tokio::select! {
        biased;
        () = fence.retired() => return Err(Error::Unreachable("range ask cancelled")),
        result = open_typed(conn, StreamKind::Sync) => result?,
    };
    let mut io = Private::new(streams.0, streams.1, fence);
    let result = exchange(&mut io, me, preamble, query, target).await;
    if let Err(error) = &result {
        io.abort(match error {
            Error::MalformedBundle(_) | Error::SizeLimitExceeded(_) => {
                crate::wire::WireError::ProtocolLimits
            }
            _ => crate::wire::WireError::TransportFailed,
        });
    }
    result
}

async fn exchange(
    io: &mut Private,
    me: Digest32,
    preamble: Preamble,
    query: Query,
    target: Option<crate::log::history::HeadTarget>,
) -> Result<Reply> {
    let mut overhead = crate::transport::streams::StreamKind::Sync.frame().len() + 4;
    let encoded = preamble.encode();
    overhead += encoded.len() + 4;
    io.write(&encoded).await?;
    let encoded = Frame::Hello(crate::wire::SYNC_MODE_BOUNDED_HISTORY).encode_private()?;
    overhead += encoded.len() + 4;
    io.write(&encoded).await?;
    let encoded = Frame::Want {
        request: preamble.request,
        query: query.clone(),
        target,
    }
    .encode_private()?;
    overhead += encoded.len() + 4;
    io.write(&encoded).await?;
    let reply = match io
        .read(super::MAX_HELLO_FRAME_BYTES + 4, Some(&[0x01]))
        .await?
    {
        Read::Frame(frame) => frame,
        Read::End => return Err(Error::Unreachable("range closed before HELLO")),
    };
    if !matches!(reply.frame()?, Frame::Hello(mode) if mode == crate::wire::SYNC_MODE_BOUNDED_HISTORY)
    {
        return Err(Error::MalformedBundle("history HELLO mode"));
    }
    overhead += reply.wire_len();
    drop(reply);
    let (body_offset, explicit_body) = match query {
        Query::Range {
            want: RangeWant::Body { offset, .. },
            ..
        } => (offset, true),
        _ => (0, false),
    };
    let mut credit = Response::new(preamble.request, query)?;
    credit.charge_handshake(overhead)?;
    let mut answer = Answer::default();
    loop {
        let incoming = match io.read(credit.remaining_wire(), None).await? {
            Read::Frame(frame) => frame,
            Read::End => return Err(Error::Unreachable("range closed before DONE")),
        };
        let frame = incoming.frame()?;
        credit.accept(&frame, incoming.wire_len())?;
        answer.bytes += incoming.wire_len();
        if let Frame::Done {
            status,
            continuation,
            ..
        } = frame
        {
            // An answer may stop at any frame (PL-5): a position whose header the stop cut
            // off is not part of it; the continuation names that position again.
            if status != Status::Complete
                && answer
                    .pieces
                    .last()
                    .is_some_and(|piece| piece.header.is_none())
            {
                answer.pieces.pop();
            }
            // The holder finishes its stream right after Done (`history_stream::serve`): read
            // that end before the stream is dropped, so dropping it never tells the holder that
            // the answer was stopped. A receipt counts as served only on the acknowledged end of
            // its stream, and a stop arriving first would fail a delivered receipt. At most one
            // prefix and one byte are read here: anything after Done but the end is refused.
            match io.read(4 + 1, None).await? {
                Read::End => {}
                Read::Frame(_) => return Err(Error::MalformedBundle("history frame after DONE")),
            }
            return Ok(Reply {
                status,
                continuation,
                answer,
            });
        }
        let header = matches!(
            frame,
            Frame::Meta {
                object: Object::Header(_),
                ..
            }
        );
        answer.take(preamble.room, &frame)?;
        if header {
            // A sealed package for another member gets body credit only under an explicit
            // Body want (opaque relay). In an ordinary page its header completes header-only,
            // and a chunk of its body is refused by `credit.accept` before any byte is kept.
            let for_another = answer
                .expected_package_for()
                .is_some_and(|recipient| recipient != Some(me));
            if let Some((hash, length)) = answer
                .expected_body()
                .filter(|_| explicit_body || !for_another)
            {
                credit.expect_body(hash, length, body_offset.min(length))?;
            }
        }
    }
}

/// One position of an answer: its inclusion proof, then its header, then its body bytes.
struct Piece {
    proof: Option<InclusionProof>,
    header: Option<Entry>,
    body: Vec<u8>,
}

/// The frames of one answer, held until its Done. Bounded by the one response quantum.
#[derive(Default)]
pub(crate) struct Answer {
    head: Option<SignedHead>,
    contexts: HashMap<Digest32, ControlContext>,
    consistency: Vec<(Descriptor, ConsistencyProof)>,
    pieces: Vec<Piece>,
    controls: Vec<ControlRangeProof>,
    /// The holder's corrected Have pages of the asked author, when it could not serve all it
    /// said.
    pub(crate) corrected: Vec<super::AuthorHave>,
    /// MP-9: a fork proof's two signed headers, the answer to `Query::Fork`.
    pub(crate) fork: Option<(Vec<u8>, Vec<u8>)>,
    /// The wire bytes the answer arrived in: what its assembly is counted at (`pull::Assembly`).
    bytes: usize,
}

impl Answer {
    /// The signed head the answer carried (a `Query::HeadById` answer's one object).
    pub(crate) fn head(&self) -> Option<&SignedHead> {
        self.head.as_ref()
    }

    /// The wire bytes the answer arrived in.
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// The identities of the contexts the answer carried: what a Range continuing it has
    /// already received (`pull::exchange`, `Query::Range`'s `skip`).
    pub(crate) fn context_ids(&self) -> impl Iterator<Item = &Digest32> {
        self.contexts.keys()
    }

    /// Take one response frame already admitted by the request's wire credit.
    pub(crate) fn take(&mut self, room: Digest32, frame: &Frame<'_>) -> Result<()> {
        match frame {
            Frame::Meta { object, .. } => match object {
                Object::Head(bytes) => {
                    if self.head.is_some() {
                        return Err(invalid("bundle head repeated"));
                    }
                    self.head = Some(SignedHead::from_wire(bytes)?);
                }
                Object::Context(bytes) => {
                    let context = ControlContext::from_wire(bytes)?;
                    if context.room != room || context.scope != LogScope::Public {
                        return Err(invalid("bundle context differs"));
                    }
                    self.contexts.insert(context.hash(), context);
                }
                Object::Proof(Proof::Consistency { prefix, proof }) => {
                    self.consistency.push((*prefix, proof.clone()));
                }
                Object::Proof(Proof::Inclusion(proof)) => self.pieces.push(Piece {
                    proof: Some(proof.clone()),
                    header: None,
                    body: Vec::new(),
                }),
                Object::Proof(Proof::Control(proof)) => self.controls.push(proof.clone()),
                Object::Header(bytes) => {
                    let header = Entry::from_wire(bytes)?;
                    if header.payload.is_some() {
                        return Err(invalid("bundle header carries a body"));
                    }
                    match self.pieces.last_mut() {
                        Some(piece) if piece.header.is_none() => {
                            if piece
                                .proof
                                .as_ref()
                                .is_some_and(|proof| proof.position != header.skeleton.seq)
                            {
                                return Err(invalid("bundle header differs from its proof"));
                            }
                            piece.header = Some(header);
                        }
                        _ => self.pieces.push(Piece {
                            proof: None,
                            header: Some(header),
                            body: Vec::new(),
                        }),
                    }
                }
                Object::Fork {
                    existing,
                    conflicting,
                } => {
                    if self.fork.is_some() {
                        return Err(invalid("bundle fork repeated"));
                    }
                    self.fork = Some((existing.to_vec(), conflicting.to_vec()));
                }
            },
            Frame::Chunk { entry, bytes, .. } => {
                let piece = self
                    .pieces
                    .last_mut()
                    .filter(|piece| {
                        piece
                            .header
                            .as_ref()
                            .is_some_and(|h| h.entry_hash() == *entry)
                    })
                    .ok_or(invalid("bundle chunk without its header"))?;
                piece.body.extend_from_slice(bytes);
            }
            Frame::Holding(authors) => {
                self.corrected = authors.clone();
            }
            _ => return Err(invalid("bundle frame kind")),
        }
        Ok(())
    }

    /// The header and body length a chunk credit expects next, if this frame was a header.
    pub(crate) fn expected_body(&self) -> Option<(Digest32, u64)> {
        let header = self.pieces.last()?.header.as_ref()?;
        Some((header.entry_hash(), header.skeleton.payload_len))
    }

    /// When the last header is a sealed key package: the recipient its signed header names.
    fn expected_package_for(&self) -> Option<Option<Digest32>> {
        let v2 = self.pieces.last()?.header.as_ref()?.skeleton.v2.as_ref()?;
        (v2.kind == crate::log::history::SignedEntryKind::KeyPackage).then_some(v2.recipient)
    }
}

/// A body cut by the response quantum, carried into this connection's next answer only.
pub(crate) struct Partial {
    pub(crate) head: Digest32,
    pub(crate) header: Entry,
    pub(crate) bytes: Vec<u8>,
}

/// What one checked answer proved, for the frontier. Bodies here are checked against their
/// signed headers and held by this connection only.
pub(crate) struct Checked {
    /// Every position whose header and inclusion were checked, the header with its whole body
    /// when the holder served it (payload `None`: this holder did not serve it).
    pub(crate) entries: Vec<Entry>,
    pub(crate) partial: Option<Partial>,
    /// The positions whose receipt (header, inclusion and own prefix) this answer brought.
    pub(crate) receipts: Vec<u64>,
    /// The answer saved something this node did not hold before: the head, a context, a header
    /// under this head, the head committed here, or a control coverage (S/admission.rs
    /// `brought`). `vox status` counts one that saved nothing as `empty`; one that saved some
    /// moves `last sync`.
    pub(crate) brought: bool,
    /// MP-9: the promotion of the asked head compared it with the accepted one and found two
    /// signed entries of its author at one position: the caller records the fork.
    pub(crate) fork: Option<Box<(Entry, Entry)>>,
    /// The contexts this answer (or `check`'s `pending`) carried that no proof of it used: not
    /// kept, and not something this node now holds (`None`: one it stores already, carried by
    /// identity only). A Range whose answer stopped before the proof that uses them carries
    /// them on to its next answer (`pull::exchange`).
    pub(crate) unused: HashMap<Digest32, Option<ControlContext>>,
    /// How many control proofs of the want this answer verified: each completes a covered
    /// interval, which the asker's next ask starts after.
    pub(crate) controls: usize,
}

struct Contexts<'a> {
    inner: &'a entry_store::Read<'a>,
    held: std::cell::RefCell<HashMap<Digest32, ControlContext>>,
    generated: std::cell::RefCell<Vec<ControlContext>>,
    /// Every context a verifier of this answer looked up, sent or stored: what its proofs used.
    used: std::cell::RefCell<std::collections::HashSet<Digest32>>,
}
impl ContextSource for Contexts<'_> {
    fn context(&self, hash: &Digest32) -> Result<Option<ControlContext>> {
        self.used.borrow_mut().insert(*hash);
        if let Some(context) = self.held.borrow().get(hash) {
            return Ok(Some(context.clone()));
        }
        self.inner.history_context(hash)
    }
}
impl Contexts<'_> {
    /// Run one bounded verifier to its end with fresh work credit per slice, as admission's
    /// verifier turn does. A missing context the holder did not send is a wrong answer.
    fn drive<T>(
        &self,
        mut step: impl FnMut(&Self, &mut WorkBudget) -> Result<HistoryStep<T>>,
    ) -> Result<T> {
        loop {
            let mut work = WorkBudget::default();
            match step(self, &mut work)? {
                HistoryStep::Complete(value) => return Ok(value),
                HistoryStep::Progress(context) => {
                    self.held
                        .borrow_mut()
                        .insert(context.hash(), context.clone());
                    self.generated.borrow_mut().push(context);
                }
                HistoryStep::MissingContext(_) => {
                    return Err(invalid("bundle lacks a context its proof needs"))
                }
                HistoryStep::Yielded => {}
            }
        }
    }
}

type Ranges = Vec<(u64, Descriptor)>;

/// Check one answer under `head_id` and keep what it proved, in one transaction, as admission
/// keeps completed proofs (S/admission.rs). `anchor` is the size the request named; `partial`
/// is this connection's cut body that a Body want continues; `pending` the contexts earlier
/// answers of the same request carried and no proof had used yet. Only the contexts a proof of
/// this answer used are kept; the rest are returned (`Checked::unused`), never stored.
#[allow(clippy::too_many_arguments)]
pub(crate) fn check(
    room: &impl HistoryAdmissionRoom,
    store: &Store,
    committed: &std::sync::atomic::AtomicBool,
    own_observed: &std::sync::atomic::AtomicBool,
    head_id: Digest32,
    anchor: u64,
    want: RangeWant,
    answer: Answer,
    partial: Option<Partial>,
    pending: HashMap<Digest32, Option<ControlContext>>,
) -> Result<Checked> {
    let Answer {
        head,
        mut contexts,
        consistency,
        pieces,
        controls,
        corrected: _,
        fork: _,
        bytes: _,
    } = answer;
    let mut carried_stored = Vec::new();
    for (hash, context) in pending {
        match context {
            Some(context) => {
                contexts.entry(hash).or_insert(context);
            }
            None => carried_stored.push(hash),
        }
    }
    let input = room.history_read(store)?;
    let signed = match head {
        Some(head) => head,
        None => input
            .history_head(&head_id)?
            .ok_or(invalid("bundle head is held by neither side"))?,
    };
    let binding = signed.binding;
    if signed.id() != head_id
        || binding.room != room.channel_id()
        || binding.scope != LogScope::Public
    {
        return Err(invalid("bundle head differs from its request"));
    }
    let author = binding.author;
    let key = room
        .history_author_key(&author)
        .ok_or(invalid("bundle author is unknown"))?;
    let held_head = input.history_head(&head_id)?.is_some();
    let source = Contexts {
        inner: &input,
        held: std::cell::RefCell::new(contexts),
        generated: std::cell::RefCell::new(Vec::new()),
        used: std::cell::RefCell::new(std::collections::HashSet::new()),
    };
    let vhead: VerifiedHead = source.drive(|_, work| signed.verify(&key, work))?;
    // Continuity from each size the answer proves a prefix of: the size the asker named, and
    // each entry's own position. Each holder's prefix is proven against the signed root as an
    // admitted consistency proof is (S/admission.rs stage); promotion then compares the named
    // one with the asker's own accepted root.
    // A page of entries leads with the receipt of `lo - 1` (header, inclusion and own prefix,
    // no body): checked as every receipt is, kept unless held by position (`edge_held` below),
    // and not handed over (server.rs range).
    let edge = match want {
        RangeWant::Entries { lo, .. } if lo > 1 => Some(lo - 1),
        _ => None,
    };
    // Under a head the asker named from an anchor below its size, the answer also leads with
    // the receipt of the head's terminal position when the want does not reach it (server.rs
    // range): checked as every receipt is, not handed over; promotion commits the head with it.
    let terminal = (anchor < signed.root.leaves
        && !matches!(want, RangeWant::Entries { hi, .. } if hi == signed.root.leaves))
    .then_some(signed.root.leaves);
    let mut prefixes = Vec::with_capacity(consistency.len());
    for (claimed, proof) in consistency {
        let from = proof.from;
        let (lo, hi) = want.interval();
        if claimed.leaves != from
            || from > signed.root.leaves
            || (from != anchor && !(lo..=hi).contains(&from) && Some(from) != edge)
        {
            return Err(invalid("bundle consistency differs from its request"));
        }
        let mut verifier = ConsistencyVerifier::new(vhead.clone(), claimed, proof)?;
        let prefix = source.drive(|source, work| verifier.advance(source, work))?;
        prefixes.push((prefix, verifier.take_verified_ranges()?));
    }
    let (lo, hi) = want.interval();
    let mut entries = Vec::new();
    let mut included = Vec::new();
    let mut headers = Vec::new();
    let mut cut = None;
    let mut carried = partial;
    for piece in pieces {
        let header = piece
            .header
            .ok_or(invalid("bundle proof without its header"))?;
        let seq = header.skeleton.seq;
        let extra = Some(seq) == edge || Some(seq) == terminal;
        if (seq < lo && !extra) || (seq > hi && Some(seq) != terminal) || seq > signed.root.leaves {
            return Err(invalid("bundle position outside its request"));
        }
        let vheader =
            source.drive(|_, work| VerifiedHeader::verify(&header, binding, &key, work))?;
        let (offset, mut bytes) = match (want, carried.take()) {
            (RangeWant::Body { offset, .. }, Some(partial))
                if offset > 0
                    && partial.head == head_id
                    && partial.header.header_wire() == header.header_wire()
                    && partial.bytes.len() as u64 == offset =>
            {
                (offset, partial.bytes)
            }
            // A first body request: the header and its inclusion under the named head, checked
            // below as every page's entry is, then the body from its start.
            (RangeWant::Body { offset: 0, .. }, None) if piece.proof.is_some() => (0, Vec::new()),
            (RangeWant::Body { .. }, _) => return Err(invalid("bundle body without its start")),
            (_, carried_back) => {
                carried = carried_back;
                (0, Vec::new())
            }
        };
        match piece.proof {
            Some(proof) => {
                if proof.position != seq || proof.size != signed.root.leaves {
                    return Err(invalid("bundle inclusion differs from its position"));
                }
                let mut verifier = InclusionVerifier::new(vhead.clone(), vheader.clone(), proof)?;
                let proved = source.drive(|source, work| verifier.advance(source, work))?;
                included.push((proved, verifier.take_verified_ranges()?));
                headers.push(vheader);
            }
            // Only a later offset of a Body want continues a header whose inclusion an earlier
            // answer proved.
            None if matches!(want, RangeWant::Body { offset, .. } if offset > 0) => {}
            None => return Err(invalid("bundle header without its inclusion")),
        }
        if extra {
            if !piece.body.is_empty() {
                return Err(invalid("bundle receipt carries a body"));
            }
            continue;
        }
        bytes.extend_from_slice(&piece.body);
        let length = header.skeleton.payload_len;
        if bytes.len() as u64 > length || length > MAX_PAYLOAD_BYTES as u64 {
            return Err(invalid("bundle body exceeds its header"));
        }
        if bytes.len() as u64 == length {
            let mut whole = header.clone();
            whole.payload = Some(bytes);
            whole.verify_payload_binding()?;
            entries.push(whole);
        } else if bytes.len() as u64 == offset && offset == 0 {
            // No byte of it was sent: this holder did not serve that body in this answer.
            entries.push(header);
        } else {
            if cut.is_some() {
                return Err(invalid("bundle cut twice"));
            }
            cut = Some(Partial {
                head: head_id,
                header,
                bytes,
            });
        }
    }
    let mut proved_controls = Vec::new();
    for proof in controls {
        if proof.lo < lo || proof.hi > hi {
            return Err(invalid("bundle control interval outside its request"));
        }
        let mut verifier = ControlRangeVerifier::new(vhead.clone(), proof)?;
        let proved = source.drive(|source, work| verifier.advance(&key, source, work))?;
        let mut ranges = verifier.take_verified_ranges()?;
        ranges.sort_unstable_by(|(a, x), (b, y)| a.cmp(b).then(y.leaves.cmp(&x.leaves)));
        proved_controls.push((proved, ranges));
    }
    // Only the contexts a proof of this answer looked up are kept (with those its verifiers
    // made); one no proof used is no fact this node holds: it is returned unused, never stored.
    let Contexts {
        held,
        generated,
        used,
        ..
    } = source;
    let generated = generated.into_inner();
    let used = used.into_inner();
    let made: std::collections::HashSet<Digest32> =
        generated.iter().map(ControlContext::hash).collect();
    let mut keep_contexts = Vec::new();
    let mut unused = HashMap::new();
    for (hash, context) in held.into_inner() {
        if made.contains(&hash) {
            continue;
        }
        let stored = input.history_context(&hash)?.is_some();
        if !used.contains(&hash) {
            // Carried on: by identity alone when this node stores it already.
            unused.insert(hash, (!stored).then_some(context));
        } else if !stored {
            keep_contexts.push(context);
        }
    }
    for hash in carried_stored {
        if !used.contains(&hash) {
            unused.entry(hash).or_insert(None);
        }
    }
    for context in generated {
        if input.history_context(&context.hash())?.is_none() {
            keep_contexts.push(context);
        }
    }
    let accepted_before = held_head && input.history_head_accepted(&head_id, binding)?;
    // The receipt of `lo - 1` a page leads with serves only the page's first entry, and that
    // entry finds its predecessor by the one lookup admission uses (`parent_evidence`):
    // published there, or a parent receipt located by position. One held so is checked like
    // every proof of the answer but not kept again under this head; one not held so is kept and
    // combined (`combine_parent`), so admission then finds it. Whether a published parent's
    // stored prefix is its own (`SparseParent::check_published`) is admission's local check: a
    // receipt kept here could not change it (that slot holds the other history's range).
    let edge_held = match edge.and_then(|seq| {
        headers
            .iter()
            .find(|header| header.entry().skeleton.seq == seq)
            .map(|header| (seq, header.entry().entry_hash()))
    }) {
        Some((seq, hash)) => super::admission::parent_evidence(&input, &author, seq)?
            .is_some_and(|parent| parent.header().entry_hash() == hash),
        None => false,
    };
    let redundant = |seq: u64| edge_held && Some(seq) == edge;
    // The edge's own prefix is not kept again, unless it is also the one promotion starts from.
    let kept_prefix = |prefix: &crate::log::history::ConsistentPrefix| {
        !redundant(prefix.prefix().leaves) || prefix.prefix().leaves == anchor
    };
    // The headers not held yet: neither published at their position (under a head in the
    // accepted chain) nor pending (kept by position under an accepted head, whichever accepted
    // head brought them; else under this head). Only these are brought, and only these are
    // kept pending below.
    let mut fresh = Vec::new();
    for header in &headers {
        let entry = header.entry();
        if redundant(entry.skeleton.seq) {
            continue;
        }
        let published = if accepted_before {
            input.history_position_header(&author, entry.skeleton.seq)?
        } else {
            None
        };
        let held = published
            .or(input.history_pending_header(&head_id, entry.skeleton.seq)?)
            .is_some_and(|held| held.entry_hash() == entry.entry_hash());
        if !held {
            fresh.push(header);
        }
    }
    let mut brought = !held_head || !keep_contexts.is_empty() || !fresh.is_empty();
    drop(input);
    // The head object, as a Head query's answer is observed (S/admission.rs stage).
    if !held_head {
        let wire = signed.to_wire();
        super::admission::stage(
            room,
            store,
            (committed, own_observed),
            [0; 16],
            [0; 32],
            &super::Query::Head(author),
            Object::Head(&wire),
        )?;
    }
    let tree = TreeBinding {
        room: binding.room,
        scope: LogScope::Public,
        author,
    };
    room.history_write_tracked(store, committed, |index| {
        for context in &keep_contexts {
            index.keep_history_context(context)?;
        }
        for header in &headers {
            index.keep_history_header(header)?;
        }
        for (proved, ranges) in &included {
            if redundant(proved.header().entry().skeleton.seq) {
                continue;
            }
            keep_needed(
                index,
                head_id,
                tree,
                ranges,
                inclusion_ranges(proved.header().entry().skeleton.seq, proved.root().leaves)?,
            )?;
            index.keep_history_inclusion_receipt(proved)?;
        }
        for (prefix, ranges) in &prefixes {
            if !kept_prefix(prefix) {
                continue;
            }
            keep_needed(
                index,
                head_id,
                tree,
                ranges,
                consistency_ranges(prefix.prefix().leaves, prefix.root().leaves)?,
            )?;
            // Under this head only, unless it is already accepted: its range [1, n] is a fact
            // of the accepted chain only once the head is (`keep_history_prefix_receipt`).
            index.keep_history_prefix_receipt(prefix)?;
        }
        Ok(())
    })?;
    // The head first: a receipt kept under a head committed here is found by its author and
    // position (`keep_history_parent_receipt`), whatever head a later entry names. A head of
    // another history is compared with the accepted one there (MP-9): a fork found is the
    // caller's to record; a comparison still waiting keeps the head as the author's unresolved
    // one, which this node's Have then lists.
    let mut fork = None;
    if !prefixes.is_empty() || !included.is_empty() {
        if let super::admission::Advanced::Fork(pair) =
            super::admission::promote_head(room, store, committed, head_id)?
        {
            fork = Some(pair);
        }
    }
    let accepted = (!prefixes.is_empty() || !included.is_empty() || !proved_controls.is_empty())
        && room
            .history_read(store)?
            .history_head_accepted(&head_id, binding)?;
    // After the promotion, under a head now accepted: each pending header is kept once by its
    // author and position (one already published there not at all), and the receipts kept above
    // under the head alone become facts of the accepted chain: each inclusion receipt gets its
    // locator by position, so a header proven here is served whatever head is asked later
    // (`history_proof_header`), and each prefix receipt its range [1, n]. Under a head of
    // another history, or one still unresolved, all of them stay bound to the head.
    let publish = accepted && !accepted_before;
    if !fresh.is_empty() || publish {
        room.history_write_tracked(store, committed, |index| {
            for header in &fresh {
                index.keep_history_pending_header(&head_id, header)?;
            }
            if publish {
                for (proved, _) in &included {
                    if !redundant(proved.header().entry().skeleton.seq) {
                        index.keep_history_inclusion_receipt(proved)?;
                    }
                }
                for (prefix, _) in &prefixes {
                    if kept_prefix(prefix) {
                        index.keep_history_prefix_receipt(prefix)?;
                    }
                }
            }
            Ok(())
        })?;
    }
    let mut receipts = Vec::new();
    for (proved, _) in &included {
        let seq = proved.header().entry().skeleton.seq;
        if !redundant(seq) {
            super::admission::combine_parent(room, store, committed, head_id, author, seq)?;
        }
        if prefixes
            .iter()
            .any(|(prefix, _)| prefix.prefix().leaves == seq)
        {
            receipts.push(seq);
        }
    }
    brought |= publish;
    // Coverage is kept only under an accepted head (S/admission.rs, the Controls arm); under a
    // head not yet accepted it stays owed and is asked again once the head is. It is history
    // this node did not hold before only when it covers a position not covered yet.
    if !proved_controls.is_empty() && accepted {
        brought |= room.history_write_tracked(store, committed, |index| {
            let mut grew = false;
            for (proved, ranges) in &proved_controls {
                let mut collapsed = 0;
                for (start, descriptor) in ranges {
                    if *start <= collapsed {
                        continue;
                    }
                    index.keep_history_proof_range(head_id, tree, *start, *descriptor)?;
                    if descriptor.controls == 0 {
                        collapsed = start + descriptor.leaves - 1;
                    }
                }
                match index.keep_control_coverage(proved, 0)? {
                    entry_store::sparse::CoverageKept::Partial => {
                        return Err(invalid("bundle control coverage incomplete"));
                    }
                    entry_store::sparse::CoverageKept::Complete { grew: more } => grew |= more,
                }
            }
            Ok(grew)
        })?;
    }
    // Every full aligned block this answer's proofs verified, kept by author and position once
    // the head is accepted: served again under any later head of the author without walking
    // back to this one (S/admission.rs keep_blocks).
    let trace: Ranges = included
        .iter()
        .map(|(_, ranges)| ranges)
        .chain(prefixes.iter().map(|(_, ranges)| ranges))
        .chain(proved_controls.iter().map(|(_, ranges)| ranges))
        .flatten()
        .copied()
        .collect();
    if !trace.is_empty() {
        super::admission::keep_blocks(room, store, committed, head_id, tree, &trace)?;
    }
    Ok(Checked {
        entries,
        partial: cut,
        receipts,
        brought,
        fork,
        unused,
        controls: proved_controls.len(),
    })
}

fn keep_needed(
    index: &mut entry_store::Write<'_, '_>,
    head: Digest32,
    tree: TreeBinding,
    ranges: &Ranges,
    needed: Vec<TreeRange>,
) -> Result<()> {
    for (start, descriptor) in ranges {
        let range = TreeRange {
            start: *start,
            leaves: descriptor.leaves,
        };
        if needed.contains(&range) {
            index.keep_history_proof_range(head, tree, *start, *descriptor)?;
        }
    }
    Ok(())
}
