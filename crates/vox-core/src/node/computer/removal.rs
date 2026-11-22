//! Room choices and local results share the signed removal's atomic state snapshot.
use super::*;
use crate::node::link::b32_encode as text_id;
use serde::{Deserialize, Serialize};

/// One reviewed membership and the local node which will reconcile it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RemovalRoom {
    /// Room identity, never its mutable display name.
    pub room: Digest32,
    /// Exact removed computer's node.
    pub member: Digest32,
    /// Local observer, preferably a node authorized to remove the member.
    pub local_node: Digest32,
    /// Local admin when available, otherwise the room creator for the operator's command.
    pub command_node: Digest32,
    /// Exact reviewed governance projection; changed rooms require another review.
    pub revision: u64,
}

/// Public readback of a saved choice and its unfinished room memberships.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemovalProgress {
    /// Signed computer-removal event.
    pub event: String,
    /// Removed computer fingerprint.
    pub computer: String,
    /// The person chose to retain these memberships.
    pub keep_rooms: bool,
    /// Rows not yet reconciled against the room's committed membership.
    pub pending: Vec<RemovalRoom>,
    /// Local nodes whose rooms cannot be checked until they are unlocked.
    pub unchecked_nodes: Vec<String>,
}

pub(super) fn put_rooms(e: &mut Encoder, rooms: &[RemovalRoom]) {
    e.array(rooms.len());
    for row in rooms {
        e.array(5)
            .bytes(&row.room)
            .bytes(&row.member)
            .bytes(&row.local_node)
            .bytes(&row.command_node)
            .uint(row.revision);
    }
}

pub(super) fn read_rooms(d: &mut Decoder<'_>) -> Result<Vec<RemovalRoom>> {
    let mut rooms = Vec::new();
    for _ in 0..count(d)? {
        arity(d, 5)?;
        rooms.push(RemovalRoom {
            room: digest(d)?,
            member: digest(d)?,
            local_node: digest(d)?,
            command_node: digest(d)?,
            revision: d.uint()?,
        });
    }
    if rooms.windows(2).any(|rows| rows[0] >= rows[1]) {
        return Err(bad());
    }
    Ok(rooms)
}
impl RemovalRoom {
    pub(crate) fn put_review(e: &mut Encoder, rooms: &Option<Vec<Self>>) {
        e.array(usize::from(rooms.is_some()));
        if let Some(rooms) = rooms {
            put_rooms(e, rooms);
        }
    }

    pub(crate) fn read_review(d: &mut Decoder<'_>) -> Result<Option<Vec<Self>>> {
        match d.array()? {
            0 => Ok(None),
            1 => read_rooms(d).map(Some),
            _ => Err(bad()),
        }
    }
    fn id(&self) -> Digest32 {
        sha256_concat(&[&self.room, &self.member, &self.local_node])
    }
}

#[derive(Clone)]
pub(super) struct RemovalChoice {
    pub(super) keep_rooms: bool,
    pub(super) rooms: Vec<RemovalRoom>,
}
impl RemovalChoice {
    pub(super) fn put(&self, e: &mut Encoder) {
        e.array(2).uint(u64::from(self.keep_rooms));
        put_rooms(e, &self.rooms);
    }
    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        arity(d, 2)?;
        let keep_rooms = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(bad()),
        };
        Ok(Self {
            keep_rooms,
            rooms: read_rooms(d)?,
        })
    }
}
impl Computer {
    /// Historical authenticated node identities of this exact computer, including retired nodes.
    pub fn nodes_of_computer(&self, target: Digest32) -> Result<BTreeSet<Digest32>> {
        lock(&self.state).members_of_computer(target)
    }

    fn all_removal_rows(s: &State, event: Digest32, choice: &RemovalChoice) -> Vec<RemovalRoom> {
        let mut rows = choice.rooms.clone();
        for ((held, _), extra) in &s.removal_local {
            if *held == event {
                rows.extend(extra.iter().cloned());
            }
        }
        rows.sort();
        rows.dedup_by_key(|row| row.id());
        for row in &mut rows {
            if let Some(Some(creator)) = s.removal_done.get(&(event, row.id())) {
                row.command_node = *creator;
            }
        }
        rows
    }
    fn local_nodes_at(
        s: &State,
        accepted: &BTreeSet<Digest32>,
        local: Digest32,
        sequence: u64,
    ) -> Result<BTreeSet<Digest32>> {
        let mut nodes = BTreeSet::new();
        for id in accepted {
            let event = s.history[id].event()?;
            if event.author == local && event.sequence < sequence {
                for binding in event.bindings {
                    nodes.insert(binding.verify(&event.author, &event.group)?);
                }
            }
        }
        Ok(nodes)
    }

    pub(super) fn removal_progress(s: &State, local: Digest32) -> Result<Vec<RemovalProgress>> {
        let mut progress = Vec::new();
        let accepted = s.accepted_history()?;
        for id in &accepted {
            let event = s.history[id].event()?;
            if event.author != local {
                continue;
            }
            let Some(removal) = event.removal else {
                continue;
            };
            let choice = s.removal_choice.get(id);
            let keep_rooms = choice.is_none_or(|choice| choice.keep_rooms);
            let local_nodes = Self::local_nodes_at(s, &accepted, local, event.sequence)?;
            progress.push(RemovalProgress {
                event: text_id(id),
                computer: text_id(&removal.target),
                keep_rooms,
                pending: choice
                    .map_or_else(Vec::new, |choice| Self::all_removal_rows(s, *id, choice))
                    .into_iter()
                    .filter(|row| {
                        !keep_rooms && s.removal_done.get(&(*id, row.id())) != Some(&None)
                    })
                    .collect(),
                unchecked_nodes: local_nodes
                    .iter()
                    .filter(|node| !keep_rooms && !s.removal_local.contains_key(&(*id, **node)))
                    .map(text_id)
                    .collect(),
            });
            #[cfg(feature = "test-knobs")]
            if super::fx28_mutant("hide-no-admin-removal") {
                if let Some(work) = progress.last_mut() {
                    work.pending
                        .retain(|row| row.command_node == row.local_node);
                }
            }
        }
        Ok(progress)
    }

    /// At an unlocked attachment's first room continuation, capture its remembered rooms once.
    pub(crate) fn capture_removal_rooms(&self, node: Digest32, rooms: &[Digest32]) -> Result<()> {
        #[cfg(feature = "test-knobs")]
        if super::fx28_mutant("do-not-derive-removal-at-attach") {
            return Ok(());
        }
        let local = self.signer.fingerprint();
        let pending: Vec<_> = {
            let s = lock(&self.state);
            let mut pending = Vec::new();
            if s.removal_choice.iter().all(|(event, choice)| {
                choice.keep_rooms || s.removal_local.contains_key(&(*event, node))
            }) {
                return Ok(());
            }
            let accepted = s.accepted_history()?;
            for id in &accepted {
                let event = s.history[id].event()?;
                if event.author != local || s.removal_local.contains_key(&(*id, node)) {
                    continue;
                }
                let Some(removal) = event.removal else {
                    continue;
                };
                let local_nodes = Self::local_nodes_at(&s, &accepted, local, event.sequence)?;
                if s.removal_choice
                    .get(id)
                    .is_some_and(|choice| !choice.keep_rooms)
                    && local_nodes.contains(&node)
                {
                    pending.push((*id, removal.target));
                }
            }
            pending
        };
        if pending.is_empty() {
            return Ok(());
        }
        let mut captured = Vec::new();
        for (event, target) in pending {
            let targets = self.nodes_of_computer(target)?;
            let mut rows = Vec::new();
            for room in rooms {
                for member in &targets {
                    rows.push(RemovalRoom {
                        room: *room,
                        member: *member,
                        local_node: node,
                        command_node: [0; 32],
                        revision: 0,
                    });
                }
            }
            rows.sort();
            captured.push((event, rows));
        }
        self.change(|s| {
            let mut total: usize = s.removal_local.values().map(Vec::len).sum::<usize>()
                + s.removal_choice
                    .values()
                    .map(|choice| choice.rooms.len())
                    .sum::<usize>();
            for (event, rows) in captured {
                if s.removal_local.contains_key(&(event, node)) {
                    continue;
                }
                total += rows.len();
                if total > MAX_RECORDS || s.removal_local.len() >= MAX_RECORDS {
                    return Err(Error::Profile(HISTORY_FULL));
                }
                s.removal_local.insert((event, node), rows);
            }
            s.refresh_removal_pending()?;
            Ok(())
        })
    }

    pub(crate) fn room_removals(
        &self,
        local_node: Digest32,
        room: Digest32,
    ) -> Result<Vec<(Digest32, Digest32, RemovalRoom)>> {
        let s = lock(&self.state);
        let local = self.signer.fingerprint();
        let mut rows = Vec::new();
        for id in s.accepted_history()? {
            let event = s.history[&id].event()?;
            if event.author != local {
                continue;
            }
            let Some(choice) = s
                .removal_choice
                .get(&id)
                .filter(|choice| !choice.keep_rooms)
            else {
                continue;
            };
            for row in Self::all_removal_rows(&s, id, choice) {
                if row.local_node == local_node
                    && row.room == room
                    && s.removal_done.get(&(id, row.id())) != Some(&None)
                {
                    rows.push((id, row.id(), row));
                }
            }
        }
        Ok(rows)
    }

    /// Record only a checked absence/eviction (None) or a checked authority refusal (Some).
    pub(crate) fn finish_room_removal(
        &self,
        event: Digest32,
        row: Digest32,
        authority: Option<Digest32>,
    ) -> Result<()> {
        self.change(|s| {
            let record = s.history.get(&event).ok_or_else(bad)?.event()?;
            let choice = s.removal_choice.get(&event).ok_or_else(bad)?;
            if record.author != self.signer.fingerprint()
                || choice.keep_rooms
                || !Self::all_removal_rows(s, event, choice)
                    .iter()
                    .any(|held| held.id() == row)
            {
                return Err(bad());
            }
            s.removal_done.insert((event, row), authority);
            s.refresh_removal_pending()?;
            Ok(())
        })
    }
    pub(crate) fn has_pending_room_removals(&self) -> bool {
        lock(&self.state).removal_pending
    }
}
/// Local facts of one accepted signed removal; no room or transport work is scheduled here.
#[derive(Clone)]
pub(super) struct Suppression {
    local_nodes: BTreeSet<Digest32>,
    boundaries: BTreeMap<(Digest32, Digest32), BTreeMap<Digest32, u64>>,
    remembered: BTreeMap<Digest32, BTreeSet<Digest32>>,
}
impl Suppression {
    pub(super) fn put(&self, e: &mut Encoder) {
        e.array(3).array(self.local_nodes.len());
        for node in &self.local_nodes {
            e.bytes(node);
        }
        e.array(self.boundaries.len());
        for ((node, room), cuts) in &self.boundaries {
            e.array(3).bytes(node).bytes(room).array(cuts.len());
            for (member, sequence) in cuts {
                e.array(2).bytes(member).uint(*sequence);
            }
        }
        e.array(self.remembered.len());
        for (node, rooms) in &self.remembered {
            e.array(2).bytes(node).array(rooms.len());
            for room in rooms {
                e.bytes(room);
            }
        }
    }
    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        arity(d, 3)?;
        let mut local_nodes = BTreeSet::new();
        for _ in 0..count(d)? {
            if !local_nodes.insert(digest(d)?) {
                return Err(bad());
            }
        }
        let mut boundaries = BTreeMap::new();
        for _ in 0..count(d)? {
            arity(d, 3)?;
            let node = digest(d)?;
            let room = digest(d)?;
            if !local_nodes.contains(&node) {
                return Err(bad());
            }
            let mut cuts = BTreeMap::new();
            for _ in 0..count(d)? {
                arity(d, 2)?;
                let member = digest(d)?;
                if cuts.insert(member, d.uint()?).is_some() {
                    return Err(bad());
                }
            }
            if boundaries.insert((node, room), cuts).is_some() {
                return Err(bad());
            }
        }
        let mut remembered = BTreeMap::new();
        for _ in 0..count(d)? {
            arity(d, 2)?;
            let node = digest(d)?;
            if !local_nodes.contains(&node) {
                return Err(bad());
            }
            let mut rooms = BTreeSet::new();
            for _ in 0..count(d)? {
                if !rooms.insert(digest(d)?) {
                    return Err(bad());
                }
            }
            if remembered.insert(node, rooms).is_some() {
                return Err(bad());
            }
        }
        Ok(Self {
            local_nodes,
            boundaries,
            remembered,
        })
    }
}
impl State {
    fn members_of_computer(&self, target: Digest32) -> Result<BTreeSet<Digest32>> {
        let mut nodes = BTreeSet::new();
        for id in self.accepted_history()? {
            let event = self.history[&id].event()?;
            if event.author == target {
                for binding in event.bindings {
                    nodes.insert(binding.verify(&event.author, &event.group)?);
                }
            }
        }
        Ok(nodes)
    }
    fn removed_members(&self, event: &Digest32) -> Result<BTreeSet<Digest32>> {
        let removal = self.history[event].event()?.removal.ok_or_else(bad)?;
        self.members_of_computer(removal.target)
    }
    pub(super) fn refresh_removal_pending(&mut self) -> Result<()> {
        self.removal_pending = false;
        if self.removal_choice.values().all(|choice| choice.keep_rooms) {
            return Ok(());
        }
        let local = self.description.fingerprint()?;
        let accepted = self.accepted_history()?;
        for (id, choice) in &self.removal_choice {
            if choice.keep_rooms || !accepted.contains(id) {
                continue;
            }
            let event = self.history[id].event()?;
            if Computer::all_removal_rows(self, *id, choice)
                .iter()
                .any(|row| self.removal_done.get(&(*id, row.id())) != Some(&None))
                || Computer::local_nodes_at(self, &accepted, local, event.sequence)?
                    .iter()
                    .any(|node| !self.removal_local.contains_key(&(*id, *node)))
            {
                self.removal_pending = true;
                break;
            }
        }
        Ok(())
    }
    pub(super) fn capture_suppression(&mut self, accepted: &BTreeSet<Digest32>) -> Result<()> {
        let local = self.description.fingerprint()?;
        for id in accepted {
            if self.suppression.contains_key(id) {
                continue;
            }
            let event = self.history[id].event()?;
            if event.removal.is_none() {
                continue;
            }
            let mut local_nodes = BTreeSet::new();
            if let Some(roster) = self.rosters.get(&local) {
                let roster = roster.event()?;
                for binding in roster.bindings {
                    local_nodes.insert(binding.verify(&local, &roster.group)?);
                }
            }
            self.suppression.insert(
                *id,
                Suppression {
                    local_nodes,
                    boundaries: BTreeMap::new(),
                    remembered: BTreeMap::new(),
                },
            );
        }
        Ok(())
    }
}
impl Computer {
    /// Capture once while the caller owns the room's admission order. No publication lease
    /// is requested: only local removal results change, and a competing writer is never waited on.
    pub(crate) fn capture_offer_boundaries(
        &self,
        node: Digest32,
        remembered: &[Digest32],
        rooms: &[(Digest32, Vec<crate::node::api::OfferBasis>)],
    ) -> Result<bool> {
        let owed = |s: &State| {
            s.suppression.values().any(|work| {
                work.local_nodes.contains(&node)
                    && (!work.remembered.contains_key(&node)
                        || rooms.iter().any(|(room, _)| {
                            work.remembered
                                .get(&node)
                                .is_some_and(|known| known.contains(room))
                                && !work.boundaries.contains_key(&(node, *room))
                        }))
            })
        };
        if !owed(&lock(&self.state)) {
            return Ok(true);
        }
        let Some(_writer) = self.try_journal_writer() else {
            return Ok(false);
        };
        let mut next = lock(&self.state).clone();
        if !owed(&next) {
            return Ok(true);
        }
        let members: BTreeMap<_, _> = next
            .suppression
            .iter()
            .filter(|(_, work)| work.local_nodes.contains(&node))
            .map(|(event, _)| Ok((*event, next.removed_members(event)?)))
            .collect::<Result<_>>()?;
        for (event, work) in next
            .suppression
            .iter_mut()
            .filter(|(_, work)| work.local_nodes.contains(&node))
        {
            work.remembered
                .entry(node)
                .or_insert_with(|| remembered.iter().copied().collect());
            for (room, bases) in rooms {
                if !work.remembered[&node].contains(room) {
                    continue;
                }
                if work.boundaries.contains_key(&(node, *room)) {
                    continue;
                }
                let mut cuts: BTreeMap<_, _> =
                    members[event].iter().map(|member| (*member, 0)).collect();
                for basis in bases
                    .iter()
                    .filter(|basis| members[event].contains(&basis.member))
                {
                    cuts.entry(basis.member)
                        .and_modify(|cut: &mut u64| *cut = (*cut).max(basis.seq))
                        .or_insert(basis.seq);
                }
                work.boundaries.insert((node, *room), cuts);
            }
        }
        super::blocking_transaction(|| self.save(&next))?;
        *lock(&self.state) = next;
        Ok(true)
    }
    pub(crate) fn suppress_offer(
        &self,
        node: Digest32,
        room: Digest32,
        basis: &crate::node::api::OfferBasis,
    ) -> bool {
        #[cfg(feature = "test-knobs")]
        if super::fx28_mutant("offer-removed-nodes") {
            return false;
        }
        let s = lock(&self.state);
        s.suppression.iter().any(|(event, work)| {
            if !work.local_nodes.contains(&node) {
                return false;
            }
            if work
                .remembered
                .get(&node)
                .is_some_and(|known| !known.contains(&room))
            {
                return false;
            }
            match work.boundaries.get(&(node, room)) {
                Some(cuts) => {
                    let Some(cut) = cuts.get(&basis.member) else {
                        return false;
                    };
                    #[cfg(feature = "test-knobs")]
                    if super::fx28_mutant("suppress-every-basis-forever") {
                        return true;
                    }
                    basis.seq <= *cut
                }
                None => s
                    .removed_members(event)
                    .map_or(true, |members| members.contains(&basis.member)),
            }
        })
    }
    pub(crate) fn offer_boundaries_owed(&self, node: Digest32, rooms: &[Digest32]) -> bool {
        lock(&self.state).suppression.values().any(|work| {
            work.local_nodes.contains(&node)
                && (!work.remembered.contains_key(&node)
                    || rooms.iter().any(|room| {
                        work.remembered[&node].contains(room)
                            && !work.boundaries.contains_key(&(node, *room))
                    }))
        })
    }
    pub(super) fn suppression_pending(s: &State) -> Vec<String> {
        let mut pending = Vec::new();
        for work in s.suppression.values() {
            for node in &work.local_nodes {
                match work.remembered.get(node) {
                    None => pending.push(format!("{}: removed-computer trust offers wait until its rooms are checked; run vox node unlock fp:{}", text_id(node), text_id(node))),
                    Some(rooms) => for room in rooms {
                        if !work.boundaries.contains_key(&(*node, *room)) {
                            pending.push(format!("{}: room {} still owes its removed-computer offer boundary; run vox room open {} --node fp:{}", text_id(node), text_id(room), text_id(room), text_id(node)));
                        }
                    }
                }
            }
        }
        pending
    }
}
