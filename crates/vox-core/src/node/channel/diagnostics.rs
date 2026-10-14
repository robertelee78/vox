//! Bounded opening diagnostics. The sealed log retains the records themselves.

/// A sample of records set aside while opening a room, with a count of further records.
/// This is a diagnostic summary, never the authoritative record of room history.
#[derive(Clone, Debug, Default)]
pub struct SetAside {
    entries: Vec<String>,
    omitted: u64,
}

/// At most 64 KiB of diagnostic text per open room, regardless of log length.
const SAMPLE_LIMIT: usize = 64;
const ENTRY_BYTES: usize = 1024;

impl SetAside {
    pub(super) fn push(&mut self, mut entry: String) {
        if self.entries.len() == SAMPLE_LIMIT {
            self.omitted = self.omitted.saturating_add(1);
            return;
        }
        if entry.len() > ENTRY_BYTES {
            let mut end = ENTRY_BYTES - "…".len();
            while !entry.is_char_boundary(end) {
                end -= 1;
            }
            entry.truncate(end);
            entry.push('…');
            // Do not retain the original allocation behind a shortened diagnostic.
            entry.shrink_to_fit();
        }
        self.entries.push(entry);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn entries(&self) -> &[String] {
        &self.entries
    }

    pub(crate) fn omitted(&self) -> u64 {
        self.omitted
    }
}
