// A Session's entries as the app holds them (ADR-034 FR-4): only the pages asked for. The newest
// page is read when the Session is shown and read again whenever the node says it changed; an
// older page is read only when the person scrolls up to it. Each entry is held once, oldest first.

/// The entries of the Session on screen loaded so far, and where the older ones begin.
struct SessionPages: Equatable {
    /// The entries loaded, oldest first, each once.
    private(set) var entries: [FfiSessionEntry] = []
    /// How many entries the Session has before the first one loaded.
    private(set) var older: UInt64 = 0
    /// Where the older entries end, for `sessionReadOlder`; nil when there are none.
    private(set) var before: String?

    /// The Session's newest page, read again. Pages loaded on scroll that it joins stay, before it;
    /// an entry in both is the newest page's, as it now stands (a request answered). A newest page
    /// that does not reach what was loaded would leave a hole between them: the older pages are
    /// let go, and read again as the person scrolls up.
    mutating func newest(_ page: FfiSessionRead) {
        let ids = Set(page.entries.map(\.id))
        guard let first = entries.first, !ids.contains(first.id),
              let joined = entries.firstIndex(where: { ids.contains($0.id) }) else {
            entries = page.entries
            older = page.older
            before = page.before
            return
        }
        entries = Array(entries[..<joined]) + page.entries
    }

    /// The page before the first entry loaded, read as the person scrolled up to it: put before
    /// what is loaded. Taken only for the cursor it was asked with: a newest page read meanwhile
    /// may have moved it. Whether it was taken.
    @discardableResult
    mutating func older(_ page: FfiSessionRead, asked cursor: String) -> Bool {
        guard before == cursor else { return false }
        let have = Set(entries.map(\.id))
        entries = page.entries.filter { !have.contains($0.id) } + entries
        older = page.older
        before = page.before
        return true
    }

    /// An older loaded request can be answered after the newest page no longer includes it.
    /// Refresh only the requests already held; this never pulls in surrounding transcript.
    mutating func refreshRequests(_ current: [FfiSessionEntry]) {
        let byID = Dictionary(current.map { ($0.id, $0) }, uniquingKeysWith: { _, latest in latest })
        entries = entries.map { byID[$0.id] ?? $0 }
    }

    /// Nothing loaded: another Session, or none, on screen.
    mutating func clear() {
        self = SessionPages()
    }
}
