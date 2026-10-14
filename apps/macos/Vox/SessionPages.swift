// A Session's bounded activity window (ADR-034 FR-4). Older activity is loaded only on
// request. Live refresh preserves a pinned older window; End reloads the newest page.

/// The entries of the Session on screen loaded so far, and where the older ones begin.
struct SessionPages: Equatable {
    /// The entries loaded, oldest first, each once.
    private(set) var entries: [FfiSessionEntry] = []
    /// How many entries the Session has before the first one loaded.
    private(set) var older: UInt64 = 0
    /// Where the older entries end, for `sessionReadOlder`; nil when there are none.
    private(set) var before: String?

    /// At most 128 protocol-admitted activity entries, independently of stored history.
    /// This row budget is not a measured process-memory or whole-app byte bound.
    private static let windowEntries = 128
    private(set) var hasNewer = false

    /// Following replaces the window with the authoritative newest page. While the reader
    /// is on older activity, refresh only held rows; new output must not move that window.
    mutating func newest(_ page: FfiSessionRead, following: Bool) {
        if following || entries.isEmpty {
            entries = page.entries
            older = page.older
            before = page.before
            hasNewer = false
        } else {
            let current = Dictionary(page.entries.map { ($0.id, $0) },
                                     uniquingKeysWith: { _, latest in latest })
            entries = entries.map { current[$0.id] ?? $0 }
            hasNewer = hasNewer || page.entries.last?.id != entries.last?.id
        }
    }

    /// The page before the first entry loaded, read as the person scrolled up to it: put before
    /// what is loaded. Taken only for the cursor it was asked with: a newest page read meanwhile
    /// may have moved it. Whether it was taken.
    @discardableResult
    mutating func older(_ page: FfiSessionRead, asked cursor: String) -> Bool {
        guard before == cursor else { return false }
        let have = Set(entries.map(\.id))
        let joined = page.entries.filter { !have.contains($0.id) } + entries
        if joined.count > Self.windowEntries { hasNewer = true }
        entries = Array(joined.prefix(Self.windowEntries))
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
