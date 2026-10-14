import Foundation

// A Session's bounded activity window (ADR-034 FR-4). Older activity is loaded only on
// request. Live refresh preserves a pinned older window; End reloads the newest page.

/// The entries of the Session on screen loaded so far, and where the older ones begin.
struct SessionPages: Equatable {
    /// The entries loaded, oldest first, each once.
    private(set) var entries: [FfiSessionEntry] = []
    private(set) var instance: Data?
    /// How many entries the Session has before the first one loaded.
    private(set) var older: UInt64 = 0
    /// Where the older entries end, for `sessionReadOlder`; nil when there are none.
    private(set) var before: String?

    /// At most 128 protocol-admitted activity entries, independently of stored history.
    /// This row budget is not a measured process-memory or whole-app byte bound.
    private static let windowEntries = 128
    /// UTF-8 payload retained across older pages, including Details and question/file fields.
    /// A single protocol-bounded entry is always kept, so a large activity remains readable.
    /// Swift/SwiftUI allocation overhead and physical footprint are measured separately.
    private static let windowTextBytes = 8 * 1024 * 1024
    private(set) var hasNewer = false

    /// Following replaces the window with the authoritative newest page. While the reader
    /// is on older activity, refresh only held rows; new output must not move that window.
    mutating func newest(_ page: FfiSessionRead, following: Bool) {
        if following {
            instance = page.instance
            entries = page.entries
            older = page.older
            before = page.before
            hasNewer = false
        } else {
            // Exact revalidation is authoritative for the held window. The newest page
            // only tells the reader that later activity is available; it cannot restore
            // expired rows or overwrite a newer exact lookup of a request's resolution.
            hasNewer = hasNewer || (!page.entries.isEmpty && page.entries.last?.id != entries.last?.id)
        }
    }

    /// The page before the first entry loaded, read as the person scrolled up to it: put before
    /// what is loaded. Taken only for the cursor it was asked with: a newest page read meanwhile
    /// may have moved it. Whether it was taken.
    @discardableResult
    mutating func older(_ page: FfiSessionRead, asked cursor: String) -> Bool {
        guard before == cursor, instance == page.instance else { return false }
        let have = Set(entries.map(\.id))
        let joined = page.entries.filter { !have.contains($0.id) } + entries
        entries = joined
        boundOlderWindow()
        older = page.older
        before = page.before
        return true
    }

    /// Missing rows are removed only after an exact successful read for this room instance.
    /// Exact lookup's older/before are not pagination metadata; preserve the page cursor.
    @discardableResult
    mutating func revalidate(_ page: FfiSessionRead) -> Bool {
        guard instance == page.instance else { return false }
        let current = Dictionary(page.entries.map { ($0.id, $0) },
                                 uniquingKeysWith: { _, latest in latest })
        entries = entries.compactMap { current[$0.id] }
        boundOlderWindow()
        return true
    }

    /// An older loaded request can be answered after the newest page no longer includes it.
    /// Refresh only the requests already held; this never pulls in surrounding transcript.
    mutating func refreshRequests(_ current: [FfiSessionEntry]) {
        let byID = Dictionary(current.map { ($0.id, $0) }, uniquingKeysWith: { _, latest in latest })
        entries = entries.map { byID[$0.id] ?? $0 }
        boundOlderWindow()
    }

    /// Drop only the newest edge of a pinned window. Its authoritative older count and
    /// cursor still describe its unchanged first entry; evicted activity stays on disk.
    private mutating func boundOlderWindow() {
        var bytes = 0
        var kept = 0
        for entry in entries {
            let cost = Self.textBytes(entry)
            if kept > 0 && (kept >= Self.windowEntries || cost > Self.windowTextBytes - bytes) { break }
            bytes += cost
            kept += 1
            if bytes >= Self.windowTextBytes { break }
        }
        if kept < entries.count {
            entries = Array(entries.prefix(kept))
            hasNewer = true
        }
    }

    private static func textBytes(_ entry: FfiSessionEntry) -> Int {
        var size = entry.id.utf8.count + entry.line.utf8.count + entry.details.utf8.count
        if let file = entry.file {
            size += file.name.utf8.count + file.sha256.utf8.count + file.entry.utf8.count
            size += file.pulledPath?.utf8.count ?? 0
        }
        if let request = entry.request {
            size += request.reference.utf8.count + (request.state?.utf8.count ?? 0)
            for question in request.questions {
                size += question.text.utf8.count
                for option in question.options { size += option.utf8.count }
            }
        }
        return size
    }

    /// Nothing loaded: another Session, or none, on screen.
    mutating func clear() {
        self = SessionPages()
    }
}
