// Comparing a fingerprint, group by group, as it is typed or pasted (ADR-028 K-5, ADR-014 M-16;
// P16, #624): a partial entry says how many groups match so far, a mismatch names its group and
// says not to trust the node, and only then is Remove offered; a whole match is marked as one.
// The same field on a keyring row, on a node's card, and, collapsed, on every offer.

import SwiftUI

/// What a fingerprint typed so far says against the node's own.
enum Comparison: Equatable {
    /// Nothing typed yet.
    case empty
    /// Every group typed so far matches: `groups` whole groups of `of`.
    case sofar(groups: Int, of: Int)
    /// All of it matches.
    case matches(of: Int)
    /// Group `group` (1-based) differs: what was typed there and what the node's is.
    case differs(group: Int, typed: String, theirs: String)

    /// The comparison of `typed` (case, spaces and dashes not counting) with `fingerprint`.
    static func of(_ typed: String, with fingerprint: String) -> Comparison {
        let a = Array(normal(typed))
        let b = Array(normal(fingerprint))
        let total = (b.count + 3) / 4
        if a.isEmpty { return .empty }
        let group = { (i: Int) -> String in
            String(b[(i / 4) * 4 ..< min(b.count, (i / 4) * 4 + 4)])
        }
        let typedGroup = { (i: Int) -> String in
            String(a[(i / 4) * 4 ..< min(a.count, (i / 4) * 4 + 4)])
        }
        for i in 0 ..< a.count {
            if i >= b.count {
                return .differs(group: total + 1, typed: typedGroup(i), theirs: "")
            }
            if a[i] != b[i] {
                return .differs(group: i / 4 + 1, typed: typedGroup(i), theirs: group(i))
            }
        }
        return a.count == b.count ? .matches(of: total) : .sofar(groups: a.count / 4, of: total)
    }

    private static func normal(_ s: String) -> String {
        s.lowercased().filter { !$0.isWhitespace && $0 != "-" && $0 != "·" }
    }
}

/// The compare field and what it says. `remove`, when given, is offered only on a mismatch.
struct CompareField: View {
    let fingerprint: String
    let name: String
    /// The identifier prefix its parts carry: "<prefix>-compare", "<prefix>-compare-said".
    let id: String
    var remove: (() -> Void)?
    @State private var typed = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            TextField("Their fingerprint, pasted or typed", text: $typed).font(Theme.mono)
                .accessibilityLabel("Their fingerprint, to compare with \(name)'s")
                .accessibilityIdentifier("\(id)-compare")
            switch Comparison.of(typed, with: fingerprint) {
            case .empty:
                EmptyView()
            case let .sofar(groups, of):
                StateMark(kind: .plain, words: "So far matches \(groups) of \(of) groups.")
                    .accessibilityIdentifier("\(id)-compare-said")
            case let .matches(of):
                HStack(spacing: 6) {
                    Text("✓").font(Theme.mono)
                    Text("Matches \(name)'s fingerprint, all \(of) groups.")
                }
                .foregroundStyle(VoxTokens.Colors.accent)
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("Matches \(name)'s fingerprint, all \(of) groups.")
                .accessibilityIdentifier("\(id)-compare-said")
            case let .differs(group, typed, theirs):
                StateMark(kind: .danger,
                          words: theirs.isEmpty
                              ? "Longer than \(name)'s fingerprint: from group \(group) on it is not "
                                  + "this node's. This is not the node you were given: do not trust it."
                              : "Group \(group) does not match: you have \(typed), \(name)'s is "
                                  + "\(theirs). This is not the node you were given: do not trust it.")
                    .accessibilityIdentifier("\(id)-compare-said")
                if let remove {
                    Button("Remove \(name)…", role: .destructive, action: remove)
                        .accessibilityIdentifier("\(id)-compare-remove")
                }
            }
        }
    }
}
