// The main window's two side columns, resizable and remembered (v0.4.1): the sidebar and the room's
// inspector each take a width the person drags, between a minimum that never clips their content
// and a maximum that leaves the timeline its room; each width, and whether the inspector shows, is
// kept in the app's defaults and used again at the next launch.

import AppKit
import SwiftUI

enum Columns {
    enum Side: String {
        case sidebar, inspector

        /// The narrowest it may be: the room names and the members' trust words still fit.
        var min: CGFloat { Theme.scaled(200) }
        /// Its width at first launch.
        var standard: CGFloat { Theme.scaled(self == .sidebar ? 260 : 240) }
        /// The widest it may be.
        var max: CGFloat { Theme.scaled(440) }

        fileprivate var key: String { "column.\(rawValue).width" }
    }

    /// The width last dragged to, kept within its bounds; the standard width before any drag.
    static func width(_ side: Side) -> CGFloat {
        let kept = CGFloat(UserDefaults.standard.double(forKey: side.key))
        guard kept > 0 else { return side.standard }
        return Swift.min(Swift.max(kept, side.min), side.max)
    }

    /// Keep `width` as the column's width, once it is a real one (a hidden or collapsing column
    /// reports nothing worth keeping).
    static func remember(_ side: Side, _ width: CGFloat) {
        guard width >= side.min, width <= side.max + 1 else { return }
        UserDefaults.standard.set(Double(width.rounded()), forKey: side.key)
    }

    static let inspectorShownKey = "column.inspector.shown"

    /// Whether the inspector shows: shown until the person hides it.
    static var inspectorShown: Bool {
        UserDefaults.standard.object(forKey: inspectorShownKey) as? Bool ?? true
    }
}

extension View {
    /// Keep this column's width as it is dragged.
    func remembersWidth(of side: Columns.Side) -> some View {
        background(GeometryReader { geometry in
            Color.clear
                .onAppear { Columns.remember(side, geometry.size.width) }
                .onChange(of: geometry.size.width) { Columns.remember(side, $0) }
        })
    }
}

/// The line between the timeline and the inspector, which the person drags: the inspector's
/// width follows within its bounds and is kept when the drag ends. A resize cursor shows over it.
struct ColumnDivider: View {
    @Binding var width: CGFloat
    let side: Columns.Side
    @State private var start: CGFloat?

    var body: some View {
        Rectangle()
            .fill(Color.clear)
            .frame(width: 7)
            .overlay(Hairline(vertical: true))
            .contentShape(Rectangle())
            .onHover { inside in
                if inside { NSCursor.resizeLeftRight.push() } else { NSCursor.pop() }
            }
            .gesture(DragGesture(minimumDistance: 1, coordinateSpace: .global)
                .onChanged { drag in
                    let from = start ?? width
                    start = from
                    // Dragging left widens a column on the right.
                    width = Swift.min(Swift.max(from - drag.translation.width, side.min), side.max)
                }
                .onEnded { _ in
                    start = nil
                    Columns.remember(side, width)
                })
            .accessibilityElement()
            .accessibilityLabel("Inspector width")
            .accessibilityValue("\(Int(width)) points")
            .accessibilityIdentifier("inspector-divider")
    }
}
