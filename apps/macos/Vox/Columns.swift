// The main window's two side columns, resizable and remembered (v0.4.1): the sidebar and the room's
// inspector each take a width the person drags, between a minimum that never clips their content
// and a maximum that leaves the timeline its room; each width, and whether the inspector shows, is
// kept in the app's defaults and used again at the next launch.

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
