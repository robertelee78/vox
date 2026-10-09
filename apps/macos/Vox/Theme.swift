// The app's look, from the one token file (ADR-028 L-1): every colour, face and motion value here
// comes from VoxTokens, generated at build from assets/theme/vox-tokens.json. No view names a
// colour of its own.
//
// It respects the person's settings (L-5): Reduce Motion stills every animation. Increase
// Contrast lifts secondary text to primary, a hairline to text.secondary, and marks a selection
// with the focus accent (L-3); the token file has no high-contrast values, so it uses the ones it
// has. Reduce Transparency: content is drawn only in opaque token colours on bg.base, never on a
// material or a colour made translucent (L-6); the navigation layer's system material is the
// system's, which turns it opaque itself. A face that names a text style follows the system's text
// size; one the token file gives a fixed size keeps it.

import AppKit
import SwiftUI

/// The spacing scale and the two corner radii, from the token file (L-1a). Inside the
/// conversation they are taken at its text size (`voxPadding`, `voxTextScale`); elsewhere as they are.
typealias Space = VoxTokens.Space
typealias Radius = VoxTokens.Radius

enum Theme {
    /// The face for running text: SF Pro (L-7).
    static var text: Font { font(VoxTokens.Fonts.appText) }
    /// Fingerprints, addresses and commands: SF Mono (L-7).
    static var mono: Font { font(VoxTokens.Fonts.appMono) }
    /// Uppercase eyebrow labels: SF Mono, tracked (L-7).
    static var eyebrow: Font { font(VoxTokens.Fonts.appEyebrow) }
    /// Pane, sheet and dialog titles: SF Pro semibold (L-7), at a steady size.
    static var title: Font { font(VoxTokens.Fonts.appTitle) }
    /// Large headings, on the first-run screens only: Inter Display ExtraBold, which the app
    /// carries (L-7).
    static var heading: Font { font(VoxTokens.Fonts.appHeading, defaultSize: headingSize,
                                    relativeTo: .largeTitle) }
    /// A file's or folder's symbol in its card: the title style, so it follows the text size.
    static var glyph: Font { font(VoxTokens.Fonts.appGlyph) }

    /// A heading's size when the token file gives none.
    static let headingSize = 28.0

    /// The conversation's text size, a multiple of Actual Size (View > Bigger, Smaller, Actual
    /// Size, and Settings), up to twice its size (WCAG 2.1 1.4.4). The decider (v0.4.1): it scales
    /// the conversation only, the timeline and the composer, as in Messages and Slack; the sidebar
    /// and the inspector keep a steady size, the sidebar following macOS's sidebar size. Kept on
    /// this Mac.
    static var scale: Double {
        let kept = UserDefaults.standard.double(forKey: scaleKey)
        return scales.contains(kept) ? kept : 1
    }
    static let scaleKey = "textScale"
    /// Buttons, menus and toggles outside the conversation: a steady size.
    static var controls: ControlSize { .regular }
    /// Buttons and menus in the conversation, at its text size: macOS draws a control's label in
    /// the control's own size, not the view's font.
    static func controls(_ scale: Double) -> ControlSize {
        switch scale {
        case ..<1.15: return .regular
        case ..<1.75: return .large
        default:
            if #available(macOS 14, *) { return .extraLarge }
            return .large
        }
    }

    /// A width that holds text outside the conversation, whose text keeps a steady size.
    static func scaled(_ points: CGFloat) -> CGFloat { points }
    /// The sizes Bigger and Smaller step through.
    static let scales: [Double] = [0.85, 1, 1.15, 1.3, 1.5, 1.75, 2]

    /// `face` as a font. A bundled face scales with `relativeTo`; a system face that names a text
    /// style is that style; a size the token file gives is kept as it is.
    static func font(_ face: VoxTokens.Face, defaultSize: Double? = nil,
                     relativeTo: Font.TextStyle = .body, scale: Double = 1) -> Font {
        let weight = Font.Weight(face.weight)
        if let bundled = face.bundled, registered(bundled) {
            // A bundled file is one face: it is named by its PostScript name, the file's name.
            let postScript = (bundled as NSString).deletingPathExtension
            return .custom(postScript, size: (face.size ?? defaultSize ?? 13) * scale,
                           relativeTo: relativeTo)
        }
        let design: Font.Design = face.system == "monospaced" ? .monospaced : .default
        let size = face.size ?? defaultSize ?? points(textStyle(face.system) ?? relativeTo)
        return .system(size: size * scale, weight: weight, design: design)
    }

    /// macOS's size for a text style at Actual Size, in points.
    static func points(_ style: Font.TextStyle) -> Double {
        switch style {
        case .largeTitle: return 26
        case .title: return 22
        case .title2: return 17
        case .title3: return 15
        case .headline, .body: return 13
        case .callout: return 12
        case .subheadline: return 11
        case .footnote, .caption, .caption2: return 10
        @unknown default: return 13
        }
    }

    /// The text style a token's system role names, if it names one.
    private static func textStyle(_ role: String?) -> Font.TextStyle? {
        switch role {
        case "largeTitle": return .largeTitle
        case "title": return .title
        case "title2": return .title2
        case "title3": return .title3
        case "headline": return .headline
        case "subheadline": return .subheadline
        case "body": return .body
        case "callout": return .callout
        case "footnote": return .footnote
        case "caption": return .caption
        case "caption2": return .caption2
        default: return nil
        }
    }

    /// Whether the font file `name` ships in the bundle; registered for this process the first
    /// time it is asked for.
    private static func registered(_ name: String) -> Bool {
        if let known = fonts[name] { return known }
        let file = name as NSString
        var found = false
        if let url = Bundle.main.url(forResource: file.deletingPathExtension,
                                     withExtension: file.pathExtension) {
            found = CTFontManagerRegisterFontsForURL(url as CFURL, .process, nil)
        }
        fonts[name] = found
        return found
    }

    private static var fonts: [String: Bool] = [:]

    /// The app's one animation, or none under Reduce Motion (L-5).
    static func motion(reduced: Bool) -> Animation? {
        reduced ? nil : .spring(response: VoxTokens.Motion.appSpringResponseMs / 1000,
                                dampingFraction: VoxTokens.Motion.appSpringDamping)
    }
}

extension Font.Weight {
    /// A token's numeric weight (100–900).
    init(_ value: Int) {
        switch value {
        case ..<150: self = .ultraLight
        case ..<250: self = .thin
        case ..<350: self = .light
        case ..<450: self = .regular
        case ..<550: self = .medium
        case ..<650: self = .semibold
        case ..<750: self = .bold
        case ..<850: self = .heavy
        default: self = .black
        }
    }
}

/// Secondary text, lifted to primary under Increase Contrast (L-5).
struct SecondaryText: ViewModifier {
    @Environment(\.colorSchemeContrast) private var contrast

    func body(content: Content) -> some View {
        content.foregroundStyle(contrast == .increased ? VoxTokens.Colors.textPrimary
                                                       : VoxTokens.Colors.textSecondary)
    }
}

/// A face's tracking and case, which a `Font` cannot carry (L-7).
/// The conversation's text size, where one applies (`conversationScale`); 1 elsewhere.
private struct VoxTextScale: EnvironmentKey {
    static let defaultValue = 1.0
}

extension EnvironmentValues {
    var voxTextScale: Double {
        get { self[VoxTextScale.self] }
        set { self[VoxTextScale.self] = newValue }
    }
}

/// A face at the text size of where it is drawn.
private struct ScaledFont: ViewModifier {
    @Environment(\.voxTextScale) private var scale
    let face: VoxTokens.Face

    func body(content: Content) -> some View { content.font(Theme.font(face, scale: scale)) }
}

/// A typeset face (tracking, case) at the text size of where it is drawn.
private struct ScaledTypeset: ViewModifier {
    @Environment(\.voxTextScale) private var scale
    let face: VoxTokens.Face
    let defaultSize: Double
    var relativeTo: Font.TextStyle = .body
    var keepCase = false

    func body(content: Content) -> some View {
        content.modifier(Typeset(face: face,
                                 font: Theme.font(face, defaultSize: defaultSize,
                                                  relativeTo: relativeTo, scale: scale),
                                 size: (face.size ?? defaultSize) * scale, keepCase: keepCase))
    }
}

private struct Typeset: ViewModifier {
    let face: VoxTokens.Face
    let font: Font
    let size: Double
    /// Set the face's case: never for a caption, whose case is its content.
    var keepCase = false

    func body(content: Content) -> some View {
        content.font(font)
            .tracking(face.tracking * size)
            .textCase(face.uppercase && !keepCase ? .uppercase : nil)
    }
}

/// Every bordered button, drawn in SwiftUI so its label takes the app's face and text size (WCAG
/// 1.4.4: macOS draws its own buttons in a fixed control font): bg.overlay with a text.muted edge
/// (1.4.11), the label in text.primary, or danger for a destructive one; dimmer while pressed or
/// off. A button styled plain or borderless keeps its own.
struct VoxButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var enabled
    @Environment(\.voxTextScale) private var scale

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(Theme.font(VoxTokens.Fonts.appText, scale: scale))
            .foregroundStyle(configuration.role == .destructive ? VoxTokens.Colors.danger
                                                                : VoxTokens.Colors.textPrimary)
            .padding(.horizontal, Space.s12 * scale)
            .padding(.vertical, Space.s4 * scale)
            .background(RoundedRectangle(cornerRadius: Radius.control * scale)
                .fill(configuration.isPressed ? VoxTokens.Colors.bgPanel : VoxTokens.Colors.bgOverlay))
            .overlay(RoundedRectangle(cornerRadius: Radius.control * scale)
                .stroke(VoxTokens.Colors.textMuted))
            .opacity(enabled ? 1 : 0.45)
            .contentShape(Rectangle())
    }
}

/// A card's outline: text.muted, 4.5:1 or more on every background, since an outline is all that
/// marks a card's edge (WCAG 2.1 1.4.11); under Increase Contrast its token's hex_hc, which the
/// colour set carries (L-5, #450).
private struct CardOutline: ViewModifier {
    @Environment(\.voxTextScale) private var scale

    func body(content: Content) -> some View {
        content.overlay(RoundedRectangle(cornerRadius: Radius.control * scale)
            .stroke(VoxTokens.Colors.textMuted))
    }
}

/// Padding of a spacing step at the text size of where it is drawn (L-1a).
private struct ScaledPadding: ViewModifier {
    @Environment(\.voxTextScale) private var scale
    let edges: Edge.Set
    let points: CGFloat

    func body(content: Content) -> some View { content.padding(edges, points * scale) }
}

/// A selected row or card: drawn on bg.overlay with a bar in the accent at its leading edge, so
/// it is marked by more than its colour (WCAG 1.4.1, 1.4.11); outlined in the accent too under
/// Increase Contrast (L-3, L-5); and said to be selected.
private struct SelectionMark: ViewModifier {
    let selected: Bool
    /// The row the keyboard is on (WCAG 2.4.7): outlined in the focus accent, as well as marked.
    var focused = false
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.voxTextScale) private var scale

    func body(content: Content) -> some View {
        content
            .background(selected ? VoxTokens.Colors.bgOverlay : Color.clear)
            .overlay(alignment: .leading) {
                if selected {
                    Rectangle().fill(VoxTokens.Colors.accent).frame(width: 2)
                }
            }
            .overlay {
                if focused {
                    RoundedRectangle(cornerRadius: Radius.control * scale)
                        .stroke(VoxTokens.Colors.accent, lineWidth: 2)
                } else if selected && contrast == .increased {
                    RoundedRectangle(cornerRadius: Radius.control * scale)
                        .stroke(VoxTokens.Colors.accent)
                }
            }
            .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

extension View {
    /// Draw as secondary text.
    func secondaryText() -> some View { modifier(SecondaryText()) }

    /// An uppercase eyebrow label, in the token file's face, tracking and case (L-7).
    func eyebrow() -> some View {
        modifier(ScaledTypeset(face: VoxTokens.Fonts.appEyebrow, defaultSize: NSFont.systemFontSize))
    }

    /// The eyebrow's face, size and tracking, never its case: for what carries a name, a link or
    /// anything a person or a peer wrote, whose case is its content (an uppercased URL is another
    /// URL, an uppercased alias another name).
    func caption() -> some View {
        modifier(ScaledTypeset(face: VoxTokens.Fonts.appEyebrow, defaultSize: NSFont.systemFontSize,
                               keepCase: true))
    }

    /// A pane's, sheet's or dialog's title: SF Pro semibold, never scaled, and a header to
    /// assistive technologies (L-7).
    func title() -> some View {
        font(Theme.title).accessibilityAddTraits(.isHeader)
    }

    /// A large heading, in the token file's face and tracking (L-7): the first-run screens only
    /// (RootView's setup), never a pane, sheet or dialog.
    func heading() -> some View {
        modifier(ScaledTypeset(face: VoxTokens.Fonts.appHeading, defaultSize: Theme.headingSize,
                               relativeTo: .largeTitle))
    }

    /// The conversation's text size for everything inside: the timeline and the composer (the
    /// decider, v0.4.1). Outside it, text keeps a steady size.
    func conversationScale(_ scale: Double) -> some View {
        environment(\.voxTextScale, scale)
            .font(Theme.font(VoxTokens.Fonts.appText, scale: scale))
            .controlSize(Theme.controls(scale))
    }

    /// `face`, at the text size of where it is drawn: the conversation's inside it, steady outside.
    func voxFont(_ face: VoxTokens.Face) -> some View { modifier(ScaledFont(face: face)) }

    /// Padding of a spacing step (`Space`): at the conversation's text size inside it, as it is
    /// elsewhere (L-1a).
    func voxPadding(_ edges: Edge.Set, _ points: CGFloat) -> some View {
        modifier(ScaledPadding(edges: edges, points: points))
    }

    /// `voxPadding` on every edge.
    func voxPadding(_ points: CGFloat) -> some View {
        modifier(ScaledPadding(edges: .all, points: points))
    }

    /// Outline a card (L-5).
    func cardOutline() -> some View { modifier(CardOutline()) }

    /// Mark a row or card selected, or not (L-3, L-5).
    func selectionMark(_ selected: Bool) -> some View { modifier(SelectionMark(selected: selected)) }

    /// A row or card selected by clicking it: marked when `selected`, and to assistive
    /// technologies one element that is a button and says whether it is selected.
    func selectable(_ selected: Bool, focused: Bool = false,
                    select: @escaping () -> Void) -> some View {
        accessibilityElement(children: .contain)
            .modifier(SelectionMark(selected: selected, focused: focused))
            .contentShape(Rectangle())
            .onTapGesture(perform: select)
            .accessibilityAddTraits(.isButton)
            .accessibilityAction(.default, select)
    }

    /// The content surface, the timeline and the content panes: bg.base, text.primary (L-6).
    func contentSurface() -> some View {
        background(VoxTokens.Colors.bgBase)
            .foregroundStyle(VoxTokens.Colors.textPrimary)
    }

    /// The sidebar's and a sheet's surface: bg.panel, never the system's material (L-6).
    func panelSurface() -> some View {
        background(VoxTokens.Colors.bgPanel)
            .foregroundStyle(VoxTokens.Colors.textPrimary)
    }

    /// The inspector's and the status bar's surface: bg.raised (L-6).
    func raisedSurface() -> some View {
        background(VoxTokens.Colors.bgRaised)
            .foregroundStyle(VoxTokens.Colors.textPrimary)
    }
}

/// The line between two surfaces, or two parts of one: line.hair, one point wide, never the
/// system's divider (L-6).
struct Hairline: View {
    var vertical = false

    var body: some View {
        Rectangle().fill(VoxTokens.Colors.lineHair)
            .frame(width: vertical ? 1 : nil, height: vertical ? nil : 1)
            .accessibilityHidden(true)
    }
}

/// Whether a node is in this node's keyring, shown by glyph, weight and words, never by colour
/// alone (ADR-028 L-4, E-6).
enum Trust: Equatable {
    /// In the keyring, and it trusts this node back.
    case mutual
    /// In the keyring; it does not trust this node.
    case oneWay
    /// Not in the keyring.
    case none

    var glyph: String {
        switch self {
        case .mutual: return "⇄"
        case .oneWay: return "→"
        case .none: return "·"
        }
    }

    /// What the state is, in words.
    var words: String {
        switch self {
        case .mutual: return "in keyring, trusts you"
        case .oneWay: return "in keyring"
        case .none: return "not in keyring"
        }
    }
}

/// A member's name with its trust: in the keyring in text.primary bold with ⇄ or →; not in it
/// in text.secondary with · and the words "not in keyring" (L-4).
struct TrustMark: View {
    let name: String
    let trust: Trust

    var body: some View {
        HStack(spacing: Space.s8) {
            Text(trust.glyph).font(Theme.mono)
            Text(name).fontWeight(trust == .none ? .regular : .bold)
            if trust == .none {
                Text(trust.words).font(Theme.eyebrow)
            }
        }
        .modifier(TrustStyle(trust: trust))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(name), \(trust.words)")
    }
}

private struct TrustStyle: ViewModifier {
    let trust: Trust
    @Environment(\.colorSchemeContrast) private var contrast

    func body(content: Content) -> some View {
        content.foregroundStyle(trust == .none && contrast != .increased
                                ? VoxTokens.Colors.textSecondary : VoxTokens.Colors.textPrimary)
    }
}

/// A state stated in words with its glyph (E-6): live in the accent (L-3), attention with ▲,
/// danger with ✕, anything else plain.
struct StateMark: View {
    enum Kind {
        case live, attention, danger, plain
    }

    let kind: Kind
    let words: String

    var body: some View {
        HStack(spacing: Space.s8) {
            Text(glyph).font(Theme.mono)
            // Its own face: a sidebar list sets its rows' font over the one inherited.
            Text(words).font(Theme.text)
        }
        .foregroundStyle(color)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(words)
    }

    private var glyph: String {
        switch kind {
        case .live: return "●"
        case .attention: return "▲"
        case .danger: return "✕"
        case .plain: return "○"
        }
    }

    private var color: Color {
        switch kind {
        case .live: return VoxTokens.Colors.accent
        case .attention: return VoxTokens.Colors.attention
        case .danger: return VoxTokens.Colors.danger
        case .plain: return VoxTokens.Colors.textPrimary
        }
    }
}
