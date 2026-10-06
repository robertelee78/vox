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

enum Theme {
    /// The face for running text: SF Pro (L-7).
    static var text: Font { font(VoxTokens.Fonts.appText) }
    /// Fingerprints, addresses and commands: SF Mono (L-7).
    static var mono: Font { font(VoxTokens.Fonts.appMono) }
    /// Uppercase eyebrow labels: SF Mono, tracked (L-7).
    static var eyebrow: Font { font(VoxTokens.Fonts.appEyebrow) }
    /// Large headings: Inter Display ExtraBold, which the app carries (L-7).
    static var heading: Font { font(VoxTokens.Fonts.appHeading, defaultSize: headingSize,
                                    relativeTo: .largeTitle) }
    /// A file's or folder's symbol in its card: the title style, so it follows the text size.
    static var glyph: Font { font(VoxTokens.Fonts.appGlyph) }

    /// A heading's size when the token file gives none.
    static let headingSize = 28.0

    /// `face` as a font. A bundled face scales with `relativeTo`; a system face that names a text
    /// style is that style; a size the token file gives is kept as it is.
    static func font(_ face: VoxTokens.Face, defaultSize: Double? = nil,
                     relativeTo: Font.TextStyle = .body) -> Font {
        let weight = Font.Weight(face.weight)
        if let bundled = face.bundled, registered(bundled) {
            // A bundled file is one face: it is named by its PostScript name, the file's name.
            let postScript = (bundled as NSString).deletingPathExtension
            return .custom(postScript, size: face.size ?? defaultSize ?? 13, relativeTo: relativeTo)
        }
        let design: Font.Design = face.system == "monospaced" ? .monospaced : .default
        if let size = face.size ?? defaultSize {
            return .system(size: size, weight: weight, design: design)
        }
        return .system(textStyle(face.system) ?? relativeTo, design: design).weight(weight)
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
private struct Typeset: ViewModifier {
    let face: VoxTokens.Face
    let font: Font
    let size: Double

    func body(content: Content) -> some View {
        content.font(font)
            .tracking(face.tracking * size)
            .textCase(face.uppercase ? .uppercase : nil)
    }
}

/// A card's outline: line.hair, or text.secondary under Increase Contrast (L-5).
private struct CardOutline: ViewModifier {
    @Environment(\.colorSchemeContrast) private var contrast

    func body(content: Content) -> some View {
        content.overlay(RoundedRectangle(cornerRadius: 6)
            .stroke(contrast == .increased ? VoxTokens.Colors.textSecondary
                                           : VoxTokens.Colors.lineHair))
    }
}

/// A selected row or card: drawn on bg.overlay, outlined in the focus accent under Increase
/// Contrast (L-3, L-5), and said to be selected.
private struct SelectionMark: ViewModifier {
    let selected: Bool
    @Environment(\.colorSchemeContrast) private var contrast

    func body(content: Content) -> some View {
        content
            .background(selected ? VoxTokens.Colors.bgOverlay : Color.clear)
            .overlay {
                if selected && contrast == .increased {
                    RoundedRectangle(cornerRadius: 4).stroke(VoxTokens.Colors.accent)
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
        let face = VoxTokens.Fonts.appEyebrow
        return modifier(Typeset(face: face, font: Theme.eyebrow,
                                size: face.size ?? NSFont.systemFontSize))
    }

    /// A large heading, in the token file's face and tracking (L-7).
    func heading() -> some View {
        let face = VoxTokens.Fonts.appHeading
        return modifier(Typeset(face: face, font: Theme.heading,
                                size: face.size ?? Theme.headingSize))
    }

    /// Outline a card (L-5).
    func cardOutline() -> some View { modifier(CardOutline()) }

    /// Mark a row or card selected, or not (L-3, L-5).
    func selectionMark(_ selected: Bool) -> some View { modifier(SelectionMark(selected: selected)) }

    /// A row or card selected by clicking it: marked when `selected`, and to assistive
    /// technologies one element that is a button and says whether it is selected.
    func selectable(_ selected: Bool, select: @escaping () -> Void) -> some View {
        accessibilityElement(children: .contain)
            .selectionMark(selected)
            .contentShape(Rectangle())
            .onTapGesture(perform: select)
            .accessibilityAddTraits(.isButton)
            .accessibilityAction(.default, select)
    }

    /// The content surface: bg.base, text.primary (L-6).
    func contentSurface() -> some View {
        background(VoxTokens.Colors.bgBase)
            .foregroundStyle(VoxTokens.Colors.textPrimary)
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
        HStack(spacing: 6) {
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
        HStack(spacing: 6) {
            Text(glyph).font(Theme.mono)
            Text(words)
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
