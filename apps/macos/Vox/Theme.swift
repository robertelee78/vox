// The app's look, from the one token file (ADR-028 L-1): every colour, face and motion value here
// comes from VoxTokens, generated at build from assets/theme/vox-tokens.json. No view names a
// colour of its own.
//
// It respects the person's settings (L-5): Reduce Motion stills every animation, Increase
// Contrast lifts secondary text to primary, and Reduce Transparency is honoured by drawing on
// bg.base, never on a material, outside the navigation layer (L-6).

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
    static var heading: Font { font(VoxTokens.Fonts.appHeading, defaultSize: 28) }

    static func font(_ face: VoxTokens.Face, defaultSize: Double? = nil) -> Font {
        let weight = Font.Weight(face.weight)
        if let bundled = face.bundled, registered(bundled) {
            // A bundled file is one face: it is named by its PostScript name, the file's name.
            let postScript = (bundled as NSString).deletingPathExtension
            return .custom(postScript, size: face.size ?? defaultSize ?? 13)
        }
        switch face.system {
        case "monospaced":
            return .system(size: face.size ?? defaultSize ?? NSFont.systemFontSize, weight: weight,
                           design: .monospaced)
        default:
            if let size = face.size ?? defaultSize {
                return .system(size: size, weight: weight)
            }
            return .body.weight(weight)
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

extension View {
    /// Draw as secondary text.
    func secondaryText() -> some View { modifier(SecondaryText()) }

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
