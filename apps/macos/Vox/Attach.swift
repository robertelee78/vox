// Attaching a file to the room (ADR-014 M-24, ADR-028 F-1): dropped on the timeline, pasted, or
// chosen with Attach…; then a To: and a note, sent as one share — the note and the addressees
// travel in the share itself, never as a message of their own.

import AppKit
import QuickLook
import SwiftUI
import UniformTypeIdentifiers

/// The file waiting for its To: and note.
struct Attaching: Identifiable {
    let url: URL
    var id: String { url.path }
}

/// To: and note for a file, then Send.
struct AttachSheet: View {
    @ObservedObject var model: NodeModel
    let file: Attaching
    let done: () -> Void
    @State private var to: Set<String> = []
    @State private var note = ""
    @State private var sending = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Share \(file.url.lastPathComponent)").heading()
            Text("TO").eyebrow().secondaryText()
            if model.members.isEmpty {
                Text("No one else is in this room yet.").secondaryText()
            }
            ForEach(model.members) { member in
                Toggle(isOn: Binding(get: { to.contains(member.id) },
                                     set: { on in if on { to.insert(member.id) } else { to.remove(member.id) } })) {
                    TrustMark(name: member.name, trust: member.trust)
                }
                .accessibilityIdentifier("attach-to-\(member.name)")
                .accessibilityLabel(to.contains(member.id)
                    ? "\(member.name), \(member.trust.words), addressed"
                    : "\(member.name), \(member.trust.words), not addressed")
            }
            Text(to.isEmpty ? "For the whole room." : "For the members ticked; the room sees it too.")
                .secondaryText()
            TextField("Note (optional)", text: $note)
                .accessibilityIdentifier("attach-note")
            HStack {
                Button("Cancel", action: done).keyboardShortcut(.cancelAction)
                Button("Share") {
                    sending = true
                    let (recipients, text) = (Array(to), note)
                    Task {
                        if await model.attach(file.url, to: recipients, note: text) { done() }
                        sending = false
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(sending)
                .accessibilityIdentifier("attach-send")
            }
            if let said = model.said {
                StateMark(kind: .danger, words: said).textSelection(.enabled)
            }
        }
        .padding(24)
        .frame(width: Theme.scaled(440))
    }
}

/// The first file URL among `providers`, handed to `found` on the main actor.
func firstFile(in providers: [NSItemProvider], _ found: @escaping @MainActor (URL) -> Void) -> Bool {
    guard let provider = providers.first(where: {
        $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier)
    }) else { return false }
    _ = provider.loadObject(ofClass: URL.self) { url, _ in
        guard let url, url.isFileURL else { return }
        Task { @MainActor in found(url) }
    }
    return true
}

/// The Finder Services item, "Share to Vox Room" (M-24): the file goes to the room on screen,
/// which asks its To: and note; with no room on screen, the first room the person opens does.
/// Declared by NSServices in the app's Info.plist, message `shareToVox`.
final class ServicesProvider: NSObject {
    private let app: AppModel

    init(app: AppModel) { self.app = app }

    @MainActor @objc func shareToVox(_ pasteboard: NSPasteboard, userData: String?,
                                     error: AutoreleasingUnsafeMutablePointer<NSString?>) {
        let urls = pasteboard.readObjects(forClasses: [NSURL.self],
                                          options: [.urlReadingFileURLsOnly: true]) as? [URL]
        guard let url = urls?.first else {
            error.pointee = "Vox was given no file to share." as NSString
            return
        }
        guard let node = app.node else {
            error.pointee = "Open Vox and attach its node first." as NSString
            return
        }
        node.incoming = url
        NSApp.activate(ignoringOtherApps: true)
    }
}

/// Choose a file or folder to attach (Attach…).
@MainActor
func chooseFile() -> URL? {
    let panel = NSOpenPanel()
    panel.canChooseFiles = true
    panel.canChooseDirectories = true
    panel.allowsMultipleSelection = false
    panel.prompt = "Attach"
    return panel.runModal() == .OK ? panel.url : nil
}
