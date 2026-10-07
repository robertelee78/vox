// Renders Vox.app's views offscreen into PNGs for documentation and release notes (ADR-014 M-34),
// from a demo data root `scripts/app-screenshots.sh` makes. Not part of Vox.app: the script
// compiles it with the app's own view sources, and it acts as a demo node through VoxClient as
// the app does. The views are hosted in a window that is never shown, and drawn into bitmaps.
// They show the look; they are not product proof.
//
//   VoxScreens <out dir> <demo data root> <node> <room name>

import AppKit
import SwiftUI

let args = CommandLine.arguments
guard args.count == 5 else {
    FileHandle.standardError.write("usage: VoxScreens <out> <data root> <node> <room>\n".data(using: .utf8)!)
    exit(2)
}
let (out, dataRoot, nodeName, roomName) = (URL(fileURLWithPath: args[1]), args[2], args[3], args[4])

let app = NSApplication.shared
app.setActivationPolicy(.prohibited)

/// Let the views' tasks and the node's events run for `seconds`.
@MainActor
func settle(_ seconds: Double) {
    RunLoop.main.run(until: Date().addingTimeInterval(seconds))
}

/// Let the model's own tasks run for `seconds`: its room loop (who read, who pulled) runs on the
/// main actor, which a run loop spun inside this task would hold the whole time.
@MainActor
func wait(_ seconds: Double) async {
    try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
}

/// Draw `view` at `size` in a window that is never shown, and write it to `name`.png.
@MainActor
func render<V: View>(_ view: V, _ name: String, size: CGSize = CGSize(width: 1280, height: 800)) throws {
    let host = NSHostingView(rootView: view.frame(width: size.width, height: size.height)
        .preferredColorScheme(.dark))
    let window = NSWindow(contentRect: CGRect(origin: .zero, size: size), styleMask: [.borderless],
                          backing: .buffered, defer: false)
    window.appearance = NSAppearance(named: .darkAqua)
    window.contentView = host
    host.layoutSubtreeIfNeeded()
    settle(1.5)
    guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else {
        throw NSError(domain: "VoxScreens", code: 1, userInfo: [NSLocalizedDescriptionKey: "no bitmap for \(name)"])
    }
    host.cacheDisplay(in: host.bounds, to: bitmap)
    guard let png = bitmap.representation(using: .png, properties: [:]) else {
        throw NSError(domain: "VoxScreens", code: 2, userInfo: [NSLocalizedDescriptionKey: "no PNG for \(name)"])
    }
    try png.write(to: out.appendingPathComponent("\(name).png"))
    print("wrote \(out.appendingPathComponent("\(name).png").path)")
}

Task { @MainActor in
    do {
        let client = try await VoxClient.open(dataRoot: dataRoot)
        let me = try await client.attach(node: nodeName, passphrase: nil)
        let model = NodeModel(client: client, node: nodeName, me: me, notify: false)
        await model.start()
        await wait(2)
        guard let room = model.rooms.first(where: { $0.name == roomName }) else {
            throw NSError(domain: "VoxScreens", code: 3,
                          userInfo: [NSLocalizedDescriptionKey: "the demo node holds no room \(roomName)"])
        }
        await model.show(.room(room.id))
        await wait(3)
        try render(MainWindow(model: model), "main-window")
        // A trust offer waiting on ann: cam joined and trusts her (ADR-028 K-15).
        if let offer = model.offers.first {
            await model.show(.offer(offer.fingerprint))
            await wait(1)
            try render(MainWindow(model: model), "offer")
        }
        await model.show(.keyring)
        await wait(1)
        try render(MainWindow(model: model), "keyring")
        await model.show(.decisions)
        await wait(4)
        try render(MainWindow(model: model), "decision-record")
        await client.close()
        exit(0)
    } catch {
        FileHandle.standardError.write("VoxScreens: \(sentence(error))\n".data(using: .utf8)!)
        exit(1)
    }
}
app.run()
