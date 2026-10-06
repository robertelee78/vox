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
        settle(2)
        guard let room = model.rooms.first(where: { $0.name == roomName }) else {
            throw NSError(domain: "VoxScreens", code: 3,
                          userInfo: [NSLocalizedDescriptionKey: "the demo node holds no room \(roomName)"])
        }
        await model.show(.room(room.id))
        settle(3)
        try render(MainWindow(model: model), "main-window")
        if model.roomHasAgents {
            model.showLanes = true
            settle(1)
            try render(MainWindow(model: model), "lanes")
            model.showLanes = false
        }
        await model.show(.keyring)
        settle(1)
        try render(MainWindow(model: model), "keyring")
        await model.show(.decisions)
        settle(4)
        try render(MainWindow(model: model), "decision-record")
        await client.close()
        exit(0)
    } catch {
        FileHandle.standardError.write("VoxScreens: \(sentence(error))\n".data(using: .utf8)!)
        exit(1)
    }
}
app.run()
