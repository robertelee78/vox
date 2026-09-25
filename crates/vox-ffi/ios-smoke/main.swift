// The iOS-simulator check for VoxFFI.xcframework (PRD-001 R31): linked against the
// ios-arm64-simulator slice and run inside a simulator with `xcrun simctl spawn`
// (`scripts/ios-sim-smoke.sh`). It starts the embedded node in the simulated device's
// temporary directory, creates a room, posts to it and reads the post back.
//
// It proves the slice links and the node runs on iOS. It does not reach another node:
// a simulator shares the Mac's network, but nothing here drives a second member.

import Foundation

let dir = NSTemporaryDirectory() + "vox-ios-smoke-\(getpid())"
do {
    let node = try await VoxNode.start(dataDir: dir, passphrase: "ios smoke", listen: "127.0.0.1:0")
    let room = try await node.createRoom(name: "smoke", passphrase: "room passphrase")
    try await node.post(room: room, text: "hello from iOS")
    let read = try node.read(room: room)
    print("IOS OK fp=\(node.fingerprint()) room=\(room) messages=\(read.count) first=\(read.first?.text ?? "")")
    await node.stop()
} catch {
    print("IOS ERROR \(error)")
    exit(1)
}
