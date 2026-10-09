// `vox uninstall` on a Mac: the app's background items are unregistered by the app itself, the
// one process macOS lets unregister what it registered (SMAppService). `vox uninstall` runs the
// installed app's executable with `--unregister-background-items`; it opens no window, starts no
// daemon, and exits.

import Foundation
import ServiceManagement

enum Uninstall {
    /// The flag `vox uninstall` passes (`crate::uninstall::UNREGISTER_FLAG`).
    static let flag = "--unregister-background-items"

    /// Unregister the login item and the LAN helper, say what was done on stdout, and exit: 0
    /// when both are unregistered (or were not registered), 1 with why on stderr otherwise.
    static func unregisterAndExit() -> Never {
        var said: [String] = []
        var failed: [String] = []
        let items: [(String, SMAppService)] = [
            ("the login item", .agent(plistName: "us.vox.daemon.plist")),
            ("the LAN helper", .daemon(plistName: "us.vox.lanhelper.plist")),
        ]
        for (name, item) in items {
            if item.status == .notRegistered {
                said.append("\(name) was not registered")
                continue
            }
            do {
                try item.unregister()
                said.append("\(name) is unregistered")
            } catch {
                failed.append("\(name): \(error.localizedDescription)")
            }
        }
        print(said.joined(separator: "; "))
        if !failed.isEmpty {
            FileHandle.standardError.write(Data((failed.joined(separator: "; ") + "\n").utf8))
            exit(1)
        }
        exit(0)
    }
}
