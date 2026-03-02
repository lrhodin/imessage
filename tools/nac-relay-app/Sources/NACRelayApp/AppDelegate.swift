import SwiftUI
import AppKit

@main
class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    var popover: NSPopover!
    let relay = RelayManager()
    let extractor = KeyExtractor()

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Create the status bar item
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "antenna.radiowaves.left.and.right",
                                   accessibilityDescription: "NAC Relay")
            button.action = #selector(togglePopover)
            button.target = self
        }

        // Create the popover with SwiftUI content
        popover = NSPopover()
        popover.contentSize = NSSize(width: 340, height: 500)
        popover.behavior = .transient
        popover.contentViewController = NSHostingController(
            rootView: PopoverView(relay: relay, extractor: extractor)
        )

        // Auto-start the relay
        relay.start()
    }

    @objc func togglePopover() {
        guard let button = statusItem.button else { return }
        if popover.isShown {
            popover.performClose(nil)
        } else {
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            // Bring app to front
            NSApplication.shared.activate(ignoringOtherApps: true)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return false // menubar app stays alive
    }

    func applicationWillTerminate(_ notification: Notification) {
        relay.stop()
    }

    static func main() {
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()
    }
}
