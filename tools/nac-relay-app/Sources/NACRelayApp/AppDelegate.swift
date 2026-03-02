import SwiftUI
import AppKit
import ServiceManagement

@main
class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    var popover: NSPopover!
    let relay = RelayManager()
    let extractor = KeyExtractor()
    let loginItem = LoginItemManager()

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
        popover.behavior = .transient
        let hostingController = NSHostingController(
            rootView: PopoverView(relay: relay, extractor: extractor, loginItem: loginItem)
        )
        // Let the SwiftUI view determine the popover size
        hostingController.view.setFrameSize(NSSize(width: 340, height: 1))
        popover.contentViewController = hostingController

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
