import Foundation
import ServiceManagement

/// Manages "Start at Login" via SMAppService (macOS 13+).
class LoginItemManager: ObservableObject {
    @Published var isEnabled: Bool

    private let service = SMAppService.mainApp

    init() {
        isEnabled = SMAppService.mainApp.status == .enabled
    }

    func toggle() {
        do {
            if isEnabled {
                try service.unregister()
            } else {
                try service.register()
            }
            isEnabled = service.status == .enabled
        } catch {
            // Refresh state even on error
            isEnabled = service.status == .enabled
        }
    }
}
