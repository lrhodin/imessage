import Foundation
import Combine

/// Manages the lifecycle of the bundled Go nac-relay binary.
class RelayManager: ObservableObject {
    @Published var isRunning = false
    @Published var relayAddress: String?
    @Published var logOutput: String = ""
    @Published var relayInfo: RelayInfo?
    @Published var errorMessage: String?

    private var process: Process?
    private var outputPipe: Pipe?
    private let port = 5001

    /// Path to the bundled nac-relay binary inside the .app bundle.
    private var binaryPath: String? {
        Bundle.main.path(forResource: "nac-relay", ofType: nil)
    }

    /// Directory where the Go relay stores its auth files.
    var relayDataDir: String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(home)/Library/Application Support/nac-relay"
    }

    private var relayInfoPath: String {
        "\(relayDataDir)/relay-info.json"
    }

    func start() {
        guard !isRunning else { return }
        guard let binary = binaryPath else {
            errorMessage = "nac-relay binary not found in app bundle"
            return
        }

        errorMessage = nil
        logOutput = ""

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: binary)
        proc.arguments = ["-port", "\(port)", "-addr", "0.0.0.0"]

        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        self.outputPipe = pipe

        proc.terminationHandler = { [weak self] p in
            DispatchQueue.main.async {
                self?.isRunning = false
                self?.relayAddress = nil
                if p.terminationStatus != 0 && p.terminationStatus != 15 {
                    self?.errorMessage = "Relay exited with status \(p.terminationStatus)"
                }
            }
        }

        // Read output asynchronously
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let line = String(data: data, encoding: .utf8) else { return }
            DispatchQueue.main.async {
                self?.logOutput += line
                // Keep log buffer bounded
                if let log = self?.logOutput, log.count > 10000 {
                    self?.logOutput = String(log.suffix(8000))
                }
            }
        }

        do {
            try proc.run()
            self.process = proc
            self.isRunning = true

            // Wait briefly for the relay to start and write relay-info.json
            DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) { [weak self] in
                self?.loadRelayInfo()
                self?.detectAddress()
            }
        } catch {
            errorMessage = "Failed to start relay: \(error.localizedDescription)"
        }
    }

    func stop() {
        guard let proc = process, proc.isRunning else { return }
        proc.terminate()
        outputPipe?.fileHandleForReading.readabilityHandler = nil
        process = nil
    }

    func loadRelayInfo() {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: relayInfoPath)),
              let info = try? JSONDecoder().decode(RelayInfo.self, from: data),
              !info.token.isEmpty, !info.certFingerprint.isEmpty else {
            return
        }
        DispatchQueue.main.async {
            self.relayInfo = info
        }
    }

    private func detectAddress() {
        let ips = getLocalIPAddresses()
        let addr = ips.first.map { "https://\($0):\(port)/validation-data" }
            ?? "https://localhost:\(port)/validation-data"
        DispatchQueue.main.async {
            self.relayAddress = addr
        }
    }
}
