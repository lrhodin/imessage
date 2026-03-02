import SwiftUI

struct PopoverView: View {
    @ObservedObject var relay: RelayManager
    @ObservedObject var extractor: KeyExtractor
    @ObservedObject var loginItem: LoginItemManager
    @State private var copied = false
    @State private var showLog = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            // Header
            HStack {
                Text("NAC Relay")
                    .font(.headline)
                Spacer()
                Circle()
                    .fill(relay.isRunning ? Color.green : Color.red)
                    .frame(width: 8, height: 8)
                Text(relay.isRunning ? "Running" : "Stopped")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Divider()

            // Relay address
            if let addr = relay.relayAddress, relay.isRunning {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Relay Address")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text(addr)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
            }

            // Relay token info
            if let info = relay.relayInfo, relay.isRunning {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Auth Token")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    let t = info.token
                    Text("\(t.prefix(8))...\(t.suffix(8))")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.secondary)
                }
            }

            // Error message
            if let err = relay.errorMessage {
                Text(err)
                    .font(.caption)
                    .foregroundColor(.red)
            }

            // Start/Stop button
            Button(action: {
                if relay.isRunning {
                    relay.stop()
                } else {
                    relay.start()
                }
            }) {
                HStack {
                    Image(systemName: relay.isRunning ? "stop.fill" : "play.fill")
                    Text(relay.isRunning ? "Stop Relay" : "Start Relay")
                }
                .frame(maxWidth: .infinity)
            }
            .controlSize(.large)

            Divider()

            // Hardware Key section
            Text("Hardware Key")
                .font(.headline)

            if let result = extractor.result {
                // Warnings
                ForEach(result.warnings, id: \.self) { warning in
                    HStack(alignment: .top, spacing: 4) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.yellow)
                            .font(.caption)
                        Text(warning)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                // Key output
                VStack(alignment: .leading, spacing: 4) {
                    Text(result.base64Key.prefix(60) + "...")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundColor(.secondary)
                        .lineLimit(2)

                    HStack {
                        Button(action: {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(result.base64Key, forType: .string)
                            copied = true
                            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                                copied = false
                            }
                        }) {
                            HStack {
                                Image(systemName: copied ? "checkmark" : "doc.on.doc")
                                Text(copied ? "Copied!" : "Copy Key")
                            }
                        }

                        Spacer()

                        Button("Re-extract") {
                            extractor.extract(
                                relayURL: relay.relayAddress,
                                relayInfo: relay.relayInfo
                            )
                        }
                    }
                }
            } else if extractor.isExtracting {
                HStack {
                    ProgressView()
                        .controlSize(.small)
                    Text("Extracting...")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            } else {
                if let err = extractor.errorMessage {
                    Text(err)
                        .font(.caption)
                        .foregroundColor(.red)
                }
                Button(action: {
                    extractor.extract(
                        relayURL: relay.relayAddress,
                        relayInfo: relay.relayInfo
                    )
                }) {
                    HStack {
                        Image(systemName: "key")
                        Text("Extract Hardware Key")
                    }
                    .frame(maxWidth: .infinity)
                }
                .controlSize(.large)
            }

            Divider()

            // Log toggle
            if relay.isRunning {
                DisclosureGroup("Relay Log", isExpanded: $showLog) {
                    ScrollView {
                        Text(relay.logOutput.isEmpty ? "(waiting for output...)" : relay.logOutput)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundColor(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(height: 100)
                }
                .font(.caption)
            }

            // Footer: Start at Login + Quit
            HStack {
                Toggle("Start at Login", isOn: Binding(
                    get: { loginItem.isEnabled },
                    set: { _ in loginItem.toggle() }
                ))
                .toggleStyle(.checkbox)
                .font(.caption)

                Spacer()

                Button("Quit") {
                    relay.stop()
                    NSApplication.shared.terminate(nil)
                }
                .controlSize(.small)
            }
        }
        .padding()
        .frame(width: 320)
        .fixedSize()
    }
}
