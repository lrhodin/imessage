import SwiftUI
#if canImport(AppKit)
import AppKit
#endif
#if canImport(UniformTypeIdentifiers)
import UniformTypeIdentifiers
#endif

struct ContentView: View {
    @StateObject private var extractor = HardwareExtractor()
    @State private var copied = false
    @State private var saved = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                headerSection

                if isRunningOnAppleSilicon() {
                    appleSiliconWarning
                }

                if extractor.isExtracting {
                    loadingSection
                } else if let error = extractor.errorMessage {
                    errorSection(error)
                } else if let result = extractor.result {
                    hardwareInfoSection(result)
                    if !result.warnings.isEmpty {
                        warningsSection(result.warnings)
                    }
                    keyOutputSection(result.base64Key)
                    actionsSection(result.base64Key)
                }

                Spacer()
            }
            .padding(24)
        }
        .frame(minWidth: 600, idealWidth: 700, minHeight: 900, idealHeight: 1000)
        .onAppear {
            extractor.extract()
        }
    }

    // MARK: - Header

    private var headerSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Hardware Key Extractor")
                .font(.title)
                .fontWeight(.bold)
            Text("Reads hardware identifiers for the iMessage bridge.")
                .font(.subheadline)
                .foregroundColor(.secondary)
        }
    }

    // MARK: - Apple Silicon Warning

    private var appleSiliconWarning: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(.orange)
                Text("Apple Silicon Mac Detected")
                    .fontWeight(.semibold)
            }
            Text("This tool is designed for Intel Macs. On Apple Silicon, the extracted key will be missing encrypted fields required by Apple. Use the NAC relay approach instead.")
                .font(.callout)
                .foregroundColor(.secondary)
        }
        .padding()
        .background(Color.orange.opacity(0.1))
        .cornerRadius(8)
    }

    // MARK: - Loading

    private var loadingSection: some View {
        HStack(spacing: 12) {
            ProgressView()
                .scaleEffect(0.8)
            Text("Reading hardware identifiers...")
                .foregroundColor(.secondary)
        }
        .padding(.vertical, 20)
    }

    // MARK: - Error

    private func errorSection(_ message: String) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: "xmark.circle.fill")
                    .foregroundColor(.red)
                Text("Extraction Failed")
                    .fontWeight(.semibold)
            }
            Text(message)
                .font(.callout)
                .foregroundColor(.secondary)
            Button("Retry") {
                extractor.extract()
            }
        }
        .padding()
        .background(Color.red.opacity(0.08))
        .cornerRadius(8)
    }

    // MARK: - Hardware Info

    private func hardwareInfoSection(_ result: ExtractionResult) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Hardware Info")
                .font(.headline)

            let hw = result.config.inner
            infoGrid([
                ("Model", hw.productName),
                ("Serial", hw.platformSerialNumber),
                ("Build", "\(hw.osBuildNum) (\(result.config.version))"),
                ("UUID", hw.platformUUID),
                ("Board ID", hw.boardID),
                ("MLB", hw.mlb),
                ("ROM", "\(hw.rom.count) bytes"),
                ("MAC", formatMAC(hw.ioMacAddress)),
                ("Disk UUID", hw.rootDiskUUID),
                ("Chip", chipDescription(result)),
                ("Enc Fields", encFieldsDescription(result)),
            ])
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private func infoGrid(_ items: [(String, String)]) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(items, id: \.0) { label, value in
                HStack(alignment: .top, spacing: 0) {
                    Text(label)
                        .fontWeight(.medium)
                        .frame(width: 90, alignment: .trailing)
                    Text("  ")
                    Text(value.isEmpty ? "(empty)" : value)
                        .foregroundColor(value.isEmpty ? .red : .primary)
                        .font(.system(.body, design: .monospaced))
                }
                .font(.callout)
            }
        }
    }

    private func formatMAC(_ mac: ByteArray) -> String {
        guard mac.count == 6 else { return "(missing)" }
        return mac.bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
    }

    private func chipDescription(_ result: ExtractionResult) -> String {
        if result.isAppleSilicon {
            return "Apple Silicon"
        } else if result.hasEncFields {
            return "Intel (has _enc fields)"
        } else {
            return "Intel (no _enc fields)"
        }
    }

    private func encFieldsDescription(_ result: ExtractionResult) -> String {
        let hw = result.config.inner
        let fields = [
            hw.platformSerialNumberEnc,
            hw.platformUUIDEnc,
            hw.rootDiskUUIDEnc,
            hw.romEnc,
            hw.mlbEnc,
        ]
        let present = fields.filter { !$0.isEmpty }.count
        return "\(present)/5 present"
    }

    // MARK: - Warnings

    private func warningsSection(_ warnings: [String]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(warnings, id: \.self) { warning in
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.yellow)
                        .font(.callout)
                    Text(warning)
                        .font(.callout)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding()
        .background(Color.yellow.opacity(0.08))
        .cornerRadius(8)
    }

    // MARK: - Key Output

    private func keyOutputSection(_ key: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Hardware Key")
                .font(.headline)
            Text("Paste this into the bridge login flow.")
                .font(.caption)
                .foregroundColor(.secondary)

            ScrollView(.vertical) {
                Text(key)
                    .font(.system(size: 11, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
            }
            .frame(height: 80)
            .background(Color(NSColor.textBackgroundColor))
            .cornerRadius(6)
            .overlay(
                RoundedRectangle(cornerRadius: 6)
                    .stroke(Color.gray.opacity(0.3), lineWidth: 1)
            )
        }
    }

    // MARK: - Actions

    private func actionsSection(_ key: String) -> some View {
        HStack(spacing: 12) {
            Button(action: { copyToClipboard(key) }) {
                HStack(spacing: 4) {
                    Image(systemName: copied ? "checkmark" : "doc.on.doc")
                    Text(copied ? "Copied" : "Copy to Clipboard")
                }
            }

            Button(action: { saveToFile(key) }) {
                HStack(spacing: 4) {
                    Image(systemName: saved ? "checkmark" : "square.and.arrow.down")
                    Text(saved ? "Saved" : "Save to File")
                }
            }

            Spacer()

            Button(action: {
                copied = false
                saved = false
                extractor.extract()
            }) {
                HStack(spacing: 4) {
                    Image(systemName: "arrow.clockwise")
                    Text("Re-extract")
                }
            }
        }
        .padding(.top, 4)
    }

    // MARK: - Clipboard & File

    private func copyToClipboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            copied = false
        }
    }

    private func saveToFile(_ text: String) {
        let panel = NSSavePanel()
        panel.title = "Save Hardware Key"
        panel.nameFieldStringValue = "hardware-key.txt"
        if #available(macOS 12.0, *) {
            panel.allowedContentTypes = [.plainText]
        } else {
            panel.allowedFileTypes = ["txt"]
        }
        panel.begin { response in
            if response == .OK, let url = panel.url {
                do {
                    try text.write(to: url, atomically: true, encoding: .utf8)
                    saved = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                        saved = false
                    }
                } catch {
                    // Best-effort save
                }
            }
        }
    }
}
