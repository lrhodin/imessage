import Foundation
import IOKit
import Combine

/// Reads hardware identifiers from IOKit and produces a base64-encoded
/// hardware key matching the format expected by the iMessage bridge.
///
/// This is a pure-Swift port of tools/extract-key/main.go.
class HardwareExtractor: ObservableObject {
    @Published var result: ExtractionResult?
    @Published var isExtracting = false
    @Published var errorMessage: String?

    func extract() {
        isExtracting = true
        errorMessage = nil

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                let result = try Self.performExtraction()
                DispatchQueue.main.async {
                    self?.result = result
                    self?.isExtracting = false
                }
            } catch {
                DispatchQueue.main.async {
                    self?.errorMessage = error.localizedDescription
                    self?.isExtracting = false
                }
            }
        }
    }

    // MARK: - Core extraction logic

    static func performExtraction() throws -> ExtractionResult {
        let nvramPrefix = "4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14"
        var warnings: [String] = []

        // 1. Open IOPlatformExpertDevice
        // Use 0 (MACH_PORT_NULL) for compatibility back to macOS 10.15
        guard let matching = IOServiceMatching("IOPlatformExpertDevice") else {
            throw ExtractionError.noIOPlatformExpertDevice
        }
        let platform = IOServiceGetMatchingService(0, matching)
        guard platform != IO_OBJECT_NULL else {
            throw ExtractionError.noIOPlatformExpertDevice
        }
        defer { IOObjectRelease(platform) }

        // 2. Plain-text identifiers
        let serial = ioString(platform, "IOPlatformSerialNumber") ?? ""
        let platformUUID = ioString(platform, "IOPlatformUUID") ?? ""
        var boardID = ioStringOrData(platform, "board-id")
        var productName = ioStringOrData(platform, "product-name")

        // Fallback: hw.model sysctl
        if productName == nil {
            productName = sysctlString("hw.model")
        }

        // 3. ROM and MLB from NVRAM
        var rom = ioData(platform, "\(nvramPrefix):ROM")
        var mlb: String? = ioStringOrData(platform, "\(nvramPrefix):MLB")

        // 4. Encrypted IOKit properties (present on Intel Macs)
        let serialEnc = ioData(platform, "Gq3489ugfi")
        let uuidEnc = ioData(platform, "Fyp98tpgj")
        let diskUUIDEnc = ioData(platform, "kbjfrfpoJU")
        let romEnc = ioData(platform, "oycqAZloTNDm")
        let mlbEnc = ioData(platform, "abKPld1EcMni")

        // 5. Detect Apple Silicon at runtime (the binary is x86_64 but may
        //    run under Rosetta on Apple Silicon hardware).
        let isAppleSilicon = isRunningOnAppleSilicon()

        if isAppleSilicon {
            // ROM: derive from en0 MAC address on Apple Silicon
            if rom == nil || rom?.isEmpty == true {
                rom = getEN0MACAddress()
            }
        }

        // 6. Apple Silicon: MLB from mlb-serial-number
        if mlb == nil {
            if let data = ioData(platform, "mlb-serial-number"), !data.isEmpty {
                var trimmed = Array(data)
                while trimmed.last == 0 { trimmed.removeLast() }
                if !trimmed.isEmpty {
                    mlb = String(bytes: trimmed, encoding: .utf8)
                }
            }
        }

        // 7. Fallback: IODeviceTree:/options
        if mlb == nil || rom == nil || rom?.isEmpty == true {
            let options = IORegistryEntryFromPath(0, "IODeviceTree:/options")
            if options != IO_OBJECT_NULL {
                defer { IOObjectRelease(options) }
                if mlb == nil {
                    mlb = ioStringOrData(options, "\(nvramPrefix):MLB")
                }
                if rom == nil || rom?.isEmpty == true {
                    rom = ioData(options, "\(nvramPrefix):ROM")
                }
            }
        }

        // 8. Fallback: nvram CLI
        if rom == nil || rom?.isEmpty == true {
            rom = nvramROM()
        }
        if mlb == nil {
            mlb = nvramMLB()
        }

        // 9. Other system info
        let osBuild = sysctlString("kern.osversion") ?? "unknown"
        let rootDiskUUID = getRootDiskUUID()
        let macAddress = getEN0MACAddress()

        // On Apple Silicon, board-id may be empty; use product name as fallback.
        if boardID == nil || boardID?.isEmpty == true {
            boardID = productName
        }

        let macOSVersion = getMacOSVersion()
        let darwinVersion = getDarwinVersion()

        // 10. Validate critical fields
        if serial.isEmpty { warnings.append("serial_number") }
        if platformUUID.isEmpty { warnings.append("platform_uuid") }
        if rom == nil || rom?.isEmpty == true { warnings.append("ROM") }
        if mlb == nil || mlb?.isEmpty == true { warnings.append("MLB") }
        if macAddress == nil || macAddress?.count != 6 { warnings.append("mac_address") }

        let hasEncFields = serialEnc != nil && !(serialEnc?.isEmpty ?? true)

        if isAppleSilicon {
            warnings.append(
                "Apple Silicon detected \u{2014} encrypted IOKit properties are absent. "
                + "You must run the NAC relay on this Mac and use -relay when extracting, "
                + "or enrich the key on Linux with enrich_hw_key."
            )
        } else if !hasEncFields {
            warnings.append(
                "Encrypted IOKit properties (_enc fields) not present on this Mac. "
                + "This is normal for older Intel models and macOS versions before Mojave. "
                + "The bridge will compute them automatically on Linux using enrich_hw_key."
            )
        }

        // 11. Build structs
        let hw = HardwareConfig(
            productName: productName ?? "",
            ioMacAddress: ByteArray(macAddress.map { Array($0) } ?? []),
            platformSerialNumber: serial,
            platformUUID: platformUUID,
            rootDiskUUID: rootDiskUUID,
            boardID: boardID ?? "",
            osBuildNum: osBuild,
            platformSerialNumberEnc: ByteArray(serialEnc.map { Array($0) } ?? []),
            platformUUIDEnc: ByteArray(uuidEnc.map { Array($0) } ?? []),
            rootDiskUUIDEnc: ByteArray(diskUUIDEnc.map { Array($0) } ?? []),
            rom: ByteArray(rom.map { Array($0) } ?? []),
            romEnc: ByteArray(romEnc.map { Array($0) } ?? []),
            mlb: mlb ?? "",
            mlbEnc: ByteArray(mlbEnc.map { Array($0) } ?? [])
        )

        let icloudUA = "com.apple.iCloudHelper/282 CFNetwork/1568.100.1 Darwin/\(darwinVersion)"

        let config = MacOSConfig(
            inner: hw,
            version: macOSVersion,
            protocolVersion: 1660,
            deviceID: platformUUID.uppercased(),
            icloudUA: icloudUA,
            aoskitVersion: "com.apple.AOSKit/282 (com.apple.accountsd/113)"
        )

        // 12. JSON → base64
        // Use manual ordered JSON serialization instead of JSONEncoder,
        // because JSONEncoder's keyed container uses NSDictionary internally
        // which does not preserve key insertion order.
        let jsonString = config.toOrderedJSON()
        let jsonData = Data(jsonString.utf8)
        let base64Key = jsonData.base64EncodedString()

        return ExtractionResult(
            config: config,
            base64Key: base64Key,
            warnings: warnings,
            isAppleSilicon: isAppleSilicon,
            hasEncFields: hasEncFields
        )
    }
}
