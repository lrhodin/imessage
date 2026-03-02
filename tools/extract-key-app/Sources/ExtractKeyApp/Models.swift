import Foundation

// MARK: - ByteArray

/// A wrapper around [UInt8] that encodes to/from a JSON array of integers
/// (e.g. [10, 20, 30]) matching Rust's serde serialize_bytes format.
/// Empty values serialize as [] (not null).
struct ByteArray: Codable, Equatable {
    var bytes: [UInt8]

    init(_ bytes: [UInt8] = []) {
        self.bytes = bytes
    }

    init(_ data: Data) {
        self.bytes = Array(data)
    }

    var isEmpty: Bool { bytes.isEmpty }
    var count: Int { bytes.count }

    func encode(to encoder: Encoder) throws {
        var container = encoder.unkeyedContainer()
        for byte in bytes {
            try container.encode(Int(byte))
        }
    }

    init(from decoder: Decoder) throws {
        var container = try decoder.unkeyedContainer()
        var result: [UInt8] = []
        while !container.isAtEnd {
            let val = try container.decode(UInt8.self)
            result.append(val)
        }
        self.bytes = result
    }

    /// Hex representation for display.
    var hexString: String {
        bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
    }

    /// JSON array string like [10,20,30] — matches Go/Rust output.
    var jsonArray: String {
        "[\(bytes.map { String($0) }.joined(separator: ","))]"
    }
}

// MARK: - HardwareConfig

/// Matches rustpush/open-absinthe/src/nac.rs HardwareConfig exactly.
struct HardwareConfig: Codable {
    var productName: String
    var ioMacAddress: ByteArray
    var platformSerialNumber: String
    var platformUUID: String
    var rootDiskUUID: String
    var boardID: String
    var osBuildNum: String
    var platformSerialNumberEnc: ByteArray
    var platformUUIDEnc: ByteArray
    var rootDiskUUIDEnc: ByteArray
    var rom: ByteArray
    var romEnc: ByteArray
    var mlb: String
    var mlbEnc: ByteArray

    enum CodingKeys: String, CodingKey {
        case productName = "product_name"
        case ioMacAddress = "io_mac_address"
        case platformSerialNumber = "platform_serial_number"
        case platformUUID = "platform_uuid"
        case rootDiskUUID = "root_disk_uuid"
        case boardID = "board_id"
        case osBuildNum = "os_build_num"
        case platformSerialNumberEnc = "platform_serial_number_enc"
        case platformUUIDEnc = "platform_uuid_enc"
        case rootDiskUUIDEnc = "root_disk_uuid_enc"
        case rom
        case romEnc = "rom_enc"
        case mlb
        case mlbEnc = "mlb_enc"
    }
}

// MARK: - MacOSConfig

/// Matches rustpush/src/macos.rs MacOSConfig.
struct MacOSConfig: Codable {
    var inner: HardwareConfig
    var version: String
    var protocolVersion: UInt32
    var deviceID: String
    var icloudUA: String
    var aoskitVersion: String

    enum CodingKeys: String, CodingKey {
        case inner
        case version
        case protocolVersion = "protocol_version"
        case deviceID = "device_id"
        case icloudUA = "icloud_ua"
        case aoskitVersion = "aoskit_version"
    }
}

// MARK: - Ordered JSON Serialization

/// Escape a string for JSON output (handles quotes, backslashes, control chars).
/// Does NOT escape forward slashes (matching Go's json.Marshal).
private func jsonEscape(_ s: String) -> String {
    var result = ""
    for c in s {
        switch c {
        case "\"": result += "\\\""
        case "\\": result += "\\\\"
        case "\n": result += "\\n"
        case "\r": result += "\\r"
        case "\t": result += "\\t"
        default:
            if c.asciiValue != nil && c.asciiValue! < 0x20 {
                result += String(format: "\\u%04x", c.asciiValue!)
            } else {
                result.append(c)
            }
        }
    }
    return result
}

extension HardwareConfig {
    /// Serialize to JSON with key order matching Go's struct field declaration order.
    /// Swift's JSONEncoder uses NSDictionary internally which is unordered,
    /// so we build the JSON string manually.
    func toOrderedJSON() -> String {
        let pairs: [(String, String)] = [
            ("product_name", "\"\(jsonEscape(productName))\""),
            ("io_mac_address", ioMacAddress.jsonArray),
            ("platform_serial_number", "\"\(jsonEscape(platformSerialNumber))\""),
            ("platform_uuid", "\"\(jsonEscape(platformUUID))\""),
            ("root_disk_uuid", "\"\(jsonEscape(rootDiskUUID))\""),
            ("board_id", "\"\(jsonEscape(boardID))\""),
            ("os_build_num", "\"\(jsonEscape(osBuildNum))\""),
            ("platform_serial_number_enc", platformSerialNumberEnc.jsonArray),
            ("platform_uuid_enc", platformUUIDEnc.jsonArray),
            ("root_disk_uuid_enc", rootDiskUUIDEnc.jsonArray),
            ("rom", rom.jsonArray),
            ("rom_enc", romEnc.jsonArray),
            ("mlb", "\"\(jsonEscape(mlb))\""),
            ("mlb_enc", mlbEnc.jsonArray),
        ]
        let body = pairs.map { "\"\($0.0)\":\($0.1)" }.joined(separator: ",")
        return "{\(body)}"
    }
}

extension MacOSConfig {
    /// Serialize to JSON with key order matching Go's struct field declaration order.
    func toOrderedJSON() -> String {
        let pairs: [(String, String)] = [
            ("inner", inner.toOrderedJSON()),
            ("version", "\"\(jsonEscape(version))\""),
            ("protocol_version", "\(protocolVersion)"),
            ("device_id", "\"\(jsonEscape(deviceID))\""),
            ("icloud_ua", "\"\(jsonEscape(icloudUA))\""),
            ("aoskit_version", "\"\(jsonEscape(aoskitVersion))\""),
        ]
        let body = pairs.map { "\"\($0.0)\":\($0.1)" }.joined(separator: ",")
        return "{\(body)}"
    }
}

// MARK: - ExtractionResult

/// Result returned by the hardware extractor for the UI.
struct ExtractionResult {
    var config: MacOSConfig
    var base64Key: String
    var warnings: [String]
    var isAppleSilicon: Bool
    var hasEncFields: Bool
}

// MARK: - ExtractionError

enum ExtractionError: Error, LocalizedError {
    case noIOPlatformExpertDevice

    var errorDescription: String? {
        switch self {
        case .noIOPlatformExpertDevice:
            return "Failed to find IOPlatformExpertDevice in IOKit registry"
        }
    }
}
