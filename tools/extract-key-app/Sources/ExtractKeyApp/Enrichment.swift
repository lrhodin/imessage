import Foundation
import CEncrypt

/// Encrypt a plaintext IOKit property value using the XNU kernel function.
/// Returns 17 bytes of encrypted output.
func encryptIOProperty(_ data: [UInt8]) -> [UInt8] {
    var output = [UInt8](repeating: 0, count: 17)
    data.withUnsafeBufferPointer { buf in
        sub_ffffff8000ec7320(buf.baseAddress, UInt64(buf.count), &output)
    }
    return output
}

/// Parse a UUID string like "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" into 16 raw bytes.
func uuidStringToBytes(_ uuid: String) -> [UInt8]? {
    let hex = uuid.replacingOccurrences(of: "-", with: "")
    guard hex.count == 32 else { return nil }
    var bytes = [UInt8]()
    var i = hex.startIndex
    while i < hex.endIndex {
        let end = hex.index(i, offsetBy: 2)
        guard let byte = UInt8(hex[i..<end], radix: 16) else { return nil }
        bytes.append(byte)
        i = end
    }
    return bytes
}

/// Enrich a HardwareConfig by computing any missing _enc fields from plaintext values.
/// Uses the XNU kernel encryption function linked from encrypt.s.
func enrichMissingEncFields(_ hw: inout HardwareConfig) {
    // platform_serial_number → Gq3489ugfi
    if hw.platformSerialNumberEnc.isEmpty && !hw.platformSerialNumber.isEmpty {
        hw.platformSerialNumberEnc = ByteArray(encryptIOProperty(Array(hw.platformSerialNumber.utf8)))
    }

    // platform_uuid → Fyp98tpgj (UUID as 16 raw bytes)
    if hw.platformUUIDEnc.isEmpty && !hw.platformUUID.isEmpty {
        if let uuidBytes = uuidStringToBytes(hw.platformUUID) {
            hw.platformUUIDEnc = ByteArray(encryptIOProperty(uuidBytes))
        }
    }

    // root_disk_uuid → kbjfrfpoJU (UUID as 16 raw bytes)
    if hw.rootDiskUUIDEnc.isEmpty && !hw.rootDiskUUID.isEmpty {
        if let uuidBytes = uuidStringToBytes(hw.rootDiskUUID) {
            hw.rootDiskUUIDEnc = ByteArray(encryptIOProperty(uuidBytes))
        }
    }

    // mlb → abKPld1EcMni
    if hw.mlbEnc.isEmpty && !hw.mlb.isEmpty {
        hw.mlbEnc = ByteArray(encryptIOProperty(Array(hw.mlb.utf8)))
    }

    // rom → oycqAZloTNDm (6 raw bytes)
    if hw.romEnc.isEmpty && !hw.rom.isEmpty {
        hw.romEnc = ByteArray(encryptIOProperty(hw.rom.bytes))
    }
}
