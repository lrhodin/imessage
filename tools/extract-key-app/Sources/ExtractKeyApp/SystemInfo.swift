import Foundation
import DiskArbitration

// MARK: - MAC Address

/// Get the en0 MAC address (6 bytes) via getifaddrs.
func getEN0MACAddress() -> Data? {
    var ifaddrsPtr: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifaddrsPtr) == 0, let firstAddr = ifaddrsPtr else { return nil }
    defer { freeifaddrs(firstAddr) }

    var cursor: UnsafeMutablePointer<ifaddrs>? = firstAddr
    while let ifa = cursor {
        defer { cursor = ifa.pointee.ifa_next }
        let name = String(cString: ifa.pointee.ifa_name)
        guard name == "en0",
              let addr = ifa.pointee.ifa_addr,
              addr.pointee.sa_family == UInt8(AF_LINK) else { continue }

        return addr.withMemoryRebound(to: sockaddr_dl.self, capacity: 1) { sdl in
            guard sdl.pointee.sdl_alen == 6 else { return nil }
            // Link-layer address starts at sdl_data + sdl_nlen
            return withUnsafePointer(to: sdl.pointee.sdl_data) { dataPtr in
                let rawPtr = UnsafeRawPointer(dataPtr)
                    .advanced(by: Int(sdl.pointee.sdl_nlen))
                return Data(bytes: rawPtr, count: 6)
            }
        }
    }
    return nil
}

// MARK: - Root Disk UUID

/// Get the UUID of the root filesystem volume via DiskArbitration.
func getRootDiskUUID() -> String {
    guard let session = DASessionCreate(kCFAllocatorDefault) else { return "unknown" }

    var sfs = statfs()
    guard statfs("/", &sfs) == 0 else { return "unknown" }

    let bsdName: String = withUnsafePointer(to: &sfs.f_mntfromname) {
        $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
            String(cString: $0)
        }
    }

    guard let disk = DADiskCreateFromBSDName(kCFAllocatorDefault, session, bsdName) else {
        return "unknown"
    }
    guard let desc = DADiskCopyDescription(disk) as? [CFString: Any] else {
        return "unknown"
    }

    // kDADiskDescriptionVolumeUUIDKey returns a CFUUID
    let key = kDADiskDescriptionVolumeUUIDKey as String
    for (k, v) in desc {
        if (k as String) == key {
            let uuid = v as! CFUUID
            if let str = CFUUIDCreateString(kCFAllocatorDefault, uuid) {
                return str as String
            }
        }
    }
    return "unknown"
}

// MARK: - Architecture Detection

/// Detect Apple Silicon at runtime. Works even when running an x86_64
/// binary under Rosetta on Apple Silicon hardware.
func isRunningOnAppleSilicon() -> Bool {
    // sysctl "sysctl.proc_translated" returns 1 when running under Rosetta.
    var ret: Int32 = 0
    var size = MemoryLayout<Int32>.size
    if sysctlbyname("sysctl.proc_translated", &ret, &size, nil, 0) == 0 && ret == 1 {
        return true // x86_64 binary running under Rosetta on Apple Silicon
    }
    // Native arm64 binary on Apple Silicon
    #if arch(arm64)
    return true
    #else
    return false
    #endif
}

// MARK: - Sysctl

/// Read a sysctl string value by name.
func sysctlString(_ name: String) -> String? {
    var size: Int = 0
    guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
    var buf = [CChar](repeating: 0, count: size)
    guard sysctlbyname(name, &buf, &size, nil, 0) == 0 else { return nil }
    return String(cString: buf)
}

// MARK: - Process Helpers

/// Run a subprocess and return its stdout as a string.
func runProcess(_ path: String, args: [String]) -> String? {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: path)
    proc.arguments = args
    let pipe = Pipe()
    proc.standardOutput = pipe
    proc.standardError = FileHandle.nullDevice
    do {
        try proc.run()
        proc.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8)
    } catch {
        return nil
    }
}

// MARK: - NVRAM Fallbacks

/// Decode nvram percent-encoded binary output (e.g. "%1e%eb%08n%ae").
private func decodeNVRAMPercent(_ input: String) -> Data? {
    var bytes: [UInt8] = []
    var i = input.startIndex
    while i < input.endIndex {
        if input[i] == "%" {
            let hexStart = input.index(after: i)
            guard hexStart < input.endIndex else { break }
            let hexEnd = input.index(hexStart, offsetBy: 2, limitedBy: input.endIndex)
                ?? input.endIndex
            let hex = String(input[hexStart..<hexEnd])
            if let byte = UInt8(hex, radix: 16) {
                bytes.append(byte)
            }
            i = hexEnd
        } else {
            bytes.append(UInt8(input[i].asciiValue ?? 0))
            i = input.index(after: i)
        }
    }
    return bytes.isEmpty ? nil : Data(bytes)
}

/// Read ROM from nvram CLI (fallback when IOKit doesn't expose it).
func nvramROM() -> Data? {
    guard let output = runProcess(
        "/usr/sbin/nvram",
        args: ["4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:ROM"]
    ) else { return nil }
    guard let tabIdx = output.firstIndex(of: "\t") else { return nil }
    let value = String(output[output.index(after: tabIdx)...])
        .trimmingCharacters(in: .newlines)
    return decodeNVRAMPercent(value)
}

/// Read MLB from nvram CLI (plain text after tab).
func nvramMLB() -> String? {
    guard let output = runProcess(
        "/usr/sbin/nvram",
        args: ["4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:MLB"]
    ) else { return nil }
    guard let tabIdx = output.firstIndex(of: "\t") else { return nil }
    let value = String(output[output.index(after: tabIdx)...])
        .trimmingCharacters(in: .newlines)
    return value.isEmpty ? nil : value
}

// MARK: - Version Info

/// Get the macOS version string (e.g. "14.3.1").
func getMacOSVersion() -> String {
    if let output = runProcess("/usr/bin/sw_vers", args: ["-productVersion"]) {
        return output.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    return "14.0"
}

/// Get the Darwin kernel version string (e.g. "23.3.0").
func getDarwinVersion() -> String {
    if let output = runProcess("/usr/bin/uname", args: ["-r"]) {
        return output.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    return "22.5.0"
}
