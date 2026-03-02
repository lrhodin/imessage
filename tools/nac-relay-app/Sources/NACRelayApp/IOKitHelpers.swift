import Foundation
import IOKit

/// Read a string property from an IOKit registry entry.
func ioString(_ entry: io_service_t, _ key: String) -> String? {
    guard let ref = IORegistryEntryCreateCFProperty(
        entry, key as CFString, kCFAllocatorDefault, 0
    ) else { return nil }

    let value = ref.takeRetainedValue()
    if CFGetTypeID(value) == CFStringGetTypeID() {
        return (value as! CFString) as String
    }
    return nil
}

/// Read a data property from an IOKit registry entry.
func ioData(_ entry: io_service_t, _ key: String) -> Data? {
    guard let ref = IORegistryEntryCreateCFProperty(
        entry, key as CFString, kCFAllocatorDefault, 0
    ) else { return nil }

    let value = ref.takeRetainedValue()
    if CFGetTypeID(value) == CFDataGetTypeID() {
        return (value as! CFData) as Data
    }
    return nil
}

/// Read a property that could be either a string or null-terminated data.
/// Tries string first, then data (stripping trailing null bytes).
func ioStringOrData(_ entry: io_service_t, _ key: String) -> String? {
    if let s = ioString(entry, key) { return s }
    if let data = ioData(entry, key), !data.isEmpty {
        // Strip trailing null bytes
        var trimmed = data
        while let last = trimmed.last, last == 0 {
            trimmed = trimmed.dropLast()
        }
        return String(data: Data(trimmed), encoding: .utf8)
    }
    return nil
}
