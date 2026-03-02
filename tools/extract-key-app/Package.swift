// swift-tools-version: 5.9
import PackageDescription
import Foundation

// Resolve the library path relative to Package.swift's location.
// build.sh places libxnu_encrypt.a in .build/lib/ before invoking swift build.
let packageDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let libDir = packageDir + "/.build/lib"

let package = Package(
    name: "ExtractKeyApp",
    platforms: [
        .macOS(.v10_15)
    ],
    targets: [
        .target(
            name: "CEncrypt",
            path: "Sources/CEncrypt",
            publicHeadersPath: "include"
        ),
        .executableTarget(
            name: "ExtractKeyApp",
            dependencies: ["CEncrypt"],
            path: "Sources/ExtractKeyApp",
            linkerSettings: [
                .linkedFramework("IOKit"),
                .linkedFramework("DiskArbitration"),
                .unsafeFlags(["-L\(libDir)", "-lxnu_encrypt"]),
            ]
        )
    ]
)
