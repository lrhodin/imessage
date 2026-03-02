// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "NACRelayApp",
    platforms: [
        .macOS(.v13)
    ],
    targets: [
        .executableTarget(
            name: "NACRelayApp",
            path: "Sources/NACRelayApp",
            linkerSettings: [
                .linkedFramework("IOKit"),
                .linkedFramework("DiskArbitration"),
                .linkedFramework("Security"),
            ]
        )
    ]
)
