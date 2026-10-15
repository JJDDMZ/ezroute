// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "EZSwitch",
    platforms: [.macOS("27.0")],
    products: [.executable(name: "EZSwitch", targets: ["EZSwitch"]),
               .executable(name: "EZRoutingTool", targets: ["EZRoutingTool"])],
    targets: [
        .target(name: "EZSwitchCore"),
        .executableTarget(name: "EZSwitch", dependencies: ["EZSwitchCore"]),
        .executableTarget(name: "EZRoutingTool", dependencies: ["EZSwitchCore"]),
        .testTarget(name: "EZSwitchCoreTests", dependencies: ["EZSwitchCore"])
    ]
)
