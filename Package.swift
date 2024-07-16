// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CryptoSwiftWrapper",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(
            name: "CryptoSwiftWrapper",
            targets: ["CryptoSwiftWrapper"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "3.5.2")),
    ],
    targets: [
        .target(
            name: "CryptoSwiftWrapper", 
            dependencies: ["_cyfn", .product(name: "Crypto", package: "swift-crypto")],
            publicHeadersPath: "Sources/CryptoSwiftWrapper/include"),
        .systemLibrary(
            name: "_cyfn", path: "Sources/_cyfn"),
        .testTarget(
            name: "CryptoSwiftWrapperTests",
            dependencies: ["CryptoSwiftWrapper"]
        ),
    ]
)
