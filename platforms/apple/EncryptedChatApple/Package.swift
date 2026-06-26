// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "EncryptedChatApple",
    defaultLocalization: "en",
    platforms: [
        .iOS(.v18),
        .macOS(.v15)
    ],
    products: [
        .library(name: "EncryptedChatApple", targets: ["EncryptedChatApple"])
    ],
    targets: [
        .target(name: "EncryptedChatApple")
    ]
)
