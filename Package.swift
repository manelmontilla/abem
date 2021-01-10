// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "abem",
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "abem",
            targets: ["abem"]),
    ],
    dependencies: [
        .package(name:"Sodium",url:"git@github.com:manelmontilla/swift-sodium.git", from: "0.9.3"),
        
        .package(name: "SwiftProtobuf", url: "git@github.com:apple/swift-protobuf.git", from: "1.14.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "abem",
            dependencies: ["Sodium","SwiftProtobuf"]),
        .testTarget(
            name: "abemTests",
            dependencies: ["abem"]),
    ]
)
