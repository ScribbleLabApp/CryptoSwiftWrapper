// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

//===-- ./Package.swift - Package Configuration ------------  -*- swift -*-===//
//                                                                            //
// This source file is part of the Scribble Foundation open source project    //
//                                                                            //
// Copyright (c) 2024 ScribbleLabApp. and the ScribbleLab project authors     //
// Licensed under Apache License v2.0 with Runtime Library Exception          //
//                                                                            //
// You may not use this file except in compliance with the License.           //
// You may obtain a copy of the License at                                    //
//                                                                            //
//      http://www.apache.org/licenses/LICENSE-2.0                            //
//                                                                            //
// Unless required by applicable law or agreed to in writing, software        //
// distributed under the License is distributed on an "AS IS" BASIS,          //
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   //
// See the License for the specific language governing permissions and        //
// limitations under the License.                                             //
//                                                                            //
//===----------------------------------------------------------------------===//

import PackageDescription

let package = Package(
    name: "CryptoSwiftWrapper",
    platforms: [.iOS(.v18), .macOS(.v15), .macCatalyst(.v18)],
    products: [
        .library(
            name: "CryptoSwiftWrapper",
            targets: ["CryptoSwiftWrapper"]),
        .library(
            name: "CCrypto",
            targets: ["CCrypto"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "3.5.2")),
    ],
    targets: [
        .target(
            name: "CryptoSwiftWrapper", 
            dependencies: ["_cyfn", "CCrypto", .product(name: "Crypto", package: "swift-crypto")],
            path: "Sources/CryptoSwiftWrapper",
            resources: [
                .copy("../../.PrivacyInfo.xcprivacy")
            ],
            publicHeadersPath: "include" // Sources/CryptoSwiftWrapper/
        ),
        .target(
            name: "CCrypto",
            dependencies: ["_cyfn"],
            path: "Sources/CCrypto",
            publicHeadersPath: "include", // Sources/CCrypto/
            cSettings: [
                .headerSearchPath("include")
            ],
            linkerSettings: []
        ),
        .systemLibrary(
            name: "_cyfn", path: "Sources/_cyfn"),
        .testTarget(
            name: "CryptoSwiftWrapperTests",
            dependencies: ["CryptoSwiftWrapper"]
        ),
    ]
)
