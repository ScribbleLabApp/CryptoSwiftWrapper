
# CryptoSwiftWrapper

Interact with Swift-Crypto’s AES-GCM encryption and decryption capabilities in C

## Overview

The CryptoSwiftWrapper module provides an easy-to-use interface for cryptographic operations using AES-GCM. It allows Swift code to perform encryption and decryption tasks, while exposing these capabilities to C through a clean API.

Use the CryptoSwiftWrapper to perform common cryptographic operations using Swift-Crypto:

- Data integrity and security through SHA256 and SH512 implementation.
- Generate cryptographically secure keys and initialization vectors.
- Encrypt and decrypt data using AES-GCM.

Prefer CryptoSwiftWrapper for its simplicity and integration with Swift. It abstracts the complexities of managing raw pointers and ensures secure memory handling.

## 🖥️ Installation

### Requirements

#### Swift Libary:

- iOS 18.0+
- macOS 15.0+
- Swift 5.5+

#### C Libary:

- A compiler such as gcc or clang
- C17
- C++17

#### Swift Package Manager (swift) (recommended)

You can integrate CryptoSwiftWrapper into your project using Swift Package Manager (SPM). Here’s how:

1. In Xcode 16, open your project and navigate to File → Swift Packages → Add Package Dependency...
2. Paste the repository URL (https://github.com/ScribbleLabApp/CryptoSwiftWrapper.git) and click Next.
3. For Version, verify it's Up to next major.
4. Click Next and select the CryptoSwiftWrapper package.
5. Click Finish.

You can also add it to the dependencies of your `Package.swift` file:

```swift
dependencies: [
  .package(url: "https://github.com/ScribbleLabApp/CryptoSwiftWrapper.git", .upToNextMajor(from: "0.1.0"))
]
```

### Usage

Once CryptoSwiftWrapper is added as a dependency using SPM, you need to ensure it’s accessible from your C codebase. Here’s how you can achieve that:

- **Bridging Header (`CryptoSwiftWrapper.h`):** To expose Swift-Crypto’s AES-GCM capabilities to C, you need to create a bridging header (CryptoSwiftWrapper.h) that includes the necessary C interfaces.
- **Include Paths:** When compiling your C code, make sure to include the path to `CryptoSwiftWrapper/cyfn.h` (which includes _cyfn/cyfn.h) so that the functions and definitions from `_cyfn/cyfn.h` are available in your C project.

> [!IMPORTANT]
Avoid directly including _cyfn/cyfn.h to maintain encapsulation and proper abstraction.

### Build process

After cloning the CryptoSwiftWrapper repository to your local machine, navigate to the project directory in your Terminal. Once there, run our build script:

```sh
chmod u+x build_script.sh
./build_script.sh
```
