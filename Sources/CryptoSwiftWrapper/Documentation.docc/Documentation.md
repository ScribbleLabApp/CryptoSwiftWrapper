# ``CryptoSwiftWrapper``

Interact with Swift-Crypto's AES-GCM encryption and decryption capabilities in C

@Metadata {
    @Available(iOS, introduced: "18.0")
    @Available(iPadOS, introduced: "18.0") 
    @Available(macOS, introduced: "15.0")
    @Available(MacCatalyst, introduced: "18.0")
    
    @Available(Swift, introduced: "6")
    
    @SupportedLanguage(swift)
    @SupportedLanguage(c)
}

## Overview

The CryptoSwiftWrapper module provides an easy-to-use interface for cryptographic operations using AES-GCM. It allows Swift code to perform encryption and decryption tasks, while exposing these capabilities to C through a clean API.

Use the CryptoSwiftWrapper to perform common cryptographic operations using Swift-Crypto:

- Generate cryptographically secure keys and initialization vectors.
- Encrypt and decrypt data using AES-GCM.

Prefer CryptoSwiftWrapper for its simplicity and integration with Swift. It abstracts the complexities of managing raw pointers and ensures secure memory handling.

## Topics

### Essential

- <doc:UsageExample>
- <doc:CYErrors>

### Key and IV Generation

- ``generate_key_iv()``

### En-/Decryption

- ``encrypt_data(plaintext:plaintext_len:key:iv:ciphertext:)``
- ``decrypt_data(ciphertext:ciphertext_len:key:iv:tag:tag_len:plaintext:)``

### SHA 256 & 512

- <doc:SHA_IMPL>
