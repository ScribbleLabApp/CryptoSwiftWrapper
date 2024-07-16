# Integration Guide

Learn how to integrate CryptoSwiftWrapper into your Swift or C project for secure encryption and decryption operations.

## Overview

CryptoSwiftWrapper provides convenient wrappers around Swift-Crypto's AES-GCM encryption and decryption capabilities. This tutorial demonstrates how to generate encryption keys, encrypt plaintext data, decrypt ciphertext data, and handle errors using CryptoSwiftWrapper in both Swift and C.

### Implementation

@TabNavigator {
    @Tab("Swift") {
        #### Step 1: Add CryptoSwiftWrapper to Your Project
        
        Ensure CryptoSwiftWrapper is included in your project. You can use Swift Package Manager to add it:
        
        ```swift
        dependencies: [
            .package(url: "https://github.com/your-repo/CryptoSwiftWrapper.git", from: "1.0.0")
        ]
        ```
        
        #### Step 2: Generate a Key and IV
        
        Use `generate_key_iv()` to generate a key and initialization vector (IV) for AES encryption:
        
        ```swift
        guard let keyIvPtr = generate_key_iv() else {
            fatalError("Failed to generate key and IV")
        }

        let key = keyIvPtr.assumingMemoryBound(to: UInt8.self)
        let iv = key.advanced(by: Int(AES_KEY_SIZE / 8)).assumingMemoryBound(to: UInt8.self)

        // Use key and iv for encryption...
        ```
        
        #### Step 3: Encrypt Data
        
        Encrypt plaintext data using `encrypt_data()`:
        
        ```swift
        let plaintext: [UInt8] = [0x01, 0x02, 0x03, 0x04]
        let ciphertext = UnsafeMutablePointer<UInt8>.allocate(capacity: plaintext.count)

        let encryptedLength = encrypt_data(plaintext, Int32(plaintext.count), key, iv, ciphertext)

        if encryptedLength < 0 {
            fatalError("Encryption failed with error code: \(encryptedLength)")
        }

        // Use encrypted data...
        ```
        
        #### Step 4: Decrypt Data
        
        Decrypt ciphertext data using decrypt_data():
        
        ```swift
        let decrypted = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(encryptedLength))
        let decryptedLength = decrypt_data(ciphertext, encryptedLength, key, iv, nil, 0, decrypted)

        if decryptedLength < 0 {
            fatalError("Decryption failed with error code: \(decryptedLength)")
        }

        // Use decrypted data...
        ```
        
        #### Step 5: Cleanup
        
        Don't forget to deallocate memory allocated by `generate_key_iv()`, `encrypt_data()`, and `decrypt_data()`:
        
        ```swift
        keyIvPtr.deallocate()
        ciphertext.deallocate()
        decrypted.deallocate()
        ```
    }
    
    @Tab("C") {
        #### Step 1: Include CryptoSwiftWrapper in Your Project
        
        Include `cyfn.h` in your C project and link with CryptoSwiftWrapper:
        
        ```c
        #include "CryptoSwiftWrapper/cyfn.h"
        ```
        
        #### Step 2: Generate a Key and IV
        
        Use `generate_key_iv()` to generate a key and IV for AES encryption:
        
        ```c
        unsigned char *key, *iv;
        void *keyIvPtr = generate_key_iv();

        if (!keyIvPtr) {
            fprintf(stderr, "Failed to generate key and IV\n");
            exit(CY_ERR_GENKEY);
        }

        key = keyIvPtr;
        iv = key + AES_KEY_SIZE / 8;

        // Use key and iv for encryption...
        ```
        
        #### Step 3: Encrypt Data
        
        Encrypt plaintext data using `encrypt_data()`:
        
        ```c
        const unsigned char plaintext[] = {0x01, 0x02, 0x03, 0x04};
        unsigned char ciphertext[1024];
        int ciphertext_len = encrypt_data(plaintext, sizeof(plaintext), key, iv, ciphertext);

        if (ciphertext_len < 0) {
            fprintf(stderr, "Encryption failed with error code: %d\n", ciphertext_len);
            exit(CY_ERR_ENCR);
        }

        // Use encrypted data...
        ```
        
        #### Step 4: Decrypt Data
        
        Decrypt ciphertext data using `decrypt_data()`:
        
        ```c
        unsigned char decrypted[1024];
        int decrypted_len = decrypt_data(ciphertext, ciphertext_len, key, iv, NULL, 0, decrypted);

        if (decrypted_len < 0) {
            fprintf(stderr, "Decryption failed with error code: %d\n", decrypted_len);
            exit(CY_ERR_DECR);
        }

        // Use decrypted data...
        ```
        
        #### Step 5: Cleanup
        
        Free allocated memory when done:
        
        ```c
        free(key);
        ```
    }
}
