//===-- CryptoSwiftWrapper/CYCryptoFunctions.swift - SCW ---  -*- swift -*-===//
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
///
/// Swift Source for Swift-Crypto encryption and decryption.
///
/// This file defines functions and constants to interact with Swift-Crypto's AES-GCM
/// encryption and decryption capabilities. It includes functions for key generation,
/// encryption, and decryption operations using AES-GCM mode.
///
//===----------------------------------------------------------------------===//

import Crypto
import _cyfn
import Foundation

/// Generates a key and initialization vector (IV) for AES encryption.
///
/// - Returns: A pointer to the allocated memory containing the key and IV.
/// - Note: The caller is responsible for freeing the allocated memory using `free()`.
@_cdecl("s_generate_key_iv")
public func generate_key_iv() -> UnsafeMutableRawPointer? {
    let key = SymmetricKey(size: .bits256)
    let iv = SymmetricKey(size: .bits128)
    
    let keyIvPtr = UnsafeMutableRawPointer.allocate(byteCount: Int(AES_KEY_SIZE + AES_BLOCK_SIZE), alignment: 1)
    
    key.withUnsafeBytes { keyBytes in
        iv.withUnsafeBytes { ivBytes in
            keyIvPtr.copyMemory(from: keyBytes.baseAddress!, byteCount: Int(AES_KEY_SIZE))
            keyIvPtr.advanced(by: Int(AES_KEY_SIZE)).copyMemory(from: ivBytes.baseAddress!, byteCount: Int(AES_BLOCK_SIZE))
        }
    }
    
    return keyIvPtr
}

/// Encrypts plaintext data using AES-GCM encryption.
///
/// - Parameters:
///   - plaintext: Pointer to the plaintext data.
///   - plaintext_len: Length of the plaintext data.
///   - key: Pointer to the AES encryption key.
///   - iv: Pointer to the AES initialization vector (IV).
///   - ciphertext: Pointer to store the encrypted ciphertext data.
/// - Returns: The length of the encrypted ciphertext data on success, or `CY_ERR_ENCR` on failure.
@_cdecl("s_encrypt_data")
public func encrypt_data(plaintext: UnsafePointer<UInt8>, plaintext_len: Int32, key: UnsafePointer<UInt8>, iv: UnsafePointer<UInt8>, ciphertext: UnsafeMutablePointer<UInt8>) -> Int32 {
    let keyData = Data(bytes: key, count: Int(AES_KEY_SIZE))
    let ivData = Data(bytes: iv, count: Int(AES_BLOCK_SIZE))
    let plaintextData = Data(bytes: plaintext, count: Int(plaintext_len))
    
    do {
        let sealedBox = try AES.GCM.seal(plaintextData, using: SymmetricKey(data: keyData), nonce: AES.GCM.Nonce(data: ivData))
        
        let ciphertextBuffer = UnsafeMutableBufferPointer(start: ciphertext, count: sealedBox.ciphertext.count)
        _ = ciphertextBuffer.initialize(from: sealedBox.ciphertext)
        
        return Int32(sealedBox.ciphertext.count)
    } catch {
        return CY_ERR_ENCR
    }
}

/// Decrypts ciphertext data encrypted using AES-GCM encryption.
///
/// - Parameters:
///   - ciphertext: Pointer to the ciphertext data.
///   - ciphertext_len: Length of the ciphertext data.
///   - key: Pointer to the AES encryption key.
///   - iv: Pointer to the AES initialization vector (IV).
///   - tag: Pointer to the authentication tag used for decryption.
///   - tag_len: Length of the authentication tag.
///   - plaintext: Pointer to store the decrypted plaintext data.
/// - Returns: The length of the decrypted plaintext data on success, or `CY_ERR_DECR` on failure.
@_cdecl("s_decrypt_data")
public func decrypt_data(ciphertext: UnsafePointer<UInt8>, ciphertext_len: Int32, key: UnsafePointer<UInt8>, iv: UnsafePointer<UInt8>, tag: UnsafePointer<UInt8>, tag_len: Int32, plaintext: UnsafeMutablePointer<UInt8>) -> Int32 {
    let keyData = Data(bytes: key, count: Int(AES_KEY_SIZE / 8))
    let ivData = Data(bytes: iv, count: Int(AES_BLOCK_SIZE))
    let ciphertextData = Data(bytes: ciphertext, count: Int(ciphertext_len))
    let tagData = Data(bytes: tag, count: Int(tag_len))
    
    do {
        let nonce = try AES.GCM.Nonce(data: ivData)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertextData, tag: tagData)
        
        let decryptedData = try AES.GCM.open(sealedBox, using: SymmetricKey(data: keyData))
        
        let plaintextBuffer = UnsafeMutableBufferPointer(start: plaintext, count: decryptedData.count)
        _ = plaintextBuffer.initialize(from: decryptedData)
        
        return Int32(decryptedData.count)
    } catch {
        return CY_ERR_DECR
    }
}
