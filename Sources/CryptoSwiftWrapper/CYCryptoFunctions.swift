//
//  File.swift
//  
//
//  Created by Nevio Hirani on 16.07.24.
//

import Crypto
import _cyfn
import Foundation

@_cdecl("generate_key_iv")
public func generate_key_iv() -> UnsafeMutableRawPointer? {
    let key = SymmetricKey(size: .bits256)
    let iv = SymmetricKey(size: .bits128)
    
    // Allocate memory for key and iv combined
    let keyIvPtr = UnsafeMutableRawPointer.allocate(byteCount: Int(AES_KEY_SIZE + AES_BLOCK_SIZE), alignment: 1)
    
    // Copy key and iv data into keyIvPtr
    key.withUnsafeBytes { keyBytes in
        iv.withUnsafeBytes { ivBytes in
            keyIvPtr.copyMemory(from: keyBytes.baseAddress!, byteCount: Int(AES_KEY_SIZE))
            keyIvPtr.advanced(by: Int(AES_KEY_SIZE)).copyMemory(from: ivBytes.baseAddress!, byteCount: Int(AES_BLOCK_SIZE))
        }
    }
    
    return keyIvPtr
}

@_cdecl("encrypt_data")
public func encrypt_data(plaintext: UnsafePointer<UInt8>, plaintext_len: Int32, key: UnsafePointer<UInt8>, iv: UnsafePointer<UInt8>, ciphertext: UnsafeMutablePointer<UInt8>) -> Int32 {
    let keyData = Data(bytes: key, count: Int(AES_KEY_SIZE))
    let ivData = Data(bytes: iv, count: Int(AES_BLOCK_SIZE))
    let plaintextData = Data(bytes: plaintext, count: Int(plaintext_len))
    
    do {
        let sealedBox = try AES.GCM.seal(plaintextData, using: SymmetricKey(data: keyData), nonce: AES.GCM.Nonce(data: ivData))
        
        // Use UnsafeMutableBufferPointer to initialize ciphertext
        let ciphertextBuffer = UnsafeMutableBufferPointer(start: ciphertext, count: sealedBox.ciphertext.count)
        _ = ciphertextBuffer.initialize(from: sealedBox.ciphertext)
        
        return Int32(sealedBox.ciphertext.count)
    } catch {
        return CY_ERR_ENCR
    }
}

@_cdecl("decrypt_data")
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
