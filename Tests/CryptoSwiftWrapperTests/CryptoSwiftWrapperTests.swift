import XCTest
import Crypto

@testable import CryptoSwiftWrapper
@testable import _cyfn

final class CryptoSwiftWrapperTests: XCTestCase {
    func testGenerateKeyIv() {
        guard let keyIvPtr = generate_key_iv() else {
            XCTFail("Failed to generate key and IV")
            return
        }
        
        let keySize = AES_KEY_SIZE / 8
        let ivSize = AES_BLOCK_SIZE
        
        // Access the key and IV
        let key = keyIvPtr.assumingMemoryBound(to: UInt8.self)
        let iv = keyIvPtr.advanced(by: Int(keySize)).assumingMemoryBound(to: UInt8.self)
        
        // Verify the memory addresses
        let keyBytes = UnsafeBufferPointer(start: key, count: Int(keySize))
        let ivBytes = UnsafeBufferPointer(start: iv, count: Int(ivSize))
        
        XCTAssertEqual(keyBytes.count, Int(keySize), "Key size is incorrect")
        XCTAssertEqual(ivBytes.count, Int(ivSize), "IV size is incorrect")
        
        keyIvPtr.deallocate()
    }
    
    func testEncryptData() {
        let keyIvPtr = generate_key_iv()!
        let key = keyIvPtr.assumingMemoryBound(to: UInt8.self)
        let iv = keyIvPtr.advanced(by: Int(AES_KEY_SIZE / 8)).assumingMemoryBound(to: UInt8.self)
        
        let plaintext = "Hello, World!".data(using: .utf8)!
        let plaintextBytes = [UInt8](plaintext)
        let ciphertext = UnsafeMutablePointer<UInt8>.allocate(capacity: plaintext.count + Int(AES_BLOCK_SIZE) + 16)
        
        let ciphertextLen = encrypt_data(plaintext: plaintextBytes, plaintext_len: Int32(plaintext.count), key: key, iv: iv, ciphertext: ciphertext)
        XCTAssertGreaterThan(ciphertextLen, 0, "Encryption failed")
        
        ciphertext.deallocate()
        keyIvPtr.deallocate()
    }
    
    func testDecryptData() {
        let keyIvPtr = generate_key_iv()!
        let key = keyIvPtr.assumingMemoryBound(to: UInt8.self)
        let iv = keyIvPtr.advanced(by: Int(AES_KEY_SIZE / 8)).assumingMemoryBound(to: UInt8.self)
        
        let plaintext = "Hello, World!".data(using: .utf8)!
        let plaintextBytes = [UInt8](plaintext)
        let ciphertext = UnsafeMutablePointer<UInt8>.allocate(capacity: plaintext.count + Int(AES_BLOCK_SIZE) + 16)
        
        let ciphertextLen = encrypt_data(plaintext: plaintextBytes, plaintext_len: Int32(plaintext.count), key: key, iv: iv, ciphertext: ciphertext)
        XCTAssertGreaterThan(ciphertextLen, 0, "Encryption failed")
        
        let tag = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
        let tagLen = 16
        let decryptedText = UnsafeMutablePointer<UInt8>.allocate(capacity: plaintext.count)
        
        let decryptedLen = decrypt_data(ciphertext, ciphertextLen, key, iv, tag, Int32(tagLen), decryptedText)
        XCTAssertGreaterThan(decryptedLen, 0, "Decryption failed")
        
        let decryptedData = Data(bytes: decryptedText, count: Int(decryptedLen))
        XCTAssertEqual(decryptedData, plaintext, "Decrypted text does not match original text")
        
        ciphertext.deallocate()
        decryptedText.deallocate()
        tag.deallocate()
        keyIvPtr.deallocate()
    }
}
