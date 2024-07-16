import XCTest
import Crypto

@testable import CryptoSwiftWrapper
@testable import _cyfn

final class CryptoSwiftWrapperTests: XCTestCase {
    func testGenerateKeyIV() throws {
        let keyIvPtr = generate_key_iv()
        XCTAssertNotNil(keyIvPtr, "Key and IV pointer should not be nil")
        
        // Assuming AES_KEY_SIZE and AES_BLOCK_SIZE are defined somewhere
        let totalSize = Int(AES_KEY_SIZE + AES_BLOCK_SIZE)
        
        // Assuming the key and iv sizes match the expected size
        let keySize = Int(AES_KEY_SIZE)
        let ivSize = Int(AES_BLOCK_SIZE)
        
        // Check if key and iv were correctly copied
        let keyData = Data(bytes: keyIvPtr!, count: keySize)
        let ivData = Data(bytes: keyIvPtr!.advanced(by: keySize), count: ivSize)
        
        XCTAssertEqual(keyData.count, keySize, "Key size should match expected size")
        XCTAssertEqual(ivData.count, ivSize, "IV size should match expected size")
        
        // Clean up memory allocated in generate_key_iv() after testing
        keyIvPtr?.deallocate()
    }
}
