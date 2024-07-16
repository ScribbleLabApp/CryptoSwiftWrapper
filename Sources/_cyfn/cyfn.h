//===-- _cyfn/cyfn.h - Swift-Crypto Wrapper --------------------  -*- C -*-===//
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
/// \file
/// \brief Header file providing C interfaces for Swift-Crypto encryption and decryption.
///
/// This file defines functions and constants to interact with Swift-Crypto's AES-GCM
/// encryption and decryption capabilities. It includes functions for key generation,
/// encryption, and decryption operations using AES-GCM mode.
///
/// Usage Example:
/// \code
/// unsigned char key[AES_KEY_SIZE / 8];
/// unsigned char iv[AES_BLOCK_SIZE];
/// unsigned char tag[AES_GCM_TAG_SIZE];
/// unsigned char plaintext[256];
/// unsigned char ciphertext[512];
///
/// // Generate key and IV
/// void *keyIvPtr = generate_key_iv(key, iv);
///
/// // Encrypt plaintext
/// int encrypted_len = encrypt_data(plaintext, sizeof(plaintext), key, iv, tag, sizeof(tag), ciphertext);
///
/// // Decrypt ciphertext
/// int decrypted_len = decrypt_data(ciphertext, encrypted_len, key, iv, tag, sizeof(tag), plaintext);
///
/// // Free allocated memory for key and IV
/// free(keyIvPtr);
/// \endcode
///
//===----------------------------------------------------------------------===//

#ifndef cyfn_h
#define cyfn_h

#include <stdint.h>

#define AES_KEY_SIZE 256
#define AES_BLOCK_SIZE 16

#define CY_ERR_GENKEY -100          ///< Error code indicating key generation failure.
#define CY_ERR_ENCR -101            ///< Error code indicating encryption failure.
#define CY_ERR_DECR -102            ///< Error code indicating decryption failure.
#define CY_ERR_INIT -103            ///< Error code indicating initialization failure.
#define CY_ERR_OSSL -104            ///< Error code indicating an OpenSSL error.

#ifdef __cplusplus
extern "C" {
#endif

/// Generates a key and initialization vector (IV) for encryption.
///
/// This function allocates memory for the combined key and IV.
///
/// - Parameters:
///   - key: Pointer to store the generated encryption key.
///   - iv: Pointer to store the generated IV.
/// - Returns: A pointer to the allocated memory containing the key and IV.
///            The caller is responsible for freeing this memory using `free()`.
void* generate_key_iv(unsigned char *key, unsigned char *iv);

/// Encrypts plaintext data using AES-GCM encryption.
///
/// - Parameters:
///   - plaintext: Pointer to the plaintext data to encrypt.
///   - plaintext_len: Length of the plaintext data.
///   - key: Pointer to the encryption key.
///   - iv: Pointer to the initialization vector (IV).
///   - tag: Pointer to the authentication tag.
///   - tag_len: Length of the authentication tag.
///   - ciphertext: Pointer to store the encrypted ciphertext data.
/// - Returns: `CY_ERR_ENCR` on encryption failure, or the length of the encrypted
///            ciphertext data on success.
int encrypt_data(const unsigned char *plaintext, int plaintext_len,
                 const unsigned char *key, const unsigned char *iv,
                 const unsigned char *tag, int tag_len,
                 unsigned char *ciphertext);

/// Decrypts ciphertext data encrypted using AES-GCM encryption.
///
/// - Parameters:
///   - ciphertext: Pointer to the ciphertext data to decrypt.
///   - ciphertext_len: Length of the ciphertext data.
///   - key: Pointer to the encryption key.
///   - iv: Pointer to the initialization vector (IV).
///   - tag: Pointer to the authentication tag.
///   - tag_len: Length of the authentication tag.
///   - plaintext: Pointer to store the decrypted plaintext data.
/// - Returns: `CY_ERR_DECR` on decryption failure, or the length of the decrypted
///            plaintext data on success.
int decrypt_data(const unsigned char *ciphertext, int ciphertext_len,
                 const unsigned char *key, const unsigned char *iv,
                 const unsigned char *tag, int tag_len,
                 unsigned char *plaintext);

#ifdef __cplusplus
}
#endif

#endif /* cyfn_h */
