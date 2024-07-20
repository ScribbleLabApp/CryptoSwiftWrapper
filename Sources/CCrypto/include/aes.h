//===-- CCrypto/include/aes.h - AES -------------------------------*- C -*-===//
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
///
//===----------------------------------------------------------------------===//

#ifndef aes_h
#define aes_h

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#define AES_BLOCK_SIZE 16

#define Nb 4       // Number of columns (32-bit words) in the state
#define Nk_128 4   // Number of columns in key for AES-128
#define Nk_192 6   // Number of columns in key for AES-192
#define Nk_256 8   // Number of columns in key for AES-256
#define Nr_128 10  // Number of rounds for AES-128
#define Nr_192 12  // Number of rounds for AES-192
#define Nr_256 14  // Number of rounds for AES-256


typedef enum {
    AES128 = 16,
    AES192 = 24,
    AES256 = 32
} AES_KEYSIZE;

typedef enum {
    ECB_MODE,
    CBC_MODE,
    CFB_MODE,
    OFB_MODE,
    CTR_MODE
} AES_MODE;

typedef struct {
    AES_KEYSIZE key_size;
    AES_MODE mode;
    uint8_t key[32];
    uint8_t iv[AES_BLOCK_SIZE];
} AES_CTX;

void AES_init(AES_CTX *ctx, AES_KEYSIZE key_size, AES_MODE mode, const uint8_t *key, const uint8_t *iv);
void AES_encrypt(const AES_CTX *ctx, const uint8_t *plaintext, uint8_t *ciphertext, size_t length);
void AES_decrypt(const AES_CTX *ctx, const uint8_t *ciphertext, uint8_t *plaintext, size_t length);

#endif /* aes_h */
