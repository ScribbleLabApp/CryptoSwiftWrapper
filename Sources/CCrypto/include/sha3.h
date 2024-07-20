//===-- CCrypto/include/sha3.h - SHA-3 ALGORITHM ------------------*- C -*-===//
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
/// This file provides functions for generating and printing SHA-3 hash values.
///
//===----------------------------------------------------------------------===//

#ifndef sha3_h
#define sha3_h

#include <stdint.h>
#include <string.h>

#define SHA3_SUCCESS          0    ///< Success code for SHA-3 operations.
#define SHA3_NULL_INPUT      -1    ///< Error code for null input parameter.
#define SHA3_INVALID_LENGTH  -2    ///< Error code for invalid input length.
#define SHA3_MEMORY_ERROR    -3

/// SHA-3 context structure.
typedef struct {
    uint64_t state[25];            ///< Keccak state (1600 bits = 25 * 64 bits).
    uint64_t bitlen;               ///< Total message bit length.
    unsigned int r;                ///< Rate in bytes.
    unsigned int capacity;         ///< Capacity in bytes.
    unsigned int hashlen;          ///< Hash output length in bytes.
    unsigned char *buffer;         ///< Buffer for data block.
} sha3_ctx_t;

/// Initialize SHA-3 context for given hash length.
/// \param ctx SHA-3 context structure to be initialized.
/// \param hashlen Length of the hash output in bytes (224, 256, 384, or 512).
/// \return SHA3_SUCCESS on success, SHA3_INVALID_LENGTH if hashlen is not valid.
int sha3_init(sha3_ctx_t *ctx, unsigned int hashlen);

/// Update SHA-3 context with input data.
/// \param ctx SHA-3 context structure.
/// \param data Input data buffer.
/// \param len Length of the input data buffer in bytes.
/// \return SHA3_SUCCESS on success, SHA3_NULL_INPUT if ctx or data is NULL.
int sha3_update(sha3_ctx_t *ctx, const unsigned char *data, size_t len);

/// Finalize SHA-3 hash computation and output the hash value.
/// \param ctx SHA-3 context structure.
/// \param hash Output buffer to store the hash value (must be pre-allocated).
/// \return SHA3_SUCCESS on success, SHA3_NULL_INPUT if ctx or hash is NULL.
int sha3_final(sha3_ctx_t *ctx, unsigned char *hash);

/// Compute SHA-3 hash directly from input data.
/// \param data Input data buffer.
/// \param len Length of the input data buffer in bytes.
/// \param hash Output buffer to store the hash value (must be pre-allocated).
/// \param hashlen Length of the hash output in bytes (224, 256, 384, or 512).
/// \return SHA3_SUCCESS on success, SHA3_NULL_INPUT if data or hash is NULL,
///         SHA3_INVALID_LENGTH if hashlen is not valid.
int sha3(const unsigned char *data, size_t len, unsigned char *hash, unsigned int hashlen);

static void KeccakF1600_StatePermute(uint64_t state[25]);
static void KeccakF(uint64_t state[25]);

static const uint64_t KeccakF_RoundConstants[24];
static const unsigned int KeccakF_RoundConstantsSize;
static const unsigned int KeccakF_RotationOffsets[24];
static const unsigned int KeccakF_PiLane[25];
static const unsigned int KeccakF_Mod5[25];

#endif /* sha3_h */
