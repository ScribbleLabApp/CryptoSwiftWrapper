//===-- CCrypto/include/sha256.h - SHA256 ALGORYTHM ------------  -*- C -*-===//
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
/// This file provides functions for generating and printing SHA-256 and SHA-512
/// hashes. It includes a simple implementation of the
/// SHA-256 hash algorithm.
///
//===----------------------------------------------------------------------===//

#ifndef sha256_h
#define sha256_h

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>

#define CY_SHA256_SUCCESS 0                    ///< Success code for SHA-256 operations
#define CY_ERR_SHA256_NULL_PTR -6              ///< Error code for null pointer
#define CY_ERR_SHA256_INVALID_LEN -7           ///< Error code for invalid length

/// \def ROTR
/// Rotate right macro
/// \param x Input value
/// \param n Number of bits to rotate
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

/// \def Ch
/// Choice function used in SHA-256
/// \param x Input value
/// \param y Input value
/// \param z Input value
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))

/// \def Maj
/// Majority function used in SHA-256
/// \param x Input value
/// \param y Input value
/// \param z Input value
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/// \def Sigma0
/// Sigma0 function used in SHA-256
/// \param x Input value
#define Sigma0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))

/// \def Sigma1
/// Sigma1 function used in SHA-256
/// \param x Input value
#define Sigma1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))

/// \def sigma0
/// sigma0 function used in SHA-256
/// \param x Input value
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))

/// \def sigma1
/// sigma1 function used in SHA-256
/// \param x Input value
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

extern const uint32_t K[64];
extern const uint32_t H256[8];

/// Compresses a single 512-bit block of input data using the SHA-256 algorithm.
///
/// - Parameters:
/// - state: The current hash state (8 x 32-bit words).
/// - block: The 512-bit block of input data (64 bytes).
void sha256_compress(uint32_t state[8], const unsigned char block[64]);

/// Computes the SHA-256 hash of the input data.
///
/// - Parameters:
/// - input: Pointer to the input data.
/// - len: Length of the input data in bytes.
/// - output: Pointer to the buffer where the computed hash will be stored (32 bytes).
///
/// - Returns:
/// - CY_SHA256_SUCCESS (0) on success.
/// - CY_ERR_SHA256_NULL_PTR (-6) if a null pointer is provided.
/// - CY_ERR_SHA256_INVALID_LEN (-7) if the input length is invalid.
int sha256_hash(const unsigned char *input, size_t len, unsigned char *output);

#endif /* sha256_h */
