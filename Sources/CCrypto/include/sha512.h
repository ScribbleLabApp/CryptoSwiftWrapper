//===-- CCrypto/include/sha512.h - SHA512 ALGORITHM -------------------*- C -*-===//
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
/// This file provides functions for generating and printing SHA-512
/// hashes. It includes an implementation of the SHA-512 hash algorithm
/// and functions to print SHA-512 hash values.
///
//===----------------------------------------------------------------------===//

#ifndef sha512_h
#define sha512_h

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define SHA512_SUCCESS              0          ///< Success code for SHA-512 operations.
#define SHA512_NULL_INPUT          -8          ///< Error code for null input parameter.
#define SHA512_NULL_OUTPUT         -9          ///< Error code for null output parameter.
#define SHA512_MEMORY_ERROR        -10         ///< Error code for memory allocation failure.
#define SHA512_INVALID_LENGTH      -11         ///< Error code for invalid input length.

#define SHA512_BLOCK_SIZE 128                  ///< Block size in bytes for SHA-512.
#define SHA512_HASH_SIZE  64                   ///< Hash size in bytes for SHA-512.

/// \defgroup RotationMacros Rotation Macros
/// @{
/// Perform a 64-bit right rotate operation on x by n bits.
/// \param x Input value to be rotated.
/// \param n Number of bits to rotate by.
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
/// @}


/// \defgroup LogicalFunctions Logical Functions
/// @{
/// SHA-512 logical functions.
/// \param x First input value.
/// \param y Second input value.
/// \param z Third input value.
#define Ch64(x, y, z)    (((x) & (y)) ^ (~(x) & (z)))                   ///< Ch function for SHA-512.
#define Maj64(x, y, z)   (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))      ///< Maj function for SHA-512.
/// @}

/// \defgroup SigmaFunctions Sigma Functions
/// @{
/// SHA-512 sigma functions.
/// \param x Input value.
#define Sigma0_64(x)     (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39)) ///< Sigma0 function for SHA-512.
#define Sigma1_64(x)     (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41)) ///< Sigma1 function for SHA-512.
/// @}

/// \defgroup sigmaFunctions sigma Functions
/// @{
/// SHA-512 sigma functions.
/// \param x Input value.
#define sigma0_64(x)     (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))      ///< sigma0 function for SHA-512.
#define sigma1_64(x)     (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))    ///< sigma1 function for SHA-512.
/// @}

const uint64_t K512[80];

const uint64_t H512[8];

typedef struct {
    uint64_t words[80];
} SHA512_Message_Schedule;

#pragma mark - Helper functions start

int sha512_hash(const unsigned char *input, size_t len, unsigned char *output);
static void sha512_process_block(SHA512_Message_Schedule *schedule, uint64_t state[8]);
void sha512_print_hash(const unsigned char *hash);

#pragma mark - Helper functions end

#endif /* sha512_h */
