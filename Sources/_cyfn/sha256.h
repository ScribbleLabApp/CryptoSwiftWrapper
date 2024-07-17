//===-- _cyfn/sha256.h - SHA256 ALGORYTHM ----------------------  -*- C -*-===//
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
/// SHA-256 hash algorithm and a function to print SHA-512 hash values.
///
//===----------------------------------------------------------------------===//

#ifndef sha256_h
#define sha256_h

#include <stdio.h>
#include <stdint.h>
#include <string.h>

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

const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

const uint32_t H256[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

typedef struct {
    uint32_t words[64];
} SHA256_Message_Schedule;

/// Compresses a single 512-bit block of input data using the SHA-256 algorithm.
///
/// - Parameters:
///   - state: The current hash state (8 x 32-bit words).
///   - block: The 512-bit block of input data (64 bytes).
void sha256_compress(uint32_t state[8], const unsigned char block[64]) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t T1, T2;

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (int t = 0; t < 16; ++t) {
        W[t] = (block[t * 4 + 0] << 24) | (block[t * 4 + 1] << 16) | (block[t * 4 + 2] << 8) | (block[t * 4 + 3] << 0);
    }
    for (int t = 16; t < 64; ++t) {
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
    }

    for (int t = 0; t < 64; ++t) {
        T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
        T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}


/// Computes the SHA-256 hash of the input data.
///
/// - Parameters:
///   - input: Pointer to the input data.
///   - len: Length of the input data in bytes.
///   - output: Pointer to the buffer where the computed hash will be stored (32 bytes).
///
/// - Returns:
///   - CY_SHA256_SUCCESS (0) on success.
///   - CY_ERR_SHA256_NULL_PTR (-6) if a null pointer is provided.
///   - CY_ERR_SHA256_INVALID_LEN (-7) if the input length is invalid.
int sha256_hash(const unsigned char *input, size_t len, unsigned char *output) {
    if (input == NULL || output == NULL) {
        return CY_ERR_SHA256_NULL_PTR;
    }
    if (len == 0) {
        return CY_ERR_SHA256_INVALID_LEN;
    }

    uint32_t state[8];
    unsigned char block[64];
    size_t i;
    uint64_t bitlen = len * 8;

    state[0] = H256[0]; state[1] = H256[1]; state[2] = H256[2]; state[3] = H256[3];
    state[4] = H256[4]; state[5] = H256[5]; state[6] = H256[6]; state[7] = H256[7];

    for (i = 0; i < len / 64; i++) {
        memcpy(block, input + i * 64, 64);
        sha256_compress(state, block);
    }

    memset(block, 0, 64);
    memcpy(block, input + i * 64, len % 64);
    block[len % 64] = 0x80;
    if (len % 64 >= 56) {
        sha256_compress(state, block);
        memset(block, 0, 64);
    }
    block[56] = (bitlen >> 56) & 0xff;
    block[57] = (bitlen >> 48) & 0xff;
    block[58] = (bitlen >> 40) & 0xff;
    block[59] = (bitlen >> 32) & 0xff;
    block[60] = (bitlen >> 24) & 0xff;
    block[61] = (bitlen >> 16) & 0xff;
    block[62] = (bitlen >> 8) & 0xff;
    block[63] = (bitlen >> 0) & 0xff;
    sha256_compress(state, block);

    for (i = 0; i < 8; i++) {
        output[i * 4 + 0] = (state[i] >> 24) & 0xff;
        output[i * 4 + 1] = (state[i] >> 16) & 0xff;
        output[i * 4 + 2] = (state[i] >> 8) & 0xff;
        output[i * 4 + 3] = (state[i] >> 0) & 0xff;
    }

    return CY_SHA256_SUCCESS;
}

#endif /* sha256_h */
