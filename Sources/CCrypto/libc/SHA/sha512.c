//===-- CCrypto/libc/sha512.h - SHA512 ALGORITHM ------------------*- C -*-===//
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

#include "sha512.h"
#include <string.h>

const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

const uint64_t H512[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

void sha512_compress(uint64_t state[8], const unsigned char block[128]) {
    uint64_t W[80];
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t T1, T2;

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (int t = 0; t < 16; ++t) {
        W[t] = ((uint64_t)block[t * 8 + 0] << 56) | ((uint64_t)block[t * 8 + 1] << 48) |
               ((uint64_t)block[t * 8 + 2] << 40) | ((uint64_t)block[t * 8 + 3] << 32) |
               ((uint64_t)block[t * 8 + 4] << 24) | ((uint64_t)block[t * 8 + 5] << 16) |
               ((uint64_t)block[t * 8 + 6] << 8) | ((uint64_t)block[t * 8 + 7] << 0);
    }
    for (int t = 16; t < 80; ++t) {
        W[t] = sigma1_64(W[t - 2]) + W[t - 7] + sigma0_64(W[t - 15]) + W[t - 16];
    }

    for (int t = 0; t < 80; ++t) {
        T1 = h + Sigma1_64(e) + Ch64(e, f, g) + K512[t] + W[t];
        T2 = Sigma0_64(a) + Maj64(a, b, c);
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

int sha512_hash(const unsigned char *input, size_t len, unsigned char *output) {
    if (input == NULL) {
        return SHA512_NULL_INPUT;
    }

    if (output == NULL) {
        return SHA512_NULL_OUTPUT;
    }

    if (len == 0) {
        return SHA512_INVALID_LENGTH;
    }

    uint64_t state[8];
    unsigned char block[SHA512_BLOCK_SIZE];
    size_t i;
    size_t remaining = len;

    for (i = 0; i < 8; i++) {
        state[i] = H512[i];
    }

    while (remaining >= SHA512_BLOCK_SIZE) {
        memcpy(block, input + (len - remaining), SHA512_BLOCK_SIZE);
        sha512_compress(state, block);
        remaining -= SHA512_BLOCK_SIZE;
    }

    memset(block, 0, SHA512_BLOCK_SIZE);
    memcpy(block, input + (len - remaining), remaining);

    block[remaining] = 0x80;
    if (remaining >= 112) {
        sha512_compress(state, block);
        memset(block, 0, SHA512_BLOCK_SIZE);
    }

    uint64_t bit_length = len * 8;
    block[SHA512_BLOCK_SIZE - 8] = bit_length >> 56;
    block[SHA512_BLOCK_SIZE - 7] = bit_length >> 48;
    block[SHA512_BLOCK_SIZE - 6] = bit_length >> 40;
    block[SHA512_BLOCK_SIZE - 5] = bit_length >> 32;
    block[SHA512_BLOCK_SIZE - 4] = bit_length >> 24;
    block[SHA512_BLOCK_SIZE - 3] = bit_length >> 16;
    block[SHA512_BLOCK_SIZE - 2] = bit_length >> 8;
    block[SHA512_BLOCK_SIZE - 1] = bit_length;

    sha512_compress(state, block);

    for (i = 0; i < 8; i++) {
        output[i * 8]     = (unsigned char)(state[i] >> 56);
        output[i * 8 + 1] = (unsigned char)(state[i] >> 48);
        output[i * 8 + 2] = (unsigned char)(state[i] >> 40);
        output[i * 8 + 3] = (unsigned char)(state[i] >> 32);
        output[i * 8 + 4] = (unsigned char)(state[i] >> 24);
        output[i * 8 + 5] = (unsigned char)(state[i] >> 16);
        output[i * 8 + 6] = (unsigned char)(state[i] >> 8);
        output[i * 8 + 7] = (unsigned char)(state[i]);
    }

    return SHA512_SUCCESS;
}
