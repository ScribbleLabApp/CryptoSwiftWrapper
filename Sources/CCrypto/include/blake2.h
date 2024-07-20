//===-- CCrypto/include/blake2.h - BLAKE2 ALGORITHM ---------------*- C -*-===//
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

#ifndef blake2_h
#define blake2_h

#include <stdint.h>
#include <string.h>

#define BLAKE2S_BLOCKBYTES  64
#define BLAKE2S_OUTBYTES    32

#define BLAKE2S_STATE_SIZE  8
#define BLAKE2S_KEYBYTES    32

#define ROTR32(x, y) (((x) >> (y)) | ((x) << (32 - (y))))

#define G(r, i, a, b, c, d)                     \
    do {                                        \
        a = a + b + m[blake2s_sigma[r][2*i+0]]; \
        d = ROTR32(d ^ a, 16);                  \
        c = c + d;                              \
        b = ROTR32(b ^ c, 12);                  \
        a = a + b + m[blake2s_sigma[r][2*i+1]]; \
        d = ROTR32(d ^ a, 8);                   \
        c = c + d;                              \
        b = ROTR32(b ^ c, 7);                   \
    } while (0)

typedef struct {
    uint8_t  b[BLAKE2S_BLOCKBYTES];
    uint32_t h[BLAKE2S_STATE_SIZE];
    uint32_t t[2];
    uint32_t f[2];
    size_t   buflen;
    size_t   outlen;
    const uint8_t  *last_node;
} blake2s_state;

static void blake2s_compress(blake2s_state *S, const uint8_t block[BLAKE2S_BLOCKBYTES]);
int blake2s_init(blake2s_state *S, size_t outlen, const void *key, size_t keylen);
int blake2s_update(blake2s_state *S, const void *pin, size_t inlen);
int blake2s_final(blake2s_state *S, void *out, size_t outlen);

#endif /* blake2_h */
