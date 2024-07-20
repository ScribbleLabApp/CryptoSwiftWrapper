//===-- CCrypto/src/sha3.c - SHA-3 Algorithm Implementation -------*- C -*-===//
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

#include "sha3.h"
#include <stdlib.h>

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static const uint64_t KeccakF_RoundConstants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const unsigned int KeccakF_RoundConstantsSize = sizeof(KeccakF_RoundConstants) / sizeof(uint64_t);

static const unsigned int KeccakF_RotationOffsets[24] = {
    0,  1, 62, 28, 27, 36, 44,  6, 55, 20,  3, 10, 43, 25, 39, 41,
    45, 15, 21,  8, 18,  2, 61, 56
};

static const unsigned int KeccakF_PiLane[25] = {
    0,  1, 62, 28, 27, 36, 44,  6, 55, 20,  3, 10, 43, 25, 39, 41,
    45, 15, 21,  8, 18,  2, 61, 56, 14
};

static const unsigned int KeccakF_Mod5[25] = {
    0,  1, 62, 28, 27, 36, 44,  6, 55, 20,  3, 10, 43, 25, 39, 41,
    45, 15, 21,  8, 18,  2, 61, 56, 14
};

static void KeccakF(uint64_t state[25]) {
    uint64_t Aba, Abe, Abi, Abo, Abu;
    uint64_t Aga, Age, Agi, Ago, Agu;
    uint64_t Aka, Ake, Aki, Ako, Aku;
    uint64_t Ama, Ame, Ami, Amo, Amu;
    uint64_t Asa, Ase, Asi, Aso, Asu;

    uint64_t BCa, BCe, BCi, BCo, BCu;
    uint64_t Da, De, Di, Do, Du;
    uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
    uint64_t Ega, Ege, Egi, Ego, Egu;
    uint64_t Eka, Eke, Eki, Eko, Eku;
    uint64_t Ema, Eme, Emi, Emo, Emu;
    uint64_t Esa, Ese, Esi, Eso, Esu;

    int round;

    for (round = 0; round < 24; round += 5) {
        BCa = state[ 0] ^ state[ 5] ^ state[10] ^ state[15] ^ state[20];
        BCe = state[ 1] ^ state[ 6] ^ state[11] ^ state[16] ^ state[21];
        BCi = state[ 2] ^ state[ 7] ^ state[12] ^ state[17] ^ state[22];
        BCo = state[ 3] ^ state[ 8] ^ state[13] ^ state[18] ^ state[23];
        BCu = state[ 4] ^ state[ 9] ^ state[14] ^ state[19] ^ state[24];

        Da = ROTL64(BCe, 1) ^ BCa;
        De = ROTL64(BCi, 1) ^ BCe;
        Di = ROTL64(BCo, 1) ^ BCi;
        Do = ROTL64(BCu, 1) ^ BCo;
        Du = ROTL64(BCa, 1) ^ BCu;

        state[ 0] ^= Da;
        state[ 5] ^= De;
        state[10] ^= Di;
        state[15] ^= Do;
        state[20] ^= Du;

        BCa = state[ 0] ^ state[ 5] ^ state[10] ^ state[15] ^ state[20];
        BCe = state[ 1] ^ state[ 6] ^ state[11] ^ state[16] ^ state[21];
        BCi = state[ 2] ^ state[ 7] ^ state[12] ^ state[17] ^ state[22];
        BCo = state[ 3] ^ state[ 8] ^ state[13] ^ state[18] ^ state[23];
        BCu = state[ 4] ^ state[ 9] ^ state[14] ^ state[19] ^ state[24];

        Da = ROTL64(BCe, 44) ^ BCa;
        De = ROTL64(BCi, 44) ^ BCe;
        Di = ROTL64(BCo, 44) ^ BCi;
        Do = ROTL64(BCu, 44) ^ BCo;
        Du = ROTL64(BCa, 44) ^ BCu;

        state[ 0] ^= Da;
        state[ 5] ^= De;
        state[10] ^= Di;
        state[15] ^= Do;
        state[20] ^= Du;
    }

    for (round = 0; round < 24; ++round) {
        Aba = state[KeccakF_PiLane[ 0]];
        Abe = state[KeccakF_PiLane[ 1]];
        Abi = state[KeccakF_PiLane[ 2]];
        Abo = state[KeccakF_PiLane[ 3]];
        Abu = state[KeccakF_PiLane[ 4]];

        Aga = state[KeccakF_PiLane[ 5]];
        Age = state[KeccakF_PiLane[ 6]];
        Agi = state[KeccakF_PiLane[ 7]];
        Ago = state[KeccakF_PiLane[ 8]];
        Agu = state[KeccakF_PiLane[ 9]];

        Aka = state[KeccakF_PiLane[10]];
        Ake = state[KeccakF_PiLane[11]];
        Aki = state[KeccakF_PiLane[12]];
        Ako = state[KeccakF_PiLane[13]];
        Aku = state[KeccakF_PiLane[14]];

        Ama = state[KeccakF_PiLane[15]];
        Ame = state[KeccakF_PiLane[16]];
        Ami = state[KeccakF_PiLane[17]];
        Amo = state[KeccakF_PiLane[18]];
        Amu = state[KeccakF_PiLane[19]];

        Asa = state[KeccakF_PiLane[20]];
        Ase = state[KeccakF_PiLane[21]];
        Asi = state[KeccakF_PiLane[22]];
        Aso = state[KeccakF_PiLane[23]];
        Asu = state[KeccakF_PiLane[24]];

        Eba = Aba;
        Ebe = ROTL64(Age, KeccakF_RotationOffsets[round + 1]);
        Ebi = ROTL64(Aki, KeccakF_RotationOffsets[round + 2]);
        Ebo = ROTL64(Amo, KeccakF_RotationOffsets[round + 3]);
        Ebu = ROTL64(Asu, KeccakF_RotationOffsets[round + 4]);

        Ega = Aga;
        Ege = ROTL64(Ake, KeccakF_RotationOffsets[round + 1]);
        Egi = ROTL64(Ami, KeccakF_RotationOffsets[round + 2]);
        Ego = ROTL64(Aso, KeccakF_RotationOffsets[round + 3]);
        Egu = ROTL64(Aba, KeccakF_RotationOffsets[round + 4]);

        Eka = Aka;
        Eke = ROTL64(Ame, KeccakF_RotationOffsets[round + 1]);
        Eki = ROTL64(Asi, KeccakF_RotationOffsets[round + 2]);
        Eko = ROTL64(Aba, KeccakF_RotationOffsets[round + 3]);
        Eku = ROTL64(Age, KeccakF_RotationOffsets[round + 4]);

        Ema = Ama;
        Eme = ROTL64(Abo, KeccakF_RotationOffsets[round + 1]);
        Emi = ROTL64(Agu, KeccakF_RotationOffsets[round + 2]);
        Emo = ROTL64(Aka, KeccakF_RotationOffsets[round + 3]);
        Emu = ROTL64(Ame, KeccakF_RotationOffsets[round + 4]);

        Esa = Asa;
        Ese = ROTL64(Age, KeccakF_RotationOffsets[round + 1]);
        Esi = ROTL64(Ako, KeccakF_RotationOffsets[round + 2]);
        Eso = ROTL64(Amo, KeccakF_RotationOffsets[round + 3]);
        Esu = ROTL64(Abi, KeccakF_RotationOffsets[round + 4]);

        Aba ^= (~Abe) & (Abi);
        Abe ^= (~Abi) & (Abo);
        Abi ^= (~Abo) & (Abu);
        Abo ^= (~Abu) & (Aba);
        Abu ^= (~Aba) & (Abe);

        Aga ^= (~Age) & (Agi);
        Age ^= (~Agi) & (Ago);
        Agi ^= (~Ago) & (Agu);
        Ago ^= (~Agu) & (Aga);
        Agu ^= (~Aga) & (Age);

        Aka ^= (~Ake) & (Aki);
        Ake ^= (~Aki) & (Ako);
        Aki ^= (~Ako) & (Aku);
        Ako ^= (~Aku) & (Aka);
        Aku ^= (~Aka) & (Ake);

        Ama ^= (~Ame) & (Ami);
        Ame ^= (~Ami) & (Amo);
        Ami ^= (~Amo) & (Amu);
        Amo ^= (~Amu) & (Ama);
        Amu ^= (~Ama) & (Ame);

        Asa ^= (~Ase) & (Asi);
        Ase ^= (~Asi) & (Aso);
        Asi ^= (~Aso) & (Asu);
        Aso ^= (~Asu) & (Asa);
        Asu ^= (~Asa) & (Ase);

        Aba ^= KeccakF_RoundConstants[round];
    }
}

static void KeccakF1600_StatePermute(uint64_t state[25]) {
    int round;

    for (round = 0; round < 24; round++) {
        KeccakF(state);
    }
}

int sha3_init(sha3_ctx_t *ctx, unsigned int hashlen) {
    if (ctx == NULL || (hashlen != 224 && hashlen != 256 && hashlen != 384 && hashlen != 512)) {
        return SHA3_INVALID_LENGTH;
    }

    ctx->hashlen = hashlen / 8;
    ctx->r = 200 - 2 * ctx->hashlen;
    ctx->capacity = ctx->r / 8;
    ctx->bitlen = 0;
    ctx->buffer = (unsigned char *)malloc(ctx->r / 8);
    if (ctx->buffer == NULL) {
        return SHA3_MEMORY_ERROR;
    }

    memset(ctx->state, 0, sizeof(ctx->state));
    return SHA3_SUCCESS;
}

int sha3_update(sha3_ctx_t *ctx, const unsigned char *data, size_t len) {
    if (ctx == NULL || data == NULL) {
        return SHA3_NULL_INPUT;
    }

    size_t index = 0;
    while (len--) {
        ctx->buffer[ctx->bitlen++ / 8] ^= data[index++];
        if (ctx->bitlen == 8 * ctx->r) {
            for (size_t i = 0; i < ctx->r / 8; ++i) {
                ctx->state[i] ^= ((uint64_t *)ctx->buffer)[i];
            }
            KeccakF1600_StatePermute(ctx->state);
            ctx->bitlen = 0;
        }
    }

    return SHA3_SUCCESS;
}

int sha3_final(sha3_ctx_t *ctx, unsigned char *hash) {
    if (ctx == NULL || hash == NULL) {
        return SHA3_NULL_INPUT;
    }

    ctx->buffer[ctx->bitlen / 8] ^= 0x06;
    ctx->buffer[(ctx->r - 1) / 8] ^= 0x80;

    for (size_t i = 0; i < ctx->r / 8; ++i) {
        ctx->state[i] ^= ((uint64_t *)ctx->buffer)[i];
    }

    KeccakF1600_StatePermute(ctx->state);

    memcpy(hash, ctx->state, ctx->hashlen);

    free(ctx->buffer);
    ctx->bitlen = 0;

    return SHA3_SUCCESS;
}

int sha3(const unsigned char *data, size_t len, unsigned char *hash, unsigned int hashlen) {
    sha3_ctx_t ctx;
    int ret;

    ret = sha3_init(&ctx, hashlen);
    if (ret != SHA3_SUCCESS) {
        return ret;
    }

    ret = sha3_update(&ctx, data, len);
    if (ret != SHA3_SUCCESS) {
        return ret;
    }

    ret = sha3_final(&ctx, hash);
    if (ret != SHA3_SUCCESS) {
        return ret;
    }

    return SHA3_SUCCESS;
}
