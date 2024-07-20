//
//  blake2.c
//  
//
//  Created by Nevio Hirani on 17.07.24.
//

#include "blake2.h"

static const uint32_t blake2s_IV[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const uint8_t blake2s_sigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 }
};

static int blake2s_init0(blake2s_state *S) {
    size_t i;

    memset(S, 0, sizeof(blake2s_state));
    for (i = 0; i < BLAKE2S_STATE_SIZE; ++i) {
        S->h[i] = blake2s_IV[i];
    }

    return 0;
}

static void blake2s_compress(blake2s_state *S, const uint8_t block[BLAKE2S_BLOCKBYTES]) {
    uint32_t m[16];
    uint32_t v[16];
    size_t i;

    for (i = 0; i < 16; ++i) {
        m[i] = (block[4 * i + 0]) |
               (block[4 * i + 1] << 8) |
               (block[4 * i + 2] << 16) |
               (block[4 * i + 3] << 24);
    }

    for (i = 0; i < 8; ++i) {
        v[i] = S->h[i];
    }

    v[ 8] = blake2s_IV[0];
    v[ 9] = blake2s_IV[1];
    v[10] = blake2s_IV[2];
    v[11] = blake2s_IV[3];
    v[12] = S->t[0] ^ blake2s_IV[4];
    v[13] = S->t[1] ^ blake2s_IV[5];
    v[14] = S->f[0] ^ blake2s_IV[6];
    v[15] = S->f[1] ^ blake2s_IV[7];

    for (i = 0; i < 10; ++i) {
        G(i, 0, v[ 0], v[ 4], v[ 8], v[12]);
        G(i, 1, v[ 1], v[ 5], v[ 9], v[13]);
        G(i, 2, v[ 2], v[ 6], v[10], v[14]);
        G(i, 3, v[ 3], v[ 7], v[11], v[15]);
        G(i, 4, v[ 0], v[ 5], v[10], v[15]);
        G(i, 5, v[ 1], v[ 6], v[11], v[12]);
        G(i, 6, v[ 2], v[ 7], v[ 8], v[13]);
        G(i, 7, v[ 3], v[ 4], v[ 9], v[14]);
    }

    for (i = 0; i < 8; ++i) {
        S->h[i] ^= v[i] ^ v[i + 8];
    }
}

int blake2s_init(blake2s_state *S, size_t outlen, const void *key, size_t keylen) {
    if (outlen == 0 || outlen > BLAKE2S_OUTBYTES) {
        return -1;
    }

    if (keylen > BLAKE2S_KEYBYTES) {
        return -1;
    }

    blake2s_init0(S);
    S->outlen = (uint8_t)outlen;
    S->buflen = BLAKE2S_BLOCKBYTES;

    memset(S->b, 0, S->buflen);
    S->t[0] = 0;
    S->t[1] = 0;
    S->f[0] = 0;
    S->f[1] = 0;
    S->last_node = NULL;

    if (keylen > 0) {
        uint8_t block[BLAKE2S_BLOCKBYTES];
        memset(block, 0, BLAKE2S_BLOCKBYTES);
        memcpy(block, key, keylen);
        blake2s_update(S, block, BLAKE2S_BLOCKBYTES);
        memset(block, 0, BLAKE2S_BLOCKBYTES); // Avoid leaking key
    }

    return 0;
}

int blake2s_update(blake2s_state *S, const void *pin, size_t inlen) {
    const uint8_t *in = (const uint8_t *)pin;

    while (inlen > 0) {
        size_t left = S->buflen;
        size_t fill = BLAKE2S_BLOCKBYTES - left;

        if (inlen > fill) {
            memcpy(S->b + left, in, fill);
            S->t[0] += BLAKE2S_BLOCKBYTES;
            if (S->t[0] == 0) {
                S->t[1]++;
            }
            blake2s_compress(S, S->b);
            S->buflen = 0;
            in += fill;
            inlen -= fill;
        } else {
            memcpy(S->b + left, in, inlen);
            S->buflen += inlen;
            in += inlen;
            inlen -= inlen;
        }
    }

    return 0;
}

int blake2s_final(blake2s_state *S, void *out, size_t outlen) {
    uint8_t buffer[BLAKE2S_OUTBYTES];
    size_t i;

    if (outlen == 0 || outlen > BLAKE2S_OUTBYTES) {
        return -1;
    }

    if (blake2s_update(S, S->b, S->buflen) != 0) {
        return -1;
    }

    S->t[0] += S->buflen;
    if (S->t[0] < S->buflen) {
        S->t[1]++;
    }

    S->f[0] = 0xFFFFFFFF;
    memset(S->b + S->buflen, 0, BLAKE2S_BLOCKBYTES - S->buflen);
    blake2s_compress(S, S->b);

    for (i = 0; i < BLAKE2S_STATE_SIZE; ++i) {
        buffer[4 * i + 0] = (uint8_t)(S->h[i] >> 0);
        buffer[4 * i + 1] = (uint8_t)(S->h[i] >> 8);
        buffer[4 * i + 2] = (uint8_t)(S->h[i] >> 16);
        buffer[4 * i + 3] = (uint8_t)(S->h[i] >> 24);
    }

    memcpy(out, buffer, outlen);
    memset(buffer, 0, sizeof(buffer)); // Avoid leaking sensitive data

    return 0;
}
