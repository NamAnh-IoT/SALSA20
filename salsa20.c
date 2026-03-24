#include<stdint.h>
#include<stdio.h>
#include<stddef.h>
#include "salsa20.h"

static uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void s20_quarterround(uint32_t *y0, uint32_t *y1, uint32_t *y2, uint32_t *y3) {
    *y1 ^= rotl(*y0 + *y3, 7);
    *y2 ^= rotl(*y1 + *y0, 9);
    *y3 ^= rotl(*y2 + *y1, 13);
    *y0 ^= rotl(*y3 + *y2, 18);
}

static void s20_rowround(uint32_t y[16]) {
    s20_quarterround(&y[0], &y[1], &y[2], &y[3]);
    s20_quarterround(&y[5], &y[6], &y[7], &y[4]);
    s20_quarterround(&y[10], &y[11], &y[8], &y[9]);
    s20_quarterround(&y[15], &y[12], &y[13], &y[14]);
}

static void s20_columnround(uint32_t x[16]) {
    s20_quarterround(&x[0], &x[4], &x[8], &x[12]);
    s20_quarterround(&x[5], &x[9], &x[13], &x[1]);
    s20_quarterround(&x[10], &x[14], &x[2], &x[6]);
    s20_quarterround(&x[15], &x[3], &x[7], &x[11]);
}

static void s20_doubleround(uint32_t x[16]) {
    s20_columnround(x);
    s20_rowround(x);
}

static uint32_t load32_le(const uint8_t *src) {
    return (uint32_t)src[0] | ((uint32_t)src[1] << 8) |
           ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

static void store32_le(uint8_t *dst, uint32_t val) {
    dst[0] = (uint8_t)(val);
    dst[1] = (uint8_t)(val >> 8);
    dst[2] = (uint8_t)(val >> 16);
    dst[3] = (uint8_t)(val >> 24);
}

static void s20_hash(uint8_t seq[64], const uint32_t state[16]) {
    uint32_t x[16];
    int i;
    for (i = 0; i < 16; ++i) x[i] = state[i];
    for (i = 0; i < 10; ++i) s20_doubleround(x);
    for (i = 0; i < 16; ++i) store32_le(seq + (i * 4), x[i] + state[i]);
}

static const uint8_t sigma[16] = "expand 32-byte k";
static const uint8_t tau[16]   = "expand 16-byte k";

enum s20_status_t s20crypt(uint8_t *key,
                           enum s20_keylenght_t keylen,
                           uint8_t *nonce,
                           uint32_t counter,
                           uint8_t *input,
                           uint8_t *output,
                           uint32_t buflen) {
    if (!key || !nonce || !input || !output) return S20_FAILURE;

    uint32_t state[16];
    uint8_t block[64];
    const uint8_t *constants;

    if (keylen == S_20_KEY_256) {
        constants = sigma;
        state[1] = load32_le(key + 0);
        state[2] = load32_le(key + 4);
        state[3] = load32_le(key + 8);
        state[4] = load32_le(key + 12);
        state[11] = load32_le(key + 16);
        state[12] = load32_le(key + 20);
        state[13] = load32_le(key + 24);
        state[14] = load32_le(key + 28);
    } else {
        constants = tau;
        state[1] = load32_le(key + 0);
        state[2] = load32_le(key + 4);
        state[3] = load32_le(key + 8);
        state[4] = load32_le(key + 12);
        state[11] = load32_le(key + 0);
        state[12] = load32_le(key + 4);
        state[13] = load32_le(key + 8);
        state[14] = load32_le(key + 12);
    }

    state[0] = load32_le(constants + 0);
    state[5] = load32_le(constants + 4);
    state[10] = load32_le(constants + 8);
    state[15] = load32_le(constants + 12);

    state[6] = load32_le(nonce + 0);
    state[7] = load32_le(nonce + 4);

    state[8] = counter;
    state[9] = 0;

    uint32_t i;
    for (i = 0; i < buflen; ++i) {
        if (i % 64 == 0) {
            s20_hash(block, state);
            state[8]++;
            if (state[8] == 0) state[9]++; 
        }
        output[i] = input[i] ^ block[i % 64];
    }

    return S_20_SUCCESS;
}

// int main() {
//     // 1. Khai báo Key (256-bit = 32 byte) và Nonce/IV (64-bit = 8 byte)
//     uint8_t key[32] = {
//         1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
//         17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
//     };
//     uint8_t nonce[8] = { 101, 102, 103, 104, 105, 106, 107, 108 };
    
//     // 2. Để lấy Keystream thuần túy, đầu vào phải là mảng toàn số 0 (0x00)
//     uint8_t input_zeros[64] = {0}; 
//     uint8_t keystream[64] = {0};

//     // 3. Chạy thuật toán với Counter = 0
//     s20crypt(key, S_20_KEY_256, nonce, 0, input_zeros, keystream, 64);

//     // 4. In ra màn hình theo đúng format của file eSTREAM testvector.256
//     printf("Set 1, vector# Custom:\n");
    
//     // In Key
//     printf("                         key = ");
//     for(int i = 0; i < 32; i++) {
//         printf("%02X", key[i]);
//     }
//     printf("\n");
    
//     // In IV (Nonce)
//     printf("                          IV = ");
//     for(int i = 0; i < 8; i++) {
//         printf("%02X", nonce[i]);
//     }
//     printf("\n");
    
//     // In Keystream (ngắt dòng mỗi 32 ký tự Hex = 16 byte để giống format chuẩn)
//     printf("               stream[0..63] = ");
//     for(int i = 0; i < 64; i++) {
//         printf("%02X", keystream[i]);
//         if ((i + 1) % 16 == 0 && i != 63) {
//             printf("\n                               ");
//         }
//     }
//     printf("\n\n");
//     return 0;
// }