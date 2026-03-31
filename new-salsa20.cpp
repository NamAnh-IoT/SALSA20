#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

/* Hàm biến đổi 1/4 (Quarter-round) của Salsa20 */
void quarter_round(uint32_t *y0, uint32_t *y1, uint32_t *y2, uint32_t *y3) {
    *y1 ^= ROTL(*y0 + *y3, 7);
    *y2 ^= ROTL(*y1 + *y0, 9);
    *y3 ^= ROTL(*y2 + *y1, 13);
    *y0 ^= ROTL(*y3 + *y2, 18);
}

/* Hàm cốt lõi biến đổi khối 64 byte */
void salsa20_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    int i;

    for (i = 0; i < 16; ++i) x[i] = in[i];

    for (i = 0; i < 20; i += 2) {
        quarter_round(&x[0], &x[4], &x[8], &x[12]);
        quarter_round(&x[5], &x[9], &x[13], &x[1]);
        quarter_round(&x[10], &x[14], &x[2], &x[6]);
        quarter_round(&x[15], &x[3], &x[7], &x[11]);

        quarter_round(&x[0], &x[1], &x[2], &x[3]);
        quarter_round(&x[5], &x[6], &x[7], &x[4]);
        quarter_round(&x[10], &x[11], &x[8], &x[9]);
        quarter_round(&x[15], &x[12], &x[13], &x[14]);
    }

    for (i = 0; i < 16; ++i) out[i] = x[i] + in[i];
}

/* Hàm thiết lập ma trận 16 số nguyên 32-bit (64 byte) từ Key và Nonce */
void salsa20_setup(uint32_t matrix[16], const uint8_t key[32], const uint8_t nonce[8], uint64_t counter) {
    matrix[0] = 0x61657870;
    matrix[5] = 0x6e642033;
    matrix[10] = 0x322d6279;
    matrix[15] = 0x7465206b;

    memcpy(&matrix[1], key, 16);
    memcpy(&matrix[11], key + 16, 16);
    memcpy(&matrix[6], nonce, 8);

    matrix[8] = counter & 0xFFFFFFFF;
    matrix[9] = counter >> 32;
}

/* Hàm mã hóa/giải mã chính */
void salsa20_encrypt(const uint8_t *key, const uint8_t *nonce, uint64_t counter, uint8_t *data, uint32_t data_len) {
    uint32_t matrix[16];
    uint32_t keystream[16];
    uint8_t *keystream8 = (uint8_t *)keystream;
    uint32_t i, j;

    for (i = 0; i < data_len; i += 64) {
        salsa20_setup(matrix, key, nonce, counter);
        salsa20_block(keystream, matrix);

        uint32_t block_len = (data_len - i < 64) ? (data_len - i) : 64;
        for (j = 0; j < block_len; ++j) {
            data[i + j] ^= keystream8[j];
        }

        counter++;
    }
}

int main() {
    uint8_t key[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    uint8_t nonce[8] = {1,2,3,4,5,6,7,8};
    
    char message[] = "Do you like to study cryptography course";
    uint32_t len = strlen(message);

    printf("Van ban goc: %s\n", message);

    salsa20_encrypt(key, nonce, 0, (uint8_t *)message, len);
    printf("Sau khi ma hoa (dang byte): ");
    for(int i=0; i<len; i++) printf("%02x ", (uint8_t)message[i]);
    printf("\n");

    salsa20_encrypt(key, nonce, 0, (uint8_t *)message, len);
    printf("Sau khi giai ma: %s\n", message);

    return 0;
}