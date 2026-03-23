#include<stdint.h>
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

