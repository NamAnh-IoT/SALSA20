#ifndef _SALSA20_H_
#define _SALSA20_H_

#include<stdint.h>
#include<stddef.h>

enum s20_status_t {
    S_20_SUCCESS, S20_FAILURE;
};

enum s20_keylenght_t {
    S_20_KEY_128, S_20_KEY_256;
};

enum s20_status_t s20crypt(uint8_t *key,
                        enum s20_keylenght_t keylen,    
                        uint8_t *nonce,
                        uint32_t counter,
                        uint8_t *input,
                        uint8_t *output,
                        uint32_t buflen);

#endif
                       