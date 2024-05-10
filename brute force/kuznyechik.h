#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define KUZNYECHIK_KEY_SIZE 32
#define KUZNYECHIK_BLOCK_SIZE 16
#define KUZNYECHIK_SUBKEYS_SIZE (16 * 10)

struct kuznyechik_ctx
{
    uint8_t key[KUZNYECHIK_SUBKEYS_SIZE];
    uint8_t dekey[KUZNYECHIK_SUBKEYS_SIZE];
};

void xor_byte(uint8_t *dst, const uint8_t *src, unsigned int size);

void xor_byte_cpy(uint8_t *dst, const uint8_t *src1, const uint8_t *src2, unsigned int size);


void S(uint8_t *a, const uint8_t *b);

void Sinv(uint8_t *a, const uint8_t *b);

void Linv(uint8_t *a, const uint8_t *b);

void LSX(uint8_t *a, const uint8_t *b, const uint8_t *c);

void XLiSi(uint8_t *a, const uint8_t *b, const uint8_t *c);

void subkey(uint8_t *out, const uint8_t *key, unsigned int i);

int kuznyechik_set_key(struct kuznyechik_ctx *ctx, const uint8_t *in_key, unsigned int key_len);

void kuznyechik_encrypt(const struct kuznyechik_ctx *ctx, uint8_t *out, const uint8_t *in);

void kuznyechik_decrypt(const struct kuznyechik_ctx *ctx, uint8_t *out, const uint8_t *in);
