#include <stdio.h>

#include "randombytes.h"
#include "crypto_scalarmult_curve25519.h"

void hex(unsigned char* bs, size_t l)
{
    for(size_t i = 0; i < l; i++) {
        printf("%02x", bs[i]);
    }
}

int main()
{
    unsigned char sa[crypto_scalarmult_curve25519_SCALARBYTES];
    randombytes(sa, sizeof(sa));

    unsigned char pa[crypto_scalarmult_curve25519_BYTES];
    crypto_scalarmult_curve25519_base(pa, sa);

    unsigned char sb[crypto_scalarmult_curve25519_SCALARBYTES];
    randombytes(sb, sizeof(sb));

    unsigned char pb[crypto_scalarmult_curve25519_BYTES];
    crypto_scalarmult_curve25519_base(pb, sb);

    unsigned char shared[crypto_scalarmult_curve25519_BYTES];
    crypto_scalarmult_curve25519(shared, sa, pb);

    printf("TestVector {\n");
    printf("    secret_a: \""); hex(sa, sizeof(sa)); printf("\",\n");
    printf("    public_a: Some(\""); hex(pa, sizeof(pa)); printf("\"),\n");
    printf("    secret_b: Some(\""); hex(sb, sizeof(sb)); printf("\"),\n");
    printf("    public_b: \""); hex(pb, sizeof(pb)); printf("\",\n");
    printf("    shared: \""); hex(shared, sizeof(shared)); printf("\",\n");
    printf("},\n");

    return 0;
}
