#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (sodium_init() < 0) return 1;
    if (argc < 3) {
        printf("Usage: %s <priv_out> <pub_out>\n", argv[0]);
        return 1;
    }
    const char *priv = argv[1], *pub = argv[2];
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);
    FILE *f = fopen(priv, "wb");
    if (!f) { perror("fopen priv"); return 1; }
    fwrite(sk, 1, sizeof(sk), f); fclose(f);
    chmod(priv, 0600);
    f = fopen(pub, "wb");
    if (!f) { perror("fopen pub"); return 1; }
    fwrite(pk, 1, sizeof(pk), f); fclose(f);
    printf("Keys written: %s %s\n", priv, pub);
    return 0;
}
