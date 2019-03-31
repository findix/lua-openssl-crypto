#include "openssl.h"

void test(char *passphrase, char *plaintext)
{
    char *p;
    size_t sz;
    encrypt_bytes(passphrase, plaintext, &p, &sz);
    char str[sz + 1];
    memcpy(str, p, sz);
    str[sz] = '\0';
    printf("%s %d\n", p, sz);
    free(p);
}

int main(int argc, char *argv[])
{
    char passphrase[] = "p0S8rX680*48";
    char plaintext[] = "this is a test";
    test(passphrase, plaintext);
    return 0;
}