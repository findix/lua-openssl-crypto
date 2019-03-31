#ifndef OPENSSL_CRYPTO_H
#define OPENSSL_CRYPTO_H

// #include <stdio.h>
// #include <stdlib.h>
#include <string.h>
// #include <limits.h>
// #include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
// #include <openssl/objects.h>
// #include <openssl/x509.h>
#include <openssl/rand.h>
// #include <openssl/pem.h>
// #ifndef OPENSSL_NO_COMP
// # include <openssl/comp.h>
// #endif
#include <ctype.h>

#undef SIZE
#undef BSIZE
#define SIZE (512)
#define BSIZE (8 * 1024)

// fmt.c begin
#define B_FORMAT_TEXT 0x8000
#define FORMAT_UNDEF 0
#define FORMAT_TEXT (1 | B_FORMAT_TEXT)   /* Generic text */
#define FORMAT_BINARY 2                   /* Generic binary */
#define FORMAT_BASE64 (3 | B_FORMAT_TEXT) /* Base64 */
#define FORMAT_ASN1 4                     /* ASN.1/DER */
#define FORMAT_PEM (5 | B_FORMAT_TEXT)
#define FORMAT_PKCS12 6
#define FORMAT_SMIME (7 | B_FORMAT_TEXT)
#define FORMAT_ENGINE 8                   /* Not really a file format */
#define FORMAT_PEMRSA (9 | B_FORMAT_TEXT) /* PEM RSAPubicKey format */
#define FORMAT_ASN1RSA 10                 /* DER RSAPubicKey format */
#define FORMAT_MSBLOB 11                  /* MS Key blob format */
#define FORMAT_PVK 12                     /* MS PVK file format */
#define FORMAT_HTTP 13                    /* Download using HTTP */
#define FORMAT_NSS 14                     /* NSS keylog format */

int FMT_istext(int format);

// fmt.c end

int encrypt_bytes();

struct doall_enc_ciphers
{
    BIO *bio;
    int n;
};

#endif