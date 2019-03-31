#include "openssl.h"

int FMT_istext(int format)
{
    return (format & B_FORMAT_TEXT) == B_FORMAT_TEXT;
}

BIO *dup_bio_in(int format);
BIO *bio_open_default(const char *filename, char mode, int format);
static int set_hex(const char *in, unsigned char *out, int size);
int opt_cipher(const char *name, const EVP_CIPHER **cipherp);
int opt_md(const char *name, const EVP_MD **mdp);

// aes_256_cbc encrypt with salt and base64 packed
int encrypt_bytes(char *passphrase, char *plaintext, char **p, size_t *size)
{
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    // static char buf[128];
    static const char magic[] = "Salted__";
    BIO *in = NULL, *out = NULL, *b64 = NULL, *benc = NULL, *rbio = NULL, *wbio = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL /* , *c */;
    const EVP_MD *dgst = NULL;
    char *hkey = NULL, *hiv = NULL, *hsalt = NULL;
    char *infile = NULL, *outfile = NULL, *prog;
    char *str = NULL, *passarg = NULL, *pass = NULL, *strbuf = NULL;
    char mbuf[sizeof(magic) - 1];
    int bsize = BSIZE, verbose = 0, /* debug = 0, */ olb64 = 0, nosalt = 0;
    int enc = 1, printkey = 0, i /* , k */;
    int base64 = 0, informat = FORMAT_BINARY, outformat = FORMAT_BINARY;
    int ret = 1, inl, nopad = 0;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    unsigned char *buff = NULL, salt[PKCS5_SALT_LEN];
    int pbkdf2 = 0;
    int iter = 0;
    // long n;
    // struct doall_enc_ciphers dec;

    // Create cipher
    prog = "enc";
    if (cipher == NULL && strcmp(prog, "enc") != 0)
    {
        printf("%s is not a known cipher\n", prog);
        goto end;
    }

    // set opt
    enc = 1;                            // -e
    opt_cipher("aes-256-cbc", &cipher); //-aes-256-cbc
    base64 = 1;                         // -a or -base64
    nosalt = 0;                         // -salt
    passarg = passphrase;               // -k passphrase
    opt_md("md5", &dgst);               // -md md5
    // debug
    // verbose = 1;
    // printkey = 1;

    if (dgst == NULL)
        dgst = EVP_sha256();

    if (iter == 0)
        iter = 1;

    /* It must be large enough for a base64 encoded line */
    if (base64 && bsize < 80)
        bsize = 80;
    if (verbose)
        printf("bufsize=%d\n", bsize);

    if (base64)
    {
        if (enc)
            outformat = FORMAT_BASE64;
        else
            informat = FORMAT_BASE64;
    }

    strbuf = malloc(SIZE);
    buff = malloc(EVP_ENCODE_LENGTH(bsize));

    if (infile == NULL)
    {
        in = BIO_new(BIO_s_mem());
    }
    else
    {
        in = bio_open_default(infile, 'r', informat);
    }
    if (in == NULL)
        goto end;

    if (str == NULL && passarg != NULL)
    {
        str = passarg;
    }

    if (outfile == NULL)
    {
        out = BIO_new(BIO_s_mem());
    }
    else
    {
        out = bio_open_default(outfile, 'w', outformat);
    }
    if (out == NULL)
        goto end;

    rbio = in;
    wbio = out;

    if (base64)
    {
        if ((b64 = BIO_new(BIO_f_base64())) == NULL)
            goto end;
        if (olb64)
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        if (enc)
            wbio = BIO_push(b64, wbio);
        else
            rbio = BIO_push(b64, rbio);
    }

    if (cipher != NULL)
    {
        /*
        * Note that str is NULL if a key was passed on the command line, so
        * we get no salt in that case. Is this a bug?
        */
        if (str != NULL)
        {
            /*
            * Salt handling: if encrypting generate a salt and write to
            * output BIO. If decrypting read salt from input BIO.
            */
            unsigned char *sptr;
            size_t str_len = strlen(str);

            if (nosalt)
            {
                sptr = NULL;
            }
            else
            {
                if (enc)
                {
                    if (hsalt)
                    {
                        if (!set_hex(hsalt, salt, sizeof(salt)))
                        {
                            printf("invalid hex salt value\n");
                            goto end;
                        }
                    }
                    else if (RAND_bytes(salt, sizeof(salt)) <= 0)
                    {
                        goto end;
                    }
                    /*
                     * If -P option then don't bother writing
                     */
                    if ((printkey != 2) && (BIO_write(wbio, magic,
                                                      sizeof(magic) - 1) != sizeof(magic) - 1 ||
                                            BIO_write(wbio,
                                                      (char *)salt,
                                                      sizeof(salt)) != sizeof(salt)))
                    {
                        printf("error writing output file\n");
                        goto end;
                    }
                }
                else if (BIO_read(rbio, mbuf, sizeof(mbuf)) != sizeof(mbuf) || BIO_read(rbio,
                                                                                        (unsigned char *)salt,
                                                                                        sizeof(salt)) != sizeof(salt))
                {
                    printf("error reading input file\n");
                    goto end;
                }
                else if (memcmp(mbuf, magic, sizeof(magic) - 1))
                {
                    printf("bad magic number\n");
                    goto end;
                }
                sptr = salt;
            }

            if (pbkdf2 == 1)
            {
                /*
                * derive key and default iv
                * concatenated into a temporary buffer
                */
                unsigned char tmpkeyiv[EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH];
                int iklen = EVP_CIPHER_key_length(cipher);
                int ivlen = EVP_CIPHER_iv_length(cipher);
                /* not needed if HASH_UPDATE() is fixed : */
                int islen = (sptr != NULL ? sizeof(salt) : 0);
                if (!PKCS5_PBKDF2_HMAC(str, str_len, sptr, islen,
                                       iter, dgst, iklen + ivlen, tmpkeyiv))
                {
                    printf("PKCS5_PBKDF2_HMAC failed\n");
                    goto end;
                }
                /* split and move data back to global buffer */
                memcpy(key, tmpkeyiv, iklen);
                memcpy(iv, tmpkeyiv + iklen, ivlen);
            }
            else
            {
                // printf("*** WARNING : "
                //        "deprecated key derivation used.\n"
                //        "Using -iter or -pbkdf2 would be better.\n");
                if (!EVP_BytesToKey(cipher, dgst, sptr,
                                    (unsigned char *)str, str_len,
                                    1, key, iv))
                {
                    printf("EVP_BytesToKey failed\n");
                    goto end;
                }
            }
            /*
             * zero the complete buffer or the string passed from the command
             * line.
             */
            OPENSSL_cleanse(str, str_len);
        }
        if (hiv != NULL)
        {
            int siz = EVP_CIPHER_iv_length(cipher);
            if (siz == 0)
            {
                printf("warning: iv not use by this cipher\n");
            }
            else if (!set_hex(hiv, iv, siz))
            {
                printf("invalid hex iv value\n");
                goto end;
            }
        }
        if ((hiv == NULL) && (str == NULL) && EVP_CIPHER_iv_length(cipher) != 0)
        {
            /*
             * No IV was explicitly set and no IV was generated.
             * Hence the IV is undefined, making correct decryption impossible.
             */
            printf("iv undefined\n");
            goto end;
        }
        if (hkey != NULL)
        {
            if (!set_hex(hkey, key, EVP_CIPHER_key_length(cipher)))
            {
                printf("invalid hex key value\n");
                goto end;
            }
            /* wiping secret data as we no longer need it */
            OPENSSL_cleanse(hkey, strlen(hkey));
        }

        if ((benc = BIO_new(BIO_f_cipher())) == NULL)
            goto end;

        /*
         * Since we may be changing parameters work on the encryption context
         * rather than calling BIO_set_cipher().
         */

        BIO_get_cipher_ctx(benc, &ctx);

        if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc))
        {
            printf("Error setting cipher %s\n",
                   EVP_CIPHER_name(cipher));
            goto end;
        }

        if (nopad)
            EVP_CIPHER_CTX_set_padding(ctx, 0);

        if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, enc))
        {
            printf("Error setting cipher %s\n",
                   EVP_CIPHER_name(cipher));
            goto end;
        }

        if (printkey)
        {
            if (!nosalt)
            {
                printf("salt=");
                for (i = 0; i < (int)sizeof(salt); i++)
                    printf("%02X", salt[i]);
                printf("\n");
            }
            if (EVP_CIPHER_key_length(cipher) > 0)
            {
                printf("key=");
                for (i = 0; i < EVP_CIPHER_key_length(cipher); i++)
                    printf("%02X", key[i]);
                printf("\n");
            }
            if (EVP_CIPHER_iv_length(cipher) > 0)
            {
                printf("iv =");
                for (i = 0; i < EVP_CIPHER_iv_length(cipher); i++)
                    printf("%02X", iv[i]);
                printf("\n");
            }
            if (printkey == 2)
            {
                ret = 0;
                goto end;
            }
        }
    }

    // 写入
    BIO_write(rbio, plaintext, strlen(plaintext));

    /* Only encrypt/decrypt as we write the file */
    if (benc != NULL)
        wbio = BIO_push(benc, wbio);

    for (;;)
    {
        inl = BIO_read(rbio, (char *)buff, bsize);
        if (inl <= 0)
            break;
        if (BIO_write(wbio, (char *)buff, inl) != inl)
        {
            printf("error writing output file\n");
            goto end;
        }
    }

    if (!BIO_flush(wbio))
    {
        printf("bad decrypt\n");
        goto end;
    }

    char *data;
    size_t sz;
    sz = BIO_get_mem_data(wbio, &data);
    if (!size)
    {
        ret = 1;
        goto end;
    }
    (*size) = sz;
    *p = malloc(sz);
    memcpy(*p, data, sz);
    ret = 0;
    if (verbose)
    {
        printf("bytes read   : %8ju\n", BIO_number_read(in));
        printf("bytes written: %8ju\n", BIO_number_written(out));
    }
end:
    OPENSSL_free(strbuf);
    OPENSSL_free(buff);
    BIO_free(in);
    BIO_free_all(out);
    BIO_free(benc);
    BIO_free(b64);
    OPENSSL_free(pass);

    /* Clean up */

    /* Removes all digests and ciphers */
    EVP_cleanup();

    /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
    CRYPTO_cleanup_all_ex_data();

    return ret;
}

/*
 * Centralized handling of input and output files with format specification
 * The format is meant to show what the input and output is supposed to be,
 * and is therefore a show of intent more than anything else.  However, it
 * does impact behavior on some platforms, such as differentiating between
 * text and binary input/output on non-Unix platforms
 */
BIO *dup_bio_in(int format)
{
    return BIO_new_fp(stdin, BIO_NOCLOSE | (FMT_istext(format) ? BIO_FP_TEXT : 0));
}

BIO *dup_bio_out(int format)
{
    return BIO_new_fp(stdout,
                      BIO_NOCLOSE | (FMT_istext(format) ? BIO_FP_TEXT : 0));
}

static const char *modestr(char mode, int format)
{
    switch (mode)
    {
    case 'a':
        return FMT_istext(format) ? "a" : "ab";
    case 'r':
        return FMT_istext(format) ? "r" : "rb";
    case 'w':
        return FMT_istext(format) ? "w" : "wb";
    }
    /* The assert above should make sure we never reach this point */
    return NULL;
}

static const char *modeverb(char mode)
{
    switch (mode)
    {
    case 'a':
        return "appending";
    case 'r':
        return "reading";
    case 'w':
        return "writing";
    }
    return "(doing something)";
}

static BIO *bio_open_default_(const char *filename, char mode, int format, int quiet)
{
    BIO *ret;

    if (filename == NULL || strcmp(filename, "-") == 0)
    {
        ret = mode == 'r' ? dup_bio_in(format) : dup_bio_out(format);
        if (quiet)
        {
            ERR_clear_error();
            return ret;
        }
        if (ret != NULL)
            return ret;
        printf("Can't open %s, %s\n", mode == 'r' ? "stdin" : "stdout", strerror(errno));
    }
    else
    {
        ret = BIO_new_file(filename, modestr(mode, format));
        if (quiet)
        {
            ERR_clear_error();
            return ret;
        }
        if (ret != NULL)
            return ret;
        printf("Can't open %s for %s, %s\n", filename, modeverb(mode), strerror(errno));
    }
    return NULL;
}

BIO *bio_open_default(const char *filename, char mode, int format)
{
    return bio_open_default_(filename, mode, format, 0);
}

int OPENSSL_hexchar2int(unsigned char c)
{
#ifdef CHARSET_EBCDIC
    c = os_toebcdic[c];
#endif

    switch (c)
    {
    case '0':
        return 0;
    case '1':
        return 1;
    case '2':
        return 2;
    case '3':
        return 3;
    case '4':
        return 4;
    case '5':
        return 5;
    case '6':
        return 6;
    case '7':
        return 7;
    case '8':
        return 8;
    case '9':
        return 9;
    case 'a':
    case 'A':
        return 0x0A;
    case 'b':
    case 'B':
        return 0x0B;
    case 'c':
    case 'C':
        return 0x0C;
    case 'd':
    case 'D':
        return 0x0D;
    case 'e':
    case 'E':
        return 0x0E;
    case 'f':
    case 'F':
        return 0x0F;
    }
    return -1;
}

static int set_hex(const char *in, unsigned char *out, int size)
{
    int i, n;
    unsigned char j;

    i = size * 2;
    n = strlen(in);
    if (n > i)
    {
        printf("hex string is too long, ignoring excess\n");
        n = i; /* ignore exceeding part */
    }
    else if (n < i)
    {
        printf("hex string is too short, padding with zero bytes to length\n");
    }

    memset(out, 0, size);
    for (i = 0; i < n; i++)
    {
        j = (unsigned char)*in++;
        if (!isxdigit(j))
        {
            printf("non-hex digit\n");
            return 0;
        }
        j = (unsigned char)OPENSSL_hexchar2int(j);
        if (i & 1)
            out[i / 2] |= j;
        else
            out[i / 2] = (j << 4);
    }
    return 1;
}

/* Parse a cipher name, put it in *EVP_CIPHER; return 0 on failure, else 1. */
int opt_cipher(const char *name, const EVP_CIPHER **cipherp)
{
    *cipherp = EVP_get_cipherbyname(name);
    if (*cipherp != NULL)
        return 1;
    printf("Unrecognized flag %s\n", name);
    return 0;
}

/*
 * Parse message digest name, put it in *EVP_MD; return 0 on failure, else 1.
 */
int opt_md(const char *name, const EVP_MD **mdp)
{
    *mdp = EVP_get_digestbyname(name);
    if (*mdp != NULL)
        return 1;
    printf("Unrecognized flag %s\n", name);
    return 0;
}