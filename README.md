# lua-openssl-crypto

this is a c library with lua binding which can encrypt bytes just like openssl app.

there is only one interface.

```c
int encrypt_bytes(char *passphrase, char *plaintext, char **p, size_t *size)
```

the result is same as `echo -n "127.0.0.1:62863" | openssl enc -e -aes-256-cbc -a -salt -k "[Passphrase]"`

This library is using on client of [Frontd](https://github.com/FantaBlade/frontd)

`openssl.c` is basicly a modified version of [openssl](https://github.com/openssl/openssl)