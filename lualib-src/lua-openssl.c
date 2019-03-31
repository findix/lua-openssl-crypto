#include <lua.h>
#include <lauxlib.h>

#include "openssl.h"

// aes_256_cbc encrypt with salt and base64 packed
static int
crypt_encrypt(lua_State *L)
{
  const char *passphrase = luaL_checkstring(L, 1);
  const char *plaintext = luaL_checkstring(L, 2);

  char *p;
  size_t sz;
  encrypt_bytes(passphrase, plaintext, &p, &sz);
  lua_pushlstring(L, p, sz);
  free(p);
  return 1;
}

int luaopen_lopenssl(lua_State *L)
{
  luaL_checkversion(L);

  luaL_Reg l[] = {
      {"encrypt", crypt_encrypt},
      {NULL, NULL}};

  luaL_newlib(L, l);
  return 1;
}