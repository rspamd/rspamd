/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/***
 * @module rspamd_cryptobox
 * Rspamd cryptobox is a module that operates with digital signatures and
 * hashes.
 * @example
 * local hash = require "rspamd_cryptobox_hash"
 *
 * local h = hash.create()
 * h:update('hello world')
 * print(h:hex())
 */

#include "lua_common.h"
#include "cryptobox.h"
#include "keypair.h"
#include "unix-std.h"

LUA_FUNCTION_DEF (cryptobox_pubkey,	 load);
LUA_FUNCTION_DEF (cryptobox_pubkey,	 create);
LUA_FUNCTION_DEF (cryptobox_pubkey,	 gc);
LUA_FUNCTION_DEF (cryptobox_keypair,	 load);
LUA_FUNCTION_DEF (cryptobox_keypair,	 create);
LUA_FUNCTION_DEF (cryptobox_keypair,	 gc);
LUA_FUNCTION_DEF (cryptobox_signature, create);
LUA_FUNCTION_DEF (cryptobox_signature, load);
LUA_FUNCTION_DEF (cryptobox_signature, save);
LUA_FUNCTION_DEF (cryptobox_signature, gc);
LUA_FUNCTION_DEF (cryptobox_hash, create);
LUA_FUNCTION_DEF (cryptobox_hash, create_keyed);
LUA_FUNCTION_DEF (cryptobox_hash, update);
LUA_FUNCTION_DEF (cryptobox_hash, hex);
LUA_FUNCTION_DEF (cryptobox_hash, base32);
LUA_FUNCTION_DEF (cryptobox_hash, base64);
LUA_FUNCTION_DEF (cryptobox_hash, bin);
LUA_FUNCTION_DEF (cryptobox_hash, gc);
LUA_FUNCTION_DEF (cryptobox,			 verify_memory);
LUA_FUNCTION_DEF (cryptobox,			 verify_file);
LUA_FUNCTION_DEF (cryptobox,			 sign_file);
LUA_FUNCTION_DEF (cryptobox,			 sign_memory);

static const struct luaL_reg cryptoboxlib_f[] = {
	LUA_INTERFACE_DEF (cryptobox, verify_memory),
	LUA_INTERFACE_DEF (cryptobox, verify_file),
	LUA_INTERFACE_DEF (cryptobox, sign_memory),
	LUA_INTERFACE_DEF (cryptobox, sign_file),
	{NULL, NULL}
};

static const struct luaL_reg cryptoboxpubkeylib_f[] = {
	LUA_INTERFACE_DEF (cryptobox_pubkey, load),
	LUA_INTERFACE_DEF (cryptobox_pubkey, create),
	{NULL, NULL}
};

static const struct luaL_reg cryptoboxpubkeylib_m[] = {
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_cryptobox_pubkey_gc},
	{NULL, NULL}
};

static const struct luaL_reg cryptoboxkeypairlib_f[] = {
	LUA_INTERFACE_DEF (cryptobox_keypair, load),
	LUA_INTERFACE_DEF (cryptobox_keypair, create),
	{NULL, NULL}
};

static const struct luaL_reg cryptoboxkeypairlib_m[] = {
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_cryptobox_keypair_gc},
	{NULL, NULL}
};

static const struct luaL_reg cryptoboxsignlib_f[] = {
	LUA_INTERFACE_DEF (cryptobox_signature, load),
	LUA_INTERFACE_DEF (cryptobox_signature, create),
	{NULL, NULL}
};

static const struct luaL_reg cryptoboxsignlib_m[] = {
	LUA_INTERFACE_DEF (cryptobox_signature, save),
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_cryptobox_signature_gc},
	{NULL, NULL}
};

static const struct luaL_reg cryptoboxhashlib_f[] = {
	LUA_INTERFACE_DEF (cryptobox_hash, create),
	LUA_INTERFACE_DEF (cryptobox_hash, create_keyed),
	{NULL, NULL}
};

static const struct luaL_reg cryptoboxhashlib_m[] = {
	LUA_INTERFACE_DEF (cryptobox_hash, update),
	LUA_INTERFACE_DEF (cryptobox_hash, hex),
	LUA_INTERFACE_DEF (cryptobox_hash, base32),
	LUA_INTERFACE_DEF (cryptobox_hash, base64),
	LUA_INTERFACE_DEF (cryptobox_hash, bin),
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_cryptobox_hash_gc},
	{NULL, NULL}
};


static struct rspamd_cryptobox_pubkey *
lua_check_cryptobox_pubkey (lua_State * L, int pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{cryptobox_pubkey}");

	luaL_argcheck (L, ud != NULL, 1, "'cryptobox_pubkey' expected");
	return ud ? *((struct rspamd_cryptobox_pubkey **)ud) : NULL;
}

static struct rspamd_cryptobox_keypair *
lua_check_cryptobox_keypair (lua_State * L, int pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{cryptobox_keypair}");

	luaL_argcheck (L, ud != NULL, 1, "'cryptobox_keypair' expected");
	return ud ? *((struct rspamd_cryptobox_keypair **)ud) : NULL;
}

static rspamd_fstring_t *
lua_check_cryptobox_sign (lua_State * L, int pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{cryptobox_signature}");

	luaL_argcheck (L, ud != NULL, 1, "'cryptobox_signature' expected");
	return ud ? *((rspamd_fstring_t **)ud) : NULL;
}

static rspamd_cryptobox_hash_state_t *
lua_check_cryptobox_hash (lua_State * L, int pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{cryptobox_hash}");

	luaL_argcheck (L, ud != NULL, 1, "'cryptobox_hash' expected");
	return ud ? *((rspamd_cryptobox_hash_state_t **)ud) : NULL;
}

/***
 * @function rspamd_cryptobox_pubkey.load(file[, type[, alg]])
 * Loads public key from base32 encoded file
 * @param {string} file filename to load
 * @param {string} type optional 'sign' or 'kex' for signing and encryption
 * @param {string} alg optional 'default' or 'nist' for curve25519/nistp256 keys
 * @return {cryptobox_pubkey} new public key
 */
static gint
lua_cryptobox_pubkey_load (lua_State *L)
{
	struct rspamd_cryptobox_pubkey *pkey = NULL, **ppkey;
	const gchar *filename, *arg;
	gint type = RSPAMD_KEYPAIR_SIGN;
	gint alg = RSPAMD_CRYPTOBOX_MODE_25519;
	guchar *map;
	gsize len;

	filename = luaL_checkstring (L, 1);
	if (filename != NULL) {
		map = rspamd_file_xmap (filename, PROT_READ, &len);

		if (map == NULL) {
			msg_err ("cannot open pubkey from file: %s, %s",
				filename,
				strerror (errno));
			lua_pushnil (L);
		}
		else {
			if (lua_type (L, 2) == LUA_TSTRING) {
				/* keypair type */
				arg = lua_tostring (L, 2);

				if (strcmp (arg, "sign") == 0) {
					type = RSPAMD_KEYPAIR_SIGN;
				}
				else if (strcmp (arg, "kex") == 0) {
					type = RSPAMD_KEYPAIR_KEX;
				}
			}
			if (lua_type (L, 3) == LUA_TSTRING) {
				/* algorithm */
				arg = lua_tostring (L, 3);

				if (strcmp (arg, "default") == 0 || strcmp (arg, "curve25519") == 0) {
					type = RSPAMD_CRYPTOBOX_MODE_25519;
				}
				else if (strcmp (arg, "nist") == 0) {
					type = RSPAMD_CRYPTOBOX_MODE_NIST;
				}
			}

			pkey = rspamd_pubkey_from_base32 (map, len, type, alg);

			if (pkey == NULL) {
				msg_err ("cannot open pubkey from file: %s", filename);
				munmap (map, len);
				lua_pushnil (L);
			}
			else {
				munmap (map, len);
				ppkey = lua_newuserdata (L, sizeof (void *));
				rspamd_lua_setclass (L, "rspamd{cryptobox_pubkey}", -1);
				*ppkey = pkey;
			}
		}
	}
	else {
		return luaL_error (L, "bad input arguments");
	}

	return 1;
}


/***
 * @function rspamd_cryptobox_pubkey.create(data[, type[, alg]])
 * Loads public key from base32 encoded file
 * @param {base32 string} base32 string with the key
 * @param {string} type optional 'sign' or 'kex' for signing and encryption
 * @param {string} alg optional 'default' or 'nist' for curve25519/nistp256 keys
 * @return {cryptobox_pubkey} new public key
 */
static gint
lua_cryptobox_pubkey_create (lua_State *L)
{
	struct rspamd_cryptobox_pubkey *pkey = NULL, **ppkey;
	const gchar *buf, *arg;
	gsize len;
	gint type = RSPAMD_KEYPAIR_SIGN;
	gint alg = RSPAMD_CRYPTOBOX_MODE_25519;

	buf = luaL_checklstring (L, 1, &len);
	if (buf != NULL) {
		if (lua_type (L, 2) == LUA_TSTRING) {
			/* keypair type */
			arg = lua_tostring (L, 2);

			if (strcmp (arg, "sign") == 0) {
				type = RSPAMD_KEYPAIR_SIGN;
			}
			else if (strcmp (arg, "kex") == 0) {
				type = RSPAMD_KEYPAIR_KEX;
			}
		}
		if (lua_type (L, 3) == LUA_TSTRING) {
			/* algorithm */
			arg = lua_tostring (L, 3);

			if (strcmp (arg, "default") == 0 || strcmp (arg, "curve25519") == 0) {
				type = RSPAMD_CRYPTOBOX_MODE_25519;
			}
			else if (strcmp (arg, "nist") == 0) {
				type = RSPAMD_CRYPTOBOX_MODE_NIST;
			}
		}

		pkey = rspamd_pubkey_from_base32 (buf, len, type, alg);

		if (pkey == NULL) {
			msg_err ("cannot load pubkey from string");
			lua_pushnil (L);
		}
		else {
			ppkey = lua_newuserdata (L, sizeof (void *));
			rspamd_lua_setclass (L, "rspamd{cryptobox_pubkey}", -1);
			*ppkey = pkey;
		}

	}
	else {
		return luaL_error (L, "bad input arguments");
	}

	return 1;
}

static gint
lua_cryptobox_pubkey_gc (lua_State *L)
{
	struct rspamd_cryptobox_pubkey *pkey = lua_check_cryptobox_pubkey (L, 1);

	if (pkey != NULL) {
		rspamd_pubkey_unref (pkey);
	}

	return 0;
}

/***
 * @function rspamd_cryptobox_keypair.load(file)
 * Loads public key from UCL file
 * @param {string} file filename to load
 * @return {cryptobox_keypair} new keypair
 */
static gint
lua_cryptobox_keypair_load (lua_State *L)
{
	struct rspamd_cryptobox_keypair *kp, **pkp;
	const gchar *filename;
	struct ucl_parser *parser;
	ucl_object_t *obj;

	filename = luaL_checkstring (L, 1);
	if (filename != NULL) {
		parser = ucl_parser_new (0);

		if (!ucl_parser_add_file (parser, filename)) {
			msg_err ("cannot open keypair from file: %s, %s",
				filename,
				ucl_parser_get_error (parser));
			ucl_parser_free (parser);
			lua_pushnil (L);
		}
		else {
			obj = ucl_parser_get_object (parser);
			kp = rspamd_keypair_from_ucl (obj);
			ucl_parser_free (parser);

			if (kp == NULL) {
				msg_err ("cannot open keypair from file: %s",
						filename);
				ucl_object_unref (obj);
				lua_pushnil (L);
			}
			else {
				pkp = lua_newuserdata (L, sizeof (gpointer));
				*pkp = kp;
				rspamd_lua_setclass (L, "rspamd{cryptobox_keypair}", -1);
				ucl_object_unref (obj);
			}
		}
	}
	else {
		return luaL_error (L, "bad input arguments");
	}

	return 1;
}

/***
 * @function rspamd_cryptobox_keypair.create(ucl_data)
 * Loads public key from UCL data
 * @param {string} ucl_data ucl to load
 * @return {cryptobox_keypair} new keypair
 */
static gint
lua_cryptobox_keypair_create (lua_State *L)
{
	struct rspamd_cryptobox_keypair *kp, **pkp;
	const gchar *buf;
	gsize len;
	struct ucl_parser *parser;
	ucl_object_t *obj;

	buf = luaL_checklstring (L, 1, &len);
	if (buf != NULL) {
		parser = ucl_parser_new (0);

		if (!ucl_parser_add_chunk (parser, buf, len)) {
			msg_err ("cannot open keypair from data: %s",
				ucl_parser_get_error (parser));
			ucl_parser_free (parser);
			lua_pushnil (L);
		}
		else {
			obj = ucl_parser_get_object (parser);
			kp = rspamd_keypair_from_ucl (obj);
			ucl_parser_free (parser);

			if (kp == NULL) {
				msg_err ("cannot load keypair from data");
				ucl_object_unref (obj);
				lua_pushnil (L);
			}
			else {
				pkp = lua_newuserdata (L, sizeof (gpointer));
				*pkp = kp;
				rspamd_lua_setclass (L, "rspamd{cryptobox_keypair}", -1);
				ucl_object_unref (obj);
			}
		}
	}
	else {
		luaL_error (L, "bad input arguments");
	}

	return 1;
}

static gint
lua_cryptobox_keypair_gc (lua_State *L)
{
	struct rspamd_cryptobox_keypair *kp = lua_check_cryptobox_keypair (L, 1);

	if (kp != NULL) {
		rspamd_keypair_unref (kp);
	}

	return 0;
}

/***
 * @function rspamd_cryptobox_signature.load(file)
 * Loads signature from raw file
 * @param {string} file filename to load
 * @return {cryptobox_signature} new signature
 */
static gint
lua_cryptobox_signature_load (lua_State *L)
{
	rspamd_fstring_t *sig, **psig;
	const gchar *filename;
	gpointer data;
	int fd;
	struct stat st;

	filename = luaL_checkstring (L, 1);
	if (filename != NULL) {
		fd = open (filename, O_RDONLY);
		if (fd == -1) {
			msg_err ("cannot open signature file: %s, %s", filename,
				strerror (errno));
			lua_pushnil (L);
		}
		else {
			sig = g_malloc (sizeof (rspamd_fstring_t));
			if (fstat (fd, &st) == -1 ||
				(data =
				mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0))
						== MAP_FAILED) {
				msg_err ("cannot mmap file %s: %s", filename, strerror (errno));
				lua_pushnil (L);
			}
			else {
				if (st.st_size == rspamd_cryptobox_signature_bytes (
						RSPAMD_CRYPTOBOX_MODE_25519)) {
					sig = rspamd_fstring_new_init (data, st.st_size);
					psig = lua_newuserdata (L, sizeof (rspamd_fstring_t *));
					rspamd_lua_setclass (L, "rspamd{cryptobox_signature}", -1);
					*psig = sig;
				}
				else {
					msg_err ("size of %s missmatches: %d while %d is expected",
							filename, (int)st.st_size,
							rspamd_cryptobox_signature_bytes (RSPAMD_CRYPTOBOX_MODE_25519));
					lua_pushnil (L);
				}

				munmap (data, st.st_size);
			}
			close (fd);
		}
	}
	else {
		luaL_error (L, "bad input arguments");
	}

	return 1;
}

/***
 * @method rspamd_cryptobox_signature:save(file)
 * Stores signature in raw file
 * @param {string} file filename to use
 * @return {boolean} true if signature has been saved
 */
static gint
lua_cryptobox_signature_save (lua_State *L)
{
	rspamd_fstring_t *sig;
	gint fd, flags;
	const gchar *filename;
	gboolean forced = FALSE, res = TRUE;

	sig = lua_check_cryptobox_sign (L, 1);
	filename = luaL_checkstring (L, 2);

	if (!sig || !filename) {
		luaL_error (L, "bad input arguments");
		return 1;
	}

	if (lua_gettop (L) > 2) {
		forced = lua_toboolean (L, 3);
	}

	if (sig != NULL && filename != NULL) {
		flags = O_WRONLY | O_CREAT;
		if (forced) {
			flags |= O_TRUNC;
		}
		else {
			flags |= O_EXCL;
		}
		fd = open (filename, flags, 00644);
		if (fd == -1) {
			msg_err ("cannot create a signature file: %s, %s",
				filename,
				strerror (errno));
			lua_pushboolean (L, FALSE);
		}
		else {
			while (write (fd, sig->str, sig->len) == -1) {
				if (errno == EINTR) {
					continue;
				}
				msg_err ("cannot write to a signature file: %s, %s",
					filename,
					strerror (errno));
				res = FALSE;
				break;
			}
			lua_pushboolean (L, res);
			close (fd);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/***
 * @function rspamd_cryptobox_signature.create(data)
 * Creates signature object from raw data
 * @param {data} raw signature data
 * @return {cryptobox_signature} signature object
 */
static gint
lua_cryptobox_signature_create (lua_State *L)
{
	rspamd_fstring_t *sig, **psig;
	struct rspamd_lua_text *t;
	const gchar *data;
	gsize dlen;

	if (lua_isuserdata (L, 1)) {
		t = lua_check_text (L, 1);

		if (!t) {
			return luaL_error (L, "invalid arguments");
		}

		data = t->start;
		dlen = t->len;
	}
	else {
		data = luaL_checklstring (L, 1, &dlen);
	}

	if (data != NULL) {
		if (dlen == rspamd_cryptobox_signature_bytes (RSPAMD_CRYPTOBOX_MODE_25519)) {
			sig = rspamd_fstring_new_init (data, dlen);
			psig = lua_newuserdata (L, sizeof (rspamd_fstring_t *));
			rspamd_lua_setclass (L, "rspamd{cryptobox_signature}", -1);
			*psig = sig;
		}
	}
	else {
		return luaL_error (L, "bad input arguments");
	}

	return 1;
}

static gint
lua_cryptobox_signature_gc (lua_State *L)
{
	rspamd_fstring_t *sig = lua_check_cryptobox_sign (L, 1);

	rspamd_fstring_free (sig);

	return 0;
}

/***
 * @function rspamd_cryptobox_hash.create([string])
 * Creates new hash context
 * @param {string} data raw signature data
 * @return {cryptobox_hash} hash object
 */
static gint
lua_cryptobox_hash_create (lua_State *L)
{
	rspamd_cryptobox_hash_state_t *h, **ph;
	const gchar *s;
	gsize len;

	h = g_slice_alloc (sizeof (*h));
	rspamd_cryptobox_hash_init (h, NULL, 0);
	ph = lua_newuserdata (L, sizeof (void *));
	*ph = h;
	rspamd_lua_setclass (L, "rspamd{cryptobox_hash}", -1);

	if (lua_type (L, 1) == LUA_TSTRING) {
		s = lua_tolstring (L, 1, &len);

		if (s) {
			rspamd_cryptobox_hash_update (h, s, len);
		}
	}

	return 1;
}

/***
 * @function rspamd_cryptobox_hash.create_keyed(key, [string])
 * Creates new hash context with specified key
 * @param {string} key key
 * @return {cryptobox_hash} hash object
 */
static gint
lua_cryptobox_hash_create_keyed (lua_State *L)
{
	rspamd_cryptobox_hash_state_t *h, **ph;
	const gchar *key, *s;
	gsize len;
	gsize keylen;

	key = luaL_checklstring (L, 1, &keylen);

	if (key != NULL) {
		h = g_slice_alloc (sizeof (*h));
		rspamd_cryptobox_hash_init (h, key, keylen);
		ph = lua_newuserdata (L, sizeof (void *));
		*ph = h;
		rspamd_lua_setclass (L, "rspamd{cryptobox_hash}", -1);

		if (lua_type (L, 2) == LUA_TSTRING) {
			s = lua_tolstring (L, 2, &len);

			if (s) {
				rspamd_cryptobox_hash_update (h, s, len);
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/***
 * @method cryptobox_hash:update(data)
 * Updates hash with the specified data (hash should not be finalized using `hex` or `bin` methods)
 * @param {string} data data to hash
 */
static gint
lua_cryptobox_hash_update (lua_State *L)
{
	rspamd_cryptobox_hash_state_t *h = lua_check_cryptobox_hash (L, 1);
	const gchar *data;
	struct rspamd_lua_text *t;
	gsize len;

	if (lua_isuserdata (L, 2)) {
		t = lua_check_text (L, 2);

		if (!t) {
			return luaL_error (L, "invalid arguments");
		}

		data = t->start;
		len = t->len;
	}
	else {
		data = luaL_checklstring (L, 2, &len);
	}

	if (lua_isnumber (L, 3)) {
		gsize nlen = lua_tonumber (L, 3);

		if (nlen > len) {
			return luaL_error (L, "invalid length: %d while %d is available",
					(int)nlen, (int)len);
		}

		len = nlen;
	}

	if (h && data) {
		rspamd_cryptobox_hash_update (h, data, len);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

/***
 * @method cryptobox_hash:hex()
 * Finalizes hash and return it as hex string
 * @return {string} hex value of hash
 */
static gint
lua_cryptobox_hash_hex (lua_State *L)
{
	rspamd_cryptobox_hash_state_t *h = lua_check_cryptobox_hash (L, 1);
	guchar out[rspamd_cryptobox_HASHBYTES],
		out_hex[rspamd_cryptobox_HASHBYTES * 2 + 1];

	if (h) {
		memset (out_hex, 0, sizeof (out_hex));
		rspamd_cryptobox_hash_final (h, out);
		rspamd_encode_hex_buf (out, sizeof (out), out_hex, sizeof (out_hex));

		lua_pushstring (L, out_hex);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/***
 * @method cryptobox_hash:base32()
 * Finalizes hash and return it as zbase32 string
 * @return {string} base32 value of hash
 */
static gint
lua_cryptobox_hash_base32 (lua_State *L)
{
	rspamd_cryptobox_hash_state_t *h = lua_check_cryptobox_hash (L, 1);
	guchar out[rspamd_cryptobox_HASHBYTES],
		out_b32[rspamd_cryptobox_HASHBYTES * 2];

	if (h) {
		memset (out_b32, 0, sizeof (out_b32));
		rspamd_cryptobox_hash_final (h, out);
		rspamd_encode_base32_buf (out, sizeof (out), out_b32, sizeof (out_b32));

		lua_pushstring (L, out_b32);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/***
 * @method cryptobox_hash:base64()
 * Finalizes hash and return it as base64 string
 * @return {string} base64 value of hash
 */
static gint
lua_cryptobox_hash_base64 (lua_State *L)
{
	rspamd_cryptobox_hash_state_t *h = lua_check_cryptobox_hash (L, 1);
	guchar out[rspamd_cryptobox_HASHBYTES], *b64;
	gsize len;

	if (h) {
		rspamd_cryptobox_hash_final (h, out);
		b64 = rspamd_encode_base64 (out, sizeof (out), 0, &len);
		lua_pushlstring (L, b64, len);
		g_free (b64);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/***
 * @method cryptobox_hash:bin()
 * Finalizes hash and return it as raw string
 * @return {string} raw value of hash
 */
static gint
lua_cryptobox_hash_bin (lua_State *L)
{
	rspamd_cryptobox_hash_state_t *h = lua_check_cryptobox_hash (L, 1);
	guchar out[rspamd_cryptobox_HASHBYTES];

	if (h) {
		rspamd_cryptobox_hash_final (h, out);
		lua_pushlstring (L, out, sizeof (out));
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_cryptobox_hash_gc (lua_State *L)
{
	rspamd_cryptobox_hash_state_t *h = lua_check_cryptobox_hash (L, 1);

	rspamd_explicit_memzero (h, sizeof (*h));
	g_slice_free1 (sizeof (*h), h);

	return 0;
}

/***
 * @function rspamd_cryptobox.verify_memory(pk, sig, data)
 * Check memory using specified cryptobox key and signature
 * @param {pubkey} pk public key to verify
 * @param {sig} signature to check
 * @param {string} data data to check signature against
 * @return {boolean} `true` - if string matches cryptobox signature
 */
static gint
lua_cryptobox_verify_memory (lua_State *L)
{
	struct rspamd_cryptobox_pubkey *pk;
	rspamd_fstring_t *signature;
	struct rspamd_lua_text *t;
	const gchar *data;
	gsize len;
	gint ret;

	pk = lua_check_cryptobox_pubkey (L, 1);
	signature = lua_check_cryptobox_sign (L, 2);

	if (lua_isuserdata (L, 3)) {
		t = lua_check_text (L, 3);

		if (!t) {
			return luaL_error (L, "invalid arguments");
		}

		data = t->start;
		len = t->len;
	}
	else {
		data = luaL_checklstring (L, 3, &len);
	}

	if (pk != NULL && signature != NULL && data != NULL) {
		ret = rspamd_cryptobox_verify (signature->str, data, len,
				rspamd_pubkey_get_pk (pk, NULL), RSPAMD_CRYPTOBOX_MODE_25519);

		if (ret) {
			lua_pushboolean (L, 1);
		}
		else {
			lua_pushboolean (L, 0);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/***
 * @function rspamd_cryptobox.verify_file(pk, sig, file)
 * Check file using specified cryptobox key and signature
 * @param {pubkey} pk public key to verify
 * @param {sig} signature to check
 * @param {string} file to load data from
 * @return {boolean} `true` - if string matches cryptobox signature
 */
static gint
lua_cryptobox_verify_file (lua_State *L)
{
	const gchar *fname;
	struct rspamd_cryptobox_pubkey *pk;
	rspamd_fstring_t *signature;
	guchar *map = NULL;
	gsize len;
	gint ret;

	pk = lua_check_cryptobox_pubkey (L, 1);
	signature = lua_check_cryptobox_sign (L, 2);
	fname = luaL_checkstring (L, 3);

	map = rspamd_file_xmap (fname, PROT_READ, &len);

	if (map != NULL && pk != NULL && signature != NULL) {
		ret = rspamd_cryptobox_verify (signature->str, map, len,
				rspamd_pubkey_get_pk (pk, NULL), RSPAMD_CRYPTOBOX_MODE_25519);

		if (ret) {
			lua_pushboolean (L, 1);
		}
		else {
			lua_pushboolean (L, 0);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	if (map != NULL) {
		munmap (map, len);
	}

	return 1;
}

/***
 * @function rspamd_cryptobox.sign_memory(kp, data)
 * Sign data using specified keypair
 * @param {keypair} kp keypair to sign
 * @param {string} data
 * @return {cryptobox_signature} signature object
 */
static gint
lua_cryptobox_sign_memory (lua_State *L)
{
	struct rspamd_cryptobox_keypair *kp;
	const gchar *data;
	struct rspamd_lua_text *t;
	gsize len = 0;
	rspamd_fstring_t *sig, **psig;

	kp = lua_check_cryptobox_keypair (L, 1);

	if (lua_isuserdata (L, 2)) {
		t = lua_check_text (L, 2);

		if (!t) {
			return luaL_error (L, "invalid arguments");
		}

		data = t->start;
		len = t->len;
	}
	else {
		data = luaL_checklstring (L, 2, &len);
	}


	if (!kp || !data) {
		return luaL_error (L, "invalid arguments");
	}

	sig = rspamd_fstring_sized_new (rspamd_cryptobox_signature_bytes (
			rspamd_keypair_alg (kp)));
	rspamd_cryptobox_sign (sig->str, &sig->len, data,
			len, rspamd_keypair_component (kp, RSPAMD_KEYPAIR_COMPONENT_SK,
					NULL), rspamd_keypair_alg (kp));

	psig = lua_newuserdata (L, sizeof (void *));
	*psig = sig;
	rspamd_lua_setclass (L, "rspamd{cryptobox_signature}", -1);

	return 1;
}

/***
 * @function rspamd_cryptobox.sign_file(kp, file)
 * Sign file using specified keypair
 * @param {keypair} kp keypair to sign
 * @param {string} filename
 * @return {cryptobox_signature} signature object
 */
static gint
lua_cryptobox_sign_file (lua_State *L)
{
	struct rspamd_cryptobox_keypair *kp;
	const gchar *filename;
	gchar *data;
	gsize len = 0;
	rspamd_fstring_t *sig, **psig;

	kp = lua_check_cryptobox_keypair (L, 1);
	filename = luaL_checkstring (L, 2);

	if (!kp || !filename) {
		return luaL_error (L, "invalid arguments");
	}

	data = rspamd_file_xmap (filename, PROT_READ, &len);

	if (data == NULL) {
		msg_err ("cannot mmap file %s: %s", filename, strerror (errno));
		lua_pushnil (L);
	}
	else {
		sig = rspamd_fstring_sized_new (rspamd_cryptobox_signature_bytes (
				rspamd_keypair_alg (kp)));
		rspamd_cryptobox_sign (sig->str, &sig->len, data,
				len, rspamd_keypair_component (kp, RSPAMD_KEYPAIR_COMPONENT_SK,
						NULL), rspamd_keypair_alg (kp));

		psig = lua_newuserdata (L, sizeof (void *));
		*psig = sig;
		rspamd_lua_setclass (L, "rspamd{cryptobox_signature}", -1);
		munmap (data, len);
	}

	return 1;
}

static gint
lua_load_pubkey (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, cryptoboxpubkeylib_f);

	return 1;
}

static gint
lua_load_keypair (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, cryptoboxkeypairlib_f);

	return 1;
}

static gint
lua_load_signature (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, cryptoboxsignlib_f);

	return 1;
}

static gint
lua_load_hash (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, cryptoboxhashlib_f);

	return 1;
}

static gint
lua_load_cryptobox (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, cryptoboxlib_f);

	return 1;
}

void
luaopen_cryptobox (lua_State * L)
{
	luaL_newmetatable (L, "rspamd{cryptobox_pubkey}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{cryptobox_pubkey}");
	lua_rawset (L, -3);

	luaL_register (L, NULL, cryptoboxpubkeylib_m);
	rspamd_lua_add_preload (L, "rspamd_cryptobox_pubkey", lua_load_pubkey);

	luaL_newmetatable (L, "rspamd{cryptobox_keypair}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{cryptobox_keypair}");
	lua_rawset (L, -3);

	luaL_register (L, NULL, cryptoboxkeypairlib_m);
	rspamd_lua_add_preload (L, "rspamd_cryptobox_keypair", lua_load_keypair);

	luaL_newmetatable (L, "rspamd{cryptobox_signature}");

	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{cryptobox_signature}");
	lua_rawset (L, -3);

	luaL_register (L, NULL, cryptoboxsignlib_m);
	rspamd_lua_add_preload (L, "rspamd_cryptobox_signature", lua_load_signature);

	luaL_newmetatable (L, "rspamd{cryptobox_hash}");

	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{cryptobox_hash}");
	lua_rawset (L, -3);

	luaL_register (L, NULL, cryptoboxhashlib_m);
	rspamd_lua_add_preload (L, "rspamd_cryptobox_hash", lua_load_hash);

	rspamd_lua_add_preload (L, "rspamd_cryptobox", lua_load_cryptobox);

	lua_settop (L, 0);
}
