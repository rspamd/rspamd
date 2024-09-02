/*
 * Copyright 2024 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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
#include "libcryptobox/cryptobox.h"
#include "libcryptobox/keypair.h"
#include "libcryptobox/keypair_private.h"
#include "unix-std.h"
#include "contrib/libottery/ottery.h"
#include "libutil/ref.h"

#include <stdalign.h>
#include <openssl/hmac.h>


enum lua_cryptobox_hash_type {
	LUA_CRYPTOBOX_HASH_BLAKE2 = 0,
	LUA_CRYPTOBOX_HASH_SSL,
	LUA_CRYPTOBOX_HASH_HMAC,
	LUA_CRYPTOBOX_HASH_XXHASH64,
	LUA_CRYPTOBOX_HASH_XXHASH32,
	LUA_CRYPTOBOX_HASH_XXHASH3,
	LUA_CRYPTOBOX_HASH_MUM,
	LUA_CRYPTOBOX_HASH_T1HA,
};

struct rspamd_lua_cryptobox_hash {
	union {
		rspamd_cryptobox_hash_state_t *h;
		EVP_MD_CTX *c;
		EVP_MAC_CTX *hmac_c;
		rspamd_cryptobox_fast_hash_state_t *fh;
	} content;

	unsigned char out[rspamd_cryptobox_HASHBYTES];

	uint8_t type;
	uint8_t out_len;
	uint8_t is_finished;

	ref_entry_t ref;
};

LUA_FUNCTION_DEF(cryptobox_pubkey, load);
LUA_FUNCTION_DEF(cryptobox_pubkey, create);
LUA_FUNCTION_DEF(cryptobox_pubkey, gc);
LUA_FUNCTION_DEF(cryptobox_keypair, load);
LUA_FUNCTION_DEF(cryptobox_keypair, create);
LUA_FUNCTION_DEF(cryptobox_keypair, gc);
LUA_FUNCTION_DEF(cryptobox_keypair, totable);
LUA_FUNCTION_DEF(cryptobox_keypair, get_type);
LUA_FUNCTION_DEF(cryptobox_keypair, get_alg);
LUA_FUNCTION_DEF(cryptobox_keypair, get_pk);
LUA_FUNCTION_DEF(cryptobox_signature, create);
LUA_FUNCTION_DEF(cryptobox_signature, load);
LUA_FUNCTION_DEF(cryptobox_signature, save);
LUA_FUNCTION_DEF(cryptobox_signature, gc);
LUA_FUNCTION_DEF(cryptobox_signature, hex);
LUA_FUNCTION_DEF(cryptobox_signature, base32);
LUA_FUNCTION_DEF(cryptobox_signature, base64);
LUA_FUNCTION_DEF(cryptobox_signature, bin);
LUA_FUNCTION_DEF(cryptobox_hash, create);
LUA_FUNCTION_DEF(cryptobox_hash, create_specific);
LUA_FUNCTION_DEF(cryptobox_hash, create_specific_keyed);
LUA_FUNCTION_DEF(cryptobox_hash, create_keyed);
LUA_FUNCTION_DEF(cryptobox_hash, update);
LUA_FUNCTION_DEF(cryptobox_hash, reset);
LUA_FUNCTION_DEF(cryptobox_hash, hex);
LUA_FUNCTION_DEF(cryptobox_hash, base32);
LUA_FUNCTION_DEF(cryptobox_hash, base64);
LUA_FUNCTION_DEF(cryptobox_hash, bin);
LUA_FUNCTION_DEF(cryptobox_hash, gc);
LUA_FUNCTION_DEF(cryptobox, verify_memory);
LUA_FUNCTION_DEF(cryptobox, verify_file);
LUA_FUNCTION_DEF(cryptobox, sign_file);
LUA_FUNCTION_DEF(cryptobox, sign_memory);
LUA_FUNCTION_DEF(cryptobox, encrypt_memory);
LUA_FUNCTION_DEF(cryptobox, encrypt_file);
LUA_FUNCTION_DEF(cryptobox, decrypt_memory);
LUA_FUNCTION_DEF(cryptobox, decrypt_file);
LUA_FUNCTION_DEF(cryptobox, encrypt_cookie);
LUA_FUNCTION_DEF(cryptobox, decrypt_cookie);
LUA_FUNCTION_DEF(cryptobox, pbkdf);
LUA_FUNCTION_DEF(cryptobox, gen_dkim_keypair);

/* Secretbox API: uses libsodium secretbox and blake2b for key derivation */
LUA_FUNCTION_DEF(cryptobox_secretbox, create);
LUA_FUNCTION_DEF(cryptobox_secretbox, encrypt);
LUA_FUNCTION_DEF(cryptobox_secretbox, decrypt);
LUA_FUNCTION_DEF(cryptobox_secretbox, gc);

static const struct luaL_reg cryptoboxlib_f[] = {
	LUA_INTERFACE_DEF(cryptobox, verify_memory),
	LUA_INTERFACE_DEF(cryptobox, verify_file),
	LUA_INTERFACE_DEF(cryptobox, sign_memory),
	LUA_INTERFACE_DEF(cryptobox, sign_file),
	LUA_INTERFACE_DEF(cryptobox, encrypt_memory),
	LUA_INTERFACE_DEF(cryptobox, encrypt_file),
	LUA_INTERFACE_DEF(cryptobox, decrypt_memory),
	LUA_INTERFACE_DEF(cryptobox, decrypt_file),
	LUA_INTERFACE_DEF(cryptobox, encrypt_cookie),
	LUA_INTERFACE_DEF(cryptobox, decrypt_cookie),
	LUA_INTERFACE_DEF(cryptobox, pbkdf),
	LUA_INTERFACE_DEF(cryptobox, gen_dkim_keypair),
	{NULL, NULL}};

static const struct luaL_reg cryptoboxpubkeylib_f[] = {
	LUA_INTERFACE_DEF(cryptobox_pubkey, load),
	LUA_INTERFACE_DEF(cryptobox_pubkey, create),
	{NULL, NULL}};

static const struct luaL_reg cryptoboxpubkeylib_m[] = {
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_cryptobox_pubkey_gc},
	{NULL, NULL}};

static const struct luaL_reg cryptoboxkeypairlib_f[] = {
	LUA_INTERFACE_DEF(cryptobox_keypair, load),
	LUA_INTERFACE_DEF(cryptobox_keypair, create),
	{NULL, NULL}};

static const struct luaL_reg cryptoboxkeypairlib_m[] = {
	{"__tostring", rspamd_lua_class_tostring},
	{"totable", lua_cryptobox_keypair_totable},
	{"get_type", lua_cryptobox_keypair_get_type},
	{"get_alg", lua_cryptobox_keypair_get_alg},
	{"type", lua_cryptobox_keypair_get_type},
	{"alg", lua_cryptobox_keypair_get_alg},
	{"pk", lua_cryptobox_keypair_get_pk},
	{"pubkey", lua_cryptobox_keypair_get_pk},
	{"__gc", lua_cryptobox_keypair_gc},
	{NULL, NULL}};

static const struct luaL_reg cryptoboxsignlib_f[] = {
	LUA_INTERFACE_DEF(cryptobox_signature, load),
	LUA_INTERFACE_DEF(cryptobox_signature, create),
	{NULL, NULL}};

static const struct luaL_reg cryptoboxsignlib_m[] = {
	LUA_INTERFACE_DEF(cryptobox_signature, save),
	LUA_INTERFACE_DEF(cryptobox_signature, hex),
	LUA_INTERFACE_DEF(cryptobox_signature, base32),
	LUA_INTERFACE_DEF(cryptobox_signature, base64),
	LUA_INTERFACE_DEF(cryptobox_signature, bin),
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_cryptobox_signature_gc},
	{NULL, NULL}};

static const struct luaL_reg cryptoboxhashlib_f[] = {
	LUA_INTERFACE_DEF(cryptobox_hash, create),
	LUA_INTERFACE_DEF(cryptobox_hash, create_keyed),
	LUA_INTERFACE_DEF(cryptobox_hash, create_specific),
	LUA_INTERFACE_DEF(cryptobox_hash, create_specific_keyed),
	{NULL, NULL}};

static const struct luaL_reg cryptoboxhashlib_m[] = {
	LUA_INTERFACE_DEF(cryptobox_hash, update),
	LUA_INTERFACE_DEF(cryptobox_hash, reset),
	LUA_INTERFACE_DEF(cryptobox_hash, hex),
	LUA_INTERFACE_DEF(cryptobox_hash, base32),
	LUA_INTERFACE_DEF(cryptobox_hash, base64),
	LUA_INTERFACE_DEF(cryptobox_hash, bin),
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_cryptobox_hash_gc},
	{NULL, NULL}};


static const struct luaL_reg cryptoboxsecretboxlib_f[] = {
	LUA_INTERFACE_DEF(cryptobox_secretbox, create),
	{NULL, NULL},
};

static const struct luaL_reg cryptoboxsecretboxlib_m[] = {
	LUA_INTERFACE_DEF(cryptobox_secretbox, encrypt),
	LUA_INTERFACE_DEF(cryptobox_secretbox, decrypt),
	{"__gc", lua_cryptobox_secretbox_gc},
	{NULL, NULL},
};

struct rspamd_lua_cryptobox_secretbox {
	unsigned char sk[crypto_secretbox_KEYBYTES];
};

static struct rspamd_cryptobox_pubkey *
lua_check_cryptobox_pubkey(lua_State *L, int pos)
{
	void *ud = rspamd_lua_check_udata(L, pos, rspamd_cryptobox_pubkey_classname);

	luaL_argcheck(L, ud != NULL, 1, "'cryptobox_pubkey' expected");
	return ud ? *((struct rspamd_cryptobox_pubkey **) ud) : NULL;
}

static struct rspamd_cryptobox_keypair *
lua_check_cryptobox_keypair(lua_State *L, int pos)
{
	void *ud = rspamd_lua_check_udata(L, pos, rspamd_cryptobox_keypair_classname);

	luaL_argcheck(L, ud != NULL, 1, "'cryptobox_keypair' expected");
	return ud ? *((struct rspamd_cryptobox_keypair **) ud) : NULL;
}

static rspamd_fstring_t *
lua_check_cryptobox_sign(lua_State *L, int pos)
{
	void *ud = rspamd_lua_check_udata(L, pos, rspamd_cryptobox_signature_classname);

	luaL_argcheck(L, ud != NULL, 1, "'cryptobox_signature' expected");
	return ud ? *((rspamd_fstring_t **) ud) : NULL;
}

struct rspamd_lua_cryptobox_hash *
lua_check_cryptobox_hash(lua_State *L, int pos)
{
	void *ud = rspamd_lua_check_udata(L, pos, rspamd_cryptobox_hash_classname);

	luaL_argcheck(L, ud != NULL, 1, "'cryptobox_hash' expected");
	return ud ? *((struct rspamd_lua_cryptobox_hash **) ud) : NULL;
}

static struct rspamd_lua_cryptobox_secretbox *
lua_check_cryptobox_secretbox(lua_State *L, int pos)
{
	void *ud = rspamd_lua_check_udata(L, pos, rspamd_cryptobox_secretbox_classname);

	luaL_argcheck(L, ud != NULL, 1, "'cryptobox_secretbox' expected");
	return ud ? *((struct rspamd_lua_cryptobox_secretbox **) ud) : NULL;
}

/***
 * @function rspamd_cryptobox_pubkey.load(file[, type[, alg]])
 * Loads public key from base32 encoded file
 * @param {string} file filename to load
 * @param {string} type optional 'sign' or 'kex' for signing and encryption
 * @return {cryptobox_pubkey} new public key
 */
static int
lua_cryptobox_pubkey_load(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_cryptobox_pubkey *pkey = NULL, **ppkey;
	const char *filename, *arg;
	int type = RSPAMD_KEYPAIR_SIGN;
	unsigned char *map;
	gsize len;

	filename = luaL_checkstring(L, 1);
	if (filename != NULL) {
		map = rspamd_file_xmap(filename, PROT_READ, &len, TRUE);

		if (map == NULL) {
			msg_err("cannot open pubkey from file: %s, %s",
					filename,
					strerror(errno));
			lua_pushnil(L);
		}
		else {
			if (lua_type(L, 2) == LUA_TSTRING) {
				/* keypair type */
				arg = lua_tostring(L, 2);

				if (strcmp(arg, "sign") == 0) {
					type = RSPAMD_KEYPAIR_SIGN;
				}
				else if (strcmp(arg, "kex") == 0) {
					type = RSPAMD_KEYPAIR_KEX;
				}
			}

			pkey = rspamd_pubkey_from_base32(map, len, type);

			if (pkey == NULL) {
				msg_err("cannot open pubkey from file: %s", filename);
				munmap(map, len);
				lua_pushnil(L);
			}
			else {
				munmap(map, len);
				ppkey = lua_newuserdata(L, sizeof(void *));
				rspamd_lua_setclass(L, rspamd_cryptobox_pubkey_classname, -1);
				*ppkey = pkey;
			}
		}
	}
	else {
		return luaL_error(L, "bad input arguments");
	}

	return 1;
}


/***
 * @function rspamd_cryptobox_pubkey.create(data[, type[, alg]])
 * Loads public key from base32 encoded string
 * @param {base32 string} base32 string with the key
 * @param {string} type optional 'sign' or 'kex' for signing and encryption
 * @return {cryptobox_pubkey} new public key
 */
static int
lua_cryptobox_pubkey_create(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_cryptobox_pubkey *pkey = NULL, **ppkey;
	const char *buf, *arg;
	gsize len;
	int type = RSPAMD_KEYPAIR_SIGN;

	buf = luaL_checklstring(L, 1, &len);
	if (buf != NULL) {
		if (lua_type(L, 2) == LUA_TSTRING) {
			/* keypair type */
			arg = lua_tostring(L, 2);

			if (strcmp(arg, "sign") == 0) {
				type = RSPAMD_KEYPAIR_SIGN;
			}
			else if (strcmp(arg, "kex") == 0) {
				type = RSPAMD_KEYPAIR_KEX;
			}
		}

		pkey = rspamd_pubkey_from_base32(buf, len, type);

		if (pkey == NULL) {
			msg_err("cannot load pubkey from string");
			lua_pushnil(L);
		}
		else {
			ppkey = lua_newuserdata(L, sizeof(void *));
			rspamd_lua_setclass(L, rspamd_cryptobox_pubkey_classname, -1);
			*ppkey = pkey;
		}
	}
	else {
		return luaL_error(L, "bad input arguments");
	}

	return 1;
}

static int
lua_cryptobox_pubkey_gc(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_cryptobox_pubkey *pkey = lua_check_cryptobox_pubkey(L, 1);

	if (pkey != NULL) {
		rspamd_pubkey_unref(pkey);
	}

	return 0;
}

/***
 * @function rspamd_cryptobox_keypair.load(file|table)
 * Loads public key from UCL file or directly from Lua
 * @param {string} file filename to load
 * @return {cryptobox_keypair} new keypair
 */
static int
lua_cryptobox_keypair_load(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_cryptobox_keypair *kp, **pkp;
	const char *buf;
	gsize len;
	struct ucl_parser *parser;
	ucl_object_t *obj;

	if (lua_type(L, 1) == LUA_TSTRING) {
		buf = luaL_checklstring(L, 1, &len);
		if (buf != NULL) {
			parser = ucl_parser_new(0);

			if (!ucl_parser_add_chunk(parser, buf, len)) {
				msg_err("cannot open keypair from data: %s",
						ucl_parser_get_error(parser));
				ucl_parser_free(parser);
				lua_pushnil(L);
			}
			else {
				obj = ucl_parser_get_object(parser);
				kp = rspamd_keypair_from_ucl(obj);
				ucl_parser_free(parser);

				if (kp == NULL) {
					msg_err("cannot load keypair from data");
					ucl_object_unref(obj);
					lua_pushnil(L);
				}
				else {
					pkp = lua_newuserdata(L, sizeof(gpointer));
					*pkp = kp;
					rspamd_lua_setclass(L, rspamd_cryptobox_keypair_classname, -1);
					ucl_object_unref(obj);
				}
			}
		}
		else {
			luaL_error(L, "bad input arguments");
		}
	}
	else {
		/* Directly import from lua */
		obj = ucl_object_lua_import(L, 1);
		kp = rspamd_keypair_from_ucl(obj);

		if (kp == NULL) {
			msg_err("cannot load keypair from data");
			ucl_object_unref(obj);
			lua_pushnil(L);
		}
		else {
			pkp = lua_newuserdata(L, sizeof(gpointer));
			*pkp = kp;
			rspamd_lua_setclass(L, rspamd_cryptobox_keypair_classname, -1);
			ucl_object_unref(obj);
		}
	}

	return 1;
}

/***
 * @function rspamd_cryptobox_keypair.create([type='encryption'[, alg='curve25519']])
 * Generates new keypair
 * @param {string} type type of keypair: 'encryption' (default) or 'sign'
 * @return {cryptobox_keypair} new keypair
 */
static int
lua_cryptobox_keypair_create(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_cryptobox_keypair *kp, **pkp;
	enum rspamd_cryptobox_keypair_type type = RSPAMD_KEYPAIR_KEX;

	if (lua_isstring(L, 1)) {
		const char *str = lua_tostring(L, 1);

		if (strcmp(str, "sign") == 0) {
			type = RSPAMD_KEYPAIR_SIGN;
		}
		else if (strcmp(str, "encryption") == 0) {
			type = RSPAMD_KEYPAIR_KEX;
		}
		else {
			return luaL_error(L, "invalid keypair type: %s", str);
		}
	}

	kp = rspamd_keypair_new(type);

	pkp = lua_newuserdata(L, sizeof(gpointer));
	*pkp = kp;
	rspamd_lua_setclass(L, rspamd_cryptobox_keypair_classname, -1);

	return 1;
}

static int
lua_cryptobox_keypair_gc(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_cryptobox_keypair *kp = lua_check_cryptobox_keypair(L, 1);

	if (kp != NULL) {
		rspamd_keypair_unref(kp);
	}

	return 0;
}

/***
 * @method keypair:totable([hex=false]])
 * Converts keypair to table (not very safe due to memory leftovers)
 */
static int
lua_cryptobox_keypair_totable(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_cryptobox_keypair *kp = lua_check_cryptobox_keypair(L, 1);
	ucl_object_t *obj;
	gboolean hex = FALSE;
	int ret = 1;

	if (kp != NULL) {

		if (lua_isboolean(L, 2)) {
			hex = lua_toboolean(L, 2);
		}

		obj = rspamd_keypair_to_ucl(kp, hex ? RSPAMD_KEYPAIR_DUMP_HEX : RSPAMD_KEYPAIR_DUMP_DEFAULT);

		ret = ucl_object_push_lua(L, obj, true);
		ucl_object_unref(obj);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return ret;
}
/***
 * @method keypair:type()
 * Returns type of keypair as a string: 'encryption' or 'sign'
 * @return {string} type of keypair as a string
 */
static int
lua_cryptobox_keypair_get_type(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_cryptobox_keypair *kp = lua_check_cryptobox_keypair(L, 1);

	if (kp) {
		if (kp->type == RSPAMD_KEYPAIR_KEX) {
			lua_pushstring(L, "encryption");
		}
		else {
			lua_pushstring(L, "sign");
		}
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

/***
 * @method keypair:alg()
 * Returns algorithm of keypair as a string: 'encryption' or 'sign'
 * @return {string} type of keypair as a string
 */
static int
lua_cryptobox_keypair_get_alg(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_cryptobox_keypair *kp = lua_check_cryptobox_keypair(L, 1);

	if (kp) {
		lua_pushstring(L, "curve25519");
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

/***
 * @method keypair:pk()
 * Returns pubkey for a specific keypair
 * @return {rspamd_pubkey} pubkey for a keypair
 */
static int
lua_cryptobox_keypair_get_pk(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_cryptobox_keypair *kp = lua_check_cryptobox_keypair(L, 1);
	struct rspamd_cryptobox_pubkey *pk, **ppk;
	const unsigned char *data;
	unsigned int dlen;

	if (kp) {
		data = rspamd_keypair_component(kp, RSPAMD_KEYPAIR_COMPONENT_PK, &dlen);
		pk = rspamd_pubkey_from_bin(data, dlen, kp->type);

		if (pk == NULL) {
			return luaL_error(L, "invalid keypair");
		}

		ppk = lua_newuserdata(L, sizeof(*ppk));
		*ppk = pk;
		rspamd_lua_setclass(L, rspamd_cryptobox_pubkey_classname, -1);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

/***
 * @function rspamd_cryptobox_signature.load(file)
 * Loads signature from raw file
 * @param {string} file filename to load
 * @return {cryptobox_signature} new signature
 */
static int
lua_cryptobox_signature_load(lua_State *L)
{
	LUA_TRACE_POINT;
	rspamd_fstring_t *sig, **psig;
	const char *filename;
	gpointer data;
	int fd;
	struct stat st;

	filename = luaL_checkstring(L, 1);
	if (filename != NULL) {
		fd = open(filename, O_RDONLY);
		if (fd == -1) {
			msg_err("cannot open signature file: %s, %s", filename,
					strerror(errno));
			lua_pushnil(L);
		}
		else {
			if (fstat(fd, &st) == -1 ||
				(data =
					 mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
				msg_err("cannot mmap file %s: %s", filename, strerror(errno));
				lua_pushnil(L);
			}
			else {
				if (st.st_size > 0) {
					sig = rspamd_fstring_new_init(data, st.st_size);
					psig = lua_newuserdata(L, sizeof(rspamd_fstring_t *));
					rspamd_lua_setclass(L, rspamd_cryptobox_signature_classname, -1);
					*psig = sig;
				}
				else {
					msg_err("size of %s mismatches: %d while %d is expected",
							filename, (int) st.st_size,
							crypto_sign_bytes());
					lua_pushnil(L);
				}

				munmap(data, st.st_size);
			}
			close(fd);
		}
	}
	else {
		luaL_error(L, "bad input arguments");
	}

	return 1;
}

/***
 * @method rspamd_cryptobox_signature:save(file)
 * Stores signature in raw file
 * @param {string} file filename to use
 * @return {boolean} true if signature has been saved
 */
static int
lua_cryptobox_signature_save(lua_State *L)
{
	LUA_TRACE_POINT;
	rspamd_fstring_t *sig;
	int fd, flags;
	const char *filename;
	gboolean forced = FALSE, res = TRUE;

	sig = lua_check_cryptobox_sign(L, 1);
	filename = luaL_checkstring(L, 2);

	if (!sig || !filename) {
		luaL_error(L, "bad input arguments");
		return 1;
	}

	if (lua_gettop(L) > 2) {
		forced = lua_toboolean(L, 3);
	}

	if (sig != NULL && filename != NULL) {
		flags = O_WRONLY | O_CREAT;
		if (forced) {
			flags |= O_TRUNC;
		}
		else {
			flags |= O_EXCL;
		}
		fd = open(filename, flags, 00644);
		if (fd == -1) {
			msg_err("cannot create a signature file: %s, %s",
					filename,
					strerror(errno));
			lua_pushboolean(L, FALSE);
		}
		else {
			while (write(fd, sig->str, sig->len) == -1) {
				if (errno == EINTR) {
					continue;
				}
				msg_err("cannot write to a signature file: %s, %s",
						filename,
						strerror(errno));
				res = FALSE;
				break;
			}
			lua_pushboolean(L, res);
			close(fd);
		}
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

/***
 * @function rspamd_cryptobox_signature.create(data)
 * Creates signature object from raw data
 * @param {data} raw signature data
 * @return {cryptobox_signature} signature object
 */
static int
lua_cryptobox_signature_create(lua_State *L)
{
	LUA_TRACE_POINT;
	rspamd_fstring_t *sig, **psig;
	struct rspamd_lua_text *t;
	const char *data;
	gsize dlen;

	if (lua_isuserdata(L, 1)) {
		t = lua_check_text(L, 1);

		if (!t) {
			return luaL_error(L, "invalid arguments");
		}

		data = t->start;
		dlen = t->len;
	}
	else {
		data = luaL_checklstring(L, 1, &dlen);
	}

	if (data != NULL) {
		if (dlen == crypto_sign_bytes()) {
			sig = rspamd_fstring_new_init(data, dlen);
			psig = lua_newuserdata(L, sizeof(rspamd_fstring_t *));
			rspamd_lua_setclass(L, rspamd_cryptobox_signature_classname, -1);
			*psig = sig;
		}
	}
	else {
		return luaL_error(L, "bad input arguments");
	}

	return 1;
}

/***
 * @method cryptobox_signature:hex()
 * Return hex encoded signature string
 * @return {string} raw value of signature
 */
static int
lua_cryptobox_signature_hex(lua_State *L)
{
	LUA_TRACE_POINT;
	rspamd_fstring_t *sig = lua_check_cryptobox_sign(L, 1);
	char *encoded;

	if (sig) {
		encoded = rspamd_encode_hex(sig->str, sig->len);
		lua_pushstring(L, encoded);
		g_free(encoded);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

/***
 * @method cryptobox_signature:base32([b32type='default'])
 * Return base32 encoded signature string
 * @param {string} b32type base32 type (default, bleach, rfc)
 * @return {string} raw value of signature
 */
static int
lua_cryptobox_signature_base32(lua_State *L)
{
	LUA_TRACE_POINT;
	rspamd_fstring_t *sig = lua_check_cryptobox_sign(L, 1);
	char *encoded;
	enum rspamd_base32_type btype = RSPAMD_BASE32_DEFAULT;

	if (lua_type(L, 2) == LUA_TSTRING) {
		btype = rspamd_base32_decode_type_from_str(lua_tostring(L, 2));

		if (btype == RSPAMD_BASE32_INVALID) {
			return luaL_error(L, "invalid b32 type: %s", lua_tostring(L, 2));
		}
	}

	if (sig) {
		encoded = rspamd_encode_base32(sig->str, sig->len, btype);
		lua_pushstring(L, encoded);
		g_free(encoded);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

/***
 * @method cryptobox_signature:base64()
 * Return base64 encoded signature string
 * @return {string} raw value of signature
 */
static int
lua_cryptobox_signature_base64(lua_State *L)
{
	LUA_TRACE_POINT;
	rspamd_fstring_t *sig = lua_check_cryptobox_sign(L, 1);
	gsize dlen;
	char *encoded;

	if (sig) {
		encoded = rspamd_encode_base64(sig->str, sig->len, 0, &dlen);
		lua_pushlstring(L, encoded, dlen);
		g_free(encoded);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

/***
 * @method cryptobox_signature:bin()
 * Return raw signature string
 * @return {string} raw value of signature
 */
static int
lua_cryptobox_signature_bin(lua_State *L)
{
	LUA_TRACE_POINT;
	rspamd_fstring_t *sig = lua_check_cryptobox_sign(L, 1);

	if (sig) {
		lua_pushlstring(L, sig->str, sig->len);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

static int
lua_cryptobox_signature_gc(lua_State *L)
{
	LUA_TRACE_POINT;
	rspamd_fstring_t *sig = lua_check_cryptobox_sign(L, 1);

	rspamd_fstring_free(sig);

	return 0;
}

static void
rspamd_lua_hash_update(struct rspamd_lua_cryptobox_hash *h,
					   const void *p, gsize len)
{
	if (h) {
		switch (h->type) {
		case LUA_CRYPTOBOX_HASH_BLAKE2:
			rspamd_cryptobox_hash_update(h->content.h, p, len);
			break;
		case LUA_CRYPTOBOX_HASH_SSL:
			EVP_DigestUpdate(h->content.c, p, len);
			break;
		case LUA_CRYPTOBOX_HASH_HMAC:
			EVP_MAC_update(h->content.hmac_c, p, len);
			break;
		case LUA_CRYPTOBOX_HASH_XXHASH64:
		case LUA_CRYPTOBOX_HASH_XXHASH32:
		case LUA_CRYPTOBOX_HASH_XXHASH3:
		case LUA_CRYPTOBOX_HASH_MUM:
		case LUA_CRYPTOBOX_HASH_T1HA:
			rspamd_cryptobox_fast_hash_update(h->content.fh, p, len);
			break;
		default:
			g_assert_not_reached();
		}
	}
}

static void
lua_cryptobox_hash_dtor(struct rspamd_lua_cryptobox_hash *h)
{
	if (h->type == LUA_CRYPTOBOX_HASH_SSL) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
		EVP_MD_CTX_cleanup(h->content.c);
#else
		EVP_MD_CTX_reset(h->content.c);
#endif
		EVP_MD_CTX_destroy(h->content.c);
	}
	else if (h->type == LUA_CRYPTOBOX_HASH_HMAC) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
	(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x30500000)
		HMAC_CTX_cleanup(h->content.hmac_c);
		g_free(h->content.hmac_c);
#else
		EVP_MAC_CTX_free(h->content.hmac_c);
#endif
	}
	else if (h->type == LUA_CRYPTOBOX_HASH_BLAKE2) {
		rspamd_explicit_memzero(h->content.h, sizeof(*h->content.h));
		free(h->content.h); /* Allocated by posix_memalign */
	}
	else {
		rspamd_cryptobox_fast_hash_free(h->content.fh);
	}

	g_free(h);
}

static inline void
rspamd_lua_hash_init_default(struct rspamd_lua_cryptobox_hash *h,
							 const char *key, gsize keylen)
{
	h->type = LUA_CRYPTOBOX_HASH_BLAKE2;
	if (posix_memalign((void **) &h->content.h,
					   RSPAMD_ALIGNOF(rspamd_cryptobox_hash_state_t),
					   sizeof(*h->content.h)) != 0) {
		g_assert_not_reached();
	}

	rspamd_cryptobox_hash_init(h->content.h, key, keylen);
	h->out_len = rspamd_cryptobox_HASHBYTES;
}

static void
rspamd_lua_ssl_hash_create(struct rspamd_lua_cryptobox_hash *h, const EVP_MD *htype,
						   bool insecure)
{
	h->type = LUA_CRYPTOBOX_HASH_SSL;
	h->content.c = EVP_MD_CTX_create();
	h->out_len = EVP_MD_size(htype);

	if (insecure) {
		/* Should never ever be used for crypto/security purposes! */
#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
		EVP_MD_CTX_set_flags(h->content.c, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
#endif
	}

	EVP_DigestInit_ex(h->content.c, htype, NULL);
}

static void
rspamd_lua_ssl_hmac_create(struct rspamd_lua_cryptobox_hash *h, const EVP_MD *htype,
						   const char *key, gsize keylen,
						   bool insecure)
{
	h->type = LUA_CRYPTOBOX_HASH_HMAC;

#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
	(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x30500000)
	h->content.hmac_c = g_malloc0(sizeof(*h->content.hmac_c));
#else
	EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	h->content.hmac_c = EVP_MAC_CTX_new(mac);
#endif
	h->out_len = EVP_MD_size(htype);

#if OPENSSL_VERSION_NUMBER > 0x10100000L
	if (insecure) {
		/* Should never ever be used for crypto/security purposes! */
#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
		//HMAC_CTX_set_flags(h->content.hmac_c, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
		//EVP_MD_CTX_set_flags(h->content.c, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
#endif
	}
#endif
	OSSL_PARAM params[2];
	params[0] = OSSL_PARAM_construct_utf8_string("digest", EVP_MD_get0_name(htype), 0);
	params[1] = OSSL_PARAM_construct_end();

	EVP_MAC_init(h->content.hmac_c, key, keylen, params);
}

static struct rspamd_lua_cryptobox_hash *
rspamd_lua_hash_create(const char *type, const char *key, gsize keylen)
{
	struct rspamd_lua_cryptobox_hash *h;

	h = g_malloc0(sizeof(*h));
	REF_INIT_RETAIN(h, lua_cryptobox_hash_dtor);

	if (type) {
		if (g_ascii_strcasecmp(type, "md5") == 0) {
			if (keylen > 0) {
				rspamd_lua_ssl_hmac_create(h, EVP_md5(), key, keylen, true);
			}
			else {
				rspamd_lua_ssl_hash_create(h, EVP_md5(), true);
			}
		}
		else if (g_ascii_strcasecmp(type, "sha1") == 0 ||
				 g_ascii_strcasecmp(type, "sha") == 0) {
			if (keylen > 0) {
				rspamd_lua_ssl_hmac_create(h, EVP_sha1(), key, keylen, true);
			}
			else {
				rspamd_lua_ssl_hash_create(h, EVP_sha1(), true);
			}
		}
		else if (g_ascii_strcasecmp(type, "sha256") == 0) {
			if (keylen > 0) {
				rspamd_lua_ssl_hmac_create(h, EVP_sha256(), key, keylen, true);
			}
			else {
				rspamd_lua_ssl_hash_create(h, EVP_sha256(), true);
			}
		}
		else if (g_ascii_strcasecmp(type, "sha512") == 0) {
			if (keylen > 0) {
				rspamd_lua_ssl_hmac_create(h, EVP_sha512(), key, keylen, true);
			}
			else {
				rspamd_lua_ssl_hash_create(h, EVP_sha512(), true);
			}
		}
		else if (g_ascii_strcasecmp(type, "sha384") == 0) {
			if (keylen > 0) {
				rspamd_lua_ssl_hmac_create(h, EVP_sha384(), key, keylen, true);
			}
			else {
				rspamd_lua_ssl_hash_create(h, EVP_sha384(), true);
			}
		}
		else if (g_ascii_strcasecmp(type, "xxh64") == 0) {
			h->type = LUA_CRYPTOBOX_HASH_XXHASH64;
			h->content.fh = rspamd_cryptobox_fast_hash_new();
			rspamd_cryptobox_fast_hash_init_specific(h->content.fh,
													 RSPAMD_CRYPTOBOX_XXHASH64, 0);
			h->out_len = sizeof(uint64_t);
		}
		else if (g_ascii_strcasecmp(type, "xxh32") == 0) {
			h->type = LUA_CRYPTOBOX_HASH_XXHASH32;
			h->content.fh = rspamd_cryptobox_fast_hash_new();
			rspamd_cryptobox_fast_hash_init_specific(h->content.fh,
													 RSPAMD_CRYPTOBOX_XXHASH32, 0);
			h->out_len = sizeof(uint32_t);
		}
		else if (g_ascii_strcasecmp(type, "xxh3") == 0) {
			h->type = LUA_CRYPTOBOX_HASH_XXHASH3;
			h->content.fh = rspamd_cryptobox_fast_hash_new();
			rspamd_cryptobox_fast_hash_init_specific(h->content.fh,
													 RSPAMD_CRYPTOBOX_XXHASH3, 0);
			h->out_len = sizeof(uint64_t);
		}
		else if (g_ascii_strcasecmp(type, "mum") == 0) {
			h->type = LUA_CRYPTOBOX_HASH_MUM;
			h->content.fh = rspamd_cryptobox_fast_hash_new();
			rspamd_cryptobox_fast_hash_init_specific(h->content.fh,
													 RSPAMD_CRYPTOBOX_MUMHASH, 0);
			h->out_len = sizeof(uint64_t);
		}
		else if (g_ascii_strcasecmp(type, "t1ha") == 0) {
			h->type = LUA_CRYPTOBOX_HASH_T1HA;
			h->content.fh = rspamd_cryptobox_fast_hash_new();
			rspamd_cryptobox_fast_hash_init_specific(h->content.fh,
													 RSPAMD_CRYPTOBOX_T1HA, 0);
			h->out_len = sizeof(uint64_t);
		}
		else if (g_ascii_strcasecmp(type, "blake2") == 0) {
			rspamd_lua_hash_init_default(h, key, keylen);
		}
		else {
			g_free(h);

			return NULL;
		}
	}
	else {
		/* Default hash type */
		rspamd_lua_hash_init_default(h, key, keylen);
	}

	return h;
}

/***
 * @function rspamd_cryptobox_hash.create([string])
 * Creates new hash context
 * @param {string} data optional string to hash
 * @return {cryptobox_hash} hash object
 */
static int
lua_cryptobox_hash_create(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_cryptobox_hash *h, **ph;
	const char *s = NULL;
	struct rspamd_lua_text *t;
	gsize len = 0;

	h = rspamd_lua_hash_create(NULL, NULL, 0);

	if (lua_type(L, 1) == LUA_TSTRING) {
		s = lua_tolstring(L, 1, &len);
	}
	else if (lua_type(L, 1) == LUA_TUSERDATA) {
		t = lua_check_text(L, 1);

		if (!t) {
			REF_RELEASE(h);
			return luaL_error(L, "invalid arguments");
		}

		s = t->start;
		len = t->len;
	}

	if (s) {
		rspamd_lua_hash_update(h, s, len);
	}

	ph = lua_newuserdata(L, sizeof(void *));
	*ph = h;
	rspamd_lua_setclass(L, rspamd_cryptobox_hash_classname, -1);

	return 1;
}

/***
 * @function rspamd_cryptobox_hash.create_specific(type, [string])
 * Creates new hash context
 * @param {string} type type of hash (blake2, sha256, md5, sha512, mum, xxh64, xxh32, t1ha)
 * @param {string} string initial data
 * @return {cryptobox_hash} hash object
 */
static int
lua_cryptobox_hash_create_specific(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_cryptobox_hash *h, **ph;
	const char *s = NULL, *type = luaL_checkstring(L, 1);
	gsize len = 0;
	struct rspamd_lua_text *t;

	if (!type) {
		return luaL_error(L, "invalid arguments");
	}

	h = rspamd_lua_hash_create(type, NULL, 0);

	if (h == NULL) {
		return luaL_error(L, "invalid hash type: %s", type);
	}

	if (lua_type(L, 2) == LUA_TSTRING) {
		s = lua_tolstring(L, 2, &len);
	}
	else if (lua_type(L, 2) == LUA_TUSERDATA) {
		t = lua_check_text(L, 2);

		if (!t) {
			REF_RELEASE(h);
			return luaL_error(L, "invalid arguments");
		}

		s = t->start;
		len = t->len;
	}

	if (s) {
		rspamd_lua_hash_update(h, s, len);
	}

	ph = lua_newuserdata(L, sizeof(void *));
	*ph = h;
	rspamd_lua_setclass(L, rspamd_cryptobox_hash_classname, -1);

	return 1;
}

/***
 * @function rspamd_cryptobox_hash.create_keyed(key, [string])
 * Creates new hash context with specified key
 * @param {string} key key
 * @return {cryptobox_hash} hash object
 */
static int
lua_cryptobox_hash_create_keyed(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_cryptobox_hash *h, **ph;
	const char *key, *s = NULL;
	struct rspamd_lua_text *t;
	gsize len = 0;
	gsize keylen;

	key = luaL_checklstring(L, 1, &keylen);

	if (key != NULL) {
		h = rspamd_lua_hash_create(NULL, key, keylen);

		if (lua_type(L, 2) == LUA_TSTRING) {
			s = lua_tolstring(L, 2, &len);
		}
		else if (lua_type(L, 2) == LUA_TUSERDATA) {
			t = lua_check_text(L, 2);

			if (!t) {
				REF_RELEASE(h);
				return luaL_error(L, "invalid arguments");
			}

			s = t->start;
			len = t->len;
		}

		if (s) {
			rspamd_lua_hash_update(h, s, len);
		}

		ph = lua_newuserdata(L, sizeof(void *));
		*ph = h;
		rspamd_lua_setclass(L, rspamd_cryptobox_hash_classname, -1);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

/***
 * @function rspamd_cryptobox_hash.create_specific_keyed(key, type, [string])
 * Creates new hash context with specified key
 * @param {string} key key
 * @return {cryptobox_hash} hash object
 */
static int
lua_cryptobox_hash_create_specific_keyed(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_cryptobox_hash *h, **ph;
	const char *key, *s = NULL, *type = luaL_checkstring(L, 2);
	struct rspamd_lua_text *t;
	gsize len = 0;
	gsize keylen;

	key = luaL_checklstring(L, 1, &keylen);

	if (key != NULL && type != NULL) {
		h = rspamd_lua_hash_create(type, key, keylen);

		if (h == NULL) {
			return luaL_error(L, "invalid hash type: %s", type);
		}

		if (lua_type(L, 3) == LUA_TSTRING) {
			s = lua_tolstring(L, 3, &len);
		}
		else if (lua_type(L, 3) == LUA_TUSERDATA) {
			t = lua_check_text(L, 3);

			if (!t) {
				REF_RELEASE(h);

				return luaL_error(L, "invalid arguments");
			}

			s = t->start;
			len = t->len;
		}

		if (s) {
			rspamd_lua_hash_update(h, s, len);
		}

		ph = lua_newuserdata(L, sizeof(void *));
		*ph = h;
		rspamd_lua_setclass(L, rspamd_cryptobox_hash_classname, -1);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

/***
 * @method cryptobox_hash:update(data)
 * Updates hash with the specified data (hash should not be finalized using `hex` or `bin` methods)
 * @param {string} data data to hash
 */
static int
lua_cryptobox_hash_update(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_cryptobox_hash *h = lua_check_cryptobox_hash(L, 1), **ph;
	const char *data;
	struct rspamd_lua_text *t;
	gsize len;

	if (lua_isuserdata(L, 2)) {
		t = lua_check_text(L, 2);

		if (!t) {
			return luaL_error(L, "invalid arguments");
		}

		data = t->start;
		len = t->len;
	}
	else {
		data = luaL_checklstring(L, 2, &len);
	}

	if (lua_isnumber(L, 3)) {
		gsize nlen = lua_tonumber(L, 3);

		if (nlen > len) {
			return luaL_error(L, "invalid length: %d while %d is available",
							  (int) nlen, (int) len);
		}

		len = nlen;
	}

	if (h && data) {
		if (!h->is_finished) {
			rspamd_lua_hash_update(h, data, len);
		}
		else {
			return luaL_error(L, "hash is already finalized");
		}
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	ph = lua_newuserdata(L, sizeof(void *));
	*ph = h;
	REF_RETAIN(h);
	rspamd_lua_setclass(L, rspamd_cryptobox_hash_classname, -1);

	return 1;
}

/***
 * @method cryptobox_hash:reset()
 * Resets hash to the initial state
 */
static int
lua_cryptobox_hash_reset(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_cryptobox_hash *h = lua_check_cryptobox_hash(L, 1), **ph;

	if (h) {
		switch (h->type) {
		case LUA_CRYPTOBOX_HASH_BLAKE2:
			memset(h->content.h, 0, sizeof(*h->content.h));
			rspamd_cryptobox_hash_init(h->content.h, NULL, 0);
			break;
		case LUA_CRYPTOBOX_HASH_SSL:
			EVP_DigestInit(h->content.c, EVP_MD_CTX_get0_md(h->content.c));
			break;
		case LUA_CRYPTOBOX_HASH_HMAC:
#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
	(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x30500000)
			/* Old openssl is awesome... */
			HMAC_Init_ex(h->content.hmac_c, NULL, 0, h->content.hmac_c->md, NULL);
#else
			EVP_MAC_CTX_free(h->content.hmac_c);
			EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
			h->content.hmac_c = EVP_MAC_CTX_new(mac);
#endif
			break;
		case LUA_CRYPTOBOX_HASH_XXHASH64:
			rspamd_cryptobox_fast_hash_init_specific(h->content.fh,
													 RSPAMD_CRYPTOBOX_XXHASH64, 0);
			break;
		case LUA_CRYPTOBOX_HASH_XXHASH32:
			rspamd_cryptobox_fast_hash_init_specific(h->content.fh,
													 RSPAMD_CRYPTOBOX_XXHASH32, 0);
			break;
		case LUA_CRYPTOBOX_HASH_XXHASH3:
			rspamd_cryptobox_fast_hash_init_specific(h->content.fh,
													 RSPAMD_CRYPTOBOX_XXHASH3, 0);
			break;
		case LUA_CRYPTOBOX_HASH_MUM:
			rspamd_cryptobox_fast_hash_init_specific(h->content.fh,
													 RSPAMD_CRYPTOBOX_MUMHASH, 0);
			break;
		case LUA_CRYPTOBOX_HASH_T1HA:
			rspamd_cryptobox_fast_hash_init_specific(h->content.fh,
													 RSPAMD_CRYPTOBOX_T1HA, 0);
			break;
		default:
			g_assert_not_reached();
		}
		h->is_finished = FALSE;
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	ph = lua_newuserdata(L, sizeof(void *));
	*ph = h;
	REF_RETAIN(h);
	rspamd_lua_setclass(L, rspamd_cryptobox_hash_classname, -1);

	return 1;
}

static void
lua_cryptobox_hash_finish(struct rspamd_lua_cryptobox_hash *h)
{
	uint64_t ll;
	unsigned char out[rspamd_cryptobox_HASHBYTES];
	unsigned int ssl_outlen = sizeof(out);

	switch (h->type) {
	case LUA_CRYPTOBOX_HASH_BLAKE2:
		rspamd_cryptobox_hash_final(h->content.h, out);
		memcpy(h->out, out, sizeof(out));
		break;
	case LUA_CRYPTOBOX_HASH_SSL:
		EVP_DigestFinal_ex(h->content.c, out, &ssl_outlen);
		h->out_len = ssl_outlen;
		g_assert(ssl_outlen <= sizeof(h->out));
		memcpy(h->out, out, ssl_outlen);
		break;
	case LUA_CRYPTOBOX_HASH_HMAC:
		size_t ssl_outlen_size_t = ssl_outlen;
		EVP_MAC_final(h->content.hmac_c, out, &ssl_outlen_size_t, sizeof(out));
		ssl_outlen = ssl_outlen_size_t;
		h->out_len = ssl_outlen;
		g_assert(ssl_outlen <= sizeof(h->out));
		memcpy(h->out, out, ssl_outlen);
		break;
	case LUA_CRYPTOBOX_HASH_XXHASH64:
	case LUA_CRYPTOBOX_HASH_XXHASH32:
	case LUA_CRYPTOBOX_HASH_XXHASH3:
	case LUA_CRYPTOBOX_HASH_MUM:
	case LUA_CRYPTOBOX_HASH_T1HA:
		ll = rspamd_cryptobox_fast_hash_final(h->content.fh);
		memcpy(h->out, &ll, sizeof(ll));
		break;
	default:
		g_assert_not_reached();
	}

	h->is_finished = TRUE;
}

/***
 * @method cryptobox_hash:hex()
 * Finalizes hash and return it as hex string
 * @return {string} hex value of hash
 */
static int
lua_cryptobox_hash_hex(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_cryptobox_hash *h = lua_check_cryptobox_hash(L, 1);
	unsigned char out_hex[rspamd_cryptobox_HASHBYTES * 2 + 1], *r;
	unsigned int dlen;

	if (h) {
		if (!h->is_finished) {
			lua_cryptobox_hash_finish(h);
		}

		memset(out_hex, 0, sizeof(out_hex));
		r = h->out;
		dlen = h->out_len;

		if (lua_isnumber(L, 2)) {
			unsigned int lim = lua_tonumber(L, 2);

			if (lim < dlen) {
				r += dlen - lim;
				dlen = lim;
			}
		}

		rspamd_encode_hex_buf(r, dlen, out_hex, sizeof(out_hex));
		lua_pushstring(L, out_hex);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

/***
 * @method cryptobox_hash:base32([b32type])
 * Finalizes hash and return it as zbase32 (by default) string
 * @param {string} b32type base32 type (default, bleach, rfc)
 * @return {string} base32 value of hash
 */
static int
lua_cryptobox_hash_base32(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_cryptobox_hash *h = lua_check_cryptobox_hash(L, 1);
	unsigned char out_b32[rspamd_cryptobox_HASHBYTES * 2], *r;
	unsigned int dlen;

	if (h) {
		enum rspamd_base32_type btype = RSPAMD_BASE32_DEFAULT;

		if (lua_type(L, 2) == LUA_TSTRING) {
			btype = rspamd_base32_decode_type_from_str(lua_tostring(L, 2));

			if (btype == RSPAMD_BASE32_INVALID) {
				return luaL_error(L, "invalid b32 type: %s", lua_tostring(L, 2));
			}
		}

		if (!h->is_finished) {
			lua_cryptobox_hash_finish(h);
		}

		memset(out_b32, 0, sizeof(out_b32));
		r = h->out;
		dlen = h->out_len;

		if (lua_isnumber(L, 2)) {
			unsigned int lim = lua_tonumber(L, 2);

			if (lim < dlen) {
				r += dlen - lim;
				dlen = lim;
			}
		}

		rspamd_encode_base32_buf(r, dlen, out_b32, sizeof(out_b32), btype);
		lua_pushstring(L, out_b32);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

/***
 * @method cryptobox_hash:base64()
 * Finalizes hash and return it as base64 string
 * @return {string} base64 value of hash
 */
static int
lua_cryptobox_hash_base64(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_cryptobox_hash *h = lua_check_cryptobox_hash(L, 1);
	unsigned char *b64, *r;
	gsize len;
	unsigned int dlen;

	if (h) {
		if (!h->is_finished) {
			lua_cryptobox_hash_finish(h);
		}

		r = h->out;
		dlen = h->out_len;

		if (lua_isnumber(L, 2)) {
			unsigned int lim = lua_tonumber(L, 2);

			if (lim < dlen) {
				r += dlen - lim;
				dlen = lim;
			}
		}

		b64 = rspamd_encode_base64(r, dlen, 0, &len);
		lua_pushlstring(L, b64, len);
		g_free(b64);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

/***
 * @method cryptobox_hash:bin()
 * Finalizes hash and return it as raw string
 * @return {string} raw value of hash
 */
static int
lua_cryptobox_hash_bin(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_cryptobox_hash *h = lua_check_cryptobox_hash(L, 1);
	unsigned char *r;
	unsigned int dlen;

	if (h) {
		if (!h->is_finished) {
			lua_cryptobox_hash_finish(h);
		}

		r = h->out;
		dlen = h->out_len;

		if (lua_isnumber(L, 2)) {
			unsigned int lim = lua_tonumber(L, 2);

			if (lim < dlen) {
				r += dlen - lim;
				dlen = lim;
			}
		}

		lua_pushlstring(L, r, dlen);
		h->is_finished = TRUE;
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

static int
lua_cryptobox_hash_gc(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_cryptobox_hash *h = lua_check_cryptobox_hash(L, 1);

	REF_RELEASE(h);

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
static int
lua_cryptobox_verify_memory(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_cryptobox_pubkey *pk;
	rspamd_fstring_t *signature;
	struct rspamd_lua_text *t;
	const char *data;
	gsize len;
	int ret;

	pk = lua_check_cryptobox_pubkey(L, 1);
	signature = lua_check_cryptobox_sign(L, 2);

	if (lua_isuserdata(L, 3)) {
		t = lua_check_text(L, 3);

		if (!t) {
			return luaL_error(L, "invalid arguments");
		}

		data = t->start;
		len = t->len;
	}
	else {
		data = luaL_checklstring(L, 3, &len);
	}

	if (pk != NULL && signature != NULL && data != NULL) {
		ret = rspamd_cryptobox_verify(signature->str, signature->len, data, len,
									  rspamd_pubkey_get_pk(pk, NULL));

		if (ret) {
			lua_pushboolean(L, 1);
		}
		else {
			lua_pushboolean(L, 0);
		}
	}
	else {
		return luaL_error(L, "invalid arguments");
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
static int
lua_cryptobox_verify_file(lua_State *L)
{
	LUA_TRACE_POINT;
	const char *fname;
	struct rspamd_cryptobox_pubkey *pk;
	rspamd_fstring_t *signature;
	unsigned char *map = NULL;
	gsize len;
	int ret;

	pk = lua_check_cryptobox_pubkey(L, 1);
	signature = lua_check_cryptobox_sign(L, 2);
	fname = luaL_checkstring(L, 3);

	map = rspamd_file_xmap(fname, PROT_READ, &len, TRUE);

	if (map != NULL && pk != NULL && signature != NULL) {
		ret = rspamd_cryptobox_verify(signature->str, signature->len,
									  map, len,
									  rspamd_pubkey_get_pk(pk, NULL));

		if (ret) {
			lua_pushboolean(L, 1);
		}
		else {
			lua_pushboolean(L, 0);
		}
	}
	else {
		if (map != NULL) {
			munmap(map, len);
		}

		return luaL_error(L, "invalid arguments");
	}

	if (map != NULL) {
		munmap(map, len);
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
static int
lua_cryptobox_sign_memory(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_cryptobox_keypair *kp;
	const char *data;
	struct rspamd_lua_text *t;
	gsize len = 0;
	rspamd_fstring_t *sig, **psig;

	kp = lua_check_cryptobox_keypair(L, 1);

	if (lua_isuserdata(L, 2)) {
		t = lua_check_text(L, 2);

		if (!t) {
			return luaL_error(L, "invalid arguments");
		}

		data = t->start;
		len = t->len;
	}
	else {
		data = luaL_checklstring(L, 2, &len);
	}


	if (!kp || !data || kp->type == RSPAMD_KEYPAIR_KEX) {
		return luaL_error(L, "invalid arguments");
	}

	sig = rspamd_fstring_sized_new(crypto_sign_bytes());

	unsigned long long siglen = sig->len;
	rspamd_cryptobox_sign(sig->str, &siglen, data,
						  len, rspamd_keypair_component(kp, RSPAMD_KEYPAIR_COMPONENT_SK, NULL));

	sig->len = siglen;
	psig = lua_newuserdata(L, sizeof(void *));
	*psig = sig;
	rspamd_lua_setclass(L, rspamd_cryptobox_signature_classname, -1);

	return 1;
}

/***
 * @function rspamd_cryptobox.sign_file(kp, file)
 * Sign file using specified keypair
 * @param {keypair} kp keypair to sign
 * @param {string} filename
 * @return {cryptobox_signature} signature object
 */
static int
lua_cryptobox_sign_file(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_cryptobox_keypair *kp;
	const char *filename;
	char *data;
	gsize len = 0;
	rspamd_fstring_t *sig, **psig;

	kp = lua_check_cryptobox_keypair(L, 1);
	filename = luaL_checkstring(L, 2);

	if (!kp || !filename) {
		return luaL_error(L, "invalid arguments");
	}

	data = rspamd_file_xmap(filename, PROT_READ, &len, TRUE);

	if (data == NULL) {
		msg_err("cannot mmap file %s: %s", filename, strerror(errno));
		lua_pushnil(L);
	}
	else {
		sig = rspamd_fstring_sized_new(crypto_sign_bytes());

		unsigned long long siglen = sig->len;

		rspamd_cryptobox_sign(sig->str, &siglen, data,
							  len, rspamd_keypair_component(kp, RSPAMD_KEYPAIR_COMPONENT_SK, NULL));

		sig->len = siglen;
		psig = lua_newuserdata(L, sizeof(void *));
		*psig = sig;
		rspamd_lua_setclass(L, rspamd_cryptobox_signature_classname, -1);
		munmap(data, len);
	}

	return 1;
}

/***
 * @function rspamd_cryptobox.encrypt_memory(kp, data)
 * Encrypt data using specified keypair/pubkey
 * @param {keypair|string} kp keypair or pubkey in base32 to use
 * @param {string|text} data
 * @return {rspamd_text} encrypted text
 */
static int
lua_cryptobox_encrypt_memory(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_cryptobox_keypair *kp = NULL;
	struct rspamd_cryptobox_pubkey *pk = NULL;
	const char *data;
	unsigned char *out = NULL;
	struct rspamd_lua_text *t, *res;
	gsize len = 0, outlen = 0;
	GError *err = NULL;
	bool owned_pk = false;

	if (lua_type(L, 1) == LUA_TUSERDATA) {
		if (rspamd_lua_check_udata_maybe(L, 1, rspamd_cryptobox_keypair_classname)) {
			kp = lua_check_cryptobox_keypair(L, 1);
		}
		else if (rspamd_lua_check_udata_maybe(L, 1, rspamd_cryptobox_pubkey_classname)) {
			pk = lua_check_cryptobox_pubkey(L, 1);
		}
	}
	else if (lua_type(L, 1) == LUA_TSTRING) {
		const char *b32;
		gsize blen;

		b32 = lua_tolstring(L, 1, &blen);
		pk = rspamd_pubkey_from_base32(b32, blen, RSPAMD_KEYPAIR_KEX);
		owned_pk = true;
	}

	if (lua_isuserdata(L, 2)) {
		t = lua_check_text(L, 2);

		if (!t) {
			goto err;
		}

		data = t->start;
		len = t->len;
	}
	else {
		data = luaL_checklstring(L, 2, &len);
	}


	if (!(kp || pk) || !data) {
		goto err;
	}

	if (kp) {
		if (!rspamd_keypair_encrypt(kp, data, len, &out, &outlen, &err)) {
			int ret = luaL_error(L, "cannot encrypt data: %s", err->message);
			g_error_free(err);

			if (owned_pk) {
				rspamd_pubkey_unref(pk);
			}

			return ret;
		}
	}
	else {
		if (!rspamd_pubkey_encrypt(pk, data, len, &out, &outlen, &err)) {
			int ret = luaL_error(L, "cannot encrypt data: %s", err->message);
			g_error_free(err);

			if (owned_pk) {
				rspamd_pubkey_unref(pk);
			}

			return ret;
		}
	}

	res = lua_newuserdata(L, sizeof(*res));
	res->flags = RSPAMD_TEXT_FLAG_OWN;
	res->start = out;
	res->len = outlen;
	rspamd_lua_setclass(L, rspamd_text_classname, -1);

	if (owned_pk) {
		rspamd_pubkey_unref(pk);
	}

	return 1;
err:

	if (owned_pk) {
		rspamd_pubkey_unref(pk);
	}

	return luaL_error(L, "invalid arguments");
}

/***
 * @function rspamd_cryptobox.encrypt_file(kp|pk_string, filename)
 * Encrypt data using specified keypair/pubkey
 * @param {keypair|string} kp keypair or pubkey in base32 to use
 * @param {string} filename
 * @return {rspamd_text} encrypted text
 */
static int
lua_cryptobox_encrypt_file(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_cryptobox_keypair *kp = NULL;
	struct rspamd_cryptobox_pubkey *pk = NULL;
	const char *filename;
	char *data = NULL;
	unsigned char *out = NULL;
	struct rspamd_lua_text *res;
	gsize len = 0, outlen = 0;
	GError *err = NULL;
	bool own_pk = false;

	if (lua_type(L, 1) == LUA_TUSERDATA) {
		if (rspamd_lua_check_udata_maybe(L, 1, rspamd_cryptobox_keypair_classname)) {
			kp = lua_check_cryptobox_keypair(L, 1);
		}
		else if (rspamd_lua_check_udata_maybe(L, 1, rspamd_cryptobox_pubkey_classname)) {
			pk = lua_check_cryptobox_pubkey(L, 1);
		}
	}
	else if (lua_type(L, 1) == LUA_TSTRING) {
		const char *b32;
		gsize blen;

		b32 = lua_tolstring(L, 1, &blen);
		pk = rspamd_pubkey_from_base32(b32, blen, RSPAMD_KEYPAIR_KEX);
		own_pk = true;
	}

	filename = luaL_checkstring(L, 2);
	data = rspamd_file_xmap(filename, PROT_READ, &len, TRUE);

	if (!(kp || pk) || !data) {
		goto err;
	}

	if (kp) {
		if (!rspamd_keypair_encrypt(kp, data, len, &out, &outlen, &err)) {
			int ret = luaL_error(L, "cannot encrypt file %s: %s", filename,
								 err->message);
			g_error_free(err);
			munmap(data, len);
			if (own_pk) {
				rspamd_pubkey_unref(pk);
			}

			return ret;
		}
	}
	else if (pk) {
		if (!rspamd_pubkey_encrypt(pk, data, len, &out, &outlen, &err)) {
			int ret = luaL_error(L, "cannot encrypt file %s: %s", filename,
								 err->message);
			g_error_free(err);
			munmap(data, len);

			if (own_pk) {
				rspamd_pubkey_unref(pk);
			}

			return ret;
		}
	}

	res = lua_newuserdata(L, sizeof(*res));
	res->flags = RSPAMD_TEXT_FLAG_OWN;
	res->start = out;
	res->len = outlen;
	rspamd_lua_setclass(L, rspamd_text_classname, -1);
	munmap(data, len);
	if (own_pk) {
		rspamd_pubkey_unref(pk);
	}

	return 1;

err:
	if (data) {
		munmap(data, len);
	}
	if (own_pk) {
		rspamd_pubkey_unref(pk);
	}
	return luaL_error(L, "invalid arguments");
}

/***
 * @function rspamd_cryptobox.decrypt_memory(kp, data[, nist = false])
 * Encrypt data using specified keypair
 * @param {keypair} kp keypair to use
 * @param {string} data
 * @return status,{rspamd_text}|error status is boolean variable followed by either unencrypted data or an error message
 */
static int
lua_cryptobox_decrypt_memory(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_cryptobox_keypair *kp;
	const char *data;
	unsigned char *out;
	struct rspamd_lua_text *t, *res;
	gsize len = 0, outlen;
	GError *err = NULL;

	kp = lua_check_cryptobox_keypair(L, 1);

	if (lua_isuserdata(L, 2)) {
		t = lua_check_text(L, 2);

		if (!t) {
			return luaL_error(L, "invalid arguments");
		}

		data = t->start;
		len = t->len;
	}
	else {
		data = luaL_checklstring(L, 2, &len);
	}


	if (!kp || !data) {
		return luaL_error(L, "invalid arguments");
	}

	if (!rspamd_keypair_decrypt(kp, data, len, &out, &outlen, &err)) {
		lua_pushboolean(L, false);
		lua_pushstring(L, err->message);
		g_error_free(err);
	}
	else {
		lua_pushboolean(L, true);
		res = lua_newuserdata(L, sizeof(*res));
		res->flags = RSPAMD_TEXT_FLAG_OWN;
		res->start = out;
		res->len = outlen;
		rspamd_lua_setclass(L, rspamd_text_classname, -1);
	}

	return 2;
}

/***
 * @function rspamd_cryptobox.decrypt_file(kp, filename)
 * Encrypt data using specified keypair
 * @param {keypair} kp keypair to use
 * @param {string} filename
 * @return status,{rspamd_text}|error status is boolean variable followed by either unencrypted data or an error message
 */
static int
lua_cryptobox_decrypt_file(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_cryptobox_keypair *kp;
	const char *filename;
	char *data;
	unsigned char *out;
	struct rspamd_lua_text *res;
	gsize len = 0, outlen;
	GError *err = NULL;

	kp = lua_check_cryptobox_keypair(L, 1);
	if (!kp) {
		return luaL_error(L, "invalid arguments; keypair is expected");
	}

	filename = luaL_checkstring(L, 2);
	data = rspamd_file_xmap(filename, PROT_READ, &len, TRUE);
	if (!data) {
		return luaL_error(L, "invalid arguments; cannot mmap %s: %s",
						  filename, strerror(errno));
	}

	if (!rspamd_keypair_decrypt(kp, data, len, &out, &outlen, &err)) {
		lua_pushboolean(L, false);
		lua_pushstring(L, err->message);
		g_error_free(err);
	}
	else {
		lua_pushboolean(L, true);
		res = lua_newuserdata(L, sizeof(*res));
		res->flags = RSPAMD_TEXT_FLAG_OWN;
		res->start = out;
		res->len = outlen;
		rspamd_lua_setclass(L, rspamd_text_classname, -1);
	}

	munmap(data, len);

	return 2;
}

#define RSPAMD_CRYPTOBOX_AES_BLOCKSIZE 16
#define RSPAMD_CRYPTOBOX_AES_KEYSIZE 16

/***
 * @function rspamd_cryptobox.encrypt_cookie(secret_key, secret_cookie)
 * Specialised function that performs AES-CTR encryption of the provided cookie
 * ```
 * e := base64(nonce||aesencrypt(nonce, secret_cookie))
 * nonce := uint32_le(unix_timestamp)||random_64bit
 * aesencrypt := aes_ctr(nonce, secret_key) ^ pad(secret_cookie)
 * pad := secret_cookie || 0^(32-len(secret_cookie))
 * ```
 * @param {string} secret_key secret key as a hex string (must be 16 bytes in raw or 32 in hex)
 * @param {string} secret_cookie secret cookie as a string for up to 31 character
 * @return {string} e function value for this sk and cookie
 */
static int
lua_cryptobox_encrypt_cookie(lua_State *L)
{
	unsigned char aes_block[RSPAMD_CRYPTOBOX_AES_BLOCKSIZE], *blk;
	unsigned char padded_cookie[RSPAMD_CRYPTOBOX_AES_BLOCKSIZE];
	unsigned char nonce[RSPAMD_CRYPTOBOX_AES_BLOCKSIZE];
	unsigned char aes_key[RSPAMD_CRYPTOBOX_AES_KEYSIZE];
	unsigned char result[RSPAMD_CRYPTOBOX_AES_BLOCKSIZE * 2];
	uint32_t ts;

	const char *sk, *cookie;
	gsize sklen, cookie_len;
	int bklen;

	sk = lua_tolstring(L, 1, &sklen);
	cookie = lua_tolstring(L, 2, &cookie_len);

	if (sk && cookie) {
		if (sklen == 32) {
			/* Hex */
			rspamd_decode_hex_buf(sk, sklen, aes_key, sizeof(aes_key));
		}
		else if (sklen == RSPAMD_CRYPTOBOX_AES_KEYSIZE) {
			/* Raw */
			memcpy(aes_key, sk, sizeof(aes_key));
		}
		else {
			return luaL_error(L, "invalid keysize %d", (int) sklen);
		}

		if (cookie_len > sizeof(padded_cookie) - 1) {
			return luaL_error(L, "cookie is too long %d", (int) cookie_len);
		}

		/* Fill nonce */
		ottery_rand_bytes(nonce, sizeof(uint64_t) + sizeof(uint32_t));
		ts = (uint32_t) rspamd_get_calendar_ticks();
		ts = GUINT32_TO_LE(ts);
		memcpy(nonce + sizeof(uint64_t) + sizeof(uint32_t), &ts, sizeof(ts));

		/* Prepare padded cookie */
		memset(padded_cookie, 0, sizeof(padded_cookie));
		memcpy(padded_cookie, cookie, cookie_len);

		/* Perform AES CTR via AES ECB on nonce */
		EVP_CIPHER_CTX *ctx;
		ctx = EVP_CIPHER_CTX_new();
		EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, aes_key, NULL);
		EVP_CIPHER_CTX_set_padding(ctx, 0);

		bklen = sizeof(aes_block);
		blk = aes_block;
		g_assert(EVP_EncryptUpdate(ctx, blk, &bklen, nonce, sizeof(nonce)));
		blk += bklen;
		g_assert(EVP_EncryptFinal_ex(ctx, blk, &bklen));
		EVP_CIPHER_CTX_free(ctx);

		/* Encode result */
		memcpy(result, nonce, sizeof(nonce));
		for (unsigned int i = 0; i < sizeof(aes_block); i++) {
			result[i + sizeof(nonce)] = padded_cookie[i] ^ aes_block[i];
		}

		gsize rlen;
		char *res = rspamd_encode_base64(result, sizeof(result),
										 0, &rlen);

		lua_pushlstring(L, res, rlen);
		g_free(res);
		rspamd_explicit_memzero(aes_key, sizeof(aes_key));
		rspamd_explicit_memzero(aes_block, sizeof(aes_block));
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

/***
 * @function rspamd_cryptobox.decrypt_cookie(secret_key, encrypted_cookie)
 * Specialised function that performs AES-CTR decryption of the provided cookie in form
 * ```
 * e := base64(nonce||aesencrypt(nonce, secret_cookie))
 * nonce := int32_le(unix_timestamp)||random_96bit
 * aesencrypt := aes_ctr(nonce, secret_key) ^ pad(secret_cookie)
 * pad := secret_cookie || 0^(32-len(secret_cookie))
 * ```
 * @param {string} secret_key secret key as a hex string (must be 16 bytes in raw or 32 in hex)
 * @param {string} encrypted_cookie encrypted cookie as a base64 encoded string
 * @return {string+number} decrypted value of the cookie and the cookie timestamp
 */
static int
lua_cryptobox_decrypt_cookie(lua_State *L)
{
	unsigned char *blk;
	unsigned char nonce[RSPAMD_CRYPTOBOX_AES_BLOCKSIZE];
	unsigned char aes_key[RSPAMD_CRYPTOBOX_AES_KEYSIZE];
	unsigned char *src;
	uint32_t ts;

	const char *sk, *cookie;
	gsize sklen, cookie_len;
	int bklen;

	sk = lua_tolstring(L, 1, &sklen);
	cookie = lua_tolstring(L, 2, &cookie_len);

	if (sk && cookie) {
		if (sklen == 32) {
			/* Hex */
			rspamd_decode_hex_buf(sk, sklen, aes_key, sizeof(aes_key));
		}
		else if (sklen == RSPAMD_CRYPTOBOX_AES_KEYSIZE) {
			/* Raw */
			memcpy(aes_key, sk, sizeof(aes_key));
		}
		else {
			return luaL_error(L, "invalid keysize %d", (int) sklen);
		}

		src = g_malloc(cookie_len);

		rspamd_cryptobox_base64_decode(cookie, cookie_len, src, &cookie_len);

		if (cookie_len != RSPAMD_CRYPTOBOX_AES_BLOCKSIZE * 2) {
			g_free(src);
			lua_pushnil(L);

			return 1;
		}

		/* Perform AES CTR via AES ECB on nonce */
		EVP_CIPHER_CTX *ctx;
		ctx = EVP_CIPHER_CTX_new();
		/* As per CTR definition, we use encrypt for both encrypt and decrypt */
		EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, aes_key, NULL);
		EVP_CIPHER_CTX_set_padding(ctx, 0);

		/* Copy time */
		memcpy(&ts, src + sizeof(uint64_t) + sizeof(uint32_t), sizeof(ts));
		ts = GUINT32_FROM_LE(ts);
		bklen = sizeof(nonce);
		blk = nonce;
		g_assert(EVP_EncryptUpdate(ctx, blk, &bklen, src,
								   RSPAMD_CRYPTOBOX_AES_BLOCKSIZE));
		blk += bklen;
		g_assert(EVP_EncryptFinal_ex(ctx, blk, &bklen));
		EVP_CIPHER_CTX_free(ctx);

		/* Decode result */
		for (unsigned int i = 0; i < RSPAMD_CRYPTOBOX_AES_BLOCKSIZE; i++) {
			src[i + sizeof(nonce)] ^= nonce[i];
		}

		if (src[RSPAMD_CRYPTOBOX_AES_BLOCKSIZE * 2 - 1] != '\0') {
			/* Bad cookie */
			lua_pushnil(L);
			lua_pushnil(L);
		}
		else {
			lua_pushstring(L, src + sizeof(nonce));
			lua_pushnumber(L, ts);
		}

		rspamd_explicit_memzero(src, RSPAMD_CRYPTOBOX_AES_BLOCKSIZE * 2);
		g_free(src);
		rspamd_explicit_memzero(aes_key, sizeof(aes_key));
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 2;
}

/***
 * @function rspamd_cryptobox.pbkdf([password, [kdf_alg]])
 * Function that encrypts password using PBKDF function.
 * This function either reads password from STDIN or accepts prepared password as
 * an argument
 * @param {string} password optional password string
 * @param {string} kdf_alg algorithm to use (catena or pbkdf2)
 * @return {string} encrypted password or nil if error occurs
 */
static int
lua_cryptobox_pbkdf(lua_State *L)
{
	const struct rspamd_controller_pbkdf *pbkdf = NULL;
	const char *pbkdf_str = "catena";
	char *password;
	gsize pwlen;

	if (lua_type(L, 2) == LUA_TSTRING) {
		pbkdf_str = lua_tostring(L, 2);
	}

	for (unsigned int i = 0; i < RSPAMD_PBKDF_ID_MAX - 1; i++) {
		pbkdf = &pbkdf_list[i];

		if (g_ascii_strcasecmp(pbkdf_str, pbkdf->alias) == 0) {
			break;
		}
		if (g_ascii_strcasecmp(pbkdf_str, pbkdf->name) == 0) {
			break;
		}

		pbkdf = NULL;
	}

	if (pbkdf == NULL) {
		return luaL_error(L, "invalid pbkdf algorithm: %s", pbkdf_str);
	}

	if (lua_type(L, 1) == LUA_TSTRING) {
		password = g_strdup(lua_tolstring(L, 1, &pwlen));
	}
	else {
		pwlen = 8192;
		password = g_malloc0(pwlen);
		pwlen = rspamd_read_passphrase(password, pwlen, 0, NULL);
	}

	if (pwlen == 0) {
		lua_pushnil(L);
		g_free(password);

		return 1;
	}

	unsigned char *salt, *key;
	char *encoded_salt, *encoded_key;
	GString *result;

	salt = g_alloca(pbkdf->salt_len);
	key = g_alloca(pbkdf->key_len);
	ottery_rand_bytes(salt, pbkdf->salt_len);
	/* Derive key */
	rspamd_cryptobox_pbkdf(password, pwlen,
						   salt, pbkdf->salt_len, key, pbkdf->key_len, pbkdf->complexity,
						   pbkdf->type);

	encoded_salt = rspamd_encode_base32(salt, pbkdf->salt_len, RSPAMD_BASE32_DEFAULT);
	encoded_key = rspamd_encode_base32(key, pbkdf->key_len, RSPAMD_BASE32_DEFAULT);

	result = g_string_new("");
	rspamd_printf_gstring(result, "$%d$%s$%s", pbkdf->id, encoded_salt,
						  encoded_key);

	g_free(encoded_salt);
	g_free(encoded_key);
	rspamd_explicit_memzero(password, pwlen);
	g_free(password);
	lua_pushlstring(L, result->str, result->len);
	g_string_free(result, TRUE);

	return 1;
}

/***
 * @function rspamd_cryptobox.gen_dkim_keypair([alg, [nbits]])
 * Generates DKIM keypair. Returns 2 base64 strings as rspamd_text: privkey and pubkey
 * @param {string} alg optional algorithm (rsa default, can be ed25519)
 * @param {number} nbits optional number of bits for rsa (default 1024)
 * @return {rspamd_text,rspamd_text} private key and public key as base64 encoded strings
 */
static int
lua_cryptobox_gen_dkim_keypair(lua_State *L)
{
	const char *alg_str = "rsa";
	unsigned int nbits = 1024;
	struct rspamd_lua_text *priv_out, *pub_out;

	if (lua_type(L, 1) == LUA_TSTRING) {
		alg_str = lua_tostring(L, 1);
	}

	if (lua_type(L, 2) == LUA_TNUMBER) {
		nbits = lua_tointeger(L, 2);
	}

	if (strcmp(alg_str, "rsa") == 0) {
		BIGNUM *e;
		RSA *r;
		EVP_PKEY *pk;

		e = BN_new();
		pk = EVP_PKEY_new();

		if (BN_set_word(e, RSA_F4) != 1) {
			BN_free(e);
			EVP_PKEY_free(pk);

			return luaL_error(L, "BN_set_word failed");
		}

		EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
		if (EVP_PKEY_keygen_init(pctx) != 1) {
			BN_free(e);
			EVP_PKEY_free(pk);
			EVP_PKEY_CTX_free(pctx);

			return luaL_error(L, "EVP_PKEY_keygen_init failed");
		}
		EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, nbits);
		EVP_PKEY_CTX_set1_rsa_keygen_pubexp(pctx, e);
		if (EVP_PKEY_keygen(pctx, &pk) != 1) {
			BN_free(e);
			EVP_PKEY_free(pk);
			EVP_PKEY_CTX_free(pctx);

			return luaL_error(L, "EVP_PKEY_keygen failed");
		}

		BIO *mbio;
		int rc, len;
		unsigned char *data;
		char *b64_data;
		gsize b64_len;

		mbio = BIO_new(BIO_s_mem());

		/* Process private key */
		rc = i2d_PrivateKey_bio(mbio, pk);

		if (rc == 0) {
			BIO_free(mbio);
			BN_free(e);
			EVP_PKEY_free(pk);

			return luaL_error(L, "i2d_RSAPrivateKey_bio failed");
		}

		len = BIO_get_mem_data(mbio, &data);

		b64_data = rspamd_encode_base64(data, len, -1, &b64_len);

		priv_out = lua_newuserdata(L, sizeof(*priv_out));
		rspamd_lua_setclass(L, rspamd_text_classname, -1);
		priv_out->start = b64_data;
		priv_out->len = b64_len;
		priv_out->flags = RSPAMD_TEXT_FLAG_OWN | RSPAMD_TEXT_FLAG_WIPE;

		/* Process public key */
		BIO_reset(mbio);
		rc = i2d_PUBKEY_bio(mbio, pk);

		if (rc == 0) {
			BIO_free(mbio);
			BN_free(e);
			EVP_PKEY_free(pk);

			return luaL_error(L, "i2d_RSA_PUBKEY_bio failed");
		}

		len = BIO_get_mem_data(mbio, &data);

		b64_data = rspamd_encode_base64(data, len, -1, &b64_len);

		pub_out = lua_newuserdata(L, sizeof(*pub_out));
		rspamd_lua_setclass(L, rspamd_text_classname, -1);
		pub_out->start = b64_data;
		pub_out->len = b64_len;
		pub_out->flags = RSPAMD_TEXT_FLAG_OWN;

		BN_free(e);
		EVP_PKEY_free(pk);
		BIO_free(mbio);
	}
	else if (strcmp(alg_str, "ed25519") == 0) {
		rspamd_sig_pk_t pk;
		rspamd_sig_sk_t sk;
		char *b64_data;
		gsize b64_len;

		rspamd_cryptobox_keypair_sig(pk, sk);

		/* Process private key */
		b64_data = rspamd_encode_base64(sk,
										crypto_sign_secretkeybytes(),
										-1, &b64_len);

		priv_out = lua_newuserdata(L, sizeof(*priv_out));
		rspamd_lua_setclass(L, rspamd_text_classname, -1);
		priv_out->start = b64_data;
		priv_out->len = b64_len;
		priv_out->flags = RSPAMD_TEXT_FLAG_OWN | RSPAMD_TEXT_FLAG_WIPE;

		/* Process public key */
		b64_data = rspamd_encode_base64(pk,
										crypto_sign_publickeybytes(),
										-1, &b64_len);

		pub_out = lua_newuserdata(L, sizeof(*pub_out));
		rspamd_lua_setclass(L, rspamd_text_classname, -1);
		pub_out->start = b64_data;
		pub_out->len = b64_len;
		pub_out->flags = RSPAMD_TEXT_FLAG_OWN;

		rspamd_explicit_memzero(pk, sizeof(pk));
		rspamd_explicit_memzero(sk, sizeof(sk));
	}
	else if (strcmp(alg_str, "ed25519-seed") == 0) {
		rspamd_sig_pk_t pk;
		rspamd_sig_sk_t sk;
		char *b64_data;
		gsize b64_len;

		rspamd_cryptobox_keypair_sig(pk, sk);

		/* Process private key */
		b64_data = rspamd_encode_base64(sk,
										32,
										-1, &b64_len);

		priv_out = lua_newuserdata(L, sizeof(*priv_out));
		rspamd_lua_setclass(L, rspamd_text_classname, -1);
		priv_out->start = b64_data;
		priv_out->len = b64_len;
		priv_out->flags = RSPAMD_TEXT_FLAG_OWN | RSPAMD_TEXT_FLAG_WIPE;

		/* Process public key */
		b64_data = rspamd_encode_base64(pk,
										crypto_sign_publickeybytes(),
										-1, &b64_len);

		pub_out = lua_newuserdata(L, sizeof(*pub_out));
		rspamd_lua_setclass(L, rspamd_text_classname, -1);
		pub_out->start = b64_data;
		pub_out->len = b64_len;
		pub_out->flags = RSPAMD_TEXT_FLAG_OWN;

		rspamd_explicit_memzero(pk, sizeof(pk));
		rspamd_explicit_memzero(sk, sizeof(sk));
	}
	else {
		return luaL_error(L, "invalid algorithm %s", alg_str);
	}

	return 2;
}

/*
 * Secretbox API
 */
/* Ensure that KDF output is suitable for crypto_secretbox_KEYBYTES */
#ifdef crypto_generichash_BYTES_MIN
G_STATIC_ASSERT(crypto_secretbox_KEYBYTES >= crypto_generichash_BYTES_MIN);
#endif

/***
 * @function rspamd_cryptobox_secretbox.create(secret_string, [params])
 * Generates a secretbox state by expanding secret string
 * @param {string/text} secret_string secret string (should have high enough entropy)
 * @param {table} params optional parameters - NYI
 * @return {rspamd_cryptobox_secretbox} opaque object with the key expanded
 */
static int
lua_cryptobox_secretbox_create(lua_State *L)
{
	const char *in;
	gsize inlen;


	if (lua_isstring(L, 1)) {
		in = lua_tolstring(L, 1, &inlen);
	}
	else if (lua_isuserdata(L, 1)) {
		struct rspamd_lua_text *t = lua_check_text(L, 1);

		if (!t) {
			return luaL_error(L, "invalid arguments; userdata is not text");
		}

		in = t->start;
		inlen = t->len;
	}
	else {
		return luaL_error(L, "invalid arguments; userdata or string are expected");
	}

	if (in == NULL || inlen == 0) {
		return luaL_error(L, "invalid arguments; non empty secret expected");
	}

	struct rspamd_lua_cryptobox_secretbox *sbox, **psbox;

	sbox = g_malloc0(sizeof(*sbox));
	crypto_generichash(sbox->sk, sizeof(sbox->sk), in, inlen, NULL, 0);
	psbox = lua_newuserdata(L, sizeof(*psbox));
	*psbox = sbox;
	rspamd_lua_setclass(L, rspamd_cryptobox_secretbox_classname, -1);

	return 1;
}


static int
lua_cryptobox_secretbox_gc(lua_State *L)
{
	struct rspamd_lua_cryptobox_secretbox *sbox =
		lua_check_cryptobox_secretbox(L, 1);

	if (sbox != NULL) {
		sodium_memzero(sbox->sk, sizeof(sbox->sk));
		g_free(sbox);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 0;
}

/***
 * @method rspamd_cryptobox_secretbox:encrypt(input, [nonce])
 * Encrypts data using secretbox. MAC is prepended to the message
 * @param {string/text} input input to encrypt
 * @param {string/text} nonce optional nonce (must be 1 - 192 bits length)
 * @param {table} params optional parameters - NYI
 * @return {rspamd_text},{rspamd_text} output with mac + nonce or just output if nonce is there
 */
static int
lua_cryptobox_secretbox_encrypt(lua_State *L)
{
	const char *in, *nonce;
	gsize inlen, nlen;
	struct rspamd_lua_cryptobox_secretbox *sbox =
		lua_check_cryptobox_secretbox(L, 1);
	struct rspamd_lua_text *out;

	if (sbox == NULL) {
		return luaL_error(L, "invalid argument for secretbox state");
	}

	if (lua_isstring(L, 2)) {
		in = lua_tolstring(L, 2, &inlen);
	}
	else if (lua_isuserdata(L, 2)) {
		struct rspamd_lua_text *t = lua_check_text(L, 2);

		if (!t) {
			return luaL_error(L, "invalid first argument; userdata is not text");
		}

		in = t->start;
		inlen = t->len;
	}
	else {
		return luaL_error(L, "invalid first argument; userdata or string are expected");
	}

	/* Nonce part */
	if (!lua_isnoneornil(L, 3)) {
		if (lua_isstring(L, 3)) {
			nonce = lua_tolstring(L, 3, &nlen);
		}
		else if (lua_isuserdata(L, 3)) {
			struct rspamd_lua_text *t = lua_check_text(L, 3);

			if (!t) {
				return luaL_error(L, "invalid second argument; userdata is not text");
			}

			nonce = t->start;
			nlen = t->len;
		}
		else {
			return luaL_error(L, "invalid second argument; userdata or string are expected");
		}

		if (nlen < 1 || nlen > crypto_secretbox_NONCEBYTES) {
			return luaL_error(L, "bad nonce");
		}

		unsigned char real_nonce[crypto_secretbox_NONCEBYTES];

		memset(real_nonce, 0, sizeof(real_nonce));
		memcpy(real_nonce, nonce, nlen);

		out = lua_new_text(L, NULL, inlen + crypto_secretbox_MACBYTES,
						   TRUE);
		crypto_secretbox_easy((unsigned char *) out->start, in, inlen,
							  nonce, sbox->sk);

		return 1;
	}
	else {
		/* Random nonce */
		struct rspamd_lua_text *random_nonce;

		out = lua_new_text(L, NULL, inlen + crypto_secretbox_MACBYTES,
						   TRUE);
		random_nonce = lua_new_text(L, NULL, crypto_secretbox_NONCEBYTES, TRUE);

		randombytes_buf((unsigned char *) random_nonce->start, random_nonce->len);
		crypto_secretbox_easy((unsigned char *) out->start, in, inlen,
							  random_nonce->start, sbox->sk);

		return 2; /* output + random nonce */
	}
}

/***
 * @method rspamd_cryptobox_secretbox:decrypt(input, nonce)
 * Decrypts data using secretbox
 * @param {string/text} input input to decrypt
 * @param {string/text} nonce nonce used to encrypt
 * @param {table} params optional parameters - NYI
 * @return {boolean},{rspamd_text} decryption result + decrypted text
 */
static int
lua_cryptobox_secretbox_decrypt(lua_State *L)
{
	const char *in, *nonce;
	gsize inlen, nlen;
	struct rspamd_lua_cryptobox_secretbox *sbox =
		lua_check_cryptobox_secretbox(L, 1);
	struct rspamd_lua_text *out;

	if (sbox == NULL) {
		return luaL_error(L, "invalid argument for secretbox state");
	}

	/* Input argument */
	if (lua_isstring(L, 2)) {
		in = lua_tolstring(L, 2, &inlen);
	}
	else if (lua_isuserdata(L, 2)) {
		struct rspamd_lua_text *t = lua_check_text(L, 2);

		if (!t) {
			return luaL_error(L, "invalid first argument; userdata is not text");
		}

		in = t->start;
		inlen = t->len;
	}
	else {
		return luaL_error(L, "invalid first argument; userdata or string are expected");
	}

	/* Nonce argument */
	if (lua_isstring(L, 3)) {
		nonce = lua_tolstring(L, 3, &nlen);
	}
	else if (lua_isuserdata(L, 3)) {
		struct rspamd_lua_text *t = lua_check_text(L, 3);

		if (!t) {
			return luaL_error(L, "invalid second argument; userdata is not text");
		}

		nonce = t->start;
		nlen = t->len;
	}
	else {
		return luaL_error(L, "invalid second argument; userdata or string are expected");
	}


	if (nlen < 1 || nlen > crypto_secretbox_NONCEBYTES) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "invalid nonce");
		return 2;
	}

	if (inlen < crypto_secretbox_MACBYTES) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "too short");
		return 2;
	}

	unsigned char real_nonce[crypto_secretbox_NONCEBYTES];

	memset(real_nonce, 0, sizeof(real_nonce));
	memcpy(real_nonce, nonce, nlen);

	out = lua_new_text(L, NULL, inlen - crypto_secretbox_MACBYTES,
					   TRUE);
	int text_pos = lua_gettop(L);

	if (crypto_secretbox_open_easy((unsigned char *) out->start, in, inlen,
								   nonce, sbox->sk) == 0) {
		lua_pushboolean(L, true);
		lua_pushvalue(L, text_pos); /* Prevent gc by copying in stack */
	}
	else {
		lua_pushboolean(L, false);
		lua_pushstring(L, "authentication error");
	}

	/* This causes gc method if decryption has failed */
	lua_remove(L, text_pos);

	return 2;
}

static int
lua_load_pubkey(lua_State *L)
{
	lua_newtable(L);
	luaL_register(L, NULL, cryptoboxpubkeylib_f);

	return 1;
}

static int
lua_load_keypair(lua_State *L)
{
	lua_newtable(L);
	luaL_register(L, NULL, cryptoboxkeypairlib_f);

	return 1;
}

static int
lua_load_signature(lua_State *L)
{
	lua_newtable(L);
	luaL_register(L, NULL, cryptoboxsignlib_f);

	return 1;
}

static int
lua_load_hash(lua_State *L)
{
	lua_newtable(L);
	luaL_register(L, NULL, cryptoboxhashlib_f);

	return 1;
}

static int
lua_load_cryptobox_secretbox(lua_State *L)
{
	lua_newtable(L);
	luaL_register(L, NULL, cryptoboxsecretboxlib_f);

	return 1;
}

static int
lua_load_cryptobox(lua_State *L)
{
	lua_newtable(L);
	luaL_register(L, NULL, cryptoboxlib_f);

	return 1;
}

void luaopen_cryptobox(lua_State *L)
{
	rspamd_lua_new_class(L, rspamd_cryptobox_pubkey_classname, cryptoboxpubkeylib_m);
	lua_pop(L, 1);
	rspamd_lua_add_preload(L, "rspamd_cryptobox_pubkey", lua_load_pubkey);

	rspamd_lua_new_class(L, rspamd_cryptobox_keypair_classname, cryptoboxkeypairlib_m);
	lua_pop(L, 1);
	rspamd_lua_add_preload(L, "rspamd_cryptobox_keypair", lua_load_keypair);

	rspamd_lua_new_class(L, rspamd_cryptobox_signature_classname, cryptoboxsignlib_m);
	lua_pop(L, 1);
	rspamd_lua_add_preload(L, "rspamd_cryptobox_signature", lua_load_signature);

	rspamd_lua_new_class(L, rspamd_cryptobox_hash_classname, cryptoboxhashlib_m);
	lua_pop(L, 1);
	rspamd_lua_add_preload(L, "rspamd_cryptobox_hash", lua_load_hash);

	rspamd_lua_new_class(L, rspamd_cryptobox_secretbox_classname,
						 cryptoboxsecretboxlib_m);
	lua_pop(L, 1);
	rspamd_lua_add_preload(L, "rspamd_cryptobox_secretbox",
						   lua_load_cryptobox_secretbox);

	rspamd_lua_add_preload(L, "rspamd_cryptobox", lua_load_cryptobox);

	lua_settop(L, 0);
}
