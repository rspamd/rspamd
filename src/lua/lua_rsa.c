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
/**
 * @file lua_rsa.c
 * This module exports routines to load rsa keys, check inline or external
 * rsa signatures. It assumes sha256 based signatures.
 */

#include "lua_common.h"
#include "unix-std.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>

LUA_FUNCTION_DEF (rsa_pubkey,	 load);
LUA_FUNCTION_DEF (rsa_pubkey,	 create);
LUA_FUNCTION_DEF (rsa_pubkey,	 gc);
LUA_FUNCTION_DEF (rsa_privkey,	 load_file);
LUA_FUNCTION_DEF (rsa_privkey,	 load_pem);
LUA_FUNCTION_DEF (rsa_privkey,	 load_raw);
LUA_FUNCTION_DEF (rsa_privkey,	 load_base64);
LUA_FUNCTION_DEF (rsa_privkey,	 create);
LUA_FUNCTION_DEF (rsa_privkey,	 gc);
LUA_FUNCTION_DEF (rsa_signature, create);
LUA_FUNCTION_DEF (rsa_signature, load);
LUA_FUNCTION_DEF (rsa_signature, save);
LUA_FUNCTION_DEF (rsa_signature, base64);
LUA_FUNCTION_DEF (rsa_signature, gc);
LUA_FUNCTION_DEF (rsa,			 verify_memory);
LUA_FUNCTION_DEF (rsa,			 sign_memory);

static const struct luaL_reg rsalib_f[] = {
	LUA_INTERFACE_DEF (rsa, verify_memory),
	LUA_INTERFACE_DEF (rsa, sign_memory),
	{NULL, NULL}
};

static const struct luaL_reg rsapubkeylib_f[] = {
	LUA_INTERFACE_DEF (rsa_pubkey, load),
	LUA_INTERFACE_DEF (rsa_pubkey, create),
	{NULL, NULL}
};

static const struct luaL_reg rsapubkeylib_m[] = {
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_rsa_pubkey_gc},
	{NULL, NULL}
};

static const struct luaL_reg rsaprivkeylib_f[] = {
	LUA_INTERFACE_DEF (rsa_privkey, load_file),
	LUA_INTERFACE_DEF (rsa_privkey, load_pem),
	LUA_INTERFACE_DEF (rsa_privkey, load_raw),
	LUA_INTERFACE_DEF (rsa_privkey, load_base64),
	LUA_INTERFACE_DEF (rsa_privkey, create),
	{NULL, NULL}
};

static const struct luaL_reg rsaprivkeylib_m[] = {
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_rsa_privkey_gc},
	{NULL, NULL}
};

static const struct luaL_reg rsasignlib_f[] = {
	LUA_INTERFACE_DEF (rsa_signature, load),
	LUA_INTERFACE_DEF (rsa_signature, create),
	{NULL, NULL}
};

static const struct luaL_reg rsasignlib_m[] = {
	LUA_INTERFACE_DEF (rsa_signature, save),
	LUA_INTERFACE_DEF (rsa_signature, base64),
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_rsa_signature_gc},
	{NULL, NULL}
};

static RSA *
lua_check_rsa_pubkey (lua_State * L, int pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{rsa_pubkey}");

	luaL_argcheck (L, ud != NULL, 1, "'rsa_pubkey' expected");
	return ud ? *((RSA **)ud) : NULL;
}

static RSA *
lua_check_rsa_privkey (lua_State * L, int pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{rsa_privkey}");

	luaL_argcheck (L, ud != NULL, 1, "'rsa_privkey' expected");
	return ud ? *((RSA **)ud) : NULL;
}

static rspamd_fstring_t *
lua_check_rsa_sign (lua_State * L, int pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{rsa_signature}");

	luaL_argcheck (L, ud != NULL, 1, "'rsa_signature' expected");
	return ud ? *((rspamd_fstring_t **)ud) : NULL;
}

static gint
lua_rsa_pubkey_load (lua_State *L)
{
	RSA *rsa = NULL, **prsa;
	const gchar *filename;
	FILE *f;

	filename = luaL_checkstring (L, 1);
	if (filename != NULL) {
		f = fopen (filename, "r");
		if (f == NULL) {
			msg_err ("cannot open pubkey from file: %s, %s",
				filename,
				strerror (errno));
			lua_pushnil (L);
		}
		else {
			if (!PEM_read_RSA_PUBKEY (f, &rsa, NULL, NULL)) {
				msg_err ("cannot open pubkey from file: %s, %s", filename,
					ERR_error_string (ERR_get_error (), NULL));
				lua_pushnil (L);
			}
			else {
				prsa = lua_newuserdata (L, sizeof (RSA *));
				rspamd_lua_setclass (L, "rspamd{rsa_pubkey}", -1);
				*prsa = rsa;
			}
			fclose (f);
		}
	}
	else {
		lua_pushnil (L);
	}
	return 1;
}

static gint
lua_rsa_pubkey_create (lua_State *L)
{
	RSA *rsa = NULL, **prsa;
	const gchar *buf;
	BIO *bp;

	buf = luaL_checkstring (L, 1);
	if (buf != NULL) {
		bp = BIO_new_mem_buf ((void *)buf, -1);

		if (!PEM_read_bio_RSA_PUBKEY (bp, &rsa, NULL, NULL)) {
			msg_err ("cannot parse pubkey: %s",
				ERR_error_string (ERR_get_error (), NULL));
			lua_pushnil (L);
		}
		else {
			prsa = lua_newuserdata (L, sizeof (RSA *));
			rspamd_lua_setclass (L, "rspamd{rsa_pubkey}", -1);
			*prsa = rsa;
		}
		BIO_free (bp);
	}
	else {
		lua_pushnil (L);
	}
	return 1;
}

static gint
lua_rsa_pubkey_gc (lua_State *L)
{
	RSA *rsa = lua_check_rsa_pubkey (L, 1);

	if (rsa != NULL) {
		RSA_free (rsa);
	}

	return 0;
}

static gint
lua_rsa_privkey_load_file (lua_State *L)
{
	RSA *rsa = NULL, **prsa;
	const gchar *filename;
	FILE *f;

	filename = luaL_checkstring (L, 1);
	if (filename != NULL) {
		f = fopen (filename, "r");
		if (f == NULL) {
			msg_err ("cannot open private key from file: %s, %s",
				filename,
				strerror (errno));
			lua_pushnil (L);
		}
		else {
			if (!PEM_read_RSAPrivateKey (f, &rsa, NULL, NULL)) {
				msg_err ("cannot open private key from file: %s, %s", filename,
					ERR_error_string (ERR_get_error (), NULL));
				lua_pushnil (L);
			}
			else {
				prsa = lua_newuserdata (L, sizeof (RSA *));
				rspamd_lua_setclass (L, "rspamd{rsa_privkey}", -1);
				*prsa = rsa;
			}
			fclose (f);
		}
	}
	else {
		lua_pushnil (L);
	}
	return 1;
}

static gint
lua_rsa_privkey_load_pem (lua_State *L)
{
	RSA *rsa = NULL, **prsa;
	BIO *b;
	struct rspamd_lua_text *t;
	const gchar *data;
	gsize len;

	if (lua_isuserdata (L, 1)) {
		t = lua_check_text (L, 1);

		if (!t) {
			return luaL_error (L, "invalid arguments");
		}

		data = t->start;
		len = t->len;
	}
	else {
		data = luaL_checklstring (L, 1, &len);
	}

	if (data != NULL) {
		b = BIO_new_mem_buf (data, len);

		if (!PEM_read_bio_RSAPrivateKey (b, &rsa, NULL, NULL)) {
			msg_err ("cannot open private key from data, %s",
					ERR_error_string (ERR_get_error (), NULL));
			lua_pushnil (L);
		}
		else {
			prsa = lua_newuserdata (L, sizeof (RSA *));
			rspamd_lua_setclass (L, "rspamd{rsa_privkey}", -1);
			*prsa = rsa;
		}

		BIO_free (b);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_rsa_privkey_load_raw (lua_State *L)
{
	RSA *rsa = NULL, **prsa;
	BIO *b;
	struct rspamd_lua_text *t;
	const gchar *data;
	gsize len;

	if (lua_isuserdata (L, 1)) {
		t = lua_check_text (L, 1);

		if (!t) {
			return luaL_error (L, "invalid arguments");
		}

		data = t->start;
		len = t->len;
	}
	else {
		data = luaL_checklstring (L, 1, &len);
	}

	if (data != NULL) {
		b = BIO_new_mem_buf (data, len);
		rsa = d2i_RSAPrivateKey_bio (b, NULL);

		if (rsa == NULL) {
			msg_err ("cannot open private key from data, %s",
					ERR_error_string (ERR_get_error (), NULL));
			lua_pushnil (L);
		}
		else {
			prsa = lua_newuserdata (L, sizeof (RSA *));
			rspamd_lua_setclass (L, "rspamd{rsa_privkey}", -1);
			*prsa = rsa;
		}

		BIO_free (b);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_rsa_privkey_load_base64 (lua_State *L)
{
	RSA *rsa = NULL, **prsa;
	BIO *b;
	EVP_PKEY *evp = NULL;
	struct rspamd_lua_text *t;
	const gchar *data;
	guchar *decoded;
	gsize len, dec_len;

	if (lua_isuserdata (L, 1)) {
		t = lua_check_text (L, 1);

		if (!t) {
			return luaL_error (L, "invalid arguments");
		}

		data = t->start;
		len = t->len;
	}
	else {
		data = luaL_checklstring (L, 1, &len);
	}

	if (data != NULL) {
		decoded = g_malloc (len);

		if (!rspamd_cryptobox_base64_decode (data, len, decoded, &dec_len)) {
			g_free (decoded);

			return luaL_error (L, "invalid base64 encoding");
		}

		b = BIO_new_mem_buf (decoded, dec_len);

		if (d2i_PrivateKey_bio (b, &evp) != NULL) {
			rsa = EVP_PKEY_get1_RSA (evp);

			if (rsa == NULL) {
				msg_err ("cannot open RSA private key from data, %s",
						ERR_error_string (ERR_get_error (), NULL));
				lua_pushnil (L);
			}
			else {
				prsa = lua_newuserdata (L, sizeof (RSA *));
				rspamd_lua_setclass (L, "rspamd{rsa_privkey}", -1);
				*prsa = rsa;
			}

			EVP_PKEY_free (evp);
		}
		else {
			msg_err ("cannot open EVP private key from data, %s",
					ERR_error_string (ERR_get_error (), NULL));
			lua_pushnil (L);
		}

		BIO_free (b);
		g_free (decoded);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_rsa_privkey_create (lua_State *L)
{
	RSA *rsa = NULL, **prsa;
	const gchar *buf;
	BIO *bp;

	buf = luaL_checkstring (L, 1);
	if (buf != NULL) {
		bp = BIO_new_mem_buf ((void *)buf, -1);

		if (!PEM_read_bio_RSAPrivateKey (bp, &rsa, NULL, NULL)) {
			msg_err ("cannot parse private key: %s",
				ERR_error_string (ERR_get_error (), NULL));
			lua_pushnil (L);
		}
		else {
			prsa = lua_newuserdata (L, sizeof (RSA *));
			rspamd_lua_setclass (L, "rspamd{rsa_privkey}", -1);
			*prsa = rsa;
		}
		BIO_free (bp);
	}
	else {
		lua_pushnil (L);
	}
	return 1;
}

static gint
lua_rsa_privkey_gc (lua_State *L)
{
	RSA *rsa = lua_check_rsa_privkey (L, 1);

	if (rsa != NULL) {
		RSA_free (rsa);
	}

	return 0;
}

static gint
lua_rsa_signature_load (lua_State *L)
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
			if (fstat (fd, &st) == -1 ||
				(data =
				mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0))
						== MAP_FAILED) {
				msg_err ("cannot mmap file %s: %s", filename, strerror (errno));
				lua_pushnil (L);
			}
			else {
				sig = rspamd_fstring_new_init (data, st.st_size);
				psig = lua_newuserdata (L, sizeof (rspamd_fstring_t *));
				rspamd_lua_setclass (L, "rspamd{rsa_signature}", -1);
				*psig = sig;
				munmap (data, st.st_size);
			}
			close (fd);
		}
	}
	else {
		lua_pushnil (L);
	}
	return 1;
}

static gint
lua_rsa_signature_save (lua_State *L)
{
	rspamd_fstring_t *sig;
	gint fd, flags;
	const gchar *filename;
	gboolean forced = FALSE, res = TRUE;

	sig = lua_check_rsa_sign (L, 1);
	filename = luaL_checkstring (L, 2);
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
		lua_pushboolean (L, FALSE);
	}

	return 1;
}

static gint
lua_rsa_signature_create (lua_State *L)
{
	rspamd_fstring_t *sig, **psig;
	const gchar *data;
	gsize dlen;

	data = luaL_checklstring (L, 1, &dlen);
	if (data != NULL) {
		sig = rspamd_fstring_new_init (data, dlen);
		psig = lua_newuserdata (L, sizeof (rspamd_fstring_t *));
		rspamd_lua_setclass (L, "rspamd{rsa_signature}", -1);
		*psig = sig;
	}

	return 1;
}

static gint
lua_rsa_signature_gc (lua_State *L)
{
	rspamd_fstring_t *sig = lua_check_rsa_sign (L, 1);

	rspamd_fstring_free (sig);

	return 0;
}

static gint
lua_rsa_signature_base64 (lua_State *L)
{
	rspamd_fstring_t *sig = lua_check_rsa_sign (L, 1);
	guint boundary = 0;
	gchar *b64;
	gsize outlen;
	enum rspamd_newlines_type how = RSPAMD_TASK_NEWLINES_CRLF;

	if (lua_isnumber (L, 2)) {
		boundary = lua_tonumber (L, 2);
	}

	if (lua_isstring (L, 3)) {
		const gchar *how_str = lua_tostring (L, 3);

		if (strcmp (how_str, "cr") == 0) {
			how = RSPAMD_TASK_NEWLINES_CR;
		}
		else if (strcmp (how_str, "lf") == 0) {
			how = RSPAMD_TASK_NEWLINES_LF;
		}
		else {
			how = RSPAMD_TASK_NEWLINES_CRLF;
		}
	}

	b64 = rspamd_encode_base64_fold (sig->str, sig->len, boundary, &outlen, how);

	if (b64) {
		lua_pushlstring (L, b64, outlen);
		g_free (b64);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/**
 * Check memory using specified rsa key and signature
 *
 * arguments:
 * (rsa_pubkey, rsa_signature, string)
 *
 * returns:
 * true - if string match rsa signature
 * false - otherwise
 */
static gint
lua_rsa_verify_memory (lua_State *L)
{
	RSA *rsa;
	rspamd_fstring_t *signature;
	const gchar *data;
	gsize sz;
	gint ret;

	rsa = lua_check_rsa_pubkey (L, 1);
	signature = lua_check_rsa_sign (L, 2);
	data = luaL_checklstring (L, 3, &sz);

	if (rsa != NULL && signature != NULL && data != NULL) {
		ret = RSA_verify (NID_sha256, data, sz,
				signature->str, signature->len, rsa);

		if (ret == 0) {
			msg_info ("cannot check rsa signature for data: %s",
				ERR_error_string (ERR_get_error (), NULL));
			lua_pushboolean (L, FALSE);
		}
		else {
			lua_pushboolean (L, TRUE);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/**
 * Sign memory using specified rsa key and signature
 *
 * arguments:
 * (rsa_privkey, string)
 *
 * returns:
 * rspamd_signature object
 * nil - otherwise
 */
static gint
lua_rsa_sign_memory (lua_State *L)
{
	RSA *rsa;
	rspamd_fstring_t *signature, **psig;
	const gchar *data;
	gsize sz;
	gint ret;

	rsa = lua_check_rsa_privkey (L, 1);
	data = luaL_checklstring (L, 2, &sz);

	if (rsa != NULL && data != NULL) {
		signature = rspamd_fstring_sized_new (RSA_size (rsa));

		guint siglen = signature->len;
		ret = RSA_sign (NID_sha256, data, sz,
				signature->str, &siglen, rsa);

		if (ret != 1) {
			rspamd_fstring_free (signature);

			return luaL_error (L, "cannot sign: %s",
					ERR_error_string (ERR_get_error (), NULL));
		}
		else {
			signature->len = siglen;
			psig = lua_newuserdata (L, sizeof (rspamd_fstring_t *));
			rspamd_lua_setclass (L, "rspamd{rsa_signature}", -1);
			*psig = signature;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_load_pubkey (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, rsapubkeylib_f);

	return 1;
}

static gint
lua_load_privkey (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, rsaprivkeylib_f);

	return 1;
}

static gint
lua_load_signature (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, rsasignlib_f);

	return 1;
}

static gint
lua_load_rsa (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, rsalib_f);

	return 1;
}

void
luaopen_rsa (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{rsa_pubkey}", rsapubkeylib_m);
	lua_pop (L, 1);
	rspamd_lua_add_preload (L, "rspamd_rsa_pubkey", lua_load_pubkey);

	rspamd_lua_new_class (L, "rspamd{rsa_privkey}", rsaprivkeylib_m);
	lua_pop (L, 1);
	rspamd_lua_add_preload (L, "rspamd_rsa_privkey", lua_load_privkey);

	rspamd_lua_new_class (L, "rspamd{rsa_signature}", rsasignlib_m);
	lua_pop (L, 1);
	rspamd_lua_add_preload (L, "rspamd_rsa_signature", lua_load_signature);

	rspamd_lua_add_preload (L, "rspamd_rsa", lua_load_rsa);

	lua_settop (L, 0);
}
