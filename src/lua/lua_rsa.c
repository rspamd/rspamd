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

LUA_FUNCTION_DEF(rsa_pubkey, load);
LUA_FUNCTION_DEF(rsa_pubkey, create);
LUA_FUNCTION_DEF(rsa_pubkey, gc);
LUA_FUNCTION_DEF(rsa_pubkey, tostring);

LUA_FUNCTION_DEF(rsa_privkey, load_file);
LUA_FUNCTION_DEF(rsa_privkey, load_pem);
LUA_FUNCTION_DEF(rsa_privkey, load_raw);
LUA_FUNCTION_DEF(rsa_privkey, load_base64);
LUA_FUNCTION_DEF(rsa_privkey, create);
LUA_FUNCTION_DEF(rsa_privkey, gc);
LUA_FUNCTION_DEF(rsa_privkey, save);

LUA_FUNCTION_DEF(rsa_signature, create);
LUA_FUNCTION_DEF(rsa_signature, load);
LUA_FUNCTION_DEF(rsa_signature, save);
LUA_FUNCTION_DEF(rsa_signature, base64);
LUA_FUNCTION_DEF(rsa_signature, gc);

LUA_FUNCTION_DEF(rsa, verify_memory);
LUA_FUNCTION_DEF(rsa, sign_memory);
LUA_FUNCTION_DEF(rsa, keypair);

static const struct luaL_reg rsalib_f[] = {
	LUA_INTERFACE_DEF(rsa, verify_memory),
	LUA_INTERFACE_DEF(rsa, sign_memory),
	LUA_INTERFACE_DEF(rsa, keypair),
	{NULL, NULL}};

static const struct luaL_reg rsapubkeylib_f[] = {
	LUA_INTERFACE_DEF(rsa_pubkey, load),
	LUA_INTERFACE_DEF(rsa_pubkey, create),
	{NULL, NULL}};

static const struct luaL_reg rsapubkeylib_m[] = {
	{"__tostring", lua_rsa_pubkey_tostring},
	{"__gc", lua_rsa_pubkey_gc},
	{NULL, NULL}};

static const struct luaL_reg rsaprivkeylib_f[] = {
	LUA_INTERFACE_DEF(rsa_privkey, load_file),
	LUA_INTERFACE_DEF(rsa_privkey, load_pem),
	LUA_INTERFACE_DEF(rsa_privkey, load_raw),
	LUA_INTERFACE_DEF(rsa_privkey, load_base64),
	LUA_INTERFACE_DEF(rsa_privkey, create),
	{NULL, NULL}};

static const struct luaL_reg rsaprivkeylib_m[] = {
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_rsa_privkey_gc},
	LUA_INTERFACE_DEF(rsa_privkey, save),
	{NULL, NULL}};

static const struct luaL_reg rsasignlib_f[] = {
	LUA_INTERFACE_DEF(rsa_signature, load),
	LUA_INTERFACE_DEF(rsa_signature, create),
	{NULL, NULL}};

static const struct luaL_reg rsasignlib_m[] = {
	LUA_INTERFACE_DEF(rsa_signature, save),
	LUA_INTERFACE_DEF(rsa_signature, base64),
	{"__tostring", rspamd_lua_class_tostring},
	{"__gc", lua_rsa_signature_gc},
	{NULL, NULL}};

static EVP_PKEY *
lua_check_rsa_pubkey(lua_State *L, int pos)
{
	void *ud = rspamd_lua_check_udata(L, pos, rspamd_rsa_pubkey_classname);

	luaL_argcheck(L, ud != NULL, 1, "'rsa_pubkey' expected");
	return ud ? *((EVP_PKEY **) ud) : NULL;
}

static EVP_PKEY *
lua_check_rsa_privkey(lua_State *L, int pos)
{
	void *ud = rspamd_lua_check_udata(L, pos, rspamd_rsa_privkey_classname);

	luaL_argcheck(L, ud != NULL, 1, "'rsa_privkey' expected");
	return ud ? *((EVP_PKEY **) ud) : NULL;
}

static rspamd_fstring_t *
lua_check_rsa_sign(lua_State *L, int pos)
{
	void *ud = rspamd_lua_check_udata(L, pos, rspamd_rsa_signature_classname);

	luaL_argcheck(L, ud != NULL, 1, "'rsa_signature' expected");
	return ud ? *((rspamd_fstring_t **) ud) : NULL;
}

static int
lua_rsa_pubkey_load(lua_State *L)
{
	EVP_PKEY *pkey = NULL, **ppkey;
	const char *filename;
	FILE *f;

	filename = luaL_checkstring(L, 1);
	if (filename != NULL) {
		f = fopen(filename, "r");
		if (f == NULL) {
			msg_err("cannot open pubkey from file: %s, %s",
					filename,
					strerror(errno));
			lua_pushnil(L);
		}
		else {
			if (!PEM_read_PUBKEY(f, &pkey, NULL, NULL)) {
				msg_err("cannot open pubkey from file: %s, %s", filename,
						ERR_error_string(ERR_get_error(), NULL));
				lua_pushnil(L);
			}
			else {
				ppkey = lua_newuserdata(L, sizeof(EVP_PKEY *));
				rspamd_lua_setclass(L, rspamd_rsa_pubkey_classname, -1);
				*ppkey = pkey;
			}
			fclose(f);
		}
	}
	else {
		lua_pushnil(L);
	}
	return 1;
}

static int
lua_rsa_privkey_save(lua_State *L)
{
	const char *filename;
	const char *type = "pem";
	FILE *f;
	int ret;
	EVP_PKEY *pkey = lua_check_rsa_privkey(L, 1);

	filename = luaL_checkstring(L, 2);
	if (lua_gettop(L) > 2) {
		type = luaL_checkstring(L, 3);
	}

	if (pkey != NULL && filename != NULL) {
		if (strcmp(filename, "-") == 0) {
			f = stdout;
		}
		else {
			f = fopen(filename, "wb");
		}
		if (f == NULL) {
			msg_err("cannot save privkey to file: %s, %s",
					filename,
					strerror(errno));
			lua_pushboolean(L, FALSE);
		}
		else {
			if (f != stdout) {
				/* Set secure permissions for the private key file */
				chmod(filename, S_IRUSR | S_IWUSR);
			}

			if (strcmp(type, "der") == 0) {
				ret = i2d_PrivateKey_fp(f, pkey);
			}
			else {
				ret = PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);
			}

			if (!ret) {
				msg_err("cannot save privkey to file: %s, %s", filename,
						ERR_error_string(ERR_get_error(), NULL));
				lua_pushboolean(L, FALSE);
			}
			else {
				lua_pushboolean(L, TRUE);
			}

			if (f != stdout) {
				fclose(f);
			}
			else {
				fflush(f);
			}
		}
	}
	else {
		lua_pushboolean(L, FALSE);
	}

	return 1;
}


static int
lua_rsa_pubkey_create(lua_State *L)
{
	EVP_PKEY *pkey, **ppkey;
	const char *buf;
	BIO *bp;

	buf = luaL_checkstring(L, 1);
	if (buf != NULL) {
		bp = BIO_new_mem_buf((void *) buf, -1);

		if (!PEM_read_bio_PUBKEY(bp, &pkey, NULL, NULL)) {
			msg_err("cannot parse pubkey: %s",
					ERR_error_string(ERR_get_error(), NULL));
			lua_pushnil(L);
		}
		else {
			ppkey = lua_newuserdata(L, sizeof(EVP_PKEY *));
			rspamd_lua_setclass(L, rspamd_rsa_pubkey_classname, -1);
			*ppkey = pkey;
		}
		BIO_free(bp);
	}
	else {
		lua_pushnil(L);
	}
	return 1;
}

static int
lua_rsa_pubkey_gc(lua_State *L)
{
	EVP_PKEY *pkey = lua_check_rsa_pubkey(L, 1);

	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
	}

	return 0;
}

static int
lua_rsa_pubkey_tostring(lua_State *L)
{
	EVP_PKEY *pkey = lua_check_rsa_pubkey(L, 1);

	if (pkey != NULL) {
		BIO *pubout = BIO_new(BIO_s_mem());
		const char *pubdata;
		gsize publen;
		int rc = i2d_PUBKEY_bio(pubout, pkey);

		if (rc != 1) {
			BIO_free(pubout);

			return luaL_error(L, "i2d_PUBKEY_bio failed");
		}

		publen = BIO_get_mem_data(pubout, &pubdata);
		lua_pushlstring(L, pubdata, publen);
		BIO_free(pubout);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

static int
lua_rsa_privkey_load_file(lua_State *L)
{
	EVP_PKEY *pkey = NULL, **ppkey;
	const char *filename;
	FILE *f;

	filename = luaL_checkstring(L, 1);
	if (filename != NULL) {
		f = fopen(filename, "r");
		if (f == NULL) {
			msg_err("cannot open private key from file: %s, %s",
					filename,
					strerror(errno));
			lua_pushnil(L);
		}
		else {
			if (!PEM_read_PrivateKey(f, &pkey, NULL, NULL)) {
				msg_err("cannot open private key from file: %s, %s", filename,
						ERR_error_string(ERR_get_error(), NULL));
				lua_pushnil(L);
			}
			else {
				ppkey = lua_newuserdata(L, sizeof(EVP_PKEY *));
				rspamd_lua_setclass(L, rspamd_rsa_privkey_classname, -1);
				*ppkey = pkey;
			}
			fclose(f);
		}
	}
	else {
		lua_pushnil(L);
	}
	return 1;
}

static int
lua_rsa_privkey_load_pem(lua_State *L)
{
	EVP_PKEY *pkey = NULL, **ppkey;
	BIO *b;
	struct rspamd_lua_text *t;
	const char *data;
	gsize len;

	if (lua_isuserdata(L, 1)) {
		t = lua_check_text(L, 1);

		if (!t) {
			return luaL_error(L, "invalid arguments");
		}

		data = t->start;
		len = t->len;
	}
	else {
		data = luaL_checklstring(L, 1, &len);
	}

	if (data != NULL) {
		b = BIO_new_mem_buf(data, len);

		if (!PEM_read_bio_PrivateKey(b, &pkey, NULL, NULL)) {
			msg_err("cannot open private key from data, %s",
					ERR_error_string(ERR_get_error(), NULL));
			lua_pushnil(L);
		}
		else {
			ppkey = lua_newuserdata(L, sizeof(EVP_PKEY *));
			rspamd_lua_setclass(L, rspamd_rsa_privkey_classname, -1);
			*ppkey = pkey;
		}

		BIO_free(b);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

static int
lua_rsa_privkey_load_raw(lua_State *L)
{
	EVP_PKEY *pkey = NULL, **ppkey;
	BIO *b;
	struct rspamd_lua_text *t;
	const char *data;
	gsize len;

	if (lua_isuserdata(L, 1)) {
		t = lua_check_text(L, 1);

		if (!t) {
			return luaL_error(L, "invalid arguments");
		}

		data = t->start;
		len = t->len;
	}
	else {
		data = luaL_checklstring(L, 1, &len);
	}

	if (data != NULL) {
		b = BIO_new_mem_buf(data, len);
		pkey = d2i_PrivateKey_bio(b, NULL);

		if (pkey == NULL) {
			msg_err("cannot open private key from data, %s",
					ERR_error_string(ERR_get_error(), NULL));
			lua_pushnil(L);
		}
		else {
			ppkey = lua_newuserdata(L, sizeof(EVP_PKEY *));
			rspamd_lua_setclass(L, rspamd_rsa_privkey_classname, -1);
			*ppkey = pkey;
		}

		BIO_free(b);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

static int
lua_rsa_privkey_load_base64(lua_State *L)
{
	EVP_PKEY *pkey = NULL, **ppkey;
	BIO *b;
	struct rspamd_lua_text *t;
	const char *data;
	unsigned char *decoded;
	gsize len, dec_len;

	if (lua_isuserdata(L, 1)) {
		t = lua_check_text(L, 1);

		if (!t) {
			return luaL_error(L, "invalid arguments");
		}

		data = t->start;
		len = t->len;
	}
	else {
		data = luaL_checklstring(L, 1, &len);
	}

	if (data != NULL) {
		decoded = g_malloc(len);

		if (!rspamd_cryptobox_base64_decode(data, len, decoded, &dec_len)) {
			g_free(decoded);

			return luaL_error(L, "invalid base64 encoding");
		}

		b = BIO_new_mem_buf(decoded, dec_len);

		if (d2i_PrivateKey_bio(b, &pkey) != NULL) {
			if (pkey == NULL) {
				msg_err("cannot open RSA private key from data, %s",
						ERR_error_string(ERR_get_error(), NULL));
				lua_pushnil(L);
			}
			else {
				ppkey = lua_newuserdata(L, sizeof(EVP_PKEY *));
				rspamd_lua_setclass(L, rspamd_rsa_privkey_classname, -1);
				*ppkey = pkey;
			}

		}
		else {
			msg_err("cannot open EVP private key from data, %s",
					ERR_error_string(ERR_get_error(), NULL));
			lua_pushnil(L);
		}

		BIO_free(b);
		g_free(decoded);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

static int
lua_rsa_privkey_create(lua_State *L)
{
	EVP_PKEY *pkey = NULL, **ppkey;
	const char *buf;
	BIO *bp;

	buf = luaL_checkstring(L, 1);
	if (buf != NULL) {
		bp = BIO_new_mem_buf((void *) buf, -1);

		if (!PEM_read_bio_PrivateKey(bp, &pkey, NULL, NULL)) {
			msg_err("cannot parse private key: %s",
					ERR_error_string(ERR_get_error(), NULL));
			lua_pushnil(L);
		}
		else {
			ppkey = lua_newuserdata(L, sizeof(EVP_PKEY *));
			rspamd_lua_setclass(L, rspamd_rsa_privkey_classname, -1);
			*ppkey = pkey;
		}
		BIO_free(bp);
	}
	else {
		lua_pushnil(L);
	}
	return 1;
}

static int
lua_rsa_privkey_gc(lua_State *L)
{
	EVP_PKEY *pkey = lua_check_rsa_privkey(L, 1);

	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
	}

	return 0;
}

static int
lua_rsa_signature_load(lua_State *L)
{
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
				sig = rspamd_fstring_new_init(data, st.st_size);
				psig = lua_newuserdata(L, sizeof(rspamd_fstring_t *));
				rspamd_lua_setclass(L, rspamd_rsa_signature_classname, -1);
				*psig = sig;
				munmap(data, st.st_size);
			}
			close(fd);
		}
	}
	else {
		lua_pushnil(L);
	}
	return 1;
}

static int
lua_rsa_signature_save(lua_State *L)
{
	rspamd_fstring_t *sig;
	int fd, flags;
	const char *filename;
	gboolean forced = FALSE, res = TRUE;

	sig = lua_check_rsa_sign(L, 1);
	filename = luaL_checkstring(L, 2);
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
		lua_pushboolean(L, FALSE);
	}

	return 1;
}

static int
lua_rsa_signature_create(lua_State *L)
{
	rspamd_fstring_t *sig, **psig;
	const char *data;
	gsize dlen;

	data = luaL_checklstring(L, 1, &dlen);
	if (data != NULL) {
		sig = rspamd_fstring_new_init(data, dlen);
		psig = lua_newuserdata(L, sizeof(rspamd_fstring_t *));
		rspamd_lua_setclass(L, rspamd_rsa_signature_classname, -1);
		*psig = sig;
	}

	return 1;
}

static int
lua_rsa_signature_gc(lua_State *L)
{
	rspamd_fstring_t *sig = lua_check_rsa_sign(L, 1);

	rspamd_fstring_free(sig);

	return 0;
}

static int
lua_rsa_signature_base64(lua_State *L)
{
	rspamd_fstring_t *sig = lua_check_rsa_sign(L, 1);
	unsigned int boundary = 0;
	char *b64;
	gsize outlen;
	enum rspamd_newlines_type how = RSPAMD_TASK_NEWLINES_CRLF;

	if (lua_isnumber(L, 2)) {
		boundary = lua_tonumber(L, 2);
	}

	if (lua_isstring(L, 3)) {
		const char *how_str = lua_tostring(L, 3);

		if (strcmp(how_str, "cr") == 0) {
			how = RSPAMD_TASK_NEWLINES_CR;
		}
		else if (strcmp(how_str, "lf") == 0) {
			how = RSPAMD_TASK_NEWLINES_LF;
		}
		else {
			how = RSPAMD_TASK_NEWLINES_CRLF;
		}
	}

	b64 = rspamd_encode_base64_fold(sig->str, sig->len, boundary, &outlen, how);

	if (b64) {
		lua_pushlstring(L, b64, outlen);
		g_free(b64);
	}
	else {
		lua_pushnil(L);
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
static int
lua_rsa_verify_memory(lua_State *L)
{
	EVP_PKEY *pkey;
	rspamd_fstring_t *signature;
	const char *data;
	gsize sz;
	int ret;

	pkey = lua_check_rsa_pubkey(L, 1);
	signature = lua_check_rsa_sign(L, 2);
	data = luaL_checklstring(L, 3, &sz);

	if (pkey != NULL && signature != NULL && data != NULL) {
		EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
  g_assert(pctx != NULL);
  g_assert(EVP_PKEY_verify_init(pctx) == 1);

		ret = EVP_PKEY_verify(pctx, signature->str, signature->len, data, sz);

		if (ret == 0) {
			lua_pushboolean(L, FALSE);
			lua_pushstring(L, ERR_error_string(ERR_get_error(), NULL));

			return 2;
		}
		else {
			lua_pushboolean(L, TRUE);
		}
		EVP_PKEY_CTX_free(pctx);
	}
	else {
		lua_pushnil(L);
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
static int
lua_rsa_sign_memory(lua_State *L)
{
	EVP_PKEY *pkey;
	rspamd_fstring_t *signature, **psig;
	const char *data;
	gsize sz;
	int ret;

	pkey = lua_check_rsa_privkey(L, 1);
	data = luaL_checklstring(L, 2, &sz);

	if (pkey != NULL && data != NULL) {
		signature = rspamd_fstring_sized_new(EVP_PKEY_get_size(pkey));

		EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
		g_assert(pctx != NULL);

		g_assert(EVP_PKEY_sign_init(pctx) == 1);
		size_t slen = signature->allocated;

		ret = EVP_PKEY_sign(pctx, signature->str, &slen, data, sz);
		EVP_PKEY_CTX_free(pctx);
		if (ret != 1) {
			rspamd_fstring_free(signature);

			return luaL_error(L, "cannot sign: %s",
							  ERR_error_string(ERR_get_error(), NULL));
		}
		else {
			signature->len = slen;
			psig = lua_newuserdata(L, sizeof(rspamd_fstring_t *));
			rspamd_lua_setclass(L, rspamd_rsa_signature_classname, -1);
			*psig = signature;
		}
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

static int
lua_rsa_keypair(lua_State *L)
{
	BIGNUM *e;
	EVP_PKEY *pkey = NULL, *pub_pkey, *priv_pkey, **ppkey;
	int bits = lua_gettop(L) > 0 ? lua_tointeger(L, 1) : 1024;

	if (bits > 4096 || bits < 512) {
		return luaL_error(L, "invalid bits count");
	}

	e = BN_new();

	g_assert(BN_set_word(e, RSA_F4) == 1);
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	g_assert(pctx != NULL);
	g_assert(EVP_PKEY_keygen_init(pctx) == 1);

	g_assert(EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, bits) == 1);
	g_assert(EVP_PKEY_CTX_set1_rsa_keygen_pubexp(pctx, e) == 1);

	g_assert(EVP_PKEY_keygen(pctx, &pkey) == 1);
	g_assert(pkey != NULL);

	priv_pkey = EVP_PKEY_dup(pkey);
	ppkey = lua_newuserdata(L, sizeof(EVP_PKEY *));
	rspamd_lua_setclass(L, rspamd_rsa_privkey_classname, -1);
	*ppkey = priv_pkey;

	pub_pkey = EVP_PKEY_dup(pkey);
	ppkey = lua_newuserdata(L, sizeof(EVP_PKEY *));
	rspamd_lua_setclass(L, rspamd_rsa_pubkey_classname, -1);
	*ppkey = pub_pkey;

	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pctx);
	BN_free(e);

	return 2;
}

static int
lua_load_pubkey(lua_State *L)
{
	lua_newtable(L);
	luaL_register(L, NULL, rsapubkeylib_f);

	return 1;
}

static int
lua_load_privkey(lua_State *L)
{
	lua_newtable(L);
	luaL_register(L, NULL, rsaprivkeylib_f);

	return 1;
}

static int
lua_load_signature(lua_State *L)
{
	lua_newtable(L);
	luaL_register(L, NULL, rsasignlib_f);

	return 1;
}

static int
lua_load_rsa(lua_State *L)
{
	lua_newtable(L);
	luaL_register(L, NULL, rsalib_f);

	return 1;
}

void luaopen_rsa(lua_State *L)
{
	rspamd_lua_new_class(L, rspamd_rsa_pubkey_classname, rsapubkeylib_m);
	lua_pop(L, 1);
	rspamd_lua_add_preload(L, "rspamd_rsa_pubkey", lua_load_pubkey);

	rspamd_lua_new_class(L, rspamd_rsa_privkey_classname, rsaprivkeylib_m);
	lua_pop(L, 1);
	rspamd_lua_add_preload(L, "rspamd_rsa_privkey", lua_load_privkey);

	rspamd_lua_new_class(L, rspamd_rsa_signature_classname, rsasignlib_m);
	lua_pop(L, 1);
	rspamd_lua_add_preload(L, "rspamd_rsa_signature", lua_load_signature);

	rspamd_lua_add_preload(L, "rspamd_rsa", lua_load_rsa);

	lua_settop(L, 0);
}
