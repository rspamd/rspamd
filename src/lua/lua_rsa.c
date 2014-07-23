/* Copyright (c) 2013, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


/**
 * @file lua_rsa.c
 * This module exports routines to load rsa keys, check inline or external
 * rsa signatures. It assumes sha256 based signatures.
 */

#include "lua_common.h"

#ifdef HAVE_OPENSSL
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

LUA_FUNCTION_DEF (rsa_pubkey,	 load);
LUA_FUNCTION_DEF (rsa_pubkey,	 create);
LUA_FUNCTION_DEF (rsa_pubkey,	 gc);
LUA_FUNCTION_DEF (rsa_privkey,	 load);
LUA_FUNCTION_DEF (rsa_privkey,	 create);
LUA_FUNCTION_DEF (rsa_privkey,	 gc);
LUA_FUNCTION_DEF (rsa_signature, create);
LUA_FUNCTION_DEF (rsa_signature, load);
LUA_FUNCTION_DEF (rsa_signature, save);
LUA_FUNCTION_DEF (rsa_signature, gc);
LUA_FUNCTION_DEF (rsa,			 verify_memory);
LUA_FUNCTION_DEF (rsa,			 verify_file);
LUA_FUNCTION_DEF (rsa,			 sign_file);
LUA_FUNCTION_DEF (rsa,			 sign_memory);

static const struct luaL_reg rsalib_f[] = {
	LUA_INTERFACE_DEF (rsa, verify_memory),
	LUA_INTERFACE_DEF (rsa, verify_file),
	LUA_INTERFACE_DEF (rsa, sign_memory),
	LUA_INTERFACE_DEF (rsa, sign_file),
	{NULL, NULL}
};

static const struct luaL_reg rsapubkeylib_f[] = {
	LUA_INTERFACE_DEF (rsa_pubkey, load),
	LUA_INTERFACE_DEF (rsa_pubkey, create),
	{NULL, NULL}
};

static const struct luaL_reg rsapubkeylib_m[] = {
	{"__tostring", lua_class_tostring},
	{"__gc", lua_rsa_pubkey_gc},
	{NULL, NULL}
};

static const struct luaL_reg rsaprivkeylib_f[] = {
	LUA_INTERFACE_DEF (rsa_privkey, load),
	LUA_INTERFACE_DEF (rsa_privkey, create),
	{NULL, NULL}
};

static const struct luaL_reg rsaprivkeylib_m[] = {
	{"__tostring", lua_class_tostring},
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
	{"__tostring", lua_class_tostring},
	{"__gc", lua_rsa_signature_gc},
	{NULL, NULL}
};

static RSA *
lua_check_rsa_pubkey (lua_State * L, int pos)
{
	void *ud = luaL_checkudata (L, pos, "rspamd{rsa_pubkey}");

	luaL_argcheck (L, ud != NULL, 1, "'rsa_pubkey' expected");
	return ud ? *((RSA **)ud) : NULL;
}

static RSA *
lua_check_rsa_privkey (lua_State * L, int pos)
{
	void *ud = luaL_checkudata (L, pos, "rspamd{rsa_privkey}");

	luaL_argcheck (L, ud != NULL, 1, "'rsa_privkey' expected");
	return ud ? *((RSA **)ud) : NULL;
}

static f_str_t *
lua_check_rsa_sign (lua_State * L, int pos)
{
	void *ud = luaL_checkudata (L, pos, "rspamd{rsa_signature}");

	luaL_argcheck (L, ud != NULL, 1, "'rsa_signature' expected");
	return ud ? *((f_str_t **)ud) : NULL;
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
				lua_setclass (L, "rspamd{rsa_pubkey}", -1);
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
			lua_setclass (L, "rspamd{rsa_pubkey}", -1);
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
lua_rsa_privkey_load (lua_State *L)
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
				lua_setclass (L, "rspamd{rsa_privkey}", -1);
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
			lua_setclass (L, "rspamd{rsa_privkey}", -1);
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
	f_str_t *sig, **psig;
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
			sig = g_malloc (sizeof (f_str_t));
			if (fstat (fd, &st) == -1 ||
				(data =
				mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd,
				0)) == MAP_FAILED) {
				msg_err ("cannot mmap file %s: %s", filename, strerror (errno));
				lua_pushnil (L);
			}
			else {
				sig->size = st.st_size;
				sig->len = sig->size;
				sig->begin = g_malloc (sig->len);
				memcpy (sig->begin, data, sig->len);
				psig = lua_newuserdata (L, sizeof (f_str_t *));
				lua_setclass (L, "rspamd{rsa_signature}", -1);
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
	f_str_t *sig;
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
			while (write (fd, sig->begin, sig->len) == -1) {
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
	f_str_t *sig, **psig;
	const gchar *data;

	data = luaL_checkstring (L, 1);
	if (data != NULL) {
		sig = g_malloc (sizeof (f_str_t));
		sig->len = strlen (data);
		sig->size = sig->len;
		sig->begin = g_malloc (sig->len);
		memcpy (sig->begin, data, sig->len);
		psig = lua_newuserdata (L, sizeof (f_str_t *));
		lua_setclass (L, "rspamd{rsa_signature}", -1);
		*psig = sig;
	}

	return 1;
}

static gint
lua_rsa_signature_gc (lua_State *L)
{
	f_str_t *sig = lua_check_rsa_sign (L, 1);

	if (sig != NULL) {
		if (sig->begin != NULL) {
			g_free (sig->begin);
		}
		g_free (sig);
	}

	return 0;
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
	f_str_t *signature;
	const gchar *data;
	gchar *data_sig;
	gint ret;

	rsa = lua_check_rsa_pubkey (L, 1);
	signature = lua_check_rsa_sign (L, 2);
	data = luaL_checkstring (L, 3);

	if (rsa != NULL && signature != NULL && data != NULL) {
		data_sig = g_compute_checksum_for_string (G_CHECKSUM_SHA256, data, -1);
		ret = RSA_verify (NID_sha1, data_sig, strlen (data_sig),
				signature->begin, signature->len, rsa);
		if (ret == 0) {
			msg_info ("cannot check rsa signature for data: %s",
				ERR_error_string (ERR_get_error (), NULL));
			lua_pushboolean (L, FALSE);
		}
		else {
			lua_pushboolean (L, TRUE);
		}
		g_free (data_sig);
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
lua_rsa_verify_file (lua_State *L)
{
	RSA *rsa;
	f_str_t *signature;
	const gchar *filename;
	gchar *data = NULL, *data_sig;
	gint ret, fd;
	struct stat st;

	rsa = lua_check_rsa_pubkey (L, 1);
	signature = lua_check_rsa_sign (L, 2);
	filename = luaL_checkstring (L, 3);

	if (rsa != NULL && signature != NULL && filename != NULL) {
		fd = open (filename, O_RDONLY);
		if (fd == -1) {
			msg_err ("cannot open file %s: %s", filename, strerror (errno));
			lua_pushnil (L);
		}
		else {
			if (fstat (fd, &st) == -1 ||
				(data =
				mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd,
				0)) == MAP_FAILED) {
				msg_err ("cannot mmap file %s: %s", filename, strerror (errno));
				lua_pushnil (L);
			}
			else {
				data_sig = g_compute_checksum_for_data (G_CHECKSUM_SHA256,
						data,
						st.st_size);
				ret = RSA_verify (NID_sha1, data_sig, strlen (data_sig),
						signature->begin, signature->len, rsa);
				if (ret == 0) {
					msg_info ("cannot check rsa signature for file: %s, %s",
						filename, ERR_error_string (ERR_get_error (), NULL));
					lua_pushboolean (L, FALSE);
				}
				else {
					lua_pushboolean (L, TRUE);
				}
				g_free (data_sig);
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
	f_str_t *signature, **psig;
	const gchar *data;
	gchar *data_sig;
	gint ret;

	rsa = lua_check_rsa_privkey (L, 1);
	data = luaL_checkstring (L, 2);

	if (rsa != NULL && data != NULL) {
		signature = g_malloc (sizeof (f_str_t));
		signature->len = RSA_size (rsa);
		signature->size = signature->len;
		signature->begin = g_malloc (signature->len);
		data_sig = g_compute_checksum_for_string (G_CHECKSUM_SHA256, data, -1);
		ret = RSA_sign (NID_sha1, data_sig, strlen (data_sig),
				signature->begin, (guint *)&signature->len, rsa);
		if (ret == 0) {
			msg_info ("cannot make a signature for data: %s",
				ERR_error_string (ERR_get_error (), NULL));
			lua_pushnil (L);
			g_free (signature->begin);
			g_free (signature);
		}
		else {
			psig = lua_newuserdata (L, sizeof (f_str_t *));
			lua_setclass (L, "rspamd{rsa_signature}", -1);
			*psig = signature;
		}
		g_free (data_sig);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/**
 * Sign file using specified rsa key and signature
 *
 * arguments:
 * (rsa_privkey, rsa_signature, string)
 *
 * returns:
 * true - if string match rsa signature
 * false - otherwise
 */
static gint
lua_rsa_sign_file (lua_State *L)
{
	RSA *rsa;
	f_str_t *signature, **psig;
	const gchar *filename;
	gchar *data = NULL, *data_sig;
	gint ret, fd;
	struct stat st;

	rsa = lua_check_rsa_privkey (L, 1);
	filename = luaL_checkstring (L, 2);

	if (rsa != NULL && filename != NULL) {
		fd = open (filename, O_RDONLY);
		if (fd == -1) {
			msg_err ("cannot open file %s: %s", filename, strerror (errno));
			lua_pushnil (L);
		}
		else {
			if (fstat (fd, &st) == -1 ||
				(data =
				mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd,
				0)) == MAP_FAILED) {
				msg_err ("cannot mmap file %s: %s", filename, strerror (errno));
				lua_pushnil (L);
			}
			else {
				signature = g_malloc (sizeof (f_str_t));
				signature->len = RSA_size (rsa);
				signature->size = signature->len;
				signature->begin = g_malloc (signature->len);
				data_sig = g_compute_checksum_for_string (G_CHECKSUM_SHA256,
						data,
						st.st_size);
				ret = RSA_sign (NID_sha1, data_sig, strlen (data_sig),
						signature->begin, (guint *)&signature->len, rsa);
				if (ret == 0) {
					msg_info ("cannot make a signature for data: %s",
						ERR_error_string (ERR_get_error (), NULL));
					lua_pushnil (L);
					g_free (signature->begin);
					g_free (signature);
				}
				else {
					psig = lua_newuserdata (L, sizeof (f_str_t *));
					lua_setclass (L, "rspamd{rsa_signature}", -1);
					*psig = signature;
				}
				g_free (data_sig);
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

gint
luaopen_rsa (lua_State * L)
{
	luaL_newmetatable (L, "rspamd{rsa_pubkey}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{rsa_pubkey}");
	lua_rawset (L, -3);

	luaL_register (L, NULL,			rsapubkeylib_m);
	luaL_register (L, "rsa_pubkey", rsapubkeylib_f);

	luaL_newmetatable (L, "rspamd{rsa_privkey}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{rsa_privkey}");
	lua_rawset (L, -3);

	luaL_register (L, NULL,			 rsaprivkeylib_m);
	luaL_register (L, "rsa_privkey", rsaprivkeylib_f);

	luaL_newmetatable (L, "rspamd{rsa_signature}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{rsa_signature}");
	lua_rawset (L, -3);

	luaL_register (L, NULL,			   rsasignlib_m);
	luaL_register (L, "rsa_signature", rsasignlib_f);

	luaL_register (L, "rsa",			   rsalib_f);

	return 1;
}

#else
gint
luaopen_rsa (lua_State * L)
{
	msg_info ("this rspamd version is not linked against openssl, therefore no "
		"RSA support is available");

	return 1;

}
#endif
