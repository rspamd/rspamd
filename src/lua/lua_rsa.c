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

LUA_FUNCTION_DEF (rsa_key, load);
LUA_FUNCTION_DEF (rsa_key, create);
LUA_FUNCTION_DEF (rsa_key, gc);
LUA_FUNCTION_DEF (rsa_signature, create);
LUA_FUNCTION_DEF (rsa_signature, load);
LUA_FUNCTION_DEF (rsa_signature, gc);
LUA_FUNCTION_DEF (rsa, check_memory);
LUA_FUNCTION_DEF (rsa, check_file);

static const struct luaL_reg    rsalib_f[] = {
	LUA_INTERFACE_DEF (rsa, check_memory),
	LUA_INTERFACE_DEF (rsa, check_file),
	{NULL, NULL}
};

static const struct luaL_reg rsakeylib_f[] = {
		LUA_INTERFACE_DEF (rsa_key, load),
		LUA_INTERFACE_DEF (rsa_key, create),
		{NULL, NULL}
};

static const struct luaL_reg rsakeylib_m[] = {
		{"__tostring", lua_class_tostring},
		{"__gc", lua_rsa_key_gc},
		{NULL, NULL}
};

static const struct luaL_reg rsasignlib_f[] = {
		LUA_INTERFACE_DEF (rsa_signature, load),
		LUA_INTERFACE_DEF (rsa_signature, create),
		{NULL, NULL}
};

static const struct luaL_reg rsasignlib_m[] = {
		{"__tostring", lua_class_tostring},
		{"__gc", lua_rsa_signature_gc},
		{NULL, NULL}
};

static RSA *
lua_check_rsa_key (lua_State * L, int pos)
{
	void                           *ud = luaL_checkudata (L, pos, "rspamd{rsa_key}");

	luaL_argcheck (L, ud != NULL, 1, "'rsa_key' expected");
	return ud ? *((RSA **)ud) : NULL;
}

static gpointer
lua_check_rsa_sign (lua_State * L, int pos)
{
	void                           *ud = luaL_checkudata (L, pos, "rspamd{rsa_signature}");

	luaL_argcheck (L, ud != NULL, 1, "'rsa_signature' expected");
	return ud ? *((gpointer *)ud) : NULL;
}

static gint
lua_rsa_key_load (lua_State *L)
{
	RSA	*rsa = NULL, **prsa;
	const gchar *filename;
	FILE *f;

	filename = luaL_checkstring (L, 1);
	if (filename != NULL) {
		f = fopen (filename, "r");
		if (f == NULL) {
			msg_err ("cannot open pubkey from file: %s, %s", filename, strerror (errno));
			lua_pushnil (L);
		}
		else {
			if (! PEM_read_RSA_PUBKEY (f, &rsa, NULL, NULL)) {
				msg_err ("cannot open pubkey from file: %s, %s", filename,
						ERR_error_string (ERR_get_error (), NULL));
				lua_pushnil (L);
			}
			else {
				prsa = lua_newuserdata (L, sizeof (RSA *));
				lua_setclass (L, "rspamd{rsa_key}", -1);
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
lua_rsa_key_create (lua_State *L)
{
	RSA	*rsa = NULL, **prsa;
	const gchar *buf;
	BIO *bp;

	buf = luaL_checkstring (L, 1);
	if (buf != NULL) {
		bp = BIO_new_mem_buf ((void *)buf, -1);

		if (! PEM_read_bio_RSA_PUBKEY (bp, &rsa, NULL, NULL)) {
			msg_err ("cannot parse pubkey: %s",
					ERR_error_string (ERR_get_error (), NULL));
			lua_pushnil (L);
		}
		else {
			prsa = lua_newuserdata (L, sizeof (RSA *));
			lua_setclass (L, "rspamd{rsa_key}", -1);
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
lua_rsa_key_gc (lua_State *L)
{
	RSA *rsa = lua_check_rsa_key (L, 1);

	if (rsa != NULL) {
		RSA_free (rsa);
	}

	return 0;
}

static gint
lua_rsa_signature_load (lua_State *L)
{
	gchar *sig, **psig;
	const gchar *filename;
	FILE *f;
	gint siglen;

	siglen = g_checksum_type_get_length (G_CHECKSUM_SHA256);
	filename = luaL_checkstring (L, 1);
	if (filename != NULL) {
		f = fopen (filename, "r");
		if (f == NULL) {
			msg_err ("cannot open signature file: %s, %s", filename, strerror (errno));
			lua_pushnil (L);
		}
		else {
			sig = g_malloc (siglen * 2 + 1);
			if (fread (sig, siglen * 2, 1, f) == 1) {
				sig[siglen * 2] = '\0';
				psig = lua_newuserdata (L, sizeof (gchar *));
				lua_setclass (L, "rspamd{rsa_signature}", -1);
				*psig = sig;
			}
			else {
				msg_err ("cannot read signature file: %s, %s", filename, strerror (errno));
				g_free (sig);
				lua_pushnil (L);
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
lua_rsa_signature_create (lua_State *L)
{
	gchar *sig, **psig;
	const gchar *data;
	guint siglen;

	siglen = g_checksum_type_get_length (G_CHECKSUM_SHA256);
	data = luaL_checkstring (L, 1);
	if (data != NULL) {
		sig = g_malloc (siglen * 2 + 1);
		if (strlen (data) == siglen * 2) {
			memcpy (sig, data, siglen * 2);
			sig[siglen * 2] = '\0';
			psig = lua_newuserdata (L, sizeof (gchar *));
			lua_setclass (L, "rspamd{rsa_signature}", -1);
			*psig = sig;
		}
		else {
			msg_err ("cannot read signature string: %s", data);
			g_free (sig);
			lua_pushnil (L);
		}
	}

	return 1;
}

static gint
lua_rsa_signature_gc (lua_State *L)
{
	gpointer sig = lua_check_rsa_sign (L, 1);

	if (sig != NULL) {
		g_free (sig);
	}

	return 0;
}

/**
 * Check memory using specified rsa key and signature
 *
 * arguments:
 * (rsa_key, rsa_signature, string)
 *
 * returns:
 * true - if string match rsa signature
 * false - otherwise
 */
static gint
lua_rsa_check_memory (lua_State *L)
{
	RSA *rsa;
	gpointer signature;
	const gchar *data;
	gchar *data_sig;
	gint ret, siglen;

	siglen = g_checksum_type_get_length (G_CHECKSUM_SHA256);

	rsa = lua_check_rsa_key (L, 1);
	signature = lua_check_rsa_sign (L, 2);
	data = luaL_checkstring (L, 3);

	if (rsa != NULL && signature != NULL && data != NULL) {
		data_sig = g_compute_checksum_for_string (G_CHECKSUM_SHA256, data, -1);
		ret = RSA_verify (NID_sha1, signature, siglen * 2, data_sig, strlen (data_sig), rsa);
		if (ret == 0) {
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
 * Check memory using specified rsa key and signature
 *
 * arguments:
 * (rsa_key, rsa_signature, string)
 *
 * returns:
 * true - if string match rsa signature
 * false - otherwise
 */
static gint
lua_rsa_check_file (lua_State *L)
{
	RSA *rsa;
	gpointer signature;
	const gchar *filename;
	gchar *data = NULL, *data_sig;
	gint ret, siglen;
	gint fd;
	struct stat st;

	siglen = g_checksum_type_get_length (G_CHECKSUM_SHA256);

	rsa = lua_check_rsa_key (L, 1);
	signature = lua_check_rsa_sign (L, 2);
	filename = luaL_checkstring (L, 3);

	if (rsa != NULL && signature != NULL && data != NULL) {
		fd = open (filename, O_RDONLY);
		if (fd == -1) {
			msg_err ("cannot open file %s: %s", filename, strerror (errno));
			lua_pushnil (L);
		}
		else {
			if (fstat (fd, &st) == -1 ||
					(data = mmap (NULL,  st.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
				msg_err ("cannot mmap file %s: %s", filename, strerror (errno));
				lua_pushnil (L);
			}
			else {
				data_sig = g_compute_checksum_for_data (G_CHECKSUM_SHA256, data, st.st_size);
				ret = RSA_verify (NID_sha1, signature, siglen * 2, data_sig, strlen (data_sig), rsa);
				if (ret == 0) {
					lua_pushboolean (L, FALSE);
				}
				else {
					lua_pushboolean (L, TRUE);
				}
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
	luaL_newmetatable (L, "rspamd{rsa_key}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{rsa_key}");
	lua_rawset (L, -3);

	luaL_register (L, NULL, rsakeylib_m);
	luaL_register (L, "rsa_key", rsakeylib_f);

	luaL_newmetatable (L, "rspamd{rsa_signature}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{rsa_signature}");
	lua_rawset (L, -3);

	luaL_register (L, NULL, rsasignlib_m);
	luaL_register (L, "rsa_signature", rsasignlib_f);

	luaL_register (L, "rsa", rsalib_f);

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
