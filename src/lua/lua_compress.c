/*-
 * Copyright 2021 Vsevolod Stakhov
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

#include "lua_common.h"
#include "unix-std.h"
#include <zlib.h>

#ifdef SYS_ZSTD
#  include "zstd.h"
#  include "zstd_errors.h"
#else
#  include "contrib/zstd/zstd.h"
#  include "contrib/zstd/error_public.h"
#endif

/***
 * @module rspamd_compress
 * This module contains compression/decompression routines (zstd and zlib currently)
 */

/***
 * @function zstd.compress_ctx()
 * Creates new compression ctx
 * @return {compress_ctx} new compress ctx
 */
LUA_FUNCTION_DEF (zstd, compress_ctx);

/***
 * @function zstd.compress_ctx()
 * Creates new compression ctx
 * @return {compress_ctx} new compress ctx
 */
LUA_FUNCTION_DEF (zstd, decompress_ctx);

LUA_FUNCTION_DEF (zstd_compress, stream);
LUA_FUNCTION_DEF (zstd_compress, dtor);

LUA_FUNCTION_DEF (zstd_decompress, stream);
LUA_FUNCTION_DEF (zstd_decompress, dtor);

static const struct luaL_reg zstd_compress_lib_f[] = {
		LUA_INTERFACE_DEF (zstd, compress_ctx),
		LUA_INTERFACE_DEF (zstd, decompress_ctx),
		{NULL, NULL}
};

static const struct luaL_reg zstd_compress_lib_m[] = {
		LUA_INTERFACE_DEF (zstd_compress, stream),
		{"__gc", lua_zstd_compress_dtor},
		{NULL, NULL}
};

static const struct luaL_reg zstd_decompress_lib_m[] = {
		LUA_INTERFACE_DEF (zstd_decompress, stream),
		{"__gc", lua_zstd_decompress_dtor},
		{NULL, NULL}
};

static ZSTD_CStream *
lua_check_zstd_compress_ctx (lua_State *L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{zstd_compress}");
	luaL_argcheck (L, ud != NULL, pos, "'zstd_compress' expected");
	return ud ? *(ZSTD_CStream **)ud : NULL;
}

static ZSTD_DStream *
lua_check_zstd_decompress_ctx (lua_State *L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{zstd_decompress}");
	luaL_argcheck (L, ud != NULL, pos, "'zstd_decompress' expected");
	return ud ? *(ZSTD_DStream **)ud : NULL;
}

int
lua_zstd_push_error (lua_State *L, int err)
{
	lua_pushnil (L);
	lua_pushfstring (L, "zstd error %d (%s)", err, ZSTD_getErrorString (err));

	return 2;
}

gint
lua_compress_zstd_compress (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t = NULL, *res;
	gsize sz, r;
	gint comp_level = 1;

	t = lua_check_text_or_string (L,1);

	if (t == NULL || t->start == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (lua_type (L, 2) == LUA_TNUMBER) {
		comp_level = lua_tointeger (L, 2);
	}

	sz = ZSTD_compressBound (t->len);

	if (ZSTD_isError (sz)) {
		msg_err ("cannot compress data: %s", ZSTD_getErrorName (sz));
		lua_pushnil (L);

		return 1;
	}

	res = lua_newuserdata (L, sizeof (*res));
	res->start = g_malloc (sz);
	res->flags = RSPAMD_TEXT_FLAG_OWN;
	rspamd_lua_setclass (L, "rspamd{text}", -1);
	r = ZSTD_compress ((void *)res->start, sz, t->start, t->len, comp_level);

	if (ZSTD_isError (r)) {
		msg_err ("cannot compress data: %s", ZSTD_getErrorName (r));
		lua_pop (L, 1); /* Text will be freed here */
		lua_pushnil (L);

		return 1;
	}

	res->len = r;

	return 1;
}

gint
lua_compress_zstd_decompress (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t = NULL, *res;
	gsize outlen, r;
	ZSTD_DStream *zstream;
	ZSTD_inBuffer zin;
	ZSTD_outBuffer zout;
	gchar *out;

	t = lua_check_text_or_string (L,1);

	if (t == NULL || t->start == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	zstream = ZSTD_createDStream ();
	ZSTD_initDStream (zstream);

	zin.pos = 0;
	zin.src = t->start;
	zin.size = t->len;

	if ((outlen = ZSTD_getDecompressedSize (zin.src, zin.size)) == 0) {
		outlen = ZSTD_DStreamOutSize ();
	}

	out = g_malloc (outlen);

	zout.dst = out;
	zout.pos = 0;
	zout.size = outlen;

	while (zin.pos < zin.size) {
		r = ZSTD_decompressStream (zstream, &zout, &zin);

		if (ZSTD_isError (r)) {
			msg_err ("cannot decompress data: %s", ZSTD_getErrorName (r));
			ZSTD_freeDStream (zstream);
			g_free (out);
			lua_pushstring (L, ZSTD_getErrorName (r));
			lua_pushnil (L);

			return 2;
		}

		if (zin.pos < zin.size && zout.pos == zout.size) {
			/* We need to extend output buffer */
			zout.size = zout.size * 2;
			out = g_realloc (zout.dst, zout.size);
			zout.dst = out;
		}
	}

	ZSTD_freeDStream (zstream);
	lua_pushnil (L); /* Error */
	res = lua_newuserdata (L, sizeof (*res));
	res->start = out;
	res->flags = RSPAMD_TEXT_FLAG_OWN;
	rspamd_lua_setclass (L, "rspamd{text}", -1);
	res->len = zout.pos;

	return 2;
}

gint
lua_compress_zlib_decompress (lua_State *L, bool is_gzip)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t = NULL, *res;
	gsize sz;
	z_stream strm;
	gint rc;
	guchar *p;
	gsize remain;
	gssize size_limit = -1;

	int windowBits = is_gzip ? (MAX_WBITS + 16) : (MAX_WBITS);

	t = lua_check_text_or_string (L,1);

	if (t == NULL || t->start == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (lua_type (L, 2) == LUA_TNUMBER) {
		size_limit = lua_tointeger (L, 2);
		if (size_limit <= 0) {
			return luaL_error (L, "invalid arguments (size_limit)");
		}

		sz = MIN (t->len * 2, size_limit);
	}
	else {
		sz = t->len * 2;
	}

	memset (&strm, 0, sizeof (strm));
	/* windowBits +16 to decode gzip, zlib 1.2.0.4+ */

	/* Here are dragons to distinguish between raw deflate and zlib */
	if (windowBits == MAX_WBITS && t->len > 0) {
		if ((int)(unsigned char)((t->start[0] << 4)) != 0x80) {
			/* Assume raw deflate */
			windowBits = -windowBits;
		}
	}

	rc = inflateInit2 (&strm, windowBits);

	if (rc != Z_OK) {
		return luaL_error (L, "cannot init zlib");
	}

	strm.avail_in = t->len;
	strm.next_in = (guchar *)t->start;

	res = lua_newuserdata (L, sizeof (*res));
	res->start = g_malloc (sz);
	res->flags = RSPAMD_TEXT_FLAG_OWN;
	rspamd_lua_setclass (L, "rspamd{text}", -1);

	p = (guchar *)res->start;
	remain = sz;

	while (strm.avail_in != 0) {
		strm.avail_out = remain;
		strm.next_out = p;

		rc = inflate (&strm, Z_NO_FLUSH);

		if (rc != Z_OK && rc != Z_BUF_ERROR) {
			if (rc == Z_STREAM_END) {
				break;
			}
			else {
				msg_err ("cannot decompress data: %s (last error: %s)",
						zError (rc), strm.msg);
				lua_pop (L, 1); /* Text will be freed here */
				lua_pushnil (L);
				inflateEnd (&strm);

				return 1;
			}
		}

		res->len = strm.total_out;

		if (strm.avail_out == 0 && strm.avail_in != 0) {

			if (size_limit > 0 || res->len >= G_MAXUINT32 / 2) {
				if (res->len > size_limit || res->len >= G_MAXUINT32 / 2) {
					lua_pop (L, 1); /* Text will be freed here */
					lua_pushnil (L);
					inflateEnd (&strm);

					return 1;
				}
			}

			/* Need to allocate more */
			remain = res->len;
			res->start = g_realloc ((gpointer)res->start, res->len * 2);
			sz = res->len * 2;
			p = (guchar *)res->start + remain;
			remain = sz - remain;
		}
	}

	inflateEnd (&strm);
	res->len = strm.total_out;

	return 1;
}

gint
lua_compress_zlib_compress (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t = NULL, *res;
	gsize sz;
	z_stream strm;
	gint rc, comp_level = Z_DEFAULT_COMPRESSION;
	guchar *p;
	gsize remain;

	t = lua_check_text_or_string (L,1);

	if (t == NULL || t->start == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (lua_isnumber (L, 2)) {
		comp_level = lua_tointeger (L, 2);

		if (comp_level > Z_BEST_COMPRESSION || comp_level < Z_BEST_SPEED) {
			return luaL_error (L, "invalid arguments: compression level must be between %d and %d",
					Z_BEST_SPEED, Z_BEST_COMPRESSION);
		}
	}


	memset (&strm, 0, sizeof (strm));
	rc = deflateInit2 (&strm, comp_level, Z_DEFLATED,
			MAX_WBITS + 16, MAX_MEM_LEVEL - 1, Z_DEFAULT_STRATEGY);

	if (rc != Z_OK) {
		return luaL_error (L, "cannot init zlib: %s", zError (rc));
	}

	sz = deflateBound (&strm, t->len);

	strm.avail_in = t->len;
	strm.next_in = (guchar *) t->start;

	res = lua_newuserdata (L, sizeof (*res));
	res->start = g_malloc (sz);
	res->flags = RSPAMD_TEXT_FLAG_OWN;
	rspamd_lua_setclass (L, "rspamd{text}", -1);

	p = (guchar *) res->start;
	remain = sz;

	while (strm.avail_in != 0) {
		strm.avail_out = remain;
		strm.next_out = p;

		rc = deflate (&strm, Z_FINISH);

		if (rc != Z_OK && rc != Z_BUF_ERROR) {
			if (rc == Z_STREAM_END) {
				break;
			}
			else {
				msg_err ("cannot compress data: %s (last error: %s)",
						zError (rc), strm.msg);
				lua_pop (L, 1); /* Text will be freed here */
				lua_pushnil (L);
				deflateEnd (&strm);

				return 1;
			}
		}

		res->len = strm.total_out;

		if (strm.avail_out == 0 && strm.avail_in != 0) {
			/* Need to allocate more */
			remain = res->len;
			res->start = g_realloc ((gpointer) res->start, strm.avail_in + sz);
			sz = strm.avail_in + sz;
			p = (guchar *) res->start + remain;
			remain = sz - remain;
		}
	}

	deflateEnd (&strm);
	res->len = strm.total_out;

	return 1;
}

/* Stream API interface for Zstd: both compression and decompression */

/* Operations allowed by zstd stream methods */
static const char *const zstd_stream_op[] = {
		"continue",
		"flush",
		"end",
		NULL
};

static gint
lua_zstd_compress_ctx (lua_State *L)
{
	ZSTD_CCtx *ctx, **pctx;

	pctx = lua_newuserdata (L, sizeof (*pctx));
	ctx = ZSTD_createCCtx ();

	if (!ctx) {
		return luaL_error (L, "context create failed");
	}

	*pctx = ctx;
	rspamd_lua_setclass (L, "rspamd{zstd_compress}", -1);
	return 1;
}

static gint
lua_zstd_compress_dtor (lua_State *L)
{
	ZSTD_CCtx *ctx = lua_check_zstd_compress_ctx (L, 1);

	if (ctx) {
		ZSTD_freeCCtx (ctx);
	}

	return 0;
}

static gint
lua_zstd_compress_reset (lua_State *L)
{
	ZSTD_CCtx *ctx = lua_check_zstd_compress_ctx (L, 1);

	if (ctx) {
		ZSTD_CCtx_reset (ctx, ZSTD_reset_session_and_parameters);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_zstd_compress_stream (lua_State *L)
{
	ZSTD_CStream *ctx = lua_check_zstd_compress_ctx (L, 1);
	struct rspamd_lua_text *t = lua_check_text_or_string (L, 2);
	int op = luaL_checkoption (L, 3, zstd_stream_op[0], zstd_stream_op);
	int err = 0;
	ZSTD_inBuffer inb;
	ZSTD_outBuffer onb;

	if (ctx && t) {
		gsize dlen = 0;

		inb.size = t->len;
		inb.pos = 0;
		inb.src = (const void*)t->start;

		onb.pos = 0;
		onb.size = ZSTD_CStreamInSize (); /* Initial guess */
		onb.dst = NULL;

		for (;;) {
			if ((onb.dst = g_realloc (onb.dst, onb.size)) == NULL) {
				return lua_zstd_push_error (L, ZSTD_error_memory_allocation);
			}

			dlen = onb.size;

			int res = ZSTD_compressStream2 (ctx, &onb, &inb, op);

			if (res == 0) {
				/* All done */
				break;
			}

			if ((err = ZSTD_getErrorCode (res))) {
				break;
			}

			onb.size *= 2;
			res += dlen; /* Hint returned by compression routine */

			/* Either double the buffer, or use the hint provided */
			if (onb.size < res) {
				onb.size = res;
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	if (err) {
		return lua_zstd_push_error (L, err);
	}

	lua_new_text (L, onb.dst, onb.pos, TRUE);

	return 1;
}

static gint
lua_zstd_decompress_dtor (lua_State *L)
{
	ZSTD_DStream *ctx = lua_check_zstd_decompress_ctx (L, 1);

	if (ctx) {
		ZSTD_freeDStream (ctx);
	}

	return 0;
}


static gint
lua_zstd_decompress_ctx (lua_State *L)
{
	ZSTD_DStream *ctx, **pctx;

	pctx = lua_newuserdata (L, sizeof (*pctx));
	ctx = ZSTD_createDStream ();

	if (!ctx) {
		return luaL_error (L, "context create failed");
	}

	*pctx = ctx;
	rspamd_lua_setclass (L, "rspamd{zstd_decompress}", -1);
	return 1;
}

static gint
lua_zstd_decompress_stream (lua_State *L)
{
	ZSTD_DStream *ctx = lua_check_zstd_decompress_ctx (L, 1);
	struct rspamd_lua_text *t = lua_check_text_or_string (L, 2);
	int err = 0;
	ZSTD_inBuffer inb;
	ZSTD_outBuffer onb;

	if (ctx && t) {
		gsize dlen = 0;

		if (t->len == 0) {
			return lua_zstd_push_error (L, ZSTD_error_init_missing);
		}

		inb.size = t->len;
		inb.pos = 0;
		inb.src = (const void*)t->start;

		onb.pos = 0;
		onb.size = ZSTD_DStreamInSize (); /* Initial guess */
		onb.dst = NULL;

		for (;;) {
			if ((onb.dst = g_realloc (onb.dst, onb.size)) == NULL) {
				return lua_zstd_push_error (L, ZSTD_error_memory_allocation);
			}

			dlen = onb.size;

			int res = ZSTD_decompressStream (ctx, &onb, &inb);

			if (res == 0) {
				/* All done */
				break;
			}

			if ((err = ZSTD_getErrorCode (res))) {
				break;
			}

			onb.size *= 2;
			res += dlen; /* Hint returned by compression routine */

			/* Either double the buffer, or use the hint provided */
			if (onb.size < res) {
				onb.size = res;
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	if (err) {
		return lua_zstd_push_error (L, err);
	}

	lua_new_text (L, onb.dst, onb.pos, TRUE);

	return 1;
}

static gint
lua_load_zstd (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, zstd_compress_lib_f);

	return 1;
}

void
luaopen_compress (lua_State *L)
{
	rspamd_lua_new_class (L, "rspamd{zstd_compress}", zstd_compress_lib_m);
	rspamd_lua_new_class (L, "rspamd{zstd_decompress}", zstd_decompress_lib_m);
	lua_pop (L, 2);

	rspamd_lua_add_preload (L, "rspamd_zstd", lua_load_zstd);
}
