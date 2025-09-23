/*
 * Copyright 2025 Vsevolod Stakhov
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

#include "lua_common.h"
#include "unix-std.h"

#include <archive.h>
#include <archive_entry.h>

/***
 * @module archive
 * Libarchive bindings for packing and unpacking archives in memory.
 */

/***
 * @function archive.pack(format, files[, options])
 * Packs a list of files into an in-memory archive using libarchive.
 *
 * @param {string} format archive format name (typical: "zip", "tar", "7zip")
 * @param {table} files array of tables: { name = string, content = string|rspamd_text, [mode|perms] = int, [mtime] = int }
 * @param {table} options optional table configuring filters and format behavior
 *  - filters: string or array of strings; compression filters to apply (e.g. "gzip", "xz", "zstd", "bzip2")
 *  - password: string passphrase for encrypted formats (ZIP only here)
 *  - format_options: table of format-specific options (alternatively, a nested table named after the format, e.g. options.zip = {...})
 *
 * ZIP-specific options (via options.format_options or options.zip):
 *  - encryption: "traditional" (aka "zipcrypt"), "aes128", or "aes256"
 *  - compression: "store" | "deflate"
 *  - compression-level: integer 0..9 (0 implies "store")
 *  - zip64: boolean (true to force Zip64; use with care)
 *  - hdrcharset: character set name for filenames
 *  - experimental, fakecrc32: booleans (testing only; not recommended for production)
 *
 * Notes:
 *  - If options.password is set and encryption is omitted, you can specify it explicitly as shown below.
 *  - For a complete list of libarchive ZIP options, consult libarchive documentation.
 *
 * @return {text} archive bytes
 *
 * @example -- Plain ZIP
 * local blob = archive.pack("zip", {
 *   { name = "a.txt", content = "Hello" },
 * })
 *
 * @example -- ZIP with ZipCrypto (traditional)
 * local blob = archive.pack("zip", files, { password = "secret", zip = { encryption = "traditional" } })
 *
 * @example -- ZIP with AES-128
 * local blob = archive.pack("zip", files, { password = "secret", format_options = { encryption = "aes128" } })
 *
 * @example -- TAR.GZ
 * local blob = archive.pack("tar", files, { filters = "gzip" })
 */

LUA_FUNCTION_DEF(archive, pack);
/***
 * @function archive.unpack(data[, format])
 * Unpacks an archive from a Lua string (or rspamd_text) using libarchive.
 * @param {string|text} data archive contents
 * @param {string} format optional format name to restrict autodetection (e.g. "zip")
 * @return {table} array of files: { name = string, content = string } (non-regular entries are skipped)
 */
LUA_FUNCTION_DEF(archive, unpack);
/***
 * @function archive.supported_formats()
 * Returns a table describing runtime-supported formats and filters.
 * @return {table} { formats = { read = {...}, write = {...} }, filters = { read = {...}, write = {...} } }
 */
LUA_FUNCTION_DEF(archive, supported_formats);
/***
 * @function archive.zip(files)
 * Create a ZIP archive from a list of files.
 * @param {table} files array of tables: { name = string, content = string|rspamd_text, [mode|perms] = int, [mtime] = int }
 * @return {text} archive bytes
 */
LUA_FUNCTION_DEF(archive, zip);
LUA_FUNCTION_DEF(archive, zip_encrypt);
/***
 * @function archive.unzip(data)
 * Extract files from a ZIP archive.
 * @param {string|text} data archive contents
 * @return {table} array of files: { name = string, content = text }
 */
LUA_FUNCTION_DEF(archive, unzip);
/***
 * @function archive.tar(files[, compression])
 * Create a TAR archive from a list of files, with optional compression.
 * Supported compression: "gz", "xz", "zstd", "bz2".
 * @param {table} files array of tables: { name = string, content = string|rspamd_text, [mode|perms] = int, [mtime] = int }
 * @param {string} compression optional compression short name
 * @return {text} archive bytes
 */
LUA_FUNCTION_DEF(archive, tar);
/***
 * @function archive.untar(data)
 * Extract files from a TAR archive. Compression is auto-detected (gz/xz/zstd/bz2/...).
 * @param {string|text} data archive contents
 * @return {table} array of files: { name = string, content = text }
 */
LUA_FUNCTION_DEF(archive, untar);
LUA_FUNCTION_DEF(archive, zip);
LUA_FUNCTION_DEF(archive, unzip);
LUA_FUNCTION_DEF(archive, tar);
LUA_FUNCTION_DEF(archive, untar);

static const struct luaL_reg arch_mod_f[] = {
	LUA_INTERFACE_DEF(archive, pack),
	LUA_INTERFACE_DEF(archive, unpack),
	LUA_INTERFACE_DEF(archive, supported_formats),
	LUA_INTERFACE_DEF(archive, zip),
	LUA_INTERFACE_DEF(archive, zip_encrypt),
	LUA_INTERFACE_DEF(archive, unzip),
	LUA_INTERFACE_DEF(archive, tar),
	LUA_INTERFACE_DEF(archive, untar),
	{NULL, NULL}};

struct rspamd_archive_buf {
	GByteArray *buf;
};

static int
lua_archive_write_open(struct archive *a, void *cd)
{
	(void) a;
	(void) cd;
	return ARCHIVE_OK;
}

static la_ssize_t
lua_archive_write_cb(struct archive *a, void *cd, const void *buff, size_t len)
{
	(void) a;
	struct rspamd_archive_buf *ctx = (struct rspamd_archive_buf *) cd;

	if (len > 0) {
		g_byte_array_append(ctx->buf, (const guint8 *) buff, len);
	}

	return (la_ssize_t) len;
}

static int
lua_archive_write_close(struct archive *a, void *cd)
{
	(void) a;
	(void) cd;

	return ARCHIVE_OK;
}

static gboolean
lua_archive_add_filters(lua_State *L, struct archive *a, int opts_idx)
{
	gboolean ok = TRUE;

	if (opts_idx <= 0 || !lua_istable(L, opts_idx)) {
		return ok;
	}

	lua_getfield(L, opts_idx, "filters");

	if (lua_isstring(L, -1)) {
		const char *fltr = lua_tostring(L, -1);
		int r = archive_write_add_filter_by_name(a, fltr);

		if (r != ARCHIVE_OK && r != ARCHIVE_WARN) {
			ok = FALSE;
		}
	}
	else if (lua_istable(L, -1)) {
		lua_pushnil(L);

		while (lua_next(L, -2)) {
			const char *fltr = lua_tostring(L, -1);
			if (fltr) {
				int r = archive_write_add_filter_by_name(a, fltr);
				if (r != ARCHIVE_OK && r != ARCHIVE_WARN) {
					ok = FALSE;
					lua_pop(L, 1); /* value */
					break;
				}
			}
			lua_pop(L, 1); /* value */
		}
	}

	lua_pop(L, 1); /* filters */

	return ok;
}

static gboolean
lua_archive_set_format(lua_State *L, struct archive *a, const char *fmt)
{
	int r = archive_write_set_format_by_name(a, fmt);

	if (r == ARCHIVE_OK || r == ARCHIVE_WARN) {
		return TRUE;
	}

	lua_pushfstring(L, "unsupported format: %s", fmt ? fmt : "(nil)");
	return FALSE;
}

static gboolean
lua_archive_set_format_options_table(lua_State *L, struct archive *a, const char *fmt, int idx)
{
	gboolean ok = TRUE;

	if (!lua_istable(L, idx)) {
		return ok;
	}

	lua_pushnil(L);

	while (lua_next(L, idx)) {
		const char *key = lua_tostring(L, -2);
		const char *valstr = NULL;
		char nb[64];

		if (key) {
			int t = lua_type(L, -1);
			if (t == LUA_TSTRING) {
				valstr = lua_tostring(L, -1);
			}
			else if (t == LUA_TNUMBER) {
				rspamd_snprintf(nb, sizeof(nb), "%l", (long) lua_tointeger(L, -1));
				valstr = nb;
			}
			else if (t == LUA_TBOOLEAN) {
				valstr = lua_toboolean(L, -1) ? "1" : "0";
			}

			if (valstr) {
				int r = archive_write_set_format_option(a, fmt, key, valstr);
				if (r != ARCHIVE_OK && r != ARCHIVE_WARN) {
					ok = FALSE;
					lua_pop(L, 1); /* value */
					break;
				}
			}
		}

		lua_pop(L, 1); /* value */
	}

	return ok;
}

static gboolean
lua_archive_add_format_options(lua_State *L, struct archive *a, const char *fmt, int opts_idx)
{
	gboolean ok = TRUE;

	if (opts_idx <= 0 || !lua_istable(L, opts_idx)) {
		return ok;
	}

	/* Optional password */
	lua_getfield(L, opts_idx, "password");
	if (lua_isstring(L, -1)) {
		const char *pw = lua_tostring(L, -1);
		if (pw && *pw) {
			int r = archive_write_set_passphrase(a, pw);
			if (r != ARCHIVE_OK && r != ARCHIVE_WARN) {
				ok = FALSE;
			}
		}
	}
	lua_pop(L, 1);

	/* Generic format_options table */
	lua_getfield(L, opts_idx, "format_options");
	if (!lua_isnil(L, -1)) {
		if (!lua_archive_set_format_options_table(L, a, fmt, lua_gettop(L))) {
			ok = FALSE;
		}
	}
	lua_pop(L, 1);

	/* Also support nested table named after format (e.g. options.zip) */
	if (fmt) {
		lua_getfield(L, opts_idx, fmt);
		if (!lua_isnil(L, -1)) {
			if (!lua_archive_set_format_options_table(L, a, fmt, lua_gettop(L))) {
				ok = FALSE;
			}
		}
		lua_pop(L, 1);
	}

	return ok;
}
static int
lua_archive_zip(lua_State *L)
{
	/* zip(files) -> text */
	luaL_checktype(L, 1, LUA_TTABLE);
	/* Stack: [files] -> [files, nil] -> [files, nil, "zip"] -> ["zip", files, nil] */
	lua_settop(L, 1);
	lua_pushnil(L);
	lua_pushstring(L, "zip");
	lua_insert(L, 1);
	return lua_archive_pack(L);
}

/***
 * @function archive.zip_encrypt(files[, password])
 * Convenience helper for creating ZIP archives.
 * - If password is provided and non-empty, uses libarchive with ZIP traditional encryption (ZipCrypto).
 * - If password is nil/empty, produces a plain (unencrypted) ZIP.
 * - For AES encryption, prefer archive.pack("zip", files, { password = "...", zip = { encryption = "aes128"|"aes256" } }).
 * @param {table} files array: { name = string, content = string|rspamd_text, [mode|perms] = int, [mtime] = int }
 * @param {string} password optional password string
 * @return {text} archive bytes
 */
static int
lua_archive_zip_encrypt(lua_State *L)
{
	LUA_TRACE_POINT;
	/* Re-route to libarchive packer with traditional encryption */
	luaL_checktype(L, 1, LUA_TTABLE); /* files */
	const char *password = NULL;
	if (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) {
		if (lua_type(L, 2) == LUA_TSTRING) {
			password = lua_tostring(L, 2);
		}
		else {
			return luaL_error(L, "invalid password (string expected)");
		}
	}

	/* Build args: ["zip", files, options] */
	lua_settop(L, 1); /* keep only files */
	if (password && *password) {
		lua_newtable(L); /* options */
		lua_pushstring(L, "password");
		lua_pushstring(L, password);
		lua_settable(L, -3);
		/* options.zip = { encryption = "traditional" } */
		lua_pushstring(L, "zip");
		lua_newtable(L);
		lua_pushstring(L, "encryption");
		lua_pushstring(L, "traditional");
		lua_settable(L, -3);
		lua_settable(L, -3); /* options.zip = {...} */
	}
	else {
		lua_pushnil(L); /* no options => plain ZIP */
	}

	lua_pushstring(L, "zip");
	lua_insert(L, 1); /* fmt at 1, files at 2, options/nil at 3 */

	return lua_archive_pack(L);
}

static int
lua_archive_enable_read_format_by_name(struct archive *a, const char *fmt)
{
	if (fmt == NULL) {
		return ARCHIVE_FATAL;
	}
	if (g_ascii_strcasecmp(fmt, "zip") == 0) return archive_read_support_format_zip(a);
	if (g_ascii_strcasecmp(fmt, "7z") == 0 || g_ascii_strcasecmp(fmt, "7zip") == 0) return archive_read_support_format_7zip(a);
	if (g_ascii_strcasecmp(fmt, "tar") == 0 || g_ascii_strcasecmp(fmt, "ustar") == 0 || g_ascii_strcasecmp(fmt, "pax") == 0) return archive_read_support_format_tar(a);
	if (g_ascii_strcasecmp(fmt, "cpio") == 0) return archive_read_support_format_cpio(a);
	if (g_ascii_strcasecmp(fmt, "ar") == 0) return archive_read_support_format_ar(a);
	if (g_ascii_strcasecmp(fmt, "xar") == 0) return archive_read_support_format_xar(a);
	if (g_ascii_strcasecmp(fmt, "iso") == 0 || g_ascii_strcasecmp(fmt, "iso9660") == 0) return archive_read_support_format_iso9660(a);
	if (g_ascii_strcasecmp(fmt, "mtree") == 0) return archive_read_support_format_mtree(a);
	if (g_ascii_strcasecmp(fmt, "rar") == 0) return archive_read_support_format_rar(a);
	if (g_ascii_strcasecmp(fmt, "cab") == 0) return archive_read_support_format_cab(a);
	if (g_ascii_strcasecmp(fmt, "lha") == 0 || g_ascii_strcasecmp(fmt, "lzh") == 0) return archive_read_support_format_lha(a);
	if (g_ascii_strcasecmp(fmt, "warc") == 0) return archive_read_support_format_warc(a);
	/* Fallback: unsupported name */
	return ARCHIVE_FATAL;
}

static int
lua_archive_enable_read_filter_by_name(struct archive *a, const char *fl)
{
	if (fl == NULL) {
		return ARCHIVE_FATAL;
	}
	if (g_ascii_strcasecmp(fl, "gzip") == 0 || g_ascii_strcasecmp(fl, "gz") == 0) return archive_read_support_filter_gzip(a);
	if (g_ascii_strcasecmp(fl, "bzip2") == 0 || g_ascii_strcasecmp(fl, "bz2") == 0) return archive_read_support_filter_bzip2(a);
	if (g_ascii_strcasecmp(fl, "xz") == 0) return archive_read_support_filter_xz(a);
	if (g_ascii_strcasecmp(fl, "lzma") == 0) return archive_read_support_filter_lzma(a);
	if (g_ascii_strcasecmp(fl, "zstd") == 0 || g_ascii_strcasecmp(fl, "zst") == 0) return archive_read_support_filter_zstd(a);
	if (g_ascii_strcasecmp(fl, "lz4") == 0) return archive_read_support_filter_lz4(a);
	if (g_ascii_strcasecmp(fl, "lzip") == 0) return archive_read_support_filter_lzip(a);
	if (g_ascii_strcasecmp(fl, "compress") == 0) return archive_read_support_filter_compress(a);
	if (g_ascii_strcasecmp(fl, "grzip") == 0) return archive_read_support_filter_grzip(a);
	if (g_ascii_strcasecmp(fl, "uu") == 0) return archive_read_support_filter_uu(a);
	return ARCHIVE_FATAL;
}

static int
lua_archive_unzip(lua_State *L)
{
	/* unzip(data) -> files */
	luaL_checkany(L, 1);
	lua_settop(L, 1);
	/* Stack: [data] -> [data, "zip"] */
	lua_pushstring(L, "zip");
	return lua_archive_unpack(L);
}

static int
lua_archive_tar(lua_State *L)
{
	/* tar(files[, compression]) -> text */
	luaL_checktype(L, 1, LUA_TTABLE);
	const char *comp = NULL;
	if (lua_type(L, 2) == LUA_TSTRING) {
		comp = lua_tostring(L, 2);
	}

	/* Build args: ["ustar", files, options|nil] */
	lua_settop(L, 1); /* keep only files */
	if (comp != NULL && *comp) {
		const char *filter = NULL;
		if (g_ascii_strcasecmp(comp, "gz") == 0 || g_ascii_strcasecmp(comp, "gzip") == 0) filter = "gzip";
		else if (g_ascii_strcasecmp(comp, "xz") == 0)
			filter = "xz";
		else if (g_ascii_strcasecmp(comp, "zst") == 0 || g_ascii_strcasecmp(comp, "zstd") == 0)
			filter = "zstd";
		else if (g_ascii_strcasecmp(comp, "bz2") == 0 || g_ascii_strcasecmp(comp, "bzip2") == 0)
			filter = "bzip2";

		if (filter) {
			lua_newtable(L);
			lua_pushstring(L, "filters");
			lua_pushstring(L, filter);
			lua_settable(L, -3);
		}
		else {
			lua_pushnil(L);
		}
	}
	else {
		lua_pushnil(L);
	}

	lua_pushstring(L, "ustar");
	lua_insert(L, 1);
	return lua_archive_pack(L);
}

static int
lua_archive_untar(lua_State *L)
{
	/* untar(data) -> files; compression autodetected */
	luaL_checkany(L, 1);
	lua_settop(L, 1);
	/* Restrict to tar format */
	lua_pushstring(L, "tar");
	return lua_archive_unpack(L);
}

static gboolean
lua_archive_entry_from_table(lua_State *L, int idx, struct archive_entry **pentry, const char **pdata, size_t *pdlen)
{
	/* idx: table with fields: name (string), content (string/rspamd_text), optional: mode/perms, mtime */
	const char *name;
	time_t mtime = (time_t) 0;
	mode_t mode = 0644;

	luaL_checktype(L, idx, LUA_TTABLE);

	lua_getfield(L, idx, "name");
	name = lua_tostring(L, -1);

	if (name == NULL || *name == '\0') {
		lua_pop(L, 1);
		return FALSE;
	}

	lua_getfield(L, idx, "content");

	struct rspamd_lua_text *t = NULL;
	const char *sdata = NULL;
	size_t slen = 0;

	/* Accept rspamd_text or Lua string */
	if ((t = lua_check_text_or_string(L, -1)) != NULL) {
		sdata = (const char *) t->start;
		slen = t->len;
	}
	else if (lua_isstring(L, -1)) {
		sdata = lua_tolstring(L, -1, &slen);
	}
	else {
		lua_pop(L, 2); /* content, name */
		return FALSE;
	}

	lua_pop(L, 1); /* content */

	/* Optional perms/mode */
	lua_getfield(L, idx, "mode");
	if (lua_isnumber(L, -1)) {
		mode = (mode_t) lua_tointeger(L, -1);
	}
	lua_pop(L, 1);

	lua_getfield(L, idx, "perms");
	if (lua_isnumber(L, -1)) {
		mode = (mode_t) lua_tointeger(L, -1);
	}
	lua_pop(L, 1);

	/* Optional mtime */
	lua_getfield(L, idx, "mtime");
	if (lua_isnumber(L, -1)) {
		mtime = (time_t) lua_tointeger(L, -1);
	}
	lua_pop(L, 1);

	struct archive_entry *ae = archive_entry_new();
	archive_entry_set_pathname(ae, name);
	archive_entry_set_size(ae, (la_int64_t) slen);
	archive_entry_set_filetype(ae, AE_IFREG);
	archive_entry_set_perm(ae, mode);
	if (mtime != (time_t) 0) {
		archive_entry_set_mtime(ae, mtime, 0);
	}

	*pentry = ae;
	*pdata = sdata;
	*pdlen = slen;

	lua_pop(L, 1); /* name */

	return TRUE;
}

static int
lua_archive_pack(lua_State *L)
{
	LUA_TRACE_POINT;
	const char *fmt;
	gboolean ok;
	struct archive *a = NULL;
	struct rspamd_archive_buf wctx;

	fmt = luaL_checkstring(L, 1);
	luaL_checktype(L, 2, LUA_TTABLE);

	a = archive_write_new();

	if (a == NULL) {
		return luaL_error(L, "cannot create libarchive writer");
	}

	ok = lua_archive_set_format(L, a, fmt);
	if (!ok) {
		archive_write_free(a);
		return luaL_error(L, "%s", lua_tostring(L, -1));
	}

	/* Options (filters, format options, password) at index 3 */
	if (!lua_archive_add_filters(L, a, 3)) {
		lua_pushstring(L, "cannot set compression filter(s)");
		archive_write_free(a);
		return lua_error(L);
	}

	if (!lua_archive_add_format_options(L, a, fmt, 3)) {
		const char *aerr = archive_error_string(a);
		lua_pushfstring(L, "cannot set format options: %s", aerr ? aerr : "unknown error");
		archive_write_free(a);
		return lua_error(L);
	}

	wctx.buf = g_byte_array_new();

	if (archive_write_open(a, &wctx, lua_archive_write_open, lua_archive_write_cb, lua_archive_write_close) != ARCHIVE_OK) {
		const char *aerr = archive_error_string(a);
		lua_pushfstring(L, "cannot open archive writer: %s", aerr ? aerr : "unknown error");
		g_byte_array_free(wctx.buf, TRUE);
		archive_write_free(a);
		return lua_error(L);
	}

	/* Iterate files table */
	lua_pushnil(L);

	while (lua_next(L, 2)) {
		if (!lua_istable(L, -1)) {
			archive_write_free(a);
			g_byte_array_free(wctx.buf, TRUE);
			return luaL_error(L, "invalid file entry (expected table)");
		}

		struct archive_entry *ae = NULL;
		const char *data = NULL;
		size_t dlen = 0;

		if (!lua_archive_entry_from_table(L, lua_gettop(L), &ae, &data, &dlen)) {
			archive_write_free(a);
			g_byte_array_free(wctx.buf, TRUE);
			return luaL_error(L, "invalid file entry (missing name/content)");
		}

		int r = archive_write_header(a, ae);
		if (r != ARCHIVE_OK) {
			const char *aerr = archive_error_string(a);
			lua_pushfstring(L, "cannot write header: %s", aerr ? aerr : "unknown error");
			archive_entry_free(ae);
			archive_write_free(a);
			g_byte_array_free(wctx.buf, TRUE);
			return lua_error(L);
		}

		if (dlen > 0) {
			la_ssize_t wr = archive_write_data(a, data, dlen);
			if (wr < 0 || (size_t) wr != dlen) {
				const char *aerr = archive_error_string(a);
				lua_pushfstring(L, "cannot write data: %s", aerr ? aerr : "unknown error");
				archive_entry_free(ae);
				archive_write_free(a);
				g_byte_array_free(wctx.buf, TRUE);
				return lua_error(L);
			}
		}

		archive_entry_free(ae);
		lua_pop(L, 1); /* pop value (file entry) */
	}

	archive_write_close(a);
	archive_write_free(a);

	/* Return rspamd{text}; transfer ownership of buffer */
	size_t outlen = wctx.buf->len;
	guint8 *outdata = g_byte_array_free(wctx.buf, FALSE);
	struct rspamd_lua_text *txt = lua_new_text(L, (const char *) outdata, outlen, FALSE);
	txt->flags |= RSPAMD_TEXT_FLAG_OWN;

	return 1;
}

/***
 * @function archive.unpack(data[, format][, password])
 * Unpacks an archive from a Lua string (or rspamd_text) using libarchive.
 * @param {string|text} data archive contents
 * @param {string} format optional format name to restrict autodetection (e.g. "zip")
 * @param {string} password optional passphrase for encrypted archives (ZIP: ZipCrypto/AES)
 * @return {table} array of files: { name = string, content = text } (non-regular entries are skipped)
 */
static int
lua_archive_unpack(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t = NULL;
	const char *format = NULL;
	const char *password = NULL;
	struct archive *a = NULL;

	t = lua_check_text_or_string(L, 1);

	if (t == NULL || t->start == NULL) {
		return luaL_error(L, "invalid arguments");
	}

	if (lua_type(L, 2) == LUA_TSTRING) {
		format = lua_tostring(L, 2);
	}
	if (lua_type(L, 3) == LUA_TSTRING) {
		password = lua_tostring(L, 3);
	}

	a = archive_read_new();
	if (a == NULL) {
		return luaL_error(L, "cannot create libarchive reader");
	}

	archive_read_support_filter_all(a);
	if (format) {
		/* Enable a specific format by known name mapping */
		lua_archive_enable_read_format_by_name(a, format);
	}
	else {
		archive_read_support_format_all(a);
	}

	if (password && *password) {
		/* supply passphrase for encrypted archives (e.g. zip AES) */
		int pr = archive_read_add_passphrase(a, password);
		if (pr != ARCHIVE_OK) {
			const char *aerr = archive_error_string(a);
			lua_pushfstring(L, "cannot set passphrase: %s", aerr ? aerr : "unknown error");
			archive_read_free(a);
			return lua_error(L);
		}
	}

	int r = archive_read_open_memory(a, t->start, t->len);
	if (r != ARCHIVE_OK) {
		const char *aerr = archive_error_string(a);
		lua_pushfstring(L, "cannot open archive: %s", aerr ? aerr : "unknown error");
		archive_read_free(a);
		return lua_error(L);
	}

	/* Debug: check if archive has encrypted entries */
	if (archive_read_has_encrypted_entries(a) > 0) {
		/* encrypted entries detected */
	}

	lua_newtable(L);

	struct archive_entry *ae;
	int n = 0;

	while ((r = archive_read_next_header(a, &ae)) == ARCHIVE_OK) {
		const char *name = archive_entry_pathname_utf8(ae);
		mode_t ftype = archive_entry_filetype(ae);

		if (name == NULL) {
			name = archive_entry_pathname(ae);
		}

		if (ftype == AE_IFREG && name != NULL) {
			GByteArray *ba = g_byte_array_new();
			char buf[8192];

			for (;;) {
				la_ssize_t rr = archive_read_data(a, buf, sizeof(buf));
				if (rr == 0) {
					break;
				}
				else if (rr < 0) {
					const char *aerr = archive_error_string(a);
					lua_pushfstring(L, "cannot read data: %s", aerr ? aerr : "unknown error");
					g_byte_array_free(ba, TRUE);
					archive_read_free(a);
					return lua_error(L);
				}
				g_byte_array_append(ba, (const guint8 *) buf, (guint) rr);
			}

			lua_newtable(L);
			lua_pushstring(L, "name");
			lua_pushstring(L, name);
			lua_settable(L, -3);

			lua_pushstring(L, "content");
			size_t blen = ba->len;
			guint8 *bdata = g_byte_array_free(ba, FALSE);
			struct rspamd_lua_text *cnt = lua_new_text(L, (const char *) bdata, blen, FALSE);
			cnt->flags |= RSPAMD_TEXT_FLAG_OWN;
			lua_settable(L, -3);

			lua_rawseti(L, -2, ++n);
		}
		else {
			archive_read_data_skip(a);
		}
	}

	archive_read_free(a);

	return 1;
}

/***
 * @function archive.supported_formats()
 * Returns a table describing runtime-supported formats and filters.
 * @return {table} { formats = { read = {...}, write = {...} }, filters = { read = {...}, write = {...} } }
 */
static int
lua_archive_supported_formats(lua_State *L)
{
	LUA_TRACE_POINT;
	/* Conservative known lists; probe by name to discover runtime support */
	static const char *known_formats[] = {
		"7zip", "ar", "cpio", "iso9660", "mtree", "pax", "raw", "tar",
		"xar", "zip", "cab", "lha", "lzh", "rar", "warc", "rpm",
		NULL};
	static const char *known_filters[] = {
		"b64encode", "b64decode", "bzip2", "compress", "grzip", "gzip",
		"lrzip", "lzip", "lzma", "xz", "lz4", "zstd", "uu", "zlib",
		NULL};

	struct archive *ar = archive_read_new();
	struct archive *aw = archive_write_new();

	lua_newtable(L);

	/* formats = { read = {...}, write = {...} } */
	lua_pushstring(L, "formats");
	lua_newtable(L);

	lua_pushstring(L, "read");
	lua_newtable(L);
	for (int i = 0, n = 0; known_formats[i] != NULL; i++) {
		const char *fmt = known_formats[i];
		if (ar && lua_archive_enable_read_format_by_name(ar, fmt) != ARCHIVE_FATAL) {
			lua_pushstring(L, fmt);
			lua_rawseti(L, -2, ++n);
		}
	}
	lua_settable(L, -3);

	lua_pushstring(L, "write");
	lua_newtable(L);
	for (int i = 0, n = 0; known_formats[i] != NULL; i++) {
		const char *fmt = known_formats[i];
		if (aw && archive_write_set_format_by_name(aw, fmt) != ARCHIVE_FATAL) {
			lua_pushstring(L, fmt);
			lua_rawseti(L, -2, ++n);
		}
	}
	lua_settable(L, -3);

	lua_settable(L, -3); /* formats */

	/* filters = { read = {...}, write = {...} } */
	lua_pushstring(L, "filters");
	lua_newtable(L);

	lua_pushstring(L, "read");
	lua_newtable(L);
	for (int i = 0, n = 0; known_filters[i] != NULL; i++) {
		const char *fl = known_filters[i];
		if (ar && lua_archive_enable_read_filter_by_name(ar, fl) != ARCHIVE_FATAL) {
			lua_pushstring(L, fl);
			lua_rawseti(L, -2, ++n);
		}
	}
	lua_settable(L, -3);

	lua_pushstring(L, "write");
	lua_newtable(L);
	for (int i = 0, n = 0; known_filters[i] != NULL; i++) {
		const char *fl = known_filters[i];
		if (aw && archive_write_add_filter_by_name(aw, fl) != ARCHIVE_FATAL) {
			lua_pushstring(L, fl);
			lua_rawseti(L, -2, ++n);
		}
	}
	lua_settable(L, -3);

	lua_settable(L, -3); /* filters */

	if (ar) {
		archive_read_free(ar);
	}
	if (aw) {
		archive_write_free(aw);
	}

	return 1;
}

static int
lua_load_archive_module(lua_State *L)
{
	lua_newtable(L);
	luaL_register(L, NULL, arch_mod_f);

	return 1;
}

void luaopen_libarchive(lua_State *L)
{
	/* Preload under both plain "archive" and namespaced "rspamd_archive" */
	rspamd_lua_add_preload(L, "archive", lua_load_archive_module);
	rspamd_lua_add_preload(L, "rspamd_archive", lua_load_archive_module);
}
