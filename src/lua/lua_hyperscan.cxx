/*
 * Copyright 2026 Vsevolod Stakhov
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

#ifdef WITH_HYPERSCAN
#include "hs.h"
#include "libserver/hyperscan_tools.h"
#include "cryptobox.h"
#include <vector>
#include <cstring>

/***
 * @module rspamd_hyperscan
 * Rspamd hyperscan module provides Lua bindings for Hyperscan pattern matching.
 * This module exposes compilation, serialization, and validation functions
 * for hyperscan databases.
 *
 * @example
local rspamd_hyperscan = require "rspamd_hyperscan"

-- Check if hyperscan is available
if rspamd_hyperscan.has_hyperscan() then
    -- Get platform identifier
    local platform_id = rspamd_hyperscan.platform_id()

    -- Compile patterns
    local patterns = {"pattern1", "pattern2"}
    local flags = {0, 0}  -- HS_FLAG_* values
    local ids = {1, 2}
    local db, err = rspamd_hyperscan.compile(patterns, flags, ids)

    if db then
        -- Serialize to binary blob
        local blob = rspamd_hyperscan.serialize(db)

        -- Validate blob
        local valid, err = rspamd_hyperscan.validate(blob)

        -- Deserialize back
        local db2 = rspamd_hyperscan.deserialize(blob)
    end
end
 */

/* Database magic for unified format */
static const unsigned char rspamd_hs_magic[] = {'r', 's', 'h', 's', 'r', 'e', '1', '1'};
#define RSPAMD_HS_MAGIC_LEN (sizeof(rspamd_hs_magic))

/* Userdata wrapper for hs_database_t */
struct lua_hs_db {
	hs_database_t *db;
	hs_scratch_t *scratch;
};

#define LUA_HS_DB "rspamd{hyperscan_db}"

static struct lua_hs_db *
lua_check_hs_db(lua_State *L, int idx)
{
	void *ud = rspamd_lua_check_udata(L, idx, LUA_HS_DB);
	luaL_argcheck(L, ud != NULL, idx, "'hyperscan_db' expected");
	return (struct lua_hs_db *) ud;
}

/***
 * @function rspamd_hyperscan.has_hyperscan()
 * Check if hyperscan support is available
 * @return {boolean} true if hyperscan is available
 */
static int
lua_hyperscan_has_hyperscan(lua_State *L)
{
	lua_pushboolean(L, true);
	return 1;
}

/***
 * @function rspamd_hyperscan.platform_id()
 * Get platform identifier string for cache keys
 * @return {string} platform identifier including HS version, CPU features, etc.
 */
static int
lua_hyperscan_platform_id(lua_State *L)
{
	const char *pid = rspamd_hyperscan_get_platform_id();
	lua_pushstring(L, pid);
	return 1;
}

/***
 * @function rspamd_hyperscan.compile(patterns, flags, ids)
 * Compile patterns into a hyperscan database
 * @param {table} patterns array of pattern strings
 * @param {table} flags array of HS_FLAG_* values (one per pattern)
 * @param {table} ids array of pattern IDs (one per pattern)
 * @return {hyperscan_db,nil} database object or nil on error
 * @return {nil,string} nil and error message on failure
 */
static int
lua_hyperscan_compile(lua_State *L)
{
	if (!lua_istable(L, 1)) {
		return luaL_error(L, "patterns must be a table");
	}

	size_t npat = rspamd_lua_table_size(L, 1);
	if (npat == 0) {
		lua_pushnil(L);
		lua_pushstring(L, "no patterns provided");
		return 2;
	}

	std::vector<const char *> patterns(npat);
	std::vector<std::string> pattern_storage(npat);
	std::vector<unsigned int> flags(npat, 0);
	std::vector<unsigned int> ids(npat);

	/* Extract patterns */
	for (size_t i = 0; i < npat; i++) {
		lua_rawgeti(L, 1, i + 1);
		if (lua_isstring(L, -1)) {
			size_t len;
			const char *pat = lua_tolstring(L, -1, &len);
			pattern_storage[i] = std::string(pat, len);
			patterns[i] = pattern_storage[i].c_str();
		}
		else {
			lua_pop(L, 1);
			lua_pushnil(L);
			lua_pushfstring(L, "pattern %d is not a string", (int) (i + 1));
			return 2;
		}
		lua_pop(L, 1);
		ids[i] = i;
	}

	/* Extract flags if provided */
	if (lua_istable(L, 2)) {
		for (size_t i = 0; i < npat; i++) {
			lua_rawgeti(L, 2, i + 1);
			if (lua_isnumber(L, -1)) {
				flags[i] = lua_tointeger(L, -1);
			}
			lua_pop(L, 1);
		}
	}

	/* Extract IDs if provided */
	if (lua_istable(L, 3)) {
		for (size_t i = 0; i < npat; i++) {
			lua_rawgeti(L, 3, i + 1);
			if (lua_isnumber(L, -1)) {
				ids[i] = lua_tointeger(L, -1);
			}
			lua_pop(L, 1);
		}
	}

	hs_database_t *db = nullptr;
	hs_compile_error_t *compile_err = nullptr;

	hs_error_t err = hs_compile_multi(
		patterns.data(),
		flags.data(),
		ids.data(),
		npat,
		HS_MODE_BLOCK,
		nullptr,
		&db,
		&compile_err);

	if (err != HS_SUCCESS) {
		const char *err_msg = compile_err ? compile_err->message : "unknown error";
		lua_pushnil(L);
		if (compile_err && compile_err->expression >= 0) {
			lua_pushfstring(L, "compile error at pattern %d: %s",
							compile_err->expression, err_msg);
		}
		else {
			lua_pushfstring(L, "compile error: %s", err_msg);
		}
		if (compile_err) {
			hs_free_compile_error(compile_err);
		}
		return 2;
	}

	/* Allocate scratch for matching */
	hs_scratch_t *scratch = nullptr;
	err = hs_alloc_scratch(db, &scratch);
	if (err != HS_SUCCESS) {
		hs_free_database(db);
		lua_pushnil(L);
		lua_pushstring(L, "failed to allocate scratch space");
		return 2;
	}

	/* Create userdata */
	auto *ud = (struct lua_hs_db *) lua_newuserdata(L, sizeof(struct lua_hs_db));
	ud->db = db;
	ud->scratch = scratch;
	rspamd_lua_setclass(L, LUA_HS_DB, -1);

	return 1;
}

/***
 * @function rspamd_hyperscan.serialize(db, [ids, flags])
 * Serialize a hyperscan database to binary blob with unified header
 * @param {hyperscan_db} db database to serialize
 * @param {table} ids optional array of pattern IDs to include in header
 * @param {table} flags optional array of pattern flags to include in header
 * @return {text} serialized database as rspamd_text or nil on error
 */
static int
lua_hyperscan_serialize(lua_State *L)
{
	struct lua_hs_db *db = lua_check_hs_db(L, 1);
	if (!db || !db->db) {
		lua_pushnil(L);
		lua_pushstring(L, "invalid database");
		return 2;
	}

	/* Serialize database first - hyperscan allocates the buffer */
	char *ser_bytes = nullptr;
	size_t ser_size = 0;
	hs_error_t err = hs_serialize_database(db->db, &ser_bytes, &ser_size);
	if (err != HS_SUCCESS) {
		lua_pushnil(L);
		lua_pushstring(L, "failed to serialize database");
		return 2;
	}

	/* Get platform info */
	hs_platform_info_t plt;
	err = hs_populate_platform(&plt);
	if (err != HS_SUCCESS) {
		free(ser_bytes);
		lua_pushnil(L);
		lua_pushstring(L, "failed to get platform info");
		return 2;
	}

	/* Extract IDs and flags if provided */
	std::vector<unsigned int> ids;
	std::vector<unsigned int> hs_flags;

	if (lua_istable(L, 2)) {
		size_t n = rspamd_lua_table_size(L, 2);
		ids.resize(n);
		for (size_t i = 0; i < n; i++) {
			lua_rawgeti(L, 2, i + 1);
			ids[i] = lua_isnumber(L, -1) ? lua_tointeger(L, -1) : i;
			lua_pop(L, 1);
		}
	}

	if (lua_istable(L, 3)) {
		size_t n = rspamd_lua_table_size(L, 3);
		hs_flags.resize(n);
		for (size_t i = 0; i < n; i++) {
			lua_rawgeti(L, 3, i + 1);
			hs_flags[i] = lua_isnumber(L, -1) ? lua_tointeger(L, -1) : 0;
			lua_pop(L, 1);
		}
	}

	int n = (int) ids.size();

	/* Calculate total size */
	size_t header_size = RSPAMD_HS_MAGIC_LEN +
						 sizeof(plt) +
						 sizeof(n) +
						 (n > 0 ? sizeof(unsigned int) * n * 2 : 0) +
						 sizeof(uint64_t); /* CRC */

	size_t total_size = header_size + ser_size;

	/* Allocate buffer */
	auto *text = static_cast<struct rspamd_lua_text *>(
		lua_newuserdata(L, sizeof(struct rspamd_lua_text)));
	rspamd_lua_setclass(L, rspamd_text_classname, -1);

	char *buf = static_cast<char *>(g_malloc(total_size));
	text->start = buf;
	text->len = total_size;
	text->flags = RSPAMD_TEXT_FLAG_OWN;

	/* Write header */
	char *p = buf;

	/* Magic */
	memcpy(p, rspamd_hs_magic, RSPAMD_HS_MAGIC_LEN);
	p += RSPAMD_HS_MAGIC_LEN;

	/* Platform */
	memcpy(p, &plt, sizeof(plt));
	p += sizeof(plt);

	/* Count */
	memcpy(p, &n, sizeof(n));
	p += sizeof(n);

	/* IDs - remember position for CRC */
	char *ids_start = p;
	if (n > 0) {
		memcpy(p, ids.data(), sizeof(unsigned int) * n);
		p += sizeof(unsigned int) * n;

		/* Flags */
		if (hs_flags.size() == ids.size()) {
			memcpy(p, hs_flags.data(), sizeof(unsigned int) * n);
		}
		else {
			memset(p, 0, sizeof(unsigned int) * n);
		}
		p += sizeof(unsigned int) * n;
	}

	/* Calculate CRC over IDs + flags + HS blob (compatible with re_cache.c) */
	rspamd_cryptobox_fast_hash_state_t crc_st;
	rspamd_cryptobox_fast_hash_init(&crc_st, 0xdeadbabe);
	if (n > 0) {
		rspamd_cryptobox_fast_hash_update(&crc_st, ids_start, sizeof(unsigned int) * n);
		rspamd_cryptobox_fast_hash_update(&crc_st, ids_start + sizeof(unsigned int) * n,
										  sizeof(unsigned int) * n);
	}
	rspamd_cryptobox_fast_hash_update(&crc_st, ser_bytes, ser_size);
	uint64_t crc = rspamd_cryptobox_fast_hash_final(&crc_st);

	memcpy(p, &crc, sizeof(crc));
	p += sizeof(crc);

	/* Copy serialized database */
	memcpy(p, ser_bytes, ser_size);

	/* Free hyperscan-allocated buffer (use free(), not g_free()) */
	free(ser_bytes);

	return 1;
}

/***
 * @function rspamd_hyperscan.validate(blob)
 * Validate a serialized hyperscan database blob
 * @param {text|string} blob serialized database
 * @return {boolean} true if valid
 * @return {string} error message if invalid
 */
static int
lua_hyperscan_validate(lua_State *L)
{
	const char *data = nullptr;
	size_t len = 0;
	struct rspamd_lua_text *t;

	if (lua_isstring(L, 1)) {
		data = lua_tolstring(L, 1, &len);
	}
	else if ((t = (struct rspamd_lua_text *) rspamd_lua_check_udata_maybe(L, 1, rspamd_text_classname))) {
		data = t->start;
		len = t->len;
	}
	else {
		return luaL_error(L, "blob must be a string or text");
	}

	if (len < RSPAMD_HS_MAGIC_LEN) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "blob too small");
		return 2;
	}

	/* Check magic */
	if (memcmp(data, rspamd_hs_magic, RSPAMD_HS_MAGIC_LEN) != 0) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "invalid magic");
		return 2;
	}

	const char *p = data + RSPAMD_HS_MAGIC_LEN;
	const char *end = data + len;

	/* Check platform */
	if ((size_t) (end - p) < sizeof(hs_platform_info_t)) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "truncated platform info");
		return 2;
	}

	hs_platform_info_t stored_plt;
	memcpy(&stored_plt, p, sizeof(stored_plt));
	p += sizeof(stored_plt);

	hs_platform_info_t cur_plt;
	if (hs_populate_platform(&cur_plt) != HS_SUCCESS) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "failed to get current platform");
		return 2;
	}

	/* Compare platform - tune is the most important */
	if (stored_plt.tune != cur_plt.tune) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "platform mismatch");
		return 2;
	}

	/* Read count */
	if ((size_t) (end - p) < sizeof(int)) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "truncated count");
		return 2;
	}

	int n;
	memcpy(&n, p, sizeof(n));
	p += sizeof(n);

	if (n < 0) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "invalid pattern count");
		return 2;
	}

	/* Remember start of IDs for CRC calculation */
	const char *ids_start = p;
	size_t arrays_size = (n > 0) ? sizeof(unsigned int) * n * 2 : 0;
	if ((size_t) (end - p) < arrays_size + sizeof(uint64_t)) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "truncated arrays or CRC");
		return 2;
	}

	p += arrays_size;

	/* Verify CRC (over IDs + flags + HS blob, compatible with re_cache.c) */
	uint64_t stored_crc;
	memcpy(&stored_crc, p, sizeof(stored_crc));
	p += sizeof(stored_crc);

	const char *hs_blob = p;
	size_t hs_len = end - p;

	rspamd_cryptobox_fast_hash_state_t crc_st;
	rspamd_cryptobox_fast_hash_init(&crc_st, 0xdeadbabe);
	if (n > 0) {
		rspamd_cryptobox_fast_hash_update(&crc_st, ids_start, sizeof(unsigned int) * n);
		rspamd_cryptobox_fast_hash_update(&crc_st, ids_start + sizeof(unsigned int) * n,
										  sizeof(unsigned int) * n);
	}
	rspamd_cryptobox_fast_hash_update(&crc_st, hs_blob, hs_len);
	uint64_t calc_crc = rspamd_cryptobox_fast_hash_final(&crc_st);

	if (stored_crc != calc_crc) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "CRC mismatch");
		return 2;
	}

	/* Validate hyperscan portion */
	if (hs_len == 0) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "empty hyperscan database");
		return 2;
	}

	hs_database_t *test_db = nullptr;
	hs_error_t err = hs_deserialize_database(p, hs_len, &test_db);
	if (err != HS_SUCCESS) {
		lua_pushboolean(L, false);
		lua_pushfstring(L, "hyperscan deserialize failed: %d", err);
		return 2;
	}

	hs_free_database(test_db);
	lua_pushboolean(L, true);
	return 1;
}

/***
 * @function rspamd_hyperscan.deserialize(blob)
 * Deserialize a hyperscan database from blob
 * @param {text|string} blob serialized database
 * @return {hyperscan_db} database object or nil
 * @return {string} error message on failure
 */
static int
lua_hyperscan_deserialize(lua_State *L)
{
	const char *data = nullptr;
	size_t len = 0;
	struct rspamd_lua_text *t;

	if (lua_isstring(L, 1)) {
		data = lua_tolstring(L, 1, &len);
	}
	else if ((t = (struct rspamd_lua_text *) rspamd_lua_check_udata_maybe(L, 1, rspamd_text_classname))) {
		data = t->start;
		len = t->len;
	}
	else {
		return luaL_error(L, "blob must be a string or text");
	}

	/* Validate first */
	if (len < RSPAMD_HS_MAGIC_LEN) {
		lua_pushnil(L);
		lua_pushstring(L, "blob too small");
		return 2;
	}

	if (memcmp(data, rspamd_hs_magic, RSPAMD_HS_MAGIC_LEN) != 0) {
		lua_pushnil(L);
		lua_pushstring(L, "invalid magic");
		return 2;
	}

	const char *p = data + RSPAMD_HS_MAGIC_LEN;
	const char *end = data + len;

	/* Skip platform */
	p += sizeof(hs_platform_info_t);

	/* Read count */
	int n;
	memcpy(&n, p, sizeof(n));
	p += sizeof(n);

	/* Skip IDs and flags */
	if (n > 0) {
		p += sizeof(unsigned int) * n * 2;
	}

	/* Skip CRC */
	p += sizeof(uint64_t);

	/* Deserialize hyperscan database */
	size_t hs_len = end - p;
	hs_database_t *db = nullptr;

	hs_error_t err = hs_deserialize_database(p, hs_len, &db);
	if (err != HS_SUCCESS) {
		lua_pushnil(L);
		lua_pushfstring(L, "deserialize failed: %d", err);
		return 2;
	}

	/* Allocate scratch */
	hs_scratch_t *scratch = nullptr;
	err = hs_alloc_scratch(db, &scratch);
	if (err != HS_SUCCESS) {
		hs_free_database(db);
		lua_pushnil(L);
		lua_pushstring(L, "failed to allocate scratch");
		return 2;
	}

	/* Create userdata */
	auto *ud = (struct lua_hs_db *) lua_newuserdata(L, sizeof(struct lua_hs_db));
	ud->db = db;
	ud->scratch = scratch;
	rspamd_lua_setclass(L, LUA_HS_DB, -1);

	return 1;
}

/* Database methods */
static int
lua_hs_db_gc(lua_State *L)
{
	struct lua_hs_db *db = lua_check_hs_db(L, 1);
	if (db) {
		if (db->scratch) {
			hs_free_scratch(db->scratch);
		}
		if (db->db) {
			hs_free_database(db->db);
		}
	}
	return 0;
}

/***
 * @method hyperscan_db:match(text)
 * Match text against the database
 * @param {text|string} text to match
 * @return {table} array of {id, from, to} matches or empty table
 */
struct match_context {
	lua_State *L;
	int match_count;
};

static int
match_callback(unsigned int id, unsigned long long from,
			   unsigned long long to, unsigned int flags, void *context)
{
	auto *ctx = (struct match_context *) context;
	lua_State *L = ctx->L;

	ctx->match_count++;

	/* Push match table: {id=id, from=from, to=to} */
	lua_createtable(L, 0, 3);

	lua_pushinteger(L, id);
	lua_setfield(L, -2, "id");

	lua_pushinteger(L, from);
	lua_setfield(L, -2, "from");

	lua_pushinteger(L, to);
	lua_setfield(L, -2, "to");

	/* Add to result array */
	lua_rawseti(L, -2, ctx->match_count);

	return 0;
}

static int
lua_hs_db_match(lua_State *L)
{
	struct lua_hs_db *db = lua_check_hs_db(L, 1);
	if (!db || !db->db || !db->scratch) {
		lua_newtable(L);
		return 1;
	}

	const char *text = nullptr;
	size_t len = 0;
	struct rspamd_lua_text *t;

	if (lua_isstring(L, 2)) {
		text = lua_tolstring(L, 2, &len);
	}
	else if ((t = (struct rspamd_lua_text *) rspamd_lua_check_udata_maybe(L, 2, rspamd_text_classname))) {
		text = t->start;
		len = t->len;
	}
	else {
		lua_newtable(L);
		return 1;
	}

	/* Create result table */
	lua_newtable(L);

	struct match_context ctx;
	ctx.L = L;
	ctx.match_count = 0;

	hs_scan(db->db, text, len, 0, db->scratch, match_callback, &ctx);

	return 1;
}

static const struct luaL_reg hyperscanlib_f[] = {
	LUA_INTERFACE_DEF(hyperscan, has_hyperscan),
	LUA_INTERFACE_DEF(hyperscan, platform_id),
	LUA_INTERFACE_DEF(hyperscan, compile),
	LUA_INTERFACE_DEF(hyperscan, serialize),
	LUA_INTERFACE_DEF(hyperscan, validate),
	LUA_INTERFACE_DEF(hyperscan, deserialize),
	{NULL, NULL}};

static const struct luaL_reg hs_db_m[] = {
	LUA_INTERFACE_DEF(hs_db, match),
	{"__gc", lua_hs_db_gc},
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}};

static int
lua_load_hyperscan(lua_State *L)
{
	lua_newtable(L);

	/* Hyperscan flags */
	lua_pushstring(L, "flags");
	lua_newtable(L);
	lua_pushinteger(L, HS_FLAG_CASELESS);
	lua_setfield(L, -2, "caseless");
	lua_pushinteger(L, HS_FLAG_DOTALL);
	lua_setfield(L, -2, "dotall");
	lua_pushinteger(L, HS_FLAG_MULTILINE);
	lua_setfield(L, -2, "multiline");
	lua_pushinteger(L, HS_FLAG_SINGLEMATCH);
	lua_setfield(L, -2, "singlematch");
	lua_pushinteger(L, HS_FLAG_UTF8);
	lua_setfield(L, -2, "utf8");
	lua_pushinteger(L, HS_FLAG_UCP);
	lua_setfield(L, -2, "ucp");
	lua_pushinteger(L, HS_FLAG_SOM_LEFTMOST);
	lua_setfield(L, -2, "som_leftmost");
	lua_settable(L, -3);

	luaL_register(L, NULL, hyperscanlib_f);

	return 1;
}

#else /* !WITH_HYPERSCAN */

static int
lua_hyperscan_has_hyperscan(lua_State *L)
{
	lua_pushboolean(L, false);
	return 1;
}

static int
lua_hyperscan_not_available(lua_State *L)
{
	return luaL_error(L, "hyperscan support is not available");
}

static const struct luaL_reg hyperscanlib_f[] = {
	LUA_INTERFACE_DEF(hyperscan, has_hyperscan),
	{"platform_id", lua_hyperscan_not_available},
	{"compile", lua_hyperscan_not_available},
	{"serialize", lua_hyperscan_not_available},
	{"validate", lua_hyperscan_not_available},
	{"deserialize", lua_hyperscan_not_available},
	{NULL, NULL}};

static int
lua_load_hyperscan(lua_State *L)
{
	lua_newtable(L);
	luaL_register(L, NULL, hyperscanlib_f);
	return 1;
}

#endif /* WITH_HYPERSCAN */

extern "C" void luaopen_hyperscan(lua_State *L)
{
#ifdef WITH_HYPERSCAN
	rspamd_lua_new_class(L, LUA_HS_DB, hs_db_m);
	lua_pop(L, 1);
#endif
	rspamd_lua_add_preload(L, "rspamd_hyperscan", lua_load_hyperscan);
}
