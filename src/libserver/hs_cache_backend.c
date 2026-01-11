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

#include "hs_cache_backend.h"
#include "lua/lua_common.h"
#include "lua/lua_classnames.h"
#include "libutil/util.h"
#include "libserver/worker_util.h"
#include "libserver/cfg_file.h"
#include "libserver/redis_pool.h"
#ifdef WITH_HYPERSCAN
#include "libserver/hyperscan_tools.h"
#else
/* Fallback when hyperscan is not available */
#define msg_debug_hyperscan(...) \
	do {                         \
	} while (0)
#endif

static struct rspamd_hs_cache_backend *global_hs_cache_backend = NULL;

/* Lua backend state - set by hs_helper when using non-file backend */
static lua_State *lua_backend_L = NULL;
static int lua_backend_ref = LUA_NOREF;
static const char *lua_backend_platform_id = NULL;

static gboolean
rspamd_hs_cache_try_init_lua_backend_with_opts(struct rspamd_config *cfg,
											   struct ev_loop *ev_base,
											   const ucl_object_t *opts,
											   const char *backend_name,
											   const char *cache_dir)
{
	lua_State *L;
	int err_idx;

	if (!cfg || !cfg->lua_state || !ev_base || !opts || !backend_name) {
		return FALSE;
	}

	if (strcmp(backend_name, "file") == 0) {
		return FALSE;
	}

	L = (lua_State *) cfg->lua_state;

	/* Ensure redis pool is bound to this process event loop (required for lua_redis async requests) */
	if (cfg->redis_pool) {
		rspamd_redis_pool_config(cfg->redis_pool, cfg, ev_base);
	}

	/* Load lua_hs_cache module */
	lua_pushcfunction(L, rspamd_lua_traceback);
	err_idx = lua_gettop(L);

	lua_getglobal(L, "require");
	lua_pushstring(L, "lua_hs_cache");

	if (lua_pcall(L, 1, 1, err_idx) != 0) {
		lua_settop(L, err_idx - 1);
		return FALSE;
	}

	/* Get create_backend function */
	lua_getfield(L, -1, "create_backend");
	if (!lua_isfunction(L, -1)) {
		lua_settop(L, err_idx - 1);
		return FALSE;
	}

	/* Push options as config table */
	ucl_object_push_lua(L, opts, true);

	/* Set event loop for lua_redis */
	{
		struct ev_loop **pev_base = (struct ev_loop **) lua_newuserdata(L, sizeof(struct ev_loop *));
		*pev_base = ev_base;
		rspamd_lua_setclass(L, rspamd_ev_base_classname, -1);
		lua_setfield(L, -2, "ev_base");
	}

	/* Set rspamd_config for lua_redis */
	{
		struct rspamd_config **pcfg = (struct rspamd_config **) lua_newuserdata(L, sizeof(struct rspamd_config *));
		*pcfg = cfg;
		rspamd_lua_setclass(L, rspamd_config_classname, -1);
		lua_setfield(L, -2, "rspamd_config");
	}

	/* Force backend/cache_dir */
	lua_pushstring(L, backend_name);
	lua_setfield(L, -2, "backend");
	if (cache_dir) {
		lua_pushstring(L, cache_dir);
		lua_setfield(L, -2, "cache_dir");
	}

#ifdef WITH_HYPERSCAN
	const char *platform_id = rspamd_hyperscan_get_platform_id();
	if (platform_id) {
		lua_pushstring(L, platform_id);
		lua_setfield(L, -2, "platform_id");
	}
#else
	const char *platform_id = NULL;
#endif

	/* Call create_backend(config) */
	if (lua_pcall(L, 1, 1, err_idx) != 0) {
		const char *lua_err = lua_tostring(L, -1);
		msg_err("failed to create hyperscan cache backend '%s': %s",
				backend_name, lua_err ? lua_err : "unknown error");
		lua_settop(L, err_idx - 1);
		return FALSE;
	}

	int ref = luaL_ref(L, LUA_REGISTRYINDEX);
	/* Pop the module table */
	lua_pop(L, 1);

	rspamd_hs_cache_set_lua_backend(L, ref, platform_id);
	lua_settop(L, err_idx - 1);

	msg_debug_hyperscan("initialized hyperscan cache backend: %s", backend_name);

	return TRUE;
}

void rspamd_hs_cache_set_backend(struct rspamd_hs_cache_backend *backend)
{
	if (global_hs_cache_backend) {
		g_free(global_hs_cache_backend);
	}
	global_hs_cache_backend = backend;
}

struct rspamd_hs_cache_backend *
rspamd_hs_cache_get_backend(void)
{
	return global_hs_cache_backend;
}

gboolean
rspamd_hs_cache_has_custom_backend(void)
{
	return global_hs_cache_backend != NULL;
}

void rspamd_hs_cache_free_backend(void)
{
	if (global_hs_cache_backend) {
		g_free(global_hs_cache_backend);
		global_hs_cache_backend = NULL;
	}
	lua_backend_L = NULL;
	lua_backend_ref = LUA_NOREF;
	lua_backend_platform_id = NULL;
}

void rspamd_hs_cache_set_lua_backend(lua_State *L, int ref, const char *platform_id)
{
	lua_backend_L = L;
	lua_backend_ref = ref;
	lua_backend_platform_id = platform_id;
}

gboolean
rspamd_hs_cache_has_lua_backend(void)
{
	return lua_backend_L != NULL && lua_backend_ref != LUA_NOREF;
}

gboolean
rspamd_hs_cache_try_init_lua_backend(struct rspamd_config *cfg,
									 struct ev_loop *ev_base)
{
	GList *cur;
	const struct rspamd_worker_conf *cf = NULL;
	const ucl_object_t *opts = NULL;
	const char *backend_name = NULL;
	const char *cache_dir = NULL;
	GQuark hs_quark;

	if (rspamd_hs_cache_has_lua_backend()) {
		return TRUE;
	}

	if (!cfg || !cfg->workers) {
		return FALSE;
	}

	hs_quark = g_quark_try_string("hs_helper");
	for (cur = cfg->workers; cur != NULL; cur = g_list_next(cur)) {
		cf = (const struct rspamd_worker_conf *) cur->data;
		if (cf && (hs_quark != 0 ? (cf->type == hs_quark) : (strcmp(g_quark_to_string(cf->type), "hs_helper") == 0))) {
			opts = cf->options;
			break;
		}
	}

	if (!opts) {
		return FALSE;
	}

	const ucl_object_t *b = ucl_object_lookup(opts, "cache_backend");
	if (b && ucl_object_type(b) == UCL_STRING) {
		backend_name = ucl_object_tostring(b);
	}
	if (!backend_name) {
		backend_name = "file";
	}

	const ucl_object_t *d = ucl_object_lookup(opts, "cache_dir");
	if (d && ucl_object_type(d) == UCL_STRING) {
		cache_dir = ucl_object_tostring(d);
	}
	if (!cache_dir) {
		cache_dir = cfg->hs_cache_dir;
	}

	return rspamd_hs_cache_try_init_lua_backend_with_opts(cfg, ev_base, opts, backend_name, cache_dir);
}

static int
lua_hs_cache_async_callback(lua_State *L)
{
	rspamd_hs_cache_async_cb cb = (rspamd_hs_cache_async_cb) lua_touserdata(L, lua_upvalueindex(1));
	void *ud = lua_touserdata(L, lua_upvalueindex(2));
	const char *entity_name = lua_tostring(L, lua_upvalueindex(3));
	const char *cache_key = lua_tostring(L, lua_upvalueindex(4));
	const char *err = lua_tostring(L, 1);
	const unsigned char *data = NULL;
	size_t len = 0;

	if (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) {
		if (lua_isboolean(L, 2)) {
			/* exists_async: pass boolean as len (1/0), keep data NULL */
			len = lua_toboolean(L, 2) ? 1 : 0;
		}
		else {
			/* Prefer rspamd{text} or Lua strings without forcing conversion */
			struct rspamd_lua_text *t = lua_check_text_or_string(L, 2);
			if (t && t->start) {
				data = (const unsigned char *) t->start;
				len = t->len;
			}
		}
	}

	msg_debug_hyperscan("async_callback: entity='%s', key=%s, success=%s, len=%z, err=%s",
						entity_name ? entity_name : "unknown",
						cache_key ? cache_key : "unknown",
						err == NULL ? "yes" : "no", len, err ? err : "(none)");

	if (cb) {
		cb(err == NULL, data, len, err, ud);
	}

	return 0;
}

void rspamd_hs_cache_lua_save_async(const char *cache_key,
									const char *entity_name,
									const unsigned char *data,
									gsize len,
									rspamd_hs_cache_async_cb cb,
									void *ud)
{
	lua_State *L = lua_backend_L;
	int err_idx;

	msg_debug_hyperscan("save_async: entity='%s', key=%s, len=%z",
						entity_name ? entity_name : "unknown", cache_key, len);

	if (rspamd_current_worker && rspamd_current_worker->state != rspamd_worker_state_running) {
		msg_debug_hyperscan("save_async: worker terminating, skipping");
		if (cb) cb(FALSE, NULL, 0, "worker is terminating", ud);
		return;
	}

	if (!rspamd_hs_cache_has_lua_backend()) {
		msg_debug_hyperscan("save_async: no Lua backend");
		if (cb) cb(FALSE, NULL, 0, "Lua backend not initialized", ud);
		return;
	}

	lua_pushcfunction(L, rspamd_lua_traceback);
	err_idx = lua_gettop(L);

	/* Get backend object */
	lua_rawgeti(L, LUA_REGISTRYINDEX, lua_backend_ref);
	if (!lua_istable(L, -1)) {
		lua_settop(L, err_idx - 1);
		if (cb) cb(FALSE, NULL, 0, "Invalid Lua backend reference", ud);
		return;
	}

	/* Get save_async method */
	lua_getfield(L, -1, "save_async");
	if (!lua_isfunction(L, -1)) {
		lua_settop(L, err_idx - 1);
		if (cb) cb(FALSE, NULL, 0, "Lua backend has no save_async method", ud);
		return;
	}

	/* Push self (backend object) */
	lua_pushvalue(L, -2);
	/* Push cache_key */
	lua_pushstring(L, cache_key);
	/* Push platform_id */
	lua_pushstring(L, lua_backend_platform_id ? lua_backend_platform_id : "default");
	/* Push data */
	lua_pushlstring(L, (const char *) data, len);

	/* Push callback wrapper with 4 upvalues: cb, ud, entity_name, cache_key */
	lua_pushlightuserdata(L, (void *) cb);
	lua_pushlightuserdata(L, ud);
	lua_pushstring(L, entity_name ? entity_name : "unknown");
	lua_pushstring(L, cache_key);
	lua_pushcclosure(L, lua_hs_cache_async_callback, 4);

	/* Call backend:save_async(cache_key, platform_id, data, callback) */
	if (lua_pcall(L, 5, 0, err_idx) != 0) {
		const char *lua_err = lua_tostring(L, -1);
		if (cb) cb(FALSE, NULL, 0, lua_err ? lua_err : "Lua call failed", ud);
		lua_settop(L, err_idx - 1);
		return;
	}

	lua_settop(L, err_idx - 1);
}

void rspamd_hs_cache_lua_load_async(const char *cache_key,
									const char *entity_name,
									rspamd_hs_cache_async_cb cb,
									void *ud)
{
	lua_State *L = lua_backend_L;
	int err_idx;

	msg_debug_hyperscan("load_async: entity='%s', key=%s",
						entity_name ? entity_name : "unknown", cache_key);

	if (rspamd_current_worker && rspamd_current_worker->state != rspamd_worker_state_running) {
		msg_debug_hyperscan("load_async: worker terminating, skipping");
		if (cb) cb(FALSE, NULL, 0, "worker is terminating", ud);
		return;
	}

	if (!rspamd_hs_cache_has_lua_backend()) {
		if (cb) cb(FALSE, NULL, 0, "Lua backend not initialized", ud);
		return;
	}

	lua_pushcfunction(L, rspamd_lua_traceback);
	err_idx = lua_gettop(L);

	/* Get backend object */
	lua_rawgeti(L, LUA_REGISTRYINDEX, lua_backend_ref);
	if (!lua_istable(L, -1)) {
		lua_settop(L, err_idx - 1);
		if (cb) cb(FALSE, NULL, 0, "Invalid Lua backend reference", ud);
		return;
	}

	/* Get load_async method */
	lua_getfield(L, -1, "load_async");
	if (!lua_isfunction(L, -1)) {
		lua_settop(L, err_idx - 1);
		if (cb) cb(FALSE, NULL, 0, "Lua backend has no load_async method", ud);
		return;
	}

	/* Push self (backend object) */
	lua_pushvalue(L, -2);
	/* Push cache_key */
	lua_pushstring(L, cache_key);
	/* Push platform_id */
	lua_pushstring(L, lua_backend_platform_id ? lua_backend_platform_id : "default");

	/* Push callback wrapper with 4 upvalues: cb, ud, entity_name, cache_key */
	lua_pushlightuserdata(L, (void *) cb);
	lua_pushlightuserdata(L, ud);
	lua_pushstring(L, entity_name ? entity_name : "unknown");
	lua_pushstring(L, cache_key);
	lua_pushcclosure(L, lua_hs_cache_async_callback, 4);

	/* Call backend:load_async(cache_key, platform_id, callback) */
	if (lua_pcall(L, 4, 0, err_idx) != 0) {
		const char *lua_err = lua_tostring(L, -1);
		if (cb) cb(FALSE, NULL, 0, lua_err ? lua_err : "Lua call failed", ud);
		lua_settop(L, err_idx - 1);
		return;
	}

	lua_settop(L, err_idx - 1);
}

void rspamd_hs_cache_lua_exists_async(const char *cache_key,
									  const char *entity_name,
									  rspamd_hs_cache_async_cb cb,
									  void *ud)
{
	lua_State *L = lua_backend_L;
	int err_idx;

	msg_debug_hyperscan("exists_async: entity='%s', key=%s",
						entity_name ? entity_name : "unknown", cache_key);

	if (rspamd_current_worker && rspamd_current_worker->state != rspamd_worker_state_running) {
		msg_debug_hyperscan("exists_async: worker terminating, skipping");
		if (cb) cb(FALSE, NULL, 0, "worker is terminating", ud);
		return;
	}

	if (!rspamd_hs_cache_has_lua_backend()) {
		msg_debug_hyperscan("exists_async: no Lua backend");
		if (cb) cb(FALSE, NULL, 0, "Lua backend not initialized", ud);
		return;
	}

	lua_pushcfunction(L, rspamd_lua_traceback);
	err_idx = lua_gettop(L);

	/* Get backend object */
	lua_rawgeti(L, LUA_REGISTRYINDEX, lua_backend_ref);
	if (!lua_istable(L, -1)) {
		lua_settop(L, err_idx - 1);
		if (cb) cb(FALSE, NULL, 0, "Invalid Lua backend reference", ud);
		return;
	}

	/* Get exists_async method */
	lua_getfield(L, -1, "exists_async");
	if (!lua_isfunction(L, -1)) {
		lua_settop(L, err_idx - 1);
		if (cb) cb(FALSE, NULL, 0, "Lua backend has no exists_async method", ud);
		return;
	}

	/* Push self (backend object) */
	lua_pushvalue(L, -2);
	/* Push cache_key */
	lua_pushstring(L, cache_key);
	/* Push platform_id */
	lua_pushstring(L, lua_backend_platform_id ? lua_backend_platform_id : "default");

	/* Push callback wrapper with 4 upvalues: cb, ud, entity_name, cache_key */
	lua_pushlightuserdata(L, (void *) cb);
	lua_pushlightuserdata(L, ud);
	lua_pushstring(L, entity_name ? entity_name : "unknown");
	lua_pushstring(L, cache_key);
	lua_pushcclosure(L, lua_hs_cache_async_callback, 4);

	/* Call backend:exists_async(cache_key, platform_id, callback) */
	if (lua_pcall(L, 4, 0, err_idx) != 0) {
		const char *lua_err = lua_tostring(L, -1);
		if (cb) cb(FALSE, NULL, 0, lua_err ? lua_err : "Lua call failed", ud);
		lua_settop(L, err_idx - 1);
		return;
	}

	lua_settop(L, err_idx - 1);
}
