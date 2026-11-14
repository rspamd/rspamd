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

#include "config.h"
#include "cfg_dynamic.h"
#include "cfg_file.h"
#include "lua/lua_common.h"
#include "libutil/cxx/hash_util.hxx"
#include "contrib/ankerl/unordered_dense.h"

#include <algorithm>
#include <string>

namespace {

/* Do not try to call a failing Lua function more often than this (seconds) */
constexpr const double dynconf_retry_interval = 1.0;

struct dynconf_subscriber {
	rspamd_dynconf_apply_cb cb;
	void *ud;
};

struct dynconf_ctx {
	ankerl::unordered_dense::map<std::string, dynconf_subscriber,
								 rspamd::smart_str_hash, rspamd::smart_str_equal>
		subscribers;
	int check_ref = LUA_NOREF; /* Lua check function (registry ref) */
	bool in_check = false;     /* Reentrancy guard */
};

auto dynconf_get_ctx(struct rspamd_config *cfg, bool create) -> dynconf_ctx *
{
	if (cfg->dynconf_ctx == nullptr && create) {
		cfg->dynconf_ctx = new dynconf_ctx();
	}

	return static_cast<dynconf_ctx *>(cfg->dynconf_ctx);
}

auto dynconf_is_valid_ref(int ref) -> bool
{
	return ref != LUA_NOREF && ref != LUA_REFNIL;
}

}// namespace

extern "C" {

gboolean
rspamd_dynconf_register_module(struct rspamd_config *cfg,
							   const char *module,
							   const char *const *dynamic_paths,
							   rspamd_dynconf_apply_cb cb,
							   void *ud)
{
	if (cfg == nullptr || module == nullptr || cb == nullptr) {
		return FALSE;
	}

	auto *L = RSPAMD_LUA_CFG_STATE(cfg);

	if (L == nullptr) {
		return FALSE;
	}

	auto *ctx = dynconf_get_ctx(cfg, true);
	/* The subscriber has to be known before the Lua side can notify it */
	ctx->subscribers[std::string{module}] = dynconf_subscriber{cb, ud};

	auto top = lua_gettop(L);

	lua_pushcfunction(L, &rspamd_lua_traceback);
	auto err_idx = lua_gettop(L);

	if (!rspamd_lua_require_function(L, "lua_dynconf", "register_c")) {
		msg_warn_config("cannot register module %s for dynamic configuration: "
						"lua_dynconf is not available",
						module);
		lua_settop(L, top);

		return FALSE;
	}

	lua_pushstring(L, module);
	lua_createtable(L, 0, 0);

	if (dynamic_paths) {
		int i = 1;

		for (auto *p = dynamic_paths; *p != nullptr; p++, i++) {
			lua_pushstring(L, *p);
			lua_rawseti(L, -2, i);
		}
	}

	auto ret = FALSE;

	if (lua_pcall(L, 2, 2, err_idx) != 0) {
		msg_err_config("cannot register module %s for dynamic configuration: %s",
					   module, lua_tostring(L, -1));
	}
	else {
		if (lua_toboolean(L, -2)) {
			ret = TRUE;
		}
		else {
			msg_warn_config("module %s is not registered for dynamic configuration: %s",
							module, lua_isstring(L, -1) ? lua_tostring(L, -1) : "unknown error");
		}
	}

	lua_settop(L, top);

	return ret;
}

gboolean
rspamd_dynconf_notify(struct rspamd_config *cfg,
					  const char *module,
					  const ucl_object_t *values,
					  GError **err)
{
	auto *ctx = dynconf_get_ctx(cfg, false);

	if (ctx == nullptr) {
		g_set_error(err, g_quark_from_static_string("dynconf"), 404,
					"no C modules are registered for dynamic configuration");
		return FALSE;
	}

	auto it = ctx->subscribers.find(std::string_view{module});

	if (it == ctx->subscribers.end()) {
		g_set_error(err, g_quark_from_static_string("dynconf"), 404,
					"module %s has no C subscriber", module);
		return FALSE;
	}

	/* Copy it, as the callback might modify the map by registering modules */
	auto sub = it->second;

	return sub.cb(cfg, module, values, sub.ud, err);
}

uint64_t
rspamd_dynconf_generation(struct rspamd_config *cfg)
{
	return cfg->dyn_generation;
}

void rspamd_dynconf_bump_generation(struct rspamd_config *cfg)
{
	cfg->dyn_generation++;
}

void rspamd_dynconf_set_next_check(struct rspamd_config *cfg, double when, int cbref)
{
	auto *L = RSPAMD_LUA_CFG_STATE(cfg);
	auto *ctx = dynconf_get_ctx(cfg, true);

	if (dynconf_is_valid_ref(cbref)) {
		if (dynconf_is_valid_ref(ctx->check_ref) && L) {
			luaL_unref(L, LUA_REGISTRYINDEX, ctx->check_ref);
		}

		ctx->check_ref = cbref;
	}

	if (when <= 0.0 || !dynconf_is_valid_ref(ctx->check_ref)) {
		/* Disarm */
		cfg->dyn_next_check = 0.0;

		if (dynconf_is_valid_ref(ctx->check_ref) && L) {
			luaL_unref(L, LUA_REGISTRYINDEX, ctx->check_ref);
		}

		ctx->check_ref = LUA_NOREF;
	}
	else {
		if (ctx->in_check) {
			/* The check function re-arms with its own interval: never faster than the backoff */
			when = std::max(when, ev_time() + dynconf_retry_interval);
		}

		cfg->dyn_next_check = when;
	}
}

void rspamd_dynconf_run_check(struct rspamd_config *cfg,
							  struct ev_loop *loop,
							  double now)
{
	auto *ctx = dynconf_get_ctx(cfg, false);
	auto *L = RSPAMD_LUA_CFG_STATE(cfg);

	if (ctx == nullptr || L == nullptr || !dynconf_is_valid_ref(ctx->check_ref)) {
		cfg->dyn_next_check = 0.0;
		return;
	}

	if (ctx->in_check || loop == nullptr) {
		/* A task without an event loop cannot start asynchronous requests: try the next one */
		return;
	}

	/*
	 * Back off before calling Lua: the Lua function re-arms the trigger with its
	 * own interval, but if it fails or does not, we must not call it for every task
	 */
	cfg->dyn_next_check = now + dynconf_retry_interval;
	ctx->in_check = true;

	/*
	 * Always the main state of the configuration, never a coroutine of a task:
	 * the check function only starts asynchronous requests and returns
	 */
	auto top = lua_gettop(L);

	lua_pushcfunction(L, &rspamd_lua_traceback);
	auto err_idx = lua_gettop(L);
	lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->check_ref);

	auto **pcfg = static_cast<struct rspamd_config **>(lua_newuserdata(L, sizeof(struct rspamd_config *)));
	rspamd_lua_setclass(L, rspamd_config_classname, -1);
	*pcfg = cfg;

	auto **pev_base = static_cast<struct ev_loop **>(lua_newuserdata(L, sizeof(struct ev_loop *)));
	rspamd_lua_setclass(L, rspamd_ev_base_classname, -1);
	*pev_base = loop;

	if (lua_pcall(L, 2, 0, err_idx) != 0) {
		msg_err_config("dynamic configuration check failed: %s", lua_tostring(L, -1));
	}

	lua_settop(L, top);
	ctx->in_check = false;
}

void rspamd_dynconf_free(struct rspamd_config *cfg)
{
	auto *ctx = dynconf_get_ctx(cfg, false);

	if (ctx == nullptr) {
		return;
	}

	auto *L = RSPAMD_LUA_CFG_STATE(cfg);

	if (dynconf_is_valid_ref(ctx->check_ref) && L) {
		luaL_unref(L, LUA_REGISTRYINDEX, ctx->check_ref);
	}

	delete ctx;
	cfg->dynconf_ctx = nullptr;
	cfg->dyn_next_check = 0.0;
}
}
