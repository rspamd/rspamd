/*-
 * Copyright 2019 Vsevolod Stakhov
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
 * @file lua_spf.c
 * This module exports spf functions to Lua
 */

#include "lua_common.h"
#include "libserver/spf.h"
#include "libutil/ref.h"

#define SPF_RECORD_CLASS "rspamd{spf_record}"

LUA_FUNCTION_DEF (spf, resolve);
LUA_FUNCTION_DEF (spf, config);
LUA_FUNCTION_DEF (spf, set_credentials);
LUA_FUNCTION_DEF (spf, get_domain);
LUA_FUNCTION_DEF (spf_record, check_ip);
LUA_FUNCTION_DEF (spf_record, dtor);

static luaL_reg rspamd_spf_f[] = {
		LUA_INTERFACE_DEF (spf, resolve),
		LUA_INTERFACE_DEF (spf, config),
		LUA_INTERFACE_DEF (spf, set_credentials),
		LUA_INTERFACE_DEF (spf, get_domain),
		{NULL, NULL},
};

static luaL_reg rspamd_spf_record_m[] = {
		LUA_INTERFACE_DEF (spf_record, check_ip),
		{"__gc", lua_spf_record_dtor},
		{NULL, NULL},
};

struct rspamd_lua_spf_cbdata {
	struct rspamd_task *task;
	lua_State *L;
	gint cbref;
	ref_entry_t ref;
};

static gint
lua_load_spf (lua_State * L)
{
	lua_newtable (L);

	/* Create integer arguments to check SPF results */
	lua_newtable (L);
	lua_pushinteger (L, SPF_FAIL);
	lua_setfield (L, -2, "fail");
	lua_pushinteger (L, SPF_PASS);
	lua_setfield (L, -2, "pass");
	lua_pushinteger (L, SPF_NEUTRAL);
	lua_setfield (L, -2, "neutral");
	lua_pushinteger (L, SPF_SOFT_FAIL);
	lua_setfield (L, -2, "soft_fail");

	lua_setfield (L, -2, "results");

	/* Flags stuff */
	lua_newtable (L);

	lua_pushinteger (L, RSPAMD_SPF_RESOLVED_TEMP_FAILED);
	lua_setfield (L, -2, "temp_fail");
	lua_pushinteger (L, RSPAMD_SPF_RESOLVED_NA);
	lua_setfield (L, -2, "na");
	lua_pushinteger (L, RSPAMD_SPF_RESOLVED_PERM_FAILED);
	lua_setfield (L, -2, "perm_fail");
	lua_pushinteger (L, RSPAMD_SPF_FLAG_CACHED);
	lua_setfield (L, -2, "cached");

	lua_setfield (L, -2, "flags");

	luaL_register (L, NULL, rspamd_spf_f);

	return 1;
}

void luaopen_spf (lua_State *L)
{
	rspamd_lua_new_class (L, SPF_RECORD_CLASS, rspamd_spf_record_m);
	lua_pop (L, 1); /* No need in metatable... */

	rspamd_lua_add_preload (L, "rspamd_spf", lua_load_spf);
	lua_settop (L, 0);
}

static void
lua_spf_push_result (struct rspamd_lua_spf_cbdata *cbd, gint code_flags,
		struct spf_resolved *resolved, const gchar *err)
{
	g_assert (cbd != NULL);
	REF_RETAIN (cbd);

	lua_pushcfunction (cbd->L, &rspamd_lua_traceback);
	gint err_idx = lua_gettop (cbd->L);

	lua_rawgeti (cbd->L, LUA_REGISTRYINDEX, cbd->cbref);

	if (resolved) {
		struct spf_resolved **presolved;

		presolved = lua_newuserdata (cbd->L, sizeof (*presolved));
		rspamd_lua_setclass (cbd->L, SPF_RECORD_CLASS, -1);
		*presolved = spf_record_ref (resolved);
	}
	else {
		lua_pushnil (cbd->L);
	}

	lua_pushinteger (cbd->L, code_flags);

	if (err) {
		lua_pushstring (cbd->L, err);
	}
	else {
		lua_pushnil (cbd->L);
	}

	if (lua_pcall (cbd->L, 3, 0, err_idx) != 0) {
		struct rspamd_task *task = cbd->task;

		msg_err_task ("cannot call callback function for spf: %s",
				lua_tostring (cbd->L, -1));
	}

	lua_settop (cbd->L, err_idx - 1);

	REF_RELEASE (cbd);
}

static void
lua_spf_dtor (struct rspamd_lua_spf_cbdata *cbd)
{
	if (cbd) {
		luaL_unref (cbd->L, LUA_REGISTRYINDEX, cbd->cbref);
	}
}

static void
spf_lua_lib_callback (struct spf_resolved *record, struct rspamd_task *task,
					 gpointer ud)
{
	struct rspamd_lua_spf_cbdata *cbd = (struct rspamd_lua_spf_cbdata *)ud;

	if (record && (record->flags & RSPAMD_SPF_RESOLVED_NA)) {
		lua_spf_push_result (cbd, RSPAMD_SPF_RESOLVED_NA, record,
				"no record found");
	}
	else if (record && record->elts->len == 0 && (record->flags & RSPAMD_SPF_RESOLVED_TEMP_FAILED)) {
		lua_spf_push_result (cbd, RSPAMD_SPF_RESOLVED_TEMP_FAILED, record,
				"temporary resolution error");
	}
	else if (record && record->elts->len == 0 && (record->flags & RSPAMD_SPF_RESOLVED_PERM_FAILED)) {
		lua_spf_push_result (cbd, RSPAMD_SPF_RESOLVED_PERM_FAILED, record,
				"permanent resolution error");
	}
	else if (record && record->elts->len == 0) {
		lua_spf_push_result (cbd, RSPAMD_SPF_RESOLVED_PERM_FAILED, record,
				"record is empty");
	}
	else if (record && record->domain) {
		spf_record_ref (record);
		lua_spf_push_result (cbd, record->flags, record, NULL);
		spf_record_unref (record);
	}

	REF_RELEASE (cbd);
}

/***
 * @function rspamd_spf.resolve(task, callback)
 * Resolves SPF credentials for a task
 * @param {rspamd_task} task task
 * @param {function} callback callback that is called on spf resolution
*/
gint
lua_spf_resolve (lua_State * L)
{
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task && lua_isfunction (L, 2)) {
		struct rspamd_lua_spf_cbdata *cbd = rspamd_mempool_alloc0 (task->task_pool,
				sizeof (*cbd));
		struct rspamd_spf_cred *spf_cred;

		cbd->task = task;
		cbd->L = L;
		lua_pushvalue (L, 2);
		cbd->cbref = luaL_ref (L, LUA_REGISTRYINDEX);
		/* TODO: make it as an optional parameter */
		spf_cred = rspamd_spf_get_cred (task);
		REF_INIT_RETAIN (cbd, lua_spf_dtor);

		if (!rspamd_spf_resolve (task, spf_lua_lib_callback, cbd, spf_cred)) {
			msg_info_task ("cannot make spf request for %s", spf_cred->domain);
			lua_spf_push_result (cbd, RSPAMD_SPF_RESOLVED_TEMP_FAILED,
					NULL, "DNS failed");
			REF_RELEASE (cbd);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_spf_record_dtor (lua_State *L)
{
	struct spf_resolved *record =
			* (struct spf_resolved **)rspamd_lua_check_udata (L, 1,
					SPF_RECORD_CLASS);

	if (record) {
		spf_record_unref (record);
	}

	return 0;
}