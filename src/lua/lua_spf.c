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

LUA_FUNCTION_DEF (spf_record, check_ip);
LUA_FUNCTION_DEF (spf_record, dtor);
LUA_FUNCTION_DEF (spf_record, get_domain);
LUA_FUNCTION_DEF (spf_record, get_elts);
LUA_FUNCTION_DEF (spf_record, get_ttl);
LUA_FUNCTION_DEF (spf_record, get_timestamp);
LUA_FUNCTION_DEF (spf_record, get_digest);

static luaL_reg rspamd_spf_f[] = {
		LUA_INTERFACE_DEF (spf, resolve),
		LUA_INTERFACE_DEF (spf, config),
		{NULL, NULL},
};

static luaL_reg rspamd_spf_record_m[] = {
		LUA_INTERFACE_DEF (spf_record, check_ip),
		LUA_INTERFACE_DEF (spf_record, get_domain),
		LUA_INTERFACE_DEF (spf_record, get_ttl),
		LUA_INTERFACE_DEF (spf_record, get_digest),
		LUA_INTERFACE_DEF (spf_record, get_elts),
		LUA_INTERFACE_DEF (spf_record, get_timestamp),
		{"__gc", lua_spf_record_dtor},
		{NULL, NULL},
};

struct rspamd_lua_spf_cbdata {
	struct rspamd_task *task;
	lua_State *L;
	struct rspamd_symcache_item *item;
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

	lua_setfield (L, -2, "policy");

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
		if (cbd->item) {
			rspamd_symcache_item_async_dec_check (cbd->task, cbd->item,
					"lua_spf");
		}
	}
}

static void
spf_lua_lib_callback (struct spf_resolved *record, struct rspamd_task *task,
					 gpointer ud)
{
	struct rspamd_lua_spf_cbdata *cbd = (struct rspamd_lua_spf_cbdata *)ud;

	if (record) {
		if ((record->flags & RSPAMD_SPF_RESOLVED_NA)) {
			lua_spf_push_result (cbd, RSPAMD_SPF_RESOLVED_NA, NULL,
					"no SPF record");
		}
		else if (record->elts->len == 0) {
			if (record->flags & RSPAMD_SPF_RESOLVED_PERM_FAILED) {
				lua_spf_push_result (cbd, RSPAMD_SPF_RESOLVED_PERM_FAILED, NULL,
			"bad SPF record");
			}
			else if ((record->flags & RSPAMD_SPF_RESOLVED_TEMP_FAILED)) {
				lua_spf_push_result (cbd, RSPAMD_SPF_RESOLVED_TEMP_FAILED, NULL,
						"temporary DNS error");
			}
			else {
				lua_spf_push_result (cbd, RSPAMD_SPF_RESOLVED_PERM_FAILED, NULL,
						"empty SPF record");
			}
		}
		else if (record->domain) {
			spf_record_ref (record);
			lua_spf_push_result (cbd, record->flags, record, NULL);
			spf_record_unref (record);
		}
		else {
			lua_spf_push_result (cbd, RSPAMD_SPF_RESOLVED_PERM_FAILED, NULL,
					"internal error: non empty record for no domain");
		}
	}
	else {
		lua_spf_push_result (cbd, RSPAMD_SPF_RESOLVED_PERM_FAILED, NULL,
				"internal error: no record");
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
		cbd->item = rspamd_symcache_get_cur_item (task);

		if (cbd->item) {
			rspamd_symcache_item_async_inc (task, cbd->item, "lua_spf");
		}
		REF_INIT_RETAIN (cbd, lua_spf_dtor);

		if (!rspamd_spf_resolve (task, spf_lua_lib_callback, cbd, spf_cred)) {
			msg_info_task ("cannot make spf request for %s",
					spf_cred ? spf_cred->domain : "empty domain");
			if (spf_cred) {
				lua_spf_push_result (cbd, RSPAMD_SPF_RESOLVED_TEMP_FAILED,
						NULL, "DNS failed");
			}
			else {
				lua_spf_push_result (cbd, RSPAMD_SPF_RESOLVED_NA,
						NULL, "No domain");
			}
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
	struct spf_resolved *record;

	RSPAMD_LUA_CHECK_UDATA_PTR_OR_RETURN(L, 1, SPF_RECORD_CLASS,
			struct spf_resolved,
			record);

	if (record) {
		spf_record_unref (record);
	}

	return 0;
}

static void
lua_spf_push_spf_addr (lua_State *L, struct spf_addr *addr)
{
	gchar *addr_mask;

	lua_createtable (L, 0, 4);

	lua_pushinteger (L, addr->mech);
	lua_setfield (L, -2, "result");
	lua_pushinteger (L, addr->flags);
	lua_setfield (L, -2, "flags");

	if (addr->spf_string) {
		lua_pushstring (L, addr->spf_string);
		lua_setfield (L, -2, "str");
	}

	addr_mask = spf_addr_mask_to_string (addr);

	if (addr_mask) {
		lua_pushstring (L, addr_mask);
		lua_setfield (L, -2, "addr");
		g_free (addr_mask);
	}
}

static gint
spf_check_element (lua_State *L, struct spf_resolved *rec, struct spf_addr *addr,
				   struct rspamd_lua_ip *ip)
{
	gboolean res = FALSE;
	const guint8 *s, *d;
	guint af, mask, bmask, addrlen;


	if (addr->flags & RSPAMD_SPF_FLAG_TEMPFAIL) {
		/* Ignore failed addresses */

		return -1;
	}

	af = rspamd_inet_address_get_af (ip->addr);
	/* Basic comparing algorithm */
	if (((addr->flags & RSPAMD_SPF_FLAG_IPV6) && af == AF_INET6) ||
		((addr->flags & RSPAMD_SPF_FLAG_IPV4) && af == AF_INET)) {
		d = rspamd_inet_address_get_hash_key (ip->addr, &addrlen);

		if (af == AF_INET6) {
			s = (const guint8 *)addr->addr6;
			mask = addr->m.dual.mask_v6;
		}
		else {
			s = (const guint8 *)addr->addr4;
			mask = addr->m.dual.mask_v4;
		}

		/* Compare the first bytes */
		bmask = mask / CHAR_BIT;
		if (mask > addrlen * CHAR_BIT) {
			/* XXX: add logging */
		}
		else if (memcmp (s, d, bmask) == 0) {
			if (bmask * CHAR_BIT < mask) {
				/* Compare the remaining bits */
				s += bmask;
				d += bmask;
				mask = (0xff << (CHAR_BIT - (mask - bmask * 8))) & 0xff;

				if ((*s & mask) == (*d & mask)) {
					res = TRUE;
				}
			}
			else {
				res = TRUE;
			}
		}
	}
	else {
		if (addr->flags & RSPAMD_SPF_FLAG_ANY) {
			res = TRUE;
		}
		else {
			res = FALSE;
		}
	}

	if (res) {
		if (addr->flags & RSPAMD_SPF_FLAG_ANY) {
			if (rec->flags & RSPAMD_SPF_RESOLVED_PERM_FAILED) {
				lua_pushboolean (L, false);
				lua_pushinteger (L, RSPAMD_SPF_RESOLVED_PERM_FAILED);
				lua_pushfstring (L, "%cany", spf_mech_char (addr->mech));
			}
			else if (rec->flags & RSPAMD_SPF_RESOLVED_TEMP_FAILED) {
				lua_pushboolean (L, false);
				lua_pushinteger (L, RSPAMD_SPF_RESOLVED_TEMP_FAILED);
				lua_pushfstring (L, "%cany", spf_mech_char (addr->mech));
			}
			else {
				lua_pushboolean (L, true);
				lua_pushinteger (L, addr->mech);
				lua_spf_push_spf_addr (L, addr);
			}
		}
		else {
			lua_pushboolean (L, true);
			lua_pushinteger (L, addr->mech);
			lua_spf_push_spf_addr (L, addr);
		}

		return 3;
	}

	return -1;
}

/***
 * @method rspamd_spf_record:check_ip(ip)
 * Checks the processed record versus a specific IP address. This function
 * returns 3 values normally:
 * 1. Boolean check result
 * 2. If result is `false` then the second value is the error flag (e.g. rspamd_spf.flags.temp_fail), otherwise it will be an SPF method
 * 3. If result is `false` then this will be an error string, otherwise - an SPF string (e.g. `mx` or `ip4:x.y.z.1`)
 * @param {rspamd_ip|string} ip address
 * @return {result,flag_or_policy,error_or_addr} - triplet
*/
static gint
lua_spf_record_check_ip (lua_State *L)
{
	struct spf_resolved *record;
	RSPAMD_LUA_CHECK_UDATA_PTR_OR_RETURN(L, 1, SPF_RECORD_CLASS,
			struct spf_resolved,
			record);
	struct rspamd_lua_ip *ip = NULL;
	gint nres = 0;
	gboolean need_free_ip = FALSE;

	if (lua_type (L, 2) == LUA_TUSERDATA) {
		ip = lua_check_ip (L, 2);
	}
	else if (lua_type (L, 2) == LUA_TSTRING) {
		const gchar *ip_str;
		gsize iplen;

		ip = g_malloc0 (sizeof (struct rspamd_lua_ip));
		ip_str = lua_tolstring (L, 2, &iplen);

		if (!rspamd_parse_inet_address (&ip->addr,
				ip_str, iplen, RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
			g_free (ip);
			ip = NULL;
		}
		else {
			need_free_ip = TRUE;
		}
	}

	if (record && ip && ip->addr) {
		for (guint i = 0; i < record->elts->len; i ++) {
			struct spf_addr *addr = &g_array_index (record->elts, struct spf_addr, i);
			if ((nres = spf_check_element (L, record, addr, ip)) > 0) {
				if (need_free_ip) {
					g_free (ip);
				}

				return nres;
			}
		}
	}
	else {
		if (need_free_ip) {
			g_free (ip);
		}

		return luaL_error (L, "invalid arguments");
	}

	if (need_free_ip) {
		g_free (ip);
	}

	/* If we are here it means that there is no ALL record */
	/*
	 * According to https://tools.ietf.org/html/rfc7208#section-4.7 it means
	 * SPF neutral
	 */
	struct spf_addr fake_all;

	fake_all.mech = SPF_NEUTRAL;
	fake_all.flags = RSPAMD_SPF_FLAG_ANY;
	fake_all.spf_string = "all";

	lua_pushboolean (L, true);
	lua_pushinteger (L, SPF_NEUTRAL);
	lua_spf_push_spf_addr (L, &fake_all);

	return 3;
}

/***
 * @method rspamd_spf_record:get_domain()
 * Returns domain for the specific spf record
*/
static gint
lua_spf_record_get_domain (lua_State *L)
{
	struct spf_resolved *record;
	RSPAMD_LUA_CHECK_UDATA_PTR_OR_RETURN(L, 1, SPF_RECORD_CLASS,
			struct spf_resolved,
			record);

	if (record) {
		lua_pushstring (L, record->domain);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/***
 * @method rspamd_spf_record:get_ttl()
 * Returns ttl for the specific spf record
*/
static gint
lua_spf_record_get_ttl (lua_State *L)
{
	struct spf_resolved *record;
	RSPAMD_LUA_CHECK_UDATA_PTR_OR_RETURN(L, 1, SPF_RECORD_CLASS,
			struct spf_resolved,
			record);

	if (record) {
		lua_pushinteger (L, record->ttl);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/***
 * @method rspamd_spf_record:get_timestamp()
 * Returns ttl for the specific spf record
*/
static gint
lua_spf_record_get_timestamp (lua_State *L)
{
	struct spf_resolved *record;
	RSPAMD_LUA_CHECK_UDATA_PTR_OR_RETURN(L, 1, SPF_RECORD_CLASS,
			struct spf_resolved,
			record);

	if (record) {
		lua_pushnumber (L, record->timestamp);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/***
 * @method rspamd_spf_record:get_digest()
 * Returns string hex representation of the record digest (fast hash function)
*/
static gint
lua_spf_record_get_digest (lua_State *L)
{
	struct spf_resolved *record;
	RSPAMD_LUA_CHECK_UDATA_PTR_OR_RETURN(L, 1, SPF_RECORD_CLASS,
			struct spf_resolved,
			record);

	if (record) {
		gchar hexbuf[64];

		rspamd_snprintf (hexbuf, sizeof (hexbuf), "%xuL", record->digest);
		lua_pushstring (L, hexbuf);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/***
 * @method rspamd_spf_record:get_elts()
 * Returns a list of all elements in an SPF record. Each element is a table with the
 * following fields:
 *
 * - result - mech flag from rspamd_spf.results
 * - flags - all flags
 * - addr - address and mask as a string
 * - str - string representation (if available)
*/
static gint
lua_spf_record_get_elts (lua_State *L)
{
	struct spf_resolved *record;
	RSPAMD_LUA_CHECK_UDATA_PTR_OR_RETURN(L, 1, SPF_RECORD_CLASS,
			struct spf_resolved,
			record);

	if (record) {
		guint i;
		struct spf_addr *addr;

		lua_createtable (L, record->elts->len, 0);

		for (i = 0; i < record->elts->len; i ++) {
			addr = (struct spf_addr *)&g_array_index (record->elts,
					struct spf_addr, i);
			lua_spf_push_spf_addr (L, addr);

			lua_rawseti (L, -2, i + 1);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/***
 * @function rspamd_spf.config(object)
 * Configures SPF library according to the UCL config
 * @param {table} object configuration object
*/
gint
lua_spf_config (lua_State * L)
{
	ucl_object_t *config_obj = ucl_object_lua_import (L, 1);

	if (config_obj) {
		spf_library_config (config_obj);
		ucl_object_unref (config_obj); /* As we copy data all the time */
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}