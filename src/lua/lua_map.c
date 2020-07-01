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

#include "lua_common.h"
#include "libserver/maps/map.h"
#include "libserver/maps/map_helpers.h"
#include "libserver/maps/map_private.h"
#include "contrib/libucl/lua_ucl.h"

/***
 * This module is used to manage rspamd maps and map like objects
 *
 * @module rspamd_map
 *
 * All maps could be obtained by function `rspamd_config:get_maps()`
 * Also see [`lua_maps` module description](lua_maps.html).
 */

/***
 * @method map:get_key(in)
 * Variable method for different types of maps:
 *
 * - For hash maps it returns boolean and accepts string
 * - For kv maps it returns string (or nil) and accepts string
 * - For radix maps it returns boolean and accepts IP address (as object, string or number)
 *
 * @param {vary} in input to check
 * @return {bool|string} if a value is found then this function returns string or `True` if not - then it returns `nil` or `False`
 */
LUA_FUNCTION_DEF (map, get_key);


/***
 * @method map:is_signed()
 * Returns `True` if a map is signed
 * @return {bool} signed value
 */
LUA_FUNCTION_DEF (map, is_signed);

/***
 * @method map:get_proto()
 * Returns protocol of map as string:
 *
 * - `http`: for HTTP map
 * - `file`: for file map
 * @return {string} string representation of the map protocol
 */
LUA_FUNCTION_DEF (map, get_proto);

/***
 * @method map:get_sign_key()
 * Returns pubkey used for signing as base32 string or nil
 * @return {string} base32 encoded string or nil
 */
LUA_FUNCTION_DEF (map, get_sign_key);

/***
 * @method map:set_sign_key(key)
 * Set trusted key for signatures for this map
 * @param {string} key base32 encoded string or nil
 */
LUA_FUNCTION_DEF (map, set_sign_key);

/***
 * @method map:set_callback(cb)
 * Set callback for a specified callback map.
 * @param {function} cb map callback function
 */
LUA_FUNCTION_DEF (map, set_callback);

/***
 * @method map:get_uri()
 * Get uri for a specified map
 * @return {string} map's URI
 */
LUA_FUNCTION_DEF (map, get_uri);

/***
 * @method map:get_stats(reset)
 * Get statistics for specific map. It returns table in form:
 *  [key] => [nhits]
 * @param {boolean} reset reset stats if true
 * @return {table} map's stat
 */
LUA_FUNCTION_DEF (map, get_stats);

/***
 * @method map:get_data_digest()
 * Get data digest for specific map
 * @return {string} 64 bit number represented as string (due to Lua limitations)
 */
LUA_FUNCTION_DEF (map, get_data_digest);

/***
 * @method map:get_nelts()
 * Get number of elements for specific map
 * @return {number} number of elements in the map
 */
LUA_FUNCTION_DEF (map, get_nelts);

static const struct luaL_reg maplib_m[] = {
	LUA_INTERFACE_DEF (map, get_key),
	LUA_INTERFACE_DEF (map, is_signed),
	LUA_INTERFACE_DEF (map, get_proto),
	LUA_INTERFACE_DEF (map, get_sign_key),
	LUA_INTERFACE_DEF (map, set_sign_key),
	LUA_INTERFACE_DEF (map, set_callback),
	LUA_INTERFACE_DEF (map, get_uri),
	LUA_INTERFACE_DEF (map, get_stats),
	LUA_INTERFACE_DEF (map, get_data_digest),
	LUA_INTERFACE_DEF (map, get_nelts),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

struct lua_map_callback_data {
	lua_State *L;
	gint ref;
	gboolean opaque;
	rspamd_fstring_t *data;
	struct rspamd_lua_map *lua_map;
};

struct rspamd_lua_map  *
lua_check_map (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{map}");
	luaL_argcheck (L, ud != NULL, pos, "'map' expected");
	return ud ? *((struct rspamd_lua_map **)ud) : NULL;
}

gint
lua_config_add_radix_map (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *map_line, *description;
	struct rspamd_lua_map *map, **pmap;
	struct rspamd_map *m;

	if (cfg) {
		map_line = luaL_checkstring (L, 2);
		description = lua_tostring (L, 3);
		map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
		map->data.radix = NULL;
		map->type = RSPAMD_LUA_MAP_RADIX;

		if ((m = rspamd_map_add (cfg, map_line, description,
				rspamd_radix_read,
				rspamd_radix_fin,
				rspamd_radix_dtor,
				(void **)&map->data.radix,
				NULL, RSPAMD_MAP_DEFAULT)) == NULL) {
			msg_warn_config ("invalid radix map %s", map_line);
			lua_pushnil (L);

			return 1;
		}

		map->map = m;
		m->lua_map = map;
		pmap = lua_newuserdata (L, sizeof (void *));
		*pmap = map;
		rspamd_lua_setclass (L, "rspamd{map}", -1);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;

}

gint
lua_config_radix_from_config (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *mname, *optname;
	const ucl_object_t *obj;
	struct rspamd_lua_map *map, **pmap;
	ucl_object_t *fake_obj;
	struct rspamd_map *m;

	if (!cfg) {
		return luaL_error (L, "invalid arguments");
	}

	mname = luaL_checkstring (L, 2);
	optname = luaL_checkstring (L, 3);

	if (mname && optname) {
		obj = rspamd_config_get_module_opt (cfg, mname, optname);

		if (obj) {
			map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
			map->data.radix = NULL;
			map->type = RSPAMD_LUA_MAP_RADIX;

			fake_obj = ucl_object_typed_new (UCL_OBJECT);
			ucl_object_insert_key (fake_obj, ucl_object_ref (obj),
					"data", 0, false);
			ucl_object_insert_key (fake_obj, ucl_object_fromstring ("static"),
					"url", 0, false);

			if ((m = rspamd_map_add_from_ucl (cfg, fake_obj, "static radix map",
					rspamd_radix_read,
					rspamd_radix_fin,
					rspamd_radix_dtor,
					(void **)&map->data.radix,
					NULL, RSPAMD_MAP_DEFAULT)) == NULL) {
				msg_err_config ("invalid radix map static");
				lua_pushnil (L);
				ucl_object_unref (fake_obj);

				return 1;
			}

			ucl_object_unref (fake_obj);
			pmap = lua_newuserdata (L, sizeof (void *));
			map->map = m;
			m->lua_map = map;
			*pmap = map;
			rspamd_lua_setclass (L, "rspamd{map}", -1);
		}
		else {
			msg_warn_config ("Couldnt find config option [%s][%s]", mname,
					optname);
			lua_pushnil (L);
		}

	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}


gint
lua_config_radix_from_ucl (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	ucl_object_t *obj;
	struct rspamd_lua_map *map, **pmap;
	ucl_object_t *fake_obj;
	struct rspamd_map *m;

	if (!cfg) {
		return luaL_error (L, "invalid arguments");
	}

	obj = ucl_object_lua_import (L, 2);

	if (obj) {
		map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
		map->data.radix = NULL;
		map->type = RSPAMD_LUA_MAP_RADIX;

		fake_obj = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (fake_obj, ucl_object_ref (obj),
				"data", 0, false);
		ucl_object_insert_key (fake_obj, ucl_object_fromstring ("static"),
				"url", 0, false);

		if ((m = rspamd_map_add_from_ucl (cfg, fake_obj, "static radix map",
				rspamd_radix_read,
				rspamd_radix_fin,
				rspamd_radix_dtor,
				(void **)&map->data.radix,
				NULL, RSPAMD_MAP_DEFAULT)) == NULL) {
			msg_err_config ("invalid radix map static");
			lua_pushnil (L);
			ucl_object_unref (fake_obj);
			ucl_object_unref (obj);

			return 1;
		}

		ucl_object_unref (fake_obj);
		ucl_object_unref (obj);
		pmap = lua_newuserdata (L, sizeof (void *));
		map->map = m;
		m->lua_map = map;
		*pmap = map;
		rspamd_lua_setclass (L, "rspamd{map}", -1);

	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

gint
lua_config_add_hash_map (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *map_line, *description;
	struct rspamd_lua_map *map, **pmap;
	struct rspamd_map *m;

	if (cfg) {
		map_line = luaL_checkstring (L, 2);
		description = lua_tostring (L, 3);
		map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
		map->data.hash = NULL;
		map->type = RSPAMD_LUA_MAP_SET;

		if ((m = rspamd_map_add (cfg, map_line, description,
				rspamd_kv_list_read,
				rspamd_kv_list_fin,
				rspamd_kv_list_dtor,
				(void **)&map->data.hash,
				NULL, RSPAMD_MAP_DEFAULT)) == NULL) {
			msg_warn_config ("invalid set map %s", map_line);
			lua_pushnil (L);
			return 1;
		}

		map->map = m;
		m->lua_map = map;
		pmap = lua_newuserdata (L, sizeof (void *));
		*pmap = map;
		rspamd_lua_setclass (L, "rspamd{map}", -1);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;

}

gint
lua_config_add_kv_map (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *map_line, *description;
	struct rspamd_lua_map *map, **pmap;
	struct rspamd_map *m;

	if (cfg) {
		map_line = luaL_checkstring (L, 2);
		description = lua_tostring (L, 3);
		map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
		map->data.hash = NULL;
		map->type = RSPAMD_LUA_MAP_HASH;

		if ((m = rspamd_map_add (cfg, map_line, description,
				rspamd_kv_list_read,
				rspamd_kv_list_fin,
				rspamd_kv_list_dtor,
				(void **)&map->data.hash,
				NULL, RSPAMD_MAP_DEFAULT)) == NULL) {
			msg_warn_config ("invalid hash map %s", map_line);
			lua_pushnil (L);

			return 1;
		}

		map->map = m;
		m->lua_map = map;
		pmap = lua_newuserdata (L, sizeof (void *));
		*pmap = map;
		rspamd_lua_setclass (L, "rspamd{map}", -1);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}


static gchar *
lua_map_read (gchar *chunk, gint len,
	struct map_cb_data *data,
	gboolean final)
{
	struct lua_map_callback_data *cbdata, *old;

	if (data->cur_data == NULL) {
		old = (struct lua_map_callback_data *)data->prev_data;
		cbdata = old;
		cbdata->L = old->L;
		cbdata->ref = old->ref;
		cbdata->lua_map = old->lua_map;
		data->cur_data = cbdata;
		data->prev_data = NULL;
	}
	else {
		cbdata = (struct lua_map_callback_data *)data->cur_data;
	}

	if (cbdata->data == NULL) {
		cbdata->data = rspamd_fstring_new_init (chunk, len);
	}
	else {
		cbdata->data = rspamd_fstring_append (cbdata->data, chunk, len);
	}

	return NULL;
}

static void
lua_map_fin (struct map_cb_data *data, void **target)
{
	struct lua_map_callback_data *cbdata;
	struct rspamd_lua_map **pmap;
	struct rspamd_map *map;

	map = data->map;

	if (data->cur_data) {
		cbdata = (struct lua_map_callback_data *)data->cur_data;
	}
	else {
		msg_err_map ("no data read for map");
		return;
	}

	if (cbdata->ref == -1) {
		msg_err_map ("map has no callback set");
	}
	else if (cbdata->data != NULL && cbdata->data->len != 0) {

		lua_pushcfunction (cbdata->L, &rspamd_lua_traceback);
		int err_idx = lua_gettop (cbdata->L);

		lua_rawgeti (cbdata->L, LUA_REGISTRYINDEX, cbdata->ref);

		if (!cbdata->opaque) {
			lua_pushlstring (cbdata->L, cbdata->data->str, cbdata->data->len);
		}
		else {
			struct rspamd_lua_text *t;

			t = lua_newuserdata (cbdata->L, sizeof (*t));
			rspamd_lua_setclass (cbdata->L, "rspamd{text}", -1);
			t->flags = 0;
			t->len = cbdata->data->len;
			t->start = cbdata->data->str;
		}

		pmap = lua_newuserdata (cbdata->L, sizeof (void *));
		*pmap = cbdata->lua_map;
		rspamd_lua_setclass (cbdata->L, "rspamd{map}", -1);

		gint ret = lua_pcall (cbdata->L, 2, 0, err_idx);

		if (ret != 0) {
			msg_info_map ("call to %s failed (%d): %s", "map fin function",
				ret,
				lua_tostring (cbdata->L, -1));
		}

		lua_settop (cbdata->L, err_idx - 1);
	}

	cbdata->data = rspamd_fstring_assign (cbdata->data, "", 0);

	if (target) {
		*target = data->cur_data;
	}

	if (data->prev_data) {
		data->prev_data = NULL;
	}
}

static void
lua_map_dtor (struct map_cb_data *data)
{
	struct lua_map_callback_data *cbdata;

	if (data->cur_data) {
		cbdata = (struct lua_map_callback_data *)data->cur_data;
		if (cbdata->ref != -1) {
			luaL_unref (cbdata->L, LUA_REGISTRYINDEX, cbdata->ref);
		}

		if (cbdata->data) {
			rspamd_fstring_free (cbdata->data);
		}
	}
}

gint
lua_config_add_map (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const char *description = NULL;
	const gchar *type = NULL;
	ucl_object_t *map_obj = NULL;
	struct lua_map_callback_data *cbdata;
	struct rspamd_lua_map *map, **pmap;
	struct rspamd_map *m;
	gboolean opaque_data = FALSE;
	int cbidx = -1, ret;
	GError *err = NULL;

	if (cfg) {
		if (!rspamd_lua_parse_table_arguments (L, 2, &err,
				RSPAMD_LUA_PARSE_ARGUMENTS_DEFAULT,
				"*url=O;description=S;callback=F;type=S;opaque_data=B",
				&map_obj, &description, &cbidx, &type, &opaque_data)) {
			ret = luaL_error (L, "invalid table arguments: %s", err->message);
			g_error_free (err);
			if (map_obj) {
				ucl_object_unref (map_obj);
			}

			return ret;
		}

		g_assert (map_obj != NULL);

		if (type == NULL && cbidx != -1) {
			type = "callback";
		}
		else if (type == NULL) {
			return luaL_error (L, "invalid map type");
		}

		if (strcmp (type, "callback") == 0) {
			map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
			map->type = RSPAMD_LUA_MAP_CALLBACK;
			map->data.cbdata = rspamd_mempool_alloc0 (cfg->cfg_pool,
					sizeof (*map->data.cbdata));
			cbdata = map->data.cbdata;
			cbdata->L = L;
			cbdata->data = NULL;
			cbdata->lua_map = map;
			cbdata->ref = cbidx;
			cbdata->opaque = opaque_data;

			if ((m = rspamd_map_add_from_ucl (cfg, map_obj, description,
					lua_map_read,
					lua_map_fin,
					lua_map_dtor,
					(void **)&map->data.cbdata,
					NULL, RSPAMD_MAP_DEFAULT)) == NULL) {

				if (cbidx != -1) {
					luaL_unref (L, LUA_REGISTRYINDEX, cbidx);
				}

				if (map_obj) {
					ucl_object_unref (map_obj);
				}

				lua_pushnil (L);

				return 1;
			}
			m->lua_map = map;
		}
		else if (strcmp (type, "set") == 0) {
			map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
			map->data.hash = NULL;
			map->type = RSPAMD_LUA_MAP_SET;

			if ((m = rspamd_map_add_from_ucl (cfg, map_obj, description,
					rspamd_kv_list_read,
					rspamd_kv_list_fin,
					rspamd_kv_list_dtor,
					(void **)&map->data.hash,
					NULL, RSPAMD_MAP_DEFAULT)) == NULL) {
				lua_pushnil (L);
				ucl_object_unref (map_obj);

				return 1;
			}
			m->lua_map = map;
		}
		else if (strcmp (type, "map") == 0 || strcmp (type, "hash") == 0) {
			map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
			map->data.hash = NULL;
			map->type = RSPAMD_LUA_MAP_HASH;

			if ((m = rspamd_map_add_from_ucl (cfg, map_obj, description,
					rspamd_kv_list_read,
					rspamd_kv_list_fin,
					rspamd_kv_list_dtor,
					(void **)&map->data.hash,
					NULL, RSPAMD_MAP_DEFAULT)) == NULL) {
				lua_pushnil (L);
				ucl_object_unref (map_obj);

				return 1;
			}
			m->lua_map = map;
		}
		else if (strcmp (type, "radix") == 0) {
			map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
			map->data.radix = NULL;
			map->type = RSPAMD_LUA_MAP_RADIX;

			if ((m = rspamd_map_add_from_ucl (cfg, map_obj, description,
					rspamd_radix_read,
					rspamd_radix_fin,
					rspamd_radix_dtor,
					(void **)&map->data.radix,
					NULL, RSPAMD_MAP_DEFAULT)) == NULL) {
				lua_pushnil (L);
				ucl_object_unref (map_obj);

				return 1;
			}
			m->lua_map = map;
		}
		else if (strcmp (type, "regexp") == 0) {
			map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
			map->data.re_map = NULL;
			map->type = RSPAMD_LUA_MAP_REGEXP;

			if ((m = rspamd_map_add_from_ucl (cfg, map_obj, description,
					rspamd_regexp_list_read_single,
					rspamd_regexp_list_fin,
					rspamd_regexp_list_dtor,
					(void **) &map->data.re_map,
					NULL, RSPAMD_MAP_DEFAULT)) == NULL) {
				lua_pushnil (L);
				ucl_object_unref (map_obj);

				return 1;
			}
			m->lua_map = map;
		}
		else if (strcmp (type, "regexp_multi") == 0) {
			map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
			map->data.re_map = NULL;
			map->type = RSPAMD_LUA_MAP_REGEXP_MULTIPLE;

			if ((m = rspamd_map_add_from_ucl (cfg, map_obj, description,
					rspamd_regexp_list_read_multiple,
					rspamd_regexp_list_fin,
					rspamd_regexp_list_dtor,
					(void **) &map->data.re_map,
					NULL, RSPAMD_MAP_DEFAULT)) == NULL) {
				lua_pushnil (L);
				ucl_object_unref (map_obj);

				return 1;
			}
			m->lua_map = map;
		}
		else if (strcmp (type, "glob") == 0) {
			map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
			map->data.re_map = NULL;
			map->type = RSPAMD_LUA_MAP_REGEXP;

			if ((m = rspamd_map_add_from_ucl (cfg, map_obj, description,
					rspamd_glob_list_read_single,
					rspamd_regexp_list_fin,
					rspamd_regexp_list_dtor,
					(void **) &map->data.re_map,
					NULL, RSPAMD_MAP_DEFAULT)) == NULL) {
				lua_pushnil (L);
				ucl_object_unref (map_obj);

				return 1;
			}
			m->lua_map = map;
		}
		else if (strcmp (type, "glob_multi") == 0) {
			map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
			map->data.re_map = NULL;
			map->type = RSPAMD_LUA_MAP_REGEXP_MULTIPLE;

			if ((m = rspamd_map_add_from_ucl (cfg, map_obj, description,
					rspamd_glob_list_read_multiple,
					rspamd_regexp_list_fin,
					rspamd_regexp_list_dtor,
					(void **) &map->data.re_map,
					NULL, RSPAMD_MAP_DEFAULT)) == NULL) {
				lua_pushnil (L);
				ucl_object_unref (map_obj);

				return 1;
			}
			m->lua_map = map;
		}
		else if (strcmp (type, "cdb") == 0) {
			map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
			map->data.cdb_map = NULL;
			map->type = RSPAMD_LUA_MAP_CDB;

			if ((m = rspamd_map_add_from_ucl (cfg, map_obj, description,
					rspamd_cdb_list_read,
					rspamd_cdb_list_fin,
					rspamd_cdb_list_dtor,
					(void **) &map->data.cdb_map,
					NULL, RSPAMD_MAP_FILE_ONLY|RSPAMD_MAP_FILE_NO_READ)) == NULL) {
				lua_pushnil (L);
				ucl_object_unref (map_obj);

				return 1;
			}
			m->lua_map = map;
		}
		else {
			ret = luaL_error (L, "invalid arguments: unknown type '%s'", type);
			ucl_object_unref (map_obj);

			return ret;
		}

		map->map = m;
		pmap = lua_newuserdata (L, sizeof (void *));
		*pmap = map;
		rspamd_lua_setclass (L, "rspamd{map}", -1);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	ucl_object_unref (map_obj);

	return 1;
}

gint
lua_config_get_maps (lua_State*L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	struct rspamd_lua_map *map, **pmap;
	struct rspamd_map *m;
	gint i = 1;
	GList *cur;

	if (cfg) {
		lua_newtable (L);
		cur = g_list_first (cfg->maps);

		while (cur) {
			m = cur->data;

			if (m->lua_map) {
				map = m->lua_map;
			}
			else {
				/* Implement heuristic */
				map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));

				if (m->read_callback == rspamd_radix_read) {
					map->type = RSPAMD_LUA_MAP_RADIX;
					map->data.radix = *m->user_data;
				}
				else if (m->read_callback == rspamd_kv_list_read) {
					map->type = RSPAMD_LUA_MAP_HASH;
					map->data.hash = *m->user_data;
				}
				else {
					map->type = RSPAMD_LUA_MAP_UNKNOWN;
				}

				map->map = m;
				m->lua_map = map;
			}

			pmap = lua_newuserdata (L, sizeof (*pmap));
			*pmap = map;
			rspamd_lua_setclass (L, "rspamd{map}", -1);
			lua_rawseti (L, -2, i);

			cur = g_list_next (cur);
			i ++;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static const gchar *
lua_map_process_string_key (lua_State *L, gint pos, gsize *len)
{
	struct rspamd_lua_text *t;

	if (lua_type (L, pos) == LUA_TSTRING) {
		return lua_tolstring (L, pos, len);
	}
	else if (lua_type (L, pos) == LUA_TUSERDATA) {
		t = lua_check_text (L, pos);

		if (t) {
			*len = t->len;
			return t->start;
		}
	}

	return NULL;
}

/* Radix and hash table functions */
static gint
lua_map_get_key (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_map *map = lua_check_map (L, 1);
	struct rspamd_radix_map_helper *radix;
	struct rspamd_lua_ip *addr = NULL;
	const gchar *key, *value = NULL;
	gpointer ud;
	gsize len;
	guint32 key_num = 0;
	gboolean ret = FALSE;

	if (map) {
		if (map->type == RSPAMD_LUA_MAP_RADIX) {
			radix = map->data.radix;

			if (lua_type (L, 2) == LUA_TSTRING) {
				const gchar *addr_str;

				addr_str = luaL_checklstring (L, 2, &len);
				addr = g_alloca (sizeof (*addr));
				addr->addr = g_alloca (rspamd_inet_address_storage_size ());

				if (!rspamd_parse_inet_address_ip (addr_str, len, addr->addr)) {
					addr = NULL;
				}
			}
			else if (lua_type (L, 2) == LUA_TUSERDATA) {
				ud = rspamd_lua_check_udata (L, 2, "rspamd{ip}");
				if (ud != NULL) {
					addr = *((struct rspamd_lua_ip **)ud);

					if (addr->addr == NULL) {
						addr = NULL;
					}
				}
				else {
					msg_err ("invalid userdata type provided, rspamd{ip} expected");
				}
			}
			else if (lua_type (L, 2) == LUA_TNUMBER) {
				key_num = luaL_checkinteger (L, 2);
				key_num = htonl (key_num);
			}

			if (radix) {
				gconstpointer p = NULL;

				if (addr != NULL) {
					if ((p = rspamd_match_radix_map_addr (radix, addr->addr))
							!=  NULL) {
						ret = TRUE;
					}
					else {
						p = 0;
					}
				}
				else if (key_num != 0) {
					if ((p = rspamd_match_radix_map (radix,
							(guint8 *)&key_num, sizeof (key_num))) != NULL) {
						ret = TRUE;
					}
					else {
						p = 0;
					}
				}

				value = (const char *)p;
			}

			if (ret) {
				lua_pushstring (L, value);
				return 1;
			}
		}
		else if (map->type == RSPAMD_LUA_MAP_SET) {
			key = lua_map_process_string_key (L, 2, &len);

			if (key && map->data.hash) {
				ret = rspamd_match_hash_map (map->data.hash, key, len) != NULL;
			}
		}
		else if (map->type == RSPAMD_LUA_MAP_REGEXP) {
			key = lua_map_process_string_key (L, 2, &len);

			if (key && map->data.re_map) {
				value = rspamd_match_regexp_map_single (map->data.re_map, key,
						len);

				if (value) {
					lua_pushstring (L, value);
					return 1;
				}
			}
		}
		else if (map->type == RSPAMD_LUA_MAP_REGEXP_MULTIPLE) {
			GPtrArray *ar;
			guint i;
			const gchar *val;

			key = lua_map_process_string_key (L, 2, &len);

			if (key && map->data.re_map) {
				ar = rspamd_match_regexp_map_all (map->data.re_map, key,
						len);

				if (ar) {
					lua_createtable (L, ar->len, 0);

					PTR_ARRAY_FOREACH (ar, i, val) {
						lua_pushstring (L, val);
						lua_rawseti (L, -2, i + 1);
					}

					g_ptr_array_free (ar, TRUE);

					return 1;
				}
			}
		}
		else if (map->type == RSPAMD_LUA_MAP_HASH) {
			/* key-value map */
			key = lua_map_process_string_key (L, 2, &len);

			if (key && map->data.hash) {
				value = rspamd_match_hash_map (map->data.hash, key, len);
			}

			if (value) {
				lua_pushstring (L, value);
				return 1;
			}
		}
		else if (map->type == RSPAMD_LUA_MAP_CDB) {
			/* cdb map */
			const rspamd_ftok_t *tok = NULL;

			key = lua_map_process_string_key (L, 2, &len);

			if (key && map->data.cdb_map) {
				tok = rspamd_match_cdb_map (map->data.cdb_map, key, len);
			}

			if (tok) {
				lua_pushlstring (L, tok->begin, tok->len);
				return 1;
			}
		}
		else {
			/* callback map or unknown type map */
			lua_pushnil (L);
			return 1;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, ret);
	return 1;
}

static gboolean
lua_map_traverse_cb (gconstpointer key,
		gconstpointer value, gsize hits, gpointer ud)
{
	lua_State *L = (lua_State *)ud;

	lua_pushstring (L, key);
	lua_pushinteger (L, hits);
	lua_settable (L, -3);

	return TRUE;
}

static gint
lua_map_get_stats (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_map *map = lua_check_map (L, 1);
	gboolean do_reset = FALSE;

	if (map != NULL) {
		if (lua_isboolean (L, 2)) {
			do_reset = lua_toboolean (L, 2);
		}

		lua_createtable (L, 0, map->map->nelts);

		if (map->map->traverse_function) {
			rspamd_map_traverse (map->map, lua_map_traverse_cb, L, do_reset);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_map_get_data_digest (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_map *map = lua_check_map (L, 1);
	gchar numbuf[64];

	if (map != NULL) {
		rspamd_snprintf (numbuf, sizeof (numbuf), "%uL", map->map->digest);
		lua_pushstring (L, numbuf);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_map_get_nelts (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_map *map = lua_check_map (L, 1);

	if (map != NULL) {
		lua_pushinteger (L, map->map->nelts);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static int
lua_map_is_signed (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_map *map = lua_check_map (L, 1);
	gboolean ret = FALSE;
	struct rspamd_map_backend *bk;
	guint i;

	if (map != NULL) {
		if (map->map) {
			for (i = 0; i < map->map->backends->len; i ++) {
				bk = g_ptr_array_index (map->map->backends, i);
				if (bk->is_signed && bk->protocol == MAP_PROTO_FILE) {
					ret = TRUE;
					break;
				}
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, ret);
	return 1;
}

static int
lua_map_get_proto (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_map *map = lua_check_map (L, 1);
	const gchar *ret = "undefined";
	struct rspamd_map_backend *bk;
	guint i;

	if (map != NULL) {
		for (i = 0; i < map->map->backends->len; i ++) {
			bk = g_ptr_array_index (map->map->backends, i);
			switch (bk->protocol) {
			case MAP_PROTO_FILE:
				ret = "file";
				break;
			case MAP_PROTO_HTTP:
				ret = "http";
				break;
			case MAP_PROTO_HTTPS:
				ret = "https";
				break;
			case MAP_PROTO_STATIC:
				ret = "static";
				break;
			}
			lua_pushstring (L, ret);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}


	return map->map->backends->len;
}

static int
lua_map_get_sign_key (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_map *map = lua_check_map (L, 1);
	struct rspamd_map_backend *bk;
	guint i;
	GString *ret = NULL;

	if (map != NULL) {
		for (i = 0; i < map->map->backends->len; i ++) {
			bk = g_ptr_array_index (map->map->backends, i);

			if (bk->trusted_pubkey) {
				ret = rspamd_pubkey_print (bk->trusted_pubkey,
						RSPAMD_KEYPAIR_PUBKEY|RSPAMD_KEYPAIR_BASE32);
			}
			else {
				ret = NULL;
			}

			if (ret) {
				lua_pushlstring (L, ret->str, ret->len);
				g_string_free (ret, TRUE);
			}
			else {
				lua_pushnil (L);
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return map->map->backends->len;
}

static int
lua_map_set_sign_key (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_map *map = lua_check_map (L, 1);
	struct rspamd_map_backend *bk;
	const gchar *pk_str;
	struct rspamd_cryptobox_pubkey *pk;
	gsize len;
	guint i;

	pk_str = lua_tolstring (L, 2, &len);

	if (map && pk_str) {
		pk = rspamd_pubkey_from_base32 (pk_str, len, RSPAMD_KEYPAIR_SIGN,
				RSPAMD_CRYPTOBOX_MODE_25519);

		if (!pk) {
			return luaL_error (L, "invalid pubkey string");
		}

		for (i = 0; i < map->map->backends->len; i ++) {
			bk = g_ptr_array_index (map->map->backends, i);
			if (bk->trusted_pubkey) {
				/* Unref old pk */
				rspamd_pubkey_unref (bk->trusted_pubkey);
			}

			bk->trusted_pubkey = rspamd_pubkey_ref (pk);
		}

		rspamd_pubkey_unref (pk);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static int
lua_map_set_callback (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_map *map = lua_check_map (L, 1);

	if (!map || map->type != RSPAMD_LUA_MAP_CALLBACK || map->data.cbdata == NULL) {
		return luaL_error (L, "invalid map");
	}

	if (lua_type (L, 2) != LUA_TFUNCTION) {
		return luaL_error (L, "invalid callback");
	}

	lua_pushvalue (L, 2);
	/* Get a reference */
	map->data.cbdata->ref = luaL_ref (L, LUA_REGISTRYINDEX);

	return 0;
}

static int
lua_map_get_uri (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_map *map = lua_check_map (L, 1);
	struct rspamd_map_backend *bk;
	guint i;

	if (map != NULL) {
		for (i = 0; i < map->map->backends->len; i ++) {
			bk = g_ptr_array_index (map->map->backends, i);
			lua_pushstring (L, bk->uri);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return map->map->backends->len;
}

void
luaopen_map (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{map}", maplib_m);

	lua_pop (L, 1);
}
