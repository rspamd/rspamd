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
#include "libutil/map.h"
#include "libutil/map_private.h"
#include "libutil/radix.h"
#include "lua/lua_map.h"

/***
 * This module is used to manage rspamd maps and map like objects
 *
 * @module rspamd_map
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
 * - `embedded`: for manually created maps
 * @return {string} string representation of the map protocol
 */
LUA_FUNCTION_DEF (map, get_proto);

static const struct luaL_reg maplib_m[] = {
	LUA_INTERFACE_DEF (map, get_key),
	LUA_INTERFACE_DEF (map, is_signed),
	LUA_INTERFACE_DEF (map, get_proto),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

enum rspamd_lua_map_type {
	RSPAMD_LUA_MAP_RADIX = 0,
	RSPAMD_LUA_MAP_SET,
	RSPAMD_LUA_MAP_HASH,
	RSPAMD_LUA_MAP_CALLBACK
};

struct rspamd_map;
struct radix_tree_compressed;

struct rspamd_lua_map {
	struct rspamd_map *map;
	enum rspamd_lua_map_type type;

	union {
		struct radix_tree_compressed *radix;
		GHashTable *hash;
		gint cbref;
	} data;
};

struct lua_map_callback_data {
	lua_State *L;
	gint ref;
	GString *data;
	struct rspamd_lua_map *lua_map;
};

static struct rspamd_lua_map  *
lua_check_map (lua_State * L)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{map}");
	luaL_argcheck (L, ud != NULL, 1, "'map' expected");
	return ud ? *((struct rspamd_lua_map **)ud) : NULL;
}

gint
lua_config_add_radix_map (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *map_line, *description;
	struct rspamd_lua_map *map, **pmap;
	struct rspamd_map *m;

	if (cfg) {
		map_line = luaL_checkstring (L, 2);
		description = lua_tostring (L, 3);
		map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
		map->data.radix = radix_create_compressed ();
		map->type = RSPAMD_LUA_MAP_RADIX;

		if ((m = rspamd_map_add (cfg, map_line, description,
				rspamd_radix_read,
				rspamd_radix_fin,
				(void **)&map->data.radix)) == NULL) {
			msg_warn_config ("invalid radix map %s", map_line);
			radix_destroy_compressed (map->data.radix);
			lua_pushnil (L);
			return 1;
		}

		map->map = m;
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
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *mname, *optname;
	const ucl_object_t *obj;
	struct rspamd_lua_map *map, **pmap;

	if (!cfg) {
		return luaL_error (L, "invalid arguments");
	}

	mname = luaL_checkstring (L, 2);
	optname = luaL_checkstring (L, 3);

	if (mname && optname) {
		obj = rspamd_config_get_module_opt (cfg, mname, optname);
		if (obj) {
			map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
			map->data.radix = radix_create_compressed ();
			map->type = RSPAMD_LUA_MAP_RADIX;
			map->data.radix = radix_create_compressed ();
			radix_add_generic_iplist (ucl_obj_tostring (obj), &map->data.radix);
			pmap = lua_newuserdata (L, sizeof (void *));
			*pmap = map;
			rspamd_lua_setclass (L, "rspamd{map}", -1);
		} else {
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
lua_config_add_hash_map (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *map_line, *description;
	struct rspamd_lua_map *map, **pmap;
	struct rspamd_map *m;

	if (cfg) {
		map_line = luaL_checkstring (L, 2);
		description = lua_tostring (L, 3);
		map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
		map->data.hash = g_hash_table_new (rspamd_strcase_hash,
				rspamd_strcase_equal);
		map->type = RSPAMD_LUA_MAP_SET;

		if ((m = rspamd_map_add (cfg, map_line, description,
				rspamd_hosts_read,
				rspamd_hosts_fin,
				(void **)&map->data.hash)) == NULL) {
			msg_warn_config ("invalid set map %s", map_line);
			g_hash_table_destroy (map->data.hash);
			lua_pushnil (L);
			return 1;
		}

		map->map = m;
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
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *map_line, *description;
	struct rspamd_lua_map *map, **pmap;
	struct rspamd_map *m;

	if (cfg) {
		map_line = luaL_checkstring (L, 2);
		description = lua_tostring (L, 3);
		map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
		map->data.hash = g_hash_table_new (rspamd_strcase_hash,
				rspamd_strcase_equal);
		map->type = RSPAMD_LUA_MAP_HASH;

		if ((m = rspamd_map_add (cfg, map_line, description,
				rspamd_kv_list_read,
				rspamd_kv_list_fin,
				(void **)&map->data.hash)) == NULL) {
			msg_warn_config ("invalid hash map %s", map_line);
			g_hash_table_destroy (map->data.hash);
			lua_pushnil (L);
			return 1;
		}

		map->map = m;
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
lua_map_read (rspamd_mempool_t *pool, gchar *chunk, gint len,
	struct map_cb_data *data)
{
	struct lua_map_callback_data *cbdata, *old;

	if (data->cur_data == NULL) {
		cbdata = g_slice_alloc0 (sizeof (*cbdata));
		old = (struct lua_map_callback_data *)data->prev_data;
		cbdata->L = old->L;
		cbdata->ref = old->ref;
		cbdata->lua_map = old->lua_map;
		data->cur_data = cbdata;
	}
	else {
		cbdata = (struct lua_map_callback_data *)data->cur_data;
	}

	if (cbdata->data == NULL) {
		cbdata->data = g_string_new_len (chunk, len);
	}
	else {
		g_string_append_len (cbdata->data, chunk, len);
	}

	return NULL;
}

static void
lua_map_fin (rspamd_mempool_t * pool, struct map_cb_data *data)
{
	struct lua_map_callback_data *cbdata, *old;
	struct rspamd_lua_map **pmap;

	if (data->prev_data) {
		/* Cleanup old data */
		old = (struct lua_map_callback_data *)data->prev_data;
		if (old->data) {
			g_string_free (old->data, TRUE);
		}
		g_slice_free1 (sizeof (*old), old);
		data->prev_data = NULL;
	}

	if (data->cur_data) {
		cbdata = (struct lua_map_callback_data *)data->cur_data;
	}
	else {
		msg_err_pool ("no data read for map");
		return;
	}

	if (cbdata->data != NULL && cbdata->data->len != 0) {
		lua_rawgeti (cbdata->L, LUA_REGISTRYINDEX, cbdata->ref);
		lua_pushlstring (cbdata->L, cbdata->data->str, cbdata->data->len);
		pmap = lua_newuserdata (cbdata->L, sizeof (void *));
		*pmap = cbdata->lua_map;
		rspamd_lua_setclass (cbdata->L, "rspamd{map}", -1);

		if (lua_pcall (cbdata->L, -1, 0, 0) != 0) {
			msg_info_pool ("call to %s failed: %s", "local function",
				lua_tostring (cbdata->L, -1));
			lua_pop (cbdata->L, 1);
		}
	}
}

gint
lua_config_add_map (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *map_line, *description;
	struct lua_map_callback_data *cbdata, **pcbdata;
	struct rspamd_lua_map *map;
	struct rspamd_map *m;
	int cbidx;

	if (cfg) {
		map_line = luaL_checkstring (L, 2);

		if (lua_gettop (L) == 4) {
			description = lua_tostring (L, 3);
			cbidx = 4;
		}
		else {
			description = NULL;
			cbidx = 3;
		}

		if (lua_type (L, cbidx) == LUA_TFUNCTION) {
			cbdata = g_slice_alloc (sizeof (*cbdata));
			cbdata->L = L;
			cbdata->data = NULL;
			lua_pushvalue (L, cbidx);
			/* Get a reference */
			cbdata->ref = luaL_ref (L, LUA_REGISTRYINDEX);
			map = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (*map));
			map->type = RSPAMD_LUA_MAP_CALLBACK;
			map->data.cbref = cbdata->ref;
			cbdata->lua_map = map;
			pcbdata = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (cbdata));
			*pcbdata = cbdata;

			if ((m = rspamd_map_add (cfg, map_line, description,
					lua_map_read, lua_map_fin,
					(void **)pcbdata)) == NULL) {
				msg_warn_config ("invalid hash map %s", map_line);
				lua_pushboolean (L, false);
			}
			else {
				map->map = m;
				lua_pushboolean (L, true);
			}
		}
		else {
			msg_warn_config ("invalid callback argument for map %s", map_line);
			lua_pushboolean (L, false);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/* Radix and hash table functions */
static gint
lua_map_get_key (lua_State * L)
{
	struct rspamd_lua_map *map = lua_check_map (L);
	radix_compressed_t *radix;
	struct rspamd_lua_ip *addr = NULL;
	const gchar *key, *value = NULL;
	gpointer ud;
	guint32 key_num = 0;
	gboolean ret = FALSE;

	if (map) {
		if (map->type == RSPAMD_LUA_MAP_RADIX) {
			radix = map->data.radix;

			if (lua_type (L, 2) == LUA_TNUMBER) {
				key_num = luaL_checknumber (L, 2);
				key_num = htonl (key_num);
			}
			else if (lua_type (L, 2) == LUA_TUSERDATA) {
				ud = luaL_checkudata (L, 2, "rspamd{ip}");
				if (ud != NULL) {
					addr = *((struct rspamd_lua_ip **)ud);
					if (addr->addr == NULL) {
						msg_err ("rspamd{ip} is not valid");
						addr = NULL;
					}
				}
				else {
					msg_err ("invalid userdata type provided, rspamd{ip} expected");
				}
			}

			if (addr != NULL) {
				if (radix_find_compressed_addr (radix, addr->addr)
						!=  RADIX_NO_VALUE) {
					ret = TRUE;
				}
			}
			else if (key_num != 0) {
				if (radix_find_compressed (radix, (guint8 *)&key_num, sizeof (key_num))
						!= RADIX_NO_VALUE) {
					ret = TRUE;
				}
			}
		}
		else if (map->type == RSPAMD_LUA_MAP_SET) {
			key = lua_tostring (L, 2);

			if (key) {
				ret = g_hash_table_lookup (map->data.hash, key) != NULL;
			}
		}
		else {
			/* key-value map */
			key = lua_tostring (L, 2);

			if (key) {
				value = g_hash_table_lookup (map->data.hash, key);

				if (value) {
					lua_pushstring (L, value);
					return 1;
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
lua_map_is_signed (lua_State *L)
{
	struct rspamd_lua_map *map = lua_check_map (L);
	gboolean ret = FALSE;

	if (map != NULL) {
		if (map->map) {
			if (map->map->is_signed) {
				ret = TRUE;
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
	struct rspamd_lua_map *map = lua_check_map (L);
	const gchar *ret = "undefined";

	if (map != NULL) {
		if (map->map == NULL) {
			ret = "embedded";
		}
		else {
			switch (map->map->protocol) {
			case MAP_PROTO_FILE:
				ret = "file";
				break;
			case MAP_PROTO_HTTP:
				ret = "http";
				break;
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushstring (L, ret);
	return 1;
}


void
luaopen_map (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{map}", maplib_m);

	lua_pop (L, 1);
}
