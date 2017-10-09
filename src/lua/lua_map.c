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
#include "contrib/libucl/lua_ucl.h"

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

static const struct luaL_reg maplib_m[] = {
	LUA_INTERFACE_DEF (map, get_key),
	LUA_INTERFACE_DEF (map, is_signed),
	LUA_INTERFACE_DEF (map, get_proto),
	LUA_INTERFACE_DEF (map, get_sign_key),
	LUA_INTERFACE_DEF (map, set_sign_key),
	LUA_INTERFACE_DEF (map, set_callback),
	LUA_INTERFACE_DEF (map, get_uri),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

struct lua_map_callback_data {
	lua_State *L;
	gint ref;
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
				(void **)&map->data.radix)) == NULL) {
			msg_warn_config ("invalid radix map %s", map_line);
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
					(void **)&map->data.radix)) == NULL) {
				msg_err_config ("invalid radix map static");
				lua_pushnil (L);
				ucl_object_unref (fake_obj);

				return 1;
			}

			ucl_object_unref (fake_obj);
			pmap = lua_newuserdata (L, sizeof (void *));
			map->map = m;
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
				(void **)&map->data.radix)) == NULL) {
			msg_err_config ("invalid radix map static");
			lua_pushnil (L);
			ucl_object_unref (fake_obj);

			return 1;
		}

		ucl_object_unref (fake_obj);
		pmap = lua_newuserdata (L, sizeof (void *));
		map->map = m;
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
				rspamd_hosts_read,
				rspamd_hosts_fin,
				(void **)&map->data.hash)) == NULL) {
			msg_warn_config ("invalid set map %s", map_line);
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
		map->data.hash = NULL;
		map->type = RSPAMD_LUA_MAP_HASH;

		if ((m = rspamd_map_add (cfg, map_line, description,
				rspamd_kv_list_read,
				rspamd_kv_list_fin,
				(void **)&map->data.hash)) == NULL) {
			msg_warn_config ("invalid hash map %s", map_line);
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
lua_map_fin (struct map_cb_data *data)
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

	if (data->prev_data) {
		data->prev_data = NULL;
	}

	if (cbdata->ref == -1) {
		msg_err_map ("map has no callback set");
	}
	else if (cbdata->data != NULL && cbdata->data->len != 0) {
		lua_rawgeti (cbdata->L, LUA_REGISTRYINDEX, cbdata->ref);
		lua_pushlstring (cbdata->L, cbdata->data->str, cbdata->data->len);
		pmap = lua_newuserdata (cbdata->L, sizeof (void *));
		*pmap = cbdata->lua_map;
		rspamd_lua_setclass (cbdata->L, "rspamd{map}", -1);

		if (lua_pcall (cbdata->L, 2, 0, 0) != 0) {
			msg_info_map ("call to %s failed: %s", "local function",
				lua_tostring (cbdata->L, -1));
			lua_pop (cbdata->L, 1);
		}
	}

	cbdata->data = rspamd_fstring_assign (cbdata->data, "", 0);
}

gint
lua_config_add_map (lua_State *L)
{
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const char *description = NULL;
	const gchar *type = NULL;
	ucl_object_t *map_obj = NULL;
	struct lua_map_callback_data *cbdata;
	struct rspamd_lua_map *map, **pmap;
	struct rspamd_map *m;
	int cbidx = -1, ret;
	GError *err = NULL;

	if (cfg) {
		if (!rspamd_lua_parse_table_arguments (L, 2, &err,
				"*url=O;description=S;callback=F;type=S",
				&map_obj, &description, &cbidx, &type)) {
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

			if ((m = rspamd_map_add_from_ucl (cfg, map_obj, description,
					lua_map_read, lua_map_fin,
					(void **)&map->data.cbdata)) == NULL) {

				if (cbidx != -1) {
					luaL_unref (L, LUA_REGISTRYINDEX, cbidx);
				}

				if (map_obj) {
					ucl_object_unref (map_obj);
				}

				lua_pushnil (L);

				return 1;
			}
		}
		else if (strcmp (type, "set") == 0) {
			map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
			map->data.hash = NULL;
			map->type = RSPAMD_LUA_MAP_SET;

			if ((m = rspamd_map_add_from_ucl (cfg, map_obj, description,
					rspamd_hosts_read,
					rspamd_hosts_fin,
					(void **)&map->data.hash)) == NULL) {
				lua_pushnil (L);
				ucl_object_unref (map_obj);

				return 1;
			}
		}
		else if (strcmp (type, "map") == 0 || strcmp (type, "hash") == 0) {
			map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
			map->data.hash = NULL;
			map->type = RSPAMD_LUA_MAP_HASH;

			if ((m = rspamd_map_add_from_ucl (cfg, map_obj, description,
					rspamd_kv_list_read,
					rspamd_kv_list_fin,
					(void **)&map->data.hash)) == NULL) {
				lua_pushnil (L);
				ucl_object_unref (map_obj);

				return 1;
			}
		}
		else if (strcmp (type, "radix") == 0) {
			map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
			map->data.radix = NULL;
			map->type = RSPAMD_LUA_MAP_RADIX;

			if ((m = rspamd_map_add_from_ucl (cfg, map_obj, description,
					rspamd_radix_read,
					rspamd_radix_fin,
					(void **)&map->data.radix)) == NULL) {
				lua_pushnil (L);
				ucl_object_unref (map_obj);

				return 1;
			}
		}
		else if (strcmp (type, "regexp") == 0) {
			map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
			map->data.re_map = NULL;
			map->type = RSPAMD_LUA_MAP_REGEXP;

			if ((m = rspamd_map_add_from_ucl (cfg, map_obj, description,
					rspamd_regexp_list_read_single,
					rspamd_regexp_list_fin,
					(void **) &map->data.re_map)) == NULL) {
				lua_pushnil (L);
				ucl_object_unref (map_obj);

				return 1;
			}
		}
		else if (strcmp (type, "regexp_multi") == 0) {
			map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*map));
			map->data.re_map = NULL;
			map->type = RSPAMD_LUA_MAP_REGEXP_MULTIPLE;

			if ((m = rspamd_map_add_from_ucl (cfg, map_obj, description,
					rspamd_regexp_list_read_multiple,
					rspamd_regexp_list_fin,
					(void **) &map->data.re_map)) == NULL) {
				lua_pushnil (L);
				ucl_object_unref (map_obj);

				return 1;
			}
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
	struct rspamd_lua_map *map = lua_check_map (L, 1);
	radix_compressed_t *radix;
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
				gsize len;

				addr_str = luaL_checklstring (L, 2, &len);
				addr = g_alloca (sizeof (*addr));
				addr->addr = g_alloca (rspamd_inet_address_storage_size ());

				if (!rspamd_parse_inet_address_ip (addr_str, len, addr->addr)) {
					addr = NULL;
					msg_err ("invalid ip address: %*s", (gint)len, addr_str);
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
				key_num = luaL_checknumber (L, 2);
				key_num = htonl (key_num);
			}

			if (radix) {
				guintptr p = 0;

				if (addr != NULL) {
					if ((p = radix_find_compressed_addr (radix, addr->addr))
							!=  RADIX_NO_VALUE) {
						ret = TRUE;
					}
					else {
						p = 0;
					}
				}
				else if (key_num != 0) {
					if ((p = radix_find_compressed (radix,
							(guint8 *)&key_num, sizeof (key_num))) != RADIX_NO_VALUE) {
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
				ret = g_hash_table_lookup (map->data.hash, key) != NULL;
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
				value = g_hash_table_lookup (map->data.hash, key);
			}

			if (value) {
				lua_pushstring (L, value);
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

static int
lua_map_is_signed (lua_State *L)
{
	struct rspamd_lua_map *map = lua_check_map (L, 1);
	gboolean ret = FALSE;
	struct rspamd_map_backend *bk;
	guint i;

	if (map != NULL) {
		if (map->map) {
			for (i = 0; i < map->map->backends->len; i ++) {
				bk = g_ptr_array_index (map->map->backends, i);
				if (bk->is_signed) {
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
	struct rspamd_lua_map *map = lua_check_map (L, 1);
	const gchar *ret = "undefined";
	struct rspamd_map_backend *bk;
		guint i;

	if (map != NULL) {
		for (i = 0; i < map->map->backends->len; i ++) {
			bk = g_ptr_array_index (map->map->backends, i);
			ret = bk->uri;
			lua_pushstring (L, ret);
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
