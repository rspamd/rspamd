/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "lua_common.h"
#include "expressions.h"
#include "symbols_cache.h"
#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif

/* 
 * This is implementation of lua routines to handle config file params 
 */

/* Process a single item in 'metrics' table */
static void
lua_process_metric (lua_State *L, const gchar *name, struct config_file *cfg)
{
	GList                               *metric_list;
	gchar                               *symbol, *old_desc;
	const gchar                         *desc;
	struct metric                       *metric;
	gdouble                             *score, *old_score;

	/* Get module opt structure */
	if ((metric = g_hash_table_lookup (cfg->metrics, name)) == NULL) {
		metric = check_metric_conf (cfg, metric);
		metric->name = memory_pool_strdup (cfg->cfg_pool, name);
	}

	/* Now iterate throught module table */
	for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
		/* key - -2, value - -1 */
		symbol = memory_pool_strdup (cfg->cfg_pool, luaL_checkstring (L, -2));
		if (symbol != NULL) {
			if (lua_istable (L, -1)) {
				/* We got a table, so extract individual attributes */
				lua_pushstring (L, "weight");
				lua_gettable (L, -2);
				if (lua_isnumber (L, -1)) {
					score = memory_pool_alloc (cfg->cfg_pool, sizeof (double));
					*score = lua_tonumber (L, -1);
				}
				else {
					msg_warn ("cannot get weight of symbol: %s", symbol);
					continue;
				}
				lua_pop (L, 1);
				lua_pushstring (L, "description");
				lua_gettable (L, -2);
				if (lua_isstring (L, -1)) {
					desc = lua_tostring (L, -1);
					old_desc = g_hash_table_lookup (metric->descriptions, symbol);
					if (old_desc) {
						msg_info ("replacing description for symbol %s", symbol);
						g_hash_table_replace (metric->descriptions,
							symbol, memory_pool_strdup (cfg->cfg_pool, desc));
					}
					else {
						g_hash_table_insert (metric->descriptions,
							symbol, memory_pool_strdup (cfg->cfg_pool, desc));
					}
				}
				lua_pop (L, 1);
			}
			else if (lua_isnumber (L, -1)) {
				/* Just got weight */
				score = memory_pool_alloc (cfg->cfg_pool, sizeof (double));
				*score = lua_tonumber (L, -1);
			}
			else {
				msg_warn ("cannot get weight of symbol: %s", symbol);
				continue;
			}
			/* Insert symbol */
			if ((old_score = g_hash_table_lookup (metric->symbols, symbol)) != NULL) {
				msg_info ("replacing weight for symbol %s: %.2f -> %.2f", symbol, *old_score, *score);
				g_hash_table_replace (metric->symbols, symbol, score);
			}
			else {
				g_hash_table_insert (metric->symbols, symbol, score);
			}

			if ((metric_list = g_hash_table_lookup (cfg->metrics_symbols, symbol)) == NULL) {
				metric_list = g_list_prepend (NULL, metric);
				memory_pool_add_destructor (cfg->cfg_pool, (pool_destruct_func)g_list_free, metric_list);
				g_hash_table_insert (cfg->metrics_symbols, symbol, metric_list);
			}
			else {
				/* Slow but keep start element of list in safe */
				if (!g_list_find (metric_list, metric)) {
					metric_list = g_list_append (metric_list, metric);
				}
			}
		}
	}
}

/* Do post load initialization based on lua */
void
lua_post_load_config (struct config_file *cfg)
{
	lua_State                            *L = cfg->lua_state;
	const gchar                          *name, *val;
	gchar                                *sym;
	struct expression                    *expr, *old_expr;
	ucl_object_t                   *obj;
	gsize                                 keylen;

	/* First check all module options that may be overriden in 'config' global */
	lua_getglobal (L, "config");

	if (lua_istable (L, -1)) {
		/* Iterate */
		for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
			/* 'key' is at index -2 and 'value' is at index -1 */
			/* Key must be a string and value must be a table */
			name = luaL_checklstring (L, -2, &keylen);
			if (name != NULL && lua_istable (L, -1)) {
				obj = lua_rcl_obj_get (L, -1);
				if (obj != NULL) {
					cfg->rcl_obj = ucl_object_insert_key_merged (cfg->rcl_obj, obj, name, keylen, true);
				}
			}
		}
	}

	/* Check metrics settings */
	lua_getglobal (L, "metrics");

	if (lua_istable (L, -1)) {
		/* Iterate */
		for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
			/* 'key' is at index -2 and 'value' is at index -1 */
			/* Key must be a string and value must be a table */
			name = luaL_checkstring (L, -2);
			if (name != NULL && lua_istable (L, -1)) {
				lua_process_metric (L, name, cfg);
			}
		}
	}

	/* Check composites */
	lua_getglobal (L, "composites");

	if (lua_istable (L, -1)) {
		/* Iterate */
		for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
			/* 'key' is at index -2 and 'value' is at index -1 */
			/* Key must be a string and value must be a table */
			name = luaL_checkstring (L, -2);
			if (name != NULL && lua_isstring (L, -1)) {
				val = lua_tostring (L, -1);
				sym = memory_pool_strdup(cfg->cfg_pool, name);
				if ((expr = parse_expression (cfg->cfg_pool, memory_pool_strdup(cfg->cfg_pool, val))) == NULL) {
					msg_err ("cannot parse composite expression: %s", val);
					continue;
				}
				/* Now check hash table for this composite */
				if ((old_expr = g_hash_table_lookup (cfg->composite_symbols, name)) != NULL) {
					msg_info ("replacing composite symbol %s", name);
					g_hash_table_replace (cfg->composite_symbols, sym, expr);
				}
				else {
					g_hash_table_insert (cfg->composite_symbols, sym, expr);
					register_virtual_symbol (&cfg->cache, sym, 1);
				}
			}
		}
	}
}

/* Handle lua dynamic config param */
gboolean
lua_handle_param (struct worker_task *task, gchar *mname, gchar *optname, enum lua_var_type expected_type, gpointer *res)
{
	/* xxx: Adopt this for rcl */
	
	/* Option not found */
	*res = NULL;
	return FALSE;
}

#define FAKE_RES_VAR "rspamd_res"
gboolean
lua_check_condition (struct config_file *cfg, const gchar *condition)
{
	lua_State                            *L = cfg->lua_state;
	gchar                                *hostbuf, *condbuf;
	gsize                                 hostlen;
	gboolean                              res;
#ifdef HAVE_SYS_UTSNAME_H
	struct utsname                        uts;
#endif

	/* Set some globals for condition */
	/* XXX: think what other variables can be useful */
	hostlen = sysconf (_SC_HOST_NAME_MAX) + 1;
	hostbuf = alloca (hostlen);
	gethostname (hostbuf, hostlen);
	hostbuf[hostlen - 1] = '\0';

	/* Hostname */
	lua_pushstring (L, hostbuf);
	lua_setglobal (L, "hostname");
	/* Config file name */
	lua_pushstring (L, cfg->cfg_name);
	lua_setglobal (L, "cfg_name");
	/* Check for uname */
#ifdef HAVE_SYS_UTSNAME_H
	uname (&uts);
	lua_pushstring (L, uts.sysname);
	lua_setglobal (L, "osname");
	lua_pushstring (L, uts.release);
	lua_setglobal (L, "osrelease");
#else
	lua_pushstring (L, "unknown");
	lua_setglobal (L, "osname");
	lua_pushstring (L, "");
	lua_setglobal (L, "osrelease");
#endif

#ifdef HAVE_OPENSSL
	lua_pushboolean (L, TRUE);
#else
	lua_pushboolean (L, FALSE);
#endif
	lua_setglobal (L, "rspamd_supports_rsa");

	/* Rspamd paths */
	lua_newtable (L);
	lua_set_table_index (L, "etcdir", ETC_PREFIX);
	lua_set_table_index (L, "prefix", CMAKE_PREFIX);
	lua_set_table_index (L, "localstatesdir", LOCALSTATES_PREFIX);
	lua_setglobal (L, "rspamd_paths");

	/* Make fake string */
	hostlen = sizeof (FAKE_RES_VAR "=") + strlen (condition);
	condbuf = g_malloc (hostlen);
	rspamd_strlcpy (condbuf, FAKE_RES_VAR "=", sizeof (FAKE_RES_VAR "="));
	g_strlcat (condbuf, condition, hostlen);
	/* Evaluate condition */
	if (luaL_dostring (L, condbuf) != 0) {
		msg_err ("eval of '%s' failed: '%s'", condition, lua_tostring (L, -1));
		g_free (condbuf);
		return FALSE;
	}
	/* Get global variable res to get result */
	lua_getglobal (L, FAKE_RES_VAR);
	if (! lua_isboolean (L, -1)) {
		msg_err ("bad string evaluated: %s, type: %s", condbuf, lua_typename (L, lua_type (L, -1)));
		g_free (condbuf);
			return FALSE;
	}

	res = lua_toboolean (L, -1);
	g_free (condbuf);

	return res;
}
