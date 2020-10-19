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
#include "config.h"
#include "rspamd.h"
#include "libserver/maps/map.h"
#include "scan_result.h"
#include "dynamic_cfg.h"
#include "unix-std.h"
#include "lua/lua_common.h"

#include <math.h>

struct config_json_buf {
	GString *buf;
	struct rspamd_config *cfg;
};

/**
 * Apply configuration to the specified configuration
 * @param conf_metrics
 * @param cfg
 */
static void
apply_dynamic_conf (const ucl_object_t *top, struct rspamd_config *cfg)
{
	gint test_act;
	const ucl_object_t *cur_elt, *cur_nm, *it_val;
	ucl_object_iter_t it = NULL;
	const gchar *name;
	gdouble nscore;
	static const guint priority = 3;

	while ((cur_elt = ucl_object_iterate (top, &it, true))) {
		if (ucl_object_type (cur_elt) != UCL_OBJECT) {
			msg_err ("loaded json array element is not an object");
			continue;
		}

		cur_nm = ucl_object_lookup (cur_elt, "metric");
		if (!cur_nm || ucl_object_type (cur_nm) != UCL_STRING) {
			msg_err (
					"loaded json metric object element has no 'metric' attribute");
			continue;
		}

		cur_nm = ucl_object_lookup (cur_elt, "symbols");
		/* Parse symbols */
		if (cur_nm && ucl_object_type (cur_nm) == UCL_ARRAY) {
			ucl_object_iter_t nit = NULL;

			while ((it_val = ucl_object_iterate (cur_nm, &nit, true))) {
				if (ucl_object_lookup (it_val, "name") &&
						ucl_object_lookup (it_val, "value")) {
					const ucl_object_t *n =
							ucl_object_lookup (it_val, "name");
					const ucl_object_t *v =
							ucl_object_lookup (it_val, "value");

					nscore = ucl_object_todouble (v);

					/*
					 * We use priority = 3 here
					 */
					rspamd_config_add_symbol (cfg,
							ucl_object_tostring (n), nscore, NULL, NULL,
							0, priority, cfg->default_max_shots);
				}
				else {
					msg_info (
							"json symbol object has no mandatory 'name' and 'value' attributes");
				}
			}
		}
		else {
			ucl_object_t *arr;

			arr = ucl_object_typed_new (UCL_ARRAY);
			ucl_object_insert_key ((ucl_object_t *)cur_elt, arr, "symbols",
					sizeof ("symbols") - 1, false);
		}
		cur_nm = ucl_object_lookup (cur_elt, "actions");
		/* Parse actions */
		if (cur_nm && ucl_object_type (cur_nm) == UCL_ARRAY) {
			ucl_object_iter_t nit = NULL;

			while ((it_val = ucl_object_iterate (cur_nm, &nit, true))) {
				const ucl_object_t *n = ucl_object_lookup (it_val, "name");
				const ucl_object_t *v = ucl_object_lookup (it_val, "value");

				if (n != NULL && v != NULL) {
					name = ucl_object_tostring (n);

					if (!name || !rspamd_action_from_str (name, &test_act)) {
						msg_err ("unknown action: %s",
								ucl_object_tostring (ucl_object_lookup (it_val,
										"name")));
						continue;
					}


					if (ucl_object_type (v) == UCL_NULL) {
						nscore = NAN;
					}
					else {
						nscore = ucl_object_todouble (v);
					}

					ucl_object_t *obj_tbl = ucl_object_typed_new (UCL_OBJECT);
					ucl_object_insert_key (obj_tbl, ucl_object_fromdouble (nscore),
							"score", 0, false);
					ucl_object_insert_key (obj_tbl, ucl_object_fromdouble (priority),
							"priority", 0, false);
					rspamd_config_set_action_score (cfg, name, obj_tbl);
					ucl_object_unref (obj_tbl);
				}
				else {
					msg_info (
							"json action object has no mandatory 'name' and 'value' attributes");
				}
			}
		}
		else {
			ucl_object_t *arr;

			arr = ucl_object_typed_new (UCL_ARRAY);
			ucl_object_insert_key ((ucl_object_t *)cur_elt, arr, "actions",
					sizeof ("actions") - 1, false);
		}
	}
}

/* Callbacks for reading json dynamic rules */
static gchar *
json_config_read_cb (gchar * chunk,
	gint len,
	struct map_cb_data *data,
	gboolean final)
{
	struct config_json_buf *jb, *pd;

	pd = data->prev_data;

	g_assert (pd != NULL);

	if (data->cur_data == NULL) {
		jb = g_malloc0 (sizeof (*jb));
		jb->cfg = pd->cfg;
		data->cur_data = jb;
	}
	else {
		jb = data->cur_data;
	}

	if (jb->buf == NULL) {
		/* Allocate memory for buffer */
		jb->buf = g_string_sized_new (MAX (len, BUFSIZ));
	}

	g_string_append_len (jb->buf, chunk, len);

	return NULL;
}

static void
json_config_fin_cb (struct map_cb_data *data, void **target)
{
	struct config_json_buf *jb;
	ucl_object_t *top;
	struct ucl_parser *parser;

	/* Now parse json */
	if (data->cur_data) {
		jb = data->cur_data;
	}
	else {
		return;
	}

	if (jb->buf == NULL) {
		msg_err ("no data read");

		return;
	}

	parser = ucl_parser_new (0);

	if (!ucl_parser_add_chunk (parser, jb->buf->str, jb->buf->len)) {
		msg_err ("cannot load json data: parse error %s",
				ucl_parser_get_error (parser));
		ucl_parser_free (parser);
		return;
	}

	top = ucl_parser_get_object (parser);
	ucl_parser_free (parser);

	if (ucl_object_type (top) != UCL_ARRAY) {
		ucl_object_unref (top);
		msg_err ("loaded json is not an array");
		return;
	}

	ucl_object_unref (jb->cfg->current_dynamic_conf);
	apply_dynamic_conf (top, jb->cfg);
	jb->cfg->current_dynamic_conf = top;

	if (target) {
		*target = data->cur_data;
	}

	if (data->prev_data) {
		jb = data->prev_data;
		/* Clean prev data */
		if (jb->buf) {
			g_string_free (jb->buf, TRUE);
		}

		g_free (jb);
	}
}

static void
json_config_dtor_cb (struct map_cb_data *data)
{
	struct config_json_buf *jb;

	if (data->cur_data) {
		jb = data->cur_data;
		/* Clean prev data */
		if (jb->buf) {
			g_string_free (jb->buf, TRUE);
		}

		if (jb->cfg && jb->cfg->current_dynamic_conf) {
			ucl_object_unref (jb->cfg->current_dynamic_conf);
		}

		g_free (jb);
	}
}

/**
 * Init dynamic configuration using map logic and specific configuration
 * @param cfg config file
 */
void
init_dynamic_config (struct rspamd_config *cfg)
{
	struct config_json_buf *jb, **pjb;

	if (cfg->dynamic_conf == NULL) {
		/* No dynamic conf has been specified, so do not try to load it */
		return;
	}

	/* Now try to add map with json data */
	jb = g_malloc (sizeof (struct config_json_buf));
	pjb = g_malloc (sizeof (struct config_json_buf *));
	jb->buf = NULL;
	jb->cfg = cfg;
	*pjb = jb;
	cfg->current_dynamic_conf = ucl_object_typed_new (UCL_ARRAY);
	rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)g_free,
			pjb);

	if (!rspamd_map_add (cfg,
			cfg->dynamic_conf,
			"Dynamic configuration map",
			json_config_read_cb,
			json_config_fin_cb,
			json_config_dtor_cb,
			(void **)pjb, NULL, RSPAMD_MAP_DEFAULT)) {
		msg_err ("cannot add map for configuration %s", cfg->dynamic_conf);
	}
}

/**
 * Dump dynamic configuration to the disk
 * @param cfg
 * @return
 */
gboolean
dump_dynamic_config (struct rspamd_config *cfg)
{
	struct stat st;
	gchar *dir, pathbuf[PATH_MAX];
	gint fd;

	if (cfg->dynamic_conf == NULL || cfg->current_dynamic_conf == NULL) {
		/* No dynamic conf has been specified, so do not try to dump it */
		msg_err ("cannot save dynamic conf as it is not specified");
		return FALSE;
	}

	dir = g_path_get_dirname (cfg->dynamic_conf);
	if (dir == NULL) {
		msg_err ("invalid path: %s", cfg->dynamic_conf);
		return FALSE;
	}

	if (stat (cfg->dynamic_conf, &st) == -1) {
		msg_debug ("%s is unavailable: %s", cfg->dynamic_conf,
			strerror (errno));
		st.st_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	}
	if (access (dir, W_OK | R_OK) == -1) {
		msg_warn ("%s is inaccessible: %s", dir, strerror (errno));
		g_free (dir);
		return FALSE;
	}
	rspamd_snprintf (pathbuf,
		sizeof (pathbuf),
		"%s%crconf-XXXXXX",
		dir,
		G_DIR_SEPARATOR);
	g_free (dir);
#ifdef HAVE_MKSTEMP
	/* Umask is set before */
	fd = mkstemp (pathbuf);
#else
	fd = g_mkstemp_full (pathbuf, O_RDWR, S_IWUSR | S_IRUSR);
#endif
	if (fd == -1) {
		msg_err ("mkstemp error: %s", strerror (errno));

		return FALSE;
	}

	struct ucl_emitter_functions *emitter_functions;
	FILE *fp;

	fp = fdopen (fd, "w");
	emitter_functions = ucl_object_emit_file_funcs (fp);

	if (!ucl_object_emit_full (cfg->current_dynamic_conf, UCL_EMIT_JSON,
			emitter_functions, NULL)) {
		msg_err ("cannot emit ucl object: %s", strerror (errno));
		ucl_object_emit_funcs_free (emitter_functions);
		fclose (fp);
		return FALSE;
	}

	(void)unlink (cfg->dynamic_conf);

	/* Rename old config */
	if (rename (pathbuf, cfg->dynamic_conf) == -1) {
		msg_err ("rename error: %s", strerror (errno));
		fclose (fp);
		ucl_object_emit_funcs_free (emitter_functions);
		unlink (pathbuf);

		return FALSE;
	}
	/* Set permissions */

	if (chmod (cfg->dynamic_conf, st.st_mode) == -1) {
		msg_warn ("chmod failed: %s", strerror (errno));
	}

	fclose (fp);
	ucl_object_emit_funcs_free (emitter_functions);

	return TRUE;
}

static ucl_object_t*
new_dynamic_metric (const gchar *metric_name, ucl_object_t *top)
{
	ucl_object_t *metric;

	metric = ucl_object_typed_new (UCL_OBJECT);

	ucl_object_insert_key (metric, ucl_object_fromstring (metric_name),
			"metric", sizeof ("metric") - 1, true);
	ucl_object_insert_key (metric, ucl_object_typed_new (UCL_ARRAY),
			"actions", sizeof ("actions") - 1, false);
	ucl_object_insert_key (metric, ucl_object_typed_new (UCL_ARRAY),
			"symbols", sizeof ("symbols") - 1, false);

	ucl_array_append (top, metric);

	return metric;
}

static ucl_object_t *
dynamic_metric_find_elt (const ucl_object_t *arr, const gchar *name)
{
	ucl_object_iter_t it = NULL;
	const ucl_object_t *cur, *n;

	it = ucl_object_iterate_new (arr);

	while ((cur = ucl_object_iterate_safe (it, true)) != NULL) {
		if (cur->type == UCL_OBJECT) {
			n = ucl_object_lookup (cur, "name");
			if (n && n->type == UCL_STRING &&
				strcmp (name, ucl_object_tostring (n)) == 0) {
				ucl_object_iterate_free (it);

				return (ucl_object_t *)ucl_object_lookup (cur, "value");
			}
		}
	}

	ucl_object_iterate_free (it);

	return NULL;
}

static ucl_object_t *
dynamic_metric_find_metric (const ucl_object_t *arr, const gchar *metric)
{
	ucl_object_iter_t it = NULL;
	const ucl_object_t *cur, *n;

	it = ucl_object_iterate_new (arr);

	while ((cur = ucl_object_iterate_safe (it, true)) != NULL) {
		if (cur->type == UCL_OBJECT) {
			n = ucl_object_lookup (cur, "metric");
			if (n && n->type == UCL_STRING &&
				strcmp (metric, ucl_object_tostring (n)) == 0) {
				ucl_object_iterate_free (it);

				return (ucl_object_t *)cur;
			}
		}
	}

	ucl_object_iterate_free (it);

	return NULL;
}

static ucl_object_t *
new_dynamic_elt (ucl_object_t *arr, const gchar *name, gdouble value)
{
	ucl_object_t *n;

	n = ucl_object_typed_new (UCL_OBJECT);
	ucl_object_insert_key (n, ucl_object_fromstring (name), "name",
		sizeof ("name") - 1, false);
	ucl_object_insert_key (n, ucl_object_fromdouble (value), "value",
		sizeof ("value") - 1, false);

	ucl_array_append (arr, n);

	return n;
}

static gint
rspamd_maybe_add_lua_dynsym (struct rspamd_config *cfg,
		const gchar *sym,
		gdouble score)
{
	lua_State *L = cfg->lua_state;
	gint ret = -1;
	struct rspamd_config **pcfg;

	lua_getglobal (L, "rspamd_plugins");
	if (lua_type (L, -1) == LUA_TTABLE) {
		lua_pushstring (L, "dynamic_conf");
		lua_gettable (L, -2);

		if (lua_type (L, -1) == LUA_TTABLE) {
			lua_pushstring (L, "add_symbol");
			lua_gettable (L, -2);

			if (lua_type (L, -1) == LUA_TFUNCTION) {
				pcfg = lua_newuserdata (L, sizeof (*pcfg));
				*pcfg = cfg;
				rspamd_lua_setclass (L, "rspamd{config}", -1);
				lua_pushstring (L, sym);
				lua_pushnumber (L, score);

				if (lua_pcall (L, 3, 1, 0) != 0) {
					msg_err_config ("cannot execute add_symbol script: %s",
							lua_tostring (L, -1));
				}
				else {
					ret = lua_toboolean (L, -1);
				}

				lua_pop (L, 1);
			}
			else {
				lua_pop (L, 1);
			}
		}

		lua_pop (L, 1);
	}

	lua_pop (L, 1);

	return ret;
}

static gint
rspamd_maybe_add_lua_dynact (struct rspamd_config *cfg,
		const gchar *action,
		gdouble score)
{
	lua_State *L = cfg->lua_state;
	gint ret = -1;
	struct rspamd_config **pcfg;

	lua_getglobal (L, "rspamd_plugins");
	if (lua_type (L, -1) == LUA_TTABLE) {
		lua_pushstring (L, "dynamic_conf");
		lua_gettable (L, -2);

		if (lua_type (L, -1) == LUA_TTABLE) {
			lua_pushstring (L, "add_action");
			lua_gettable (L, -2);

			if (lua_type (L, -1) == LUA_TFUNCTION) {
				pcfg = lua_newuserdata (L, sizeof (*pcfg));
				*pcfg = cfg;
				rspamd_lua_setclass (L, "rspamd{config}", -1);
				lua_pushstring (L, action);
				lua_pushnumber (L, score);

				if (lua_pcall (L, 3, 1, 0) != 0) {
					msg_err_config ("cannot execute add_action script: %s",
							lua_tostring (L, -1));
				}
				else {
					ret = lua_toboolean (L, -1);
				}

				lua_pop (L, 1);
			}
			else {
				lua_pop (L, 1);
			}
		}

		lua_pop (L, 1);
	}

	lua_pop (L, 1);

	return ret;
}

/**
 * Add symbol for specified metric
 * @param cfg config file object
 * @param metric metric's name
 * @param symbol symbol's name
 * @param value value of symbol
 * @return
 */
gboolean
add_dynamic_symbol (struct rspamd_config *cfg,
	const gchar *metric_name,
	const gchar *symbol,
	gdouble value)
{
	ucl_object_t *metric, *syms;
	gint ret;

	if ((ret = rspamd_maybe_add_lua_dynsym (cfg, symbol, value)) != -1) {
		return ret == 0 ? FALSE : TRUE;
	}

	if (cfg->dynamic_conf == NULL) {
		msg_info ("dynamic conf is disabled");
		return FALSE;
	}

	metric = dynamic_metric_find_metric (cfg->current_dynamic_conf,
			metric_name);
	if (metric == NULL) {
		metric = new_dynamic_metric (metric_name, cfg->current_dynamic_conf);
	}

	syms = (ucl_object_t *)ucl_object_lookup (metric, "symbols");
	if (syms != NULL) {
		ucl_object_t *sym;

		sym = dynamic_metric_find_elt (syms, symbol);
		if (sym) {
			sym->value.dv = value;
		}
		else {
			new_dynamic_elt (syms, symbol, value);
		}
	}

	apply_dynamic_conf (cfg->current_dynamic_conf, cfg);

	return TRUE;
}

gboolean
remove_dynamic_symbol (struct rspamd_config *cfg,
	const gchar *metric_name,
	const gchar *symbol)
{
	ucl_object_t *metric, *syms;
	gboolean ret = FALSE;

	if (cfg->dynamic_conf == NULL) {
		msg_info ("dynamic conf is disabled");
		return FALSE;
	}

	metric = dynamic_metric_find_metric (cfg->current_dynamic_conf,
			metric_name);
	if (metric == NULL) {
		return FALSE;
	}

	syms = (ucl_object_t *)ucl_object_lookup (metric, "symbols");
	if (syms != NULL) {
		ucl_object_t *sym;

		sym = dynamic_metric_find_elt (syms, symbol);

		if (sym) {
			ret = ucl_array_delete ((ucl_object_t *)syms, sym) != NULL;

			if (ret) {
				ucl_object_unref (sym);
			}
		}
	}

	if (ret) {
		apply_dynamic_conf (cfg->current_dynamic_conf, cfg);
	}

	return ret;
}


/**
 * Add action for specified metric
 * @param cfg config file object
 * @param metric metric's name
 * @param action action's name
 * @param value value of symbol
 * @return
 */
gboolean
add_dynamic_action (struct rspamd_config *cfg,
	const gchar *metric_name,
	guint action,
	gdouble value)
{
	ucl_object_t *metric, *acts;
	const gchar *action_name = rspamd_action_to_str (action);
	gint ret;

	if ((ret = rspamd_maybe_add_lua_dynact (cfg, action_name, value)) != -1) {
		return ret == 0 ? FALSE : TRUE;
	}

	if (cfg->dynamic_conf == NULL) {
		msg_info ("dynamic conf is disabled");
		return FALSE;
	}

	metric = dynamic_metric_find_metric (cfg->current_dynamic_conf,
			metric_name);
	if (metric == NULL) {
		metric = new_dynamic_metric (metric_name, cfg->current_dynamic_conf);
	}

	acts = (ucl_object_t *)ucl_object_lookup (metric, "actions");
	if (acts != NULL) {
		ucl_object_t *act;

		act = dynamic_metric_find_elt (acts, action_name);
		if (act) {
			act->value.dv = value;
		}
		else {
			new_dynamic_elt (acts, action_name, value);
		}
	}

	apply_dynamic_conf (cfg->current_dynamic_conf, cfg);

	return TRUE;
}

gboolean
remove_dynamic_action (struct rspamd_config *cfg,
	const gchar *metric_name,
	guint action)
{
	ucl_object_t *metric, *acts;
	const gchar *action_name = rspamd_action_to_str (action);
	gboolean ret = FALSE;

	if (cfg->dynamic_conf == NULL) {
		msg_info ("dynamic conf is disabled");
		return FALSE;
	}

	metric = dynamic_metric_find_metric (cfg->current_dynamic_conf,
			metric_name);
	if (metric == NULL) {
		return FALSE;
	}

	acts = (ucl_object_t *)ucl_object_lookup (metric, "actions");

	if (acts != NULL) {
		ucl_object_t *act;

		act = dynamic_metric_find_elt (acts, action_name);

		if (act) {
			ret = ucl_array_delete (acts, act) != NULL;
		}
		if (ret) {
			ucl_object_unref (act);
		}
	}

	if (ret) {
		apply_dynamic_conf (cfg->current_dynamic_conf, cfg);
	}

	return ret;
}
