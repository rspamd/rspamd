/* Copyright (c) 2013, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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

#include "cfg_rcl.h"
#include "main.h"
#include "uthash_strcase.h"
#include "utlist.h"
#include "cfg_file.h"
#include "lua/lua_common.h"
#include "expressions.h"
#include "classifiers/classifiers.h"
#include "tokenizers/tokenizers.h"


struct rspamd_rcl_default_handler_data {
	struct rspamd_rcl_struct_parser pd;
	const gchar *key;
	rspamd_rcl_handler_t handler;
	UT_hash_handle hh;
};

struct rspamd_rcl_section {
	const gchar *name;                  /**< name of section */
	rspamd_rcl_handler_t handler;       /**< handler of section attributes */
	enum ucl_type type;         /**< type of attribute */
	gboolean required;                  /**< whether this param is required */
	gboolean strict_type;               /**< whether we need strict type */
	UT_hash_handle hh;                  /** hash handle */
	struct rspamd_rcl_section *subsections; /**< hash table of subsections */
	struct rspamd_rcl_default_handler_data *default_parser; /**< generic parsing fields */
	rspamd_rcl_section_fin_t fin; /** called at the end of section parsing */
	gpointer fin_ud;
};

struct rspamd_worker_param_parser {
	rspamd_rcl_handler_t handler;                   /**< handler function									*/
	struct rspamd_rcl_struct_parser parser;         /**< parser attributes									*/
	const gchar *name;                              /**< parameter's name									*/
	UT_hash_handle hh;                              /**< hash by name										*/
};

struct rspamd_worker_cfg_parser {
	struct rspamd_worker_param_parser *parsers;     /**< parsers hash										*/
	gint type;                                      /**< workers quark										*/
	gboolean (*def_obj_parser)(const ucl_object_t *obj, gpointer ud);   /**< default object parser								*/
	gpointer def_ud;
	UT_hash_handle hh;                              /**< hash by type										*/
};

/*
 * Common section handlers
 */
static gboolean
rspamd_rcl_logging_handler (struct rspamd_config *cfg, const ucl_object_t *obj,
	gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	const ucl_object_t *val;
	const gchar *facility, *log_type, *log_level;

	val = ucl_object_find_key (obj, "type");
	if (val != NULL && ucl_object_tostring_safe (val, &log_type)) {
		if (g_ascii_strcasecmp (log_type, "file") == 0) {
			/* Need to get filename */
			val = ucl_object_find_key (obj, "filename");
			if (val == NULL || val->type != UCL_STRING) {
				g_set_error (err,
					CFG_RCL_ERROR,
					ENOENT,
					"filename attribute must be specified for file logging type");
				return FALSE;
			}
			cfg->log_type = RSPAMD_LOG_FILE;
			cfg->log_file = rspamd_mempool_strdup (cfg->cfg_pool,
					ucl_object_tostring (val));
		}
		else if (g_ascii_strcasecmp (log_type, "syslog") == 0) {
			/* Need to get facility */
			cfg->log_facility = LOG_DAEMON;
			cfg->log_type = RSPAMD_LOG_SYSLOG;
			val = ucl_object_find_key (obj, "facility");
			if (val != NULL && ucl_object_tostring_safe (val, &facility)) {
				if (g_ascii_strcasecmp (facility, "LOG_AUTH") == 0 ||
					g_ascii_strcasecmp (facility, "auth") == 0 ) {
					cfg->log_facility = LOG_AUTH;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_CRON") == 0 ||
					g_ascii_strcasecmp (facility, "cron") == 0 ) {
					cfg->log_facility = LOG_CRON;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_DAEMON") == 0 ||
					g_ascii_strcasecmp (facility, "daemon") == 0 ) {
					cfg->log_facility = LOG_DAEMON;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_MAIL") == 0 ||
					g_ascii_strcasecmp (facility, "mail") == 0) {
					cfg->log_facility = LOG_MAIL;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_USER") == 0 ||
					g_ascii_strcasecmp (facility, "user") == 0 ) {
					cfg->log_facility = LOG_USER;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_LOCAL0") == 0 ||
					g_ascii_strcasecmp (facility, "local0") == 0) {
					cfg->log_facility = LOG_LOCAL0;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_LOCAL1") == 0 ||
					g_ascii_strcasecmp (facility, "local1") == 0) {
					cfg->log_facility = LOG_LOCAL1;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_LOCAL2") == 0 ||
					g_ascii_strcasecmp (facility, "local2") == 0) {
					cfg->log_facility = LOG_LOCAL2;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_LOCAL3") == 0 ||
					g_ascii_strcasecmp (facility, "local3") == 0) {
					cfg->log_facility = LOG_LOCAL3;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_LOCAL4") == 0 ||
					g_ascii_strcasecmp (facility, "local4") == 0) {
					cfg->log_facility = LOG_LOCAL4;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_LOCAL5") == 0 ||
					g_ascii_strcasecmp (facility, "local5") == 0) {
					cfg->log_facility = LOG_LOCAL5;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_LOCAL6") == 0 ||
					g_ascii_strcasecmp (facility, "local6") == 0) {
					cfg->log_facility = LOG_LOCAL6;
				}
				else if (g_ascii_strcasecmp (facility, "LOG_LOCAL7") == 0 ||
					g_ascii_strcasecmp (facility, "local7") == 0) {
					cfg->log_facility = LOG_LOCAL7;
				}
				else {
					g_set_error (err,
						CFG_RCL_ERROR,
						EINVAL,
						"invalid log facility: %s",
						facility);
					return FALSE;
				}
			}
		}
		else if (g_ascii_strcasecmp (log_type,
			"stderr") == 0 || g_ascii_strcasecmp (log_type, "console") == 0) {
			cfg->log_type = RSPAMD_LOG_CONSOLE;
		}
		else {
			g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"invalid log type: %s",
				log_type);
			return FALSE;
		}
	}
	else {
		/* No type specified */
		msg_warn (
			"logging type is not specified correctly, log output to the console");
	}

	/* Handle log level */
	val = ucl_object_find_key (obj, "level");
	if (val != NULL && ucl_object_tostring_safe (val, &log_level)) {
		if (g_ascii_strcasecmp (log_level, "error") == 0) {
			cfg->log_level = G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL;
		}
		else if (g_ascii_strcasecmp (log_level, "warning") == 0) {
			cfg->log_level = G_LOG_LEVEL_WARNING;
		}
		else if (g_ascii_strcasecmp (log_level, "info") == 0) {
			cfg->log_level = G_LOG_LEVEL_INFO | G_LOG_LEVEL_MESSAGE;
		}
		else if (g_ascii_strcasecmp (log_level, "debug") == 0) {
			cfg->log_level = G_LOG_LEVEL_DEBUG;
		}
		else {
			g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"invalid log level: %s",
				log_level);
			return FALSE;
		}
	}

	return rspamd_rcl_section_parse_defaults (section, cfg, obj, cfg, err);
}

static gboolean
rspamd_rcl_options_handler (struct rspamd_config *cfg, const ucl_object_t *obj,
	gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	const ucl_object_t *dns, *upstream;
	struct rspamd_rcl_section *dns_section, *upstream_section;

	HASH_FIND_STR (section->subsections, "dns", dns_section);

	dns = ucl_object_find_key (obj, "dns");
	if (dns_section != NULL && dns != NULL) {
		if (!rspamd_rcl_section_parse_defaults (dns_section, cfg, dns, cfg,
			err)) {
			return FALSE;
		}
	}

	HASH_FIND_STR (section->subsections, "upstream", upstream_section);

	upstream = ucl_object_find_key (obj, "upstream");
	if (upstream_section != NULL && upstream != NULL) {
		if (!rspamd_rcl_section_parse_defaults (upstream_section, cfg,
			upstream, cfg, err)) {
			return FALSE;
		}
	}

	return rspamd_rcl_section_parse_defaults (section, cfg, obj, cfg, err);
}

static gint
rspamd_symbols_group_find_func (gconstpointer a, gconstpointer b)
{
	const struct rspamd_symbols_group *gr = a;
	const gchar *uv = b;

	return g_ascii_strcasecmp (gr->name, uv);
}

/**
 * Insert a symbol to the metric
 * @param cfg
 * @param metric
 * @param obj symbol rcl object (either float value or an object)
 * @param err
 * @return
 */
static gboolean
rspamd_rcl_insert_symbol (struct rspamd_config *cfg, struct metric *metric,
	const ucl_object_t *obj, gboolean is_legacy, GError **err)
{
	const gchar *group = "ungrouped", *description = NULL, *sym_name;
	gdouble symbol_score, *score_ptr;
	const ucl_object_t *val;
	struct rspamd_symbols_group *sym_group;
	struct rspamd_symbol_def *sym_def;
	GList *metric_list, *group_list;
	gboolean one_shot = FALSE;

	/*
	 * We allow two type of definitions:
	 * symbol = weight
	 * or
	 * symbol {
	 *	weight = ...;
	 *	description = ...;
	 *	group = ...;
	 *	one_shot = true/false;
	 * }
	 */
	if (is_legacy) {
		val = ucl_object_find_key (obj, "name");
		if (val == NULL) {
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "symbol name is missing");
			return FALSE;
		}
		sym_name = ucl_object_tostring (val);
	}
	else {
		sym_name = ucl_object_key (obj);
	}
	if (ucl_object_todouble_safe (obj, &symbol_score)) {
		description = NULL;
	}
	else if (obj->type == UCL_OBJECT) {
		val = ucl_object_find_key (obj, "weight");
		if (val == NULL || !ucl_object_todouble_safe (val, &symbol_score)) {
			g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"invalid symbol score: %s",
				sym_name);
			return FALSE;
		}
		val = ucl_object_find_key (obj, "description");
		if (val != NULL) {
			description = ucl_object_tostring (val);
		}
		val = ucl_object_find_key (obj, "group");
		if (val != NULL) {
			ucl_object_tostring_safe (val, &group);
		}
		val = ucl_object_find_key (obj, "one_shot");
		if (val != NULL) {
			one_shot = ucl_object_toboolean (val);
		}
	}
	else {
		g_set_error (err,
			CFG_RCL_ERROR,
			EINVAL,
			"invalid symbol type: %s",
			sym_name);
		return FALSE;
	}

	sym_def =
		rspamd_mempool_alloc (cfg->cfg_pool, sizeof (struct rspamd_symbol_def));
	score_ptr = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (gdouble));

	*score_ptr = symbol_score;
	sym_def->weight_ptr = score_ptr;
	sym_def->name = rspamd_mempool_strdup (cfg->cfg_pool, sym_name);
	sym_def->description = (gchar *)description;
	sym_def->one_shot = one_shot;

	g_hash_table_insert (metric->symbols, sym_def->name, sym_def);

	if ((metric_list =
		g_hash_table_lookup (cfg->metrics_symbols, sym_def->name)) == NULL) {
		metric_list = g_list_prepend (NULL, metric);
		rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)g_list_free,
			metric_list);
		g_hash_table_insert (cfg->metrics_symbols, sym_def->name, metric_list);
	}
	else {
		/* Slow but keep start element of list in safe */
		if (!g_list_find (metric_list, metric)) {
			metric_list = g_list_append (metric_list, metric);
		}
	}

	/* Search for symbol group */
	group_list = g_list_find_custom (cfg->symbols_groups,
			group,
			rspamd_symbols_group_find_func);
	if (group_list == NULL) {
		/* Create new group */
		sym_group =
			rspamd_mempool_alloc (cfg->cfg_pool,
				sizeof (struct rspamd_symbols_group));
		sym_group->name = rspamd_mempool_strdup (cfg->cfg_pool, group);
		sym_group->symbols = NULL;
		cfg->symbols_groups = g_list_prepend (cfg->symbols_groups, sym_group);
	}
	else {
		sym_group = group_list->data;
	}
	/* Insert symbol */
	sym_group->symbols = g_list_prepend (sym_group->symbols, sym_def);

	return TRUE;
}

static gboolean
rspamd_rcl_metric_handler (struct rspamd_config *cfg, const ucl_object_t *obj,
	gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	const ucl_object_t *val, *cur;
	const gchar *metric_name, *subject_name, *semicolon, *act_str;
	struct metric *metric;
	struct metric_action *action;
	gdouble action_score, grow_factor;
	gint action_value;
	gboolean new = TRUE, have_actions = FALSE;
	gdouble unknown_weight;
	ucl_object_iter_t it = NULL;

	val = ucl_object_find_key (obj, "name");
	if (val == NULL || !ucl_object_tostring_safe (val, &metric_name)) {
		metric_name = DEFAULT_METRIC;
	}

	metric = g_hash_table_lookup (cfg->metrics, metric_name);
	if (metric == NULL) {
		metric = rspamd_config_new_metric (cfg, metric);
		metric->name = metric_name;
	}
	else {
		new = FALSE;
	}

	/* Handle actions */
	val = ucl_object_find_key (obj, "actions");
	if (val != NULL) {
		if (val->type != UCL_OBJECT) {
			g_set_error (err, CFG_RCL_ERROR, EINVAL,
				"actions must be an object");
			return FALSE;
		}
		while ((cur = ucl_iterate_object (val, &it, true)) != NULL) {
			if (!rspamd_action_from_str (ucl_object_key (cur), &action_value) ||
				!ucl_object_todouble_safe (cur, &action_score)) {
				g_set_error (err,
					CFG_RCL_ERROR,
					EINVAL,
					"invalid action definition: %s",
					ucl_object_key (cur));
				return FALSE;
			}
			action = &metric->actions[action_value];
			action->action = action_value;
			action->score = action_score;
		}
	}
	else if (new) {
		/* Switch to legacy mode */
		val = ucl_object_find_key (obj, "required_score");
		if (val != NULL && ucl_object_todouble_safe (val, &action_score)) {
			action = &metric->actions[METRIC_ACTION_REJECT];
			action->action = METRIC_ACTION_REJECT;
			action->score = action_score;
			have_actions = TRUE;
		}
		val = ucl_object_find_key (obj, "action");
		LL_FOREACH (val, cur)
		{
			if (cur->type == UCL_STRING) {
				act_str = ucl_object_tostring (cur);
				semicolon = strchr (act_str, ':');
				if (semicolon != NULL) {
					if (rspamd_action_from_str (act_str, &action_value)) {
						action_score = strtod (semicolon + 1, NULL);
						action = &metric->actions[action_value];
						action->action = action_value;
						action->score = action_score;
						have_actions = TRUE;
					}
				}
			}
		}
		if (new && !have_actions) {
			g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"metric %s has no actions",
				metric_name);
			return FALSE;
		}
	}

	/* Handle symbols */
	val = ucl_object_find_key (obj, "symbols");
	if (val != NULL) {
		if (val->type == UCL_ARRAY) {
			val = val->value.ov;
		}
		if (val->type != UCL_OBJECT) {
			g_set_error (err, CFG_RCL_ERROR, EINVAL,
				"symbols must be an object");
			return FALSE;
		}
		it = NULL;
		while ((cur = ucl_iterate_object (val, &it, true)) != NULL) {
			if (!rspamd_rcl_insert_symbol (cfg, metric, cur, FALSE, err)) {
				return FALSE;
			}
		}
	}
	else {
		/* Legacy variant */
		val = ucl_object_find_key (obj, "symbol");
		if (val != NULL) {
			if (val->type == UCL_ARRAY) {
				val = val->value.ov;
			}
			if (val->type != UCL_OBJECT) {
				g_set_error (err,
					CFG_RCL_ERROR,
					EINVAL,
					"symbols must be an object");
				return FALSE;
			}
			LL_FOREACH (val, cur)
			{
				if (!rspamd_rcl_insert_symbol (cfg, metric, cur, TRUE, err)) {
					return FALSE;
				}
			}
		}
		else if (new) {
			g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"metric %s has no symbols",
				metric_name);
			return FALSE;
		}
	}

	val = ucl_object_find_key (obj, "grow_factor");
	if (val && ucl_object_todouble_safe (val, &grow_factor)) {
		metric->grow_factor = grow_factor;
	}

	val = ucl_object_find_key (obj, "subject");
	if (val && ucl_object_tostring_safe (val, &subject_name)) {
		metric->subject = (gchar *)subject_name;
	}

	val = ucl_object_find_key (obj, "unknown_weight");
	if (val && ucl_object_todouble_safe (val, &unknown_weight) &&
		unknown_weight != 0.) {
		metric->unknown_weight = unknown_weight;
		metric->accept_unknown_symbols = TRUE;
	}

	/* Insert the resulting metric */
	if (new) {
		g_hash_table_insert (cfg->metrics, (void *)metric->name, metric);
		cfg->metrics_list = g_list_prepend (cfg->metrics_list, metric);
		if (strcmp (metric->name, DEFAULT_METRIC) == 0) {
			cfg->default_metric = metric;
		}
	}

	return TRUE;
}

static gboolean
rspamd_rcl_worker_handler (struct rspamd_config *cfg, const ucl_object_t *obj,
	gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	const ucl_object_t *val, *cur;
	ucl_object_iter_t it = NULL;
	const gchar *worker_type, *worker_bind;
	GQuark qtype;
	struct rspamd_worker_conf *wrk;
	struct rspamd_worker_cfg_parser *wparser;
	struct rspamd_worker_param_parser *whandler;

	val = ucl_object_find_key (obj, "type");
	if (val != NULL && ucl_object_tostring_safe (val, &worker_type)) {
		qtype = g_quark_try_string (worker_type);
		if (qtype != 0) {
			wrk = rspamd_config_new_worker (cfg, NULL);
			wrk->worker = rspamd_get_worker_by_type (qtype);
			if (wrk->worker == NULL) {
				g_set_error (err,
					CFG_RCL_ERROR,
					EINVAL,
					"unknown worker type: %s",
					worker_type);
				return FALSE;
			}
			wrk->type = qtype;
			if (wrk->worker->worker_init_func) {
				wrk->ctx = wrk->worker->worker_init_func (cfg);
			}
		}
		else {
			g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"unknown worker type: %s",
				worker_type);
			return FALSE;
		}
	}
	else {
		g_set_error (err, CFG_RCL_ERROR, EINVAL, "undefined worker type");
		return FALSE;
	}

	val = ucl_object_find_key (obj, "bind_socket");
	if (val != NULL) {
		it = ucl_object_iterate_new (val);
		while ((cur = ucl_object_iterate_safe (it, true)) != NULL) {
			if (!ucl_object_tostring_safe (cur, &worker_bind)) {
				continue;
			}
			if (!rspamd_parse_bind_line (cfg, wrk, worker_bind)) {
				g_set_error (err,
					CFG_RCL_ERROR,
					EINVAL,
					"cannot parse bind line: %s",
					worker_bind);
				ucl_object_iterate_free (it);
				return FALSE;
			}
		}
		ucl_object_iterate_free (it);
	}

	wrk->options = (ucl_object_t *)obj;

	if (!rspamd_rcl_section_parse_defaults (section, cfg, obj, wrk, err)) {
		return FALSE;
	}

	/* Parse other attributes */
	HASH_FIND_INT (cfg->wrk_parsers, (gint *)&qtype, wparser);
	if (wparser != NULL && obj->type == UCL_OBJECT) {
		it = NULL;
		while ((cur = ucl_iterate_object (obj, &it, true)) != NULL) {
			HASH_FIND_STR (wparser->parsers, ucl_object_key (cur), whandler);
			if (whandler != NULL) {
				if (!whandler->handler (cfg, cur, &whandler->parser, section,
					err)) {
					return FALSE;
				}
			}
		}
		if (wparser->def_obj_parser != NULL) {
			if (!wparser->def_obj_parser (obj, wparser->def_ud)) {
				return FALSE;
			}
		}
	}

	cfg->workers = g_list_prepend (cfg->workers, wrk);

	return TRUE;
}

static void
rspamd_rcl_set_lua_globals (struct rspamd_config *cfg, lua_State *L)
{
	struct rspamd_config **pcfg;

	/* First check for global variable 'config' */
	lua_getglobal (L, "config");
	if (lua_isnil (L, -1)) {
		/* Assign global table to set up attributes */
		lua_newtable (L);
		lua_setglobal (L, "config");
	}

	lua_getglobal (L, "metrics");
	if (lua_isnil (L, -1)) {
		lua_newtable (L);
		lua_setglobal (L, "metrics");
	}

	lua_getglobal (L, "composites");
	if (lua_isnil (L, -1)) {
		lua_newtable (L);
		lua_setglobal (L, "composites");
	}

	lua_getglobal (L, "classifiers");
	if (lua_isnil (L, -1)) {
		lua_newtable (L);
		lua_setglobal (L, "classifiers");
	}

	pcfg = lua_newuserdata (L, sizeof (struct rspamd_config *));
	rspamd_lua_setclass (L, "rspamd{config}", -1);
	*pcfg = cfg;
	lua_setglobal (L, "rspamd_config");

	/* Clear stack from globals */
	lua_pop (L, 4);
}

static gboolean
rspamd_rcl_lua_handler (struct rspamd_config *cfg, const ucl_object_t *obj,
	gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	const gchar *lua_src = rspamd_mempool_strdup (cfg->cfg_pool,
			ucl_object_tostring (obj));
	gchar *cur_dir, *lua_dir, *lua_file, *tmp1, *tmp2;
	lua_State *L = cfg->lua_state;

	tmp1 = g_strdup (lua_src);
	tmp2 = g_strdup (lua_src);
	lua_dir = dirname (tmp1);
	lua_file = basename (tmp2);
	if (lua_dir && lua_file) {
		cur_dir = g_malloc (PATH_MAX);
		if (getcwd (cur_dir, PATH_MAX) != NULL && chdir (lua_dir) != -1) {
			/* Load file */
			if (luaL_loadfile (L, lua_file) != 0) {
				g_set_error (err,
					CFG_RCL_ERROR,
					EINVAL,
					"cannot load lua file %s: %s",
					lua_src,
					lua_tostring (L, -1));
				if (chdir (cur_dir) == -1) {
					msg_err ("cannot chdir to %s: %s", cur_dir,
						strerror (errno));;
				}
				g_free (cur_dir);
				g_free (tmp1);
				g_free (tmp2);
				return FALSE;
			}
			rspamd_rcl_set_lua_globals (cfg, L);
			/* Now do it */
			if (lua_pcall (L, 0, LUA_MULTRET, 0) != 0) {
				g_set_error (err,
					CFG_RCL_ERROR,
					EINVAL,
					"cannot init lua file %s: %s",
					lua_src,
					lua_tostring (L, -1));
				if (chdir (cur_dir) == -1) {
					msg_err ("cannot chdir to %s: %s", cur_dir,
						strerror (errno));;
				}
				g_free (cur_dir);
				g_free (tmp1);
				g_free (tmp2);
				return FALSE;
			}
		}
		else {
			g_set_error (err, CFG_RCL_ERROR, ENOENT, "cannot chdir to %s: %s",
				lua_src, strerror (errno));
			if (chdir (cur_dir) == -1) {
				msg_err ("cannot chdir to %s: %s", cur_dir, strerror (errno));;
			}
			g_free (cur_dir);
			g_free (tmp1);
			g_free (tmp2);
			return FALSE;

		}
		if (chdir (cur_dir) == -1) {
			msg_err ("cannot chdir to %s: %s", cur_dir, strerror (errno));;
		}
		g_free (cur_dir);
		g_free (tmp1);
		g_free (tmp2);
	}
	else {
		g_set_error (err, CFG_RCL_ERROR, ENOENT, "cannot find to %s: %s",
			lua_src, strerror (errno));
		return FALSE;
	}

	return TRUE;
}

static gboolean
rspamd_rcl_add_module_path (struct rspamd_config *cfg,
	const gchar *path,
	GError **err)
{
	struct stat st;
	struct script_module *cur_mod;
	glob_t globbuf;
	gchar *pattern;
	size_t len;
	guint i;

	if (stat (path, &st) == -1) {
		g_set_error (err,
			CFG_RCL_ERROR,
			errno,
			"cannot stat path %s, %s",
			path,
			strerror (errno));
		return FALSE;
	}

	/* Handle directory */
	if (S_ISDIR (st.st_mode)) {
		globbuf.gl_offs = 0;
		len = strlen (path) + sizeof ("*.lua");
		pattern = g_malloc (len);
		snprintf (pattern, len, "%s%s", path, "*.lua");

		if (glob (pattern, GLOB_DOOFFS, NULL, &globbuf) == 0) {
			for (i = 0; i < globbuf.gl_pathc; i++) {
				cur_mod =
					rspamd_mempool_alloc (cfg->cfg_pool,
						sizeof (struct script_module));
				cur_mod->path = rspamd_mempool_strdup (cfg->cfg_pool,
						globbuf.gl_pathv[i]);
				cfg->script_modules = g_list_prepend (cfg->script_modules,
						cur_mod);
			}
			globfree (&globbuf);
			g_free (pattern);
		}
		else {
			g_set_error (err,
				CFG_RCL_ERROR,
				errno,
				"glob failed for %s, %s",
				pattern,
				strerror (errno));
			g_free (pattern);
			return FALSE;
		}
	}
	else {
		/* Handle single file */
		cur_mod =
			rspamd_mempool_alloc (cfg->cfg_pool, sizeof (struct script_module));
		cur_mod->path = rspamd_mempool_strdup (cfg->cfg_pool, path);
		cfg->script_modules = g_list_prepend (cfg->script_modules, cur_mod);
	}

	return TRUE;
}

static gboolean
rspamd_rcl_modules_handler (struct rspamd_config *cfg, const ucl_object_t *obj,
	gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	const ucl_object_t *val, *cur;
	const gchar *data;

	if (obj->type == UCL_OBJECT) {
		val = ucl_object_find_key (obj, "path");

		LL_FOREACH (val, cur)
		{
			if (ucl_object_tostring_safe (cur, &data)) {
				if (!rspamd_rcl_add_module_path (cfg,
					rspamd_mempool_strdup (cfg->cfg_pool, data), err)) {
					return FALSE;
				}
			}
		}
	}
	else if (ucl_object_tostring_safe (obj, &data)) {
		if (!rspamd_rcl_add_module_path (cfg,
			rspamd_mempool_strdup (cfg->cfg_pool, data), err)) {
			return FALSE;
		}
	}
	else {
		g_set_error (err,
			CFG_RCL_ERROR,
			EINVAL,
			"module parameter has wrong type (must be an object or a string)");
		return FALSE;
	}

	return TRUE;
}

static gboolean
rspamd_rcl_statfile_handler (struct rspamd_config *cfg, const ucl_object_t *obj,
	gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	struct rspamd_classifier_config *ccf = ud;
	const ucl_object_t *val;
	struct rspamd_statfile_config *st;
	GList *labels;

	st = rspamd_config_new_statfile (cfg, NULL);

#if 0
	const gchar *data;
	gdouble binlog_rotate;
	val = ucl_object_find_key (obj, "binlog");
	if (val != NULL && ucl_object_tostring_safe (val, &data)) {
		if (st->binlog == NULL) {
			st->binlog =
				rspamd_mempool_alloc0 (cfg->cfg_pool,
					sizeof (struct statfile_binlog_params));
		}
		if (g_ascii_strcasecmp (data, "master") == 0) {
			st->binlog->affinity = AFFINITY_MASTER;
		}
		else if (g_ascii_strcasecmp (data, "slave") == 0) {
			st->binlog->affinity = AFFINITY_SLAVE;
		}
		else {
			st->binlog->affinity = AFFINITY_NONE;
		}
		/* Parse remaining binlog attributes */
		val = ucl_object_find_key (obj, "binlog_rotate");
		if (val != NULL && ucl_object_todouble_safe (val, &binlog_rotate)) {
			st->binlog->rotate_time = binlog_rotate;
		}
		val = ucl_object_find_key (obj, "binlog_master");
		if (val != NULL && ucl_object_tostring_safe (val, &data)) {
			if (!rspamd_parse_host_port (cfg->cfg_pool, data,
				&st->binlog->master_addr, &st->binlog->master_port)) {
				msg_err ("cannot parse master address: %s", data);
				return FALSE;
			}
		}
	}
#endif


	if (rspamd_rcl_section_parse_defaults (section, cfg, obj, st, err)) {
		ccf->statfiles = g_list_prepend (ccf->statfiles, st);
		if (st->label != NULL) {
			labels = g_hash_table_lookup (ccf->labels, st->label);
			if (labels != NULL) {
				labels = g_list_append (labels, st);
			}
			else {
				g_hash_table_insert (ccf->labels, st->label,
					g_list_prepend (NULL, st));
			}
		}
		if (st->symbol != NULL) {
			g_hash_table_insert (cfg->classifiers_symbols, st->symbol, st);
		}
		else {
			g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"statfile must have a symbol defined");
			return FALSE;
		}

		if (st->path == NULL) {
			g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"statfile must have a path defined");
			return FALSE;
		}

		st->opts = (ucl_object_t *)obj;

		val = ucl_object_find_key (obj, "spam");
		if (val == NULL) {
			msg_info (
				"statfile %s has no explicit 'spam' setting, trying to guess by symbol",
				st->symbol);
			if (rspamd_strncasestr (st->symbol, "spam",
				strlen (st->symbol)) != NULL) {
				st->is_spam = TRUE;
			}
			else if (rspamd_strncasestr (st->symbol, "ham",
				strlen (st->symbol)) != NULL) {
				st->is_spam = FALSE;
			}
			else {
				g_set_error (err,
					CFG_RCL_ERROR,
					EINVAL,
					"cannot guess spam setting from %s",
					st->symbol);
				return FALSE;
			}
			msg_info ("guessed that statfile with symbol %s is %s",
				st->symbol,
				st->is_spam ?
				"spam" : "ham");
		}
		return TRUE;
	}

	return FALSE;
}

static gboolean
rspamd_rcl_classifier_handler (struct rspamd_config *cfg,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	const ucl_object_t *val, *cur;
	ucl_object_iter_t it = NULL;
	const gchar *key, *type;
	struct rspamd_classifier_config *ccf, *found = NULL;
	gboolean res = TRUE;
	struct rspamd_rcl_section *stat_section;
	GList *cur_cl;

	val = ucl_object_find_key (obj, "type");
	if (val == NULL || !ucl_object_tostring_safe (val, &type)) {
		g_set_error (err,
			CFG_RCL_ERROR,
			EINVAL,
			"classifier should have type defined");
		return FALSE;
	}

	cur_cl = cfg->classifiers;
	while (cur_cl != NULL) {
		ccf = cur_cl->data;
		if (g_ascii_strcasecmp (ccf->classifier->name, type) == 0) {
			found = ccf;
			break;
		}
		cur_cl = g_list_next (cur_cl);
	}

	if (found == NULL) {
		ccf = rspamd_config_new_classifier (cfg, NULL);
		ccf->classifier = get_classifier (type);
	}
	else {
		ccf = found;
	}

	HASH_FIND_STR (section->subsections, "statfile", stat_section);

	while ((val = ucl_iterate_object (obj, &it, true)) != NULL && res) {
		key = ucl_object_key (val);
		if (key != NULL) {
			if (g_ascii_strcasecmp (key, "statfile") == 0) {
				LL_FOREACH (val, cur)
				{
					res = rspamd_rcl_statfile_handler (cfg,
							cur,
							ccf,
							stat_section,
							err);
					if (!res) {
						return FALSE;
					}
				}
			}
			else if (g_ascii_strcasecmp (key,
				"type") == 0 && val->type == UCL_STRING) {
				continue;
			}
			else if (g_ascii_strcasecmp (key,
				"tokenizer") == 0 && val->type == UCL_STRING) {
				ccf->tokenizer = get_tokenizer (ucl_object_tostring (val));
			}
			else {
				/* Just insert a value of option to the hash */
				g_hash_table_insert (ccf->opts,
					(gpointer)key,
					(gpointer)ucl_object_tostring_forced (val));
			}
		}
	}

	if (found == NULL) {
		cfg->classifiers = g_list_prepend (cfg->classifiers, ccf);
	}


	return res;
}

static gboolean
rspamd_rcl_composite_handler (struct rspamd_config *cfg,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	const ucl_object_t *val;
	struct expression *expr;
	struct rspamd_composite *composite;
	const gchar *composite_name, *composite_expression;
	gboolean new = TRUE;

	val = ucl_object_find_key (obj, "name");
	if (val == NULL || !ucl_object_tostring_safe (val, &composite_name)) {
		g_set_error (err,
			CFG_RCL_ERROR,
			EINVAL,
			"composite must have a name defined");
		return FALSE;
	}

	if (g_hash_table_lookup (cfg->composite_symbols, composite_name) != NULL) {
		msg_warn ("composite %s is redefined", composite_name);
		new = FALSE;
	}

	val = ucl_object_find_key (obj, "expression");
	if (val == NULL || !ucl_object_tostring_safe (val, &composite_expression)) {
		g_set_error (err,
			CFG_RCL_ERROR,
			EINVAL,
			"composite must have an expression defined");
		return FALSE;
	}

	if ((expr =
		parse_expression (cfg->cfg_pool,
		(gchar *)composite_expression)) == NULL) {
		g_set_error (err,
			CFG_RCL_ERROR,
			EINVAL,
			"cannot parse composite expression: %s",
			composite_expression);
		return FALSE;
	}

	composite =
		rspamd_mempool_alloc (cfg->cfg_pool, sizeof (struct rspamd_composite));
	composite->expr = expr;
	composite->id = g_hash_table_size (cfg->composite_symbols);
	g_hash_table_insert (cfg->composite_symbols,
		(gpointer)composite_name,
		composite);

	if (new) {
		register_virtual_symbol (&cfg->cache, composite_name, 1);
	}

	return TRUE;
}

/**
 * Add new section to the configuration
 * @param top top section
 * @param name the name of the section
 * @param handler handler function for all attributes
 * @param type type of object handled by a handler
 * @param required whether at least one of these sections is required
 * @param strict_type turn on strict check for types for this section
 * @return newly created structure
 */
static inline struct rspamd_rcl_section *
rspamd_rcl_add_section (struct rspamd_rcl_section **top,
	const gchar *name, rspamd_rcl_handler_t handler,
	enum ucl_type type, gboolean required, gboolean strict_type)
{
	struct rspamd_rcl_section *new;

	new = g_slice_alloc0 (sizeof (struct rspamd_rcl_section));
	new->name = name;
	new->handler = handler;
	new->type = type;
	new->strict_type = strict_type;

	HASH_ADD_KEYPTR (hh, *top, new->name, strlen (new->name), new);
	return new;
}

/**
 * Add a default handler for a section
 * @param section section pointer
 * @param name name of param
 * @param handler handler of param
 * @param offset offset in a structure
 * @param flags flags for the parser
 * @return newly created structure
 */
static inline struct rspamd_rcl_default_handler_data *
rspamd_rcl_add_default_handler (struct rspamd_rcl_section *section,
	const gchar *name,
	rspamd_rcl_handler_t handler,
	gsize offset,
	gint flags)
{
	struct rspamd_rcl_default_handler_data *new;

	new = g_slice_alloc0 (sizeof (struct rspamd_rcl_default_handler_data));
	new->key = name;
	new->handler = handler;
	new->pd.offset = offset;
	new->pd.flags = flags;

	HASH_ADD_KEYPTR (hh, section->default_parser, new->key, strlen (
			new->key), new);
	return new;
}

struct rspamd_rcl_section *
rspamd_rcl_config_init (void)
{
	struct rspamd_rcl_section *new = NULL, *sub, *ssub;

	/*
	 * Important notice:
	 * the order of parsing is equal to order of this initialization, therefore
	 * it is possible to init some portions of config prior to others
	 */

	/**
	 * Logging section
	 */
	sub = rspamd_rcl_add_section (&new,
			"logging",
			rspamd_rcl_logging_handler,
			UCL_OBJECT,
			FALSE,
			TRUE);
	/* Default handlers */
	rspamd_rcl_add_default_handler (sub,
		"log_buffer",
		rspamd_rcl_parse_struct_integer,
		G_STRUCT_OFFSET (struct rspamd_config, log_buf_size),
		0);
	rspamd_rcl_add_default_handler (sub,
		"log_urls",
		rspamd_rcl_parse_struct_boolean,
		G_STRUCT_OFFSET (struct rspamd_config, log_urls),
		0);
	rspamd_rcl_add_default_handler (sub,
		"debug_ip",
		rspamd_rcl_parse_struct_string,
		G_STRUCT_OFFSET (struct rspamd_config, debug_ip_map),
		0);
	rspamd_rcl_add_default_handler (sub,
		"debug_symbols",
		rspamd_rcl_parse_struct_string_list,
		G_STRUCT_OFFSET (struct rspamd_config, debug_symbols),
		0);
	rspamd_rcl_add_default_handler (sub,
		"log_color",
		rspamd_rcl_parse_struct_boolean,
		G_STRUCT_OFFSET (struct rspamd_config, log_color),
		0);
	/**
	 * Options section
	 */
	sub = rspamd_rcl_add_section (&new,
			"options",
			rspamd_rcl_options_handler,
			UCL_OBJECT,
			FALSE,
			TRUE);
	rspamd_rcl_add_default_handler (sub,
		"cache_file",
		rspamd_rcl_parse_struct_string,
		G_STRUCT_OFFSET (struct rspamd_config, cache_filename),
		RSPAMD_CL_FLAG_STRING_PATH);
	/* Old DNS configuration */
	rspamd_rcl_add_default_handler (sub,
		"dns_nameserver",
		rspamd_rcl_parse_struct_string_list,
		G_STRUCT_OFFSET (struct rspamd_config, nameservers),
		0);
	rspamd_rcl_add_default_handler (sub,
		"dns_timeout",
		rspamd_rcl_parse_struct_time,
		G_STRUCT_OFFSET (struct rspamd_config, dns_timeout),
		RSPAMD_CL_FLAG_TIME_FLOAT);
	rspamd_rcl_add_default_handler (sub,
		"dns_retransmits",
		rspamd_rcl_parse_struct_integer,
		G_STRUCT_OFFSET (struct rspamd_config, dns_retransmits),
		RSPAMD_CL_FLAG_INT_32);
	rspamd_rcl_add_default_handler (sub,
		"dns_sockets",
		rspamd_rcl_parse_struct_integer,
		G_STRUCT_OFFSET (struct rspamd_config, dns_io_per_server),
		RSPAMD_CL_FLAG_INT_32);

	/* New DNS configiration */
	ssub = rspamd_rcl_add_section (&sub->subsections, "dns", NULL,
			UCL_OBJECT, FALSE, TRUE);
	rspamd_rcl_add_default_handler (ssub,
		"nameserver",
		rspamd_rcl_parse_struct_string_list,
		G_STRUCT_OFFSET (struct rspamd_config, nameservers),
		0);
	rspamd_rcl_add_default_handler (ssub,
		"timeout",
		rspamd_rcl_parse_struct_time,
		G_STRUCT_OFFSET (struct rspamd_config, dns_timeout),
		RSPAMD_CL_FLAG_TIME_FLOAT);
	rspamd_rcl_add_default_handler (ssub,
		"retransmits",
		rspamd_rcl_parse_struct_integer,
		G_STRUCT_OFFSET (struct rspamd_config, dns_retransmits),
		RSPAMD_CL_FLAG_INT_32);
	rspamd_rcl_add_default_handler (ssub,
		"sockets",
		rspamd_rcl_parse_struct_integer,
		G_STRUCT_OFFSET (struct rspamd_config, dns_io_per_server),
		RSPAMD_CL_FLAG_INT_32);

	/* New upstreams configuration */
	ssub = rspamd_rcl_add_section (&sub->subsections, "upstream", NULL,
		UCL_OBJECT, FALSE, TRUE);
	rspamd_rcl_add_default_handler (ssub,
		"max_errors",
		rspamd_rcl_parse_struct_integer,
		G_STRUCT_OFFSET (struct rspamd_config, upstream_max_errors),
		RSPAMD_CL_FLAG_UINT);
	rspamd_rcl_add_default_handler (ssub,
		"error_time",
		rspamd_rcl_parse_struct_time,
		G_STRUCT_OFFSET (struct rspamd_config, upstream_error_time),
		RSPAMD_CL_FLAG_TIME_FLOAT);
	rspamd_rcl_add_default_handler (ssub,
		"revive_time",
		rspamd_rcl_parse_struct_time,
		G_STRUCT_OFFSET (struct rspamd_config, upstream_revive_time),
		RSPAMD_CL_FLAG_TIME_FLOAT);

	rspamd_rcl_add_default_handler (sub,
		"raw_mode",
		rspamd_rcl_parse_struct_boolean,
		G_STRUCT_OFFSET (struct rspamd_config, raw_mode),
		0);
	rspamd_rcl_add_default_handler (sub,
		"one_shot",
		rspamd_rcl_parse_struct_boolean,
		G_STRUCT_OFFSET (struct rspamd_config, one_shot_mode),
		0);
	rspamd_rcl_add_default_handler (sub,
		"check_attachements",
		rspamd_rcl_parse_struct_boolean,
		G_STRUCT_OFFSET (struct rspamd_config, check_text_attachements),
		0);
	rspamd_rcl_add_default_handler (sub,
		"tempdir",
		rspamd_rcl_parse_struct_string,
		G_STRUCT_OFFSET (struct rspamd_config, temp_dir),
		RSPAMD_CL_FLAG_STRING_PATH);
	rspamd_rcl_add_default_handler (sub,
		"pidfile",
		rspamd_rcl_parse_struct_string,
		G_STRUCT_OFFSET (struct rspamd_config, pid_file),
		RSPAMD_CL_FLAG_STRING_PATH);
	rspamd_rcl_add_default_handler (sub,
		"filters",
		rspamd_rcl_parse_struct_string,
		G_STRUCT_OFFSET (struct rspamd_config, filters_str),
		0);
	rspamd_rcl_add_default_handler (sub,
		"sync_interval",
		rspamd_rcl_parse_struct_time,
		G_STRUCT_OFFSET (struct rspamd_config, statfile_sync_interval),
		RSPAMD_CL_FLAG_TIME_INTEGER);
	rspamd_rcl_add_default_handler (sub,
		"sync_timeout",
		rspamd_rcl_parse_struct_time,
		G_STRUCT_OFFSET (struct rspamd_config, statfile_sync_timeout),
		RSPAMD_CL_FLAG_TIME_INTEGER);
	rspamd_rcl_add_default_handler (sub,
		"max_diff",
		rspamd_rcl_parse_struct_integer,
		G_STRUCT_OFFSET (struct rspamd_config, max_diff),
		RSPAMD_CL_FLAG_INT_SIZE);
	rspamd_rcl_add_default_handler (sub,
		"map_watch_interval",
		rspamd_rcl_parse_struct_time,
		G_STRUCT_OFFSET (struct rspamd_config, map_timeout),
		RSPAMD_CL_FLAG_TIME_FLOAT);
	rspamd_rcl_add_default_handler (sub,
		"dynamic_conf",
		rspamd_rcl_parse_struct_string,
		G_STRUCT_OFFSET (struct rspamd_config, dynamic_conf),
		0);
	rspamd_rcl_add_default_handler (sub, "rrd", rspamd_rcl_parse_struct_string,
		G_STRUCT_OFFSET (struct rspamd_config,
		rrd_file), RSPAMD_CL_FLAG_STRING_PATH);
	rspamd_rcl_add_default_handler (sub,
		"history_file",
		rspamd_rcl_parse_struct_string,
		G_STRUCT_OFFSET (struct rspamd_config, history_file),
		RSPAMD_CL_FLAG_STRING_PATH);
	rspamd_rcl_add_default_handler (sub,
		"use_mlock",
		rspamd_rcl_parse_struct_boolean,
		G_STRUCT_OFFSET (struct rspamd_config, mlock_statfile_pool),
		0);
	rspamd_rcl_add_default_handler (sub,
		"strict_protocol_headers",
		rspamd_rcl_parse_struct_boolean,
		G_STRUCT_OFFSET (struct rspamd_config, strict_protocol_headers),
		0);
	rspamd_rcl_add_default_handler (sub,
		"check_all_filters",
		rspamd_rcl_parse_struct_boolean,
		G_STRUCT_OFFSET (struct rspamd_config, check_all_filters),
		0);

	/**
	 * Metric section
	 */
	sub = rspamd_rcl_add_section (&new,
			"metric",
			rspamd_rcl_metric_handler,
			UCL_OBJECT,
			FALSE,
			TRUE);

	/**
	 * Worker section
	 */
	sub = rspamd_rcl_add_section (&new,
			"worker",
			rspamd_rcl_worker_handler,
			UCL_OBJECT,
			FALSE,
			TRUE);
	rspamd_rcl_add_default_handler (sub,
		"count",
		rspamd_rcl_parse_struct_integer,
		G_STRUCT_OFFSET (struct rspamd_worker_conf, count),
		RSPAMD_CL_FLAG_INT_16);
	rspamd_rcl_add_default_handler (sub,
		"max_files",
		rspamd_rcl_parse_struct_integer,
		G_STRUCT_OFFSET (struct rspamd_worker_conf, rlimit_nofile),
		RSPAMD_CL_FLAG_INT_32);
	rspamd_rcl_add_default_handler (sub,
		"max_core",
		rspamd_rcl_parse_struct_integer,
		G_STRUCT_OFFSET (struct rspamd_worker_conf, rlimit_maxcore),
		RSPAMD_CL_FLAG_INT_32);

	/**
	 * Modules handler
	 */
	sub = rspamd_rcl_add_section (&new,
			"modules",
			rspamd_rcl_modules_handler,
			UCL_OBJECT,
			FALSE,
			FALSE);

	/**
	 * Classifiers handler
	 */
	sub = rspamd_rcl_add_section (&new,
			"classifier",
			rspamd_rcl_classifier_handler,
			UCL_OBJECT,
			FALSE,
			TRUE);
	ssub = rspamd_rcl_add_section (&sub->subsections,
			"statfile",
			rspamd_rcl_statfile_handler,
			UCL_OBJECT,
			TRUE,
			TRUE);
	rspamd_rcl_add_default_handler (ssub,
		"symbol",
		rspamd_rcl_parse_struct_string,
		G_STRUCT_OFFSET (struct rspamd_statfile_config, symbol),
		0);
	rspamd_rcl_add_default_handler (ssub,
		"path",
		rspamd_rcl_parse_struct_string,
		G_STRUCT_OFFSET (struct rspamd_statfile_config, path),
		RSPAMD_CL_FLAG_STRING_PATH);
	rspamd_rcl_add_default_handler (ssub,
		"label",
		rspamd_rcl_parse_struct_string,
		G_STRUCT_OFFSET (struct rspamd_statfile_config, label),
		0);
	rspamd_rcl_add_default_handler (ssub,
		"size",
		rspamd_rcl_parse_struct_integer,
		G_STRUCT_OFFSET (struct rspamd_statfile_config, size),
		RSPAMD_CL_FLAG_INT_SIZE);
	rspamd_rcl_add_default_handler (ssub,
		"spam",
		rspamd_rcl_parse_struct_boolean,
		G_STRUCT_OFFSET (struct rspamd_statfile_config, is_spam),
		0);

	/**
	 * Composites handler
	 */
	sub = rspamd_rcl_add_section (&new,
			"composite",
			rspamd_rcl_composite_handler,
			UCL_OBJECT,
			FALSE,
			TRUE);

	/**
	 * Lua handler
	 */
	sub = rspamd_rcl_add_section (&new,
			"lua",
			rspamd_rcl_lua_handler,
			UCL_STRING,
			FALSE,
			TRUE);

	return new;
}

struct rspamd_rcl_section *
rspamd_rcl_config_get_section (struct rspamd_rcl_section *top,
	const char *path)
{
	struct rspamd_rcl_section *cur, *found;
	char **path_components;
	gint ncomponents, i;


	if (path == NULL) {
		return top;
	}

	path_components = g_strsplit_set (path, "/", -1);
	ncomponents = g_strv_length (path_components);

	cur = top;
	for (i = 0; i < ncomponents; i++) {
		if (cur == NULL) {
			g_strfreev (path_components);
			return NULL;
		}
		HASH_FIND_STR (cur, path_components[i], found);
		if (found == NULL) {
			g_strfreev (path_components);
			return NULL;
		}
		cur = found;
	}

	g_strfreev (path_components);
	return found;
}

gboolean
rspamd_read_rcl_config (struct rspamd_rcl_section *top,
	struct rspamd_config *cfg, const ucl_object_t *obj, GError **err)
{
	const ucl_object_t *found, *cur_obj;
	struct rspamd_rcl_section *cur, *tmp;

	if (obj->type != UCL_OBJECT) {
		g_set_error (err,
			CFG_RCL_ERROR,
			EINVAL,
			"top configuration must be an object");
		return FALSE;
	}

	/* Iterate over known sections and ignore unknown ones */
	HASH_ITER (hh, top, cur, tmp)
	{
		found = ucl_object_find_key (obj, cur->name);
		if (found == NULL) {
			if (cur->required) {
				g_set_error (err, CFG_RCL_ERROR, ENOENT,
					"required section %s is missing", cur->name);
				return FALSE;
			}
		}
		else {
			/* Check type */
			if (cur->strict_type) {
				if (cur->type != found->type) {
					g_set_error (err, CFG_RCL_ERROR, EINVAL,
						"object in section %s has invalid type", cur->name);
					return FALSE;
				}
			}
			LL_FOREACH (found, cur_obj)
			{
				if (cur->handler != NULL) {
					if (!cur->handler (cfg, cur_obj, NULL, cur, err)) {
						return FALSE;
					}
				}
				else {
					rspamd_rcl_section_parse_defaults (cur,
						cfg,
						cur_obj,
						cfg,
						err);
				}
			}
		}
		if (cur->fin) {
			cur->fin (cfg, cur->fin_ud);
		}
	}

	cfg->rcl_obj = (ucl_object_t *)obj;

	return TRUE;
}

gboolean
rspamd_rcl_section_parse_defaults (struct rspamd_rcl_section *section,
	struct rspamd_config *cfg, const ucl_object_t *obj, gpointer ptr,
	GError **err)
{
	const ucl_object_t *found;
	struct rspamd_rcl_default_handler_data *cur, *tmp;

	if (obj->type != UCL_OBJECT) {
		g_set_error (err,
			CFG_RCL_ERROR,
			EINVAL,
			"default configuration must be an object");
		return FALSE;
	}

	HASH_ITER (hh, section->default_parser, cur, tmp)
	{
		found = ucl_object_find_key (obj, cur->key);
		if (found != NULL) {
			cur->pd.user_struct = ptr;
			if (!cur->handler (cfg, found, &cur->pd, section, err)) {
				return FALSE;
			}
		}
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_string (struct rspamd_config *cfg,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	gchar **target;
	const gsize num_str_len = 32;

	target = (gchar **)(((gchar *)pd->user_struct) + pd->offset);
	switch (obj->type) {
	case UCL_STRING:
		*target =
			rspamd_mempool_strdup (cfg->cfg_pool, ucl_copy_value_trash (obj));
		break;
	case UCL_INT:
		*target = rspamd_mempool_alloc (cfg->cfg_pool, num_str_len);
		rspamd_snprintf (*target, num_str_len, "%L", obj->value.iv);
		break;
	case UCL_FLOAT:
		*target = rspamd_mempool_alloc (cfg->cfg_pool, num_str_len);
		rspamd_snprintf (*target, num_str_len, "%f", obj->value.dv);
		break;
	case UCL_BOOLEAN:
		*target = rspamd_mempool_alloc (cfg->cfg_pool, num_str_len);
		rspamd_snprintf (*target, num_str_len, "%b", (gboolean)obj->value.iv);
		break;
	default:
		g_set_error (err,
			CFG_RCL_ERROR,
			EINVAL,
			"cannot convert object or array to string");
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_integer (struct rspamd_config *cfg,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	union {
		gint *ip;
		gint32 *i32p;
		gint16 *i16p;
		gint64 *i64p;
		guint *up;
		gsize *sp;
	} target;
	gint64 val;

	if (pd->flags == RSPAMD_CL_FLAG_INT_32) {
		target.i32p = (gint32 *)(((gchar *)pd->user_struct) + pd->offset);
		if (!ucl_object_toint_safe (obj, &val)) {
			g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"cannot convert param to integer");
			return FALSE;
		}
		*target.i32p = val;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_INT_64) {
		target.i64p = (gint64 *)(((gchar *)pd->user_struct) + pd->offset);
		if (!ucl_object_toint_safe (obj, &val)) {
			g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"cannot convert param to integer");
			return FALSE;
		}
		*target.i64p = val;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_INT_SIZE) {
		target.sp = (gsize *)(((gchar *)pd->user_struct) + pd->offset);
		if (!ucl_object_toint_safe (obj, &val)) {
			g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"cannot convert param to integer");
			return FALSE;
		}
		*target.sp = val;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_INT_16) {
		target.i16p = (gint16 *)(((gchar *)pd->user_struct) + pd->offset);
		if (!ucl_object_toint_safe (obj, &val)) {
			g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"cannot convert param to integer");
			return FALSE;
		}
		*target.i16p = val;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_UINT) {
		target.up = (guint *)(((gchar *)pd->user_struct) + pd->offset);
		if (!ucl_object_toint_safe (obj, &val)) {
			g_set_error (err,
					CFG_RCL_ERROR,
					EINVAL,
					"cannot convert param to integer");
			return FALSE;
		}
		*target.up = val;
	}
	else {
		target.ip = (gint *)(((gchar *)pd->user_struct) + pd->offset);
		if (!ucl_object_toint_safe (obj, &val)) {
			g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"cannot convert param to integer");
			return FALSE;
		}
		*target.ip = val;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_double (struct rspamd_config *cfg,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	gdouble *target;

	target = (gdouble *)(((gchar *)pd->user_struct) + pd->offset);

	if (!ucl_object_todouble_safe (obj, target)) {
		g_set_error (err,
			CFG_RCL_ERROR,
			EINVAL,
			"cannot convert param to double");
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_time (struct rspamd_config *cfg,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	union {
		gint *psec;
		guint32 *pu32;
		gdouble *pdv;
		struct timeval *ptv;
		struct timespec *pts;
	} target;
	gdouble val;

	if (!ucl_object_todouble_safe (obj, &val)) {
		g_set_error (err,
			CFG_RCL_ERROR,
			EINVAL,
			"cannot convert param to double");
		return FALSE;
	}

	if (pd->flags == RSPAMD_CL_FLAG_TIME_TIMEVAL) {
		target.ptv =
			(struct timeval *)(((gchar *)pd->user_struct) + pd->offset);
		target.ptv->tv_sec = (glong)val;
		target.ptv->tv_usec = (val - (glong)val) * 1000000;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_TIME_TIMESPEC) {
		target.pts =
			(struct timespec *)(((gchar *)pd->user_struct) + pd->offset);
		target.pts->tv_sec = (glong)val;
		target.pts->tv_nsec = (val - (glong)val) * 1000000000000LL;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_TIME_FLOAT) {
		target.pdv = (double *)(((gchar *)pd->user_struct) + pd->offset);
		*target.pdv = val;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_TIME_INTEGER) {
		target.psec = (gint *)(((gchar *)pd->user_struct) + pd->offset);
		*target.psec = val * 1000;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_TIME_UINT_32) {
		target.pu32 = (guint32 *)(((gchar *)pd->user_struct) + pd->offset);
		*target.pu32 = val * 1000;
	}
	else {
		g_set_error (err,
			CFG_RCL_ERROR,
			EINVAL,
			"invalid flags to parse time value");
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_string_list (struct rspamd_config *cfg,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	GList **target;
	gchar *val;
	const ucl_object_t *cur;
	const gsize num_str_len = 32;
	ucl_object_iter_t iter = NULL;

	target = (GList **)(((gchar *)pd->user_struct) + pd->offset);

	if (obj->type != UCL_ARRAY) {
		g_set_error (err,
			CFG_RCL_ERROR,
			EINVAL,
			"an array of strings is expected");
		return FALSE;
	}

	while ((cur = ucl_iterate_object (obj, &iter, true)) != NULL) {
		switch (cur->type) {
		case UCL_STRING:
			val =
				rspamd_mempool_strdup (cfg->cfg_pool,
					ucl_copy_value_trash (cur));
			break;
		case UCL_INT:
			val = rspamd_mempool_alloc (cfg->cfg_pool, num_str_len);
			rspamd_snprintf (val, num_str_len, "%L", cur->value.iv);
			break;
		case UCL_FLOAT:
			val = rspamd_mempool_alloc (cfg->cfg_pool, num_str_len);
			rspamd_snprintf (val, num_str_len, "%f", cur->value.dv);
			break;
		case UCL_BOOLEAN:
			val = rspamd_mempool_alloc (cfg->cfg_pool, num_str_len);
			rspamd_snprintf (val, num_str_len, "%b", (gboolean)cur->value.iv);
			break;
		default:
			g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"cannot convert an object or array to string");
			return FALSE;
		}
		*target = g_list_prepend (*target, val);
	}

	/* Add a destructor */
	rspamd_mempool_add_destructor (cfg->cfg_pool,
		(rspamd_mempool_destruct_t)g_list_free,
		*target);

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_boolean (struct rspamd_config *cfg,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	gboolean *target;

	target = (gboolean *)(((gchar *)pd->user_struct) + pd->offset);

	if (obj->type == UCL_BOOLEAN) {
		*target = obj->value.iv;
	}
	else if (obj->type == UCL_INT) {
		*target = obj->value.iv;
	}
	else {
		g_set_error (err,
			CFG_RCL_ERROR,
			EINVAL,
			"cannot convert an object to boolean");
		return FALSE;
	}

	return TRUE;
}

void
rspamd_rcl_register_worker_option (struct rspamd_config *cfg,
	gint type,
	const gchar *name,
	rspamd_rcl_handler_t handler,
	gpointer target,
	gsize offset,
	gint flags)
{
	struct rspamd_worker_param_parser *nhandler;
	struct rspamd_worker_cfg_parser *nparser;

	HASH_FIND_INT (cfg->wrk_parsers, &type, nparser);
	if (nparser == NULL) {
		/* Allocate new parser for this worker */
		nparser =
			rspamd_mempool_alloc0 (cfg->cfg_pool,
				sizeof (struct rspamd_worker_cfg_parser));
		nparser->type = type;
		HASH_ADD_INT (cfg->wrk_parsers, type, nparser);
	}

	HASH_FIND_STR (nparser->parsers, name, nhandler);
	if (nhandler != NULL) {
		msg_warn (
			"handler for parameter %s is already registered for worker type %s",
			name,
			g_quark_to_string (type));
		return;
	}
	nhandler =
		rspamd_mempool_alloc0 (cfg->cfg_pool,
			sizeof (struct rspamd_worker_param_parser));
	nhandler->name = name;
	nhandler->parser.flags = flags;
	nhandler->parser.offset = offset;
	nhandler->parser.user_struct = target;
	nhandler->handler = handler;
	HASH_ADD_KEYPTR (hh, nparser->parsers, name, strlen (name), nhandler);
}


void
rspamd_rcl_register_worker_parser (struct rspamd_config *cfg, gint type,
	gboolean (*func)(ucl_object_t *, gpointer), gpointer ud)
{
	struct rspamd_worker_cfg_parser *nparser;
	HASH_FIND_INT (cfg->wrk_parsers, &type, nparser);
	if (nparser == NULL) {
		/* Allocate new parser for this worker */
		nparser =
			rspamd_mempool_alloc0 (cfg->cfg_pool,
				sizeof (struct rspamd_worker_cfg_parser));
		nparser->type = type;
		HASH_ADD_INT (cfg->wrk_parsers, type, nparser);
	}

	nparser->def_obj_parser = func;
	nparser->def_ud = ud;
}

gboolean
rspamd_config_read (struct rspamd_config *cfg, const gchar *filename,
	const gchar *convert_to, rspamd_rcl_section_fin_t logger_fin,
	gpointer logger_ud)
{
	struct stat st;
	gint fd;
	gchar *data;
	GError *err = NULL;
	struct rspamd_rcl_section *top, *logger;
	gboolean res;
	struct ucl_parser *parser;

	if (stat (filename, &st) == -1) {
		msg_err ("cannot stat %s: %s", filename, strerror (errno));
		return FALSE;
	}
	if ((fd = open (filename, O_RDONLY)) == -1) {
		msg_err ("cannot open %s: %s", filename, strerror (errno));
		return FALSE;

	}
	/* Now mmap this file to simplify reading process */
	if ((data =
		mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		msg_err ("cannot mmap %s: %s", filename, strerror (errno));
		close (fd);
		return FALSE;
	}
	close (fd);

	parser = ucl_parser_new (0);
	rspamd_ucl_add_conf_variables (parser);
	rspamd_ucl_add_conf_macros (parser, cfg);
	if (!ucl_parser_add_chunk (parser, data, st.st_size)) {
		msg_err ("ucl parser error: %s", ucl_parser_get_error (parser));
		ucl_parser_free (parser);
		munmap (data, st.st_size);
		return FALSE;
	}
	munmap (data, st.st_size);
	cfg->rcl_obj = ucl_parser_get_object (parser);
	ucl_parser_free (parser);
	res = TRUE;

	if (!res) {
		return FALSE;
	}

	top = rspamd_rcl_config_init ();
	err = NULL;

	HASH_FIND_STR (top, "logging", logger);
	if (logger != NULL) {
		logger->fin = logger_fin;
		logger->fin_ud = logger_ud;
	}

	if (!rspamd_read_rcl_config (top, cfg, cfg->rcl_obj, &err)) {
		msg_err ("rcl parse error: %s", err->message);
		return FALSE;
	}

	return TRUE;
}
