/* Copyright (c) 2013-2015, Vsevolod Stakhov
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
#include "rspamd.h"
#include "uthash_strcase.h"
#include "utlist.h"
#include "cfg_file.h"
#include "lua/lua_common.h"
#include "expression.h"
#include "composites.h"
#include "libserver/worker_util.h"
#include "unix-std.h"
#include "cryptobox.h"

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_GLOB_H
#include <glob.h>
#endif

struct rspamd_rcl_default_handler_data {
	struct rspamd_rcl_struct_parser pd;
	const gchar *key;
	rspamd_rcl_default_handler_t handler;
	UT_hash_handle hh;
};

struct rspamd_rcl_section {
	const gchar *name;                  /**< name of section */
	const gchar *key_attr;
	const gchar *default_key;
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
	rspamd_rcl_default_handler_t handler;           /**< handler function									*/
	struct rspamd_rcl_struct_parser parser;         /**< parser attributes									*/
	const gchar *name;                              /**< parameter's name									*/
	UT_hash_handle hh;                              /**< hash by name										*/
};

struct rspamd_worker_cfg_parser {
	struct rspamd_worker_param_parser *parsers;     /**< parsers hash										*/
	gint type;                                      /**< workers quark										*/
	gboolean (*def_obj_parser)(ucl_object_t *obj, gpointer ud);   /**< default object parser								*/
	gpointer def_ud;
	UT_hash_handle hh;                              /**< hash by type										*/
};

static gboolean rspamd_rcl_process_section (struct rspamd_rcl_section *sec,
		gpointer ptr, const ucl_object_t *obj, rspamd_mempool_t *pool,
		GError **err);

/*
 * Common section handlers
 */
static gboolean
rspamd_rcl_logging_handler (rspamd_mempool_t *pool, const ucl_object_t *obj,
	const gchar *key, gpointer ud, struct rspamd_rcl_section *section,
	GError **err)
{
	const ucl_object_t *val;
	const gchar *facility, *log_type, *log_level;
	struct rspamd_config *cfg = ud;

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
#ifdef HAVE_SYSLOG_H
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
#endif
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
		msg_warn_config (
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

	return rspamd_rcl_section_parse_defaults (section, cfg->cfg_pool, obj,
			cfg, err);
}

static gboolean
rspamd_rcl_options_handler (rspamd_mempool_t *pool, const ucl_object_t *obj,
	const gchar *key, gpointer ud,
	struct rspamd_rcl_section *section, GError **err)
{
	const ucl_object_t *dns, *upstream;
	struct rspamd_config *cfg = ud;
	struct rspamd_rcl_section *dns_section, *upstream_section;

	HASH_FIND_STR (section->subsections, "dns", dns_section);

	dns = ucl_object_find_key (obj, "dns");
	if (dns_section != NULL && dns != NULL) {
		if (!rspamd_rcl_section_parse_defaults (dns_section, cfg->cfg_pool, dns,
				cfg, err)) {
			return FALSE;
		}
	}

	HASH_FIND_STR (section->subsections, "upstream", upstream_section);

	upstream = ucl_object_find_key (obj, "upstream");
	if (upstream_section != NULL && upstream != NULL) {
		if (!rspamd_rcl_section_parse_defaults (upstream_section, cfg->cfg_pool,
			upstream, cfg, err)) {
			return FALSE;
		}
	}

	return rspamd_rcl_section_parse_defaults (section, cfg->cfg_pool, obj,
			cfg, err);
}

struct rspamd_rcl_symbol_data {
	struct metric *metric;
	struct rspamd_symbols_group *gr;
	struct rspamd_config *cfg;
};

static gboolean
rspamd_rcl_group_handler (rspamd_mempool_t *pool, const ucl_object_t *obj,
		const gchar *key, gpointer ud,
		struct rspamd_rcl_section *section, GError **err)
{
	struct rspamd_rcl_symbol_data *sd = ud;
	struct metric *metric;
	struct rspamd_symbols_group *gr;
	const ucl_object_t *val, *cur;
	struct rspamd_rcl_section *subsection;

	g_assert (key != NULL);

	metric = sd->metric;

	gr = g_hash_table_lookup (metric->groups, key);

	if (gr == NULL) {
		gr = rspamd_config_new_group (sd->cfg, metric, key);
	}

	if (!rspamd_rcl_section_parse_defaults (section, pool, obj,
			metric, err)) {
		return FALSE;
	}

	sd->gr = gr;

	/* Handle symbols */
	val = ucl_object_find_key (obj, "symbol");
	if (val != NULL && ucl_object_type (val) == UCL_OBJECT) {
		HASH_FIND_STR (section->subsections, "symbol", subsection);
		g_assert (subsection != NULL);

		LL_FOREACH (val, cur) {
			if (!rspamd_rcl_process_section (subsection, sd, cur,
					pool, err)) {
				return FALSE;
			}
		}
	}

	return TRUE;
}

static gboolean
rspamd_rcl_symbol_handler (rspamd_mempool_t *pool, const ucl_object_t *obj,
		const gchar *key, gpointer ud,
		struct rspamd_rcl_section *section, GError **err)
{
	struct rspamd_rcl_symbol_data *sd = ud;
	struct rspamd_symbol_def *sym_def;
	struct metric *metric;
	struct rspamd_config *cfg;
	const ucl_object_t *elt;
	GList *metric_list;

	g_assert (key != NULL);
	metric = sd->metric;
	g_assert (metric != NULL);
	cfg = sd->cfg;

	sym_def = g_hash_table_lookup (metric->symbols, key);

	if (sym_def == NULL) {
		sym_def = rspamd_mempool_alloc0 (pool, sizeof (*sym_def));
		sym_def->name = rspamd_mempool_strdup (pool, key);
		sym_def->gr = sd->gr;
		sym_def->weight_ptr = rspamd_mempool_alloc (pool, sizeof (gdouble));

		g_hash_table_insert (metric->symbols, sym_def->name, sym_def);

		if (sd->gr) {
			g_hash_table_insert (sd->gr->symbols, sym_def->name, sym_def);
		}
		if ((metric_list =
				g_hash_table_lookup (cfg->metrics_symbols, sym_def->name)) == NULL) {
			metric_list = g_list_prepend (NULL, metric);
			rspamd_mempool_add_destructor (cfg->cfg_pool,
					(rspamd_mempool_destruct_t)g_list_free,
					metric_list);
			g_hash_table_insert (cfg->metrics_symbols, sym_def->name, metric_list);
		}
		else {
			if (!g_list_find (metric_list, metric)) {
				metric_list = g_list_append (metric_list, metric);
			}
		}
	}
	else {
		msg_warn_config ("redefining symbol '%s' in metric '%s'", key, metric->name);
	}

	if ((elt = ucl_object_find_key (obj, "one_shot")) != NULL) {
		if (ucl_object_toboolean (elt)) {
			sym_def->flags |= RSPAMD_SYMBOL_FLAG_ONESHOT;
		}
	}

	if ((elt = ucl_object_find_key (obj, "ignore")) != NULL) {
		if (ucl_object_toboolean (elt)) {
			sym_def->flags |= RSPAMD_SYMBOL_FLAG_IGNORE;
		}
	}

	if (!rspamd_rcl_section_parse_defaults (section, pool, obj,
			sym_def, err)) {
		return FALSE;
	}

	if (ucl_object_find_any_key (obj, "score", "weight", NULL) != NULL) {
		*sym_def->weight_ptr = sym_def->score;
	}

	return TRUE;
}

static gboolean
rspamd_rcl_actions_handler (rspamd_mempool_t *pool, const ucl_object_t *obj,
		const gchar *key, gpointer ud,
		struct rspamd_rcl_section *section, GError **err)
{
	gdouble action_score;
	struct metric_action *action;
	struct metric *metric = ud;
	gint action_value;
	const ucl_object_t *cur;
	ucl_object_iter_t it = NULL;

	while ((cur = ucl_iterate_object (obj, &it, true)) != NULL) {
		if (!rspamd_action_from_str (ucl_object_key (cur), &action_value) ||
				!ucl_object_todouble_safe (cur, &action_score)) {
			g_set_error (err,
					CFG_RCL_ERROR,
					EINVAL,
					"invalid action definition: '%s'",
					ucl_object_key (cur));
			return FALSE;
		}
		else {
			action = &metric->actions[action_value];
			action->action = action_value;
			action->score = action_score;
		}
	}

	return TRUE;
}

static gboolean
rspamd_rcl_metric_handler (rspamd_mempool_t *pool, const ucl_object_t *obj,
		const gchar *key, gpointer ud,
		struct rspamd_rcl_section *section, GError **err)
{
	const ucl_object_t *val, *cur, *elt;
	ucl_object_iter_t it;
	struct rspamd_config *cfg = ud;
	struct metric *metric;
	struct rspamd_rcl_section *subsection;
	struct rspamd_rcl_symbol_data sd;
	struct rspamd_symbol_def *sym_def;

	g_assert (key != NULL);

	metric = g_hash_table_lookup (cfg->metrics, key);
	if (metric == NULL) {
		metric = rspamd_config_new_metric (cfg, metric, key);
	}

	if (!rspamd_rcl_section_parse_defaults (section, cfg->cfg_pool, obj,
			metric, err)) {
		return FALSE;
	}

	if (metric->unknown_weight > 0) {
		metric->accept_unknown_symbols = TRUE;
	}

	/* Handle actions */
	val = ucl_object_find_key (obj, "actions");
	if (val != NULL) {
		if (val->type != UCL_OBJECT) {
			g_set_error (err, CFG_RCL_ERROR, EINVAL,
				"actions must be an object");
			return FALSE;
		}

		HASH_FIND_STR (section->subsections, "actions", subsection);
		g_assert (subsection != NULL);
		if (!rspamd_rcl_process_section (subsection, metric, val,
				cfg->cfg_pool, err)) {
			return FALSE;
		}
	}

	/* No more legacy mode */

	/* Handle grouped symbols */
	val = ucl_object_find_key (obj, "group");
	if (val != NULL && ucl_object_type (val) == UCL_OBJECT) {
		HASH_FIND_STR (section->subsections, "group", subsection);
		g_assert (subsection != NULL);
		sd.gr = NULL;
		sd.cfg = cfg;
		sd.metric = metric;

		LL_FOREACH (val, cur) {
			if (!rspamd_rcl_process_section (subsection, &sd, cur,
					cfg->cfg_pool, err)) {
				return FALSE;
			}
		}
	}

	/* Handle symbols */
	val = ucl_object_find_key (obj, "symbol");
	if (val != NULL && ucl_object_type (val) == UCL_OBJECT) {
		HASH_FIND_STR (section->subsections, "symbol", subsection);
		g_assert (subsection != NULL);
		sd.gr = NULL;
		sd.cfg = cfg;
		sd.metric = metric;

		LL_FOREACH (val, cur) {
			if (!rspamd_rcl_process_section (subsection, &sd, cur,
					cfg->cfg_pool, err)) {
				return FALSE;
			}
		}
	}

	/* Handle ignored symbols */
	val = ucl_object_find_key (obj, "ignore");
	if (val != NULL && ucl_object_type (val) == UCL_ARRAY) {
		LL_FOREACH (val, cur) {
			it = NULL;

			while ((elt = ucl_iterate_object (cur, &it, true)) != NULL) {
				if (ucl_object_type (elt) == UCL_STRING) {
					sym_def = g_hash_table_lookup (metric->symbols,
							ucl_object_tostring (elt));

					if (sym_def != NULL) {
						sym_def->flags |= RSPAMD_SYMBOL_FLAG_IGNORE;
					}
					else {
						msg_warn ("cannot find symbol %s to set ignore flag",
								ucl_object_tostring (elt));
					}
				}
			}
		}
	}

	return TRUE;
}

static gboolean
rspamd_rcl_worker_handler (rspamd_mempool_t *pool, const ucl_object_t *obj,
		const gchar *key, gpointer ud,
		struct rspamd_rcl_section *section, GError **err)
{
	const ucl_object_t *val, *cur;
	ucl_object_t *robj;
	ucl_object_iter_t it = NULL;
	const gchar *worker_type, *worker_bind;
	struct rspamd_config *cfg = ud;
	GQuark qtype;
	struct rspamd_worker_conf *wrk;
	struct rspamd_worker_cfg_parser *wparser;
	struct rspamd_worker_param_parser *whandler;

	g_assert (key != NULL);
	worker_type = key;

	qtype = g_quark_try_string (worker_type);
	if (qtype != 0) {
		wrk = rspamd_config_new_worker (cfg, NULL);
		wrk->worker = rspamd_get_worker_by_type (cfg, qtype);
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

	val = ucl_object_find_key (obj, "bind_socket");
	/* This name is more logical */
	if (val == NULL) {
		val = ucl_object_find_key (obj, "listen");
	}
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

	if (!rspamd_rcl_section_parse_defaults (section, cfg->cfg_pool, obj,
			wrk, err)) {
		return FALSE;
	}

	/* Parse other attributes */
	HASH_FIND_INT (cfg->wrk_parsers, (gint *)&qtype, wparser);
	if (wparser != NULL && obj->type == UCL_OBJECT) {
		it = NULL;
		while ((cur = ucl_iterate_object (obj, &it, true)) != NULL) {
			HASH_FIND_STR (wparser->parsers, ucl_object_key (cur), whandler);
			if (whandler != NULL) {
				if (!whandler->handler (cfg->cfg_pool, cur, &whandler->parser,
						section, err)) {
					return FALSE;
				}
			}
		}
		if (wparser->def_obj_parser != NULL) {
			robj = ucl_object_ref (obj);

			if (!wparser->def_obj_parser (robj, wparser->def_ud)) {
				ucl_object_unref (robj);

				return FALSE;
			}

			ucl_object_unref (robj);
		}
	}

	cfg->workers = g_list_prepend (cfg->workers, wrk);

	return TRUE;
}

#define RSPAMD_CONFDIR_INDEX "CONFDIR"
#define RSPAMD_RUNDIR_INDEX "RUNDIR"
#define RSPAMD_DBDIR_INDEX "DBDIR"
#define RSPAMD_LOGDIR_INDEX "LOGDIR"
#define RSPAMD_PLUGINSDIR_INDEX "PLUGINSDIR"
#define RSPAMD_RULESDIR_INDEX "RULESDIR"
#define RSPAMD_WWWDIR_INDEX "WWWDIR"
#define RSPAMD_PREFIX_INDEX "PREFIX"
#define RSPAMD_VERSION_INDEX "VERSION"

static void
rspamd_rcl_set_lua_globals (struct rspamd_config *cfg, lua_State *L,
		GHashTable *vars)
{
	struct rspamd_config **pcfg;
	GHashTableIter it;
	gpointer k, v;

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

	rspamd_lua_set_path (L, cfg);

	/* Set known paths as rspamd_paths global */
	lua_getglobal (L, "rspamd_paths");
	if (lua_isnil (L, -1)) {
		lua_newtable (L);
		rspamd_lua_table_set (L, RSPAMD_CONFDIR_INDEX, RSPAMD_CONFDIR);
		rspamd_lua_table_set (L, RSPAMD_RUNDIR_INDEX, RSPAMD_RUNDIR);
		rspamd_lua_table_set (L, RSPAMD_DBDIR_INDEX, RSPAMD_DBDIR);
		rspamd_lua_table_set (L, RSPAMD_LOGDIR_INDEX, RSPAMD_LOGDIR);
		rspamd_lua_table_set (L, RSPAMD_WWWDIR_INDEX, RSPAMD_WWWDIR);
		rspamd_lua_table_set (L, RSPAMD_PLUGINSDIR_INDEX, RSPAMD_PLUGINSDIR);
		rspamd_lua_table_set (L, RSPAMD_RULESDIR_INDEX, RSPAMD_RULESDIR);
		rspamd_lua_table_set (L, RSPAMD_PREFIX_INDEX, RSPAMD_PREFIX);

		/* Override from vars if needed */
		if (vars != NULL) {
			g_hash_table_iter_init (&it, vars);

			while (g_hash_table_iter_next (&it, &k, &v)) {
				rspamd_lua_table_set (L, k, v);
			}
		}

		lua_setglobal (L, "rspamd_paths");
	}
}

static gboolean
rspamd_rcl_lua_handler (rspamd_mempool_t *pool, const ucl_object_t *obj,
		const gchar *key, gpointer ud,
		struct rspamd_rcl_section *section, GError **err)
{
	struct rspamd_config *cfg = ud;
	const gchar *lua_src = rspamd_mempool_strdup (pool,
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
					msg_err_config ("cannot chdir to %s: %s", cur_dir,
						strerror (errno));
				}
				g_free (cur_dir);
				g_free (tmp1);
				g_free (tmp2);
				return FALSE;
			}
			/* Now do it */
			if (lua_pcall (L, 0, LUA_MULTRET, 0) != 0) {
				g_set_error (err,
					CFG_RCL_ERROR,
					EINVAL,
					"cannot init lua file %s: %s",
					lua_src,
					lua_tostring (L, -1));
				if (chdir (cur_dir) == -1) {
					msg_err_config ("cannot chdir to %s: %s", cur_dir,
						strerror (errno));
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
				msg_err_config ("cannot chdir to %s: %s", cur_dir, strerror (errno));
			}
			g_free (cur_dir);
			g_free (tmp1);
			g_free (tmp2);
			return FALSE;

		}
		if (chdir (cur_dir) == -1) {
			msg_err_config ("cannot chdir to %s: %s", cur_dir, strerror (errno));
		}
		g_free (cur_dir);
		g_free (tmp1);
		g_free (tmp2);
	}
	else {
		g_free (tmp1);
		g_free (tmp2);
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
	gchar *pattern, *ext_pos;
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
		rspamd_snprintf (pattern, len, "%s%s", path, "*.lua");

		if (glob (pattern, GLOB_DOOFFS, NULL, &globbuf) == 0) {
			for (i = 0; i < globbuf.gl_pathc; i++) {
				cur_mod =
					rspamd_mempool_alloc (cfg->cfg_pool,
						sizeof (struct script_module));
				cur_mod->path = rspamd_mempool_strdup (cfg->cfg_pool,
						globbuf.gl_pathv[i]);
				cur_mod->name = g_path_get_basename (cur_mod->path);
				rspamd_mempool_add_destructor (cfg->cfg_pool, g_free,
						cur_mod->name);
				ext_pos = strstr (cur_mod->name, ".lua");

				if (ext_pos != NULL) {
					*ext_pos = '\0';
				}

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
		cur_mod->name = g_path_get_basename (cur_mod->path);
		rspamd_mempool_add_destructor (cfg->cfg_pool, g_free,
				cur_mod->name);
		ext_pos = strstr (cur_mod->name, ".lua");

		if (ext_pos != NULL) {
			*ext_pos = '\0';
		}

		cfg->script_modules = g_list_prepend (cfg->script_modules, cur_mod);
	}

	return TRUE;
}

static gboolean
rspamd_rcl_modules_handler (rspamd_mempool_t *pool, const ucl_object_t *obj,
		const gchar *key, gpointer ud,
		struct rspamd_rcl_section *section, GError **err)
{
	const ucl_object_t *val, *cur;
	struct rspamd_config *cfg = ud;
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

struct statfile_parser_data {
	struct rspamd_config *cfg;
	struct rspamd_classifier_config *ccf;
};

static gboolean
rspamd_rcl_statfile_handler (rspamd_mempool_t *pool, const ucl_object_t *obj,
		const gchar *key, gpointer ud,
		struct rspamd_rcl_section *section, GError **err)
{
	struct statfile_parser_data *stud = ud;
	struct rspamd_classifier_config *ccf;
	struct rspamd_config *cfg;
	const ucl_object_t *val;
	struct rspamd_statfile_config *st;
	GList *labels;

	g_assert (key != NULL);

	cfg = stud->cfg;
	ccf = stud->ccf;

	st = rspamd_config_new_statfile (cfg, NULL);
	st->symbol = rspamd_mempool_strdup (cfg->cfg_pool, key);

	if (rspamd_rcl_section_parse_defaults (section, pool, obj, st, err)) {
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

		st->opts = (ucl_object_t *)obj;
		st->clcf = ccf;

		val = ucl_object_find_key (obj, "spam");
		if (val == NULL) {
			msg_info_config (
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
			msg_info_config ("guessed that statfile with symbol %s is %s",
				st->symbol,
				st->is_spam ?
				"spam" : "ham");
		}
		return TRUE;
	}

	return FALSE;
}

static gboolean
rspamd_rcl_classifier_handler (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	const gchar *key,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	const ucl_object_t *val, *cur;
	ucl_object_iter_t it = NULL;
	struct rspamd_config *cfg = ud;
	struct statfile_parser_data stud;
	const gchar *st_key;
	struct rspamd_classifier_config *ccf;
	gboolean res = TRUE;
	struct rspamd_rcl_section *stat_section;
	struct rspamd_tokenizer_config *tkcf = NULL;

	g_assert (key != NULL);
	ccf = rspamd_config_new_classifier (cfg, NULL);

	ccf->classifier = rspamd_mempool_strdup (cfg->cfg_pool, key);

	if (rspamd_rcl_section_parse_defaults (section, cfg->cfg_pool, obj,
			ccf, err)) {

		HASH_FIND_STR (section->subsections, "statfile", stat_section);

		if (ccf->classifier == NULL) {
			ccf->classifier = "bayes";
		}

		if (ccf->name == NULL) {
			ccf->name = ccf->classifier;
		}

		while ((val = ucl_iterate_object (obj, &it, true)) != NULL && res) {
			st_key = ucl_object_key (val);
			if (st_key != NULL) {
				if (g_ascii_strcasecmp (st_key, "statfile") == 0) {
					LL_FOREACH (val, cur) {
						stud.cfg = cfg;
						stud.ccf = ccf;
						res = rspamd_rcl_process_section (stat_section, &stud,
								cur, cfg->cfg_pool, err);

						if (!res) {
							return FALSE;
						}
					}
				}
				else if (g_ascii_strcasecmp (st_key, "tokenizer") == 0) {
					tkcf = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*tkcf));

					if (ucl_object_type (val) == UCL_STRING) {
						tkcf->name = ucl_object_tostring (val);
					}
					else if (ucl_object_type (val) == UCL_OBJECT) {
						cur = ucl_object_find_key (val, "name");
						if (cur != NULL) {
							tkcf->name = ucl_object_tostring (cur);
							tkcf->opts = val;
						}
						else {
							cur = ucl_object_find_key (val, "type");
							if (cur != NULL) {
								tkcf->name = ucl_object_tostring (cur);
								tkcf->opts = val;
							}
						}
					}
				}
			}
		}
	}
	else {
		msg_err_config ("fatal configuration error, cannot parse statfile definition");
	}

	if (tkcf == NULL) {
		tkcf = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*tkcf));
		tkcf->name = NULL;

	}

	ccf->tokenizer = tkcf;
	ccf->opts = (ucl_object_t *)obj;
	cfg->classifiers = g_list_prepend (cfg->classifiers, ccf);


	return res;
}

static gboolean
rspamd_rcl_composite_handler (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	const gchar *key,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	const ucl_object_t *val;
	struct rspamd_expression *expr;
	struct rspamd_config *cfg = ud;
	struct rspamd_composite *composite;
	const gchar *composite_name, *composite_expression, *group, *metric,
		*description;
	gdouble score;
	gboolean new = TRUE;

	g_assert (key != NULL);

	composite_name = key;

	if (g_hash_table_lookup (cfg->composite_symbols, composite_name) != NULL) {
		msg_warn_config ("composite %s is redefined", composite_name);
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

	if (!rspamd_parse_expression (composite_expression, 0, &composite_expr_subr,
				NULL, cfg->cfg_pool, err, &expr)) {
		if (err && *err) {
			msg_err_config ("cannot parse composite expression for %s: %e",
				composite_name, *err);
		}
		else {
			msg_err_config ("cannot parse composite expression for %s: unknown error",
				composite_name);
		}

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
		rspamd_symbols_cache_add_symbol (cfg->cache, composite_name, 0,
			NULL, NULL, SYMBOL_TYPE_COMPOSITE, -1);
	}

	val = ucl_object_find_key (obj, "score");
	if (val != NULL && ucl_object_todouble_safe (val, &score)) {
		/* Also set score in the metric */

		val = ucl_object_find_key (obj, "group");
		if (val != NULL) {
			group = ucl_object_tostring (val);
		}
		else {
			group = "composite";
		}

		val = ucl_object_find_key (obj, "metric");
		if (val != NULL) {
			metric = ucl_object_tostring (val);
		}
		else {
			metric = DEFAULT_METRIC;
		}

		val = ucl_object_find_key (obj, "description");
		if (val != NULL) {
			description = ucl_object_tostring (val);
		}
		else {
			description = composite_expression;
		}

		rspamd_config_add_metric_symbol (cfg, metric, composite_name, score,
				description, group, FALSE, FALSE);
	}

	return TRUE;
}

struct rspamd_rcl_section *
rspamd_rcl_add_section (struct rspamd_rcl_section **top,
	const gchar *name, const gchar *key_attr, rspamd_rcl_handler_t handler,
	enum ucl_type type, gboolean required, gboolean strict_type)
{
	struct rspamd_rcl_section *new;

	new = g_slice_alloc0 (sizeof (struct rspamd_rcl_section));
	new->name = name;
	new->key_attr = key_attr;
	new->handler = handler;
	new->type = type;
	new->strict_type = strict_type;

	HASH_ADD_KEYPTR (hh, *top, new->name, strlen (new->name), new);
	return new;
}

struct rspamd_rcl_default_handler_data *
rspamd_rcl_add_default_handler (struct rspamd_rcl_section *section,
		const gchar *name,
		rspamd_rcl_default_handler_t handler,
		goffset offset,
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
	struct rspamd_rcl_section *new = NULL, *sub, *ssub, *sssub;

	/*
	 * Important notice:
	 * the order of parsing is equal to order of this initialization, therefore
	 * it is possible to init some portions of config prior to others
	 */

	/**
	 * Logging section
	 */
	sub = rspamd_rcl_add_section (&new,
			"logging", NULL,
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
			"log_re_cache",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, log_re_cache),
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
	rspamd_rcl_add_default_handler (sub,
			"color",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, log_color),
			0);
	rspamd_rcl_add_default_handler (sub,
			"log_systemd",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, log_systemd),
			0);
	rspamd_rcl_add_default_handler (sub,
			"systemd",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, log_systemd),
			0);
	rspamd_rcl_add_default_handler (sub,
			"debug_modules",
			rspamd_rcl_parse_struct_string_list,
			G_STRUCT_OFFSET (struct rspamd_config, debug_modules),
			RSPAMD_CL_FLAG_STRING_LIST_HASH);
	rspamd_rcl_add_default_handler (sub,
			"log_format",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, log_format_str),
			0);
	/**
	 * Options section
	 */
	sub = rspamd_rcl_add_section (&new,
			"options", NULL,
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
	rspamd_rcl_add_default_handler (sub,
			"dns_max_requests",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, dns_max_requests),
			RSPAMD_CL_FLAG_INT_32);
	rspamd_rcl_add_default_handler (sub,
			"classify_headers",
			rspamd_rcl_parse_struct_string_list,
			G_STRUCT_OFFSET (struct rspamd_config, classify_headers),
			0);
	rspamd_rcl_add_default_handler (sub,
			"control_socket",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, control_socket_path),
			0);
	rspamd_rcl_add_default_handler (sub,
			"explicit_modules",
			rspamd_rcl_parse_struct_string_list,
			G_STRUCT_OFFSET (struct rspamd_config, explicit_modules),
			RSPAMD_CL_FLAG_STRING_LIST_HASH);
	rspamd_rcl_add_default_handler (sub,
			"allow_raw_input",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, allow_raw_input),
			0);
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
			rspamd_rcl_parse_struct_string_list,
			G_STRUCT_OFFSET (struct rspamd_config, filters),
			0);
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
	rspamd_rcl_add_default_handler (sub,
			"all_filters",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, check_all_filters),
			0);
	rspamd_rcl_add_default_handler (sub,
			"min_word_len",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, min_word_len),
			RSPAMD_CL_FLAG_UINT);
	rspamd_rcl_add_default_handler (sub,
			"max_word_len",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, max_word_len),
			RSPAMD_CL_FLAG_UINT);
	rspamd_rcl_add_default_handler (sub,
			"words_decay",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, words_decay),
			RSPAMD_CL_FLAG_UINT);
	rspamd_rcl_add_default_handler (sub,
			"url_tld",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, tld_file),
			RSPAMD_CL_FLAG_STRING_PATH);
	rspamd_rcl_add_default_handler (sub,
			"tld",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, tld_file),
			RSPAMD_CL_FLAG_STRING_PATH);
	rspamd_rcl_add_default_handler (sub,
			"history_rows",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, history_rows),
			RSPAMD_CL_FLAG_UINT);
	rspamd_rcl_add_default_handler (sub,
			"disable_hyperscan",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, disable_hyperscan),
			0);
	rspamd_rcl_add_default_handler (sub,
			"cores_dir",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, cores_dir),
			RSPAMD_CL_FLAG_STRING_PATH);
	rspamd_rcl_add_default_handler (sub,
			"max_cores_size",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, max_cores_size),
			RSPAMD_CL_FLAG_INT_SIZE);
	rspamd_rcl_add_default_handler (sub,
			"max_cores_count",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, max_cores_count),
			RSPAMD_CL_FLAG_INT_SIZE);

	/* New DNS configuration */
	ssub = rspamd_rcl_add_section (&sub->subsections, "dns", NULL, NULL,
			UCL_OBJECT, FALSE, TRUE);
	rspamd_rcl_add_default_handler (ssub,
			"nameserver",
			rspamd_rcl_parse_struct_string_list,
			G_STRUCT_OFFSET (struct rspamd_config, nameservers),
			0);
	rspamd_rcl_add_default_handler (ssub,
			"server",
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
	rspamd_rcl_add_default_handler (ssub,
			"connections",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, dns_io_per_server),
			RSPAMD_CL_FLAG_INT_32);


	/* New upstreams configuration */
	ssub = rspamd_rcl_add_section (&sub->subsections, "upstream", NULL, NULL,
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

	/**
	 * Metric section
	 */
	sub = rspamd_rcl_add_section (&new,
			"metric", "name",
			rspamd_rcl_metric_handler,
			UCL_OBJECT,
			FALSE,
			TRUE);
	sub->default_key = DEFAULT_METRIC;
	rspamd_rcl_add_default_handler (sub,
			"unknown_weight",
			rspamd_rcl_parse_struct_double,
			G_STRUCT_OFFSET (struct metric, unknown_weight),
			0);
	rspamd_rcl_add_default_handler (sub,
			"grow_factor",
			rspamd_rcl_parse_struct_double,
			G_STRUCT_OFFSET (struct metric, grow_factor),
			0);
	rspamd_rcl_add_default_handler (sub,
			"subject",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct metric, subject),
			0);

	/* Ungrouped symbols */
	ssub = rspamd_rcl_add_section (&sub->subsections,
			"symbol", "name",
			rspamd_rcl_symbol_handler,
			UCL_OBJECT,
			TRUE,
			TRUE);
	rspamd_rcl_add_default_handler (ssub,
			"description",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_symbol_def, description),
			0);
	rspamd_rcl_add_default_handler (ssub,
			"score",
			rspamd_rcl_parse_struct_double,
			G_STRUCT_OFFSET (struct rspamd_symbol_def, score),
			0);
	rspamd_rcl_add_default_handler (ssub,
			"weight",
			rspamd_rcl_parse_struct_double,
			G_STRUCT_OFFSET (struct rspamd_symbol_def, score),
			0);

	/* Actions part */
	ssub = rspamd_rcl_add_section (&sub->subsections,
			"actions", NULL,
			rspamd_rcl_actions_handler,
			UCL_OBJECT,
			TRUE,
			TRUE);

	/* Group part */
	ssub = rspamd_rcl_add_section (&sub->subsections,
			"group", "name",
			rspamd_rcl_group_handler,
			UCL_OBJECT,
			TRUE,
			TRUE);
	rspamd_rcl_add_default_handler (ssub,
			"disabled",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_symbols_group, disabled),
			0);
	rspamd_rcl_add_default_handler (ssub,
			"enabled",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_symbols_group, disabled),
			RSPAMD_CL_FLAG_BOOLEAN_INVERSE);
	rspamd_rcl_add_default_handler (ssub,
			"max_score",
			rspamd_rcl_parse_struct_double,
			G_STRUCT_OFFSET (struct rspamd_symbols_group, max_score),
			0);

	/* Grouped symbols */
	sssub = rspamd_rcl_add_section (&ssub->subsections,
			"symbol", "name",
			rspamd_rcl_symbol_handler,
			UCL_OBJECT,
			TRUE,
			TRUE);
	rspamd_rcl_add_default_handler (sssub,
			"description",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_symbol_def, description),
			0);
	rspamd_rcl_add_default_handler (sssub,
			"score",
			rspamd_rcl_parse_struct_double,
			G_STRUCT_OFFSET (struct rspamd_symbol_def, score),
			0);
	rspamd_rcl_add_default_handler (sssub,
			"weight",
			rspamd_rcl_parse_struct_double,
			G_STRUCT_OFFSET (struct rspamd_symbol_def, score),
			0);

	/**
	 * Worker section
	 */
	sub = rspamd_rcl_add_section (&new,
			"worker", "type",
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
			"modules", NULL,
			rspamd_rcl_modules_handler,
			UCL_OBJECT,
			FALSE,
			FALSE);

	/**
	 * Classifiers handler
	 */
	sub = rspamd_rcl_add_section (&new,
			"classifier", "type",
			rspamd_rcl_classifier_handler,
			UCL_OBJECT,
			FALSE,
			TRUE);
	/* Default classifier is 'bayes' for now */
	sub->default_key = "bayes";

	rspamd_rcl_add_default_handler (sub,
			"min_tokens",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_classifier_config, min_tokens),
			RSPAMD_CL_FLAG_INT_32);
	rspamd_rcl_add_default_handler (sub,
			"max_tokens",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_classifier_config, max_tokens),
			RSPAMD_CL_FLAG_INT_32);
	rspamd_rcl_add_default_handler (sub,
			"backend",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_classifier_config, backend),
			0);
	rspamd_rcl_add_default_handler (sub,
			"name",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_classifier_config, name),
			0);

	/*
	 * Statfile defaults
	 */
	ssub = rspamd_rcl_add_section (&sub->subsections,
			"statfile", "symbol",
			rspamd_rcl_statfile_handler,
			UCL_OBJECT,
			TRUE,
			TRUE);
	rspamd_rcl_add_default_handler (ssub,
			"label",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_statfile_config, label),
			0);
	rspamd_rcl_add_default_handler (ssub,
			"spam",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_statfile_config, is_spam),
			0);

	/**
	 * Composites handler
	 */
	sub = rspamd_rcl_add_section (&new,
			"composite", "name",
			rspamd_rcl_composite_handler,
			UCL_OBJECT,
			FALSE,
			TRUE);

	/**
	 * Lua handler
	 */
	sub = rspamd_rcl_add_section (&new,
			"lua", NULL,
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
	struct rspamd_rcl_section *cur, *found = NULL;
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

static gboolean
rspamd_rcl_process_section (struct rspamd_rcl_section *sec,
		gpointer ptr, const ucl_object_t *obj, rspamd_mempool_t *pool,
		GError **err)
{
	ucl_object_iter_t it;
	const ucl_object_t *cur;
	gboolean is_nested = TRUE;
	const gchar *key = NULL;

	g_assert (obj != NULL);
	g_assert (sec->handler != NULL);

	it = NULL;

	if (sec->key_attr != NULL) {
		while ((cur = ucl_iterate_object (obj, &it, true)) != NULL) {
			if (ucl_object_type (cur) != UCL_OBJECT) {
				is_nested = FALSE;
				break;
			}
		}
	}
	else {
		is_nested = FALSE;
	}

	if (is_nested) {
		/* Just reiterate on all subobjects */
		it = NULL;

		while ((cur = ucl_iterate_object (obj, &it, true)) != NULL) {
			if (!sec->handler (pool, cur, ucl_object_key (cur), ptr, sec, err)) {
				return FALSE;
			}
		}

		return TRUE;
	}
	else {
		if (sec->key_attr != NULL) {
			/* First of all search for required attribute and use it as a key */
			cur = ucl_object_find_key (obj, sec->key_attr);

			if (cur == NULL) {
				if (sec->default_key == NULL) {
					g_set_error (err, CFG_RCL_ERROR, EINVAL, "required attribute "
							"'%s' is missing for section '%s'", sec->key_attr,
							sec->name);
					return FALSE;
				}
				else {
					msg_info ("using default key '%s' for mandatory field '%s' "
							"for section '%s'", sec->default_key, sec->key_attr,
							sec->name);
					key = sec->default_key;
				}
			}
			else if (ucl_object_type (cur) != UCL_STRING) {
				g_set_error (err, CFG_RCL_ERROR, EINVAL, "required attribute %s"
						" is not a string for section %s",
						sec->key_attr, sec->name);
				return FALSE;
			}
			else {
				key = ucl_object_tostring (cur);
			}
		}
	}

	return sec->handler (pool, obj, key, ptr, sec, err);
}

gboolean
rspamd_rcl_parse (struct rspamd_rcl_section *top,
		gpointer ptr, rspamd_mempool_t *pool,
		const ucl_object_t *obj, GError **err)
{
	const ucl_object_t *found, *cur_obj;
	struct rspamd_rcl_section *cur, *tmp, *found_sec;

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
		if (strcmp (cur->name, "*") == 0) {
			/* Default section handler */
			LL_FOREACH (obj, cur_obj) {
				HASH_FIND_STR (top, ucl_object_key (cur_obj), found_sec);

				if (found_sec == NULL) {
					if (cur->handler != NULL) {
						if (!rspamd_rcl_process_section (cur, ptr, cur_obj,
								pool, err)) {
							return FALSE;
						}
					}
					else {
						rspamd_rcl_section_parse_defaults (cur,
								pool,
								cur_obj,
								ptr,
								err);
					}
				}
			}
		}
		else {
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

				LL_FOREACH (found, cur_obj) {
					if (cur->handler != NULL) {
						if (!rspamd_rcl_process_section (cur, ptr, cur_obj,
								pool, err)) {
							return FALSE;
						}
					}
					else {
						rspamd_rcl_section_parse_defaults (cur,
								pool,
								cur_obj,
								ptr,
								err);
					}
				}
			}
		}
		if (cur->fin) {
			cur->fin (pool, cur->fin_ud);
		}
	}

	return TRUE;
}

gboolean
rspamd_rcl_section_parse_defaults (struct rspamd_rcl_section *section,
	rspamd_mempool_t *pool, const ucl_object_t *obj, gpointer ptr,
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
			if (!cur->handler (pool, found, &cur->pd, section, err)) {
				return FALSE;
			}
		}
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_string (rspamd_mempool_t *pool,
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
			rspamd_mempool_strdup (pool, ucl_copy_value_trash (obj));
		break;
	case UCL_INT:
		*target = rspamd_mempool_alloc (pool, num_str_len);
		rspamd_snprintf (*target, num_str_len, "%L", obj->value.iv);
		break;
	case UCL_FLOAT:
		*target = rspamd_mempool_alloc (pool, num_str_len);
		rspamd_snprintf (*target, num_str_len, "%f", obj->value.dv);
		break;
	case UCL_BOOLEAN:
		*target = rspamd_mempool_alloc (pool, num_str_len);
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
rspamd_rcl_parse_struct_integer (rspamd_mempool_t *pool,
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
	int64_t val;

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
rspamd_rcl_parse_struct_double (rspamd_mempool_t *pool,
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
			"cannot convert param %s to double", ucl_object_key (obj));
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_time (rspamd_mempool_t *pool,
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
				"cannot convert param %s to double", ucl_object_key (obj));
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
			"invalid flags to parse time value in %s", ucl_object_key (obj));
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_keypair (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	gpointer *target;
	gpointer key;
	const gchar *val, *sem = NULL, *pk = NULL, *sk = NULL;
	gchar keybuf[256];
	const ucl_object_t *elt;

	target = (gpointer *)(((gchar *)pd->user_struct) + pd->offset);
	if (obj->type == UCL_STRING) {
		/* Pk and Sk are just linked all together */
		val = ucl_object_tostring (obj);
		if ((sem = strchr (val, ':')) != NULL) {
			sk = val;
			pk = sem + 1;
		}
		else {
			/* Try to parse the key as is */
			key = rspamd_http_connection_make_key ((gchar *)val, strlen (val));
			if (key != NULL) {
				*target = key;
				return TRUE;
			}
			g_set_error (err,
					CFG_RCL_ERROR,
					EINVAL,
					"invalid string with keypair content for %s",
					ucl_object_key (obj));
			return FALSE;
		}
	}
	else if (obj->type == UCL_OBJECT) {
		elt = ucl_object_find_key (obj, "pubkey");
		if (elt == NULL || !ucl_object_tostring_safe (elt, &pk)) {
			g_set_error (err,
					CFG_RCL_ERROR,
					EINVAL,
					"no sane pubkey found in the keypair: %s",
					ucl_object_key (obj));
			return FALSE;
		}
		elt = ucl_object_find_key (obj, "privkey");
		if (elt == NULL || !ucl_object_tostring_safe (elt, &sk)) {
			g_set_error (err,
					CFG_RCL_ERROR,
					EINVAL,
					"no sane privkey found in the keypair: %s",
					ucl_object_key (obj));
			return FALSE;
		}
	}

	if (sk == NULL || pk == NULL) {
		g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"no sane pubkey or privkey found in the keypair: %s",
				ucl_object_key (obj));
		return FALSE;
	}

	if (!sem) {
		rspamd_snprintf (keybuf, sizeof (keybuf), "%s%s", sk, pk);
	}
	else {
		rspamd_snprintf (keybuf, sizeof (keybuf), "%*s%s", (gint)(sem - sk),
				sk, pk);
	}

	key = rspamd_http_connection_make_key (keybuf, strlen (keybuf));
	if (key != NULL) {
		/* XXX: clean buffer after usage */
		*target = key;
		return TRUE;
	}

	g_set_error (err,
			CFG_RCL_ERROR,
			EINVAL,
			"cannot load the keypair specified: %s",
			ucl_object_key (obj));
	return FALSE;
}

static void
rspamd_rcl_insert_string_list_item (gpointer *target, rspamd_mempool_t *pool,
		const gchar *src, gboolean is_hash)
{
	union {
		GHashTable *hv;
		GList *lv;
		gpointer p;
	} d;
	gchar *val;

	d.p = *target;

	if (is_hash) {
		if (d.hv == NULL) {
			d.hv = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
		}

		val = rspamd_mempool_strdup (pool, src);
		g_hash_table_insert (d.hv, val, val);
	}
	else {
		val = rspamd_mempool_strdup (pool, src);
		d.lv = g_list_prepend (d.lv, val);
	}

	*target = d.p;
}

gboolean
rspamd_rcl_parse_struct_string_list (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	gpointer *target;
	gchar *val, **strvec, **cvec;
	const ucl_object_t *cur;
	const gsize num_str_len = 32;
	ucl_object_iter_t iter = NULL;
	gboolean is_hash;


	is_hash = pd->flags & RSPAMD_CL_FLAG_STRING_LIST_HASH;
	target = (gpointer *)(((gchar *)pd->user_struct) + pd->offset);

	iter = ucl_object_iterate_new (obj);

	while ((cur = ucl_object_iterate_safe (iter, true)) != NULL) {
		switch (cur->type) {
		case UCL_STRING:
			strvec = g_strsplit_set (ucl_object_tostring (cur), ",", -1);
			cvec = strvec;

			while (*cvec) {
				rspamd_rcl_insert_string_list_item (target, pool, *cvec, is_hash);
				cvec ++;
			}

			g_strfreev (strvec);
			/* Go to the next object */
			continue;
		case UCL_INT:
			val = rspamd_mempool_alloc (pool, num_str_len);
			rspamd_snprintf (val, num_str_len, "%L", cur->value.iv);
			break;
		case UCL_FLOAT:
			val = rspamd_mempool_alloc (pool, num_str_len);
			rspamd_snprintf (val, num_str_len, "%f", cur->value.dv);
			break;
		case UCL_BOOLEAN:
			val = rspamd_mempool_alloc (pool, num_str_len);
			rspamd_snprintf (val, num_str_len, "%b", (gboolean)cur->value.iv);
			break;
		default:
			g_set_error (err,
					CFG_RCL_ERROR,
					EINVAL,
					"cannot convert an object or array to string: %s",
					ucl_object_key (obj));
			return FALSE;
		}

		rspamd_rcl_insert_string_list_item (target, pool, val, is_hash);
	}

	if (*target == NULL) {
		g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"an array of strings is expected: %s",
				ucl_object_key (obj));
		return FALSE;
	}

	/* Add a destructor */

	if (!is_hash) {
		rspamd_mempool_add_destructor (pool,
				(rspamd_mempool_destruct_t) g_list_free,
				*target);
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_boolean (rspamd_mempool_t *pool,
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
				"cannot convert an object to boolean: %s",
				ucl_object_key (obj));
		return FALSE;
	}

	if (pd->flags & RSPAMD_CL_FLAG_BOOLEAN_INVERSE) {
		*target = !*target;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_addr (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	rspamd_inet_addr_t **target;
	const gchar *val;

	target = (rspamd_inet_addr_t **)(((gchar *)pd->user_struct) + pd->offset);

	if (ucl_object_type (obj) == UCL_STRING) {
		val = ucl_object_tostring (obj);

		if (!rspamd_parse_inet_address (target, val, 0)) {
			g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"cannot parse inet address: %s", val);
			return FALSE;
		}
	}
	else {
		g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"cannot convert an object to inet address: %s",
				ucl_object_key (obj));
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_mime_addr (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	InternetAddressList **target, *tmp_addr;
	const gchar *val;
	ucl_object_iter_t it;
	const ucl_object_t *cur;

	target = (InternetAddressList **)(((gchar *)pd->user_struct) + pd->offset);
	if (*target == NULL) {
		*target = internet_address_list_new ();
	#ifdef GMIME24
			rspamd_mempool_add_destructor (pool,
					(rspamd_mempool_destruct_t) g_object_unref,
					*target);
	#else
			rspamd_mempool_add_destructor (pool,
					(rspamd_mempool_destruct_t) internet_address_list_destroy,
					*target);
	#endif
	}

	it = ucl_object_iterate_new (obj);

	while ((cur = ucl_object_iterate_safe (it, true)) != NULL) {

		if (ucl_object_type (cur) == UCL_STRING) {
			val = ucl_object_tostring (obj);
			tmp_addr = internet_address_list_parse_string (val);

			if (tmp_addr) {
				internet_address_list_append (*target, tmp_addr);
#ifdef GMIME24
				g_object_unref (tmp_addr);
#else
				internet_address_list_destroy (tmp_addr);
#endif
			}
			else {
				g_set_error (err,
						CFG_RCL_ERROR,
						EINVAL,
						"cannot parse inet address: %s in %s", val,
						ucl_object_key (obj));
				ucl_object_iterate_free (it);

				return FALSE;
			}
		}
		else {
			g_set_error (err,
					CFG_RCL_ERROR,
					EINVAL,
					"cannot get inet address from ucl object in %s",
					ucl_object_key (obj));
			ucl_object_iterate_free (it);

			return FALSE;
		}
	}

	ucl_object_iterate_free (it);
	return TRUE;
}

void
rspamd_rcl_register_worker_option (struct rspamd_config *cfg,
	gint type,
	const gchar *name,
	rspamd_rcl_default_handler_t handler,
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
		msg_warn_config (
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
	gpointer logger_ud, GHashTable *vars)
{
	struct stat st;
	gint fd;
	gchar *data;
	GError *err = NULL;
	struct rspamd_rcl_section *top, *logger;
	struct ucl_parser *parser;
	unsigned char cksumbuf[rspamd_cryptobox_HASHBYTES];

	if (stat (filename, &st) == -1) {
		msg_err_config ("cannot stat %s: %s", filename, strerror (errno));
		return FALSE;
	}
	if ((fd = open (filename, O_RDONLY)) == -1) {
		msg_err_config ("cannot open %s: %s", filename, strerror (errno));
		return FALSE;

	}
	/* Now mmap this file to simplify reading process */
	if ((data =
		mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		msg_err_config ("cannot mmap %s: %s", filename, strerror (errno));
		close (fd);
		return FALSE;
	}
	close (fd);

	rspamd_cryptobox_hash (cksumbuf, data, st.st_size, NULL, 0);
	cfg->checksum = rspamd_encode_base32 (cksumbuf, sizeof (cksumbuf));
	/* Also change the tag of cfg pool to be equal to the checksum */
	rspamd_strlcpy (cfg->cfg_pool->tag.uid, cfg->checksum,
			MIN (sizeof (cfg->cfg_pool->tag.uid), strlen (cfg->checksum)));

	parser = ucl_parser_new (0);
	rspamd_ucl_add_conf_variables (parser, vars);
	rspamd_ucl_add_conf_macros (parser, cfg);

	if (!ucl_parser_add_chunk (parser, data, st.st_size)) {
		msg_err_config ("ucl parser error: %s", ucl_parser_get_error (parser));
		ucl_parser_free (parser);
		munmap (data, st.st_size);
		return FALSE;
	}

	munmap (data, st.st_size);
	cfg->rcl_obj = ucl_parser_get_object (parser);
	ucl_parser_free (parser);

	top = rspamd_rcl_config_init ();
	rspamd_rcl_set_lua_globals (cfg, cfg->lua_state, vars);
	err = NULL;

	if (logger_fin != NULL) {
		HASH_FIND_STR (top, "logging", logger);
		if (logger != NULL) {
			logger->fin = logger_fin;
			logger->fin_ud = logger_ud;
		}
	}

	if (!rspamd_rcl_parse (top, cfg, cfg->cfg_pool, cfg->rcl_obj, &err)) {
		msg_err_config ("rcl parse error: %e", err);
		g_error_free (err);
		return FALSE;
	}

	return TRUE;
}
