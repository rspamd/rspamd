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
#include "cfg_rcl.h"
#include "rspamd.h"
#include "../../contrib/mumhash/mum.h"
#define HASH_CASELESS
#include "uthash_strcase.h"
#include "utlist.h"
#include "cfg_file.h"
#include "lua/lua_common.h"
#include "expression.h"
#include "composites.h"
#include "libserver/worker_util.h"
#include "unix-std.h"
#include "cryptobox.h"
#include "libutil/multipattern.h"

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
	ucl_object_t *doc_ref;       /**< reference to the section's documentation */
};

struct rspamd_worker_param_key {
	const gchar *name;
	gpointer ptr;
};

struct rspamd_worker_param_parser {
	rspamd_rcl_default_handler_t handler;           /**< handler function									*/
	struct rspamd_rcl_struct_parser parser;         /**< parser attributes									*/

	struct rspamd_worker_param_key key;
};

struct rspamd_worker_cfg_parser {
	GHashTable *parsers;                            /**< parsers hash										*/
	gint type;                                      /**< workers quark										*/
	gboolean (*def_obj_parser)(ucl_object_t *obj, gpointer ud);   /**<
 														 default object parser								*/
	gpointer def_ud;
};

static gboolean rspamd_rcl_process_section (struct rspamd_config *cfg,
		struct rspamd_rcl_section *sec,
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
	const gchar *facility = NULL, *log_type = NULL, *log_level = NULL;
	struct rspamd_config *cfg = ud;

	val = ucl_object_lookup (obj, "type");
	if (val != NULL && ucl_object_tostring_safe (val, &log_type)) {
		if (g_ascii_strcasecmp (log_type, "file") == 0) {
			/* Need to get filename */
			val = ucl_object_lookup (obj, "filename");
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
			val = ucl_object_lookup (obj, "facility");
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
	val = ucl_object_lookup (obj, "level");
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

	return rspamd_rcl_section_parse_defaults (cfg, section, cfg->cfg_pool, obj,
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

	dns = ucl_object_lookup (obj, "dns");
	if (dns_section != NULL && dns != NULL) {
		if (!rspamd_rcl_section_parse_defaults (cfg,
				dns_section, cfg->cfg_pool, dns,
				cfg, err)) {
			return FALSE;
		}
	}

	HASH_FIND_STR (section->subsections, "upstream", upstream_section);

	upstream = ucl_object_lookup (obj, "upstream");
	if (upstream_section != NULL && upstream != NULL) {
		if (!rspamd_rcl_section_parse_defaults (cfg,
				upstream_section, cfg->cfg_pool,
				upstream, cfg, err)) {
			return FALSE;
		}
	}

	if (rspamd_rcl_section_parse_defaults (cfg,
			section, cfg->cfg_pool, obj,
			cfg, err)) {
		/* We need to init this early */
		rspamd_multipattern_library_init (cfg->hs_cache_dir,
				cfg->libs_ctx->crypto_ctx);

		return TRUE;
	}

	return FALSE;
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

	if (!rspamd_rcl_section_parse_defaults (sd->cfg, section, pool, obj,
			gr, err)) {
		return FALSE;
	}

	sd->gr = gr;

	/* Handle symbols */
	val = ucl_object_lookup (obj, "symbol");
	if (val != NULL && ucl_object_type (val) == UCL_OBJECT) {
		HASH_FIND_STR (section->subsections, "symbol", subsection);
		g_assert (subsection != NULL);

		LL_FOREACH (val, cur) {
			if (!rspamd_rcl_process_section (sd->cfg, subsection, sd, cur,
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
	struct metric *metric;
	struct rspamd_config *cfg;
	const ucl_object_t *elt;
	const gchar *description = NULL;
	gdouble score = 0.0;
	guint priority = 1, flags = 0;

	g_assert (key != NULL);
	metric = sd->metric;
	g_assert (metric != NULL);
	cfg = sd->cfg;

	if ((elt = ucl_object_lookup (obj, "one_shot")) != NULL) {
		if (ucl_object_toboolean (elt)) {
			flags |= RSPAMD_SYMBOL_FLAG_ONESHOT;
		}
	}

	if ((elt = ucl_object_lookup (obj, "ignore")) != NULL) {
		if (ucl_object_toboolean (elt)) {
			flags |= RSPAMD_SYMBOL_FLAG_IGNORE;
		}
	}

	elt = ucl_object_lookup_any (obj, "score", "weight", NULL);
	if (elt) {
		score = ucl_object_todouble (elt);
	}

	elt = ucl_object_lookup (obj, "priority");
	if (elt) {
		priority = ucl_object_toint (elt);
	}
	else {
		priority = ucl_object_get_priority (obj) + 1;
	}

	elt = ucl_object_lookup (obj, "description");
	if (elt) {
		description = ucl_object_tostring (elt);
	}

	if (sd->gr) {
		rspamd_config_add_metric_symbol (cfg, metric->name, key, score,
				description, sd->gr->name, flags, priority);
	}
	else {
		rspamd_config_add_metric_symbol (cfg, metric->name, key, score,
				description, NULL, flags, priority);
	}

	return TRUE;
}

struct metric_actions_cbdata {
	struct rspamd_config *cfg;
	struct metric *metric;
};

static gboolean
rspamd_rcl_actions_handler (rspamd_mempool_t *pool, const ucl_object_t *obj,
		const gchar *key, gpointer ud,
		struct rspamd_rcl_section *section, GError **err)
{
	gdouble action_score;
	struct metric_actions_cbdata *cbdata = ud;
	gint action_value;
	const ucl_object_t *cur;
	ucl_object_iter_t it = NULL;
	struct metric *metric;
	struct rspamd_config *cfg;

	metric = cbdata->metric;
	cfg = cbdata->cfg;

	while ((cur = ucl_object_iterate (obj, &it, true)) != NULL) {
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
			rspamd_config_set_action_score (cfg, metric->name,
					ucl_object_key (cur), action_score,
					ucl_object_get_priority (cur));
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
	struct metric_actions_cbdata acts_cbdata;

	g_assert (key != NULL);

	metric = g_hash_table_lookup (cfg->metrics, key);
	if (metric == NULL) {
		metric = rspamd_config_new_metric (cfg, metric, key);
	}

	if (!rspamd_rcl_section_parse_defaults (cfg, section, cfg->cfg_pool, obj,
			metric, err)) {
		return FALSE;
	}

	if (metric->unknown_weight > 0) {
		metric->accept_unknown_symbols = TRUE;
	}

	/* Handle actions */
	val = ucl_object_lookup (obj, "actions");
	if (val != NULL) {
		if (val->type != UCL_OBJECT) {
			g_set_error (err, CFG_RCL_ERROR, EINVAL,
				"actions must be an object");
			return FALSE;
		}

		HASH_FIND_STR (section->subsections, "actions", subsection);
		g_assert (subsection != NULL);
		acts_cbdata.cfg = cfg;
		acts_cbdata.metric = metric;

		if (!rspamd_rcl_process_section (cfg, subsection, &acts_cbdata, val,
				cfg->cfg_pool, err)) {
			return FALSE;
		}
	}

	/* No more legacy mode */

	/* Handle grouped symbols */
	val = ucl_object_lookup (obj, "group");
	if (val != NULL && ucl_object_type (val) == UCL_OBJECT) {
		HASH_FIND_STR (section->subsections, "group", subsection);
		g_assert (subsection != NULL);
		sd.gr = NULL;
		sd.cfg = cfg;
		sd.metric = metric;

		LL_FOREACH (val, cur) {
			if (!rspamd_rcl_process_section (cfg, subsection, &sd, cur,
					cfg->cfg_pool, err)) {
				return FALSE;
			}
		}
	}

	/* Handle symbols */
	val = ucl_object_lookup (obj, "symbol");
	if (val != NULL && ucl_object_type (val) == UCL_OBJECT) {
		HASH_FIND_STR (section->subsections, "symbol", subsection);
		g_assert (subsection != NULL);
		sd.gr = NULL;
		sd.cfg = cfg;
		sd.metric = metric;

		LL_FOREACH (val, cur) {
			if (!rspamd_rcl_process_section (cfg, subsection, &sd, cur,
					cfg->cfg_pool, err)) {
				return FALSE;
			}
		}
	}

	/* Handle ignored symbols */
	val = ucl_object_lookup (obj, "ignore");
	if (val != NULL && ucl_object_type (val) == UCL_ARRAY) {
		LL_FOREACH (val, cur) {
			it = NULL;

			while ((elt = ucl_object_iterate (cur, &it, true)) != NULL) {
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
	const ucl_object_t *val, *cur, *cur_obj;
	struct rspamd_dynamic_worker *dyn_wrk;
	worker_t *dyn_ctx;
	ucl_object_t *robj;
	ucl_object_iter_t it = NULL;
	const gchar *worker_type, *worker_bind, *lib_path;
	struct rspamd_config *cfg = ud;
	GQuark qtype;
	struct rspamd_worker_conf *wrk;
	struct rspamd_worker_cfg_parser *wparser;
	struct rspamd_worker_param_parser *whandler;
	struct rspamd_worker_param_key srch;

	g_assert (key != NULL);
	worker_type = key;

	val = ucl_object_lookup_any (obj, "module", "load", NULL);

	if (val != NULL && ucl_object_tostring_safe (val, &lib_path)) {

		if (!g_module_supported ()) {
			msg_err_config ("modules are not supported, so load of %s is impossible",
					worker_type);

			return FALSE;
		}

		dyn_wrk = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*dyn_wrk));
		dyn_wrk->lib = g_module_open (lib_path, G_MODULE_BIND_LAZY);

		if (dyn_wrk->lib == NULL) {
			msg_err_config ("cannot load %s at %s: %s", worker_type,
					lib_path, strerror (errno));

			return FALSE;
		}

		if (!g_module_symbol (dyn_wrk->lib, "rspamd_dyn_worker",
				(gpointer *)&dyn_ctx)) {
			msg_err_config ("cannot load %s at %s: missing entry point",
					worker_type,
					lib_path);
			g_module_close (dyn_wrk->lib);

			return FALSE;
		}

		if (!rspamd_check_worker (cfg, dyn_ctx)) {
			g_module_close (dyn_wrk->lib);

			return FALSE;
		}

		memcpy (&dyn_wrk->wrk, dyn_ctx, sizeof (dyn_wrk->wrk));
		dyn_wrk->path = lib_path;
		dyn_wrk->type = g_quark_from_static_string (worker_type);
		cfg->dynamic_workers = g_list_prepend (cfg->dynamic_workers, dyn_wrk);
	}

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
		msg_err_config ("unknown worker type: %s", worker_type);
		return TRUE;
	}

	val = ucl_object_lookup_any (obj, "bind_socket", "listen", "bind", NULL);
	/* This name is more logical */
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

	if (!rspamd_rcl_section_parse_defaults (cfg, section, cfg->cfg_pool, obj,
			wrk, err)) {
		return FALSE;
	}

	/* Parse other attributes */
	wparser = g_hash_table_lookup (cfg->wrk_parsers, &qtype);

	if (wparser != NULL && obj->type == UCL_OBJECT) {
		it = NULL;
		while ((cur = ucl_object_iterate (obj, &it, true)) != NULL) {
			srch.name = ucl_object_key (cur);
			srch.ptr = wrk->ctx; /* XXX: is it valid? */
			whandler = g_hash_table_lookup (wparser->parsers, &srch);

			if (whandler != NULL) {

				LL_FOREACH (cur, cur_obj) {
					if (!whandler->handler (cfg->cfg_pool,
							cur_obj,
							&whandler->parser,
							section,
							err)) {
						return FALSE;
					}

					if (!(whandler->parser.flags & RSPAMD_CL_FLAG_MULTIPLE)) {
						break;
					}
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

static gint
rspamd_rcl_cmp_components (const gchar *comp1, const gchar *comp2)
{
	guint v1, v2;

	v1 = strtoul (comp1, NULL, 10);
	v2 = strtoul (comp2, NULL, 10);

	return v1 - v2;
}

static int
rspamd_rcl_lua_version_cmp (lua_State *L)
{
	const gchar *ver;
	gchar **components;
	gint ret = 0;

	if (lua_type (L, 2) == LUA_TSTRING) {
		ver = lua_tostring (L, 2);

		components = g_strsplit_set (ver, ".-_", -1);

		if (!components) {
			return luaL_error (L, "invalid arguments to 'cmp': %s", ver);
		}

		if (components[0]) {
			ret = rspamd_rcl_cmp_components (components[0], RSPAMD_VERSION_MAJOR);
		}

		if (ret) {
			goto set;
		}

		if (components[1]) {
			ret = rspamd_rcl_cmp_components (components[1], RSPAMD_VERSION_MINOR);
		}

		if (ret) {
			goto set;
		}

		if (components[2]) {
			ret = rspamd_rcl_cmp_components (components[2], RSPAMD_VERSION_PATCH);
		}

		/*
		 * XXX: we don't compare git releases assuming that it is meaningless
		 */
	}
	else {
		return luaL_error (L, "invalid arguments to 'cmp'");
	}

set:
	g_strfreev (components);
	lua_pushnumber (L, ret);

	return 1;
}

static int
rspamd_rcl_lua_version_numeric (lua_State *L)
{
	static gint64 version_num = RSPAMD_VERSION_NUM;
	const gchar *type;

	if (lua_gettop (L) >= 2 && lua_type (L, 1) == LUA_TSTRING) {
		type = lua_tostring (L, 1);
		if (g_ascii_strcasecmp (type, "short") == 0) {
			version_num = RSPAMD_VERSION_MAJOR_NUM * 1000 +
					RSPAMD_VERSION_MINOR_NUM * 100 + RSPAMD_VERSION_PATCH_NUM * 10;
		}
		else if (g_ascii_strcasecmp (type, "main") == 0) {
			version_num = RSPAMD_VERSION_MAJOR_NUM * 1000 +
						RSPAMD_VERSION_MINOR_NUM * 100;
		}
		else if (g_ascii_strcasecmp (type, "major") == 0) {
			version_num = RSPAMD_VERSION_MAJOR_NUM;
		}
		else if (g_ascii_strcasecmp (type, "minor") == 0) {
			version_num = RSPAMD_VERSION_MINOR_NUM;
		}
		else if (g_ascii_strcasecmp (type, "patch") == 0) {
			version_num = RSPAMD_VERSION_PATCH_NUM;
		}
	}

	lua_pushnumber (L, version_num);

	return 1;
}

static int
rspamd_rcl_lua_version (lua_State *L)
{
	const gchar *result = NULL, *type;

	if (lua_gettop (L) == 0) {
		result = RVERSION;
	}
	else if (lua_gettop (L) >= 1 && lua_type (L, 1) == LUA_TSTRING) {
		/* We got something like string */
		type = lua_tostring (L, 1);

		if (g_ascii_strcasecmp (type, "short") == 0) {
			result = RSPAMD_VERSION_MAJOR
					"." RSPAMD_VERSION_MINOR
					"." RSPAMD_VERSION_PATCH;
		}
		else if (g_ascii_strcasecmp (type, "main") == 0) {
			result = RSPAMD_VERSION_MAJOR "." RSPAMD_VERSION_MINOR;
		}
		else if (g_ascii_strcasecmp (type, "major") == 0) {
			result = RSPAMD_VERSION_MAJOR;
		}
		else if (g_ascii_strcasecmp (type, "minor") == 0) {
			result = RSPAMD_VERSION_MINOR;
		}
		else if (g_ascii_strcasecmp (type, "patch") == 0) {
			result = RSPAMD_VERSION_PATCH;
		}
		else if (g_ascii_strcasecmp (type, "id") == 0) {
			result = RID;
		}
		else if (g_ascii_strcasecmp (type, "num") == 0) {
			return rspamd_rcl_lua_version_numeric (L);
		}
		else if (g_ascii_strcasecmp (type, "cmp") == 0) {
			return rspamd_rcl_lua_version_cmp (L);
		}
	}

	lua_pushstring (L, result);

	return 1;
}

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

	lua_getglobal (L, "rspamd_version");
	if (lua_isnil (L, -1)) {
		lua_pushcfunction (L, rspamd_rcl_lua_version);
		lua_setglobal (L, "rspamd_version");
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
	GString *tb;
	gint err_idx;

	tmp1 = g_strdup (lua_src);
	tmp2 = g_strdup (lua_src);
	lua_dir = dirname (tmp1);
	lua_file = basename (tmp2);

	if (lua_dir && lua_file) {
		cur_dir = g_malloc (PATH_MAX);
		if (getcwd (cur_dir, PATH_MAX) != NULL && chdir (lua_dir) != -1) {
			/* Push traceback function */
			lua_pushcfunction (L, &rspamd_lua_traceback);
			err_idx = lua_gettop (L);

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
			if (lua_pcall (L, 0, 0, err_idx) != 0) {
				tb = lua_touserdata (L, -1);
				g_set_error (err,
						CFG_RCL_ERROR,
						EINVAL,
						"cannot init lua file %s: %s",
						lua_src,
						tb->str);
				g_string_free (tb, TRUE);
				lua_pop (L, 2);

				if (chdir (cur_dir) == -1) {
					msg_err_config ("cannot chdir to %s: %s", cur_dir,
						strerror (errno));
				}

				g_free (cur_dir);
				g_free (tmp1);
				g_free (tmp2);

				return FALSE;
			}

			lua_pop (L, 1);
		}
		else {
			g_set_error (err, CFG_RCL_ERROR, ENOENT, "cannot chdir to %s: %s",
					lua_dir, strerror (errno));
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
		val = ucl_object_lookup (obj, "path");

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

	if (rspamd_rcl_section_parse_defaults (cfg, section, pool, obj, st, err)) {
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

		val = ucl_object_lookup (obj, "spam");
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
	lua_State *L;

	g_assert (key != NULL);
	ccf = rspamd_config_new_classifier (cfg, NULL);

	ccf->classifier = rspamd_mempool_strdup (cfg->cfg_pool, key);

	if (rspamd_rcl_section_parse_defaults (cfg, section, cfg->cfg_pool, obj,
			ccf, err)) {

		HASH_FIND_STR (section->subsections, "statfile", stat_section);

		if (ccf->classifier == NULL) {
			ccf->classifier = "bayes";
		}

		if (ccf->name == NULL) {
			ccf->name = ccf->classifier;
		}

		while ((val = ucl_object_iterate (obj, &it, true)) != NULL && res) {
			st_key = ucl_object_key (val);
			if (st_key != NULL) {
				if (g_ascii_strcasecmp (st_key, "statfile") == 0) {
					LL_FOREACH (val, cur) {
						stud.cfg = cfg;
						stud.ccf = ccf;
						res = rspamd_rcl_process_section (cfg, stat_section, &stud,
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
						cur = ucl_object_lookup (val, "name");
						if (cur != NULL) {
							tkcf->name = ucl_object_tostring (cur);
							tkcf->opts = val;
						}
						else {
							cur = ucl_object_lookup (val, "type");
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

	/* Handle lua conditions */
	val = ucl_object_lookup_any (obj, "condition", "learn_condition", NULL);

	if (val) {
		LL_FOREACH (val, cur) {
			if (ucl_object_type (cur) == UCL_STRING) {
				const gchar *lua_script;
				gsize slen;
				gint err_idx, ref_idx;
				GString *tb = NULL;

				lua_script = ucl_object_tolstring (cur, &slen);
				L = cfg->lua_state;
				lua_pushcfunction (L, &rspamd_lua_traceback);
				err_idx = lua_gettop (L);


				/* Load file */
				if (luaL_loadbuffer (L, lua_script, slen, "learn_condition") != 0) {
					g_set_error (err,
							CFG_RCL_ERROR,
							EINVAL,
							"cannot load lua condition script: %s",
							lua_tostring (L, -1));
					lua_settop (L, 0); /* Error function */

					return FALSE;
				}

				/* Now do it */
				if (lua_pcall (L, 0, 1, err_idx) != 0) {
					tb = lua_touserdata (L, -1);
					g_set_error (err,
							CFG_RCL_ERROR,
							EINVAL,
							"cannot init lua condition script: %s",
							tb->str);
					g_string_free (tb, TRUE);
					lua_settop (L, 0);

					return FALSE;
				}

				if (!lua_isfunction (L, -1)) {
					g_set_error (err,
							CFG_RCL_ERROR,
							EINVAL,
							"cannot init lua condition script: "
							"must return function");
					lua_settop (L, 0);

					return FALSE;
				}

				ref_idx = luaL_ref (L, LUA_REGISTRYINDEX);
				ccf->learn_conditions = g_list_append (ccf->learn_conditions,
						GINT_TO_POINTER (ref_idx));
				lua_settop (L, 0);
			}
		}
	}

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

	val = ucl_object_lookup (obj, "expression");
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
		rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (struct rspamd_composite));
	composite->expr = expr;
	composite->id = g_hash_table_size (cfg->composite_symbols);
	g_hash_table_insert (cfg->composite_symbols,
		(gpointer)composite_name,
		composite);

	if (new) {
		rspamd_symbols_cache_add_symbol (cfg->cache, composite_name, 0,
			NULL, NULL, SYMBOL_TYPE_COMPOSITE, -1);
	}

	val = ucl_object_lookup (obj, "score");
	if (val != NULL && ucl_object_todouble_safe (val, &score)) {
		/* Also set score in the metric */

		val = ucl_object_lookup (obj, "group");
		if (val != NULL) {
			group = ucl_object_tostring (val);
		}
		else {
			group = "composite";
		}

		val = ucl_object_lookup (obj, "metric");
		if (val != NULL) {
			metric = ucl_object_tostring (val);
		}
		else {
			metric = DEFAULT_METRIC;
		}

		val = ucl_object_lookup (obj, "description");
		if (val != NULL) {
			description = ucl_object_tostring (val);
		}
		else {
			description = composite_expression;
		}

		rspamd_config_add_metric_symbol (cfg, metric, composite_name, score,
				description, group, FALSE, FALSE);
	}

	val = ucl_object_lookup (obj, "policy");

	if (val) {
		composite->policy = rspamd_composite_policy_from_str (
				ucl_object_tostring (val));

		if (composite->policy == RSPAMD_COMPOSITE_POLICY_UNKNOWN) {
			g_set_error (err,
					CFG_RCL_ERROR,
					EINVAL,
					"composite %s has incorrect policy", composite_name);
			return FALSE;
		}
	}

	return TRUE;
}

struct rspamd_rcl_section *
rspamd_rcl_add_section (struct rspamd_rcl_section **top,
	const gchar *name, const gchar *key_attr, rspamd_rcl_handler_t handler,
	enum ucl_type type, gboolean required, gboolean strict_type)
{
	struct rspamd_rcl_section *new;
	ucl_object_t *parent_doc;

	new = g_slice_alloc0 (sizeof (struct rspamd_rcl_section));
	new->name = name;
	new->key_attr = key_attr;
	new->handler = handler;
	new->type = type;
	new->strict_type = strict_type;

	if (*top == NULL) {
		parent_doc = NULL;
		new->doc_ref = NULL;
	}
	else {
		parent_doc = (*top)->doc_ref;
		new->doc_ref = rspamd_rcl_add_doc_obj (parent_doc,
				NULL,
				name,
				type,
				NULL,
				0,
				NULL,
				0);
	}

	HASH_ADD_KEYPTR (hh, *top, new->name, strlen (new->name), new);
	return new;
}

struct rspamd_rcl_section *
rspamd_rcl_add_section_doc (struct rspamd_rcl_section **top,
		const gchar *name, const gchar *key_attr, rspamd_rcl_handler_t handler,
		enum ucl_type type, gboolean required, gboolean strict_type,
		ucl_object_t *doc_target,
		const gchar *doc_string)
{
	struct rspamd_rcl_section *new;

	new = g_slice_alloc0 (sizeof (struct rspamd_rcl_section));
	new->name = name;
	new->key_attr = key_attr;
	new->handler = handler;
	new->type = type;
	new->strict_type = strict_type;

	new->doc_ref = rspamd_rcl_add_doc_obj (doc_target,
			doc_string,
			name,
			type,
			NULL,
			0,
			NULL,
			0);

	HASH_ADD_KEYPTR (hh, *top, new->name, strlen (new->name), new);
	return new;
}

struct rspamd_rcl_default_handler_data *
rspamd_rcl_add_default_handler (struct rspamd_rcl_section *section,
		const gchar *name,
		rspamd_rcl_default_handler_t handler,
		goffset offset,
		gint flags,
		const gchar *doc_string)
{
	struct rspamd_rcl_default_handler_data *new;

	new = g_slice_alloc0 (sizeof (struct rspamd_rcl_default_handler_data));
	new->key = name;
	new->handler = handler;
	new->pd.offset = offset;
	new->pd.flags = flags;

	if (section->doc_ref != NULL) {
		rspamd_rcl_add_doc_obj (section->doc_ref,
				doc_string,
				name,
				UCL_NULL,
				handler,
				flags,
				NULL,
				0);
	}

	HASH_ADD_KEYPTR (hh, section->default_parser, new->key, strlen (
			new->key), new);
	return new;
}

struct rspamd_rcl_section *
rspamd_rcl_config_init (struct rspamd_config *cfg)
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
	sub = rspamd_rcl_add_section_doc (&new,
			"logging", NULL,
			rspamd_rcl_logging_handler,
			UCL_OBJECT,
			FALSE,
			TRUE,
			cfg->doc_strings,
			"Configure rspamd logging");
	/* Default handlers */
	rspamd_rcl_add_default_handler (sub,
			"log_buffer",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, log_buf_size),
			0,
			"Size of log buffer in bytes (for file logging)");
	rspamd_rcl_add_default_handler (sub,
			"log_urls",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, log_urls),
			0,
			"Write each URL found in a message to the log file");
	rspamd_rcl_add_default_handler (sub,
			"log_re_cache",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, log_re_cache),
			0,
			"Write statistics of regexp processing to log (useful for hyperscan)");
	rspamd_rcl_add_default_handler (sub,
			"debug_ip",
			rspamd_rcl_parse_struct_ucl,
			G_STRUCT_OFFSET (struct rspamd_config, debug_ip_map),
			0,
			"Enable debugging log for the specified IP addresses");
	rspamd_rcl_add_default_handler (sub,
			"debug_symbols",
			rspamd_rcl_parse_struct_string_list,
			G_STRUCT_OFFSET (struct rspamd_config, debug_symbols),
			0,
			"Enable debug for the specified symbols");
	rspamd_rcl_add_default_handler (sub,
			"log_color",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, log_color),
			0,
			"Enable colored output (for console logging)");
	rspamd_rcl_add_default_handler (sub,
			"color",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, log_color),
			0,
			"Enable colored output (for console logging)");
	rspamd_rcl_add_default_handler (sub,
			"log_systemd",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, log_systemd),
			0,
			"Enable systemd compatible logging");
	rspamd_rcl_add_default_handler (sub,
			"systemd",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, log_systemd),
			0,
			"Enable systemd compatible logging");
	rspamd_rcl_add_default_handler (sub,
			"debug_modules",
			rspamd_rcl_parse_struct_string_list,
			G_STRUCT_OFFSET (struct rspamd_config, debug_modules),
			RSPAMD_CL_FLAG_STRING_LIST_HASH,
			"Enable debugging for the specified modules");
	rspamd_rcl_add_default_handler (sub,
			"log_format",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, log_format_str),
			0,
			"Specify format string for the task logging output "
					"(https://rspamd.com/doc/configuration/logging.html "
					"for details)");
	rspamd_rcl_add_default_handler (sub,
			"encryption_key",
			rspamd_rcl_parse_struct_pubkey,
			G_STRUCT_OFFSET (struct rspamd_config, log_encryption_key),
			0,
			"Encrypt sensitive information in logs using this pubkey");
	/**
	 * Options section
	 */
	sub = rspamd_rcl_add_section_doc (&new,
			"options", NULL,
			rspamd_rcl_options_handler,
			UCL_OBJECT,
			FALSE,
			TRUE,
			cfg->doc_strings,
			"Global rspamd options");
	rspamd_rcl_add_default_handler (sub,
			"cache_file",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, cache_filename),
			RSPAMD_CL_FLAG_STRING_PATH,
			"Path to the cache file");
	/* Old DNS configuration */
	rspamd_rcl_add_default_handler (sub,
			"dns_nameserver",
			rspamd_rcl_parse_struct_ucl,
			G_STRUCT_OFFSET (struct rspamd_config, nameservers),
			0,
			"Legacy option for DNS servers used");
	rspamd_rcl_add_default_handler (sub,
			"dns_timeout",
			rspamd_rcl_parse_struct_time,
			G_STRUCT_OFFSET (struct rspamd_config, dns_timeout),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"Legacy option for DNS request timeout");
	rspamd_rcl_add_default_handler (sub,
			"dns_retransmits",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, dns_retransmits),
			RSPAMD_CL_FLAG_INT_32,
			"Legacy option for DNS retransmits count");
	rspamd_rcl_add_default_handler (sub,
			"dns_sockets",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, dns_io_per_server),
			RSPAMD_CL_FLAG_INT_32,
			"Legacy option for DNS sockets per server count");
	rspamd_rcl_add_default_handler (sub,
			"dns_max_requests",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, dns_max_requests),
			RSPAMD_CL_FLAG_INT_32,
			"Legacy option for DNS maximum requests per task count");
	rspamd_rcl_add_default_handler (sub,
			"classify_headers",
			rspamd_rcl_parse_struct_string_list,
			G_STRUCT_OFFSET (struct rspamd_config, classify_headers),
			0,
			"List of headers used for classifiers");
	rspamd_rcl_add_default_handler (sub,
			"control_socket",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, control_socket_path),
			0,
			"Path to the control socket");
	rspamd_rcl_add_default_handler (sub,
			"explicit_modules",
			rspamd_rcl_parse_struct_string_list,
			G_STRUCT_OFFSET (struct rspamd_config, explicit_modules),
			RSPAMD_CL_FLAG_STRING_LIST_HASH,
			"Always load these modules even if they are not configured explicitly");
	rspamd_rcl_add_default_handler (sub,
			"allow_raw_input",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, allow_raw_input),
			0,
			"Allow non MIME input for rspamd");
	rspamd_rcl_add_default_handler (sub,
			"raw_mode",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, raw_mode),
			0,
			"Don't try to convert all messages to utf8");
	rspamd_rcl_add_default_handler (sub,
			"one_shot",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, one_shot_mode),
			0,
			"Add all symbols only once per message");
	rspamd_rcl_add_default_handler (sub,
			"check_attachements",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, check_text_attachements),
			0,
			"Treat text attachements as normal text parts");
	rspamd_rcl_add_default_handler (sub,
			"tempdir",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, temp_dir),
			RSPAMD_CL_FLAG_STRING_PATH,
			"Directory for temporary files");
	rspamd_rcl_add_default_handler (sub,
			"pidfile",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, pid_file),
			RSPAMD_CL_FLAG_STRING_PATH,
			"Path to the pid file");
	rspamd_rcl_add_default_handler (sub,
			"filters",
			rspamd_rcl_parse_struct_string_list,
			G_STRUCT_OFFSET (struct rspamd_config, filters),
			0,
			"List of internal filters enabled");
	rspamd_rcl_add_default_handler (sub,
			"max_diff",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, max_diff),
			RSPAMD_CL_FLAG_INT_SIZE,
			"Legacy option, do not use");
	rspamd_rcl_add_default_handler (sub,
			"map_watch_interval",
			rspamd_rcl_parse_struct_time,
			G_STRUCT_OFFSET (struct rspamd_config, map_timeout),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"Interval for checking maps");
	rspamd_rcl_add_default_handler (sub,
			"dynamic_conf",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, dynamic_conf),
			0,
			"Path to the dynamic configuration");
	rspamd_rcl_add_default_handler (sub,
			"rrd",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, rrd_file),
			RSPAMD_CL_FLAG_STRING_PATH,
			"Path to RRD file");
	rspamd_rcl_add_default_handler (sub,
			"history_file",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, history_file),
			RSPAMD_CL_FLAG_STRING_PATH,
			"Path to history file");
	rspamd_rcl_add_default_handler (sub,
			"use_mlock",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, mlock_statfile_pool),
			0,
			"Use mlock call for statistics to ensure that all files are in RAM");
	rspamd_rcl_add_default_handler (sub,
			"strict_protocol_headers",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, strict_protocol_headers),
			0,
			"Emit errors if there are unknown HTTP headers in a request");
	rspamd_rcl_add_default_handler (sub,
			"check_all_filters",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, check_all_filters),
			0,
			"Always check all filters");
	rspamd_rcl_add_default_handler (sub,
			"all_filters",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, check_all_filters),
			0,
			"Always check all filters");
	rspamd_rcl_add_default_handler (sub,
			"min_word_len",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, min_word_len),
			RSPAMD_CL_FLAG_UINT,
			"Minimum length of the word to be considered in statistics/fuzzy");
	rspamd_rcl_add_default_handler (sub,
			"max_word_len",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, max_word_len),
			RSPAMD_CL_FLAG_UINT,
			"Maximum length of the word to be considered in statistics/fuzzy");
	rspamd_rcl_add_default_handler (sub,
			"words_decay",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, words_decay),
			RSPAMD_CL_FLAG_UINT,
			"Start skipping words at this amount");
	rspamd_rcl_add_default_handler (sub,
			"url_tld",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, tld_file),
			RSPAMD_CL_FLAG_STRING_PATH,
			"Path to the TLD file for urls detector");
	rspamd_rcl_add_default_handler (sub,
			"tld",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, tld_file),
			RSPAMD_CL_FLAG_STRING_PATH,
			"Path to the TLD file for urls detector");
	rspamd_rcl_add_default_handler (sub,
			"hs_cache_dir",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, hs_cache_dir),
			RSPAMD_CL_FLAG_STRING_PATH,
			"Path directory where rspamd would save hyperscan cache");
	rspamd_rcl_add_default_handler (sub,
			"history_rows",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, history_rows),
			RSPAMD_CL_FLAG_UINT,
			"Number of records in the history file");
	rspamd_rcl_add_default_handler (sub,
			"disable_hyperscan",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, disable_hyperscan),
			0,
			"Disable hyperscan optimizations for regular expressions");
	rspamd_rcl_add_default_handler (sub,
			"vectorized_hyperscan",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, vectorized_hyperscan),
			0,
			"Use hyperscan in vectorized mode (experimental)");
	rspamd_rcl_add_default_handler (sub,
			"cores_dir",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, cores_dir),
			RSPAMD_CL_FLAG_STRING_PATH,
			"Path to the directory where rspamd core files are intended to be dumped");
	rspamd_rcl_add_default_handler (sub,
			"max_cores_size",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, max_cores_size),
			RSPAMD_CL_FLAG_INT_SIZE,
			"Limit of joint size of all files in `cores_dir`");
	rspamd_rcl_add_default_handler (sub,
			"max_cores_count",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, max_cores_count),
			RSPAMD_CL_FLAG_INT_SIZE,
			"Limit of files count in `cores_dir`");
	rspamd_rcl_add_default_handler (sub,
			"local_addrs",
			rspamd_rcl_parse_struct_ucl,
			G_STRUCT_OFFSET (struct rspamd_config, local_addrs),
			0,
			"Use the specified addresses as local ones");
	rspamd_rcl_add_default_handler (sub,
			"local_networks",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, local_addrs),
			0,
			"Use the specified addresses as local ones (alias for `local_addrs`)");
	rspamd_rcl_add_default_handler (sub,
			"trusted_keys",
			rspamd_rcl_parse_struct_string_list,
			G_STRUCT_OFFSET (struct rspamd_config, trusted_keys),
			RSPAMD_CL_FLAG_STRING_LIST_HASH,
			"List of trusted public keys used for signatures in base32 encoding");
	rspamd_rcl_add_default_handler (sub,
			"enable_shutdown_workaround",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, enable_shutdown_workaround),
			0,
			"Enable workaround for legacy clients");
	rspamd_rcl_add_default_handler (sub,
			"ignore_received",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, ignore_received),
			0,
			"Ignore data from the first received header");
	rspamd_rcl_add_default_handler (sub,
			"ssl_ca_path",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, ssl_ca_path),
			RSPAMD_CL_FLAG_STRING_PATH,
			"Path to ssl CA file");
	rspamd_rcl_add_default_handler (sub,
			"ssl_ciphers",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, ssl_ciphers),
			0,
			"List of ssl ciphers (e.g. HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4)");
	rspamd_rcl_add_default_handler (sub,
			"magic_file",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_config, magic_file),
			0,
			"Path to a custom libmagic file");
	rspamd_rcl_add_default_handler (sub,
			"max_message",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, max_message),
			RSPAMD_CL_FLAG_INT_SIZE,
			"Maximum size of the message to be scanned");
	/* New DNS configuration */
	ssub = rspamd_rcl_add_section_doc (&sub->subsections, "dns", NULL, NULL,
			UCL_OBJECT, FALSE, TRUE,
			cfg->doc_strings,
			"Options for DNS resolver");
	rspamd_rcl_add_default_handler (ssub,
			"nameserver",
			rspamd_rcl_parse_struct_ucl,
			G_STRUCT_OFFSET (struct rspamd_config, nameservers),
			0,
			"List of DNS servers");
	rspamd_rcl_add_default_handler (ssub,
			"server",
			rspamd_rcl_parse_struct_ucl,
			G_STRUCT_OFFSET (struct rspamd_config, nameservers),
			0,
			"List of DNS servers");
	rspamd_rcl_add_default_handler (ssub,
			"timeout",
			rspamd_rcl_parse_struct_time,
			G_STRUCT_OFFSET (struct rspamd_config, dns_timeout),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"DNS request timeout");
	rspamd_rcl_add_default_handler (ssub,
			"retransmits",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, dns_retransmits),
			RSPAMD_CL_FLAG_INT_32,
			"DNS request retransmits");
	rspamd_rcl_add_default_handler (ssub,
			"sockets",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, dns_io_per_server),
			RSPAMD_CL_FLAG_INT_32,
			"Number of sockets per DNS server");
	rspamd_rcl_add_default_handler (ssub,
			"connections",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, dns_io_per_server),
			RSPAMD_CL_FLAG_INT_32,
			"Number of sockets per DNS server");
	rspamd_rcl_add_default_handler (ssub,
			"enable_dnssec",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_config, enable_dnssec),
			0,
			"Enable DNSSEC support in Rspamd");


	/* New upstreams configuration */
	ssub = rspamd_rcl_add_section_doc (&sub->subsections, "upstream", NULL, NULL,
			UCL_OBJECT, FALSE, TRUE,
			cfg->doc_strings,
			"Upstreams configuration parameters");
	rspamd_rcl_add_default_handler (ssub,
			"max_errors",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_config, upstream_max_errors),
			RSPAMD_CL_FLAG_UINT,
			"Maximum number of errors during `error_time` to consider upstream down");
	rspamd_rcl_add_default_handler (ssub,
			"error_time",
			rspamd_rcl_parse_struct_time,
			G_STRUCT_OFFSET (struct rspamd_config, upstream_error_time),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"Time frame to check errors");
	rspamd_rcl_add_default_handler (ssub,
			"revive_time",
			rspamd_rcl_parse_struct_time,
			G_STRUCT_OFFSET (struct rspamd_config, upstream_revive_time),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"Time before attempting to recover upstream after an error");

	/**
	 * Metric section
	 */
	sub = rspamd_rcl_add_section_doc (&new,
			"metric", "name",
			rspamd_rcl_metric_handler,
			UCL_OBJECT,
			FALSE,
			TRUE,
			cfg->doc_strings,
			"Metrics configuration");
	sub->default_key = DEFAULT_METRIC;
	rspamd_rcl_add_default_handler (sub,
			"unknown_weight",
			rspamd_rcl_parse_struct_double,
			G_STRUCT_OFFSET (struct metric, unknown_weight),
			0,
			"Accept unknown symbols with the specified weight");
	rspamd_rcl_add_default_handler (sub,
			"grow_factor",
			rspamd_rcl_parse_struct_double,
			G_STRUCT_OFFSET (struct metric, grow_factor),
			0,
			"Multiply the subsequent symbols by this number "
					"(does not affect symbols with score less or "
					"equal to zero)");
	rspamd_rcl_add_default_handler (sub,
			"subject",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct metric, subject),
			0,
			"Rewrite subject with this value");

	/* Ungrouped symbols */
	ssub = rspamd_rcl_add_section_doc (&sub->subsections,
			"symbol", "name",
			rspamd_rcl_symbol_handler,
			UCL_OBJECT,
			TRUE,
			TRUE,
			sub->doc_ref,
			"Symbols settings");

	/* Actions part */
	ssub = rspamd_rcl_add_section_doc (&sub->subsections,
			"actions", NULL,
			rspamd_rcl_actions_handler,
			UCL_OBJECT,
			TRUE,
			TRUE,
			sub->doc_ref,
			"Actions settings");

	/* Group part */
	ssub = rspamd_rcl_add_section_doc (&sub->subsections,
			"group", "name",
			rspamd_rcl_group_handler,
			UCL_OBJECT,
			TRUE,
			TRUE,
			sub->doc_ref,
			"Symbol groups settings");
	rspamd_rcl_add_default_handler (ssub,
			"disabled",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_symbols_group, disabled),
			0,
			"Disable symbols group");
	rspamd_rcl_add_default_handler (ssub,
			"enabled",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_symbols_group, disabled),
			RSPAMD_CL_FLAG_BOOLEAN_INVERSE,
			"Enable or disable symbols group");
	rspamd_rcl_add_default_handler (ssub,
			"max_score",
			rspamd_rcl_parse_struct_double,
			G_STRUCT_OFFSET (struct rspamd_symbols_group, max_score),
			0,
			"Maximum score that could be reached by this symbols group");

	/* Grouped symbols */
	rspamd_rcl_add_section_doc (&ssub->subsections,
			"symbol", "name",
			rspamd_rcl_symbol_handler,
			UCL_OBJECT,
			TRUE,
			TRUE,
			ssub->doc_ref,
			"Symbols settings");

	/**
	 * Worker section
	 */
	sub = rspamd_rcl_add_section_doc (&new,
			"worker", "type",
			rspamd_rcl_worker_handler,
			UCL_OBJECT,
			FALSE,
			TRUE,
			cfg->doc_strings,
			"Workers common options");
	rspamd_rcl_add_default_handler (sub,
			"count",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_worker_conf, count),
			RSPAMD_CL_FLAG_INT_16,
			"Number of workers to spawn");
	rspamd_rcl_add_default_handler (sub,
			"max_files",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_worker_conf, rlimit_nofile),
			RSPAMD_CL_FLAG_INT_32,
			"Maximum number of opened files per worker");
	rspamd_rcl_add_default_handler (sub,
			"max_core",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_worker_conf, rlimit_maxcore),
			RSPAMD_CL_FLAG_INT_32,
			"Max size of core file in bytes");

	/**
	 * Modules handler
	 */
	sub = rspamd_rcl_add_section_doc (&new,
			"modules", NULL,
			rspamd_rcl_modules_handler,
			UCL_OBJECT,
			FALSE,
			FALSE,
			cfg->doc_strings,
			"Lua plugins to load");

	/**
	 * Classifiers handler
	 */
	sub = rspamd_rcl_add_section_doc (&new,
			"classifier", "type",
			rspamd_rcl_classifier_handler,
			UCL_OBJECT,
			FALSE,
			TRUE,
			cfg->doc_strings,
			"CLassifier options");
	/* Default classifier is 'bayes' for now */
	sub->default_key = "bayes";

	rspamd_rcl_add_default_handler (sub,
			"min_tokens",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_classifier_config, min_tokens),
			RSPAMD_CL_FLAG_INT_32,
			"Minumum count of tokens (words) to be considered for statistics");
	rspamd_rcl_add_default_handler (sub,
			"max_tokens",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_classifier_config, max_tokens),
			RSPAMD_CL_FLAG_INT_32,
			"Maximum count of tokens (words) to be considered for statistics");
	rspamd_rcl_add_default_handler (sub,
			"max_tokens",
			rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct rspamd_classifier_config, min_learns),
			RSPAMD_CL_FLAG_UINT,
			"Minimum number of learns for each statfile to use this classifier");
	rspamd_rcl_add_default_handler (sub,
			"backend",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_classifier_config, backend),
			0,
			"Statfiles engine");
	rspamd_rcl_add_default_handler (sub,
			"name",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_classifier_config, name),
			0,
			"Name of classifier");

	/*
	 * Statfile defaults
	 */
	ssub = rspamd_rcl_add_section_doc (&sub->subsections,
			"statfile", "symbol",
			rspamd_rcl_statfile_handler,
			UCL_OBJECT,
			TRUE,
			TRUE,
			sub->doc_ref,
			"Statfiles options");
	rspamd_rcl_add_default_handler (ssub,
			"label",
			rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct rspamd_statfile_config, label),
			0,
			"Statfile unique label");
	rspamd_rcl_add_default_handler (ssub,
			"spam",
			rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct rspamd_statfile_config, is_spam),
			0,
			"Sets if this statfile contains spam samples");

	/**
	 * Composites handler
	 */
	sub = rspamd_rcl_add_section_doc (&new,
			"composite", "name",
			rspamd_rcl_composite_handler,
			UCL_OBJECT,
			FALSE,
			TRUE,
			cfg->doc_strings,
			"Rspamd composite symbols");

	/**
	 * Lua handler
	 */
	sub = rspamd_rcl_add_section_doc (&new,
			"lua", NULL,
			rspamd_rcl_lua_handler,
			UCL_STRING,
			FALSE,
			TRUE,
			cfg->doc_strings,
			"Lua files to load");

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
rspamd_rcl_process_section (struct rspamd_config *cfg,
		struct rspamd_rcl_section *sec,
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
		while ((cur = ucl_object_iterate (obj, &it, true)) != NULL) {
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

		while ((cur = ucl_object_iterate (obj, &it, true)) != NULL) {
			if (!sec->handler (pool, cur, ucl_object_key (cur), ptr, sec, err)) {
				return FALSE;
			}
		}

		return TRUE;
	}
	else {
		if (sec->key_attr != NULL) {
			/* First of all search for required attribute and use it as a key */
			cur = ucl_object_lookup (obj, sec->key_attr);

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
		struct rspamd_config *cfg,
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
						if (!rspamd_rcl_process_section (cfg, cur, ptr, cur_obj,
								pool, err)) {
							return FALSE;
						}
					}
					else {
						rspamd_rcl_section_parse_defaults (cfg,
								cur,
								pool,
								cur_obj,
								ptr,
								err);
					}
				}
			}
		}
		else {
			found = ucl_object_lookup (obj, cur->name);
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
						if (!rspamd_rcl_process_section (cfg, cur, ptr, cur_obj,
								pool, err)) {
							return FALSE;
						}
					}
					else {
						rspamd_rcl_section_parse_defaults (cfg, cur,
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
rspamd_rcl_section_parse_defaults (struct rspamd_config *cfg,
		struct rspamd_rcl_section *section,
		rspamd_mempool_t *pool, const ucl_object_t *obj, gpointer ptr,
		GError **err)
{
	const ucl_object_t *found, *cur_obj;
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
		found = ucl_object_lookup (obj, cur->key);
		if (found != NULL) {
			cur->pd.user_struct = ptr;
			cur->pd.cfg = cfg;

			LL_FOREACH (found, cur_obj) {
				if (!cur->handler (pool, cur_obj, &cur->pd, section, err)) {
					return FALSE;
				}

				if (!(cur->pd.flags & RSPAMD_CL_FLAG_MULTIPLE)) {
					break;
				}
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
		rspamd_snprintf (*target, num_str_len, "%B", (gboolean)obj->value.iv);
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
	struct rspamd_cryptobox_keypair **target, *kp;

	target = (struct rspamd_cryptobox_keypair **)(((gchar *)pd->user_struct) +
			pd->offset);
	if (obj->type == UCL_OBJECT) {
		kp = rspamd_keypair_from_ucl (obj);

		if (kp != NULL) {
			*target = kp;
		}
		else {
			g_set_error (err,
					CFG_RCL_ERROR,
					EINVAL,
					"cannot load the keypair specified: %s",
					ucl_object_key (obj));
			return FALSE;
		}
	}
	else {
		g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"no sane pubkey or privkey found in the keypair: %s",
				ucl_object_key (obj));
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_pubkey (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	struct rspamd_cryptobox_pubkey **target, *pk;
	gsize len;
	const gchar *str;

	target = (struct rspamd_cryptobox_pubkey **)(((gchar *)pd->user_struct) +
			pd->offset);
	if (obj->type == UCL_STRING) {
		str = ucl_object_tolstring (obj, &len);
		pk = rspamd_pubkey_from_base32 (str, len, RSPAMD_KEYPAIR_KEX,
				RSPAMD_CRYPTOBOX_MODE_25519);

		if (pk != NULL) {
			*target = pk;
		}
		else {
			g_set_error (err,
					CFG_RCL_ERROR,
					EINVAL,
					"cannot load the pubkey specified: %s",
					ucl_object_key (obj));
			return FALSE;
		}
	}
	else {
		g_set_error (err,
				CFG_RCL_ERROR,
				EINVAL,
				"no sane pubkey found in the element: %s",
				ucl_object_key (obj));
		return FALSE;
	}

	return TRUE;
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
			rspamd_mempool_add_destructor (pool,
					(rspamd_mempool_destruct_t)g_hash_table_unref, d.hv);
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
	gboolean is_hash, need_destructor = TRUE;


	is_hash = pd->flags & RSPAMD_CL_FLAG_STRING_LIST_HASH;
	target = (gpointer *)(((gchar *)pd->user_struct) + pd->offset);

	if (!is_hash && *target != NULL) {
		need_destructor = FALSE;
	}

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
			rspamd_snprintf (val, num_str_len, "%B", (gboolean)cur->value.iv);
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

	if (!is_hash && *target != NULL) {
		*target = g_list_reverse (*target);

		if (need_destructor) {
			rspamd_mempool_add_destructor (pool,
					(rspamd_mempool_destruct_t) g_list_free,
					*target);
		}
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_ucl (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	const ucl_object_t **target;

	target = (const ucl_object_t **)(((gchar *)pd->user_struct) + pd->offset);

	*target = obj;

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_iplist (rspamd_mempool_t *pool,
		const ucl_object_t *obj,
		gpointer ud,
		struct rspamd_rcl_section *section,
		GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	radix_compressed_t **target;

	target = (radix_compressed_t **)(((gchar *)pd->user_struct) + pd->offset);

	return rspamd_config_radix_from_ucl (pd->cfg, obj,
			ucl_object_key (obj), target, err);
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

static guint
rspamd_worker_param_key_hash (gconstpointer p)
{
	const struct rspamd_worker_param_key *k = p;
	rspamd_cryptobox_fast_hash_state_t st;

	rspamd_cryptobox_fast_hash_init (&st, rspamd_hash_seed ());
	rspamd_cryptobox_fast_hash_update (&st, k->name, strlen (k->name));
	rspamd_cryptobox_fast_hash_update (&st, &k->ptr, sizeof (gpointer));

	return rspamd_cryptobox_fast_hash_final (&st);
}

static gboolean
rspamd_worker_param_key_equal (gconstpointer p1, gconstpointer p2)
{
	const struct rspamd_worker_param_key *k1 = p1, *k2 = p2;

	if (k1->ptr == k2->ptr) {
		return strcmp (k1->name, k2->name) == 0;
	}

	return FALSE;
}

void
rspamd_rcl_register_worker_option (struct rspamd_config *cfg,
		GQuark type,
		const gchar *name,
		rspamd_rcl_default_handler_t handler,
		gpointer target,
		glong offset,
		gint flags,
		const gchar *doc_string)
{
	struct rspamd_worker_param_parser *nhandler;
	struct rspamd_worker_cfg_parser *nparser;
	struct rspamd_worker_param_key srch;
	const ucl_object_t *doc_workers, *doc_target;
	ucl_object_t *doc_obj;

	nparser = g_hash_table_lookup (cfg->wrk_parsers, &type);

	if (nparser == NULL) {
		rspamd_rcl_register_worker_parser (cfg, type, NULL, NULL);
		nparser = g_hash_table_lookup (cfg->wrk_parsers, &type);

		g_assert (nparser != NULL);
	}

	srch.name = name;
	srch.ptr = target;

	nhandler = g_hash_table_lookup (nparser->parsers, &srch);
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
	nhandler->key.name = name;
	nhandler->key.ptr = target;
	nhandler->parser.flags = flags;
	nhandler->parser.offset = offset;
	nhandler->parser.user_struct = target;
	nhandler->handler = handler;

	g_hash_table_insert (nparser->parsers, &nhandler->key, nhandler);

	doc_workers = ucl_object_lookup (cfg->doc_strings, "workers");

	if (doc_workers == NULL) {
		doc_obj = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (cfg->doc_strings, doc_obj, "workers", 0, false);
		doc_workers = doc_obj;
	}

	doc_target = ucl_object_lookup (doc_workers, g_quark_to_string (type));

	if (doc_target == NULL) {
		doc_obj = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key ((ucl_object_t *)doc_workers, doc_obj,
				g_quark_to_string (type), 0, true);
		doc_target = doc_obj;
	}

	rspamd_rcl_add_doc_obj ((ucl_object_t *) doc_target,
			doc_string,
			name,
			UCL_NULL,
			handler,
			flags,
			NULL,
			0);
}


void
rspamd_rcl_register_worker_parser (struct rspamd_config *cfg, gint type,
	gboolean (*func)(ucl_object_t *, gpointer), gpointer ud)
{
	struct rspamd_worker_cfg_parser *nparser;

	nparser = g_hash_table_lookup (cfg->wrk_parsers, &type);

	if (nparser == NULL) {
		/* Allocate new parser for this worker */
		nparser =
			rspamd_mempool_alloc0 (cfg->cfg_pool,
				sizeof (struct rspamd_worker_cfg_parser));
		nparser->type = type;
		nparser->parsers = g_hash_table_new (rspamd_worker_param_key_hash,
				rspamd_worker_param_key_equal);
		rspamd_mempool_add_destructor (cfg->cfg_pool,
				(rspamd_mempool_destruct_t)g_hash_table_unref, nparser->parsers);

		g_hash_table_insert (cfg->wrk_parsers, &nparser->type, nparser);
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

	parser = ucl_parser_new (UCL_PARSER_SAVE_COMMENTS);
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
	cfg->config_comments = ucl_object_ref (ucl_parser_get_comments (parser));
	ucl_parser_free (parser);

	top = rspamd_rcl_config_init (cfg);
	rspamd_rcl_set_lua_globals (cfg, cfg->lua_state, vars);
	err = NULL;

	if (logger_fin != NULL) {
		HASH_FIND_STR (top, "logging", logger);
		if (logger != NULL) {
			logger->fin = logger_fin;
			logger->fin_ud = logger_ud;
		}
	}

	if (!rspamd_rcl_parse (top, cfg, cfg, cfg->cfg_pool, cfg->rcl_obj, &err)) {
		msg_err_config ("rcl parse error: %e", err);
		g_error_free (err);
		return FALSE;
	}

	return TRUE;
}

static void
rspamd_rcl_doc_obj_from_handler (ucl_object_t *doc_obj,
		rspamd_rcl_default_handler_t handler,
		gint flags)
{
	gboolean has_example = FALSE, has_type = FALSE;
	const gchar *type = NULL;

	if (ucl_object_lookup (doc_obj, "example") != NULL) {
		has_example = TRUE;
	}

	if (ucl_object_lookup (doc_obj, "type") != NULL) {
		has_type = TRUE;
	}

	if (handler == rspamd_rcl_parse_struct_string) {
		if (!has_type) {
			ucl_object_insert_key (doc_obj, ucl_object_fromstring ("string"),
					"type", 0, false);
		}
	}
	else if (handler == rspamd_rcl_parse_struct_integer) {
		type = "int";

		if (flags & RSPAMD_CL_FLAG_INT_16) {
			type = "int16";
		}
		else if (flags & RSPAMD_CL_FLAG_INT_32) {
			type = "int32";
		}
		else if (flags & RSPAMD_CL_FLAG_INT_64) {
			type = "int64";
		}
		else if (flags & RSPAMD_CL_FLAG_INT_SIZE) {
			type = "size";
		}
		else if (flags & RSPAMD_CL_FLAG_UINT) {
			type = "uint";
		}

		if (!has_type) {
			ucl_object_insert_key (doc_obj, ucl_object_fromstring (type),
					"type", 0, false);
		}
	}
	else if (handler == rspamd_rcl_parse_struct_double) {
		if (!has_type) {
			ucl_object_insert_key (doc_obj, ucl_object_fromstring ("double"),
					"type", 0, false);
		}
	}
	else if (handler == rspamd_rcl_parse_struct_time) {
		type = "time";

		if (!has_type) {
			ucl_object_insert_key (doc_obj, ucl_object_fromstring (type),
					"type", 0, false);
		}
	}
	else if (handler == rspamd_rcl_parse_struct_string_list) {
		if (!has_type) {
			ucl_object_insert_key (doc_obj, ucl_object_fromstring ("string list"),
					"type", 0, false);
		}
		if (!has_example) {
			ucl_object_insert_key (doc_obj,
					ucl_object_fromstring_common ("param = \"str1, str2, str3\" OR "
							"param = [\"str1\", \"str2\", \"str3\"]", 0, 0),
					"example",
					0,
					false);
		}
	}
	else if (handler == rspamd_rcl_parse_struct_boolean) {
		if (!has_type) {
			ucl_object_insert_key (doc_obj,
					ucl_object_fromstring ("bool"),
					"type",
					0,
					false);
		}
	}
	else if (handler == rspamd_rcl_parse_struct_keypair) {
		if (!has_type) {
			ucl_object_insert_key (doc_obj,
					ucl_object_fromstring ("keypair"),
					"type",
					0,
					false);
		}
		if (!has_example) {
			ucl_object_insert_key (doc_obj,
					ucl_object_fromstring ("keypair { "
							"pubkey = <base32_string>;"
							" privkey = <base32_string>; "
							"}"),
					"example",
					0,
					false);
		}
	}
	else if (handler == rspamd_rcl_parse_struct_addr) {
		if (!has_type) {
			ucl_object_insert_key (doc_obj,
					ucl_object_fromstring ("socket address"),
					"type",
					0,
					false);
		}
	}
	else if (handler == rspamd_rcl_parse_struct_mime_addr) {
		if (!has_type) {
			ucl_object_insert_key (doc_obj,
					ucl_object_fromstring ("email address"),
					"type",
					0,
					false);
		}
	}
}

ucl_object_t *
rspamd_rcl_add_doc_obj (ucl_object_t *doc_target,
		const char *doc_string,
		const char *doc_name,
		ucl_type_t type,
		rspamd_rcl_default_handler_t handler,
		gint flags,
		const char *default_value,
		gboolean required)
{
	ucl_object_t *doc_obj;

	if (doc_target == NULL || doc_name == NULL) {
		return NULL;
	}

	doc_obj = ucl_object_typed_new (UCL_OBJECT);

	/* Insert doc string itself */
	if (doc_string) {
		ucl_object_insert_key (doc_obj,
				ucl_object_fromstring_common (doc_string, 0, 0),
				"data", 0, false);
	}
	else {
		ucl_object_insert_key (doc_obj, ucl_object_fromstring ("undocumented"),
				"data", 0, false);
	}

	if (type != UCL_NULL) {
		ucl_object_insert_key (doc_obj,
				ucl_object_fromstring (ucl_object_type_to_string (type)),
				"type", 0, false);
	}

	rspamd_rcl_doc_obj_from_handler (doc_obj, handler, flags);

	ucl_object_insert_key (doc_obj,
			ucl_object_frombool (required),
			"required", 0, false);

	if (default_value) {
		ucl_object_insert_key (doc_obj,
				ucl_object_fromstring_common (default_value, 0, 0),
				"default", 0, false);
	}

	ucl_object_insert_key (doc_target, doc_obj, doc_name, 0, true);

	return doc_obj;
}

ucl_object_t *
rspamd_rcl_add_doc_by_path (struct rspamd_config *cfg,
		const gchar *doc_path,
		const char *doc_string,
		const char *doc_name,
		ucl_type_t type,
		rspamd_rcl_default_handler_t handler,
		gint flags,
		const char *default_value,
		gboolean required)
{
	const ucl_object_t *found, *cur;
	ucl_object_t *obj;
	gchar **path_components, **comp;

	if (doc_path == NULL) {
		/* Assume top object */
		return rspamd_rcl_add_doc_obj (cfg->doc_strings,
				doc_string,
				doc_name,
				type,
				handler,
				flags,
				default_value,
				required);
	}
	else {
		found = ucl_object_lookup_path (cfg->doc_strings, doc_path);

		if (found != NULL) {
			return rspamd_rcl_add_doc_obj ((ucl_object_t *) found,
					doc_string,
					doc_name,
					type,
					handler,
					flags,
					default_value,
					required);
		}

		/* Otherwise we need to insert all components of the path */
		path_components = g_strsplit_set (doc_path, ".", -1);
		cur = cfg->doc_strings;

		for (comp = path_components; *comp != NULL; comp++) {
			if (ucl_object_type (cur) != UCL_OBJECT) {
				msg_err_config ("Bad path while lookup for '%s' at %s",
						doc_path, *comp);
				return NULL;
			}

			found = ucl_object_lookup (cur, *comp);

			if (found == NULL) {
				obj = ucl_object_typed_new (UCL_OBJECT);
				ucl_object_insert_key ((ucl_object_t *) cur,
						obj,
						*comp,
						0,
						true);
				cur = obj;
			}
			else {
				cur = found;
			}
		}
	}

	return rspamd_rcl_add_doc_obj ((ucl_object_t *) cur,
			doc_string,
			doc_name,
			type,
			handler,
			flags,
			default_value,
			required);
}
