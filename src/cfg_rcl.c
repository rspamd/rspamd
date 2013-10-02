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
#include "settings.h"

/*
 * Common section handlers
 */
static gboolean
rspamd_rcl_logging_handler (struct config_file *cfg, rspamd_cl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	rspamd_cl_object_t *val;
	gchar *filepath;
	const gchar *facility, *log_type, *log_level;

	val = rspamd_cl_obj_get_key (obj, "type");
	if (val != NULL && rspamd_cl_obj_tostring_safe (val, &log_type)) {
		if (g_ascii_strcasecmp (log_type, "file") == 0) {
			/* Need to get filename */
			val = rspamd_cl_obj_get_key (obj, "filename");
			if (val == NULL || val->type != RSPAMD_CL_STRING) {
				g_set_error (err, CFG_RCL_ERROR, ENOENT, "filename attribute must be specified for file logging type");
				return FALSE;
			}
			if ((filepath = realpath (rspamd_cl_obj_tostring (val), NULL)) == NULL ||
					access (filepath, W_OK) == -1) {
				g_set_error (err, CFG_RCL_ERROR, errno, "log file is inaccessible");
				return FALSE;
			}
			cfg->log_type = RSPAMD_LOG_FILE;
			cfg->log_file = memory_pool_strdup (cfg->cfg_pool, filepath);
		}
		else if (g_ascii_strcasecmp (log_type, "syslog") == 0) {
			/* Need to get facility */
			cfg->log_facility = LOG_DAEMON;
			cfg->log_type = RSPAMD_LOG_SYSLOG;
			val = rspamd_cl_obj_get_key (obj, "facility");
			if (val != NULL && rspamd_cl_obj_tostring_safe (val, &facility)) {
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
					g_set_error (err, CFG_RCL_ERROR, EINVAL, "invalid log facility: %s", facility);
					return FALSE;
				}
			}
		}
		else if (g_ascii_strcasecmp (log_type, "stderr") == 0 || g_ascii_strcasecmp (log_type, "console") == 0) {
			cfg->log_type = RSPAMD_LOG_CONSOLE;
		}
		else {
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "invalid log type: %s", log_type);
			return FALSE;
		}
	}
	else {
		/* No type specified */
		msg_warn ("logging type is not specified correctly, log output to the console");
	}

	/* Handle log level */
	val = rspamd_cl_obj_get_key (obj, "level");
	if (val != NULL && rspamd_cl_obj_tostring_safe (val, &log_level)) {
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
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "invalid log level: %s", log_level);
			return FALSE;
		}
	}

	return rspamd_rcl_section_parse_defaults (section, cfg, obj, cfg, err);
}

static gboolean
rspamd_rcl_options_handler (struct config_file *cfg, rspamd_cl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	rspamd_cl_object_t *val;
	const gchar *user_settings, *domain_settings;

	/* Handle user and domain settings */
	val = rspamd_cl_obj_get_key (obj, "user_settings");
	if (val != NULL && rspamd_cl_obj_tostring_safe (val, &user_settings)) {
		if (!read_settings (user_settings, "Users' settings", cfg, cfg->user_settings)) {
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot read settings: %s", user_settings);
			return FALSE;
		}
		cfg->user_settings_str = memory_pool_strdup (cfg->cfg_pool, user_settings);
	}

	val = rspamd_cl_obj_get_key (obj, "domain_settings");
	if (val != NULL && rspamd_cl_obj_tostring_safe (val, &domain_settings)) {
		if (!read_settings (domain_settings, "Domains settings", cfg, cfg->domain_settings)) {
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot read settings: %s", domain_settings);
			return FALSE;
		}
		cfg->domain_settings_str = memory_pool_strdup (cfg->cfg_pool, domain_settings);
	}

	return rspamd_rcl_section_parse_defaults (section, cfg, obj, cfg, err);
}

static gint
rspamd_symbols_group_find_func (gconstpointer a, gconstpointer b)
{
	const struct symbols_group		*gr = a;
	const gchar						*uv = b;

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
rspamd_rcl_insert_symbol (struct config_file *cfg, struct metric *metric,
		rspamd_cl_object_t *obj, GError **err)
{
	const gchar *group = "ungrouped", *description = NULL;
	gdouble symbol_score, *score_ptr;
	rspamd_cl_object_t *val;
	struct symbols_group *sym_group;
	struct symbol_def *sym_def;
	GList *metric_list, *group_list;

	/*
	 * We allow two type of definitions:
	 * symbol = weight
	 * or
	 * symbol {
	 *	weight = ...;
	 *	description = ...;
	 *	group = ...;
	 * }
	 */
	if (rspamd_cl_obj_todouble_safe (obj, &symbol_score)) {
		description = NULL;
	}
	else if (obj->type == RSPAMD_CL_OBJECT) {
		val = rspamd_cl_obj_get_key (obj, "score");
		if (val == NULL || !rspamd_cl_obj_todouble_safe (val, &symbol_score)) {
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "invalid symbol score: %s", obj->key);
			return FALSE;
		}
		val = rspamd_cl_obj_get_key (obj, "description");
		if (val != NULL) {
			description = rspamd_cl_obj_tostring (val);
		}
		val = rspamd_cl_obj_get_key (obj, "group");
		if (val != NULL) {
			rspamd_cl_obj_tostring_safe (val, &group);
		}
	}
	else {
		g_set_error (err, CFG_RCL_ERROR, EINVAL, "invalid symbol type: %s", obj->key);
		return FALSE;
	}

	sym_def = memory_pool_alloc (cfg->cfg_pool, sizeof (struct symbol_def));
	score_ptr = memory_pool_alloc (cfg->cfg_pool, sizeof (gdouble));

	*score_ptr = symbol_score;
	sym_def->weight_ptr = score_ptr;
	sym_def->name = memory_pool_strdup (cfg->cfg_pool, obj->key);
	sym_def->description = (gchar *)description;

	g_hash_table_insert (metric->symbols, sym_def->name, score_ptr);

	if ((metric_list = g_hash_table_lookup (cfg->metrics_symbols, sym_def->name)) == NULL) {
		metric_list = g_list_prepend (NULL, metric);
		memory_pool_add_destructor (cfg->cfg_pool, (pool_destruct_func)g_list_free, metric_list);
		g_hash_table_insert (cfg->metrics_symbols, sym_def->name, metric_list);
	}
	else {
		/* Slow but keep start element of list in safe */
		if (!g_list_find (metric_list, metric)) {
			metric_list = g_list_append (metric_list, metric);
		}
	}

	/* Search for symbol group */
	group_list = g_list_find_custom (cfg->symbols_groups, group, rspamd_symbols_group_find_func);
	if (group_list == NULL) {
		/* Create new group */
		sym_group = memory_pool_alloc (cfg->cfg_pool, sizeof (struct symbols_group));
		sym_group->name = memory_pool_strdup (cfg->cfg_pool, group);
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
rspamd_rcl_metric_handler (struct config_file *cfg, rspamd_cl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	rspamd_cl_object_t *val, *cur, *tmp;
	const gchar *metric_name, *subject_name;
	struct metric *metric;
	struct metric_action *action;
	gdouble action_score, grow_factor;
	gint action_value;
	gboolean new = TRUE;

	val = rspamd_cl_obj_get_key (obj, "name");
	if (val == NULL || !rspamd_cl_obj_tostring_safe (val, &metric_name)) {
		metric_name = DEFAULT_METRIC;
	}

	metric = g_hash_table_lookup (cfg->metrics, metric_name);
	if (metric == NULL) {
		metric = check_metric_conf (cfg, metric);
	}
	else {
		new = FALSE;
	}

	/* Handle actions */
	val = rspamd_cl_obj_get_key (obj, "actions");
	if (val != NULL) {
		if (val->type != RSPAMD_CL_OBJECT) {
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "actions must be an object");
			return FALSE;
		}
		HASH_ITER (hh, val, cur, tmp) {
			if (!check_action_str (cur->key, &action_value) ||
					!rspamd_cl_obj_todouble_safe (cur, &action_score)) {
				g_set_error (err, CFG_RCL_ERROR, EINVAL, "invalid action definition: %s", cur->key);
				return FALSE;
			}
			action = &metric->actions[action_value];
			action->action = action_value;
			action->score = action_score;
		}
	}
	else if (new) {
		g_set_error (err, CFG_RCL_ERROR, EINVAL, "metric %s has no actions", metric_name);
		return FALSE;
	}

	/* Handle symbols */
	val = rspamd_cl_obj_get_key (obj, "symbols");
	if (val != NULL) {
		if (val->type == RSPAMD_CL_ARRAY) {
			val = val->value.ov;
		}
		if (val->type != RSPAMD_CL_OBJECT) {
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "symbols must be an object");
			return FALSE;
		}
		HASH_ITER (hh, val, cur, tmp) {
			if (!rspamd_rcl_insert_symbol (cfg, metric, cur, err)) {
				return FALSE;
			}
		}
	}

	val = rspamd_cl_obj_get_key (obj, "grow_factor");
	if (val && rspamd_cl_obj_todouble_safe (val, &grow_factor)) {
		metric->grow_factor = grow_factor;
	}

	val = rspamd_cl_obj_get_key (obj, "subject");
	if (val && rspamd_cl_obj_tostring_safe (val, &subject_name)) {
		metric->subject = (gchar *)subject_name;
	}

	/* Insert the resulting metric */
	g_hash_table_insert (cfg->metrics, metric->name, metric);
	cfg->metrics_list = g_list_prepend (cfg->metrics_list, metric);

	return TRUE;
}

static gboolean
rspamd_rcl_worker_handler (struct config_file *cfg, rspamd_cl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	rspamd_cl_object_t *val, *cur, *tmp;
	const gchar *worker_type, *worker_bind;
	GQuark qtype;
	struct worker_conf *wrk;
	struct rspamd_worker_bind_conf *bcf;
	struct rspamd_worker_cfg_parser *wparser;
	struct rspamd_worker_param_parser *whandler;

	val = rspamd_cl_obj_get_key (obj, "type");
	if (val != NULL && rspamd_cl_obj_tostring_safe (val, &worker_type)) {
		qtype = g_quark_try_string (worker_type);
		if (qtype != 0) {
			wrk = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct worker_conf));
			wrk->worker = get_worker_by_type (qtype);
			if (wrk->worker == NULL) {
				g_set_error (err, CFG_RCL_ERROR, EINVAL, "unknown worker type: %s", worker_type);
				return FALSE;
			}
			wrk->type = qtype;
			if (wrk->worker->worker_init_func) {
				wrk->ctx = wrk->worker->worker_init_func (cfg);
			}
		}
		else {
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "unknown worker type: %s", worker_type);
			return FALSE;
		}
	}
	else {
		g_set_error (err, CFG_RCL_ERROR, EINVAL, "undefined worker type");
		return FALSE;
	}

	val = rspamd_cl_obj_get_key (obj, "bind_socket");
	if (val != NULL) {
		if (val->type == RSPAMD_CL_ARRAY) {
			val = val->value.ov;
		}
		LL_FOREACH (val, cur) {
			if (!rspamd_cl_obj_tostring_safe (cur, &worker_bind)) {
				continue;
			}
			bcf = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct rspamd_worker_bind_conf));
			if (!parse_host_port_priority (cfg->cfg_pool, worker_bind, &bcf->bind_host,
					&bcf->bind_port, NULL)) {
				g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot parse bind line: %s", worker_bind);
				return FALSE;
			}
			LL_PREPEND (wrk->bind_conf, bcf);
		}
	}

	wrk->options = obj;

	if (!rspamd_rcl_section_parse_defaults (section, cfg, obj, wrk, err)) {
		return FALSE;
	}

	/* Parse other attributes */
	HASH_FIND_INT (cfg->wrk_parsers, (gint *)&qtype, wparser);
	if (wparser != NULL && obj->type == RSPAMD_CL_OBJECT) {
		HASH_ITER (hh, obj->value.ov, cur, tmp) {
			HASH_FIND_STR (wparser->parsers, cur->key, whandler);
			if (whandler != NULL) {
				if (!whandler->handler (cfg, cur, &whandler->parser, section, err)) {
					return FALSE;
				}
			}
		}
	}

	cfg->workers = g_list_prepend (cfg->workers, wrk);

	return TRUE;
}

/**
 * Fake handler to parse default options only, uses struct cfg_file as pointer
 * for default handlers
 */
static gboolean
rspamd_rcl_empty_handler (struct config_file *cfg, rspamd_cl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	return rspamd_rcl_section_parse_defaults (section, cfg, obj, cfg, err);
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
static inline struct rspamd_rcl_section*
rspamd_rcl_add_section (struct rspamd_rcl_section *top,
		const gchar *name, rspamd_rcl_handler_t handler,
		enum rspamd_cl_type type, gboolean required, gboolean strict_type)
{
	struct rspamd_rcl_section *new;

	new = g_slice_alloc0 (sizeof (struct rspamd_rcl_section));
	new->name = name;
	new->handler = handler;
	new->type = type;
	new->strict_type = strict_type;

	HASH_ADD_KEYPTR (hh, top, new->name, strlen (new->name), new);
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
rspamd_rcl_add_default_handler (struct rspamd_rcl_section *section, const gchar *name,
		rspamd_rcl_handler_t handler, gsize offset, gint flags)
{
	struct rspamd_rcl_default_handler_data *new;

	new = g_slice_alloc0 (sizeof (struct rspamd_rcl_default_handler_data));
	new->key = name;
	new->handler = handler;
	new->pd.offset = offset;
	new->pd.flags = flags;

	HASH_ADD_KEYPTR (hh, section->default_parser, new->key, strlen (new->key), new);
	return new;
}

struct rspamd_rcl_section*
rspamd_rcl_config_init (void)
{
	struct rspamd_rcl_section *new, *sub;

	new = g_slice_alloc0 (sizeof (struct rspamd_rcl_section));

	/* TODO: add all known rspamd sections here */
	/**
	 * Logging section
	 */
	sub = rspamd_rcl_add_section (new, "logging", rspamd_rcl_logging_handler, RSPAMD_CL_OBJECT,
			FALSE, TRUE);
	/* Default handlers */
	rspamd_rcl_add_default_handler (sub, "log_buffer", rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct config_file, log_buf_size), 0);
	rspamd_rcl_add_default_handler (sub, "log_urls", rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct config_file, log_urls), 0);
	rspamd_rcl_add_default_handler (sub, "debug_ip", rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct config_file, debug_ip_map), 0);
	rspamd_rcl_add_default_handler (sub, "debug_symbols", rspamd_rcl_parse_struct_string_list,
			G_STRUCT_OFFSET (struct config_file, debug_symbols), 0);
	rspamd_rcl_add_default_handler (sub, "log_color", rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct config_file, log_color), 0);
	/**
	 * Options section
	 */
	sub = rspamd_rcl_add_section (new, "options", rspamd_rcl_options_handler, RSPAMD_CL_OBJECT,
			FALSE, TRUE);
	rspamd_rcl_add_default_handler (sub, "statfile_pool_size", rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct config_file, max_statfile_size), RSPAMD_CL_FLAG_INT_SIZE);
	rspamd_rcl_add_default_handler (sub, "cache_file", rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct config_file, cache_filename), 0);
	rspamd_rcl_add_default_handler (sub, "dns_nameserver", rspamd_rcl_parse_struct_string_list,
			G_STRUCT_OFFSET (struct config_file, nameservers), 0);
	rspamd_rcl_add_default_handler (sub, "dns_timeout", rspamd_rcl_parse_struct_time,
			G_STRUCT_OFFSET (struct config_file, dns_timeout), RSPAMD_CL_FLAG_TIME_INTEGER);
	rspamd_rcl_add_default_handler (sub, "dns_retransmits", rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct config_file, dns_retransmits), RSPAMD_CL_FLAG_INT_32);
	rspamd_rcl_add_default_handler (sub, "raw_mode", rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct config_file, raw_mode), 0);
	rspamd_rcl_add_default_handler (sub, "one_shot", rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct config_file, one_shot_mode), 0);
	rspamd_rcl_add_default_handler (sub, "check_attachements", rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct config_file, check_text_attachements), 0);
	rspamd_rcl_add_default_handler (sub, "tempdir", rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct config_file, temp_dir), 0);
	rspamd_rcl_add_default_handler (sub, "pidfile", rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct config_file, pid_file), 0);
	rspamd_rcl_add_default_handler (sub, "filters", rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct config_file, filters_str), 0);
	rspamd_rcl_add_default_handler (sub, "sync_interval", rspamd_rcl_parse_struct_time,
			G_STRUCT_OFFSET (struct config_file, statfile_sync_interval), RSPAMD_CL_FLAG_TIME_INTEGER);
	rspamd_rcl_add_default_handler (sub, "sync_timeout", rspamd_rcl_parse_struct_time,
			G_STRUCT_OFFSET (struct config_file, statfile_sync_timeout), RSPAMD_CL_FLAG_TIME_INTEGER);
	rspamd_rcl_add_default_handler (sub, "max_diff", rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct config_file, max_diff), RSPAMD_CL_FLAG_INT_SIZE);
	rspamd_rcl_add_default_handler (sub, "map_watch_interval", rspamd_rcl_parse_struct_time,
			G_STRUCT_OFFSET (struct config_file, map_timeout), RSPAMD_CL_FLAG_TIME_FLOAT);
	rspamd_rcl_add_default_handler (sub, "dynamic_conf", rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct config_file, dynamic_conf), 0);
	rspamd_rcl_add_default_handler (sub, "rrd", rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct config_file, rrd_file), 0);
	rspamd_rcl_add_default_handler (sub, "history_file", rspamd_rcl_parse_struct_string,
			G_STRUCT_OFFSET (struct config_file, history_file), 0);
	rspamd_rcl_add_default_handler (sub, "use_mlock", rspamd_rcl_parse_struct_boolean,
			G_STRUCT_OFFSET (struct config_file, mlock_statfile_pool), 0);

	/**
	 * Metric section
	 */
	sub = rspamd_rcl_add_section (new, "metric", rspamd_rcl_metric_handler, RSPAMD_CL_OBJECT,
			FALSE, TRUE);

	/**
	 * Worker section
	 */
	sub = rspamd_rcl_add_section (new, "worker", rspamd_rcl_worker_handler, RSPAMD_CL_OBJECT,
			FALSE, TRUE);
	rspamd_rcl_add_default_handler (sub, "count", rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct worker_conf, count), RSPAMD_CL_FLAG_INT_16);
	rspamd_rcl_add_default_handler (sub, "max_files", rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct worker_conf, rlimit_nofile), RSPAMD_CL_FLAG_INT_32);
	rspamd_rcl_add_default_handler (sub, "max_core", rspamd_rcl_parse_struct_integer,
			G_STRUCT_OFFSET (struct worker_conf, rlimit_maxcore), RSPAMD_CL_FLAG_INT_32);

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
	for (i = 0; i < ncomponents; i ++) {
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
		struct config_file *cfg, rspamd_cl_object_t *obj, GError **err)
{
	rspamd_cl_object_t *found;
	struct rspamd_rcl_section *cur, *tmp;

	if (obj->type != RSPAMD_CL_OBJECT) {
		g_set_error (err, CFG_RCL_ERROR, EINVAL, "top configuration must be an object");
		return FALSE;
	}

	/* Iterate over known sections and ignore unknown ones */
	HASH_ITER (hh, top, cur, tmp) {
		found = rspamd_cl_obj_get_key (obj, cur->name);
		if (found == NULL) {
			if (cur->required) {
				g_set_error (err, CFG_RCL_ERROR, ENOENT, "required section %s is missing", cur->name);
				return FALSE;
			}
		}
		else {
			/* Check type */
			if (cur->strict_type) {
				if (cur->type != found->type) {
					g_set_error (err, CFG_RCL_ERROR, EINVAL, "object in section %s has invalid type", cur->name);
					return FALSE;
				}
			}
			if (!cur->handler (cfg, found, NULL, cur, err)) {
				return FALSE;
			}
		}
	}

	cfg->rcl_obj = obj;

	return TRUE;
}

gboolean rspamd_rcl_section_parse_defaults (struct rspamd_rcl_section *section,
		struct config_file *cfg, rspamd_cl_object_t *obj, gpointer ptr,
		GError **err)
{
	rspamd_cl_object_t *found;
	struct rspamd_rcl_default_handler_data *cur, *tmp;

	if (obj->type != RSPAMD_CL_OBJECT) {
		g_set_error (err, CFG_RCL_ERROR, EINVAL, "default configuration must be an object");
		return FALSE;
	}

	HASH_ITER (hh, section->default_parser, cur, tmp) {
		found = rspamd_cl_obj_get_key (obj, cur->key);
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
rspamd_rcl_parse_struct_string (struct config_file *cfg, rspamd_cl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	gchar **target;
	const gsize num_str_len = 32;

	target = (gchar **)(((gchar *)pd->user_struct) + pd->offset);
	switch (obj->type) {
	case RSPAMD_CL_STRING:
		/* Direct assigning is safe, as object is likely linked to the cfg mem_pool */
		*target = obj->value.sv;
		break;
	case RSPAMD_CL_INT:
		*target = memory_pool_alloc (cfg->cfg_pool, num_str_len);
		rspamd_snprintf (*target, num_str_len, "%L", obj->value.iv);
		break;
	case RSPAMD_CL_FLOAT:
		*target = memory_pool_alloc (cfg->cfg_pool, num_str_len);
		rspamd_snprintf (*target, num_str_len, "%f", obj->value.dv);
		break;
	case RSPAMD_CL_BOOLEAN:
		*target = memory_pool_alloc (cfg->cfg_pool, num_str_len);
		rspamd_snprintf (*target, num_str_len, "%b", (gboolean)obj->value.iv);
		break;
	default:
		g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot convert object or array to string");
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_integer (struct config_file *cfg, rspamd_cl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	union {
		gint *ip;
		gint32 *i32p;
		gint16 *i16p;
		gint64 *i64p;
		gsize *sp;
	} target;
	gint64 val;

	if (pd->flags == RSPAMD_CL_FLAG_INT_32) {
		target.i32p = (gint32 *)(((gchar *)pd->user_struct) + pd->offset);
		if (!rspamd_cl_obj_toint_safe (obj, &val)) {
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot convert param to integer");
			return FALSE;
		}
		*target.i32p = val;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_INT_64) {
		target.i64p = (gint64 *)(((gchar *)pd->user_struct) + pd->offset);
		if (!rspamd_cl_obj_toint_safe (obj, &val)) {
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot convert param to integer");
			return FALSE;
		}
		*target.i64p = val;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_INT_SIZE) {
		target.sp = (gsize *)(((gchar *)pd->user_struct) + pd->offset);
		if (!rspamd_cl_obj_toint_safe (obj, &val)) {
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot convert param to integer");
			return FALSE;
		}
		*target.sp = val;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_INT_16) {
		target.i16p = (gint16 *)(((gchar *)pd->user_struct) + pd->offset);
		if (!rspamd_cl_obj_toint_safe (obj, &val)) {
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot convert param to integer");
			return FALSE;
		}
		*target.i16p = val;
	}
	else {
		target.ip = (gint *)(((gchar *)pd->user_struct) + pd->offset);
		if (!rspamd_cl_obj_toint_safe (obj, &val)) {
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot convert param to integer");
			return FALSE;
		}
		*target.ip = val;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_double (struct config_file *cfg, rspamd_cl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	gdouble *target;

	target = (gdouble *)(((gchar *)pd->user_struct) + pd->offset);

	if (!rspamd_cl_obj_todouble_safe (obj, target)) {
		g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot convert param to double");
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_time (struct config_file *cfg, rspamd_cl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err)
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

	if (!rspamd_cl_obj_todouble_safe (obj, &val)) {
		g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot convert param to double");
		return FALSE;
	}

	if (pd->flags == RSPAMD_CL_FLAG_TIME_TIMEVAL) {
		target.ptv = (struct timeval *)(((gchar *)pd->user_struct) + pd->offset);
		target.ptv->tv_sec = (glong)val;
		target.ptv->tv_usec = (val - (glong)val) * 1000000;
	}
	else if (pd->flags == RSPAMD_CL_FLAG_TIME_TIMESPEC) {
		target.pts = (struct timespec *)(((gchar *)pd->user_struct) + pd->offset);
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
		g_set_error (err, CFG_RCL_ERROR, EINVAL, "invalid flags to parse time value");
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_string_list (struct config_file *cfg, rspamd_cl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	GList **target;
	gchar *val;
	rspamd_cl_object_t *cur;
	const gsize num_str_len = 32;

	target = (GList **)(((gchar *)pd->user_struct) + pd->offset);

	if (obj->type != RSPAMD_CL_ARRAY) {
		g_set_error (err, CFG_RCL_ERROR, EINVAL, "an array of strings is expected");
		return FALSE;
	}

	for (cur = obj; cur != NULL; cur = cur->next) {
		switch (cur->type) {
		case RSPAMD_CL_STRING:
			/* Direct assigning is safe, as curect is likely linked to the cfg mem_pool */
			val = cur->value.sv;
			break;
		case RSPAMD_CL_INT:
			val = memory_pool_alloc (cfg->cfg_pool, num_str_len);
			rspamd_snprintf (val, num_str_len, "%L", cur->value.iv);
			break;
		case RSPAMD_CL_FLOAT:
			val = memory_pool_alloc (cfg->cfg_pool, num_str_len);
			rspamd_snprintf (val, num_str_len, "%f", cur->value.dv);
			break;
		case RSPAMD_CL_BOOLEAN:
			val = memory_pool_alloc (cfg->cfg_pool, num_str_len);
			rspamd_snprintf (val, num_str_len, "%b", (gboolean)cur->value.iv);
			break;
		default:
			g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot convert an object or array to string");
			return FALSE;
		}
		*target = g_list_prepend (*target, val);
	}

	/* Add a destructor */
	memory_pool_add_destructor (cfg->cfg_pool, (pool_destruct_func)g_list_free, *target);

	return TRUE;
}

gboolean
rspamd_rcl_parse_struct_boolean (struct config_file *cfg, rspamd_cl_object_t *obj,
		gpointer ud, struct rspamd_rcl_section *section, GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	gboolean *target;

	target = (gboolean *)(((gchar *)pd->user_struct) + pd->offset);

	if (obj->type == RSPAMD_CL_BOOLEAN) {
		*target = obj->value.iv;
	}
	else if (obj->type == RSPAMD_CL_INT) {
		*target = obj->value.iv;
	}
	else {
		g_set_error (err, CFG_RCL_ERROR, EINVAL, "cannot convert an object to boolean");
		return FALSE;
	}

	return TRUE;
}

void
rspamd_rcl_register_worker_option (struct config_file *cfg, gint type, const gchar *name,
		rspamd_rcl_handler_t handler, gpointer target, gsize offset, gint flags)
{
	struct rspamd_worker_param_parser *nhandler;
	struct rspamd_worker_cfg_parser *nparser;

	HASH_FIND_INT (cfg->wrk_parsers, &type, nparser);
	if (nparser == NULL) {
		/* Allocate new parser for this worker */
		nparser = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct rspamd_worker_cfg_parser));
		nparser->type = type;
		HASH_ADD_INT (cfg->wrk_parsers, type, nparser);
	}

	HASH_FIND_STR (nparser->parsers, name, nhandler);
	if (nhandler != NULL) {
		msg_warn ("handler for parameter %s is already registered for worker type %s",
				name, g_quark_to_string (type));
		return;
	}
	nhandler = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct rspamd_worker_param_parser));
	nhandler->name = name;
	nhandler->parser.flags = flags;
	nhandler->parser.offset = offset;
	nhandler->parser.user_struct = target;
	nhandler->handler = handler;
	HASH_ADD_STR (nparser->parsers, name, nhandler);
}
