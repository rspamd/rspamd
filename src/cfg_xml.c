/*
 * Copyright (c) 2009, Rambler media
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Read and write rspamd dynamic parameters from xml files
 */

#include "config.h"
#include "cfg_xml.h"
#include "main.h"
#include "logger.h"
#include "util.h"
#include "classifiers/classifiers.h"
#include "tokenizers/tokenizers.h"
#include "lua/lua_common.h"
#include "view.h"
#include "map.h"
#include "expressions.h"
#include "settings.h"

/* Maximum attributes for param */
#define MAX_PARAM 64

#define EOL "\n"

#define NULL_ATTR 	\
{					\
	NULL,			\
	NULL,			\
	0,				\
	NULL			\
}					\

#define NULL_DEF_ATTR 	\
{					\
	NULL,			\
	0,				\
	NULL			\
}					\

enum xml_config_section {
	XML_SECTION_MAIN,
    XML_SECTION_LOGGING, 
	XML_SECTION_WORKER,
	XML_SECTION_METRIC,
	XML_SECTION_CLASSIFIER,
	XML_SECTION_STATFILE,
	XML_SECTION_MODULE,
	XML_SECTION_MODULES,
	XML_SECTION_VIEW
};

struct xml_config_param {
	const gchar 		   *name;
	element_handler_func 	handler;
	gint 					offset;
	gpointer 				user_data;
};

struct xml_default_config_param {
	element_default_handler_func 	handler;
	gint 					offset;
	gpointer 				user_data;
};

struct xml_parser_rule {
	enum xml_config_section section;
	struct xml_config_param params[MAX_PARAM];
	struct xml_default_config_param default_param;
};

/* Here we describes our basic grammar */
static struct xml_parser_rule grammar[] = {
	{ XML_SECTION_MAIN, {
			{
				"pidfile",
				xml_handle_string,
				G_STRUCT_OFFSET (struct config_file, pid_file),
				NULL
			},
            {
				"lua",
				handle_lua,
				0,
				NULL
            },
			{
				"raw_mode",
				xml_handle_boolean,
				G_STRUCT_OFFSET (struct config_file, raw_mode),
				NULL
			},
			{
				"tempdir",
				xml_handle_string,
				G_STRUCT_OFFSET (struct config_file, temp_dir),
				NULL
			},
			{
				"checksum",
				xml_handle_string,
				G_STRUCT_OFFSET (struct config_file, dump_checksum),
				NULL
			},
			{
				"statfile_pool_size",
				xml_handle_size,
				G_STRUCT_OFFSET (struct config_file, max_statfile_size),
				NULL
			},
			{
				"filters",
				xml_handle_string,
				G_STRUCT_OFFSET (struct config_file, filters_str),
				NULL
			},
			{
				"variable",
				handle_variable,
				0,
				NULL
			},
			{
				"composite",
				handle_composite,
				0,
				NULL
			},
			{
				"user_settings",
				handle_user_settings,
				0,
				NULL
			},
			{
				"domain_settings",
				handle_domain_settings,
				0,
				NULL
			},
			{
				"cache_file",
				xml_handle_string,
				G_STRUCT_OFFSET (struct config_file, cache_filename),
				NULL
			},
			{
				"dns_timeout",
				xml_handle_seconds,
				G_STRUCT_OFFSET (struct config_file, dns_timeout),
				NULL
			},
			{
				"dns_retransmits",
				xml_handle_uint32,
				G_STRUCT_OFFSET (struct config_file, dns_retransmits),
				NULL
			},
			NULL_ATTR
		},
		NULL_DEF_ATTR
	},
	{ XML_SECTION_LOGGING, {
			{
				"type",
				handle_log_type,
				0,
				NULL
			},
			{
				"level",
				handle_log_level,
				0,
				NULL
			},
			{
				"log_urls",
				xml_handle_boolean,
				G_STRUCT_OFFSET (struct config_file, log_urls),
				NULL
			},
			{
				"log_buffer",
				xml_handle_uint32,
				G_STRUCT_OFFSET (struct config_file, log_buf_size),
				NULL
			},
			{
				"debug_ip",
				xml_handle_string,
				G_STRUCT_OFFSET (struct config_file, debug_ip_map),
				NULL
			},
			{
				"debug_symbols",
				xml_handle_string_list,
				G_STRUCT_OFFSET (struct config_file, debug_symbols),
				NULL
			},
			{
				"log_color",
				xml_handle_boolean,
				G_STRUCT_OFFSET (struct config_file, log_color),
				NULL
			},
			NULL_ATTR
		},
		NULL_DEF_ATTR
	},
	{ XML_SECTION_WORKER, {
			{
				"type",
				worker_handle_type,
				0,
				NULL
			},
			{
				"bind_socket",
				worker_handle_bind,
				0,
				NULL
			},
			{
				"count",
				xml_handle_uint16,
				G_STRUCT_OFFSET (struct worker_conf, count),
				NULL
			},
			{
				"maxfiles",
				xml_handle_uint32,
				G_STRUCT_OFFSET (struct worker_conf, rlimit_nofile),
				NULL
			},
			{
				"maxcore",
				xml_handle_uint32,
				G_STRUCT_OFFSET (struct worker_conf, rlimit_maxcore),
				NULL
			},
			NULL_ATTR
		},
		{
			worker_handle_param,
			0,
			NULL
		}
	},
	{ XML_SECTION_METRIC, {
			{
				"name",
				xml_handle_string,
				G_STRUCT_OFFSET (struct metric, name),
				NULL
			},
			{
				"grow_factor",
				xml_handle_double,
				G_STRUCT_OFFSET (struct metric, grow_factor),
				NULL
			},
			{
				"required_score",
				xml_handle_double,
				G_STRUCT_OFFSET (struct metric, required_score),
				NULL
			},
			{
				"reject_score",
				xml_handle_double,
				G_STRUCT_OFFSET (struct metric, reject_score),
				NULL
			},
			{
				"symbol",
				handle_metric_symbol,
				0,
				NULL
			},
			{
				"action",
				handle_metric_action,
				0,
				NULL
			},
			NULL_ATTR
		},
		NULL_DEF_ATTR
	},
	{ XML_SECTION_CLASSIFIER, {
			{
				"metric",
				xml_handle_string,
				G_STRUCT_OFFSET (struct classifier_config, metric),
				NULL
			},
			{
				"tokenizer",
				handle_classifier_tokenizer,
				0,
				NULL
			},
			NULL_ATTR
		},
		{
			handle_classifier_opt,
			0,
			NULL
		}
	},
	{ XML_SECTION_STATFILE, {
			{
				"symbol",
				xml_handle_string,
				G_STRUCT_OFFSET (struct statfile, symbol),
				NULL
			},
			{
				"path",
				xml_handle_string,
				G_STRUCT_OFFSET (struct statfile, path),
				NULL
			},
			{
				"size",
				xml_handle_size,
				G_STRUCT_OFFSET (struct statfile, size),
				NULL
			},
			{
				"normalizer",
				handle_statfile_normalizer,
				0,
				NULL
			},
			{
				"binlog",
				handle_statfile_binlog,
				0,
				NULL
			},
			{
				"binlog_rotate",
				handle_statfile_binlog_rotate,
				0,
				NULL
			},
			{
				"binlog_master",
				handle_statfile_binlog_master,
				0,
				NULL
			},
			NULL_ATTR
		},
		NULL_DEF_ATTR
	},
	{ XML_SECTION_MODULE, {
			NULL_ATTR
		},
		{
			handle_module_opt,
			0,
			NULL
		}
	},
	{ XML_SECTION_MODULES, {
			{
				"path",
				handle_module_path,
				0,
				NULL
			},
			NULL_ATTR
		},
		NULL_DEF_ATTR
	},
	{ XML_SECTION_VIEW, {
			{
				"skip_check",
				xml_handle_boolean,
				G_STRUCT_OFFSET (struct rspamd_view, skip_check),
				NULL
			},
			{
				"ip",
				handle_view_ip,
				0,
				NULL
			},
			{
				"client_ip",
				handle_view_client_ip,
				0,
				NULL
			},
			{
				"from",
				handle_view_from,
				0,
				NULL
			},
			{
				"rcpt",
				handle_view_rcpt,
				0,
				NULL
			},
			{
				"symbols",
				handle_view_symbols,
				0,
				NULL
			},
			NULL_ATTR
		},
		NULL_DEF_ATTR
	},
};

GHashTable *module_options = NULL,
		   *worker_options = NULL,
		   *classifier_options = NULL;

GQuark
xml_error_quark (void)
{
	return g_quark_from_static_string ("xml-error-quark");
}

static inline const gchar *
xml_state_to_string (struct rspamd_xml_userdata *ud)
{
	switch (ud->state) {
		case XML_READ_START:
			return "read start tag";
		case XML_READ_PARAM:
			return "read param";
		case XML_READ_MODULE:
			return "read module section";
		case XML_READ_MODULES:
			return "read modules section";
		case XML_READ_CLASSIFIER:
			return "read classifier section";
		case XML_READ_STATFILE:
			return "read statfile section";
		case XML_READ_METRIC:
			return "read metric section";
		case XML_READ_WORKER:
			return "read worker section";
		case XML_READ_VIEW:
			return "read view section";
		case XML_READ_LOGGING:
			return "read logging section";
		case XML_READ_VALUE:
			return "read value";
		case XML_SKIP_ELEMENTS:
			return "skip if block";
		case XML_ERROR:
			return "error occured";
		case XML_END:
			return "read final tag";
	}
	/* Unreached */
	return "unknown state";
}

static inline gboolean
extract_attr (const gchar *attr, const gchar **attribute_names, const gchar **attribute_values, gchar **res) 
{
	const gchar **cur_attr, **cur_value;

	cur_attr = attribute_names;
	cur_value = attribute_values;

	while (*cur_attr && *cur_value) {
		if (g_ascii_strcasecmp (*cur_attr, attr) == 0) {
			*res = (gchar *) *cur_value;
			return TRUE;
		}
		cur_attr ++;
		cur_value ++;
	}

	return FALSE;
}

static inline gchar*
xml_asciiz_string (memory_pool_t *pool, const gchar *text, gsize len)
{
	gchar                           *val;

	val = memory_pool_alloc (pool, len + 1);
	rspamd_strlcpy (val, text, len + 1);

	return val;
}

/* Find among attributes required ones and form new array of pairs attribute-value */
static GHashTable *
process_attrs (struct config_file *cfg, const gchar **attribute_names, const gchar **attribute_values)
{
	const gchar                         **attr, **value;
	GHashTable                     *res;

	if (*attribute_names == NULL) {
		/* No attributes required */
		return NULL;
	}

	res = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);

	attr = attribute_names;
	value = attribute_values;
	while (*attr) {
		/* Copy attributes to pool */
		g_hash_table_insert (res, memory_pool_strdup (cfg->cfg_pool, *attr), memory_pool_strdup (cfg->cfg_pool, *value));
		attr ++;
		value ++;
	}

	memory_pool_add_destructor (cfg->cfg_pool, (pool_destruct_func)g_hash_table_destroy, res);

	return res;
}

static gboolean
call_param_handler (struct rspamd_xml_userdata *ctx, const gchar *name, gchar *value, gpointer dest_struct, enum xml_config_section section)
{
	struct xml_parser_rule         *rule;
	struct xml_config_param        *param;
	gint                            i;
	
	/* First find required section */
	for (i = 0; i < G_N_ELEMENTS (grammar); i ++) {
		rule = &grammar[i];
		if (rule->section == section) {
			/* Now find attribute in section or call default handler */
			param = &rule->params[0];
			while (param && param->handler) {
				if (param->name && g_ascii_strcasecmp (param->name, name) == 0) {
					/* Call specified handler */
					return param->handler (ctx->cfg, ctx, ctx->cur_attrs, value, param->user_data, dest_struct, param->offset);
				}
				param ++;
			}
			if (rule->default_param.handler != NULL) {
				/* Call default handler */
				return rule->default_param.handler (ctx->cfg, ctx, name, ctx->cur_attrs, value, param->user_data, dest_struct, param->offset);
			}
		}
	}
	
	msg_err ("could not find handler for tag %s at section %d", name, section);
	return FALSE;
}

/* Handlers */
/* Specific handlers */

/* Logging section */
gboolean 
handle_log_type (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	gchar                           *val;
	if (g_ascii_strcasecmp (data, "file") == 0) {
		/* Find filename attribute */
		if ((val = g_hash_table_lookup (attrs, "filename")) == NULL) {
			msg_err ("cannot log to file that is not specified");
			return FALSE;
		}
		cfg->log_type = RSPAMD_LOG_FILE;
		cfg->log_file = val;
	}
	else if (g_ascii_strcasecmp (data, "console") == 0) {
		cfg->log_type = RSPAMD_LOG_CONSOLE;
	}
	else if (g_ascii_strcasecmp (data, "syslog") == 0) {
		if ((val = g_hash_table_lookup (attrs, "facility")) == NULL) {
			msg_err ("cannot log to syslog when facility is not specified");
			return FALSE;
		}
		cfg->log_type = RSPAMD_LOG_SYSLOG;
		/* Rather ugly check */
		if (g_ascii_strncasecmp (val, "LOG_AUTH", sizeof ("LOG_AUTH") - 1) == 0 || g_ascii_strncasecmp (val, "auth", sizeof ("auth") - 1) == 0 ) {
			cfg->log_facility = LOG_AUTH;
		}
		else if (g_ascii_strncasecmp (val, "LOG_CRON", sizeof ("LOG_CRON") - 1) == 0 || g_ascii_strncasecmp (val, "cron", sizeof ("cron") - 1) == 0 ) {
			cfg->log_facility = LOG_CRON;
		}
		else if (g_ascii_strncasecmp (val, "LOG_DAEMON", sizeof ("LOG_DAEMON") - 1) == 0 || g_ascii_strncasecmp (val, "daemon", sizeof ("daemon") - 1) == 0 ) {
			cfg->log_facility = LOG_DAEMON;
		}
		else if (g_ascii_strncasecmp (val, "LOG_MAIL", sizeof ("LOG_MAIL") - 1) == 0 || g_ascii_strncasecmp (val, "mail", sizeof ("mail") - 1) == 0) {
			cfg->log_facility = LOG_MAIL;
		}
		else if (g_ascii_strncasecmp (val, "LOG_USER", sizeof ("LOG_USER") - 1) == 0 || g_ascii_strncasecmp (val, "user", sizeof ("user") - 1) == 0 ) {
			cfg->log_facility = LOG_USER;
		}
		else if (g_ascii_strncasecmp (val, "LOG_LOCAL0", sizeof ("LOG_LOCAL0") - 1) == 0 || g_ascii_strncasecmp (val, "local0", sizeof ("local0") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL0;
		}
		else if (g_ascii_strncasecmp (val, "LOG_LOCAL1", sizeof ("LOG_LOCAL1") - 1) == 0 || g_ascii_strncasecmp (val, "local1", sizeof ("local1") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL1;
		}
		else if (g_ascii_strncasecmp (val, "LOG_LOCAL2", sizeof ("LOG_LOCAL2") - 1) == 0 || g_ascii_strncasecmp (val, "local2", sizeof ("local2") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL2;
		}
		else if (g_ascii_strncasecmp (val, "LOG_LOCAL3", sizeof ("LOG_LOCAL3") - 1) == 0 || g_ascii_strncasecmp (val, "local3", sizeof ("local3") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL3;
		}
		else if (g_ascii_strncasecmp (val, "LOG_LOCAL4", sizeof ("LOG_LOCAL4") - 1) == 0 || g_ascii_strncasecmp (val, "local4", sizeof ("local4") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL4;
		}
		else if (g_ascii_strncasecmp (val, "LOG_LOCAL5", sizeof ("LOG_LOCAL5") - 1) == 0 || g_ascii_strncasecmp (val, "local5", sizeof ("local5") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL5;
		}
		else if (g_ascii_strncasecmp (val, "LOG_LOCAL6", sizeof ("LOG_LOCAL6") - 1) == 0 || g_ascii_strncasecmp (val, "local6", sizeof ("local6") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL6;
		}
		else if (g_ascii_strncasecmp (val, "LOG_LOCAL7", sizeof ("LOG_LOCAL7") - 1) == 0 || g_ascii_strncasecmp (val, "local7", sizeof ("local7") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL7;
		}
		else {
			msg_err ("invalid logging facility: %s", val);
			return FALSE;
		}
	}
	else {
		msg_err ("invalid logging type: %s", data);
		return FALSE;
	}
	
	return TRUE;
}

gboolean 
handle_log_level (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	if (g_ascii_strcasecmp (data, "error") == 0) {
		cfg->log_level = G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL;
	}
	else if (g_ascii_strcasecmp (data, "warning") == 0) {
		cfg->log_level = G_LOG_LEVEL_WARNING;
	}
	else if (g_ascii_strcasecmp (data, "info") == 0) {
		cfg->log_level = G_LOG_LEVEL_INFO | G_LOG_LEVEL_MESSAGE;
	}
	else if (g_ascii_strcasecmp (data, "debug") == 0) {
		cfg->log_level = G_LOG_LEVEL_DEBUG;
	}
	else {
		msg_err ("unknown log level: %s", data);
		return FALSE;
	}

	return TRUE;
}

/* Worker section */
gboolean 
worker_handle_param (struct config_file *cfg, struct rspamd_xml_userdata *ctx, const gchar *tag, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	struct worker_conf             *wrk = ctx->section_pointer;
	const gchar                    *name;
	struct xml_config_param        *cparam;
	GHashTable                     *worker_config;

	if (g_ascii_strcasecmp (tag, "option") == 0 || g_ascii_strcasecmp (tag, "param") == 0)  {
		if ((name = g_hash_table_lookup (attrs, "name")) == NULL) {
			msg_err ("worker param tag must have \"name\" attribute");
			return FALSE;
		}
	}
	else {
		name = tag;
	}

	if (!worker_options ||
			(worker_config = g_hash_table_lookup (worker_options, &wrk->type)) == NULL ||
			(cparam = g_hash_table_lookup (worker_config, name)) == NULL) {
		msg_warn ("unregistered worker attribute '%s' for worker %s", name, process_to_str (wrk->type));
		g_hash_table_insert (wrk->params, (char *)name, memory_pool_strdup (cfg->cfg_pool, data));
	}
	else {
		return cparam->handler (cfg, ctx, attrs, data, NULL, cparam->user_data, cparam->offset);
	}

	return TRUE;
}
gboolean 
worker_handle_type (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	struct worker_conf             *wrk = ctx->section_pointer;

	
	if (g_ascii_strcasecmp (data, "normal") == 0) {
		wrk->type = TYPE_WORKER;
		wrk->has_socket = TRUE;
	}
	else if (g_ascii_strcasecmp (data, "controller") == 0) {
		wrk->type = TYPE_CONTROLLER;
		wrk->has_socket = TRUE;
	}
	else if (g_ascii_strcasecmp (data, "lmtp") == 0) {
		wrk->type = TYPE_LMTP;
		wrk->has_socket = TRUE;
	}
	else if (g_ascii_strcasecmp (data, "smtp") == 0) {
		wrk->type = TYPE_SMTP;
		wrk->has_socket = TRUE;
	}
	else if (g_ascii_strcasecmp (data, "fuzzy") == 0) {
		wrk->type = TYPE_FUZZY;
		wrk->has_socket = FALSE;
	}
	else if (g_ascii_strcasecmp (data, "greylist") == 0) {
		wrk->type = TYPE_GREYLIST;
		wrk->has_socket = FALSE;
	}
	else {
		msg_err ("unknown worker type: %s", data);
		return FALSE;
	}

	return TRUE;
}

gboolean 
worker_handle_bind (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	struct worker_conf             *wrk = ctx->section_pointer;

	if (!parse_bind_line (cfg, wrk, data)) {
		msg_err ("cannot parse bind_socket: %s", data);
		return FALSE;
	}

	return TRUE;
}

gboolean
handle_metric_action (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	struct metric                  *metric = ctx->section_pointer;
	gchar                          *p, *errstr;
	gint                            res;
	struct metric_action           *action;

	/* First of all check whether we have data with weight (reject:50 for example) */
	if ((p = strchr (data, ':')) == NULL) {
		if (check_action_str (data, &res)) {
			metric->action = res;
			return TRUE;
		}
		return FALSE;
	}
	else {
		if (!check_action_str (data, &res)) {
			return FALSE;
		}
		else {
			action = memory_pool_alloc (cfg->cfg_pool, sizeof (struct metric_action));
			action->action = res;
			errno = 0;
			action->score = strtod (p + 1, &errstr);
			if (errno != 0 || (errstr != NULL && *errstr != '\0')) {
				msg_err ("invalid double value: %s", data);
				return FALSE;
			}
			metric->actions = g_list_prepend (metric->actions, action);
		}
	}

	return TRUE;
}

gboolean
handle_metric_symbol (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	gchar                           *strval, *err;
	double                         *value;
	GList                          *metric_list;
	struct metric                  *metric = ctx->section_pointer;

	value = memory_pool_alloc (cfg->cfg_pool, sizeof (double));
	if ((strval = g_hash_table_lookup (attrs, "weight")) == NULL) {
		msg_info ("symbol tag should have \"weight\" attribute, assume weight 1.0");
		*value = 1.0;
	}
	else {
		errno = 0;
		*value = strtod (strval, &err);
		if (errno != 0 || (err != NULL && *err != 0)) {
			msg_err ("invalid number: %s, %s", strval, strerror (errno));
			return FALSE;
		}
	}
	
	g_hash_table_insert (metric->symbols, data, value);

	if ((metric_list = g_hash_table_lookup (cfg->metrics_symbols, data)) == NULL) {
		metric_list = g_list_prepend (NULL, metric);
		memory_pool_add_destructor (cfg->cfg_pool, (pool_destruct_func)g_list_free, metric_list);
		g_hash_table_insert (cfg->metrics_symbols, data, metric_list);
	}
	else {
		/* Slow but keep start element of list in safe */
		metric_list = g_list_append (metric_list, metric);
	}

	return TRUE;
}

/* Modules section */
gboolean 
handle_module_opt (struct config_file *cfg, struct rspamd_xml_userdata *ctx, const gchar *tag, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	gchar                          *val;
	struct module_opt              *cur;
	gboolean                        is_lua = FALSE;
	const gchar                    *name;

	if (g_ascii_strcasecmp (tag, "option") == 0 || g_ascii_strcasecmp (tag, "param") == 0) {
		if ((name = g_hash_table_lookup (attrs, "name")) == NULL) {
			msg_err ("worker param tag must have \"name\" attribute");
			return FALSE;
		}
	}
	else {
		name = tag;
	}

	/* Check for lua */
	if ((val = g_hash_table_lookup (attrs, "lua")) != NULL) {
		if (g_ascii_strcasecmp (val, "yes") == 0) {
			is_lua = TRUE;
		}
	}
	/*
	 * XXX: in fact we cannot check for lua modules and need to do it in post-config procedure
	 * so just insert any options provided and try to handle them in further process
	 */

	/* Insert option */
	cur = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct module_opt));
	cur->param = (char *)name;
	cur->value = data;
	cur->is_lua = is_lua;
	ctx->section_pointer = g_list_prepend (ctx->section_pointer, cur);

	return TRUE;
}

/* Handle lua tag */
gboolean 
handle_lua (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	gchar                        *val, *cur_dir, *lua_dir, *lua_file, *tmp1, *tmp2;
	lua_State                    *L = cfg->lua_state;

	/* First check for global variable 'config' */
	lua_getglobal (L, "config");

	if (lua_isnil (L, -1)) {
		/* Assign global table to set up attributes */
		lua_newtable (L);
		lua_setglobal (L, "config");
		/* Now config table can be used for configuring rspamd */
	}
	/* First check "src" attribute */
	if ((val = g_hash_table_lookup (attrs, "src")) != NULL) {
		/* Chdir */
		tmp1 = g_strdup (val);
		tmp2 = g_strdup (val);
		lua_dir = dirname (tmp1);
		lua_file = basename (tmp2);
		if (lua_dir && lua_file) {
			cur_dir = g_malloc (PATH_MAX);
			if (getcwd (cur_dir, PATH_MAX) != NULL && chdir (lua_dir) != -1) {
				if (luaL_dofile (L, lua_file) != 0) {
					msg_err ("cannot load lua file %s: %s", val, lua_tostring (L, -1));
					if (chdir (cur_dir) == -1) {
						msg_err ("cannot chdir to %s: %s", cur_dir, strerror (errno));;
					}
					g_free (cur_dir);
					g_free (tmp1);
					g_free (tmp2);
					return FALSE;
				}
			}
			else {
				msg_err ("cannot chdir to %s: %s", lua_dir, strerror (errno));;
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
			msg_err ("directory for file %s does not exists", val);
		}
	}
	else if (data != NULL && *data != '\0') {
		/* Try to load a string */
		if (luaL_dostring (L, data) != 0) {
			msg_err ("cannot load lua chunk: %s", lua_tostring (L, -1));
			return FALSE;
		}
	}

	return TRUE;
}

/* Modules section */
gboolean 
handle_module_path (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	struct stat st;
	struct script_module *cur;
	glob_t globbuf;
	gchar                           *pattern;
	size_t len;
	gint                            i;

	if (stat (data, &st) == -1) {
		msg_err ("cannot stat path %s, %s", data, strerror (errno));
		return FALSE;
	}
	
	/* Handle directory */
	if (S_ISDIR (st.st_mode)) {
		globbuf.gl_offs = 0;
		len = strlen (data) + sizeof ("*.lua");
		pattern = g_malloc (len);
		snprintf (pattern, len, "%s%s", data, "*.lua");

		if (glob (pattern, GLOB_DOOFFS, NULL, &globbuf) == 0) {
			for (i = 0; i < globbuf.gl_pathc; i ++) {
				cur = memory_pool_alloc (cfg->cfg_pool, sizeof (struct script_module));
				cur->path = memory_pool_strdup (cfg->cfg_pool, globbuf.gl_pathv[i]);
				cfg->script_modules = g_list_prepend (cfg->script_modules, cur);
			}
			globfree (&globbuf);
			g_free (pattern);
		}
		else {
			msg_err ("glob failed: %s", strerror (errno));
			g_free (pattern);
			return FALSE;
		}
	}
	else {
		/* Handle single file */
		cur = memory_pool_alloc (cfg->cfg_pool, sizeof (struct script_module));
		cur->path = memory_pool_strdup (cfg->cfg_pool, data);
		cfg->script_modules = g_list_prepend (cfg->script_modules, cur);
	}

	
	return TRUE;
}

/* Variables and composites */
gboolean 
handle_variable (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	gchar                        *val;
	
	if ((val = g_hash_table_lookup (attrs, "name")) == NULL) {
		msg_err ("'name' attribute is required for tag 'variable'");
		return FALSE;
	}

	g_hash_table_insert (cfg->variables, val, memory_pool_strdup (cfg->cfg_pool, data));
	return TRUE;
}

gboolean 
handle_composite (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	gchar                        *val;
	struct expression            *expr;
	
	if ((val = g_hash_table_lookup (attrs, "name")) == NULL) {
		msg_err ("'name' attribute is required for tag 'composite'");
		return FALSE;
	}

	if ((expr = parse_expression (cfg->cfg_pool, data)) == NULL) {
		msg_err ("cannot parse composite expression: %s", data);
		return FALSE;
	}
	g_hash_table_insert (cfg->composite_symbols, val, expr);

	return TRUE;
}

/* View section */
gboolean 
handle_view_ip (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	struct rspamd_view          *view = ctx->section_pointer;

	if (!add_view_ip (view, data)) {
		msg_err ("invalid ip line in view definition: ip = '%s'", data);
		return FALSE;
	}
	
	return TRUE;
}
gboolean 
handle_view_client_ip (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	struct rspamd_view          *view = ctx->section_pointer;

	if (!add_view_client_ip (view, data)) {
		msg_err ("invalid ip line in view definition: ip = '%s'", data);
		return FALSE;
	}
	
	return TRUE;
}
gboolean 
handle_view_from (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	struct rspamd_view          *view = ctx->section_pointer;

	if (!add_view_from (view, data)) {
		msg_err ("invalid from line in view definition: from = '%s'", data);
		return FALSE;
	}
	
	return TRUE;
}
gboolean 
handle_view_rcpt (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	struct rspamd_view          *view = ctx->section_pointer;

	if (!add_view_rcpt (view, data)) {
		msg_err ("invalid from line in view definition: rcpt = '%s'", data);
		return FALSE;
	}

	return TRUE;
}
gboolean
handle_view_symbols (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	struct rspamd_view          *view = ctx->section_pointer;

	if (!add_view_symbols (view, data)) {
		msg_err ("invalid symbols line in view definition: symbols = '%s'", data);
		return FALSE;
	}
	cfg->domain_settings_str = memory_pool_strdup (cfg->cfg_pool, data);

	return TRUE;
}

/* Settings */
gboolean 
handle_user_settings (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	if (!read_settings (data, cfg, cfg->user_settings)) {
		msg_err ("cannot read settings %s", data);
		return FALSE;
	}
	cfg->user_settings_str = memory_pool_strdup (cfg->cfg_pool, data);

	return TRUE;
}
gboolean 
handle_domain_settings (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	if (!read_settings (data, cfg, cfg->domain_settings)) {
		msg_err ("cannot read settings %s", data);
		return FALSE;
	}

	return TRUE;
}

/* Classifier */
gboolean 
handle_classifier_tokenizer (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	struct classifier_config     *ccf = ctx->section_pointer;
	
	if ((ccf->tokenizer = get_tokenizer (data)) == NULL) {
		msg_err ("unknown tokenizer %s", data);
		return FALSE;
	}

	return TRUE;
}

gboolean 
handle_classifier_opt (struct config_file *cfg, struct rspamd_xml_userdata *ctx, const gchar *tag, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	struct classifier_config       *ccf = ctx->section_pointer;
	const gchar                    *name;
	struct xml_config_param        *cparam;
	GHashTable                     *classifier_config;

	if (g_ascii_strcasecmp (tag, "option") == 0 || g_ascii_strcasecmp (tag, "param") == 0) {
		if ((name = g_hash_table_lookup (attrs, "name")) == NULL) {
			msg_err ("worker param tag must have \"name\" attribute");
			return FALSE;
		}
	}
	else {
		name = tag;
	}

	if (!classifier_options ||
			(classifier_config = g_hash_table_lookup (classifier_options, ccf->classifier->name)) == NULL ||
			(cparam = g_hash_table_lookup (classifier_config, name)) == NULL) {
		msg_warn ("unregistered classifier attribute '%s' for classifier %s", name, ccf->classifier->name);
		return FALSE;
	}
	else {
		g_hash_table_insert (ccf->opts, (char *)name, memory_pool_strdup (cfg->cfg_pool, data));
	}

	return TRUE;
}

/* Statfile */
gboolean 
handle_statfile_normalizer (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	msg_info ("normalizer option is now not available as rspamd always use internal normalizer for winnow (hyperbolic tanhent)");
	return TRUE;
}

gboolean 
handle_statfile_binlog (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	struct statfile             *st = ctx->section_pointer;

	if (st->binlog == NULL) {
		st->binlog = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile_binlog_params));
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

	return TRUE;
}

gboolean 
handle_statfile_binlog_rotate (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	struct statfile             *st = ctx->section_pointer;

	if (st->binlog == NULL) {
		st->binlog = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile_binlog_params));
	}
	st->binlog->rotate_time = parse_time (data, TIME_SECONDS);
	
	return TRUE;
}

gboolean 
handle_statfile_binlog_master (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	struct statfile             *st = ctx->section_pointer;
	if (st->binlog == NULL) {
		st->binlog = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile_binlog_params));
	}

	if (!parse_host_port (data, &st->binlog->master_addr, &st->binlog->master_port)) {
		msg_err ("cannot parse master address: %s", data);
		return FALSE;
	}

	return TRUE;
}

/* Common handlers */
gboolean 
xml_handle_string (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	/* Simply assign pointer to pointer */
	gchar                       **dest;

	dest = (gchar **)G_STRUCT_MEMBER_P (dest_struct, offset);
	*dest = memory_pool_strdup (cfg->cfg_pool, data);

	return TRUE;
}

gboolean
xml_handle_string_list (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	GList                      **dest;
	gchar                      **tokens, **cur;

	dest = (GList **)G_STRUCT_MEMBER_P (dest_struct, offset);
	*dest = NULL;

	tokens = g_strsplit_set (data, ";,", 0);
	if (!tokens || !tokens[0]) {
		return FALSE;
	}
	memory_pool_add_destructor (cfg->cfg_pool, (pool_destruct_func)g_strfreev, tokens);
	cur = tokens;
	while (*cur) {
		*dest = g_list_prepend (*dest, *cur);
		cur ++;
	}

	return TRUE;
}


gboolean 
xml_handle_size (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	gsize                      *dest;

	dest = (gsize *)G_STRUCT_MEMBER_P (dest_struct, offset);
	*dest = parse_limit (data);
	
	return TRUE;
}

gboolean 
xml_handle_seconds (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	guint32                      *dest;

	dest = (guint32 *)G_STRUCT_MEMBER_P (dest_struct, offset);
	*dest = parse_time (data, TIME_SECONDS);
	
	return TRUE;
}

gboolean 
xml_handle_boolean (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	gboolean                    *dest;

	dest = (gboolean *)G_STRUCT_MEMBER_P (dest_struct, offset);
	*dest = parse_flag (data);
	/* gchar -> gboolean */
	if (*dest == -1) {
		msg_err ("bad boolean: %s", data);
		return FALSE;
	}
	else if (*dest == 1)  {
		*dest = TRUE;
	}
	
	return TRUE;
}

gboolean 
xml_handle_double (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	double                      *dest;
	gchar                           *err = NULL;

	dest = (double *)G_STRUCT_MEMBER_P (dest_struct, offset);
	errno = 0;
	*dest = strtod (data, &err);
	if (errno != 0 || (err != NULL && *err != 0)) {
		msg_err ("invalid number: %s, %s", data, strerror (errno));
		return FALSE;
	}
	
	return TRUE;
}

gboolean 
xml_handle_int (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	gint                            *dest;
	gchar                           *err = NULL;

	dest = (gint *)G_STRUCT_MEMBER_P (dest_struct, offset);
	errno = 0;
	*dest = strtol (data, &err, 10);
	if (errno != 0 || (err != NULL && *err != 0)) {
		msg_err ("invalid number: %s, %s", data, strerror (errno));
		return FALSE;
	}
	
	return TRUE;
}

gboolean 
xml_handle_uint32 (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	guint32                         *dest;
	gchar                           *err = NULL;

	dest = (guint32 *)G_STRUCT_MEMBER_P (dest_struct, offset);
	errno = 0;
	*dest = strtoul (data, &err, 10);
	if (errno != 0 || (err != NULL && *err != 0)) {
		msg_err ("invalid number: %s, %s", data, strerror (errno));
		return FALSE;
	}
	
	return TRUE;
}

gboolean 
xml_handle_uint16 (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	guint16                    *dest;
	gchar                           *err = NULL;

	dest = (guint16 *)G_STRUCT_MEMBER_P (dest_struct, offset);
	errno = 0;
	*dest = strtoul (data, &err, 10);
	if (errno != 0 || (err != NULL && *err != 0)) {
		msg_err ("invalid number: %s, %s", data, strerror (errno));
		return FALSE;
	}
	
	return TRUE;
}

/* XML callbacks */
void 
rspamd_xml_start_element (GMarkupParseContext *context, const gchar *element_name, const gchar **attribute_names,
								const gchar **attribute_values, gpointer user_data, GError **error)
{
	struct rspamd_xml_userdata *ud = user_data;
	struct classifier_config   *ccf;
	gchar                      *res, *condition;

	if (g_ascii_strcasecmp (element_name, "if") == 0) {
		/* Push current state to queue */
		g_queue_push_head (ud->if_stack, GSIZE_TO_POINTER ((gsize)ud->state));
		/* Now get attributes */
		ud->cur_attrs = process_attrs (ud->cfg, attribute_names, attribute_values);
		if ((condition = g_hash_table_lookup (ud->cur_attrs, "condition")) == NULL) {
			msg_err ("unknown condition attribute for if tag");
			*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "param 'condition' is required for tag 'if'");
			ud->state = XML_ERROR;
		}
		if (! lua_check_condition (ud->cfg, condition)) {
			ud->state = XML_SKIP_ELEMENTS;
		}
		return;
	}
	switch (ud->state) {
		case XML_READ_START:
			if (g_ascii_strcasecmp (element_name, "rspamd") != 0) {
				/* Invalid XML, it must contains root element <rspamd></rspamd> */
				*error = g_error_new (xml_error_quark (), XML_START_MISSING, "start element is missing");
				ud->state = XML_ERROR;
			}
			else {
				ud->state = XML_READ_PARAM;
			}
			break;
		case XML_READ_PARAM:
			/* Read parameter name and try to find among list of known parameters */
			if (g_ascii_strcasecmp (element_name, "module") == 0) {
				/* Read module data */
				if (extract_attr ("name", attribute_names, attribute_values, &res)) {
					ud->parent_pointer = memory_pool_strdup (ud->cfg->cfg_pool, res);
					/* Empty list */
					ud->section_pointer = NULL;
					ud->state = XML_READ_MODULE;
				}
				else {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "param 'name' is required for tag 'module'");
					ud->state = XML_ERROR;
				}
			}
			else if (g_ascii_strcasecmp (element_name, "modules") == 0) {
				ud->state = XML_READ_MODULES;	
			}
			else if (g_ascii_strcasecmp (element_name, "logging") == 0) {
				ud->state = XML_READ_LOGGING;	
			}
			else if (g_ascii_strcasecmp (element_name, "metric") == 0) {
				ud->state = XML_READ_METRIC;
				/* Create object */
				ud->section_pointer = check_metric_conf (ud->cfg, NULL);
			}
			else if (g_ascii_strcasecmp (element_name, "classifier") == 0) {
				if (extract_attr ("type", attribute_names, attribute_values, &res)) {
					ud->state = XML_READ_CLASSIFIER;
					/* Create object */
					ccf = check_classifier_cfg (ud->cfg, NULL);
					if ((ccf->classifier = get_classifier (res)) == NULL) {
						*error = g_error_new (xml_error_quark (), XML_INVALID_ATTR, "invalid classifier type: %s", res);
						ud->state = XML_ERROR;
					}
					else {
						ud->section_pointer = ccf;
					}
				}
				else {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "param 'type' is required for tag 'classifier'");
					ud->state = XML_ERROR;
				}
			}
			else if (g_ascii_strcasecmp (element_name, "worker") == 0) {
				ud->state = XML_READ_WORKER;
				/* Create object */
				ud->section_pointer = check_worker_conf (ud->cfg, NULL);
			}
			else if (g_ascii_strcasecmp (element_name, "lua") == 0) {
				rspamd_strlcpy (ud->section_name, element_name, sizeof (ud->section_name));
				ud->cur_attrs = process_attrs (ud->cfg, attribute_names, attribute_values);
				if (! handle_lua (ud->cfg, ud, ud->cur_attrs, NULL, NULL, ud->cfg, 0)) {
					*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "cannot parse tag '%s'", ud->section_name);
					ud->state = XML_ERROR;
				}
				else {
					ud->state = XML_READ_VALUE;
				}
			}
			else if (g_ascii_strcasecmp (element_name, "view") == 0) {
				ud->state = XML_READ_VIEW;
				/* Create object */
				ud->section_pointer = init_view (ud->cfg->cfg_pool);
			}
			else {
				/* Extract other tags */
				rspamd_strlcpy (ud->section_name, element_name, sizeof (ud->section_name));
				ud->cur_attrs = process_attrs (ud->cfg, attribute_names, attribute_values);
				ud->state = XML_READ_VALUE;
			}
			break;
		case XML_READ_CLASSIFIER:
			if (g_ascii_strcasecmp (element_name, "statfile") == 0) {
				ud->state = XML_READ_STATFILE;

				/* Now section pointer is statfile and parent pointer is classifier */
				ud->parent_pointer = ud->section_pointer;
				ud->section_pointer = memory_pool_alloc0 (ud->cfg->cfg_pool, sizeof (struct statfile));
			}
			else {
				rspamd_strlcpy (ud->section_name, element_name, sizeof (ud->section_name));
				/* Save attributes */
				ud->cur_attrs = process_attrs (ud->cfg, attribute_names, attribute_values);
			}
			break;
		case XML_SKIP_ELEMENTS:
			/* Do nothing */
			return;
		case XML_READ_MODULE:
		case XML_READ_METRIC:
		case XML_READ_MODULES:
		case XML_READ_STATFILE:
		case XML_READ_WORKER:
		case XML_READ_LOGGING:
		case XML_READ_VIEW:
			rspamd_strlcpy (ud->section_name, element_name, sizeof (ud->section_name));
			/* Save attributes */
			ud->cur_attrs = process_attrs (ud->cfg, attribute_names, attribute_values);
			break;
		default:
			if (*error == NULL) {
				*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "element %s is unexpected in this state %s",
					element_name, xml_state_to_string (ud));
			}
			break;
	}
}

#define CHECK_TAG(x, required)																												\
do {																																		\
if (g_ascii_strcasecmp (element_name, (x)) == 0) {																							\
	ud->state = XML_READ_PARAM;																												\
	res = TRUE;																																\
}																																			\
else {																																		\
	res = FALSE;																															\
	if ((required) == TRUE) {																												\
	*error = g_error_new (xml_error_quark (), XML_UNMATCHED_TAG, "element %s is unexpected in this state, expected %s", element_name, (x));	\
	ud->state = XML_ERROR;																													\
	}																																		\
}																																			\
} while (0)

void 
rspamd_xml_end_element (GMarkupParseContext	*context, const gchar *element_name, gpointer user_data, GError **error)
{
	struct rspamd_xml_userdata *ud = user_data;
	struct metric              *m;
	struct classifier_config   *ccf;
	struct statfile            *st;
	gboolean                    res;
	gpointer                    tptr;
	
	if (g_ascii_strcasecmp (element_name, "if") == 0) {
		tptr = g_queue_pop_head (ud->if_stack);

		if (tptr == NULL) {
			*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "element %s is umatched", element_name);
			ud->state = XML_ERROR;
		}
		/* Restore state */
		if (ud->state == XML_SKIP_ELEMENTS) {
			ud->state = GPOINTER_TO_SIZE (tptr);
		}
		/* Skip processing */

		return;
	}

	switch (ud->state) {
		case XML_READ_MODULE:
			CHECK_TAG ("module", FALSE);
			if (res) {
				if (ud->section_pointer != NULL) {
					g_hash_table_insert (ud->cfg->modules_opts, ud->parent_pointer, ud->section_pointer);
					ud->parent_pointer = NULL;
					ud->section_pointer = NULL;
				}
			}
			break;
		case XML_READ_CLASSIFIER:
			CHECK_TAG ("classifier", FALSE);
			if (res) {
				ccf = ud->section_pointer;
				if (ccf->statfiles == NULL) {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "classifier cannot contains no statfiles");
					ud->state = XML_ERROR;
					return;
				}
				ud->cfg->classifiers = g_list_prepend (ud->cfg->classifiers, ccf);
			}
			break;
		case XML_READ_STATFILE:
			CHECK_TAG ("statfile", FALSE);
			if (res) {
				ccf = ud->parent_pointer;
				st = ud->section_pointer;
				/* Check statfile and insert it into classifier */
				if (st->path == NULL || st->size == 0 || st->symbol == NULL) {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "not enough arguments in statfile definition");
					ud->state = XML_ERROR;
					return;
				}
				ccf->statfiles = g_list_prepend (ccf->statfiles, st);
				ud->cfg->statfiles = g_list_prepend (ud->cfg->statfiles, st);
				g_hash_table_insert (ud->cfg->classifiers_symbols, st->symbol, ccf);
				ud->section_pointer = ccf;
				ud->parent_pointer = NULL;
				ud->state = XML_READ_CLASSIFIER;
			}
			break;
		case XML_READ_MODULES:
			CHECK_TAG ("modules", FALSE);
			break;
		case XML_READ_METRIC:
			CHECK_TAG ("metric", FALSE);
			if (res) {
				m = ud->section_pointer;
				if (m->name == NULL) {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "metric attribute \"name\" is required but missing");
					ud->state = XML_ERROR;
					return;
				}
				g_hash_table_insert (ud->cfg->metrics, m->name, m);
				ud->cfg->metrics_list = g_list_prepend (ud->cfg->metrics_list, m);
			}	
			break;
		case XML_READ_WORKER:
			CHECK_TAG ("worker", FALSE);
			if (res) {
				/* Insert object to list */
				ud->cfg->workers = g_list_prepend (ud->cfg->workers, ud->section_pointer);
			}
			break;
		case XML_READ_VIEW:
			CHECK_TAG ("view", FALSE);
			if (res) {
				/* Insert object to list */
				ud->cfg->views = g_list_prepend (ud->cfg->views, ud->section_pointer);
			}
			break;
		case XML_READ_VALUE:
			/* Check tags parity */
			CHECK_TAG (ud->section_name, TRUE);
			break;
		case XML_READ_LOGGING:
			CHECK_TAG ("logging", FALSE);
			break;
		case XML_READ_PARAM:
			if (g_ascii_strcasecmp (element_name, "rspamd") == 0) {
				/* End of document */
				ud->state = XML_END; 
			}
			else {
				*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "element %s is umatched", element_name);
				ud->state = XML_ERROR;
			}
			break;
		case XML_SKIP_ELEMENTS:
			return;
		default:
			ud->state = XML_ERROR;
			break;
	}

}
#undef CHECK_TAG

void 
rspamd_xml_text (GMarkupParseContext *context, const gchar *text, gsize text_len, gpointer user_data, GError **error)
{
	struct rspamd_xml_userdata *ud = user_data;
	gchar                           *val;
	struct config_file *cfg = ud->cfg;
	
	/* Strip space symbols */
	while (*text && g_ascii_isspace (*text)) {
		text ++;
	}
	if (*text == '\0') {
		/* Skip empty text */
		return;
	}

	val = xml_asciiz_string (cfg->cfg_pool, text, text_len);

	switch (ud->state) {
		case XML_READ_MODULE:
			if (!call_param_handler (ud, ud->section_name, val, ud->section_pointer, XML_SECTION_MODULE)) {
				*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "cannot parse tag '%s' data: %s", ud->section_name, val);
				ud->state = XML_ERROR;
			}
			break;
		case XML_READ_MODULES:
			if (!call_param_handler (ud, ud->section_name, val, cfg, XML_SECTION_MODULES)) {
				*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "cannot parse tag '%s' data: %s", ud->section_name, val);
				ud->state = XML_ERROR;
			}
			break;
		case XML_READ_CLASSIFIER:
			if (!call_param_handler (ud, ud->section_name, val, ud->section_pointer, XML_SECTION_CLASSIFIER)) {
				*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "cannot parse tag '%s' data: %s", ud->section_name, val);
				ud->state = XML_ERROR;
			}
			break;
		case XML_READ_STATFILE:
			if (!call_param_handler (ud, ud->section_name, val, ud->section_pointer, XML_SECTION_STATFILE)) {
				*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "cannot parse tag '%s' data: %s", ud->section_name, val);
				ud->state = XML_ERROR;
			}
			break;
		case XML_READ_METRIC:
			if (!call_param_handler (ud, ud->section_name, val, ud->section_pointer, XML_SECTION_METRIC)) {
				*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "cannot parse tag '%s' data: %s", ud->section_name, val);
				ud->state = XML_ERROR;
			}
			break;
		case XML_READ_WORKER:
			if (!call_param_handler (ud, ud->section_name, val, ud->section_pointer, XML_SECTION_WORKER)) {
				*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "cannot parse tag '%s' data: %s", ud->section_name, val);
				ud->state = XML_ERROR;
			}
			break;
		case XML_READ_VIEW:
			if (!call_param_handler (ud, ud->section_name, val, ud->section_pointer, XML_SECTION_VIEW)) {
				*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "cannot parse tag '%s' data: %s", ud->section_name, val);
				ud->state = XML_ERROR;
			}
			break;
		case XML_READ_VALUE:
			if (!call_param_handler (ud, ud->section_name, val, cfg, XML_SECTION_MAIN)) {
				*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "cannot parse tag '%s' data: %s", ud->section_name, val);
				ud->state = XML_ERROR;
			}
			break;
		case XML_READ_LOGGING:
			if (!call_param_handler (ud, ud->section_name, val, cfg, XML_SECTION_LOGGING)) {
				*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "cannot parse tag '%s' data: %s", ud->section_name, val);
				ud->state = XML_ERROR;
			}
			break;
		case XML_SKIP_ELEMENTS:
			/* Do nothing */
			return;
		default:
			ud->state = XML_ERROR;
			break;
	}

}

void 
rspamd_xml_error (GMarkupParseContext *context, GError *error, gpointer user_data)
{
	struct rspamd_xml_userdata *ud = user_data;
	
	msg_err ("xml parser error: %s, at state \"%s\"", error->message, xml_state_to_string (ud));
}

/* Register handlers for specific parts of config */

/* Checker for module options */
struct option_callback_data {
	const gchar *optname;
	gboolean res;
	struct xml_config_param *param;
};

static void
module_option_callback (gpointer key, gpointer value, gpointer ud)
{
	const gchar                      *optname = key;
	static gchar                      rebuf[512];
	struct option_callback_data      *cd = ud;
	GRegex                           *re;
	GError                           *err = NULL;
	gsize                             relen;

	if (*optname == '/') {
		relen = strcspn (optname + 1, "/");
		if (relen > sizeof (rebuf)) {
			relen = sizeof (rebuf);
		}
		rspamd_strlcpy (rebuf, optname + 1, relen);
		/* This is a regexp so compile and check it */
		re = g_regex_new (rebuf, G_REGEX_CASELESS, 0, &err);
		if (err != NULL) {
			msg_err ("failed to compile regexp for option '%s', error was: %s, regexp was: %s", cd->optname, err->message, rebuf);
			return;
		}
		if (g_regex_match (re, cd->optname, 0, NULL)) {
			cd->res = TRUE;
			cd->param = value;
		}
	}

	return;
}

gboolean
check_module_option (const gchar *mname, const gchar *optname, const gchar *data)
{
	struct xml_config_param          *param;
	enum module_opt_type              type;
	GHashTable                       *module;
	gchar                            *err_str;
	struct option_callback_data       cd;

	if (module_options == NULL) {
		msg_warn ("no module options registered while checking option %s for module %s", mname, optname);
		return FALSE;
	}
	if ((module = g_hash_table_lookup (module_options, mname)) == NULL) {
		msg_warn ("module %s has not registered any options while checking for option %s", mname, optname);
		return FALSE;
	}

	if ((param = g_hash_table_lookup (module, optname)) == NULL) {
		/* Try to handle regexp options */
		cd.optname = optname;
		cd.res = FALSE;
		g_hash_table_foreach (module, module_option_callback, &cd);
		if (!cd.res) {
			msg_warn ("module %s has not registered option %s", mname, optname);
			return FALSE;
		}
		param = cd.param;
	}

	type = param->offset;

	/* Now handle option of each type */
	switch (type) {
	case MODULE_OPT_TYPE_STRING:
	case MODULE_OPT_TYPE_ANY:
		/* Allways OK */
		return TRUE;
	case MODULE_OPT_TYPE_INT:
		(void)strtol (data, &err_str, 10);
		if (*err_str != '\0') {
			msg_warn ("non-numeric data for option: '%s' for module: '%s' at position: '%s'", optname, mname, err_str);
			return FALSE;
		}
		break;
	case MODULE_OPT_TYPE_UINT:
		(void)strtoul (data, &err_str, 10);
		if (*err_str != '\0') {
			msg_warn ("non-numeric data for option: '%s' for module: '%s' at position: '%s'", optname, mname, err_str);
			return FALSE;
		}
		break;
	case MODULE_OPT_TYPE_DOUBLE:
		(void)strtod (data, &err_str);
		if (*err_str != '\0') {
			msg_warn ("non-numeric data for option: '%s' for module: '%s' at position: '%s'", optname, mname, err_str);
			return FALSE;
		}
		break;
	case MODULE_OPT_TYPE_TIME:
		(void)parse_time (data, TIME_SECONDS);
		if (errno != 0) {
			msg_warn ("non-numeric data for option: '%s' for module: '%s': %s", optname, mname, strerror (errno));
			return FALSE;
		}
		break;
	case MODULE_OPT_TYPE_SIZE:
		(void)parse_limit (data);
		if (errno != 0) {
			msg_warn ("non-numeric data for option: '%s' for module: '%s': %s", optname, mname, strerror (errno));
			return FALSE;
		}
		break;
	case MODULE_OPT_TYPE_MAP:
		if (!check_map_proto (data, NULL, NULL)) {
			return FALSE;
		}
		break;
	}

	return TRUE;
}

/* Register new module option */
void
register_module_opt (const gchar *mname, const gchar *optname, enum module_opt_type type)
{
	struct xml_config_param          *param;
	GHashTable                       *module;

	if (module_options == NULL) {
		module_options = g_hash_table_new (g_str_hash, g_str_equal);
	}
	if ((module = g_hash_table_lookup (module_options, mname)) == NULL) {
		module = g_hash_table_new (g_str_hash, g_str_equal);
		g_hash_table_insert (module_options, (char *)mname, module);
	}
	if ((param = g_hash_table_lookup (module, optname)) == NULL) {
		/* Register new param */
		param = g_malloc (sizeof (struct xml_config_param));
		param->handler = NULL;
		param->offset = type;
		param->name = optname;
		g_hash_table_insert (module, (char *)optname, param);
	}
	else {
		/* Param already exists replace it */
		msg_warn ("replace old handler for param '%s'", optname);
		g_free (param);
		param = g_malloc (sizeof (struct xml_config_param));
		param->handler = NULL;
		param->offset = type;
		param->name = optname;
		g_hash_table_insert (module, (char *)optname, param);
	}
}

/* Register new worker's options */
void
register_worker_opt (gint wtype, const gchar *optname, element_handler_func func, gpointer dest_struct, gint offset)
{
	struct xml_config_param          *param;
	GHashTable                       *worker;
	gint                             *new_key;

	if (worker_options == NULL) {
		worker_options = g_hash_table_new (g_int_hash, g_int_equal);
	}
	if ((worker = g_hash_table_lookup (worker_options, &wtype)) == NULL) {
		worker = g_hash_table_new (g_str_hash, g_str_equal);
		new_key = g_malloc (sizeof (gint));
		*new_key = wtype;
		g_hash_table_insert (worker_options, new_key, worker);
	}
	if ((param = g_hash_table_lookup (worker, optname)) == NULL) {
		/* Register new param */
		param = g_malloc (sizeof (struct xml_config_param));
		param->handler = func;
		param->user_data = dest_struct;
		param->offset = offset;
		param->name = optname;
		g_hash_table_insert (worker, (char *)optname, param);
	}
	else {
		/* Param already exists replace it */
		msg_warn ("replace old handler for param '%s'", optname);
		g_free (param);
		param = g_malloc (sizeof (struct xml_config_param));
		param->handler = func;
		param->user_data = dest_struct;
		param->offset = offset;
		param->name = optname;
		g_hash_table_insert (worker, (char *)optname, param);
	}
}

/* Register new classifier option */
void
register_classifier_opt (const gchar *ctype, const gchar *optname)
{
	struct xml_config_param          *param;
	GHashTable                       *classifier;

	if (classifier_options == NULL) {
		classifier_options = g_hash_table_new (g_str_hash, g_str_equal);
	}
	if ((classifier = g_hash_table_lookup (classifier_options, ctype)) == NULL) {
		classifier = g_hash_table_new (g_str_hash, g_str_equal);
		g_hash_table_insert (classifier_options, (char *)ctype, classifier);
	}
	if ((param = g_hash_table_lookup (classifier, optname)) == NULL) {
		/* Register new param */
		param = g_malloc (sizeof (struct xml_config_param));
		param->handler = NULL;
		param->user_data = NULL;
		param->offset = 0;
		param->name = optname;
		g_hash_table_insert (classifier, (char *)optname, param);
	}
	else {
		/* Param already exists replace it */
		msg_warn ("replace old handler for param '%s'", optname);
		g_free (param);
		param = g_malloc (sizeof (struct xml_config_param));
		param->handler = NULL;
		param->user_data = NULL;
		param->offset = 0;
		param->name = optname;
		g_hash_table_insert (classifier, (char *)optname, param);
	}
}


/* Dumper part */

/* Dump specific sections */

/* Dump main section variables */
static gboolean
xml_dump_main (struct config_file *cfg, FILE *f)
{
	gchar                           *escaped_str;
	
	/* Print header comment */
	rspamd_fprintf (f, "<!-- Main section -->" EOL);

	escaped_str = g_markup_escape_text (cfg->temp_dir, -1); 
	rspamd_fprintf (f, "<tempdir>%s</tempdir>" EOL, escaped_str);
	g_free (escaped_str);

	escaped_str = g_markup_escape_text (cfg->pid_file, -1); 
	rspamd_fprintf (f, "<pidfile>%s</pidfile>" EOL, escaped_str);
	g_free (escaped_str);

	escaped_str = g_markup_escape_text (cfg->filters_str, -1); 
	rspamd_fprintf (f, "<filters>%s</filters>" EOL, escaped_str);
	g_free (escaped_str);
	
	if (cfg->user_settings_str) {
		escaped_str = g_markup_escape_text (cfg->user_settings_str, -1); 
		rspamd_fprintf (f, "<user_settings>%s</user_settings>" EOL, escaped_str);
		g_free (escaped_str);
	}
	if (cfg->domain_settings_str) {
		escaped_str = g_markup_escape_text (cfg->domain_settings_str, -1); 
		rspamd_fprintf (f, "<domain_settings>%s</domain_settings>" EOL, escaped_str);
		g_free (escaped_str);
	}
	rspamd_fprintf (f, "<statfile_pool_size>%z</statfile_pool_size>" EOL, cfg->max_statfile_size);

	if (cfg->checksum)  {
		escaped_str = g_markup_escape_text (cfg->checksum, -1); 
		rspamd_fprintf (f, "<checksum>%s</checksum>" EOL, escaped_str);
		g_free (escaped_str);
	}

	rspamd_fprintf (f, "<raw_mode>%s</raw_mode>" EOL, cfg->raw_mode ? "yes" : "no");

	/* Print footer comment */
	rspamd_fprintf (f, "<!-- End of main section -->" EOL EOL);

	return TRUE;
}

/* Dump variables section */
static void
xml_variable_callback (gpointer key, gpointer value, gpointer user_data)
{
	FILE *f = user_data;
	gchar                           *escaped_key, *escaped_value;

	escaped_key = g_markup_escape_text (key, -1); 
	escaped_value = g_markup_escape_text (value, -1);
	rspamd_fprintf (f,  "<variable name=\"%s\">%s</variable>" EOL, escaped_key, escaped_value);
	g_free (escaped_key);
	g_free (escaped_value);
}

static gboolean
xml_dump_variables (struct config_file *cfg, FILE *f)
{
	/* Print header comment */
	rspamd_fprintf (f, "<!-- Variables section -->" EOL);

	/* Iterate through variables */
	g_hash_table_foreach (cfg->variables, xml_variable_callback, (gpointer)f);

	/* Print footer comment */
	rspamd_fprintf (f, "<!-- End of variables section -->" EOL EOL);

	return TRUE;
}

/* Composites section */
static void
xml_composite_callback (gpointer key, gpointer value, gpointer user_data)
{
	FILE *f = user_data;
	struct expression *expr;
	gchar                           *escaped_key, *escaped_value;
	
	expr = value;

	escaped_key = g_markup_escape_text (key, -1); 
	escaped_value = g_markup_escape_text (expr->orig, -1);
	rspamd_fprintf (f,  "<composite name=\"%s\">%s</composite>" EOL, escaped_key, escaped_value);
	g_free (escaped_key);
	g_free (escaped_value);
}

static gboolean
xml_dump_composites (struct config_file *cfg, FILE *f)
{
	/* Print header comment */
	rspamd_fprintf (f, "<!-- Composites section -->" EOL);

	/* Iterate through variables */
	g_hash_table_foreach (cfg->composite_symbols, xml_composite_callback, (gpointer)f);

	/* Print footer comment */
	rspamd_fprintf (f, "<!-- End of composites section -->" EOL EOL);

	return TRUE;
}

/* Workers */
static void
xml_worker_param_callback (gpointer key, gpointer value, gpointer user_data)
{
	FILE *f = user_data;
	gchar                           *escaped_key, *escaped_value;

	escaped_key = g_markup_escape_text (key, -1); 
	escaped_value = g_markup_escape_text (value, -1);
	rspamd_fprintf (f,  "    <param name=\"%s\">%s</param>" EOL, escaped_key, escaped_value);
	g_free (escaped_key);
	g_free (escaped_value);
}

static gboolean
xml_dump_workers (struct config_file *cfg, FILE *f)
{
	GList *cur;
	struct worker_conf *wrk;
	gchar                           *escaped_str;

	/* Print header comment */
	rspamd_fprintf (f, "<!-- Workers section -->" EOL);

	/* Iterate through list */
	cur = g_list_first (cfg->workers);
	while (cur) {
		wrk = cur->data;
		
		rspamd_fprintf (f, "<worker>" EOL);
		switch (wrk->type) {
			case TYPE_WORKER:
				rspamd_fprintf (f, "  <type>normal</type>" EOL);
				break;
			case TYPE_CONTROLLER:
				rspamd_fprintf (f, "  <type>controller</type>" EOL);
				break;
			case TYPE_FUZZY:
				rspamd_fprintf (f, "  <type>fuzzy</type>" EOL);
				break;
			case TYPE_LMTP:
				rspamd_fprintf (f, "  <type>lmtp</type>" EOL);
				break;
			case TYPE_SMTP:
				rspamd_fprintf (f, "  <type>smtp</type>" EOL);
				break;
		}
		escaped_str = g_markup_escape_text (wrk->bind_host, -1); 
		rspamd_fprintf (f, "  <bind_socket>%s</bind_socket>" EOL, escaped_str);
		g_free (escaped_str);

		rspamd_fprintf (f, "  <count>%ud</count>" EOL, wrk->count);
		rspamd_fprintf (f, "  <maxfiles>%ud</maxfiles>" EOL, wrk->rlimit_nofile);
		rspamd_fprintf (f, "  <maxcore>%ud</maxcore>" EOL, wrk->rlimit_maxcore);
		
		/* Now dump other attrs */
		rspamd_fprintf (f, "<!-- Other params -->" EOL);
		g_hash_table_foreach (wrk->params, xml_worker_param_callback, f);

		rspamd_fprintf (f, "</worker>" EOL);

		cur = g_list_next (cur);
	}

	/* Print footer comment */
	rspamd_fprintf (f, "<!-- End of workers section -->" EOL EOL);

	return TRUE;
}

/* Modules dump */
static void
xml_module_callback (gpointer key, gpointer value, gpointer user_data)
{
	FILE *f = user_data;
	gchar                           *escaped_key, *escaped_value;
	GList *cur;
	struct module_opt *opt;
	
	escaped_key = g_markup_escape_text (key, -1); 
	rspamd_fprintf (f, "<!-- %s -->" EOL, escaped_key);
	rspamd_fprintf (f, "<module name=\"%s\">" EOL, escaped_key);
	g_free (escaped_key);

	cur = g_list_first (value);
	while (cur) {
		opt = cur->data;
		escaped_key = g_markup_escape_text (opt->param, -1); 
		escaped_value = g_markup_escape_text (opt->value, -1);
		rspamd_fprintf (f,  "  <option name=\"%s\">%s</option>" EOL, escaped_key, escaped_value);
		g_free (escaped_key);
		g_free (escaped_value);
		cur = g_list_next (cur);
	}
	rspamd_fprintf (f, "</module>" EOL EOL);
}

static gboolean
xml_dump_modules (struct config_file *cfg, FILE *f)
{
	/* Print header comment */
	rspamd_fprintf (f, "<!-- Modules section -->" EOL);

	/* Iterate through variables */
	g_hash_table_foreach (cfg->modules_opts, xml_module_callback, (gpointer)f);

	/* Print footer comment */
	rspamd_fprintf (f, "<!-- End of modules section -->" EOL EOL);

	return TRUE;
}

/* Classifiers dump */
static void
xml_classifier_callback (gpointer key, gpointer value, gpointer user_data)
{
	FILE *f = user_data;
	gchar                           *escaped_key, *escaped_value;

	escaped_key = g_markup_escape_text (key, -1); 
	escaped_value = g_markup_escape_text (value, -1);
	rspamd_fprintf (f,  " <option name=\"%s\">%s</option>" EOL, escaped_key, escaped_value);
	g_free (escaped_key);
	g_free (escaped_value);
}

static gboolean
xml_dump_classifiers (struct config_file *cfg, FILE *f)
{
	GList *cur, *cur_st;
	struct classifier_config *ccf;
	struct statfile *st;

	/* Print header comment */
	rspamd_fprintf (f, "<!-- Classifiers section -->" EOL);

	/* Iterate through classifiers */
	cur = g_list_first (cfg->classifiers);
	while (cur) {
		ccf = cur->data;
		rspamd_fprintf (f, "<classifier type=\"%s\">" EOL, ccf->classifier->name);
		rspamd_fprintf (f, " <tokenizer>%s</tokenizer>" EOL, ccf->tokenizer->name);
		rspamd_fprintf (f, " <metric>%s</metric>" EOL, ccf->metric);
		g_hash_table_foreach (ccf->opts, xml_classifier_callback, f);
		/* Statfiles */
		cur_st = g_list_first (ccf->statfiles);
		while (cur_st) {
			st = cur_st->data;
			rspamd_fprintf (f, " <statfile>" EOL);
			rspamd_fprintf (f, "  <symbol>%s</symbol>" EOL "  <size>%z</size>" EOL "  <path>%s</path>" EOL,
						st->symbol, st->size, st->path);
			rspamd_fprintf (f, "  <normalizer>%s</normalizer>" EOL, st->normalizer_str);
			/* Binlog */
			if (st->binlog) {
				if (st->binlog->affinity == AFFINITY_MASTER) {
					rspamd_fprintf (f, "  <binlog>master</binlog>" EOL);
				}
				else if (st->binlog->affinity == AFFINITY_SLAVE) {
					rspamd_fprintf (f, "  <binlog>slave</binlog>" EOL);
					rspamd_fprintf (f, "  <binlog_master>%s:%d</binlog_master>" EOL, 
							inet_ntoa (st->binlog->master_addr), (gint)ntohs (st->binlog->master_port)); 
				}
				rspamd_fprintf (f, "  <binlog_rotate>%T</binlog_rotate>" EOL, st->binlog->rotate_time);
			}
			rspamd_fprintf (f, " </statfile>" EOL);
			cur_st = g_list_next (cur_st);
		}

		rspamd_fprintf (f, "</classifier>" EOL);
		cur = g_list_next (cur);
	}

	/* Print footer comment */
	rspamd_fprintf (f, "<!-- End of classifiers section -->" EOL EOL);

	return TRUE;

}

/* Logging section */
static gboolean
xml_dump_logging (struct config_file *cfg, FILE *f)
{
	gchar *escaped_value;

	/* Print header comment */
	rspamd_fprintf (f, "<!-- Logging section -->" EOL);
	rspamd_fprintf (f, "<logging>" EOL);
	
	/* Level */
	if (cfg->log_level < G_LOG_LEVEL_WARNING) {
		rspamd_fprintf (f, " <level>error</level>" EOL);
	}
	else if (cfg->log_level < G_LOG_LEVEL_MESSAGE) {
		rspamd_fprintf (f, " <level>warning</level>" EOL);
	}
	else if (cfg->log_level < G_LOG_LEVEL_DEBUG) {
		rspamd_fprintf (f, " <level>info</level>" EOL);
	}
	else {
		rspamd_fprintf (f, " <level>debug</level>" EOL);
	}
	
	/* Other options */
	rspamd_fprintf (f, " <log_urls>%s</log_urls>" EOL, cfg->log_urls ? "yes" : "no");
	if (cfg->log_buf_size != 0) {
		rspamd_fprintf (f, " <log_buffer>%ud</log_buffer>" EOL, (guint)cfg->log_buf_size);
	}
	if (cfg->debug_ip_map != NULL) {
		escaped_value = g_markup_escape_text (cfg->debug_ip_map, -1);
		rspamd_fprintf (f, " <debug_ip>%s</debug_ip>" EOL, escaped_value);
		g_free (escaped_value);
	}
	
	/* Handle type */
	if (cfg->log_type == RSPAMD_LOG_FILE) {
		escaped_value = g_markup_escape_text (cfg->log_file, -1);
		rspamd_fprintf (f, " <type filename=\"%s\">file</type>" EOL, escaped_value);
		g_free (escaped_value);
	}
	else if (cfg->log_type == RSPAMD_LOG_CONSOLE) {
		rspamd_fprintf (f, " <type>console</type>" EOL);
	}
	else if (cfg->log_type == RSPAMD_LOG_SYSLOG) {
		escaped_value = NULL;
		switch (cfg->log_facility) {
			case LOG_AUTH:
				escaped_value = "LOG_AUTH";
				break;
			case LOG_CRON:
				escaped_value = "LOG_CRON";
				break;
			case LOG_DAEMON:
				escaped_value = "LOG_DAEMON";
				break;
			case LOG_MAIL:
				escaped_value = "LOG_MAIL";
				break;
			case LOG_USER:
				escaped_value = "LOG_USER";
				break;
			case LOG_LOCAL0:
				escaped_value = "LOG_LOCAL0";
				break;
			case LOG_LOCAL1:
				escaped_value = "LOG_LOCAL1";
				break;
			case LOG_LOCAL2:
				escaped_value = "LOG_LOCAL2";
				break;
			case LOG_LOCAL3:
				escaped_value = "LOG_LOCAL3";
				break;
			case LOG_LOCAL4:
				escaped_value = "LOG_LOCAL4";
				break;
			case LOG_LOCAL5:
				escaped_value = "LOG_LOCAL5";
				break;
			case LOG_LOCAL6:
				escaped_value = "LOG_LOCAL6";
				break;
			case LOG_LOCAL7:
				escaped_value = "LOG_LOCAL7";
				break;
		}
		rspamd_fprintf (f, " <type facility=\"%s\">syslog</type>" EOL, escaped_value);
	}
	rspamd_fprintf (f, "</logging>" EOL);
	/* Print footer comment */
	rspamd_fprintf (f, "<!-- End of logging section -->" EOL EOL);

	return TRUE;
}

/* Modules */
static gboolean
xml_dump_modules_paths (struct config_file *cfg, FILE *f)
{
	GList                          *cur;
	gchar                          *escaped_value;
	struct script_module           *module;

	/* Print header comment */
	rspamd_fprintf (f, "<!-- Modules section -->" EOL);
	rspamd_fprintf (f, "<modules>" EOL);

	cur = cfg->script_modules;
	while (cur) {
		module = cur->data;
		escaped_value = g_markup_escape_text (module->path, -1);
		rspamd_fprintf (f, " <path>%s</path>" EOL, escaped_value);
		g_free (escaped_value);
		cur = g_list_next (cur);
	}

	rspamd_fprintf (f, "</modules>" EOL);
	/* Print footer comment */
	rspamd_fprintf (f, "<!-- End of modules section -->" EOL EOL);

	return TRUE;
}


#define CHECK_RES do { if (!res) { fclose (f); return FALSE; } } while (0)
gboolean 
xml_dump_config (struct config_file *cfg, const gchar *filename)
{
	FILE *f;
	gboolean res = FALSE;

	f = fopen (filename, "w");
	if (f == NULL) {
		msg_err ("cannot open file '%s': %s", filename, strerror (errno));
		return FALSE;
	}
	
	/* Header */
	rspamd_fprintf (f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" EOL "<rspamd>" EOL);
	/* Now dump all parts of config */
	res = xml_dump_main (cfg, f);
	CHECK_RES;
	res = xml_dump_logging (cfg, f);
	CHECK_RES;
	res = xml_dump_variables (cfg, f);
	CHECK_RES;
	res = xml_dump_composites (cfg, f);
	CHECK_RES;
	res = xml_dump_workers (cfg, f);
	CHECK_RES;
	res = xml_dump_modules (cfg, f);
	CHECK_RES;
	res = xml_dump_classifiers (cfg, f);
	CHECK_RES;
	res = xml_dump_modules_paths (cfg, f);
	CHECK_RES;
	/* Footer */
	rspamd_fprintf (f, "</rspamd>" EOL);
	fclose (f);

	return TRUE;
}
