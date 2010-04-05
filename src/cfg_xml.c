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

/* Maximum attributes for param */
#define MAX_PARAM 64

#define NULL_ATTR 	\
{					\
	NULL,			\
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
	XML_SECTION_FACTORS,
	XML_SECTION_MODULE,
	XML_SECTION_MODULES,
	XML_SECTION_VIEW,
	XML_SECTION_SETTINGS
};

struct xml_config_param {
	const char *name;
	element_handler_func handler;
	int offset;
	gpointer user_data;
};

struct xml_parser_rule {
	enum xml_config_section section;
	struct xml_config_param params[MAX_PARAM];
	struct xml_config_param default_param;
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
			NULL_ATTR
		},
		NULL_ATTR
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
			NULL_ATTR
		},
		NULL_ATTR
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
			NULL,
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
				"cache_file",
				xml_handle_string,
				G_STRUCT_OFFSET (struct metric, cache_filename),
				NULL
			},
			NULL_ATTR
		},
		NULL_ATTR
	},
	{ XML_SECTION_CLASSIFIER, {
			NULL_ATTR
		},
		NULL_ATTR
	},
	{ XML_SECTION_FACTORS, {
			{
				"grow_factor",
				xml_handle_double,
				G_STRUCT_OFFSET (struct config_file, grow_factor),
				NULL
			},
			NULL_ATTR
		},
		{
			NULL,
			handle_factor,
			0,
			NULL
		}
	},
	{ XML_SECTION_MODULE, {
			NULL_ATTR
		},
		{
			NULL,
			handle_module_opt,
			0,
			NULL
		}
	},
	{ XML_SECTION_MODULES, {
			NULL_ATTR
		},
		NULL_ATTR
	},
	{ XML_SECTION_VIEW, {
			NULL_ATTR
		},
		NULL_ATTR
	},
	{ XML_SECTION_SETTINGS, {
			NULL_ATTR
		},
		NULL_ATTR
	}
};

GQuark
xml_error_quark (void)
{
	return g_quark_from_static_string ("xml-error-quark");
}


static inline gboolean
extract_attr (const gchar *attr, const gchar **attribute_names, const gchar **attribute_values, gchar **res) 
{
	const gchar **cur_attr, **cur_value;

	cur_attr = attribute_names;
	cur_value = attribute_values;

	while (*cur_attr && *cur_value) {
		if (g_ascii_strcasecmp (*cur_attr, attr)) {
			*res = (gchar *) *cur_value;
			return TRUE;
		}
		cur_attr ++;
		cur_value ++;
	}

	return FALSE;
}

static inline char*
xml_asciiz_string (memory_pool_t *pool, const gchar *text, gsize len)
{
	char	                       *val;

	val = memory_pool_alloc (pool, len + 1);
	g_strlcpy (val, text, len + 1);

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
	int                             i;
	
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
				param = &rule->default_param;
				/* Call default handler */
				return param->handler (ctx->cfg, ctx, ctx->cur_attrs, value, param->user_data, dest_struct, param->offset);
			}
		}
	}

	return FALSE;
}

/* Handlers */
/* Specific handlers */

gboolean 
handle_log_type (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	char                           *val;
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
		if (g_ascii_strncasecmp (val, "LOG_AUTH", sizeof ("LOG_AUTH") - 1) == 0) {
			cfg->log_facility = LOG_AUTH;
		}
		else if (g_ascii_strncasecmp (val, "LOG_CRON", sizeof ("LOG_CRON") - 1) == 0) {
			cfg->log_facility = LOG_CRON;
		}
		else if (g_ascii_strncasecmp (val, "LOG_DAEMON", sizeof ("LOG_DAEMON") - 1) == 0) {
			cfg->log_facility = LOG_DAEMON;
		}
		else if (g_ascii_strncasecmp (val, "LOG_MAIL", sizeof ("LOG_MAIL") - 1) == 0) {
			cfg->log_facility = LOG_MAIL;
		}
		else if (g_ascii_strncasecmp (val, "LOG_USER", sizeof ("LOG_USER") - 1) == 0) {
			cfg->log_facility = LOG_USER;
		}
		else if (g_ascii_strncasecmp (val, "LOG_LOCAL0", sizeof ("LOG_LOCAL0") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL0;
		}
		else if (g_ascii_strncasecmp (val, "LOG_LOCAL1", sizeof ("LOG_LOCAL1") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL1;
		}
		else if (g_ascii_strncasecmp (val, "LOG_LOCAL2", sizeof ("LOG_LOCAL2") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL2;
		}
		else if (g_ascii_strncasecmp (val, "LOG_LOCAL3", sizeof ("LOG_LOCAL3") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL3;
		}
		else if (g_ascii_strncasecmp (val, "LOG_LOCAL4", sizeof ("LOG_LOCAL4") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL4;
		}
		else if (g_ascii_strncasecmp (val, "LOG_LOCAL5", sizeof ("LOG_LOCAL5") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL5;
		}
		else if (g_ascii_strncasecmp (val, "LOG_LOCAL6", sizeof ("LOG_LOCAL6") - 1) == 0) {
			cfg->log_facility = LOG_LOCAL6;
		}
		else if (g_ascii_strncasecmp (val, "LOG_LOCAL7", sizeof ("LOG_LOCAL7") - 1) == 0) {
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
handle_log_level (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
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

gboolean 
worker_handle_param (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	struct worker_conf             *wrk = ctx->other_data;
	char                           *name;

	if ((name = g_hash_table_lookup (attrs, "name")) == NULL) {
		msg_err ("worker param tag must have \"name\" attribute");
		return FALSE;
	}

	g_hash_table_insert (wrk->params, name, memory_pool_strdup (cfg->cfg_pool, data));

	return TRUE;
}
gboolean 
worker_handle_type (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	struct worker_conf             *wrk = ctx->other_data;

	
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
	else if (g_ascii_strcasecmp (data, "fuzzy") == 0) {
		wrk->type = TYPE_FUZZY;
		wrk->has_socket = FALSE;
	}
	else {
		msg_err ("unknown worker type: %s", data);
		return FALSE;
	}

	return TRUE;
}

gboolean 
worker_handle_bind (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	struct worker_conf             *wrk = ctx->other_data;

	if (!parse_bind_line (cfg, wrk, data)) {
		msg_err ("cannot parse bind_socket: %s", data);
		return FALSE;
	}

	return TRUE;
}

gboolean 
handle_factor (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	char                           *name, *err;
	double                         *value;

	if ((name = g_hash_table_lookup (attrs, "name")) == NULL) {
		msg_err ("factor tag must have \"name\" attribute");
		return FALSE;
	}

	value = memory_pool_alloc (cfg->cfg_pool, sizeof (double));

	errno = 0;
	*value = strtod (data, &err);
	if (errno != 0 || (err != NULL && *err != 0)) {
		msg_err ("invalid number: %s, %s", data, strerror (errno));
		return FALSE;
	}
	
	g_hash_table_insert (cfg->factors, name, value);

	return TRUE;
}

gboolean 
handle_module_opt (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	char	                       *name, *val;
	GList                          *cur_opt;
	struct module_opt              *cur;
	gboolean                        is_lua = FALSE;
	
	if ((name = g_hash_table_lookup (attrs, "name")) == NULL) {
		msg_err ("param tag must have \"name\" attribute");
		return FALSE;
	}
	
	/* Check for lua */
	if ((val = g_hash_table_lookup (attrs, "lua")) != NULL) {
		if (g_ascii_strcasecmp (val, "yes") == 0) {
			is_lua = TRUE;
		}
	}
	cur_opt = g_hash_table_lookup (cfg->modules_opts, ctx->section_name);
	if (cur_opt == NULL) {
		/* Insert new option structure */
		cur = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct module_opt));
		cur->param = name;
		cur->value = data;
		cur->is_lua = is_lua;
		cur_opt = g_list_prepend (NULL, cur);
		g_hash_table_insert (cfg->modules_opts, memory_pool_strdup (cfg->cfg_pool, ctx->section_name), cur_opt);
	}
	else {
		/* First try to find option with this name */
		while (cur_opt) {
			cur = cur_opt->data;
			if (strcmp (cur->param, name) == 0) {
				/* cur->value is in pool */
				cur->value = data;
				cur->is_lua = is_lua;
				return TRUE;
			}
			cur_opt = g_list_next (cur_opt);
		}
		/* Not found, insert */
		cur = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct module_opt));
		cur->param = name;
		cur->value = data;
		cur->is_lua = is_lua;
		/* Slow way, but we cannot prepend here as we need to modify pointer inside module_options hash */
		cur_opt = g_list_append (cur_opt, cur);
	}

	return TRUE;
}

/* Handle lua tag */
gboolean 
handle_lua (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	gchar                        *val;
	lua_State                    *L = cfg->lua_state;

	/* First check for global variable 'config' */
	lua_getglobal (L, "config");

	if (lua_isnil (L, 1)) {
		/* Assign global table to set up attributes */
		lua_newtable (L);
		lua_setglobal (L, "config");
		/* Now config table can be used for configuring rspamd */
	}
	/* First check "src" attribute */
	if ((val = g_hash_table_lookup (attrs, "src")) != NULL) {
		if (luaL_dofile (L, val) != 0) {
			msg_err ("cannot load lua file %s: %s", val, lua_tostring (L, -1));
			return FALSE;
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

/* Common handlers */
gboolean 
xml_handle_string (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	/* Simply assign pointer to pointer */
	gchar                       **dest;

	dest = (char **)G_STRUCT_MEMBER_P (dest_struct, offset);
	*dest = memory_pool_strdup (cfg->cfg_pool, data);

	return TRUE;
}


gboolean 
xml_handle_size (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	gsize                      *dest;

	dest = (gsize *)G_STRUCT_MEMBER_P (dest_struct, offset);
	*dest = parse_limit (data);
	
	return TRUE;
}

gboolean 
xml_handle_seconds (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	time_t                      *dest;

	dest = (time_t *)G_STRUCT_MEMBER_P (dest_struct, offset);
	*dest = parse_seconds (data);
	
	return TRUE;
}

gboolean 
xml_handle_boolean (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
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
xml_handle_double (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	double                      *dest;
	char                        *err = NULL;

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
xml_handle_int (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	int                         *dest;
	char                        *err = NULL;

	dest = (int *)G_STRUCT_MEMBER_P (dest_struct, offset);
	errno = 0;
	*dest = strtol (data, &err, 10);
	if (errno != 0 || (err != NULL && *err != 0)) {
		msg_err ("invalid number: %s, %s", data, strerror (errno));
		return FALSE;
	}
	
	return TRUE;
}

gboolean 
xml_handle_uint32 (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	uint32_t                    *dest;
	char                        *err = NULL;

	dest = (uint32_t *)G_STRUCT_MEMBER_P (dest_struct, offset);
	errno = 0;
	*dest = strtoul (data, &err, 10);
	if (errno != 0 || (err != NULL && *err != 0)) {
		msg_err ("invalid number: %s, %s", data, strerror (errno));
		return FALSE;
	}
	
	return TRUE;
}

gboolean 
xml_handle_uint16 (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	uint16_t                    *dest;
	char                        *err = NULL;

	dest = (uint16_t *)G_STRUCT_MEMBER_P (dest_struct, offset);
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
	gchar *res;

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
					g_strlcpy (ud->section_name, res, sizeof (ud->section_name));
					ud->state = XML_READ_MODULE;
				}
				else {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "param 'name' is required for tag 'module'");
					ud->state = XML_ERROR;
				}
			}
			else if (g_ascii_strcasecmp (element_name, "factors") == 0) {
				ud->state = XML_READ_FACTORS;	
			}
			else if (g_ascii_strcasecmp (element_name, "logging") == 0) {
				ud->state = XML_READ_LOGGING;	
			}
			else if (g_ascii_strcasecmp (element_name, "metric") == 0) {
				if (extract_attr ("name", attribute_names, attribute_values, &res)) {
					g_strlcpy (ud->section_name, res, sizeof (ud->section_name));
					ud->state = XML_READ_METRIC;
					/* Create object */
					ud->other_data = memory_pool_alloc0 (ud->cfg->cfg_pool, sizeof (struct metric));
				}
				else {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "param 'name' is required for tag 'metric'");
					ud->state = XML_ERROR;
				}
			}
			else if (g_ascii_strcasecmp (element_name, "classifier") == 0) {
				if (extract_attr ("type", attribute_names, attribute_values, &res)) {
					g_strlcpy (ud->section_name, res, sizeof (ud->section_name));
					ud->state = XML_READ_CLASSIFIER;
					/* Create object */
					ud->other_data = check_classifier_cfg (ud->cfg, NULL);
				}
				else {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "param 'type' is required for tag 'classifier'");
					ud->state = XML_ERROR;
				}
			}
			else if (g_ascii_strcasecmp (element_name, "worker") == 0) {
				ud->state = XML_READ_WORKER;
				/* Create object */
				ud->other_data = check_worker_conf (ud->cfg, NULL);
			}
			else if (g_ascii_strcasecmp (element_name, "variable") == 0) {
				if (extract_attr ("name", attribute_names, attribute_values, &res)) {
					g_strlcpy (ud->section_name, res, sizeof (ud->section_name));
					ud->state = XML_READ_VARIABLE;
				}
				else {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "param 'name' is required for tag 'variable'");
					ud->state = XML_ERROR;
				}
				
			} 
			else {
				/* Extract other tags */
				g_strlcpy (ud->section_name, element_name, sizeof (ud->section_name));
				ud->state = XML_READ_VALUE;
			}
			break;
		case XML_READ_MODULE:
		case XML_READ_FACTORS:
		case XML_READ_CLASSIFIER:
		case XML_READ_STATFILE:
		case XML_READ_WORKER:
		case XML_READ_LOGGING:
			/* Save attributes */
			ud->cur_attrs = process_attrs (ud->cfg, attribute_names, attribute_values);
			break;
		default:
			*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "element %s is unexpected in this state", element_name);
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
	gboolean res;
	
	switch (ud->state) {
		case XML_READ_MODULE:
			CHECK_TAG ("module", FALSE);
			break;
		case XML_READ_CLASSIFIER:
			CHECK_TAG ("classifier", FALSE);
			break;
		case XML_READ_STATFILE:
			CHECK_TAG ("statfile", FALSE);
			break;
		case XML_READ_FACTORS:
			CHECK_TAG ("factors", FALSE);
			break;
		case XML_READ_METRIC:
			CHECK_TAG ("metric", FALSE);
			if (res) {
				struct metric *m = ud->other_data;
				if (m->name == NULL) {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "metric attribute \"name\" is required but missing");
					ud->state = XML_ERROR;
					return;
				}
				if (m->classifier == NULL) {
					m->classifier = get_classifier ("winnow");
				}
				g_hash_table_insert (ud->cfg->metrics, m->name, m);
				ud->cfg->metrics_list = g_list_prepend (ud->cfg->metrics_list, m);
			}	
			break;
		case XML_READ_WORKER:
			CHECK_TAG ("worker", FALSE);
			if (res) {
				/* Insert object to list */
				ud->cfg->workers = g_list_prepend (ud->cfg->workers, ud->other_data);
			}
			break;
		case XML_READ_VARIABLE:
			CHECK_TAG ("variable", TRUE);
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
	char *val;
	struct config_file *cfg = ud->cfg;

	val = xml_asciiz_string (cfg->cfg_pool, text, text_len);

	switch (ud->state) {
		case XML_READ_MODULE:
			if (!call_param_handler (ud, ud->section_name, val, ud->other_data, XML_SECTION_MODULE)) {
				*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "cannot parse tag's '%s' data: %s", ud->section_name, val);
				ud->state = XML_ERROR;
			}
			break;
		case XML_READ_CLASSIFIER:
			if (!call_param_handler (ud, ud->section_name, val, ud->other_data, XML_SECTION_CLASSIFIER)) {
				*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "cannot parse tag's '%s' data: %s", ud->section_name, val);
				ud->state = XML_ERROR;
			}
			break;
		case XML_READ_STATFILE:
			break;
		case XML_READ_FACTORS:
			if (!call_param_handler (ud, ud->section_name, val, cfg, XML_SECTION_CLASSIFIER)) {
				*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "cannot parse tag's '%s' data: %s", ud->section_name, val);
				ud->state = XML_ERROR;
			}
			break;
		case XML_READ_METRIC:
			if (!call_param_handler (ud, ud->section_name, val, ud->other_data, XML_SECTION_METRIC)) {
				*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "cannot parse tag's '%s' data: %s", ud->section_name, val);
				ud->state = XML_ERROR;
			}
			break;
		case XML_READ_WORKER:
			if (!call_param_handler (ud, ud->section_name, val, ud->other_data, XML_SECTION_WORKER)) {
				*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "cannot parse tag's '%s' data: %s", ud->section_name, val);
				ud->state = XML_ERROR;
			}
			break;
		case XML_READ_VARIABLE:
		case XML_READ_VALUE:
			if (!call_param_handler (ud, ud->section_name, val, cfg, XML_SECTION_MAIN)) {
				*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "cannot parse tag's '%s' data: %s", ud->section_name, val);
				ud->state = XML_ERROR;
			}
			break;
		case XML_READ_LOGGING:
			if (!call_param_handler (ud, ud->section_name, val, cfg, XML_SECTION_LOGGING)) {
				*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "cannot parse tag's '%s' data: %s", ud->section_name, val);
				ud->state = XML_ERROR;
			}
			break;
		default:
			ud->state = XML_ERROR;
			break;
	}

}

void 
rspamd_xml_error (GMarkupParseContext *context, GError *error, gpointer user_data)
{
	struct rspamd_xml_userdata *ud = user_data;
	
	msg_err ("xml parser error: %s, at state %d", error->message, ud->state);
}


/* Dumper part */

/* Dump specific sections */

/* Dump main section variables */
static gboolean
xml_dump_main (struct config_file *cfg, FILE *f)
{
	char *escaped_str;
	
	/* Print header comment */
	fprintf (f, "<!-- Main section -->" CRLF);

	escaped_str = g_markup_escape_text (cfg->temp_dir, -1); 
	fprintf (f, "  <tempdir>%s</tempdir>" CRLF, escaped_str);
	g_free (escaped_str);

	escaped_str = g_markup_escape_text (cfg->pid_file, -1); 
	fprintf (f, "  <pidfile>%s</pidfile>" CRLF, escaped_str);
	g_free (escaped_str);

	escaped_str = g_markup_escape_text (cfg->filters_str, -1); 
	fprintf (f, "  <filters>%s</filters>" CRLF, escaped_str);
	g_free (escaped_str);

	if (cfg->checksum)  {
		escaped_str = g_markup_escape_text (cfg->checksum, -1); 
		fprintf (f, "  <checksum>%s</checksum>" CRLF, escaped_str);
		g_free (escaped_str);
	}

	fprintf (f, "  <raw_mode>%s</raw_mode>" CRLF, cfg->raw_mode ? "yes" : "no");

	/* Print footer comment */
	fprintf (f, "<!-- End of main section -->" CRLF);

	return TRUE;
}

/* Dump variables section */
static void
xml_variable_callback (gpointer key, gpointer value, gpointer user_data)
{
	FILE *f = user_data;
	char *escaped_key, *escaped_value;

	escaped_key = g_markup_escape_text (key, -1); 
	escaped_value = g_markup_escape_text (value, -1);
	fprintf (f,  "  <variable name=\"%s\">%s</variable>" CRLF, escaped_key, escaped_value);
	g_free (escaped_key);
	g_free (escaped_value);
}

static gboolean
xml_dump_variables (struct config_file *cfg, FILE *f)
{
	/* Print header comment */
	fprintf (f, "<!-- Variables section -->" CRLF);

	/* Iterate through variables */
	g_hash_table_foreach (cfg->variables, xml_variable_callback, (gpointer)f);

	/* Print footer comment */
	fprintf (f, "<!-- End of variables section -->" CRLF);

	return TRUE;
}

/* Workers */
static void
xml_worker_param_callback (gpointer key, gpointer value, gpointer user_data)
{
	FILE *f = user_data;
	char *escaped_key, *escaped_value;

	escaped_key = g_markup_escape_text (key, -1); 
	escaped_value = g_markup_escape_text (value, -1);
	fprintf (f,  "    <param name=\"%s\">%s</param>" CRLF, escaped_key, escaped_value);
	g_free (escaped_key);
	g_free (escaped_value);
}

static gboolean
xml_dump_workers (struct config_file *cfg, FILE *f)
{
	GList *cur;
	struct worker_conf *wrk;
	char *escaped_str;

	/* Print header comment */
	fprintf (f, "<!-- Workers section -->" CRLF);

	/* Iterate through list */
	cur = g_list_first (cfg->workers);
	while (cur) {
		wrk = cur->data;
		
		fprintf (f, "<worker>" CRLF);
		switch (wrk->type) {
			case TYPE_WORKER:
				fprintf (f, "  <type>normal</type>" CRLF);
				break;
			case TYPE_CONTROLLER:
				fprintf (f, "  <type>controller</type>" CRLF);
				break;
			case TYPE_FUZZY:
				fprintf (f, "  <type>fuzzy</type>" CRLF);
				break;
			case TYPE_LMTP:
				fprintf (f, "  <type>lmtp</type>" CRLF);
				break;
		}
		escaped_str = g_markup_escape_text (wrk->bind_host, -1); 
		fprintf (f, "  <bind_socket>%s</bind_socket>" CRLF, escaped_str);
		g_free (escaped_str);

		fprintf (f, "  <count>%u</count>" CRLF, wrk->count);
		fprintf (f, "  <maxfiles>%u</maxfiles>" CRLF, wrk->rlimit_nofile);
		fprintf (f, "  <maxcore>%u</maxcore>" CRLF, wrk->rlimit_maxcore);
		
		/* Now dump other attrs */
		fprintf (f, "<!-- Other params -->" CRLF);
		g_hash_table_foreach (wrk->params, xml_worker_param_callback, f);

		fprintf (f, "</worker>" CRLF);

		cur = g_list_next (cur);
	}

	/* Print footer comment */
	fprintf (f, "<!-- End of workers section -->" CRLF);

	return TRUE;
}

/* Modules dump */
static void
xml_module_callback (gpointer key, gpointer value, gpointer user_data)
{
	FILE *f = user_data;
	char *escaped_key, *escaped_value;
	GList *cur;
	struct module_opt *opt;
	
	escaped_key = g_markup_escape_text (key, -1); 
	fprintf (f, "<!-- %s -->" CRLF, escaped_key);
	fprintf (f, "<module name=\"%s\">" CRLF, escaped_key);
	g_free (escaped_key);

	cur = g_list_first (value);
	while (cur) {
		opt = cur->data;
		escaped_key = g_markup_escape_text (opt->param, -1); 
		escaped_value = g_markup_escape_text (opt->value, -1);
		fprintf (f,  "  <option name=\"%s\">%s</option>" CRLF, escaped_key, escaped_value);
		g_free (escaped_key);
		g_free (escaped_value);
		cur = g_list_next (cur);
	}
	fprintf (f, "</module>" CRLF);
}

static gboolean
xml_dump_modules (struct config_file *cfg, FILE *f)
{
	/* Print header comment */
	fprintf (f, "<!-- Modules section -->" CRLF);

	/* Iterate through variables */
	g_hash_table_foreach (cfg->modules_opts, xml_module_callback, (gpointer)f);

	/* Print footer comment */
	fprintf (f, "<!-- End of modules section -->" CRLF);

	return TRUE;
}

#define CHECK_RES do { if (!res) { fclose (f); return FALSE; } } while (0)
gboolean 
xml_dump_config (struct config_file *cfg, const char *filename)
{
	FILE *f;
	gboolean res = FALSE;

	f = fopen (filename, "w");
	if (f == NULL) {
		msg_err ("cannot open file '%s': %s", filename, strerror (errno));
		return FALSE;
	}
	
	/* Header */
	fprintf (f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" CRLF "<rspamd>" CRLF);
	/* Now dump all parts of config */
	res = xml_dump_main (cfg, f);
	CHECK_RES;
	res = xml_dump_variables (cfg, f);
	CHECK_RES;
	res = xml_dump_workers (cfg, f);
	CHECK_RES;
	res = xml_dump_modules (cfg, f);
	CHECK_RES;
	/* Footer */
	fprintf (f, "</rspamd>" CRLF);
	fclose (f);

	return TRUE;
}
