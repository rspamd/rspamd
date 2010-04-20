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

enum xml_config_section {
	XML_SECTION_MAIN,
    XML_SECTION_LOGGING, 
	XML_SECTION_WORKER,
	XML_SECTION_METRIC,
	XML_SECTION_CLASSIFIER,
	XML_SECTION_STATFILE,
	XML_SECTION_FACTORS,
	XML_SECTION_MODULE,
	XML_SECTION_MODULES,
	XML_SECTION_VIEW
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
			{
				"option",
				handle_classifier_opt,
				0,
				NULL
			},
			NULL_ATTR
		},
		NULL_ATTR
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
		NULL_ATTR
	},
	{ XML_SECTION_FACTORS, {
			{
				"grow_factor",
				xml_handle_double,
				G_STRUCT_OFFSET (struct config_file, grow_factor),
				NULL
			},
			{
				"factor",
				handle_factor,
				0,
				NULL
			},
			NULL_ATTR
		},
		NULL_ATTR
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
			{
				"path",
				handle_module_path,
				0,
				NULL
			},
			NULL_ATTR
		},
		NULL_ATTR
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
				"symbols",
				handle_view_symbols,
				0,
				NULL
			},
			NULL_ATTR
		},
		NULL_ATTR
	},
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
		if (g_ascii_strcasecmp (*cur_attr, attr) == 0) {
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
	
	msg_err ("could not find handler for tag %s at section %d", name, section);
	return FALSE;
}

/* Handlers */
/* Specific handlers */

/* Logging section */
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

/* Worker section */
gboolean 
worker_handle_param (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	struct worker_conf             *wrk = ctx->section_pointer;
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
	struct worker_conf             *wrk = ctx->section_pointer;

	if (!parse_bind_line (cfg, wrk, data)) {
		msg_err ("cannot parse bind_socket: %s", data);
		return FALSE;
	}

	return TRUE;
}

/* Factors section */
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

/* Modules section */
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
	cur_opt = ctx->section_pointer;
	/* Insert option */
	cur = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct module_opt));
	cur->param = name;
	cur->value = data;
	cur->is_lua = is_lua;
	ctx->section_pointer = g_list_prepend (ctx->section_pointer, cur);

	return TRUE;
}

/* Handle lua tag */
gboolean 
handle_lua (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
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
			getcwd (cur_dir, PATH_MAX);
			if (chdir (lua_dir) != -1) {
				if (luaL_dofile (L, lua_file) != 0) {
					msg_err ("cannot load lua file %s: %s", val, lua_tostring (L, -1));
					chdir (cur_dir);
					g_free (cur_dir);
					g_free (tmp1);
					g_free (tmp2);
					return FALSE;
				}
			}
			else {
				msg_err ("cannot chdir to %s: %s", lua_dir, strerror (errno));;
				chdir (cur_dir);
				g_free (cur_dir);
				g_free (tmp1);
				g_free (tmp2);
				return FALSE;
			
			}
			chdir (cur_dir);
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
handle_module_path (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	struct stat st;
	struct script_module *cur;
	glob_t globbuf;
	char *pattern;
	size_t len;
	int i;

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
		}
		else {
			msg_err ("glob failed: %s", strerror (errno));
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
handle_variable (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
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
handle_composite (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
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
handle_view_ip (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	struct rspamd_view          *view = ctx->section_pointer;

	if (!add_view_ip (view, data)) {
		msg_err ("invalid ip line in view definition: ip = '%s'", data);
		return FALSE;
	}
	
	return TRUE;
}
gboolean 
handle_view_client_ip (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	struct rspamd_view          *view = ctx->section_pointer;

	if (!add_view_client_ip (view, data)) {
		msg_err ("invalid ip line in view definition: ip = '%s'", data);
		return FALSE;
	}
	
	return TRUE;
}
gboolean 
handle_view_from (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	struct rspamd_view          *view = ctx->section_pointer;

	if (!add_view_from (view, data)) {
		msg_err ("invalid from line in view definition: ip = '%s'", data);
		return FALSE;
	}
	
	return TRUE;
}
gboolean 
handle_view_symbols (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	struct rspamd_view          *view = ctx->section_pointer;

	if (!add_view_symbols (view, data)) {
		msg_err ("invalid symbols line in view definition: ip = '%s'", data);
		return FALSE;
	}
	cfg->domain_settings_str = memory_pool_strdup (cfg->cfg_pool, data);

	return TRUE;
}

/* Settings */
gboolean 
handle_user_settings (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	if (!read_settings (data, cfg, cfg->user_settings)) {
		msg_err ("cannot read settings %s", data);
		return FALSE;
	}
	cfg->user_settings_str = memory_pool_strdup (cfg->cfg_pool, data);

	return TRUE;
}
gboolean 
handle_domain_settings (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	if (!read_settings (data, cfg, cfg->domain_settings)) {
		msg_err ("cannot read settings %s", data);
		return FALSE;
	}

	return TRUE;
}

/* Classifier */
gboolean 
handle_classifier_tokenizer (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	struct classifier_config     *ccf = ctx->section_pointer;
	
	if ((ccf->tokenizer = get_tokenizer (data)) == NULL) {
		msg_err ("unknown tokenizer %s", data);
		return FALSE;
	}

	return TRUE;
}

gboolean 
handle_classifier_opt (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	struct classifier_config     *ccf = ctx->section_pointer;
	gchar                        *val;
	
	if ((val = g_hash_table_lookup (attrs, "name")) == NULL) {
		msg_err ("'name' attribute is required for tag 'option'");
		return FALSE;
	}

	g_hash_table_insert (ccf->opts, val, memory_pool_strdup (cfg->cfg_pool, data));
	return TRUE;
}

/* Statfile */
gboolean 
handle_statfile_normalizer (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	struct statfile             *st = ctx->section_pointer;
	
	if (!parse_normalizer (cfg, st, data)) {
		msg_err ("cannot parse normalizer string: %s", data);
		return FALSE;
	}
	
	return TRUE;
}

gboolean 
handle_statfile_binlog (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
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
handle_statfile_binlog_rotate (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	struct statfile             *st = ctx->section_pointer;

	if (st->binlog == NULL) {
		st->binlog = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile_binlog_params));
	}
	st->binlog->rotate_time = parse_seconds (data);
	
	return TRUE;
}

gboolean 
handle_statfile_binlog_master (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, int offset)
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
	struct classifier_config   *ccf;
	gchar                      *res;

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
			else if (g_ascii_strcasecmp (element_name, "factors") == 0) {
				ud->state = XML_READ_FACTORS;	
			}
			else if (g_ascii_strcasecmp (element_name, "modules") == 0) {
				ud->state = XML_READ_MODULES;	
			}
			else if (g_ascii_strcasecmp (element_name, "logging") == 0) {
				ud->state = XML_READ_LOGGING;	
			}
			else if (g_ascii_strcasecmp (element_name, "metric") == 0) {
				if (extract_attr ("name", attribute_names, attribute_values, &res)) {
					g_strlcpy (ud->section_name, res, sizeof (ud->section_name));
					ud->state = XML_READ_METRIC;
					/* Create object */
					ud->section_pointer = memory_pool_alloc0 (ud->cfg->cfg_pool, sizeof (struct metric));
				}
				else {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "param 'name' is required for tag 'metric'");
					ud->state = XML_ERROR;
				}
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
			else if (g_ascii_strcasecmp (element_name, "view") == 0) {
				ud->state = XML_READ_VIEW;
				/* Create object */
				ud->section_pointer = init_view (ud->cfg->cfg_pool);
			}
			else {
				/* Extract other tags */
				g_strlcpy (ud->section_name, element_name, sizeof (ud->section_name));
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
				g_strlcpy (ud->section_name, element_name, sizeof (ud->section_name));
				/* Save attributes */
				ud->cur_attrs = process_attrs (ud->cfg, attribute_names, attribute_values);
			}
			break;
		case XML_READ_MODULE:
		case XML_READ_MODULES:
		case XML_READ_FACTORS:
		case XML_READ_STATFILE:
		case XML_READ_WORKER:
		case XML_READ_LOGGING:
			g_strlcpy (ud->section_name, element_name, sizeof (ud->section_name));
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
	struct metric              *m;
	struct classifier_config   *ccf;
	struct statfile            *st;
	gboolean res;
	
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
		case XML_READ_FACTORS:
			CHECK_TAG ("factors", FALSE);
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

	if (*text == '\n') {
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
		case XML_READ_FACTORS:
			if (!call_param_handler (ud, ud->section_name, val, cfg, XML_SECTION_FACTORS)) {
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
		default:
			ud->state = XML_ERROR;
			break;
	}

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
		case XML_READ_FACTORS:
			return "read factors section";
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
		case XML_ERROR:
			return "error occured";
		case XML_END:
			return "read final tag";
	}
	/* Unreached */
	return "unknown state";
}

void 
rspamd_xml_error (GMarkupParseContext *context, GError *error, gpointer user_data)
{
	struct rspamd_xml_userdata *ud = user_data;
	
	msg_err ("xml parser error: %s, at state \"%s\"", error->message, xml_state_to_string (ud));
}


/* Dumper part */

/* Dump specific sections */

/* Dump main section variables */
static gboolean
xml_dump_main (struct config_file *cfg, FILE *f)
{
	char *escaped_str;
	
	/* Print header comment */
	fprintf (f, "<!-- Main section -->" EOL);

	escaped_str = g_markup_escape_text (cfg->temp_dir, -1); 
	fprintf (f, "<tempdir>%s</tempdir>" EOL, escaped_str);
	g_free (escaped_str);

	escaped_str = g_markup_escape_text (cfg->pid_file, -1); 
	fprintf (f, "<pidfile>%s</pidfile>" EOL, escaped_str);
	g_free (escaped_str);

	escaped_str = g_markup_escape_text (cfg->filters_str, -1); 
	fprintf (f, "<filters>%s</filters>" EOL, escaped_str);
	g_free (escaped_str);
	
	if (cfg->user_settings_str) {
		escaped_str = g_markup_escape_text (cfg->user_settings_str, -1); 
		fprintf (f, "<user_settings>%s</user_settings>" EOL, escaped_str);
		g_free (escaped_str);
	}
	if (cfg->domain_settings_str) {
		escaped_str = g_markup_escape_text (cfg->domain_settings_str, -1); 
		fprintf (f, "<domain_settings>%s</domain_settings>" EOL, escaped_str);
		g_free (escaped_str);
	}
	fprintf (f, "<statfile_pool_size>%llu</statfile_pool_size>" EOL, (long long unsigned)cfg->max_statfile_size);

	if (cfg->checksum)  {
		escaped_str = g_markup_escape_text (cfg->checksum, -1); 
		fprintf (f, "<checksum>%s</checksum>" EOL, escaped_str);
		g_free (escaped_str);
	}

	fprintf (f, "<raw_mode>%s</raw_mode>" EOL, cfg->raw_mode ? "yes" : "no");

	/* Print footer comment */
	fprintf (f, "<!-- End of main section -->" EOL EOL);

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
	fprintf (f,  "<variable name=\"%s\">%s</variable>" EOL, escaped_key, escaped_value);
	g_free (escaped_key);
	g_free (escaped_value);
}

static gboolean
xml_dump_variables (struct config_file *cfg, FILE *f)
{
	/* Print header comment */
	fprintf (f, "<!-- Variables section -->" EOL);

	/* Iterate through variables */
	g_hash_table_foreach (cfg->variables, xml_variable_callback, (gpointer)f);

	/* Print footer comment */
	fprintf (f, "<!-- End of variables section -->" EOL EOL);

	return TRUE;
}

/* Dump factors section */
static void
xml_factors_callback (gpointer key, gpointer value, gpointer user_data)
{
	FILE *f = user_data;
	char *escaped_key;

	escaped_key = g_markup_escape_text (key, -1); 
	fprintf (f,  " <factor name=\"%s\">%.2f</factor>" EOL, escaped_key, *(double *)value);
	g_free (escaped_key);
}

static gboolean
xml_dump_factors (struct config_file *cfg, FILE *f)
{
	/* Print header comment */
	fprintf (f, "<!-- Factors section -->" EOL "<factors>" EOL );

	/* Iterate through variables */
	g_hash_table_foreach (cfg->factors, xml_factors_callback, (gpointer)f);

	/* Print footer comment */
	fprintf (f, "</factors>" EOL "<!-- End of factors section -->" EOL EOL);

	return TRUE;
}

/* Composites section */
static void
xml_composite_callback (gpointer key, gpointer value, gpointer user_data)
{
	FILE *f = user_data;
	struct expression *expr;
	char *escaped_key, *escaped_value;
	
	expr = value;

	escaped_key = g_markup_escape_text (key, -1); 
	escaped_value = g_markup_escape_text (expr->orig, -1);
	fprintf (f,  "<composite name=\"%s\">%s</composite>" EOL, escaped_key, escaped_value);
	g_free (escaped_key);
	g_free (escaped_value);
}

static gboolean
xml_dump_composites (struct config_file *cfg, FILE *f)
{
	/* Print header comment */
	fprintf (f, "<!-- Composites section -->" EOL);

	/* Iterate through variables */
	g_hash_table_foreach (cfg->composite_symbols, xml_composite_callback, (gpointer)f);

	/* Print footer comment */
	fprintf (f, "<!-- End of composites section -->" EOL EOL);

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
	fprintf (f,  "    <param name=\"%s\">%s</param>" EOL, escaped_key, escaped_value);
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
	fprintf (f, "<!-- Workers section -->" EOL);

	/* Iterate through list */
	cur = g_list_first (cfg->workers);
	while (cur) {
		wrk = cur->data;
		
		fprintf (f, "<worker>" EOL);
		switch (wrk->type) {
			case TYPE_WORKER:
				fprintf (f, "  <type>normal</type>" EOL);
				break;
			case TYPE_CONTROLLER:
				fprintf (f, "  <type>controller</type>" EOL);
				break;
			case TYPE_FUZZY:
				fprintf (f, "  <type>fuzzy</type>" EOL);
				break;
			case TYPE_LMTP:
				fprintf (f, "  <type>lmtp</type>" EOL);
				break;
		}
		escaped_str = g_markup_escape_text (wrk->bind_host, -1); 
		fprintf (f, "  <bind_socket>%s</bind_socket>" EOL, escaped_str);
		g_free (escaped_str);

		fprintf (f, "  <count>%u</count>" EOL, wrk->count);
		fprintf (f, "  <maxfiles>%u</maxfiles>" EOL, wrk->rlimit_nofile);
		fprintf (f, "  <maxcore>%u</maxcore>" EOL, wrk->rlimit_maxcore);
		
		/* Now dump other attrs */
		fprintf (f, "<!-- Other params -->" EOL);
		g_hash_table_foreach (wrk->params, xml_worker_param_callback, f);

		fprintf (f, "</worker>" EOL);

		cur = g_list_next (cur);
	}

	/* Print footer comment */
	fprintf (f, "<!-- End of workers section -->" EOL EOL);

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
	fprintf (f, "<!-- %s -->" EOL, escaped_key);
	fprintf (f, "<module name=\"%s\">" EOL, escaped_key);
	g_free (escaped_key);

	cur = g_list_first (value);
	while (cur) {
		opt = cur->data;
		escaped_key = g_markup_escape_text (opt->param, -1); 
		escaped_value = g_markup_escape_text (opt->value, -1);
		fprintf (f,  "  <option name=\"%s\">%s</option>" EOL, escaped_key, escaped_value);
		g_free (escaped_key);
		g_free (escaped_value);
		cur = g_list_next (cur);
	}
	fprintf (f, "</module>" EOL EOL);
}

static gboolean
xml_dump_modules (struct config_file *cfg, FILE *f)
{
	/* Print header comment */
	fprintf (f, "<!-- Modules section -->" EOL);

	/* Iterate through variables */
	g_hash_table_foreach (cfg->modules_opts, xml_module_callback, (gpointer)f);

	/* Print footer comment */
	fprintf (f, "<!-- End of modules section -->" EOL EOL);

	return TRUE;
}

/* Classifiers dump */
static void
xml_classifier_callback (gpointer key, gpointer value, gpointer user_data)
{
	FILE *f = user_data;
	char *escaped_key, *escaped_value;

	escaped_key = g_markup_escape_text (key, -1); 
	escaped_value = g_markup_escape_text (value, -1);
	fprintf (f,  " <option name=\"%s\">%s</option>" EOL, escaped_key, escaped_value);
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
	fprintf (f, "<!-- Classifiers section -->" EOL);

	/* Iterate through classifiers */
	cur = g_list_first (cfg->classifiers);
	while (cur) {
		ccf = cur->data;
		fprintf (f, "<classifier type=\"%s\">" EOL, ccf->classifier->name);
		fprintf (f, " <tokenizer>%s</tokenizer>" EOL, ccf->tokenizer->name);
		fprintf (f, " <metric>%s</metric>" EOL, ccf->metric);
		g_hash_table_foreach (ccf->opts, xml_classifier_callback, f);
		/* Statfiles */
		cur_st = g_list_first (ccf->statfiles);
		while (cur_st) {
			st = cur_st->data;
			fprintf (f, " <statfile>" EOL);
			fprintf (f, "  <symbol>%s</symbol>" EOL "  <size>%lu</size>" EOL "  <path>%s</path>" EOL,
						st->symbol, (long unsigned)st->size, st->path);
			fprintf (f, "  <normalizer>%s</normalizer>" EOL, st->normalizer_str);
			/* Binlog */
			if (st->binlog) {
				if (st->binlog->affinity == AFFINITY_MASTER) {
					fprintf (f, "  <binlog>master</binlog>" EOL);
				}
				else if (st->binlog->affinity == AFFINITY_SLAVE) {
					fprintf (f, "  <binlog>slave</binlog>" EOL);
					fprintf (f, "  <binlog_master>%s:%d</binlog_master>" EOL, 
							inet_ntoa (st->binlog->master_addr), ntohs (st->binlog->master_port)); 
				}
				fprintf (f, "  <binlog_rotate>%lu</binlog_rotate>" EOL, (long unsigned)st->binlog->rotate_time);
			}
			fprintf (f, " </statfile>" EOL);
			cur_st = g_list_next (cur_st);
		}

		fprintf (f, "</classifier>" EOL);
		cur = g_list_next (cur);
	}

	/* Print footer comment */
	fprintf (f, "<!-- End of classifiers section -->" EOL EOL);

	return TRUE;

}

/* Logging section */
static gboolean
xml_dump_logging (struct config_file *cfg, FILE *f)
{
	gchar *escaped_value;

	/* Print header comment */
	fprintf (f, "<!-- Logging section -->" EOL);
	fprintf (f, "<logging>" EOL);
	
	/* Level */
	if (cfg->log_level < G_LOG_LEVEL_WARNING) {
		fprintf (f, " <level>error</level>" EOL);
	}
	else if (cfg->log_level < G_LOG_LEVEL_MESSAGE) {
		fprintf (f, " <level>warning</level>" EOL);
	}
	else if (cfg->log_level < G_LOG_LEVEL_DEBUG) {
		fprintf (f, " <level>info</level>" EOL);
	}
	else {
		fprintf (f, " <level>debug</level>" EOL);
	}
	
	/* Other options */
	fprintf (f, " <log_urls>%s</log_urls>" EOL, cfg->log_urls ? "yes" : "no");
	if (cfg->log_buf_size != 0) {
		fprintf (f, " <log_buffer>%u</log_buffer>" EOL, (unsigned)cfg->log_buf_size);
	}
	if (cfg->debug_ip_map != NULL) {
		escaped_value = g_markup_escape_text (cfg->debug_ip_map, -1);
		fprintf (f, " <debug_ip>%s</debug_ip>" EOL, escaped_value);
		g_free (escaped_value);
	}
	
	/* Handle type */
	if (cfg->log_type == RSPAMD_LOG_FILE) {
		escaped_value = g_markup_escape_text (cfg->log_file, -1);
		fprintf (f, " <type filename=\"%s\">file</type>" EOL, escaped_value);
		g_free (escaped_value);
	}
	else if (cfg->log_type == RSPAMD_LOG_CONSOLE) {
		fprintf (f, " <type>console</type>" EOL);
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
		fprintf (f, " <type facility=\"%s\">syslog</type>" EOL, escaped_value);
	}
	fprintf (f, "</logging>" EOL);
	/* Print footer comment */
	fprintf (f, "<!-- End of logging section -->" EOL EOL);

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
	fprintf (f, "<!-- Modules section -->" EOL);
	fprintf (f, "<modules>" EOL);

	cur = cfg->script_modules;
	while (cur) {
		module = cur->data;
		escaped_value = g_markup_escape_text (module->path, -1);
		fprintf (f, " <path>%s</path>" EOL, escaped_value);
		g_free (escaped_value);
		cur = g_list_next (cur);
	}

	fprintf (f, "</modules>" EOL);
	/* Print footer comment */
	fprintf (f, "<!-- End of modules section -->" EOL EOL);

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
	fprintf (f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" EOL "<rspamd>" EOL);
	/* Now dump all parts of config */
	res = xml_dump_main (cfg, f);
	CHECK_RES;
	res = xml_dump_logging (cfg, f);
	CHECK_RES;
	res = xml_dump_variables (cfg, f);
	CHECK_RES;
	res = xml_dump_factors (cfg, f);
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
	fprintf (f, "</rspamd>" EOL);
	fclose (f);

	return TRUE;
}
