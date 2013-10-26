/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
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

#include "view.h"
#include "map.h"
#include "expressions.h"
#include "settings.h"

#include "lua/lua_common.h"

enum xml_read_state {
	XML_READ_START,
	XML_READ_PARAM,
	XML_READ_MODULE,
	XML_READ_MODULE_META,
	XML_READ_MODULES,
	XML_READ_CLASSIFIER,
	XML_READ_STATFILE,
	XML_READ_METRIC,
	XML_READ_WORKER,
	XML_READ_VIEW,
	XML_READ_LOGGING,
	XML_READ_OPTIONS,
	XML_READ_VALUE,
	XML_SKIP_ELEMENTS,
	XML_ERROR,
	XML_SUBPARSER,
	XML_END
};

/* Maximum attributes for param */
#define MAX_PARAM 64

#define EOL "\n"

#if 0
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
	XML_SECTION_OPTIONS,
    XML_SECTION_LOGGING, 
	XML_SECTION_WORKER,
	XML_SECTION_METRIC,
	XML_SECTION_CLASSIFIER,
	XML_SECTION_STATFILE,
	XML_SECTION_MODULE,
	XML_SECTION_MODULE_META,
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

struct xml_subparser {
	enum xml_read_state state;
	const GMarkupParser *parser;
	gpointer user_data;
	void (*fin_func)(gpointer ud);
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
				"check_attachements",
				xml_handle_boolean,
				G_STRUCT_OFFSET (struct config_file, check_text_attachements),
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
			{
				"dns_throttling_errors",
				xml_handle_uint32,
				G_STRUCT_OFFSET (struct config_file, dns_throttling_errors),
				NULL
			},
			{
				"dns_throttling_time",
				xml_handle_seconds,
				G_STRUCT_OFFSET (struct config_file, dns_throttling_time),
				NULL
			},
			NULL_ATTR
		},
		NULL_DEF_ATTR
	},
	{ XML_SECTION_OPTIONS, {
			{
				"statfile_pool_size",
				xml_handle_size,
				G_STRUCT_OFFSET (struct config_file, max_statfile_size),
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
			{
				"dns_nameserver",
				options_handle_nameserver,
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
				"one_shot",
				xml_handle_boolean,
				G_STRUCT_OFFSET (struct config_file, one_shot_mode),
				NULL
			},
			{
				"check_attachements",
				xml_handle_boolean,
				G_STRUCT_OFFSET (struct config_file, check_text_attachements),
				NULL
			},
			{
				"tempdir",
				xml_handle_string,
				G_STRUCT_OFFSET (struct config_file, temp_dir),
				NULL
			},
			{
				"pidfile",
				xml_handle_string,
				G_STRUCT_OFFSET (struct config_file, pid_file),
				NULL
			},
			{
				"filters",
				xml_handle_string,
				G_STRUCT_OFFSET (struct config_file, filters_str),
				NULL
			},
			{
				"sync_interval",
				xml_handle_seconds,
				G_STRUCT_OFFSET (struct config_file, statfile_sync_interval),
				NULL
			},
			{
				"sync_timeout",
				xml_handle_seconds,
				G_STRUCT_OFFSET (struct config_file, statfile_sync_timeout),
				NULL
			},
			{
				"max_diff",
				xml_handle_size,
				G_STRUCT_OFFSET (struct config_file, max_diff),
				NULL
			},
			{
				"map_watch_interval",
				xml_handle_seconds_double,
				G_STRUCT_OFFSET (struct config_file, map_timeout),
				NULL
			},
			{
				"dynamic_conf",
				xml_handle_string,
				G_STRUCT_OFFSET (struct config_file, dynamic_conf),
				NULL
			},
			{
				"use_mlock",
				xml_handle_boolean,
				G_STRUCT_OFFSET (struct config_file, mlock_statfile_pool),
				NULL
			},
			{
				"rrd",
				xml_handle_string,
				G_STRUCT_OFFSET (struct config_file, rrd_file),
				NULL
			},
			{
				"history_file",
				xml_handle_string,
				G_STRUCT_OFFSET (struct config_file, history_file),
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
				xml_handle_deprecated,
				0,
				NULL
			},
			{
				"reject_score",
				xml_handle_deprecated,
				0,
				NULL
			},
			{
				"subject",
				xml_handle_string,
				G_STRUCT_OFFSET (struct metric, subject),
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
				"label",
				xml_handle_string,
				G_STRUCT_OFFSET (struct statfile, label),
				NULL
			},
			{
				"size",
				xml_handle_size,
				G_STRUCT_OFFSET (struct statfile, size),
				NULL
			},
			{
				"spam",
				xml_handle_boolean,
				G_STRUCT_OFFSET (struct statfile, is_spam),
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
		{
				handle_statfile_opt,
				0,
				NULL
		}
	},
	{ XML_SECTION_MODULE_META, {
			{
				"name",
				xml_handle_string,
				G_STRUCT_OFFSET (struct module_meta_opt, name),
				NULL
			},
			NULL_ATTR
		},
		{
			handle_module_meta,
			0,
			NULL
		}
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
		   *classifier_options = NULL,
		   *subparsers = NULL;
#endif

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
		case XML_READ_MODULE_META:
			return "read module meta section";
		case XML_READ_OPTIONS:
			return "read options section";
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
		case XML_SUBPARSER:
			return "subparser handle";
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


/* Find among attributes required ones and form new array of pairs attribute-value */
static void
process_attrs (const gchar **attribute_names, const gchar **attribute_values, ucl_object_t *top)
{
	const gchar                         **attr, **value;
	GHashTable                     *res;

	attr = attribute_names;
	value = attribute_values;
	while (*attr) {
		/* Copy attributes to pool */
		ucl_object_insert_key (top, ucl_object_fromstring_common (*value, 0, UCL_STRING_PARSE), *attr, 0, TRUE);
		attr ++;
		value ++;
	}
}


/* Handlers */

static void
set_lua_globals (struct config_file *cfg, lua_State *L)
{
	struct config_file           **pcfg;

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

	pcfg = lua_newuserdata (L, sizeof (struct config_file *));
	lua_setclass (L, "rspamd{config}", -1);
	*pcfg = cfg;
	lua_setglobal (L, "rspamd_config");

	/* Clear stack from globals */
	lua_pop (L, 4);
}

/* Handle lua tag */
gboolean
handle_lua (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	gchar                        *val, *cur_dir, *lua_dir, *lua_file, *tmp1, *tmp2;
	lua_State                    *L = cfg->lua_state;

	/* Now config tables can be used for configuring rspamd */
	/* First check "src" attribute */
	if (attrs != NULL && (val = g_hash_table_lookup (attrs, "src")) != NULL) {
		/* Chdir */
		tmp1 = g_strdup (val);
		tmp2 = g_strdup (val);
		lua_dir = dirname (tmp1);
		lua_file = basename (tmp2);
		if (lua_dir && lua_file) {
			cur_dir = g_malloc (PATH_MAX);
			if (getcwd (cur_dir, PATH_MAX) != NULL && chdir (lua_dir) != -1) {
				/* Load file */
				if (luaL_loadfile (L, lua_file) != 0) {
					msg_err ("cannot load lua file %s: %s", val, lua_tostring (L, -1));
					if (chdir (cur_dir) == -1) {
						msg_err ("cannot chdir to %s: %s", cur_dir, strerror (errno));;
					}
					g_free (cur_dir);
					g_free (tmp1);
					g_free (tmp2);
					return FALSE;
				}
				set_lua_globals (cfg, L);
				/* Now do it */
				if (lua_pcall (L, 0, LUA_MULTRET, 0) != 0) {
					msg_err ("init of %s failed: %s", val, lua_tostring (L, -1));
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
		if (luaL_loadstring (L, data) != 0) {
			msg_err ("cannot load lua chunk: %s", lua_tostring (L, -1));
			return FALSE;
		}
		set_lua_globals (cfg, L);
		/* Now do it */
		if (lua_pcall (L, 0, LUA_MULTRET, 0) != 0) {
			msg_err ("init of lua chunk failed: %s", lua_tostring (L, -1));
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
	guint                           i;

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
	
	if (attrs == NULL || (val = g_hash_table_lookup (attrs, "name")) == NULL) {
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
	struct rspamd_composite      *composite;
	
	if (attrs == NULL || (val = g_hash_table_lookup (attrs, "name")) == NULL) {
		msg_err ("'name' attribute is required for tag 'composite'");
		return FALSE;
	}

	if ((expr = parse_expression (cfg->cfg_pool, data)) == NULL) {
		msg_err ("cannot parse composite expression: %s", data);
		return FALSE;
	}
	composite = memory_pool_alloc (cfg->cfg_pool, sizeof (struct rspamd_composite));
	composite->expr = expr;
	composite->id = g_hash_table_size (cfg->composite_symbols) + 1;
	g_hash_table_insert (cfg->composite_symbols, val, composite);
	register_virtual_symbol (&cfg->cache, val, 1);

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
	if (!read_settings (data, "Users' settings", cfg, cfg->user_settings)) {
		msg_err ("cannot read settings %s", data);
		return FALSE;
	}
	cfg->user_settings_str = memory_pool_strdup (cfg->cfg_pool, data);

	return TRUE;
}
gboolean 
handle_domain_settings (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	if (!read_settings (data, "Domains' settings", cfg, cfg->domain_settings)) {
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
		if (attrs == NULL || (name = g_hash_table_lookup (attrs, "name")) == NULL) {
			msg_err ("worker param tag must have \"name\" attribute");
			return FALSE;
		}
	}
	else {
		name = memory_pool_strdup (cfg->cfg_pool, tag);
	}


	g_hash_table_insert (ccf->opts, (char *)name, memory_pool_strdup (cfg->cfg_pool, data));


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
	st->binlog->rotate_time = cfg_parse_time (data, TIME_SECONDS);
	
	return TRUE;
}

gboolean 
handle_statfile_binlog_master (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	struct statfile             *st = ctx->section_pointer;
	if (st->binlog == NULL) {
		st->binlog = memory_pool_alloc0 (cfg->cfg_pool, sizeof (struct statfile_binlog_params));
	}

	if (!parse_host_port (cfg->cfg_pool, data, &st->binlog->master_addr, &st->binlog->master_port)) {
		msg_err ("cannot parse master address: %s", data);
		return FALSE;
	}

	return TRUE;
}

gboolean
handle_statfile_opt (struct config_file *cfg, struct rspamd_xml_userdata *ctx, const gchar *tag, GHashTable *attrs, gchar *data, gpointer user_data, gpointer dest_struct, gint offset)
{
	struct statfile                *st = ctx->section_pointer;
	const gchar                    *name;

	if (g_ascii_strcasecmp (tag, "option") == 0 || g_ascii_strcasecmp (tag, "param") == 0) {
		if (attrs == NULL || (name = g_hash_table_lookup (attrs, "name")) == NULL) {
			msg_err ("worker param tag must have \"name\" attribute");
			return FALSE;
		}
	}
	else {
		name = memory_pool_strdup (cfg->cfg_pool, tag);
	}

	g_hash_table_insert (st->opts, (char *)name, memory_pool_strdup (cfg->cfg_pool, data));

	return TRUE;
}

/* XML callbacks */
void 
rspamd_xml_start_element (GMarkupParseContext *context, const gchar *element_name, const gchar **attribute_names,
								const gchar **attribute_values, gpointer user_data, GError **error)
{
	struct rspamd_xml_userdata *ud = user_data;
	struct xml_subparser       *subparser;
	struct classifier_config   *ccf;
	gchar                      *res, *condition;
	ucl_object_t                *obj;


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
			if (g_ascii_strcasecmp (element_name, "classifier") == 0) {
				if (extract_attr ("type", attribute_names, attribute_values, &res)) {
					ud->state = XML_READ_CLASSIFIER;
				}
				else {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "param 'type' is required for tag 'classifier'");
					ud->state = XML_ERROR;
				}
			}
			else {
				/* Legacy XML support */
				if (g_ascii_strcasecmp (element_name, "param") == 0) {
					if (extract_attr ("value", attribute_names, attribute_values, &res)) {
						element_name = res;
					}
					else {
						*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "param 'value' is required for tag 'param'");
						ud->state = XML_ERROR;
					}
				}

				if (ud->nested == 0) {
					/* Top object */
					obj = ucl_object_new ();
					obj->type = UCL_OBJECT;
					ud->parent_pointer[0] = obj;
					ucl_object_insert_key (ud->cfg->rcl_obj, obj, element_name, 0, true);
					process_attrs (attribute_names, attribute_values, obj);
				}
				rspamd_strlcpy (ud->section_name[ud->nested], element_name, MAX_NAME);
				ud->nested ++;
			}
			break;
		case XML_READ_CLASSIFIER:
			if (g_ascii_strcasecmp (element_name, "statfile") == 0) {
				ud->state = XML_READ_STATFILE;

				/* Now section pointer is statfile and parent pointer is classifier */
				ud->parent_pointer[0] = ud->section_pointer;
				ud->section_pointer = check_statfile_conf (ud->cfg, NULL);
			}
			else {
				rspamd_strlcpy (ud->section_name[ud->nested], element_name, MAX_NAME);
				/* Save attributes */
			}
			break;
		default:
			if (*error == NULL) {
				*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "element %s is unexpected in this state %s",
					element_name, xml_state_to_string (ud));
			}
			break;
	}
}


void 
rspamd_xml_end_element (GMarkupParseContext	*context, const gchar *element_name, gpointer user_data, GError **error)
{

	struct rspamd_xml_userdata *ud = user_data;

	if (g_ascii_strcasecmp (ud->section_name[ud->nested - 1], element_name) == 0) {
		ud->nested --;
	}
	else {
		*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "element %s is umatched", element_name);
		ud->state = XML_ERROR;
	}
}
#undef CHECK_TAG

void 
rspamd_xml_text (GMarkupParseContext *context, const gchar *text, gsize text_len, gpointer user_data, GError **error)
{
	struct rspamd_xml_userdata *ud = user_data;
	ucl_object_t *top;
	
	while (text_len > 0 && g_ascii_isspace (*text)) {
		text_len --;
		text ++;
	}

	if (text_len == 0) {
		return;
	}

	top = ud->parent_pointer[ud->nested - 1];
	ucl_object_insert_key (top, ucl_object_fromstring_common (text, text_len, UCL_STRING_PARSE),
			ud->section_name[ud->nested], 0, true);
}

void 
rspamd_xml_error (GMarkupParseContext *context, GError *error, gpointer user_data)
{
	struct rspamd_xml_userdata *ud = user_data;
	
	msg_err ("xml parser error: %s, at state \"%s\"", error->message, xml_state_to_string (ud));
}

/* Register new module option */
void
register_module_opt (const gchar *mname, const gchar *optname, enum module_opt_type type)
{
	msg_err ("this function is depreciated and must not be used");
}

/* Register new worker's options */
void
register_worker_opt (gint wtype, const gchar *optname, element_handler_func func, gpointer dest_struct, gint offset)
{
	msg_err ("this function is depreciated and must not be used");
}

/* Register new classifier option */
void
register_classifier_opt (const gchar *ctype, const gchar *optname)
{
	msg_err ("this function is depreciated and must not be used");
}

void
register_subparser (const gchar *tag, int state, const GMarkupParser *parser, void (*fin_func)(gpointer ud), gpointer user_data)
{
	msg_err ("this function is depreciated and must not be used");
}
