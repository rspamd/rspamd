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
#include "logger.h"
#include "util.h"

/* Maximum attributes for param */
#define MAX_PARAM 64

#define NULL_ATTR 	\
{					\
	NULL,			\
	NULL,			\
	0,				\
	NULL			\
}					\

/* Basic xml parsing functions */
gboolean xml_handle_string (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset);

/* Numeric params */
gboolean xml_handle_size (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean xml_handle_double (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean xml_handle_seconds (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean xml_handle_int (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean xml_handle_uint32 (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean xml_handle_uint16 (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset);

/* Flags */
gboolean xml_handle_boolean (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset);

/* Specific params */
gboolean worker_handle_param (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset);
gboolean handle_factor (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset);


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
			NULL_ATTR
		},
		NULL_ATTR
	},
	{ XML_SECTION_WORKER, {
			NULL_ATTR
		},
		{
			NULL,
			worker_handle_param,
			0,
			NULL
		},
	},
	{ XML_SECTION_METRIC, {
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
		NULL_ATTR
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
call_param_handler (struct rspamd_xml_userdata *ctx, const gchar *name, const gchar *value, gpointer dest_struct, enum xml_config_section section)
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

gboolean 
worker_handle_param (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{

}

gboolean 
handle_factor (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{

}

static void
xml_parse_module_opt (struct rspamd_xml_userdata *ud, const gchar *text, gsize len)
{
	char	                       *val;
	GList                          *cur_opt;
	struct module_opt              *cur;
	
	val = xml_asciiz_string (ud->cfg->cfg_pool, text, len);
	cur_opt = g_hash_table_lookup (ud->cfg->modules_opts, ud->section_name);
	if (cur_opt == NULL) {
		/* Insert new option structure */
		cur = memory_pool_alloc (ud->cfg->cfg_pool, sizeof (struct module_opt));
		cur->param = memory_pool_strdup (ud->cfg->cfg_pool, ud->other_data);
		cur->value = val;
		cur_opt = g_list_prepend (NULL, cur);
		g_hash_table_insert (ud->cfg->modules_opts, memory_pool_strdup (ud->cfg->cfg_pool, ud->section_name), cur_opt);
	}
	else {
		/* First try to find option with this name */
		while (cur_opt) {
			cur = cur_opt->data;
			if (strcmp (cur->param, ud->other_data) == 0) {
				/* cur->value is in pool */
				cur->value = val;
				return;
			}
			cur_opt = g_list_next (cur_opt);
		}
		/* Not found, insert */
		cur = memory_pool_alloc (ud->cfg->cfg_pool, sizeof (struct module_opt));
		cur->param = memory_pool_strdup (ud->cfg->cfg_pool, ud->other_data);
		cur->value = val;
		cur_opt = g_list_prepend (cur_opt, cur);
	}

}

/* Common handlers */
gboolean 
xml_handle_string (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	/* Simply assign pointer to pointer */
	gchar                       **dest;

	dest = (char **)G_STRUCT_MEMBER_P (dest_struct, offset);
	*dest = memory_pool_strdup (cfg->cfg_pool, data);

	return TRUE;
}


gboolean 
xml_handle_size (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	gsize                      *dest;

	dest = (gsize *)G_STRUCT_MEMBER_P (dest_struct, offset);
	*dest = parse_limit (data);
	
	return TRUE;
}

gboolean 
xml_handle_seconds (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset)
{
	time_t                      *dest;

	dest = (time_t *)G_STRUCT_MEMBER_P (dest_struct, offset);
	*dest = parse_seconds (data);
	
	return TRUE;
}

gboolean 
xml_handle_boolean (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset)
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
xml_handle_double (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset)
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
xml_handle_int (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset)
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
xml_handle_uint32 (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset)
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
xml_handle_uint16 (struct config_file *cfg, struct rspamd_xml_userdata *ctx, GHashTable *attrs, const gchar *data, gpointer user_data, gpointer dest_struct, int offset)
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
					g_strlcpy (ud->section_name, res, sizeof (res));
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
					g_strlcpy (ud->section_name, res, sizeof (res));
					ud->state = XML_READ_METRIC;
				}
				else {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "param 'name' is required for tag 'metric'");
					ud->state = XML_ERROR;
				}
			}
			else if (g_ascii_strcasecmp (element_name, "classifier") == 0) {
				if (extract_attr ("type", attribute_names, attribute_values, &res)) {
					g_strlcpy (ud->section_name, res, sizeof (res));
					ud->state = XML_READ_CLASSIFIER;
				}
				else {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "param 'type' is required for tag 'classifier'");
					ud->state = XML_ERROR;
				}
			}
			else if (g_ascii_strcasecmp (element_name, "worker") == 0) {
				ud->state = XML_READ_WORKER;
			}
			else {
				/* Other params */
				if (g_ascii_strcasecmp (element_name, "variable") == 0) {
					if (extract_attr ("name", attribute_names, attribute_values, &res)) {
						g_strlcpy (ud->section_name, res, sizeof (res));
						ud->state = XML_READ_VARIABLE;
					}
					else {
						*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "param 'name' is required for tag 'variable'");
						ud->state = XML_ERROR;
					}
				
				} 
				else if (g_ascii_strcasecmp (element_name, "pidfile") == 0) {
					ud->state = XML_READ_PIDFILE;
				}
				else if (g_ascii_strcasecmp (element_name, "filters") == 0) {
					ud->state = XML_READ_FILTERS;
				}
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
			break;
		case XML_READ_WORKER:
			CHECK_TAG ("worker", FALSE);
			break;
		case XML_READ_VARIABLE:
			CHECK_TAG ("variable", TRUE);
			break;
		case XML_READ_PIDFILE:
			CHECK_TAG ("pidfile", TRUE);
			break;
		case XML_READ_STATFILE_POOL:
			CHECK_TAG ("statfile_pool_size", TRUE);
			break;
		case XML_READ_FILTERS:
			CHECK_TAG ("filters", TRUE);
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
		case XML_READ_PIDFILE:
		case XML_READ_STATFILE_POOL:
		case XML_READ_FILTERS:
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
		case XML_READ_PARAM:
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

