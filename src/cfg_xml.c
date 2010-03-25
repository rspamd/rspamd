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
					ud->section_name = g_strdup (res);
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
					ud->section_name = g_strdup (res);
					ud->state = XML_READ_METRIC;
				}
				else {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "param 'name' is required for tag 'metric'");
					ud->state = XML_ERROR;
				}
			}
			else if (g_ascii_strcasecmp (element_name, "classifier") == 0) {
				if (extract_attr ("type", attribute_names, attribute_values, &res)) {
					ud->section_name = g_strdup (res);
					ud->state = XML_READ_CLASSIFIER;
				}
				else {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "param 'type' is required for tag 'classifier'");
					ud->state = XML_ERROR;
				}
			}
			else if (g_ascii_strcasecmp (element_name, "worker") == 0) {
				if (extract_attr ("type", attribute_names, attribute_values, &res)) {
					ud->section_name = g_strdup (res);
					ud->state = XML_READ_WORKER;
				}
				else {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "param 'type' is required for tag 'worker'");
					ud->state = XML_ERROR;
				}
			}
			else {
				/* Other params */
				if (g_ascii_strcasecmp (element_name, "variable") == 0) {
					if (extract_attr ("name", attribute_names, attribute_values, &res)) {
						ud->section_name = g_strdup (res);
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
			if (g_ascii_strcasecmp (element_name, "param") == 0) {
				if (extract_attr ("name", attribute_names, attribute_values, &res)) {
					ud->other_data = g_strdup (res);
				}
				else {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "param 'name' is required for tag 'param'");
					ud->state = XML_ERROR;
				}
			}
			break;
		case XML_READ_CLASSIFIER:
			break;
		case XML_READ_STATFILE:
			break;
		case XML_READ_FACTORS:
			if (g_ascii_strcasecmp (element_name, "factor") == 0) {
				if (extract_attr ("name", attribute_names, attribute_values, &res)) {
					ud->other_data = g_strdup (res);
				}
				else {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "param 'name' is required for tag 'factor'");
					ud->state = XML_ERROR;
				}
			}
			break;
		case XML_READ_WORKER:
			break;
		case XML_READ_LOGGING:
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
	if (!required) {																														\
		g_free (ud->section_name);																											\
	}																																		\
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
	double *tmp;

	switch (ud->state) {
		case XML_READ_MODULE:
			if (ud->other_data) {
				/* Insert or replace module's option */
				xml_parse_module_opt (ud, text, text_len);	
				g_free (ud->other_data);
			}
			break;
		case XML_READ_CLASSIFIER:
			break;
		case XML_READ_STATFILE:
			break;
		case XML_READ_FACTORS:
			if (ud->other_data) {
				/* Assume that we have factor name in other_data */
				val = xml_asciiz_string (ud->cfg->cfg_pool, text, text_len);
				tmp = memory_pool_alloc (ud->cfg->cfg_pool, sizeof (double));
				*tmp = strtod (val, NULL);
				g_hash_table_insert (ud->cfg->factors, ud->other_data, tmp);
				g_free (ud->other_data);
			}
			break;
		case XML_READ_METRIC:
			break;
		case XML_READ_WORKER:
			break;
		case XML_READ_VARIABLE:
			if (ud->other_data) {
				/* Assume that we have factor name in other_data */
				val = xml_asciiz_string (ud->cfg->cfg_pool, text, text_len);
				g_hash_table_insert (ud->cfg->variables, ud->other_data, val);
				g_free (ud->other_data);
			}
			break;
		case XML_READ_PIDFILE:
			val = xml_asciiz_string (ud->cfg->cfg_pool, text, text_len);
			ud->cfg->pid_file = val;
			break;
		case XML_READ_STATFILE_POOL:
			val = xml_asciiz_string (ud->cfg->cfg_pool, text, text_len);
			ud->cfg->max_statfile_size = strtoull (val, NULL, 10);
			break;
		case XML_READ_FILTERS:
			val = xml_asciiz_string (ud->cfg->cfg_pool, text, text_len);
			ud->cfg->filters_str = val;
			break;
		case XML_READ_LOGGING:
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

