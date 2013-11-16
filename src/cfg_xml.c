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
#include "cfg_file.h"

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
static gboolean
process_attrs (const gchar **attribute_names, const gchar **attribute_values, ucl_object_t *top)
{
	const gchar                         **attr, **value;
	gboolean res = FALSE;

	attr = attribute_names;
	value = attribute_values;
	while (*attr) {
		/* Copy attributes to pool */
		top = ucl_object_insert_key (top, ucl_object_fromstring_common (*value, 0, UCL_STRING_PARSE), *attr, 0, TRUE);
		attr ++;
		value ++;
		res = TRUE;
	}
	return res;
}


/* Handlers */

/* XML callbacks */
void 
rspamd_xml_start_element (GMarkupParseContext *context, const gchar *element_name, const gchar **attribute_names,
								const gchar **attribute_values, gpointer user_data, GError **error)
{
	struct rspamd_xml_userdata *ud = user_data;
	gchar                      *res;
	ucl_object_t                *obj, *tobj;


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
			/* Legacy XML support */
			if (g_ascii_strcasecmp (element_name, "param") == 0) {
				if (extract_attr ("value", attribute_names, attribute_values, &res)) {
					element_name = res;
				}
				else if (extract_attr ("name", attribute_names, attribute_values, &res)) {
					element_name = res;
				}
				else {
					*error = g_error_new (xml_error_quark (), XML_PARAM_MISSING, "attribute 'value' or 'name' are required for tag 'param'");
					ud->state = XML_ERROR;
				}
			}

			rspamd_strlcpy (ud->section_name[ud->nested], element_name, MAX_NAME);
			if (ud->nested == 0) {
				/* Top object */

				if (g_ascii_strcasecmp (element_name, "lua") == 0 &&
						extract_attr ("src", attribute_names, attribute_values, &res)) {
					/* Lua is 'special' tag */
					obj = ucl_object_fromstring (res);
					ud->cfg->rcl_obj = ucl_object_insert_key (ud->cfg->rcl_obj, obj, element_name, 0, true);
					ud->parent_pointer[0] = obj;
					ud->nested ++;
				}
				else if (g_ascii_strcasecmp (element_name, "composite") == 0) {
					/* Composite is 'special' tag */
					obj = ucl_object_new ();
					obj->type = UCL_OBJECT;
					ud->parent_pointer[0] = obj;
					ud->cfg->rcl_obj = ucl_object_insert_key (ud->cfg->rcl_obj, obj, element_name, 0, true);
					process_attrs (attribute_names, attribute_values, obj);
					ud->nested ++;
					rspamd_strlcpy (ud->section_name[ud->nested], "expression", MAX_NAME);
				}
				else if (g_ascii_strcasecmp (element_name, "module") == 0 &&
						extract_attr ("name", attribute_names, attribute_values, &res)) {
					obj = ucl_object_new ();
					obj->type = UCL_OBJECT;
					ud->parent_pointer[0] = obj;
					ud->cfg->rcl_obj = ucl_object_insert_key (ud->cfg->rcl_obj, obj, res, 0, true);
					ud->nested ++;
				}
				else {
					obj = ucl_object_new ();
					obj->type = UCL_OBJECT;
					ud->parent_pointer[0] = obj;
					ud->cfg->rcl_obj = ucl_object_insert_key (ud->cfg->rcl_obj, obj, element_name, 0, true);
					process_attrs (attribute_names, attribute_values, obj);
					ud->nested ++;
				}
			}
			else {
				tobj = ucl_object_new ();
				if (g_ascii_strcasecmp (element_name, "symbol") == 0 &&
						process_attrs (attribute_names, attribute_values, tobj)) {
					ud->parent_pointer[ud->nested] = tobj;
					tobj->type = UCL_OBJECT;
					ud->parent_pointer[ud->nested - 1] =
							ucl_object_insert_key (ud->parent_pointer[ud->nested - 1], tobj, element_name, 0, true);
					ud->nested ++;
					/* XXX: very ugly */
					rspamd_strlcpy (ud->section_name[ud->nested], "name", MAX_NAME);
				}
				else if (g_ascii_strcasecmp (element_name, "statfile") == 0) {
					/* XXX: ugly as well */
					ud->parent_pointer[ud->nested] = tobj;
					tobj->type = UCL_OBJECT;
					ud->parent_pointer[ud->nested - 1] =
							ucl_object_insert_key (ud->parent_pointer[ud->nested - 1], tobj, element_name, 0, true);
					ud->nested ++;
				}
				else {
					ucl_object_unref (tobj);
					process_attrs (attribute_names, attribute_values, ud->parent_pointer[ud->nested - 1]);
				}
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

	if (ud->nested > 0) {
		if (g_ascii_strcasecmp (ud->section_name[ud->nested - 1], element_name) == 0) {
			ud->nested --;
		}
		else if (g_ascii_strcasecmp (element_name, "param") == 0) {
			/* Another ugly hack */
			ud->nested --;
		}
		else if (g_ascii_strcasecmp (ud->section_name[ud->nested], element_name) != 0) {
			*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "element %s is unmatched", element_name);
			ud->state = XML_ERROR;
		}
	}
	else if (g_ascii_strcasecmp ("rspamd", element_name) != 0) {
		*error = g_error_new (xml_error_quark (), XML_EXTRA_ELEMENT, "element %s is unmatched on the top level", element_name);
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
	ud->parent_pointer[ud->nested - 1] =
			ucl_object_insert_key (top, ucl_object_fromstring_common (text, text_len,
					UCL_STRING_PARSE|UCL_STRING_PARSE_BYTES),
					ud->section_name[ud->nested], 0, true);
}

void 
rspamd_xml_error (GMarkupParseContext *context, GError *error, gpointer user_data)
{
	struct rspamd_xml_userdata *ud = user_data;
	
	msg_err ("xml parser error: %s, at state \"%s\"", error->message, xml_state_to_string (ud));
}
