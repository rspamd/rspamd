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
#include "lua_common.h"


LUA_FUNCTION_DEF (xmlrpc, parse_reply);
LUA_FUNCTION_DEF (xmlrpc, make_request);

static const struct luaL_reg xmlrpclib_m[] = {
	LUA_INTERFACE_DEF (xmlrpc, parse_reply),
	LUA_INTERFACE_DEF (xmlrpc, make_request),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

#define msg_debug_xmlrpc(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_xmlrpc_log_id, "xmlrpc", "", \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(xmlrpc)

enum lua_xmlrpc_state {
	read_method_responce = 0,
	read_params = 1,
	read_param = 2,
	read_param_value = 3,
	read_param_element = 4,
	read_struct = 5,
	read_struct_member_name = 6,
	read_struct_member_value = 7,
	read_struct_element = 8,
	read_string = 9,
	read_int = 10,
	read_double = 11,
	read_array = 12,
	read_array_value = 13,
	read_array_element = 14,
	error_state = 99,
	success_state = 100,
};

enum lua_xmlrpc_stack {
	st_array = 1,
	st_struct = 2,
};

struct lua_xmlrpc_ud {
	enum lua_xmlrpc_state parser_state;
	GQueue *st;
	gint param_count;
	gboolean got_text;
	lua_State *L;
};

static void xmlrpc_start_element (GMarkupParseContext *context,
	const gchar *name,
	const gchar **attribute_names,
	const gchar **attribute_values,
	gpointer user_data,
	GError **error);
static void xmlrpc_end_element (GMarkupParseContext *context,
	const gchar *element_name,
	gpointer user_data,
	GError **error);
static void xmlrpc_error (GMarkupParseContext *context,
	GError *error,
	gpointer user_data);
static void xmlrpc_text (GMarkupParseContext *context,
	const gchar *text,
	gsize text_len,
	gpointer user_data,
	GError **error);

static GMarkupParser xmlrpc_parser = {
	.start_element = xmlrpc_start_element,
	.end_element = xmlrpc_end_element,
	.passthrough = NULL,
	.text = xmlrpc_text,
	.error = xmlrpc_error,
};

static GQuark
xmlrpc_error_quark (void)
{
	return g_quark_from_static_string ("xmlrpc-error-quark");
}

static void
xmlrpc_start_element (GMarkupParseContext *context,
	const gchar *name,
	const gchar **attribute_names,
	const gchar **attribute_values,
	gpointer user_data,
	GError **error)
{
	struct lua_xmlrpc_ud *ud = user_data;
	enum lua_xmlrpc_state last_state;

	last_state = ud->parser_state;

	msg_debug_xmlrpc ("got start element %s on state %d", name, last_state);

	switch (ud->parser_state) {
	case read_method_responce:
		/* Expect tag methodResponse */
		if (g_ascii_strcasecmp (name, "methodResponse") == 0) {
			ud->parser_state = read_params;
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_params:
		/* Expect tag params */
		if (g_ascii_strcasecmp (name, "params") == 0) {
			ud->parser_state = read_param;
			/* result -> table of params indexed by int */
			lua_newtable (ud->L);
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_param:
		/* Expect tag param */
		if (g_ascii_strcasecmp (name, "param") == 0) {
			ud->parser_state = read_param_value;
			/* Create new param */
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_param_value:
		/* Expect tag value */
		if (g_ascii_strcasecmp (name, "value") == 0) {
			ud->parser_state = read_param_element;
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_param_element:
		/* Expect tag struct */
		if (g_ascii_strcasecmp (name, "struct") == 0) {
			ud->parser_state = read_struct;
			/* Create new param of table type */
			lua_newtable (ud->L);
			g_queue_push_head (ud->st, GINT_TO_POINTER (st_struct));
			msg_debug_xmlrpc ("push struct");
		}
		else if (g_ascii_strcasecmp (name, "array") == 0) {
			ud->parser_state = read_array;
			/* Create new param of table type */
			lua_newtable (ud->L);
			g_queue_push_head (ud->st, GINT_TO_POINTER (st_array));
			msg_debug_xmlrpc ("push array");
		}
		else if (g_ascii_strcasecmp (name, "string") == 0) {
			ud->parser_state = read_string;
			ud->got_text = FALSE;
		}
		else if (g_ascii_strcasecmp (name, "int") == 0) {
			ud->parser_state = read_int;
			ud->got_text = FALSE;
		}
		else if (g_ascii_strcasecmp (name, "double") == 0) {
			ud->parser_state = read_double;
			ud->got_text = FALSE;
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_struct:
		/* Parse structure */
		/* Expect tag member */
		if (g_ascii_strcasecmp (name, "member") == 0) {
			ud->parser_state = read_struct_member_name;
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_struct_member_name:
		/* Expect tag name */
		if (g_ascii_strcasecmp (name, "name") == 0) {
			ud->parser_state = read_struct_member_value;
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_struct_member_value:
		/* Accept value */
		if (g_ascii_strcasecmp (name, "value") == 0) {
			ud->parser_state = read_struct_element;
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_struct_element:
		/* Parse any values */
		/* Primitives */
		if (g_ascii_strcasecmp (name, "string") == 0) {
			ud->parser_state = read_string;
			ud->got_text = FALSE;
		}
		else if (g_ascii_strcasecmp (name, "int") == 0) {
			ud->parser_state = read_int;
			ud->got_text = FALSE;
		}
		else if (g_ascii_strcasecmp (name, "double") == 0) {
			ud->parser_state = read_double;
			ud->got_text = FALSE;
		}
		/* Structure */
		else if (g_ascii_strcasecmp (name, "struct") == 0) {
			ud->parser_state = read_struct;
			/* Create new param of table type */
			lua_newtable (ud->L);
			g_queue_push_head (ud->st, GINT_TO_POINTER (st_struct));
			msg_debug_xmlrpc ("push struct");
		}
		else if (g_ascii_strcasecmp (name, "array") == 0) {
			ud->parser_state = read_array;
			/* Create new param of table type */
			lua_newtable (ud->L);
			g_queue_push_head (ud->st, GINT_TO_POINTER (st_array));
			msg_debug_xmlrpc ("push array");
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_array:
		/* Parse array */
		/* Expect data */
		if (g_ascii_strcasecmp (name, "data") == 0) {
			ud->parser_state = read_array_value;
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_array_value:
		/* Accept array value */
		if (g_ascii_strcasecmp (name, "value") == 0) {
			ud->parser_state = read_array_element;
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_array_element:
		/* Parse any values */
		/* Primitives */
		if (g_ascii_strcasecmp (name, "string") == 0) {
			ud->parser_state = read_string;
			ud->got_text = FALSE;
		}
		else if (g_ascii_strcasecmp (name, "int") == 0) {
			ud->parser_state = read_int;
			ud->got_text = FALSE;
		}
		else if (g_ascii_strcasecmp (name, "double") == 0) {
			ud->parser_state = read_double;
			ud->got_text = FALSE;
		}
		/* Structure */
		else if (g_ascii_strcasecmp (name, "struct") == 0) {
			ud->parser_state = read_struct;
			/* Create new param of table type */
			lua_newtable (ud->L);
			g_queue_push_head (ud->st, GINT_TO_POINTER (st_struct));
			msg_debug_xmlrpc ("push struct");
		}
		else if (g_ascii_strcasecmp (name, "array") == 0) {
			ud->parser_state = read_array;
			/* Create new param of table type */
			lua_newtable (ud->L);
			g_queue_push_head (ud->st, GINT_TO_POINTER (st_array));
			msg_debug_xmlrpc ("push array");
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	default:
		break;
	}

	msg_debug_xmlrpc ("switched state on start tag %d->%d", last_state,
			ud->parser_state);

	if (ud->parser_state == error_state) {
		g_set_error (error,
			xmlrpc_error_quark (), 1, "xmlrpc parse error on state: %d, while parsing start tag: %s",
			last_state, name);
	}
}

static void
xmlrpc_end_element (GMarkupParseContext *context,
	const gchar *name,
	gpointer user_data,
	GError **error)
{
	struct lua_xmlrpc_ud *ud = user_data;
	enum lua_xmlrpc_state last_state;
	int last_queued;

	last_state = ud->parser_state;

	msg_debug_xmlrpc ("got end element %s on state %d", name, last_state);

	switch (ud->parser_state) {
	case read_method_responce:
		ud->parser_state = error_state;
		break;
	case read_params:
		/* Got methodResponse */
		if (g_ascii_strcasecmp (name, "methodResponse") == 0) {
			/* End processing */
			ud->parser_state = success_state;
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_param:
		/* Got tag params */
		if (g_ascii_strcasecmp (name, "params") == 0) {
			ud->parser_state = read_params;
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_param_value:
		/* Got tag param */
		if (g_ascii_strcasecmp (name, "param") == 0) {
			ud->parser_state = read_param;
			lua_rawseti (ud->L, -2, ++ud->param_count);
			msg_debug_xmlrpc ("set param element idx: %d", ud->param_count);
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_param_element:
		/* Got tag value */
		if (g_ascii_strcasecmp (name, "value") == 0) {
			if (g_queue_get_length (ud->st) == 0) {
				ud->parser_state = read_param_value;
			}
			else {
				if (GPOINTER_TO_INT (g_queue_peek_head (ud->st)) == st_struct) {
					ud->parser_state = read_struct_member_name;
				}
				else {
					ud->parser_state = read_array_value;
				}
			}
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_struct:
		/* Got tag struct */
		if (g_ascii_strcasecmp (name, "struct") == 0) {
			g_assert (GPOINTER_TO_INT (g_queue_pop_head (ud->st)) == st_struct);

			if (g_queue_get_length (ud->st) == 0) {
				ud->parser_state = read_param_element;
			}
			else {
				last_queued = GPOINTER_TO_INT (g_queue_peek_head (ud->st));
				if (last_queued == st_struct) {
					ud->parser_state = read_struct_element;
				}
				else {
					ud->parser_state = read_array_element;
				}
			}

			msg_debug_xmlrpc ("pop struct");
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_struct_member_name:
		/* Got tag member */
		if (g_ascii_strcasecmp (name, "member") == 0) {
			ud->parser_state = read_struct;
			/* Set table */
			msg_debug_xmlrpc ("set struct element idx: %s",
					lua_tostring (ud->L, -2));
			lua_settable (ud->L, -3);
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_struct_member_value:
		/* Got tag name */
		if (g_ascii_strcasecmp (name, "name") == 0) {
			ud->parser_state = read_struct_member_value;
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_struct_element:
		/* Got tag value */
		if (g_ascii_strcasecmp (name, "value") == 0) {
			ud->parser_state = read_struct_member_name;
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_string:
	case read_int:
	case read_double:
		/* Parse any values */
		/* Handle empty tags */
		if (!ud->got_text) {
			lua_pushnil (ud->L);
		}
		else {
			ud->got_text = FALSE;
		}
		/* Primitives */
		if (g_ascii_strcasecmp (name, "string") == 0 ||
				g_ascii_strcasecmp (name, "int") == 0 ||
				g_ascii_strcasecmp (name, "double") == 0) {
			if (GPOINTER_TO_INT (g_queue_peek_head (ud->st)) == st_struct) {
				ud->parser_state = read_struct_element;
			}
			else {
				ud->parser_state = read_array_element;
			}
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_array:
		/* Got tag array */
		if (g_ascii_strcasecmp (name, "array") == 0) {
			g_assert (GPOINTER_TO_INT (g_queue_pop_head (ud->st)) == st_array);

			if (g_queue_get_length (ud->st) == 0) {
				ud->parser_state = read_param_element;
			}
			else {
				last_queued = GPOINTER_TO_INT (g_queue_peek_head (ud->st));
				if (last_queued == st_struct) {
					ud->parser_state = read_struct_element;
				}
				else {
					ud->parser_state = read_array_element;
				}
			}

			msg_debug_xmlrpc ("pop array");
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_array_value:
		/* Got tag data */
		if (g_ascii_strcasecmp (name, "data") == 0) {
			ud->parser_state = read_array;
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	case read_array_element:
		/* Got tag value */
		if (g_ascii_strcasecmp (name, "value") == 0) {
			guint tbl_len = rspamd_lua_table_size (ud->L, -2);
			lua_rawseti (ud->L, -2, tbl_len + 1);
			msg_debug_xmlrpc ("set array element idx: %d", tbl_len + 1);
			ud->parser_state = read_array_value;
		}
		else {
			/* Error state */
			ud->parser_state = error_state;
		}
		break;
	default:
		break;
	}

	msg_debug_xmlrpc ("switched state on end tag %d->%d",
			last_state, ud->parser_state);

	if (ud->parser_state == error_state) {
		g_set_error (error,
			xmlrpc_error_quark (), 1, "xmlrpc parse error on state: %d, while parsing end tag: %s",
			last_state, name);
	}
}

static void
xmlrpc_text (GMarkupParseContext *context,
	const gchar *text,
	gsize text_len,
	gpointer user_data,
	GError **error)
{
	struct lua_xmlrpc_ud *ud = user_data;
	gulong num;
	gdouble dnum;

	/* Strip line */
	while (text_len > 0 && g_ascii_isspace (*text)) {
		text++;
		text_len--;
	}
	while (text_len > 0 && g_ascii_isspace (text[text_len - 1])) {
		text_len--;
	}

	if (text_len > 0) {
		msg_debug_xmlrpc ("got data on state %d", ud->parser_state);
		switch (ud->parser_state) {
		case read_struct_member_value:
			/* Push key */
			lua_pushlstring (ud->L, text, text_len);
			break;
		case read_string:
			/* Push string value */
			lua_pushlstring (ud->L, text, text_len);
			break;
		case read_int:
			/* Push integer value */
			rspamd_strtoul (text, text_len, &num);
			lua_pushinteger (ud->L, num);
			break;
		case read_double:
			/* Push integer value */
			dnum = strtod (text, NULL);
			lua_pushnumber (ud->L, dnum);
			break;
		default:
			break;
		}
		ud->got_text = TRUE;
	}
}

static void
xmlrpc_error (GMarkupParseContext *context, GError *error, gpointer user_data)
{
	msg_err ("xmlrpc parser error: %s", error->message);
}

static gint
lua_xmlrpc_parse_reply (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *data;
	GMarkupParseContext *ctx;
	GError *err = NULL;
	struct lua_xmlrpc_ud ud;
	gsize s;
	gboolean res;

	data = luaL_checklstring (L, 1, &s);

	if (data != NULL) {
		ud.L = L;
		ud.parser_state = read_method_responce;
		ud.param_count = 0;
		ud.st = g_queue_new ();

		ctx = g_markup_parse_context_new (&xmlrpc_parser,
				G_MARKUP_TREAT_CDATA_AS_TEXT, &ud, NULL);
		res = g_markup_parse_context_parse (ctx, data, s, &err);

		g_markup_parse_context_free (ctx);
		if (!res) {
			lua_pushnil (L);
		}
	}
	else {
		lua_pushnil (L);
	}

	/* Return table or nil */
	return 1;
}

static gint
lua_xmlrpc_parse_table (lua_State *L,
	gint pos,
	gchar *databuf,
	gint pr,
	gsize size)
{
	gint r = pr, num;
	double dnum;

	r += rspamd_snprintf (databuf + r, size - r, "<struct>");
	lua_pushnil (L);  /* first key */
	while (lua_next (L, pos) != 0) {
		/* uses 'key' (at index -2) and 'value' (at index -1) */
		if (lua_type (L, -2) != LUA_TSTRING) {
			/* Ignore non sting keys */
			lua_pop (L, 1);
			continue;
		}
		r += rspamd_snprintf (databuf + r,
				size - r,
				"<member><name>%s</name><value>",
				lua_tostring (L, -2));
		switch (lua_type (L, -1)) {
		case LUA_TNUMBER:
			num = lua_tointeger (L, -1);
			dnum = lua_tonumber (L, -1);

			/* Try to avoid conversion errors */
			if (dnum != (double)num) {
				r += rspamd_snprintf (databuf + r,
						sizeof (databuf) - r,
						"<double>%f</double>",
						dnum);
			}
			else {
				r += rspamd_snprintf (databuf + r,
						sizeof (databuf) - r,
						"<int>%d</int>",
						num);
			}
			break;
		case LUA_TBOOLEAN:
			r += rspamd_snprintf (databuf + r,
					size - r,
					"<boolean>%d</boolean>",
					lua_toboolean (L, -1) ? 1 : 0);
			break;
		case LUA_TSTRING:
			r += rspamd_snprintf (databuf + r, size - r, "<string>%s</string>",
					lua_tostring (L, -1));
			break;
		case LUA_TTABLE:
			/* Recursive call */
			r += lua_xmlrpc_parse_table (L, -1, databuf + r, r, size);
			break;
		}
		r += rspamd_snprintf (databuf + r, size - r, "</value></member>");
		/* removes 'value'; keeps 'key' for next iteration */
		lua_pop (L, 1);
	}
	r += rspamd_snprintf (databuf + r, size - r, "</struct>");

	return r - pr;
}

/*
 * Internal limitation: xmlrpc request must NOT be more than
 * BUFSIZ * 2 (16384 bytes)
 */
static gint
lua_xmlrpc_make_request (lua_State *L)
{
	LUA_TRACE_POINT;
	gchar databuf[BUFSIZ * 2];
	const gchar *func;
	gint r, top, i, num;
	double dnum;

	func = luaL_checkstring (L, 1);

	if (func) {
		r = rspamd_snprintf (databuf, sizeof(databuf),
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				"<methodCall><methodName>%s</methodName><params>",
				func);
		/* Extract arguments */
		top = lua_gettop (L);
		/* Get additional options */
		for (i = 2; i <= top; i++) {
			r += rspamd_snprintf (databuf + r,
					sizeof (databuf) - r,
					"<param><value>");
			switch (lua_type (L, i)) {
			case LUA_TNUMBER:
				num = lua_tointeger (L, i);
				dnum = lua_tonumber (L, i);

				/* Try to avoid conversion errors */
				if (dnum != (double)num) {
					r += rspamd_snprintf (databuf + r,
							sizeof (databuf) - r,
							"<double>%f</double>",
							dnum);
				}
				else {
					r += rspamd_snprintf (databuf + r,
							sizeof (databuf) - r,
							"<int>%d</int>",
							num);
				}
				break;
			case LUA_TBOOLEAN:
				r += rspamd_snprintf (databuf + r,
						sizeof (databuf) - r,
						"<boolean>%d</boolean>",
						lua_toboolean (L, i) ? 1 : 0);
				break;
			case LUA_TSTRING:
				r += rspamd_snprintf (databuf + r,
						sizeof (databuf) - r,
						"<string>%s</string>",
						lua_tostring (L, i));
				break;
			case LUA_TTABLE:
				r +=
					lua_xmlrpc_parse_table (L, i, databuf, r, sizeof (databuf));
				break;
			}
			r += rspamd_snprintf (databuf + r,
					sizeof (databuf) - r,
					"</value></param>");
		}

		r += rspamd_snprintf (databuf + r,
				sizeof (databuf) - r,
				"</params></methodCall>");
		lua_pushlstring (L, databuf, r);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_load_xmlrpc (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, xmlrpclib_m);

	return 1;
}

void
luaopen_xmlrpc (lua_State * L)
{
	rspamd_lua_add_preload (L, "rspamd_xmlrpc", lua_load_xmlrpc);
}

