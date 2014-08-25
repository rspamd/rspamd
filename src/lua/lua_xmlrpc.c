/* Copyright (c) 2010, Vsevolod Stakhov
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

#include "lua_common.h"


LUA_FUNCTION_DEF (xmlrpc, parse_reply);
LUA_FUNCTION_DEF (xmlrpc, make_request);

static const struct luaL_reg xmlrpclib_m[] = {
	LUA_INTERFACE_DEF (xmlrpc, parse_reply),
	LUA_INTERFACE_DEF (xmlrpc, make_request),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

struct lua_xmlrpc_ud {
	gint parser_state;
	gint depth;
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
	int last_state;

	last_state = ud->parser_state;

	switch (ud->parser_state) {
	case 0:
		/* Expect tag methodResponse */
		if (g_ascii_strcasecmp (name, "methodResponse") == 0) {
			ud->parser_state = 1;
		}
		else {
			/* Error state */
			ud->parser_state = 99;
		}
		break;
	case 1:
		/* Expect tag params */
		if (g_ascii_strcasecmp (name, "params") == 0) {
			ud->parser_state = 2;
			/* result -> table of params indexed by int */
			lua_newtable (ud->L);
		}
		else {
			/* Error state */
			ud->parser_state = 99;
		}
		break;
	case 2:
		/* Expect tag param */
		if (g_ascii_strcasecmp (name, "param") == 0) {
			ud->parser_state = 3;
			/* Create new param */
		}
		else {
			/* Error state */
			ud->parser_state = 99;
		}
		break;
	case 3:
		/* Expect tag value */
		if (g_ascii_strcasecmp (name, "value") == 0) {
			ud->parser_state = 4;
		}
		else {
			/* Error state */
			ud->parser_state = 99;
		}
		break;
	case 4:
		/* Expect tag struct */
		if (g_ascii_strcasecmp (name, "struct") == 0) {
			ud->parser_state = 5;
			/* Create new param of table type */
			lua_newtable (ud->L);
			ud->depth++;
		}
		else if (g_ascii_strcasecmp (name, "string") == 0) {
			ud->parser_state = 11;
			ud->got_text = FALSE;
		}
		else if (g_ascii_strcasecmp (name, "int") == 0) {
			ud->parser_state = 12;
			ud->got_text = FALSE;
		}
		else if (g_ascii_strcasecmp (name, "double") == 0) {
			ud->parser_state = 13;
			ud->got_text = FALSE;
		}
		else {
			/* Error state */
			ud->parser_state = 99;
		}
		break;
	case 5:
		/* Parse structure */
		/* Expect tag member */
		if (g_ascii_strcasecmp (name, "member") == 0) {
			ud->parser_state = 6;
		}
		else {
			/* Error state */
			ud->parser_state = 99;
		}
		break;
	case 6:
		/* Expect tag name */
		if (g_ascii_strcasecmp (name, "name") == 0) {
			ud->parser_state = 7;
		}
		else {
			/* Error state */
			ud->parser_state = 99;
		}
		break;
	case 7:
		/* Accept value */
		if (g_ascii_strcasecmp (name, "value") == 0) {
			ud->parser_state = 8;
		}
		else {
			/* Error state */
			ud->parser_state = 99;
		}
		break;
	case 8:
		/* Parse any values */
		/* Primitives */
		if (g_ascii_strcasecmp (name, "string") == 0) {
			ud->parser_state = 11;
			ud->got_text = FALSE;
		}
		else if (g_ascii_strcasecmp (name, "int") == 0) {
			ud->parser_state = 12;
			ud->got_text = FALSE;
		}
		else if (g_ascii_strcasecmp (name, "double") == 0) {
			ud->parser_state = 13;
			ud->got_text = FALSE;
		}
		/* Structure */
		else if (g_ascii_strcasecmp (name, "struct") == 0) {
			ud->parser_state = 5;
			/* Create new param of table type */
			lua_newtable (ud->L);
			ud->depth++;
		}
		else {
			/* Error state */
			ud->parser_state = 99;
		}
		break;
	}

	if (ud->parser_state == 99) {
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
	int last_state;

	last_state = ud->parser_state;

	switch (ud->parser_state) {
	case 0:
		ud->parser_state = 99;
		break;
	case 1:
		/* Got methodResponse */
		if (g_ascii_strcasecmp (name, "methodResponse") == 0) {
			/* End processing */
			ud->parser_state = 100;
		}
		else {
			/* Error state */
			ud->parser_state = 99;
		}
		break;
	case 2:
		/* Got tag params */
		if (g_ascii_strcasecmp (name, "params") == 0) {
			ud->parser_state = 1;
		}
		else {
			/* Error state */
			ud->parser_state = 99;
		}
		break;
	case 3:
		/* Got tag param */
		if (g_ascii_strcasecmp (name, "param") == 0) {
			ud->parser_state = 2;
			lua_rawseti (ud->L, -2, ++ud->param_count);
		}
		else {
			/* Error state */
			ud->parser_state = 99;
		}
		break;
	case 4:
		/* Got tag value */
		if (g_ascii_strcasecmp (name, "value") == 0) {
			if (ud->depth == 0) {
				ud->parser_state = 3;
			}
			else {
				/* Parse other members */
				ud->parser_state = 6;
			}
		}
		else {
			/* Error state */
			ud->parser_state = 99;
		}
		break;
	case 5:
		/* Got tag struct */
		if (g_ascii_strcasecmp (name, "struct") == 0) {
			ud->parser_state = 4;
			ud->depth--;
		}
		else {
			/* Error state */
			ud->parser_state = 99;
		}
		break;
	case 6:
		/* Got tag member */
		if (g_ascii_strcasecmp (name, "member") == 0) {
			ud->parser_state = 5;
			/* Set table */
			lua_settable (ud->L, -3);
		}
		else {
			/* Error state */
			ud->parser_state = 99;
		}
		break;
	case 7:
		/* Got tag name */
		if (g_ascii_strcasecmp (name, "name") == 0) {
			ud->parser_state = 7;
		}
		else {
			/* Error state */
			ud->parser_state = 99;
		}
		break;
	case 8:
		/* Got tag value */
		if (g_ascii_strcasecmp (name, "value") == 0) {
			ud->parser_state = 6;
		}
		else {
			/* Error state */
			ud->parser_state = 99;
		}
		break;
	case 11:
	case 12:
	case 13:
		/* Parse any values */
		/* Handle empty tags */
		if (!ud->got_text) {
			lua_pushnil (ud->L);
		}
		else {
			ud->got_text = FALSE;
		}
		/* Primitives */
		if (g_ascii_strcasecmp (name, "string") == 0) {
			ud->parser_state = 8;
		}
		else if (g_ascii_strcasecmp (name, "int") == 0) {
			ud->parser_state = 8;
		}
		else if (g_ascii_strcasecmp (name, "double") == 0) {
			ud->parser_state = 8;
		}
		else {
			/* Error state */
			ud->parser_state = 99;
		}
		break;
	}

	if (ud->parser_state == 99) {
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
	gint num;
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

		switch (ud->parser_state) {
		case 7:
			/* Push key */
			lua_pushlstring (ud->L, text, text_len);
			break;
		case 11:
			/* Push string value */
			lua_pushlstring (ud->L, text, text_len);
			break;
		case 12:
			/* Push integer value */
			num = strtoul (text, NULL, 10);
			lua_pushinteger (ud->L, num);
			break;
		case 13:
			/* Push integer value */
			dnum = strtod (text, NULL);
			lua_pushnumber (ud->L, dnum);
			break;
		}
		ud->got_text = TRUE;
	}
}

static void
xmlrpc_error (GMarkupParseContext *context, GError *error, gpointer user_data)
{
	struct lua_xmlrpc_ud *ud = user_data;

	msg_err ("xmlrpc parser error: %s", error->message, ud->parser_state);
}

static gint
lua_xmlrpc_parse_reply (lua_State *L)
{
	const gchar *data;
	GMarkupParseContext *ctx;
	GError *err = NULL;
	struct lua_xmlrpc_ud ud;
	gsize s;
	gboolean res;

	data = luaL_checklstring (L, 1, &s);

	if (data != NULL) {
		ud.L = L;
		ud.parser_state = 0;
		ud.depth = 0;
		ud.param_count = 0;

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

