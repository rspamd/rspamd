/*-
 * Copyright 2020 Vsevolod Stakhov
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
#include "tokenizers/tokenizers.h"
#include "contrib/uthash/utlist.h"
#include "libserver/html/html.h"
#include "libmime/email_addr.h"
#include "libmime/content_type.h"
#include "libmime/mime_headers.h"
#include "libmime/smtp_parsers.h"
#include "lua_parsers.h"

/***
 * @module rspamd_parsers
 * This module contains Lua-C interfaces to Rspamd parsers of different kind.
 */

/***
 * @function parsers.tokenize_text(input[, exceptions])
 * Create tokens from a text using optional exceptions list
 * @param {text/string} input input data
 * @param {table} exceptions, a table of pairs containing <start_pos,length> of exceptions in the input
 * @return {table/strings} list of strings representing words in the text
 */


/***
 * @function parsers.parse_html(input)
 * Parses HTML and returns the according text
 * @param {string|text} in input HTML
 * @return {rspamd_text} processed text with no HTML tags
 */

/***
 * @function parsers.parse_mail_address(str, [pool])
 * Parses email address and returns a table of tables in the following format:
 *
 * - `raw` - the original value without any processing
 * - `name` - name of internet address in UTF8, e.g. for `Vsevolod Stakhov <blah@foo.com>` it returns `Vsevolod Stakhov`
 * - `addr` - address part of the address
 * - `user` - user part (if present) of the address, e.g. `blah`
 * - `domain` - domain part (if present), e.g. `foo.com`
 * - `flags` - table with following keys set to true if given condition fulfilled:
 *   - [valid] - valid SMTP address in conformity with https://tools.ietf.org/html/rfc5321#section-4.1.
 *   - [ip] - domain is IPv4/IPv6 address
 *   - [braced] - angled `<blah@foo.com>` address
 *   - [quoted] - quoted user part
 *   - [empty] - empty address
 *   - [backslash] - user part contains backslash
 *   - [8bit] - contains 8bit characters
 *
 * @param {string} str input string
 * @param {rspamd_mempool} pool memory pool to use
 * @return {table/tables} parsed list of mail addresses
 */

/***
 *  @function parsers.parse_content_type(ct_string, mempool)
 * Parses content-type string to a table:
 * - `type`
 * - `subtype`
 * - `charset`
 * - `boundary`
 * - other attributes
 *
 * @param {string} ct_string content type as string
 * @param {rspamd_mempool} mempool needed to store temporary data (e.g. task pool)
 * @return table or nil if cannot parse content type
 */

/***
 * @function parsers.parse_smtp_date(str[, local_tz])
 * Converts an SMTP date string to unix timestamp
 * @param {string} str input string
 * @param {boolean} local_tz convert to local tz if `true`
 * @return {number} time as unix timestamp (converted to float)
 */

static const struct luaL_reg parserslib_f[] = {
	LUA_INTERFACE_DEF (parsers, tokenize_text),
	LUA_INTERFACE_DEF (parsers, parse_html),
	LUA_INTERFACE_DEF (parsers, parse_mail_address),
	LUA_INTERFACE_DEF (parsers, parse_content_type),
	LUA_INTERFACE_DEF (parsers, parse_smtp_date),

	{NULL, NULL}
};

gint
lua_parsers_tokenize_text (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *in = NULL;
	gsize len = 0, pos, ex_len, i;
	GList *exceptions = NULL, *cur;
	struct rspamd_lua_text *t;
	struct rspamd_process_exception *ex;
	UText utxt = UTEXT_INITIALIZER;
	GArray *res;
	rspamd_stat_token_t *w;

	if (lua_type (L, 1) == LUA_TSTRING) {
		in = luaL_checklstring (L, 1, &len);
	}
	else if (lua_type (L, 1) == LUA_TUSERDATA) {
		t = lua_check_text (L, 1);

		if (t) {
			in = t->start;
			len = t->len;
		}
	}

	if (in == NULL) {
		lua_pushnil (L);
		return 1;
	}

	if (lua_gettop (L) > 1 && lua_type (L, 2) == LUA_TTABLE) {
		lua_pushvalue (L, 2);
		lua_pushnil (L);

		while (lua_next (L, -2) != 0) {
			if (lua_type (L, -1) == LUA_TTABLE) {
				lua_rawgeti (L, -1, 1);
				pos = luaL_checknumber (L, -1);
				lua_pop (L, 1);
				lua_rawgeti (L, -1, 2);
				ex_len = luaL_checknumber (L, -1);
				lua_pop (L, 1);

				if (ex_len > 0) {
					ex = g_malloc0 (sizeof (*ex));
					ex->pos = pos;
					ex->len = ex_len;
					ex->type = RSPAMD_EXCEPTION_GENERIC;
					exceptions = g_list_prepend (exceptions, ex);
				}
			}
			lua_pop (L, 1);
		}

		lua_pop (L, 1);
	}

	if (exceptions) {
		exceptions = g_list_reverse (exceptions);
	}

	UErrorCode uc_err = U_ZERO_ERROR;
	utext_openUTF8 (&utxt,
			in,
			len,
			&uc_err);

	res = rspamd_tokenize_text ((gchar *)in, len,
			&utxt,
			RSPAMD_TOKENIZE_UTF, NULL,
			exceptions,
			NULL, NULL, NULL);

	if (res == NULL) {
		lua_pushnil (L);
	}
	else {
		lua_createtable (L, res->len, 0);

		for (i = 0; i < res->len; i ++) {
			w = &g_array_index (res, rspamd_stat_token_t, i);
			lua_pushlstring (L, w->original.begin, w->original.len);
			lua_rawseti (L, -2, i + 1);
		}
	}

	cur = exceptions;
	while (cur) {
		ex = cur->data;
		g_free (ex);
		cur = g_list_next (cur);
	}

	g_list_free (exceptions);
	utext_close (&utxt);

	return 1;
}

gint
lua_parsers_parse_html (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t;
	const gchar *start = NULL;
	gsize len;
	GByteArray *in;
	rspamd_mempool_t *pool;
	void *hc;

	if (lua_type (L, 1) == LUA_TUSERDATA) {
		t = lua_check_text (L, 1);

		if (t != NULL) {
			start = t->start;
			len = t->len;
		}
	}
	else if (lua_type (L, 1) == LUA_TSTRING) {
		start = luaL_checklstring (L, 1, &len);
	}

	if (start != NULL) {
		pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL, 0);
		in = g_byte_array_sized_new (len);
		g_byte_array_append (in, start, len);

		hc = rspamd_html_process_part(pool, in);

		rspamd_ftok_t res;
		rspamd_html_get_parsed_content(hc, &res);
		lua_new_text(L, res.begin, res.len, TRUE);

		g_byte_array_free (in, TRUE);
		rspamd_mempool_delete (pool);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

gint
lua_parsers_parse_mail_address (lua_State *L)
{
	LUA_TRACE_POINT;
	GPtrArray *addrs;
	gsize len;
	const gchar *str = luaL_checklstring (L, 1, &len);
	gint max_addrs = luaL_optinteger(L, 3, 10240);
	rspamd_mempool_t *pool;
	gboolean own_pool = FALSE;

	if (str) {

		if (lua_type (L, 2) == LUA_TUSERDATA) {
			pool = rspamd_lua_check_mempool (L, 2);

			if (pool == NULL) {
				return luaL_error (L, "invalid arguments");
			}
		}
		else {
			pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
					"lua parsers", 0);
			own_pool = TRUE;
		}

		addrs = rspamd_email_address_from_mime (pool, str, len, NULL, max_addrs);

		if (addrs == NULL) {
			lua_pushnil (L);
		}
		else {
			lua_push_emails_address_list (L, addrs, 0);
		}

		if (own_pool) {
			rspamd_mempool_delete (pool);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

gint
lua_parsers_parse_content_type (lua_State *L)
{
	LUA_TRACE_POINT;
	gsize len;
	const gchar *ct_str = luaL_checklstring (L, 1, &len);
	rspamd_mempool_t *pool = rspamd_lua_check_mempool (L, 2);
	struct rspamd_content_type *ct;

	if (!ct_str || !pool) {
		return luaL_error (L, "invalid arguments");
	}

	ct = rspamd_content_type_parse (ct_str, len, pool);

	if (ct == NULL) {
		lua_pushnil (L);
	}
	else {
		GHashTableIter it;
		gpointer k, v;

		lua_createtable (L, 0, 4 + (ct->attrs ? g_hash_table_size (ct->attrs) : 0));

		if (ct->type.len > 0) {
			lua_pushstring (L, "type");
			lua_pushlstring (L, ct->type.begin, ct->type.len);
			lua_settable (L, -3);
		}

		if (ct->subtype.len > 0) {
			lua_pushstring (L, "subtype");
			lua_pushlstring (L, ct->subtype.begin, ct->subtype.len);
			lua_settable (L, -3);
		}

		if (ct->charset.len > 0) {
			lua_pushstring (L, "charset");
			lua_pushlstring (L, ct->charset.begin, ct->charset.len);
			lua_settable (L, -3);
		}

		if (ct->orig_boundary.len > 0) {
			lua_pushstring (L, "boundary");
			lua_pushlstring (L, ct->orig_boundary.begin, ct->orig_boundary.len);
			lua_settable (L, -3);
		}

		if (ct->attrs) {
			g_hash_table_iter_init (&it, ct->attrs);

			while (g_hash_table_iter_next (&it, &k, &v)) {
				struct rspamd_content_type_param *param =
						(struct rspamd_content_type_param *)v, *cur;
				guint i = 1;

				lua_pushlstring (L, param->name.begin, param->name.len);
				lua_createtable (L, 1, 0);

				DL_FOREACH (param, cur) {
					lua_pushlstring (L, cur->value.begin, cur->value.len);
					lua_rawseti (L, -2, i++);
				}

				lua_settable (L, -3);
			}
		}
	}

	return 1;
}

int
lua_parsers_parse_smtp_date (lua_State *L)
{
	gsize slen;
	const gchar *str = lua_tolstring (L, 1, &slen);
	GError *err = NULL;

	if (str == NULL) {
		return luaL_argerror (L, 1, "invalid argument");
	}

	time_t tt = rspamd_parse_smtp_date (str, slen, &err);

	if (err == NULL) {
		if (lua_isboolean (L, 2) && !!lua_toboolean (L, 2)) {
			struct tm t;

			rspamd_localtime (tt, &t);
#if !defined(__sun)
			t.tm_gmtoff = 0;
#endif
			t.tm_isdst = 0;
			tt = mktime (&t);
		}

		lua_pushnumber (L, tt);
	}
	else {
		lua_pushnil (L);
		lua_pushstring (L, err->message);
		g_error_free (err);

		return 2;
	}

	return 1;
}

static gint
lua_load_parsers (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, parserslib_f);

	return 1;
}

void
luaopen_parsers (lua_State * L)
{
	rspamd_lua_add_preload (L, "rspamd_parsers", lua_load_parsers);
}