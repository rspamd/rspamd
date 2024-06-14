/*
 * Copyright 2024 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "lua_common.h"
#include "lua_url.h"


/***
 * @module rspamd_url
 * This module provides routines to handle URL's and extract URL's from the text.
 * Objects of this class are returned, for example, by `task:get_urls()` or `task:get_emails()`.
 * You can also create `rspamd_url` from any text.
 * @example
local url = require "rspamd_url"
local mpool = require "rspamd_mempool"

url.init("/usr/share/rspamd/effective_tld_names.dat")
local pool = mpool.create()
local res = url.create(pool, 'Look at: http://user@test.example.com/test?query")
local t = res:to_table()
-- Content of t:
-- url = ['http://test.example.com/test?query']
-- host = ['test.example.com']
-- user = ['user']
-- path = ['test']
-- tld = ['example.com']

pool:destroy() -- res is destroyed here, so you should not use it afterwards

local mistake = res:to_table() -- INVALID! as pool is destroyed
 */

/* URL methods */
LUA_FUNCTION_DEF(url, get_length);
LUA_FUNCTION_DEF(url, get_host);
LUA_FUNCTION_DEF(url, get_port);
LUA_FUNCTION_DEF(url, get_user);
LUA_FUNCTION_DEF(url, get_path);
LUA_FUNCTION_DEF(url, get_query);
LUA_FUNCTION_DEF(url, get_fragment);
LUA_FUNCTION_DEF(url, get_text);
LUA_FUNCTION_DEF(url, tostring);
LUA_FUNCTION_DEF(url, get_raw);
LUA_FUNCTION_DEF(url, get_tld);
LUA_FUNCTION_DEF(url, get_flags);
LUA_FUNCTION_DEF(url, get_flags_num);
LUA_FUNCTION_DEF(url, get_protocol);
LUA_FUNCTION_DEF(url, to_table);
LUA_FUNCTION_DEF(url, is_phished);
LUA_FUNCTION_DEF(url, is_redirected);
LUA_FUNCTION_DEF(url, is_obscured);
LUA_FUNCTION_DEF(url, is_html_displayed);
LUA_FUNCTION_DEF(url, is_subject);
LUA_FUNCTION_DEF(url, get_phished);
LUA_FUNCTION_DEF(url, set_redirected);
LUA_FUNCTION_DEF(url, get_count);
LUA_FUNCTION_DEF(url, get_visible);
LUA_FUNCTION_DEF(url, create);
LUA_FUNCTION_DEF(url, init);
LUA_FUNCTION_DEF(url, all);
LUA_FUNCTION_DEF(url, lt);
LUA_FUNCTION_DEF(url, eq);
LUA_FUNCTION_DEF(url, get_order);
LUA_FUNCTION_DEF(url, get_part_order);
LUA_FUNCTION_DEF(url, to_http);

static const struct luaL_reg urllib_m[] = {
	LUA_INTERFACE_DEF(url, get_length),
	LUA_INTERFACE_DEF(url, get_host),
	LUA_INTERFACE_DEF(url, get_port),
	LUA_INTERFACE_DEF(url, get_user),
	LUA_INTERFACE_DEF(url, get_path),
	LUA_INTERFACE_DEF(url, get_query),
	LUA_INTERFACE_DEF(url, get_fragment),
	LUA_INTERFACE_DEF(url, get_text),
	LUA_INTERFACE_DEF(url, get_tld),
	LUA_INTERFACE_DEF(url, get_raw),
	LUA_INTERFACE_DEF(url, get_protocol),
	LUA_INTERFACE_DEF(url, to_table),
	LUA_INTERFACE_DEF(url, is_phished),
	LUA_INTERFACE_DEF(url, is_redirected),
	LUA_INTERFACE_DEF(url, is_obscured),
	LUA_INTERFACE_DEF(url, is_html_displayed),
	LUA_INTERFACE_DEF(url, is_subject),
	LUA_INTERFACE_DEF(url, get_phished),

	LUA_INTERFACE_DEF(url, get_visible),
	LUA_INTERFACE_DEF(url, get_count),
	LUA_INTERFACE_DEF(url, get_flags),
	LUA_INTERFACE_DEF(url, get_flags_num),
	LUA_INTERFACE_DEF(url, get_order),
	LUA_INTERFACE_DEF(url, get_part_order),
	LUA_INTERFACE_DEF(url, to_http),
	{"get_redirected", lua_url_get_phished},
	LUA_INTERFACE_DEF(url, set_redirected),
	{"__tostring", lua_url_tostring},
	{"__eq", lua_url_eq},
	{"__lt", lua_url_lt},
	{NULL, NULL}};

static const struct luaL_reg urllib_f[] = {
	LUA_INTERFACE_DEF(url, init),
	LUA_INTERFACE_DEF(url, create),
	LUA_INTERFACE_DEF(url, all),
	{NULL, NULL}};

struct rspamd_lua_url *
lua_check_url(lua_State *L, int pos)
{
	void *ud = rspamd_lua_check_udata(L, pos, rspamd_url_classname);
	luaL_argcheck(L, ud != NULL, pos, "'url' expected");
	return ud ? ((struct rspamd_lua_url *) ud) : NULL;
}

static gboolean
lua_url_single_inserter(struct rspamd_url *url, gsize start_offset,
						gsize end_offset, gpointer ud)
{
	lua_State *L = ud;
	struct rspamd_lua_url *lua_url;

	lua_url = lua_newuserdata(L, sizeof(struct rspamd_lua_url));
	rspamd_lua_setclass(L, rspamd_url_classname, -1);
	lua_url->url = url;

	return TRUE;
}

/***
 * @method url:get_length()
 * Get length of the url
 * @return {number} length of url in bytes
 */
static int
lua_url_get_length(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL) {
		lua_pushinteger(L, url->url->urllen);
	}
	else {
		lua_pushnil(L);
	}
	return 1;
}

/***
 * @method url:get_host()
 * Get domain part of the url
 * @return {string} domain part of URL
 */
static int
lua_url_get_host(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL && url->url && url->url->hostlen > 0) {
		lua_pushlstring(L, rspamd_url_host(url->url), url->url->hostlen);
	}
	else {
		lua_pushnil(L);
	}
	return 1;
}

/***
 * @method url:get_port()
 * Get port of the url
 * @return {number} url port
 */
static int
lua_url_get_port(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL) {
		if (rspamd_url_get_port_if_special(url->url) == 0) {
			lua_pushnil(L);
		}
		else {
			lua_pushinteger(L, rspamd_url_get_port_if_special(url->url));
		}
	}
	else {
		lua_pushnil(L);
	}
	return 1;
}

/***
 * @method url:get_user()
 * Get user part of the url (e.g. username in email)
 * @return {string} user part of URL
 */
static int
lua_url_get_user(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL && rspamd_url_user(url->url) != NULL) {
		lua_pushlstring(L, rspamd_url_user(url->url), url->url->userlen);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

/***
 * @method url:get_path()
 * Get path of the url
 * @return {string} path part of URL
 */
static int
lua_url_get_path(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL && url->url->datalen > 0) {
		lua_pushlstring(L, rspamd_url_data_unsafe(url->url), url->url->datalen);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

/***
 * @method url:get_query()
 * Get query of the url
 * @return {string} query part of URL
 */
static int
lua_url_get_query(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL && url->url->querylen > 0) {
		lua_pushlstring(L, rspamd_url_query_unsafe(url->url), url->url->querylen);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

/***
 * @method url:get_fragment()
 * Get fragment of the url
 * @return {string} fragment part of URL
 */
static int
lua_url_get_fragment(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL && url->url->fragmentlen > 0) {
		lua_pushlstring(L, rspamd_url_fragment_unsafe(url->url), url->url->fragmentlen);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

/***
 * @method url:get_text()
 * Get full content of the url
 * @return {string} url string
 */
static int
lua_url_get_text(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL) {
		lua_pushlstring(L, url->url->string, url->url->urllen);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

/***
 * @method url:tostring()
 * Get full content of the url or user@domain in case of email
 * @return {string} url as a string
 */
static int
lua_url_tostring(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL && url->url != NULL) {
		if (url->url->protocol == PROTOCOL_MAILTO) {
			char *tmp = g_malloc(url->url->userlen + 1 +
								 url->url->hostlen);
			if (url->url->userlen) {
				memcpy(tmp, url->url->string + url->url->usershift, url->url->userlen);
			}

			tmp[url->url->userlen] = '@';
			memcpy(tmp + url->url->userlen + 1, rspamd_url_host_unsafe(url->url),
				   url->url->hostlen);

			lua_pushlstring(L, tmp, url->url->userlen + 1 + url->url->hostlen);
			g_free(tmp);
		}
		else {
			lua_pushlstring(L, url->url->string, url->url->urllen);
		}
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

/***
 * @method url:to_http()
 * Get URL suitable for HTTP request (e.g. by trimming fragment and user parts)
 * @return {string} url as a string
 */
static int
lua_url_to_http(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL && url->url != NULL) {
		if (url->url->protocol == PROTOCOL_MAILTO) {
			/* Nothing to do here */
			lua_pushnil(L);
		}
		else {

			if (url->url->userlen > 0) {
				/* We need to reconstruct url :( */
				gsize len = url->url->urllen - url->url->fragmentlen + 1;

				/* Strip the # character */
				if (url->url->fragmentlen > 0 && len > 0) {
					while (url->url->string[len - 1] == '#' && len > 0) {
						len--;
					}
				}
				char *nstr = g_malloc(len);
				char *d = nstr, *end = nstr + len;
				memcpy(nstr, url->url->string, url->url->protocollen);
				d += url->url->protocollen;
				*d++ = ':';
				*d++ = '/';
				*d++ = '/';

				/* Host part */
				memcpy(d, rspamd_url_host(url->url), url->url->hostlen);
				d += url->url->hostlen;

				int port = rspamd_url_get_port_if_special(url->url);

				if (port > 0) {
					d += rspamd_snprintf(d, end - d, ":%d/", port);
				}
				else {
					*d++ = '/';
				}

				if (url->url->datalen > 0) {
					memcpy(d, rspamd_url_data_unsafe(url->url), url->url->datalen);
					d += url->url->datalen;
				}

				if (url->url->querylen > 0) {
					*d++ = '?';
					memcpy(d, rspamd_url_query_unsafe(url->url), url->url->querylen);
					d += url->url->querylen;
				}

				g_assert(d < end);
				lua_pushlstring(L, nstr, d - nstr);
			}
			else {
				gsize len = url->url->urllen - url->url->fragmentlen;

				/* Strip the # character */
				if (url->url->fragmentlen > 0 && len > 0) {
					while (url->url->string[len - 1] == '#' && len > 0) {
						len--;
					}
				}
				lua_pushlstring(L, url->url->string, len);
			}
		}
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

/***
 * @method url:get_raw()
 * Get full content of the url as it was parsed (e.g. with urldecode)
 * @return {string} url string
 */
static int
lua_url_get_raw(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL) {
		lua_pushlstring(L, url->url->raw, url->url->rawlen);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

/***
 * @method url:is_phished()
 * Check whether URL is treated as phished
 * @return {boolean} `true` if URL is phished
 */
static int
lua_url_is_phished(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL) {
		lua_pushboolean(L, url->url->flags & RSPAMD_URL_FLAG_PHISHED);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

/***
 * @method url:is_redirected()
 * Check whether URL was redirected
 * @return {boolean} `true` if URL is redirected
 */
static int
lua_url_is_redirected(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL) {
		lua_pushboolean(L, url->url->flags & RSPAMD_URL_FLAG_REDIRECTED);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

/***
 * @method url:is_obscured()
 * Check whether URL is treated as obscured or obfuscated (e.g. numbers in IP address or other hacks)
 * @return {boolean} `true` if URL is obscured
 */
static int
lua_url_is_obscured(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL) {
		lua_pushboolean(L, url->url->flags & RSPAMD_URL_FLAG_OBSCURED);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}


/***
 * @method url:is_html_displayed()
 * Check whether URL is just displayed in HTML (e.g. NOT a real href)
 * @return {boolean} `true` if URL is displayed only
 */
static int
lua_url_is_html_displayed(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL) {
		lua_pushboolean(L, url->url->flags & RSPAMD_URL_FLAG_HTML_DISPLAYED);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

/***
 * @method url:is_subject()
 * Check whether URL is found in subject
 * @return {boolean} `true` if URL is found in subject
 */
static int
lua_url_is_subject(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL) {
		lua_pushboolean(L, url->url->flags & RSPAMD_URL_FLAG_SUBJECT);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

/***
 * @method url:get_phished()
 * Get another URL that pretends to be this URL (e.g. used in phishing)
 * @return {url} phished URL
 */
static int
lua_url_get_phished(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *purl, *url = lua_check_url(L, 1);

	if (url) {
		if (url->url->ext && url->url->ext->linked_url != NULL) {
			/* XXX: in fact, this is the only possible combination of flags, so this check is redundant */
			if (url->url->flags &
				(RSPAMD_URL_FLAG_PHISHED | RSPAMD_URL_FLAG_REDIRECTED)) {
				purl = lua_newuserdata(L, sizeof(struct rspamd_lua_url));
				rspamd_lua_setclass(L, rspamd_url_classname, -1);
				purl->url = url->url->ext->linked_url;

				return 1;
			}
		}
	}

	lua_pushnil(L);
	return 1;
}

/***
 * @method url:set_redirected(url, pool)
 * Set url as redirected to another url
 * @param {string|url} url new url that is redirecting an old one
 * @param {pool} pool memory pool to allocate memory if needed
 * @return {url} parsed redirected url (if needed)
 */
static int
lua_url_set_redirected(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1), *redir;
	rspamd_mempool_t *pool = NULL;

	if (url == NULL) {
		return luaL_error(L, "url is required as the first argument");
	}

	if (lua_type(L, 2) == LUA_TSTRING) {
		/* Parse url */
		if (lua_type(L, 3) != LUA_TUSERDATA) {
			return luaL_error(L, "mempool is required as the third argument");
		}

		pool = rspamd_lua_check_mempool(L, 3);

		if (pool == NULL) {
			return luaL_error(L, "mempool is required as the third argument");
		}

		gsize len;
		const char *urlstr = lua_tolstring(L, 2, &len);

		rspamd_url_find_single(pool, urlstr, len, RSPAMD_URL_FIND_ALL,
							   lua_url_single_inserter, L);

		if (lua_type(L, -1) != LUA_TUSERDATA) {
			/* URL is actually not found */
			lua_pushnil(L);
		}
		else {
			redir = lua_check_url(L, -1);

			url->url->flags |= RSPAMD_URL_FLAG_REDIRECTED;

			if (url->url->ext == NULL) {
				url->url->ext = rspamd_mempool_alloc0_type(pool, struct rspamd_url_ext);
			}
			url->url->ext->linked_url = redir->url;
		}
	}
	else {
		redir = lua_check_url(L, 2);

		if (redir == NULL) {
			return luaL_error(L, "url is required as the second argument");
		}

		pool = rspamd_lua_check_mempool(L, 3);

		if (pool == NULL) {
			return luaL_error(L, "mempool is required as the third argument");
		}

		url->url->flags |= RSPAMD_URL_FLAG_REDIRECTED;
		if (url->url->ext == NULL) {
			url->url->ext = rspamd_mempool_alloc0_type(pool, struct rspamd_url_ext);
		}
		url->url->ext->linked_url = redir->url;

		/* Push back on stack */
		lua_pushvalue(L, 2);
	}

	return 1;
}

/***
 * @method url:get_tld()
 * Get effective second level domain part (eSLD) of the url host
 * @return {string} effective second level domain part (eSLD) of the url host
 */
static int
lua_url_get_tld(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL && url->url->tldlen > 0) {
		lua_pushlstring(L, rspamd_url_tld_unsafe(url->url), url->url->tldlen);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

/***
 * @method url:get_protocol()
 * Get protocol name
 * @return {string} protocol as a string
 */
static int
lua_url_get_protocol(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL && url->url->protocol != PROTOCOL_UNKNOWN) {
		lua_pushstring(L, rspamd_url_protocol_name(url->url->protocol));
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

/***
 * @method url:get_count()
 * Return number of occurrences for this particular URL
 * @return {number} number of occurrences
 */
static int
lua_url_get_count(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL && url->url != NULL) {
		lua_pushinteger(L, url->url->count);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

/***
* @method url:get_visible()
* Get visible part of the url with html tags stripped
* @return {string} url string
*/
static int
lua_url_get_visible(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url != NULL && url->url->ext && url->url->ext->visible_part) {
		lua_pushstring(L, url->url->ext->visible_part);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

/***
 * @method url:to_table()
 * Return url as a table with the following fields:
 *
 * - `url`: full content
 * - `host`: hostname part
 * - `user`: user part
 * - `path`: path part
 * - `tld`: top level domain
 * - `protocol`: url protocol
 * @return {table} URL as a table
 */
static int
lua_url_to_table(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);
	struct rspamd_url *u;

	if (url != NULL) {
		u = url->url;
		lua_createtable(L, 0, 12);
		lua_pushstring(L, "url");
		lua_pushlstring(L, u->string, u->urllen);
		lua_settable(L, -3);

		if (u->hostlen > 0) {
			lua_pushstring(L, "host");
			lua_pushlstring(L, rspamd_url_host_unsafe(u), u->hostlen);
			lua_settable(L, -3);
		}

		if (rspamd_url_get_port_if_special(u) != 0) {
			lua_pushstring(L, "port");
			lua_pushinteger(L, rspamd_url_get_port_if_special(u));
			lua_settable(L, -3);
		}

		if (u->tldlen > 0) {
			lua_pushstring(L, "tld");
			lua_pushlstring(L, rspamd_url_tld_unsafe(u), u->tldlen);
			lua_settable(L, -3);
		}

		if (u->userlen > 0) {
			lua_pushstring(L, "user");
			lua_pushlstring(L, rspamd_url_user(u), u->userlen);
			lua_settable(L, -3);
		}

		if (u->datalen > 0) {
			lua_pushstring(L, "path");
			lua_pushlstring(L, rspamd_url_data_unsafe(u), u->datalen);
			lua_settable(L, -3);
		}

		if (u->querylen > 0) {
			lua_pushstring(L, "query");
			lua_pushlstring(L, rspamd_url_query_unsafe(u), u->querylen);
			lua_settable(L, -3);
		}

		if (u->fragmentlen > 0) {
			lua_pushstring(L, "fragment");
			lua_pushlstring(L, rspamd_url_fragment_unsafe(u), u->fragmentlen);
			lua_settable(L, -3);
		}


		lua_pushstring(L, "protocol");
		lua_pushstring(L, rspamd_url_protocol_name(u->protocol));
		lua_settable(L, -3);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

static rspamd_mempool_t *static_lua_url_pool;

RSPAMD_CONSTRUCTOR(rspamd_urls_static_pool_ctor)
{
	static_lua_url_pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
											 "static_lua_url", 0);
}

RSPAMD_DESTRUCTOR(rspamd_urls_static_pool_dtor)
{
	rspamd_mempool_delete(static_lua_url_pool);
}

/***
 * @function url.create([mempool,] str, [{flags_table}])
 * @param {rspamd_mempool} memory pool for URL, e.g. `task:get_mempool()`
 * @param {string} text that contains URL (can also contain other stuff)
 * @return {url} new url object that exists as long as the corresponding mempool exists
 */
static int
lua_url_create(lua_State *L)
{
	LUA_TRACE_POINT;
	rspamd_mempool_t *pool;
	struct rspamd_lua_text *t;
	struct rspamd_lua_url *u;

	if (lua_type(L, 1) == LUA_TUSERDATA) {
		pool = rspamd_lua_check_mempool(L, 1);
		t = lua_check_text_or_string(L, 2);
	}
	else {
		pool = static_lua_url_pool;
		t = lua_check_text_or_string(L, 1);
	}

	if (pool == NULL) {
		return luaL_error(L, "invalid arguments: mempool is expected as the second argument");
	}

	if (t == NULL) {
		return luaL_error(L, "invalid arguments: string/text is expected as the first argument");
	}

	rspamd_url_find_single(pool, t->start, t->len, RSPAMD_URL_FIND_ALL,
						   lua_url_single_inserter, L);

	if (lua_type(L, -1) != LUA_TUSERDATA) {
		/* URL is actually not found */
		lua_pushnil(L);

		return 1;
	}

	u = (struct rspamd_lua_url *) lua_touserdata(L, -1);

	if (lua_type(L, 3) == LUA_TTABLE) {
		/* Add flags */
		for (lua_pushnil(L); lua_next(L, 3); lua_pop(L, 1)) {
			int nmask = 0;
			const char *fname = lua_tostring(L, -1);

			if (rspamd_url_flag_from_string(fname, &nmask)) {
				u->url->flags |= nmask;
			}
			else {
				lua_pop(L, 1);
				return luaL_error(L, "invalid flag: %s", fname);
			}
		}
	}

	return 1;
}

/***
 * @function url.init(tld_file)
 * Initialize url library if not initialized yet by Rspamd
 * @param {string} tld_file path to effective_tld_names.dat file (public suffix list)
 * @return nothing
 */
static int
lua_url_init(lua_State *L)
{
	const char *tld_path;

	tld_path = luaL_checkstring(L, 1);

	rspamd_url_init(tld_path);

	return 0;
}

static gboolean
lua_url_table_inserter(struct rspamd_url *url, gsize start_offset,
					   gsize end_offset, gpointer ud)
{
	lua_State *L = ud;
	struct rspamd_lua_url *lua_url;
	int n;

	n = rspamd_lua_table_size(L, -1);
	lua_url = lua_newuserdata(L, sizeof(struct rspamd_lua_url));
	rspamd_lua_setclass(L, rspamd_url_classname, -1);
	lua_url->url = url;
	lua_rawseti(L, -2, n + 1);

	return TRUE;
}


static int
lua_url_all(lua_State *L)
{
	LUA_TRACE_POINT;
	rspamd_mempool_t *pool = rspamd_lua_check_mempool(L, 1);
	const char *text;
	size_t length;

	if (pool == NULL) {
		lua_pushnil(L);
	}
	else {
		text = luaL_checklstring(L, 2, &length);

		if (text != NULL) {
			lua_newtable(L);
			rspamd_url_find_multiple(pool, text, length,
									 RSPAMD_URL_FIND_ALL, NULL,
									 lua_url_table_inserter, L);
		}
		else {
			lua_pushnil(L);
		}
	}

	return 1;
}

/***
 * @method url:get_flags()
 * Return flags for a specified URL as map 'flag'->true for all flags set,
 * possible flags are:
 *
 * - `phished`: URL is likely phished
 * - `numeric`: URL is numeric (e.g. IP address)
 * - `obscured`: URL was obscured
 * - `redirected`: URL comes from redirector
 * - `html_displayed`: URL is used just for displaying purposes
 * - `text`: URL comes from the text
 * - `subject`: URL comes from the subject
 * - `host_encoded`: URL host part is encoded
 * - `schema_encoded`: URL schema part is encoded
 * - `query_encoded`: URL query part is encoded
 * - `missing_slashes`: URL has some slashes missing
 * - `idn`: URL has international characters
 * - `has_port`: URL has port
 * - `has_user`: URL has user part
 * - `schemaless`: URL has no schema
 * - `unnormalised`: URL has some unicode unnormalities
 * - `zw_spaces`: URL has some zero width spaces
 * - `url_displayed`: URL has some other url-like string in visible part
 * - `image`: URL is from src attribute of img HTML tag
 * @return {table} URL flags
 */
#define PUSH_FLAG(fl)                                         \
	do {                                                      \
		if (flags & (fl)) {                                   \
			lua_pushstring(L, rspamd_url_flag_to_string(fl)); \
			lua_pushboolean(L, true);                         \
			lua_settable(L, -3);                              \
		}                                                     \
	} while (0)

static int
lua_url_get_flags(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);
	enum rspamd_url_flags flags;

	if (url != NULL) {
		flags = url->url->flags;

		lua_createtable(L, 0, 4);

		for (int i = 0; i < RSPAMD_URL_MAX_FLAG_SHIFT; i++) {
			PUSH_FLAG(1u << i);
		}
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

#undef PUSH_FLAG

static int
lua_url_get_flags_num(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url) {
		lua_pushinteger(L, url->url->flags);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

static int
lua_url_get_order(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url) {
		if (url->url->order != (uint16_t) -1) {
			lua_pushinteger(L, url->url->order);
		}
		else {
			lua_pushnil(L);
		}
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

static int
lua_url_get_part_order(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *url = lua_check_url(L, 1);

	if (url) {
		if (url->url->part_order != (uint16_t) -1) {
			lua_pushinteger(L, url->url->part_order);
		}
		else {
			lua_pushnil(L);
		}
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

void lua_tree_url_callback(gpointer key, gpointer value, gpointer ud)
{
	struct rspamd_lua_url *lua_url;
	struct rspamd_url *url = (struct rspamd_url *) value;
	struct lua_tree_cb_data *cb = ud;

	if ((url->protocol & cb->protocols_mask) == url->protocol) {

		/* Handle different flags application logic */
		switch (cb->flags_mode) {
		case url_flags_mode_include_any:
			if (url->flags != (url->flags & cb->flags_mask)) {
				return;
			}
			break;
		case url_flags_mode_include_explicit:
			if ((url->flags & cb->flags_mask) != cb->flags_mask) {
				return;
			}
			break;
		case url_flags_mode_exclude_include:
			if ((url->flags & cb->flags_exclude_mask) != 0) {
				return;
			}
			if ((url->flags & cb->flags_mask) == 0) {
				return;
			}
			break;
		}

		if (cb->skip_prob > 0) {
			double coin = rspamd_random_double_fast_seed(&cb->random_seed);

			if (coin < cb->skip_prob) {
				return;
			}
		}

		lua_url = lua_newuserdata(cb->L, sizeof(struct rspamd_lua_url));
		lua_pushvalue(cb->L, cb->metatable_pos);
		lua_setmetatable(cb->L, -2);
		lua_url->url = url;
		lua_rawseti(cb->L, -2, cb->i++);
	}
}

gboolean
lua_url_cbdata_fill(lua_State *L,
					int pos,
					struct lua_tree_cb_data *cbd,
					unsigned int default_protocols,
					unsigned int default_flags,
					gsize max_urls)
{
	int protocols_mask = 0;

	int pos_arg_type = lua_type(L, pos);
	unsigned int flags_mask = default_flags;
	gboolean seen_flags = FALSE, seen_protocols = FALSE;

	memset(cbd, 0, sizeof(*cbd));
	cbd->flags_mode = url_flags_mode_include_any;

	if (pos_arg_type == LUA_TBOOLEAN) {
		protocols_mask = default_protocols;
		if (lua_toboolean(L, 2)) {
			protocols_mask |= PROTOCOL_MAILTO;
		}
	}
	else if (pos_arg_type == LUA_TTABLE) {
		if (rspamd_lua_geti(L, 1, pos) == LUA_TNIL) {
			/* New method: indexed table */

			lua_getfield(L, pos, "flags");
			if (lua_istable(L, -1)) {
				int top = lua_gettop(L);

				lua_getfield(L, pos, "flags_mode");
				if (lua_isstring(L, -1)) {
					const char *mode_str = lua_tostring(L, -1);

					if (strcmp(mode_str, "explicit") == 0) {
						cbd->flags_mode = url_flags_mode_include_explicit;
						/*
						 * Ignore default flags in this mode and include
						 * merely flags specified by a caller
						 */
						flags_mask = 0;
					}
				}
				lua_pop(L, 1);

				for (lua_pushnil(L); lua_next(L, top); lua_pop(L, 1)) {
					int nmask = 0;


					if (lua_type(L, -1) == LUA_TSTRING) {
						const char *fname = lua_tostring(L, -1);


						if (rspamd_url_flag_from_string(fname, &nmask)) {
							flags_mask |= nmask;
						}
						else {
							msg_info("bad url flag: %s", fname);
							return FALSE;
						}
					}
					else {
						flags_mask |= lua_tointeger(L, -1);
					}
				}

				seen_flags = TRUE;
			}
			else {
				flags_mask |= default_flags;
			}
			lua_pop(L, 1);

			lua_getfield(L, pos, "protocols");
			if (lua_istable(L, -1)) {
				int top = lua_gettop(L);

				for (lua_pushnil(L); lua_next(L, top); lua_pop(L, 1)) {
					int nmask;
					const char *pname = lua_tostring(L, -1);

					nmask = rspamd_url_protocol_from_string(pname);

					if (nmask != PROTOCOL_UNKNOWN) {
						protocols_mask |= nmask;
					}
					else {
						msg_info("bad url protocol: %s", pname);
						return FALSE;
					}
				}
				seen_protocols = TRUE;
			}
			else {
				protocols_mask = default_protocols;
			}
			lua_pop(L, 1);

			if (!seen_protocols) {
				lua_getfield(L, pos, "emails");
				if (lua_isboolean(L, -1)) {
					if (lua_toboolean(L, -1)) {
						protocols_mask |= PROTOCOL_MAILTO;
					}
				}
				lua_pop(L, 1);
			}

			if (!seen_flags) {
				lua_getfield(L, pos, "images");
				if (lua_isboolean(L, -1)) {
					if (lua_toboolean(L, -1)) {
						flags_mask |= RSPAMD_URL_FLAG_IMAGE;
					}
					else {
						flags_mask &= ~RSPAMD_URL_FLAG_IMAGE;
					}
				}
				else {
					flags_mask &= ~RSPAMD_URL_FLAG_IMAGE;
				}
				lua_pop(L, 1);
			}

			if (!seen_flags) {
				lua_getfield(L, pos, "content");
				if (lua_isboolean(L, -1)) {
					if (lua_toboolean(L, -1)) {
						flags_mask |= RSPAMD_URL_FLAG_CONTENT;
					}
					else {
						flags_mask &= ~RSPAMD_URL_FLAG_CONTENT;
					}
				}
				else {
					flags_mask &= ~RSPAMD_URL_FLAG_CONTENT;
				}
				lua_pop(L, 1);
			}

			lua_getfield(L, pos, "max_urls");
			if (lua_isnumber(L, -1)) {
				max_urls = lua_tonumber(L, -1);
			}
			lua_pop(L, 1);

			lua_getfield(L, pos, "sort");
			if (lua_isboolean(L, -1)) {
				cbd->sort = TRUE;
			}
			lua_pop(L, 1);
		}
		else {
			/* Plain table of the protocols */
			for (lua_pushnil(L); lua_next(L, pos); lua_pop(L, 1)) {
				int nmask;
				const char *pname = lua_tostring(L, -1);

				nmask = rspamd_url_protocol_from_string(pname);

				if (nmask != PROTOCOL_UNKNOWN) {
					protocols_mask |= nmask;
				}
				else {
					msg_info("bad url protocol: %s", pname);
					return FALSE;
				}
			}
		}

		lua_pop(L, 1); /* After rspamd_lua_geti */
	}
	else if (pos_arg_type == LUA_TSTRING) {
		const char *plist = lua_tostring(L, pos);
		char **strvec;
		char *const *cvec;

		strvec = g_strsplit_set(plist, ",;", -1);
		cvec = strvec;

		while (*cvec) {
			int nmask;

			nmask = rspamd_url_protocol_from_string(*cvec);

			if (nmask != PROTOCOL_UNKNOWN) {
				protocols_mask |= nmask;
			}
			else {
				msg_info("bad url protocol: %s", *cvec);
				g_strfreev(strvec);

				return FALSE;
			}

			cvec++;
		}

		g_strfreev(strvec);
	}
	else if (pos_arg_type == LUA_TNONE || pos_arg_type == LUA_TNIL) {
		protocols_mask = default_protocols;
		flags_mask = default_flags;
	}
	else {
		return FALSE;
	}

	if (lua_type(L, pos + 1) == LUA_TBOOLEAN) {
		if (lua_toboolean(L, pos + 1)) {
			flags_mask |= RSPAMD_URL_FLAG_IMAGE;
		}
		else {
			flags_mask &= ~RSPAMD_URL_FLAG_IMAGE;
		}
	}

	cbd->i = 1;
	cbd->L = L;
	cbd->max_urls = max_urls;
	cbd->protocols_mask = protocols_mask;
	cbd->flags_mask = flags_mask;

	/* This needs to be removed from the stack */
	rspamd_lua_class_metatable(L, rspamd_url_classname);
	cbd->metatable_pos = lua_gettop(L);
	(void) lua_checkstack(L, cbd->metatable_pos + 4);

	return TRUE;
}

gboolean
lua_url_cbdata_fill_exclude_include(lua_State *L,
									int pos,
									struct lua_tree_cb_data *cbd,
									unsigned int default_protocols,
									gsize max_urls)
{
	unsigned int protocols_mask = default_protocols;
	unsigned int include_flags_mask, exclude_flags_mask;

	int pos_arg_type = lua_type(L, pos);

	memset(cbd, 0, sizeof(*cbd));
	cbd->flags_mode = url_flags_mode_exclude_include;

	/* Include flags */
	if (pos_arg_type == LUA_TTABLE) {
		include_flags_mask = 0; /* Reset to no flags */

		for (lua_pushnil(L); lua_next(L, pos); lua_pop(L, 1)) {
			int nmask = 0;

			if (lua_type(L, -1) == LUA_TSTRING) {
				const char *fname = lua_tostring(L, -1);

				if (rspamd_url_flag_from_string(fname, &nmask)) {
					include_flags_mask |= nmask;
				}
				else {
					msg_info("bad url include flag: %s", fname);
					return FALSE;
				}
			}
			else {
				include_flags_mask |= lua_tointeger(L, -1);
			}
		}
	}
	else if (pos_arg_type == LUA_TNIL || pos_arg_type == LUA_TNONE) {
		/* Include all flags */
		include_flags_mask = ~0U;
	}
	else {
		msg_info("bad arguments: wrong include mask");
		return FALSE;
	}

	/* Exclude flags */
	pos_arg_type = lua_type(L, pos + 1);
	if (pos_arg_type == LUA_TTABLE) {
		exclude_flags_mask = 0; /* Reset to no flags */

		for (lua_pushnil(L); lua_next(L, pos + 1); lua_pop(L, 1)) {
			int nmask = 0;

			if (lua_type(L, -1) == LUA_TSTRING) {
				const char *fname = lua_tostring(L, -1);

				if (rspamd_url_flag_from_string(fname, &nmask)) {
					exclude_flags_mask |= nmask;
				}
				else {
					msg_info("bad url exclude flag: %s", fname);
					return FALSE;
				}
			}
			else {
				exclude_flags_mask |= lua_tointeger(L, -1);
			}
		}
	}
	else if (pos_arg_type == LUA_TNIL || pos_arg_type == LUA_TNONE) {
		/* Empty all exclude flags */
		exclude_flags_mask = 0U;
	}
	else {
		msg_info("bad arguments: wrong exclude mask");
		return FALSE;
	}

	if (lua_type(L, pos + 2) == LUA_TTABLE) {
		protocols_mask = 0U; /* Reset all protocols */

		for (lua_pushnil(L); lua_next(L, pos + 2); lua_pop(L, 1)) {
			int nmask;
			const char *pname = lua_tostring(L, -1);

			nmask = rspamd_url_protocol_from_string(pname);

			if (nmask != PROTOCOL_UNKNOWN) {
				protocols_mask |= nmask;
			}
			else {
				msg_info("bad url protocol: %s", pname);
				return FALSE;
			}
		}
	}
	else {
		protocols_mask = default_protocols;
	}

	cbd->i = 1;
	cbd->L = L;
	cbd->max_urls = max_urls;
	cbd->protocols_mask = protocols_mask;
	cbd->flags_mask = include_flags_mask;
	cbd->flags_exclude_mask = exclude_flags_mask;

	/* This needs to be removed from the stack */
	rspamd_lua_class_metatable(L, rspamd_url_classname);
	cbd->metatable_pos = lua_gettop(L);
	(void) lua_checkstack(L, cbd->metatable_pos + 4);

	return TRUE;
}


void lua_url_cbdata_dtor(struct lua_tree_cb_data *cbd)
{
	if (cbd->metatable_pos != -1) {
		lua_remove(cbd->L, cbd->metatable_pos);
	}
}

gsize lua_url_adjust_skip_prob(float timestamp,
							   unsigned char digest[16],
							   struct lua_tree_cb_data *cb,
							   gsize sz)
{
	if (cb->max_urls > 0 && sz > cb->max_urls) {
		cb->skip_prob = 1.0 - ((double) cb->max_urls) / (double) sz;
		/*
		 * Use task dependent probabilistic seed to ensure that
		 * consequent task:get_urls return the same list of urls
		 * We use both digest and timestamp here to avoid attack surface
		 * based just on digest.
		 */
		memcpy(&cb->random_seed, digest, 4);
		memcpy(((unsigned char *) &cb->random_seed) + 4, &timestamp, 4);
		sz = cb->max_urls;
	}

	return sz;
}

static int
lua_url_eq(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *u1 = lua_check_url(L, 1),
						  *u2 = lua_check_url(L, 2);

	if (u1 && u2) {
		lua_pushboolean(L, (rspamd_url_cmp(u1->url, u2->url) == 0));
	}
	else {
		lua_pushboolean(L, false);
	}

	return 1;
}

static int
lua_url_lt(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_url *u1 = lua_check_url(L, 1),
						  *u2 = lua_check_url(L, 2);

	if (u1 && u2) {
		lua_pushinteger(L, rspamd_url_cmp(u1->url, u2->url));
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

static int
lua_load_url(lua_State *L)
{
	lua_newtable(L);
	luaL_register(L, NULL, urllib_f);

	/* Push flags */
	lua_createtable(L, 0, RSPAMD_URL_MAX_FLAG_SHIFT);
	for (int i = 0; i < RSPAMD_URL_MAX_FLAG_SHIFT; i++) {
		unsigned int flag = 1u << i;

		lua_pushinteger(L, flag);
		lua_setfield(L, -2, rspamd_url_flag_to_string(flag));
	}

	lua_setfield(L, -2, "flags");

	return 1;
}

void luaopen_url(lua_State *L)
{
	rspamd_lua_new_class(L, rspamd_url_classname, urllib_m);
	lua_pop(L, 1);

	rspamd_lua_add_preload(L, "rspamd_url", lua_load_url);
}
