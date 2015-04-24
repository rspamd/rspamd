/* Copyright (c) 2015, Vsevolod Stakhov
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

/***
 * @module rspamd_url
 * This module provides routines to handle URL's and extract URL's from the text.
 * Objects of this class are returned, for example, by `task:get_urls()` or `task:get_emails()`.
 * You can also create `rspamd_url` from any text.
 * @example
local url = require "rspamd_url"
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
LUA_FUNCTION_DEF (url, get_length);
LUA_FUNCTION_DEF (url, get_host);
LUA_FUNCTION_DEF (url, get_user);
LUA_FUNCTION_DEF (url, get_path);
LUA_FUNCTION_DEF (url, get_text);
LUA_FUNCTION_DEF (url, get_tld);
LUA_FUNCTION_DEF (url, to_table);
LUA_FUNCTION_DEF (url, is_phished);
LUA_FUNCTION_DEF (url, get_phished);
LUA_FUNCTION_DEF (url, create);
LUA_FUNCTION_DEF (url, all);

static const struct luaL_reg urllib_m[] = {
	LUA_INTERFACE_DEF (url, get_length),
	LUA_INTERFACE_DEF (url, get_host),
	LUA_INTERFACE_DEF (url, get_user),
	LUA_INTERFACE_DEF (url, get_path),
	LUA_INTERFACE_DEF (url, get_text),
	LUA_INTERFACE_DEF (url, get_tld),
	LUA_INTERFACE_DEF (url, to_table),
	LUA_INTERFACE_DEF (url, is_phished),
	LUA_INTERFACE_DEF (url, get_phished),
	{"__tostring", lua_url_get_text},
	{NULL, NULL}
};

static const struct luaL_reg urllib_f[] = {
	LUA_INTERFACE_DEF (url, create),
	LUA_INTERFACE_DEF (url, all),
	{NULL, NULL}
};

static struct rspamd_lua_url *
lua_check_url (lua_State * L, gint pos)
{
	void *ud = luaL_checkudata (L, pos, "rspamd{url}");
	luaL_argcheck (L, ud != NULL, pos, "'url' expected");
	return ud ? ((struct rspamd_lua_url *)ud) : NULL;
}


/***
 * @method url:get_length()
 * Get length of the url
 * @return {number} length of url in bytes
 */
static gint
lua_url_get_length (lua_State *L)
{
	struct rspamd_lua_url *url = lua_check_url (L, 1);

	if (url != NULL) {
		lua_pushinteger (L, url->url->urllen);
	}
	else {
		lua_pushnil (L);
	}
	return 1;
}

/***
 * @method url:get_host()
 * Get domain part of the url
 * @return {string} domain part of URL
 */
static gint
lua_url_get_host (lua_State *L)
{
	struct rspamd_lua_url *url = lua_check_url (L, 1);

	if (url != NULL) {
		lua_pushlstring (L, url->url->host, url->url->hostlen);
	}
	else {
		lua_pushnil (L);
	}
	return 1;
}

/***
 * @method url:get_user()
 * Get user part of the url (e.g. username in email)
 * @return {string} user part of URL
 */
static gint
lua_url_get_user (lua_State *L)
{
	struct rspamd_lua_url *url = lua_check_url (L, 1);

	if (url != NULL && url->url->user != NULL) {
		lua_pushlstring (L, url->url->user, url->url->userlen);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/***
 * @method url:get_path()
 * Get path of the url
 * @return {string} path part of URL
 */
static gint
lua_url_get_path (lua_State *L)
{
	struct rspamd_lua_url *url = lua_check_url (L, 1);

	if (url != NULL && url->url->datalen > 0) {
		lua_pushlstring (L, url->url->data, url->url->datalen);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/***
 * @method url:get_text()
 * Get full content of the url
 * @return {string} url string
 */
static gint
lua_url_get_text (lua_State *L)
{
	struct rspamd_lua_url *url = lua_check_url (L, 1);

	if (url != NULL) {
		lua_pushlstring (L, url->url->string, url->url->urllen);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/***
 * @method url:is_phished()
 * Check whether URL is treated as phished
 * @return {boolean} `true` if URL is phished
 */
static gint
lua_url_is_phished (lua_State *L)
{
	struct rspamd_lua_url *url = lua_check_url (L, 1);

	if (url != NULL) {
		lua_pushboolean (L, url->url->is_phished);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/***
 * @method url:get_phished()
 * Get another URL that pretends to be this URL (e.g. used in phishing)
 * @return {url} phished URL
 */
static gint
lua_url_get_phished (lua_State *L)
{
	struct rspamd_lua_url *purl, *url = lua_check_url (L, 1);

	if (url) {
		if (url->url->is_phished && url->url->phished_url != NULL) {
			purl = lua_newuserdata (L, sizeof (struct rspamd_lua_url));
			rspamd_lua_setclass (L, "rspamd{url}", -1);
			purl->url = url->url->phished_url;

			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

/***
 * @method url:get_tld()
 * Get top level domain part of the url host
 * @return {string} top level part of the url host
 */
static gint
lua_url_get_tld (lua_State *L)
{
	struct rspamd_lua_url *url = lua_check_url (L, 1);

	if (url != NULL && url->url->tldlen > 0) {
		lua_pushlstring (L, url->url->tld, url->url->tldlen);
	}
	else {
		lua_pushnil (L);
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
static gint
lua_url_to_table (lua_State *L)
{
	struct rspamd_lua_url *url = lua_check_url (L, 1);
	struct rspamd_url *u;

	if (url != NULL) {
		u = url->url;
		lua_newtable (L);
		lua_pushstring (L, "url");
		lua_pushlstring (L, u->string, u->urllen);
		lua_settable (L, -3);

		if (u->hostlen > 0) {
			lua_pushstring (L, "host");
			lua_pushlstring (L, u->host, u->hostlen);
			lua_settable (L, -3);
		}

		if (u->tldlen > 0) {
			lua_pushstring (L, "tld");
			lua_pushlstring (L, u->tld, u->tldlen);
			lua_settable (L, -3);
		}

		if (u->userlen > 0) {
			lua_pushstring (L, "user");
			lua_pushlstring (L, u->user, u->userlen);
			lua_settable (L, -3);
		}

		if (u->hostlen > 0) {
			lua_pushstring (L, "path");
			lua_pushlstring (L, u->data, u->datalen);
			lua_settable (L, -3);
		}

		lua_pushstring (L, "protocol");

		switch (u->protocol) {
		case PROTOCOL_FILE:
			lua_pushstring (L, "file");
			break;
		case PROTOCOL_FTP:
			lua_pushstring (L, "ftp");
			break;
		case PROTOCOL_HTTP:
			lua_pushstring (L, "http");
			break;
		case PROTOCOL_HTTPS:
			lua_pushstring (L, "https");
			break;
		case PROTOCOL_MAILTO:
			lua_pushstring (L, "mailto");
			break;
		case PROTOCOL_UNKNOWN:
		default:
			lua_pushstring (L, "unknown");
			break;
		}
		lua_settable (L, -3);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/***
 * @function url.create(mempool, str)
 * @param {rspamd_mempool} memory pool for URL, e.g. `task:get_mempool()`
 * @param {string} text that contains URL (can also contain other stuff)
 * @return {url} new url object that exists as long as the corresponding mempool exists
 */
static gint
lua_url_create (lua_State *L)
{
	struct rspamd_url *url;
	struct rspamd_lua_url *lua_url;
	rspamd_mempool_t *pool = rspamd_lua_check_mempool (L, 1);
	const gchar *text;

	if (pool == NULL) {
		lua_pushnil (L);
	}
	else {
		text = luaL_checkstring (L, 2);

		if (text != NULL) {
			url = rspamd_url_get_next (pool, text, NULL, NULL);

			if (url == NULL) {
				lua_pushnil (L);
			}
			else {
				lua_url = lua_newuserdata (L, sizeof (struct rspamd_lua_url));
				rspamd_lua_setclass (L, "rspamd{url}", -1);
				lua_url->url = url;
			}
		}
		else {
			lua_pushnil (L);
		}
	}


	return 1;
}

static gint
lua_url_all (lua_State *L)
{
	struct rspamd_url *url;
	struct rspamd_lua_url *lua_url;
	rspamd_mempool_t *pool = rspamd_lua_check_mempool (L, 1);
	const gchar *text,*end;
	gint i = 1;
	size_t length;
	const gchar **pos;

	if (pool == NULL) {
		lua_pushnil (L);
	}
	else {
		text = luaL_checklstring (L, 2, &length);

		if (text != NULL) {
			*pos = text;
			end = text + length;
			lua_newtable (L);
			
			while (*pos <= end) {
				url = rspamd_url_get_next (pool, text, pos, NULL);				

				if (url != NULL) {
					lua_url = lua_newuserdata (L, sizeof (struct rspamd_lua_url));
					rspamd_lua_setclass (L, "rspamd{url}", -1);
					lua_url->url = url;
					lua_pushinteger (L, i++);
					lua_pushlstring (L, url->string, url->urllen);
					lua_settable (L, -3);
				}
				else
					break;
			}

		}
		else {
			lua_pushnil (L);
		}
	}


	return 1;

}


static gint
lua_load_url (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, urllib_f);

	return 1;
}

void
luaopen_url (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{url}", urllib_m);
	lua_pop (L, 1);

	rspamd_lua_add_preload (L, "rspamd_url", lua_load_url);
}
