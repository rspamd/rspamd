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
#include "lua_thread_pool.h"
#include "http_private.h"
#include "unix-std.h"
#include "zlib.h"

/***
 * @module rspamd_http
 * Rspamd HTTP module represents HTTP asynchronous client available from LUA code.
 * This module hides all complexity: DNS resolving, sessions management, zero-copy
 * text transfers and so on under the hood.
 * @example
local rspamd_http = require "rspamd_http"

local function symbol_callback(task)
	local function http_callback(err_message, code, body, headers)
		task:insert_result('SYMBOL', 1) -- task is available via closure
	end

 	rspamd_http.request({
 		task=task,
 		url='http://example.com/data',
 		body=task:get_content(),
 		callback=http_callback,
 		headers={Header='Value', OtherHeader='Value'},
 		mime_type='text/plain',
 		})
 end
 */

#define MAX_HEADERS_SIZE 8192

static const gchar *M = "rspamd lua http";

LUA_FUNCTION_DEF (http, request);

static const struct luaL_reg httplib_m[] = {
	LUA_INTERFACE_DEF (http, request),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

#define RSPAMD_LUA_HTTP_FLAG_TEXT (1 << 0)
#define RSPAMD_LUA_HTTP_FLAG_NOVERIFY (1 << 1)
#define RSPAMD_LUA_HTTP_FLAG_RESOLVED (1 << 2)

struct lua_http_cbdata {
	struct rspamd_http_connection *conn;
	struct rspamd_async_session *session;
	struct rspamd_symcache_item *item;
	struct rspamd_http_message *msg;
	struct event_base *ev_base;
	struct rspamd_config *cfg;
	struct rspamd_task *task;
	struct timeval tv;
	struct rspamd_cryptobox_keypair *local_kp;
	struct rspamd_cryptobox_pubkey *peer_pk;
	rspamd_inet_addr_t *addr;
	gchar *mime_type;
	gchar *host;
	gchar *auth;
	const gchar *url;
	gsize max_size;
	gint flags;
	gint fd;
	gint cbref;
	struct thread_entry *thread;
};

static const int default_http_timeout = 5000;

static struct rspamd_dns_resolver *
lua_http_global_resolver (struct event_base *ev_base)
{
	static struct rspamd_dns_resolver *global_resolver;

	if (global_resolver == NULL) {
		global_resolver = dns_resolver_init (NULL, ev_base, NULL);
	}

	return global_resolver;
}

static void
lua_http_fin (gpointer arg)
{
	struct lua_http_cbdata *cbd = (struct lua_http_cbdata *)arg;

	if (cbd->cbref != -1) {
		luaL_unref (cbd->cfg->lua_state, LUA_REGISTRYINDEX, cbd->cbref);
	}

	if (cbd->conn) {
		/* Here we already have a connection, so we need to unref it */
		rspamd_http_connection_unref (cbd->conn);
	}
	else if (cbd->msg != NULL) {
		/* We need to free message */
		rspamd_http_message_unref (cbd->msg);
	}

	if (cbd->fd != -1) {
		close (cbd->fd);
	}

	if (cbd->addr) {
		rspamd_inet_address_free (cbd->addr);
	}

	if (cbd->mime_type) {
		g_free (cbd->mime_type);
	}

	if (cbd->host) {
		g_free (cbd->host);
	}

	if (cbd->auth) {
		g_free (cbd->auth);
	}

	if (cbd->local_kp) {
		rspamd_keypair_unref (cbd->local_kp);
	}

	if (cbd->peer_pk) {
		rspamd_pubkey_unref (cbd->peer_pk);
	}

	g_free (cbd);
}

static void
lua_http_maybe_free (struct lua_http_cbdata *cbd)
{
	if (cbd->session) {

		if (cbd->flags & RSPAMD_LUA_HTTP_FLAG_RESOLVED) {
			/* Event is added merely for resolved events */
			if (cbd->item) {
				rspamd_symcache_item_async_dec_check (cbd->task, cbd->item, M);
			}

			rspamd_session_remove_event (cbd->session, lua_http_fin, cbd);
		}
	}
	else {
		lua_http_fin (cbd);
	}
}

static void
lua_http_push_error (struct lua_http_cbdata *cbd, const char *err)
{
	struct lua_callback_state lcbd;
	lua_State *L;

	lua_thread_pool_prepare_callback (cbd->cfg->lua_thread_pool, &lcbd);

	L = lcbd.L;

	lua_rawgeti (L, LUA_REGISTRYINDEX, cbd->cbref);
	lua_pushstring (L, err);


	if (cbd->item) {
		rspamd_symcache_set_cur_item (cbd->task, cbd->item);
	}

	if (lua_pcall (L, 1, 0, 0) != 0) {
		msg_info ("callback call failed: %s", lua_tostring (L, -1));
		lua_pop (L, 1);
	}

	lua_thread_pool_restore_callback (&lcbd);
}

static void lua_http_resume_handler (struct rspamd_http_connection *conn,
						 struct rspamd_http_message *msg, const char *err);

static void
lua_http_error_handler (struct rspamd_http_connection *conn, GError *err)
{
	struct lua_http_cbdata *cbd = (struct lua_http_cbdata *)conn->ud;
	if (cbd->cbref == -1) {
		lua_http_resume_handler (conn, NULL, err->message);
	}
	else {
		lua_http_push_error (cbd, err->message);
	}
	lua_http_maybe_free (cbd);
}

static int
lua_http_finish_handler (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg)
{
	struct lua_http_cbdata *cbd = (struct lua_http_cbdata *)conn->ud;
	struct rspamd_http_header *h, *htmp;
	const gchar *body;
	gsize body_len;

	struct lua_callback_state lcbd;
	lua_State *L;

	if (cbd->cbref == -1) {
		lua_http_resume_handler (conn, msg, NULL);
		lua_http_maybe_free (cbd);
		return 0;
	}
	lua_thread_pool_prepare_callback (cbd->cfg->lua_thread_pool, &lcbd);

	L = lcbd.L;

	lua_rawgeti (L, LUA_REGISTRYINDEX, cbd->cbref);
	/* Error */
	lua_pushnil (L);
	/* Reply code */
	lua_pushinteger (L, msg->code);
	/* Body */
	body = rspamd_http_message_get_body (msg, &body_len);

	if (cbd->flags & RSPAMD_LUA_HTTP_FLAG_TEXT) {
		struct rspamd_lua_text *t;

		t = lua_newuserdata (L, sizeof (*t));
		rspamd_lua_setclass (L, "rspamd{text}", -1);
		t->start = body;
		t->len = body_len;
		t->flags = 0;
	}
	else {
		if (body_len > 0) {
			lua_pushlstring (L, body, body_len);
		}
		else {
			lua_pushnil (L);
		}
	}
	/* Headers */
	lua_newtable (L);

	HASH_ITER (hh, msg->headers, h, htmp) {
		/*
		 * Lowercase header name, as Lua cannot search in caseless matter
		 */
		rspamd_str_lc (h->combined->str, h->name.len);
		lua_pushlstring (L, h->name.begin, h->name.len);
		lua_pushlstring (L, h->value.begin, h->value.len);
		lua_settable (L, -3);
	}

	if (cbd->item) {
		/* Replace watcher to deal with nested calls */
		rspamd_symcache_set_cur_item (cbd->task, cbd->item);
	}

	if (lua_pcall (L, 4, 0, 0) != 0) {
		msg_info ("callback call failed: %s", lua_tostring (L, -1));
		lua_pop (L, 1);
	}

	lua_http_maybe_free (cbd);

	lua_thread_pool_restore_callback (&lcbd);

	return 0;
}

/*
 * resumes yielded thread
 */
static void
lua_http_resume_handler (struct rspamd_http_connection *conn,
						 struct rspamd_http_message *msg, const char *err)
{
	struct lua_http_cbdata *cbd = (struct lua_http_cbdata *)conn->ud;
	lua_State *L = cbd->thread->lua_state;
	const gchar *body;
	gsize body_len;
	struct rspamd_http_header *h, *htmp;

	if (err) {
		lua_pushstring (L, err);
		lua_pushnil (L);
	}
	else {
		/*
		 * 1 - nil (error)
		 * 2 - table:
		 *   code (int)
		 *   content (string)
		 *   headers (table: header -> value)
		 */
		lua_pushnil (L); // error code

		lua_createtable (L, 0, 3);

		/* code */
		lua_pushliteral (L, "code");
		lua_pushinteger (L, msg->code);
		lua_settable (L, -3);

		/* content */
		lua_pushliteral (L, "content");

		body = rspamd_http_message_get_body (msg, &body_len);
		if (cbd->flags & RSPAMD_LUA_HTTP_FLAG_TEXT) {
			struct rspamd_lua_text *t;

			t = lua_newuserdata (L, sizeof (*t));
			rspamd_lua_setclass (L, "rspamd{text}", -1);
			t->start = body;
			t->len = body_len;
			t->flags = 0;
		}
		else {
			if (body_len > 0) {
				lua_pushlstring (L, body, body_len);
			}
			else {
				lua_pushnil (L);
			}
		}
		lua_settable (L, -3);

		/* headers */
		lua_pushliteral (L, "headers");
		lua_newtable (L);

		HASH_ITER (hh, msg->headers, h, htmp) {
			/*
			 * Lowercase header name, as Lua cannot search in caseless matter
			 */
			rspamd_str_lc (h->combined->str, h->name.len);
			lua_pushlstring (L, h->name.begin, h->name.len);
			lua_pushlstring (L, h->value.begin, h->value.len);
			lua_settable (L, -3);
		}

		lua_settable (L, -3);
	}

	if (cbd->item) {
		/* Replace watcher to deal with nested calls */
		rspamd_symcache_set_cur_item (cbd->task, cbd->item);
	}

	lua_thread_resume (cbd->thread, 2);
}

static gboolean
lua_http_make_connection (struct lua_http_cbdata *cbd)
{
	int fd;

	rspamd_inet_address_set_port (cbd->addr, cbd->msg->port);
	fd = rspamd_inet_address_connect (cbd->addr, SOCK_STREAM, TRUE);

	if (fd == -1) {
		msg_info ("cannot connect to %V", cbd->msg->host);
		return FALSE;
	}
	cbd->fd = fd;

	if (cbd->cfg) {
		cbd->conn = rspamd_http_connection_new (NULL,
				lua_http_error_handler,
				lua_http_finish_handler,
				RSPAMD_HTTP_CLIENT_SIMPLE,
				RSPAMD_HTTP_CLIENT,
				NULL,
				(cbd->flags & RSPAMD_LUA_HTTP_FLAG_NOVERIFY) ?
				cbd->cfg->libs_ctx->ssl_ctx_noverify : cbd->cfg->libs_ctx->ssl_ctx);
	}
	else {
		cbd->conn = rspamd_http_connection_new (NULL,
				lua_http_error_handler,
				lua_http_finish_handler,
				RSPAMD_HTTP_CLIENT_SIMPLE,
				RSPAMD_HTTP_CLIENT,
				NULL,
				NULL);
	}

	if (cbd->conn) {
		if (cbd->local_kp) {
			rspamd_http_connection_set_key (cbd->conn, cbd->local_kp);
		}

		if (cbd->peer_pk) {
			rspamd_http_message_set_peer_key (cbd->msg, cbd->peer_pk);
		}

		if (cbd->flags & RSPAMD_LUA_HTTP_FLAG_NOVERIFY) {
			cbd->msg->flags |= RSPAMD_HTTP_FLAG_SSL_NOVERIFY;
		}

		if (cbd->max_size) {
			rspamd_http_connection_set_max_size (cbd->conn, cbd->max_size);
		}

		if (cbd->auth) {
			rspamd_http_message_add_header (cbd->msg, "Authorization",
					cbd->auth);
		}

		if (cbd->session) {
			rspamd_session_add_event (cbd->session,
					(event_finalizer_t) lua_http_fin, cbd,
					M);
			cbd->flags |= RSPAMD_LUA_HTTP_FLAG_RESOLVED;
		}

		if (cbd->item) {
			rspamd_symcache_item_async_inc (cbd->task, cbd->item, M);
		}

		struct rspamd_http_message *msg = cbd->msg;

		/* Message is now owned by a connection object */
		cbd->msg = NULL;

		rspamd_http_connection_write_message (cbd->conn, msg,
				cbd->host, cbd->mime_type, cbd, fd,
				&cbd->tv, cbd->ev_base);

		return TRUE;
	}

	return FALSE;
}

static void
lua_http_dns_handler (struct rdns_reply *reply, gpointer ud)
{
	struct lua_http_cbdata *cbd = (struct lua_http_cbdata *)ud;

	if (reply->code != RDNS_RC_NOERROR) {
		lua_http_push_error (cbd, "unable to resolve host");
		lua_http_maybe_free (cbd);
	}
	else {
		if (reply->entries->type == RDNS_REQUEST_A) {
			cbd->addr = rspamd_inet_address_new (AF_INET,
					&reply->entries->content.a.addr);
		}
		else if (reply->entries->type == RDNS_REQUEST_AAAA) {
			cbd->addr = rspamd_inet_address_new (AF_INET6,
					&reply->entries->content.aaa.addr);
		}

		if (!lua_http_make_connection (cbd)) {
			lua_http_push_error (cbd, "unable to make connection to the host");
			lua_http_maybe_free (cbd);

			return;
		}
	}

	if (cbd->item) {
		rspamd_symcache_item_async_dec_check (cbd->task, cbd->item, M);
	}
}

static void
lua_http_push_headers (lua_State *L, struct rspamd_http_message *msg)
{
	const char *name, *value;
	gint i, sz;

	lua_pushnil (L);
	while (lua_next (L, -2) != 0) {

		lua_pushvalue (L, -2);
		name = lua_tostring (L, -1);
		sz = rspamd_lua_table_size (L, -2);
		if (sz != 0 && name != NULL) {
			for (i = 1; i <= sz ; i++) {
				lua_rawgeti (L, -2, i);
				value = lua_tostring (L, -1);
				if (value != NULL) {
					rspamd_http_message_add_header (msg, name, value);
				}
				lua_pop (L, 1);
			}
		} else {
			value = lua_tostring (L, -2);
			if (name != NULL && value != NULL) {
				rspamd_http_message_add_header (msg, name, value);
			}
		}
		lua_pop (L, 2);
	}
}

/***
 * @function rspamd_http.request({params...})
 * This function creates HTTP request and accepts several parameters as a table using key=value syntax.
 * Required params are:
 *
 * - `url`
 * - `task`
 *
 * In taskless mode, instead of `task` required are:
 *
 * - `ev_base`
 * - `config`
 *
 * @param {string} url specifies URL for a request in the standard URI form (e.g. 'http://example.com/path')
 * @param {function} callback specifies callback function in format  `function (err_message, code, body, headers)` that is called on HTTP request completion. if this parameter is missing, the function performs "pseudo-synchronous" call (see [Synchronous and Asynchronous API overview](/doc/lua/sync_async.html#API-example-http-module)
 * @param {task} task if called from symbol handler it is generally a good idea to use the common task objects: event base, DNS resolver and events session
 * @param {table} headers optional headers in form `[name='value', name='value']`
 * @param {string} mime_type MIME type of the HTTP content (for example, `text/html`)
 * @param {string/text} body full body content, can be opaque `rspamd{text}` to avoid data copying
 * @param {number} timeout floating point request timeout value in seconds (default is 5.0 seconds)
 * @param {resolver} resolver to perform DNS-requests. Usually got from either `task` or `config`
 * @param {boolean} gzip if true, body of the requests will be compressed
 * @param {boolean} no_ssl_verify disable SSL peer checks
 * @param {string} user for HTTP authentication
 * @param {string} password for HTTP authentication, only if "user" present
 * @return {boolean} `true`, in **async** mode, if a request has been successfully scheduled. If this value is `false` then some error occurred, the callback thus will not be called.
 * @return In **sync** mode `string|nil, nil|table` In sync mode  error message if any and response as table: `int` _code_, `string` _content_ and `table` _headers_ (header -> value)
 */
static gint
lua_http_request (lua_State *L)
{
	LUA_TRACE_POINT;
	struct event_base *ev_base;
	struct rspamd_http_message *msg;
	struct lua_http_cbdata *cbd;
	struct rspamd_dns_resolver *resolver;
	struct rspamd_async_session *session = NULL;
	struct rspamd_lua_text *t;
	struct rspamd_task *task = NULL;
	struct rspamd_config *cfg = NULL;
	struct rspamd_cryptobox_pubkey *peer_key = NULL;
	struct rspamd_cryptobox_keypair *local_kp = NULL;
	const gchar *url, *lua_body;
	rspamd_fstring_t *body = NULL;
	gchar *to_resolve;
	gint cbref = -1;
	gsize bodylen;
	gdouble timeout = default_http_timeout;
	gint flags = 0;
	gchar *mime_type = NULL;
	gchar *auth = NULL;
	gsize max_size = 0;
	gboolean gzip = FALSE;

	if (lua_gettop (L) >= 2) {
		/* url, callback and event_base format */
		url = luaL_checkstring (L, 1);

		if (url == NULL || lua_type (L, 2) != LUA_TFUNCTION) {
			msg_err ("http request has bad params");
			lua_pushboolean (L, FALSE);
			return 1;
		}

		lua_pushvalue (L, 2);
		cbref = luaL_ref (L, LUA_REGISTRYINDEX);

		if (lua_gettop (L) >= 3 && rspamd_lua_check_udata_maybe (L, 3, "rspamd{ev_base}")) {
			ev_base = *(struct event_base **)lua_touserdata (L, 3);
		}
		else {
			ev_base = NULL;
		}

		if (lua_gettop (L) >= 4 && rspamd_lua_check_udata_maybe (L, 4, "rspamd{resolver}")) {
			resolver = *(struct rspamd_dns_resolver **)lua_touserdata (L, 4);
		}
		else {
			resolver = lua_http_global_resolver (ev_base);
		}

		if (lua_gettop (L) >= 5 && rspamd_lua_check_udata_maybe (L, 5, "rspamd{session}")) {
			session = *(struct rspamd_async_session **)lua_touserdata (L, 5);
		}
		else {
			session = NULL;
		}

		msg = rspamd_http_message_from_url (url);

		if (msg == NULL) {
			lua_pushboolean (L, FALSE);
			return 1;
		}
	}
	else if (lua_type (L, 1) == LUA_TTABLE) {
		lua_pushstring (L, "url");
		lua_gettable (L, 1);
		url = luaL_checkstring (L, -1);
		lua_pop (L, 1);

		lua_pushstring (L, "callback");
		lua_gettable (L, 1);
		if (url == NULL || lua_type (L, -1) != LUA_TFUNCTION) {
			lua_pop (L, 1);
		} else {
			cbref = luaL_ref (L, LUA_REGISTRYINDEX);
		}

		lua_pushstring (L, "task");
		lua_gettable (L, 1);

		if (lua_type (L, -1) == LUA_TUSERDATA) {
			task = lua_check_task (L, -1);
			ev_base = task->ev_base;
			resolver = task->resolver;
			session = task->s;
			cfg = task->cfg;
		}
		lua_pop (L, 1);

		if (task == NULL) {
			lua_pushstring (L, "ev_base");
			lua_gettable (L, 1);
			if (rspamd_lua_check_udata_maybe (L, -1, "rspamd{ev_base}")) {
				ev_base = *(struct event_base **)lua_touserdata (L, -1);
			}
			else {
				ev_base = NULL;
			}
			lua_pop (L, 1);


			lua_pushstring (L, "session");
			lua_gettable (L, 1);
			if (rspamd_lua_check_udata_maybe (L, -1, "rspamd{session}")) {
				session = *(struct rspamd_async_session **)lua_touserdata (L, -1);
			}
			else {
				session = NULL;
			}
			lua_pop (L, 1);

			lua_pushstring (L, "config");
			lua_gettable (L, 1);
			if (rspamd_lua_check_udata_maybe (L, -1, "rspamd{config}")) {
				cfg = *(struct rspamd_config **)lua_touserdata (L, -1);
			}
			else {
				cfg = NULL;
			}

			lua_pop (L, 1);

			lua_pushstring (L, "resolver");
			lua_gettable (L, 1);

			if (rspamd_lua_check_udata_maybe (L, -1, "rspamd{resolver}")) {
				resolver = *(struct rspamd_dns_resolver **)lua_touserdata (L, -1);
			}
			else {
				if (cfg && cfg->dns_resolver) {
					resolver = cfg->dns_resolver;
				}
				else {
					resolver = lua_http_global_resolver (ev_base);
				}
			}
			lua_pop (L, 1);
		}

		msg = rspamd_http_message_from_url (url);
		if (msg == NULL) {
			msg_err ("cannot create HTTP message from url %s", url);
			lua_pushboolean (L, FALSE);
			return 1;
		}

		lua_pushstring (L, "headers");
		lua_gettable (L, 1);
		if (lua_type (L, -1) == LUA_TTABLE) {
			lua_http_push_headers (L, msg);
		}
		lua_pop (L, 1);

		lua_pushstring (L, "timeout");
		lua_gettable (L, 1);
		if (lua_type (L, -1) == LUA_TNUMBER) {
			timeout = lua_tonumber (L, -1) * 1000.;
		}
		lua_pop (L, 1);

		lua_pushstring (L, "mime_type");
		lua_gettable (L, 1);
		if (lua_type (L, -1) == LUA_TSTRING) {
			mime_type = g_strdup (lua_tostring (L, -1));
		}
		lua_pop (L, 1);

		lua_pushstring (L, "body");
		lua_gettable (L, 1);
		if (lua_type (L, -1) == LUA_TSTRING) {
			lua_body = lua_tolstring (L, -1, &bodylen);
			body = rspamd_fstring_new_init (lua_body, bodylen);
		}
		else if (lua_type (L, -1) == LUA_TUSERDATA) {
			t = lua_check_text (L, -1);
			/* TODO: think about zero-copy possibilities */
			if (t) {
				body = rspamd_fstring_new_init (t->start, t->len);
			}
			else {
				return luaL_error (L, "invalid body argument type: %s",
						lua_typename (L, lua_type (L, -1)));
			}
		}
		else if (lua_type (L, -1) == LUA_TTABLE) {
			body = rspamd_fstring_new ();

			for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
				if (lua_type (L, -1) == LUA_TSTRING) {
					lua_body = lua_tolstring (L, -1, &bodylen);
					body = rspamd_fstring_append (body, lua_body, bodylen);
				}
				else if (lua_type (L, -1) == LUA_TUSERDATA) {
					t = lua_check_text (L, -1);

					if (t) {
						body = rspamd_fstring_append (body, t->start, t->len);
					}
					else {
						return luaL_error (L, "invalid body argument: %s",
								lua_typename (L, lua_type (L, -1)));
					}
				}
				else {
					return luaL_error (L, "invalid body argument type: %s",
							lua_typename (L, lua_type (L, -1)));
				}
			}
		}
		else if (lua_type (L, -1) != LUA_TNONE && lua_type (L, -1) != LUA_TNIL) {
			return luaL_error (L, "invalid body argument type: %s",
					lua_typename (L, lua_type (L, -1)));
		}
		lua_pop (L, 1);

		lua_pushstring (L, "peer_key");
		lua_gettable (L, 1);

		if (lua_type (L, -1) == LUA_TSTRING) {
			const gchar *in;
			gsize inlen;

			in = lua_tolstring (L, -1, &inlen);
			peer_key = rspamd_pubkey_from_base32 (in, inlen,
					RSPAMD_KEYPAIR_KEX, RSPAMD_CRYPTOBOX_MODE_25519);
		}

		lua_pop (L, 1);

		lua_pushstring (L, "keypair");
		lua_gettable (L, 1);

		if (lua_type (L, -1) == LUA_TTABLE) {
			ucl_object_t *kp_ucl = ucl_object_lua_import (L, -1);

			local_kp = rspamd_keypair_from_ucl (kp_ucl);
			ucl_object_unref (kp_ucl);
		}

		lua_pop (L, 1);

		lua_pushstring (L, "opaque_body");
		lua_gettable (L, 1);

		if (!!lua_toboolean (L, -1)) {
			flags |= RSPAMD_LUA_HTTP_FLAG_TEXT;
		}

		lua_pop (L, 1);

		lua_pushstring (L, "gzip");
		lua_gettable (L, 1);

		if (!!lua_toboolean (L, -1)) {
			gzip = TRUE;
		}

		lua_pop (L, 1);

		lua_pushstring (L, "no_ssl_verify");
		lua_gettable (L, 1);

		if (!!lua_toboolean (L, -1)) {
			flags |= RSPAMD_LUA_HTTP_FLAG_NOVERIFY;
		}

		lua_pop (L, 1);

		lua_pushstring (L, "max_size");
		lua_gettable (L, 1);

		if (lua_type (L, -1) == LUA_TNUMBER) {
			max_size = lua_tonumber (L, -1);
		}

		lua_pop (L, 1);

		lua_pushstring (L, "method");
		lua_gettable (L, 1);

		if (lua_type (L, -1) == LUA_TSTRING) {
			rspamd_http_message_set_method (msg, lua_tostring (L, -1));
		}

		lua_pop (L, 1);

		lua_pushstring (L, "user");
		lua_gettable (L, 1);

		if (lua_type (L, -1) == LUA_TSTRING) {
			const gchar *user = lua_tostring (L, -1);

			lua_pushstring (L, "password");
			lua_gettable (L, 1);

			if (lua_type (L, -1) == LUA_TSTRING) {
				const gchar *password = lua_tostring (L, -1);
				gchar *tmpbuf;
				gsize tlen;

				tlen = strlen (user) + strlen (password) + 1;
				tmpbuf = g_malloc (tlen + 1);
				rspamd_snprintf (tmpbuf, tlen + 1, "%s:%s", user, password);
				tlen *= 2;
				tlen += sizeof ("Basic ") - 1;
				auth = g_malloc (tlen + 1);
				rspamd_snprintf (auth, tlen + 1, "Basic %Bs", tmpbuf);
				g_free (tmpbuf);
			}
			else {
				msg_warn ("HTTP user must have password, disabling auth");
			}

			lua_pop (L, 1); /* password */
		}

		lua_pop (L, 1); /* username */
	}
	else {
		msg_err ("http request has bad params");
		lua_pushboolean (L, FALSE);

		return 1;
	}

	if (session && rspamd_session_blocked (session)) {
		lua_pushboolean (L, FALSE);

		return 1;
	}
	if (task == NULL && cfg == NULL) {
		return luaL_error (L,
				"Bad params to rspamd_http:request(): either task or config should be set");
	}

	if (ev_base == NULL) {
		return luaL_error (L,
				"Bad params to rspamd_http:request(): ev_base isn't passed");
	}

	cbd = g_malloc0 (sizeof (*cbd));
	cbd->cbref = cbref;
	cbd->msg = msg;
	cbd->ev_base = ev_base;
	cbd->mime_type = mime_type;
	msec_to_tv (timeout, &cbd->tv);
	cbd->fd = -1;
	cbd->cfg = cfg;
	cbd->peer_pk = peer_key;
	cbd->local_kp = local_kp;
	cbd->flags = flags;
	cbd->max_size = max_size;
	cbd->url = url;
	cbd->auth = auth;
	cbd->task = task;

	if (task) {
		cbd->item = rspamd_symcache_get_cur_item (task);
	}

	if (msg->host) {
		cbd->host = rspamd_fstring_cstr (msg->host);
	}

	if (body) {
		if (gzip) {
			if (rspamd_fstring_gzip (&body)) {
				rspamd_http_message_add_header (msg, "Content-Encoding", "gzip");
			}
		}

		rspamd_http_message_set_body_from_fstring_steal (msg, body);
	}

	if (session) {
		cbd->session = session;
	}

	if (rspamd_parse_inet_address (&cbd->addr, msg->host->str, msg->host->len)) {
		/* Host is numeric IP, no need to resolve */
		if (!lua_http_make_connection (cbd)) {
			lua_http_maybe_free (cbd);
			lua_pushboolean (L, FALSE);

			return 1;
		}
	}
	else {
		if (task == NULL) {
			to_resolve = g_malloc (msg->host->len + 1);
			rspamd_strlcpy (to_resolve, msg->host->str, msg->host->len + 1);

			if (!make_dns_request (resolver, session, NULL, lua_http_dns_handler, cbd,
					RDNS_REQUEST_A,
					to_resolve)) {
				lua_http_maybe_free (cbd);
				lua_pushboolean (L, FALSE);
				g_free (to_resolve);

				return 1;
			}


			g_free (to_resolve);
		}
		else {
			to_resolve = rspamd_mempool_fstrdup (task->task_pool, msg->host);

			if (!make_dns_request_task_forced (task, lua_http_dns_handler, cbd,
					RDNS_REQUEST_A, to_resolve)) {
				lua_http_maybe_free (cbd);
				lua_pushboolean (L, FALSE);

				return 1;
			}
			else if (cbd->item) {
				rspamd_symcache_item_async_inc (cbd->task, cbd->item, M);
			}
		}
	}

	if (cbd->cbref == -1) {
		cbd->thread = lua_thread_pool_get_running_entry (cfg->lua_thread_pool);

		return lua_thread_yield (cbd->thread, 0);
	}
	else {
		lua_pushboolean (L, TRUE);
	}

	return 1;
}

static gint
lua_load_http (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, httplib_m);

	return 1;
}

void
luaopen_http (lua_State * L)
{
	rspamd_lua_add_preload (L, "rspamd_http", lua_load_http);
}
