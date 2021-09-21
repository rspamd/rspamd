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
#include "libserver/http/http_private.h"
#include "ref.h"
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
#define RSPAMD_LUA_HTTP_FLAG_KEEP_ALIVE (1 << 3)
#define RSPAMD_LUA_HTTP_FLAG_YIELDED (1 << 4)

struct lua_http_cbdata {
	struct rspamd_http_connection *conn;
	struct rspamd_async_session *session;
	struct rspamd_symcache_item *item;
	struct rspamd_http_message *msg;
	struct ev_loop *event_loop;
	struct rspamd_config *cfg;
	struct rspamd_task *task;
	ev_tstamp timeout;
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
	ref_entry_t ref;
};

static const gdouble default_http_timeout = 5.0;

static struct rspamd_dns_resolver *
lua_http_global_resolver (struct ev_loop *ev_base)
{
	static struct rspamd_dns_resolver *global_resolver;

	if (global_resolver == NULL) {
		global_resolver = rspamd_dns_resolver_init (NULL, ev_base, NULL);
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
lua_http_cbd_dtor (struct lua_http_cbdata *cbd)
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
		if (cbd->flags & RSPAMD_LUA_HTTP_FLAG_YIELDED) {
			cbd->flags &= ~RSPAMD_LUA_HTTP_FLAG_YIELDED;
			lua_http_resume_handler (conn, NULL, err->message);
		}
		else {
			/* TODO: kill me please */
			msg_info ("lost HTTP error from %s in coroutines mess: %s",
					rspamd_inet_address_to_string_pretty (cbd->addr),
					err->message);
		}
	}
	else {
		lua_http_push_error (cbd, err->message);
	}

	REF_RELEASE (cbd);
}

static int
lua_http_finish_handler (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg)
{
	struct lua_http_cbdata *cbd = (struct lua_http_cbdata *)conn->ud;
	struct rspamd_http_header *h;
	const gchar *body;
	gsize body_len;

	struct lua_callback_state lcbd;
	lua_State *L;

	if (cbd->cbref == -1) {
		if (cbd->flags & RSPAMD_LUA_HTTP_FLAG_YIELDED) {
			cbd->flags &= ~RSPAMD_LUA_HTTP_FLAG_YIELDED;
			lua_http_resume_handler (conn, msg, NULL);
		}
		else {
			/* TODO: kill me please */
			msg_err ("lost HTTP data from %s in coroutines mess",
					rspamd_inet_address_to_string_pretty (cbd->addr));
		}

		REF_RELEASE (cbd);

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

	kh_foreach_value (msg->headers, h, {
		/*
		 * Lowercase header name, as Lua cannot search in caseless matter
		 */
		rspamd_str_lc (h->combined->str, h->name.len);
		lua_pushlstring (L, h->name.begin, h->name.len);
		lua_pushlstring (L, h->value.begin, h->value.len);
		lua_settable (L, -3);
	});

	if (cbd->item) {
		/* Replace watcher to deal with nested calls */
		rspamd_symcache_set_cur_item (cbd->task, cbd->item);
	}

	if (lua_pcall (L, 4, 0, 0) != 0) {
		msg_info ("callback call failed: %s", lua_tostring (L, -1));
		lua_pop (L, 1);
	}

	REF_RELEASE (cbd);

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
	struct rspamd_http_header *h;

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

		kh_foreach_value (msg->headers, h, {
			/*
			 * Lowercase header name, as Lua cannot search in caseless matter
			 */
			rspamd_str_lc (h->combined->str, h->name.len);
			lua_pushlstring (L, h->name.begin, h->name.len);
			lua_pushlstring (L, h->value.begin, h->value.len);
			lua_settable (L, -3);
		});

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
	rspamd_inet_address_set_port (cbd->addr, cbd->msg->port);

	if (cbd->flags & RSPAMD_LUA_HTTP_FLAG_KEEP_ALIVE) {
		cbd->fd = -1; /* FD is owned by keepalive connection */
		cbd->conn = rspamd_http_connection_new_keepalive (
				NULL, /* Default context */
				NULL,
				lua_http_error_handler,
				lua_http_finish_handler,
				cbd->addr,
				cbd->host);
	}
	else {
		cbd->fd = -1;
		cbd->conn = rspamd_http_connection_new_client (
				NULL, /* Default context */
				NULL,
				lua_http_error_handler,
				lua_http_finish_handler,
				RSPAMD_HTTP_CLIENT_SIMPLE,
				cbd->addr);
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

		if (cbd->task) {
			cbd->conn->log_tag = cbd->task->task_pool->tag.uid;

			if (cbd->item) {
				rspamd_symcache_item_async_inc (cbd->task, cbd->item, M);
			}
		}
		else if (cbd->cfg) {
			cbd->conn->log_tag = cbd->cfg->cfg_pool->tag.uid;
		}

		struct rspamd_http_message *msg = cbd->msg;

		/* Message is now owned by a connection object */
		cbd->msg = NULL;

		return rspamd_http_connection_write_message (cbd->conn, msg,
				cbd->host, cbd->mime_type, cbd,
				cbd->timeout);
	}

	return FALSE;
}

static void
lua_http_dns_handler (struct rdns_reply *reply, gpointer ud)
{
	struct lua_http_cbdata *cbd = (struct lua_http_cbdata *)ud;
	struct rspamd_symcache_item *item;
	struct rspamd_task *task;

	task = cbd->task;
	item = cbd->item;

	if (reply->code != RDNS_RC_NOERROR) {
		lua_http_push_error (cbd, "unable to resolve host");
		REF_RELEASE (cbd);
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

		REF_RETAIN (cbd);
		if (!lua_http_make_connection (cbd)) {
			lua_http_push_error (cbd, "unable to make connection to the host");

			if (cbd->ref.refcount > 1) {
				REF_RELEASE (cbd);
			}

			REF_RELEASE (cbd);

			return;
		}
		REF_RELEASE (cbd);
	}

	if (item) {
		rspamd_symcache_item_async_dec_check (task, item, M);
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
 * @param {boolean} keepalive enable keep-alive pool
 * @param {string} user for HTTP authentication
 * @param {string} password for HTTP authentication, only if "user" present
 * @return {boolean} `true`, in **async** mode, if a request has been successfully scheduled. If this value is `false` then some error occurred, the callback thus will not be called.
 * @return In **sync** mode `string|nil, nil|table` In sync mode  error message if any and response as table: `int` _code_, `string` _content_ and `table` _headers_ (header -> value)
 */
static gint
lua_http_request (lua_State *L)
{
	LUA_TRACE_POINT;
	struct ev_loop *ev_base;
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
			ev_base = *(struct ev_loop **)lua_touserdata (L, 3);
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

			if (task) {
				ev_base = task->event_loop;
				resolver = task->resolver;
				session = task->s;
				cfg = task->cfg;
			}
		}
		lua_pop (L, 1);

		if (task == NULL) {
			lua_pushstring (L, "ev_base");
			lua_gettable (L, 1);
			if (rspamd_lua_check_udata_maybe (L, -1, "rspamd{ev_base}")) {
				ev_base = *(struct ev_loop **)lua_touserdata (L, -1);
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
			timeout = lua_tonumber (L, -1);
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
				rspamd_http_message_unref (msg);
				g_free (mime_type);

				return luaL_error (L, "invalid body argument type: %s",
						lua_typename (L, lua_type (L, -1)));
			}
		}
		else if (lua_type (L, -1) == LUA_TTABLE) {
			gsize total_len = 0, nelts = rspamd_lua_table_size (L, -1);

			/* Calculate length and check types */
			for (gsize i = 0; i < nelts; i ++) {
				lua_rawgeti (L, -1, i + 1);

				if (lua_type (L, -1) == LUA_TSTRING) {
#if LUA_VERSION_NUM >= 502
					total_len += lua_rawlen (L, -1);
#else
					total_len += lua_objlen (L, -1);
#endif
				}
				else if (lua_type (L, -1) == LUA_TUSERDATA) {
					t = lua_check_text (L, -1);

					if (t) {
						total_len += t->len;
					}
					else {
						rspamd_http_message_unref (msg);
						if (mime_type) {
							g_free (mime_type);
						}

						return luaL_error (L, "invalid body argument: %s",
								lua_typename (L, lua_type (L, -1)));
					}
				}
				else {
					rspamd_http_message_unref (msg);
					if (mime_type) {
						g_free (mime_type);
					}

					return luaL_error (L, "invalid body argument type: %s",
							lua_typename (L, lua_type (L, -1)));
				}

				lua_pop (L, 1);
			}

			/* Preallocate body */
			if (total_len > 0) {
				body = rspamd_fstring_sized_new (total_len);
			}
			else {
				rspamd_http_message_unref (msg);
				if (mime_type) {
					g_free (mime_type);
				}

				return luaL_error (L, "empty body specified");
			}

			/* Fill elements */
			for (gsize i = 0; i < nelts; i ++) {
				lua_rawgeti (L, -1, i + 1);

				if (lua_type (L, -1) == LUA_TSTRING) {
					lua_body = lua_tolstring (L, -1, &bodylen);
					body = rspamd_fstring_append (body, lua_body, bodylen);
				}
				else {
					t = lua_check_text (L, -1);

					if (t) {
						body = rspamd_fstring_append(body, t->start, t->len);
					}
				}

				lua_pop (L, 1);
			}
		}
		else if (lua_type (L, -1) != LUA_TNONE && lua_type (L, -1) != LUA_TNIL) {
			rspamd_http_message_unref (msg);
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

		lua_pushstring (L, "keepalive");
		lua_gettable (L, 1);

		if (!!lua_toboolean (L, -1)) {
			flags |= RSPAMD_LUA_HTTP_FLAG_KEEP_ALIVE;
		}

		lua_pop (L, 1);

		lua_pushstring (L, "max_size");
		lua_gettable (L, 1);

		if (lua_type (L, -1) == LUA_TNUMBER) {
			max_size = lua_tointeger (L, -1);
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

		g_free (auth);
		rspamd_http_message_unref (msg);
		if (body) {
			rspamd_fstring_free (body);
		}
		if (local_kp) {
			rspamd_keypair_unref (local_kp);
		}

		return 1;
	}
	if (task == NULL && cfg == NULL) {
		g_free (auth);
		rspamd_http_message_unref (msg);
		if (body) {
			rspamd_fstring_free (body);
		}
		if (local_kp) {
			rspamd_keypair_unref (local_kp);
		}

		return luaL_error (L,
				"Bad params to rspamd_http:request(): either task or config should be set");
	}

	if (ev_base == NULL) {
		g_free (auth);
		rspamd_http_message_unref (msg);
		if (body) {
			rspamd_fstring_free (body);
		}
		if (local_kp) {
			rspamd_keypair_unref (local_kp);
		}

		return luaL_error (L,
				"Bad params to rspamd_http:request(): ev_base isn't passed");
	}

	cbd = g_malloc0 (sizeof (*cbd));
	cbd->cbref = cbref;
	cbd->msg = msg;
	cbd->event_loop = ev_base;
	cbd->mime_type = mime_type;
	cbd->timeout = timeout;
	cbd->fd = -1;
	cbd->cfg = cfg;
	cbd->peer_pk = peer_key;
	cbd->local_kp = local_kp;
	cbd->flags = flags;
	cbd->max_size = max_size;
	cbd->url = url;
	cbd->auth = auth;
	cbd->task = task;

	if (cbd->cbref == -1) {
		cbd->thread = lua_thread_pool_get_running_entry (cfg->lua_thread_pool);
	}

	REF_INIT_RETAIN (cbd, lua_http_cbd_dtor);

	if (task) {
		cbd->item = rspamd_symcache_get_cur_item (task);
	}


	const rspamd_ftok_t *host_header_tok = rspamd_http_message_find_header (msg, "Host");
	if (host_header_tok != NULL) {
		if (msg->host) {
			g_string_free (msg->host, true);
		}
		msg->host = g_string_new_len (host_header_tok->begin, host_header_tok->len);
		cbd->host = msg->host->str;
	}
	else {
		if (msg->host) {
			cbd->host = msg->host->str;
		}
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

	if (msg->host && rspamd_parse_inet_address (&cbd->addr,
			msg->host->str, msg->host->len, RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
		/* Host is numeric IP, no need to resolve */
		gboolean ret;

		REF_RETAIN (cbd);
		ret = lua_http_make_connection (cbd);

		if (!ret) {
			if (cbd->ref.refcount > 1) {
				/* Not released by make_connection */
				REF_RELEASE (cbd);
			}

			REF_RELEASE (cbd);
			lua_pushboolean (L, FALSE);

			return 1;
		}

		REF_RELEASE (cbd);
	}
	else {
		if (!cbd->host) {
			REF_RELEASE (cbd);

			return luaL_error (L, "no host has been specified");
		}
		if (task == NULL) {

			REF_RETAIN (cbd);
			if (!rspamd_dns_resolver_request (resolver, session, NULL, lua_http_dns_handler, cbd,
					RDNS_REQUEST_A,
					cbd->host)) {
				if (cbd->ref.refcount > 1) {
					/* Not released by make_connection */
					REF_RELEASE (cbd);
				}

				REF_RELEASE (cbd);
				lua_pushboolean (L, FALSE);

				return 1;
			}

			REF_RELEASE (cbd);
		}
		else {
			REF_RETAIN (cbd);

			if (!rspamd_dns_resolver_request_task_forced (task, lua_http_dns_handler, cbd,
					RDNS_REQUEST_A, cbd->host)) {
				if (cbd->ref.refcount > 1) {
					/* Not released by make_connection */
					REF_RELEASE (cbd);
				}

				REF_RELEASE (cbd);
				lua_pushboolean (L, FALSE);

				return 1;
			}
			else if (cbd->item) {
				rspamd_symcache_item_async_inc (cbd->task, cbd->item, M);
			}

			REF_RELEASE (cbd);
		}
	}

	if (cbd->cbref == -1) {
		cbd->thread = lua_thread_pool_get_running_entry (cfg->lua_thread_pool);
		cbd->flags |= RSPAMD_LUA_HTTP_FLAG_YIELDED;

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
