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
#include "buffer.h"
#include "dns.h"
#include "http.h"

#define MAX_HEADERS_SIZE 8192

LUA_FUNCTION_DEF (http, request);

static const struct luaL_reg httplib_m[] = {
	LUA_INTERFACE_DEF (http, request),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

struct lua_http_cbdata {
	lua_State *L;
	struct rspamd_http_connection *conn;
	struct rspamd_async_session *session;
	struct rspamd_http_message *msg;
	struct event_base *ev_base;
	struct timeval tv;
	rspamd_inet_addr_t addr;
	gint cbref;
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

	luaL_unref (cbd->L, LUA_REGISTRYINDEX, cbd->cbref);
	if (cbd->conn) {
		/* Here we already have a connection, so we need to unref it */
		rspamd_http_connection_unref (cbd->conn);
	}
	else if (cbd->msg != NULL) {
		/* We need to free message */
		rspamd_http_message_free (cbd->msg);
	}

	g_slice_free1 (sizeof (struct lua_http_cbdata), cbd);
}

static void
lua_http_maybe_free (struct lua_http_cbdata *cbd)
{
	if (cbd->session) {
		remove_normal_event (cbd->session, lua_http_fin, cbd);
	}
	else {
		lua_http_fin (cbd);
	}
}

static void
lua_http_push_error (struct lua_http_cbdata *cbd, const char *err)
{
	lua_rawgeti (cbd->L, LUA_REGISTRYINDEX, cbd->cbref);
	lua_pushstring (cbd->L, err);

	if (lua_pcall (cbd->L, 1, 0, 0) != 0) {
		msg_info ("callback call failed: %s", lua_tostring (cbd->L, -1));
	}
}

static void
lua_http_error_handler (struct rspamd_http_connection *conn, GError *err)
{
	struct lua_http_cbdata *cbd = (struct lua_http_cbdata *)conn->ud;

	lua_http_push_error (cbd, err->message);
	lua_http_maybe_free (cbd);
}

static int
lua_http_finish_handler (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg)
{
	struct lua_http_cbdata *cbd = (struct lua_http_cbdata *)conn->ud;
	struct rspamd_http_header *h;

	lua_rawgeti (cbd->L, LUA_REGISTRYINDEX, cbd->cbref);
	/* Error */
	lua_pushnil (cbd->L);
	/* Reply code */
	lua_pushinteger (cbd->L, msg->code);
	/* Body */
	lua_pushlstring (cbd->L, msg->body->str, msg->body->len);
	/* Headers */
	lua_newtable (cbd->L);
	LL_FOREACH (msg->headers, h) {
		rspamd_lua_table_set (cbd->L, h->name->str, h->value->str);
	}
	if (lua_pcall (cbd->L, 4, 0, 0) != 0) {
		msg_info ("callback call failed: %s", lua_tostring (cbd->L, -1));
	}

	lua_http_maybe_free (cbd);

	return 0;
}

static gboolean
lua_http_make_connection (struct lua_http_cbdata *cbd)
{
	int fd;

	rspamd_inet_address_set_port (&cbd->addr, cbd->msg->port);
	fd = rspamd_inet_address_connect (&cbd->addr, SOCK_STREAM, TRUE);

	if (fd == -1) {
		lua_http_maybe_free (cbd);
		return FALSE;
	}
	cbd->conn = rspamd_http_connection_new (NULL, lua_http_error_handler,
			lua_http_finish_handler, RSPAMD_HTTP_CLIENT_SIMPLE, RSPAMD_HTTP_CLIENT);

	rspamd_http_connection_write_message (cbd->conn, cbd->msg,
			NULL, NULL, cbd, fd, &cbd->tv, cbd->ev_base);
	/* Message is now owned by a connection object */
	cbd->msg = NULL;

	return TRUE;
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
		/* XXX: support ipv6 some day */
		cbd->addr.af = AF_INET;
		memcpy (&cbd->addr.addr.s4.sin_addr, &reply->entries->content.a.addr,
				sizeof (struct in_addr));
		if (!lua_http_make_connection (cbd)) {
			lua_http_push_error (cbd, "unable to make connection to the host");
			lua_http_maybe_free (cbd);
		}
	}
}

static void
lua_http_push_headers (lua_State *L, struct rspamd_http_message *msg)
{
	const char *name, *value;

	lua_pushnil (L);
	while (lua_next (L, -2) != 0) {

		name = rspamd_lua_table_get (L, "name");
		value = rspamd_lua_table_get (L, "value");

		if (name != NULL && value != NULL) {
			rspamd_http_message_add_header (msg, name, value);
		}
		lua_pop (L, 1);
	}
	lua_pop (L, 1);
}

static gint
lua_http_request (lua_State *L)
{
	const gchar *url;
	gint cbref;
	struct event_base *ev_base;
	struct rspamd_http_message *msg;
	struct lua_http_cbdata *cbd;
	struct rspamd_dns_resolver *resolver;
	struct rspamd_async_session *session;
	gdouble timeout = default_http_timeout;

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
		if (lua_gettop (L) >= 3 && luaL_checkudata (L, 3, "rspamd{ev_base}")) {
			ev_base = *(struct event_base **)lua_touserdata (L, 3);
		}
		else {
			ev_base = NULL;
		}
		if (lua_gettop (L) >= 4 && luaL_checkudata (L, 4, "rspamd{resolver}")) {
			resolver = *(struct rspamd_dns_resolver **)lua_touserdata (L, 4);
		}
		else {
			resolver = lua_http_global_resolver (ev_base);
		}
		if (lua_gettop (L) >= 5 && luaL_checkudata (L, 5, "rspamd{session}")) {
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
		lua_gettable (L, -2);
		url = luaL_checkstring (L, -1);
		lua_pop (L, 1);

		lua_pushstring (L, "callback");
		lua_gettable (L, -2);
		if (url == NULL || lua_type (L, -1) != LUA_TFUNCTION) {
			lua_pop (L, 1);
			msg_err ("http request has bad params");
			lua_pushboolean (L, FALSE);
			return 1;
		}
		cbref = luaL_ref (L, LUA_REGISTRYINDEX);

		lua_pushstring (L, "ev_base");
		lua_gettable (L, -2);
		if (luaL_checkudata (L, -1, "rspamd{ev_base}")) {
			ev_base = *(struct event_base **)lua_touserdata (L, -1);
		}
		else {
			ev_base = NULL;
		}
		lua_pop (L, 1);

		lua_pushstring (L, "resolver");
		lua_gettable (L, -2);
		if (luaL_checkudata (L, -1, "rspamd{resolver}")) {
			resolver = *(struct rspamd_dns_resolver **)lua_touserdata (L, -1);
		}
		else {
			resolver = lua_http_global_resolver (ev_base);
		}
		lua_pop (L, 1);

		lua_pushstring (L, "session");
		lua_gettable (L, -2);
		if (luaL_checkudata (L, -1, "rspamd{session}")) {
			session = *(struct rspamd_async_session **)lua_touserdata (L, -1);
		}
		else {
			session = NULL;
		}
		lua_pop (L, 1);

		msg = rspamd_http_message_from_url (url);
		if (msg == NULL) {
			lua_pushboolean (L, FALSE);
			return 1;
		}

		lua_pushstring (L, "headers");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TTABLE) {
			lua_http_push_headers (L, msg);
		}
		lua_pop (L, 1);

		lua_pushstring (L, "timeout");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TNUMBER) {
			timeout = lua_tonumber (L, -1) * 1000.;
		}
		lua_pop (L, 1);

		lua_pushstring (L, "body");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TSTRING) {
			msg->body = g_string_new (lua_tostring (L, -1));
		}
		lua_pop (L, 1);
	}
	else {
		msg_err ("http request has bad params");
		lua_pushboolean (L, FALSE);
		return 1;
	}

	cbd = g_slice_alloc0 (sizeof (*cbd));
	cbd->L = L;
	cbd->cbref = cbref;
	cbd->msg = msg;
	msec_to_tv (timeout, &cbd->tv);
	if (session) {
		register_async_event (session,
				(event_finalizer_t)lua_http_fin,
				cbd,
				g_quark_from_static_string ("lua http"));
	}

	if (rspamd_parse_inet_address (&cbd->addr, msg->host->str)) {
		/* Host is numeric IP, no need to resolve */
		if (!lua_http_make_connection (cbd)) {
			lua_pushboolean (L, FALSE);
			return 1;
		}
	}
	else {
		make_dns_request (resolver, session, NULL, lua_http_dns_handler, cbd,
				RDNS_REQUEST_A, msg->host->str);
	}

	lua_pushboolean (L, TRUE);
	return 1;
}

gint
luaopen_http (lua_State * L)
{

	luaL_register (L, "rspamd_http", httplib_m);

	return 1;
}
