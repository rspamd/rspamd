/*
 * Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
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

#include "lua_common.h"
#include "buffer.h"
#include "dns.h"
#include "utlist.h"

LUA_FUNCTION_DEF (tcp, request);

static const struct luaL_reg tcp_libf[] = {
	LUA_INTERFACE_DEF (tcp, request),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

struct lua_tcp_cbdata {
	lua_State *L;
	struct rspamd_async_session *session;
	struct event_base *ev_base;
	struct timeval tv;
	rspamd_inet_addr_t *addr;
	rspamd_mempool_t *pool;
	struct iovec *iov;
	gint fd;
	gint cbref;
	guint iovlen;
	guint pos;
	guint total;
	gboolean partial;
	guint16 port;
};

static const int default_tcp_timeout = 5000;

static struct rspamd_dns_resolver *
lua_tcp_global_resolver (struct event_base *ev_base)
{
	static struct rspamd_dns_resolver *global_resolver;

	if (global_resolver == NULL) {
		global_resolver = dns_resolver_init (NULL, ev_base, NULL);
	}

	return global_resolver;
}

static void
lua_tcp_fin (gpointer arg)
{
	struct lua_tcp_cbdata *cbd = (struct lua_tcp_cbdata *)arg;

	luaL_unref (cbd->L, LUA_REGISTRYINDEX, cbd->cbref);

	if (cbd->fd != -1) {
		close (cbd->fd);
	}

	if (cbd->addr) {
		rspamd_inet_address_destroy (cbd->addr);
	}

	g_slice_free1 (sizeof (struct lua_tcp_cbdata), cbd);
}

static void
lua_tcp_maybe_free (struct lua_tcp_cbdata *cbd)
{
	if (cbd->session) {
		remove_normal_event (cbd->session, lua_tcp_fin, cbd);
	}
	else {
		lua_tcp_fin (cbd);
	}
}

static void
lua_tcp_push_error (struct lua_tcp_cbdata *cbd, const char *err)
{
	lua_rawgeti (cbd->L, LUA_REGISTRYINDEX, cbd->cbref);
	lua_pushstring (cbd->L, err);

	if (lua_pcall (cbd->L, 1, 0, 0) != 0) {
		msg_info ("callback call failed: %s", lua_tostring (cbd->L, -1));
	}
}

static gboolean
lua_tcp_make_connection (struct lua_tcp_cbdata *cbd)
{
	int fd;

	rspamd_inet_address_set_port (cbd->addr, cbd->port);
	fd = rspamd_inet_address_connect (cbd->addr, SOCK_STREAM, TRUE);

	if (fd == -1) {
		msg_info ("cannot connect to %s", rspamd_inet_address_to_string (cbd->addr));
		return FALSE;
	}
	cbd->fd = fd;

	return TRUE;
}

static void
lua_tcp_dns_handler (struct rdns_reply *reply, gpointer ud)
{
	struct lua_tcp_cbdata *cbd = (struct lua_tcp_cbdata *)ud;

	if (reply->code != RDNS_RC_NOERROR) {
		lua_tcp_push_error (cbd, "unable to resolve host");
		lua_tcp_maybe_free (cbd);
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

		if (!lua_tcp_make_connection (cbd)) {
			lua_tcp_push_error (cbd, "unable to make connection to the host");
			lua_tcp_maybe_free (cbd);
		}
	}
}

static gboolean
lua_tcp_arg_toiovec (lua_State *L, gint pos, rspamd_mempool_t *pool,
		struct iovec *vec)
{
	struct rspamd_lua_text *t;
	gsize len;
	const gchar *str;

	if (lua_type (L, pos) == LUA_TUSERDATA) {
		t = lua_check_text (L, pos);

		if (t) {
			vec->iov_base = (void *)t->start;
			vec->iov_len = t->len;
		}
		else {
			return FALSE;
		}
	}
	else if (lua_type (L, pos) == LUA_TSTRING) {
		str = luaL_checklstring (L, pos, &len);
		vec->iov_base = rspamd_mempool_alloc (pool, len + 1);
		rspamd_strlcpy (vec->iov_base, str, len + 1);
		vec->iov_len = len;
	}
	else {
		return FALSE;
	}

	return TRUE;
}

static gint
lua_tcp_request (lua_State *L)
{
	const gchar *host;
	guint port;
	gint cbref, tp;
	struct event_base *ev_base;
	struct lua_tcp_cbdata *cbd;
	struct rspamd_dns_resolver *resolver;
	struct rspamd_async_session *session;
	struct rspamd_task *task = NULL;
	rspamd_mempool_t *pool;
	struct iovec *iov = NULL;
	guint niov = 0, total_out;
	gdouble timeout = default_tcp_timeout;
	gboolean partial = FALSE;

	if (lua_type (L, 1) == LUA_TTABLE) {
		lua_pushstring (L, "url");
		lua_gettable (L, -2);
		host = luaL_checkstring (L, -1);
		lua_pop (L, 1);

		lua_pushstring (L, "port");
		lua_gettable (L, -2);
		port = luaL_checknumber (L, -1);
		lua_pop (L, 1);

		lua_pushstring (L, "callback");
		lua_gettable (L, -2);
		if (host == NULL || lua_type (L, -1) != LUA_TFUNCTION) {
			lua_pop (L, 1);
			msg_err ("tcp request has bad params");
			lua_pushboolean (L, FALSE);
			return 1;
		}
		cbref = luaL_ref (L, LUA_REGISTRYINDEX);

		lua_pushstring (L, "task");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TUSERDATA) {
			task = lua_check_task (L, -1);
			ev_base = task->ev_base;
			resolver = task->resolver;
			session = task->s;
			pool = task->task_pool;
		}
		lua_pop (L, 1);

		if (task == NULL) {
			lua_pushstring (L, "ev_base");
			lua_gettable (L, -2);
			if (luaL_checkudata (L, -1, "rspamd{ev_base}")) {
				ev_base = *(struct event_base **)lua_touserdata (L, -1);
			}
			else {
				ev_base = NULL;
			}
			lua_pop (L, 1);

			lua_pushstring (L, "pool");
			lua_gettable (L, -2);
			if (luaL_checkudata (L, -1, "rspamd{mempool}")) {
				pool = *(rspamd_mempool_t **)lua_touserdata (L, -1);
			}
			else {
				pool = NULL;
			}
			lua_pop (L, 1);

			lua_pushstring (L, "resolver");
			lua_gettable (L, -2);
			if (luaL_checkudata (L, -1, "rspamd{resolver}")) {
				resolver = *(struct rspamd_dns_resolver **)lua_touserdata (L, -1);
			}
			else {
				resolver = lua_tcp_global_resolver (ev_base);
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
		}

		lua_pushstring (L, "timeout");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TNUMBER) {
			timeout = lua_tonumber (L, -1) * 1000.;
		}
		lua_pop (L, 1);

		lua_pushstring (L, "partial");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TBOOLEAN) {
			partial = lua_toboolean (L, -1);
		}
		lua_pop (L, 1);

		if (pool == NULL) {
			lua_pop (L, 1);
			msg_err ("tcp request has no memory pool associated");
			lua_pushboolean (L, FALSE);
			return 1;
		}

		lua_pushstring (L, "data");
		lua_gettable (L, -2);
		total_out = 0;

		tp = lua_type (L, -1);
		if (tp == LUA_TSTRING || tp == LUA_TUSERDATA) {
			iov = rspamd_mempool_alloc (pool, sizeof (*iov));
			niov = 1;

			if (!lua_tcp_arg_toiovec (L, -1, pool, iov)) {
				lua_pop (L, 1);
				msg_err ("tcp request has bad data argument");
				lua_pushboolean (L, FALSE);
				return 1;
			}

			total_out = iov[0].iov_len;
		}
		else if (tp == LUA_TTABLE) {
			/* Count parts */
			lua_pushnil (L);
			while (lua_next (L, -2) != 0) {
				niov ++;
				lua_pop (L, 1);
			}

			iov = rspamd_mempool_alloc (pool, sizeof (*iov) * niov);
			lua_pushnil (L);
			niov = 0;

			while (lua_next (L, -2) != 0) {
				if (!lua_tcp_arg_toiovec (L, -1, pool, &iov[niov])) {
					lua_pop (L, 2);
					msg_err ("tcp request has bad data argument at pos %d", niov);
					lua_pushboolean (L, FALSE);
					return 1;
				}

				total_out += iov[niov].iov_len;
				niov ++;

				lua_pop (L, 1);
			}
		}

		lua_pop (L, 1);
	}
	else {
		msg_err ("tcp request has bad params");
		lua_pushboolean (L, FALSE);

		return 1;
	}

	cbd = g_slice_alloc0 (sizeof (*cbd));
	cbd->L = L;
	cbd->cbref = cbref;
	cbd->ev_base = ev_base;
	msec_to_tv (timeout, &cbd->tv);
	cbd->fd = -1;
	cbd->pool = pool;
	cbd->partial = partial;
	cbd->iov = iov;
	cbd->iovlen = niov;
	cbd->total = total_out;
	cbd->pos = 0;

	if (session) {
		cbd->session = session;
		register_async_event (session,
				(event_finalizer_t)lua_tcp_fin,
				cbd,
				g_quark_from_static_string ("lua tcp"));
	}

	if (rspamd_parse_inet_address (&cbd->addr, host)) {
		rspamd_inet_address_set_port (cbd->addr, port);
		/* Host is numeric IP, no need to resolve */
		if (!lua_tcp_make_connection (cbd)) {
			lua_tcp_maybe_free (cbd);
			lua_pushboolean (L, FALSE);

			return 1;
		}
	}
	else {
		make_dns_request (resolver, session, NULL, lua_tcp_dns_handler, cbd,
				RDNS_REQUEST_A, host);
	}

	lua_pushboolean (L, TRUE);
	return 1;
}

static gint
lua_load_tcp (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, tcp_libf);

	return 1;
}

void
luaopen_tcp (lua_State * L)
{
	rspamd_lua_add_preload (L, "rspamd_tcp", lua_load_tcp);
}
