/*-
 * Copyright 2019 Vsevolod Stakhov
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
#include "utlist.h"
#include "unix-std.h"
#include <math.h>

static const gchar *M = "rspamd lua udp";

/***
 * @module rspamd_udp
 * Rspamd UDP module represents generic UDP asynchronous client available from LUA code.
 * This module is quite simple: it can either send requests to some address or
 * it can send requests and wait for replies, potentially handling retransmits.
 * @example
local logger = require "rspamd_logger"
local udp = require "rspamd_udp"

rspamd_config.SYM = function(task)
  udp.sento({
    host = addr, -- must be ip address object (e.g. received by upstream module)
    port = 500,
    data = data, -- can be table, string or rspamd_text
    timeout = 0.5, -- default = 1s
    task = task, -- if has task
    session = session, -- optional
    ev_base = ev_base, -- if no task available
  }
end
 */

static const double default_udp_timeout = 1.0;

LUA_FUNCTION_DEF (udp, sendto);

static const struct luaL_reg udp_libf[] = {
	LUA_INTERFACE_DEF (udp, sendto),
	{NULL, NULL}
};

struct lua_udp_cbdata {
	struct event io;
	struct event_base *ev_base;
	rspamd_mempool_t *pool;
	rspamd_inet_addr_t *addr;
	struct rspamd_symcache_item *item;
	struct rspamd_async_session *s;
	struct iovec *iov;
	lua_State *L;
	guint iovlen;
	gint sock;
	gint cbref;
};

#define msg_debug_udp(...)  rspamd_conditional_debug_fast (NULL, cbd->addr, \
        rspamd_lua_udp_log_id, "lua_udp", cbd->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(lua_udp)

static inline void
lua_fill_iov (lua_State *L, rspamd_mempool_t *pool,
		struct iovec *iov, gint pos)
{
	if (lua_type (L, pos) == LUA_TUSERDATA) {
		struct rspamd_lua_text *t = lua_check_text (L, pos);

		if (t) {
			iov->iov_base = rspamd_mempool_alloc (pool, t->len);
			iov->iov_len = t->len;
			memcpy (iov->iov_base, t->start, t->len);
		}
	}
	else {
		const gchar *s;
		gsize len;

		s = lua_tolstring (L, pos, &len);

		iov->iov_base = rspamd_mempool_alloc (pool, len);
		iov->iov_len = len;
		memcpy (iov->iov_base, s, len);
	}
}

static void
lua_udp_cbd_fin (gpointer p)
{
	struct lua_udp_cbdata *cbd = (struct lua_udp_cbdata *)p;

	if (cbd->sock != -1) {
		close (cbd->sock);
	}

	if (cbd->addr) {
		rspamd_inet_address_free (cbd->addr);
	}
}


enum rspamd_udp_send_result {
	RSPAMD_SENT_OK,
	RSPAMD_SENT_RETRY,
	RSPAMD_SENT_FAILURE
};

static enum rspamd_udp_send_result
lua_try_send_request (struct lua_udp_cbdata *cbd)
{
	struct msghdr msg;
	gint r;

	memset (&msg, 0, sizeof (msg));
	msg.msg_iov = cbd->iov;
	msg.msg_iovlen = cbd->iovlen;
	msg.msg_name = rspamd_inet_address_get_sa (cbd->addr, &msg.msg_namelen);

	r = sendmsg (cbd->sock, &msg, 0);

	if (r != -1) {
		return RSPAMD_SENT_OK;
	}

	if (errno == EAGAIN || errno == EINTR) {
		return RSPAMD_SENT_RETRY;
	}

	return RSPAMD_SENT_FAILURE;
}


/***
 * @function rspamd_tcp.request({params})
 * This function creates and sends TCP request to the specified host and port,
 * resolves hostname (if needed) and invokes continuation callback upon data received
 * from the remote peer. This function accepts table of arguments with the following
 * attributes
 *
 * - `task`: rspamd task objects (implies `pool`, `session`, `ev_base` and `resolver` arguments)
 * - `ev_base`: event base (if no task specified)
 * - `session`: events session (no task)
 * - `host`: IP or name of the peer (required)
 * - `port`: remote port to use
 * - `data`: a table of strings or `rspamd_text` objects that contains data pieces
 * - `callback`: continuation function (required)
 * - `on_connect`: callback called on connection success
 * - `timeout`: floating point value that specifies timeout for IO operations in **seconds**
 * - `partial`: boolean flag that specifies that callback should be called on any data portion received
 * - `stop_pattern`: stop reading on finding a certain pattern (e.g. \r\n.\r\n for smtp)
 * - `shutdown`: half-close socket after writing (boolean: default false)
 * - `read`: read response after sending request (boolean: default true)
 * @return {boolean} true if request has been sent
 */
static gint
lua_udp_sendto (lua_State *L) {
	LUA_TRACE_POINT;
	const gchar *host;
	guint port;
	gint cbref, tp, conn_cbref = -1;
	struct event_base *ev_base = NULL;
	struct lua_udp_cbdata *cbd;
	struct rspamd_async_session *session = NULL;
	struct rspamd_task *task = NULL;
	rspamd_inet_addr_t *addr;
	rspamd_mempool_t *pool = NULL;
	struct iovec *iov = NULL;
	guint niov = 0, total_out;
	guint64 h;
	gdouble timeout = default_udp_timeout;

	if (lua_type (L, 1) == LUA_TTABLE) {
		lua_pushstring (L, "port");
		lua_gettable (L, -2);

		if (lua_type (L, -1) == LUA_TNUMBER) {
			port = luaL_checknumber (L, -1);
		}
		else {
			/* We assume that it is a unix socket */
			port = 0;
		}

		lua_pop (L, 1);

		lua_pushstring (L, "host");
		lua_gettable (L, -2);

		if (lua_type (L, -1) == LUA_TSTRING) {
			host = luaL_checkstring (L, -1);

			if (rspamd_parse_inet_address (&addr, host, 0)) {
				rspamd_inet_address_set_port (addr, port);
			}
			else {
				lua_pop (L, 1);
				return luaL_error (L, "invalid host: %s", host);
			}
		}
		else if (lua_type (L, -1) == LUA_TUSERDATA) {
			struct rspamd_lua_ip *lip;

			lip = lua_check_ip (L, -1);

			if (lip == NULL || lip->addr == NULL) {
				lua_pop (L, 1);
				return luaL_error (L, "invalid host class");
			}

			addr = rspamd_inet_address_copy (lip->addr);
		}
		else {
			lua_pop (L, 1);
			return luaL_error (L, "invalid host");
		}

		lua_pop (L, 1);

		lua_pushstring (L, "task");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TUSERDATA) {
			task = lua_check_task (L, -1);
			ev_base = task->ev_base;
			session = task->s;
			pool = task->task_pool;
		}
		lua_pop (L, 1);

		if (task == NULL) {
			lua_pushstring (L, "ev_base");
			lua_gettable (L, -2);
			if (rspamd_lua_check_udata_maybe (L, -1, "rspamd{ev_base}")) {
				ev_base = *(struct event_base **) lua_touserdata (L, -1);
			} else {
				ev_base = NULL;
			}
			lua_pop (L, 1);

			lua_pushstring (L, "session");
			lua_gettable (L, -2);
			if (rspamd_lua_check_udata_maybe (L, -1, "rspamd{session}")) {
				session = *(struct rspamd_async_session **) lua_touserdata (L, -1);
			} else {
				session = NULL;
			}
			lua_pop (L, 1);

			lua_pushstring (L, "session");
			lua_gettable (L, -2);
			if (rspamd_lua_check_udata_maybe (L, -1, "rspamd{mempool}")) {
				pool = *(rspamd_mempool_t **) lua_touserdata (L, -1);
			} else {
				pool = NULL;
			}
			lua_pop (L, 1);
		}

		lua_pushstring (L, "timeout");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TNUMBER) {
			timeout = lua_tonumber (L, -1) * 1000.;
		}
		lua_pop (L, 1);

		if (!ev_base || !pool) {
			rspamd_inet_address_free (addr);

			return luaL_error (L, "invalid arguments");
		}

		cbd = rspamd_mempool_alloc0 (pool, sizeof (*cbd));
		cbd->ev_base = ev_base;
		cbd->pool = pool;
		cbd->s = session;
		cbd->addr = addr;
		cbd->sock = rspamd_socket_create (rspamd_inet_address_get_af (addr),
				SOCK_DGRAM, 0, TRUE);

		if (cbd->sock == -1) {
			rspamd_inet_address_free (addr);

			return luaL_error (L, "cannot open socket: %s", strerror (errno));
		}

		cbd->L = L;

		gsize data_len;

		lua_pushstring (L, "data");
		if (lua_type (L, -1) == LUA_TTABLE) {
			data_len = rspamd_lua_table_size (L, -1);
			cbd->iov = rspamd_mempool_alloc (pool,
					sizeof (*cbd->iov) * data_len);

			for (int i = 0; i < data_len; i ++) {
				lua_rawgeti (L, -1, i + 1);
				lua_fill_iov (L, pool, &cbd->iov[i], -1);
				lua_pop (L, 1);
			}

			cbd->iovlen = data_len;
		}
		else {
			cbd->iov = rspamd_mempool_alloc (pool, sizeof (*cbd->iov));
			cbd->iovlen = 1;
			lua_fill_iov (L, pool, cbd->iov, -1);
		}

		lua_pop (L, 1);

		enum rspamd_udp_send_result r;

		r = lua_try_send_request (cbd);
		if (r == RSPAMD_SENT_OK) {
			lua_pushboolean (L, true);
			lua_udp_cbd_fin (cbd);
		}
		else if (r == RSPAMD_SENT_FAILURE) {
			lua_pushboolean (L, false);
			lua_pushstring (L, strerror (errno));
			lua_udp_cbd_fin (cbd);

			return 2;
		}
		else {
			/* TODO: add waiting */
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_load_udp (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, udp_libf);

	return 1;
}

void
luaopen_udp (lua_State * L)
{
	rspamd_lua_add_preload (L, "rspamd_udp", lua_load_udp);
}
