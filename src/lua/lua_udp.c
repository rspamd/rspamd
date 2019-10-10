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
#include <src/libutil/libev_helper.h>

static const gchar *M = "rspamd lua udp";

/***
 * @module rspamd_udp
 * Rspamd UDP module is available from the version 1.9.0 and represents a generic
 * UDP asynchronous client available from the LUA code.
 * This module is quite simple: it can either send requests to some address or
 * it can send requests and wait for replies, potentially handling retransmits.
 * @example
local logger = require "rspamd_logger"
local udp = require "rspamd_udp"

rspamd_config.SYM = function(task)
  udp.sento{
    host = addr, -- must be ip address object (e.g. received by upstream module)
    port = 500,
    data = {'str1', 'str2'}, -- can be table, string or rspamd_text
    timeout = 0.5, -- default = 1s
    task = task, -- if has task
    session = session, -- optional
    ev_base = ev_base, -- if no task available
    -- You can include callback and then Rspamd will try to read replies
    callback = function(success, data)
      -- success is bool, data is either data or an error (string)
    end,
    retransmits = 0, -- Or more if retransmitting is necessary
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
	struct ev_loop *event_loop;
	struct rspamd_io_ev ev;
	struct rspamd_async_event *async_ev;
	struct rspamd_task *task;
	rspamd_mempool_t *pool;
	rspamd_inet_addr_t *addr;
	struct rspamd_symcache_item *item;
	struct rspamd_async_session *s;
	struct iovec *iov;
	lua_State *L;
	guint retransmits;
	guint iovlen;
	gint sock;
	gint cbref;
	gboolean sent;
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
		rspamd_ev_watcher_stop (cbd->event_loop, &cbd->ev);
		close (cbd->sock);
	}

	if (cbd->addr) {
		rspamd_inet_address_free (cbd->addr);
	}

	if (cbd->cbref) {
		luaL_unref (cbd->L, LUA_REGISTRYINDEX, cbd->cbref);
	}
}

static void
lua_udp_maybe_free (struct lua_udp_cbdata *cbd)
{
	if (cbd->item) {
		rspamd_symcache_item_async_dec_check (cbd->task, cbd->item, M);
		cbd->item = NULL;
	}

	if (cbd->async_ev) {
		rspamd_session_remove_event (cbd->s, lua_udp_cbd_fin, cbd);
	}
	else {
		lua_udp_cbd_fin (cbd);
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

static void
lua_udp_maybe_push_error (struct lua_udp_cbdata *cbd, const gchar *err)
{
	if (cbd->cbref != -1) {
		gint top;
		lua_State *L = cbd->L;

		top = lua_gettop (L);
		lua_rawgeti (L, LUA_REGISTRYINDEX, cbd->cbref);

		/* Error message */
		lua_pushboolean (L, false);
		lua_pushstring (L, err);

		if (cbd->item) {
			rspamd_symcache_set_cur_item (cbd->task, cbd->item);
		}

		if (lua_pcall (L, 2, 0, 0) != 0) {
			msg_info ("callback call failed: %s", lua_tostring (L, -1));
		}

		lua_settop (L, top);
	}

	lua_udp_maybe_free (cbd);
}

static void
lua_udp_push_data (struct lua_udp_cbdata *cbd, const gchar *data,
		gssize len)
{
	if (cbd->cbref != -1) {
		gint top;
		lua_State *L = cbd->L;

		top = lua_gettop (L);
		lua_rawgeti (L, LUA_REGISTRYINDEX, cbd->cbref);

		/* Error message */
		lua_pushboolean (L, true);
		lua_pushlstring (L, data, len);

		if (cbd->item) {
			rspamd_symcache_set_cur_item (cbd->task, cbd->item);
		}

		if (lua_pcall (L, 2, 0, 0) != 0) {
			msg_info ("callback call failed: %s", lua_tostring (L, -1));
		}

		lua_settop (L, top);
	}

	lua_udp_maybe_free (cbd);
}

static gboolean
lua_udp_maybe_register_event (struct lua_udp_cbdata *cbd)
{
	if (cbd->s && !cbd->async_ev) {
		cbd->async_ev = rspamd_session_add_event (cbd->s, lua_udp_cbd_fin,
				cbd, M);

		if (!cbd->async_ev) {
			return FALSE;
		}
	}

	if (cbd->task && !cbd->item) {
		cbd->item = rspamd_symcache_get_cur_item (cbd->task);
		rspamd_symcache_item_async_inc (cbd->task, cbd->item, M);
	}

	return TRUE;
}

static void
lua_udp_io_handler (gint fd, short what, gpointer p)
{
	struct lua_udp_cbdata *cbd = (struct lua_udp_cbdata *)p;
	gssize r;

	if (what == EV_TIMEOUT) {
		if (cbd->sent && cbd->retransmits > 0) {
			r = lua_try_send_request (cbd);

			if (r == RSPAMD_SENT_OK) {
				rspamd_ev_watcher_reschedule (cbd->event_loop, &cbd->ev, EV_READ);
				lua_udp_maybe_register_event (cbd);
				cbd->retransmits --;
			}
			else if (r == RSPAMD_SENT_FAILURE) {
				lua_udp_maybe_push_error (cbd, "write error");
			}
			else {
				cbd->retransmits --;
				rspamd_ev_watcher_reschedule (cbd->event_loop, &cbd->ev, EV_WRITE);
			}
		}
		else {
			if (!cbd->sent) {
				lua_udp_maybe_push_error (cbd, "sent timeout");
			}
			else {
				lua_udp_maybe_push_error (cbd, "read timeout");
			}
		}
	}
	else if (what == EV_WRITE) {
		r = lua_try_send_request (cbd);

		if (r == RSPAMD_SENT_OK) {
			if (cbd->cbref != -1) {
				rspamd_ev_watcher_reschedule (cbd->event_loop, &cbd->ev, EV_READ);
				cbd->sent = TRUE;
			}
			else {
				lua_udp_maybe_free (cbd);
			}
		}
		else if (r == RSPAMD_SENT_FAILURE) {
			lua_udp_maybe_push_error (cbd, "write error");
		}
		else {
			cbd->retransmits --;
			rspamd_ev_watcher_reschedule (cbd->event_loop, &cbd->ev, EV_WRITE);
		}
	}
	else if (what == EV_READ) {
		guchar udpbuf[4096];
		socklen_t slen;
		struct sockaddr *sa;

		sa = rspamd_inet_address_get_sa (cbd->addr, &slen);

		r = recvfrom (cbd->sock, udpbuf, sizeof (udpbuf), 0, sa, &slen);

		if (r == -1) {
			lua_udp_maybe_push_error (cbd, strerror (errno));
		}
		else {
			lua_udp_push_data (cbd, udpbuf, r);
		}
	}
}

/***
 * @function rspamd_udp.sendto({params})
 * This function simply sends data to an external UDP service
 *
 * - `task`: rspamd task objects (implies `pool`, `session` and `ev_base` arguments)
 * - `ev_base`: event base (if no task specified)
 * - `session`: events session (no task, optional)
 * - `pool`: memory pool (if no task specified)
 * - `host`: IP or name of the peer (required)
 * - `port`: remote port to use (if `host` has no port part this is required)
 * - `data`: a table of strings or `rspamd_text` objects that contains data pieces
 * - `retransmits`: number of retransmits if needed
 * - `callback`: optional callback if reply should be read
 * @return {boolean} true if request has been sent (additional string if it has not)
 */
static gint
lua_udp_sendto (lua_State *L) {
	LUA_TRACE_POINT;
	const gchar *host;
	guint port;
	struct ev_loop *ev_base = NULL;
	struct lua_udp_cbdata *cbd;
	struct rspamd_async_session *session = NULL;
	struct rspamd_task *task = NULL;
	rspamd_inet_addr_t *addr;
	rspamd_mempool_t *pool = NULL;
	gdouble timeout = default_udp_timeout;

	if (lua_type (L, 1) == LUA_TTABLE) {
		lua_pushstring (L, "port");
		lua_gettable (L, -2);

		if (lua_type (L, -1) == LUA_TNUMBER) {
			port = lua_tointeger (L, -1);
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

			if (rspamd_parse_inet_address (&addr,
					host, strlen (host), RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
				if (port != 0) {
					rspamd_inet_address_set_port (addr, port);
				}
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

			if (port != 0) {
				rspamd_inet_address_set_port (addr, port);
			}
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
			ev_base = task->event_loop;
			session = task->s;
			pool = task->task_pool;
		}
		lua_pop (L, 1);

		if (task == NULL) {
			lua_pushstring (L, "ev_base");
			lua_gettable (L, -2);
			if (rspamd_lua_check_udata_maybe (L, -1, "rspamd{ev_base}")) {
				ev_base = *(struct ev_loop **) lua_touserdata (L, -1);
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

			lua_pushstring (L, "pool");
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
			timeout = lua_tonumber (L, -1);
		}
		lua_pop (L, 1);

		if (!ev_base || !pool) {
			rspamd_inet_address_free (addr);

			return luaL_error (L, "invalid arguments");
		}


		cbd = rspamd_mempool_alloc0 (pool, sizeof (*cbd));
		cbd->event_loop = ev_base;
		cbd->pool = pool;
		cbd->s = session;
		cbd->addr = addr;
		cbd->sock = rspamd_socket_create (rspamd_inet_address_get_af (addr),
				SOCK_DGRAM, 0, TRUE);
		cbd->cbref = -1;
		cbd->ev.timeout = timeout;

		if (cbd->sock == -1) {
			rspamd_inet_address_free (addr);

			return luaL_error (L, "cannot open socket: %s", strerror (errno));
		}

		cbd->L = L;

		gsize data_len;

		lua_pushstring (L, "data");
		lua_gettable (L, -2);

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

		lua_pushstring (L, "callback");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TFUNCTION) {
			cbd->cbref = luaL_ref (L, LUA_REGISTRYINDEX);
		}
		else {
			lua_pop (L, 1);
		}

		lua_pushstring (L, "retransmits");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TNUMBER) {
			cbd->retransmits = lua_tonumber (L, -1);
		}
		lua_pop (L, 1);

		enum rspamd_udp_send_result r;

		r = lua_try_send_request (cbd);
		if (r == RSPAMD_SENT_OK) {
			if (cbd->cbref == -1) {
				lua_udp_maybe_free (cbd);
			}
			else {
				if (!lua_udp_maybe_register_event (cbd)) {
					lua_pushboolean (L, false);
					lua_pushstring (L, "session error");
					lua_udp_maybe_free (cbd);

					return 2;
				}

				rspamd_ev_watcher_init (&cbd->ev, cbd->sock, EV_READ,
						lua_udp_io_handler, cbd);
				rspamd_ev_watcher_start (cbd->event_loop, &cbd->ev, timeout);
				cbd->sent = TRUE;
			}

			lua_pushboolean (L, true);
		}
		else if (r == RSPAMD_SENT_FAILURE) {
			lua_pushboolean (L, false);
			lua_pushstring (L, strerror (errno));
			lua_udp_maybe_free (cbd);

			return 2;
		}
		else {
			rspamd_ev_watcher_init (&cbd->ev, cbd->sock, EV_WRITE,
					lua_udp_io_handler, cbd);
			rspamd_ev_watcher_start (cbd->event_loop, &cbd->ev, timeout);

			if (!lua_udp_maybe_register_event (cbd)) {
				lua_pushboolean (L, false);
				lua_pushstring (L, "session error");
				lua_udp_maybe_free (cbd);

				return 2;
			}
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
