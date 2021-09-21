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
#include "libserver/ssl_util.h"
#include "utlist.h"
#include "unix-std.h"
#include <math.h>

static const gchar *M = "rspamd lua tcp";

/***
 * @module rspamd_tcp
 * Rspamd TCP module represents generic TCP asynchronous client available from LUA code.
 * This module hides all complexity: DNS resolving, sessions management, zero-copy
 * text transfers and so on under the hood. It can work in partial or complete modes:
 *
 * - partial mode is used when you need to call a continuation routine each time data is available for read
 * - complete mode calls for continuation merely when all data is read from socket (e.g. when a server sends reply and closes a connection)
 * @example
local logger = require "rspamd_logger"
local tcp = require "rspamd_tcp"

rspamd_config.SYM = function(task)

    local function cb(err, data)
        logger.infox('err: %1, data: %2', err, tostring(data))
    end

    tcp.request({
    	task = task,
    	host = "google.com",
    	port = 80,
    	data = {"GET / HTTP/1.0\r\n", "Host: google.com\r\n", "\r\n"},
    	callback = cb})
end

-- New TCP syntax test
rspamd_config:register_symbol({
  name = 'TCP_TEST',
  type = "normal",
  callback = function(task)
    local logger = require "rspamd_logger"
    local function rcpt_done_cb(err, data, conn)
      logger.errx(task, 'RCPT: got reply: %s, error: %s', data, err)
      conn:close()
    end
    local function rcpt_cb(err, conn)
      logger.errx(task, 'written rcpt, error: %s', err)
      conn:add_read(rcpt_done_cb, '\r\n')
    end
    local function from_done_cb(err, data, conn)
      logger.errx(task, 'FROM: got reply: %s, error: %s', data, err)
      conn:add_write(rcpt_cb, 'RCPT TO: <test@yandex.ru>\r\n')
    end
    local function from_cb(err, conn)
      logger.errx(task, 'written from, error: %s', err)
      conn:add_read(from_done_cb, '\r\n')
    end
    local function hello_done_cb(err, data, conn)
      logger.errx(task, 'HELO: got reply: %s, error: %s', data, err)
      conn:add_write(from_cb, 'MAIL FROM: <>\r\n')
    end
    local function hello_cb(err, conn)
      logger.errx(task, 'written hello, error: %s', err)
      conn:add_read(hello_done_cb, '\r\n')
    end
    local function init_cb(err, data, conn)
      logger.errx(task, 'got reply: %s, error: %s', data, err)
      conn:add_write(hello_cb, 'HELO example.com\r\n')
    end
    tcp.request{
      task = task,
      callback = init_cb,
      stop_pattern = '\r\n',
      host = 'mx.yandex.ru',
      port = 25
    }
  end,
  priority = 10,
})
 */

LUA_FUNCTION_DEF (tcp, request);

/***
 * @function rspamd_tcp.connect_sync()
 *
 * Creates pseudo-synchronous TCP connection.
 * Each method of the connection requiring IO, becames a yielding point,
 * i.e. current thread Lua thread is get suspended and resumes as soon as IO is done
 *
 * This class represents low-level API, using of "lua_tcp_sync" module is recommended.
 *
 * @example

local rspamd_tcp = require "rspamd_tcp"
local logger = require "rspamd_logger"

local function http_simple_tcp_symbol(task)

    local err
    local is_ok, connection = rspamd_tcp.connect_sync {
      task = task,
      host = '127.0.0.1',
      timeout = 20,
      port = 18080,
      ssl = false, -- If SSL connection is needed
      ssl_verify = true, -- set to false if verify is not needed
    }

    is_ok, err = connection:write('GET /request_sync HTTP/1.1\r\nConnection: keep-alive\r\n\r\n')

    logger.errx(task, 'write %1, %2', is_ok, err)
    if not is_ok then
      logger.errx(task, 'write error: %1', err)
    end

    local data
    is_ok, data = connection:read_once();

    logger.errx(task, 'read_once: is_ok: %1, data: %2', is_ok, data)

    is_ok, err = connection:write("POST /request2 HTTP/1.1\r\n\r\n")
    logger.errx(task, 'write[2] %1, %2', is_ok, err)

    is_ok, data = connection:read_once();
    logger.errx(task, 'read_once[2]: is_ok %1, data: %2', is_ok, data)

    connection:close()
end

rspamd_config:register_symbol({
  name = 'SIMPLE_TCP_TEST',
  score = 1.0,
  callback = http_simple_tcp_symbol,
  no_squeeze = true
})
 *
 */
LUA_FUNCTION_DEF (tcp, connect_sync);

/***
 * @method tcp:close()
 *
 * Closes TCP connection
 */
LUA_FUNCTION_DEF (tcp, close);

/***
 * @method tcp:add_read(callback, [pattern])
 *
 * Adds new read event to the tcp connection
 * @param {function} callback to be called when data is read
 * @param {string} pattern optional stop pattern
 */
LUA_FUNCTION_DEF (tcp, add_read);

/***
 * @method tcp:add_write(callback, data)
 *
 * Adds new write event to the tcp connection
 * @param {function} optional callback to be called when data is completely written
 * @param {table/string/text} data to send to a remote server
 */
LUA_FUNCTION_DEF (tcp, add_write);

/***
 * @method tcp:shift_callback()
 *
 * Shifts the current callback and go to the next one (if any)
 */
LUA_FUNCTION_DEF (tcp, shift_callback);

/***
 * @method tcp:starttls([no_verify])
 *
 * Starts tls connection
 * @param {boolean} no_verify used to skip ssl verification
 */
LUA_FUNCTION_DEF (tcp, starttls);

static const struct luaL_reg tcp_libf[] = {
	LUA_INTERFACE_DEF (tcp, request),
	{"new", lua_tcp_request},
	{"connect", lua_tcp_request},
	{"connect_sync", lua_tcp_connect_sync},
	{NULL, NULL}
};

static const struct luaL_reg tcp_libm[] = {
	LUA_INTERFACE_DEF (tcp, close),
	LUA_INTERFACE_DEF (tcp, add_read),
	LUA_INTERFACE_DEF (tcp, add_write),
	LUA_INTERFACE_DEF (tcp, shift_callback),
	LUA_INTERFACE_DEF (tcp, starttls),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

/***
 * @method tcp:close()
 *
 * Closes TCP connection
 */
LUA_FUNCTION_DEF (tcp_sync, close);

/***
 * @method read_once()
 *
 * Performs one read operation. If syscall returned with EAGAIN/EINT,
 * restarts the operation, so it always returns either data or error.
 */
LUA_FUNCTION_DEF (tcp_sync, read_once);

/***
 * @method eof()
 *
 * True if last IO operation ended with EOF, i.e. endpoint closed connection
 */
LUA_FUNCTION_DEF (tcp_sync, eof);

/***
 * @method shutdown()
 *
 * Half-shutdown TCP connection
 */
LUA_FUNCTION_DEF (tcp_sync, shutdown);

/***
 * @method write()
 *
 * Writes data into the stream. If syscall returned with EAGAIN/EINT
 * restarts the operation. If performs write() until all the passed
 * data is written completely.
 */
LUA_FUNCTION_DEF (tcp_sync, write);

LUA_FUNCTION_DEF (tcp_sync, gc);

static void lua_tcp_sync_session_dtor (gpointer ud);

static const struct luaL_reg tcp_sync_libm[] = {
	LUA_INTERFACE_DEF (tcp_sync, close),
	LUA_INTERFACE_DEF (tcp_sync, read_once),
	LUA_INTERFACE_DEF (tcp_sync, write),
	LUA_INTERFACE_DEF (tcp_sync, eof),
	LUA_INTERFACE_DEF (tcp_sync, shutdown),
	{"__gc",       lua_tcp_sync_gc},
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

struct lua_tcp_read_handler {
	gchar *stop_pattern;
	guint plen;
	gint cbref;
};

struct lua_tcp_write_handler {
	struct iovec *iov;
	guint iovlen;
	gint cbref;
	gsize pos;
	gsize total_bytes;
};

enum lua_tcp_handler_type {
	LUA_WANT_WRITE = 0,
	LUA_WANT_READ,
	LUA_WANT_CONNECT
};

struct lua_tcp_handler {
	union {
		struct lua_tcp_read_handler r;
		struct lua_tcp_write_handler w;
	} h;
	enum lua_tcp_handler_type type;
};

struct lua_tcp_dtor {
	rspamd_mempool_destruct_t dtor;
	void *data;
	struct lua_tcp_dtor *next;
};

#define LUA_TCP_FLAG_PARTIAL (1u << 0u)
#define LUA_TCP_FLAG_SHUTDOWN (1u << 2u)
#define LUA_TCP_FLAG_CONNECTED (1u << 3u)
#define LUA_TCP_FLAG_FINISHED (1u << 4u)
#define LUA_TCP_FLAG_SYNC (1u << 5u)
#define LUA_TCP_FLAG_RESOLVED (1u << 6u)
#define LUA_TCP_FLAG_SSL (1u << 7u)
#define LUA_TCP_FLAG_SSL_NOVERIFY (1u << 8u)

#undef TCP_DEBUG_REFS
#ifdef TCP_DEBUG_REFS
#define TCP_RETAIN(x) do { \
	msg_info ("retain ref %p, refcount: %d", (x), (x)->ref.refcount); \
	REF_RETAIN(x);	\
} while (0)

#define TCP_RELEASE(x) do { \
	msg_info ("release ref %p, refcount: %d", (x), (x)->ref.refcount); \
	REF_RELEASE(x);	\
} while (0)
#else
#define TCP_RETAIN(x)  REF_RETAIN(x)
#define TCP_RELEASE(x) REF_RELEASE(x)
#endif

struct lua_tcp_cbdata {
	struct rspamd_async_session *session;
	struct rspamd_async_event *async_ev;
	struct ev_loop *event_loop;
	rspamd_inet_addr_t *addr;
	GByteArray *in;
	GQueue *handlers;
	gint fd;
	gint connect_cb;
	guint port;
	guint flags;
	gchar tag[7];
	struct rspamd_io_ev ev;
	struct lua_tcp_dtor *dtors;
	ref_entry_t ref;
	struct rspamd_task *task;
	struct rspamd_symcache_item *item;
	struct thread_entry *thread;
	struct rspamd_config *cfg;
	struct rspamd_ssl_connection *ssl_conn;
	gchar *hostname;
	gboolean eof;
};

#define IS_SYNC(c) (((c)->flags & LUA_TCP_FLAG_SYNC) != 0)

#define msg_debug_tcp(...)  rspamd_conditional_debug_fast (NULL, cbd->addr, \
        rspamd_lua_tcp_log_id, "lua_tcp", cbd->tag, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(lua_tcp)

static void lua_tcp_handler (int fd, short what, gpointer ud);
static void lua_tcp_plan_handler_event (struct lua_tcp_cbdata *cbd,
		gboolean can_read, gboolean can_write);
static void lua_tcp_unregister_event (struct lua_tcp_cbdata *cbd);

static void
lua_tcp_void_finalyser (gpointer arg) {}

static const gdouble default_tcp_timeout = 5.0;

static struct rspamd_dns_resolver *
lua_tcp_global_resolver (struct ev_loop *ev_base,
		struct rspamd_config *cfg)
{
	static struct rspamd_dns_resolver *global_resolver;

	if (cfg && cfg->dns_resolver) {
		return cfg->dns_resolver;
	}

	if (global_resolver == NULL) {
		global_resolver = rspamd_dns_resolver_init (NULL, ev_base, cfg);
	}

	return global_resolver;
}

static gboolean
lua_tcp_shift_handler (struct lua_tcp_cbdata *cbd)
{
	struct lua_tcp_handler *hdl;

	hdl = g_queue_pop_head (cbd->handlers);

	if (hdl == NULL) {
		/* We are done */
		return FALSE;
	}

	if (hdl->type == LUA_WANT_READ) {
		msg_debug_tcp ("switch from read handler %d", hdl->h.r.cbref);
		if (hdl->h.r.cbref && hdl->h.r.cbref != -1) {
			luaL_unref (cbd->cfg->lua_state, LUA_REGISTRYINDEX, hdl->h.r.cbref);
		}

		if (hdl->h.r.stop_pattern) {
			g_free (hdl->h.r.stop_pattern);
		}
	}
	else if (hdl->type == LUA_WANT_WRITE) {
		msg_debug_tcp ("switch from write handler %d", hdl->h.r.cbref);
		if (hdl->h.w.cbref && hdl->h.w.cbref != -1) {
			luaL_unref (cbd->cfg->lua_state, LUA_REGISTRYINDEX, hdl->h.w.cbref);
		}

		if (hdl->h.w.iov) {
			g_free (hdl->h.w.iov);
		}
	}
	else {
		msg_debug_tcp ("removing connect handler");
		/* LUA_WANT_CONNECT: it doesn't allocate anything, nothing to do here */
	}

	g_free (hdl);

	return TRUE;
}

static void
lua_tcp_fin (gpointer arg)
{
	struct lua_tcp_cbdata *cbd = (struct lua_tcp_cbdata *)arg;
	struct lua_tcp_dtor *dtor, *dttmp;

	if (IS_SYNC (cbd) && cbd->task) {
		/*
		pointer is now becoming invalid, we should remove registered destructor,
		all the necessary steps are done here
		*/
		rspamd_mempool_replace_destructor (cbd->task->task_pool,
				lua_tcp_sync_session_dtor, cbd, NULL);
	}

	msg_debug_tcp ("finishing TCP %s connection", IS_SYNC (cbd) ? "sync" : "async");

	if (cbd->connect_cb != -1) {
		luaL_unref (cbd->cfg->lua_state, LUA_REGISTRYINDEX, cbd->connect_cb);
	}

	if (cbd->ssl_conn) {
		/* TODO: postpone close in case ssl is used ! */
		rspamd_ssl_connection_free (cbd->ssl_conn);
	}

	if (cbd->fd != -1) {
		rspamd_ev_watcher_stop (cbd->event_loop, &cbd->ev);
		close (cbd->fd);
		cbd->fd = -1;
	}

	if (cbd->addr) {
		rspamd_inet_address_free (cbd->addr);
	}

	while (lua_tcp_shift_handler (cbd)) {}
	g_queue_free (cbd->handlers);

	LL_FOREACH_SAFE (cbd->dtors, dtor, dttmp) {
		dtor->dtor (dtor->data);
		g_free (dtor);
	}

	g_byte_array_unref (cbd->in);
	g_free (cbd->hostname);
	g_free (cbd);
}

static struct lua_tcp_cbdata *
lua_check_tcp (lua_State *L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{tcp}");
	luaL_argcheck (L, ud != NULL, pos, "'tcp' expected");
	return ud ? *((struct lua_tcp_cbdata **)ud) : NULL;
}

static void
lua_tcp_maybe_free (struct lua_tcp_cbdata *cbd)
{
	if (IS_SYNC (cbd)) {
		/*
		 * in this mode, we don't remove object, we only remove the event
		 * Object is owned by lua and will be destroyed on __gc()
		 */

		if (cbd->item) {
			rspamd_symcache_item_async_dec_check (cbd->task, cbd->item, M);
			cbd->item = NULL;
		}

		if (cbd->async_ev) {
			rspamd_session_remove_event (cbd->session, lua_tcp_void_finalyser, cbd);
		}

		cbd->async_ev = NULL;
	}
	else {
		if (cbd->item) {
			rspamd_symcache_item_async_dec_check (cbd->task, cbd->item, M);
			cbd->item = NULL;
		}

		if (cbd->async_ev) {
			rspamd_session_remove_event (cbd->session, lua_tcp_fin, cbd);
		}
		else {
			lua_tcp_fin (cbd);
		}
	}
}

#ifdef __GNUC__
static void
lua_tcp_push_error (struct lua_tcp_cbdata *cbd, gboolean is_fatal,
		const char *err, ...) __attribute__ ((format(printf, 3, 4)));
#endif

static void lua_tcp_resume_thread_error_argp (struct lua_tcp_cbdata *cbd, const gchar *error, va_list argp);

static void
lua_tcp_push_error (struct lua_tcp_cbdata *cbd, gboolean is_fatal,
		const char *err, ...)
{
	va_list ap, ap_copy;
	struct lua_tcp_cbdata **pcbd;
	struct lua_tcp_handler *hdl;
	gint cbref, top;
	struct lua_callback_state cbs;
	lua_State *L;
	gboolean callback_called = FALSE;

	if (cbd->thread) {
		va_start (ap, err);
		lua_tcp_resume_thread_error_argp (cbd, err, ap);
		va_end (ap);

		return;
	}

	lua_thread_pool_prepare_callback (cbd->cfg->lua_thread_pool, &cbs);
	L = cbs.L;

	va_start (ap, err);

	for (;;) {
		hdl = g_queue_peek_head (cbd->handlers);

		if (hdl == NULL) {
			break;
		}

		if (hdl->type == LUA_WANT_READ) {
			cbref = hdl->h.r.cbref;
		}
		else {
			cbref = hdl->h.w.cbref;
		}

		if (cbref != -1) {
			top = lua_gettop (L);
			lua_rawgeti (L, LUA_REGISTRYINDEX, cbref);

			/* Error message */
			va_copy (ap_copy, ap);
			lua_pushvfstring (L, err, ap_copy);
			va_end (ap_copy);

			/* Body */
			lua_pushnil (L);
			/* Connection */
			pcbd = lua_newuserdata (L, sizeof (*pcbd));
			*pcbd = cbd;
			rspamd_lua_setclass (L, "rspamd{tcp}", -1);
			TCP_RETAIN (cbd);

			if (cbd->item) {
				rspamd_symcache_set_cur_item (cbd->task, cbd->item);
			}

			if (lua_pcall (L, 3, 0, 0) != 0) {
				msg_info ("callback call failed: %s", lua_tostring (L, -1));
			}

			lua_settop (L, top);

			TCP_RELEASE (cbd);

			callback_called = TRUE;
		}

		if (!is_fatal) {
			if (callback_called) {
				/* Stop on the first callback found */
				break;
			}
			else {
				/* Shift to another callback to inform about non fatal error */
				msg_debug_tcp ("non fatal error find matching callback");
				lua_tcp_shift_handler (cbd);
				continue;
			}
		}
		else {
			msg_debug_tcp ("fatal error rollback all handlers");
			lua_tcp_shift_handler (cbd);
		}
	}

	va_end (ap);

	lua_thread_pool_restore_callback (&cbs);
}

static void lua_tcp_resume_thread (struct lua_tcp_cbdata *cbd, const guint8 *str, gsize len);

static void
lua_tcp_push_data (struct lua_tcp_cbdata *cbd, const guint8 *str, gsize len)
{
	struct rspamd_lua_text *t;
	struct lua_tcp_cbdata **pcbd;
	struct lua_tcp_handler *hdl;
	gint cbref, arg_cnt, top;
	struct lua_callback_state cbs;
	lua_State *L;

	if (cbd->thread) {
		lua_tcp_resume_thread (cbd, str, len);
		return;
	}

	lua_thread_pool_prepare_callback (cbd->cfg->lua_thread_pool, &cbs);
	L = cbs.L;

	hdl = g_queue_peek_head (cbd->handlers);

	g_assert (hdl != NULL);

	if (hdl->type == LUA_WANT_READ) {
		cbref = hdl->h.r.cbref;
	}
	else {
		cbref = hdl->h.w.cbref;
	}

	if (cbref != -1) {
		top = lua_gettop (L);
		lua_rawgeti (L, LUA_REGISTRYINDEX, cbref);
		/* Error */
		lua_pushnil (L);
		/* Body */

		if (hdl->type == LUA_WANT_READ) {
			t = lua_newuserdata (L, sizeof (*t));
			rspamd_lua_setclass (L, "rspamd{text}", -1);
			t->start = (const gchar *)str;
			t->len = len;
			t->flags = 0;
			arg_cnt = 3;
		}
		else {
			arg_cnt = 2;
		}
		/* Connection */
		pcbd = lua_newuserdata (L, sizeof (*pcbd));
		*pcbd = cbd;
		rspamd_lua_setclass (L, "rspamd{tcp}", -1);

		TCP_RETAIN (cbd);

		if (cbd->item) {
			rspamd_symcache_set_cur_item (cbd->task, cbd->item);
		}

		if (lua_pcall (L, arg_cnt, 0, 0) != 0) {
			msg_info ("callback call failed: %s", lua_tostring (L, -1));
		}

		lua_settop (L, top);
		TCP_RELEASE (cbd);
	}

	lua_thread_pool_restore_callback (&cbs);
}

static void
lua_tcp_resume_thread_error_argp (struct lua_tcp_cbdata *cbd, const gchar *error, va_list argp)
{
	struct thread_entry *thread = cbd->thread;
	lua_State *L = thread->lua_state;

	lua_pushboolean (L, FALSE);
	lua_pushvfstring (L, error, argp);

	lua_tcp_shift_handler (cbd);
	// lua_tcp_unregister_event (cbd);
	lua_thread_pool_set_running_entry (cbd->cfg->lua_thread_pool, cbd->thread);
	lua_thread_resume (thread, 2);
	TCP_RELEASE (cbd);
}

static void
lua_tcp_resume_thread (struct lua_tcp_cbdata *cbd, const guint8 *str, gsize len)
{
	/*
	 * typical call returns:
	 *
	 * read:
	 *  error:
	 *    (nil, error message)
	 *  got data:
	 *    (true, data)
	 * write/connect:
	 *   error:
	 *     (nil, error message)
	 *   wrote
	 *     (true)
	 */

	lua_State *L = cbd->thread->lua_state;
	struct lua_tcp_handler *hdl;

	hdl = g_queue_peek_head (cbd->handlers);

	lua_pushboolean (L, TRUE);
	if (hdl->type == LUA_WANT_READ) {
		lua_pushlstring (L, str, len);
	}
	else {
		lua_pushnil (L);
	}

	lua_tcp_shift_handler (cbd);
	lua_thread_pool_set_running_entry (cbd->cfg->lua_thread_pool,
			cbd->thread);

	if (cbd->item) {
		rspamd_symcache_set_cur_item (cbd->task, cbd->item);
	}

	lua_thread_resume (cbd->thread, 2);

	TCP_RELEASE (cbd);
}

static void
lua_tcp_plan_read (struct lua_tcp_cbdata *cbd)
{
	rspamd_ev_watcher_reschedule (cbd->event_loop, &cbd->ev, EV_READ);
}

static void
lua_tcp_connect_helper (struct lua_tcp_cbdata *cbd)
{
	/* This is used for sync mode only */
	lua_State *L = cbd->thread->lua_state;

	struct lua_tcp_cbdata **pcbd;

	lua_pushboolean (L, TRUE);

	lua_thread_pool_set_running_entry (cbd->cfg->lua_thread_pool, cbd->thread);
	pcbd = lua_newuserdata (L, sizeof (*pcbd));
	*pcbd = cbd;
	rspamd_lua_setclass (L, "rspamd{tcp_sync}", -1);
	msg_debug_tcp ("tcp connected");

	lua_tcp_shift_handler (cbd);

	// lua_tcp_unregister_event (cbd);
	lua_thread_resume (cbd->thread, 2);
	TCP_RELEASE (cbd);
}

static void
lua_tcp_write_helper (struct lua_tcp_cbdata *cbd)
{
	struct iovec *start;
	guint niov, i;
	gint flags = 0;
	bool allocated_iov = false;
	gsize remain;
	gssize r;
	struct iovec *cur_iov;
	struct lua_tcp_handler *hdl;
	struct lua_tcp_write_handler *wh;
	struct msghdr msg;

	hdl = g_queue_peek_head (cbd->handlers);

	g_assert (hdl != NULL && hdl->type == LUA_WANT_WRITE);
	wh = &hdl->h.w;

	if (wh->pos == wh->total_bytes) {
		goto call_finish_handler;
	}

	start = &wh->iov[0];
	niov = wh->iovlen;
	remain = wh->pos;
	/* We know that niov is small enough for that */

	if (niov < 1024) {
		cur_iov = g_alloca (niov * sizeof (struct iovec));
	}
	else {
		cur_iov = g_malloc0 (niov * sizeof (struct iovec));
		allocated_iov = true;
	}

	memcpy (cur_iov, wh->iov, niov * sizeof (struct iovec));

	for (i = 0; i < wh->iovlen && remain > 0; i++) {
		/* Find out the first iov required */
		start = &cur_iov[i];
		if (start->iov_len <= remain) {
			remain -= start->iov_len;
			start = &cur_iov[i + 1];
			niov--;
		}
		else {
			start->iov_base = (void *)((char *)start->iov_base + remain);
			start->iov_len -= remain;
			remain = 0;
		}
	}

	memset (&msg, 0, sizeof (msg));
	msg.msg_iov = start;
	msg.msg_iovlen = MIN (IOV_MAX, niov);
	g_assert (niov > 0);
#ifdef MSG_NOSIGNAL
	flags = MSG_NOSIGNAL;
#endif

	msg_debug_tcp ("want write %d io vectors of %d", (int)msg.msg_iovlen,
			(int)niov);

	if (cbd->ssl_conn) {
		r = rspamd_ssl_writev (cbd->ssl_conn, msg.msg_iov, msg.msg_iovlen);
	}
	else {
		r = sendmsg (cbd->fd, &msg, flags);
	}

	if (allocated_iov) {
		g_free (cur_iov);
	}

	if (r == -1) {
		if (!(cbd->ssl_conn)) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				msg_debug_tcp ("got temporary failure, retry write");
				lua_tcp_plan_handler_event (cbd, TRUE, TRUE);
				return;
			}
			else {
				lua_tcp_push_error (cbd, TRUE,
						"IO write error while trying to write %d bytes: %s",
						(gint) remain, strerror (errno));

				msg_debug_tcp ("write error, terminate connection");
				TCP_RELEASE (cbd);
			}
		}

		return;
	}
	else {
		wh->pos += r;
	}

	msg_debug_tcp ("written %z bytes: %z/%z", r,
			wh->pos, wh->total_bytes);

	if (wh->pos >= wh->total_bytes) {
		goto call_finish_handler;
	}
	else {
		/* Want to write more */
		if (r > 0) {
			/* XXX: special case: we know that we want to write more data
			 * than it is available in iov function.
			 *
			 * Hence, we need to check if we can write more at some point...
			 */
			lua_tcp_write_helper (cbd);
		}
	}

	return;

call_finish_handler:

	msg_debug_tcp ("finishing TCP write, calling TCP handler");

	if ((cbd->flags & LUA_TCP_FLAG_SHUTDOWN)) {
		/* Half close the connection */
		shutdown (cbd->fd, SHUT_WR);
		cbd->flags &= ~LUA_TCP_FLAG_SHUTDOWN;
	}

	lua_tcp_push_data (cbd, NULL, 0);
	if (!IS_SYNC (cbd)) {
		lua_tcp_shift_handler (cbd);
		lua_tcp_plan_handler_event (cbd, TRUE, TRUE);
	}
}

static gboolean
lua_tcp_process_read_handler (struct lua_tcp_cbdata *cbd,
		struct lua_tcp_read_handler *rh, gboolean eof)
{
	guint slen;
	goffset pos;

	if (rh->stop_pattern) {
		slen = rh->plen;

		if (cbd->in->len >= slen) {
			if ((pos = rspamd_substring_search (cbd->in->data, cbd->in->len,
					rh->stop_pattern, slen)) != -1) {
				msg_debug_tcp ("found TCP stop pattern");
				lua_tcp_push_data (cbd, cbd->in->data, pos);

				if (!IS_SYNC (cbd)) {
					lua_tcp_shift_handler (cbd);
				}
				if (pos + slen < cbd->in->len) {
					/* We have a leftover */
					memmove (cbd->in->data, cbd->in->data + pos + slen,
							cbd->in->len - (pos + slen));
					cbd->in->len = cbd->in->len - (pos + slen);
				}
				else {
					cbd->in->len = 0;
				}

				return TRUE;
			}
			else {
				/* Plan new read */
				msg_debug_tcp ("NOT found TCP stop pattern");

				if (!cbd->eof) {
					lua_tcp_plan_read (cbd);
				}
				else {
					/* Got session finished but no stop pattern */
					lua_tcp_push_error (cbd, TRUE,
							"IO read error: connection terminated");
				}
			}
		}
	}
	else {
		msg_debug_tcp ("read TCP partial data %d bytes", cbd->in->len);
		slen = cbd->in->len;

		/* we have eaten all the data, handler should not know that there is something */
		cbd->in->len = 0;
		lua_tcp_push_data (cbd, cbd->in->data, slen);
		if (!IS_SYNC (cbd)) {
			lua_tcp_shift_handler (cbd);
		}

		return TRUE;
	}

	return FALSE;
}

static void
lua_tcp_process_read (struct lua_tcp_cbdata *cbd,
		guchar *in, gssize r)
{
	struct lua_tcp_handler *hdl;
	struct lua_tcp_read_handler *rh;

	hdl = g_queue_peek_head (cbd->handlers);

	g_assert (hdl != NULL && hdl->type == LUA_WANT_READ);
	rh = &hdl->h.r;

	if (r > 0) {
		if (cbd->flags & LUA_TCP_FLAG_PARTIAL) {
			lua_tcp_push_data (cbd, in, r);
			/* Plan next event */
			lua_tcp_plan_read (cbd);
		}
		else {
			g_byte_array_append (cbd->in, in, r);

			if (!lua_tcp_process_read_handler (cbd, rh, FALSE)) {
				/* Plan more read */
				lua_tcp_plan_read (cbd);
			}
			else {
				/* Go towards the next handler */
				if (!IS_SYNC (cbd)) {
					lua_tcp_plan_handler_event (cbd, TRUE, TRUE);
				}
			}
		}
	}
	else if (r == 0) {
		/* EOF */
		cbd->eof = TRUE;
		if (cbd->in->len > 0) {
			/* We have some data to process */
			lua_tcp_process_read_handler (cbd, rh, TRUE);
		}
		else {
			lua_tcp_push_error (cbd, TRUE, "IO read error: connection terminated");
		}

		lua_tcp_plan_handler_event (cbd, FALSE, FALSE);
	}
	else {
		/* An error occurred */
		if (errno == EAGAIN || errno == EINTR) {
			/* Restart call */
			lua_tcp_plan_read (cbd);

			return;
		}

		/* Fatal error */
		cbd->eof = TRUE;
		if (cbd->in->len > 0) {
			/* We have some data to process */
			lua_tcp_process_read_handler (cbd, rh, TRUE);
		}
		else {
			lua_tcp_push_error (cbd, TRUE,
					"IO read error while trying to read data: %s",
					strerror (errno));
		}

		lua_tcp_plan_handler_event (cbd, FALSE, FALSE);
	}
}

static void
lua_tcp_handler (int fd, short what, gpointer ud)
{
	struct lua_tcp_cbdata *cbd = ud;
	guchar inbuf[8192];
	gssize r;
	gint so_error = 0;
	socklen_t so_len = sizeof (so_error);
	struct lua_callback_state cbs;
	lua_State *L;
	enum lua_tcp_handler_type event_type;
	TCP_RETAIN (cbd);

	msg_debug_tcp ("processed TCP event: %d", what);

	struct lua_tcp_handler *rh = g_queue_peek_head (cbd->handlers);
	event_type = rh->type;

	rspamd_ev_watcher_stop (cbd->event_loop, &cbd->ev);

	if (what == EV_READ) {
		if (cbd->ssl_conn) {
			r = rspamd_ssl_read (cbd->ssl_conn, inbuf, sizeof (inbuf));
		}
		else {
			r = read (cbd->fd, inbuf, sizeof (inbuf));
		}

		lua_tcp_process_read (cbd, inbuf, r);
	}
	else if (what == EV_WRITE) {

		if (!(cbd->flags & LUA_TCP_FLAG_CONNECTED)) {
			if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &so_error, &so_len) == -1) {
				lua_tcp_push_error (cbd, TRUE, "Cannot get socket error: %s",
						strerror (errno));
				TCP_RELEASE (cbd);
				goto out;
			}
			else if (so_error != 0) {
				lua_tcp_push_error (cbd, TRUE, "Socket error detected: %s",
						strerror (so_error));
				TCP_RELEASE (cbd);
				goto out;
			}
			else {
				cbd->flags |= LUA_TCP_FLAG_CONNECTED;

				if (cbd->connect_cb != -1) {
					struct lua_tcp_cbdata **pcbd;
					gint top;

					lua_thread_pool_prepare_callback (cbd->cfg->lua_thread_pool, &cbs);
					L = cbs.L;

					top = lua_gettop (L);
					lua_rawgeti (L, LUA_REGISTRYINDEX, cbd->connect_cb);
					pcbd = lua_newuserdata (L, sizeof (*pcbd));
					*pcbd = cbd;
					TCP_RETAIN (cbd);
					rspamd_lua_setclass (L, "rspamd{tcp}", -1);

					if (cbd->item) {
						rspamd_symcache_set_cur_item (cbd->task, cbd->item);
					}

					if (lua_pcall (L, 1, 0, 0) != 0) {
						msg_info ("callback call failed: %s", lua_tostring (L, -1));
					}

					lua_settop (L, top);
					TCP_RELEASE (cbd);
					lua_thread_pool_restore_callback (&cbs);
				}
			}
		}

		if (event_type == LUA_WANT_WRITE) {
			lua_tcp_write_helper (cbd);
		}
		else if (event_type == LUA_WANT_CONNECT) {
			lua_tcp_connect_helper (cbd);
		}
		else {
			g_assert_not_reached ();
		}
	}
	else {
		lua_tcp_push_error (cbd, TRUE, "IO timeout");
		TCP_RELEASE (cbd);
	}

out:
	TCP_RELEASE (cbd);
}

static void
lua_tcp_plan_handler_event (struct lua_tcp_cbdata *cbd, gboolean can_read,
		gboolean can_write)
{
	struct lua_tcp_handler *hdl;

	hdl = g_queue_peek_head (cbd->handlers);

	if (hdl == NULL) {
		if (!(cbd->flags & LUA_TCP_FLAG_FINISHED)) {
			/* We are finished with a connection */
			msg_debug_tcp ("no handlers left, finish session");
			TCP_RELEASE (cbd);
			cbd->flags |= LUA_TCP_FLAG_FINISHED;
		}
	}
	else {
		if (hdl->type == LUA_WANT_READ) {

			/* We need to check if we have some leftover in the buffer */
			if (cbd->in->len > 0) {
				msg_debug_tcp ("process read buffer leftover");
				if (lua_tcp_process_read_handler (cbd, &hdl->h.r, FALSE)) {
					if (!IS_SYNC(cbd)) {
						/* We can go to the next handler */
						lua_tcp_plan_handler_event (cbd, can_read, can_write);
					}
				}
			}
			else {
				if (can_read) {
					/* We need to plan a new event */
					msg_debug_tcp ("plan new read");
					rspamd_ev_watcher_reschedule (cbd->event_loop, &cbd->ev,
							EV_READ);
				}
				else {
					/* Cannot read more */
					msg_debug_tcp ("cannot read more");
					lua_tcp_push_error (cbd, FALSE, "EOF, cannot read more data");
					if (!IS_SYNC (cbd)) {
						lua_tcp_shift_handler (cbd);
						lua_tcp_plan_handler_event (cbd, can_read, can_write);
					}
				}
			}
		}
		else if (hdl->type == LUA_WANT_WRITE) {
			/*
			 * We need to plan write event if there is something in the
			 * write request
			 */

			if (hdl->h.w.pos < hdl->h.w.total_bytes) {
				msg_debug_tcp ("plan new write");
				if (can_write) {
					rspamd_ev_watcher_reschedule (cbd->event_loop, &cbd->ev,
							EV_WRITE);
				}
				else {
					/* Cannot write more */
					lua_tcp_push_error (cbd, FALSE, "EOF, cannot write more data");
					if (!IS_SYNC(cbd)) {
						lua_tcp_shift_handler (cbd);
						lua_tcp_plan_handler_event (cbd, can_read, can_write);
					}
				}
			}
			else {
				/* We shouldn't have empty write handlers */
				g_assert_not_reached ();
			}
		}
		else { /* LUA_WANT_CONNECT */
			msg_debug_tcp ("plan new connect");
			rspamd_ev_watcher_reschedule (cbd->event_loop, &cbd->ev,
					EV_WRITE);
		}
	}
}

static gboolean
lua_tcp_register_event (struct lua_tcp_cbdata *cbd)
{
	if (cbd->session) {
		event_finalizer_t fin = IS_SYNC (cbd) ? lua_tcp_void_finalyser : lua_tcp_fin;

		cbd->async_ev = rspamd_session_add_event (cbd->session, fin, cbd, M);

		if (!cbd->async_ev) {
			return FALSE;
		}
	}

	return TRUE;
}

static void
lua_tcp_register_watcher (struct lua_tcp_cbdata *cbd)
{
	if (cbd->item && cbd->task) {
		rspamd_symcache_item_async_inc (cbd->task, cbd->item, M);
	}
}

static void
lua_tcp_ssl_on_error (gpointer ud, GError *err)
{
	struct lua_tcp_cbdata *cbd = (struct lua_tcp_cbdata *)ud;

	if (err) {
		lua_tcp_push_error (cbd, TRUE, "ssl error: %s", err->message);
	}
	else {
		lua_tcp_push_error (cbd, TRUE, "ssl error: unknown error");
	}

	TCP_RELEASE (cbd);
}

static gboolean
lua_tcp_make_connection (struct lua_tcp_cbdata *cbd)
{
	int fd;

	rspamd_inet_address_set_port (cbd->addr, cbd->port);
	fd = rspamd_inet_address_connect (cbd->addr, SOCK_STREAM, TRUE);

	if (fd == -1) {
		if (cbd->session) {
			rspamd_mempool_t *pool = rspamd_session_mempool (cbd->session);
			msg_info_pool ("cannot connect to %s (%s): %s",
					rspamd_inet_address_to_string (cbd->addr),
					cbd->hostname,
					strerror (errno));
		}
		else {
			msg_info ("cannot connect to %s (%s): %s",
					rspamd_inet_address_to_string (cbd->addr),
					cbd->hostname,
					strerror (errno));
		}

		return FALSE;
	}

	cbd->fd = fd;

#if 0
	if (!(cbd->flags & LUA_TCP_FLAG_RESOLVED)) {
		/* We come here without resolving, so we need to add a watcher */
		lua_tcp_register_watcher (cbd);
	}
	else {
		cbd->flags |= LUA_TCP_FLAG_RESOLVED;
	}
#endif

	if (cbd->flags & LUA_TCP_FLAG_SSL) {
		gpointer ssl_ctx;
		gboolean verify_peer;

		if (cbd->flags & LUA_TCP_FLAG_SSL_NOVERIFY) {
			ssl_ctx = cbd->cfg->libs_ctx->ssl_ctx_noverify;
			verify_peer = FALSE;
		}
		else {
			ssl_ctx = cbd->cfg->libs_ctx->ssl_ctx;
			verify_peer = TRUE;
		}

		cbd->ssl_conn = rspamd_ssl_connection_new (ssl_ctx,
				cbd->event_loop,
				verify_peer,
				cbd->tag);

		if (!rspamd_ssl_connect_fd (cbd->ssl_conn, fd, cbd->hostname, &cbd->ev,
				cbd->ev.timeout, lua_tcp_handler, lua_tcp_ssl_on_error, cbd)) {
			lua_tcp_push_error (cbd, TRUE, "ssl connection failed: %s",
					strerror (errno));

			return FALSE;
		}
		else {
			lua_tcp_register_event (cbd);
		}
	}
	else {
		rspamd_ev_watcher_init (&cbd->ev, cbd->fd, EV_WRITE,
				lua_tcp_handler, cbd);
		lua_tcp_register_event (cbd);
		lua_tcp_plan_handler_event (cbd, TRUE, TRUE);
	}


	return TRUE;
}

static void
lua_tcp_dns_handler (struct rdns_reply *reply, gpointer ud)
{
	struct lua_tcp_cbdata *cbd = (struct lua_tcp_cbdata *)ud;
	const struct rdns_request_name *rn;

	if (reply->code != RDNS_RC_NOERROR) {
		rn = rdns_request_get_name (reply->request, NULL);
		lua_tcp_push_error (cbd, TRUE, "unable to resolve host: %s",
				rn->name);
		TCP_RELEASE (cbd);
	}
	else {
		/*
		 * We set this flag as it means that we have already registered the watcher
		 * when started DNS query
		 */
		cbd->flags |= LUA_TCP_FLAG_RESOLVED;

		if (reply->entries->type == RDNS_REQUEST_A) {
			cbd->addr = rspamd_inet_address_new (AF_INET,
					&reply->entries->content.a.addr);
		}
		else if (reply->entries->type == RDNS_REQUEST_AAAA) {
			cbd->addr = rspamd_inet_address_new (AF_INET6,
					&reply->entries->content.aaa.addr);
		}

		rspamd_inet_address_set_port (cbd->addr, cbd->port);

		if (!lua_tcp_make_connection (cbd)) {
			lua_tcp_push_error (cbd, TRUE, "unable to make connection to the host %s",
					rspamd_inet_address_to_string (cbd->addr));
			TCP_RELEASE (cbd);
		}
	}
}

static gboolean
lua_tcp_arg_toiovec (lua_State *L, gint pos, struct lua_tcp_cbdata *cbd,
		struct iovec *vec)
{
	struct rspamd_lua_text *t;
	gsize len;
	const gchar *str;
	struct lua_tcp_dtor *dtor;

	if (lua_type (L, pos) == LUA_TUSERDATA) {
		t = lua_check_text (L, pos);

		if (t) {
			vec->iov_base = (void *)t->start;
			vec->iov_len = t->len;

			if (t->flags & RSPAMD_TEXT_FLAG_OWN) {
				/* Steal ownership */
				t->flags = 0;
				dtor = g_malloc0 (sizeof (*dtor));
				dtor->dtor = g_free;
				dtor->data = (void *)t->start;
				LL_PREPEND (cbd->dtors, dtor);
			}
		}
		else {
			msg_err ("bad userdata argument at position %d", pos);
			return FALSE;
		}
	}
	else if (lua_type (L, pos) == LUA_TSTRING) {
		str = luaL_checklstring (L, pos, &len);
		vec->iov_base = g_malloc (len);
		dtor = g_malloc0 (sizeof (*dtor));
		dtor->dtor = g_free;
		dtor->data = vec->iov_base;
		LL_PREPEND (cbd->dtors, dtor);
		memcpy (vec->iov_base, str, len);
		vec->iov_len = len;
	}
	else {
		msg_err ("bad argument at position %d", pos);
		return FALSE;
	}

	return TRUE;
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
 * - `resolver`: DNS resolver (no task)
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
lua_tcp_request (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *host;
	gchar *stop_pattern = NULL;
	guint port;
	gint cbref, tp, conn_cbref = -1;
	gsize plen = 0;
	struct ev_loop *event_loop = NULL;
	struct lua_tcp_cbdata *cbd;
	struct rspamd_dns_resolver *resolver = NULL;
	struct rspamd_async_session *session = NULL;
	struct rspamd_task *task = NULL;
	struct rspamd_config *cfg = NULL;
	struct iovec *iov = NULL;
	guint niov = 0, total_out;
	guint64 h;
	gdouble timeout = default_tcp_timeout;
	gboolean partial = FALSE, do_shutdown = FALSE, do_read = TRUE,
		ssl = FALSE, ssl_noverify = FALSE;

	if (lua_type (L, 1) == LUA_TTABLE) {
		lua_pushstring (L, "host");
		lua_gettable (L, -2);
		host = luaL_checkstring (L, -1);
		lua_pop (L, 1);

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

		lua_pushstring (L, "callback");
		lua_gettable (L, -2);
		if (host == NULL || lua_type (L, -1) != LUA_TFUNCTION) {
			lua_pop (L, 1);
			msg_err ("tcp request has bad params");
			lua_pushboolean (L, FALSE);
			return 1;
		}
		cbref = luaL_ref (L, LUA_REGISTRYINDEX);

		cbd = g_malloc0 (sizeof (*cbd));

		lua_pushstring (L, "task");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TUSERDATA) {
			task = lua_check_task (L, -1);
			event_loop = task->event_loop;
			resolver = task->resolver;
			session = task->s;
			cfg = task->cfg;
		}
		lua_pop (L, 1);

		if (task == NULL) {
			lua_pushstring (L, "ev_base");
			lua_gettable (L, -2);
			if (rspamd_lua_check_udata_maybe (L, -1, "rspamd{ev_base}")) {
				event_loop = *(struct ev_loop **)lua_touserdata (L, -1);
			}
			else {
				g_free (cbd);

				return luaL_error (L, "event loop is required");
			}
			lua_pop (L, 1);

			lua_pushstring (L, "session");
			lua_gettable (L, -2);
			if (rspamd_lua_check_udata_maybe (L, -1, "rspamd{session}")) {
				session = *(struct rspamd_async_session **)lua_touserdata (L, -1);
			}
			else {
				session = NULL;
			}
			lua_pop (L, 1);

			lua_pushstring (L, "config");
			lua_gettable (L, -2);
			if (rspamd_lua_check_udata_maybe (L, -1, "rspamd{config}")) {
				cfg = *(struct rspamd_config **)lua_touserdata (L, -1);
			}
			else {
				cfg = NULL;
			}
			lua_pop (L, 1);

			lua_pushstring (L, "resolver");
			lua_gettable (L, -2);
			if (rspamd_lua_check_udata_maybe (L, -1, "rspamd{resolver}")) {
				resolver = *(struct rspamd_dns_resolver **)lua_touserdata (L, -1);
			}
			else {
				resolver = lua_tcp_global_resolver (event_loop, cfg);
			}
			lua_pop (L, 1);
		}

		lua_pushstring (L, "timeout");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TNUMBER) {
			timeout = lua_tonumber (L, -1);
		}
		lua_pop (L, 1);

		lua_pushstring (L, "stop_pattern");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TSTRING) {
			const gchar *p;

			p = lua_tolstring (L, -1, &plen);

			if (p && plen > 0) {
				stop_pattern = g_malloc (plen);
				memcpy (stop_pattern, p, plen);
			}
		}
		lua_pop (L, 1);

		lua_pushstring (L, "partial");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TBOOLEAN) {
			partial = lua_toboolean (L, -1);
		}
		lua_pop (L, 1);

		lua_pushstring (L, "shutdown");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TBOOLEAN) {
			do_shutdown = lua_toboolean (L, -1);
		}
		lua_pop (L, 1);

		lua_pushstring (L, "read");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TBOOLEAN) {
			do_read = lua_toboolean (L, -1);
		}
		lua_pop (L, 1);

		lua_pushstring (L, "ssl");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TBOOLEAN) {
			ssl = lua_toboolean (L, -1);
		}
		lua_pop (L, 1);

		lua_pushstring (L, "ssl_noverify");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TBOOLEAN) {
			ssl_noverify = lua_toboolean (L, -1);
			lua_pop (L, 1);
		}
		else {
			lua_pop (L, 1); /* Previous nil... */
			/* Similar to lua http, meh... */
			lua_pushstring (L, "no_ssl_verify");
			lua_gettable (L, -2);

			if (lua_type (L, -1) == LUA_TBOOLEAN) {
				ssl_noverify = lua_toboolean (L, -1);
			}

			lua_pop (L, 1);
		}

		lua_pushstring (L, "on_connect");
		lua_gettable (L, -2);

		if (lua_type (L, -1) == LUA_TFUNCTION) {
			conn_cbref = luaL_ref (L, LUA_REGISTRYINDEX);
		}
		else {
			lua_pop (L, 1);
		}

		lua_pushstring (L, "data");
		lua_gettable (L, -2);
		total_out = 0;

		tp = lua_type (L, -1);
		if (tp == LUA_TSTRING || tp == LUA_TUSERDATA) {
			iov = g_malloc (sizeof (*iov));
			niov = 1;

			if (!lua_tcp_arg_toiovec (L, -1, cbd, iov)) {
				lua_pop (L, 1);
				msg_err ("tcp request has bad data argument");
				lua_pushboolean (L, FALSE);
				g_free (iov);
				g_free (cbd);

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

			iov = g_malloc (sizeof (*iov) * niov);
			lua_pushnil (L);
			niov = 0;

			while (lua_next (L, -2) != 0) {
				if (!lua_tcp_arg_toiovec (L, -1, cbd, &iov[niov])) {
					lua_pop (L, 2);
					msg_err ("tcp request has bad data argument at pos %d", niov);
					lua_pushboolean (L, FALSE);
					g_free (iov);
					g_free (cbd);

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
		return luaL_error (L, "tcp request has bad params");
	}

	if (resolver == NULL && cfg == NULL && task == NULL) {
		g_free (cbd);
		g_free (iov);

		return luaL_error (L, "tcp request has bad params: one of "
						"{resolver,task,config} should be set");
	}

	cbd->task = task;

	if (task) {
		cbd->item = rspamd_symcache_get_cur_item (task);
	}

	cbd->cfg = cfg;
	h = rspamd_random_uint64_fast ();
	rspamd_snprintf (cbd->tag, sizeof (cbd->tag), "%uxL", h);
	cbd->handlers = g_queue_new ();
	cbd->hostname = g_strdup (host);

	if (total_out > 0) {
		struct lua_tcp_handler *wh;

		wh = g_malloc0 (sizeof (*wh));
		wh->type = LUA_WANT_WRITE;
		wh->h.w.iov = iov;
		wh->h.w.iovlen = niov;
		wh->h.w.total_bytes = total_out;
		wh->h.w.pos = 0;
		/* Cannot set write handler here */
		wh->h.w.cbref = -1;

		if (cbref != -1 && !do_read) {
			/* We have write only callback */
			wh->h.w.cbref = cbref;
		}
		else {
			/* We have simple client callback */
			wh->h.w.cbref = -1;
		}

		g_queue_push_tail (cbd->handlers, wh);
	}

	cbd->event_loop = event_loop;
	cbd->fd = -1;
	cbd->port = port;
	cbd->ev.timeout = timeout;

	if (ssl) {
		cbd->flags |= LUA_TCP_FLAG_SSL;

		if (ssl_noverify) {
			cbd->flags |= LUA_TCP_FLAG_SSL_NOVERIFY;
		}
	}

	if (do_read) {
		cbd->in = g_byte_array_sized_new (8192);
	}
	else {
		/* Save some space... */
		cbd->in = g_byte_array_new ();
	}

	if (partial) {
		cbd->flags |= LUA_TCP_FLAG_PARTIAL;
	}

	if (do_shutdown) {
		cbd->flags |= LUA_TCP_FLAG_SHUTDOWN;
	}

	if (do_read) {
		struct lua_tcp_handler *rh;

		rh = g_malloc0 (sizeof (*rh));
		rh->type = LUA_WANT_READ;
		rh->h.r.cbref = cbref;
		rh->h.r.stop_pattern = stop_pattern;
		rh->h.r.plen = plen;
		g_queue_push_tail (cbd->handlers, rh);
	}

	cbd->connect_cb = conn_cbref;
	REF_INIT_RETAIN (cbd, lua_tcp_maybe_free);

	if (session) {
		cbd->session = session;

		if (rspamd_session_blocked (session)) {
			lua_tcp_push_error (cbd, TRUE, "async session is the blocked state");
			TCP_RELEASE (cbd);
			cbd->item = NULL; /* To avoid decrease with no watcher */
			lua_pushboolean (L, FALSE);

			return 1;
		}
	}

	if (rspamd_parse_inet_address (&cbd->addr,
			host, strlen (host), RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
		rspamd_inet_address_set_port (cbd->addr, port);
		/* Host is numeric IP, no need to resolve */
		lua_tcp_register_watcher (cbd);

		if (!lua_tcp_make_connection (cbd)) {
			lua_tcp_push_error (cbd, TRUE, "cannot connect to the host: %s", host);
			lua_pushboolean (L, FALSE);

			/* No reset of the item as watcher has been registered */
			TCP_RELEASE (cbd);

			return 1;
		}
	}
	else {
		if (task == NULL) {
			if (!rspamd_dns_resolver_request (resolver, session, NULL, lua_tcp_dns_handler, cbd,
					RDNS_REQUEST_A, host)) {
				lua_tcp_push_error (cbd, TRUE, "cannot resolve host: %s", host);
				lua_pushboolean (L, FALSE);
				cbd->item = NULL; /* To avoid decrease with no watcher */
				TCP_RELEASE (cbd);

				return 1;
			}
			else {
				lua_tcp_register_watcher (cbd);
			}
		}
		else {
			if (!rspamd_dns_resolver_request_task (task, lua_tcp_dns_handler, cbd,
					RDNS_REQUEST_A, host)) {
				lua_tcp_push_error (cbd, TRUE, "cannot resolve host: %s", host);
				lua_pushboolean (L, FALSE);
				cbd->item = NULL; /* To avoid decrease with no watcher */

				TCP_RELEASE (cbd);

				return 1;
			}
			else {
				lua_tcp_register_watcher (cbd);
			}
		}
	}

	lua_pushboolean (L, TRUE);
	return 1;
}

/***
 * @function rspamd_tcp.connect_sync({params})
 * Creates new pseudo-synchronous connection to the specific address:port
 *
 * - `task`: rspamd task objects (implies `pool`, `session`, `ev_base` and `resolver` arguments)
 * - `ev_base`: event base (if no task specified)
 * - `resolver`: DNS resolver (no task)
 * - `session`: events session (no task)
 * - `config`: config (no task)
 * - `host`: IP or name of the peer (required)
 * - `port`: remote port to use
 * - `timeout`: floating point value that specifies timeout for IO operations in **seconds**
 * @return {boolean} true if request has been sent
 */
static gint
lua_tcp_connect_sync (lua_State *L)
{
	LUA_TRACE_POINT;
	GError *err = NULL;

	gint64 port = -1;
	gdouble timeout = default_tcp_timeout;
	const gchar *host = NULL;
	gint ret;
	guint64 h;

	struct rspamd_task *task = NULL;
	struct rspamd_async_session *session = NULL;
	struct rspamd_dns_resolver *resolver = NULL;
	struct rspamd_config *cfg = NULL;
	struct ev_loop *ev_base = NULL;
	struct lua_tcp_cbdata *cbd;


	int arguments_validated = rspamd_lua_parse_table_arguments (L, 1, &err,
			RSPAMD_LUA_PARSE_ARGUMENTS_DEFAULT,
			"task=U{task};session=U{session};resolver=U{resolver};ev_base=U{ev_base};"
			"*host=S;*port=I;timeout=D;config=U{config}",
			&task, &session, &resolver, &ev_base,
			&host, &port, &timeout, &cfg);

	if (!arguments_validated) {
		if (err) {
			ret = luaL_error (L, "invalid arguments: %s", err->message);
			g_error_free (err);

			return ret;
		}

		return luaL_error (L, "invalid arguments");
	}

	if (0 > port || port > 65535) {
		return luaL_error (L, "invalid port given (correct values: 1..65535)");
	}

	if (task == NULL && (cfg == NULL || ev_base == NULL || session == NULL)) {
		return luaL_error (L, "invalid arguments: either task or config+ev_base+session should be set");
	}

	if (isnan (timeout)) {
		/* rspamd_lua_parse_table_arguments() sets missing N field to zero */
		timeout = default_tcp_timeout;
	}

	cbd = g_new0 (struct lua_tcp_cbdata, 1);

	if (task) {
		static const gchar hexdigests[16] = "0123456789abcdef";

		cfg = task->cfg;
		ev_base = task->event_loop;
		session = task->s;
		/* Make a readable tag */
		memcpy (cbd->tag, task->task_pool->tag.uid, sizeof (cbd->tag) - 2);
		cbd->tag[sizeof (cbd->tag) - 2] = hexdigests[GPOINTER_TO_INT (cbd) & 0xf];
		cbd->tag[sizeof (cbd->tag) - 1] = 0;
	}
	else {
		h = rspamd_random_uint64_fast ();
		rspamd_snprintf (cbd->tag, sizeof (cbd->tag), "%uxL", h);
	}

	if (resolver == NULL) {
		if (task) {
			resolver = task->resolver;
		}
		else {
			resolver = lua_tcp_global_resolver (ev_base, cfg);
		}
	}

	cbd->task = task;
	cbd->cfg = cfg;
	cbd->thread = lua_thread_pool_get_running_entry (cfg->lua_thread_pool);


	cbd->handlers = g_queue_new ();

	cbd->event_loop = ev_base;
	cbd->flags |= LUA_TCP_FLAG_SYNC;
	cbd->fd = -1;
	cbd->port = (guint16)port;

	cbd->in = g_byte_array_new ();

	cbd->connect_cb = -1;

	REF_INIT_RETAIN (cbd, lua_tcp_maybe_free);

	if (task) {
		rspamd_mempool_add_destructor (task->task_pool, lua_tcp_sync_session_dtor, cbd);
	}

	struct lua_tcp_handler *wh;

	wh = g_malloc0 (sizeof (*wh));
	wh->type = LUA_WANT_CONNECT;

	g_queue_push_tail (cbd->handlers, wh);

	if (session) {
		cbd->session = session;

		if (rspamd_session_blocked (session)) {
			TCP_RELEASE (cbd);
			lua_pushboolean (L, FALSE);
			lua_pushliteral (L, "Session is being destroyed, requests are not allowed");

			return 2;
		}
	}

	if (rspamd_parse_inet_address (&cbd->addr,
			host, strlen (host), RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
		rspamd_inet_address_set_port (cbd->addr, (guint16)port);
		/* Host is numeric IP, no need to resolve */
		if (!lua_tcp_make_connection (cbd)) {
			lua_pushboolean (L, FALSE);
			lua_pushliteral (L, "Failed to initiate connection");

			TCP_RELEASE (cbd);

			return 2;
		}
	}
	else {
		if (task == NULL) {
			if (!rspamd_dns_resolver_request (resolver, session, NULL, lua_tcp_dns_handler, cbd,
					RDNS_REQUEST_A, host)) {
				lua_pushboolean (L, FALSE);
				lua_pushliteral (L, "Failed to initiate dns request");

				TCP_RELEASE (cbd);

				return 2;
			}
			else {
				lua_tcp_register_watcher (cbd);
			}
		}
		else {
			cbd->item = rspamd_symcache_get_cur_item (task);

			if (!rspamd_dns_resolver_request_task (task, lua_tcp_dns_handler, cbd,
					RDNS_REQUEST_A, host)) {
				lua_pushboolean (L, FALSE);
				lua_pushliteral (L, "Failed to initiate dns request");
				TCP_RELEASE (cbd);

				return 2;
			}
			else {
				lua_tcp_register_watcher (cbd);
			}
		}
	}

	return lua_thread_yield (cbd->thread, 0);
}

static gint
lua_tcp_close (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_tcp_cbdata *cbd = lua_check_tcp (L, 1);

	if (cbd == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	cbd->flags |= LUA_TCP_FLAG_FINISHED;
	TCP_RELEASE (cbd);

	return 0;
}

static gint
lua_tcp_add_read (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_tcp_cbdata *cbd = lua_check_tcp (L, 1);
	struct lua_tcp_handler *rh;
	gchar *stop_pattern = NULL;
	const gchar *p;
	gsize plen = 0;
	gint cbref = -1;

	if (cbd == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (lua_type (L, 2) == LUA_TFUNCTION) {
		lua_pushvalue (L, 2);
		cbref = luaL_ref (L, LUA_REGISTRYINDEX);
	}

	if (lua_type (L, 3) == LUA_TSTRING) {
		p = lua_tolstring (L, 3, &plen);

		if (p && plen > 0) {
			stop_pattern = g_malloc (plen);
			memcpy (stop_pattern, p, plen);
		}
	}

	rh = g_malloc0 (sizeof (*rh));
	rh->type = LUA_WANT_READ;
	rh->h.r.cbref = cbref;
	rh->h.r.stop_pattern = stop_pattern;
	rh->h.r.plen = plen;
	msg_debug_tcp ("added read event, cbref: %d", cbref);

	g_queue_push_tail (cbd->handlers, rh);

	return 0;
}

static gint
lua_tcp_add_write (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_tcp_cbdata *cbd = lua_check_tcp (L, 1);
	struct lua_tcp_handler *wh;
	gint cbref = -1, tp;
	struct iovec *iov = NULL;
	guint niov = 0, total_out = 0;

	if (cbd == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (lua_type (L, 2) == LUA_TFUNCTION) {
		lua_pushvalue (L, 2);
		cbref = luaL_ref (L, LUA_REGISTRYINDEX);
	}

	tp = lua_type (L, 3);
	if (tp == LUA_TSTRING || tp == LUA_TUSERDATA) {
		iov = g_malloc (sizeof (*iov));
		niov = 1;

		if (!lua_tcp_arg_toiovec (L, 3, cbd, iov)) {
			msg_err ("tcp request has bad data argument");
			lua_pushboolean (L, FALSE);
			g_free (iov);

			return 1;
		}

		total_out = iov[0].iov_len;
	}
	else if (tp == LUA_TTABLE) {
		/* Count parts */
		lua_pushvalue (L, 3);

		lua_pushnil (L);
		while (lua_next (L, -2) != 0) {
			niov ++;
			lua_pop (L, 1);
		}

		iov = g_malloc (sizeof (*iov) * niov);
		lua_pushnil (L);
		niov = 0;

		while (lua_next (L, -2) != 0) {
			if (!lua_tcp_arg_toiovec (L, -1, cbd, &iov[niov])) {
				lua_pop (L, 2);
				msg_err ("tcp request has bad data argument at pos %d", niov);
				lua_pushboolean (L, FALSE);
				g_free (iov);
				g_free (cbd);

				return 1;
			}

			total_out += iov[niov].iov_len;
			niov ++;

			lua_pop (L, 1);
		}

		lua_pop (L, 1);
	}

	wh = g_malloc0 (sizeof (*wh));
	wh->type = LUA_WANT_WRITE;
	wh->h.w.iov = iov;
	wh->h.w.iovlen = niov;
	wh->h.w.total_bytes = total_out;
	wh->h.w.pos = 0;
	/* Cannot set write handler here */
	wh->h.w.cbref = cbref;
	msg_debug_tcp ("added write event, cbref: %d", cbref);

	g_queue_push_tail (cbd->handlers, wh);
	lua_pushboolean (L, TRUE);

	return 1;
}

static gint
lua_tcp_shift_callback (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_tcp_cbdata *cbd = lua_check_tcp (L, 1);

	if (cbd == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	lua_tcp_shift_handler (cbd);
	lua_tcp_plan_handler_event (cbd, TRUE, TRUE);

	return 0;
}

static struct lua_tcp_cbdata *
lua_check_sync_tcp (lua_State *L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{tcp_sync}");
	luaL_argcheck (L, ud != NULL, pos, "'tcp' expected");
	return ud ? *((struct lua_tcp_cbdata **)ud) : NULL;
}

static int
lua_tcp_sync_close (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_tcp_cbdata *cbd = lua_check_sync_tcp (L, 1);

	if (cbd == NULL) {
		return luaL_error (L, "invalid arguments [self is not rspamd{tcp_sync}]");
	}
	cbd->flags |= LUA_TCP_FLAG_FINISHED;

	if (cbd->fd != -1) {
		rspamd_ev_watcher_stop (cbd->event_loop, &cbd->ev);
		close (cbd->fd);
		cbd->fd = -1;
	}

	return 0;
}

static void
lua_tcp_sync_session_dtor (gpointer ud)
{
	struct lua_tcp_cbdata *cbd = ud;
	cbd->flags |= LUA_TCP_FLAG_FINISHED;

	if (cbd->fd != -1) {
		msg_debug ("closing sync TCP connection");
		rspamd_ev_watcher_stop (cbd->event_loop, &cbd->ev);
		close (cbd->fd);
		cbd->fd = -1;
	}

	/* Task is gone, we should not try use it anymore */
	cbd->task = NULL;

	/* All events are removed when task is done, we should not refer them */
	cbd->async_ev = NULL;
}

static int
lua_tcp_sync_read_once (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_tcp_cbdata *cbd = lua_check_sync_tcp (L, 1);
	struct lua_tcp_handler *rh;

	if (cbd == NULL) {
		return luaL_error (L, "invalid arguments [self is not rspamd{tcp_sync}]");
	}

	struct thread_entry *thread = lua_thread_pool_get_running_entry (cbd->cfg->lua_thread_pool);

	rh = g_malloc0 (sizeof (*rh));
	rh->type = LUA_WANT_READ;
	rh->h.r.cbref = -1;

	msg_debug_tcp ("added read sync event, thread: %p", thread);

	g_queue_push_tail (cbd->handlers, rh);
	lua_tcp_plan_handler_event (cbd, TRUE, TRUE);

	TCP_RETAIN (cbd);

	return lua_thread_yield (thread, 0);
}

static int
lua_tcp_sync_write (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_tcp_cbdata *cbd = lua_check_sync_tcp (L, 1);
	struct lua_tcp_handler *wh;
	gint tp;
	struct iovec *iov = NULL;
	guint niov = 0;
	gsize total_out = 0;

	if (cbd == NULL) {
		return luaL_error (L, "invalid arguments [self is not rspamd{tcp_sync}]");
	}

	struct thread_entry *thread = lua_thread_pool_get_running_entry (cbd->cfg->lua_thread_pool);

	tp = lua_type (L, 2);
	if (tp == LUA_TSTRING || tp == LUA_TUSERDATA) {
		iov = g_malloc (sizeof (*iov));
		niov = 1;

		if (!lua_tcp_arg_toiovec (L, 2, cbd, iov)) {
			msg_err ("tcp request has bad data argument");
			g_free (iov);
			g_free (cbd);

			return luaL_error (L, "invalid arguments second parameter (data) is expected to be either string or rspamd{text}");
		}

		total_out = iov[0].iov_len;
	}
	else if (tp == LUA_TTABLE) {
		/* Count parts */
		lua_pushvalue (L, 3);

		lua_pushnil (L);
		while (lua_next (L, -2) != 0) {
			niov ++;
			lua_pop (L, 1);
		}

		iov = g_malloc (sizeof (*iov) * niov);
		lua_pushnil (L);
		niov = 0;

		while (lua_next (L, -2) != 0) {
			if (!lua_tcp_arg_toiovec (L, -1, cbd, &iov[niov])) {
				msg_err ("tcp request has bad data argument at pos %d", niov);
				g_free (iov);
				g_free (cbd);

				return luaL_error (L, "invalid arguments second parameter (data) is expected to be either string or rspamd{text}");
			}

			total_out += iov[niov].iov_len;
			niov ++;

			lua_pop (L, 1);
		}

		lua_pop (L, 1);
	}

	wh = g_malloc0 (sizeof (*wh));
	wh->type = LUA_WANT_WRITE;
	wh->h.w.iov = iov;
	wh->h.w.iovlen = niov;
	wh->h.w.total_bytes = total_out;
	wh->h.w.pos = 0;
	wh->h.w.cbref = -1;
	msg_debug_tcp ("added sync write event, thread: %p", thread);

	g_queue_push_tail (cbd->handlers, wh);
	lua_tcp_plan_handler_event (cbd, TRUE, TRUE);

	TCP_RETAIN (cbd);

	return lua_thread_yield (thread, 0);
}

static gint
lua_tcp_sync_eof(lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_tcp_cbdata *cbd = lua_check_sync_tcp (L, 1);
	if (cbd == NULL) {
		return luaL_error (L, "invalid arguments [self is not rspamd{tcp_sync}]");
	}

	lua_pushboolean(L, cbd->eof);

	return 1;
}

static gint
lua_tcp_sync_shutdown (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_tcp_cbdata *cbd = lua_check_sync_tcp (L, 1);
	if (cbd == NULL) {
		return luaL_error (L, "invalid arguments [self is not rspamd{tcp_sync}]");
	}

	shutdown (cbd->fd, SHUT_WR);

	return 0;
}

static gint
lua_tcp_starttls (lua_State * L)
{
	LUA_TRACE_POINT;
	struct lua_tcp_cbdata *cbd = lua_check_tcp (L, 1);
	gpointer ssl_ctx;
	gboolean verify_peer;

	if (cbd == NULL || cbd->ssl_conn != NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (cbd->flags & LUA_TCP_FLAG_SSL_NOVERIFY) {
		ssl_ctx = cbd->cfg->libs_ctx->ssl_ctx_noverify;
		verify_peer = FALSE;
	}
	else {
		ssl_ctx = cbd->cfg->libs_ctx->ssl_ctx;
		verify_peer = TRUE;
	}

	cbd->ssl_conn = rspamd_ssl_connection_new (ssl_ctx,
			cbd->event_loop,
			verify_peer,
			cbd->tag);

	if (!rspamd_ssl_connect_fd (cbd->ssl_conn, cbd->fd, cbd->hostname, &cbd->ev,
			cbd->ev.timeout, lua_tcp_handler, lua_tcp_ssl_on_error, cbd)) {
		lua_tcp_push_error (cbd, TRUE, "ssl connection failed: %s",
				strerror (errno));
	}

	return 0;
}

static gint
lua_tcp_sync_gc (lua_State * L)
{
	struct lua_tcp_cbdata *cbd = lua_check_sync_tcp (L, 1);
	if (!cbd) {
		return luaL_error (L, "invalid arguments [self is not rspamd{tcp_sync}]");
	}

	lua_tcp_maybe_free(cbd);
	lua_tcp_fin (cbd);

	return 0;
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
	rspamd_lua_new_class (L, "rspamd{tcp}", tcp_libm);
	rspamd_lua_new_class (L, "rspamd{tcp_sync}", tcp_sync_libm);
	lua_pop (L, 1);
}
