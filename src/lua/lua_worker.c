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
#include "unix-std.h"
#include "worker_util.h"
#include "rspamd_control.h"
#include "ottery.h"

#ifdef WITH_JEMALLOC
#include <jemalloc/jemalloc.h>
#endif

#include <sys/wait.h>
#include <src/libserver/rspamd_control.h>

/***
 * @module rspamd_worker
 * This module provides methods to access worker related functions in various
 * places, such as periodic events or on_load events.
 */


LUA_FUNCTION_DEF (worker, get_name);
LUA_FUNCTION_DEF (worker, get_stat);
LUA_FUNCTION_DEF (worker, get_index);
LUA_FUNCTION_DEF (worker, get_count);
LUA_FUNCTION_DEF (worker, get_pid);
LUA_FUNCTION_DEF (worker, is_scanner);
LUA_FUNCTION_DEF (worker, is_primary_controller);
LUA_FUNCTION_DEF (worker, spawn_process);
LUA_FUNCTION_DEF (worker, get_mem_stats);
LUA_FUNCTION_DEF (worker, add_control_handler);

const luaL_reg worker_reg[] = {
		LUA_INTERFACE_DEF (worker, get_name),
		{"get_type", lua_worker_get_name},
		LUA_INTERFACE_DEF (worker, get_stat),
		LUA_INTERFACE_DEF (worker, get_index),
		LUA_INTERFACE_DEF (worker, get_count),
		LUA_INTERFACE_DEF (worker, get_pid),
		LUA_INTERFACE_DEF (worker, spawn_process),
		LUA_INTERFACE_DEF (worker, is_scanner),
		LUA_INTERFACE_DEF (worker, is_primary_controller),
		LUA_INTERFACE_DEF (worker, get_mem_stats),
		LUA_INTERFACE_DEF (worker, add_control_handler),
		{"__tostring", rspamd_lua_class_tostring},
		{NULL, NULL}
};

static struct rspamd_worker *
lua_check_worker (lua_State *L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{worker}");
	luaL_argcheck (L, ud != NULL, pos, "'worker' expected");
	return ud ? *((struct rspamd_worker **)ud) : NULL;
}

static gint
lua_worker_get_stat (lua_State *L)
{
	struct rspamd_worker *w = lua_check_worker (L, 1);

	if (w) {
		rspamd_mempool_stat_t mem_st;
		struct rspamd_stat *stat, stat_copy;
		ucl_object_t *top, *sub;
		gint i;
		guint64 spam = 0, ham = 0;

		memset (&mem_st, 0, sizeof (mem_st));
		rspamd_mempool_stat (&mem_st);
		memcpy (&stat_copy, w->srv->stat, sizeof (stat_copy));
		stat = &stat_copy;
		top = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (top, ucl_object_fromint (
				stat->messages_scanned), "scanned", 0, false);
		ucl_object_insert_key (top, ucl_object_fromint (
				stat->messages_learned), "learned", 0, false);
		if (stat->messages_scanned > 0) {
			sub = ucl_object_typed_new (UCL_OBJECT);
			for (i = METRIC_ACTION_REJECT; i <= METRIC_ACTION_NOACTION; i++) {
				ucl_object_insert_key (sub,
						ucl_object_fromint (stat->actions_stat[i]),
						rspamd_action_to_str (i), 0, false);
				if (i < METRIC_ACTION_GREYLIST) {
					spam += stat->actions_stat[i];
				}
				else {
					ham += stat->actions_stat[i];
				}
			}
			ucl_object_insert_key (top, sub, "actions", 0, false);
		}
		else {
			sub = ucl_object_typed_new (UCL_OBJECT);
			for (i = METRIC_ACTION_REJECT; i <= METRIC_ACTION_NOACTION; i++) {
				ucl_object_insert_key (sub,
						0,
						rspamd_action_to_str (i), 0, false);
			}
			ucl_object_insert_key (top, sub, "actions", 0, false);
		}
		ucl_object_insert_key (top, ucl_object_fromint (
				spam), "spam_count", 0, false);
		ucl_object_insert_key (top, ucl_object_fromint (
				ham),  "ham_count",      0, false);
		ucl_object_insert_key (top,
				ucl_object_fromint (stat->connections_count), "connections", 0, false);
		ucl_object_insert_key (top,
				ucl_object_fromint (stat->control_connections_count),
				"control_connections", 0, false);
		ucl_object_insert_key (top,
				ucl_object_fromint (mem_st.pools_allocated), "pools_allocated", 0,
				false);
		ucl_object_insert_key (top,
				ucl_object_fromint (mem_st.pools_freed), "pools_freed", 0, false);
		ucl_object_insert_key (top,
				ucl_object_fromint (mem_st.bytes_allocated), "bytes_allocated", 0,
				false);
		ucl_object_insert_key (top,
				ucl_object_fromint (
						mem_st.chunks_allocated), "chunks_allocated", 0, false);
		ucl_object_insert_key (top,
				ucl_object_fromint (mem_st.shared_chunks_allocated),
				"shared_chunks_allocated", 0, false);
		ucl_object_insert_key (top,
				ucl_object_fromint (mem_st.chunks_freed), "chunks_freed", 0, false);
		ucl_object_insert_key (top,
				ucl_object_fromint (
						mem_st.oversized_chunks), "chunks_oversized", 0, false);

		ucl_object_push_lua (L, top, true);
		ucl_object_unref (top);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_worker_get_name (lua_State *L)
{
	struct rspamd_worker *w = lua_check_worker (L, 1);

	if (w) {
		lua_pushstring (L, g_quark_to_string (w->type));
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_worker_get_index (lua_State *L)
{
	struct rspamd_worker *w = lua_check_worker (L, 1);

	if (w) {
		lua_pushinteger (L, w->index);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_worker_get_count (lua_State *L)
{
	struct rspamd_worker *w = lua_check_worker (L, 1);

	if (w) {
		lua_pushinteger (L, w->cf->count);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_worker_get_pid (lua_State *L)
{
	struct rspamd_worker *w = lua_check_worker (L, 1);

	if (w) {
		lua_pushinteger (L, w->pid);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}


static gint
lua_worker_is_scanner (lua_State *L)
{
	struct rspamd_worker *w = lua_check_worker (L, 1);

	if (w) {
		lua_pushboolean (L, rspamd_worker_is_scanner (w));
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_worker_is_primary_controller (lua_State *L)
{
	struct rspamd_worker *w = lua_check_worker (L, 1);

	if (w) {
		lua_pushboolean (L, rspamd_worker_is_primary_controller (w));
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

struct rspamd_control_cbdata {
	lua_State *L;
	rspamd_mempool_t *pool;
	struct rspamd_worker *w;
	struct rspamd_config *cfg;
	struct ev_loop *event_loop;
	struct rspamd_async_session *session;
	enum rspamd_control_type cmd;
	gint cbref;
	gint fd;
};

static gboolean
lua_worker_control_fin_session (void *ud)
{
	struct rspamd_control_reply rep;
	struct rspamd_control_cbdata *cbd = (struct rspamd_control_cbdata *)ud;
	rspamd_mempool_t *pool;

	pool = cbd->pool;

	memset (&rep, 0, sizeof (rep));
	rep.type = cbd->cmd;

	if (write (cbd->fd, &rep, sizeof (rep)) != sizeof (rep)) {
		msg_err_pool ("cannot write reply to the control socket: %s",
				strerror (errno));
	}

	return TRUE;
}

static void
lua_worker_control_session_dtor (void *ud)
{
	struct rspamd_control_cbdata *cbd = (struct rspamd_control_cbdata *)ud;

	rspamd_mempool_delete (cbd->pool);
}

static gboolean
lua_worker_control_handler (struct rspamd_main *rspamd_main,
							struct rspamd_worker *worker,
							gint fd,
							gint attached_fd,
							struct rspamd_control_command *cmd,
							gpointer ud)
{
	struct rspamd_async_session *session, **psession;
	struct rspamd_control_cbdata *cbd = (struct rspamd_control_cbdata *)ud;
	rspamd_mempool_t *pool;
	lua_State *L;
	gint err_idx, status;

	L = cbd->L;
	pool = cbd->pool;
	session = rspamd_session_create (cbd->pool,
			lua_worker_control_fin_session,
			NULL,
			lua_worker_control_session_dtor,
			cbd);
	cbd->session = session;
	cbd->fd = fd;

	lua_pushcfunction (L, &rspamd_lua_traceback);
	err_idx = lua_gettop (L);
	lua_rawgeti (L, LUA_REGISTRYINDEX, cbd->cbref);
	psession = lua_newuserdata (L, sizeof (*psession));
	rspamd_lua_setclass (L, "rspamd{session}", -1);
	*psession = session;

	/* Command name */
	lua_pushstring (L, rspamd_control_command_to_string (cmd->type));

	/* Command's extras */
	lua_newtable (L);

	switch (cmd->type) {
	case RSPAMD_CONTROL_CHILD_CHANGE:
		lua_pushinteger (L, cmd->cmd.child_change.pid);
		lua_setfield (L, -2, "pid");
		switch (cmd->cmd.child_change.what) {
		case rspamd_child_offline:
			lua_pushstring (L, "offline");
			lua_setfield (L, -2, "what");
			break;
		case rspamd_child_online:
			lua_pushstring (L, "online");
			lua_setfield (L, -2, "what");
			break;
		case rspamd_child_terminated:
			lua_pushstring (L, "terminated");
			lua_setfield (L, -2, "what");
			status = cmd->cmd.child_change.additional;

			if (WIFEXITED (status)) {
				lua_pushinteger (L, WEXITSTATUS (status));
				lua_setfield (L, -2, "exit_code");
			}

			if (WIFSIGNALED (status)) {
				lua_pushinteger (L, WTERMSIG (status));
				lua_setfield (L, -2, "signal");
#ifdef WCOREDUMP
				lua_pushboolean (L, WCOREDUMP (status));
				lua_setfield (L, -2, "core");
#endif
			}
			break;
		}
		break;
	case RSPAMD_CONTROL_MONITORED_CHANGE:
		lua_pushinteger (L, cmd->cmd.monitored_change.sender);
		lua_setfield (L, -2, "sender");
		lua_pushboolean (L, cmd->cmd.monitored_change.alive);
		lua_setfield (L, -2, "alive");
		lua_pushlstring (L, cmd->cmd.monitored_change.tag,
				sizeof (cmd->cmd.monitored_change.tag));
		lua_setfield (L, -2, "tag");
		break;
	case RSPAMD_CONTROL_HYPERSCAN_LOADED:
		lua_pushstring (L, cmd->cmd.hs_loaded.cache_dir);
		lua_setfield (L, -2, "cache_dir");
		lua_pushboolean (L, cmd->cmd.hs_loaded.forced);
		lua_setfield (L, -2, "forced");
		break;
	case RSPAMD_CONTROL_STAT:
	case RSPAMD_CONTROL_RELOAD:
	case RSPAMD_CONTROL_RERESOLVE:
	case RSPAMD_CONTROL_RECOMPILE:
	case RSPAMD_CONTROL_LOG_PIPE:
	case RSPAMD_CONTROL_FUZZY_STAT:
	case RSPAMD_CONTROL_FUZZY_SYNC:
	default:
		break;
	}

	if (lua_pcall (L, 3, 0, err_idx) != 0) {
		msg_err_pool ("cannot init lua parser script: %s", lua_tostring (L, -1));
		lua_settop (L, err_idx - 1);

		struct rspamd_control_reply rep;

		memset (&rep, 0, sizeof (rep));
		rep.type = cbd->cmd;
		rep.reply.monitored_change.status = -1;

		if (write (fd, &rep, sizeof (rep)) != sizeof (rep)) {
			msg_err_pool ("cannot write reply to the control socket: %s",
					strerror (errno));
		}

		rspamd_session_destroy (session);
	}
	else {
		lua_settop (L, err_idx - 1);
		rspamd_session_pending (session);
	}

	return TRUE;
}

static gint
lua_worker_add_control_handler (lua_State *L)
{
	struct rspamd_worker *w = lua_check_worker (L, 1);
	struct rspamd_config *cfg = lua_check_config (L, 2);
	struct ev_loop *event_loop = lua_check_ev_base (L, 3);
	const gchar *cmd_name = luaL_checkstring (L, 4);
	enum rspamd_control_type cmd;
	struct rspamd_control_cbdata *cbd;

	if (w && cfg && event_loop && cmd_name && lua_isfunction (L, 5)) {
		cmd = rspamd_control_command_from_string (cmd_name);

		if (cmd == RSPAMD_CONTROL_MAX) {
			return luaL_error (L, "invalid command type: %s", cmd_name);
		}

		rspamd_mempool_t *pool = rspamd_mempool_new (
				rspamd_mempool_suggest_size (), "lua_control", 0);
		cbd = rspamd_mempool_alloc0 (pool, sizeof (*cbd));
		cbd->pool = pool;
		cbd->event_loop = event_loop;
		cbd->w = w;
		cbd->cfg = cfg;
		cbd->cmd = cmd;
		cbd->L = L;
		/* Refcount callback */
		lua_pushvalue (L, 5);
		cbd->cbref = luaL_ref (L, LUA_REGISTRYINDEX);

		rspamd_control_worker_add_cmd_handler (w, cmd, lua_worker_control_handler,
				cbd);
	}
	else {
		return luaL_error (L, "invalid arguments, need worker, cfg, "
						"ev_loop, cmd_name and callback function");
	}

	return 0;
}

#ifdef WITH_JEMALLOC
static void
lua_worker_jemalloc_stats_cb (void *ud, const char *msg)
{
	lua_State *L = (lua_State *)ud;

	lua_pushstring (L, msg);
}
#endif

static gint
lua_worker_get_mem_stats (lua_State *L)
{
	struct rspamd_worker *w = lua_check_worker (L, 1);

	if (w) {
#ifdef WITH_JEMALLOC
		malloc_stats_print (lua_worker_jemalloc_stats_cb, (void *)L, NULL);
#else
		lua_pushstring (L, "no stats, jemalloc support is required");
#endif
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

struct rspamd_lua_process_cbdata {
	gint sp[2];
	gint func_cbref;
	gint cb_cbref;
	gboolean replied;
	gboolean is_error;
	pid_t cpid;
	lua_State *L;
	guint64 sz;
	GString *io_buf;
	GString *out_buf;
	goffset out_pos;
	struct rspamd_worker *wrk;
	struct ev_loop *event_loop;
	ev_io ev;
};

static void
rspamd_lua_execute_lua_subprocess (lua_State *L,
								   struct rspamd_lua_process_cbdata *cbdata)
{
	gint err_idx, r;
	guint64 wlen = 0;

	lua_pushcfunction (L, &rspamd_lua_traceback);
	err_idx = lua_gettop (L);

	lua_rawgeti (L, LUA_REGISTRYINDEX, cbdata->func_cbref);

	if (lua_pcall (L, 0, 1, err_idx) != 0) {
		const gchar *s = lua_tostring (L, -1);
		gsize slen = strlen (s);

		msg_err ("call to subprocess failed: %s", s);
		/* Indicate error */
		wlen = (1ULL << 63u) + slen;

		r = write (cbdata->sp[1], &wlen, sizeof (wlen));
		if (r == -1) {
			msg_err ("write failed: %s", strerror (errno));
		}

		r = write (cbdata->sp[1], s, slen);
		if (r == -1) {
			msg_err ("write failed: %s", strerror (errno));
		}
	}
	else {
		struct rspamd_lua_text *t = lua_check_text_or_string (L, -1);

		if (t) {
			wlen = t->len;
			r = write (cbdata->sp[1], &wlen, sizeof (wlen));

			if (r == -1) {
				msg_err ("write failed: %s", strerror (errno));
			}

			r = write (cbdata->sp[1], t->start, wlen);

			if (r == -1) {
				msg_err ("write failed: %s", strerror (errno));
			}
		}
		else {
			msg_err ("subprocess: invalid return value: %s",
					lua_typename (L, lua_type (L, -1)));
		}
	}

	lua_settop (L, err_idx - 1);
}

static void
rspamd_lua_call_on_complete (lua_State *L,
							 struct rspamd_lua_process_cbdata *cbdata,
							 const gchar *err_msg,
							 const gchar *data, gsize datalen)
{
	gint err_idx;

	lua_pushcfunction (L, &rspamd_lua_traceback);
	err_idx = lua_gettop (L);

	lua_rawgeti (L, LUA_REGISTRYINDEX, cbdata->cb_cbref);

	if (err_msg) {
		lua_pushstring (L, err_msg);
	}
	else {
		lua_pushnil (L);
	}

	if (data) {
		lua_pushlstring (L, data, datalen);
	}
	else {
		lua_pushnil (L);
	}

	if (lua_pcall (L, 2, 0, err_idx) != 0) {
		msg_err ("call to on_complete script failed: %s",
				lua_tostring (L, -1));
	}

	lua_settop (L, err_idx - 1);
}

static gboolean
rspamd_lua_cld_handler (struct rspamd_worker_signal_handler *sigh, void *ud)
{
	struct rspamd_lua_process_cbdata *cbdata = ud;
	struct rspamd_srv_command srv_cmd;
	lua_State *L;
	pid_t died;
	gint res = 0;

	/* Are we called by a correct children ? */
	died = waitpid (cbdata->cpid, &res, WNOHANG);

	if (died <= 0) {
		/* Wait more */
		return TRUE;
	}

	L = cbdata->L;
	msg_info ("handled SIGCHLD from %P", cbdata->cpid);

	if (!cbdata->replied) {
		/* We still need to call on_complete callback */
		ev_io_stop (cbdata->event_loop, &cbdata->ev);
		rspamd_lua_call_on_complete (cbdata->L, cbdata,
				"Worker has died without reply", NULL, 0);
	}

	/* Free structures */
	close (cbdata->sp[0]);
	luaL_unref (L, LUA_REGISTRYINDEX, cbdata->func_cbref);
	luaL_unref (L, LUA_REGISTRYINDEX, cbdata->cb_cbref);
	g_string_free (cbdata->io_buf, TRUE);

	if (cbdata->out_buf) {
		g_string_free (cbdata->out_buf, TRUE);
	}

	/* Notify main */
	memset (&srv_cmd, 0, sizeof (srv_cmd));
	srv_cmd.type = RSPAMD_SRV_ON_FORK;
	srv_cmd.cmd.on_fork.state = child_dead;
	srv_cmd.cmd.on_fork.cpid = cbdata->cpid;
	srv_cmd.cmd.on_fork.ppid = getpid ();
	rspamd_srv_send_command (cbdata->wrk, cbdata->event_loop, &srv_cmd, -1,
			NULL, NULL);
	g_free (cbdata);

	/* We are done with this SIGCHLD */
	return FALSE;
}

static void
rspamd_lua_subprocess_io (EV_P_ ev_io *w, int revents)
{
	struct rspamd_lua_process_cbdata *cbdata =
			(struct rspamd_lua_process_cbdata *)w->data;
	gssize r;

	if (cbdata->sz == (guint64)-1) {
		guint64 sz;

		/* We read size of reply + flags first */
		r = read (cbdata->sp[0], cbdata->io_buf->str + cbdata->io_buf->len,
				sizeof (guint64) - cbdata->io_buf->len);

		if (r == 0) {
			ev_io_stop (cbdata->event_loop, &cbdata->ev);
			rspamd_lua_call_on_complete (cbdata->L, cbdata,
					"Unexpected EOF", NULL, 0);
			cbdata->replied = TRUE;
			kill (cbdata->cpid, SIGTERM);

			return;
		}
		else if (r == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				return;
			}
			else {
				ev_io_stop (cbdata->event_loop, &cbdata->ev);
				rspamd_lua_call_on_complete (cbdata->L, cbdata,
						strerror (errno), NULL, 0);
				cbdata->replied = TRUE;
				kill (cbdata->cpid, SIGTERM);

				return;
			}
		}

		cbdata->io_buf->len += r;

		if (cbdata->io_buf->len == sizeof (guint64)) {
			memcpy ((guchar *)&sz, cbdata->io_buf->str, sizeof (sz));

			if (sz & (1ULL << 63)) {
				cbdata->is_error = TRUE;
				sz &= ~(1ULL << 63);
			}

			cbdata->io_buf->len = 0;
			cbdata->sz = sz;
			g_string_set_size (cbdata->io_buf, sz + 1);
			cbdata->io_buf->len = 0;
		}
	}
	else {
		/* Read data */
		r = read (cbdata->sp[0], cbdata->io_buf->str + cbdata->io_buf->len,
				cbdata->sz - cbdata->io_buf->len);

		if (r == 0) {
			ev_io_stop (cbdata->event_loop, &cbdata->ev);
			rspamd_lua_call_on_complete (cbdata->L, cbdata,
					"Unexpected EOF", NULL, 0);
			cbdata->replied = TRUE;
			kill (cbdata->cpid, SIGTERM);

			return;
		}
		else if (r == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				return;
			}
			else {
				ev_io_stop (cbdata->event_loop, &cbdata->ev);
				rspamd_lua_call_on_complete (cbdata->L, cbdata,
						strerror (errno), NULL, 0);
				cbdata->replied = TRUE;
				kill (cbdata->cpid, SIGTERM);

				return;
			}
		}

		cbdata->io_buf->len += r;

		if (cbdata->io_buf->len == cbdata->sz) {
			gchar rep[4];

			ev_io_stop (cbdata->event_loop, &cbdata->ev);
			/* Finished reading data */
			if (cbdata->is_error) {
				cbdata->io_buf->str[cbdata->io_buf->len] = '\0';
				rspamd_lua_call_on_complete (cbdata->L, cbdata,
						cbdata->io_buf->str, NULL, 0);
			}
			else {
				rspamd_lua_call_on_complete (cbdata->L, cbdata,
						NULL, cbdata->io_buf->str, cbdata->io_buf->len);
			}

			cbdata->replied = TRUE;

			/* Write reply to the child */
			rspamd_socket_blocking (cbdata->sp[0]);
			memset (rep, 0, sizeof (rep));
			(void) !write (cbdata->sp[0], rep, sizeof (rep));
		}
	}
}

static gint
lua_worker_spawn_process (lua_State *L)
{
	struct rspamd_worker *w = lua_check_worker (L, 1);
	struct rspamd_lua_process_cbdata *cbdata;
	struct rspamd_abstract_worker_ctx *actx;
	struct rspamd_srv_command srv_cmd;
	const gchar *cmdline = NULL, *input = NULL, *proctitle = NULL;
	gsize inputlen = 0;
	pid_t pid;
	GError *err = NULL;
	gint func_cbref, cb_cbref;

	if (!rspamd_lua_parse_table_arguments (L, 2, &err,
			RSPAMD_LUA_PARSE_ARGUMENTS_DEFAULT,
			"func=F;exec=S;stdin=V;*on_complete=F;proctitle=S", &func_cbref,
			&cmdline, &inputlen, &input, &cb_cbref, &proctitle)) {
		msg_err ("cannot get parameters list: %e", err);

		if (err) {
			g_error_free (err);
		}

		return 0;
	}

	cbdata = g_malloc0 (sizeof (*cbdata));
	cbdata->cb_cbref = cb_cbref;
	cbdata->func_cbref = func_cbref;

	if (input) {
		cbdata->out_buf = g_string_new_len (input, inputlen);
		cbdata->out_pos = 0;
	}

	if (rspamd_socketpair (cbdata->sp, SOCK_STREAM) == -1) {
		msg_err ("cannot spawn socketpair: %s", strerror (errno));
		luaL_unref (L, LUA_REGISTRYINDEX, cbdata->func_cbref);
		luaL_unref (L, LUA_REGISTRYINDEX, cbdata->cb_cbref);
		g_free (cbdata);

		return 0;
	}

	actx = w->ctx;
	cbdata->wrk = w;
	cbdata->L = L;
	cbdata->event_loop = actx->event_loop;
	cbdata->sz = (guint64)-1;

	pid = fork ();

	if (pid == -1) {
		msg_err ("cannot spawn process: %s", strerror (errno));
		close (cbdata->sp[0]);
		close (cbdata->sp[1]);
		luaL_unref (L, LUA_REGISTRYINDEX, cbdata->func_cbref);
		luaL_unref (L, LUA_REGISTRYINDEX, cbdata->cb_cbref);
		g_free (cbdata);

		return 0;
	}
	else if (pid == 0) {
		/* Child */
		gint rc;
		gchar inbuf[4];

		rspamd_log_on_fork (w->cf->type, w->srv->cfg, w->srv->logger);
		rc = ottery_init (w->srv->cfg->libs_ctx->ottery_cfg);

		if (rc != OTTERY_ERR_NONE) {
			msg_err ("cannot initialize PRNG: %d", rc);
			abort ();
		}
		rspamd_random_seed_fast ();
#ifdef HAVE_EVUTIL_RNG_INIT
		evutil_secure_rng_init ();
#endif

		close (cbdata->sp[0]);
		/* Here we assume that we can block on writing results */
		rspamd_socket_blocking (cbdata->sp[1]);
		g_hash_table_remove_all (w->signal_events);
		ev_loop_destroy (cbdata->event_loop);

		if (proctitle) {
			setproctitle ("lua process: %s", proctitle);
		}
		else {
			setproctitle ("lua process: unnamed");
		}

		cbdata->event_loop = ev_loop_new (EVFLAG_SIGNALFD);
		rspamd_worker_unblock_signals ();
		rspamd_lua_execute_lua_subprocess (L, cbdata);

		/* Wait for parent to reply and exit */
		rc = read (cbdata->sp[1], inbuf, sizeof (inbuf));

		if (rc >= sizeof (inbuf) &&
			memcmp (inbuf, "\0\0\0\0", sizeof (inbuf)) == 0) {
			exit (EXIT_SUCCESS);
		}
		else {
			msg_err ("got invalid reply from parent");

			exit (EXIT_FAILURE);
		}

	}

	cbdata->cpid = pid;
	cbdata->io_buf = g_string_sized_new (8);
	/* Notify main */
	memset (&srv_cmd, 0, sizeof (srv_cmd));
	srv_cmd.type = RSPAMD_SRV_ON_FORK;
	srv_cmd.cmd.on_fork.state = child_create;
	srv_cmd.cmd.on_fork.cpid = pid;
	srv_cmd.cmd.on_fork.ppid = getpid ();
	rspamd_srv_send_command (w, cbdata->event_loop, &srv_cmd, -1, NULL, NULL);

	close (cbdata->sp[1]);
	rspamd_socket_nonblocking (cbdata->sp[0]);
	/* Parent */
	rspamd_worker_set_signal_handler (SIGCHLD, w, cbdata->event_loop,
			rspamd_lua_cld_handler,
			cbdata);

	/* Add result pipe waiting */
	ev_io_init (&cbdata->ev, rspamd_lua_subprocess_io, cbdata->sp[0], EV_READ);
	cbdata->ev.data = cbdata;
	ev_io_start (cbdata->event_loop, &cbdata->ev);

	return 0;
}

void
luaopen_worker (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{worker}", worker_reg);
}
