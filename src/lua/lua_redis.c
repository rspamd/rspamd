/* Copyright (c) 2010-2011, Vsevolod Stakhov
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
#include "dns.h"

#include "hiredis.h"
#include "async.h"
#include "adapters/libevent.h"

#define REDIS_DEFAULT_TIMEOUT 1.0

/***
 * @module rspamd_redis
 * This module implements redis asynchronous client for rspamd LUA API.
 * Here is an example of using of this module:
 * @example
local rspamd_redis = require "rspamd_redis"
local rspamd_logger = require "rspamd_logger"

local function symbol_callback(task)
	local redis_key = 'some_key'
	local function redis_cb(task, err, data)
		if not err then
			rspamd_logger.infox('redis returned %1=%2', redis_key, data)
		end
	end

	rspamd_redis.make_request(task, "127.0.0.1:6379", redis_cb,
		'GET', {redis_key})
	-- or in table form:
	-- rspamd_redis.make_request({task=task, host="127.0.0.1:6379,
	--	callback=redis_cb, timeout=2.0, cmd='GET', args={redis_key}})
end
 */

LUA_FUNCTION_DEF (redis, make_request);

static const struct luaL_reg redislib_m[] = {
	LUA_INTERFACE_DEF (redis, make_request),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

/**
 * Struct for userdata representation
 */
struct lua_redis_userdata {
	redisAsyncContext *ctx;
	lua_State *L;
	struct rspamd_task *task;
	struct event timeout;
	gchar *server;
	gchar *reqline;
	gchar **args;
	gint cbref;
	guint nargs;
	guint16 port;
	guint16 terminated;
};

static void
lua_redis_free_args (struct lua_redis_userdata *ud)
{
	guint i;

	if (ud->args) {
		for (i = 0; i < ud->nargs; i ++) {
			g_free (ud->args[i]);
		}

		g_free (ud->args);
	}
}

static void
lua_redis_fin (void *arg)
{
	struct lua_redis_userdata *ud = arg;

	if (ud->ctx) {
		ud->terminated = 1;
		redisAsyncFree (ud->ctx);
		lua_redis_free_args (ud);
		event_del (&ud->timeout);
		luaL_unref (ud->L, LUA_REGISTRYINDEX, ud->cbref);
	}
}

/**
 * Push error of redis request to lua callback
 * @param code
 * @param ud
 */
static void
lua_redis_push_error (const gchar *err,
	struct lua_redis_userdata *ud,
	gboolean connected)
{
	struct rspamd_task **ptask;

	/* Push error */
	lua_rawgeti (ud->L, LUA_REGISTRYINDEX, ud->cbref);
	ptask = lua_newuserdata (ud->L, sizeof (struct rspamd_task *));
	rspamd_lua_setclass (ud->L, "rspamd{task}", -1);

	*ptask = ud->task;
	/* String of error */
	lua_pushstring (ud->L, err);
	/* Data is nil */
	lua_pushnil (ud->L);
	if (lua_pcall (ud->L, 3, 0, 0) != 0) {
		msg_info ("call to callback failed: %s", lua_tostring (ud->L, -1));
	}

	if (connected) {
		remove_normal_event (ud->task->s, lua_redis_fin, ud);
	}
}

static void
lua_redis_push_reply (lua_State *L, const redisReply *r)
{
	guint i;

	switch (r->type) {
	case REDIS_REPLY_INTEGER:
		lua_pushinteger (L, r->integer);
		break;
	case REDIS_REPLY_NIL:
		/* XXX: not the best approach */
		lua_newuserdata (L, sizeof (gpointer));
		break;
	case REDIS_REPLY_STRING:
	case REDIS_REPLY_STATUS:
		lua_pushlstring (L, r->str, r->len);
		break;
	case REDIS_REPLY_ARRAY:
		lua_createtable (L, r->elements, 0);
		for (i = 0; i < r->elements; ++i) {
			lua_redis_push_reply (L, r->element[i]);
			lua_rawseti (L, -2, i + 1); /* Store sub-reply */
		}
		break;
	default: /* should not happen */
		msg_info ("unknown reply type: %d", r->type);
		break;
	}
}

/**
 * Push data of redis request to lua callback
 * @param r redis reply data
 * @param ud
 */
static void
lua_redis_push_data (const redisReply *r, struct lua_redis_userdata *ud)
{
	struct rspamd_task **ptask;

	/* Push error */
	lua_rawgeti (ud->L, LUA_REGISTRYINDEX, ud->cbref);
	ptask = lua_newuserdata (ud->L, sizeof (struct rspamd_task *));
	rspamd_lua_setclass (ud->L, "rspamd{task}", -1);

	*ptask = ud->task;
	/* Error is nil */
	lua_pushnil (ud->L);
	/* Data */
	lua_redis_push_reply (ud->L, r);

	if (lua_pcall (ud->L, 3, 0, 0) != 0) {
		msg_info ("call to callback failed: %s", lua_tostring (ud->L, -1));
	}

	remove_normal_event (ud->task->s, lua_redis_fin, ud);
}

/**
 * Callback for redis replies
 * @param c context of redis connection
 * @param r redis reply
 * @param priv userdata
 */
static void
lua_redis_callback (redisAsyncContext *c, gpointer r, gpointer priv)
{
	redisReply *reply = r;
	struct lua_redis_userdata *ud = priv;

	if (ud->terminated) {
		/* We are already at the termination stage, just go out */
		return;
	}

	if (c->err == 0) {
		if (r != NULL) {
			if (reply->type != REDIS_REPLY_ERROR) {
				lua_redis_push_data (reply, ud);
			}
			else {
				lua_redis_push_error (reply->str, ud, TRUE);
			}
		}
		else {
			lua_redis_push_error ("received no data from server", ud, TRUE);
		}
	}
	else {
		if (c->err == REDIS_ERR_IO) {
			lua_redis_push_error (strerror (errno), ud, TRUE);
		}
		else {
			lua_redis_push_error (c->errstr, ud, TRUE);
		}
	}
}

static void
lua_redis_timeout (int fd, short what, gpointer u)
{
	struct lua_redis_userdata *ud = u;

	msg_info ("timeout while querying redis server");
	lua_redis_push_error ("timeout while connecting the server", ud, TRUE);
}


static void
lua_redis_parse_args (lua_State *L, gint idx, const gchar *cmd,
		struct lua_redis_userdata *ud)
{
	gchar **args = NULL;
	gint top;

	if (idx != 0 && lua_type (L, idx) == LUA_TTABLE) {
		/* Get all arguments */
		lua_pushvalue (L, 5);
		lua_pushnil (L);
		top = 0;

		while (lua_next (L, -2) != 0) {
			if (lua_isstring (L, -1)) {
				top ++;
			}
			lua_pop (L, 1);
		}

		args = g_malloc ((top + 1) * sizeof (gchar *));
		lua_pushnil (L);
		args[0] = g_strdup (cmd);
		top = 1;

		while (lua_next (L, -2) != 0) {
			args[top++] = g_strdup (lua_tostring (L, -1));
			lua_pop (L, 1);
		}

		lua_pop (L, 1);
	}
	else {
		/* Use merely cmd */
		args = g_malloc (sizeof (gchar *));
		args[0] = g_strdup (cmd);
		top = 1;
	}

	ud->nargs = top;
	ud->args = args;
}

static void
lua_redis_connect_cb (const struct redisAsyncContext *c, int status)
{
	/*
	 * Workaround to prevent double close:
	 * https://groups.google.com/forum/#!topic/redis-db/mQm46XkIPOY
	 */
#if defined(HIREDIS_MAJOR) && HIREDIS_MAJOR == 0 && HIREDIS_MINOR <= 11
	struct redisAsyncContext *nc = (struct redisAsyncContext *)c;
	if (status == REDIS_ERR) {
		nc->c.fd = -1;
	}
#endif
}

/***
 * @function rspamd_redis.make_request({params})
 * Make request to redis server, params is a table of key=value arguments in any order
 * @param {task} task worker task object
 * @param {ip} host server address
 * @param {function} callback callback to be called in form `function (task, err, data)`
 * @param {string} cmd command to be sent to redis
 * @param {table} args numeric array of strings used as redis arguments
 * @param {number} timeout timeout in seconds for request (1.0 by default)
 * @return {boolean} `true` if a request has been scheduled
 */
static int
lua_redis_make_request (lua_State *L)
{
	struct lua_redis_userdata *ud;
	struct rspamd_lua_ip *addr = NULL;
	struct rspamd_task *task = NULL;
	const gchar *cmd = NULL;
	gint top, cbref = -1;
	struct timeval tv;
	gboolean ret = FALSE;
	gdouble timeout = REDIS_DEFAULT_TIMEOUT;

	if (lua_istable (L, 1)) {
		/* Table version */
		lua_pushstring (L, "task");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TUSERDATA) {
			task = lua_check_task (L, -1);
		}
		lua_pop (L, 1);

		lua_pushstring (L, "callback");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TFUNCTION) {
			/* This also pops function from the stack */
			cbref = luaL_ref (L, LUA_REGISTRYINDEX);
		}
		else {
			msg_err ("bad callback argument for lua redis");
			lua_pop (L, 1);
		}

		lua_pushstring (L, "cmd");
		lua_gettable (L, -2);
		cmd = lua_tostring (L, -1);
		lua_pop (L, 1);

		lua_pushstring (L, "host");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TUSERDATA) {
			addr = lua_check_ip (L, -1);
		}
		lua_pop (L, 1);

		lua_pushstring (L, "timeout");
		lua_gettable (L, -2);
		timeout = lua_tonumber (L, -1);
		lua_pop (L, 1);

		if (task != NULL && addr != NULL && cbref != -1 && cmd != NULL) {
			ud =
					rspamd_mempool_alloc (task->task_pool,
							sizeof (struct lua_redis_userdata));
			ud->task = task;
			ud->L = L;
			ud->cbref = cbref;
			lua_pushstring (L, "args");
			lua_redis_parse_args (L, -1, cmd, ud);
			ret = TRUE;
		}
		else {
			if (cbref != -1) {
				luaL_unref (L, LUA_REGISTRYINDEX, cbref);
			}

			msg_err ("incorrect function invocation");
		}
	}
	else if ((task = lua_check_task (L, 1)) != NULL) {
		addr = lua_check_ip (L, 2);
		top = lua_gettop (L);
		/* Now get callback */
		if (lua_isfunction (L, 3) && addr != NULL && addr->addr && top >= 4) {
			/* Create userdata */
			ud =
				rspamd_mempool_alloc (task->task_pool,
					sizeof (struct lua_redis_userdata));
			ud->task = task;
			ud->L = L;

			/* Pop other arguments */
			lua_pushvalue (L, 3);
			/* Get a reference */
			ud->cbref = luaL_ref (L, LUA_REGISTRYINDEX);

			cmd = luaL_checkstring (L, 4);
			if (top > 4) {
				lua_redis_parse_args (L, 5, cmd, ud);
			}
			else {
				lua_redis_parse_args (L, 0, cmd, ud);
			}

			ret = TRUE;
		}
		else {
			msg_err ("incorrect function invocation");
		}
	}

	if (ret) {
		ud->terminated = 0;
		ud->ctx = redisAsyncConnect (rspamd_inet_address_to_string (addr->addr),
				rspamd_inet_address_get_port (addr->addr));
		redisAsyncSetConnectCallback (ud->ctx, lua_redis_connect_cb);

		if (ud->ctx == NULL || ud->ctx->err) {
			ud->terminated = 1;
			redisAsyncFree (ud->ctx);
			lua_redis_free_args (ud);
			luaL_unref (ud->L, LUA_REGISTRYINDEX, ud->cbref);
			lua_pushboolean (L, FALSE);

			return 1;
		}
		redisLibeventAttach (ud->ctx, ud->task->ev_base);
		ret = redisAsyncCommandArgv (ud->ctx,
					lua_redis_callback,
					ud,
					ud->nargs,
					(const gchar **)ud->args,
					NULL);
		if (ret == REDIS_OK) {
			register_async_event (ud->task->s,
					lua_redis_fin,
					ud,
					g_quark_from_static_string ("lua redis"));

			double_to_tv (timeout, &tv);
			event_set (&ud->timeout, -1, EV_TIMEOUT, lua_redis_timeout, ud);
			event_base_set (ud->task->ev_base, &ud->timeout);
			event_add (&ud->timeout, &tv);
		}
		else {
			msg_info ("call to redis failed: %s", ud->ctx->errstr);
			ud->terminated = 1;
			lua_redis_free_args (ud);
			redisAsyncFree (ud->ctx);
			luaL_unref (ud->L, LUA_REGISTRYINDEX, ud->cbref);
		}
	}

	lua_pushboolean (L, ret);

	return 1;
}

static gint
lua_load_redis (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, redislib_m);

	return 1;
}
/**
 * Open redis library
 * @param L lua stack
 * @return
 */
void
luaopen_redis (lua_State * L)
{
	rspamd_lua_add_preload (L, "rspamd_redis", lua_load_redis);
}
