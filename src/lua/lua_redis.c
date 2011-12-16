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

#ifndef WITH_SYSTEM_HIREDIS
#include "hiredis.h"
#include "async.h"
#include "adapters/libevent.h"
#else
#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include <hiredis/adapters/libevent.h>
#endif


/**
 * Redis access API for lua from task object
 */

LUA_FUNCTION_DEF (redis, make_request);

static const struct luaL_reg    redislib_m[] = {
	LUA_INTERFACE_DEF (redis, make_request),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

/**
 * Struct for userdata representation
 */
struct lua_redis_userdata {
	redisAsyncContext *ctx;
	lua_State *L;
	struct worker_task *task;
	gint cbref;
	gchar *server;
	struct in_addr ina;
	gchar *reqline;
	guint16 port;
	f_str_t *args;
	guint args_num;
};

/**
 * Utility function to extract worker task from lua arguments
 * @param L lua stack
 * @return worker task object
 */
static struct worker_task      *
lua_check_task (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{task}");
	luaL_argcheck (L, ud != NULL, 1, "'task' expected");
	return ud ? *((struct worker_task **)ud) : NULL;
}

static void
lua_redis_fin (void *arg)
{
	struct lua_redis_userdata			*ud = arg;

	if (ud->ctx) {
		redisAsyncFree (ud->ctx);
		luaL_unref (ud->L, LUA_REGISTRYINDEX, ud->cbref);
	}
}

/**
 * Push error of redis request to lua callback
 * @param code
 * @param ud
 */
static void
lua_redis_push_error (const gchar *err, struct lua_redis_userdata *ud, gboolean connected)
{
	struct worker_task					**ptask;

	/* Push error */
	lua_rawgeti (ud->L, LUA_REGISTRYINDEX, ud->cbref);
	ptask = lua_newuserdata (ud->L, sizeof (struct worker_task *));
	lua_setclass (ud->L, "rspamd{task}", -1);

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

/**
 * Push data of redis request to lua callback
 * @param r redis reply data
 * @param ud
 */
static void
lua_redis_push_data (const redisReply *r, struct lua_redis_userdata *ud)
{
	struct worker_task					**ptask;

	/* Push error */
	lua_rawgeti (ud->L, LUA_REGISTRYINDEX, ud->cbref);
	ptask = lua_newuserdata (ud->L, sizeof (struct worker_task *));
	lua_setclass (ud->L, "rspamd{task}", -1);

	*ptask = ud->task;
	/* Error is nil */
	lua_pushnil (ud->L);
	/* Data */
	if (r->type == REDIS_REPLY_STRING) {
		lua_pushlstring (ud->L, r->str, r->len);
	}
	else if (r->type == REDIS_REPLY_INTEGER) {
		lua_pushnumber (ud->L, r->integer);
	}
	else if (r->type == REDIS_REPLY_STATUS) {
		lua_pushlstring (ud->L, r->str, r->len);
	}
	else {
		msg_info ("bad type is passed: %d", r->type);
		lua_pushnil (ud->L);
	}

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
	redisReply 							*reply = r;
	struct lua_redis_userdata			*ud = priv;

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
			lua_redis_push_error ("received no data from server", ud, FALSE);
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
/**
 * Make a real request to redis server and attach it to libevent cycle
 * @param ud userdata object
 * @return
 */
static gboolean
lua_redis_make_request_real (struct lua_redis_userdata *ud)
{
	ud->ctx = redisAsyncConnect (inet_ntoa (ud->ina), ud->port);
	if (ud->ctx == NULL || ud->ctx->err) {
		lua_redis_push_error (ud->ctx ? ud->ctx->errstr : "unknown error", ud, FALSE);
		return FALSE;
	}
	else {
		register_async_event (ud->task->s, lua_redis_fin, ud, FALSE);
	}
	redisLibeventAttach (ud->ctx, ud->task->ev_base);
	/* Make a request now */
	switch (ud->args_num) {
	case 0:
		redisAsyncCommand (ud->ctx, lua_redis_callback, ud, ud->reqline);
		break;
	case 1:
		redisAsyncCommand (ud->ctx, lua_redis_callback, ud, ud->reqline, ud->args[0].begin, ud->args[0].len);
		break;
	case 2:
		redisAsyncCommand (ud->ctx, lua_redis_callback, ud, ud->reqline, ud->args[0].begin, ud->args[0].len,
				ud->args[1].begin, ud->args[1].len);
		break;
	default:
		/* XXX: cannot handle more than 3 arguments */
		redisAsyncCommand (ud->ctx, lua_redis_callback, ud, ud->reqline, ud->args[0].begin, ud->args[0].len,
				ud->args[1].begin, ud->args[1].len,
				ud->args[2].begin, ud->args[2].len);
		break;
	}

	return TRUE;
}

/**
 * Get result of dns error
 * @param reply dns reply object
 * @param arg user data
 */
static void
lua_redis_dns_callback (struct rspamd_dns_reply *reply, gpointer arg)
{
	struct lua_redis_userdata			*ud = arg;
	union rspamd_reply_element			*elt;


	if (reply->code != DNS_RC_NOERROR) {
		lua_redis_push_error (dns_strerror (reply->code), ud, FALSE);
		return;
	}
	else {
		elt = reply->elements->data;
		memcpy (&ud->ina, &elt->a.addr[0], sizeof (struct in_addr));
		/* Make real request */
		lua_redis_make_request_real (ud);
	}
}

/**
 * Make request to redis server
 * @param task worker task object
 * @param server server to check
 * @param port port of redis server
 * @param callback callback to be called
 * @param request request line
 * @param args list of arguments
 * @return
 */
static int
lua_redis_make_request (lua_State *L)
{
	struct worker_task					*task;
	struct lua_redis_userdata			*ud;
	const gchar						 	*server, *tmp;
	guint								 port, i;

	if ((task = lua_check_task (L)) != NULL) {
		server = luaL_checkstring (L, 2);
		port = luaL_checkint (L, 3);
		/* Now get callback */
		if (lua_isfunction (L, 4) && server != NULL && port > 0 && port < G_MAXUINT16) {
			/* Create userdata */
			ud = memory_pool_alloc (task->task_pool, sizeof (struct lua_redis_userdata));
			ud->server = memory_pool_strdup (task->task_pool, server);
			ud->port = port;
			ud->task = task;
			ud->L = L;
			ud->ctx = NULL;
			/* Pop other arguments */
			lua_pushvalue (L, 4);
			/* Get a reference */
			ud->cbref = luaL_ref (L, LUA_REGISTRYINDEX);
			ud->reqline = memory_pool_strdup (task->task_pool, luaL_checkstring (L, 5));
			/* Now get remaining args */
			ud->args_num = lua_gettop (L) - 5;
			ud->args = memory_pool_alloc (task->task_pool, ud->args_num * sizeof (f_str_t));
			for (i = 0; i < ud->args_num; i ++) {
				tmp = lua_tolstring (L, i + 6, &ud->args[i].len);
				/* Make a copy of argument */
				ud->args[i].begin = memory_pool_alloc (task->task_pool, ud->args[i].len);
				memcpy (ud->args[i].begin, tmp, ud->args[i].len);
			}
			/* Now check whether we need to perform DNS request */
			if (inet_aton (ud->server, &ud->ina) == 0) {
				/* Need to make dns request */
				/* Resolve hostname */
				if (make_dns_request (task->resolver, task->s, task->task_pool, lua_redis_dns_callback, ud,
					DNS_REQUEST_A, ud->server)) {
					task->dns_requests ++;
					lua_pushboolean (L, TRUE);
				}
				else {
					msg_info ("failed to resolve %s", ud->server);
					lua_pushboolean (L, FALSE);
				}
			}
			else {
				if (! lua_redis_make_request_real (ud)) {
					lua_pushboolean (L, FALSE);
				}
				else {
					lua_pushboolean (L, TRUE);
				}
			}
		}
		else {
			msg_info ("function requred as 4-th argument");
			lua_pushboolean (L, FALSE);
		}
	}

	return 1;
}

/**
 * Open redis library
 * @param L lua stack
 * @return
 */
gint
luaopen_redis (lua_State * L)
{

	luaL_openlib (L, "rspamd_redis", redislib_m, 0);

	return 1;
}
