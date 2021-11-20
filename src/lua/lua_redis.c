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
#include "utlist.h"

#include "contrib/hiredis/hiredis.h"
#include "contrib/hiredis/async.h"

#define REDIS_DEFAULT_TIMEOUT 1.0

static const gchar *M = "rspamd lua redis";
static void *redis_null;

/***
 * @module rspamd_redis
 * This module implements redis asynchronous client for rspamd LUA API.
 * Here is an example of using of this module:
 * @example
local rspamd_redis = require "rspamd_redis"
local rspamd_logger = require "rspamd_logger"

local function symbol_callback(task)
	local redis_key = 'some_key'
	local function redis_cb(err, data)
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
LUA_FUNCTION_DEF (redis, make_request_sync);
LUA_FUNCTION_DEF (redis, connect);
LUA_FUNCTION_DEF (redis, connect_sync);
LUA_FUNCTION_DEF (redis, add_cmd);
LUA_FUNCTION_DEF (redis, exec);
LUA_FUNCTION_DEF (redis, gc);

static const struct luaL_reg redislib_f[] = {
	LUA_INTERFACE_DEF (redis, make_request),
	LUA_INTERFACE_DEF (redis, make_request_sync),
	LUA_INTERFACE_DEF (redis, connect),
	LUA_INTERFACE_DEF (redis, connect_sync),
	{NULL, NULL}
};

static const struct luaL_reg redislib_m[] = {
	LUA_INTERFACE_DEF (redis, add_cmd),
	LUA_INTERFACE_DEF (redis, exec),
	{"__gc", lua_redis_gc},
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

#undef REDIS_DEBUG_REFS
#ifdef REDIS_DEBUG_REFS
#define REDIS_RETAIN(x) do { \
	msg_err ("retain ref %p, refcount: %d", (x), (x)->ref.refcount); \
	REF_RETAIN(x);	\
} while (0)

#define REDIS_RELEASE(x) do { \
	msg_err ("release ref %p, refcount: %d", (x), (x)->ref.refcount); \
	REF_RELEASE(x);	\
} while (0)
#else
#define REDIS_RETAIN REF_RETAIN
#define REDIS_RELEASE REF_RELEASE
#endif

struct lua_redis_request_specific_userdata;
/**
 * Struct for userdata representation
 */
struct lua_redis_userdata {
	redisAsyncContext *ctx;
	struct rspamd_task *task;
	struct rspamd_symcache_item *item;
	struct rspamd_async_session *s;
	struct ev_loop *event_loop;
	struct rspamd_config *cfg;
	struct rspamd_redis_pool *pool;
	gchar *server;
	gchar log_tag[RSPAMD_LOG_ID_LEN + 1];
	struct lua_redis_request_specific_userdata *specific;
	gdouble timeout;
	guint16 port;
	guint16 terminated;
};

#define msg_debug_lua_redis(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_lua_redis_log_id, "lua_redis", ud->log_tag, \
        G_STRFUNC, \
        __VA_ARGS__)
INIT_LOG_MODULE(lua_redis)

#define LUA_REDIS_SPECIFIC_REPLIED (1 << 0)
/* session was finished */
#define LUA_REDIS_SPECIFIC_FINISHED (1 << 1)
#define LUA_REDIS_ASYNC (1 << 0)
#define LUA_REDIS_TEXTDATA (1 << 1)
#define LUA_REDIS_TERMINATED (1 << 2)
#define LUA_REDIS_NO_POOL (1 << 3)
#define LUA_REDIS_SUBSCRIBED (1 << 4)
#define IS_ASYNC(ctx) ((ctx)->flags & LUA_REDIS_ASYNC)

struct lua_redis_request_specific_userdata {
	gint cbref;
	guint nargs;
	gchar **args;
	gsize *arglens;
	struct lua_redis_userdata *c;
	struct lua_redis_ctx *ctx;
	struct lua_redis_request_specific_userdata *next;
	ev_timer timeout_ev;
	guint flags;
};

struct lua_redis_ctx {
	guint flags;
	struct lua_redis_userdata async;
	guint cmds_pending;
	ref_entry_t ref;
	GQueue *replies; /* for sync connection only */
	GQueue *events_cleanup; /* for sync connection only */
	struct thread_entry *thread; /* for sync mode, set only if there was yield */
};

struct lua_redis_result {
	gboolean is_error;
	gint result_ref;
	struct rspamd_symcache_item *item;
	struct rspamd_async_session *s;
	struct rspamd_task *task;
	struct lua_redis_request_specific_userdata *sp_ud;
};

static struct lua_redis_ctx *
lua_check_redis (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{redis}");
	luaL_argcheck (L, ud != NULL, pos, "'redis' expected");
	return ud ? *((struct lua_redis_ctx **)ud) : NULL;
}

static void
lua_redis_free_args (char **args, gsize *arglens, guint nargs)
{
	guint i;

	if (args) {
		for (i = 0; i < nargs; i ++) {
			g_free (args[i]);
		}

		g_free (args);
		g_free (arglens);
	}
}

static void
lua_redis_dtor (struct lua_redis_ctx *ctx)
{
	struct lua_redis_userdata *ud;
	struct lua_redis_request_specific_userdata *cur, *tmp;
	gboolean is_successful = TRUE;
	struct redisAsyncContext *ac;

	ud = &ctx->async;
	msg_debug_lua_redis ("desctructing %p", ctx);

	if (ud->ctx) {

		LL_FOREACH_SAFE (ud->specific, cur, tmp) {
			ev_timer_stop (ud->event_loop, &cur->timeout_ev);

			if (!(cur->flags & LUA_REDIS_SPECIFIC_REPLIED)) {
				is_successful = FALSE;
			}

			cur->flags |= LUA_REDIS_SPECIFIC_FINISHED;
		}

		ctx->flags |= LUA_REDIS_TERMINATED;

		ud->terminated = 1;
		ac = ud->ctx;
		ud->ctx = NULL;

		if (!is_successful) {
			rspamd_redis_pool_release_connection (ud->pool, ac,
					RSPAMD_REDIS_RELEASE_FATAL);
		}
		else {
			rspamd_redis_pool_release_connection (ud->pool, ac,
					(ctx->flags & LUA_REDIS_NO_POOL) ?
					RSPAMD_REDIS_RELEASE_ENFORCE : RSPAMD_REDIS_RELEASE_DEFAULT);
		}

	}

	LL_FOREACH_SAFE (ud->specific, cur, tmp) {
		lua_redis_free_args (cur->args, cur->arglens, cur->nargs);

		if (cur->cbref != -1) {
			luaL_unref (ud->cfg->lua_state, LUA_REGISTRYINDEX, cur->cbref);
		}

		g_free (cur);
	}

	if (ctx->events_cleanup) {
		g_queue_free (ctx->events_cleanup);
		ctx->events_cleanup = NULL;
	}
	if (ctx->replies) {
		g_queue_free (ctx->replies);
		ctx->replies = NULL;
	}

	g_free (ctx);
}

static gint
lua_redis_gc (lua_State *L)
{
	struct lua_redis_ctx *ctx = lua_check_redis (L, 1);

	if (ctx) {
		REDIS_RELEASE (ctx);
	}

	return 0;
}

static void
lua_redis_fin (void *arg)
{
	struct lua_redis_request_specific_userdata *sp_ud = arg;
	struct lua_redis_userdata *ud;
	struct lua_redis_ctx *ctx;

	ctx = sp_ud->ctx;
	ud = sp_ud->c;

	if (ev_can_stop (&sp_ud->timeout_ev)) {
		ev_timer_stop (sp_ud->ctx->async.event_loop, &sp_ud->timeout_ev);
	}

	msg_debug_lua_redis ("finished redis query %p from session %p; refcount=%d",
			sp_ud, ctx, ctx->ref.refcount);
	sp_ud->flags |= LUA_REDIS_SPECIFIC_FINISHED;

	REDIS_RELEASE (ctx);
}

/**
 * Push error of redis request to lua callback
 * @param code
 * @param ud
 */
static void
lua_redis_push_error (const gchar *err,
	struct lua_redis_ctx *ctx,
	struct lua_redis_request_specific_userdata *sp_ud,
	gboolean connected)
{
	struct lua_redis_userdata *ud = sp_ud->c;
	struct lua_callback_state cbs;
	lua_State *L;

	if (!(sp_ud->flags & (LUA_REDIS_SPECIFIC_REPLIED|LUA_REDIS_SPECIFIC_FINISHED))) {
		if (sp_ud->cbref != -1) {

			lua_thread_pool_prepare_callback (ud->cfg->lua_thread_pool, &cbs);
			L = cbs.L;

			lua_pushcfunction (L, &rspamd_lua_traceback);
			int err_idx = lua_gettop (L);
			/* Push error */
			lua_rawgeti (cbs.L, LUA_REGISTRYINDEX, sp_ud->cbref);

			/* String of error */
			lua_pushstring (cbs.L, err);
			/* Data is nil */
			lua_pushnil (cbs.L);

			if (ud->item) {
				rspamd_symcache_set_cur_item (ud->task, ud->item);
			}

			if (lua_pcall (cbs.L, 2, 0, err_idx) != 0) {
				msg_info ("call to callback failed: %s", lua_tostring (cbs.L, -1));
			}

			lua_settop (L, err_idx - 1);
			lua_thread_pool_restore_callback (&cbs);
		}

		sp_ud->flags |= LUA_REDIS_SPECIFIC_REPLIED;

		if (connected && ud->s) {
			if (ud->item) {
				rspamd_symcache_item_async_dec_check (ud->task, ud->item, M);
			}

			rspamd_session_remove_event (ud->s, lua_redis_fin, sp_ud);
		}
		else {
			lua_redis_fin (sp_ud);
		}
	}
}

static void
lua_redis_push_reply (lua_State *L, const redisReply *r, gboolean text_data)
{
	guint i;
	struct rspamd_lua_text *t;

	switch (r->type) {
	case REDIS_REPLY_INTEGER:
		lua_pushinteger (L, r->integer);
		break;
	case REDIS_REPLY_NIL:
		lua_getfield (L, LUA_REGISTRYINDEX, "redis.null");
		break;
	case REDIS_REPLY_STRING:
	case REDIS_REPLY_STATUS:
		if (text_data) {
			t = lua_newuserdata (L, sizeof (*t));
			rspamd_lua_setclass (L, "rspamd{text}", -1);
			t->flags = 0;
			t->start = r->str;
			t->len = r->len;
		}
		else {
			lua_pushlstring (L, r->str, r->len);
		}
		break;
	case REDIS_REPLY_ARRAY:
		lua_createtable (L, r->elements, 0);
		for (i = 0; i < r->elements; ++i) {
			lua_redis_push_reply (L, r->element[i], text_data);
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
lua_redis_push_data (const redisReply *r, struct lua_redis_ctx *ctx,
		struct lua_redis_request_specific_userdata *sp_ud)
{
	struct lua_redis_userdata *ud = sp_ud->c;
	struct lua_callback_state cbs;
	lua_State *L;

	if (!(sp_ud->flags & (LUA_REDIS_SPECIFIC_REPLIED|LUA_REDIS_SPECIFIC_FINISHED)) ||
			(sp_ud->flags & LUA_REDIS_SUBSCRIBED)) {
		if (sp_ud->cbref != -1) {
			lua_thread_pool_prepare_callback (ud->cfg->lua_thread_pool, &cbs);
			L = cbs.L;

			lua_pushcfunction (L, &rspamd_lua_traceback);
			int err_idx = lua_gettop (L);
			/* Push error */
			lua_rawgeti (cbs.L, LUA_REGISTRYINDEX, sp_ud->cbref);
			/* Error is nil */
			lua_pushnil (cbs.L);
			/* Data */
			lua_redis_push_reply (cbs.L, r, ctx->flags & LUA_REDIS_TEXTDATA);

			if (ud->item) {
				rspamd_symcache_set_cur_item (ud->task, ud->item);
			}

			gint ret = lua_pcall (cbs.L, 2, 0, err_idx);

			if (ret != 0) {
				msg_info ("call to lua_redis callback failed (%d): %s",
						ret, lua_tostring (cbs.L, -1));
			}

			lua_settop (L, err_idx - 1);
			lua_thread_pool_restore_callback (&cbs);
		}

		if (sp_ud->flags & LUA_REDIS_SUBSCRIBED) {
			if (!(sp_ud->flags & LUA_REDIS_SPECIFIC_REPLIED)) {
				if (ev_can_stop (&sp_ud->timeout_ev)) {
					ev_timer_stop (sp_ud->ctx->async.event_loop,
							&sp_ud->timeout_ev);
				}
			}
		}

		sp_ud->flags |= LUA_REDIS_SPECIFIC_REPLIED;

		if (!(sp_ud->flags & LUA_REDIS_SUBSCRIBED)) {
			if (ud->s) {
				if (ud->item) {
					rspamd_symcache_item_async_dec_check (ud->task,
							ud->item, M);
				}

				rspamd_session_remove_event (ud->s, lua_redis_fin, sp_ud);
			}
			else {
				lua_redis_fin (sp_ud);
			}
		}
	}
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
	struct lua_redis_request_specific_userdata *sp_ud = priv;
	struct lua_redis_ctx *ctx;
	struct lua_redis_userdata *ud;
	redisAsyncContext *ac;

	ctx = sp_ud->ctx;
	ud = sp_ud->c;

	if (ud->terminated) {
		/* We are already at the termination stage, just go out */
		return;
	}

	msg_debug_lua_redis ("got reply from redis %p for query %p", sp_ud->c->ctx,
			sp_ud);

	REDIS_RETAIN (ctx);

	/* If session is finished, we cannot call lua callbacks */
	if (!(sp_ud->flags & LUA_REDIS_SPECIFIC_FINISHED) ||
			(sp_ud->flags & LUA_REDIS_SUBSCRIBED)) {
		if (c->err == 0) {
			if (r != NULL) {
				if (reply->type != REDIS_REPLY_ERROR) {
					lua_redis_push_data (reply, ctx, sp_ud);
				}
				else {
					lua_redis_push_error (reply->str, ctx, sp_ud, TRUE);
				}
			}
			else {
				lua_redis_push_error ("received no data from server", ctx, sp_ud, TRUE);
			}
		}
		else {
			if (c->err == REDIS_ERR_IO) {
				lua_redis_push_error (strerror (errno), ctx, sp_ud, TRUE);
			}
			else {
				lua_redis_push_error (c->errstr, ctx, sp_ud, TRUE);
			}
		}
	}

	if (!(sp_ud->flags & LUA_REDIS_SUBSCRIBED)) {
		ctx->cmds_pending--;

		if (ctx->cmds_pending == 0 && !ud->terminated) {
			/* Disconnect redis early as we don't need it anymore */
			ud->terminated = 1;
			ac = ud->ctx;
			ud->ctx = NULL;

			if (ac) {
				msg_debug_lua_redis ("release redis connection ud=%p; ctx=%p; refcount=%d",
						ud, ctx, ctx->ref.refcount);
				rspamd_redis_pool_release_connection (ud->pool, ac,
						(ctx->flags & LUA_REDIS_NO_POOL) ?
						RSPAMD_REDIS_RELEASE_ENFORCE : RSPAMD_REDIS_RELEASE_DEFAULT);
			}
		}
	}

	REDIS_RELEASE (ctx);
}

static gint
lua_redis_push_results (struct lua_redis_ctx *ctx, lua_State *L)
{
	gint results = g_queue_get_length (ctx->replies);
	gint i;
	gboolean can_use_lua = TRUE;

	results = g_queue_get_length (ctx->replies);

	if (!lua_checkstack (L, (results * 2) + 1)) {
		luaL_error (L, "cannot resize stack to fit %d commands",
				ctx->cmds_pending);

		can_use_lua = FALSE;
	}

	for (i = 0; i < results; i ++) {
		struct lua_redis_result *result = g_queue_pop_head (ctx->replies);

		if (can_use_lua) {
			lua_pushboolean (L, !result->is_error);
			lua_rawgeti (L, LUA_REGISTRYINDEX, result->result_ref);
		}

		luaL_unref (L, LUA_REGISTRYINDEX, result->result_ref);

		g_queue_push_tail (ctx->events_cleanup, result);
	}

	return can_use_lua ? results * 2 : 0;
}

static void
lua_redis_cleanup_events (struct lua_redis_ctx *ctx)
{
	REDIS_RETAIN (ctx); /* To avoid preliminary destruction */

	while (!g_queue_is_empty (ctx->events_cleanup)) {
		struct lua_redis_result *result = g_queue_pop_head (ctx->events_cleanup);

		if (result->item) {
			rspamd_symcache_item_async_dec_check (result->task, result->item, M);
		}

		if (result->s) {
			rspamd_session_remove_event (result->s, lua_redis_fin, result->sp_ud);
		}
		else {
			lua_redis_fin (result->sp_ud);
		}

		g_free (result);
	}

	REDIS_RELEASE (ctx);
}

/**
 * Callback for redis replies
 * @param c context of redis connection
 * @param r redis reply
 * @param priv userdata
 */
static void
lua_redis_callback_sync (redisAsyncContext *ac, gpointer r, gpointer priv)
{
	redisReply *reply = r;

	struct lua_redis_request_specific_userdata *sp_ud = priv;
	struct lua_redis_ctx *ctx;
	struct lua_redis_userdata *ud;
	struct thread_entry* thread;
	gint results;

	ctx = sp_ud->ctx;
	ud = sp_ud->c;
	lua_State *L = ctx->async.cfg->lua_state;

	sp_ud->flags |= LUA_REDIS_SPECIFIC_REPLIED;

	if (ud->terminated) {
		/* We are already at the termination stage, just go out */
		/* TODO:
		   if somebody is waiting for us (ctx->thread), return result,
		   otherwise, indeed, ignore
		 */
		return;
	}

	if (ev_can_stop ( &sp_ud->timeout_ev)) {
		ev_timer_stop (ud->event_loop, &sp_ud->timeout_ev);
	}

	if (!(sp_ud->flags & LUA_REDIS_SPECIFIC_FINISHED)) {
		msg_debug_lua_redis ("got reply from redis: %p for query %p", ac, sp_ud);

		struct lua_redis_result *result = g_malloc0 (sizeof *result);

		if (ac->err == 0) {
			if (r != NULL) {
				if (reply->type != REDIS_REPLY_ERROR) {
					result->is_error = FALSE;
					lua_redis_push_reply (L, reply, ctx->flags & LUA_REDIS_TEXTDATA);
				}
				else {
					result->is_error = TRUE;
					lua_pushstring (L, reply->str);
				}
			}
			else {
				result->is_error = TRUE;
				lua_pushliteral (L, "received no data from server");
			}
		}
		else {
			result->is_error = TRUE;
			if (ac->err == REDIS_ERR_IO) {
				lua_pushstring (L, strerror (errno));
			}
			else {
				lua_pushstring (L, ac->errstr);
			}
		}

		/* if error happened, we should terminate the connection,
		   and release it */

		if (result->is_error && sp_ud->c->ctx) {
			ac = sp_ud->c->ctx;
			/* Set to NULL to avoid double free in dtor */
			sp_ud->c->ctx = NULL;
			ctx->flags |= LUA_REDIS_TERMINATED;

			/*
			 * This will call all callbacks pending so the entire context
			 * will be destructed
			 */
			rspamd_redis_pool_release_connection (sp_ud->c->pool, ac,
					RSPAMD_REDIS_RELEASE_FATAL);
		}

		result->result_ref = luaL_ref (L, LUA_REGISTRYINDEX);
		result->s = ud->s;
		result->item = ud->item;
		result->task = ud->task;
		result->sp_ud = sp_ud;

		g_queue_push_tail (ctx->replies, result);

	}

	ctx->cmds_pending --;

	if (ctx->cmds_pending == 0) {
		if (ctx->thread) {
			if (!(sp_ud->flags & LUA_REDIS_SPECIFIC_FINISHED)) {
				/* somebody yielded and waits for results */
				thread = ctx->thread;
				ctx->thread = NULL;

				results = lua_redis_push_results(ctx, thread->lua_state);
				lua_thread_resume (thread, results);
				lua_redis_cleanup_events(ctx);
			}
			else {
				/* We cannot resume the thread as the associated task has gone */
				lua_thread_pool_terminate_entry_full (ud->cfg->lua_thread_pool,
						ctx->thread, G_STRLOC, true);
				ctx->thread = NULL;
			}
		}
	}

}

static void
lua_redis_timeout_sync (EV_P_ ev_timer *w, int revents)
{
	struct lua_redis_request_specific_userdata *sp_ud =
			(struct lua_redis_request_specific_userdata *)w->data;
	struct lua_redis_ctx *ctx;
	struct lua_redis_userdata *ud;
	redisAsyncContext *ac;

	if (sp_ud->flags & LUA_REDIS_SPECIFIC_FINISHED) {
		return;
	}

	ud = sp_ud->c;
	ctx = sp_ud->ctx;
	msg_debug_lua_redis ("timeout while querying redis server: %p, redis: %p", sp_ud,
			sp_ud->c->ctx);

	if (sp_ud->c->ctx) {
		ac = sp_ud->c->ctx;

		/* Set to NULL to avoid double free in dtor */
		sp_ud->c->ctx = NULL;
		ac->err = REDIS_ERR_IO;
		errno = ETIMEDOUT;
		ctx->flags |= LUA_REDIS_TERMINATED;

		/*
		 * This will call all callbacks pending so the entire context
		 * will be destructed
		 */
		rspamd_redis_pool_release_connection (sp_ud->c->pool, ac,
				RSPAMD_REDIS_RELEASE_FATAL);
	}
}

static void
lua_redis_timeout (EV_P_ ev_timer *w, int revents)
{
	struct lua_redis_request_specific_userdata *sp_ud =
			(struct lua_redis_request_specific_userdata *)w->data;
	struct lua_redis_userdata *ud;
	struct lua_redis_ctx *ctx;
	redisAsyncContext *ac;

	if (sp_ud->flags & LUA_REDIS_SPECIFIC_FINISHED) {
		return;
	}

	ctx = sp_ud->ctx;
	ud = sp_ud->c;

	REDIS_RETAIN (ctx);
	msg_debug_lua_redis ("timeout while querying redis server: %p, redis: %p", sp_ud,
			sp_ud->c->ctx);
	lua_redis_push_error ("timeout while connecting the server", ctx, sp_ud, TRUE);

	if (sp_ud->c->ctx) {
		ac = sp_ud->c->ctx;
		/* Set to NULL to avoid double free in dtor */
		sp_ud->c->ctx = NULL;
		ac->err = REDIS_ERR_IO;
		errno = ETIMEDOUT;
		/*
		 * This will call all callbacks pending so the entire context
		 * will be destructed
		 */
		rspamd_redis_pool_release_connection (sp_ud->c->pool, ac,
				RSPAMD_REDIS_RELEASE_FATAL);
	}

	REDIS_RELEASE (ctx);
}


static void
lua_redis_parse_args (lua_State *L, gint idx, const gchar *cmd,
		gchar ***pargs, gsize **parglens, guint *nargs)
{
	gchar **args = NULL;
	gsize *arglens;
	gint top;

	if (idx != 0 && lua_type (L, idx) == LUA_TTABLE) {
		/* Get all arguments */
		lua_pushvalue (L, idx);
		lua_pushnil (L);
		top = 0;

		while (lua_next (L, -2) != 0) {
			gint type = lua_type (L, -1);

			if (type == LUA_TNUMBER || type == LUA_TSTRING ||
					type == LUA_TUSERDATA) {
				top ++;
			}
			lua_pop (L, 1);
		}

		args = g_malloc ((top + 1) * sizeof (gchar *));
		arglens = g_malloc ((top + 1) * sizeof (gsize));
		arglens[0] = strlen (cmd);
		args[0] = g_malloc (arglens[0]);
		memcpy (args[0], cmd, arglens[0]);
		top = 1;
		lua_pushnil (L);

		while (lua_next (L, -2) != 0) {
			gint type = lua_type (L, -1);

			if (type == LUA_TSTRING) {
				const gchar *s;

				s = lua_tolstring (L, -1, &arglens[top]);
				args[top] = g_malloc (arglens[top]);
				memcpy (args[top], s, arglens[top]);
				top ++;
			}
			else if (type == LUA_TUSERDATA) {
				struct rspamd_lua_text *t;

				t = lua_check_text (L, -1);

				if (t && t->start) {
					arglens[top] = t->len;
					args[top] = g_malloc (arglens[top]);
					memcpy (args[top], t->start, arglens[top]);
					top ++;
				}
			}
			else if (type == LUA_TNUMBER) {
				gdouble val = lua_tonumber (L, -1);
				gint r;
				gchar numbuf[64];

				if (val == (gdouble)((gint64)val)) {
					r = rspamd_snprintf (numbuf, sizeof (numbuf), "%L",
							(gint64)val);
				}
				else {
					r = rspamd_snprintf (numbuf, sizeof (numbuf), "%f",
							val);
				}

				arglens[top] = r;
				args[top] = g_malloc (arglens[top]);
				memcpy (args[top], numbuf, arglens[top]);
				top ++;
			}

			lua_pop (L, 1);
		}

		lua_pop (L, 1);
	}
	else {
		/* Use merely cmd */

		args = g_malloc (sizeof (gchar *));
		arglens = g_malloc (sizeof (gsize));
		arglens[0] = strlen (cmd);
		args[0] = g_malloc (arglens[0]);
		memcpy (args[0], cmd, arglens[0]);
		top = 1;
	}

	*pargs = args;
	*parglens = arglens;
	*nargs = top;
}

static struct lua_redis_ctx *
rspamd_lua_redis_prepare_connection (lua_State *L, gint *pcbref, gboolean is_async)
{
	struct lua_redis_ctx *ctx = NULL;
	rspamd_inet_addr_t *ip = NULL;
	struct lua_redis_userdata *ud = NULL;
	struct rspamd_lua_ip *addr = NULL;
	struct rspamd_task *task = NULL;
	const gchar *host = NULL;
	const gchar *password = NULL, *dbname = NULL, *log_tag = NULL;
	gint cbref = -1;
	struct rspamd_config *cfg = NULL;
	struct rspamd_async_session *session = NULL;
	struct ev_loop *ev_base = NULL;
	gboolean ret = FALSE;
	guint flags = 0;

	if (lua_istable (L, 1)) {
		/* Table version */
		lua_pushvalue (L, 1);
		lua_pushstring (L, "task");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TUSERDATA) {
			task = lua_check_task_maybe (L, -1);
		}
		lua_pop (L, 1);

		if (!task) {
			/* We need to get ev_base, config and session separately */
			lua_pushstring (L, "config");
			lua_gettable (L, -2);
			if (lua_type (L, -1) == LUA_TUSERDATA) {
				cfg = lua_check_config (L, -1);
			}
			lua_pop (L, 1);

			lua_pushstring (L, "session");
			lua_gettable (L, -2);
			if (lua_type (L, -1) == LUA_TUSERDATA) {
				session = lua_check_session (L, -1);
			}
			lua_pop (L, 1);

			lua_pushstring (L, "ev_base");
			lua_gettable (L, -2);
			if (lua_type (L, -1) == LUA_TUSERDATA) {
				ev_base = lua_check_ev_base (L, -1);
			}
			lua_pop (L, 1);

			if (cfg && ev_base) {
				ret = TRUE;
			}
			else if (!cfg) {
				msg_err_task_check ("config is not passed");
			}
			else {
				msg_err_task_check ("ev_base is not set");
			}
		}
		else {
			cfg = task->cfg;
			session = task->s;
			ev_base = task->event_loop;
			log_tag = task->task_pool->tag.uid;
			ret = TRUE;

		}

		if (pcbref) {
			lua_pushstring (L, "callback");
			lua_gettable (L, -2);
			if (lua_type (L, -1) == LUA_TFUNCTION) {
				/* This also pops function from the stack */
				cbref = luaL_ref (L, LUA_REGISTRYINDEX);
				*pcbref = cbref;
			}
			else {
				*pcbref = -1;
				lua_pop (L, 1);
			}
		}

		lua_pushstring (L, "host");
		lua_gettable (L, -2);

		if (lua_type (L, -1) == LUA_TUSERDATA) {
			addr = lua_check_ip (L, -1);
			host = rspamd_inet_address_to_string_pretty (addr->addr);
		}
		else if (lua_type (L, -1) == LUA_TSTRING) {
			host = lua_tostring (L, -1);

			if (rspamd_parse_inet_address (&ip,
					host, strlen (host), RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
				addr = g_alloca (sizeof (*addr));
				addr->addr = ip;

				if (rspamd_inet_address_get_port (ip) == 0) {
					rspamd_inet_address_set_port (ip, 6379);
				}
			}
		}
		lua_pop (L, 1);

		lua_pushstring (L, "password");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TSTRING) {
			password = lua_tostring (L, -1);
		}
		lua_pop (L, 1);

		lua_pushstring (L, "dbname");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TSTRING) {
			dbname = lua_tostring (L, -1);
		}
		lua_pop (L, 1);

		lua_pushstring (L, "opaque_data");
		lua_gettable (L, -2);
		if (!!lua_toboolean (L, -1)) {
			flags |= LUA_REDIS_TEXTDATA;
		}
		lua_pop (L, 1);

		lua_pushstring (L, "no_pool");
		lua_gettable (L, -2);
		if (!!lua_toboolean (L, -1)) {
			flags |= LUA_REDIS_NO_POOL;
		}
		lua_pop (L, 1);

		lua_pop (L, 1); /* table */

		if (session && rspamd_session_blocked (session)) {
			msg_err_task_check ("Session is being destroying");
			ret = FALSE;
		}

		if (ret && addr != NULL) {
			ctx = g_malloc0 (sizeof (struct lua_redis_ctx));
			REF_INIT_RETAIN (ctx, lua_redis_dtor);
			if (is_async) {
				ctx->flags |= flags | LUA_REDIS_ASYNC;
				ud = &ctx->async;
			}
			else {
				ud = &ctx->async;
				ctx->replies = g_queue_new ();
				ctx->events_cleanup = g_queue_new ();

			}

			ud->s = session;
			ud->cfg = cfg;
			ud->pool = cfg->redis_pool;
			ud->event_loop = ev_base;
			ud->task = task;

			if (log_tag) {
				rspamd_strlcpy (ud->log_tag, log_tag, sizeof (ud->log_tag));
			}
			else {
				/* Use pointer itself as a tag */
				rspamd_snprintf (ud->log_tag, sizeof (ud->log_tag),
						"%ud",
						(int)rspamd_cryptobox_fast_hash (&ud, sizeof (ud), 0));
			}

			if (task) {
				ud->item = rspamd_symcache_get_cur_item (task);
			}

			ret = TRUE;
		}
		else {
			if (cbref != -1) {
				luaL_unref (L, LUA_REGISTRYINDEX, cbref);
			}

			msg_err_task_check ("incorrect function invocation");
			ret = FALSE;
		}
	}

	if (ret) {
		ud->terminated = 0;
		ud->ctx = rspamd_redis_pool_connect (ud->pool,
				dbname, password,
				rspamd_inet_address_to_string (addr->addr),
				rspamd_inet_address_get_port (addr->addr));

		if (ip) {
			rspamd_inet_address_free (ip);
		}

		if (ud->ctx == NULL || ud->ctx->err) {
			if (ud->ctx) {
				msg_err_task_check ("cannot connect to redis: %s",
						ud->ctx->errstr);
				rspamd_redis_pool_release_connection (ud->pool, ud->ctx,
						RSPAMD_REDIS_RELEASE_FATAL);
				ud->ctx = NULL;
			}
			else {
				msg_err_task_check ("cannot connect to redis (OS error): %s",
						strerror (errno));
			}

			REDIS_RELEASE (ctx);

			return NULL;
		}

		msg_debug_lua_redis ("opened redis connection host=%s; ctx=%p; ud=%p",
				host, ctx, ud);

		return ctx;
	}

	if (ip) {
		rspamd_inet_address_free (ip);
	}

	return NULL;
}

/***
 * @function rspamd_redis.make_request({params})
 * Make request to redis server, params is a table of key=value arguments in any order
 * @param {task} task worker task object
 * @param {ip|string} host server address
 * @param {function} callback callback to be called in form `function (task, err, data)`
 * @param {string} cmd command to be sent to redis
 * @param {table} args numeric array of strings used as redis arguments
 * @param {number} timeout timeout in seconds for request (1.0 by default)
 * @return {boolean} `true` if a request has been scheduled
 */
static int
lua_redis_make_request (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_redis_request_specific_userdata *sp_ud;
	struct lua_redis_userdata *ud;
	struct lua_redis_ctx *ctx, **pctx;
	const gchar *cmd = NULL;
	gdouble timeout = REDIS_DEFAULT_TIMEOUT;
	gint cbref = -1;
	gboolean ret = FALSE;

	ctx = rspamd_lua_redis_prepare_connection (L, &cbref, TRUE);

	if (ctx) {
		ud = &ctx->async;
		sp_ud = g_malloc0 (sizeof (*sp_ud));
		sp_ud->cbref = cbref;
		sp_ud->c = ud;
		sp_ud->ctx = ctx;

		lua_pushstring (L, "cmd");
		lua_gettable (L, -2);
		cmd = lua_tostring (L, -1);
		lua_pop (L, 1);

		lua_pushstring (L, "timeout");
		lua_gettable (L, 1);
		if (lua_type (L, -1) == LUA_TNUMBER) {
			timeout = lua_tonumber (L, -1);
		}
		lua_pop (L, 1);
		ud->timeout = timeout;


		lua_pushstring (L, "args");
		lua_gettable (L, 1);
		lua_redis_parse_args (L, -1, cmd, &sp_ud->args, &sp_ud->arglens,
				&sp_ud->nargs);
		lua_pop (L, 1);
		LL_PREPEND (ud->specific, sp_ud);

		ret = redisAsyncCommandArgv (ud->ctx,
				lua_redis_callback,
				sp_ud,
				sp_ud->nargs,
				(const gchar **)sp_ud->args,
				sp_ud->arglens);

		if (ret == REDIS_OK) {
			if (ud->s) {
				rspamd_session_add_event (ud->s,
						lua_redis_fin, sp_ud,
						M);

				if (ud->item) {
					rspamd_symcache_item_async_inc (ud->task, ud->item, M);
				}
			}

			REDIS_RETAIN (ctx); /* Cleared by fin event */
			ctx->cmds_pending ++;

			if (ud->ctx->c.flags & REDIS_SUBSCRIBED) {
				msg_debug_lua_redis ("subscribe command, never unref/timeout");
				sp_ud->flags |= LUA_REDIS_SUBSCRIBED;
			}

			sp_ud->timeout_ev.data = sp_ud;
			ev_now_update_if_cheap ((struct ev_loop *)ud->event_loop);
			ev_timer_init (&sp_ud->timeout_ev, lua_redis_timeout, timeout, 0.0);
			ev_timer_start (ud->event_loop, &sp_ud->timeout_ev);

			ret = TRUE;
		}
		else {
			msg_info ("call to redis failed: %s", ud->ctx->errstr);
			rspamd_redis_pool_release_connection (ud->pool, ud->ctx,
					RSPAMD_REDIS_RELEASE_FATAL);
			ud->ctx = NULL;
			REDIS_RELEASE (ctx);
			ret = FALSE;
		}
	}
	else {
		lua_pushboolean (L, FALSE);
		lua_pushnil (L);

		return 2;
	}

	lua_pushboolean (L, ret);

	if (ret) {
		pctx = lua_newuserdata (L, sizeof (ctx));
		*pctx = ctx;
		rspamd_lua_setclass (L, "rspamd{redis}", -1);
	}
	else {
		lua_pushnil (L);
	}

	return 2;
}

/***
 * @function rspamd_redis.make_request_sync({params})
 * Make blocking request to redis server, params is a table of key=value arguments in any order
 * @param {ip|string} host server address
 * @param {string} cmd command to be sent to redis
 * @param {table} args numeric array of strings used as redis arguments
 * @param {number} timeout timeout in seconds for request (1.0 by default)
 * @return {boolean + result} `true` and a result if a request has been successful
 */
static int
lua_redis_make_request_sync (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_ip *addr = NULL;
	rspamd_inet_addr_t *ip = NULL;
	const gchar *cmd = NULL, *host;
	struct timeval tv;
	gboolean ret = FALSE;
	gdouble timeout = REDIS_DEFAULT_TIMEOUT;
	gchar **args = NULL;
	gsize *arglens = NULL;
	guint nargs = 0, flags = 0;
	redisContext *ctx;
	redisReply *r;

	if (lua_istable (L, 1)) {
		lua_pushvalue (L, 1);

		lua_pushstring (L, "cmd");
		lua_gettable (L, -2);
		cmd = lua_tostring (L, -1);
		lua_pop (L, 1);

		lua_pushstring (L, "host");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TUSERDATA) {
			addr = lua_check_ip (L, -1);
		}
		else if (lua_type (L, -1) == LUA_TSTRING) {
			host = lua_tostring (L, -1);
			if (rspamd_parse_inet_address (&ip,
					host, strlen (host), RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
				addr = g_alloca (sizeof (*addr));
				addr->addr = ip;

				if (rspamd_inet_address_get_port (ip) == 0) {
					rspamd_inet_address_set_port (ip, 6379);
				}
			}
		}
		lua_pop (L, 1);

		lua_pushstring (L, "timeout");
		lua_gettable (L, -2);
		if (lua_type (L, -1) == LUA_TNUMBER) {
			timeout = lua_tonumber (L, -1);
		}
		lua_pop (L, 1);

		lua_pushstring (L, "opaque_data");
		lua_gettable (L, -2);
		if (!!lua_toboolean (L, -1)) {
			flags |= LUA_REDIS_TEXTDATA;
		}
		lua_pop (L, 1);


		if (cmd) {
			lua_pushstring (L, "args");
			lua_gettable (L, -2);
			lua_redis_parse_args (L, -1, cmd, &args, &arglens, &nargs);
			lua_pop (L, 1);
		}

		lua_pop (L, 1);

		if (addr && cmd) {
			ret = TRUE;
		}
	}

	if (ret) {
		double_to_tv (timeout, &tv);

		if (rspamd_inet_address_get_af (addr->addr) == AF_UNIX) {
			ctx = redisConnectUnixWithTimeout (
					rspamd_inet_address_to_string (addr->addr), tv);
		}
		else {
			ctx = redisConnectWithTimeout (
					rspamd_inet_address_to_string (addr->addr),
					rspamd_inet_address_get_port (addr->addr), tv);
		}

		if (ip) {
			rspamd_inet_address_free (ip);
		}

		if (ctx == NULL || ctx->err) {
			redisFree (ctx);
			lua_redis_free_args (args, arglens, nargs);
			lua_pushboolean (L, FALSE);

			return 1;
		}

		r = redisCommandArgv (ctx,
					nargs,
					(const gchar **)args,
					arglens);

		if (r != NULL) {
			if (r->type != REDIS_REPLY_ERROR) {
				lua_pushboolean (L, TRUE);
				lua_redis_push_reply (L, r, flags & LUA_REDIS_TEXTDATA);
			}
			else {
				lua_pushboolean (L, FALSE);
				lua_pushstring (L, r->str);
			}

			freeReplyObject (r);
			redisFree (ctx);
			lua_redis_free_args (args, arglens, nargs);

			return 2;
		}
		else {
			msg_info ("call to redis failed: %s", ctx->errstr);
			redisFree (ctx);
			lua_redis_free_args (args, arglens, nargs);
			lua_pushboolean (L, FALSE);
		}
	}
	else {
		if (ip) {
			rspamd_inet_address_free (ip);
		}
		msg_err ("bad arguments for redis request");
		lua_redis_free_args (args, arglens, nargs);

		lua_pushboolean (L, FALSE);
	}

	return 1;
}

/***
 * @function rspamd_redis.connect({params})
 * Make request to redis server, params is a table of key=value arguments in any order
 * @param {task} task worker task object
 * @param {ip|string} host server address
 * @param {number} timeout timeout in seconds for request (1.0 by default)
 * @return {boolean,redis} new connection object or nil if connection failed
 */
static int
lua_redis_connect (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_redis_userdata *ud;
	struct lua_redis_ctx *ctx, **pctx;
	gdouble timeout = REDIS_DEFAULT_TIMEOUT;

	ctx = rspamd_lua_redis_prepare_connection (L, NULL, TRUE);

	if (ctx) {
		ud = &ctx->async;

		lua_pushstring (L, "timeout");
		lua_gettable (L, 1);
		if (lua_type (L, -1) == LUA_TNUMBER) {
			timeout = lua_tonumber (L, -1);
		}

		lua_pop (L, 1);
		ud->timeout = timeout;
	}
	else {
		lua_pushboolean (L, FALSE);
		lua_pushnil (L);

		return 2;
	}

	lua_pushboolean (L, TRUE);
	pctx = lua_newuserdata (L, sizeof (ctx));
	*pctx = ctx;
	rspamd_lua_setclass (L, "rspamd{redis}", -1);

	return 2;
}

/***
 * @function rspamd_redis.connect_sync({params})
 * Make blocking request to redis server, params is a table of key=value arguments in any order
 * @param {ip|string} host server address
 * @param {number} timeout timeout in seconds for request (1.0 by default)
 * @return {redis} redis object if a request has been successful
 */
static int
lua_redis_connect_sync (lua_State *L)
{
	LUA_TRACE_POINT;
	gdouble timeout = REDIS_DEFAULT_TIMEOUT;
	struct lua_redis_ctx *ctx, **pctx;

	ctx = rspamd_lua_redis_prepare_connection (L, NULL, FALSE);

	if (ctx) {
		if (lua_istable (L, 1)) {
			lua_pushstring (L, "timeout");
			lua_gettable (L, 1);
			if (lua_type (L, -1) == LUA_TNUMBER) {
				timeout = lua_tonumber (L, -1);
			}
			lua_pop (L, 1);
		}

		ctx->async.timeout = timeout;

		lua_pushboolean (L, TRUE);
		pctx = lua_newuserdata (L, sizeof (ctx));
		*pctx = ctx;
		rspamd_lua_setclass (L, "rspamd{redis}", -1);
	}
	else {
		lua_pushboolean (L, FALSE);
		lua_pushstring (L, "bad arguments for redis request");
		return 2;
	}

	return 2;
}

/***
 * @method rspamd_redis:add_cmd(cmd, {args})
 * Append new cmd to redis pipeline
 * @param {string} cmd command to be sent to redis
 * @param {table} args array of strings used as redis arguments
 * @return {boolean} `true` if a request has been successful
 */
static int
lua_redis_add_cmd (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_redis_ctx *ctx = lua_check_redis (L, 1);
	struct lua_redis_request_specific_userdata *sp_ud;
	struct lua_redis_userdata *ud;
	const gchar *cmd = NULL;
	gint args_pos = 2;
	gint cbref = -1, ret;

	if (ctx) {
		if (ctx->flags & LUA_REDIS_TERMINATED) {
			lua_pushboolean (L, FALSE);
			lua_pushstring (L, "Connection is terminated");

			return 2;
		}

		/* Async version */
		if (lua_type (L, 2) == LUA_TSTRING) {
			/* No callback version */
			cmd = lua_tostring (L, 2);
			args_pos = 3;
		}
		else if (lua_type (L, 2) == LUA_TFUNCTION) {
			lua_pushvalue (L, 2);
			cbref = luaL_ref (L, LUA_REGISTRYINDEX);
			cmd = lua_tostring (L, 3);
			args_pos = 4;
		}
		else {
			return luaL_error (L, "invalid arguments");
		}

		sp_ud = g_malloc0 (sizeof (*sp_ud));
		if (IS_ASYNC (ctx)) {
			sp_ud->c = &ctx->async;
			ud = &ctx->async;
			sp_ud->cbref = cbref;
		}
		else {
			sp_ud->c = &ctx->async;
			ud = &ctx->async;
		}
		sp_ud->ctx = ctx;

		lua_redis_parse_args (L, args_pos, cmd, &sp_ud->args,
					&sp_ud->arglens, &sp_ud->nargs);

		LL_PREPEND (sp_ud->c->specific, sp_ud);

		if (ud->s && rspamd_session_blocked (ud->s)) {
			lua_pushboolean (L, 0);
			lua_pushstring (L, "session is terminating");

			return 2;
		}

		if (IS_ASYNC (ctx)) {
			ret = redisAsyncCommandArgv (sp_ud->c->ctx,
					lua_redis_callback,
					sp_ud,
					sp_ud->nargs,
					(const gchar **)sp_ud->args,
					sp_ud->arglens);
		}
		else {
			ret = redisAsyncCommandArgv (sp_ud->c->ctx,
					lua_redis_callback_sync,
					sp_ud,
					sp_ud->nargs,
					(const gchar **)sp_ud->args,
					sp_ud->arglens);
		}

		if (ret == REDIS_OK) {
			if (ud->s) {
				rspamd_session_add_event (ud->s,
						lua_redis_fin,
						sp_ud,
						M);

				if (ud->item) {
					rspamd_symcache_item_async_inc (ud->task, ud->item, M);
				}
			}

			sp_ud->timeout_ev.data = sp_ud;

			if (IS_ASYNC (ctx)) {
				ev_timer_init (&sp_ud->timeout_ev, lua_redis_timeout,
						sp_ud->c->timeout, 0.0);
			}
			else {
				ev_timer_init (&sp_ud->timeout_ev, lua_redis_timeout_sync,
						sp_ud->c->timeout, 0.0);
			}

			ev_timer_start (ud->event_loop, &sp_ud->timeout_ev);
			REDIS_RETAIN (ctx);
			ctx->cmds_pending ++;
		}
		else {
			msg_info ("call to redis failed: %s",
					sp_ud->c->ctx->errstr);
			lua_pushboolean (L, 0);
			lua_pushstring (L, sp_ud->c->ctx->errstr);

			return 2;
		}
	}

	lua_pushboolean (L, true);

	return 1;
}

/***
 * @method rspamd_redis:exec()
 * Executes pending commands (suitable for blocking IO only for now)
 * @return {boolean}, {table}, ...: pairs in format [bool, result] for each request pending
 */
static int
lua_redis_exec (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_redis_ctx *ctx = lua_check_redis (L, 1);

	if (ctx == NULL) {
		lua_error (L);

		return 1;
	}

	if (IS_ASYNC (ctx)) {
		lua_pushstring (L, "Async redis pipelining is not implemented");
		lua_error (L);
		return 0;
	}
	else {
		if (false /* !ctx->d.sync */) {
			lua_pushstring (L, "cannot exec commands when not connected");
			lua_error (L);
			return 0;
		}
		else {
			if (ctx->cmds_pending == 0 && g_queue_get_length (ctx->replies) == 0) {
				lua_pushstring (L, "No pending commands to execute");
				lua_error (L);
			}
			if (ctx->cmds_pending == 0 && g_queue_get_length (ctx->replies) > 0) {
				gint results = lua_redis_push_results (ctx, L);
				return results;
			}
			else {
				ctx->thread = lua_thread_pool_get_running_entry (ctx->async.cfg->lua_thread_pool);
				return lua_thread_yield (ctx->thread, 0);
			}
		}
	}
}

static gint
lua_load_redis (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, redislib_f);

	return 1;
}

static gint
lua_redis_null_idx (lua_State *L)
{
	lua_pushnil (L);

	return 1;
}

static void
lua_redis_null_mt (lua_State *L)
{
	luaL_newmetatable (L, "redis{null}");

	lua_pushcfunction (L, lua_redis_null_idx);
	lua_setfield (L, -2, "__index");
	lua_pushcfunction (L, lua_redis_null_idx);
	lua_setfield (L, -2, "__tostring");

	lua_pop (L, 1);
}

/**
 * Open redis library
 * @param L lua stack
 * @return
 */
void
luaopen_redis (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{redis}", redislib_m);
	lua_pop (L, 1);
	rspamd_lua_add_preload (L, "rspamd_redis", lua_load_redis);

	/* Set null element */
	lua_redis_null_mt (L);
	redis_null = lua_newuserdata (L, 0);
	luaL_getmetatable (L, "redis{null}");
	lua_setmetatable (L, -2);
	lua_setfield (L, LUA_REGISTRYINDEX, "redis.null");
}
