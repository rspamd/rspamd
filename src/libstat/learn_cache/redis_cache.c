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
#include "config.h"
#include "learn_cache.h"
#include "rspamd.h"
#include "stat_api.h"
#include "stat_internal.h"
#include "cryptobox.h"
#include "ucl.h"
#include "hiredis.h"
#include "adapters/libev.h"
#include "lua/lua_common.h"
#include "libmime/message.h"

#define REDIS_DEFAULT_TIMEOUT 0.5
#define REDIS_STAT_TIMEOUT 30
#define REDIS_DEFAULT_PORT 6379
#define DEFAULT_REDIS_KEY "learned_ids"

static const gchar *M = "redis learn cache";

struct rspamd_redis_cache_ctx {
	lua_State *L;
	struct rspamd_statfile_config *stcf;
	const gchar *password;
	const gchar *dbname;
	const gchar *redis_object;
	gdouble timeout;
	gint conf_ref;
};

struct rspamd_redis_cache_runtime {
	struct rspamd_redis_cache_ctx *ctx;
	struct rspamd_task *task;
	struct upstream *selected;
	ev_timer timer_ev;
	redisAsyncContext *redis;
	gboolean has_event;
};

static GQuark
rspamd_stat_cache_redis_quark (void)
{
	return g_quark_from_static_string (M);
}

static inline struct upstream_list *
rspamd_redis_get_servers (struct rspamd_redis_cache_ctx *ctx,
						  const gchar *what)
{
	lua_State *L = ctx->L;
	struct upstream_list *res;

	lua_rawgeti (L, LUA_REGISTRYINDEX, ctx->conf_ref);
	lua_pushstring (L, what);
	lua_gettable (L, -2);
	res = *((struct upstream_list**)lua_touserdata (L, -1));
	lua_settop (L, 0);

	return res;
}

static void
rspamd_redis_cache_maybe_auth (struct rspamd_redis_cache_ctx *ctx,
		redisAsyncContext *redis)
{
	if (ctx->password) {
		redisAsyncCommand (redis, NULL, NULL, "AUTH %s", ctx->password);
	}
	if (ctx->dbname) {
		redisAsyncCommand (redis, NULL, NULL, "SELECT %s", ctx->dbname);
	}
}

/* Called on connection termination */
static void
rspamd_redis_cache_fin (gpointer data)
{
	struct rspamd_redis_cache_runtime *rt = data;
	redisAsyncContext *redis;

	rt->has_event = FALSE;
	ev_timer_stop (rt->task->event_loop, &rt->timer_ev);

	if (rt->redis) {
		redis = rt->redis;
		rt->redis = NULL;
		/* This calls for all callbacks pending */
		redisAsyncFree (redis);
	}
}

static void
rspamd_redis_cache_timeout (EV_P_ ev_timer *w, int revents)
{
	struct rspamd_redis_cache_runtime *rt =
			(struct rspamd_redis_cache_runtime *)w->data;
	struct rspamd_task *task;

	task = rt->task;

	msg_err_task ("connection to redis server %s timed out",
			rspamd_upstream_name (rt->selected));
	rspamd_upstream_fail (rt->selected, FALSE, "timeout");

	if (rt->has_event) {
		rspamd_session_remove_event (task->s, rspamd_redis_cache_fin, rt);
	}
}

/* Called when we have checked the specified message id */
static void
rspamd_stat_cache_redis_get (redisAsyncContext *c, gpointer r, gpointer priv)
{
	struct rspamd_redis_cache_runtime *rt = priv;
	redisReply *reply = r;
	struct rspamd_task *task;
	glong val = 0;

	task = rt->task;

	if (c->err == 0) {
		if (reply) {
			if (G_LIKELY (reply->type == REDIS_REPLY_INTEGER)) {
				val = reply->integer;
			}
			else if (reply->type == REDIS_REPLY_STRING) {
				rspamd_strtol (reply->str, reply->len, &val);
			}
			else {
				if (reply->type == REDIS_REPLY_ERROR) {
					msg_err_task ("cannot learn %s: redis error: \"%s\"",
							rt->ctx->stcf->symbol, reply->str);
				}
				else if (reply->type != REDIS_REPLY_NIL) {
					msg_err_task ("bad learned type for %s: %d",
							rt->ctx->stcf->symbol, reply->type);
				}

				val = 0;
			}
		}

		if ((val > 0 && (task->flags & RSPAMD_TASK_FLAG_LEARN_SPAM)) ||
				(val < 0 && (task->flags & RSPAMD_TASK_FLAG_LEARN_HAM))) {
			/* Already learned */
			msg_info_task ("<%s> has been already "
					"learned as %s, ignore it", MESSAGE_FIELD (task, message_id),
					(task->flags & RSPAMD_TASK_FLAG_LEARN_SPAM) ? "spam" : "ham");
			task->flags |= RSPAMD_TASK_FLAG_ALREADY_LEARNED;
		}
		else if (val != 0) {
			/* Unlearn flag */
			task->flags |= RSPAMD_TASK_FLAG_UNLEARN;
		}

		rspamd_upstream_ok (rt->selected);
	}
	else {
		rspamd_upstream_fail (rt->selected, FALSE, c->errstr);
	}

	if (rt->has_event) {
		rspamd_session_remove_event (task->s, rspamd_redis_cache_fin, rt);
	}
}

/* Called when we have learned the specified message id */
static void
rspamd_stat_cache_redis_set (redisAsyncContext *c, gpointer r, gpointer priv)
{
	struct rspamd_redis_cache_runtime *rt = priv;
	struct rspamd_task *task;

	task = rt->task;

	if (c->err == 0) {
		/* XXX: we ignore results here */
		rspamd_upstream_ok (rt->selected);
	}
	else {
		rspamd_upstream_fail (rt->selected, FALSE, c->errstr);
	}

	if (rt->has_event) {
		rspamd_session_remove_event (task->s, rspamd_redis_cache_fin, rt);
	}
}

static void
rspamd_stat_cache_redis_generate_id (struct rspamd_task *task)
{
	rspamd_cryptobox_hash_state_t st;
	rspamd_token_t *tok;
	guint i;
	guchar out[rspamd_cryptobox_HASHBYTES];
	gchar *b32out;
	gchar *user = NULL;

	rspamd_cryptobox_hash_init (&st, NULL, 0);

	user = rspamd_mempool_get_variable (task->task_pool, "stat_user");
	/* Use dedicated hash space for per users cache */
	if (user != NULL) {
		rspamd_cryptobox_hash_update (&st, user, strlen (user));
	}

	for (i = 0; i < task->tokens->len; i ++) {
		tok = g_ptr_array_index (task->tokens, i);
		rspamd_cryptobox_hash_update (&st, (guchar *)&tok->data,
				sizeof (tok->data));
	}

	rspamd_cryptobox_hash_final (&st, out);

	b32out = rspamd_mempool_alloc (task->task_pool,
			sizeof (out) * 8 / 5 + 3);
	i = rspamd_encode_base32_buf (out, sizeof (out), b32out,
			sizeof (out) * 8 / 5 + 2, RSPAMD_BASE32_DEFAULT);

	if (i > 0) {
		/* Zero terminate */
		b32out[i] = '\0';
	}

	rspamd_mempool_set_variable (task->task_pool, "words_hash", b32out, NULL);
}

gpointer
rspamd_stat_cache_redis_init (struct rspamd_stat_ctx *ctx,
		struct rspamd_config *cfg,
		struct rspamd_statfile *st,
		const ucl_object_t *cf)
{
	struct rspamd_redis_cache_ctx *cache_ctx;
	struct rspamd_statfile_config *stf = st->stcf;
	const ucl_object_t *obj;
	gboolean ret = FALSE;
	lua_State *L = (lua_State *)cfg->lua_state;
	gint conf_ref = -1;

	cache_ctx = g_malloc0 (sizeof (*cache_ctx));
	cache_ctx->timeout = REDIS_DEFAULT_TIMEOUT;
	cache_ctx->L = L;

	/* First search in backend configuration */
	obj = ucl_object_lookup (st->classifier->cfg->opts, "backend");
	if (obj != NULL && ucl_object_type (obj) == UCL_OBJECT) {
		ret = rspamd_lua_try_load_redis (L, obj, cfg, &conf_ref);
	}

	/* Now try statfiles config */
	if (!ret && stf->opts) {
		ret = rspamd_lua_try_load_redis (L, stf->opts, cfg, &conf_ref);
	}

	/* Now try classifier config */
	if (!ret && st->classifier->cfg->opts) {
		ret = rspamd_lua_try_load_redis (L, st->classifier->cfg->opts, cfg, &conf_ref);
	}

	/* Now try global redis settings */
	if (!ret) {
		obj = ucl_object_lookup (cfg->rcl_obj, "redis");

		if (obj) {
			const ucl_object_t *specific_obj;

			specific_obj = ucl_object_lookup (obj, "statistics");

			if (specific_obj) {
				ret = rspamd_lua_try_load_redis (L,
						specific_obj, cfg, &conf_ref);
			}
			else {
				ret = rspamd_lua_try_load_redis (L,
						obj, cfg, &conf_ref);
			}
		}
	}

	if (!ret) {
		msg_err_config ("cannot init redis cache for %s", stf->symbol);
		g_free (cache_ctx);
		return NULL;
	}

	obj = ucl_object_lookup (st->classifier->cfg->opts, "cache_key");

	if (obj) {
		cache_ctx->redis_object = ucl_object_tostring (obj);
	}
	else {
		cache_ctx->redis_object = DEFAULT_REDIS_KEY;
	}

	cache_ctx->conf_ref = conf_ref;

	/* Check some common table values */
	lua_rawgeti (L, LUA_REGISTRYINDEX, conf_ref);

	lua_pushstring (L, "timeout");
	lua_gettable (L, -2);
	if (lua_type (L, -1) == LUA_TNUMBER) {
		cache_ctx->timeout = lua_tonumber (L, -1);
	}
	lua_pop (L, 1);

	lua_pushstring (L, "db");
	lua_gettable (L, -2);
	if (lua_type (L, -1) == LUA_TSTRING) {
		cache_ctx->dbname = rspamd_mempool_strdup (cfg->cfg_pool,
				lua_tostring (L, -1));
	}
	lua_pop (L, 1);

	lua_pushstring (L, "password");
	lua_gettable (L, -2);
	if (lua_type (L, -1) == LUA_TSTRING) {
		cache_ctx->password = rspamd_mempool_strdup (cfg->cfg_pool,
				lua_tostring (L, -1));
	}
	lua_pop (L, 1);

	lua_settop (L, 0);

	cache_ctx->stcf = stf;

	return (gpointer)cache_ctx;
}

gpointer
rspamd_stat_cache_redis_runtime (struct rspamd_task *task,
		gpointer c, gboolean learn)
{
	struct rspamd_redis_cache_ctx *ctx = c;
	struct rspamd_redis_cache_runtime *rt;
	struct upstream *up;
	struct upstream_list *ups;
	rspamd_inet_addr_t *addr;

	g_assert (ctx != NULL);

	if (task->tokens == NULL || task->tokens->len == 0) {
		return NULL;
	}

	if (learn) {
		ups = rspamd_redis_get_servers (ctx, "write_servers");

		if (!ups) {
			msg_err_task ("no write servers defined for %s, cannot learn",
					ctx->stcf->symbol);
			return NULL;
		}

		up = rspamd_upstream_get (ups,
				RSPAMD_UPSTREAM_MASTER_SLAVE,
				NULL,
				0);
	}
	else {
		ups = rspamd_redis_get_servers (ctx, "read_servers");

		if (!ups) {
			msg_err_task ("no read servers defined for %s, cannot check",
					ctx->stcf->symbol);
			return NULL;
		}

		up = rspamd_upstream_get (ups,
				RSPAMD_UPSTREAM_ROUND_ROBIN,
				NULL,
				0);
	}

	if (up == NULL) {
		msg_err_task ("no upstreams reachable");
		return NULL;
	}

	rt = rspamd_mempool_alloc0 (task->task_pool, sizeof (*rt));
	rt->selected = up;
	rt->task = task;
	rt->ctx = ctx;

	addr = rspamd_upstream_addr_next (up);
	g_assert (addr != NULL);

	if (rspamd_inet_address_get_af (addr) == AF_UNIX) {
		rt->redis = redisAsyncConnectUnix (rspamd_inet_address_to_string (addr));
	}
	else {
		rt->redis = redisAsyncConnect (rspamd_inet_address_to_string (addr),
				rspamd_inet_address_get_port (addr));
	}

	if (rt->redis == NULL) {
		msg_warn_task ("cannot connect to redis server %s: %s",
				rspamd_inet_address_to_string_pretty (addr),
				strerror (errno));

		return NULL;
	}
	else if (rt->redis->err != REDIS_OK) {
		msg_warn_task ("cannot connect to redis server %s: %s",
				rspamd_inet_address_to_string_pretty (addr),
				rt->redis->errstr);
		redisAsyncFree (rt->redis);
		rt->redis = NULL;

		return NULL;
	}

	redisLibevAttach (task->event_loop, rt->redis);

	/* Now check stats */
	rt->timer_ev.data = rt;
	ev_timer_init (&rt->timer_ev, rspamd_redis_cache_timeout,
			rt->ctx->timeout, 0.0);
	rspamd_redis_cache_maybe_auth (ctx, rt->redis);

	if (!learn) {
		rspamd_stat_cache_redis_generate_id (task);
	}

	return rt;
}

gint
rspamd_stat_cache_redis_check (struct rspamd_task *task,
		gboolean is_spam,
		gpointer runtime)
{
	struct rspamd_redis_cache_runtime *rt = runtime;
	gchar *h;

	if (rspamd_session_blocked (task->s)) {
		return RSPAMD_LEARN_INGORE;
	}

	h = rspamd_mempool_get_variable (task->task_pool, "words_hash");

	if (h == NULL) {
		return RSPAMD_LEARN_INGORE;
	}

	if (redisAsyncCommand (rt->redis, rspamd_stat_cache_redis_get, rt,
			"HGET %s %s",
			rt->ctx->redis_object, h) == REDIS_OK) {
		rspamd_session_add_event (task->s,
				rspamd_redis_cache_fin,
				rt,
				M);
		ev_timer_start (rt->task->event_loop, &rt->timer_ev);
		rt->has_event = TRUE;
	}

	/* We need to return OK every time */
	return RSPAMD_LEARN_OK;
}

gint
rspamd_stat_cache_redis_learn (struct rspamd_task *task,
		gboolean is_spam,
		gpointer runtime)
{
	struct rspamd_redis_cache_runtime *rt = runtime;
	gchar *h;
	gint flag;

	if (rt == NULL || rt->ctx == NULL || rspamd_session_blocked (task->s)) {
		return RSPAMD_LEARN_INGORE;
	}

	h = rspamd_mempool_get_variable (task->task_pool, "words_hash");
	g_assert (h != NULL);

	flag = (task->flags & RSPAMD_TASK_FLAG_LEARN_SPAM) ? 1 : -1;

	if (redisAsyncCommand (rt->redis, rspamd_stat_cache_redis_set, rt,
			"HSET %s %s %d",
			rt->ctx->redis_object, h, flag) == REDIS_OK) {
		rspamd_session_add_event (task->s,
				rspamd_redis_cache_fin, rt, M);
		ev_timer_start (rt->task->event_loop, &rt->timer_ev);
		rt->has_event = TRUE;
	}

	/* We need to return OK every time */
	return RSPAMD_LEARN_OK;
}

void
rspamd_stat_cache_redis_close (gpointer c)
{
	struct rspamd_redis_cache_ctx *ctx = (struct rspamd_redis_cache_ctx *)c;
	lua_State *L;

	L = ctx->L;

	if (ctx->conf_ref) {
		luaL_unref (L, LUA_REGISTRYINDEX, ctx->conf_ref);
	}

	g_free (ctx);
}
