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
#include "adapters/libevent.h"

#define REDIS_DEFAULT_TIMEOUT 0.5
#define REDIS_STAT_TIMEOUT 30
#define REDIS_DEFAULT_PORT 6379
#define DEFAULT_REDIS_KEY "learned_ids"

struct rspamd_redis_cache_ctx {
	struct rspamd_statfile_config *stcf;
	struct upstream_list *read_servers;
	struct upstream_list *write_servers;
	const gchar *password;
	const gchar *dbname;
	const gchar *redis_object;
	gdouble timeout;
};

struct rspamd_redis_cache_runtime {
	struct rspamd_redis_cache_ctx *ctx;
	struct rspamd_task *task;
	struct upstream *selected;
	struct event timeout_event;
	redisAsyncContext *redis;
	gboolean has_event;
};

static GQuark
rspamd_stat_cache_redis_quark (void)
{
	return g_quark_from_static_string ("redis-statistics");
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
	if (event_get_base (&rt->timeout_event)) {
		event_del (&rt->timeout_event);
	}

	if (rt->redis) {
		redis = rt->redis;
		rt->redis = NULL;
		/* This calls for all callbacks pending */
		redisAsyncFree (redis);
	}
}

static void
rspamd_redis_cache_timeout (gint fd, short what, gpointer d)
{
	struct rspamd_redis_cache_runtime *rt = d;
	struct rspamd_task *task;

	task = rt->task;

	msg_err_task ("connection to redis server %s timed out",
			rspamd_upstream_name (rt->selected));
	rspamd_upstream_fail (rt->selected);

	if (rt->has_event) {
		rspamd_session_remove_event (task->s, rspamd_redis_cache_fin, d);
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
				if (reply->type != REDIS_REPLY_NIL) {
					msg_err_task ("bad learned type for %s: %d",
							rt->ctx->stcf->symbol, reply->type);
				}

				val = 0;
			}
		}

		if ((val > 0 && (task->flags & RSPAMD_TASK_FLAG_LEARN_SPAM)) ||
				(val < 0 && (task->flags & RSPAMD_TASK_FLAG_LEARN_HAM))) {
			/* Already learned */
			g_set_error (&task->err, rspamd_stat_quark (), 404,
					"<%s> has been already "
					"learned as %s, ignore it", task->message_id,
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
		rspamd_upstream_fail (rt->selected);
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
		rspamd_upstream_fail (rt->selected);
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
		rspamd_cryptobox_hash_update (&st, tok->data, tok->datalen);
	}

	rspamd_cryptobox_hash_final (&st, out);

	b32out = rspamd_encode_base32 (out, sizeof (out));
	g_assert (b32out != NULL);
	rspamd_mempool_set_variable (task->task_pool, "words_hash", b32out, g_free);
}

static gboolean
rspamd_redis_cache_try_ucl (struct rspamd_redis_cache_ctx *cache_ctx,
		const ucl_object_t *obj,
		struct rspamd_config *cfg,
		const gchar *symbol)
{
	const ucl_object_t *elt, *relt;

	elt = ucl_object_lookup_any (obj, "read_servers", "servers", NULL);

	if (elt == NULL) {
		return FALSE;
	}

	cache_ctx->read_servers = rspamd_upstreams_create (cfg->ups_ctx);
	if (!rspamd_upstreams_from_ucl (cache_ctx->read_servers, elt,
			REDIS_DEFAULT_PORT, NULL)) {
		msg_err ("statfile %s cannot get read servers configuration",
				symbol);
		return FALSE;
	}

	relt = elt;

	elt = ucl_object_lookup (obj, "write_servers");
	if (elt == NULL) {
		/* Use read servers as write ones */
		g_assert (relt != NULL);
		cache_ctx->write_servers = rspamd_upstreams_create (cfg->ups_ctx);
		if (!rspamd_upstreams_from_ucl (cache_ctx->write_servers, relt,
				REDIS_DEFAULT_PORT, NULL)) {
			msg_err ("statfile %s cannot get write servers configuration",
					symbol);
			return FALSE;
		}
	}
	else {
		cache_ctx->write_servers = rspamd_upstreams_create (cfg->ups_ctx);
		if (!rspamd_upstreams_from_ucl (cache_ctx->write_servers, elt,
				REDIS_DEFAULT_PORT, NULL)) {
			msg_err ("statfile %s cannot get write servers configuration",
					symbol);
			rspamd_upstreams_destroy (cache_ctx->write_servers);
			cache_ctx->write_servers = NULL;
		}
	}


	elt = ucl_object_lookup (obj, "timeout");
	if (elt) {
		cache_ctx->timeout = ucl_object_todouble (elt);
	}
	else {
		cache_ctx->timeout = REDIS_DEFAULT_TIMEOUT;
	}

	elt = ucl_object_lookup (obj, "password");
	if (elt) {
		cache_ctx->password = ucl_object_tostring (elt);
	}
	else {
		cache_ctx->password = NULL;
	}

	elt = ucl_object_lookup_any (obj, "db", "database", "dbname", NULL);
	if (elt) {
		cache_ctx->dbname = ucl_object_tostring (elt);
	}
	else {
		cache_ctx->dbname = NULL;
	}

	elt = ucl_object_lookup_any (obj, "cache_key", "key", NULL);
	if (elt == NULL || ucl_object_type (elt) != UCL_STRING) {
		cache_ctx->redis_object = DEFAULT_REDIS_KEY;
	}
	else {
		cache_ctx->redis_object = ucl_object_tostring (elt);
	}

	return TRUE;
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

	cache_ctx = g_slice_alloc0 (sizeof (*cache_ctx));

	/* First search in backend configuration */
	obj = ucl_object_lookup (st->classifier->cfg->opts, "backend");
	if (obj != NULL && ucl_object_type (obj) == UCL_OBJECT) {
		ret = rspamd_redis_cache_try_ucl (cache_ctx, obj, cfg, stf->symbol);
	}

	/* Now try statfiles config */
	if (!ret) {
		ret = rspamd_redis_cache_try_ucl (cache_ctx, stf->opts, cfg, stf->symbol);
	}

	/* Now try classifier config */
	if (!ret) {
		ret = rspamd_redis_cache_try_ucl (cache_ctx, st->classifier->cfg->opts, cfg,
				stf->symbol);
	}

	/* Now try global redis settings */
	if (!ret) {
		obj = ucl_object_lookup (cfg->rcl_obj, "redis");

		if (obj) {
			const ucl_object_t *specific_obj;

			specific_obj = ucl_object_lookup (obj, "statistics");

			if (specific_obj) {
				ret = rspamd_redis_cache_try_ucl (cache_ctx, specific_obj, cfg,
						stf->symbol);
			}
			else {
				ret = rspamd_redis_cache_try_ucl (cache_ctx, obj, cfg,
						stf->symbol);
			}
		}
	}


	if (!ret) {
		msg_err_config ("cannot init redis cache for %s", stf->symbol);
		g_slice_free1 (sizeof (*cache_ctx), cache_ctx);
		return NULL;
	}

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
	rspamd_inet_addr_t *addr;

	g_assert (ctx != NULL);

	if (learn && ctx->write_servers == NULL) {
		msg_err_task ("no write servers defined for %s, cannot learn",
				ctx->stcf->symbol);
		return NULL;
	}

	if (task->tokens == NULL || task->tokens->len == 0) {
		return NULL;
	}

	if (learn) {
		up = rspamd_upstream_get (ctx->write_servers,
				RSPAMD_UPSTREAM_MASTER_SLAVE,
				NULL,
				0);
	}
	else {
		up = rspamd_upstream_get (ctx->read_servers,
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

	addr = rspamd_upstream_addr (up);
	g_assert (addr != NULL);
	rt->redis = redisAsyncConnect (rspamd_inet_address_to_string (addr),
			rspamd_inet_address_get_port (addr));
	g_assert (rt->redis != NULL);

	redisLibeventAttach (rt->redis, task->ev_base);

	/* Now check stats */
	event_set (&rt->timeout_event, -1, EV_TIMEOUT, rspamd_redis_cache_timeout, rt);
	event_base_set (task->ev_base, &rt->timeout_event);
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
	struct timeval tv;
	gchar *h;

	h = rspamd_mempool_get_variable (task->task_pool, "words_hash");

	if (h == NULL) {
		return RSPAMD_LEARN_INGORE;
	}

	double_to_tv (rt->ctx->timeout, &tv);

	if (redisAsyncCommand (rt->redis, rspamd_stat_cache_redis_get, rt,
			"HGET %s %s",
			rt->ctx->redis_object, h) == REDIS_OK) {
		rspamd_session_add_event (task->s, rspamd_redis_cache_fin, rt,
				rspamd_stat_cache_redis_quark ());
		event_add (&rt->timeout_event, &tv);
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
	struct timeval tv;
	gchar *h;
	gint flag;

	h = rspamd_mempool_get_variable (task->task_pool, "words_hash");
	g_assert (h != NULL);

	double_to_tv (rt->ctx->timeout, &tv);
	flag = (task->flags & RSPAMD_TASK_FLAG_LEARN_SPAM) ? 1 : -1;

	if (redisAsyncCommand (rt->redis, rspamd_stat_cache_redis_set, rt,
			"HSET %s %s %d",
			rt->ctx->redis_object, h, flag) == REDIS_OK) {
		rspamd_session_add_event (task->s, rspamd_redis_cache_fin, rt,
				rspamd_stat_cache_redis_quark ());
		event_add (&rt->timeout_event, &tv);
		rt->has_event = TRUE;
	}

	/* We need to return OK every time */
	return RSPAMD_LEARN_OK;
}

void
rspamd_stat_cache_redis_close (gpointer c)
{

}
