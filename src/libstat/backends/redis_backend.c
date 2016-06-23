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
#include "rspamd.h"
#include "stat_internal.h"
#include "upstream.h"
#include "lua/lua_common.h"

#ifdef WITH_HIREDIS
#include "hiredis.h"
#include "adapters/libevent.h"
#include "ref.h"


#define REDIS_CTX(p) (struct redis_stat_ctx *)(p)
#define REDIS_RUNTIME(p) (struct redis_stat_runtime *)(p)
#define REDIS_BACKEND_TYPE "redis"
#define REDIS_DEFAULT_PORT 6379
#define REDIS_DEFAULT_OBJECT "%s%l"
#define REDIS_DEFAULT_USERS_OBJECT "%s%l%r"
#define REDIS_DEFAULT_TIMEOUT 0.5
#define REDIS_STAT_TIMEOUT 30

struct redis_stat_ctx {
	struct rspamd_statfile_config *stcf;
	struct upstream_list *read_servers;
	struct upstream_list *write_servers;
	struct rspamd_stat_async_elt *stat_elt;
	const gchar *redis_object;
	const gchar *password;
	const gchar *dbname;
	gdouble timeout;
	gboolean enable_users;
	gint cbref_user;
};

enum rspamd_redis_connection_state {
	RSPAMD_REDIS_DISCONNECTED = 0,
	RSPAMD_REDIS_CONNECTED,
	RSPAMD_REDIS_REQUEST_SENT,
	RSPAMD_REDIS_TIMEDOUT,
	RSPAMD_REDIS_TERMINATED
};

struct redis_stat_runtime {
	struct redis_stat_ctx *ctx;
	struct rspamd_task *task;
	struct upstream *selected;
	struct event timeout_event;
	GArray *results;
	struct rspamd_statfile_config *stcf;
	gchar *redis_object_expanded;
	redisAsyncContext *redis;
	guint64 learned;
	gint id;
	gboolean has_event;
};

/* Used to get statistics from redis */
struct rspamd_redis_stat_cbdata;

struct rspamd_redis_stat_elt {
	struct redis_stat_ctx *ctx;
	struct rspamd_stat_async_elt *async;
	struct event_base *ev_base;
	ucl_object_t *stat;
	struct rspamd_redis_stat_cbdata *cbdata;
};

struct rspamd_redis_stat_cbdata {
	struct rspamd_redis_stat_elt *elt;
	redisAsyncContext *redis;
	ucl_object_t *cur;
	GPtrArray *cur_keys;
	struct upstream *selected;
	guint inflight;
	gboolean wanna_die;
};

#define GET_TASK_ELT(task, elt) (task == NULL ? NULL : (task)->elt)

static GQuark
rspamd_redis_stat_quark (void)
{
	return g_quark_from_static_string ("redis-statistics");
}


/*
 * Non-static for lua unit testing
 */
gsize
rspamd_redis_expand_object (const gchar *pattern,
		struct redis_stat_ctx *ctx,
		struct rspamd_task *task,
		gchar **target)
{
	gsize tlen = 0;
	const gchar *p = pattern, *elt;
	gchar *d, *end;
	enum  {
		just_char,
		percent_char,
		mod_char
	} state = just_char;
	struct rspamd_statfile_config *stcf;
	lua_State *L = NULL;
	struct rspamd_task **ptask;
	GString *tb;
	const gchar *rcpt = NULL;
	gint err_idx;

	g_assert (ctx != NULL);
	stcf = ctx->stcf;

	if (task) {
		L = task->cfg->lua_state;
	}

	if (ctx->enable_users) {
		if (ctx->cbref_user == -1) {
			rcpt = rspamd_task_get_principal_recipient (task);
		}
		else if (L) {
			/* Execute lua function to get userdata */
			lua_pushcfunction (L, &rspamd_lua_traceback);
			err_idx = lua_gettop (L);

			lua_rawgeti (L, LUA_REGISTRYINDEX, ctx->cbref_user);
			ptask = lua_newuserdata (L, sizeof (struct rspamd_task *));
			*ptask = task;
			rspamd_lua_setclass (L, "rspamd{task}", -1);

			if (lua_pcall (L, 1, 1, err_idx) != 0) {
				tb = lua_touserdata (L, -1);
				msg_err_task ("call to user extraction script failed: %v", tb);
				g_string_free (tb, TRUE);
			}
			else {
				rcpt = rspamd_mempool_strdup (task->task_pool, lua_tostring (L, -1));
			}

			/* Result + error function */
			lua_pop (L, 2);
		}

		if (rcpt) {
			rspamd_mempool_set_variable (task->task_pool, "stat_user",
					(gpointer)rcpt, NULL);
		}
	}



	/* Length calculation */
	while (*p) {
		switch (state) {
		case just_char:
			if (*p == '%') {
				state = percent_char;
			}
			else {
				tlen ++;
			}
			p ++;
			break;
		case percent_char:
			switch (*p) {
			case '%':
				tlen ++;
				state = just_char;
				break;
			case 'u':
				elt = GET_TASK_ELT (task, user);
				if (elt) {
					tlen += strlen (elt);
				}
				break;
			case 'r':

				if (rcpt == NULL) {
					elt = rspamd_task_get_principal_recipient (task);
				}
				else {
					elt = rcpt;
				}

				if (elt) {
					tlen += strlen (elt);
				}
				break;
			case 'l':
				if (stcf->label) {
					tlen += strlen (stcf->label);
				}
				break;
			case 's':
				if (stcf->symbol) {
					tlen += strlen (stcf->symbol);
				}
				break;
			default:
				state = just_char;
				tlen ++;
				break;
			}

			if (state == percent_char) {
				state = mod_char;
			}
			p ++;
			break;

		case mod_char:
			switch (*p) {
			case 'd':
				p ++;
				state = just_char;
				break;
			default:
				state = just_char;
				break;
			}
			break;
		}
	}

	if (target == NULL || task == NULL) {
		return tlen;
	}

	*target = rspamd_mempool_alloc (task->task_pool, tlen + 1);
	d = *target;
	end = d + tlen + 1;
	d[tlen] = '\0';
	p = pattern;
	state = just_char;

	/* Expand string */
	while (*p && d < end) {
		switch (state) {
		case just_char:
			if (*p == '%') {
				state = percent_char;
			}
			else {
				*d++ = *p;
			}
			p ++;
			break;
		case percent_char:
			switch (*p) {
			case '%':
				*d++ = *p;
				state = just_char;
				break;
			case 'u':
				elt = GET_TASK_ELT (task, user);
				if (elt) {
					d += rspamd_strlcpy (d, elt, end - d);
				}
				break;
			case 'r':
				if (rcpt == NULL) {
					elt = rspamd_task_get_principal_recipient (task);
				}
				else {
					elt = rcpt;
				}

				if (elt) {
					d += rspamd_strlcpy (d, elt, end - d);
				}
				break;
			case 'l':
				if (stcf->label) {
					d += rspamd_strlcpy (d, stcf->label, end - d);
				}
				break;
			case 's':
				if (stcf->symbol) {
					d += rspamd_strlcpy (d, stcf->symbol, end - d);
				}
				break;
			default:
				state = just_char;
				*d++ = *p;
				break;
			}

			if (state == percent_char) {
				state = mod_char;
			}
			p ++;
			break;

		case mod_char:
			switch (*p) {
			case 'd':
				/* TODO: not supported yet */
				p ++;
				state = just_char;
				break;
			default:
				state = just_char;
				break;
			}
			break;
		}
	}

	return tlen;
}

static void
rspamd_redis_maybe_auth (struct redis_stat_ctx *ctx, redisAsyncContext *redis)
{
	if (ctx->password) {
		redisAsyncCommand (redis, NULL, NULL, "AUTH %s", ctx->password);
	}
	if (ctx->dbname) {
		redisAsyncCommand (redis, NULL, NULL, "SELECT %s", ctx->dbname);
	}
}

static rspamd_fstring_t *
rspamd_redis_tokens_to_query (struct rspamd_task *task, GPtrArray *tokens,
		const gchar *arg0, const gchar *arg1, gboolean learn, gint idx,
		gboolean intvals)
{
	rspamd_fstring_t *out;
	rspamd_token_t *tok;
	gchar n0[64], n1[64];
	guint i, l0, l1, larg0, larg1;
	guint64 num;

	g_assert (tokens != NULL);

	larg0 = strlen (arg0);
	larg1 = strlen (arg1);
	out = rspamd_fstring_sized_new (1024);

	if (!learn) {
		rspamd_printf_fstring (&out, ""
				"*%d\r\n"
				"$%d\r\n"
				"%s\r\n"
				"$%d\r\n"
				"%s\r\n",
				(tokens->len + 2),
				larg0, arg0,
				larg1, arg1);
	}

	for (i = 0; i < tokens->len; i ++) {
		tok = g_ptr_array_index (tokens, i);
		memcpy (&num, tok->data, sizeof (num));

		if (learn) {
			rspamd_printf_fstring (&out, ""
					"*4\r\n"
					"$%d\r\n"
					"%s\r\n"
					"$%d\r\n"
					"%s\r\n",
					larg0, arg0,
					larg1, arg1);

			l0 = rspamd_snprintf (n0, sizeof (n0), "%uL", num);

			if (intvals) {
				l1 = rspamd_snprintf (n1, sizeof (n1), "%L",
						(gint64)tok->values[idx]);
			}
			else {
				l1 = rspamd_snprintf (n1, sizeof (n1), "%f",
						tok->values[idx]);
			}

			rspamd_printf_fstring (&out, ""
					"$%d\r\n"
					"%s\r\n"
					"$%d\r\n"
					"%s\r\n", l0, n0, l1, n1);
		}
		else {
			l0 = rspamd_snprintf (n0, sizeof (n0), "%uL", num);
			rspamd_printf_fstring (&out, ""
					"$%d\r\n"
					"%s\r\n", l0, n0);
		}
	}

	return out;
}

static void
rspamd_redis_async_cbdata_cleanup (struct rspamd_redis_stat_cbdata *cbdata)
{
	guint i;
	gchar *k;

	if (cbdata && !cbdata->wanna_die) {
		/* Avoid double frees */
		cbdata->wanna_die = TRUE;
		redisAsyncFree (cbdata->redis);

		for (i = 0; i < cbdata->cur_keys->len; i ++) {
			k = g_ptr_array_index (cbdata->cur_keys, i);
			g_free (k);
		}

		g_ptr_array_free (cbdata->cur_keys, TRUE);

		if (cbdata->elt) {
			cbdata->elt->cbdata = NULL;
			/* Re-enable parent event */
			cbdata->elt->async->enabled = TRUE;

			/* Replace ucl object */
			if (cbdata->cur) {
				if (cbdata->elt->stat) {
					ucl_object_unref (cbdata->elt->stat);
				}

				cbdata->elt->stat = cbdata->cur;
				cbdata->cur = NULL;
			}
		}

		if (cbdata->cur) {
			ucl_object_unref (cbdata->cur);
		}

		g_slice_free1 (sizeof (*cbdata), cbdata);
	}
}

/* Called when we get number of learns for a specific key */
static void
rspamd_redis_stat_learns (redisAsyncContext *c, gpointer r, gpointer priv)
{
	struct rspamd_redis_stat_cbdata *cbdata = priv;
	redisReply *reply = r;
	ucl_object_t *obj;
	gulong num = 0;

	if (cbdata->wanna_die) {
		return;
	}

	cbdata->inflight --;

	if (c->err == 0 && r != NULL) {
		if (G_LIKELY (reply->type == REDIS_REPLY_INTEGER)) {
			num = reply->integer;
		}
		else if (reply->type == REDIS_REPLY_STRING) {
			rspamd_strtoul (reply->str, reply->len, &num);
		}

		obj = (ucl_object_t *)ucl_object_lookup (cbdata->cur, "revision");
		if (obj) {
			obj->value.iv += num;
		}
	}

	if (cbdata->inflight == 0) {
		rspamd_redis_async_cbdata_cleanup (cbdata);
	}
}

/* Called when we get number of elements for a specific key */
static void
rspamd_redis_stat_key (redisAsyncContext *c, gpointer r, gpointer priv)
{
	struct rspamd_redis_stat_cbdata *cbdata = priv;
	redisReply *reply = r;
	ucl_object_t *obj;
	glong num = 0;

	if (cbdata->wanna_die) {
		return;
	}

	cbdata->inflight --;

	if (c->err == 0 && r != NULL) {
		if (G_LIKELY (reply->type == REDIS_REPLY_INTEGER)) {
			num = reply->integer;
		}
		else if (reply->type == REDIS_REPLY_STRING) {
			rspamd_strtol (reply->str, reply->len, &num);
		}

		if (num < 0) {
			msg_err ("bad learns count: %L", (gint64)num);
			num = 0;
		}

		obj = (ucl_object_t *)ucl_object_lookup (cbdata->cur, "used");
		if (obj) {
			obj->value.iv += num;
		}

		obj = (ucl_object_t *)ucl_object_lookup (cbdata->cur, "total");
		if (obj) {
			obj->value.iv += num;
		}

		obj = (ucl_object_t *)ucl_object_lookup (cbdata->cur, "size");
		if (obj) {
			/* Size of key + size of int64_t */
			obj->value.iv += num * (sizeof (G_STRINGIFY (G_MAXINT64)) +
					sizeof (guint64) + sizeof (gpointer));
		}
	}

	if (cbdata->inflight == 0) {
		rspamd_redis_async_cbdata_cleanup (cbdata);
	}
}

/* Called when we have connected to the redis server and got keys to check */
static void
rspamd_redis_stat_keys (redisAsyncContext *c, gpointer r, gpointer priv)
{
	struct rspamd_redis_stat_cbdata *cbdata = priv;
	redisReply *reply = r, *elt;
	gchar **pk, *k;
	guint i, processed = 0;


	if (cbdata->wanna_die) {
		return;
	}

	cbdata->inflight --;

	if (c->err == 0 && r != NULL) {
		if (reply->type == REDIS_REPLY_ARRAY) {
			g_ptr_array_set_size (cbdata->cur_keys, reply->elements);

			for (i = 0; i < reply->elements; i ++) {
				elt = reply->element[i];

				if (elt->type == REDIS_REPLY_STRING) {
					pk = (gchar **)&g_ptr_array_index (cbdata->cur_keys, i);
					*pk = g_malloc (elt->len + 1);
					rspamd_strlcpy (*pk, elt->str, elt->len + 1);
					processed ++;
				}
			}

			if (processed) {
				for (i = 0; i < cbdata->cur_keys->len; i ++) {
					k = (gchar *)g_ptr_array_index (cbdata->cur_keys, i);

					if (k) {
						redisAsyncCommand (cbdata->redis, rspamd_redis_stat_key,
								cbdata,
								"HLEN %s",
								k);
						redisAsyncCommand (cbdata->redis, rspamd_redis_stat_learns,
								cbdata,
								"HGET %s learns",
								k);
						cbdata->inflight += 2;
					}
				}
			}
		}

		/* Set up the required keys */
		ucl_object_insert_key (cbdata->cur,
				ucl_object_typed_new (UCL_INT), "revision", 0, false);
		ucl_object_insert_key (cbdata->cur,
				ucl_object_typed_new (UCL_INT), "used", 0, false);
		ucl_object_insert_key (cbdata->cur,
				ucl_object_typed_new (UCL_INT), "total", 0, false);
		ucl_object_insert_key (cbdata->cur,
				ucl_object_typed_new (UCL_INT), "size", 0, false);
		ucl_object_insert_key (cbdata->cur,
				ucl_object_fromstring (cbdata->elt->ctx->stcf->symbol),
				"symbol", 0, false);
		ucl_object_insert_key (cbdata->cur, ucl_object_fromstring ("redis"),
				"type", 0, false);
		ucl_object_insert_key (cbdata->cur, ucl_object_fromint (0),
				"languages", 0, false);
		ucl_object_insert_key (cbdata->cur, ucl_object_fromint (processed),
				"users", 0, false);

		rspamd_upstream_ok (cbdata->selected);
	}
	else {
		msg_err ("cannot get keys to gather stat");
		rspamd_upstream_fail (cbdata->selected);
		rspamd_redis_async_cbdata_cleanup (cbdata);
	}

	if (cbdata->inflight == 0) {
		rspamd_redis_async_cbdata_cleanup (cbdata);
	}
}

static void
rspamd_redis_async_stat_cb (struct rspamd_stat_async_elt *elt, gpointer d)
{
	struct redis_stat_ctx *ctx;
	struct rspamd_redis_stat_elt *redis_elt = elt->ud;
	struct rspamd_redis_stat_cbdata *cbdata;
	rspamd_inet_addr_t *addr;

	g_assert (redis_elt != NULL);

	ctx = redis_elt->ctx;

	if (redis_elt->cbdata) {
		/* We have some other process pending */
		rspamd_redis_async_cbdata_cleanup (redis_elt->cbdata);
	}

	/* Disable further events unless needed */
	elt->enabled = FALSE;

	cbdata = g_slice_alloc0 (sizeof (*cbdata));
	cbdata->selected = rspamd_upstream_get (ctx->read_servers,
					RSPAMD_UPSTREAM_ROUND_ROBIN,
					NULL,
					0);

	g_assert (cbdata->selected != NULL);
	addr = rspamd_upstream_addr (cbdata->selected);
	g_assert (addr != NULL);
	cbdata->redis = redisAsyncConnect (rspamd_inet_address_to_string (addr),
			rspamd_inet_address_get_port (addr));
	g_assert (cbdata->redis != NULL);

	redisLibeventAttach (cbdata->redis, redis_elt->ev_base);

	cbdata->inflight = 1;
	cbdata->cur = ucl_object_typed_new (UCL_OBJECT);
	cbdata->elt = redis_elt;
	cbdata->cur_keys = g_ptr_array_new ();
	redis_elt->cbdata = cbdata;

	/* XXX: deal with timeouts maybe */
	/* Get keys in redis that match our symbol */
	rspamd_redis_maybe_auth (ctx, cbdata->redis);
	redisAsyncCommand (cbdata->redis, rspamd_redis_stat_keys, cbdata,
			"KEYS %s*",
			ctx->stcf->symbol);
}

static void
rspamd_redis_async_stat_fin (struct rspamd_stat_async_elt *elt, gpointer d)
{
	struct rspamd_redis_stat_elt *redis_elt = elt->ud;

	rspamd_redis_async_cbdata_cleanup (redis_elt->cbdata);
}

/* Called on connection termination */
static void
rspamd_redis_fin (gpointer data)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (data);
	redisAsyncContext *redis;

	rt->has_event = FALSE;
	/* Stop timeout */
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
rspamd_redis_fin_learn (gpointer data)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (data);
	redisAsyncContext *redis;

	rt->has_event = FALSE;
	/* Stop timeout */
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
rspamd_redis_timeout (gint fd, short what, gpointer d)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (d);
	struct rspamd_task *task;
	redisAsyncContext *redis;

	task = rt->task;

	msg_err_task_check ("connection to redis server %s timed out",
			rspamd_upstream_name (rt->selected));

	rspamd_upstream_fail (rt->selected);

	if (rt->redis) {
		redis = rt->redis;
		rt->redis = NULL;
		/* This calls for all callbacks pending */
		redisAsyncFree (redis);
	}
}

/* Called when we have connected to the redis server and got stats */
static void
rspamd_redis_connected (redisAsyncContext *c, gpointer r, gpointer priv)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (priv);
	redisReply *reply = r;
	struct rspamd_task *task;
	glong val = 0;

	task = rt->task;

	if (c->err == 0) {
		if (r != NULL) {
			if (G_LIKELY (reply->type == REDIS_REPLY_INTEGER)) {
				val = reply->integer;
			}
			else if (reply->type == REDIS_REPLY_STRING) {
				rspamd_strtol (reply->str, reply->len, &val);
			}
			else {
				if (reply->type != REDIS_REPLY_NIL) {
					msg_err_task ("bad learned type for %s: %d",
						rt->stcf->symbol, reply->type);
				}

				val = 0;
			}

			if (val < 0) {
				msg_warn_task ("invalid number of learns for %s: %L",
						rt->stcf->symbol, val);
				val = 0;
			}

			rt->learned = val;
			msg_debug_task ("connected to redis server, tokens learned for %s: %uL",
					rt->redis_object_expanded, rt->learned);
			rspamd_upstream_ok (rt->selected);
		}
	}
	else {
		msg_err_task ("error getting reply from redis server %s: %s",
				rspamd_upstream_name (rt->selected), c->errstr);
		rspamd_upstream_fail (rt->selected);
	}

}

/* Called when we have received tokens values from redis */
static void
rspamd_redis_processed (redisAsyncContext *c, gpointer r, gpointer priv)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (priv);
	redisReply *reply = r, *elt;
	struct rspamd_task *task;
	rspamd_token_t *tok;
	guint i, processed = 0, found = 0;
	gulong val;
	gdouble float_val;

	task = rt->task;

	if (c->err == 0) {
		if (r != NULL) {
			if (reply->type == REDIS_REPLY_ARRAY) {

				if (reply->elements == task->tokens->len) {
					for (i = 0; i < reply->elements; i ++) {
						tok = g_ptr_array_index (task->tokens, i);
						elt = reply->element[i];

						if (G_LIKELY (elt->type == REDIS_REPLY_INTEGER)) {
							tok->values[rt->id] = elt->integer;
							found ++;
						}
						else if (elt->type == REDIS_REPLY_STRING) {
							if (rt->stcf->clcf->flags &
									RSPAMD_FLAG_CLASSIFIER_INTEGER) {
								rspamd_strtoul (elt->str, elt->len, &val);
								tok->values[rt->id] = val;
							}
							else {
								float_val = strtod (elt->str, NULL);
								tok->values[rt->id] = float_val;
							}

							found ++;
						}
						else {
							tok->values[rt->id] = 0;
						}

						processed ++;
					}

					if (rt->stcf->is_spam) {
						task->flags |= RSPAMD_TASK_FLAG_HAS_SPAM_TOKENS;
					}
					else {
						task->flags |= RSPAMD_TASK_FLAG_HAS_HAM_TOKENS;
					}
				}
				else {
					msg_err_task_check ("got invalid length of reply vector from redis: "
							"%d, expected: %d",
							(gint)reply->elements,
							(gint)task->tokens->len);
				}
			}
			else {
				msg_err_task_check ("got invalid reply from redis: %d",
						reply->type);
			}

			msg_debug_task_check ("received tokens for %s: %d processed, %d found",
					rt->redis_object_expanded, processed, found);
			rspamd_upstream_ok (rt->selected);
		}
	}
	else {
		msg_err_task ("error getting reply from redis server %s: %s",
				rspamd_upstream_name (rt->selected), c->errstr);

		if (rt->redis) {
			rspamd_upstream_fail (rt->selected);
		}
	}

	if (rt->has_event) {
		rspamd_session_remove_event (task->s, rspamd_redis_fin, rt);
	}
}

/* Called when we have set tokens during learning */
static void
rspamd_redis_learned (redisAsyncContext *c, gpointer r, gpointer priv)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (priv);
	struct rspamd_task *task;

	task = rt->task;

	if (c->err == 0) {
		rspamd_upstream_ok (rt->selected);
	}
	else {
		msg_err_task_check ("error getting reply from redis server %s: %s",
				rspamd_upstream_name (rt->selected), c->errstr);

		if (rt->redis) {
			rspamd_upstream_fail (rt->selected);
		}
	}

	if (rt->has_event) {
		rspamd_session_remove_event (task->s, rspamd_redis_fin_learn, rt);
	}
}

static gboolean
rspamd_redis_try_ucl (struct redis_stat_ctx *backend,
		const ucl_object_t *obj,
		struct rspamd_config *cfg,
		const gchar *symbol)
{
	const ucl_object_t *elt, *relt, *users_enabled;
	const gchar *lua_script;

	elt = ucl_object_lookup_any (obj, "read_servers", "servers", NULL);

	if (elt == NULL) {
		return FALSE;
	}

	backend->read_servers = rspamd_upstreams_create (cfg->ups_ctx);
	if (!rspamd_upstreams_from_ucl (backend->read_servers, elt,
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
		backend->write_servers = rspamd_upstreams_create (cfg->ups_ctx);
		if (!rspamd_upstreams_from_ucl (backend->write_servers, relt,
				REDIS_DEFAULT_PORT, NULL)) {
			msg_err ("statfile %s cannot get write servers configuration",
					symbol);
			return FALSE;
		}
	}
	else {
		backend->write_servers = rspamd_upstreams_create (cfg->ups_ctx);
		if (!rspamd_upstreams_from_ucl (backend->write_servers, elt,
				REDIS_DEFAULT_PORT, NULL)) {
			msg_err ("statfile %s cannot get write servers configuration",
					symbol);
			rspamd_upstreams_destroy (backend->write_servers);
			backend->write_servers = NULL;
		}
	}

	elt = ucl_object_lookup (obj, "prefix");
	if (elt == NULL || ucl_object_type (elt) != UCL_STRING) {
		/* Default non-users statistics */
		backend->redis_object = REDIS_DEFAULT_OBJECT;

		/*
		 * Make redis backend compatible with sqlite3 backend in users settings
		 */
		users_enabled = ucl_object_lookup_any (obj, "per_user",
				"users_enabled", NULL);

		if (users_enabled != NULL) {
			if (ucl_object_type (users_enabled) == UCL_BOOLEAN) {
				backend->enable_users = ucl_object_toboolean (users_enabled);
				backend->cbref_user = -1;

				if (backend->enable_users) {
					backend->redis_object = REDIS_DEFAULT_USERS_OBJECT;
				}
			}
			else if (ucl_object_type (users_enabled) == UCL_STRING) {
				lua_script = ucl_object_tostring (users_enabled);

				if (luaL_dostring (cfg->lua_state, lua_script) != 0) {
					msg_err_config ("cannot execute lua script for users "
							"extraction: %s", lua_tostring (cfg->lua_state, -1));
				}
				else {
					if (lua_type (cfg->lua_state, -1) == LUA_TFUNCTION) {
						backend->enable_users = TRUE;
						backend->cbref_user = luaL_ref (cfg->lua_state,
								LUA_REGISTRYINDEX);
					}
					else {
						msg_err_config ("lua script must return "
								"function(task) and not %s",
								lua_typename (cfg->lua_state, lua_type (
										cfg->lua_state, -1)));
					}
				}
			}
		}
		else {
			backend->enable_users = FALSE;
		}
	}
	else {
		/* XXX: sanity check */
		backend->redis_object = ucl_object_tostring (elt);
	}

	elt = ucl_object_lookup (obj, "timeout");
	if (elt) {
		backend->timeout = ucl_object_todouble (elt);
	}
	else {
		backend->timeout = REDIS_DEFAULT_TIMEOUT;
	}

	elt = ucl_object_lookup (obj, "password");
	if (elt) {
		backend->password = ucl_object_tostring (elt);
	}
	else {
		backend->password = NULL;
	}

	elt = ucl_object_lookup_any (obj, "db", "database", "dbname", NULL);
	if (elt) {
		backend->dbname = ucl_object_tostring (elt);
	}
	else {
		backend->dbname = NULL;
	}

	return TRUE;
}

gpointer
rspamd_redis_init (struct rspamd_stat_ctx *ctx,
		struct rspamd_config *cfg, struct rspamd_statfile *st)
{
	struct redis_stat_ctx *backend;
	struct rspamd_statfile_config *stf = st->stcf;
	struct rspamd_redis_stat_elt *st_elt;
	const ucl_object_t *obj;
	gboolean ret = FALSE;

	backend = g_slice_alloc0 (sizeof (*backend));

	/* First search in backend configuration */
	obj = ucl_object_lookup (st->classifier->cfg->opts, "backend");
	if (obj != NULL && ucl_object_type (obj) == UCL_OBJECT) {
		ret = rspamd_redis_try_ucl (backend, obj, cfg, stf->symbol);
	}

	/* Now try statfiles config */
	if (!ret) {
		ret = rspamd_redis_try_ucl (backend, stf->opts, cfg, stf->symbol);
	}

	/* Now try classifier config */
	if (!ret) {
		ret = rspamd_redis_try_ucl (backend, st->classifier->cfg->opts, cfg,
				stf->symbol);
	}

	if (!ret) {
		msg_err_config ("cannot init redis backend for %s", stf->symbol);
		g_slice_free1 (sizeof (*backend), backend);
		return NULL;
	}

	stf->clcf->flags |= RSPAMD_FLAG_CLASSIFIER_INCREMENTING_BACKEND;
	backend->stcf = stf;

	st_elt = g_slice_alloc0 (sizeof (*st_elt));
	st_elt->ev_base = ctx->ev_base;
	st_elt->ctx = backend;
	backend->stat_elt = rspamd_stat_ctx_register_async (
			rspamd_redis_async_stat_cb,
			rspamd_redis_async_stat_fin,
			st_elt,
			REDIS_STAT_TIMEOUT);
	st_elt->async = backend->stat_elt;

	return (gpointer)backend;
}

gpointer
rspamd_redis_runtime (struct rspamd_task *task,
		struct rspamd_statfile_config *stcf,
		gboolean learn, gpointer c)
{
	struct redis_stat_ctx *ctx = REDIS_CTX (c);
	struct redis_stat_runtime *rt;
	struct upstream *up;
	rspamd_inet_addr_t *addr;

	g_assert (ctx != NULL);
	g_assert (stcf != NULL);

	if (learn && ctx->write_servers == NULL) {
		msg_err_task ("no write servers defined for %s, cannot learn", stcf->symbol);
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
	rspamd_redis_expand_object (ctx->redis_object, ctx, task,
			&rt->redis_object_expanded);
	rt->selected = up;
	rt->task = task;
	rt->ctx = ctx;
	rt->stcf = stcf;

	addr = rspamd_upstream_addr (up);
	g_assert (addr != NULL);
	rt->redis = redisAsyncConnect (rspamd_inet_address_to_string (addr),
			rspamd_inet_address_get_port (addr));

	if (rt->redis == NULL) {
		msg_err_task ("cannot connect redis");
		return NULL;
	}

	redisLibeventAttach (rt->redis, task->ev_base);
	rspamd_redis_maybe_auth (ctx, rt->redis);

	return rt;
}

void
rspamd_redis_close (gpointer p)
{
	struct redis_stat_ctx *ctx = REDIS_CTX (p);

	if (ctx->read_servers) {
		rspamd_upstreams_destroy (ctx->read_servers);
	}

	if (ctx->write_servers) {
		rspamd_upstreams_destroy (ctx->write_servers);
	}

	g_slice_free1 (sizeof (*ctx), ctx);
}

gboolean
rspamd_redis_process_tokens (struct rspamd_task *task,
		GPtrArray *tokens,
		gint id, gpointer p)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (p);
	rspamd_fstring_t *query;
	struct timeval tv;
	gint ret;

	if (tokens == NULL || tokens->len == 0 || rt->redis == NULL) {
		return FALSE;
	}

	rt->id = id;

	if (redisAsyncCommand (rt->redis, rspamd_redis_connected, rt, "HGET %s %s",
			rt->redis_object_expanded, "learns") == REDIS_OK) {

		rspamd_session_add_event (task->s, rspamd_redis_fin, rt,
				rspamd_redis_stat_quark ());
		rt->has_event = TRUE;

		if (event_get_base (&rt->timeout_event)) {
			event_del (&rt->timeout_event);
		}
		event_set (&rt->timeout_event, -1, EV_TIMEOUT, rspamd_redis_timeout, rt);
		event_base_set (task->ev_base, &rt->timeout_event);
		double_to_tv (rt->ctx->timeout, &tv);
		event_add (&rt->timeout_event, &tv);

		query = rspamd_redis_tokens_to_query (task, tokens,
				"HMGET", rt->redis_object_expanded, FALSE, -1,
				rt->stcf->clcf->flags & RSPAMD_FLAG_CLASSIFIER_INTEGER);
		g_assert (query != NULL);
		rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t)rspamd_fstring_free, query);

		ret = redisAsyncFormattedCommand (rt->redis, rspamd_redis_processed, rt,
				query->str, query->len);

		if (ret == REDIS_OK) {
			return TRUE;
		}
		else {
			msg_err_task ("call to redis failed: %s", rt->redis->errstr);
		}
	}

	return FALSE;
}

void
rspamd_redis_finalize_process (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (runtime);
	redisAsyncContext *redis;

	if (event_get_base (&rt->timeout_event)) {
		event_del (&rt->timeout_event);
	}

	if (rt->redis) {
		redis = rt->redis;
		rt->redis = NULL;
		redisAsyncFree (redis);
	}
}

gboolean
rspamd_redis_learn_tokens (struct rspamd_task *task, GPtrArray *tokens,
		gint id, gpointer p)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (p);
	struct upstream *up;
	rspamd_inet_addr_t *addr;
	struct timeval tv;
	rspamd_fstring_t *query;
	const gchar *redis_cmd;
	rspamd_token_t *tok;
	gint ret;

	up = rspamd_upstream_get (rt->ctx->write_servers,
			RSPAMD_UPSTREAM_MASTER_SLAVE,
			NULL,
			0);

	if (up == NULL) {
		msg_err_task ("no upstreams reachable");
		return FALSE;
	}

	rt->selected = up;

	addr = rspamd_upstream_addr (up);
	g_assert (addr != NULL);
	rt->redis = redisAsyncConnect (rspamd_inet_address_to_string (addr),
			rspamd_inet_address_get_port (addr));
	g_assert (rt->redis != NULL);

	redisLibeventAttach (rt->redis, task->ev_base);
	rspamd_redis_maybe_auth (rt->ctx, rt->redis);

	if (rt->stcf->clcf->flags & RSPAMD_FLAG_CLASSIFIER_INTEGER) {
		redis_cmd = "HINCRBY";
	}
	else {
		redis_cmd = "HINCRBYFLOAT";
	}

	rt->id = id;
	query = rspamd_redis_tokens_to_query (task, tokens,
			redis_cmd, rt->redis_object_expanded, TRUE, id,
			rt->stcf->clcf->flags & RSPAMD_FLAG_CLASSIFIER_INTEGER);
	g_assert (query != NULL);

	/*
	 * XXX:
	 * Dirty hack: we get a token and check if it's value is -1 or 1, so
	 * we could understand that we are learning or unlearning
	 */

	tok = g_ptr_array_index (task->tokens, 0);

	if (tok->values[id] > 0) {
		rspamd_printf_fstring (&query, ""
				"*4\r\n"
				"$7\r\n"
				"HINCRBY\r\n"
				"$%d\r\n"
				"%s\r\n"
				"$6\r\n"
				"learns\r\n"
				"$1\r\n"
				"1\r\n",
				(gint)strlen (rt->redis_object_expanded),
				rt->redis_object_expanded);
	}
	else {
		rspamd_printf_fstring (&query, ""
				"*4\r\n"
				"$7\r\n"
				"HINCRBY\r\n"
				"$%d\r\n"
				"%s\r\n"
				"$6\r\n"
				"learns\r\n"
				"$2\r\n"
				"-1\r\n",
				(gint)strlen (rt->redis_object_expanded),
				rt->redis_object_expanded);
	}

	rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t)rspamd_fstring_free, query);

	ret = redisAsyncFormattedCommand (rt->redis, rspamd_redis_learned, rt,
			query->str, query->len);

	if (ret == REDIS_OK) {
		rspamd_session_add_event (task->s, rspamd_redis_fin_learn, rt,
				rspamd_redis_stat_quark ());
		rt->has_event = TRUE;

		/* Set timeout */
		if (event_get_base (&rt->timeout_event)) {
			event_del (&rt->timeout_event);
		}
		event_set (&rt->timeout_event, -1, EV_TIMEOUT, rspamd_redis_timeout, rt);
		event_base_set (task->ev_base, &rt->timeout_event);
		double_to_tv (rt->ctx->timeout, &tv);
		event_add (&rt->timeout_event, &tv);

		return TRUE;
	}
	else {
		msg_err_task ("call to redis failed: %s", rt->redis->errstr);
	}

	return FALSE;
}


void
rspamd_redis_finalize_learn (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (runtime);
	redisAsyncContext *redis;

	if (event_get_base (&rt->timeout_event)) {
		event_del (&rt->timeout_event);
	}

	if (rt->redis) {
		redis = rt->redis;
		rt->redis = NULL;
		redisAsyncFree (redis);
	}
}

gulong
rspamd_redis_total_learns (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (runtime);

	return rt->learned;
}

gulong
rspamd_redis_inc_learns (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (runtime);

	/* XXX: may cause races */
	return rt->learned + 1;
}

gulong
rspamd_redis_dec_learns (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (runtime);

	/* XXX: may cause races */
	return rt->learned + 1;
}

gulong
rspamd_redis_learns (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (runtime);

	return rt->learned;
}

ucl_object_t *
rspamd_redis_get_stat (gpointer runtime,
		gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (runtime);
	struct rspamd_redis_stat_elt *st;
	redisAsyncContext *redis;

	if (rt->ctx->stat_elt) {
		st = rt->ctx->stat_elt->ud;

		if (rt->redis) {
			redis = rt->redis;
			rt->redis = NULL;
			redisAsyncFree (redis);
		}

		if (st->stat) {
			return ucl_object_ref (st->stat);
		}
	}

	return NULL;
}

gpointer
rspamd_redis_load_tokenizer_config (gpointer runtime,
		gsize *len)
{
	return NULL;
}

#endif
