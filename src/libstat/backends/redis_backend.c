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
#include "libserver/mempool_vars_internal.h"
#include "hiredis.h"
#include "adapters/libev.h"
#include "ref.h"

#define msg_debug_stat_redis(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_stat_redis_log_id, "stat_redis", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(stat_redis)

#define REDIS_CTX(p) (struct redis_stat_ctx *)(p)
#define REDIS_RUNTIME(p) (struct redis_stat_runtime *)(p)
#define REDIS_BACKEND_TYPE "redis"
#define REDIS_DEFAULT_PORT 6379
#define REDIS_DEFAULT_OBJECT "%s%l"
#define REDIS_DEFAULT_USERS_OBJECT "%s%l%r"
#define REDIS_DEFAULT_TIMEOUT 0.5
#define REDIS_STAT_TIMEOUT 30

struct redis_stat_ctx {
	lua_State *L;
	struct rspamd_statfile_config *stcf;
	gint conf_ref;
	struct rspamd_stat_async_elt *stat_elt;
	const gchar *redis_object;
	const gchar *password;
	const gchar *dbname;
	gdouble timeout;
	gboolean enable_users;
	gboolean store_tokens;
	gboolean new_schema;
	gboolean enable_signatures;
	guint expiry;
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
	ev_timer timeout_event;
	GArray *results;
	GPtrArray *tokens;
	struct rspamd_statfile_config *stcf;
	gchar *redis_object_expanded;
	redisAsyncContext *redis;
	guint64 learned;
	gint id;
	gboolean has_event;
	GError *err;
};

/* Used to get statistics from redis */
struct rspamd_redis_stat_cbdata;

struct rspamd_redis_stat_elt {
	struct redis_stat_ctx *ctx;
	struct rspamd_stat_async_elt *async;
	struct ev_loop *event_loop;
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

static const gchar *M = "redis statistics";

static GQuark
rspamd_redis_stat_quark (void)
{
	return g_quark_from_static_string (M);
}

static inline struct upstream_list *
rspamd_redis_get_servers (struct redis_stat_ctx *ctx,
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
	const gchar *rcpt = NULL;
	gint err_idx;

	g_assert (ctx != NULL);
	g_assert (task != NULL);
	stcf = ctx->stcf;

	L = task->cfg->lua_state;
	g_assert (L != NULL);

	if (ctx->enable_users) {
		if (ctx->cbref_user == -1) {
			rcpt = rspamd_task_get_principal_recipient (task);
		}
		else {
			/* Execute lua function to get userdata */
			lua_pushcfunction (L, &rspamd_lua_traceback);
			err_idx = lua_gettop (L);

			lua_rawgeti (L, LUA_REGISTRYINDEX, ctx->cbref_user);
			ptask = lua_newuserdata (L, sizeof (struct rspamd_task *));
			*ptask = task;
			rspamd_lua_setclass (L, "rspamd{task}", -1);

			if (lua_pcall (L, 1, 1, err_idx) != 0) {
				msg_err_task ("call to user extraction script failed: %s",
						lua_tostring (L, -1));
			}
			else {
				rcpt = rspamd_mempool_strdup (task->task_pool, lua_tostring (L, -1));
			}

			/* Result + error function */
			lua_settop (L, err_idx - 1);
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
				/* Label miss is OK */
				break;
			case 's':
				if (ctx->new_schema) {
					tlen += sizeof ("RS") - 1;
				}
				else {
					if (stcf->symbol) {
						tlen += strlen (stcf->symbol);
					}
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


	if (target == NULL) {
		return -1;
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
				if (ctx->new_schema) {
					d += rspamd_strlcpy (d, "RS", end - d);
				}
				else {
					if (stcf->symbol) {
						d += rspamd_strlcpy (d, stcf->symbol, end - d);
					}
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

// the `b` conversion type character is unknown to gcc
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"
#endif
static rspamd_fstring_t *
rspamd_redis_tokens_to_query (struct rspamd_task *task,
		struct redis_stat_runtime *rt,
		GPtrArray *tokens,
		const gchar *command,
		const gchar *prefix,
		gboolean learn,
		gint idx,
		gboolean intvals)
{
	rspamd_fstring_t *out;
	rspamd_token_t *tok;
	gchar n0[512], n1[64];
	guint i, l0, l1, cmd_len, prefix_len;
	gint ret;

	g_assert (tokens != NULL);

	cmd_len = strlen (command);
	prefix_len = strlen (prefix);
	out = rspamd_fstring_sized_new (1024);

	if (learn) {
		rspamd_printf_fstring (&out, "*1\r\n$5\r\nMULTI\r\n");

		ret = redisAsyncFormattedCommand (rt->redis, NULL, NULL,
				out->str, out->len);

		if (ret != REDIS_OK) {
			msg_err_task ("call to redis failed: %s", rt->redis->errstr);
			rspamd_fstring_free (out);

			return NULL;
		}

		out->len = 0;
	}
	else {
		if (rt->ctx->new_schema) {
			/* Multi + HGET */
			rspamd_printf_fstring (&out, "*1\r\n$5\r\nMULTI\r\n");

			ret = redisAsyncFormattedCommand (rt->redis, NULL, NULL,
					out->str, out->len);

			if (ret != REDIS_OK) {
				msg_err_task ("call to redis failed: %s", rt->redis->errstr);
				rspamd_fstring_free (out);

				return NULL;
			}

			out->len = 0;
		}
		else {
			rspamd_printf_fstring (&out, ""
							"*%d\r\n"
							"$%d\r\n"
							"%s\r\n"
							"$%d\r\n"
							"%s\r\n",
					(tokens->len + 2),
					cmd_len, command,
					prefix_len, prefix);
		}
	}

	for (i = 0; i < tokens->len; i ++) {
		tok = g_ptr_array_index (tokens, i);

		if (learn) {
			if (intvals) {
				l1 = rspamd_snprintf (n1, sizeof (n1), "%L",
						(gint64) tok->values[idx]);
			} else {
				l1 = rspamd_snprintf (n1, sizeof (n1), "%f",
						tok->values[idx]);
			}

			if (rt->ctx->new_schema) {
				/*
				 * HINCRBY <prefix_token> <0|1> <value>
				 */
				l0 = rspamd_snprintf (n0, sizeof (n0), "%*s_%uL",
						prefix_len, prefix,
						tok->data);

				rspamd_printf_fstring (&out, ""
								"*4\r\n"
								"$%d\r\n"
								"%s\r\n"
								"$%d\r\n"
								"%s\r\n"
								"$%d\r\n"
								"%s\r\n"
								"$%d\r\n"
								"%s\r\n",
						cmd_len, command,
						l0, n0,
						1, rt->stcf->is_spam ? "S" : "H",
						l1, n1);
			}
			else {
				l0 = rspamd_snprintf (n0, sizeof (n0), "%uL", tok->data);

				/*
				 * HINCRBY <prefix> <token> <value>
				 */
				rspamd_printf_fstring (&out, ""
								"*4\r\n"
								"$%d\r\n"
								"%s\r\n"
								"$%d\r\n"
								"%s\r\n"
								"$%d\r\n"
								"%s\r\n"
								"$%d\r\n"
								"%s\r\n",
						cmd_len, command,
						prefix_len, prefix,
						l0, n0,
						l1, n1);
			}

			ret = redisAsyncFormattedCommand (rt->redis, NULL, NULL,
					out->str, out->len);

			if (ret != REDIS_OK) {
				msg_err_task ("call to redis failed: %s", rt->redis->errstr);
				rspamd_fstring_free (out);

				return NULL;
			}

			if (rt->ctx->store_tokens) {

				if (!rt->ctx->new_schema) {
					/*
					 * We store tokens in form
					 * HSET prefix_tokens <token_id> "token_string"
					 * ZINCRBY prefix_z 1.0 <token_id>
					 */
					if (tok->t1 && tok->t2) {
						redisAsyncCommand (rt->redis, NULL, NULL,
								"HSET %b_tokens %b %b:%b",
								prefix, (size_t) prefix_len,
								n0, (size_t) l0,
								tok->t1->stemmed.begin, tok->t1->stemmed.len,
								tok->t2->stemmed.begin, tok->t2->stemmed.len);
					} else if (tok->t1) {
						redisAsyncCommand (rt->redis, NULL, NULL,
								"HSET %b_tokens %b %b",
								prefix, (size_t) prefix_len,
								n0, (size_t) l0,
								tok->t1->stemmed.begin,
								tok->t1->stemmed.len);
					}
				}
				else {
					/*
					 * We store tokens in form
					 * HSET <token_id> "tokens" "token_string"
					 * ZINCRBY prefix_z 1.0 <token_id>
					 */
					if (tok->t1 && tok->t2) {
						redisAsyncCommand (rt->redis, NULL, NULL,
								"HSET %b %s %b:%b",
								n0, (size_t) l0,
								"tokens",
								tok->t1->stemmed.begin, tok->t1->stemmed.len,
								tok->t2->stemmed.begin, tok->t2->stemmed.len);
					} else if (tok->t1) {
						redisAsyncCommand (rt->redis, NULL, NULL,
								"HSET %b %s %b",
								n0, (size_t) l0,
								"tokens",
								tok->t1->stemmed.begin, tok->t1->stemmed.len);
					}
				}

				redisAsyncCommand (rt->redis, NULL, NULL,
						"ZINCRBY %b_z %b %b",
						prefix, (size_t)prefix_len,
						n1, (size_t)l1,
						n0, (size_t)l0);
			}

			if (rt->ctx->new_schema && rt->ctx->expiry > 0) {
				out->len = 0;
				l1 = rspamd_snprintf (n1, sizeof (n1), "%d",
						rt->ctx->expiry);

				rspamd_printf_fstring (&out, ""
								"*3\r\n"
								"$6\r\n"
								"EXPIRE\r\n"
								"$%d\r\n"
								"%s\r\n"
								"$%d\r\n"
								"%s\r\n",
						l0, n0,
						l1, n1);
				redisAsyncFormattedCommand (rt->redis, NULL, NULL,
						out->str, out->len);
			}

			out->len = 0;
		}
		else {
			if (rt->ctx->new_schema) {
				l0 = rspamd_snprintf (n0, sizeof (n0), "%*s_%uL",
						prefix_len, prefix,
						tok->data);

				rspamd_printf_fstring (&out, ""
								"*3\r\n"
								"$%d\r\n"
								"%s\r\n"
								"$%d\r\n"
								"%s\r\n"
								"$%d\r\n"
								"%s\r\n",
						cmd_len, command,
						l0, n0,
						1, rt->stcf->is_spam ? "S" : "H");

				ret = redisAsyncFormattedCommand (rt->redis, NULL, NULL,
						out->str, out->len);

				if (ret != REDIS_OK) {
					msg_err_task ("call to redis failed: %s", rt->redis->errstr);
					rspamd_fstring_free (out);

					return NULL;
				}

				out->len = 0;
			}
			else {
				l0 = rspamd_snprintf (n0, sizeof (n0), "%uL", tok->data);
				rspamd_printf_fstring (&out, ""
						"$%d\r\n"
						"%s\r\n", l0, n0);
			}
		}
	}

	if (!learn && rt->ctx->new_schema) {
		rspamd_printf_fstring (&out, "*1\r\n$4\r\nEXEC\r\n");
	}

	return out;
}
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

static void
rspamd_redis_store_stat_signature (struct rspamd_task *task,
		struct redis_stat_runtime *rt,
		GPtrArray *tokens,
		const gchar *prefix)
{
	gchar *sig, keybuf[512], nbuf[64];
	rspamd_token_t *tok;
	guint i, blen, klen;
	rspamd_fstring_t *out;

	sig = rspamd_mempool_get_variable (task->task_pool,
			RSPAMD_MEMPOOL_STAT_SIGNATURE);

	if (sig == NULL) {
		msg_err_task ("cannot get bayes signature");
		return;
	}

	out = rspamd_fstring_sized_new (1024);
	klen = rspamd_snprintf (keybuf, sizeof (keybuf), "%s_%s_%s",
			prefix, sig, rt->stcf->is_spam ? "S" : "H");

	/* Cleanup key */
	rspamd_printf_fstring (&out, ""
					"*2\r\n"
					"$3\r\n"
					"DEL\r\n"
					"$%d\r\n"
					"%s\r\n",
			klen, keybuf);
	redisAsyncFormattedCommand (rt->redis, NULL, NULL,
			out->str, out->len);
	out->len = 0;

	rspamd_printf_fstring (&out, ""
					"*%d\r\n"
					"$5\r\n"
					"LPUSH\r\n"
					"$%d\r\n"
					"%s\r\n",
			tokens->len + 2,
			klen, keybuf);

	PTR_ARRAY_FOREACH (tokens, i, tok) {
		blen = rspamd_snprintf (nbuf, sizeof (nbuf), "%uL", tok->data);
		rspamd_printf_fstring (&out, ""
				"$%d\r\n"
				"%s\r\n", blen, nbuf);
	}

	redisAsyncFormattedCommand (rt->redis, NULL, NULL,
			out->str, out->len);
	out->len = 0;

	if (rt->ctx->expiry > 0) {
		out->len = 0;
		blen = rspamd_snprintf (nbuf, sizeof (nbuf), "%d",
				rt->ctx->expiry);

		rspamd_printf_fstring (&out, ""
						"*3\r\n"
						"$6\r\n"
						"EXPIRE\r\n"
						"$%d\r\n"
						"%s\r\n"
						"$%d\r\n"
						"%s\r\n",
				klen, keybuf,
				blen, nbuf);
		redisAsyncFormattedCommand (rt->redis, NULL, NULL,
				out->str, out->len);
	}

	rspamd_fstring_free (out);
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

		g_free (cbdata);
	}
}

/* Called when we get number of learns for a specific key */
static void
rspamd_redis_stat_learns (redisAsyncContext *c, gpointer r, gpointer priv)
{
	struct rspamd_redis_stat_elt *redis_elt = (struct rspamd_redis_stat_elt *)priv;
	struct rspamd_redis_stat_cbdata *cbdata;
	redisReply *reply = r;
	ucl_object_t *obj;
	gulong num = 0;

	cbdata = redis_elt->cbdata;

	if (cbdata == NULL || cbdata->wanna_die) {
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

		obj = (ucl_object_t *) ucl_object_lookup (cbdata->cur, "revision");
		if (obj) {
			obj->value.iv += num;
		}
	}

	if (cbdata->inflight == 0) {
		rspamd_redis_async_cbdata_cleanup (cbdata);
		redis_elt->cbdata = NULL;
	}
}

/* Called when we get number of elements for a specific key */
static void
rspamd_redis_stat_key (redisAsyncContext *c, gpointer r, gpointer priv)
{
	struct rspamd_redis_stat_elt *redis_elt = (struct rspamd_redis_stat_elt *)priv;
	struct rspamd_redis_stat_cbdata *cbdata;
	redisReply *reply = r;
	ucl_object_t *obj;
	glong num = 0;

	cbdata = redis_elt->cbdata;

	if (cbdata == NULL || cbdata->wanna_die) {
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
		redis_elt->cbdata = NULL;
	}
}

/* Called when we have connected to the redis server and got keys to check */
static void
rspamd_redis_stat_keys (redisAsyncContext *c, gpointer r, gpointer priv)
{
	struct rspamd_redis_stat_elt *redis_elt = (struct rspamd_redis_stat_elt *)priv;
	struct rspamd_redis_stat_cbdata *cbdata;
	redisReply *reply = r, *more_elt, *elts, *elt;
	gchar **pk, *k;
	guint i, processed = 0;
	gboolean more = false;

	cbdata = redis_elt->cbdata;

	if (cbdata == NULL || cbdata->wanna_die) {
		return;
	}

	cbdata->inflight --;

	if (c->err == 0 && r != NULL) {
		if (reply->type == REDIS_REPLY_ARRAY) {
			more_elt = reply->element[0];
			elts = reply->element[1];

			if (more_elt != NULL && more_elt->str != NULL && strcmp (more_elt->str, "0") != 0) {
				more = true;
			}

			/* Clear the existing stuff */
			PTR_ARRAY_FOREACH (cbdata->cur_keys, i, k) {
				if (k) {
					g_free (k);
				}
			}

			g_ptr_array_set_size (cbdata->cur_keys, elts->elements);

			for (i = 0; i < elts->elements; i ++) {
				elt = elts->element[i];

				if (elt->type == REDIS_REPLY_STRING) {
					pk = (gchar **)&g_ptr_array_index (cbdata->cur_keys, i);
					*pk = g_malloc (elt->len + 1);
					rspamd_strlcpy (*pk, elt->str, elt->len + 1);
					processed ++;
				}
				else {
					pk = (gchar **)&g_ptr_array_index (cbdata->cur_keys, i);
					*pk = NULL;
				}
			}

			if (processed) {
				PTR_ARRAY_FOREACH (cbdata->cur_keys, i, k) {
					if (k) {
						const gchar *learned_key = "learns";

						if (cbdata->elt->ctx->new_schema) {
							if (cbdata->elt->ctx->stcf->is_spam) {
								learned_key = "learns_spam";
							}
							else {
								learned_key = "learns_ham";
							}
							redisAsyncCommand (cbdata->redis,
									rspamd_redis_stat_learns,
									redis_elt,
									"HGET %s %s",
									k, learned_key);
							cbdata->inflight += 1;
						}
						else {
							redisAsyncCommand (cbdata->redis,
									rspamd_redis_stat_key,
									redis_elt,
									"HLEN %s",
									k);
							redisAsyncCommand (cbdata->redis,
									rspamd_redis_stat_learns,
									redis_elt,
									"HGET %s %s",
									k, learned_key);
							cbdata->inflight += 2;
						}
					}
				}
			}
		}

		if (more) {
			/* Get more stat keys */
			redisAsyncCommand (cbdata->redis, rspamd_redis_stat_keys, redis_elt,
					"SSCAN %s_keys %s COUNT 1000",
					cbdata->elt->ctx->stcf->symbol, more_elt->str);

			cbdata->inflight += 1;
		}
		else {
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

			if (cbdata->inflight == 0) {
				rspamd_redis_async_cbdata_cleanup (cbdata);
				redis_elt->cbdata = NULL;
			}
		}
	}
	else {
		if (c->errstr) {
			msg_err ("cannot get keys to gather stat: %s", c->errstr);
		}
		else {
			msg_err ("cannot get keys to gather stat: unknown error");
		}

		rspamd_upstream_fail (cbdata->selected, FALSE, c->errstr);
		rspamd_redis_async_cbdata_cleanup (cbdata);
		redis_elt->cbdata = NULL;
	}
}

static void
rspamd_redis_async_stat_cb (struct rspamd_stat_async_elt *elt, gpointer d)
{
	struct redis_stat_ctx *ctx;
	struct rspamd_redis_stat_elt *redis_elt = elt->ud;
	struct rspamd_redis_stat_cbdata *cbdata;
	rspamd_inet_addr_t *addr;
	struct upstream_list *ups;
	redisAsyncContext *redis_ctx;
	struct upstream *selected;

	g_assert (redis_elt != NULL);

	ctx = redis_elt->ctx;

	if (redis_elt->cbdata) {
		/* We have some other process pending */
		rspamd_redis_async_cbdata_cleanup (redis_elt->cbdata);
		redis_elt->cbdata = NULL;
	}

	/* Disable further events unless needed */
	elt->enabled = FALSE;

	ups = rspamd_redis_get_servers (ctx, "read_servers");

	if (!ups) {
		return;
	}

	selected = rspamd_upstream_get (ups,
					RSPAMD_UPSTREAM_ROUND_ROBIN,
					NULL,
					0);

	g_assert (selected != NULL);
	addr = rspamd_upstream_addr_next (selected);
	g_assert (addr != NULL);

	if (rspamd_inet_address_get_af (addr) == AF_UNIX) {
		redis_ctx = redisAsyncConnectUnix (rspamd_inet_address_to_string (addr));
	}
	else {
		redis_ctx = redisAsyncConnect (rspamd_inet_address_to_string (addr),
				rspamd_inet_address_get_port (addr));
	}

	if (redis_ctx == NULL) {
		msg_warn ("cannot connect to redis server %s: %s",
				rspamd_inet_address_to_string_pretty (addr),
				strerror (errno));

		return;
	}
	else if (redis_ctx->err != REDIS_OK) {
		msg_warn ("cannot connect to redis server %s: %s",
				rspamd_inet_address_to_string_pretty (addr),
				redis_ctx->errstr);
		redisAsyncFree (redis_ctx);

		return;
	}

	redisLibevAttach (redis_elt->event_loop, redis_ctx);
	cbdata = g_malloc0 (sizeof (*cbdata));
	cbdata->redis = redis_ctx;
	cbdata->selected = selected;
	cbdata->inflight = 1;
	cbdata->cur = ucl_object_typed_new (UCL_OBJECT);
	cbdata->elt = redis_elt;
	cbdata->cur_keys = g_ptr_array_sized_new (1000);
	redis_elt->cbdata = cbdata;

	/* XXX: deal with timeouts maybe */
	/* Get keys in redis that match our symbol */
	rspamd_redis_maybe_auth (ctx, cbdata->redis);
	redisAsyncCommand (cbdata->redis, rspamd_redis_stat_keys, redis_elt,
			"SSCAN %s_keys 0 COUNT 1000",
			ctx->stcf->symbol);
}

static void
rspamd_redis_async_stat_fin (struct rspamd_stat_async_elt *elt, gpointer d)
{
	struct rspamd_redis_stat_elt *redis_elt = elt->ud;

	if (redis_elt->cbdata != NULL) {
		rspamd_redis_async_cbdata_cleanup (redis_elt->cbdata);
		redis_elt->cbdata = NULL;
	}
}

/* Called on connection termination */
static void
rspamd_redis_fin (gpointer data)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (data);
	redisAsyncContext *redis;

	if (rt->has_event) {
		/* Should not happen ! */
		msg_err ("FIXME: this code path should not be reached!");
		rspamd_session_remove_event (rt->task->s, NULL, rt);
		rt->has_event = FALSE;
	}
	/* Stop timeout */
	if (ev_can_stop (&rt->timeout_event)) {
		ev_timer_stop (rt->task->event_loop, &rt->timeout_event);
	}

	if (rt->tokens) {
		g_ptr_array_unref (rt->tokens);
		rt->tokens = NULL;
	}

	if (rt->redis) {
		redis = rt->redis;
		rt->redis = NULL;
		/* This calls for all callbacks pending */
		redisAsyncFree (redis);
	}

	if (rt->err) {
		g_error_free (rt->err);
	}
}

static void
rspamd_redis_timeout (EV_P_ ev_timer *w, int revents)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (w->data);
	struct rspamd_task *task;
	redisAsyncContext *redis;

	task = rt->task;

	msg_err_task_check ("connection to redis server %s timed out",
			rspamd_upstream_name (rt->selected));

	rspamd_upstream_fail (rt->selected, FALSE, "timeout");

	if (rt->redis) {
		redis = rt->redis;
		rt->redis = NULL;
		/* This calls for all callbacks pending */
		redisAsyncFree (redis);
	}

	if (rt->tokens) {
		g_ptr_array_unref (rt->tokens);
		rt->tokens = NULL;
	}

	if (!rt->err) {
		g_set_error (&rt->err, rspamd_redis_stat_quark (), ETIMEDOUT,
				"error getting reply from redis server %s: timeout",
				rspamd_upstream_name (rt->selected));
	}
	if (rt->has_event) {
		rt->has_event = FALSE;
		rspamd_session_remove_event (task->s, NULL, rt);
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

	if (c->err == 0 && rt->has_event) {
		if (r != NULL) {
			if (reply->type == REDIS_REPLY_ARRAY) {

				if (reply->elements == task->tokens->len) {
					for (i = 0; i < reply->elements; i ++) {
						tok = g_ptr_array_index (task->tokens, i);
						elt = reply->element[i];

						if (G_UNLIKELY (elt->type == REDIS_REPLY_INTEGER)) {
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
								float_val = strtof (elt->str, NULL);
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
				if (reply->type == REDIS_REPLY_ERROR) {
					msg_err_task_check ("cannot learn %s: redis error: \"%s\"",
							rt->stcf->symbol, reply->str);
				}
				else {
					msg_err_task_check ("got invalid reply from redis: %s, array expected",
							rspamd_redis_type_to_string(reply->type));
				}
			}

			msg_debug_stat_redis ("received tokens for %s: %d processed, %d found",
					rt->redis_object_expanded, processed, found);
			rspamd_upstream_ok (rt->selected);
		}
	}
	else {
		msg_err_task ("error getting reply from redis server %s: %s",
				rspamd_upstream_name (rt->selected), c->errstr);

		if (rt->redis) {
			rspamd_upstream_fail (rt->selected, FALSE, c->errstr);
		}

		if (!rt->err) {
			g_set_error (&rt->err, rspamd_redis_stat_quark (), c->err,
					"cannot get values: error getting reply from redis server %s: %s",
					rspamd_upstream_name (rt->selected), c->errstr);
		}
	}

	if (rt->has_event) {
		rt->has_event = FALSE;
		rspamd_session_remove_event (task->s, NULL, rt);
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
	gboolean final = TRUE;

	task = rt->task;

	if (c->err == 0 && rt->has_event) {
		if (r != NULL) {
			if (G_UNLIKELY (reply->type == REDIS_REPLY_INTEGER)) {
				val = reply->integer;
			}
			else if (reply->type == REDIS_REPLY_STRING) {
				rspamd_strtol (reply->str, reply->len, &val);
			}
			else {
				if (reply->type != REDIS_REPLY_NIL) {
					if (reply->type == REDIS_REPLY_ERROR) {
						msg_err_task ("cannot learn %s: redis error: \"%s\"",
								rt->stcf->symbol, reply->str);
					}
					else {
						msg_err_task ("bad learned type for %s: %s, nil expected",
								rt->stcf->symbol,
								rspamd_redis_type_to_string(reply->type));
					}
				}

				val = 0;
			}

			if (val < 0) {
				msg_warn_task ("invalid number of learns for %s: %L",
						rt->stcf->symbol, val);
				val = 0;
			}

			rt->learned = val;
			msg_debug_stat_redis ("connected to redis server, tokens learned for %s: %uL",
					rt->redis_object_expanded, rt->learned);
			rspamd_upstream_ok (rt->selected);

			/* Save learn count in mempool variable */
			gint64 *learns_cnt;
			const gchar *var_name;

			if (rt->stcf->is_spam) {
				var_name = RSPAMD_MEMPOOL_SPAM_LEARNS;
			}
			else {
				var_name = RSPAMD_MEMPOOL_HAM_LEARNS;
			}

			learns_cnt = rspamd_mempool_get_variable (task->task_pool,
					var_name);

			if (learns_cnt) {
				(*learns_cnt) += rt->learned;
			}
			else {
				learns_cnt = rspamd_mempool_alloc (task->task_pool,
						sizeof (*learns_cnt));
				*learns_cnt = rt->learned;
				rspamd_mempool_set_variable (task->task_pool,
						var_name,
						learns_cnt, NULL);
			}

			if (rt->learned >= rt->stcf->clcf->min_learns && rt->learned > 0) {
				rspamd_fstring_t *query = rspamd_redis_tokens_to_query (
						task,
						rt,
						rt->tokens,
						rt->ctx->new_schema ? "HGET" : "HMGET",
						rt->redis_object_expanded, FALSE, -1,
						rt->stcf->clcf->flags & RSPAMD_FLAG_CLASSIFIER_INTEGER);
				g_assert (query != NULL);
				rspamd_mempool_add_destructor (task->task_pool,
						(rspamd_mempool_destruct_t)rspamd_fstring_free, query);

				int ret = redisAsyncFormattedCommand (rt->redis,
						rspamd_redis_processed, rt,
						query->str, query->len);

				if (ret != REDIS_OK) {
					msg_err_task ("call to redis failed: %s", rt->redis->errstr);
				}
				else {
					/* Further is handled by rspamd_redis_processed */
					final = FALSE;
					/* Restart timeout */
					if (ev_can_stop (&rt->timeout_event)) {
						rt->timeout_event.repeat = rt->ctx->timeout;
						ev_timer_again (task->event_loop, &rt->timeout_event);
					}
					else {
						rt->timeout_event.data = rt;
						ev_timer_init (&rt->timeout_event, rspamd_redis_timeout,
								rt->ctx->timeout, 0.);
						ev_timer_start (task->event_loop, &rt->timeout_event);
					}
				}
			}
			else {
				msg_warn_task ("skip obtaining bayes tokens for %s of classifier "
							   "%s: not enough learns %d; %d required",
						rt->stcf->symbol, rt->stcf->clcf->name,
						(int)rt->learned, rt->stcf->clcf->min_learns);
			}
		}
	}
	else if (rt->has_event) {
		msg_err_task ("error getting reply from redis server %s: %s",
				rspamd_upstream_name (rt->selected), c->errstr);
		rspamd_upstream_fail (rt->selected, FALSE,  c->errstr);

		if (!rt->err) {
			g_set_error (&rt->err, rspamd_redis_stat_quark (), c->err,
					"error getting reply from redis server %s: %s",
					rspamd_upstream_name (rt->selected), c->errstr);
		}
	}

	if (final && rt->has_event) {
		rt->has_event = FALSE;
		rspamd_session_remove_event (task->s, NULL, rt);
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
			rspamd_upstream_fail (rt->selected, FALSE, c->errstr);
		}

		if (!rt->err) {
			g_set_error (&rt->err, rspamd_redis_stat_quark (), c->err,
					"cannot get learned: error getting reply from redis server %s: %s",
					rspamd_upstream_name (rt->selected), c->errstr);
		}
	}

	if (rt->has_event) {
		rt->has_event = FALSE;
		rspamd_session_remove_event (task->s, NULL, rt);
	}
}
static void
rspamd_redis_parse_classifier_opts (struct redis_stat_ctx *backend,
		const ucl_object_t *obj,
		struct rspamd_config *cfg)
{
	const gchar *lua_script;
	const ucl_object_t *elt, *users_enabled;

	users_enabled = ucl_object_lookup_any (obj, "per_user",
			"users_enabled", NULL);

	if (users_enabled != NULL) {
		if (ucl_object_type (users_enabled) == UCL_BOOLEAN) {
			backend->enable_users = ucl_object_toboolean (users_enabled);
			backend->cbref_user = -1;
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
		backend->cbref_user = -1;
	}

	elt = ucl_object_lookup (obj, "prefix");
	if (elt == NULL || ucl_object_type (elt) != UCL_STRING) {
		/* Default non-users statistics */
		if (backend->enable_users || backend->cbref_user != -1) {
			backend->redis_object = REDIS_DEFAULT_USERS_OBJECT;
		}
		else {
			backend->redis_object = REDIS_DEFAULT_OBJECT;
		}
	}
	else {
		/* XXX: sanity check */
		backend->redis_object = ucl_object_tostring (elt);
	}

	elt = ucl_object_lookup (obj, "store_tokens");
	if (elt) {
		backend->store_tokens = ucl_object_toboolean (elt);
	}
	else {
		backend->store_tokens = FALSE;
	}

	elt = ucl_object_lookup (obj, "new_schema");
	if (elt) {
		backend->new_schema = ucl_object_toboolean (elt);
	}
	else {
		backend->new_schema = FALSE;

		msg_warn_config ("you are using old bayes schema for redis statistics, "
				"please consider converting it to a new one "
				"by using 'rspamadm configwizard statistics'");
	}

	elt = ucl_object_lookup (obj, "signatures");
	if (elt) {
		backend->enable_signatures = ucl_object_toboolean (elt);
	}
	else {
		backend->enable_signatures = FALSE;
	}

	elt = ucl_object_lookup_any (obj, "expiry", "expire", NULL);
	if (elt) {
		backend->expiry = ucl_object_toint (elt);
	}
	else {
		backend->expiry = 0;
	}
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
	gint conf_ref = -1;
	lua_State *L = (lua_State *)cfg->lua_state;

	backend = g_malloc0 (sizeof (*backend));
	backend->L = L;
	backend->timeout = REDIS_DEFAULT_TIMEOUT;

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
		msg_err_config ("cannot init redis backend for %s", stf->symbol);
		g_free (backend);
		return NULL;
	}

	backend->conf_ref = conf_ref;

	/* Check some common table values */
	lua_rawgeti (L, LUA_REGISTRYINDEX, conf_ref);

	lua_pushstring (L, "timeout");
	lua_gettable (L, -2);
	if (lua_type (L, -1) == LUA_TNUMBER) {
		backend->timeout = lua_tonumber (L, -1);
	}
	lua_pop (L, 1);

	lua_pushstring (L, "db");
	lua_gettable (L, -2);
	if (lua_type (L, -1) == LUA_TSTRING) {
		backend->dbname = rspamd_mempool_strdup (cfg->cfg_pool,
				lua_tostring (L, -1));
	}
	lua_pop (L, 1);

	lua_pushstring (L, "password");
	lua_gettable (L, -2);
	if (lua_type (L, -1) == LUA_TSTRING) {
		backend->password = rspamd_mempool_strdup (cfg->cfg_pool,
				lua_tostring (L, -1));
	}
	lua_pop (L, 1);

	lua_settop (L, 0);

	rspamd_redis_parse_classifier_opts (backend, st->classifier->cfg->opts, cfg);
	stf->clcf->flags |= RSPAMD_FLAG_CLASSIFIER_INCREMENTING_BACKEND;
	backend->stcf = stf;

	st_elt = g_malloc0 (sizeof (*st_elt));
	st_elt->event_loop = ctx->event_loop;
	st_elt->ctx = backend;
	backend->stat_elt = rspamd_stat_ctx_register_async (
			rspamd_redis_async_stat_cb,
			rspamd_redis_async_stat_fin,
			st_elt,
			REDIS_STAT_TIMEOUT);
	st_elt->async = backend->stat_elt;

	return (gpointer)backend;
}

/*
 * This callback is called when Redis is disconnected somehow, and the structure
 * itself is usually freed by hiredis itself
 */
static void
rspamd_stat_redis_on_disconnect(const struct redisAsyncContext *ac, int status)
{
	struct redis_stat_runtime *rt = (struct redis_stat_runtime *)ac->data;

	if (ev_can_stop (&rt->timeout_event)) {
		ev_timer_stop (rt->task->event_loop, &rt->timeout_event);
	}
	rt->redis = NULL;
}

static void
rspamd_stat_redis_on_connect(const struct redisAsyncContext *ac, int status)
{
	struct redis_stat_runtime *rt = (struct redis_stat_runtime *)ac->data;


	if (status == REDIS_ERR) {
		/*
		 * We also need to reset rt->redis as it will be subsequently freed without
		 * calling for redis_on_disconnect callback...
		 */
		if (ev_can_stop (&rt->timeout_event)) {
			ev_timer_stop (rt->task->event_loop, &rt->timeout_event);
		}
		rt->redis = NULL;
	}
}

gpointer
rspamd_redis_runtime (struct rspamd_task *task,
		struct rspamd_statfile_config *stcf,
		gboolean learn, gpointer c)
{
	struct redis_stat_ctx *ctx = REDIS_CTX (c);
	struct redis_stat_runtime *rt;
	struct upstream *up;
	struct upstream_list *ups;
	char *object_expanded = NULL;
	rspamd_inet_addr_t *addr;

	g_assert (ctx != NULL);
	g_assert (stcf != NULL);

	if (learn) {
		ups = rspamd_redis_get_servers (ctx, "write_servers");

		if (!ups) {
			msg_err_task ("no write servers defined for %s, cannot learn",
					stcf->symbol);
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
			msg_err_task ("no read servers defined for %s, cannot stat",
					stcf->symbol);
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

	if (rspamd_redis_expand_object (ctx->redis_object, ctx, task,
			&object_expanded) == 0) {
		msg_err_task ("expansion for %s failed for symbol %s "
				 "(maybe learning per user classifier with no user or recipient)",
				 learn ? "learning" : "classifying",
				 stcf->symbol);
		return NULL;
	}

	rt = rspamd_mempool_alloc0 (task->task_pool, sizeof (*rt));
	rt->selected = up;
	rt->task = task;
	rt->ctx = ctx;
	rt->stcf = stcf;
	rt->redis_object_expanded = object_expanded;

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
	rspamd_redis_maybe_auth (ctx, rt->redis);
	rt->redis->data = rt;
	redisAsyncSetDisconnectCallback (rt->redis, rspamd_stat_redis_on_disconnect);
	redisAsyncSetConnectCallback (rt->redis, rspamd_stat_redis_on_connect);

	rspamd_mempool_add_destructor (task->task_pool, rspamd_redis_fin, rt);

	return rt;
}

void
rspamd_redis_close (gpointer p)
{
	struct redis_stat_ctx *ctx = REDIS_CTX (p);
	lua_State *L = ctx->L;

	if (ctx->conf_ref) {
		luaL_unref (L, LUA_REGISTRYINDEX, ctx->conf_ref);
	}

	g_free (ctx);
}

gboolean
rspamd_redis_process_tokens (struct rspamd_task *task,
		GPtrArray *tokens,
		gint id, gpointer p)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (p);
	const gchar *learned_key = "learns";

	if (rspamd_session_blocked (task->s)) {
		return FALSE;
	}

	if (tokens == NULL || tokens->len == 0 || rt->redis == NULL) {
		return FALSE;
	}

	rt->id = id;

	if (rt->ctx->new_schema) {
		if (rt->ctx->stcf->is_spam) {
			learned_key = "learns_spam";
		}
		else {
			learned_key = "learns_ham";
		}
	}

	if (redisAsyncCommand (rt->redis, rspamd_redis_connected, rt, "HGET %s %s",
			rt->redis_object_expanded, learned_key) == REDIS_OK) {

		rspamd_session_add_event (task->s, NULL, rt, M);
		rt->has_event = TRUE;
		rt->tokens = g_ptr_array_ref (tokens);

		if (ev_can_stop (&rt->timeout_event)) {
			rt->timeout_event.repeat = rt->ctx->timeout;
			ev_timer_again (task->event_loop, &rt->timeout_event);
		}
		else {
			rt->timeout_event.data = rt;
			ev_timer_init (&rt->timeout_event, rspamd_redis_timeout,
					rt->ctx->timeout, 0.);
			ev_timer_start (task->event_loop, &rt->timeout_event);
		}
	}

	return FALSE;
}

gboolean
rspamd_redis_finalize_process (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (runtime);

	if (rt->err) {
		msg_info_task ("cannot retrieve stat tokens from Redis: %e", rt->err);
		g_error_free (rt->err);
		rt->err = NULL;
		rspamd_redis_fin (rt);

		return FALSE;
	}

	rspamd_redis_fin (rt);

	return TRUE;
}

gboolean
rspamd_redis_learn_tokens (struct rspamd_task *task, GPtrArray *tokens,
		gint id, gpointer p)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (p);
	rspamd_fstring_t *query;
	const gchar *redis_cmd;
	rspamd_token_t *tok;
	gint ret;
	goffset off;
	const gchar *learned_key = "learns";

	if (rspamd_session_blocked (task->s)) {
		return FALSE;
	}

	if (rt->ctx->new_schema) {
		if (rt->ctx->stcf->is_spam) {
			learned_key = "learns_spam";
		}
		else {
			learned_key = "learns_ham";
		}
	}

	/*
	 * Add the current key to the set of learned keys
	 */
	redisAsyncCommand (rt->redis, NULL, NULL, "SADD %s_keys %s",
			rt->stcf->symbol, rt->redis_object_expanded);

	if (rt->ctx->new_schema) {
		redisAsyncCommand (rt->redis, NULL, NULL, "HSET %s version 2",
				rt->redis_object_expanded);
	}

	if (rt->stcf->clcf->flags & RSPAMD_FLAG_CLASSIFIER_INTEGER) {
		redis_cmd = "HINCRBY";
	}
	else {
		redis_cmd = "HINCRBYFLOAT";
	}

	rt->id = id;
	query = rspamd_redis_tokens_to_query (task, rt, tokens,
			redis_cmd, rt->redis_object_expanded, TRUE, id,
			rt->stcf->clcf->flags & RSPAMD_FLAG_CLASSIFIER_INTEGER);
	g_assert (query != NULL);
	query->len = 0;

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
				"$%d\r\n"
				"%s\r\n" /* Learned key */
				"$1\r\n"
				"1\r\n",
				(gint)strlen (rt->redis_object_expanded),
				rt->redis_object_expanded,
				(gint)strlen (learned_key),
				learned_key);
	}
	else {
		rspamd_printf_fstring (&query, ""
				"*4\r\n"
				"$7\r\n"
				"HINCRBY\r\n"
				"$%d\r\n"
				"%s\r\n"
				"$%d\r\n"
				"%s\r\n" /* Learned key */
				"$2\r\n"
				"-1\r\n",
				(gint)strlen (rt->redis_object_expanded),
				rt->redis_object_expanded,
				(gint)strlen (learned_key),
				learned_key);
	}

	ret = redisAsyncFormattedCommand (rt->redis, NULL, NULL,
			query->str, query->len);

	if (ret != REDIS_OK) {
		msg_err_task ("call to redis failed: %s", rt->redis->errstr);
		rspamd_fstring_free (query);

		return FALSE;
	}

	off = query->len;
	ret = rspamd_printf_fstring (&query, "*1\r\n$4\r\nEXEC\r\n");
	ret = redisAsyncFormattedCommand (rt->redis, rspamd_redis_learned, rt,
			query->str + off, ret);
	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t)rspamd_fstring_free, query);

	if (ret == REDIS_OK) {

		/* Add signature if needed */
		if (rt->ctx->enable_signatures) {
			rspamd_redis_store_stat_signature (task, rt, tokens,
					"RSIG");
		}

		rspamd_session_add_event (task->s, NULL, rt, M);
		rt->has_event = TRUE;

		/* Set timeout */
		if (ev_can_stop (&rt->timeout_event)) {
			rt->timeout_event.repeat = rt->ctx->timeout;
			ev_timer_again (task->event_loop, &rt->timeout_event);
		}
		else {
			rt->timeout_event.data = rt;
			ev_timer_init (&rt->timeout_event, rspamd_redis_timeout,
					rt->ctx->timeout, 0.);
			ev_timer_start (task->event_loop, &rt->timeout_event);
		}

		return TRUE;
	}
	else {
		msg_err_task ("call to redis failed: %s", rt->redis->errstr);
	}

	return FALSE;
}


gboolean
rspamd_redis_finalize_learn (struct rspamd_task *task, gpointer runtime,
		gpointer ctx, GError **err)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (runtime);

	if (rt->err) {
		g_propagate_error (err, rt->err);
		rt->err = NULL;
		rspamd_redis_fin (rt);

		return FALSE;
	}

	rspamd_redis_fin (rt);

	return TRUE;
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
