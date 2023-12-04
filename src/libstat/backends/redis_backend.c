/*
 * Copyright 2023 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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

#define msg_debug_stat_redis(...) rspamd_conditional_debug_fast(NULL, NULL,                                                       \
																rspamd_stat_redis_log_id, "stat_redis", task->task_pool->tag.uid, \
																RSPAMD_LOG_FUNC,                                                  \
																__VA_ARGS__)

INIT_LOG_MODULE(stat_redis)

#define REDIS_CTX(p) (struct redis_stat_ctx *) (p)
#define REDIS_RUNTIME(p) (struct redis_stat_runtime *) (p)
#define REDIS_BACKEND_TYPE "redis"
#define REDIS_DEFAULT_PORT 6379
#define REDIS_DEFAULT_OBJECT "%s%l"
#define REDIS_DEFAULT_USERS_OBJECT "%s%l%r"
#define REDIS_DEFAULT_TIMEOUT 0.5
#define REDIS_STAT_TIMEOUT 30
#define REDIS_MAX_USERS 1000

struct redis_stat_ctx {
	lua_State *L;
	struct rspamd_statfile_config *stcf;
	gint conf_ref;
	struct rspamd_stat_async_elt *stat_elt;
	const char *redis_object;
	gboolean enable_users;
	gboolean store_tokens;
	gboolean new_schema;
	gboolean enable_signatures;
	guint expiry;
	guint max_users;
	gint cbref_user;

	gint cbref_classify;
	gint cbref_learn;
};


struct redis_stat_runtime {
	struct redis_stat_ctx *ctx;
	struct rspamd_task *task;
	struct rspamd_statfile_config *stcf;
	GArray *results;
	gchar *redis_object_expanded;
	guint64 learned;
	gint id;
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
rspamd_redis_stat_quark(void)
{
	return g_quark_from_static_string(M);
}

static inline struct upstream_list *
rspamd_redis_get_servers(struct redis_stat_ctx *ctx,
						 const gchar *what)
{
	lua_State *L = ctx->L;
	struct upstream_list *res;

	lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->conf_ref);
	lua_pushstring(L, what);
	lua_gettable(L, -2);
	res = *((struct upstream_list **) lua_touserdata(L, -1));
	lua_settop(L, 0);

	return res;
}

/*
 * Non-static for lua unit testing
 */
gsize rspamd_redis_expand_object(const gchar *pattern,
								 struct redis_stat_ctx *ctx,
								 struct rspamd_task *task,
								 gchar **target)
{
	gsize tlen = 0;
	const gchar *p = pattern, *elt;
	gchar *d, *end;
	enum {
		just_char,
		percent_char,
		mod_char
	} state = just_char;
	struct rspamd_statfile_config *stcf;
	lua_State *L = NULL;
	struct rspamd_task **ptask;
	const gchar *rcpt = NULL;
	gint err_idx;

	g_assert(ctx != NULL);
	g_assert(task != NULL);
	stcf = ctx->stcf;

	L = task->cfg->lua_state;
	g_assert(L != NULL);

	if (ctx->enable_users) {
		if (ctx->cbref_user == -1) {
			rcpt = rspamd_task_get_principal_recipient(task);
		}
		else {
			/* Execute lua function to get userdata */
			lua_pushcfunction(L, &rspamd_lua_traceback);
			err_idx = lua_gettop(L);

			lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->cbref_user);
			ptask = lua_newuserdata(L, sizeof(struct rspamd_task *));
			*ptask = task;
			rspamd_lua_setclass(L, "rspamd{task}", -1);

			if (lua_pcall(L, 1, 1, err_idx) != 0) {
				msg_err_task("call to user extraction script failed: %s",
							 lua_tostring(L, -1));
			}
			else {
				rcpt = rspamd_mempool_strdup(task->task_pool, lua_tostring(L, -1));
			}

			/* Result + error function */
			lua_settop(L, err_idx - 1);
		}

		if (rcpt) {
			rspamd_mempool_set_variable(task->task_pool, "stat_user",
										(gpointer) rcpt, NULL);
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
				tlen++;
			}
			p++;
			break;
		case percent_char:
			switch (*p) {
			case '%':
				tlen++;
				state = just_char;
				break;
			case 'u':
				elt = GET_TASK_ELT(task, auth_user);
				if (elt) {
					tlen += strlen(elt);
				}
				break;
			case 'r':

				if (rcpt == NULL) {
					elt = rspamd_task_get_principal_recipient(task);
				}
				else {
					elt = rcpt;
				}

				if (elt) {
					tlen += strlen(elt);
				}
				break;
			case 'l':
				if (stcf->label) {
					tlen += strlen(stcf->label);
				}
				/* Label miss is OK */
				break;
			case 's':
				if (ctx->new_schema) {
					tlen += sizeof("RS") - 1;
				}
				else {
					if (stcf->symbol) {
						tlen += strlen(stcf->symbol);
					}
				}
				break;
			default:
				state = just_char;
				tlen++;
				break;
			}

			if (state == percent_char) {
				state = mod_char;
			}
			p++;
			break;

		case mod_char:
			switch (*p) {
			case 'd':
				p++;
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

	*target = rspamd_mempool_alloc(task->task_pool, tlen + 1);
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
			p++;
			break;
		case percent_char:
			switch (*p) {
			case '%':
				*d++ = *p;
				state = just_char;
				break;
			case 'u':
				elt = GET_TASK_ELT(task, auth_user);
				if (elt) {
					d += rspamd_strlcpy(d, elt, end - d);
				}
				break;
			case 'r':
				if (rcpt == NULL) {
					elt = rspamd_task_get_principal_recipient(task);
				}
				else {
					elt = rcpt;
				}

				if (elt) {
					d += rspamd_strlcpy(d, elt, end - d);
				}
				break;
			case 'l':
				if (stcf->label) {
					d += rspamd_strlcpy(d, stcf->label, end - d);
				}
				break;
			case 's':
				if (ctx->new_schema) {
					d += rspamd_strlcpy(d, "RS", end - d);
				}
				else {
					if (stcf->symbol) {
						d += rspamd_strlcpy(d, stcf->symbol, end - d);
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
			p++;
			break;

		case mod_char:
			switch (*p) {
			case 'd':
				/* TODO: not supported yet */
				p++;
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


#if 0
// Leave it unless the conversion is done, to use as a reference
static rspamd_fstring_t *
rspamd_redis_tokens_to_query(struct rspamd_task *task,
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

	g_assert(tokens != NULL);

	cmd_len = strlen(command);
	prefix_len = strlen(prefix);
	out = rspamd_fstring_sized_new(1024);

	if (learn) {
		rspamd_printf_fstring(&out, "*1\r\n$5\r\nMULTI\r\n");

		ret = redisAsyncFormattedCommand(rt->redis, NULL, NULL,
										 out->str, out->len);

		if (ret != REDIS_OK) {
			msg_err_task("call to redis failed: %s", rt->redis->errstr);
			rspamd_fstring_free(out);

			return NULL;
		}

		out->len = 0;
	}
	else {
		if (rt->ctx->new_schema) {
			/* Multi + HGET */
			rspamd_printf_fstring(&out, "*1\r\n$5\r\nMULTI\r\n");

			ret = redisAsyncFormattedCommand(rt->redis, NULL, NULL,
											 out->str, out->len);

			if (ret != REDIS_OK) {
				msg_err_task("call to redis failed: %s", rt->redis->errstr);
				rspamd_fstring_free(out);

				return NULL;
			}

			out->len = 0;
		}
		else {
			rspamd_printf_fstring(&out, ""
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

	for (i = 0; i < tokens->len; i++) {
		tok = g_ptr_array_index(tokens, i);

		if (learn) {
			if (intvals) {
				l1 = rspamd_snprintf(n1, sizeof(n1), "%L",
									 (gint64) tok->values[idx]);
			}
			else {
				l1 = rspamd_snprintf(n1, sizeof(n1), "%f",
									 tok->values[idx]);
			}

			if (rt->ctx->new_schema) {
				/*
				 * HINCRBY <prefix_token> <0|1> <value>
				 */
				l0 = rspamd_snprintf(n0, sizeof(n0), "%*s_%uL",
									 prefix_len, prefix,
									 tok->data);

				rspamd_printf_fstring(&out, ""
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
				l0 = rspamd_snprintf(n0, sizeof(n0), "%uL", tok->data);

				/*
				 * HINCRBY <prefix> <token> <value>
				 */
				rspamd_printf_fstring(&out, ""
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

			ret = redisAsyncFormattedCommand(rt->redis, NULL, NULL,
											 out->str, out->len);

			if (ret != REDIS_OK) {
				msg_err_task("call to redis failed: %s", rt->redis->errstr);
				rspamd_fstring_free(out);

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
						redisAsyncCommand(rt->redis, NULL, NULL,
										  "HSET %b_tokens %b %b:%b",
										  prefix, (size_t) prefix_len,
										  n0, (size_t) l0,
										  tok->t1->stemmed.begin, tok->t1->stemmed.len,
										  tok->t2->stemmed.begin, tok->t2->stemmed.len);
					}
					else if (tok->t1) {
						redisAsyncCommand(rt->redis, NULL, NULL,
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
						redisAsyncCommand(rt->redis, NULL, NULL,
										  "HSET %b %s %b:%b",
										  n0, (size_t) l0,
										  "tokens",
										  tok->t1->stemmed.begin, tok->t1->stemmed.len,
										  tok->t2->stemmed.begin, tok->t2->stemmed.len);
					}
					else if (tok->t1) {
						redisAsyncCommand(rt->redis, NULL, NULL,
										  "HSET %b %s %b",
										  n0, (size_t) l0,
										  "tokens",
										  tok->t1->stemmed.begin, tok->t1->stemmed.len);
					}
				}

				redisAsyncCommand(rt->redis, NULL, NULL,
								  "ZINCRBY %b_z %b %b",
								  prefix, (size_t) prefix_len,
								  n1, (size_t) l1,
								  n0, (size_t) l0);
			}

			if (rt->ctx->new_schema && rt->ctx->expiry > 0) {
				out->len = 0;
				l1 = rspamd_snprintf(n1, sizeof(n1), "%d",
									 rt->ctx->expiry);

				rspamd_printf_fstring(&out, ""
											"*3\r\n"
											"$6\r\n"
											"EXPIRE\r\n"
											"$%d\r\n"
											"%s\r\n"
											"$%d\r\n"
											"%s\r\n",
									  l0, n0,
									  l1, n1);
				redisAsyncFormattedCommand(rt->redis, NULL, NULL,
										   out->str, out->len);
			}

			out->len = 0;
		}
		else {
			if (rt->ctx->new_schema) {
				l0 = rspamd_snprintf(n0, sizeof(n0), "%*s_%uL",
									 prefix_len, prefix,
									 tok->data);

				rspamd_printf_fstring(&out, ""
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

				ret = redisAsyncFormattedCommand(rt->redis, NULL, NULL,
												 out->str, out->len);

				if (ret != REDIS_OK) {
					msg_err_task("call to redis failed: %s", rt->redis->errstr);
					rspamd_fstring_free(out);

					return NULL;
				}

				out->len = 0;
			}
			else {
				l0 = rspamd_snprintf(n0, sizeof(n0), "%uL", tok->data);
				rspamd_printf_fstring(&out, ""
											"$%d\r\n"
											"%s\r\n",
									  l0, n0);
			}
		}
	}

	if (!learn && rt->ctx->new_schema) {
		rspamd_printf_fstring(&out, "*1\r\n$4\r\nEXEC\r\n");
	}

	return out;
}


static void
rspamd_redis_store_stat_signature(struct rspamd_task *task,
								  struct redis_stat_runtime *rt,
								  GPtrArray *tokens,
								  const gchar *prefix)
{
	gchar *sig, keybuf[512], nbuf[64];
	rspamd_token_t *tok;
	guint i, blen, klen;
	rspamd_fstring_t *out;

	sig = rspamd_mempool_get_variable(task->task_pool,
									  RSPAMD_MEMPOOL_STAT_SIGNATURE);

	if (sig == NULL) {
		msg_err_task("cannot get bayes signature");
		return;
	}

	out = rspamd_fstring_sized_new(1024);
	klen = rspamd_snprintf(keybuf, sizeof(keybuf), "%s_%s_%s",
						   prefix, sig, rt->stcf->is_spam ? "S" : "H");

	/* Cleanup key */
	rspamd_printf_fstring(&out, ""
								"*2\r\n"
								"$3\r\n"
								"DEL\r\n"
								"$%d\r\n"
								"%s\r\n",
						  klen, keybuf);
	redisAsyncFormattedCommand(rt->redis, NULL, NULL,
							   out->str, out->len);
	out->len = 0;

	rspamd_printf_fstring(&out, ""
								"*%d\r\n"
								"$5\r\n"
								"LPUSH\r\n"
								"$%d\r\n"
								"%s\r\n",
						  tokens->len + 2,
						  klen, keybuf);

	PTR_ARRAY_FOREACH(tokens, i, tok)
	{
		blen = rspamd_snprintf(nbuf, sizeof(nbuf), "%uL", tok->data);
		rspamd_printf_fstring(&out, ""
									"$%d\r\n"
									"%s\r\n",
							  blen, nbuf);
	}

	redisAsyncFormattedCommand(rt->redis, NULL, NULL,
							   out->str, out->len);
	out->len = 0;

	if (rt->ctx->expiry > 0) {
		out->len = 0;
		blen = rspamd_snprintf(nbuf, sizeof(nbuf), "%d",
							   rt->ctx->expiry);

		rspamd_printf_fstring(&out, ""
									"*3\r\n"
									"$6\r\n"
									"EXPIRE\r\n"
									"$%d\r\n"
									"%s\r\n"
									"$%d\r\n"
									"%s\r\n",
							  klen, keybuf,
							  blen, nbuf);
		redisAsyncFormattedCommand(rt->redis, NULL, NULL,
								   out->str, out->len);
	}

	rspamd_fstring_free(out);
}

#endif

static void
rspamd_redis_async_cbdata_cleanup(struct rspamd_redis_stat_cbdata *cbdata)
{
	guint i;
	gchar *k;

	if (cbdata && !cbdata->wanna_die) {
		/* Avoid double frees */
		cbdata->wanna_die = TRUE;
		redisAsyncFree(cbdata->redis);

		for (i = 0; i < cbdata->cur_keys->len; i++) {
			k = g_ptr_array_index(cbdata->cur_keys, i);
			g_free(k);
		}

		g_ptr_array_free(cbdata->cur_keys, TRUE);

		if (cbdata->elt) {
			cbdata->elt->cbdata = NULL;
			/* Re-enable parent event */
			cbdata->elt->async->enabled = TRUE;

			/* Replace ucl object */
			if (cbdata->cur) {
				if (cbdata->elt->stat) {
					ucl_object_unref(cbdata->elt->stat);
				}

				cbdata->elt->stat = cbdata->cur;
				cbdata->cur = NULL;
			}
		}

		if (cbdata->cur) {
			ucl_object_unref(cbdata->cur);
		}

		g_free(cbdata);
	}
}

/* Called when we get number of learns for a specific key */
static void
rspamd_redis_stat_learns(redisAsyncContext *c, gpointer r, gpointer priv)
{
	struct rspamd_redis_stat_elt *redis_elt = (struct rspamd_redis_stat_elt *) priv;
	struct rspamd_redis_stat_cbdata *cbdata;
	redisReply *reply = r;
	ucl_object_t *obj;
	gulong num = 0;

	cbdata = redis_elt->cbdata;

	if (cbdata == NULL || cbdata->wanna_die) {
		return;
	}

	cbdata->inflight--;

	if (c->err == 0 && r != NULL) {
		if (G_LIKELY(reply->type == REDIS_REPLY_INTEGER)) {
			num = reply->integer;
		}
		else if (reply->type == REDIS_REPLY_STRING) {
			rspamd_strtoul(reply->str, reply->len, &num);
		}

		obj = (ucl_object_t *) ucl_object_lookup(cbdata->cur, "revision");
		if (obj) {
			obj->value.iv += num;
		}
	}

	if (cbdata->inflight == 0) {
		rspamd_redis_async_cbdata_cleanup(cbdata);
		redis_elt->cbdata = NULL;
	}
}

/* Called when we get number of elements for a specific key */
static void
rspamd_redis_stat_key(redisAsyncContext *c, gpointer r, gpointer priv)
{
	struct rspamd_redis_stat_elt *redis_elt = (struct rspamd_redis_stat_elt *) priv;
	struct rspamd_redis_stat_cbdata *cbdata;
	redisReply *reply = r;
	ucl_object_t *obj;
	glong num = 0;

	cbdata = redis_elt->cbdata;

	if (cbdata == NULL || cbdata->wanna_die) {
		return;
	}

	cbdata->inflight--;

	if (c->err == 0 && r != NULL) {
		if (G_LIKELY(reply->type == REDIS_REPLY_INTEGER)) {
			num = reply->integer;
		}
		else if (reply->type == REDIS_REPLY_STRING) {
			rspamd_strtol(reply->str, reply->len, &num);
		}

		if (num < 0) {
			msg_err("bad learns count: %L", (gint64) num);
			num = 0;
		}

		obj = (ucl_object_t *) ucl_object_lookup(cbdata->cur, "used");
		if (obj) {
			obj->value.iv += num;
		}

		obj = (ucl_object_t *) ucl_object_lookup(cbdata->cur, "total");
		if (obj) {
			obj->value.iv += num;
		}

		obj = (ucl_object_t *) ucl_object_lookup(cbdata->cur, "size");
		if (obj) {
			/* Size of key + size of int64_t */
			obj->value.iv += num * (sizeof(G_STRINGIFY(G_MAXINT64)) +
									sizeof(guint64) + sizeof(gpointer));
		}
	}

	if (cbdata->inflight == 0) {
		rspamd_redis_async_cbdata_cleanup(cbdata);
		redis_elt->cbdata = NULL;
	}
}

/* Called when we have connected to the redis server and got keys to check */
static void
rspamd_redis_stat_keys(redisAsyncContext *c, gpointer r, gpointer priv)
{
	struct rspamd_redis_stat_elt *redis_elt = (struct rspamd_redis_stat_elt *) priv;
	struct rspamd_redis_stat_cbdata *cbdata;
	redisReply *reply = r, *more_elt, *elts, *elt;
	gchar **pk, *k;
	guint i, processed = 0;
	gboolean more = false;

	cbdata = redis_elt->cbdata;

	if (cbdata == NULL || cbdata->wanna_die) {
		return;
	}

	cbdata->inflight--;

	if (c->err == 0 && r != NULL) {
		if (reply->type == REDIS_REPLY_ARRAY) {
			more_elt = reply->element[0];
			elts = reply->element[1];

			if (more_elt != NULL && more_elt->str != NULL && strcmp(more_elt->str, "0") != 0) {
				more = true;
			}

			/* Clear the existing stuff */
			PTR_ARRAY_FOREACH(cbdata->cur_keys, i, k)
			{
				if (k) {
					g_free(k);
				}
			}

			g_ptr_array_set_size(cbdata->cur_keys, elts->elements);

			for (i = 0; i < elts->elements; i++) {
				elt = elts->element[i];

				if (elt->type == REDIS_REPLY_STRING) {
					pk = (gchar **) &g_ptr_array_index(cbdata->cur_keys, i);
					*pk = g_malloc(elt->len + 1);
					rspamd_strlcpy(*pk, elt->str, elt->len + 1);
					processed++;
				}
				else {
					pk = (gchar **) &g_ptr_array_index(cbdata->cur_keys, i);
					*pk = NULL;
				}
			}

			if (processed) {
				PTR_ARRAY_FOREACH(cbdata->cur_keys, i, k)
				{
					if (k) {
						const gchar *learned_key = "learns";

						if (cbdata->elt->ctx->new_schema) {
							if (cbdata->elt->ctx->stcf->is_spam) {
								learned_key = "learns_spam";
							}
							else {
								learned_key = "learns_ham";
							}
							redisAsyncCommand(cbdata->redis,
											  rspamd_redis_stat_learns,
											  redis_elt,
											  "HGET %s %s",
											  k, learned_key);
							cbdata->inflight += 1;
						}
						else {
							redisAsyncCommand(cbdata->redis,
											  rspamd_redis_stat_key,
											  redis_elt,
											  "HLEN %s",
											  k);
							redisAsyncCommand(cbdata->redis,
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
			redisAsyncCommand(cbdata->redis, rspamd_redis_stat_keys, redis_elt,
							  "SSCAN %s_keys %s COUNT %d",
							  cbdata->elt->ctx->stcf->symbol,
							  more_elt->str,
							  cbdata->elt->ctx->max_users);

			cbdata->inflight += 1;
		}
		else {
			/* Set up the required keys */
			ucl_object_insert_key(cbdata->cur,
								  ucl_object_typed_new(UCL_INT), "revision", 0, false);
			ucl_object_insert_key(cbdata->cur,
								  ucl_object_typed_new(UCL_INT), "used", 0, false);
			ucl_object_insert_key(cbdata->cur,
								  ucl_object_typed_new(UCL_INT), "total", 0, false);
			ucl_object_insert_key(cbdata->cur,
								  ucl_object_typed_new(UCL_INT), "size", 0, false);
			ucl_object_insert_key(cbdata->cur,
								  ucl_object_fromstring(cbdata->elt->ctx->stcf->symbol),
								  "symbol", 0, false);
			ucl_object_insert_key(cbdata->cur, ucl_object_fromstring("redis"),
								  "type", 0, false);
			ucl_object_insert_key(cbdata->cur, ucl_object_fromint(0),
								  "languages", 0, false);
			ucl_object_insert_key(cbdata->cur, ucl_object_fromint(processed),
								  "users", 0, false);

			rspamd_upstream_ok(cbdata->selected);

			if (cbdata->inflight == 0) {
				rspamd_redis_async_cbdata_cleanup(cbdata);
				redis_elt->cbdata = NULL;
			}
		}
	}
	else {
		if (c->errstr) {
			msg_err("cannot get keys to gather stat: %s", c->errstr);
		}
		else {
			msg_err("cannot get keys to gather stat: unknown error");
		}

		rspamd_upstream_fail(cbdata->selected, FALSE, c->errstr);
		rspamd_redis_async_cbdata_cleanup(cbdata);
		redis_elt->cbdata = NULL;
	}
}

static void
rspamd_redis_async_stat_cb(struct rspamd_stat_async_elt *elt, gpointer d)
{
	struct redis_stat_ctx *ctx;
	struct rspamd_redis_stat_elt *redis_elt = elt->ud;
	struct rspamd_redis_stat_cbdata *cbdata;
	rspamd_inet_addr_t *addr;
	struct upstream_list *ups;
	redisAsyncContext *redis_ctx;
	struct upstream *selected;

	g_assert(redis_elt != NULL);

	ctx = redis_elt->ctx;

	if (redis_elt->cbdata) {
		/* We have some other process pending */
		rspamd_redis_async_cbdata_cleanup(redis_elt->cbdata);
		redis_elt->cbdata = NULL;
	}

	/* Disable further events unless needed */
	elt->enabled = FALSE;

	ups = rspamd_redis_get_servers(ctx, "read_servers");

	if (!ups) {
		return;
	}

	selected = rspamd_upstream_get(ups,
								   RSPAMD_UPSTREAM_ROUND_ROBIN,
								   NULL,
								   0);

	g_assert(selected != NULL);
	addr = rspamd_upstream_addr_next(selected);
	g_assert(addr != NULL);

	if (rspamd_inet_address_get_af(addr) == AF_UNIX) {
		redis_ctx = redisAsyncConnectUnix(rspamd_inet_address_to_string(addr));
	}
	else {
		redis_ctx = redisAsyncConnect(rspamd_inet_address_to_string(addr),
									  rspamd_inet_address_get_port(addr));
	}

	if (redis_ctx == NULL) {
		msg_warn("cannot connect to redis server %s: %s",
				 rspamd_inet_address_to_string_pretty(addr),
				 strerror(errno));

		return;
	}
	else if (redis_ctx->err != REDIS_OK) {
		msg_warn("cannot connect to redis server %s: %s",
				 rspamd_inet_address_to_string_pretty(addr),
				 redis_ctx->errstr);
		redisAsyncFree(redis_ctx);

		return;
	}

	redisLibevAttach(redis_elt->event_loop, redis_ctx);
	cbdata = g_malloc0(sizeof(*cbdata));
	cbdata->redis = redis_ctx;
	cbdata->selected = selected;
	cbdata->inflight = 1;
	cbdata->cur = ucl_object_typed_new(UCL_OBJECT);
	cbdata->elt = redis_elt;
	cbdata->cur_keys = g_ptr_array_sized_new(ctx->max_users);
	redis_elt->cbdata = cbdata;

	/* XXX: deal with timeouts maybe */
	/* Get keys in redis that match our symbol */
	redisAsyncCommand(cbdata->redis, rspamd_redis_stat_keys, redis_elt,
					  "SSCAN %s_keys 0 COUNT %d",
					  ctx->stcf->symbol,
					  ctx->max_users);
}

static void
rspamd_redis_async_stat_fin(struct rspamd_stat_async_elt *elt, gpointer d)
{
	struct rspamd_redis_stat_elt *redis_elt = elt->ud;

	if (redis_elt->cbdata != NULL) {
		rspamd_redis_async_cbdata_cleanup(redis_elt->cbdata);
		redis_elt->cbdata = NULL;
	}

	/* Clear the static elements */
	if (redis_elt->stat) {
		ucl_object_unref(redis_elt->stat);
		redis_elt->stat = NULL;
	}

	g_free(redis_elt);
}

/* Called on connection termination */
static void
rspamd_redis_fin(gpointer data)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME(data);

	if (rt->err) {
		g_error_free(rt->err);
	}
}


static bool
rspamd_redis_parse_classifier_opts(struct redis_stat_ctx *backend,
								   const ucl_object_t *statfile_obj,
								   const ucl_object_t *classifier_obj,
								   struct rspamd_config *cfg)
{
	const gchar *lua_script;
	const ucl_object_t *elt, *users_enabled;

	users_enabled = ucl_object_lookup_any(classifier_obj, "per_user",
										  "users_enabled", NULL);

	if (users_enabled != NULL) {
		if (ucl_object_type(users_enabled) == UCL_BOOLEAN) {
			backend->enable_users = ucl_object_toboolean(users_enabled);
			backend->cbref_user = -1;
		}
		else if (ucl_object_type(users_enabled) == UCL_STRING) {
			lua_script = ucl_object_tostring(users_enabled);

			if (luaL_dostring(cfg->lua_state, lua_script) != 0) {
				msg_err_config("cannot execute lua script for users "
							   "extraction: %s",
							   lua_tostring(cfg->lua_state, -1));
			}
			else {
				if (lua_type(cfg->lua_state, -1) == LUA_TFUNCTION) {
					backend->enable_users = TRUE;
					backend->cbref_user = luaL_ref(cfg->lua_state,
												   LUA_REGISTRYINDEX);
				}
				else {
					msg_err_config("lua script must return "
								   "function(task) and not %s",
								   lua_typename(cfg->lua_state, lua_type(
																	cfg->lua_state, -1)));
				}
			}
		}
	}
	else {
		backend->enable_users = FALSE;
		backend->cbref_user = -1;
	}

	elt = ucl_object_lookup(classifier_obj, "prefix");
	if (elt == NULL || ucl_object_type(elt) != UCL_STRING) {
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
		backend->redis_object = ucl_object_tostring(elt);
	}

	elt = ucl_object_lookup(classifier_obj, "store_tokens");
	if (elt) {
		backend->store_tokens = ucl_object_toboolean(elt);
	}
	else {
		backend->store_tokens = FALSE;
	}

	elt = ucl_object_lookup(classifier_obj, "signatures");
	if (elt) {
		backend->enable_signatures = ucl_object_toboolean(elt);
	}
	else {
		backend->enable_signatures = FALSE;
	}

	elt = ucl_object_lookup_any(classifier_obj, "expiry", "expire", NULL);
	if (elt) {
		backend->expiry = ucl_object_toint(elt);
	}
	else {
		backend->expiry = 0;
	}

	elt = ucl_object_lookup(classifier_obj, "max_users");
	if (elt) {
		backend->max_users = ucl_object_toint(elt);
	}
	else {
		backend->max_users = REDIS_MAX_USERS;
	}

	lua_State *L = RSPAMD_LUA_CFG_STATE(cfg);
	lua_pushcfunction(L, &rspamd_lua_traceback);
	int err_idx = lua_gettop(L);

	/* Obtain function */
	if (!rspamd_lua_require_function(L, "lua_bayes_redis", "lua_bayes_init_classifier")) {
		msg_err_config("cannot require lua_bayes_redis.lua_bayes_init_classifier");
		lua_settop(L, err_idx - 1);

		return false;
	}

	/* Push arguments */
	ucl_object_push_lua(L, classifier_obj, false);
	ucl_object_push_lua(L, statfile_obj, false);

	if (lua_pcall(L, 2, 2, err_idx) != 0) {
		msg_err("call to lua_bayes_init_classifier "
				"script failed: %s",
				lua_tostring(L, -1));
		lua_settop(L, err_idx - 1);

		return NULL;
	}

	/* Results are in the stack:
	 * top - 1 - classifier function (idx = -2)
	 * top - learn function (idx = -1)
	 */

	lua_pushvalue(L, -2);
	backend->cbref_classify = luaL_ref(L, LUA_REGISTRYINDEX);

	lua_pushvalue(L, -1);
	backend->cbref_learn = luaL_ref(L, LUA_REGISTRYINDEX);

	lua_settop(L, err_idx - 1);

	return true;
}

gpointer
rspamd_redis_init(struct rspamd_stat_ctx *ctx,
				  struct rspamd_config *cfg, struct rspamd_statfile *st)
{
	struct redis_stat_ctx *backend;
	struct rspamd_statfile_config *stf = st->stcf;
	struct rspamd_redis_stat_elt *st_elt;
	const ucl_object_t *obj;
	gboolean ret = FALSE;
	gint conf_ref = -1;
	lua_State *L = (lua_State *) cfg->lua_state;

	backend = g_malloc0(sizeof(*backend));
	backend->L = L;
	backend->max_users = REDIS_MAX_USERS;

	backend->conf_ref = conf_ref;

	lua_settop(L, 0);

	if (!rspamd_redis_parse_classifier_opts(backend, st->stcf->opts, st->classifier->cfg->opts, cfg)) {
		msg_err_config("cannot init redis backend for %s", stf->symbol);
		g_free(backend);
		return NULL;
	}

	stf->clcf->flags |= RSPAMD_FLAG_CLASSIFIER_INCREMENTING_BACKEND;
	backend->stcf = stf;

	st_elt = g_malloc0(sizeof(*st_elt));
	st_elt->event_loop = ctx->event_loop;
	st_elt->ctx = backend;
#if 0
	backend->stat_elt = rspamd_stat_ctx_register_async(
		rspamd_redis_async_stat_cb,
		rspamd_redis_async_stat_fin,
		st_elt,
		REDIS_STAT_TIMEOUT);
	st_elt->async = backend->stat_elt;
#endif

	return (gpointer) backend;
}

gpointer
rspamd_redis_runtime(struct rspamd_task *task,
					 struct rspamd_statfile_config *stcf,
					 gboolean learn, gpointer c, gint _id)
{
	struct redis_stat_ctx *ctx = REDIS_CTX(c);
	struct redis_stat_runtime *rt;
	char *object_expanded = NULL;
	rspamd_inet_addr_t *addr;

	g_assert(ctx != NULL);
	g_assert(stcf != NULL);

	if (rspamd_redis_expand_object(ctx->redis_object, ctx, task,
								   &object_expanded) == 0) {
		msg_err_task("expansion for %s failed for symbol %s "
					 "(maybe learning per user classifier with no user or recipient)",
					 learn ? "learning" : "classifying",
					 stcf->symbol);
		return NULL;
	}

	rt = rspamd_mempool_alloc0(task->task_pool, sizeof(*rt));
	rt->task = task;
	rt->ctx = ctx;
	rt->redis_object_expanded = object_expanded;
	rt->stcf = stcf;

	rspamd_mempool_add_destructor(task->task_pool, rspamd_redis_fin, rt);

	return rt;
}

void rspamd_redis_close(gpointer p)
{
	struct redis_stat_ctx *ctx = REDIS_CTX(p);
	lua_State *L = ctx->L;

	if (ctx->conf_ref) {
		luaL_unref(L, LUA_REGISTRYINDEX, ctx->conf_ref);
	}

	if (ctx->cbref_learn) {
		luaL_unref(L, LUA_REGISTRYINDEX, ctx->cbref_learn);
	}

	if (ctx->cbref_classify) {
		luaL_unref(L, LUA_REGISTRYINDEX, ctx->cbref_classify);
	}

	g_free(ctx);
}

/*
 * Serialise stat tokens to message pack
 */
static char *
rspamd_redis_serialize_tokens(struct rspamd_task *task, GPtrArray *tokens, gsize *ser_len)
{
	/* Each token is int64_t that requires 9 bytes + 4 bytes array len + 1 byte array magic */
	gsize req_len = tokens->len * 9 + 5, i;
	gchar *buf, *p;
	rspamd_token_t *tok;

	buf = rspamd_mempool_alloc(task->task_pool, req_len);
	p = buf;

	/* Array */
	*p++ = (gchar) 0xdd;
	/* Length in big-endian (4 bytes) */
	*p++ = (gchar) ((tokens->len >> 24) & 0xff);
	*p++ = (gchar) ((tokens->len >> 16) & 0xff);
	*p++ = (gchar) ((tokens->len >> 8) & 0xff);
	*p++ = (gchar) (tokens->len & 0xff);

	PTR_ARRAY_FOREACH(tokens, i, tok)
	{
		*p++ = (gchar) 0xd3;

		guint64 val = GUINT64_TO_BE(tok->data);
		memcpy(p, &val, sizeof(val));
		p += sizeof(val);
	}

	*ser_len = p - buf;

	return buf;
}

static gint
rspamd_redis_classified(lua_State *L)
{
	const gchar *cookie = lua_tostring(L, lua_upvalueindex(1));
	struct rspamd_task *task = lua_check_task(L, 1);
	struct redis_stat_runtime *rt = REDIS_RUNTIME(rspamd_mempool_get_variable(task->task_pool, cookie));
	/* TODO: write it */
}

gboolean
rspamd_redis_process_tokens(struct rspamd_task *task,
							GPtrArray *tokens,
							gint id, gpointer p)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME(p);
	lua_State *L = rt->ctx->L;

	if (rspamd_session_blocked(task->s)) {
		return FALSE;
	}

	if (tokens == NULL || tokens->len == 0) {
		return FALSE;
	}

	/* TODO: check if we have tokens for that particular id for this class */

	gsize tokens_len;
	gchar *tokens_buf = rspamd_redis_serialize_tokens(task, tokens, &tokens_len);

	rt->id = id;

	lua_pushcfunction(L, &rspamd_lua_traceback);
	gint err_idx = lua_gettop(L);

	/* Function arguments */
	lua_rawgeti(L, LUA_REGISTRYINDEX, rt->ctx->cbref_classify);
	rspamd_lua_task_push(L, task);
	lua_pushstring(L, rt->redis_object_expanded);
	lua_pushinteger(L, id);
	lua_pushboolean(L, rt->stcf->is_spam);
	lua_new_text(L, tokens_buf, tokens_len, false);

	/* Store rt in random cookie */
	gchar *cookie = rspamd_mempool_alloc(task->task_pool, 16);
	rspamd_random_hex(cookie, 16);
	cookie[15] = '\0';
	rspamd_mempool_set_variable(task->task_pool, cookie, rt, NULL);
	/* Callback */
	lua_pushstring(L, cookie);
	lua_pushcclosure(L, &rspamd_redis_classified, 1);


	if (lua_pcall(L, 6, 0, err_idx) != 0) {
		msg_err_task("call to redis failed: %s", lua_tostring(L, -1));
		lua_settop(L, err_idx - 1);
		return FALSE;
	}

	lua_settop(L, err_idx - 1);
	return TRUE;
}

gboolean
rspamd_redis_finalize_process(struct rspamd_task *task, gpointer runtime,
							  gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME(runtime);

	if (rt->err) {
		msg_info_task("cannot retrieve stat tokens from Redis: %e", rt->err);
		g_error_free(rt->err);
		rt->err = NULL;
		rspamd_redis_fin(rt);

		return FALSE;
	}

	rspamd_redis_fin(rt);

	return TRUE;
}

gboolean
rspamd_redis_learn_tokens(struct rspamd_task *task, GPtrArray *tokens,
						  gint id, gpointer p)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME(p);
	lua_State *L = rt->ctx->L;

	/* TODO: write learn function */

	return FALSE;
}


gboolean
rspamd_redis_finalize_learn(struct rspamd_task *task, gpointer runtime,
							gpointer ctx, GError **err)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME(runtime);

	if (rt->err) {
		g_propagate_error(err, rt->err);
		rt->err = NULL;
		rspamd_redis_fin(rt);

		return FALSE;
	}

	rspamd_redis_fin(rt);

	return TRUE;
}

gulong
rspamd_redis_total_learns(struct rspamd_task *task, gpointer runtime,
						  gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME(runtime);

	return rt->learned;
}

gulong
rspamd_redis_inc_learns(struct rspamd_task *task, gpointer runtime,
						gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME(runtime);

	/* XXX: may cause races */
	return rt->learned + 1;
}

gulong
rspamd_redis_dec_learns(struct rspamd_task *task, gpointer runtime,
						gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME(runtime);

	/* XXX: may cause races */
	return rt->learned + 1;
}

gulong
rspamd_redis_learns(struct rspamd_task *task, gpointer runtime,
					gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME(runtime);

	return rt->learned;
}

ucl_object_t *
rspamd_redis_get_stat(gpointer runtime,
					  gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME(runtime);
	struct rspamd_redis_stat_elt *st;
	redisAsyncContext *redis;

	if (rt->ctx->stat_elt) {
		st = rt->ctx->stat_elt->ud;

		if (st->stat) {
			return ucl_object_ref(st->stat);
		}
	}

	return NULL;
}

gpointer
rspamd_redis_load_tokenizer_config(gpointer runtime,
								   gsize *len)
{
	return NULL;
}
