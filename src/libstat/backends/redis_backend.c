/* Copyright (c) 2015, Vsevolod Stakhov
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

#include "config.h"
#include "rspamd.h"
#include "stat_internal.h"
#include "upstream.h"

#ifdef WITH_HIREDIS
#include "hiredis/hiredis.h"
#include "hiredis/adapters/libevent.h"


#define REDIS_CTX(p) (struct redis_stat_ctx *)(p)
#define REDIS_RUNTIME(p) (struct redis_stat_runtime *)(p)
#define REDIS_BACKEND_TYPE "redis"
#define REDIS_DEFAULT_PORT 6379
#define REDIS_DEFAULT_OBJECT "%s%l"
#define REDIS_DEFAULT_TIMEOUT 0.5

struct redis_stat_ctx {
	struct upstream_list *read_servers;
	struct upstream_list *write_servers;

	const gchar *redis_object;
	gdouble timeout;
};

enum rspamd_redis_connection_state {
	RSPAMD_REDIS_DISCONNECTED = 0,
	RSPAMD_REDIS_CONNECTED,
	RSPAMD_REDIS_TIMEDOUT
};

struct redis_stat_runtime {
	struct redis_stat_ctx *ctx;
	struct rspamd_task *task;
	struct upstream *selected;
	struct event timeout_event;
	GArray *results;
	gchar *redis_object_expanded;
	redisAsyncContext *redis;
	guint64 learned;
	gint id;
	enum rspamd_redis_connection_state conn_state;
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
		struct rspamd_statfile_config *stcf,
		struct rspamd_task *task,
		gchar **target)
{
	gsize tlen = 0;
	const gchar *p = pattern, *elt;
	InternetAddressList *ia;
	InternetAddress *iaelt;
	InternetAddressMailbox *imb;
	gchar *d, *end;
	enum  {
		just_char,
		percent_char,
		mod_char
	} state = just_char;

	g_assert (stcf != NULL);

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
			case 'f':
				if (task) {
					elt = rspamd_task_get_sender (task);
					if (elt) {
						tlen += strlen (elt);
					}
				}
				break;
			case 'u':
				elt = GET_TASK_ELT (task, user);
				if (elt) {
					tlen += strlen (elt);
				}
				break;
			case 'r':
				ia = GET_TASK_ELT (task, rcpt_envelope);
				if (ia != NULL) {
					iaelt = internet_address_list_get_address (ia, 0);
					imb = INTERNET_ADDRESS_IS_MAILBOX (iaelt) ?
								INTERNET_ADDRESS_MAILBOX (iaelt) : NULL;

					elt = (imb ? internet_address_mailbox_get_addr (imb) : NULL);

					if (elt) {
						tlen += strlen (elt);
					}
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

	if (target == NULL) {
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
			case 'f':
				if (task) {
					elt = rspamd_task_get_sender (task);
					if (elt) {
						d += rspamd_strlcpy (d, elt, end - d);
					}
				}
				break;
			case 'u':
				elt = GET_TASK_ELT (task, user);
				if (elt) {
					d += rspamd_strlcpy (d, elt, end - d);
				}
				break;
			case 'r':
				ia = GET_TASK_ELT (task, rcpt_envelope);
				if (ia != NULL) {
					iaelt = internet_address_list_get_address (ia, 0);
					imb = INTERNET_ADDRESS_IS_MAILBOX (iaelt) ?
							INTERNET_ADDRESS_MAILBOX (iaelt) : NULL;

					elt = (imb ? internet_address_mailbox_get_addr (imb) : NULL);

					if (elt) {
						d += rspamd_strlcpy (d, elt, end - d);
					}
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

static rspamd_fstring_t *
rspamd_redis_tokens_to_query (struct rspamd_task *task, GPtrArray *tokens,
		const gchar *arg0, const gchar *arg1, gboolean learn, gint idx)
{
	rspamd_fstring_t *out;
	rspamd_token_t *tok;
	gchar n0[64], n1[64];
	guint i, l0, l1;
	guint64 num;

	g_assert (tokens != NULL);

	l0 = strlen (arg0);
	l1 = strlen (arg1);
	out = rspamd_fstring_sized_new (1024);
	rspamd_printf_fstring (&out, "*%d\r\n"
			"$%d\r\n"
			"%s\r\n"
			"$%d\r\n"
			"%s\r\n",
			learn ? (tokens->len * 2 + 2) : (tokens->len + 2),
			l0, arg0,
			l1, arg1);

	for (i = 0; i < tokens->len; i ++) {
		tok = g_ptr_array_index (tokens, i);
		memcpy (&num, tok->data, sizeof (num));
		l0 = rspamd_snprintf (n0, sizeof (n0), "%uL", num);

		if (learn) {
			if (tok->values[idx] == (guint64)tok->values[idx]) {
				l1 = rspamd_snprintf (n1, sizeof (n1), "%uL",
						(guint64)tok->values[idx]);
			}
			else {
				l1 = rspamd_snprintf (n1, sizeof (n1), "%f",
						(guint64)tok->values[idx]);
			}

			rspamd_printf_fstring (&out, "$%d\r\n%s\r\n"
					"$%d\r\n%s\r\n", l0, n0, l1, n1);
		}
		else {
			rspamd_printf_fstring (&out, "$%d\r\n%s\r\n", l0, n0);
		}
	}

	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t)rspamd_fstring_free, out);

	return out;
}

/* Called on connection termination */
static void
rspamd_redis_fin (gpointer data)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (data);

	if (rt->conn_state != RSPAMD_REDIS_CONNECTED) {
		redisAsyncFree (rt->redis);
		rt->conn_state = RSPAMD_REDIS_DISCONNECTED;
	}

	event_del (&rt->timeout_event);
}

static void
rspamd_redis_fin_learn (gpointer data)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (data);

	if (rt->conn_state != RSPAMD_REDIS_CONNECTED) {
		redisAsyncFree (rt->redis);
		rt->conn_state = RSPAMD_REDIS_DISCONNECTED;
	}

	event_del (&rt->timeout_event);
}

static void
rspamd_redis_fin_set_learns (gpointer data)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (data);

	if (rt->conn_state != RSPAMD_REDIS_CONNECTED) {
		redisAsyncFree (rt->redis);
		rt->conn_state = RSPAMD_REDIS_DISCONNECTED;
	}

	event_del (&rt->timeout_event);
}

static void
rspamd_redis_timeout (gint fd, short what, gpointer d)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (d);
	struct rspamd_task *task;

	task = rt->task;

	msg_err_task ("connection to redis server %s timed out",
			rspamd_upstream_name (rt->selected));
	rspamd_upstream_fail (rt->selected);
	rt->conn_state = RSPAMD_REDIS_TIMEDOUT;
	rspamd_session_remove_event (task->s, rspamd_redis_fin, d);
}

/* Called when we have connected to the redis server and got stats */
static void
rspamd_redis_connected (redisAsyncContext *c, gpointer r, gpointer priv)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (priv);
	redisReply *reply = r;
	struct rspamd_task *task;

	task = rt->task;

	if (c->err == 0) {
		if (r != NULL) {
			if (reply->type == REDIS_REPLY_INTEGER) {
				rt->learned = reply->integer;
			}
			else {
				rt->learned = 0;
			}

			rt->conn_state = RSPAMD_REDIS_CONNECTED;

			msg_debug_task ("connected to redis server, tokens learned for %s: %d",
					rt->redis_object_expanded, rt->learned);
			rspamd_upstream_ok (rt->selected);
			rspamd_session_remove_event (task->s, rspamd_redis_fin, rt);
		}
		else {
			msg_err_task ("error getting reply from redis server %s: %s",
					rspamd_upstream_name (rt->selected), c->errstr);
			rspamd_upstream_fail (rt->selected);
			rspamd_session_remove_event (task->s, rspamd_redis_fin, rt);
		}
	}
	else {
		msg_err_task ("error getting reply from redis server %s: %s",
				rspamd_upstream_name (rt->selected), c->errstr);
		rspamd_upstream_fail (rt->selected);
		rspamd_session_remove_event (task->s, rspamd_redis_fin, rt);
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

	task = rt->task;

	if (c->err == 0) {
		if (r != NULL) {
			if (reply->type == REDIS_REPLY_ARRAY) {

				if (reply->elements == task->tokens->len) {
					for (i = 0; i < reply->elements; i ++) {
						elt = reply->element[i];

						if (elt->type == REDIS_REPLY_INTEGER) {
							tok = g_ptr_array_index (task->tokens, i);
							tok->values[rt->id] = elt->integer;
							found ++;
						}
						else if (elt->type == REDIS_REPLY_STRING) {
							tok = g_ptr_array_index (task->tokens, i);
							rspamd_strtoul (elt->str, elt->len, &val);
							tok->values[rt->id] = val;
							found ++;
						}
						else {
							tok->values[rt->id] = 0;
						}

						processed ++;
					}
				}
			}
			else {
			}

			msg_debug_task ("received tokens for %s: %d processed, %d found",
					rt->redis_object_expanded, processed, found);
			rspamd_upstream_ok (rt->selected);
			rspamd_session_remove_event (task->s, rspamd_redis_fin, rt);
		}
		else {
			msg_err_task ("error getting reply from redis server %s: %s",
					rspamd_upstream_name (rt->selected), c->errstr);
			rspamd_upstream_fail (rt->selected);
			rspamd_session_remove_event (task->s, rspamd_redis_fin, rt);
		}
	}
	else {
		msg_err_task ("error getting reply from redis server %s: %s",
				rspamd_upstream_name (rt->selected), c->errstr);
		rspamd_upstream_fail (rt->selected);
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
		rspamd_session_remove_event (task->s, rspamd_redis_fin_learn, rt);
	}
	else {
		msg_err_task ("error getting reply from redis server %s: %s",
				rspamd_upstream_name (rt->selected), c->errstr);
		rspamd_upstream_fail (rt->selected);
		rspamd_session_remove_event (task->s, rspamd_redis_fin_learn, rt);
	}
}

gpointer
rspamd_redis_init (struct rspamd_stat_ctx *ctx,
		struct rspamd_config *cfg, struct rspamd_statfile *st)
{
	struct redis_stat_ctx *backend;
	struct rspamd_statfile_config *stf = st->stcf;
	const ucl_object_t *elt;

	backend = g_slice_alloc0 (sizeof (*backend));

	elt = ucl_object_find_key (stf->opts, "read_servers");
	if (elt == NULL) {
		elt = ucl_object_find_key (stf->opts, "servers");
	}
	if (elt == NULL) {
		msg_err ("statfile %s has no redis servers", stf->symbol);

		return NULL;
	}
	else {
		backend->read_servers = rspamd_upstreams_create (cfg->ups_ctx);
		if (!rspamd_upstreams_from_ucl (backend->read_servers, elt,
				REDIS_DEFAULT_PORT, NULL)) {
			msg_err ("statfile %s cannot read servers configuration",
					stf->symbol);
			return NULL;
		}
	}

	elt = ucl_object_find_key (stf->opts, "write_servers");
	if (elt == NULL) {
		msg_err ("statfile %s has no write redis servers, "
				"so learning is impossible", stf->symbol);
		backend->write_servers = NULL;
	}
	else {
		backend->write_servers = rspamd_upstreams_create (cfg->ups_ctx);
		if (!rspamd_upstreams_from_ucl (backend->write_servers, elt,
				REDIS_DEFAULT_PORT, NULL)) {
			msg_err ("statfile %s cannot write servers configuration",
					stf->symbol);
			rspamd_upstreams_destroy (backend->write_servers);
			backend->write_servers = NULL;
		}
	}

	elt = ucl_object_find_key (stf->opts, "prefix");
	if (elt == NULL || ucl_object_type (elt) != UCL_STRING) {
		backend->redis_object = REDIS_DEFAULT_OBJECT;
	}
	else {
		/* XXX: sanity check */
		backend->redis_object = ucl_object_tostring (elt);
		if (rspamd_redis_expand_object (backend->redis_object, stf,
				NULL, NULL) == 0) {
			msg_err ("statfile %s cannot write servers configuration",
					stf->symbol);
		}
	}

	elt = ucl_object_find_key (stf->opts, "timeout");
	if (elt) {
		backend->timeout = ucl_object_todouble (elt);
	}
	else {
		backend->timeout = REDIS_DEFAULT_TIMEOUT;
	}


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
	struct timeval tv;

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
	rspamd_redis_expand_object (ctx->redis_object, stcf, task,
			&rt->redis_object_expanded);
	rt->selected = up;
	rt->task = task;
	rt->ctx = ctx;
	rt->conn_state = RSPAMD_REDIS_DISCONNECTED;

	addr = rspamd_upstream_addr (up);
	g_assert (addr != NULL);
	rt->redis = redisAsyncConnect (rspamd_inet_address_to_string (addr),
			rspamd_inet_address_get_port (addr));
	g_assert (rt->redis != NULL);

	redisLibeventAttach (rt->redis, task->ev_base);
	rspamd_session_add_event (task->s, rspamd_redis_fin, rt,
			rspamd_redis_stat_quark ());

	/* Now check stats */
	event_set (&rt->timeout_event, -1, EV_TIMEOUT, rspamd_redis_timeout, rt);
	event_base_set (task->ev_base, &rt->timeout_event);
	double_to_tv (ctx->timeout, &tv);
	event_add (&rt->timeout_event, &tv);

	redisAsyncCommand (rt->redis, rspamd_redis_connected, rt, "HGET %s %s",
			rt->redis_object_expanded, "learned");

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

	if (tokens == NULL || tokens->len == 0 || rt->redis == NULL ||
			rt->conn_state != RSPAMD_REDIS_CONNECTED) {
		return FALSE;
	}

	rt->id = id;
	query = rspamd_redis_tokens_to_query (task, tokens,
			"HMGET", rt->redis_object_expanded, FALSE, -1);
	g_assert (query != NULL);

	ret = redisAsyncFormattedCommand (rt->redis, rspamd_redis_processed, rt,
			query->str, query->len);
	if (ret == REDIS_OK) {
		rspamd_session_add_event (task->s, rspamd_redis_fin, rt,
				rspamd_redis_stat_quark ());
		/* Reset timeout */
		event_del (&rt->timeout_event);
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
rspamd_redis_finalize_process (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (runtime);

	if (rt->conn_state == RSPAMD_REDIS_CONNECTED) {
		event_del (&rt->timeout_event);
		redisAsyncFree (rt->redis);

		rt->conn_state = RSPAMD_REDIS_DISCONNECTED;
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
	gint ret;

	if (rt->conn_state != RSPAMD_REDIS_DISCONNECTED) {
		/* We are likely in some bad state */
		msg_err_task ("invalid state for function: %d", rt->conn_state);

		return FALSE;
	}

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

	event_set (&rt->timeout_event, -1, EV_TIMEOUT, rspamd_redis_timeout, rt);
	event_base_set (task->ev_base, &rt->timeout_event);
	double_to_tv (rt->ctx->timeout, &tv);
	event_add (&rt->timeout_event, &tv);

	rt->id = id;
	query = rspamd_redis_tokens_to_query (task, tokens,
			"HMSET", rt->redis_object_expanded, TRUE, id);
	g_assert (query != NULL);

	ret = redisAsyncFormattedCommand (rt->redis, rspamd_redis_learned, rt,
			query->str, query->len);

	if (ret == REDIS_OK) {
		rspamd_session_add_event (task->s, rspamd_redis_fin_learn, rt,
				rspamd_redis_stat_quark ());
		/* Reset timeout */
		event_del (&rt->timeout_event);
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

	if (rt->conn_state == RSPAMD_REDIS_CONNECTED) {
		event_del (&rt->timeout_event);
		redisAsyncFree (rt->redis);

		rt->conn_state = RSPAMD_REDIS_DISCONNECTED;
	}
}

gulong
rspamd_redis_total_learns (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (runtime);

	return 0;
}

gulong
rspamd_redis_inc_learns (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (runtime);

	return 0;
}

gulong
rspamd_redis_dec_learns (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (runtime);

	return 0;
}

gulong
rspamd_redis_learns (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (runtime);

	return 0;
}

ucl_object_t *
rspamd_redis_get_stat (gpointer runtime,
		gpointer ctx)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (runtime);

	return NULL;
}

gpointer
rspamd_redis_load_tokenizer_config (gpointer runtime,
		gsize *len)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (runtime);

	return NULL;
}


#endif
