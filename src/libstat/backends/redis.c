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
#endif

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

struct redis_stat_runtime {
	struct redis_stat_ctx *ctx;
	struct rspamd_task *task;
	struct upstream *selected;
	struct event timeout_event;
	GArray *results;
	gchar *redis_object_expanded;
	redisAsyncContext *redis;
	guint64 learned;
	gboolean connected;
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

/* Called on connection termination */
static void
rspamd_redis_fin (gpointer data)
{
	struct redis_stat_runtime *rt = REDIS_RUNTIME (data);

	redisAsyncFree (rt->redis);
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

			rt->connected = TRUE;
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

gpointer
rspamd_redis_init (struct rspamd_stat_ctx *ctx,
		struct rspamd_config *cfg, struct rspamd_statfile *st)
{
	struct redis_stat_ctx *backend;
	struct rspamd_statfile_config *stf = st->stcf;
	const ucl_object_t *elt;

	backend = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*backend));

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
		struct rspamd_statfile_config *stcf, \
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
		msg_err ("no write servers defined for %s, cannot learn", stcf->symbol);
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
		msg_err ("no upstreams reachable");
		return NULL;
	}

	rt = rspamd_mempool_alloc0 (task->task_pool, sizeof (*rt));
	rspamd_redis_expand_object (ctx->redis_object, stcf, task,
			&rt->redis_object_expanded);
	rt->selected = up;
	rt->task = task;

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
