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
#include "upstream.h"
#include "ottery.h"
#include "ref.h"
#include "cfg_file.h"
#include "rdns.h"
#include "cryptobox.h"
#include "utlist.h"
#include "logger.h"
#include "contrib/librdns/rdns.h"
#include "contrib/mumhash/mum.h"

#include <math.h>


struct upstream_inet_addr_entry {
	rspamd_inet_addr_t *addr;
	guint priority;
	struct upstream_inet_addr_entry *next;
};

struct upstream_addr_elt {
	rspamd_inet_addr_t *addr;
	guint priority;
	guint errors;
};

struct upstream_list_watcher {
	rspamd_upstream_watch_func func;
	GFreeFunc dtor;
	gpointer ud;
	enum rspamd_upstreams_watch_event events_mask;
	struct upstream_list_watcher *next, *prev;
};

struct upstream {
	guint weight;
	guint cur_weight;
	guint errors;
	guint checked;
	guint dns_requests;
	gint active_idx;
	guint ttl;
	gchar *name;
	ev_timer ev;
	gdouble last_fail;
	gdouble last_resolve;
	gpointer ud;
	enum rspamd_upstream_flag flags;
	struct upstream_list *ls;
	GList *ctx_pos;
	struct upstream_ctx *ctx;

	struct {
		GPtrArray *addr; /* struct upstream_addr_elt */
		guint cur;
	} addrs;

	struct upstream_inet_addr_entry *new_addrs;
	gpointer data;
	gchar uid[8];
	ref_entry_t ref;
#ifdef UPSTREAMS_THREAD_SAFE
	rspamd_mutex_t *lock;
#endif
};

struct upstream_limits {
	gdouble revive_time;
	gdouble revive_jitter;
	gdouble error_time;
	gdouble dns_timeout;
	gdouble lazy_resolve_time;
	guint max_errors;
	guint dns_retransmits;
};

struct upstream_list {
	gchar *ups_line;
	struct upstream_ctx *ctx;
	GPtrArray *ups;
	GPtrArray *alive;
	struct upstream_list_watcher *watchers;
	guint64 hash_seed;
	const struct upstream_limits *limits;
	enum rspamd_upstream_flag flags;
	guint cur_elt;
	enum rspamd_upstream_rotation rot_alg;
#ifdef UPSTREAMS_THREAD_SAFE
	rspamd_mutex_t *lock;
#endif
};

struct upstream_ctx {
	struct rdns_resolver *res;
	struct ev_loop *event_loop;
	struct upstream_limits limits;
	GQueue *upstreams;
	gboolean configured;
	rspamd_mempool_t *pool;
	ref_entry_t ref;
};

#ifndef UPSTREAMS_THREAD_SAFE
#define RSPAMD_UPSTREAM_LOCK(x) do { } while (0)
#define RSPAMD_UPSTREAM_UNLOCK(x) do { } while (0)
#else
#define RSPAMD_UPSTREAM_LOCK(x) rspamd_mutex_lock(x->lock)
#define RSPAMD_UPSTREAM_UNLOCK(x) rspamd_mutex_unlock(x->lock)
#endif

#define msg_debug_upstream(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_upstream_log_id, "upstream", upstream->uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_upstream(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "upstream", upstream->uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(upstream)

/* 4 errors in 10 seconds */
#define DEFAULT_MAX_ERRORS 4
static const guint default_max_errors = DEFAULT_MAX_ERRORS;
#define DEFAULT_REVIVE_TIME 60
static const gdouble default_revive_time = DEFAULT_REVIVE_TIME;
#define DEFAULT_REVIVE_JITTER 0.4
static const gdouble default_revive_jitter = DEFAULT_REVIVE_JITTER;
#define DEFAULT_ERROR_TIME 10
static const gdouble default_error_time = DEFAULT_ERROR_TIME;
#define DEFAULT_DNS_TIMEOUT 1.0
static const gdouble default_dns_timeout = DEFAULT_DNS_TIMEOUT;
#define DEFAULT_DNS_RETRANSMITS 2
static const guint default_dns_retransmits = DEFAULT_DNS_RETRANSMITS;
/* TODO: make it configurable */
#define DEFAULT_LAZY_RESOLVE_TIME 3600.0
static const gdouble default_lazy_resolve_time = DEFAULT_LAZY_RESOLVE_TIME;

static const struct upstream_limits default_limits = {
		.revive_time = DEFAULT_REVIVE_TIME,
		.revive_jitter = DEFAULT_REVIVE_JITTER,
		.error_time = DEFAULT_ERROR_TIME,
		.dns_timeout = DEFAULT_DNS_TIMEOUT,
		.dns_retransmits = DEFAULT_DNS_RETRANSMITS,
		.max_errors = DEFAULT_MAX_ERRORS,
		.lazy_resolve_time = DEFAULT_LAZY_RESOLVE_TIME,
};

static void rspamd_upstream_lazy_resolve_cb (struct ev_loop *, ev_timer *, int );

void
rspamd_upstreams_library_config (struct rspamd_config *cfg,
								 struct upstream_ctx *ctx,
								 struct ev_loop *event_loop,
								 struct rdns_resolver *resolver)
{
	g_assert (ctx != NULL);
	g_assert (cfg != NULL);

	if (cfg->upstream_error_time) {
		ctx->limits.error_time = cfg->upstream_error_time;
	}
	if (cfg->upstream_max_errors) {
		ctx->limits.max_errors = cfg->upstream_max_errors;
	}
	if (cfg->upstream_revive_time) {
		ctx->limits.revive_time = cfg->upstream_max_errors;
	}
	if (cfg->upstream_lazy_resolve_time) {
		ctx->limits.lazy_resolve_time = cfg->upstream_lazy_resolve_time;
	}
	if (cfg->dns_retransmits) {
		ctx->limits.dns_retransmits = cfg->dns_retransmits;
	}
	if (cfg->dns_timeout) {
		ctx->limits.dns_timeout = cfg->dns_timeout;
	}

	ctx->event_loop = event_loop;
	ctx->res = resolver;
	ctx->configured = TRUE;

	/* Start lazy resolving */
	if (event_loop && resolver) {
		GList *cur;
		struct upstream *upstream;

		cur = ctx->upstreams->head;

		while (cur) {
			upstream = cur->data;
			if (!ev_can_stop (&upstream->ev) && upstream->ls &&
						!(upstream->flags & RSPAMD_UPSTREAM_FLAG_NORESOLVE)) {
				gdouble when;

				if (upstream->flags & RSPAMD_UPSTREAM_FLAG_SRV_RESOLVE) {
					/* Resolve them immediately ! */
					when = 0.0;
				}
				else {
					when = rspamd_time_jitter (upstream->ls->limits->lazy_resolve_time,
							upstream->ls->limits->lazy_resolve_time * .1);
				}

				ev_timer_init (&upstream->ev, rspamd_upstream_lazy_resolve_cb,
						when, 0);
				upstream->ev.data = upstream;
				ev_timer_start (ctx->event_loop, &upstream->ev);
			}

			cur = g_list_next (cur);
		}
	}
}

static void
rspamd_upstream_ctx_dtor (struct upstream_ctx *ctx)
{
	GList *cur;
	struct upstream *u;

	cur = ctx->upstreams->head;

	while (cur) {
		u = cur->data;
		u->ctx = NULL;
		u->ctx_pos = NULL;
		cur = g_list_next (cur);
	}

	g_queue_free (ctx->upstreams);
	rspamd_mempool_delete (ctx->pool);
	g_free (ctx);
}

void
rspamd_upstreams_library_unref (struct upstream_ctx *ctx)
{
	REF_RELEASE (ctx);
}

struct upstream_ctx *
rspamd_upstreams_library_init (void)
{
	struct upstream_ctx *ctx;

	ctx = g_malloc0 (sizeof (*ctx));
	memcpy (&ctx->limits, &default_limits, sizeof (ctx->limits));
	ctx->pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
			"upstreams", 0);

	ctx->upstreams = g_queue_new ();
	REF_INIT_RETAIN (ctx, rspamd_upstream_ctx_dtor);

	return ctx;
}

static gint
rspamd_upstream_af_to_weight (const rspamd_inet_addr_t *addr)
{
	int ret;

	switch (rspamd_inet_address_get_af (addr)) {
	case AF_UNIX:
		ret = 2;
		break;
	case AF_INET:
		ret = 1;
		break;
	default:
		ret = 0;
		break;
	}

	return ret;
}

/*
 * Select IPv4 addresses before IPv6
 */
static gint
rspamd_upstream_addr_sort_func (gconstpointer a, gconstpointer b)
{
	const struct upstream_addr_elt *ip1 = *(const struct upstream_addr_elt **)a,
			*ip2 = *(const struct upstream_addr_elt **)b;
	gint w1, w2;

	if (ip1->priority == 0 && ip2->priority == 0) {
		w1 = rspamd_upstream_af_to_weight (ip1->addr);
		w2 = rspamd_upstream_af_to_weight (ip2->addr);
	}
	else {
		w1 = ip1->priority;
		w2 = ip2->priority;
	}

	/* Inverse order */
	return w2 - w1;
}

static void
rspamd_upstream_set_active (struct upstream_list *ls, struct upstream *upstream)
{
	RSPAMD_UPSTREAM_LOCK (ls);
	g_ptr_array_add (ls->alive, upstream);
	upstream->active_idx = ls->alive->len - 1;

	if (upstream->ctx && upstream->ctx->configured &&
		!(upstream->flags & RSPAMD_UPSTREAM_FLAG_NORESOLVE)) {

		if (ev_can_stop (&upstream->ev)) {
			ev_timer_stop (upstream->ctx->event_loop, &upstream->ev);
		}

		/* Start lazy (or not so lazy) names resolution */
		gdouble when;

		if (upstream->flags & RSPAMD_UPSTREAM_FLAG_SRV_RESOLVE) {
			/* Resolve them immediately ! */
			when = 0.0;
		}
		else {
			when = rspamd_time_jitter (upstream->ls->limits->lazy_resolve_time,
					upstream->ls->limits->lazy_resolve_time * .1);
		}
		ev_timer_init (&upstream->ev, rspamd_upstream_lazy_resolve_cb,
				when, 0);
		upstream->ev.data = upstream;
		msg_debug_upstream ("start lazy resolving for %s in %.0f seconds",
				upstream->name, when);
		ev_timer_start (upstream->ctx->event_loop, &upstream->ev);
	}

	RSPAMD_UPSTREAM_UNLOCK (ls);
}

static void
rspamd_upstream_addr_elt_dtor (gpointer a)
{
	struct upstream_addr_elt *elt = a;

	if (elt) {
		rspamd_inet_address_free (elt->addr);
		g_free (elt);
	}
}

static void
rspamd_upstream_update_addrs (struct upstream *upstream)
{
	guint addr_cnt, i, port;
	gboolean seen_addr, reset_errors = FALSE;
	struct upstream_inet_addr_entry *cur, *tmp;
	GPtrArray *new_addrs;
	struct upstream_addr_elt *addr_elt, *naddr;

	/*
	 * We need first of all get the saved port, since DNS gives us no
	 * idea about what port has been used previously
	 */
	RSPAMD_UPSTREAM_LOCK (upstream);

	if (upstream->addrs.addr->len > 0 && upstream->new_addrs) {
		addr_elt = g_ptr_array_index (upstream->addrs.addr, 0);
		port = rspamd_inet_address_get_port (addr_elt->addr);

		/* Now calculate new addrs count */
		addr_cnt = 0;
		LL_FOREACH (upstream->new_addrs, cur) {
			addr_cnt++;
		}

		/* At 10% probability reset errors on addr elements */
		if (rspamd_random_double_fast () > 0.9) {
			reset_errors = TRUE;
			msg_debug_upstream ("reset errors on upstream %s",
					upstream->name);
		}

		new_addrs = g_ptr_array_new_full (addr_cnt, rspamd_upstream_addr_elt_dtor);

		/* Copy addrs back */
		LL_FOREACH (upstream->new_addrs, cur) {
			seen_addr = FALSE;
			naddr = NULL;
			/* Ports are problematic, set to compare in the next block */
			rspamd_inet_address_set_port (cur->addr, port);

			PTR_ARRAY_FOREACH (upstream->addrs.addr, i, addr_elt) {
				if (rspamd_inet_address_compare (addr_elt->addr, cur->addr, FALSE) == 0) {
					naddr = g_malloc0 (sizeof (*naddr));
					naddr->addr = cur->addr;
					naddr->errors = reset_errors ? 0 : addr_elt->errors;
					seen_addr = TRUE;

					break;
				}
			}

			if (!seen_addr) {
				naddr = g_malloc0 (sizeof (*naddr));
				naddr->addr = cur->addr;
				naddr->errors = 0;
				msg_debug_upstream ("new address for %s: %s",
						upstream->name,
						rspamd_inet_address_to_string_pretty (naddr->addr));
			}
			else {
				msg_debug_upstream ("existing address for %s: %s",
						upstream->name,
						rspamd_inet_address_to_string_pretty (cur->addr));
			}

			g_ptr_array_add (new_addrs, naddr);
		}

		/* Free old addresses */
		g_ptr_array_free (upstream->addrs.addr, TRUE);

		upstream->addrs.cur = 0;
		upstream->addrs.addr = new_addrs;
		g_ptr_array_sort (upstream->addrs.addr, rspamd_upstream_addr_sort_func);
	}

	LL_FOREACH_SAFE (upstream->new_addrs, cur, tmp) {
		/* Do not free inet address pointer since it has been transferred to up */
		g_free (cur);
	}

	upstream->new_addrs = NULL;
	RSPAMD_UPSTREAM_UNLOCK (upstream);
}

static void
rspamd_upstream_dns_cb (struct rdns_reply *reply, void *arg)
{
	struct upstream *up = (struct upstream *)arg;
	struct rdns_reply_entry *entry;
	struct upstream_inet_addr_entry *up_ent;

	if (reply->code == RDNS_RC_NOERROR) {
		entry = reply->entries;

		RSPAMD_UPSTREAM_LOCK (up);
		while (entry) {

			if (entry->type == RDNS_REQUEST_A) {
				up_ent = g_malloc0 (sizeof (*up_ent));
				up_ent->addr = rspamd_inet_address_new (AF_INET,
						&entry->content.a.addr);
				LL_PREPEND (up->new_addrs, up_ent);
			}
			else if (entry->type == RDNS_REQUEST_AAAA) {
				up_ent = g_malloc0 (sizeof (*up_ent));
				up_ent->addr = rspamd_inet_address_new (AF_INET6,
						&entry->content.aaa.addr);
				LL_PREPEND (up->new_addrs, up_ent);
			}
			entry = entry->next;
		}

		RSPAMD_UPSTREAM_UNLOCK (up);
	}

	up->dns_requests--;

	if (up->dns_requests == 0) {
		rspamd_upstream_update_addrs (up);
	}

	REF_RELEASE (up);
}

struct rspamd_upstream_srv_dns_cb {
	struct upstream *up;
	guint priority;
	guint port;
	guint requests_inflight;
};

/* Used when we have resolved SRV record and resolved addrs */
static void
rspamd_upstream_dns_srv_phase2_cb (struct rdns_reply *reply, void *arg)
{
	struct rspamd_upstream_srv_dns_cb *cbdata =
			(struct rspamd_upstream_srv_dns_cb *)arg;
	struct upstream *up;
	struct rdns_reply_entry *entry;
	struct upstream_inet_addr_entry *up_ent;

	up = cbdata->up;

	if (reply->code == RDNS_RC_NOERROR) {
		entry = reply->entries;

		RSPAMD_UPSTREAM_LOCK (up);
		while (entry) {

			if (entry->type == RDNS_REQUEST_A) {
				up_ent = g_malloc0 (sizeof (*up_ent));
				up_ent->addr = rspamd_inet_address_new (AF_INET,
						&entry->content.a.addr);
				up_ent->priority = cbdata->priority;
				rspamd_inet_address_set_port (up_ent->addr, cbdata->port);
				LL_PREPEND (up->new_addrs, up_ent);
			}
			else if (entry->type == RDNS_REQUEST_AAAA) {
				up_ent = g_malloc0 (sizeof (*up_ent));
				up_ent->addr = rspamd_inet_address_new (AF_INET6,
						&entry->content.aaa.addr);
				up_ent->priority = cbdata->priority;
				rspamd_inet_address_set_port (up_ent->addr, cbdata->port);
				LL_PREPEND (up->new_addrs, up_ent);
			}
			entry = entry->next;
		}

		RSPAMD_UPSTREAM_UNLOCK (up);
	}

	up->dns_requests--;
	cbdata->requests_inflight --;

	if (cbdata->requests_inflight == 0) {
		g_free (cbdata);
	}

	if (up->dns_requests == 0) {
		rspamd_upstream_update_addrs (up);
	}

	REF_RELEASE (up);
}

static void
rspamd_upstream_dns_srv_cb (struct rdns_reply *reply, void *arg)
{
	struct upstream *upstream = (struct upstream *) arg;
	struct rdns_reply_entry *entry;
	struct rspamd_upstream_srv_dns_cb *ncbdata;

	if (reply->code == RDNS_RC_NOERROR) {
		entry = reply->entries;

		RSPAMD_UPSTREAM_LOCK (upstream);
		while (entry) {
			/* XXX: we ignore weight as it contradicts with upstreams logic */
			if (entry->type == RDNS_REQUEST_SRV) {
				msg_debug_upstream ("got srv reply for %s: %s "
						"(weight=%d, priority=%d, port=%d)",
						upstream->name, entry->content.srv.target,
						entry->content.srv.weight, entry->content.srv.priority,
						entry->content.srv.port);
				ncbdata = g_malloc0 (sizeof (*ncbdata));
				ncbdata->priority = entry->content.srv.weight;
				ncbdata->port = entry->content.srv.port;
				/* XXX: for all entries? */
				upstream->ttl = entry->ttl;

				if (rdns_make_request_full (upstream->ctx->res,
						rspamd_upstream_dns_srv_phase2_cb, ncbdata,
						upstream->ls->limits->dns_timeout,
						upstream->ls->limits->dns_retransmits,
						1, entry->content.srv.target, RDNS_REQUEST_A) != NULL) {
					upstream->dns_requests++;
					REF_RETAIN (upstream);
					ncbdata->requests_inflight ++;
				}

				if (rdns_make_request_full (upstream->ctx->res,
						rspamd_upstream_dns_srv_phase2_cb, ncbdata,
						upstream->ls->limits->dns_timeout,
						upstream->ls->limits->dns_retransmits,
						1, entry->content.srv.target, RDNS_REQUEST_AAAA) != NULL) {
					upstream->dns_requests++;
					REF_RETAIN (upstream);
					ncbdata->requests_inflight ++;
				}

				if (ncbdata->requests_inflight == 0) {
					g_free (ncbdata);
				}
			}
			entry = entry->next;
		}

		RSPAMD_UPSTREAM_UNLOCK (upstream);
	}

	upstream->dns_requests--;
	REF_RELEASE (upstream);
}

static void
rspamd_upstream_revive_cb (struct ev_loop *loop, ev_timer *w, int revents)
{
	struct upstream *upstream = (struct upstream *)w->data;

	RSPAMD_UPSTREAM_LOCK (upstream);
	ev_timer_stop (loop, w);

	msg_debug_upstream ("revive upstream %s", upstream->name);

	if (upstream->ls) {
		rspamd_upstream_set_active (upstream->ls, upstream);
	}

	RSPAMD_UPSTREAM_UNLOCK (upstream);
	g_assert (upstream->ref.refcount > 1);
	REF_RELEASE (upstream);
}

static void
rspamd_upstream_resolve_addrs (const struct upstream_list *ls,
		struct upstream *upstream)
{
	/* XXX: maybe make it configurable */
	static const gdouble min_resolve_interval = 60.0;

	if (upstream->ctx->res != NULL &&
		upstream->ctx->configured &&
		upstream->dns_requests == 0 &&
		!(upstream->flags & RSPAMD_UPSTREAM_FLAG_NORESOLVE)) {

		gdouble now = ev_now (upstream->ctx->event_loop);

		if (now - upstream->last_resolve < min_resolve_interval) {
			msg_info_upstream ("do not resolve upstream %s as it was checked %.0f "
					  "seconds ago (%.0f is minimum)",
					upstream->name, now - upstream->last_resolve,
					min_resolve_interval);

			return;
		}

		/* Resolve name of the upstream one more time */
		if (upstream->name[0] != '/') {
			upstream->last_resolve = now;

			if (upstream->flags & RSPAMD_UPSTREAM_FLAG_SRV_RESOLVE) {
				if (rdns_make_request_full (upstream->ctx->res,
						rspamd_upstream_dns_srv_cb, upstream,
						ls->limits->dns_timeout, ls->limits->dns_retransmits,
						1, upstream->name, RDNS_REQUEST_SRV) != NULL) {
					upstream->dns_requests++;
					REF_RETAIN (upstream);
				}
			}
			else {
				if (rdns_make_request_full (upstream->ctx->res,
						rspamd_upstream_dns_cb, upstream,
						ls->limits->dns_timeout, ls->limits->dns_retransmits,
						1, upstream->name, RDNS_REQUEST_A) != NULL) {
					upstream->dns_requests++;
					REF_RETAIN (upstream);
				}

				if (rdns_make_request_full (upstream->ctx->res,
						rspamd_upstream_dns_cb, upstream,
						ls->limits->dns_timeout, ls->limits->dns_retransmits,
						1, upstream->name, RDNS_REQUEST_AAAA) != NULL) {
					upstream->dns_requests++;
					REF_RETAIN (upstream);
				}
			}
		}
	}
	else if (upstream->dns_requests != 0) {
		msg_info_upstream ("do not resolve upstream %s as another request for "
					 "resolving has been already issued",
					 upstream->name);
	}
}

static void
rspamd_upstream_lazy_resolve_cb (struct ev_loop *loop, ev_timer *w, int revents)
{
	struct upstream *up = (struct upstream *)w->data;

	RSPAMD_UPSTREAM_LOCK (up);
	ev_timer_stop (loop, w);

	if (up->ls) {
		rspamd_upstream_resolve_addrs (up->ls, up);

		if (up->ttl == 0 || up->ttl > up->ls->limits->lazy_resolve_time) {
			w->repeat = rspamd_time_jitter (up->ls->limits->lazy_resolve_time,
					up->ls->limits->lazy_resolve_time * .1);
		}
		else {
			w->repeat = up->ttl;
		}

		ev_timer_again (loop, w);
	}

	RSPAMD_UPSTREAM_UNLOCK (up);
}

static void
rspamd_upstream_set_inactive (struct upstream_list *ls, struct upstream *upstream)
{
	gdouble ntim;
	guint i;
	struct upstream *cur;
	struct upstream_list_watcher *w;

	RSPAMD_UPSTREAM_LOCK (ls);
	g_ptr_array_remove_index (ls->alive, upstream->active_idx);
	upstream->active_idx = -1;

	/* We need to update all indicies */
	for (i = 0; i < ls->alive->len; i ++) {
		cur = g_ptr_array_index (ls->alive, i);
		cur->active_idx = i;
	}

	if (upstream->ctx) {
		rspamd_upstream_resolve_addrs (ls, upstream);

		REF_RETAIN (upstream);
		ntim = rspamd_time_jitter (ls->limits->revive_time,
				ls->limits->revive_time * ls->limits->revive_jitter);

		if (ev_can_stop (&upstream->ev)) {
			ev_timer_stop (upstream->ctx->event_loop, &upstream->ev);
		}

		msg_debug_upstream ("mark upstream %s inactive; revive in %.0f seconds",
				upstream->name, ntim);
		ev_timer_init (&upstream->ev, rspamd_upstream_revive_cb, ntim, 0);
		upstream->ev.data = upstream;

		if (upstream->ctx->event_loop != NULL && upstream->ctx->configured) {
			ev_timer_start (upstream->ctx->event_loop, &upstream->ev);
		}
	}

	DL_FOREACH (upstream->ls->watchers, w) {
		if (w->events_mask & RSPAMD_UPSTREAM_WATCH_OFFLINE) {
			w->func (upstream, RSPAMD_UPSTREAM_WATCH_OFFLINE, upstream->errors, w->ud);
		}
	}

	RSPAMD_UPSTREAM_UNLOCK (ls);
}

void
rspamd_upstream_fail (struct upstream *upstream,
					  gboolean addr_failure,
					  const gchar *reason)
{
	gdouble error_rate = 0, max_error_rate = 0;
	gdouble sec_last, sec_cur;
	struct upstream_addr_elt *addr_elt;
	struct upstream_list_watcher *w;

	msg_debug_upstream ("upstream %s failed; reason: %s",
			upstream->name,
			reason);

	if (upstream->ctx && upstream->active_idx != -1 && upstream->ls) {
		sec_cur = rspamd_get_ticks (FALSE);

		RSPAMD_UPSTREAM_LOCK (upstream);
		if (upstream->errors == 0) {
			/* We have the first error */
			upstream->last_fail = sec_cur;
			upstream->errors = 1;

			if (upstream->ls && upstream->dns_requests == 0) {
				/* Try to re-resolve address immediately */
				rspamd_upstream_resolve_addrs (upstream->ls, upstream);
			}

			DL_FOREACH (upstream->ls->watchers, w) {
				if (w->events_mask & RSPAMD_UPSTREAM_WATCH_FAILURE) {
					w->func (upstream, RSPAMD_UPSTREAM_WATCH_FAILURE, 1, w->ud);
				}
			}
		}
		else {
			sec_last = upstream->last_fail;

			if (sec_cur >= sec_last) {
				upstream->errors ++;


				DL_FOREACH (upstream->ls->watchers, w) {
					if (w->events_mask & RSPAMD_UPSTREAM_WATCH_FAILURE) {
						w->func (upstream, RSPAMD_UPSTREAM_WATCH_FAILURE,
								upstream->errors, w->ud);
					}
				}

				if (sec_cur - sec_last >= upstream->ls->limits->error_time)  {
					error_rate = ((gdouble)upstream->errors) / (sec_cur - sec_last);
					max_error_rate = ((gdouble)upstream->ls->limits->max_errors) /
									 upstream->ls->limits->error_time;
				}

				if (error_rate > max_error_rate) {
					/* Remove upstream from the active list */
					if (upstream->ls->ups->len > 1) {
						msg_debug_upstream ("mark upstream %s inactive; "
											"reason: %s; %.2f "
											"error rate (%d errors), "
											"%.2f max error rate, "
											"%.1f first error time, "
											"%.1f current ts, "
											"%d upstreams left",
								upstream->name,
								reason,
								error_rate,
								upstream->errors,
								max_error_rate,
								sec_last,
								sec_cur,
								upstream->ls->alive->len - 1);
						rspamd_upstream_set_inactive (upstream->ls, upstream);
						upstream->errors = 0;
					}
					else {
						msg_debug_upstream ("cannot mark last alive upstream %s "
											"inactive; reason: %s; %.2f "
											"error rate (%d errors), "
											"%.2f max error rate, "
											"%.1f first error time, "
											"%.1f current ts",
								upstream->name,
								reason,
								error_rate,
								upstream->errors,
								max_error_rate,
								sec_last,
								sec_cur);
						/* Just re-resolve addresses */
						if (sec_cur - sec_last > upstream->ls->limits->revive_time) {
							upstream->errors = 0;
							rspamd_upstream_resolve_addrs (upstream->ls, upstream);
						}
					}
				}
				else if (sec_cur - sec_last >= upstream->ls->limits->error_time) {
					/* Forget the whole interval */
					upstream->last_fail = sec_cur;
					upstream->errors = 1;
				}
			}
		}

		if (addr_failure) {
			/* Also increase count of errors for this specific address */
			if (upstream->addrs.addr) {
				addr_elt = g_ptr_array_index (upstream->addrs.addr,
						upstream->addrs.cur);
				addr_elt->errors++;
			}
		}

		RSPAMD_UPSTREAM_UNLOCK (upstream);
	}
}

void
rspamd_upstream_ok (struct upstream *upstream)
{
	struct upstream_addr_elt *addr_elt;
	struct upstream_list_watcher *w;

	RSPAMD_UPSTREAM_LOCK (upstream);
	if (upstream->errors > 0 && upstream->active_idx != -1 && upstream->ls) {
		/* We touch upstream if and only if it is active */
		msg_debug_upstream ("reset errors on upstream %s (was %ud)", upstream->name, upstream->errors);
		upstream->errors = 0;

		if (upstream->addrs.addr) {
			addr_elt = g_ptr_array_index (upstream->addrs.addr, upstream->addrs.cur);
			addr_elt->errors = 0;
		}

		DL_FOREACH (upstream->ls->watchers, w) {
			if (w->events_mask & RSPAMD_UPSTREAM_WATCH_SUCCESS) {
				w->func (upstream, RSPAMD_UPSTREAM_WATCH_SUCCESS, 0, w->ud);
			}
		}
	}

	RSPAMD_UPSTREAM_UNLOCK (upstream);
}

void
rspamd_upstream_set_weight (struct upstream *up, guint weight)
{
	RSPAMD_UPSTREAM_LOCK (up);
	up->weight = weight;
	RSPAMD_UPSTREAM_UNLOCK (up);
}

#define SEED_CONSTANT 0xa574de7df64e9b9dULL

struct upstream_list*
rspamd_upstreams_create (struct upstream_ctx *ctx)
{
	struct upstream_list *ls;

	ls = g_malloc0 (sizeof (*ls));
	ls->hash_seed = SEED_CONSTANT;
	ls->ups = g_ptr_array_new ();
	ls->alive = g_ptr_array_new ();

#ifdef UPSTREAMS_THREAD_SAFE
	ls->lock = rspamd_mutex_new ();
#endif
	ls->cur_elt = 0;
	ls->ctx = ctx;
	ls->rot_alg = RSPAMD_UPSTREAM_UNDEF;

	if (ctx) {
		ls->limits = &ctx->limits;
	}
	else {
		ls->limits = &default_limits;
	}

	return ls;
}

gsize
rspamd_upstreams_count (struct upstream_list *ups)
{
	return ups != NULL ? ups->ups->len : 0;
}

gsize
rspamd_upstreams_alive (struct upstream_list *ups)
{
	return ups != NULL ? ups->alive->len : 0;
}

static void
rspamd_upstream_dtor (struct upstream *up)
{
	struct upstream_inet_addr_entry *cur, *tmp;

	if (up->new_addrs) {
		LL_FOREACH_SAFE(up->new_addrs, cur, tmp) {
			/* Here we need to free pointer as well */
			rspamd_inet_address_free (cur->addr);
			g_free (cur);
		}
	}

	if (up->addrs.addr) {
		g_ptr_array_free (up->addrs.addr, TRUE);
	}

#ifdef UPSTREAMS_THREAD_SAFE
	rspamd_mutex_free (up->lock);
#endif

	if (up->ctx) {

		if (ev_can_stop (&up->ev)) {
			ev_timer_stop (up->ctx->event_loop, &up->ev);
		}

		g_queue_delete_link (up->ctx->upstreams, up->ctx_pos);
		REF_RELEASE (up->ctx);
	}

	g_free (up);
}

rspamd_inet_addr_t*
rspamd_upstream_addr_next (struct upstream *up)
{
	guint idx, next_idx;
	struct upstream_addr_elt *e1, *e2;

	do {
		idx = up->addrs.cur;
		next_idx = (idx + 1) % up->addrs.addr->len;
		e1 = g_ptr_array_index (up->addrs.addr, idx);
		e2 = g_ptr_array_index (up->addrs.addr, next_idx);
		up->addrs.cur = next_idx;
	} while (e2->errors > e1->errors);

	return e2->addr;
}

rspamd_inet_addr_t*
rspamd_upstream_addr_cur (const struct upstream *up)
{
	struct upstream_addr_elt *elt;

	elt = g_ptr_array_index (up->addrs.addr, up->addrs.cur);

	return elt->addr;
}

const gchar*
rspamd_upstream_name (struct upstream *up)
{
	return up->name;
}

gint
rspamd_upstream_port (struct upstream *up)
{
	struct upstream_addr_elt *elt;

	elt = g_ptr_array_index (up->addrs.addr, up->addrs.cur);
	return rspamd_inet_address_get_port (elt->addr);
}

gboolean
rspamd_upstreams_add_upstream (struct upstream_list *ups, const gchar *str,
		guint16 def_port, enum rspamd_upstream_parse_type parse_type,
		void *data)
{
	struct upstream *upstream;
	GPtrArray *addrs = NULL;
	guint i, slen;
	rspamd_inet_addr_t *addr;
	enum rspamd_parse_host_port_result ret = RSPAMD_PARSE_ADDR_FAIL;

	upstream = g_malloc0 (sizeof (*upstream));
	slen = strlen (str);

	switch (parse_type) {
	case RSPAMD_UPSTREAM_PARSE_DEFAULT:
		if (slen > sizeof ("service=") &&
			RSPAMD_LEN_CHECK_STARTS_WITH (str, slen, "service=")) {
			const gchar *plus_pos, *service_pos, *semicolon_pos;

			/* Accept service=srv_name+hostname[:priority] */
			service_pos = str + sizeof ("service=") - 1;
			plus_pos = strchr (service_pos, '+');

			if (plus_pos != NULL) {
				semicolon_pos = strchr (plus_pos + 1, ':');

				if (semicolon_pos) {
					upstream->weight = strtoul (semicolon_pos + 1, NULL, 10);
				}
				else {
					semicolon_pos = plus_pos + strlen (plus_pos);
				}

				/*
				 * Now our name is _service._tcp.<domain>
				 * where <domain> is string between semicolon_pos and plus_pos +1
				 * while service is a string between service_pos and plus_pos
				 */
				guint namelen = (semicolon_pos - (plus_pos + 1)) +
						(plus_pos - service_pos) +
						(sizeof ("tcp") - 1) +
						4;
				addrs = g_ptr_array_sized_new (1);
				upstream->name = ups->ctx ?
						rspamd_mempool_alloc (ups->ctx->pool, namelen + 1) :
						g_malloc (namelen + 1);

				rspamd_snprintf (upstream->name, namelen + 1,
						"_%*s._tcp.%*s",
						(gint)(plus_pos - service_pos), service_pos,
						(gint)(semicolon_pos - (plus_pos + 1)), plus_pos + 1);
				upstream->flags |= RSPAMD_UPSTREAM_FLAG_SRV_RESOLVE;
				ret = RSPAMD_PARSE_ADDR_RESOLVED;
			}
		}
		else {
			ret = rspamd_parse_host_port_priority (str, &addrs,
					&upstream->weight,
					&upstream->name, def_port,
					FALSE,
					ups->ctx ? ups->ctx->pool : NULL);
		}
		break;
	case RSPAMD_UPSTREAM_PARSE_NAMESERVER:
		addrs = g_ptr_array_sized_new (1);
		if (rspamd_parse_inet_address (&addr, str, strlen (str),
				RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
			if (ups->ctx) {
				upstream->name = rspamd_mempool_strdup (ups->ctx->pool, str);
			}
			else {
				upstream->name = g_strdup (str);
			}
			if (rspamd_inet_address_get_port (addr) == 0) {
				rspamd_inet_address_set_port (addr, def_port);
			}

			g_ptr_array_add (addrs, addr);
			ret = RSPAMD_PARSE_ADDR_NUMERIC;

			if (ups->ctx) {
				rspamd_mempool_add_destructor (ups->ctx->pool,
						(rspamd_mempool_destruct_t) rspamd_inet_address_free,
						addr);
				rspamd_mempool_add_destructor (ups->ctx->pool,
						(rspamd_mempool_destruct_t) rspamd_ptr_array_free_hard,
						addrs);
			}
		}
		else {
			g_ptr_array_free (addrs, TRUE);
		}

		break;
	}

	if (ret == RSPAMD_PARSE_ADDR_FAIL) {
		g_free (upstream);
		return FALSE;
	}
	else {
		upstream->flags |= ups->flags;

		if (ret == RSPAMD_PARSE_ADDR_NUMERIC) {
			/* Add noresolve flag */
			upstream->flags |= RSPAMD_UPSTREAM_FLAG_NORESOLVE;
		}
		for (i = 0; i < addrs->len; i ++) {
			addr = g_ptr_array_index (addrs, i);
			rspamd_upstream_add_addr (upstream, rspamd_inet_address_copy (addr));
		}
	}

	if (upstream->weight == 0 && ups->rot_alg == RSPAMD_UPSTREAM_MASTER_SLAVE) {
		/* Special heuristic for master-slave rotation */
		if (ups->ups->len == 0) {
			/* Prioritize the first */
			upstream->weight = 1;
		}
	}

	g_ptr_array_add (ups->ups, upstream);
	upstream->ud = data;
	upstream->cur_weight = upstream->weight;
	upstream->ls = ups;
	REF_INIT_RETAIN (upstream, rspamd_upstream_dtor);
#ifdef UPSTREAMS_THREAD_SAFE
	upstream->lock = rspamd_mutex_new ();
#endif
	upstream->ctx = ups->ctx;

	if (upstream->ctx) {
		REF_RETAIN (ups->ctx);
		g_queue_push_tail (ups->ctx->upstreams, upstream);
		upstream->ctx_pos = g_queue_peek_tail_link (ups->ctx->upstreams);
	}

	guint h = rspamd_cryptobox_fast_hash (upstream->name,
			strlen (upstream->name), 0);
	memset (upstream->uid, 0, sizeof (upstream->uid));
	rspamd_encode_base32_buf ((const guchar *) &h, sizeof (h),
			upstream->uid, sizeof (upstream->uid) - 1, RSPAMD_BASE32_DEFAULT);

	msg_debug_upstream ("added upstream %s (%s)", upstream->name,
			upstream->flags & RSPAMD_UPSTREAM_FLAG_NORESOLVE ? "numeric ip" : "DNS name");
	g_ptr_array_sort (upstream->addrs.addr, rspamd_upstream_addr_sort_func);
	rspamd_upstream_set_active (ups, upstream);

	return TRUE;
}

void
rspamd_upstreams_set_flags (struct upstream_list *ups,
		enum rspamd_upstream_flag flags)
{
	ups->flags = flags;
}

void
rspamd_upstreams_set_rotation (struct upstream_list *ups,
		enum rspamd_upstream_rotation rot)
{
	ups->rot_alg = rot;
}

gboolean
rspamd_upstream_add_addr (struct upstream *up, rspamd_inet_addr_t *addr)
{
	struct upstream_addr_elt *elt;
	/*
	 * XXX: slow and inefficient
	 */
	if (up->addrs.addr == NULL) {
		up->addrs.addr = g_ptr_array_new_full (8, rspamd_upstream_addr_elt_dtor);
	}

	elt = g_malloc0 (sizeof (*elt));
	elt->addr = addr;
	g_ptr_array_add (up->addrs.addr, elt);
	g_ptr_array_sort (up->addrs.addr, rspamd_upstream_addr_sort_func);

	return TRUE;
}

gboolean
rspamd_upstreams_parse_line_len (struct upstream_list *ups,
		const gchar *str, gsize len, guint16 def_port, void *data)
{
	const gchar *end = str + len, *p = str;
	const gchar *separators = ";, \n\r\t";
	gchar *tmp;
	guint span_len;
	gboolean ret = FALSE;

	if (RSPAMD_LEN_CHECK_STARTS_WITH(p, len, "random:")) {
		ups->rot_alg = RSPAMD_UPSTREAM_RANDOM;
		p += sizeof ("random:") - 1;
	}
	else if (RSPAMD_LEN_CHECK_STARTS_WITH(p, len, "master-slave:")) {
		ups->rot_alg = RSPAMD_UPSTREAM_MASTER_SLAVE;
		p += sizeof ("master-slave:") - 1;
	}
	else if (RSPAMD_LEN_CHECK_STARTS_WITH(p, len, "round-robin:")) {
		ups->rot_alg = RSPAMD_UPSTREAM_ROUND_ROBIN;
		p += sizeof ("round-robin:") - 1;
	}
	else if (RSPAMD_LEN_CHECK_STARTS_WITH(p, len, "hash:")) {
		ups->rot_alg = RSPAMD_UPSTREAM_HASHED;
		p += sizeof ("hash:") - 1;
	}
	else if (RSPAMD_LEN_CHECK_STARTS_WITH(p, len, "sequential:")) {
		ups->rot_alg = RSPAMD_UPSTREAM_SEQUENTIAL;
		p += sizeof ("sequential:") - 1;
	}

	while (p < end) {
		span_len = rspamd_memcspn (p, separators, end - p);

		if (span_len > 0) {
			tmp = g_malloc (span_len + 1);
			rspamd_strlcpy (tmp, p, span_len + 1);

			if (rspamd_upstreams_add_upstream (ups, tmp, def_port,
					RSPAMD_UPSTREAM_PARSE_DEFAULT,
					data)) {
				ret = TRUE;
			}

			g_free (tmp);
		}

		p += span_len;
		/* Skip separators */
		if (p < end) {
			p += rspamd_memspn (p, separators, end - p);
		}
	}

	if (!ups->ups_line) {
		ups->ups_line = g_malloc (len + 1);
		rspamd_strlcpy (ups->ups_line, str, len + 1);
	}

	return ret;
}


gboolean
rspamd_upstreams_parse_line (struct upstream_list *ups,
							 const gchar *str, guint16 def_port, void *data)
{
	return rspamd_upstreams_parse_line_len (ups, str, strlen (str),
			def_port, data);
}

gboolean
rspamd_upstreams_from_ucl (struct upstream_list *ups,
		const ucl_object_t *in, guint16 def_port, void *data)
{
	gboolean ret = FALSE;
	const ucl_object_t *cur;
	ucl_object_iter_t it = NULL;

	it = ucl_object_iterate_new (in);

	while ((cur = ucl_object_iterate_safe (it, true)) != NULL) {
		if (ucl_object_type (cur) == UCL_STRING) {
			ret = rspamd_upstreams_parse_line (ups, ucl_object_tostring (cur),
					def_port, data);
		}
	}

	ucl_object_iterate_free (it);

	return ret;
}

void
rspamd_upstreams_destroy (struct upstream_list *ups)
{
	guint i;
	struct upstream *up;
	struct upstream_list_watcher *w, *tmp;

	if (ups != NULL) {
		g_ptr_array_free (ups->alive, TRUE);

		for (i = 0; i < ups->ups->len; i ++) {
			up = g_ptr_array_index (ups->ups, i);
			up->ls = NULL;
			REF_RELEASE (up);
		}

		DL_FOREACH_SAFE (ups->watchers, w, tmp) {
			if (w->dtor) {
				w->dtor (w->ud);
			}
			g_free (w);
		}

		g_free (ups->ups_line);
		g_ptr_array_free (ups->ups, TRUE);
#ifdef UPSTREAMS_THREAD_SAFE
		rspamd_mutex_free (ups->lock);
#endif
		g_free (ups);
	}
}

static void
rspamd_upstream_restore_cb (gpointer elt, gpointer ls)
{
	struct upstream *up = (struct upstream *)elt;
	struct upstream_list *ups = (struct upstream_list *)ls;
	struct upstream_list_watcher *w;

	/* Here the upstreams list is already locked */
	RSPAMD_UPSTREAM_LOCK (up);

	if (ev_can_stop (&up->ev)) {
		ev_timer_stop (up->ctx->event_loop, &up->ev);
	}

	g_ptr_array_add (ups->alive, up);
	up->active_idx = ups->alive->len - 1;
	RSPAMD_UPSTREAM_UNLOCK (up);

	DL_FOREACH (up->ls->watchers, w) {
		if (w->events_mask & RSPAMD_UPSTREAM_WATCH_ONLINE) {
			w->func (up, RSPAMD_UPSTREAM_WATCH_ONLINE, up->errors, w->ud);
		}
	}

	/* For revive event */
	g_assert (up->ref.refcount > 1);
	REF_RELEASE (up);
}

static struct upstream*
rspamd_upstream_get_random (struct upstream_list *ups,
							struct upstream *except)
{
	for (;;) {
		guint idx = ottery_rand_range (ups->alive->len - 1);
		struct upstream *up;

		up = g_ptr_array_index (ups->alive, idx);

		if (except && up == except) {
			continue;
		}

		return up;
	}
}

static struct upstream*
rspamd_upstream_get_round_robin (struct upstream_list *ups,
								 struct upstream *except,
								 gboolean use_cur)
{
	guint max_weight = 0, min_checked = G_MAXUINT;
	struct upstream *up = NULL, *selected = NULL, *min_checked_sel = NULL;
	guint i;

	/* Select upstream with the maximum cur_weight */
	RSPAMD_UPSTREAM_LOCK (ups);

	for (i = 0; i < ups->alive->len; i ++) {
		up = g_ptr_array_index (ups->alive, i);

		if (except != NULL && up == except) {
			continue;
		}

		if (use_cur) {
			if (up->cur_weight > max_weight) {
				selected = up;
				max_weight = up->cur_weight;
			}
		}
		else {
			if (up->weight > max_weight) {
				selected = up;
				max_weight = up->weight;
			}
		}

		/*
		 * This code is used when all upstreams have zero weight
		 * The logic is to select least currently used upstream and penalise
		 * upstream with errors. The error penalty should no be too high
		 * to avoid sudden traffic drop in this case.
		 */
		if (up->checked + up->errors * 2 < min_checked) {
			min_checked_sel = up;
			min_checked = up->checked;
		}
	}

	if (max_weight == 0) {
		/* All upstreams have zero weight */
		if (min_checked > G_MAXUINT / 2) {
			/* Reset all checked counters to avoid overflow */
			for (i = 0; i < ups->alive->len; i ++) {
				up = g_ptr_array_index (ups->alive, i);
				up->checked = 0;
			}
		}

		selected = min_checked_sel;
	}

	if (use_cur && selected) {
		if (selected->cur_weight > 0) {
			selected->cur_weight--;
		}
		else {
			selected->cur_weight = selected->weight;
		}
	}

	RSPAMD_UPSTREAM_UNLOCK (ups);

	return selected;
}

/*
 * The key idea of this function is obtained from the following paper:
 * A Fast, Minimal Memory, Consistent Hash Algorithm
 * John Lamping, Eric Veach
 *
 * http://arxiv.org/abs/1406.2294
 */
static guint32
rspamd_consistent_hash (guint64 key, guint32 nbuckets)
{
	gint64 b = -1, j = 0;

	while (j < nbuckets) {
		b = j;
		key *= 2862933555777941757ULL + 1;
		j = (b + 1) * (double)(1ULL << 31) / (double)((key >> 33) + 1ULL);
	}

	return b;
}

static struct upstream*
rspamd_upstream_get_hashed (struct upstream_list *ups,
							struct upstream *except,
							const guint8 *key, guint keylen)
{
	guint64 k;
	guint32 idx;
	static const guint max_tries = 20;
	struct upstream *up = NULL;

	/* Generate 64 bits input key */
	k = rspamd_cryptobox_fast_hash_specific (RSPAMD_CRYPTOBOX_XXHASH64,
			key, keylen, ups->hash_seed);

	RSPAMD_UPSTREAM_LOCK (ups);
	/*
	 * Select new upstream from all upstreams
	 */
	for (guint i = 0; i < max_tries; i ++) {
		idx = rspamd_consistent_hash (k, ups->ups->len);
		up = g_ptr_array_index (ups->ups, idx);

		if (up->active_idx < 0 || (except != NULL && up == except)) {
			/* Found inactive or excluded upstream */
			k = mum_hash_step (k, ups->hash_seed);
		}
		else {
			break;
		}
	}
	RSPAMD_UPSTREAM_UNLOCK (ups);

	if (up->active_idx >= 0) {
		return up;
	}

	/* We failed to find any active upstream */
	up = rspamd_upstream_get_random (ups, except);
	msg_info ("failed to find hashed upstream for %s, fallback to random: %s",
			ups->ups_line, up->name);

	return up;
}

static struct upstream*
rspamd_upstream_get_common (struct upstream_list *ups,
							struct upstream* except,
							enum rspamd_upstream_rotation default_type,
							const guchar *key, gsize keylen,
							gboolean forced)
{
	enum rspamd_upstream_rotation type;
	struct upstream *up = NULL;

	RSPAMD_UPSTREAM_LOCK (ups);
	if (ups->alive->len == 0) {
		/* We have no upstreams alive */
		msg_warn ("there are no alive upstreams left for %s, revive all of them",
				ups->ups_line);
		g_ptr_array_foreach (ups->ups, rspamd_upstream_restore_cb, ups);
	}
	RSPAMD_UPSTREAM_UNLOCK (ups);

	if (ups->alive->len == 1 && default_type != RSPAMD_UPSTREAM_SEQUENTIAL) {
		/* Fast path */
		up =  g_ptr_array_index (ups->alive, 0);
		goto end;
	}

	if (!forced) {
		type = ups->rot_alg != RSPAMD_UPSTREAM_UNDEF ? ups->rot_alg : default_type;
	}
	else {
		type = default_type != RSPAMD_UPSTREAM_UNDEF ? default_type : ups->rot_alg;
	}

	if (type == RSPAMD_UPSTREAM_HASHED && (keylen == 0 || key == NULL)) {
		/* Cannot use hashed rotation when no key is specified, switch to random */
		type = RSPAMD_UPSTREAM_RANDOM;
	}

	switch (type) {
	default:
	case RSPAMD_UPSTREAM_RANDOM:
		up = rspamd_upstream_get_random (ups, except);
		break;
	case RSPAMD_UPSTREAM_HASHED:
		up = rspamd_upstream_get_hashed (ups, except, key, keylen);
		break;
	case RSPAMD_UPSTREAM_ROUND_ROBIN:
		up = rspamd_upstream_get_round_robin (ups, except, TRUE);
		break;
	case RSPAMD_UPSTREAM_MASTER_SLAVE:
		up = rspamd_upstream_get_round_robin (ups, except, FALSE);
		break;
	case RSPAMD_UPSTREAM_SEQUENTIAL:
		if (ups->cur_elt >= ups->alive->len) {
			ups->cur_elt = 0;
			return NULL;
		}

		up = g_ptr_array_index (ups->alive, ups->cur_elt ++);
		break;
	}

end:
	if (up) {
		up->checked ++;
	}

	return up;
}

struct upstream*
rspamd_upstream_get (struct upstream_list *ups,
		enum rspamd_upstream_rotation default_type,
		const guchar *key, gsize keylen)
{
	return rspamd_upstream_get_common (ups, NULL, default_type, key, keylen, FALSE);
}

struct upstream*
rspamd_upstream_get_forced (struct upstream_list *ups,
		enum rspamd_upstream_rotation forced_type,
		const guchar *key, gsize keylen)
{
	return rspamd_upstream_get_common (ups, NULL, forced_type, key, keylen, TRUE);
}

struct upstream *rspamd_upstream_get_except (struct upstream_list *ups,
											 struct upstream *except,
											 enum rspamd_upstream_rotation default_type,
											 const guchar *key, gsize keylen)
{
	return rspamd_upstream_get_common (ups, except, default_type, key, keylen, FALSE);
}

void
rspamd_upstream_reresolve (struct upstream_ctx *ctx)
{
	GList *cur;
	struct upstream *up;

	cur = ctx->upstreams->head;

	while (cur) {
		up = cur->data;
		REF_RETAIN (up);
		rspamd_upstream_resolve_addrs (up->ls, up);
		REF_RELEASE (up);
		cur = g_list_next (cur);
	}
}

gpointer
rspamd_upstream_set_data (struct upstream *up, gpointer data)
{
	gpointer prev_data = up->data;
	up->data = data;

	return prev_data;
}

gpointer
rspamd_upstream_get_data (struct upstream *up)
{
	return up->data;
}


void
rspamd_upstreams_foreach (struct upstream_list *ups,
		rspamd_upstream_traverse_func cb, void *ud)
{
	struct upstream *up;
	guint i;

	for (i = 0; i < ups->ups->len; i ++) {
		up = g_ptr_array_index (ups->ups, i);

		cb (up, i, ud);
	}
}

void
rspamd_upstreams_set_limits (struct upstream_list *ups,
								  gdouble revive_time,
								  gdouble revive_jitter,
								  gdouble error_time,
								  gdouble dns_timeout,
								  guint max_errors,
								  guint dns_retransmits)
{
	struct upstream_limits *nlimits;
	g_assert (ups != NULL);

	nlimits = rspamd_mempool_alloc (ups->ctx->pool, sizeof (*nlimits));
	memcpy (nlimits, ups->limits, sizeof (*nlimits));

	if (!isnan (revive_time)) {
		nlimits->revive_time = revive_time;
	}

	if (!isnan (revive_jitter)) {
		nlimits->revive_jitter = revive_jitter;
	}

	if (!isnan (error_time)) {
		nlimits->error_time = error_time;
	}

	if (!isnan (dns_timeout)) {
		nlimits->dns_timeout = dns_timeout;
	}

	if (max_errors > 0) {
		nlimits->max_errors = max_errors;
	}

	if (dns_retransmits > 0) {
		nlimits->dns_retransmits = dns_retransmits;
	}

	ups->limits = nlimits;
}

void rspamd_upstreams_add_watch_callback (struct upstream_list *ups,
										  enum rspamd_upstreams_watch_event events,
										  rspamd_upstream_watch_func func,
										  GFreeFunc dtor,
										  gpointer ud)
{
	struct upstream_list_watcher *nw;

	g_assert ((events & RSPAMD_UPSTREAM_WATCH_ALL) != 0);

	nw = g_malloc (sizeof (*nw));
	nw->func = func;
	nw->events_mask = events;
	nw->ud = ud;
	nw->dtor = dtor;

	DL_APPEND (ups->watchers, nw);
}

struct upstream*
rspamd_upstream_ref (struct upstream *up)
{
	REF_RETAIN (up);
	return up;
}

void
rspamd_upstream_unref (struct upstream *up)
{
	REF_RELEASE (up);
}
