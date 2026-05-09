/*
 * Copyright 2024 Vsevolod Stakhov
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
#include "upstream.h"
#include "upstream_internal.h"
#include "ottery.h"
#include "ref.h"
#include "cfg_file.h"
#include "rdns.h"
#include "cryptobox.h"
#include "utlist.h"
#include "contrib/libev/ev.h"
#include "logger.h"
#include "contrib/librdns/rdns.h"

#include <math.h>
#include <netdb.h>


struct upstream_inet_addr_entry {
	rspamd_inet_addr_t *addr;
	unsigned int priority;
	struct upstream_inet_addr_entry *next;
};

struct upstream_addr_elt {
	rspamd_inet_addr_t *addr;
	unsigned int priority;
	unsigned int errors;
};

struct upstream_list_watcher {
	rspamd_upstream_watch_func func;
	GFreeFunc dtor;
	gpointer ud;
	enum rspamd_upstreams_watch_event events_mask;
	struct upstream_list_watcher *next, *prev;
};

/* Ring hash point for consistent hashing (Ketama) */
struct upstream_ring_point {
	uint64_t hash;
	struct upstream *up;
};

struct upstream {
	unsigned int weight;
	unsigned int cur_weight;
	unsigned int errors;
	unsigned int checked;
	unsigned int dns_requests;
	/*
	 * Passive in-flight counter: incremented on every selection via
	 * rspamd_upstream_get_common, decremented in rspamd_upstream_ok /
	 * rspamd_upstream_fail. Used by P2C as the load comparator.
	 */
	unsigned int inflight;
	int active_idx;
	unsigned int ttl;
	char *name;
	ev_timer ev;
	double last_fail;
	double last_resolve;
	/* Probe/half-open state */
	double next_probe_at;
	double probe_backoff;
	unsigned int half_open_inflight;
	/*
	 * Wall time (ev_now/ticks) of the most recent revive. Zero when the
	 * upstream is in steady state. While non-zero and within the configured
	 * slow_start window, selection scales the upstream's effective weight
	 * up linearly from 0 to 1.
	 */
	double revived_at;

	/*
	 * Latency EWMA in seconds. Zero when no samples have been recorded.
	 * Updated by rspamd_upstream_record_latency with time-weighted decay
	 * controlled by upstream_limits.latency_half_life_s.
	 */
	double latency_ewma;
	double latency_last_at;
	unsigned int latency_n;
	gpointer ud;
	enum rspamd_upstream_flag flags;
	struct upstream_list *ls;
	GList *ctx_pos;
	struct upstream_ctx *ctx;

	struct {
		GPtrArray *addr; /* struct upstream_addr_elt */
		unsigned int cur;
	} addrs;

	struct upstream_inet_addr_entry *new_addrs;
	gpointer data;
	char uid[8];
	/*
	 * Port to apply to addresses returned by the first DNS resolution when
	 * the upstream was created in PENDING_RESOLVE state (no initial addrs
	 * to copy the port from). Zero otherwise.
	 */
	uint16_t deferred_port;
	ref_entry_t ref;

	/* Token bucket fields for weighted load balancing */
	gsize max_tokens;       /* Maximum token capacity */
	gsize available_tokens; /* Current available tokens */
	gsize inflight_tokens;  /* Tokens reserved by in-flight requests */
	double last_refill_at;  /* Last lazy-refill timestamp (ev_now/ticks); 0 = uninit */

	/*
	 * SRV-derived member fields. Set on members (FLAG_SRV_MEMBER); zero
	 * on non-SRV upstreams and on SRV parents. srv_priority and srv_weight
	 * mirror RFC 2782 fields from the originating SRV reply entry; they
	 * survive re-resolves until the corresponding target disappears.
	 * srv_parent is a weak back-pointer used to remove the member from the
	 * parent's hash table during drain. It does not hold a ref on the
	 * parent.
	 */
	struct upstream *srv_parent;
	unsigned int srv_priority;
	unsigned int srv_weight;

	/*
	 * Owned by SRV parents (FLAG_SRV_RESOLVE). Hash table from "fqdn:port"
	 * to struct upstream * (the member). Used by the re-resolve diff path
	 * to identify add/remove/update of members. NULL on members and on
	 * non-SRV upstreams.
	 */
	GHashTable *srv_members;

	/*
	 * Tombstone for graceful drain. Set when a member is removed from the
	 * parent's set (target disappeared from a re-resolve). Once true, the
	 * revive timer must not re-activate the upstream — it should silently
	 * release the timer ref and leave the upstream waiting for inflight
	 * selectors to release their refs, after which the dtor runs.
	 */
	gboolean is_draining;
#ifdef UPSTREAMS_THREAD_SAFE
	rspamd_mutex_t *lock;
#endif
};

struct upstream_limits {
	double revive_time;
	double revive_jitter;
	double error_time;
	double dns_timeout;
	double lazy_resolve_time;
	double resolve_min_interval;
	double probe_max_backoff;
	double probe_jitter;
	unsigned int max_errors;
	unsigned int dns_retransmits;

	/* Token bucket configuration */
	gsize token_bucket_max;          /* Max tokens per upstream (default: 10000) */
	gsize token_bucket_scale;        /* Bytes per token (default: 1024) */
	gsize token_bucket_min;          /* Min tokens for selection (default: 1) */
	gsize token_bucket_base_cost;    /* Base cost per request (default: 10) */
	gsize token_bucket_refill_per_s; /* Lazy refill rate (default: max/60) */

	/*
	 * Slow start window (milliseconds). When non-zero, a freshly revived
	 * upstream's effective weight ramps linearly from 0 to its configured
	 * weight over this window, smoothing the thundering herd that otherwise
	 * lands on the just-revived backend. Default 0 (disabled).
	 */
	unsigned int slow_start_ms;

	/*
	 * Latency EWMA half-life in seconds. Larger = slower to react, smaller
	 * = noisier. Default 60.0. Set to 0 to weight every sample equally
	 * (degrades to a 1/n moving average regardless of inter-arrival time).
	 */
	double latency_half_life_s;
};

struct upstream_list {
	char *ups_line;
	struct upstream_ctx *ctx;
	GPtrArray *ups;
	GPtrArray *alive;
	struct upstream_list_watcher *watchers;
	uint64_t hash_seed;
	const struct upstream_limits *limits;
	enum rspamd_upstream_flag flags;
	unsigned int cur_elt;
	enum rspamd_upstream_rotation rot_alg;

	/* Ring hash for consistent hashing (Ketama) */
	struct upstream_ring_point *ring;
	unsigned int ring_len;
	gboolean ring_dirty;
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
#define RSPAMD_UPSTREAM_LOCK(x) \
	do {                        \
	} while (0)
#define RSPAMD_UPSTREAM_UNLOCK(x) \
	do {                          \
	} while (0)
#else
#define RSPAMD_UPSTREAM_LOCK(x) rspamd_mutex_lock(x->lock)
#define RSPAMD_UPSTREAM_UNLOCK(x) rspamd_mutex_unlock(x->lock)
#endif

#define msg_debug_upstream(...) rspamd_conditional_debug_fast(NULL, NULL,                                        \
															  rspamd_upstream_log_id, "upstream", upstream->uid, \
															  G_STRFUNC,                                         \
															  __VA_ARGS__)
#define msg_info_upstream(...) rspamd_default_log_function(G_LOG_LEVEL_INFO,          \
														   "upstream", upstream->uid, \
														   G_STRFUNC,                 \
														   __VA_ARGS__)
#define msg_err_upstream(...) rspamd_default_log_function(G_LOG_LEVEL_INFO,          \
														  "upstream", upstream->uid, \
														  G_STRFUNC,                 \
														  __VA_ARGS__)

INIT_LOG_MODULE(upstream)

/* 4 errors in 10 seconds */
#define DEFAULT_MAX_ERRORS 4
static const unsigned int default_max_errors = DEFAULT_MAX_ERRORS;
#define DEFAULT_REVIVE_TIME 60
static const double default_revive_time = DEFAULT_REVIVE_TIME;
#define DEFAULT_REVIVE_JITTER 0.4
static const double default_revive_jitter = DEFAULT_REVIVE_JITTER;
#define DEFAULT_ERROR_TIME 10
static const double default_error_time = DEFAULT_ERROR_TIME;
#define DEFAULT_DNS_TIMEOUT 1.0
static const double default_dns_timeout = DEFAULT_DNS_TIMEOUT;
#define DEFAULT_DNS_RETRANSMITS 2
static const unsigned int default_dns_retransmits = DEFAULT_DNS_RETRANSMITS;
#define DEFAULT_LAZY_RESOLVE_TIME 3600.0
static const double default_lazy_resolve_time = DEFAULT_LAZY_RESOLVE_TIME;
#define DEFAULT_RESOLVE_MIN_INTERVAL 60.0
static const double default_resolve_min_interval = DEFAULT_RESOLVE_MIN_INTERVAL;
#define DEFAULT_PROBE_MAX_BACKOFF 600.0
static const double default_probe_max_backoff = DEFAULT_PROBE_MAX_BACKOFF;
#define DEFAULT_PROBE_JITTER 0.3
static const double default_probe_jitter = DEFAULT_PROBE_JITTER;

/* Token bucket defaults */
#define DEFAULT_TOKEN_BUCKET_MAX 10000
#define DEFAULT_TOKEN_BUCKET_SCALE 1024
#define DEFAULT_TOKEN_BUCKET_MIN 1
#define DEFAULT_TOKEN_BUCKET_BASE_COST 10
/* Default refill rate: full bucket regenerates in 60s of wall time. */
#define DEFAULT_TOKEN_BUCKET_REFILL_PER_S (DEFAULT_TOKEN_BUCKET_MAX / 60)
/* EWMA half-life: stale samples lose half their weight every 60s. */
#define DEFAULT_LATENCY_HALF_LIFE_S 60.0

/*
 * Initial delay before retrying DNS for a PENDING_RESOLVE upstream, and the
 * cap for the exponential back-off used while the upstream stays pending.
 */
#define UPSTREAM_PENDING_RESOLVE_INITIAL_DELAY 1.0
#define UPSTREAM_PENDING_RESOLVE_MAX_DELAY 60.0

static const struct upstream_limits default_limits = {
	.revive_time = DEFAULT_REVIVE_TIME,
	.revive_jitter = DEFAULT_REVIVE_JITTER,
	.error_time = DEFAULT_ERROR_TIME,
	.dns_timeout = DEFAULT_DNS_TIMEOUT,
	.dns_retransmits = DEFAULT_DNS_RETRANSMITS,
	.max_errors = DEFAULT_MAX_ERRORS,
	.lazy_resolve_time = DEFAULT_LAZY_RESOLVE_TIME,
	.resolve_min_interval = DEFAULT_RESOLVE_MIN_INTERVAL,
	.probe_max_backoff = DEFAULT_PROBE_MAX_BACKOFF,
	.probe_jitter = DEFAULT_PROBE_JITTER,
	.token_bucket_max = DEFAULT_TOKEN_BUCKET_MAX,
	.token_bucket_scale = DEFAULT_TOKEN_BUCKET_SCALE,
	.token_bucket_min = DEFAULT_TOKEN_BUCKET_MIN,
	.token_bucket_base_cost = DEFAULT_TOKEN_BUCKET_BASE_COST,
	.token_bucket_refill_per_s = DEFAULT_TOKEN_BUCKET_REFILL_PER_S,
	.latency_half_life_s = DEFAULT_LATENCY_HALF_LIFE_S,
};

static void rspamd_upstream_lazy_resolve_cb(struct ev_loop *, ev_timer *, int);
static void rspamd_upstream_revive_cb(struct ev_loop *loop, ev_timer *w, int revents);
static void rspamd_upstream_dtor(struct upstream *up);
static void rspamd_upstream_resolve_addrs(const struct upstream_list *ls,
										  struct upstream *upstream);
static void rspamd_upstream_set_inactive(struct upstream_list *ls,
										 struct upstream *upstream);

void rspamd_upstreams_library_config(struct rspamd_config *cfg,
									 struct upstream_ctx *ctx,
									 struct ev_loop *event_loop,
									 struct rdns_resolver *resolver)
{
	g_assert(ctx != NULL);
	g_assert(cfg != NULL);

	if (cfg->upstream_error_time) {
		ctx->limits.error_time = cfg->upstream_error_time;
	}
	if (cfg->upstream_max_errors) {
		ctx->limits.max_errors = cfg->upstream_max_errors;
	}
	if (cfg->upstream_revive_time) {
		ctx->limits.revive_time = cfg->upstream_revive_time;
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
	if (cfg->upstream_resolve_min_interval) {
		ctx->limits.resolve_min_interval = cfg->upstream_resolve_min_interval;
	}
	if (cfg->upstream_probe_max_backoff) {
		ctx->limits.probe_max_backoff = cfg->upstream_probe_max_backoff;
	}
	if (cfg->upstream_probe_jitter) {
		ctx->limits.probe_jitter = cfg->upstream_probe_jitter;
	}

	/* Some sanity checks */
	if (ctx->limits.resolve_min_interval > ctx->limits.revive_time) {
		/* We must be able to resolve host during the revive time */
		ctx->limits.resolve_min_interval = ctx->limits.revive_time;
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
			if (!ev_can_stop(&upstream->ev) && upstream->ls &&
				!((upstream->flags & RSPAMD_UPSTREAM_FLAG_NORESOLVE) ||
				  (upstream->flags & RSPAMD_UPSTREAM_FLAG_DNS))) {
				double when;

				if (upstream->flags & RSPAMD_UPSTREAM_FLAG_SRV_RESOLVE) {
					/* Resolve them immediately ! */
					when = 0.0;
				}
				else if (upstream->flags & RSPAMD_UPSTREAM_FLAG_PENDING_RESOLVE) {
					when = rspamd_time_jitter(UPSTREAM_PENDING_RESOLVE_INITIAL_DELAY,
											  UPSTREAM_PENDING_RESOLVE_INITIAL_DELAY * .25);
				}
				else {
					when = rspamd_time_jitter(upstream->ls->limits->lazy_resolve_time,
											  upstream->ls->limits->lazy_resolve_time * .1);
				}

				ev_timer_init(&upstream->ev, rspamd_upstream_lazy_resolve_cb,
							  when, 0);
				upstream->ev.data = upstream;
				ev_timer_start(ctx->event_loop, &upstream->ev);
			}

			cur = g_list_next(cur);
		}
	}
}

static void
rspamd_upstream_ctx_dtor(struct upstream_ctx *ctx)
{
	GList *cur;
	struct upstream *u;

	cur = ctx->upstreams->head;

	while (cur) {
		u = cur->data;
		u->ctx = NULL;
		u->ctx_pos = NULL;
		cur = g_list_next(cur);
	}

	g_queue_free(ctx->upstreams);
	rspamd_mempool_delete(ctx->pool);
	g_free(ctx);
}

void rspamd_upstreams_library_unref(struct upstream_ctx *ctx)
{
	REF_RELEASE(ctx);
}

struct upstream_ctx *
rspamd_upstreams_library_init(void)
{
	struct upstream_ctx *ctx;

	ctx = g_malloc0(sizeof(*ctx));
	memcpy(&ctx->limits, &default_limits, sizeof(ctx->limits));
	ctx->pool = rspamd_mempool_new_long_lived(rspamd_mempool_suggest_size(),
											  "upstreams");

	ctx->upstreams = g_queue_new();
	REF_INIT_RETAIN(ctx, rspamd_upstream_ctx_dtor);

	return ctx;
}

static int
rspamd_upstream_af_to_weight(const rspamd_inet_addr_t *addr)
{
	int ret;

	switch (rspamd_inet_address_get_af(addr)) {
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
static int
rspamd_upstream_addr_sort_func(gconstpointer a, gconstpointer b)
{
	const struct upstream_addr_elt *ip1 = *(const struct upstream_addr_elt **) a,
								   *ip2 = *(const struct upstream_addr_elt **) b;
	int w1, w2;

	if (ip1->priority == 0 && ip2->priority == 0) {
		w1 = rspamd_upstream_af_to_weight(ip1->addr);
		w2 = rspamd_upstream_af_to_weight(ip2->addr);
	}
	else {
		w1 = ip1->priority;
		w2 = ip2->priority;
	}

	/* Inverse order */
	return w2 - w1;
}

static void
rspamd_upstream_set_active(struct upstream_list *ls, struct upstream *upstream)
{
	gboolean is_pending = FALSE;

	RSPAMD_UPSTREAM_LOCK(ls);

	/*
	 * SRV parents are placeholders that own member upstreams; they must
	 * never become selectable. Skip the alive-list bookkeeping but keep
	 * the lazy-resolve timer setup below — that timer is what drives the
	 * periodic SRV re-resolution.
	 */
	if (upstream->flags & RSPAMD_UPSTREAM_FLAG_SRV_RESOLVE) {
		upstream->active_idx = -1;
		goto schedule_resolve;
	}

	is_pending = (upstream->flags & RSPAMD_UPSTREAM_FLAG_PENDING_RESOLVE) != 0;

	if (!is_pending) {
		g_ptr_array_add(ls->alive, upstream);
		upstream->active_idx = ls->alive->len - 1;

		/* Invalidate ring hash */
		ls->ring_dirty = TRUE;

		/* Initialize token bucket state */
		if (ls->rot_alg == RSPAMD_UPSTREAM_TOKEN_BUCKET) {
			upstream->max_tokens = ls->limits->token_bucket_max;
			upstream->available_tokens = upstream->max_tokens;
			upstream->inflight_tokens = 0;
		}
	}
	else {
		upstream->active_idx = -1;
	}

schedule_resolve:
	if (upstream->ctx && upstream->ctx->configured &&
		!((upstream->flags & RSPAMD_UPSTREAM_FLAG_NORESOLVE) ||
		  (upstream->flags & RSPAMD_UPSTREAM_FLAG_DNS))) {

		/*
		 * Snapshot any backoff state already accumulated by lazy_resolve_cb
		 * before we stop the timer, so we can preserve it for pending
		 * upstreams that aren't yet resolved.
		 */
		double prev_repeat = ev_can_stop(&upstream->ev) ? upstream->ev.repeat : 0.0;

		if (ev_can_stop(&upstream->ev)) {
			ev_timer_stop(upstream->ctx->event_loop, &upstream->ev);
		}

		/* Start lazy (or not so lazy) names resolution */
		double when;

		if (upstream->flags & RSPAMD_UPSTREAM_FLAG_SRV_RESOLVE) {
			/* Resolve them immediately ! */
			when = 0.0;
		}
		else if (is_pending) {
			/*
			 * Keep the backoff already grown by repeated lazy_resolve_cb
			 * runs; falling back to the initial delay would mask repeated
			 * DNS failure with optimistic 1s retries.
			 */
			if (prev_repeat >= UPSTREAM_PENDING_RESOLVE_INITIAL_DELAY) {
				when = prev_repeat;
			}
			else {
				when = rspamd_time_jitter(UPSTREAM_PENDING_RESOLVE_INITIAL_DELAY,
										  UPSTREAM_PENDING_RESOLVE_INITIAL_DELAY * .25);
			}
		}
		else {
			when = rspamd_time_jitter(upstream->ls->limits->lazy_resolve_time,
									  upstream->ls->limits->lazy_resolve_time * .1);
		}
		ev_timer_init(&upstream->ev, rspamd_upstream_lazy_resolve_cb,
					  when, 0);
		upstream->ev.data = upstream;
		msg_debug_upstream("start %s resolving for %s in %.0f seconds",
						   is_pending ? "deferred" : "lazy",
						   upstream->name, when);
		ev_timer_start(upstream->ctx->event_loop, &upstream->ev);
	}

	RSPAMD_UPSTREAM_UNLOCK(ls);
}

static void
rspamd_upstream_addr_elt_dtor(gpointer a)
{
	struct upstream_addr_elt *elt = a;

	if (elt) {
		rspamd_inet_address_free(elt->addr);
		g_free(elt);
	}
}

/* Forward decl: defined a few lines below */
static void rspamd_upstream_promote_pending(struct upstream *upstream);

static void
rspamd_upstream_update_addrs(struct upstream *upstream)
{
	unsigned int addr_cnt, i, port;
	gboolean seen_addr, reset_errors = FALSE, was_pending = FALSE;
	struct upstream_inet_addr_entry *cur, *tmp;
	GPtrArray *new_addrs;
	struct upstream_addr_elt *addr_elt, *naddr;

	/*
	 * We need first of all get the saved port, since DNS gives us no
	 * idea about what port has been used previously. For PENDING_RESOLVE
	 * upstreams there is no prior address: use the port stashed at parse
	 * time on `upstream->deferred_port`.
	 */
	RSPAMD_UPSTREAM_LOCK(upstream);

	if (upstream->new_addrs &&
		(upstream->addrs.addr == NULL || upstream->addrs.addr->len == 0)) {
		was_pending = (upstream->flags & RSPAMD_UPSTREAM_FLAG_PENDING_RESOLVE) != 0;
		port = upstream->deferred_port;
	}
	else if (upstream->addrs.addr && upstream->addrs.addr->len > 0 &&
			 upstream->new_addrs) {
		addr_elt = g_ptr_array_index(upstream->addrs.addr, 0);
		port = rspamd_inet_address_get_port(addr_elt->addr);
	}
	else {
		port = 0;
	}

	if (upstream->new_addrs) {
		/* Now calculate new addrs count */
		addr_cnt = 0;
		LL_FOREACH(upstream->new_addrs, cur)
		{
			addr_cnt++;
		}

		/* At 10% probability reset errors on addr elements */
		if (rspamd_random_double_fast() > 0.9) {
			reset_errors = TRUE;
			msg_debug_upstream("reset errors on upstream %s",
							   upstream->name);
		}

		new_addrs = g_ptr_array_new_full(addr_cnt, rspamd_upstream_addr_elt_dtor);

		/* Copy addrs back */
		LL_FOREACH(upstream->new_addrs, cur)
		{
			seen_addr = FALSE;
			naddr = NULL;
			/* Ports are problematic, set to compare in the next block */
			rspamd_inet_address_set_port(cur->addr, port);

			if (upstream->addrs.addr) {
				PTR_ARRAY_FOREACH(upstream->addrs.addr, i, addr_elt)
				{
					if (rspamd_inet_address_compare(addr_elt->addr, cur->addr, FALSE) == 0) {
						naddr = g_malloc0(sizeof(*naddr));
						naddr->addr = cur->addr;
						naddr->errors = reset_errors ? 0 : addr_elt->errors;
						seen_addr = TRUE;

						break;
					}
				}
			}

			if (!seen_addr) {
				naddr = g_malloc0(sizeof(*naddr));
				naddr->addr = cur->addr;
				naddr->errors = 0;
				msg_debug_upstream("new address for %s: %s",
								   upstream->name,
								   rspamd_inet_address_to_string_pretty(naddr->addr));
			}
			else {
				msg_debug_upstream("existing address for %s: %s",
								   upstream->name,
								   rspamd_inet_address_to_string_pretty(cur->addr));
			}

			g_ptr_array_add(new_addrs, naddr);
		}

		/* Free old addresses */
		if (upstream->addrs.addr) {
			g_ptr_array_free(upstream->addrs.addr, TRUE);
		}

		upstream->addrs.cur = 0;
		upstream->addrs.addr = new_addrs;
		g_ptr_array_sort(upstream->addrs.addr, rspamd_upstream_addr_sort_func);
	}

	LL_FOREACH_SAFE(upstream->new_addrs, cur, tmp)
	{
		/* Do not free inet address pointer since it has been transferred to up */
		g_free(cur);
	}

	upstream->new_addrs = NULL;
	RSPAMD_UPSTREAM_UNLOCK(upstream);

	if (was_pending && upstream->addrs.addr && upstream->addrs.addr->len > 0) {
		rspamd_upstream_promote_pending(upstream);
	}
}

/*
 * Move a previously PENDING_RESOLVE upstream into the alive list now that
 * addresses have been resolved. Mirrors the alive-side bookkeeping of
 * rspamd_upstream_set_active without re-entering the resolution-scheduling
 * branch (the lazy-resolve timer is already running).
 */
static void
rspamd_upstream_promote_pending(struct upstream *upstream)
{
	struct upstream_list *ls = upstream->ls;
	struct upstream_list_watcher *w;

	if (ls == NULL || upstream->is_draining) {
		return;
	}

	RSPAMD_UPSTREAM_LOCK(ls);

	if (!(upstream->flags & RSPAMD_UPSTREAM_FLAG_PENDING_RESOLVE)) {
		RSPAMD_UPSTREAM_UNLOCK(ls);
		return;
	}

	upstream->flags &= ~RSPAMD_UPSTREAM_FLAG_PENDING_RESOLVE;

	g_ptr_array_add(ls->alive, upstream);
	upstream->active_idx = ls->alive->len - 1;
	ls->ring_dirty = TRUE;

	if (ls->rot_alg == RSPAMD_UPSTREAM_TOKEN_BUCKET) {
		upstream->max_tokens = ls->limits->token_bucket_max;
		upstream->available_tokens = upstream->max_tokens;
		upstream->inflight_tokens = 0;
	}

	msg_info_upstream("resolved deferred upstream %s; promoted to alive",
					  upstream->name);

	DL_FOREACH(ls->watchers, w)
	{
		if (w->events_mask & RSPAMD_UPSTREAM_WATCH_ONLINE) {
			w->func(upstream, RSPAMD_UPSTREAM_WATCH_ONLINE, upstream->errors,
					w->ud);
		}
	}

	RSPAMD_UPSTREAM_UNLOCK(ls);
}

static void
rspamd_upstream_dns_cb(struct rdns_reply *reply, void *arg)
{
	struct upstream *up = (struct upstream *) arg;
	struct rdns_reply_entry *entry;
	struct upstream_inet_addr_entry *up_ent;

	if (reply->code == RDNS_RC_NOERROR) {
		entry = reply->entries;

		RSPAMD_UPSTREAM_LOCK(up);
		while (entry) {

			if (entry->type == RDNS_REQUEST_A) {
				up_ent = g_malloc0(sizeof(*up_ent));
				up_ent->addr = rspamd_inet_address_new(AF_INET,
													   &entry->content.a.addr);
				LL_PREPEND(up->new_addrs, up_ent);
			}
			else if (entry->type == RDNS_REQUEST_AAAA) {
				up_ent = g_malloc0(sizeof(*up_ent));
				up_ent->addr = rspamd_inet_address_new(AF_INET6,
													   &entry->content.aaa.addr);
				LL_PREPEND(up->new_addrs, up_ent);
			}
			entry = entry->next;
		}

		RSPAMD_UPSTREAM_UNLOCK(up);
	}

	up->dns_requests--;

	if (up->dns_requests == 0) {
		rspamd_upstream_update_addrs(up);
	}

	REF_RELEASE(up);
}

/*
 * Build a stable "fqdn:port" key for indexing SRV members on the parent.
 * Allocated with g_malloc; the parent's hash table owns the string and
 * frees it via the value-destroy callback registered at hash creation.
 */
static char *
rspamd_upstream_srv_member_key(const char *target, uint16_t port)
{
	return g_strdup_printf("%s:%u", target, (unsigned int) port);
}

/*
 * Create a brand-new SRV member upstream, register it with the parent,
 * push it into the upstream list and ctx queue, and kick off A/AAAA
 * resolution. The member starts in PENDING_RESOLVE state and becomes
 * selectable only after rspamd_upstream_promote_pending fires from
 * rspamd_upstream_update_addrs once a non-empty A/AAAA reply arrives.
 *
 * Caller holds parent's lock. ls and ctx must be non-NULL (i.e. parent
 * is still attached to a live list).
 */
static struct upstream *
rspamd_upstream_srv_create_member(struct upstream *parent,
								  const char *target,
								  uint16_t port,
								  uint16_t srv_weight,
								  uint16_t srv_priority)
{
	struct upstream_list *ls = parent->ls;
	struct upstream_ctx *ctx = parent->ctx;
	struct upstream *member;
	rspamd_mempool_t *pool = ctx ? ctx->pool : NULL;
	unsigned int h;
	char *key;

	g_assert(ls != NULL);
	g_assert(ctx != NULL);

	member = g_malloc0(sizeof(*member));
	member->name = pool ? rspamd_mempool_strdup(pool, target) : g_strdup(target);
	member->srv_parent = parent;
	member->srv_priority = srv_priority;
	member->srv_weight = srv_weight;
	/*
	 * RFC 2782 weight 0 means "rarely used but selectable". We clamp to >=1
	 * so the existing weighted-RR path doesn't treat the member as
	 * effectively disabled. True weight-0 semantics are a follow-up.
	 */
	member->weight = MAX((unsigned int) srv_weight, 1u);
	member->cur_weight = member->weight;
	member->deferred_port = port;
	member->active_idx = -1;
	/*
	 * Members inherit the list-level flags applied to the parent at
	 * creation time but never carry the SRV_RESOLVE marker themselves —
	 * that flag is the parent placeholder's identifying mark.
	 */
	member->flags = (parent->flags & ~RSPAMD_UPSTREAM_FLAG_SRV_RESOLVE) |
					RSPAMD_UPSTREAM_FLAG_SRV_MEMBER |
					RSPAMD_UPSTREAM_FLAG_PENDING_RESOLVE;

	g_ptr_array_add(ls->ups, member);
	member->ud = parent->ud;
	member->ls = ls;
	REF_INIT_RETAIN(member, rspamd_upstream_dtor);
#ifdef UPSTREAMS_THREAD_SAFE
	member->lock = rspamd_mutex_new();
#endif
	member->ctx = ctx;
	REF_RETAIN(ctx);
	g_queue_push_tail(ctx->upstreams, member);
	member->ctx_pos = g_queue_peek_tail_link(ctx->upstreams);

	h = rspamd_cryptobox_fast_hash(member->name, strlen(member->name), 0);
	memset(member->uid, 0, sizeof(member->uid));
	rspamd_encode_base32_buf((const unsigned char *) &h, sizeof(h),
							 member->uid, sizeof(member->uid) - 1,
							 RSPAMD_BASE32_DEFAULT);

	key = rspamd_upstream_srv_member_key(target, port);
	g_hash_table_insert(parent->srv_members, key, member);

	{
		struct upstream *upstream = member;
		msg_info_upstream("created SRV member %s for %s "
						  "(target=%s port=%ud weight=%ud priority=%ud)",
						  member->uid, parent->name, target,
						  (unsigned int) port,
						  (unsigned int) srv_weight,
						  (unsigned int) srv_priority);
	}

	/*
	 * set_active arms the lazy-resolve timer; for PENDING_RESOLVE members
	 * it leaves them out of `alive`. The first successful A/AAAA reply
	 * promotes the member via rspamd_upstream_promote_pending.
	 */
	rspamd_upstream_set_active(ls, member);
	/*
	 * Issue the A/AAAA query immediately rather than waiting for the lazy
	 * timer; users expect new SRV targets to start serving traffic
	 * promptly after a re-resolve.
	 */
	rspamd_upstream_resolve_addrs(ls, member);

	return member;
}

/*
 * Graceful drain: remove a member from selection, unlink it from the
 * parent's hash, drop its presence in `ls->ups`. The set_inactive call
 * keeps the upstream pinned in memory until its revive timer fires —
 * by that point any in-flight selectors will have called fail/ok/release
 * and the dtor can run safely.
 *
 * The is_draining flag tells revive_cb to skip set_active when the
 * timer fires, so the drained member stays out of selection forever.
 */
static void
rspamd_upstream_srv_drain_member(struct upstream *member)
{
	struct upstream *parent = member->srv_parent;
	struct upstream_list *ls = member->ls;
	struct upstream *upstream = member; /* for the logging macro */

	if (!(member->flags & RSPAMD_UPSTREAM_FLAG_SRV_MEMBER)) {
		return;
	}

	msg_info_upstream("drain SRV member %s (%s)",
					  member->uid, member->name);

	member->is_draining = TRUE;

	/* Stop any timer that might re-activate the member. */
	if (member->ctx && member->ctx->event_loop && ev_can_stop(&member->ev)) {
		ev_timer_stop(member->ctx->event_loop, &member->ev);
	}

	/* Unlink from the parent's index. */
	if (parent && parent->srv_members) {
		GHashTableIter it;
		gpointer k, v;

		g_hash_table_iter_init(&it, parent->srv_members);
		while (g_hash_table_iter_next(&it, &k, &v)) {
			if (v == member) {
				g_hash_table_iter_remove(&it);
				break;
			}
		}
	}

	/*
	 * Pull from the alive list directly, mirroring the relevant subset
	 * of set_inactive. We deliberately do NOT go through set_inactive
	 * itself: it pins the upstream with REF_RETAIN+revive timer
	 * expecting the timer to release later, but for a drained member
	 * there is no "later" — we want the dtor to run as soon as inflight
	 * selectors release their refs.
	 */
	if (ls != NULL && member->active_idx != -1) {
		struct upstream_list_watcher *w;

		RSPAMD_UPSTREAM_LOCK(ls);
		g_ptr_array_remove_index(ls->alive, member->active_idx);
		member->active_idx = -1;
		ls->ring_dirty = TRUE;

		if (ls->rot_alg == RSPAMD_UPSTREAM_TOKEN_BUCKET &&
			member->inflight_tokens > 0) {
			member->available_tokens += member->inflight_tokens;
			if (member->available_tokens > member->max_tokens) {
				member->available_tokens = member->max_tokens;
			}
			member->inflight_tokens = 0;
		}

		/* Reindex */
		for (unsigned int i = 0; i < ls->alive->len; i++) {
			struct upstream *cur = g_ptr_array_index(ls->alive, i);
			cur->active_idx = i;
		}

		DL_FOREACH(ls->watchers, w)
		{
			if (w->events_mask & RSPAMD_UPSTREAM_WATCH_OFFLINE) {
				w->func(member, RSPAMD_UPSTREAM_WATCH_OFFLINE,
						member->errors, w->ud);
			}
		}

		RSPAMD_UPSTREAM_UNLOCK(ls);
	}

	/* Remove from ls->ups so traversal/probe paths stop seeing it. */
	if (ls != NULL) {
		for (unsigned int i = 0; i < ls->ups->len; i++) {
			if (g_ptr_array_index(ls->ups, i) == member) {
				g_ptr_array_remove_index(ls->ups, i);
				break;
			}
		}
	}

	/* Sever the parent link so the dtor doesn't re-touch parent state. */
	member->srv_parent = NULL;

	/*
	 * Production grace window: a caller may have just received this
	 * member from rspamd_upstream_get_* and not yet called fail/ok.
	 * Arm a one-shot timer (reusing revive_cb, which checks is_draining
	 * and bails to REF_RELEASE on fire) to keep the upstream alive long
	 * enough for inflight selectors to drain naturally. We use
	 * revive_time as the grace period — same TTL the rest of the system
	 * already assumes for inactive upstreams.
	 *
	 * Without an event loop (tests, early startup), no inflight is
	 * possible; we skip the timer and let REF_RELEASE below run the
	 * dtor synchronously.
	 */
	if (member->ctx && member->ctx->event_loop && ls != NULL) {
		double ntim = rspamd_time_jitter(ls->limits->revive_time,
										 ls->limits->revive_time *
											 ls->limits->revive_jitter);
		REF_RETAIN(member);
		ev_timer_init(&member->ev, rspamd_upstream_revive_cb, ntim, 0);
		member->ev.data = member;
		if (member->ctx->configured) {
			ev_timer_start(member->ctx->event_loop, &member->ev);
		}
	}

	/* Release the original creation ref. */
	REF_RELEASE(member);
}

/*
 * Apply a snapshot of SRV targets to a parent. Public-internal entry
 * point: takes a plain-data array decoupled from the DNS client struct
 * layout, so tests can drive expansion without DNS.
 *
 * Caller must ensure parent has srv_members allocated (true for any
 * upstream created via "service=..."). Acquires/releases the parent
 * lock internally.
 */
void rspamd_upstream_srv_apply(struct upstream *parent,
							   const struct rspamd_upstream_srv_entry *entries,
							   size_t n)
{
	GHashTable *seen;
	GList *to_drain = NULL, *cur;
	GHashTableIter iter;
	gpointer k, v;
	size_t i;
	struct upstream *upstream = parent; /* for the logging macro */

	if (parent == NULL || parent->srv_members == NULL) {
		return;
	}

	RSPAMD_UPSTREAM_LOCK(parent);

	seen = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

	for (i = 0; i < n; i++) {
		const struct rspamd_upstream_srv_entry *e = &entries[i];
		struct upstream *existing;
		char *key;

		msg_debug_upstream("apply SRV target for %s: %s "
						   "(weight=%ud priority=%ud port=%ud)",
						   parent->name, e->target,
						   (unsigned int) e->weight,
						   (unsigned int) e->priority,
						   (unsigned int) e->port);

		key = rspamd_upstream_srv_member_key(e->target, e->port);
		existing = g_hash_table_lookup(parent->srv_members, key);

		if (existing != NULL) {
			gboolean topology_changed = FALSE;

			if (existing->srv_weight != e->weight) {
				existing->srv_weight = e->weight;
				existing->weight = MAX((unsigned int) e->weight, 1u);
				if (existing->cur_weight == 0) {
					existing->cur_weight = existing->weight;
				}
				topology_changed = TRUE;
			}
			if (existing->srv_priority != e->priority) {
				existing->srv_priority = e->priority;
				topology_changed = TRUE;
			}
			if (topology_changed && parent->ls != NULL) {
				parent->ls->ring_dirty = TRUE;
			}
			/* Refresh A/AAAA so address changes propagate. */
			if (parent->ls != NULL) {
				rspamd_upstream_resolve_addrs(parent->ls, existing);
			}
		}
		else {
			rspamd_upstream_srv_create_member(parent, e->target, e->port,
											  e->weight, e->priority);
		}

		g_hash_table_insert(seen, key, NULL);
	}

	/* Anything in srv_members not in `seen` is gone — drain it. */
	g_hash_table_iter_init(&iter, parent->srv_members);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		if (!g_hash_table_contains(seen, k)) {
			to_drain = g_list_prepend(to_drain, v);
		}
	}

	for (cur = to_drain; cur != NULL; cur = cur->next) {
		rspamd_upstream_srv_drain_member((struct upstream *) cur->data);
	}
	g_list_free(to_drain);
	g_hash_table_unref(seen);

	RSPAMD_UPSTREAM_UNLOCK(parent);
}

struct upstream *
rspamd_upstream_srv_test_get_parent(struct upstream_list *ups)
{
	unsigned int i;

	if (ups == NULL) {
		return NULL;
	}

	for (i = 0; i < ups->ups->len; i++) {
		struct upstream *up = g_ptr_array_index(ups->ups, i);
		if (up->flags & RSPAMD_UPSTREAM_FLAG_SRV_RESOLVE) {
			return up;
		}
	}

	return NULL;
}

void rspamd_upstream_member_force_alive_for_test(struct upstream *member,
												 const char *ip_str)
{
	rspamd_inet_addr_t *addr = NULL;

	g_assert(member != NULL);
	g_assert(member->flags & RSPAMD_UPSTREAM_FLAG_SRV_MEMBER);

	if (!rspamd_parse_inet_address(&addr, ip_str, strlen(ip_str),
								   RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
		g_assert_not_reached();
	}

	rspamd_inet_address_set_port(addr, member->deferred_port);
	rspamd_upstream_add_addr(member, addr);

	/*
	 * Drop the PENDING_RESOLVE flag and place the member into the alive
	 * list directly. set_active would re-arm the lazy-resolve timer; in
	 * tests the runtime has no event loop, so we do the bookkeeping by
	 * hand to keep the test deterministic.
	 */
	RSPAMD_UPSTREAM_LOCK(member->ls);
	member->flags &= ~RSPAMD_UPSTREAM_FLAG_PENDING_RESOLVE;
	g_ptr_array_add(member->ls->alive, member);
	member->active_idx = member->ls->alive->len - 1;
	member->ls->ring_dirty = TRUE;
	RSPAMD_UPSTREAM_UNLOCK(member->ls);
}

/*
 * SRV reply handler: convert the rdns reply into the plain-data entry
 * vector and hand it to rspamd_upstream_srv_apply. Each SRV target lives
 * as its own struct upstream — own error budget, latency EWMA,
 * addresses, and full first-class participation in every selection
 * algorithm.
 *
 * On reply errors (NXDOMAIN, timeout) we deliberately do nothing: the
 * existing member set remains in place and the next re-resolve gets to
 * try again. Otherwise one bad query would tear down the whole cluster.
 */
static void
rspamd_upstream_dns_srv_cb(struct rdns_reply *reply, void *arg)
{
	struct upstream *parent = (struct upstream *) arg;
	struct upstream *upstream = parent; /* for the logging macro */
	struct rdns_reply_entry *entry;

	if (parent->ls == NULL || parent->is_draining) {
		/* Parent destroyed or drained mid-flight; just release the ref. */
		parent->dns_requests--;
		REF_RELEASE(parent);
		return;
	}

	if (reply->code == RDNS_RC_NOERROR) {
		GArray *flat = g_array_new(FALSE, FALSE,
								   sizeof(struct rspamd_upstream_srv_entry));

		for (entry = reply->entries; entry != NULL; entry = entry->next) {
			if (entry->type != RDNS_REQUEST_SRV) {
				continue;
			}

			parent->ttl = entry->ttl;

			struct rspamd_upstream_srv_entry e = {
				.target = entry->content.srv.target,
				.port = entry->content.srv.port,
				.weight = entry->content.srv.weight,
				.priority = entry->content.srv.priority,
			};
			g_array_append_val(flat, e);
		}

		rspamd_upstream_srv_apply(parent,
								  (const struct rspamd_upstream_srv_entry *) flat->data,
								  flat->len);
		g_array_free(flat, TRUE);
	}
	else {
		msg_info_upstream("SRV resolution for %s returned %s; keeping "
						  "existing %ud member(s)",
						  parent->name, rdns_strerror(reply->code),
						  parent->srv_members ? (unsigned int) g_hash_table_size(parent->srv_members) : 0u);
	}

	parent->dns_requests--;
	REF_RELEASE(parent);
}

static void
rspamd_upstream_revive_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct upstream *upstream = (struct upstream *) w->data;

	RSPAMD_UPSTREAM_LOCK(upstream);
	ev_timer_stop(loop, w);

	/*
	 * Drained SRV members must not re-enter the alive list. The drain
	 * helper unlinks them from `ls->ups` and `srv_members` and flips this
	 * flag; the only thing left is to release the timer ref so the dtor
	 * runs once inflight selectors release theirs.
	 */
	if (upstream->is_draining) {
		msg_debug_upstream("skip revive for drained upstream %s",
						   upstream->name);
		RSPAMD_UPSTREAM_UNLOCK(upstream);
		REF_RELEASE(upstream);
		return;
	}

	msg_debug_upstream("revive upstream %s", upstream->name);

	if (upstream->ls) {
		/* Mark the time so selection paths can apply slow-start ramping. */
		upstream->revived_at = ev_now(loop);
		rspamd_upstream_set_active(upstream->ls, upstream);
	}

	RSPAMD_UPSTREAM_UNLOCK(upstream);
	g_assert(upstream->ref.refcount > 1);
	REF_RELEASE(upstream);
}

static void
rspamd_upstream_resolve_addrs(const struct upstream_list *ls,
							  struct upstream *upstream)
{
	/*
	 * Drained SRV members and SRV parents must never resolve. Parents
	 * resolve SRV through the dedicated path below; the early bail here
	 * matters when set_inactive is invoked on a draining member: it would
	 * otherwise re-issue A/AAAA and pollute the just-released state.
	 */
	if (upstream->is_draining) {
		return;
	}

	if ((upstream->flags & RSPAMD_UPSTREAM_FLAG_DNS)) {
		/* For DNS upstreams: resolve synchronously using getaddrinfo if name */
		if (upstream->name[0] != '/') {
			/* If marked NORESOLVE at init (numeric address), keep old behaviour */
			if (upstream->flags & RSPAMD_UPSTREAM_FLAG_NORESOLVE) {
				return;
			}

			/* Extract host part without port */
			char dns_name[253 + 1];
			const char *semicolon_pos = strchr(upstream->name, ':');

			if (semicolon_pos != NULL && semicolon_pos > upstream->name) {
				if (sizeof(dns_name) > (size_t) (semicolon_pos - upstream->name)) {
					rspamd_strlcpy(dns_name, upstream->name,
								   semicolon_pos - upstream->name + 1);
				}
				else {
					msg_err_upstream("internal error: upstream name is larger than max DNS name: %s",
									 upstream->name);
					rspamd_strlcpy(dns_name, upstream->name, sizeof(dns_name));
				}
			}
			else {
				rspamd_strlcpy(dns_name, upstream->name, sizeof(dns_name));
			}

			/* Use saved port from current address */
			unsigned int port = 0;
			if (upstream->addrs.addr && upstream->addrs.addr->len > 0) {
				struct upstream_addr_elt *addr_elt = g_ptr_array_index(upstream->addrs.addr, 0);
				port = rspamd_inet_address_get_port(addr_elt->addr);
			}

			struct addrinfo hints, *res = NULL, *cur;
			memset(&hints, 0, sizeof(hints));
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_family = AF_UNSPEC;
			hints.ai_flags = AI_NUMERICSERV;

			char portbuf[8];
			if (port == 0) {
				/* Fallback to default 53 if unknown */
				rspamd_strlcpy(portbuf, "53", sizeof(portbuf));
			}
			else {
				rspamd_snprintf(portbuf, sizeof(portbuf), "%ud", port);
			}

			int gr = getaddrinfo(dns_name, portbuf, &hints, &res);
			if (gr == 0 && res != NULL) {
				RSPAMD_UPSTREAM_LOCK(upstream);
				struct upstream_inet_addr_entry *up_ent;
				for (cur = res; cur != NULL; cur = cur->ai_next) {
					rspamd_inet_addr_t *na = rspamd_inet_address_from_sa(cur->ai_addr, cur->ai_addrlen);
					if (na == NULL) {
						continue;
					}
					rspamd_inet_address_set_port(na, port);
					up_ent = g_malloc0(sizeof(*up_ent));
					up_ent->addr = na;
					up_ent->priority = 0;
					LL_PREPEND(upstream->new_addrs, up_ent);
				}
				RSPAMD_UPSTREAM_UNLOCK(upstream);

				freeaddrinfo(res);

				rspamd_upstream_update_addrs(upstream);
			}
		}

		return;
	}

	if (upstream->ctx->res != NULL &&
		upstream->ctx->configured &&
		upstream->dns_requests == 0 &&
		!(upstream->flags & RSPAMD_UPSTREAM_FLAG_NORESOLVE)) {

		double now = ev_now(upstream->ctx->event_loop);

		if (now - upstream->last_resolve < upstream->ctx->limits.resolve_min_interval) {
			msg_info_upstream("do not resolve upstream %s as it was checked %.0f "
							  "seconds ago (%.0f is minimum)",
							  upstream->name, now - upstream->last_resolve,
							  upstream->ctx->limits.resolve_min_interval);

			return;
		}

		/* Resolve name of the upstream one more time */
		if (upstream->name[0] != '/') {
			upstream->last_resolve = now;

			/*
			 * If upstream name has a port, then we definitely need to resolve
			 * merely host part!
			 */
			char dns_name[253 + 1]; /* 253 == max dns name + \0 */
			const char *semicolon_pos = strchr(upstream->name, ':');

			if (semicolon_pos != NULL && semicolon_pos > upstream->name) {
				if (sizeof(dns_name) > semicolon_pos - upstream->name) {
					rspamd_strlcpy(dns_name, upstream->name,
								   semicolon_pos - upstream->name + 1);
				}
				else {
					/* XXX: truncated */
					msg_err_upstream("internal error: upstream name is larger than"
									 "max DNS name: %s",
									 upstream->name);
					rspamd_strlcpy(dns_name, upstream->name, sizeof(dns_name));
				}
			}
			else {
				rspamd_strlcpy(dns_name, upstream->name, sizeof(dns_name));
			}

			if (upstream->flags & RSPAMD_UPSTREAM_FLAG_SRV_RESOLVE) {
				if (rdns_make_request_full(upstream->ctx->res,
										   rspamd_upstream_dns_srv_cb, upstream,
										   ls->limits->dns_timeout, ls->limits->dns_retransmits,
										   1, dns_name, RDNS_REQUEST_SRV) != NULL) {
					upstream->dns_requests++;
					REF_RETAIN(upstream);
				}
			}
			else {
				if (rdns_make_request_full(upstream->ctx->res,
										   rspamd_upstream_dns_cb, upstream,
										   ls->limits->dns_timeout, ls->limits->dns_retransmits,
										   1, dns_name, RDNS_REQUEST_A) != NULL) {
					upstream->dns_requests++;
					REF_RETAIN(upstream);
				}

				if (rdns_make_request_full(upstream->ctx->res,
										   rspamd_upstream_dns_cb, upstream,
										   ls->limits->dns_timeout, ls->limits->dns_retransmits,
										   1, dns_name, RDNS_REQUEST_AAAA) != NULL) {
					upstream->dns_requests++;
					REF_RETAIN(upstream);
				}
			}
		}
	}
	else if (upstream->dns_requests != 0) {
		msg_info_upstream("do not resolve upstream %s as another request for "
						  "resolving has been already issued",
						  upstream->name);
	}
}

static void
rspamd_upstream_lazy_resolve_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct upstream *up = (struct upstream *) w->data;

	RSPAMD_UPSTREAM_LOCK(up);
	ev_timer_stop(loop, w);

	if (up->ls) {
		rspamd_upstream_resolve_addrs(up->ls, up);

		if (up->flags & RSPAMD_UPSTREAM_FLAG_PENDING_RESOLVE) {
			/*
			 * Still no addresses — back off exponentially but cap so we keep
			 * trying every minute or so. Once update_addrs runs successfully
			 * the flag is cleared and the next branch takes over.
			 */
			double next = w->repeat * 2.0;
			if (next < UPSTREAM_PENDING_RESOLVE_INITIAL_DELAY) {
				next = UPSTREAM_PENDING_RESOLVE_INITIAL_DELAY;
			}
			if (next > UPSTREAM_PENDING_RESOLVE_MAX_DELAY) {
				next = UPSTREAM_PENDING_RESOLVE_MAX_DELAY;
			}
			w->repeat = rspamd_time_jitter(next, next * .25);
		}
		else if (up->ttl == 0 || up->ttl > up->ls->limits->lazy_resolve_time) {
			w->repeat = rspamd_time_jitter(up->ls->limits->lazy_resolve_time,
										   up->ls->limits->lazy_resolve_time * .1);
		}
		else {
			w->repeat = up->ttl;
		}

		ev_timer_again(loop, w);
	}

	RSPAMD_UPSTREAM_UNLOCK(up);
}

static void
rspamd_upstream_set_inactive(struct upstream_list *ls, struct upstream *upstream)
{
	double ntim;
	unsigned int i;
	struct upstream *cur;
	struct upstream_list_watcher *w;

	g_assert(upstream != NULL);
	RSPAMD_UPSTREAM_LOCK(ls);
	g_ptr_array_remove_index(ls->alive, upstream->active_idx);
	upstream->active_idx = -1;

	/* Invalidate ring hash */
	ls->ring_dirty = TRUE;

	/*
	 * Restore inflight tokens to available pool when transitioning to
	 * inactive — those requests are abandoned, the tokens should be
	 * available when the upstream comes back.
	 */
	if (ls->rot_alg == RSPAMD_UPSTREAM_TOKEN_BUCKET &&
		upstream->inflight_tokens > 0) {
		RSPAMD_UPSTREAM_LOCK(upstream);
		upstream->available_tokens += upstream->inflight_tokens;
		if (upstream->available_tokens > upstream->max_tokens) {
			upstream->available_tokens = upstream->max_tokens;
		}
		upstream->inflight_tokens = 0;
		RSPAMD_UPSTREAM_UNLOCK(upstream);
	}

	/* We need to update all indices */
	for (i = 0; i < ls->alive->len; i++) {
		cur = g_ptr_array_index(ls->alive, i);
		cur->active_idx = i;
	}

	if (upstream->ctx) {
		rspamd_upstream_resolve_addrs(ls, upstream);

		REF_RETAIN(upstream);
		ntim = rspamd_time_jitter(ls->limits->revive_time,
								  ls->limits->revive_time * ls->limits->revive_jitter);

		if (ev_can_stop(&upstream->ev)) {
			ev_timer_stop(upstream->ctx->event_loop, &upstream->ev);
		}

		msg_debug_upstream("mark upstream %s inactive; revive in %.0f seconds",
						   upstream->name, ntim);
		/* Initialize probe scheduling */
		if (upstream->probe_backoff <= 0) {
			upstream->probe_backoff = ls->limits->revive_time;
		}
		if (upstream->ctx && upstream->ctx->event_loop) {
			upstream->next_probe_at = ev_now(upstream->ctx->event_loop) +
									  rspamd_time_jitter(upstream->probe_backoff,
														 upstream->probe_backoff * ls->limits->probe_jitter);
		}
		else {
			double now = rspamd_get_ticks(FALSE);
			upstream->next_probe_at = now + rspamd_time_jitter(upstream->probe_backoff,
															   upstream->probe_backoff * ls->limits->probe_jitter);
		}
		ev_timer_init(&upstream->ev, rspamd_upstream_revive_cb, ntim, 0);
		upstream->ev.data = upstream;

		if (upstream->ctx->event_loop != NULL && upstream->ctx->configured) {
			ev_timer_start(upstream->ctx->event_loop, &upstream->ev);
		}
	}

	DL_FOREACH(upstream->ls->watchers, w)
	{
		if (w->events_mask & RSPAMD_UPSTREAM_WATCH_OFFLINE) {
			w->func(upstream, RSPAMD_UPSTREAM_WATCH_OFFLINE, upstream->errors, w->ud);
		}
	}

	RSPAMD_UPSTREAM_UNLOCK(ls);
}

void rspamd_upstream_fail(struct upstream *upstream,
						  gboolean addr_failure,
						  const char *reason)
{
	double error_rate = 0, max_error_rate = 0;
	double sec_last, sec_cur;
	struct upstream_addr_elt *addr_elt;
	struct upstream_list_watcher *w;

	g_assert(upstream != NULL);
	msg_debug_upstream("upstream %s failed; reason: %s",
					   upstream->name,
					   reason);

	/* Pair with the increment in rspamd_upstream_get_common. */
	if (upstream->inflight > 0) {
		upstream->inflight--;
	}

	if (upstream->ctx && upstream->active_idx != -1 && upstream->ls) {
		sec_cur = rspamd_get_ticks(FALSE);

		RSPAMD_UPSTREAM_LOCK(upstream);
		if (upstream->errors == 0) {
			/* We have the first error */
			upstream->last_fail = sec_cur;
			upstream->errors = 1;

			if (upstream->ls && upstream->dns_requests == 0) {
				/* Try to re-resolve address immediately */
				rspamd_upstream_resolve_addrs(upstream->ls, upstream);
			}

			DL_FOREACH(upstream->ls->watchers, w)
			{
				if (w->events_mask & RSPAMD_UPSTREAM_WATCH_FAILURE) {
					w->func(upstream, RSPAMD_UPSTREAM_WATCH_FAILURE, 1, w->ud);
				}
			}
		}
		else {
			sec_last = upstream->last_fail;

			if (sec_cur >= sec_last) {
				upstream->errors++;


				DL_FOREACH(upstream->ls->watchers, w)
				{
					if (w->events_mask & RSPAMD_UPSTREAM_WATCH_FAILURE) {
						w->func(upstream, RSPAMD_UPSTREAM_WATCH_FAILURE,
								upstream->errors, w->ud);
					}
				}

				if (sec_cur - sec_last >= upstream->ls->limits->error_time) {
					error_rate = ((double) upstream->errors) / (sec_cur - sec_last);
					max_error_rate = ((double) upstream->ls->limits->max_errors) /
									 upstream->ls->limits->error_time;
				}

				if (error_rate > max_error_rate) {
					/* Remove upstream from the active list */
					if (upstream->ls->ups->len > 1) {
						msg_debug_upstream("mark upstream %s inactive; "
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
						rspamd_upstream_set_inactive(upstream->ls, upstream);
						upstream->errors = 0;
					}
					else {
						msg_debug_upstream("cannot mark last alive upstream %s "
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
							rspamd_upstream_resolve_addrs(upstream->ls, upstream);
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
				addr_elt = g_ptr_array_index(upstream->addrs.addr,
											 upstream->addrs.cur);
				addr_elt->errors++;
			}
		}

		/* If this was a half-open probe, schedule next probe with backoff */
		if (upstream->half_open_inflight > 0) {
			double now = upstream->ctx && upstream->ctx->event_loop ? ev_now(upstream->ctx->event_loop) : rspamd_get_ticks(FALSE);
			if (upstream->probe_backoff <= 0) {
				upstream->probe_backoff = upstream->ls->limits->revive_time;
			}
			upstream->probe_backoff = MIN(upstream->probe_backoff * 2.0, upstream->ls->limits->probe_max_backoff);
			upstream->next_probe_at = now + rspamd_time_jitter(upstream->probe_backoff,
															   upstream->probe_backoff * upstream->ls->limits->probe_jitter);
			upstream->half_open_inflight = 0;
		}

		RSPAMD_UPSTREAM_UNLOCK(upstream);
	}
}

void rspamd_upstream_ok(struct upstream *upstream)
{
	struct upstream_addr_elt *addr_elt;
	struct upstream_list_watcher *w;

	RSPAMD_UPSTREAM_LOCK(upstream);
	/* Pair with the increment in rspamd_upstream_get_common. */
	if (upstream->inflight > 0) {
		upstream->inflight--;
	}
	/* Success handling */
	if (upstream->half_open_inflight > 0) {
		/* Successful probe: mark alive and reset backoff */
		upstream->half_open_inflight = 0;
		upstream->probe_backoff = upstream->ls ? upstream->ls->limits->revive_time : default_revive_time;
		upstream->next_probe_at = 0;
		if (upstream->ls && upstream->active_idx == -1) {
			/* Activate this upstream; mark for slow-start ramping. */
			upstream->revived_at = upstream->ctx && upstream->ctx->event_loop
									   ? ev_now(upstream->ctx->event_loop)
									   : rspamd_get_ticks(FALSE);
			rspamd_upstream_set_active(upstream->ls, upstream);
		}
	}

	if (upstream->errors > 0 && upstream->active_idx != -1 && upstream->ls) {
		/* We touch upstream if and only if it is active */
		msg_debug_upstream("reset errors on upstream %s (was %ud)", upstream->name, upstream->errors);
		upstream->errors = 0;

		if (upstream->addrs.addr) {
			addr_elt = g_ptr_array_index(upstream->addrs.addr, upstream->addrs.cur);
			addr_elt->errors = 0;
		}

		DL_FOREACH(upstream->ls->watchers, w)
		{
			if (w->events_mask & RSPAMD_UPSTREAM_WATCH_SUCCESS) {
				w->func(upstream, RSPAMD_UPSTREAM_WATCH_SUCCESS, 0, w->ud);
			}
		}
	}

	RSPAMD_UPSTREAM_UNLOCK(upstream);
}

void rspamd_upstream_release(struct upstream *up)
{
	if (up == NULL) {
		return;
	}

	RSPAMD_UPSTREAM_LOCK(up);
	/* Pair with the increment in rspamd_upstream_get_common /
	 * rspamd_upstream_get_token_bucket without disturbing error or
	 * latency state. */
	if (up->inflight > 0) {
		up->inflight--;
	}
	RSPAMD_UPSTREAM_UNLOCK(up);
}

void rspamd_upstream_set_weight(struct upstream *up, unsigned int weight)
{
	RSPAMD_UPSTREAM_LOCK(up);
	up->weight = weight;
	RSPAMD_UPSTREAM_UNLOCK(up);
}

#define SEED_CONSTANT 0xa574de7df64e9b9dULL

struct upstream_list *
rspamd_upstreams_create(struct upstream_ctx *ctx)
{
	struct upstream_list *ls;

	ls = g_malloc0(sizeof(*ls));
	ls->hash_seed = SEED_CONSTANT;
	ls->ups = g_ptr_array_new();
	ls->alive = g_ptr_array_new();

#ifdef UPSTREAMS_THREAD_SAFE
	ls->lock = rspamd_mutex_new();
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

gsize rspamd_upstreams_count(struct upstream_list *ups)
{
	gsize n = 0;
	unsigned int i;
	struct upstream *up;

	if (ups == NULL) {
		return 0;
	}

	/*
	 * SRV parents are placeholders, not selectable upstreams. Count only
	 * first-class entries so callers see the real cluster size.
	 */
	for (i = 0; i < ups->ups->len; i++) {
		up = g_ptr_array_index(ups->ups, i);
		if (!(up->flags & RSPAMD_UPSTREAM_FLAG_SRV_RESOLVE)) {
			n++;
		}
	}

	return n;
}

gsize rspamd_upstreams_alive(struct upstream_list *ups)
{
	return ups != NULL ? ups->alive->len : 0;
}

static void
rspamd_upstream_dtor(struct upstream *up)
{
	struct upstream_inet_addr_entry *cur, *tmp;

	if (up->new_addrs) {
		LL_FOREACH_SAFE(up->new_addrs, cur, tmp)
		{
			/* Here we need to free pointer as well */
			rspamd_inet_address_free(cur->addr);
			g_free(cur);
		}
	}

	if (up->addrs.addr) {
		g_ptr_array_free(up->addrs.addr, TRUE);
	}

	/*
	 * SRV parents own a hash table of "fqdn:port" → member upstream. The
	 * members themselves carry their own refs and are freed independently
	 * once their drain ref counts reach zero, so we only release the hash
	 * itself here. Drain on rspamd_upstreams_destroy already cleared the
	 * entries by the time the parent's dtor runs.
	 */
	if (up->srv_members != NULL) {
		g_hash_table_unref(up->srv_members);
		up->srv_members = NULL;
	}

#ifdef UPSTREAMS_THREAD_SAFE
	rspamd_mutex_free(up->lock);
#endif

	if (up->ctx) {

		if (ev_can_stop(&up->ev)) {
			ev_timer_stop(up->ctx->event_loop, &up->ev);
		}

		g_queue_delete_link(up->ctx->upstreams, up->ctx_pos);
		REF_RELEASE(up->ctx);
	}

	g_free(up);
}

rspamd_inet_addr_t *
rspamd_upstream_addr_next(struct upstream *up)
{
	unsigned int idx, next_idx, cur_af,
		min_errors, min_errors_idx;
	struct upstream_addr_elt *e1, *e2;

	/*
	 * We apply the following algorithm:
	 * 1) Get the current element and it's AF
	 * 2) If the next element has the same AF, then we just move to the next element
	 * 3) If the next element has different AF, then we should find the next element with the same AF
	 * 4) If we cannot find such element, then we return the next element (switching AF)
	 */

	if (up == NULL || up->addrs.addr == NULL ||
		up->addrs.addr->len == 0) {
		/* Pending DNS resolution or never had any addresses */
		return NULL;
	}

	idx = up->addrs.cur;
	next_idx = up->addrs.cur;
	e1 = g_ptr_array_index(up->addrs.addr, up->addrs.cur);
	cur_af = rspamd_inet_address_get_af(e1->addr);
	min_errors = e1->errors;
	min_errors_idx = idx;

	for (;;) {
		unsigned int new_af;
		next_idx = (next_idx + 1) % up->addrs.addr->len;
		e2 = g_ptr_array_index(up->addrs.addr, next_idx);

		if (e2->errors < min_errors) {
			min_errors = e2->errors;
			min_errors_idx = next_idx;
		}

		if (next_idx == idx) {
			/* We did a full circle, so we have to select something else */
			if (e2->errors == 0) {
				/* No errors on the current address, so we can use it */
			}
			else {
				/* We have some errors, so we had to select the address with the lowest err count */
				next_idx = min_errors_idx;
			}

			/* Always stop on full circle */
			break;
		}

		new_af = rspamd_inet_address_get_af(e2->addr);

		if (cur_af == new_af && e2->errors <= e1->errors) {
			/* Same AF */
			up->addrs.cur = next_idx;
			return e2->addr;
		}
	}

	e2 = g_ptr_array_index(up->addrs.addr, next_idx);
	up->addrs.cur = next_idx;

	return e2->addr;
}

rspamd_inet_addr_t *
rspamd_upstream_addr_cur(const struct upstream *up)
{
	struct upstream_addr_elt *elt;

	if (up == NULL || up->addrs.addr == NULL ||
		up->addrs.addr->len == 0) {
		return NULL;
	}

	elt = g_ptr_array_index(up->addrs.addr, up->addrs.cur);

	return elt->addr;
}

const char *
rspamd_upstream_name(struct upstream *up)
{
	return up->name;
}

int rspamd_upstream_port(struct upstream *up)
{
	struct upstream_addr_elt *elt;

	if (up == NULL || up->addrs.addr == NULL ||
		up->addrs.addr->len == 0) {
		/* Pending or never resolved: fall back to the parsed port if known */
		return up != NULL ? (int) up->deferred_port : -1;
	}

	elt = g_ptr_array_index(up->addrs.addr, up->addrs.cur);
	return rspamd_inet_address_get_port(elt->addr);
}

/*
 * Fallback parser used when DNS resolution fails for a hostname-style upstream.
 * Extracts host and port from "host[:port[:priority]]" so the upstream can be
 * created in PENDING_RESOLVE state and resolved later.
 *
 * Returns TRUE on a syntactically valid hostname; FALSE otherwise (in which
 * case the upstream cannot be deferred and creation must fail).
 */
static gboolean
rspamd_upstream_parse_pending_host(const char *str, char **out_host,
								   uint16_t *out_port, uint16_t def_port,
								   rspamd_mempool_t *pool)
{
	const char *colon, *host_end;
	size_t hlen;
	uint16_t port = def_port;

	if (str == NULL || str[0] == '\0' || str[0] == '[' || str[0] == '/' ||
		str[0] == '.' || str[0] == '*' || str[0] == ':') {
		return FALSE;
	}

	colon = strchr(str, ':');

	if (colon != NULL) {
		host_end = colon;
		if (colon[1] != '\0') {
			char *endptr = NULL;
			unsigned long pn = strtoul(colon + 1, &endptr, 10);
			if (pn == 0 || pn > UINT16_MAX) {
				return FALSE;
			}
			port = (uint16_t) pn;
		}
	}
	else {
		host_end = str + strlen(str);
	}

	hlen = host_end - str;
	if (hlen == 0 || hlen > 253) {
		return FALSE;
	}

	if (pool) {
		*out_host = rspamd_mempool_alloc(pool, hlen + 1);
	}
	else {
		*out_host = g_malloc(hlen + 1);
	}
	rspamd_strlcpy(*out_host, str, hlen + 1);
	*out_port = port;

	return TRUE;
}

gboolean
rspamd_upstreams_add_upstream(struct upstream_list *ups, const char *str,
							  uint16_t def_port, enum rspamd_upstream_parse_type parse_type,
							  void *data)
{
	struct upstream *upstream;
	GPtrArray *addrs = NULL;
	unsigned int i, slen;
	rspamd_inet_addr_t *addr;
	enum rspamd_parse_host_port_result ret = RSPAMD_PARSE_ADDR_FAIL;

	upstream = g_malloc0(sizeof(*upstream));
	slen = strlen(str);

	switch (parse_type) {
	case RSPAMD_UPSTREAM_PARSE_DEFAULT:
		if (slen > sizeof("service=") &&
			RSPAMD_LEN_CHECK_STARTS_WITH(str, slen, "service=")) {
			const char *plus_pos, *service_pos, *semicolon_pos;

			/* Accept service=srv_name+hostname[:priority] */
			service_pos = str + sizeof("service=") - 1;
			plus_pos = strchr(service_pos, '+');

			if (plus_pos != NULL) {
				semicolon_pos = strchr(plus_pos + 1, ':');

				if (semicolon_pos) {
					upstream->weight = strtoul(semicolon_pos + 1, NULL, 10);
				}
				else {
					semicolon_pos = plus_pos + strlen(plus_pos);
				}

				/*
				 * Now our name is _service._tcp.<domain>
				 * where <domain> is string between semicolon_pos and plus_pos +1
				 * while service is a string between service_pos and plus_pos
				 */
				unsigned int namelen = (semicolon_pos - (plus_pos + 1)) +
									   (plus_pos - service_pos) +
									   (sizeof("tcp") - 1) +
									   4;
				addrs = g_ptr_array_sized_new(1);
				upstream->name = ups->ctx ? rspamd_mempool_alloc(ups->ctx->pool, namelen + 1) : g_malloc(namelen + 1);

				rspamd_snprintf(upstream->name, namelen + 1,
								"_%*s._tcp.%*s",
								(int) (plus_pos - service_pos), service_pos,
								(int) (semicolon_pos - (plus_pos + 1)), plus_pos + 1);
				upstream->flags |= RSPAMD_UPSTREAM_FLAG_SRV_RESOLVE;
				/*
				 * Pre-allocate the member index. The hash owns the keys
				 * (g_free destructor) and not the values; member upstreams
				 * are released through their own ref counts during drain
				 * or list teardown.
				 */
				upstream->srv_members = g_hash_table_new_full(g_str_hash,
															  g_str_equal,
															  g_free, NULL);
				ret = RSPAMD_PARSE_ADDR_RESOLVED;

				if (ups->ctx) {
					rspamd_mempool_add_destructor(ups->ctx->pool,
												  (rspamd_mempool_destruct_t) rspamd_ptr_array_free_hard,
												  addrs);
				}
			}
		}
		else {
			ret = rspamd_parse_host_port_priority(str, &addrs,
												  &upstream->weight,
												  &upstream->name, def_port,
												  FALSE,
												  ups->ctx ? ups->ctx->pool : NULL);

			if (ret == RSPAMD_PARSE_ADDR_FAIL) {
				char *pending_host = NULL;
				uint16_t pending_port = 0;

				if (rspamd_upstream_parse_pending_host(str, &pending_host,
													   &pending_port, def_port,
													   ups->ctx ? ups->ctx->pool : NULL)) {
					/*
					 * DNS failed but the input looks like a hostname.
					 * Create the upstream in PENDING_RESOLVE state so the
					 * lazy resolver can populate addresses later. The upstream
					 * stays out of the alive list until resolution succeeds.
					 */
					upstream->name = pending_host;
					upstream->deferred_port = pending_port;
					upstream->flags |= RSPAMD_UPSTREAM_FLAG_PENDING_RESOLVE;
					addrs = g_ptr_array_sized_new(0);
					if (ups->ctx) {
						rspamd_mempool_add_destructor(ups->ctx->pool,
													  (rspamd_mempool_destruct_t) rspamd_ptr_array_free_hard,
													  addrs);
					}
					ret = RSPAMD_PARSE_ADDR_RESOLVED;
					rspamd_default_log_function(G_LOG_LEVEL_WARNING,
												"upstream", NULL, G_STRFUNC,
												"address resolution for %s "
												"failed at config time; "
												"deferring (will retry asynchronously)",
												pending_host);
				}
			}
		}
		break;
	case RSPAMD_UPSTREAM_PARSE_NAMESERVER:
		addrs = g_ptr_array_sized_new(1);
		if (rspamd_parse_inet_address(&addr, str, strlen(str),
									  RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
			if (ups->ctx) {
				upstream->name = rspamd_mempool_strdup(ups->ctx->pool, str);
			}
			else {
				upstream->name = g_strdup(str);
			}
			if (rspamd_inet_address_get_port(addr) == 0) {
				rspamd_inet_address_set_port(addr, def_port);
			}

			g_ptr_array_add(addrs, addr);
			ret = RSPAMD_PARSE_ADDR_NUMERIC;

			if (ups->ctx) {
				rspamd_mempool_add_destructor(ups->ctx->pool,
											  (rspamd_mempool_destruct_t) rspamd_inet_address_free,
											  addr);
				rspamd_mempool_add_destructor(ups->ctx->pool,
											  (rspamd_mempool_destruct_t) rspamd_ptr_array_free_hard,
											  addrs);
			}
		}
		else {
			/* Not numeric: resolve synchronously and add all IPs */
			struct addrinfo hints, *res = NULL, *cur;
			char hostbuf[256];
			const char *colon = strchr(str, ':');
			char portbuf[8];
			unsigned int portnum = def_port;

			if (colon != NULL && colon > str) {
				size_t hlen = MIN((size_t) (colon - str), sizeof(hostbuf) - 1);
				rspamd_strlcpy(hostbuf, str, hlen + 1);
				if (colon[1] != '\0') {
					portnum = strtoul(colon + 1, NULL, 10);
				}
			}
			else {
				rspamd_strlcpy(hostbuf, str, sizeof(hostbuf));
			}

			rspamd_snprintf(portbuf, sizeof(portbuf), "%ud", portnum);
			memset(&hints, 0, sizeof(hints));
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_family = AF_UNSPEC;
			hints.ai_flags = AI_NUMERICSERV;

			if (getaddrinfo(hostbuf, portbuf, &hints, &res) == 0 && res != NULL) {
				for (cur = res; cur != NULL; cur = cur->ai_next) {
					rspamd_inet_addr_t *na = rspamd_inet_address_from_sa(cur->ai_addr, cur->ai_addrlen);
					if (na == NULL) {
						continue;
					}
					rspamd_inet_address_set_port(na, portnum);
					g_ptr_array_add(addrs, na);
				}
				freeaddrinfo(res);
				if (ups->ctx) {
					rspamd_mempool_add_destructor(ups->ctx->pool,
												  (rspamd_mempool_destruct_t) rspamd_ptr_array_free_hard,
												  addrs);
				}
				if (ups->ctx) {
					upstream->name = rspamd_mempool_strdup(ups->ctx->pool, str);
				}
				else {
					upstream->name = g_strdup(str);
				}
				ret = RSPAMD_PARSE_ADDR_RESOLVED;
			}
			else {
				g_ptr_array_free(addrs, TRUE);
				addrs = NULL;
			}
		}

		break;
	}

	if (ret == RSPAMD_PARSE_ADDR_FAIL) {
		/* Clean up addrs if created but not managed by mempool */
		if (addrs && !ups->ctx) {
			g_ptr_array_free(addrs, TRUE);
		}
		g_free(upstream);
		return FALSE;
	}
	else {
		upstream->flags |= ups->flags;

		if (ret == RSPAMD_PARSE_ADDR_NUMERIC) {
			/* Add noresolve flag */
			upstream->flags |= RSPAMD_UPSTREAM_FLAG_NORESOLVE;
		}
		for (i = 0; i < addrs->len; i++) {
			addr = g_ptr_array_index(addrs, i);
			rspamd_upstream_add_addr(upstream, rspamd_inet_address_copy(addr, NULL));
		}

		/* Free addrs array if no pool (not managed by mempool destructor) */
		if (!ups->ctx) {
			g_ptr_array_free(addrs, TRUE);
		}
	}

	if (upstream->weight == 0 && ups->rot_alg == RSPAMD_UPSTREAM_MASTER_SLAVE) {
		/* Special heuristic for master-slave rotation */
		if (ups->ups->len == 0) {
			/* Prioritize the first */
			upstream->weight = 1;
		}
	}

	g_ptr_array_add(ups->ups, upstream);
	upstream->ud = data;
	upstream->cur_weight = upstream->weight;
	upstream->ls = ups;
	REF_INIT_RETAIN(upstream, rspamd_upstream_dtor);
#ifdef UPSTREAMS_THREAD_SAFE
	upstream->lock = rspamd_mutex_new();
#endif
	upstream->ctx = ups->ctx;

	if (upstream->ctx) {
		REF_RETAIN(ups->ctx);
		g_queue_push_tail(ups->ctx->upstreams, upstream);
		upstream->ctx_pos = g_queue_peek_tail_link(ups->ctx->upstreams);
	}

	unsigned int h = rspamd_cryptobox_fast_hash(upstream->name,
												strlen(upstream->name), 0);
	memset(upstream->uid, 0, sizeof(upstream->uid));
	rspamd_encode_base32_buf((const unsigned char *) &h, sizeof(h),
							 upstream->uid, sizeof(upstream->uid) - 1, RSPAMD_BASE32_DEFAULT);

	msg_debug_upstream("added upstream %s (%s)", upstream->name,
					   upstream->flags & RSPAMD_UPSTREAM_FLAG_NORESOLVE ? "numeric ip" : (upstream->flags & RSPAMD_UPSTREAM_FLAG_PENDING_RESOLVE ? "DNS name (deferred)" : "DNS name"));
	if (upstream->addrs.addr) {
		g_ptr_array_sort(upstream->addrs.addr, rspamd_upstream_addr_sort_func);
	}
	rspamd_upstream_set_active(ups, upstream);

	return TRUE;
}

void rspamd_upstreams_set_flags(struct upstream_list *ups,
								enum rspamd_upstream_flag flags)
{
	ups->flags = flags;
}

void rspamd_upstreams_set_rotation(struct upstream_list *ups,
								   enum rspamd_upstream_rotation rot)
{
	ups->rot_alg = rot;
}

gboolean
rspamd_upstream_add_addr(struct upstream *up, rspamd_inet_addr_t *addr)
{
	struct upstream_addr_elt *elt;
	/*
	 * XXX: slow and inefficient
	 */
	if (up->addrs.addr == NULL) {
		up->addrs.addr = g_ptr_array_new_full(8, rspamd_upstream_addr_elt_dtor);
	}

	elt = g_malloc0(sizeof(*elt));
	elt->addr = addr;
	g_ptr_array_add(up->addrs.addr, elt);
	g_ptr_array_sort(up->addrs.addr, rspamd_upstream_addr_sort_func);

	return TRUE;
}

gboolean
rspamd_upstreams_parse_line_len(struct upstream_list *ups,
								const char *str, gsize len, uint16_t def_port, void *data)
{
	const char *end = str + len, *p = str;
	const char *separators = ";, \n\r\t";
	char *tmp;
	unsigned int span_len;
	gboolean ret = FALSE;

	if (RSPAMD_LEN_CHECK_STARTS_WITH(p, len, "random:")) {
		ups->rot_alg = RSPAMD_UPSTREAM_RANDOM;
		p += sizeof("random:") - 1;
	}
	else if (RSPAMD_LEN_CHECK_STARTS_WITH(p, len, "master-slave:")) {
		ups->rot_alg = RSPAMD_UPSTREAM_MASTER_SLAVE;
		p += sizeof("master-slave:") - 1;
	}
	else if (RSPAMD_LEN_CHECK_STARTS_WITH(p, len, "round-robin:")) {
		ups->rot_alg = RSPAMD_UPSTREAM_ROUND_ROBIN;
		p += sizeof("round-robin:") - 1;
	}
	else if (RSPAMD_LEN_CHECK_STARTS_WITH(p, len, "hash:")) {
		ups->rot_alg = RSPAMD_UPSTREAM_HASHED;
		p += sizeof("hash:") - 1;
	}

	while (p < end) {
		span_len = rspamd_memcspn(p, end - p, separators, strlen(separators));

		if (span_len > 0) {
			tmp = g_malloc(span_len + 1);
			rspamd_strlcpy(tmp, p, span_len + 1);

			if (rspamd_upstreams_add_upstream(ups, tmp, def_port,
											  RSPAMD_UPSTREAM_PARSE_DEFAULT,
											  data)) {
				ret = TRUE;
			}

			g_free(tmp);
		}

		p += span_len;
		/* Skip separators */
		if (p < end) {
			p += rspamd_memspn(p, separators, end - p);
		}
	}

	if (!ups->ups_line) {
		ups->ups_line = g_malloc(len + 1);
		rspamd_strlcpy(ups->ups_line, str, len + 1);
	}

	return ret;
}


gboolean
rspamd_upstreams_parse_line(struct upstream_list *ups,
							const char *str, uint16_t def_port, void *data)
{
	return rspamd_upstreams_parse_line_len(ups, str, strlen(str),
										   def_port, data);
}

gboolean
rspamd_upstreams_from_ucl(struct upstream_list *ups,
						  const ucl_object_t *in, uint16_t def_port, void *data)
{
	gboolean ret = FALSE;
	const ucl_object_t *cur;
	ucl_object_iter_t it = NULL;

	it = ucl_object_iterate_new(in);

	while ((cur = ucl_object_iterate_safe(it, true)) != NULL) {
		if (ucl_object_type(cur) == UCL_STRING) {
			ret = rspamd_upstreams_parse_line(ups, ucl_object_tostring(cur),
											  def_port, data);
		}
	}

	ucl_object_iterate_free(it);

	return ret;
}

void rspamd_upstreams_destroy(struct upstream_list *ups)
{
	unsigned int i;
	struct upstream *up;
	struct upstream_list_watcher *w, *tmp;

	if (ups != NULL) {
		/* Clean up ring hash */
		g_free(ups->ring);
		ups->ring = NULL;
		ups->ring_len = 0;

		g_ptr_array_free(ups->alive, TRUE);

		for (i = 0; i < ups->ups->len; i++) {
			up = g_ptr_array_index(ups->ups, i);
			up->ls = NULL;
			REF_RELEASE(up);
		}

		DL_FOREACH_SAFE(ups->watchers, w, tmp)
		{
			if (w->dtor) {
				w->dtor(w->ud);
			}
			g_free(w);
		}

		g_free(ups->ups_line);
		g_ptr_array_free(ups->ups, TRUE);
#ifdef UPSTREAMS_THREAD_SAFE
		rspamd_mutex_free(ups->lock);
#endif
		g_free(ups);
	}
}

static void
rspamd_upstream_restore_cb(gpointer elt, gpointer ls)
{
	struct upstream *up = (struct upstream *) elt;
	struct upstream_list *ups = (struct upstream_list *) ls;
	struct upstream_list_watcher *w;

	/* Here the upstreams list is already locked */
	RSPAMD_UPSTREAM_LOCK(up);

	if (ev_can_stop(&up->ev)) {
		ev_timer_stop(up->ctx->event_loop, &up->ev);
	}

	g_ptr_array_add(ups->alive, up);
	up->active_idx = ups->alive->len - 1;
	ups->ring_dirty = TRUE;
	RSPAMD_UPSTREAM_UNLOCK(up);

	DL_FOREACH(up->ls->watchers, w)
	{
		if (w->events_mask & RSPAMD_UPSTREAM_WATCH_ONLINE) {
			w->func(up, RSPAMD_UPSTREAM_WATCH_ONLINE, up->errors, w->ud);
		}
	}

	/* For revive event */
	g_assert(up->ref.refcount > 1);
	REF_RELEASE(up);
}

static struct upstream *
rspamd_upstream_get_random(struct upstream_list *ups,
						   struct upstream *except)
{
	unsigned int n = ups->alive->len;
	struct upstream *up;

	if (n == 0) {
		return NULL;
	}
	if (n == 1) {
		up = g_ptr_array_index(ups->alive, 0);
		return (except != NULL && up == except) ? NULL : up;
	}

	/* n >= 2: at most one excluded, retry-on-collision is bounded */
	for (;;) {
		unsigned int idx = ottery_rand_range(n - 1);
		up = g_ptr_array_index(ups->alive, idx);

		if (except != NULL && up == except) {
			continue;
		}

		return up;
	}
}

/*
 * Slow start factor in [0, 1]: 1.0 in steady state, ramping linearly from
 * 0 toward 1 over `slow_start_ms` after a revive. Returns 1.0 when slow
 * start is disabled or the upstream has never been revived. Mutates
 * revived_at to clear the cache once the window expires.
 */
static inline double
rspamd_upstream_slow_start_factor(struct upstream *up, double now)
{
	const struct upstream_limits *limits;
	double elapsed_ms;
	double factor;

	if (up->ls == NULL || up->revived_at <= 0) {
		return 1.0;
	}
	limits = up->ls->limits;
	if (limits->slow_start_ms == 0) {
		return 1.0;
	}

	elapsed_ms = (now - up->revived_at) * 1000.0;
	if (elapsed_ms <= 0) {
		return 0.0;
	}
	if (elapsed_ms >= (double) limits->slow_start_ms) {
		up->revived_at = 0; /* clear: no further work for this upstream */
		return 1.0;
	}

	factor = elapsed_ms / (double) limits->slow_start_ms;
	if (factor < 0.0) factor = 0.0;
	return factor;
}

/*
 * Load score used by P2C: combines passive in-flight count with a small
 * penalty for recent errors and (when available) latency EWMA. Lower is
 * better.
 *
 * Phase 2 score, when latency samples exist:
 *   score = latency * (inflight + 1) + errors_penalty
 *
 * This is a lightweight approximation of PeakEWMA used by Linkerd/Finagle:
 * a slow backend with low load still loses to a fast one with comparable
 * load; a fast backend with high load can still lose to an idle slow one
 * if the latency gap is small enough.
 *
 * Phase 1 fallback (no latency yet):
 *   score = inflight + errors * 2
 *
 * During slow start the score is scaled *up* by the inverse factor so a
 * barely-warmed-up upstream looks loaded relative to its peers and
 * receives proportionally less traffic.
 */
static inline double
rspamd_upstream_load_score(struct upstream *up, double now)
{
	double base;
	double factor;

	if (up->latency_n > 0 && up->latency_ewma > 0) {
		base = up->latency_ewma * (double) (up->inflight + 1) +
			   (double) up->errors * 5.0 * up->latency_ewma;
	}
	else {
		base = (double) up->inflight + (double) up->errors * 2.0;
	}

	factor = rspamd_upstream_slow_start_factor(up, now);
	if (factor < 1.0) {
		/* As factor -> 0, score -> infinity (heavily deprioritised). */
		if (factor < 0.01) {
			factor = 0.01;
		}
		return base / factor + (1.0 - factor) * 100.0;
	}
	return base;
}

/*
 * Power of Two Choices: pick two distinct alive upstreams uniformly at
 * random and return the one with the lower load score. Provably within a
 * constant factor of optimal max-load and the modern default for
 * load-aware random selection.
 */
static struct upstream *
rspamd_upstream_get_p2c(struct upstream_list *ups, struct upstream *except)
{
	unsigned int n = ups->alive->len;
	struct upstream *a, *b;
	double now;

	if (n == 0) {
		return NULL;
	}
	if (n == 1) {
		a = g_ptr_array_index(ups->alive, 0);
		return (except != NULL && a == except) ? NULL : a;
	}
	if (n == 2 && except != NULL) {
		/* If one of the two is excluded, the choice is forced. */
		a = g_ptr_array_index(ups->alive, 0);
		b = g_ptr_array_index(ups->alive, 1);
		if (a == except) return b;
		if (b == except) return a;
		/* Neither excluded: fall through to standard P2C. */
	}

	/* Sample two distinct indices. */
	unsigned int i = ottery_rand_range(n - 1);
	unsigned int j;
	do {
		j = ottery_rand_range(n - 1);
	} while (j == i);

	a = g_ptr_array_index(ups->alive, i);
	b = g_ptr_array_index(ups->alive, j);

	if (except != NULL) {
		if (a == except) return b;
		if (b == except) return a;
	}

	if (ups->ctx && ups->ctx->event_loop) {
		now = ev_now(ups->ctx->event_loop);
	}
	else {
		now = rspamd_get_ticks(FALSE);
	}

	return rspamd_upstream_load_score(a, now) <= rspamd_upstream_load_score(b, now) ? a : b;
}

static struct upstream *
rspamd_upstream_get_round_robin(struct upstream_list *ups,
								struct upstream *except,
								gboolean use_cur)
{
	unsigned int max_weight = 0, min_checked = G_MAXUINT;
	struct upstream *up = NULL, *selected = NULL, *min_checked_sel = NULL;
	unsigned int i;
	double now;

	/* Select upstream with the maximum cur_weight */
	RSPAMD_UPSTREAM_LOCK(ups);

	if (ups->ctx && ups->ctx->event_loop) {
		now = ev_now(ups->ctx->event_loop);
	}
	else {
		now = rspamd_get_ticks(FALSE);
	}

	for (i = 0; i < ups->alive->len; i++) {
		unsigned int eff;
		double factor;

		up = g_ptr_array_index(ups->alive, i);

		if (except != NULL && up == except) {
			continue;
		}

		factor = rspamd_upstream_slow_start_factor(up, now);
		eff = use_cur ? up->cur_weight : up->weight;
		if (factor < 1.0) {
			/* Scale weight down during the slow-start ramp. */
			eff = (unsigned int) ((double) eff * factor);
		}

		if (eff > max_weight) {
			selected = up;
			max_weight = eff;
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

	if (max_weight == 0 && use_cur) {
		/*
		 * All cur_weights have been exhausted. If any upstream has a
		 * configured weight, reset all cur_weights to restart the
		 * weighted round-robin cycle. Otherwise fall through to the
		 * unweighted min_checked selection.
		 */
		gboolean any_weight = FALSE;

		for (i = 0; i < ups->alive->len; i++) {
			up = g_ptr_array_index(ups->alive, i);

			if (up->weight > 0) {
				any_weight = TRUE;
				break;
			}
		}

		if (any_weight) {
			/* Reset all cur_weights and re-select */
			for (i = 0; i < ups->alive->len; i++) {
				up = g_ptr_array_index(ups->alive, i);
				up->cur_weight = up->weight;
			}

			max_weight = 0;
			selected = NULL;

			for (i = 0; i < ups->alive->len; i++) {
				up = g_ptr_array_index(ups->alive, i);

				if (except != NULL && up == except) {
					continue;
				}

				if (up->cur_weight > max_weight) {
					selected = up;
					max_weight = up->cur_weight;
				}
			}
		}
		else {
			/* All weights are zero: use least-checked selection */
			if (min_checked > G_MAXUINT / 2) {
				for (i = 0; i < ups->alive->len; i++) {
					up = g_ptr_array_index(ups->alive, i);
					up->checked = 0;
				}
			}

			selected = min_checked_sel;
		}
	}
	else if (max_weight == 0) {
		/* Non-weighted path (use_cur == FALSE) */
		if (min_checked > G_MAXUINT / 2) {
			for (i = 0; i < ups->alive->len; i++) {
				up = g_ptr_array_index(ups->alive, i);
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

	RSPAMD_UPSTREAM_UNLOCK(ups);

	return selected;
}

/*
 * Ring hash (Ketama-style) consistent hashing.
 *
 * Each alive upstream gets a number of virtual nodes placed on a hash ring.
 * Lookup hashes the key and binary-searches for the next ring point.
 * When an upstream fails, only its virtual nodes disappear; keys that
 * mapped to them naturally slide to the next point on the ring, giving
 * minimal disruption (only ~1/n of keys move for each removed upstream).
 */

/* Virtual nodes per unit of weight (weight 0 is treated as 1) */
#define RSPAMD_RING_VNODES 100

static int
rspamd_upstream_ring_cmp(const void *a, const void *b)
{
	const struct upstream_ring_point *p1 = a, *p2 = b;

	if (p1->hash < p2->hash) {
		return -1;
	}
	if (p1->hash > p2->hash) {
		return 1;
	}

	return 0;
}

static void
rspamd_upstream_ring_build(struct upstream_list *ups)
{
	unsigned int i, j;
	struct upstream *up;
	unsigned int total_vnodes = 0;

	g_free(ups->ring);
	ups->ring = NULL;
	ups->ring_len = 0;

	if (ups->alive->len == 0) {
		ups->ring_dirty = FALSE;
		return;
	}

	/* Calculate total ring points needed */
	for (i = 0; i < ups->alive->len; i++) {
		up = g_ptr_array_index(ups->alive, i);
		total_vnodes += MAX(up->weight, 1) * RSPAMD_RING_VNODES;
	}

	ups->ring = g_malloc(total_vnodes * sizeof(struct upstream_ring_point));

	for (i = 0; i < ups->alive->len; i++) {
		up = g_ptr_array_index(ups->alive, i);
		unsigned int nvnodes = MAX(up->weight, 1) * RSPAMD_RING_VNODES;

		for (j = 0; j < nvnodes; j++) {
			char vnode_key[280]; /* upstream name (253 max) + : + digits */
			int len = rspamd_snprintf(vnode_key, sizeof(vnode_key),
									  "%s:%ud", up->name, j);
			uint64_t h = rspamd_cryptobox_fast_hash_specific(
				RSPAMD_CRYPTOBOX_XXHASH64,
				vnode_key, len, ups->hash_seed);

			ups->ring[ups->ring_len].hash = h;
			ups->ring[ups->ring_len].up = up;
			ups->ring_len++;
		}
	}

	qsort(ups->ring, ups->ring_len, sizeof(struct upstream_ring_point),
		  rspamd_upstream_ring_cmp);

	ups->ring_dirty = FALSE;
}

static struct upstream *
rspamd_upstream_get_hashed(struct upstream_list *ups,
						   struct upstream *except,
						   const uint8_t *key, unsigned int keylen)
{
	uint64_t k;
	struct upstream *up;

	RSPAMD_UPSTREAM_LOCK(ups);

	/* Lazy ring rebuild */
	if (ups->ring_dirty || ups->ring == NULL) {
		rspamd_upstream_ring_build(ups);
	}

	if (ups->ring_len == 0) {
		RSPAMD_UPSTREAM_UNLOCK(ups);
		return NULL;
	}

	/* Hash the lookup key */
	k = rspamd_cryptobox_fast_hash_specific(RSPAMD_CRYPTOBOX_XXHASH64,
											key, keylen, ups->hash_seed);

	/* Binary search for first ring point >= k */
	unsigned int lo = 0, hi = ups->ring_len;

	while (lo < hi) {
		unsigned int mid = lo + (hi - lo) / 2;

		if (ups->ring[mid].hash < k) {
			lo = mid + 1;
		}
		else {
			hi = mid;
		}
	}

	/* Wrap around */
	if (lo >= ups->ring_len) {
		lo = 0;
	}

	up = ups->ring[lo].up;

	/* Handle 'except': walk forward on ring to find a different upstream */
	if (except != NULL && up == except) {
		for (unsigned int i = 1; i < ups->ring_len; i++) {
			unsigned int idx = (lo + i) % ups->ring_len;

			if (ups->ring[idx].up != except) {
				up = ups->ring[idx].up;
				break;
			}
		}

		if (up == except) {
			/* All ring points belong to the excluded upstream */
			RSPAMD_UPSTREAM_UNLOCK(ups);
			return NULL;
		}
	}

	RSPAMD_UPSTREAM_UNLOCK(ups);

	return up;
}

static struct upstream *
rspamd_upstream_get_common(struct upstream_list *ups,
						   struct upstream *except,
						   enum rspamd_upstream_rotation default_type,
						   const unsigned char *key, gsize keylen,
						   gboolean forced)
{
	enum rspamd_upstream_rotation type;
	struct upstream *up = NULL;

	RSPAMD_UPSTREAM_LOCK(ups);
	if (ups->alive->len == 0) {
		/* Probe mode: find the earliest probe-ready upstream and allow one inflight */
		double now = ups->ctx && ups->ctx->event_loop ? ev_now(ups->ctx->event_loop) : rspamd_get_ticks(FALSE);
		struct upstream *candidate = NULL;
		double min_probe = HUGE_VAL;

		for (unsigned int i = 0; i < ups->ups->len; i++) {
			struct upstream *cur = g_ptr_array_index(ups->ups, i);
			if (cur->active_idx >= 0 || (except && cur == except)) {
				continue;
			}
			/*
			 * SRV parents never enter selection; they only own member
			 * upstreams. Skip them so probe mode considers real backends.
			 */
			if (cur->flags & RSPAMD_UPSTREAM_FLAG_SRV_RESOLVE) {
				continue;
			}
			/*
			 * Pending-resolve upstreams have no addresses yet — they can't
			 * be probed. The lazy resolver will move them into `alive` once
			 * DNS comes back.
			 */
			if (cur->flags & RSPAMD_UPSTREAM_FLAG_PENDING_RESOLVE) {
				continue;
			}

			if (cur->next_probe_at == 0) {
				/* Initialize probe schedule based on revive_time */
				cur->probe_backoff = cur->probe_backoff > 0 ? cur->probe_backoff : ups->limits->revive_time;
				cur->next_probe_at = now + rspamd_time_jitter(cur->probe_backoff,
															  cur->probe_backoff * ups->limits->probe_jitter);
			}

			if (cur->next_probe_at <= now && cur->half_open_inflight == 0) {
				candidate = cur;
				break;
			}

			if (cur->next_probe_at < min_probe) {
				min_probe = cur->next_probe_at;
			}
		}

		if (candidate) {
			candidate->half_open_inflight = 1; /* allow one request */
			up = candidate;
		}

		RSPAMD_UPSTREAM_UNLOCK(ups);

		return up; /* can be NULL if not ready yet */
	}
	RSPAMD_UPSTREAM_UNLOCK(ups);

	if (ups->alive->len == 1 && default_type != RSPAMD_UPSTREAM_SEQUENTIAL) {
		/* Fast path: single alive upstream is returned even when it equals
		 * `except` (documented last-resort behaviour to avoid NULL return). */
		up = g_ptr_array_index(ups->alive, 0);
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
		/*
		 * Silent upgrade: P2C strictly dominates uniform random. Existing
		 * RANDOM callers get load-aware selection at no cost.
		 */
		up = rspamd_upstream_get_p2c(ups, except);
		break;
	case RSPAMD_UPSTREAM_P2C:
		up = rspamd_upstream_get_p2c(ups, except);
		break;
	case RSPAMD_UPSTREAM_HASHED:
		up = rspamd_upstream_get_hashed(ups, except, key, keylen);
		break;
	case RSPAMD_UPSTREAM_ROUND_ROBIN:
		up = rspamd_upstream_get_round_robin(ups, except, TRUE);
		break;
	case RSPAMD_UPSTREAM_MASTER_SLAVE:
		up = rspamd_upstream_get_round_robin(ups, except, FALSE);
		break;
	case RSPAMD_UPSTREAM_TOKEN_BUCKET:
		/*
		 * Token bucket requires message size, which isn't available here.
		 * Fall back to P2C. Use rspamd_upstream_get_token_bucket() for
		 * proper token bucket selection.
		 */
		up = rspamd_upstream_get_p2c(ups, except);
		break;
	case RSPAMD_UPSTREAM_SEQUENTIAL:
		if (ups->cur_elt >= ups->alive->len) {
			ups->cur_elt = 0;
			return NULL;
		}

		up = g_ptr_array_index(ups->alive, ups->cur_elt++);
		break;
	}

end:
	if (up) {
		up->checked++;
		up->inflight++;
	}

	return up;
}

struct upstream *
rspamd_upstream_get(struct upstream_list *ups,
					enum rspamd_upstream_rotation default_type,
					const unsigned char *key, gsize keylen)
{
	return rspamd_upstream_get_common(ups, NULL, default_type, key, keylen, FALSE);
}

struct upstream *
rspamd_upstream_get_forced(struct upstream_list *ups,
						   enum rspamd_upstream_rotation forced_type,
						   const unsigned char *key, gsize keylen)
{
	return rspamd_upstream_get_common(ups, NULL, forced_type, key, keylen, TRUE);
}

struct upstream *rspamd_upstream_get_except(struct upstream_list *ups,
											struct upstream *except,
											enum rspamd_upstream_rotation default_type,
											const unsigned char *key, gsize keylen)
{
	return rspamd_upstream_get_common(ups, except, default_type, key, keylen, FALSE);
}

void rspamd_upstream_reresolve(struct upstream_ctx *ctx)
{
	GList *cur;
	struct upstream *up;

	cur = ctx->upstreams->head;

	while (cur) {
		up = cur->data;
		g_assert(up != NULL);
		REF_RETAIN(up);
		rspamd_upstream_resolve_addrs(up->ls, up);
		REF_RELEASE(up);
		cur = g_list_next(cur);
	}
}

gpointer
rspamd_upstream_set_data(struct upstream *up, gpointer data)
{
	gpointer prev_data = up->data;
	up->data = data;

	return prev_data;
}

gpointer
rspamd_upstream_get_data(struct upstream *up)
{
	return up->data;
}


void rspamd_upstreams_foreach(struct upstream_list *ups,
							  rspamd_upstream_traverse_func cb, void *ud)
{
	struct upstream *up;
	unsigned int i, idx = 0;

	for (i = 0; i < ups->ups->len; i++) {
		up = g_ptr_array_index(ups->ups, i);

		/*
		 * Skip SRV parent placeholders — they aren't selectable
		 * upstreams and exposing them to consumers (foreach is the
		 * public iteration API) would surprise callers that expect
		 * to enumerate real backends.
		 */
		if (up->flags & RSPAMD_UPSTREAM_FLAG_SRV_RESOLVE) {
			continue;
		}

		cb(up, idx++, ud);
	}
}

void rspamd_upstreams_set_limits(struct upstream_list *ups,
								 double revive_time,
								 double revive_jitter,
								 double error_time,
								 double dns_timeout,
								 unsigned int max_errors,
								 unsigned int dns_retransmits)
{
	struct upstream_limits *nlimits;
	g_assert(ups != NULL);

	nlimits = rspamd_mempool_alloc(ups->ctx->pool, sizeof(*nlimits));
	memcpy(nlimits, ups->limits, sizeof(*nlimits));

	if (!isnan(revive_time)) {
		nlimits->revive_time = revive_time;
	}

	if (!isnan(revive_jitter)) {
		nlimits->revive_jitter = revive_jitter;
	}

	if (!isnan(error_time)) {
		nlimits->error_time = error_time;
	}

	if (!isnan(dns_timeout)) {
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

void rspamd_upstreams_add_watch_callback(struct upstream_list *ups,
										 enum rspamd_upstreams_watch_event events,
										 rspamd_upstream_watch_func func,
										 GFreeFunc dtor,
										 gpointer ud)
{
	struct upstream_list_watcher *nw;

	g_assert((events & RSPAMD_UPSTREAM_WATCH_ALL) != 0);

	nw = g_malloc(sizeof(*nw));
	nw->func = func;
	nw->events_mask = events;
	nw->ud = ud;
	nw->dtor = dtor;

	DL_APPEND(ups->watchers, nw);
}

enum rspamd_upstream_rotation
rspamd_upstreams_get_rotation(struct upstream_list *ups)
{
	if (ups == NULL) {
		return RSPAMD_UPSTREAM_UNDEF;
	}
	return ups->rot_alg;
}

void rspamd_upstreams_set_token_bucket(struct upstream_list *ups,
									   gsize max_tokens,
									   gsize scale_factor,
									   gsize min_tokens,
									   gsize base_cost)
{
	struct upstream_limits *nlimits;
	g_assert(ups != NULL);
	g_assert(ups->ctx != NULL && ups->ctx->pool != NULL);

	nlimits = rspamd_mempool_alloc(ups->ctx->pool, sizeof(*nlimits));
	memcpy(nlimits, ups->limits, sizeof(*nlimits));

	if (max_tokens > 0) {
		nlimits->token_bucket_max = max_tokens;
		/* Keep refill rate proportional: full bucket regenerates in 60s. */
		nlimits->token_bucket_refill_per_s = max_tokens / 60;
		if (nlimits->token_bucket_refill_per_s == 0) {
			nlimits->token_bucket_refill_per_s = 1;
		}
	}
	if (scale_factor > 0) {
		nlimits->token_bucket_scale = scale_factor;
	}
	if (min_tokens > 0) {
		nlimits->token_bucket_min = min_tokens;
	}
	if (base_cost > 0) {
		nlimits->token_bucket_base_cost = base_cost;
	}

	ups->limits = nlimits;
}

void rspamd_upstreams_set_slow_start(struct upstream_list *ups,
									 unsigned int slow_start_ms)
{
	struct upstream_limits *nlimits;
	g_assert(ups != NULL);
	g_assert(ups->ctx != NULL && ups->ctx->pool != NULL);

	nlimits = rspamd_mempool_alloc(ups->ctx->pool, sizeof(*nlimits));
	memcpy(nlimits, ups->limits, sizeof(*nlimits));
	nlimits->slow_start_ms = slow_start_ms;
	ups->limits = nlimits;
}

void rspamd_upstreams_set_latency_half_life(struct upstream_list *ups,
											double half_life_s)
{
	struct upstream_limits *nlimits;
	g_assert(ups != NULL);
	g_assert(ups->ctx != NULL && ups->ctx->pool != NULL);

	if (half_life_s < 0) {
		half_life_s = 0;
	}
	nlimits = rspamd_mempool_alloc(ups->ctx->pool, sizeof(*nlimits));
	memcpy(nlimits, ups->limits, sizeof(*nlimits));
	nlimits->latency_half_life_s = half_life_s;
	ups->limits = nlimits;
}

/*
 * Time-weighted EWMA for latency. Older samples decay so that a
 * once-slow-but-recovered upstream isn't forever penalised.
 *
 * Mathematically: alpha = 1 - exp(-dt / tau), where tau is set so the
 * weight halves over `latency_half_life_s` of wall time. tau = hl/ln(2).
 *
 * If half_life is 0 we degrade to a flat moving average where every
 * sample has equal weight regardless of arrival time.
 */
void rspamd_upstream_record_latency(struct upstream *up, double seconds)
{
	double now;
	double dt;
	double tau;
	double alpha;
	double half_life;

	if (up == NULL || seconds < 0) {
		return;
	}

	RSPAMD_UPSTREAM_LOCK(up);

	if (up->ctx && up->ctx->event_loop) {
		now = ev_now(up->ctx->event_loop);
	}
	else {
		now = rspamd_get_ticks(FALSE);
	}

	if (up->latency_n == 0 || up->latency_last_at <= 0) {
		up->latency_ewma = seconds;
	}
	else {
		half_life = up->ls ? up->ls->limits->latency_half_life_s : DEFAULT_LATENCY_HALF_LIFE_S;
		if (half_life <= 0) {
			/* Flat moving average. */
			alpha = 1.0 / (double) (up->latency_n + 1);
		}
		else {
			dt = now - up->latency_last_at;
			if (dt < 0.0) {
				dt = 0.0;
			}
			tau = half_life / 0.6931471805599453; /* ln(2) */
			alpha = 1.0 - exp(-dt / tau);
			/* Cap so we never wholly forget the prior estimate. */
			if (alpha > 0.5) alpha = 0.5;
			if (alpha < 0.01) alpha = 0.01;
		}
		up->latency_ewma = alpha * seconds + (1.0 - alpha) * up->latency_ewma;
	}

	up->latency_last_at = now;
	if (up->latency_n < UINT_MAX) {
		up->latency_n++;
	}

	RSPAMD_UPSTREAM_UNLOCK(up);
}

double rspamd_upstream_get_latency(const struct upstream *up)
{
	if (up == NULL) {
		return 0.0;
	}
	return up->latency_ewma;
}

/*
 * Calculate token cost for a message of given size
 */
static inline gsize
rspamd_upstream_calculate_tokens(const struct upstream_limits *limits,
								 gsize message_size)
{
	return limits->token_bucket_base_cost +
		   (message_size / limits->token_bucket_scale);
}

/*
 * Lazy per-upstream token bucket initialization. Called from selection paths
 * to ensure max_tokens is set for upstreams that joined before the rotation
 * algorithm was switched to TOKEN_BUCKET.
 */
static inline void
rspamd_upstream_ensure_tokens(struct upstream_list *ups, struct upstream *up)
{
	if (up->max_tokens == 0) {
		up->max_tokens = ups->limits->token_bucket_max;
		up->available_tokens = up->max_tokens;
		up->inflight_tokens = 0;
		up->last_refill_at = 0;
	}
}

/*
 * Lazy time-based refill. Adds floor(dt * refill_per_s) tokens to
 * available_tokens, capped at max_tokens. Called from selection and return
 * paths so that an upstream that has been quiet (or that lost tokens to a
 * failure) gradually regains capacity without any timer fan-out.
 */
static inline void
rspamd_upstream_refill_tokens(struct upstream *up,
							  const struct upstream_limits *limits,
							  double now)
{
	gsize add;
	double dt;

	if (limits->token_bucket_refill_per_s == 0 || up->max_tokens == 0) {
		up->last_refill_at = now;
		return;
	}

	if (up->last_refill_at <= 0) {
		up->last_refill_at = now;
		return;
	}

	dt = now - up->last_refill_at;
	if (dt <= 0) {
		return;
	}

	add = (gsize) (dt * (double) limits->token_bucket_refill_per_s);
	if (add == 0) {
		/* Don't update last_refill_at; let small increments accumulate. */
		return;
	}

	if (up->available_tokens + add < up->available_tokens) {
		/* Overflow guard */
		up->available_tokens = up->max_tokens;
	}
	else {
		up->available_tokens += add;
		if (up->available_tokens > up->max_tokens) {
			up->available_tokens = up->max_tokens;
		}
	}
	up->last_refill_at = now;
}

static inline double
rspamd_upstream_now(const struct upstream *up)
{
	if (up->ctx && up->ctx->event_loop) {
		return ev_now(up->ctx->event_loop);
	}
	return rspamd_get_ticks(FALSE);
}

struct upstream *
rspamd_upstream_get_token_bucket(struct upstream_list *ups,
								 struct upstream *except,
								 gsize message_size,
								 gsize *reserved_tokens)
{
	struct upstream *selected = NULL;
	struct upstream *fallback = NULL;
	gsize best_eligible_inflight = G_MAXSIZE;
	gsize least_loaded_inflight = G_MAXSIZE;
	gsize token_cost;
	unsigned int i;

	if (ups == NULL || reserved_tokens == NULL) {
		return NULL;
	}

	*reserved_tokens = 0;

	RSPAMD_UPSTREAM_LOCK(ups);

	/* Handle empty alive list same as other algorithms */
	if (ups->alive->len == 0) {
		RSPAMD_UPSTREAM_UNLOCK(ups);
		return NULL;
	}

	token_cost = rspamd_upstream_calculate_tokens(ups->limits, message_size);

	double now;
	if (ups->ctx && ups->ctx->event_loop) {
		now = ev_now(ups->ctx->event_loop);
	}
	else {
		now = rspamd_get_ticks(FALSE);
	}

	/*
	 * Linear scan over alive[]: prefer the lowest-inflight upstream that has
	 * sufficient available tokens. If no upstream is eligible, fall back to
	 * the least-loaded one (whose available_tokens we will clamp to 0).
	 *
	 * Alive sets are typically small (2-10); a flat scan is faster than a
	 * heap once you account for the by-value heap macros' O(n) repair cost.
	 */
	for (i = 0; i < ups->alive->len; i++) {
		struct upstream *up = g_ptr_array_index(ups->alive, i);

		if (except != NULL && up == except) {
			continue;
		}

		rspamd_upstream_ensure_tokens(ups, up);
		rspamd_upstream_refill_tokens(up, ups->limits, now);

		if (up->inflight_tokens < least_loaded_inflight) {
			least_loaded_inflight = up->inflight_tokens;
			fallback = up;
		}

		if (up->available_tokens >= token_cost &&
			up->inflight_tokens < best_eligible_inflight) {
			best_eligible_inflight = up->inflight_tokens;
			selected = up;
		}
	}

	if (selected == NULL) {
		selected = fallback;
	}

	if (selected != NULL) {
		if (selected->available_tokens >= token_cost) {
			selected->available_tokens -= token_cost;
		}
		else {
			selected->available_tokens = 0;
		}
		selected->inflight_tokens += token_cost;
		*reserved_tokens = token_cost;
		selected->checked++;
		selected->inflight++; /* paired with ok()/fail() decrement */
	}

	RSPAMD_UPSTREAM_UNLOCK(ups);

	return selected;
}

void rspamd_upstream_return_tokens(struct upstream *up, gsize tokens, gboolean success)
{
	struct upstream_list *ls;

	if (up == NULL || tokens == 0) {
		return;
	}

	ls = up->ls;

	if (ls) {
		RSPAMD_UPSTREAM_LOCK(ls);
	}
	RSPAMD_UPSTREAM_LOCK(up);

	/* Return tokens from inflight */
	if (up->inflight_tokens >= tokens) {
		up->inflight_tokens -= tokens;
	}
	else {
		msg_warn("upstream %s: returning %z tokens but only %z inflight (possible double-return)",
				 up->name, tokens, up->inflight_tokens);
		up->inflight_tokens = 0;
	}

	/* Only restore available tokens on success; failure relies on lazy
	 * refill below to gradually restore capacity. */
	if (success) {
		up->available_tokens += tokens;
		/* Cap at max tokens */
		if (up->available_tokens > up->max_tokens) {
			up->available_tokens = up->max_tokens;
		}
	}

	/* Lazy refill makes failure non-permanent: a flapping upstream that
	 * loses tokens to failures regains them over time when the bucket is
	 * touched. */
	if (ls != NULL) {
		rspamd_upstream_refill_tokens(up, ls->limits, rspamd_upstream_now(up));
	}

	RSPAMD_UPSTREAM_UNLOCK(up);
	if (ls) {
		RSPAMD_UPSTREAM_UNLOCK(ls);
	}
}

struct upstream *
rspamd_upstream_ref(struct upstream *up)
{
	REF_RETAIN(up);
	return up;
}

void rspamd_upstream_unref(struct upstream *up)
{
	REF_RELEASE(up);
}
