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

struct upstream_inet_addr_entry {
	rspamd_inet_addr_t *addr;
	struct upstream_inet_addr_entry *next;
};

struct upstream_addr_elt {
	rspamd_inet_addr_t *addr;
	guint errors;
};

struct upstream {
	guint weight;
	guint cur_weight;
	guint errors;
	guint dns_requests;
	gint active_idx;
	gchar *name;
	struct event ev;
	struct timeval tv;
	gpointer ud;
	struct upstream_list *ls;
	GList *ctx_pos;
	struct upstream_ctx *ctx;

	struct {
		GPtrArray *addr; /* struct upstream_addr_elt */
		guint cur;
	} addrs;

	struct upstream_inet_addr_entry *new_addrs;
	rspamd_mutex_t *lock;
	gpointer data;
	ref_entry_t ref;
};

struct upstream_list {
	struct upstream_ctx *ctx;
	GPtrArray *ups;
	GPtrArray *alive;
	rspamd_mutex_t *lock;
	guint64 hash_seed;
	guint cur_elt;
	enum rspamd_upstream_flag flags;
	enum rspamd_upstream_rotation rot_alg;
};

struct upstream_ctx {
	struct rdns_resolver *res;
	struct event_base *ev_base;
	guint max_errors;
	gdouble revive_time;
	gdouble revive_jitter;
	gdouble error_time;
	gdouble dns_timeout;
	guint dns_retransmits;
	GQueue *upstreams;
	gboolean configured;
	ref_entry_t ref;
};

#ifndef UPSTREAMS_THREAD_SAFE
#define RSPAMD_UPSTREAM_LOCK(x) do { } while (0)
#define RSPAMD_UPSTREAM_UNLOCK(x) do { } while (0)
#else
#define RSPAMD_UPSTREAM_LOCK(x) rspamd_mutex_lock(x)
#define RSPAMD_UPSTREAM_UNLOCK(x) rspamd_mutex_unlock(x)
#endif

/* 4 errors in 10 seconds */
static guint default_max_errors = 4;
static gdouble default_revive_time = 60;
static gdouble default_revive_jitter = 0.4;
static gdouble default_error_time = 10;
static gdouble default_dns_timeout = 1.0;
static guint default_dns_retransmits = 2;

void
rspamd_upstreams_library_config (struct rspamd_config *cfg,
		struct upstream_ctx *ctx, struct event_base *ev_base,
		struct rdns_resolver *resolver)
{
	g_assert (ctx != NULL);
	g_assert (cfg != NULL);

	if (cfg->upstream_error_time) {
		ctx->error_time = cfg->upstream_error_time;
	}
	if (cfg->upstream_max_errors) {
		ctx->max_errors = cfg->upstream_max_errors;
	}
	if (cfg->upstream_revive_time) {
		ctx->revive_time = cfg->upstream_max_errors;
	}
	if (cfg->dns_retransmits) {
		ctx->dns_retransmits = cfg->dns_retransmits;
	}
	if (cfg->dns_timeout) {
		ctx->dns_timeout = cfg->dns_timeout;
	}

	ctx->ev_base = ev_base;
	ctx->res = resolver;
	ctx->configured = TRUE;
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
	g_slice_free1 (sizeof (*ctx), ctx);
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

	ctx = g_slice_alloc0 (sizeof (*ctx));
	ctx->error_time = default_error_time;
	ctx->max_errors = default_max_errors;
	ctx->dns_retransmits = default_dns_retransmits;
	ctx->dns_timeout = default_dns_timeout;
	ctx->revive_jitter = default_revive_jitter;
	ctx->revive_time = default_revive_time;

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
	const struct upstream_addr_elt **ip1 = (const struct upstream_addr_elt **)a,
			**ip2 = (const struct upstream_addr_elt **)b;
	gint w1, w2;

	w1 = rspamd_upstream_af_to_weight ((*ip1)->addr);
	w2 = rspamd_upstream_af_to_weight ((*ip2)->addr);

	return w2 - w1;
}

static void
rspamd_upstream_set_active (struct upstream_list *ls, struct upstream *up)
{
	RSPAMD_UPSTREAM_LOCK (ls->lock);
	g_ptr_array_add (ls->alive, up);
	up->active_idx = ls->alive->len - 1;
	RSPAMD_UPSTREAM_UNLOCK (ls->lock);
}

static void
rspamd_upstream_addr_elt_dtor (gpointer a)
{
	struct upstream_addr_elt *elt = a;

	rspamd_inet_address_destroy (elt->addr);
	g_slice_free1 (sizeof (*elt), elt);
}

static void
rspamd_upstream_update_addrs (struct upstream *up)
{
	guint16 port;
	guint addr_cnt;
	struct upstream_inet_addr_entry *cur, *tmp;
	GPtrArray *new_addrs;
	struct upstream_addr_elt *addr_elt;

	/*
	 * We need first of all get the saved port, since DNS gives us no
	 * idea about what port has been used previously
	 */
	RSPAMD_UPSTREAM_LOCK (up->lock);

	if (up->addrs.addr->len > 0 && up->new_addrs) {
		addr_elt = g_ptr_array_index (up->addrs.addr, 0);
		port = rspamd_inet_address_get_port (addr_elt->addr);

		/* Free old addresses */
		g_ptr_array_free (up->addrs.addr, TRUE);

		/* Now calculate new addrs count */
		addr_cnt = 0;
		LL_FOREACH (up->new_addrs, cur) {
			addr_cnt++;
		}
		new_addrs = g_ptr_array_new_full (addr_cnt, rspamd_upstream_addr_elt_dtor);

		/* Copy addrs back */
		LL_FOREACH (up->new_addrs, cur) {
			rspamd_inet_address_set_port (cur->addr, port);
			addr_elt = g_slice_alloc (sizeof (*addr_elt));
			addr_elt->addr = cur->addr;
			addr_elt->errors = 0;
			g_ptr_array_add (new_addrs, addr_elt);
		}

		up->addrs.cur = 0;
		up->addrs.addr = new_addrs;
		g_ptr_array_sort (up->addrs.addr, rspamd_upstream_addr_sort_func);
	}

	LL_FOREACH_SAFE (up->new_addrs, cur, tmp) {
		/* Do not free inet address pointer since it has been transferred to up */
		g_free (cur);
	}
	up->new_addrs = NULL;

	RSPAMD_UPSTREAM_UNLOCK (up->lock);
}

static void
rspamd_upstream_dns_cb (struct rdns_reply *reply, void *arg)
{
	struct upstream *up = (struct upstream *)arg;
	struct rdns_reply_entry *entry;
	struct upstream_inet_addr_entry *up_ent;

	if (reply->code == RDNS_RC_NOERROR) {
		entry = reply->entries;

		RSPAMD_UPSTREAM_LOCK (up->lock);
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

		RSPAMD_UPSTREAM_UNLOCK (up->lock);
	}

	up->dns_requests--;

	if (up->dns_requests == 0) {
		rspamd_upstream_update_addrs (up);
	}

	REF_RELEASE (up);
}

static void
rspamd_upstream_revive_cb (int fd, short what, void *arg)
{
	struct upstream *up = (struct upstream *)arg;

	RSPAMD_UPSTREAM_LOCK (up->lock);
	event_del (&up->ev);
	if (up->ls) {
		rspamd_upstream_set_active (up->ls, up);
	}

	RSPAMD_UPSTREAM_UNLOCK (up->lock);
	REF_RELEASE (up);
}

static void
rspamd_upstream_set_inactive (struct upstream_list *ls, struct upstream *up)
{
	gdouble ntim;
	guint i;
	struct upstream *cur;

	RSPAMD_UPSTREAM_LOCK (ls->lock);
	g_ptr_array_remove_index (ls->alive, up->active_idx);
	up->active_idx = -1;

	/* We need to update all indicies */
	for (i = 0; i < ls->alive->len; i ++) {
		cur = g_ptr_array_index (ls->alive, i);
		cur->active_idx = i;
	}

	if (up->ctx->res != NULL && up->ctx->configured &&
			!(ls->flags & RSPAMD_UPSTREAM_FLAG_NORESOLVE)) {
		/* Resolve name of the upstream one more time */
		if (up->name[0] != '/') {

			if (rdns_make_request_full (up->ctx->res, rspamd_upstream_dns_cb, up,
					up->ctx->dns_timeout, up->ctx->dns_retransmits,
					1, up->name, RDNS_REQUEST_A) != NULL) {
				up->dns_requests ++;
				REF_RETAIN (up);
			}

			if (rdns_make_request_full (up->ctx->res, rspamd_upstream_dns_cb, up,
					up->ctx->dns_timeout, up->ctx->dns_retransmits,
					1, up->name, RDNS_REQUEST_AAAA) != NULL) {
				up->dns_requests ++;
				REF_RETAIN (up);
			}
		}
	}

	REF_RETAIN (up);
	evtimer_set (&up->ev, rspamd_upstream_revive_cb, up);
	if (up->ctx->ev_base != NULL && up->ctx->configured) {
		event_base_set (up->ctx->ev_base, &up->ev);
	}

	ntim = rspamd_time_jitter (up->ctx->revive_time, up->ctx->revive_jitter);
	double_to_tv (ntim, &up->tv);
	event_add (&up->ev, &up->tv);

	RSPAMD_UPSTREAM_UNLOCK (ls->lock);
}

void
rspamd_upstream_fail (struct upstream *up)
{
	struct timeval tv;
	gdouble error_rate, max_error_rate;
	gdouble sec_last, sec_cur;
	struct upstream_addr_elt *addr_elt;

	if (up->active_idx != -1) {
		gettimeofday (&tv, NULL);

		RSPAMD_UPSTREAM_LOCK (up->lock);
		if (up->errors == 0) {
			/* We have the first error */
			up->tv = tv;
			up->errors = 1;
		}
		else {
			sec_last = tv_to_double (&up->tv);
			sec_cur = tv_to_double (&tv);

			if (sec_cur >= sec_last) {
				up->errors ++;

				if (sec_cur > sec_last) {
					error_rate = ((gdouble)up->errors) / (sec_cur - sec_last);
					max_error_rate = ((gdouble)up->ctx->max_errors) / up->ctx->error_time;
				}
				else {
					error_rate = 1;
					max_error_rate = 0;
				}

				if (up->ls->ups->len > 1 && error_rate > max_error_rate) {
					/* Remove upstream from the active list */
					up->errors = 0;
					rspamd_upstream_set_inactive (up->ls, up);
				}
			}
		}

		/* Also increase count of errors for this specific address */
		if (up->addrs.addr) {
			addr_elt = g_ptr_array_index (up->addrs.addr, up->addrs.cur);
			addr_elt->errors ++;
		}

		RSPAMD_UPSTREAM_UNLOCK (up->lock);
	}
}

void
rspamd_upstream_ok (struct upstream *up)
{
	struct upstream_addr_elt *addr_elt;

	RSPAMD_UPSTREAM_LOCK (up->lock);
	if (up->errors > 0 && up->active_idx != -1) {
		/* We touch upstream if and only if it is active */
		up->errors = 0;
		rspamd_upstream_set_active (up->ls, up);

		if (up->addrs.addr) {
			addr_elt = g_ptr_array_index (up->addrs.addr, up->addrs.cur);
			addr_elt->errors = 0;
		}
	}

	RSPAMD_UPSTREAM_UNLOCK (up->lock);
}

#define SEED_CONSTANT 0xa574de7df64e9b9dULL

struct upstream_list*
rspamd_upstreams_create (struct upstream_ctx *ctx)
{
	struct upstream_list *ls;

	ls = g_slice_alloc0 (sizeof (*ls));
	ls->hash_seed = SEED_CONSTANT;
	ls->ups = g_ptr_array_new ();
	ls->alive = g_ptr_array_new ();
	ls->lock = rspamd_mutex_new ();
	ls->cur_elt = 0;
	ls->ctx = ctx;
	ls->rot_alg = RSPAMD_UPSTREAM_UNDEF;

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
			rspamd_inet_address_destroy (cur->addr);
			g_free (cur);
		}
	}

	if (up->addrs.addr) {
		g_ptr_array_free (up->addrs.addr, TRUE);
	}

	rspamd_mutex_free (up->lock);
	g_free (up->name);

	if (up->ctx) {
		g_queue_delete_link (up->ctx->upstreams, up->ctx_pos);
		REF_RELEASE (up->ctx);
	}

	g_slice_free1 (sizeof (*up), up);
}

rspamd_inet_addr_t*
rspamd_upstream_addr (struct upstream *up)
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

const gchar*
rspamd_upstream_name (struct upstream *up)
{
	return up->name;
}

gboolean
rspamd_upstreams_add_upstream (struct upstream_list *ups,
		const gchar *str, guint16 def_port, void *data)
{
	struct upstream *up;
	GPtrArray *addrs = NULL;
	guint i;
	rspamd_inet_addr_t *addr;

	up = g_slice_alloc0 (sizeof (*up));

	if (!rspamd_parse_host_port_priority (str, &addrs,
			&up->weight,
			&up->name, def_port, NULL)) {
		g_slice_free1 (sizeof (*up), up);
		return FALSE;
	}
	else {
		for (i = 0; i < addrs->len; i ++) {
			addr = g_ptr_array_index (addrs, i);
			rspamd_upstream_add_addr (up, rspamd_inet_address_copy (addr));
		}

		g_ptr_array_free (addrs, TRUE);
	}

	if (up->weight == 0 && ups->rot_alg == RSPAMD_UPSTREAM_MASTER_SLAVE) {
		/* Special heuristic for master-slave rotation */
		if (ups->ups->len == 0) {
			/* Prioritize the first */
			up->weight = 1;
		}
	}

	g_ptr_array_add (ups->ups, up);
	up->ud = data;
	up->cur_weight = up->weight;
	up->ls = ups;
	REF_INIT_RETAIN (up, rspamd_upstream_dtor);
	up->lock = rspamd_mutex_new ();
	up->ctx = ups->ctx;
	REF_RETAIN (ups->ctx);
	g_queue_push_tail (ups->ctx->upstreams, up);
	up->ctx_pos = g_queue_peek_tail_link (ups->ctx->upstreams);
	g_ptr_array_sort (up->addrs.addr, rspamd_upstream_addr_sort_func);

	rspamd_upstream_set_active (ups, up);

	return TRUE;
}

void
rspamd_upstreams_set_flags (struct upstream_list *ups,
		enum rspamd_upstream_flag flags)
{
	ups->flags = flags;
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

	elt = g_slice_alloc0 (sizeof (*elt));
	elt->addr = addr;
	g_ptr_array_add (up->addrs.addr, elt);
	g_ptr_array_sort (up->addrs.addr, rspamd_upstream_addr_sort_func);

	return TRUE;
}

gboolean
rspamd_upstreams_parse_line (struct upstream_list *ups,
		const gchar *str, guint16 def_port, void *data)
{
	const gchar *end = str + strlen (str), *p = str;
	const gchar *separators = ";, \n\r\t";
	gchar *tmp;
	guint len;
	gboolean ret = FALSE;

	if (g_ascii_strncasecmp (p, "random:", sizeof ("random:") - 1) == 0) {
		ups->rot_alg = RSPAMD_UPSTREAM_RANDOM;
		p += sizeof ("random:") - 1;
	}
	else if (g_ascii_strncasecmp (p,
			"master-slave:",
			sizeof ("master-slave:") - 1) == 0) {
		ups->rot_alg = RSPAMD_UPSTREAM_MASTER_SLAVE;
		p += sizeof ("master-slave:") - 1;
	}
	else if (g_ascii_strncasecmp (p,
			"round-robin:",
			sizeof ("round-robin:") - 1) == 0) {
		ups->rot_alg = RSPAMD_UPSTREAM_ROUND_ROBIN;
		p += sizeof ("round-robin:") - 1;
	}
	else if (g_ascii_strncasecmp (p,
			"hash:",
			sizeof ("hash:") - 1) == 0) {
		ups->rot_alg = RSPAMD_UPSTREAM_HASHED;
		p += sizeof ("hash:") - 1;
	}
	else if (g_ascii_strncasecmp (p,
			"sequential:",
			sizeof ("sequential:") - 1) == 0) {
		ups->rot_alg = RSPAMD_UPSTREAM_SEQUENTIAL;
		p += sizeof ("sequential:") - 1;
	}

	while (p < end) {
		len = strcspn (p, separators);
		if (len > 0) {
			tmp = g_malloc (len + 1);
			rspamd_strlcpy (tmp, p, len + 1);
			if (rspamd_upstreams_add_upstream (ups, tmp, def_port, data)) {
				ret = TRUE;
			}
			else {
				g_free (tmp);
			}
		}
		p += len;
		/* Skip separators */
		p += strspn (p, separators);
	}

	return ret;
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

	if (ups != NULL) {
		g_ptr_array_free (ups->alive, TRUE);

		for (i = 0; i < ups->ups->len; i ++) {
			up = g_ptr_array_index (ups->ups, i);
			up->ls = NULL;
			REF_RELEASE (up);
		}

		g_ptr_array_free (ups->ups, TRUE);
		rspamd_mutex_free (ups->lock);
		g_slice_free1 (sizeof (*ups), ups);
	}
}

static void
rspamd_upstream_restore_cb (gpointer elt, gpointer ls)
{
	struct upstream *up = (struct upstream *)elt;
	struct upstream_list *ups = (struct upstream_list *)ls;

	/* Here the upstreams list is already locked */
	RSPAMD_UPSTREAM_LOCK (up->lock);

	if (event_get_base (&up->ev)) {
		event_del (&up->ev);
	}
	g_ptr_array_add (ups->alive, up);
	up->active_idx = ups->alive->len - 1;
	RSPAMD_UPSTREAM_UNLOCK (up->lock);
	/* For revive event */
	REF_RELEASE (up);
}

static struct upstream*
rspamd_upstream_get_random (struct upstream_list *ups)
{
	guint idx = ottery_rand_range (ups->alive->len - 1);

	return g_ptr_array_index (ups->alive, idx);
}

static struct upstream*
rspamd_upstream_get_round_robin (struct upstream_list *ups, gboolean use_cur)
{
	guint max_weight = 0;
	struct upstream *up, *selected = NULL;
	guint i;

	/* Select upstream with the maximum cur_weight */
	RSPAMD_UPSTREAM_LOCK (ups->lock);
	for (i = 0; i < ups->alive->len; i ++) {
		up = g_ptr_array_index (ups->alive, i);
		if (use_cur) {
			if (up->cur_weight >= max_weight) {
				selected = up;
				max_weight = up->cur_weight;
			}
		}
		else {
			if (up->weight >= max_weight) {
				selected = up;
				max_weight = up->weight;
			}
		}
	}

	if (max_weight == 0) {
		/*
		 * We actually don't have any weight information, so we could use
		 * random selection here
		 */
		selected = g_ptr_array_index (ups->alive,
				ottery_rand_range (ups->alive->len - 1));
	}

	if (use_cur && selected) {
		if (selected->cur_weight > 0) {
			selected->cur_weight--;
		}
		else {
			selected->cur_weight = selected->weight;
		}
	}

	RSPAMD_UPSTREAM_UNLOCK (ups->lock);

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
rspamd_upstream_get_hashed (struct upstream_list *ups, const guint8 *key, guint keylen)
{
	guint64 k;
	guint32 idx;

	/* Generate 64 bits input key */
	k = rspamd_cryptobox_fast_hash_specific (RSPAMD_CRYPTOBOX_XXHASH64,
			key, keylen, ups->hash_seed);

	RSPAMD_UPSTREAM_LOCK (ups->lock);
	idx = rspamd_consistent_hash (k, ups->alive->len);
	RSPAMD_UPSTREAM_UNLOCK (ups->lock);

	return g_ptr_array_index (ups->alive, idx);
}

static struct upstream*
rspamd_upstream_get_common (struct upstream_list *ups,
		enum rspamd_upstream_rotation default_type,
		const guchar *key, gsize keylen, gboolean forced)
{
	enum rspamd_upstream_rotation type;

	RSPAMD_UPSTREAM_LOCK (ups->lock);
	if (ups->alive->len == 0) {
		/* We have no upstreams alive */
		g_ptr_array_foreach (ups->ups, rspamd_upstream_restore_cb, ups);
	}
	RSPAMD_UPSTREAM_UNLOCK (ups->lock);

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
		return rspamd_upstream_get_random (ups);
	case RSPAMD_UPSTREAM_HASHED:
		return rspamd_upstream_get_hashed (ups, key, keylen);
	case RSPAMD_UPSTREAM_ROUND_ROBIN:
		return rspamd_upstream_get_round_robin (ups, TRUE);
	case RSPAMD_UPSTREAM_MASTER_SLAVE:
		return rspamd_upstream_get_round_robin (ups, FALSE);
	case RSPAMD_UPSTREAM_SEQUENTIAL:
		if (ups->cur_elt >= ups->alive->len) {
			ups->cur_elt = 0;
			return NULL;
		}

		return g_ptr_array_index (ups->alive, ups->cur_elt ++);
	}

	/* Silent stupid compilers */
	return NULL;
}

struct upstream*
rspamd_upstream_get (struct upstream_list *ups,
		enum rspamd_upstream_rotation default_type,
		const guchar *key, gsize keylen)
{
	return rspamd_upstream_get_common (ups, default_type, key, keylen, FALSE);
}

struct upstream*
rspamd_upstream_get_forced (struct upstream_list *ups,
		enum rspamd_upstream_rotation forced_type,
		const guchar *key, gsize keylen)
{
	return rspamd_upstream_get_common (ups, forced_type, key, keylen, TRUE);
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

		if (up->name[0] != '/' && ctx->res != NULL &&
				!(up->ls->flags & RSPAMD_UPSTREAM_FLAG_NORESOLVE)) {
			if (rdns_make_request_full (ctx->res,
					rspamd_upstream_dns_cb,
					up,
					ctx->dns_timeout,
					ctx->dns_retransmits,
					1,
					up->name,
					RDNS_REQUEST_A) != NULL) {
				up->dns_requests++;
				REF_RETAIN (up);
			}

			if (rdns_make_request_full (ctx->res,
					rspamd_upstream_dns_cb,
					up,
					ctx->dns_timeout,
					ctx->dns_retransmits,
					1,
					up->name,
					RDNS_REQUEST_AAAA) != NULL) {
				up->dns_requests++;
				REF_RETAIN (up);
			}
		}

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

		cb (up, ud);
	}
}
