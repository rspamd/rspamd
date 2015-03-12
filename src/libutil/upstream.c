/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
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
#include "upstream.h"
#include "ottery.h"
#include "ref.h"
#include "cfg_file.h"
#include "rdns.h"
#include "xxhash.h"
#include "utlist.h"

struct upstream_inet_addr_entry {
	rspamd_inet_addr_t *addr;
	struct upstream_inet_addr_entry *next;
};

struct upstream {
	guint weight;
	guint cur_weight;
	guint errors;
	gint active_idx;
	gchar *name;
	struct event ev;
	struct timeval tv;
	gpointer ud;
	struct upstream_list *ls;

	struct {
		GPtrArray *addr;
		guint cur;
	} addrs;

	struct upstream_inet_addr_entry *new_addrs;
	rspamd_mutex_t *lock;

	ref_entry_t ref;
};

struct upstream_list {
	GPtrArray *ups;
	GPtrArray *alive;
	rspamd_mutex_t *lock;
	guint64 hash_seed;
	guint cur_elt;
};

static struct rdns_resolver *res = NULL;
static struct event_base *ev_base = NULL;
/* 4 errors in 10 seconds */
static guint default_max_errors = 4;
static gdouble default_revive_time = 60;
static gdouble default_revive_jitter = 0.4;
static gdouble default_error_time = 10;
static gdouble default_dns_timeout = 1.0;
static guint default_dns_retransmits = 2;

void
rspamd_upstreams_library_config (struct rspamd_config *cfg)
{
	if (cfg->upstream_error_time) {
		default_error_time = cfg->upstream_error_time;
	}
	if (cfg->upstream_max_errors) {
		default_max_errors = cfg->upstream_max_errors;
	}
	if (cfg->upstream_revive_time) {
		default_revive_time = cfg->upstream_max_errors;
	}
	if (cfg->dns_retransmits) {
		default_dns_retransmits = cfg->dns_retransmits;
	}
	if (cfg->dns_timeout) {
		default_dns_timeout = cfg->dns_timeout;
	}
}

void
rspamd_upstreams_library_init (struct rdns_resolver *resolver,
		struct event_base *base)
{
	res = resolver;
	ev_base = base;
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
	const rspamd_inet_addr_t *ip1 = (const rspamd_inet_addr_t *)a,
			*ip2 = (const rspamd_inet_addr_t *)b;
	gint w1, w2;

	w1 = rspamd_upstream_af_to_weight (ip1);
	w2 = rspamd_upstream_af_to_weight (ip2);

	return w2 - w1;
}

static void
rspamd_upstream_set_active (struct upstream_list *ls, struct upstream *up)
{
	rspamd_mutex_lock (ls->lock);
	g_ptr_array_add (ls->alive, up);
	up->active_idx = ls->alive->len - 1;
	rspamd_mutex_unlock (ls->lock);
}

static void
rspamd_upstream_dns_cb (struct rdns_reply *reply, void *arg)
{
	struct upstream *up = (struct upstream *)arg;
	struct rdns_reply_entry *entry;
	struct upstream_inet_addr_entry *up_ent;

	if (reply->code == RDNS_RC_NOERROR) {
		entry = reply->entries;

		rspamd_mutex_lock (up->lock);
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
		rspamd_mutex_unlock (up->lock);
	}

	REF_RELEASE (up);
}

static void
rspamd_upstream_update_addrs (struct upstream *up)
{
	guint16 port;
	guint addr_cnt;
	struct upstream_inet_addr_entry *cur, *tmp;
	GPtrArray *new_addrs;

	/*
	 * We need first of all get the saved port, since DNS gives us no
	 * idea about what port has been used previously
	 */
	if (up->addrs.addr->len > 0 && up->new_addrs) {
		port = rspamd_inet_address_get_port (g_ptr_array_index (up->addrs.addr, 0));

		/* Free old addresses */
		g_ptr_array_free (up->addrs.addr, TRUE);

		/* Now calculate new addrs count */
		addr_cnt = 0;
		LL_FOREACH (up->new_addrs, cur) {
			addr_cnt ++;
		}
		new_addrs = g_ptr_array_new_full (addr_cnt,
				(GDestroyNotify)rspamd_inet_address_destroy);

		/* Copy addrs back */
		LL_FOREACH (up->new_addrs, cur) {
			rspamd_inet_address_set_port (cur->addr, port);
			g_ptr_array_add (new_addrs, cur->addr);
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
}

static void
rspamd_upstream_revive_cb (int fd, short what, void *arg)
{
	struct upstream *up = (struct upstream *)arg;

	rspamd_mutex_lock (up->lock);
	event_del (&up->ev);
	if (up->ls) {
		rspamd_upstream_set_active (up->ls, up);

		if (up->new_addrs) {
			rspamd_upstream_update_addrs (up);
		}
	}

	rspamd_mutex_unlock (up->lock);
	REF_RELEASE (up);
}

static void
rspamd_upstream_set_inactive (struct upstream_list *ls, struct upstream *up)
{
	gdouble ntim;

	rspamd_mutex_lock (ls->lock);
	g_ptr_array_remove_index (ls->alive, up->active_idx);
	up->active_idx = -1;

	if (res != NULL) {
		/* Resolve name of the upstream one more time */
		if (up->name[0] != '/') {
			REF_RETAIN (up);
			rdns_make_request_full (res, rspamd_upstream_dns_cb, up,
					default_dns_timeout, default_dns_retransmits,
					1, up->name, RDNS_REQUEST_A);
			REF_RETAIN (up);
			rdns_make_request_full (res, rspamd_upstream_dns_cb, up,
					default_dns_timeout, default_dns_retransmits,
					1, up->name, RDNS_REQUEST_AAAA);
		}
	}

	REF_RETAIN (up);
	evtimer_set (&up->ev, rspamd_upstream_revive_cb, up);
	if (ev_base != NULL) {
		event_base_set (ev_base, &up->ev);
	}

	ntim = default_revive_time + ottery_rand_range (
			default_revive_time * default_revive_jitter);
	double_to_tv (ntim, &up->tv);
	event_add (&up->ev, &up->tv);

	rspamd_mutex_unlock (ls->lock);
}

void
rspamd_upstream_fail (struct upstream *up)
{
	struct timeval tv;
	gdouble error_rate, max_error_rate;
	gint msec_last, msec_cur;

	gettimeofday (&tv, NULL);

	rspamd_mutex_lock (up->lock);
	if (up->errors == 0 && up->active_idx != -1) {
		/* We have the first error */
		up->tv = tv;
		up->errors = 1;
	}
	else if (up->active_idx != -1) {
		msec_last = tv_to_msec (&up->tv) / 1000.;
		msec_cur = tv_to_msec (&tv) / 1000.;
		if (msec_cur >= msec_last) {
			if (msec_cur > msec_last) {
				error_rate = ((gdouble)up->errors) / (msec_cur - msec_last);
				max_error_rate = (gdouble)default_max_errors / default_error_time;
			}
			else {
				error_rate = 1;
				max_error_rate = 0;
			}

			if (error_rate > max_error_rate && up->active_idx != -1) {
				/* Remove upstream from the active list */
				up->errors = 0;
				rspamd_upstream_set_inactive (up->ls, up);
			}
		}
	}
	rspamd_mutex_unlock (up->lock);
}

void
rspamd_upstream_ok (struct upstream *up)
{
	rspamd_mutex_lock (up->lock);
	if (up->errors > 0 && up->active_idx != -1) {
		/* We touch upstream if and only if it is active */
		up->errors = 0;
		rspamd_upstream_set_active (up->ls, up);
	}

	rspamd_mutex_unlock (up->lock);
}

#define SEED_CONSTANT 0xa574de7df64e9b9dULL

struct upstream_list*
rspamd_upstreams_create (void)
{
	struct upstream_list *ls;

	ls = g_slice_alloc (sizeof (*ls));
	ls->hash_seed = SEED_CONSTANT;
	ls->ups = g_ptr_array_new ();
	ls->alive = g_ptr_array_new ();
	ls->lock = rspamd_mutex_new ();
	ls->cur_elt = 0;

	return ls;
}

gsize
rspamd_upstreams_count (struct upstream_list *ups)
{
	return ups->ups->len;
}

gsize
rspamd_upstreams_alive (struct upstream_list *ups)
{
	return ups->alive->len;
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
	g_free (up->addrs.addr);
	g_slice_free1 (sizeof (*up), up);
}

rspamd_inet_addr_t*
rspamd_upstream_addr (struct upstream *up)
{
	gint idx, next_idx, w1, w2;
	/*
	 * We know that addresses are sorted in the way that ipv4 addresses come
	 * first. Therefore, we select only ipv4 addresses if they exist, since
	 * many systems now has poorly supported ipv6
	 */
	idx = up->addrs.cur;
	next_idx = (idx + 1) % up->addrs.addr->len;
	w1 = rspamd_upstream_af_to_weight (g_ptr_array_index (up->addrs.addr, idx));
	w2 = rspamd_upstream_af_to_weight (g_ptr_array_index (up->addrs.addr,
			next_idx));

	/*
	 * We don't care about the exact priorities, but we prefer ipv4/unix
	 * addresses before any ipv6 addresses
	 */
	if (!w1 || w2) {
		up->addrs.cur = next_idx;
	}
	else {
		up->addrs.cur = 0;
	}

	return g_ptr_array_index (up->addrs.addr, up->addrs.cur);
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

	up = g_slice_alloc0 (sizeof (*up));

	if (!rspamd_parse_host_port_priority (str, &up->addrs.addr,
			&up->weight,
			&up->name, def_port, NULL)) {
		g_slice_free1 (sizeof (*up), up);
		return FALSE;
	}

	g_ptr_array_add (ups->ups, up);
	up->ud = data;
	up->cur_weight = up->weight;
	up->ls = ups;
	REF_INIT_RETAIN (up, rspamd_upstream_dtor);
	up->lock = rspamd_mutex_new ();
	g_ptr_array_sort (up->addrs.addr, rspamd_upstream_addr_sort_func);

	rspamd_upstream_set_active (ups, up);

	return TRUE;
}

gboolean
rspamd_upstream_add_addr (struct upstream *up, rspamd_inet_addr_t *addr)
{
	/*
	 * XXX: slow and inefficient
	 */
	g_ptr_array_add (up->addrs.addr, addr);
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

	if (ucl_object_type (in) == UCL_ARRAY) {
		while ((cur = ucl_iterate_object (in, &it, true)) != NULL) {
			if (rspamd_upstreams_from_ucl (ups, cur, def_port, data)) {
				ret = TRUE;
			}
		}
	}
	else if (ucl_object_type (in) == UCL_STRING) {
		ret = rspamd_upstreams_parse_line (ups, ucl_object_tostring (in),
				def_port, data);
	}

	return ret;
}

void
rspamd_upstreams_destroy (struct upstream_list *ups)
{
	guint i;
	struct upstream *up;

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

static void
rspamd_upstream_restore_cb (gpointer elt, gpointer ls)
{
	struct upstream *up = (struct upstream *)elt;
	struct upstream_list *ups = (struct upstream_list *)ls;

	/* Here the upstreams list is already locked */
	rspamd_mutex_lock (up->lock);
	event_del (&up->ev);

	if (up->new_addrs) {
		rspamd_upstream_update_addrs (up);
	}

	g_ptr_array_add (ups->alive, up);
	up->active_idx = ups->alive->len - 1;
	rspamd_mutex_unlock (up->lock);
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
	rspamd_mutex_lock (ups->lock);
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

	if (use_cur) {
		if (selected->cur_weight > 0) {
			selected->cur_weight--;
		}
		else {
			selected->cur_weight = selected->weight;
		}
	}
	rspamd_mutex_unlock (ups->lock);

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
	k = XXH64 (key, keylen, ups->hash_seed);

	rspamd_mutex_lock (ups->lock);
	idx = rspamd_consistent_hash (k, ups->alive->len);
	rspamd_mutex_unlock (ups->lock);

	return g_ptr_array_index (ups->alive, idx);
}

struct upstream*
rspamd_upstream_get (struct upstream_list *ups,
		enum rspamd_upstream_rotation type, ...)
{
	va_list ap;
	const guint8 *key;
	guint keylen;

	rspamd_mutex_lock (ups->lock);
	if (ups->alive->len == 0) {
		/* We have no upstreams alive */
		g_ptr_array_foreach (ups->ups, rspamd_upstream_restore_cb, ups);
	}
	rspamd_mutex_unlock (ups->lock);

	switch (type) {
	case RSPAMD_UPSTREAM_RANDOM:
		return rspamd_upstream_get_random (ups);
	case RSPAMD_UPSTREAM_HASHED:
		va_start (ap, type);
		key = va_arg (ap, const guint8 *);
		keylen = va_arg (ap, guint);
		va_end (ap);
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
