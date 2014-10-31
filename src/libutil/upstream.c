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
#include "rdns.h"
#include "xxhash.h"
#include "utlist.h"

struct upstream_inet_addr_entry {
	rspamd_inet_addr_t addr;
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
		rspamd_inet_addr_t *addr;
		guint count;
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
};

static struct rdns_resolver *res = NULL;
static struct event_base *ev_base = NULL;
/* 4 errors in 10 seconds */
const guint default_max_errors = 4;
const guint default_revive_time = 60;
const guint default_error_time = 10;
const gdouble default_dns_timeout = 1.0;
const guint default_dns_retransmits = 2;
const guint default_max_addresses = 1024;

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
				up_ent = g_malloc (sizeof (*up_ent));

				up_ent->addr.addr.s4.sin_addr = entry->content.a.addr;
				up_ent->addr.af = AF_INET;
				up_ent->addr.slen = sizeof (up_ent->addr.addr.s4);
				LL_PREPEND (up->new_addrs, up_ent);
			}
			else if (entry->type == RDNS_REQUEST_AAAA) {
				up_ent = g_malloc (sizeof (*up_ent));

				memcpy (&up_ent->addr.addr.s6.sin6_addr,
						&entry->content.aaa.addr, sizeof (struct in6_addr));
				up_ent->addr.af = AF_INET6;
				up_ent->addr.slen = sizeof (up_ent->addr.addr.s6);
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
	rspamd_inet_addr_t *new_addrs, *old;

	/*
	 * We need first of all get the saved port, since DNS gives us no
	 * idea about what port has been used previously
	 */
	if (up->addrs.count > 0 && up->new_addrs) {
		port = rspamd_inet_address_get_port (&up->addrs.addr[0]);

		/* Now calculate new addrs count */
		addr_cnt = 0;
		LL_FOREACH (up->new_addrs, cur) {
			addr_cnt ++;
		}
		new_addrs = g_new (rspamd_inet_addr_t, addr_cnt);

		/* Copy addrs back */
		addr_cnt = 0;
		LL_FOREACH (up->new_addrs, cur) {
			memcpy (&new_addrs[addr_cnt], cur, sizeof (rspamd_inet_addr_t));
			rspamd_inet_address_set_port (&new_addrs[addr_cnt], port);
			addr_cnt ++;
		}

		old = up->addrs.addr;
		up->addrs.cur = 0;
		up->addrs.count = addr_cnt;
		up->addrs.addr = new_addrs;
		g_free (old);
	}

	LL_FOREACH_SAFE (up->new_addrs, cur, tmp) {
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
	up->tv.tv_sec = default_revive_time;
	up->tv.tv_usec = 0;
	event_add (&up->ev, &up->tv);

	rspamd_mutex_unlock (ls->lock);
}

void
rspamd_upstreams_library_init (struct rdns_resolver *resolver,
		struct event_base *base)
{
	res = resolver;
	ev_base = base;
}

void
rspamd_upstream_fail (struct upstream *up)
{
	struct timeval tv;
	gdouble error_rate, max_error_rate, msec_last, msec_cur;

	rspamd_mutex_lock (up->lock);
	if (g_atomic_int_compare_and_exchange (&up->errors, 0, 1)) {
		gettimeofday (&up->tv, NULL);
		up->errors ++;
	}
	else {
		g_atomic_int_inc (&up->errors);
	}

	gettimeofday (&tv, NULL);

	msec_last = tv_to_msec (&up->tv) / 1000.;
	msec_cur = tv_to_msec (&tv) / 1000.;
	if (msec_cur > msec_last) {
		error_rate = ((gdouble)up->errors) / (msec_cur - msec_last);
		max_error_rate = (gdouble)default_max_errors / (gdouble)default_error_time;

		if (error_rate > max_error_rate) {
			/* Remove upstream from the active list */
			rspamd_upstream_set_inactive (up->ls, up);
		}
	}
	rspamd_mutex_unlock (up->lock);
}

void
rspamd_upstream_ok (struct upstream *up)
{
	rspamd_mutex_lock (up->lock);
	if (up->errors > 0) {
		up->errors = 0;
		rspamd_upstream_set_active (up->ls, up);
	}

	rspamd_mutex_unlock (up->lock);
}

struct upstream_list*
rspamd_upstreams_create (void)
{
	struct upstream_list *ls;

	ls = g_slice_alloc (sizeof (*ls));
	ottery_rand_bytes (&ls->hash_seed, sizeof (ls->hash_seed));
	ls->ups = g_ptr_array_new ();
	ls->alive = g_ptr_array_new ();
	ls->lock = rspamd_mutex_new ();

	return ls;
}

gsize
rspamd_upstreams_count (struct upstream_list *ups)
{
	return ups->ups->len;
}

static void
rspamd_upstream_dtor (struct upstream *up)
{
	struct upstream_inet_addr_entry *cur, *tmp;

	if (up->new_addrs) {
		LL_FOREACH_SAFE(up->new_addrs, cur, tmp) {
			g_free (cur);
		}
	}

	rspamd_mutex_free (up->lock);
	g_free (up->name);
	g_slice_free1 (sizeof (*up), up);
}

rspamd_inet_addr_t*
rspamd_upstream_addr (struct upstream *up)
{
	return &up->addrs.addr[up->addrs.cur++ % up->addrs.count];
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

	up->addrs.count = default_max_addresses;
	if (!rspamd_parse_host_port_priority (str, &up->addrs.addr,
			&up->addrs.count, &up->weight,
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

	rspamd_upstream_set_active (ups, up);

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
		}
		p += len + 1;
		/* Skip separators */
		p += strspn (p, separators) + 1;
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
	struct upstream *up, *selected;
	guint i;

	/* Select upstream with the maximum cur_weight */
	rspamd_mutex_lock (ups->lock);
	for (i = 0; i < ups->alive->len; i ++) {
		up = g_ptr_array_index (ups->alive, i);
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
	union {
		guint64 k64;
		guint32 k32[2];
	} h;

	guint32 idx;

	/* Generate 64 bits input key */
	h.k32[0] = XXH32 (key, keylen, ((guint32*)&ups->hash_seed)[0]);
	h.k32[1] = XXH32 (key, keylen, ((guint32*)&ups->hash_seed)[1]);

	rspamd_mutex_lock (ups->lock);
	idx = rspamd_consistent_hash (h.k64, ups->alive->len);
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
	}
}
