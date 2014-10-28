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

	ref_entry_t ref;
};

struct upstream_list {
	GPtrArray *ups;
	GPtrArray *alive;
	rspamd_mutex_t *lock;
	guint hash_seed;
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

	event_del (&up->ev);
	if (up->ls) {
		rspamd_upstream_set_active (up->ls, up);

		if (up->new_addrs) {
			rspamd_upstream_update_addrs (up);
		}
	}

	REF_RELEASE (up);
}

static void
rspamd_upstream_set_inactive (struct upstream_list *ls, struct upstream *up)
{
	rspamd_mutex_lock (ls->lock);
	g_ptr_array_remove_index (ls->alive, up->active_idx);
	up->active_idx = -1;

	/* Resolve name of the upstream one more time */
	if (up->name[0] != '/') {
		REF_RETAIN (up);
		rdns_make_request_full (res, rspamd_upstream_dns_cb, up,
			default_dns_timeout, default_dns_retransmits,
			RDNS_REQUEST_A, up->name);
		REF_RETAIN (up);
		rdns_make_request_full (res, rspamd_upstream_dns_cb, up,
			default_dns_timeout, default_dns_retransmits,
			RDNS_REQUEST_AAAA, up->name);
	}

	REF_RETAIN (up);
	evtimer_set (&up->ev, rspamd_upstream_revive_cb, up);
	event_base_set (ev_base, &up->ev);
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
	gdouble error_rate, max_error_rate;

	if (g_atomic_int_compare_and_exchange (&up->errors, 0, 1)) {
		gettimeofday (&up->tv, NULL);
		up->errors ++;
	}
	else {
		g_atomic_int_inc (&up->errors);
	}

	gettimeofday (&tv, NULL);

	error_rate = ((gdouble)up->errors) / (tv.tv_sec - up->tv.tv_sec);
	max_error_rate = (gdouble)default_max_errors / (gdouble)default_error_time;

	if (error_rate > max_error_rate) {
		/* Remove upstream from the active list */
		rspamd_upstream_set_inactive (up->ls, up);
	}
}

void
rspamd_upstream_ok (struct upstream *up)
{
	if (up->errors > 0) {
		up->errors = 0;
		rspamd_upstream_set_active (up->ls, up);
	}

	/* Rotate weight of the alive upstream */
	up->cur_weight = up->cur_weight > 0 ? up->cur_weight -- : up->weight;
}

struct upstream_list*
rspamd_upstreams_create (void)
{
	struct upstream_list *ls;

	ls = g_slice_alloc (sizeof (*ls));
	ls->hash_seed = ottery_rand_unsigned ();
	ls->ups = g_ptr_array_new ();
	ls->alive = g_ptr_array_new ();
	ls->lock = rspamd_mutex_new ();

	return ls;
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

	g_free (up->name);
	g_slice_free1 (sizeof (*up), up);
}

rspamd_inet_addr_t*
rspamd_upstream_addr (struct upstream *up)
{
	return &up->addrs.addr[up->addrs.cur++ % up->addrs.count];
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
			&up->name, def_port)) {
		g_slice_free1 (sizeof (*up), up);
		return FALSE;
	}

	g_ptr_array_add (ups->ups, up);
	up->ud = data;
	up->cur_weight = up->weight;
	REF_INIT_RETAIN (up, rspamd_upstream_dtor);

	rspamd_upstream_set_active (ups, up);

	return TRUE;
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
