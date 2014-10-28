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

struct upstream {
	guint weight;
	guint cur_weight;
	guint errors;
	guint port;
	gint active_idx;
	gchar *name;
	struct event ev;
	struct timeval tv;
	gpointer ud;
	struct upstream_list *ls;
	rspamd_inet_addr_t addr;
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

	if (reply->code == RDNS_RC_NOERROR) {

	}

	REF_RELEASE (up);
}

static void
rspamd_revive_cb (int fd, short what, void *arg)
{
	struct upstream *up = (struct upstream *)arg;

	event_del (&up->ev);
	if (up->ls) {
		rspamd_upstream_set_active (up->ls, up);
	}

	REF_RELEASE (up);
}

static void
rspamd_upstream_set_inactive (struct upstream_list *ls, struct upstream *up)
{
	gint query_type = -1;

	rspamd_mutex_lock (ls->lock);
	g_ptr_array_remove_index (ls->alive, up->active_idx);
	up->active_idx = -1;
	/* Resolve name of the upstream one more time */
	if (up->addr.af == AF_INET) {
		query_type = RDNS_REQUEST_A;
	}
	else if (up->addr.af == AF_INET6) {
		query_type = RDNS_REQUEST_AAAA;
	}

	if (query_type != -1) {
		REF_RETAIN (up);
		rdns_make_request_full (res, rspamd_upstream_dns_cb, up,
			default_dns_timeout, default_dns_retransmits,
			RDNS_REQUEST_A, up->name);
	}

	REF_RETAIN (up);
	evtimer_set (&up->ev, rspamd_revive_cb, up);
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
	ls->ups = g_array_new (FALSE, TRUE, sizeof (struct upstream_list));
	ls->alive = g_ptr_array_new ();
	ls->lock = rspamd_mutex_new ();

	return ls;
}

static void
rspamd_upstream_dtor (struct upstream *up)
{
	g_free (up->name);
	g_slice_free1 (sizeof (*up), up);
}

rspamd_inet_addr_t*
rspamd_upstream_addr (struct upstream *up)
{
	return &up->addr;
}

gboolean
rspamd_upstreams_add_upstream (struct upstream_list *ups,
		const gchar *str, guint16 def_port, void *data)
{
	struct upstream *up;

	up = g_slice_alloc0 (sizeof (*up));

	if (!rspamd_parse_host_port_priority (str, &up->addr, &up->weight,
			&up->name, def_port)) {
		g_slice_free1 (sizeof (*up), up);
		return FALSE;
	}

	g_ptr_array_add (ups->ups, up);
	up->ud = data;
	up->cur_weight = up->weight;
	up->port = rspamd_inet_address_get_port (&up->addr);
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
