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

struct upstream {
	guint weight;
	guint cur_weight;
	guint errors;
	guint port;
	guint active_idx;
	gchar *name;
	struct event ev;
	struct timeval tv;
	gpointer ud;
	struct upstream_list *ls;
	rspamd_inet_addr_t addr;
};

struct upstream_list {
	GArray *ups;
	GPtrArray *alive;
	rspamd_mutex_t *lock;
	guint hash_seed;
};

static struct rdns_resolver *res = NULL;
static struct event_base *ev_base = NULL;
const guint default_max_errors = 4;

static void
rspamd_upstream_set_inactive (struct upstream_list *ls, struct upstream *up)
{
	rspamd_mutex_lock (ls->lock);
	g_ptr_array_remove_index (ls->alive, up->active_idx);
	up->active_idx = 0;
	rspamd_mutex_unlock (ls->lock);
}

static void
rspamd_upstream_set_active (struct upstream_list *ls, struct upstream *up)
{
	rspamd_mutex_lock (ls->lock);
	g_ptr_array_add (ls->alive, up);
	up->active_idx = ls->alive->len - 1;
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
	if (g_atomic_int_compare_and_exchange (&up->errors, 0, 1)) {
		gettimeofday (&up->tv, NULL);
		up->errors ++;
	}
	else {
		g_atomic_int_inc (&up->errors);
	}

	if (g_atomic_int_compare_and_exchange (&up->errors, default_max_errors, 0)) {
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


rspamd_inet_addr_t*
rspamd_upstream_addr (struct upstream *up)
{
	return &up->addr;
}
