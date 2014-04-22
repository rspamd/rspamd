/* Copyright (c) 2010-2011, Vsevolod Stakhov
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
#include "main.h"
#include "message.h"
#include "lua/lua_common.h"

extern struct rspamd_main			*rspamd_main;

/**
 * Return worker's control structure by its type
 * @param type
 * @return worker's control structure or NULL
 */
worker_t*
get_worker_by_type (GQuark type)
{
	worker_t						**cur;

	cur = &workers[0];
	while (*cur) {
		if (g_quark_from_string ((*cur)->name) == type) {
			return *cur;
		}
		cur ++;
	}

	return NULL;
}

double
set_counter (const gchar *name, guint32 value)
{
	struct counter_data            *cd;
	double                          alpha;
	gchar                           *key;

	cd = rspamd_hash_lookup (rspamd_main->counters, (gpointer) name);

	if (cd == NULL) {
		cd = rspamd_mempool_alloc_shared (rspamd_main->counters->pool, sizeof (struct counter_data));
		cd->value = value;
		cd->number = 0;
		key = rspamd_mempool_strdup_shared (rspamd_main->counters->pool, name);
		rspamd_hash_insert (rspamd_main->counters, (gpointer) key, (gpointer) cd);
	}
	else {
		/* Calculate new value */
		rspamd_mempool_wlock_rwlock (rspamd_main->counters->lock);

		alpha = 2. / (++cd->number + 1);
		cd->value = cd->value * (1. - alpha) + value * alpha;

		rspamd_mempool_wunlock_rwlock (rspamd_main->counters->lock);
	}

	return cd->value;
}

struct event_base *
prepare_worker (struct rspamd_worker *worker, const char *name,
		rspamd_sig_handler_t sig_handler,
		void (*accept_handler)(int, short, void *))
{
	struct event_base                *ev_base;
	struct event                     *accept_event;
	struct sigaction                  signals;
	GList                             *cur;
	gint                               listen_socket;

#ifdef WITH_PROFILER
	extern void                     _start (void), etext (void);
	monstartup ((u_long) & _start, (u_long) & etext);
#endif

	gperf_profiler_init (worker->srv->cfg, name);

	worker->srv->pid = getpid ();

	ev_base = event_init ();

	init_signals (&signals, sig_handler);
	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);

	/* Accept all sockets */
	cur = worker->cf->listen_socks;
	while (cur) {
		listen_socket = GPOINTER_TO_INT (cur->data);
		if (listen_socket != -1) {
			accept_event = g_slice_alloc0 (sizeof (struct event));
			event_set (accept_event, listen_socket, EV_READ | EV_PERSIST,
					accept_handler, worker);
			event_base_set (ev_base, accept_event);
			event_add (accept_event, NULL);
			worker->accept_events = g_list_prepend (worker->accept_events, accept_event);
		}
		cur = g_list_next (cur);
	}

	return ev_base;
}

void
worker_stop_accept (struct rspamd_worker *worker)
{
	GList                             *cur;
	struct event                     *event;

	/* Remove all events */
	cur = worker->accept_events;
	while (cur) {
		event = cur->data;
		event_del (event);
		cur = g_list_next (cur);
		g_slice_free1 (sizeof (struct event), event);
	}

	if (worker->accept_events != NULL) {
		g_list_free (worker->accept_events);
	}
}
