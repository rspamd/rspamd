/*
 * Copyright (c) 2009, Rambler media
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "main.h"
#include "events.h"

#undef RSPAMD_EVENTS_DEBUG

static gboolean
rspamd_event_equal (gconstpointer a, gconstpointer b)
{
	const struct rspamd_async_event  *ev1 = a, *ev2 = b;

	if (ev1->fin == ev2->fin) {
		return ev1->user_data == ev2->user_data;
	}

	return FALSE;
}

static guint
rspamd_event_hash (gconstpointer a)
{
	const struct rspamd_async_event  *ev = a;

	return GPOINTER_TO_UINT (ev->user_data);
}

struct rspamd_async_session    *
new_async_session (memory_pool_t * pool, event_finalizer_t fin,
		event_finalizer_t restore, event_finalizer_t cleanup, void *user_data)
{
	struct rspamd_async_session    *new;

	new = memory_pool_alloc (pool, sizeof (struct rspamd_async_session));
	new->pool = pool;
	new->fin = fin;
	new->restore = restore;
	new->cleanup = cleanup;
	new->user_data = user_data;
	new->wanna_die = FALSE;
	new->events = g_hash_table_new (rspamd_event_hash, rspamd_event_equal);
	new->threads = 0;

	memory_pool_add_destructor (pool, (pool_destruct_func) g_hash_table_destroy, new->events);

	return new;
}

void
register_async_event (struct rspamd_async_session *session, event_finalizer_t fin, void *user_data, gboolean forced)
{
	struct rspamd_async_event      *new;

	if (session == NULL) {
		msg_info ("session is NULL");
		return;
	}

	new = memory_pool_alloc (session->pool, sizeof (struct rspamd_async_event));
	new->fin = fin;
	new->user_data = user_data;

	g_hash_table_insert (session->events, new, new);
#ifdef RSPAMD_EVENTS_DEBUG
	msg_info ("added event: %p, pending %d events", user_data, g_hash_table_size (session->events));
#endif
}

void
remove_normal_event (struct rspamd_async_session *session, event_finalizer_t fin, void *ud)
{
	struct rspamd_async_event       search_ev;

	if (session == NULL) {
		msg_info ("session is NULL");
		return;
	}

	search_ev.fin = fin;
	search_ev.user_data = ud;
	if (g_hash_table_remove (session->events, &search_ev)) {
		fin (ud);
	}

#ifdef RSPAMD_EVENTS_DEBUG
	msg_info ("removed event: %p, pending %d events", ud, g_hash_table_size (session->events));
#endif

	check_session_pending (session);
}

static void
rspamd_session_destroy (gpointer k, gpointer v, gpointer unused)
{
	struct rspamd_async_event      *ev = v;

	/* Call event's finalizer */
	if (ev->fin != NULL) {
		ev->fin (ev->user_data);
	}
}

gboolean
destroy_session (struct rspamd_async_session *session)
{
	if (session == NULL) {
		msg_info ("session is NULL");
		return FALSE;
	}

	session->wanna_die = TRUE;

	g_hash_table_foreach (session->events, rspamd_session_destroy, session);

	if (session->threads == 0) {
		if (session->cleanup != NULL) {
			session->cleanup (session->user_data);
		}
		return TRUE;
	}

	return FALSE;
}

gboolean
check_session_pending (struct rspamd_async_session *session)
{
	if (session->threads == 0 && g_hash_table_size (session->events) == 0) {
		if (session->fin != NULL) {
			session->fin (session->user_data);
		}
		/* Check events count again */
		if (g_hash_table_size (session->events) != 0) {
			if (session->restore != NULL) {
				session->restore (session->user_data);
			}
			return TRUE;
		}
		return FALSE;
	}

	return TRUE;
}


/**
 * Add new async thread to session
 * @param session session object
 */
void
register_async_thread (struct rspamd_async_session *session)
{
	g_atomic_int_inc (&session->threads);
}

/**
 * Remove async thread from session and check whether session can be terminated
 * @param session session object
 */
void
remove_async_thread (struct rspamd_async_session *session)
{
	if (g_atomic_int_dec_and_test (&session->threads)) {
		(void) check_session_pending (session);
	}
}
