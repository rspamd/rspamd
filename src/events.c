/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
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

#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
static void
event_mutex_free (gpointer data)
{
	GMutex						   *mtx = data;

	g_mutex_free (mtx);
}

static void
event_cond_free (gpointer data)
{
	GCond						   *cond = data;

	g_cond_free (cond);
}
#endif

struct rspamd_async_session    *
new_async_session (memory_pool_t * pool, session_finalizer_t fin,
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
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
	new->mtx = g_mutex_new ();
	new->cond = g_cond_new ();
	memory_pool_add_destructor (pool, (pool_destruct_func) event_mutex_free, new->mtx);
	memory_pool_add_destructor (pool, (pool_destruct_func) event_cond_free, new->cond);
#else
	new->mtx = memory_pool_alloc (pool, sizeof (GMutex));
	g_mutex_init (new->mtx);
	new->cond = memory_pool_alloc (pool, sizeof (GCond));
	g_cond_init (new->cond);
	memory_pool_add_destructor (pool, (pool_destruct_func) g_mutex_clear, new->mtx);
	memory_pool_add_destructor (pool, (pool_destruct_func) g_cond_clear, new->cond);
#endif
	new->threads = 0;

	memory_pool_add_destructor (pool, (pool_destruct_func) g_hash_table_destroy, new->events);

	return new;
}

void
register_async_event (struct rspamd_async_session *session, event_finalizer_t fin, void *user_data, GQuark subsystem)
{
	struct rspamd_async_event      *new;

	if (session == NULL) {
		msg_info ("session is NULL");
		return;
	}

	g_mutex_lock (session->mtx);
	new = memory_pool_alloc (session->pool, sizeof (struct rspamd_async_event));
	new->fin = fin;
	new->user_data = user_data;
	new->subsystem = subsystem;

	g_hash_table_insert (session->events, new, new);
#ifdef RSPAMD_EVENTS_DEBUG
	msg_info ("added event: %p, pending %d events, subsystem: %s", user_data, g_hash_table_size (session->events),
			g_quark_to_string (subsystem));
#endif
	g_mutex_unlock (session->mtx);
}

void
remove_normal_event (struct rspamd_async_session *session, event_finalizer_t fin, void *ud)
{
	struct rspamd_async_event       search_ev, *found_ev;

	if (session == NULL) {
		msg_info ("session is NULL");
		return;
	}

	g_mutex_lock (session->mtx);
	/* Search for event */
	search_ev.fin = fin;
	search_ev.user_data = ud;
	if ((found_ev = g_hash_table_lookup (session->events, &search_ev)) != NULL) {
		g_hash_table_remove (session->events, found_ev);
#ifdef RSPAMD_EVENTS_DEBUG
		msg_info ("removed event: %p, subsystem: %s, pending %d events", ud,
			g_quark_to_string (found_ev->subsystem), g_hash_table_size (session->events));
#endif
		/* Remove event */
		fin (ud);
	}
	g_mutex_unlock (session->mtx);

	check_session_pending (session);
}

static gboolean
rspamd_session_destroy (gpointer k, gpointer v, gpointer unused)
{
	struct rspamd_async_event      *ev = v;

	/* Call event's finalizer */
	if (ev->fin != NULL) {
		ev->fin (ev->user_data);
	}

	return TRUE;
}

gboolean
destroy_session (struct rspamd_async_session *session)
{
	if (session == NULL) {
		msg_info ("session is NULL");
		return FALSE;
	}

	g_mutex_lock (session->mtx);
	if (session->threads > 0) {
	/* Wait for conditional variable to finish processing */
		g_mutex_unlock (session->mtx);
		g_cond_wait (session->cond, session->mtx);
	}

	session->wanna_die = TRUE;

	g_hash_table_foreach_remove (session->events, rspamd_session_destroy, session);

	/* Mutex can be destroyed here */
	g_mutex_unlock (session->mtx);

	if (session->cleanup != NULL) {
		session->cleanup (session->user_data);
	}
	return TRUE;
}

gboolean
check_session_pending (struct rspamd_async_session *session)
{
	g_mutex_lock (session->mtx);
	if (session->wanna_die && g_hash_table_size (session->events) == 0) {
		session->wanna_die = FALSE;
		if (session->threads > 0) {
			/* Wait for conditional variable to finish processing */
			g_cond_wait (session->cond, session->mtx);
		}
		if (session->fin != NULL) {
			if (! session->fin (session->user_data)) {
				g_mutex_unlock (session->mtx);
				/* Session finished incompletely, perform restoration */
				if (session->restore != NULL) {
					session->restore (session->user_data);
					/* Call pending once more */
					return check_session_pending (session);
				}
				return TRUE;
			}
		}
		g_mutex_unlock (session->mtx);
		return FALSE;
	}
	g_mutex_unlock (session->mtx);
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
#ifdef RSPAMD_EVENTS_DEBUG
	msg_info ("added thread: pending %d thread", session->threads);
#endif
}

/**
 * Remove async thread from session and check whether session can be terminated
 * @param session session object
 */
void
remove_async_thread (struct rspamd_async_session *session)
{
	if (g_atomic_int_dec_and_test (&session->threads)) {
		/* Signal if there are any sessions waiting */
		g_mutex_lock (session->mtx);
		g_cond_signal (session->cond);
		g_mutex_unlock (session->mtx);
	}
#ifdef RSPAMD_EVENTS_DEBUG
	msg_info ("removed thread: pending %d thread", session->threads);
#endif
}
