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
#include "rspamd.h"
#include "contrib/uthash/utlist.h"
#include "events.h"
#include "cryptobox.h"

#define RSPAMD_SESSION_FLAG_WATCHING (1 << 0)
#define RSPAMD_SESSION_FLAG_DESTROYING (1 << 1)

#define RSPAMD_SESSION_IS_WATCHING(s) ((s)->flags & RSPAMD_SESSION_FLAG_WATCHING)
#define RSPAMD_SESSION_IS_DESTROYING(s) ((s)->flags & RSPAMD_SESSION_FLAG_DESTROYING)

#define msg_err_session(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL, \
        "events", session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_session(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        "events", session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_session(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "events", session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_session(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
        "events", session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

struct rspamd_watch_stack {
	event_watcher_t cb;
	gpointer ud;
	struct rspamd_watch_stack *next;
};

struct rspamd_async_watcher {
	struct rspamd_watch_stack *st;
	guint remain;
	gint id;
};

struct rspamd_async_event {
	GQuark subsystem;
	event_finalizer_t fin;
	void *user_data;
	struct rspamd_async_watcher *w;
};

struct rspamd_async_session {
	session_finalizer_t fin;
	event_finalizer_t restore;
	event_finalizer_t cleanup;
	GHashTable *events;
	void *user_data;
	rspamd_mempool_t *pool;
	struct rspamd_async_watcher *cur_watcher;
	guint flags;
};

static gboolean
rspamd_event_equal (gconstpointer a, gconstpointer b)
{
	const struct rspamd_async_event *ev1 = a, *ev2 = b;

	if (ev1->fin == ev2->fin) {
		return ev1->user_data == ev2->user_data;
	}

	return FALSE;
}

static guint
rspamd_event_hash (gconstpointer a)
{
	const struct rspamd_async_event *ev = a;
	rspamd_cryptobox_fast_hash_state_t st;
	union {
		event_finalizer_t f;
		gpointer p;
	} u;

	u.f = ev->fin;

	rspamd_cryptobox_fast_hash_init (&st, rspamd_hash_seed ());
	rspamd_cryptobox_fast_hash_update (&st, &ev->user_data, sizeof (gpointer));
	rspamd_cryptobox_fast_hash_update (&st, &u, sizeof (u));

	return rspamd_cryptobox_fast_hash_final (&st);
}


struct rspamd_async_session *
rspamd_session_create (rspamd_mempool_t * pool, session_finalizer_t fin,
	event_finalizer_t restore, event_finalizer_t cleanup, void *user_data)
{
	struct rspamd_async_session *new;

	new = rspamd_mempool_alloc0 (pool, sizeof (struct rspamd_async_session));
	new->pool = pool;
	new->fin = fin;
	new->restore = restore;
	new->cleanup = cleanup;
	new->user_data = user_data;
	new->events = g_hash_table_new (rspamd_event_hash, rspamd_event_equal);

	rspamd_mempool_add_destructor (pool,
		(rspamd_mempool_destruct_t) g_hash_table_destroy,
		new->events);

	return new;
}

void
rspamd_session_add_event (struct rspamd_async_session *session,
	event_finalizer_t fin,
	void *user_data,
	GQuark subsystem)
{
	struct rspamd_async_event *new;

	if (session == NULL) {
		msg_err ("session is NULL");
		return;
	}

	new = rspamd_mempool_alloc (session->pool,
			sizeof (struct rspamd_async_event));
	new->fin = fin;
	new->user_data = user_data;
	new->subsystem = subsystem;

	if (RSPAMD_SESSION_IS_WATCHING (session)) {
		new->w = session->cur_watcher;
		new->w->remain ++;
		msg_debug_session ("added event: %p, pending %d events, "
				"subsystem: %s, watcher: %d",
				user_data,
				g_hash_table_size (session->events),
				g_quark_to_string (subsystem),
				new->w->id);
	}
	else {
		new->w = NULL;
		msg_debug_session ("added event: %p, pending %d events, "
				"subsystem: %s, no watcher!",
				user_data,
				g_hash_table_size (session->events),
				g_quark_to_string (subsystem));
	}

	g_hash_table_insert (session->events, new, new);
}

static inline void
rspamd_session_call_watcher_stack (struct rspamd_async_session *session,
		struct rspamd_async_watcher *w)
{
	struct rspamd_watch_stack *st;

	LL_FOREACH (w->st, st) {
		st->cb (session->user_data, st->ud);
	}

	w->st = NULL;
}

void
rspamd_session_remove_event (struct rspamd_async_session *session,
	event_finalizer_t fin,
	void *ud)
{
	struct rspamd_async_event search_ev, *found_ev;

	if (session == NULL) {
		msg_err ("session is NULL");
		return;
	}

	/* Search for event */
	search_ev.fin = fin;
	search_ev.user_data = ud;
	found_ev = g_hash_table_lookup (session->events, &search_ev);
	g_assert (found_ev != NULL);

	/* Remove event */
	fin (ud);

	/* Call watcher if needed */
	if (found_ev->w) {
		msg_debug_session ("removed event: %p, subsystem: %s, "
				"pending %d events, watcher: %d (%d pending)", ud,
				g_quark_to_string (found_ev->subsystem),
				g_hash_table_size (session->events),
				found_ev->w->id, found_ev->w->remain);

		if (found_ev->w->remain > 0) {
			if (--found_ev->w->remain == 0) {
				rspamd_session_call_watcher_stack (session, found_ev->w);
			}
		}
	}
	else {
		msg_debug_session ("removed event: %p, subsystem: %s, "
				"pending %d events, no watcher!", ud,
				g_quark_to_string (found_ev->subsystem),
				g_hash_table_size (session->events));
	}

	g_hash_table_remove (session->events, found_ev);

	rspamd_session_pending (session);
}

static gboolean
rspamd_session_destroy_callback (gpointer k, gpointer v, gpointer d)
{
	struct rspamd_async_event *ev = v;
	struct rspamd_async_session *session = d;

	/* Call event's finalizer */
	msg_debug_session ("removed event on destroy: %p, subsystem: %s",
			ev->user_data,
			g_quark_to_string (ev->subsystem));

	if (ev->fin != NULL) {
		ev->fin (ev->user_data);
	}

	/* We ignore watchers on session destroying */

	return TRUE;
}

gboolean
rspamd_session_destroy (struct rspamd_async_session *session)
{
	if (session == NULL) {
		msg_err ("session is NULL");
		return FALSE;
	}

	if (!(session->flags & RSPAMD_SESSION_FLAG_DESTROYING)) {
		session->flags |= RSPAMD_SESSION_FLAG_DESTROYING;
		rspamd_session_cleanup (session);

		if (session->cleanup != NULL) {
			session->cleanup (session->user_data);
		}
	}

	return TRUE;
}

void
rspamd_session_cleanup (struct rspamd_async_session *session)
{
	if (session == NULL) {
		msg_err ("session is NULL");
		return;
	}

	g_hash_table_foreach_remove (session->events,
			rspamd_session_destroy_callback,
			session);
}

gboolean
rspamd_session_pending (struct rspamd_async_session *session)
{
	gboolean ret = TRUE;

	if (g_hash_table_size (session->events) == 0) {
		if (session->fin != NULL) {
			msg_debug_session ("call fin handler, as no events are pending");

			if (!session->fin (session->user_data)) {
				/* Session finished incompletely, perform restoration */
				msg_debug_session ("restore incomplete session");
				if (session->restore != NULL) {
					session->restore (session->user_data);
				}
			}
			else {
				ret = FALSE;
			}
		}

		ret = FALSE;
	}

	return ret;
}

void
rspamd_session_watch_start (struct rspamd_async_session *session,
		gint id,
		event_watcher_t cb,
		gpointer ud)
{
	struct rspamd_watch_stack *st_elt;

	g_assert (session != NULL);
	g_assert (!RSPAMD_SESSION_IS_WATCHING (session));

	if (session->cur_watcher == NULL) {
		session->cur_watcher = rspamd_mempool_alloc0 (session->pool,
				sizeof (*session->cur_watcher));
	}

	st_elt = rspamd_mempool_alloc (session->pool, sizeof (*st_elt));
	st_elt->cb = cb;
	st_elt->ud = ud;
	LL_PREPEND (session->cur_watcher->st, st_elt);

	session->cur_watcher->id = id;
	session->flags |= RSPAMD_SESSION_FLAG_WATCHING;
}

guint
rspamd_session_watch_stop (struct rspamd_async_session *session)
{
	guint remain;

	g_assert (session != NULL);
	g_assert (RSPAMD_SESSION_IS_WATCHING (session));

	remain = session->cur_watcher->remain;

	if (remain > 0) {
		/* Avoid reusing */
		session->cur_watcher = NULL;
	}

	session->flags &= ~RSPAMD_SESSION_FLAG_WATCHING;

	return remain;
}


guint
rspamd_session_events_pending (struct rspamd_async_session *session)
{
	guint npending;

	g_assert (session != NULL);

	npending = g_hash_table_size (session->events);
	msg_debug_session ("pending %d events", npending);

	if (RSPAMD_SESSION_IS_WATCHING (session)) {
		npending += session->cur_watcher->remain;
		msg_debug_session ("pending %d watchers, id: %d",
				session->cur_watcher->remain, session->cur_watcher->id);
	}

	return npending;
}

inline void
rspamd_session_watcher_push_callback (struct rspamd_async_session *session,
		struct rspamd_async_watcher *w,
		event_watcher_t cb,
		gpointer ud)
{
	struct rspamd_watch_stack *st;

	g_assert (session != NULL);

	if (w == NULL) {
		if (RSPAMD_SESSION_IS_WATCHING (session)) {
			w = session->cur_watcher;
		}
		else {
			return;
		}
	}

	if (w) {
		w->remain ++;
		msg_debug_session ("push session, watcher: %d, %d events",
				w->id,
				w->remain);

		if (cb) {
			st = rspamd_mempool_alloc (session->pool, sizeof (*st));
			st->cb = cb;
			st->ud = ud;

			LL_PREPEND (w->st, st);
		}
	}
}

void
rspamd_session_watcher_push (struct rspamd_async_session *session)
{
	rspamd_session_watcher_push_callback (session, NULL, NULL, NULL);
}

void
rspamd_session_watcher_push_specific (struct rspamd_async_session *session,
		struct rspamd_async_watcher *w)
{
	rspamd_session_watcher_push_callback (session, w, NULL, NULL);
}

void
rspamd_session_watcher_pop (struct rspamd_async_session *session,
		struct rspamd_async_watcher *w)
{
	g_assert (session != NULL);

	if (w && w->remain > 0) {
		msg_debug_session ("pop session, watcher: %d, %d events", w->id,
				w->remain);
		w->remain --;

		if (w->remain == 0) {
			rspamd_session_call_watcher_stack (session, w);
		}
	}
}

struct rspamd_async_watcher*
rspamd_session_get_watcher (struct rspamd_async_session *session)
{
	g_assert (session != NULL);

	if (RSPAMD_SESSION_IS_WATCHING (session)) {
		return session->cur_watcher;
	}
	else {
		return NULL;
	}
}
