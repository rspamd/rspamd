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
#include "events.h"
#include "cryptobox.h"

#define RSPAMD_SESSION_FLAG_WATCHING (1 << 0)
#define RSPAMD_SESSION_FLAG_DESTROYING (1 << 1)

#define RSPAMD_SESSION_IS_WATCHING(s) ((s)->flags & RSPAMD_SESSION_FLAG_WATCHING)
#define RSPAMD_SESSION_IS_DESTROYING(s) ((s)->flags & RSPAMD_SESSION_FLAG_DESTROYING)

#define msg_err_session(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL, \
        session->pool->tag.tagname, session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_session(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        session->pool->tag.tagname, session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_session(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        session->pool->tag.tagname, session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_session(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
        session->pool->tag.tagname, session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

struct rspamd_async_watcher {
	event_watcher_t cb;
	guint remain;
	gpointer ud;
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
	}
	else {
		new->w = NULL;
	}

	g_hash_table_insert (session->events, new, new);

	msg_debug_session ("added event: %p, pending %d events, subsystem: %s",
		user_data,
		g_hash_table_size (session->events),
		g_quark_to_string (subsystem));
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

	msg_debug_session ("removed event: %p, subsystem: %s, pending %d events", ud,
			g_quark_to_string (found_ev->subsystem),
			g_hash_table_size (session->events));
	/* Remove event */
	fin (ud);

	/* Call watcher if needed */
	if (found_ev->w) {
		if (found_ev->w->remain > 0) {
			if (--found_ev->w->remain == 0) {
				found_ev->w->cb (session->user_data, found_ev->w->ud);
			}
		}
	}

	g_hash_table_remove (session->events, found_ev);

	rspamd_session_pending (session);
}

static gboolean
rspamd_session_destroy_callback (gpointer k, gpointer v, gpointer unused)
{
	struct rspamd_async_event *ev = v;

	/* Call event's finalizer */
	msg_debug ("removed event on destroy: %p, subsystem: %s", ev->user_data,
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
			if (!session->fin (session->user_data)) {
				/* Session finished incompletely, perform restoration */
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
rspamd_session_watch_start (struct rspamd_async_session *s,
		event_watcher_t cb,
		gpointer ud)
{
	g_assert (s != NULL);
	g_assert (!RSPAMD_SESSION_IS_WATCHING (s));

	if (s->cur_watcher == NULL) {
		s->cur_watcher = rspamd_mempool_alloc (s->pool, sizeof (*s->cur_watcher));
	}

	s->cur_watcher->cb = cb;
	s->cur_watcher->remain = 0;
	s->cur_watcher->ud = ud;
	s->flags |= RSPAMD_SESSION_FLAG_WATCHING;
}

guint
rspamd_session_watch_stop (struct rspamd_async_session *s)
{
	guint remain;

	g_assert (s != NULL);
	g_assert (RSPAMD_SESSION_IS_WATCHING (s));

	remain = s->cur_watcher->remain;

	if (remain > 0) {
		/* Avoid reusing */
		s->cur_watcher = NULL;
	}

	s->flags &= ~RSPAMD_SESSION_FLAG_WATCHING;

	return remain;
}


guint
rspamd_session_events_pending (struct rspamd_async_session *s)
{
	guint npending;

	g_assert (s != NULL);

	npending = g_hash_table_size (s->events);

	if (RSPAMD_SESSION_IS_WATCHING (s)) {
		npending += s->cur_watcher->remain;
	}

	return npending;
}

void
rspamd_session_watcher_push (struct rspamd_async_session *s)
{
	g_assert (s != NULL);

	if (RSPAMD_SESSION_IS_WATCHING (s)) {
		s->cur_watcher->remain ++;
	}
}

void
rspamd_session_watcher_push_specific (struct rspamd_async_session *s,
		struct rspamd_async_watcher *w)
{
	g_assert (s != NULL);

	if (w) {
		w->remain ++;
	}
}

void
rspamd_session_watcher_pop (struct rspamd_async_session *s,
		struct rspamd_async_watcher *w)
{
	g_assert (s != NULL);

	if (w) {
		if (--w->remain == 0) {
			w->cb (s->user_data, w->ud);
		}
	}
}

struct rspamd_async_watcher*
rspamd_session_get_watcher (struct rspamd_async_session *s)
{
	g_assert (s != NULL);

	return s->cur_watcher;
}
