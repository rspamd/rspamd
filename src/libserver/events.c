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
#define RSPAMD_SESSION_FLAG_CLEANUP (1 << 2)

#define RSPAMD_SESSION_IS_WATCHING(s) ((s)->flags & RSPAMD_SESSION_FLAG_WATCHING)
#define RSPAMD_SESSION_CAN_ADD_EVENT(s) (!((s)->flags & (RSPAMD_SESSION_FLAG_DESTROYING|RSPAMD_SESSION_FLAG_CLEANUP)))

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
#define msg_debug_session(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_events_log_id, "events", session->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(events)

/* Average symbols count to optimize hash allocation */
static struct rspamd_counter_data events_count;

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

static guint rspamd_event_hash (gconstpointer a);
static gboolean rspamd_event_equal (gconstpointer a, gconstpointer b);

/* Define **SET** of events */
KHASH_INIT (rspamd_events_hash,
		struct rspamd_async_event *,
		char,
		false,
		rspamd_event_hash,
		rspamd_event_equal);

struct rspamd_async_session {
	session_finalizer_t fin;
	event_finalizer_t restore;
	event_finalizer_t cleanup;
	khash_t(rspamd_events_hash) *events;
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
	union _pointer_fp_thunk {
		event_finalizer_t f;
		gpointer p;
	};
	struct ev_storage {
		union _pointer_fp_thunk p;
		gpointer ud;
	} st;

	st.p.f = ev->fin;
	st.ud = ev->user_data;

	return rspamd_cryptobox_fast_hash (&st, sizeof (st), rspamd_hash_seed ());
}

static void
rspamd_session_dtor (gpointer d)
{
	struct rspamd_async_session *s = (struct rspamd_async_session *)d;

	/* Events are usually empty at this point */
	rspamd_set_counter_ema (&events_count, s->events->n_buckets, 0.5);
	kh_destroy (rspamd_events_hash, s->events);
}

struct rspamd_async_session *
rspamd_session_create (rspamd_mempool_t * pool,
					   session_finalizer_t fin,
					   event_finalizer_t restore,
					   event_finalizer_t cleanup,
					   void *user_data)
{
	struct rspamd_async_session *s;

	s = rspamd_mempool_alloc0 (pool, sizeof (struct rspamd_async_session));
	s->pool = pool;
	s->fin = fin;
	s->restore = restore;
	s->cleanup = cleanup;
	s->user_data = user_data;
	s->events = kh_init (rspamd_events_hash);

	if (events_count.mean > 4) {
		kh_resize (rspamd_events_hash, s->events, events_count.mean);
	}
	else {
		kh_resize (rspamd_events_hash, s->events, 4);
	}

	rspamd_mempool_add_destructor (pool, rspamd_session_dtor, s);

	return s;
}

struct rspamd_async_event *
rspamd_session_add_event (struct rspamd_async_session *session,
						  struct rspamd_async_watcher *w,
						  event_finalizer_t fin,
						  gpointer user_data,
						  GQuark subsystem)
{
	struct rspamd_async_event *new_event;
	gint ret;

	if (session == NULL) {
		msg_err ("session is NULL");
		g_assert_not_reached ();
	}

	if (!RSPAMD_SESSION_CAN_ADD_EVENT (session)) {
		msg_debug_session ("skip adding event subsystem: %s: "
					 "session is destroying/cleaning",
				g_quark_to_string (subsystem));

		return NULL;
	}

	new_event = rspamd_mempool_alloc (session->pool,
			sizeof (struct rspamd_async_event));
	new_event->fin = fin;
	new_event->user_data = user_data;
	new_event->subsystem = subsystem;

	if (w == NULL) {
		if (RSPAMD_SESSION_IS_WATCHING (session)) {
			new_event->w = session->cur_watcher;
			new_event->w->remain++;
			msg_debug_session ("added event: %p, pending %d events, "
							   "subsystem: %s, watcher: %d (%d)",
					user_data,
					kh_size (session->events),
					g_quark_to_string (subsystem),
					new_event->w->id,
					new_event->w->remain);
		} else {
			new_event->w = NULL;
			msg_debug_session ("added event: %p, pending %d events, "
							   "subsystem: %s, no watcher!",
					user_data,
					kh_size (session->events),
					g_quark_to_string (subsystem));
		}
	}
	else {
		new_event->w = w;
		new_event->w->remain++;
		msg_debug_session ("added event: %p, pending %d events, "
						   "subsystem: %s, explicit watcher: %d (%d)",
				user_data,
				kh_size (session->events),
				g_quark_to_string (subsystem),
				new_event->w->id,
				new_event->w->remain);
	}

	kh_put (rspamd_events_hash, session->events, new_event, &ret);
	g_assert (ret > 0);

	return new_event;
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
	khiter_t k;

	if (session == NULL) {
		msg_err ("session is NULL");
		return;
	}

	if (!RSPAMD_SESSION_CAN_ADD_EVENT (session)) {
		/* Session is already cleaned up, ignore this */
		return;
	}

	/* Search for event */
	search_ev.fin = fin;
	search_ev.user_data = ud;
	k = kh_get (rspamd_events_hash, session->events, &search_ev);
	if (k == kh_end (session->events)) {
		gchar t;

		msg_err_session ("cannot find event: %p(%p)", fin, ud);
		kh_foreach (session->events, found_ev, t, {
			msg_err_session ("existing event %s: %p(%p)",
					g_quark_to_string (found_ev->subsystem),
					found_ev->fin, found_ev->user_data);
		});

		(void)t;

		g_assert_not_reached ();
	}

	found_ev = kh_key (session->events, k);
	kh_del (rspamd_events_hash, session->events, k);

	/* Remove event */
	fin (ud);

	/* Call watcher if needed */
	if (found_ev->w) {
		msg_debug_session ("removed event: %p, subsystem: %s, "
				"pending %d events, watcher: %d (%d pending)", ud,
				g_quark_to_string (found_ev->subsystem),
				kh_size (session->events),
				found_ev->w->id, found_ev->w->remain - 1);

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
				kh_size (session->events));
	}

	rspamd_session_pending (session);
}

gboolean
rspamd_session_destroy (struct rspamd_async_session *session)
{
	if (session == NULL) {
		msg_err ("session is NULL");
		return FALSE;
	}

	if (!rspamd_session_blocked (session)) {
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
	struct rspamd_async_event *ev;

	if (session == NULL) {
		msg_err ("session is NULL");
		return;
	}

	session->flags |= RSPAMD_SESSION_FLAG_CLEANUP;

	kh_foreach_key (session->events, ev, {
		/* Call event's finalizer */
		msg_debug_session ("removed event on destroy: %p, subsystem: %s",
				ev->user_data,
				g_quark_to_string (ev->subsystem));

		if (ev->fin != NULL) {
			ev->fin (ev->user_data);
		}
	});

	kh_clear (rspamd_events_hash, session->events);

	session->flags &= ~RSPAMD_SESSION_FLAG_CLEANUP;
}

gboolean
rspamd_session_pending (struct rspamd_async_session *session)
{
	gboolean ret = TRUE;

	if (kh_size (session->events) == 0) {
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

	npending = kh_size (session->events);
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

struct rspamd_async_watcher*
rspamd_session_replace_watcher (struct rspamd_async_session *s,
		struct rspamd_async_watcher *w)
{
	struct rspamd_async_watcher *res = NULL;

	g_assert (s != NULL);

	if (s->cur_watcher) {
		res = s->cur_watcher;

		if (!w) {
			/* We remove watching, so clear watching flag as well */
			s->flags &= ~RSPAMD_SESSION_FLAG_WATCHING;

		}

		s->cur_watcher = w;
	}
	else {
		if (w) {
			s->flags |= RSPAMD_SESSION_FLAG_WATCHING;
		}

		s->cur_watcher = w;
	}

	return res;
}

rspamd_mempool_t *
rspamd_session_mempool (struct rspamd_async_session *session)
{
	g_assert (session != NULL);

	return session->pool;
}

gboolean
rspamd_session_blocked (struct rspamd_async_session *session)
{
	g_assert (session != NULL);

	return !RSPAMD_SESSION_CAN_ADD_EVENT (session);
}