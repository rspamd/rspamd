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
#include "contrib/libucl/khash.h"
#include "async_session.h"
#include "cryptobox.h"

#define RSPAMD_SESSION_FLAG_DESTROYING (1 << 1)
#define RSPAMD_SESSION_FLAG_CLEANUP (1 << 2)

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


struct rspamd_async_event {
	const gchar *subsystem;
	const gchar *loc;
	event_finalizer_t fin;
	void *user_data;
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
rspamd_session_add_event_full (struct rspamd_async_session *session,
							   event_finalizer_t fin,
							   gpointer user_data,
							   const gchar *subsystem,
							   const gchar *loc)
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
				subsystem);

		return NULL;
	}

	new_event = rspamd_mempool_alloc (session->pool,
			sizeof (struct rspamd_async_event));
	new_event->fin = fin;
	new_event->user_data = user_data;
	new_event->subsystem = subsystem;
	new_event->loc = loc;

	msg_debug_session ("added event: %p, pending %d (+1) events, "
					   "subsystem: %s (%s)",
			user_data,
			kh_size (session->events),
			subsystem,
			loc);

	kh_put (rspamd_events_hash, session->events, new_event, &ret);
	g_assert (ret > 0);

	return new_event;
}

void
rspamd_session_remove_event_full (struct rspamd_async_session *session,
								  event_finalizer_t fin,
								  void *ud,
								  const gchar *loc)
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

		msg_err_session ("cannot find event: %p(%p) from %s", fin, ud, loc);
		kh_foreach (session->events, found_ev, t, {
			msg_err_session ("existing event %s (%s): %p(%p)",
					found_ev->subsystem,
					found_ev->loc,
					found_ev->fin,
					found_ev->user_data);
		});

		(void)t;

		g_assert_not_reached ();
	}

	found_ev = kh_key (session->events, k);
	msg_debug_session ("removed event: %p, pending %d (-1) events, "
					   "subsystem: %s (%s), added at %s",
			ud,
			kh_size (session->events),
			found_ev->subsystem,
			loc,
			found_ev->loc);
	kh_del (rspamd_events_hash, session->events, k);

	/* Remove event */
	if (fin) {
		fin (ud);
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
	khash_t(rspamd_events_hash) *uncancellable_events = kh_init(rspamd_events_hash);

	kh_foreach_key (session->events, ev, {
		/* Call event's finalizer */
		int ret;

		if (ev->fin != NULL) {
			msg_debug_session ("removed event on destroy: %p, subsystem: %s",
					ev->user_data,
					ev->subsystem);
			ev->fin (ev->user_data);
		}
		else {
			msg_debug_session ("NOT removed event on destroy - uncancellable: %p, subsystem: %s",
					ev->user_data,
					ev->subsystem);
			/* Assume an event is uncancellable, move it to a new hash table */
			kh_put (rspamd_events_hash, uncancellable_events, ev, &ret);
		}
	});

	kh_destroy (rspamd_events_hash, session->events);
	session->events = uncancellable_events;
	msg_debug_session ("pending %d uncancellable events", kh_size (uncancellable_events));
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

guint
rspamd_session_events_pending (struct rspamd_async_session *session)
{
	guint npending;

	g_assert (session != NULL);

	npending = kh_size (session->events);
	msg_debug_session ("pending %d events", npending);

	return npending;
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