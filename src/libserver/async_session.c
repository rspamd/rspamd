/*
 * Copyright 2023 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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

#define RSPAMD_SESSION_CAN_ADD_EVENT(s) (!((s)->flags & (RSPAMD_SESSION_FLAG_DESTROYING | RSPAMD_SESSION_FLAG_CLEANUP)))

#define msg_err_session(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL,             \
														 "events", session->pool->tag.uid, \
														 G_STRFUNC,                        \
														 __VA_ARGS__)
#define msg_warn_session(...) rspamd_default_log_function(G_LOG_LEVEL_WARNING,              \
														  "events", session->pool->tag.uid, \
														  G_STRFUNC,                        \
														  __VA_ARGS__)
#define msg_info_session(...) rspamd_default_log_function(G_LOG_LEVEL_INFO,                 \
														  "events", session->pool->tag.uid, \
														  G_STRFUNC,                        \
														  __VA_ARGS__)
#define msg_debug_session(...) rspamd_conditional_debug_fast(NULL, NULL,                                             \
															 rspamd_events_log_id, "events", session->pool->tag.uid, \
															 G_STRFUNC,                                              \
															 __VA_ARGS__)

INIT_LOG_MODULE(events)

/* Average symbols count to optimize hash allocation */
static struct rspamd_counter_data events_count;


struct rspamd_async_event {
	const char *subsystem;
	/* Snapshotted at add-time via session->item_name_resolver. May be NULL. */
	const char *item_name;
	/* Caller-supplied human annotation. May be NULL. */
	const char *label;
	event_finalizer_t fin;
	void *user_data;
};

static inline bool
rspamd_event_equal(const struct rspamd_async_event *ev1, const struct rspamd_async_event *ev2)
{
	return ev1->fin == ev2->fin && ev1->user_data == ev2->user_data;
}

static inline uint64_t
rspamd_event_hash(const struct rspamd_async_event *ev)
{
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

	return rspamd_cryptobox_fast_hash(&st, sizeof(st), rspamd_hash_seed());
}

/* Define **SET** of events */
KHASH_INIT(rspamd_events_hash,
		   struct rspamd_async_event *,
		   char,
		   false,
		   rspamd_event_hash,
		   rspamd_event_equal);

struct rspamd_async_session {
	session_finalizer_t fin;
	event_finalizer_t restore;
	event_finalizer_t cleanup;
	rspamd_session_item_name_resolver_t item_name_resolver;
	khash_t(rspamd_events_hash) * events;
	void *user_data;
	rspamd_mempool_t *pool;
	unsigned int flags;
};

void rspamd_session_set_item_name_resolver(struct rspamd_async_session *session,
										   rspamd_session_item_name_resolver_t resolver)
{
	if (session != NULL) {
		session->item_name_resolver = resolver;
	}
}

static void
rspamd_session_dtor(gpointer d)
{
	struct rspamd_async_session *s = (struct rspamd_async_session *) d;

	/* Events are usually empty at this point */
	rspamd_set_counter_ema(&events_count, s->events->n_buckets, 0.5);
	kh_destroy(rspamd_events_hash, s->events);
}

struct rspamd_async_session *
rspamd_session_create(rspamd_mempool_t *pool,
					  session_finalizer_t fin,
					  event_finalizer_t restore,
					  event_finalizer_t cleanup,
					  void *user_data)
{
	struct rspamd_async_session *s;

	s = rspamd_mempool_alloc0(pool, sizeof(struct rspamd_async_session));
	s->pool = pool;
	s->fin = fin;
	s->restore = restore;
	s->cleanup = cleanup;
	s->user_data = user_data;
	s->events = kh_init(rspamd_events_hash);

	kh_resize(rspamd_events_hash, s->events, MAX(4, events_count.mean));
	rspamd_mempool_add_destructor(pool, rspamd_session_dtor, s);

	return s;
}

struct rspamd_async_event *
rspamd_session_add_event_full(struct rspamd_async_session *session,
							  event_finalizer_t fin,
							  gpointer user_data,
							  const char *subsystem,
							  const char *label)
{
	struct rspamd_async_event *new_event;
	int ret;

	if (session == NULL) {
		msg_err("session is NULL");
		g_assert_not_reached();
	}

	if (!RSPAMD_SESSION_CAN_ADD_EVENT(session)) {
		msg_debug_session("skip adding event subsystem: %s: "
						  "session is destroying/cleaning",
						  subsystem);

		return NULL;
	}

	new_event = rspamd_mempool_alloc(session->pool,
									 sizeof(struct rspamd_async_event));
	new_event->fin = fin;
	new_event->user_data = user_data;
	new_event->subsystem = subsystem;
	new_event->label = label;
	new_event->item_name = NULL;
	if (session->item_name_resolver != NULL) {
		new_event->item_name = session->item_name_resolver(session->user_data);
	}

	msg_debug_session("added event: %p, pending %d (+1) events, "
					  "subsystem: %s, item: %s, label: %s",
					  user_data,
					  kh_size(session->events),
					  subsystem,
					  new_event->item_name ? new_event->item_name : "(none)",
					  label ? label : "(none)");

	kh_put(rspamd_events_hash, session->events, new_event, &ret);
	g_assert(ret > 0);

	return new_event;
}

void rspamd_session_event_update_label(struct rspamd_async_event *ev,
									   const char *label)
{
	if (ev != NULL) {
		ev->label = label;
	}
}

void rspamd_session_remove_event(struct rspamd_async_session *session,
								 event_finalizer_t fin,
								 void *ud)
{
	struct rspamd_async_event search_ev, *found_ev;
	khiter_t k;

	if (session == NULL) {
		msg_err("session is NULL");
		return;
	}

	if (!RSPAMD_SESSION_CAN_ADD_EVENT(session)) {
		/* Session is already cleaned up, ignore this */
		return;
	}

	/* Search for event */
	search_ev.fin = fin;
	search_ev.user_data = ud;
	k = kh_get(rspamd_events_hash, session->events, &search_ev);
	if (k == kh_end(session->events)) {

		msg_err_session("cannot find event: %p(%p) (%d total events)", fin, ud,
						(int) kh_size(session->events));
		kh_foreach_key(session->events, found_ev, {
			msg_err_session("existing event subsystem=%s, item=%s, label=%s: %p(%p)",
							found_ev->subsystem,
							found_ev->item_name ? found_ev->item_name : "(none)",
							found_ev->label ? found_ev->label : "(none)",
							found_ev->fin,
							found_ev->user_data);
		});

		g_assert_not_reached();
	}

	found_ev = kh_key(session->events, k);
	msg_debug_session("removed event: %p, pending %d (-1) events, "
					  "subsystem: %s, item: %s, label: %s",
					  ud,
					  kh_size(session->events),
					  found_ev->subsystem,
					  found_ev->item_name ? found_ev->item_name : "(none)",
					  found_ev->label ? found_ev->label : "(none)");
	kh_del(rspamd_events_hash, session->events, k);

	/* Remove event */
	if (fin) {
		fin(ud);
	}

	rspamd_session_pending(session);
}

gboolean
rspamd_session_destroy(struct rspamd_async_session *session)
{
	if (session == NULL) {
		msg_err("session is NULL");
		return FALSE;
	}

	if (!rspamd_session_blocked(session)) {
		session->flags |= RSPAMD_SESSION_FLAG_DESTROYING;
		rspamd_session_cleanup(session, false);

		if (session->cleanup != NULL) {
			session->cleanup(session->user_data);
		}
	}

	return TRUE;
}

void rspamd_session_cleanup(struct rspamd_async_session *session, bool forced_cleanup)
{
	struct rspamd_async_event *ev;

	if (session == NULL) {
		msg_err("session is NULL");
		return;
	}

	session->flags |= RSPAMD_SESSION_FLAG_CLEANUP;
	khash_t(rspamd_events_hash) *uncancellable_events = kh_init(rspamd_events_hash);

	kh_foreach_key(session->events, ev, {
		/* Call event's finalizer */
		int ret;

		if (ev->fin != NULL) {
			msg_debug_session("%sremoved event on destroy: %p, subsystem: %s, item: %s, label: %s",
							  forced_cleanup ? "forced " : "",
							  ev->user_data,
							  ev->subsystem,
							  ev->item_name ? ev->item_name : "(none)",
							  ev->label ? ev->label : "(none)");
			ev->fin(ev->user_data);
		}
		else {
			msg_debug_session("NOT %sremoved event on destroy - uncancellable: %p, subsystem: %s, item: %s, label: %s",
							  forced_cleanup ? "forced " : "",
							  ev->user_data,
							  ev->subsystem,
							  ev->item_name ? ev->item_name : "(none)",
							  ev->label ? ev->label : "(none)");
			/* Assume an event is uncancellable, move it to a new hash table */
			kh_put(rspamd_events_hash, uncancellable_events, ev, &ret);
		}
	});

	kh_destroy(rspamd_events_hash, session->events);
	session->events = uncancellable_events;
	if (forced_cleanup && kh_size(uncancellable_events) > 0) {
		msg_info_session("pending %d uncancellable events after forced cleanup",
						 kh_size(uncancellable_events));
	}
	else {
		msg_debug_session("pending %d uncancellable events", kh_size(uncancellable_events));
	}

	session->flags &= ~RSPAMD_SESSION_FLAG_CLEANUP;
}

gboolean
rspamd_session_pending(struct rspamd_async_session *session)
{
	gboolean ret = TRUE;

	if (kh_size(session->events) == 0) {
		if (session->fin != NULL) {
			msg_debug_session("call fin handler, as no events are pending");

			if (!session->fin(session->user_data)) {
				/* Session finished incompletely, perform restoration */
				msg_debug_session("restore incomplete session");
				if (session->restore != NULL) {
					session->restore(session->user_data);
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

unsigned int rspamd_session_events_pending(struct rspamd_async_session *session)
{
	unsigned int npending;

	g_assert(session != NULL);

	npending = kh_size(session->events);
	msg_debug_session("pending %d events", npending);

	return npending;
}

#define RSPAMD_DUMP_MAX_SUBSYSTEMS 16
#define RSPAMD_DUMP_MAX_SOURCES_PER_SUB 4

static inline bool
rspamd_str_eq_nullable(const char *a, const char *b)
{
	if (a == b) {
		return true;
	}
	if (a == NULL || b == NULL) {
		return false;
	}
	return strcmp(a, b) == 0;
}

#define RSPAMD_DUMP_MAX_GROUPS 32

GString *
rspamd_session_describe_pending(struct rspamd_async_session *session)
{
	struct rspamd_async_event *ev;
	GString *out;
	unsigned int total = 0;
	unsigned int n_groups = 0;
	/* Events that did not fit into the first RSPAMD_DUMP_MAX_GROUPS groups —
	 * these may belong to any number of distinct groups; we cannot tell without
	 * spending more memory, so we just report the event count. */
	unsigned int overflow_events = 0;
	unsigned int i;

	struct dump_group {
		const char *subsystem;
		const char *item_name;
		const char *label;
		unsigned int count;
	} groups[RSPAMD_DUMP_MAX_GROUPS];

	if (session == NULL || kh_size(session->events) == 0) {
		return NULL;
	}

	kh_foreach_key(session->events, ev, {
		const char *sub = ev->subsystem ? ev->subsystem : "(null)";
		const char *item = ev->item_name;
		const char *lbl = ev->label;
		struct dump_group *g = NULL;

		total++;

		for (i = 0; i < n_groups; i++) {
			if (strcmp(groups[i].subsystem, sub) == 0 &&
				rspamd_str_eq_nullable(groups[i].item_name, item) &&
				rspamd_str_eq_nullable(groups[i].label, lbl)) {
				g = &groups[i];
				break;
			}
		}

		if (g == NULL) {
			if (n_groups < RSPAMD_DUMP_MAX_GROUPS) {
				g = &groups[n_groups++];
				g->subsystem = sub;
				g->item_name = item;
				g->label = lbl;
				g->count = 0;
			}
			else {
				overflow_events++;
			}
		}

		if (g != NULL) {
			g->count++;
		}
	});

	if (total == 0) {
		return NULL;
	}

	out = g_string_sized_new(256);
	rspamd_printf_gstring(out, "total=%ud; ", total);

	for (i = 0; i < n_groups; i++) {
		const struct dump_group *g = &groups[i];

		if (i > 0) {
			g_string_append(out, ", ");
		}

		g_string_append(out, g->subsystem);
		if (g->item_name != NULL && g->label != NULL) {
			rspamd_printf_gstring(out, "[%s/%s]", g->item_name, g->label);
		}
		else if (g->item_name != NULL) {
			rspamd_printf_gstring(out, "[%s]", g->item_name);
		}
		else if (g->label != NULL) {
			rspamd_printf_gstring(out, "[%s]", g->label);
		}
		rspamd_printf_gstring(out, "=%ud", g->count);
	}

	if (overflow_events > 0) {
		rspamd_printf_gstring(out, ", (+%ud events not shown)", overflow_events);
	}

	return out;
}

#undef RSPAMD_DUMP_MAX_GROUPS
#undef RSPAMD_DUMP_MAX_SUBSYSTEMS
#undef RSPAMD_DUMP_MAX_SOURCES_PER_SUB

rspamd_mempool_t *
rspamd_session_mempool(struct rspamd_async_session *session)
{
	g_assert(session != NULL);

	return session->pool;
}

gboolean
rspamd_session_blocked(struct rspamd_async_session *session)
{
	g_assert(session != NULL);

	return !RSPAMD_SESSION_CAN_ADD_EVENT(session);
}