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
#ifndef RSPAMD_ASYNC_SESSION_H
#define RSPAMD_ASYNC_SESSION_H

#include "config.h"
#include "mem_pool.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rspamd_async_event;
struct rspamd_async_session;

typedef void (*event_finalizer_t)(gpointer ud);

typedef gboolean (*session_finalizer_t)(gpointer user_data);

/**
 * Callback that returns a human-readable name (typically the currently-executing
 * symbol) to associate with an event when it is added. Receives the session's
 * user_data. May return NULL if no such context exists (e.g. events added
 * outside symcache execution). Returned string must remain valid at least until
 * the event is removed.
 */
typedef const char *(*rspamd_session_item_name_resolver_t)(gpointer user_data);

/**
 * Make new async session
 * @param pool pool to alloc memory from
 * @param fin a callback called when no events are found in session
 * @param restore a callback is called to restore processing of session
 * @param cleanup a callback called when session is forcefully destroyed
 * @param user_data abstract user data
 * @return
 */
struct rspamd_async_session *rspamd_session_create(rspamd_mempool_t *pool,
												   session_finalizer_t fin, event_finalizer_t restore,
												   event_finalizer_t cleanup, gpointer user_data);

/**
 * Registers (or clears with NULL) a callback that the session calls at
 * add-event time to snapshot the "owning item" name (typically the symbol name
 * that initiated the async request). Used only for diagnostics — has no effect
 * on event lifecycle. Task-scoped sessions should wire this to look up the
 * currently-executing symcache item.
 * @param session session object
 * @param resolver resolver callback, or NULL to disable
 */
void rspamd_session_set_item_name_resolver(struct rspamd_async_session *session,
										   rspamd_session_item_name_resolver_t resolver);

/**
 * Insert new event to the session
 * @param session session object
 * @param fin finalizer callback
 * @param user_data abstract user_data
 * @param subsystem static name of the subsystem registering the event (e.g. "rspamd dns")
 * @param label optional human-readable annotation (e.g. "tcp write"), may be NULL
 */
struct rspamd_async_event *
rspamd_session_add_event_full(struct rspamd_async_session *session,
							  event_finalizer_t fin,
							  gpointer user_data,
							  const char *subsystem,
							  const char *label);

#define rspamd_session_add_event(session, fin, user_data, subsystem) \
	rspamd_session_add_event_full(session, fin, user_data, subsystem, NULL)

/**
 * Updates the label (human annotation) of an already-registered event.
 * Intended for callers whose event is long-lived (e.g. a TCP connection)
 * and whose "current operation" (read / write / connect) changes during
 * the event's lifetime. The new label must remain valid until the event
 * is removed or the label is updated again.
 * @param ev event returned by rspamd_session_add_event[_full]; may be NULL (no-op)
 * @param label new label or NULL to clear
 */
void rspamd_session_event_update_label(struct rspamd_async_event *ev,
									   const char *label);

/**
 * Remove normal event
 * @param session session object
 * @param fin final callback
 * @param ud user data object
 */
void rspamd_session_remove_event(struct rspamd_async_session *session,
								 event_finalizer_t fin,
								 gpointer ud);

/**
 * Must be called at the end of session, it calls fin functions for all non-forced callbacks
 * @return true if the whole session was destroyed and false if there are forced events
 */
gboolean rspamd_session_destroy(struct rspamd_async_session *session);

/**
 * Try to remove all events pending
 */
void rspamd_session_cleanup(struct rspamd_async_session *session, bool forced_cleanup);

/**
 * Returns mempool associated with async session
 * @param session
 * @return
 */
rspamd_mempool_t *rspamd_session_mempool(struct rspamd_async_session *session);

/**
 * Check session for events pending and call fin callback if no events are pending
 * @param session session object
 * @return TRUE if session has pending events
 */
gboolean rspamd_session_pending(struct rspamd_async_session *session);

/**
 * Returns number of events pending
 * @param session
 * @return
 */
unsigned int rspamd_session_events_pending(struct rspamd_async_session *session);

/**
 * Builds a single human-readable line describing all currently-pending async
 * events, grouped by the (subsystem, item_name, label) triple. Each group is
 * rendered as "<subsystem>[<item>/<label>]=N" when both item and label are
 * known, degrading to "<subsystem>[<item>]=N", "<subsystem>[<label>]=N", or
 * bare "<subsystem>=N" if fields are missing. Example output:
 *   "total=5; rspamd dns[RBL_FOO]=3, rspamd dns[SURBL]=1, rspamd lua http[X]=1"
 * Returns a newly-allocated GString that the caller MUST free with
 * g_string_free(..., TRUE), or NULL if there are no pending events.
 * Intended to be called from timeout handlers so the caller can log with the
 * proper task module tag (msg_info_task).
 * @param session session to dump
 * @return newly-allocated GString or NULL
 */
GString *rspamd_session_describe_pending(struct rspamd_async_session *session);


/**
 * Returns TRUE if an async session is currently destroying
 * @param s
 * @return
 */
gboolean rspamd_session_blocked(struct rspamd_async_session *s);

#ifdef __cplusplus
}
#endif

#endif /*RSPAMD_ASYNC_SESSION_H*/
