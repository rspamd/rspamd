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
#ifndef RSPAMD_EVENTS_H
#define RSPAMD_EVENTS_H

#include "config.h"
#include "mem_pool.h"

struct rspamd_async_event;
struct rspamd_async_session;
struct rspamd_async_watcher;

typedef void (*event_finalizer_t)(gpointer ud);
typedef void (*event_watcher_t)(gpointer session_data, gpointer ud);
typedef gboolean (*session_finalizer_t)(gpointer user_data);

/**
 * Make new async session
 * @param pool pool to alloc memory from
 * @param fin a callback called when no events are found in session
 * @param restore a callback is called to restore processing of session
 * @param cleanup a callback called when session is forcefully destroyed
 * @param user_data abstract user data
 * @return
 */
struct rspamd_async_session * rspamd_session_create (rspamd_mempool_t *pool,
	session_finalizer_t fin, event_finalizer_t restore,
	event_finalizer_t cleanup, gpointer user_data);

/**
 * Insert new event to the session
 * @param session session object
 * @param fin finalizer callback
 * @param user_data abstract user_data
 * @param forced unused
 */
void rspamd_session_add_event (struct rspamd_async_session *session,
	event_finalizer_t fin, gpointer user_data, GQuark subsystem);

/**
 * Remove normal event
 * @param session session object
 * @param fin final callback
 * @param ud user data object
 */
void rspamd_session_remove_event (struct rspamd_async_session *session,
	event_finalizer_t fin,
	gpointer ud);

/**
 * Must be called at the end of session, it calls fin functions for all non-forced callbacks
 * @return true if the whole session was destroyed and false if there are forced events
 */
gboolean rspamd_session_destroy (struct rspamd_async_session *session);

/**
 * Try to remove all events pending
 */
void rspamd_session_cleanup (struct rspamd_async_session *session);

/**
 * Check session for events pending and call fin callback if no events are pending
 * @param session session object
 * @return TRUE if session has pending events
 */
gboolean rspamd_session_pending (struct rspamd_async_session *session);

/**
 * Returns number of events pending
 * @param session
 * @return
 */
guint rspamd_session_events_pending (struct rspamd_async_session *session);

/**
 * Start watching for events in the session, so the specified watcher will be added
 * to all subsequent events until `rspamd_session_watch_stop` is called
 * @param s session object
 * @param cb watcher callback that is called when all events watched are destroyed
 * @param ud opaque data for the callback
 */
void rspamd_session_watch_start (struct rspamd_async_session *s,
		gint id,
		event_watcher_t cb,
		gpointer ud);

/**
 * Stop watching mode, if no events are watched since the last `rspamd_session_watch_start`,
 * then the watcher is silently ignored
 * @param s session
 * @return number of events watched
 */
guint rspamd_session_watch_stop (struct rspamd_async_session *s);

/**
 * Create a fake event just for event watcher
 * @param s
 */
void rspamd_session_watcher_push (struct rspamd_async_session *s);

/**
 * Push callback to the watcher specified
 */
void rspamd_session_watcher_push_callback (struct rspamd_async_session *s,
		struct rspamd_async_watcher *w,
		event_watcher_t cb,
		gpointer ud);

/**
 * Increase refcount for a specific watcher
 */
void rspamd_session_watcher_push_specific (struct rspamd_async_session *s,
		struct rspamd_async_watcher *w);

/**
 * Remove a fake event from a watcher
 * @param s
 */
void rspamd_session_watcher_pop (struct rspamd_async_session *s,
		struct rspamd_async_watcher *w);

/**
 * Returns the current watcher for events session
 * @param s
 * @return
 */
struct rspamd_async_watcher* rspamd_session_get_watcher (
		struct rspamd_async_session *s);

#endif /* RSPAMD_EVENTS_H */
