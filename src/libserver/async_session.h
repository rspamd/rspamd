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

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_async_event;
struct rspamd_async_session;

typedef void (*event_finalizer_t) (gpointer ud);

typedef gboolean (*session_finalizer_t) (gpointer user_data);

/**
 * Make new async session
 * @param pool pool to alloc memory from
 * @param fin a callback called when no events are found in session
 * @param restore a callback is called to restore processing of session
 * @param cleanup a callback called when session is forcefully destroyed
 * @param user_data abstract user data
 * @return
 */
struct rspamd_async_session *rspamd_session_create (rspamd_mempool_t *pool,
													session_finalizer_t fin, event_finalizer_t restore,
													event_finalizer_t cleanup, gpointer user_data);

/**
 * Insert new event to the session
 * @param session session object
 * @param fin finalizer callback
 * @param user_data abstract user_data
 * @param forced unused
 */
struct rspamd_async_event *
rspamd_session_add_event_full (struct rspamd_async_session *session,
							   event_finalizer_t fin,
							   gpointer user_data,
							   const gchar *subsystem,
							   const gchar *loc);

#define rspamd_session_add_event(session, fin, user_data, subsystem) \
    rspamd_session_add_event_full(session, fin, user_data, subsystem, G_STRLOC)

/**
 * Remove normal event
 * @param session session object
 * @param fin final callback
 * @param ud user data object
 */
void rspamd_session_remove_event_full (struct rspamd_async_session *session,
									   event_finalizer_t fin,
									   gpointer ud,
									   const gchar *loc);

#define rspamd_session_remove_event(session, fin, user_data) \
    rspamd_session_remove_event_full(session, fin, user_data, G_STRLOC)

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
 * Returns mempool associated with async session
 * @param session
 * @return
 */
rspamd_mempool_t *rspamd_session_mempool (struct rspamd_async_session *session);

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
 * Returns TRUE if an async session is currently destroying
 * @param s
 * @return
 */
gboolean rspamd_session_blocked (struct rspamd_async_session *s);

#ifdef  __cplusplus
}
#endif

#endif /*RSPAMD_ASYNC_SESSION_H*/
