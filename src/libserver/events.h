/*
 * Copyright (c) 2009-2015, Vsevolod Stakhov
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

#ifndef RSPAMD_EVENTS_H
#define RSPAMD_EVENTS_H

#include "config.h"
#include "mem_pool.h"

struct rspamd_async_event;
struct rspamd_async_session;

typedef void (*event_finalizer_t)(gpointer ud);
typedef void (*event_watcher_t)(gpointer ud);
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
		event_watcher_t cb,
		gpointer ud);

/**
 * Stop watching mode, if no events are watched since the last `rspamd_session_watch_start`,
 * then the watcher is silently ignored
 * @param s session
 * @return number of events watched
 */
guint rspamd_session_watch_stop (struct rspamd_async_session *s);

#endif /* RSPAMD_EVENTS_H */
