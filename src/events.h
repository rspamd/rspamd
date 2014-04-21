#ifndef RSPAMD_EVENTS_H
#define RSPAMD_EVENTS_H

#include "config.h"
#include "mem_pool.h"

struct rspamd_async_event;

typedef void (*event_finalizer_t)(void *user_data);
typedef gboolean (*session_finalizer_t)(void *user_data);

struct rspamd_async_event {
	GQuark subsystem;
	event_finalizer_t fin;
	void *user_data;
	guint ref;
};

struct rspamd_async_session {
	session_finalizer_t fin;
	event_finalizer_t restore;
	event_finalizer_t cleanup;
	GHashTable *events;
	void *user_data;
	rspamd_mempool_t *pool;
	gboolean wanna_die;
	guint threads;
	GMutex *mtx;
	GCond *cond;
};

/**
 * Make new async session
 * @param pool pool to alloc memory from
 * @param fin a callback called when no events are found in session
 * @param restore a callback is called to restore processing of session
 * @param cleanup a callback called when session is forcefully destroyed
 * @param user_data abstract user data
 * @return
 */
struct rspamd_async_session *new_async_session (rspamd_mempool_t *pool,
		session_finalizer_t fin, event_finalizer_t restore,
		event_finalizer_t cleanup, void *user_data);

/**
 * Insert new event to the session
 * @param session session object
 * @param fin finalizer callback
 * @param user_data abstract user_data
 * @param forced unused
 */
void register_async_event (struct rspamd_async_session *session,
		event_finalizer_t fin, void *user_data, GQuark subsystem);

/**
 * Remove normal event
 * @param session session object
 * @param fin final callback
 * @param ud user data object
 */
void remove_normal_event (struct rspamd_async_session *session, event_finalizer_t fin, void *ud); 

/**
 * Must be called at the end of session, it calls fin functions for all non-forced callbacks
 * @return true if the whole session was destroyed and false if there are forced events 
 */
gboolean destroy_session (struct rspamd_async_session *session);

/**
 * Check session for events pending and call fin callback if no events are pending
 * @param session session object
 * @return TRUE if session has pending events
 */
gboolean check_session_pending (struct rspamd_async_session *session);

/**
 * Add new async thread to session
 * @param session session object
 */
void register_async_thread (struct rspamd_async_session *session);

/**
 * Remove async thread from session and check whether session can be terminated
 * @param session session object
 */
void remove_async_thread (struct rspamd_async_session *session);

#endif /* RSPAMD_EVENTS_H */
