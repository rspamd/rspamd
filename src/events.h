#ifndef RSPAMD_EVENTS_H
#define RSPAMD_EVENTS_H

#include "config.h"

struct rspamd_async_event;

typedef void (*event_finalizer_t)(void *user_data);

struct rspamd_async_event {
	event_finalizer_t fin;
	void *user_data;
	gboolean forced;
	guint ref;
};

struct rspamd_async_session {
	event_finalizer_t fin;
	GQueue *events;
	void *user_data;
	memory_pool_t *pool;
	gboolean wanna_die;
};

/* Makes new async session */
struct rspamd_async_session *new_async_session (memory_pool_t *pool, event_finalizer_t fin, void *user_data);
/* Insert event into session */
void register_async_event (struct rspamd_async_session *session, event_finalizer_t fin, void *user_data, gboolean forced);
/* Must be called by forced events to call session destructor properly */
void remove_forced_event (struct rspamd_async_session *session, event_finalizer_t fin);
void remove_normal_event (struct rspamd_async_session *session, event_finalizer_t fin, void *ud); 

/**
 * Must be called at the end of session, it calls fin functions for all non-forced callbacks
 * @return true if the whole session was destroyed and false if there are forced events 
 */
gboolean destroy_session (struct rspamd_async_session *session);

#endif /* RSPAMD_EVENTS_H */
