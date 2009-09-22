/*
 * Copyright (c) 2009, Rambler media
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
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "main.h"
#include "events.h"


struct rspamd_async_session*
new_async_session (memory_pool_t *pool, event_finalizer_t fin, void *user_data)
{
	struct rspamd_async_session *new;

	new = memory_pool_alloc (pool, sizeof (struct rspamd_async_session));
	new->pool = pool;
	new->fin = fin;
	new->user_data = user_data;
	new->wanna_die = FALSE;
	new->events = g_queue_new ();

	memory_pool_add_destructor (pool, (pool_destruct_func)g_queue_free, new->events);

	return new;
}

void 
register_async_event (struct rspamd_async_session *session, event_finalizer_t fin, void *user_data, gboolean forced)
{
	struct rspamd_async_event *new, *ev;
	GList *cur;

	if (session == NULL) {
		msg_info ("register_async_event: session is NULL");
		return;
	}
	
	if (forced) {
		/* For forced events try first to increase its reference */
		cur = session->events->head;
		while (cur) {
			ev = cur->data;
			if (ev->forced && ev->fin == fin) {
				ev->ref ++;
				return;
			}
			cur = g_list_next (cur);
		}
	}

	new = memory_pool_alloc (session->pool, sizeof (struct rspamd_async_event));
	new->fin = fin;
	new->user_data = user_data;
	new->forced = forced;
	new->ref = 1;
	g_queue_push_head (session->events, new);
}

void 
remove_forced_event (struct rspamd_async_session *session, event_finalizer_t fin)
{
	struct rspamd_async_event *ev;
	GList *cur;

	if (session == NULL) {
		msg_info ("remove_forced_event: session is NULL");
		return;
	}
	
	cur = session->events->head;
	while (cur) {
		ev = cur->data;
		if (ev->forced && ev->fin == fin) {
			ev->ref --;
			if (ev->ref == 0) {
				g_queue_delete_link (session->events, cur);
			}
			break;
		}
		cur = g_list_next (cur);
	}

	if (session->wanna_die && session->fin != NULL && g_queue_get_length (session->events) == 0) {
		/* Call session destroy after all forced events are ready */
		session->fin (session->user_data);
	}
}

void 
remove_normal_event (struct rspamd_async_session *session, event_finalizer_t fin, void *ud) 
{
	struct rspamd_async_event *ev;
	GList *cur;

	if (session == NULL) {
		msg_info ("remove_forced_event: session is NULL");
		return;
	}
	
	cur = session->events->head;
	while (cur) {
		ev = cur->data;
		if (ev->fin == fin && ev->user_data == ud && !ev->forced) {
			g_queue_delete_link (session->events, cur);
			if (ev->fin) {
				ev->fin (ev->user_data);
			}
			break;
		}
		cur = g_list_next (cur);
	}
}

gboolean
destroy_session (struct rspamd_async_session *session)
{
	struct rspamd_async_event *ev;
	GList *cur, *tmp;

	if (session == NULL) {
		msg_info ("destroy_session: session is NULL");
		return FALSE;
	}
	
	session->wanna_die = TRUE;
	
	cur = session->events->head;

	while (cur) {
		ev = cur->data;
		if (!ev->forced) {
			if (ev->fin != NULL) {
				ev->fin (ev->user_data);
			}
			tmp = cur;
			cur = g_list_next (cur);
			g_queue_delete_link (session->events, tmp);
		}
		else {
			/* Do nothing with forced callbacks */
			cur = g_list_next (cur);
		}
	}

	if (g_queue_get_length (session->events) == 0) {
		if (session->fin != NULL) {
			session->fin (session->user_data);
		}
		return TRUE;
	}

	return FALSE;
}
