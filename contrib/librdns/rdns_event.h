/*
 * Copyright (c) 2014, Vsevolod Stakhov
 *
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
#ifndef RDNS_EVENT_H_
#define RDNS_EVENT_H_

#include <event.h>
#include <stdlib.h>
#include <string.h>
#include "rdns.h"

#ifdef  __cplusplus
extern "C" {
#endif

static void* rdns_libevent_add_read (void *priv_data, int fd, void *user_data);
static void rdns_libevent_del_read(void *priv_data, void *ev_data);
static void* rdns_libevent_add_write (void *priv_data, int fd, void *user_data);
static void rdns_libevent_del_write (void *priv_data, void *ev_data);
static void* rdns_libevent_add_timer (void *priv_data, double after, void *user_data);
static void* rdns_libevent_add_periodic (void *priv_data, double after,
		rdns_periodic_callback cb, void *user_data);
static void rdns_libevent_del_periodic (void *priv_data, void *ev_data);
static void rdns_libevent_repeat_timer (void *priv_data, void *ev_data);
static void rdns_libevent_del_timer (void *priv_data, void *ev_data);

struct rdns_event_periodic_cbdata {
	struct event *ev;
	rdns_periodic_callback cb;
	void *cbdata;
};

static void
rdns_bind_libevent (struct rdns_resolver *resolver, struct event_base *ev_base)
{
	struct rdns_async_context ev_ctx = {
		.add_read = rdns_libevent_add_read,
		.del_read = rdns_libevent_del_read,
		.add_write = rdns_libevent_add_write,
		.del_write = rdns_libevent_del_write,
		.add_timer = rdns_libevent_add_timer,
		.add_periodic = rdns_libevent_add_periodic,
		.del_periodic = rdns_libevent_del_periodic,
		.repeat_timer = rdns_libevent_repeat_timer,
		.del_timer = rdns_libevent_del_timer,
		.cleanup = NULL
	}, *nctx;

	/* XXX: never got freed */
	nctx = malloc (sizeof (struct rdns_async_context));
	if (nctx != NULL) {
		memcpy (nctx, &ev_ctx, sizeof (struct rdns_async_context));
		nctx->data = ev_base;
	}
	rdns_resolver_async_bind (resolver, nctx);
}

static void
rdns_libevent_read_event (int fd, short what, void *ud)
{
	rdns_process_read (fd, ud);
}

static void
rdns_libevent_write_event (int fd, short what, void *ud)
{
	rdns_process_retransmit (fd, ud);
}

static void
rdns_libevent_timer_event (int fd, short what, void *ud)
{
	rdns_process_timer (ud);
}

static void
rdns_libevent_periodic_event (int fd, short what, void *ud)
{
	struct rdns_event_periodic_cbdata *cbdata = ud;
	cbdata->cb (cbdata->cbdata);
}

static void*
rdns_libevent_add_read (void *priv_data, int fd, void *user_data)
{
	struct event *ev;
	ev = malloc (sizeof (struct event));
	if (ev != NULL) {
		event_set (ev, fd, EV_READ | EV_PERSIST, rdns_libevent_read_event, user_data);
		event_base_set (priv_data, ev);
		event_add (ev, NULL);
	}
	return ev;
}

static void
rdns_libevent_del_read(void *priv_data, void *ev_data)
{
	struct event *ev = ev_data;
	if (ev != NULL) {
		event_del (ev);
		free (ev);
	}
}
static void*
rdns_libevent_add_write (void *priv_data, int fd, void *user_data)
{
	struct event *ev;
	ev = malloc (sizeof (struct event));
	if (ev != NULL) {
		event_set (ev, fd, EV_WRITE | EV_PERSIST,
				rdns_libevent_write_event, user_data);
		event_base_set (priv_data, ev);
		event_add (ev, NULL);
	}
	return ev;
}

static void
rdns_libevent_del_write (void *priv_data, void *ev_data)
{
	struct event *ev = ev_data;
	if (ev != NULL) {
		event_del (ev);
		free (ev);
	}
}

#define rdns_event_double_to_tv(dbl, tv) do {											\
    (tv)->tv_sec = (int)(dbl); 												\
    (tv)->tv_usec = ((dbl) - (int)(dbl))*1000*1000; 						\
} while(0)

static void*
rdns_libevent_add_timer (void *priv_data, double after, void *user_data)
{
	struct event *ev;
	struct timeval tv;
	ev = malloc (sizeof (struct event));
	if (ev != NULL) {
		rdns_event_double_to_tv (after, &tv);
		event_set (ev, -1, EV_TIMEOUT|EV_PERSIST, rdns_libevent_timer_event, user_data);
		event_base_set (priv_data, ev);
		event_add (ev, &tv);
	}
	return ev;
}

static void*
rdns_libevent_add_periodic (void *priv_data, double after,
		rdns_periodic_callback cb, void *user_data)
{
	struct event *ev;
	struct timeval tv;
	struct rdns_event_periodic_cbdata *cbdata = NULL;

	ev = malloc (sizeof (struct event));
	if (ev != NULL) {
		cbdata = malloc (sizeof (struct rdns_event_periodic_cbdata));
		if (cbdata != NULL) {
			rdns_event_double_to_tv (after, &tv);
			cbdata->cb = cb;
			cbdata->cbdata = user_data;
			cbdata->ev = ev;
			event_set (ev, -1, EV_TIMEOUT|EV_PERSIST, rdns_libevent_periodic_event, cbdata);
			event_base_set (priv_data, ev);
			event_add (ev, &tv);
		}
		else {
			free (ev);
			return NULL;
		}
	}
	return cbdata;
}

static void
rdns_libevent_del_periodic (void *priv_data, void *ev_data)
{
	struct rdns_event_periodic_cbdata *cbdata = ev_data;
	if (cbdata != NULL) {
		event_del (cbdata->ev);
		free (cbdata->ev);
		free (cbdata);
	}
}

static void
rdns_libevent_repeat_timer (void *priv_data, void *ev_data)
{
	/* XXX: libevent hides timeval, so timeouts are persistent here */
}

#undef rdns_event_double_to_tv

static void
rdns_libevent_del_timer (void *priv_data, void *ev_data)
{
	struct event *ev = ev_data;
	if (ev != NULL) {
		event_del (ev);
		free (ev);
	}
}

#ifdef  __cplusplus
}
#endif

#endif /* RDNS_EV_H_ */
