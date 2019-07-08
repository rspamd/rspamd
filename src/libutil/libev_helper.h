/*-
 * Copyright 2019 Vsevolod Stakhov
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

#ifndef RSPAMD_LIBEV_HELPER_H
#define RSPAMD_LIBEV_HELPER_H

#include "config.h"
#include "contrib/libev/ev.h"


#ifdef  __cplusplus
extern "C" {
#endif

/*
 * This module is a little helper to simplify libevent->libev transition
 * It allows to create timed IO watchers utilising both
 */

typedef void (*rspamd_ev_cb) (int fd, short what, void *ud);

struct rspamd_io_ev {
	ev_io io;
	ev_timer tm;
	rspamd_ev_cb cb;
	void *ud;
	ev_tstamp last_activity;
	ev_tstamp timeout;
};

/**
 * Initialize watcher similar to event_init
 * @param ev
 * @param fd
 * @param what
 * @param cb
 * @param ud
 */
void rspamd_ev_watcher_init (struct rspamd_io_ev *ev,
							 int fd, short what, rspamd_ev_cb cb, void *ud);

/**
 * Start watcher with the specific timeout
 * @param loop
 * @param ev
 * @param timeout
 */
void rspamd_ev_watcher_start (struct ev_loop *loop,
							  struct rspamd_io_ev *ev,
							  ev_tstamp timeout);

/**
 * Stops watcher and clean it up
 * @param loop
 * @param ev
 */
void rspamd_ev_watcher_stop (struct ev_loop *loop,
							 struct rspamd_io_ev *ev);

/**
 * Convenience function to reschedule watcher with different events
 * @param loop
 * @param ev
 * @param what
 */
void rspamd_ev_watcher_reschedule (struct ev_loop *loop,
								   struct rspamd_io_ev *ev,
								   short what);

#ifdef  __cplusplus
}
#endif

#endif
