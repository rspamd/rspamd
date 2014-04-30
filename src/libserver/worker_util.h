/* Copyright (c) 2014, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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
#ifndef WORKER_UTIL_H_
#define WORKER_UTIL_H_

#include "config.h"
#include "util.h"

/**
 * Return worker's control structure by its type
 * @param type
 * @return worker's control structure or NULL
 */
worker_t* get_worker_by_type (GQuark type);

/**
 * Set counter for a symbol
 */
double set_counter (const gchar *name, guint32 value);

#ifndef HAVE_SA_SIGINFO
typedef void (*rspamd_sig_handler_t) (gint);
#else
typedef void (*rspamd_sig_handler_t) (gint, siginfo_t *, void *);
#endif

struct rspamd_worker;

/**
 * Prepare worker's startup
 * @param worker worker structure
 * @param name name of the worker
 * @param sig_handler handler of main signals
 * @param accept_handler handler of accept event for listen sockets
 * @return event base suitable for a worker
 */
struct event_base *
prepare_worker (struct rspamd_worker *worker, const char *name,
		void (*accept_handler)(int, short, void *));

/**
 * Stop accepting new connections for a worker
 * @param worker
 */
void worker_stop_accept (struct rspamd_worker *worker);

#endif /* WORKER_UTIL_H_ */
