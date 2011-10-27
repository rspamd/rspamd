/* Copyright (c) 2010, Vsevolod Stakhov
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


#ifndef KVSTORAGE_SERVER_H_
#define KVSTORAGE_SERVER_H_

#include "config.h"
#include "mem_pool.h"

/* Configuration context for kvstorage worker */
struct kvstorage_worker_ctx {
	struct timeval io_timeout;
	guint32 timeout_raw;
	GList *threads;
	gint s_pair[2];
	memory_pool_t *pool;
	struct event_base *ev_base;
	GStaticMutex log_mtx;
};

struct kvstorage_worker_thread {
	struct event bind_ev;
	struct timeval *tv;
	struct kvstorage_worker_ctx *ctx;
	struct rspamd_worker *worker;
	GThread *thr;
	struct event_base *ev_base;
	GStaticMutex *log_mtx;
	guint id;
};

gpointer init_kvstorage_worker (void);
void start_kvstorage_worker (struct rspamd_worker *worker);

#endif /* KVSTORAGE_SERVER_H_ */
