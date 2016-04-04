/*
 * Copyright (c) 2016, Vsevolod Stakhov
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
#ifndef RSPAMD_WORKER_PRIVATE_H
#define RSPAMD_WORKER_PRIVATE_H

#include "config.h"
#include "libcryptobox/cryptobox.h"
#include "libcryptobox/keypair.h"
#include "libserver/task.h"
#include "libserver/cfg_file.h"
#include "libserver/rspamd_control.h"

/*
 * Worker's context
 */
struct rspamd_worker_log_pipe {
	gint fd;
	enum rspamd_log_pipe_type type;
	struct rspamd_worker_log_pipe *prev, *next;
};

static const guint64 rspamd_worker_magic = 0xb48abc69d601dc1dULL;

struct rspamd_worker_ctx {
	guint64 magic;
	guint32 timeout;
	struct timeval io_tv;
	/* Detect whether this worker is mime worker    */
	gboolean is_mime;
	/* HTTP worker									*/
	gboolean is_http;
	/* JSON output                                  */
	gboolean is_json;
	/* Allow learning throught worker				*/
	gboolean allow_learn;
	/* DNS resolver */
	struct rspamd_dns_resolver *resolver;
	/* Limit of tasks */
	guint32 max_tasks;
	/* Maximum time for task processing */
	gdouble task_timeout;
	/* Events base */
	struct event_base *ev_base;
	/* Encryption key */
	struct rspamd_cryptobox_keypair *key;
	/* Keys cache */
	struct rspamd_keypair_cache *keys_cache;
	/* Configuration */
	struct rspamd_config *cfg;
	/* Log pipe */
	struct rspamd_worker_log_pipe *log_pipes;
};

#endif
