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
#ifndef RSPAMD_WORKER_PRIVATE_H
#define RSPAMD_WORKER_PRIVATE_H

#include "config.h"
#include "libcryptobox/cryptobox.h"
#include "libcryptobox/keypair.h"
#include "libserver/task.h"
#include "libserver/cfg_file.h"
#include "libserver/rspamd_control.h"

#ifdef  __cplusplus
extern "C" {
#endif

static const guint64 rspamd_worker_magic = 0xb48abc69d601dc1dULL;

struct rspamd_lang_detector;

struct rspamd_worker_ctx {
	guint64 magic;
	/* Events base */
	struct ev_loop *event_loop;
	/* DNS resolver */
	struct rspamd_dns_resolver *resolver;
	/* Config */
	struct rspamd_config *cfg;

	ev_tstamp timeout;
	/* Detect whether this worker is mime worker    */
	gboolean is_mime;
	/* Allow encrypted requests only using network */
	gboolean encrypted_only;
	/* Limit of tasks */
	guint32 max_tasks;
	/* Maximum time for task processing */
	ev_tstamp task_timeout;
	/* Encryption key */
	struct rspamd_cryptobox_keypair *key;
	/* Keys cache */
	struct rspamd_http_context *http_ctx;
	/* Language detector */
	struct rspamd_lang_detector *lang_det;
};

/*
 * Init scanning routines
 */
void rspamd_worker_init_scanner (struct rspamd_worker *worker,
								 struct ev_loop *ev_base,
								 struct rspamd_dns_resolver *resolver,
								 struct rspamd_lang_detector **plang_det);

#ifdef  __cplusplus
}
#endif

#endif
