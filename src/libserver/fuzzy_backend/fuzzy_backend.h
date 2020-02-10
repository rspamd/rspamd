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
#ifndef SRC_LIBSERVER_FUZZY_BACKEND_H_
#define SRC_LIBSERVER_FUZZY_BACKEND_H_

#include "config.h"
#include "contrib/libev/ev.h"
#include "fuzzy_wire.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_fuzzy_backend;
struct rspamd_config;

/*
 * Callbacks for fuzzy methods
 */
typedef void (*rspamd_fuzzy_check_cb) (struct rspamd_fuzzy_reply *rep, void *ud);

typedef void (*rspamd_fuzzy_update_cb) (gboolean success,
										guint nadded,
										guint ndeleted,
										guint nextended,
										guint nignored,
										void *ud);

typedef void (*rspamd_fuzzy_version_cb) (guint64 rev, void *ud);

typedef void (*rspamd_fuzzy_count_cb) (guint64 count, void *ud);

typedef gboolean (*rspamd_fuzzy_periodic_cb) (void *ud);

/**
 * Open fuzzy backend
 * @param ev_base
 * @param config
 * @param err
 * @return
 */
struct rspamd_fuzzy_backend *rspamd_fuzzy_backend_create (struct ev_loop *ev_base,
														  const ucl_object_t *config,
														  struct rspamd_config *cfg,
														  GError **err);


/**
 * Check a specific hash in storage
 * @param cmd
 * @param cb
 * @param ud
 */
void rspamd_fuzzy_backend_check (struct rspamd_fuzzy_backend *bk,
								 const struct rspamd_fuzzy_cmd *cmd,
								 rspamd_fuzzy_check_cb cb, void *ud);

/**
 * Process updates for a specific queue
 * @param bk
 * @param updates queue of struct fuzzy_peer_cmd
 * @param src
 */
void rspamd_fuzzy_backend_process_updates (struct rspamd_fuzzy_backend *bk,
										   GArray *updates, const gchar *src, rspamd_fuzzy_update_cb cb,
										   void *ud);

/**
 * Gets number of hashes from the backend
 * @param bk
 * @param cb
 * @param ud
 */
void rspamd_fuzzy_backend_count (struct rspamd_fuzzy_backend *bk,
								 rspamd_fuzzy_count_cb cb, void *ud);

/**
 * Returns number of revision for a specific source
 * @param bk
 * @param src
 * @param cb
 * @param ud
 */
void rspamd_fuzzy_backend_version (struct rspamd_fuzzy_backend *bk,
								   const gchar *src,
								   rspamd_fuzzy_version_cb cb, void *ud);

/**
 * Returns unique id for backend
 * @param backend
 * @return
 */
const gchar *rspamd_fuzzy_backend_id (struct rspamd_fuzzy_backend *backend);

/**
 * Starts expire process for the backend
 * @param backend
 */
void rspamd_fuzzy_backend_start_update (struct rspamd_fuzzy_backend *backend,
										gdouble timeout,
										rspamd_fuzzy_periodic_cb cb,
										void *ud);

struct ev_loop *rspamd_fuzzy_backend_event_base (struct rspamd_fuzzy_backend *backend);

gdouble rspamd_fuzzy_backend_get_expire (struct rspamd_fuzzy_backend *backend);

/**
 * Closes backend
 * @param backend
 */
void rspamd_fuzzy_backend_close (struct rspamd_fuzzy_backend *backend);

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBSERVER_FUZZY_BACKEND_H_ */
