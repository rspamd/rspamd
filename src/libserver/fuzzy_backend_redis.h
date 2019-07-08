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
#ifndef SRC_LIBSERVER_FUZZY_BACKEND_REDIS_H_
#define SRC_LIBSERVER_FUZZY_BACKEND_REDIS_H_

#include "config.h"
#include "fuzzy_backend.h"


#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Subroutines for fuzzy_backend
 */
void *rspamd_fuzzy_backend_init_redis (struct rspamd_fuzzy_backend *bk,
									   const ucl_object_t *obj,
									   struct rspamd_config *cfg,
									   GError **err);

void rspamd_fuzzy_backend_check_redis (struct rspamd_fuzzy_backend *bk,
									   const struct rspamd_fuzzy_cmd *cmd,
									   rspamd_fuzzy_check_cb cb, void *ud,
									   void *subr_ud);

void rspamd_fuzzy_backend_update_redis (struct rspamd_fuzzy_backend *bk,
										GArray *updates, const gchar *src,
										rspamd_fuzzy_update_cb cb, void *ud,
										void *subr_ud);

void rspamd_fuzzy_backend_count_redis (struct rspamd_fuzzy_backend *bk,
									   rspamd_fuzzy_count_cb cb, void *ud,
									   void *subr_ud);

void rspamd_fuzzy_backend_version_redis (struct rspamd_fuzzy_backend *bk,
										 const gchar *src,
										 rspamd_fuzzy_version_cb cb, void *ud,
										 void *subr_ud);

const gchar *rspamd_fuzzy_backend_id_redis (struct rspamd_fuzzy_backend *bk,
											void *subr_ud);

void rspamd_fuzzy_backend_expire_redis (struct rspamd_fuzzy_backend *bk,
										void *subr_ud);

void rspamd_fuzzy_backend_close_redis (struct rspamd_fuzzy_backend *bk,
									   void *subr_ud);

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBSERVER_FUZZY_BACKEND_REDIS_H_ */
