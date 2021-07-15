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
#ifndef SRC_LIBSERVER_COMPOSITES_H_
#define SRC_LIBSERVER_COMPOSITES_H_

#include "config.h"
#include "contrib/libucl/ucl.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_task;
struct rspamd_config;

/**
 * Process all results and form composite metrics from existent metrics as it is defined in config
 * @param task worker's task that present message from user
 */
void rspamd_composites_process_task(struct rspamd_task *task);

/**
 * Creates a composites manager
 * @param cfg
 * @return
 */
void* rspamd_composites_manager_create(struct rspamd_config *cfg);
/**
 * Returns number of elements in a composite manager
 * @return
 */
gsize rspamd_composites_manager_nelts(void *);
/**
 * Adds a composite from config
 * @return
 */
void* rspamd_composites_manager_add_from_ucl(void *,  const char *, const ucl_object_t *);

/**
 * Adds a composite from config
 * @return
 */
void* rspamd_composites_manager_add_from_string(void *, const char *, const char *);

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBSERVER_COMPOSITES_H_ */
