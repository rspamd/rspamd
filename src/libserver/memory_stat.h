/*
 * Copyright 2026 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef RSPAMD_MEMORY_STAT_H
#define RSPAMD_MEMORY_STAT_H

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rspamd_main;
struct rspamd_worker;
struct rspamd_control_command;

/**
 * Collect a memory dump for the current worker and send it back over the
 * control pipe. The function builds a UCL document with mempool statistics,
 * Lua heap usage, process memory information and (when compiled in) jemalloc
 * stats; it serializes the document to a temporary file and passes the file
 * descriptor over @fd via SCM_RIGHTS together with a short summary reply.
 *
 * Returns TRUE if the reply was successfully sent (regardless of how much
 * detail was collected).
 */
gboolean rspamd_memory_stat_collect_and_send(struct rspamd_main *rspamd_main,
											 struct rspamd_worker *worker,
											 int fd,
											 struct rspamd_control_command *cmd);

#ifdef __cplusplus
}
#endif

#endif
