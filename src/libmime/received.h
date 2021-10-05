/*-
 * Copyright 2021 Vsevolod Stakhov
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


#ifndef RSPAMD_RECEIVED_H
#define RSPAMD_RECEIVED_H

#include "config.h"
#include "libutil/addr.h"

#ifdef  __cplusplus
extern "C" {
#endif
/*
 * C bindings for C++ received code
 */

struct rspamd_email_address;
struct rspamd_received_header_chain;
struct rspamd_mime_header;

/**
 * Parse received header from an input header data
 * @param task
 * @param data
 * @param sz
 * @param hdr
 * @return
 */
bool rspamd_received_header_parse(struct rspamd_task *task,
		const char *data, size_t sz, struct rspamd_mime_header *hdr);


/**
 * Process task data and the most top received and fix either part if needed
 * @param task
 * @return
 */
bool rspamd_received_maybe_fix_task(struct rspamd_task *task);

struct lua_State;
/**
 * Push received headers chain to lua
 * @param task
 * @param L
 * @return
 */
bool rspamd_received_export_to_lua(struct rspamd_task *task, struct lua_State *L);

#ifdef  __cplusplus
}
#endif


#endif //RSPAMD_RECEIVED_H
