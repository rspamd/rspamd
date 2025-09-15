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
#ifndef SRC_LIBMIME_MIME_PARSER_H_
#define SRC_LIBMIME_MIME_PARSER_H_

#include "config.h"

struct rspamd_config;

struct rspamd_mime_parser_config;

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize shared mime parser config (stores Lua refs, precompiled data) */
struct rspamd_mime_parser_config *rspamd_mime_parser_init_shared(struct rspamd_config *cfg);
void rspamd_mime_parser_free_shared(struct rspamd_mime_parser_config *cfg);

/* Accessors */
int rspamd_mime_parser_get_lua_magic_cbref(const struct rspamd_mime_parser_config *cfg);

struct rspamd_task;
struct rspamd_mime_part;

enum rspamd_mime_parse_error {
	RSPAMD_MIME_PARSE_OK = 0,
	RSPAMD_MIME_PARSE_FATAL,
	RSPAMD_MIME_PARSE_NESTING,
	RSPAMD_MIME_PARSE_NO_PART,
};

enum rspamd_mime_parse_error rspamd_mime_parse_task(struct rspamd_task *task,
													GError **err);

void rspamd_mime_parser_calc_digest(struct rspamd_mime_part *part);


#ifdef __cplusplus
}
#endif

#endif /* SRC_LIBMIME_MIME_PARSER_H_ */
