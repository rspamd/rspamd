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
#ifndef SRC_LIBMIME_MIME_HEADERS_H_
#define SRC_LIBMIME_MIME_HEADERS_H_

#include "config.h"

struct rspamd_task;

struct rspamd_mime_header {
	gchar *name;
	gchar *value;
	const gchar *raw_value; /* As it is in the message (unfolded and unparsed) */
	gsize raw_len;
	gboolean tab_separated;
	gboolean empty_separator;
	gchar *separator;
	gchar *decoded;
};

void rspamd_mime_headers_process (struct rspamd_task *task, GHashTable *target,
		const gchar *in, gsize len, gboolean check_newlines);

#endif /* SRC_LIBMIME_MIME_HEADERS_H_ */
