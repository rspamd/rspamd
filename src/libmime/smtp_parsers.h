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
#ifndef SRC_LIBMIME_SMTP_PARSERS_H_
#define SRC_LIBMIME_SMTP_PARSERS_H_

#include "config.h"
#include "email_addr.h"
#include "task.h"
#include "message.h"

int rspamd_smtp_recieved_parse (struct rspamd_task *task,
		const char *data, size_t len, struct received_header *rh);
int rspamd_smtp_addr_parse (const char *data, size_t len,
		struct rspamd_email_address *addr);

void rspamd_strip_newlines_parse (const gchar *begin, const gchar *pe,
		GByteArray *data, gboolean is_html, guint *newlines_count,
		GPtrArray *newlines);

#endif /* SRC_LIBMIME_SMTP_PARSERS_H_ */
