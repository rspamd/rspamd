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
#ifndef SRC_LIBMIME_MIME_ENCODING_H_
#define SRC_LIBMIME_MIME_ENCODING_H_

#include "config.h"
#include "mem_pool.h"

struct rspamd_task;
struct rspamd_mime_part;
struct rspamd_mime_text_part;

/**
 * Convert charset to a valid iconv charset
 * @param pool pool to store temporary data
 * @param in
 * @return
 */
const gchar * rspamd_mime_detect_charset (rspamd_mempool_t *pool,
		const rspamd_ftok_t *in);

/**
 * Convert text chunk to utf-8. Input encoding is substituted using
 * `rspamd_mime_detect_charset`.
 * If input encoding is already utf, this function returns input pointer.
 * Memory is allocated from pool if a conversion is needed
 * @param pool
 * @param input
 * @param len
 * @param in_enc
 * @param olen
 * @param err
 * @return
 */
gchar * rspamd_mime_text_to_utf8 (rspamd_mempool_t *pool,
		gchar *input, gsize len, const gchar *in_enc,
		gsize *olen, GError **err);

/**
 * Maybe convert part to utf-8
 * @param task
 * @param text_part
 * @return
 */
GByteArray * rspamd_mime_text_part_maybe_convert (struct rspamd_task *task,
		struct rspamd_mime_text_part *text_part);


#endif /* SRC_LIBMIME_MIME_ENCODING_H_ */
