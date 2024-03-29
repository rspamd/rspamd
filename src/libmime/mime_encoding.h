/*
 * Copyright 2024 Vsevolod Stakhov
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
#ifndef SRC_LIBMIME_MIME_ENCODING_H_
#define SRC_LIBMIME_MIME_ENCODING_H_

#include "config.h"
#include "mem_pool.h"
#include "fstring.h"
#include <unicode/uchar.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rspamd_task;
struct rspamd_mime_part;
struct rspamd_mime_text_part;
struct rspamd_charset_converter;

/**
 * Convert charset alias to a canonic charset name
 * @param pool pool to store temporary data
 * @param in
 * @return
 */
const char *rspamd_mime_detect_charset(const rspamd_ftok_t *in,
									   rspamd_mempool_t *pool);

/**
 * Convert text chunk to utf-8. Input encoding is substituted using
 * `rspamd_mime_detect_charset`.
 * If input encoding is already utf, this function returns input pointer.
 * Memory is allocated from pool if a conversion is needed
 * @param pool
 * @param input
 * @param len
 * @param in_enc canon charset
 * @param olen
 * @param err
 * @return
 */
char *rspamd_mime_text_to_utf8(rspamd_mempool_t *pool,
							   char *input, gsize len, const char *in_enc,
							   gsize *olen, GError **err);

/**
 * Converts data from `in` to `out`,
 * returns `FALSE` if `enc` is not a valid iconv charset
 *
 * This function, in fact, copies `in` from `out` replacing out content in
 * total.
 * @param in
 * @param out
 * @param enc validated canonical charset name. If NULL, then utf8 check is done only
 * @return
 */
gboolean rspamd_mime_to_utf8_byte_array(GByteArray *in,
										GByteArray *out,
										rspamd_mempool_t *pool,
										const char *enc);

/**
 * Maybe convert part to utf-8
 * @param task
 * @param text_part
 * @return
 */
void rspamd_mime_text_part_maybe_convert(struct rspamd_task *task,
										 struct rspamd_mime_text_part *text_part);

/**
 * Checks utf8 charset and normalize/validate utf8 string
 * @param charset
 * @param in
 * @param len
 * @return
 */
gboolean rspamd_mime_charset_utf_check(rspamd_ftok_t *charset,
									   char *in, gsize len,
									   gboolean content_check);

/**
 * Ensure that all characters in string are valid utf8 chars or replace them
 * with '?'
 * @param in
 * @param len
 */
void rspamd_mime_charset_utf_enforce(char *in, gsize len);

/**
  * Gets cached converter
  * @param enc input encoding
  * @param pool pool to use for temporary normalisation
  * @param is_canon TRUE if normalisation is needed
  * @param err output error
  * @return converter
  */
struct rspamd_charset_converter *rspamd_mime_get_converter_cached(
	const char *enc,
	rspamd_mempool_t *pool,
	gboolean is_canon,
	UErrorCode *err);

/**
 * Performs charset->utf16 conversion
 * @param cnv
 * @param dest
 * @param destCapacity
 * @param src
 * @param srcLength
 * @param pErrorCode
 * @return
 */
int32_t
rspamd_converter_to_uchars(struct rspamd_charset_converter *cnv,
						   UChar *dest,
						   int32_t destCapacity,
						   const char *src,
						   int32_t srcLength,
						   UErrorCode *pErrorCode);

/**
 * Detect charset in text
 * @param in
 * @param inlen
 * @return detected charset name or NULL
 */
const char *rspamd_mime_charset_find_by_content(const char *in, gsize inlen,
												bool check_utf8);

#ifdef __cplusplus
}
#endif

#endif /* SRC_LIBMIME_MIME_ENCODING_H_ */
