/*
 * Copyright 2025 Vsevolod Stakhov
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

#ifndef RSPAMD_MULTIPART_RESPONSE_H
#define RSPAMD_MULTIPART_RESPONSE_H

#include "config.h"
#include "libutil/fstring.h"
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rspamd_multipart_response_c;

struct rspamd_multipart_response_c *rspamd_multipart_response_new(void);

void rspamd_multipart_response_add_part(
	struct rspamd_multipart_response_c *resp,
	const char *name,
	const char *content_type,
	const char *data, gsize len,
	gboolean compress);

/**
 * Serialize the multipart response.
 * @param resp response handle
 * @param zstream ZSTD compression stream (may be NULL)
 * @return newly allocated fstring (caller owns)
 */
rspamd_fstring_t *rspamd_multipart_response_serialize(
	struct rspamd_multipart_response_c *resp,
	void *zstream);

/**
 * Prepare piecewise iov segments for zero-copy writev.
 * @param resp response handle
 * @param zstream ZSTD compression stream (may be NULL)
 */
void rspamd_multipart_response_prepare_iov(
	struct rspamd_multipart_response_c *resp,
	void *zstream);

/**
 * Get the prepared body iov segments.
 * Returned pointer is valid until resp is freed.
 * @param resp response handle
 * @param count [out] number of iov segments
 * @param total_len [out] total byte length across all segments
 * @return pointer to iov array
 */
const struct iovec *rspamd_multipart_response_body_iov(
	struct rspamd_multipart_response_c *resp,
	gsize *count,
	gsize *total_len);

/**
 * Get the Content-Type header value (includes boundary).
 * The returned string is valid until resp is freed.
 */
const char *rspamd_multipart_response_content_type(
	struct rspamd_multipart_response_c *resp);

void rspamd_multipart_response_free(
	struct rspamd_multipart_response_c *resp);

#ifdef __cplusplus
}
#endif

#endif /* RSPAMD_MULTIPART_RESPONSE_H */
