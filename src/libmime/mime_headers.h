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
#include "libutil/mem_pool.h"

struct rspamd_task;

enum rspamd_rfc2047_encoding {
	RSPAMD_RFC2047_QP = 0,
	RSPAMD_RFC2047_BASE64,
};

enum rspamd_mime_header_special_type {
	RSPAMD_HEADER_GENERIC = 0,
	RSPAMD_HEADER_RECEIVED = 1 << 0,
	RSPAMD_HEADER_TO = 1 << 2,
	RSPAMD_HEADER_CC = 1 << 3,
	RSPAMD_HEADER_BCC = 1 << 4,
	RSPAMD_HEADER_FROM = 1 << 5,
	RSPAMD_HEADER_MESSAGE_ID = 1 << 6,
	RSPAMD_HEADER_SUBJECT = 1 << 7,
	RSPAMD_HEADER_RETURN_PATH = 1 << 8,
	RSPAMD_HEADER_DELIVERED_TO = 1 << 9,
	RSPAMD_HEADER_SENDER = 1 << 10,
	RSPAMD_HEADER_RCPT = 1 << 11,
	RSPAMD_HEADER_UNIQUE = 1 << 12
};

struct rspamd_mime_header {
	gchar *name;
	gchar *value;
	const gchar *raw_value; /* As it is in the message (unfolded and unparsed) */
	gsize raw_len;
	gboolean tab_separated;
	gboolean empty_separator;
	guint order;
	enum rspamd_mime_header_special_type type;
	gchar *separator;
	gchar *decoded;
};

/**
 * Process headers and store them in `target`
 * @param task
 * @param target
 * @param in
 * @param len
 * @param check_newlines
 */
void rspamd_mime_headers_process (struct rspamd_task *task, GHashTable *target,
		GQueue *order,
		const gchar *in, gsize len,
		gboolean check_newlines);

/**
 * Perform rfc2047 decoding of a header
 * @param pool
 * @param in
 * @param inlen
 * @return
 */
gchar * rspamd_mime_header_decode (rspamd_mempool_t *pool, const gchar *in,
		gsize inlen, gboolean *invalid_utf);

/**
 * Encode mime header if needed
 * @param in
 * @param len
 * @return newly allocated encoded header
 */
gchar * rspamd_mime_header_encode (const gchar *in, gsize len);

/**
 * Generate new unique message id
 * @param fqdn
 * @return
 */
gchar * rspamd_mime_message_id_generate (const gchar *fqdn);

#endif /* SRC_LIBMIME_MIME_HEADERS_H_ */
