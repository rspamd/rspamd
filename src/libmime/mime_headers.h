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
#include "libutil/addr.h"
#include "khash.h"
#include "contrib/libucl/ucl.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_task;

enum rspamd_rfc2047_encoding {
	RSPAMD_RFC2047_QP = 0,
	RSPAMD_RFC2047_BASE64,
};

enum rspamd_mime_header_flags {
	RSPAMD_HEADER_GENERIC = 0u,
	RSPAMD_HEADER_RECEIVED = 1u << 0u,
	RSPAMD_HEADER_TO = 1u << 2u,
	RSPAMD_HEADER_CC = 1u << 3u,
	RSPAMD_HEADER_BCC = 1u << 4u,
	RSPAMD_HEADER_FROM = 1u << 5u,
	RSPAMD_HEADER_MESSAGE_ID = 1u << 6u,
	RSPAMD_HEADER_SUBJECT = 1u << 7u,
	RSPAMD_HEADER_RETURN_PATH = 1u << 8u,
	RSPAMD_HEADER_DELIVERED_TO = 1u << 9u,
	RSPAMD_HEADER_SENDER = 1u << 10u,
	RSPAMD_HEADER_RCPT = 1u << 11u,
	RSPAMD_HEADER_UNIQUE = 1u << 12u,
	RSPAMD_HEADER_EMPTY_SEPARATOR = 1u << 13u,
	RSPAMD_HEADER_TAB_SEPARATED = 1u << 14u,
	RSPAMD_HEADER_MODIFIED = 1u << 15u, /* Means we need to check modified chain */
	RSPAMD_HEADER_ADDED = 1u << 16u, /* A header has been artificially added */
	RSPAMD_HEADER_REMOVED = 1u << 17u, /* A header has been artificially removed */
	RSPAMD_HEADER_NON_EXISTING = 1u << 18u, /* Header was not in the original message */
};

struct rspamd_mime_header {
	const gchar *raw_value; /* As it is in the message (unfolded and unparsed) */
	gsize raw_len;
	guint order;
	int flags; /* see enum rspamd_mime_header_flags */
	/* These are zero terminated (historically) */
	gchar *name; /* Also used for key */
	gchar *value;
	gchar *separator;
	gchar *decoded;
	struct rspamd_mime_header *modified_chain; /* Headers modified during transform */
	struct rspamd_mime_header *prev, *next; /* Headers with the same name */
	struct rspamd_mime_header *ord_next; /* Overall order of headers, slist */
};

struct rspamd_mime_headers_table;

/**
 * Process headers and store them in `target`
 * @param task
 * @param target
 * @param in
 * @param len
 * @param check_newlines
 */
void rspamd_mime_headers_process (struct rspamd_task *task,
								  struct rspamd_mime_headers_table *target,
								  struct rspamd_mime_header **order_ptr,
								  const gchar *in, gsize len,
								  gboolean check_newlines);

/**
 * Perform rfc2047 decoding of a header
 * @param pool
 * @param in
 * @param inlen
 * @return
 */
gchar *rspamd_mime_header_decode (rspamd_mempool_t *pool, const gchar *in,
								  gsize inlen, gboolean *invalid_utf);

/**
 * Encode mime header if needed
 * @param in
 * @param len
 * @return newly allocated encoded header
 */
gchar *rspamd_mime_header_encode (const gchar *in, gsize len);

/**
 * Generate new unique message id
 * @param fqdn
 * @return
 */
gchar *rspamd_mime_message_id_generate (const gchar *fqdn);

/**
 * Get an array of header's values with specified header's name using raw headers
 * @param task worker task structure
 * @param field header's name
 * @return An array of header's values or NULL. It is NOT permitted to free array or values.
 */
struct rspamd_mime_header *
rspamd_message_get_header_array (struct rspamd_task *task,
								const gchar *field,
								gboolean need_modified);

/**
 * Get an array of header's values with specified header's name using raw headers
 * @param htb hash table indexed by header name (caseless) with ptr arrays as elements
 * @param field header's name
 * @return An array of header's values or NULL. It is NOT permitted to free array or values.
 */
struct rspamd_mime_header *
rspamd_message_get_header_from_hash (struct rspamd_mime_headers_table *hdrs,
									 const gchar *field,
									 gboolean need_modified);

/**
 * Modifies a header (or insert one if not found)
 * @param hdrs
 * @param hdr_name
 * @param obj an array of modified values
 *
 */
void
rspamd_message_set_modified_header (struct rspamd_task *task,
									struct rspamd_mime_headers_table *hdrs,
									const gchar *hdr_name,
									const ucl_object_t *obj);

/**
 * Cleans up hash table of the headers
 * @param htb
 */
void rspamd_message_headers_unref (struct rspamd_mime_headers_table *hdrs);

struct rspamd_mime_headers_table * rspamd_message_headers_ref (struct rspamd_mime_headers_table *hdrs);

/**
 * Init headers hash
 * @return
 */
struct rspamd_mime_headers_table* rspamd_message_headers_new (void);

/**
 * Returns size for a headers table
 * @param hdrs
 * @return
 */
gsize rspamd_mime_headers_count (struct rspamd_mime_headers_table *hdrs);

typedef bool(rspamd_hdr_traverse_func_t)(const gchar *, const struct rspamd_mime_header *, void *);
/**
 * Traverse all headers in a table
 * @param func
 * @param ud
 * @return
 */
bool rspamd_mime_headers_foreach(const struct rspamd_mime_headers_table *,
		rspamd_hdr_traverse_func_t func, void *ud);

/**
 * Strip rfc822 CFWS sequences from a string in place
 * @param input input
 * @param len length of the input
 * @return new length of the input
 */
gsize rspamd_strip_smtp_comments_inplace (gchar *input, gsize len);

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBMIME_MIME_HEADERS_H_ */
