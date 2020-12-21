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
#ifndef SRC_LIBMIME_CONTENT_TYPE_H_
#define SRC_LIBMIME_CONTENT_TYPE_H_

#include "config.h"
#include "libutil/fstring.h"
#include "libutil/mem_pool.h"

#ifdef  __cplusplus
extern "C" {
#endif

enum rspamd_content_type_flags {
	RSPAMD_CONTENT_TYPE_VALID = 0,
	RSPAMD_CONTENT_TYPE_BROKEN = 1 << 0,
	RSPAMD_CONTENT_TYPE_MULTIPART = 1 << 1,
	RSPAMD_CONTENT_TYPE_TEXT = 1 << 2,
	RSPAMD_CONTENT_TYPE_MESSAGE = 1 << 3,
	RSPAMD_CONTENT_TYPE_DSN = 1 << 4,
	RSPAMD_CONTENT_TYPE_MISSING = 1 << 5,
	RSPAMD_CONTENT_TYPE_ENCRYPTED = 1 << 6,
	RSPAMD_CONTENT_TYPE_SMIME = 1 << 7,
};

enum rspamd_content_param_flags {
	RSPAMD_CONTENT_PARAM_NORMAL = 0,
	RSPAMD_CONTENT_PARAM_RFC2231 = (1 << 0),
	RSPAMD_CONTENT_PARAM_PIECEWISE = (1 << 1),
	RSPAMD_CONTENT_PARAM_BROKEN = (1 << 2),
};

struct rspamd_content_type_param {
	rspamd_ftok_t name;
	rspamd_ftok_t value;
	guint rfc2231_id;
	enum rspamd_content_param_flags flags;
	struct rspamd_content_type_param *prev, *next;
};

struct rspamd_content_type {
	gchar *cpy;
	rspamd_ftok_t type;
	rspamd_ftok_t subtype;
	rspamd_ftok_t charset;
	rspamd_ftok_t boundary;
	rspamd_ftok_t orig_boundary;
	enum rspamd_content_type_flags flags;
	GHashTable *attrs; /* Can be empty */
};

enum rspamd_content_disposition_type {
	RSPAMD_CT_UNKNOWN = 0,
	RSPAMD_CT_INLINE = 1,
	RSPAMD_CT_ATTACHMENT = 2,
};

struct rspamd_content_disposition {
	gchar *lc_data;
	enum rspamd_content_disposition_type type;
	rspamd_ftok_t filename;
	GHashTable *attrs; /* Can be empty */
};

/**
 * Adds new parameter to content type structure
 * @param ct
 * @param name_start (can be modified)
 * @param name_end
 * @param value_start (can be modified)
 * @param value_end
 */
void
rspamd_content_type_add_param (rspamd_mempool_t *pool,
							   struct rspamd_content_type *ct,
							   gchar *name_start, gchar *name_end,
							   gchar *value_start, gchar *value_end);

/**
 * Parse content type from the header (performs copy + lowercase)
 * @param in
 * @param len
 * @param pool
 * @return
 */
struct rspamd_content_type *rspamd_content_type_parse (const gchar *in,
													   gsize len, rspamd_mempool_t *pool);

/**
 * Adds new param for content disposition header
 * @param pool
 * @param cd
 * @param name_start
 * @param name_end
 * @param value_start
 * @param value_end
 */
void
rspamd_content_disposition_add_param (rspamd_mempool_t *pool,
									  struct rspamd_content_disposition *cd,
									  const gchar *name_start, const gchar *name_end,
									  const gchar *value_start, const gchar *value_end);

/**
 * Parse content-disposition header
 * @param in
 * @param len
 * @param pool
 * @return
 */
struct rspamd_content_disposition *rspamd_content_disposition_parse (const gchar *in,
																	 gsize len,
																	 rspamd_mempool_t *pool);

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBMIME_CONTENT_TYPE_H_ */
