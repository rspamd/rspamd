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
#ifndef SRC_LIBMIME_EMAIL_ADDR_H_
#define SRC_LIBMIME_EMAIL_ADDR_H_

#include "config.h"
#include "libutil/mem_pool.h"
#include "libutil/ref.h"


#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_mime_header;

enum rspamd_email_address_flags {
	RSPAMD_EMAIL_ADDR_VALID = (1 << 0),
	RSPAMD_EMAIL_ADDR_IP = (1 << 1),
	RSPAMD_EMAIL_ADDR_BRACED = (1 << 2),
	RSPAMD_EMAIL_ADDR_QUOTED = (1 << 3),
	RSPAMD_EMAIL_ADDR_EMPTY = (1 << 4),
	RSPAMD_EMAIL_ADDR_HAS_BACKSLASH = (1 << 5),
	RSPAMD_EMAIL_ADDR_ADDR_ALLOCATED = (1 << 6),
	RSPAMD_EMAIL_ADDR_USER_ALLOCATED = (1 << 7),
	RSPAMD_EMAIL_ADDR_HAS_8BIT = (1 << 8),
	RSPAMD_EMAIL_ADDR_ALIASED = (1 << 9),
	RSPAMD_EMAIL_ADDR_ORIGINAL = (1 << 10),
};

/*
 * Structure that represents email address in a convenient way
 */
struct rspamd_email_address {
	const gchar *raw;
	const gchar *addr;
	const gchar *user;
	const gchar *domain;
	const gchar *name;

	guint raw_len;
	guint addr_len;
	guint domain_len;
	guint user_len;
	guint flags;
};

struct rspamd_task;

/**
 * Create email address from a single rfc822 address (e.g. from mail from:)
 * @param str string to use
 * @param len length of string
 * @return
 */
struct rspamd_email_address *rspamd_email_address_from_smtp (const gchar *str, guint len);

/**
 * Parses email address from the mime header, decodes names and return the array
 * of `rspamd_email_address`. If `src` is NULL, then this function creates a new
 * array and adds a destructor to remove elements when `pool` is destroyed.
 * Otherwise, addresses are appended to `src`.
 * @param hdr
 * @param len
 * @return
 */
GPtrArray *
rspamd_email_address_from_mime (rspamd_mempool_t *pool, const gchar *hdr, guint len,
		GPtrArray *src, gint max_elements);

/**
 * Destroys list of email addresses
 * @param ptr
 */
void rspamd_email_address_list_destroy (gpointer ptr);

void rspamd_email_address_free (struct rspamd_email_address *addr);


#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBMIME_EMAIL_ADDR_H_ */
