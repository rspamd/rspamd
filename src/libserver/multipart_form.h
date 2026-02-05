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

#ifndef RSPAMD_MULTIPART_FORM_H
#define RSPAMD_MULTIPART_FORM_H

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rspamd_multipart_entry_c {
	const char *name;
	gsize name_len;
	const char *filename;
	gsize filename_len;
	const char *content_type;
	gsize content_type_len;
	const char *content_encoding;
	gsize content_encoding_len;
	const char *data;
	gsize data_len;
};

struct rspamd_multipart_form_c;

/**
 * Parse multipart/form-data body. Returns NULL on error.
 * The returned handle must be freed with rspamd_multipart_form_free().
 *
 * IMPORTANT: The returned form contains pointers into the original
 * data buffer (zero-copy). The caller MUST ensure 'data' remains valid
 * for the lifetime of the returned form.
 */
struct rspamd_multipart_form_c *rspamd_multipart_form_parse(
	const char *data, gsize len,
	const char *boundary, gsize boundary_len);

/**
 * Get number of parts.
 */
gsize rspamd_multipart_form_nparts(const struct rspamd_multipart_form_c *form);

/**
 * Find part by name. Returns NULL if not found.
 */
const struct rspamd_multipart_entry_c *rspamd_multipart_form_find(
	const struct rspamd_multipart_form_c *form,
	const char *name, gsize name_len);

/**
 * Free parsed form.
 */
void rspamd_multipart_form_free(struct rspamd_multipart_form_c *form);

#ifdef __cplusplus
}
#endif

#endif /* RSPAMD_MULTIPART_FORM_H */
