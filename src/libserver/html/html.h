/*-
 * Copyright 2021 Vsevolod Stakhov
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

#ifndef RSPAMD_HTML_H
#define RSPAMD_HTML_H

#include "config.h"
#include "libutil/mem_pool.h"
#include "libserver/url.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * HTML content flags
 */
#define RSPAMD_HTML_FLAG_BAD_START (1 << 0)
#define RSPAMD_HTML_FLAG_BAD_ELEMENTS (1 << 1)
#define RSPAMD_HTML_FLAG_XML (1 << 2)
#define RSPAMD_HTML_FLAG_UNBALANCED (1 << 3)
#define RSPAMD_HTML_FLAG_UNKNOWN_ELEMENTS (1 << 4)
#define RSPAMD_HTML_FLAG_DUPLICATE_ELEMENTS (1 << 5)
#define RSPAMD_HTML_FLAG_TOO_MANY_TAGS (1 << 6)
#define RSPAMD_HTML_FLAG_HAS_DATA_URLS (1 << 7)
#define RSPAMD_HTML_FLAG_HAS_ZEROS (1 << 8)

/*
 * Image flags
 */
#define RSPAMD_HTML_FLAG_IMAGE_EMBEDDED (1 << 0)
#define RSPAMD_HTML_FLAG_IMAGE_EXTERNAL (1 << 1)
#define RSPAMD_HTML_FLAG_IMAGE_DATA (1 << 2)


struct rspamd_image;

struct html_image {
	guint height;
	guint width;
	guint flags;
	gchar *src;
	struct rspamd_url *url;
	struct rspamd_image *embedded_image;
	void *tag;
};


/* Forwarded declaration */
struct rspamd_task;

/*
 * Decode HTML entitles in text. Text is modified in place.
 */
guint rspamd_html_decode_entitles_inplace(gchar *s, gsize len);

void* rspamd_html_process_part(rspamd_mempool_t *pool,
							   GByteArray *in);

void *rspamd_html_process_part_full(rspamd_mempool_t *pool,
									GByteArray *in, GList **exceptions,
									khash_t (rspamd_url_hash) *url_set,
									GPtrArray *part_urls,
									bool allow_css);

/*
 * Returns true if a specified tag has been seen in a part
 */
gboolean rspamd_html_tag_seen(void *ptr, const gchar *tagname);

/**
 * Returns name for the specified tag id
 * @param id
 * @return
 */
const gchar *rspamd_html_tag_by_id(gint id);

/**
 * Returns HTML tag id by name
 * @param name
 * @return
 */
gint rspamd_html_tag_by_name(const gchar *name);

/**
 * Gets a name for a tag
 * @param tag
 * @param len
 * @return
 */
const gchar *rspamd_html_tag_name(void *tag, gsize *len);

/**
 * Find HTML image by content id
 * @param html_content
 * @param cid
 * @param cid_len
 * @return
 */
struct html_image* rspamd_html_find_embedded_image(void *html_content,
		const char *cid, gsize cid_len);

/**
 * Stores parsed content in ftok_t structure
 * @param html_content
 * @param dest
 * @return
 */
bool rspamd_html_get_parsed_content(void *html_content, rspamd_ftok_t *dest);

/**
 * Returns number of tags in the html content
 * @param html_content
 * @return
 */
gsize rspamd_html_get_tags_count(void *html_content);


#ifdef  __cplusplus
}
#endif

#endif
