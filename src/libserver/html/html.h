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

struct html_color {
	union {
		struct {
#if !defined(BYTE_ORDER) || BYTE_ORDER == LITTLE_ENDIAN
			guint8 b;
			guint8 g;
			guint8 r;
			guint8 alpha;
#else
			guint8 alpha;
			guint8 r;
			guint8 g;
			guint8 b;
#endif
		} comp;
		guint32 val;
	} d;
	gboolean valid;
};

struct html_block {
	void *tag;
	struct html_color font_color;
	struct html_color background_color;
	rspamd_ftok_t style;
	guint font_size;
	gboolean visible;
	gchar *html_class;
};

/* Public tags flags */
/* XML tag */
#define FL_XML          (1 << 23)
/* Closing tag */
#define FL_CLOSING      (1 << 24)
/* Fully closed tag (e.g. <a attrs />) */
#define FL_CLOSED       (1 << 25)
#define FL_BROKEN       (1 << 26)
#define FL_IGNORE       (1 << 27)
#define FL_BLOCK        (1 << 28)
#define FL_HREF         (1 << 29)
#define FL_IMAGE        (1 << 30)

/* Forwarded declaration */
struct rspamd_task;
struct html_content;

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
gboolean rspamd_html_tag_seen(struct html_content *hc, const gchar *tagname);

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


#ifdef  __cplusplus
}
#endif

#endif
