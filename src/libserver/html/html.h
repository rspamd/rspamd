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
#include "libserver/html/html_features.h"

#ifdef __cplusplus
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
#define RSPAMD_HTML_FLAG_TOO_MANY_ATTRS (1 << 9)
/* `<![CDATA[` outside of SVG/MathML, where browsers take it as a bogus comment */
#define RSPAMD_HTML_FLAG_CDATA_IN_HTML (1 << 10)

/*
 * Image flags
 */
#define RSPAMD_HTML_FLAG_IMAGE_EMBEDDED (1 << 0)
#define RSPAMD_HTML_FLAG_IMAGE_EXTERNAL (1 << 1)
#define RSPAMD_HTML_FLAG_IMAGE_DATA (1 << 2)


struct rspamd_image;

struct html_image {
	unsigned int height;
	unsigned int width;
	unsigned int flags;
	char *src;
	struct rspamd_url *url;
	struct rspamd_image *embedded_image;
	void *tag;
	/* The same dimensions in double precision, for the tiny area
	 * check: rounding each side to an integer would distort the
	 * area of fractional dimensions in both directions */
	double width_exact;
	double height_exact;
	/* Dimension provenance for the tiny external pixel classification:
	 * 0 = not specified, 1 = attribute, 2 = stylesheet, 3 = inline style,
	 * 4 = specified but unresolvable (percent or non-numeric CSS value) */
	unsigned char width_source;
	unsigned char height_source;
	/* Absolute min-width/min-height from the inline style (in pixels),
	 * used to re-clamp the size after stylesheet reconciliation */
	double min_width;
	double min_height;
	/* Bits of inline-specified minimums (0x1 height, 0x2 width; the
	 * higher bits 0x4/0x8 mark the percent ones, which cannot be
	 * resolved but may raise the size, and 0x10/0x20 the !important
	 * ones): an inline minimum overrides a stylesheet one entirely,
	 * unless the latter is !important while the former is not */
	unsigned char min_source;
	/* Inline max-width/max-height bounds (in pixels); a negative value
	 * means no bound (none or a non-absolute value) */
	double max_width;
	double max_height;
	/* Bits of inline-specified maximums (0x1 height, 0x2 width; the
	 * higher bits 0x4/0x8 mark the !important ones): an inline
	 * maximum overrides a stylesheet one entirely, unless the latter
	 * is !important while the former is not */
	unsigned char max_source;
	/* Bits of !important inline width/height declarations (0x1 height,
	 * 0x2 width): an inline !important beats a stylesheet !important */
	unsigned char inline_important;
};


/* Forwarded declaration */
struct rspamd_task;

/*
 * Decode HTML entitles in text. Text is modified in place.
 */
unsigned int rspamd_html_decode_entitles_inplace(char *s, gsize len);

void *rspamd_html_process_part(rspamd_mempool_t *pool,
							   GByteArray *in);

void *rspamd_html_process_part_full(struct rspamd_task *task,
									GByteArray *in, GList **exceptions,
									khash_t(rspamd_url_hash) * url_set,
									GPtrArray *part_urls,
									bool allow_css,
									uint16_t *cur_url_order);

/*
 * Returns true if a specified tag has been seen in a part
 */
gboolean rspamd_html_tag_seen(void *ptr, const char *tagname);

/**
 * Returns name for the specified tag id
 * @param id
 * @return
 */
const char *rspamd_html_tag_by_id(int id);

/**
 * Returns HTML tag id by name
 * @param name
 * @return
 */
int rspamd_html_tag_by_name(const char *name);

/**
 * Gets a name for a tag
 * @param tag
 * @param len
 * @return
 */
const char *rspamd_html_tag_name(void *tag, gsize *len);

/**
 * Find HTML image by content id
 * @param html_content
 * @param cid
 * @param cid_len
 * @return
 */
struct html_image *rspamd_html_find_embedded_image(void *html_content,
												   const char *cid, gsize cid_len);

/**
 * Link all embedded HTML images using a Content-ID to rspamd_image hash table
 * @param html_content
 * @param cid_images
 */
void rspamd_html_link_embedded_images(void *html_content,
									  GHashTable *cid_images);

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

/**
 * Returns heuristic button weight for a given URL within this HTML content
 */
float rspamd_html_url_button_weight(void *html_content, struct rspamd_url *u);

/**
 * Returns an immutable pointer to aggregated html features
 */
const struct rspamd_html_features *rspamd_html_get_features(void *html_content);

/**
 * Creates CTA (call-to-action) URLs heap for a text part
 * Collects top-K URLs by button weight using min-heap (O(n log k))
 * @param text_part text part to fill cta_urls for
 * @param task task for mempool allocation
 * @param max_cta maximum number of CTA URLs to collect
 */
void rspamd_html_process_cta_urls(struct rspamd_mime_text_part *text_part,
								  struct rspamd_task *task,
								  unsigned int max_cta);


#ifdef __cplusplus
}
#endif

#endif
