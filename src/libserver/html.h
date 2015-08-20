/*
 * Functions for simple html parsing
 */

#ifndef RSPAMD_HTML_H
#define RSPAMD_HTML_H

#include "config.h"
#include "mem_pool.h"

/*
 * HTML content flags
 */
#define RSPAMD_HTML_FLAG_BAD_START (1 << 0)
#define RSPAMD_HTML_FLAG_BAD_ELEMENTS (1 << 1)
#define RSPAMD_HTML_FLAG_XML (1 << 2)
#define RSPAMD_HTML_FLAG_UNBALANCED (1 << 3)
#define RSPAMD_HTML_FLAG_UNKNOWN_ELEMENTS (1 << 4)
#define RSPAMD_HTML_FLAG_DUPLICATE_ELEMENTS (1 << 5)

/*
 * Image flags
 */
#define RSPAMD_HTML_FLAG_IMAGE_EMBEDDED (1 << 0)
#define RSPAMD_HTML_FLAG_IMAGE_EXTERNAL (1 << 1)

enum html_component_type {
	RSPAMD_HTML_COMPONENT_NAME = 0,
	RSPAMD_HTML_COMPONENT_HREF,
	RSPAMD_HTML_COMPONENT_COLOR,
	RSPAMD_HTML_COMPONENT_STYLE,
	RSPAMD_HTML_COMPONENT_CLASS,
	RSPAMD_HTML_COMPONENT_WIDTH,
	RSPAMD_HTML_COMPONENT_HEIGHT
};

struct html_tag_component {
	enum html_component_type type;
	const guchar *start;
	guint len;
};

struct html_image {
	guint height;
	guint width;
	guint flags;
	gchar *src;
};

struct html_block {
	gint id;
	gchar *font_color;
	gchar *background_color;
	gchar *style;
	guint font_size;
	gchar *class;
};

struct html_tag {
	gint id;
	struct html_tag_component name;
	GList *params;
	gint flags;
};

/* Forwarded declaration */
struct rspamd_task;

struct html_content {
	GNode *html_tags;
	gint flags;
	guchar *tags_seen;
	GPtrArray *images;
	GPtrArray *blocks;
};

/*
 * Decode HTML entitles in text. Text is modified in place.
 */
guint rspamd_html_decode_entitles_inplace (gchar *s, guint len);

GByteArray* rspamd_html_process_part (rspamd_mempool_t *pool,
		struct html_content *hc,
		GByteArray *in);

GByteArray* rspamd_html_process_part_full (rspamd_mempool_t *pool,
		struct html_content *hc,
		GByteArray *in, GList **exceptions, GHashTable *urls, GHashTable *emails);

/*
 * Returns true if a specified tag has been seen in a part
 */
gboolean rspamd_html_tag_seen (struct html_content *hc, const gchar *tagname);

#endif
