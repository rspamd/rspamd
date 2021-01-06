/*
 * Functions for simple html parsing
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

enum html_component_type {
	RSPAMD_HTML_COMPONENT_NAME = 0,
	RSPAMD_HTML_COMPONENT_HREF,
	RSPAMD_HTML_COMPONENT_COLOR,
	RSPAMD_HTML_COMPONENT_BGCOLOR,
	RSPAMD_HTML_COMPONENT_STYLE,
	RSPAMD_HTML_COMPONENT_CLASS,
	RSPAMD_HTML_COMPONENT_WIDTH,
	RSPAMD_HTML_COMPONENT_HEIGHT,
	RSPAMD_HTML_COMPONENT_SIZE,
	RSPAMD_HTML_COMPONENT_REL,
	RSPAMD_HTML_COMPONENT_ALT,
};

struct html_tag_component {
	enum html_component_type type;
	guint len;
	const guchar *start;
};


struct rspamd_image;

struct html_image {
	guint height;
	guint width;
	guint flags;
	gchar *src;
	struct rspamd_url *url;
	struct rspamd_image *embedded_image;
	struct html_tag *tag;
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
	struct html_tag *tag;
	struct html_color font_color;
	struct html_color background_color;
	struct html_tag_component style;
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

struct html_tag {
	gint id;
	gint flags;
	struct html_tag_component name;
	guint content_length;
	goffset content_offset;
	GQueue *params;
	gpointer extra; /** Additional data associated with tag (e.g. image) */
	GNode *parent;
};

/* Forwarded declaration */
struct rspamd_task;

struct html_content {
	struct rspamd_url *base_url;
	GNode *html_tags;
	gint flags;
	guint total_tags;
	struct html_color bgcolor;
	guchar *tags_seen;
	GPtrArray *images;
	GPtrArray *blocks;
	GByteArray *parsed;
};

/*
 * Decode HTML entitles in text. Text is modified in place.
 */
guint rspamd_html_decode_entitles_inplace (gchar *s, gsize len);

GByteArray *rspamd_html_process_part (rspamd_mempool_t *pool,
									  struct html_content *hc,
									  GByteArray *in);

GByteArray *rspamd_html_process_part_full (rspamd_mempool_t *pool,
										   struct html_content *hc,
										   GByteArray *in, GList **exceptions,
										   khash_t (rspamd_url_hash) *url_set,
										   GPtrArray *part_urls);

/*
 * Returns true if a specified tag has been seen in a part
 */
gboolean rspamd_html_tag_seen (struct html_content *hc, const gchar *tagname);

/**
 * Returns name for the specified tag id
 * @param id
 * @return
 */
const gchar *rspamd_html_tag_by_id (gint id);

/**
 * Returns HTML tag id by name
 * @param name
 * @return
 */
gint rspamd_html_tag_by_name (const gchar *name);

/**
 * Extract URL from HTML tag component and sets component elements if needed
 * @param pool
 * @param start
 * @param len
 * @param comp
 * @return
 */

#ifdef  __cplusplus
}
#endif

#endif
