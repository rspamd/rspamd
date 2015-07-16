/*
 * Functions for simple html parsing
 */

#ifndef RSPAMD_HTML_H
#define RSPAMD_HTML_H

#include "config.h"
#include "mem_pool.h"

#define RSPAMD_HTML_FLAG_BAD_START (1 << 0)
#define RSPAMD_HTML_FLAG_BAD_ELEMENTS (1 << 1)
#define RSPAMD_HTML_FLAG_XML (1 << 2)
#define RSPAMD_HTML_FLAG_UNBALANCED (1 << 3)
#define RSPAMD_HTML_FLAG_UNKNOWN_ELEMENTS (1 << 4)

enum html_component_type {
	RSPAMD_HTML_COMPONENT_NAME = 0,
	RSPAMD_HTML_COMPONENT_HREF,
	RSPAMD_HTML_COMPONENT_COLOR,
	RSPAMD_HTML_COMPONENT_WIDTH,
	RSPAMD_HTML_COMPONENT_HEIGHT
};

struct html_tag_component {
	enum html_component_type type;
	const guchar *start;
	guint len;
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
};

/*
 * Get tag structure by its name (binary search is used)
 */
struct html_tag * get_tag_by_name (const gchar *name);

/*
 * Decode HTML entitles in text. Text is modified in place.
 */
guint rspamd_html_decode_entitles_inplace (gchar *s, guint len);

GByteArray* rspamd_html_process_part (rspamd_mempool_t *pool,
		struct html_content *hc,
		GByteArray *in);

#endif
