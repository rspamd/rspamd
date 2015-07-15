/*
 * Functions for simple html parsing
 */

#ifndef RSPAMD_HTML_H
#define RSPAMD_HTML_H

#include "config.h"
#include "mem_pool.h"

struct html_tag {
	gint id;
	const gchar *name;
	gint flags;
};

struct html_node {
	struct html_tag *tag;
	gint flags;
};

/* Forwarded declaration */
struct rspamd_task;

/*
 * Add a single node to the tags tree
 */
gboolean add_html_node (struct rspamd_task *task,
	rspamd_mempool_t *pool,
	struct mime_text_part *part,
	gchar *tag_text,
	gsize tag_len,
	gsize remain,
	GNode **cur_level);

/*
 * Get tag structure by its name (binary search is used)
 */
struct html_tag * get_tag_by_name (const gchar *name);

/*
 * Decode HTML entitles in text. Text is modified in place.
 */
void rspamd_html_decode_entitles_inplace (gchar *s, guint *len);

#endif
