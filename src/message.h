/**
 * @file message.h
 * Message processing functions and structures
 */

#ifndef RSPAMD_MESSAGE_H
#define RSPAMD_MESSAGE_H

#include "config.h"
#include "fuzzy.h"

struct worker_task;
struct controller_session;

struct mime_part {
	GMimeContentType *type;
	GByteArray *content;
	GMimeObject *parent;
	gchar *checksum;
	const gchar *filename;
};

struct mime_text_part {
	gboolean is_html;
	gboolean is_raw;
	gboolean is_balanced;
	gboolean is_empty;
	gboolean is_utf;
	const gchar *real_charset;
	GByteArray *orig;
	GByteArray *content;
	GNode *html_nodes;
	GTree *urls;
	GTree *html_urls;
	fuzzy_hash_t *fuzzy;
	GMimeObject *parent;
};

struct received_header {
	gchar *from_hostname;
	gchar *from_ip;
	gchar *real_hostname;
	gchar *real_ip;
	gchar *by_hostname;
	gint is_error;
};

/**
 * Process message with all filters/statfiles, extract mime parts, urls and 
 * call metrics consolidation functions
 * @param task worker_task object
 * @return 0 if we have delayed filters to process and 1 if we have finished with processing
 */
gint process_message (struct worker_task *task);

void message_set_header (GMimeMessage *message, const gchar *field, const gchar *value);
GList* message_get_header (memory_pool_t *pool, GMimeMessage *message, const gchar *field);

#endif
