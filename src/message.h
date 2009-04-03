/**
 * @file message.h
 * Message processing functions and structures
 */

#ifndef RSPAMD_MESSAGE_H
#define RSPAMD_MESSAGE_H

#include "config.h"
#include "fuzzy.h"

struct mime_part {
	GMimeContentType *type;
	GByteArray *content;
};

struct mime_text_part {
	gboolean is_html;
	GByteArray *orig;
	GByteArray *content;
	fuzzy_hash_t *fuzzy;
};

/**
 * Process message with all filters/statfiles, extract mime parts, urls and 
 * call metrics consolidation functions
 * @param task worker_task object
 * @return 0 if we have delayed filters to process and 1 if we have finished with processing
 */
int process_message (struct worker_task *task);

/*
 * Process message for learning statfile classifier. 
 * It extract text and html parts and strip tags from html parts
 * @param session session that contains message
 * @return 0 allways (may be changed in future) 
 */
int process_learn (struct controller_session *session);

/**
 * Return next text part (or html with stripped tags) for specified list
 * @param pool memory pool in which place object
 * @param parts current position in list
 * @param cur pointer to which we save current position after processing
 */
GByteArray* get_next_text_part (memory_pool_t *pool, GList *parts, GList **cur);

void message_set_header (GMimeMessage *message, const char *field, const char *value);
GList* message_get_header (memory_pool_t *pool, GMimeMessage *message, const char *field);

#endif
