/**
 * @file message.h
 * Message processing functions and structures
 */

#ifndef RSPAMD_MESSAGE_H
#define RSPAMD_MESSAGE_H

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#ifndef HAVE_OWN_QUEUE_H
#include <sys/queue.h>
#else
#include "queue.h"
#endif
#include <sys/time.h>

#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <signal.h>
#include <event.h>

#include "main.h"

#include <glib.h>
#include <gmime/gmime.h>

struct mime_part {
	GMimeContentType *type;
	GByteArray *content;
	TAILQ_ENTRY (mime_part) next;
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

#endif
