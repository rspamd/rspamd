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

int process_message (struct worker_task *task);
int process_learn (struct controller_session *session);
GByteArray* get_next_text_part (memory_pool_t *pool, GList *parts, GList **cur);

#endif
