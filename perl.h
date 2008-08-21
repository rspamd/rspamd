#ifndef RSPAM_PERL_H
#define RSPAM_PERL_H

#include <sys/types.h>
#include <glib.h>
#include "memcached.h"

struct uri;
struct worker_task;

int perl_call_header_filter (const char *function, struct worker_task *task);
int perl_call_mime_filter (const char *function, struct worker_task *task);
int perl_call_message_filter (const char *function, struct worker_task *task);
int perl_call_url_filter (const char *function, struct worker_task *task);
int perl_call_chain_filter (const char *function, struct worker_task *task, int *marks, unsigned int number);

void perl_call_memcached_callback (memcached_ctx_t *ctx, memc_error_t error, void *data);

#endif
