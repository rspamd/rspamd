#ifndef RSPAM_PERL_H
#define RSPAM_PERL_H


#include "config.h"
#include "memcached.h"


struct uri;
struct worker_task;
struct config_file;

void init_perl_filters (struct config_file *cfg);

gint perl_call_filter (const gchar *function, struct worker_task *task);
gint perl_call_chain_filter (const gchar *function, struct worker_task *task, gint *marks, guint number);

void perl_call_memcached_callback (memcached_ctx_t *ctx, memc_error_t error, void *data);

double perl_consolidation_func (struct worker_task *task, const gchar *metric_name, const gchar *function_name);

#endif
