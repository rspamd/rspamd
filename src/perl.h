#ifndef RSPAM_PERL_H
#define RSPAM_PERL_H


#include "config.h"
#include "memcached.h"


struct uri;
struct worker_task;
struct config_file;

void init_perl_filters (struct config_file *cfg);

int perl_call_filter (const char *function, struct worker_task *task);
int perl_call_chain_filter (const char *function, struct worker_task *task, int *marks, unsigned int number);

void perl_call_memcached_callback (memcached_ctx_t *ctx, memc_error_t error, void *data);

double perl_consolidation_func (struct worker_task *task, const char *metric_name, const char *function_name);

#endif
