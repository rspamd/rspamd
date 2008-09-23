#ifndef RSPAMD_FILTER_H
#define RSPAMD_FILTER_H

#include <sys/types.h>
#ifndef HAVE_OWN_QUEUE_H
#include <sys/queue.h>
#else
#include "queue.h"
#endif
#include <glib.h>

struct worker_task;

typedef double (*metric_cons_func)(struct worker_task *task, const char *metric_name);
typedef void (*filter_func)(struct worker_task *task);

enum filter_type { C_FILTER, PERL_FILTER };

struct filter {
	char *func_name;
	enum filter_type type;
	LIST_ENTRY (filter) next;
};

struct metric {
	char *name;
	char *func_name;
	metric_cons_func func;
	double required_score;
};

struct filter_result {
	const char *symbol;
	u_char flag;
	LIST_ENTRY (filter_result) next;
};

struct metric_result {
	struct metric *metric;
	double score;
	LIST_HEAD (resultq, filter_result) results;
};

int process_filters (struct worker_task *task);
void insert_result (struct worker_task *task, const char *metric_name, const char *symbol, u_char flag);
double factor_consolidation_func (struct worker_task *task, const char *metric_name);

#endif
