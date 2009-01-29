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
	struct classifier *classifier;
};

struct metric_result {
	struct metric *metric;
	double score;
	GHashTable *symbols;
};

int process_filters (struct worker_task *task);
void process_statfiles (struct worker_task *task);
void insert_result (struct worker_task *task, const char *metric_name, const char *symbol, double flag);
void make_composites (struct worker_task *task);
double factor_consolidation_func (struct worker_task *task, const char *metric_name);

#endif
