#include <sys/types.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>

#include "mem_pool.h"
#include "filter.h"
#include "main.h"
#include "cfg_file.h"

void
insert_result (struct worker_task *task, const char *metric_name, const char *symbol, u_char flag)
{
	struct filter_result *result;
	struct metric *metric;
	struct metric_result *metric_res;

	metric = g_hash_table_lookup (task->worker->srv->cfg->metrics, metric_name);
	if (metric == NULL) {
		return;
	}

	result = memory_pool_alloc (task->task_pool, sizeof (struct filter_result));
	result->symbol = symbol;
	result->flag = flag;
	metric_res = g_hash_table_lookup (task->results, metric_name);

	if (metric_res == NULL) {
		/* Create new metric chain */
		metric_res = memory_pool_alloc (task->task_pool, sizeof (struct metric_result));
		LIST_INIT (&metric_res->results);
		metric_res->metric = metric;
		g_hash_table_insert (task->results, (gpointer)metric_name, metric_res);
	}
	
	LIST_INSERT_HEAD (&metric_res->results, result, next);
}

int 
process_filters (struct worker_task *task)
{
	/* TODO: Implement new logic of filters chains */
}
