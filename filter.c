#include <sys/types.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>

#include "mem_pool.h"
#include "filter.h"
#include "main.h"
#include "cfg_file.h"
#include "perl.h"

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

/*
 * Default consolidation function based on factors in config file
 */
double
factor_consolidation_func (struct worker_task *task, const char *metric_name)
{
	struct metric_result *metric_res;
	struct filter_result *result;
	double *factor;
	double res = 0.;

	metric_res = g_hash_table_lookup (task->results, metric_name);
	if (metric_res == NULL) {
		return res;
	}

	LIST_FOREACH (result, &metric_res->results, next) {
		if (result->flag) {
			factor = g_hash_table_lookup (task->worker->srv->cfg->factors, result->symbol);
			if (factor == NULL) {
				/* Default multiplier is 1 */
				res ++;
			}
			else {
				res += *factor;
			}
		}
	}

	return res;
}

/* 
 * Call perl or C module function for specified part of message 
 */
static void
call_filter_by_name (struct worker_task *task, const char *name, enum script_type sc_type, enum filter_type filt_type)
{
	struct module_ctx *c_module;

	switch (filt_type) {
		case C_FILTER:
			c_module = g_hash_table_lookup (task->worker->srv->cfg->c_modules, name);
			if (c_module) {
				switch (filt_type) {
					case SCRIPT_HEADER:
						c_module->header_filter (task);
						break;
					case SCRIPT_MIME:
						c_module->mime_filter (task);
						break;
					case SCRIPT_URL:
						c_module->url_filter (task);
						break;
					case SCRIPT_MESSAGE:
						c_module->message_filter (task);
						break;
				}
			}
			break;
		case PERL_FILTER:
			switch (filt_type) {
				case SCRIPT_HEADER:
					perl_call_header_filter (name, task);
					break;
				case SCRIPT_MIME:
					perl_call_mime_filter (name, task);
					break;
				case SCRIPT_URL:
					perl_call_url_filter (name, task);
					break;
				case SCRIPT_MESSAGE:
					perl_call_message_filter (name, task);
					break;
			}
			break;
	}
}

static void
metric_process_callback (gpointer key, gpointer value, void *data)
{
	struct worker_task *task = (struct worker_task *)data;
	struct metric_result *metric_res = (struct metric_result *)value;
	
	if (metric_res->metric->func != NULL) {
		metric_res->score = metric_res->metric->func (task, metric_res->metric->name);
	}
	else {
		metric_res->score = factor_consolidation_func (task, metric_res->metric->name);
	}
}

static int
continue_process_filters (struct worker_task *task)
{
	struct filter *cur = task->save.entry;
	
	cur = LIST_NEXT (cur, next);
	/* Note: no breaks in this case! */
	switch (task->save.type) {
		case SCRIPT_HEADER:
			while (cur) {
				call_filter_by_name (task, cur->func_name, cur->type, SCRIPT_HEADER);
				if (task->save.saved) {
					task->save.entry = cur;
					task->save.type = SCRIPT_HEADER;
					return 0;
				}
				cur = LIST_NEXT (cur, next);
			}
			/* Process mime filters */
			cur = LIST_FIRST (&task->worker->srv->cfg->mime_filters);
		case SCRIPT_MIME:
			while (cur) {
				call_filter_by_name (task, cur->func_name, cur->type, SCRIPT_MIME);
				if (task->save.saved) {
					task->save.entry = cur;
					task->save.type = SCRIPT_MIME;
					return 0;
				}
				cur = LIST_NEXT (cur, next);
			}
			/* Process url filters */
			cur = LIST_FIRST (&task->worker->srv->cfg->url_filters);
		case SCRIPT_URL:
			while (cur) {
				call_filter_by_name (task, cur->func_name, cur->type, SCRIPT_URL);
				if (task->save.saved) {
					task->save.entry = cur;
					task->save.type = SCRIPT_URL;
					return 0;
				}
				cur = LIST_NEXT (cur, next);
			}
			/* Process message filters */
			cur = LIST_FIRST (&task->worker->srv->cfg->message_filters);
		case SCRIPT_MESSAGE:
			while (cur) {
				call_filter_by_name (task, cur->func_name, cur->type, SCRIPT_MESSAGE);
				if (task->save.saved) {
					task->save.entry = cur;
					task->save.type = SCRIPT_MESSAGE;
					return 0;
				}
				cur = LIST_NEXT (cur, next);
			}
			/* All done */
			return 1;
	}
}

int 
process_filters (struct worker_task *task)
{
	struct filter *cur;

	if (task->save.saved) {
		task->save.saved = 0;
		return continue_process_filters (task);
	}

	/* Process filters in order that they are listed in config file */
	LIST_FOREACH (cur, &task->worker->srv->cfg->header_filters, next) {
		call_filter_by_name (task, cur->func_name, cur->type, SCRIPT_HEADER);
		if (task->save.saved) {
			task->save.entry = cur;
			task->save.type = SCRIPT_HEADER;
			return 0;
		}
	}

	LIST_FOREACH (cur, &task->worker->srv->cfg->mime_filters, next) {
		call_filter_by_name (task, cur->func_name, cur->type, SCRIPT_MIME);
		if (task->save.saved) {
			task->save.entry = cur;
			task->save.type = SCRIPT_MIME;
			return 0;
		}
	}

	LIST_FOREACH (cur, &task->worker->srv->cfg->url_filters, next) {
		call_filter_by_name (task, cur->func_name, cur->type, SCRIPT_URL);
		if (task->save.saved) {
			task->save.entry = cur;
			task->save.type = SCRIPT_URL;
			return 0;
		}
	}

	LIST_FOREACH (cur, &task->worker->srv->cfg->message_filters, next) {
		call_filter_by_name (task, cur->func_name, cur->type, SCRIPT_MESSAGE);
		if (task->save.saved) {
			task->save.entry = cur;
			task->save.type = SCRIPT_MESSAGE;
			return 0;
		}
	}

	/* Process all metrics */
	g_hash_table_foreach (task->results, metric_process_callback, task);
	return 1;
}
