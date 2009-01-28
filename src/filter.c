#include <sys/types.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>

#include "mem_pool.h"
#include "filter.h"
#include "main.h"
#include "message.h"
#include "cfg_file.h"
#include "perl.h"
#include "util.h"
#include "classifiers/classifiers.h"
#include "tokenizers/tokenizers.h"

void
insert_result (struct worker_task *task, const char *metric_name, const char *symbol, u_char flag)
{
	struct metric *metric;
	struct metric_result *metric_res;

	metric = g_hash_table_lookup (task->worker->srv->cfg->metrics, metric_name);
	if (metric == NULL) {
		return;
	}

	metric_res = g_hash_table_lookup (task->results, metric_name);

	if (metric_res == NULL) {
		/* Create new metric chain */
		metric_res = memory_pool_alloc (task->task_pool, sizeof (struct metric_result));
		metric_res->symbols = g_hash_table_new (g_str_hash, g_str_equal);
		memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_hash_table_destroy, metric_res->symbols);
		metric_res->metric = metric;
		g_hash_table_insert (task->results, (gpointer)metric_name, metric_res);
	}
	
	g_hash_table_insert (metric_res->symbols, (gpointer)symbol, GSIZE_TO_POINTER (flag));
}

/*
 * Default consolidation function based on factors in config file
 */
double
factor_consolidation_func (struct worker_task *task, const char *metric_name)
{
	struct metric_result *metric_res;
	double *factor;
	double res = 0.;
	GList *symbols = NULL, *cur;

	metric_res = g_hash_table_lookup (task->results, metric_name);
	if (metric_res == NULL) {
		return res;
	}
	
	symbols = g_hash_table_get_keys (metric_res->symbols);
	cur = g_list_first (symbols);
	while (cur) {
		factor = g_hash_table_lookup (task->worker->srv->cfg->factors, cur->data);
		if (factor == NULL) {
			/* Default multiplier is 1 */
			res ++;
		}
		else {
			res += *factor;
		}
		cur = g_list_next (cur);
	}

	g_list_free (symbols);

	return res;
}

/* 
 * Call perl or C module function for specified part of message 
 */
static void
call_filter_by_name (struct worker_task *task, const char *name, enum filter_type filt_type, enum script_type sc_type)
{
	struct module_ctx *c_module;
	int res = 0;
	
	switch (filt_type) {
		case C_FILTER:
			c_module = g_hash_table_lookup (task->worker->srv->cfg->c_modules, name);
			if (c_module) {
				res = 1;
				switch (sc_type) {
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
			else {
				msg_debug ("call_filter_by_name: %s is not a C module", name);
			}
			break;
		case PERL_FILTER:
			res = 1;
			switch (sc_type) {
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

	msg_debug ("call_filter_by_name: filter name: %s, result: %d", name, (int)res);
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
	msg_debug ("process_metric_callback: got result %.2f from consolidation function for metric %s", 
					metric_res->score, metric_res->metric->name);
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
			/* Process all metrics */
			g_hash_table_foreach (task->results, metric_process_callback, task);
			/* All done */
			bufferevent_enable (task->bev, EV_WRITE);
			evbuffer_drain (task->bev->output, EVBUFFER_LENGTH (task->bev->output));
			process_statfiles (task);
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

struct composites_data {
	struct worker_task *task;
	struct metric_result *metric_res;
};

static void
composites_foreach_callback (gpointer key, gpointer value, void *data)
{
	struct composites_data *cd = (struct composites_data *)data;
	struct expression *expr = (struct expression *)value;
	GQueue *stack;
	GList *symbols = NULL, *s;
	gsize cur, op1, op2;
	
	stack = g_queue_new ();

	while (expr) {
		if (expr->type == EXPR_OPERAND) {
			/* Find corresponding symbol */
			if (g_hash_table_lookup (cd->metric_res->symbols, expr->content.operand) == NULL) {
				cur = 0;
			}
			else {
				cur = 1;
				symbols = g_list_append (symbols, expr->content.operand);
			}
			g_queue_push_head (stack, GSIZE_TO_POINTER (cur));
		}
		else {
			if (g_queue_is_empty (stack)) {
				/* Queue has no operands for operation, exiting */
				g_list_free (symbols);
				g_queue_free (stack);
				return;
			}
			switch (expr->content.operation) {
				case '!':
					op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
					op1 = !op1;
					g_queue_push_head (stack, GSIZE_TO_POINTER (op1));
					break;
				case '&':
					op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
					op2 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
					g_queue_push_head (stack, GSIZE_TO_POINTER (op1 && op2));
				case '|':
					op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
					op2 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
					g_queue_push_head (stack, GSIZE_TO_POINTER (op1 || op2));
				default:
					expr = expr->next;
					continue;
			}
		}
		expr = expr->next;
	}
	if (!g_queue_is_empty (stack)) {
		op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
		if (op1) {
			/* Remove all symbols that are in composite symbol */
			s = g_list_first (symbols);
			while (s) {
				g_hash_table_remove (cd->metric_res->symbols, s->data);
				s = g_list_next (s);
			}
			/* Add new symbol */
			g_hash_table_insert (cd->metric_res->symbols, key, GSIZE_TO_POINTER (op1));
		}
	}

	g_queue_free (stack);
	g_list_free (symbols);

	return;
}

static void
composites_metric_callback (gpointer key, gpointer value, void *data) 
{
	struct worker_task *task = (struct worker_task *)data;
	struct composites_data *cd = memory_pool_alloc (task->task_pool, sizeof (struct composites_data));
	struct metric_result *metric_res = (struct metric_result *)value;

	cd->task = task;
	cd->metric_res = (struct metric_result *)metric_res;

	g_hash_table_foreach (task->cfg->composite_symbols, composites_foreach_callback, cd);
}

void 
make_composites (struct worker_task *task)
{
	g_hash_table_foreach (task->results, composites_metric_callback, task);
}

struct statfile_callback_data {
	GHashTable *metrics;
	GHashTable *tokens;
	struct worker_task *task;
};

struct statfile_result {
	double weight;
	GList *symbols;
	struct classifier *classifier;
};

static void
statfiles_callback (gpointer key, gpointer value, void *arg)
{
	struct statfile_callback_data *data= (struct statfile_callback_data *)arg;
	struct worker_task *task = data->task;
	struct statfile *st = (struct statfile *)value;
	GTree *tokens = NULL;
	char *filename;
	double weight;
	struct statfile_result *res;
	GList *cur = NULL;
	GByteArray *content;
	f_str_t c;
	
	if (g_list_length (task->rcpt) == 1) {
		filename = resolve_stat_filename (task->task_pool, st->pattern, task->from, (char *)task->rcpt->data);
	}
	else {
		/* XXX: handle multiply recipients correctly */
		filename = resolve_stat_filename (task->task_pool, st->pattern, task->from, "");
	}
	
	if (statfile_pool_open (task->worker->srv->statfile_pool, filename) == -1) {
		return;
	}
	
	if ((tokens = g_hash_table_lookup (data->tokens, st->tokenizer)) == NULL) {
		while ((content = get_next_text_part (task->task_pool, task->parts, &cur)) != NULL) {
			c.begin = content->data;
			c.len = content->len;
			/* Tree would be freed at task pool freeing */
			if (!st->tokenizer->tokenize_func (st->tokenizer, task->task_pool, &c, &tokens)) {
				msg_info ("statfiles_callback: cannot tokenize input");
				return;
			}
		}
		g_hash_table_insert (data->tokens, st->tokenizer, tokens);
	}
	
	weight = st->classifier->classify_func (task->worker->srv->statfile_pool, filename, tokens);

	msg_debug ("process_statfiles: got classify weight: %.2f", weight);
	
	if (weight > 0.000001) {

		if ((res = g_hash_table_lookup (data->metrics, st->metric)) == NULL) {
			res = memory_pool_alloc (task->task_pool, sizeof (struct statfile_result));
			res->symbols = g_list_prepend (NULL, st->alias);
			res->weight = st->classifier->add_result_func (0, weight * st->weight);
			g_hash_table_insert (data->metrics, st->metric, res);
		}
		else {
			res->symbols = g_list_prepend (NULL, st->alias);
			res->weight = st->classifier->add_result_func (res->weight, weight * st->weight);
		}
		msg_debug ("process_statfiles: result weight: %.2f", res->weight);
	}
	
}

static void
statfiles_results_callback (gpointer key, gpointer value, void *arg)
{
	struct worker_task *task = (struct worker_task *)arg;
	struct metric_result *metric_res;
	struct metric *metric;
	struct statfile_result *res = (struct statfile_result *)value;
	GList *cur_symbol;

	metric_res = g_hash_table_lookup (task->results, (char *)key);

	metric = g_hash_table_lookup (task->worker->srv->cfg->metrics, (char *)key);
	if (metric == NULL) {
		return;
	}

	if (metric_res == NULL) {
		/* Create new metric chain */
		metric_res = memory_pool_alloc (task->task_pool, sizeof (struct metric_result));
		metric_res->symbols = g_hash_table_new (g_str_hash, g_str_equal);
		memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_hash_table_destroy, metric_res->symbols);
		metric_res->metric = metric;
		metric_res->score = res->weight;
		g_hash_table_insert (task->results, metric->name, metric_res);
	}
	else {
		metric_res->score += res->weight;
	}
	msg_debug ("statfiles_results_callback: got total weight %.2f for metric %s", metric_res->score, metric->name);

	cur_symbol = g_list_first (res->symbols);
	while (cur_symbol) {	
		msg_debug ("statfiles_results_callback: insert symbol %s to metric %s", (char *)cur_symbol->data, metric->name);
		g_hash_table_insert (metric_res->symbols, (char *)cur_symbol->data, GSIZE_TO_POINTER (1));
		cur_symbol = g_list_next (cur_symbol);
	}

	g_list_free (res->symbols);

}


void
process_statfiles (struct worker_task *task)
{
	struct statfile_callback_data cd;
	
	cd.task = task;
	cd.tokens = g_hash_table_new (g_direct_hash, g_direct_equal);
	cd.metrics = g_hash_table_new (g_str_hash, g_str_equal);

	g_hash_table_foreach (task->cfg->statfiles, statfiles_callback, &cd);
	g_hash_table_foreach (cd.metrics, statfiles_results_callback, task);
	
	g_hash_table_destroy (cd.tokens);
	g_hash_table_destroy (cd.metrics);

	task->state = WRITE_REPLY;
}

static void
insert_metric_header (gpointer metric_name, gpointer metric_value, gpointer data)
{
	struct worker_task *task = (struct worker_task *)data;
	int r = 0;
	/* Try to be rfc2822 compatible and avoid long headers with folding */
	char header_name[128], outbuf[1000];
	GList *symbols = NULL, *cur;
	struct metric_result *metric_res = (struct metric_result *)metric_value;
	
	snprintf (header_name, sizeof (header_name), "X-Spam-%s", metric_res->metric->name);

	if (metric_res->score >= metric_res->metric->required_score) {
		r += snprintf (outbuf + r, sizeof (outbuf) - r, "yes; %.2f/%.2f; ", metric_res->score, metric_res->metric->required_score);
	}
	else {
		r += snprintf (outbuf + r, sizeof (outbuf) - r, "no; %.2f/%.2f; ", metric_res->score, metric_res->metric->required_score);
	}

	symbols = g_hash_table_get_keys (metric_res->symbols);
	cur = symbols;
	while (cur) {
		if (g_list_next (cur) != NULL) {
			r += snprintf (outbuf + r, sizeof (outbuf) - r, "%s,", (char *)cur->data);
		}
		else {
			r += snprintf (outbuf + r, sizeof (outbuf) - r, "%s", (char *)cur->data);
		}
		cur = g_list_next (cur);
	}
	g_list_free (symbols);
	g_mime_message_add_header (task->message, header_name, outbuf);

}

void
insert_headers (struct worker_task *task)
{
	g_hash_table_foreach (task->results, insert_metric_header, task);
}

/* 
 * vi:ts=4 
 */
