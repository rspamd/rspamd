/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "mem_pool.h"
#include "filter.h"
#include "main.h"
#include "message.h"
#include "cfg_file.h"
#include "util.h"
#include "expressions.h"
#include "diff.h"

#ifdef WITH_LUA
#   include "lua/lua_common.h"
#endif

#define COMMON_PART_FACTOR 95

#ifndef PARAM_H_HAS_BITSET
/* Bit map related macros. */
#define NBBY    8               /* number of bits in a byte */
#define setbit(a, \
		i)     (((unsigned char *)(a))[(i) / NBBY] |= 1 << ((i) % NBBY))
#define clrbit(a, \
		i)     (((unsigned char *)(a))[(i) / NBBY] &= ~(1 << ((i) % NBBY)))
#define isset(a,i)                                                      \
	(((const unsigned char *)(a))[(i) / NBBY] & (1 << ((i) % NBBY)))
#define isclr(a,i)                                                      \
	((((const unsigned char *)(a))[(i) / NBBY] & (1 << ((i) % NBBY))) == 0)
#endif
#define BITSPERBYTE (8 * sizeof (gchar))
#define NBYTES(nbits)   (((nbits) + BITSPERBYTE - 1) / BITSPERBYTE)

static inline GQuark
filter_error_quark (void)
{
	return g_quark_from_static_string ("g-filter-error-quark");
}

struct metric_result *
rspamd_create_metric_result (struct rspamd_task *task, const gchar *name)
{
	struct metric_result *metric_res;
	struct metric *metric;

	metric_res = g_hash_table_lookup (task->results, name);

	if (metric_res != NULL) {
		return metric_res;
	}

	metric = g_hash_table_lookup (task->cfg->metrics, name);
	if (metric == NULL) {
		return NULL;
	}

	metric_res =
			rspamd_mempool_alloc (task->task_pool,
					sizeof (struct metric_result));
	metric_res->symbols = g_hash_table_new (rspamd_str_hash,
			rspamd_str_equal);
	metric_res->checked = FALSE;
	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) g_hash_table_unref,
			metric_res->symbols);
	metric_res->metric = metric;
	metric_res->grow_factor = 0;
	metric_res->score = 0;
	g_hash_table_insert (task->results, (gpointer) metric->name,
			metric_res);
	metric_res->action = METRIC_ACTION_MAX;

	return metric_res;
}

static void
insert_metric_result (struct rspamd_task *task,
	struct metric *metric,
	const gchar *symbol,
	double flag,
	GList * opts,
	gboolean single)
{
	struct metric_result *metric_res;
	struct symbol *s;
	gdouble w;
	struct rspamd_symbol_def *sdef;
	const ucl_object_t *mobj, *sobj;

	metric_res = rspamd_create_metric_result (task, metric->name);

	sdef = g_hash_table_lookup (metric->symbols, symbol);
	if (sdef == NULL) {
		w = 0.0;
	}
	else {
		w = (*sdef->weight_ptr) * flag;
	}

	if (task->settings) {
		mobj = ucl_object_find_key (task->settings, metric->name);
		if (mobj) {
			gdouble corr;

			sobj = ucl_object_find_key (mobj, symbol);
			if (sobj != NULL && ucl_object_todouble_safe (sobj, &corr)) {
				msg_debug ("settings: changed weight of symbol %s from %.2f to %.2f",
						symbol, w, corr);
				w = corr * flag;
			}
		}
	}

	/* Add metric score */
	if ((s = g_hash_table_lookup (metric_res->symbols, symbol)) != NULL) {
		if (sdef && sdef->one_shot) {
			/*
			 * For one shot symbols we do not need to add them again, so
			 * we just force single behaviour here
			 */
			single = TRUE;
		}
		if (s->options && opts && opts != s->options) {
			/* Append new options */
			s->options = g_list_concat (s->options, g_list_copy (opts));
			/*
			 * Note that there is no need to add new destructor of GList as elements of appended
			 * GList are used directly, so just free initial GList
			 */
		}
		else if (opts) {
			s->options = g_list_copy (opts);
			rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t) g_list_free, s->options);
		}
		if (!single) {
			/* Handle grow factor */
			if (metric_res->grow_factor && w > 0) {
				w *= metric_res->grow_factor;
				metric_res->grow_factor *= metric->grow_factor;
			}
			s->score += w;
			metric_res->score += w;
		}
		else {
			if (fabs (s->score) < fabs (w)) {
				/* Replace less weight with a bigger one */
				metric_res->score = metric_res->score - s->score + w;
				s->score = w;
			}
		}
	}
	else {
		s = rspamd_mempool_alloc (task->task_pool, sizeof (struct symbol));

		/* Handle grow factor */
		if (metric_res->grow_factor && w > 0) {
			w *= metric_res->grow_factor;
			metric_res->grow_factor *= metric->grow_factor;
		}
		else if (w > 0) {
			metric_res->grow_factor = metric->grow_factor;
		}

		s->score = w;
		s->name = symbol;
		metric_res->score += w;

		if (opts) {
			s->options = g_list_copy (opts);
			rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t) g_list_free, s->options);
		}
		else {
			s->options = NULL;
		}

		g_hash_table_insert (metric_res->symbols, (gpointer) symbol, s);
	}
	debug_task ("symbol %s, score %.2f, metric %s, factor: %f",
		symbol,
		s->score,
		metric->name,
		w);

}

#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
static GStaticMutex result_mtx = G_STATIC_MUTEX_INIT;
#else
G_LOCK_DEFINE (result_mtx);
#endif

static void
insert_result_common (struct rspamd_task *task,
	const gchar *symbol,
	double flag,
	GList * opts,
	gboolean single)
{
	struct metric *metric;
	struct cache_item *item;
	GList *cur, *metric_list;

	/* Avoid concurrenting inserting of results */
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
	g_static_mutex_lock (&result_mtx);
#else
	G_LOCK (result_mtx);
#endif
	metric_list = g_hash_table_lookup (task->cfg->metrics_symbols, symbol);
	if (metric_list) {
		cur = metric_list;

		while (cur) {
			metric = cur->data;
			insert_metric_result (task, metric, symbol, flag, opts, single);
			cur = g_list_next (cur);
		}
	}
	else {
		/* Insert symbol to default metric */
		insert_metric_result (task,
			task->cfg->default_metric,
			symbol,
			flag,
			opts,
			single);
	}

	/* Process cache item */
	if (task->cfg->cache) {
		item = g_hash_table_lookup (task->cfg->cache->items_by_symbol, symbol);
		if (item != NULL) {
			item->s->frequency++;
		}
	}

	if (opts != NULL) {
		/* XXX: it is not wise to destroy them here */
		g_list_free (opts);
	}
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
	g_static_mutex_unlock (&result_mtx);
#else
	G_UNLOCK (result_mtx);
#endif
}

/* Insert result that may be increased on next insertions */
void
rspamd_task_insert_result (struct rspamd_task *task,
	const gchar *symbol,
	double flag,
	GList * opts)
{
	insert_result_common (task, symbol, flag, opts, task->cfg->one_shot_mode);
}

/* Insert result as a single option */
void
rspamd_task_insert_result_single (struct rspamd_task *task,
	const gchar *symbol,
	double flag,
	GList * opts)
{
	insert_result_common (task, symbol, flag, opts, TRUE);
}

static gboolean
check_metric_settings (struct rspamd_task *task, struct metric *metric,
	double *score)
{
	const ucl_object_t *mobj, *reject, *act;
	double val;

	if (task->settings == NULL) {
		return FALSE;
	}

	mobj = ucl_object_find_key (task->settings, metric->name);
	if (mobj != NULL) {
		act = ucl_object_find_key (mobj, "actions");
		if (act != NULL) {
			reject = ucl_object_find_key (act,
					rspamd_action_to_str (METRIC_ACTION_REJECT));
			if (reject != NULL && ucl_object_todouble_safe (reject, &val)) {
				*score = val;
				return TRUE;
			}
		}
	}

	return FALSE;
}

/* Return true if metric has score that is more than spam score for it */
static gboolean
check_metric_is_spam (struct rspamd_task *task, struct metric *metric)
{
	struct metric_result *res;
	double ms;

	/* Avoid concurrency while checking results */
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
	g_static_mutex_lock (&result_mtx);
#else
	G_LOCK (result_mtx);
#endif
	res = g_hash_table_lookup (task->results, metric->name);
	if (res) {
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
		g_static_mutex_unlock (&result_mtx);
#else
		G_UNLOCK (result_mtx);
#endif
		if (!check_metric_settings (task, metric, &ms)) {
			ms = metric->actions[METRIC_ACTION_REJECT].score;
		}
		return (ms > 0 && res->score >= ms);
	}

#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
	g_static_mutex_unlock (&result_mtx);
#else
	G_UNLOCK (result_mtx);
#endif

	return FALSE;
}

gint
rspamd_process_filters (struct rspamd_task *task)
{
	GList *cur;
	struct metric *metric;
	gpointer item = NULL;

	/* Insert default metric to be sure that it exists all the time */
	rspamd_create_metric_result (task, DEFAULT_METRIC);
	if (task->settings) {
		const ucl_object_t *wl;

		wl = ucl_object_find_key (task->settings, "whitelist");
		if (wl != NULL) {
			msg_info ("<%s> is whitelisted", task->message_id);
			task->is_skipped = TRUE;
			return 0;
		}
	}

	/* Process metrics symbols */
	while (call_symbol_callback (task, task->cfg->cache, &item)) {
		/* Check reject actions */
		cur = task->cfg->metrics_list;
		while (cur) {
			metric = cur->data;
			if (!task->pass_all_filters &&
				metric->actions[METRIC_ACTION_REJECT].score > 0 &&
				check_metric_is_spam (task, metric)) {
				task->state = WRITE_REPLY;
				return 1;
			}
			cur = g_list_next (cur);
		}
	}

	task->state = WAIT_FILTER;

	return 1;
}


struct composites_data {
	struct rspamd_task *task;
	struct metric_result *metric_res;
	GTree *symbols_to_remove;
	guint8 *checked;
};

struct symbol_remove_data {
	struct symbol *ms;
	gboolean remove_weight;
	gboolean remove_symbol;
};

static gint
remove_compare_data (gconstpointer a, gconstpointer b)
{
	const gchar *ca = a, *cb = b;

	return strcmp (ca, cb);
}

static void
composites_foreach_callback (gpointer key, gpointer value, void *data)
{
	struct composites_data *cd = (struct composites_data *)data;
	struct rspamd_composite *composite = value, *ncomp;
	struct expression *expr;
	GQueue *stack;
	GList *symbols = NULL, *s;
	gsize cur, op1, op2;
	gchar logbuf[256], *sym, *check_sym;
	gint r;
	struct symbol *ms;
	struct symbol_remove_data *rd;


	expr = composite->expr;
	if (isset (cd->checked, composite->id)) {
		/* Symbol was already checked */
		return;
	}

	stack = g_queue_new ();

	while (expr) {
		if (expr->type == EXPR_STR) {
			/* Find corresponding symbol */
			sym = expr->content.operand;
			if (*sym == '~' || *sym == '-') {
				sym++;
			}
			if (g_hash_table_lookup (cd->metric_res->symbols, sym) == NULL) {
				cur = 0;
				if ((ncomp =
					g_hash_table_lookup (cd->task->cfg->composite_symbols,
					sym)) != NULL) {
					/* Set checked for this symbol to avoid cyclic references */
					if (isclr (cd->checked, ncomp->id)) {
						setbit (cd->checked, composite->id);
						composites_foreach_callback (sym, ncomp, cd);
						if (g_hash_table_lookup (cd->metric_res->symbols,
							sym) != NULL) {
							cur = 1;
						}
					}
				}
			}
			else {
				cur = 1;
				symbols = g_list_prepend (symbols, expr->content.operand);
			}
			g_queue_push_head (stack, GSIZE_TO_POINTER (cur));
		}
		else {
			if (g_queue_is_empty (stack)) {
				/* Queue has no operands for operation, exiting */
				g_list_free (symbols);
				g_queue_free (stack);
				setbit (cd->checked, composite->id);
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
				break;
			case '|':
				op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
				op2 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
				g_queue_push_head (stack, GSIZE_TO_POINTER (op1 || op2));
				break;
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
			r = rspamd_snprintf (logbuf,
					sizeof (logbuf),
					"<%s>, insert symbol %s instead of symbols: ",
					cd->task->message_id,
					key);
			while (s) {
				sym = s->data;
				if (*sym == '~' || *sym == '-') {
					check_sym = sym + 1;
				}
				else {
					check_sym = sym;
				}
				ms = g_hash_table_lookup (cd->metric_res->symbols, check_sym);

				if (ms == NULL) {
					/* Try to process other composites */
					if ((ncomp =
						g_hash_table_lookup (cd->task->cfg->composite_symbols,
						check_sym)) != NULL) {
						/* Set checked for this symbol to avoid cyclic references */
						if (isclr (cd->checked, ncomp->id)) {
							setbit (cd->checked, composite->id);
							composites_foreach_callback (check_sym, ncomp, cd);
							ms = g_hash_table_lookup (cd->metric_res->symbols,
									check_sym);
						}
					}
				}

				if (ms != NULL) {
					rd =
						rspamd_mempool_alloc (cd->task->task_pool,
							sizeof (struct symbol_remove_data));
					rd->ms = ms;
					if (G_UNLIKELY (*sym == '~')) {
						rd->remove_weight = FALSE;
						rd->remove_symbol = TRUE;
					}
					else if (G_UNLIKELY (*sym == '-')) {
						rd->remove_symbol = FALSE;
						rd->remove_weight = FALSE;
					}
					else {
						rd->remove_symbol = TRUE;
						rd->remove_weight = TRUE;
					}
					if (!g_tree_lookup (cd->symbols_to_remove, ms->name)) {
						g_tree_insert (cd->symbols_to_remove,
							(gpointer)ms->name,
							rd);
					}
				}
				else {

				}

				if (s->next) {
					r += rspamd_snprintf (logbuf + r,
							sizeof (logbuf) - r,
							"%s, ",
							s->data);
				}
				else {
					r += rspamd_snprintf (logbuf + r,
							sizeof (logbuf) - r,
							"%s",
							s->data);
				}
				s = g_list_next (s);
			}
			/* Add new symbol */
			rspamd_task_insert_result_single (cd->task, key, 1.0, NULL);
			msg_info ("%s", logbuf);
		}
	}

	setbit (cd->checked, composite->id);
	g_queue_free (stack);
	g_list_free (symbols);

	return;
}



static gboolean
composites_remove_symbols (gpointer key, gpointer value, gpointer data)
{
	struct composites_data *cd = data;
	struct symbol_remove_data *rd = value;

	if (rd->remove_symbol) {
		g_hash_table_remove (cd->metric_res->symbols, key);
	}
	if (rd->remove_weight) {
		cd->metric_res->score -= rd->ms->score;
	}

	return FALSE;
}

static void
composites_metric_callback (gpointer key, gpointer value, gpointer data)
{
	struct rspamd_task *task = (struct rspamd_task *)data;
	struct composites_data *cd =
		rspamd_mempool_alloc (task->task_pool, sizeof (struct composites_data));
	struct metric_result *metric_res = (struct metric_result *)value;

	cd->task = task;
	cd->metric_res = (struct metric_result *)metric_res;
	cd->symbols_to_remove = g_tree_new (remove_compare_data);
	cd->checked =
		rspamd_mempool_alloc0 (task->task_pool,
			NBYTES (g_hash_table_size (task->cfg->composite_symbols)));

	/* Process hash table */
	g_hash_table_foreach (task->cfg->composite_symbols,
		composites_foreach_callback,
		cd);

	/* Remove symbols that are in composites */
	g_tree_foreach (cd->symbols_to_remove, composites_remove_symbols, cd);
	/* Free list */
	g_tree_destroy (cd->symbols_to_remove);
}

void
rspamd_make_composites (struct rspamd_task *task)
{
	g_hash_table_foreach (task->results, composites_metric_callback, task);
}

struct classifiers_cbdata {
	struct rspamd_task *task;
	struct lua_locked_state *nL;
};

static void
classifiers_callback (gpointer value, void *arg)
{
	/* XXX: totally broken now */
#if 0
	struct classifiers_cbdata *cbdata = arg;
	struct rspamd_task *task;
	struct rspamd_classifier_config *cl = value;
	struct classifier_ctx *ctx;
	struct mime_text_part *text_part, *p1, *p2;
	struct rspamd_statfile_config *st;
	GTree *tokens = NULL;
	GList *cur;
	gint *dist = NULL, diff;
	gboolean is_twopart = FALSE;

	task = cbdata->task;

	cur = g_list_first (task->text_parts);
	dist = rspamd_mempool_get_variable (task->task_pool, "parts_distance");
	if (cur != NULL && cur->next != NULL && cur->next->next == NULL) {
		is_twopart = TRUE;
	}
	ctx = cl->classifier->init_func (task->task_pool, cl);

	if ((tokens = g_hash_table_lookup (task->tokens, cl->tokenizer)) == NULL) {
		while (cur != NULL) {
			text_part = (struct mime_text_part *)cur->data;
			if (text_part->is_empty) {
				cur = g_list_next (cur);
				continue;
			}
			if (dist != NULL && cur->next == NULL) {
				/* Compare part's content */

				if (*dist >= COMMON_PART_FACTOR) {
					msg_info (
							"message <%s> has two common text parts, ignore the last one",
							task->message_id);
					break;
				}
			}
			else if (cur->next == NULL && is_twopart) {
				p1 = cur->prev->data;
				p2 = text_part;
				if (p1->diff_str != NULL && p2->diff_str != NULL) {
					diff =
							rspamd_diff_distance (p1->diff_str, p2->diff_str);
				}
				else {
					diff = rspamd_fuzzy_compare_parts (p1, p2);
				}
				if (diff >= COMMON_PART_FACTOR) {
					msg_info (
							"message <%s> has two common text parts, ignore the last one",
							task->message_id);
					break;
				}
			}
			/* Tree would be freed at task pool freeing */
			if (!cl->tokenizer->tokenize_func (cl->tokenizer,
					task->task_pool, text_part->words, &tokens,
					FALSE, text_part->is_utf, text_part->urls_offset)) {
				msg_info ("cannot tokenize input");
				return;
			}
			cur = g_list_next (cur);
		}

		if (tokens != NULL) {
			g_hash_table_insert (task->tokens, cl->tokenizer, tokens);
		}
	}

	/* Take care of subject */
	tokenize_subject (task, &tokens);

	if (tokens == NULL) {
		return;
	}

	if (cbdata->nL != NULL) {
		rspamd_mutex_lock (cbdata->nL->m);
		cl->classifier->classify_func (ctx,
			tokens,
			task,
			cbdata->nL->L);
		rspamd_mutex_unlock (cbdata->nL->m);
	}
	else {
		/* Non-threaded case */
		cl->classifier->classify_func (ctx,
			tokens,
			task,
			task->cfg->lua_state);
	}
#endif
}


void
rspamd_process_statistics (struct rspamd_task *task)
{
	struct classifiers_cbdata cbdata;

	if (task->is_skipped) {
		return;
	}

	if (task->tokens == NULL) {
		task->tokens = g_hash_table_new (g_direct_hash, g_direct_equal);
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t)g_hash_table_unref, task->tokens);
	}
	cbdata.task = task;
	cbdata.nL = NULL;
	g_list_foreach (task->cfg->classifiers, classifiers_callback, &cbdata);

	/* Process results */
	rspamd_make_composites (task);
}

void
rspamd_process_statistic_threaded (gpointer data, gpointer user_data)
{
	struct rspamd_task *task = (struct rspamd_task *)data;
	struct lua_locked_state *nL = user_data;
	struct classifiers_cbdata cbdata;

	if (task->is_skipped) {
		remove_async_thread (task->s);
		return;
	}

	if (task->tokens == NULL) {
		task->tokens = g_hash_table_new (g_direct_hash, g_direct_equal);
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t)g_hash_table_unref, task->tokens);
	}

	cbdata.task = task;
	cbdata.nL = nL;
	g_list_foreach (task->cfg->classifiers, classifiers_callback, &cbdata);
	remove_async_thread (task->s);
}

static void
insert_metric_header (gpointer metric_name, gpointer metric_value,
	gpointer data)
{
#ifndef GLIB_HASH_COMPAT
	struct rspamd_task *task = (struct rspamd_task *)data;
	gint r = 0;
	/* Try to be rfc2822 compatible and avoid long headers with folding */
	gchar header_name[128], outbuf[1000];
	GList *symbols = NULL, *cur;
	struct metric_result *metric_res = (struct metric_result *)metric_value;
	double ms;

	rspamd_snprintf (header_name,
		sizeof (header_name),
		"X-Spam-%s",
		metric_res->metric->name);

	if (!check_metric_settings (task, metric_res->metric, &ms)) {
		ms = metric_res->metric->actions[METRIC_ACTION_REJECT].score;
	}
	if (ms > 0 && metric_res->score >= ms) {
		r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r,
				"yes; %.2f/%.2f/%.2f; ", metric_res->score, ms, ms);
	}
	else {
		r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r,
				"no; %.2f/%.2f/%.2f; ", metric_res->score, ms, ms);
	}

	symbols = g_hash_table_get_keys (metric_res->symbols);
	cur = symbols;
	while (cur) {
		if (g_list_next (cur) != NULL) {
			r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r,
					"%s,", (gchar *)cur->data);
		}
		else {
			r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r,
					"%s", (gchar *)cur->data);
		}
		cur = g_list_next (cur);
	}
	g_list_free (symbols);
#ifdef GMIME24
	g_mime_object_append_header (GMIME_OBJECT (
			task->message), header_name, outbuf);
#else
	g_mime_message_add_header (task->message, header_name, outbuf);
#endif

#endif /* GLIB_COMPAT */
}

void
insert_headers (struct rspamd_task *task)
{
	g_hash_table_foreach (task->results, insert_metric_header, task);
}

gboolean
rspamd_action_from_str (const gchar *data, gint *result)
{
	if (g_ascii_strncasecmp (data, "reject", sizeof ("reject") - 1) == 0) {
		*result = METRIC_ACTION_REJECT;
	}
	else if (g_ascii_strncasecmp (data, "greylist",
		sizeof ("greylist") - 1) == 0) {
		*result = METRIC_ACTION_GREYLIST;
	}
	else if (g_ascii_strncasecmp (data, "add_header", sizeof ("add_header") -
		1) == 0) {
		*result = METRIC_ACTION_ADD_HEADER;
	}
	else if (g_ascii_strncasecmp (data, "rewrite_subject",
		sizeof ("rewrite_subject") - 1) == 0) {
		*result = METRIC_ACTION_REWRITE_SUBJECT;
	}
	else if (g_ascii_strncasecmp (data, "add header", sizeof ("add header") -
			1) == 0) {
		*result = METRIC_ACTION_ADD_HEADER;
	}
	else if (g_ascii_strncasecmp (data, "rewrite subject",
			sizeof ("rewrite subject") - 1) == 0) {
		*result = METRIC_ACTION_REWRITE_SUBJECT;
	}
	else if (g_ascii_strncasecmp (data, "soft_reject",
			sizeof ("soft_reject") - 1) == 0) {
		*result = METRIC_ACTION_SOFT_REJECT;
	}
	else if (g_ascii_strncasecmp (data, "soft reject",
			sizeof ("soft reject") - 1) == 0) {
		*result = METRIC_ACTION_SOFT_REJECT;
	}
	else {
		return FALSE;
	}
	return TRUE;
}

const gchar *
rspamd_action_to_str (enum rspamd_metric_action action)
{
	switch (action) {
	case METRIC_ACTION_REJECT:
		return "reject";
	case METRIC_ACTION_SOFT_REJECT:
		return "soft reject";
	case METRIC_ACTION_REWRITE_SUBJECT:
		return "rewrite subject";
	case METRIC_ACTION_ADD_HEADER:
		return "add header";
	case METRIC_ACTION_GREYLIST:
		return "greylist";
	case METRIC_ACTION_NOACTION:
		return "no action";
	case METRIC_ACTION_MAX:
		return "invalid max action";
	}

	return "unknown action";
}

static double
get_specific_action_score (const ucl_object_t *metric,
		struct metric_action *action)
{
	const ucl_object_t *act, *sact;
	double score;

	if (metric) {
		act = ucl_object_find_key (metric, "actions");
		if (act) {
			sact = ucl_object_find_key (act, rspamd_action_to_str (action->action));
			if (sact != NULL && ucl_object_todouble_safe (sact, &score)) {
				return score;
			}
		}
	}

	return action->score;
}

gint
rspamd_check_action_metric (struct rspamd_task *task,
		double score, double *rscore, struct metric *metric)
{
	struct metric_action *action, *selected_action = NULL;
	double max_score = 0;
	const ucl_object_t *ms = NULL;
	int i;

	if (metric->actions != NULL) {
		if (task->settings) {
			ms = ucl_object_find_key (task->settings, metric->name);
		}

		for (i = METRIC_ACTION_REJECT; i < METRIC_ACTION_MAX; i++) {
			double sc;

			action = &metric->actions[i];
			sc = get_specific_action_score (ms, action);

			if (sc < 0) {
				continue;
			}
			if (score >= sc && sc > max_score) {
				selected_action = action;
				max_score = sc;
			}

			if (rscore != NULL && i == METRIC_ACTION_REJECT) {
				*rscore = sc;
			}
		}
	}
	if (selected_action) {
		return selected_action->action;
	}

	return METRIC_ACTION_NOACTION;
}

gboolean
rspamd_learn_task_spam (struct rspamd_classifier_config *cl,
	struct rspamd_task *task,
	gboolean is_spam,
	GError **err)
{
	/* XXX: Totally broken now */
	return FALSE;
#if 0
	GList *cur, *ex;
	struct classifier_ctx *cls_ctx;
	GTree *tokens = NULL;
	struct mime_text_part *part, *p1, *p2;
	gboolean is_utf = FALSE, is_twopart = FALSE;
	gint diff;

	cur = g_list_first (task->text_parts);
	if (cur != NULL && cur->next != NULL && cur->next->next == NULL) {
		is_twopart = TRUE;
	}

	/* Get tokens from each element */
	while (cur) {
		part = cur->data;
		/* Skip empty parts */
		if (part->is_empty) {
			cur = g_list_next (cur);
			continue;
		}
		is_utf = part->is_utf;
		ex = part->urls_offset;
		if (is_twopart && cur->next == NULL) {
			/*
			 * Compare part's content
			 * Note: here we don't have filters proceeded this message, so using pool variable is a bad idea
			 */
			p1 = cur->prev->data;
			p2 = part;
			if (p1->diff_str != NULL && p2->diff_str != NULL) {
				diff = rspamd_diff_distance (p1->diff_str, p2->diff_str);
			}
			else {
				diff = rspamd_fuzzy_compare_parts (p1, p2);
			}
			if (diff >= COMMON_PART_FACTOR) {
				msg_info (
					"message <%s> has two common text parts, ignore the last one",
					task->message_id);
				break;
			}
		}
		/* Get tokens */
		if (!cl->tokenizer->tokenize_func (
				cl->tokenizer, task->task_pool,
				part->words, &tokens, FALSE, is_utf, ex)) {
			g_set_error (err,
				filter_error_quark (), 2, "Cannot tokenize message");
			return FALSE;
		}
		cur = g_list_next (cur);
	}

	/* Handle messages without text */
	if (tokens == NULL) {
		g_set_error (err,
			filter_error_quark (), 3, "Cannot tokenize message, no text data");
		msg_info ("learn failed for message <%s>, no tokens to extract",
			task->message_id);
		return FALSE;
	}

	/* Take care of subject */
	tokenize_subject (task, &tokens);

	/* Init classifier */
	cls_ctx = cl->classifier->init_func (
		task->task_pool, cl);
	/* Learn */
	if (!cl->classifier->learn_spam_func (
			cls_ctx,
			tokens, task, is_spam, task->cfg->lua_state, err)) {
		if (*err) {
			msg_info ("learn failed for message <%s>, learn error: %s",
				task->message_id,
				(*err)->message);
			return FALSE;
		}
		else {
			g_set_error (err,
				filter_error_quark (), 4,
				"Learn failed, unknown learn classifier error");
			msg_info ("learn failed for message <%s>, unknown learn error",
				task->message_id);
			return FALSE;
		}
	}
	/* Increase statistics */
	task->worker->srv->stat->messages_learned++;

	msg_info ("learn success for message <%s>",
		task->message_id);

	return TRUE;
#endif
}

/*
 * vi:ts=4
 */
