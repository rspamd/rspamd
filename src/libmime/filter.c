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
#include "expression.h"
#include "diff.h"
#include "libstat/stat_api.h"
#include "utlist.h"

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

static rspamd_expression_atom_t * rspamd_composite_expr_parse (const gchar *line, gsize len,
		rspamd_mempool_t *pool, gpointer ud, GError **err);
static gint rspamd_composite_expr_process (gpointer input, rspamd_expression_atom_t *atom);
static gint rspamd_composite_expr_priority (rspamd_expression_atom_t *atom);
static void rspamd_composite_expr_destroy (rspamd_expression_atom_t *atom);

const struct rspamd_atom_subr composite_expr_subr = {
	.parse = rspamd_composite_expr_parse,
	.process = rspamd_composite_expr_process,
	.priority = rspamd_composite_expr_priority,
	.destroy = rspamd_composite_expr_destroy
};

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
	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) g_hash_table_unref,
			metric_res->symbols);
	metric_res->sym_groups = g_hash_table_new (g_direct_hash, g_direct_equal);
	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) g_hash_table_unref,
			metric_res->sym_groups);
	metric_res->checked = FALSE;
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
	gdouble w, *gr_score = NULL;
	struct rspamd_symbol_def *sdef;
	struct rspamd_symbols_group *gr = NULL;
	const ucl_object_t *mobj, *sobj;

	metric_res = rspamd_create_metric_result (task, metric->name);

	sdef = g_hash_table_lookup (metric->symbols, symbol);
	if (sdef == NULL) {
		w = 0.0;
	}
	else {
		w = (*sdef->weight_ptr) * flag;
		gr = sdef->gr;

		if (gr != NULL) {
			gr_score = g_hash_table_lookup (metric_res->sym_groups, gr);

			if (gr_score == NULL) {
				gr_score = rspamd_mempool_alloc (task->task_pool, sizeof (gdouble));
				*gr_score = 0;
				g_hash_table_insert (metric_res->sym_groups, gr, gr_score);
			}
		}
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

	/* XXX: does not take grow factor into account */
	if (gr != NULL && gr_score != NULL && gr->max_score > 0.0) {
		if (*gr_score >= gr->max_score) {
			msg_info ("maximum group score %.2f for group %s has been reached,"
					" ignoring symbol %s with weight %.2f", gr->max_score,
					gr->name, symbol, w);
			return;
		}
		else if (*gr_score + w > gr->max_score) {
			w = gr->max_score - *gr_score;
		}

		*gr_score += w;
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
		s->def = sdef;
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
		/* XXX: increase frequency here */
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
			task->flags |= RSPAMD_TASK_FLAG_SKIP;
			return 0;
		}
	}

	/* Process metrics symbols */
	while (call_symbol_callback (task, task->cfg->cache, &item)) {
		/* Check reject actions */
		cur = task->cfg->metrics_list;
		while (cur) {
			metric = cur->data;
			if (!(task->flags & RSPAMD_TASK_FLAG_PASS_ALL) &&
				metric->actions[METRIC_ACTION_REJECT].score > 0 &&
				check_metric_is_spam (task, metric)) {
				msg_info ("<%s> has already scored more than %.2f, so do not "
						"plan any more checks", task->message_id,
						metric->actions[METRIC_ACTION_REJECT].score);
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
	struct rspamd_composite *composite;
	struct metric_result *metric_res;
	GTree *symbols_to_remove;
	guint8 *checked;
};

struct symbol_remove_data {
	struct symbol *ms;
	gboolean remove_weight;
	gboolean remove_symbol;
	GList *comp;
};


/*
 * Composites are just sequences of symbols
 */
static rspamd_expression_atom_t *
rspamd_composite_expr_parse (const gchar *line, gsize len,
		rspamd_mempool_t *pool, gpointer ud, GError **err)
{
	gsize clen;
	rspamd_expression_atom_t *res;

	clen = strcspn (line, ", \t()><+!|&\n");
	if (clen == 0) {
		/* Invalid composite atom */
		g_set_error (err, filter_error_quark (), 100, "Invalid composite: %s",
				line);
		return NULL;
	}

	res = rspamd_mempool_alloc0 (pool, sizeof (*res));
	res->len = clen;
	res->str = line;
	res->data = rspamd_mempool_alloc (pool, clen + 1);
	rspamd_strlcpy (res->data, line, clen + 1);

	return res;
}

static gint
rspamd_composite_process_single_symbol (struct composites_data *cd,
		const gchar *sym, struct symbol **pms)
{
	struct symbol *ms = NULL;
	gint rc = 0;
	struct rspamd_composite *ncomp;

	if ((ms = g_hash_table_lookup (cd->metric_res->symbols, sym)) == NULL) {
		if ((ncomp =
				g_hash_table_lookup (cd->task->cfg->composite_symbols,
						sym)) != NULL) {
			/* Set checked for this symbol to avoid cyclic references */
			if (isclr (cd->checked, ncomp->id * 2)) {
				setbit (cd->checked, cd->composite->id * 2);
				rc = rspamd_process_expression (ncomp->expr,
						RSPAMD_EXPRESSION_FLAG_NOOPT, cd);
				clrbit (cd->checked, cd->composite->id * 2);

				if (rc) {
					setbit (cd->checked, ncomp->id * 2 + 1);
				}
				setbit (cd->checked, ncomp->id * 2);

				ms = g_hash_table_lookup (cd->metric_res->symbols, sym);
			}
			else {
				/*
				 * XXX: in case of cyclic references this would return 0
				 */
				rc = isset (cd->checked, ncomp->id * 2 + 1);
			}
		}
	}
	else {
		rc = 1;
	}

	*pms = ms;
	return rc;
}

static gint
rspamd_composite_expr_process (gpointer input, rspamd_expression_atom_t *atom)
{
	struct composites_data *cd = (struct composites_data *)input;
	const gchar *sym = atom->data;
	struct symbol_remove_data *rd;
	struct symbol *ms;
	struct rspamd_symbols_group *gr;
	struct rspamd_symbol_def *sdef;
	gint rc = 0;
	gchar t = '\0';

	if (isset (cd->checked, cd->composite->id * 2)) {
		/* We have already checked this composite, so just return its value */
		rc = isset (cd->checked, cd->composite->id * 2 + 1);
		return rc;
	}

	if (*sym == '~' || *sym == '-') {
		t = *sym ++;
	}

	if (strncmp (sym, "g:", 2) == 0) {
		gr = g_hash_table_lookup (cd->task->cfg->symbols_groups, sym + 2);

		if (gr != NULL) {
			LL_FOREACH (gr->symbols, sdef) {
				rc = rspamd_composite_process_single_symbol (cd, sdef->name, &ms);
				if (rc) {
					break;
				}
			}
		}
	}
	else {
		rc = rspamd_composite_process_single_symbol (cd, sym, &ms);
	}

	if (rc && ms) {
		/*
		 * At this point we know that we need to do something about this symbol,
		 * however, we don't know whether we need to delete it unfortunately,
		 * that depends on the later decisions when the complete expression is
		 * evaluated.
		 */
		if ((rd = g_tree_lookup (cd->symbols_to_remove, ms->name)) == NULL) {
			rd = rspamd_mempool_alloc (cd->task->task_pool, sizeof (*rd));
			rd->ms = ms;

			if (G_UNLIKELY (t == '~')) {
				rd->remove_weight = FALSE;
				rd->remove_symbol = TRUE;
			}
			else if (G_UNLIKELY (t == '-')) {
				rd->remove_symbol = FALSE;
				rd->remove_weight = FALSE;
			}
			else {
				rd->remove_symbol = TRUE;
				rd->remove_weight = TRUE;
			}

			rd->comp = g_list_prepend (NULL, cd->composite);
			g_tree_insert (cd->symbols_to_remove,
					(gpointer)ms->name,
					rd);
		}
		else {
			/*
			 * XXX: what if we have different preferences regarding
			 * weight and symbol removal in different composites?
			 */
			rd->comp = g_list_prepend (rd->comp, cd->composite);
		}
	}

	return rc;
}

/*
 * We don't have preferences for composites
 */
static gint
rspamd_composite_expr_priority (rspamd_expression_atom_t *atom)
{
	return 0;
}

static void
rspamd_composite_expr_destroy (rspamd_expression_atom_t *atom)
{
	/* Composite atoms are destroyed just with the pool */
}

static gint
remove_compare_data (gconstpointer a, gconstpointer b)
{
	const gchar *ca = a, *cb = b;

	return strcmp (ca, cb);
}

static void
composites_foreach_callback (gpointer key, gpointer value, void *data)
{
	struct composites_data *cd = data;
	struct rspamd_composite *comp = value;
	gint rc;

	cd->composite = comp;

	rc = rspamd_process_expression (comp->expr, RSPAMD_EXPRESSION_FLAG_NOOPT, cd);

	/* Checked bit */
	setbit (cd->checked, comp->id * 2);

	/* Result bit */
	if (rc) {
		setbit (cd->checked, comp->id * 2 + 1);
		rspamd_task_insert_result_single (cd->task, key, 1.0, NULL);
	}
	else {
		clrbit (cd->checked, comp->id * 2 + 1);
	}
}


static gboolean
composites_remove_symbols (gpointer key, gpointer value, gpointer data)
{
	struct composites_data *cd = data;
	struct symbol_remove_data *rd = value;
	GList *cur;
	struct rspamd_composite *comp;
	gboolean matched = FALSE;

	cur = rd->comp;

	/*
	 * XXX: actually, this is a weak assumption as we are unaware here about
	 * negate operation and so on. We need to parse AST directly and remove
	 * only those symbols that could be removed.
	 */
	while (cur) {
		comp = cur->data;

		if (isset (cd->checked, comp->id * 2 + 1)) {
			matched = TRUE;
			break;
		}

		cur = g_list_next (cur);
	}

	g_list_free (rd->comp);

	if (matched) {
		if (rd->remove_symbol) {
			g_hash_table_remove (cd->metric_res->symbols, key);
		}
		if (rd->remove_weight) {
			cd->metric_res->score -= rd->ms->score;
		}
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
			NBYTES (g_hash_table_size (task->cfg->composite_symbols) * 2));

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


void
rspamd_process_statistics (struct rspamd_task *task)
{
	if (RSPAMD_TASK_IS_SKIPPED (task)) {
		return;
	}

	/* TODO: handle err here */
	rspamd_stat_classify (task, task->cfg->lua_state, NULL);

	/* Process results */
	rspamd_make_composites (task);
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
	return rspamd_stat_learn (task, is_spam, task->cfg->lua_state, err);
}

/*
 * vi:ts=4
 */
