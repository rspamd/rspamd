/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "logger.h"
#include "expression.h"
#include "task.h"
#include "utlist.h"
#include "filter.h"
#include "composites.h"

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

static GQuark
rspamd_composites_quark (void)
{
	return g_quark_from_static_string ("composites");
}

static rspamd_expression_atom_t *
rspamd_composite_expr_parse (const gchar *line, gsize len,
		rspamd_mempool_t *pool, gpointer ud, GError **err)
{
	gsize clen;
	rspamd_expression_atom_t *res;

	/*
	 * Composites are just sequences of symbols
	 */
	clen = strcspn (line, ", \t()><+!|&\n");
	if (clen == 0) {
		/* Invalid composite atom */
		g_set_error (err, rspamd_composites_quark (), 100, "Invalid composite: %s",
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
	struct metric *metric;
	GHashTableIter it;
	gpointer k, v;
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
		metric = g_hash_table_lookup (cd->task->cfg->metrics, DEFAULT_METRIC);
		g_assert (metric != NULL);
		gr = g_hash_table_lookup (metric->groups, sym + 2);

		if (gr != NULL) {
			g_hash_table_iter_init (&it, gr->symbols);

			while (g_hash_table_iter_next (&it, &k, &v)) {
				sdef = v;
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
