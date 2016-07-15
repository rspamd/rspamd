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
	GHashTable *symbols_to_remove;
	guint8 *checked;
};

enum rspamd_composite_action {
	RSPAMD_COMPOSITE_UNTOUCH = 0,
	RSPAMD_COMPOSITE_REMOVE_SYMBOL = (1 << 0),
	RSPAMD_COMPOSITE_REMOVE_WEIGHT = (1 << 1),
	RSPAMD_COMPOSITE_REMOVE_FORCED = (1 << 2)
};

struct symbol_remove_data {
	struct symbol *ms;
	struct rspamd_composite *comp;
	GNode *parent;
	guint action;
	struct symbol_remove_data *prev, *next;
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
	const gchar *beg = atom->data, *sym = NULL;
	gchar t;
	struct symbol_remove_data *rd, *nrd;
	struct symbol *ms;
	struct rspamd_symbols_group *gr;
	struct rspamd_symbol_def *sdef;
	struct metric *metric;
	GHashTableIter it;
	gpointer k, v;
	gint rc = 0;

	if (isset (cd->checked, cd->composite->id * 2)) {
		/* We have already checked this composite, so just return its value */
		rc = isset (cd->checked, cd->composite->id * 2 + 1);
		return rc;
	}

	sym = beg;

	while (*sym != '\0' && !g_ascii_isalnum (*sym)) {
		sym ++;
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
		rd = g_hash_table_lookup (cd->symbols_to_remove, ms->name);

		nrd = rspamd_mempool_alloc (cd->task->task_pool, sizeof (*nrd));
		nrd->ms = ms;

		/* By default remove symbols */
		switch (cd->composite->policy) {
		case RSPAMD_COMPOSITE_POLICY_REMOVE_ALL:
		default:
			nrd->action = (RSPAMD_COMPOSITE_REMOVE_SYMBOL|RSPAMD_COMPOSITE_REMOVE_WEIGHT);
			break;
		case RSPAMD_COMPOSITE_POLICY_REMOVE_SYMBOL:
			nrd->action = RSPAMD_COMPOSITE_REMOVE_SYMBOL;
			break;
		case RSPAMD_COMPOSITE_POLICY_REMOVE_WEIGHT:
			nrd->action = RSPAMD_COMPOSITE_REMOVE_WEIGHT;
			break;
		case RSPAMD_COMPOSITE_POLICY_LEAVE:
			nrd->action = 0;
			break;
		}

		for (;;) {
			t = *beg;

			if (t == '~') {
				nrd->action &= ~RSPAMD_COMPOSITE_REMOVE_WEIGHT;
			}
			else if (t == '-') {
				nrd->action &= ~(RSPAMD_COMPOSITE_REMOVE_WEIGHT|
						RSPAMD_COMPOSITE_REMOVE_SYMBOL);
			}
			else if (t == '^') {
				nrd->action |= RSPAMD_COMPOSITE_REMOVE_FORCED;
			}
			else {
				break;
			}

			beg ++;
		}

		nrd->comp = cd->composite;
		nrd->parent = atom->parent;

		if (rd == NULL) {
			DL_APPEND (rd, nrd);
			g_hash_table_insert (cd->symbols_to_remove,
							(gpointer)ms->name,
							rd);
		}
		else {
			DL_APPEND (rd, nrd);
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


static void
composites_foreach_callback (gpointer key, gpointer value, void *data)
{
	struct composites_data *cd = data;
	struct rspamd_composite *comp = value;
	gint rc;

	cd->composite = comp;

	if (!isset (cd->checked, cd->composite->id * 2)) {
		if (rspamd_symbols_cache_is_checked (cd->task, cd->task->cfg->cache,
				key)) {
			setbit (cd->checked, comp->id * 2);
			clrbit (cd->checked, comp->id * 2 + 1);
		}
		else {
			rc = rspamd_process_expression (comp->expr,
					RSPAMD_EXPRESSION_FLAG_NOOPT, cd);

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
	}
}


static void
composites_remove_symbols (gpointer key, gpointer value, gpointer data)
{
	struct composites_data *cd = data;
	struct symbol_remove_data *rd = value, *cur;
	gboolean skip = FALSE, has_valid_op = FALSE,
			want_remove_score = TRUE, want_remove_symbol = TRUE,
			want_forced = FALSE;
	GNode *par;

	DL_FOREACH (rd, cur) {
		if (!isset (cd->checked, cur->comp->id * 2 + 1)) {
			continue;
		}
		/*
		 * First of all exclude all elements with any parent that is negation:
		 * !A || B -> here we can have both !A and B matched, but we do *NOT*
		 * want to remove symbol in that case
		 */
		par = cur->parent;
		skip = FALSE;

		while (par) {
			if (rspamd_expression_node_is_op (par, OP_NOT)) {
				skip = TRUE;
				break;
			}

			par = par->parent;
		}

		if (skip) {
			continue;
		}

		has_valid_op = TRUE;
		/*
		 * Now we can try to remove symbols/scores
		 *
		 * We apply the following logic here:
		 * - if no composites would like to save score then we remove score
		 * - if no composites would like to save symbol then we remove symbol
		 */
		if (!(cur->action & RSPAMD_COMPOSITE_REMOVE_SYMBOL)) {
			want_remove_symbol = FALSE;
		}

		if (!(cur->action & RSPAMD_COMPOSITE_REMOVE_WEIGHT)) {
			want_remove_score = FALSE;
		}

		if (cur->action & RSPAMD_COMPOSITE_REMOVE_FORCED) {
			want_forced = TRUE;
		}
	}

	if (has_valid_op) {
		if (want_remove_symbol || want_forced) {
			g_hash_table_remove (cd->metric_res->symbols, key);
		}
		if (want_remove_score || want_forced) {
			cd->metric_res->score -= rd->ms->score;
		}
	}
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
	cd->symbols_to_remove = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	cd->checked =
		rspamd_mempool_alloc0 (task->task_pool,
			NBYTES (g_hash_table_size (task->cfg->composite_symbols) * 2));

	/* Process hash table */
	g_hash_table_foreach (task->cfg->composite_symbols,
		composites_foreach_callback,
		cd);

	/* Remove symbols that are in composites */
	g_hash_table_foreach (cd->symbols_to_remove, composites_remove_symbols, cd);
	/* Free list */
	g_hash_table_unref (cd->symbols_to_remove);
}

void
rspamd_make_composites (struct rspamd_task *task)
{
	g_hash_table_foreach (task->results, composites_metric_callback, task);
}


enum rspamd_composite_policy
rspamd_composite_policy_from_str (const gchar *string)
{
	enum rspamd_composite_policy ret = RSPAMD_COMPOSITE_POLICY_UNKNOWN;

	if (strcmp (string, "remove") == 0 || strcmp (string, "remove_all") == 0 ||
			strcmp (string, "default") == 0) {
		ret = RSPAMD_COMPOSITE_POLICY_REMOVE_ALL;
	}
	else if (strcmp (string, "remove_symbol") == 0) {
		ret = RSPAMD_COMPOSITE_POLICY_REMOVE_SYMBOL;
	}
	else if (strcmp (string, "remove_weight") == 0) {
		ret = RSPAMD_COMPOSITE_POLICY_REMOVE_WEIGHT;
	}
	else if (strcmp (string, "leave") == 0 || strcmp (string, "remove_none") == 0) {
		ret = RSPAMD_COMPOSITE_POLICY_LEAVE;
	}

	return ret;
}
