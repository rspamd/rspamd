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

#include <math.h>

#define msg_err_composites(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        "composites", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_composites(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        "composites", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_composites(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "composites", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

#define msg_debug_composites(...)  rspamd_conditional_debug_fast (NULL, task->from_addr, \
        rspamd_composites_log_id, "composites", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(composites)

struct composites_data {
	struct rspamd_task *task;
	struct rspamd_composite *composite;
	struct rspamd_metric_result *metric_res;
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
	const gchar *sym;
	struct rspamd_composite *comp;
	GNode *parent;
	guint action;
	struct symbol_remove_data *prev, *next;
};

static rspamd_expression_atom_t * rspamd_composite_expr_parse (const gchar *line, gsize len,
		rspamd_mempool_t *pool, gpointer ud, GError **err);
static gdouble rspamd_composite_expr_process (struct rspamd_expr_process_data *process_data, rspamd_expression_atom_t *atom);
static gint rspamd_composite_expr_priority (rspamd_expression_atom_t *atom);
static void rspamd_composite_expr_destroy (rspamd_expression_atom_t *atom);
static void composites_foreach_callback (gpointer key, gpointer value, void *data);

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
	clen = strcspn (line, ", \t()><!|&\n");
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

static gdouble
rspamd_composite_process_single_symbol (struct composites_data *cd,
		const gchar *sym, struct rspamd_symbol_result **pms)
{
	struct rspamd_symbol_result *ms = NULL;
	gdouble rc = 0;
	struct rspamd_composite *ncomp;
	struct rspamd_task *task = cd->task;

	if ((ms = rspamd_task_find_symbol_result (cd->task, sym)) == NULL) {
		msg_debug_composites ("not found symbol %s in composite %s", sym,
				cd->composite->sym);
		if ((ncomp =
				g_hash_table_lookup (cd->task->cfg->composite_symbols,
						sym)) != NULL) {

			msg_debug_composites ("symbol %s for composite %s is another composite",
					sym, cd->composite->sym);

			if (isclr (cd->checked, ncomp->id * 2)) {
				struct rspamd_composite *saved;

				msg_debug_composites ("composite dependency %s for %s is not checked",
						sym, cd->composite->sym);
				/* Set checked for this symbol to avoid cyclic references */
				setbit (cd->checked, cd->composite->id * 2);
				saved = cd->composite; /* Save the current composite */
				composites_foreach_callback ((gpointer)ncomp->sym, ncomp, cd);

				/* Restore state */
				cd->composite = saved;
				clrbit (cd->checked, cd->composite->id * 2);

				ms = rspamd_task_find_symbol_result (cd->task, sym);
			}
			else {
				/*
				 * XXX: in case of cyclic references this would return 0
				 */
				if (isset (cd->checked, ncomp->id * 2 + 1)) {
					ms = rspamd_task_find_symbol_result (cd->task, sym);
				}
			}
		}
	}

	if (ms) {
		msg_debug_composites ("found symbol %s in composite %s, weight: %.3f",
				sym, cd->composite->sym, ms->score);
		if (ms->score == 0) {
			rc = 0.001; /* Distinguish from 0 */
		}
		else {
			rc = ms->score;
		}
	}

	*pms = ms;
	return rc;
}

static void
rspamd_composite_process_symbol_removal (rspamd_expression_atom_t *atom,
										 struct composites_data *cd,
										 struct rspamd_symbol_result *ms,
										 const gchar *beg)
{
	gchar t;
	struct symbol_remove_data *rd, *nrd;
	struct rspamd_task *task = cd->task;

	if (ms == NULL) {
		return;
	}

	/*
	 * At this point we know that we need to do something about this symbol,
	 * however, we don't know whether we need to delete it unfortunately,
	 * that depends on the later decisions when the complete expression is
	 * evaluated.
	 */
	rd = g_hash_table_lookup (cd->symbols_to_remove, ms->name);

	nrd = rspamd_mempool_alloc (cd->task->task_pool, sizeof (*nrd));
	nrd->sym = ms->name;

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
			nrd->action &= ~RSPAMD_COMPOSITE_REMOVE_SYMBOL;
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
		g_hash_table_insert (cd->symbols_to_remove, (gpointer)ms->name, rd);
		msg_debug_composites ("added symbol %s to removal: %d policy, from composite %s",
				ms->name, nrd->action, cd->composite->sym);
	}
	else {
		DL_APPEND (rd, nrd);
		msg_debug_composites ("append symbol %s to removal: %d policy, from composite %s",
				ms->name, nrd->action, cd->composite->sym);
	}
}

static gdouble
rspamd_composite_expr_process (struct rspamd_expr_process_data *process_data,
		rspamd_expression_atom_t *atom)
{
	struct composites_data *cd = process_data->cd;
	const gchar *beg = atom->data, *sym = NULL;

	struct rspamd_symbol_result *ms = NULL;
	struct rspamd_symbols_group *gr;
	struct rspamd_symbol *sdef;
	struct rspamd_task *task = cd->task;
	GHashTableIter it;
	gpointer k, v;
	gdouble rc = 0, max = 0;

	if (isset (cd->checked, cd->composite->id * 2)) {
		/* We have already checked this composite, so just return its value */
		if (isset (cd->checked, cd->composite->id * 2 + 1)) {
			ms = rspamd_task_find_symbol_result (cd->task, sym);
		}

		if (ms) {
			if (ms->score == 0) {
				rc = 0.001; /* Distinguish from 0 */
			}
			else {
				rc = ms->score;
			}
		}

		msg_debug_composites ("composite %s is already checked, result: %.2f",
				cd->composite->sym, rc);

		return rc;
	}

	sym = beg;

	while (*sym != '\0' && !g_ascii_isalnum (*sym)) {
		sym ++;
	}

	if (strncmp (sym, "g:", 2) == 0) {
		gr = g_hash_table_lookup (cd->task->cfg->groups, sym + 2);

		if (gr != NULL) {
			g_hash_table_iter_init (&it, gr->symbols);

			while (g_hash_table_iter_next (&it, &k, &v)) {
				sdef = v;
				rc = rspamd_composite_process_single_symbol (cd, sdef->name, &ms);

				if (rc) {
					rspamd_composite_process_symbol_removal (atom,
							cd,
							ms,
							beg);

					if (fabs (rc) > max) {
						max = fabs (rc);
					}
				}
			}
		}

		rc = max;
	}
	else if (strncmp (sym, "g+:", 3) == 0) {
		/* Group, positive symbols only */
		gr = g_hash_table_lookup (cd->task->cfg->groups, sym + 3);

		if (gr != NULL) {
			g_hash_table_iter_init (&it, gr->symbols);

			while (g_hash_table_iter_next (&it, &k, &v)) {
				sdef = v;

				if (sdef->score > 0) {
					rc = rspamd_composite_process_single_symbol (cd,
							sdef->name,
							&ms);

					if (rc) {
						rspamd_composite_process_symbol_removal (atom,
								cd,
								ms,
								beg);

						if (fabs (rc) > max) {
							max = fabs (rc);
						}
					}
				}
			}

			rc = max;
		}
	}
	else if (strncmp (sym, "g-:", 3) == 0) {
		/* Group, negative symbols only */
		gr = g_hash_table_lookup (cd->task->cfg->groups, sym + 3);

		if (gr != NULL) {
			g_hash_table_iter_init (&it, gr->symbols);

			while (g_hash_table_iter_next (&it, &k, &v)) {
				sdef = v;

				if (sdef->score < 0) {
					rc = rspamd_composite_process_single_symbol (cd, sdef->name, &ms);

					if (rc) {
						rspamd_composite_process_symbol_removal (atom,
								cd,
								ms,
								beg);

						if (fabs (rc) > max) {
							max = fabs (rc);
						}
					}
				}
			}

			rc = max;
		}
	}
	else {
		rc = rspamd_composite_process_single_symbol (cd, sym, &ms);

		if (rc) {
			rspamd_composite_process_symbol_removal (atom,
					cd,
					ms,
					beg);
		}
	}

	msg_debug_composites ("final result for composite %s is %.2f",
			cd->composite->sym, rc);

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
	struct rspamd_task *task;
	gdouble rc;

	cd->composite = comp;
	task = cd->task;

	if (!isset (cd->checked, cd->composite->id * 2)) {
		if (rspamd_symcache_is_checked (cd->task, cd->task->cfg->cache,
				key)) {
			msg_debug_composites ("composite %s is checked in symcache but not "
					"in composites bitfield", cd->composite->sym);
			setbit (cd->checked, comp->id * 2);
			clrbit (cd->checked, comp->id * 2 + 1);
		}
		else {
			if (rspamd_task_find_symbol_result (cd->task, key) != NULL) {
				/* Already set, no need to check */
				msg_debug_composites ("composite %s is already in metric "
						"in composites bitfield", cd->composite->sym);
				setbit (cd->checked, comp->id * 2);
				clrbit (cd->checked, comp->id * 2 + 1);

				return;
			}

			struct rspamd_expr_process_data process_data;
			memset (&process_data, 0, sizeof process_data);

			process_data.flags = RSPAMD_EXPRESSION_FLAG_NOOPT;
			process_data.cd = cd;

			rc = rspamd_process_expression (comp->expr, &process_data);

			/* Checked bit */
			setbit (cd->checked, comp->id * 2);

			/* Result bit */
			if (rc != 0) {
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
	struct rspamd_task *task;
	struct symbol_remove_data *rd = value, *cur;
	struct rspamd_symbol_result *ms;
	gboolean skip = FALSE, has_valid_op = FALSE,
			want_remove_score = TRUE, want_remove_symbol = TRUE,
			want_forced = FALSE;
	GNode *par;

	task = cd->task;

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

	ms = rspamd_task_find_symbol_result (task, rd->sym);

	if (has_valid_op && ms && !(ms->flags & RSPAMD_SYMBOL_RESULT_IGNORED)) {

		if (want_remove_score || want_forced) {
			msg_debug_composites ("remove symbol weight for %s (was %.2f)",
					key, ms->score);
			cd->metric_res->score -= ms->score;
			ms->score = 0.0;
		}

		if (want_remove_symbol || want_forced) {
			ms->flags |= RSPAMD_SYMBOL_RESULT_IGNORED;
			msg_debug_composites ("remove symbol %s", key);
		}
	}
}

static void
composites_metric_callback (struct rspamd_metric_result *metric_res,
		struct rspamd_task *task)
{
	struct composites_data *cd =
		rspamd_mempool_alloc (task->task_pool, sizeof (struct composites_data));

	cd->task = task;
	cd->metric_res = metric_res;
	cd->symbols_to_remove = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	cd->checked =
		rspamd_mempool_alloc0 (task->task_pool,
			NBYTES (g_hash_table_size (task->cfg->composite_symbols) * 2));

	/* Process hash table */
	rspamd_symcache_composites_foreach (task,
			task->cfg->cache,
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
	if (task->result) {
		composites_metric_callback (task->result, task);
	}
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
