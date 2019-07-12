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
#include "mem_pool.h"
#include "filter.h"
#include "rspamd.h"
#include "message.h"
#include "lua/lua_common.h"
#include "libserver/cfg_file_private.h"
#include "libmime/filter_private.h"
#include <math.h>
#include "contrib/uthash/utlist.h"

#define msg_debug_metric(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_metric_log_id, "metric", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(metric)

/* Average symbols count to optimize hash allocation */
static struct rspamd_counter_data symbols_count;

static void
rspamd_metric_result_dtor (gpointer d)
{
	struct rspamd_metric_result *r = (struct rspamd_metric_result *)d;
	struct rspamd_symbol_result sres;

	rspamd_set_counter_ema (&symbols_count, kh_size (r->symbols), 0.5);

	kh_foreach_value (r->symbols, sres, {
		if (sres.options) {
			kh_destroy (rspamd_options_hash, sres.options);
		}
	});
	kh_destroy (rspamd_symbols_hash, r->symbols);
	kh_destroy (rspamd_symbols_group_hash, r->sym_groups);
}

struct rspamd_metric_result *
rspamd_create_metric_result (struct rspamd_task *task)
{
	struct rspamd_metric_result *metric_res;
	guint i;

	metric_res = task->result;

	if (metric_res != NULL) {
		return metric_res;
	}

	metric_res = rspamd_mempool_alloc0 (task->task_pool,
			sizeof (struct rspamd_metric_result));
	metric_res->symbols = kh_init (rspamd_symbols_hash);
	metric_res->sym_groups = kh_init (rspamd_symbols_group_hash);

	/* Optimize allocation */
	kh_resize (rspamd_symbols_group_hash, metric_res->sym_groups, 4);

	if (symbols_count.mean > 4) {
		kh_resize (rspamd_symbols_hash, metric_res->symbols, symbols_count.mean);
	}
	else {
		kh_resize (rspamd_symbols_hash, metric_res->symbols, 4);
	}

	if (task->cfg) {
		struct rspamd_action *act, *tmp;

		metric_res->actions_limits = rspamd_mempool_alloc0 (task->task_pool,
			sizeof (struct rspamd_action_result) * HASH_COUNT (task->cfg->actions));
		i = 0;

		HASH_ITER (hh, task->cfg->actions, act, tmp) {
			if (!(act->flags & RSPAMD_ACTION_NO_THRESHOLD)) {
				metric_res->actions_limits[i].cur_limit = act->threshold;
			}
			metric_res->actions_limits[i].action = act;

			i ++;
		}

		metric_res->nactions = i;
	}

	rspamd_mempool_add_destructor (task->task_pool,
			rspamd_metric_result_dtor,
			metric_res);

	return metric_res;
}

static inline int
rspamd_pr_sort (const struct rspamd_passthrough_result *pra,
				const struct rspamd_passthrough_result *prb)
{
	return prb->priority - pra->priority;
}

void
rspamd_add_passthrough_result (struct rspamd_task *task,
									struct rspamd_action *action,
									guint priority,
									double target_score,
									const gchar *message,
									const gchar *module,
									guint flags)
{
	struct rspamd_metric_result *metric_res;
	struct rspamd_passthrough_result *pr;

	metric_res = task->result;

	pr = rspamd_mempool_alloc (task->task_pool, sizeof (*pr));
	pr->action = action;
	pr->priority = priority;
	pr->message = message;
	pr->module = module;
	pr->target_score = target_score;
	pr->flags = flags;

	DL_APPEND (metric_res->passthrough_result, pr);
	DL_SORT (metric_res->passthrough_result, rspamd_pr_sort);

	if (!isnan (target_score)) {

		msg_info_task ("<%s>: set pre-result to '%s' %s(%.2f): '%s' from %s(%d)",
				MESSAGE_FIELD_CHECK (task, message_id), action->name,
				flags & RSPAMD_PASSTHROUGH_LEAST ? "*least " : "",
				target_score,
				message, module, priority);
	}
	else {
		msg_info_task ("<%s>: set pre-result to '%s' %s(no score): '%s' from %s(%d)",
				MESSAGE_FIELD_CHECK (task, message_id), action->name,
				flags & RSPAMD_PASSTHROUGH_LEAST ? "*least " : "",
				message, module, priority);
	}
}

static inline gdouble
rspamd_check_group_score (struct rspamd_task *task,
		const gchar *symbol,
		struct rspamd_symbols_group *gr,
		gdouble *group_score,
		gdouble w)
{
	if (gr != NULL && group_score && gr->max_score > 0.0 && w > 0.0) {
		if (*group_score >= gr->max_score && w > 0) {
			msg_info_task ("maximum group score %.2f for group %s has been reached,"
						   " ignoring symbol %s with weight %.2f", gr->max_score,
					gr->name, symbol, w);
			return NAN;
		}
		else if (*group_score + w > gr->max_score) {
			w = gr->max_score - *group_score;
		}
	}

	return w;
}

#ifndef DBL_EPSILON
#define DBL_EPSILON 2.2204460492503131e-16
#endif

static struct rspamd_symbol_result *
insert_metric_result (struct rspamd_task *task,
		const gchar *symbol,
		double weight,
		const gchar *opt,
		enum rspamd_symbol_insert_flags flags)
{
	struct rspamd_metric_result *metric_res;
	struct rspamd_symbol_result *s = NULL;
	gdouble final_score, *gr_score = NULL, next_gf = 1.0, diff;
	struct rspamd_symbol *sdef;
	struct rspamd_symbols_group *gr = NULL;
	const ucl_object_t *mobj, *sobj;
	gint max_shots, ret;
	guint i;
	khiter_t k;
	gboolean single = !!(flags & RSPAMD_SYMBOL_INSERT_SINGLE);
	gchar *sym_cpy;

	metric_res = task->result;

	if (!isfinite (weight)) {
		msg_warn_task ("detected %s score for symbol %s, replace it with zero",
				isnan (weight) ? "NaN" : "infinity", symbol);
		weight = 0.0;
	}

	msg_debug_metric ("want to insert symbol %s, initial weight %.2f",
			symbol, weight);

	sdef = g_hash_table_lookup (task->cfg->symbols, symbol);
	if (sdef == NULL) {
		if (flags & RSPAMD_SYMBOL_INSERT_ENFORCE) {
			final_score = 1.0 * weight; /* Enforce static weight to 1.0 */
		}
		else {
			final_score = 0.0;
		}

		msg_debug_metric ("no symbol definition for %s; final multiplier %.2f",
				symbol, final_score);
	}
	else {
		if (sdef->cache_item) {
			/* Check if we can insert this symbol at all */
			if (!rspamd_symcache_is_item_allowed (task, sdef->cache_item, FALSE)) {
				msg_debug_metric ("symbol %s is not allowed to be inserted due to settings",
						symbol);
				return NULL;
			}
		}

		final_score = (*sdef->weight_ptr) * weight;

		PTR_ARRAY_FOREACH (sdef->groups, i, gr) {
			k = kh_get (rspamd_symbols_group_hash, metric_res->sym_groups, gr);

			if (k == kh_end (metric_res->sym_groups)) {
				k = kh_put (rspamd_symbols_group_hash, metric_res->sym_groups,
						gr, &ret);
				kh_value (metric_res->sym_groups, k) = 0;
			}
		}

		msg_debug_metric ("metric multiplier for %s is %.2f",
				symbol, *sdef->weight_ptr);
	}

	if (task->settings) {
		mobj = task->settings;
		gdouble corr;

		sobj = ucl_object_lookup (mobj, symbol);
		if (sobj != NULL && ucl_object_todouble_safe (sobj, &corr)) {
			msg_debug_metric ("settings: changed weight of symbol %s from %.2f "
					 "to %.2f * %.2f",
					symbol, final_score, corr, weight);
			final_score = corr * weight;
		}
	}

	k = kh_get (rspamd_symbols_hash, metric_res->symbols, symbol);
	if (k != kh_end (metric_res->symbols)) {
		/* Existing metric score */
		s = &kh_value (metric_res->symbols, k);
		if (single) {
			max_shots = 1;
		}
		else {
			if (sdef) {
				max_shots = sdef->nshots;
			}
			else {
				max_shots = task->cfg->default_max_shots;
			}
		}

		msg_debug_metric ("nshots: %d for symbol %s", max_shots, symbol);

		if (!single && (max_shots > 0 && (s->nshots >= max_shots))) {
			single = TRUE;
		}

		/* Now check for the duplicate options */
		if (opt && s->options) {
			k = kh_get (rspamd_options_hash, s->options, opt);

			if (k == kh_end (s->options)) {
				rspamd_task_add_result_option (task, s, opt);
			}
			else {
				s->nshots ++;
			}
		}
		else {
			s->nshots ++;
			rspamd_task_add_result_option (task, s, opt);
		}

		/* Adjust diff */
		if (!single) {
			diff = final_score;
			msg_debug_metric ("symbol %s can be inserted multiple times: %.2f weight",
					symbol, diff);
		}
		else {
			if (fabs (s->score) < fabs (final_score) &&
				signbit (s->score) == signbit (final_score)) {
				/* Replace less significant weight with a more significant one */
				diff = final_score - s->score;
				msg_debug_metric ("symbol %s can be inserted single time;"
					  " weight adjusted %.2f + %.2f",
						symbol, s->score, diff);
			}
			else {
				diff = 0;
			}
		}

		if (diff) {
			/* Handle grow factor */
			if (metric_res->grow_factor && diff > 0) {
				diff *= metric_res->grow_factor;
				next_gf *= task->cfg->grow_factor;
			}
			else if (diff > 0) {
				next_gf = task->cfg->grow_factor;
			}

			msg_debug_metric ("adjust grow factor to %.2f for symbol %s (%.2f final)",
					next_gf, symbol, diff);

			if (sdef) {
				PTR_ARRAY_FOREACH (sdef->groups, i, gr) {
					gdouble cur_diff;

					k = kh_get (rspamd_symbols_group_hash,
							metric_res->sym_groups, gr);
					g_assert (k != kh_end (metric_res->sym_groups));
					gr_score = &kh_value (metric_res->sym_groups, k);
					cur_diff = rspamd_check_group_score (task, symbol, gr,
							gr_score, diff);

					if (isnan (cur_diff)) {
						/* Limit reached, do not add result */
						msg_debug_metric (
								"group limit %.2f is reached for %s when inserting symbol %s;"
								" drop score %.2f",
								*gr_score, gr->name, symbol, diff);

						diff = NAN;
						break;
					} else if (gr_score) {
						*gr_score += cur_diff;

						if (cur_diff < diff) {
							/* Reduce */
							msg_debug_metric (
									"group limit %.2f is reached for %s when inserting symbol %s;"
									" reduce score %.2f - %.2f",
									*gr_score, gr->name, symbol, diff, cur_diff);
							diff = cur_diff;
						}
					}
				}
			}

			if (!isnan (diff)) {
				metric_res->score += diff;
				metric_res->grow_factor = next_gf;

				if (single) {
					msg_debug_metric ("final score for single symbol %s = %.2f; %.2f diff",
							symbol, final_score, diff);
					s->score = final_score;
				} else {
					msg_debug_metric ("increase final score for multiple symbol %s += %.2f = %.2f",
							symbol, s->score, diff);
					s->score += diff;
				}
			}
		}
	}
	else {
		/* New result */
		sym_cpy = rspamd_mempool_strdup (task->task_pool, symbol);
		k = kh_put (rspamd_symbols_hash, metric_res->symbols,
				sym_cpy, &ret);
		g_assert (ret > 0);
		s = &kh_value (metric_res->symbols, k);
		memset (s, 0, sizeof (*s));

		/* Handle grow factor */
		if (metric_res->grow_factor && final_score > 0) {
			final_score *= metric_res->grow_factor;
			next_gf *= task->cfg->grow_factor;
		}
		else if (final_score > 0) {
			next_gf = task->cfg->grow_factor;
		}

		msg_debug_metric ("adjust grow factor to %.2f for symbol %s (%.2f final)",
				next_gf, symbol, final_score);

		s->name = sym_cpy;
		s->sym = sdef;
		s->nshots = 1;

		if (sdef) {
			/* Check group limits */
			PTR_ARRAY_FOREACH (sdef->groups, i, gr) {
				gdouble cur_score;

				k = kh_get (rspamd_symbols_group_hash, metric_res->sym_groups, gr);
				g_assert (k != kh_end (metric_res->sym_groups));
				gr_score = &kh_value (metric_res->sym_groups, k);
				cur_score = rspamd_check_group_score (task, symbol, gr,
						gr_score, final_score);

				if (isnan (cur_score)) {
					/* Limit reached, do not add result */
					msg_debug_metric (
							"group limit %.2f is reached for %s when inserting symbol %s;"
							" drop score %.2f",
							*gr_score, gr->name, symbol, final_score);
					final_score = NAN;
					break;
				} else if (gr_score) {
					*gr_score += cur_score;

					if (cur_score < final_score) {
						/* Reduce */
						msg_debug_metric (
								"group limit %.2f is reached for %s when inserting symbol %s;"
								" reduce score %.2f - %.2f",
								*gr_score, gr->name, symbol, final_score, cur_score);
						final_score = cur_score;
					}
				}
			}
		}

		if (!isnan (final_score)) {
			const double epsilon = DBL_EPSILON;

			metric_res->score += final_score;
			metric_res->grow_factor = next_gf;
			s->score = final_score;

			if (final_score > epsilon) {
				metric_res->npositive ++;
				metric_res->positive_score += final_score;
			}
			else if (final_score < -epsilon) {
				metric_res->nnegative ++;
				metric_res->negative_score += fabs (final_score);
			}
		}
		else {
			s->score = 0;
		}

		rspamd_task_add_result_option (task, s, opt);
	}

	msg_debug_metric ("final insertion for symbol %s, score %.2f, factor: %f",
			symbol,
			s->score,
			final_score);

	return s;
}

struct rspamd_symbol_result *
rspamd_task_insert_result_full (struct rspamd_task *task,
		const gchar *symbol,
		double weight,
		const gchar *opt,
		enum rspamd_symbol_insert_flags flags)
{
	struct rspamd_symbol_result *s = NULL;

	if (task->processed_stages & (RSPAMD_TASK_STAGE_IDEMPOTENT >> 1)) {
		msg_err_task ("cannot insert symbol %s on idempotent phase",
				symbol);

		return NULL;
	}

	/* Insert symbol to default metric */
	s = insert_metric_result (task,
			symbol,
			weight,
			opt,
			flags);

	/* Process cache item */
	if (s && task->cfg->cache && s->sym) {
		rspamd_symcache_inc_frequency (task->cfg->cache, s->sym->cache_item);
	}

	return s;
}

gboolean
rspamd_task_add_result_option (struct rspamd_task *task,
		struct rspamd_symbol_result *s, const gchar *val)
{
	struct rspamd_symbol_option *opt;
	gboolean ret = FALSE;
	gchar *opt_cpy;
	khiter_t k;
	gint r;

	if (s && val) {
		if (s->options && !(s->sym &&
				(s->sym->flags & RSPAMD_SYMBOL_FLAG_ONEPARAM)) &&
				kh_size (s->options) < task->cfg->default_max_shots) {
			/* Append new options */
			k = kh_get (rspamd_options_hash, s->options, val);

			if (k == kh_end (s->options)) {
				opt = rspamd_mempool_alloc0 (task->task_pool, sizeof (*opt));
				opt_cpy = rspamd_mempool_strdup (task->task_pool, val);
				k = kh_put (rspamd_options_hash, s->options, opt_cpy, &r);

				kh_value (s->options, k) = opt;
				opt->option = opt_cpy;
				DL_APPEND (s->opts_head, opt);

				ret = TRUE;
			}
		}
		else {
			s->options = kh_init (rspamd_options_hash);
			opt = rspamd_mempool_alloc0 (task->task_pool, sizeof (*opt));
			opt_cpy = rspamd_mempool_strdup (task->task_pool, val);
			k = kh_put (rspamd_options_hash, s->options, opt_cpy, &r);

			kh_value (s->options, k) = opt;
			opt->option = opt_cpy;
			DL_APPEND (s->opts_head, opt);

			ret = TRUE;
		}
	}
	else if (!val) {
		ret = TRUE;
	}

	return ret;
}

struct rspamd_action*
rspamd_check_action_metric (struct rspamd_task *task)
{
	struct rspamd_action_result *action_lim,
			*noaction = NULL;
	struct rspamd_action *selected_action = NULL, *least_action = NULL;
	struct rspamd_passthrough_result *pr;
	double max_score = -(G_MAXDOUBLE), sc;
	int i;
	struct rspamd_metric_result *mres = task->result;
	gboolean seen_least = FALSE;

	if (mres->passthrough_result != NULL)  {
		DL_FOREACH (mres->passthrough_result, pr) {
			if (!seen_least || !(pr->flags & RSPAMD_PASSTHROUGH_LEAST)) {
				sc = pr->target_score;
				selected_action = pr->action;

				if (!(pr->flags & RSPAMD_PASSTHROUGH_LEAST)) {
					if (!isnan (sc)) {
						if (pr->action->action_type == METRIC_ACTION_NOACTION) {
							mres->score = MIN (sc, mres->score);
						}
						else {
							mres->score = sc;
						}
					}

					return selected_action;
				}
				else {
					seen_least = true;
					least_action = selected_action;

					if (isnan (sc)) {

						if (selected_action->flags & RSPAMD_ACTION_NO_THRESHOLD) {
							/*
							 * In this case, we have a passthrough action that
							 * is `least` action, however, there is no threshold
							 * on it.
							 *
							 * Hence, we imply the following logic:
							 *
							 * - we leave score unchanged
							 * - we apply passthrough no threshold action unless
							 *   score based action *is not* reject, otherwise
							 *   we apply reject action
							 */
						}
						else {
							sc = selected_action->threshold;
							max_score = sc;
						}
					}
					else {
						max_score = sc;
					}
				}
			}
		}
	}
	/* We are not certain about the results during processing */

	/*
	 * Select result by score
	 */
	for (i = mres->nactions - 1; i >= 0; i--) {
		action_lim = &mres->actions_limits[i];
		sc = action_lim->cur_limit;

		if (action_lim->action->action_type == METRIC_ACTION_NOACTION) {
			noaction = action_lim;
		}

		if (isnan (sc) ||
			(action_lim->action->flags & (RSPAMD_ACTION_NO_THRESHOLD|RSPAMD_ACTION_HAM))) {
			continue;
		}

		if (mres->score >= sc && sc > max_score) {
			selected_action = action_lim->action;
			max_score = sc;
		}
	}

	if (selected_action == NULL) {
		selected_action = noaction->action;
	}

	if (selected_action) {

		if (seen_least) {

			if (least_action->flags & RSPAMD_ACTION_NO_THRESHOLD) {
				if (selected_action->action_type != METRIC_ACTION_REJECT &&
						selected_action->action_type != METRIC_ACTION_DISCARD) {
					/* Override score based action with least action */
					selected_action = least_action;
				}
			}
			else {
				/* Adjust score if needed */
				mres->score = MAX (max_score, mres->score);
			}
		}

		return selected_action;
	}

	return noaction->action;
}

struct rspamd_symbol_result*
rspamd_task_find_symbol_result (struct rspamd_task *task, const char *sym)
{
	struct rspamd_symbol_result *res = NULL;
	khiter_t k;


	if (task->result) {
		k = kh_get (rspamd_symbols_hash, task->result->symbols, sym);

		if (k != kh_end (task->result->symbols)) {
			res = &kh_value (task->result->symbols, k);
		}
	}

	return res;
}

void
rspamd_task_symbol_result_foreach (struct rspamd_task *task,
										GHFunc func,
										gpointer ud)
{
	const gchar *kk;
	struct rspamd_symbol_result res;

	if (func && task->result) {
		kh_foreach (task->result->symbols, kk, res, {
			func ((gpointer)kk, (gpointer)&res, ud);
		});
	}
}