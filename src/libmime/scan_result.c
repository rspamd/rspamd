/*
 * Copyright 2024 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "mem_pool.h"
#include "scan_result.h"
#include "rspamd.h"
#include "message.h"
#include "lua/lua_common.h"
#include "libserver/cfg_file_private.h"
#include "libmime/scan_result_private.h"
#include "rspamd_simdutf.h"
#include <math.h>
#include "contrib/uthash/utlist.h"

#define msg_debug_metric(...) rspamd_conditional_debug_fast(NULL, NULL,                                               \
															rspamd_metric_log_id, "metric", task->task_pool->tag.uid, \
															RSPAMD_LOG_FUNC,                                          \
															__VA_ARGS__)

INIT_LOG_MODULE(metric)

/* Average symbols count to optimize hash allocation */
static struct rspamd_counter_data symbols_count;

static void
rspamd_scan_result_dtor(gpointer d)
{
	struct rspamd_scan_result *r = (struct rspamd_scan_result *) d;
	struct rspamd_symbol_result *sres;

	rspamd_set_counter_ema(&symbols_count, kh_size(r->symbols), 0.5);

	if (r->symbol_cbref != -1) {
		luaL_unref(r->task->cfg->lua_state, LUA_REGISTRYINDEX, r->symbol_cbref);
	}

	kh_foreach_value(r->symbols, sres, {
		if (sres->options) {
			kh_destroy(rspamd_options_hash, sres->options);
		}
	});

	kh_destroy(rspamd_symbols_hash, r->symbols);
	kh_destroy(rspamd_symbols_group_hash, r->sym_groups);
}

static void
rspamd_metric_actions_foreach_cb(int i, struct rspamd_action *act, void *cbd)
{
	struct rspamd_scan_result *metric_res = (struct rspamd_scan_result *) cbd;
	metric_res->actions_config[i].flags = RSPAMD_ACTION_RESULT_DEFAULT;
	if (!(act->flags & RSPAMD_ACTION_NO_THRESHOLD)) {
		metric_res->actions_config[i].cur_limit = act->threshold;
	}
	else {
		metric_res->actions_config[i].flags |= RSPAMD_ACTION_RESULT_NO_THRESHOLD;
	}
	metric_res->actions_config[i].action = act;
}

struct rspamd_scan_result *
rspamd_create_metric_result(struct rspamd_task *task,
							const char *name, int lua_sym_cbref)
{
	struct rspamd_scan_result *metric_res;

	metric_res = rspamd_mempool_alloc0(task->task_pool,
									   sizeof(struct rspamd_scan_result));
	metric_res->symbols = kh_init(rspamd_symbols_hash);
	metric_res->sym_groups = kh_init(rspamd_symbols_group_hash);

	if (name) {
		metric_res->name = rspamd_mempool_strdup(task->task_pool, name);
	}
	else {
		metric_res->name = NULL;
	}

	metric_res->symbol_cbref = lua_sym_cbref;
	metric_res->task = task;

	/* Optimize allocation */
	kh_resize(rspamd_symbols_group_hash, metric_res->sym_groups, 4);

	if (symbols_count.mean > 4) {
		kh_resize(rspamd_symbols_hash, metric_res->symbols, symbols_count.mean);
	}
	else {
		kh_resize(rspamd_symbols_hash, metric_res->symbols, 4);
	}

	if (task->cfg) {
		size_t nact = rspamd_config_actions_size(task->cfg);
		metric_res->actions_config = rspamd_mempool_alloc0(task->task_pool,
														   sizeof(struct rspamd_action_config) * nact);
		rspamd_config_actions_foreach_enumerate(task->cfg, rspamd_metric_actions_foreach_cb, metric_res);
		metric_res->nactions = nact;
	}

	rspamd_mempool_add_destructor(task->task_pool,
								  rspamd_scan_result_dtor,
								  metric_res);
	DL_APPEND(task->result, metric_res);

	return metric_res;
}

static inline int
rspamd_pr_sort(const struct rspamd_passthrough_result *pra,
			   const struct rspamd_passthrough_result *prb)
{
	return prb->priority - pra->priority;
}

bool rspamd_add_passthrough_result(struct rspamd_task *task,
								   struct rspamd_action *action,
								   unsigned int priority,
								   double target_score,
								   const char *message,
								   const char *module,
								   uint flags,
								   struct rspamd_scan_result *scan_result)
{
	struct rspamd_passthrough_result *pr;

	if (scan_result == NULL) {
		scan_result = task->result;
	}

	/* Find the specific action config */
	struct rspamd_action_config *action_config = NULL;

	for (unsigned int i = 0; i < scan_result->nactions; i++) {
		struct rspamd_action_config *cur = &scan_result->actions_config[i];

		/* We assume that all action pointers are static */
		if (cur->action == action) {
			action_config = cur;
			break;
		}
	}

	if (action_config && (action_config->flags & RSPAMD_ACTION_RESULT_DISABLED)) {
		msg_info_task("<%s>: NOT set pre-result to '%s' %s(%.2f): '%s' from %s(%d); action is disabled",
					  MESSAGE_FIELD_CHECK(task, message_id), action->name,
					  flags & RSPAMD_PASSTHROUGH_LEAST ? "*least " : "",
					  target_score,
					  message, module, priority);

		return false;
	}

	pr = rspamd_mempool_alloc(task->task_pool, sizeof(*pr));
	pr->action = action;
	pr->priority = priority;
	pr->message = message;
	pr->module = module;
	pr->target_score = target_score;
	pr->flags = flags;

	DL_APPEND(scan_result->passthrough_result, pr);
	DL_SORT(scan_result->passthrough_result, rspamd_pr_sort);

	if (!isnan(target_score)) {

		msg_info_task("<%s>: set pre-result to '%s' %s(%.2f): '%s' from %s(%d)",
					  MESSAGE_FIELD_CHECK(task, message_id), action->name,
					  flags & RSPAMD_PASSTHROUGH_LEAST ? "*least " : "",
					  target_score,
					  message, module, priority);
	}
	else {
		msg_info_task("<%s>: set pre-result to '%s' %s(no score): '%s' from %s(%d)",
					  MESSAGE_FIELD_CHECK(task, message_id), action->name,
					  flags & RSPAMD_PASSTHROUGH_LEAST ? "*least " : "",
					  message, module, priority);
	}

	scan_result->nresults++;

	return true;
}

static inline double
rspamd_check_group_score(struct rspamd_task *task,
						 const char *symbol,
						 struct rspamd_symbols_group *gr,
						 double *group_score,
						 double w)
{
	double group_limit = NAN;

	if (gr != NULL && group_score) {
		if ((*group_score + w) >= 0 && !isnan(gr->max_score) && gr->max_score > 0) {
			group_limit = gr->max_score;
		}
		else if ((*group_score + w) < 0 && !isnan(gr->min_score) && gr->min_score < 0) {
			group_limit = -gr->min_score;
		}
	}

	if (gr != NULL && group_limit && !isnan(group_limit)) {
		if (fabs(*group_score) >= group_limit && signbit(*group_score) == signbit(w)) {
			/* Cannot add more to the group */
			msg_info_task("maximum group score %.2f for group %s has been reached,"
						  " ignoring symbol %s with weight %.2f",
						  group_limit,
						  gr->name, symbol, w);
			return NAN;
		}
		else if (fabs(*group_score + w) > group_limit) {
			/* Reduce weight */
			double new_w = signbit(w) ? -group_limit - *group_score : group_limit - *group_score;
			msg_info_task("maximum group score %.2f for group %s has been reached,"
						  " reduce weight of symbol %s from %.2f to %.2f",
						  group_limit,
						  gr->name, symbol, w, new_w);
			w = new_w;
		}
	}

	return w;
}

#ifndef DBL_EPSILON
#define DBL_EPSILON 2.2204460492503131e-16
#endif

static struct rspamd_symbol_result *
insert_metric_result(struct rspamd_task *task,
					 const char *symbol,
					 double weight,
					 const char *opt,
					 struct rspamd_scan_result *metric_res,
					 enum rspamd_symbol_insert_flags flags,
					 bool *new_sym)
{
	struct rspamd_symbol_result *symbol_result = NULL;
	double final_score, *gr_score = NULL, diff;
	struct rspamd_symbol *sdef;
	struct rspamd_symbols_group *gr = NULL;
	const ucl_object_t *mobj, *sobj;
	int max_shots = G_MAXINT, ret;
	unsigned int i;
	khiter_t k;
	gboolean single = !!(flags & RSPAMD_SYMBOL_INSERT_SINGLE);
	char *sym_cpy;

	if (!isfinite(weight)) {
		msg_warn_task("detected %s score for symbol %s, replace it with zero",
					  isnan(weight) ? "NaN" : "infinity", symbol);
		weight = 0.0;
	}

	msg_debug_metric("want to insert symbol %s, initial weight %.2f",
					 symbol, weight);

	sdef = g_hash_table_lookup(task->cfg->symbols, symbol);
	if (sdef == NULL) {
		if (flags & RSPAMD_SYMBOL_INSERT_ENFORCE) {
			final_score = 1.0 * weight; /* Enforce static weight to 1.0 */
		}
		else {
			final_score = 0.0;
		}

		msg_debug_metric("no symbol definition for %s; final multiplier %.2f",
						 symbol, final_score);
	}
	else {
		if (sdef->cache_item) {
			/* Check if we can insert this symbol at all */
			if (!rspamd_symcache_is_item_allowed(task, sdef->cache_item, FALSE)) {
				msg_debug_metric("symbol %s is not allowed to be inserted due to settings",
								 symbol);
				return NULL;
			}
		}

		final_score = (*sdef->weight_ptr) * weight;

		PTR_ARRAY_FOREACH(sdef->groups, i, gr)
		{
			k = kh_get(rspamd_symbols_group_hash, metric_res->sym_groups, gr);

			if (k == kh_end(metric_res->sym_groups)) {
				k = kh_put(rspamd_symbols_group_hash, metric_res->sym_groups,
						   gr, &ret);
				kh_value(metric_res->sym_groups, k) = 0;
			}
		}

		msg_debug_metric("metric multiplier for %s is %.2f",
						 symbol, *sdef->weight_ptr);
	}

	if (task->settings) {
		double corr;
		mobj = ucl_object_lookup(task->settings, "scores");

		if (!mobj) {
			/* Legacy */
			mobj = task->settings;
		}
		else {
			msg_debug_metric("found scores in the settings");
		}

		sobj = ucl_object_lookup(mobj, symbol);
		if (sobj != NULL && ucl_object_todouble_safe(sobj, &corr)) {
			msg_debug_metric("settings: changed weight of symbol %s from %.2f "
							 "to %.2f * %.2f",
							 symbol, final_score, corr, weight);
			final_score = corr * weight;
		}
	}

	k = kh_get(rspamd_symbols_hash, metric_res->symbols, symbol);
	if (k != kh_end(metric_res->symbols)) {
		/* Existing metric score */
		symbol_result = kh_value(metric_res->symbols, k);
		if (single) {
			max_shots = 1;
		}
		else {
			if (sdef) {
				if (sdef->groups) {
					PTR_ARRAY_FOREACH(sdef->groups, i, gr)
					{
						if (gr->flags & RSPAMD_SYMBOL_GROUP_ONE_SHOT) {
							max_shots = 1;
						}
					}
				}

				max_shots = MIN(max_shots, sdef->nshots);
			}
			else {
				max_shots = task->cfg->default_max_shots;
			}
		}

		msg_debug_metric("nshots: %d for symbol %s", max_shots, symbol);

		if (!single && (max_shots > 0 && (symbol_result->nshots >= max_shots))) {
			single = TRUE;
		}

		symbol_result->nshots++;

		if (opt) {
			rspamd_task_add_result_option(task, symbol_result, opt, strlen(opt));
		}

		/* Adjust diff */
		if (!single) {
			diff = final_score;
			msg_debug_metric("symbol %s can be inserted multiple times: %.2f weight",
							 symbol, diff);
		}
		else {
			if (fabs(symbol_result->score) < fabs(final_score) &&
				signbit(symbol_result->score) == signbit(final_score)) {
				/* Replace less significant weight with a more significant one */
				diff = final_score - symbol_result->score;
				msg_debug_metric("symbol %s can be inserted single time;"
								 " weight adjusted %.2f + %.2f",
								 symbol, symbol_result->score, diff);
			}
			else {
				diff = 0;
			}
		}

		if (diff) {

			if (sdef) {
				PTR_ARRAY_FOREACH(sdef->groups, i, gr)
				{
					double cur_diff;

					k = kh_get(rspamd_symbols_group_hash,
							   metric_res->sym_groups, gr);
					g_assert(k != kh_end(metric_res->sym_groups));
					gr_score = &kh_value(metric_res->sym_groups, k);
					cur_diff = rspamd_check_group_score(task, symbol, gr,
														gr_score, diff);

					if (isnan(cur_diff)) {
						/* Limit reached, do not add result */
						msg_debug_metric(
							"group limit %.2f is reached for %s when inserting symbol %s;"
							" drop score %.2f",
							*gr_score, gr->name, symbol, diff);

						diff = NAN;
						break;
					}
					else if (gr_score) {
						*gr_score += cur_diff;
						diff = cur_diff;
					}
				}
			}

			if (!isnan(diff)) {
				metric_res->score += diff;
				if (single) {
					msg_debug_metric("final score for single symbol %s = %.2f; %.2f diff",
									 symbol, final_score, diff);
					symbol_result->score = final_score;
				}
				else {
					msg_debug_metric("increase final score for multiple symbol %s += %.2f = %.2f",
									 symbol, symbol_result->score, diff);
					symbol_result->score += diff;
				}
			}
		}
	}
	else {
		/* New result */
		if (new_sym) {
			*new_sym = true;
		}

		sym_cpy = rspamd_mempool_strdup(task->task_pool, symbol);
		k = kh_put(rspamd_symbols_hash, metric_res->symbols,
				   sym_cpy, &ret);
		g_assert(ret > 0);
		symbol_result = rspamd_mempool_alloc0(task->task_pool, sizeof(*symbol_result));
		kh_value(metric_res->symbols, k) = symbol_result;

		symbol_result->name = sym_cpy;
		symbol_result->sym = sdef;
		symbol_result->nshots = 1;

		if (sdef) {
			/* Check group limits */
			PTR_ARRAY_FOREACH(sdef->groups, i, gr)
			{
				double cur_score;

				k = kh_get(rspamd_symbols_group_hash, metric_res->sym_groups, gr);
				g_assert(k != kh_end(metric_res->sym_groups));
				gr_score = &kh_value(metric_res->sym_groups, k);
				cur_score = rspamd_check_group_score(task, symbol, gr,
													 gr_score, final_score);

				if (isnan(cur_score)) {
					/* Limit reached, do not add result */
					msg_debug_metric(
						"group limit %.2f is reached for %s when inserting symbol %s;"
						" drop score %.2f",
						*gr_score, gr->name, symbol, final_score);
					final_score = NAN;
					break;
				}
				else if (gr_score) {
					*gr_score += cur_score;
					final_score = cur_score;
				}
			}
		}

		if (!isnan(final_score)) {
			const double epsilon = DBL_EPSILON;

			metric_res->score += final_score;
			symbol_result->score = final_score;

			if (final_score > epsilon) {
				metric_res->npositive++;
				metric_res->positive_score += final_score;
			}
			else if (final_score < -epsilon) {
				metric_res->nnegative++;
				metric_res->negative_score += fabs(final_score);
			}
		}
		else {
			symbol_result->score = 0;
		}

		if (opt) {
			rspamd_task_add_result_option(task, symbol_result, opt, strlen(opt));
		}
	}

	msg_debug_metric("final insertion for symbol %s, score %.2f, factor: %f",
					 symbol,
					 symbol_result->score,
					 final_score);
	metric_res->nresults++;

	return symbol_result;
}

struct rspamd_symbol_result *
rspamd_task_insert_result_full(struct rspamd_task *task,
							   const char *symbol,
							   double weight,
							   const char *opt,
							   enum rspamd_symbol_insert_flags flags,
							   struct rspamd_scan_result *result)
{
	struct rspamd_symbol_result *symbol_result = NULL, *ret = NULL;
	struct rspamd_scan_result *mres;

	/*
	 * We allow symbols to be inserted for skipped tasks, as it might be a
	 * race condition before some symbol is finished and skip flag being set.
	 */
	if (!RSPAMD_TASK_IS_SKIPPED(task) && (task->processed_stages & (RSPAMD_TASK_STAGE_IDEMPOTENT >> 1))) {
		msg_err_task("cannot insert symbol %s on idempotent phase",
					 symbol);

		return NULL;
	}

	if (result == NULL) {
		/* Insert everywhere */
		DL_FOREACH(task->result, mres)
		{
			if (mres->symbol_cbref != -1) {
				/* Check if we can insert this symbol to this symbol result */
				GError *err = NULL;
				lua_State *L = (lua_State *) task->cfg->lua_state;

				if (!rspamd_lua_universal_pcall(L, mres->symbol_cbref,
												G_STRLOC, 1, "uss", &err,
												rspamd_task_classname, task, symbol, mres->name ? mres->name : "default")) {
					msg_warn_task("cannot call for symbol_cbref for result %s: %e",
								  mres->name ? mres->name : "default", err);
					g_error_free(err);

					continue;
				}
				else {
					if (!lua_toboolean(L, -1)) {
						/* Skip symbol */
						msg_debug_metric("skip symbol %s for result %s due to Lua return value",
										 symbol, mres->name);
						lua_pop(L, 1); /* Remove result */

						continue;
					}

					lua_pop(L, 1); /* Remove result */
				}
			}

			bool new_symbol = false;

			symbol_result = insert_metric_result(task,
												 symbol,
												 weight,
												 opt,
												 mres,
												 flags,
												 &new_symbol);

			if (mres->name == NULL) {
				/* Default result */
				ret = symbol_result;

				/* Process cache item */
				if (symbol_result && task->cfg->cache && symbol_result->sym && symbol_result->nshots == 1) {
					rspamd_symcache_inc_frequency(task->cfg->cache,
												  symbol_result->sym->cache_item,
												  symbol_result->sym->name);
				}
			}
			else if (new_symbol) {
				/* O(N) but we normally don't have any shadow results */
				LL_APPEND(ret, symbol_result);
			}
		}
	}
	else {
		/* Specific insertion */
		symbol_result = insert_metric_result(task,
											 symbol,
											 weight,
											 opt,
											 result,
											 flags,
											 NULL);
		ret = symbol_result;

		if (result->name == NULL) {
			/* Process cache item */
			if (symbol_result && task->cfg->cache && symbol_result->sym && symbol_result->nshots == 1) {
				rspamd_symcache_inc_frequency(task->cfg->cache,
											  symbol_result->sym->cache_item,
											  symbol_result->sym->name);
			}
		}
	}

	return ret;
}

static char *
rspamd_task_option_safe_copy(struct rspamd_task *task,
							 const char *val,
							 gsize vlen,
							 gsize *outlen)
{
	const char *p, *end;

	p = val;
	end = val + vlen;
	vlen = 0; /* Reuse */

	while (p < end) {
		if (*p & 0x80) {
			UChar32 uc;
			int off = 0;

			U8_NEXT(p, off, end - p, uc);

			if (uc > 0) {
				if (u_isprint(uc)) {
					vlen += off;
				}
				else {
					/* We will replace it with 0xFFFD */
					vlen += MAX(off, 3);
				}
			}
			else {
				vlen += MAX(off, 3);
			}

			p += off;
		}
		else if (!g_ascii_isprint(*p)) {
			/* Another 0xFFFD */
			vlen += 3;
			p++;
		}
		else {
			p++;
			vlen++;
		}
	}

	char *dest, *d;

	dest = rspamd_mempool_alloc(task->task_pool, vlen + 1);
	d = dest;
	p = val;

	while (p < end) {
		if (*p & 0x80) {
			UChar32 uc;
			int off = 0;

			U8_NEXT(p, off, end - p, uc);

			if (uc > 0) {
				if (u_isprint(uc)) {
					memcpy(d, p, off);
					d += off;
				}
				else {
					/* We will replace it with 0xFFFD */
					*d++ = '\357';
					*d++ = '\277';
					*d++ = '\275';
				}
			}
			else {
				*d++ = '\357';
				*d++ = '\277';
				*d++ = '\275';
			}

			p += off;
		}
		else if (!g_ascii_isprint(*p)) {
			/* Another 0xFFFD */
			*d++ = '\357';
			*d++ = '\277';
			*d++ = '\275';
			p++;
		}
		else {
			*d++ = *p++;
		}
	}

	*d = '\0';
	*(outlen) = d - dest;

	return dest;
}

gboolean
rspamd_task_add_result_option(struct rspamd_task *task,
							  struct rspamd_symbol_result *s,
							  const char *val,
							  gsize vlen)
{
	struct rspamd_symbol_option *opt, srch;
	gboolean ret = FALSE;
	char *opt_cpy = NULL;
	gsize cpy_len;
	khiter_t k;
	int r;
	struct rspamd_symbol_result *cur;

	if (s && val) {
		/*
		 * Here we assume that this function is all the time called with the
		 * symbol from the default result, not some shadow result, or
		 * the option insertion will be wrong
		 */
		LL_FOREACH(s, cur)
		{
			if (cur->opts_len < 0) {
				/* Cannot add more options, give up */
				msg_debug_task("cannot add more options to symbol %s when adding option %s",
							   cur->name, val);
				ret = FALSE;
				continue;
			}

			if (!cur->options) {
				cur->options = kh_init(rspamd_options_hash);
			}

			if (vlen + cur->opts_len > task->cfg->max_opts_len) {
				/* Add truncated option */
				msg_info_task("cannot add more options to symbol %s when adding option %s",
							  cur->name, val);
				val = "...";
				vlen = 3;
				cur->opts_len = -1;
			}

			if (!(cur->sym && (cur->sym->flags & RSPAMD_SYMBOL_FLAG_ONEPARAM))) {

				srch.option = (char *) val;
				srch.optlen = vlen;
				k = kh_get(rspamd_options_hash, cur->options, &srch);

				if (k == kh_end(cur->options)) {
					opt_cpy = rspamd_task_option_safe_copy(task, val, vlen, &cpy_len);
					if (cpy_len != vlen) {
						srch.option = (char *) opt_cpy;
						srch.optlen = cpy_len;
						k = kh_get(rspamd_options_hash, cur->options, &srch);
					}
					/* Append new options */
					if (k == kh_end(cur->options)) {
						opt = rspamd_mempool_alloc0(task->task_pool, sizeof(*opt));
						opt->optlen = cpy_len;
						opt->option = opt_cpy;

						kh_put(rspamd_options_hash, cur->options, opt, &r);
						DL_APPEND(cur->opts_head, opt);

						if (s == cur) {
							ret = TRUE;
						}
					}
				}
			}
			else {
				/* Skip addition */
				if (s == cur) {
					ret = FALSE;
				}
			}

			if (ret && cur->opts_len >= 0) {
				cur->opts_len += vlen;
			}
		}
	}
	else if (!val) {
		ret = TRUE;
	}

	task->result->nresults++;

	return ret;
}

struct rspamd_action_config *
rspamd_find_action_config_for_action(struct rspamd_scan_result *scan_result,
									 struct rspamd_action *act)
{
	for (unsigned int i = 0; i < scan_result->nactions; i++) {
		struct rspamd_action_config *cur = &scan_result->actions_config[i];

		if (act == cur->action) {
			return cur;
		}
	}

	return NULL;
}

struct rspamd_action *
rspamd_check_action_metric(struct rspamd_task *task,
						   struct rspamd_passthrough_result **ppr,
						   struct rspamd_scan_result *scan_result)
{
	struct rspamd_action_config *action_lim,
		*noaction = NULL;
	struct rspamd_action *selected_action = NULL, *least_action = NULL;
	struct rspamd_passthrough_result *pr, *sel_pr = NULL;
	double max_score = -(G_MAXDOUBLE), sc;
	gboolean seen_least = FALSE;

	if (scan_result == NULL) {
		scan_result = task->result;
	}

	if (scan_result->passthrough_result != NULL) {
		DL_FOREACH(scan_result->passthrough_result, pr)
		{
			struct rspamd_action_config *act_config =
				rspamd_find_action_config_for_action(scan_result, pr->action);

			/* Skip disabled actions */
			if (act_config && (act_config->flags & RSPAMD_ACTION_RESULT_DISABLED)) {
				continue;
			}

			if (!seen_least || !(pr->flags & RSPAMD_PASSTHROUGH_LEAST)) {
				sc = pr->target_score;
				selected_action = pr->action;

				if (!(pr->flags & RSPAMD_PASSTHROUGH_LEAST)) {
					if (!isnan(sc)) {
						if (pr->action->action_type == METRIC_ACTION_NOACTION) {
							scan_result->score = MIN(sc, scan_result->score);
						}
						else {
							scan_result->score = sc;
						}
					}

					if (ppr) {
						*ppr = pr;
					}

					return selected_action;
				}
				else {
					seen_least = true;
					least_action = selected_action;

					if (isnan(sc)) {

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
							sel_pr = pr;
						}
					}
					else {
						max_score = sc;
						sel_pr = pr;
					}
				}
			}
		}
	}

	/*
	 * Select result by score
	 */
	for (size_t i = scan_result->nactions - 1; i != (size_t) -1; i--) {
		action_lim = &scan_result->actions_config[i];
		sc = action_lim->cur_limit;

		if (action_lim->action->action_type == METRIC_ACTION_NOACTION) {
			noaction = action_lim;
		}

		if ((action_lim->flags & (RSPAMD_ACTION_RESULT_DISABLED | RSPAMD_ACTION_RESULT_NO_THRESHOLD))) {
			continue;
		}

		if (isnan(sc) ||
			(action_lim->action->flags & (RSPAMD_ACTION_NO_THRESHOLD | RSPAMD_ACTION_HAM))) {
			continue;
		}

		if (scan_result->score >= sc && sc > max_score) {
			selected_action = action_lim->action;
			max_score = sc;
		}
	}

	if (selected_action == NULL) {
		selected_action = noaction->action;
	}

	if (selected_action) {

		if (seen_least) {
			/* Adjust least action */
			if (least_action->flags & RSPAMD_ACTION_NO_THRESHOLD) {
				if (selected_action->action_type != METRIC_ACTION_REJECT &&
					selected_action->action_type != METRIC_ACTION_DISCARD) {
					/* Override score based action with least action */
					selected_action = least_action;

					if (ppr) {
						*ppr = sel_pr;
					}
				}
			}
			else {
				/* Adjust score if needed */
				if (max_score > scan_result->score) {
					if (ppr) {
						*ppr = sel_pr;
					}

					scan_result->score = max_score;
				}
			}
		}

		return selected_action;
	}

	if (ppr) {
		*ppr = sel_pr;
	}

	return noaction->action;
}

struct rspamd_symbol_result *
rspamd_task_find_symbol_result(struct rspamd_task *task, const char *sym,
							   struct rspamd_scan_result *result)
{
	struct rspamd_symbol_result *res = NULL;
	khiter_t k;

	if (result == NULL) {
		/* Use default result */
		result = task->result;
	}

	k = kh_get(rspamd_symbols_hash, result->symbols, sym);

	if (k != kh_end(result->symbols)) {
		res = kh_value(result->symbols, k);
	}

	return res;
}

struct rspamd_symbol_result *rspamd_task_remove_symbol_result(
	struct rspamd_task *task,
	const char *symbol,
	struct rspamd_scan_result *result)
{
	struct rspamd_symbol_result *res = NULL;
	khiter_t k;

	if (result == NULL) {
		/* Use default result */
		result = task->result;
	}

	k = kh_get(rspamd_symbols_hash, result->symbols, symbol);

	if (k != kh_end(result->symbols)) {
		res = kh_value(result->symbols, k);

		if (!isnan(res->score)) {
			/* Remove score from the result */
			result->score -= res->score;

			/* Also check the group limit */
			if (result->sym_groups && res->sym) {
				struct rspamd_symbol_group *gr;
				int i;
				khiter_t k_groups;

				PTR_ARRAY_FOREACH(res->sym->groups, i, gr)
				{
					double *gr_score;

					k_groups = kh_get(rspamd_symbols_group_hash,
									  result->sym_groups, gr);

					if (k_groups != kh_end(result->sym_groups)) {
						gr_score = &kh_value(result->sym_groups, k_groups);

						if (gr_score) {
							*gr_score -= res->score;
						}
					}
				}
			}
		}

		kh_del(rspamd_symbols_hash, result->symbols, k);
	}
	else {
		return NULL;
	}

	return res;
}

void rspamd_task_symbol_result_foreach(struct rspamd_task *task,
									   struct rspamd_scan_result *result, GHFunc func,
									   gpointer ud)
{
	const char *kk;
	struct rspamd_symbol_result *res;

	if (result == NULL) {
		/* Use default result */
		result = task->result;
	}

	if (func) {
		kh_foreach(result->symbols, kk, res, {
			func((gpointer) kk, (gpointer) res, ud);
		});
	}
}

struct rspamd_scan_result *
rspamd_find_metric_result(struct rspamd_task *task,
						  const char *name)
{
	struct rspamd_scan_result *res;

	if (name == NULL || strcmp(name, "default") == 0) {
		return task->result;
	}

	DL_FOREACH(task->result, res)
	{
		if (res->name && strcmp(res->name, name) == 0) {
			return res;
		}
	}

	return NULL;
}

void rspamd_task_result_adjust_grow_factor(struct rspamd_task *task,
										   struct rspamd_scan_result *result,
										   double grow_factor)
{
	const char *kk;
	struct rspamd_symbol_result *res;
	double final_grow_factor = grow_factor;
	double max_limit = G_MINDOUBLE;

	if (grow_factor > 1.0) {

		for (unsigned int i = 0; i < result->nactions; i++) {
			struct rspamd_action_config *cur = &result->actions_config[i];

			if (cur->cur_limit > 0 && max_limit < cur->cur_limit) {
				max_limit = cur->cur_limit;
			}
		}

		/* Adjust factor by selecting all symbols and checking those with positive scores */
		kh_foreach(result->symbols, kk, res, {
			if (res->score > 0) {
				double mult = grow_factor - 1.0;
				/* We adjust the factor by the ratio of the score to the max limit */
				if (max_limit > 0 && !isnan(res->score)) {
					mult *= res->score / max_limit;
					final_grow_factor *= 1.0 + mult;
				}
			}
		});

		/* At this stage we know that we have some grow factor to apply */
		if (final_grow_factor > 1.0) {
			msg_info_task("calculated final grow factor for task: %.3f (%.2f the original one)",
						  final_grow_factor, grow_factor);
			kh_foreach(result->symbols, kk, res, {
				if (res->score > 0) {
					result->score -= res->score;
					res->score *= final_grow_factor;
					result->score += res->score;
				}
			});
		}
	}
}
