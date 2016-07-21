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
#include "cryptobox.h"
#include <math.h>


#define COMMON_PART_FACTOR 95

struct metric_result *
rspamd_create_metric_result (struct rspamd_task *task, const gchar *name)
{
	struct metric_result *metric_res;
	struct metric *metric;
	guint i;

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
	metric_res->metric = metric;
	metric_res->grow_factor = 0;
	metric_res->score = 0;

	for (i = 0; i < METRIC_ACTION_MAX; i++) {
		metric_res->actions_limits[i] = metric->actions[i].score;
	}

	metric_res->action = METRIC_ACTION_MAX;
	g_hash_table_insert (task->results, (gpointer) metric->name,
			metric_res);

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
		mobj = task->settings;
		gdouble corr;

		sobj = ucl_object_lookup (mobj, symbol);
		if (sobj != NULL && ucl_object_todouble_safe (sobj, &corr)) {
			msg_debug ("settings: changed weight of symbol %s from %.2f to %.2f",
					symbol, w, corr);
			w = corr * flag;
		}
	}

	/* XXX: does not take grow factor into account */
	if (gr != NULL && gr_score != NULL && gr->max_score > 0.0) {
		if (*gr_score >= gr->max_score) {
			msg_info_task ("maximum group score %.2f for group %s has been reached,"
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
		if (sdef && (sdef->flags & RSPAMD_SYMBOL_FLAG_ONESHOT)) {
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
	msg_debug ("symbol %s, score %.2f, metric %s, factor: %f",
		symbol,
		s->score,
		metric->name,
		w);
}

static void
insert_result_common (struct rspamd_task *task,
	const gchar *symbol,
	double flag,
	GList * opts,
	gboolean single)
{
	struct metric *metric;
	GList *cur, *metric_list;

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
		rspamd_symbols_cache_inc_frequency (task->cfg->cache, symbol);
	}

	if (opts != NULL) {
		/* XXX: it is not wise to destroy them here */
		g_list_free (opts);
	}
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

gboolean
rspamd_action_from_str (const gchar *data, gint *result)
{
	guint64 h;

	h = rspamd_cryptobox_fast_hash_specific (RSPAMD_CRYPTOBOX_XXHASH64,
			data, strlen (data), 0xdeadbabe);

	switch (h) {
	case 0x9917BFDB46332B8CULL: /* reject */
		*result = METRIC_ACTION_REJECT;
		break;
	case 0x7130EE37D07B3715ULL: /* greylist */
		*result = METRIC_ACTION_GREYLIST;
		break;
	case 0xCA6087E05480C60CULL: /* add_header */
	case 0x87A3D27783B16241ULL: /* add header */
		*result = METRIC_ACTION_ADD_HEADER;
		break;
	case 0x4963374ED8B90449ULL: /* rewrite_subject */
	case 0x5C9FC4679C025948ULL: /* rewrite subject */
		*result = METRIC_ACTION_REWRITE_SUBJECT;
		break;
	case 0xFC7D6502EE71FDD9ULL: /* soft reject */
	case 0x73576567C262A82DULL: /* soft_reject */
		*result = METRIC_ACTION_SOFT_REJECT;
		break;
	case 0x207091B927D1EC0DULL: /* no action */
	case 0xB7D92D002CD46325ULL: /* no_action */
	case 0x167C0DF4BAA9BCECULL: /* accept */
		*result = METRIC_ACTION_NOACTION;
		break;
	default:
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

const gchar *
rspamd_action_to_str_alt (enum rspamd_metric_action action)
{
	switch (action) {
	case METRIC_ACTION_REJECT:
		return "reject";
	case METRIC_ACTION_SOFT_REJECT:
		return "soft_reject";
	case METRIC_ACTION_REWRITE_SUBJECT:
		return "rewrite_subject";
	case METRIC_ACTION_ADD_HEADER:
		return "add_header";
	case METRIC_ACTION_GREYLIST:
		return "greylist";
	case METRIC_ACTION_NOACTION:
		return "no action";
	case METRIC_ACTION_MAX:
		return "invalid max action";
	}

	return "unknown action";
}

enum rspamd_metric_action
rspamd_check_action_metric (struct rspamd_task *task, struct metric_result *mres)
{
	struct metric_action *action, *selected_action = NULL;
	double max_score = 0, sc;
	int i;

	if (task->pre_result.action == METRIC_ACTION_MAX) {
		for (i = METRIC_ACTION_REJECT; i < METRIC_ACTION_MAX; i++) {
			action = &mres->metric->actions[i];
			sc = mres->actions_limits[i];

			if (isnan (sc)) {
				continue;
			}

			if (mres->score >= sc && sc > max_score) {
				selected_action = action;
				max_score = sc;
			}
		}
	}
	else {
		i = task->pre_result.action;
		selected_action = &mres->metric->actions[i];
		sc = mres->actions_limits[i];

		while (isnan (sc)) {
			i = (i + 1) % METRIC_ACTION_MAX;
			sc = mres->actions_limits[i];

			if (i == task->pre_result.action) {
				/* No scores defined, just avoid NaN */
				sc = 0;
				break;
			}
		}

		mres->score = sc;
	}

	if (selected_action) {
		return selected_action->action;
	}

	return METRIC_ACTION_NOACTION;
}
