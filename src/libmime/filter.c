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
		rspamd_symbols_cache_inc_frequency (task->cfg->cache, symbol);
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
