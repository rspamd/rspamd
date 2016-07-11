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
/***MODULE:chartable
 * rspamd module that make marks based on symbol chains
 *
 * Allowed options:
 * - symbol (string): symbol to insert (default: 'R_BAD_CHARSET')
 * - threshold (double): value that would be used as threshold in expression characters_changed / total_characters
 *   (e.g. if threshold is 0.1 than charset change should occure more often than in 10 symbols), default: 0.1
 */

#include "config.h"
#include "libmime/message.h"
#include "rspamd.h"

#define DEFAULT_SYMBOL "R_CHARSET_MIXED"
#define DEFAULT_URL_SYMBOL "R_CHARSET_MIXED_URL"
#define DEFAULT_THRESHOLD 0.1

#define msg_err_chartable(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        "chartable", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_chartable(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        "chartable", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_chartable(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "chartable", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_chartable(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
        "chartable", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

/* Initialization */
gint chartable_module_init (struct rspamd_config *cfg, struct module_ctx **ctx);
gint chartable_module_config (struct rspamd_config *cfg);
gint chartable_module_reconfig (struct rspamd_config *cfg);

module_t chartable_module = {
	"chartable",
	chartable_module_init,
	chartable_module_config,
	chartable_module_reconfig,
	NULL,
	RSPAMD_MODULE_VER
};

struct chartable_ctx {
	struct module_ctx ctx;
	const gchar *symbol;
	const gchar *url_symbol;
	double threshold;
	guint max_word_len;

	rspamd_mempool_t *chartable_pool;
};

static struct chartable_ctx *chartable_module_ctx = NULL;
static void chartable_symbol_callback (struct rspamd_task *task, void *unused);
static void chartable_url_symbol_callback (struct rspamd_task *task, void *unused);

gint
chartable_module_init (struct rspamd_config *cfg, struct module_ctx **ctx)
{
	chartable_module_ctx = g_malloc (sizeof (struct chartable_ctx));

	chartable_module_ctx->chartable_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL);
	chartable_module_ctx->max_word_len = 10;

	*ctx = (struct module_ctx *)chartable_module_ctx;

	return 0;
}


gint
chartable_module_config (struct rspamd_config *cfg)
{
	const ucl_object_t *value;
	gint res = TRUE;

	if (!rspamd_config_is_module_enabled (cfg, "chartable")) {
		return TRUE;
	}

	if ((value =
		rspamd_config_get_module_opt (cfg, "chartable", "symbol")) != NULL) {
		chartable_module_ctx->symbol = ucl_obj_tostring (value);
	}
	else {
		chartable_module_ctx->symbol = DEFAULT_SYMBOL;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "chartable", "url_symbol")) != NULL) {
		chartable_module_ctx->url_symbol = ucl_obj_tostring (value);
	}
	else {
		chartable_module_ctx->url_symbol = DEFAULT_URL_SYMBOL;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "chartable", "threshold")) != NULL) {
		if (!ucl_obj_todouble_safe (value, &chartable_module_ctx->threshold)) {
			msg_warn_config ("invalid numeric value");
			chartable_module_ctx->threshold = DEFAULT_THRESHOLD;
		}
	}
	else {
		chartable_module_ctx->threshold = DEFAULT_THRESHOLD;
	}
	if ((value =
			rspamd_config_get_module_opt (cfg, "chartable", "max_word_len")) != NULL) {
		chartable_module_ctx->max_word_len = ucl_object_toint (value);
	}
	else {
		chartable_module_ctx->threshold = DEFAULT_THRESHOLD;
	}

	rspamd_symbols_cache_add_symbol (cfg->cache,
			chartable_module_ctx->symbol,
			0,
			chartable_symbol_callback,
			NULL,
			SYMBOL_TYPE_NORMAL,
			-1);
	rspamd_symbols_cache_add_symbol (cfg->cache,
			chartable_module_ctx->url_symbol,
			0,
			chartable_url_symbol_callback,
			NULL,
			SYMBOL_TYPE_NORMAL,
			-1);

	msg_info_config ("init internal chartable module");

	return res;
}

gint
chartable_module_reconfig (struct rspamd_config *cfg)
{
	rspamd_mempool_delete (chartable_module_ctx->chartable_pool);
	chartable_module_ctx->chartable_pool = rspamd_mempool_new (1024, NULL);

	return chartable_module_config (cfg);
}

static gdouble
rspamd_chartable_process_word_utf (struct rspamd_task *task, rspamd_ftok_t *w,
		gboolean is_url)
{
	const gchar *p, *end, *c;
	gdouble badness = 0.0;
	gunichar uc;
	gint sc, last_sc;
	guint same_script_count = 0, nsym = 0;
	enum {
		start_process = 0,
		got_alpha,
		got_digit,
		got_unknown,
	} state = start_process;

	p = w->begin;
	end = p + w->len;
	c = p;
	last_sc = 0;

	/* We assume that w is normalized */

	while (p < end) {
		uc = g_utf8_get_char (p);

		if (g_unichar_isalpha (uc)) {
			sc = g_unichar_get_script (uc);

			if (state == got_digit) {
				/* Penalize digit -> alpha translations */
				if (!is_url && sc != G_UNICODE_SCRIPT_COMMON &&
						sc != G_UNICODE_SCRIPT_LATIN) {
					badness += 1.0;
				}
			}
			else if (state == got_alpha) {
				/* Check script */
				if (same_script_count > 0) {
					if (sc != last_sc) {
						badness += 1.0 / (gdouble)same_script_count;
						last_sc = sc;
						same_script_count = 1;
					}
					else {
						same_script_count ++;
					}
				}
				else {
					last_sc = sc;
					same_script_count = 1;
				}
			}

			state = got_alpha;

		}
		else if (g_unichar_isdigit (uc)) {
			state = got_digit;
			same_script_count = 0;
		}
		else {
			/* We don't care about unknown characters here */
			state = got_unknown;
			same_script_count = 0;
		}

		nsym ++;
		p = g_utf8_next_char (p);
	}

	/* Try to avoid FP for long words */
	if (nsym > chartable_module_ctx->max_word_len) {
		badness = 0;
	}
	else {
		if (badness > 4.0) {
			badness = 4.0;
		}
	}

	msg_debug_chartable ("word %T, badness: %.2f", w, badness);

	return badness;
}

static gdouble
rspamd_chartable_process_word_ascii (struct rspamd_task *task, rspamd_ftok_t *w,
		gboolean is_url)
{
	const gchar *p, *end, *c;
	gdouble badness = 0.0;
	enum {
		ascii = 1,
		non_ascii
	} sc, last_sc;
	gint same_script_count = 0;
	enum {
		start_process = 0,
		got_alpha,
		got_digit,
		got_unknown,
	} state = start_process;

	p = w->begin;
	end = p + w->len;
	c = p;
	last_sc = 0;

	if (w->len > chartable_module_ctx->max_word_len) {
		return 0.0;
	}

	/* We assume that w is normalized */
	while (p < end) {
		if (g_ascii_isalpha (*p) || *p > 0x7f) {

			if (state == got_digit) {
				/* Penalize digit -> alpha translations */
				if (!is_url && !g_ascii_isxdigit (*p)) {
					badness += 1.0;
				}
			}
			else if (state == got_alpha) {
				/* Check script */
				sc = (*p > 0x7f) ? ascii : non_ascii;

				if (same_script_count > 0) {
					if (sc != last_sc) {
						badness += 1.0 / (gdouble)same_script_count;
						last_sc = sc;
						same_script_count = 1;
					}
					else {
						same_script_count ++;
					}
				}
				else {
					last_sc = sc;
					same_script_count = 1;
				}
			}

			state = got_alpha;

		}
		else if (g_ascii_isdigit (*p)) {
			state = got_digit;
			same_script_count = 0;
		}
		else {
			/* We don't care about unknown characters here */
			state = got_unknown;
			same_script_count = 0;
		}

		p ++;
	}

	if (badness > 4.0) {
		badness = 4.0;
	}

	msg_debug_chartable ("word %T, badness: %.2f", w, badness);

	return badness;
}

static void
rspamd_chartable_process_part (struct rspamd_task *task,
		struct rspamd_mime_text_part *part)
{
	rspamd_ftok_t *w;
	guint i;
	gdouble cur_score = 0.0;

	if (part == NULL || part->normalized_words == NULL ||
			part->normalized_words->len == 0) {
		return;
	}

	for (i = 0; i < part->normalized_words->len; i++) {
		w = &g_array_index (part->normalized_words, rspamd_ftok_t, i);

		if (w->len > 0) {

			if (IS_PART_UTF (part)) {
				cur_score += rspamd_chartable_process_word_utf (task, w, FALSE);
			}
			else {
				cur_score += rspamd_chartable_process_word_ascii (task, w, FALSE);
			}
		}
	}

	cur_score /= (gdouble)part->normalized_words->len;

	if (cur_score > 2.0) {
		cur_score = 2.0;
	}

	if (cur_score > chartable_module_ctx->threshold) {
		rspamd_task_insert_result (task, chartable_module_ctx->symbol,
				cur_score, NULL);

	}
}

static void
chartable_symbol_callback (struct rspamd_task *task, void *unused)
{
	guint i;
	struct rspamd_mime_text_part *part;

	for (i = 0; i < task->text_parts->len; i ++) {
		part = g_ptr_array_index (task->text_parts, i);
		rspamd_chartable_process_part (task, part);
	}
}

static void
chartable_url_symbol_callback (struct rspamd_task *task, void *unused)
{
	struct rspamd_url *u;
	GHashTableIter it;
	gpointer k, v;
	rspamd_ftok_t w;
	gdouble cur_score = 0.0;

	g_hash_table_iter_init (&it, task->urls);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		u = v;

		if (cur_score > 2.0) {
			cur_score = 2.0;
			break;
		}

		if (u->hostlen > 0) {
			w.begin = u->host;
			w.len = u->hostlen;

			if (g_utf8_validate (w.begin, w.len, NULL)) {
				cur_score += rspamd_chartable_process_word_utf (task, &w, TRUE);
			}
			else {
				cur_score += rspamd_chartable_process_word_ascii (task, &w, TRUE);
			}
		}
	}

	g_hash_table_iter_init (&it, task->emails);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		u = v;

		if (cur_score > 2.0) {
			cur_score = 2.0;
			break;
		}

		if (u->hostlen > 0) {
			w.begin = u->host;
			w.len = u->hostlen;

			if (g_utf8_validate (w.begin, w.len, NULL)) {
				cur_score += rspamd_chartable_process_word_utf (task, &w, TRUE);
			}
			else {
				cur_score += rspamd_chartable_process_word_ascii (task, &w, TRUE);
			}
		}
	}

	if (cur_score > chartable_module_ctx->threshold) {
		rspamd_task_insert_result (task, chartable_module_ctx->symbol,
				cur_score, NULL);

	}
}
