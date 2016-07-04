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
#define DEFAULT_THRESHOLD 0.1

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
	double threshold;

	rspamd_mempool_t *chartable_pool;
};

static struct chartable_ctx *chartable_module_ctx = NULL;
static void chartable_symbol_callback (struct rspamd_task *task, void *unused);

gint
chartable_module_init (struct rspamd_config *cfg, struct module_ctx **ctx)
{
	chartable_module_ctx = g_malloc (sizeof (struct chartable_ctx));

	chartable_module_ctx->chartable_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL);

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
		rspamd_config_get_module_opt (cfg, "chartable", "threshold")) != NULL) {
		if (!ucl_obj_todouble_safe (value, &chartable_module_ctx->threshold)) {
			msg_warn_config ("invalid numeric value");
			chartable_module_ctx->threshold = DEFAULT_THRESHOLD;
		}
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

static gboolean
check_part (struct rspamd_mime_text_part *part, gboolean raw_mode)
{
	guchar *p, *p1;
	gunichar c, t;
	GUnicodeScript scc, sct;
	guint32 mark = 0, total = 0, max = 0, i;
	guint32 remain = part->content->len;
	guint32 scripts[G_UNICODE_SCRIPT_NKO];
	GUnicodeScript sel = 0;

	p = part->content->data;

	if (IS_PART_UTF (part) || raw_mode) {
		while (remain > 1) {
			if ((g_ascii_isalpha (*p) &&
				(*(p + 1) & 0x80)) ||
				((*p & 0x80) && g_ascii_isalpha (*(p + 1)))) {
				mark++;
				total++;
			}
			/* Current and next symbols are of one class */
			else if (((*p & 0x80) &&
				(*(p + 1) & 0x80)) ||
				(g_ascii_isalpha (*p) && g_ascii_isalpha (*(p + 1)))) {
				total++;
			}
			p++;
			remain--;
		}
	}
	else {
		memset (&scripts, 0, sizeof (scripts));
		while (remain > 0) {
			c = g_utf8_get_char_validated (p, remain);
			if (c == (gunichar) - 2 || c == (gunichar) - 1) {
				/* Invalid characters detected, stop processing */
				return FALSE;
			}

			scc = g_unichar_get_script (c);
			if (scc < (gint)G_N_ELEMENTS (scripts)) {
				scripts[scc]++;
			}
			p1 = g_utf8_next_char (p);
			remain -= p1 - p;
			p = p1;

			if (remain > 0) {
				t = g_utf8_get_char_validated (p, remain);
				if (t == (gunichar) - 2 || t == (gunichar) - 1) {
					/* Invalid characters detected, stop processing */
					return FALSE;
				}
				sct = g_unichar_get_script (t);
				if (g_unichar_isalpha (c) && g_unichar_isalpha (t)) {
					/* We have two unicode alphanumeric characters, so we can check its script */
					if (sct != scc) {
						mark++;
					}
					total++;
				}
				p1 = g_utf8_next_char (p);
				remain -= p1 - p;
				p = p1;
			}
		}
		/* Detect the mostly charset of this part */
		for (i = 0; i < G_N_ELEMENTS (scripts); i++) {
			if (scripts[i] > max) {
				max = scripts[i];
				sel = i;
			}
		}
		part->script = sel;
	}

	if (total == 0) {
		return 0;
	}

	return ((double)mark / (double)total) > chartable_module_ctx->threshold;
}

static void
chartable_symbol_callback (struct rspamd_task *task, void *unused)
{
	guint i;
	struct rspamd_mime_text_part *part;

	for (i = 0; i < task->text_parts->len; i ++) {
		part = g_ptr_array_index (task->text_parts, i);

		if (!IS_PART_EMPTY (part) && check_part (part, task->cfg->raw_mode)) {
			rspamd_task_insert_result (task, chartable_module_ctx->symbol, 1, NULL);
		}
	}

}
