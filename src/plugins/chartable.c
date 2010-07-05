/*
 * Copyright (c) 2009, Rambler media
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
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/***MODULE:chartable
 * rspamd module that make marks based on symbol chains
 *
 * Allowed options:
 * - symbol (string): symbol to insert (default: 'R_BAD_CHARSET')
 * - threshold (double): value that would be used as threshold in expression characters_changed / total_characters
 *   (e.g. if threshold is 0.1 than charset change should occure more often than in 10 symbols), default: 0.1
 */

#include "../config.h"
#include "../main.h"
#include "../message.h"
#include "../modules.h"
#include "../cfg_file.h"
#include "../expressions.h"
#include "../view.h"

#define DEFAULT_SYMBOL "R_CHARSET_MIXED"
#define DEFAULT_THRESHOLD 0.1

struct chartable_ctx {
	int                             (*filter) (struct worker_task * task);
	char                           *symbol;
	double                          threshold;

	memory_pool_t                  *chartable_pool;
};

static struct chartable_ctx    *chartable_module_ctx = NULL;

static int                      chartable_mime_filter (struct worker_task *task);
static void                     chartable_symbol_callback (struct worker_task *task, void *unused);

int
chartable_module_init (struct config_file *cfg, struct module_ctx **ctx)
{
	chartable_module_ctx = g_malloc (sizeof (struct chartable_ctx));

	chartable_module_ctx->filter = chartable_mime_filter;
	chartable_module_ctx->chartable_pool = memory_pool_new (memory_pool_get_size ());

	*ctx = (struct module_ctx *)chartable_module_ctx;

	return 0;
}


int
chartable_module_config (struct config_file *cfg)
{
	char                           *value;
	int                             res = TRUE;

	if ((value = get_module_opt (cfg, "chartable", "symbol")) != NULL) {
		chartable_module_ctx->symbol = memory_pool_strdup (chartable_module_ctx->chartable_pool, value);
	}
	else {
		chartable_module_ctx->symbol = DEFAULT_SYMBOL;
	} 
	if ((value = get_module_opt (cfg, "chartable", "threshold")) != NULL) {
		errno = 0;
		chartable_module_ctx->threshold = strtod (value, NULL);
		if (errno != 0) {
			msg_warn ("invalid numeric value '%s': %s", value, strerror (errno));
			chartable_module_ctx->threshold = DEFAULT_THRESHOLD;
		}
	}
	else {
		chartable_module_ctx->threshold = DEFAULT_THRESHOLD;
	}

	register_symbol (&cfg->cache, chartable_module_ctx->symbol, 1, chartable_symbol_callback, NULL);

	return res;
}

int
chartable_module_reconfig (struct config_file *cfg)
{
	memory_pool_delete (chartable_module_ctx->chartable_pool);
	chartable_module_ctx->chartable_pool = memory_pool_new (1024);

	return chartable_module_config (cfg);
}

static                          gboolean
check_part (struct mime_text_part *part, gboolean raw_mode)
{
	unsigned char                  *p, *p1;
	gunichar                        c, t;
	GUnicodeScript                  scc, sct;
	uint32_t                        mark = 0, total = 0;
	uint32_t                        remain = part->content->len;

	p = part->content->data;

	if (part->is_raw || raw_mode) {
		while (remain > 1) {
			if ((g_ascii_isalpha (*p) && (*(p + 1) & 0x80)) || ((*p & 0x80) && g_ascii_isalpha (*(p + 1)))) {
				mark++;
				total++;
			}
			/* Current and next symbols are of one class */
			else if (((*p & 0x80) && (*(p + 1) & 0x80)) || (g_ascii_isalpha (*p) && g_ascii_isalpha (*(p + 1)))) {
				total++;
			}
			p++;
			remain--;
		}
	}
	else {
		while (remain > 0) {
			c = g_utf8_get_char_validated (p, remain);
			if (c == (gunichar) -2 || c == (gunichar) -1) {
				/* Invalid characters detected, stop processing */
				return FALSE;
			}

			scc = g_unichar_get_script (c);
			p1 = g_utf8_next_char (p);
			remain -= p1 - p;
			p = p1;

			if (remain > 0) {
				t = g_utf8_get_char_validated (p, remain);
				if (t == (gunichar) -2 || t == (gunichar) -1) {
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
	}

	return ((double)mark / (double)total) > chartable_module_ctx->threshold;
}

static void
chartable_symbol_callback (struct worker_task *task, void *unused)
{
	GList                          *cur;
	struct mime_text_part          *part;

	if (check_view (task->cfg->views, chartable_module_ctx->symbol, task)) {
		cur = g_list_first (task->text_parts);
		while (cur) {
			part = cur->data;
			if (!part->is_empty && check_part (part, task->cfg->raw_mode)) {
				insert_result (task, chartable_module_ctx->symbol, 1, NULL);
			}
			cur = g_list_next (cur);
		}
	}

}

static int
chartable_mime_filter (struct worker_task *task)
{
	/* XXX: remove it */
	return 0;
}
