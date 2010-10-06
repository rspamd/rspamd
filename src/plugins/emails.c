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

/***MODULE:email
 * rspamd module that extracts emails from messages and check them via blacklist
 * 
 * Allowed options:
 * - symbol (string): symbol to insert (default: 'R_BAD_EMAIL')
 * - blacklist (map string): map that contains list of bad emails
 */

#include "../config.h"
#include "../main.h"
#include "../message.h"
#include "../modules.h"
#include "../cfg_file.h"
#include "../expressions.h"
#include "../util.h"
#include "../view.h"
#include "../map.h"

#define DEFAULT_SYMBOL "R_BAD_EMAIL"

static const gchar              *email_re_text =
	"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+(?:[A-Z]{2}|com|org|net|gov|mil|biz|info|mobi|name|aero|jobs|museum)\\b";

struct email_ctx {
	gint                            (*filter) (struct worker_task * task);
	gchar                           *symbol;
	GRegex                         *email_re;

	GHashTable                     *blacklist;
	gchar                           *blacklist_file;

	memory_pool_t                  *email_pool;
};

static struct email_ctx        *email_module_ctx = NULL;

static gint                      emails_mime_filter (struct worker_task *task);
static void                     emails_symbol_callback (struct worker_task *task, void *unused);
static gint                      emails_command_handler (struct worker_task *task);

gint
emails_module_init (struct config_file *cfg, struct module_ctx **ctx)
{
	GError                         *err = NULL;

	email_module_ctx = g_malloc (sizeof (struct email_ctx));

	email_module_ctx->filter = emails_mime_filter;
	email_module_ctx->email_pool = memory_pool_new (memory_pool_get_size ());
	email_module_ctx->email_re = g_regex_new (email_re_text, G_REGEX_RAW | G_REGEX_OPTIMIZE | G_REGEX_CASELESS, 0, &err);
	email_module_ctx->blacklist = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);

	*ctx = (struct module_ctx *)email_module_ctx;

	register_protocol_command ("emails", emails_command_handler);

	return 0;
}


gint
emails_module_config (struct config_file *cfg)
{
	gchar                           *value;
	gint                            res = TRUE;

	if ((value = get_module_opt (cfg, "emails", "symbol")) != NULL) {
		email_module_ctx->symbol = memory_pool_strdup (email_module_ctx->email_pool, value);
	}
	else {
		email_module_ctx->symbol = DEFAULT_SYMBOL;
	}
	if ((value = get_module_opt (cfg, "emails", "blacklist")) != NULL) {
		if (add_map (value, read_host_list, fin_host_list, (void **)&email_module_ctx->blacklist)) {
			email_module_ctx->blacklist_file = memory_pool_strdup (email_module_ctx->email_pool, value + sizeof ("file://") - 1);
		}
	}


	register_symbol (&cfg->cache, email_module_ctx->symbol, 1, emails_symbol_callback, NULL);

	return res;
}

gint
emails_module_reconfig (struct config_file *cfg)
{
	memory_pool_delete (email_module_ctx->email_pool);
	email_module_ctx->email_pool = memory_pool_new (memory_pool_get_size ());

	return emails_module_config (cfg);
}

static GList                   *
extract_emails (struct worker_task *task)
{
	GList                          *res = NULL, *cur;
	GMatchInfo                     *info;
	GError                         *err = NULL;
	struct mime_text_part          *part;
	gchar                           *email_str;
	gint                            rc;

	cur = g_list_first (task->text_parts);
	while (cur) {
		part = cur->data;

		if (part->is_empty) {
			cur = g_list_next (cur);
			continue;
		}

		rc = g_regex_match_full (email_module_ctx->email_re, (const gchar *)part->orig->data, part->orig->len, 0, 0, &info, &err);
		if (rc) {
			while (g_match_info_matches (info)) {
				email_str = g_match_info_fetch (info, 0);
				if (email_str != NULL) {
					res = g_list_prepend (res, email_str);
					memory_pool_add_destructor (task->task_pool, (pool_destruct_func) g_free, email_str);
				}
				/* Get next match */
				g_match_info_next (info, &err);
			}
		}
		else if (err != NULL) {
			debug_task ("error matching regexp: %s", err->message);
		}
		else {
			debug_task ("cannot find url pattern in given string");
		}
		g_match_info_free (info);

		cur = g_list_next (cur);
	}
	if (res != NULL) {
		memory_pool_add_destructor (task->task_pool, (pool_destruct_func) g_list_free, res);
	}

	return res;
}

static gint
emails_command_handler (struct worker_task *task)
{
	GList                          *emails, *cur;
	gchar                           outbuf[BUFSIZ];
	gint                            r, num = 0;

	emails = extract_emails (task);

	r = snprintf (outbuf, sizeof (outbuf), "%s 0 %s" CRLF, (task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER, "OK");

	r += snprintf (outbuf + r, sizeof (outbuf) - r - 2, "Emails: ");

	cur = g_list_first (emails);

	while (cur) {
		num++;
		if (g_list_next (cur) != NULL) {
			r += snprintf (outbuf + r, sizeof (outbuf) - r - 2, "%s, ", (gchar *)cur->data);
		}
		else {
			r += snprintf (outbuf + r, sizeof (outbuf) - r - 2, "%s", (gchar *)cur->data);
		}
		cur = g_list_next (cur);
	}

	outbuf[r++] = '\r';
	outbuf[r++] = '\n';

	if (! rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE, FALSE)) {
		return -1;
	}
	msg_info ("msg ok, id: <%s>, %d emails extracted", task->message_id, num);

	return 0;
}

static void
emails_symbol_callback (struct worker_task *task, void *unused)
{
	GList                          *emails, *cur;


	if (check_view (task->cfg->views, email_module_ctx->symbol, task)) {
		emails = extract_emails (task);
		if (email_module_ctx->blacklist && emails) {
			cur = g_list_first (emails);

			while (cur) {
				if (g_hash_table_lookup (email_module_ctx->blacklist, cur->data) != NULL) {
					insert_result (task, email_module_ctx->symbol, 1, g_list_prepend (NULL, memory_pool_strdup (task->task_pool, (gchar *)cur->data)));

				}
				cur = g_list_next (cur);
			}
		}
	}

}

static gint
emails_mime_filter (struct worker_task *task)
{
	/* XXX: remove this */
	return 0;
}
