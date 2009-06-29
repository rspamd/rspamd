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
 */

#include "../config.h"
#include "../main.h"
#include "../message.h"
#include "../modules.h"
#include "../cfg_file.h"
#include "../expressions.h"
#include "../util.h"
#include "../view.h"

#define DEFAULT_SYMBOL "R_BAD_EMAIL"

static const char *email_re_text = "[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+(?:[A-Z]{2}|com|org|net|gov|mil|biz|info|mobi|name|aero|jobs|museum)\\b";

struct email_ctx {
	int (*header_filter)(struct worker_task *task);
	int (*mime_filter)(struct worker_task *task);
	int (*message_filter)(struct worker_task *task);
	int (*url_filter)(struct worker_task *task);
	char *metric;
	char *symbol;
	GRegex *email_re;

	GHashTable *blacklist;
	char *blacklist_file;

	memory_pool_t *email_pool;
};

static struct email_ctx *email_module_ctx = NULL;

static int emails_mime_filter (struct worker_task *task);
static int emails_command_handler (struct worker_task *task);

int
emails_module_init (struct config_file *cfg, struct module_ctx **ctx)
{
	GError *err = NULL;

	email_module_ctx = g_malloc (sizeof (struct email_ctx));

	email_module_ctx->header_filter = NULL;
	email_module_ctx->mime_filter = emails_mime_filter;
	email_module_ctx->message_filter = NULL;
	email_module_ctx->url_filter = NULL;
	email_module_ctx->email_pool = memory_pool_new (memory_pool_get_size ());
	email_module_ctx->email_re = g_regex_new (email_re_text, G_REGEX_RAW | G_REGEX_OPTIMIZE | G_REGEX_CASELESS, 0, &err);
	email_module_ctx->blacklist = g_hash_table_new (g_str_hash, g_str_equal);
	
	*ctx = (struct module_ctx *)email_module_ctx;
	
	register_protocol_command ("emails", emails_command_handler);

	return 0;
}


int
emails_module_config (struct config_file *cfg)
{
	char *value;
	int res = TRUE;

	if ((value = get_module_opt (cfg, "emails", "metric")) != NULL) {
		email_module_ctx->metric = memory_pool_strdup (email_module_ctx->email_pool, value);
		g_free (value);
	}
	else {
		email_module_ctx->metric = DEFAULT_METRIC;
	}
	if ((value = get_module_opt (cfg, "emails", "symbol")) != NULL) {
		email_module_ctx->symbol = memory_pool_strdup (email_module_ctx->email_pool, value);
		g_free (value);
	}
	else {
		email_module_ctx->symbol = DEFAULT_SYMBOL;
	}
	if ((value = get_module_opt (cfg, "emails", "blacklist")) != NULL) {
		if (g_ascii_strncasecmp (value, "file://", sizeof ("file://") - 1) == 0) {
			if (parse_host_list (email_module_ctx->email_pool, email_module_ctx->blacklist, value + sizeof ("file://") - 1)) {
				email_module_ctx->blacklist_file = memory_pool_strdup (email_module_ctx->email_pool, value + sizeof ("file://") - 1);
			}
		}
	}	
	return res;
}

int
emails_module_reconfig (struct config_file *cfg)
{
	memory_pool_delete (email_module_ctx->email_pool);
	email_module_ctx->email_pool = memory_pool_new (memory_pool_get_size ());

	return emails_module_config (cfg);
}

static GList *
extract_emails (struct worker_task *task)
{
	GList *res = NULL, *cur;
	GMatchInfo *info;
	GError *err = NULL;
	struct mime_text_part *part;
	char *email_str;
	int rc;

	cur = g_list_first (task->text_parts);
	while (cur) {
		part = cur->data;

		rc = g_regex_match_full (email_module_ctx->email_re, (const char *)part->orig->data, part->orig->len, 0, 0, &info, &err);
		if (rc) {
			while (g_match_info_matches (info)) {
				email_str = g_match_info_fetch (info, 0);
				if (email_str != NULL) {
					res = g_list_prepend (res, email_str);
					memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_free, email_str);
				}
				/* Get next match */
				g_match_info_next (info, &err);
			}
		}
		else if (err != NULL) {
			msg_debug ("extract_emails: error matching regexp: %s", err->message);
		}
		else {
			msg_debug ("extract_emails: cannot find url pattern in given string");
		}
		g_match_info_free (info);

		cur = g_list_next (cur);
	}
	if (res != NULL) {
		memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_list_free, res);
	}
	
	return res;
}

static int 
emails_command_handler (struct worker_task *task)
{
	GList *emails, *cur;
	char outbuf[BUFSIZ];
	int r, num = 0;

	emails = extract_emails (task);

	r = snprintf (outbuf, sizeof (outbuf), "%s 0 %s" CRLF, (task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER, "OK");
	
	r += snprintf (outbuf + r, sizeof (outbuf) - r - 2, "Emails: ");
	
	cur = g_list_first (emails);

	while (cur) {
		num ++;
		if (g_list_next (cur) != NULL) {
			r += snprintf (outbuf + r, sizeof (outbuf) - r - 2, "%s, ", (char *)cur->data);
		}
		else {
			r += snprintf (outbuf + r, sizeof (outbuf) - r - 2, "%s", (char *)cur->data);
		}
		cur = g_list_next (cur);
	}
	
	outbuf[r++] = '\r'; outbuf[r++] = '\n';

	rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE);
	msg_info ("process_message: msg ok, id: <%s>, %d emails extracted", task->message_id, num);

	return 0;
}

static int 
emails_mime_filter (struct worker_task *task)
{	
	GList *emails, *cur;

	emails = extract_emails (task);

	if (check_view (task->cfg->views, email_module_ctx->symbol, task)) {
		if (email_module_ctx->blacklist && emails) {
			cur = g_list_first (emails);

			while (cur) {
				if (g_hash_table_lookup (email_module_ctx->blacklist, cur->data) != NULL) {
					insert_result (task, email_module_ctx->metric, email_module_ctx->symbol, 1, 
								g_list_prepend (NULL, memory_pool_strdup (task->task_pool, (char *)cur->data)));
		
				}
				cur = g_list_next (cur);
			}
		}
	}

	return 0;
}

