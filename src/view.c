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
#include "main.h"
#include "util.h"
#include "view.h"
#include "expressions.h"
#include "cfg_file.h"
#include "map.h"

struct rspamd_view             *
init_view (struct config_file *cfg, memory_pool_t * pool)
{
	struct rspamd_view             *new;

	new = memory_pool_alloc0 (pool, sizeof (struct rspamd_view));

	new->pool = pool;
	new->from_hash = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
	new->symbols_hash = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
	new->rcpt_hash = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
	new->ip_tree = radix_tree_create ();
	new->client_ip_tree = radix_tree_create ();
	new->cfg = cfg;

	memory_pool_add_destructor (new->pool, (pool_destruct_func) g_hash_table_destroy, new->symbols_hash);

	return new;
}

gboolean
add_view_from (struct rspamd_view * view, gchar *line)
{
	struct rspamd_regexp           *re = NULL;

	if (add_map (view->cfg, line, read_host_list, fin_host_list, (void **)&view->from_hash)) {
		return TRUE;
	}
	else if ((re = parse_regexp (view->pool, line, TRUE)) != NULL) {
		view->from_re_list = g_list_prepend (view->from_re_list, re);
		return TRUE;
	}

	return FALSE;
}

gboolean
add_view_rcpt (struct rspamd_view * view, gchar *line)
{
	struct rspamd_regexp           *re = NULL;

	if (add_map (view->cfg, line, read_host_list, fin_host_list, (void **)&view->rcpt_hash)) {
		return TRUE;
	}
	else if ((re = parse_regexp (view->pool, line, TRUE)) != NULL) {
		view->rcpt_re_list = g_list_prepend (view->rcpt_re_list, re);
		return TRUE;
	}

	return FALSE;
}

gboolean
add_view_symbols (struct rspamd_view * view, gchar *line)
{
	struct rspamd_regexp           *re = NULL;
	GList                          *symbols;

	if (add_map (view->cfg, line, read_host_list, fin_host_list, (void **)&view->symbols_hash)) {
		return TRUE;
	}
	else if ((re = parse_regexp (view->pool, line, TRUE)) != NULL) {
		view->symbols_re_list = g_list_prepend (view->symbols_re_list, re);
		return TRUE;
	}
	else {
		/* Try to parse symbols line as comma separated list */
		symbols = parse_comma_list (view->pool, line);
		while (symbols) {
			g_hash_table_insert (view->symbols_hash, (gchar *)symbols->data, symbols->data);
			/* Symbols list would be free at pool destruction */
			symbols = g_list_next (symbols);
		}
	}

	return FALSE;

}

gboolean
add_view_ip (struct rspamd_view * view, gchar *line)
{
	if (add_map (view->cfg, line, read_radix_list, fin_radix_list, (void **)&view->ip_tree)) {
		return TRUE;
	}

	return FALSE;
}

gboolean
add_view_client_ip (struct rspamd_view * view, gchar *line)
{
	if (add_map (view->cfg, line, read_radix_list, fin_radix_list, (void **)&view->client_ip_tree)) {
		return TRUE;
	}

	return FALSE;
}


static struct rspamd_view             *
find_view_by_ip (GList * views, struct worker_task *task)
{
	GList                          *cur;
	struct rspamd_view             *v;

#ifdef HAVE_INET_PTON

	if (task->from_addr.ipv6 || task->from_addr.d.in4.s_addr == INADDR_NONE) {
		return NULL;
	}

	cur = views;
	while (cur) {
		v = cur->data;
		if (radix32tree_find (v->ip_tree, ntohl (task->from_addr.d.in4.s_addr)) != RADIX_NO_VALUE) {
			return v;
		}
		cur = g_list_next (cur);
	}

	return NULL;
#else

	if (task->from_addr.s_addr == INADDR_NONE) {
		return NULL;
	}

	cur = views;
	while (cur) {
		v = cur->data;
		if (radix32tree_find (v->ip_tree, ntohl (task->from_addr.s_addr)) != RADIX_NO_VALUE) {
			return v;
		}
		cur = g_list_next (cur);
	}

	return NULL;
#endif
}

static struct rspamd_view             *
find_view_by_client_ip (GList * views, struct worker_task *task)
{
	GList                          *cur;
	struct rspamd_view             *v;

	if (task->client_addr.s_addr == INADDR_NONE) {
		return NULL;
	}

	cur = views;
	while (cur) {
		v = cur->data;
		if (radix32tree_find (v->client_ip_tree, ntohl (task->client_addr.s_addr)) != RADIX_NO_VALUE) {
			msg_info ("found view for client ip %s", inet_ntoa (task->client_addr));
			return v;
		}
		cur = g_list_next (cur);
	}

	return NULL;
}

static struct rspamd_view             *
find_view_by_from (GList * views, struct worker_task *task)
{
	GList                          *cur, *cur_re;
	struct rspamd_view             *v;
	struct rspamd_regexp           *re;
	gchar                          *from_domain;

	if (task->from == NULL) {
		return NULL;
	}

	cur = views;
	while (cur) {
		v = cur->data;
		/* First try to lookup in hashtable domain name */
		if ((from_domain = strchr (task->from, '@')) != NULL) {
			from_domain ++;
			if (g_hash_table_lookup (v->from_hash, from_domain) != NULL) {
				msg_info ("found view for client from %s", task->from);
				return v;
			}
		}
		if (g_hash_table_lookup (v->from_hash, task->from) != NULL) {
			msg_info ("found view for client from %s", task->from);
			return v;
		}
		/* Then try to match re */
		cur_re = v->from_re_list;

		while (cur_re) {
			re = cur_re->data;
			if (g_regex_match (re->regexp, task->from, 0, NULL) == TRUE) {
				msg_info ("found view for client from %s", task->from);
				return v;
			}
			cur_re = g_list_next (cur_re);
		}
		cur = g_list_next (cur);
	}

	return NULL;
}

static inline gboolean
check_view_rcpt (struct rspamd_view *v, struct worker_task *task)
{
	GList                          *cur, *cur_re;
	gchar                           rcpt_user[256], *p;
	gint                            l;
	struct rspamd_regexp           *re;

	cur = task->rcpt;
	while (cur) {
		if ((p = strchr (cur->data, '@')) != NULL) {
			l = MIN ((gint)sizeof (rcpt_user) - 1, p - (gchar *)cur->data);
			memcpy (rcpt_user, cur->data, l);
			rcpt_user[l] = '\0';
			/* First try to lookup in hashtable */
			if (g_hash_table_lookup (v->rcpt_hash, rcpt_user) != NULL) {
				msg_info ("found view for client rcpt %s", rcpt_user);
				return TRUE;
			}
			/* Then try to match re */
			cur_re = v->rcpt_re_list;

			while (cur_re) {
				re = cur_re->data;
				if (g_regex_match (re->regexp, rcpt_user, 0, NULL) == TRUE) {
					msg_info ("found view for client rcpt %s", rcpt_user);
					return TRUE;
				}
				cur_re = g_list_next (cur_re);
			}
		}
		/* Now check the whole recipient */
		if (g_hash_table_lookup (v->rcpt_hash, cur->data) != NULL) {
			msg_info ("found view for client rcpt %s", rcpt_user);
			return TRUE;
		}
		/* Then try to match re */
		cur_re = v->rcpt_re_list;

		while (cur_re) {
			re = cur_re->data;
			if (g_regex_match (re->regexp, cur->data, 0, NULL) == TRUE) {
				msg_info ("found view for client rcpt %s", rcpt_user);
				return TRUE;
			}
			cur_re = g_list_next (cur_re);
		}
		cur = g_list_next (cur);
	}

	return FALSE;
}

static struct rspamd_view             *
find_view_by_rcpt (GList * views, struct worker_task *task)
{
	GList                          *cur;
	struct rspamd_view             *v;

	if (task->from == NULL) {
		return NULL;
	}

	cur = views;
	while (cur) {
		v = cur->data;
		if (check_view_rcpt (v, task)) {
			return v;
		}
		cur = g_list_next (cur);
	}

	return NULL;
}

static                          gboolean
match_view_symbol (struct rspamd_view *v, const gchar *symbol)
{
	GList                          *cur;
	struct rspamd_regexp           *re;

	/* Special case */
	if (symbol == NULL) {
		return TRUE;
	}
	/* First try to lookup in hashtable */
	if (g_hash_table_lookup (v->symbols_hash, symbol) != NULL) {
		return TRUE;
	}
	/* Then try to match re */
	cur = v->symbols_re_list;

	while (cur) {
		re = cur->data;
		if (g_regex_match (re->regexp, symbol, 0, NULL) == TRUE) {
			return TRUE;
		}
		cur = g_list_next (cur);
	}

	return FALSE;
}

gboolean
check_view (GList * views, const gchar *symbol, struct worker_task * task)
{
	struct rspamd_view             *selected = NULL;


	if (views == NULL || (task->view == NULL && task->view_checked == TRUE)) {
		/* If now views defined just return TRUE to check each symbol */
		return TRUE;
	}

	if (task->view != NULL) {
		goto check_symbol;
	}

	if ((selected = find_view_by_ip (views, task)) == NULL) {
		if ((selected = find_view_by_client_ip (views, task)) == NULL) {
			if ((selected = find_view_by_from (views, task)) == NULL) {
				if ((selected = find_view_by_rcpt (views, task)) == NULL) {
					/* No matching view for this task */
					task->view_checked = TRUE;
					return TRUE;
				}
			}
		}
	}

	task->view_checked = TRUE;
	task->view = selected;

  check_symbol:
	/* selected is now not NULL */
	if (task->view->skip_check) {
		return FALSE;
	}
	if (match_view_symbol (task->view, symbol)) {
		return TRUE;
	}

	return FALSE;
}

gboolean
check_skip (GList * views, struct worker_task * task)
{
	if (check_view (views, NULL, task) == FALSE) {
		return TRUE;
	}
	return FALSE;
}
