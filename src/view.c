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

#include "config.h"
#include "main.h"
#include "util.h"
#include "view.h"
#include "expressions.h"
#include "cfg_file.h"

struct rspamd_view* 
init_view (memory_pool_t *pool)
{
	struct rspamd_view *new;

	new = memory_pool_alloc0 (pool, sizeof (struct rspamd_view));

	new->pool = pool;
	new->from_hash = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
	new->symbols_hash = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);

	memory_pool_add_destructor (new->pool, (pool_destruct_func)g_hash_table_destroy, new->from_hash);
	memory_pool_add_destructor (new->pool, (pool_destruct_func)g_hash_table_destroy, new->symbols_hash);

	return new;
}

gboolean 
add_view_from (struct rspamd_view *view, char *line)
{
	struct rspamd_regexp *re = NULL;

	if (g_ascii_strncasecmp (line, "file://", sizeof ("file://") - 1) == 0) {
		if (parse_host_list (view->pool, view->from_hash, line + sizeof ("file://") - 1)) {
			return TRUE;
		}
	}
	else if ((re = parse_regexp (view->pool, line, TRUE)) != NULL) {
		view->from_re_list = g_list_prepend (view->from_re_list, re);
		return TRUE;
	}

	return FALSE;
}

gboolean 
add_view_symbols (struct rspamd_view *view, char *line)
{
	struct rspamd_regexp *re = NULL;
	GList *symbols;

	if (g_ascii_strncasecmp (line, "file://", sizeof ("file://") - 1) == 0) {
		if (parse_host_list (view->pool, view->symbols_hash, line + sizeof ("file://") - 1)) {
			return TRUE;
		}
	}
	else if ((re = parse_regexp (view->pool, line, TRUE)) != NULL) {
		view->symbols_re_list = g_list_prepend (view->symbols_re_list, re);
		return TRUE;
	}
	else {
		/* Try to parse symbols line as comma separated list */
		symbols = parse_comma_list (view->pool, line);
		while (symbols) {
			g_hash_table_insert (view->symbols_hash, (char *)symbols->data, symbols->data);
			/* Symbols list would be free at pool destruction */
			symbols = g_list_next (symbols);
		}
	}

	return FALSE;

}

gboolean 
add_view_ip (struct rspamd_view *view, char *line)
{
	if (g_ascii_strncasecmp (line, "file://", sizeof ("file://") - 1) == 0) {
		if (parse_radix_list (view->pool, view->ip_tree, line + sizeof ("file://") - 1)) {
			return TRUE;
		}
	}

	return FALSE;

}


struct rspamd_view *
find_view_by_ip (GList *views, struct worker_task *task)
{
	GList *cur;
	struct rspamd_view *v;

	if (task->from_addr.s_addr == INADDR_NONE) {
		return NULL;
	}
	
	cur = views;
	while (cur) {
		v = cur->data;
		if (radix32tree_find (v->ip_tree, task->from_addr.s_addr) != RADIX_NO_VALUE) {
			return v;
		}
		cur = g_list_next (cur);
	}

	return NULL;
}

struct rspamd_view *
find_view_by_from (GList *views, struct worker_task *task)
{
	GList *cur, *cur_re;
	struct rspamd_view *v;
	struct rspamd_regexp *re;

	if (task->from == NULL) {
		return NULL;
	}
	
	cur = views;
	while (cur) {
		v = cur->data;
		/* First try to lookup in hashtable */
		if (g_hash_table_lookup (v->from_hash, task->from) != NULL) {
			return v;
		}
		/* Then try to match re */
		cur_re = v->from_re_list;

		while (cur_re) {
			re = cur_re->data;
			if (g_regex_match (re->regexp, task->from, 0, NULL) == TRUE) {
				return v;
			}
			cur_re = g_list_next (cur_re);
		}
		cur = g_list_next (cur);
	}

	return NULL;
}

static gboolean
match_view_symbol (struct rspamd_view *v, const char *symbol)
{
	GList *cur;
	struct rspamd_regexp *re;

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
check_view (GList *views, const char *symbol, struct worker_task *task)
{
	struct rspamd_view *selected = NULL;


	if (views == NULL || (task->view == NULL && task->view_checked == TRUE)) {
		/* If now views defined just return TRUE to check each symbol */
		return TRUE;
	}
	
	if (task->view != NULL) {
		goto check_symbol;
	}

	if ((selected = find_view_by_ip (views, task)) == NULL) {
		if ((selected = find_view_by_from (views, task)) == NULL) {
			/* No matching view for this task */
			task->view_checked = TRUE;
			return TRUE;
		}
	}
	
	task->view_checked = TRUE;
	task->view = selected;

check_symbol:
	/* selected is now not NULL */
	if (match_view_symbol (task->view, symbol)) {
		return TRUE;
	}

	return FALSE;
}
