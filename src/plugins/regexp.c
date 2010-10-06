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

/***MODULE:regexp
 * rspamd module that implements different regexp rules
 */



#include "../config.h"
#include "../main.h"
#include "../message.h"
#include "../modules.h"
#include "../cfg_file.h"
#include "../map.h"
#include "../util.h"
#include "../expressions.h"
#include "../view.h"
#include "../lua/lua_common.h"
#include "../json/jansson.h"

#define DEFAULT_STATFILE_PREFIX "./"

struct regexp_module_item {
	struct expression               *expr;
	gchar                           *symbol;
	guint32                         avg_time;
	gpointer                        lua_function;
};

struct autolearn_data {
	gchar                           *statfile_name;
	gchar                           *symbol;
	float                           weight;
};

struct regexp_ctx {
	gint                            (*filter) (struct worker_task * task);
	GHashTable                     *autolearn_symbols;
	gchar                           *statfile_prefix;

	memory_pool_t                  *regexp_pool;
	memory_pool_t                  *dynamic_pool;
};

struct regexp_json_buf {
	guint8                         *buf;
	guint8                         *pos;
	size_t                          buflen;
	struct config_file             *cfg;
};

/* Lua regexp module for checking rspamd regexps */
LUA_FUNCTION_DEF (regexp, match);

static const struct luaL_reg    regexplib_m[] = {
	LUA_INTERFACE_DEF (regexp, match),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

static struct regexp_ctx       *regexp_module_ctx = NULL;

static gint                     regexp_common_filter (struct worker_task *task);
static gboolean                 rspamd_regexp_match_number (struct worker_task *task, GList * args, void *unused);
static gboolean                 rspamd_raw_header_exists (struct worker_task *task, GList * args, void *unused);
static gboolean                 rspamd_check_smtp_data (struct worker_task *task, GList * args, void *unused);
static void                     process_regexp_item (struct worker_task *task, void *user_data);

static gint
luaopen_regexp (lua_State * L)
{
	lua_newclass (L, "rspamd{regexp}", regexplib_m);
	luaL_openlib (L, "rspamd_regexp", null_reg, 0);

	return 1;
}

static void 
regexp_dynamic_insert_result (struct worker_task *task, void *user_data)
{
	gchar                           *symbol = user_data;
		
	insert_result (task, symbol, 1, NULL);
}

static gboolean
parse_regexp_ipmask (const gchar *begin, struct dynamic_map_item *addr)
{
	const gchar *pos;
	gchar                           ip_buf[sizeof ("255.255.255.255")], mask_buf[3], *p;
	gint                            state = 0, dots = 0;
	
	bzero (ip_buf, sizeof (ip_buf));
	bzero (mask_buf, sizeof (mask_buf));
	pos = begin;
	p = ip_buf;

	if (*pos == '!') {
		addr->negative = TRUE;
		pos ++;
	}
	else {
		addr->negative = FALSE;
	}

	while (*pos) {
		switch (state) {
			case 0:
				state = 1;
				p = ip_buf;
				dots = 0;
				break;
			case 1:
				/* Begin parse ip */
				if (p - ip_buf >= sizeof (ip_buf) || dots > 3) {
					return FALSE;
				}
				if (g_ascii_isdigit (*pos)) {
					*p ++ = *pos ++;
				}
				else if (*pos == '.') {
					*p ++ = *pos ++;
					dots ++;
				}
				else if (*pos == '/') {
					pos ++;
					p = mask_buf;
					state = 2;
				}
				else {
					/* Invalid character */
					return FALSE;
				}
				break;
			case 2:
				/* Parse mask */
				if (p - mask_buf > 2) {
					return FALSE;
				}
				if (g_ascii_isdigit (*pos)) {
					*p ++ = *pos ++;
				}
				else {
					return FALSE;
				}
				break;
		}
	}

	if (!inet_aton (ip_buf, &addr->addr)) {
		return FALSE;
	}
	if (state == 2) {
		/* Also parse mask */
		addr->mask = (mask_buf[0] - '0') * 10 + mask_buf[1] - '0';
		if (addr->mask > 32) {
			msg_info ("bad ipmask value: '%s'", begin);
			return FALSE;
		}
	}
	else {
		addr->mask = 32;
	}

	return TRUE;

}

/* Process regexp expression */
static                          gboolean
read_regexp_expression (memory_pool_t * pool, struct regexp_module_item *chain, gchar *symbol, gchar *line, gboolean raw_mode)
{
	struct expression              *e, *cur;

	e = parse_expression (pool, line);
	if (e == NULL) {
		msg_warn ("%s = \"%s\" is invalid regexp expression", symbol, line);
		return FALSE;
	}
	chain->expr = e;
	cur = e;
	while (cur) {
		if (cur->type == EXPR_REGEXP) {
			cur->content.operand = parse_regexp (pool, cur->content.operand, raw_mode);
			if (cur->content.operand == NULL) {
				msg_warn ("cannot parse regexp, skip expression %s = \"%s\"", symbol, line);
				return FALSE;
			}
			cur->type = EXPR_REGEXP_PARSED;
		}
		cur = cur->next;
	}

	return TRUE;
}


/* Callbacks for reading json dynamic rules */
guint8                         *
json_regexp_read_cb (memory_pool_t * pool, guint8 * chunk, size_t len, struct map_cb_data *data)
{
	struct regexp_json_buf                *jb;
	size_t                          free, off;

	if (data->cur_data == NULL) {
		jb = g_malloc (sizeof (struct regexp_json_buf));
		jb->cfg = ((struct regexp_json_buf *)data->prev_data)->cfg;
		jb->buf = NULL;
		jb->pos = NULL;
		data->cur_data = jb;
	}
	else {
		jb = data->cur_data;
	}

	if (jb->buf == NULL) {
		/* Allocate memory for buffer */
		jb->buflen = len * 2;
		jb->buf = g_malloc (jb->buflen);
		jb->pos = jb->buf;
	}

	off = jb->pos - jb->buf;
	free = jb->buflen - off;

	if (free < len) {
		jb->buflen = MAX (jb->buflen * 2, jb->buflen + len * 2);
		jb->buf = g_realloc (jb->buf, jb->buflen);
		jb->pos = jb->buf + off;
	}

	memcpy (jb->pos, chunk, len);
	jb->pos += len;

	/* Say not to copy any part of this buffer */
	return NULL;
}

void
json_regexp_fin_cb (memory_pool_t * pool, struct map_cb_data *data)
{
	struct regexp_json_buf         *jb;
	gint                            nelts, i, j;
	json_t                         *js, *cur_elt, *cur_nm, *it_val;
	json_error_t                    je;
	gchar                           *cur_rule, *cur_symbol;
	double                          score;
	gboolean                        enabled;
	struct regexp_module_item      *cur_item;
	GList                          *cur_networks = NULL;
	struct dynamic_map_item        *cur_nitem;
	memory_pool_t                  *new_pool;

	if (data->prev_data) {
		jb = data->prev_data;
		/* Clean prev data */
		if (jb->buf) {
			g_free (jb->buf);
		}
		g_free (jb);
	}

	/* Now parse json */
	if (data->cur_data) {
		jb = data->cur_data;
	}
	else {
		msg_err ("no data read");
		return;
	}
	if (jb->buf == NULL) {
		msg_err ("no data read");
		return;
	}
	/* NULL terminate current buf */
	*jb->pos = '\0';

	js = json_loads (jb->buf, &je);
	if (!js) {
		msg_err ("cannot load json data: parse error %s, on line %d", je.text, je.line);
		return;
	}

	if (!json_is_array (js)) {
		json_decref (js);
		msg_err ("loaded json is not an array");
		return;
	}
	
	new_pool = memory_pool_new (memory_pool_get_size ());
		
	remove_dynamic_rules (jb->cfg->cache);
	if (regexp_module_ctx->dynamic_pool != NULL) {
		memory_pool_delete (regexp_module_ctx->dynamic_pool);
	}
	regexp_module_ctx->dynamic_pool = new_pool;

	nelts = json_array_size (js);
	for (i = 0; i < nelts; i++) {
		cur_networks = NULL;
		cur_rule = NULL;
		enabled = TRUE;

		cur_elt = json_array_get (js, i);
		if (!cur_elt || !json_is_object (cur_elt)) {
			msg_err ("loaded json is not an object");
			continue;
		}
		/* Factor param */
		cur_nm = json_object_get (cur_elt, "factor");
		if (cur_nm == NULL || !json_is_number (cur_nm)) {
			msg_err ("factor is not a number or not exists, but is required");
			continue;
		}
		score = json_number_value (cur_nm); 
		/* Symbol param */
		cur_nm = json_object_get (cur_elt, "symbol");
		if (cur_nm == NULL || !json_is_string (cur_nm)) {
			msg_err ("symbol is not a string or not exists, but is required");
			continue;
		}
		cur_symbol = memory_pool_strdup (new_pool, json_string_value (cur_nm)); 
		/* Enabled flag */
		cur_nm = json_object_get (cur_elt, "enabled");
		if (cur_nm != NULL && json_is_boolean (cur_nm)) {
			if (json_is_false (cur_nm)) {
				msg_info ("rule %s is disabled in json", cur_symbol);
				continue;
			}
		}
		/* Now check other settings */
		/* Rule */
		cur_nm = json_object_get (cur_elt, "rule");
		if (cur_nm != NULL && json_is_string (cur_nm)) {
			cur_rule = memory_pool_strdup (new_pool, json_string_value (cur_nm));
		}
		/* Networks array */
		cur_nm = json_object_get (cur_elt, "networks");
		if (cur_nm != NULL && json_is_array (cur_nm)) {
			for (j = 0; j < json_array_size (cur_nm); j++) {
				it_val = json_array_get (cur_nm, i);
				if (it_val && json_is_string (it_val)) {
					cur_nitem = memory_pool_alloc (new_pool, sizeof (struct dynamic_map_item));
					if (parse_regexp_ipmask (json_string_value (it_val), cur_nitem)) {
						cur_networks = g_list_prepend (cur_networks, cur_nitem);
					}
				}
			}
		}
		if (cur_rule) {
			/* Dynamic rule has rule option */
			cur_item = memory_pool_alloc0 (new_pool, sizeof (struct regexp_module_item));
			cur_item->symbol = cur_symbol;
			if (read_regexp_expression (new_pool, cur_item, cur_symbol, cur_rule, jb->cfg->raw_mode)) {
				register_dynamic_symbol (new_pool, &jb->cfg->cache, cur_symbol, score, process_regexp_item, cur_item, cur_networks);
			}
			else {
				msg_warn ("cannot parse dynamic rule");
			}
		}
		else {
			/* Just rule that is allways true (for whitelisting for example) */
			register_dynamic_symbol (new_pool, &jb->cfg->cache, cur_symbol, score, regexp_dynamic_insert_result, cur_symbol, cur_networks);
		}
		if (cur_networks) {
			g_list_free (cur_networks);
		}
	}
	json_decref (js);
}

/* Init function */
gint
regexp_module_init (struct config_file *cfg, struct module_ctx **ctx)
{
	regexp_module_ctx = g_malloc (sizeof (struct regexp_ctx));

	regexp_module_ctx->filter = regexp_common_filter;
	regexp_module_ctx->regexp_pool = memory_pool_new (memory_pool_get_size ());
	regexp_module_ctx->dynamic_pool = NULL;
	regexp_module_ctx->autolearn_symbols = g_hash_table_new (g_str_hash, g_str_equal);

	*ctx = (struct module_ctx *)regexp_module_ctx;
	register_expression_function ("regexp_match_number", rspamd_regexp_match_number, NULL);
	register_expression_function ("raw_header_exists", rspamd_raw_header_exists, NULL);
	register_expression_function ("check_smtp_data", rspamd_check_smtp_data, NULL);

	(void)luaopen_regexp (cfg->lua_state);

	return 0;
}


/* 
 * Parse string in format:
 * SYMBOL:statfile:weight
 */
void
parse_autolearn_param (const gchar *param, const gchar *value, struct config_file *cfg)
{
	struct autolearn_data          *d;
	gchar                           *p;

	p = memory_pool_strdup (regexp_module_ctx->regexp_pool, value);
	d = memory_pool_alloc (regexp_module_ctx->regexp_pool, sizeof (struct autolearn_data));

	d->symbol = strsep (&p, ":");
	if (d->symbol) {
		d->statfile_name = strsep (&p, ":");
		if (d->statfile_name) {
			if (p != NULL && *p != '\0') {
				d->weight = strtod (p, NULL);
				g_hash_table_insert (regexp_module_ctx->autolearn_symbols, d->symbol, d);
			}
		}
		else {
			msg_warn ("cannot extract statfile name from %s", p);
		}
	}
	else {
		msg_warn ("cannot extract symbol name from %s", p);
	}
}

gint
regexp_module_config (struct config_file *cfg)
{
	GList                          *cur_opt = NULL;
	struct module_opt              *cur;
	struct regexp_module_item      *cur_item;
	gchar                           *value;
	gint                            res = TRUE;
	struct regexp_json_buf         *jb, **pjb;

	if ((value = get_module_opt (cfg, "regexp", "statfile_prefix")) != NULL) {
		regexp_module_ctx->statfile_prefix = memory_pool_strdup (regexp_module_ctx->regexp_pool, value);
	}
	else {
		regexp_module_ctx->statfile_prefix = DEFAULT_STATFILE_PREFIX;
	}
	if ((value = get_module_opt (cfg, "regexp", "dynamic_rules")) != NULL) {
		jb = g_malloc (sizeof (struct regexp_json_buf));
		pjb = g_malloc (sizeof (struct regexp_json_buf *));
		jb->buf = NULL;
		jb->cfg = cfg;
		*pjb = jb;
		if (!add_map (value, json_regexp_read_cb, json_regexp_fin_cb, (void **)pjb)) {
			msg_err ("cannot add map %s", value);
		}
	}


	cur_opt = g_hash_table_lookup (cfg->modules_opts, "regexp");
	while (cur_opt) {
		cur = cur_opt->data;
		if (strcmp (cur->param, "metric") == 0 || strcmp (cur->param, "statfile_prefix") == 0) {
			cur_opt = g_list_next (cur_opt);
			continue;
		}
		else if (g_ascii_strncasecmp (cur->param, "autolearn", sizeof ("autolearn") - 1) == 0) {
			parse_autolearn_param (cur->param, cur->value, cfg);
			cur_opt = g_list_next (cur_opt);
			continue;
		}
		else if (g_ascii_strncasecmp (cur->param, "dynamic_rules", sizeof ("dynamic_rules") - 1) == 0) {
			cur_opt = g_list_next (cur_opt);
			continue;
		}
		cur_item = memory_pool_alloc0 (regexp_module_ctx->regexp_pool, sizeof (struct regexp_module_item));
		cur_item->symbol = cur->param;
		if (cur->is_lua && cur->lua_type == LUA_VAR_STRING) {
			if (!read_regexp_expression (regexp_module_ctx->regexp_pool, cur_item, cur->param, cur->actual_data, cfg->raw_mode)) {
				res = FALSE;
			}
		}
		else if (cur->is_lua && cur->lua_type == LUA_VAR_FUNCTION) {
			cur_item->lua_function = cur->actual_data;
		}
		else if (! cur->is_lua) {
			if (!read_regexp_expression (regexp_module_ctx->regexp_pool, cur_item, cur->param, cur->value, cfg->raw_mode)) {
				res = FALSE;
			}
		}
		else {
			msg_err ("unknown variable type for %s", cur->param);
			res = FALSE;
		}
		
		if ( !res) {
			/* Stop on errors */
			break;
		}
		
		register_symbol (&cfg->cache, cur->param, 1, process_regexp_item, cur_item);

		cur_opt = g_list_next (cur_opt);
	}


	return res;
}

gint
regexp_module_reconfig (struct config_file *cfg)
{
	memory_pool_delete (regexp_module_ctx->regexp_pool);
	regexp_module_ctx->regexp_pool = memory_pool_new (memory_pool_get_size ());

	return regexp_module_config (cfg);
}

static const gchar              *
find_raw_header_pos (const gchar *headers, const gchar *headerv)
{
	const gchar                     *p = headers;
	gsize                           headerlen = strlen (headerv);

	if (headers == NULL) {
		return NULL;
	}

	while (*p) {
		/* Try to find headers only at the begin of line */
		if (*p == '\r' || *p == '\n') {
			if (*(p + 1) == '\n' && *p == '\r') {
				p++;
			}
			if (g_ascii_isspace (*(++p))) {
				/* Folding */
				continue;
			}
			if (g_ascii_strncasecmp (p, headerv, headerlen) == 0) {
				/* Find semicolon */
				p += headerlen;
				if (*p == ':') {
					while (*p && g_ascii_isspace (*(++p)));
					return p;
				}
			}
		}
		if (*p != '\0') {
			p++;
		}
	}

	return NULL;
}

struct url_regexp_param {
	struct worker_task             *task;
	GRegex                         *regexp;
	struct rspamd_regexp           *re;
	gboolean                        found;
};

static                          gboolean
tree_url_callback (gpointer key, gpointer value, void *data)
{
	struct url_regexp_param        *param = data;
	struct uri                     *url = value;
	GError                         *err = NULL;

	if (g_regex_match_full (param->regexp, struri (url), -1, 0, 0, NULL, &err) == TRUE) {
		if (G_UNLIKELY (param->re->is_test)) {
			msg_info ("process test regexp %s for url %s returned TRUE", struri (url));
		}
		task_cache_add (param->task, param->re, 1);
		param->found = TRUE;
		return TRUE;
	}
	else if (G_UNLIKELY (param->re->is_test)) {
		msg_info ("process test regexp %s for url %s returned FALSE", struri (url));
	}
	if (err != NULL) {
		msg_info ("error occured while processing regexp \"%s\": %s", param->re->regexp_text, err->message);
	}

	return FALSE;
}

static                          gsize
process_regexp (struct rspamd_regexp *re, struct worker_task *task, const gchar *additional)
{
	gchar                           *headerv, *c, t;
	struct mime_text_part          *part;
	GList                          *cur, *headerlist;
	GRegex                         *regexp;
	GError                         *err = NULL;
	struct url_regexp_param         callback_param = {
		.task = task,
		.regexp = re->regexp,
		.re = re,
		.found = FALSE
	};
	gint                            r;


	if (re == NULL) {
		msg_info ("invalid regexp passed");
		return 0;
	}

	if ((r = task_cache_check (task, re)) != -1) {
		debug_task ("regexp /%s/ is found in cache, result: %d", re->regexp_text, r);
		return r == 1;
	}
	
	if (additional != NULL) {
		/* We have additional parameter defined, so ignore type of regexp expression and use it for parsing */
		if (G_UNLIKELY (re->is_test)) {
			msg_info ("process test regexp %s with test %s", re->regexp_text, additional);
		}
		if (g_regex_match_full (re->regexp, additional, strlen (additional), 0, 0, NULL, NULL) == TRUE) {
			if (G_UNLIKELY (re->is_test)) {
				msg_info ("result of regexp %s is true", re->regexp_text);
			}
			task_cache_add (task, re, 1);
			return 1;
		}
		else {
			task_cache_add (task, re, 0);
			return 0;
		}
	}

	switch (re->type) {
	case REGEXP_NONE:
		msg_warn ("bad error detected: %s has invalid regexp type", re->regexp_text);
		return 0;
	case REGEXP_HEADER:
		if (re->header == NULL) {
			msg_info ("header regexp without header name: '%s'", re->regexp_text);
			task_cache_add (task, re, 0);
			return 0;
		}
		debug_task ("checking header regexp: %s = %s", re->header, re->regexp_text);

		headerlist = message_get_header (task->task_pool, task->message, re->header);
		if (headerlist == NULL) {
			if (G_UNLIKELY (re->is_test)) {
				msg_info ("process test regexp %s for header %s returned FALSE: no header found", re->regexp_text, re->header);
			}
			task_cache_add (task, re, 0);
			return 0;
		}
		else {
			memory_pool_add_destructor (task->task_pool, (pool_destruct_func) g_list_free, headerlist);
			if (re->regexp == NULL) {
				debug_task ("regexp contains only header and it is found %s", re->header);
				task_cache_add (task, re, 1);
				return 1;
			}
			cur = headerlist;
			while (cur) {
				debug_task ("found header \"%s\" with value \"%s\"", re->header, (const gchar *)cur->data);

				if (cur->data && g_regex_match_full (re->regexp, cur->data, -1, 0, 0, NULL, &err) == TRUE) {
					if (G_UNLIKELY (re->is_test)) {
						msg_info ("process test regexp %s for header %s with value '%s' returned TRUE", re->regexp_text, re->header, (const gchar *)cur->data);
					}
					task_cache_add (task, re, 1);
					return 1;
				}
				else if (G_UNLIKELY (re->is_test)) {
					msg_info ("process test regexp %s for header %s with value '%s' returned FALSE", re->regexp_text, re->header, (const gchar *)cur->data);
				}
				if (err != NULL) {
					msg_info ("error occured while processing regexp \"%s\": %s", re->regexp_text, err->message);
				}
				cur = g_list_next (cur);
			}
			task_cache_add (task, re, 0);
			return 0;
		}
		break;
	case REGEXP_MIME:
		debug_task ("checking mime regexp: %s", re->regexp_text);
		cur = g_list_first (task->text_parts);
		while (cur) {
			part = (struct mime_text_part *)cur->data;
			/* Skip empty parts */
			if (part->is_empty) {
				cur = g_list_next (cur);
				continue;
			}
			if (part->is_raw) {
				regexp = re->raw_regexp;
			}
			else {
				regexp = re->regexp;
			}

			if (g_regex_match_full (regexp, part->orig->data, part->orig->len, 0, 0, NULL, &err) == TRUE) {
				if (G_UNLIKELY (re->is_test)) {
					msg_info ("process test regexp %s for mime part returned TRUE", re->regexp_text);
				}
				task_cache_add (task, re, 1);
				return 1;
			}
			else if (G_UNLIKELY (re->is_test)) {
				msg_info ("process test regexp %s for mime part of length %d returned FALSE", re->regexp_text, (gint)part->orig->len);
			}
			if (err != NULL) {
				msg_info ("error occured while processing regexp \"%s\": %s", re->regexp_text, err->message);
			}
			cur = g_list_next (cur);
		}
		task_cache_add (task, re, 0);
		return 0;
	case REGEXP_MESSAGE:
		debug_task ("checking message regexp: %s", re->regexp_text);

		if (g_regex_match_full (re->raw_regexp, task->msg->begin, task->msg->len, 0, 0, NULL, &err) == TRUE) {
			if (G_UNLIKELY (re->is_test)) {
				msg_info ("process test regexp %s for message of length %d returned TRUE", re->regexp_text, (gint)task->msg->len);
			}
			task_cache_add (task, re, 1);
			return 1;
		}
		else if (G_UNLIKELY (re->is_test)) {
			msg_info ("process test regexp %s for message of length %d returned FALSE", re->regexp_text, (gint)task->msg->len);
		}
		if (err != NULL) {
			msg_info ("error occured while processing regexp \"%s\": %s", re->regexp_text, err->message);
		}
		task_cache_add (task, re, 0);
		return 0;
	case REGEXP_URL:
		debug_task ("checking url regexp: %s", re->regexp_text);
		cur = g_list_first (task->text_parts);
		while (cur) {
			part = (struct mime_text_part *)cur->data;
			/* Skip empty parts */
			if (part->is_empty) {
				cur = g_list_next (cur);
				continue;
			}
			if (part->is_raw) {
				regexp = re->raw_regexp;
			}
			else {
				regexp = re->regexp;
			}
			callback_param.task = task;
			callback_param.regexp = regexp;
			callback_param.re = re;
			callback_param.found = FALSE;
			if (part->urls) {
				g_tree_foreach (part->urls, tree_url_callback, &callback_param);
			}
			if (part->html_urls && callback_param.found == FALSE) {
				g_tree_foreach (part->html_urls, tree_url_callback, &callback_param);
			}
			cur = g_list_next (cur);
		}
		if (callback_param.found == FALSE) {
			task_cache_add (task, re, 0);
		}
		return 0;
	case REGEXP_RAW_HEADER:
		debug_task ("checking for raw header: %s with regexp: %s", re->header, re->regexp_text);
		if (task->raw_headers == NULL) {
			debug_task ("cannot check for raw header in message, no headers found");
			task_cache_add (task, re, 0);
			return 0;
		}
		if ((headerv = (gchar *)find_raw_header_pos (task->raw_headers, re->header)) == NULL) {
			/* No header was found */
			task_cache_add (task, re, 0);
			return 0;
		}
		/* Now the main problem is to find position of end of raw header */
		c = headerv;
		while (*c) {
			/* We need to handle all types of line end */
			if ((*c == '\r' && *(c + 1) == '\n')) {
				c++;
				/* Check for folding */
				if (!g_ascii_isspace (*(c + 1))) {
					c++;
					break;
				}
			}
			else if (*c == '\r' || *c == '\n') {
				if (!g_ascii_isspace (*(c + 1))) {
					c++;
					break;
				}
			}
			c++;
		}
		/* Temporary null terminate this part of string */
		t = *c;
		*c = '\0';
		debug_task ("found raw header \"%s\" with value \"%s\"", re->header, headerv);

		if (g_regex_match_full (re->raw_regexp, headerv, -1, 0, 0, NULL, &err) == TRUE) {
			if (re->is_test) {
				msg_info ("process test regexp %s for raw header %s with value '%s' returned TRUE", re->regexp_text, re->header, headerv);
			}
			*c = t;
			task_cache_add (task, re, 1);
			return 1;
		}
		else if (re->is_test) {
			msg_info ("process test regexp %s for raw header %s with value '%s' returned FALSE", re->regexp_text, re->header, headerv);
		}
		if (err != NULL) {
			msg_info ("error occured while processing regexp \"%s\": %s", re->regexp_text, err->message);
		}
		*c = t;
		task_cache_add (task, re, 0);
		return 0;
	default:
		msg_warn ("bad error detected: %p is not a valid regexp object", re);
	}

	/* Not reached */
	return 0;
}

static                          gboolean
optimize_regexp_expression (struct expression **e, GQueue * stack, gboolean res)
{
	struct expression              *it = (*e)->next;
	gboolean                        ret = FALSE, is_nearest = TRUE;
	gint                            skip_level = 0;

	/* Skip nearest logical operators from optimization */
	if (!it || (it->type == EXPR_OPERATION && it->content.operation != '!')) {
		g_queue_push_head (stack, GSIZE_TO_POINTER (res));
		return ret;
	}

	while (it) {
		/* Find first operation for this iterator */
		if (it->type == EXPR_OPERATION) {
			/* If this operation is just ! just inverse res and check for further operators */
			if (it->content.operation == '!') {
				if (is_nearest) {
					msg_debug ("found '!' operator, inversing result");
					res = !res;
					*e = it;
				}
				it = it->next;
				continue;
			}
			else {
				skip_level--;
			}
			/* Check whether we found corresponding operator for this operand */
			if (skip_level <= 0) {
				if (it->content.operation == '|' && res == TRUE) {
					msg_debug ("found '|' and previous expression is true");
					*e = it;
					ret = TRUE;
				}
				else if (it->content.operation == '&' && res == FALSE) {
					msg_debug ("found '&' and previous expression is false");
					*e = it;
					ret = TRUE;
				}
				break;
			}
		}
		else {
			is_nearest = FALSE;
			skip_level++;
		}
		it = it->next;
	}

	g_queue_push_head (stack, GSIZE_TO_POINTER (res));

	return ret;
}

static                          gboolean
process_regexp_expression (struct expression *expr, gchar *symbol, struct worker_task *task, const gchar *additional)
{
	GQueue                         *stack;
	gsize                           cur, op1, op2;
	struct expression              *it = expr;
	struct rspamd_regexp           *re;
	gboolean                        try_optimize = TRUE;

	stack = g_queue_new ();

	while (it) {
		if (it->type == EXPR_REGEXP_PARSED) {
			/* Find corresponding symbol */
			cur = process_regexp ((struct rspamd_regexp *)it->content.operand, task, additional);
			debug_task ("regexp %s found", cur ? "is" : "is not");
			if (try_optimize) {
				try_optimize = optimize_regexp_expression (&it, stack, cur);
			}
			else {
				g_queue_push_head (stack, GSIZE_TO_POINTER (cur));
			}
		}
		else if (it->type == EXPR_FUNCTION) {
			cur = (gsize) call_expression_function ((struct expression_function *)it->content.operand, task);
			debug_task ("function %s returned %s", ((struct expression_function *)it->content.operand)->name, cur ? "true" : "false");
			if (try_optimize) {
				try_optimize = optimize_regexp_expression (&it, stack, cur);
			}
			else {
				g_queue_push_head (stack, GSIZE_TO_POINTER (cur));
			}
		}
		else if (it->type == EXPR_REGEXP) {
			/* Compile regexp if it is not parsed */
			if (it->content.operand == NULL) {
				it = it->next;
				continue;
			}
			re = parse_regexp (task->cfg->cfg_pool, it->content.operand, task->cfg->raw_mode);
			if (re == NULL) {
				msg_warn ("cannot parse regexp, skip expression");
				g_queue_free (stack);
				return FALSE;
			}
			it->content.operand = re;
			it->type = EXPR_REGEXP_PARSED;
			/* Continue with this regexp once again */
			continue;
		}
		else if (it->type == EXPR_OPERATION) {
			if (g_queue_is_empty (stack)) {
				/* Queue has no operands for operation, exiting */
				msg_warn ("regexp expression seems to be invalid: empty stack while reading operation");
				g_queue_free (stack);
				return FALSE;
			}
			debug_task ("got operation %c", it->content.operation);
			switch (it->content.operation) {
			case '!':
				op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
				op1 = !op1;
				try_optimize = optimize_regexp_expression (&it, stack, op1);
				break;
			case '&':
				op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
				op2 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
				try_optimize = optimize_regexp_expression (&it, stack, op1 && op2);
				break;
			case '|':
				op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
				op2 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
				try_optimize = optimize_regexp_expression (&it, stack, op1 || op2);
				break;
			default:
				it = it->next;
				continue;
			}
		}
		if (it) {
			it = it->next;
		}
	}
	if (!g_queue_is_empty (stack)) {
		op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
		if (op1) {
			g_queue_free (stack);
			return TRUE;
		}
	}
	else {
		msg_warn ("regexp expression seems to be invalid: empty stack at the end of expression, symbol %s", symbol);
	}

	g_queue_free (stack);

	return FALSE;
}

static void
process_regexp_item (struct worker_task *task, void *user_data)
{
	struct regexp_module_item      *item = user_data;
	gboolean                        res = FALSE;
	
	if (item->lua_function) {
		/* Just call function */
		if (lua_call_expression_func (item->lua_function, task, NULL, &res) && res) {
			insert_result (task, item->symbol, 1, NULL);
		}
	}
	else {
		/* Process expression */
		if (process_regexp_expression (item->expr, item->symbol, task, NULL)) {
			insert_result (task, item->symbol, 1, NULL);
		}
	}
}

static gint
regexp_common_filter (struct worker_task *task)
{
	/* XXX: remove this shit too */
	return 0;
}

static                          gboolean
rspamd_regexp_match_number (struct worker_task *task, GList * args, void *unused)
{
	gint                            param_count, res = 0;
	struct expression_argument     *arg;
	GList                          *cur;

	if (args == NULL) {
		msg_warn ("no parameters to function");
		return FALSE;
	}

	arg = get_function_arg (args->data, task, TRUE);
	param_count = strtoul (arg->data, NULL, 10);

	cur = args->next;
	while (cur) {
		arg = get_function_arg (cur->data, task, FALSE);
		if (arg && arg->type == EXPRESSION_ARGUMENT_BOOL) {
			if ((gboolean) GPOINTER_TO_SIZE (arg->data)) {
				res++;
			}
		}
		else {
			if (process_regexp_expression (cur->data, "regexp_match_number", task, NULL)) {
				res++;
			}
			if (res >= param_count) {
				return TRUE;
			}
		}
		cur = g_list_next (cur);
	}

	return res >= param_count;
}

static                          gboolean
rspamd_raw_header_exists (struct worker_task *task, GList * args, void *unused)
{
	struct expression_argument     *arg;

	if (args == NULL || task == NULL) {
		return FALSE;
	}

	arg = get_function_arg (args->data, task, TRUE);
	if (!arg || arg->type == EXPRESSION_ARGUMENT_BOOL) {
		msg_warn ("invalid argument to function is passed");
		return FALSE;
	}
	if (find_raw_header_pos (task->raw_headers, (gchar *)arg->data) == NULL) {
		return FALSE;
	}

	return TRUE;
}

static gboolean
match_smtp_data (struct worker_task *task, const gchar *re_text, const gchar *what)
{
	struct rspamd_regexp           *re;
	gint                            r;

	if (*re_text == '/') {
		/* This is a regexp */
		if ((re = re_cache_check (re_text, task->cfg->cfg_pool)) == NULL) {
			re = parse_regexp (task->cfg->cfg_pool, (gchar *)re_text, task->cfg->raw_mode);
			if (re == NULL) {
				msg_warn ("cannot compile regexp for function");
				return FALSE;
			}
			re_cache_add ((gchar *)re_text, re, task->cfg->cfg_pool);
		}
		if ((r = task_cache_check (task, re)) == -1) {
			if (g_regex_match (re->regexp, what, 0, NULL) == TRUE) {
				task_cache_add (task, re, 1);
				return TRUE;
			}
			task_cache_add (task, re, 0);
		}
		else {
			return r == 1;
		}
	}
	else if (g_ascii_strcasecmp (re_text, what) == 0) {
		return TRUE;
	}

	return FALSE;
}

static                          gboolean
rspamd_check_smtp_data (struct worker_task *task, GList * args, void *unused)
{
	struct expression_argument     *arg;
	GList                          *cur, *rcpt_list = NULL;
	gchar                           *type, *what = NULL;

	if (args == NULL) {
		msg_warn ("no parameters to function");
		return FALSE;
	}

	arg = get_function_arg (args->data, task, TRUE);

	if (!arg || !arg->data) {
		msg_warn ("no parameters to function");
		return FALSE;
	}
	else {
		type = arg->data;
		switch (*type) {
			case 'f':
			case 'F':
				if (g_ascii_strcasecmp (type, "from") == 0) {
					what = task->from;
				}
				else {
					msg_warn ("bad argument to function: %s", type);
					return FALSE;
				}
				break;
			case 'h':
			case 'H':
				if (g_ascii_strcasecmp (type, "helo") == 0) {
					what = task->helo;
				}
				else {
					msg_warn ("bad argument to function: %s", type);
					return FALSE;
				}
				break;
			case 'u':
			case 'U':
				if (g_ascii_strcasecmp (type, "user") == 0) {
					what = task->user;
				}
				else {
					msg_warn ("bad argument to function: %s", type);
					return FALSE;
				}
				break;
			case 's':
			case 'S':
				if (g_ascii_strcasecmp (type, "subject") == 0) {
					what = task->subject;
				}
				else {
					msg_warn ("bad argument to function: %s", type);
					return FALSE;
				}
				break;
			case 'r':
			case 'R':
				if (g_ascii_strcasecmp (type, "rcpt") == 0) {
					rcpt_list = task->rcpt;
				}
				else {
					msg_warn ("bad argument to function: %s", type);
					return FALSE;
				}
				break;
			default:
				msg_warn ("bad argument to function: %s", type);
				return FALSE;
		}
	}

	if (what == NULL && rcpt_list == NULL) {
		/* Not enough data so regexp would NOT be found anyway */
		return FALSE;
	}
	
	/* We would process only one more argument, others are ignored */
	cur = args->next;
	if (cur) {
		arg = get_function_arg (cur->data, task, FALSE);
		if (arg && arg->type == EXPRESSION_ARGUMENT_NORMAL) {
			if (what != NULL) {
				return match_smtp_data (task, arg->data, what);
			}
			else {
				while (rcpt_list) {
					if (match_smtp_data (task, arg->data, rcpt_list->data)) {
						return TRUE;
					}
					rcpt_list = g_list_next (rcpt_list);
				}
			}
		}
		else {
			if (what != NULL) {
				if (process_regexp_expression (arg->data, "regexp_check_smtp_data", task, what)) {
					return TRUE;
				}
			}
			else {
				while (rcpt_list) {
					if (process_regexp_expression (arg->data, "regexp_check_smtp_data", task, rcpt_list->data)) {
						return TRUE;
					}
					rcpt_list = g_list_next (rcpt_list);
				}
			}
		}
	}

	return FALSE;
}

/* Lua part */
static gint
lua_regexp_match (lua_State *L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{task}");
	struct worker_task             *task;
	const gchar                    *re_text;
	struct rspamd_regexp           *re;
	gint                            r;

	luaL_argcheck (L, ud != NULL, 1, "'task' expected");
	task = *((struct worker_task **)ud);
	re_text = luaL_checkstring (L, 2);


	/* This is a regexp */
	if ((re = re_cache_check (re_text, task->cfg->cfg_pool)) == NULL) {
		re = parse_regexp (task->cfg->cfg_pool, (gchar *)re_text, task->cfg->raw_mode);
		if (re == NULL) {
			msg_warn ("cannot compile regexp for function");
			return FALSE;
		}
		re_cache_add ((gchar *)re_text, re, task->cfg->cfg_pool);
	}
	r = process_regexp (re, task, NULL);
	lua_pushboolean (L, r == 1);

	return 1;
}
