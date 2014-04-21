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

/***MODULE:regexp
 * rspamd module that implements different regexp rules
 */


#include "config.h"
#include "main.h"
#include "message.h"
#include "cfg_file.h"
#include "map.h"
#include "util.h"
#include "expressions.h"
#include "view.h"
#include "lua/lua_common.h"
#include "json/jansson.h"

#define DEFAULT_STATFILE_PREFIX "./"

struct regexp_module_item {
	struct expression               *expr;
	const gchar                           *symbol;
	guint32                         avg_time;
	gpointer                        lua_function;
};

struct autolearn_data {
	gchar                           *statfile_name;
	gchar                           *symbol;
	float                           weight;
};

struct regexp_ctx {
	gint                          (*filter) (struct rspamd_task * task);
	GHashTable                     *autolearn_symbols;
	gchar                          *statfile_prefix;

	rspamd_mempool_t                  *regexp_pool;
	rspamd_mempool_t                  *dynamic_pool;
	gsize                           max_size;
	gsize							max_threads;
	GThreadPool					   *workers;
};

struct regexp_json_buf {
	gchar                          *buf;
	gchar                          *pos;
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
static GMutex 				   *workers_mtx = NULL;

static gint                     regexp_common_filter (struct rspamd_task *task);
static void				     process_regexp_item_threaded (gpointer data, gpointer user_data);
static gboolean                 rspamd_regexp_match_number (struct rspamd_task *task, GList * args, void *unused);
static gboolean                 rspamd_raw_header_exists (struct rspamd_task *task, GList * args, void *unused);
static gboolean                 rspamd_check_smtp_data (struct rspamd_task *task, GList * args, void *unused);
static gboolean                 rspamd_regexp_occurs_number (struct rspamd_task *task, GList * args, void *unused);
static gboolean                 rspamd_content_type_is_type (struct rspamd_task * task, GList * args, void *unused);
static gboolean                 rspamd_content_type_is_subtype (struct rspamd_task *task, GList * args, void *unused);
static gboolean                 rspamd_content_type_has_param (struct rspamd_task * task, GList * args, void *unused);
static gboolean                 rspamd_content_type_compare_param (struct rspamd_task * task, GList * args, void *unused);
static gboolean                 rspamd_has_content_part (struct rspamd_task *task, GList * args, void *unused);
static gboolean                 rspamd_has_content_part_len (struct rspamd_task *task, GList * args, void *unused);
static void                    process_regexp_item (struct rspamd_task *task, void *user_data);


/* Initialization */
gint regexp_module_init (struct config_file *cfg, struct module_ctx **ctx);
gint regexp_module_config (struct config_file *cfg);
gint regexp_module_reconfig (struct config_file *cfg);

module_t regexp_module = {
	"regexp",
	regexp_module_init,
	regexp_module_config,
	regexp_module_reconfig
};

/* Task cache functions */
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
static GStaticMutex task_cache_mtx =  G_STATIC_MUTEX_INIT;
#else
G_LOCK_DEFINE (task_cache_mtx);
#endif

void
task_cache_add (struct rspamd_task *task, struct rspamd_regexp *re, gint32 result)
{
	if (result == 0) {
		result = -1;
	}
	/* Avoid concurrenting inserting of results */
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
	g_static_mutex_lock (&task_cache_mtx);
#else
	G_LOCK (task_cache_mtx);
#endif
	g_hash_table_insert (task->re_cache, re->regexp_text, GINT_TO_POINTER (result));
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
	g_static_mutex_unlock (&task_cache_mtx);
#else
	G_UNLOCK (task_cache_mtx);
#endif
}

gint32
task_cache_check (struct rspamd_task *task, struct rspamd_regexp *re)
{
	gpointer                        res;
	gint32                          r;

#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
	g_static_mutex_lock (&task_cache_mtx);
#else
	G_LOCK (task_cache_mtx);
#endif
	if ((res = g_hash_table_lookup (task->re_cache, re->regexp_text)) != NULL) {
		r = GPOINTER_TO_INT (res);
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
		g_static_mutex_unlock (&task_cache_mtx);
#else
		G_UNLOCK (task_cache_mtx);
#endif
		if (r == -1) {
			return 0;
		}
		return 1;
	}
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
	g_static_mutex_unlock (&task_cache_mtx);
#else
	G_UNLOCK (task_cache_mtx);
#endif
	return -1;
}


static gint
luaopen_regexp (lua_State * L)
{
	luaL_register (L, "rspamd_regexp", regexplib_m);

	return 1;
}

static void 
regexp_dynamic_insert_result (struct rspamd_task *task, void *user_data)
{
	gchar                           *symbol = user_data;
		
	insert_result (task, symbol, 1, NULL);
}

/*
 * Utility functions for matching exact number of regexps
 */
typedef gboolean (*int_compare_func) (gint a, gint b);
static gboolean
op_equal (gint a, gint b)
{
	return a == b;
}
static gboolean
op_more (gint a, gint b)
{
	return a > b;
}
static gboolean
op_less (gint a, gint b)
{
	return a < b;
}
static gboolean
op_more_equal (gint a, gint b)
{
	return a >= b;
}
static gboolean
op_less_equal (gint a, gint b)
{
	return a <= b;
}

/*
 * Process ip and mask of dynamic regexp
 */
static gboolean
parse_regexp_ipmask (const gchar *begin, struct dynamic_map_item *addr)
{
	const gchar                    *pos;
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
				if (p - ip_buf >= (gint)sizeof (ip_buf) || dots > 3) {
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
read_regexp_expression (rspamd_mempool_t * pool, struct regexp_module_item *chain,
		const gchar *symbol, const gchar *line, gboolean raw_mode)
{
	struct expression              *e, *cur;

	e = parse_expression (pool, (gchar *)line);
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
gchar                         *
json_regexp_read_cb (rspamd_mempool_t * pool, gchar * chunk, gint len, struct map_cb_data *data)
{
	struct regexp_json_buf                *jb;
	gint                            free, off;

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
json_regexp_fin_cb (rspamd_mempool_t * pool, struct map_cb_data *data)
{
	struct regexp_json_buf         *jb;
	guint                           nelts, i, j;
	json_t                         *js, *cur_elt, *cur_nm, *it_val;
	json_error_t                    je;
	gchar                           *cur_rule, *cur_symbol;
	double                          score;
	struct regexp_module_item      *cur_item;
	GList                          *cur_networks = NULL;
	struct dynamic_map_item        *cur_nitem;
	rspamd_mempool_t                  *new_pool;

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
	
	new_pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());
		
	remove_dynamic_rules (jb->cfg->cache);
	if (regexp_module_ctx->dynamic_pool != NULL) {
		rspamd_mempool_delete (regexp_module_ctx->dynamic_pool);
	}
	regexp_module_ctx->dynamic_pool = new_pool;

	nelts = json_array_size (js);
	for (i = 0; i < nelts; i++) {
		cur_networks = NULL;
		cur_rule = NULL;

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
		cur_symbol = rspamd_mempool_strdup (new_pool, json_string_value (cur_nm)); 
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
			cur_rule = rspamd_mempool_strdup (new_pool, json_string_value (cur_nm));
		}
		/* Networks array */
		cur_nm = json_object_get (cur_elt, "networks");
		if (cur_nm != NULL && json_is_array (cur_nm)) {
			for (j = 0; j < json_array_size (cur_nm); j++) {
				it_val = json_array_get (cur_nm, i);
				if (it_val && json_is_string (it_val)) {
					cur_nitem = rspamd_mempool_alloc (new_pool, sizeof (struct dynamic_map_item));
					if (parse_regexp_ipmask (json_string_value (it_val), cur_nitem)) {
						cur_networks = g_list_prepend (cur_networks, cur_nitem);
					}
				}
			}
		}
		if (cur_rule) {
			/* Dynamic rule has rule option */
			cur_item = rspamd_mempool_alloc0 (new_pool, sizeof (struct regexp_module_item));
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

	regexp_module_ctx->regexp_pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());
	regexp_module_ctx->dynamic_pool = NULL;
	regexp_module_ctx->autolearn_symbols = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	regexp_module_ctx->workers = NULL;

	*ctx = (struct module_ctx *)regexp_module_ctx;
	register_expression_function ("regexp_match_number", rspamd_regexp_match_number, NULL);
	register_expression_function ("regexp_occurs_number", rspamd_regexp_occurs_number, NULL);
	register_expression_function ("raw_header_exists", rspamd_raw_header_exists, NULL);
	register_expression_function ("check_smtp_data", rspamd_check_smtp_data, NULL);
	register_expression_function ("content_type_is_type", rspamd_content_type_is_type, NULL);
	register_expression_function ("content_type_is_subtype", rspamd_content_type_is_subtype, NULL);
	register_expression_function ("content_type_has_param", rspamd_content_type_has_param, NULL);
	register_expression_function ("content_type_compare_param", rspamd_content_type_compare_param, NULL);
	register_expression_function ("has_content_part", rspamd_has_content_part, NULL);
	register_expression_function ("has_content_part_len", rspamd_has_content_part_len, NULL);

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

	p = rspamd_mempool_strdup (regexp_module_ctx->regexp_pool, value);
	d = rspamd_mempool_alloc (regexp_module_ctx->regexp_pool, sizeof (struct autolearn_data));

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
	struct regexp_module_item      *cur_item;
	const ucl_object_t             *sec, *value;
	ucl_object_iter_t               it = NULL;
	gint                            res = TRUE;
	struct regexp_json_buf         *jb, **pjb;


	sec = ucl_object_find_key (cfg->rcl_obj, "regexp");
	if (sec == NULL) {
		msg_err ("regexp module enabled, but no rules are defined");
		return TRUE;
	}

	regexp_module_ctx->max_size = 0;
	regexp_module_ctx->max_threads = 0;
	regexp_module_ctx->workers = NULL;

	while ((value = ucl_iterate_object (sec, &it, true)) != NULL) {
		if (g_ascii_strncasecmp (ucl_object_key (value), "autolearn", sizeof ("autolearn") - 1) == 0) {
			parse_autolearn_param (ucl_object_key (value), ucl_obj_tostring (value), cfg);
		}
		else if (g_ascii_strncasecmp (ucl_object_key (value), "dynamic_rules", sizeof ("dynamic_rules") - 1) == 0) {
			jb = g_malloc (sizeof (struct regexp_json_buf));
			pjb = g_malloc (sizeof (struct regexp_json_buf *));
			jb->buf = NULL;
			jb->cfg = cfg;
			*pjb = jb;
			if (!add_map (cfg, ucl_obj_tostring (value),
					"Dynamic regexp rules", json_regexp_read_cb, json_regexp_fin_cb,
					(void **)pjb)) {
				msg_err ("cannot add map %s", ucl_obj_tostring (value));
			}
		}
		else if (g_ascii_strncasecmp (ucl_object_key (value), "max_size", sizeof ("max_size") - 1) == 0) {
			regexp_module_ctx->max_size = ucl_obj_toint (value);
		}
		else if (g_ascii_strncasecmp (ucl_object_key (value), "max_threads", sizeof ("max_threads") - 1) == 0) {
			regexp_module_ctx->max_threads = ucl_obj_toint (value);
		}
		else if (value->type == UCL_STRING) {
			cur_item = rspamd_mempool_alloc0 (regexp_module_ctx->regexp_pool, sizeof (struct regexp_module_item));
			cur_item->symbol = ucl_object_key (value);
			if (!read_regexp_expression (regexp_module_ctx->regexp_pool, cur_item, ucl_object_key (value),
					ucl_obj_tostring (value), cfg->raw_mode)) {
				res = FALSE;
			}
			register_symbol (&cfg->cache, cur_item->symbol, 1, process_regexp_item, cur_item);
		}
		else if (value->type == UCL_USERDATA) {
			cur_item = rspamd_mempool_alloc0 (regexp_module_ctx->regexp_pool, sizeof (struct regexp_module_item));
			cur_item->symbol = ucl_object_key (value);
			cur_item->lua_function = value->value.ud;
			register_symbol (&cfg->cache, cur_item->symbol, 1, process_regexp_item, cur_item);
		}
		else {
			msg_warn ("unknown type of attribute %s for regexp module", ucl_object_key (value));
		}
	}

	return res;
}

gint
regexp_module_reconfig (struct config_file *cfg)
{
	rspamd_mempool_delete (regexp_module_ctx->regexp_pool);
	regexp_module_ctx->regexp_pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());

	return regexp_module_config (cfg);
}

struct url_regexp_param {
	struct rspamd_task             *task;
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
process_regexp (struct rspamd_regexp *re, struct rspamd_task *task, const gchar *additional,
		gint limit, int_compare_func f)
{
	guint8                         *ct;
	gsize                           clen;
	gint                            r, passed = 0, start, end, old;
	gboolean                        matched = FALSE;

	GList                          *cur, *headerlist;
	GRegex                         *regexp;
	GMatchInfo                     *info;
	GError                         *err = NULL;
	struct url_regexp_param         callback_param = {
		.task = task,
		.re = re,
		.found = FALSE
	};
	struct mime_text_part          *part;
	struct raw_header              *rh;

	if (re == NULL) {
		msg_info ("invalid regexp passed");
		return 0;
	}

	callback_param.regexp = re->regexp;
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
		/* Check header's name */
		if (re->header == NULL) {
			msg_info ("header regexp without header name: '%s'", re->regexp_text);
			task_cache_add (task, re, 0);
			return 0;
		}
		debug_task ("checking header regexp: %s = %s", re->header, re->regexp_text);

		/* Get list of specified headers */
		headerlist = message_get_header (task->task_pool, task->message, re->header, re->is_strong);
		if (headerlist == NULL) {
			/* Header is not found */
			if (G_UNLIKELY (re->is_test)) {
				msg_info ("process test regexp %s for header %s returned FALSE: no header found", re->regexp_text, re->header);
			}
			task_cache_add (task, re, 0);
			return 0;
		}
		else {
			rspamd_mempool_add_destructor (task->task_pool, (rspamd_mempool_destruct_t)g_list_free, headerlist);
			/* Check whether we have regexp for it */
			if (re->regexp == NULL) {
				debug_task ("regexp contains only header and it is found %s", re->header);
				task_cache_add (task, re, 1);
				return 1;
			}
			/* Iterate throught headers */
			cur = headerlist;
			while (cur) {
				debug_task ("found header \"%s\" with value \"%s\"", re->header, (const gchar *)cur->data);
				/* Try to match regexp */
				if (!re->is_raw) {
					/* Validate input */
					if (!cur->data || !g_utf8_validate (cur->data, -1, NULL)) {
						cur = g_list_next (cur);
						continue;
					}
				}
				if (cur->data && g_regex_match_full (re->regexp, cur->data, -1, 0, 0, NULL, &err) == TRUE) {
					if (G_UNLIKELY (re->is_test)) {
						msg_info ("process test regexp %s for header %s with value '%s' returned TRUE", re->regexp_text, re->header, (const gchar *)cur->data);
					}
					if (f != NULL && limit > 1) {
						/* If we have limit count, increase passed count and compare with limit */
						if (f (++passed, limit)) {
							task_cache_add (task, re, 1);
							return 1;
						}
					}
					else {
						task_cache_add (task, re, 1);
						return 1;
					}
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
		/* Iterate throught text parts */
		cur = g_list_first (task->text_parts);
		while (cur) {
			part = (struct mime_text_part *)cur->data;
			/* Skip empty parts */
			if (part->is_empty) {
				cur = g_list_next (cur);
				continue;
			}
			/* Skip too large parts */
			if (regexp_module_ctx->max_size != 0 && part->content->len > regexp_module_ctx->max_size) {
				msg_info ("<%s> skip part of size %Hud", task->message_id, part->content->len);
				cur = g_list_next (cur);
				continue;
			}
			/* Check raw flags */
			if (part->is_raw) {
				regexp = re->raw_regexp;
			}
			else {
				/* This time there is no need to validate anything as conversion succeed only for valid characters */
				regexp = re->regexp;
			}
			/* Select data for regexp */
			if (re->is_raw) {
				ct = part->orig->data;
				clen = part->orig->len;
			}
			else {
				ct = part->content->data;
				clen = part->content->len;
			}
			/* If we have limit, apply regexp so much times as we can */
			if (f != NULL && limit > 1) {
				end = 0;
				while ((matched = g_regex_match_full (regexp, ct + end + 1, clen - end - 1, 0, 0, &info, &err)) == TRUE) {
					if (G_UNLIKELY (re->is_test)) {
						msg_info ("process test regexp %s for mime part of length %d returned TRUE",
								re->regexp_text,
								(gint)clen,
								end);
					}
					if (f (++passed, limit)) {
						task_cache_add (task, re, 1);
						return 1;
					}
					else {
						/* Match not found, skip further cycles */
						old = end;
						if (!g_match_info_fetch_pos (info, 0, &start, &end) || end <= 0) {
							break;
						}
						end += old;
					}
					g_match_info_free (info);
				}
				g_match_info_free (info);
			}
			else {
				if (g_regex_match_full (regexp, ct, clen, 0, 0, NULL, &err) == TRUE) {
					if (G_UNLIKELY (re->is_test)) {
						msg_info ("process test regexp %s for mime part of length %d returned TRUE", re->regexp_text,
								(gint)clen);
					}
					task_cache_add (task, re, 1);
					return 1;
				}

			}
			if (!matched && G_UNLIKELY (re->is_test)) {
				msg_info ("process test regexp %s for mime part of length %d returned FALSE", re->regexp_text,
						(gint)clen);
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
		regexp = re->raw_regexp;
		ct = task->msg->str;
		clen = task->msg->len;

		if (regexp_module_ctx->max_size != 0 && clen > regexp_module_ctx->max_size) {
			msg_info ("<%s> skip message of size %Hz", task->message_id, clen);
			return 0;
		}
		/* If we have limit, apply regexp so much times as we can */
		if (f != NULL && limit > 1) {
			end = 0;
			while ((matched = g_regex_match_full (regexp, ct + end + 1, clen - end - 1, 0, 0, &info, &err)) == TRUE) {
				if (G_UNLIKELY (re->is_test)) {
					msg_info ("process test regexp %s for mime part of length %d returned TRUE", re->regexp_text,
							(gint)clen);
				}
				if (f (++passed, limit)) {
					task_cache_add (task, re, 1);
					return 1;
				}
				else {
					/* Match not found, skip further cycles */
					old = end;
					if (!g_match_info_fetch_pos (info, 0, &start, &end) || end <= 0) {
						break;
					}
					old += end;
				}
				g_match_info_free (info);
			}
			g_match_info_free (info);
		}
		else {
			if (g_regex_match_full (regexp, ct, clen, 0, 0, NULL, &err) == TRUE) {
				if (G_UNLIKELY (re->is_test)) {
					msg_info ("process test regexp %s for message part of length %d returned TRUE", re->regexp_text,
							(gint)clen);
				}
				task_cache_add (task, re, 1);
				return 1;
			}

		}
		if (!matched && G_UNLIKELY (re->is_test)) {
			msg_info ("process test regexp %s for message part of length %d returned FALSE", re->regexp_text,
					(gint)clen);
		}
		if (err != NULL) {
			msg_info ("error occured while processing regexp \"%s\": %s", re->regexp_text, err->message);
		}
		task_cache_add (task, re, 0);
		return 0;
	case REGEXP_URL:
		debug_task ("checking url regexp: %s", re->regexp_text);
		if (f != NULL && limit > 1) {
			/*XXX: add support of it */
			msg_warn ("numbered matches are not supported for url regexp");
		}
		regexp = re->regexp;
		callback_param.task = task;
		callback_param.regexp = regexp;
		callback_param.re = re;
		callback_param.found = FALSE;
		if (task->urls) {
			g_tree_foreach (task->urls, tree_url_callback, &callback_param);
		}
		if (task->emails && callback_param.found == FALSE) {
			g_tree_foreach (task->emails, tree_url_callback, &callback_param);
		}
		if (callback_param.found == FALSE) {
			task_cache_add (task, re, 0);
		}
		return 0;
	case REGEXP_RAW_HEADER:
		debug_task ("checking for raw header: %s with regexp: %s", re->header, re->regexp_text);
		/* Check header's name */
		if (re->header == NULL) {
			msg_info ("header regexp without header name: '%s'", re->regexp_text);
			task_cache_add (task, re, 0);
			return 0;
		}
		debug_task ("checking header regexp: %s = %s", re->header, re->regexp_text);

		/* Get list of specified headers */
		headerlist = message_get_raw_header (task, re->header, re->is_strong);
		if (headerlist == NULL) {
			/* Header is not found */
			if (G_UNLIKELY (re->is_test)) {
				msg_info ("process test regexp %s for header %s returned FALSE: no header found", re->regexp_text, re->header);
			}
			task_cache_add (task, re, 0);
			return 0;
		}
		else {
			/* Check whether we have regexp for it */
			if (re->regexp == NULL) {
				debug_task ("regexp contains only header and it is found %s", re->header);
				task_cache_add (task, re, 1);
				return 1;
			}
			/* Iterate throught headers */
			cur = headerlist;
			while (cur) {
				debug_task ("found header \"%s\" with value \"%s\"", re->header, (const gchar *)cur->data);
				rh = cur->data;
				/* Try to match regexp */
				if (!re->is_raw) {
					/* Validate input */
					if (!rh->value || !g_utf8_validate (rh->value, -1, NULL)) {
						cur = g_list_next (cur);
						continue;
					}
				}
				if (rh->value && g_regex_match_full (re->regexp, rh->value, -1, 0, 0, NULL, &err) == TRUE) {
					if (G_UNLIKELY (re->is_test)) {
						msg_info ("process test regexp %s for header %s with value '%s' returned TRUE", re->regexp_text, re->header, (const gchar *)cur->data);
					}
					if (f != NULL && limit > 1) {
						/* If we have limit count, increase passed count and compare with limit */
						if (f (++passed, limit)) {
							task_cache_add (task, re, 1);
							return 1;
						}
					}
					else {
						task_cache_add (task, re, 1);
						return 1;
					}
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
	default:
		msg_warn ("bad error detected: %p is not a valid regexp object", re);
	}

	/* Not reached */
	return 0;
}

static gboolean
maybe_call_lua_function (const gchar *name, struct rspamd_task *task, lua_State *L)
{
	struct rspamd_task            **ptask;
	gboolean                        res;

	lua_getglobal (L, name);
	if (lua_isfunction (L, -1)) {
		ptask = lua_newuserdata (L, sizeof (struct rspamd_task *));
		lua_setclass (L, "rspamd{task}", -1);
		*ptask = task;
		/* Call function */
		if (lua_pcall (L, 1, 1, 0) != 0) {
			msg_info ("call to %s failed: %s", (gchar *)name, lua_tostring (L, -1));
			return FALSE;
		}
		res = lua_toboolean (L, -1);
		lua_pop (L, 1);
		return res;
	}
	else {
		lua_pop (L, 1);
	}
	return FALSE;
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
process_regexp_expression (struct expression *expr, const gchar *symbol, struct rspamd_task *task,
		const gchar *additional, struct lua_locked_state *nL)
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
			cur = process_regexp ((struct rspamd_regexp *)it->content.operand, task, additional, 0, NULL);
			debug_task ("regexp %s found", cur ? "is" : "is not");
			if (try_optimize) {
				try_optimize = optimize_regexp_expression (&it, stack, cur);
			}
			else {
				g_queue_push_head (stack, GSIZE_TO_POINTER (cur));
			}
		}
		else if (it->type == EXPR_FUNCTION) {
			if (nL) {
				rspamd_mutex_lock (nL->m);
				cur = (gsize) call_expression_function ((struct expression_function *)it->content.operand, task, nL->L);
				rspamd_mutex_unlock (nL->m);
			}
			else {
				cur = (gsize) call_expression_function ((struct expression_function *)it->content.operand, task, task->cfg->lua_state);
			}
			debug_task ("function %s returned %s", ((struct expression_function *)it->content.operand)->name, cur ? "true" : "false");
			if (try_optimize) {
				try_optimize = optimize_regexp_expression (&it, stack, cur);
			}
			else {
				g_queue_push_head (stack, GSIZE_TO_POINTER (cur));
			}
		}
		else if (it->type == EXPR_STR) {
			/* This may be lua function, try to call it */
			if (nL) {
				rspamd_mutex_lock (nL->m);
				cur = maybe_call_lua_function ((const gchar*)it->content.operand, task, nL->L);
				rspamd_mutex_unlock (nL->m);
			}
			else {
				cur = maybe_call_lua_function ((const gchar*)it->content.operand, task, task->cfg->lua_state);
			}
			debug_task ("function %s returned %s", (const gchar *)it->content.operand, cur ? "true" : "false");
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

struct regexp_threaded_ud {
	struct regexp_module_item *item;
	struct rspamd_task *task;
};

static void
process_regexp_item_threaded (gpointer data, gpointer user_data)
{
	struct regexp_threaded_ud	   *ud = data;
	struct lua_locked_state		   *nL = user_data;

	/* Process expression */
	if (process_regexp_expression (ud->item->expr, ud->item->symbol, ud->task, NULL, nL)) {
		g_mutex_lock (workers_mtx);
		insert_result (ud->task, ud->item->symbol, 1, NULL);
		g_mutex_unlock (workers_mtx);
	}
	remove_async_thread (ud->task->s);
}

static void
process_regexp_item (struct rspamd_task *task, void *user_data)
{
	struct regexp_module_item      *item = user_data;
	gboolean                        res = FALSE;
	struct regexp_threaded_ud	   *thr_ud;
	GError						   *err = NULL;
	struct lua_locked_state		   *nL;


	if (!item->lua_function && regexp_module_ctx->max_threads > 1) {
		if (regexp_module_ctx->workers == NULL) {
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
# if GLIB_MINOR_VERSION > 20
			if (! g_thread_get_initialized ()) {
				g_thread_init (NULL);
			}
# else
			g_thread_init (NULL);
# endif
			workers_mtx = g_mutex_new ();
#else
			workers_mtx = rspamd_mempool_alloc (regexp_module_ctx->regexp_pool, sizeof (GMutex));
			g_mutex_init (workers_mtx);
#endif
			nL = init_lua_locked (task->cfg);
			luaopen_regexp (nL->L);
			regexp_module_ctx->workers = g_thread_pool_new (process_regexp_item_threaded,
					nL, regexp_module_ctx->max_threads, TRUE, &err);
			if (err != NULL) {
				msg_err ("thread pool creation failed: %s", err->message);
				regexp_module_ctx->max_threads = 0;
				return;
			}
		}
		thr_ud = rspamd_mempool_alloc (task->task_pool, sizeof (struct regexp_threaded_ud));
		thr_ud->item = item;
		thr_ud->task = task;


		register_async_thread (task->s);
		g_thread_pool_push (regexp_module_ctx->workers, thr_ud, &err);
		if (err != NULL) {
			msg_err ("error pushing task to the regexp thread pool: %s", err->message);
			remove_async_thread (task->s);
		}
	}
	else {
		/* Non-threaded version */
		if (item->lua_function) {
			/* Just call function */
			if (lua_call_expression_func (item->lua_function, task, NULL, &res) && res) {
				insert_result (task, item->symbol, 1, NULL);
			}
		}
		else {
			/* Process expression */
			if (process_regexp_expression (item->expr, item->symbol, task, NULL, NULL)) {
				insert_result (task, item->symbol, 1, NULL);
			}
		}
	}
}

static                          gboolean
rspamd_regexp_match_number (struct rspamd_task *task, GList * args, void *unused)
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
			if (process_regexp_expression (cur->data, "regexp_match_number", task, NULL, NULL)) {
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
rspamd_regexp_occurs_number (struct rspamd_task *task, GList * args, void *unused)
{
	gint                            limit;
	struct expression_argument     *arg;
	struct rspamd_regexp           *re;
	gchar                          *param, *err_str, op;
	int_compare_func                f = NULL;

	if (args == NULL || args->next == NULL) {
		msg_warn ("wrong number of parameters to function, must be 2");
		return FALSE;
	}

	arg = get_function_arg (args->data, task, TRUE);
	if ((re = re_cache_check (arg->data, task->cfg->cfg_pool)) == NULL) {
		re = parse_regexp (task->cfg->cfg_pool, arg->data, task->cfg->raw_mode);
		if (!re) {
			msg_err ("cannot parse given regexp: %s", (gchar *)arg->data);
			return FALSE;
		}
	}

	arg = get_function_arg (args->next->data, task, TRUE);
	param = arg->data;
	op = *param;
	if (g_ascii_isdigit (op)) {
		op = '=';
	}
	else {
		param ++;
	}
	switch (op) {
	case '>':
		if (*param == '=') {
			f = op_more_equal;
			param ++;
		}
		else {
			f = op_more;
		}
		break;
	case '<':
		if (*param == '=') {
			f = op_less_equal;
			param ++;
		}
		else {
			f = op_less;
		}
		break;
	case '=':
		f = op_equal;
		break;
	default:
		msg_err ("wrong operation character: %c, assumed '=', '>', '<', '>=', '<=' or empty op", op);
		return FALSE;
	}

	limit = strtoul (param, &err_str, 10);
	if (*err_str != 0) {
		msg_err ("wrong numeric: %s at position: %s", param, err_str);
		return FALSE;
	}

	return process_regexp (re, task, NULL, limit, f);
}
static                          gboolean
rspamd_raw_header_exists (struct rspamd_task *task, GList * args, void *unused)
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

	return g_hash_table_lookup (task->raw_headers, arg->data) != NULL;
}

static gboolean
match_smtp_data (struct rspamd_task *task, const gchar *re_text, const gchar *what)
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
rspamd_check_smtp_data (struct rspamd_task *task, GList * args, void *unused)
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
		else if (arg != NULL) {
			if (what != NULL) {
				if (process_regexp_expression (arg->data, "regexp_check_smtp_data", task, what, NULL)) {
					return TRUE;
				}
			}
			else {
				while (rcpt_list) {
					if (process_regexp_expression (arg->data, "regexp_check_smtp_data", task, rcpt_list->data, NULL)) {
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
	struct rspamd_task             *task;
	const gchar                    *re_text;
	struct rspamd_regexp           *re;
	gint                            r = 0;

	luaL_argcheck (L, ud != NULL, 1, "'task' expected");
	task = ud ? *((struct rspamd_task **)ud) : NULL;
	re_text = luaL_checkstring (L, 2);

	/* This is a regexp */
	if (task != NULL) {
		if ((re = re_cache_check (re_text, task->cfg->cfg_pool)) == NULL) {
			re = parse_regexp (task->cfg->cfg_pool, (gchar *)re_text, task->cfg->raw_mode);
			if (re == NULL) {
				msg_warn ("cannot compile regexp for function");
				return FALSE;
			}
			re_cache_add ((gchar *)re_text, re, task->cfg->cfg_pool);
		}
		r = process_regexp (re, task, NULL, 0, NULL);
	}
	lua_pushboolean (L, r == 1);

	return 1;
}

static gboolean
rspamd_content_type_compare_param (struct rspamd_task * task, GList * args, void *unused)
{
	gchar                           *param_name, *param_pattern;
	const gchar                     *param_data;
	struct rspamd_regexp           *re;
	struct expression_argument     *arg, *arg1;
	GMimeObject                    *part;
	GMimeContentType               *ct;
	gint                            r;
	gboolean                        recursive = FALSE, result = FALSE;
	GList                          *cur = NULL;
	struct mime_part               *cur_part;

	if (args == NULL) {
		msg_warn ("no parameters to function");
		return FALSE;
	}
	arg = get_function_arg (args->data, task, TRUE);
	param_name = arg->data;
	args = g_list_next (args);
	if (args == NULL) {
		msg_warn ("too few params to function");
		return FALSE;
	}
	arg = get_function_arg (args->data, task, TRUE);
	param_pattern = arg->data;


	part = g_mime_message_get_mime_part (task->message);
	if (part) {
		ct = (GMimeContentType *)g_mime_object_get_content_type (part);
		if (args->next) {
			args = g_list_next (args);
			arg1 = get_function_arg (args->data, task, TRUE);
			if (g_ascii_strncasecmp (arg1->data, "true", sizeof ("true") - 1) == 0) {
				recursive = TRUE;
			}
		}
		else {
			/*
			 * If user did not specify argument, let's assume that he wants
			 * recursive search if mime part is multipart/mixed
			 */
			if (g_mime_content_type_is_type (ct, "multipart", "*")) {
				recursive = TRUE;
			}
		}

		if (recursive) {
			cur = task->parts;
		}

#ifndef GMIME24
		g_object_unref (part);
#endif
		for (;;) {
			if ((param_data = g_mime_content_type_get_parameter ((GMimeContentType *)ct, param_name)) == NULL) {
				result = FALSE;
			}
			else {
				if (*param_pattern == '/') {
					/* This is regexp, so compile and create g_regexp object */
					if ((re = re_cache_check (param_pattern, task->cfg->cfg_pool)) == NULL) {
						re = parse_regexp (task->cfg->cfg_pool, param_pattern, task->cfg->raw_mode);
						if (re == NULL) {
							msg_warn ("cannot compile regexp for function");
							return FALSE;
						}
						re_cache_add (param_pattern, re, task->cfg->cfg_pool);
					}
					if ((r = task_cache_check (task, re)) == -1) {
						if (g_regex_match (re->regexp, param_data, 0, NULL) == TRUE) {
							task_cache_add (task, re, 1);
							return TRUE;
						}
						task_cache_add (task, re, 0);
					}
					else {

					}
				}
				else {
					/* Just do strcasecmp */
					if (g_ascii_strcasecmp (param_data, param_pattern) == 0) {
						return TRUE;
					}
				}
			}
			/* Get next part */
			if (! recursive) {
				return result;
			}
			else if (cur != NULL) {
				cur_part = cur->data;
				if (cur_part->type != NULL) {
					ct = cur_part->type;
				}
				cur = g_list_next (cur);
			}
			else {
				/* All is done */
				return result;
			}
		}

	}

	return FALSE;
}

static gboolean
rspamd_content_type_has_param (struct rspamd_task * task, GList * args, void *unused)
{
	gchar                           *param_name;
	const gchar                     *param_data;
	struct expression_argument     *arg, *arg1;
	GMimeObject                    *part;
	GMimeContentType               *ct;
	gboolean                        recursive = FALSE, result = FALSE;
	GList                          *cur = NULL;
	struct mime_part               *cur_part;

	if (args == NULL) {
		msg_warn ("no parameters to function");
		return FALSE;
	}
	arg = get_function_arg (args->data, task, TRUE);
	param_name = arg->data;

	part = g_mime_message_get_mime_part (task->message);
	if (part) {
		ct = (GMimeContentType *)g_mime_object_get_content_type (part);
		if (args->next) {
			args = g_list_next (args);
			arg1 = get_function_arg (args->data, task, TRUE);
			if (g_ascii_strncasecmp (arg1->data, "true", sizeof ("true") - 1) == 0) {
				recursive = TRUE;
			}
		}
		else {
			/*
			 * If user did not specify argument, let's assume that he wants
			 * recursive search if mime part is multipart/mixed
			 */
			if (g_mime_content_type_is_type (ct, "multipart", "*")) {
				recursive = TRUE;
			}
		}

		if (recursive) {
			cur = task->parts;
		}

#ifndef GMIME24
		g_object_unref (part);
#endif
		for (;;) {
			if ((param_data = g_mime_content_type_get_parameter ((GMimeContentType *)ct, param_name)) != NULL) {
				return TRUE;
			}
			/* Get next part */
			if (! recursive) {
				return result;
			}
			else if (cur != NULL) {
				cur_part = cur->data;
				if (cur_part->type != NULL) {
					ct = cur_part->type;
				}
				cur = g_list_next (cur);
			}
			else {
				/* All is done */
				return result;
			}
		}

	}

	return TRUE;
}

static gboolean
rspamd_content_type_is_subtype (struct rspamd_task *task, GList * args, void *unused)
{
	gchar                          *param_pattern;
	struct rspamd_regexp           *re;
	struct expression_argument     *arg, *arg1;
	GMimeObject                    *part;
	GMimeContentType               *ct;
	gint                            r;
	gboolean                        recursive = FALSE, result = FALSE;
	GList                          *cur = NULL;
	struct mime_part               *cur_part;

	if (args == NULL) {
		msg_warn ("no parameters to function");
		return FALSE;
	}
	arg = get_function_arg (args->data, task, TRUE);
	param_pattern = arg->data;

	part = g_mime_message_get_mime_part (task->message);
	if (part) {
		ct = (GMimeContentType *)g_mime_object_get_content_type (part);
		if (args->next) {
			args = g_list_next (args);
			arg1 = get_function_arg (args->data, task, TRUE);
			if (g_ascii_strncasecmp (arg1->data, "true", sizeof ("true") - 1) == 0) {
				recursive = TRUE;
			}
		}
		else {
			/*
			 * If user did not specify argument, let's assume that he wants
			 * recursive search if mime part is multipart/mixed
			 */
			if (g_mime_content_type_is_type (ct, "multipart", "*")) {
				recursive = TRUE;
			}
		}

		if (recursive) {
			cur = task->parts;
		}

#ifndef GMIME24
		g_object_unref (part);
#endif
		for (;;) {
			if (*param_pattern == '/') {
				/* This is regexp, so compile and create g_regexp object */
				if ((re = re_cache_check (param_pattern, task->cfg->cfg_pool)) == NULL) {
					re = parse_regexp (task->cfg->cfg_pool, param_pattern, task->cfg->raw_mode);
					if (re == NULL) {
						msg_warn ("cannot compile regexp for function");
						return FALSE;
					}
					re_cache_add (param_pattern, re, task->cfg->cfg_pool);
				}
				if ((r = task_cache_check (task, re)) == -1) {
					if (g_regex_match (re->regexp, ct->subtype, 0, NULL) == TRUE) {
						task_cache_add (task, re, 1);
						return TRUE;
					}
					task_cache_add (task, re, 0);
				}
				else {

				}
			}
			else {
				/* Just do strcasecmp */
				if (g_ascii_strcasecmp (ct->subtype, param_pattern) == 0) {
					return TRUE;
				}
			}
			/* Get next part */
			if (! recursive) {
				return result;
			}
			else if (cur != NULL) {
				cur_part = cur->data;
				if (cur_part->type != NULL) {
					ct = cur_part->type;
				}
				cur = g_list_next (cur);
			}
			else {
				/* All is done */
				return result;
			}
		}

	}

	return FALSE;
}

static gboolean
rspamd_content_type_is_type (struct rspamd_task * task, GList * args, void *unused)
{
	gchar                          *param_pattern;
	struct rspamd_regexp           *re;
	struct expression_argument     *arg, *arg1;
	GMimeObject                    *part;
	GMimeContentType               *ct;
	gint                            r;
	gboolean                        recursive = FALSE, result = FALSE;
	GList                          *cur = NULL;
	struct mime_part               *cur_part;

	if (args == NULL) {
		msg_warn ("no parameters to function");
		return FALSE;
	}
	arg = get_function_arg (args->data, task, TRUE);
	param_pattern = arg->data;


	part = g_mime_message_get_mime_part (task->message);
	if (part) {
		ct = (GMimeContentType *)g_mime_object_get_content_type (part);
		if (args->next) {
			args = g_list_next (args);
			arg1 = get_function_arg (args->data, task, TRUE);
			if (g_ascii_strncasecmp (arg1->data, "true", sizeof ("true") - 1) == 0) {
				recursive = TRUE;
			}
		}
		else {
			/*
			 * If user did not specify argument, let's assume that he wants
			 * recursive search if mime part is multipart/mixed
			 */
			if (g_mime_content_type_is_type (ct, "multipart", "*")) {
				recursive = TRUE;
			}
		}

		if (recursive) {
			cur = task->parts;
		}

#ifndef GMIME24
		g_object_unref (part);
#endif
		for (;;) {
			if (*param_pattern == '/') {
				/* This is regexp, so compile and create g_regexp object */
				if ((re = re_cache_check (param_pattern, task->cfg->cfg_pool)) == NULL) {
					re = parse_regexp (task->cfg->cfg_pool, param_pattern, task->cfg->raw_mode);
					if (re == NULL) {
						msg_warn ("cannot compile regexp for function");
						return FALSE;
					}
					re_cache_add (param_pattern, re, task->cfg->cfg_pool);
				}
				if ((r = task_cache_check (task, re)) == -1) {
					if (g_regex_match (re->regexp, ct->type, 0, NULL) == TRUE) {
						task_cache_add (task, re, 1);
						return TRUE;
					}
					task_cache_add (task, re, 0);
				}
				else {

				}
			}
			else {
				/* Just do strcasecmp */
				if (g_ascii_strcasecmp (ct->type, param_pattern) == 0) {
					return TRUE;
				}
			}
			/* Get next part */
			if (! recursive) {
				return result;
			}
			else if (cur != NULL) {
				cur_part = cur->data;
				if (cur_part->type != NULL) {
					ct = cur_part->type;
				}
				cur = g_list_next (cur);
			}
			else {
				/* All is done */
				return result;
			}
		}

	}

	return FALSE;
}

static                   gboolean
compare_subtype (struct rspamd_task *task, GMimeContentType * ct, gchar *subtype)
{
	struct rspamd_regexp           *re;
	gint                            r;

	if (subtype == NULL || ct == NULL) {
		msg_warn ("invalid parameters passed");
		return FALSE;
	}
	if (*subtype == '/') {
		/* This is regexp, so compile and create g_regexp object */
		if ((re = re_cache_check (subtype, task->cfg->cfg_pool)) == NULL) {
			re = parse_regexp (task->cfg->cfg_pool, subtype, task->cfg->raw_mode);
			if (re == NULL) {
				msg_warn ("cannot compile regexp for function");
				return FALSE;
			}
			re_cache_add (subtype, re, task->cfg->cfg_pool);
		}
		if ((r = task_cache_check (task, re)) == -1) {
			if (g_regex_match (re->regexp, subtype, 0, NULL) == TRUE) {
				task_cache_add (task, re, 1);
				return TRUE;
			}
			task_cache_add (task, re, 0);
		}
		else {
			return r == 1;
		}
	}
	else {
		/* Just do strcasecmp */
		if (ct->subtype && g_ascii_strcasecmp (ct->subtype, subtype) == 0) {
			return TRUE;
		}
	}

	return FALSE;
}

static                   gboolean
compare_len (struct mime_part *part, guint min, guint max)
{
	if (min == 0 && max == 0) {
		return TRUE;
	}

	if (min == 0) {
		return part->content->len <= max;
	}
	else if (max == 0) {
		return part->content->len >= min;
	}
	else {
		return part->content->len >= min && part->content->len <= max;
	}
}

static gboolean
common_has_content_part (struct rspamd_task * task, gchar *param_type, gchar *param_subtype, gint min_len, gint max_len)
{
	struct rspamd_regexp           *re;
	struct mime_part               *part;
	GList                          *cur;
	GMimeContentType               *ct;
	gint                            r;

	cur = g_list_first (task->parts);
	while (cur) {
		part = cur->data;
		ct = part->type;
		if (ct == NULL) {
			cur = g_list_next (cur);
			continue;
		}

		if (*param_type == '/') {
			/* This is regexp, so compile and create g_regexp object */
			if ((re = re_cache_check (param_type, task->cfg->cfg_pool)) == NULL) {
				re = parse_regexp (task->cfg->cfg_pool, param_type, task->cfg->raw_mode);
				if (re == NULL) {
					msg_warn ("cannot compile regexp for function");
					cur = g_list_next (cur);
					continue;
				}
				re_cache_add (param_type, re, task->cfg->cfg_pool);
			}
			if ((r = task_cache_check (task, re)) == -1) {
				if (ct->type && g_regex_match (re->regexp, ct->type, 0, NULL) == TRUE) {
					if (param_subtype) {
						if (compare_subtype (task, ct, param_subtype)) {
							if (compare_len (part, min_len, max_len)) {
								return TRUE;
							}
						}
					}
					else {
						if (compare_len (part, min_len, max_len)) {
							return TRUE;
						}
					}
					task_cache_add (task, re, 1);
				}
				else {
					task_cache_add (task, re, 0);
				}
			}
			else {
				if (r == 1) {
					if (compare_subtype (task, ct, param_subtype)) {
						if (compare_len (part, min_len, max_len)) {
							return TRUE;
						}
					}
				}
			}
		}
		else {
			/* Just do strcasecmp */
			if (ct->type && g_ascii_strcasecmp (ct->type, param_type) == 0) {
				if (param_subtype) {
					if (compare_subtype (task, ct, param_subtype)) {
						if (compare_len (part, min_len, max_len)) {
							return TRUE;
						}
					}
				}
				else {
					if (compare_len (part, min_len, max_len)) {
						return TRUE;
					}
				}
			}
		}
		cur = g_list_next (cur);
	}

	return FALSE;
}

static gboolean
rspamd_has_content_part (struct rspamd_task * task, GList * args, void *unused)
{
	gchar                           *param_type = NULL, *param_subtype = NULL;
	struct expression_argument     *arg;

	if (args == NULL) {
		msg_warn ("no parameters to function");
		return FALSE;
	}

	arg = get_function_arg (args->data, task, TRUE);
	param_type = arg->data;
	args = args->next;
	if (args) {
		arg = args->data;
		param_subtype = arg->data;
	}

	return common_has_content_part (task, param_type, param_subtype, 0, 0);
}

static gboolean
rspamd_has_content_part_len (struct rspamd_task * task, GList * args, void *unused)
{
	gchar                           *param_type = NULL, *param_subtype = NULL;
	gint                            min = 0, max = 0;
	struct expression_argument     *arg;

	if (args == NULL) {
		msg_warn ("no parameters to function");
		return FALSE;
	}

	arg = get_function_arg (args->data, task, TRUE);
	param_type = arg->data;
	args = args->next;
	if (args) {
		arg = get_function_arg (args->data, task, TRUE);
		param_subtype = arg->data;
		args = args->next;
		if (args) {
			arg = get_function_arg (args->data, task, TRUE);
			errno = 0;
			min = strtoul (arg->data, NULL, 10);
			if (errno != 0) {
				msg_warn ("invalid numeric value '%s': %s", (gchar *)arg->data, strerror (errno));
				return FALSE;
			}
			args = args->next;
			if (args) {
				arg = get_function_arg (args->data, task, TRUE);
				max = strtoul (arg->data, NULL, 10);
				if (errno != 0) {
					msg_warn ("invalid numeric value '%s': %s", (gchar *)arg->data, strerror (errno));
					return FALSE;
				}
			}
		}
	}

	return common_has_content_part (task, param_type, param_subtype, min, max);
}
