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

/***MODULE:surbl
 * rspamd module that implements SURBL url checking
 *
 * Allowed options:
 * - weight (integer): weight of symbol
 * Redirecotor options:
 * - redirector (string): address of http redirector utility in format "host:port"
 * - redirector_connect_timeout (seconds): redirector connect timeout (default: 1s)
 * - redirector_read_timeout (seconds): timeout for reading data (default: 5s)
 * - redirector_hosts_map (map string): map that contains domains to check with redirector
 * Surbl options:
 * - exceptions (map string): map of domains that should be checked via surbl using 3 (e.g. somehost.domain.com)
 *   components of domain name instead of normal 2 (e.g. domain.com)
 * - whitelist (map string): map of domains that should be whitelisted for surbl checks
 * - max_urls (integer): maximum allowed number of urls in message to be checked
 * - suffix (string): surbl address (for example insecure-bl.rambler.ru), may contain %b if bits are used (read documentation about it)
 * - bit (string): describes a prefix for a single bit
 */

#include "config.h"
#include "libmime/message.h"
#include "libutil/hash.h"
#include "libutil/map.h"
#include "main.h"
#include "surbl.h"
#include "regexp.h"

#include "utlist.h"

static struct surbl_ctx *surbl_module_ctx = NULL;

static void surbl_test_url (struct rspamd_task *task, void *user_data);
static void dns_callback (struct rdns_reply *reply, gpointer arg);
static void process_dns_results (struct rspamd_task *task,
	struct suffix_item *suffix, gchar *url, guint32 addr);


#define NO_REGEXP (gpointer) - 1

#define SURBL_ERROR surbl_error_quark ()
#define WHITELIST_ERROR 0
#define CONVERSION_ERROR 1
#define DUPLICATE_ERROR 1
GQuark
surbl_error_quark (void)
{
	return g_quark_from_static_string ("surbl-error-quark");
}

/* Initialization */
gint surbl_module_init (struct rspamd_config *cfg, struct module_ctx **ctx);
gint surbl_module_config (struct rspamd_config *cfg);
gint surbl_module_reconfig (struct rspamd_config *cfg);

module_t surbl_module = {
	"surbl",
	surbl_module_init,
	surbl_module_config,
	surbl_module_reconfig,
	NULL
};

static void
exception_insert (gpointer st, gconstpointer key, gpointer value)
{
	GHashTable **t = st;
	gint level = 0;
	const gchar *p = key;
	rspamd_fstring_t *val;


	while (*p) {
		if (*p == '.') {
			level++;
		}
		p++;
	}
	if (level >= MAX_LEVELS) {
		msg_err ("invalid domain in exceptions list: %s, levels: %d",
			(gchar *)key,
			level);
		return;
	}

	val = g_malloc (sizeof (rspamd_fstring_t));
	val->begin = (gchar *)key;
	val->len = strlen (key);
	if (t[level] == NULL) {
		t[level] = g_hash_table_new_full (rspamd_fstring_hash,
				rspamd_fstring_equal,
				g_free,
				NULL);
	}
	g_hash_table_insert (t[level], val, value);
}

static gchar *
read_exceptions_list (rspamd_mempool_t * pool,
	gchar * chunk,
	gint len,
	struct map_cb_data *data)
{
	if (data->cur_data == NULL) {
		data->cur_data = rspamd_mempool_alloc0 (pool,
				sizeof (GHashTable *) * MAX_LEVELS);
	}
	return rspamd_parse_abstract_list (pool,
			   chunk,
			   len,
			   data,
			   (insert_func) exception_insert);
}

static void
fin_exceptions_list (rspamd_mempool_t * pool, struct map_cb_data *data)
{
	GHashTable **t;
	gint i;

	if (data->prev_data) {
		t = data->prev_data;
		for (i = 0; i < MAX_LEVELS; i++) {
			if (t[i] != NULL) {
				g_hash_table_destroy (t[i]);
			}
		}
	}
}

static void
redirector_insert (gpointer st, gconstpointer key, gpointer value)
{
	GHashTable *t = st;
	const gchar *p = key, *begin = key;
	gchar *new;
	gsize len;
	rspamd_regexp_t *re = NO_REGEXP;
	GError *err = NULL;
	guint idx;

	while (*p && !g_ascii_isspace (*p)) {
		p++;
	}

	len = p - begin;
	new = g_malloc (len + 1);
	memcpy (new, begin, len);
	new[len] = '\0';
	idx = surbl_module_ctx->redirector_ptrs->len;
	rspamd_trie_insert (surbl_module_ctx->redirector_trie, new, idx);
	g_ptr_array_add (surbl_module_ctx->redirector_ptrs, new);

	if (g_ascii_isspace (*p)) {
		while (g_ascii_isspace (*p) && *p) {
			p++;
		}
		if (*p) {
			re = rspamd_regexp_new (p,
					"ir",
					&err);
			if (re == NULL) {
				msg_warn ("could not read regexp: %s while reading regexp %s",
					err->message,
					p);
				g_error_free (err);
				re = NO_REGEXP;
			}
		}
	}
	g_hash_table_insert (t, new, re);
}

static void
redirector_item_free (gpointer p)
{
	rspamd_regexp_t *re;
	if (p != NULL && p != NO_REGEXP) {
		re = (rspamd_regexp_t *)p;
		rspamd_regexp_unref (re);
	}
}

static gchar *
read_redirectors_list (rspamd_mempool_t * pool,
	gchar * chunk,
	gint len,
	struct map_cb_data *data)
{
	if (data->cur_data == NULL) {
		data->cur_data = g_hash_table_new_full (rspamd_strcase_hash,
				rspamd_strcase_equal,
				g_free,
				redirector_item_free);
	}

	return rspamd_parse_abstract_list (pool,
			   chunk,
			   len,
			   data,
			   (insert_func) redirector_insert);
}

void
fin_redirectors_list (rspamd_mempool_t * pool, struct map_cb_data *data)
{
	if (data->prev_data) {
		g_hash_table_destroy (data->prev_data);
	}
}

gint
surbl_module_init (struct rspamd_config *cfg, struct module_ctx **ctx)
{
	surbl_module_ctx = g_malloc (sizeof (struct surbl_ctx));

	surbl_module_ctx->use_redirector = 0;
	surbl_module_ctx->suffixes = NULL;
	surbl_module_ctx->surbl_pool = rspamd_mempool_new (
		rspamd_mempool_suggest_size ());

	surbl_module_ctx->tld2_file = NULL;
	surbl_module_ctx->whitelist_file = NULL;
	surbl_module_ctx->redirectors = NULL;
	surbl_module_ctx->redirector_trie = rspamd_trie_create (TRUE);
	surbl_module_ctx->redirector_ptrs = g_ptr_array_new ();

	surbl_module_ctx->redirector_hosts = g_hash_table_new (rspamd_strcase_hash,
			rspamd_strcase_equal);
	surbl_module_ctx->whitelist = g_hash_table_new (rspamd_strcase_hash,
			rspamd_strcase_equal);
	/* Zero exceptions hashes */
	surbl_module_ctx->exceptions = rspamd_mempool_alloc0 (
		surbl_module_ctx->surbl_pool,
		MAX_LEVELS * sizeof (GHashTable *));
	/* Register destructors */
	rspamd_mempool_add_destructor (surbl_module_ctx->surbl_pool,
		(rspamd_mempool_destruct_t) g_hash_table_destroy,
		surbl_module_ctx->whitelist);
	rspamd_mempool_add_destructor (surbl_module_ctx->surbl_pool,
		(rspamd_mempool_destruct_t) g_hash_table_destroy,
		surbl_module_ctx->redirector_hosts);

	rspamd_mempool_add_destructor (surbl_module_ctx->surbl_pool,
		(rspamd_mempool_destruct_t) rspamd_trie_free,
		surbl_module_ctx->redirector_trie);
	rspamd_mempool_add_destructor (surbl_module_ctx->surbl_pool,
		(rspamd_mempool_destruct_t) g_ptr_array_unref,
		surbl_module_ctx->redirector_ptrs);

	*ctx = (struct module_ctx *)surbl_module_ctx;

	return 0;
}

/*
 * Register virtual symbols for suffixes with bit wildcard
 */
static void
register_bit_symbols (struct rspamd_config *cfg, struct suffix_item *suffix)
{
	GList *cur;
	struct surbl_bit_item *bit;

	if (suffix->bits != NULL) {
		/* Prepend bit to symbol */
		cur = g_list_first (suffix->bits);
		while (cur) {
			bit = (struct surbl_bit_item *)cur->data;
			register_virtual_symbol (&cfg->cache, bit->symbol, 1);
			cur = g_list_next (cur);
		}
	}
	else {
		register_virtual_symbol (&cfg->cache, suffix->symbol, 1);
	}
}

gint
surbl_module_config (struct rspamd_config *cfg)
{
	GList *cur_opt;
	struct suffix_item *new_suffix, *cur_suffix = NULL;
	struct surbl_bit_item *new_bit;

	const ucl_object_t *value, *cur, *cur_rule, *cur_bit;
	ucl_object_iter_t it = NULL;
	const gchar *redir_val;
	guint32 bit;
	gint i;


	if ((value =
		rspamd_config_get_module_opt (cfg, "surbl", "redirector")) != NULL) {
		i = 0;
		LL_FOREACH (value, cur)
		{
			i++;
		}
		surbl_module_ctx->redirectors = rspamd_upstreams_create ();
		rspamd_mempool_add_destructor (surbl_module_ctx->surbl_pool,
				(rspamd_mempool_destruct_t)rspamd_upstreams_destroy,
				surbl_module_ctx->redirectors);
		LL_FOREACH (value, cur)
		{
			redir_val = ucl_obj_tostring (cur);
			if (rspamd_upstreams_add_upstream (surbl_module_ctx->redirectors,
					redir_val, 80, NULL)) {
				surbl_module_ctx->use_redirector = TRUE;
			}
			i++;
		}
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "surbl",
		"redirector_symbol")) != NULL) {
		surbl_module_ctx->redirector_symbol = ucl_obj_tostring (value);
		register_virtual_symbol (&cfg->cache,
			surbl_module_ctx->redirector_symbol,
			1.0);
	}
	else {
		surbl_module_ctx->redirector_symbol = NULL;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "surbl", "weight")) != NULL) {
		surbl_module_ctx->weight = ucl_obj_toint (value);
	}
	else {
		surbl_module_ctx->weight = DEFAULT_SURBL_WEIGHT;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "surbl", "url_expire")) != NULL) {
		surbl_module_ctx->url_expire = ucl_obj_todouble (value);
	}
	else {
		surbl_module_ctx->url_expire = DEFAULT_SURBL_URL_EXPIRE;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "surbl",
		"redirector_connect_timeout")) != NULL) {
		surbl_module_ctx->connect_timeout = ucl_obj_todouble (value);
	}
	else {
		surbl_module_ctx->connect_timeout = DEFAULT_REDIRECTOR_CONNECT_TIMEOUT;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "surbl",
		"redirector_read_timeout")) != NULL) {
		surbl_module_ctx->read_timeout = ucl_obj_todouble (value);
	}
	else {
		surbl_module_ctx->read_timeout = DEFAULT_REDIRECTOR_READ_TIMEOUT;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "surbl",
		"redirector_hosts_map")) != NULL) {
		rspamd_map_add (cfg, ucl_obj_tostring (
				value),
			"SURBL redirectors list", read_redirectors_list, fin_redirectors_list,
			(void **)&surbl_module_ctx->redirector_hosts);
	}

	if ((value =
		rspamd_config_get_module_opt (cfg, "surbl", "max_urls")) != NULL) {
		surbl_module_ctx->max_urls = ucl_obj_toint (value);
	}
	else {
		surbl_module_ctx->max_urls = DEFAULT_SURBL_MAX_URLS;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "surbl", "exceptions")) != NULL) {
		if (rspamd_map_add (cfg, ucl_obj_tostring (value),
			"SURBL exceptions list", read_exceptions_list, fin_exceptions_list,
			(void **)&surbl_module_ctx->exceptions)) {
			surbl_module_ctx->tld2_file = rspamd_mempool_strdup (
				surbl_module_ctx->surbl_pool,
				ucl_obj_tostring (value) + sizeof ("file://") - 1);
		}
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "surbl", "whitelist")) != NULL) {
		if (rspamd_map_add (cfg, ucl_obj_tostring (value),
			"SURBL whitelist", rspamd_hosts_read, rspamd_hosts_fin,
			(void **)&surbl_module_ctx->whitelist)) {
			surbl_module_ctx->whitelist_file = rspamd_mempool_strdup (
				surbl_module_ctx->surbl_pool,
				ucl_obj_tostring (value) + sizeof ("file://") - 1);
		}
	}

	value = rspamd_config_get_module_opt (cfg, "surbl", "rule");
	if (value != NULL && value->type == UCL_OBJECT) {
		LL_FOREACH (value, cur_rule)
		{
			cur = ucl_obj_get_key (cur_rule, "suffix");
			if (cur == NULL) {
				msg_err ("surbl rule must have explicit symbol definition");
				continue;
			}
			new_suffix = rspamd_mempool_alloc (surbl_module_ctx->surbl_pool,
					sizeof (struct suffix_item));
			new_suffix->suffix = rspamd_mempool_strdup (
				surbl_module_ctx->surbl_pool,
				ucl_obj_tostring (cur));
			new_suffix->options = 0;
			new_suffix->bits = NULL;

			cur = ucl_obj_get_key (cur_rule, "symbol");
			if (cur == NULL) {
				msg_warn (
					"surbl rule for suffix %s lacks symbol, using %s as symbol",
					new_suffix->suffix,
					DEFAULT_SURBL_SYMBOL);
				new_suffix->symbol = rspamd_mempool_strdup (
					surbl_module_ctx->surbl_pool,
					DEFAULT_SURBL_SYMBOL);
			}
			else {
				new_suffix->symbol = rspamd_mempool_strdup (
					surbl_module_ctx->surbl_pool,
					ucl_obj_tostring (cur));
			}
			cur = ucl_obj_get_key (cur_rule, "options");
			if (cur != NULL && cur->type == UCL_STRING) {
				if (strstr (ucl_obj_tostring (cur), "noip") != NULL) {
					new_suffix->options |= SURBL_OPTION_NOIP;
				}
			}
			cur = ucl_obj_get_key (cur_rule, "bits");
			if (cur != NULL && cur->type == UCL_OBJECT) {
				it = NULL;
				while ((cur_bit =
					ucl_iterate_object (cur, &it, true)) != NULL) {
					if (ucl_object_key (cur_bit) != NULL && cur_bit->type ==
						UCL_INT) {
						gchar *p;

						bit = ucl_obj_toint (cur_bit);
						new_bit = rspamd_mempool_alloc (
							surbl_module_ctx->surbl_pool,
							sizeof (struct surbl_bit_item));
						new_bit->bit = bit;
						new_bit->symbol = rspamd_mempool_strdup (
							surbl_module_ctx->surbl_pool,
							ucl_object_key (cur_bit));
						/* Convert to uppercase */
						p = new_bit->symbol;
						while (*p) {
							*p = g_ascii_toupper (*p);
							p ++;
						}

						msg_debug ("add new bit suffix: %d with symbol: %s",
							(gint)new_bit->bit, new_bit->symbol);
						new_suffix->bits = g_list_prepend (new_suffix->bits,
								new_bit);
					}
				}
			}
			surbl_module_ctx->suffixes = g_list_prepend (
				surbl_module_ctx->suffixes,
				new_suffix);
			register_callback_symbol (&cfg->cache,
				new_suffix->symbol,
				1,
				surbl_test_url,
				new_suffix);
		}
	}
	/* Add default suffix */
	if (surbl_module_ctx->suffixes == NULL) {
		msg_err ("surbl module loaded but no suffixes defined, skip checks");
		return TRUE;
	}

	if (surbl_module_ctx->suffixes != NULL) {
		rspamd_mempool_add_destructor (surbl_module_ctx->surbl_pool,
			(rspamd_mempool_destruct_t) g_list_free,
			surbl_module_ctx->suffixes);
	}

	cur_opt = surbl_module_ctx->suffixes;
	while (cur_opt) {
		cur_suffix = cur_opt->data;
		if (cur_suffix->bits != NULL) {
			register_bit_symbols (cfg, cur_suffix);
			rspamd_mempool_add_destructor (surbl_module_ctx->surbl_pool,
				(rspamd_mempool_destruct_t) g_list_free,
				cur_suffix->bits);
		}
		cur_opt = g_list_next (cur_opt);
	}

	return TRUE;
}

gint
surbl_module_reconfig (struct rspamd_config *cfg)
{
	/* Delete pool and objects */
	rspamd_mempool_delete (surbl_module_ctx->surbl_pool);
	/* Reinit module */
	surbl_module_ctx->use_redirector = 0;
	surbl_module_ctx->suffixes = NULL;
	surbl_module_ctx->surbl_pool = rspamd_mempool_new (
		rspamd_mempool_suggest_size ());

	surbl_module_ctx->tld2_file = NULL;
	surbl_module_ctx->whitelist_file = NULL;
	surbl_module_ctx->redirectors = NULL;
	surbl_module_ctx->redirector_trie = rspamd_trie_create (TRUE);
	surbl_module_ctx->redirector_ptrs = g_ptr_array_new ();

	surbl_module_ctx->redirector_hosts = g_hash_table_new (rspamd_strcase_hash,
			rspamd_strcase_equal);
	surbl_module_ctx->whitelist = g_hash_table_new (rspamd_strcase_hash,
			rspamd_strcase_equal);
	/* Zero exceptions hashes */
	surbl_module_ctx->exceptions = rspamd_mempool_alloc0 (
		surbl_module_ctx->surbl_pool,
		MAX_LEVELS * sizeof (GHashTable *));
	/* Register destructors */
	rspamd_mempool_add_destructor (surbl_module_ctx->surbl_pool,
		(rspamd_mempool_destruct_t) g_hash_table_destroy,
		surbl_module_ctx->whitelist);
	rspamd_mempool_add_destructor (surbl_module_ctx->surbl_pool,
		(rspamd_mempool_destruct_t) g_hash_table_destroy,
		surbl_module_ctx->redirector_hosts);

	rspamd_mempool_add_destructor (surbl_module_ctx->surbl_pool,
		(rspamd_mempool_destruct_t) g_list_free,
		surbl_module_ctx->suffixes);

	rspamd_mempool_add_destructor (surbl_module_ctx->surbl_pool,
		(rspamd_mempool_destruct_t) rspamd_trie_free,
		surbl_module_ctx->redirector_trie);
	rspamd_mempool_add_destructor (surbl_module_ctx->surbl_pool,
		(rspamd_mempool_destruct_t) g_ptr_array_unref,
		surbl_module_ctx->redirector_ptrs);

	/* Perform configure */
	return surbl_module_config (cfg);
}



static gchar *
format_surbl_request (rspamd_mempool_t * pool,
	rspamd_fstring_t * hostname,
	struct suffix_item *suffix,
	gboolean append_suffix,
	GError ** err,
	gboolean forced,
	GTree *tree,
	struct rspamd_url *url)
{
	GHashTable *t;
	gchar *result = NULL, *dots[MAX_LEVELS],
		num_buf[sizeof("18446744073709551616")], *p;
	gint len, slen, r, i, dots_num = 0, level = MAX_LEVELS;
	gboolean is_numeric = TRUE;
	guint64 ip_num;
	rspamd_fstring_t f;

	if (G_LIKELY (suffix != NULL)) {
		slen = strlen (suffix->suffix);
	}
	else if (!append_suffix) {
		slen = 0;
	}
	else {
		g_assert_not_reached ();
	}
	len = hostname->len + slen + 2;

	p = hostname->begin;
	while (p - hostname->begin < (gint)hostname->len && dots_num < MAX_LEVELS) {
		if (*p == '.') {
			dots[dots_num] = p;
			dots_num++;
		}
		else if (!g_ascii_isdigit (*p)) {
			is_numeric = FALSE;
		}
		p++;
	}

	/* Check for numeric expressions */
	if (is_numeric && dots_num == 3) {
		/* This is ip address */
		if (suffix != NULL && (suffix->options & SURBL_OPTION_NOIP) != 0) {
			/* Ignore such requests */
			msg_info ("ignore request of ip url for list %s", suffix->symbol);
			return NULL;
		}
		result = rspamd_mempool_alloc (pool, len);
		r = rspamd_snprintf (result, len, "%*s.%*s.%*s.%*s",
				(gint)(hostname->len - (dots[2] - hostname->begin + 1)),
				dots[2] + 1,
				(gint)(dots[2] - dots[1] - 1),
				dots[1] + 1,
				(gint)(dots[1] - dots[0] - 1),
				dots[0] + 1,
				(gint)(dots[0] - hostname->begin),
				hostname->begin);
	}
	else if (is_numeric && dots_num == 0) {
		/* This is number */
		if (suffix != NULL && (suffix->options & SURBL_OPTION_NOIP) != 0) {
			/* Ignore such requests */
			msg_info ("ignore request of ip url for list %s", suffix->symbol);
			return NULL;
		}
		rspamd_strlcpy (num_buf, hostname->begin,
			MIN (hostname->len + 1, sizeof (num_buf)));
		errno = 0;
		ip_num = strtoull (num_buf, NULL, 10);
		if (errno != 0) {
			msg_info ("cannot convert ip to number '%s': %s",
				num_buf,
				strerror (errno));
			g_set_error (err, SURBL_ERROR, /* error domain */
				CONVERSION_ERROR,   /* error code */
				"URL cannot be decoded");
			return NULL;
		}

		len = sizeof ("255.255.255.255") + slen;
		result = rspamd_mempool_alloc (pool, len);
		/* Hack for bugged windows resolver */
		ip_num &= 0xFFFFFFFF;
		/* Get octets */
		r = rspamd_snprintf (result,
				len,
				"%ud.%ud.%ud.%ud",
				(guint32) ip_num & 0x000000FF,
				(guint32) (ip_num & 0x0000FF00) >> 8,
				(guint32) (ip_num & 0x00FF0000) >> 16,
				(guint32) (ip_num & 0xFF000000) >> 24);
	}
	else {
		/* Not a numeric url */
		result = rspamd_mempool_alloc (pool, len);
		/* Now we should try to check for exceptions */
		if (!forced) {
			for (i = MAX_LEVELS - 1; i >= 0; i--) {
				t = surbl_module_ctx->exceptions[i];
				if (t != NULL && dots_num >= i + 1) {
					f.begin = dots[dots_num - i - 1] + 1;
					f.len = hostname->len -
						(dots[dots_num - i - 1] - hostname->begin + 1);
					if (g_hash_table_lookup (t, &f) != NULL) {
						level = dots_num - i - 1;
						break;
					}
				}
			}
		}
		if (level != MAX_LEVELS) {
			if (level == 0) {
				r = rspamd_snprintf (result,
						len,
						"%*s",
						(gint)hostname->len,
						hostname->begin);
			}
			else {
				r = rspamd_snprintf (result, len, "%*s",
						(gint)(hostname->len -
						(dots[level - 1] - hostname->begin + 1)),
						dots[level - 1] + 1);
			}
		}
		else if (dots_num >= 2) {
			r = rspamd_snprintf (result, len, "%*s",
					(gint)(hostname->len -
					(dots[dots_num - 2] - hostname->begin + 1)),
					dots[dots_num - 2] + 1);
		}
		else {
			r = rspamd_snprintf (result,
					len,
					"%*s",
					(gint)hostname->len,
					hostname->begin);
		}
	}

	url->surbl = result;
	url->surbllen = r;

	if (tree != NULL) {
		if (g_tree_lookup (tree, result) != NULL) {
			msg_debug ("url %s is already registered", result);
			g_set_error (err, SURBL_ERROR, /* error domain */
				DUPLICATE_ERROR,        /* error code */
				"URL is duplicated: %s",        /* error message format string */
				result);
			return NULL;
		}
		else {
			g_tree_insert (tree, result, result);
		}
	}

	if (!forced &&
		g_hash_table_lookup (surbl_module_ctx->whitelist, result) != NULL) {
		msg_debug ("url %s is whitelisted", result);
		g_set_error (err, SURBL_ERROR, /* error domain */
			WHITELIST_ERROR,                /* error code */
			"URL is whitelisted: %s",               /* error message format string */
			result);
		return NULL;
	}


	if (append_suffix) {
		rspamd_snprintf (result + r, len - r, ".%s", suffix->suffix);
	}

	msg_debug ("request: %s, dots: %d, level: %d, orig: %*s",
		result,
		dots_num,
		level,
		(gint)hostname->len,
		hostname->begin);

	return result;
}

static void
make_surbl_requests (struct rspamd_url *url, struct rspamd_task *task,
	struct suffix_item *suffix, gboolean forced, GTree *tree)
{
	gchar *surbl_req;
	rspamd_fstring_t f;
	GError *err = NULL;
	struct dns_param *param;

	f.begin = url->host;
	f.len = url->hostlen;

	if ((surbl_req = format_surbl_request (task->task_pool, &f, suffix, TRUE,
		&err, forced, tree, url)) != NULL) {
		param =
			rspamd_mempool_alloc (task->task_pool, sizeof (struct dns_param));
		param->url = url;
		param->task = task;
		param->suffix = suffix;
		param->host_resolve =
			rspamd_mempool_strdup (task->task_pool, surbl_req);
		debug_task ("send surbl dns request %s", surbl_req);
		if (make_dns_request (task->resolver, task->s, task->task_pool,
			dns_callback,
			(void *)param, RDNS_REQUEST_A, surbl_req)) {
			task->dns_requests++;
		}
	}
	else if (err != NULL && err->code != WHITELIST_ERROR && err->code !=
		DUPLICATE_ERROR) {
		msg_info ("cannot format url string for surbl %s, %s", struri (
				url), err->message);
		g_error_free (err);
		return;
	}
	else if (err != NULL) {
		g_error_free (err);
	}
}

static void
process_dns_results (struct rspamd_task *task,
	struct suffix_item *suffix,
	gchar *url,
	guint32 addr)
{
	GList *cur;
	struct surbl_bit_item *bit;

	if (suffix->bits != NULL) {
		cur = g_list_first (suffix->bits);

		while (cur) {
			bit = (struct surbl_bit_item *)cur->data;
			debug_task ("got result(%d) AND bit(%d): %d",
				(gint)addr,
				(gint)ntohl (bit->bit),
				(gint)bit->bit & (gint)ntohl (addr));
			if (((gint)bit->bit & (gint)ntohl (addr)) != 0) {
				rspamd_task_insert_result (task, bit->symbol, 1,
					g_list_prepend (NULL,
					rspamd_mempool_strdup (task->task_pool, url)));
			}
			cur = g_list_next (cur);
		}
	}
	else {
		rspamd_task_insert_result (task, suffix->symbol, 1,
			g_list_prepend (NULL,
			rspamd_mempool_strdup (task->task_pool, url)));
	}
}

static void
dns_callback (struct rdns_reply *reply, gpointer arg)
{
	struct dns_param *param = (struct dns_param *)arg;
	struct rspamd_task *task;
	struct rdns_reply_entry *elt;

	task = param->task;

	debug_task ("in surbl request callback");
	/* If we have result from DNS server, this url exists in SURBL, so increase score */
	if (reply->code == RDNS_RC_NOERROR && reply->entries) {
		msg_info ("<%s> domain [%s] is in surbl %s", param->task->message_id,
			param->host_resolve, param->suffix->suffix);
		elt = reply->entries;
		if (elt->type == RDNS_REQUEST_A) {
			process_dns_results (param->task, param->suffix,
				param->host_resolve, (guint32)elt->content.a.addr.s_addr);
		}
	}
	else {
		debug_task ("<%s> domain [%s] is not in surbl %s",
			param->task->message_id, param->host_resolve,
			param->suffix->suffix);
	}
}

static void
free_redirector_session (void *ud)
{
	struct redirector_param *param = (struct redirector_param *)ud;

	event_del (&param->ev);
	g_string_free (param->buf, TRUE);
	close (param->sock);
}

static void
redirector_callback (gint fd, short what, void *arg)
{
	struct redirector_param *param = (struct redirector_param *)arg;
	gchar url_buf[512];
	gint r, urllen;
	struct timeval *timeout;
	gchar *p, *c, *urlstr;
	gboolean found = FALSE;

	switch (param->state) {
	case STATE_CONNECT:
		/* We have write readiness after connect call, so reinit event */
		if (what == EV_WRITE) {
			timeout =
				rspamd_mempool_alloc (param->task->task_pool,
					sizeof (struct timeval));
			double_to_tv (surbl_module_ctx->read_timeout, timeout);
			event_del (&param->ev);
			event_set (&param->ev,
				param->sock,
				EV_READ | EV_PERSIST,
				redirector_callback,
				(void *)param);
			event_add (&param->ev, timeout);
			r = rspamd_snprintf (url_buf,
					sizeof (url_buf),
					"GET %s HTTP/1.0\r\n\r\n",
					struri (param->url));
			if (write (param->sock, url_buf, r) == -1) {
				msg_err ("write failed %s to %s", strerror (
						errno), rspamd_upstream_name (param->redirector));
				rspamd_upstream_fail (param->redirector);
				remove_normal_event (param->task->s,
					free_redirector_session,
					param);
				return;
			}
			param->state = STATE_READ;
		}
		else {
			msg_info (
				"<%s> connection to redirector %s timed out while waiting for write",
				param->task->message_id,
				rspamd_upstream_name (param->redirector));
			rspamd_upstream_fail (param->redirector);
			remove_normal_event (param->task->s, free_redirector_session,
				param);

			return;
		}
		break;
	case STATE_READ:
		if (what == EV_READ) {
			r = read (param->sock, url_buf, sizeof (url_buf) - 1);
			if (r <= 0) {
				msg_err ("read failed: %s from %s", strerror (
						errno), rspamd_upstream_name (param->redirector));
				rspamd_upstream_fail (param->redirector);
				make_surbl_requests (param->url,
					param->task,
					param->suffix,
					FALSE,
					param->tree);
				remove_normal_event (param->task->s,
					free_redirector_session,
					param);
				return;
			}

			g_string_append_len (param->buf, url_buf, r);

			if ((p = strstr (param->buf->str, "Uri: ")) != NULL) {
				p += sizeof ("Uri: ") - 1;
				c = p;
				while (p++ < param->buf->str + param->buf->len - 1) {
					if (*p == '\r' || *p == '\n') {
						*p = '\0';
						found = TRUE;
						break;
					}
				}

				if (found) {
					msg_info ("<%s> got reply from redirector: '%s' -> '%s'",
						param->task->message_id,
						struri (param->url),
						c);

					urllen = strlen (c);
					urlstr = rspamd_mempool_alloc (param->task->task_pool,
							urllen + 1);
					rspamd_strlcpy (urlstr, c, urllen + 1);
					r = rspamd_url_parse (param->url, urlstr, urllen,
							param->task->task_pool);

					if (r == URI_ERRNO_OK) {
						make_surbl_requests (param->url,
							param->task,
							param->suffix,
							FALSE,
							param->tree);
					}
				}
				else {
					msg_info ("<%s> could not resolve '%s' on redirector",
							param->task->message_id,
							struri (param->url));
				}
			}
			rspamd_upstream_ok (param->redirector);
			remove_normal_event (param->task->s, free_redirector_session,
				param);
		}
		else {
			msg_info (
				"<%s> reading redirector %s timed out, while waiting for read",
				rspamd_upstream_name (param->redirector),
				param->task->message_id);
			rspamd_upstream_fail (param->redirector);
			remove_normal_event (param->task->s, free_redirector_session,
				param);
		}
		break;
	}
}


static void
register_redirector_call (struct rspamd_url *url, struct rspamd_task *task,
	struct suffix_item *suffix, const gchar *rule, GTree *tree)
{
	gint s = -1;
	struct redirector_param *param;
	struct timeval *timeout;
	struct upstream *selected;

	selected = rspamd_upstream_get (surbl_module_ctx->redirectors,
			RSPAMD_UPSTREAM_ROUND_ROBIN);

	if (selected) {
		s = rspamd_inet_address_connect (rspamd_upstream_addr (selected),
				SOCK_STREAM, TRUE);
	}

	if (s == -1) {
		msg_info ("<%s> cannot create tcp socket failed: %s",
			task->message_id,
			strerror (errno));
		make_surbl_requests (url, task, suffix, FALSE, tree);
		return;
	}

	param =
		rspamd_mempool_alloc (task->task_pool,
			sizeof (struct redirector_param));
	param->url = url;
	param->task = task;
	param->state = STATE_CONNECT;
	param->sock = s;
	param->suffix = suffix;
	param->redirector = selected;
	param->buf = g_string_sized_new (1024);
	param->tree = tree;
	timeout = rspamd_mempool_alloc (task->task_pool, sizeof (struct timeval));
	double_to_tv (surbl_module_ctx->connect_timeout, timeout);
	event_set (&param->ev, s, EV_WRITE, redirector_callback, (void *)param);
	event_add (&param->ev, timeout);
	register_async_event (task->s,
		free_redirector_session,
		param,
		g_quark_from_static_string ("surbl"));

	msg_info (
		"<%s> registered redirector call for %s to %s, according to rule: %s",
		task->message_id,
		struri (url),
		rspamd_upstream_name (param->redirector),
		rule);
}

static gboolean
surbl_tree_url_callback (gpointer key, gpointer value, void *data)
{
	struct redirector_param *param = data;
	struct rspamd_task *task;
	struct rspamd_url *url = value;
	gchar *red_domain;
	const gchar *pos;
	rspamd_regexp_t *re;
	guint idx, len;

	task = param->task;
	debug_task ("check url %s", struri (url));

	if (url->hostlen <= 0) {
		return FALSE;
	}

	if (surbl_module_ctx->use_redirector) {
		/* Search in trie */
		if (surbl_module_ctx->redirector_trie &&
			(pos =
			rspamd_trie_lookup (surbl_module_ctx->redirector_trie, url->host,
			url->hostlen, &idx)) != NULL &&
			idx < surbl_module_ctx->redirector_ptrs->len) {
			/* Get corresponding prefix */
			red_domain = g_ptr_array_index (surbl_module_ctx->redirector_ptrs,
					idx);
			if (red_domain != NULL) {
				len = strlen (red_domain);
				/* First check that we have found domain at the end of host */
				if (pos + len == url->host + url->hostlen &&
					(pos == url->host || *(pos - 1) == '.')) {
					/* Try to find corresponding regexp */
					re = g_hash_table_lookup (
						surbl_module_ctx->redirector_hosts,
						red_domain);
					if (re != NULL &&
						(re == NO_REGEXP ||
						rspamd_regexp_search (re, url->string, 0, NULL, NULL, TRUE))) {
						/* If no regexp found or founded regexp matches url string register redirector's call */
						if (surbl_module_ctx->redirector_symbol != NULL) {
							rspamd_task_insert_result (param->task,
								surbl_module_ctx->redirector_symbol,
								1,
								g_list_prepend (NULL, red_domain));
						}
						register_redirector_call (url,
							param->task,
							param->suffix,
							red_domain,
							param->tree);
						return FALSE;
					}
				}
			}
		}
		make_surbl_requests (url, param->task, param->suffix, FALSE,
			param->tree);
	}
	else {
		make_surbl_requests (url, param->task, param->suffix, FALSE,
			param->tree);
	}

	return FALSE;
}

static void
surbl_test_url (struct rspamd_task *task, void *user_data)
{
	struct redirector_param param;
	struct suffix_item *suffix = user_data;

	param.task = task;
	param.suffix = suffix;
	param.tree = g_tree_new ((GCompareFunc)strcmp);
	rspamd_mempool_add_destructor (task->task_pool,
		(rspamd_mempool_destruct_t)g_tree_destroy,
		param.tree);
	g_tree_foreach (task->urls, surbl_tree_url_callback, &param);
}
/*
 * Handlers of URLS command
 */
#if 0
struct urls_tree_cb_data {
	gchar *buf;
	gsize len;
	gsize off;
	struct rspamd_task *task;
};

static gboolean
calculate_buflen_cb (gpointer key, gpointer value, gpointer cbdata)
{
	struct urls_tree_cb_data *cb = cbdata;
	struct rspamd_url *url = value;

	cb->len += strlen (struri (url)) + url->hostlen + sizeof (" <\"\">, ") - 1;

	return FALSE;
}

static gboolean
write_urls_buffer (gpointer key, gpointer value, gpointer cbdata)
{
	struct urls_tree_cb_data *cb = cbdata;
	struct rspamd_url *url = value;
	rspamd_fstring_t f;
	gchar *urlstr;
	gsize len;

	f.begin = url->host;
	f.len = url->hostlen;
	if ((urlstr =
		format_surbl_request (cb->task->task_pool, &f, NULL, FALSE, NULL,
		FALSE)) != NULL) {
		len = strlen (urlstr);
		if (cb->off + len >= cb->len) {
			msg_info (
				"cannot write urls header completely, stripped reply at: %z",
				cb->off);
			return TRUE;
		}
		else {
			cb->off += rspamd_snprintf (cb->buf + cb->off,
					cb->len - cb->off,
					" %s <\"%s\">,",
					urlstr,
					struri (url));
		}
	}

	return FALSE;
}


static gboolean
urls_command_handler (struct rspamd_task *task)
{
	struct urls_tree_cb_data cb;

	/* First calculate buffer length */
	cb.len = sizeof (RSPAMD_REPLY_BANNER "/1.0 0 " SPAMD_OK CRLF "Urls: " CRLF);
	cb.off = 0;
	g_tree_foreach (task->urls, calculate_buflen_cb, &cb);

	cb.buf = rspamd_mempool_alloc (task->task_pool, cb.len * sizeof (gchar));
	cb.off += rspamd_snprintf (cb.buf + cb.off,
			cb.len - cb.off,
			"%s/%s 0 %s" CRLF "Urls:",
			(task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER,
			"1.3",
			SPAMD_OK);
	cb.task = task;

	/* Write urls to buffer */
	g_tree_foreach (task->urls, write_urls_buffer, &cb);

	/* Strip last ',' */
	if (cb.buf[cb.off - 1] == ',') {
		cb.buf[--cb.off] = '\0';
	}
	/* Write result */
	if (!rspamd_dispatcher_write (task->dispatcher, cb.buf, cb.off, FALSE,
		TRUE)) {
		return FALSE;
	}
	if (!rspamd_dispatcher_write (task->dispatcher, CRLF, sizeof (CRLF) - 1,
		FALSE, TRUE)) {
		return FALSE;
	}
	task->state = STATE_REPLY;

	return TRUE;
}
#endif
/*
 * vi:ts=4
 */
