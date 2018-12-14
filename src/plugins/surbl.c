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
#include "libutil/map.h"
#include "libutil/map_helpers.h"
#include "rspamd.h"
#include "utlist.h"
#include "multipattern.h"
#include "monitored.h"
#include "libserver/html.h"
#include "libutil/http_private.h"
#include "unix-std.h"
#include "lua/lua_common.h"

#define msg_err_surbl(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        "surbl", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_surbl(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        "surbl", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_surbl(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "surbl", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_surbl(...)  rspamd_conditional_debug_fast (NULL, task->from_addr, \
        rspamd_surbl_log_id, "surbl", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(surbl)

static const gchar *M = "surbl";

#define DEFAULT_SURBL_WEIGHT 10
#define DEFAULT_REDIRECTOR_READ_TIMEOUT 5.0
#define DEFAULT_SURBL_SYMBOL "SURBL_DNS"
#define SURBL_OPTION_NOIP (1 << 0)
#define SURBL_OPTION_RESOLVEIP (1 << 1)
#define SURBL_OPTION_CHECKIMAGES (1 << 2)
#define SURBL_OPTION_CHECKDKIM (1 << 3)
#define MAX_LEVELS 10

struct surbl_ctx {
	struct module_ctx ctx;
	guint16 weight;
	gdouble read_timeout;
	gboolean use_tags;
	GList *suffixes;
	gchar *metric;
	const gchar *redirector_symbol;
	GHashTable **exceptions;
	struct rspamd_hash_map_helper *whitelist;
	GHashTable *redirector_tlds;
	guint use_redirector;
	guint max_redirected_urls;
	gint redirector_cbid;
	struct upstream_list *redirectors;
};

struct suffix_item {
	guint64 magic;
	const gchar *monitored_domain;
	const gchar *suffix;
	const gchar *symbol;
	guint32 options;
	GArray *bits;
	GHashTable *ips;
	struct rspamd_monitored *m;
	gint callback_id;
	gint url_process_cbref;
};

struct dns_param {
	struct rspamd_url *url;
	struct rspamd_task *task;
	gchar *host_resolve;
	struct suffix_item *suffix;
	struct rspamd_symcache_item *item;
	struct surbl_module_ctx *ctx;
};

struct redirector_param {
	struct rspamd_url *url;
	struct rspamd_task *task;
	struct upstream *redirector;
	struct surbl_ctx *ctx;
	struct rspamd_http_connection *conn;
	GHashTable *tree;
	struct suffix_item *suffix;
	struct rspamd_symcache_item *item;
	gint sock;
	guint redirector_requests;
};

struct surbl_bit_item {
	guint32 bit;
	gchar *symbol;
};

#define SURBL_REDIRECTOR_CALLBACK "SURBL_REDIRECTOR_CALLBACK"

static const guint64 rspamd_surbl_cb_magic = 0xe09b8536f80de0d1ULL;
static const gchar *rspamd_surbl_default_monitored = "facebook.com";
static const guint default_max_redirected_urls = 10;

static void surbl_test_url (struct rspamd_task *task,
							struct rspamd_symcache_item *item,
							void *user_data);
static void surbl_test_redirector (struct rspamd_task *task,
								   struct rspamd_symcache_item *item,
								   void *user_data);
static void surbl_dns_callback (struct rdns_reply *reply, gpointer arg);
static void surbl_dns_ip_callback (struct rdns_reply *reply, gpointer arg);
static void process_dns_results (struct rspamd_task *task,
	struct suffix_item *suffix, gchar *resolved_name,
	guint32 addr, struct rspamd_url *url);
static gint surbl_register_redirect_handler (lua_State *L);
static gint surbl_continue_process_handler (lua_State *L);
static gint surbl_is_redirector_handler (lua_State *L);

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
		NULL,
		RSPAMD_MODULE_VER,
		(guint)-1,
};

static inline struct surbl_ctx *
surbl_get_context (struct rspamd_config *cfg)
{
	return (struct surbl_ctx *)g_ptr_array_index (cfg->c_modules,
			surbl_module.ctx_offset);
}

static void
exceptions_free_value (gpointer v)
{
	rspamd_ftok_t *val = v;

	g_free ((gpointer)val->begin);
	g_free (val);
}

static void
exception_insert (gpointer st, gconstpointer key, gconstpointer value)
{
	GHashTable **t = st;
	gint level = 0;
	const gchar *p = key;
	rspamd_ftok_t *val;

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

	val = g_malloc (sizeof (rspamd_ftok_t));
	val->begin = g_strdup (key);
	val->len = strlen (key);

	if (t[level] == NULL) {
		t[level] = g_hash_table_new_full (rspamd_ftok_icase_hash,
				rspamd_ftok_icase_equal,
				exceptions_free_value,
				g_free);
	}

	g_hash_table_replace (t[level], val, g_strdup (value));
}

static gchar *
read_exceptions_list (gchar * chunk,
	gint len,
	struct map_cb_data *data,
	gboolean final)
{
	GHashTable **t;
	guint i;

	if (data->cur_data == NULL) {
		t = data->prev_data;

		if (t) {
			for (i = 0; i < MAX_LEVELS; i++) {
				if (t[i] != NULL) {
					g_hash_table_destroy (t[i]);
				}
				t[i] = NULL;
			}

			g_free (t);
		}

		data->prev_data = NULL;
		data->cur_data = g_malloc0 (MAX_LEVELS * sizeof (GHashTable *));
	}

	return rspamd_parse_kv_list (
			   chunk,
			   len,
			   data,
			   exception_insert,
			   "",
			   final);
}

static void
fin_exceptions_list (struct map_cb_data *data)
{
	GHashTable **t;
	gint i;

	if (data->prev_data) {
		t = data->prev_data;
		for (i = 0; i < MAX_LEVELS; i++) {
			if (t[i] != NULL) {
				rspamd_default_log_function (G_LOG_LEVEL_DEBUG,
						"surbl", "",
						G_STRFUNC,
						"exceptions level %d: %d elements",
						i, g_hash_table_size (t[i]));
			}
		}
	}
}

static void
dtor_exceptions_list (struct map_cb_data *data)
{
	GHashTable **t;
	gint i;

	if (data->cur_data) {
		t = data->cur_data;
		for (i = 0; i < MAX_LEVELS; i++) {
			if (t[i] != NULL) {
				g_hash_table_destroy (t[i]);
			}
			t[i] = NULL;
		}

		g_free (t);
	}
}

static void
redirector_insert (gpointer st, gconstpointer key, gconstpointer value)
{
	GHashTable *tld_hash = st;
	const gchar *p = key, *begin = key;
	rspamd_fstring_t *pat;
	rspamd_ftok_t *tok;
	rspamd_regexp_t *re = NO_REGEXP;
	GError *err = NULL;

	while (*p && !g_ascii_isspace (*p)) {
		p++;
	}

	pat = rspamd_fstring_new_init (begin, p - begin);
	tok = g_malloc0 (sizeof (*tok));
	tok->begin = pat->str;
	tok->len = pat->len;

	if (g_ascii_isspace (*p)) {
		while (g_ascii_isspace (*p) && *p) {
			p++;
		}
		if (*p) {
			re = rspamd_regexp_new (p,
					"ir",
					&err);
			if (re == NULL) {
				msg_warn ("could not read regexp: %e while reading regexp %s",
					err,
					p);
				g_error_free (err);
				re = NO_REGEXP;
			}
		}
	}

	g_hash_table_replace (tld_hash, tok, re);
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
read_redirectors_list (gchar * chunk,
	gint len,
	struct map_cb_data *data,
	gboolean final)
{
	GHashTable *tld_hash;

	if (data->cur_data == NULL) {
		tld_hash  = g_hash_table_new_full (rspamd_ftok_icase_hash,
				rspamd_ftok_icase_equal,
				rspamd_fstring_mapped_ftok_free,
				redirector_item_free);

		data->cur_data = tld_hash;
	}

	return rspamd_parse_kv_list (
			   chunk,
			   len,
			   data,
			   redirector_insert,
			   "",
			   final);
}

void
fin_redirectors_list (struct map_cb_data *data)
{
	GHashTable *tld_hash;

	if (data->prev_data) {
		tld_hash = data->prev_data;

		g_hash_table_unref (tld_hash);
	}
}

void
dtor_redirectors_list (struct map_cb_data *data)
{
	GHashTable *tld_hash;

	if (data->cur_data) {
		tld_hash = data->cur_data;

		g_hash_table_unref (tld_hash);
	}
}

gint
surbl_module_init (struct rspamd_config *cfg, struct module_ctx **ctx)
{
	struct surbl_ctx *surbl_module_ctx;

	surbl_module_ctx = rspamd_mempool_alloc0 (cfg->cfg_pool,
			sizeof (struct surbl_ctx));

	surbl_module_ctx->use_redirector = 0;
	surbl_module_ctx->suffixes = NULL;

	surbl_module_ctx->redirectors = NULL;
	surbl_module_ctx->whitelist = NULL;
	surbl_module_ctx->exceptions = NULL;
	surbl_module_ctx->redirector_cbid = -1;


	*ctx = (struct module_ctx *)surbl_module_ctx;

	rspamd_rcl_add_doc_by_path (cfg,
			NULL,
			"URL blacklist plugin",
			"surbl",
			UCL_OBJECT,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"surbl",
			"List of redirector servers",
			"redirector",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"surbl",
			"Map of domains that should be checked with redirector",
			"redirector_hosts_map",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"surbl",
			"Connect timeout for redirector",
			"redirector_connect_timeout",
			UCL_TIME,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"surbl",
			"Read timeout for redirector",
			"redirector_read_timeout",
			UCL_TIME,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"surbl",
			"Maximum number of URLs to process per message",
			"max_urls",
			UCL_INT,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"surbl",
			"Rules for TLD composition",
			"exceptions",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"surbl",
			"Map of whitelisted domains",
			"whitelist",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"surbl",
			"URL blacklist rule",
			"rule",
			UCL_OBJECT,
			NULL,
			0,
			NULL,
			0);
	/* Rules doc strings */
	rspamd_rcl_add_doc_by_path (cfg,
			"surbl.rule",
			"Name of DNS black list (e.g. `multi.surbl.com`)",
			"suffix",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"surbl.rule",
			"Symbol to insert (if no bits or suffixes are defined)",
			"symbol",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"surbl.rule",
			"Whether the defined rule should be used",
			"enabled",
			UCL_BOOLEAN,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"surbl.rule",
			"Do not try to check URLs with IP address instead of hostname",
			"no_ip",
			UCL_BOOLEAN,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"surbl.rule",
			"Resolve URL host and then check against the specified suffix with reversed IP octets",
			"resolve_ip",
			UCL_BOOLEAN,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"surbl.rule",
			"Check images URLs with this URL list",
			"images",
			UCL_BOOLEAN,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"surbl.rule",
			"Parse IP bits in DNS reply, the content is 'symbol = <bit>'",
			"bits",
			UCL_OBJECT,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"surbl.rule",
			"Parse IP addresses in DNS reply, the content is 'symbol = address'",
			"ips",
			UCL_OBJECT,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"surbl.rule",
			"Check domains in valid DKIM signatures",
			"check_dkim",
			UCL_BOOLEAN,
			NULL,
			0,
			NULL,
			0);

	return 0;
}

/*
 * Register virtual symbols for suffixes with bit wildcard
 */
static void
register_bit_symbols (struct rspamd_config *cfg, struct suffix_item *suffix,
		gint parent_id)
{
	guint i;
	GHashTableIter it;
	struct surbl_bit_item *bit;
	gpointer k, v;

	if (suffix->ips != NULL) {
		g_hash_table_iter_init (&it, suffix->ips);

		while (g_hash_table_iter_next (&it, &k, &v)) {
			bit = v;
			rspamd_symcache_add_symbol (cfg->cache, bit->symbol,
					0, NULL, NULL,
					SYMBOL_TYPE_VIRTUAL, parent_id);
			msg_debug_config ("bit: %d", bit->bit);
		}
	}
	else if (suffix->bits != NULL) {
		for (i = 0; i < suffix->bits->len; i++) {
			bit = &g_array_index (suffix->bits, struct surbl_bit_item, i);
			rspamd_symcache_add_symbol (cfg->cache, bit->symbol,
					0, NULL, NULL,
					SYMBOL_TYPE_VIRTUAL, parent_id);
		}
	}
	else {
		rspamd_symcache_add_symbol (cfg->cache, suffix->symbol,
				0, NULL, NULL,
				SYMBOL_TYPE_VIRTUAL, parent_id);
	}
}

static gint
surbl_module_parse_rule (const ucl_object_t* value, struct rspamd_config* cfg)
{
	const ucl_object_t* cur_rule;
	const ucl_object_t* cur;
	gint cb_id;
	gint nrules = 0;
	struct suffix_item* new_suffix;
	const gchar* ip_val, *monitored_domain = NULL;
	struct surbl_bit_item* new_bit;
	ucl_object_t *ropts;
	struct surbl_ctx *surbl_module_ctx = surbl_get_context (cfg);

	LL_FOREACH(value, cur_rule) {
		monitored_domain = NULL;

		cur = ucl_object_lookup (cur_rule, "enabled");
		if (cur != NULL && cur->type == UCL_BOOLEAN) {
			if (!ucl_object_toboolean (cur)) {
				continue;
			}
		}

		cur = ucl_object_lookup (cur_rule, "suffix");
		if (cur == NULL) {
			msg_err_config("surbl rule must have explicit symbol "
					"definition");
			continue;
		}

		new_suffix = rspamd_mempool_alloc0 (cfg->cfg_pool,
				sizeof (struct suffix_item));
		new_suffix->magic = rspamd_surbl_cb_magic;
		new_suffix->suffix = rspamd_mempool_strdup (
				cfg->cfg_pool, ucl_obj_tostring (cur));
		new_suffix->options = 0;
		new_suffix->bits = g_array_new (FALSE, FALSE,
				sizeof (struct surbl_bit_item));
		rspamd_mempool_add_destructor (cfg->cfg_pool,
				(rspamd_mempool_destruct_t )rspamd_array_free_hard,
				new_suffix->bits);

		cur = ucl_object_lookup (cur_rule, "symbol");
		if (cur == NULL) {
			if (ucl_object_key (value)) {
				new_suffix->symbol = rspamd_mempool_strdup (
						cfg->cfg_pool,
						ucl_object_key (value));
			}
			else {
				msg_warn_config(
						"surbl rule for suffix %s lacks symbol, using %s as symbol",
						new_suffix->suffix, DEFAULT_SURBL_SYMBOL);
				new_suffix->symbol = rspamd_mempool_strdup (
						cfg->cfg_pool, DEFAULT_SURBL_SYMBOL);
			}
		}
		else {
			new_suffix->symbol = rspamd_mempool_strdup (
					cfg->cfg_pool, ucl_obj_tostring (cur));
		}

		cur = ucl_object_lookup (cur_rule, "options");
		if (cur != NULL && cur->type == UCL_STRING) {
			if (strstr(ucl_obj_tostring (cur), "noip") != NULL) {
				new_suffix->options |= SURBL_OPTION_NOIP;
			}
		}

		cur = ucl_object_lookup (cur_rule, "no_ip");
		if (cur != NULL && cur->type == UCL_BOOLEAN) {
			if (ucl_object_toboolean (cur)) {
				new_suffix->options |= SURBL_OPTION_NOIP;
			}
		}

		cur = ucl_object_lookup (cur_rule, "monitored_domain");
		if (cur != NULL && cur->type == UCL_STRING) {
			monitored_domain = ucl_object_tostring (cur);
		}

		cur = ucl_object_lookup (cur_rule, "resolve_ip");
		if (cur != NULL && cur->type == UCL_BOOLEAN) {
			if (ucl_object_toboolean (cur)) {
				new_suffix->options |= SURBL_OPTION_RESOLVEIP;

				if (!monitored_domain) {
					monitored_domain = "1.0.0.127";
				}
			}
		}

		if (!monitored_domain) {
			monitored_domain = rspamd_surbl_default_monitored;
		}

		ropts = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (ropts,
				ucl_object_fromstring (monitored_domain),
				"prefix", 0, false);
		ucl_object_insert_key (ropts,
				ucl_object_fromstring ("nxdomain"),
				"rcode", 0, false);
		rspamd_mempool_add_destructor (cfg->cfg_pool,
				(rspamd_mempool_destruct_t )ucl_object_unref,
				ropts);

		cur = ucl_object_lookup (cur_rule, "images");
		if (cur != NULL && cur->type == UCL_BOOLEAN) {
			if (ucl_object_toboolean (cur)) {
				new_suffix->options |= SURBL_OPTION_CHECKIMAGES;
			}
		}

		cur = ucl_object_lookup (cur_rule, "check_dkim");
		if (cur != NULL && cur->type == UCL_BOOLEAN) {
			if (ucl_object_toboolean (cur)) {
				new_suffix->options |= SURBL_OPTION_CHECKDKIM;
			}
		}

		if ((new_suffix->options & (SURBL_OPTION_RESOLVEIP | SURBL_OPTION_NOIP))
				== (SURBL_OPTION_NOIP | SURBL_OPTION_RESOLVEIP)) {
			/* Mutually exclusive options */
			msg_err_config ("options noip and resolve_ip are "
					"mutually exclusive for suffix %s", new_suffix->suffix);

			continue;
		}

		GString *sym = g_string_sized_new (127);
		gchar *p;

		rspamd_printf_gstring (sym, "SURBL_%s",
				new_suffix->suffix);

		p = sym->str;

		while (*p) {
			if (*p == '.') {
				*p = '_';
			}
			else {
				*p = g_ascii_toupper (*p);
			}

			p ++;
		}

		cb_id = rspamd_symcache_add_symbol (cfg->cache, sym->str,
				0, surbl_test_url, new_suffix, SYMBOL_TYPE_CALLBACK, -1);
		rspamd_symcache_add_dependency (cfg->cache, cb_id,
				SURBL_REDIRECTOR_CALLBACK);
		g_string_free (sym, TRUE);
		nrules++;
		new_suffix->callback_id = cb_id;
		cur = ucl_object_lookup (cur_rule, "bits");

		if (cur != NULL && cur->type == UCL_OBJECT) {
			ucl_object_iter_t it = NULL;
			const ucl_object_t* cur_bit;
			guint32 bit;

			while ((cur_bit = ucl_object_iterate (cur, &it, true)) != NULL) {
				if (ucl_object_key (cur_bit) != NULL
						&& cur_bit->type == UCL_INT) {
					gchar* p;
					bit = ucl_obj_toint (cur_bit);
					new_bit = rspamd_mempool_alloc (
							cfg->cfg_pool,
							sizeof(struct surbl_bit_item));
					new_bit->bit = bit;
					new_bit->symbol = rspamd_mempool_strdup (
							cfg->cfg_pool,
							ucl_object_key (cur_bit));
					/* Convert to uppercase */
					p = new_bit->symbol;

					while (*p) {
						*p = g_ascii_toupper (*p);
						p++;
					}

					msg_debug_config("add new bit suffix: %d with symbol: %s",
							(gint)new_bit->bit, new_bit->symbol);
					g_array_append_val(new_suffix->bits, *new_bit);
				}
			}
		}

		cur = ucl_object_lookup(cur_rule, "ips");
		if (cur != NULL && cur->type == UCL_OBJECT) {
			ucl_object_iter_t it = NULL;
			const ucl_object_t* cur_bit;
			guint32 bit;

			new_suffix->ips = g_hash_table_new (g_int_hash, g_int_equal);
			rspamd_mempool_add_destructor (cfg->cfg_pool,
					(rspamd_mempool_destruct_t )g_hash_table_unref,
					new_suffix->ips);

			while ((cur_bit = ucl_object_iterate (cur, &it, true)) != NULL) {
				if (ucl_object_key (cur_bit) != NULL) {
					gchar* p;
					ip_val = ucl_obj_tostring (cur_bit);
					new_bit = rspamd_mempool_alloc (
							cfg->cfg_pool,
							sizeof(struct surbl_bit_item));
					if (inet_pton (AF_INET, ip_val, &bit) != 1) {
						msg_err_config ("cannot parse ip %s: %s", ip_val,
								strerror (errno));
						continue;
					}
					new_bit->bit = bit;
					new_bit->symbol = rspamd_mempool_strdup (
							cfg->cfg_pool,
							ucl_object_key (cur_bit));
					/* Convert to uppercase */
					p = new_bit->symbol;
					while (*p) {
						*p = g_ascii_toupper (*p);
						p++;
					}
					msg_debug_config ("add new IP suffix: %d with symbol: %s",
							(gint)new_bit->bit, new_bit->symbol);
					g_hash_table_insert (new_suffix->ips, &new_bit->bit,
							new_bit);
				}
			}
		}

		cur = ucl_object_lookup (cur_rule, "process_script");
		if (cur != NULL && cur->type == UCL_STRING) {
			lua_State *L = cfg->lua_state;
			GString *tb;
			gint err_idx;
			const gchar *input = ucl_object_tostring (cur);
			gboolean loaded = FALSE;

			lua_pushcfunction (L, &rspamd_lua_traceback);
			err_idx = lua_gettop (L);

			/* First try return + input */
			tb = g_string_sized_new (strlen (input) + sizeof ("return "));
			rspamd_printf_gstring (tb, "return %s", input);

			if (luaL_loadstring (L, tb->str) != 0) {
				/* Reset stack */
				lua_settop (L, err_idx - 1);
				lua_pushcfunction (L, &rspamd_lua_traceback);
				err_idx = lua_gettop (L);
				/* Try with no return */
				if (luaL_loadstring (L, input) != 0) {
					msg_err_config ("cannot load string %s\n",
							input);
				}
				else {
					loaded = TRUE;
				}
			}
			else {
				loaded = TRUE;
			}

			g_string_free (tb, TRUE);

			if (loaded) {
				if (lua_pcall (L, 0, 1, err_idx) != 0) {
					tb = lua_touserdata (L, -1);
					msg_err_config ("call failed: %v\n", tb);
					g_string_free (tb, TRUE);
				}
				else if (lua_isfunction (L, -1)) {
					new_suffix->url_process_cbref = luaL_ref (L,
							LUA_REGISTRYINDEX);
				}
			}

			lua_settop (L, err_idx - 1);
		}

		if (new_suffix->symbol) {
			/* Register just a symbol itself */
			rspamd_symcache_add_symbol (cfg->cache,
					new_suffix->symbol, 0,
					NULL, NULL, SYMBOL_TYPE_VIRTUAL, cb_id);
			nrules++;
		}

		new_suffix->m = rspamd_monitored_create (cfg->monitored_ctx,
				new_suffix->suffix, RSPAMD_MONITORED_DNS,
				RSPAMD_MONITORED_DEFAULT, ropts);
		surbl_module_ctx->suffixes = g_list_prepend (surbl_module_ctx->suffixes,
				new_suffix);
	}

	return nrules;
}

gint
surbl_module_config (struct rspamd_config *cfg)
{
	GList *cur_opt;
	struct suffix_item *cur_suffix = NULL;
	const ucl_object_t *value, *cur;
	const gchar *redir_val;
	gint nrules = 0;
	lua_State *L;
	struct surbl_ctx *surbl_module_ctx = surbl_get_context (cfg);

	if (!rspamd_config_is_module_enabled (cfg, "surbl")) {
		return TRUE;
	}

	/* Register global methods */
	L = cfg->lua_state;
	lua_getglobal (L, "rspamd_plugins");

	if (lua_type (L, -1) == LUA_TTABLE) {
		lua_pushstring (L, "surbl");
		lua_createtable (L, 0, 3);
		/* Set methods */
		lua_pushstring (L, "register_redirect");
		lua_pushcfunction (L, surbl_register_redirect_handler);
		lua_settable (L, -3);
		lua_pushstring (L, "continue_process");
		lua_pushcfunction (L, surbl_continue_process_handler);
		lua_settable (L, -3);
		lua_pushstring (L, "is_redirector");
		lua_pushcfunction (L, surbl_is_redirector_handler);
		lua_settable (L, -3);
		/* Finish surbl key */
		lua_settable (L, -3);
	}

	lua_pop (L, 1); /* Remove global function */

	(void) rspamd_symcache_add_symbol (cfg->cache, SURBL_REDIRECTOR_CALLBACK,
			0, surbl_test_redirector, NULL,
			SYMBOL_TYPE_CALLBACK, -1);

	if ((value =
		rspamd_config_get_module_opt (cfg, "surbl", "redirector")) != NULL) {
		surbl_module_ctx->redirectors = rspamd_upstreams_create (cfg->ups_ctx);
		rspamd_mempool_add_destructor (cfg->cfg_pool,
				(rspamd_mempool_destruct_t)rspamd_upstreams_destroy,
				surbl_module_ctx->redirectors);
		LL_FOREACH (value, cur)
		{
			redir_val = ucl_obj_tostring (cur);
			if (rspamd_upstreams_add_upstream (surbl_module_ctx->redirectors,
					redir_val, 80, RSPAMD_UPSTREAM_PARSE_DEFAULT,
					NULL)) {
				surbl_module_ctx->use_redirector = TRUE;
			}
		}
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "surbl",
		"redirector_symbol")) != NULL) {
		surbl_module_ctx->redirector_symbol = ucl_obj_tostring (value);
		rspamd_symcache_add_symbol (cfg->cache,
				surbl_module_ctx->redirector_symbol,
				0, NULL, NULL, SYMBOL_TYPE_COMPOSITE, -1);
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
			rspamd_config_get_module_opt (cfg, "surbl", "use_tags")) != NULL) {
		surbl_module_ctx->use_tags = ucl_obj_toboolean (value);
	}
	else {
		surbl_module_ctx->use_tags = FALSE;
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
		if (!rspamd_map_add_from_ucl (cfg, value,
				"SURBL redirectors list",
				read_redirectors_list,
				fin_redirectors_list,
				dtor_redirectors_list,
				(void **)&surbl_module_ctx->redirector_tlds)) {

			msg_warn_config ("bad redirectors map definition: %s",
					ucl_obj_tostring (value));
		}
	}

	if ((value =
		rspamd_config_get_module_opt (cfg, "surbl", "exceptions")) != NULL) {
		rspamd_map_add_from_ucl (cfg, value,
				"SURBL exceptions list",
				read_exceptions_list,
				fin_exceptions_list,
				dtor_exceptions_list,
				(void **)&surbl_module_ctx->exceptions);
	}
	if ((value =
			rspamd_config_get_module_opt (cfg, "surbl", "whitelist")) != NULL) {
		rspamd_map_add_from_ucl (cfg, value,
				"SURBL whitelist",
				rspamd_kv_list_read,
				rspamd_kv_list_fin,
				rspamd_kv_list_dtor,
				(void **)&surbl_module_ctx->whitelist);
	}

	value = rspamd_config_get_module_opt (cfg, "surbl", "rule");
	if (value != NULL && value->type == UCL_OBJECT) {
		ucl_object_iter_t it = NULL;
		const ucl_object_t *cur_value;

		if (ucl_object_lookup (value, "symbol") != NULL) {
			/* Old style */
			nrules += surbl_module_parse_rule (value, cfg);
		}
		else {
			/* New style */
			while ((cur_value = ucl_object_iterate (value, &it, true)) != NULL) {
				nrules += surbl_module_parse_rule (cur_value, cfg);
			}
		}
	}

	value = rspamd_config_get_module_opt (cfg, "surbl", "rules");
	if (value != NULL && value->type == UCL_OBJECT) {
		ucl_object_iter_t it = NULL;
		const ucl_object_t *cur_value;

		/* New style only */
		while ((cur_value = ucl_object_iterate (value, &it, true)) != NULL) {
			nrules += surbl_module_parse_rule (cur_value, cfg);
		}
	}

	/* Add default suffix */
	if (surbl_module_ctx->suffixes == NULL) {
		msg_err_config ("surbl module loaded but no suffixes defined, skip "
				"checks");
		return TRUE;
	}

	if (surbl_module_ctx->suffixes != NULL) {
		rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t) g_list_free,
			surbl_module_ctx->suffixes);
	}


	cur_opt = surbl_module_ctx->suffixes;
	while (cur_opt) {
		cur_suffix = cur_opt->data;

		if (cur_suffix->bits != NULL || cur_suffix->ips != NULL) {
			register_bit_symbols (cfg, cur_suffix, cur_suffix->callback_id);
		}

		if (cur_suffix->options & SURBL_OPTION_CHECKDKIM) {
			rspamd_symcache_add_dependency (cfg->cache,
					cur_suffix->callback_id, "DKIM_TRACE");
		}

		cur_opt = g_list_next (cur_opt);
	}

	surbl_module_ctx->max_redirected_urls = default_max_redirected_urls;

	if ((value =
			rspamd_config_get_module_opt (cfg, "surbl", "max_redirected_urls")) != NULL) {
		surbl_module_ctx->max_redirected_urls = ucl_obj_toint (value);
	}

	msg_info_config ("init internal surbls module, %d uribl rules loaded",
			nrules);

	return TRUE;
}

gint
surbl_module_reconfig (struct rspamd_config *cfg)
{
	struct surbl_ctx *surbl_module_ctx = surbl_get_context (cfg);

	/* Reinit module */
	surbl_module_ctx->use_redirector = 0;
	surbl_module_ctx->suffixes = NULL;
	surbl_module_ctx->redirectors = NULL;
	surbl_module_ctx->whitelist = NULL;
	/* Zero exceptions hashes */
	surbl_module_ctx->exceptions = NULL;

	rspamd_mempool_add_destructor (cfg->cfg_pool,
		(rspamd_mempool_destruct_t) g_list_free,
		surbl_module_ctx->suffixes);

	/* Perform configure */
	return surbl_module_config (cfg);
}



static gchar *
format_surbl_request (rspamd_mempool_t * pool,
					  rspamd_ftok_t * hostname,
					  struct suffix_item *suffix,
					  gboolean append_suffix,
					  GError ** err,
					  gboolean forced,
					  GHashTable *tree,
					  struct rspamd_url *url,
					  lua_State *L,
					  struct surbl_ctx *surbl_module_ctx)
{
	GHashTable *t;
	gchar *result = NULL;
	const gchar *p, *dots[MAX_LEVELS];
	gint r, i, dots_num = 0, level = MAX_LEVELS;
	gsize slen, len;
	gboolean found_exception = FALSE;
	rspamd_ftok_t f;


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

		p++;
	}

	/* Check for numeric expressions */
	if (url->flags & RSPAMD_URL_FLAG_NUMERIC) {
		/* This is ip address */
		if (suffix != NULL && (suffix->options & SURBL_OPTION_NOIP) != 0) {
			/* Ignore such requests */
			msg_info_pool ("ignore request of ip url for list %s",
					suffix->symbol);
			return NULL;
		}

		if (dots_num == 3) {
			/* IPv4 address */
			result = rspamd_mempool_alloc (pool, len);
			r = rspamd_snprintf (result, len, "%*s.%*s.%*s.%*s",
					(gint) (hostname->len - (dots[2] - hostname->begin + 1)),
					dots[2] + 1,
					(gint) (dots[2] - dots[1] - 1),
					dots[1] + 1,
					(gint) (dots[1] - dots[0] - 1),
					dots[0] + 1,
					(gint) (dots[0] - hostname->begin),
					hostname->begin);
		}
		else {
			/* Just pring ip as is */
			result = rspamd_mempool_alloc (pool, len);
			r = rspamd_snprintf (result, len, "%*s",
					(gint)hostname->len, hostname->begin);
		}
	}
	else {
		/* Not a numeric url */
		result = rspamd_mempool_alloc (pool, len);
		/* Now we should try to check for exceptions */
		if (!forced && surbl_module_ctx->exceptions) {
			for (i = MAX_LEVELS - 1; i >= 0; i--) {
				t = surbl_module_ctx->exceptions[i];
				if (t != NULL && dots_num >= i + 1) {
					f.begin = dots[dots_num - i - 1] + 1;
					f.len = hostname->len -
						(dots[dots_num - i - 1] - hostname->begin + 1);
					if (g_hash_table_lookup (t, &f) != NULL) {
						level = dots_num - i - 1;
						found_exception = TRUE;
						break;
					}
				}
			}
		}

		if (found_exception || url->tldlen == 0) {
			if (level != MAX_LEVELS) {
				if (level == 0) {
					r = rspamd_snprintf (result,
							len,
							"%T",
							hostname);
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
						"%T",
						hostname);
			}
		}
		else {
			r = rspamd_snprintf (result,
						len,
						"%*s",
						url->tldlen,
						url->tld);
		}
	}

	url->surbl = result;
	url->surbllen = r;

	if (!forced &&
			rspamd_match_hash_map (surbl_module_ctx->whitelist, result) != NULL) {
		msg_debug_pool ("url %s is whitelisted", result);
		g_set_error (err, SURBL_ERROR,
				WHITELIST_ERROR,
				"URL is whitelisted: %s",
				result);
		return NULL;
	}

	if (append_suffix) {
		if (suffix->url_process_cbref > 0) {
			lua_rawgeti (L, LUA_REGISTRYINDEX, suffix->url_process_cbref);
			lua_pushstring (L, result);
			lua_pushstring (L, suffix->suffix);

			if (lua_pcall (L, 2, 1, 0) != 0) {
				msg_err_pool ("cannot call url process script: %s",
						lua_tostring (L, -1));
				lua_pop (L, 1);
				rspamd_snprintf (result + r, len - r, ".%s", suffix->suffix);
			}
			else {
				result = rspamd_mempool_strdup (pool, lua_tostring (L, -1));
				lua_pop (L, 1);
			}
		}
		else {
			rspamd_snprintf (result + r, len - r, ".%s", suffix->suffix);
		}
	}

	if (tree != NULL) {
		if (g_hash_table_lookup (tree, result) != NULL) {
			msg_debug_pool ("url %s is already registered", result);
			g_set_error (err, SURBL_ERROR,
				DUPLICATE_ERROR,
				"URL is duplicated: %s",
				result);
			return NULL;
		}
		else {
			g_hash_table_insert (tree, result, url);
		}
	}

	msg_debug_pool ("request: %s, dots: %d, level: %d, orig: %*s",
		result,
		dots_num,
		level,
		(gint)hostname->len,
		hostname->begin);

	return result;
}

static void
make_surbl_requests (struct rspamd_url *url, struct rspamd_task *task,
					 struct rspamd_symcache_item *item,
					 struct suffix_item *suffix,
					 gboolean forced, GHashTable *tree,
					 struct surbl_ctx *surbl_module_ctx)
{
	gchar *surbl_req;
	rspamd_ftok_t f;
	GError *err = NULL;
	struct dns_param *param;


	f.begin = url->host;
	f.len = url->hostlen;

	if (suffix->options & SURBL_OPTION_RESOLVEIP) {
		/*
		 * We need to get url real TLD, resolve it with no suffix and then
		 * check against surbl using reverse octets printing
		 */
		surbl_req = format_surbl_request (task->task_pool,
				&f,
				suffix,
				FALSE,
				&err,
				forced,
				tree,
				url,
				task->cfg->lua_state,
				surbl_module_ctx);

		if (surbl_req == NULL) {
			if (err != NULL) {
				if (err->code != WHITELIST_ERROR && err->code != DUPLICATE_ERROR) {
					msg_info_surbl ("cannot format url string for surbl %*s, %e",
							url->urllen, url->string,
							err);
				}
				g_error_free (err);
				return;
			}
		}
		else {
			/* XXX: We make merely A request here */
			param =
					rspamd_mempool_alloc (task->task_pool,
							sizeof (struct dns_param));
			param->url = url;
			param->task = task;
			param->suffix = suffix;
			param->host_resolve =
					rspamd_mempool_strdup (task->task_pool, surbl_req);
			msg_debug_surbl ("send surbl dns ip request %s to %s", surbl_req,
					suffix->suffix);

			if (make_dns_request_task (task,
					surbl_dns_ip_callback,
					(void *) param, RDNS_REQUEST_A, surbl_req)) {
				param->item = item;
				rspamd_symcache_item_async_inc (task, item, M);
			}
		}
	}
	else if ((surbl_req = format_surbl_request (task->task_pool,
			&f,
			suffix,
			TRUE,
			&err,
			forced,
			tree,
			url,
			task->cfg->lua_state,
			surbl_module_ctx)) != NULL) {
		param =
			rspamd_mempool_alloc (task->task_pool, sizeof (struct dns_param));
		param->url = url;
		param->task = task;
		param->suffix = suffix;
		param->host_resolve =
			rspamd_mempool_strdup (task->task_pool, url->surbl);
		msg_debug_surbl ("send surbl dns request %s", surbl_req);

		if (make_dns_request_task (task,
				surbl_dns_callback,
				(void *) param, RDNS_REQUEST_A, surbl_req)) {
			param->item = item;
			rspamd_symcache_item_async_inc (task, item, M);
		}
	}
	else if (err != NULL) {
		if (err->code != WHITELIST_ERROR && err->code != DUPLICATE_ERROR) {
			msg_info_surbl ("cannot format url string for surbl %*s, %e",
					url->urllen,
					url->string, err);
		}
		g_error_free (err);
		return;
	}
}

static void
process_dns_results (struct rspamd_task *task,
	struct suffix_item *suffix,
	gchar *resolved_name,
	guint32 addr,
	struct rspamd_url *uri)
{
	guint i;
	gboolean got_result = FALSE;
	struct surbl_bit_item *bit;
	struct in_addr ina;
	struct surbl_ctx *surbl_module_ctx = surbl_get_context (task->cfg);

	if (suffix->ips && g_hash_table_size (suffix->ips) > 0) {

		bit = g_hash_table_lookup (suffix->ips, &addr);
		if (bit != NULL) {
			msg_info_surbl ("<%s> domain [%s] is in surbl %s(%xd)",
					task->message_id,
					resolved_name, suffix->suffix,
					bit->bit);
			rspamd_task_insert_result (task, bit->symbol, 1, resolved_name);

			if (surbl_module_ctx->use_tags) {
				rspamd_url_add_tag (uri, "surbl", bit->symbol, task->task_pool);
			}
			got_result = TRUE;
		}
	}
	else if (suffix->bits != NULL && suffix->bits->len > 0) {
		for (i = 0; i < suffix->bits->len; i ++) {

			bit = &g_array_index (suffix->bits, struct surbl_bit_item, i);
			msg_debug_surbl ("got result(%d) AND bit(%d): %d",
				(gint)addr,
				(gint)ntohl (bit->bit),
				(gint)bit->bit & (gint)ntohl (addr));

			if (((gint)bit->bit & (gint)ntohl (addr)) != 0) {
				got_result = TRUE;
				msg_info_surbl ("<%s> domain [%s] is in surbl %s(%xd)",
						task->message_id,
						resolved_name, suffix->suffix,
						bit->bit);
				rspamd_task_insert_result (task, bit->symbol, 1, resolved_name);

				if (surbl_module_ctx->use_tags) {
					rspamd_url_add_tag (uri, "surbl", bit->symbol, task->task_pool);
				}
			}
		}
	}
	if (!got_result) {
		if ((suffix->bits == NULL || suffix->bits->len == 0) &&
				suffix->ips == NULL) {
			msg_info_surbl ("<%s> domain [%s] is in surbl %s",
					task->message_id,
					resolved_name, suffix->suffix);
			rspamd_task_insert_result (task, suffix->symbol, 1, resolved_name);

			if (surbl_module_ctx->use_tags) {
				rspamd_url_add_tag (uri, "surbl", suffix->symbol, task->task_pool);
			}
		}
		else {
			ina.s_addr = addr;
			msg_info_surbl ("<%s> domain [%s] is in surbl %s but at unknown result: %s",
					task->message_id,
					resolved_name, suffix->suffix,
					inet_ntoa (ina));
		}
	}
}

static void
surbl_dns_callback (struct rdns_reply *reply, gpointer arg)
{
	struct dns_param *param = (struct dns_param *)arg;
	struct rspamd_task *task;
	struct rdns_reply_entry *elt;

	task = param->task;
	if (reply->code == RDNS_RC_NOERROR && reply->entries) {
		msg_debug_surbl ("<%s> domain [%s] is in surbl %s",
				param->task->message_id,
			param->host_resolve, param->suffix->suffix);

		DL_FOREACH (reply->entries, elt) {
			if (elt->type == RDNS_REQUEST_A) {
				process_dns_results (param->task, param->suffix,
						param->host_resolve, (guint32) elt->content.a.addr.s_addr,
						param->url);
			}
		}
	}
	else {
		msg_debug_surbl ("<%s> domain [%s] is not in surbl %s",
			param->task->message_id, param->host_resolve,
			param->suffix->suffix);
	}

	rspamd_symcache_item_async_dec_check (param->task, param->item, M);
}

static void
surbl_dns_ip_callback (struct rdns_reply *reply, gpointer arg)
{
	struct dns_param *param = (struct dns_param *) arg;
	struct rspamd_task *task;
	struct rdns_reply_entry *elt;
	GString *to_resolve;
	guint32 ip_addr;

	task = param->task;
	/* If we have result from DNS server, this url exists in SURBL, so increase score */
	if (reply->code == RDNS_RC_NOERROR && reply->entries) {

		LL_FOREACH (reply->entries, elt) {

			if (elt->type == RDNS_REQUEST_A) {
				to_resolve = g_string_sized_new (
						strlen (param->suffix->suffix) +
						sizeof ("255.255.255.255."));
				ip_addr = elt->content.a.addr.s_addr;

				/* Big endian <4>.<3>.<2>.<1> */
				rspamd_printf_gstring (to_resolve, "%d.%d.%d.%d.%s",
						ip_addr >> 24 & 0xff,
						ip_addr >> 16 & 0xff,
						ip_addr >> 8 & 0xff,
						ip_addr & 0xff, param->suffix->suffix);
				msg_debug_surbl (
						"<%s> domain [%s] send %v request to surbl",
						param->task->message_id,
						param->host_resolve,
						to_resolve);

				if (make_dns_request_task (task,
						surbl_dns_callback,
						param, RDNS_REQUEST_A, to_resolve->str)) {
					rspamd_symcache_item_async_inc (param->task, param->item, M);
				}

				g_string_free (to_resolve, TRUE);
			}
		}
	}
	else {
		msg_debug_surbl ("<%s> domain [%s] cannot be resolved for SURBL check %s",
				param->task->message_id, param->host_resolve,
				param->suffix->suffix);

	}

	rspamd_symcache_item_async_dec_check (param->task, param->item, M);
}

static void
free_redirector_session (void *ud)
{
	struct redirector_param *param = (struct redirector_param *)ud;

	if (param->item) {
		rspamd_symcache_item_async_dec_check (param->task, param->item, M);
	}

	rspamd_http_connection_unref (param->conn);
	close (param->sock);
}

static void
surbl_redirector_error (struct rspamd_http_connection *conn,
	GError *err)
{
	struct redirector_param *param = (struct redirector_param *)conn->ud;
	struct rspamd_task *task;

	task = param->task;
	msg_err_surbl ("connection with http server %s terminated incorrectly: %e",
		rspamd_inet_address_to_string (rspamd_upstream_addr (param->redirector)),
		err);
	rspamd_upstream_fail (param->redirector, FALSE);
	rspamd_session_remove_event (param->task->s, free_redirector_session,
			param);
}

static int
surbl_redirector_finish (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg)
{
	struct redirector_param *param = (struct redirector_param *)conn->ud;
	struct rspamd_task *task;
	struct surbl_ctx *surbl_module_ctx;
	gint r, urllen;
	struct rspamd_url *redirected_url, *existing;
	const rspamd_ftok_t *hdr;
	gchar *urlstr;

	task = param->task;
	surbl_module_ctx = surbl_get_context (task->cfg);

	if (msg->code == 200) {
		hdr = rspamd_http_message_find_header (msg, "Uri");

		if (hdr != NULL) {
			msg_info_surbl ("<%s> got reply from redirector: '%*s' -> '%T'",
					param->task->message_id,
					param->url->urllen, param->url->string,
					hdr);
			urllen = hdr->len;
			urlstr = rspamd_mempool_alloc (task->task_pool,
					urllen + 1);
			redirected_url = rspamd_mempool_alloc0 (task->task_pool,
					sizeof (*redirected_url));
			rspamd_strlcpy (urlstr, hdr->begin, urllen + 1);
			r = rspamd_url_parse (redirected_url, urlstr, urllen,
					task->task_pool);

			if (r == URI_ERRNO_OK) {
				if ((existing = g_hash_table_lookup (task->urls, redirected_url)) == NULL) {
					g_hash_table_insert (task->urls, redirected_url,
							redirected_url);
					redirected_url->phished_url = param->url;
					redirected_url->flags |= RSPAMD_URL_FLAG_REDIRECTED;
				}
				else {
					existing->count ++;
				}

				if (surbl_module_ctx->use_tags) {
					rspamd_url_add_tag (param->url, "redirector", urlstr,
							task->task_pool);
				}
			}
			else {
				msg_info_surbl ("cannot parse redirector reply: %s", urlstr);
			}
		}
	}
	else {
		msg_info_surbl ("<%s> could not resolve '%*s' on redirector",
				param->task->message_id,
				param->url->urllen, param->url->string);
	}

	rspamd_upstream_ok (param->redirector);
	rspamd_session_remove_event (param->task->s, free_redirector_session,
			param);

	return 0;
}


static void
register_redirector_call (struct rspamd_url *url, struct rspamd_task *task,
	const gchar *rule)
{
	gint s = -1;
	struct redirector_param *param;
	struct timeval *timeout;
	struct upstream *selected;
	struct rspamd_http_message *msg;
	struct surbl_ctx *surbl_module_ctx = surbl_get_context (task->cfg);

	if (!rspamd_session_blocked (task->s)) {

		selected = rspamd_upstream_get (surbl_module_ctx->redirectors,
				RSPAMD_UPSTREAM_ROUND_ROBIN, url->host, url->hostlen);

		if (selected) {
			s = rspamd_inet_address_connect (rspamd_upstream_addr (selected),
					SOCK_STREAM, TRUE);
		}

		if (s == -1) {
			msg_info_surbl ("<%s> cannot create tcp socket failed: %s",
					task->message_id,
					strerror (errno));

			return;
		}

		param =
				rspamd_mempool_alloc (task->task_pool,
						sizeof (struct redirector_param));
		param->url = url;
		param->task = task;
		param->conn = rspamd_http_connection_new (NULL,
				surbl_redirector_error,
				surbl_redirector_finish,
				RSPAMD_HTTP_CLIENT_SIMPLE,
				RSPAMD_HTTP_CLIENT,
				NULL,
				NULL);
		param->ctx = surbl_module_ctx;
		msg = rspamd_http_new_message (HTTP_REQUEST);
		msg->url = rspamd_fstring_assign (msg->url, url->string, url->urllen);
		param->sock = s;
		param->redirector = selected;
		timeout = rspamd_mempool_alloc (task->task_pool, sizeof (struct timeval));
		double_to_tv (surbl_module_ctx->read_timeout, timeout);

		rspamd_session_add_event (task->s,
				free_redirector_session, param,
				M);
		param->item = rspamd_symcache_get_cur_item (task);

		if (param->item) {
			rspamd_symcache_item_async_inc (param->task, param->item, M);
		}

		rspamd_http_connection_write_message (param->conn, msg, NULL,
				NULL, param, s, timeout, task->ev_base);

		msg_info_surbl (
				"<%s> registered redirector call for %*s to %s, according to rule: %s",
				task->message_id,
				url->urllen, url->string,
				rspamd_upstream_name (param->redirector),
				rule);
	}
}

static gboolean
surbl_test_tags (struct rspamd_task *task, struct redirector_param *param,
		struct rspamd_url *url)
{
	struct rspamd_url_tag *tag = NULL, *cur;
	gchar *ftld = NULL;
	rspamd_ftok_t tld;
	gboolean processed = FALSE;

	if (url->tags) {
		tag = g_hash_table_lookup (url->tags, "surbl");
	}

	if (tag) {
		tld.begin = url->tld;
		tld.len = url->tldlen;

		ftld = rspamd_mempool_ftokdup (task->task_pool, &tld);
	}

	if (tag) {
		/* We know results for this URL */

		DL_FOREACH (tag, cur) {
			msg_info_surbl ("<%s> domain [%s] is in surbl %s (tags)",
					task->message_id,
					ftld, cur->data);
			rspamd_task_insert_result (task, cur->data, 1, ftld);
		}

		processed = TRUE;
	}

	return processed;
}

static void
surbl_tree_redirector_callback (gpointer key, gpointer value, void *data)
{
	struct redirector_param *param = data, *nparam;
	struct rspamd_task *task, **ptask;
	struct rspamd_url *url = value, **purl;
	lua_State *L;
	rspamd_regexp_t *re;
	rspamd_ftok_t srch;
	gboolean found = FALSE;
	gchar *found_tld;
	struct surbl_ctx *surbl_module_ctx;

	task = param->task;
	surbl_module_ctx = param->ctx;

	msg_debug_surbl ("check url redirection %*s", url->urllen, url->string);

	if (url->hostlen <= 0) {
		return;
	}

	/* Search in trie */
	srch.begin = url->tld;
	srch.len = url->tldlen;
	re = g_hash_table_lookup (surbl_module_ctx->redirector_tlds, &srch);

	if (re) {
		if (re == NO_REGEXP) {
			found = TRUE;
		}
		else if (rspamd_regexp_search (re, url->string, 0,
				NULL, NULL, TRUE, NULL)) {
			found = TRUE;
		}

		if (found) {
			found_tld = rspamd_mempool_ftokdup (task->task_pool, &srch);

			if (surbl_module_ctx->redirector_symbol != NULL) {
				rspamd_task_insert_result (param->task,
						surbl_module_ctx->redirector_symbol,
						1,
						found_tld);
			}

			if (param->redirector_requests >= surbl_module_ctx->max_redirected_urls) {
				msg_info_surbl ("cannot register redirector request for url domain: "
						"%s, max_redirected_urls is reached: %d",
						found_tld, surbl_module_ctx->max_redirected_urls);

				return;
			}

			param->redirector_requests ++;

			if (surbl_module_ctx->redirector_cbid != -1) {
				nparam = rspamd_mempool_alloc (task->task_pool,
						sizeof (*nparam));
				/* Copy to detach from the shared param */
				memcpy (nparam, param, sizeof (*param));
				nparam->url = url;
				L = task->cfg->lua_state;
				lua_rawgeti (L, LUA_REGISTRYINDEX,
						surbl_module_ctx->redirector_cbid);
				ptask = lua_newuserdata (L, sizeof (*ptask));
				*ptask = task;
				rspamd_lua_setclass (L, "rspamd{task}", -1);
				purl = lua_newuserdata (L, sizeof (*purl));
				*purl = url;
				rspamd_lua_setclass (L, "rspamd{url}", -1);
				lua_pushlightuserdata (L, nparam);
				rspamd_symcache_set_cur_item (task, param->item);

				if (lua_pcall (L, 3, 0, 0) != 0) {
					msg_err_task ("cannot call for redirector script: %s",
							lua_tostring (L, -1));
					lua_pop (L, 1);
				}
				else {
					nparam->item = param->item;
				}
			}
			else {
				register_redirector_call (url,
						param->task,
						found_tld);
			}
		}
	}
}

static void
surbl_tree_url_callback (gpointer key, gpointer value, void *data)
{
	struct redirector_param *param = data;
	struct rspamd_url *url = value;
	struct rspamd_task *task;
	struct surbl_ctx *surbl_module_ctx;

	if (url->hostlen <= 0) {
		return;
	}

	if (url->flags & RSPAMD_URL_FLAG_HTML_DISPLAYED) {
		/* Skip urls that are displayed only */
		return;
	}

	task = param->task;
	surbl_module_ctx = param->ctx;

	msg_debug_surbl ("check url %*s in %s", url->urllen, url->string,
			param->suffix->suffix);

	if (surbl_module_ctx->use_tags && surbl_test_tags (param->task, param, url)) {
		return;
	}

	if (url->tags && g_hash_table_lookup (url->tags, "redirector")) {
		/* URL is redirected, skip from checks */
		return;
	}

	make_surbl_requests (url, param->task, param->item, param->suffix, FALSE,
			param->tree, surbl_module_ctx);
}

static void
surbl_test_url (struct rspamd_task *task,
		struct rspamd_symcache_item *item,
		void *user_data)
{
	struct redirector_param *param;
	struct suffix_item *suffix = user_data;
	guint i, j;
	struct rspamd_mime_text_part *part;
	struct html_image *img;
	struct rspamd_url *url;
	struct surbl_ctx *surbl_module_ctx = surbl_get_context (task->cfg);

	if (!rspamd_monitored_alive (suffix->m)) {
		msg_info_surbl ("disable surbl %s as it is reported to be offline",
				suffix->suffix);
		rspamd_symcache_finalize_item (task, item);

		return;
	}

	param = rspamd_mempool_alloc0 (task->task_pool, sizeof (*param));
	param->task = task;
	param->suffix = suffix;
	param->tree = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
	param->ctx = surbl_module_ctx;
	param->item = item;

	rspamd_mempool_add_destructor (task->task_pool,
		(rspamd_mempool_destruct_t)g_hash_table_unref,
		param->tree);
	g_hash_table_foreach (task->urls, surbl_tree_url_callback, param);

	rspamd_symcache_item_async_inc (task, item, M);

	/* We also need to check and process img URLs */
	if (suffix->options & SURBL_OPTION_CHECKIMAGES) {
		for (i = 0; i < task->text_parts->len; i ++) {
			part = g_ptr_array_index (task->text_parts, i);

			if (part->html && part->html->images) {
				for (j = 0; j < part->html->images->len; j ++) {
					img = g_ptr_array_index (part->html->images, j);

					if ((img->flags & RSPAMD_HTML_FLAG_IMAGE_EXTERNAL)
							&& img->url) {
						surbl_tree_url_callback (img->url, img->url, param);
						msg_debug_surbl ("checked image url %s over %s",
								img->src, suffix->suffix);
					}
				}
			}
		}
	}

	if (suffix->options & SURBL_OPTION_CHECKDKIM) {
		struct rspamd_symbol_result *s;
		struct rspamd_symbol_option *opt;

		s = rspamd_task_find_symbol_result (task, "DKIM_TRACE");

		if (s && s->opts_head) {
			DL_FOREACH (s->opts_head, opt) {
				gsize len = strlen (opt->option);
				gchar *p = opt->option + len - 1;

				if (*p == '+') {
					url = rspamd_html_process_url (task->task_pool,
							opt->option, len - 2, NULL);

					if (url) {
						surbl_tree_url_callback (url, url, param);
						msg_debug_surbl ("checked dkim url %s over %s",
								url->string, suffix->suffix);
					}
				}
			}
		}
	}

	rspamd_symcache_item_async_dec_check (task, item, M);
}

static void
surbl_test_redirector (struct rspamd_task *task,
					   struct rspamd_symcache_item *item,
					   void *user_data)
{
	struct redirector_param *param;
	guint i, j;
	struct rspamd_mime_text_part *part;
	struct html_image *img;
	struct rspamd_url *url;
	struct surbl_ctx *surbl_module_ctx = surbl_get_context (task->cfg);

	if (!surbl_module_ctx->use_redirector || !surbl_module_ctx->redirector_tlds) {
		rspamd_symcache_finalize_item (task, item);

		return;
	}

	rspamd_symcache_item_async_inc (task, item, M);

	param = rspamd_mempool_alloc0 (task->task_pool, sizeof (*param));
	param->task = task;
	param->suffix = NULL;
	param->redirector_requests = 0;
	param->ctx = surbl_module_ctx;
	param->item = item;
	g_hash_table_foreach (task->urls, surbl_tree_redirector_callback, param);

	/* We also need to check and process img URLs */
	for (i = 0; i < task->text_parts->len; i ++) {
		part = g_ptr_array_index (task->text_parts, i);
		if (part->html && part->html->images) {
			for (j = 0; j < part->html->images->len; j ++) {
				img = g_ptr_array_index (part->html->images, j);

				if ((img->flags & RSPAMD_HTML_FLAG_IMAGE_EXTERNAL)
						&& img->src) {
					url = rspamd_html_process_url (task->task_pool,
							img->src, strlen (img->src), NULL);

					if (url) {
						surbl_tree_redirector_callback (url, url, param);
						msg_debug_surbl ("checked image url %s for redirectors",
								img->src);
					}
				}
			}
		}
	}

	rspamd_symcache_item_async_dec_check (task, item, M);
}


static gint
surbl_register_redirect_handler (lua_State *L)
{
	struct surbl_ctx *surbl_module_ctx;
	struct rspamd_config *cfg = lua_check_config (L, 1);

	if (!cfg) {
		return luaL_error (L, "config is now required as the first parameter");
	}

	surbl_module_ctx = surbl_get_context (cfg);

	if (surbl_module_ctx->redirector_cbid != -1) {
		luaL_unref (L, LUA_REGISTRYINDEX, surbl_module_ctx->redirector_cbid);
	}

	lua_pushvalue (L, 2);

	if (lua_type (L, -1) == LUA_TFUNCTION) {
		surbl_module_ctx->redirector_cbid = luaL_ref (L, LUA_REGISTRYINDEX);
		surbl_module_ctx->use_redirector = TRUE;
	}
	else {
		lua_pop (L, 1);

		return luaL_error (L, "argument must be a function");
	}

	return 0;
}

static gint
surbl_is_redirector_handler (lua_State *L)
{
	const gchar *url;
	struct rspamd_task *task;
	struct rspamd_url uri;
	gsize len;
	rspamd_regexp_t *re;
	rspamd_ftok_t srch;
	gboolean found = FALSE;
	gchar *found_tld, *url_cpy;
	struct surbl_ctx *surbl_module_ctx;

	task = lua_check_task (L, 1);
	url = luaL_checklstring (L, 2, &len);
	surbl_module_ctx = surbl_get_context (task->cfg);

	if (task && url) {
		url_cpy = rspamd_mempool_alloc (task->task_pool, len);
		memcpy (url_cpy, url, len);

		if (rspamd_url_parse (&uri, url_cpy, len, task->task_pool)) {
			msg_debug_surbl ("check url redirection %*s", uri.urllen,
					uri.string);

			if (uri.hostlen <= 0) {
				lua_pushboolean (L, false);

				return 1;
			}

			/* Search in trie */
			srch.begin = uri.tld;
			srch.len = uri.tldlen;
			re = g_hash_table_lookup (surbl_module_ctx->redirector_tlds, &srch);

			if (re) {
				if (re == NO_REGEXP) {
					found = TRUE;
				}
				else if (rspamd_regexp_search (re, uri.string, 0,
						NULL, NULL, TRUE, NULL)) {
					found = TRUE;
				}

				if (found) {
					found_tld = rspamd_mempool_ftokdup (task->task_pool, &srch);
					lua_pushboolean (L, true);
					lua_pushstring (L, found_tld);

					return 2;
				}
			}
		}
	}
	else {
		return luaL_error (L, "arguments must be: task, url");
	}

	lua_pushboolean (L, false);

	return 1;
}

/*
 * Accepts two arguments:
 * url: string with a redirected URL, if url is nil, then it couldn't be resolved
 * userdata: opaque pointer of `struct redirector_param *`
 */
static gint
surbl_continue_process_handler (lua_State *L)
{
	struct redirector_param *param;
	struct rspamd_task *task;
	const gchar *nurl;
	gint r;
	gsize urllen;
	struct rspamd_url *redirected_url;
	gchar *urlstr;
	struct surbl_ctx *surbl_module_ctx;

	nurl = lua_tolstring (L, 1, &urllen);
	param = (struct redirector_param *)lua_topointer (L, 2);

	if (param != NULL) {
		task = param->task;
		surbl_module_ctx = surbl_get_context (task->cfg);

		if (nurl != NULL) {
			msg_info_surbl ("<%s> got reply from redirector: '%*s' -> '%*s'",
					param->task->message_id,
					param->url->urllen, param->url->string,
					(gint)urllen, nurl);
			urlstr = rspamd_mempool_alloc (task->task_pool,
					urllen + 1);
			redirected_url = rspamd_mempool_alloc0 (task->task_pool,
					sizeof (*redirected_url));
			rspamd_strlcpy (urlstr, nurl, urllen + 1);
			r = rspamd_url_parse (redirected_url, urlstr, urllen,
					task->task_pool);

			if (r == URI_ERRNO_OK) {
				if (!g_hash_table_lookup (task->urls, redirected_url)) {
					g_hash_table_insert (task->urls, redirected_url,
							redirected_url);
					redirected_url->phished_url = param->url;
					redirected_url->flags |= RSPAMD_URL_FLAG_REDIRECTED;
				}

				if (surbl_module_ctx->use_tags) {
					rspamd_url_add_tag (param->url, "redirector", urlstr,
							task->task_pool);
				}
			}
			else {
				msg_info_surbl ("<%s> could not resolve '%*s' on redirector",
						param->task->message_id,
						param->url->urllen, param->url->string);
			}
		}
		else {
			msg_info_surbl ("<%s> could not resolve '%*s' on redirector",
					param->task->message_id,
					param->url->urllen, param->url->string);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}
