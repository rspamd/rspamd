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

#include "../config.h"
#include "../util.h"
#include "../message.h"
#include "../view.h"
#include "../map.h"
#include "../evdns/evdns.h"

#include "surbl.h"

static struct surbl_ctx        *surbl_module_ctx = NULL;

static int                      surbl_filter (struct worker_task *task);
static void                     surbl_test_url (struct worker_task *task, void *user_data);
static void                     dns_callback (int result, char type, int count, int ttl, void *addresses, void *data);
static void                     process_dns_results (struct worker_task *task, struct suffix_item *suffix, char *url, uint32_t addr);
static int                      urls_command_handler (struct worker_task *task);

#define SURBL_ERROR surbl_error_quark ()
#define WHITELIST_ERROR 0
#define CONVERSION_ERROR 1
GQuark
surbl_error_quark (void)
{
	return g_quark_from_static_string ("surbl-error-quark");
}

static void
exception_insert (gpointer st, gconstpointer key, gpointer value)
{
	GHashTable                    **t = st;
	int                             level = 0;
	const char                     *p = key;
	f_str_t                        *val;
	

	while (*p) {
		if (*p == '.') {
			level ++;
		}
		p ++;
	}
	if (level >= MAX_LEVELS) {
		msg_err ("invalid domain in exceptions list: %s, levels: %d", (char *)key, level);
		return;
	}
	
	val = g_malloc (sizeof (f_str_t));
	val->begin = (char *)key;
	val->len = strlen (key);
	if (t[level] == NULL) {
		t[level] = g_hash_table_new_full (fstr_strcase_hash, fstr_strcase_equal, g_free, NULL);
	}
	g_hash_table_insert (t[level], val, value);
}

static u_char *
read_exceptions_list (memory_pool_t * pool, u_char * chunk, size_t len, struct map_cb_data *data)
{
	if (data->cur_data == NULL) {
		data->cur_data = memory_pool_alloc (pool, sizeof (GHashTable *) * MAX_LEVELS);
	}
	return abstract_parse_list (pool, chunk, len, data, (insert_func) exception_insert);
}

static void
fin_exceptions_list (memory_pool_t * pool, struct map_cb_data *data)
{
	GHashTable                    **t;
	int                             i;

	if (data->prev_data) {
		t = data->prev_data;
		for (i = 0; i < MAX_LEVELS; i ++) {
			if (t[i] != NULL) {
				g_hash_table_destroy (t[i]);
			}
		}
	}
}

int
surbl_module_init (struct config_file *cfg, struct module_ctx **ctx)
{
	surbl_module_ctx = g_malloc (sizeof (struct surbl_ctx));

	surbl_module_ctx->filter = surbl_filter;
	surbl_module_ctx->use_redirector = 0;
	surbl_module_ctx->suffixes = NULL;
	surbl_module_ctx->bits = NULL;
	surbl_module_ctx->surbl_pool = memory_pool_new (memory_pool_get_size ());

	surbl_module_ctx->tld2_file = NULL;
	surbl_module_ctx->whitelist_file = NULL;

	surbl_module_ctx->redirector_hosts = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
	surbl_module_ctx->whitelist = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
	/* Zero exceptions hashes */
	surbl_module_ctx->exceptions = memory_pool_alloc0 (surbl_module_ctx->surbl_pool, MAX_LEVELS * sizeof (GHashTable *));
	/* Register destructors */
	memory_pool_add_destructor (surbl_module_ctx->surbl_pool, (pool_destruct_func) g_hash_table_destroy, surbl_module_ctx->whitelist);
	memory_pool_add_destructor (surbl_module_ctx->surbl_pool, (pool_destruct_func) g_hash_table_destroy, surbl_module_ctx->redirector_hosts);

	memory_pool_add_destructor (surbl_module_ctx->surbl_pool, (pool_destruct_func) g_list_free, surbl_module_ctx->suffixes);
	memory_pool_add_destructor (surbl_module_ctx->surbl_pool, (pool_destruct_func) g_list_free, surbl_module_ctx->bits);

	*ctx = (struct module_ctx *)surbl_module_ctx;

	register_protocol_command ("urls", urls_command_handler);

	return 0;
}

int
surbl_module_config (struct config_file *cfg)
{
	struct hostent                 *hent;
	GList                          *cur_opt;
	struct module_opt              *cur;
	struct suffix_item             *new_suffix;
	struct surbl_bit_item          *new_bit;

	char                           *value, *cur_tok, *str;
	uint32_t                        bit;


	if ((value = get_module_opt (cfg, "surbl", "redirector")) != NULL) {
		str = memory_pool_strdup (surbl_module_ctx->surbl_pool, value);
		cur_tok = strsep (&str, ":");
		if (!inet_aton (cur_tok, &surbl_module_ctx->redirector_addr)) {
			/* Try to call gethostbyname */
			hent = gethostbyname (cur_tok);
			if (hent != NULL) {
				memcpy ((char *)&surbl_module_ctx->redirector_addr, hent->h_addr, sizeof (struct in_addr));
				if (str != NULL) {
					surbl_module_ctx->redirector_port = (uint16_t) strtoul (str, NULL, 10);
				}
				else {
					surbl_module_ctx->redirector_port = DEFAULT_REDIRECTOR_PORT;
				}
				surbl_module_ctx->use_redirector = 1;
			}
		}
	}
	if ((value = get_module_opt (cfg, "surbl", "weight")) != NULL) {
		surbl_module_ctx->weight = atoi (value);
	}
	else {
		surbl_module_ctx->weight = DEFAULT_SURBL_WEIGHT;
	}
	if ((value = get_module_opt (cfg, "surbl", "url_expire")) != NULL) {
		surbl_module_ctx->url_expire = atoi (value);
	}
	else {
		surbl_module_ctx->url_expire = DEFAULT_SURBL_URL_EXPIRE;
	}
	if ((value = get_module_opt (cfg, "surbl", "redirector_connect_timeout")) != NULL) {
		surbl_module_ctx->connect_timeout = parse_seconds (value);
	}
	else {
		surbl_module_ctx->connect_timeout = DEFAULT_REDIRECTOR_CONNECT_TIMEOUT;
	}
	if ((value = get_module_opt (cfg, "surbl", "redirector_read_timeout")) != NULL) {
		surbl_module_ctx->read_timeout = parse_seconds (value);
	}
	else {
		surbl_module_ctx->read_timeout = DEFAULT_REDIRECTOR_READ_TIMEOUT;
	}
	if ((value = get_module_opt (cfg, "surbl", "redirector_hosts_map")) != NULL) {
		add_map (value, read_host_list, fin_host_list, (void **)&surbl_module_ctx->redirector_hosts);
	}
	else {
		surbl_module_ctx->read_timeout = DEFAULT_REDIRECTOR_READ_TIMEOUT;
	}
	if ((value = get_module_opt (cfg, "surbl", "max_urls")) != NULL) {
		surbl_module_ctx->max_urls = atoi (value);
	}
	else {
		surbl_module_ctx->max_urls = DEFAULT_SURBL_MAX_URLS;
	}
	if ((value = get_module_opt (cfg, "surbl", "exceptions")) != NULL) {
		if (add_map (value, read_exceptions_list, fin_exceptions_list, (void **)&surbl_module_ctx->exceptions)) {
			surbl_module_ctx->tld2_file = memory_pool_strdup (surbl_module_ctx->surbl_pool, value + sizeof ("file://") - 1);
		}
	}
	if ((value = get_module_opt (cfg, "surbl", "whitelist")) != NULL) {
		if (add_map (value, read_host_list, fin_host_list, (void **)&surbl_module_ctx->whitelist)) {
			surbl_module_ctx->whitelist_file = memory_pool_strdup (surbl_module_ctx->surbl_pool, value + sizeof ("file://") - 1);
		}
	}


	cur_opt = g_hash_table_lookup (cfg->modules_opts, "surbl");
	while (cur_opt) {
		cur = cur_opt->data;
		if (!g_strncasecmp (cur->param, "suffix", sizeof ("suffix") - 1)) {
			if ((str = strchr (cur->param, '_')) != NULL) {
				new_suffix = memory_pool_alloc (surbl_module_ctx->surbl_pool, sizeof (struct suffix_item));
				*str = '\0';
				new_suffix->symbol = memory_pool_strdup (surbl_module_ctx->surbl_pool, str + 1);
				new_suffix->suffix = memory_pool_strdup (surbl_module_ctx->surbl_pool, cur->value);
				msg_debug ("add new surbl suffix: %s with symbol: %s", new_suffix->suffix, new_suffix->symbol);
				*str = '_';
				surbl_module_ctx->suffixes = g_list_prepend (surbl_module_ctx->suffixes, new_suffix);
				register_symbol (&cfg->cache, new_suffix->symbol, 1, surbl_test_url, new_suffix);
			}
		}
		if (!g_strncasecmp (cur->param, "bit", sizeof ("bit") - 1)) {
			if ((str = strchr (cur->param, '_')) != NULL) {
				bit = strtoul (str + 1, NULL, 10);
				if (bit != 0) {
					new_bit = memory_pool_alloc (surbl_module_ctx->surbl_pool, sizeof (struct surbl_bit_item));
					new_bit->bit = bit;
					new_bit->symbol = memory_pool_strdup (surbl_module_ctx->surbl_pool, cur->value);
					msg_debug ("add new bit suffix: %d with symbol: %s", (int)new_bit->bit, new_bit->symbol);
					surbl_module_ctx->bits = g_list_prepend (surbl_module_ctx->bits, new_bit);
				}
			}
		}
		cur_opt = g_list_next (cur_opt);
	}
	/* Add default suffix */
	if (surbl_module_ctx->suffixes == NULL) {
		new_suffix = memory_pool_alloc (surbl_module_ctx->surbl_pool, sizeof (struct suffix_item));
		new_suffix->suffix = memory_pool_strdup (surbl_module_ctx->surbl_pool, DEFAULT_SURBL_SUFFIX);
		new_suffix->symbol = memory_pool_strdup (surbl_module_ctx->surbl_pool, DEFAULT_SURBL_SYMBOL);
		msg_debug ("add default surbl suffix: %s with symbol: %s", new_suffix->suffix, new_suffix->symbol);
		surbl_module_ctx->suffixes = g_list_prepend (surbl_module_ctx->suffixes, new_suffix);
		register_symbol (&cfg->cache, new_suffix->symbol, 1, surbl_test_url, new_suffix);
	}

	return TRUE;
}

int
surbl_module_reconfig (struct config_file *cfg)
{
	memory_pool_delete (surbl_module_ctx->surbl_pool);
	surbl_module_ctx->surbl_pool = memory_pool_new (1024);

	return surbl_module_config (cfg);
}



static char                    *
format_surbl_request (memory_pool_t * pool, f_str_t * hostname, struct suffix_item *suffix, gboolean append_suffix, GError ** err)
{
	GHashTable                     *t;
	char                           *result = NULL, *dots[MAX_LEVELS], num_buf[sizeof("18446744073709551616")], *p;
	int                             len, slen, r, i, dots_num = 0, level = MAX_LEVELS;
	gboolean                        is_numeric = TRUE;
	guint64                         ip_num;
	f_str_t                         f;

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
	while (p - hostname->begin < hostname->len && dots_num < MAX_LEVELS) {
		if (*p == '.') {
			dots[dots_num] = p;
			dots_num ++;
		}
		else if (! g_ascii_isdigit (*p)) {
			is_numeric = FALSE;
		}
		p ++;
	}
	
	/* Check for numeric expressions */
	if (is_numeric && dots_num == 3) {
		/* This is ip address */
		result = memory_pool_alloc (pool, len);
		r = snprintf (result, len, "%*s.%*s.%*s.%*s", 
				(int)(hostname->len - (dots[2] - hostname->begin + 1)),
				dots[2] + 1,
				(int)(dots[2] - dots[1] - 1),
				dots[1],
				(int)(dots[1] - dots[0] - 1),
				dots[0],
				(int)(dots[0] - hostname->begin),
				hostname->begin);
	}
	else if (is_numeric && dots_num == 0) {
		/* This is number */
		g_strlcpy (num_buf, hostname->begin, MIN (hostname->len + 1, sizeof (num_buf)));
		errno = 0;
		ip_num = strtoull (num_buf, NULL, 10);
		if (errno != 0) {
			msg_info ("cannot convert ip to number '%s': %s", num_buf, strerror (errno));
			g_set_error (err, SURBL_ERROR,	/* error domain */
				CONVERSION_ERROR,	/* error code */
				"URL cannot be decoded");
			return NULL;
		}

		len = sizeof ("255.255.255.255") + slen;
		result = memory_pool_alloc (pool, len);
		/* Hack for bugged windows resolver */
		ip_num &= 0xFFFFFFFF;
		/* Get octets */
		r = snprintf (result, len, "%u.%u.%u.%u",
			(uint32_t) ip_num & 0x000000FF, (uint32_t) (ip_num & 0x0000FF00) >> 8, (uint32_t) (ip_num & 0x00FF0000) >> 16, (uint32_t) (ip_num & 0xFF000000) >> 24);
	}
	else {
		/* Not a numeric url */
		result = memory_pool_alloc (pool, len);
		/* Now we should try to check for exceptions */
		for (i = MAX_LEVELS - 1; i >= 0; i --) {
			t = surbl_module_ctx->exceptions[i];
			if (t != NULL && dots_num >= i + 1) {
				f.begin = dots[dots_num - i - 1] + 1;
				f.len = hostname->len - (dots[dots_num - i - 1] - hostname->begin + 1);
				if (g_hash_table_lookup (t, &f) != NULL) {
					level = dots_num - i - 1;
					break;
				}
			}
		}
		if (level != MAX_LEVELS) {
			if (level == 0) {
				r = snprintf (result, len, "%*s", (int)hostname->len, hostname->begin);
			}
			else {
				r = snprintf (result, len, "%*s", 
					(int)(hostname->len - (dots[level - 1] - hostname->begin + 1)),
					dots[level - 1] + 1);
			}
		}
		else if (dots_num >= 2) {
			r = snprintf (result, len, "%*s",
					(int)(hostname->len - (dots[dots_num - 2] - hostname->begin + 1)),
					dots[dots_num - 2] + 1);
		}
		else {
			r = snprintf (result, len, "%*s", (int)hostname->len, hostname->begin);
		}
	}

	if (g_hash_table_lookup (surbl_module_ctx->whitelist, result) != NULL) {
		msg_debug ("url %s is whitelisted", result);
		g_set_error (err, SURBL_ERROR,	/* error domain */
						WHITELIST_ERROR,	/* error code */
						"URL is whitelisted: %s",	/* error message format string */
						result);
		return NULL;
	}


	if (append_suffix) {
		r += snprintf (result + r, len - r, ".%s", suffix->suffix);
	}

	msg_debug ("request: %s, dots: %d, level: %d, orig: %*s", result, dots_num, level, (int)hostname->len, hostname->begin);

	return result;
}

static void
make_surbl_requests (struct uri *url, struct worker_task *task, GTree * tree, struct suffix_item *suffix)
{
	char                           *surbl_req;
	f_str_t                         f;
	GError                         *err = NULL;
	struct dns_param               *param;

	f.begin = url->host;
	f.len = url->hostlen;

	if (check_view (task->cfg->views, suffix->symbol, task)) {
		if ((surbl_req = format_surbl_request (task->task_pool, &f, suffix, TRUE, &err)) != NULL) {
			if (g_tree_lookup (tree, surbl_req) == NULL) {
				g_tree_insert (tree, surbl_req, surbl_req);
				param = memory_pool_alloc (task->task_pool, sizeof (struct dns_param));
				param->url = url;
				param->task = task;
				param->suffix = suffix;
				param->host_resolve = memory_pool_strdup (task->task_pool, surbl_req);
				debug_task ("send surbl dns request %s", surbl_req);
				if (evdns_resolve_ipv4 (surbl_req, DNS_QUERY_NO_SEARCH, dns_callback, (void *)param) == 0) {
					param->task->save.saved++;
					register_async_event (task->s, (event_finalizer_t) dns_callback, NULL, TRUE);
				}
			}
			else {
				debug_task ("request %s is already sent", surbl_req);
			}
		}
		else if (err != NULL && err->code != WHITELIST_ERROR) {
			msg_info ("cannot format url string for surbl %s, %s", struri (url), err->message);
			g_error_free (err);
			return;
		}
		else if (err != NULL) {
			g_error_free (err);
		}
	}
	else {
		debug_task ("skipping symbol that is not in view: %s", suffix->symbol);
	}
}

static void
process_dns_results (struct worker_task *task, struct suffix_item *suffix, char *url, uint32_t addr)
{
	char                           *c, *symbol;
	GList                          *cur;
	struct surbl_bit_item          *bit;
	int                             len, found = 0;

	if ((c = strchr (suffix->symbol, '%')) != NULL && *(c + 1) == 'b') {
		cur = g_list_first (surbl_module_ctx->bits);

		while (cur) {
			bit = (struct surbl_bit_item *)cur->data;
			debug_task ("got result(%d) AND bit(%d): %d", (int)addr, (int)ntohl (bit->bit), (int)bit->bit & (int)ntohl (addr));
			if (((int)bit->bit & (int)ntohl (addr)) != 0) {
				len = strlen (suffix->symbol) - 2 + strlen (bit->symbol) + 1;
				*c = '\0';
				symbol = memory_pool_alloc (task->task_pool, len);
				snprintf (symbol, len, "%s%s%s", suffix->symbol, bit->symbol, c + 2);
				*c = '%';
				insert_result (task, symbol, 1, g_list_prepend (NULL, memory_pool_strdup (task->task_pool, url)));
				found = 1;
			}
			cur = g_list_next (cur);
		}

		if (!found) {
			insert_result (task, suffix->symbol, 1, g_list_prepend (NULL, memory_pool_strdup (task->task_pool, url)));
		}
	}
	else {
		insert_result (task, suffix->symbol, 1, g_list_prepend (NULL, memory_pool_strdup (task->task_pool, url)));
	}
}

static void
dns_callback (int result, char type, int count, int ttl, void *addresses, void *data)
{
	struct dns_param               *param = (struct dns_param *)data;
	struct worker_task             *task = param->task;

	debug_task ("in surbl request callback");
	/* If we have result from DNS server, this url exists in SURBL, so increase score */
	if (result == DNS_ERR_NONE && type == DNS_IPv4_A) {
		msg_info ("<%s> domain [%s] is in surbl %s", param->task->message_id, param->host_resolve, param->suffix->suffix);
		process_dns_results (param->task, param->suffix, param->host_resolve, (uint32_t) (((in_addr_t *) addresses)[0]));
	}
	else {
		debug_task ("<%s> domain [%s] is not in surbl %s", param->task->message_id, param->host_resolve, param->suffix->suffix);
	}

	param->task->save.saved--;
	if (param->task->save.saved == 0) {
		/* Call other filters */
		param->task->save.saved = 1;
		process_filters (param->task);
	}
	remove_forced_event (param->task->s, (event_finalizer_t) dns_callback);

}

static void
memcached_callback (memcached_ctx_t * ctx, memc_error_t error, void *data)
{
	struct memcached_param         *param = (struct memcached_param *)data;
	int                            *url_count;

	switch (ctx->op) {
	case CMD_CONNECT:
		if (error != OK) {
			msg_info ("memcached returned error %s on CONNECT stage", memc_strerror (error));
			memc_close_ctx (param->ctx);
			param->task->save.saved--;
			if (param->task->save.saved == 0) {
				/* Call other filters */
				param->task->save.saved = 1;
				process_filters (param->task);
			}
		}
		else {
			memc_get (param->ctx, param->ctx->param);
		}
		break;
	case CMD_READ:
		if (error != OK) {
			msg_info ("memcached returned error %s on READ stage", memc_strerror (error));
			memc_close_ctx (param->ctx);
			param->task->save.saved--;
			if (param->task->save.saved == 0) {
				/* Call other filters */
				param->task->save.saved = 1;
				process_filters (param->task);
			}
		}
		else {
			url_count = (int *)param->ctx->param->buf;
			/* Do not check DNS for urls that have count more than max_urls */
			if (*url_count > surbl_module_ctx->max_urls) {
				msg_info ("url '%s' has count %d, max: %d", struri (param->url), *url_count, surbl_module_ctx->max_urls);
				/* 
				 * XXX: try to understand why we should use memcached here
				 * insert_result (param->task, surbl_module_ctx->metric, surbl_module_ctx->symbol, 1);
				 */
			}
			(*url_count)++;
			memc_set (param->ctx, param->ctx->param, surbl_module_ctx->url_expire);
		}
		break;
	case CMD_WRITE:
		if (error != OK) {
			msg_info ("memcached returned error %s on WRITE stage", memc_strerror (error));
		}
		memc_close_ctx (param->ctx);
		param->task->save.saved--;
		if (param->task->save.saved == 0) {
			/* Call other filters */
			param->task->save.saved = 1;
			process_filters (param->task);
		}
		make_surbl_requests (param->url, param->task, param->tree, param->suffix);
		break;
	default:
		return;
	}
}

static void
register_memcached_call (struct uri *url, struct worker_task *task, GTree * url_tree, struct suffix_item *suffix)
{
	struct memcached_param         *param;
	struct memcached_server        *selected;
	memcached_param_t              *cur_param;
	gchar                          *sum_str;
	int                            *url_count;

	param = memory_pool_alloc (task->task_pool, sizeof (struct memcached_param));
	cur_param = memory_pool_alloc0 (task->task_pool, sizeof (memcached_param_t));
	url_count = memory_pool_alloc (task->task_pool, sizeof (int));

	param->url = url;
	param->task = task;
	param->tree = url_tree;
	param->suffix = suffix;

	param->ctx = memory_pool_alloc0 (task->task_pool, sizeof (memcached_ctx_t));

	cur_param->buf = (u_char *) url_count;
	cur_param->bufsize = sizeof (int);

	sum_str = g_compute_checksum_for_string (G_CHECKSUM_MD5, struri (url), -1);
	g_strlcpy (cur_param->key, sum_str, sizeof (cur_param->key));
	g_free (sum_str);

	selected = (struct memcached_server *)get_upstream_by_hash ((void *)task->cfg->memcached_servers,
		task->cfg->memcached_servers_num, sizeof (struct memcached_server),
		time (NULL), task->cfg->memcached_error_time, task->cfg->memcached_dead_time, task->cfg->memcached_maxerrors, cur_param->key, strlen (cur_param->key));
	if (selected == NULL) {
		msg_err ("no memcached servers can be selected");
		return;
	}
	param->ctx->callback = memcached_callback;
	param->ctx->callback_data = (void *)param;
	param->ctx->protocol = task->cfg->memcached_protocol;
	memcpy (&param->ctx->addr, &selected->addr, sizeof (struct in_addr));
	param->ctx->port = selected->port;
	param->ctx->timeout.tv_sec = task->cfg->memcached_connect_timeout / 1000;
	param->ctx->timeout.tv_sec = task->cfg->memcached_connect_timeout - param->ctx->timeout.tv_sec * 1000;
	param->ctx->sock = -1;
#ifdef WITH_DEBUG
	param->ctx->options = MEMC_OPT_DEBUG;
#else
	param->ctx->options = 0;
#endif
	param->ctx->param = cur_param;
	memc_init_ctx (param->ctx);
}

static void
free_redirector_session (void *ud)
{
	struct redirector_param        *param = (struct redirector_param *)ud;

	event_del (&param->ev);
	close (param->sock);
	param->task->save.saved--;
	make_surbl_requests (param->url, param->task, param->tree, param->suffix);
	if (param->task->save.saved == 0) {
		/* Call other filters */
		param->task->save.saved = 1;
		process_filters (param->task);
	}

}

static void
redirector_callback (int fd, short what, void *arg)
{
	struct redirector_param        *param = (struct redirector_param *)arg;
	struct worker_task             *task = param->task;
	char                            url_buf[1024];
	int                             r;
	struct timeval                 *timeout;
	char                           *p, *c;

	switch (param->state) {
	case STATE_CONNECT:
		/* We have write readiness after connect call, so reinit event */
		if (what == EV_WRITE) {
			timeout = memory_pool_alloc (param->task->task_pool, sizeof (struct timeval));
			timeout->tv_sec = surbl_module_ctx->read_timeout / 1000;
			timeout->tv_usec = surbl_module_ctx->read_timeout - timeout->tv_sec * 1000;
			event_del (&param->ev);
			event_set (&param->ev, param->sock, EV_READ | EV_PERSIST, redirector_callback, (void *)param);
			event_add (&param->ev, timeout);
			r = snprintf (url_buf, sizeof (url_buf), "GET %s HTTP/1.0\r\n\r\n", struri (param->url));
			if (write (param->sock, url_buf, r) == -1) {
				msg_err ("write failed %s", strerror (errno));
				remove_normal_event (param->task->s, free_redirector_session, param);
				return;
			}
			param->state = STATE_READ;
		}
		else {
			msg_info ("<%s> connection to redirector timed out while waiting for write", param->task->message_id);
			remove_normal_event (param->task->s, free_redirector_session, param);
			return;
		}
		break;
	case STATE_READ:
		if (what == EV_READ) {
			r = read (param->sock, url_buf, sizeof (url_buf));
			if ((p = strstr (url_buf, "Uri: ")) != NULL) {
				p += sizeof ("Uri: ") - 1;
				c = p;
				while (p++ < url_buf + sizeof (url_buf) - 1) {
					if (*p == '\r' || *p == '\n') {
						*p = '\0';
						break;
					}
				}
				if (*p == '\0') {
					debug_task ("<%s> got reply from redirector: '%s' -> '%s'", param->task->message_id, struri (param->url), c);
					parse_uri (param->url, memory_pool_strdup (param->task->task_pool, c), param->task->task_pool);
				}
			}
			remove_normal_event (param->task->s, free_redirector_session, param);
		}
		else {
			msg_info ("<%s> reading redirector timed out, while waiting for read", param->task->message_id);
			remove_normal_event (param->task->s, free_redirector_session, param);
		}
		break;
	}
}


static void
register_redirector_call (struct uri *url, struct worker_task *task, GTree * url_tree, struct suffix_item *suffix)
{
	int                             s;
	struct redirector_param        *param;
	struct timeval                 *timeout;

	s = make_tcp_socket (&surbl_module_ctx->redirector_addr, surbl_module_ctx->redirector_port, FALSE, TRUE);

	if (s == -1) {
		msg_info ("<%s> cannot create tcp socket failed: %s", task->message_id, strerror (errno));
		task->save.saved--;
		make_surbl_requests (url, task, url_tree, suffix);
		return;
	}

	param = memory_pool_alloc (task->task_pool, sizeof (struct redirector_param));
	param->url = url;
	param->task = task;
	param->state = STATE_CONNECT;
	param->sock = s;
	param->tree = url_tree;
	param->suffix = suffix;
	timeout = memory_pool_alloc (task->task_pool, sizeof (struct timeval));
	timeout->tv_sec = surbl_module_ctx->connect_timeout / 1000;
	timeout->tv_usec = surbl_module_ctx->connect_timeout - timeout->tv_sec * 1000;
	event_set (&param->ev, s, EV_WRITE, redirector_callback, (void *)param);
	event_add (&param->ev, timeout);
	register_async_event (task->s, free_redirector_session, param, FALSE);
}

static                          gboolean
tree_url_callback (gpointer key, gpointer value, void *data)
{
	struct redirector_param        *param = data;
	struct worker_task             *task = param->task;
	struct uri                     *url = value;
	f_str_t                         f;
	char                           *urlstr;
	GError                         *err = NULL;

	debug_task ("check url %s", struri (url));


	if (surbl_module_ctx->use_redirector) {
		f.begin = url->host;
		f.len = url->hostlen;
		if ((urlstr = format_surbl_request (param->task->task_pool, &f, NULL, FALSE, &err)) != NULL) {
			if (g_hash_table_lookup (surbl_module_ctx->redirector_hosts, urlstr) != NULL) {
				register_redirector_call (url, param->task, param->tree, param->suffix);
				param->task->save.saved++;
				return FALSE;
			}
		}
		make_surbl_requests (url, param->task, param->tree, param->suffix);
	}
	else {
		if (param->task->worker->srv->cfg->memcached_servers_num > 0) {
			register_memcached_call (url, param->task, param->tree, param->suffix);
			param->task->save.saved++;
		}
		else {
			make_surbl_requests (url, param->task, param->tree, param->suffix);
		}
	}

	return FALSE;
}

static void
surbl_test_url (struct worker_task *task, void *user_data)
{
	GTree                          *url_tree;
	GList                          *cur;
	struct mime_text_part          *part;
	struct redirector_param         param;
	struct suffix_item             *suffix = user_data;

	url_tree = g_tree_new ((GCompareFunc) g_ascii_strcasecmp);

	param.tree = url_tree;
	param.task = task;
	param.suffix = suffix;
	cur = task->text_parts;
	while (cur) {
		part = cur->data;
		if (part->urls) {
			g_tree_foreach (part->urls, tree_url_callback, &param);
		}
		if (part->html_urls) {
			g_tree_foreach (part->html_urls, tree_url_callback, &param);
		}

		cur = g_list_next (cur);
	}

	memory_pool_add_destructor (task->task_pool, (pool_destruct_func) g_tree_destroy, url_tree);
}

static int
surbl_filter (struct worker_task *task)
{
	/* XXX: remove this shit */
	return 0;
}

static int
urls_command_handler (struct worker_task *task)
{
	GList                          *cur;
	char                           *outbuf, *urlstr;
	int                             r, num = 0, buflen;
	struct uri                     *url;
	GError                         *err = NULL;
	GTree                          *url_tree;
	f_str_t                         f;

	url_tree = g_tree_new ((GCompareFunc) g_ascii_strcasecmp);

	/* First calculate buffer length */
	cur = g_list_first (task->urls);
	buflen = 0;
	while (cur) {
		url = cur->data;
		buflen += strlen (struri (url)) + url->hostlen + sizeof (" <\"\">, ") - 1;
		cur = g_list_next (cur);
	}

	buflen += sizeof (RSPAMD_REPLY_BANNER " 0 OK" CRLF CRLF "URLs: ");

	outbuf = memory_pool_alloc (task->task_pool, buflen * sizeof (char));

	r = snprintf (outbuf, buflen, "%s 0 %s" CRLF, (task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER, "OK");

	r += snprintf (outbuf + r, buflen - r - 2, "URLs: ");

	cur = g_list_first (task->urls);

	while (cur) {
		num++;
		url = cur->data;
		if (g_tree_lookup (url_tree, struri (url)) == NULL) {
			g_tree_insert (url_tree, struri (url), url);
			f.begin = url->host;
			f.len = url->hostlen;
			if ((urlstr = format_surbl_request (task->task_pool, &f, NULL, FALSE, &err)) != NULL) {
				if (g_list_next (cur) != NULL) {
					r += snprintf (outbuf + r, buflen - r - 2, "%s <\"%s\">, ", (char *)urlstr, struri (url));
				}
				else {
					r += snprintf (outbuf + r, buflen - r - 2, "%s <\"%s\">", (char *)urlstr, struri (url));
				}
			}
		}
		cur = g_list_next (cur);
	}

	outbuf[r++] = '\r';
	outbuf[r++] = '\n';

	rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE, TRUE);
	msg_info ("msg ok, id: <%s>, %d urls extracted", task->message_id, num);
	g_tree_destroy (url_tree);

	return 0;
}


/*
 * vi:ts=4 
 */
