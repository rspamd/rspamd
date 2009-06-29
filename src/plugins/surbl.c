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
 */

#include "../config.h"
#include "../util.h"
#include "../message.h"
#include "../view.h"
#include <evdns.h>

#include "surbl.h"

static struct surbl_ctx *surbl_module_ctx = NULL;

static int surbl_test_url (struct worker_task *task);
static void dns_callback (int result, char type, int count, int ttl, void *addresses, void *data);
static void process_dns_results (struct worker_task *task, struct suffix_item *suffix, char *url, uint32_t addr);
static int  urls_command_handler (struct worker_task *task);

#define SURBL_ERROR surbl_error_quark ()
#define WHITELIST_ERROR 0
GQuark
surbl_error_quark (void)
{
	return g_quark_from_static_string ("surbl-error-quark");
}

int
surbl_module_init (struct config_file *cfg, struct module_ctx **ctx)
{
	GError *err = NULL;

	surbl_module_ctx = g_malloc (sizeof (struct surbl_ctx));

	surbl_module_ctx->header_filter = NULL;
	surbl_module_ctx->mime_filter = NULL;
	surbl_module_ctx->message_filter = NULL;
	surbl_module_ctx->url_filter = surbl_test_url;
	surbl_module_ctx->use_redirector = 0;
	surbl_module_ctx->suffixes = NULL;
	surbl_module_ctx->bits = NULL;
	surbl_module_ctx->surbl_pool = memory_pool_new (memory_pool_get_size ());
	
	surbl_module_ctx->tld2_file = NULL;
	surbl_module_ctx->whitelist_file = NULL;
	surbl_module_ctx->tld2 = g_hash_table_new (g_str_hash, g_str_equal);
	/* Register destructors */
	memory_pool_add_destructor (surbl_module_ctx->surbl_pool, (pool_destruct_func)g_hash_table_remove_all, surbl_module_ctx->tld2);

	surbl_module_ctx->whitelist = g_hash_table_new (g_str_hash, g_str_equal);
	/* Register destructors */
	memory_pool_add_destructor (surbl_module_ctx->surbl_pool, (pool_destruct_func)g_hash_table_remove_all, surbl_module_ctx->whitelist);
	
	memory_pool_add_destructor (surbl_module_ctx->surbl_pool, (pool_destruct_func)g_list_free, surbl_module_ctx->suffixes);
	memory_pool_add_destructor (surbl_module_ctx->surbl_pool, (pool_destruct_func)g_list_free, surbl_module_ctx->bits);
		
	/* Init matching regexps */
	surbl_module_ctx->extract_hoster_regexp = g_regex_new ("([^.]+)\\.([^.]+)\\.([^.]+)$", G_REGEX_RAW | G_REGEX_OPTIMIZE, 0, &err);
	surbl_module_ctx->extract_normal_regexp = g_regex_new ("([^.]+)\\.([^.]+)$", G_REGEX_RAW | G_REGEX_OPTIMIZE, 0, &err);
	surbl_module_ctx->extract_numeric_regexp = g_regex_new ("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$", G_REGEX_RAW | G_REGEX_OPTIMIZE, 0, &err);

	*ctx = (struct module_ctx *)surbl_module_ctx;

	register_protocol_command ("urls", urls_command_handler);

	return 0;
}

int
surbl_module_config (struct config_file *cfg)
{
	struct hostent *hent;
	GList *cur_opt;
	struct module_opt *cur;
	struct suffix_item *new_suffix;
	struct surbl_bit_item *new_bit;

	char *value, *cur_tok, *str;
	uint32_t bit;


	if ((value = get_module_opt (cfg, "surbl", "redirector")) != NULL) {
		str = memory_pool_strdup (surbl_module_ctx->surbl_pool, value);
		cur_tok = strsep (&str, ":");
		if (!inet_aton (cur_tok, &surbl_module_ctx->redirector_addr)) {
			/* Try to call gethostbyname */
			hent = gethostbyname (cur_tok);
			if (hent != NULL) {
				memcpy((char *)&surbl_module_ctx->redirector_addr, hent->h_addr, sizeof(struct in_addr));
				if (str != NULL) {
					surbl_module_ctx->redirector_port = (uint16_t)strtoul (str, NULL, 10);
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
	if ((value = get_module_opt (cfg, "surbl", "max_urls")) != NULL) {
		surbl_module_ctx->max_urls = atoi (value);
	}
	else {
		surbl_module_ctx->max_urls = DEFAULT_SURBL_MAX_URLS;
	}
	if ((value = get_module_opt (cfg, "surbl", "metric")) != NULL) {
		surbl_module_ctx->metric = memory_pool_strdup (surbl_module_ctx->surbl_pool, value);
	}
	else {
		surbl_module_ctx->metric = DEFAULT_METRIC;
	}
	if ((value = get_module_opt (cfg, "surbl", "2tld")) != NULL) {
		if (g_ascii_strncasecmp (value, "file://", sizeof ("file://") - 1) == 0) {
			if (parse_host_list (surbl_module_ctx->surbl_pool, surbl_module_ctx->tld2, value + sizeof ("file://") - 1)) {
				surbl_module_ctx->tld2_file = memory_pool_strdup (surbl_module_ctx->surbl_pool, value + sizeof ("file://") - 1);
			}
		}
	}
	if ((value = get_module_opt (cfg, "surbl", "whitelist")) != NULL) {
		if (g_ascii_strncasecmp (value, "file://", sizeof ("file://") - 1) == 0) {
			if (parse_host_list (surbl_module_ctx->surbl_pool, surbl_module_ctx->whitelist, value + sizeof ("file://") - 1)) {
				surbl_module_ctx->whitelist_file = memory_pool_strdup (surbl_module_ctx->surbl_pool, value + sizeof ("file://") - 1);
			}
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
				msg_debug ("surbl_module_config: add new surbl suffix: %s with symbol: %s", 
							new_suffix->suffix, new_suffix->symbol);
				*str = '_';
				surbl_module_ctx->suffixes = g_list_prepend (surbl_module_ctx->suffixes, new_suffix);
			}
		}
		if (!g_strncasecmp (cur->param, "bit", sizeof ("bit") - 1)) {
			if ((str = strchr (cur->param, '_')) != NULL) {
				bit = strtoul (str + 1, NULL, 10);
				if (bit != 0) {
					new_bit = memory_pool_alloc (surbl_module_ctx->surbl_pool, sizeof (struct surbl_bit_item));
					new_bit->bit = bit;
					new_bit->symbol = memory_pool_strdup (surbl_module_ctx->surbl_pool, cur->value);
					msg_debug ("surbl_module_config: add new bit suffix: %d with symbol: %s", 
								(int)new_bit->bit, new_bit->symbol);
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
		msg_debug ("surbl_module_config: add default surbl suffix: %s with symbol: %s", 
								new_suffix->suffix, new_suffix->symbol);
		surbl_module_ctx->suffixes = g_list_prepend (surbl_module_ctx->suffixes, new_suffix);
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



static char *
format_surbl_request (memory_pool_t *pool, f_str_t *hostname, struct suffix_item *suffix, char **host_end, gboolean append_suffix, GError **err) 
{
	GMatchInfo *info;
	char *result = NULL;
    int len, slen, r;
   	
	if (suffix != NULL) {
		slen = strlen (suffix->suffix);
	}
	else if (!append_suffix) {
		slen = 0;
	}
	else {
		g_assert_not_reached ();
	}
    len = hostname->len + slen + 2;

	/* First try to match numeric expression */
	if (g_regex_match_full (surbl_module_ctx->extract_numeric_regexp, hostname->begin, hostname->len, 0, 0, &info, NULL) == TRUE) {
		gchar *octet1, *octet2, *octet3, *octet4;
		octet1 = g_match_info_fetch (info, 1);
		octet2 = g_match_info_fetch (info, 2);
		octet3 = g_match_info_fetch (info, 3);
		octet4 = g_match_info_fetch (info, 4);
		result = memory_pool_alloc (pool, len);
		msg_debug ("format_surbl_request: got numeric host for check: %s.%s.%s.%s", octet1, octet2, octet3, octet4);
		r = snprintf (result, len, "%s.%s.%s.%s", octet4, octet3, octet2, octet1);
		if (g_hash_table_lookup (surbl_module_ctx->whitelist, result) != NULL) {
			g_free (octet1);
			g_free (octet2);
			g_free (octet3);
			g_free (octet4);
			g_match_info_free (info);
			msg_debug ("format_surbl_request: url %s is whitelisted", result);
			g_set_error (err,
                   SURBL_ERROR,                 /* error domain */
                   WHITELIST_ERROR,            	/* error code */
                   "URL is whitelisted: %s", 	/* error message format string */
                   result);

			return NULL;
		}
		if (append_suffix) {
			r += snprintf (result + r, len - r, ".%s", suffix->suffix);
		}
		*host_end = result + r - slen - 1;
		g_free (octet1);
		g_free (octet2);
		g_free (octet3);
		g_free (octet4);
		g_match_info_free (info);
		return result;
	}
	g_match_info_free (info);
	/* Try to match normal domain */
	if (g_regex_match_full (surbl_module_ctx->extract_normal_regexp, hostname->begin, hostname->len, 0, 0, &info, NULL) == TRUE) {
		gchar *part1, *part2;
		part1 = g_match_info_fetch (info, 1);
		part2 = g_match_info_fetch (info, 2);
		g_match_info_free (info);
		result = memory_pool_alloc (pool, len); 
		snprintf (result, len, "%s.%s", part1, part2);
		if (g_hash_table_lookup (surbl_module_ctx->tld2, result) != NULL) {
			/* Match additional part for hosters */
			g_free (part1);
			g_free (part2);
			if (g_regex_match_full (surbl_module_ctx->extract_hoster_regexp, hostname->begin, hostname->len, 0, 0, &info, NULL) == TRUE) {
				gchar *hpart1, *hpart2, *hpart3;
				hpart1 = g_match_info_fetch (info, 1);
				hpart2 = g_match_info_fetch (info, 2);
				hpart3 = g_match_info_fetch (info, 3);
				msg_debug ("format_surbl_request: got hoster 3-d level domain %s.%s.%s", hpart1, hpart2, hpart3);
				r = snprintf (result, len, "%s.%s.%s", hpart1, hpart2, hpart3);
				if (g_hash_table_lookup (surbl_module_ctx->whitelist, result) != NULL) {
					g_free (hpart1);
					g_free (hpart2);
					g_free (hpart3);
					g_match_info_free (info);
					msg_debug ("format_surbl_request: url %s is whitelisted", result);
					g_set_error (err,
						   SURBL_ERROR,                 /* error domain */
						   WHITELIST_ERROR,            	/* error code */
						   "URL is whitelisted: %s", 	/* error message format string */
						   result);
					return NULL;
				}
				if (append_suffix) {
					r += snprintf (result + r, len - r, ".%s", suffix->suffix);
				}
				*host_end = result + r - slen - 1;
				g_free (hpart1);
				g_free (hpart2);
				g_free (hpart3);
				g_match_info_free (info);
				return result;
			}
			g_match_info_free (info);
			*host_end = NULL;
			return NULL;
		}
		else {
			if (g_hash_table_lookup (surbl_module_ctx->whitelist, result) != NULL) {
				g_free (part1);
				g_free (part2);
				msg_debug ("format_surbl_request: url %s is whitelisted", result);
				g_set_error (err,
					   SURBL_ERROR,                 /* error domain */
					   WHITELIST_ERROR,            	/* error code */
					   "URL is whitelisted: %s", 	/* error message format string */
					   result);
				return NULL;
			}
			if (append_suffix) {
				r += snprintf (result + r, len - r, ".%s", suffix->suffix);
			}
			*host_end = result + r - slen - 1;
			msg_debug ("format_surbl_request: got normal 2-d level domain %s.%s", part1, part2);
		}
		g_free (part1);
		g_free (part2);
		return result;
	}

	g_match_info_free (info);
	*host_end = NULL;
	return NULL;
}

static void 
make_surbl_requests (struct uri* url, struct worker_task *task, GTree *tree)
{	
	char *surbl_req;
	f_str_t f;
	GList *cur;
	GError *err = NULL;
	struct dns_param *param;
	struct suffix_item *suffix;
	char *host_end;

	cur = g_list_first (surbl_module_ctx->suffixes);
	f.begin = url->host;
	f.len = url->hostlen;

	while (cur) {
		suffix = (struct suffix_item *)cur->data;
		if (check_view (task->cfg->views, suffix->symbol, task)) {
			if ((surbl_req = format_surbl_request (task->task_pool, &f, suffix, &host_end, TRUE, &err)) != NULL) {
				if (g_tree_lookup (tree, surbl_req) == NULL) {
					g_tree_insert (tree, surbl_req, surbl_req);
					param = memory_pool_alloc (task->task_pool, sizeof (struct dns_param));
					param->url = url;
					param->task = task;
					param->suffix = suffix;
					*host_end = '\0';
					param->host_resolve = memory_pool_strdup (task->task_pool, surbl_req);
					*host_end = '.';
					msg_debug ("surbl_test_url: send surbl dns request %s", surbl_req);
					evdns_resolve_ipv4 (surbl_req, DNS_QUERY_NO_SEARCH, dns_callback, (void *)param);
					param->task->save.saved ++;
				}
				else {
					msg_debug ("make_surbl_requests: request %s is already sent", surbl_req);
				}
			}
			else if (err != NULL && err->code != WHITELIST_ERROR) {
				msg_info ("surbl_test_url: cannot format url string for surbl %s, %s", struri (url), err->message);
				return;
			}
		}
		else {
			msg_debug ("make_surbl_requests: skipping symbol that is not in view: %s", suffix->symbol);
		}
		cur = g_list_next (cur);
	}
}

static void
process_dns_results (struct worker_task *task, struct suffix_item *suffix, char *url, uint32_t addr)
{
	char *c, *symbol;
	GList *cur;
	struct surbl_bit_item *bit;
	int len, found = 0;
	
	if ((c = strchr (suffix->symbol, '%')) != NULL && *(c + 1) == 'b') {
		cur = g_list_first (surbl_module_ctx->bits);

		while (cur) {
			bit = (struct surbl_bit_item *)cur->data;
			msg_debug ("process_dns_results: got result(%d) AND bit(%d): %d", (int)addr, (int)ntohl(bit->bit), 
							(int)bit->bit & (int)ntohl (addr));
			if (((int)bit->bit & (int)ntohl (addr)) != 0) {
				len = strlen (suffix->symbol) - 2 + strlen (bit->symbol) + 1;
				*c = '\0';
				symbol = memory_pool_alloc (task->task_pool, len);
				snprintf (symbol, len, "%s%s%s", suffix->symbol, bit->symbol, c + 2);
				*c = '%';
				insert_result (task, surbl_module_ctx->metric, symbol, 1, 
							g_list_prepend (NULL, memory_pool_strdup (task->task_pool, url)));
				found = 1;
			}
			cur = g_list_next (cur);
		}

		if (!found) {
			insert_result (task, surbl_module_ctx->metric, suffix->symbol, 1, 
							g_list_prepend (NULL, memory_pool_strdup (task->task_pool, url)));
		}
	}
	else {
		insert_result (task, surbl_module_ctx->metric, suffix->symbol, 1, 
							g_list_prepend (NULL, memory_pool_strdup (task->task_pool, url)));
	}
}

static void 
dns_callback (int result, char type, int count, int ttl, void *addresses, void *data)
{
	struct dns_param *param = (struct dns_param *)data;
	
	msg_debug ("dns_callback: in surbl request callback");
	/* If we have result from DNS server, this url exists in SURBL, so increase score */
	if (result == DNS_ERR_NONE && type == DNS_IPv4_A) {
		msg_info ("surbl_check: <%s> domain [%s] is in surbl %s", 
					param->task->message_id, param->host_resolve, param->suffix->suffix);
		process_dns_results (param->task, param->suffix, param->host_resolve, (uint32_t)(((in_addr_t *)addresses)[0]));
	}
	else {
		msg_debug ("surbl_check: <%s> domain [%s] is not in surbl %s", 
					param->task->message_id, param->host_resolve, param->suffix->suffix);
	}
	
	param->task->save.saved --;
	if (param->task->save.saved == 0) {
		/* Call other filters */
		param->task->save.saved = 1;
		process_filters (param->task);
	}

}

static void 
memcached_callback (memcached_ctx_t *ctx, memc_error_t error, void *data)
{
	struct memcached_param *param = (struct memcached_param *)data;
	int *url_count;

	switch (ctx->op) {
		case CMD_CONNECT:
			if (error != OK) {
				msg_info ("memcached_callback: memcached returned error %s on CONNECT stage", memc_strerror (error));
				memc_close_ctx (param->ctx);
				param->task->save.saved --;
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
				msg_info ("memcached_callback: memcached returned error %s on READ stage", memc_strerror (error));
				memc_close_ctx (param->ctx);
				param->task->save.saved --;
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
					msg_info ("memcached_callback: url '%s' has count %d, max: %d", struri (param->url), *url_count, surbl_module_ctx->max_urls);
					/* 
					 * XXX: try to understand why we should use memcached here
					 * insert_result (param->task, surbl_module_ctx->metric, surbl_module_ctx->symbol, 1);
					 */
				}
				(*url_count) ++;
				memc_set (param->ctx, param->ctx->param, surbl_module_ctx->url_expire);
			}
			break;
		case CMD_WRITE:
			if (error != OK) {
				msg_info ("memcached_callback: memcached returned error %s on WRITE stage", memc_strerror (error));
			}
			memc_close_ctx (param->ctx);
			param->task->save.saved --;
			if (param->task->save.saved == 0) {
				/* Call other filters */
				param->task->save.saved = 1;
				process_filters (param->task);
			}
			make_surbl_requests (param->url, param->task, param->tree);
			break;
		default:
			return;
	}
}

static void
register_memcached_call (struct uri *url, struct worker_task *task, GTree *url_tree) 
{
	struct memcached_param *param;
	struct memcached_server *selected;
	memcached_param_t *cur_param;
	gchar *sum_str;
	int *url_count;

	param = memory_pool_alloc (task->task_pool, sizeof (struct memcached_param));
	cur_param = memory_pool_alloc0 (task->task_pool, sizeof (memcached_param_t));
	url_count = memory_pool_alloc (task->task_pool, sizeof (int));

	param->url = url;
	param->task = task;
	param->tree = url_tree;

	param->ctx = memory_pool_alloc0 (task->task_pool, sizeof (memcached_ctx_t));

	cur_param->buf = (u_char *)url_count;
	cur_param->bufsize = sizeof (int);

	sum_str = g_compute_checksum_for_string (G_CHECKSUM_MD5, struri (url), -1);
	g_strlcpy (cur_param->key, sum_str, sizeof (cur_param->key));
	g_free (sum_str);

	selected = (struct memcached_server *) get_upstream_by_hash ((void *)task->cfg->memcached_servers,
											task->cfg->memcached_servers_num, sizeof (struct memcached_server),
											time (NULL), task->cfg->memcached_error_time, task->cfg->memcached_dead_time, task->cfg->memcached_maxerrors,
											cur_param->key, strlen(cur_param->key));
	if (selected == NULL) {
		msg_err ("surbl_register_memcached_call: no memcached servers can be selected");
		return;
	}
	param->ctx->callback = memcached_callback;
	param->ctx->callback_data = (void *)param;
	param->ctx->protocol = task->cfg->memcached_protocol;
	memcpy(&param->ctx->addr, &selected->addr, sizeof (struct in_addr));
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
redirector_callback (int fd, short what, void *arg)
{
	struct redirector_param *param = (struct redirector_param *)arg;
	char url_buf[1024];
	int r;
	struct timeval *timeout;
	char *p, *c;

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
					msg_err ("redirector_callback: write failed %s", strerror (errno));
					event_del (&param->ev);
					close (fd);
					param->task->save.saved --;
					make_surbl_requests (param->url, param->task, param->tree);
					if (param->task->save.saved == 0) {
						/* Call other filters */
						param->task->save.saved = 1;
						process_filters (param->task);
					}
					return;
				}
				param->state = STATE_READ;
			}
			else {
				event_del (&param->ev);
				close (fd);
				msg_info ("redirector_callback: <%s> connection to redirector timed out while waiting for write",
							param->task->message_id);
				param->task->save.saved --;
				make_surbl_requests (param->url, param->task, param->tree);

				if (param->task->save.saved == 0) {
					/* Call other filters */
					param->task->save.saved = 1;
					process_filters (param->task);
				}
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
						msg_debug ("redirector_callback: <%s> got reply from redirector: '%s' -> '%s'", 
									param->task->message_id, struri (param->url), c);
						parse_uri (param->url, memory_pool_strdup (param->task->task_pool, c), param->task->task_pool);
					}
				}
				event_del (&param->ev);
				close (fd);
				param->task->save.saved --;
				make_surbl_requests (param->url, param->task, param->tree);
				if (param->task->save.saved == 0) {
					/* Call other filters */
					param->task->save.saved = 1;
					process_filters (param->task);
				}
			}
			else {
				event_del (&param->ev);
				close (fd);
				msg_info ("redirector_callback: <%s> reading redirector timed out, while waiting for read",
							param->task->message_id);
				param->task->save.saved --;
				make_surbl_requests (param->url, param->task, param->tree);
				if (param->task->save.saved == 0) {
					/* Call other filters */
					param->task->save.saved = 1;
					process_filters (param->task);
				}
			}
			break;
	}
}


static void
register_redirector_call (struct uri *url, struct worker_task *task, GTree *url_tree) 
{
	int s;
	struct redirector_param *param;
	struct timeval *timeout;

	s = make_tcp_socket (&surbl_module_ctx->redirector_addr, surbl_module_ctx->redirector_port, FALSE);

	if (s == -1) {
		msg_info ("register_redirector_call: <%s> cannot create tcp socket failed: %s", 
					task->message_id, strerror (errno));
		task->save.saved --;
		make_surbl_requests (url, task, url_tree);
		return; 
	}

	param = memory_pool_alloc (task->task_pool, sizeof (struct redirector_param));
	param->url = url;
	param->task = task;
	param->state = STATE_CONNECT;
	param->sock = s;
	param->tree = url_tree;
	timeout = memory_pool_alloc (task->task_pool, sizeof (struct timeval));
	timeout->tv_sec = surbl_module_ctx->connect_timeout / 1000;
	timeout->tv_usec = surbl_module_ctx->connect_timeout - timeout->tv_sec * 1000;
	event_set (&param->ev, s, EV_WRITE, redirector_callback, (void *)param);
	event_add (&param->ev, timeout);
}

static gboolean
tree_url_callback (gpointer key, gpointer value, void *data)
{
	struct redirector_param *param = data;
	struct uri *url = value;

	msg_debug ("surbl_test_url: check url %s", struri (url));

	if (surbl_module_ctx->use_redirector) {
		register_redirector_call (url, param->task, param->tree);
		param->task->save.saved++;
	}
	else {
		if (param->task->worker->srv->cfg->memcached_servers_num > 0) {
			register_memcached_call (url, param->task, param->tree);
			param->task->save.saved++;
		}
		else {
			make_surbl_requests (url, param->task, param->tree);
		}
	}

	return FALSE;
}

static int 
surbl_test_url (struct worker_task *task)
{
	GTree *url_tree;
	GList *cur;
	struct mime_text_part *part;
	struct redirector_param param;

	/* Try to check lists */
	if (surbl_module_ctx->tld2_file) {
		maybe_parse_host_list (surbl_module_ctx->surbl_pool, surbl_module_ctx->tld2, surbl_module_ctx->tld2_file);
	}
	if (surbl_module_ctx->whitelist_file) {
		maybe_parse_host_list (surbl_module_ctx->surbl_pool, surbl_module_ctx->whitelist, surbl_module_ctx->whitelist_file);
	}

	url_tree = g_tree_new ((GCompareFunc)g_ascii_strcasecmp);
	
	param.tree = url_tree;
	param.task = task;
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

	memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_tree_destroy, url_tree);
	return 0;
}

static int 
urls_command_handler (struct worker_task *task)
{
	GList *cur;
	char outbuf[16384], *urlstr;
	int r, num = 0;
	struct uri *url;
	GError *err = NULL;
	GTree *url_tree;
	f_str_t f;
	char *host_end;

	url_tree = g_tree_new ((GCompareFunc)g_ascii_strcasecmp);

	r = snprintf (outbuf, sizeof (outbuf), "%s 0 %s" CRLF, (task->proto == SPAMC_PROTO) ? SPAMD_REPLY_BANNER : RSPAMD_REPLY_BANNER, "OK");
	
	r += snprintf (outbuf + r, sizeof (outbuf) - r - 2, "URLs: ");
	
	cur = g_list_first (task->urls);

	while (cur) {
		num ++;
		url = cur->data;
		if (g_tree_lookup (url_tree, struri (url)) == NULL) {
			g_tree_insert (url_tree, struri (url), url);
			f.begin = url->host;
			f.len = url->hostlen;
			if ((urlstr = format_surbl_request (task->task_pool, &f, NULL, &host_end, FALSE, &err)) != NULL) {
				if (g_list_next (cur) != NULL) {
					r += snprintf (outbuf + r, sizeof (outbuf) - r - 2, "%s, ", (char *)urlstr);
				}
				else {
					r += snprintf (outbuf + r, sizeof (outbuf) - r - 2, "%s", (char *)urlstr);
				}
			}
		}
		cur = g_list_next (cur);
	}
	
	outbuf[r++] = '\r'; outbuf[r++] = '\n';

	rspamd_dispatcher_write (task->dispatcher, outbuf, r, FALSE);
	msg_info ("process_message: msg ok, id: <%s>, %d urls extracted", task->message_id, num);
	g_tree_destroy (url_tree);

	return 0;
}


/*
 * vi:ts=4 
 */
