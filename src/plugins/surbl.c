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

#include <evdns.h>

#include "../config.h"
#include "../main.h"
#include "../modules.h"
#include "../cfg_file.h"
#include "../memcached.h"

#define DEFAULT_REDIRECTOR_PORT 8080
#define DEFAULT_SURBL_WEIGHT 10
#define DEFAULT_REDIRECTOR_CONNECT_TIMEOUT 1000
#define DEFAULT_REDIRECTOR_READ_TIMEOUT 5000
#define DEFAULT_SURBL_MAX_URLS 1000
#define DEFAULT_SURBL_URL_EXPIRE 86400
#define DEFAULT_SURBL_SYMBOL "SURBL_DNS"
#define DEFAULT_SURBL_SUFFIX "multi.surbl.org"

struct surbl_ctx {
	int (*header_filter)(struct worker_task *task);
	int (*mime_filter)(struct worker_task *task);
	int (*message_filter)(struct worker_task *task);
	int (*url_filter)(struct worker_task *task);
	struct in_addr redirector_addr;
	uint16_t redirector_port;
	uint16_t weight;
	unsigned int connect_timeout;
	unsigned int read_timeout;
	unsigned int max_urls;
	unsigned int url_expire;
	char *suffix;
	char *symbol;
	char *metric;
	GHashTable *hosters;
	GHashTable *whitelist;
	unsigned use_redirector;
	memory_pool_t *surbl_pool;
};

struct redirector_param {
	struct uri *url;
	struct worker_task *task;
	enum {
		STATE_CONNECT,
		STATE_READ,
	} state;
	struct event ev;
	int sock;
};

struct memcached_param {
	struct uri *url;
	struct worker_task *task;
	memcached_ctx_t *ctx;
};

static char *hash_fill = "1";
struct surbl_ctx *surbl_module_ctx;
GRegex *extract_hoster_regexp, *extract_normal_regexp, *extract_numeric_regexp;

static int surbl_test_url (struct worker_task *task);

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
	surbl_module_ctx->surbl_pool = memory_pool_new (1024);
	
	surbl_module_ctx->hosters = g_hash_table_new (g_str_hash, g_str_equal);
	/* Register destructors */
	memory_pool_add_destructor (surbl_module_ctx->surbl_pool, (pool_destruct_func)g_hash_table_remove_all, surbl_module_ctx->hosters);

	surbl_module_ctx->whitelist = g_hash_table_new (g_str_hash, g_str_equal);
	/* Register destructors */
	memory_pool_add_destructor (surbl_module_ctx->surbl_pool, (pool_destruct_func)g_hash_table_remove_all, surbl_module_ctx->whitelist);
		
	/* Init matching regexps */
	extract_hoster_regexp = g_regex_new ("([^.]+)\\.([^.]+)\\.([^.]+)$", G_REGEX_RAW, 0, &err);
	extract_normal_regexp = g_regex_new ("([^.]+)\\.([^.]+)$", G_REGEX_RAW, 0, &err);
	extract_numeric_regexp = g_regex_new ("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$", G_REGEX_RAW, 0, &err);

	*ctx = (struct module_ctx *)surbl_module_ctx;

	return 0;
}

int
surbl_module_config (struct config_file *cfg)
{
	struct hostent *hent;

	char *value, *cur_tok, *str;

	evdns_init ();

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
		/* Free cur_tok as it is actually initial str after strsep */
		free (cur_tok);
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
	if ((value = get_module_opt (cfg, "surbl", "suffix")) != NULL) {
		surbl_module_ctx->suffix = memory_pool_strdup (surbl_module_ctx->surbl_pool, value);
		g_free (value);
	}
	else {
		surbl_module_ctx->suffix = DEFAULT_SURBL_SUFFIX;
	}
	if ((value = get_module_opt (cfg, "surbl", "symbol")) != NULL) {
		surbl_module_ctx->symbol = memory_pool_strdup (surbl_module_ctx->surbl_pool, value);
		g_free (value);
	}
	else {
		surbl_module_ctx->symbol = DEFAULT_SURBL_SYMBOL;
	}
	if ((value = get_module_opt (cfg, "surbl", "metric")) != NULL) {
		surbl_module_ctx->metric = memory_pool_strdup (surbl_module_ctx->surbl_pool, value);
		g_free (value);
	}
	else {
		surbl_module_ctx->metric = DEFAULT_METRIC;
	}
	if ((value = get_module_opt (cfg, "surbl", "hostings")) != NULL) {
		char comment_flag = 0;
		str = value;
		while (*value ++) {
			if (*value == '#') {
				comment_flag = 1;
			}
			if (*value == '\r' || *value == '\n' || *value == ',') {
				if (!comment_flag && str != value) {
					g_hash_table_insert (surbl_module_ctx->hosters, g_strstrip(str), hash_fill);
					str = value + 1;
				}
				else if (*value != ',') {
					comment_flag = 0;
					str = value + 1;
				}
			}
		}
	}
	if ((value = get_module_opt (cfg, "surbl", "whitelist")) != NULL) {
		char comment_flag = 0;
		str = value;
		while (*value ++) {
			if (*value == '#') {
				comment_flag = 1;
			}
			if (*value == '\r' || *value == '\n' || *value == ',') {
				if (!comment_flag && str != value) {
					g_hash_table_insert (surbl_module_ctx->whitelist, g_strstrip(str), hash_fill);
					str = value + 1;
				}
				else if (*value != ',') {
					comment_flag = 0;
					str = value + 1;
				}
			}
		}
	}
}

int
surbl_module_reconfig (struct config_file *cfg)
{
	memory_pool_delete (surbl_module_ctx->surbl_pool);
	surbl_module_ctx->surbl_pool = memory_pool_new (1024);

	return surbl_module_config (cfg);
}

static char *
format_surbl_request (memory_pool_t *pool, f_str_t *hostname) 
{
	GMatchInfo *info;
	char *result = NULL;
    int len;
    
    len = hostname->len + strlen (surbl_module_ctx->suffix) + 2;

	/* First try to match numeric expression */
	if (g_regex_match_full (extract_numeric_regexp, hostname->begin, hostname->len, 0, 0, &info, NULL) == TRUE) {
		gchar *octet1, *octet2, *octet3, *octet4;
		octet1 = g_match_info_fetch (info, 1);
		octet2 = g_match_info_fetch (info, 2);
		octet3 = g_match_info_fetch (info, 3);
		octet4 = g_match_info_fetch (info, 4);
		g_match_info_free (info);
		result = memory_pool_alloc (pool, len); 
		msg_debug ("format_surbl_request: got numeric host for check: %s.%s.%s.%s", octet1, octet2, octet3, octet4);
		snprintf (result, len, "%s.%s.%s.%s.%s", octet4, octet3, octet2, octet1, surbl_module_ctx->suffix);
		g_free (octet1);
		g_free (octet2);
		g_free (octet3);
		g_free (octet4);
		return result;
	}
	g_match_info_free (info);
	/* Try to match normal domain */
	if (g_regex_match_full (extract_normal_regexp, hostname->begin, hostname->len, 0, 0, &info, NULL) == TRUE) {
		gchar *part1, *part2;
		part1 = g_match_info_fetch (info, 1);
		part2 = g_match_info_fetch (info, 2);
		g_match_info_free (info);
		result = memory_pool_alloc (pool, len); 
		msg_debug ("format_surbl_request: got normal 2-d level domain %s.%s", part1, part2);
		if (g_hash_table_lookup (surbl_module_ctx->hosters, result) != NULL) {
			/* Match additional part for hosters */
			g_free (part1);
			g_free (part2);
			if (g_regex_match_full (extract_hoster_regexp, hostname->begin, hostname->len, 0, 0, &info, NULL) == TRUE) {
				gchar *hpart1, *hpart2, *hpart3;
				hpart1 = g_match_info_fetch (info, 1);
				hpart2 = g_match_info_fetch (info, 2);
				hpart3 = g_match_info_fetch (info, 3);
				g_match_info_free (info);
				msg_debug ("format_surbl_request: got hoster 3-d level domain %s.%s.%s", hpart1, hpart2, hpart3);
				snprintf (result, len, "%s.%s.%s.%s", hpart1, hpart2, hpart3, surbl_module_ctx->suffix);
				g_free (hpart1);
				g_free (hpart2);
				g_free (hpart3);
				return result;
			}
			return NULL;
		}
		snprintf (result, len, "%s.%s.%s", part1, part2, surbl_module_ctx->suffix);
		g_free (part1);
		g_free (part2);
		return result;
	}

	return NULL;
}

static void 
dns_callback (int result, char type, int count, int ttl, void *addresses, void *data)
{
	struct memcached_param *param = (struct memcached_param *)data;
	
	msg_debug ("dns_callback: in surbl request callback");
	/* If we have result from DNS server, this url exists in SURBL, so increase score */
	if (result == DNS_ERR_NONE && type == DNS_IPv4_A) {
		msg_info ("surbl_check: url %s is in surbl %s", param->url->host, surbl_module_ctx->suffix);
		insert_result (param->task, surbl_module_ctx->metric, surbl_module_ctx->symbol, 1);
	}
	else {
		msg_debug ("surbl_check: url %s is not in surbl %s", param->url->host, surbl_module_ctx->suffix);
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
	char *surbl_req;
	f_str_t c;

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
					insert_result (param->task, surbl_module_ctx->metric, surbl_module_ctx->symbol, 1);
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
			c.begin = param->url->host;
			c.len = param->url->hostlen;
			if ((surbl_req = format_surbl_request (param->task->task_pool, &c)) != NULL) {
				msg_debug ("surbl_memcached: send surbl dns request %s", surbl_req);
				param->task->save.saved ++;
				evdns_resolve_ipv4 (surbl_req, DNS_QUERY_NO_SEARCH, dns_callback, (void *)param);
				return;
			}
			break;
	}
}

static void
register_memcached_call (struct uri *url, struct worker_task *task) 
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
	struct timeval timeout;
	char *p, *c;

	switch (param->state) {
		case STATE_CONNECT:
			/* We have write readiness after connect call, so reinit event */
			if (what == EV_WRITE) {
				timeout.tv_sec = surbl_module_ctx->connect_timeout / 1000;
				timeout.tv_usec = surbl_module_ctx->connect_timeout - timeout.tv_sec * 1000;
				event_del (&param->ev);
				event_set (&param->ev, param->sock, EV_READ | EV_PERSIST | EV_TIMEOUT, redirector_callback, (void *)param);
				event_add (&param->ev, &timeout);
				r = snprintf (url_buf, sizeof (url_buf), "GET %s HTTP/1.0\r\n\r\n", struri (param->url));
				if (write (param->sock, url_buf, r) == -1) {
					msg_err ("redirector_callback: write failed %m");
					event_del (&param->ev);
					param->task->save.saved --;
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
				msg_info ("redirector_callback: connection to redirector timed out");
				param->task->save.saved --;
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
						msg_info ("redirector_callback: got reply from redirector: '%s' -> '%s'", struri (param->url), c);
						parse_uri (param->url, c, param->task->task_pool);
						register_memcached_call (param->url, param->task);
						param->task->save.saved ++;
					}
				}
				event_del (&param->ev);
				param->task->save.saved --;
				if (param->task->save.saved == 0) {
					/* Call other filters */
					param->task->save.saved = 1;
					process_filters (param->task);
				}
			}
			else {
				event_del (&param->ev);
				msg_info ("redirector_callback: reading redirector timed out");
				param->task->save.saved --;
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
register_redirector_call (struct uri *url, struct worker_task *task) 
{
	struct sockaddr_in sc;
	int ofl, r, s;
	struct redirector_param *param;
	struct timeval timeout;

	bzero (&sc, sizeof (struct sockaddr_in *));
	sc.sin_family = AF_INET;
	sc.sin_port = surbl_module_ctx->redirector_port;
	memcpy (&sc.sin_addr, &surbl_module_ctx->redirector_addr, sizeof (struct in_addr));

	s = socket (PF_INET, SOCK_STREAM, 0);

	if (s == -1) {
		msg_info ("register_redirector_call: socket() failed: %m");
		return; 
	}

	/* set nonblocking */
    ofl = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, ofl | O_NONBLOCK);
	
	if ((r = connect (s, (struct sockaddr*)&sc, sizeof (struct sockaddr_in))) == -1) {
		if (errno != EINPROGRESS) {
			close (s);
			msg_info ("register_redirector_call: connect() failed: %m");
		}
	}
	param = memory_pool_alloc (task->task_pool, sizeof (struct redirector_param));
	param->url = url;
	param->task = task;
	param->state = STATE_READ;
	param->sock = s;
	timeout.tv_sec = surbl_module_ctx->connect_timeout / 1000;
	timeout.tv_usec = surbl_module_ctx->connect_timeout - timeout.tv_sec * 1000;
	event_set (&param->ev, s, EV_WRITE | EV_TIMEOUT, redirector_callback, (void *)param);
	event_add (&param->ev, &timeout);
}

static int 
surbl_test_url (struct worker_task *task)
{
	struct uri *url;
	char *surbl_req;
	struct memcached_param *param;
	f_str_t c;

	TAILQ_FOREACH (url, &task->urls, next) {
		msg_debug ("surbl_test_url: check url %s", struri (url));
		if (surbl_module_ctx->use_redirector) {
			register_redirector_call (url, task);
		}
		else {
			if (task->worker->srv->cfg->memcached_servers_num > 0) {
				register_memcached_call (url, task);
			}
			else {
				c.begin = url->host;
				c.len = url->hostlen;
				if ((surbl_req = format_surbl_request (task->task_pool, &c)) != NULL) {
					param = memory_pool_alloc (task->task_pool, sizeof (struct memcached_param));
					param->task = task;
					param->url = url;
					msg_debug ("surbl_test_url: send surbl dns request %s", surbl_req);
					evdns_resolve_ipv4 (surbl_req, DNS_QUERY_NO_SEARCH, dns_callback, (void *)param);
				}
				else {
					msg_info ("surbl_test_url: cannot format url string for surbl %s", struri (url));
					return;
				}
			}
		}
		task->save.saved++;
	}
	return 0;
}

/*
 * vi:ts=4 
 */
