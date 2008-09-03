/***MODULE:surbl
 * rspamd module that implements SURBL url checking
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/param.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>
#include <fcntl.h>
#include <stdlib.h>

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
	unsigned use_redirector:1;
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

struct surbl_ctx *surbl_module_ctx;

static int surbl_test_url (struct worker_task *task);

int
surbl_module_init (struct config_file *cfg, struct module_ctx **ctx)
{
	struct hostent *hent;

	char *value, *cur_tok, *str;

	surbl_module_ctx = g_malloc (sizeof (struct surbl_ctx));

	surbl_module_ctx->header_filter = NULL;
	surbl_module_ctx->mime_filter = NULL;
	surbl_module_ctx->message_filter = NULL;
	surbl_module_ctx->url_filter = surbl_test_url;
	surbl_module_ctx->use_redirector = 0;

	if ((value = get_module_opt (cfg, "surbl", "redirector")) != NULL) {
		str = strdup (value);
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

	*ctx = (struct module_ctx *)surbl_module_ctx;

	evdns_init ();

	return 0;
}

static void 
memcached_callback (memcached_ctx_t *ctx, memc_error_t error, void *data)
{
	struct memcached_param *param = (struct memcached_param *)data;
	int *url_count;
	struct filter_result *res;

	switch (ctx->op) {
		case CMD_CONNECT:
			if (error != OK) {
				msg_info ("memcached_callback: memcached returned error %s on CONNECT stage");
				memc_close_ctx (param->ctx);
				param->task->save.saved --;
				if (param->task->save.saved == 0) {
					/* Call other filters */
					param->task->save.saved = 1;
					process_filters (param->task);
				}
				g_free (param->ctx->param->buf);
				g_free (param->ctx->param);
				g_free (param->ctx);
				g_free (param);
			}
			else {
				memc_get (param->ctx, param->ctx->param);
			}
			break;
		case CMD_READ:
			if (error != OK) {
				msg_info ("memcached_callback: memcached returned error %s on READ stage");
				memc_close_ctx (param->ctx);
				param->task->save.saved --;
				if (param->task->save.saved == 0) {
					/* Call other filters */
					param->task->save.saved = 1;
					process_filters (param->task);
				}
				g_free (param->ctx->param->buf);
				g_free (param->ctx->param);
				g_free (param->ctx);
				g_free (param);
			}
			else {
				url_count = (int *)param->ctx->param->buf;
				/* Do not check DNS for urls that have count more than max_urls */
				if (*url_count > surbl_module_ctx->max_urls) {
					msg_info ("memcached_callback: url '%s' has count %d, max: %d", struri (param->url), *url_count, surbl_module_ctx->max_urls);
					res = TAILQ_LAST (&param->task->results, resultsq);
					res->mark += surbl_module_ctx->weight;
				}
				(*url_count) ++;
				memc_set (param->ctx, param->ctx->param, surbl_module_ctx->url_expire);
			}
			break;
		case CMD_WRITE:
			if (error != OK) {
				msg_info ("memcached_callback: memcached returned error %s on WRITE stage");
			}
			memc_close_ctx (param->ctx);
			param->task->save.saved --;
			if (param->task->save.saved == 0) {
				/* Call other filters */
				param->task->save.saved = 1;
				process_filters (param->task);
			}
			//XXX: read http://surbl.org and add surbl request here
			g_free (param->ctx->param->buf);
			g_free (param->ctx->param);
			g_free (param->ctx);
			g_free (param);
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

	param = g_malloc (sizeof (struct memcached_param));
	cur_param = g_malloc (sizeof (memcached_param_t));
	url_count = g_malloc (sizeof (int));

	param->url = url;
	param->task = task;

	param->ctx = g_malloc (sizeof (memcached_ctx_t));
	bzero (param->ctx, sizeof (memcached_ctx_t));
	bzero (cur_param, sizeof (memcached_param_t));

	cur_param->buf = (u_char *)url_count;
	cur_param->bufsize = sizeof (int);

	sum_str = g_compute_checksum_for_string (G_CHECKSUM_MD5, struri (url), -1);
	strlcpy (cur_param->key, sum_str, sizeof (cur_param->key));
	g_free (sum_str);

	selected = (struct memcached_server *) get_upstream_by_hash ((void *)task->cfg->memcached_servers,
											task->cfg->memcached_servers_num, sizeof (struct memcached_server),
											time (NULL), task->cfg->memcached_error_time, task->cfg->memcached_dead_time, task->cfg->memcached_maxerrors,
											cur_param->key, strlen(cur_param->key));
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
				write (param->sock, url_buf, r);
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
				g_free (param);
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
						parse_uri (param->url, c);
						normalize_uri (param->url, c);
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
				g_free (param);
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
				g_free (param);
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
	param = g_malloc (sizeof (struct redirector_param));
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

	TAILQ_FOREACH (url, &task->urls, next) {
		if (surbl_module_ctx->use_redirector) {
			register_redirector_call (url, task);
		}
		else {
			register_memcached_call (url, task);
		}
		task->save.saved++;
	}
	return 0;
}

/*
 * vi:ts=4 
 */
