/* Copyright (c) 2010-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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
#include "util.h"
#include "main.h"
#include "message.h"
#include "protocol.h"
#include "upstream.h"
#include "cfg_file.h"
#include "cfg_xml.h"
#include "map.h"
#include "dns.h"
#include "tokenizers/tokenizers.h"
#include "classifiers/classifiers.h"
#include "dynamic_cfg.h"
#include "rrd.h"
#include "json/jansson.h"

#include <evhttp.h>
#if (_EVENT_NUMERIC_VERSION > 0x02010000) && defined(HAVE_OPENSSL)
#define HAVE_WEBUI_SSL
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <event2/event-config.h>
#include <event2/bufferevent.h>
#include <event2/util.h>
#include <event2/bufferevent_ssl.h>
#endif

/* Another workaround for old libevent */
#ifndef HTTP_INTERNAL
#define HTTP_INTERNAL 500
#endif

#ifdef WITH_GPERF_TOOLS
#   include <glib/gprintf.h>
#endif

/* 60 seconds for worker's IO */
#define DEFAULT_WORKER_IO_TIMEOUT 60000

/* HTTP paths */
#define PATH_AUTH "/login"
#define PATH_SYMBOLS "/symbols"
#define PATH_ACTIONS "/actions"
#define PATH_MAPS "/maps"
#define PATH_GET_MAP "/getmap"
#define PATH_GRAPH "/graph"
#define PATH_PIE_CHART "/pie"
#define PATH_HISTORY "/history"
#define PATH_LEARN_SPAM "/learnspam"
#define PATH_LEARN_HAM "/learnham"
#define PATH_SAVE_ACTIONS "/saveactions"
#define PATH_SAVE_SYMBOLS "/savesymbols"
#define PATH_SAVE_MAP "/savemap"
#define PATH_SCAN "/scan"

/* Graph colors */
#define COLOR_CLEAN "#58A458"
#define COLOR_PROBABLE_SPAM "#D67E7E"
#define COLOR_GREYLIST "#A0A0A0"
#define COLOR_REJECT "#CB4B4B"
#define COLOR_TOTAL "#9440ED"

gpointer init_webui_worker (void);
void start_webui_worker (struct rspamd_worker *worker);

worker_t webui_worker = {
	"webui",					/* Name */
	init_webui_worker,		/* Init function */
	start_webui_worker,		/* Start function */
	TRUE,					/* Has socket */
	TRUE,					/* Non unique */
	FALSE,					/* Non threaded */
	TRUE					/* Killable */
};

/*
 * Worker's context
 */
struct rspamd_webui_worker_ctx {
	/* DNS resolver */
	struct rspamd_dns_resolver     *resolver;
	/* Events base */
	struct event_base              *ev_base;
	/* Whether we use ssl for this server */
	gboolean use_ssl;
	/* Webui password */
	gchar *password;
	/* HTTP server */
	struct evhttp *http;
	/* Server's start time */
	time_t start_time;
	/* Main server */
	struct rspamd_main *srv;
	/* Configuration */
	struct config_file *cfg;
	/* SSL cert */
	gchar *ssl_cert;
	/* SSL private key */
	gchar *ssl_key;
	/* Worker */
	struct rspamd_worker *worker;
};

static sig_atomic_t             wanna_die = 0;

/* Signal handlers */

#ifndef HAVE_SA_SIGINFO
static void
sig_handler (gint signo)
#else
static void
sig_handler (gint signo, siginfo_t * info, void *unused)
#endif
{
	struct timeval                  tv;

	switch (signo) {
	case SIGINT:
	case SIGTERM:
		if (!wanna_die) {
			wanna_die = 1;
			tv.tv_sec = 0;
			tv.tv_usec = 0;
			event_loopexit (&tv);

#ifdef WITH_GPERF_TOOLS
			ProfilerStop ();
#endif
		}
		break;
	}
}

/*
 * Config reload is designed by sending sigusr2 to active workers and pending shutdown of them
 */
static void
sigusr2_handler (gint fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *) arg;
	/* Do not accept new connections, preparing to end worker's process */
	struct timeval                  tv;

	if (!wanna_die) {
		tv.tv_sec = SOFT_SHUTDOWN_TIME;
		tv.tv_usec = 0;
		event_del (&worker->sig_ev_usr1);
		event_del (&worker->sig_ev_usr2);
		event_del (&worker->bind_ev);
		msg_info ("worker's shutdown is pending in %d sec", SOFT_SHUTDOWN_TIME);
		event_loopexit (&tv);
	}
	return;
}

/*
 * Reopen log is designed by sending sigusr1 to active workers and pending shutdown of them
 */
static void
sigusr1_handler (gint fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *) arg;

	reopen_log (worker->srv->logger);

	return;
}

#ifdef HAVE_WEBUI_SSL

static struct bufferevent*
webui_ssl_bufferevent_gen (struct event_base *base, void *arg)
{
	SSL_CTX									*server_ctx = arg;
	SSL										*client_ctx;
	struct bufferevent						*base_bev, *ssl_bev;

	client_ctx = SSL_new (server_ctx);

	base_bev = bufferevent_socket_new (base, -1, 0);
	if (base_bev == NULL) {
		msg_err ("cannot create base bufferevent for ssl connection");
		return NULL;
	}

	ssl_bev = bufferevent_openssl_filter_new (base, base_bev, client_ctx, BUFFEREVENT_SSL_ACCEPTING, 0);

	if (ssl_bev == NULL) {
		msg_err ("cannot create ssl bufferevent for ssl connection");
	}

	return ssl_bev;
}

static void
webui_ssl_init (struct rspamd_webui_worker_ctx *ctx)
{
	SSL_CTX									*server_ctx;

	/* Initialize the OpenSSL library */
	SSL_load_error_strings ();
	SSL_library_init ();
	/* We MUST have entropy, or else there's no point to crypto. */
	if (!RAND_poll ()) {
		return NULL;
	}

	server_ctx = SSL_CTX_new (SSLv23_server_method ());

	if (! SSL_CTX_use_certificate_chain_file (server_ctx, ctx->ssl_cert) ||
			! SSL_CTX_use_PrivateKey_file(server_ctx, ctx->ssl_key, SSL_FILETYPE_PEM)) {
		msg_err ("cannot load ssl key %s or ssl cert: %s", ctx->ssl_key, ctx->ssl_cert);
		return;
	}
	SSL_CTX_set_options (server_ctx, SSL_OP_NO_SSLv2);

	if (server_ctx) {
		/* Set generator for ssl events */
		evhttp_set_bevcb (ctx->http, webui_ssl_bufferevent_gen, server_ctx);
	}
}
#endif

/* Calculate and set content-length header */
static void
http_calculate_content_length (struct evbuffer *evb, struct evhttp_request *req)
{
	gchar									 numbuf[64];

#if _EVENT_NUMERIC_VERSION > 0x02000000
	rspamd_snprintf (numbuf, sizeof (numbuf), "%z", evbuffer_get_length (evb));
#else
	rspamd_snprintf (numbuf, sizeof (numbuf), "%z", evb->totallen);
#endif
	evhttp_add_header(req->output_headers, "Content-Length", numbuf);
}

/* Check for password if it is required by configuration */
static gboolean
http_check_password (struct rspamd_webui_worker_ctx *ctx, struct evhttp_request *req)
{
	const gchar								*password;
	struct evbuffer							*evb;

	if (ctx->password) {
		password = evhttp_find_header (req->input_headers, "Password");
		if (password == NULL || strcmp (password, ctx->password) != 0) {
			msg_info ("incorrect or absent password was specified");
			evb = evbuffer_new ();
			if (!evb) {
				msg_err ("cannot allocate evbuffer for reply");
				evhttp_send_reply (req, HTTP_INTERNAL, "500 insufficient memory", NULL);
				return FALSE;
			}
			evbuffer_add (evb, "{\"error\":\"unauthorized\"}" CRLF, sizeof ("{\"error\":\"unauthorized\"}" CRLF));
			evhttp_send_reply (req, 403, "403 access denied", evb);
			evbuffer_free (evb);
			return FALSE;
		}
	}

	return TRUE;
}

struct scan_callback_data {
	struct worker_task *task;
	struct evhttp_request *req;
	struct rspamd_webui_worker_ctx *ctx;
	gboolean processed;
	struct evbuffer *out;
	gboolean first_symbol;
};


/*
 * Write metric result in json format
 */
static void
http_scan_metric_symbols_callback (gpointer key, gpointer value, gpointer ud)
{
	struct scan_callback_data				*cbdata = ud;
	struct symbol							*s = value;
	GList									*cur;

	/* Show data for a single symbol */
	if (cbdata->first_symbol) {
		cbdata->first_symbol = FALSE;
		evbuffer_add_printf (cbdata->out, "{\"name\":\"%s\",\"weight\":%.2f", s->name, s->score);
	}
	else {
		evbuffer_add_printf (cbdata->out, ",{\"name\":\"%s\",\"weight\":%.2f", s->name, s->score);
	}
	if (s->options) {
		evbuffer_add_printf (cbdata->out, ",\"options\":[");
		cur = s->options;
		while (cur) {
			evbuffer_add_printf (cbdata->out, "\"%s\"%c", (gchar *)cur->data, g_list_next (cur) ? ',' : ']');
			cur = g_list_next (cur);
		}
	}
	evbuffer_add (cbdata->out, "}", 1);
}
/*
 * Called before destroying of task's session
 */
static void
http_scan_task_free (gpointer arg)
{
	struct scan_callback_data				*cbdata = arg;
	struct evbuffer							*evb;
	struct metric_result					*mres;

	if (cbdata->processed) {
		evb = evbuffer_new ();
		if (!evb) {
			msg_err ("cannot allocate evbuffer for reply");
			evhttp_send_reply (cbdata->req, HTTP_INTERNAL, "500 insufficient memory", NULL);
			free_task_hard (cbdata->task);
			return;
		}
		cbdata->out = evb;
		cbdata->first_symbol = TRUE;

		mres = g_hash_table_lookup (cbdata->task->results, DEFAULT_METRIC);
		if (mres) {
			evbuffer_add_printf (evb, "{\"is_spam\": %s,"
					"\"is_skipped\":%s,"
					"\"score\":%.2f,"
					"\"required_score\":%.2f,"
					"\"action\":\"%s\","
					"\"symbols\":[",
					mres->score >= mres->metric->required_score ? "true" : "false",
					cbdata->task->is_skipped ? "true" : "false", mres->score, mres->metric->required_score,
					str_action_metric (check_metric_action (mres->score, mres->metric->required_score, mres->metric)));
			/* Iterate all symbols */
			g_hash_table_foreach (mres->symbols, http_scan_metric_symbols_callback, cbdata);
			evbuffer_add (evb, "]}" CRLF, 4);
		}
		else {
			evbuffer_add_printf (evb, "{\"success\":false}" CRLF);
		}
		evhttp_add_header (cbdata->req->output_headers, "Connection", "close");
		http_calculate_content_length (evb, cbdata->req);

		evhttp_send_reply (cbdata->req, HTTP_OK, "OK", evb);
		evbuffer_free (evb);
		free_task_hard (cbdata->task);
	}
	/* If task is not processed, just do nothing */
	return;
}

/*
 * Handler of session destroying
 */
static void
http_scan_task_event_helper (int fd, short what, gpointer arg)
{
	struct scan_callback_data				*cbdata = arg;

	destroy_session (cbdata->task->s);
}

/*
 * Called if all filters are processed, non-threaded and simple version
 */
static gboolean
http_scan_task_fin (gpointer arg)
{
	struct scan_callback_data				*cbdata = arg;
	static struct timeval					 tv = {.tv_sec = 0, .tv_usec = 0 };

	if (cbdata->task->state != WRITING_REPLY) {
		cbdata->task->state = WRITE_REPLY;
	}

	/* Check if we have all events finished */
	if (cbdata->task->state != WRITING_REPLY) {
		if (cbdata->task->fin_callback) {
			cbdata->task->fin_callback (cbdata->task->fin_arg);
		}
		else {
			/*
			 * XXX: we cannot call this one directly as session mutex is locked, so we need to plan some event
			 * unfortunately
			 * destroy_session (cbdata->task->s);
			*/
			event_base_once (cbdata->ctx->ev_base, -1, EV_TIMEOUT, http_scan_task_event_helper, cbdata, &tv);
		}
	}

	return TRUE;
}

/*
 * Called if session was restored inside fin callback
 */
static void
http_scan_task_restore (gpointer arg)
{
	struct scan_callback_data				*cbdata = arg;

	/* Special state */
	cbdata->task->state = WRITING_REPLY;
}

/* Prepare callback data for scan */
static struct scan_callback_data*
http_prepare_scan (struct evhttp_request *req, struct rspamd_webui_worker_ctx *ctx, struct evbuffer *in, GError **err)
{
	struct worker_task						*task;
	struct scan_callback_data				*cbdata;

	/* Check for data */
	if (EVBUFFER_LENGTH (in) == 0) {
		g_set_error (err, g_quark_from_static_string ("webui"), 500, "no message for learning");
		return NULL;
	}

	/* Prepare task */
	task = construct_task (ctx->worker);
	if (task == NULL) {
		g_set_error (err, g_quark_from_static_string ("webui"), 500, "task cannot be created");
		return NULL;
	}

	task->msg = memory_pool_alloc (task->task_pool, sizeof (f_str_t));
	task->msg->begin = EVBUFFER_DATA (in);
	task->msg->len = EVBUFFER_LENGTH (in);

	task->resolver = ctx->resolver;
	task->ev_base = ctx->ev_base;

	cbdata = memory_pool_alloc (task->task_pool, sizeof (struct scan_callback_data));
	cbdata->task = task;
	cbdata->req = req;
	cbdata->ctx = ctx;
	cbdata->processed = FALSE;

	if (process_message (task) == -1) {
		msg_warn ("processing of message failed");
		g_set_error (err, g_quark_from_static_string ("webui"), 500, "message cannot be processed");
		free_task_hard (task);
		return NULL;
	}

	/* Set up async session */
	task->s = new_async_session (task->task_pool, http_scan_task_fin, http_scan_task_restore, http_scan_task_free, cbdata);
	if (process_filters (task) == -1) {
		msg_warn ("filtering of message failed");
		g_set_error (err, g_quark_from_static_string ("webui"), 500, "message cannot be filtered");
		free_task_hard (task);
		return NULL;
	}

	cbdata->processed = TRUE;

	return cbdata;
}

struct learn_callback_data {
	struct worker_task *task;
	struct evhttp_request *req;
	struct classifier_config *classifier;
	struct rspamd_webui_worker_ctx *ctx;
	gboolean is_spam;
	gboolean processed;
};

/*
 * Called before destroying of task's session, here we can perform learning
 */
static void
http_learn_task_free (gpointer arg)
{
	struct learn_callback_data				*cbdata = arg;
	GError									*err = NULL;
	struct evbuffer							*evb;

	if (cbdata->processed) {
		evb = evbuffer_new ();
		if (!evb) {
			msg_err ("cannot allocate evbuffer for reply");
			evhttp_send_reply (cbdata->req, HTTP_INTERNAL, "500 insufficient memory", NULL);
			free_task_hard (cbdata->task);
			return;
		}

		if (!learn_task_spam (cbdata->classifier, cbdata->task, cbdata->is_spam, &err)) {
			evbuffer_add_printf (evb, "{\"error\":\"%s\"}" CRLF, err->message);
			evhttp_add_header (cbdata->req->output_headers, "Connection", "close");
			http_calculate_content_length (evb, cbdata->req);

			evhttp_send_reply (cbdata->req, HTTP_INTERNAL + err->code, err->message, evb);
			evbuffer_free (evb);
			g_error_free (err);
			free_task_hard (cbdata->task);
			return;
		}
		/* Successful learn */
		evbuffer_add_printf (evb, "{\"success\":true}" CRLF);
		evhttp_add_header (cbdata->req->output_headers, "Connection", "close");
		http_calculate_content_length (evb, cbdata->req);

		evhttp_send_reply (cbdata->req, HTTP_OK, "OK", evb);
		evbuffer_free (evb);
		free_task_hard (cbdata->task);
	}
	/* If task is not processed, just do nothing */
	return;
}

/*
 * Handler of session destroying
 */
static void
http_learn_task_event_helper (int fd, short what, gpointer arg)
{
	struct learn_callback_data				*cbdata = arg;

	destroy_session (cbdata->task->s);
}

/*
 * Called if all filters are processed, non-threaded and simple version
 */
static gboolean
http_learn_task_fin (gpointer arg)
{
	struct learn_callback_data				*cbdata = arg;
	static struct timeval					 tv = {.tv_sec = 0, .tv_usec = 0 };

	if (cbdata->task->state != WRITING_REPLY) {
		cbdata->task->state = WRITE_REPLY;
	}

	/* Check if we have all events finished */
	if (cbdata->task->state != WRITING_REPLY) {
		if (cbdata->task->fin_callback) {
			cbdata->task->fin_callback (cbdata->task->fin_arg);
		}
		else {
			/*
			 * XXX: we cannot call this one directly as session mutex is locked, so we need to plan some event
			 * unfortunately
			 * destroy_session (cbdata->task->s);
			*/
			event_base_once (cbdata->ctx->ev_base, -1, EV_TIMEOUT, http_learn_task_event_helper, cbdata, &tv);
		}
	}

	return TRUE;
}

/*
 * Called if session was restored inside fin callback
 */
static void
http_learn_task_restore (gpointer arg)
{
	struct learn_callback_data				*cbdata = arg;

	/* Special state */
	cbdata->task->state = WRITING_REPLY;
}

/* Prepare callback data for learn */
static struct learn_callback_data*
http_prepare_learn (struct evhttp_request *req, struct rspamd_webui_worker_ctx *ctx, struct evbuffer *in, gboolean is_spam, GError **err)
{
	struct worker_task						*task;
	struct learn_callback_data				*cbdata;
	struct classifier_config				*cl;

	/* Check for data */
	if (EVBUFFER_LENGTH (in) == 0) {
		g_set_error (err, g_quark_from_static_string ("webui"), 500, "no message for learning");
		return NULL;
	}
	/* Check for classifier */
	cl = find_classifier_conf (ctx->cfg, "bayes");
	if (cl == NULL) {
		g_set_error (err, g_quark_from_static_string ("webui"), 500, "classifier not found");
		return NULL;
	}
	/* Prepare task */
	task = construct_task (ctx->worker);
	if (task == NULL) {
		g_set_error (err, g_quark_from_static_string ("webui"), 500, "task cannot be created");
		return NULL;
	}

	task->msg = memory_pool_alloc (task->task_pool, sizeof (f_str_t));
	task->msg->begin = EVBUFFER_DATA (in);
	task->msg->len = EVBUFFER_LENGTH (in);

	task->resolver = ctx->resolver;
	task->ev_base = ctx->ev_base;

	cbdata = memory_pool_alloc (task->task_pool, sizeof (struct learn_callback_data));
	cbdata->task = task;
	cbdata->req = req;
	cbdata->classifier = cl;
	cbdata->ctx = ctx;
	cbdata->is_spam = is_spam;
	cbdata->processed = FALSE;

	if (process_message (task) == -1) {
		msg_warn ("processing of message failed");
		g_set_error (err, g_quark_from_static_string ("webui"), 500, "message cannot be processed");
		free_task_hard (task);
		return NULL;
	}

	/* Set up async session */
	task->s = new_async_session (task->task_pool, http_learn_task_fin, http_learn_task_restore, http_learn_task_free, cbdata);
	if (process_filters (task) == -1) {
		msg_warn ("filtering of message failed");
		g_set_error (err, g_quark_from_static_string ("webui"), 500, "message cannot be filtered");
		free_task_hard (task);
		return NULL;
	}

	cbdata->processed = TRUE;

	return cbdata;
}

/*
 * Set metric action
 */
static gboolean
http_set_metric_action (struct config_file *cfg,
		json_t *jv, struct metric *metric, enum rspamd_metric_action act)
{
	gdouble									 actval;
	GList									*cur;
	struct metric_action					*act_found;

	if (!json_is_number (jv)) {
		msg_err ("json element data error");
		return FALSE;
	}
	actval = json_number_value (jv);
	if (metric->action == act && metric->required_score != actval) {
		return add_dynamic_action (cfg, DEFAULT_METRIC, act, actval);
	}

	/* Try to search in all metrics */
	/* XXX: clarify this code, currently it looks like a crap */
	cur = metric->actions;
	while (cur) {
		act_found = cur->data;
		if (act_found->action == act) {
			if (act_found->score != actval) {
				return add_dynamic_action (cfg, DEFAULT_METRIC, act, actval);
			}
		}
		cur = g_list_next (cur);
	}

	return TRUE;
}

/* Command handlers */

/*
 * Auth command handler:
 * request: /auth
 * headers: Password
 * reply: json {"auth": "ok", "version": "0.5.2", "uptime": "some uptime", "error": "none"}
 */
static void
http_handle_auth (struct evhttp_request *req, gpointer arg)
{
	struct rspamd_webui_worker_ctx 			*ctx = arg;
	struct rspamd_stat						*st;
	struct evbuffer							*evb;
	gchar									*auth = "ok", *error = "none";
	time_t									 uptime;
	gulong									 data[4];

	if (!http_check_password (ctx, req)) {
		return;
	}

	evb = evbuffer_new ();
	if (!evb) {
		msg_err ("cannot allocate evbuffer for reply");
		evhttp_send_reply (req, HTTP_INTERNAL, "500 insufficient memory", NULL);
		return;
	}

	st = ctx->srv->stat;
	data[0] = st->actions_stat[METRIC_ACTION_NOACTION];
	data[1] = st->actions_stat[METRIC_ACTION_ADD_HEADER] + st->actions_stat[METRIC_ACTION_REWRITE_SUBJECT];
	data[2] = st->actions_stat[METRIC_ACTION_GREYLIST];
	data[3] = st->actions_stat[METRIC_ACTION_REJECT];

	/* Get uptime */
	uptime = time (NULL) - ctx->start_time;

	evbuffer_add_printf (evb, "{\"auth\": \"%s\",\"version\":\"%s\",\"uptime\": %lu,\"error\":\"%s\", "
			"\"clean\":%lu,\"probable\":%lu,\"greylist\":%lu,\"reject\":%lu,"
			"\"scanned\":%u,\"learned\":%u}" CRLF,
			auth, RVERSION, (long unsigned)uptime, error, data[0], data[1], data[2], data[3],
			st->messages_scanned, st->messages_learned);
	evhttp_add_header (req->output_headers, "Connection", "close");
	http_calculate_content_length (evb, req);

	evhttp_send_reply (req, HTTP_OK, "OK", evb);
	evbuffer_free (evb);
}

/*
 * Symbols command handler:
 * request: /symbols
 * reply: json [{
 * 	"name": "group_name",
 * 	"symbols": [
 * 		{
 * 		"name": "name",
 * 		"weight": 0.1,
 * 		"description": "description of symbol"
 * 		},
 * 		{...}
 * },
 * {...}]
 */
static void
http_handle_symbols (struct evhttp_request *req, gpointer arg)
{
	struct rspamd_webui_worker_ctx 			*ctx = arg;
	struct evbuffer							*evb;
	GList									*cur_gr, *cur_sym;
	struct symbols_group					*gr;
	struct symbol_def						*sym;

	if (!http_check_password (ctx, req)) {
		return;
	}

	evb = evbuffer_new ();
	if (!evb) {
		msg_err ("cannot allocate evbuffer for reply");
		evhttp_send_reply (req, HTTP_INTERNAL, "500", NULL);
		return;
	}

	/* Trailer */
	evbuffer_add (evb, "[", 1);

	/* Go throught all symbols groups */
	cur_gr = ctx->cfg->symbols_groups;
	while (cur_gr) {
		gr = cur_gr->data;
		evbuffer_add_printf (evb, "{\"group\":\"%s\",\"rules\":[", gr->name);
		/* Iterate throught all symbols */
		cur_sym = gr->symbols;
		while (cur_sym) {
			sym = cur_sym->data;

			if (sym->description) {
				evbuffer_add_printf (evb, "{\"symbol\":\"%s\",\"weight\":%.2f,\"description\":\"%s\"%s", sym->name, *sym->weight_ptr,
						sym->description, g_list_next (cur_sym) ? "}," : "}");
			}
			else {
				evbuffer_add_printf (evb, "{\"symbol\":\"%s\",\"weight\":%.2f%s", sym->name, *sym->weight_ptr,
										g_list_next (cur_sym) ? "}," : "}");
			}

			cur_sym = g_list_next (cur_sym);
		}
		if (g_list_next (cur_gr)) {
			evbuffer_add (evb, "]},", 3);
		}
		else {
			evbuffer_add (evb, "]},", 2);
		}
		cur_gr = g_list_next (cur_gr);
	}
	evbuffer_add (evb, "]" CRLF, 3);
	evhttp_add_header (req->output_headers, "Connection", "close");
	http_calculate_content_length (evb, req);

	evhttp_send_reply (req, HTTP_OK, "OK", evb);
	evbuffer_free (evb);
}

/*
 * Actions command handler:
 * request: /actions
 * reply: json [{
 * 	"action": "no action",
 * 	"value": 1.1
 * },
 * {...}]
 */
static void
http_handle_actions (struct evhttp_request *req, gpointer arg)
{
	struct rspamd_webui_worker_ctx 			*ctx = arg;
	struct evbuffer							*evb;
	struct metric							*metric;
	GList									*cur;
	struct metric_action					*act;

	if (!http_check_password (ctx, req)) {
		return;
	}

	evb = evbuffer_new ();
	if (!evb) {
		msg_err ("cannot allocate evbuffer for reply");
		evhttp_send_reply (req, HTTP_INTERNAL, "500", NULL);
		return;
	}

	/* Trailer */
	evbuffer_add (evb, "[", 1);

	/* Get actions for default metric */
	metric = g_hash_table_lookup (ctx->cfg->metrics, DEFAULT_METRIC);
	if (metric != NULL) {

		cur = metric->actions;
		while (cur) {
			act = cur->data;
			cur = g_list_next (cur);
			evbuffer_add_printf (evb, "{\"action\":\"%s\",\"value\":%.2f},", str_action_metric (act->action), act->score);
		}
		/* Print default action */
		evbuffer_add_printf (evb, "{\"action\":\"%s\",\"value\":%.2f}", str_action_metric (metric->action), metric->required_score);
	}

	evbuffer_add (evb, "]" CRLF, 3);
	evhttp_add_header (req->output_headers, "Connection", "close");
	http_calculate_content_length (evb, req);

	evhttp_send_reply (req, HTTP_OK, "OK", evb);
	evbuffer_free (evb);
}
/*
 * Maps command handler:
 * request: /maps
 * headers: Password
 * reply: json [
 * 		{
 * 		"map": "name",
 * 		"description": "description",
 * 		"editable": true
 * 		},
 * 		{...}
 * ]
 */
static void
http_handle_maps (struct evhttp_request *req, gpointer arg)
{
	struct rspamd_webui_worker_ctx 			*ctx = arg;
	struct evbuffer							*evb;
	GList									*cur, *tmp = NULL;
	struct rspamd_map						*map;
	gboolean								 editable;


	if (!http_check_password (ctx, req)) {
		return;
	}

	evb = evbuffer_new ();
	if (!evb) {
		msg_err ("cannot allocate evbuffer for reply");
		evhttp_send_reply (req, HTTP_INTERNAL, "500 insufficient memory", NULL);
		return;
	}

	/* Trailer */
	evbuffer_add (evb, "[", 1);

	/* Iterate over all maps */
	cur = ctx->cfg->maps;
	while (cur) {
		map = cur->data;
		if (map->protocol == MAP_PROTO_FILE && map->description != NULL) {
			if (access (map->uri, R_OK) == 0) {
				tmp = g_list_prepend (tmp, map);
			}
		}
		cur = g_list_next (cur);
	}
	/* Iterate over selected maps */
	cur = tmp;
	while (cur) {
		map = cur->data;
		editable = access (map->uri, W_OK) == 0;
		evbuffer_add_printf (evb, "{\"map\":%u,\"description\":\"%s\",\"editable\":%s%s",
				map->id, map->description, editable ? "true" : "false",
						cur->next ? "}," : "}");
		cur = g_list_next (cur);
	}

	if (tmp) {
		g_list_free (tmp);
	}

	evbuffer_add (evb, "]" CRLF, 3);
	evhttp_add_header (req->output_headers, "Connection", "close");
	http_calculate_content_length (evb, req);

	evhttp_send_reply (req, HTTP_OK, "OK", evb);
	evbuffer_free (evb);
}

/*
 * Get map command handler:
 * request: /getmap
 * headers: Password, Map
 * reply: plain-text
 */
static void
http_handle_get_map (struct evhttp_request *req, gpointer arg)
{
	struct rspamd_webui_worker_ctx 			*ctx = arg;
	struct evbuffer							*evb;
	GList									*cur;
	struct rspamd_map						*map;
	const gchar								*idstr;
	gchar									*errstr;
	struct stat								 st;
	gint									 fd;
	guint32									 id;
	gboolean								 found = FALSE;


	if (!http_check_password (ctx, req)) {
		return;
	}

	evb = evbuffer_new ();
	if (!evb) {
		msg_err ("cannot allocate evbuffer for reply");
		evhttp_send_reply (req, HTTP_INTERNAL, "500 insufficient memory", NULL);
		return;
	}

	idstr = evhttp_find_header (req->input_headers, "Map");

	if (idstr == NULL) {
		msg_info ("absent map id");
		evbuffer_free (evb);
		evhttp_send_reply (req, HTTP_INTERNAL, "500 map open error", NULL);
		return;
	}

	id = strtoul (idstr, &errstr, 10);
	if (*errstr != '\0') {
		msg_info ("invalid map id");
		evbuffer_free (evb);
		evhttp_send_reply (req, HTTP_INTERNAL, "500 map open error", NULL);
		return;
	}

	/* Now let's be sure that we have map defined in configuration */
	cur = ctx->cfg->maps;
	while (cur) {
		map = cur->data;
		if (map->id == id && map->protocol == MAP_PROTO_FILE) {
			found = TRUE;
			break;
		}
		cur = g_list_next (cur);
	}

	if (!found) {
		msg_info ("map not found");
		evbuffer_free (evb);
		evhttp_send_reply (req, HTTP_NOTFOUND, "404 map not found", NULL);
		return;
	}

	if (stat (map->uri, &st) == -1 || (fd = open (map->uri, O_RDONLY)) == -1) {
		msg_err ("cannot open map %s: %s", map->uri, strerror (errno));
		evbuffer_free (evb);
		evhttp_send_reply (req, HTTP_INTERNAL, "500 map open error", NULL);
		return;
	}
	/* Set buffer size */
	if (evbuffer_expand (evb, st.st_size) != 0) {
		msg_err ("cannot allocate buffer for map %s: %s", map->uri, strerror (errno));
		evbuffer_free (evb);
		evhttp_send_reply (req, HTTP_INTERNAL, "500 insufficient memory", NULL);
		close (fd);
		return;
	}

	/* Read the whole buffer */
	if (evbuffer_read (evb, fd, st.st_size) == -1) {
		msg_err ("cannot read map %s: %s", map->uri, strerror (errno));
		evbuffer_free (evb);
		evhttp_send_reply (req, HTTP_INTERNAL, "500 map read error", NULL);
		close (fd);
		return;
	}

	evhttp_add_header (req->output_headers, "Connection", "close");
	http_calculate_content_length (evb, req);

	close (fd);

	evhttp_send_reply (req, HTTP_OK, "OK", evb);
	evbuffer_free (evb);
}

/*
 * Graph command handler:
 * request: /graph
 * headers: Password
 * reply: json [
 * 		{ label: "Foo", data: [ [10, 1], [17, -14], [30, 5] ] },
 * 		{ label: "Bar", data: [ [10, 1], [17, -14], [30, 5] ] },
 * 		{...}
 * ]
 */
/* XXX: now this function returns only random data */
static void
http_handle_graph (struct evhttp_request *req, gpointer arg)
{
	struct rspamd_webui_worker_ctx 			*ctx = arg;
	struct evbuffer							*evb;
	gint									 i, seed;
	time_t									 now, t;
	double									 vals[5][100];

	if (!http_check_password (ctx, req)) {
		return;
	}

	evb = evbuffer_new ();
	if (!evb) {
		msg_err ("cannot allocate evbuffer for reply");
		evhttp_send_reply (req, HTTP_INTERNAL, "500 insufficient memory", NULL);
		return;
	}

	/* Trailer */
	evbuffer_add (evb, "[", 1);

	/* XXX: simple and stupid set */
	seed = g_random_int ();
	for (i = 0; i < 100; i ++, seed ++) {
		vals[0][i] = fabs ((sin (seed * 0.1 * M_PI_2) + 1) * 40. + ((gint)(g_random_int () % 2) - 1));
		vals[1][i] = vals[0][i] * 0.5;
		vals[2][i] = vals[0][i] * 0.1;
		vals[3][i] = vals[0][i] * 0.3;
		vals[4][i] = vals[0][i] * 1.9;
	}

	now = time (NULL);

	/* Ham label */
	t = now - 6000;
	evbuffer_add_printf (evb, "{\"label\": \"Clean messages\", \"lines\": {\"fill\": false}, \"color\": \""
			COLOR_CLEAN "\", \"data\":[");
	for (i = 0; i < 100; i ++, t += 60) {
		evbuffer_add_printf (evb, "[%llu,%.2f%s", (long long unsigned)t * 1000, vals[0][i], i == 99 ? "]" : "],");
	}
	evbuffer_add (evb, "]},", 3);

	/* Probable spam label */
	t = now - 6000;
	evbuffer_add_printf (evb, "{\"label\": \"Probable spam messages\", \"lines\": {\"fill\": false}, \"color\": \""
			COLOR_PROBABLE_SPAM "\", \"data\":[");
	for (i = 0; i < 100; i ++, t += 60) {
		evbuffer_add_printf (evb, "[%llu,%.2f%s", (long long unsigned)t * 1000, vals[1][i], i == 99 ? "]" : "],");
	}
	evbuffer_add (evb, "]},", 3);

	/* Greylist label */
	t = now - 6000;
	evbuffer_add_printf (evb, "{\"label\": \"Greylisted messages\", \"lines\": {\"fill\": false}, \"color\": \""
			COLOR_GREYLIST "\", \"data\":[");
	for (i = 0; i < 100; i ++, t += 60) {
		evbuffer_add_printf (evb, "[%llu,%.2f%s", (long long unsigned)t * 1000, vals[2][i], i == 99 ? "]" : "],");
	}
	evbuffer_add (evb, "]},", 3);

	/* Reject label */
	t = now - 6000;
	evbuffer_add_printf (evb, "{\"label\": \"Rejected messages\", \"lines\": {\"fill\": false}, \"color\": \""
			COLOR_REJECT "\", \"data\":[");
	for (i = 0; i < 100; i ++, t += 60) {
		evbuffer_add_printf (evb, "[%llu,%.2f%s", (long long unsigned)t * 1000, vals[3][i], i == 99 ? "]" : "],");
	}
	evbuffer_add (evb, "]},", 3);

	/* Total label */
	t = now - 6000;
	evbuffer_add_printf (evb, "{\"label\": \"Total messages\", \"lines\": {\"fill\": false}, \"color\": \""
			COLOR_TOTAL "\", \"data\":[");
	for (i = 0; i < 100; i ++, t += 60) {
		evbuffer_add_printf (evb, "[%llu,%.2f%s", (long long unsigned)t * 1000, vals[4][i], i == 99 ? "]" : "],");
	}
	evbuffer_add (evb, "]}", 2);

	evbuffer_add (evb, "]" CRLF, 3);

	evhttp_add_header (req->output_headers, "Connection", "close");
	http_calculate_content_length (evb, req);

	evhttp_send_reply (req, HTTP_OK, "OK", evb);
	evbuffer_free (evb);
}

/*
 * Pie chart command handler:
 * request: /pie
 * headers: Password
 * reply: json [
 * 		{ label: "Foo", data: 11 },
 * 		{ label: "Bar", data: 20 },
 * 		{...}
 * ]
 */
static void
http_handle_pie_chart (struct evhttp_request *req, gpointer arg)
{
	struct rspamd_webui_worker_ctx 			*ctx = arg;
	struct evbuffer							*evb;
	gdouble                             	 data[4], total;

	if (!http_check_password (ctx, req)) {
		return;
	}

	evb = evbuffer_new ();
	if (!evb) {
		msg_err ("cannot allocate evbuffer for reply");
		evhttp_send_reply (req, HTTP_INTERNAL, "500 insufficient memory", NULL);
		return;
	}

	total = ctx->srv->stat->messages_scanned;
	if (total != 0) {
		data[0] = ctx->srv->stat->actions_stat[METRIC_ACTION_NOACTION] / total * 100.;
		data[1] = (ctx->srv->stat->actions_stat[METRIC_ACTION_ADD_HEADER] + ctx->srv->stat->actions_stat[METRIC_ACTION_REWRITE_SUBJECT]) / total * 100.;
		data[2] = ctx->srv->stat->actions_stat[METRIC_ACTION_GREYLIST] / total * 100.;
		data[3] = ctx->srv->stat->actions_stat[METRIC_ACTION_REJECT] / total * 100.;

		evbuffer_add_printf (evb, "[[\"Clean messages\",%.2f],", data[0]);
		evbuffer_add_printf (evb, "[\"Probable spam messages\",%.2f],", data[1]);
		evbuffer_add_printf (evb, "[\"Greylisted messages\",%.2f],", data[2]);
		evbuffer_add_printf (evb, "[\"Rejected messages\",%.2f]]" CRLF, data[3]);
	}
	else {
		evbuffer_add_printf (evb, "[[\"Not scanned messages\", 0]]" CRLF);
	}


	evhttp_add_header (req->output_headers, "Connection", "close");
	http_calculate_content_length (evb, req);

	evhttp_send_reply (req, HTTP_OK, "OK", evb);
	evbuffer_free (evb);
}

/*
 * History command handler:
 * request: /history
 * headers: Password
 * reply: json [
 * 		{ label: "Foo", data: 11 },
 * 		{ label: "Bar", data: 20 },
 * 		{...}
 * ]
 */
static void
http_handle_history (struct evhttp_request *req, gpointer arg)
{
	struct rspamd_webui_worker_ctx 			*ctx = arg;
	struct evbuffer							*evb;
	struct roll_history_row					*row;
	struct roll_history						 copied_history;
	gint									 i, row_num;
	struct tm								*tm;
	gchar									 timebuf[32];
	gchar									 ip_buf[INET6_ADDRSTRLEN];

	if (!http_check_password (ctx, req)) {
		return;
	}

	evb = evbuffer_new ();
	if (!evb) {
		msg_err ("cannot allocate evbuffer for reply");
		evhttp_send_reply (req, HTTP_INTERNAL, "500 insufficient memory", NULL);
		return;
	}

	/* Set lock on history */
	memory_pool_lock_mutex (ctx->srv->history->mtx);
	ctx->srv->history->need_lock = TRUE;
	/* Copy locked */
	memcpy (&copied_history, ctx->srv->history, sizeof (copied_history));
	memory_pool_unlock_mutex (ctx->srv->history->mtx);

	/* Trailer */
	evbuffer_add (evb, "[", 1);

	/* Go throught all rows */
	row_num = copied_history.cur_row;
	for (i = 0; i < HISTORY_MAX_ROWS; i ++, row_num ++) {
		if (row_num == HISTORY_MAX_ROWS) {
			row_num = 0;
		}
		row = &copied_history.rows[row_num];
		/* Get only completed rows */
		if (row->completed) {
			if (i != 0) {
				evbuffer_add (evb, ",", 1);
			}
			tm = localtime (&row->tv.tv_sec);
			strftime (timebuf, sizeof (timebuf), "%F %H:%M:%S", tm);
#ifdef HAVE_INET_PTON
			if (row->from_addr.ipv6) {
				inet_ntop (AF_INET6, &row->from_addr.d.in6, ip_buf, sizeof (ip_buf));
			}
			else {
				inet_ntop (AF_INET, &row->from_addr.d.in4, ip_buf, sizeof (ip_buf));
			}
#else
			rspamd_strlcpy (ip_buf, inet_ntoa (task->from_addr), sizeof (ip_buf));
#endif
			if (row->user[0] != '\0') {
				evbuffer_add_printf (evb, "{\"time\":\"%s\",\"id\":\"%s\",\"ip\":\"%s\",\"action\":\"%s\","
					"\"score\":%.2f,\"required_score\": %.2f,\"symbols\":\"%s\",\"size\":%zd,\"scan_time\":%u,"
					"\"user\":\"%s\"}", timebuf, row->message_id, ip_buf, str_action_metric (row->action),
					row->score, row->required_score, row->symbols, row->len, row->scan_time, row->user);
			}
			else {
				evbuffer_add_printf (evb, "{\"time\":\"%s\",\"id\":\"%s\",\"ip\":\"%s\",\"action\":\"%s\","
					"\"score\": %.2f,\"required_score\":%.2f,\"symbols\":\"%s\",\"size\":%zd,\"scan_time\":%u}",
					timebuf, row->message_id, ip_buf, str_action_metric (row->action),
					row->score, row->required_score, row->symbols, row->len, row->scan_time);
			}
		}
	}

	evbuffer_add (evb, "]" CRLF, 3);

	evhttp_add_header (req->output_headers, "Connection", "close");
	http_calculate_content_length (evb, req);

	evhttp_send_reply (req, HTTP_OK, "OK", evb);
	evbuffer_free (evb);
}

/*
 * Learn spam command handler:
 * request: /learnspam
 * headers: Password
 * input: plaintext data
 * reply: json {"success":true} or {"error":"error message"}
 */
static void
http_handle_learn_spam (struct evhttp_request *req, gpointer arg)
{
	struct rspamd_webui_worker_ctx 			*ctx = arg;
	struct evbuffer							*evb, *inb;
	GError									*err = NULL;
	struct learn_callback_data				*cbdata;

	if (!http_check_password (ctx, req)) {
		return;
	}

	inb = req->input_buffer;

	cbdata = http_prepare_learn (req, ctx, inb, TRUE, &err);
	if (cbdata == NULL) {
		/* Handle error */
		evb = evbuffer_new ();
		if (!evb) {
			msg_err ("cannot allocate evbuffer for reply");
			evhttp_send_reply (req, HTTP_INTERNAL, "500 insufficient memory", NULL);
			return;
		}
		evbuffer_add_printf (evb, "{\"error\":\"%s\"}" CRLF, err->message);
		evhttp_add_header (req->output_headers, "Connection", "close");
		http_calculate_content_length (evb, req);

		evhttp_send_reply (req, err->code, err->message, evb);
		evbuffer_free (evb);
		g_error_free (err);
		return;
	}
}

/*
 * Learn ham command handler:
 * request: /learnham
 * headers: Password
 * input: plaintext data
 * reply: json {"success":true} or {"error":"error message"}
 */
static void
http_handle_learn_ham (struct evhttp_request *req, gpointer arg)
{
	struct rspamd_webui_worker_ctx 			*ctx = arg;
	struct evbuffer							*evb, *inb;
	GError									*err = NULL;
	struct learn_callback_data				*cbdata;

	if (!http_check_password (ctx, req)) {
		return;
	}

	inb = req->input_buffer;

	cbdata = http_prepare_learn (req, ctx, inb, FALSE, &err);
	if (cbdata == NULL) {
		/* Handle error */
		evb = evbuffer_new ();
		if (!evb) {
			msg_err ("cannot allocate evbuffer for reply");
			evhttp_send_reply (req, HTTP_INTERNAL, "500 insufficient memory", NULL);
			return;
		}
		evbuffer_add_printf (evb, "{\"error\":\"%s\"}" CRLF, err->message);
		evhttp_add_header (req->output_headers, "Connection", "close");
		http_calculate_content_length (evb, req);

		evhttp_send_reply (req, err->code, err->message, evb);
		evbuffer_free (evb);
		g_error_free (err);
		return;
	}
}

/*
 * Save actions command handler:
 * request: /saveactions
 * headers: Password
 * input: json array [<spam>,<probable spam>,<greylist>]
 * reply: json {"success":true} or {"error":"error message"}
 */
static void
http_handle_save_actions (struct evhttp_request *req, gpointer arg)
{
	struct rspamd_webui_worker_ctx 			*ctx = arg;
	struct evbuffer							*evb;
	struct metric							*metric;
	json_t									*json, *jv;
	json_error_t							 je;


	evb = evbuffer_new ();
	if (!evb) {
		msg_err ("cannot allocate evbuffer for reply");
		evhttp_send_reply (req, HTTP_INTERNAL, "500 insufficient memory", NULL);
		return;
	}

	metric = g_hash_table_lookup (ctx->cfg->metrics, DEFAULT_METRIC);
	if (metric == NULL) {
		msg_err ("cannot find default metric");
		evbuffer_free (evb);
		evhttp_send_reply (req, HTTP_INTERNAL, "500 default metric not defined", NULL);
		return;
	}

	/* Now check for dynamic config */
	if (!ctx->cfg->dynamic_conf) {
		msg_err ("dynamic conf has not been defined");
		evbuffer_free (evb);
		evhttp_send_reply (req, HTTP_INTERNAL, "503 dynamic config not found, cannot save", NULL);
		return;
	}

	/* Try to load json */
	json = json_load_evbuffer (req->input_buffer, &je);
	if (json == NULL) {
		msg_err ("json load error: %s", je.text);
		evbuffer_free (evb);
		evhttp_send_reply (req, HTTP_INTERNAL, "504 json parse error", NULL);
		return;
	}

	if (!json_is_array (json) || json_array_size (json) != 3) {
		msg_err ("json data error");
		evbuffer_free (evb);
		json_delete (json);
		evhttp_send_reply (req, HTTP_INTERNAL, "505 invalid json data", NULL);
		return;
	}

	/* Now try to check what we have */

	/* Spam element */
	jv = json_array_get (json, 0);
	if (!http_set_metric_action (ctx->cfg, jv, metric, METRIC_ACTION_REJECT)) {
		msg_err ("json data error");
		evbuffer_free (evb);
		json_delete (json);
		evhttp_send_reply (req, HTTP_INTERNAL, "506 cannot set action's value", NULL);
		return;
	}

	/* Probable spam */
	jv = json_array_get (json, 1);
	if (!http_set_metric_action (ctx->cfg, jv, metric, METRIC_ACTION_ADD_HEADER)) {
		msg_err ("json data error");
		evbuffer_free (evb);
		json_delete (json);
		evhttp_send_reply (req, HTTP_INTERNAL, "506 cannot set action's value", NULL);
		return;
	}

	/* Greylist */
	jv = json_array_get (json, 2);
	if (!http_set_metric_action (ctx->cfg, jv, metric, METRIC_ACTION_GREYLIST)) {
		msg_err ("json data error");
		evbuffer_free (evb);
		json_delete (json);
		evhttp_send_reply (req, HTTP_INTERNAL, "506 cannot set action's value", NULL);
		return;
	}

	dump_dynamic_config (ctx->cfg);

	evbuffer_add_printf (evb, "{\"success\":true}" CRLF);
	evhttp_add_header (req->output_headers, "Connection", "close");
	http_calculate_content_length (evb, req);
	evhttp_send_reply (req, HTTP_OK, "OK", evb);
	evbuffer_free (evb);
}

/*
 * Save symbols command handler:
 * request: /savesymbols
 * headers: Password
 * input: json data
 * reply: json {"success":true} or {"error":"error message"}
 */
static void
http_handle_save_symbols (struct evhttp_request *req, gpointer arg)
{
	struct rspamd_webui_worker_ctx 			*ctx = arg;
	struct evbuffer							*evb;
	struct metric							*metric;
	struct symbol							*sym;
	json_t									*json, *jv, *jname, *jvalue;
	json_error_t							 je;
	guint									 i, len;
	gdouble									 val;

	evb = evbuffer_new ();
	if (!evb) {
		msg_err ("cannot allocate evbuffer for reply");
		evhttp_send_reply (req, HTTP_INTERNAL, "500 insufficient memory", NULL);
		return;
	}

	metric = g_hash_table_lookup (ctx->cfg->metrics, DEFAULT_METRIC);
	if (metric == NULL) {
		msg_err ("cannot find default metric");
		evbuffer_free (evb);
		evhttp_send_reply (req, HTTP_INTERNAL, "500 default metric not defined", NULL);
		return;
	}

	/* Now check for dynamic config */
	if (!ctx->cfg->dynamic_conf) {
		msg_err ("dynamic conf has not been defined");
		evbuffer_free (evb);
		evhttp_send_reply (req, HTTP_INTERNAL, "503 dynamic config not found, cannot save", NULL);
		return;
	}

	/* Try to load json */
	json = json_load_evbuffer (req->input_buffer, &je);
	if (json == NULL) {
		msg_err ("json load error: %s", je.text);
		evbuffer_free (evb);
		evhttp_send_reply (req, HTTP_INTERNAL, "504 json parse error", NULL);
		return;
	}

	if (!json_is_array (json) || (len = json_array_size (json)) == 0) {
		msg_err ("json data error");
		evbuffer_free (evb);
		json_delete (json);
		evhttp_send_reply (req, HTTP_INTERNAL, "505 invalid json data", NULL);
		return;
	}

	/* Iterate over all elements */
	for (i = 0; i < len; i ++) {
		jv = json_array_get (json, i);
		if (!json_is_object (jv)) {
			msg_err ("json array data error");
			evbuffer_free (evb);
			json_delete (json);
			evhttp_send_reply (req, HTTP_INTERNAL, "505 invalid json data", NULL);
			return;
		}
		jname = json_object_get (jv, "name");
		jvalue = json_object_get (jv, "value");
		if (!json_is_string (jname) || !json_is_number (jvalue)) {
			msg_err ("json object data error");
			evbuffer_free (evb);
			json_delete (json);
			evhttp_send_reply (req, HTTP_INTERNAL, "505 invalid json data", NULL);
			return;
		}
		val = json_number_value (jvalue);
		sym = g_hash_table_lookup (metric->symbols, json_string_value (jname));
		if (sym && fabs (sym->score - val) > 0.01) {
			if (!add_dynamic_symbol (ctx->cfg, DEFAULT_METRIC, json_string_value (jname), val)) {
				evbuffer_free (evb);
				json_delete (json);
				evhttp_send_reply (req, HTTP_INTERNAL, "506 cannot write symbol's value", NULL);
				return;
			}
		}
	}

	evbuffer_add_printf (evb, "{\"success\":true}" CRLF);
	evhttp_add_header (req->output_headers, "Connection", "close");
	http_calculate_content_length (evb, req);
	evhttp_send_reply (req, HTTP_OK, "OK", evb);
	evbuffer_free (evb);
}

/*
 * Save symbols command handler:
 * request: /savesymbols
 * headers: Password, Map
 * input: plaintext data
 * reply: json {"success":true} or {"error":"error message"}
 */
static void
http_handle_save_map (struct evhttp_request *req, gpointer arg)
{
	struct rspamd_webui_worker_ctx 			*ctx = arg;
	struct evbuffer							*evb;
	GList									*cur;
	struct rspamd_map						*map;
	const gchar								*idstr;
	gchar									*errstr;
	guint32									 id;
	gboolean								 found = FALSE;
	gint									 fd;


	if (!http_check_password (ctx, req)) {
		return;
	}

	evb = evbuffer_new ();
	if (!evb) {
		msg_err ("cannot allocate evbuffer for reply");
		evhttp_send_reply (req, HTTP_INTERNAL, "500 insufficient memory", NULL);
		return;
	}

	idstr = evhttp_find_header (req->input_headers, "Map");

	if (idstr == NULL) {
		msg_info ("absent map id");
		evbuffer_free (evb);
		evhttp_send_reply (req, HTTP_INTERNAL, "500 map open error", NULL);
		return;
	}

	id = strtoul (idstr, &errstr, 10);
	if (*errstr != '\0') {
		msg_info ("invalid map id");
		evbuffer_free (evb);
		evhttp_send_reply (req, HTTP_INTERNAL, "500 map open error", NULL);
		return;
	}

	/* Now let's be sure that we have map defined in configuration */
	cur = ctx->cfg->maps;
	while (cur) {
		map = cur->data;
		if (map->id == id && map->protocol == MAP_PROTO_FILE) {
			found = TRUE;
			break;
		}
		cur = g_list_next (cur);
	}

	if (!found) {
		msg_info ("map not found: %d", id);
		evbuffer_free (evb);
		evhttp_send_reply (req, HTTP_NOTFOUND, "404 map not found", NULL);
		return;
	}

	if (g_atomic_int_get (map->locked)) {
		msg_info ("map locked: %s", map->uri);
		evbuffer_free (evb);
		evhttp_send_reply (req, HTTP_NOTFOUND, "404 map is locked", NULL);
		return;
	}

	/* Set lock */
	g_atomic_int_set (map->locked, 1);
	fd = open (map->uri, O_WRONLY | O_TRUNC);
	if (fd == -1) {
		g_atomic_int_set (map->locked, 0);
		msg_info ("map %s open error: %s", map->uri, strerror (errno));
		evbuffer_free (evb);
		evhttp_send_reply (req, HTTP_NOTFOUND, "404 map open error", NULL);
		return;
	}

	if (evbuffer_write (req->input_buffer, fd) == -1) {
		close (fd);
		g_atomic_int_set (map->locked, 0);
		msg_info ("map %s open error: %s", map->uri, strerror (errno));
		evbuffer_free (evb);
		evhttp_send_reply (req, HTTP_INTERNAL, "500 map open error", NULL);
		return;
	}

	/* Close and unlock */
	close (fd);
	g_atomic_int_set (map->locked, 0);

	evbuffer_add_printf (evb, "{\"success\":true}" CRLF);
	evhttp_add_header (req->output_headers, "Connection", "close");
	http_calculate_content_length (evb, req);
	evhttp_send_reply (req, HTTP_OK, "OK", evb);
	evbuffer_free (evb);
}

/*
 * Learn ham command handler:
 * request: /scan
 * headers: Password
 * input: plaintext data
 * reply: json {scan data} or {"error":"error message"}
 */
static void
http_handle_scan (struct evhttp_request *req, gpointer arg)
{
	struct rspamd_webui_worker_ctx 			*ctx = arg;
	struct evbuffer							*evb, *inb;
	GError									*err = NULL;
	struct scan_callback_data				*cbdata;

	if (!http_check_password (ctx, req)) {
		return;
	}

	inb = req->input_buffer;

	cbdata = http_prepare_scan (req, ctx, inb, &err);
	if (cbdata == NULL) {
		/* Handle error */
		evb = evbuffer_new ();
		if (!evb) {
			msg_err ("cannot allocate evbuffer for reply");
			evhttp_send_reply (req, HTTP_INTERNAL, "500 insufficient memory", NULL);
			return;
		}
		evbuffer_add_printf (evb, "{\"error\":\"%s\"}" CRLF, err->message);
		evhttp_add_header (req->output_headers, "Connection", "close");
		http_calculate_content_length (evb, req);

		evhttp_send_reply (req, err->code, err->message, evb);
		evbuffer_free (evb);
		g_error_free (err);
		return;
	}
}


gpointer
init_webui_worker (void)
{
	struct rspamd_webui_worker_ctx     *ctx;
	GQuark								type;

	type = g_quark_try_string ("webui");

	ctx = g_malloc0 (sizeof (struct rspamd_webui_worker_ctx));

	register_worker_opt (type, "password", xml_handle_string, ctx, G_STRUCT_OFFSET (struct rspamd_webui_worker_ctx, password));
	register_worker_opt (type, "ssl", xml_handle_boolean, ctx, G_STRUCT_OFFSET (struct rspamd_webui_worker_ctx, use_ssl));
	register_worker_opt (type, "ssl_cert", xml_handle_string, ctx, G_STRUCT_OFFSET (struct rspamd_webui_worker_ctx, ssl_cert));
	register_worker_opt (type, "ssl_key", xml_handle_string, ctx, G_STRUCT_OFFSET (struct rspamd_webui_worker_ctx, ssl_key));

	return ctx;
}

/*
 * Start worker process
 */
void
start_webui_worker (struct rspamd_worker *worker)
{
	struct sigaction                signals;
	struct rspamd_webui_worker_ctx *ctx = worker->ctx;

#ifdef WITH_PROFILER
	extern void                     _start (void), etext (void);
	monstartup ((u_long) & _start, (u_long) & etext);
#endif

	gperf_profiler_init (worker->srv->cfg, "webui_worker");

	worker->srv->pid = getpid ();

	ctx->ev_base = event_init ();

	ctx->cfg = worker->srv->cfg;
	ctx->srv = worker->srv;

	init_signals (&signals, sig_handler);
	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);

	/* SIGUSR2 handler */
	signal_set (&worker->sig_ev_usr2, SIGUSR2, sigusr2_handler, (void *) worker);
	event_base_set (ctx->ev_base, &worker->sig_ev_usr2);
	signal_add (&worker->sig_ev_usr2, NULL);

	/* SIGUSR1 handler */
	signal_set (&worker->sig_ev_usr1, SIGUSR1, sigusr1_handler, (void *) worker);
	event_base_set (ctx->ev_base, &worker->sig_ev_usr1);
	signal_add (&worker->sig_ev_usr1, NULL);

	ctx->start_time = time (NULL);
	ctx->worker = worker;
	/* Accept event */
	ctx->http = evhttp_new (ctx->ev_base);
	evhttp_accept_socket (ctx->http, worker->cf->listen_sock);

	if (ctx->use_ssl) {
#ifdef HAVE_WEBUI_SSL
		if (ctx->ssl_cert && ctx->ssl_key) {
			webui_ssl_init (ctx);
		}
		else {
			msg_err ("ssl cannot be enabled without key and cert for this server");
		}
#else
		msg_err ("http ssl is not supported by this libevent version");
#endif
	}

	/* Add callbacks for different methods */
	evhttp_set_cb (ctx->http, PATH_AUTH, http_handle_auth, ctx);
	evhttp_set_cb (ctx->http, PATH_SYMBOLS, http_handle_symbols, ctx);
	evhttp_set_cb (ctx->http, PATH_ACTIONS, http_handle_actions, ctx);
	evhttp_set_cb (ctx->http, PATH_MAPS, http_handle_maps, ctx);
	evhttp_set_cb (ctx->http, PATH_GET_MAP, http_handle_get_map, ctx);
	evhttp_set_cb (ctx->http, PATH_GRAPH, http_handle_graph, ctx);
	evhttp_set_cb (ctx->http, PATH_PIE_CHART, http_handle_pie_chart, ctx);
	evhttp_set_cb (ctx->http, PATH_HISTORY, http_handle_history, ctx);
	evhttp_set_cb (ctx->http, PATH_LEARN_SPAM, http_handle_learn_spam, ctx);
	evhttp_set_cb (ctx->http, PATH_LEARN_HAM, http_handle_learn_ham, ctx);
	evhttp_set_cb (ctx->http, PATH_SAVE_ACTIONS, http_handle_save_actions, ctx);
	evhttp_set_cb (ctx->http, PATH_SAVE_SYMBOLS, http_handle_save_symbols, ctx);
	evhttp_set_cb (ctx->http, PATH_SAVE_MAP, http_handle_save_map, ctx);
	evhttp_set_cb (ctx->http, PATH_SCAN, http_handle_scan, ctx);

	ctx->resolver = dns_resolver_init (ctx->ev_base, worker->srv->cfg);

	/* Maps events */
	start_map_watch (worker->srv->cfg, ctx->ev_base);

	event_base_loop (ctx->ev_base, 0);

	close_log (rspamd_main->logger);
	exit (EXIT_SUCCESS);
}

