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
#include "http.h"
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

gpointer init_webui_worker (struct config_file *cfg);
void start_webui_worker (struct rspamd_worker *worker);

worker_t webui_worker = {
	"webui",					/* Name */
	init_webui_worker,		/* Init function */
	start_webui_worker,		/* Start function */
	TRUE,					/* Has socket */
	TRUE,					/* Non unique */
	FALSE,					/* Non threaded */
	TRUE,					/* Killable */
	SOCK_STREAM				/* TCP socket */
};
/*
 * Worker's context
 */
struct rspamd_webui_worker_ctx {
	guint32                         timeout;
	struct timeval                  io_tv;
	/* DNS resolver */
	struct rspamd_dns_resolver     *resolver;
	/* Events base */
	struct event_base              *ev_base;
	/* Whether we use ssl for this server */
	gboolean use_ssl;
	/* Webui password */
	gchar *password;
	/* HTTP server */
	struct rspamd_http_connection_router *http;
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
	/* A map of secure IP */
	gchar *secure_ip;
	radix_tree_t *secure_map;

	/* Static files dir */
	gchar *static_files_dir;

	/* Worker */
	struct rspamd_worker *worker;
};

struct rspamd_webui_session {
	struct rspamd_webui_worker_ctx *ctx;
	memory_pool_t *pool;
	struct worker_task *task;
	struct classifier_config *cl;
	struct {
		union {
			struct in_addr in4;
			struct in6_addr in6;
		} d;
		gboolean ipv6;
		gboolean has_addr;
	} from_addr;
	gboolean is_spam;
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
		worker_stop_accept (worker);
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

static void
rspamd_webui_send_error (struct rspamd_http_connection_entry *entry, gint code,
		const gchar *error_msg)
{
	struct rspamd_http_message *msg;

	msg = rspamd_http_new_message (HTTP_RESPONSE);
	msg->date = time (NULL);
	msg->code = code;
	msg->body = g_string_sized_new (128);
	rspamd_printf_gstring (msg->body, "{\"error\":\"%s\"}", error_msg);
	rspamd_http_connection_reset (entry->conn);
	rspamd_http_connection_write_message (entry->conn, msg, NULL,
			"application/json", entry, entry->conn->fd, entry->rt->ptv, entry->rt->ev_base);
	entry->is_reply = TRUE;
}

static void
rspamd_webui_send_string (struct rspamd_http_connection_entry *entry, const gchar *str)
{
	struct rspamd_http_message *msg;

	msg = rspamd_http_new_message (HTTP_RESPONSE);
	msg->date = time (NULL);
	msg->code = 200;
	msg->body = g_string_new (str);
	rspamd_http_connection_reset (entry->conn);
	rspamd_http_connection_write_message (entry->conn, msg, NULL,
			"application/json", entry, entry->conn->fd, entry->rt->ptv, entry->rt->ev_base);
	entry->is_reply = TRUE;
}

static void
rspamd_webui_send_ucl (struct rspamd_http_connection_entry *entry, ucl_object_t *obj)
{
	struct rspamd_http_message *msg;

	msg = rspamd_http_new_message (HTTP_RESPONSE);
	msg->date = time (NULL);
	msg->code = 200;
	msg->body = g_string_sized_new (BUFSIZ);
	rspamd_ucl_emit_gstring (obj, UCL_EMIT_JSON_COMPACT, msg->body);
	rspamd_http_connection_reset (entry->conn);
	rspamd_http_connection_write_message (entry->conn, msg, NULL,
			"application/json", entry, entry->conn->fd, entry->rt->ptv, entry->rt->ev_base);
	entry->is_reply = TRUE;
}

/* Check for password if it is required by configuration */
static gboolean
rspamd_webui_check_password (struct rspamd_http_connection_entry *entry,
		struct rspamd_webui_session *session, struct rspamd_http_message *msg)
{
	const gchar								*password;
	struct rspamd_webui_worker_ctx			*ctx = session->ctx;

	if (!session->from_addr.has_addr) {
		msg_info ("allow unauthorized connection from a unix socket");
		return TRUE;
	}
	else if (ctx->secure_map && !session->from_addr.ipv6) {
		if (radix32tree_find (ctx->secure_map,
				ntohl (session->from_addr.d.in4.s_addr)) != RADIX_NO_VALUE) {
			msg_info ("allow unauthorized connection from a trusted IP %s",
					inet_ntoa (session->from_addr.d.in4));
			return TRUE;
		}
	}
	if (ctx->password) {
		password = rspamd_http_message_find_header (msg, "Password");
		if (password == NULL || strcmp (password, ctx->password) != 0) {
			msg_info ("incorrect or absent password was specified");
			rspamd_webui_send_error (entry, 403, "Unauthorized");
			return FALSE;
		}
	}
	else if (ctx->secure_map) {
		msg_info ("deny unauthorized connection");
		return FALSE;
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

#if 0
/*
 * Write metric result in json format
 */
static void
rspamd_webui_scan_metric_symbols_callback (gpointer key, gpointer value, gpointer ud)
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
rspamd_webui_scan_task_free (gpointer arg)
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
					mres->score >= mres->metric->actions[METRIC_ACTION_REJECT].score ? "true" : "false",
					cbdata->task->is_skipped ? "true" : "false", mres->score,
					mres->metric->actions[METRIC_ACTION_REJECT].score,
					str_action_metric (
							check_metric_action (mres->score, mres->metric->actions[METRIC_ACTION_REJECT].score, mres->metric)));
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
rspamd_webui_scan_task_event_helper (int fd, short what, gpointer arg)
{
	struct scan_callback_data				*cbdata = arg;

	destroy_session (cbdata->task->s);
}

/*
 * Called if all filters are processed, non-threaded and simple version
 */
static gboolean
rspamd_webui_scan_task_fin (gpointer arg)
{
	struct scan_callback_data				*cbdata = arg;
	static struct timeval					 tv = {.tv_sec = 0, .tv_usec = 0 };
#if 0
	if (cbdata->task->state != WRITING_REPLY) {
		process_statfiles (cbdata->task);
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
#endif
	return TRUE;
}

/*
 * Called if session was restored inside fin callback
 */
static void
rspamd_webui_scan_task_restore (gpointer arg)
{
	struct scan_callback_data				*cbdata = arg;

	/* Special state */
#if 0
	cbdata->task->state = WRITING_REPLY;
#endif
}

/* Prepare callback data for scan */
static struct scan_callback_data*
rspamd_webui_prepare_scan (struct evhttp_request *req, struct rspamd_webui_worker_ctx *ctx, struct evbuffer *in, GError **err)
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

	task->msg = g_string_new_len (EVBUFFER_DATA (in), EVBUFFER_LENGTH (in));

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
rspamd_webui_learn_task_free (gpointer arg)
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
rspamd_webui_learn_task_event_helper (int fd, short what, gpointer arg)
{
	struct learn_callback_data				*cbdata = arg;

	destroy_session (cbdata->task->s);
}

/*
 * Called if all filters are processed, non-threaded and simple version
 */
static gboolean
rspamd_webui_learn_task_fin (gpointer arg)
{
	struct learn_callback_data				*cbdata = arg;
	static struct timeval					 tv = {.tv_sec = 0, .tv_usec = 0 };
#if 0
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
#endif
	return TRUE;
}

/*
 * Called if session was restored inside fin callback
 */
static void
rspamd_webui_learn_task_restore (gpointer arg)
{
	struct learn_callback_data				*cbdata = arg;
#if 0
	/* Special state */
	cbdata->task->state = WRITING_REPLY;
#endif
}

/* Prepare callback data for learn */
static struct learn_callback_data*
rspamd_webui_prepare_learn (struct evhttp_request *req, struct rspamd_webui_worker_ctx *ctx, struct evbuffer *in, gboolean is_spam, GError **err)
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

	task->msg = g_string_new_len (EVBUFFER_DATA (in), EVBUFFER_LENGTH (in));

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
#endif


/* Command handlers */

/*
 * Auth command handler:
 * request: /auth
 * headers: Password
 * reply: json {"auth": "ok", "version": "0.5.2", "uptime": "some uptime", "error": "none"}
 */
static int
rspamd_webui_handle_auth (struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg)
{
	struct rspamd_webui_session 			*session = conn_ent->ud;
	struct rspamd_stat						*st;
	int64_t									 uptime;
	gulong									 data[4];
	ucl_object_t							*obj;

	if (!rspamd_webui_check_password (conn_ent, session, msg)) {
		return 0;
	}

	obj = ucl_object_typed_new (UCL_OBJECT);
	st = session->ctx->srv->stat;
	data[0] = st->actions_stat[METRIC_ACTION_NOACTION];
	data[1] = st->actions_stat[METRIC_ACTION_ADD_HEADER] + st->actions_stat[METRIC_ACTION_REWRITE_SUBJECT];
	data[2] = st->actions_stat[METRIC_ACTION_GREYLIST];
	data[3] = st->actions_stat[METRIC_ACTION_REJECT];

	/* Get uptime */
	uptime = time (NULL) - session->ctx->start_time;

	ucl_object_insert_key (obj, ucl_object_fromstring (RVERSION), "version", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromstring ("ok"), "auth", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromint (uptime), "uptime", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromint (data[0]), "clean", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromint (data[1]), "probable", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromint (data[2]), "greylist", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromint (data[3]), "reject", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromint (st->messages_scanned), "scanned", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromint (st->messages_learned), "learned", 0, false);

	rspamd_webui_send_ucl (conn_ent, obj);
	ucl_object_unref (obj);

	return 0;
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
static int
rspamd_webui_handle_symbols (struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg)
{
	struct rspamd_webui_session 			*session = conn_ent->ud;
	GList									*cur_gr, *cur_sym;
	struct symbols_group					*gr;
	struct symbol_def						*sym;
	ucl_object_t							*obj, *top, *sym_obj;

	if (!rspamd_webui_check_password (conn_ent, session, msg)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);

	/* Go through all symbols groups */
	cur_gr = session->ctx->cfg->symbols_groups;
	while (cur_gr) {
		gr = cur_gr->data;
		obj = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (obj, ucl_object_fromstring (gr->name), "group", 0, false);
		/* Iterate through all symbols */
		cur_sym = gr->symbols;
		while (cur_sym) {
			sym_obj = ucl_object_typed_new (UCL_OBJECT);
			sym = cur_sym->data;

			ucl_object_insert_key (sym_obj, ucl_object_fromstring (sym->name),
					"symbol", 0, false);
			ucl_object_insert_key (sym_obj, ucl_object_fromdouble (*sym->weight_ptr),
					"weight", 0, false);
			if (sym->description) {
				ucl_object_insert_key (sym_obj, ucl_object_fromstring (sym->description),
					"description", 0, false);
			}

			ucl_object_insert_key (obj, sym_obj, "rules", 0, false);
			cur_sym = g_list_next (cur_sym);
		}
		cur_gr = g_list_next (cur_gr);
		ucl_array_append (top, obj);
	}

	rspamd_webui_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
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
static int
rspamd_webui_handle_actions (struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg)
{
	struct rspamd_webui_session 			*session = conn_ent->ud;
	struct metric							*metric;
	struct metric_action					*act;
	gint									 i;
	ucl_object_t							*obj, *top;

	if (!rspamd_webui_check_password (conn_ent, session, msg)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);

	/* Get actions for default metric */
	metric = g_hash_table_lookup (session->ctx->cfg->metrics, DEFAULT_METRIC);
	if (metric != NULL) {
		for (i = METRIC_ACTION_REJECT; i < METRIC_ACTION_MAX; i ++) {
			act = &metric->actions[i];
			if (act->score > 0) {
				obj = ucl_object_typed_new (UCL_OBJECT);
				ucl_object_insert_key (obj,
						ucl_object_fromstring (str_action_metric (act->action)), "action", 0, false);
				ucl_object_insert_key (obj, ucl_object_fromdouble (act->score), "value", 0, false);
				ucl_array_append (top, obj);
			}
		}
	}

	rspamd_webui_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
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
static int
rspamd_webui_handle_maps (struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg)
{
	struct rspamd_webui_session 			*session = conn_ent->ud;
	GList									*cur, *tmp = NULL;
	struct rspamd_map						*map;
	gboolean								 editable;
	ucl_object_t							*obj, *top;


	if (!rspamd_webui_check_password (conn_ent, session, msg)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);
	/* Iterate over all maps */
	cur = session->ctx->cfg->maps;
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
		editable = (access (map->uri, W_OK) == 0);

		obj = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (obj, ucl_object_fromint (map->id),
				"map", 0, false);
		ucl_object_insert_key (obj, ucl_object_fromstring (map->description),
				"description", 0, false);
		ucl_object_insert_key (obj, ucl_object_frombool (editable),
				"editable", 0, false);
		ucl_array_append (top, obj);

		cur = g_list_next (cur);
	}

	if (tmp) {
		g_list_free (tmp);
	}

	rspamd_webui_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

/*
 * Get map command handler:
 * request: /getmap
 * headers: Password, Map
 * reply: plain-text
 */
static int
rspamd_webui_handle_get_map (struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg)
{
	struct rspamd_webui_session 			*session = conn_ent->ud;
	GList									*cur;
	struct rspamd_map						*map;
	const gchar								*idstr;
	gchar									*errstr;
	struct stat								 st;
	gint									 fd;
	guint32									 id;
	gboolean								 found = FALSE;
	struct rspamd_http_message				*reply;


	if (!rspamd_webui_check_password (conn_ent, session, msg)) {
		return 0;
	}


	idstr = rspamd_http_message_find_header (msg, "Map");

	if (idstr == NULL) {
		msg_info ("absent map id");
		rspamd_webui_send_error (conn_ent, 400, "400 id header missing");
		return 0;
	}

	id = strtoul (idstr, &errstr, 10);
	if (*errstr != '\0') {
		msg_info ("invalid map id");
		rspamd_webui_send_error (conn_ent, 400, "400 invalid map id");
		return 0;
	}

	/* Now let's be sure that we have map defined in configuration */
	cur = session->ctx->cfg->maps;
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
		rspamd_webui_send_error (conn_ent, 404, "404 map not found");
		return 0;
	}

	if (stat (map->uri, &st) == -1 || (fd = open (map->uri, O_RDONLY)) == -1) {
		msg_err ("cannot open map %s: %s", map->uri, strerror (errno));
		rspamd_webui_send_error (conn_ent, 500, "500 map open error");
		return 0;
	}

	reply = rspamd_http_new_message (HTTP_RESPONSE);
	reply->date = time (NULL);
	reply->code = 200;
	reply->body = g_string_sized_new (st.st_size);

	/* Read the whole buffer */
	if (read (fd, msg->body->str, st.st_size) == -1) {
		rspamd_http_message_free (reply);
		msg_err ("cannot read map %s: %s", map->uri, strerror (errno));
		rspamd_webui_send_error (conn_ent, 500, "500 map read error");
		return 0;
	}

	reply->body->len = st.st_size;
	reply->body->str[reply->body->len] = '\0';

	close (fd);

	rspamd_http_connection_reset (conn_ent->conn);
	rspamd_http_connection_write_message (conn_ent->conn, reply, NULL,
			"text/plain", conn_ent, conn_ent->conn->fd,
			conn_ent->rt->ptv, conn_ent->rt->ev_base);
	conn_ent->is_reply = TRUE;

	return 0;
}

#if 0
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
rspamd_webui_handle_graph (struct evhttp_request *req, gpointer arg)
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
#endif
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
static int
rspamd_webui_handle_pie_chart (struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg)
{
	struct rspamd_webui_session 			*session = conn_ent->ud;
	struct rspamd_webui_worker_ctx			*ctx;
	gdouble									 data[4], total;
	ucl_object_t							*top, *obj;

	ctx = session->ctx;

	if (!rspamd_webui_check_password (conn_ent, session, msg)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);
	total = ctx->srv->stat->messages_scanned;
	if (total != 0) {
		obj = ucl_object_typed_new (UCL_ARRAY);

		data[0] = ctx->srv->stat->actions_stat[METRIC_ACTION_NOACTION] / total * 100.;
		data[1] = (ctx->srv->stat->actions_stat[METRIC_ACTION_ADD_HEADER] +
				ctx->srv->stat->actions_stat[METRIC_ACTION_REWRITE_SUBJECT]) / total * 100.;
		data[2] = ctx->srv->stat->actions_stat[METRIC_ACTION_GREYLIST] / total * 100.;
		data[3] = ctx->srv->stat->actions_stat[METRIC_ACTION_REJECT] / total * 100.;

		ucl_array_append (obj, ucl_object_fromstring ("Clean messages"));
		ucl_array_append (obj, ucl_object_fromdouble (data[0]));
		ucl_array_append (top, obj);
		ucl_array_append (obj, ucl_object_fromstring ("Probable spam messages"));
		ucl_array_append (obj, ucl_object_fromdouble (data[1]));
		ucl_array_append (top, obj);
		ucl_array_append (obj, ucl_object_fromstring ("Greylisted messages"));
		ucl_array_append (obj, ucl_object_fromdouble (data[2]));
		ucl_array_append (top, obj);
		ucl_array_append (obj, ucl_object_fromstring ("Rejected messages"));
		ucl_array_append (obj, ucl_object_fromdouble (data[3]));
		ucl_array_append (top, obj);
	}
	else {
		obj = ucl_object_typed_new (UCL_ARRAY);

		ucl_array_append (obj, ucl_object_fromstring ("Scanned messages"));
		ucl_array_append (obj, ucl_object_fromdouble (0));
		ucl_array_append (top, obj);
	}

	rspamd_webui_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
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
static int
rspamd_webui_handle_history (struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg)
{
	struct rspamd_webui_session 			*session = conn_ent->ud;
	struct rspamd_webui_worker_ctx			*ctx;
	struct roll_history_row					*row;
	struct roll_history						 copied_history;
	gint									 i, rows_proc, row_num;
	struct tm								*tm;
	gchar									 timebuf[32];
	gchar									 ip_buf[INET6_ADDRSTRLEN];
	ucl_object_t							*top, *obj;

	ctx = session->ctx;

	if (!rspamd_webui_check_password (conn_ent, session, msg)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);

	/* Set lock on history */
	memory_pool_lock_mutex (ctx->srv->history->mtx);
	ctx->srv->history->need_lock = TRUE;
	/* Copy locked */
	memcpy (&copied_history, ctx->srv->history, sizeof (copied_history));
	memory_pool_unlock_mutex (ctx->srv->history->mtx);

	/* Go through all rows */
	row_num = copied_history.cur_row;
	for (i = 0, rows_proc = 0; i < HISTORY_MAX_ROWS; i ++, row_num ++) {
		if (row_num == HISTORY_MAX_ROWS) {
			row_num = 0;
		}
		row = &copied_history.rows[row_num];
		/* Get only completed rows */
		if (row->completed) {
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
			obj = ucl_object_typed_new (UCL_OBJECT);
			ucl_object_insert_key (obj, ucl_object_fromstring (timebuf), "time", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromstring (row->message_id), "id", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromstring (ip_buf), "ip", 0, false);
			ucl_object_insert_key (obj,
					ucl_object_fromstring (str_action_metric (row->action)), "action", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromdouble (row->score), "score", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromdouble (row->required_score), "required_score", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromstring (row->symbols), "symbols", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromint (row->len), "size", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromint (row->scan_time), "scan_time", 0, false);
			if (row->user[0] != '\0') {
				ucl_object_insert_key (obj, ucl_object_fromstring (row->user), "user", 0, false);
			}
			ucl_array_append (top, obj);
			rows_proc ++;
		}
	}

	rspamd_webui_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

static gboolean
rspamd_webui_learn_fin_task (void *ud)
{
	struct worker_task						*task = ud;
	struct rspamd_webui_session 			*session;
	struct rspamd_http_connection_entry		*conn_ent;
	GError									*err = NULL;

	conn_ent = task->fin_arg;
	session = conn_ent->ud;

	if (!learn_task_spam (session->cl, task, session->is_spam, &err)) {
		rspamd_webui_send_error (conn_ent, 500 + err->code, err->message);
		return TRUE;
	}
	/* Successful learn */
	rspamd_webui_send_string (conn_ent, "{\"success\":true}");

	return TRUE;
}

static int
rspamd_webui_handle_learn_common (struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg, gboolean is_spam)
{
	struct rspamd_webui_session 			*session = conn_ent->ud;
	struct rspamd_webui_worker_ctx			*ctx;
	struct classifier_config				*cl;
	struct worker_task						*task;
	const gchar								*classifier;

	ctx = session->ctx;

	if (!rspamd_webui_check_password (conn_ent, session, msg)) {
		return 0;
	}

	if (msg->body->len == 0) {
		msg_err ("got zero length body, cannot continue");
		rspamd_webui_send_error (conn_ent, 400, "Empty body is not permitted");
		return 0;
	}

	if ((classifier = rspamd_http_message_find_header (msg, "Classifier")) == NULL) {
		classifier = "bayes";
	}

	cl = find_classifier_conf (ctx->cfg, classifier);
	if (cl == NULL) {
		rspamd_webui_send_error (conn_ent, 400, "Classifier not found");
		return 0;
	}

	task = construct_task (session->ctx->worker);
	task->ev_base = session->ctx->ev_base;
	task->msg = msg->body;

	task->resolver = ctx->resolver;
	task->ev_base = ctx->ev_base;

	task->s = new_async_session (session->pool, rspamd_webui_learn_fin_task, NULL,
			free_task_hard, task);
	task->s->wanna_die = TRUE;
	task->fin_arg = conn_ent;

	if (process_message (task) == -1) {
		msg_warn ("processing of message failed");
		destroy_session (task->s);
		rspamd_webui_send_error (conn_ent, 500, "Message cannot be processed");
		return 0;
	}

	if (process_filters (task) == -1) {
		msg_warn ("filters cannot be processed for %s", task->message_id);
		destroy_session (task->s);
		rspamd_webui_send_error (conn_ent, 500, "Filters cannot be processed");
		return 0;
	}

	session->task = task;
	session->cl = cl;
	session->is_spam = is_spam;

	return 0;
}

/*
 * Learn spam command handler:
 * request: /learnspam
 * headers: Password
 * input: plaintext data
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_webui_handle_learnspam (struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg)
{
	return rspamd_webui_handle_learn_common (conn_ent, msg, TRUE);
}
/*
 * Learn ham command handler:
 * request: /learnham
 * headers: Password
 * input: plaintext data
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_webui_handle_learnham (struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg)
{
	return rspamd_webui_handle_learn_common (conn_ent, msg, TRUE);
}

/*
 * Save actions command handler:
 * request: /saveactions
 * headers: Password
 * input: json array [<spam>,<probable spam>,<greylist>]
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_webui_handle_saveactions (struct rspamd_http_connection_entry *conn_ent,
		struct rspamd_http_message *msg)
{
	struct rspamd_webui_session 			*session = conn_ent->ud;
	struct ucl_parser						*parser;
	struct metric							*metric;
	ucl_object_t							*obj, *cur;
	struct rspamd_webui_worker_ctx 			*ctx;
	const gchar								*error;
	gint64									 score;
	gint									 i;
	enum rspamd_metric_action				 act;

	ctx = session->ctx;

	if (!rspamd_webui_check_password (conn_ent, session, msg)) {
		return 0;
	}

	if (msg->body->len == 0) {
		msg_err ("got zero length body, cannot continue");
		rspamd_webui_send_error (conn_ent, 400, "Empty body is not permitted");
		return 0;
	}

	metric = g_hash_table_lookup (ctx->cfg->metrics, DEFAULT_METRIC);
	if (metric == NULL) {
		msg_err ("cannot find default metric");
		rspamd_webui_send_error (conn_ent, 500, "Default metric is absent");
		return 0;
	}

	/* Now check for dynamic config */
	if (!ctx->cfg->dynamic_conf) {
		msg_err ("dynamic conf has not been defined");
		rspamd_webui_send_error (conn_ent, 500, "No dynamic_rules setting defined");
		return 0;
	}

	parser = ucl_parser_new (0);
	ucl_parser_add_chunk (parser, msg->body->str, msg->body->len);

	if ((error = ucl_parser_get_error (parser)) != NULL) {
		msg_err ("cannot parse input: %s", error);
		rspamd_webui_send_error (conn_ent, 400, "Cannot parse input");
		ucl_parser_free (parser);
		return 0;
	}

	obj = ucl_parser_get_object (parser);
	ucl_parser_free (parser);

	if (obj->type != UCL_ARRAY || obj->len != 3) {
		msg_err ("input is not an array of 3 elements");
		rspamd_webui_send_error (conn_ent, 400, "Cannot parse input");
		ucl_object_unref (obj);
		return 0;
	}

	cur = obj->value.av;
	for (i = 0; i < 3 && cur != NULL; i ++, cur = cur->next) {
		switch(i) {
		case 0:
			act = METRIC_ACTION_REJECT;
			break;
		case 1:
			act = METRIC_ACTION_ADD_HEADER;
			break;
		case 2:
			act = METRIC_ACTION_GREYLIST;
			break;
		}
		score = ucl_object_toint (cur);
		if (metric->actions[act].score != score) {
			add_dynamic_action (ctx->cfg, DEFAULT_METRIC, act, score);
		}
	}

	dump_dynamic_config (ctx->cfg);

	rspamd_webui_send_string (conn_ent, "{\"success\":true}");

	return 0;
}

#if 0

/*
 * Save symbols command handler:
 * request: /savesymbols
 * headers: Password
 * input: json data
 * reply: json {"success":true} or {"error":"error message"}
 */
static void
rspamd_webui_handle_save_symbols (struct evhttp_request *req, gpointer arg)
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
rspamd_webui_handle_save_map (struct evhttp_request *req, gpointer arg)
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
rspamd_webui_handle_scan (struct evhttp_request *req, gpointer arg)
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

#endif

static void
rspamd_webui_error_handler (struct rspamd_http_connection_entry *conn_ent, GError *err)
{
	msg_err ("http error occurred: %s", err->message);
}

static void
rspamd_webui_finish_handler (struct rspamd_http_connection_entry *conn_ent)
{
	struct rspamd_webui_session 		*session = conn_ent->ud;

	if (session->pool) {
		memory_pool_delete (session->pool);
	}
	if (session->task != NULL) {
		destroy_session (session->task->s);
	}

	g_slice_free1 (sizeof (struct rspamd_webui_session), session);
}

static void
rspamd_webui_accept_socket (gint fd, short what, void *arg)
{
	struct rspamd_worker				*worker = (struct rspamd_worker *) arg;
	struct rspamd_webui_worker_ctx		*ctx;
	struct rspamd_webui_session			*nsession;
	gint								 nfd;
	union sa_union						 su;
	socklen_t							 addrlen = sizeof (su);
	char								 ip_str[INET6_ADDRSTRLEN + 1];

	ctx = worker->ctx;

	if ((nfd =
			accept_from_socket (fd, &su.sa, &addrlen)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0){
		return;
	}

	nsession = g_slice_alloc0 (sizeof (struct rspamd_webui_session));
	nsession->pool = memory_pool_new (memory_pool_get_size ());
	nsession->ctx = ctx;

	if (su.sa.sa_family == AF_UNIX) {
		msg_info ("accepted connection from unix socket");
		nsession->from_addr.has_addr = FALSE;
	}
	else if (su.sa.sa_family == AF_INET) {
		msg_info ("accepted connection from %s port %d",
				inet_ntoa (su.s4.sin_addr), ntohs (su.s4.sin_port));
		nsession->from_addr.has_addr = TRUE;
		nsession->from_addr.d.in4.s_addr = su.s4.sin_addr.s_addr;
	}
	else if (su.sa.sa_family == AF_INET6) {
		msg_info ("accepted connection from %s port %d",
				inet_ntop (su.sa.sa_family, &su.s6.sin6_addr, ip_str, sizeof (ip_str)),
				ntohs (su.s6.sin6_port));
		memcpy (&nsession->from_addr.d.in6, &su.s6.sin6_addr,
				sizeof (struct in6_addr));
		nsession->from_addr.has_addr = TRUE;
		nsession->from_addr.ipv6 = TRUE;
	}

	rspamd_http_router_handle_socket (ctx->http, nfd, nsession);
}

gpointer
init_webui_worker (struct config_file *cfg)
{
	struct rspamd_webui_worker_ctx		*ctx;
	GQuark								type;

	type = g_quark_try_string ("webui");

	ctx = g_malloc0 (sizeof (struct rspamd_webui_worker_ctx));

	ctx->timeout = DEFAULT_WORKER_IO_TIMEOUT;

	rspamd_rcl_register_worker_option (cfg, type, "password",
			rspamd_rcl_parse_struct_string, ctx,
			G_STRUCT_OFFSET (struct rspamd_webui_worker_ctx, password), 0);

	rspamd_rcl_register_worker_option (cfg, type, "ssl",
			rspamd_rcl_parse_struct_boolean, ctx,
			G_STRUCT_OFFSET (struct rspamd_webui_worker_ctx, use_ssl), 0);

	rspamd_rcl_register_worker_option (cfg, type, "ssl_cert",
			rspamd_rcl_parse_struct_string, ctx,
			G_STRUCT_OFFSET (struct rspamd_webui_worker_ctx, ssl_cert), 0);

	rspamd_rcl_register_worker_option (cfg, type, "ssl_key",
			rspamd_rcl_parse_struct_string, ctx,
			G_STRUCT_OFFSET (struct rspamd_webui_worker_ctx, ssl_key), 0);
	rspamd_rcl_register_worker_option (cfg, type, "timeout",
			rspamd_rcl_parse_struct_time, ctx,
			G_STRUCT_OFFSET (struct rspamd_webui_worker_ctx, timeout), RSPAMD_CL_FLAG_TIME_INTEGER);

	rspamd_rcl_register_worker_option (cfg, type, "secure_ip",
			rspamd_rcl_parse_struct_string, ctx,
			G_STRUCT_OFFSET (struct rspamd_webui_worker_ctx, secure_ip), 0);

	rspamd_rcl_register_worker_option (cfg, type, "static_dir",
			rspamd_rcl_parse_struct_string, ctx,
			G_STRUCT_OFFSET (struct rspamd_webui_worker_ctx, static_files_dir), 0);

	return ctx;
}

/*
 * Start worker process
 */
void
start_webui_worker (struct rspamd_worker *worker)
{
	struct rspamd_webui_worker_ctx *ctx = worker->ctx;

	ctx->ev_base = prepare_worker (worker, "controller", sig_handler, rspamd_webui_accept_socket);
	msec_to_tv (ctx->timeout, &ctx->io_tv);

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
	ctx->cfg = worker->srv->cfg;
	ctx->srv = worker->srv;
	if (ctx->secure_ip != NULL) {
		if (!add_map (worker->srv->cfg, ctx->secure_ip, "Allow webui access from the specified IP",
				read_radix_list, fin_radix_list, (void **)&ctx->secure_map)) {
			if (!rspamd_parse_ip_list (ctx->secure_ip, &ctx->secure_map)) {
				msg_warn ("cannot load or parse ip list from '%s'", ctx->secure_ip);
			}
		}
	}
	/* Accept event */
	ctx->http = rspamd_http_router_new (rspamd_webui_error_handler,
			rspamd_webui_finish_handler, &ctx->io_tv, ctx->ev_base,
			ctx->static_files_dir);

	/* Add callbacks for different methods */
	rspamd_http_router_add_path (ctx->http, PATH_AUTH, rspamd_webui_handle_auth);
	rspamd_http_router_add_path (ctx->http, PATH_SYMBOLS, rspamd_webui_handle_symbols);
	rspamd_http_router_add_path (ctx->http, PATH_ACTIONS, rspamd_webui_handle_actions);
	rspamd_http_router_add_path (ctx->http, PATH_MAPS, rspamd_webui_handle_maps);
	rspamd_http_router_add_path (ctx->http, PATH_GET_MAP, rspamd_webui_handle_get_map);
	rspamd_http_router_add_path (ctx->http, PATH_PIE_CHART, rspamd_webui_handle_pie_chart);
	rspamd_http_router_add_path (ctx->http, PATH_HISTORY, rspamd_webui_handle_history);
	rspamd_http_router_add_path (ctx->http, PATH_LEARN_SPAM, rspamd_webui_handle_learnspam);
	rspamd_http_router_add_path (ctx->http, PATH_LEARN_HAM, rspamd_webui_handle_learnham);
	rspamd_http_router_add_path (ctx->http, PATH_SAVE_ACTIONS, rspamd_webui_handle_saveactions);
#if 0
	rspamd_http_router_add_path (ctx->http, PATH_GRAPH, rspamd_webui_handle_graph, ctx);

	rspamd_http_router_add_path (ctx->http, PATH_SAVE_SYMBOLS, rspamd_webui_handle_save_symbols, ctx);
	rspamd_http_router_add_path (ctx->http, PATH_SAVE_MAP, rspamd_webui_handle_save_map, ctx);
	rspamd_http_router_add_path (ctx->http, PATH_SCAN, rspamd_webui_handle_scan, ctx);
#endif

	ctx->resolver = dns_resolver_init (worker->srv->logger, ctx->ev_base, worker->srv->cfg);

	/* Maps events */
	start_map_watch (worker->srv->cfg, ctx->ev_base);

	event_base_loop (ctx->ev_base, 0);

	g_mime_shutdown ();
	close_log (rspamd_main->logger);
	exit (EXIT_SUCCESS);
}
