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
#define PATH_MAPS "/maps"
#define PATH_GET_MAP "/getmap"
#define PATH_GRAPH "/graph"

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
	struct evbuffer							*evb;
	const gchar								*password;
	gchar									*auth = "ok", *error = "none", uptime_buf[128];
	time_t									 uptime, days, hours, minutes;

	evb = evbuffer_new ();
	if (!evb) {
		msg_err ("cannot allocate evbuffer for reply");
		evhttp_send_reply (req, HTTP_INTERNAL, "500 insufficient memory", NULL);
		return;
	}

	if (ctx->password) {
		password = evhttp_find_header (req->input_headers, "Password");
		if (password == NULL || strcmp (password, ctx->password) != 0) {
			auth = "failed";
			error = "unauthorized";
		}
	}
	/* Print uptime */
	uptime = time (NULL) - ctx->start_time;
	/* If uptime more than 2 hours, print as a number of days. */
	if (uptime >= 2 * 3600) {
		days = uptime / 86400;
		hours = uptime / 3600 - days * 24;
		minutes = uptime / 60 - hours * 60 - days * 1440;
		rspamd_snprintf (uptime_buf, sizeof (uptime_buf), "%d day%s %d hour%s %d minute%s", days, days != 1 ? "s" : " ", hours, hours != 1 ? "s" : " ", minutes, minutes != 1 ? "s" : " ");
	}
	/* If uptime is less than 1 minute print only seconds */
	else if (uptime / 60 == 0) {
		rspamd_snprintf (uptime_buf, sizeof (uptime_buf), "%d second%s", (gint)uptime, (gint)uptime != 1 ? "s" : " ");
	}
	/* Else print the minutes and seconds. */
	else {
		hours = uptime / 3600;
		minutes = uptime / 60 - hours * 60;
		uptime -= hours * 3600 + minutes * 60;
		rspamd_snprintf (uptime_buf, sizeof (uptime_buf), "%d hour%s %d minute%s %d second%s", hours, hours != 1 ? "s" : " ", minutes, minutes != 1 ? "s" : " ", (gint)uptime, uptime != 1 ? "s" : " ");
	}

	evbuffer_add_printf (evb, "{\"auth\": \"%s\", \"version\": \"%s\", \"uptime\": \"%s\", \"error\": \"%s\"}" CRLF,
			auth, RVERSION, uptime_buf, error);
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
				evbuffer_add_printf (evb, "{\"symbol\":\"%s\",\"weight\":%.2f,\"description\":\"%s\"%s", sym->name, sym->weight,
						sym->description, g_list_next (cur_sym) ? "}," : "}");
			}
			else {
				evbuffer_add_printf (evb, "{\"symbol\":\"%s\",\"weight\":%.2f%s", sym->name, sym->weight,
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
	GList									*cur;
	struct rspamd_map						*map, *next;
	gboolean								 editable;
	gchar									*comma;

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
				editable = access (map->uri, W_OK) == 0;
				if (cur->next) {
					next = cur->next->data;
					if (next->protocol == MAP_PROTO_FILE && next->description != NULL &&
							access (next->uri, R_OK) == 0) {
						comma = "},";
					}
					else {
						comma = "}";
					}
				}
				else {
					comma = "}";
				}
				evbuffer_add_printf (evb, "{\"map\":%u,\"description\":\"%s\",\"editable\":%s%s",
						map->id, map->description, editable ? "true" : "false",
						comma);
			}
		}
		cur = g_list_next (cur);
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

	evb = evbuffer_new ();
	if (!evb) {
		msg_err ("cannot allocate evbuffer for reply");
		evhttp_send_reply (req, HTTP_INTERNAL, "500 insufficient memory", NULL);
		return;
	}

	/* Trailer */
	evbuffer_add_printf (evb, "{\"series\": [");

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
	evbuffer_add_printf (evb, "{\"label\": \"Clean messages\", \"lines\": {\"fill\": false}, \"data\":[");
	for (i = 0; i < 100; i ++, t += 60) {
		evbuffer_add_printf (evb, "[%llu,%.2f%s", (long long unsigned)t * 1000, vals[0][i], i == 99 ? "]" : "],");
	}
	evbuffer_add (evb, "]},", 3);

	/* Probable spam label */
	t = now - 6000;
	evbuffer_add_printf (evb, "{\"label\": \"Probable spam messages\", \"lines\": {\"fill\": false}, \"data\":[");
	for (i = 0; i < 100; i ++, t += 60) {
		evbuffer_add_printf (evb, "[%llu,%.2f%s", (long long unsigned)t * 1000, vals[1][i], i == 99 ? "]" : "],");
	}
	evbuffer_add (evb, "]},", 3);

	/* Greylist label */
	t = now - 6000;
	evbuffer_add_printf (evb, "{\"label\": \"Greylisted messages\", \"lines\": {\"fill\": false}, \"data\":[");
	for (i = 0; i < 100; i ++, t += 60) {
		evbuffer_add_printf (evb, "[%llu,%.2f%s", (long long unsigned)t * 1000, vals[2][i], i == 99 ? "]" : "],");
	}
	evbuffer_add (evb, "]},", 3);

	/* Reject label */
	t = now - 6000;
	evbuffer_add_printf (evb, "{\"label\": \"Rejected messages\", \"lines\": {\"fill\": false}, \"data\":[");
	for (i = 0; i < 100; i ++, t += 60) {
		evbuffer_add_printf (evb, "[%llu,%.2f%s", (long long unsigned)t * 1000, vals[3][i], i == 99 ? "]" : "],");
	}
	evbuffer_add (evb, "]},", 3);

	/* Total label */
	t = now - 6000;
	evbuffer_add_printf (evb, "{\"label\": \"Total messages\", \"lines\": {\"fill\": false}, \"data\":[");
	for (i = 0; i < 100; i ++, t += 60) {
		evbuffer_add_printf (evb, "[%llu,%.2f%s", (long long unsigned)t * 1000, vals[4][i], i == 99 ? "]" : "],");
	}
	evbuffer_add (evb, "]},", 2);

	evbuffer_add_printf (evb, "],\"colors\":[\"" COLOR_CLEAN "\", \"" COLOR_PROBABLE_SPAM "\", \""
			COLOR_GREYLIST "\", \"" COLOR_REJECT "\", \"" COLOR_TOTAL "\"]}" CRLF);
	evhttp_add_header (req->output_headers, "Connection", "close");
	http_calculate_content_length (evb, req);

	evhttp_send_reply (req, HTTP_OK, "OK", evb);
	evbuffer_free (evb);
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
	evhttp_set_cb (ctx->http, PATH_MAPS, http_handle_maps, ctx);
	evhttp_set_cb (ctx->http, PATH_GET_MAP, http_handle_get_map, ctx);
	evhttp_set_cb (ctx->http, PATH_GRAPH, http_handle_graph, ctx);

	ctx->resolver = dns_resolver_init (ctx->ev_base, worker->srv->cfg);

	/* Maps events */
	start_map_watch (worker->srv->cfg, ctx->ev_base);

	event_base_loop (ctx->ev_base, 0);

	close_log (rspamd_main->logger);
	exit (EXIT_SUCCESS);
}
