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
#include "main.h"
#include "cfg_file.h"
#include "cfg_xml.h"
#include "util.h"
#include "smtp_proto.h"
#include "map.h"
#include "message.h"
#include "settings.h"
#include "dns.h"
#include "upstream.h"
#include "proxy.h"

/*
 * SMTP proxy is a simple smtp proxy worker for dns resolving and
 * load balancing. It uses XCLIENT command and is designed for MTA
 * that supports that (postfix and exim).
 */

/* Upstream timeouts */
#define DEFAULT_UPSTREAM_ERROR_TIME 10
#define DEFAULT_UPSTREAM_DEAD_TIME 300
#define DEFAULT_UPSTREAM_MAXERRORS 10

#define DEFAULT_PROXY_BUF_LEN 100 * 1024

#define SMTP_MAXERRORS 15

static sig_atomic_t                    wanna_die = 0;

/* Init functions */
gpointer init_smtp_proxy (struct config_file *cfg);
void start_smtp_proxy (struct rspamd_worker *worker);

worker_t smtp_proxy_worker = {
	"smtp_proxy",				/* Name */
	init_smtp_proxy,			/* Init function */
	start_smtp_proxy,			/* Start function */
	TRUE,						/* Has socket */
	FALSE,						/* Non unique */
	FALSE,						/* Non threaded */
	TRUE,						/* Killable */
	SOCK_STREAM					/* TCP socket */
};

struct smtp_proxy_ctx {
	struct smtp_upstream upstreams[MAX_SMTP_UPSTREAMS];
	size_t upstream_num;
	gchar *upstreams_str;

	memory_pool_t *pool;
	guint32 smtp_delay;
	guint32 delay_jitter;
	guint32 smtp_timeout_raw;
	struct timeval smtp_timeout;

	gboolean use_xclient;

	gboolean instant_reject;

	gsize proxy_buf_len;

	struct rspamd_dns_resolver *resolver;
	struct event_base *ev_base;

	GList *rbls;
};

enum rspamd_smtp_proxy_state {
	SMTP_PROXY_STATE_RESOLVE_REVERSE = 0,
	SMTP_PROXY_STATE_RESOLVE_NORMAL,
	SMTP_PROXY_STATE_RESOLVE_RBL,
	SMTP_PROXY_STATE_DELAY,
	SMTP_PROXY_STATE_GREETING,
	SMTP_PROXY_STATE_XCLIENT,
	SMTP_PROXY_STATE_PROXY,
	SMTP_PROXY_STATE_REJECT,
	SMTP_PROXY_STATE_REJECT_EMULATE
};

struct smtp_proxy_session {
	struct smtp_proxy_ctx *ctx;
	memory_pool_t *pool;

	enum rspamd_smtp_proxy_state state;
	struct rspamd_worker *worker;
	struct in_addr client_addr;
	gchar *ptr_str;
	gchar *hostname;
	gchar *error;
	gchar *temp_name;
	gint sock;
	gint upstream_sock;

	struct rspamd_async_session *s;
	rspamd_io_dispatcher_t *dispatcher;

	rspamd_proxy_t *proxy;

	struct smtp_upstream *upstream;

	struct event *delay_timer;
	struct event upstream_ev;

	gboolean resolved;
	struct rspamd_dns_resolver *resolver;
	struct event_base *ev_base;

	GString *upstream_greeting;

	guint rbl_requests;
	gchar *dnsbl_applied;

	gchar *from;
	gchar *rcpt;

	guint errors;
};

#ifndef HAVE_SA_SIGINFO
static void
sig_handler (gint signo)
#else
static void
sig_handler (gint signo, siginfo_t *info, void *unused)
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
 * Config reload is designed by sending sigusr to active workers and pending shutdown of them
 */
static void
sigusr2_handler (gint fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	/* Do not accept new connections, preparing to end worker's process */
	struct timeval                  tv;
	if (! wanna_die) {
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
free_smtp_proxy_session (gpointer arg)
{
	struct smtp_proxy_session            *session = arg;
	static const char fatal_smtp_error[] = "521 5.2.1 Internal error" CRLF;

	if (session) {
		if (session->dispatcher) {
			rspamd_remove_dispatcher (session->dispatcher);
		}

		if (session->upstream_greeting) {
			g_string_free (session->upstream_greeting, TRUE);
		}

		if (session->state != SMTP_PROXY_STATE_PROXY && session->state != SMTP_PROXY_STATE_REJECT &&
				session->state != SMTP_PROXY_STATE_REJECT_EMULATE) {
			/* Send 521 fatal error */
			if (write (session->sock, fatal_smtp_error, sizeof (fatal_smtp_error)) == -1) {
				msg_err ("write error to client failed: %s", strerror (errno));
			}
		}
		else if ((session->state == SMTP_PROXY_STATE_REJECT || session->state == SMTP_PROXY_STATE_REJECT_EMULATE) &&
				session->from && session->rcpt && session->dnsbl_applied) {
			msg_info ("reject by %s mail from <%s> to <%s>, ip: %s", session->dnsbl_applied,
					session->from, session->rcpt, inet_ntoa (session->client_addr));
		}

		close (session->sock);

		if (session->proxy) {
			rspamd_proxy_close (session->proxy);
		}
		if (session->ptr_str) {
			free (session->ptr_str);
		}
		if (session->upstream_sock != -1) {
			event_del (&session->upstream_ev);
			close (session->upstream_sock);
		}
		memory_pool_delete (session->pool);
		g_slice_free1 (sizeof (struct smtp_proxy_session), session);
	}
}

static void
smtp_proxy_err_proxy (GError * err, void *arg)
{
	struct smtp_proxy_session            *session = arg;

	if (err) {
		g_error_free (err);
		msg_info ("abnormally closing connection, error: %s", err->message);
	}
	/* Free buffers */
	session->state = SMTP_PROXY_STATE_REJECT;
	destroy_session (session->s);
}

/**
 * Check whether SMTP greeting is valid
 * @param s
 * @return
 */
static gint
check_valid_smtp_greeting (GString *s)
{
	gchar								*p;

	p = s->str + s->len - 1;
	if (s->len < 6 || (*p != '\n' || *(p - 1) != '\r')) {
		return 1;
	}
	p -= 5;

	while (p >= s->str) {
		/* It is fast to use memcmp here as we compare only 4 bytes */
		if (memcmp (p, "220 ", 4) == 0) {
			/* Check position */
			if (p == s->str || *(p - 1) == '\n') {
				return 1;
			}
			return 0;
		}
		else if ((*p == '5' || *p == '4' || *p == '3') &&
				g_ascii_isdigit (p[1]) && g_ascii_isdigit (p[2]) && p[3] == ' ') {
			return -1;
		}
		p --;
	}

	return 1;
}

/*
 * Handle upstream greeting
 */

static void
smtp_proxy_greeting_handler (gint fd, short what, void *arg)
{
	struct smtp_proxy_session           *session = arg;
	gint								 r;
	gchar								 read_buf[BUFSIZ];

	if (what == EV_READ) {
		if (session->state == SMTP_PROXY_STATE_GREETING) {
			/* Fill greeting buffer with new portion of data */
			r = read (fd, read_buf, sizeof (read_buf) - 1);
			if (r > 0) {
				g_string_append_len (session->upstream_greeting, read_buf, r);
				/* Now search line with 220 */
				r = check_valid_smtp_greeting (session->upstream_greeting);
				if (r == 1) {
					/* Send xclient */
					if (session->ctx->use_xclient) {
						r = rspamd_snprintf (read_buf, sizeof (read_buf), "XCLIENT NAME=%s ADDR=%s" CRLF,
								session->hostname, inet_ntoa (session->client_addr));
						r = write (session->upstream_sock, read_buf, r);

						if (r < 0 && errno == EAGAIN) {
							/* Add write event */
							event_del (&session->upstream_ev);
							event_set (&session->upstream_ev, session->upstream_sock,
									EV_WRITE, smtp_proxy_greeting_handler, session);
							event_base_set (session->ev_base, &session->upstream_ev);
							event_add (&session->upstream_ev, NULL);
						}
						else if (r > 0) {
							session->upstream_greeting->len = 0;
							session->state = SMTP_PROXY_STATE_XCLIENT;
						}
						else {
							msg_info ("connection with %s got write error: %s", inet_ntoa (session->client_addr), strerror (errno));
							destroy_session (session->s);
						}
					}
					else {
						event_del (&session->upstream_ev);
						/* Start direct proxy */
						r = write (session->sock, session->upstream_greeting->str, session->upstream_greeting->len);
						/* TODO: handle client's error here */
						if (r > 0) {
							session->proxy = rspamd_create_proxy (session->sock, session->upstream_sock, session->pool,
								session->ev_base, session->ctx->proxy_buf_len,
								&session->ctx->smtp_timeout, smtp_proxy_err_proxy, session);
							session->state = SMTP_PROXY_STATE_PROXY;
						}
						else {
							msg_info ("connection with %s got write error: %s", inet_ntoa (session->client_addr), strerror (errno));
							destroy_session (session->s);
						}
					}
				}
				else if (r == -1) {
					/* Proxy sent 500 error */
					msg_info ("connection with %s got smtp error for greeting", session->upstream->name);
					destroy_session (session->s);
				}
			}
			else {
				msg_info ("connection with %s got read error: %s", session->upstream->name, strerror (errno));
				destroy_session (session->s);
			}
		}
		else if (session->state == SMTP_PROXY_STATE_XCLIENT) {
			/* Fill greeting buffer with new portion of data */
			r = read (fd, read_buf, sizeof (read_buf) - 1);
			if (r > 0) {
				g_string_append_len (session->upstream_greeting, read_buf, r);
				/* Now search line with 220 */
				r = check_valid_smtp_greeting (session->upstream_greeting);
				if (r == 1) {
					event_del (&session->upstream_ev);
					/* Start direct proxy */
					r = write (session->sock, session->upstream_greeting->str, session->upstream_greeting->len);
					/* TODO: handle client's error here */
					if (r > 0) {
						session->proxy = rspamd_create_proxy (session->sock, session->upstream_sock, session->pool,
								session->ev_base, session->ctx->proxy_buf_len,
								&session->ctx->smtp_timeout, smtp_proxy_err_proxy, session);
						session->state = SMTP_PROXY_STATE_PROXY;
					}
					else {
						msg_info ("connection with %s got write error: %s", inet_ntoa (session->client_addr), strerror (errno));
						destroy_session (session->s);
					}
				}
				else if (r == -1) {
					/* Proxy sent 500 error */
					msg_info ("connection with %s got smtp error for xclient", session->upstream->name);
					destroy_session (session->s);
				}
			}
		}
		else {
			msg_info ("connection with %s got read event at improper state: %d", session->upstream->name, session->state);
			destroy_session (session->s);
		}
	}
	else if (what == EV_WRITE) {
		if (session->state == SMTP_PROXY_STATE_GREETING) {
			/* Send xclient again */
			r = rspamd_snprintf (read_buf, sizeof (read_buf), "XCLIENT NAME=%s ADDR=%s" CRLF,
					session->hostname, inet_ntoa (session->client_addr));
			r = write (session->upstream_sock, read_buf, r);

			if (r < 0 && errno == EAGAIN) {
				/* Add write event */
				event_del (&session->upstream_ev);
				event_set (&session->upstream_ev, session->upstream_sock,
						EV_WRITE, smtp_proxy_greeting_handler, session);
				event_base_set (session->ev_base, &session->upstream_ev);
				event_add (&session->upstream_ev, NULL);
			}
			else if (r > 0) {
				session->upstream_greeting->len = 0;
				session->state = SMTP_PROXY_STATE_XCLIENT;
				event_del (&session->upstream_ev);
				event_set (&session->upstream_ev, session->upstream_sock,
						EV_READ | EV_PERSIST, smtp_proxy_greeting_handler, session);
				event_base_set (session->ev_base, &session->upstream_ev);
				event_add (&session->upstream_ev, NULL);
			}
			else {
				msg_info ("connection with %s got write error: %s", session->upstream->name, strerror (errno));
				destroy_session (session->s);
			}
		}
		else {
			msg_info ("connection with %s got write event at improper state: %d", session->upstream->name, session->state);
			destroy_session (session->s);
		}
	}
	else {
		/* Timeout */
		msg_info ("connection with %s timed out", session->upstream->name);
		destroy_session (session->s);
	}
}

static gboolean
create_smtp_proxy_upstream_connection (struct smtp_proxy_session *session)
{
	struct smtp_upstream              	*selected;

	/* Try to select upstream */
	selected = (struct smtp_upstream *)get_upstream_round_robin (session->ctx->upstreams,
			session->ctx->upstream_num, sizeof (struct smtp_upstream),
			time (NULL), DEFAULT_UPSTREAM_ERROR_TIME, DEFAULT_UPSTREAM_DEAD_TIME, DEFAULT_UPSTREAM_MAXERRORS);
	if (selected == NULL) {
		msg_err ("no upstreams suitable found");
		return FALSE;
	}

	session->upstream = selected;

	/* Now try to create socket */
	session->upstream_sock = make_universal_socket (selected->name, selected->port, SOCK_STREAM, TRUE, FALSE, FALSE);
	if (session->upstream_sock == -1) {
		msg_err ("cannot make a connection to %s", selected->name);
		upstream_fail (&selected->up, time (NULL));
		return FALSE;
	}
	/* Create a proxy for upstream connection */
	rspamd_dispatcher_pause (session->dispatcher);
	/* First of all get upstream's greeting */
	session->state = SMTP_PROXY_STATE_GREETING;

	event_set (&session->upstream_ev, session->upstream_sock, EV_READ | EV_PERSIST, smtp_proxy_greeting_handler, session);
	event_base_set (session->ev_base, &session->upstream_ev);
	event_add (&session->upstream_ev, &session->ctx->smtp_timeout);

	session->upstream_greeting = g_string_sized_new (BUFSIZ);

	return TRUE;
}

static void
smtp_dnsbl_cb (struct rdns_reply *reply, void *arg)
{
	struct smtp_proxy_session 						*session = arg;
	const gchar										*p;
	gint											 dots = 0;

	session->rbl_requests --;

	msg_debug ("got reply for %s: %s", rdns_request_get_name (reply->request), rdns_strerror (reply->code));

	if (session->state != SMTP_PROXY_STATE_REJECT) {

		if (reply->code == DNS_RC_NOERROR) {
			/* This means that address is in dnsbl */
			p = rdns_request_get_name (reply->request);
			while (*p) {
				if (*p == '.') {
					dots ++;
				}
				if (dots == 4) {
					session->dnsbl_applied = (gchar *)p + 1;
					break;
				}
				p ++;
			}
			session->state = SMTP_PROXY_STATE_REJECT;
		}
	}

	if (session->rbl_requests == 0) {
		if (session->state != SMTP_PROXY_STATE_REJECT) {
			/* Make proxy */
			if (!create_smtp_proxy_upstream_connection (session)) {
				rspamd_dispatcher_restore (session->dispatcher);
			}
		}
		else {
			if (session->ctx->instant_reject) {
				msg_info ("reject %s is denied by dnsbl: %s",
						inet_ntoa (session->client_addr), session->dnsbl_applied);
				if (!rspamd_dispatcher_write (session->dispatcher,
						make_smtp_error (session->pool, 521, "%s Client denied by %s", "5.2.1", session->dnsbl_applied),
						0, FALSE, TRUE)) {
					msg_err ("cannot write smtp error");
				}
			}
			else {
				/* Emulate fake smtp session */
				rspamd_set_dispatcher_policy (session->dispatcher, BUFFER_LINE, 0);
				if (!rspamd_dispatcher_write (session->dispatcher,
						make_smtp_error (session->pool, 220, "smtp ready"),
						0, FALSE, TRUE)) {
					msg_err ("cannot write smtp reply");
				}
			}
			rspamd_dispatcher_restore (session->dispatcher);
		}
	}
}

/*
 * Create requests to all rbls
 */
static void
make_rbl_requests (struct smtp_proxy_session *session)
{
	GList									*cur;
	gchar									*p, *dst;
	guint									 len;

	cur = session->ctx->rbls;
	while (cur) {
		len = INET_ADDRSTRLEN + strlen (cur->data) + 1;
		dst = memory_pool_alloc (session->pool, len);
		/* Print ipv4 addr */
		p = (gchar *)&session->client_addr.s_addr;
		rspamd_snprintf (dst, len, "%ud.%ud.%ud.%ud.%s", (guint)p[3],
				(guint)p[2], (guint)p[1], (guint)p[0], cur->data);
		if (make_dns_request (session->resolver, session->s, session->pool,
								smtp_dnsbl_cb, session, DNS_REQUEST_A, dst)) {
			session->rbl_requests ++;
			msg_debug ("send request to %s", dst);
		}
		cur = g_list_next (cur);
	}

	if (session->rbl_requests == 0) {
		/* Create proxy */
		if (! create_smtp_proxy_upstream_connection (session)) {
			rspamd_dispatcher_restore (session->dispatcher);
		}
	}
}

/* Resolving and delay handlers */
/*
 * Return from a delay
 */
static void
smtp_delay_handler (gint fd, short what, void *arg)
{
	struct smtp_proxy_session 				*session = arg;

	remove_normal_event (session->s, (event_finalizer_t) event_del,
			session->delay_timer);
	if (session->state == SMTP_PROXY_STATE_DELAY) {
		/* TODO: Create upstream connection here */
		if (session->ctx->rbls) {
			make_rbl_requests (session);
		}
		else {
			if (!create_smtp_proxy_upstream_connection (session)) {
				rspamd_dispatcher_restore (session->dispatcher);
			}
		}
	}
	else {
		/* TODO: Write error here */
		session->state = SMTP_PROXY_STATE_REJECT;
		if (!rspamd_dispatcher_write (session->dispatcher,
				make_smtp_error (session->pool, 521, "%s Improper use of SMTP command pipelining", "5.2.1"),
				0, FALSE, TRUE)) {
			msg_err ("cannot write smtp error");
		}
		rspamd_dispatcher_restore (session->dispatcher);
	}
}

/*
 * Make delay for a client
 */
static void
smtp_make_delay (struct smtp_proxy_session *session)
{
	struct event 							*tev;
	struct timeval 							*tv;
	gint32 									 jitter;

	if (session->ctx->smtp_delay != 0 && session->state == SMTP_PROXY_STATE_DELAY) {
		tev = memory_pool_alloc (session->pool, sizeof(struct event));
		tv = memory_pool_alloc (session->pool, sizeof(struct timeval));
		if (session->ctx->delay_jitter != 0) {
			jitter = g_random_int_range (0, session->ctx->delay_jitter);
			msec_to_tv (session->ctx->smtp_delay + jitter, tv);
		}
		else {
			msec_to_tv (session->ctx->smtp_delay, tv);
		}

		evtimer_set (tev, smtp_delay_handler, session);
		evtimer_add (tev, tv);
		register_async_event (session->s, (event_finalizer_t) event_del, tev,
				g_quark_from_static_string ("smtp proxy"));
		session->delay_timer = tev;
	}
	else if (session->state == SMTP_PROXY_STATE_DELAY) {
		/* TODO: Create upstream connection here */
		if (session->ctx->rbls) {
			make_rbl_requests (session);
		}
		else {
			if (!create_smtp_proxy_upstream_connection (session)) {
				rspamd_dispatcher_restore (session->dispatcher);
			}
		}
	}
}

/*
 * Handle DNS replies
 */
static void
smtp_dns_cb (struct rdns_reply *reply, void *arg)
{
	struct smtp_proxy_session 						*session = arg;
	gint 											 res = 0;
	struct rdns_reply_entry 						*elt;
	GList 											*cur;

	switch (session->state)
	{
	case SMTP_PROXY_STATE_RESOLVE_REVERSE:
		/* Parse reverse reply and start resolve of this ip */
		if (reply->code != DNS_RC_NOERROR) {
			rspamd_conditional_debug (rspamd_main->logger,
					session->client_addr.s_addr, __FUNCTION__, "DNS error: %s",
					rdns_strerror (reply->code));

			if (reply->code == DNS_RC_NXDOMAIN) {
				session->hostname = memory_pool_strdup (session->pool,
						XCLIENT_HOST_UNAVAILABLE);
			}
			else {
				session->hostname = memory_pool_strdup (session->pool,
						XCLIENT_HOST_TEMPFAIL);
			}
			session->state = SMTP_PROXY_STATE_DELAY;
			smtp_make_delay (session);
		}
		else {
			if (reply->entries) {
				elt = reply->entries;
				session->hostname = memory_pool_strdup (session->pool,
						elt->content.ptr.name);
				session->state = SMTP_PROXY_STATE_RESOLVE_NORMAL;
				make_dns_request (session->resolver, session->s, session->pool,
						smtp_dns_cb, session, DNS_REQUEST_A, session->hostname);

			}
		}
		break;
	case SMTP_PROXY_STATE_RESOLVE_NORMAL:
		if (reply->code != DNS_RC_NOERROR) {
			rspamd_conditional_debug (rspamd_main->logger,
					session->client_addr.s_addr, __FUNCTION__, "DNS error: %s",
					rdns_strerror (reply->code));

			if (reply->code == DNS_RC_NXDOMAIN) {
				session->hostname = memory_pool_strdup (session->pool,
						XCLIENT_HOST_UNAVAILABLE);
			}
			else {
				session->hostname = memory_pool_strdup (session->pool,
						XCLIENT_HOST_TEMPFAIL);
			}
			session->state = SMTP_PROXY_STATE_DELAY;
			smtp_make_delay (session);
		}
		else {
			res = 0;
			LL_FOREACH (reply->entries, elt) {
				if (memcmp (&session->client_addr, &elt->content.a.addr,
						sizeof(struct in_addr)) == 0) {
					res = 1;
					session->resolved = TRUE;
					break;
				}
				cur = g_list_next (cur);
			}

			if (res == 0) {
				msg_info(
						"cannot find address for hostname: %s, ip: %s", session->hostname,
						inet_ntoa (session->client_addr));
				session->hostname = memory_pool_strdup (session->pool,
						XCLIENT_HOST_UNAVAILABLE);
			}
			session->state = SMTP_PROXY_STATE_DELAY;
			smtp_make_delay (session);
		}
		break;
	default:
		/* TODO: write something about pipelining */
		break;
	}
}

static void
proxy_parse_smtp_input (f_str_t *line, struct smtp_proxy_session *session)
{
	gchar								 *p, *c, *end;
	gsize								  len;

	p = line->begin;
	end = line->begin + line->len;
	if (line->len >= sizeof("rcpt to: ") - 1 && (*p == 'r' || *p == 'R') && session->rcpt == NULL) {
		if (g_ascii_strncasecmp (p, "rcpt to: ", sizeof ("rcpt to: ") - 1) == 0) {
			p += sizeof ("rcpt to: ") - 1;
			/* Skip spaces */
			while ((g_ascii_isspace (*p) || *p == '<') && p < end) {
				p ++;
			}
			c = p;
			while (!(g_ascii_isspace (*p) || *p == '>') && p < end) {
				p ++;
			}
			len = p - c;
			session->rcpt = memory_pool_alloc (session->pool, len + 1);
			rspamd_strlcpy (session->rcpt, c, len + 1);
		}
	}
	else if (line->len >= sizeof("mail from: ") - 1 && (*p == 'm' || *p == 'M') && session->from == NULL) {
		if (g_ascii_strncasecmp (p, "mail from: ", sizeof ("mail from: ") - 1) == 0) {
			p += sizeof ("mail from: ") - 1;
			/* Skip spaces */
			while ((g_ascii_isspace (*p) || *p == '<') && p < end) {
				p ++;
			}
			c = p;
			while (!(g_ascii_isspace (*p) || *p == '>') && p < end) {
				p ++;
			}
			len = p - c;
			session->from = memory_pool_alloc (session->pool, len + 1);
			rspamd_strlcpy (session->from, c, len + 1);
		}
	}
	else if (line->len >= sizeof ("quit") - 1 && (*p == 'q' || *p == 'Q')) {
		if (g_ascii_strncasecmp (p, "quit", sizeof ("quit") - 1) == 0) {
			session->state = SMTP_PROXY_STATE_REJECT;
		}
	}
}

/*
 * Callback that is called when there is data to read in buffer
 */
static                          gboolean
smtp_proxy_read_socket (f_str_t * in, void *arg)
{
	struct smtp_proxy_session            *session = arg;
	gchar								 *p;

	if (session->state != SMTP_PROXY_STATE_REJECT_EMULATE) {
		/* This can be called only if client is using invalid pipelining */
		session->state = SMTP_PROXY_STATE_REJECT;
		if (!rspamd_dispatcher_write (session->dispatcher,
				make_smtp_error (session->pool, 521, "%s Improper use of SMTP command pipelining", "5.2.1"),
				0, FALSE, TRUE)) {
			msg_err ("cannot write smtp error");
		}
		destroy_session (session->s);
	}
	else {
		/* Try to extract data */
		p = in->begin;
		if (in->len >= sizeof ("helo") - 1 && (*p == 'h' || *p == 'H' || *p == 'e' || *p == 'E')) {
			return rspamd_dispatcher_write (session->dispatcher,
					"220 smtp ready" CRLF,
					0, FALSE, TRUE);
		}
		else if (in->len > 0) {
			proxy_parse_smtp_input (in, session);
		}
		if (session->state == SMTP_PROXY_STATE_REJECT) {
			/* Received QUIT command */
			if (!rspamd_dispatcher_write (session->dispatcher,
					"221 2.0.0 Bye" CRLF,
					0, FALSE, TRUE)) {
				msg_err ("cannot write smtp error");
			}
			destroy_session (session->s);
			return FALSE;
		}
		if (session->rcpt != NULL) {
			session->errors ++;
			if (session->errors > SMTP_MAXERRORS) {
				if (!rspamd_dispatcher_write (session->dispatcher,
						"521 5.2.1 Maximum errors reached" CRLF,
						0, FALSE, TRUE)) {
					msg_err ("cannot write smtp error");
				}
				destroy_session (session->s);
				return FALSE;
			}
			return rspamd_dispatcher_write (session->dispatcher,
					make_smtp_error (session->pool, 521, "%s Client denied by %s", "5.2.1", session->dnsbl_applied),
					0, FALSE, TRUE);
		}
		else {
			return rspamd_dispatcher_write (session->dispatcher,
					"250 smtp ready" CRLF,
					0, FALSE, TRUE);
		}
	}

	return FALSE;
}

/*
 * Actually called only if something goes wrong
 */
static                          gboolean
smtp_proxy_write_socket (void *arg)
{
	struct smtp_proxy_session            *session = arg;

	if (session->ctx->instant_reject) {
		destroy_session (session->s);
		return FALSE;
	}
	else {
		session->state = SMTP_PROXY_STATE_REJECT_EMULATE;
	}

	return TRUE;
}

/*
 * Called if something goes wrong
 */
static void
smtp_proxy_err_socket (GError * err, void *arg)
{
	struct smtp_proxy_session            *session = arg;

	if (err) {
		if (err->code == ETIMEDOUT) {
			/* Write smtp error */
			if (!rspamd_dispatcher_write (session->dispatcher,
					"421 4.4.2 Error: timeout exceeded" CRLF,
					0, FALSE, TRUE)) {
				msg_err ("cannot write smtp error");
			}
		}
		msg_info ("abnormally closing connection, error: %s", err->message);
		g_error_free (err);
	}
	/* Free buffers */
	destroy_session (session->s);
}

/*
 * Accept new connection and construct session
 */
static void
accept_socket (gint fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	union sa_union                  su;
	struct smtp_proxy_session      *session;
	struct smtp_proxy_ctx          *ctx;

	socklen_t                       addrlen = sizeof (su.ss);
	gint                            nfd;

	if ((nfd = accept_from_socket (fd, (struct sockaddr *)&su.ss, &addrlen)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		return;
	}

	ctx = worker->ctx;
	session = g_slice_alloc0 (sizeof (struct smtp_proxy_session));
	session->pool = memory_pool_new (memory_pool_get_size ());

	if (su.ss.ss_family == AF_UNIX) {
		msg_info ("accepted connection from unix socket");
		session->client_addr.s_addr = INADDR_NONE;
	}
	else if (su.ss.ss_family == AF_INET) {
		msg_info ("accepted connection from %s port %d", inet_ntoa (su.s4.sin_addr), ntohs (su.s4.sin_port));
		memcpy (&session->client_addr, &su.s4.sin_addr, sizeof (struct in_addr));
	}

	session->sock = nfd;
	session->worker = worker;
	session->ctx = ctx;
	session->resolver = ctx->resolver;
	session->ev_base = ctx->ev_base;
	session->upstream_sock = -1;
	session->ptr_str = rdns_generate_ptr_from_str (inet_ntoa (su.s4.sin_addr));
	worker->srv->stat->connections_count++;

	/* Resolve client's addr */
	/* Set up async session */
	session->s = new_async_session (session->pool, NULL, NULL, free_smtp_proxy_session, session);
	session->state = SMTP_PROXY_STATE_RESOLVE_REVERSE;
	if (! make_dns_request (session->resolver, session->s, session->pool,
			smtp_dns_cb, session, DNS_REQUEST_PTR, session->ptr_str)) {
		msg_err ("cannot resolve %s", inet_ntoa (session->client_addr));
		g_slice_free1 (sizeof (struct smtp_proxy_session), session);
		close (nfd);
		return;
	}
	else {
		session->dispatcher = rspamd_create_dispatcher (session->ev_base, nfd, BUFFER_ANY,
								smtp_proxy_read_socket, smtp_proxy_write_socket, smtp_proxy_err_socket,
								&session->ctx->smtp_timeout, session);
		session->dispatcher->peer_addr = session->client_addr.s_addr;
	}
}

gpointer
init_smtp_proxy (struct config_file *cfg)
{
	struct smtp_proxy_ctx         		*ctx;
	GQuark								type;

	type = g_quark_try_string ("smtp_proxy");

	ctx = g_malloc0 (sizeof (struct smtp_worker_ctx));
	ctx->pool = memory_pool_new (memory_pool_get_size ());

	/* Set default values */
	ctx->smtp_timeout_raw = 300000;
	ctx->smtp_delay = 0;
	ctx->instant_reject = TRUE;

	rspamd_rcl_register_worker_option (cfg, type, "upstreams",
			rspamd_rcl_parse_struct_string, ctx,
			G_STRUCT_OFFSET (struct smtp_proxy_ctx, upstreams_str), 0);

	rspamd_rcl_register_worker_option (cfg, type, "timeout",
			rspamd_rcl_parse_struct_time, ctx,
			G_STRUCT_OFFSET (struct smtp_proxy_ctx, smtp_timeout_raw), RSPAMD_CL_FLAG_TIME_UINT_32);

	rspamd_rcl_register_worker_option (cfg, type, "delay",
			rspamd_rcl_parse_struct_time, ctx,
			G_STRUCT_OFFSET (struct smtp_proxy_ctx, smtp_delay), RSPAMD_CL_FLAG_TIME_UINT_32);

	rspamd_rcl_register_worker_option (cfg, type, "jitter",
			rspamd_rcl_parse_struct_time, ctx,
			G_STRUCT_OFFSET (struct smtp_proxy_ctx, delay_jitter), RSPAMD_CL_FLAG_TIME_UINT_32);

	rspamd_rcl_register_worker_option (cfg, type, "xclient",
			rspamd_rcl_parse_struct_boolean, ctx,
			G_STRUCT_OFFSET (struct smtp_proxy_ctx, use_xclient), 0);

	rspamd_rcl_register_worker_option (cfg, type, "instant_reject",
			rspamd_rcl_parse_struct_boolean, ctx,
			G_STRUCT_OFFSET (struct smtp_proxy_ctx, instant_reject), 0);

	rspamd_rcl_register_worker_option (cfg, type, "proxy_buffer",
			rspamd_rcl_parse_struct_integer, ctx,
			G_STRUCT_OFFSET (struct smtp_proxy_ctx, proxy_buf_len), RSPAMD_CL_FLAG_INT_32);

	rspamd_rcl_register_worker_option (cfg, type, "dnsbl",
			rspamd_rcl_parse_struct_string_list, ctx,
			G_STRUCT_OFFSET (struct smtp_proxy_ctx, rbls), 0);

	return ctx;
}

/* Make post-init configuration */
static gboolean
config_smtp_proxy_worker (struct rspamd_worker *worker)
{
	struct smtp_proxy_ctx         *ctx = worker->ctx;
	gchar                         *value;

	/* Init timeval */
	msec_to_tv (ctx->smtp_timeout_raw, &ctx->smtp_timeout);

	/* Init upstreams */
	if ((value = ctx->upstreams_str) != NULL) {
		if (!parse_upstreams_line (ctx->pool, ctx->upstreams, value, &ctx->upstream_num)) {
			return FALSE;
		}
	}
	else {
		msg_err ("no upstreams defined, don't know what to do");
		return FALSE;
	}

	if (ctx->proxy_buf_len == 0) {
		ctx->proxy_buf_len = DEFAULT_PROXY_BUF_LEN;
	}

	return TRUE;
}

/*
 * Start worker process
 */
void
start_smtp_proxy (struct rspamd_worker *worker)
{
	struct smtp_proxy_ctx         *ctx = worker->ctx;

	ctx->ev_base = prepare_worker (worker, "smtp_proxy", sig_handler, accept_socket);

	/* Set smtp options */
	if ( !config_smtp_proxy_worker (worker)) {
		msg_err ("cannot configure smtp worker, exiting");
		exit (EXIT_SUCCESS);
	}


	/* SIGUSR2 handler */
	signal_set (&worker->sig_ev_usr2, SIGUSR2, sigusr2_handler, (void *) worker);
	event_base_set (ctx->ev_base, &worker->sig_ev_usr2);
	signal_add (&worker->sig_ev_usr2, NULL);

	/* SIGUSR1 handler */
	signal_set (&worker->sig_ev_usr1, SIGUSR1, sigusr1_handler, (void *) worker);
	event_base_set (ctx->ev_base, &worker->sig_ev_usr1);
	signal_add (&worker->sig_ev_usr1, NULL);

	/* DNS resolver */
	ctx->resolver = dns_resolver_init (worker->srv->logger, ctx->ev_base, worker->srv->cfg);

	/* Set umask */
	umask (S_IWGRP | S_IWOTH | S_IROTH | S_IRGRP);

	event_base_loop (ctx->ev_base, 0);

	close_log (rspamd_main->logger);
	exit (EXIT_SUCCESS);
}

