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

#include "config.h"
#include "main.h"
#include "cfg_file.h"
#include "util.h"
#include "smtp.h"
#include "map.h"
#include "evdns/evdns.h"

/* Max line size as it is defined in rfc2822 */
#define OUTBUFSIZ 1000

/* SMTP error messages */


static sig_atomic_t                    wanna_die = 0;


#ifndef HAVE_SA_SIGINFO
static void
sig_handler (int signo)
#else
static void
sig_handler (int signo, siginfo_t *info, void *unused)
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

char *
make_smtp_error (struct smtp_session *session, int error_code, const char *format, ...)
{
	va_list                         vp;
	char                           *result = NULL, *p;
	size_t                          len;
	
	va_start (vp, format);
	len = g_printf_string_upper_bound (format, vp);
	result = memory_pool_alloc (session->pool, len + sizeof ("65535 "));
	p = result + snprintf (result, len, "%d ", error_code);
	vsnprintf (p, len - (p - result), format, vp);
	va_end (vp);

	return result;
}

static void
free_smtp_session (gpointer arg)
{
	struct smtp_session            *session = arg;
	
	if (session) {
		if (session->task) {
			free_task (session->task, FALSE);
		}
		if (session->dispatcher) {
			rspamd_remove_dispatcher (session->dispatcher);
		}
		memory_pool_delete (session->pool);
		close (session->sock);
		g_free (session);
	}
}

/*
 * Config reload is designed by sending sigusr to active workers and pending shutdown of them
 */
static void
sigusr_handler (int fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	/* Do not accept new connections, preparing to end worker's process */
	struct timeval                  tv;
	if (! wanna_die) {
		tv.tv_sec = SOFT_SHUTDOWN_TIME;
		tv.tv_usec = 0;
		event_del (&worker->sig_ev);
		event_del (&worker->bind_ev);
		do_reopen_log = 1;
		msg_info ("worker's shutdown is pending in %d sec", SOFT_SHUTDOWN_TIME);
		event_loopexit (&tv);
	}
	return;
}

static gboolean
read_smtp_command (struct smtp_session *session, f_str_t *line)
{
	/* XXX: write dialog implementation */

	return FALSE;
}

/*
 * Callback that is called when there is data to read in buffer
 */
static                          gboolean
smtp_read_socket (f_str_t * in, void *arg)
{
	struct smtp_session            *session = arg;

	switch (session->state) {
		case SMTP_STATE_RESOLVE_REVERSE:
		case SMTP_STATE_RESOLVE_NORMAL:
		case SMTP_STATE_DELAY:
			session->error = make_smtp_error (session, 550, "%s Improper use of SMTP command pipelining");
			session->state = SMTP_STATE_ERROR;
			break;
		case SMTP_STATE_GREETING:
		case SMTP_STATE_HELO:
		case SMTP_STATE_FROM:
		case SMTP_STATE_RCPT:
		case SMTP_STATE_DATA:
			return read_smtp_command (session, in);
			break;
		default:
			session->error = make_smtp_error (session, 550, "%s Internal error");
			session->state = SMTP_STATE_ERROR;
			break;
	}

	return TRUE;
}

/*
 * Callback for socket writing
 */
static                          gboolean
smtp_write_socket (void *arg)
{
	struct smtp_session            *session = arg;

	if (session->state == SMTP_STATE_WRITE_ERROR) {
		rspamd_dispatcher_write (session->dispatcher, session->error, 0, FALSE, TRUE);
		destroy_session (session->s);
		return FALSE;
	}
	
	return TRUE;
}

/*
 * Called if something goes wrong
 */
static void
smtp_err_socket (GError * err, void *arg)
{
	struct smtp_session            *session = arg;

	msg_info ("abnormally closing connection, error: %s", err->message);
	/* Free buffers */
	destroy_session (session->s);
}

/*
 * Write greeting to client
 */
static void
write_smtp_greeting (struct smtp_session *session)
{
	if (session->ctx->smtp_banner) {
		rspamd_dispatcher_write (session->dispatcher, session->ctx->smtp_banner, 0, FALSE, TRUE);
	}
}

/*
 * Return from a delay
 */
static void
smtp_delay_handler (int fd, short what, void *arg)
{
	struct smtp_session            *session = arg;

	if (session->state == SMTP_STATE_DELAY) {
		session->state = SMTP_STATE_GREETING;
		write_smtp_greeting (session);
	}
	else {
		session->state = SMTP_STATE_WRITE_ERROR;
		smtp_write_socket (session);
	}
}

/*
 * Make delay for a client
 */
static void
smtp_make_delay (struct smtp_session *session)
{
	struct event                  *tev;
	struct timeval                *tv;

	if (session->ctx->smtp_delay != 0 && session->state == SMTP_STATE_DELAY) {
		tev = memory_pool_alloc (session->pool, sizeof (struct event));
		tv = memory_pool_alloc (session->pool, sizeof (struct timeval));
		tv->tv_sec = session->ctx->smtp_delay / 1000;
		tv->tv_usec = session->ctx->smtp_delay - tv->tv_sec * 1000;

		evtimer_set (tev, smtp_delay_handler, session);
		evtimer_add (tev, tv);
	}
	else if (session->state == SMTP_STATE_DELAY) {
		session->state = SMTP_STATE_GREETING;
		write_smtp_greeting (session);
	}
}

/*
 * Handle DNS replies
 */
static void
smtp_dns_cb (int result, char type, int count, int ttl, void *addresses, void *arg)
{
	struct smtp_session            *session = arg;
	int                             i, res = 0;

	switch (session->state) {
		case SMTP_STATE_RESOLVE_REVERSE:
			/* Parse reverse reply and start resolve of this ip */
			if (result != DNS_ERR_NONE || type != DNS_PTR) {
				debug_ip (session->client_addr.s_addr, "DNS error: %s", evdns_err_to_string (result));
				
				if (result == DNS_ERR_NOTEXIST) {
					session->hostname = memory_pool_strdup (session->pool, "unknown");
				}
				else {
					session->hostname = memory_pool_strdup (session->pool, "tempfail");
				}
				session->state = SMTP_STATE_DELAY;
				smtp_make_delay (session);
			}
			else {
				if (addresses) {
					session->hostname = memory_pool_strdup (session->pool, * ((const char**)addresses));
					session->state = SMTP_STATE_RESOLVE_NORMAL;
					evdns_resolve_ipv4 (session->hostname, DNS_QUERY_NO_SEARCH, smtp_dns_cb, (void *)session);
				}
			}
			break;
		case SMTP_STATE_RESOLVE_NORMAL:
			if (result != DNS_ERR_NONE || type != DNS_IPv4_A) {
				debug_ip (session->client_addr.s_addr, "DNS error: %s", evdns_err_to_string (result));
				if (result == DNS_ERR_NOTEXIST) {
					session->hostname = memory_pool_strdup (session->pool, "unknown");
				}
				else {
					session->hostname = memory_pool_strdup (session->pool, "tempfail");
				}
				session->state = SMTP_STATE_DELAY;
				smtp_make_delay (session);
			}
			else {
				res = 0;
				for (i = 0; i < count; i++) {
					if (session->client_addr.s_addr == ((in_addr_t *)addresses)[i]) {
						res = 1;
						session->resolved = TRUE;
						break;
					}
				}

				if (res == 0) {
					msg_info ("cannot find address for hostname: %s, ip: %s", session->hostname, inet_ntoa (session->client_addr));
					session->hostname = memory_pool_strdup (session->pool, "unknown");
				}
				session->state = SMTP_STATE_DELAY;
				smtp_make_delay (session);
			}
			break;
		case SMTP_STATE_ERROR:
			session->state = SMTP_STATE_WRITE_ERROR;
			smtp_write_socket (session);
			break;
		default:
			/* 
			 * This callback is called on unknown state, usually this indicates
			 * an error (invalid pipelining)
			 */
			break;
	}
}

/*
 * Accept new connection and construct task
 */
static void
accept_socket (int fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	struct sockaddr_storage         ss;
	struct sockaddr_in             *sin;
	struct smtp_session            *session;

	socklen_t                       addrlen = sizeof (ss);
	int                             nfd;

	if ((nfd = accept_from_socket (fd, (struct sockaddr *)&ss, &addrlen)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		return;
	}

	session = g_malloc (sizeof (struct smtp_session));
	session->pool = memory_pool_new (memory_pool_get_size ());

	if (ss.ss_family == AF_UNIX) {
		msg_info ("accepted connection from unix socket");
		session->client_addr.s_addr = INADDR_NONE;
	}
	else if (ss.ss_family == AF_INET) {
		sin = (struct sockaddr_in *)&ss;
		msg_info ("accepted connection from %s port %d", inet_ntoa (sin->sin_addr), ntohs (sin->sin_port));
		memcpy (&session->client_addr, &sin->sin_addr, sizeof (struct in_addr));
	}

	session->sock = nfd;
	session->ctx = worker->ctx;
	worker->srv->stat->connections_count++;

	/* Resolve client's addr */
	session->state = SMTP_STATE_RESOLVE_REVERSE;
	if (evdns_resolve_reverse (&session->client_addr, DNS_QUERY_NO_SEARCH, smtp_dns_cb, session) != 0) {
		msg_err ("cannot resolve %s", inet_ntoa (session->client_addr));
		g_free (session);
		close (nfd);
	}
	
	/* Set up dispatcher */
	session->dispatcher = rspamd_create_dispatcher (nfd, BUFFER_LINE, 
							smtp_read_socket, smtp_write_socket, smtp_err_socket, &session->ctx->smtp_timeout, session);
	session->dispatcher->peer_addr = session->client_addr.s_addr;
	/* Set up async session */
	session->s = new_async_session (session->pool, free_smtp_session, session);

}

static void
parse_smtp_banner (struct smtp_worker_ctx *ctx, const char *line)
{
	int                             hostmax, banner_len = sizeof ("220 ") - 1;
	char                           *p, *t, *hostbuf;
	gboolean                        has_crlf = FALSE;

	p = (char *)line;
	while (*p) {
		if (*p == '%') {
			p ++;
			switch (*p) {
				case 'n':
					/* Assume %n as CRLF */
					banner_len += sizeof (CRLF) - 1 + sizeof ("220 -") - 1 - 2;
					has_crlf = TRUE;
					break;
				case 'h':
					hostmax = sysconf (_SC_HOST_NAME_MAX) + 1;
					hostbuf = alloca (hostmax);
					gethostname (hostbuf, hostmax);
					hostbuf[hostmax - 1] = '\0';
					banner_len += strlen (hostbuf) - 2;
					break;
				case '%':
					banner_len += 1;
					break;
				default:
					banner_len += 2;
					break;
			}
		}
		else {
			banner_len += 1;
		}
		p ++;
	}
	
	banner_len += sizeof (CRLF);

	ctx->smtp_banner = memory_pool_alloc (ctx->pool, banner_len + 1);
	t = ctx->smtp_banner;
	p = (char *)line;

	if (has_crlf) {
		t = g_stpcpy (t, "220-");
	}
	else {
		t = g_stpcpy (t, "220 ");
	}

	while (*p) {
		if (*p == '%') {
			p ++;
			switch (*p) {
				case 'n':
					/* Assume %n as CRLF */
					*t++ = CR; *t++ = LF;
					t = g_stpcpy (t, "220-");
					break;
				case 'h':
					t = g_stpcpy (t, hostbuf);
					break;
				case '%':
					*t++ = '%';
					break;
				default:
					/* Copy all %<char> to dest */
					*t++ = *(p - 1); *t++ = *p;
					break;
			}
		}
		else {
			*t ++ = *p ++;
		}
	}
	t = g_stpcpy (t, CRLF);
}

static gboolean
parse_upstreams_line (struct smtp_worker_ctx *ctx, const char *line)
{
	char                          **strv, *p, *t, *err_str;
	uint32_t                        num, i;
	struct smtp_upstream           *cur;
	char                            resolved_path[PATH_MAX];
	
	strv = g_strsplit (line, ",; ", 0);
	num = g_strv_length (strv);

	if (num >= MAX_UPSTREAM) {
		msg_err ("cannot define %d upstreams %d is max", num, MAX_UPSTREAM);
		return FALSE;
	}

	for (i = 0; i < num; i ++) {
		p = strv[i];
		cur = &ctx->upstreams[ctx->upstream_num];
		if ((t = strrchr (p, ':')) != NULL) {
			/* Assume that after last `:' we have weigth */
			*t = '\0';
			t ++;
			errno = 0;
			cur->up.weight = strtoul (t, &err_str, 10);
			if (errno != 0 || (err_str && *err_str != '\0')) {
				msg_err ("cannot convert weight: %s, %s", t, strerror (errno));
				g_strfreev (strv);
				return FALSE;
			}
		}
		if (*p == '/') {
			cur->is_unix = TRUE;
			if (realpath (p, resolved_path) == NULL) {
				msg_err ("cannot resolve path: %s", resolved_path);
				g_strfreev (strv);
				return FALSE;
			}
			cur->name = memory_pool_strdup (ctx->pool, resolved_path);
			ctx->upstream_num ++;
		}
		else {
			if (! parse_host_port (p, &cur->addr, &cur->port)) {
				g_strfreev (strv);
				return FALSE;
			}
			cur->name = memory_pool_strdup (ctx->pool, p);
			ctx->upstream_num ++;
		}
	}

	g_strfreev (strv);
	return TRUE;
}

static gboolean
config_smtp_worker (struct rspamd_worker *worker)
{
	struct smtp_worker_ctx         *ctx;
	char                           *value, *err_str;
	uint32_t                        timeout;

	ctx = g_malloc0 (sizeof (struct smtp_worker_ctx));
	ctx->pool = memory_pool_new (memory_pool_get_size ());
	
	/* Set default values */
	ctx->smtp_timeout.tv_sec = 300;
	ctx->smtp_timeout.tv_usec = 0;
	ctx->smtp_delay = 0;
	ctx->smtp_banner = "220 ESMTP Ready." CRLF;

	if ((value = g_hash_table_lookup (worker->cf->params, "upstreams")) != NULL) {
		if (!parse_upstreams_line (ctx, value)) {
			return FALSE;
		}
	}
	else {
		return FALSE;
	}
	if ((value = g_hash_table_lookup (worker->cf->params, "banner")) != NULL) {
		parse_smtp_banner (ctx, value);
	}
	if ((value = g_hash_table_lookup (worker->cf->params, "smtp_timeout")) != NULL) {
		errno = 0;
		timeout = strtoul (value, &err_str, 10);
		if (errno != 0 || (err_str && *err_str != '\0')) {
			msg_warn ("cannot parse timeout, invalid number: %s: %s", value, strerror (errno));
		}
		else {
			ctx->smtp_timeout.tv_sec = timeout / 1000;
			ctx->smtp_timeout.tv_usec = timeout - ctx->smtp_timeout.tv_sec * 1000;
		}
	}
	if ((value = g_hash_table_lookup (worker->cf->params, "smtp_delay")) != NULL) {
		errno = 0;
		ctx->smtp_delay = strtoul (value, &err_str, 10);
		if (errno != 0 || (err_str && *err_str != '\0')) {
			msg_warn ("cannot parse delay, invalid number: %s: %s", value, strerror (errno));
		}
	}
	/* Set ctx */
	worker->ctx = ctx;
	
	return TRUE;
	
}


/*
 * Start worker process
 */
void
start_smtp_worker (struct rspamd_worker *worker)
{
	struct sigaction                signals;

	gperf_profiler_init (worker->srv->cfg, "worker");

	worker->srv->pid = getpid ();

	event_init ();
	evdns_init ();

	init_signals (&signals, sig_handler);
	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);

	/* SIGUSR2 handler */
	signal_set (&worker->sig_ev, SIGUSR2, sigusr_handler, (void *)worker);
	signal_add (&worker->sig_ev, NULL);

	/* Accept event */
	event_set (&worker->bind_ev, worker->cf->listen_sock, EV_READ | EV_PERSIST, accept_socket, (void *)worker);
	event_add (&worker->bind_ev, NULL);

	/* Maps events */
	start_map_watch ();

	/* Set smtp options */
	config_smtp_worker (worker);

	event_loop (0);
	
	close_log ();
	exit (EXIT_SUCCESS);
}

/* 
 * vi:ts=4 
 */
