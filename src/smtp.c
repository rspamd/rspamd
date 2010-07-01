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
#include "smtp_proto.h"
#include "map.h"
#include "message.h"
#include "settings.h"
#include "evdns/evdns.h"

/* Max line size as it is defined in rfc2822 */
#define OUTBUFSIZ 1000

/* Upstream timeouts */
#define DEFAULT_UPSTREAM_ERROR_TIME 10
#define DEFAULT_UPSTREAM_DEAD_TIME 300
#define DEFAULT_UPSTREAM_MAXERRORS 10


#define DEFAULT_REJECT_MESSAGE "450 4.5.0 Spam message rejected"

static gboolean smtp_write_socket (void *arg);

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


static void
free_smtp_session (gpointer arg)
{
	struct smtp_session            *session = arg;
	
	if (session) {
		if (session->task) {
			free_task (session->task, FALSE);
			if (session->task->msg->begin) {
				munmap (session->task->msg->begin, session->task->msg->len);
			}
		}
		if (session->rcpt) {
			g_list_free (session->rcpt);
		}
		if (session->dispatcher) {
			rspamd_remove_dispatcher (session->dispatcher);
		}
		close (session->sock);
		if (session->temp_name != NULL) {
			unlink (session->temp_name);
		}
		if (session->temp_fd != -1) {
			close (session->temp_fd);
		}
		memory_pool_delete (session->pool);
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
create_smtp_upstream_connection (struct smtp_session *session)
{
	struct smtp_upstream              *selected;
	struct sockaddr_un                *un;

	/* Try to select upstream */
	selected = (struct smtp_upstream *)get_upstream_round_robin (session->ctx->upstreams, 
			session->ctx->upstream_num, sizeof (struct smtp_upstream),
			session->session_time, DEFAULT_UPSTREAM_ERROR_TIME, DEFAULT_UPSTREAM_DEAD_TIME, DEFAULT_UPSTREAM_MAXERRORS);
	if (selected == NULL) {
		msg_err ("no upstreams suitable found");
		return FALSE;
	}

	session->upstream = selected;

	/* Now try to create socket */
	if (selected->is_unix) {
		un = alloca (sizeof (struct sockaddr_un));
		session->upstream_sock = make_unix_socket (selected->name, un, FALSE);
	}
	else {
		session->upstream_sock = make_tcp_socket (&selected->addr, selected->port, FALSE, TRUE);
	}
	if (session->upstream_sock == -1) {
		msg_err ("cannot make a connection to %s", selected->name);
		upstream_fail (&selected->up, session->session_time);
		return FALSE;
	}
	/* Create a dispatcher for upstream connection */
	session->upstream_dispatcher = rspamd_create_dispatcher (session->upstream_sock, BUFFER_LINE, 
							smtp_upstream_read_socket, smtp_upstream_write_socket, smtp_upstream_err_socket, 
							&session->ctx->smtp_timeout, session);
	session->state = SMTP_STATE_WAIT_UPSTREAM;
	session->upstream_state = SMTP_STATE_GREETING;
	register_async_event (session->s, (event_finalizer_t)smtp_upstream_finalize_connection, session, FALSE);
	return TRUE;
}

static gboolean
call_stage_filters (struct smtp_session *session, enum rspamd_smtp_stage stage)
{
	gboolean                         res = TRUE;
	GList                           *list = session->ctx->smtp_filters[stage];
	struct smtp_filter              *filter;
	
	while (list) {
		filter = list->data;
		if (! filter->filter (session, filter->filter_data)) {
			res = FALSE;
			break;
		}
		list = g_list_next (list);
	}

	return res;
}

static gboolean
read_smtp_command (struct smtp_session *session, f_str_t *line)
{
	/* XXX: write dialog implementation */
	struct smtp_command             *cmd;
	char                             outbuf[BUFSIZ];
	int                              r;
	
	if (! parse_smtp_command (session, line, &cmd)) {
		session->error = SMTP_ERROR_BAD_COMMAND;
		session->errors ++;
		return FALSE;
	}
	
	switch (cmd->command) {
		case SMTP_COMMAND_HELO:
		case SMTP_COMMAND_EHLO:
			if (session->state == SMTP_STATE_GREETING || session->state == SMTP_STATE_HELO) {
				if (parse_smtp_helo (session, cmd)) {
					session->state = SMTP_STATE_FROM;
				}
				else {
					session->errors ++;
				}
				if (! call_stage_filters (session, SMTP_STAGE_HELO)) {
					return FALSE;
				}
				return TRUE;
			}
			else {
				goto improper_sequence;
			}
			break;
		case SMTP_COMMAND_QUIT:
			session->state = SMTP_STATE_QUIT;
			break;
		case SMTP_COMMAND_NOOP:
			break;
		case SMTP_COMMAND_MAIL:
			if (((session->state == SMTP_STATE_GREETING || session->state == SMTP_STATE_HELO) && !session->ctx->helo_required) 
					|| session->state == SMTP_STATE_FROM) {
				if (parse_smtp_from (session, cmd)) {
					session->state = SMTP_STATE_RCPT;
				}
				else {
					session->errors ++;
					return FALSE;
				}
				if (! call_stage_filters (session, SMTP_STAGE_MAIL)) {
					return FALSE;
				}
			}
			else {
				goto improper_sequence;
			}
			break;
		case SMTP_COMMAND_RCPT:
			if (session->state == SMTP_STATE_RCPT) {
				if (parse_smtp_rcpt (session, cmd)) {
					if (! call_stage_filters (session, SMTP_STAGE_RCPT)) {
						return FALSE;
					}
					/* Make upstream connection */
					if (session->upstream == NULL) {
						if (!create_smtp_upstream_connection (session)) {
							session->error = SMTP_ERROR_UPSTREAM;
							session->state = SMTP_STATE_CRITICAL_ERROR;
							return FALSE;
						}
					}
					else {
						/* Send next rcpt to upstream */
						session->state = SMTP_STATE_WAIT_UPSTREAM;
						session->upstream_state = SMTP_STATE_BEFORE_DATA;
						rspamd_dispatcher_restore (session->upstream_dispatcher);
						r = rspamd_snprintf (outbuf, sizeof (outbuf), "RCPT TO: ");
						r += smtp_upstream_write_list (session->rcpt->data, outbuf + r, sizeof (outbuf) - r);
						session->cur_rcpt = NULL;
						return rspamd_dispatcher_write (session->upstream_dispatcher, outbuf, r, FALSE, FALSE);
					}
					session->state = SMTP_STATE_WAIT_UPSTREAM;
					return TRUE;
				}
				else {
					session->errors ++;
					return FALSE;
				}
			}
			else {
				goto improper_sequence;
			}
			break;
		case SMTP_COMMAND_RSET:
			session->from = NULL;
			if (session->rcpt) {
				g_list_free (session->rcpt);
			}
			if (session->upstream) {
				remove_normal_event (session->s, smtp_upstream_finalize_connection, session);
				session->upstream = NULL;
			}
			session->state = SMTP_STATE_GREETING; 
			break;
		case SMTP_COMMAND_DATA:
			if (session->state == SMTP_STATE_RCPT) {
				if (session->rcpt == NULL) {
					session->error = SMTP_ERROR_RECIPIENTS;
					session->errors ++;
					return FALSE;
				}
				if (! call_stage_filters (session, SMTP_STAGE_DATA)) {
					return FALSE;
				}
				if (session->upstream == NULL) {
					session->error = SMTP_ERROR_UPSTREAM;
					session->state = SMTP_STATE_CRITICAL_ERROR;
					return FALSE;
				}
				else {
					session->upstream_state = SMTP_STATE_DATA;
					rspamd_dispatcher_restore (session->upstream_dispatcher);
					r = rspamd_snprintf (outbuf, sizeof (outbuf), "DATA" CRLF);
					session->state = SMTP_STATE_WAIT_UPSTREAM;
					session->error = SMTP_ERROR_DATA_OK;
					return rspamd_dispatcher_write (session->upstream_dispatcher, outbuf, r, FALSE, FALSE);
				}
			}
			else {
				goto improper_sequence;
			}
		case SMTP_COMMAND_VRFY:
		case SMTP_COMMAND_EXPN:
		case SMTP_COMMAND_HELP:
			session->error = SMTP_ERROR_UNIMPLIMENTED;
			return FALSE;
	}
	
	session->error = SMTP_ERROR_OK;
	return TRUE;

improper_sequence:
	session->errors ++;
	session->error = SMTP_ERROR_SEQUENCE;
	return FALSE;
}

static gboolean
smtp_send_upstream_message (struct smtp_session *session)
{
	rspamd_dispatcher_pause (session->dispatcher);
	rspamd_dispatcher_restore (session->upstream_dispatcher);
	
	session->upstream_state = SMTP_STATE_IN_SENDFILE;
	session->state = SMTP_STATE_WAIT_UPSTREAM;
	if (! rspamd_dispatcher_sendfile (session->upstream_dispatcher, session->temp_fd, session->temp_size)) {
		msg_err ("sendfile failed: %s", strerror (errno));
		goto err;
	}
	return TRUE;

err:
	session->error = SMTP_ERROR_FILE;
	session->state = SMTP_STATE_CRITICAL_ERROR;
	if (! rspamd_dispatcher_write (session->dispatcher, session->error, 0, FALSE, TRUE)) {
		return FALSE;
	}
	destroy_session (session->s);
	return FALSE;
}

static gboolean
process_smtp_data (struct smtp_session *session)
{
	struct stat                     st;
	int                             r;
	GList                          *cur, *t;
	f_str_t                        *f;
	char                           *s;

	if (fstat (session->temp_fd, &st) == -1) {
		msg_err ("fstat failed: %s", strerror (errno));
		goto err;
	}
	/* Now mmap temp file if it is small enough */
	session->temp_size = st.st_size;
	if (session->ctx->max_size == 0 || st.st_size < session->ctx->max_size) {
		session->task = construct_task (session->worker);
		session->task->fin_callback = smtp_write_socket;
		session->task->fin_arg = session;
		session->task->msg = memory_pool_alloc (session->pool, sizeof (f_str_t));
#ifdef HAVE_MMAP_NOCORE
		if ((session->task->msg->begin = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED | MAP_NOCORE, session->temp_fd, 0)) == MAP_FAILED) {
#else
		if ((session->task->msg->begin = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, session->temp_fd, 0)) == MAP_FAILED) {
#endif
			msg_err ("mmap failed: %s", strerror (errno));
			goto err;
		}
		session->task->msg->len = st.st_size;
		session->task->helo = session->helo;
		/* Save MAIL FROM */
		cur = session->from;
		if (cur) {
			f = cur->data;
			s = memory_pool_alloc (session->pool, f->len + 1);
			g_strlcpy (s, f->begin, f->len + 1);
			session->task->from = s;
		}
		/* Save recipients */
		t = session->rcpt;
		while (t) {
			cur = t->data;
			if (cur) {
				f = cur->data;
				s = memory_pool_alloc (session->pool, f->len + 1);
				g_strlcpy (s, f->begin, f->len + 1);
				session->task->rcpt = g_list_prepend (session->task->rcpt, s);
			}
			t = g_list_next (t);
		}

		memcpy (&session->task->from_addr, &session->client_addr, sizeof (struct in_addr));
		session->task->cmd = CMD_CHECK;

		if (process_message (session->task) == -1) {
			msg_err ("cannot process message");
			munmap (session->task->msg->begin, st.st_size);
			msg_err ("process message failed: %s", strerror (errno));
			goto err;
		}
		r = process_filters (session->task);
		if (r == -1) {
			munmap (session->task->msg->begin, st.st_size);
			msg_err ("cannot process filters");
			goto err;
		}
		else if (r == 0) {
			session->state = SMTP_STATE_END;
			rspamd_dispatcher_pause (session->dispatcher);
		}
		else {
			process_statfiles (session->task);
			session->state = SMTP_STATE_END;
			return smtp_write_socket (session);
		}
	}
	else {
		session->task = NULL;
		return smtp_send_upstream_message (session);
	}

	return TRUE;
err:
	session->error = SMTP_ERROR_FILE;
	session->state = SMTP_STATE_CRITICAL_ERROR;
	if (! rspamd_dispatcher_write (session->dispatcher, session->error, 0, FALSE, TRUE)) {
		return FALSE;
	}
	destroy_session (session->s);
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
			session->error = make_smtp_error (session, 550, "%s Improper use of SMTP command pipelining", "5.5.0");
			session->state = SMTP_STATE_ERROR;
			break;
		case SMTP_STATE_GREETING:
		case SMTP_STATE_HELO:
		case SMTP_STATE_FROM:
		case SMTP_STATE_RCPT:
		case SMTP_STATE_DATA:
			read_smtp_command (session, in);
			if (session->state != SMTP_STATE_WAIT_UPSTREAM) {
				if (session->errors > session->ctx->max_errors) {
					session->error = SMTP_ERROR_LIMIT;
					session->state = SMTP_STATE_CRITICAL_ERROR;
					if (! rspamd_dispatcher_write (session->dispatcher, session->error, 0, FALSE, TRUE)) {
						return FALSE;
					}
					destroy_session (session->s);
					return FALSE;
				}
				if (! smtp_write_socket (session)) {
					return FALSE;
				}
			}
			break;
		case SMTP_STATE_AFTER_DATA:
			if (in->len == 0) {
				return TRUE;
			}
			if (in->len == 3 && memcmp (in->begin, DATA_END_TRAILER, in->len) == 0) {
				return process_smtp_data (session);
			}

			if (write (session->temp_fd, in->begin, in->len) != in->len) {
				msg_err ("cannot write to temp file: %s", strerror (errno));
				session->error = SMTP_ERROR_FILE;
				session->state = SMTP_STATE_CRITICAL_ERROR;
				if (! rspamd_dispatcher_write (session->dispatcher, session->error, 0, FALSE, TRUE)) {
					return FALSE;
				}
				destroy_session (session->s);
				return FALSE;
			}
			break;
		case SMTP_STATE_WAIT_UPSTREAM:
			rspamd_dispatcher_pause (session->dispatcher);
			break;
		default:
			session->error = make_smtp_error (session, 550, "%s Internal error", "5.5.0");
			session->state = SMTP_STATE_ERROR;
			break;
	}

	if (session->state == SMTP_STATE_QUIT) {
		destroy_session (session->s);
		return FALSE;
	}
	else if (session->state == SMTP_STATE_WAIT_UPSTREAM) {
		rspamd_dispatcher_pause (session->dispatcher);
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
	double                          ms = 0, rs = 0;
	int                             r;
	struct metric_result           *metric_res;
	struct metric                  *m;
	char                            logbuf[1024];
	gboolean                        is_spam = FALSE;
	GList                          *symbols, *cur;	

	if (session->state == SMTP_STATE_CRITICAL_ERROR) {
		if (session->error != NULL) {
			if (! rspamd_dispatcher_write (session->dispatcher, session->error, 0, FALSE, TRUE)) {
				return FALSE;
			}
		}
		destroy_session (session->s);
		return FALSE;
	}
	else if (session->state == SMTP_STATE_END) {
		if (session->task != NULL) {
			/* Check metric */
			m = g_hash_table_lookup (session->cfg->metrics, session->ctx->metric);
			metric_res = g_hash_table_lookup (session->task->results, session->ctx->metric);
			if (m != NULL && metric_res != NULL) {
				if (!check_metric_settings (session->task, m, &ms, &rs)) {
					ms = m->required_score;
					rs = m->reject_score;
				}
				if (metric_res->score >= ms) {
					is_spam = TRUE;
				}

				r = rspamd_snprintf (logbuf, sizeof (logbuf), "msg ok, id: <%s>, ", session->task->message_id);
				r += rspamd_snprintf (logbuf + r, sizeof (logbuf) - r, "(%s: %s: [%.2f/%.2f/%.2f] [", 
						(char *)m->name, is_spam ? "T" : "F", metric_res->score, ms, rs);
				symbols = g_hash_table_get_keys (metric_res->symbols);
				cur = symbols;
				while (cur) {
					if (g_list_next (cur) != NULL) {
						r += rspamd_snprintf (logbuf + r, sizeof (logbuf) - r, "%s,", (char *)cur->data);
					}
					else {
						r += rspamd_snprintf (logbuf + r, sizeof (logbuf) - r, "%s", (char *)cur->data);
					}
					cur = g_list_next (cur);
				}
				g_list_free (symbols);
#ifdef HAVE_CLOCK_GETTIME
				r += rspamd_snprintf (logbuf + r, sizeof (logbuf) - r, "]), len: %l, time: %sms",
					(long int)session->task->msg->len, calculate_check_time (&session->task->ts, session->cfg->clock_res));
#else
				r += rspamd_snprintf (logbuf + r, sizeof (logbuf) - r, "]), len: %l, time: %sms",
					(long int)session->task->msg->len, calculate_check_time (&session->task->tv, session->cfg->clock_res));
#endif
				msg_info ("%s", logbuf);

				if (is_spam) {
					if (! rspamd_dispatcher_write (session->dispatcher, session->ctx->reject_message, 0, FALSE, TRUE)) {
						return FALSE;
					}
					if (! rspamd_dispatcher_write (session->dispatcher, CRLF, sizeof (CRLF) - 1, FALSE, TRUE)) {
						return FALSE;
					}
					destroy_session (session->s);
					return FALSE;
				}
			}
			return smtp_send_upstream_message (session);
		}
		else {
			if (session->error != NULL) {
				if (! rspamd_dispatcher_write (session->dispatcher, session->error, 0, FALSE, TRUE)) {
					return FALSE;
				}
			}
		}
	}
	else {
		if (session->error != NULL) {
			if (! rspamd_dispatcher_write (session->dispatcher, session->error, 0, FALSE, TRUE)) {
				return FALSE;
			}
		}
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
static gboolean
write_smtp_greeting (struct smtp_session *session)
{
	if (session->ctx->smtp_banner) {
		if (! rspamd_dispatcher_write (session->dispatcher, session->ctx->smtp_banner, 0, FALSE, TRUE)) {
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * Return from a delay
 */
static void
smtp_delay_handler (int fd, short what, void *arg)
{
	struct smtp_session            *session = arg;
	
	remove_normal_event (session->s, (event_finalizer_t)event_del, session->delay_timer);
	if (session->state == SMTP_STATE_DELAY) {
		session->state = SMTP_STATE_GREETING;
		write_smtp_greeting (session);
	}
	else {
		session->state = SMTP_STATE_CRITICAL_ERROR;
		(void)smtp_write_socket (session);
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
	gint32                         jitter;

	if (session->ctx->smtp_delay != 0 && session->state == SMTP_STATE_DELAY) {
		tev = memory_pool_alloc (session->pool, sizeof (struct event));
		tv = memory_pool_alloc (session->pool, sizeof (struct timeval));
		if (session->ctx->delay_jitter != 0) {
			jitter = g_random_int_range (0, session->ctx->delay_jitter);
			tv->tv_sec = (session->ctx->smtp_delay + jitter) / 1000;
			tv->tv_usec = (session->ctx->smtp_delay + jitter - tv->tv_sec * 1000) * 1000;
		}
		else {
			tv->tv_sec = session->ctx->smtp_delay / 1000;
			tv->tv_usec = (session->ctx->smtp_delay - tv->tv_sec * 1000) * 1000;
		}

		evtimer_set (tev, smtp_delay_handler, session);
		evtimer_add (tev, tv);
		register_async_event (session->s, (event_finalizer_t)event_del, tev, FALSE);
		session->delay_timer = tev;
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
	
	remove_forced_event (session->s, (event_finalizer_t)smtp_dns_cb);
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
					register_async_event (session->s, (event_finalizer_t)smtp_dns_cb, NULL, TRUE);
					
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
	union sa_union                  su;
	struct smtp_session            *session;

	socklen_t                       addrlen = sizeof (su.ss);
	int                             nfd;

	if ((nfd = accept_from_socket (fd, (struct sockaddr *)&su.ss, &addrlen)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		return;
	}

	session = g_malloc0 (sizeof (struct smtp_session));
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
	session->temp_fd = -1;
	session->worker = worker;
	session->ctx = worker->ctx;
	session->cfg = worker->srv->cfg;
	session->session_time = time (NULL);
	worker->srv->stat->connections_count++;

	/* Resolve client's addr */
	session->state = SMTP_STATE_RESOLVE_REVERSE;
	if (evdns_resolve_reverse (&session->client_addr, DNS_QUERY_NO_SEARCH, smtp_dns_cb, session) != 0) {
		msg_err ("cannot resolve %s", inet_ntoa (session->client_addr));
		g_free (session);
		close (nfd);
		return;
	}
	else {
		/* Set up async session */
		session->s = new_async_session (session->pool, free_smtp_session, session);
		register_async_event (session->s, (event_finalizer_t)smtp_dns_cb, NULL, TRUE);
		/* Set up dispatcher */
		session->dispatcher = rspamd_create_dispatcher (nfd, BUFFER_LINE, 
								smtp_read_socket, smtp_write_socket, smtp_err_socket, &session->ctx->smtp_timeout, session);
		session->dispatcher->peer_addr = session->client_addr.s_addr;
	}
}

static void
parse_smtp_banner (struct smtp_worker_ctx *ctx, const char *line)
{
	int                             hostmax, banner_len = sizeof ("220 ") - 1;
	char                           *p, *t, *hostbuf = NULL;
	gboolean                        has_crlf = FALSE;

	p = (char *)line;
	while (*p) {
		if (*p == '%') {
			p ++;
			switch (*p) {
				case 'n':
					/* Assume %n as CRLF */
					banner_len += sizeof (CRLF) - 1 + sizeof ("220 -") - 1;
					has_crlf = TRUE;
					break;
				case 'h':
					hostmax = sysconf (_SC_HOST_NAME_MAX) + 1;
					hostbuf = alloca (hostmax);
					gethostname (hostbuf, hostmax);
					hostbuf[hostmax - 1] = '\0';
					banner_len += strlen (hostbuf);
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
			banner_len ++;
		}
		p ++;
	}
	
	if (has_crlf) {
		banner_len += sizeof (CRLF "220 " CRLF);
	}
	else {
		banner_len += sizeof (CRLF);
	}

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
					p ++;
					break;
				case 'h':
					t = g_stpcpy (t, hostbuf);
					p ++;
					break;
				case '%':
					*t++ = '%';
					p ++;
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
	if (has_crlf) {
		t = g_stpcpy (t, CRLF "220 " CRLF);
	}
	else {
		t = g_stpcpy (t, CRLF);
	}
}

static gboolean
parse_upstreams_line (struct smtp_worker_ctx *ctx, const char *line)
{
	char                          **strv, *p, *t, *tt, *err_str;
	uint32_t                        num, i;
	struct smtp_upstream           *cur;
	char                            resolved_path[PATH_MAX];
	
	strv = g_strsplit_set (line, ",; ", -1);
	num = g_strv_length (strv);

	if (num >= MAX_UPSTREAM) {
		msg_err ("cannot define %d upstreams %d is max", num, MAX_UPSTREAM);
		return FALSE;
	}

	for (i = 0; i < num; i ++) {
		p = strv[i];
		cur = &ctx->upstreams[ctx->upstream_num];
		if ((t = strrchr (p, ':')) != NULL && (tt = strchr (p, ':')) != t) {
			/* Assume that after last `:' we have weigth */
			*t = '\0';
			t ++;
			errno = 0;
			cur->up.priority = strtoul (t, &err_str, 10);
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

static void
make_capabilities (struct smtp_worker_ctx *ctx, const char *line)
{
	char                          **strv, *p, *result, *hostbuf;
	uint32_t                        num, i, len, hostmax;

	strv = g_strsplit_set (line, ",;", -1);
	num = g_strv_length (strv);
	
	hostmax = sysconf (_SC_HOST_NAME_MAX) + 1;
	hostbuf = alloca (hostmax);
	gethostname (hostbuf, hostmax);
	hostbuf[hostmax - 1] = '\0';

	len = sizeof ("250-") + strlen (hostbuf) + sizeof (CRLF) - 1;

	for (i = 0; i < num; i ++) {
		p = strv[i];
		len += sizeof ("250-") + sizeof (CRLF) + strlen (p) - 2;
	}

	result = memory_pool_alloc (ctx->pool, len);
	ctx->smtp_capabilities = result;
	
	p = result;
	if (num == 0) {
		p += rspamd_snprintf (p, len - (p - result), "250 %s" CRLF, hostbuf);
	}
	else {
		p += rspamd_snprintf (p, len - (p - result), "250-%s" CRLF, hostbuf);
		for (i = 0; i < num; i ++) {
			if (i != num - 1) {
				p += rspamd_snprintf (p, len - (p - result), "250-%s" CRLF, strv[i]);
			}
			else {
				p += rspamd_snprintf (p, len - (p - result), "250 %s" CRLF, strv[i]);
			}
		}
	}

	g_strfreev (strv);
}


static gboolean
config_smtp_worker (struct rspamd_worker *worker)
{
	struct smtp_worker_ctx         *ctx;
	char                           *value;
	uint32_t                        timeout;

	ctx = g_malloc0 (sizeof (struct smtp_worker_ctx));
	ctx->pool = memory_pool_new (memory_pool_get_size ());
	
	/* Set default values */
	ctx->smtp_timeout.tv_sec = 300;
	ctx->smtp_timeout.tv_usec = 0;
	ctx->smtp_delay = 0;
	ctx->smtp_banner = "220 ESMTP Ready." CRLF;
	bzero (ctx->smtp_filters, sizeof (GList *) * SMTP_STAGE_MAX);

	if ((value = g_hash_table_lookup (worker->cf->params, "upstreams")) != NULL) {
		if (!parse_upstreams_line (ctx, value)) {
			return FALSE;
		}
	}
	else {
		msg_err ("no upstreams defined, don't know what to do");
		return FALSE;
	}
	if ((value = g_hash_table_lookup (worker->cf->params, "smtp_banner")) != NULL) {
		parse_smtp_banner (ctx, value);
	}
	if ((value = g_hash_table_lookup (worker->cf->params, "smtp_timeout")) != NULL) {
		errno = 0;
		timeout = parse_seconds (value);
		ctx->smtp_timeout.tv_sec = timeout / 1000;
		ctx->smtp_timeout.tv_usec = (timeout - ctx->smtp_timeout.tv_sec * 1000) * 1000;
	}
	if ((value = g_hash_table_lookup (worker->cf->params, "smtp_delay")) != NULL) {
		ctx->smtp_delay = parse_seconds (value);
	}
	if ((value = g_hash_table_lookup (worker->cf->params, "smtp_jitter")) != NULL) {
		ctx->delay_jitter = parse_seconds (value);
	}
	if ((value = g_hash_table_lookup (worker->cf->params, "smtp_capabilities")) != NULL) {
		make_capabilities (ctx, value);
	}
	if ((value = g_hash_table_lookup (worker->cf->params, "smtp_metric")) != NULL) {
		ctx->metric = memory_pool_strdup (ctx->pool, value);
	}
	else {
		ctx->metric = DEFAULT_METRIC;
	}
	if ((value = g_hash_table_lookup (worker->cf->params, "smtp_max_errors")) != NULL) {
		ctx->max_errors = strtoul (value, NULL, 10);
	}
	else {
		ctx->max_errors = DEFAULT_MAX_ERRORS;
	}
	if ((value = g_hash_table_lookup (worker->cf->params, "smtp_reject_message")) != NULL) {
		ctx->reject_message = memory_pool_strdup (ctx->pool, value);
	}
	else {
		ctx->reject_message = DEFAULT_REJECT_MESSAGE;
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

	/* Set smtp options */
	if ( !config_smtp_worker (worker)) {
		msg_err ("cannot configure smtp worker, exiting");
		exit (EXIT_SUCCESS);
	}

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

	/* Set umask */
	umask (S_IWGRP | S_IWOTH | S_IROTH | S_IRGRP);

	event_loop (0);
	
	close_log ();
	exit (EXIT_SUCCESS);
}

void 
register_smtp_filter (struct smtp_worker_ctx *ctx, enum rspamd_smtp_stage stage, smtp_filter_t filter, gpointer filter_data)
{
	struct smtp_filter             *new;

	new = memory_pool_alloc (ctx->pool, sizeof (struct smtp_filter));

	new->filter = filter;
	new->filter_data = filter_data;

	if (stage >= SMTP_STAGE_MAX) {
		msg_err ("invalid smtp stage: %d", stage);
	}
	else {
		ctx->smtp_filters[stage] = g_list_prepend (ctx->smtp_filters[stage], new);
	}
}

/* 
 * vi:ts=4 
 */
