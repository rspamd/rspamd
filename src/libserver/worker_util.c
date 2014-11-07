/* Copyright (c) 2010-2011, Vsevolod Stakhov
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
#include "message.h"
#include "lua/lua_common.h"

/**
 * Return worker's control structure by its type
 * @param type
 * @return worker's control structure or NULL
 */
worker_t *
rspamd_get_worker_by_type (GQuark type)
{
	worker_t **cur;

	cur = &workers[0];
	while (*cur) {
		if (g_quark_from_string ((*cur)->name) == type) {
			return *cur;
		}
		cur++;
	}

	return NULL;
}

sig_atomic_t wanna_die = 0;

/*
 * Config reload is designed by sending sigusr2 to active workers and pending shutdown of them
 */
static void
rspamd_worker_usr2_handler (gint fd, short what, void *arg)
{
	struct rspamd_worker_signal_handler *sigh =
		(struct rspamd_worker_signal_handler *)arg;
	/* Do not accept new connections, preparing to end worker's process */
	struct timeval tv;

	if (!wanna_die) {
		tv.tv_sec = SOFT_SHUTDOWN_TIME;
		tv.tv_usec = 0;
		wanna_die = 1;
		rspamd_worker_stop_accept (sigh->worker);
		msg_info ("worker's shutdown is pending in %d sec", SOFT_SHUTDOWN_TIME);
		event_base_loopexit (sigh->base, &tv);
	}

	if (sigh->post_handler) {
		sigh->post_handler (sigh->handler_data);
	}
}

/*
 * Reopen log is designed by sending sigusr1 to active workers and pending shutdown of them
 */
static void
rspamd_worker_usr1_handler (gint fd, short what, void *arg)
{
	struct rspamd_worker_signal_handler *sigh =
			(struct rspamd_worker_signal_handler *)arg;

	reopen_log (sigh->worker->srv->logger);

	if (sigh->post_handler) {
		sigh->post_handler (sigh->handler_data);
	}
}

static void
rspamd_worker_term_handler (gint fd, short what, void *arg)
{
	struct rspamd_worker_signal_handler *sigh =
			(struct rspamd_worker_signal_handler *)arg;
	struct timeval tv;

	if (!wanna_die) {
		msg_info ("terminating after receiving %s signal", strsignal (sigh->signo));
		wanna_die = 1;
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		event_base_loopexit (sigh->base, &tv);
#ifdef WITH_GPERF_TOOLS
		ProfilerStop ();
#endif
	}

	if (sigh->post_handler) {
		sigh->post_handler (sigh->handler_data);
	}
}

static void
rspamd_worker_ignore_signal (int signo)
{
	struct sigaction sig;

	sigemptyset (&sig.sa_mask);
	sigaddset (&sig.sa_mask, signo);
	sig.sa_handler = SIG_IGN;
	sig.sa_flags = 0;
	sigaction (signo, &sig, NULL);
}

static void
rspamd_worker_set_signal_handler (int signo, struct rspamd_worker *worker,
		struct event_base *base, void (*handler)(int, short, void *))
{
	struct rspamd_worker_signal_handler *sigh;

	sigh = g_malloc0 (sizeof (*sigh));
	sigh->signo = signo;
	sigh->worker = worker;
	sigh->base = base;
	sigh->enabled = TRUE;

	signal_set (&sigh->ev, signo, handler, sigh);
	event_base_set (base, &sigh->ev);
	signal_add (&sigh->ev, NULL);

	g_hash_table_insert (worker->signal_events, GINT_TO_POINTER (signo), sigh);
}

static void
rspamd_worker_init_signals (struct rspamd_worker *worker, struct event_base *base)
{
	struct sigaction signals;
	/* We ignore these signals in the worker */
	rspamd_worker_ignore_signal (SIGPIPE);
	rspamd_worker_ignore_signal (SIGALRM);
	rspamd_worker_ignore_signal (SIGCHLD);

	/* A set of terminating signals */
	rspamd_worker_set_signal_handler (SIGTERM, worker, base,
			rspamd_worker_term_handler);
	rspamd_worker_set_signal_handler (SIGINT, worker, base,
			rspamd_worker_term_handler);
	rspamd_worker_set_signal_handler (SIGHUP, worker, base,
			rspamd_worker_term_handler);

	/* Special purpose signals */
	rspamd_worker_set_signal_handler (SIGUSR1, worker, base,
			rspamd_worker_usr1_handler);
	rspamd_worker_set_signal_handler (SIGUSR2, worker, base,
			rspamd_worker_usr2_handler);

	/* Unblock all signals processed */
	sigemptyset (&signals.sa_mask);
	sigaddset (&signals.sa_mask, SIGTERM);
	sigaddset (&signals.sa_mask, SIGINT);
	sigaddset (&signals.sa_mask, SIGHUP);
	sigaddset (&signals.sa_mask, SIGCHLD);
	sigaddset (&signals.sa_mask, SIGUSR1);
	sigaddset (&signals.sa_mask, SIGUSR2);
	sigaddset (&signals.sa_mask, SIGALRM);
	sigaddset (&signals.sa_mask, SIGPIPE);

	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);
}

struct event_base *
rspamd_prepare_worker (struct rspamd_worker *worker, const char *name,
	void (*accept_handler)(int, short, void *))
{
	struct event_base *ev_base;
	struct event *accept_event;
	GList *cur;
	gint listen_socket;

#ifdef WITH_PROFILER
	extern void _start (void), etext (void);
	monstartup ((u_long) & _start, (u_long) & etext);
#endif

	gperf_profiler_init (worker->srv->cfg, name);

	worker->srv->pid = getpid ();
	worker->signal_events = g_hash_table_new_full (g_direct_hash, g_direct_equal,
			NULL, g_free);

	ev_base = event_init ();

	rspamd_worker_init_signals (worker, ev_base);

	/* Accept all sockets */
	cur = worker->cf->listen_socks;
	while (cur) {
		listen_socket = GPOINTER_TO_INT (cur->data);
		if (listen_socket != -1) {
			accept_event = g_slice_alloc0 (sizeof (struct event));
			event_set (accept_event, listen_socket, EV_READ | EV_PERSIST,
				accept_handler, worker);
			event_base_set (ev_base, accept_event);
			event_add (accept_event, NULL);
			worker->accept_events = g_list_prepend (worker->accept_events,
					accept_event);
		}
		cur = g_list_next (cur);
	}

	return ev_base;
}

void
rspamd_worker_stop_accept (struct rspamd_worker *worker)
{
	GList *cur;
	struct event *event;
	GHashTableIter it;
	struct rspamd_worker_signal_handler *sigh;
	gpointer k, v;

	/* Remove all events */
	cur = worker->accept_events;
	while (cur) {
		event = cur->data;
		event_del (event);
		cur = g_list_next (cur);
		g_slice_free1 (sizeof (struct event), event);
	}

	if (worker->accept_events != NULL) {
		g_list_free (worker->accept_events);
	}

	g_hash_table_iter_init (&it, worker->signal_events);
	while (g_hash_table_iter_next (&it, &k, &v)) {
		sigh = (struct rspamd_worker_signal_handler *)v;
		g_hash_table_iter_steal (&it);
		if (sigh->enabled) {
			event_del (&sigh->ev);
		}
		g_free (sigh);
	}
	g_hash_table_unref (worker->signal_events);
}

void
rspamd_controller_send_error (struct rspamd_http_connection_entry *entry,
	gint code, const gchar *error_msg, ...)
{
	struct rspamd_http_message *msg;
	va_list args;

	msg = rspamd_http_new_message (HTTP_RESPONSE);

	va_start (args, error_msg);
	msg->status = g_string_sized_new (128);
	rspamd_vprintf_gstring (msg->status, error_msg, args);
	va_end (args);

	msg->date = time (NULL);
	msg->code = code;
	msg->body = g_string_sized_new (128);
	rspamd_printf_gstring (msg->body, "{\"error\":\"%v\"}", msg->status);
	rspamd_http_connection_reset (entry->conn);
	rspamd_http_connection_write_message (entry->conn,
		msg,
		NULL,
		"application/json",
		entry,
		entry->conn->fd,
		entry->rt->ptv,
		entry->rt->ev_base);
	entry->is_reply = TRUE;
}

void
rspamd_controller_send_string (struct rspamd_http_connection_entry *entry,
	const gchar *str)
{
	struct rspamd_http_message *msg;

	msg = rspamd_http_new_message (HTTP_RESPONSE);
	msg->date = time (NULL);
	msg->code = 200;
	msg->body = g_string_new (str);
	rspamd_http_connection_reset (entry->conn);
	rspamd_http_connection_write_message (entry->conn,
		msg,
		NULL,
		"application/json",
		entry,
		entry->conn->fd,
		entry->rt->ptv,
		entry->rt->ev_base);
	entry->is_reply = TRUE;
}

void
rspamd_controller_send_ucl (struct rspamd_http_connection_entry *entry,
	ucl_object_t *obj)
{
	struct rspamd_http_message *msg;

	msg = rspamd_http_new_message (HTTP_RESPONSE);
	msg->date = time (NULL);
	msg->code = 200;
	msg->body = g_string_sized_new (BUFSIZ);
	rspamd_ucl_emit_gstring (obj, UCL_EMIT_JSON_COMPACT, msg->body);
	rspamd_http_connection_reset (entry->conn);
	rspamd_http_connection_write_message (entry->conn,
		msg,
		NULL,
		"application/json",
		entry,
		entry->conn->fd,
		entry->rt->ptv,
		entry->rt->ev_base);
	entry->is_reply = TRUE;
}
