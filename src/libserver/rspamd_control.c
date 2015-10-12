/*
 * Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
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
#include "rspamd.h"
#include "rspamd_control.h"
#include "http.h"
#include "unix-std.h"
#include "utlist.h"

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

static struct timeval io_timeout = {
		.tv_sec = 30,
		.tv_usec = 0
};
static struct timeval worker_io_timeout = {
		.tv_sec = 0,
		.tv_usec = 500000
};

struct rspamd_control_session;

struct rspamd_control_reply_elt {
	struct rspamd_control_reply reply;
	struct event io_ev;
	struct rspamd_worker *wrk;
	struct rspamd_control_session *session;
	struct rspamd_control_reply_elt *prev, *next;
};

struct rspamd_control_session {
	gint fd;
	struct rspamd_main *rspamd_main;
	struct rspamd_http_connection *conn;
	struct rspamd_control_command cmd;
	struct rspamd_control_reply_elt *replies;
	guint replies_remain;
	gboolean is_reply;
};

static const struct rspamd_control_cmd_match {
	rspamd_ftok_t name;
	enum rspamd_control_type type;
} cmd_matches[] = {
		{
				.name = {
						.begin = "/stat",
						.len = 5
				},
				.type = RSPAMD_CONTROL_STAT
		},
		{
				.name = {
						.begin = "/reload",
						.len = 7
				},
				.type = RSPAMD_CONTROL_RELOAD
		},
};

void
rspamd_control_send_error (struct rspamd_control_session *session,
		gint code, const gchar *error_msg, ...)
{
	struct rspamd_http_message *msg;
	va_list args;

	msg = rspamd_http_new_message (HTTP_RESPONSE);

	va_start (args, error_msg);
	msg->status = rspamd_fstring_sized_new (128);
	rspamd_vprintf_fstring (&msg->status, error_msg, args);
	va_end (args);

	msg->date = time (NULL);
	msg->code = code;
	msg->body = rspamd_fstring_sized_new (128);
	rspamd_printf_fstring (&msg->body, "{\"error\":\"%V\"}", msg->status);
	rspamd_http_connection_reset (session->conn);
	rspamd_http_connection_write_message (session->conn,
			msg,
			NULL,
			"application/json",
			session,
			session->fd,
			&io_timeout,
			session->rspamd_main->ev_base);
}

static void
rspamd_control_send_ucl (struct rspamd_control_session *session,
		ucl_object_t *obj)
{
	struct rspamd_http_message *msg;

	msg = rspamd_http_new_message (HTTP_RESPONSE);
	msg->date = time (NULL);
	msg->code = 200;
	msg->body = rspamd_fstring_sized_new (BUFSIZ);
	rspamd_ucl_emit_fstring (obj, UCL_EMIT_JSON_COMPACT, &msg->body);
	rspamd_http_connection_reset (session->conn);
	rspamd_http_connection_write_message (session->conn,
			msg,
			NULL,
			"application/json",
			session,
			session->fd,
			&io_timeout,
			session->rspamd_main->ev_base);
}

static void
rspamd_control_connection_close (struct rspamd_control_session *session)
{
	struct rspamd_control_reply_elt *elt, *telt;

	DL_FOREACH_SAFE (session->replies, elt, telt) {
		event_del (&elt->io_ev);
		g_slice_free1 (sizeof (*elt), elt);
	}

	rspamd_http_connection_unref (session->conn);
	close (session->fd);
	g_slice_free1 (sizeof (*session), session);
}

static void
rspamd_control_write_reply (struct rspamd_control_session *session)
{
	ucl_object_t *rep, *cur;
	struct rspamd_control_reply_elt *elt;
	gchar tmpbuf[64];

	rep = ucl_object_typed_new (UCL_OBJECT);

	DL_FOREACH (session->replies, elt) {
		rspamd_snprintf (tmpbuf, sizeof (tmpbuf), "%P", elt->wrk->pid);
		cur = ucl_object_typed_new (UCL_OBJECT);

		ucl_object_insert_key (cur, ucl_object_fromstring (g_quark_to_string (
				elt->wrk->type)), "type", 0, false);

		switch (elt->session->cmd.type) {
		case RSPAMD_CONTROL_STAT:
			ucl_object_insert_key (cur, ucl_object_fromint (
					elt->reply.reply.stat.conns), "conns", 0, false);
			ucl_object_insert_key (cur, ucl_object_fromdouble (
					elt->reply.reply.stat.utime), "utime", 0, false);
			ucl_object_insert_key (cur, ucl_object_fromdouble (
					elt->reply.reply.stat.systime), "systime", 0, false);
			ucl_object_insert_key (cur, ucl_object_fromdouble (
					elt->reply.reply.stat.uptime), "uptime", 0, false);
			ucl_object_insert_key (cur, ucl_object_fromint (
					elt->reply.reply.stat.maxrss), "maxrss", 0, false);
			break;
		case RSPAMD_CONTROL_RELOAD:
			ucl_object_insert_key (cur, ucl_object_fromint (
					elt->reply.reply.reload.status), "status", 0, false);
			break;
		default:
			break;
		}

		ucl_object_insert_key (rep, cur, tmpbuf, 0, true);
	}

	rspamd_control_send_ucl (session, rep);
	ucl_object_unref (rep);
}

static void
rspamd_control_wrk_io (gint fd, short what, gpointer ud)
{
	struct rspamd_control_reply_elt *elt = ud;

	if (read (elt->wrk->control_pipe[0], &elt->reply, sizeof (elt->reply)) !=
				sizeof (elt->reply)) {
		msg_err ("cannot read request from the worker %P (%s): %s",
				elt->wrk->pid, g_quark_to_string (elt->wrk->type), strerror (errno));
	}

	elt->session->replies_remain --;
	event_del (&elt->io_ev);

	if (elt->session->replies_remain == 0) {
		rspamd_control_write_reply (elt->session);
	}
}

static void
rspamd_control_error_handler (struct rspamd_http_connection *conn, GError *err)
{
	struct rspamd_control_session *session = conn->ud;

	if (!session->is_reply) {
		msg_info ("abnormally closing control connection: %e", err);
		session->is_reply = TRUE;
		rspamd_control_send_error (session, err->code, "%s", err->message);
	}
	else {
		rspamd_control_connection_close (session);
	}
}

static gint
rspamd_control_finish_hadler (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg)
{
	struct rspamd_control_session *session = conn->ud;
	rspamd_ftok_t srch;
	guint i;
	gboolean found = FALSE;
	GHashTableIter it;
	struct rspamd_worker *wrk;
	struct rspamd_control_reply_elt *rep_elt;
	gpointer k, v;

	if (!session->is_reply) {
		if (msg->url == NULL) {
			rspamd_control_connection_close (session);

			return 0;
		}

		srch.begin = msg->url->str;
		srch.len = msg->url->len;

		session->is_reply = TRUE;

		for (i = 0; i < G_N_ELEMENTS (cmd_matches); i++) {
			if (rspamd_ftok_casecmp (&srch, &cmd_matches[i].name) == 0) {
				session->cmd.type = cmd_matches[i].type;
				found = TRUE;
				break;
			}
		}

		if (!found) {
			rspamd_control_send_error (session, 404, "Command not defined");
		}
		else {
			/* Send command to all workers */
			g_hash_table_iter_init (&it, session->rspamd_main->workers);

			while (g_hash_table_iter_next (&it, &k, &v)) {
				wrk = v;

				if (write (wrk->control_pipe[0], &session->cmd,
						sizeof (session->cmd)) == sizeof (session->cmd)) {

					rep_elt = g_slice_alloc0 (sizeof (*rep_elt));
					rep_elt->wrk = wrk;
					rep_elt->session = session;
					event_set (&rep_elt->io_ev, wrk->control_pipe[0],
							EV_READ | EV_PERSIST, rspamd_control_wrk_io,
							rep_elt);
					event_base_set (session->rspamd_main->ev_base,
							&rep_elt->io_ev);
					event_add (&rep_elt->io_ev, &worker_io_timeout);

					DL_APPEND (session->replies, rep_elt);
					session->replies_remain ++;
				}
				else {
					msg_err ("cannot write request to the worker %P (%s): %s",
						wrk->pid, g_quark_to_string (wrk->type), strerror (errno));
				}
			}
		}
	}
	else {
		rspamd_control_connection_close (session);
	}


	return 0;
}

void
rspamd_control_process_client_socket (struct rspamd_main *rspamd_main,
		gint fd)
{
	struct rspamd_control_session *session;

	session = g_slice_alloc0 (sizeof (*session));

	session->fd = fd;
	session->conn = rspamd_http_connection_new (NULL, rspamd_control_error_handler,
			rspamd_control_finish_hadler, 0, RSPAMD_HTTP_SERVER, NULL);
	session->rspamd_main = rspamd_main;
	rspamd_http_connection_read_message (session->conn, session, session->fd,
			&io_timeout, rspamd_main->ev_base);
}

struct rspamd_worker_control_data {
	struct event io_ev;
	struct rspamd_worker *worker;
	struct event_base *ev_base;
	struct {
		rspamd_worker_control_handler handler;
		gpointer ud;
	} handlers[RSPAMD_CONTROL_MAX];
};

static void
rspamd_control_default_cmd_handler (gint fd,
		struct rspamd_worker_control_data *cd,
		struct rspamd_control_command *cmd)
{
	struct rspamd_control_reply rep;
	gssize r;
	struct rusage rusg;

	memset (&rep, 0, sizeof (rep));
	rep.type = cmd->type;

	switch (cmd->type) {
	case RSPAMD_CONTROL_STAT:
		if (getrusage (RUSAGE_SELF, &rusg) == -1) {
			msg_err ("cannot get rusage stats: %s",
					strerror (errno));
		}
		else {
			rep.reply.stat.utime = tv_to_double (&rusg.ru_utime);
			rep.reply.stat.systime = tv_to_double (&rusg.ru_stime);
			rep.reply.stat.maxrss = rusg.ru_maxrss;
		}

		rep.reply.stat.conns = cd->worker->nconns;
		rep.reply.stat.uptime = rspamd_get_calendar_ticks () - cd->worker->start_time;
		break;
	case RSPAMD_CONTROL_RELOAD:
		break;
	default:
		break;
	}

	r = write (fd, &rep, sizeof (rep));

	if (r != sizeof (rep)) {
		msg_err ("cannot write reply to the control socket: %s",
				strerror (errno));
	}
}

static void
rspamd_control_default_worker_handler (gint fd, short what, gpointer ud)
{
	struct rspamd_worker_control_data *cd = ud;
	struct rspamd_control_command cmd;

	gssize r;


	r = read (fd, &cmd, sizeof (cmd));

	if (r != sizeof (cmd)) {
		msg_err ("cannot read request from the control socket: %s",
				strerror (errno));
	}
	else if ((gint)cmd.type >= 0 && cmd.type < RSPAMD_CONTROL_MAX) {

		if (cd->handlers[cmd.type].handler) {
			cd->handlers[cmd.type].handler (cd->worker->srv, cd->worker,
					fd, &cmd, cd->handlers[cmd.type].ud);
		}
		else {
			rspamd_control_default_cmd_handler (fd, cd, &cmd);
		}
	}
}

void
rspamd_control_worker_add_default_handler (struct rspamd_worker *worker,
		struct event_base *ev_base)
{
	struct rspamd_worker_control_data *cd;

	cd = g_slice_alloc0 (sizeof (*cd));
	cd->worker = worker;
	cd->ev_base = ev_base;

	event_set (&cd->io_ev, worker->control_pipe[1], EV_READ | EV_PERSIST,
			rspamd_control_default_worker_handler, cd);
	event_base_set (ev_base, &cd->io_ev);
	event_add (&cd->io_ev, NULL);

	worker->control_data = cd;
}

/**
 * Register custom handler for a specific control command for this worker
 */
void
rspamd_control_worker_add_cmd_handler (struct rspamd_worker *worker,
		enum rspamd_control_type type,
		rspamd_worker_control_handler handler,
		gpointer ud)
{
	struct rspamd_worker_control_data *cd;

	g_assert (type >= 0 && type < RSPAMD_CONTROL_MAX);
	g_assert (handler != NULL);
	g_assert (worker->control_data != NULL);

	cd = worker->control_data;
	cd->handlers[type].handler = handler;
	cd->handlers[type].ud = ud;
}
