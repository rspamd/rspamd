/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "rspamd.h"
#include "rspamd_control.h"
#include "worker_util.h"
#include "libserver/http/http_connection.h"
#include "libserver/http/http_private.h"
#include "libutil/libev_helper.h"
#include "unix-std.h"
#include "utlist.h"

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

static ev_tstamp io_timeout = 30.0;
static ev_tstamp worker_io_timeout = 0.5;

struct rspamd_control_session;

struct rspamd_control_reply_elt {
	struct rspamd_control_reply reply;
	struct rspamd_io_ev ev;
	struct ev_loop *event_loop;
	GQuark wrk_type;
	pid_t wrk_pid;
	gpointer ud;
	gint attached_fd;
	GHashTable *pending_elts;
	struct rspamd_control_reply_elt *prev, *next;
};

struct rspamd_control_session {
	gint fd;
	struct ev_loop *event_loop;
	struct rspamd_main *rspamd_main;
	struct rspamd_http_connection *conn;
	struct rspamd_control_command cmd;
	struct rspamd_control_reply_elt *replies;
	rspamd_inet_addr_t *addr;
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
						.len = sizeof ("/stat") - 1
				},
				.type = RSPAMD_CONTROL_STAT
		},
		{
				.name = {
						.begin = "/reload",
						.len = sizeof ("/reload") - 1
				},
				.type = RSPAMD_CONTROL_RELOAD
		},
		{
				.name = {
						.begin = "/reresolve",
						.len = sizeof ("/reresolve") - 1
				},
				.type = RSPAMD_CONTROL_RERESOLVE
		},
		{
				.name = {
						.begin = "/recompile",
						.len = sizeof ("/recompile") - 1
				},
				.type = RSPAMD_CONTROL_RECOMPILE
		},
		{
				.name = {
						.begin = "/fuzzystat",
						.len = sizeof ("/fuzzystat") - 1
				},
				.type = RSPAMD_CONTROL_FUZZY_STAT
		},
		{
				.name = {
						.begin = "/fuzzysync",
						.len = sizeof ("/fuzzysync") - 1
				},
				.type = RSPAMD_CONTROL_FUZZY_SYNC
		},
};

static void rspamd_control_ignore_io_handler (int fd, short what, void *ud);

static void
rspamd_control_stop_pending (struct rspamd_control_reply_elt *elt)
{
	GHashTable *htb;
	/* It stops event and frees hash */
	htb = elt->pending_elts;
	g_hash_table_remove (elt->pending_elts, elt);
	/* Release hash reference */
	g_hash_table_unref (htb);
}

void
rspamd_control_send_error (struct rspamd_control_session *session,
		gint code, const gchar *error_msg, ...)
{
	struct rspamd_http_message *msg;
	rspamd_fstring_t *reply;
	va_list args;

	msg = rspamd_http_new_message (HTTP_RESPONSE);

	va_start (args, error_msg);
	msg->status = rspamd_fstring_new ();
	rspamd_vprintf_fstring (&msg->status, error_msg, args);
	va_end (args);

	msg->date = time (NULL);
	msg->code = code;
	reply = rspamd_fstring_sized_new (msg->status->len + 16);
	rspamd_printf_fstring (&reply, "{\"error\":\"%V\"}", msg->status);
	rspamd_http_message_set_body_from_fstring_steal (msg, reply);
	rspamd_http_connection_reset (session->conn);
	rspamd_http_connection_write_message (session->conn,
			msg,
			NULL,
			"application/json",
			session,
			io_timeout);
}

static void
rspamd_control_send_ucl (struct rspamd_control_session *session,
		ucl_object_t *obj)
{
	struct rspamd_http_message *msg;
	rspamd_fstring_t *reply;

	msg = rspamd_http_new_message (HTTP_RESPONSE);
	msg->date = time (NULL);
	msg->code = 200;
	msg->status = rspamd_fstring_new_init ("OK", 2);
	reply = rspamd_fstring_sized_new (BUFSIZ);
	rspamd_ucl_emit_fstring (obj, UCL_EMIT_JSON_COMPACT, &reply);
	rspamd_http_message_set_body_from_fstring_steal (msg, reply);
	rspamd_http_connection_reset (session->conn);
	rspamd_http_connection_write_message (session->conn,
			msg,
			NULL,
			"application/json",
			session,
			io_timeout);
}

static void
rspamd_control_connection_close (struct rspamd_control_session *session)
{
	struct rspamd_control_reply_elt *elt, *telt;
	struct rspamd_main *rspamd_main;

	rspamd_main = session->rspamd_main;
	msg_info_main ("finished connection from %s",
			rspamd_inet_address_to_string (session->addr));

	DL_FOREACH_SAFE (session->replies, elt, telt) {
		rspamd_control_stop_pending (elt);
	}

	rspamd_inet_address_free (session->addr);
	rspamd_http_connection_unref (session->conn);
	close (session->fd);
	g_free (session);
}

static void
rspamd_control_write_reply (struct rspamd_control_session *session)
{
	ucl_object_t *rep, *cur, *workers;
	struct rspamd_control_reply_elt *elt;
	gchar tmpbuf[64];
	gdouble total_utime = 0, total_systime = 0;
	struct ucl_parser *parser;
	guint total_conns = 0;

	rep = ucl_object_typed_new (UCL_OBJECT);
	workers = ucl_object_typed_new (UCL_OBJECT);

	DL_FOREACH (session->replies, elt) {
		/* Skip incompatible worker for fuzzy_stat */
		if ((session->cmd.type == RSPAMD_CONTROL_FUZZY_STAT ||
			session->cmd.type == RSPAMD_CONTROL_FUZZY_SYNC) &&
				elt->wrk_type != g_quark_from_static_string ("fuzzy")) {
			continue;
		}

		rspamd_snprintf (tmpbuf, sizeof (tmpbuf), "%P", elt->wrk_pid);
		cur = ucl_object_typed_new (UCL_OBJECT);

		ucl_object_insert_key (cur, ucl_object_fromstring (g_quark_to_string (
				elt->wrk_type)), "type", 0, false);

		switch (session->cmd.type) {
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

			total_utime += elt->reply.reply.stat.utime;
			total_systime += elt->reply.reply.stat.systime;
			total_conns += elt->reply.reply.stat.conns;

			break;

		case RSPAMD_CONTROL_RELOAD:
			ucl_object_insert_key (cur, ucl_object_fromint (
					elt->reply.reply.reload.status), "status", 0, false);
			break;
		case RSPAMD_CONTROL_RECOMPILE:
			ucl_object_insert_key (cur, ucl_object_fromint (
					elt->reply.reply.recompile.status), "status", 0, false);
			break;
		case RSPAMD_CONTROL_RERESOLVE:
			ucl_object_insert_key (cur, ucl_object_fromint (
					elt->reply.reply.reresolve.status), "status", 0, false);
			break;
		case RSPAMD_CONTROL_FUZZY_STAT:
			if (elt->attached_fd != -1) {
				/* We have some data to parse */
				parser = ucl_parser_new (0);
				ucl_object_insert_key (cur,
						ucl_object_fromint (
								elt->reply.reply.fuzzy_stat.status),
						"status",
						0,
						false);

				if (ucl_parser_add_fd (parser, elt->attached_fd)) {
					ucl_object_insert_key (cur, ucl_parser_get_object (parser),
							"data", 0, false);
					ucl_parser_free (parser);
				}
				else {

					ucl_object_insert_key (cur, ucl_object_fromstring (
							ucl_parser_get_error (parser)), "error", 0, false);

					ucl_parser_free (parser);
				}

				ucl_object_insert_key (cur,
						ucl_object_fromlstring (
								elt->reply.reply.fuzzy_stat.storage_id,
								MEMPOOL_UID_LEN - 1),
						"id",
						0,
						false);
			}
			else {
				ucl_object_insert_key (cur,
						ucl_object_fromstring ("missing file"),
						"error",
						0,
						false);
				ucl_object_insert_key (cur,
						ucl_object_fromint (
								elt->reply.reply.fuzzy_stat.status),
						"status",
						0,
						false);
			}
			break;
		case RSPAMD_CONTROL_FUZZY_SYNC:
			ucl_object_insert_key (cur, ucl_object_fromint (
					elt->reply.reply.fuzzy_sync.status), "status", 0, false);
			break;
		default:
			break;
		}

		if (elt->attached_fd != -1) {
			close (elt->attached_fd);
			elt->attached_fd = -1;
		}

		ucl_object_insert_key (workers, cur, tmpbuf, 0, true);
	}

	ucl_object_insert_key (rep, workers, "workers", 0, false);

	if (session->cmd.type == RSPAMD_CONTROL_STAT) {
		/* Total stats */
		cur = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (cur, ucl_object_fromint (
				total_conns), "conns", 0, false);
		ucl_object_insert_key (cur, ucl_object_fromdouble (
				total_utime), "utime", 0, false);
		ucl_object_insert_key (cur, ucl_object_fromdouble (
				total_systime), "systime", 0, false);

		ucl_object_insert_key (rep, cur, "total", 0, false);
	}

	rspamd_control_send_ucl (session, rep);
	ucl_object_unref (rep);
}

static void
rspamd_control_wrk_io (gint fd, short what, gpointer ud)
{
	struct rspamd_control_reply_elt *elt = ud;
	struct rspamd_control_session *session;
	guchar fdspace[CMSG_SPACE(sizeof (int))];
	struct iovec iov;
	struct msghdr msg;
	gssize r;

	session = elt->ud;
	elt->attached_fd = -1;

	if (what == EV_READ) {
		iov.iov_base = &elt->reply;
		iov.iov_len = sizeof (elt->reply);
		memset (&msg, 0, sizeof (msg));
		msg.msg_control = fdspace;
		msg.msg_controllen = sizeof (fdspace);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		r = recvmsg (fd, &msg, 0);
		if (r == -1) {
			msg_err ("cannot read reply from the worker %P (%s): %s",
					elt->wrk_pid, g_quark_to_string (elt->wrk_type),
					strerror (errno));
		}
		else if (r >= (gssize)sizeof (elt->reply)) {
			if (msg.msg_controllen >= CMSG_LEN (sizeof (int))) {
				elt->attached_fd = *(int *) CMSG_DATA(CMSG_FIRSTHDR (&msg));
			}
		}
	}
	else {
		/* Timeout waiting */
		msg_warn ("timeout waiting reply from %P (%s)",
				elt->wrk_pid, g_quark_to_string (elt->wrk_type));
	}

	session->replies_remain --;
	rspamd_ev_watcher_stop (session->event_loop,
			&elt->ev);

	if (session->replies_remain == 0) {
		rspamd_control_write_reply (session);
	}
}

static void
rspamd_control_error_handler (struct rspamd_http_connection *conn, GError *err)
{
	struct rspamd_control_session *session = conn->ud;
	struct rspamd_main *rspamd_main;

	rspamd_main = session->rspamd_main;

	if (!session->is_reply) {
		msg_info_main ("abnormally closing control connection: %e", err);
		session->is_reply = TRUE;
		rspamd_control_send_error (session, err->code, "%s", err->message);
	}
	else {
		rspamd_control_connection_close (session);
	}
}

void
rspamd_pending_control_free (gpointer p)
{
	struct rspamd_control_reply_elt *rep_elt = (struct rspamd_control_reply_elt *)p;

	rspamd_ev_watcher_stop (rep_elt->event_loop, &rep_elt->ev);
	g_free (rep_elt);
}

static struct rspamd_control_reply_elt *
rspamd_control_broadcast_cmd (struct rspamd_main *rspamd_main,
							  struct rspamd_control_command *cmd,
							  gint attached_fd,
							  rspamd_ev_cb handler,
							  gpointer ud,
							  pid_t except_pid)
{
	GHashTableIter it;
	struct rspamd_worker *wrk;
	struct rspamd_control_reply_elt *rep_elt, *res = NULL;
	gpointer k, v;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	guchar fdspace[CMSG_SPACE(sizeof (int))];
	gssize r;

	g_hash_table_iter_init (&it, rspamd_main->workers);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		wrk = v;

		/* No control pipe */
		if (wrk->control_pipe[0] == -1) {
			continue;
		}

		if (except_pid != 0 && wrk->pid == except_pid) {
			continue;
		}

		/* Worker is terminating, do not bother sending stuff */
		if (wrk->state == rspamd_worker_state_terminating) {
			continue;
		}

		memset (&msg, 0, sizeof (msg));

		/* Attach fd to the message */
		if (attached_fd != -1) {
			memset (fdspace, 0, sizeof (fdspace));
			msg.msg_control = fdspace;
			msg.msg_controllen = sizeof (fdspace);
			cmsg = CMSG_FIRSTHDR (&msg);
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SCM_RIGHTS;
			cmsg->cmsg_len = CMSG_LEN (sizeof (int));
			memcpy (CMSG_DATA (cmsg), &attached_fd, sizeof (int));
		}

		iov.iov_base = cmd;
		iov.iov_len = sizeof (*cmd);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		r = sendmsg (wrk->control_pipe[0], &msg, 0);

		if (r == sizeof (*cmd)) {
			rep_elt = g_malloc0 (sizeof (*rep_elt));
			rep_elt->wrk_pid = wrk->pid;
			rep_elt->wrk_type = wrk->type;
			rep_elt->event_loop = rspamd_main->event_loop;
			rep_elt->ud = ud;
			rep_elt->pending_elts = g_hash_table_ref (wrk->control_events_pending);
			rspamd_ev_watcher_init (&rep_elt->ev,
					wrk->control_pipe[0],
					EV_READ, handler,
					rep_elt);
			rspamd_ev_watcher_start (rspamd_main->event_loop,
					&rep_elt->ev, worker_io_timeout);
			g_hash_table_insert (wrk->control_events_pending, rep_elt, rep_elt);

			DL_APPEND (res, rep_elt);
		}
		else {
			msg_err_main ("cannot write command %d(%z) to the worker %P(%s), fd: %d: %s",
					(int)cmd->type, iov.iov_len,
					wrk->pid,
					g_quark_to_string (wrk->type),
					wrk->control_pipe[0],
					strerror (errno));
		}
	}

	return res;
}

void
rspamd_control_broadcast_srv_cmd (struct rspamd_main *rspamd_main,
								  struct rspamd_control_command *cmd,
								  pid_t except_pid)
{
	rspamd_control_broadcast_cmd (rspamd_main, cmd, -1,
			rspamd_control_ignore_io_handler, NULL, except_pid);
}

static gint
rspamd_control_finish_handler (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg)
{
	struct rspamd_control_session *session = conn->ud;
	rspamd_ftok_t srch;
	guint i;
	gboolean found = FALSE;
	struct rspamd_control_reply_elt *cur;


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
			session->replies = rspamd_control_broadcast_cmd (
					session->rspamd_main, &session->cmd, -1,
					rspamd_control_wrk_io, session, 0);

			DL_FOREACH (session->replies, cur) {
				session->replies_remain ++;
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
		gint fd, rspamd_inet_addr_t *addr)
{
	struct rspamd_control_session *session;

	session = g_malloc0 (sizeof (*session));

	session->fd = fd;
	session->conn = rspamd_http_connection_new_server (rspamd_main->http_ctx,
			fd,
			NULL,
			rspamd_control_error_handler,
			rspamd_control_finish_handler,
			0);
	session->rspamd_main = rspamd_main;
	session->addr = addr;
	session->event_loop = rspamd_main->event_loop;
	rspamd_http_connection_read_message (session->conn, session,
			io_timeout);
}

struct rspamd_worker_control_data {
	ev_io io_ev;
	struct rspamd_worker *worker;
	struct ev_loop *ev_base;
	struct {
		rspamd_worker_control_handler handler;
		gpointer ud;
	} handlers[RSPAMD_CONTROL_MAX];
};

static void
rspamd_control_default_cmd_handler (gint fd,
		gint attached_fd,
		struct rspamd_worker_control_data *cd,
		struct rspamd_control_command *cmd)
{
	struct rspamd_control_reply rep;
	gssize r;
	struct rusage rusg;
	struct rspamd_config *cfg;
	struct rspamd_main *rspamd_main;

	memset (&rep, 0, sizeof (rep));
	rep.type = cmd->type;
	rspamd_main = cd->worker->srv;

	switch (cmd->type) {
	case RSPAMD_CONTROL_STAT:
		if (getrusage (RUSAGE_SELF, &rusg) == -1) {
			msg_err_main ("cannot get rusage stats: %s",
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
	case RSPAMD_CONTROL_RECOMPILE:
	case RSPAMD_CONTROL_HYPERSCAN_LOADED:
	case RSPAMD_CONTROL_MONITORED_CHANGE:
	case RSPAMD_CONTROL_FUZZY_STAT:
	case RSPAMD_CONTROL_FUZZY_SYNC:
	case RSPAMD_CONTROL_LOG_PIPE:
	case RSPAMD_CONTROL_CHILD_CHANGE:
		break;
	case RSPAMD_CONTROL_RERESOLVE:
		if (cd->worker->srv->cfg) {
			REF_RETAIN (cd->worker->srv->cfg);
			cfg = cd->worker->srv->cfg;

			if (cfg->ups_ctx) {
				msg_info_config ("reresolving upstreams");
				rspamd_upstream_reresolve (cfg->ups_ctx);
			}

			rep.reply.reresolve.status = 0;
			REF_RELEASE (cfg);
		}
		else {
			rep.reply.reresolve.status = EINVAL;
		}
		break;
	default:
		break;
	}

	r = write (fd, &rep, sizeof (rep));

	if (r != sizeof (rep)) {
		msg_err_main ("cannot write reply to the control socket: %s",
				strerror (errno));
	}

	if (attached_fd != -1) {
		close (attached_fd);
	}
}

static void
rspamd_control_default_worker_handler (EV_P_ ev_io *w, int revents)
{
	struct rspamd_worker_control_data *cd =
			(struct rspamd_worker_control_data *)w->data;
	static struct rspamd_control_command cmd;
	static struct msghdr msg;
	static struct iovec iov;
	static guchar fdspace[CMSG_SPACE(sizeof (int))];
	gint rfd = -1;
	gssize r;

	iov.iov_base = &cmd;
	iov.iov_len = sizeof (cmd);
	memset (&msg, 0, sizeof (msg));
	msg.msg_control = fdspace;
	msg.msg_controllen = sizeof (fdspace);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	r = recvmsg (w->fd, &msg, 0);

	if (r == -1) {
		if (errno != EAGAIN && errno != EINTR) {
			if (errno != ECONNRESET) {
				/*
				 * In case of connection reset it means that main process
				 * has died, so do not pollute logs
				 */
				msg_err ("cannot read request from the control socket: %s",
						strerror (errno));
			}
			ev_io_stop (cd->ev_base, &cd->io_ev);
			close (w->fd);
		}
	}
	else if (r < (gint)sizeof (cmd)) {
		msg_err ("short read of control command: %d of %d", (gint)r,
				(gint)sizeof (cmd));

		if (r == 0) {
			ev_io_stop (cd->ev_base, &cd->io_ev);
			close (w->fd);
		}
 	}
	else if ((gint)cmd.type >= 0 && cmd.type < RSPAMD_CONTROL_MAX) {

		if (msg.msg_controllen >= CMSG_LEN (sizeof (int))) {
			rfd = *(int *) CMSG_DATA(CMSG_FIRSTHDR (&msg));
		}

		if (cd->handlers[cmd.type].handler) {
			cd->handlers[cmd.type].handler (cd->worker->srv,
					cd->worker,
					w->fd,
					rfd,
					&cmd,
					cd->handlers[cmd.type].ud);
		}
		else {
			rspamd_control_default_cmd_handler (w->fd, rfd, cd, &cmd);
		}
	}
	else {
		msg_err ("unknown command: %d", (gint)cmd.type);
	}
}

void
rspamd_control_worker_add_default_cmd_handlers (struct rspamd_worker *worker,
												struct ev_loop *ev_base)
{
	struct rspamd_worker_control_data *cd;

	cd = g_malloc0 (sizeof (*cd));
	cd->worker = worker;
	cd->ev_base = ev_base;

	cd->io_ev.data = cd;
	ev_io_init (&cd->io_ev, rspamd_control_default_worker_handler,
			worker->control_pipe[1], EV_READ);
	ev_io_start (ev_base, &cd->io_ev);

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

struct rspamd_srv_reply_data {
	struct rspamd_worker *worker;
	struct rspamd_main *srv;
	gint fd;
	struct rspamd_srv_reply rep;
};

static void
rspamd_control_ignore_io_handler (int fd, short what, void *ud)
{
	struct rspamd_control_reply_elt *elt =
			(struct rspamd_control_reply_elt *)ud;

	struct rspamd_control_reply rep;

	/* At this point we just ignore replies from the workers */
	if (read (fd, &rep, sizeof (rep)) == -1) {
		msg_debug("cannot read %d bytes: %s", (int)sizeof(rep), strerror(errno));
	}
	rspamd_control_stop_pending (elt);
}

static void
rspamd_control_log_pipe_io_handler (int fd, short what, void *ud)
{
	struct rspamd_control_reply_elt *elt =
			(struct rspamd_control_reply_elt *)ud;
	struct rspamd_control_reply rep;

	/* At this point we just ignore replies from the workers */
	(void) !read (fd, &rep, sizeof (rep));
	rspamd_control_stop_pending (elt);
}

static void
rspamd_control_handle_on_fork (struct rspamd_srv_command *cmd,
		struct rspamd_main *srv)
{
	struct rspamd_worker *parent, *child;

	parent = g_hash_table_lookup (srv->workers,
			GSIZE_TO_POINTER (cmd->cmd.on_fork.ppid));

	if (parent == NULL) {
		msg_err ("cannot find parent for a forked process %P (%P child)",
				cmd->cmd.on_fork.ppid, cmd->cmd.on_fork.cpid);

		return;
	}

	if (cmd->cmd.on_fork.state == child_dead) {
		/* We need to remove stale worker */
		child = g_hash_table_lookup (srv->workers,
				GSIZE_TO_POINTER (cmd->cmd.on_fork.cpid));

		if (child == NULL) {
			msg_err ("cannot find child for a forked process %P (%P parent)",
					cmd->cmd.on_fork.cpid, cmd->cmd.on_fork.ppid);

			return;
		}

		REF_RELEASE (child->cf);
		g_hash_table_remove (srv->workers,
				GSIZE_TO_POINTER (cmd->cmd.on_fork.cpid));
		g_hash_table_unref (child->control_events_pending);
		g_free (child);
	}
	else {
		child = g_malloc0 (sizeof (struct rspamd_worker));
		child->srv = srv;
		child->type = parent->type;
		child->pid = cmd->cmd.on_fork.cpid;
		child->srv_pipe[0] = -1;
		child->srv_pipe[1] = -1;
		child->control_pipe[0] = -1;
		child->control_pipe[1] = -1;
		child->cf = parent->cf;
		child->ppid = parent->pid;
		REF_RETAIN (child->cf);
		child->control_events_pending = g_hash_table_new_full (g_direct_hash, g_direct_equal,
				NULL, rspamd_pending_control_free);
		g_hash_table_insert (srv->workers,
				GSIZE_TO_POINTER (cmd->cmd.on_fork.cpid), child);
	}
}

static void
rspamd_fill_health_reply (struct rspamd_main *srv, struct rspamd_srv_reply *rep)
{
	GHashTableIter it;
	gpointer k, v;

	memset (&rep->reply.health, 0, sizeof (rep->reply));
	g_hash_table_iter_init (&it, srv->workers);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		struct rspamd_worker *wrk = (struct rspamd_worker *)v;

		if (wrk->hb.nbeats < 0) {
			rep->reply.health.workers_hb_lost ++;
		}
		else if (rspamd_worker_is_scanner (wrk)) {
			rep->reply.health.scanners_count ++;
		}

		rep->reply.health.workers_count ++;
	}

	rep->reply.status = (g_hash_table_size (srv->workers) > 0);
}


static void
rspamd_srv_handler (EV_P_ ev_io *w, int revents)
{
	struct rspamd_worker *worker;
	static struct rspamd_srv_command cmd;
	struct rspamd_main *srv;
	struct rspamd_srv_reply_data *rdata;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	static struct iovec iov;
	static guchar fdspace[CMSG_SPACE(sizeof (int))];
	gint *spair, rfd = -1;
	gchar *nid;
	struct rspamd_control_command wcmd;
	gssize r;

	if (revents == EV_READ) {
		worker = (struct rspamd_worker *)w->data;
		srv = worker->srv;
		iov.iov_base = &cmd;
		iov.iov_len = sizeof (cmd);
		memset (&msg, 0, sizeof (msg));
		msg.msg_control = fdspace;
		msg.msg_controllen = sizeof (fdspace);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		r = recvmsg (w->fd, &msg, 0);

		if (r == -1) {
			msg_err ("cannot read from worker's srv pipe: %s",
					strerror (errno));
		}
		else if (r == 0) {
			/*
			 * Usually this means that a worker is dead, so do not try to read
			 * anything
			 */
			ev_io_stop (EV_A_ w);
		}
		else if (r != sizeof (cmd)) {
			msg_err ("cannot read from worker's srv pipe incomplete command: %d",
					(gint) r);
		}
		else {
			rdata = g_malloc0 (sizeof (*rdata));
			rdata->worker = worker;
			rdata->srv = srv;
			rdata->rep.id = cmd.id;
			rdata->rep.type = cmd.type;
			rdata->fd = -1;
			worker->tmp_data = rdata;

			if (msg.msg_controllen >= CMSG_LEN (sizeof (int))) {
				rfd = *(int *) CMSG_DATA(CMSG_FIRSTHDR (&msg));
			}

			switch (cmd.type) {
			case RSPAMD_SRV_SOCKETPAIR:
				spair = g_hash_table_lookup (srv->spairs, cmd.cmd.spair.pair_id);
				if (spair == NULL) {
					spair = g_malloc (sizeof (gint) * 2);

					if (rspamd_socketpair (spair, cmd.cmd.spair.af) == -1) {
						rdata->rep.reply.spair.code = errno;
						msg_err ("cannot create socket pair: %s", strerror (errno));
					}
					else {
						nid = g_malloc (sizeof (cmd.cmd.spair.pair_id));
						memcpy (nid, cmd.cmd.spair.pair_id,
								sizeof (cmd.cmd.spair.pair_id));
						g_hash_table_insert (srv->spairs, nid, spair);
						rdata->rep.reply.spair.code = 0;
						rdata->fd = cmd.cmd.spair.pair_num ? spair[1] : spair[0];
					}
				}
				else {
					rdata->rep.reply.spair.code = 0;
					rdata->fd = cmd.cmd.spair.pair_num ? spair[1] : spair[0];
				}
				break;
			case RSPAMD_SRV_HYPERSCAN_LOADED:
				/* Load RE cache to provide it for new forks */
				if (rspamd_re_cache_is_hs_loaded (srv->cfg->re_cache) != RSPAMD_HYPERSCAN_LOADED_FULL ||
						cmd.cmd.hs_loaded.forced) {
					rspamd_re_cache_load_hyperscan (
							srv->cfg->re_cache,
							cmd.cmd.hs_loaded.cache_dir,
							false);
				}

				/* Broadcast command to all workers */
				memset (&wcmd, 0, sizeof (wcmd));
				wcmd.type = RSPAMD_CONTROL_HYPERSCAN_LOADED;
				rspamd_strlcpy (wcmd.cmd.hs_loaded.cache_dir,
						cmd.cmd.hs_loaded.cache_dir,
						sizeof (wcmd.cmd.hs_loaded.cache_dir));
				wcmd.cmd.hs_loaded.forced = cmd.cmd.hs_loaded.forced;
				rspamd_control_broadcast_cmd (srv, &wcmd, rfd,
						rspamd_control_ignore_io_handler, NULL, worker->pid);
				break;
			case RSPAMD_SRV_MONITORED_CHANGE:
				/* Broadcast command to all workers */
				memset (&wcmd, 0, sizeof (wcmd));
				wcmd.type = RSPAMD_CONTROL_MONITORED_CHANGE;
				rspamd_strlcpy (wcmd.cmd.monitored_change.tag,
						cmd.cmd.monitored_change.tag,
						sizeof (wcmd.cmd.monitored_change.tag));
				wcmd.cmd.monitored_change.alive = cmd.cmd.monitored_change.alive;
				wcmd.cmd.monitored_change.sender = cmd.cmd.monitored_change.sender;
				rspamd_control_broadcast_cmd (srv, &wcmd, rfd,
						rspamd_control_ignore_io_handler, NULL, 0);
				break;
			case RSPAMD_SRV_LOG_PIPE:
				memset (&wcmd, 0, sizeof (wcmd));
				wcmd.type = RSPAMD_CONTROL_LOG_PIPE;
				wcmd.cmd.log_pipe.type = cmd.cmd.log_pipe.type;
				rspamd_control_broadcast_cmd (srv, &wcmd, rfd,
						rspamd_control_log_pipe_io_handler, NULL, 0);
				break;
			case RSPAMD_SRV_ON_FORK:
				rdata->rep.reply.on_fork.status = 0;
				rspamd_control_handle_on_fork (&cmd, srv);
				break;
			case RSPAMD_SRV_HEARTBEAT:
				worker->hb.last_event = ev_time ();
				rdata->rep.reply.heartbeat.status = 0;
				break;
			case RSPAMD_SRV_HEALTH:
				rspamd_fill_health_reply (srv, &rdata->rep);
				break;
			default:
				msg_err ("unknown command type: %d", cmd.type);
				break;
			}

			if (rfd != -1) {
				/* Close our copy to avoid descriptors leak */
				close (rfd);
			}

			/* Now plan write event and send data back */
			w->data = rdata;
			ev_io_stop (EV_A_ w);
			ev_io_set (w, worker->srv_pipe[0], EV_WRITE);
			ev_io_start (EV_A_ w);
		}
	}
	else if (revents == EV_WRITE) {
		rdata = (struct rspamd_srv_reply_data *)w->data;
		worker = rdata->worker;
		worker->tmp_data = NULL; /* Avoid race */
		srv = rdata->srv;

		memset (&msg, 0, sizeof (msg));

		/* Attach fd to the message */
		if (rdata->fd != -1) {
			memset (fdspace, 0, sizeof (fdspace));
			msg.msg_control = fdspace;
			msg.msg_controllen = sizeof (fdspace);
			cmsg = CMSG_FIRSTHDR (&msg);
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SCM_RIGHTS;
			cmsg->cmsg_len = CMSG_LEN (sizeof (int));
			memcpy (CMSG_DATA (cmsg), &rdata->fd, sizeof (int));
		}

		iov.iov_base = &rdata->rep;
		iov.iov_len = sizeof (rdata->rep);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		r = sendmsg (w->fd, &msg, 0);

		if (r == -1) {
			msg_err ("cannot write to worker's srv pipe: %s",
					strerror (errno));
		}

		g_free (rdata);
		w->data = worker;
		ev_io_stop (EV_A_ w);
		ev_io_set (w, worker->srv_pipe[0], EV_READ);
		ev_io_start (EV_A_ w);
	}
}

void
rspamd_srv_start_watching (struct rspamd_main *srv,
		struct rspamd_worker *worker,
		struct ev_loop *ev_base)
{
	g_assert (worker != NULL);

	worker->tmp_data = NULL;
	worker->srv_ev.data = worker;
	ev_io_init (&worker->srv_ev, rspamd_srv_handler, worker->srv_pipe[0], EV_READ);
	ev_io_start (ev_base, &worker->srv_ev);
}

struct rspamd_srv_request_data {
	struct rspamd_worker *worker;
	struct rspamd_srv_command cmd;
	gint attached_fd;
	struct rspamd_srv_reply rep;
	rspamd_srv_reply_handler handler;
	ev_io io_ev;
	gpointer ud;
};

static void
rspamd_srv_request_handler (EV_P_ ev_io *w, int revents)
{
	struct rspamd_srv_request_data *rd = (struct rspamd_srv_request_data *)w->data;
	struct msghdr msg;
	struct iovec iov;
	guchar fdspace[CMSG_SPACE(sizeof (int))];
	struct cmsghdr *cmsg;
	gssize r;
	gint rfd = -1;

	if (revents == EV_WRITE) {
		/* Send request to server */
		memset (&msg, 0, sizeof (msg));

		/* Attach fd to the message */
		if (rd->attached_fd != -1) {
			memset (fdspace, 0, sizeof (fdspace));
			msg.msg_control = fdspace;
			msg.msg_controllen = sizeof (fdspace);
			cmsg = CMSG_FIRSTHDR (&msg);
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SCM_RIGHTS;
			cmsg->cmsg_len = CMSG_LEN (sizeof (int));
			memcpy (CMSG_DATA (cmsg), &rd->attached_fd, sizeof (int));
		}

		iov.iov_base = &rd->cmd;
		iov.iov_len = sizeof (rd->cmd);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		r = sendmsg (w->fd, &msg, 0);

		if (r == -1) {
			msg_err ("cannot write to server pipe: %s", strerror (errno));
			goto cleanup;
		}

		ev_io_stop (EV_A_ w);
		ev_io_set (w, rd->worker->srv_pipe[1], EV_READ);
		ev_io_start (EV_A_ w);
	}
	else {
		iov.iov_base = &rd->rep;
		iov.iov_len = sizeof (rd->rep);
		memset (&msg, 0, sizeof (msg));
		msg.msg_control = fdspace;
		msg.msg_controllen = sizeof (fdspace);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		r = recvmsg (w->fd, &msg, 0);

		if (r == -1) {
			msg_err ("cannot read from server pipe: %s", strerror (errno));
			goto cleanup;
		}

		if (r < (gint)sizeof (rd->rep)) {
			msg_err ("cannot read from server pipe, invalid length: %d",
					(gint)r);
			goto cleanup;
		}

		if (msg.msg_controllen >= CMSG_LEN (sizeof (int))) {
			rfd = *(int *) CMSG_DATA(CMSG_FIRSTHDR (&msg));
		}

		goto cleanup;
	}

	return;

cleanup:

	if (rd->handler) {
		rd->handler (rd->worker, &rd->rep, rfd, rd->ud);
	}

	ev_io_stop (EV_A_ w);
	g_free (rd);
}

void
rspamd_srv_send_command (struct rspamd_worker *worker,
		struct ev_loop *ev_base,
		struct rspamd_srv_command *cmd,
		gint attached_fd,
		rspamd_srv_reply_handler handler,
		gpointer ud)
{
	struct rspamd_srv_request_data *rd;

	g_assert (cmd != NULL);
	g_assert (worker != NULL);

	rd = g_malloc0 (sizeof (*rd));
	cmd->id = ottery_rand_uint64 ();
	memcpy (&rd->cmd, cmd, sizeof (rd->cmd));
	rd->handler = handler;
	rd->ud = ud;
	rd->worker = worker;
	rd->rep.id = cmd->id;
	rd->rep.type = cmd->type;
	rd->attached_fd = attached_fd;

	rd->io_ev.data = rd;
	ev_io_init (&rd->io_ev, rspamd_srv_request_handler,
			rd->worker->srv_pipe[1], EV_WRITE);
	ev_io_start (ev_base, &rd->io_ev);
}

enum rspamd_control_type
rspamd_control_command_from_string (const gchar *str)
{
	enum rspamd_control_type ret = RSPAMD_CONTROL_MAX;

	if (!str) {
		return ret;
	}

	if (g_ascii_strcasecmp (str, "hyperscan_loaded") == 0) {
		ret = RSPAMD_CONTROL_HYPERSCAN_LOADED;
	}
	else if (g_ascii_strcasecmp (str, "stat") == 0) {
		ret = RSPAMD_CONTROL_STAT;
	}
	else if (g_ascii_strcasecmp (str, "reload") == 0) {
		ret = RSPAMD_CONTROL_RELOAD;
	}
	else if (g_ascii_strcasecmp (str, "reresolve") == 0) {
		ret = RSPAMD_CONTROL_RERESOLVE;
	}
	else if (g_ascii_strcasecmp (str, "recompile") == 0) {
		ret = RSPAMD_CONTROL_RECOMPILE;
	}
	else if (g_ascii_strcasecmp (str, "log_pipe") == 0) {
		ret = RSPAMD_CONTROL_LOG_PIPE;
	}
	else if (g_ascii_strcasecmp (str, "fuzzy_stat") == 0) {
		ret = RSPAMD_CONTROL_FUZZY_STAT;
	}
	else if (g_ascii_strcasecmp (str, "fuzzy_sync") == 0) {
		ret = RSPAMD_CONTROL_FUZZY_SYNC;
	}
	else if (g_ascii_strcasecmp (str, "monitored_change") == 0) {
		ret = RSPAMD_CONTROL_MONITORED_CHANGE;
	}
	else if (g_ascii_strcasecmp (str, "child_change") == 0) {
		ret = RSPAMD_CONTROL_CHILD_CHANGE;
	}

	return ret;
}

const gchar *
rspamd_control_command_to_string (enum rspamd_control_type cmd)
{
	const gchar *reply = "unknown";

	switch (cmd) {
	case RSPAMD_CONTROL_STAT:
		reply = "stat";
		break;
	case RSPAMD_CONTROL_RELOAD:
		reply = "reload";
		break;
	case RSPAMD_CONTROL_RERESOLVE:
		reply = "reresolve";
		break;
	case RSPAMD_CONTROL_RECOMPILE:
		reply = "recompile";
		break;
	case RSPAMD_CONTROL_HYPERSCAN_LOADED:
		reply = "hyperscan_loaded";
		break;
	case RSPAMD_CONTROL_LOG_PIPE:
		reply = "log_pipe";
		break;
	case RSPAMD_CONTROL_FUZZY_STAT:
		reply = "fuzzy_stat";
		break;
	case RSPAMD_CONTROL_FUZZY_SYNC:
		reply = "fuzzy_sync";
		break;
	case RSPAMD_CONTROL_MONITORED_CHANGE:
		reply = "monitored_change";
		break;
	case RSPAMD_CONTROL_CHILD_CHANGE:
		reply = "child_change";
		break;
	default:
		break;
	}

	return reply;
}
