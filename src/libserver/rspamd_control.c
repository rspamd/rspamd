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
#include "libutil/http.h"
#include "libutil/http_private.h"
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
	gpointer ud;
	gint attached_fd;
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
			session->fd,
			&io_timeout,
			session->rspamd_main->ev_base);
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
				elt->wrk->type != g_quark_from_static_string ("fuzzy")) {
			continue;
		}

		rspamd_snprintf (tmpbuf, sizeof (tmpbuf), "%P", elt->wrk->pid);
		cur = ucl_object_typed_new (UCL_OBJECT);

		ucl_object_insert_key (cur, ucl_object_fromstring (g_quark_to_string (
				elt->wrk->type)), "type", 0, false);

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
					elt->wrk->pid, g_quark_to_string (elt->wrk->type),
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
				elt->wrk->pid, g_quark_to_string (elt->wrk->type));
	}

	session->replies_remain --;
	event_del (&elt->io_ev);

	if (session->replies_remain == 0) {
		rspamd_control_write_reply (session);
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

static struct rspamd_control_reply_elt *
rspamd_control_broadcast_cmd (struct rspamd_main *rspamd_main,
		struct rspamd_control_command *cmd,
		gint attached_fd,
		void (*handler) (int, short, void *), gpointer ud)
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

			rep_elt = g_slice_alloc0 (sizeof (*rep_elt));
			rep_elt->wrk = wrk;
			rep_elt->ud = ud;
			event_set (&rep_elt->io_ev, wrk->control_pipe[0],
					EV_READ | EV_PERSIST, handler,
					rep_elt);
			event_base_set (rspamd_main->ev_base,
					&rep_elt->io_ev);
			event_add (&rep_elt->io_ev, &worker_io_timeout);

			DL_APPEND (res, rep_elt);
		}
		else {
			msg_err ("cannot write request to the worker %P (%s): %s",
					wrk->pid, g_quark_to_string (wrk->type), strerror (errno));
		}
	}

	return res;
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
					rspamd_control_wrk_io, session);

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
		gint fd)
{
	struct rspamd_control_session *session;

	session = g_slice_alloc0 (sizeof (*session));

	session->fd = fd;
	session->conn = rspamd_http_connection_new (NULL,
			rspamd_control_error_handler,
			rspamd_control_finish_handler,
			0,
			RSPAMD_HTTP_SERVER,
			NULL,
			NULL);
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
		gint attached_fd,
		struct rspamd_worker_control_data *cd,
		struct rspamd_control_command *cmd)
{
	struct rspamd_control_reply rep;
	gssize r;
	struct rusage rusg;
	struct rspamd_config *cfg;

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
	case RSPAMD_CONTROL_RECOMPILE:
	case RSPAMD_CONTROL_HYPERSCAN_LOADED:
	case RSPAMD_CONTROL_FUZZY_STAT:
	case RSPAMD_CONTROL_FUZZY_SYNC:
	case RSPAMD_CONTROL_LOG_PIPE:
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
		msg_err ("cannot write reply to the control socket: %s",
				strerror (errno));
	}

	if (attached_fd != -1) {
		close (attached_fd);
	}
}

static void
rspamd_control_default_worker_handler (gint fd, short what, gpointer ud)
{
	struct rspamd_worker_control_data *cd = ud;
	struct rspamd_control_command cmd;
	struct msghdr msg;
	struct iovec iov;
	guchar fdspace[CMSG_SPACE(sizeof (int))];
	gint rfd = -1;
	gssize r;

	iov.iov_base = &cmd;
	iov.iov_len = sizeof (cmd);
	memset (&msg, 0, sizeof (msg));
	msg.msg_control = fdspace;
	msg.msg_controllen = sizeof (fdspace);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	r = recvmsg (fd, &msg, 0);

	if (r == -1) {
		msg_err ("cannot read request from the control socket: %s",
				strerror (errno));

		if (errno != EAGAIN && errno != EINTR) {
			event_del (&cd->io_ev);
			close (fd);
		}
	}
	else if (r < (gint)sizeof (cmd)) {
		msg_err ("short read of control command: %d of %d", (gint)r,
				(gint)sizeof (cmd));

		if (r == 0) {
			event_del (&cd->io_ev);
			close (fd);
		}
 	}
	else if ((gint)cmd.type >= 0 && cmd.type < RSPAMD_CONTROL_MAX) {

		if (msg.msg_controllen >= CMSG_LEN (sizeof (int))) {
			rfd = *(int *) CMSG_DATA(CMSG_FIRSTHDR (&msg));
		}

		if (cd->handlers[cmd.type].handler) {
			cd->handlers[cmd.type].handler (cd->worker->srv,
					cd->worker,
					fd,
					rfd,
					&cmd,
					cd->handlers[cmd.type].ud);
		}
		else {
			rspamd_control_default_cmd_handler (fd, rfd, cd, &cmd);
		}
	}
	else {
		msg_err ("unknown command: %d", (gint)cmd.type);
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

struct rspamd_srv_reply_data {
	struct rspamd_worker *worker;
	gint fd;
	struct rspamd_srv_reply rep;
};

static void
rspamd_control_hs_io_handler (gint fd, short what, gpointer ud)
{
	struct rspamd_control_reply_elt *elt = ud;
	struct rspamd_control_reply rep;

	/* At this point we just ignore replies from the workers */
	(void)read (fd, &rep, sizeof (rep));
	event_del (&elt->io_ev);
	g_slice_free1 (sizeof (*elt), elt);
}

static void
rspamd_control_log_pipe_io_handler (gint fd, short what, gpointer ud)
{
	struct rspamd_control_reply_elt *elt = ud;
	struct rspamd_control_reply rep;

	/* At this point we just ignore replies from the workers */
	(void) read (fd, &rep, sizeof (rep));
	event_del (&elt->io_ev);
	g_slice_free1 (sizeof (*elt), elt);
}

static void
rspamd_srv_handler (gint fd, short what, gpointer ud)
{
	struct rspamd_worker *worker;
	struct rspamd_srv_command cmd;
	struct rspamd_main *srv;
	struct rspamd_srv_reply_data *rdata;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	guchar fdspace[CMSG_SPACE(sizeof (int))];
	gint *spair, rfd = -1;
	gchar *nid;
	struct rspamd_control_command wcmd;
	gssize r;

	if (what == EV_READ) {
		worker = ud;
		srv = worker->srv;
		iov.iov_base = &cmd;
		iov.iov_len = sizeof (cmd);
		memset (&msg, 0, sizeof (msg));
		msg.msg_control = fdspace;
		msg.msg_controllen = sizeof (fdspace);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		r = recvmsg (fd, &msg, 0);

		if (r == -1) {
			msg_err ("cannot read from worker's srv pipe: %s",
					strerror (errno));
		}
		else if (r == 0) {
			/*
			 * Usually this means that a worker is dead, so do not try to read
			 * anything
			 */
			event_del (&worker->srv_ev);
		}
		else if (r != sizeof (cmd)) {
			msg_err ("cannot read from worker's srv pipe incomplete command: %d",
					(gint) r);
		}
		else {
			rdata = g_slice_alloc0 (sizeof (*rdata));
			rdata->worker = worker;
			rdata->rep.id = cmd.id;
			rdata->rep.type = cmd.type;
			rdata->fd = -1;
			if (msg.msg_controllen >= CMSG_LEN (sizeof (int))) {
				rfd = *(int *) CMSG_DATA(CMSG_FIRSTHDR (&msg));
			}

			switch (cmd.type) {
			case RSPAMD_SRV_SOCKETPAIR:
				spair = g_hash_table_lookup (srv->spairs, cmd.cmd.spair.pair_id);
				if (spair == NULL) {
					spair = g_malloc (sizeof (gint) * 2);

					if (rspamd_socketpair (spair) == -1) {
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
				/* Broadcast command to all workers */
				memset (&wcmd, 0, sizeof (wcmd));
				wcmd.type = RSPAMD_CONTROL_HYPERSCAN_LOADED;
				/*
				 * We assume that cache dir is shared at the same address for all
				 * workers
				 */
				wcmd.cmd.hs_loaded.cache_dir = cmd.cmd.hs_loaded.cache_dir;
				wcmd.cmd.hs_loaded.forced = cmd.cmd.hs_loaded.forced;
				rspamd_control_broadcast_cmd (srv, &wcmd, rfd,
						rspamd_control_hs_io_handler, NULL);
				break;
			case RSPAMD_SRV_LOG_PIPE:
				memset (&wcmd, 0, sizeof (wcmd));
				wcmd.type = RSPAMD_CONTROL_LOG_PIPE;
				wcmd.cmd.log_pipe.type = cmd.cmd.log_pipe.type;
				rspamd_control_broadcast_cmd (srv, &wcmd, rfd,
						rspamd_control_log_pipe_io_handler, NULL);
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
			event_del (&worker->srv_ev);
			event_set (&worker->srv_ev,
					worker->srv_pipe[0],
					EV_WRITE,
					rspamd_srv_handler,
					rdata);
			event_add (&worker->srv_ev, NULL);
		}
	}
	else if (what == EV_WRITE) {
		rdata = ud;
		worker = rdata->worker;
		srv = worker->srv;

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

		r = sendmsg (fd, &msg, 0);

		if (r == -1) {
			msg_err ("cannot write to worker's srv pipe: %s",
					strerror (errno));
		}

		g_slice_free1 (sizeof (*rdata), rdata);
		event_del (&worker->srv_ev);
		event_set (&worker->srv_ev,
				worker->srv_pipe[0],
				EV_READ | EV_PERSIST,
				rspamd_srv_handler,
				worker);
		event_add (&worker->srv_ev, NULL);
	}
}

void
rspamd_srv_start_watching (struct rspamd_worker *worker,
		struct event_base *ev_base)
{
	g_assert (worker != NULL);

	event_set (&worker->srv_ev, worker->srv_pipe[0], EV_READ | EV_PERSIST,
			rspamd_srv_handler, worker);
	event_base_set (ev_base, &worker->srv_ev);
	event_add (&worker->srv_ev, NULL);
}

struct rspamd_srv_request_data {
	struct rspamd_worker *worker;
	struct rspamd_srv_command cmd;
	gint attached_fd;
	struct rspamd_srv_reply rep;
	rspamd_srv_reply_handler handler;
	struct event io_ev;
	gpointer ud;
};

static void
rspamd_srv_request_handler (gint fd, short what, gpointer ud)
{
	struct rspamd_srv_request_data *rd = ud;
	struct msghdr msg;
	struct iovec iov;
	guchar fdspace[CMSG_SPACE(sizeof (int))];
	struct cmsghdr *cmsg;
	gssize r;
	gint rfd = -1;

	if (what == EV_WRITE) {
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

		r = sendmsg (fd, &msg, 0);

		if (r == -1) {
			msg_err ("cannot write to server pipe: %s", strerror (errno));
			goto cleanup;
		}

		event_del (&rd->io_ev);
		event_set (&rd->io_ev, rd->worker->srv_pipe[1], EV_READ,
				rspamd_srv_request_handler, rd);
		event_add (&rd->io_ev, NULL);
	}
	else {
		iov.iov_base = &rd->rep;
		iov.iov_len = sizeof (rd->rep);
		memset (&msg, 0, sizeof (msg));
		msg.msg_control = fdspace;
		msg.msg_controllen = sizeof (fdspace);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		r = recvmsg (fd, &msg, 0);

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
	event_del (&rd->io_ev);
	g_slice_free1 (sizeof (*rd), rd);
}

void
rspamd_srv_send_command (struct rspamd_worker *worker,
		struct event_base *ev_base,
		struct rspamd_srv_command *cmd,
		gint attached_fd,
		rspamd_srv_reply_handler handler,
		gpointer ud)
{
	struct rspamd_srv_request_data *rd;

	g_assert (cmd != NULL);
	g_assert (worker != NULL);

	rd = g_slice_alloc0 (sizeof (*rd));
	memcpy (&rd->cmd, cmd, sizeof (rd->cmd));
	rd->handler = handler;
	rd->ud = ud;
	rd->worker = worker;
	rd->rep.id = cmd->id;
	rd->rep.type = cmd->type;
	rd->attached_fd = attached_fd;

	event_set (&rd->io_ev, worker->srv_pipe[1], EV_WRITE,
			rspamd_srv_request_handler, rd);
	event_base_set (ev_base, &rd->io_ev);
	event_add (&rd->io_ev, NULL);
}
