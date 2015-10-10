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

static struct timeval io_timeout = {
		.tv_sec = 30,
		.tv_usec = 0
};

struct rspamd_control_reply_elt {
	struct rspamd_control_reply reply;
	struct event io_ev;
	struct event tm_ev;
	struct rspamd_worker *wrk;
	struct rspamd_control_reply_elt *prev, *next;
};

struct rspamd_control_session {
	gint fd;
	struct rspamd_main *rspamd_main;
	struct rspamd_http_connection *conn;
	struct rspamd_control_command cmd;
	struct rspamd_control_reply_elt *replies;
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
		g_slice_free1 (sizeof (*elt), elt);
	}

	rspamd_http_connection_unref (session->conn);
	close (session->fd);
	g_slice_free1 (sizeof (*session), session);
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
			rspamd_control_send_error (session, 500, "Not implemented yet");
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

void
rspamd_control_worker_add_default_handler (struct rspamd_worker *worker)
{

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

}
