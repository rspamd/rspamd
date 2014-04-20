/* Copyright (c) 2010, Vsevolod Stakhov
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
#include "main.h"
#include "filter.h"
#include "settings.h"
#include "smtp.h"
#include "smtp_proto.h"

void
free_smtp_session (gpointer arg)
{
	struct smtp_session            *session = arg;

	if (session) {
		if (session->task) {
			free_task (session->task, FALSE);
			if (session->task->msg->str) {
				munmap (session->task->msg->str, session->task->msg->len);
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
		rspamd_mempool_delete (session->pool);
		g_free (session);
	}
}

gboolean
create_smtp_upstream_connection (struct smtp_session *session)
{
	struct smtp_upstream              *selected;

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
	session->upstream_sock = make_universal_socket (selected->addr, selected->port, SOCK_STREAM, TRUE, FALSE, FALSE);
	if (session->upstream_sock == -1) {
		msg_err ("cannot make a connection to %s", selected->name);
		upstream_fail (&selected->up, session->session_time);
		return FALSE;
	}
	/* Create a dispatcher for upstream connection */
	session->upstream_dispatcher = rspamd_create_dispatcher (session->ev_base, session->upstream_sock, BUFFER_LINE,
							smtp_upstream_read_socket, smtp_upstream_write_socket, smtp_upstream_err_socket,
							&session->ctx->smtp_timeout, session);
	session->state = SMTP_STATE_WAIT_UPSTREAM;
	session->upstream_state = SMTP_STATE_GREETING;
	register_async_event (session->s, (event_finalizer_t)smtp_upstream_finalize_connection, session, g_quark_from_static_string ("smtp proxy"));
	return TRUE;
}

gboolean
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

struct smtp_metric_callback_data {
	struct smtp_session            *session;
	enum rspamd_metric_action       action;
	struct metric_result           *res;
	gchar                          *log_buf;
	gint                            log_offset;
	gint                            log_size;
	gboolean                        alive;
};

static void
smtp_metric_symbols_callback (gpointer key, gpointer value, void *user_data)
{
	struct smtp_metric_callback_data    *cd = user_data;

	cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset, "%s,", (gchar *)key);
}

static void
smtp_metric_callback (gpointer key, gpointer value, gpointer ud)
{
	struct smtp_metric_callback_data *cd = ud;
	struct metric_result           *metric_res = value;
	enum rspamd_metric_action       action = METRIC_ACTION_NOACTION;
	double                          ms = 0, rs = 0;
	gboolean                        is_spam = FALSE;
	struct worker_task             *task;

	task = cd->session->task;

	if (!check_metric_settings (metric_res, &ms, &rs)) {
		ms = metric_res->metric->actions[METRIC_ACTION_REJECT].score;
		rs = metric_res->metric->actions[METRIC_ACTION_REJECT].score;
	}
	if (! check_metric_action_settings (task, metric_res, metric_res->score, &action)) {
		action = check_metric_action (metric_res->score, ms, metric_res->metric);
	}
	if (metric_res->score >= ms) {
		is_spam = 1;
	}
	if (action < cd->action) {
		cd->action = action;
		cd->res = metric_res;
	}

	if (!task->is_skipped) {
		cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset, "(%s: %c (%s): [%.2f/%.2f/%.2f] [",
				(gchar *)key, is_spam ? 'T' : 'F', str_action_metric (action), metric_res->score, ms, rs);
	}
	else {
		cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset, "(%s: %c (default): [%.2f/%.2f/%.2f] [",
				(gchar *)key, 'S', metric_res->score, ms, rs);

	}
	g_hash_table_foreach (metric_res->symbols, smtp_metric_symbols_callback, cd);
	/* Remove last , from log buf */
	if (cd->log_buf[cd->log_offset - 1] == ',') {
		cd->log_buf[--cd->log_offset] = '\0';
	}

#ifdef HAVE_CLOCK_GETTIME
	cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset, "]), len: %z, time: %s,",
		task->msg->len, calculate_check_time (&task->tv, &task->ts, task->cfg->clock_res, &task->scan_milliseconds));
#else
	cd->log_offset += rspamd_snprintf (cd->log_buf + cd->log_offset, cd->log_size - cd->log_offset, "]), len: %z, time: %s,",
		task->msg->len, calculate_check_time (&task->tv, task->cfg->clock_res, &task->scan_milliseconds));
#endif
}

gboolean
make_smtp_tempfile (struct smtp_session *session)
{
	gsize                            r;

	r = strlen (session->cfg->temp_dir) + sizeof ("/rspamd-XXXXXX");
	session->temp_name = rspamd_mempool_alloc (session->pool, r);
	rspamd_snprintf (session->temp_name, r, "%s%crspamd-XXXXXX", session->cfg->temp_dir, G_DIR_SEPARATOR);
#ifdef HAVE_MKSTEMP
	/* Umask is set before */
	session->temp_fd = mkstemp (session->temp_name);
#else
	session->temp_fd = g_mkstemp_full (session->temp_name, O_RDWR, S_IWUSR | S_IRUSR);
#endif
	if (session->temp_fd == -1) {
		msg_err ("mkstemp error: %s", strerror (errno));

		return FALSE;
	}

	return TRUE;
}

gboolean
write_smtp_reply (struct smtp_session *session)
{
	gchar                           logbuf[1024], *new_subject;
	const gchar                    *old_subject;
	struct smtp_metric_callback_data cd;
	GMimeStream                    *stream;
	gint                            old_fd, sublen;

	/* Check metrics */
	cd.session = session;
	cd.action = METRIC_ACTION_NOACTION;
	cd.res = NULL;
	cd.log_buf = logbuf;
	cd.log_offset = rspamd_snprintf (logbuf, sizeof (logbuf), "id: <%s>, qid: <%s>, ",
			session->task->message_id, session->task->queue_id);
	cd.log_size = sizeof (logbuf);
	if (session->task->user) {
		cd.log_offset += rspamd_snprintf (logbuf + cd.log_offset, sizeof (logbuf) - cd.log_offset,
				"user: %s, ", session->task->user);
	}

	g_hash_table_foreach (session->task->results, smtp_metric_callback, &cd);

	msg_info ("%s", logbuf);

	if (cd.action <= METRIC_ACTION_REJECT) {
		if (! rspamd_dispatcher_write (session->dispatcher, session->ctx->reject_message, 0, FALSE, TRUE)) {
			return FALSE;
		}
		if (! rspamd_dispatcher_write (session->dispatcher, CRLF, sizeof (CRLF) - 1, FALSE, TRUE)) {
			return FALSE;
		}
		destroy_session (session->s);
		return FALSE;
	}
	else if (cd.action <= METRIC_ACTION_ADD_HEADER || cd.action <= METRIC_ACTION_REWRITE_SUBJECT) {
		old_fd = session->temp_fd;
		if (! make_smtp_tempfile (session)) {
			session->error = SMTP_ERROR_FILE;
			session->state = SMTP_STATE_CRITICAL_ERROR;
			rspamd_dispatcher_restore (session->dispatcher);
			if (! rspamd_dispatcher_write (session->dispatcher, session->error, 0, FALSE, TRUE)) {
				goto err;
			}
			destroy_session (session->s);
			return FALSE;
		}

		if (cd.action <= METRIC_ACTION_REWRITE_SUBJECT) {
			/* XXX: add this action */
			old_subject = g_mime_message_get_subject (session->task->message);
			if (old_subject != NULL) {
				sublen = strlen (old_subject) + sizeof (SPAM_SUBJECT);
				new_subject = rspamd_mempool_alloc (session->pool, sublen);
				rspamd_snprintf (new_subject, sublen, "%s%s", SPAM_SUBJECT, old_subject);
			}
			else {
				new_subject = SPAM_SUBJECT;
			}
			g_mime_message_set_subject (session->task->message, new_subject);
		}
		else if (cd.action <= METRIC_ACTION_ADD_HEADER) {
#ifndef GMIME24
			g_mime_message_add_header (session->task->message, "X-Spam", "true");
#else
			g_mime_object_append_header (GMIME_OBJECT (session->task->message), "X-Spam", "true");
#endif
		}
		stream = g_mime_stream_fs_new (session->temp_fd);
		g_mime_stream_fs_set_owner (GMIME_STREAM_FS (stream), FALSE);
		close (old_fd);

		if (g_mime_object_write_to_stream (GMIME_OBJECT (session->task->message), stream) == -1) {
			msg_err ("cannot write MIME object to stream: %s", strerror (errno));
			session->error = SMTP_ERROR_FILE;
			session->state = SMTP_STATE_CRITICAL_ERROR;
			rspamd_dispatcher_restore (session->dispatcher);
			if (! rspamd_dispatcher_write (session->dispatcher, session->error, 0, FALSE, TRUE)) {
				goto err;
			}
			destroy_session (session->s);
			return FALSE;
		}
		g_object_unref (stream);
	}
	/* XXX: Add other actions */
	return smtp_send_upstream_message (session);
err:
	session->error = SMTP_ERROR_FILE;
	session->state = SMTP_STATE_CRITICAL_ERROR;
	if (! rspamd_dispatcher_write (session->dispatcher, session->error, 0, FALSE, TRUE)) {
		return FALSE;
	}
	destroy_session (session->s);
	return FALSE;
}

gboolean
parse_upstreams_line (rspamd_mempool_t *pool, struct smtp_upstream *upstreams, const gchar *line, gsize *count)
{
	gchar                           **strv, *p, *t, *tt, *err_str;
	guint32                         num, i;
	struct smtp_upstream           *cur;
	gchar                           resolved_path[PATH_MAX];

	strv = g_strsplit_set (line, ",; ", -1);
	num = g_strv_length (strv);

	if (num >= MAX_SMTP_UPSTREAMS) {
		msg_err ("cannot define %d upstreams %d is max", num, MAX_SMTP_UPSTREAMS);
		return FALSE;
	}
	*count = 0;

	for (i = 0; i < num; i ++) {
		p = strv[i];
		cur = &upstreams[*count];
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
			cur->name = rspamd_mempool_strdup (pool, resolved_path);
			(*count) ++;
		}
		else {
			if (! parse_host_port (pool, p, &cur->addr, &cur->port)) {
				g_strfreev (strv);
				return FALSE;
			}
			cur->name = rspamd_mempool_strdup (pool, p);
			(*count) ++;
		}
	}

	g_strfreev (strv);
	return TRUE;
}
