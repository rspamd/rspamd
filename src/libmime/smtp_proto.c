/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
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
#include "cfg_file.h"
#include "util.h"
#include "smtp.h"
#include "smtp_proto.h"
#include "smtp_utils.h"

gchar *
make_smtp_error (rspamd_mempool_t *pool,
	gint error_code,
	const gchar *format,
	...)
{
	va_list vp;
	gchar *result = NULL, *p;
	size_t len;

	va_start (vp, format);
	len = g_printf_string_upper_bound (format, vp);
	va_end (vp);
	va_start (vp, format);
	len += sizeof ("65535 ") + sizeof (CRLF) - 1;
	result = rspamd_mempool_alloc (pool, len);
	p = result + rspamd_snprintf (result, len, "%d ", error_code);
	p = rspamd_vsnprintf (p, len - (p - result), format, vp);
	*p++ = CR; *p++ = LF; *p = '\0';
	va_end (vp);

	return result;
}


gboolean
parse_smtp_command (struct smtp_session *session,
	f_str_t *line,
	struct smtp_command **cmd)
{
	enum {
		SMTP_PARSE_START = 0,
		SMTP_PARSE_SPACES,
		SMTP_PARSE_ARGUMENT,
		SMTP_PARSE_DONE
	}                              state;
	gchar *p, *c, ch, cmd_buf[4];
	guint i;
	f_str_t *arg = NULL;
	struct smtp_command *pcmd;

	if (line->len == 0) {
		return FALSE;
	}

	state = SMTP_PARSE_START;
	c = line->begin;
	p = c;
	*cmd = rspamd_mempool_alloc0 (session->pool, sizeof (struct smtp_command));
	pcmd = *cmd;

	for (i = 0; i < line->len; i++, p++) {
		ch = *p;
		switch (state) {
		case SMTP_PARSE_START:
			if (ch == ' ' || ch == ':' || ch == CR || ch == LF || i ==
				line->len - 1) {
				if (i == line->len - 1) {
					p++;
				}
				if (p - c == 4) {
					cmd_buf[0] = g_ascii_toupper (c[0]);
					cmd_buf[1] = g_ascii_toupper (c[1]);
					cmd_buf[2] = g_ascii_toupper (c[2]);
					cmd_buf[3] = g_ascii_toupper (c[3]);

					if (memcmp (cmd_buf, "HELO", 4) == 0) {
						pcmd->command = SMTP_COMMAND_HELO;
					}
					else if (memcmp (cmd_buf, "EHLO", 4) == 0) {
						pcmd->command = SMTP_COMMAND_EHLO;
					}
					else if (memcmp (cmd_buf, "MAIL", 4) == 0) {
						pcmd->command = SMTP_COMMAND_MAIL;
					}
					else if (memcmp (cmd_buf, "RCPT", 4) == 0) {
						pcmd->command = SMTP_COMMAND_RCPT;
					}
					else if (memcmp (cmd_buf, "DATA", 4) == 0) {
						pcmd->command = SMTP_COMMAND_DATA;
					}
					else if (memcmp (cmd_buf, "QUIT", 4) == 0) {
						pcmd->command = SMTP_COMMAND_QUIT;
					}
					else if (memcmp (cmd_buf, "NOOP", 4) == 0) {
						pcmd->command = SMTP_COMMAND_NOOP;
					}
					else if (memcmp (cmd_buf, "EXPN", 4) == 0) {
						pcmd->command = SMTP_COMMAND_EXPN;
					}
					else if (memcmp (cmd_buf, "RSET", 4) == 0) {
						pcmd->command = SMTP_COMMAND_RSET;
					}
					else if (memcmp (cmd_buf, "HELP", 4) == 0) {
						pcmd->command = SMTP_COMMAND_HELP;
					}
					else if (memcmp (cmd_buf, "VRFY", 4) == 0) {
						pcmd->command = SMTP_COMMAND_VRFY;
					}
					else {
						msg_info ("invalid command: %*s", 4, cmd_buf);
						return FALSE;
					}
				}
				else {
					/* Invalid command */
					msg_info ("invalid command: %*s", 4, c);
					return FALSE;
				}
				/* Now check what we have */
				if (ch == ' ' || ch == ':') {
					state = SMTP_PARSE_SPACES;
				}
				else if (ch == CR) {
					state = SMTP_PARSE_DONE;
				}
				else if (ch == LF) {
					return TRUE;
				}
			}
			else if ((ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z')) {
				msg_info ("invalid letter code in SMTP command: %d", (gint)ch);
				return FALSE;
			}
			break;
		case SMTP_PARSE_SPACES:
			if (ch == CR) {
				state = SMTP_PARSE_DONE;
			}
			else if (ch == LF) {
				goto end;
			}
			else if (ch != ' ' && ch != ':') {
				state = SMTP_PARSE_ARGUMENT;
				arg = rspamd_mempool_alloc (session->pool, sizeof (f_str_t));
				c = p;
			}
			break;
		case SMTP_PARSE_ARGUMENT:
			if (ch == ' ' || ch == ':' || ch == CR || ch == LF || i ==
				line->len - 1) {
				if (i == line->len - 1 && (ch != ' ' && ch != CR && ch != LF)) {
					p++;
				}
				arg->len = p - c;
				arg->begin = rspamd_mempool_alloc (session->pool, arg->len);
				memcpy (arg->begin, c, arg->len);
				pcmd->args = g_list_prepend (pcmd->args, arg);
				if (ch == ' ' || ch == ':') {
					state = SMTP_PARSE_SPACES;
				}
				else if (ch == CR) {
					state = SMTP_PARSE_DONE;
				}
				else {
					goto end;
				}
			}
			break;
		case SMTP_PARSE_DONE:
			if (ch == LF) {
				goto end;
			}
			msg_info ("CR without LF in SMTP command");
			return FALSE;
		}
	}

end:
	if (pcmd->args) {
		pcmd->args = g_list_reverse (pcmd->args);
		rspamd_mempool_add_destructor (session->pool,
			(rspamd_mempool_destruct_t)g_list_free,
			pcmd->args);
	}
	return TRUE;
}

static gboolean
check_smtp_path (f_str_t *path)
{
	guint i;
	gchar *p;

	p = path->begin;
	if (*p != '<' || path->len < 2) {
		return FALSE;
	}
	for (i = 0; i < path->len; i++, p++) {
		if (*p == '>' && i != path->len - 1) {
			return FALSE;
		}
	}

	return *(p - 1) == '>';
}

gboolean
parse_smtp_helo (struct smtp_session *session, struct smtp_command *cmd)
{
	f_str_t *arg;

	if (cmd->args == NULL) {
		session->error = SMTP_ERROR_BAD_ARGUMENTS;
		return FALSE;
	}
	arg = cmd->args->data;
	session->helo = rspamd_mempool_alloc (session->pool, arg->len + 1);
	rspamd_strlcpy (session->helo, arg->begin, arg->len + 1);
	/* Now try to write reply */
	if (cmd->command == SMTP_COMMAND_HELO) {
		/* No ESMTP */
		session->error = SMTP_ERROR_OK;
		session->esmtp = FALSE;
		return TRUE;
	}
	else {
		/* Try to write all capabilities */
		session->esmtp = TRUE;
		if (session->ctx->smtp_capabilities == NULL) {
			session->error = SMTP_ERROR_OK;
			return TRUE;
		}
		else {
			session->error = session->ctx->smtp_capabilities;
			return TRUE;
		}
	}

	return FALSE;
}

gboolean
parse_smtp_from (struct smtp_session *session, struct smtp_command *cmd)
{
	f_str_t *arg;
	GList *cur = cmd->args;

	if (cmd->args == NULL) {
		session->error = SMTP_ERROR_BAD_ARGUMENTS;
		return FALSE;
	}
	arg = cur->data;
	/* First argument MUST be FROM */
	if (arg->len != 4 || (
			g_ascii_toupper (arg->begin[0]) != 'F' ||
			g_ascii_toupper (arg->begin[1]) != 'R' ||
			g_ascii_toupper (arg->begin[2]) != 'O' ||
			g_ascii_toupper (arg->begin[3]) != 'M')) {
		session->error = SMTP_ERROR_BAD_ARGUMENTS;
		return FALSE;
	}
	/* Next one is from address */
	cur = g_list_next (cur);
	if (cur == NULL) {
		session->error = SMTP_ERROR_BAD_ARGUMENTS;
		return FALSE;
	}
	arg = cur->data;
	if (check_smtp_path (arg)) {
		session->from = cur;
	}
	else {
		session->error = SMTP_ERROR_BAD_ARGUMENTS;
		return FALSE;
	}

	return TRUE;
}

gboolean
parse_smtp_rcpt (struct smtp_session *session, struct smtp_command *cmd)
{
	f_str_t *arg;
	GList *cur = cmd->args;

	if (cmd->args == NULL) {
		session->error = SMTP_ERROR_BAD_ARGUMENTS;
		return FALSE;
	}
	arg = cur->data;
	/* First argument MUST be FROM */
	if (arg->len != 2 || (
			g_ascii_toupper (arg->begin[0]) != 'T' ||
			g_ascii_toupper (arg->begin[1]) != 'O')) {
		session->error = SMTP_ERROR_BAD_ARGUMENTS;
		return FALSE;
	}
	/* Next one is from address */
	cur = g_list_next (cur);
	if (cur == NULL) {
		session->error = SMTP_ERROR_BAD_ARGUMENTS;
		return FALSE;
	}
	arg = cur->data;
	if (check_smtp_path (arg)) {
		session->rcpt = g_list_prepend (session->rcpt, cur);
	}
	else {
		session->error = SMTP_ERROR_BAD_ARGUMENTS;
		return FALSE;
	}

	return TRUE;

}

/* Return -1 if there are some error, 1 if all is ok and 0 in case of incomplete reply */
static gint
check_smtp_ustream_reply (f_str_t *in, gchar success_code)
{
	gchar *p;

	/* Check for 250 at the begin of line */
	if (in->len >= sizeof ("220 ") - 1) {
		p = in->begin;
		if (p[0] == success_code) {
			/* Last reply line */
			if (p[3] == ' ') {
				return 1;
			}
			else {
				return 0;
			}
		}
		else {
			return -1;
		}
	}

	return -1;
}

size_t
smtp_upstream_write_list (GList *args, gchar *buf, size_t buflen)
{
	GList *cur = args;
	size_t r = 0;
	f_str_t *arg;

	while (cur && r < buflen - 3) {
		arg = cur->data;
		r += rspamd_snprintf (buf + r, buflen - r, " %V", arg);
		cur = g_list_next (cur);
	}

	buf[r++] = CR;
	buf[r++] = LF;
	buf[r] = '\0';

	return r;
}

gboolean
smtp_upstream_write_socket (void *arg)
{
	struct smtp_session *session = arg;

	if (session->upstream_state == SMTP_STATE_IN_SENDFILE) {
		session->upstream_state = SMTP_STATE_AFTER_DATA;
		return rspamd_dispatcher_write (session->upstream_dispatcher,
				   CRLF DATA_END_TRAILER,
				   sizeof (CRLF DATA_END_TRAILER) - 1,
				   FALSE,
				   TRUE);
	}

	return TRUE;
}

gboolean
smtp_upstream_read_socket (f_str_t * in, void *arg)
{
	struct smtp_session *session = arg;
	gchar outbuf[BUFSIZ];
	gint r;

	msg_debug ("in: %V, state: %d", in, session->upstream_state);
	switch (session->upstream_state) {
	case SMTP_STATE_GREETING:
		r = check_smtp_ustream_reply (in, '2');
		if (r == -1) {
			session->error = rspamd_mempool_alloc (session->pool, in->len + 1);
			rspamd_strlcpy (session->error, in->begin, in->len + 1);
			/* XXX: assume upstream errors as critical errors */
			session->state = SMTP_STATE_CRITICAL_ERROR;
			rspamd_dispatcher_restore (session->dispatcher);
			if (!rspamd_dispatcher_write (session->dispatcher, session->error,
				in->len, FALSE, TRUE)) {
				goto err;
			}
			if (!rspamd_dispatcher_write (session->dispatcher, CRLF,
				sizeof (CRLF) - 1, FALSE, TRUE)) {
				goto err;
			}
			destroy_session (session->s);
			return FALSE;
		}
		else if (r == 1) {
			if (session->ctx->use_xclient) {
				r = rspamd_snprintf (outbuf,
						sizeof (outbuf),
						"XCLIENT NAME=%s ADDR=%s" CRLF,
						session->resolved ? session->hostname : "[UNDEFINED]",
						inet_ntoa (session->client_addr));
				session->upstream_state = SMTP_STATE_HELO;
				return rspamd_dispatcher_write (session->upstream_dispatcher,
						   outbuf,
						   r,
						   FALSE,
						   FALSE);
			}
			else {
				session->upstream_state = SMTP_STATE_FROM;
				if (session->helo) {
					r = rspamd_snprintf (outbuf, sizeof (outbuf), "%s %s" CRLF,
							session->esmtp ? "EHLO" : "HELO",
							session->helo);
				}
				else {
					return smtp_upstream_read_socket (in, arg);
				}
				return rspamd_dispatcher_write (session->upstream_dispatcher,
						   outbuf,
						   r,
						   FALSE,
						   FALSE);
			}
		}
		break;
	case SMTP_STATE_HELO:
		r = check_smtp_ustream_reply (in, '2');
		if (r == -1) {
			session->error = rspamd_mempool_alloc (session->pool, in->len + 1);
			rspamd_strlcpy (session->error, in->begin, in->len + 1);
			/* XXX: assume upstream errors as critical errors */
			session->state = SMTP_STATE_CRITICAL_ERROR;
			rspamd_dispatcher_restore (session->dispatcher);
			if (!rspamd_dispatcher_write (session->dispatcher, session->error,
				in->len, FALSE, TRUE)) {
				goto err;
			}
			if (!rspamd_dispatcher_write (session->dispatcher, CRLF,
				sizeof (CRLF) - 1, FALSE, TRUE)) {
				goto err;
			}
			destroy_session (session->s);
			return FALSE;
		}
		else if (r == 1) {
			session->upstream_state = SMTP_STATE_FROM;
			if (session->helo) {
				r = rspamd_snprintf (outbuf, sizeof (outbuf), "%s %s" CRLF,
						session->esmtp ? "EHLO" : "HELO",
						session->helo);
			}
			else {
				return smtp_upstream_read_socket (in, arg);
			}
			return rspamd_dispatcher_write (session->upstream_dispatcher,
					   outbuf,
					   r,
					   FALSE,
					   FALSE);
		}
		break;
	case SMTP_STATE_FROM:
		r = check_smtp_ustream_reply (in, '2');
		if (r == -1) {
			session->error = rspamd_mempool_alloc (session->pool, in->len + 1);
			rspamd_strlcpy (session->error, in->begin, in->len + 1);
			/* XXX: assume upstream errors as critical errors */
			session->state = SMTP_STATE_CRITICAL_ERROR;
			rspamd_dispatcher_restore (session->dispatcher);
			if (!rspamd_dispatcher_write (session->dispatcher, session->error,
				in->len, FALSE, TRUE)) {
				goto err;
			}
			if (!rspamd_dispatcher_write (session->dispatcher, CRLF,
				sizeof (CRLF) - 1, FALSE, TRUE)) {
				goto err;
			}
			destroy_session (session->s);
			return FALSE;
		}
		else if (r == 1) {
			r = rspamd_snprintf (outbuf, sizeof (outbuf), "MAIL FROM: ");
			r +=
				smtp_upstream_write_list (session->from,
					outbuf + r,
					sizeof (outbuf) - r);
			session->upstream_state = SMTP_STATE_RCPT;
			return rspamd_dispatcher_write (session->upstream_dispatcher,
					   outbuf,
					   r,
					   FALSE,
					   FALSE);
		}
		break;
	case SMTP_STATE_RCPT:
		r = check_smtp_ustream_reply (in, '2');
		if (r == -1) {
			session->error = rspamd_mempool_alloc (session->pool, in->len + 1);
			rspamd_strlcpy (session->error, in->begin, in->len + 1);
			/* XXX: assume upstream errors as critical errors */
			session->state = SMTP_STATE_CRITICAL_ERROR;
			rspamd_dispatcher_restore (session->dispatcher);
			if (!rspamd_dispatcher_write (session->dispatcher, session->error,
				in->len, FALSE, TRUE)) {
				goto err;
			}
			if (!rspamd_dispatcher_write (session->dispatcher, CRLF,
				sizeof (CRLF) - 1, FALSE, TRUE)) {
				goto err;
			}
			destroy_session (session->s);
			return FALSE;
		}
		else if (r == 1) {
			r = rspamd_snprintf (outbuf, sizeof (outbuf), "RCPT TO: ");
			session->cur_rcpt = g_list_first (session->rcpt);
			r += smtp_upstream_write_list (session->cur_rcpt->data,
					outbuf + r,
					sizeof (outbuf) - r);
			session->cur_rcpt = g_list_next (session->cur_rcpt);
			session->upstream_state = SMTP_STATE_BEFORE_DATA;
			return rspamd_dispatcher_write (session->upstream_dispatcher,
					   outbuf,
					   r,
					   FALSE,
					   FALSE);
		}
		break;
	case SMTP_STATE_BEFORE_DATA:
		r = check_smtp_ustream_reply (in, '2');
		if (r == -1) {
			session->error = rspamd_mempool_alloc (session->pool, in->len + 1);
			rspamd_strlcpy (session->error, in->begin, in->len + 1);
			rspamd_dispatcher_restore (session->dispatcher);
			if (!rspamd_dispatcher_write (session->dispatcher, session->error,
				in->len, FALSE, TRUE)) {
				goto err;
			}
			if (!rspamd_dispatcher_write (session->dispatcher, CRLF,
				sizeof (CRLF) - 1, FALSE, TRUE)) {
				goto err;
			}
			if (session->cur_rcpt) {
				session->rcpt = g_list_delete_link (session->rcpt,
						session->cur_rcpt);
			}
			else {
				session->rcpt =
					g_list_delete_link (session->rcpt, session->rcpt);
			}
			session->errors++;
			session->state = SMTP_STATE_RCPT;
			return TRUE;
		}
		else if (r == 1) {
			if (session->cur_rcpt != NULL) {
				r = rspamd_snprintf (outbuf, sizeof (outbuf), "RCPT TO: ");
				r += smtp_upstream_write_list (session->cur_rcpt,
						outbuf + r,
						sizeof (outbuf) - r);
				session->cur_rcpt = g_list_next (session->cur_rcpt);
				if (!rspamd_dispatcher_write (session->upstream_dispatcher,
					outbuf, r, FALSE, FALSE)) {
					goto err;
				}
			}
			else {
				session->upstream_state = SMTP_STATE_DATA;
				rspamd_dispatcher_pause (session->upstream_dispatcher);
			}
			session->error = rspamd_mempool_alloc (session->pool, in->len + 1);
			rspamd_strlcpy (session->error, in->begin, in->len + 1);
			/* Write to client */
			if (!rspamd_dispatcher_write (session->dispatcher, session->error,
				in->len, FALSE, TRUE)) {
				goto err;
			}
			if (!rspamd_dispatcher_write (session->dispatcher, CRLF,
				sizeof (CRLF) - 1, FALSE, TRUE)) {
				goto err;
			}
			if (session->state == SMTP_STATE_WAIT_UPSTREAM) {
				rspamd_dispatcher_restore (session->dispatcher);
				session->state = SMTP_STATE_RCPT;
			}
		}
		break;
	case SMTP_STATE_DATA:
		r = check_smtp_ustream_reply (in, '3');
		if (r == -1) {
			session->error = rspamd_mempool_alloc (session->pool, in->len + 1);
			rspamd_strlcpy (session->error, in->begin, in->len + 1);
			/* XXX: assume upstream errors as critical errors */
			session->state = SMTP_STATE_CRITICAL_ERROR;
			rspamd_dispatcher_restore (session->dispatcher);
			if (!rspamd_dispatcher_write (session->dispatcher, session->error,
				0, FALSE, TRUE)) {
				goto err;
			}
			if (!rspamd_dispatcher_write (session->dispatcher, CRLF,
				sizeof (CRLF) - 1, FALSE, TRUE)) {
				goto err;
			}
			destroy_session (session->s);
			return FALSE;
		}
		else if (r == 1) {
			if (!make_smtp_tempfile (session)) {
				session->error = SMTP_ERROR_FILE;
				session->state = SMTP_STATE_CRITICAL_ERROR;
				rspamd_dispatcher_restore (session->dispatcher);
				if (!rspamd_dispatcher_write (session->dispatcher,
					session->error, 0, FALSE, TRUE)) {
					goto err;
				}
				destroy_session (session->s);
				return FALSE;
			}
			session->state = SMTP_STATE_AFTER_DATA;
			session->error = SMTP_ERROR_DATA_OK;
			rspamd_dispatcher_restore (session->dispatcher);
			if (!rspamd_dispatcher_write (session->dispatcher, session->error,
				0, FALSE, TRUE)) {
				goto err;
			}
			rspamd_dispatcher_pause (session->upstream_dispatcher);
			rspamd_set_dispatcher_policy (session->dispatcher, BUFFER_LINE, 0);
			session->dispatcher->strip_eol = FALSE;
			return TRUE;
		}
		break;
	case SMTP_STATE_AFTER_DATA:
		session->error = rspamd_mempool_alloc (session->pool, in->len + 1);
		rspamd_strlcpy (session->error, in->begin, in->len + 1);
		session->state = SMTP_STATE_DATA;
		rspamd_dispatcher_restore (session->dispatcher);
		if (!rspamd_dispatcher_write (session->dispatcher, session->error, 0,
			FALSE, TRUE)) {
			goto err;
		}
		if (!rspamd_dispatcher_write (session->dispatcher, CRLF, sizeof (CRLF) -
			1, FALSE, TRUE)) {
			goto err;
		}
		if (!rspamd_dispatcher_write (session->upstream_dispatcher, "QUIT" CRLF,
			sizeof ("QUIT" CRLF) - 1, FALSE, TRUE)) {
			goto err;
		}
		session->upstream_state = SMTP_STATE_END;
		return TRUE;
		break;
	case SMTP_STATE_END:
		r = check_smtp_ustream_reply (in, '5');
		if (r == -1) {
			session->error = rspamd_mempool_alloc (session->pool, in->len + 1);
			rspamd_strlcpy (session->error, in->begin, in->len + 1);
			/* XXX: assume upstream errors as critical errors */
			session->state = SMTP_STATE_CRITICAL_ERROR;
			rspamd_dispatcher_restore (session->dispatcher);
			if (!rspamd_dispatcher_write (session->dispatcher, session->error,
				0, FALSE, TRUE)) {
				goto err;
			}
			if (!rspamd_dispatcher_write (session->dispatcher, CRLF,
				sizeof (CRLF) - 1, FALSE, TRUE)) {
				goto err;
			}
			destroy_session (session->s);
			return FALSE;
		}
		else {
			remove_normal_event (session->s,
				(event_finalizer_t)smtp_upstream_finalize_connection,
				session);
		}
		return FALSE;
		break;
	default:
		msg_err ("got upstream reply at unexpected state: %d, reply: %V",
			session->upstream_state,
			in);
		session->state = SMTP_STATE_CRITICAL_ERROR;
		rspamd_dispatcher_restore (session->dispatcher);
		if (!rspamd_dispatcher_write (session->dispatcher, session->error, 0,
			FALSE, TRUE)) {
			goto err;
		}
		if (!rspamd_dispatcher_write (session->dispatcher, CRLF, sizeof (CRLF) -
			1, FALSE, TRUE)) {
			goto err;
		}
		destroy_session (session->s);
		return FALSE;
	}

	return TRUE;
err:
	msg_warn ("write error occured");
	return FALSE;
}

void
smtp_upstream_err_socket (GError *err, void *arg)
{
	struct smtp_session *session = arg;

	msg_info ("abnormally closing connection with upstream %s, error: %s",
		session->upstream->name,
		err->message);
	session->error = SMTP_ERROR_UPSTREAM;
	session->state = SMTP_STATE_CRITICAL_ERROR;
	/* XXX: assume upstream errors as critical errors */
	rspamd_dispatcher_restore (session->dispatcher);
	if (!rspamd_dispatcher_write (session->dispatcher, session->error, 0, FALSE,
		TRUE)) {
		return;
	}
	if (!rspamd_dispatcher_write (session->dispatcher, CRLF, sizeof (CRLF) - 1,
		FALSE, TRUE)) {
		return;
	}
	upstream_fail (&session->upstream->up, session->session_time);
	destroy_session (session->s);
}

void
smtp_upstream_finalize_connection (gpointer data)
{
	struct smtp_session *session = data;

	if (session->state != SMTP_STATE_CRITICAL_ERROR) {
		if (!rspamd_dispatcher_write (session->upstream_dispatcher, "QUIT" CRLF,
			0, FALSE, TRUE)) {
			msg_warn ("cannot send correctly closing message to upstream");
		}
	}
	rspamd_remove_dispatcher (session->upstream_dispatcher);
	session->upstream_dispatcher = NULL;
	close (session->upstream_sock);
	session->upstream_sock = -1;
}
