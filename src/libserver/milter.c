/*-
 * Copyright 2017 Vsevolod Stakhov
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
#include "milter.h"
#include "milter_internal.h"
#include "email_addr.h"
#include "addr.h"
#include "unix-std.h"
#include "logger.h"
#include "ottery.h"
#include "utlist.h"

#define msg_err_milter(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL, \
        "milter", priv->uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_milter(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        "milter", priv->uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_milter(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "milter", priv->uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_milter(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
        "milter", priv->uid, \
        G_STRFUNC, \
        __VA_ARGS__)

static gboolean  rspamd_milter_handle_session (
		struct rspamd_milter_session *session,
		struct rspamd_milter_private *priv);

static GQuark
rspamd_milter_quark (void)
{
	return g_quark_from_static_string ("milter");
}

static void
rspamd_milter_obuf_free (struct rspamd_milter_outbuf *obuf)
{
	if (obuf) {
		if (obuf->buf) {
			rspamd_fstring_free (obuf->buf);
		}

		g_free (obuf->buf);
	}
}

static void
rspamd_milter_session_dtor (struct rspamd_milter_session *session)
{
	struct rspamd_milter_outbuf *obuf, *obuf_tmp;
	struct rspamd_milter_private *priv;

	if (session) {
		priv = session->priv;

		if (event_get_base (&priv->ev)) {
			event_del (&priv->ev);
		}

		DL_FOREACH_SAFE (priv->out_chain, obuf, obuf_tmp) {
			rspamd_milter_obuf_free (obuf);
		}

		if (priv->parser.buf) {
			rspamd_fstring_free (priv->parser.buf);
		}

		priv->out_chain = NULL;
	}
}

static void
rspamd_milter_io_handler (gint fd, gshort what, void *ud)
{
	struct rspamd_milter_session *session = ud;
	struct rspamd_milter_private *priv;

	priv = session->priv;
}

static inline void
rspamd_milter_plan_io (struct rspamd_milter_session *session,
		struct rspamd_milter_private *priv, gshort what)
{
	if (event_get_base (&priv->ev)) {
		event_del (&priv->ev);
	}

	event_set (&priv->ev, priv->fd, what, rspamd_milter_io_handler,
			session);
	event_base_set (priv->ev_base, &priv->ev);
	event_add (&priv->ev, priv->ptv);
}

static void
rspamd_milter_on_protocol_error (struct rspamd_milter_session *session,
		struct rspamd_milter_private *priv, GError *err)
{
	REF_RETAIN (session);
	priv->err_cb (priv->fd, session, priv->ud, err);
	REF_RELEASE (session);
	g_error_free (err);
}

static gboolean
rspamd_milter_process_command (struct rspamd_milter_session *session,
		struct rspamd_milter_private *priv)
{
	GError *err;

	switch (priv->parser.cur_cmd) {
	case RSPAMD_MILTER_CMD_ABORT:
		err = g_error_new (rspamd_milter_quark (), ECONNABORTED, "connection "
				"aborted");
		rspamd_milter_on_protocol_error (session, priv, err);
		break;
	case RSPAMD_MILTER_CMD_BODY:
		break;
	case RSPAMD_MILTER_CMD_CONNECT:
		break;
	case RSPAMD_MILTER_CMD_MACRO:
		break;
	case RSPAMD_MILTER_CMD_BODYEOB:
		break;
	case RSPAMD_MILTER_CMD_HELO:
		break;
	case RSPAMD_MILTER_CMD_QUIT_NC:
		break;
	case RSPAMD_MILTER_CMD_HEADER:
		break;
	case RSPAMD_MILTER_CMD_MAIL:
		break;
	case RSPAMD_MILTER_CMD_EOH:
		break;
	case RSPAMD_MILTER_CMD_OPTNEG:
		break;
	case RSPAMD_MILTER_CMD_QUIT:
		break;
	case RSPAMD_MILTER_CMD_RCPT:
		break;
	case RSPAMD_MILTER_CMD_DATA:
		break;
	default:
		break;
	}

	return TRUE;
}

static gboolean
rspamd_milter_consume_input (struct rspamd_milter_session *session,
		struct rspamd_milter_private *priv)
{
	const guchar *p, *end;
	GError *err;

	p = priv->parser.buf->str + priv->parser.pos;
	end = priv->parser.buf->str + priv->parser.buf->len;

	while (p < end) {
		switch (priv->parser.state) {
		case st_len_1:
			/* The first length byte in big endian order */
			priv->parser.datalen = 0;
			priv->parser.datalen |= *p << 24;
			priv->parser.state = st_len_2;
			p++;
			break;
		case st_len_2:
			/* The second length byte in big endian order */
			priv->parser.datalen |= *p << 16;
			priv->parser.state = st_len_3;
			p++;
			break;
		case st_len_3:
			/* The third length byte in big endian order */
			priv->parser.datalen |= *p << 8;
			priv->parser.state = st_len_4;
			p++;
			break;
		case st_len_4:
			/* The fourth length byte in big endian order */
			priv->parser.datalen |= *p;
			priv->parser.state = st_read_cmd;
			p++;
			break;
		case st_read_cmd:
			priv->parser.cur_cmd = *p;
			priv->parser.state = st_read_data;

			if (priv->parser.datalen < 1) {
				err = g_error_new (rspamd_milter_quark (), EINVAL,
					"Command length is too short");
				rspamd_milter_on_protocol_error (session, priv, err);

				return FALSE;
			}
			else {
				/* Eat command itself */
				priv->parser.datalen --;
			}

			p++;
			break;
		case st_read_data:
			/* We might need some more data in buffer for further steps */
			if (priv->parser.buf->allocated < priv->parser.datalen) {
				priv->parser.buf = rspamd_fstring_grow (priv->parser.buf,
						priv->parser.pos + priv->parser.datalen);
				/* This can realloc buffer */
				p = priv->parser.buf->str + priv->parser.pos;
				rspamd_milter_plan_io (session, priv, EV_READ);
				goto end;
			}
			else {
				/* We may have the full command available */
				if (p + priv->parser.datalen <= end) {
					/* We need to process command */
					if (!rspamd_milter_process_command (session, priv)) {
						return FALSE;
					}

					p += priv->parser.datalen;
					priv->parser.state = st_len_1;
					priv->parser.cur_cmd = '\0';
				}
				else {
					/* Need to read more */
					rspamd_milter_plan_io (session, priv, EV_READ);
					goto end;
				}
			}
			break;
		}
	}
end:

	priv->parser.pos = p - (const guchar *)priv->parser.buf->str;
	return TRUE;
}

static gboolean
rspamd_milter_handle_session (struct rspamd_milter_session *session,
		struct rspamd_milter_private *priv)
{
	struct rspamd_milter_outbuf *obuf, *obuf_tmp;
	gssize r, to_write;
	GError *err;

	g_assert (session != NULL);

	switch (priv->state) {
	case RSPAMD_MILTER_READ_MORE:
		if (priv->parser.buf->len >= priv->parser.buf->allocated) {
			priv->parser.buf = rspamd_fstring_grow (priv->parser.buf,
					priv->parser.buf->len * 2);
		}

		r = read (priv->fd, priv->parser.buf->str + priv->parser.buf->len,
				priv->parser.buf->allocated - priv->parser.buf->len);

		if (r == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				rspamd_milter_plan_io (session, priv, EV_READ);
			}
			else {
				/* Fatal IO error */
				err = g_error_new (rspamd_milter_quark (), errno,
						"IO read error: %s", strerror (errno));
				REF_RETAIN (session);
				priv->err_cb (priv->fd, session, priv->ud, err);
				REF_RELEASE (session);
				g_error_free (err);
			}
		}
		else if (r == 0) {
			err = g_error_new (rspamd_milter_quark (), ECONNRESET,
					"Unexpected EOF");
			REF_RETAIN (session);
			priv->err_cb (priv->fd, session, priv->ud, err);
			REF_RELEASE (session);
			g_error_free (err);
		}
		else {
			priv->parser.buf->len += r;

			return rspamd_milter_consume_input (session, priv);
		}
	case RSPAMD_MILTER_WRITE_REPLY:
		if (priv->out_chain == NULL) {
			/* We have written everything, so we can read something */
			priv->state = RSPAMD_MILTER_READ_MORE;
			rspamd_milter_plan_io (session, priv, EV_READ);
		}
		else {
			DL_FOREACH_SAFE (priv->out_chain, obuf, obuf_tmp) {
				to_write = obuf->buf->len - obuf->pos;

				g_assert (to_write > 0);

				r = write (priv->fd, obuf->buf->str + obuf->pos, to_write);

				if (r == -1) {
					if (errno == EAGAIN || errno == EINTR) {
						rspamd_milter_plan_io (session, priv, EV_WRITE);
					}
					else {
						/* Fatal IO error */
						err = g_error_new (rspamd_milter_quark (), errno,
								"IO write error: %s", strerror (errno));
						REF_RETAIN (session);
						priv->err_cb (priv->fd, session, priv->ud, err);
						REF_RELEASE (session);
						g_error_free (err);
					}
				}
				else if (r == 0) {
					err = g_error_new (rspamd_milter_quark (), ECONNRESET,
							"Unexpected EOF");
					REF_RETAIN (session);
					priv->err_cb (priv->fd, session, priv->ud, err);
					REF_RELEASE (session);
					g_error_free (err);
				}
				else {
					if (r == to_write) {
						/* We have done with this buf */
						DL_DELETE (priv->out_chain, obuf);
						rspamd_milter_obuf_free (obuf);
					}
					else {
						/* We need to plan another write */
						obuf->pos += r;
						rspamd_milter_plan_io (session, priv, EV_WRITE);

						return TRUE;
					}
				}
			}

			/* Here we have written everything, so we can plan reading */
			priv->state = RSPAMD_MILTER_READ_MORE;
			rspamd_milter_plan_io (session, priv, EV_READ);
		}
		break;
	case RSPAMD_MILTER_WANNA_DIE:
		/* We are here after processing everything, so release session */
		REF_RELEASE (session);
		break;
	}

	return TRUE;
}


gboolean
rspamd_milter_handle_socket (gint fd, const struct timeval *tv,
		struct event_base *ev_base, rspamd_milter_finish finish_cb,
		rspamd_milter_error error_cb, void *ud)
{
	struct rspamd_milter_session *session;
	struct rspamd_milter_private *priv;
	guchar uidbuf[7];

	g_assert (finish_cb != NULL);
	g_assert (error_cb != NULL);

	session = g_malloc0 (sizeof (*session));
	priv = g_malloc0 (sizeof (*priv));
	priv->fd = fd;
	priv->ud = ud;
	priv->fin_cb = finish_cb;
	priv->err_cb = error_cb;
	priv->parser.state = st_len_1;
	priv->parser.buf = rspamd_fstring_sized_new (100);
	priv->ev_base = ev_base;
	priv->state = RSPAMD_MILTER_READ_MORE;
	ottery_rand_bytes (uidbuf, sizeof (uidbuf));
	rspamd_encode_hex_buf (uidbuf, sizeof (uidbuf), priv->uid,
			sizeof (priv->uid) - 1);
	priv->uid[sizeof (priv->uid) - 1] = '\0';

	if (tv) {
		memcpy (&priv->tv, tv, sizeof (*tv));
		priv->ptv = &priv->tv;
	}
	else {
		priv->ptv = NULL;
	}

	session->priv = priv;
	REF_INIT_RETAIN (session, rspamd_milter_session_dtor);

	return rspamd_milter_handle_session (session, priv);
}

gboolean
rspamd_milter_set_reply (struct rspamd_milter_session *session,
		rspamd_fstring_t *xcode,
		rspamd_fstring_t *rcode,
		rspamd_fstring_t *reply)
{
	GString *buf;
	gboolean ret;

	buf = g_string_sized_new (xcode->len + rcode->len + reply->len + 2);
	rspamd_printf_gstring (buf, "%v %v %v", xcode, rcode, reply);
	ret = rspamd_milter_send_action (session, RSPAMD_MILTER_REPLYCODE,
		buf);

	return ret;
}

#define SET_COMMAND(cmd, sz, reply, pos) do { \
	guint32 _len; \
	_len = (sz) + 1; \
	(reply) = rspamd_fstring_sized_new (sizeof (_len) + (sz)); \
	(reply)->len = sizeof (_len) + (sz); \
	_len = htonl (_len); \
	memcpy ((reply)->str, &_len, sizeof (_len)); \
	(reply)->str[sizeof(_len)] = (cmd); \
	(pos) = (guchar *)(reply)->str + sizeof (_len) + 1; \
} while (0)

gboolean
rspamd_milter_send_action (struct rspamd_milter_session *session,
		enum rspamd_milter_reply act, ...)
{
	guint32 ver, actions, protocol, idx;
	va_list ap;
	guchar cmd, *pos;
	rspamd_fstring_t *reply = NULL;
	GString *name, *value;
	struct rspamd_milter_outbuf *obuf;
	struct rspamd_milter_private *priv = session->priv;

	va_start (ap, act);
	cmd = act;

	switch (act) {
	case RSPAMD_MILTER_ACCEPT:
	case RSPAMD_MILTER_CONTINUE:
	case RSPAMD_MILTER_DISCARD:
	case RSPAMD_MILTER_PROGRESS:
	case RSPAMD_MILTER_REJECT:
	case RSPAMD_MILTER_TEMPFAIL:
		/* No additional arguments */
		SET_COMMAND (cmd, 0, reply, pos);
		break;
	case RSPAMD_MILTER_ADDHEADER:
		name = va_arg (ap, GString *);
		value = va_arg (ap, GString *);

		/* Name and value must be zero terminated */
		SET_COMMAND (cmd, name->len + value->len + 2, reply, pos);
		memcpy (pos, name->str, name->len + 1);
		pos += name->len + 1;
		memcpy (pos, value->str, value->len + 1);
		break;
	case RSPAMD_MILTER_CHGHEADER:
		idx = htonl (va_arg (ap, guint32));
		name = va_arg (ap, GString *);
		value = va_arg (ap, GString *);

		/* Name and value must be zero terminated */
		SET_COMMAND (cmd, name->len + value->len + 2 + sizeof (guint32),
				reply, pos);
		memcpy (pos, &idx, sizeof (idx));
		pos += sizeof (idx);
		memcpy (pos, name->str, name->len + 1);
		pos += name->len + 1;
		memcpy (pos, value->str, value->len + 1);
		break;
	case RSPAMD_MILTER_REPLYCODE:
	case RSPAMD_MILTER_ADDRCPT:
	case RSPAMD_MILTER_DELRCPT:
		/* Single GString * argument */
		value = va_arg (ap, GString *);
		SET_COMMAND (cmd, value->len + 1, reply, pos);
		memcpy (pos, value->str, value->len + 1);
		break;
	case RSPAMD_MILTER_OPTNEG:
		ver = htonl (va_arg (ap, guint32));
		actions = htonl (va_arg (ap, guint32));
		protocol = htonl (va_arg (ap, guint32));

		SET_COMMAND (cmd, sizeof (guint32) * 3, reply, pos);
		memcpy (pos, &ver, sizeof (ver));
		pos += sizeof (ver);
		memcpy (pos, &actions, sizeof (actions));
		pos += sizeof (actions);
		memcpy (pos,  &protocol, sizeof (protocol));
		break;
	default:
		msg_err_milter ("invalid command: %c", cmd);
		break;
	}

	va_end (ap);

	if (reply) {
		obuf = g_malloc (sizeof (*obuf));
		obuf->buf = reply;
		obuf->pos = 0;
		DL_APPEND (priv->out_chain, obuf);
		priv->state = RSPAMD_MILTER_WRITE_REPLY;
		rspamd_milter_plan_io (session, priv, EV_WRITE);

		return TRUE;
	}

	return FALSE;
}

gboolean
rspamd_milter_add_header (struct rspamd_milter_session *session,
		GString *name, GString *value)
{
	return rspamd_milter_send_action (session, RSPAMD_MILTER_ADDHEADER,
		name, value);
}

gboolean
rspamd_milter_del_header (struct rspamd_milter_session *session,
		GString *name)
{
	GString value;
	guint32 idx = 1;

	value.str = (gchar *)"";
	value.len = 0;

	return rspamd_milter_send_action (session, RSPAMD_MILTER_CHGHEADER,
			idx, name, value);
}

void
rspamd_milter_session_unref (struct rspamd_milter_session *session)
{
	REF_RELEASE (session);
}

struct rspamd_milter_session *
rspamd_milter_session_ref (struct rspamd_milter_session *session)
{
	REF_RETAIN (session);

	return session;
}
