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

static gboolean  rspamd_milter_handle_session (
		struct rspamd_milter_session *session,
		struct rspamd_milter_private *priv);

static GQuark
rspamd_milter_quark (void)
{
	return g_quark_from_static_string ("milter");
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

static gboolean
rspamd_milter_consume_input (struct rspamd_milter_session *session,
		struct rspamd_milter_private *priv)
{
	const guchar *p, *end;

	p = priv->parser.buf->str + priv->parser.pos;
	end = priv->parser.buf->str + priv->parser.buf->len;

	while (p < end) {
		switch (priv->parser.state) {
		case st_read_cmd:
			priv->parser.cur_cmd = *p;
			priv->parser.state = st_len_1;
			priv->parser.datalen = 0;
			p++;
			break;
		case st_len_1:
			/* The first length byte in big endian order */
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
			priv->parser.state = st_read_data;
			p++;
			break;
		case st_read_data:
			/* We might need some more data in buffer for further steps */
			break;
		}
	}
}

static gboolean
rspamd_milter_handle_session (struct rspamd_milter_session *session,
		struct rspamd_milter_private *priv)
{
	gssize r;
	GError *err;

	g_assert (session != NULL);

	switch (priv->state) {
	case RSPAMD_MILTER_READ_MORE:
		if (priv->parser.pos >= priv->parser.buf->allocated) {
			priv->parser.buf = rspamd_fstring_grow (priv->parser.buf,
					priv->parser.pos * 2);
		}

		r = read (priv->fd, priv->parser.buf->str + priv->parser.pos,
				priv->parser.buf->allocated - priv->parser.pos);

		if (r == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				rspamd_milter_plan_io (session, priv, EV_READ);
			}
			else {
				/* Fatal IO error */
				err = g_error_new (rspamd_milter_quark (), errno,
						"IO error: %s", strerror (errno));
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
	}
}


gboolean
rspamd_milter_handle_socket (gint fd, const struct timeval *tv,
		struct event_base *ev_base, rspamd_milter_finish finish_cb,
		rspamd_milter_error error_cb, void *ud)
{
	struct rspamd_milter_session *session;
	struct rspamd_milter_private *priv;

	g_assert (finish_cb != NULL);
	g_assert (error_cb != NULL);

	session = g_malloc0 (sizeof (*session));
	priv = g_malloc0 (sizeof (*priv));
	priv->fd = fd;
	priv->ud = ud;
	priv->fin_cb = finish_cb;
	priv->err_cb = error_cb;
	priv->parser.state = st_read_cmd;
	priv->parser.buf = rspamd_fstring_sized_new (100);
	priv->ev_base = ev_base;
	priv->state = RSPAMD_MILTER_READ_MORE;

	if (tv) {
		memcpy (&priv->tv, tv, sizeof (*tv));
		priv->ptv = &priv->tv;
	}
	else {
		priv->ptv = NULL;
	}

	session->priv = priv;

	return rspamd_milter_handle_session (session, priv);
}

gboolean rspamd_milter_set_reply (struct rspamd_milter_session *session,
		rspamd_fstring_t *xcode,
		rspamd_fstring_t *rcode,
		rspamd_fstring_t *reply);

gboolean rspamd_milter_send_action (gint fd,
		struct rspamd_milter_session *session,
		enum rspamd_milter_reply act);

gboolean rspamd_milter_add_header (struct rspamd_milter_session *session,
		GString *name, GString *value);

gboolean rspamd_milter_del_header (struct rspamd_milter_session *session,
		GString *name);

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
