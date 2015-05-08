/* Copyright (c) 2014, Vsevolod Stakhov
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
#include "http.h"
#include "utlist.h"
#include "util.h"
#include "printf.h"
#include "logger.h"
#include "ref.h"
#include "blake2.h"
#include "ottery.h"
#include "keypair_private.h"
#include "cryptobox.h"
#include <limits.h>

#define ENCRYPTED_VERSION " HTTP/1.0"

struct rspamd_http_connection_private {
	struct _rspamd_http_privbuf {
		GString *data;
		ref_entry_t ref;
	} *buf;
	gboolean new_header;
	gboolean encrypted;
	gpointer peer_key;
	struct rspamd_http_keypair *local_key;
	struct rspamd_http_header *header;
	struct http_parser parser;
	struct http_parser_settings parser_cb;
	struct event ev;
	struct timeval tv;
	struct timeval *ptv;
	struct rspamd_http_message *msg;
	struct iovec *out;
	guint outlen;
	gsize wr_pos;
	gsize wr_total;
};

enum http_magic_type {
	HTTP_MAGIC_PLAIN = 0,
	HTTP_MAGIC_HTML,
	HTTP_MAGIC_CSS,
	HTTP_MAGIC_JS,
	HTTP_MAGIC_PNG,
	HTTP_MAGIC_JPG
};

static const struct _rspamd_http_magic {
	const gchar *ext;
	const gchar *ct;
} http_file_types[] = {
	[HTTP_MAGIC_PLAIN] = { "txt", "text/plain" },
	[HTTP_MAGIC_HTML] = { "html", "text/html" },
	[HTTP_MAGIC_CSS] = { "css", "text/css" },
	[HTTP_MAGIC_JS] = { "js", "application/javascript" },
	[HTTP_MAGIC_PNG] = { "png", "image/png" },
	[HTTP_MAGIC_JPG] = { "jpg", "image/jpeg" },
};

static const gchar *http_week[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static const gchar *http_month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
							   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
static const gchar *key_header = "Key";
static const gchar *date_header = "Date";

#define RSPAMD_HTTP_KEY_ID_LEN 5

#define HTTP_ERROR http_error_quark ()
GQuark
http_error_quark (void)
{
	return g_quark_from_static_string ("http-error-quark");
}

static void
rspamd_http_keypair_dtor (struct rspamd_http_keypair *kp)
{
	rspamd_explicit_memzero (kp->sk, sizeof (kp->sk));
	rspamd_explicit_memzero (kp->nm, sizeof (kp->nm));
	g_slice_free1 (sizeof (*kp), kp);
}

static void
rspamd_http_privbuf_dtor (gpointer ud)
{
	struct _rspamd_http_privbuf *p = (struct _rspamd_http_privbuf *)ud;

	if (p->data) {
		g_string_free (p->data, TRUE);
	}
	g_slice_free1 (sizeof (struct _rspamd_http_privbuf), p);
}

static const gchar *
rspamd_http_code_to_str (gint code)
{
	if (code == 200) {
		return "OK";
	}
	else if (code == 404) {
		return "Not found";
	}
	else if (code == 403 || code == 401) {
		return "Not authorized";
	}
	else if (code >= 400 && code < 500) {
		return "Bad request";
	}
	else if (code >= 300 && code < 400) {
		return "See Other";
	}
	else if (code >= 500 && code < 600) {
		return "Internal server error";
	}

	return "Unknown error";
}

/*
 * Obtained from nginx
 * Copyright (C) Igor Sysoev
 */
static guint mday[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

time_t
rspamd_http_parse_date (const gchar *header, gsize len)
{
	const gchar *p, *end;
	gint month;
	guint day, year, hour, min, sec;
	guint64 time;
	enum {
		no = 0, rfc822, /* Tue, 10 Nov 2002 23:50:13   */
		rfc850, /* Tuesday, 10-Dec-02 23:50:13 */
		isoc /* Tue Dec 10 23:50:13 2002    */
	} fmt;

	fmt = 0;
	if (len > 0) {
		end = header + len;
	}
	else {
		end = header + strlen (header);
	}

#if (NGX_SUPPRESS_WARN)
	day = 32;
	year = 2038;
#endif

	for (p = header; p < end; p++) {
		if (*p == ',') {
			break;
		}

		if (*p == ' ') {
			fmt = isoc;
			break;
		}
	}

	for (p++; p < end; p++)
		if (*p != ' ') {
			break;
		}

	if (end - p < 18) {
		return (time_t)-1;
	}

	if (fmt != isoc) {
		if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
			return (time_t)-1;
		}

		day = (*p - '0') * 10 + *(p + 1) - '0';
		p += 2;

		if (*p == ' ') {
			if (end - p < 18) {
				return (time_t)-1;
			}
			fmt = rfc822;

		}
		else if (*p == '-') {
			fmt = rfc850;

		}
		else {
			return (time_t)-1;
		}

		p++;
	}

	switch (*p) {

	case 'J':
		month = *(p + 1) == 'a' ? 0 : *(p + 2) == 'n' ? 5 : 6;
		break;

	case 'F':
		month = 1;
		break;

	case 'M':
		month = *(p + 2) == 'r' ? 2 : 4;
		break;

	case 'A':
		month = *(p + 1) == 'p' ? 3 : 7;
		break;

	case 'S':
		month = 8;
		break;

	case 'O':
		month = 9;
		break;

	case 'N':
		month = 10;
		break;

	case 'D':
		month = 11;
		break;

	default:
		return (time_t)-1;
	}

	p += 3;

	if ((fmt == rfc822 && *p != ' ') || (fmt == rfc850 && *p != '-')) {
		return (time_t)-1;
	}

	p++;

	if (fmt == rfc822) {
		if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9'
			|| *(p + 2) < '0' || *(p + 2) > '9' || *(p + 3) < '0'
			|| *(p + 3) > '9') {
			return (time_t)-1;
		}

		year = (*p - '0') * 1000 + (*(p + 1) - '0') * 100
			+ (*(p + 2) - '0') * 10 + *(p + 3) - '0';
		p += 4;

	}
	else if (fmt == rfc850) {
		if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
			return (time_t)-1;
		}

		year = (*p - '0') * 10 + *(p + 1) - '0';
		year += (year < 70) ? 2000 : 1900;
		p += 2;
	}

	if (fmt == isoc) {
		if (*p == ' ') {
			p++;
		}

		if (*p < '0' || *p > '9') {
			return (time_t)-1;
		}

		day = *p++ - '0';

		if (*p != ' ') {
			if (*p < '0' || *p > '9') {
				return (time_t)-1;
			}

			day = day * 10 + *p++ - '0';
		}

		if (end - p < 14) {
			return (time_t)-1;
		}
	}

	if (*p++ != ' ') {
		return (time_t)-1;
	}

	if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
		return (time_t)-1;
	}

	hour = (*p - '0') * 10 + *(p + 1) - '0';
	p += 2;

	if (*p++ != ':') {
		return (time_t)-1;
	}

	if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
		return (time_t)-1;
	}

	min = (*p - '0') * 10 + *(p + 1) - '0';
	p += 2;

	if (*p++ != ':') {
		return (time_t)-1;
	}

	if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
		return (time_t)-1;
	}

	sec = (*p - '0') * 10 + *(p + 1) - '0';

	if (fmt == isoc) {
		p += 2;

		if (*p++ != ' ') {
			return (time_t)-1;
		}

		if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9'
			|| *(p + 2) < '0' || *(p + 2) > '9' || *(p + 3) < '0'
			|| *(p + 3) > '9') {
			return (time_t)-1;
		}

		year = (*p - '0') * 1000 + (*(p + 1) - '0') * 100
			+ (*(p + 2) - '0') * 10 + *(p + 3) - '0';
	}

	if (hour > 23 || min > 59 || sec > 59) {
		return (time_t)-1;
	}

	if (day == 29 && month == 1) {
		if ((year & 3) || ((year % 100 == 0) && (year % 400) != 0)) {
			return (time_t)-1;
		}

	}
	else if (day > mday[month]) {
		return (time_t)-1;
	}

	/*
	 * shift new year to March 1 and start months from 1 (not 0),
	 * it is needed for Gauss' formula
	 */

	if (--month <= 0) {
		month += 12;
		year -= 1;
	}

	/* Gauss' formula for Gregorian days since March 1, 1 BC */

	time = (guint64) (
	    /* days in years including leap years since March 1, 1 BC */

		365 * year + year / 4 - year / 100 + year / 400

	    /* days before the month */

		+ 367 * month / 12 - 30

	    /* days before the day */

		+ day - 1

	    /*
	     * 719527 days were between March 1, 1 BC and March 1, 1970,
	     * 31 and 28 days were in January and February 1970
	     */

		- 719527 + 31 + 28) * 86400 + hour * 3600 + min * 60 + sec;

	return (time_t) time;
}

static void
rspamd_http_parse_key (GString *data, struct rspamd_http_connection *conn,
		struct rspamd_http_connection_private *priv)
{
	guchar *decoded_id, *decoded_key;
	const gchar *eq_pos;
	gsize id_len, key_len;
	struct rspamd_http_keypair *kp;

	if (priv->local_key == NULL) {
		/* In this case we cannot do anything, e.g. we cannot decrypt payload */
		priv->encrypted = TRUE;
	}
	else {
		/* Check sanity of what we have */
		eq_pos = memchr (data->str, '=', data->len);
		if (eq_pos != NULL) {
			decoded_id = rspamd_decode_base32 (data->str, eq_pos - data->str,
					&id_len);
			decoded_key = rspamd_decode_base32 (eq_pos + 1, data->str + data->len -
					eq_pos - 1, &key_len);
			if (decoded_id != NULL && decoded_key != NULL) {
				if (id_len >= RSPAMD_HTTP_KEY_ID_LEN  &&
						key_len >= sizeof (kp->pk)) {
					if (memcmp (priv->local_key->id, decoded_id,
							RSPAMD_HTTP_KEY_ID_LEN) == 0) {
						kp = g_slice_alloc (sizeof (*kp));
						REF_INIT_RETAIN (kp, rspamd_http_keypair_dtor);
						memcpy (kp->pk, decoded_key, sizeof (kp->pk));
						priv->msg->peer_key = kp;

						if (conn->cache && priv->msg->peer_key) {
							rspamd_keypair_cache_process (conn->cache,
									priv->local_key, priv->msg->peer_key);
						}
					}
				}
			}
			priv->encrypted = TRUE;
			g_free (decoded_key);
			g_free (decoded_id);
		}
	}
}

static inline void
rspamd_http_check_special_header (struct rspamd_http_connection *conn,
		struct rspamd_http_connection_private *priv)
{
	if (g_ascii_strncasecmp (priv->header->name->str, date_header,
			priv->header->name->len) == 0) {
		priv->msg->date = rspamd_http_parse_date (priv->header->value->str,
				priv->header->value->len);
	}
	else if (g_ascii_strncasecmp (priv->header->name->str, key_header,
			priv->header->name->len) == 0) {
		rspamd_http_parse_key (priv->header->value, conn, priv);
	}
}

static gint
rspamd_http_on_url (http_parser * parser, const gchar *at, size_t length)
{
	struct rspamd_http_connection *conn =
		(struct rspamd_http_connection *)parser->data;
	struct rspamd_http_connection_private *priv;

	priv = conn->priv;

	g_string_append_len (priv->msg->url, at, length);

	return 0;
}

static gint
rspamd_http_on_status (http_parser * parser, const gchar *at, size_t length)
{
	struct rspamd_http_connection *conn =
		(struct rspamd_http_connection *)parser->data;
	struct rspamd_http_connection_private *priv;

	priv = conn->priv;

	if (parser->status_code != 200) {
		if (priv->msg->status == NULL) {
			priv->msg->status = g_string_sized_new (128);
		}
		g_string_append_len (priv->msg->status, at, length);
	}

	return 0;
}

static gint
rspamd_http_on_header_field (http_parser * parser,
	const gchar *at,
	size_t length)
{
	struct rspamd_http_connection *conn =
		(struct rspamd_http_connection *)parser->data;
	struct rspamd_http_connection_private *priv;

	priv = conn->priv;

	if (priv->header == NULL) {
		priv->header = g_slice_alloc (sizeof (struct rspamd_http_header));
		priv->header->name = g_slice_alloc0 (sizeof (GString));
		priv->header->value = g_slice_alloc0 (sizeof (GString));
		priv->header->combined = g_string_sized_new (64);
	}
	else if (priv->new_header) {
		g_string_append_len (priv->header->combined, "\r\n", 2);
		priv->header->value->len = priv->header->combined->len -
				priv->header->name->len - 4;
		DL_APPEND (priv->msg->headers, priv->header);
		rspamd_http_check_special_header (conn, priv);
		priv->header = g_slice_alloc (sizeof (struct rspamd_http_header));
		priv->header->name = g_slice_alloc0 (sizeof (GString));
		priv->header->value = g_slice_alloc0 (sizeof (GString));
		priv->header->combined = g_string_sized_new (64);
	}

	priv->new_header = FALSE;
	g_string_append_len (priv->header->combined, at, length);

	return 0;
}

static gint
rspamd_http_on_header_value (http_parser * parser,
	const gchar *at,
	size_t length)
{
	struct rspamd_http_connection *conn =
		(struct rspamd_http_connection *)parser->data;
	struct rspamd_http_connection_private *priv;

	priv = conn->priv;

	if (priv->header == NULL) {
		/* Should not happen */
		return -1;
	}

	if (!priv->new_header) {
		priv->new_header = TRUE;
		priv->header->name->str = priv->header->combined->str;
		priv->header->name->len = priv->header->combined->len;
		g_string_append_len (priv->header->combined, ": ", 2);
		priv->header->value->str = priv->header->combined->str +
				priv->header->combined->len;
	}

	g_string_append_len (priv->header->combined, at, length);

	return 0;
}

static int
rspamd_http_on_headers_complete (http_parser * parser)
{
	struct rspamd_http_connection *conn =
		(struct rspamd_http_connection *)parser->data;
	struct rspamd_http_connection_private *priv;

	priv = conn->priv;

	if (priv->header != NULL) {
		g_string_append_len (priv->header->combined, "\r\n", 2);
		priv->header->value->len = priv->header->combined->len -
			priv->header->name->len - 4;
		DL_APPEND (priv->msg->headers, priv->header);
		rspamd_http_check_special_header (conn, priv);
		priv->header = NULL;
	}

	if (parser->content_length != 0 && parser->content_length != ULLONG_MAX) {
		priv->msg->body = g_string_sized_new (parser->content_length + 1);
	}
	else {
		priv->msg->body = g_string_sized_new (BUFSIZ);
	}

	if (parser->flags & F_SPAMC) {
		priv->msg->flags |= RSPAMD_HTTP_FLAG_SPAMC;
	}

	priv->msg->body_buf.str = priv->msg->body->str;
	priv->msg->method = parser->method;
	priv->msg->code = parser->status_code;

	return 0;
}

static int
rspamd_http_on_body (http_parser * parser, const gchar *at, size_t length)
{
	struct rspamd_http_connection *conn =
		(struct rspamd_http_connection *)parser->data;
	struct rspamd_http_connection_private *priv;

	priv = conn->priv;

	g_string_append_len (priv->msg->body, at, length);

	if ((conn->opts & RSPAMD_HTTP_BODY_PARTIAL) && !priv->encrypted) {
		/* Incremental update is basically impossible for encrypted requests */
		return (conn->body_handler (conn, priv->msg, at, length));
	}

	return 0;
}

static int
rspamd_http_on_body_decrypted (http_parser * parser, const gchar *at, size_t length)
{
	struct rspamd_http_connection *conn =
		(struct rspamd_http_connection *)parser->data;
	struct rspamd_http_connection_private *priv;

	priv = conn->priv;

	if (priv->header != NULL) {
		g_string_append_len (priv->header->combined, "\r\n", 2);
		priv->header->value->len = priv->header->combined->len -
				priv->header->name->len - 4;
		DL_APPEND (priv->msg->headers, priv->header);
		rspamd_http_check_special_header (conn, priv);
		priv->header = NULL;
	}

	if (priv->msg->body->str == 0) {
		priv->msg->body->str = (gchar *)at;
		priv->msg->method = parser->method;
		priv->msg->code = parser->status_code;
	}

	priv->msg->body->len += length;

	return 0;
}

static int
rspamd_http_decrypt_message (struct rspamd_http_connection *conn,
		struct rspamd_http_connection_private *priv,
		struct rspamd_http_keypair *peer_key)
{
	guchar *nonce, *m;
	gsize dec_len;
	struct rspamd_http_message *msg = priv->msg;
	struct rspamd_http_header *hdr, *hdrtmp;
	struct http_parser decrypted_parser;
	struct http_parser_settings decrypted_cb;

	nonce = msg->body->str;
	m = msg->body->str + rspamd_cryptobox_NONCEBYTES +
			rspamd_cryptobox_MACBYTES;
	dec_len = msg->body->len - rspamd_cryptobox_NONCEBYTES -
			rspamd_cryptobox_MACBYTES;

	if (conn->cache) {
		if (!rspamd_cryptobox_decrypt_nm_inplace (m, dec_len, nonce,
				peer_key->nm, m - rspamd_cryptobox_MACBYTES) != 0) {
			msg_err ("cannot verify encrypted message");
			return -1;
		}
	}
	else {
		if (!rspamd_cryptobox_decrypt_inplace (m, dec_len, nonce,
				peer_key->pk, priv->local_key->sk,
				m - rspamd_cryptobox_MACBYTES) != 0) {
			msg_err ("cannot verify encrypted message");
			return -1;
		}
	}

	/* Cleanup message */
	DL_FOREACH_SAFE (msg->headers, hdr, hdrtmp) {
		g_string_free (hdr->combined, TRUE);
		g_slice_free1 (sizeof (GString), hdr->name);
		g_slice_free1 (sizeof (GString), hdr->value);
		g_slice_free1 (sizeof (struct rspamd_http_header), hdr);
	}
	msg->headers = NULL;
	g_string_assign (msg->url, "");
	msg->body->len = 0;
	msg->body->str = NULL;

	http_parser_init (&decrypted_parser,
			conn->type == RSPAMD_HTTP_SERVER ? HTTP_REQUEST : HTTP_RESPONSE);

	memset (&decrypted_cb, 0, sizeof (decrypted_cb));
	decrypted_cb.on_url = rspamd_http_on_url;
	decrypted_cb.on_status = rspamd_http_on_status;
	decrypted_cb.on_header_field = rspamd_http_on_header_field;
	decrypted_cb.on_header_value = rspamd_http_on_header_value;
	decrypted_cb.on_body = rspamd_http_on_body_decrypted;
	decrypted_parser.data = conn;
	decrypted_parser.content_length = dec_len;

	if (http_parser_execute (&decrypted_parser, &decrypted_cb, m,
			dec_len) != (size_t)dec_len) {
		msg_err ("HTTP parser error: %s when parsing encrypted request",
				http_errno_description (decrypted_parser.http_errno));

		return -1;
	}

	return 0;
}

static int
rspamd_http_on_message_complete (http_parser * parser)
{
	struct rspamd_http_connection *conn =
		(struct rspamd_http_connection *)parser->data;
	struct rspamd_http_connection_private *priv;
	int ret = 0;
	struct rspamd_http_keypair *peer_key = NULL;

	priv = conn->priv;

	if ((conn->opts & RSPAMD_HTTP_BODY_PARTIAL) == 0 && priv->encrypted) {
		if (priv->local_key == NULL || priv->msg->peer_key == NULL ||
				priv->msg->body->len < rspamd_cryptobox_NONCEBYTES +
				rspamd_cryptobox_MACBYTES) {
			msg_err ("cannot decrypt message");
			return -1;
		}

		/* We have keys, so we can decrypt message */
		peer_key = (struct rspamd_http_keypair *)priv->msg->peer_key;
		ret = rspamd_http_decrypt_message (conn, priv, peer_key);

		if (ret != 0) {
			return ret;
		}

		if (conn->body_handler != NULL) {
			rspamd_http_connection_ref (conn);
			ret = conn->body_handler (conn,
					priv->msg,
					priv->msg->body->str,
					priv->msg->body->len);
			rspamd_http_connection_unref (conn);
		}
	}
	else if ((conn->opts & RSPAMD_HTTP_BODY_PARTIAL) == 0 && conn->body_handler) {
		g_assert (conn->body_handler != NULL);
		rspamd_http_connection_ref (conn);
		ret = conn->body_handler (conn,
				priv->msg,
				priv->msg->body->str,
				priv->msg->body->len);
		rspamd_http_connection_unref (conn);
	}

	if (ret == 0) {
		if (event_pending (&priv->ev, EV_READ, NULL)) {
			event_del (&priv->ev);
		}

		rspamd_http_connection_ref (conn);
		ret = conn->finish_handler (conn, priv->msg);
		conn->finished = TRUE;
		rspamd_http_connection_unref (conn);
	}

	return ret;
}

static void
rspamd_http_simple_client_helper (struct rspamd_http_connection *conn)
{
	struct event_base *base;

	base = conn->priv->ev.ev_base;
	rspamd_http_connection_reset (conn);
	/* Plan read message */
	rspamd_http_connection_read_message (conn, conn->ud, conn->fd,
			conn->priv->ptv, base);
}

static void
rspamd_http_write_helper (struct rspamd_http_connection *conn)
{
	struct rspamd_http_connection_private *priv;
	struct iovec *start;
	guint niov, i;
	gint flags = 0;
	gsize remain;
	gssize r;
	GError *err;
	struct iovec *cur_iov;
	struct msghdr msg;

	priv = conn->priv;

	if (priv->wr_pos == priv->wr_total) {
		goto call_finish_handler;
	}

	start = &priv->out[0];
	niov = priv->outlen;
	remain = priv->wr_pos;
	/* We know that niov is small enough for that */
	cur_iov = alloca (niov * sizeof (struct iovec));
	memcpy (cur_iov, priv->out, niov * sizeof (struct iovec));
	for (i = 0; i < priv->outlen && remain > 0; i++) {
		/* Find out the first iov required */
		start = &cur_iov[i];
		if (start->iov_len <= remain) {
			remain -= start->iov_len;
			start = &cur_iov[i + 1];
			niov--;
		}
		else {
			start->iov_base = (void *)((char *)start->iov_base + remain);
			start->iov_len -= remain;
			remain = 0;
		}
	}

	memset (&msg, 0, sizeof (msg));
	msg.msg_iov = start;
	msg.msg_iovlen = MIN (IOV_MAX, niov);
	g_assert (niov > 0);
#ifdef MSG_NOSIGNAL
	flags = MSG_NOSIGNAL;
#endif
	r = sendmsg (conn->fd, &msg, flags);

	if (r == -1) {
		err =
			g_error_new (HTTP_ERROR, errno, "IO write error: %s", strerror (
					errno));
		rspamd_http_connection_ref (conn);
		conn->error_handler (conn, err);
		rspamd_http_connection_unref (conn);
		g_error_free (err);
		return;
	}
	else {
		priv->wr_pos += r;
	}

	if (priv->wr_pos >= priv->wr_total) {
		goto call_finish_handler;
	}
	else {
		/* Want to write more */
		event_add (&priv->ev, priv->ptv);
	}

	return;

call_finish_handler:
	if ((conn->opts & RSPAMD_HTTP_CLIENT_SIMPLE) == 0) {
		rspamd_http_connection_ref (conn);
		conn->finished = TRUE;
		conn->finish_handler (conn, priv->msg);
		rspamd_http_connection_unref (conn);
	}
	else {
		/* Plan read message */
		rspamd_http_simple_client_helper (conn);
	}
}

static void
rspamd_http_event_handler (int fd, short what, gpointer ud)
{
	struct rspamd_http_connection *conn = (struct rspamd_http_connection *)ud;
	struct rspamd_http_connection_private *priv;
	struct _rspamd_http_privbuf *pbuf;
	GString *buf;
	gssize r;
	GError *err;

	priv = conn->priv;
	pbuf = priv->buf;
	REF_RETAIN (pbuf);
	rspamd_http_connection_ref (conn);
	buf = priv->buf->data;

	if (what == EV_READ) {
		r = read (fd, buf->str, buf->allocated_len);
		if (r == -1) {
			err = g_error_new (HTTP_ERROR,
					errno,
					"IO read error: %s",
					strerror (errno));
			conn->error_handler (conn, err);
			g_error_free (err);

			REF_RELEASE (pbuf);
			rspamd_http_connection_unref (conn);

			return;
		}
		else if (r == 0) {
			if (!conn->finished) {
				err = g_error_new (HTTP_ERROR,
						errno,
						"IO read error: unexpected EOF");
				conn->error_handler (conn, err);
				g_error_free (err);


			}
			REF_RELEASE (pbuf);
			rspamd_http_connection_unref (conn);

			return;
		}
		else {
			buf->len = r;

			if (http_parser_execute (&priv->parser, &priv->parser_cb, buf->str,
				r) != (size_t)r || priv->parser.http_errno != 0) {
				err = g_error_new (HTTP_ERROR, priv->parser.http_errno,
						"HTTP parser error: %s",
						http_errno_description (priv->parser.http_errno));
				conn->error_handler (conn, err);
				g_error_free (err);

				REF_RELEASE (pbuf);
				rspamd_http_connection_unref (conn);

				return;
			}
		}
	}
	else if (what == EV_TIMEOUT) {
		err = g_error_new (HTTP_ERROR, ETIMEDOUT,
				"IO timeout");
		conn->error_handler (conn, err);
		g_error_free (err);

		REF_RELEASE (pbuf);
		rspamd_http_connection_unref (conn);

		return;
	}
	else if (what == EV_WRITE) {
		rspamd_http_write_helper (conn);
	}

	REF_RELEASE (pbuf);
	rspamd_http_connection_unref (conn);
}

static void
rspamd_http_parser_reset (struct rspamd_http_connection *conn)
{
	struct rspamd_http_connection_private *priv = conn->priv;

	http_parser_init (&priv->parser,
		conn->type == RSPAMD_HTTP_SERVER ? HTTP_REQUEST : HTTP_RESPONSE);

	priv->parser_cb.on_url = rspamd_http_on_url;
	priv->parser_cb.on_status = rspamd_http_on_status;
	priv->parser_cb.on_header_field = rspamd_http_on_header_field;
	priv->parser_cb.on_header_value = rspamd_http_on_header_value;
	priv->parser_cb.on_headers_complete = rspamd_http_on_headers_complete;
	priv->parser_cb.on_body = rspamd_http_on_body;
	priv->parser_cb.on_message_complete = rspamd_http_on_message_complete;
}

struct rspamd_http_connection *
rspamd_http_connection_new (rspamd_http_body_handler_t body_handler,
	rspamd_http_error_handler_t error_handler,
	rspamd_http_finish_handler_t finish_handler,
	unsigned opts,
	enum rspamd_http_connection_type type,
	struct rspamd_keypair_cache *cache)
{
	struct rspamd_http_connection *new;
	struct rspamd_http_connection_private *priv;

	if (error_handler == NULL || finish_handler == NULL) {
		return NULL;
	}

	new = g_slice_alloc0 (sizeof (struct rspamd_http_connection));
	new->opts = opts;
	new->type = type;
	new->body_handler = body_handler;
	new->error_handler = error_handler;
	new->finish_handler = finish_handler;
	new->fd = -1;
	new->ref = 1;
	new->finished = FALSE;
	new->cache = cache;

	/* Init priv */
	priv = g_slice_alloc0 (sizeof (struct rspamd_http_connection_private));
	new->priv = priv;

	rspamd_http_parser_reset (new);
	priv->parser.data = new;

	return new;
}

void
rspamd_http_connection_reset (struct rspamd_http_connection *conn)
{
	struct rspamd_http_connection_private *priv;
	struct rspamd_http_message *msg;

	priv = conn->priv;
	msg = priv->msg;

	/* Clear request */
	if (msg != NULL) {
		if (msg->peer_key) {
			priv->peer_key = msg->peer_key;
			msg->peer_key = NULL;
		}
		rspamd_http_message_free (msg);
		priv->msg = NULL;
	}
	conn->finished = FALSE;
	/* Clear priv */
	event_del (&priv->ev);
	if (priv->buf != NULL) {
		REF_RELEASE (priv->buf);
		priv->buf = NULL;
	}

	rspamd_http_parser_reset (conn);

	if (priv->out != NULL) {
		g_slice_free1 (sizeof (struct iovec) * priv->outlen, priv->out);
		priv->out = NULL;
	}
}

struct rspamd_http_message *
rspamd_http_connection_steal_msg (struct rspamd_http_connection *conn)
{
	struct rspamd_http_connection_private *priv;
	struct rspamd_http_message *msg;

	priv = conn->priv;
	msg = priv->msg;

	/* Clear request */
	if (msg != NULL) {
		if (msg->peer_key) {
			priv->peer_key = msg->peer_key;
			msg->peer_key = NULL;
		}
		priv->msg = NULL;
	}

	return msg;
}

void
rspamd_http_connection_free (struct rspamd_http_connection *conn)
{
	struct rspamd_http_connection_private *priv;
	struct rspamd_http_keypair *peer_key;

	priv = conn->priv;

	if (priv != NULL) {
		rspamd_http_connection_reset (conn);

		if (priv->local_key) {
			REF_RELEASE (priv->local_key);
		}
		if (priv->peer_key) {
			peer_key = (struct rspamd_http_keypair *)priv->peer_key;
			REF_RELEASE (peer_key);
		}

		g_slice_free1 (sizeof (struct rspamd_http_connection_private), priv);
	}

	g_slice_free1 (sizeof (struct rspamd_http_connection),		   conn);
}

void
rspamd_http_connection_read_message (struct rspamd_http_connection *conn,
	gpointer ud, gint fd, struct timeval *timeout, struct event_base *base)
{
	struct rspamd_http_connection_private *priv = conn->priv;
	struct rspamd_http_message *req;

	conn->fd = fd;
	conn->ud = ud;
	req = rspamd_http_new_message (
		conn->type == RSPAMD_HTTP_SERVER ? HTTP_REQUEST : HTTP_RESPONSE);
	priv->msg = req;

	if (priv->peer_key) {
		priv->msg->peer_key = priv->peer_key;
		priv->peer_key = NULL;
		priv->encrypted = TRUE;
	}

	if (timeout == NULL) {
		priv->ptv = NULL;
	}
	else if (&priv->tv != timeout) {
		memcpy (&priv->tv, timeout, sizeof (struct timeval));
		priv->ptv = &priv->tv;
	}

	priv->header = NULL;
	priv->buf = g_slice_alloc0 (sizeof (*priv->buf));
	REF_INIT_RETAIN (priv->buf, rspamd_http_privbuf_dtor);
	priv->buf->data = g_string_sized_new (BUFSIZ);
	priv->new_header = TRUE;

	event_set (&priv->ev,
		fd,
		EV_READ | EV_PERSIST,
		rspamd_http_event_handler,
		conn);
	if (base != NULL) {
		event_base_set (base, &priv->ev);
	}
	event_add (&priv->ev, priv->ptv);
}

static void
rspamd_http_connection_encrypt_message (
		struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg,
		struct rspamd_http_connection_private *priv,
		guchar *pbody,
		guint bodylen,
		guchar *pmethod,
		guint methodlen,
		guint preludelen,
		gint hdrcount,
		guchar *np,
		guchar *mp,
		struct rspamd_http_keypair *peer_key)
{
	struct rspamd_cryptobox_segment *segments;
	guchar *crlfp = mp + rspamd_cryptobox_MACBYTES;
	gint i, cnt;
	guint outlen;
	struct rspamd_http_header *hdr;

	outlen = priv->out[0].iov_len + priv->out[1].iov_len;
	/*
	 * Create segments from the following:
	 * Method, [URL], CRLF, nheaders, CRLF, body
	 */
	segments = g_new (struct rspamd_cryptobox_segment, hdrcount + 5);

	segments[0].data = pmethod;
	segments[0].len = methodlen;

	if (conn->type != RSPAMD_HTTP_SERVER) {
		segments[1].data = msg->url->str;
		segments[1].len = msg->url->len;
		/* space + HTTP version + crlf */
		segments[2].data = crlfp;
		segments[2].len = preludelen - 2;
		crlfp += segments[2].len;
		i = 3;
	}
	else {
		/* Here we send just CRLF */
		segments[1].data = crlfp;
		segments[1].len = 2;
		crlfp += segments[1].len;

		i = 2;
	}


	LL_FOREACH (msg->headers, hdr) {
		segments[i].data = hdr->combined->str;
		segments[i++].len = hdr->combined->len;
	}

	/* crlfp should point now at the second crlf */
	segments[i].data = crlfp;
	segments[i++].len = 2;

	if (pbody) {
		segments[i].data = pbody;
		segments[i++].len = bodylen;
	}

	cnt = i;

	if (conn->cache) {
		rspamd_cryptobox_encryptv_nm_inplace (segments,
			cnt,
			np,
			peer_key->nm, mp);
	}
	else {
		rspamd_cryptobox_encryptv_inplace (segments,
				cnt, np,
				peer_key->pk, priv->local_key->sk, mp);
	}

	/*
	 * iov[0] = base HTTP request
	 * iov[1] = CRLF
	 * iov[2] = nonce
	 * iov[3] = mac
	 * iov[4..i] = encrypted HTTP request/reply
	 */
	priv->out[2].iov_base = np;
	priv->out[2].iov_len = rspamd_cryptobox_NONCEBYTES;
	priv->out[3].iov_base = mp;
	priv->out[3].iov_len = rspamd_cryptobox_MACBYTES;

	outlen += rspamd_cryptobox_NONCEBYTES + rspamd_cryptobox_MACBYTES;

	for (i = 0; i < cnt; i ++) {
		priv->out[i + 4].iov_base = segments[i].data;
		priv->out[i + 4].iov_len = segments[i].len;
		outlen += segments[i].len;
	}

	priv->wr_total = outlen;

	g_free (segments);
}

void
rspamd_http_connection_write_message (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg, const gchar *host, const gchar *mime_type,
	gpointer ud, gint fd, struct timeval *timeout, struct event_base *base)
{
	struct rspamd_http_connection_private *priv = conn->priv;
	struct rspamd_http_header *hdr;
	struct tm t, *ptm;
	gchar datebuf[64], repbuf[128], *pbody;
	gint i, hdrcount, meth_len, preludelen = 0;
	gsize bodylen, enclen;
	GString *buf;
	gboolean encrypted = FALSE;
	gchar *b32_key, *b32_id;
	guchar nonce[rspamd_cryptobox_NONCEBYTES], mac[rspamd_cryptobox_MACBYTES],
		id[BLAKE2B_OUTBYTES];
	guchar *np = NULL, *mp = NULL, *meth_pos = NULL;
	struct rspamd_http_keypair *peer_key = NULL;

	conn->fd = fd;
	conn->ud = ud;
	priv->msg = msg;

	if (timeout == NULL) {
		priv->ptv = NULL;
	}
	else if (timeout != &priv->tv) {
		memcpy (&priv->tv, timeout, sizeof (struct timeval));
		priv->ptv = &priv->tv;
	}

	priv->header = NULL;
	priv->buf = g_slice_alloc0 (sizeof (*priv->buf));
	REF_INIT_RETAIN (priv->buf, rspamd_http_privbuf_dtor);
	priv->buf->data = g_string_sized_new (128);
	buf = priv->buf->data;

	if (priv->peer_key && priv->local_key) {
		priv->msg->peer_key = priv->peer_key;
		priv->peer_key = NULL;
		priv->encrypted = TRUE;
	}

	if (priv->local_key != NULL && msg->peer_key != NULL) {
		encrypted = TRUE;
		if (conn->cache) {
			rspamd_keypair_cache_process (conn->cache,
					priv->local_key, priv->msg->peer_key);
		}
	}

	if (encrypted) {
		if (msg->body == NULL || msg->body->len == 0) {
			pbody = NULL;
			bodylen = 0;
			msg->method = HTTP_GET;
		}
		else {
			pbody = msg->body->str;
			bodylen = msg->body->len;
			msg->method = HTTP_POST;
		}

		if (conn->type == RSPAMD_HTTP_SERVER) {
			/*
			 * iov[0] = base reply
			 * iov[1] = CRLF
			 * iov[2] = nonce
			 * iov[3] = mac
			 * iov[4] = encrypted reply
			 * iov[6] = encrypted crlf
			 * iov[7..n] = encrypted headers
			 * iov[n + 1] = encrypted crlf
			 * [iov[n + 2] = encrypted body]
			 */
			priv->outlen = 7;
			enclen = rspamd_cryptobox_NONCEBYTES + rspamd_cryptobox_MACBYTES +
					4 + /* 2 * CRLF */
					bodylen;
		}
		else {
			/*
			 * iov[0] = base request
			 * iov[1] = CRLF
			 * iov[2] = nonce
			 * iov[3] = mac
			 * iov[4] = encrypted method + space
			 * iov[5] = encrypted url
			 * iov[7] = encrypted prelude
			 * iov[8..n] = encrypted headers
			 * iov[n + 1] = encrypted crlf
			 * [iov[n + 2] = encrypted body]
			 */
			priv->outlen = 8;

			if (bodylen > 0) {
				preludelen = rspamd_snprintf (repbuf, sizeof (repbuf), "%s\r\n"
						"Content-Length: %z\r\n\r\n", ENCRYPTED_VERSION, bodylen);
			}
			else {
				preludelen = rspamd_snprintf (repbuf, sizeof (repbuf), "%s\r\n\r\n",
						ENCRYPTED_VERSION);
			}

			enclen = rspamd_cryptobox_NONCEBYTES + rspamd_cryptobox_MACBYTES +
					preludelen + /* version [content-length] + 2 * CRLF */
					bodylen;
		}

		if (bodylen > 0) {
			priv->outlen ++;
		}
	}
	else {
		if (msg->method < HTTP_SYMBOLS) {
			if (msg->body == NULL || msg->body->len == 0) {
				pbody = NULL;
				bodylen = 0;
				priv->outlen = 2;
				msg->method = HTTP_GET;
			}
			else {
				pbody = msg->body->str;
				bodylen = msg->body->len;
				priv->outlen = 3;
				msg->method = HTTP_POST;
			}
		}
		else if (msg->body != NULL) {
			pbody = msg->body->str;
			bodylen = msg->body->len;
			priv->outlen = 2;
		}
		else {
			/* Invalid body for spamc method */
			return;
		}
	}

	peer_key = (struct rspamd_http_keypair *)msg->peer_key;

	priv->wr_total = bodylen + buf->len + 2;
	hdrcount = 0;

	DL_FOREACH (msg->headers, hdr) {
		/* <name: value\r\n> */
		priv->wr_total += hdr->combined->len;
		enclen += hdr->combined->len;
		priv->outlen ++;
		hdrcount ++;
	}

	/* Allocate iov */
	priv->out = g_slice_alloc (sizeof (struct iovec) * priv->outlen);
	priv->wr_pos = 0;

	if (conn->type == RSPAMD_HTTP_SERVER) {
		/* Format reply */
		if (msg->method < HTTP_SYMBOLS) {
			ptm = gmtime (&msg->date);
			t = *ptm;
			rspamd_snprintf (datebuf,
				sizeof (datebuf),
				"%s, %02d %s %4d %02d:%02d:%02d GMT",
				http_week[t.tm_wday],
				t.tm_mday,
				http_month[t.tm_mon],
				t.tm_year + 1900,
				t.tm_hour,
				t.tm_min,
				t.tm_sec);
			if (mime_type == NULL) {
				mime_type = encrypted ? "application/octet-stream" : "text/plain";
			}
			if (encrypted) {
				/* Internal reply (encrypted) */
				meth_len = rspamd_snprintf (repbuf, sizeof (repbuf),
						"HTTP/1.1 %d %s\r\n"
						"Connection: close\r\n"
						"Server: %s\r\n"
						"Date: %s\r\n"
						"Content-Length: %z\r\n",
						"Content-Type: %s\r\n",
						msg->code,
						msg->status ? msg->status->str :
								rspamd_http_code_to_str (msg->code),
						"rspamd/" RVERSION,
						datebuf,
						bodylen,
						mime_type);
				enclen += meth_len;
				/* External reply */
				rspamd_printf_gstring (buf, "HTTP/1.1 200 OK\r\n"
						"Connection: close\r\n"
						"Server: rspamd\r\n"
						"Date: %s\r\n"
						"Content-Length: %z\r\n"
						"Content-Type: application/octet-stream\r\n",
						datebuf,
						enclen);
			}
			else {
				rspamd_printf_gstring (buf, "HTTP/1.1 %d %s\r\n"
						"Connection: close\r\n"
						"Server: %s\r\n"
						"Date: %s\r\n"
						"Content-Length: %z\r\n"
						"Content-Type: %s\r\n",
						msg->code,
						msg->status ? msg->status->str :
							rspamd_http_code_to_str (msg->code),
						"rspamd/" RVERSION,
						datebuf,
						bodylen,
						mime_type);
			}
		}
		else {
			/* Legacy spamd reply */
			if (msg->flags & RSPAMD_HTTP_FLAG_SPAMC) {
				rspamd_printf_gstring (buf, "SPAMD/1.1 0 EX_OK\r\n");
			}
			else {
				rspamd_printf_gstring (buf, "RSPAMD/1.3 0 EX_OK\r\n");
			}
		}
	}
	else {
		/* Format request */
		enclen += msg->url->len +
				strlen (http_method_str (msg->method)) + 1 /* method + space */;
		if (host == NULL && msg->host == NULL) {
			/* Fallback to HTTP/1.0 */
			if (encrypted) {
				rspamd_printf_gstring (buf, "%s %s HTTP/1.0\r\n"
					"Content-Length: %z\r\n",
					"POST",
					"/post",
					enclen);
			}
			else {
				rspamd_printf_gstring (buf, "%s %s HTTP/1.0\r\n"
					"Content-Length: %z\r\n",
					http_method_str (msg->method),
					msg->url->str,
					bodylen);
			}
		}
		else {
			if (encrypted) {
				rspamd_printf_gstring (buf, "%s %s HTTP/1.1\r\n"
						"Connection: close\r\n"
						"Host: %s\r\n"
						"Content-Length: %z\r\n",
						"POST",
						"/post",
						host != NULL ? host : msg->host->str,
						enclen);
			}
			else {
				rspamd_printf_gstring (buf, "%s %s HTTP/1.1\r\n"
						"Connection: close\r\n"
						"Host: %s\r\n"
						"Content-Length: %z\r\n",
						http_method_str (msg->method),
						msg->url->str,
						host != NULL ? host : msg->host->str,
						bodylen);
			}

		}
		if (encrypted) {
			memcpy (id, peer_key->id, sizeof (id));
			b32_key = rspamd_encode_base32 (priv->local_key->pk,
					sizeof (priv->local_key->pk));
			b32_id = rspamd_encode_base32 (id, RSPAMD_HTTP_KEY_ID_LEN);
			/* XXX: add some fuzz here */
			rspamd_printf_gstring (buf, "Key: %s=%s\r\n", b32_id, b32_key);
			g_free (b32_key);
			g_free (b32_id);
		}
	}

	/* Now set up all iov */
	priv->out[0].iov_base = buf->str;
	priv->out[0].iov_len = buf->len;

	if (encrypted) {
		ottery_rand_bytes (nonce, sizeof (nonce));
		memset (mac, 0, sizeof (mac));

		/* Add some used vars */
		meth_pos = buf->str + buf->len;

		if (conn->type == RSPAMD_HTTP_SERVER) {
			g_string_append_len (buf, repbuf, meth_len);
		}
		else {
			meth_len = strlen (http_method_str (msg->method)) + 1; /* + space */
			g_string_append_len (buf, http_method_str (msg->method),
					meth_len - 1);
			g_string_append_c (buf, ' ');
		}
		np = buf->str + buf->len;
		g_string_append_len (buf, nonce, sizeof (nonce));
		mp = buf->str + buf->len;
		g_string_append_len (buf, mac, sizeof (mac));
		/* Need to be encrypted */
		if (conn->type == RSPAMD_HTTP_SERVER) {
			g_string_append (buf, "\r\n\r\n");
		}
		else {
			g_string_append_len (buf, repbuf, preludelen);
		}
	}


	if (encrypted) {
		/* Finish external HTTP request */
		priv->out[1].iov_base = "\r\n";
		priv->out[1].iov_len = 2;
		/* Encrypt the real request */
		rspamd_http_connection_encrypt_message (conn, msg, priv, pbody, bodylen,
				meth_pos, meth_len, preludelen, hdrcount, np, mp, peer_key);
	}
	else {
		i = 1;
		LL_FOREACH (msg->headers, hdr) {
			priv->out[i].iov_base = hdr->combined->str;
			priv->out[i++].iov_len = hdr->combined->len;
		}
		if (msg->method < HTTP_SYMBOLS) {
			priv->out[i].iov_base = "\r\n";
			priv->out[i++].iov_len = 2;
		}
		else {
			/* No CRLF for compatibility reply */
			priv->wr_total -= 2;
		}
		if (msg->body != NULL) {

			if (msg->body_buf.str == NULL) {
				msg->body_buf.str = msg->body->str;
			}
			priv->out[i].iov_base = pbody;
			priv->out[i++].iov_len = bodylen;
		}
	}

	event_set (&priv->ev, fd, EV_WRITE, rspamd_http_event_handler, conn);

	if (base != NULL) {
		event_base_set (base, &priv->ev);
	}

	event_add (&priv->ev, priv->ptv);
}

struct rspamd_http_message *
rspamd_http_new_message (enum http_parser_type type)
{
	struct rspamd_http_message *new;

	new = g_slice_alloc (sizeof (struct rspamd_http_message));
	if (type == HTTP_REQUEST) {
		new->url = g_string_sized_new (32);
	}
	else {
		new->url = NULL;
		new->code = 200;
	}
	new->headers = NULL;
	new->date = 0;
	new->body = NULL;
	memset (&new->body_buf, 0, sizeof (new->body_buf));
	new->status = NULL;
	new->host = NULL;
	new->port = 80;
	new->type = type;
	new->method = HTTP_GET;
	new->peer_key = NULL;
	new->flags = 0;

	return new;
}

struct rspamd_http_message*
rspamd_http_message_from_url (const gchar *url)
{
	struct http_parser_url pu;
	struct rspamd_http_message *msg;
	const gchar *host, *path;
	size_t pathlen;

	if (url == NULL) {
		return NULL;
	}

	memset (&pu, 0, sizeof (pu));
	if (http_parser_parse_url (url, strlen (url), FALSE, &pu) != 0) {
		msg_warn ("cannot parse URL: %s", url);
		return NULL;
	}

	if ((pu.field_set & (1 << UF_HOST)) == 0) {
		msg_warn ("no host argument in URL: %s", url);
		return NULL;
	}
	if ((pu.field_set & (1 << UF_PATH)) == 0) {
		path = "/";
		pathlen = 1;
	}
	else {
		path = url + pu.field_data[UF_PATH].off;
		pathlen = pu.field_data[UF_PATH].len;
	}

	msg = rspamd_http_new_message (HTTP_REQUEST);
	host = url + pu.field_data[UF_HOST].off;

	if ((pu.field_set & (1 << UF_PORT)) != 0) {
		msg->port = pu.port;
	}
	else {
		/* XXX: magic constant */
		msg->port = 80;
	}

	msg->host = g_string_new_len (host, pu.field_data[UF_HOST].len);
	g_string_append_len (msg->url, path, pathlen);

	return msg;
}

void
rspamd_http_message_free (struct rspamd_http_message *msg)
{
	struct rspamd_http_header *hdr, *tmp_hdr;

	LL_FOREACH_SAFE (msg->headers, hdr, tmp_hdr)
	{
		g_string_free (hdr->combined, TRUE);
		g_slice_free1 (sizeof (GString), hdr->name);
		g_slice_free1 (sizeof (GString), hdr->value);
		g_slice_free1 (sizeof (struct rspamd_http_header), hdr);
	}
	if (msg->body != NULL) {
		g_string_free (msg->body, FALSE);
		g_free (msg->body_buf.str);
	}
	if (msg->url != NULL) {
		g_string_free (msg->url, TRUE);
	}
	if (msg->status != NULL) {
		g_string_free (msg->status, TRUE);
	}
	if (msg->host != NULL) {
		g_string_free (msg->host, TRUE);
	}
	if (msg->peer_key != NULL) {
		rspamd_http_connection_key_unref (msg->peer_key);
	}
	g_slice_free1 (sizeof (struct rspamd_http_message), msg);
}

void
rspamd_http_message_add_header (struct rspamd_http_message *msg,
	const gchar *name,
	const gchar *value)
{
	struct rspamd_http_header *hdr;
	guint nlen, vlen;

	if (msg != NULL && name != NULL && value != NULL) {
		hdr = g_slice_alloc (sizeof (struct rspamd_http_header));
		nlen = strlen (name);
		vlen = strlen (value);
		hdr->combined = g_string_sized_new (nlen + vlen + 4);
		rspamd_printf_gstring (hdr->combined, "%s: %s\r\n", name, value);
		hdr->value = g_slice_alloc (sizeof (GString));
		hdr->name = g_slice_alloc (sizeof (GString));
		hdr->name->str = hdr->combined->str;
		hdr->name->len = nlen;
		hdr->value->str = hdr->combined->str + nlen + 2;
		hdr->value->len = vlen;
		DL_APPEND (msg->headers, hdr);
	}
}

const gchar *
rspamd_http_message_find_header (struct rspamd_http_message *msg,
	const gchar *name)
{
	struct rspamd_http_header *hdr;
	const gchar *res = NULL;
	guint slen = strlen (name);

	if (msg != NULL) {
		LL_FOREACH (msg->headers, hdr)
		{
			if (hdr->name->len == slen) {
				if (g_ascii_strncasecmp (hdr->name->str, name, slen) == 0) {
					res = hdr->value->str;
					break;
				}
			}
		}
	}

	return res;
}

gboolean rspamd_http_message_remove_header (struct rspamd_http_message *msg,
	const gchar *name)
{
	struct rspamd_http_header *hdr, *tmp;
	gboolean res = FALSE;
	guint slen = strlen (name);

	if (msg != NULL) {
		DL_FOREACH_SAFE (msg->headers, hdr, tmp) {
			if (hdr->name->len == slen) {
				if (g_ascii_strncasecmp (hdr->name->str, name, slen) == 0) {
					res = TRUE;
					DL_DELETE (msg->headers, hdr);
					g_string_free (hdr->combined, TRUE);
					g_slice_free1 (sizeof (GString), hdr->value);
					g_slice_free1 (sizeof (GString), hdr->name);
					g_slice_free1 (sizeof (*hdr), hdr);
				}
			}
		}
	}

	return res;
}

/*
 * HTTP router functions
 */

static void
rspamd_http_entry_free (struct rspamd_http_connection_entry *entry)
{
	if (entry != NULL) {
		close (entry->conn->fd);
		rspamd_http_connection_unref (entry->conn);
		if (entry->rt->finish_handler) {
			entry->rt->finish_handler (entry);
		}

		DL_DELETE (entry->rt->conns, entry);
		g_slice_free1 (sizeof (struct rspamd_http_connection_entry), entry);
	}
}

static void
rspamd_http_router_error_handler (struct rspamd_http_connection *conn,
	GError *err)
{
	struct rspamd_http_connection_entry *entry = conn->ud;
	struct rspamd_http_message *msg;

	if (entry->is_reply) {
		/* At this point we need to finish this session and close owned socket */
		if (entry->rt->error_handler != NULL) {
			entry->rt->error_handler (entry, err);
		}
		rspamd_http_entry_free (entry);
	}
	else {
		/* Here we can write a reply to a client */
		if (entry->rt->error_handler != NULL) {
			entry->rt->error_handler (entry, err);
		}
		msg = rspamd_http_new_message (HTTP_RESPONSE);
		msg->date = time (NULL);
		msg->code = err->code;
		msg->body = g_string_new (err->message);
		rspamd_http_connection_reset (entry->conn);
		rspamd_http_connection_write_message (entry->conn,
			msg,
			NULL,
			"text/plain",
			entry,
			entry->conn->fd,
			entry->rt->ptv,
			entry->rt->ev_base);
		entry->is_reply = TRUE;
	}
}

static const gchar *
rspamd_http_router_detect_ct (const gchar *path)
{
	const gchar *dot;
	guint i;

	dot = strrchr (path, '.');
	if (dot == NULL) {
		return http_file_types[HTTP_MAGIC_PLAIN].ct;
	}
	dot++;

	for (i = 0; i < G_N_ELEMENTS (http_file_types); i++) {
		if (strcmp (http_file_types[i].ext, dot) == 0) {
			return http_file_types[i].ct;
		}
	}

	return http_file_types[HTTP_MAGIC_PLAIN].ct;
}

static gboolean
rspamd_http_router_is_subdir (const gchar *parent, const gchar *sub)
{
	if (parent == NULL || sub == NULL || *parent == '\0') {
		return FALSE;
	}

	while (*parent != '\0') {
		if (*sub != *parent) {
			return FALSE;
		}
		parent++;
		sub++;
	}

	parent--;
	if (*parent == G_DIR_SEPARATOR) {
		return TRUE;
	}

	return (*sub == G_DIR_SEPARATOR || *sub == '\0');
}

static gboolean
rspamd_http_router_try_file (struct rspamd_http_connection_entry *entry,
	struct rspamd_http_message *msg, gboolean expand_path)
{
	struct stat st;
	gint fd;
	gchar filebuf[PATH_MAX], realbuf[PATH_MAX], *dir;
	struct rspamd_http_message *reply_msg;

	rspamd_snprintf (filebuf, sizeof (filebuf), "%s%c%v",
		entry->rt->default_fs_path, G_DIR_SEPARATOR, msg->url);

	if (realpath (filebuf, realbuf) == NULL ||
		lstat (realbuf, &st) == -1) {
		return FALSE;
	}

	if (S_ISDIR (st.st_mode) && expand_path) {
		/* Try to append 'index.html' to the url */
		g_string_append_printf (msg->url, "%c%s", G_DIR_SEPARATOR,
			"index.html");
		return rspamd_http_router_try_file (entry, msg, FALSE);
	}
	else if (!S_ISREG (st.st_mode)) {
		return FALSE;
	}

	/* We also need to ensure that file is inside the defined dir */
	rspamd_strlcpy (filebuf, realbuf, sizeof (filebuf));
	dir = dirname (filebuf);
	if (dir == NULL ||
		!rspamd_http_router_is_subdir (entry->rt->default_fs_path,
		dir)) {
		return FALSE;
	}

	fd = open (realbuf, O_RDONLY);
	if (fd == -1) {
		return FALSE;
	}

	reply_msg = rspamd_http_new_message (HTTP_RESPONSE);
	reply_msg->date = time (NULL);
	reply_msg->code = 200;

	reply_msg->body = g_string_sized_new (st.st_size);
	reply_msg->body->len = st.st_size;
	reply_msg->body_buf.len = st.st_size;
	reply_msg->body_buf.str = reply_msg->body->str;

	if (read (fd, reply_msg->body->str, st.st_size) != st.st_size) {
		close (fd);
		rspamd_http_message_free (reply_msg);
		return FALSE;
	}

	reply_msg->body_buf.str[st.st_size] = '\0';

	close (fd);

	rspamd_http_connection_reset (entry->conn);

	msg_debug ("requested file %s", realbuf);
	rspamd_http_connection_write_message (entry->conn, reply_msg, NULL,
		rspamd_http_router_detect_ct (realbuf), entry, entry->conn->fd,
		entry->rt->ptv, entry->rt->ev_base);

	return TRUE;
}

static int
rspamd_http_router_finish_handler (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg)
{
	struct rspamd_http_connection_entry *entry = conn->ud;
	rspamd_http_router_handler_t handler = NULL;
	gpointer found;
	struct rspamd_http_message *err_msg;
	GError *err;

	G_STATIC_ASSERT (sizeof (rspamd_http_router_handler_t) ==
		sizeof (gpointer));

	if (entry->is_reply) {
		/* Request is finished, it is safe to free a connection */
		rspamd_http_entry_free (entry);
	}
	else {
		/* Search for path */
		if (msg->url != NULL && msg->url->len != 0) {
			found = g_hash_table_lookup (entry->rt->paths, msg->url->str);
			memcpy (&handler, &found, sizeof (found));
			msg_debug ("requested known path: %v", msg->url);
		}
		entry->is_reply = TRUE;
		if (handler != NULL) {
			return handler (entry, msg);
		}
		else {
			if (entry->rt->default_fs_path == NULL ||
				!rspamd_http_router_try_file (entry, msg, TRUE)) {
				err = g_error_new (HTTP_ERROR, 404,
						"Not found");
				if (entry->rt->error_handler != NULL) {
					entry->rt->error_handler (entry, err);
				}
				msg_info ("path: %v not found", msg->url);
				err_msg = rspamd_http_new_message (HTTP_RESPONSE);
				err_msg->date = time (NULL);
				err_msg->code = err->code;
				err_msg->body = g_string_new (err->message);
				rspamd_http_connection_reset (entry->conn);
				rspamd_http_connection_write_message (entry->conn,
					err_msg,
					NULL,
					"text/plain",
					entry,
					entry->conn->fd,
					entry->rt->ptv,
					entry->rt->ev_base);
				g_error_free (err);
			}
		}
	}

	return 0;
}

struct rspamd_http_connection_router *
rspamd_http_router_new (rspamd_http_router_error_handler_t eh,
	rspamd_http_router_finish_handler_t fh,
	struct timeval *timeout, struct event_base *base,
	const char *default_fs_path,
	struct rspamd_keypair_cache *cache)
{
	struct rspamd_http_connection_router * new;
	struct stat st;

	new = g_slice_alloc0 (sizeof (struct rspamd_http_connection_router));
	new->paths = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
	new->conns = NULL;
	new->error_handler = eh;
	new->finish_handler = fh;
	new->ev_base = base;
	if (timeout) {
		new->tv = *timeout;
		new->ptv = &new->tv;
	}
	else {
		new->ptv = NULL;
	}

	new->default_fs_path = NULL;

	if (default_fs_path != NULL) {
		if (stat (default_fs_path, &st) == -1) {
			msg_err ("cannot stat %s", default_fs_path);
		}
		else {
			if (!S_ISDIR (st.st_mode)) {
				msg_err ("path %s is not a directory", default_fs_path);
			}
			else {
				new->default_fs_path = realpath (default_fs_path, NULL);
			}
		}
	}

	new->cache = cache;

	return new;
}

void
rspamd_http_router_set_key (struct rspamd_http_connection_router *router,
		gpointer key)
{
	struct rspamd_http_keypair *kp = (struct rspamd_http_keypair *)key;

	g_assert (key != NULL);
	REF_RETAIN (kp);

	router->key = key;
}

void
rspamd_http_router_add_path (struct rspamd_http_connection_router *router,
	const gchar *path, rspamd_http_router_handler_t handler)
{
	gpointer ptr;
	G_STATIC_ASSERT (sizeof (rspamd_http_router_handler_t) ==
		sizeof (gpointer));

	if (path != NULL && handler != NULL && router != NULL) {
		memcpy (&ptr, &handler, sizeof (ptr));
		g_hash_table_insert (router->paths, (gpointer)path, ptr);
	}
}

void
rspamd_http_router_handle_socket (struct rspamd_http_connection_router *router,
	gint fd, gpointer ud)
{
	struct rspamd_http_connection_entry *conn;

	conn = g_slice_alloc (sizeof (struct rspamd_http_connection_entry));
	conn->rt = router;
	conn->ud = ud;
	conn->is_reply = FALSE;

	conn->conn = rspamd_http_connection_new (NULL,
			rspamd_http_router_error_handler,
			rspamd_http_router_finish_handler,
			0,
			RSPAMD_HTTP_SERVER, router->cache);

	if (router->key) {
		rspamd_http_connection_set_key (conn->conn, router->key);
	}

	rspamd_http_connection_read_message (conn->conn, conn, fd, router->ptv,
		router->ev_base);
	DL_PREPEND (router->conns, conn);
}

void
rspamd_http_router_free (struct rspamd_http_connection_router *router)
{
	struct rspamd_http_connection_entry *conn, *tmp;
	struct rspamd_http_keypair *kp;

	if (router) {
		DL_FOREACH_SAFE (router->conns, conn, tmp)
		{
			rspamd_http_entry_free (conn);
		}

		if (router->key) {
			kp = (struct rspamd_http_keypair *)router->key;
			REF_RELEASE (kp);
		}

		if (router->cache) {
			rspamd_keypair_cache_destroy (router->cache);
		}

		if (router->default_fs_path != NULL) {
			g_free (router->default_fs_path);
		}
		g_hash_table_unref (router->paths);
		g_slice_free1 (sizeof (struct rspamd_http_connection_router), router);
	}
}

gpointer
rspamd_http_connection_make_key (gchar *key, gsize keylen)
{
	guchar *decoded_sk, *decoded_pk;
	gsize decoded_len;
	struct rspamd_http_keypair *kp;

	decoded_sk = rspamd_decode_base32 (key, keylen / 2, &decoded_len);
	decoded_pk = rspamd_decode_base32 (key + keylen / 2, keylen / 2, &decoded_len);

	if (decoded_pk != NULL && decoded_sk != NULL) {
		if (decoded_len == rspamd_cryptobox_PKBYTES) {
			kp = g_slice_alloc (sizeof (*kp));
			REF_INIT_RETAIN (kp, rspamd_http_keypair_dtor);
			memcpy (kp->sk, decoded_sk, rspamd_cryptobox_SKBYTES);
			memcpy (kp->pk, decoded_pk, rspamd_cryptobox_PKBYTES);
			blake2b (kp->id, kp->pk, NULL, sizeof (kp->id), sizeof (kp->pk), 0);

			return (gpointer)kp;
		}
		g_free (decoded_pk);
		g_free (decoded_sk);
	}

	return NULL;
}

gpointer
rspamd_http_connection_gen_key (void)
{
	struct rspamd_http_keypair *kp;

	kp = g_slice_alloc (sizeof (*kp));
	REF_INIT_RETAIN (kp, rspamd_http_keypair_dtor);

	rspamd_cryptobox_keypair (kp->pk, kp->sk);
	blake2b (kp->id, kp->pk, NULL, sizeof (kp->id), sizeof (kp->pk), 0);

	return (gpointer)kp;
}

static void
rspamd_http_print_key_component (guchar *data, gsize datalen,
		GString *res, guint how, const gchar *description)
{
	gchar *b32;

	if (how & RSPAMD_KEYPAIR_HUMAN) {
		g_string_append_printf (res, "%s: ", description);
	}

	if (how & RSPAMD_KEYPAIR_BASE32) {
		b32 = rspamd_encode_base32 (data, datalen);
		g_string_append_printf (res, "%s", b32);
		g_free (b32);
	}
	else {
		g_string_append_len (res, data, datalen);
	}

	if (how & RSPAMD_KEYPAIR_HUMAN) {
		g_string_append_c (res, '\n');
	}
}

GString *
rspamd_http_connection_print_key (gpointer key, guint how)
{
	struct rspamd_http_keypair *kp = (struct rspamd_http_keypair *)key;
	GString *res;

	g_assert (key != NULL);

	res = g_string_new (NULL);

	if ((how & RSPAMD_KEYPAIR_PUBKEY)) {
		rspamd_http_print_key_component (kp->pk, sizeof (kp->pk), res, how,
				"Public key");
	}
	if ((how & RSPAMD_KEYPAIR_PRIVKEY)) {
		rspamd_http_print_key_component (kp->sk, sizeof (kp->sk), res, how,
				"Private key");
	}
	if ((how & RSPAMD_KEYPAIR_ID)) {
		rspamd_http_print_key_component (kp->id, RSPAMD_HTTP_KEY_ID_LEN, res, how,
				"Key ID");
	}

	return res;
}

void
rspamd_http_connection_set_key (struct rspamd_http_connection *conn,
		gpointer key)
{
	struct rspamd_http_connection_private *priv = conn->priv;
	struct rspamd_http_keypair *kp = (struct rspamd_http_keypair *)key;

	g_assert (key != NULL);
	REF_RETAIN (kp);
	priv->local_key = kp;
}

gboolean
rspamd_http_connection_is_encrypted (struct rspamd_http_connection *conn)
{
	struct rspamd_http_connection_private *priv = conn->priv;

	if (priv->peer_key != NULL) {
		return TRUE;
	}
	else if (priv->msg) {
		return priv->msg->peer_key != NULL;
	}

	return FALSE;
}

void
rspamd_http_connection_key_unref (gpointer key)
{
	struct rspamd_http_keypair *kp = (struct rspamd_http_keypair *)key;

	g_assert (key != NULL);
	REF_RELEASE (kp);
}

gpointer
rspamd_http_connection_key_ref (gpointer key)
{
	struct rspamd_http_keypair *kp = (struct rspamd_http_keypair *)key;

	g_assert (key != NULL);
	REF_RETAIN (kp);

	return kp;
}

gpointer
rspamd_http_connection_make_peer_key (const gchar *key)
{
	guchar *pk_decoded;
	gsize dec_len;
	struct rspamd_http_keypair *kp = NULL;

	pk_decoded = rspamd_decode_base32 (key, strlen (key), &dec_len);

	if (pk_decoded != NULL && dec_len == rspamd_cryptobox_PKBYTES) {
		kp = g_slice_alloc (sizeof (*kp));
		REF_INIT_RETAIN (kp, rspamd_http_keypair_dtor);
		memcpy (kp->pk, pk_decoded, sizeof (kp->pk));
		blake2b (kp->id, kp->pk, NULL, sizeof (kp->id), sizeof (kp->pk), 0);
	}

	g_free (pk_decoded);

	return kp;
}
