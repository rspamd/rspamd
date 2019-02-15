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
#include "../../contrib/mumhash/mum.h"
#include "http_private.h"
#include "utlist.h"
#include "util.h"
#include "printf.h"
#include "logger.h"
#include "ref.h"
#include "ottery.h"
#include "keypair_private.h"
#include "cryptobox.h"
#include "unix-std.h"
#include "libutil/ssl_util.h"
#include "libutil/regexp.h"
#include "libserver/url.h"

#include <openssl/err.h>

#define ENCRYPTED_VERSION " HTTP/1.0"

struct _rspamd_http_privbuf {
	rspamd_fstring_t *data;
	const gchar *zc_buf;
	gsize zc_remain;
	ref_entry_t ref;
};

enum rspamd_http_priv_flags {
	RSPAMD_HTTP_CONN_FLAG_ENCRYPTED = 1 << 0,
	RSPAMD_HTTP_CONN_FLAG_NEW_HEADER = 1 << 1,
	RSPAMD_HTTP_CONN_FLAG_RESETED = 1 << 2,
	RSPAMD_HTTP_CONN_FLAG_TOO_LARGE = 1 << 3,
	RSPAMD_HTTP_CONN_FLAG_ENCRYPTION_NEEDED = 1 << 4,
};

#define IS_CONN_ENCRYPTED(c) ((c)->flags & RSPAMD_HTTP_CONN_FLAG_ENCRYPTED)
#define IS_CONN_RESETED(c) ((c)->flags & RSPAMD_HTTP_CONN_FLAG_RESETED)

struct rspamd_http_connection_private {
	gpointer ssl_ctx;
	struct rspamd_ssl_connection *ssl;
	struct _rspamd_http_privbuf *buf;
	struct rspamd_cryptobox_pubkey *peer_key;
	struct rspamd_cryptobox_keypair *local_key;
	struct rspamd_http_header *header;
	struct http_parser parser;
	struct http_parser_settings parser_cb;
	struct event ev;
	struct timeval tv;
	struct timeval *ptv;
	struct rspamd_http_message *msg;
	struct iovec *out;
	guint outlen;
	enum rspamd_http_priv_flags flags;
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
static const rspamd_ftok_t key_header = {
		.begin = "Key",
		.len = 3
};
static const rspamd_ftok_t date_header = {
		.begin = "Date",
		.len = 4
};
static const rspamd_ftok_t last_modified_header = {
		.begin = "Last-Modified",
		.len = 13
};

static void rspamd_http_message_storage_cleanup (struct rspamd_http_message *msg);
static gboolean rspamd_http_message_grow_body (struct rspamd_http_message *msg,
		gsize len);

#define HTTP_ERROR http_error_quark ()
GQuark
http_error_quark (void)
{
	return g_quark_from_static_string ("http-error-quark");
}

static void
rspamd_http_privbuf_dtor (gpointer ud)
{
	struct _rspamd_http_privbuf *p = (struct _rspamd_http_privbuf *)ud;

	if (p->data) {
		rspamd_fstring_free (p->data);
	}

	g_free (p);
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

	day = 32;
	year = 2038;

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
rspamd_http_parse_key (rspamd_ftok_t *data, struct rspamd_http_connection *conn,
		struct rspamd_http_connection_private *priv)
{
	guchar *decoded_id;
	const gchar *eq_pos;
	gsize id_len;
	struct rspamd_cryptobox_pubkey *pk;

	if (priv->local_key == NULL) {
		/* In this case we cannot do anything, e.g. we cannot decrypt payload */
		priv->flags &= ~RSPAMD_HTTP_CONN_FLAG_ENCRYPTED;
	}
	else {
		/* Check sanity of what we have */
		eq_pos = memchr (data->begin, '=', data->len);
		if (eq_pos != NULL) {
			decoded_id = rspamd_decode_base32 (data->begin, eq_pos - data->begin,
					&id_len);

			if (decoded_id != NULL && id_len >= RSPAMD_KEYPAIR_SHORT_ID_LEN) {
				pk = rspamd_pubkey_from_base32 (eq_pos + 1,
						data->begin + data->len - eq_pos - 1,
						RSPAMD_KEYPAIR_KEX,
						RSPAMD_CRYPTOBOX_MODE_25519);
				if (pk != NULL) {
					if (memcmp (rspamd_keypair_get_id (priv->local_key),
							decoded_id,
							RSPAMD_KEYPAIR_SHORT_ID_LEN) == 0) {
						priv->msg->peer_key = pk;

						if (conn->cache && priv->msg->peer_key) {
							rspamd_keypair_cache_process (conn->cache,
									priv->local_key, priv->msg->peer_key);
						}
					}
					else {
						rspamd_pubkey_unref (pk);
					}
				}
			}

			priv->flags |= RSPAMD_HTTP_CONN_FLAG_ENCRYPTED;
			g_free (decoded_id);
		}
	}
}

static inline void
rspamd_http_check_special_header (struct rspamd_http_connection *conn,
		struct rspamd_http_connection_private *priv)
{
	if (rspamd_ftok_casecmp (&priv->header->name, &date_header) == 0) {
		priv->msg->date = rspamd_http_parse_date (priv->header->value.begin,
				priv->header->value.len);
	}
	else if (rspamd_ftok_casecmp (&priv->header->name, &key_header) == 0) {
		rspamd_http_parse_key (&priv->header->value, conn, priv);
	}
	else if (rspamd_ftok_casecmp (&priv->header->name, &last_modified_header) == 0) {
		priv->msg->last_modified = rspamd_http_parse_date (
				priv->header->value.begin,
				priv->header->value.len);
	}
}

static gint
rspamd_http_on_url (http_parser * parser, const gchar *at, size_t length)
{
	struct rspamd_http_connection *conn =
		(struct rspamd_http_connection *)parser->data;
	struct rspamd_http_connection_private *priv;

	priv = conn->priv;

	priv->msg->url = rspamd_fstring_append (priv->msg->url, at, length);

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
			priv->msg->status = rspamd_fstring_new ();
		}

		priv->msg->status = rspamd_fstring_append (priv->msg->status, at, length);
	}

	return 0;
}

static void
rspamd_http_finish_header (struct rspamd_http_connection *conn,
		struct rspamd_http_connection_private *priv)
{
	struct rspamd_http_header *hdr;

	priv->header->combined = rspamd_fstring_append (priv->header->combined,
			"\r\n", 2);
	priv->header->value.len = priv->header->combined->len -
			priv->header->name.len - 4;
	priv->header->value.begin = priv->header->combined->str +
			priv->header->name.len + 2;
	priv->header->name.begin = priv->header->combined->str;

	HASH_FIND (hh, priv->msg->headers, priv->header->name.begin,
			priv->header->name.len, hdr);

	if (hdr == NULL) {
		HASH_ADD_KEYPTR (hh, priv->msg->headers, priv->header->name.begin,
				priv->header->name.len, priv->header);
	}

	DL_APPEND (hdr, priv->header);

	rspamd_http_check_special_header (conn, priv);
}

static void
rspamd_http_init_header (struct rspamd_http_connection_private *priv)
{
	priv->header = g_malloc0 (sizeof (struct rspamd_http_header));
	priv->header->combined = rspamd_fstring_new ();
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
		rspamd_http_init_header (priv);
	}
	else if (priv->flags & RSPAMD_HTTP_CONN_FLAG_NEW_HEADER) {
		rspamd_http_finish_header (conn, priv);
		rspamd_http_init_header (priv);
	}

	priv->flags &= ~RSPAMD_HTTP_CONN_FLAG_NEW_HEADER;
	priv->header->combined = rspamd_fstring_append (priv->header->combined,
			at, length);

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

	if (!(priv->flags & RSPAMD_HTTP_CONN_FLAG_NEW_HEADER)) {
		priv->flags |= RSPAMD_HTTP_CONN_FLAG_NEW_HEADER;
		priv->header->combined = rspamd_fstring_append (priv->header->combined,
				": ", 2);
		priv->header->name.len = priv->header->combined->len - 2;
	}

	priv->header->combined = rspamd_fstring_append (priv->header->combined,
			at, length);

	return 0;
}

static int
rspamd_http_on_headers_complete (http_parser * parser)
{
	struct rspamd_http_connection *conn =
		(struct rspamd_http_connection *)parser->data;
	struct rspamd_http_connection_private *priv;
	struct rspamd_http_message *msg;
	int ret;

	priv = conn->priv;
	msg = priv->msg;

	if (priv->header != NULL) {
		rspamd_http_finish_header (conn, priv);

		priv->header = NULL;
		priv->flags &= ~RSPAMD_HTTP_CONN_FLAG_NEW_HEADER;
	}

	if (msg->method == HTTP_HEAD) {
		/* We don't care about the rest */
		if (rspamd_event_pending (&priv->ev, EV_READ)) {
			event_del (&priv->ev);
		}

		msg->code = parser->status_code;
		rspamd_http_connection_ref (conn);
		ret = conn->finish_handler (conn, msg);
		conn->finished = TRUE;
		rspamd_http_connection_unref (conn);

		return ret;
	}

	/*
	 * HTTP parser sets content length to (-1) when it doesn't know the real
	 * length, for example, in case of chunked encoding.
	 *
	 * Hence, we skip body setup here
	 */
	if (parser->content_length != ULLONG_MAX && parser->content_length != 0) {
		if (conn->max_size > 0 &&
				parser->content_length > conn->max_size) {
			/* Too large message */
			priv->flags |= RSPAMD_HTTP_CONN_FLAG_TOO_LARGE;
			return -1;
		}

		if (!rspamd_http_message_set_body (msg, NULL, parser->content_length)) {
			return -1;
		}
	}

	if (parser->flags & F_SPAMC) {
		msg->flags |= RSPAMD_HTTP_FLAG_SPAMC;
	}


	msg->method = parser->method;
	msg->code = parser->status_code;

	return 0;
}

static void
rspamd_http_switch_zc (struct _rspamd_http_privbuf *pbuf,
		struct rspamd_http_message *msg)
{
	pbuf->zc_buf = msg->body_buf.begin + msg->body_buf.len;
	pbuf->zc_remain = msg->body_buf.allocated_len - msg->body_buf.len;
}

static int
rspamd_http_on_body (http_parser * parser, const gchar *at, size_t length)
{
	struct rspamd_http_connection *conn =
		(struct rspamd_http_connection *)parser->data;
	struct rspamd_http_connection_private *priv;
	struct rspamd_http_message *msg;
	struct _rspamd_http_privbuf *pbuf;
	const gchar *p;

	priv = conn->priv;
	msg = priv->msg;
	pbuf = priv->buf;
	p = at;

	if (!(msg->flags & RSPAMD_HTTP_FLAG_HAS_BODY)) {
		if (!rspamd_http_message_set_body (msg, NULL, parser->content_length)) {
			return -1;
		}
	}

	if (conn->finished) {
		return 0;
	}

	if (conn->max_size > 0 &&
			msg->body_buf.len + length > conn->max_size) {
		/* Body length overflow */
		priv->flags |= RSPAMD_HTTP_CONN_FLAG_TOO_LARGE;
		return -1;
	}

	if (!pbuf->zc_buf) {
		if (!rspamd_http_message_append_body (msg, at, length)) {
			return -1;
		}

		/* We might have some leftover in our private buffer */
		if (pbuf->data->len == length) {
			/* Switch to zero-copy mode */
			rspamd_http_switch_zc (pbuf, msg);
		}
	}
	else {
		if (msg->body_buf.begin + msg->body_buf.len != at) {
			/* Likely chunked encoding */
			memmove ((gchar *)msg->body_buf.begin + msg->body_buf.len, at, length);
			p = msg->body_buf.begin + msg->body_buf.len;
		}

		/* Adjust zero-copy buf */
		msg->body_buf.len += length;

		if (!(msg->flags & RSPAMD_HTTP_FLAG_SHMEM)) {
			msg->body_buf.c.normal->len += length;
		}

		pbuf->zc_buf = msg->body_buf.begin + msg->body_buf.len;
		pbuf->zc_remain = msg->body_buf.allocated_len - msg->body_buf.len;
	}

	if ((conn->opts & RSPAMD_HTTP_BODY_PARTIAL) && !IS_CONN_ENCRYPTED (priv)) {
		/* Incremental update is impossible for encrypted requests so far */
		return (conn->body_handler (conn, msg, p, length));
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
		rspamd_http_finish_header (conn, priv);
		priv->header = NULL;
	}

	if (conn->finished) {
		return 0;
	}

	if (priv->msg->body_buf.len == 0) {

		priv->msg->body_buf.begin = at;
		priv->msg->method = parser->method;
		priv->msg->code = parser->status_code;
	}

	priv->msg->body_buf.len += length;

	return 0;
}

static int
rspamd_http_on_headers_complete_decrypted (http_parser *parser)
{
	struct rspamd_http_connection *conn =
			(struct rspamd_http_connection *) parser->data;
	struct rspamd_http_connection_private *priv;
	struct rspamd_http_message *msg;
	int ret;

	priv = conn->priv;
	msg = priv->msg;

	if (priv->header != NULL) {
		rspamd_http_finish_header (conn, priv);

		priv->header = NULL;
		priv->flags &= ~RSPAMD_HTTP_CONN_FLAG_NEW_HEADER;
	}

	if (parser->flags & F_SPAMC) {
		priv->msg->flags |= RSPAMD_HTTP_FLAG_SPAMC;
	}

	if (msg->method == HTTP_HEAD) {
		/* We don't care about the rest */
		if (rspamd_event_pending (&priv->ev, EV_READ)) {
			event_del (&priv->ev);
		}

		msg->code = parser->status_code;
		rspamd_http_connection_ref (conn);
		ret = conn->finish_handler (conn, msg);
		conn->finished = TRUE;
		rspamd_http_connection_unref (conn);

		return ret;
	}

	priv->msg->method = parser->method;
	priv->msg->code = parser->status_code;

	return 0;
}

static int
rspamd_http_decrypt_message (struct rspamd_http_connection *conn,
		struct rspamd_http_connection_private *priv,
		struct rspamd_cryptobox_pubkey *peer_key)
{
	guchar *nonce, *m;
	const guchar *nm;
	gsize dec_len;
	struct rspamd_http_message *msg = priv->msg;
	struct rspamd_http_header *hdr, *hdrtmp, *hcur, *hcurtmp;
	struct http_parser decrypted_parser;
	struct http_parser_settings decrypted_cb;
	enum rspamd_cryptobox_mode mode;

	mode = rspamd_keypair_alg (priv->local_key);
	nonce = msg->body_buf.str;
	m = msg->body_buf.str + rspamd_cryptobox_nonce_bytes (mode) +
			rspamd_cryptobox_mac_bytes (mode);
	dec_len = msg->body_buf.len - rspamd_cryptobox_nonce_bytes (mode) -
			rspamd_cryptobox_mac_bytes (mode);

	if ((nm = rspamd_pubkey_get_nm (peer_key, priv->local_key)) == NULL) {
		nm = rspamd_pubkey_calculate_nm (peer_key, priv->local_key);
	}

	if (!rspamd_cryptobox_decrypt_nm_inplace (m, dec_len, nonce,
			nm, m - rspamd_cryptobox_mac_bytes (mode), mode)) {
		msg_err ("cannot verify encrypted message, first bytes of the input: %*xs",
				(gint)MIN(msg->body_buf.len, 64), msg->body_buf.begin);
		return -1;
	}

	/* Cleanup message */
	HASH_ITER (hh, msg->headers, hdr, hdrtmp) {
		HASH_DELETE (hh, msg->headers, hdr);

		DL_FOREACH_SAFE (hdr, hcur, hcurtmp) {
			rspamd_fstring_free (hcur->combined);
			g_free (hcur);
		}
	}

	msg->headers = NULL;

	if (msg->url != NULL) {
		msg->url = rspamd_fstring_assign (msg->url, "", 0);
	}

	msg->body_buf.len = 0;

	memset (&decrypted_parser, 0, sizeof (decrypted_parser));
	http_parser_init (&decrypted_parser,
			conn->type == RSPAMD_HTTP_SERVER ? HTTP_REQUEST : HTTP_RESPONSE);

	memset (&decrypted_cb, 0, sizeof (decrypted_cb));
	decrypted_cb.on_url = rspamd_http_on_url;
	decrypted_cb.on_status = rspamd_http_on_status;
	decrypted_cb.on_header_field = rspamd_http_on_header_field;
	decrypted_cb.on_header_value = rspamd_http_on_header_value;
	decrypted_cb.on_headers_complete = rspamd_http_on_headers_complete_decrypted;
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
	enum rspamd_cryptobox_mode mode;

	if (conn->finished) {
		return 0;
	}

	priv = conn->priv;

	if ((conn->opts & RSPAMD_HTTP_REQUIRE_ENCRYPTION) && !IS_CONN_ENCRYPTED (priv)) {
		priv->flags |= RSPAMD_HTTP_CONN_FLAG_ENCRYPTION_NEEDED;
		msg_err ("unencrypted connection when encryption has been requested");
		return -1;
	}

	if ((conn->opts & RSPAMD_HTTP_BODY_PARTIAL) == 0 && IS_CONN_ENCRYPTED (priv)) {
		mode = rspamd_keypair_alg (priv->local_key);

		if (priv->local_key == NULL || priv->msg->peer_key == NULL ||
				priv->msg->body_buf.len < rspamd_cryptobox_nonce_bytes (mode) +
				rspamd_cryptobox_mac_bytes (mode)) {
			msg_err ("cannot decrypt message");
			return -1;
		}

		/* We have keys, so we can decrypt message */
		ret = rspamd_http_decrypt_message (conn, priv, priv->msg->peer_key);

		if (ret != 0) {
			return ret;
		}

		if (conn->body_handler != NULL) {
			rspamd_http_connection_ref (conn);
			ret = conn->body_handler (conn,
					priv->msg,
					priv->msg->body_buf.begin,
					priv->msg->body_buf.len);
			rspamd_http_connection_unref (conn);
		}
	}
	else if ((conn->opts & RSPAMD_HTTP_BODY_PARTIAL) == 0 && conn->body_handler) {
		g_assert (conn->body_handler != NULL);
		rspamd_http_connection_ref (conn);
		ret = conn->body_handler (conn,
				priv->msg,
				priv->msg->body_buf.begin,
				priv->msg->body_buf.len);
		rspamd_http_connection_unref (conn);
	}

	if (ret == 0) {
		if (rspamd_event_pending (&priv->ev, EV_READ)) {
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
	struct rspamd_http_connection_private *priv;
	gpointer ssl;
	gint request_method;

	priv = conn->priv;
	base = conn->priv->ev.ev_base;
	ssl = priv->ssl;
	priv->ssl = NULL;
	request_method = priv->msg->method;
	rspamd_http_connection_reset (conn);
	priv->ssl = ssl;
	/* Plan read message */

	if (conn->opts & RSPAMD_HTTP_CLIENT_SHARED) {
		rspamd_http_connection_read_message_shared (conn, conn->ud, conn->fd,
				conn->priv->ptv, base);
	}
	else {
		rspamd_http_connection_read_message (conn, conn->ud, conn->fd,
				conn->priv->ptv, base);
	}

	priv->msg->method = request_method;
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

	if (priv->ssl) {
		r = rspamd_ssl_writev (priv->ssl, msg.msg_iov, msg.msg_iovlen);
	}
	else {
		r = sendmsg (conn->fd, &msg, flags);
	}

	if (r == -1) {
		if (!priv->ssl) {
			err = g_error_new (HTTP_ERROR, errno, "IO write error: %s", strerror (errno));
			rspamd_http_connection_ref (conn);
			conn->error_handler (conn, err);
			rspamd_http_connection_unref (conn);
			g_error_free (err);
		}

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
		priv->flags &= ~RSPAMD_HTTP_CONN_FLAG_RESETED;
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

static gssize
rspamd_http_try_read (gint fd,
		struct rspamd_http_connection *conn,
		struct rspamd_http_connection_private *priv,
		struct _rspamd_http_privbuf *pbuf,
		const gchar **buf_ptr)
{
	gssize r;
	gchar *data;
	gsize len;
	struct rspamd_http_message *msg;

	msg = priv->msg;

	if (pbuf->zc_buf == NULL) {
		data = priv->buf->data->str;
		len = priv->buf->data->allocated;
	}
	else {
		data = (gchar *)pbuf->zc_buf;
		len = pbuf->zc_remain;

		if (len == 0) {
			rspamd_http_message_grow_body (priv->msg, priv->buf->data->allocated);
			rspamd_http_switch_zc (pbuf, msg);
			data = (gchar *)pbuf->zc_buf;
			len = pbuf->zc_remain;
		}
	}

	if (priv->ssl) {
		r = rspamd_ssl_read (priv->ssl, data, len);
	}
	else {
		r = read (fd, data, len);
	}

	if (r <= 0) {
		return r;
	}
	else {
		if (pbuf->zc_buf == NULL) {
			priv->buf->data->len = r;
		}
		else {
			pbuf->zc_remain -= r;
			pbuf->zc_buf += r;
		}
	}

	if (buf_ptr) {
		*buf_ptr = data;
	}

	return r;
}

static void
rspamd_http_ssl_err_handler (gpointer ud, GError *err)
{
	struct rspamd_http_connection *conn = (struct rspamd_http_connection *)ud;

	rspamd_http_connection_ref (conn);
	conn->error_handler (conn, err);
	rspamd_http_connection_unref (conn);
}

static void
rspamd_http_event_handler (int fd, short what, gpointer ud)
{
	struct rspamd_http_connection *conn = (struct rspamd_http_connection *)ud;
	struct rspamd_http_connection_private *priv;
	struct _rspamd_http_privbuf *pbuf;
	const gchar *d;
	gssize r;
	GError *err;

	priv = conn->priv;
	pbuf = priv->buf;
	REF_RETAIN (pbuf);
	rspamd_http_connection_ref (conn);

	if (what == EV_READ) {
		r = rspamd_http_try_read (fd, conn, priv, pbuf, &d);

		if (r > 0) {
			if (http_parser_execute (&priv->parser, &priv->parser_cb,
					d, r) != (size_t)r || priv->parser.http_errno != 0) {
				if (priv->flags & RSPAMD_HTTP_CONN_FLAG_TOO_LARGE) {
					err = g_error_new (HTTP_ERROR, 413,
							"Request entity too large: %zu",
							(size_t)priv->parser.content_length);
				}
				else if (priv->flags & RSPAMD_HTTP_CONN_FLAG_ENCRYPTION_NEEDED) {
					err = g_error_new (HTTP_ERROR, 400,
							"Encryption required");
				}
				else {
					err = g_error_new (HTTP_ERROR, 500 + priv->parser.http_errno,
							"HTTP parser error: %s",
							http_errno_description (priv->parser.http_errno));
				}

				if (!conn->finished) {
					conn->error_handler (conn, err);
				}
				else {
					msg_err ("got error after HTTP request is finished: %e", err);
				}

				g_error_free (err);

				REF_RELEASE (pbuf);
				rspamd_http_connection_unref (conn);

				return;
			}
		}
		else if (r == 0) {
			/* We can still call http parser */
			http_parser_execute (&priv->parser, &priv->parser_cb, d, r);

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
			if (!priv->ssl) {
				err = g_error_new (HTTP_ERROR,
						errno,
						"IO read error: %s",
						strerror (errno));
				conn->error_handler (conn, err);
				g_error_free (err);
			}

			REF_RELEASE (pbuf);
			rspamd_http_connection_unref (conn);

			return;
		}
	}
	else if (what == EV_TIMEOUT) {
		/* Let's try to read from the socket first */
		r = rspamd_http_try_read (fd, conn, priv, pbuf, &d);

		if (r > 0) {
			if (http_parser_execute (&priv->parser, &priv->parser_cb,
					d, r) != (size_t)r || priv->parser.http_errno != 0) {
				err = g_error_new (HTTP_ERROR, priv->parser.http_errno,
						"HTTP parser error: %s",
						http_errno_description (priv->parser.http_errno));

				if (!conn->finished) {
					conn->error_handler (conn, err);
				}
				else {
					msg_err ("got error after HTTP request is finished: %e", err);
				}

				g_error_free (err);

				REF_RELEASE (pbuf);
				rspamd_http_connection_unref (conn);

				return;
			}
		}
		else if (r == 0) {
			if (!conn->finished) {
				err = g_error_new (HTTP_ERROR, ETIMEDOUT,
						"IO timeout");
				conn->error_handler (conn, err);
				g_error_free (err);

			}
			REF_RELEASE (pbuf);
			rspamd_http_connection_unref (conn);

			return;
		}
		else {
			err = g_error_new (HTTP_ERROR, ETIMEDOUT,
					"IO timeout");
			conn->error_handler (conn, err);
			g_error_free (err);

			REF_RELEASE (pbuf);
			rspamd_http_connection_unref (conn);

			return;
		}
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
rspamd_http_connection_new (
		rspamd_http_body_handler_t body_handler,
		rspamd_http_error_handler_t error_handler,
		rspamd_http_finish_handler_t finish_handler,
		unsigned opts,
		enum rspamd_http_connection_type type,
		struct rspamd_keypair_cache *cache,
		gpointer ssl_ctx)
{
	struct rspamd_http_connection *conn;
	struct rspamd_http_connection_private *priv;

	if (error_handler == NULL || finish_handler == NULL) {
		return NULL;
	}

	conn = g_malloc0 (sizeof (struct rspamd_http_connection));
	conn->opts = opts;
	conn->type = type;
	conn->body_handler = body_handler;
	conn->error_handler = error_handler;
	conn->finish_handler = finish_handler;
	conn->fd = -1;
	conn->ref = 1;
	conn->finished = FALSE;
	conn->cache = cache;

	/* Init priv */
	priv = g_malloc0 (sizeof (struct rspamd_http_connection_private));
	conn->priv = priv;
	priv->ssl_ctx = ssl_ctx;

	rspamd_http_parser_reset (conn);
	priv->parser.data = conn;

	return conn;
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
		rspamd_http_message_unref (msg);
		priv->msg = NULL;
	}

	conn->finished = FALSE;
	/* Clear priv */

	if (!(priv->flags & RSPAMD_HTTP_CONN_FLAG_RESETED)) {

		if (rspamd_event_pending (&priv->ev, EV_READ|EV_WRITE|EV_TIMEOUT)) {
			event_del (&priv->ev);
		}

		rspamd_http_parser_reset (conn);
	}

	if (priv->buf != NULL) {
		REF_RELEASE (priv->buf);
		priv->buf = NULL;
	}

	if (priv->out != NULL) {
		g_free (priv->out);
		priv->out = NULL;
	}

	priv->flags |= RSPAMD_HTTP_CONN_FLAG_RESETED;
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

struct rspamd_http_message *
rspamd_http_connection_copy_msg (struct rspamd_http_message *msg, GError **err)
{
	struct rspamd_http_message *new_msg;
	struct rspamd_http_header *hdr, *nhdr, *nhdrs, *thdr, *hcur;
	const gchar *old_body;
	gsize old_len;
	struct stat st;
	union _rspamd_storage_u *storage;

	new_msg = rspamd_http_new_message (msg->type);
	new_msg->flags = msg->flags;

	if (msg->body_buf.len > 0) {

		if (msg->flags & RSPAMD_HTTP_FLAG_SHMEM) {
			/* Avoid copying by just maping a shared segment */
			new_msg->flags |= RSPAMD_HTTP_FLAG_SHMEM_IMMUTABLE;

			storage = &new_msg->body_buf.c;
			storage->shared.shm_fd = dup (msg->body_buf.c.shared.shm_fd);

			if (storage->shared.shm_fd == -1) {
				rspamd_http_message_unref (new_msg);
				g_set_error (err, http_error_quark (), errno,
						"cannot dup shmem fd: %d: %s",
						msg->body_buf.c.shared.shm_fd, strerror (errno));

				return NULL;
			}

			if (fstat (storage->shared.shm_fd, &st) == -1) {
				g_set_error (err, http_error_quark (), errno,
						"cannot stat shmem fd: %d: %s",
						storage->shared.shm_fd, strerror (errno));
				rspamd_http_message_unref (new_msg);

				return NULL;
			}

			/* We don't own segment, so do not try to touch it */

			if (msg->body_buf.c.shared.name) {
				storage->shared.name = msg->body_buf.c.shared.name;
				REF_RETAIN (storage->shared.name);
			}

			new_msg->body_buf.str = mmap (NULL, st.st_size,
					PROT_READ, MAP_SHARED,
					storage->shared.shm_fd, 0);

			if (new_msg->body_buf.str == MAP_FAILED) {
				g_set_error (err, http_error_quark (), errno,
						"cannot mmap shmem fd: %d: %s",
						storage->shared.shm_fd, strerror (errno));
				rspamd_http_message_unref (new_msg);

				return NULL;
			}

			new_msg->body_buf.begin = new_msg->body_buf.str;
			new_msg->body_buf.len = msg->body_buf.len;
			new_msg->body_buf.begin = new_msg->body_buf.str +
					(msg->body_buf.begin - msg->body_buf.str);
		}
		else {
			old_body = rspamd_http_message_get_body (msg, &old_len);

			if (!rspamd_http_message_set_body (new_msg, old_body, old_len)) {
				g_set_error (err, http_error_quark (), errno,
						"cannot set body for message, length: %zd",
						old_len);
				rspamd_http_message_unref (new_msg);

				return NULL;
			}
		}
	}

	if (msg->url) {
		if (new_msg->url) {
			new_msg->url = rspamd_fstring_append (new_msg->url, msg->url->str,
								msg->url->len);
		}
		else {
			new_msg->url = rspamd_fstring_new_init (msg->url->str,
					msg->url->len);
		}
	}

	if (msg->host) {
		new_msg->host = rspamd_fstring_new_init (msg->host->str,
				msg->host->len);
	}

	new_msg->method = msg->method;
	new_msg->port = msg->port;
	new_msg->date = msg->date;
	new_msg->last_modified = msg->last_modified;

	HASH_ITER (hh, msg->headers, hdr, thdr) {
		nhdrs = NULL;

		DL_FOREACH (hdr, hcur) {
			nhdr = g_malloc (sizeof (struct rspamd_http_header));

			nhdr->combined = rspamd_fstring_new_init (hcur->combined->str,
					hcur->combined->len);
			nhdr->name.begin = nhdr->combined->str +
					(hcur->name.begin - hcur->combined->str);
			nhdr->name.len = hcur->name.len;
			nhdr->value.begin = nhdr->combined->str +
					(hcur->value.begin - hcur->combined->str);
			nhdr->value.len = hcur->value.len;
			DL_APPEND (nhdrs, nhdr);
		}

		HASH_ADD_KEYPTR (hh, new_msg->headers, nhdrs->name.begin,
				nhdrs->name.len, nhdrs);
	}

	return new_msg;
}

void
rspamd_http_connection_free (struct rspamd_http_connection *conn)
{
	struct rspamd_http_connection_private *priv;

	priv = conn->priv;

	if (priv != NULL) {
		rspamd_http_connection_reset (conn);

		if (priv->ssl) {
			rspamd_ssl_connection_free (priv->ssl);
			priv->ssl = NULL;
		}

		if (priv->local_key) {
			rspamd_keypair_unref (priv->local_key);
		}
		if (priv->peer_key) {
			rspamd_pubkey_unref (priv->peer_key);
		}

		g_free (priv);
	}

	g_free (conn);
}

static void
rspamd_http_connection_read_message_common (struct rspamd_http_connection *conn,
		gpointer ud, gint fd, struct timeval *timeout, struct event_base *base,
		gint flags)
{
	struct rspamd_http_connection_private *priv = conn->priv;
	struct rspamd_http_message *req;

	conn->fd = fd;
	conn->ud = ud;
	req = rspamd_http_new_message (
		conn->type == RSPAMD_HTTP_SERVER ? HTTP_REQUEST : HTTP_RESPONSE);
	priv->msg = req;
	req->flags = flags;

	if (flags & RSPAMD_HTTP_FLAG_SHMEM) {
		req->body_buf.c.shared.shm_fd = -1;
	}

	if (priv->peer_key) {
		priv->msg->peer_key = priv->peer_key;
		priv->peer_key = NULL;
		priv->flags |= RSPAMD_HTTP_CONN_FLAG_ENCRYPTED;
	}

	if (timeout == NULL) {
		priv->ptv = NULL;
	}
	else if (&priv->tv != timeout) {
		memcpy (&priv->tv, timeout, sizeof (struct timeval));
		priv->ptv = &priv->tv;
	}

	priv->header = NULL;
	priv->buf = g_malloc0 (sizeof (*priv->buf));
	REF_INIT_RETAIN (priv->buf, rspamd_http_privbuf_dtor);
	priv->buf->data = rspamd_fstring_sized_new (8192);
	priv->flags |= RSPAMD_HTTP_CONN_FLAG_NEW_HEADER;

	event_set (&priv->ev,
		fd,
		EV_READ | EV_PERSIST,
		rspamd_http_event_handler,
		conn);
	if (base != NULL) {
		event_base_set (base, &priv->ev);
	}

	priv->flags &= ~RSPAMD_HTTP_CONN_FLAG_RESETED;
	event_add (&priv->ev, priv->ptv);
}

void
rspamd_http_connection_read_message (struct rspamd_http_connection *conn,
		gpointer ud, gint fd, struct timeval *timeout, struct event_base *base)
{
	rspamd_http_connection_read_message_common (conn, ud, fd, timeout, base, 0);
}

void
rspamd_http_connection_read_message_shared (struct rspamd_http_connection *conn,
		gpointer ud, gint fd, struct timeval *timeout, struct event_base *base)
{
	rspamd_http_connection_read_message_common (conn, ud, fd, timeout, base,
			RSPAMD_HTTP_FLAG_SHMEM);
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
		struct rspamd_cryptobox_pubkey *peer_key)
{
	struct rspamd_cryptobox_segment *segments;
	guchar *crlfp;
	const guchar *nm;
	gint i, cnt;
	guint outlen;
	struct rspamd_http_header *hdr, *htmp, *hcur;
	enum rspamd_cryptobox_mode mode;

	mode = rspamd_keypair_alg (priv->local_key);
	crlfp = mp + rspamd_cryptobox_mac_bytes (mode);

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


	HASH_ITER (hh, msg->headers, hdr, htmp) {
		DL_FOREACH (hdr, hcur) {
			segments[i].data = hcur->combined->str;
			segments[i++].len = hcur->combined->len;
		}
	}

	/* crlfp should point now at the second crlf */
	segments[i].data = crlfp;
	segments[i++].len = 2;

	if (pbody) {
		segments[i].data = pbody;
		segments[i++].len = bodylen;
	}

	cnt = i;

	if ((nm = rspamd_pubkey_get_nm (peer_key, priv->local_key)) == NULL) {
		nm = rspamd_pubkey_calculate_nm (peer_key, priv->local_key);
	}

	rspamd_cryptobox_encryptv_nm_inplace (segments, cnt, np, nm, mp, mode);

	/*
	 * iov[0] = base HTTP request
	 * iov[1] = CRLF
	 * iov[2] = nonce
	 * iov[3] = mac
	 * iov[4..i] = encrypted HTTP request/reply
	 */
	priv->out[2].iov_base = np;
	priv->out[2].iov_len = rspamd_cryptobox_nonce_bytes (mode);
	priv->out[3].iov_base = mp;
	priv->out[3].iov_len = rspamd_cryptobox_mac_bytes (mode);

	outlen += rspamd_cryptobox_nonce_bytes (mode) +
			rspamd_cryptobox_mac_bytes (mode);

	for (i = 0; i < cnt; i ++) {
		priv->out[i + 4].iov_base = segments[i].data;
		priv->out[i + 4].iov_len = segments[i].len;
		outlen += segments[i].len;
	}

	priv->wr_total = outlen;

	g_free (segments);
}

static void
rspamd_http_detach_shared (struct rspamd_http_message *msg)
{
	rspamd_fstring_t *cpy_str;

	cpy_str = rspamd_fstring_new_init (msg->body_buf.begin, msg->body_buf.len);
	rspamd_http_message_set_body_from_fstring_steal (msg, cpy_str);
}

gint
rspamd_http_message_write_header (const gchar* mime_type, gboolean encrypted,
		gchar *repbuf, gsize replen, gsize bodylen, gsize enclen, const gchar* host,
		struct rspamd_http_connection* conn, struct rspamd_http_message* msg,
		rspamd_fstring_t** buf,
		struct rspamd_http_connection_private* priv,
		struct rspamd_cryptobox_pubkey* peer_key)
{
	gchar datebuf[64];
	gint meth_len = 0;
	struct tm t;

	if (conn->type == RSPAMD_HTTP_SERVER) {
		/* Format reply */
		if (msg->method < HTTP_SYMBOLS) {
			rspamd_ftok_t status;

			rspamd_gmtime (msg->date, &t);
			rspamd_snprintf (datebuf, sizeof(datebuf),
					"%s, %02d %s %4d %02d:%02d:%02d GMT", http_week[t.tm_wday],
					t.tm_mday, http_month[t.tm_mon], t.tm_year + 1900,
					t.tm_hour, t.tm_min, t.tm_sec);
			if (mime_type == NULL) {
				mime_type =
						encrypted ? "application/octet-stream" : "text/plain";
			}

			if (msg->status == NULL || msg->status->len == 0) {
				if (msg->code == 200) {
					RSPAMD_FTOK_ASSIGN (&status, "OK");
				}
				else if (msg->code == 404) {
					RSPAMD_FTOK_ASSIGN (&status, "Not Found");
				}
				else if (msg->code == 403) {
					RSPAMD_FTOK_ASSIGN (&status, "Forbidden");
				}
				else if (msg->code >= 500 && msg->code < 600) {
					RSPAMD_FTOK_ASSIGN (&status, "Internal Server Error");
				}
				else {
					RSPAMD_FTOK_ASSIGN (&status, "Undefined Error");
				}
			}
			else {
				status.begin = msg->status->str;
				status.len = msg->status->len;
			}

			if (encrypted) {
				/* Internal reply (encrypted) */
				if (mime_type) {
					meth_len =
							rspamd_snprintf (repbuf, replen,
									"HTTP/1.1 %d %T\r\n"
											"Connection: close\r\n"
											"Server: %s\r\n"
											"Date: %s\r\n"
											"Content-Length: %z\r\n"
											"Content-Type: %s", /* NO \r\n at the end ! */
									msg->code, &status, "rspamd/" RVERSION,
									datebuf,
									bodylen, mime_type);
				}
				else {
					meth_len =
							rspamd_snprintf (repbuf, replen,
									"HTTP/1.1 %d %T\r\n"
											"Connection: close\r\n"
											"Server: %s\r\n"
											"Date: %s\r\n"
											"Content-Length: %z", /* NO \r\n at the end ! */
									msg->code, &status, "rspamd/" RVERSION,
									datebuf,
									bodylen);
				}
				enclen += meth_len;
				/* External reply */
				rspamd_printf_fstring (buf,
						"HTTP/1.1 200 OK\r\n"
						"Connection: close\r\n"
						"Server: rspamd\r\n"
						"Date: %s\r\n"
						"Content-Length: %z\r\n"
						"Content-Type: application/octet-stream\r\n",
						datebuf, enclen);
			}
			else {
				if (mime_type) {
					meth_len =
							rspamd_printf_fstring (buf,
									"HTTP/1.1 %d %T\r\n"
											"Connection: close\r\n"
											"Server: %s\r\n"
											"Date: %s\r\n"
											"Content-Length: %z\r\n"
											"Content-Type: %s\r\n",
									msg->code, &status, "rspamd/" RVERSION,
									datebuf,
									bodylen, mime_type);
				}
				else {
					meth_len =
							rspamd_printf_fstring (buf,
									"HTTP/1.1 %d %T\r\n"
											"Connection: close\r\n"
											"Server: %s\r\n"
											"Date: %s\r\n"
											"Content-Length: %z\r\n",
									msg->code, &status, "rspamd/" RVERSION,
									datebuf,
									bodylen);
				}
			}
		}
		else {
			/* Legacy spamd reply */
			if (msg->flags & RSPAMD_HTTP_FLAG_SPAMC) {
				gsize real_bodylen;
				goffset eoh_pos;
				GString tmp;

				/* Unfortunately, spamc protocol is deadly brain damaged */
				tmp.str = (gchar *)msg->body_buf.begin;
				tmp.len = msg->body_buf.len;

				if (rspamd_string_find_eoh (&tmp, &eoh_pos) != -1 &&
						bodylen > eoh_pos) {
					real_bodylen = bodylen - eoh_pos;
				}
				else {
					real_bodylen = bodylen;
				}

				rspamd_printf_fstring (buf, "SPAMD/1.1 0 EX_OK\r\n"
						"Content-length: %z\r\n",
						real_bodylen);
			}
			else {
				rspamd_printf_fstring (buf, "RSPAMD/1.3 0 EX_OK\r\n");
			}
		}
	}
	else {
		/* Format request */
		enclen += msg->url->len + strlen (http_method_str (msg->method)) + 1;

		if (host == NULL && msg->host == NULL) {
			/* Fallback to HTTP/1.0 */
			if (encrypted) {
				rspamd_printf_fstring (buf,
						"%s %s HTTP/1.0\r\n"
						"Content-Length: %z\r\n"
						"Content-Type: application/octet-stream\r\n",
						"POST",
						"/post", enclen);
			}
			else {
				rspamd_printf_fstring (buf,
						"%s %V HTTP/1.0\r\n"
						"Content-Length: %z\r\n",
						http_method_str (msg->method), msg->url, bodylen);
				if (bodylen > 0) {
					if (mime_type == NULL) {
						mime_type = "text/plain";
					}

					rspamd_printf_fstring (buf,
							"Content-Type: %s\r\n",
							mime_type);
				}
			}
		}
		else {
			if (encrypted) {
				if (host != NULL) {
					rspamd_printf_fstring (buf,
							"%s %s HTTP/1.1\r\n"
							"Connection: close\r\n"
							"Host: %s\r\n"
							"Content-Length: %z\r\n"
							"Content-Type: application/octet-stream\r\n",
							"POST", "/post", host, enclen);
				}
				else {
					rspamd_printf_fstring (buf,
							"%s %s HTTP/1.1\r\n"
							"Connection: close\r\n"
							"Host: %V\r\n"
							"Content-Length: %z\r\n"
							"Content-Type: application/octet-stream\r\n",
							"POST", "/post", msg->host, enclen);
				}
			}
			else {
				if (host != NULL) {
					rspamd_printf_fstring (buf,
							"%s %V HTTP/1.1\r\nConnection: close\r\n"
							"Host: %s\r\n"
							"Content-Length: %z\r\n",
							http_method_str (msg->method), msg->url, host,
							bodylen);
				}
				else {
					rspamd_printf_fstring (buf,
							"%s %V HTTP/1.1\r\n"
							"Connection: close\r\n"
							"Host: %V\r\n"
							"Content-Length: %z\r\n",
							http_method_str (msg->method), msg->url, msg->host,
							bodylen);
				}

				if (bodylen > 0) {
					if (mime_type != NULL) {
						rspamd_printf_fstring (buf,
								"Content-Type: %s\r\n",
								mime_type);
					}
				}
			}
		}

		if (encrypted) {
			GString *b32_key, *b32_id;

			b32_key = rspamd_keypair_print (priv->local_key,
					RSPAMD_KEYPAIR_PUBKEY | RSPAMD_KEYPAIR_BASE32);
			b32_id = rspamd_pubkey_print (peer_key,
					RSPAMD_KEYPAIR_ID_SHORT | RSPAMD_KEYPAIR_BASE32);
			/* XXX: add some fuzz here */
			rspamd_printf_fstring (&*buf, "Key: %v=%v\r\n", b32_id, b32_key);
			g_string_free (b32_key, TRUE);
			g_string_free (b32_id, TRUE);
		}
	}

	return meth_len;
}

static void
rspamd_http_connection_write_message_common (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg, const gchar *host, const gchar *mime_type,
		gpointer ud, gint fd, struct timeval *timeout, struct event_base *base,
		gboolean allow_shared)
{
	struct rspamd_http_connection_private *priv = conn->priv;
	struct rspamd_http_header *hdr, *htmp, *hcur;
	gchar repbuf[512], *pbody;
	gint i, hdrcount, meth_len = 0, preludelen = 0;
	gsize bodylen, enclen = 0;
	rspamd_fstring_t *buf;
	gboolean encrypted = FALSE;
	guchar nonce[rspamd_cryptobox_MAX_NONCEBYTES], mac[rspamd_cryptobox_MAX_MACBYTES];
	guchar *np = NULL, *mp = NULL, *meth_pos = NULL;
	struct rspamd_cryptobox_pubkey *peer_key = NULL;
	enum rspamd_cryptobox_mode mode;
	GError *err;

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
	priv->buf = g_malloc0 (sizeof (*priv->buf));
	REF_INIT_RETAIN (priv->buf, rspamd_http_privbuf_dtor);
	priv->buf->data = rspamd_fstring_sized_new (512);
	buf = priv->buf->data;

	if (priv->peer_key && priv->local_key) {
		priv->msg->peer_key = priv->peer_key;
		priv->peer_key = NULL;
		priv->flags |= RSPAMD_HTTP_CONN_FLAG_ENCRYPTED;
	}

	if (msg->peer_key != NULL) {
		if (priv->local_key == NULL) {
			/* Automatically generate a temporary keypair */
			priv->local_key = rspamd_keypair_new (RSPAMD_KEYPAIR_KEX,
					RSPAMD_CRYPTOBOX_MODE_25519);
		}

		encrypted = TRUE;

		if (conn->cache) {
			rspamd_keypair_cache_process (conn->cache,
					priv->local_key, priv->msg->peer_key);
		}
	}

	if (encrypted && (msg->flags &
			(RSPAMD_HTTP_FLAG_SHMEM_IMMUTABLE|RSPAMD_HTTP_FLAG_SHMEM))) {
		/* We cannot use immutable body to encrypt message in place */
		allow_shared = FALSE;
		rspamd_http_detach_shared (msg);
	}

	if (allow_shared) {
		gchar tmpbuf[64];

		if (!(msg->flags & RSPAMD_HTTP_FLAG_SHMEM) ||
				msg->body_buf.c.shared.name == NULL) {
			allow_shared = FALSE;
		}
		else {
			/* Insert new headers */
			rspamd_http_message_add_header (msg, "Shm",
					msg->body_buf.c.shared.name->shm_name);
			rspamd_snprintf (tmpbuf, sizeof (tmpbuf), "%d",
					(int)(msg->body_buf.begin - msg->body_buf.str));
			rspamd_http_message_add_header (msg, "Shm-Offset",
					tmpbuf);
			rspamd_snprintf (tmpbuf, sizeof (tmpbuf), "%z",
					msg->body_buf.len);
			rspamd_http_message_add_header (msg, "Shm-Length",
					tmpbuf);
		}
	}

	if (encrypted) {
		mode = rspamd_keypair_alg (priv->local_key);

		if (msg->body_buf.len == 0) {
			pbody = NULL;
			bodylen = 0;
			msg->method = HTTP_GET;
		}
		else {
			pbody = (gchar *)msg->body_buf.begin;
			bodylen = msg->body_buf.len;
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
			enclen = rspamd_cryptobox_nonce_bytes (mode) +
					rspamd_cryptobox_mac_bytes (mode) +
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
				if (mime_type != NULL) {
					preludelen = rspamd_snprintf (repbuf, sizeof (repbuf), "%s\r\n"
									"Content-Length: %z\r\n"
									"Content-Type: %s\r\n"
									"\r\n", ENCRYPTED_VERSION, bodylen,
							mime_type);
				}
				else {
					preludelen = rspamd_snprintf (repbuf, sizeof (repbuf), "%s\r\n"
							"Content-Length: %z\r\n"
							""
							"\r\n", ENCRYPTED_VERSION, bodylen);
				}

				preludelen = rspamd_snprintf (repbuf, sizeof (repbuf), "%s\r\n"
						"Content-Length: %z\r\n"
						"Content-Type: %s\r\n"
						"\r\n", ENCRYPTED_VERSION, bodylen,
						mime_type);
			}
			else {
				preludelen = rspamd_snprintf (repbuf, sizeof (repbuf),
						"%s\r\n\r\n",
						ENCRYPTED_VERSION);
			}

			enclen = rspamd_cryptobox_nonce_bytes (mode) +
					rspamd_cryptobox_mac_bytes (mode) +
					preludelen + /* version [content-length] + 2 * CRLF */
					bodylen;
		}

		if (bodylen > 0) {
			priv->outlen ++;
		}
	}
	else {
		if (msg->method < HTTP_SYMBOLS) {
			if (msg->body_buf.len == 0 || allow_shared) {
				pbody = NULL;
				bodylen = 0;
				priv->outlen = 2;

				if (msg->method == HTTP_INVALID) {
					msg->method = HTTP_GET;
				}
			}
			else {
				pbody = (gchar *)msg->body_buf.begin;
				bodylen = msg->body_buf.len;
				priv->outlen = 3;

				if (msg->method == HTTP_INVALID) {
					msg->method = HTTP_POST;
				}
			}
		}
		else if (msg->body_buf.len > 0) {
			allow_shared = FALSE;
			pbody = (gchar *)msg->body_buf.begin;
			bodylen = msg->body_buf.len;
			priv->outlen = 2;
		}
		else {
			/* Invalid body for spamc method */
			abort ();
		}
	}

	peer_key = msg->peer_key;

	priv->wr_total = bodylen + 2;

	hdrcount = 0;

	if (msg->method < HTTP_SYMBOLS) {
		HASH_ITER (hh, msg->headers, hdr, htmp) {
			DL_FOREACH (hdr, hcur) {
				/* <name: value\r\n> */
				priv->wr_total += hcur->combined->len;
				enclen += hcur->combined->len;
				priv->outlen ++;
				hdrcount ++;
			}
		}
	}

	/* Allocate iov */
	priv->out = g_malloc0 (sizeof (struct iovec) * priv->outlen);
	priv->wr_pos = 0;

	meth_len = rspamd_http_message_write_header (mime_type, encrypted,
			repbuf, sizeof (repbuf), bodylen, enclen,
			host, conn, msg,
			&buf, priv, peer_key);
	priv->wr_total += buf->len;

	/* Setup external request body */
	priv->out[0].iov_base = buf->str;
	priv->out[0].iov_len = buf->len;

	/* Buf will be used eventually for encryption */
	if (encrypted) {
		gint meth_offset, nonce_offset, mac_offset;
		mode = rspamd_keypair_alg (priv->local_key);

		ottery_rand_bytes (nonce, rspamd_cryptobox_nonce_bytes (mode));
		memset (mac, 0, rspamd_cryptobox_mac_bytes (mode));
		meth_offset = buf->len;

		if (conn->type == RSPAMD_HTTP_SERVER) {
			buf = rspamd_fstring_append (buf, repbuf, meth_len);
		}
		else {
			meth_len = strlen (http_method_str (msg->method)) + 1; /* + space */
			buf = rspamd_fstring_append (buf, http_method_str (msg->method),
					meth_len - 1);
			buf = rspamd_fstring_append (buf, " ", 1);
		}

		nonce_offset = buf->len;
		buf = rspamd_fstring_append (buf, nonce,
				rspamd_cryptobox_nonce_bytes (mode));
		mac_offset = buf->len;
		buf = rspamd_fstring_append (buf, mac,
				rspamd_cryptobox_mac_bytes (mode));

		/* Need to be encrypted */
		if (conn->type == RSPAMD_HTTP_SERVER) {
			buf = rspamd_fstring_append (buf, "\r\n\r\n", 4);
		}
		else {
			buf = rspamd_fstring_append (buf, repbuf, preludelen);
		}

		meth_pos = buf->str + meth_offset;
		np = buf->str + nonce_offset;
		mp = buf->str + mac_offset;
	}

	/* During previous writes, buf might be reallocated and changed */
	priv->buf->data = buf;

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
		if (msg->method < HTTP_SYMBOLS) {
			HASH_ITER (hh, msg->headers, hdr, htmp) {
				DL_FOREACH (hdr, hcur) {
					priv->out[i].iov_base = hcur->combined->str;
					priv->out[i++].iov_len = hcur->combined->len;
				}
			}

			priv->out[i].iov_base = "\r\n";
			priv->out[i++].iov_len = 2;
		}
		else {
			/* No CRLF for compatibility reply */
			priv->wr_total -= 2;
		}

		if (pbody != NULL) {
			priv->out[i].iov_base = pbody;
			priv->out[i++].iov_len = bodylen;
		}
	}

	priv->flags &= ~RSPAMD_HTTP_CONN_FLAG_RESETED;

	if (rspamd_event_pending (&priv->ev, EV_TIMEOUT|EV_WRITE|EV_READ)) {
		event_del (&priv->ev);
	}

	if (msg->flags & RSPAMD_HTTP_FLAG_SSL) {
		if (base != NULL) {
			event_base_set (base, &priv->ev);
		}
		if (!priv->ssl_ctx) {
			err = g_error_new (HTTP_ERROR, errno, "ssl message requested "
					"with no ssl ctx");
			rspamd_http_connection_ref (conn);
			conn->error_handler (conn, err);
			rspamd_http_connection_unref (conn);
			g_error_free (err);
			return;
		}
		else {
			if (priv->ssl) {
				/* Cleanup the existing connection */
				rspamd_ssl_connection_free (priv->ssl);
			}

			priv->ssl = rspamd_ssl_connection_new (priv->ssl_ctx, base,
					!(msg->flags & RSPAMD_HTTP_FLAG_SSL_NOVERIFY));
			g_assert (priv->ssl != NULL);

			if (!rspamd_ssl_connect_fd (priv->ssl, fd, host, &priv->ev,
					priv->ptv, rspamd_http_event_handler,
					rspamd_http_ssl_err_handler, conn)) {

				err = g_error_new (HTTP_ERROR, errno,
						"ssl connection error: ssl error=%s, errno=%s",
						ERR_error_string (ERR_get_error (), NULL),
						strerror (errno));
				rspamd_http_connection_ref (conn);
				conn->error_handler (conn, err);
				rspamd_http_connection_unref (conn);
				g_error_free (err);
				return;
			}
		}
	}
	else {
		event_set (&priv->ev, fd, EV_WRITE, rspamd_http_event_handler, conn);

		if (base != NULL) {
			event_base_set (base, &priv->ev);
		}

		event_add (&priv->ev, priv->ptv);
	}
}

void
rspamd_http_connection_write_message (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg, const gchar *host, const gchar *mime_type,
		gpointer ud, gint fd, struct timeval *timeout, struct event_base *base)
{
	rspamd_http_connection_write_message_common (conn, msg, host, mime_type,
			ud, fd, timeout, base, FALSE);
}

void
rspamd_http_connection_write_message_shared (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg, const gchar *host, const gchar *mime_type,
		gpointer ud, gint fd, struct timeval *timeout, struct event_base *base)
{
	rspamd_http_connection_write_message_common (conn, msg, host, mime_type,
			ud, fd, timeout, base, TRUE);
}

struct rspamd_http_message *
rspamd_http_new_message (enum http_parser_type type)
{
	struct rspamd_http_message *new;

	new = g_malloc0 (sizeof (struct rspamd_http_message));

	if (type == HTTP_REQUEST) {
		new->url = rspamd_fstring_new ();
	}
	else {
		new->url = NULL;
		new->code = 200;
	}

	new->port = 80;
	new->type = type;
	new->method = HTTP_INVALID;

	REF_INIT_RETAIN (new, rspamd_http_message_free);

	return new;
}

struct rspamd_http_message*
rspamd_http_message_from_url (const gchar *url)
{
	struct http_parser_url pu;
	struct rspamd_http_message *msg;
	const gchar *host, *path;
	size_t pathlen, urllen;
	guint flags = 0;

	if (url == NULL) {
		return NULL;
	}

	urllen = strlen (url);
	memset (&pu, 0, sizeof (pu));

	if (http_parser_parse_url (url, urllen, FALSE, &pu) != 0) {
		msg_warn ("cannot parse URL: %s", url);
		return NULL;
	}

	if ((pu.field_set & (1 << UF_HOST)) == 0) {
		msg_warn ("no host argument in URL: %s", url);
		return NULL;
	}

	if ((pu.field_set & (1 << UF_SCHEMA))) {
		if (pu.field_data[UF_SCHEMA].len == sizeof ("https") - 1 &&
				memcmp (url + pu.field_data[UF_SCHEMA].off, "https", 5) == 0) {
			flags |= RSPAMD_HTTP_FLAG_SSL;
		}
	}

	if ((pu.field_set & (1 << UF_PATH)) == 0) {
		path = "/";
		pathlen = 1;
	}
	else {
		path = url + pu.field_data[UF_PATH].off;
		pathlen = urllen - pu.field_data[UF_PATH].off;
	}

	msg = rspamd_http_new_message (HTTP_REQUEST);
	host = url + pu.field_data[UF_HOST].off;
	msg->flags = flags;

	if ((pu.field_set & (1 << UF_PORT)) != 0) {
		msg->port = pu.port;
	}
	else {
		/* XXX: magic constant */
		if (flags & RSPAMD_HTTP_FLAG_SSL) {
			msg->port = 443;
		}
		else {
			msg->port = 80;
		}
	}

	msg->host = rspamd_fstring_new_init (host, pu.field_data[UF_HOST].len);
	msg->url = rspamd_fstring_append (msg->url, path, pathlen);

	REF_INIT_RETAIN (msg, rspamd_http_message_free);

	return msg;
}

const gchar *
rspamd_http_message_get_body (struct rspamd_http_message *msg,
		gsize *blen)
{
	const gchar *ret = NULL;

	if (msg->body_buf.len > 0) {
		ret = msg->body_buf.begin;
	}

	if (blen) {
		*blen = msg->body_buf.len;
	}

	return ret;
}

static void
rspamd_http_shname_dtor (void *p)
{
	struct rspamd_storage_shmem *n = p;

#ifdef HAVE_SANE_SHMEM
	shm_unlink (n->shm_name);
#else
	unlink (n->shm_name);
#endif
	g_free (n->shm_name);
	g_free (n);
}

struct rspamd_storage_shmem *
rspamd_http_message_shmem_ref (struct rspamd_http_message *msg)
{
	if ((msg->flags & RSPAMD_HTTP_FLAG_SHMEM) && msg->body_buf.c.shared.name) {
		REF_RETAIN (msg->body_buf.c.shared.name);
		return msg->body_buf.c.shared.name;
	}

	return NULL;
}

guint
rspamd_http_message_get_flags (struct rspamd_http_message *msg)
{
	return msg->flags;
}

void
rspamd_http_message_shmem_unref (struct rspamd_storage_shmem *p)
{
	REF_RELEASE (p);
}

gboolean
rspamd_http_message_set_body (struct rspamd_http_message *msg,
		const gchar *data, gsize len)
{
	union _rspamd_storage_u *storage;
	storage = &msg->body_buf.c;

	rspamd_http_message_storage_cleanup (msg);

	if (msg->flags & RSPAMD_HTTP_FLAG_SHMEM) {
		storage->shared.name = g_malloc (sizeof (*storage->shared.name));
		REF_INIT_RETAIN (storage->shared.name, rspamd_http_shname_dtor);
#ifdef HAVE_SANE_SHMEM
#if defined(__DragonFly__)
		// DragonFly uses regular files for shm. User rspamd is not allowed to create
		// files in the root.
		storage->shared.name->shm_name = g_strdup ("/tmp/rhm.XXXXXXXXXXXXXXXXXXXX");
#else
		storage->shared.name->shm_name = g_strdup ("/rhm.XXXXXXXXXXXXXXXXXXXX");
#endif
		storage->shared.shm_fd = rspamd_shmem_mkstemp (storage->shared.name->shm_name);
#else
		/* XXX: assume that tempdir is /tmp */
		storage->shared.name->shm_name = g_strdup ("/tmp/rhm.XXXXXXXXXXXXXXXXXXXX");
		storage->shared.shm_fd = mkstemp (storage->shared.name->shm_name);
#endif

		if (storage->shared.shm_fd == -1) {
			return FALSE;
		}

		if (len != 0 && len != ULLONG_MAX) {
			if (ftruncate (storage->shared.shm_fd, len) == -1) {
				return FALSE;
			}

			msg->body_buf.str = mmap (NULL, len,
					PROT_WRITE|PROT_READ, MAP_SHARED,
					storage->shared.shm_fd, 0);

			if (msg->body_buf.str == MAP_FAILED) {
				return FALSE;
			}

			msg->body_buf.begin = msg->body_buf.str;
			msg->body_buf.allocated_len = len;

			if (data != NULL) {
				memcpy (msg->body_buf.str, data, len);
				msg->body_buf.len = len;
			}
		}
		else {
			msg->body_buf.len = 0;
			msg->body_buf.begin = NULL;
			msg->body_buf.str = NULL;
			msg->body_buf.allocated_len = 0;
		}
	}
	else {
		if (len != 0 && len != ULLONG_MAX) {
			if (data == NULL) {
				storage->normal = rspamd_fstring_sized_new (len);
				msg->body_buf.len = 0;
			}
			else {
				storage->normal = rspamd_fstring_new_init (data, len);
				msg->body_buf.len = len;
			}
		}
		else {
			storage->normal = rspamd_fstring_new ();
		}

		msg->body_buf.begin = storage->normal->str;
		msg->body_buf.str = storage->normal->str;
		msg->body_buf.allocated_len = storage->normal->allocated;
	}

	msg->flags |= RSPAMD_HTTP_FLAG_HAS_BODY;

	return TRUE;
}

void
rspamd_http_message_set_method (struct rspamd_http_message *msg,
		const gchar *method)
{
	gint i;

	/* Linear search: not very efficient method */
	for (i = 0; i < HTTP_METHOD_MAX; i ++) {
		if (g_ascii_strcasecmp (method, http_method_str (i)) == 0) {
			msg->method = i;
		}
	}
}

gboolean
rspamd_http_message_set_body_from_fd (struct rspamd_http_message *msg,
		gint fd)
{
	union _rspamd_storage_u *storage;
	struct stat st;

	rspamd_http_message_storage_cleanup (msg);

	storage = &msg->body_buf.c;
	msg->flags |= RSPAMD_HTTP_FLAG_SHMEM|RSPAMD_HTTP_FLAG_SHMEM_IMMUTABLE;

	storage->shared.shm_fd = dup (fd);
	msg->body_buf.str = MAP_FAILED;

	if (storage->shared.shm_fd == -1) {
		return FALSE;
	}

	if (fstat (storage->shared.shm_fd, &st) == -1) {
		return FALSE;
	}

	msg->body_buf.str = mmap (NULL, st.st_size,
			PROT_READ, MAP_SHARED,
			storage->shared.shm_fd, 0);

	if (msg->body_buf.str == MAP_FAILED) {
		return FALSE;
	}

	msg->body_buf.begin = msg->body_buf.str;
	msg->body_buf.len = st.st_size;
	msg->body_buf.allocated_len = st.st_size;

	return TRUE;
}

gboolean
rspamd_http_message_set_body_from_fstring_steal (struct rspamd_http_message *msg,
		rspamd_fstring_t *fstr)
{
	union _rspamd_storage_u *storage;

	rspamd_http_message_storage_cleanup (msg);

	storage = &msg->body_buf.c;
	msg->flags &= ~(RSPAMD_HTTP_FLAG_SHMEM|RSPAMD_HTTP_FLAG_SHMEM_IMMUTABLE);

	storage->normal = fstr;
	msg->body_buf.str = fstr->str;
	msg->body_buf.begin = msg->body_buf.str;
	msg->body_buf.len = fstr->len;
	msg->body_buf.allocated_len = fstr->allocated;

	return TRUE;
}

gboolean
rspamd_http_message_set_body_from_fstring_copy (struct rspamd_http_message *msg,
		const rspamd_fstring_t *fstr)
{
	union _rspamd_storage_u *storage;

	rspamd_http_message_storage_cleanup (msg);

	storage = &msg->body_buf.c;
	msg->flags &= ~(RSPAMD_HTTP_FLAG_SHMEM|RSPAMD_HTTP_FLAG_SHMEM_IMMUTABLE);

	storage->normal = rspamd_fstring_new_init (fstr->str, fstr->len);
	msg->body_buf.str = storage->normal->str;
	msg->body_buf.begin = msg->body_buf.str;
	msg->body_buf.len = storage->normal->len;
	msg->body_buf.allocated_len = storage->normal->allocated;

	return TRUE;
}


static gboolean
rspamd_http_message_grow_body (struct rspamd_http_message *msg, gsize len)
{
	struct stat st;
	union _rspamd_storage_u *storage;
	gsize newlen;

	storage = &msg->body_buf.c;

	if (msg->flags & RSPAMD_HTTP_FLAG_SHMEM) {
		if (storage->shared.shm_fd == -1) {
			return FALSE;
		}

		if (fstat (storage->shared.shm_fd, &st) == -1) {
			return FALSE;
		}

		/* Check if we need to grow */
		if ((gsize)st.st_size < msg->body_buf.len + len) {
			/* Need to grow */
			newlen = rspamd_fstring_suggest_size (msg->body_buf.len, st.st_size,
					len);
			/* Unmap as we need another size of segment */
			if (msg->body_buf.str != MAP_FAILED) {
				munmap (msg->body_buf.str, st.st_size);
			}

			if (ftruncate (storage->shared.shm_fd, newlen) == -1) {
				return FALSE;
			}

			msg->body_buf.str = mmap (NULL, newlen,
					PROT_WRITE|PROT_READ, MAP_SHARED,
					storage->shared.shm_fd, 0);
			if (msg->body_buf.str == MAP_FAILED) {
				return FALSE;
			}

			msg->body_buf.begin = msg->body_buf.str;
			msg->body_buf.allocated_len = newlen;
		}
	}
	else {
		storage->normal = rspamd_fstring_grow (storage->normal, len);

		/* Append might cause realloc */
		msg->body_buf.begin = storage->normal->str;
		msg->body_buf.len = storage->normal->len;
		msg->body_buf.str = storage->normal->str;
		msg->body_buf.allocated_len = storage->normal->allocated;
	}

	return TRUE;
}

gboolean
rspamd_http_message_append_body (struct rspamd_http_message *msg,
		const gchar *data, gsize len)
{
	union _rspamd_storage_u *storage;

	storage = &msg->body_buf.c;

	if (msg->flags & RSPAMD_HTTP_FLAG_SHMEM) {
		if (!rspamd_http_message_grow_body (msg, len)) {
			return FALSE;
		}

		memcpy (msg->body_buf.str + msg->body_buf.len, data, len);
		msg->body_buf.len += len;
	}
	else {
		storage->normal = rspamd_fstring_append (storage->normal, data, len);

		/* Append might cause realloc */
		msg->body_buf.begin = storage->normal->str;
		msg->body_buf.len = storage->normal->len;
		msg->body_buf.str = storage->normal->str;
		msg->body_buf.allocated_len = storage->normal->allocated;
	}

	return TRUE;
}

static void
rspamd_http_message_storage_cleanup (struct rspamd_http_message *msg)
{
	union _rspamd_storage_u *storage;
	struct stat st;

	if (msg->flags & RSPAMD_HTTP_FLAG_SHMEM) {
		storage = &msg->body_buf.c;

		if (storage->shared.shm_fd > 0) {
			g_assert (fstat (storage->shared.shm_fd, &st) != -1);

			if (msg->body_buf.str != MAP_FAILED) {
				munmap (msg->body_buf.str, st.st_size);
			}

			close (storage->shared.shm_fd);
		}

		if (storage->shared.name != NULL) {
			REF_RELEASE (storage->shared.name);
		}

		storage->shared.shm_fd = -1;
		msg->body_buf.str = MAP_FAILED;
	}
	else {
		if (msg->body_buf.c.normal) {
			rspamd_fstring_free (msg->body_buf.c.normal);
		}

		msg->body_buf.c.normal = NULL;
	}

	msg->body_buf.len = 0;
}

void
rspamd_http_connection_set_max_size (struct rspamd_http_connection *conn,
		gsize sz)
{
	conn->max_size = sz;
}

void
rspamd_http_message_free (struct rspamd_http_message *msg)
{
	struct rspamd_http_header *hdr, *htmp, *hcur, *hcurtmp;


	HASH_ITER (hh, msg->headers, hdr, htmp) {
		HASH_DEL (msg->headers, hdr);

		DL_FOREACH_SAFE (hdr, hcur, hcurtmp) {
			rspamd_fstring_free (hcur->combined);
			g_free (hcur);
		}
	}


	rspamd_http_message_storage_cleanup (msg);

	if (msg->url != NULL) {
		rspamd_fstring_free (msg->url);
	}
	if (msg->status != NULL) {
		rspamd_fstring_free (msg->status);
	}
	if (msg->host != NULL) {
		rspamd_fstring_free (msg->host);
	}
	if (msg->peer_key != NULL) {
		rspamd_pubkey_unref (msg->peer_key);
	}

	g_free (msg);
}

void
rspamd_http_message_set_peer_key (struct rspamd_http_message *msg,
		struct rspamd_cryptobox_pubkey *pk)
{
	if (msg->peer_key != NULL) {
		rspamd_pubkey_unref (msg->peer_key);
	}

	if (pk) {
		msg->peer_key = rspamd_pubkey_ref (pk);
	}
	else {
		msg->peer_key = NULL;
	}
}

void
rspamd_http_message_add_header_len (struct rspamd_http_message *msg,
	const gchar *name,
	const gchar *value,
	gsize len)
{
	struct rspamd_http_header *hdr, *found = NULL;
	guint nlen, vlen;

	if (msg != NULL && name != NULL && value != NULL) {
		hdr = g_malloc0 (sizeof (struct rspamd_http_header));
		nlen = strlen (name);
		vlen = len;
		hdr->combined = rspamd_fstring_sized_new (nlen + vlen + 4);
		rspamd_printf_fstring (&hdr->combined, "%s: %*s\r\n", name, (gint)vlen,
				value);
		hdr->name.begin = hdr->combined->str;
		hdr->name.len = nlen;
		hdr->value.begin = hdr->combined->str + nlen + 2;
		hdr->value.len = vlen;

		HASH_FIND (hh, msg->headers, hdr->name.begin,
				hdr->name.len, found);

		if (found == NULL) {
			HASH_ADD_KEYPTR (hh, msg->headers, hdr->name.begin,
					hdr->name.len, hdr);
		}

		DL_APPEND (found, hdr);
	}
}

void
rspamd_http_message_add_header (struct rspamd_http_message *msg,
		const gchar *name,
		const gchar *value)
{
	if (value) {
		rspamd_http_message_add_header_len (msg, name, value, strlen (value));
	}
}

void
rspamd_http_message_add_header_fstr (struct rspamd_http_message *msg,
		const gchar *name,
		rspamd_fstring_t *value)
{
	struct rspamd_http_header *hdr, *found = NULL;
	guint nlen, vlen;

	if (msg != NULL && name != NULL && value != NULL) {
		hdr = g_malloc0 (sizeof (struct rspamd_http_header));
		nlen = strlen (name);
		vlen = value->len;
		hdr->combined = rspamd_fstring_sized_new (nlen + vlen + 4);
		rspamd_printf_fstring (&hdr->combined, "%s: %V\r\n", name, value);
		hdr->name.begin = hdr->combined->str;
		hdr->name.len = nlen;
		hdr->value.begin = hdr->combined->str + nlen + 2;
		hdr->value.len = vlen;

		HASH_FIND (hh, msg->headers, hdr->name.begin,
				hdr->name.len, found);

		if (found == NULL) {
			HASH_ADD_KEYPTR (hh, msg->headers, hdr->name.begin,
					hdr->name.len, hdr);
		}

		DL_APPEND (found, hdr);
	}
}

const rspamd_ftok_t *
rspamd_http_message_find_header (struct rspamd_http_message *msg,
	const gchar *name)
{
	struct rspamd_http_header *hdr;
	const rspamd_ftok_t *res = NULL;
	guint slen = strlen (name);

	if (msg != NULL) {
		HASH_FIND (hh, msg->headers, name, slen, hdr);

		if (hdr) {
			res = &hdr->value;
		}
	}

	return res;
}

GPtrArray*
rspamd_http_message_find_header_multiple (
		struct rspamd_http_message *msg,
		const gchar *name)
{
	GPtrArray *res = NULL;
	struct rspamd_http_header *hdr, *cur;

	guint slen = strlen (name);

	if (msg != NULL) {
		HASH_FIND (hh, msg->headers, name, slen, hdr);

		if (hdr) {
			res = g_ptr_array_sized_new (4);

			LL_FOREACH (hdr, cur) {
				g_ptr_array_add (res, &cur->value);
			}
		}
	}


	return res;
}


gboolean
rspamd_http_message_remove_header (struct rspamd_http_message *msg,
	const gchar *name)
{
	struct rspamd_http_header *hdr, *hcur, *hcurtmp;
	gboolean res = FALSE;
	guint slen = strlen (name);

	if (msg != NULL) {
		HASH_FIND (hh, msg->headers, name, slen, hdr);

		if (hdr) {
			HASH_DEL (msg->headers, hdr);
			res = TRUE;

			DL_FOREACH_SAFE (hdr, hcur, hcurtmp) {
				rspamd_fstring_free (hcur->combined);
				g_free (hcur);
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
		g_free (entry);
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
		rspamd_http_message_set_body (msg, err->message, strlen (err->message));
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
	rspamd_ftok_t *lookup, gboolean expand_path)
{
	struct stat st;
	gint fd;
	gchar filebuf[PATH_MAX], realbuf[PATH_MAX], *dir;
	struct rspamd_http_message *reply_msg;

	rspamd_snprintf (filebuf, sizeof (filebuf), "%s%c%T",
		entry->rt->default_fs_path, G_DIR_SEPARATOR, lookup);

	if (realpath (filebuf, realbuf) == NULL ||
		lstat (realbuf, &st) == -1) {
		return FALSE;
	}

	if (S_ISDIR (st.st_mode) && expand_path) {
		/* Try to append 'index.html' to the url */
		rspamd_fstring_t *nlookup;
		rspamd_ftok_t tok;
		gboolean ret;

		nlookup = rspamd_fstring_sized_new (lookup->len + sizeof ("index.html"));
		rspamd_printf_fstring (&nlookup, "%T%c%s", lookup, G_DIR_SEPARATOR,
				"index.html");
		tok.begin = nlookup->str;
		tok.len = nlookup->len;
		ret = rspamd_http_router_try_file (entry, &tok, FALSE);
		rspamd_fstring_free (nlookup);

		return ret;
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
	rspamd_http_router_insert_headers (entry->rt, reply_msg);

	if (!rspamd_http_message_set_body_from_fd (reply_msg, fd)) {
		close (fd);
		return FALSE;
	}

	close (fd);

	rspamd_http_connection_reset (entry->conn);

	msg_debug ("requested file %s", realbuf);
	rspamd_http_connection_write_message (entry->conn, reply_msg, NULL,
		rspamd_http_router_detect_ct (realbuf), entry, entry->conn->fd,
		entry->rt->ptv, entry->rt->ev_base);

	return TRUE;
}

static void
rspamd_http_router_send_error (GError *err,
		struct rspamd_http_connection_entry *entry)
{
	struct rspamd_http_message *err_msg;

	err_msg = rspamd_http_new_message (HTTP_RESPONSE);
	err_msg->date = time (NULL);
	err_msg->code = err->code;
	rspamd_http_message_set_body (err_msg, err->message,
			strlen (err->message));
	entry->is_reply = TRUE;
	err_msg->status = rspamd_fstring_new_init (err->message, strlen (err->message));
	rspamd_http_router_insert_headers (entry->rt, err_msg);
	rspamd_http_connection_reset (entry->conn);
	rspamd_http_connection_write_message (entry->conn,
			err_msg,
			NULL,
			"text/plain",
			entry,
			entry->conn->fd,
			entry->rt->ptv,
			entry->rt->ev_base);
}


static int
rspamd_http_router_finish_handler (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg)
{
	struct rspamd_http_connection_entry *entry = conn->ud;
	rspamd_http_router_handler_t handler = NULL;
	gpointer found;

	GError *err;
	rspamd_ftok_t lookup;
	const rspamd_ftok_t *encoding;
	struct http_parser_url u;
	guint i;
	rspamd_regexp_t *re;
	struct rspamd_http_connection_router *router;

	G_STATIC_ASSERT (sizeof (rspamd_http_router_handler_t) ==
		sizeof (gpointer));

	memset (&lookup, 0, sizeof (lookup));
	router = entry->rt;

	if (entry->is_reply) {
		/* Request is finished, it is safe to free a connection */
		rspamd_http_entry_free (entry);
	}
	else {
		if (G_UNLIKELY (msg->method != HTTP_GET && msg->method != HTTP_POST)) {
			if (router->unknown_method_handler) {
				return router->unknown_method_handler (entry, msg);
			}
			else {
				err = g_error_new (HTTP_ERROR, 500,
						"Invalid method");
				if (entry->rt->error_handler != NULL) {
					entry->rt->error_handler (entry, err);
				}

				rspamd_http_router_send_error (err, entry);
				g_error_free (err);

				return 0;
			}
		}

		/* Search for path */
		if (msg->url != NULL && msg->url->len != 0) {

			http_parser_parse_url (msg->url->str, msg->url->len, TRUE, &u);

			if (u.field_set & (1 << UF_PATH)) {
				guint unnorm_len;
				lookup.begin = msg->url->str + u.field_data[UF_PATH].off;
				lookup.len = u.field_data[UF_PATH].len;

				rspamd_http_normalize_path_inplace ((gchar *)lookup.begin,
						lookup.len,
						&unnorm_len);
				lookup.len = unnorm_len;
			}
			else {
				lookup.begin = msg->url->str;
				lookup.len = msg->url->len;
			}

			found = g_hash_table_lookup (entry->rt->paths, &lookup);
			memcpy (&handler, &found, sizeof (found));
			msg_debug ("requested known path: %T", &lookup);
		}
		else {
			err = g_error_new (HTTP_ERROR, 404,
					"Empty path requested");
			if (entry->rt->error_handler != NULL) {
				entry->rt->error_handler (entry, err);
			}

			rspamd_http_router_send_error (err, entry);
			g_error_free (err);

			return 0;
		}

		entry->is_reply = TRUE;

		encoding = rspamd_http_message_find_header (msg, "Accept-Encoding");

		if (encoding && rspamd_substring_search (encoding->begin, encoding->len,
				"gzip", 4) != -1) {
			entry->support_gzip = TRUE;
		}

		if (handler != NULL) {
			return handler (entry, msg);
		}
		else {
			/* Try regexps */
			for (i = 0; i < router->regexps->len; i ++) {
				re = g_ptr_array_index (router->regexps, i);
				if (rspamd_regexp_match (re, lookup.begin, lookup.len,
						TRUE)) {
					found = rspamd_regexp_get_ud (re);
					memcpy (&handler, &found, sizeof (found));

					return handler (entry, msg);
				}
			}

			/* Now try plain file */
			if (entry->rt->default_fs_path == NULL || lookup.len == 0 ||
					!rspamd_http_router_try_file (entry, &lookup, TRUE)) {

				err = g_error_new (HTTP_ERROR, 404,
						"Not found");
				if (entry->rt->error_handler != NULL) {
					entry->rt->error_handler (entry, err);
				}

				msg_info ("path: %T not found", &lookup);
				rspamd_http_router_send_error (err, entry);
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

	new = g_malloc0 (sizeof (struct rspamd_http_connection_router));
	new->paths = g_hash_table_new_full (rspamd_ftok_icase_hash,
			rspamd_ftok_icase_equal, rspamd_fstring_mapped_ftok_free, NULL);
	new->regexps = g_ptr_array_new ();
	new->conns = NULL;
	new->error_handler = eh;
	new->finish_handler = fh;
	new->ev_base = base;
	new->response_headers = g_hash_table_new_full (rspamd_strcase_hash,
			rspamd_strcase_equal, g_free, g_free);

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
		struct rspamd_cryptobox_keypair *key)
{
	g_assert (key != NULL);

	router->key = rspamd_keypair_ref (key);
}

void
rspamd_http_router_add_path (struct rspamd_http_connection_router *router,
	const gchar *path, rspamd_http_router_handler_t handler)
{
	gpointer ptr;
	rspamd_ftok_t *key;
	rspamd_fstring_t *storage;
	G_STATIC_ASSERT (sizeof (rspamd_http_router_handler_t) ==
		sizeof (gpointer));

	if (path != NULL && handler != NULL && router != NULL) {
		memcpy (&ptr, &handler, sizeof (ptr));
		storage = rspamd_fstring_new_init (path, strlen (path));
		key = g_malloc0 (sizeof (*key));
		key->begin = storage->str;
		key->len = storage->len;
		g_hash_table_insert (router->paths, key, ptr);
	}
}

void
rspamd_http_router_set_unknown_handler (struct rspamd_http_connection_router *router,
		rspamd_http_router_handler_t handler)
{
	if (router != NULL) {
		router->unknown_method_handler = handler;
	}
}

void
rspamd_http_router_add_header (struct rspamd_http_connection_router *router,
		const gchar *name, const gchar *value)
{
	if (name != NULL && value != NULL && router != NULL) {
		g_hash_table_replace (router->response_headers, g_strdup (name),
				g_strdup (value));
	}
}

void
rspamd_http_router_insert_headers (struct rspamd_http_connection_router *router,
		struct rspamd_http_message *msg)
{
	GHashTableIter it;
	gpointer k, v;

	if (router && msg) {
		g_hash_table_iter_init (&it, router->response_headers);

		while (g_hash_table_iter_next (&it, &k, &v)) {
			rspamd_http_message_add_header (msg, k, v);
		}
	}
}

void
rspamd_http_router_add_regexp (struct rspamd_http_connection_router *router,
		struct rspamd_regexp_s *re, rspamd_http_router_handler_t handler)
{
	gpointer ptr;
	G_STATIC_ASSERT (sizeof (rspamd_http_router_handler_t) ==
			sizeof (gpointer));

	if (re != NULL && handler != NULL && router != NULL) {
		memcpy (&ptr, &handler, sizeof (ptr));
		rspamd_regexp_set_ud (re, ptr);
		g_ptr_array_add (router->regexps, rspamd_regexp_ref (re));
	}
}

void
rspamd_http_router_handle_socket (struct rspamd_http_connection_router *router,
	gint fd, gpointer ud)
{
	struct rspamd_http_connection_entry *conn;

	conn = g_malloc0 (sizeof (struct rspamd_http_connection_entry));
	conn->rt = router;
	conn->ud = ud;
	conn->is_reply = FALSE;

	conn->conn = rspamd_http_connection_new (NULL,
			rspamd_http_router_error_handler,
			rspamd_http_router_finish_handler,
			0,
			RSPAMD_HTTP_SERVER,
			router->cache,
			NULL);

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
	rspamd_regexp_t *re;
	guint i;

	if (router) {
		DL_FOREACH_SAFE (router->conns, conn, tmp) {
			rspamd_http_entry_free (conn);
		}

		if (router->key) {
			rspamd_keypair_unref (router->key);
		}

		if (router->cache) {
			rspamd_keypair_cache_destroy (router->cache);
		}

		if (router->default_fs_path != NULL) {
			g_free (router->default_fs_path);
		}

		for (i = 0; i < router->regexps->len; i ++) {
			re = g_ptr_array_index (router->regexps, i);
			rspamd_regexp_unref (re);
		}

		g_ptr_array_free (router->regexps, TRUE);
		g_hash_table_unref (router->paths);
		g_hash_table_unref (router->response_headers);
		g_free (router);
	}
}

void
rspamd_http_connection_set_key (struct rspamd_http_connection *conn,
		struct rspamd_cryptobox_keypair *key)
{
	struct rspamd_http_connection_private *priv = conn->priv;

	g_assert (key != NULL);
	priv->local_key = rspamd_keypair_ref (key);
}

const struct rspamd_cryptobox_pubkey*
rspamd_http_connection_get_peer_key (struct rspamd_http_connection *conn)
{
	struct rspamd_http_connection_private *priv = conn->priv;

	if (priv->peer_key) {
		return priv->peer_key;
	}
	else if (priv->msg) {
		return priv->msg->peer_key;
	}

	return NULL;
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

GHashTable *
rspamd_http_message_parse_query (struct rspamd_http_message *msg)
{
	GHashTable *res;
	rspamd_fstring_t *key = NULL, *value = NULL;
	rspamd_ftok_t *key_tok = NULL, *value_tok = NULL;
	const gchar *p, *c, *end;
	struct http_parser_url u;
	enum {
		parse_key,
		parse_eqsign,
		parse_value,
		parse_ampersand
	} state = parse_key;

	res = g_hash_table_new_full (rspamd_ftok_icase_hash,
			rspamd_ftok_icase_equal,
			rspamd_fstring_mapped_ftok_free,
			rspamd_fstring_mapped_ftok_free);

	if (msg->url && msg->url->len > 0) {
		http_parser_parse_url (msg->url->str, msg->url->len, TRUE, &u);

		if (u.field_set & (1 << UF_QUERY)) {
			p = msg->url->str + u.field_data[UF_QUERY].off;
			c = p;
			end = p + u.field_data[UF_QUERY].len;

			while (p <= end) {
				switch (state) {
				case parse_key:
					if ((p == end || *p == '&') && p > c) {
						/* We have a single parameter without a value */
						key = rspamd_fstring_new_init (c, p - c);
						key_tok = rspamd_ftok_map (key);
						key_tok->len = rspamd_url_decode (key->str, key->str,
								key->len);

						value = rspamd_fstring_new_init ("", 0);
						value_tok = rspamd_ftok_map (value);

						g_hash_table_replace (res, key_tok, value_tok);
						state = parse_ampersand;
					}
					else if (*p == '=' && p > c) {
						/* We have something like key=value */
						key = rspamd_fstring_new_init (c, p - c);
						key_tok = rspamd_ftok_map (key);
						key_tok->len = rspamd_url_decode (key->str, key->str,
								key->len);

						state = parse_eqsign;
					}
					else {
						p ++;
					}
					break;

				case parse_eqsign:
					if (*p != '=') {
						c = p;
						state = parse_value;
					}
					else {
						p ++;
					}
					break;

				case parse_value:
					if ((p == end || *p == '&') && p >= c) {
						g_assert (key != NULL);
						if (p > c) {
							value = rspamd_fstring_new_init (c, p - c);
							value_tok = rspamd_ftok_map (value);
							value_tok->len = rspamd_url_decode (value->str,
									value->str,
									value->len);
							/* Detect quotes for value */
							if (value_tok->begin[0] == '"') {
								memmove (value->str, value->str + 1,
										value_tok->len - 1);
								value_tok->len --;
							}
							if (value_tok->begin[value_tok->len - 1] == '"') {
								value_tok->len --;
							}
						}
						else {
							value = rspamd_fstring_new_init ("", 0);
							value_tok = rspamd_ftok_map (value);
						}

						g_hash_table_replace (res, key_tok, value_tok);
						key = value = NULL;
						key_tok = value_tok = NULL;
						state = parse_ampersand;
					}
					else {
						p ++;
					}
					break;

				case parse_ampersand:
					if (p != end && *p != '&') {
						c = p;
						state = parse_key;
					}
					else {
						p ++;
					}
					break;
				}
			}
		}

		if (state != parse_ampersand && key != NULL) {
			rspamd_fstring_free (key);
		}
	}

	return res;
}


glong
rspamd_http_date_format (gchar *buf, gsize len, time_t time)
{
	struct tm tms;

	rspamd_gmtime (time, &tms);

	return rspamd_snprintf (buf, len, "%s, %02d %s %4d %02d:%02d:%02d GMT",
			http_week[tms.tm_wday], tms.tm_mday,
			http_month[tms.tm_mon], tms.tm_year + 1900,
			tms.tm_hour, tms.tm_min, tms.tm_sec);
}

struct rspamd_http_message *
rspamd_http_message_ref (struct rspamd_http_message *msg)
{
	REF_RETAIN (msg);

	return msg;
}

void
rspamd_http_message_unref (struct rspamd_http_message *msg)
{
	REF_RELEASE (msg);
}


void
rspamd_http_normalize_path_inplace (gchar *path, guint len, guint *nlen)
{
	const gchar *p, *end, *slash = NULL, *dot = NULL;
	gchar *o;
	enum {
		st_normal = 0,
		st_got_dot,
		st_got_dot_dot,
		st_got_slash,
		st_got_slash_slash,
	} state = st_normal;

	p = path;
	end = path + len;
	o = path;

	while (p < end) {
		switch (state) {
		case st_normal:
			if (G_UNLIKELY (*p == '/')) {
				state = st_got_slash;
				slash = p;
			}
			else if (G_UNLIKELY (*p == '.')) {
				state = st_got_dot;
				dot = p;
			}
			else {
				*o++ = *p;
			}
			p ++;
			break;
		case st_got_slash:
			if (G_UNLIKELY (*p == '/')) {
				/* Ignore double slash */
				*o++ = *p;
				state = st_got_slash_slash;
			}
			else if (G_UNLIKELY (*p == '.')) {
				dot = p;
				state = st_got_dot;
			}
			else {
				*o++ = '/';
				*o++ = *p;
				slash = NULL;
				dot = NULL;
				state = st_normal;
			}
			p ++;
			break;
		case st_got_slash_slash:
			if (G_LIKELY (*p != '/')) {
				slash = p - 1;
				dot = NULL;
				state = st_normal;
				continue;
			}
			p ++;
			break;
		case st_got_dot:
			if (G_UNLIKELY (*p == '/')) {
				/* Remove any /./ or ./ paths */
				if (((o > path && *(o - 1) != '/') || (o == path)) && slash) {
					/* Preserve one slash */
					*o++ = '/';
				}

				slash = p;
				dot = NULL;
				/* Ignore last slash */
				state = st_normal;
			}
			else if (*p == '.') {
				/* Double dot character */
				state = st_got_dot_dot;
			}
			else {
				/* We have something like .some or /.some */
				if (dot && p > dot) {
					if (slash == dot - 1 && (o > path && *(o - 1) != '/')) {
						/* /.blah */
						memmove (o, slash, p - slash);
						o += p - slash;
					}
					else {
						memmove (o, dot, p - dot);
						o += p - dot;
					}
				}

				slash = NULL;
				dot = NULL;
				state = st_normal;
				continue;
			}

			p ++;
			break;
		case st_got_dot_dot:
			if (*p == '/') {
				/* We have something like /../ or ../ */
				if (slash) {
					/* We need to remove the last component from o if it is there */
					if (o > path + 2 && *(o - 1) == '/') {
						slash = rspamd_memrchr (path, '/', o - path - 2);
					}
					else if (o > path + 1) {
						slash = rspamd_memrchr (path, '/', o - path - 1);
					}
					else {
						slash = NULL;
					}

					if (slash) {
						o = (gchar *)slash;
					}
					/* Otherwise we keep these dots */
					slash = p;
					state = st_got_slash;
				}
				else {
					/* We have something like bla../, so we need to copy it as is */
					if (o > path && dot && p > dot) {
						memmove (o, dot, p - dot);
						o += p - dot;
					}

					slash = NULL;
					dot = NULL;
					state = st_normal;
					continue;
				}
			}
			else {
				/* We have something like ..bla or ... */
				if (slash) {
					*o ++ = '/';
				}

				if (dot && p > dot) {
					memmove (o, dot, p - dot);
					o += p - dot;
				}

				slash = NULL;
				dot = NULL;
				state = st_normal;
				continue;
			}

			p ++;
			break;
		}
	}

	/* Leftover */
	switch (state) {
	case st_got_dot_dot:
		/* Trailing .. */
		if (slash) {
			/* We need to remove the last component from o if it is there */
			if (o > path + 2 && *(o - 1) == '/') {
				slash = rspamd_memrchr (path, '/', o - path - 2);
			}
			else if (o > path + 1) {
				slash = rspamd_memrchr (path, '/', o - path - 1);
			}
			else {
				if (o == path) {
					/* Corner case */
					*o++ = '/';
				}

				slash = NULL;
			}

			if (slash) {
				/* Remove last / */
				o = (gchar *)slash;
			}
		}
		else {
			/* Corner case */
			if (o == path) {
				*o++ = '/';
			}
			else {
				if (dot && p > dot) {
					memmove (o, dot, p - dot);
					o += p - dot;
				}
			}
		}
		break;
	case st_got_slash:
		*o++ = '/';
		break;
	default:
		if (o > path + 1 && *(o - 1) == '/') {
			o --;
		}
		break;
	}

	if (nlen) {
		*nlen = (o - path);
	}
}

void
rspamd_http_connection_disable_encryption (struct rspamd_http_connection *conn)
{
	struct rspamd_http_connection_private *priv;

	priv = conn->priv;

	if (priv) {
		if (priv->local_key) {
			rspamd_keypair_unref (priv->local_key);
		}
		if (priv->peer_key) {
			rspamd_pubkey_unref (priv->peer_key);
		}

		priv->local_key = NULL;
		priv->peer_key = NULL;
		priv->flags &= ~RSPAMD_HTTP_CONN_FLAG_ENCRYPTED;
	}
}