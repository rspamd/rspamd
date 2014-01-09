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

struct rspamd_http_connection_private {
	GString *buf;
	gboolean new_header;
	struct rspamd_http_header *header;
	struct http_parser parser;
	struct http_parser_settings parser_cb;
	struct event ev;
	struct timeval tv;
	struct timeval *ptv;
	gboolean in_body;
	struct rspamd_http_message *req;
};

#define HTTP_ERROR http_error_quark ()
GQuark
http_error_quark (void)
{
	return g_quark_from_static_string ("http-error-quark");
}

static inline void
rspamd_http_check_date (struct rspamd_http_connection_private *priv)
{
	if (g_ascii_strcasecmp (priv->header->name->str, "date") == 0) {
		priv->req->date = rspamd_http_parse_date (priv->header->value->str,
				priv->header->value->len);
	}
}

static gint
rspamd_http_on_url (http_parser* parser, const gchar *at, size_t length)
{
	struct rspamd_http_connection *conn = (struct rspamd_http_connection *)parser->data;
	struct rspamd_http_connection_private *priv;

	priv = conn->priv;

	g_string_append_len (priv->req->url, at, length);

	return 0;
}

static gint
rspamd_http_on_header_field (http_parser* parser, const gchar *at, size_t length)
{
	struct rspamd_http_connection *conn = (struct rspamd_http_connection *)parser->data;
	struct rspamd_http_connection_private *priv;

	priv = conn->priv;

	if (priv->header == NULL) {
		priv->header = g_slice_alloc (sizeof (struct rspamd_http_header));
		priv->header->name = g_string_sized_new (32);
		priv->header->value = g_string_sized_new (32);
	}
	else if (priv->new_header) {
		LL_PREPEND (priv->req->headers, priv->header);
		rspamd_http_check_date (priv);
		priv->header = g_slice_alloc (sizeof (struct rspamd_http_header));
		priv->header->name = g_string_sized_new (32);
		priv->header->value = g_string_sized_new (32);
	}

	priv->new_header = FALSE;
	g_string_append_len (priv->header->name, at, length);

	return 0;
}

static gint
rspamd_http_on_header_value (http_parser* parser, const gchar *at, size_t length)
{
	struct rspamd_http_connection *conn = (struct rspamd_http_connection *)parser->data;
	struct rspamd_http_connection_private *priv;

	priv = conn->priv;

	if (priv->header == NULL) {
		/* Should not happen */
		return -1;
	}

	priv->new_header = TRUE;
	g_string_append_len (priv->header->value, at, length);

	return 0;
}

static int
rspamd_http_on_headers_complete (http_parser* parser)
{
	struct rspamd_http_connection *conn = (struct rspamd_http_connection *)parser->data;
	struct rspamd_http_connection_private *priv;

	priv = conn->priv;

	if (priv->header != NULL) {
		LL_PREPEND (priv->req->headers, priv->header);
		rspamd_http_check_date (priv);
		priv->header = NULL;
	}

	priv->in_body = TRUE;
	if (parser->content_length != 0 && parser->content_length != ULLONG_MAX) {
		priv->req->body = g_string_sized_new (parser->content_length + 1);
	}
	else {
		priv->req->body = g_string_sized_new (BUFSIZ);
	}

	return 0;
}

static int
rspamd_http_on_body (http_parser* parser, const gchar *at, size_t length)
{
	struct rspamd_http_connection *conn = (struct rspamd_http_connection *)parser->data;
	struct rspamd_http_connection_private *priv;

	priv = conn->priv;

	g_string_append_len (priv->req->body, at, length);

	if (conn->opts & RSPAMD_HTTP_BODY_PARTIAL) {
		return (conn->body_handler (conn, priv->req, at, length));
	}

	return 0;
}

static int
rspamd_http_on_message_complete (http_parser* parser)
{
	struct rspamd_http_connection *conn = (struct rspamd_http_connection *)parser->data;
	struct rspamd_http_connection_private *priv;
	int ret;

	priv = conn->priv;

	if (conn->opts & RSPAMD_HTTP_BODY_PARTIAL) {
		ret = conn->body_handler (conn, priv->req, NULL, 0);
	}
	else {
		ret = conn->body_handler (conn, priv->req, priv->req->body->str, priv->req->body->len);
	}

	return ret;
}

static void
rspamd_http_event_handler (int fd, short what, gpointer ud)
{
	struct rspamd_http_connection *conn = (struct rspamd_http_connection *)ud;
	struct rspamd_http_connection_private *priv;
	GString *buf;
	gssize r;
	GError *err;

	priv = conn->priv;
	buf = priv->buf;

	r = read (fd, buf->str, buf->allocated_len);
	if (r == -1) {
		err = g_error_new (HTTP_ERROR, errno, "IO read error: %s", strerror (errno));
		conn->error_handler (conn, err);
		g_error_free (err);
	}
	else {
		buf->len = r;
		if (http_parser_execute (&priv->parser, &priv->parser_cb, buf->str, r) != (size_t)r) {
			err = g_error_new (HTTP_ERROR, priv->parser.http_errno,
					"HTTP parser error: %s", http_errno_description (priv->parser.http_errno));
			conn->error_handler (conn, err);
			g_error_free (err);
		}
		/* TODO: handle EOF */
	}
}

struct rspamd_http_connection*
rspamd_http_connection_new (rspamd_http_body_handler body_handler,
		rspamd_http_error_handler error_handler, enum rspamd_http_options opts)
{
	struct rspamd_http_connection *new;
	struct rspamd_http_connection_private *priv;

	new = g_slice_alloc0 (sizeof (struct rspamd_http_connection));
	new->opts = opts;
	new->body_handler = body_handler;
	new->error_handler = error_handler;
	new->fd = -1;

	/* Init priv */
	priv = g_slice_alloc0 (sizeof (struct rspamd_http_connection_private));
	http_parser_init (&priv->parser, HTTP_REQUEST);
	priv->parser.data = new;
	priv->parser_cb.on_url = rspamd_http_on_url;
	priv->parser_cb.on_header_field = rspamd_http_on_header_field;
	priv->parser_cb.on_header_value = rspamd_http_on_header_value;
	priv->parser_cb.on_headers_complete = rspamd_http_on_headers_complete;
	priv->parser_cb.on_body = rspamd_http_on_body;
	priv->parser_cb.on_message_complete = rspamd_http_on_message_complete;

	new->priv = priv;

	return new;
}

void
rspamd_http_connection_reset (struct rspamd_http_connection *conn)
{
	struct rspamd_http_connection_private *priv;
	struct rspamd_http_message *req;
	struct rspamd_http_header *hdr, *tmp_hdr;

	priv = conn->priv;
	req = priv->req;

	/* Clear request */
	if (req != NULL) {
		LL_FOREACH_SAFE(req->headers, hdr, tmp_hdr) {
			g_string_free (hdr->name, TRUE);
			g_string_free (hdr->value, TRUE);
			g_slice_free1 (sizeof (struct rspamd_http_header), hdr);
		}
		g_string_free (req->body, TRUE);
		g_string_free (req->url, TRUE);
		g_slice_free1 (sizeof (struct rspamd_http_message), req);
		priv->req = NULL;
	}

	/* Clear priv */
	event_del (&priv->ev);
	if (priv->buf != NULL) {
		g_string_free (priv->buf, TRUE);
		priv->buf = NULL;
	}

	/* Clear conn itself */
	if (conn->fd != -1) {
		close (conn->fd);
	}
}

void
rspamd_http_connection_free (struct rspamd_http_connection *conn)
{
	struct rspamd_http_connection_private *priv;

	priv = conn->priv;
	rspamd_http_connection_reset (conn);
	g_slice_free1 (sizeof (struct rspamd_http_connection_private), priv);
	g_slice_free1 (sizeof (struct rspamd_http_connection), conn);
}

void
rspamd_http_connection_handle_request (struct rspamd_http_connection *conn,
		gpointer ud, gint fd, struct timeval *timeout, struct event_base *base)
{
	struct rspamd_http_connection_private *priv = conn->priv;
	struct rspamd_http_message *req;

	conn->fd = fd;
	conn->ud = ud;
	req = g_slice_alloc (sizeof (struct rspamd_http_message));
	req->url = g_string_sized_new (32);
	req->headers = NULL;
	req->date = 0;
	priv->req = req;

	if (timeout == NULL) {
		priv->ptv = NULL;
	}
	else {
		memcpy (&priv->tv, timeout, sizeof (struct timeval));
		priv->ptv = &priv->tv;
	}
	priv->header = NULL;
	priv->buf = g_string_sized_new (BUFSIZ);
	priv->in_body = FALSE;
	priv->new_header = TRUE;

	event_set (&priv->ev, fd, EV_READ | EV_PERSIST, rspamd_http_event_handler, conn);
	event_base_set (base, &priv->ev);
	event_add (&priv->ev, priv->ptv);
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
