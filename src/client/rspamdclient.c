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

#include "rspamdclient.h"
#include "util.h"
#include "http.h"

#ifdef HAVE_FETCH_H
#include <fetch.h>
#elif defined(CURL_FOUND)
#include <curl/curl.h>
#endif

struct rspamd_client_request;

/*
 * Since rspamd uses untagged HTTP we can pass a single message per socket
 */
struct rspamd_client_connection {
	gint fd;
	GString *server_name;
	struct event_base *ev_base;
	struct timeval timeout;
	struct rspamd_http_connection *http_conn;
	gboolean req_sent;
	struct rspamd_client_request *req;
};

struct rspamd_client_request {
	struct rspamd_client_connection *conn;
	struct rspamd_http_message *msg;
	rspamd_client_callback cb;
	gpointer ud;
};

#define RCLIENT_ERROR rspamd_client_error_quark ()
GQuark
rspamd_client_error_quark (void)
{
	return g_quark_from_static_string ("rspamd-client-error");
}

static gint
rspamd_client_body_handler (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg,
		const gchar *chunk, gsize len)
{
	/* Do nothing here */
	return 0;
}

static void
rspamd_client_error_handler (struct rspamd_http_connection *conn, GError *err)
{
	struct rspamd_client_request *req = (struct rspamd_client_request *)conn->ud;
	struct rspamd_client_connection *c;

	c = req->conn;
	req->cb (c, NULL, c->server_name->str, NULL, req->ud, err);
}

static gint
rspamd_client_finish_handler (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg)
{
	struct rspamd_client_request *req = (struct rspamd_client_request *)conn->ud;
	struct rspamd_client_connection *c;
	struct ucl_parser *parser;
	GError *err;

	c = req->conn;

	if (!c->req_sent) {
		c->req_sent = TRUE;
		rspamd_http_connection_reset (c->http_conn);
		rspamd_http_connection_read_message (c->http_conn, c->req, c->fd, &c->timeout, c->ev_base);
		return 0;
	}
	else {
		if (msg->body == NULL || msg->body->len == 0 || msg->code != 200) {
			err = g_error_new (RCLIENT_ERROR, msg->code, "HTTP error occurred: %d", msg->code);
			req->cb (c, msg, c->server_name->str, NULL, req->ud, err);
			g_error_free (err);
			return -1;
		}

		parser = ucl_parser_new (0);
		if (!ucl_parser_add_chunk (parser, msg->body->str, msg->body->len)) {
			err = g_error_new (RCLIENT_ERROR, msg->code, "Cannot parse UCL: %s",
					ucl_parser_get_error (parser));
			ucl_parser_free (parser);
			req->cb (c, msg, c->server_name->str, NULL, req->ud, err);
			g_error_free (err);
			return -1;
		}

		req->cb (c, msg, c->server_name->str, ucl_parser_get_object (parser), req->ud, NULL);
		ucl_parser_free (parser);
	}

	return -1;
}

struct rspamd_client_connection *
rspamd_client_init (struct event_base *ev_base, const gchar *name,
		guint16 port, gdouble timeout)
{
	struct rspamd_client_connection *conn;
	gint fd;

	fd = make_universal_socket (name, port, SOCK_STREAM, TRUE, FALSE, TRUE);
	if (fd == -1) {
		return NULL;
	}

	conn = g_slice_alloc (sizeof (struct rspamd_client_connection));
	conn->ev_base = ev_base;
	conn->fd = fd;
	conn->req_sent = FALSE;
	conn->http_conn = rspamd_http_connection_new (rspamd_client_body_handler,
			rspamd_client_error_handler, rspamd_client_finish_handler, 0, RSPAMD_HTTP_CLIENT);
	conn->server_name = g_string_new (name);
	if (port != 0) {
		rspamd_printf_gstring (conn->server_name, ":%d", (int)port);
	}

	double_to_tv (timeout, &conn->timeout);

	return conn;
}

gboolean
rspamd_client_command (struct rspamd_client_connection *conn,
		const gchar *command, GHashTable *attrs,
		FILE *in, rspamd_client_callback cb,
		gpointer ud, GError **err)
{
	struct rspamd_client_request *req;
	gchar *p, *hn, *hv;
	gsize remain, old_len;
	GHashTableIter it;

	req = g_slice_alloc (sizeof (struct rspamd_client_request));
	req->conn = conn;
	req->cb = cb;
	req->ud = ud;

	req->msg = rspamd_http_new_message (HTTP_REQUEST);
	if (in != NULL) {
		/* Read input stream */
		req->msg->body = g_string_sized_new (BUFSIZ);
		while (!feof (in)) {
			p = req->msg->body->str + req->msg->body->len;
			remain = req->msg->body->allocated_len - req->msg->body->len - 1;
			if (remain == 0) {
				old_len = req->msg->body->len;
				g_string_set_size (req->msg->body, old_len * 2);
				req->msg->body->len = old_len;
				continue;
			}
			remain = fread (p, 1, remain, in);
			if (remain > 0) {
				req->msg->body->len += remain;
				req->msg->body->str[req->msg->body->len] = '\0';
			}
		}
		if (ferror (in) != 0) {
			g_set_error (err, RCLIENT_ERROR, ferror (in), "input IO error: %s", strerror (ferror (in)));
			g_slice_free1 (sizeof (struct rspamd_client_request), req);
			return FALSE;
		}
	}
	else {
		req->msg->body = NULL;
	}

	/* Convert headers */
	g_hash_table_iter_init (&it, attrs);
	while (g_hash_table_iter_next (&it, (gpointer *)&hn, (gpointer *)&hv)) {
		rspamd_http_message_add_header (req->msg, hn, hv);
	}

	g_string_append_c (req->msg->url, '/');
	g_string_append (req->msg->url, command);

	conn->req = req;

	rspamd_http_connection_write_message (conn->http_conn, req->msg, NULL,
			"text/plain", req, conn->fd, &conn->timeout, conn->ev_base);

	return TRUE;
}

void
rspamd_client_destroy (struct rspamd_client_connection *conn)
{
	if (conn != NULL) {
		rspamd_http_connection_unref (conn->http_conn);
		if (conn->req != NULL) {
			g_slice_free1 (sizeof (struct rspamd_client_request), conn->req);
		}
		close (conn->fd);
		g_string_free (conn->server_name, TRUE);
		g_slice_free1 (sizeof (struct rspamd_client_connection), conn);
	}
}
