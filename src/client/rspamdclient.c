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
#include "rspamdclient.h"
#include "util.h"
#include "http.h"
#include "unix-std.h"

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
	struct rspamd_cryptobox_pubkey *key;
	struct rspamd_cryptobox_keypair *keypair;
	struct event_base *ev_base;
	struct timeval timeout;
	struct rspamd_http_connection *http_conn;
	gboolean req_sent;
	struct rspamd_client_request *req;
	struct rspamd_keypair_cache *keys_cache;
};

struct rspamd_client_request {
	struct rspamd_client_connection *conn;
	struct rspamd_http_message *msg;
	GString *input;
	rspamd_client_callback cb;
	gpointer ud;
};

#define RCLIENT_ERROR rspamd_client_error_quark ()
GQuark
rspamd_client_error_quark (void)
{
	return g_quark_from_static_string ("rspamd-client-error");
}

static void
rspamd_client_request_free (struct rspamd_client_request *req)
{
	if (req != NULL) {
		if (req->conn) {
			req->conn->req = NULL;
		}
		if (req->input) {
			g_string_free (req->input, TRUE);
		}

		g_slice_free1 (sizeof (*req), req);
	}
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
	struct rspamd_client_request *req =
		(struct rspamd_client_request *)conn->ud;
	struct rspamd_client_connection *c;

	c = req->conn;
	req->cb (c, NULL, c->server_name->str, NULL, req->input, req->ud, err);
}

static gint
rspamd_client_finish_handler (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg)
{
	struct rspamd_client_request *req =
		(struct rspamd_client_request *)conn->ud;
	struct rspamd_client_connection *c;
	struct ucl_parser *parser;
	GError *err;

	c = req->conn;

	if (!c->req_sent) {
		c->req_sent = TRUE;
		rspamd_http_connection_reset (c->http_conn);
		rspamd_http_connection_read_message (c->http_conn,
			c->req,
			c->fd,
			&c->timeout,
			c->ev_base);
		return 0;
	}
	else {
		if (msg->body == NULL || msg->body_buf.len == 0 || msg->code != 200) {
			err = g_error_new (RCLIENT_ERROR, msg->code, "HTTP error: %d, %.*s",
					msg->code,
					(gint)msg->status->len, msg->status->str);
			req->cb (c, msg, c->server_name->str, NULL, req->input, req->ud, err);
			g_error_free (err);

			return 0;
		}

		parser = ucl_parser_new (0);
		if (!ucl_parser_add_chunk (parser, msg->body_buf.begin, msg->body_buf.len)) {
			err = g_error_new (RCLIENT_ERROR, msg->code, "Cannot parse UCL: %s",
					ucl_parser_get_error (parser));
			ucl_parser_free (parser);
			req->cb (c, msg, c->server_name->str, NULL, req->input, req->ud, err);
			g_error_free (err);

			return 0;
		}

		req->cb (c, msg, c->server_name->str, ucl_parser_get_object (
				parser), req->input, req->ud, NULL);
		ucl_parser_free (parser);
	}

	return 0;
}

struct rspamd_client_connection *
rspamd_client_init (struct event_base *ev_base, const gchar *name,
	guint16 port, gdouble timeout, const gchar *key)
{
	struct rspamd_client_connection *conn;
	gint fd;

	fd = rspamd_socket (name, port, SOCK_STREAM, TRUE, FALSE, TRUE);
	if (fd == -1) {
		return NULL;
	}

	conn = g_slice_alloc0 (sizeof (struct rspamd_client_connection));
	conn->ev_base = ev_base;
	conn->fd = fd;
	conn->req_sent = FALSE;
	conn->keys_cache = rspamd_keypair_cache_new (32);
	conn->http_conn = rspamd_http_connection_new (rspamd_client_body_handler,
			rspamd_client_error_handler,
			rspamd_client_finish_handler,
			0,
			RSPAMD_HTTP_CLIENT,
			conn->keys_cache);

	conn->server_name = g_string_new (name);
	if (port != 0) {
		rspamd_printf_gstring (conn->server_name, ":%d", (int)port);
	}

	double_to_tv (timeout, &conn->timeout);

	if (key) {
		conn->key = rspamd_pubkey_from_base32 (key, 0, RSPAMD_KEYPAIR_KEX,
				RSPAMD_CRYPTOBOX_MODE_25519);

		if (conn->key) {
			conn->keypair = rspamd_keypair_new (RSPAMD_KEYPAIR_KEX,
					RSPAMD_CRYPTOBOX_MODE_25519);
			rspamd_http_connection_set_key (conn->http_conn, conn->keypair);
		}
		else {
			rspamd_client_destroy (conn);
			return NULL;
		}
	}

	return conn;
}

gboolean
rspamd_client_command (struct rspamd_client_connection *conn,
	const gchar *command, GQueue *attrs,
	FILE *in, rspamd_client_callback cb,
	gpointer ud, GError **err)
{
	struct rspamd_client_request *req;
	struct rspamd_http_client_header *nh;
	gchar *p;
	gsize remain, old_len;
	GList *cur;
	GString *input = NULL;

	req = g_slice_alloc0 (sizeof (struct rspamd_client_request));
	req->conn = conn;
	req->cb = cb;
	req->ud = ud;

	req->msg = rspamd_http_new_message (HTTP_REQUEST);
	if (conn->key) {
		req->msg->peer_key = rspamd_pubkey_ref (conn->key);
	}

	if (in != NULL) {
		/* Read input stream */
		input = g_string_sized_new (BUFSIZ);

		while (!feof (in)) {
			p = input->str + input->len;
			remain = input->allocated_len - input->len - 1;
			if (remain == 0) {
				old_len = input->len;
				g_string_set_size (input, old_len * 2);
				input->len = old_len;
				continue;
			}
			remain = fread (p, 1, remain, in);
			if (remain > 0) {
				input->len += remain;
				input->str[input->len] = '\0';
			}
		}
		if (ferror (in) != 0) {
			g_set_error (err, RCLIENT_ERROR, ferror (
					in), "input IO error: %s", strerror (ferror (in)));
			g_slice_free1 (sizeof (struct rspamd_client_request), req);
			g_string_free (input, TRUE);
			return FALSE;
		}

		req->msg->body = rspamd_fstring_new_init (input->str, input->len);
		req->input = input;
	}
	else {
		req->msg->body = NULL;
		req->input = NULL;
	}

	/* Convert headers */
	cur = attrs->head;
	while (cur != NULL) {
		nh = cur->data;

		rspamd_http_message_add_header (req->msg, nh->name, nh->value);
		cur = g_list_next (cur);
	}

	req->msg->url = rspamd_fstring_append (req->msg->url, "/", 1);
	req->msg->url = rspamd_fstring_append (req->msg->url, command, strlen (command));

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
			rspamd_client_request_free (conn->req);
		}
		close (conn->fd);
		if (conn->key) {
			rspamd_pubkey_unref (conn->key);
		}
		if (conn->keypair) {
			rspamd_keypair_unref (conn->keypair);
		}
		g_string_free (conn->server_name, TRUE);
		g_slice_free1 (sizeof (struct rspamd_client_connection), conn);
	}
}
