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
#include "libutil/util.h"
#include "libserver/http/http_connection.h"
#include "libserver/http/http_private.h"
#include "libserver/protocol_internal.h"
#include "unix-std.h"

#ifdef SYS_ZSTD
#  include "zstd.h"
#else
#  include "contrib/zstd/zstd.h"
#endif

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
	struct ev_loop *event_loop;
	ev_tstamp timeout;
	struct rspamd_http_connection *http_conn;
	gboolean req_sent;
	gdouble start_time;
	gdouble send_time;
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

		g_free (req);
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
	req->cb (c, NULL, c->server_name->str, NULL,
			req->input, req->ud,
			c->start_time, c->send_time, NULL, 0, err);
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
	const rspamd_ftok_t *tok;
	const gchar *start, *body = NULL;
	guchar *out = NULL;
	gsize len, bodylen = 0;

	c = req->conn;

	if (!c->req_sent) {
		c->req_sent = TRUE;
		c->send_time = rspamd_get_ticks (FALSE);
		rspamd_http_connection_reset (c->http_conn);
		rspamd_http_connection_read_message (c->http_conn,
			c->req,
			c->timeout);

		return 0;
	}
	else {
		if (rspamd_http_message_get_body (msg, NULL) == NULL || msg->code / 100 != 2) {
			err = g_error_new (RCLIENT_ERROR, msg->code, "HTTP error: %d, %.*s",
					msg->code,
					(gint)msg->status->len, msg->status->str);
			req->cb (c, msg, c->server_name->str, NULL, req->input, req->ud,
					c->start_time, c->send_time, body, bodylen, err);
			g_error_free (err);

			return 0;
		}

		tok = rspamd_http_message_find_header (msg, COMPRESSION_HEADER);

		if (tok) {
			/* Need to uncompress */
			rspamd_ftok_t t;

			t.begin = "zstd";
			t.len = 4;

			if (rspamd_ftok_casecmp (tok, &t) == 0) {
				ZSTD_DStream *zstream;
				ZSTD_inBuffer zin;
				ZSTD_outBuffer zout;
				gsize outlen, r;

				zstream = ZSTD_createDStream ();
				ZSTD_initDStream (zstream);

				zin.pos = 0;
				zin.src = msg->body_buf.begin;
				zin.size = msg->body_buf.len;

				if ((outlen = ZSTD_getDecompressedSize (zin.src, zin.size)) == 0) {
					outlen = ZSTD_DStreamOutSize ();
				}

				out = g_malloc (outlen);
				zout.dst = out;
				zout.pos = 0;
				zout.size = outlen;

				while (zin.pos < zin.size) {
					r = ZSTD_decompressStream (zstream, &zout, &zin);

					if (ZSTD_isError (r)) {
						err = g_error_new (RCLIENT_ERROR, 500,
								"Decompression error: %s",
								ZSTD_getErrorName (r));
						req->cb (c, msg, c->server_name->str, NULL,
								req->input, req->ud, c->start_time,
								c->send_time, body, bodylen, err);
						g_error_free (err);
						ZSTD_freeDStream (zstream);

						goto end;
					}

					if (zout.pos == zout.size) {
						/* We need to extend output buffer */
						zout.size = zout.size * 2;
						zout.dst = g_realloc (zout.dst, zout.size);
					}
				}

				ZSTD_freeDStream (zstream);

				start = zout.dst;
				len = zout.pos;
			}
			else {
				err = g_error_new (RCLIENT_ERROR, 500,
						"Invalid compression method");
				req->cb (c, msg, c->server_name->str, NULL,
						req->input, req->ud, c->start_time, c->send_time,
						body, bodylen, err);
				g_error_free (err);

				return 0;
			}
		}
		else {
			start = msg->body_buf.begin;
			len = msg->body_buf.len;
		}

		/* Deal with body */
		tok = rspamd_http_message_find_header (msg, MESSAGE_OFFSET_HEADER);

		if (tok) {
			gulong value = 0;

			if (rspamd_strtoul (tok->begin, tok->len, &value) &&
					value < len) {
				body = start + value;
				bodylen = len - value;
				len = value;
			}
		}

		parser = ucl_parser_new (0);
		if (!ucl_parser_add_chunk (parser, start, len)) {
			err = g_error_new (RCLIENT_ERROR, msg->code, "Cannot parse UCL: %s",
					ucl_parser_get_error (parser));
			ucl_parser_free (parser);
			req->cb (c, msg, c->server_name->str, NULL,
					req->input, req->ud,
					c->start_time, c->send_time, body, bodylen, err);
			g_error_free (err);

			goto end;
		}

		req->cb (c, msg, c->server_name->str,
				ucl_parser_get_object (parser),
				req->input, req->ud,
				c->start_time, c->send_time, body, bodylen, NULL);
		ucl_parser_free (parser);
	}

end:
	if (out) {
		g_free (out);
	}

	return 0;
}

struct rspamd_client_connection *
rspamd_client_init (struct rspamd_http_context *http_ctx,
					struct ev_loop *ev_base, const gchar *name,
					guint16 port, gdouble timeout, const gchar *key)
{
	struct rspamd_client_connection *conn;
	gint fd;

	fd = rspamd_socket (name, port, SOCK_STREAM, TRUE, FALSE, TRUE);

	if (fd == -1) {
		return NULL;
	}

	conn = g_malloc0 (sizeof (struct rspamd_client_connection));
	conn->event_loop = ev_base;
	conn->fd = fd;
	conn->req_sent = FALSE;
	conn->http_conn = rspamd_http_connection_new_client_socket (http_ctx,
			rspamd_client_body_handler,
			rspamd_client_error_handler,
			rspamd_client_finish_handler,
			0,
			fd);

	if (!conn->http_conn) {
		rspamd_client_destroy (conn);
		return NULL;
	}

	/* Pass socket ownership */
	rspamd_http_connection_own_socket (conn->http_conn);
	conn->server_name = g_string_new (name);

	if (port != 0) {
		rspamd_printf_gstring (conn->server_name, ":%d", (int)port);
	}

	conn->timeout = timeout;

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
		gpointer ud, gboolean compressed,
		const gchar *comp_dictionary,
		const gchar *filename,
		GError **err)
{
	struct rspamd_client_request *req;
	struct rspamd_http_client_header *nh;
	gchar *p;
	gsize remain, old_len;
	GList *cur;
	GString *input = NULL;
	rspamd_fstring_t *body;
	guint dict_id = 0;
	gsize dict_len = 0;
	void *dict = NULL;
	ZSTD_CCtx *zctx;
	gboolean ret;

	req = g_malloc0 (sizeof (struct rspamd_client_request));
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
			g_free (req);
			g_string_free (input, TRUE);
			return FALSE;
		}

		if (!compressed) {
			/* Detect zstd input */
			if (input->len > 4 && memcmp (input->str, "\x28\xb5\x2f\xfd", 4) == 0) {
				compressed = TRUE;
			}
			body = rspamd_fstring_new_init (input->str, input->len);
		}
		else {
			if (comp_dictionary) {
				dict = rspamd_file_xmap (comp_dictionary, PROT_READ, &dict_len,
						TRUE);

				if (dict == NULL) {
					g_set_error (err, RCLIENT_ERROR, errno,
							"cannot open dictionary %s: %s",
							comp_dictionary,
							strerror (errno));
					g_free (req);
					g_string_free (input, TRUE);

					return FALSE;
				}

				dict_id = -1;
			}

			body = rspamd_fstring_sized_new (ZSTD_compressBound (input->len));
			zctx = ZSTD_createCCtx ();
			body->len = ZSTD_compress_usingDict (zctx, body->str, body->allocated,
					input->str, input->len,
					dict, dict_len,
					1);

			munmap (dict, dict_len);

			if (ZSTD_isError (body->len)) {
				g_set_error (err, RCLIENT_ERROR, ferror (
						in), "compression error");
				g_free (req);
				g_string_free (input, TRUE);
				rspamd_fstring_free (body);
				ZSTD_freeCCtx (zctx);

				return FALSE;
			}

			ZSTD_freeCCtx (zctx);
		}

		rspamd_http_message_set_body_from_fstring_steal (req->msg, body);
		req->input = input;
	}
	else {
		req->input = NULL;
	}

	/* Convert headers */
	cur = attrs->head;
	while (cur != NULL) {
		nh = cur->data;

		rspamd_http_message_add_header (req->msg, nh->name, nh->value);
		cur = g_list_next (cur);
	}

	if (compressed) {
		rspamd_http_message_add_header (req->msg, COMPRESSION_HEADER, "zstd");

		if (dict_id != 0) {
			gchar dict_str[32];

			rspamd_snprintf (dict_str, sizeof (dict_str), "%ud", dict_id);
			rspamd_http_message_add_header (req->msg, "Dictionary", dict_str);
		}
	}

	if (filename) {
		rspamd_http_message_add_header (req->msg, "Filename", filename);
	}

	req->msg->url = rspamd_fstring_append (req->msg->url, "/", 1);
	req->msg->url = rspamd_fstring_append (req->msg->url, command, strlen (command));

	conn->req = req;
	conn->start_time = rspamd_get_ticks (FALSE);

	if (compressed) {
		ret = rspamd_http_connection_write_message (conn->http_conn, req->msg,
				NULL,"application/x-compressed", req,
				conn->timeout);
	}
	else {
		ret = rspamd_http_connection_write_message (conn->http_conn, req->msg,
				NULL,"text/plain", req, conn->timeout);
	}

	return ret;
}

void
rspamd_client_destroy (struct rspamd_client_connection *conn)
{
	if (conn != NULL) {
		if (conn->http_conn) {
			rspamd_http_connection_unref (conn->http_conn);
		}

		if (conn->req != NULL) {
			rspamd_client_request_free (conn->req);
		}

		if (conn->key) {
			rspamd_pubkey_unref (conn->key);
		}

		if (conn->keypair) {
			rspamd_keypair_unref (conn->keypair);
		}

		g_string_free (conn->server_name, TRUE);
		g_free (conn);
	}
}
