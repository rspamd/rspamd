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
#include "http_connection.h"
#include "http_private.h"
#include "http_message.h"
#include "utlist.h"
#include "util.h"
#include "printf.h"
#include "logger.h"
#include "ref.h"
#include "ottery.h"
#include "keypair_private.h"
#include "cryptobox.h"
#include "libutil/libev_helper.h"
#include "libserver/ssl_util.h"
#include "libserver/url.h"

#include "contrib/mumhash/mum.h"
#include "contrib/http-parser/http_parser.h"
#include "unix-std.h"

#include <openssl/err.h>

#define ENCRYPTED_VERSION " HTTP/1.0"

struct _rspamd_http_privbuf {
	rspamd_fstring_t *data;
	const gchar *zc_buf;
	gsize zc_remain;
	ref_entry_t ref;
};

enum rspamd_http_priv_flags {
	RSPAMD_HTTP_CONN_FLAG_ENCRYPTED = 1u << 0u,
	RSPAMD_HTTP_CONN_FLAG_NEW_HEADER = 1u << 1u,
	RSPAMD_HTTP_CONN_FLAG_RESETED = 1u << 2u,
	RSPAMD_HTTP_CONN_FLAG_TOO_LARGE = 1u << 3u,
	RSPAMD_HTTP_CONN_FLAG_ENCRYPTION_NEEDED = 1u << 4u,
	RSPAMD_HTTP_CONN_FLAG_PROXY = 1u << 5u,
	RSPAMD_HTTP_CONN_FLAG_PROXY_REQUEST = 1u << 6u,
	RSPAMD_HTTP_CONN_OWN_SOCKET = 1u << 7u,
};

#define IS_CONN_ENCRYPTED(c) ((c)->flags & RSPAMD_HTTP_CONN_FLAG_ENCRYPTED)
#define IS_CONN_RESETED(c) ((c)->flags & RSPAMD_HTTP_CONN_FLAG_RESETED)

struct rspamd_http_connection_private {
	struct rspamd_http_context *ctx;
	struct rspamd_ssl_connection *ssl;
	struct _rspamd_http_privbuf *buf;
	struct rspamd_keypair_cache *cache;
	struct rspamd_cryptobox_pubkey *peer_key;
	struct rspamd_cryptobox_keypair *local_key;
	struct rspamd_http_header *header;
	struct http_parser parser;
	struct http_parser_settings parser_cb;
	struct rspamd_io_ev ev;
	ev_tstamp timeout;
	struct rspamd_http_message *msg;
	struct iovec *out;
	guint outlen;
	enum rspamd_http_priv_flags flags;
	gsize wr_pos;
	gsize wr_total;
};

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
					&id_len, RSPAMD_BASE32_DEFAULT);

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

						if (priv->cache && priv->msg->peer_key) {
							rspamd_keypair_cache_process (priv->cache,
									priv->local_key,
									priv->msg->peer_key);
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
	khiter_t k;
	gint r;

	priv->header->combined = rspamd_fstring_append (priv->header->combined,
			"\r\n", 2);
	priv->header->value.len = priv->header->combined->len -
			priv->header->name.len - 4;
	priv->header->value.begin = priv->header->combined->str +
			priv->header->name.len + 2;
	priv->header->name.begin = priv->header->combined->str;

	k = kh_put (rspamd_http_headers_hash, priv->msg->headers, &priv->header->name,
			&r);

	if (r != 0) {
		kh_value (priv->msg->headers, k) = priv->header;
		hdr = NULL;
	}
	else {
		hdr = kh_value (priv->msg->headers, k);
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
		rspamd_ev_watcher_stop (priv->ctx->event_loop, &priv->ev);

		msg->code = parser->status_code;
		rspamd_http_connection_ref (conn);
		ret = conn->finish_handler (conn, msg);

		if (conn->opts & RSPAMD_HTTP_CLIENT_KEEP_ALIVE) {
			rspamd_http_context_push_keepalive (conn->priv->ctx, conn,
					msg, conn->priv->ctx->event_loop);
			rspamd_http_connection_reset (conn);
		}
		else {
			conn->finished = TRUE;
		}

		rspamd_http_connection_unref (conn);

		return ret;
	}

	/*
	 * HTTP parser sets content length to (-1) when it doesn't know the real
	 * length, for example, in case of chunked encoding.
	 *
	 * Hence, we skip body setup here
	 */
	if (parser->content_length != ULLONG_MAX && parser->content_length != 0 &&
			msg->method != HTTP_HEAD) {
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
		rspamd_ev_watcher_stop (priv->ctx->event_loop, &priv->ev);
		msg->code = parser->status_code;
		rspamd_http_connection_ref (conn);
		ret = conn->finish_handler (conn, msg);

		if (conn->opts & RSPAMD_HTTP_CLIENT_KEEP_ALIVE) {
			rspamd_http_context_push_keepalive (conn->priv->ctx, conn,
					msg, conn->priv->ctx->event_loop);
			rspamd_http_connection_reset (conn);
		}
		else {
			conn->finished = TRUE;
		}

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
	struct rspamd_http_header *hdr, *hcur, *hcurtmp;
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
	kh_foreach_value (msg->headers, hdr, {
		DL_FOREACH_SAFE (hdr, hcur, hcurtmp) {
			rspamd_fstring_free (hcur->combined);
			g_free (hcur);
		}
	});

	kh_destroy (rspamd_http_headers_hash, msg->headers);
	msg->headers = kh_init (rspamd_http_headers_hash);

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
		rspamd_ev_watcher_stop (priv->ctx->event_loop, &priv->ev);
		rspamd_http_connection_ref (conn);
		ret = conn->finish_handler (conn, priv->msg);

		if (conn->opts & RSPAMD_HTTP_CLIENT_KEEP_ALIVE) {
			rspamd_http_context_push_keepalive (conn->priv->ctx, conn,
					priv->msg, conn->priv->ctx->event_loop);
			rspamd_http_connection_reset (conn);
		}
		else {
			conn->finished = TRUE;
		}

		rspamd_http_connection_unref (conn);
	}

	return ret;
}

static void
rspamd_http_simple_client_helper (struct rspamd_http_connection *conn)
{
	struct rspamd_http_connection_private *priv;
	gpointer ssl;
	gint request_method;
	GString *prev_host = NULL;

	priv = conn->priv;
	ssl = priv->ssl;
	priv->ssl = NULL;

	/* Preserve data */
	if (priv->msg) {
		request_method = priv->msg->method;
		/* Preserve host for keepalive */
		prev_host = priv->msg->host;
		priv->msg->host = NULL;
	}

	rspamd_http_connection_reset (conn);
	priv->ssl = ssl;

	/* Plan read message */

	if (conn->opts & RSPAMD_HTTP_CLIENT_SHARED) {
		rspamd_http_connection_read_message_shared (conn, conn->ud,
				conn->priv->timeout);
	}
	else {
		rspamd_http_connection_read_message (conn, conn->ud,
				conn->priv->timeout);
	}

	if (priv->msg) {
		priv->msg->method = request_method;
		priv->msg->host = prev_host;
	}
	else {
		if (prev_host) {
			g_string_free (prev_host, TRUE);
		}
	}
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
	if (priv->ssl) {
		/* Might be recursive! */
		cur_iov = g_malloc (niov * sizeof (struct iovec));
	}
	else {
		cur_iov = alloca (niov * sizeof (struct iovec));
	}
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
		g_free (cur_iov);
	}
	else {
		r = sendmsg (conn->fd, &msg, flags);
	}

	if (r == -1) {
		if (!priv->ssl) {
			err = g_error_new (HTTP_ERROR, 500, "IO write error: %s", strerror (errno));
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

		if (priv->ssl && r > 0) {
			/* We can write more data... */
			rspamd_http_write_helper (conn);
			return;
		}
	}

	return;

call_finish_handler:
	rspamd_ev_watcher_stop (priv->ctx->event_loop, &priv->ev);

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
				else if (priv->parser.http_errno == HPE_CLOSED_CONNECTION) {
					msg_err ("got garbage after end of the message, ignore it");

					REF_RELEASE (pbuf);
					rspamd_http_connection_unref (conn);

					return;
				}
				else {
					if (priv->parser.http_errno > HPE_CB_status) {
						err = g_error_new (HTTP_ERROR, 400,
								"HTTP parser error: %s",
								http_errno_description (priv->parser.http_errno));
					}
					else {
						err = g_error_new (HTTP_ERROR, 500,
								"HTTP parser internal error: %s",
								http_errno_description (priv->parser.http_errno));
					}
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
						400,
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
						500,
						"HTTP IO read error: %s",
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
				err = g_error_new (HTTP_ERROR, 400,
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
			if (!conn->finished && !priv->ssl) {
				err = g_error_new (HTTP_ERROR, 408,
						"IO timeout");
				conn->error_handler (conn, err);
				g_error_free (err);

			}
			REF_RELEASE (pbuf);
			rspamd_http_connection_unref (conn);

			return;
		}
		else {
			if (!priv->ssl) {
				err = g_error_new(HTTP_ERROR, 408,
						"IO timeout");
				conn->error_handler(conn, err);
				g_error_free(err);
			}

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

static struct rspamd_http_connection *
rspamd_http_connection_new_common (struct rspamd_http_context *ctx,
								   gint fd,
								   rspamd_http_body_handler_t body_handler,
								   rspamd_http_error_handler_t error_handler,
								   rspamd_http_finish_handler_t finish_handler,
								   unsigned opts,
								   enum rspamd_http_connection_type type,
								   enum rspamd_http_priv_flags priv_flags,
								   struct upstream *proxy_upstream)
{
	struct rspamd_http_connection *conn;
	struct rspamd_http_connection_private *priv;

	g_assert (error_handler != NULL && finish_handler != NULL);

	if (ctx == NULL) {
		ctx = rspamd_http_context_default ();
	}

	conn = g_malloc0 (sizeof (struct rspamd_http_connection));
	conn->opts = opts;
	conn->type = type;
	conn->body_handler = body_handler;
	conn->error_handler = error_handler;
	conn->finish_handler = finish_handler;
	conn->fd = fd;
	conn->ref = 1;
	conn->finished = FALSE;

	/* Init priv */
	priv = g_malloc0 (sizeof (struct rspamd_http_connection_private));
	conn->priv = priv;
	priv->ctx = ctx;
	priv->flags = priv_flags;

	if (type == RSPAMD_HTTP_SERVER) {
		priv->cache = ctx->server_kp_cache;
	}
	else {
		priv->cache = ctx->client_kp_cache;
		if (ctx->client_kp) {
			priv->local_key = rspamd_keypair_ref (ctx->client_kp);
		}
	}

	rspamd_http_parser_reset (conn);
	priv->parser.data = conn;

	return conn;
}

struct rspamd_http_connection *
rspamd_http_connection_new_server (struct rspamd_http_context *ctx,
								   gint fd,
								   rspamd_http_body_handler_t body_handler,
								   rspamd_http_error_handler_t error_handler,
								   rspamd_http_finish_handler_t finish_handler,
								   unsigned opts)
{
	return rspamd_http_connection_new_common (ctx, fd, body_handler,
			error_handler, finish_handler, opts, RSPAMD_HTTP_SERVER, 0, NULL);
}

struct rspamd_http_connection *
rspamd_http_connection_new_client_socket (struct rspamd_http_context *ctx,
								   rspamd_http_body_handler_t body_handler,
								   rspamd_http_error_handler_t error_handler,
								   rspamd_http_finish_handler_t finish_handler,
								   unsigned opts,
								   gint fd)
{
	return rspamd_http_connection_new_common (ctx, fd, body_handler,
			error_handler, finish_handler, opts, RSPAMD_HTTP_CLIENT, 0, NULL);
}

struct rspamd_http_connection *
rspamd_http_connection_new_client (struct rspamd_http_context *ctx,
								   rspamd_http_body_handler_t body_handler,
								   rspamd_http_error_handler_t error_handler,
								   rspamd_http_finish_handler_t finish_handler,
								   unsigned opts,
								   rspamd_inet_addr_t *addr)
{
	gint fd;

	if (ctx == NULL) {
		ctx = rspamd_http_context_default ();
	}

	if (ctx->http_proxies) {
		struct upstream *up = rspamd_upstream_get (ctx->http_proxies,
				RSPAMD_UPSTREAM_ROUND_ROBIN, NULL, 0);

		if (up) {
			rspamd_inet_addr_t *proxy_addr = rspamd_upstream_addr_next (up);

			fd = rspamd_inet_address_connect (proxy_addr, SOCK_STREAM, TRUE);

			if (fd == -1) {
				msg_info ("cannot connect to http proxy %s: %s",
						rspamd_inet_address_to_string_pretty (proxy_addr),
						strerror (errno));
				rspamd_upstream_fail (up, TRUE, strerror (errno));

				return NULL;
			}

			return rspamd_http_connection_new_common (ctx, fd, body_handler,
					error_handler, finish_handler, opts,
					RSPAMD_HTTP_CLIENT,
					RSPAMD_HTTP_CONN_OWN_SOCKET|RSPAMD_HTTP_CONN_FLAG_PROXY,
					up);
		}
	}

	/* Unproxied version */
	fd = rspamd_inet_address_connect (addr, SOCK_STREAM, TRUE);

	if (fd == -1) {
		msg_info ("cannot connect make http connection to %s: %s",
				rspamd_inet_address_to_string_pretty (addr),
				strerror (errno));

		return NULL;
	}

	return rspamd_http_connection_new_common (ctx, fd, body_handler,
			error_handler, finish_handler, opts,
			RSPAMD_HTTP_CLIENT,
			RSPAMD_HTTP_CONN_OWN_SOCKET,
			NULL);
}

struct rspamd_http_connection *
rspamd_http_connection_new_keepalive (struct rspamd_http_context *ctx,
									  rspamd_http_body_handler_t body_handler,
									  rspamd_http_error_handler_t error_handler,
									  rspamd_http_finish_handler_t finish_handler,
									  rspamd_inet_addr_t *addr,
									  const gchar *host)
{
	struct rspamd_http_connection *conn;

	if (ctx == NULL) {
		ctx = rspamd_http_context_default ();
	}

	conn = rspamd_http_context_check_keepalive (ctx, addr, host);

	if (conn) {
		return conn;
	}

	conn = rspamd_http_connection_new_client (ctx,
			body_handler, error_handler, finish_handler,
			RSPAMD_HTTP_CLIENT_SIMPLE|RSPAMD_HTTP_CLIENT_KEEP_ALIVE,
			addr);

	if (conn) {
		rspamd_http_context_prepare_keepalive (ctx, conn, addr, host);
	}

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
	rspamd_ev_watcher_stop (priv->ctx->event_loop, &priv->ev);

	if (!(priv->flags & RSPAMD_HTTP_CONN_FLAG_RESETED)) {
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
	struct rspamd_http_header *hdr, *nhdr, *nhdrs, *hcur;
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
		new_msg->host = g_string_new_len (msg->host->str, msg->host->len);
	}

	new_msg->method = msg->method;
	new_msg->port = msg->port;
	new_msg->date = msg->date;
	new_msg->last_modified = msg->last_modified;

	kh_foreach_value (msg->headers, hdr, {
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

		gint r;
		khiter_t k = kh_put (rspamd_http_headers_hash, new_msg->headers,
				&nhdrs->name,&r);

		if (r != 0) {
			kh_value (new_msg->headers, k) = nhdrs;
		}
		else {
			DL_CONCAT (kh_value (new_msg->headers, k), nhdrs);
		}
	});

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

		if (priv->flags & RSPAMD_HTTP_CONN_OWN_SOCKET) {
			/* Fd is owned by a connection */
			close (conn->fd);
		}

		g_free (priv);
	}

	g_free (conn);
}

static void
rspamd_http_connection_read_message_common (struct rspamd_http_connection *conn,
		gpointer ud, ev_tstamp timeout,
		gint flags)
{
	struct rspamd_http_connection_private *priv = conn->priv;
	struct rspamd_http_message *req;

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

	priv->timeout = timeout;
	priv->header = NULL;
	priv->buf = g_malloc0 (sizeof (*priv->buf));
	REF_INIT_RETAIN (priv->buf, rspamd_http_privbuf_dtor);
	priv->buf->data = rspamd_fstring_sized_new (8192);
	priv->flags |= RSPAMD_HTTP_CONN_FLAG_NEW_HEADER;

	rspamd_ev_watcher_init (&priv->ev, conn->fd, EV_READ,
			rspamd_http_event_handler, conn);
	rspamd_ev_watcher_start (priv->ctx->event_loop, &priv->ev, priv->timeout);

	priv->flags &= ~RSPAMD_HTTP_CONN_FLAG_RESETED;
}

void
rspamd_http_connection_read_message (struct rspamd_http_connection *conn,
		gpointer ud, ev_tstamp timeout)
{
	rspamd_http_connection_read_message_common (conn, ud, timeout, 0);
}

void
rspamd_http_connection_read_message_shared (struct rspamd_http_connection *conn,
		gpointer ud, ev_tstamp timeout)
{
	rspamd_http_connection_read_message_common (conn, ud, timeout,
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
	struct rspamd_http_header *hdr, *hcur;
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


	kh_foreach_value (msg->headers, hdr, {
		DL_FOREACH (hdr, hcur) {
			segments[i].data = hcur->combined->str;
			segments[i++].len = hcur->combined->len;
		}
	});

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
	const gchar *conn_type = "close";

	if (conn->type == RSPAMD_HTTP_SERVER) {
		/* Format reply */
		if (msg->method < HTTP_SYMBOLS) {
			rspamd_ftok_t status;

			rspamd_http_date_format (datebuf, sizeof (datebuf), msg->date);

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
									msg->code, &status, priv->ctx->config.server_hdr,
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
									msg->code, &status, priv->ctx->config.server_hdr,
									datebuf,
									bodylen);
				}
				enclen += meth_len;
				/* External reply */
				rspamd_printf_fstring (buf,
						"HTTP/1.1 200 OK\r\n"
						"Connection: close\r\n"
						"Server: %s\r\n"
						"Date: %s\r\n"
						"Content-Length: %z\r\n"
						"Content-Type: application/octet-stream\r\n",
						priv->ctx->config.server_hdr,
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
									msg->code, &status, priv->ctx->config.server_hdr,
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
									msg->code, &status, priv->ctx->config.server_hdr,
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

		/* Client request */
		if (conn->opts & RSPAMD_HTTP_CLIENT_KEEP_ALIVE) {
			conn_type = "keep-alive";
		}

		/* Format request */
		enclen += RSPAMD_FSTRING_LEN (msg->url) +
				strlen (http_method_str (msg->method)) + 1;

		if (host == NULL && msg->host == NULL) {
			/* Fallback to HTTP/1.0 */
			if (encrypted) {
				rspamd_printf_fstring (buf,
						"%s %s HTTP/1.0\r\n"
						"Content-Length: %z\r\n"
						"Content-Type: application/octet-stream\r\n"
						"Connection: %s\r\n",
						"POST",
						"/post",
						enclen,
						conn_type);
			}
			else {
				rspamd_printf_fstring (buf,
						"%s %V HTTP/1.0\r\n"
						"Content-Length: %z\r\n"
						"Connection: %s\r\n",
						http_method_str (msg->method),
						msg->url,
						bodylen,
						conn_type);

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
			/* Normal HTTP/1.1 with Host */
			if (host == NULL) {
				host = msg->host->str;
			}

			if (encrypted) {
				/* TODO: Add proxy support to HTTPCrypt */
				rspamd_printf_fstring (buf,
						"%s %s HTTP/1.1\r\n"
						"Connection: %s\r\n"
						"Host: %s\r\n"
						"Content-Length: %z\r\n"
						"Content-Type: application/octet-stream\r\n",
						"POST",
						"/post",
						conn_type,
						host,
						enclen);
			}
			else {
				if (conn->priv->flags & RSPAMD_HTTP_CONN_FLAG_PROXY) {
					if ((msg->flags & RSPAMD_HTTP_FLAG_HAS_HOST_HEADER)) {
						rspamd_printf_fstring(buf,
								"%s %s://%s:%d/%V HTTP/1.1\r\n"
								"Connection: %s\r\n"
								"Content-Length: %z\r\n",
								http_method_str(msg->method),
								(msg->flags & RSPAMD_HTTP_FLAG_SSL) ? "https" : "http",
								host,
								msg->port,
								msg->url,
								conn_type,
								bodylen);
					}
					else {
						rspamd_printf_fstring(buf,
								"%s %s://%s:%d/%V HTTP/1.1\r\n"
								"Connection: %s\r\n"
								"Host: %s\r\n"
								"Content-Length: %z\r\n",
								http_method_str(msg->method),
								(msg->flags & RSPAMD_HTTP_FLAG_SSL) ? "https" : "http",
								host,
								msg->port,
								msg->url,
								conn_type,
								host,
								bodylen);
					}
				}
				else {
					if ((msg->flags & RSPAMD_HTTP_FLAG_HAS_HOST_HEADER)) {
						rspamd_printf_fstring(buf,
								"%s %V HTTP/1.1\r\n"
								"Connection: %s\r\n"
								"Content-Length: %z\r\n",
								http_method_str(msg->method),
								msg->url,
								conn_type,
								bodylen);
					}
					else {
						rspamd_printf_fstring(buf,
								"%s %V HTTP/1.1\r\n"
								"Connection: %s\r\n"
								"Host: %s\r\n"
								"Content-Length: %z\r\n",
								http_method_str(msg->method),
								msg->url,
								conn_type,
								host,
								bodylen);
					}
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

static gboolean
rspamd_http_connection_write_message_common (struct rspamd_http_connection *conn,
											 struct rspamd_http_message *msg,
											 const gchar *host,
											 const gchar *mime_type,
											 gpointer ud,
											 ev_tstamp timeout,
											 gboolean allow_shared)
{
	struct rspamd_http_connection_private *priv = conn->priv;
	struct rspamd_http_header *hdr, *hcur;
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

	conn->ud = ud;
	priv->msg = msg;
	priv->timeout = timeout;

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

		if (priv->cache) {
			rspamd_keypair_cache_process (priv->cache,
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

	if (priv->ctx->config.user_agent && conn->type == RSPAMD_HTTP_CLIENT) {
		rspamd_ftok_t srch;
		khiter_t k;
		gint r;

		RSPAMD_FTOK_ASSIGN (&srch, "User-Agent");

		k = kh_put (rspamd_http_headers_hash, msg->headers, &srch,&r);

		if (r != 0) {
			hdr = g_malloc0 (sizeof (struct rspamd_http_header));
			guint vlen = strlen (priv->ctx->config.user_agent);
			hdr->combined = rspamd_fstring_sized_new (srch.len + vlen + 4);
			rspamd_printf_fstring (&hdr->combined, "%T: %*s\r\n", &srch, vlen,
					priv->ctx->config.user_agent);
			hdr->name.begin = hdr->combined->str;
			hdr->name.len = srch.len;
			hdr->value.begin = hdr->combined->str + srch.len + 2;
			hdr->value.len = vlen;
			hdr->prev = hdr; /* for utlists */

			kh_value (msg->headers, k) = hdr;
			/* as we searched using static buffer */
			kh_key (msg->headers, k) = &hdr->name;
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
		kh_foreach_value (msg->headers, hdr, {
			DL_FOREACH (hdr, hcur) {
				/* <name: value\r\n> */
				priv->wr_total += hcur->combined->len;
				enclen += hcur->combined->len;
				priv->outlen ++;
				hdrcount ++;
			}
		});
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
			kh_foreach_value (msg->headers, hdr, {
				DL_FOREACH (hdr, hcur) {
					priv->out[i].iov_base = hcur->combined->str;
					priv->out[i++].iov_len = hcur->combined->len;
				}
			});

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

	if (priv->flags & RSPAMD_HTTP_CONN_FLAG_PROXY) {
		/* We need to disable SSL flag! */
		msg->flags &=~ RSPAMD_HTTP_FLAG_SSL;
	}

	rspamd_ev_watcher_stop (priv->ctx->event_loop, &priv->ev);

	if (msg->flags & RSPAMD_HTTP_FLAG_SSL) {
		gpointer ssl_ctx = (msg->flags & RSPAMD_HTTP_FLAG_SSL_NOVERIFY) ?
				priv->ctx->ssl_ctx_noverify : priv->ctx->ssl_ctx;

		if (!ssl_ctx) {
			err = g_error_new (HTTP_ERROR, 400, "ssl message requested "
					"with no ssl ctx");
			rspamd_http_connection_ref (conn);
			conn->error_handler (conn, err);
			rspamd_http_connection_unref (conn);
			g_error_free (err);
			return FALSE;
		}
		else {
			if (priv->ssl) {
				/* Cleanup the existing connection */
				rspamd_ssl_connection_free (priv->ssl);
			}

			priv->ssl = rspamd_ssl_connection_new (ssl_ctx, priv->ctx->event_loop,
					!(msg->flags & RSPAMD_HTTP_FLAG_SSL_NOVERIFY),
					conn->log_tag);
			g_assert (priv->ssl != NULL);

			if (!rspamd_ssl_connect_fd (priv->ssl, conn->fd, host, &priv->ev,
					priv->timeout, rspamd_http_event_handler,
					rspamd_http_ssl_err_handler, conn)) {

				err = g_error_new (HTTP_ERROR, 400,
						"ssl connection error: ssl error=%s, errno=%s",
						ERR_error_string (ERR_get_error (), NULL),
						strerror (errno));
				rspamd_http_connection_ref (conn);
				conn->error_handler (conn, err);
				rspamd_http_connection_unref (conn);
				g_error_free (err);
				return FALSE;
			}
		}
	}
	else {
		rspamd_ev_watcher_init (&priv->ev, conn->fd, EV_WRITE,
				rspamd_http_event_handler, conn);
		rspamd_ev_watcher_start (priv->ctx->event_loop, &priv->ev, priv->timeout);
	}

	return TRUE;
}

gboolean
rspamd_http_connection_write_message (struct rspamd_http_connection *conn,
									  struct rspamd_http_message *msg,
									  const gchar *host,
									  const gchar *mime_type,
									  gpointer ud,
									  ev_tstamp timeout)
{
	return rspamd_http_connection_write_message_common (conn, msg, host, mime_type,
			ud, timeout, FALSE);
}

gboolean
rspamd_http_connection_write_message_shared (struct rspamd_http_connection *conn,
											 struct rspamd_http_message *msg,
											 const gchar *host,
											 const gchar *mime_type,
											 gpointer ud,
											 ev_tstamp timeout)
{
	return rspamd_http_connection_write_message_common (conn, msg, host, mime_type,
			ud, timeout, TRUE);
}


void
rspamd_http_connection_set_max_size (struct rspamd_http_connection *conn,
		gsize sz)
{
	conn->max_size = sz;
}

void
rspamd_http_connection_set_key (struct rspamd_http_connection *conn,
		struct rspamd_cryptobox_keypair *key)
{
	struct rspamd_http_connection_private *priv = conn->priv;

	g_assert (key != NULL);
	priv->local_key = rspamd_keypair_ref (key);
}

void
rspamd_http_connection_own_socket (struct rspamd_http_connection *conn)
{
	struct rspamd_http_connection_private *priv = conn->priv;

	priv->flags |= RSPAMD_HTTP_CONN_OWN_SOCKET;
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