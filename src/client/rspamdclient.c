/*
 * Copyright 2025 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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
#include "libserver/multipart_form.h"
#include "libmime/content_type.h"
#include "ottery.h"
#include "unix-std.h"

#ifdef SYS_ZSTD
#include "zstd.h"
#else
#include "contrib/zstd/zstd.h"
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
	int fd;
	GString *server_name;
	struct rspamd_cryptobox_pubkey *key;
	struct rspamd_cryptobox_keypair *keypair;
	struct ev_loop *event_loop;
	ev_tstamp timeout;
	struct rspamd_http_connection *http_conn;
	gboolean req_sent;
	gboolean v3_mode;
	double start_time;
	double send_time;
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

#define RCLIENT_ERROR rspamd_client_error_quark()
GQuark
rspamd_client_error_quark(void)
{
	return g_quark_from_static_string("rspamd-client-error");
}

static void
rspamd_client_request_free(struct rspamd_client_request *req)
{
	if (req != NULL) {
		if (req->conn) {
			req->conn->req = NULL;
		}
		if (req->input) {
			g_string_free(req->input, TRUE);
		}

		g_free(req);
	}
}

static int
rspamd_client_body_handler(struct rspamd_http_connection *conn,
						   struct rspamd_http_message *msg,
						   const char *chunk, gsize len)
{
	/* Do nothing here */
	return 0;
}

static void
rspamd_client_error_handler(struct rspamd_http_connection *conn, GError *err)
{
	struct rspamd_client_request *req =
		(struct rspamd_client_request *) conn->ud;
	struct rspamd_client_connection *c;

	c = req->conn;
	req->cb(c, NULL, c->server_name->str, NULL,
			req->input, req->ud,
			c->start_time, c->send_time, NULL, 0, err);
}

static int
rspamd_client_v3_finish_handler(struct rspamd_http_connection *conn,
								struct rspamd_http_message *msg);

static int
rspamd_client_finish_handler(struct rspamd_http_connection *conn,
							 struct rspamd_http_message *msg)
{
	struct rspamd_client_request *req =
		(struct rspamd_client_request *) conn->ud;
	struct rspamd_client_connection *c;
	struct ucl_parser *parser;
	GError *err;
	const rspamd_ftok_t *tok;
	const char *start, *body = NULL;
	unsigned char *out = NULL;
	gsize len, bodylen = 0;

	c = req->conn;

	if (c->v3_mode) {
		return rspamd_client_v3_finish_handler(conn, msg);
	}

	if (!c->req_sent) {
		c->req_sent = TRUE;
		c->send_time = rspamd_get_ticks(FALSE);
		rspamd_http_connection_reset(c->http_conn);
		rspamd_http_connection_read_message(c->http_conn,
											c->req,
											c->timeout);

		return 0;
	}
	else {
		if (rspamd_http_message_get_body(msg, NULL) == NULL || msg->code / 100 != 2) {
			err = g_error_new(RCLIENT_ERROR, msg->code, "HTTP error: %d, %.*s",
							  msg->code,
							  (int) msg->status->len, msg->status->str);
			req->cb(c, msg, c->server_name->str, NULL, req->input, req->ud,
					c->start_time, c->send_time, body, bodylen, err);
			g_error_free(err);

			return 0;
		}

		tok = rspamd_http_message_find_header(msg, COMPRESSION_HEADER);

		if (tok) {
			/* Need to uncompress */
			rspamd_ftok_t t;

			t.begin = "zstd";
			t.len = 4;

			if (rspamd_ftok_casecmp(tok, &t) == 0) {
				ZSTD_DStream *zstream;
				ZSTD_inBuffer zin;
				ZSTD_outBuffer zout;
				gsize outlen, r;

				zstream = ZSTD_createDStream();
				ZSTD_initDStream(zstream);

				zin.pos = 0;
				zin.src = msg->body_buf.begin;
				zin.size = msg->body_buf.len;

				if ((outlen = ZSTD_getDecompressedSize(zin.src, zin.size)) == 0) {
					outlen = ZSTD_DStreamOutSize();
				}

				out = g_malloc(outlen);
				zout.dst = out;
				zout.pos = 0;
				zout.size = outlen;

				while (zin.pos < zin.size) {
					r = ZSTD_decompressStream(zstream, &zout, &zin);

					if (ZSTD_isError(r)) {
						err = g_error_new(RCLIENT_ERROR, 500,
										  "Decompression error: %s",
										  ZSTD_getErrorName(r));
						req->cb(c, msg, c->server_name->str, NULL,
								req->input, req->ud, c->start_time,
								c->send_time, body, bodylen, err);
						g_error_free(err);
						ZSTD_freeDStream(zstream);

						goto end;
					}

					if (zout.pos == zout.size) {
						/* We need to extend output buffer */
						zout.size = zout.size * 2;
						out = g_realloc(zout.dst, zout.size);
						zout.dst = out;
					}
				}

				ZSTD_freeDStream(zstream);

				start = zout.dst;
				len = zout.pos;
			}
			else {
				err = g_error_new(RCLIENT_ERROR, 500,
								  "Invalid compression method");
				req->cb(c, msg, c->server_name->str, NULL,
						req->input, req->ud, c->start_time, c->send_time,
						body, bodylen, err);
				g_error_free(err);

				return 0;
			}
		}
		else {
			start = msg->body_buf.begin;
			len = msg->body_buf.len;
		}

		/* Deal with body */
		tok = rspamd_http_message_find_header(msg, MESSAGE_OFFSET_HEADER);

		if (tok) {
			gulong value = 0;

			if (rspamd_strtoul(tok->begin, tok->len, &value) &&
				value < len) {
				body = start + value;
				bodylen = len - value;
				len = value;
			}
		}

		parser = ucl_parser_new(UCL_PARSER_SAFE_FLAGS);
		if (!ucl_parser_add_chunk_full(parser, start, len,
									   ucl_parser_get_default_priority(parser),
									   UCL_DUPLICATE_APPEND, UCL_PARSE_AUTO)) {
			err = g_error_new(RCLIENT_ERROR, msg->code, "Cannot parse UCL: %s",
							  ucl_parser_get_error(parser));
			ucl_parser_free(parser);
			req->cb(c, msg, c->server_name->str, NULL,
					req->input, req->ud,
					c->start_time, c->send_time, body, bodylen, err);
			g_error_free(err);

			goto end;
		}

		req->cb(c, msg, c->server_name->str,
				ucl_parser_get_object(parser),
				req->input, req->ud,
				c->start_time, c->send_time, body, bodylen, NULL);
		ucl_parser_free(parser);
	}

end:
	if (out) {
		g_free(out);
	}

	return 0;
}

struct rspamd_client_connection *
rspamd_client_init(struct rspamd_http_context *http_ctx,
				   struct ev_loop *ev_base, const char *name,
				   uint16_t port, double timeout, const char *key)
{
	struct rspamd_client_connection *conn;
	int fd;

	fd = rspamd_socket(name, port, SOCK_STREAM, TRUE, FALSE, TRUE);

	if (fd == -1) {
		return NULL;
	}

	conn = g_malloc0(sizeof(struct rspamd_client_connection));
	conn->event_loop = ev_base;
	conn->fd = fd;
	conn->req_sent = FALSE;
	conn->http_conn = rspamd_http_connection_new_client_socket(http_ctx,
															   rspamd_client_body_handler,
															   rspamd_client_error_handler,
															   rspamd_client_finish_handler,
															   0,
															   fd);

	if (!conn->http_conn) {
		rspamd_client_destroy(conn);
		return NULL;
	}

	/* Pass socket ownership */
	rspamd_http_connection_own_socket(conn->http_conn);
	conn->server_name = g_string_new(name);

	if (port != 0) {
		rspamd_printf_gstring(conn->server_name, ":%d", (int) port);
	}

	conn->timeout = timeout;

	if (key) {
		conn->key = rspamd_pubkey_from_base32(key, 0, RSPAMD_KEYPAIR_KEX);

		if (conn->key) {
			conn->keypair = rspamd_keypair_new(RSPAMD_KEYPAIR_KEX);
			rspamd_http_connection_set_key(conn->http_conn, conn->keypair);
		}
		else {
			rspamd_client_destroy(conn);
			return NULL;
		}
	}

	return conn;
}

gboolean
rspamd_client_command(struct rspamd_client_connection *conn,
					  const char *command, GQueue *attrs,
					  FILE *in, rspamd_client_callback cb,
					  gpointer ud, gboolean compressed,
					  const char *comp_dictionary,
					  const char *filename,
					  GError **err)
{
	struct rspamd_client_request *req;
	struct rspamd_http_client_header *nh;
	char *p;
	gsize remain, old_len;
	GList *cur;
	GString *input = NULL;
	rspamd_fstring_t *body;
	unsigned int dict_id = 0;
	gsize dict_len = 0;
	void *dict = NULL;
	ZSTD_CCtx *zctx;
	gboolean ret;

	req = g_malloc0(sizeof(struct rspamd_client_request));
	req->conn = conn;
	req->cb = cb;
	req->ud = ud;

	req->msg = rspamd_http_new_message(HTTP_REQUEST);
	if (conn->key) {
		req->msg->peer_key = rspamd_pubkey_ref(conn->key);
	}

	if (in != NULL) {
		/* Read input stream */
		input = g_string_sized_new(BUFSIZ);

		while (!feof(in)) {
			p = input->str + input->len;
			remain = input->allocated_len - input->len - 1;
			if (remain == 0) {
				old_len = input->len;
				g_string_set_size(input, old_len * 2);
				input->len = old_len;
				continue;
			}
			remain = fread(p, 1, remain, in);
			if (remain > 0) {
				input->len += remain;
				input->str[input->len] = '\0';
			}
		}
		if (ferror(in) != 0) {
			g_set_error(err, RCLIENT_ERROR, ferror(in), "input IO error: %s", strerror(ferror(in)));
			g_free(req);
			g_string_free(input, TRUE);
			return FALSE;
		}

		if (!compressed) {
			/* Detect zstd input */
			if (input->len > 4 && memcmp(input->str, "\x28\xb5\x2f\xfd", 4) == 0) {
				compressed = TRUE;
			}
			body = rspamd_fstring_new_init(input->str, input->len);
		}
		else {
			if (comp_dictionary) {
				dict = rspamd_file_xmap(comp_dictionary, PROT_READ, &dict_len,
										TRUE);

				if (dict == NULL) {
					g_set_error(err, RCLIENT_ERROR, errno,
								"cannot open dictionary %s: %s",
								comp_dictionary,
								strerror(errno));
					g_free(req);
					g_string_free(input, TRUE);

					return FALSE;
				}

				dict_id = -1;
			}

			body = rspamd_fstring_sized_new(ZSTD_compressBound(input->len));
			zctx = ZSTD_createCCtx();
			body->len = ZSTD_compress_usingDict(zctx, body->str, body->allocated,
												input->str, input->len,
												dict, dict_len,
												1);

			munmap(dict, dict_len);

			if (ZSTD_isError(body->len)) {
				g_set_error(err, RCLIENT_ERROR, ferror(in), "compression error");
				g_free(req);
				g_string_free(input, TRUE);
				rspamd_fstring_free(body);
				ZSTD_freeCCtx(zctx);

				return FALSE;
			}

			ZSTD_freeCCtx(zctx);
		}

		rspamd_http_message_set_body_from_fstring_steal(req->msg, body);
		req->input = input;
	}
	else {
		req->input = NULL;
	}

	/* Convert headers */
	cur = attrs->head;
	while (cur != NULL) {
		nh = cur->data;

		rspamd_http_message_add_header(req->msg, nh->name, nh->value);
		cur = g_list_next(cur);
	}

	if (compressed) {
		rspamd_http_message_add_header(req->msg, COMPRESSION_HEADER, "zstd");
		rspamd_http_message_add_header(req->msg, CONTENT_ENCODING_HEADER, "zstd");

		if (dict_id != 0) {
			char dict_str[32];

			rspamd_snprintf(dict_str, sizeof(dict_str), "%ud", dict_id);
			rspamd_http_message_add_header(req->msg, "Dictionary", dict_str);
		}
	}

	if (filename) {
		rspamd_http_message_add_header(req->msg, "Filename", filename);
	}

	/*
	 * Allow messagepack reply if supported
	 */
	rspamd_http_message_add_header(req->msg, "Accept", "application/msgpack");

	/* Append path ensuring a single leading slash */
	if (command != NULL && command[0] == '/') {
		req->msg->url = rspamd_fstring_append(req->msg->url, command, strlen(command));
	}
	else {
		req->msg->url = rspamd_fstring_append(req->msg->url, "/", 1);
		req->msg->url = rspamd_fstring_append(req->msg->url, command ? command : "", command ? strlen(command) : 0);
	}

	conn->req = req;
	conn->start_time = rspamd_get_ticks(FALSE);

	if (compressed) {
		ret = rspamd_http_connection_write_message(conn->http_conn, req->msg,
												   NULL, "application/x-compressed", req,
												   conn->timeout);
	}
	else {
		ret = rspamd_http_connection_write_message(conn->http_conn, req->msg,
												   NULL, "text/plain", req, conn->timeout);
	}

	return ret;
}

/*
 * V3 client: finish handler for multipart/mixed responses
 */
static int
rspamd_client_v3_finish_handler(struct rspamd_http_connection *conn,
								struct rspamd_http_message *msg)
{
	struct rspamd_client_request *req =
		(struct rspamd_client_request *) conn->ud;
	struct rspamd_client_connection *c;
	struct ucl_parser *parser;
	GError *err;
	const char *start, *body = NULL;
	gsize len, bodylen = 0;

	c = req->conn;

	if (!c->req_sent) {
		c->req_sent = TRUE;
		c->send_time = rspamd_get_ticks(FALSE);
		rspamd_http_connection_reset(c->http_conn);
		rspamd_http_connection_read_message(c->http_conn, c->req, c->timeout);
		return 0;
	}

	if (rspamd_http_message_get_body(msg, NULL) == NULL || msg->code / 100 != 2) {
		err = g_error_new(RCLIENT_ERROR, msg->code, "HTTP error: %d, %.*s",
						  msg->code,
						  (int) msg->status->len, msg->status->str);
		req->cb(c, msg, c->server_name->str, NULL, req->input, req->ud,
				c->start_time, c->send_time, NULL, 0, err);
		g_error_free(err);
		return 0;
	}

	/* Decompress whole-body compression (proxy may compress the entire response) */
	unsigned char *whole_body_decompressed = NULL;
	const char *resp_body = msg->body_buf.begin;
	gsize resp_body_len = msg->body_buf.len;

	const rspamd_ftok_t *comp_tok = rspamd_http_message_find_header(msg, COMPRESSION_HEADER);
	if (comp_tok) {
		rspamd_ftok_t zstd_tok;
		zstd_tok.begin = "zstd";
		zstd_tok.len = 4;

		if (rspamd_ftok_casecmp(comp_tok, &zstd_tok) == 0) {
			ZSTD_DStream *zstream = ZSTD_createDStream();
			ZSTD_initDStream(zstream);
			ZSTD_inBuffer zin;
			zin.src = msg->body_buf.begin;
			zin.size = msg->body_buf.len;
			zin.pos = 0;
			gsize outlen = ZSTD_getDecompressedSize(zin.src, zin.size);
			if (outlen == 0) {
				outlen = ZSTD_DStreamOutSize();
			}
			whole_body_decompressed = g_malloc(outlen);
			ZSTD_outBuffer zout;
			zout.dst = whole_body_decompressed;
			zout.size = outlen;
			zout.pos = 0;

			while (zin.pos < zin.size) {
				gsize r = ZSTD_decompressStream(zstream, &zout, &zin);
				if (ZSTD_isError(r)) {
					err = g_error_new(RCLIENT_ERROR, 500,
									  "Whole-body decompression error: %s",
									  ZSTD_getErrorName(r));
					req->cb(c, msg, c->server_name->str, NULL,
							req->input, req->ud, c->start_time,
							c->send_time, NULL, 0, err);
					g_error_free(err);
					g_free(whole_body_decompressed);
					ZSTD_freeDStream(zstream);
					return 0;
				}
				if (zout.pos == zout.size) {
					zout.size *= 2;
					whole_body_decompressed = g_realloc(zout.dst, zout.size);
					zout.dst = whole_body_decompressed;
				}
			}
			ZSTD_freeDStream(zstream);
			resp_body = (const char *) whole_body_decompressed;
			resp_body_len = zout.pos;
		}
	}

	/* Check if response is multipart/mixed */
	const rspamd_ftok_t *ct = rspamd_http_message_find_header(msg, "Content-Type");

	if (ct && rspamd_substring_search_caseless(ct->begin, ct->len,
											   "multipart/mixed", sizeof("multipart/mixed") - 1) != -1) {
		/* Parse multipart response to extract result and body */
		/* Extract boundary from Content-Type */
		struct rspamd_content_type *parsed_ct = rspamd_content_type_parse(
			ct->begin, ct->len, rspamd_mempool_new(256, "v3-client", 0));
		/* Note: we leak this small pool; acceptable for client-side */

		if (parsed_ct && parsed_ct->boundary.len > 0) {
			struct rspamd_multipart_form_c *form = rspamd_multipart_form_parse(
				resp_body, resp_body_len,
				parsed_ct->boundary.begin, parsed_ct->boundary.len);

			if (form) {
				const struct rspamd_multipart_entry_c *result_part =
					rspamd_multipart_form_find(form, "result", sizeof("result") - 1);

				if (result_part) {
					start = result_part->data;
					len = result_part->data_len;

					/* Check for per-part zstd compression */
					if (result_part->content_encoding &&
						result_part->content_encoding_len > 0 &&
						rspamd_substring_search_caseless(result_part->content_encoding,
														 result_part->content_encoding_len,
														 "zstd", 4) != -1) {
						/* Decompress */
						ZSTD_DStream *zstream = ZSTD_createDStream();
						ZSTD_initDStream(zstream);
						ZSTD_inBuffer zin = {start, len, 0};
						gsize outlen = ZSTD_getDecompressedSize(start, len);
						if (outlen == 0) outlen = ZSTD_DStreamOutSize();
						unsigned char *out = g_malloc(outlen);
						ZSTD_outBuffer zout = {out, outlen, 0};

						while (zin.pos < zin.size) {
							gsize r = ZSTD_decompressStream(zstream, &zout, &zin);
							if (ZSTD_isError(r)) {
								g_free(out);
								ZSTD_freeDStream(zstream);
								rspamd_multipart_form_free(form);
								err = g_error_new(RCLIENT_ERROR, 500,
												  "result decompression error: %s",
												  ZSTD_getErrorName(r));
								req->cb(c, msg, c->server_name->str, NULL,
										req->input, req->ud, c->start_time,
										c->send_time, NULL, 0, err);
								g_error_free(err);
								g_free(whole_body_decompressed);
								return 0;
							}
							if (zout.pos == zout.size) {
								zout.size *= 2;
								out = g_realloc(zout.dst, zout.size);
								zout.dst = out;
							}
						}
						ZSTD_freeDStream(zstream);
						start = (const char *) zout.dst;
						len = zout.pos;
						/* Note: out will be freed below via goto end pattern */
					}

					/* Extract optional body part */
					unsigned char *body_decompressed = NULL;
					const struct rspamd_multipart_entry_c *body_part =
						rspamd_multipart_form_find(form, "body", sizeof("body") - 1);
					if (body_part && body_part->data_len > 0) {
						body = body_part->data;
						bodylen = body_part->data_len;

						/* Decompress body part if needed */
						if (body_part->content_encoding &&
							body_part->content_encoding_len > 0 &&
							rspamd_substring_search_caseless(body_part->content_encoding,
															 body_part->content_encoding_len,
															 "zstd", 4) != -1) {
							ZSTD_DStream *bzstream = ZSTD_createDStream();
							ZSTD_initDStream(bzstream);
							ZSTD_inBuffer bzin = {body, bodylen, 0};
							gsize boutlen = ZSTD_getDecompressedSize(body, bodylen);
							if (boutlen == 0) boutlen = ZSTD_DStreamOutSize();
							body_decompressed = g_malloc(boutlen);
							ZSTD_outBuffer bzout = {body_decompressed, boutlen, 0};

							while (bzin.pos < bzin.size) {
								gsize r = ZSTD_decompressStream(bzstream, &bzout, &bzin);
								if (ZSTD_isError(r)) {
									g_free(body_decompressed);
									body_decompressed = NULL;
									ZSTD_freeDStream(bzstream);
									/* Non-fatal: pass compressed body as-is */
									body = body_part->data;
									bodylen = body_part->data_len;
									break;
								}
								if (bzout.pos == bzout.size) {
									bzout.size *= 2;
									body_decompressed = g_realloc(bzout.dst, bzout.size);
									bzout.dst = body_decompressed;
								}
							}
							if (body_decompressed) {
								ZSTD_freeDStream(bzstream);
								body = (const char *) bzout.dst;
								bodylen = bzout.pos;
							}
						}
					}

					parser = ucl_parser_new(UCL_PARSER_SAFE_FLAGS);
					/* Detect msgpack from content type */
					if (result_part->content_type &&
						rspamd_substring_search_caseless(result_part->content_type,
														 result_part->content_type_len,
														 "msgpack", 7) != -1) {
						ucl_parser_add_chunk_full(parser, (const unsigned char *) start, len,
												  ucl_parser_get_default_priority(parser),
												  UCL_DUPLICATE_APPEND, UCL_PARSE_MSGPACK);
					}
					else {
						ucl_parser_add_chunk(parser, (const unsigned char *) start, len);
					}

					if (ucl_parser_get_error(parser)) {
						err = g_error_new(RCLIENT_ERROR, msg->code,
										  "Cannot parse UCL: %s",
										  ucl_parser_get_error(parser));
						ucl_parser_free(parser);
						rspamd_multipart_form_free(form);
						req->cb(c, msg, c->server_name->str, NULL,
								req->input, req->ud, c->start_time,
								c->send_time, body, bodylen, err);
						g_error_free(err);
						g_free(body_decompressed);
						g_free(whole_body_decompressed);
						return 0;
					}

					req->cb(c, msg, c->server_name->str,
							ucl_parser_get_object(parser),
							req->input, req->ud,
							c->start_time, c->send_time, body, bodylen, NULL);
					ucl_parser_free(parser);
					g_free(body_decompressed);
				}
				else {
					err = g_error_new(RCLIENT_ERROR, 500,
									  "No 'result' part in multipart response");
					req->cb(c, msg, c->server_name->str, NULL,
							req->input, req->ud, c->start_time,
							c->send_time, NULL, 0, err);
					g_error_free(err);
				}

				rspamd_multipart_form_free(form);
			}
			else {
				err = g_error_new(RCLIENT_ERROR, 500,
								  "Cannot parse multipart response");
				req->cb(c, msg, c->server_name->str, NULL,
						req->input, req->ud, c->start_time,
						c->send_time, NULL, 0, err);
				g_error_free(err);
			}
		}
		else {
			err = g_error_new(RCLIENT_ERROR, 500,
							  "No boundary in multipart Content-Type");
			req->cb(c, msg, c->server_name->str, NULL,
					req->input, req->ud, c->start_time,
					c->send_time, NULL, 0, err);
			g_error_free(err);
		}
	}
	else {
		/* Fallback: non-multipart response, handle like v2 */
		start = resp_body;
		len = resp_body_len;

		parser = ucl_parser_new(UCL_PARSER_SAFE_FLAGS);
		if (!ucl_parser_add_chunk(parser, (const unsigned char *) start, len)) {
			err = g_error_new(RCLIENT_ERROR, msg->code, "Cannot parse UCL: %s",
							  ucl_parser_get_error(parser));
			ucl_parser_free(parser);
			req->cb(c, msg, c->server_name->str, NULL,
					req->input, req->ud, c->start_time,
					c->send_time, NULL, 0, err);
			g_error_free(err);
			g_free(whole_body_decompressed);
			return 0;
		}

		req->cb(c, msg, c->server_name->str,
				ucl_parser_get_object(parser),
				req->input, req->ud,
				c->start_time, c->send_time, NULL, 0, NULL);
		ucl_parser_free(parser);
	}

	g_free(whole_body_decompressed);
	return 0;
}

gboolean
rspamd_client_command_v3(struct rspamd_client_connection *conn,
						 const char *command,
						 const ucl_object_t *metadata,
						 FILE *in,
						 rspamd_client_callback cb,
						 gpointer ud,
						 gboolean compressed,
						 gboolean msgpack,
						 const char *filename,
						 GError **err)
{
	struct rspamd_client_request *req;
	GString *input = NULL;
	rspamd_fstring_t *body;
	gboolean ret;

	req = g_malloc0(sizeof(struct rspamd_client_request));
	req->conn = conn;
	req->cb = cb;
	req->ud = ud;

	req->msg = rspamd_http_new_message(HTTP_REQUEST);
	if (conn->key) {
		req->msg->peer_key = rspamd_pubkey_ref(conn->key);
	}

	/* Read message input */
	const char *msg_data = NULL;
	gsize msg_len = 0;

	if (in != NULL) {
		input = g_string_sized_new(BUFSIZ);
		char *p;
		gsize remain, old_len;

		while (!feof(in)) {
			p = input->str + input->len;
			remain = input->allocated_len - input->len - 1;
			if (remain == 0) {
				old_len = input->len;
				g_string_set_size(input, old_len * 2);
				input->len = old_len;
				continue;
			}
			remain = fread(p, 1, remain, in);
			if (remain > 0) {
				input->len += remain;
				input->str[input->len] = '\0';
			}
		}

		if (ferror(in) != 0) {
			g_set_error(err, RCLIENT_ERROR, ferror(in),
						"input IO error: %s", strerror(ferror(in)));
			g_free(req);
			g_string_free(input, TRUE);
			return FALSE;
		}

		msg_data = input->str;
		msg_len = input->len;
		req->input = input;
	}

	/* Serialize metadata to JSON or msgpack */
	char *metadata_buf = NULL;
	gsize metadata_len = 0;
	const char *metadata_ctype = "application/json";

	if (metadata) {
		if (msgpack) {
			size_t emit_len;
			metadata_buf = (char *) ucl_object_emit_len(metadata,
														UCL_EMIT_MSGPACK, &emit_len);
			metadata_len = emit_len;
			metadata_ctype = "application/msgpack";
		}
		else {
			metadata_buf = (char *) ucl_object_emit(metadata, UCL_EMIT_JSON_COMPACT);
			metadata_len = strlen(metadata_buf);
		}
	}
	else {
		if (msgpack) {
			/* Empty msgpack map: 0x80 */
			metadata_buf = g_malloc(1);
			metadata_buf[0] = '\x80';
			metadata_len = 1;
			metadata_ctype = "application/msgpack";
		}
		else {
			metadata_buf = g_strdup("{}");
			metadata_len = 2;
		}
	}

	/* Build multipart/form-data body with random boundary */
	char boundary_buf[64];
	rspamd_snprintf(boundary_buf, sizeof(boundary_buf),
					"rspamc-v3-%016xL-%016xL",
					ottery_rand_uint64(), ottery_rand_uint64());
	const char *boundary = boundary_buf;
	GString *mp_body = g_string_sized_new(metadata_len + msg_len + 512);

	/* Metadata part */
	rspamd_printf_gstring(mp_body,
						  "--%s\r\n"
						  "Content-Disposition: form-data; name=\"metadata\"\r\n"
						  "Content-Type: %s\r\n"
						  "\r\n",
						  boundary, metadata_ctype);
	g_string_append_len(mp_body, metadata_buf, metadata_len);
	g_string_append(mp_body, "\r\n");

	/* Message part */
	if (msg_data && msg_len > 0) {
		if (compressed) {
			/* Compress message with zstd */
			gsize comp_bound = ZSTD_compressBound(msg_len);
			char *comp_buf = g_malloc(comp_bound);
			gsize comp_len = ZSTD_compress(comp_buf, comp_bound,
										   msg_data, msg_len, 1);

			if (ZSTD_isError(comp_len)) {
				g_set_error(err, RCLIENT_ERROR, 500, "compression error");
				g_free(comp_buf);
				g_free(metadata_buf);
				g_string_free(mp_body, TRUE);
				g_free(req);
				if (input) g_string_free(input, TRUE);
				return FALSE;
			}

			rspamd_printf_gstring(mp_body,
								  "--%s\r\n"
								  "Content-Disposition: form-data; name=\"message\"\r\n"
								  "Content-Type: application/octet-stream\r\n"
								  "Content-Encoding: zstd\r\n"
								  "\r\n",
								  boundary);
			g_string_append_len(mp_body, comp_buf, comp_len);
			g_string_append(mp_body, "\r\n");
			g_free(comp_buf);
		}
		else {
			rspamd_printf_gstring(mp_body,
								  "--%s\r\n"
								  "Content-Disposition: form-data; name=\"message\"\r\n"
								  "Content-Type: application/octet-stream\r\n"
								  "\r\n",
								  boundary);
			g_string_append_len(mp_body, msg_data, msg_len);
			g_string_append(mp_body, "\r\n");
		}
	}

	/* Closing boundary */
	rspamd_printf_gstring(mp_body, "--%s--\r\n", boundary);

	g_free(metadata_buf);

	/* Set body */
	body = rspamd_fstring_new_init(mp_body->str, mp_body->len);
	g_string_free(mp_body, TRUE);
	rspamd_http_message_set_body_from_fstring_steal(req->msg, body);

	/* Set Content-Type with boundary */
	char ct_buf[128];
	rspamd_snprintf(ct_buf, sizeof(ct_buf),
					"multipart/form-data; boundary=%s", boundary);

	/* Add Accept headers */
	if (msgpack) {
		rspamd_http_message_add_header(req->msg, "Accept", "application/msgpack");
	}
	else {
		rspamd_http_message_add_header(req->msg, "Accept", "application/json");
	}
	if (compressed) {
		rspamd_http_message_add_header(req->msg, "Accept-Encoding", "zstd");
	}

	/* Append URL path */
	if (command != NULL && command[0] == '/') {
		req->msg->url = rspamd_fstring_append(req->msg->url, command, strlen(command));
	}
	else {
		req->msg->url = rspamd_fstring_append(req->msg->url, "/", 1);
		req->msg->url = rspamd_fstring_append(req->msg->url, command ? command : "",
											  command ? strlen(command) : 0);
	}

	conn->req = req;
	conn->v3_mode = TRUE;
	conn->start_time = rspamd_get_ticks(FALSE);

	ret = rspamd_http_connection_write_message(conn->http_conn, req->msg,
											   NULL, ct_buf, req, conn->timeout);

	return ret;
}

void rspamd_client_destroy(struct rspamd_client_connection *conn)
{
	if (conn != NULL) {
		if (conn->http_conn) {
			rspamd_http_connection_unref(conn->http_conn);
		}

		if (conn->req != NULL) {
			rspamd_client_request_free(conn->req);
		}

		if (conn->key) {
			rspamd_pubkey_unref(conn->key);
		}

		if (conn->keypair) {
			rspamd_keypair_unref(conn->keypair);
		}

		g_string_free(conn->server_name, TRUE);
		g_free(conn);
	}
}
