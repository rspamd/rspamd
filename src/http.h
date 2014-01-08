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

#ifndef HTTP_H_
#define HTTP_H_

/**
 * @file http.h
 *
 * This is an interface for HTTP client and server. This code uses HTTP parser written
 * by Joyent Inc based on nginx code.
 */

#include "config.h"
#include "http_parser.h"

/**
 * HTTP header structure
 */
struct rspamd_http_header {
	GString *name;
	GString *value;
	struct rspamd_http_header *next;
};

/**
 * HTTP request structure, used for requests
 */
struct rspamd_http_request {
	GString *url;
	struct rspamd_http_header *headers;
	GString *body;
	time_t date;
	gint code;
};

struct rspamd_http_reply {
	struct rspamd_http_header *headers;
	GString *body;
	gint code;
};

/**
 * Options for HTTP client and server
 */
enum rspamd_http_options {
	RSPAMD_HTTP_BODY_PARTIAL = 0x1//!< RSPAMD_HTTP_BODY_PARTIAL
};

struct rspamd_http_server_private;
struct rspamd_http_server;

typedef gboolean (*rspamd_http_body_handler) (struct rspamd_http_server *srv,
		struct rspamd_http_request *req,
		const gchar *chunk,
		gsize len);

typedef void (*rspamd_http_error_handler) (struct rspamd_http_server *srv, GError *err);

typedef void (*rspamd_http_reply_handler) (struct rspamd_http_server *srv,
		struct rspamd_http_reply *reply, GError *err);

/**
 * HTTP server structure
 */
struct rspamd_http_server {
	gint fd;
	struct rspamd_http_server_private *priv;
	enum rspamd_http_options opts;
	rspamd_http_body_handler body_handler;
	rspamd_http_error_handler error_handler;
	gpointer ud;
};

/**
 * Create new http server
 * @param handler handler for body
 * @param opts options
 * @return new server structure
 */
struct rspamd_http_server* rspamd_http_server_new (rspamd_http_body_handler body_handler,
		rspamd_http_error_handler error_handler,
		enum rspamd_http_options opts);

/**
 * Handle a request using socket fd and user data ud
 * @param server server structure
 * @param ud opaque user data
 * @param fd fd to read/write
 */
void rspamd_http_server_handle_request (struct rspamd_http_server *server, gpointer ud, gint fd,
		struct timeval *timeout, struct event_base *base);

/**
 * Send reply using initialised server
 * @param server server structure
 * @param reply HTTP reply
 * @return TRUE if request can be sent
 */
gboolean rspamd_http_server_write_reply (struct rspamd_http_server *server, struct rspamd_http_reply *reply,
		rspamd_http_reply_handler *handler);

/**
 * Free server structure
 * @param server
 */
void rspamd_http_server_free (struct rspamd_http_server *server);

/**
 * Reset server for a new request
 * @param server
 */
void rspamd_http_server_reset (struct rspamd_http_server *server);

/**
 * Create new HTTP reply
 * @param code code to pass
 * @return new reply object
 */
struct rspamd_http_reply * rspamd_http_new_reply (gint code);

/**
 * Append a header to reply
 * @param rep
 * @param name
 * @param value
 */
void rspamd_http_reply_add_header (struct rspamd_http_reply *rep, const gchar *name, const gchar *value);

/**
 * Free HTTP reply
 * @param rep
 */
void rspamd_http_reply_free (struct rspamd_http_reply *rep);

/**
 * Parse HTTP date header and return it as time_t
 * @param header HTTP date header
 * @param len length of header
 * @return time_t or (time_t)-1 in case of error
 */
time_t rspamd_http_parse_date (const gchar *header, gsize len);

#endif /* HTTP_H_ */
