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
 * This is an interface for HTTP client and conn. This code uses HTTP parser written
 * by Joyent Inc based on nginx code.
 */

#include "config.h"
#include "http_parser.h"

enum rspamd_http_connection_type {
	RSPAMD_HTTP_SERVER,
	RSPAMD_HTTP_CLIENT
};

/**
 * HTTP header structure
 */
struct rspamd_http_header {
	GString *name;
	GString *value;
	struct rspamd_http_header *next;
};

/**
 * HTTP message structure, used for requests and replies
 */
struct rspamd_http_message {
	GString *url;
	struct rspamd_http_header *headers;
	GString *body;
	enum http_parser_type type;
	time_t date;
	gint code;
	enum http_method method;
};


/**
 * Options for HTTP connection
 */
enum rspamd_http_options {
	RSPAMD_HTTP_BODY_PARTIAL = 0x1//!< RSPAMD_HTTP_BODY_PARTIAL
};

struct rspamd_http_connection_private;
struct rspamd_http_connection;

typedef gboolean (*rspamd_http_body_handler) (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg,
		const gchar *chunk,
		gsize len);

typedef void (*rspamd_http_error_handler) (struct rspamd_http_connection *conn, GError *err);

typedef void (*rspamd_http_finish_handler) (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg);

/**
 * HTTP connection structure
 */
struct rspamd_http_connection {
	struct rspamd_http_connection_private *priv;
	rspamd_http_body_handler body_handler;
	rspamd_http_error_handler error_handler;
	rspamd_http_finish_handler finish_handler;
	gpointer ud;
	enum rspamd_http_options opts;
	enum rspamd_http_connection_type type;
	gint fd;
};

/**
 * Create new http connection
 * @param handler handler for body
 * @param opts options
 * @return new connection structure
 */
struct rspamd_http_connection* rspamd_http_connection_new (
		rspamd_http_body_handler body_handler,
		rspamd_http_error_handler error_handler,
		rspamd_http_finish_handler finish_handler,
		enum rspamd_http_options opts,
		enum rspamd_http_connection_type type);

/**
 * Handle a request using socket fd and user data ud
 * @param conn connection structure
 * @param ud opaque user data
 * @param fd fd to read/write
 */
void rspamd_http_connection_read_message (
		struct rspamd_http_connection *conn,
		gpointer ud,
		gint fd,
		struct timeval *timeout,
		struct event_base *base);

/**
 * Send reply using initialised connection
 * @param conn connection structure
 * @param msg HTTP message
 * @param ud opaque user data
 * @param fd fd to read/write
 */
void rspamd_http_connection_write_message (
		struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg,
		const gchar *host,
		gpointer ud,
		gint fd,
		struct timeval *timeout,
		struct event_base *base);

/**
 * Free connection structure
 * @param conn
 */
void rspamd_http_connection_free (struct rspamd_http_connection *conn);

/**
 * Reset connection for a new request
 * @param conn
 */
void rspamd_http_connection_reset (struct rspamd_http_connection *conn);

/**
 * Create new HTTP reply
 * @param code code to pass
 * @return new reply object
 */
struct rspamd_http_message* rspamd_http_new_message (enum http_parser_type type);

/**
 * Append a header to reply
 * @param rep
 * @param name
 * @param value
 */
void rspamd_http_message_add_header (struct rspamd_http_message *rep, const gchar *name, const gchar *value);

/**
 * Free HTTP reply
 * @param rep
 */
void rspamd_http_message_free (struct rspamd_http_message *msg);

/**
 * Parse HTTP date header and return it as time_t
 * @param header HTTP date header
 * @param len length of header
 * @return time_t or (time_t)-1 in case of error
 */
time_t rspamd_http_parse_date (const gchar *header, gsize len);

#endif /* HTTP_H_ */
