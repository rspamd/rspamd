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
#include "keypairs_cache.h"

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
	struct rspamd_http_header *next, *prev;
};

/**
 * Legacy spamc protocol
 */
#define RSPAMD_HTTP_FLAG_SPAMC 1 << 1

/**
 * HTTP message structure, used for requests and replies
 */
struct rspamd_http_message {
	GString *url;
	GString *host;
	unsigned port;
	GString *status;
	struct rspamd_http_header *headers;
	GString *body;
	GString body_buf;
	gpointer peer_key;
	enum http_parser_type type;
	time_t date;
	gint code;
	enum http_method method;
	gint flags;
};


/**
 * Options for HTTP connection
 */
enum rspamd_http_options {
	RSPAMD_HTTP_BODY_PARTIAL = 0x1, /**< Call body handler on all body data portions */
	RSPAMD_HTTP_CLIENT_SIMPLE = 0x2, /**< Read HTTP client reply automatically */
	RSPAMD_HTTP_CLIENT_ENCRYPTED = 0x4 /**< Encrypt data for client */
};

struct rspamd_http_connection_private;
struct rspamd_http_connection;
struct rspamd_http_connection_router;
struct rspamd_http_connection_entry;

typedef int (*rspamd_http_body_handler_t) (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg,
	const gchar *chunk,
	gsize len);

typedef void (*rspamd_http_error_handler_t) (struct rspamd_http_connection *conn,
	GError *err);

typedef int (*rspamd_http_finish_handler_t) (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg);

typedef int (*rspamd_http_router_handler_t) (struct rspamd_http_connection_entry
	*conn_ent,
	struct rspamd_http_message *msg);
typedef void (*rspamd_http_router_error_handler_t) (struct
	rspamd_http_connection_entry *conn_ent,
	GError *err);
typedef void (*rspamd_http_router_finish_handler_t) (struct
	rspamd_http_connection_entry *conn_ent);

/**
 * HTTP connection structure
 */
struct rspamd_http_connection {
	struct rspamd_http_connection_private *priv;
	rspamd_http_body_handler_t body_handler;
	rspamd_http_error_handler_t error_handler;
	rspamd_http_finish_handler_t finish_handler;
	struct rspamd_keypair_cache *cache;
	gpointer ud;
	unsigned opts;
	enum rspamd_http_connection_type type;
	gboolean finished;
	gint fd;
	gint ref;
};

struct rspamd_http_connection_entry {
	struct rspamd_http_connection_router *rt;
	struct rspamd_http_connection *conn;
	gpointer ud;
	gboolean is_reply;
	struct rspamd_http_connection_entry *next;
};

struct rspamd_http_connection_router {
	struct rspamd_http_connection_entry *conns;
	GHashTable *paths;
	struct timeval tv;
	struct timeval *ptv;
	struct event_base *ev_base;
	struct rspamd_keypair_cache *cache;
	gchar *default_fs_path;
	gpointer key;
	rspamd_http_router_error_handler_t error_handler;
	rspamd_http_router_finish_handler_t finish_handler;
};

/**
 * Create new http connection
 * @param handler_t handler_t for body
 * @param opts options
 * @return new connection structure
 */
struct rspamd_http_connection * rspamd_http_connection_new (
	rspamd_http_body_handler_t body_handler,
	rspamd_http_error_handler_t error_handler,
	rspamd_http_finish_handler_t finish_handler,
	unsigned opts,
	enum rspamd_http_connection_type type,
	struct rspamd_keypair_cache *cache);

/**
 * Load the encryption keypair
 * @param key base32 encoded privkey and pubkey (in that order)
 * @param keylen length of base32 string
 * @return opaque pointer pr NULL in case of error
 */
gpointer rspamd_http_connection_make_key (gchar *key, gsize keylen);

/**
 * Generate the encryption keypair
 * @return opaque pointer pr NULL in case of error
 */
gpointer rspamd_http_connection_gen_key (void);

/**
 * Set key pointed by an opaque pointer
 * @param conn connection structure
 * @param key opaque key structure
 */
void rspamd_http_connection_set_key (struct rspamd_http_connection *conn,
		gpointer key);

/**
 * Returns TRUE if a connection is encrypted
 * @param conn
 * @return
 */
gboolean rspamd_http_connection_is_encrypted (struct rspamd_http_connection *conn);

/** Print pubkey */
#define RSPAMD_KEYPAIR_PUBKEY 0x1
/** Print secret key */
#define RSPAMD_KEYPAIR_PRIVKEY 0x2
/** Print key id */
#define RSPAMD_KEYPAIR_ID 0x4
/** Encode output with base 32 */
#define RSPAMD_KEYPAIR_BASE32 0x8
/** Human readable output */
#define RSPAMD_KEYPAIR_HUMAN 0x16
/**
 * Print keypair encoding it if needed
 * @param key key to print
 * @param how flags that specifies printing behaviour
 * @return newly allocated string with keypair
 */
GString *rspamd_http_connection_print_key (gpointer key, guint how);

/**
 * Release key pointed by an opaque pointer
 * @param key opaque key structure
 */
void rspamd_http_connection_key_unref (gpointer key);

/**
 * Increase refcount for a key pointed by an opaque pointer
 * @param key opaque key structure
 */
gpointer rspamd_http_connection_key_ref (gpointer key);

gpointer rspamd_http_connection_make_peer_key (const gchar *key);

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
	const gchar *mime_type,
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
 * Increase refcount for a connection
 * @param conn
 * @return
 */
static inline struct rspamd_http_connection *
rspamd_http_connection_ref (struct rspamd_http_connection *conn)
{
	conn->ref++;
	return conn;
}

/**
 * Decrease a refcount for a connection and free it if refcount is equal to zero
 * @param conn
 */
static void
rspamd_http_connection_unref (struct rspamd_http_connection *conn)
{
	if (--conn->ref <= 0) {
		rspamd_http_connection_free (conn);
	}
}

/**
 * Reset connection for a new request
 * @param conn
 */
void rspamd_http_connection_reset (struct rspamd_http_connection *conn);

/**
 * Create new HTTP message
 * @param type request or response
 * @return new http message
 */
struct rspamd_http_message * rspamd_http_new_message (enum http_parser_type type);

/**
 * Create HTTP message from URL
 * @param url
 * @return new message or NULL
 */
struct rspamd_http_message* rspamd_http_message_from_url (const gchar *url);

/**
 * Append a header to reply
 * @param rep
 * @param name
 * @param value
 */
void rspamd_http_message_add_header (struct rspamd_http_message *rep,
	const gchar *name,
	const gchar *value);

/**
 * Search for a specified header in message
 * @param rep message
 * @param name name of header
 */
const gchar * rspamd_http_message_find_header (struct rspamd_http_message *rep,
	const gchar *name);

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

/**
 * Create new http connection router and the associated HTTP connection
 * @param eh error handler callback
 * @param fh finish handler callback
 * @param default_fs_path if not NULL try to serve static files from
 * the specified directory
 * @return
 */
struct rspamd_http_connection_router * rspamd_http_router_new (
	rspamd_http_router_error_handler_t eh,
	rspamd_http_router_finish_handler_t fh,
	struct timeval *timeout,
	struct event_base *base,
	const char *default_fs_path,
	struct rspamd_keypair_cache *cache);

/**
 * Set encryption key for the HTTP router
 * @param router router structure
 * @param key opaque key structure
 */
void rspamd_http_router_set_key (struct rspamd_http_connection_router *router,
		gpointer key);

/**
 * Add new path to the router
 */
void rspamd_http_router_add_path (struct rspamd_http_connection_router *router,
	const gchar *path, rspamd_http_router_handler_t handler);

/**
 * Handle new accepted socket
 * @param router router object
 * @param fd server socket
 * @param ud opaque userdata
 */
void rspamd_http_router_handle_socket (
	struct rspamd_http_connection_router *router,
	gint fd,
	gpointer ud);

/**
 * Free router and all connections associated
 * @param router
 */
void rspamd_http_router_free (struct rspamd_http_connection_router *router);

#endif /* HTTP_H_ */
