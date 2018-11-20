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
#include "keypair.h"
#include "keypairs_cache.h"
#include "fstring.h"
#include "ref.h"

enum rspamd_http_connection_type {
	RSPAMD_HTTP_SERVER,
	RSPAMD_HTTP_CLIENT
};

struct rspamd_http_header;
struct rspamd_http_message;
struct rspamd_http_connection_private;
struct rspamd_http_connection;
struct rspamd_http_connection_router;
struct rspamd_http_connection_entry;

struct rspamd_storage_shmem {
	gchar *shm_name;
	ref_entry_t ref;
};

/**
 * Legacy spamc protocol
 */
#define RSPAMD_HTTP_FLAG_SPAMC (1 << 0)
/**
 * Store body of the message in a shared memory segment
 */
#define RSPAMD_HTTP_FLAG_SHMEM (1 << 2)
/**
 * Store body of the message in an immutable shared memory segment
 */
#define RSPAMD_HTTP_FLAG_SHMEM_IMMUTABLE (1 << 3)
/**
 * Use tls for this message
 */
#define RSPAMD_HTTP_FLAG_SSL (1 << 4)
/**
 * Body has been set for a message
 */
#define RSPAMD_HTTP_FLAG_HAS_BODY (1 << 5)
/**
 * Do not verify server's certificate
 */
#define RSPAMD_HTTP_FLAG_SSL_NOVERIFY (1 << 6)
/**
 * Options for HTTP connection
 */
enum rspamd_http_options {
	RSPAMD_HTTP_BODY_PARTIAL = 0x1, /**< Call body handler on all body data portions *///!< RSPAMD_HTTP_BODY_PARTIAL
	RSPAMD_HTTP_CLIENT_SIMPLE = 0x1u << 1, /**< Read HTTP client reply automatically */      //!< RSPAMD_HTTP_CLIENT_SIMPLE
	RSPAMD_HTTP_CLIENT_ENCRYPTED = 0x1u << 2, /**< Encrypt data for client */                //!< RSPAMD_HTTP_CLIENT_ENCRYPTED
	RSPAMD_HTTP_CLIENT_SHARED = 0x1u << 3, /**< Store reply in shared memory */              //!< RSPAMD_HTTP_CLIENT_SHARED
	RSPAMD_HTTP_REQUIRE_ENCRYPTION = 0x1u << 4
};

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
	gsize max_size;
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
	gboolean support_gzip;
	struct rspamd_http_connection_entry *prev, *next;
};

struct rspamd_http_connection_router {
	struct rspamd_http_connection_entry *conns;
	GHashTable *paths;
	GHashTable *response_headers;
	GPtrArray *regexps;
	struct timeval tv;
	struct timeval *ptv;
	struct event_base *ev_base;
	struct rspamd_keypair_cache *cache;
	gchar *default_fs_path;
	rspamd_http_router_handler_t unknown_method_handler;
	struct rspamd_cryptobox_keypair *key;
	rspamd_http_router_error_handler_t error_handler;
	rspamd_http_router_finish_handler_t finish_handler;
};

/**
 * Create new http connection
 * @param handler_t handler_t for body
 * @param opts options
 * @return new connection structure
 */
struct rspamd_http_connection *rspamd_http_connection_new (
		rspamd_http_body_handler_t body_handler,
		rspamd_http_error_handler_t error_handler,
		rspamd_http_finish_handler_t finish_handler,
		unsigned opts,
		enum rspamd_http_connection_type type,
		struct rspamd_keypair_cache *cache,
		gpointer ssl_ctx);


/**
 * Set key pointed by an opaque pointer
 * @param conn connection structure
 * @param key opaque key structure
 */
void rspamd_http_connection_set_key (struct rspamd_http_connection *conn,
		struct rspamd_cryptobox_keypair *key);

/**
 * Get peer's public key
 * @param conn connection structure
 * @return pubkey structure or NULL
 */
const struct rspamd_cryptobox_pubkey* rspamd_http_connection_get_peer_key (
		struct rspamd_http_connection *conn);

/**
 * Returns TRUE if a connection is encrypted
 * @param conn
 * @return
 */
gboolean rspamd_http_connection_is_encrypted (struct rspamd_http_connection *conn);

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

void rspamd_http_connection_read_message_shared (
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

void rspamd_http_connection_write_message_shared (
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
 * Extract the current message from a connection to deal with separately
 * @param conn
 * @return
 */
struct rspamd_http_message * rspamd_http_connection_steal_msg (
		struct rspamd_http_connection *conn);

/**
 * Copy the current message from a connection to deal with separately
 * @param conn
 * @return
 */
struct rspamd_http_message * rspamd_http_connection_copy_msg (
		struct rspamd_http_message *msg, GError **err);

/**
 * Create new HTTP message
 * @param type request or response
 * @return new http message
 */
struct rspamd_http_message * rspamd_http_new_message (enum http_parser_type type);

/**
 * Increase refcount number for an HTTP message
 * @param msg message to use
 * @return
 */
struct rspamd_http_message * rspamd_http_message_ref (struct rspamd_http_message *msg);
/**
 * Decrease number of refcounts for http message
 * @param msg
 */
void rspamd_http_message_unref (struct rspamd_http_message *msg);

/**
 * Sets a key for peer
 * @param msg
 * @param pk
 */
void rspamd_http_message_set_peer_key (struct rspamd_http_message *msg,
		struct rspamd_cryptobox_pubkey *pk);
/**
 * Create HTTP message from URL
 * @param url
 * @return new message or NULL
 */
struct rspamd_http_message* rspamd_http_message_from_url (const gchar *url);

/**
 * Returns body for a message
 * @param msg
 * @param blen pointer where to save body length
 * @return pointer to body start
 */
const gchar *rspamd_http_message_get_body (struct rspamd_http_message *msg,
		gsize *blen);

/**
 * Set message's body from the string
 * @param msg
 * @param data
 * @param len
 * @return TRUE if a message's body has been set
 */
gboolean rspamd_http_message_set_body (struct rspamd_http_message *msg,
		const gchar *data, gsize len);

/**
 * Set message's method by name
 * @param msg
 * @param method
 */
void rspamd_http_message_set_method (struct rspamd_http_message *msg,
		const gchar *method);
/**
 * Maps fd as message's body
 * @param msg
 * @param fd
 * @return TRUE if a message's body has been set
 */
gboolean rspamd_http_message_set_body_from_fd (struct rspamd_http_message *msg,
		gint fd);

/**
 * Uses rspamd_fstring_t as message's body, string is consumed by this operation
 * @param msg
 * @param fstr
 * @return TRUE if a message's body has been set
 */
gboolean rspamd_http_message_set_body_from_fstring_steal (struct rspamd_http_message *msg,
		rspamd_fstring_t *fstr);

/**
 * Uses rspamd_fstring_t as message's body, string is copied by this operation
 * @param msg
 * @param fstr
 * @return TRUE if a message's body has been set
 */
gboolean rspamd_http_message_set_body_from_fstring_copy (struct rspamd_http_message *msg,
		const rspamd_fstring_t *fstr);

/**
 * Appends data to message's body
 * @param msg
 * @param data
 * @param len
 * @return TRUE if a message's body has been set
 */
gboolean rspamd_http_message_append_body (struct rspamd_http_message *msg,
		const gchar *data, gsize len);

/**
 * Append a header to http message
 * @param rep
 * @param name
 * @param value
 */
void rspamd_http_message_add_header (struct rspamd_http_message *msg,
		const gchar *name,
		const gchar *value);

void rspamd_http_message_add_header_len (struct rspamd_http_message *msg,
		const gchar *name,
		const gchar *value,
		gsize len);

void rspamd_http_message_add_header_fstr (struct rspamd_http_message *msg,
		const gchar *name,
		rspamd_fstring_t *value);

/**
 * Search for a specified header in message
 * @param msg message
 * @param name name of header
 */
const rspamd_ftok_t * rspamd_http_message_find_header (
		struct rspamd_http_message *msg,
		const gchar *name);

/**
 * Search for a header that has multiple values
 * @param msg
 * @param name
 * @return list of rspamd_ftok_t * with values
 */
GPtrArray* rspamd_http_message_find_header_multiple (
		struct rspamd_http_message *msg,
		const gchar *name);

/**
 * Remove specific header from a message
 * @param msg
 * @param name
 * @return
 */
gboolean rspamd_http_message_remove_header (struct rspamd_http_message *msg,
		const gchar *name);

/**
 * Free HTTP message
 * @param msg
 */
void rspamd_http_message_free (struct rspamd_http_message *msg);

/**
 * Sets global maximum size for HTTP message being processed
 * @param sz
 */
void rspamd_http_connection_set_max_size (struct rspamd_http_connection *conn,
		gsize sz);

void rspamd_http_connection_disable_encryption (struct rspamd_http_connection *conn);

/**
 * Increase refcount for shared file (if any) to prevent early memory unlinking
 * @param msg
 */
struct rspamd_storage_shmem* rspamd_http_message_shmem_ref (struct rspamd_http_message *msg);
/**
 * Decrease external ref for shmem segment associated with a message
 * @param msg
 */
void rspamd_http_message_shmem_unref (struct rspamd_storage_shmem *p);

/**
 * Returns message's flags
 * @param msg
 * @return
 */
guint rspamd_http_message_get_flags (struct rspamd_http_message *msg);

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
		struct rspamd_cryptobox_keypair *key);

/**
 * Add new path to the router
 */
void rspamd_http_router_add_path (struct rspamd_http_connection_router *router,
		const gchar *path, rspamd_http_router_handler_t handler);

/**
 * Add custom header to append to router replies
 * @param router
 * @param name
 * @param value
 */
void rspamd_http_router_add_header (struct rspamd_http_connection_router *router,
		const gchar *name, const gchar *value);

/**
 * Sets method to handle unknown request methods
 * @param router
 * @param handler
 */
void rspamd_http_router_set_unknown_handler (struct rspamd_http_connection_router *router,
		rspamd_http_router_handler_t handler);

/**
 * Inserts router headers to the outbound message
 * @param router
 * @param msg
 */
void rspamd_http_router_insert_headers (struct rspamd_http_connection_router *router,
		struct rspamd_http_message *msg);

struct rspamd_regexp_s;
/**
 * Adds new pattern to router, regexp object is refcounted by this function
 * @param router
 * @param re
 * @param handler
 */
void rspamd_http_router_add_regexp (struct rspamd_http_connection_router *router,
		struct rspamd_regexp_s *re, rspamd_http_router_handler_t handler);
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

/**
 * Extract arguments from a message's URI contained inside query string decoding
 * them if needed
 * @param msg HTTP request message
 * @return new GHashTable which maps rspamd_ftok_t* to rspamd_ftok_t*
 * (table must be freed by a caller)
 */
GHashTable* rspamd_http_message_parse_query (struct rspamd_http_message *msg);

/**
 * Prints HTTP date from `time` to `buf` using standard HTTP date format
 * @param buf date buffer
 * @param len length of buffer
 * @param time time in unix seconds
 * @return number of bytes written
 */
glong rspamd_http_date_format (gchar *buf, gsize len, time_t time);

/**
 * Normalize HTTP path removing dot sequences and repeating '/' symbols as
 * per rfc3986#section-5.2
 * @param path
 * @param len
 * @param nlen
 */
void rspamd_http_normalize_path_inplace (gchar *path, guint len, guint *nlen);

#endif /* HTTP_H_ */
