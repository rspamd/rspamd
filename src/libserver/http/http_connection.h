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
 * This is an interface for HTTP client and conn.
 * This code uses HTTP parser written by Joyent Inc based on nginx code.
 */

#include "config.h"
#include "http_context.h"
#include "fstring.h"
#include "ref.h"
#include "http_message.h"
#include "http_util.h"
#include "addr.h"

#include "contrib/libev/ev.h"

#ifdef  __cplusplus
extern "C" {
#endif

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
struct rspamd_keepalive_hash_key;

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
 * Body has been set for a message
 */
#define RSPAMD_HTTP_FLAG_HAS_HOST_HEADER (1 << 7)
/**
 * Options for HTTP connection
 */
enum rspamd_http_options {
	RSPAMD_HTTP_BODY_PARTIAL = 1, /**< Call body handler on all body data portions */
	RSPAMD_HTTP_CLIENT_SIMPLE = 1u << 1, /**< Read HTTP client reply automatically */
	RSPAMD_HTTP_CLIENT_ENCRYPTED = 1u << 2, /**< Encrypt data for client */
	RSPAMD_HTTP_CLIENT_SHARED = 1u << 3, /**< Store reply in shared memory */
	RSPAMD_HTTP_REQUIRE_ENCRYPTION = 1u << 4,
	RSPAMD_HTTP_CLIENT_KEEP_ALIVE = 1u << 5,
};

typedef int (*rspamd_http_body_handler_t) (struct rspamd_http_connection *conn,
										   struct rspamd_http_message *msg,
										   const gchar *chunk,
										   gsize len);

typedef void (*rspamd_http_error_handler_t) (struct rspamd_http_connection *conn,
											 GError *err);

typedef int (*rspamd_http_finish_handler_t) (struct rspamd_http_connection *conn,
											 struct rspamd_http_message *msg);

/**
 * HTTP connection structure
 */
struct rspamd_http_connection {
	struct rspamd_http_connection_private *priv;
	rspamd_http_body_handler_t body_handler;
	rspamd_http_error_handler_t error_handler;
	rspamd_http_finish_handler_t finish_handler;
	gpointer ud;
	const gchar *log_tag;
	/* Used for keepalive */
	struct rspamd_keepalive_hash_key *keepalive_hash_key;
	gsize max_size;
	unsigned opts;
	enum rspamd_http_connection_type type;
	gboolean finished;
	gint fd;
	gint ref;
};

/**
 * Creates a new HTTP server connection from an opened FD returned by accept function
 * @param ctx
 * @param fd
 * @param body_handler
 * @param error_handler
 * @param finish_handler
 * @param opts
 * @return
 */
struct rspamd_http_connection *rspamd_http_connection_new_server (
		struct rspamd_http_context *ctx,
		gint fd,
		rspamd_http_body_handler_t body_handler,
		rspamd_http_error_handler_t error_handler,
		rspamd_http_finish_handler_t finish_handler,
		unsigned opts);

/**
 * Creates or reuses a new keepalive client connection identified by hostname and inet_addr
 * @param ctx
 * @param body_handler
 * @param error_handler
 * @param finish_handler
 * @param addr
 * @param host
 * @return
 */
struct rspamd_http_connection *rspamd_http_connection_new_keepalive (
		struct rspamd_http_context *ctx,
		rspamd_http_body_handler_t body_handler,
		rspamd_http_error_handler_t error_handler,
		rspamd_http_finish_handler_t finish_handler,
		rspamd_inet_addr_t *addr,
		const gchar *host);

/**
 * Creates an ordinary connection using the address specified (if proxy is not set)
 * @param ctx
 * @param body_handler
 * @param error_handler
 * @param finish_handler
 * @param opts
 * @param addr
 * @return
 */
struct rspamd_http_connection *rspamd_http_connection_new_client (
		struct rspamd_http_context *ctx,
		rspamd_http_body_handler_t body_handler,
		rspamd_http_error_handler_t error_handler,
		rspamd_http_finish_handler_t finish_handler,
		unsigned opts,
		rspamd_inet_addr_t *addr);

/**
 * Creates an ordinary client connection using ready file descriptor (ignores proxy)
 * @param ctx
 * @param body_handler
 * @param error_handler
 * @param finish_handler
 * @param opts
 * @param addr
 * @return
 */
struct rspamd_http_connection *rspamd_http_connection_new_client_socket (
		struct rspamd_http_context *ctx,
		rspamd_http_body_handler_t body_handler,
		rspamd_http_error_handler_t error_handler,
		rspamd_http_finish_handler_t finish_handler,
		unsigned opts,
		gint fd);

/**
 * Set key pointed by an opaque pointer
 * @param conn connection structure
 * @param key opaque key structure
 */
void rspamd_http_connection_set_key (struct rspamd_http_connection *conn,
									 struct rspamd_cryptobox_keypair *key);

/**
 * Transfer ownership on socket to an HTTP connection
 * @param conn
 */
void rspamd_http_connection_own_socket (struct rspamd_http_connection *conn);

/**
 * Get peer's public key
 * @param conn connection structure
 * @return pubkey structure or NULL
 */
const struct rspamd_cryptobox_pubkey *rspamd_http_connection_get_peer_key (
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
		ev_tstamp timeout);

void rspamd_http_connection_read_message_shared (
		struct rspamd_http_connection *conn,
		gpointer ud,
		ev_tstamp timeout);

/**
 * Send reply using initialised connection
 * @param conn connection structure
 * @param msg HTTP message
 * @param ud opaque user data
 * @param fd fd to read/write
 */
gboolean rspamd_http_connection_write_message (
		struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg,
		const gchar *host,
		const gchar *mime_type,
		gpointer ud,
		ev_tstamp timeout);

gboolean rspamd_http_connection_write_message_shared (
		struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg,
		const gchar *host,
		const gchar *mime_type,
		gpointer ud,
		ev_tstamp timeout);

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
rspamd_http_connection_ref (struct rspamd_http_connection *conn) {
	conn->ref++;
	return conn;
}

/**
 * Decrease a refcount for a connection and free it if refcount is equal to zero
 * @param conn
 */
static void
rspamd_http_connection_unref (struct rspamd_http_connection *conn) {
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
 * Sets global maximum size for HTTP message being processed
 * @param sz
 */
void rspamd_http_connection_set_max_size (struct rspamd_http_connection *conn,
										  gsize sz);

void rspamd_http_connection_disable_encryption (struct rspamd_http_connection *conn);

#ifdef  __cplusplus
}
#endif

#endif /* HTTP_H_ */
