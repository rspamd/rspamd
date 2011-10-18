/* Copyright (c) 2010, Vsevolod Stakhov
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
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#ifndef LIBKVSTORAGECLIENT_H_
#define LIBKVSTORAGECLIENT_H_

#include <glib.h>

/* Errors */
enum rspamd_kvstorage_error {
	KVSTORAGE_ERROR_OK = 0,
	KVSTORAGE_ERROR_TIMEOUT,
	KVSTORAGE_ERROR_NOT_EXIST,
	KVSTORAGE_ERROR_NOT_STORED,
	KVSTORAGE_ERROR_SERVER_ERROR,
	KVSTORAGE_ERROR_INTERNAL_ERROR
};

/* Forwarded definition */
struct rspamd_kvstorage_connection;

/* Callbacks for async API */
typedef void (*kvstorage_connect_cb) (enum rspamd_kvstorage_error code,
									struct rspamd_kvstorage_connection *conn, gpointer user_data);
typedef void (*kvstorage_read_cb) (enum rspamd_kvstorage_error code, const gpointer key,
									const gpointer value, gsize datalen, struct rspamd_kvstorage_connection *conn,
									gpointer user_data);
typedef void (*kvstorage_write_cb) (enum rspamd_kvstorage_error code, const gpointer key, struct rspamd_kvstorage_connection *conn,
									gpointer user_data);

/* Asynced API */

/**
 *  Create async connection with rspamd
 *  @param host hostname, ip or unix socket for a server
 *  @param port port number in host byte order
 *  @param tv timeout for operations
 *  @param cb callback
 *  @param ud user data for callback
 *  @param conn target connection
 */
enum rspamd_kvstorage_error rspamd_kvstorage_connect_async (const gchar *host,
		guint16 port, struct timeval *tv, kvstorage_connect_cb cb, gpointer ud,
		struct rspamd_kvstorage_connection **conn);

/**
 * Read key asynced
 * @param conn connection structure
 * @param key key to read
 * @param cb callback
 * @param ud user data for callback
 */
enum rspamd_kvstorage_error rspamd_kvstorage_get_async (struct rspamd_kvstorage_connection *conn,
		const gpointer key, kvstorage_read_cb cb, gpointer ud);

/**
 * Write key asynced
 * @param conn connection structure
 * @param key key to set
 * @param value data to write
 * @param cb callback
 * @param ud user data for callback
 */
enum rspamd_kvstorage_error rspamd_kvstorage_set_async (struct rspamd_kvstorage_connection *conn,
		const gpointer key, const gpointer value, gsize len, guint expire, kvstorage_write_cb cb, gpointer ud);

/**
 * Delete key asynced
 * @param conn connection structure
 * @param key key to delete
 * @param cb callback
 * @param ud user data for callback
 */
enum rspamd_kvstorage_error rspamd_kvstorage_delete_async (struct rspamd_kvstorage_connection *conn,
		const gpointer key, kvstorage_write_cb cb, gpointer ud);

/**
 * Close connection
 * @param conn connection structure
 */
enum rspamd_kvstorage_error rspamd_kvstorage_close_async (struct rspamd_kvstorage_connection *conn);

/* Synced API */
/**
 *  Create sync connection with rspamd
 *  @param host hostname, ip or unix socket for a server
 *  @param port port number in host byte order
 *  @param tv timeout for operations
 *  @param conn target connection
 */
enum rspamd_kvstorage_error rspamd_kvstorage_connect_sync (const gchar *host,
		guint16 port, struct timeval *tv,
		struct rspamd_kvstorage_connection **conn);

/**
 * Read key synced
 * @param conn connection structure
 * @param key key to read
 * @param value value readed
 */
enum rspamd_kvstorage_error rspamd_kvstorage_get_sync (struct rspamd_kvstorage_connection *conn,
		const gpointer key, gpointer **value);

/**
 * Write key synced
 * @param conn connection structure
 * @param key key to set
 * @param value data to write
 */
enum rspamd_kvstorage_error rspamd_kvstorage_set_sync (struct rspamd_kvstorage_connection *conn,
		const gpointer key, const gpointer value, gsize len, guint expire);

/**
 * Delete key synced
 * @param conn connection structure
 * @param key key to delete
 */
enum rspamd_kvstorage_error rspamd_kvstorage_delete_sync (struct rspamd_kvstorage_connection *conn,
		const gpointer key);

/**
 * Close connection
 * @param conn connection structure
 */
enum rspamd_kvstorage_error rspamd_kvstorage_close_sync (struct rspamd_kvstorage_connection *conn);

#endif /* LIBKVSTORAGECLIENT_H_ */
