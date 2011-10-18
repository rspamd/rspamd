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
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include "config.h"
#include "main.h"
#include "libkvstorageclient.h"

struct rspamd_kvstorage_connection {
	gboolean asynced;
	gint sock;
	struct timeval tv;
	enum {
		KV_STATE_NONE = 0,
		KV_STATE_CONNECTED,
		KV_STATE_SET,
		KV_STATE_GET,
		KV_STATE_WRITE_DATA,
		KV_STATE_READ_DATA,
		KV_STATE_READ_REPLY
	} state;
	struct event ev;
	kvstorage_connect_cb conn_cb;
	kvstorage_read_cb read_cb;
	kvstorage_write_cb write_cb;
	gpointer cur_ud;
	memory_pool_t *pool;
	gpointer cur_key;
	gpointer cur_value;
};

/* Callbacks for async API */
static void
rspamd_kvstorage_connect_cb (int fd, short what, gpointer ud)
{
	struct rspamd_kvstorage_connection		*c = ud;
	kvstorage_connect_cb                     cb;

	cb = (kvstorage_connect_cb)c->conn_cb;

	if (what == EV_TIMEOUT) {
		cb (KVSTORAGE_ERROR_TIMEOUT, c, c->cur_ud);
	}
	else {
		cb (KVSTORAGE_ERROR_OK, c, c->cur_ud);
	}
	c->state = KV_STATE_CONNECTED;
}

static void
rspamd_kvstorage_read_cb (int fd, short what, gpointer ud)
{
	struct rspamd_kvstorage_connection		*c = ud;
	kvstorage_read_cb                 		 cb;

	cb = (kvstorage_read_cb)c->read_cb;
}

static void
rspamd_kvstorage_write_cb (int fd, short what, gpointer ud)
{
	struct rspamd_kvstorage_connection		*c = ud;
	kvstorage_write_cb                       cb;

	cb = (kvstorage_write_cb)c->write_cb;
}

static void
rspamd_kvstorage_delete_cb (int fd, short what, gpointer ud)
{
	struct rspamd_kvstorage_connection		*c = ud;
	kvstorage_write_cb                       cb;

	cb = c->write_cb;
}

/**
 *  Create async connection with rspamd
 *  @param host hostname, ip or unix socket for a server
 *  @param port port number in host byte order
 *  @param tv timeout for operations
 *  @param cb callback
 *  @param ud user data for callback
 *  @param conn target connection
 */
enum rspamd_kvstorage_error
rspamd_kvstorage_connect_async (const gchar *host,
		guint16 port, struct timeval *tv, kvstorage_connect_cb cb, gpointer ud,
		struct rspamd_kvstorage_connection **conn)
{
	struct rspamd_kvstorage_connection		*new;
	gint									 sock;

	/* Here we do NOT try to resolve hostname */
	if ((sock = make_universal_stream_socket (host, port, TRUE, FALSE, FALSE)) == -1) {
		return KVSTORAGE_ERROR_SERVER_ERROR;
	}

	/* Allocate new connection structure */
	new = g_malloc (sizeof (struct rspamd_kvstorage_connection));

	/* Set fields */
	new->sock = sock;
	new->state = KV_STATE_NONE;
	new->asynced = TRUE;
	if (tv != NULL) {
		memcpy (&new->tv, tv, sizeof (struct timeval));
	}
	else {
		memset (&new->tv, 0, sizeof (struct timeval));
	}
	new->conn_cb = cb;
	new->cur_ud = ud;
	new->pool = memory_pool_new (memory_pool_get_size ());

	/* Set event */
	event_set (&new->ev, new->sock, EV_WRITE, rspamd_kvstorage_connect_cb, new);
	if (tv != NULL) {
		event_add (&new->ev, &new->tv);
	}
	else {
		event_add (&new->ev, NULL);
	}

	*conn = new;
	return KVSTORAGE_ERROR_OK;
}

/**
 * Read key asynced
 * @param conn connection structure
 * @param key key to read
 * @param cb callback
 * @param ud user data for callback
 */
enum rspamd_kvstorage_error
rspamd_kvstorage_get_async (struct rspamd_kvstorage_connection *conn,
		const gpointer key, kvstorage_read_cb cb, gpointer ud)
{
	if (conn == NULL || conn->state != KV_STATE_CONNECTED) {
		return KVSTORAGE_ERROR_INTERNAL_ERROR;
	}
	else {
		conn->read_cb = cb;
		conn->cur_ud = ud;
		conn->cur_key = memory_pool_strdup (conn->pool, key);
		conn->state = KV_STATE_GET;

		/* Set event */
		event_set (&conn->ev, conn->sock, EV_WRITE, rspamd_kvstorage_read_cb, conn);
		if (conn->tv.tv_sec != 0) {
			event_add (&conn->ev, &conn->tv);
		}
		else {
			event_add (&conn->ev, NULL);
		}
	}
	return KVSTORAGE_ERROR_OK;
}

/**
 * Write key asynced
 * @param conn connection structure
 * @param key key to set
 * @param value data to write
 * @param cb callback
 * @param ud user data for callback
 */
enum rspamd_kvstorage_error
rspamd_kvstorage_set_async (struct rspamd_kvstorage_connection *conn,
		const gpointer key, const gpointer value, gsize len, guint expire, kvstorage_write_cb cb, gpointer ud)
{
	if (conn == NULL || conn->state != KV_STATE_CONNECTED) {
		return KVSTORAGE_ERROR_INTERNAL_ERROR;
	}
	else {
		conn->write_cb = cb;
		conn->cur_ud = ud;
		conn->cur_key = memory_pool_strdup (conn->pool, key);
		conn->cur_value = value;
		conn->state = KV_STATE_SET;

		/* Set event */
		event_set (&conn->ev, conn->sock, EV_WRITE, rspamd_kvstorage_write_cb, conn);
		if (conn->tv.tv_sec != 0) {
			event_add (&conn->ev, &conn->tv);
		}
		else {
			event_add (&conn->ev, NULL);
		}
	}
	return KVSTORAGE_ERROR_OK;
}

/**
 * Delete key asynced
 * @param conn connection structure
 * @param key key to delete
 * @param cb callback
 * @param ud user data for callback
 */
enum rspamd_kvstorage_error
rspamd_kvstorage_delete_async (struct rspamd_kvstorage_connection *conn,
		const gpointer key, kvstorage_write_cb cb, gpointer ud)
{
	if (conn == NULL || conn->state != KV_STATE_CONNECTED) {
		return KVSTORAGE_ERROR_INTERNAL_ERROR;
	}
	else {
		conn->write_cb = cb;
		conn->cur_ud = ud;
		conn->cur_key = memory_pool_strdup (conn->pool, key);
		conn->state = KV_STATE_SET;

		/* Set event */
		event_set (&conn->ev, conn->sock, EV_WRITE, rspamd_kvstorage_delete_cb, conn);
		if (conn->tv.tv_sec != 0) {
			event_add (&conn->ev, &conn->tv);
		}
		else {
			event_add (&conn->ev, NULL);
		}
	}
	return KVSTORAGE_ERROR_OK;
}

/**
 * Close connection
 * @param conn connection structure
 */
enum rspamd_kvstorage_error
rspamd_kvstorage_close_async (struct rspamd_kvstorage_connection *conn)
{
	close (conn->sock);
	memory_pool_delete (conn->pool);
	event_del (&conn->ev);
	g_free (conn);

	return KVSTORAGE_ERROR_OK;
}

/* Synced API */
/**
 *  Create sync connection with rspamd
 *  @param host hostname, ip or unix socket for a server
 *  @param port port number in host byte order
 *  @param tv timeout for operations
 *  @param conn target connection
 */
enum rspamd_kvstorage_error
rspamd_kvstorage_connect_sync (const gchar *host,
		guint16 port, struct timeval *tv,
		struct rspamd_kvstorage_connection **conn)
{
	struct rspamd_kvstorage_connection		*new;
	gint									 sock;

	if ((sock = make_universal_stream_socket (host, port, FALSE, FALSE, TRUE)) == -1) {
		return KVSTORAGE_ERROR_INTERNAL_ERROR;
	}

	/* Allocate new connection structure */
	new = g_malloc (sizeof (struct rspamd_kvstorage_connection));

	/* Set fields */
	new->sock = sock;
	new->state = KV_STATE_NONE;
	new->asynced = FALSE;
	if (tv != NULL) {
		memcpy (&new->tv, tv, sizeof (struct timeval));
	}
	else {
		memset (&new->tv, 0, sizeof (struct timeval));
	}
	new->pool = memory_pool_new (memory_pool_get_size ());

	*conn = new;
	return KVSTORAGE_ERROR_OK;
}

/**
 * Read key synced
 * @param conn connection structure
 * @param key key to read
 * @param value value readed
 */
enum rspamd_kvstorage_error
rspamd_kvstorage_get_sync (struct rspamd_kvstorage_connection *conn,
		const gpointer key, gpointer **value)
{
	return KVSTORAGE_ERROR_OK;
}

/**
 * Write key synced
 * @param conn connection structure
 * @param key key to set
 * @param value data to write
 */
enum rspamd_kvstorage_error
rspamd_kvstorage_set_sync (struct rspamd_kvstorage_connection *conn,
		const gpointer key, const gpointer value, gsize len, guint expire)
{
	return KVSTORAGE_ERROR_OK;
}

/**
 * Delete key synced
 * @param conn connection structure
 * @param key key to delete
 */
enum rspamd_kvstorage_error
rspamd_kvstorage_delete_sync (struct rspamd_kvstorage_connection *conn,
		const gpointer key)
{
	return KVSTORAGE_ERROR_OK;
}

/**
 * Close connection
 * @param conn connection structure
 */
enum rspamd_kvstorage_error
rspamd_kvstorage_close_sync (struct rspamd_kvstorage_connection *conn)
{
	close (conn->sock);
	memory_pool_delete (conn->pool);
	g_free (conn);

	return KVSTORAGE_ERROR_OK;
}
