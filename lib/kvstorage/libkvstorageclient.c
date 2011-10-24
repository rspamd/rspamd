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

#define MAX_KV_LINE 1024

struct kvstorage_buf {
	guint pos;
	guint len;
	guint8 data[1];
};

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

/*
 * Buffer functions
 */

/*
 * Create new kvstorage_buf
 */
static struct kvstorage_buf *
rspamd_kvstorage_buf_create (guint size, memory_pool_t *pool)
{
	struct kvstorage_buf					*new;

	new = memory_pool_alloc (pool, sizeof (struct kvstorage_buf) + size);
	new->len = size;
	new->pos = 0;

	return new;
}

/*
 * Read a single line synced or asynced
 */
static gint
rspamd_kvstorage_buf_readline (struct kvstorage_buf *buf, struct rspamd_kvstorage_connection *conn)
{
	gint									r;
	guint8								   *p;

	r = read (conn->sock, buf->data, buf->len);
	if (r == -1) {
		return errno;
	}
	/* Try to parse what we have */
	p = buf->data;
	while (p - buf->data < r) {
		if (*p == '\r' || *p == '\n') {

			buf->pos = p - buf->data;
			return 0;
		}
		p ++;
	}

	if (r == (gint)buf->len) {
		/* Buffer is overflowed */
		return EOVERFLOW;
	}
	/* Line end not found */
	return EAGAIN;
}

/*
 * Read the whole buffer, return remaining characters or -1
 */
static gint
rspamd_kvstorage_buf_readall (struct kvstorage_buf *buf, struct rspamd_kvstorage_connection *conn)
{
	gint									r;

	if (buf->len - buf->pos == 0) {
		return 0;
	}
	r = read (conn->sock, buf->data + buf->pos, buf->len - buf->pos);
	if (r == -1) {
		return -1;
	}

	buf->pos += r;

	/* Line end not found */
	return buf->len - buf->pos;
}

/*
 * Write the whole buffer, return remaining characters or -1
 */
static gint
rspamd_kvstorage_buf_writeall (struct kvstorage_buf *buf, struct rspamd_kvstorage_connection *conn)
{
	gint									r;

	if (buf->len - buf->pos == 0) {
		return 0;
	}
	r = write (conn->sock, buf->data + buf->pos, buf->len - buf->pos);
	if (r == -1) {
		return -1;
	}

	buf->pos += r;

	/* Line end not found */
	return buf->len - buf->pos;
}

/*
 * Drain line from the begin of buffer, moving it from the beginning of buf
 */
static void
rspamd_kvstorage_buf_drainline (struct kvstorage_buf *buf)
{
	guint8								   *p;

	p = buf->data + buf->pos;
	/* Skip \r and \n characters */
	while (p - buf->data < buf->len && (*p == '\r' || *p == '\n')) {
		p ++;
	}
	if (p - buf->data == buf->len) {
		/* Do not move anything */
		buf->pos = 0;
		return;
	}
	memcpy (buf->data, p, buf->len - (p - buf->data));
	buf->pos = buf->len - (p - buf->data);
}

/* Common utility functions */

/*
 * Parse reply line that contains an error
 */
static enum rspamd_kvstorage_error
rspamd_kvstorage_parse_reply_error (struct kvstorage_buf *buf)
{
	guint8								   *p;
	guint                                   l = 0;

	/* Get one word */
	p = buf->data;
	while (p - buf->data < buf->pos) {
		if (g_ascii_isspace (*p)) {
			while (p - buf->data < buf->pos && g_ascii_isspace (*p)) {
				p ++;
			}
			break;
		}
		p ++;
		l ++;
	}

	/* Get common errors */
	if (g_ascii_strncasecmp (buf->data, "ERROR", MIN (l, sizeof("ERORR") - 1)) == 0) {
		return KVSTORAGE_ERROR_INTERNAL_ERROR;
	}
	else if (g_ascii_strncasecmp (buf->data, "SERVER_ERROR", MIN (l, sizeof("SERVER_ERORR") - 1)) == 0) {
		return KVSTORAGE_ERROR_SERVER_ERROR;
	}
	else if (g_ascii_strncasecmp (buf->data, "CLIENT_ERROR", MIN (l, sizeof("CLIENT_ERORR") - 1)) == 0) {
		return KVSTORAGE_ERROR_CLIENT_ERROR;
	}
	else if (g_ascii_strncasecmp (buf->data, "NOT_STORED", MIN (l, sizeof("NOT_STORED") - 1)) == 0) {
		return KVSTORAGE_ERROR_NOT_STORED;
	}
	else if (g_ascii_strncasecmp (buf->data, "NOT_FOUND", MIN (l, sizeof("NOT_FOUND") - 1)) == 0) {
		return KVSTORAGE_ERROR_NOT_FOUND;
	}
	else if (g_ascii_strncasecmp (buf->data, "EXISTS", MIN (l, sizeof("EXISTS") - 1)) == 0) {
		return KVSTORAGE_ERROR_EXISTS;
	}
	else if (g_ascii_strncasecmp (buf->data, "STORED", MIN (l, sizeof("STORED") - 1)) == 0) {
		return KVSTORAGE_ERROR_OK;
	}
	else if (g_ascii_strncasecmp (buf->data, "DELETED", MIN (l, sizeof("DELETED") - 1)) == 0) {
		return KVSTORAGE_ERROR_OK;
	}

	return KVSTORAGE_ERROR_INTERNAL_ERROR;
}

/*
 * Parse reply line, store element length
 */
static enum rspamd_kvstorage_error
rspamd_kvstorage_parse_get_line (struct kvstorage_buf *buf, guint *len, guint *flags)
{
	guint8								   *p, *c;
	gboolean                                error = TRUE;
	gchar                                  *err_str;

	p = buf->data;
	while (p - buf->data < buf->pos) {
		if (g_ascii_isspace (*p)) {
			error = FALSE;
			while (p - buf->data < buf->pos && g_ascii_isspace (*p)) {
				p ++;
			}
			break;
		}
		p ++;
	}
	/* Here we got a word or error flag */
	if (error) {
		/* Something wrong here */
		return KVSTORAGE_ERROR_SERVER_ERROR;
	}
	if (g_ascii_strncasecmp (buf->data, "VALUE", sizeof ("VALUE") - 1) != 0) {
		return rspamd_kvstorage_parse_reply_error (buf);
	}
	/* Here we got key, flags and size items */
	/* Skip key */
	error = TRUE;
	while (p - buf->data < buf->pos) {
		if (g_ascii_isspace (*p)) {
			error = FALSE;
			while (p - buf->data < buf->pos && g_ascii_isspace (*p)) {
				p ++;
			}
			break;
		}
		p ++;
	}
	if (error) {
		/* Something wrong here */
		return KVSTORAGE_ERROR_SERVER_ERROR;
	}
	/* Read flags */
	c = p;
	error = TRUE;
	while (p - buf->data < buf->pos) {
		if (g_ascii_isspace (*p)) {
			error = FALSE;
			while (p - buf->data < buf->pos && g_ascii_isspace (*p)) {
				p ++;
			}
			break;
		}
		else if (!g_ascii_isdigit (*p)) {
			break;
		}
		p ++;
	}
	if (error) {
		/* Something wrong here */
		return KVSTORAGE_ERROR_SERVER_ERROR;
	}
	*flags = strtoul (c, &err_str, 10);
	if (!g_ascii_isspace (*err_str)) {
		return KVSTORAGE_ERROR_SERVER_ERROR;
	}
	/* Read len */
	c = p;
	error = TRUE;
	while (p - buf->data < buf->pos) {
		if (g_ascii_isspace (*p)) {
			error = FALSE;
			while (p - buf->data < buf->pos && g_ascii_isspace (*p)) {
				p ++;
			}
			break;
		}
		else if (!g_ascii_isdigit (*p)) {
			break;
		}
		p ++;
	}
	if (error) {
		/* Something wrong here */
		return KVSTORAGE_ERROR_SERVER_ERROR;
	}
	*len = strtoul (c, &err_str, 10);
	if (!g_ascii_isspace (*err_str)) {
		return KVSTORAGE_ERROR_SERVER_ERROR;
	}

	return KVSTORAGE_ERROR_OK;
}

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
	new->state = KV_STATE_CONNECTED;
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
		const gpointer key, gpointer **value, guint *len)
{
	struct kvstorage_buf 				   *buf, *databuf;
	gint                                    r;
	guint									flags;

	if (conn == NULL || conn->state != KV_STATE_CONNECTED) {
		return KVSTORAGE_ERROR_INTERNAL_ERROR;
	}

	buf = rspamd_kvstorage_buf_create (MAX_KV_LINE, conn->pool);

	r = rspamd_snprintf (buf->data, buf->len, "get %s" CRLF, key);
	buf->len = r;
	while ((r = rspamd_kvstorage_buf_writeall (buf, conn)) > 0) {
		poll_sync_socket (conn->sock, tv_to_msec (&conn->tv), POLL_OUT);
	}

	if (r == -1) {
		return KVSTORAGE_ERROR_INTERNAL_ERROR;
	}
	/* Now read reply and try to parse line */
	buf->len = MAX_KV_LINE;
	buf->pos = 0;
	while ((r = rspamd_kvstorage_buf_readline (buf, conn)) == EAGAIN) {
		poll_sync_socket (conn->sock, tv_to_msec (&conn->tv), POLL_IN);
	}
	/* A line was read */
	if (r == 0) {
		if ((r = rspamd_kvstorage_parse_get_line (buf, len, &flags)) != KVSTORAGE_ERROR_OK) {
			return r;
		}
		rspamd_kvstorage_buf_drainline (buf);
		/* Now allocate and read the data */
		databuf = rspamd_kvstorage_buf_create (*len, conn->pool);
		memcpy (databuf->data, buf->data, buf->pos);
		while ((r = rspamd_kvstorage_buf_readall (databuf, conn)) > 0) {
			poll_sync_socket (conn->sock, tv_to_msec (&conn->tv), POLL_IN);
		}
		if (r == -1) {
			return KVSTORAGE_ERROR_INTERNAL_ERROR;
		}
		/* Now we have data inside buffer, read the last line */
		buf->pos = 0;
		while ((r = rspamd_kvstorage_buf_readline (buf, conn)) == EAGAIN) {
			poll_sync_socket (conn->sock, tv_to_msec (&conn->tv), POLL_IN);
		}
		*value = (gpointer)buf->data;
	}


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
	struct kvstorage_buf 				   *buf;
	gint                                    r, keylen, buflen;

	if (conn == NULL || conn->state != KV_STATE_CONNECTED) {
		return KVSTORAGE_ERROR_INTERNAL_ERROR;
	}

	/* Create buf */
	keylen = strlen (key);
	buflen = len + keylen + sizeof ("set  4294967296 4294967296 4294967296" CRLF);
	buf = rspamd_kvstorage_buf_create (buflen, conn->pool);

	r = rspamd_snprintf (buf->data, buf->len, "set %*s %ud %ud %ud" CRLF "%*s",
			keylen, key, 0, expire, len, len, value);
	buf->len = r;
	while ((r = rspamd_kvstorage_buf_writeall (buf, conn)) > 0) {
		poll_sync_socket (conn->sock, tv_to_msec (&conn->tv), POLL_OUT);
	}
	if (r == -1) {
		return KVSTORAGE_ERROR_INTERNAL_ERROR;
	}
	/* Now we can read reply */
	buf->pos = 0;
	buf->len = buflen;
	while ((r = rspamd_kvstorage_buf_readline (buf, conn)) == EAGAIN) {
		poll_sync_socket (conn->sock, tv_to_msec (&conn->tv), POLL_IN);
	}

	return rspamd_kvstorage_parse_reply_error (buf);
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
	struct kvstorage_buf 				   *buf;
	gint                                    r, keylen, buflen;

	if (conn == NULL || conn->state != KV_STATE_CONNECTED) {
		return KVSTORAGE_ERROR_INTERNAL_ERROR;
	}

	/* Create buf */
	keylen = strlen (key);
	buflen = MAX (keylen + sizeof ("delete" CRLF), MAX_KV_LINE);
	buf = rspamd_kvstorage_buf_create (buflen, conn->pool);

	r = rspamd_snprintf (buf->data, buf->len, "delete %*s" CRLF,
			keylen, key);
	buf->len = r;
	while ((r = rspamd_kvstorage_buf_writeall (buf, conn)) > 0) {
		poll_sync_socket (conn->sock, tv_to_msec (&conn->tv), POLL_OUT);
	}
	if (r == -1) {
		return KVSTORAGE_ERROR_INTERNAL_ERROR;
	}
	/* Now we can read reply */
	buf->len = buflen;
	buf->pos = 0;
	while ((r = rspamd_kvstorage_buf_readline (buf, conn)) == EAGAIN) {
		poll_sync_socket (conn->sock, tv_to_msec (&conn->tv), POLL_IN);
	}

	return rspamd_kvstorage_parse_reply_error (buf);
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
