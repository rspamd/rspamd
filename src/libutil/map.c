/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
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

/*
 * Implementation of map files handling
 */
#include "config.h"
#include "map.h"
#include "http.h"
#include "main.h"
#include "util.h"
#include "mem_pool.h"

static const gchar *hash_fill = "1";

/**
 * Data specific to file maps
 */
struct file_map_data {
	const gchar *filename;
	struct stat st;
};

/**
 * Data specific to HTTP maps
 */
struct http_map_data {
	struct addrinfo *addr;
	guint16 port;
	gchar *path;
	gchar *host;
	time_t last_checked;
	gboolean request_sent;
	struct rspamd_http_connection *conn;
};


struct http_callback_data {
	struct event_base *ev_base;
	struct timeval tv;
	struct rspamd_map *map;
	struct http_map_data *data;
	struct map_cb_data cbdata;

	GString *remain_buf;

	gint fd;
};

/* Value in seconds after whitch we would try to do stat on list file */

/* HTTP timeouts */
#define HTTP_CONNECT_TIMEOUT 2
#define HTTP_READ_TIMEOUT 10

/**
 * Helper for HTTP connection establishment
 */
static gint
connect_http (struct rspamd_map *map,
	struct http_map_data *data,
	gboolean is_async)
{
	gint sock;

	if ((sock = rspamd_socket_tcp (data->addr, FALSE, is_async)) == -1) {
		msg_info ("cannot connect to http server %s: %d, %s",
			data->host,
			errno,
			strerror (errno));
		return -1;
	}

	return sock;
}

/**
 * Write HTTP request
 */
static void
write_http_request (struct http_callback_data *cbd)
{
	gchar datebuf[128];
	struct tm *tm;
	struct rspamd_http_message *msg;

	msg = rspamd_http_new_message (HTTP_REQUEST);

	msg->url = g_string_new (cbd->data->path);
	if (cbd->data->last_checked != 0) {
		tm = gmtime (&cbd->data->last_checked);
		strftime (datebuf, sizeof (datebuf), "%a, %d %b %Y %H:%M:%S %Z", tm);

		rspamd_http_message_add_header (msg, "If-Modified-Since", datebuf);
	}

	rspamd_http_connection_write_message (cbd->data->conn, msg, cbd->data->host,
		NULL, cbd, cbd->fd, &cbd->tv, cbd->ev_base);
}

/**
 * Callback for destroying HTTP callback data
 */
static void
free_http_cbdata (struct http_callback_data *cbd)
{
	g_atomic_int_set (cbd->map->locked, 0);
	if (cbd->remain_buf) {
		g_string_free (cbd->remain_buf, TRUE);
	}

	rspamd_http_connection_reset (cbd->data->conn);
	close (cbd->fd);
	g_slice_free1 (sizeof (struct http_callback_data), cbd);
}

/*
 * HTTP callbacks
 */
static void
http_map_error (struct rspamd_http_connection *conn,
	GError *err)
{
	struct http_callback_data *cbd = conn->ud;

	msg_err ("connection with http server terminated incorrectly: %s",
			err->message);
	free_http_cbdata (cbd);
}

static int
http_map_finish (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg)
{
	struct http_callback_data *cbd = conn->ud;
	struct rspamd_map *map;

	map = cbd->map;
	if (msg->code == 200) {
		if (cbd->remain_buf != NULL) {
			map->read_callback (map->pool, cbd->remain_buf->str,
					cbd->remain_buf->len, &cbd->cbdata);
		}

		map->fin_callback (map->pool, &cbd->cbdata);
		*map->user_data = cbd->cbdata.cur_data;
		cbd->data->last_checked = msg->date;
		msg_info ("read map data from %s", cbd->data->host);
	}
	else if (msg->code == 304) {
		msg_debug ("data is not modified for server %s",
				cbd->data->host);
		cbd->data->last_checked = msg->date;
	}
	else {
		msg_info ("cannot load map %s from %s: HTTP error %d",
				map->uri, cbd->data->host, msg->code);
	}

	free_http_cbdata (cbd);

	return 0;
}

static int
http_map_read (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg,
	const gchar *chunk,
	gsize len)
{
	struct http_callback_data *cbd = conn->ud;
	gchar *pos;
	struct rspamd_map *map;

	if (msg->code != 200 || len == 0) {
		/* Ignore not full replies */
		return 0;
	}

	map = cbd->map;
	if (cbd->remain_buf != NULL) {
		/* We need to concatenate incoming buf with the remaining buf */
		g_string_append_len (cbd->remain_buf, chunk, len);

		pos = map->read_callback (map->pool, cbd->remain_buf->str,
				cbd->remain_buf->len, &cbd->cbdata);

		/* All read */
		if (pos == NULL) {
			g_string_free (cbd->remain_buf, TRUE);
			cbd->remain_buf = NULL;
		}
		else {
			/* Need to erase data processed */
			g_string_erase (cbd->remain_buf, 0, pos - cbd->remain_buf->str);
		}
	}
	else {
		pos = map->read_callback (map->pool, (gchar *)chunk, len, &cbd->cbdata);

		if (pos != NULL) {
			/* Store data in remain buf */
			cbd->remain_buf = g_string_new_len (pos, len - (pos - chunk));
		}
	}

	return 0;
}

/**
 * Callback for reading data from file
 */
static void
read_map_file (struct rspamd_map *map, struct file_map_data *data)
{
	struct map_cb_data cbdata;
	gchar buf[BUFSIZ], *remain;
	ssize_t r;
	gint fd, rlen, tlen;

	if (map->read_callback == NULL || map->fin_callback == NULL) {
		msg_err ("bad callback for reading map file");
		return;
	}

	if ((fd = open (data->filename, O_RDONLY)) == -1) {
		msg_warn ("cannot open file '%s': %s", data->filename,
			strerror (errno));
		return;
	}

	cbdata.state = 0;
	cbdata.prev_data = *map->user_data;
	cbdata.cur_data = NULL;
	cbdata.map = map;

	rlen = 0;
	tlen = 0;
	while ((r = read (fd, buf + rlen, sizeof (buf) - rlen - 1)) > 0) {
		r += rlen;
		tlen += r;
		buf[r] = '\0';
		remain = map->read_callback (map->pool, buf, r, &cbdata);
		if (remain != NULL) {
			/* copy remaining buffer to start of buffer */
			rlen = r - (remain - buf);
			memmove (buf, remain, rlen);
		}
	}

	close (fd);

	if (tlen > 0) {
		map->fin_callback (map->pool, &cbdata);
		*map->user_data = cbdata.cur_data;
	}
}

static void
jitter_timeout_event (struct rspamd_map *map, gboolean locked, gboolean initial)
{
	gdouble jittered_sec;
	gdouble timeout = initial ? 1.0 : map->cfg->map_timeout;

	/* Plan event again with jitter */
	evtimer_del (&map->ev);
	jittered_sec = timeout;
	if (locked) {
		/* Add bigger jitter */
		jittered_sec += g_random_double () * timeout * 4;
	}
	else {
		jittered_sec += g_random_double () * timeout;
	}
	double_to_tv (jittered_sec, &map->tv);

	evtimer_add (&map->ev, &map->tv);
}

/**
 * Common file callback
 */
static void
file_callback (gint fd, short what, void *ud)
{
	struct rspamd_map *map = ud;
	struct file_map_data *data = map->map_data;
	struct stat st;

	if (g_atomic_int_get (map->locked)) {
		msg_info (
			"don't try to reread map as it is locked by other process, will reread it later");
		jitter_timeout_event (map, TRUE, FALSE);
		return;
	}

	g_atomic_int_inc (map->locked);
	jitter_timeout_event (map, FALSE, FALSE);
	if (stat (data->filename,
		&st) != -1 &&
		(st.st_mtime > data->st.st_mtime || data->st.st_mtime == -1)) {
		/* File was modified since last check */
		memcpy (&data->st, &st, sizeof (struct stat));
	}
	else {
		g_atomic_int_set (map->locked, 0);
		return;
	}

	msg_info ("rereading map file %s", data->filename);
	read_map_file (map, data);
	g_atomic_int_set (map->locked, 0);
}

/**
 * Async HTTP callback
 */
static void
http_callback (gint fd, short what, void *ud)
{
	struct rspamd_map *map = ud;
	struct http_map_data *data = map->map_data;
	gint sock;
	struct http_callback_data *cbd;

	if (g_atomic_int_get (map->locked)) {
		msg_info (
			"don't try to reread map as it is locked by other process, will reread it later");
		if (data->conn->ud == NULL) {
			jitter_timeout_event (map, TRUE, TRUE);
		}
		else {
			jitter_timeout_event (map, TRUE, FALSE);
		}
		return;
	}

	g_atomic_int_inc (map->locked);
	jitter_timeout_event (map, FALSE, FALSE);
	/* Connect asynced */
	if ((sock = connect_http (map, data, TRUE)) == -1) {
		g_atomic_int_set (map->locked, 0);
		return;
	}
	else {
		/* Plan event */
		cbd = g_slice_alloc (sizeof (struct http_callback_data));
		cbd->ev_base = map->ev_base;
		cbd->map = map;
		cbd->data = data;
		cbd->remain_buf = NULL;
		cbd->cbdata.state = 0;
		cbd->cbdata.prev_data = *cbd->map->user_data;
		cbd->cbdata.cur_data = NULL;
		cbd->cbdata.map = cbd->map;
		cbd->tv.tv_sec = HTTP_CONNECT_TIMEOUT;
		cbd->tv.tv_usec = 0;
		cbd->fd = sock;
		data->conn->ud = cbd;
		msg_debug ("reading map data from %s", data->host);
		write_http_request (cbd);
	}
}

/* Start watching event for all maps */
void
rspamd_map_watch (struct rspamd_config *cfg, struct event_base *ev_base)
{
	GList *cur = cfg->maps;
	struct rspamd_map *map;
	struct file_map_data *fdata;

	/* First of all do synced read of data */
	while (cur) {
		map = cur->data;
		map->ev_base = ev_base;
		event_base_set (map->ev_base, &map->ev);
		if (map->protocol == MAP_PROTO_FILE) {
			evtimer_set (&map->ev, file_callback, map);
			/* Read initial data */
			fdata = map->map_data;
			if (fdata->st.st_mtime != -1) {
				/* Do not try to read non-existent file */
				read_map_file (map, map->map_data);
			}
			/* Plan event with jitter */
			jitter_timeout_event (map, FALSE, TRUE);
		}
		else if (map->protocol == MAP_PROTO_HTTP) {
			evtimer_set (&map->ev, http_callback, map);
			jitter_timeout_event (map, FALSE, TRUE);
		}
		cur = g_list_next (cur);
	}
}

void
rspamd_map_remove_all (struct rspamd_config *cfg)
{
	g_list_free (cfg->maps);
	cfg->maps = NULL;
	if (cfg->map_pool != NULL) {
		rspamd_mempool_delete (cfg->map_pool);
		cfg->map_pool = NULL;
	}
}

gboolean
rspamd_map_check_proto (const gchar *map_line, gint *res, const gchar **pos)
{
	g_assert (res != NULL);
	g_assert (pos != NULL);

	if (g_ascii_strncasecmp (map_line, "http://",
			sizeof ("http://") - 1) == 0) {
		*res = MAP_PROTO_HTTP;
		*pos = map_line + sizeof ("http://") - 1;
	}
	else if (g_ascii_strncasecmp (map_line, "file://", sizeof ("file://") -
			1) == 0) {
		*res = MAP_PROTO_FILE;
		*pos = map_line + sizeof ("file://") - 1;
	}
	else if (*map_line == '/') {
		/* Trivial file case */
		*res = MAP_PROTO_FILE;
		*pos = map_line;
	}
	else {
		msg_debug ("invalid map fetching protocol: %s", map_line);
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_map_add (struct rspamd_config *cfg,
	const gchar *map_line,
	const gchar *description,
	map_cb_t read_callback,
	map_fin_cb_t fin_callback,
	void **user_data)
{
	struct rspamd_map *new_map;
	enum fetch_proto proto;
	const gchar *def, *p, *hostend;
	struct file_map_data *fdata;
	struct http_map_data *hdata;
	gchar portbuf[6];
	gint i, s, r;
	struct addrinfo hints, *res;

	/* First of all detect protocol line */
	if (!rspamd_map_check_proto (map_line, (int *)&proto, &def)) {
		return FALSE;
	}
	/* Constant pool */
	if (cfg->map_pool == NULL) {
		cfg->map_pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());
	}
	new_map = rspamd_mempool_alloc0 (cfg->map_pool, sizeof (struct rspamd_map));
	new_map->read_callback = read_callback;
	new_map->fin_callback = fin_callback;
	new_map->user_data = user_data;
	new_map->protocol = proto;
	new_map->cfg = cfg;
	new_map->id = g_random_int ();
	new_map->locked =
		rspamd_mempool_alloc0_shared (cfg->cfg_pool, sizeof (gint));

	if (proto == MAP_PROTO_FILE) {
		new_map->uri = rspamd_mempool_strdup (cfg->cfg_pool, def);
		def = new_map->uri;
	}
	else {
		new_map->uri = rspamd_mempool_strdup (cfg->cfg_pool, map_line);
	}
	if (description != NULL) {
		new_map->description =
			rspamd_mempool_strdup (cfg->cfg_pool, description);
	}

	/* Now check for each proto separately */
	if (proto == MAP_PROTO_FILE) {
		fdata =
			rspamd_mempool_alloc0 (cfg->map_pool,
				sizeof (struct file_map_data));
		if (access (def, R_OK) == -1) {
			if (errno != ENOENT) {
				msg_err ("cannot open file '%s': %s", def, strerror (errno));
				return FALSE;

			}
			msg_info (
				"map '%s' is not found, but it can be loaded automatically later",
				def);
			/* We still can add this file */
			fdata->st.st_mtime = -1;
		}
		else {
			stat (def, &fdata->st);
		}
		fdata->filename = rspamd_mempool_strdup (cfg->map_pool, def);
		new_map->map_data = fdata;
	}
	else if (proto == MAP_PROTO_HTTP) {
		hdata =
			rspamd_mempool_alloc0 (cfg->map_pool,
				sizeof (struct http_map_data));
		/* Try to search port */
		if ((p = strchr (def, ':')) != NULL) {
			hostend = p;
			i = 0;
			p++;
			while (g_ascii_isdigit (*p) && i < (gint)sizeof (portbuf) - 1) {
				portbuf[i++] = *p++;
			}
			if (*p != '/') {
				msg_info ("bad http map definition: %s", def);
				return FALSE;
			}
			portbuf[i] = '\0';
			hdata->port = atoi (portbuf);
		}
		else {
			/* Default http port */
			rspamd_snprintf (portbuf, sizeof (portbuf), "80");
			hdata->port = 80;
			/* Now separate host from path */
			if ((p = strchr (def, '/')) == NULL) {
				msg_info ("bad http map definition: %s", def);
				return FALSE;
			}
			hostend = p;
		}
		hdata->host = rspamd_mempool_alloc (cfg->map_pool, hostend - def + 1);
		rspamd_strlcpy (hdata->host, def, hostend - def + 1);
		hdata->path = rspamd_mempool_strdup (cfg->map_pool, p);
		/* Now try to resolve */
		memset (&hints, 0, sizeof (hints));
		hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
		hints.ai_socktype = SOCK_STREAM; /* Stream socket */
		hints.ai_flags = 0;
		hints.ai_protocol = 0;           /* Any protocol */
		hints.ai_canonname = NULL;
		hints.ai_addr = NULL;
		hints.ai_next = NULL;

		if ((r = getaddrinfo (hdata->host, portbuf, &hints, &res)) == 0) {
			hdata->addr = res;
			rspamd_mempool_add_destructor (cfg->cfg_pool,
				(rspamd_mempool_destruct_t)freeaddrinfo, hdata->addr);
		}
		else {
			msg_err ("address resolution for %s failed: %s",
				hdata->host,
				gai_strerror (r));
			return FALSE;
		}
		/* Now try to connect */
		if ((s = rspamd_socket_tcp (hdata->addr, FALSE, FALSE)) == -1) {
			msg_info ("cannot connect to http server %s: %d, %s",
				hdata->host,
				errno,
				strerror (errno));
			return FALSE;
		}
		close (s);
		hdata->conn = rspamd_http_connection_new (http_map_read, http_map_error,
			http_map_finish,
			RSPAMD_HTTP_BODY_PARTIAL | RSPAMD_HTTP_CLIENT_SIMPLE,
			RSPAMD_HTTP_CLIENT, NULL);
		new_map->map_data = hdata;
	}
	/* Temp pool */
	new_map->pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());

	cfg->maps = g_list_prepend (cfg->maps, new_map);

	return TRUE;
}


/**
 * FSM for parsing lists
 */
gchar *
abstract_parse_kv_list (rspamd_mempool_t * pool,
	gchar * chunk,
	gint len,
	struct map_cb_data *data,
	insert_func func)
{
	gchar *c, *p, *key = NULL, *value = NULL;

	p = chunk;
	c = p;

	while (p - chunk < len) {
		switch (data->state) {
		case 0:
			/* read key */
			/* Check here comments, eol and end of buffer */
			if (*p == '#') {
				if (key != NULL && p - c  >= 0) {
					value = rspamd_mempool_alloc (pool, p - c + 1);
					memcpy (value, c, p - c);
					value[p - c] = '\0';
					value = g_strstrip (value);
					func (data->cur_data, key, value);
					msg_debug ("insert kv pair: %s -> %s", key, value);
				}
				data->state = 99;
			}
			else if (*p == '\r' || *p == '\n' || p - chunk == len - 1) {
				if (key != NULL && p - c >= 0) {
					value = rspamd_mempool_alloc (pool, p - c + 1);
					memcpy (value, c, p - c);
					value[p - c] = '\0';

					value = g_strstrip (value);
					func (data->cur_data, key, value);
					msg_debug ("insert kv pair: %s -> %s", key, value);
				}
				else if (key == NULL && p - c > 0) {
					/* Key only line */
					key = rspamd_mempool_alloc (pool, p - c + 1);
					memcpy (key, c, p - c);
					key[p - c] = '\0';
					value = rspamd_mempool_alloc (pool, 1);
					*value = '\0';
					func (data->cur_data, key, value);
					msg_debug ("insert kv pair: %s -> %s", key, value);
				}
				data->state = 100;
				key = NULL;
			}
			else if (g_ascii_isspace (*p)) {
				if (p - c > 0) {
					key = rspamd_mempool_alloc (pool, p - c + 1);
					memcpy (key, c, p - c);
					key[p - c] = '\0';
					data->state = 2;
				}
				else {
					key = NULL;
				}
			}
			else {
				p++;
			}
			break;
		case 2:
			/* Skip spaces before value */
			if (!g_ascii_isspace (*p)) {
				c = p;
				data->state = 0;
			}
			else {
				p++;
			}
			break;
		case 99:
			/* SKIP_COMMENT */
			/* Skip comment till end of line */
			if (*p == '\r' || *p == '\n') {
				while ((*p == '\r' || *p == '\n') && p - chunk < len) {
					p++;
				}
				c = p;
				key = NULL;
				data->state = 0;
			}
			else {
				p++;
			}
			break;
		case 100:
			/* Skip \r\n and whitespaces */
			if (*p == '\r' || *p == '\n' || g_ascii_isspace (*p)) {
				p++;
			}
			else {
				c = p;
				key = NULL;
				data->state = 0;
			}
			break;
		}
	}

	return c;
}

gchar *
rspamd_parse_abstract_list (rspamd_mempool_t * pool,
	gchar * chunk,
	gint len,
	struct map_cb_data *data,
	insert_func func)
{
	gchar *s, *p, *str, *start;

	p = chunk;
	start = p;

	str = g_malloc (len + 1);
	s = str;

	while (p - chunk < len) {
		switch (data->state) {
		/* READ_SYMBOL */
		case 0:
			if (*p == '#') {
				/* Got comment */
				if (s != str) {
					/* Save previous string in lines like: "127.0.0.1 #localhost" */
					*s = '\0';
					s = rspamd_mempool_strdup (pool, g_strstrip (str));
					if (strlen (s) > 0) {
						func (data->cur_data, s, hash_fill);
					}
					s = str;
					start = p;
				}
				data->state = 1;
			}
			else if (*p == '\r' || *p == '\n') {
				/* Got EOL marker, save stored string */
				if (s != str) {
					*s = '\0';
					s = rspamd_mempool_strdup (pool, g_strstrip (str));
					if (strlen (s) > 0) {
						func (data->cur_data, s, hash_fill);
					}
					s = str;
				}
				/* Skip EOL symbols */
				while ((*p == '\r' || *p == '\n') && p - chunk < len) {
					p++;
				}
				start = p;
			}
			else {
				/* Store new string in s */
				*s = *p;
				s++;
				p++;
			}
			break;
		/* SKIP_COMMENT */
		case 1:
			/* Skip comment till end of line */
			if (*p == '\r' || *p == '\n') {
				while ((*p == '\r' || *p == '\n') && p - chunk < len) {
					p++;
				}
				s = str;
				start = p;
				data->state = 0;
			}
			else {
				p++;
			}
			break;
		}
	}

	g_free (str);

	return start;
}

/**
 * Radix tree helper function
 */
static void
radix_tree_insert_helper (gpointer st, gconstpointer key, gpointer value)
{
	radix_compressed_t *tree = (radix_compressed_t *)st;

	rspamd_radix_add_iplist ((gchar *)key, " ,;", tree);
}

/* Helpers */
gchar *
rspamd_hosts_read (rspamd_mempool_t * pool,
	gchar * chunk,
	gint len,
	struct map_cb_data *data)
{
	if (data->cur_data == NULL) {
		data->cur_data = g_hash_table_new (rspamd_strcase_hash,
				rspamd_strcase_equal);
	}
	return rspamd_parse_abstract_list (pool,
			   chunk,
			   len,
			   data,
			   (insert_func) g_hash_table_insert);
}

void
rspamd_hosts_fin (rspamd_mempool_t * pool, struct map_cb_data *data)
{
	if (data->prev_data) {
		g_hash_table_destroy (data->prev_data);
	}
	if (data->cur_data) {
		msg_info ("read hash of %z elements", g_hash_table_size (data->cur_data));
	}
}

gchar *
rspamd_kv_list_read (rspamd_mempool_t * pool,
	gchar * chunk,
	gint len,
	struct map_cb_data *data)
{
	if (data->cur_data == NULL) {
		data->cur_data = g_hash_table_new (rspamd_strcase_hash,
				rspamd_strcase_equal);
	}
	return abstract_parse_kv_list (pool,
			   chunk,
			   len,
			   data,
			   (insert_func) g_hash_table_insert);
}

void
rspamd_kv_list_fin (rspamd_mempool_t * pool, struct map_cb_data *data)
{
	if (data->prev_data) {
		g_hash_table_destroy (data->prev_data);
	}
	if (data->cur_data) {
		msg_info ("read hash of %z elements", g_hash_table_size (data->cur_data));
	}
}

gchar *
rspamd_radix_read (rspamd_mempool_t * pool,
	gchar * chunk,
	gint len,
	struct map_cb_data *data)
{
	if (data->cur_data == NULL) {
		data->cur_data = radix_create_compressed ();
	}
	return rspamd_parse_abstract_list (pool,
			   chunk,
			   len,
			   data,
			   (insert_func) radix_tree_insert_helper);
}

void
rspamd_radix_fin (rspamd_mempool_t * pool, struct map_cb_data *data)
{
	if (data->prev_data) {
		radix_destroy_compressed (data->prev_data);
	}
	if (data->cur_data) {
		msg_info ("read radix trie of %z elements", radix_get_size (data->cur_data));
	}
}
