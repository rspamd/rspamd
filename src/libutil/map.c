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
/*
 * Implementation of map files handling
 */
#include "config.h"
#include "map.h"
#include "map_private.h"
#include "http.h"
#include "rspamd.h"
#include "cryptobox.h"
#include "unix-std.h"

static const gchar *hash_fill = "1";

/**
 * Helper for HTTP connection establishment
 */
static gint
connect_http (struct rspamd_map *map,
	struct http_map_data *data,
	gboolean is_async)
{
	gint sock;
	rspamd_mempool_t *pool;

	pool = map->pool;

	if ((sock = rspamd_socket_tcp (data->addr, FALSE, is_async)) == -1) {
		msg_info_pool ("cannot connect to http server %s: %d, %s",
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

	msg->url = rspamd_fstring_new_init (cbd->data->path, strlen (cbd->data->path));
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
	rspamd_mempool_t *pool;

	pool = cbd->map->pool;

	msg_err_pool ("connection with http server terminated incorrectly: %s",
			err->message);
	free_http_cbdata (cbd);
}

static int
http_map_finish (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg)
{
	struct http_callback_data *cbd = conn->ud;
	struct rspamd_map *map;
	rspamd_mempool_t *pool;

	map = cbd->map;
	pool = cbd->map->pool;

	if (msg->code == 200) {
		if (cbd->remain_buf != NULL) {
			/* Append \n to avoid issues */
			g_string_append_c (cbd->remain_buf, '\n');
			map->read_callback (map->pool, cbd->remain_buf->str,
					cbd->remain_buf->len, &cbd->cbdata);
		}

		map->fin_callback (map->pool, &cbd->cbdata);
		*map->user_data = cbd->cbdata.cur_data;
		cbd->data->last_checked = msg->date;
		msg_info_pool ("read map data from %s", cbd->data->host);
	}
	else if (msg->code == 304) {
		msg_debug_pool ("data is not modified for server %s",
				cbd->data->host);
		cbd->data->last_checked = msg->date;
	}
	else {
		msg_info_pool ("cannot load map %s from %s: HTTP error %d",
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

static gboolean
rspamd_map_check_file_sig (const char *fname,
		struct rspamd_map *map, const guchar *input,
		gsize inlen)
{
	gchar fpath[PATH_MAX];
	rspamd_mempool_t *pool = map->pool;
	guchar *data;
	struct rspamd_cryptobox_pubkey *pk = NULL;
	GString *b32_key;
	gsize len = 0;

	if (map->trusted_pubkey == NULL) {
		/* Try to load and check pubkey */
		rspamd_snprintf (fpath, sizeof (fpath), "%s.pub", fname);

		data = rspamd_file_xmap (fpath, PROT_READ, &len);

		if (data == NULL) {
			msg_err_pool ("can't open pubkey %s: %s", fpath, strerror (errno));
			return FALSE;
		}

		pk = rspamd_pubkey_from_base32 (data, len, RSPAMD_KEYPAIR_SIGN,
				RSPAMD_CRYPTOBOX_MODE_25519);
		munmap (data, len);

		if (pk == NULL) {
			msg_err_pool ("can't load pubkey %s", fpath);
			return FALSE;
		}

		/* We just check pk against the trusted db of keys */
		b32_key = rspamd_pubkey_print (pk,
				RSPAMD_KEYPAIR_BASE32|RSPAMD_KEYPAIR_PUBKEY);
		g_assert (b32_key != NULL);

		if (g_hash_table_lookup (map->cfg->trusted_keys, b32_key->str) == NULL) {
			msg_err_pool ("pubkey loaded from %s is untrusted: %v", fpath,
					b32_key);
			g_string_free (b32_key, TRUE);
			rspamd_pubkey_unref (pk);

			return FALSE;
		}

		g_string_free (b32_key, TRUE);
	}
	else {
		pk = rspamd_pubkey_ref (map->trusted_pubkey);
	}

	/* Now load signature */
	rspamd_snprintf (fpath, sizeof (fpath), "%s.sig", fname);
	data = rspamd_file_xmap (fpath, PROT_READ, &len);

	if (data == NULL) {
		msg_err_pool ("can't open signature %s: %s", fpath, strerror (errno));
		rspamd_pubkey_unref (pk);
		return FALSE;
	}

	if (len != rspamd_cryptobox_signature_bytes (RSPAMD_CRYPTOBOX_MODE_25519)) {
		msg_err_pool ("can't open signature %s: invalid signature", fpath);
		rspamd_pubkey_unref (pk);
		munmap (data, len);

		return FALSE;
	}

	if (!rspamd_cryptobox_verify (data, input, inlen,
			rspamd_pubkey_get_pk (pk, NULL), RSPAMD_CRYPTOBOX_MODE_25519)) {
		msg_err_pool ("can't verify signature %s: incorrect signature", fpath);
		rspamd_pubkey_unref (pk);
		munmap (data, len);

		return FALSE;
	}

	rspamd_pubkey_unref (pk);
	munmap (data, len);

	return TRUE;
}

/**
 * Callback for reading data from file
 */
static void
read_map_file (struct rspamd_map *map, struct file_map_data *data)
{
	struct map_cb_data cbdata;
	guchar *bytes;
	gsize len;
	rspamd_mempool_t *pool = map->pool;

	if (map->read_callback == NULL || map->fin_callback == NULL) {
		msg_err_pool ("bad callback for reading map file");
		return;
	}

	bytes = rspamd_file_xmap (data->filename, PROT_READ, &len);

	if (bytes == NULL) {
		msg_err_pool ("can't open map %s: %s", data->filename, strerror (errno));
		return;
	}

	cbdata.state = 0;
	cbdata.prev_data = *map->user_data;
	cbdata.cur_data = NULL;
	cbdata.map = map;

	if (map->is_signed) {
		if (!rspamd_map_check_file_sig (data->filename, map, bytes, len)) {
			munmap (bytes, len);

			return;
		}
	}

	map->read_callback (map->pool, bytes, len, &cbdata);

	if (len > 0) {
		map->fin_callback (map->pool, &cbdata);
		*map->user_data = cbdata.cur_data;
	}

	munmap (bytes, len);
}

static void
jitter_timeout_event (struct rspamd_map *map, gboolean locked, gboolean initial)
{
	gdouble jittered_sec;
	gdouble timeout = initial ? 1.0 : map->cfg->map_timeout;

	/* Plan event again with jitter */
	evtimer_del (&map->ev);
	jittered_sec = rspamd_time_jitter (locked ? timeout * 4 : timeout, 0);
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
	rspamd_mempool_t *pool;

	pool = map->pool;

	if (g_atomic_int_get (map->locked)) {
		msg_info_pool (
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

	msg_info_pool ("rereading map file %s", data->filename);
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
	struct http_map_data *data;
	gint sock;
	struct http_callback_data *cbd;
	rspamd_mempool_t *pool;

	data = map->map_data;
	pool = map->pool;

	if (g_atomic_int_get (map->locked)) {
		msg_info_pool (
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
		cbd->tv.tv_sec = 5;
		cbd->tv.tv_usec = 0;
		cbd->fd = sock;
		data->conn->ud = cbd;
		msg_debug_pool ("reading map data from %s", data->host);
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

static const gchar *
rspamd_map_check_proto (struct rspamd_config *cfg,
		const gchar *map_line, struct rspamd_map *map)
{
	const gchar *pos = map_line, *end;

	g_assert (map != NULL);
	g_assert (pos != NULL);

	end = pos + strlen (pos);

	if (g_ascii_strncasecmp (pos, "sign+", sizeof ("sign+") - 1) == 0) {
		map->is_signed = TRUE;
		pos += sizeof ("sign+") - 1;
	}

	if (g_ascii_strncasecmp (pos, "key=", sizeof ("key=") - 1) == 0) {
		pos += sizeof ("key=") - 1;

		if (end - pos > 64) {
			map->trusted_pubkey = rspamd_pubkey_from_hex (pos, 64,
					RSPAMD_KEYPAIR_SIGN, RSPAMD_CRYPTOBOX_MODE_25519);

			if (map->trusted_pubkey == NULL) {
				msg_err_config ("cannot read pubkey from map: %s",
						map_line);
				return NULL;
			}
		}
		else {
			msg_err_config ("cannot read pubkey from map: %s",
					map_line);
			return NULL;
		}

		pos += 64;

		if (*pos == '+' || *pos == ':') {
			pos ++;
		}
	}

	map->protocol = MAP_PROTO_FILE;

	if (g_ascii_strncasecmp (pos, "http://",
			sizeof ("http://") - 1) == 0) {
		map->protocol = MAP_PROTO_HTTP;
		/* Include http:// */
		map->uri = rspamd_mempool_strdup (cfg->cfg_pool, pos);
		pos += sizeof ("http://") - 1;
	}
	else if (g_ascii_strncasecmp (pos, "file://", sizeof ("file://") -
			1) == 0) {
		pos += sizeof ("file://") - 1;
		/* Exclude file:// */
		map->uri = rspamd_mempool_strdup (cfg->cfg_pool, pos);
	}
	else if (*pos == '/') {
		/* Trivial file case */
		map->uri = rspamd_mempool_strdup (cfg->cfg_pool, pos);
	}
	else {
		msg_err_config ("invalid map fetching protocol: %s", map_line);

		return NULL;
	}


	return pos;
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
	const gchar *def, *p, *hostend;
	struct file_map_data *fdata;
	struct http_map_data *hdata;
	gchar portbuf[6], *cksum_encoded, cksum[rspamd_cryptobox_HASHBYTES];
	gint i, s, r;
	struct addrinfo hints, *res;
	rspamd_mempool_t *pool;

	if (cfg->map_pool == NULL) {
		cfg->map_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
				"map");
		memcpy (cfg->map_pool->tag.uid, cfg->cfg_pool->tag.uid,
				sizeof (cfg->map_pool->tag.uid));
	}

	new_map = rspamd_mempool_alloc0 (cfg->map_pool, sizeof (struct rspamd_map));

	/* First of all detect protocol line */
	if (rspamd_map_check_proto (cfg, map_line, new_map) == NULL) {
		return FALSE;
	}

	new_map->read_callback = read_callback;
	new_map->fin_callback = fin_callback;
	new_map->user_data = user_data;
	new_map->cfg = cfg;
	new_map->id = g_random_int ();
	new_map->locked =
		rspamd_mempool_alloc0_shared (cfg->cfg_pool, sizeof (gint));
	def = new_map->uri;

	if (description != NULL) {
		new_map->description =
			rspamd_mempool_strdup (cfg->cfg_pool, description);
	}

	/* Now check for each proto separately */
	if (new_map->protocol == MAP_PROTO_FILE) {
		fdata =
			rspamd_mempool_alloc0 (cfg->map_pool,
				sizeof (struct file_map_data));
		if (access (def, R_OK) == -1) {
			if (errno != ENOENT) {
				msg_err_config ("cannot open file '%s': %s", def, strerror
						(errno));
				return FALSE;

			}
			msg_info_config (
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
	else if (new_map->protocol == MAP_PROTO_HTTP) {
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
				msg_info_config ("bad http map definition: %s", def);
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
				msg_info_config ("bad http map definition: %s", def);
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
			msg_err_config ("address resolution for %s failed: %s",
				hdata->host,
				gai_strerror (r));
			return FALSE;
		}
		/* Now try to connect */
		if ((s = rspamd_socket_tcp (hdata->addr, FALSE, FALSE)) == -1) {
			msg_info_config ("cannot connect to http server %s: %d, %s",
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
	rspamd_cryptobox_hash (cksum, new_map->uri, strlen (new_map->uri), NULL, 0);
	cksum_encoded = rspamd_encode_base32 (cksum, sizeof (cksum));
	new_map->pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), "map");
	memcpy (new_map->pool->tag.uid, cksum_encoded,
			sizeof (new_map->pool->tag.uid));
	g_free (cksum_encoded);
	pool = new_map->pool;
	msg_info_pool ("added map %s", new_map->uri);


	cfg->maps = g_list_prepend (cfg->maps, new_map);

	return TRUE;
}

static gchar*
strip_map_elt (rspamd_mempool_t *pool, const gchar *start,
		size_t len)
{
	gchar *res = NULL;
	const gchar *c = start, *p = start + len - 1;

	/* Strip starting spaces */
	while (g_ascii_isspace (*c)) {
		c ++;
	}

	/* Strip ending spaces */
	while (g_ascii_isspace (*p) && p >= c) {
		p --;
	}

	/* One symbol up */
	p ++;

	if (p - c > 0) {
		res = rspamd_mempool_alloc (pool, p - c + 1);
		rspamd_strlcpy (res, c, p - c + 1);
	}

	return res;
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
	gchar *c, *p, *key = NULL, *value = NULL, *end;

	p = chunk;
	c = p;
	end = p + len;

	while (p < end) {
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
					msg_debug_pool ("insert kv pair: %s -> %s", key, value);
				}
				data->state = 99;
			}
			else if (*p == '\r' || *p == '\n') {
				if (key != NULL && p - c >= 0) {
					value = rspamd_mempool_alloc (pool, p - c + 1);
					memcpy (value, c, p - c);
					value[p - c] = '\0';

					value = g_strstrip (value);
					func (data->cur_data, key, value);
					msg_debug_pool ("insert kv pair: %s -> %s", key, value);
				}
				else if (key == NULL && p - c > 0) {
					/* Key only line */
					key = rspamd_mempool_alloc (pool, p - c + 1);
					memcpy (key, c, p - c);
					key[p - c] = '\0';
					value = rspamd_mempool_alloc (pool, 1);
					*value = '\0';
					func (data->cur_data, key, value);
					msg_debug_pool ("insert kv pair: %s -> %s", key, value);
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
				while ((*p == '\r' || *p == '\n') && p < end) {
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
	gchar *p, *c, *end, *s;

	p = chunk;
	c = p;
	end = p + len;

	while (p < end) {
		switch (data->state) {
		/* READ_SYMBOL */
		case 0:
			if (*p == '#') {
				/* Got comment */
				if (p > c) {
					/* Save previous string in lines like: "127.0.0.1 #localhost" */
					s = strip_map_elt (pool, c, p - c);

					if (s) {
						func (data->cur_data, s, hash_fill);
						msg_debug_pool ("insert element (before comment): %s", s);
					}
				}
				c = p;
				data->state = 1;
			}
			else if ((*p == '\r' || *p == '\n') && p > c) {
				/* Got EOL marker, save stored string */
				s = strip_map_elt (pool, c, p - c);

				if (s) {
					func (data->cur_data, s, hash_fill);
					msg_debug_pool ("insert element (before EOL): %s", s);
				}
				/* Skip EOL symbols */
				while ((*p == '\r' || *p == '\n') && p < end) {
					p++;
				}

				if (p == end) {
					p ++;
					c = NULL;
				}
				else {
					c = p;
				}
			}
			else {
				p++;
			}
			break;
		/* SKIP_COMMENT */
		case 1:
			/* Skip comment till end of line */
			if (*p == '\r' || *p == '\n') {
				while ((*p == '\r' || *p == '\n') && p < end) {
					p++;
				}

				if (p == end) {
					p ++;
					c = NULL;
				}
				else {
					c = p;
				}
				data->state = 0;
			}
			else {
				p++;
			}
			break;
		}
	}

	if (c >= end) {
		c = NULL;
	}

	return c;
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
		msg_info_pool ("read hash of %d elements", g_hash_table_size
				(data->cur_data));
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
		msg_info_pool ("read hash of %d elements", g_hash_table_size
				(data->cur_data));
	}
}

gchar *
rspamd_radix_read (rspamd_mempool_t * pool,
	gchar * chunk,
	gint len,
	struct map_cb_data *data)
{
	radix_compressed_t *tree;
	rspamd_mempool_t *rpool;

	if (data->cur_data == NULL) {
		tree = radix_create_compressed ();
		rpool = radix_get_pool (tree);
		memcpy (rpool->tag.uid, pool->tag.uid, sizeof (rpool->tag.uid));
		data->cur_data = tree;
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
		msg_info_pool ("read radix trie of %z elements: %s",
				radix_get_size (data->cur_data), radix_get_info (data->cur_data));
	}
}
