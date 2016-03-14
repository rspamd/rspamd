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
#include "http_parser.h"

static const gchar *hash_fill = "1";
static void free_http_cbdata (struct http_callback_data *cbd);
/**
 * Write HTTP request
 */
static void
write_http_request (struct http_callback_data *cbd)
{
	gchar datebuf[128];
	struct rspamd_http_message *msg;
	rspamd_mempool_t *pool;

	pool = cbd->map->pool;

	if (cbd->fd != -1) {
		close (cbd->fd);
	}

	cbd->fd = rspamd_inet_address_connect (cbd->addr, SOCK_STREAM, TRUE);

	if (cbd->fd != -1) {
		msg = rspamd_http_new_message (HTTP_REQUEST);

		if (cbd->stage == map_load_file) {
			msg->url = rspamd_fstring_new_init (cbd->data->path, strlen (cbd->data->path));

			if (cbd->data->last_checked != 0 && cbd->stage == map_load_file) {
				rspamd_http_date_format (datebuf, sizeof (datebuf),
						cbd->data->last_checked);
				rspamd_http_message_add_header (msg, "If-Modified-Since", datebuf);
			}
		}
		else if (cbd->stage == map_load_pubkey) {
			msg->url = rspamd_fstring_new_init (cbd->data->path, strlen (cbd->data->path));
			msg->url = rspamd_fstring_append (msg->url, ".pub", 4);
		}
		else if (cbd->stage == map_load_signature) {
			msg->url = rspamd_fstring_new_init (cbd->data->path, strlen (cbd->data->path));
			msg->url = rspamd_fstring_append (msg->url, ".sig", 4);
		}
		else {
			g_assert_not_reached ();
		}

		rspamd_http_connection_write_message (cbd->conn, msg, cbd->data->host,
				NULL, cbd, cbd->fd, &cbd->tv, cbd->ev_base);
		REF_RETAIN (cbd);
	}
	else {
		msg_err_pool ("cannot connect to %s: %s", cbd->data->host,
				strerror (errno));
	}
}

static gboolean
rspamd_map_check_sig_pk (const char *fname,
		struct rspamd_map *map,
		const guchar *input,
		gsize inlen,
		struct rspamd_cryptobox_pubkey *pk)
{
	gchar fpath[PATH_MAX];
	rspamd_mempool_t *pool = map->pool;
	guchar *data;
	GString *b32_key;
	gsize len = 0;

	/* Now load signature */
	rspamd_snprintf (fpath, sizeof (fpath), "%s.sig", fname);
	data = rspamd_file_xmap (fpath, PROT_READ, &len);

	if (data == NULL) {
		msg_err_pool ("can't open signature %s: %s", fpath, strerror (errno));
		return FALSE;
	}

	if (len != rspamd_cryptobox_signature_bytes (RSPAMD_CRYPTOBOX_MODE_25519)) {
		msg_err_pool ("can't open signature %s: invalid signature", fpath);
		munmap (data, len);

		return FALSE;
	}

	if (!rspamd_cryptobox_verify (data, input, inlen,
			rspamd_pubkey_get_pk (pk, NULL), RSPAMD_CRYPTOBOX_MODE_25519)) {
		msg_err_pool ("can't verify signature %s: incorrect signature", fpath);
		munmap (data, len);

		return FALSE;
	}

	b32_key = rspamd_pubkey_print (pk,
			RSPAMD_KEYPAIR_BASE32|RSPAMD_KEYPAIR_PUBKEY);
	msg_info_pool ("verified signature in file %s using trusted key %v",
			fpath, b32_key);
	g_string_free (b32_key, TRUE);

	munmap (data, len);

	return TRUE;
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
	gboolean ret;
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

	ret = rspamd_map_check_sig_pk (fname, map, input, inlen, pk);
	rspamd_pubkey_unref (pk);

	return ret;
}

/**
 * Callback for destroying HTTP callback data
 */
static void
free_http_cbdata (struct http_callback_data *cbd)
{
	char fpath[PATH_MAX];
	struct stat st;

	if (cbd->out_fd != -1) {
		close (cbd->out_fd);
	}

	rspamd_snprintf (fpath, sizeof (fpath), "%s", cbd->tmpfile);
	if (stat (fpath, &st) != -1 && S_ISREG (st.st_mode)) {
		(void)unlink (fpath);
	}

	rspamd_snprintf (fpath, sizeof (fpath), "%s.pub", cbd->tmpfile);
	if (stat (fpath, &st) != -1 && S_ISREG (st.st_mode)) {
		(void)unlink (fpath);
	}

	rspamd_snprintf (fpath, sizeof (fpath), "%s.sig", cbd->tmpfile);
	if (stat (fpath, &st) != -1 && S_ISREG (st.st_mode)) {
		(void)unlink (fpath);
	}

	if (cbd->pk) {
		rspamd_pubkey_unref (cbd->pk);
	}

	if (cbd->conn) {
		rspamd_http_connection_unref (cbd->conn);
		cbd->conn = NULL;
	}

	if (cbd->fd != -1) {
		close (cbd->fd);
	}

	if (cbd->addr) {
		rspamd_inet_address_destroy (cbd->addr);
	}

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
	REF_RELEASE (cbd);
}

static int
http_map_finish (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg)
{
	struct http_callback_data *cbd = conn->ud;
	struct rspamd_map *map;
	rspamd_mempool_t *pool;
	char fpath[PATH_MAX];
	guchar *aux_data, *in = NULL;
	gsize inlen = 0;
	struct stat st;

	map = cbd->map;
	pool = cbd->map->pool;

	if (msg->code == 200) {

		if (cbd->stage == map_load_file) {
			if (msg->last_modified) {
				cbd->data->last_checked = msg->last_modified;
			}
			else {
				cbd->data->last_checked = msg->date;
			}

			/* Maybe we need to check signature ? */
			if (map->is_signed) {
				close (cbd->out_fd);

				if (map->trusted_pubkey) {
					/* No need to load key */
					cbd->stage = map_load_signature;
					cbd->pk = rspamd_pubkey_ref (map->trusted_pubkey);
					rspamd_snprintf (fpath, sizeof (fpath), "%s.sig",
							cbd->tmpfile);
				}
				else {
					rspamd_snprintf (fpath, sizeof (fpath), "%s.pub",
							cbd->tmpfile);
					cbd->stage = map_load_pubkey;
				}

				cbd->out_fd = rspamd_file_xopen (fpath, O_RDWR|O_CREAT, 00644);

				if (cbd->out_fd == -1) {
					msg_err_pool ("cannot open pubkey file %s for writing: %s",
							fpath, strerror (errno));
					goto end;
				}

				rspamd_http_connection_reset (cbd->conn);
				write_http_request (cbd);

				goto end;
			}
			else {
				/* Unsinged version - just open file */
				in = rspamd_file_xmap (cbd->tmpfile, PROT_READ, &inlen);

				if (in == NULL) {
					msg_err_pool ("cannot read tempfile %s: %s", cbd->tmpfile,
							strerror (errno));
					goto end;
				}
			}
		}
		else if (cbd->stage == map_load_pubkey) {
			/* We now can load pubkey */
			(void)lseek (cbd->out_fd, 0, SEEK_SET);

			if (fstat (cbd->out_fd, &st) == -1) {
				msg_err_pool ("cannot stat pubkey file %s: %s",
						fpath, strerror (errno));
				goto end;
			}

			aux_data = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED,
					cbd->out_fd, 0);
			close (cbd->out_fd);
			cbd->out_fd = -1;

			if (aux_data == MAP_FAILED) {
				msg_err_pool ("cannot map pubkey file %s: %s",
						fpath, strerror (errno));
				goto end;
			}

			cbd->pk = rspamd_pubkey_from_base32 (aux_data, st.st_size,
					RSPAMD_KEYPAIR_SIGN, RSPAMD_CRYPTOBOX_MODE_25519);
			munmap (aux_data, st.st_size);

			if (cbd->pk == NULL) {
				msg_err_pool ("cannot load pubkey file %s: bad pubkey",
						fpath);
				goto end;
			}

			rspamd_snprintf (fpath, sizeof (fpath), "%s.sig", cbd->tmpfile);
			cbd->out_fd = rspamd_file_xopen (fpath, O_RDWR|O_CREAT, 00644);

			if (cbd->out_fd == -1) {
				msg_err_pool ("cannot open signature file %s for writing: %s",
						fpath, strerror (errno));
				goto end;
			}

			cbd->stage = map_load_signature;
			rspamd_http_connection_reset (cbd->conn);
			write_http_request (cbd);

			goto end;
		}
		else if (cbd->stage == map_load_signature) {
			/* We can now check signature */
			close (cbd->out_fd);
			cbd->out_fd = -1;

			in = rspamd_file_xmap (cbd->tmpfile, PROT_READ, &inlen);

			if (in == NULL) {
				msg_err_pool ("cannot read tempfile %s: %s", cbd->tmpfile,
						strerror (errno));
				goto end;
			}

			if (!rspamd_map_check_sig_pk (cbd->tmpfile, map, in, inlen, cbd->pk)) {
				goto end;
			}
		}

		g_assert (in != NULL);

		map->read_callback (map->pool, in, inlen, &cbd->cbdata, TRUE);
		map->fin_callback (map->pool, &cbd->cbdata);

		*map->user_data = cbd->cbdata.cur_data;
		msg_info_pool ("read map data from %s", cbd->data->host);
	}
	else if (msg->code == 304 && cbd->stage == map_load_file) {
		msg_debug_pool ("data is not modified for server %s",
				cbd->data->host);

		if (msg->last_modified) {
			cbd->data->last_checked = msg->last_modified;
		}
		else {
			cbd->data->last_checked = msg->date;
		}
	}
	else {
		msg_info_pool ("cannot load map %s from %s: HTTP error %d",
				map->uri, cbd->data->host, msg->code);
	}

end:
	REF_RELEASE (cbd);

	return 0;
}

static int
http_map_read (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg,
	const gchar *chunk,
	gsize len)
{
	struct http_callback_data *cbd = conn->ud;
	rspamd_mempool_t *pool;

	if (msg->code != 200 || len == 0) {
		/* Ignore not full replies */
		return 0;
	}

	pool = cbd->map->pool;

	if (write (cbd->out_fd, chunk, len) == -1) {
		msg_err_pool ("cannot write to %s: %s", cbd->tmpfile, strerror (errno));
		REF_RELEASE (cbd);

		return -1;
	}

	return 0;
}

/**
 * Callback for reading data from file
 */
static gboolean
read_map_file (struct rspamd_map *map, struct file_map_data *data)
{
	struct map_cb_data cbdata;
	guchar *bytes;
	gsize len;
	rspamd_mempool_t *pool = map->pool;

	if (map->read_callback == NULL || map->fin_callback == NULL) {
		msg_err_pool ("bad callback for reading map file");
		return FALSE;
	}

	if (access (data->filename, R_OK) == -1) {
		/* File does not exist, skipping */
		msg_err_pool ("map file is unavailable for reading");
		return FALSE;
	}

	bytes = rspamd_file_xmap (data->filename, PROT_READ, &len);

	if (bytes == NULL) {
		msg_err_pool ("can't open map %s: %s", data->filename, strerror (errno));
		return FALSE;
	}

	cbdata.state = 0;
	cbdata.prev_data = *map->user_data;
	cbdata.cur_data = NULL;
	cbdata.map = map;

	if (map->is_signed) {
		if (!rspamd_map_check_file_sig (data->filename, map, bytes, len)) {
			munmap (bytes, len);

			return FALSE;
		}
	}

	if (len > 0) {
		map->read_callback (map->pool, bytes, len, &cbdata, TRUE);
		map->fin_callback (map->pool, &cbdata);
		*map->user_data = cbdata.cur_data;
	}

	munmap (bytes, len);

	return TRUE;
}

static void
jitter_timeout_event (struct rspamd_map *map,
		gboolean locked, gboolean initial, gboolean errored)
{
	const gdouble error_mult = 20.0, lock_mult = 4.0;
	gdouble jittered_sec;
	gdouble timeout;

	if (initial) {
		timeout = 0.0;
	}
	else if (errored) {
		timeout = map->cfg->map_timeout * error_mult;
	}
	else if (locked) {
		timeout = map->cfg->map_timeout * lock_mult;
	}
	else {
		timeout = map->cfg->map_timeout;
	}

	/* Plan event again with jitter */
	evtimer_del (&map->ev);
	jittered_sec = rspamd_time_jitter (timeout, 0);
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

	if (!g_atomic_int_compare_and_exchange (map->locked, 0, 1)) {
		msg_info_pool (
			"don't try to reread map as it is locked by other process, will reread it later");
		jitter_timeout_event (map, TRUE, FALSE, FALSE);
		return;
	}

	if (stat (data->filename, &st) != -1 &&
		(st.st_mtime > data->st.st_mtime || data->st.st_mtime == -1)) {
		/* File was modified since last check */
		memcpy (&data->st, &st, sizeof (struct stat));
	}
	else {
		g_atomic_int_set (map->locked, 0);
		jitter_timeout_event (map, FALSE, FALSE, FALSE);
		return;
	}

	msg_info_pool ("rereading map file %s", data->filename);

	if (!read_map_file (map, data)) {
		jitter_timeout_event (map, FALSE, FALSE, TRUE);
	}
	else {
		jitter_timeout_event (map, FALSE, FALSE, FALSE);
	}

	g_atomic_int_set (map->locked, 0);
}


static void
rspamd_map_dns_callback (struct rdns_reply *reply, void *arg)
{
	struct http_callback_data *cbd = arg;
	rspamd_mempool_t *pool;

	pool = cbd->map->pool;

	if (reply->code == RDNS_RC_NOERROR) {
		/*
		 * We just get the first address hoping that a resolver performs
		 * round-robin rotation well
		 */
		if (cbd->addr == NULL) {
			cbd->addr = rspamd_inet_address_from_rnds (reply->entries);

			if (cbd->addr != NULL) {
				rspamd_inet_address_set_port (cbd->addr, cbd->data->port);
				/* Try to open a socket */
				cbd->fd = rspamd_inet_address_connect (cbd->addr, SOCK_STREAM,
						TRUE);

				if (cbd->fd != -1) {
					cbd->stage = map_load_file;
					cbd->conn = rspamd_http_connection_new (http_map_read,
							http_map_error, http_map_finish,
							RSPAMD_HTTP_BODY_PARTIAL|RSPAMD_HTTP_CLIENT_SIMPLE,
							RSPAMD_HTTP_CLIENT, NULL);

					write_http_request (cbd);
				}
				else {
					rspamd_inet_address_destroy (cbd->addr);
					cbd->addr = NULL;
				}
			}
		}
	}
	else if (cbd->stage < map_load_file) {
		if (cbd->stage == map_resolve_host2) {
			/* We have still one request pending */
			cbd->stage = map_resolve_host1;
		}
		else {
			/* We could not resolve host, so cowardly fail here */
			msg_err_pool ("cannot resolve %s", cbd->data->host);
		}
	}

	REF_RELEASE (cbd);
}

/**
 * Async HTTP callback
 */
static void
http_callback (gint fd, short what, void *ud)
{
	struct rspamd_map *map = ud;
	struct http_map_data *data;
	struct http_callback_data *cbd;
	rspamd_mempool_t *pool;
	gchar tmpbuf[PATH_MAX];

	data = map->map_data;
	pool = map->pool;

	/* Plan event */
	cbd = g_slice_alloc0 (sizeof (struct http_callback_data));

	rspamd_snprintf (tmpbuf, sizeof (tmpbuf),
			"%s" G_DIR_SEPARATOR_S "rspamd_map%d-XXXXXX",
			map->cfg->temp_dir, map->id);
	cbd->out_fd = mkstemp (tmpbuf);

	if (cbd->out_fd == -1) {
		g_slice_free1 (sizeof (*cbd), cbd);
		msg_err_pool ("cannot create tempfile: %s", strerror (errno));
		jitter_timeout_event (map, FALSE, FALSE, TRUE);

		return;
	}

	cbd->tmpfile = g_strdup (tmpbuf);
	cbd->ev_base = map->ev_base;
	cbd->map = map;
	cbd->data = data;
	cbd->fd = -1;
	cbd->cbdata.state = 0;
	cbd->cbdata.prev_data = *cbd->map->user_data;
	cbd->cbdata.cur_data = NULL;
	cbd->cbdata.map = cbd->map;
	cbd->stage = map_resolve_host2;
	double_to_tv (map->cfg->map_timeout, &cbd->tv);
	REF_INIT_RETAIN (cbd, free_http_cbdata);

	msg_debug_pool ("reading map data from %s", data->host);
	/* Send both A and AAAA requests */
	if (map->r->r) {
		if (rdns_make_request_full (map->r->r, rspamd_map_dns_callback, cbd,
				map->cfg->dns_timeout, map->cfg->dns_retransmits, 1,
				data->host, RDNS_REQUEST_A)) {
			REF_RETAIN (cbd);
		}
		if (rdns_make_request_full (map->r->r, rspamd_map_dns_callback, cbd,
				map->cfg->dns_timeout, map->cfg->dns_retransmits, 1,
				data->host, RDNS_REQUEST_AAAA)) {
			REF_RETAIN (cbd);
		}
		jitter_timeout_event (map, FALSE, FALSE, FALSE);
	}
	else {
		msg_warn_pool ("cannot load map: DNS resolver is not initialized");
		jitter_timeout_event (map, FALSE, FALSE, TRUE);
	}

	/* We don't need own ref as it is now refcounted by DNS requests */
	REF_RELEASE (cbd);
}

/* Start watching event for all maps */
void
rspamd_map_watch (struct rspamd_config *cfg,
		struct event_base *ev_base,
		struct rspamd_dns_resolver *resolver)
{
	GList *cur = cfg->maps;
	struct rspamd_map *map;
	struct file_map_data *fdata;

	/* First of all do synced read of data */
	while (cur) {
		map = cur->data;
		map->ev_base = ev_base;
		map->r = resolver;
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
			jitter_timeout_event (map, FALSE, TRUE, FALSE);
		}
		else if (map->protocol == MAP_PROTO_HTTP) {
			evtimer_set (&map->ev, http_callback, map);
			jitter_timeout_event (map, FALSE, TRUE, FALSE);
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
rspamd_map_is_map (const gchar *map_line)
{
	gboolean ret = FALSE;

	g_assert (map_line != NULL);

	if (map_line[0] == '/') {
		ret = TRUE;
	}
	else if (g_ascii_strncasecmp (map_line, "sign+", sizeof ("sign+") - 1) == 0) {
		ret = TRUE;
	}
	else if (g_ascii_strncasecmp (map_line, "file://", sizeof ("file://") - 1) == 0) {
		ret = TRUE;
	}
	else if (g_ascii_strncasecmp (map_line, "http://", sizeof ("file://") - 1) == 0) {
		ret = TRUE;
	}

	return ret;
}

struct rspamd_map *
rspamd_map_add (struct rspamd_config *cfg,
	const gchar *map_line,
	const gchar *description,
	map_cb_t read_callback,
	map_fin_cb_t fin_callback,
	void **user_data)
{
	struct rspamd_map *new_map;
	const gchar *def;
	struct file_map_data *fdata;
	struct http_map_data *hdata;
	gchar *cksum_encoded, cksum[rspamd_cryptobox_HASHBYTES];
	rspamd_mempool_t *pool;
	struct http_parser_url up;
	rspamd_ftok_t tok;

	if (cfg->map_pool == NULL) {
		cfg->map_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
				"map");
		memcpy (cfg->map_pool->tag.uid, cfg->cfg_pool->tag.uid,
				sizeof (cfg->map_pool->tag.uid));
	}

	new_map = rspamd_mempool_alloc0 (cfg->map_pool, sizeof (struct rspamd_map));

	/* First of all detect protocol line */
	if (rspamd_map_check_proto (cfg, map_line, new_map) == NULL) {
		return NULL;
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
				return NULL;

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

		memset (&up, 0, sizeof (up));
		if (http_parser_parse_url (new_map->uri, strlen (new_map->uri), FALSE,
				&up) != 0) {
			msg_err_config ("cannot parse HTTP url: %s", new_map->uri);
			return NULL;
		}
		else {
			if (!(up.field_set & 1 << UF_HOST)) {
				msg_err_config ("cannot parse HTTP url: %s: no host", new_map->uri);
				return NULL;
			}

			tok.begin = new_map->uri + up.field_data[UF_HOST].off;
			tok.len = up.field_data[UF_HOST].len;
			hdata->host = rspamd_mempool_ftokdup (cfg->map_pool, &tok);

			if (up.field_set & 1 << UF_PORT) {
				hdata->port = up.port;
			}
			else {
				hdata->port = 80;
			}

			if (up.field_set & 1 << UF_PATH) {
				tok.begin = new_map->uri + up.field_data[UF_PATH].off;
				tok.len = strlen (tok.begin);

				hdata->path = rspamd_mempool_ftokdup (cfg->map_pool, &tok);
			}
		}

		new_map->map_data = hdata;

	}

	/* Temp pool */
	rspamd_cryptobox_hash (cksum, new_map->uri, strlen (new_map->uri), NULL, 0);
	cksum_encoded = rspamd_encode_base32 (cksum, sizeof (cksum));
	new_map->pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), "map");
	rspamd_strlcpy (new_map->pool->tag.uid, cksum_encoded,
			sizeof (new_map->pool->tag.uid));
	g_free (cksum_encoded);
	pool = new_map->pool;
	msg_info_pool ("added map %s", new_map->uri);


	cfg->maps = g_list_prepend (cfg->maps, new_map);

	return new_map;
}

/**
 * FSM for parsing lists
 */

#define MAP_STORE_KEY do { \
	key = rspamd_mempool_alloc (pool, p - c + 1); \
	rspamd_strlcpy (key, c, p - c + 1); \
} while (0)

#define MAP_STORE_VALUE do { \
	value = rspamd_mempool_alloc (pool, p - c + 1); \
	rspamd_strlcpy (value, c, p - c + 1); \
	value = g_strstrip (value); \
} while (0)

gchar *
rspamd_parse_kv_list (rspamd_mempool_t * pool,
	gchar * chunk,
	gint len,
	struct map_cb_data *data,
	insert_func func,
	const gchar *default_value,
	gboolean final)
{
	enum {
		map_skip_spaces_before_key = 0,
		map_read_key,
		map_read_key_quoted,
		map_read_key_slashed,
		map_skip_spaces_after_key,
		map_read_value,
		map_read_value_quoted,
		map_read_comment_start,
		map_skip_comment,
		map_read_eol,
	};

	gchar *c, *p, *key = NULL, *value = NULL, *end;

	p = chunk;
	c = p;
	end = p + len;

	while (p < end) {
		switch (data->state) {
		case map_skip_spaces_before_key:
			if (g_ascii_isspace (*p)) {
				p ++;
			}
			else {
				c = p;
				data->state = map_read_key;
			}
			break;
		case map_read_key:
			/* read key */
			/* Check here comments, eol and end of buffer */
			if (*p == '#') {
				if (p - c > 0) {
					/* Store a single key */
					MAP_STORE_KEY;
					func (data->cur_data, key, default_value);
					msg_debug_pool ("insert key only pair: %s -> %s",
							key, default_value);
					key = NULL;
				}

				data->state = map_read_comment_start;
			}
			else if (*p == '\r' || *p == '\n') {
				if (p - c > 0) {
					/* Store a single key */
					MAP_STORE_KEY;
					func (data->cur_data, key, default_value);
					msg_debug_pool ("insert key only pair: %s -> %s",
							key, default_value);
					key = NULL;
				}

				data->state = map_read_eol;
				key = NULL;
			}
			else if (g_ascii_isspace (*p)) {
				if (p - c > 0) {
					MAP_STORE_KEY;
					data->state = map_skip_spaces_after_key;
				}
				else {
					/* Should not happen */
					g_assert_not_reached ();
				}
			}
			else {
				p++;
			}
			break;
		case map_skip_spaces_after_key:
			if (g_ascii_isspace (*p)) {
				p ++;
			}
			else {
				c = p;
				data->state = map_read_value;
			}
			break;
		case map_read_value:
			g_assert (key != NULL);
			if (*p == '#') {
				if (p - c > 0) {
					/* Store a single key */
					MAP_STORE_VALUE;
					func (data->cur_data, key, value);
					msg_debug_pool ("insert key value pair: %s -> %s",
							key, value);
					key = NULL;
					value = NULL;
				}
				else {
					func (data->cur_data, key, default_value);
					msg_debug_pool ("insert key only pair: %s -> %s",
							key, default_value);
					key = NULL;
				}

				data->state = map_read_comment_start;
			}
			else if (*p == '\r' || *p == '\n') {
				if (p - c > 0) {
					/* Store a single key */
					MAP_STORE_VALUE;
					func (data->cur_data, key, value);
					msg_debug_pool ("insert key value pair: %s -> %s",
							key, value);
					key = NULL;
					value = NULL;
				}
				else {
					func (data->cur_data, key, default_value);
					msg_debug_pool ("insert key only pair: %s -> %s",
							key, default_value);
					key = NULL;
				}

				data->state = map_read_eol;
				key = NULL;
			}
			else {
				p ++;
			}
			break;
		case map_read_comment_start:
			if (*p == '#') {
				data->state = map_skip_comment;
				p ++;
				key = NULL;
				value = NULL;
			}
			else {
				g_assert_not_reached ();
			}
			break;
		case map_skip_comment:
			if (*p == '\r' || *p == '\n') {
				data->state = map_read_eol;
			}
			else {
				p ++;
			}
			break;
		case map_read_eol:
			/* Skip \r\n and whitespaces */
			if (*p == '\r' || *p == '\n') {
				p++;
			}
			else {
				data->state = map_skip_spaces_before_key;
			}
			break;
		default:
			g_assert_not_reached ();
			break;
		}
	}

	if (final) {
		/* Examine the state */
		switch (data->state) {
		case map_read_key:
			if (p - c > 0) {
				/* Store a single key */
				MAP_STORE_KEY;
				func (data->cur_data, key, default_value);
				msg_debug_pool ("insert key only pair: %s -> %s",
						key, default_value);
				key = NULL;
			}
			break;
		case map_read_value:
			g_assert (key != NULL);
			if (p - c > 0) {
				/* Store a single key */
				MAP_STORE_VALUE;
				func (data->cur_data, key, value);
				msg_debug_pool ("insert key value pair: %s -> %s",
						key, value);
				key = NULL;
				value = NULL;
			}
			else {
				func (data->cur_data, key, default_value);
				msg_debug_pool ("insert key only pair: %s -> %s",
						key, default_value);
				key = NULL;
			}
			break;
		}
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

	rspamd_radix_add_iplist ((gchar *)key, " ,;", tree, value);
}

/* Helpers */
gchar *
rspamd_hosts_read (rspamd_mempool_t * pool,
	gchar * chunk,
	gint len,
	struct map_cb_data *data,
	gboolean final)
{
	if (data->cur_data == NULL) {
		data->cur_data = g_hash_table_new (rspamd_strcase_hash,
				rspamd_strcase_equal);
	}
	return rspamd_parse_kv_list (pool,
			   chunk,
			   len,
			   data,
			   (insert_func) g_hash_table_insert,
			   hash_fill,
			   final);
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
	struct map_cb_data *data,
	gboolean final)
{
	if (data->cur_data == NULL) {
		data->cur_data = g_hash_table_new (rspamd_strcase_hash,
				rspamd_strcase_equal);
	}
	return rspamd_parse_kv_list (pool,
			   chunk,
			   len,
			   data,
			   (insert_func) g_hash_table_insert,
			   "",
			   final);
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
	struct map_cb_data *data,
	gboolean final)
{
	radix_compressed_t *tree;
	rspamd_mempool_t *rpool;

	if (data->cur_data == NULL) {
		tree = radix_create_compressed ();
		rpool = radix_get_pool (tree);
		memcpy (rpool->tag.uid, pool->tag.uid, sizeof (rpool->tag.uid));
		data->cur_data = tree;
	}
	return rspamd_parse_kv_list (pool,
			   chunk,
			   len,
			   data,
			   (insert_func) radix_tree_insert_helper,
			   hash_fill,
			   final);
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
