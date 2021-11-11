/*-
 * Copyright 2019 Vsevolod Stakhov
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
#include "libserver/http/http_connection.h"
#include "libserver/http/http_private.h"
#include "rspamd.h"
#include "contrib/libev/ev.h"
#include "contrib/uthash/utlist.h"

#ifdef SYS_ZSTD
#  include "zstd.h"
#else
#  include "contrib/zstd/zstd.h"
#endif

#undef MAP_DEBUG_REFS
#ifdef MAP_DEBUG_REFS
#define MAP_RETAIN(x, t) do { \
	msg_err (G_GNUC_PRETTY_FUNCTION ": " t ": retain ref %p, refcount: %d -> %d", (x), (x)->ref.refcount, (x)->ref.refcount + 1); \
	REF_RETAIN(x);	\
} while (0)

#define MAP_RELEASE(x, t) do { \
	msg_err (G_GNUC_PRETTY_FUNCTION ": " t ": release ref %p, refcount: %d -> %d", (x), (x)->ref.refcount, (x)->ref.refcount - 1); \
	REF_RELEASE(x);	\
} while (0)
#else
#define MAP_RETAIN(x, t) REF_RETAIN(x)
#define MAP_RELEASE(x, t) REF_RELEASE(x)
#endif

enum rspamd_map_periodic_opts {
	RSPAMD_MAP_SCHEDULE_NORMAL = 0,
	RSPAMD_MAP_SCHEDULE_ERROR = (1u << 0u),
	RSPAMD_MAP_SCHEDULE_LOCKED = (1u << 1u),
	RSPAMD_MAP_SCHEDULE_INIT = (1u << 2u),
};

static void free_http_cbdata_common (struct http_callback_data *cbd,
									 gboolean plan_new);
static void free_http_cbdata_dtor (gpointer p);
static void free_http_cbdata (struct http_callback_data *cbd);
static void rspamd_map_process_periodic (struct map_periodic_cbdata *cbd);
static void rspamd_map_schedule_periodic (struct rspamd_map *map, int how);
static gboolean read_map_file_chunks (struct rspamd_map *map,
									  struct map_cb_data *cbdata,
									  const gchar *fname,
									  gsize len,
									  goffset off);
static gboolean rspamd_map_save_http_cached_file (struct rspamd_map *map,
												  struct rspamd_map_backend *bk,
												  struct http_map_data *htdata,
												  const guchar *data,
												  gsize len);
static gboolean rspamd_map_update_http_cached_file (struct rspamd_map *map,
												  struct rspamd_map_backend *bk,
												  struct http_map_data *htdata);

guint rspamd_map_log_id = (guint)-1;
RSPAMD_CONSTRUCTOR(rspamd_map_log_init)
{
	rspamd_map_log_id = rspamd_logger_add_debug_module("map");
}

/**
 * Write HTTP request
 */
static void
write_http_request (struct http_callback_data *cbd)
{
	gchar datebuf[128];
	struct rspamd_http_message *msg;

	msg = rspamd_http_new_message (HTTP_REQUEST);

	if (cbd->bk->protocol == MAP_PROTO_HTTPS) {
		msg->flags |= RSPAMD_HTTP_FLAG_SSL;
	}

	if (cbd->check) {
		msg->method = HTTP_HEAD;
	}

	msg->url = rspamd_fstring_append (msg->url,
			cbd->data->path, strlen (cbd->data->path));

	if (cbd->check) {
		if (cbd->data->last_modified != 0) {
			rspamd_http_date_format (datebuf, sizeof (datebuf),
					cbd->data->last_modified);
			rspamd_http_message_add_header (msg, "If-Modified-Since",
					datebuf);
		}
		if (cbd->data->etag) {
			rspamd_http_message_add_header_len (msg, "If-None-Match",
					cbd->data->etag->str, cbd->data->etag->len);
		}
	}

	msg->url = rspamd_fstring_append (msg->url, cbd->data->rest,
			strlen (cbd->data->rest));

	if (cbd->data->userinfo) {
		rspamd_http_message_add_header (msg, "Authorization",
				cbd->data->userinfo);
	}

	MAP_RETAIN (cbd, "http_callback_data");
	rspamd_http_connection_write_message (cbd->conn,
			msg,
			cbd->data->host,
			NULL,
			cbd,
			cbd->timeout);
}

/**
 * Callback for destroying HTTP callback data
 */
static void
free_http_cbdata_common (struct http_callback_data *cbd, gboolean plan_new)
{
	struct map_periodic_cbdata *periodic = cbd->periodic;

	if (cbd->shmem_data) {
		rspamd_http_message_shmem_unref (cbd->shmem_data);
	}

	if (cbd->pk) {
		rspamd_pubkey_unref (cbd->pk);
	}

	if (cbd->conn) {
		rspamd_http_connection_unref (cbd->conn);
		cbd->conn = NULL;
	}

	if (cbd->addrs) {
		rspamd_inet_addr_t *addr;
		guint i;

		PTR_ARRAY_FOREACH (cbd->addrs, i, addr) {
			rspamd_inet_address_free (addr);
		}

		g_ptr_array_free (cbd->addrs, TRUE);
	}


	MAP_RELEASE (cbd->bk, "rspamd_map_backend");

	if (periodic) {
		/* Detached in case of HTTP error */
		MAP_RELEASE (periodic, "periodic");
	}

	g_free (cbd);
}

static void
free_http_cbdata (struct http_callback_data *cbd)
{
	cbd->map->tmp_dtor = NULL;
	cbd->map->tmp_dtor_data = NULL;

	free_http_cbdata_common (cbd, TRUE);
}

static void
free_http_cbdata_dtor (gpointer p)
{
	struct http_callback_data *cbd = p;
	struct rspamd_map *map;

	map = cbd->map;
	if (cbd->stage == http_map_http_conn) {
		REF_RELEASE (cbd);
	}
	else {
		/* We cannot terminate DNS requests sent */
		cbd->stage = http_map_terminated;
	}

	msg_warn_map ("%s: "
				  "connection with http server is terminated: worker is stopping",
			map->name);
}

/*
 * HTTP callbacks
 */
static void
http_map_error (struct rspamd_http_connection *conn,
	GError *err)
{
	struct http_callback_data *cbd = conn->ud;
	struct rspamd_map *map;

	map = cbd->map;

	if (cbd->periodic) {
		cbd->periodic->errored = TRUE;
		msg_err_map ("error reading %s(%s): "
					 "connection with http server terminated incorrectly: %e",
				cbd->bk->uri,
				cbd->addr ? rspamd_inet_address_to_string_pretty (cbd->addr) : "",
				err);

		rspamd_map_process_periodic (cbd->periodic);
	}

	MAP_RELEASE (cbd, "http_callback_data");
}

static void
rspamd_map_cache_cb (struct ev_loop *loop, ev_timer *w, int revents)
{
	struct rspamd_http_map_cached_cbdata *cache_cbd = (struct rspamd_http_map_cached_cbdata *)
			w->data;
	struct rspamd_map *map;
	struct http_map_data *data;

	map = cache_cbd->map;
	data = cache_cbd->data;

	if (cache_cbd->gen != cache_cbd->data->gen) {
		/* We have another update, so this cache element is obviously expired */
		/*
		 * Important!: we do not set cache availability to zero here, as there
		 * might be fresh cache
		 */
		msg_info_map ("cached data is now expired (gen mismatch %L != %L) for %s",
				cache_cbd->gen, cache_cbd->data->gen, map->name);
		MAP_RELEASE (cache_cbd->shm, "rspamd_http_map_cached_cbdata");
		ev_timer_stop (loop, &cache_cbd->timeout);
		g_free (cache_cbd);
	}
	else if (cache_cbd->data->last_checked >= cache_cbd->last_checked) {
		/*
		 * We checked map but we have not found anything more recent,
		 * reschedule cache check
		 */
		if (cache_cbd->map->poll_timeout >
			rspamd_get_calendar_ticks () - cache_cbd->data->last_checked) {
			w->repeat = cache_cbd->map->poll_timeout -
						(rspamd_get_calendar_ticks () - cache_cbd->data->last_checked);
		}
		else {
			w->repeat = cache_cbd->map->poll_timeout;
		}

		if (w->repeat < 0) {
			msg_info_map ("cached data for %s has skewed check time: %d last checked, %d poll timeout, %.2f diff",
					map->name, (int)cache_cbd->data->last_checked,
					(int)cache_cbd->map->poll_timeout,
					(rspamd_get_calendar_ticks () - cache_cbd->data->last_checked));
			w->repeat = 0.0;
		}

		cache_cbd->last_checked = cache_cbd->data->last_checked;
		msg_debug_map ("cached data is up to date for %s", map->name);
		ev_timer_again (loop, &cache_cbd->timeout);
	}
	else {
		data->cur_cache_cbd = NULL;
		g_atomic_int_set (&data->cache->available, 0);
		MAP_RELEASE (cache_cbd->shm, "rspamd_http_map_cached_cbdata");
		msg_info_map ("cached data is now expired for %s", map->name);
		ev_timer_stop (loop, &cache_cbd->timeout);
		g_free (cache_cbd);
	}
}

static int
http_map_finish (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg)
{
	struct http_callback_data *cbd = conn->ud;
	struct rspamd_map *map;
	struct rspamd_map_backend *bk;
	struct http_map_data *data;
	struct rspamd_http_map_cached_cbdata *cache_cbd;
	const rspamd_ftok_t *expires_hdr, *etag_hdr;
	char next_check_date[128];
	guchar *in = NULL;
	gsize dlen = 0;

	map = cbd->map;
	bk = cbd->bk;
	data = bk->data.hd;

	if (msg->code == 200) {

		if (cbd->check) {
			msg_info_map ("need to reread map from %s", cbd->bk->uri);
			cbd->periodic->need_modify = TRUE;
			/* Reset the whole chain */
			cbd->periodic->cur_backend = 0;
			/* Reset cache, old cached data will be cleaned on timeout */
			g_atomic_int_set (&data->cache->available, 0);
			data->cur_cache_cbd = NULL;

			rspamd_map_process_periodic (cbd->periodic);
			MAP_RELEASE (cbd, "http_callback_data");

			return 0;
		}

		cbd->data->last_checked = msg->date;

		if (msg->last_modified) {
			cbd->data->last_modified = msg->last_modified;
		}
		else {
			cbd->data->last_modified = msg->date;
		}


		/* Unsigned version - just open file */
		cbd->shmem_data = rspamd_http_message_shmem_ref (msg);
		cbd->data_len = msg->body_buf.len;

		if (cbd->data_len == 0) {
			msg_err_map ("cannot read empty map");
			goto err;
		}

		g_assert (cbd->shmem_data != NULL);

		in = rspamd_shmem_xmap (cbd->shmem_data->shm_name, PROT_READ, &dlen);

		if (in == NULL) {
			msg_err_map ("cannot read tempfile %s: %s",
					cbd->shmem_data->shm_name,
					strerror (errno));
			goto err;
		}

		/* Check for expires */
		double cached_timeout = map->poll_timeout * 2;

		expires_hdr = rspamd_http_message_find_header (msg, "Expires");

		if (expires_hdr) {
			time_t hdate;

			hdate = rspamd_http_parse_date (expires_hdr->begin, expires_hdr->len);

			if (hdate != (time_t)-1 && hdate > msg->date) {
				cached_timeout = map->next_check - msg->date +
								 map->poll_timeout * 2;

				map->next_check = hdate;
			}
			else {
				msg_info_map ("invalid expires header: %T, ignore it", expires_hdr);
				map->next_check = 0;
			}
		}

		/* Check for etag */
		etag_hdr = rspamd_http_message_find_header (msg, "ETag");

		if (etag_hdr) {
			if (cbd->data->etag) {
				/* Remove old etag */
				rspamd_fstring_free (cbd->data->etag);
			}

			cbd->data->etag = rspamd_fstring_new_init (etag_hdr->begin,
					etag_hdr->len);
		}
		else {
			if (cbd->data->etag) {
				/* Remove and clear old etag */
				rspamd_fstring_free (cbd->data->etag);
				cbd->data->etag = NULL;
			}
		}

		MAP_RETAIN (cbd->shmem_data, "shmem_data");
		cbd->data->gen ++;
		/*
		 * We know that a map is in the locked state
		 */
		g_atomic_int_set (&data->cache->available, 1);
		/* Store cached data */
		rspamd_strlcpy (data->cache->shmem_name, cbd->shmem_data->shm_name,
				sizeof (data->cache->shmem_name));
		data->cache->len = cbd->data_len;
		data->cache->last_modified = cbd->data->last_modified;
		cache_cbd = g_malloc0 (sizeof (*cache_cbd));
		cache_cbd->shm = cbd->shmem_data;
		cache_cbd->event_loop = cbd->event_loop;
		cache_cbd->map = map;
		cache_cbd->data = cbd->data;
		cache_cbd->last_checked = cbd->data->last_checked;
		cache_cbd->gen = cbd->data->gen;
		MAP_RETAIN (cache_cbd->shm, "shmem_data");

		ev_timer_init (&cache_cbd->timeout, rspamd_map_cache_cb, cached_timeout,
				0.0);
		ev_timer_start (cbd->event_loop, &cache_cbd->timeout);
		cache_cbd->timeout.data = cache_cbd;
		data->cur_cache_cbd = cache_cbd;

		if (map->next_check) {
			rspamd_http_date_format (next_check_date, sizeof (next_check_date),
					map->next_check);
		}
		else {
			rspamd_http_date_format (next_check_date, sizeof (next_check_date),
					rspamd_get_calendar_ticks () + map->poll_timeout);
		}


		if (cbd->bk->is_compressed) {
			ZSTD_DStream *zstream;
			ZSTD_inBuffer zin;
			ZSTD_outBuffer zout;
			guchar *out;
			gsize outlen, r;

			zstream = ZSTD_createDStream ();
			ZSTD_initDStream (zstream);

			zin.pos = 0;
			zin.src = in;
			zin.size = dlen;

			if ((outlen = ZSTD_getDecompressedSize (zin.src, zin.size)) == 0) {
				outlen = ZSTD_DStreamOutSize ();
			}

			out = g_malloc (outlen);

			zout.dst = out;
			zout.pos = 0;
			zout.size = outlen;

			while (zin.pos < zin.size) {
				r = ZSTD_decompressStream (zstream, &zout, &zin);

				if (ZSTD_isError (r)) {
					msg_err_map ("%s(%s): cannot decompress data: %s",
							cbd->bk->uri,
							rspamd_inet_address_to_string_pretty (cbd->addr),
							ZSTD_getErrorName (r));
					ZSTD_freeDStream (zstream);
					g_free (out);
					MAP_RELEASE (cbd->shmem_data, "shmem_data");
					goto err;
				}

				if (zout.pos == zout.size) {
					/* We need to extend output buffer */
					zout.size = zout.size * 2 + 1.0;
					out = g_realloc (zout.dst, zout.size);
					zout.dst = out;
				}
			}

			ZSTD_freeDStream (zstream);
			msg_info_map ("%s(%s): read map data %z bytes compressed, "
					"%z uncompressed, next check at %s",
					cbd->bk->uri,
					rspamd_inet_address_to_string_pretty (cbd->addr),
					dlen, zout.pos, next_check_date);
			map->read_callback (out, zout.pos, &cbd->periodic->cbdata, TRUE);
			rspamd_map_save_http_cached_file (map, bk, cbd->data, out, zout.pos);
			g_free (out);
		}
		else {
			msg_info_map ("%s(%s): read map data %z bytes, next check at %s",
					cbd->bk->uri,
					rspamd_inet_address_to_string_pretty (cbd->addr),
					dlen, next_check_date);
			rspamd_map_save_http_cached_file (map, bk, cbd->data, in, cbd->data_len);
			map->read_callback (in, cbd->data_len, &cbd->periodic->cbdata, TRUE);
		}

		MAP_RELEASE (cbd->shmem_data, "shmem_data");

		cbd->periodic->cur_backend ++;
		munmap (in, dlen);
		rspamd_map_process_periodic (cbd->periodic);
	}
	else if (msg->code == 304 && cbd->check) {
		cbd->data->last_checked = msg->date;

		if (msg->last_modified) {
			cbd->data->last_modified = msg->last_modified;
		}
		else {
			cbd->data->last_modified = msg->date;
		}

		expires_hdr = rspamd_http_message_find_header (msg, "Expires");

		if (expires_hdr) {
			time_t hdate;

			hdate = rspamd_http_parse_date (expires_hdr->begin, expires_hdr->len);
			if (hdate != (time_t)-1 && hdate > msg->date) {
				map->next_check = hdate;
			}
			else {
				msg_info_map ("invalid expires header: %T, ignore it", expires_hdr);
				map->next_check = 0;
			}
		}

		etag_hdr = rspamd_http_message_find_header (msg, "ETag");

		if (etag_hdr) {
			if (cbd->data->etag) {
				/* Remove old etag */
				rspamd_fstring_free (cbd->data->etag);
				cbd->data->etag = rspamd_fstring_new_init (etag_hdr->begin,
						etag_hdr->len);
			}
		}

		if (map->next_check) {
			rspamd_http_date_format (next_check_date, sizeof (next_check_date),
					map->next_check);
			msg_info_map ("data is not modified for server %s, next check at %s "
						  "(http cache based: %T)",
					cbd->data->host, next_check_date, expires_hdr);
		}
		else {
			rspamd_http_date_format (next_check_date, sizeof (next_check_date),
					rspamd_get_calendar_ticks () + map->poll_timeout);
			msg_info_map ("data is not modified for server %s, next check at %s "
						  "(timer based)",
					cbd->data->host, next_check_date);
		}

		rspamd_map_update_http_cached_file (map, bk, cbd->data);
		cbd->periodic->cur_backend ++;
		rspamd_map_process_periodic (cbd->periodic);
	}
	else {
		msg_info_map ("cannot load map %s from %s: HTTP error %d",
				bk->uri, cbd->data->host, msg->code);
		goto err;
	}

	MAP_RELEASE (cbd, "http_callback_data");
	return 0;

err:
	cbd->periodic->errored = 1;
	rspamd_map_process_periodic (cbd->periodic);
	MAP_RELEASE (cbd, "http_callback_data");

	return 0;
}

static gboolean
read_map_file_chunks (struct rspamd_map *map, struct map_cb_data *cbdata,
		const gchar *fname, gsize len, goffset off)
{
	gint fd;
	gssize r, avail;
	gsize buflen = 1024 * 1024;
	gchar *pos, *bytes;

	fd = rspamd_file_xopen (fname, O_RDONLY, 0, TRUE);

	if (fd == -1) {
		msg_err_map ("can't open map for buffered reading %s: %s",
				fname, strerror (errno));
		return FALSE;
	}

	if (lseek (fd, off, SEEK_SET) == -1) {
		msg_err_map ("can't seek in map to pos %d for buffered reading %s: %s",
				(gint)off, fname, strerror (errno));
		close (fd);

		return FALSE;
	}

	buflen = MIN (len, buflen);
	bytes = g_malloc (buflen);
	avail = buflen;
	pos = bytes;

	while ((r = read (fd, pos, avail)) > 0) {
		gchar *end = bytes + (pos - bytes) + r;
		msg_debug_map ("%s: read map chunk, %z bytes", fname,
				r);
		pos = map->read_callback (bytes, end - bytes, cbdata, r == len);

		if (pos && pos > bytes && pos < end) {
			guint remain = end - pos;

			memmove (bytes, pos, remain);
			pos = bytes + remain;
			/* Need to preserve the remain */
			avail = ((gssize)buflen) - remain;

			if (avail <= 0) {
				/* Try realloc, too large element */
				g_assert (buflen >= remain);
				bytes = g_realloc (bytes, buflen * 2);

				pos = bytes + remain; /* Adjust */
				avail += buflen;
				buflen *= 2;
			}
		}
		else {
			avail = buflen;
			pos = bytes;
		}

		len -= r;
	}

	if (r == -1) {
		msg_err_map ("can't read from map %s: %s", fname, strerror (errno));
		close (fd);
		g_free (bytes);

		return FALSE;
	}

	close (fd);
	g_free (bytes);

	return TRUE;
}

static gboolean
rspamd_map_check_sig_pk_mem (const guchar *sig,
							 gsize siglen,
							 struct rspamd_map *map,
							 const guchar *input,
							 gsize inlen,
							 struct rspamd_cryptobox_pubkey *pk)
{
	GString *b32_key;
	gboolean ret = TRUE;

	if (siglen != rspamd_cryptobox_signature_bytes (RSPAMD_CRYPTOBOX_MODE_25519)) {
		msg_err_map ("can't open signature for %s: invalid size: %z", map->name, siglen);

		ret = FALSE;
	}

	if (ret && !rspamd_cryptobox_verify (sig, siglen, input, inlen,
			rspamd_pubkey_get_pk (pk, NULL), RSPAMD_CRYPTOBOX_MODE_25519)) {
		msg_err_map ("can't verify signature for %s: incorrect signature", map->name);

		ret = FALSE;
	}

	if (ret) {
		b32_key = rspamd_pubkey_print (pk,
				RSPAMD_KEYPAIR_BASE32 | RSPAMD_KEYPAIR_PUBKEY);
		msg_info_map ("verified signature for %s using trusted key %v",
				map->name, b32_key);
		g_string_free (b32_key, TRUE);
	}

	return ret;
}

static gboolean
rspamd_map_check_file_sig (const char *fname,
						   struct rspamd_map *map,
						   struct rspamd_map_backend *bk,
						   const guchar *input,
						   gsize inlen) {
	guchar *data;
	struct rspamd_cryptobox_pubkey *pk = NULL;
	GString *b32_key;
	gboolean ret = TRUE;
	gsize len = 0;
	gchar fpath[PATH_MAX];

	if (bk->trusted_pubkey == NULL) {
		/* Try to load and check pubkey */
		rspamd_snprintf (fpath, sizeof (fpath), "%s.pub", fname);
		data = rspamd_file_xmap (fpath, PROT_READ, &len, TRUE);

		if (data == NULL) {
			msg_err_map ("can't open pubkey %s: %s", fpath, strerror (errno));
			return FALSE;
		}

		pk = rspamd_pubkey_from_base32 (data, len, RSPAMD_KEYPAIR_SIGN,
				RSPAMD_CRYPTOBOX_MODE_25519);
		munmap (data, len);

		if (pk == NULL) {
			msg_err_map ("can't load pubkey %s", fpath);
			return FALSE;
		}

		/* We just check pk against the trusted db of keys */
		b32_key = rspamd_pubkey_print (pk,
				RSPAMD_KEYPAIR_BASE32 | RSPAMD_KEYPAIR_PUBKEY);
		g_assert (b32_key != NULL);

		if (g_hash_table_lookup (map->cfg->trusted_keys, b32_key->str) == NULL) {
			msg_err_map ("pubkey loaded from %s is untrusted: %v", fpath,
					b32_key);
			g_string_free (b32_key, TRUE);
			rspamd_pubkey_unref (pk);

			return FALSE;
		}

		g_string_free (b32_key, TRUE);
	}
	else {
		pk = rspamd_pubkey_ref (bk->trusted_pubkey);
	}

	rspamd_snprintf (fpath, sizeof (fpath), "%s.sig", fname);
	data = rspamd_shmem_xmap (fpath, PROT_READ, &len);

	if (data == NULL) {
		msg_err_map ("can't open signature %s: %s", fpath, strerror (errno));
		ret = FALSE;
	}

	if (ret) {
		ret = rspamd_map_check_sig_pk_mem (data, len, map, input, inlen, pk);
		munmap (data, len);
	}

	rspamd_pubkey_unref (pk);

	return ret;
}

/**
 * Callback for reading data from file
 */
static gboolean
read_map_file (struct rspamd_map *map, struct file_map_data *data,
		struct rspamd_map_backend *bk, struct map_periodic_cbdata *periodic)
{
	gchar *bytes;
	gsize len;
	struct stat st;

	if (map->read_callback == NULL || map->fin_callback == NULL) {
		msg_err_map ("%s: bad callback for reading map file",
				data->filename);
		return FALSE;
	}

	if (stat (data->filename, &st) == -1) {
		/* File does not exist, skipping */
		if (errno != ENOENT) {
			msg_err_map ("%s: map file is unavailable for reading: %s",
					data->filename, strerror (errno));

			return FALSE;
		}
		else {
			msg_info_map ("%s: map file is not found; "
						  "it will be read automatically if created",
					data->filename);
			return TRUE;
		}
	}

	ev_stat_stat (map->event_loop, &data->st_ev);
	len = st.st_size;

	if (bk->is_signed) {
		bytes = rspamd_file_xmap (data->filename, PROT_READ, &len, TRUE);

		if (bytes == NULL) {
			msg_err_map ("can't open map %s: %s", data->filename, strerror (errno));
			return FALSE;
		}

		if (!rspamd_map_check_file_sig (data->filename, map, bk, bytes, len)) {
			munmap (bytes, len);

			return FALSE;
		}

		munmap (bytes, len);
	}

	if (len > 0) {
		if (map->no_file_read) {
			/* We just call read callback with backend name */
			map->read_callback (data->filename, strlen (data->filename),
					&periodic->cbdata, TRUE);
		}
		else {
			if (bk->is_compressed) {
				bytes = rspamd_file_xmap (data->filename, PROT_READ, &len, TRUE);

				if (bytes == NULL) {
					msg_err_map ("can't open map %s: %s", data->filename, strerror (errno));
					return FALSE;
				}

				ZSTD_DStream *zstream;
				ZSTD_inBuffer zin;
				ZSTD_outBuffer zout;
				guchar *out;
				gsize outlen, r;

				zstream = ZSTD_createDStream ();
				ZSTD_initDStream (zstream);

				zin.pos = 0;
				zin.src = bytes;
				zin.size = len;

				if ((outlen = ZSTD_getDecompressedSize (zin.src, zin.size)) == 0) {
					outlen = ZSTD_DStreamOutSize ();
				}

				out = g_malloc (outlen);

				zout.dst = out;
				zout.pos = 0;
				zout.size = outlen;

				while (zin.pos < zin.size) {
					r = ZSTD_decompressStream (zstream, &zout, &zin);

					if (ZSTD_isError (r)) {
						msg_err_map ("%s: cannot decompress data: %s",
								data->filename,
								ZSTD_getErrorName (r));
						ZSTD_freeDStream (zstream);
						g_free (out);
						munmap (bytes, len);
						return FALSE;
					}

					if (zout.pos == zout.size) {
						/* We need to extend output buffer */
						zout.size = zout.size * 2 + 1;
						out = g_realloc (zout.dst, zout.size);
						zout.dst = out;
					}
				}

				ZSTD_freeDStream (zstream);
				msg_info_map ("%s: read map data, %z bytes compressed, "
							  "%z uncompressed)", data->filename,
						len, zout.pos);
				map->read_callback (out, zout.pos, &periodic->cbdata, TRUE);
				g_free (out);

				munmap (bytes, len);
			}
			else {
				/* Perform buffered read: fail-safe */
				if (!read_map_file_chunks (map, &periodic->cbdata, data->filename,
						len, 0)) {
					return FALSE;
				}
			}
		}
	}
	else {
		/* Empty map */
		map->read_callback (NULL, 0, &periodic->cbdata, TRUE);
	}

	return TRUE;
}

static gboolean
read_map_static (struct rspamd_map *map, struct static_map_data *data,
		struct rspamd_map_backend *bk, struct map_periodic_cbdata *periodic)
{
	guchar *bytes;
	gsize len;

	if (map->read_callback == NULL || map->fin_callback == NULL) {
		msg_err_map ("%s: bad callback for reading map file", map->name);
		data->processed = TRUE;
		return FALSE;
	}

	bytes = data->data;
	len = data->len;

	if (len > 0) {
		if (bk->is_compressed) {
			ZSTD_DStream *zstream;
			ZSTD_inBuffer zin;
			ZSTD_outBuffer zout;
			guchar *out;
			gsize outlen, r;

			zstream = ZSTD_createDStream ();
			ZSTD_initDStream (zstream);

			zin.pos = 0;
			zin.src = bytes;
			zin.size = len;

			if ((outlen = ZSTD_getDecompressedSize (zin.src, zin.size)) == 0) {
				outlen = ZSTD_DStreamOutSize ();
			}

			out = g_malloc (outlen);

			zout.dst = out;
			zout.pos = 0;
			zout.size = outlen;

			while (zin.pos < zin.size) {
				r = ZSTD_decompressStream (zstream, &zout, &zin);

				if (ZSTD_isError (r)) {
					msg_err_map ("%s: cannot decompress data: %s",
							map->name,
							ZSTD_getErrorName (r));
					ZSTD_freeDStream (zstream);
					g_free (out);

					return FALSE;
				}

				if (zout.pos == zout.size) {
					/* We need to extend output buffer */
					zout.size = zout.size * 2 + 1;
					out = g_realloc (zout.dst, zout.size);
					zout.dst = out;
				}
			}

			ZSTD_freeDStream (zstream);
			msg_info_map ("%s: read map data, %z bytes compressed, "
					"%z uncompressed)",
					map->name,
					len, zout.pos);
			map->read_callback (out, zout.pos, &periodic->cbdata, TRUE);
			g_free (out);
		}
		else {
			msg_info_map ("%s: read map data, %z bytes",
					map->name, len);
			map->read_callback (bytes, len, &periodic->cbdata, TRUE);
		}
	}
	else {
		map->read_callback (NULL, 0, &periodic->cbdata, TRUE);
	}

	data->processed = TRUE;

	return TRUE;
}

static void
rspamd_map_periodic_dtor (struct map_periodic_cbdata *periodic)
{
	struct rspamd_map *map;

	map = periodic->map;
	msg_debug_map ("periodic dtor %p", periodic);

	if (periodic->need_modify) {
		/* We are done */
		periodic->map->fin_callback (&periodic->cbdata, periodic->map->user_data);
	}
	else {
		/* Not modified */
	}

	if (periodic->locked) {
		g_atomic_int_set (periodic->map->locked, 0);
		msg_debug_map ("unlocked map %s", periodic->map->name);

		if (periodic->map->wrk->state == rspamd_worker_state_running) {
			rspamd_map_schedule_periodic (periodic->map,
					RSPAMD_SYMBOL_RESULT_NORMAL);
		}
		else {
			msg_debug_map ("stop scheduling periodics for %s; terminating state",
					periodic->map->name);
		}
	}

	g_free (periodic);
}

/* Called on timer execution */
static void
rspamd_map_periodic_callback (struct ev_loop *loop, ev_timer *w, int revents)
{
	struct map_periodic_cbdata *cbd = (struct map_periodic_cbdata *)w->data;

	MAP_RETAIN (cbd, "periodic");
	ev_timer_stop (loop, w);
	rspamd_map_process_periodic (cbd);
	MAP_RELEASE (cbd, "periodic");
}

static void
rspamd_map_schedule_periodic (struct rspamd_map *map, int how)
{
	const gdouble error_mult = 20.0, lock_mult = 0.1;
	static const gdouble min_timer_interval = 2.0;
	const gchar *reason = "unknown reason";
	gdouble jittered_sec;
	gdouble timeout;
	struct map_periodic_cbdata *cbd;

	if (map->scheduled_check || (map->wrk &&
			map->wrk->state != rspamd_worker_state_running)) {
		/*
		 * Do not schedule check if some check is already scheduled or
		 * if worker is going to die
		 */
		return;
	}

	if (!(how & RSPAMD_MAP_SCHEDULE_INIT) && map->static_only) {
		/* No need to schedule anything for static maps */
		return;
	}

	if (map->non_trivial && map->next_check != 0) {
		timeout = map->next_check - rspamd_get_calendar_ticks ();
		map->next_check = 0;

		if (timeout > 0 && timeout < map->poll_timeout) {
			/* Early check case, jitter */
			gdouble poll_timeout = map->poll_timeout;

			if (how & RSPAMD_MAP_SCHEDULE_ERROR) {
				poll_timeout = map->poll_timeout * error_mult;
				reason = "early active non-trivial check (after error)";
			}
			else if (how & RSPAMD_MAP_SCHEDULE_LOCKED) {
				poll_timeout = map->poll_timeout * lock_mult;
				reason = "early active non-trivial check (after being locked)";
			}
			else {
				reason = "early active non-trivial check";
			}

			jittered_sec = MIN (timeout, poll_timeout);

		}
		else if (timeout <= 0) {
			/* Data is already expired, need to check */
			if (how & RSPAMD_MAP_SCHEDULE_ERROR) {
				/* In case of error we still need to increase delay */
				jittered_sec = map->poll_timeout * error_mult;
				reason = "expired non-trivial data (after error)";
			}
			else {
				jittered_sec = 0.0;
				reason = "expired non-trivial data";
			}
		}
		else {
			/* No need to check now, wait till next_check */
			jittered_sec = timeout;
			reason = "valid non-trivial data";
		}
	}
	else {
		/* No valid information when to check a map, plan a timer based check */
		timeout = map->poll_timeout;

		if (how & RSPAMD_MAP_SCHEDULE_INIT) {
			if (map->active_http) {
				/* Spill maps load to get better chances to hit ssl cache */
				timeout = rspamd_time_jitter (0.0, 2.0);
			}
			else {
				timeout = 0.0;
			}

			reason = "init scheduled check";
		}
		else {
			if (how & RSPAMD_MAP_SCHEDULE_ERROR) {
				timeout = map->poll_timeout * error_mult;
				reason = "errored scheduled check";
			}
			else if (how & RSPAMD_MAP_SCHEDULE_LOCKED) {
				timeout = map->poll_timeout * lock_mult;
				reason = "locked scheduled check";
			}
			else {
				reason = "normal scheduled check";
			}
		}

		jittered_sec = rspamd_time_jitter (timeout, 0);
	}

	/* Now, we do some sanity checks for jittered seconds */
	if (!(how & RSPAMD_MAP_SCHEDULE_INIT)) {
		/* Never allow too low interval between timer checks, it is epxensive */
		if (jittered_sec < min_timer_interval) {
			jittered_sec = rspamd_time_jitter (min_timer_interval, 0);
		}

		if (map->non_trivial) {
			/*
			 * Even if we are reported that we need to reload cache often, we
			 * still want to be sane in terms of events...
			 */
			if (jittered_sec < min_timer_interval * 2.0) {
				if (map->nelts > 0) {
					jittered_sec = min_timer_interval * 3.0;
				}
			}
		}
	}

	cbd = g_malloc0 (sizeof (*cbd));
	cbd->cbdata.state = 0;
	cbd->cbdata.prev_data = *map->user_data;
	cbd->cbdata.cur_data = NULL;
	cbd->cbdata.map = map;
	cbd->map = map;
	map->scheduled_check = cbd;
	REF_INIT_RETAIN (cbd, rspamd_map_periodic_dtor);

	cbd->ev.data = cbd;
	ev_timer_init (&cbd->ev, rspamd_map_periodic_callback, jittered_sec, 0.0);
	ev_timer_start (map->event_loop, &cbd->ev);

	msg_debug_map ("schedule new periodic event %p in %.3f seconds for %s; reason: %s",
			cbd, jittered_sec, map->name, reason);
}

static gint
rspamd_map_af_to_weight (const rspamd_inet_addr_t *addr)
{
	int ret;

	switch (rspamd_inet_address_get_af (addr)) {
	case AF_UNIX:
		ret = 2;
		break;
	case AF_INET:
		ret = 1;
		break;
	default:
		ret = 0;
		break;
	}

	return ret;
}

static gint
rspamd_map_dns_address_sort_func (gconstpointer a, gconstpointer b)
{
	const rspamd_inet_addr_t *ip1 = *(const rspamd_inet_addr_t **)a,
			*ip2 = *(const rspamd_inet_addr_t **)b;
	gint w1, w2;

	w1 = rspamd_map_af_to_weight (ip1);
	w2 = rspamd_map_af_to_weight (ip2);

	/* Inverse order */
	return w2 - w1;
}

static void
rspamd_map_dns_callback (struct rdns_reply *reply, void *arg)
{
	struct http_callback_data *cbd = arg;
	struct rdns_reply_entry *cur_rep;
	struct rspamd_map *map;
	guint flags = RSPAMD_HTTP_CLIENT_SIMPLE|RSPAMD_HTTP_CLIENT_SHARED;

	map = cbd->map;

	msg_debug_map ("got dns reply with code %s on stage %d",
			rdns_strerror (reply->code), cbd->stage);

	if (cbd->stage == http_map_terminated) {
		MAP_RELEASE (cbd, "http_callback_data");
		return;
	}

	if (reply->code == RDNS_RC_NOERROR) {
		DL_FOREACH (reply->entries, cur_rep) {
			rspamd_inet_addr_t *addr;
			addr = rspamd_inet_address_from_rnds (reply->entries);

			if (addr != NULL) {
				rspamd_inet_address_set_port (addr, cbd->data->port);
				g_ptr_array_add (cbd->addrs, (void *)addr);
			}
		}

		if (cbd->stage == http_map_resolve_host2) {
			/* We have still one request pending */
			cbd->stage = http_map_resolve_host1;
		}
		else if (cbd->stage == http_map_resolve_host1) {
			cbd->stage = http_map_http_conn;
		}
	}
	else if (cbd->stage < http_map_http_conn) {
		if (cbd->stage == http_map_resolve_host2) {
			/* We have still one request pending */
			cbd->stage = http_map_resolve_host1;
		}
		else if (cbd->addrs->len == 0) {
			/* We could not resolve host, so cowardly fail here */
			msg_err_map ("cannot resolve %s: %s", cbd->data->host,
					rdns_strerror (reply->code));
			cbd->periodic->errored = 1;
			rspamd_map_process_periodic (cbd->periodic);
		}
		else {
			/* We have at least one address, so we can continue... */
			cbd->stage = http_map_http_conn;
		}
	}

	if (cbd->stage == http_map_http_conn && cbd->addrs->len > 0) {
		rspamd_ptr_array_shuffle (cbd->addrs);
		gint idx = 0;
		/*
		 * For the existing addr we can just select any address as we have
		 * data available
		 */
		if (cbd->map->nelts > 0 && rspamd_random_double_fast () > 0.5) {
			/* Already shuffled, use whatever is the first */
			cbd->addr = (rspamd_inet_addr_t *) g_ptr_array_index (cbd->addrs, idx);
		}
		else {
			/* Always prefer IPv4 as IPv6 is almost all the time broken */
			g_ptr_array_sort (cbd->addrs, rspamd_map_dns_address_sort_func);
			cbd->addr = (rspamd_inet_addr_t *) g_ptr_array_index (cbd->addrs, idx);
		}

retry:
		msg_debug_map ("try open http connection to %s",
				rspamd_inet_address_to_string_pretty (cbd->addr));
		cbd->conn = rspamd_http_connection_new_client (NULL,
				NULL,
				http_map_error,
				http_map_finish,
				flags,
				cbd->addr);

		if (cbd->conn != NULL) {
			write_http_request (cbd);
		}
		else {
			if (idx < cbd->addrs->len - 1) {
				/* We can retry */
				idx++;
				rspamd_inet_addr_t *prev_addr = cbd->addr;
				cbd->addr = (rspamd_inet_addr_t *) g_ptr_array_index (cbd->addrs, idx);
				msg_info_map ("cannot connect to %s to get data for %s: %s, retry with %s (%d of %d)",
						rspamd_inet_address_to_string_pretty (prev_addr),
						cbd->bk->uri,
						strerror (errno),
						rspamd_inet_address_to_string_pretty (cbd->addr),
						idx + 1, cbd->addrs->len);
				goto retry;
			}
			else {
				/* Nothing else left */
				cbd->periodic->errored = TRUE;
				msg_err_map ("error reading %s(%s): "
							 "connection with http server terminated incorrectly: %s",
						cbd->bk->uri,
						cbd->addr ? rspamd_inet_address_to_string_pretty (cbd->addr) : "",
						strerror (errno));

				rspamd_map_process_periodic (cbd->periodic);
			}
		}
	}

	MAP_RELEASE (cbd, "http_callback_data");
}

static gboolean
rspamd_map_read_cached (struct rspamd_map *map, struct rspamd_map_backend *bk,
		struct map_periodic_cbdata *periodic, const gchar *host)
{
	gsize len;
	gpointer in;
	struct http_map_data *data;

	data = bk->data.hd;

	in = rspamd_shmem_xmap (data->cache->shmem_name, PROT_READ, &len);

	if (in == NULL) {
		msg_err ("cannot map cache from %s: %s", data->cache->shmem_name,
				strerror (errno));
		return FALSE;
	}

	if (len < data->cache->len) {
		msg_err ("cannot map cache from %s: bad length %z, %z expected",
				data->cache->shmem_name,
				len, data->cache->len);
		munmap (in, len);

		return FALSE;
	}

	if (bk->is_compressed) {
		ZSTD_DStream *zstream;
		ZSTD_inBuffer zin;
		ZSTD_outBuffer zout;
		guchar *out;
		gsize outlen, r;

		zstream = ZSTD_createDStream ();
		ZSTD_initDStream (zstream);

		zin.pos = 0;
		zin.src = in;
		zin.size = len;

		if ((outlen = ZSTD_getDecompressedSize (zin.src, zin.size)) == 0) {
			outlen = ZSTD_DStreamOutSize ();
		}

		out = g_malloc (outlen);

		zout.dst = out;
		zout.pos = 0;
		zout.size = outlen;

		while (zin.pos < zin.size) {
			r = ZSTD_decompressStream (zstream, &zout, &zin);

			if (ZSTD_isError (r)) {
				msg_err_map ("%s: cannot decompress data: %s",
						bk->uri,
						ZSTD_getErrorName (r));
				ZSTD_freeDStream (zstream);
				g_free (out);
				munmap (in, len);
				return FALSE;
			}

			if (zout.pos == zout.size) {
				/* We need to extend output buffer */
				zout.size = zout.size * 2 + 1;
				out = g_realloc (zout.dst, zout.size);
				zout.dst = out;
			}
		}

		ZSTD_freeDStream (zstream);
		msg_info_map ("%s: read map data cached %z bytes compressed, "
				"%z uncompressed", bk->uri,
				len, zout.pos);
		map->read_callback (out, zout.pos, &periodic->cbdata, TRUE);
		g_free (out);
	}
	else {
		msg_info_map ("%s: read map data cached %z bytes", bk->uri,
				len);
		map->read_callback (in, len, &periodic->cbdata, TRUE);
	}

	munmap (in, len);

	return TRUE;
}

static gboolean
rspamd_map_has_http_cached_file (struct rspamd_map *map,
								 struct rspamd_map_backend *bk)
{
	gchar path[PATH_MAX];
	guchar digest[rspamd_cryptobox_HASHBYTES];
	struct rspamd_config *cfg = map->cfg;
	struct stat st;

	if (cfg->maps_cache_dir == NULL || cfg->maps_cache_dir[0] == '\0') {
		return FALSE;
	}

	rspamd_cryptobox_hash (digest, bk->uri, strlen (bk->uri), NULL, 0);
	rspamd_snprintf (path, sizeof (path), "%s%c%*xs.map", cfg->maps_cache_dir,
			G_DIR_SEPARATOR, 20, digest);

	if (stat (path, &st) != -1 && st.st_size >
								  sizeof (struct rspamd_http_file_data)) {
		return TRUE;
	}

	return FALSE;
}

static gboolean
rspamd_map_save_http_cached_file (struct rspamd_map *map,
								  struct rspamd_map_backend *bk,
								  struct http_map_data *htdata,
								  const guchar *data,
								  gsize len)
{
	gchar path[PATH_MAX];
	guchar digest[rspamd_cryptobox_HASHBYTES];
	struct rspamd_config *cfg = map->cfg;
	gint fd;
	struct rspamd_http_file_data header;

	if (cfg->maps_cache_dir == NULL || cfg->maps_cache_dir[0] == '\0') {
		return FALSE;
	}

	rspamd_cryptobox_hash (digest, bk->uri, strlen (bk->uri), NULL, 0);
	rspamd_snprintf (path, sizeof (path), "%s%c%*xs.map", cfg->maps_cache_dir,
			G_DIR_SEPARATOR, 20, digest);

	fd = rspamd_file_xopen (path, O_WRONLY | O_TRUNC | O_CREAT,
			00600, FALSE);

	if (fd == -1) {
		return FALSE;
	}

	if (!rspamd_file_lock (fd, FALSE)) {
		msg_err_map ("cannot lock file %s: %s", path, strerror (errno));
		close (fd);

		return FALSE;
	}

	memcpy (header.magic, rspamd_http_file_magic, sizeof (rspamd_http_file_magic));
	header.mtime = htdata->last_modified;
	header.next_check = map->next_check;
	header.data_off = sizeof (header);

	if (htdata->etag) {
		header.data_off += RSPAMD_FSTRING_LEN (htdata->etag);
		header.etag_len = RSPAMD_FSTRING_LEN (htdata->etag);
	}
	else {
		header.etag_len = 0;
	}

	if (write (fd, &header, sizeof (header)) != sizeof (header)) {
		msg_err_map ("cannot write file %s (header stage): %s", path, strerror (errno));
		rspamd_file_unlock (fd, FALSE);
		close (fd);

		return FALSE;
	}

	if (header.etag_len > 0) {
		if (write (fd, RSPAMD_FSTRING_DATA (htdata->etag), header.etag_len) !=
			header.etag_len) {
			msg_err_map ("cannot write file %s (etag stage): %s", path, strerror (errno));
			rspamd_file_unlock (fd, FALSE);
			close (fd);

			return FALSE;
		}
	}

	/* Now write the rest */
	if (write (fd, data, len) != len) {
		msg_err_map ("cannot write file %s (data stage): %s", path, strerror (errno));
		rspamd_file_unlock (fd, FALSE);
		close (fd);

		return FALSE;
	}

	rspamd_file_unlock (fd, FALSE);
	close (fd);

	msg_info_map ("saved data from %s in %s, %uz bytes", bk->uri, path, len +
																		sizeof (header) + header.etag_len);

	return TRUE;
}

static gboolean
rspamd_map_update_http_cached_file (struct rspamd_map *map,
								  struct rspamd_map_backend *bk,
								  struct http_map_data *htdata)
{
	gchar path[PATH_MAX];
	guchar digest[rspamd_cryptobox_HASHBYTES];
	struct rspamd_config *cfg = map->cfg;
	gint fd;
	struct rspamd_http_file_data header;

	if (!rspamd_map_has_http_cached_file (map, bk)) {
		return FALSE;
	}

	rspamd_cryptobox_hash (digest, bk->uri, strlen (bk->uri), NULL, 0);
	rspamd_snprintf (path, sizeof (path), "%s%c%*xs.map", cfg->maps_cache_dir,
			G_DIR_SEPARATOR, 20, digest);

	fd = rspamd_file_xopen (path, O_WRONLY,
			00600, FALSE);

	if (fd == -1) {
		return FALSE;
	}

	if (!rspamd_file_lock (fd, FALSE)) {
		msg_err_map ("cannot lock file %s: %s", path, strerror (errno));
		close (fd);

		return FALSE;
	}

	memcpy (header.magic, rspamd_http_file_magic, sizeof (rspamd_http_file_magic));
	header.mtime = htdata->last_modified;
	header.next_check = map->next_check;
	header.data_off = sizeof (header);

	if (htdata->etag) {
		header.data_off += RSPAMD_FSTRING_LEN (htdata->etag);
		header.etag_len = RSPAMD_FSTRING_LEN (htdata->etag);
	}
	else {
		header.etag_len = 0;
	}

	if (write (fd, &header, sizeof (header)) != sizeof (header)) {
		msg_err_map ("cannot update file %s (header stage): %s", path, strerror (errno));
		rspamd_file_unlock (fd, FALSE);
		close (fd);

		return FALSE;
	}

	if (header.etag_len > 0) {
		if (write (fd, RSPAMD_FSTRING_DATA (htdata->etag), header.etag_len) !=
			header.etag_len) {
			msg_err_map ("cannot update file %s (etag stage): %s", path, strerror (errno));
			rspamd_file_unlock (fd, FALSE);
			close (fd);

			return FALSE;
		}
	}

	rspamd_file_unlock (fd, FALSE);
	close (fd);

	return TRUE;
}


static gboolean
rspamd_map_read_http_cached_file (struct rspamd_map *map,
								  struct rspamd_map_backend *bk,
								  struct http_map_data *htdata,
								  struct map_cb_data *cbdata)
{
	gchar path[PATH_MAX];
	guchar digest[rspamd_cryptobox_HASHBYTES];
	struct rspamd_config *cfg = map->cfg;
	gint fd;
	struct stat st;
	struct rspamd_http_file_data header;

	if (cfg->maps_cache_dir == NULL || cfg->maps_cache_dir[0] == '\0') {
		return FALSE;
	}

	rspamd_cryptobox_hash (digest, bk->uri, strlen (bk->uri), NULL, 0);
	rspamd_snprintf (path, sizeof (path), "%s%c%*xs.map", cfg->maps_cache_dir,
			G_DIR_SEPARATOR, 20, digest);

	fd = rspamd_file_xopen (path, O_RDONLY, 00600, FALSE);

	if (fd == -1) {
		return FALSE;
	}

	if (!rspamd_file_lock (fd, FALSE)) {
		msg_err_map ("cannot lock file %s: %s", path, strerror (errno));
		close (fd);

		return FALSE;
	}

	(void)fstat (fd, &st);

	if (read (fd, &header, sizeof (header)) != sizeof (header)) {
		msg_err_map ("cannot read file %s (header stage): %s", path, strerror (errno));
		rspamd_file_unlock (fd, FALSE);
		close (fd);

		return FALSE;
	}

	if (memcmp (header.magic, rspamd_http_file_magic,
			sizeof (rspamd_http_file_magic)) != 0) {
		msg_warn_map ("invalid or old version magic in file %s; ignore it", path);
		rspamd_file_unlock (fd, FALSE);
		close (fd);

		return FALSE;
	}

	double now = rspamd_get_calendar_ticks ();

	if (header.next_check > now) {
		map->next_check = header.next_check;
	}
	else {
		map->next_check = now;
	}

	htdata->last_modified = header.mtime;

	if (header.etag_len > 0) {
		rspamd_fstring_t *etag = rspamd_fstring_sized_new (header.etag_len);

		if (read (fd, RSPAMD_FSTRING_DATA (etag), header.etag_len) != header.etag_len) {
			msg_err_map ("cannot read file %s (etag stage): %s", path,
					strerror (errno));
			rspamd_file_unlock (fd, FALSE);
			rspamd_fstring_free (etag);
			close (fd);

			return FALSE;
		}

		etag->len = header.etag_len;

		if (htdata->etag) {
			/* FIXME: should be dealt somehow better */
			msg_warn_map ("etag is already defined as %V; cached is %V; ignore cached",
					htdata->etag, etag);
			rspamd_fstring_free (etag);
		}
		else {
			htdata->etag = etag;
		}
	}

	rspamd_file_unlock (fd, FALSE);
	close (fd);

	/* Now read file data */
	/* Perform buffered read: fail-safe */
	if (!read_map_file_chunks (map, cbdata, path,
			st.st_size - header.data_off, header.data_off)) {
		return FALSE;
	}

	struct tm tm;
	gchar ncheck_buf[32], lm_buf[32];

	rspamd_localtime (map->next_check, &tm);
	strftime (ncheck_buf, sizeof (ncheck_buf) - 1, "%Y-%m-%d %H:%M:%S", &tm);
	rspamd_localtime (htdata->last_modified, &tm);
	strftime (lm_buf, sizeof (lm_buf) - 1, "%Y-%m-%d %H:%M:%S", &tm);

	msg_info_map ("read cached data for %s from %s, %uz bytes; next check at: %s;"
				  " last modified on: %s; etag: %V",
			bk->uri,
			path,
			(size_t)(st.st_size - header.data_off),
			ncheck_buf,
			lm_buf,
			htdata->etag);

	return TRUE;
}

/**
 * Async HTTP callback
 */
static void
rspamd_map_common_http_callback (struct rspamd_map *map,
		struct rspamd_map_backend *bk,
		struct map_periodic_cbdata *periodic,
		gboolean check)
{
	struct http_map_data *data;
	struct http_callback_data *cbd;
	guint flags = RSPAMD_HTTP_CLIENT_SIMPLE|RSPAMD_HTTP_CLIENT_SHARED;

	data = bk->data.hd;

	if (g_atomic_int_get (&data->cache->available) == 1) {
		/* Read cached data */
		if (check) {
			if (data->last_modified < data->cache->last_modified) {
				msg_info_map ("need to reread cached map triggered by %s "
							  "(%d our modify time, %d cached modify time)",
						bk->uri,
						(int)data->last_modified,
						(int)data->cache->last_modified);
				periodic->need_modify = TRUE;
				/* Reset the whole chain */
				periodic->cur_backend = 0;
				rspamd_map_process_periodic (periodic);
			}
			else {
				if (map->active_http) {
					/* Check even if there is a cached version */
					goto check;
				}
				else {
					/* Switch to the next backend */
					periodic->cur_backend++;
					rspamd_map_process_periodic (periodic);
				}
			}

			return;
		}
		else {
			if (map->active_http &&
					data->last_modified > data->cache->last_modified) {
				goto check;
			}
			else if (rspamd_map_read_cached (map, bk, periodic, data->host)) {
				/* Switch to the next backend */
				periodic->cur_backend++;
				data->last_modified = data->cache->last_modified;
				rspamd_map_process_periodic (periodic);

				return;
			}
		}
	}
	else if (!map->active_http) {
		/* Switch to the next backend */
		periodic->cur_backend ++;
		rspamd_map_process_periodic (periodic);

		return;
	}

check:
	cbd = g_malloc0 (sizeof (struct http_callback_data));

	cbd->event_loop = map->event_loop;
	cbd->addrs = g_ptr_array_sized_new (4);
	cbd->map = map;
	cbd->data = data;
	cbd->check = check;
	cbd->periodic = periodic;
	MAP_RETAIN (periodic, "periodic");
	cbd->bk = bk;
	MAP_RETAIN (bk, "rspamd_map_backend");
	cbd->stage = http_map_terminated;
	REF_INIT_RETAIN (cbd, free_http_cbdata);

	msg_debug_map ("%s map data from %s", check ? "checking" : "reading",
			data->host);

	/* Try address */
	rspamd_inet_addr_t *addr = NULL;

	if (rspamd_parse_inet_address (&addr, data->host,
			strlen (data->host), RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
		rspamd_inet_address_set_port (addr, cbd->data->port);
		g_ptr_array_add (cbd->addrs, (void *)addr);
		cbd->conn = rspamd_http_connection_new_client (
				NULL,
				NULL,
				http_map_error,
				http_map_finish,
				flags,
				addr);

		if (cbd->conn != NULL) {
			cbd->stage = http_map_http_conn;
			write_http_request (cbd);
			cbd->addr = addr;
			MAP_RELEASE (cbd, "http_callback_data");
		}
		else {
			msg_warn_map ("cannot load map: cannot connect to %s: %s",
					data->host, strerror (errno));
			MAP_RELEASE (cbd, "http_callback_data");
		}

		return;
	}
	else if (map->r->r) {
		/* Send both A and AAAA requests */
		guint nreq = 0;

		if (rdns_make_request_full (map->r->r, rspamd_map_dns_callback, cbd,
				map->cfg->dns_timeout, map->cfg->dns_retransmits, 1,
				data->host, RDNS_REQUEST_A)) {
			MAP_RETAIN (cbd, "http_callback_data");
			nreq ++;
		}
		if (rdns_make_request_full (map->r->r, rspamd_map_dns_callback, cbd,
				map->cfg->dns_timeout, map->cfg->dns_retransmits, 1,
				data->host, RDNS_REQUEST_AAAA)) {
			MAP_RETAIN (cbd, "http_callback_data");
			nreq ++;
		}

		if (nreq == 2) {
			cbd->stage = http_map_resolve_host2;
		}
		else if (nreq == 1) {
			cbd->stage = http_map_resolve_host1;
		}

		map->tmp_dtor = free_http_cbdata_dtor;
		map->tmp_dtor_data = cbd;
	}
	else {
		msg_warn_map ("cannot load map: DNS resolver is not initialized");
		cbd->periodic->errored = TRUE;
	}

	MAP_RELEASE (cbd, "http_callback_data");
}

static void
rspamd_map_http_check_callback (struct map_periodic_cbdata *cbd)
{
	struct rspamd_map *map;
	struct rspamd_map_backend *bk;

	map = cbd->map;
	bk = g_ptr_array_index (cbd->map->backends, cbd->cur_backend);

	rspamd_map_common_http_callback (map, bk, cbd, TRUE);
}

static void
rspamd_map_http_read_callback (struct map_periodic_cbdata *cbd)
{
	struct rspamd_map *map;
	struct rspamd_map_backend *bk;

	map = cbd->map;
	bk = g_ptr_array_index (cbd->map->backends, cbd->cur_backend);
	rspamd_map_common_http_callback (map, bk, cbd, FALSE);
}

static void
rspamd_map_file_check_callback (struct map_periodic_cbdata *periodic)
{
	struct rspamd_map *map;
	struct file_map_data *data;
	struct rspamd_map_backend *bk;

	map = periodic->map;
	bk = g_ptr_array_index (map->backends, periodic->cur_backend);
	data = bk->data.fd;

	if (data->need_modify) {
		periodic->need_modify = TRUE;
		periodic->cur_backend = 0;
		data->need_modify = FALSE;

		rspamd_map_process_periodic (periodic);

		return;
	}

	map = periodic->map;
	/* Switch to the next backend as the rest is handled by ev_stat */
	periodic->cur_backend ++;
	rspamd_map_process_periodic (periodic);
}

static void
rspamd_map_static_check_callback (struct map_periodic_cbdata *periodic)
{
	struct rspamd_map *map;
	struct static_map_data *data;
	struct rspamd_map_backend *bk;

	map = periodic->map;
	bk = g_ptr_array_index (map->backends, periodic->cur_backend);
	data = bk->data.sd;

	if (!data->processed) {
		periodic->need_modify = TRUE;
		periodic->cur_backend = 0;

		rspamd_map_process_periodic (periodic);

		return;
	}

	/* Switch to the next backend */
	periodic->cur_backend ++;
	rspamd_map_process_periodic (periodic);
}

static void
rspamd_map_file_read_callback (struct map_periodic_cbdata *periodic)
{
	struct rspamd_map *map;
	struct file_map_data *data;
	struct rspamd_map_backend *bk;

	map = periodic->map;

	bk = g_ptr_array_index (map->backends, periodic->cur_backend);
	data = bk->data.fd;

	msg_info_map ("rereading map file %s", data->filename);

	if (!read_map_file (map, data, bk, periodic)) {
		periodic->errored = TRUE;
	}

	/* Switch to the next backend */
	periodic->cur_backend ++;
	rspamd_map_process_periodic (periodic);
}

static void
rspamd_map_static_read_callback (struct map_periodic_cbdata *periodic)
{
	struct rspamd_map *map;
	struct static_map_data *data;
	struct rspamd_map_backend *bk;

	map = periodic->map;

	bk = g_ptr_array_index (map->backends, periodic->cur_backend);
	data = bk->data.sd;

	msg_info_map ("rereading static map");

	if (!read_map_static (map, data, bk, periodic)) {
		periodic->errored = TRUE;
	}

	/* Switch to the next backend */
	periodic->cur_backend ++;
	rspamd_map_process_periodic (periodic);
}

static void
rspamd_map_process_periodic (struct map_periodic_cbdata *cbd)
{
	struct rspamd_map_backend *bk;
	struct rspamd_map *map;

	map = cbd->map;
	map->scheduled_check = NULL;

	if (!map->file_only && !cbd->locked) {
		if (!g_atomic_int_compare_and_exchange (cbd->map->locked,
				0, 1)) {
			msg_debug_map (
					"don't try to reread map %s as it is locked by other process, "
					"will reread it later", cbd->map->name);
			rspamd_map_schedule_periodic (map, RSPAMD_MAP_SCHEDULE_LOCKED);
			MAP_RELEASE (cbd, "periodic");

			return;
		}
		else {
			msg_debug_map ("locked map %s", cbd->map->name);
			cbd->locked = TRUE;
		}
	}

	if (cbd->errored) {
		/* We should not check other backends if some backend has failed */
		rspamd_map_schedule_periodic (cbd->map, RSPAMD_MAP_SCHEDULE_ERROR);

		if (cbd->locked) {
			g_atomic_int_set (cbd->map->locked, 0);
			cbd->locked = FALSE;
		}

		msg_debug_map ("unlocked map %s, refcount=%d", cbd->map->name,
				cbd->ref.refcount);
		MAP_RELEASE (cbd, "periodic");

		return;
	}

	/* For each backend we need to check for modifications */
	if (cbd->cur_backend >= cbd->map->backends->len) {
		/* Last backend */
		msg_debug_map ("finished map: %d of %d", cbd->cur_backend,
				cbd->map->backends->len);
		MAP_RELEASE (cbd, "periodic");

		return;
	}

	if (cbd->map->wrk && cbd->map->wrk->state == rspamd_worker_state_running) {
		bk = g_ptr_array_index (cbd->map->backends, cbd->cur_backend);
		g_assert (bk != NULL);

		if (cbd->need_modify) {
			/* Load data from the next backend */
			switch (bk->protocol) {
			case MAP_PROTO_HTTP:
			case MAP_PROTO_HTTPS:
				rspamd_map_http_read_callback (cbd);
				break;
			case MAP_PROTO_FILE:
				rspamd_map_file_read_callback (cbd);
				break;
			case MAP_PROTO_STATIC:
				rspamd_map_static_read_callback (cbd);
				break;
			}
		} else {
			/* Check the next backend */
			switch (bk->protocol) {
			case MAP_PROTO_HTTP:
			case MAP_PROTO_HTTPS:
				rspamd_map_http_check_callback (cbd);
				break;
			case MAP_PROTO_FILE:
				rspamd_map_file_check_callback (cbd);
				break;
			case MAP_PROTO_STATIC:
				rspamd_map_static_check_callback (cbd);
				break;
			}
		}
	}
}

static void
rspamd_map_on_stat (struct ev_loop *loop, ev_stat *w, int revents)
{
	struct rspamd_map *map = (struct rspamd_map *)w->data;

	if (w->attr.st_nlink > 0) {
		msg_info_map ("old mtime is %t (size = %Hz), "
					  "new mtime is %t (size = %Hz) for map file %s",
				w->prev.st_mtime, (gsize)w->prev.st_size,
				w->attr.st_mtime, (gsize)w->attr.st_size,
				w->path);

		/* Fire need modify flag */
		struct rspamd_map_backend *bk;
		guint i;

		PTR_ARRAY_FOREACH (map->backends, i, bk) {
			if (bk->protocol == MAP_PROTO_FILE) {
				bk->data.fd->need_modify = TRUE;
			}
		}

		map->next_check = 0;

		if (map->scheduled_check) {
			ev_timer_stop (map->event_loop, &map->scheduled_check->ev);
			MAP_RELEASE (map->scheduled_check, "rspamd_map_on_stat");
			map->scheduled_check = NULL;
		}

		rspamd_map_schedule_periodic (map, RSPAMD_MAP_SCHEDULE_INIT);
	}
}

/* Start watching event for all maps */
void
rspamd_map_watch (struct rspamd_config *cfg,
				  struct ev_loop *event_loop,
				  struct rspamd_dns_resolver *resolver,
				  struct rspamd_worker *worker,
				  enum rspamd_map_watch_type how)
{
	GList *cur = cfg->maps;
	struct rspamd_map *map;
	struct rspamd_map_backend *bk;
	guint i;

	g_assert (how > RSPAMD_MAP_WATCH_MIN && how < RSPAMD_MAP_WATCH_MAX);

	/* First of all do synced read of data */
	while (cur) {
		map = cur->data;
		map->event_loop = event_loop;
		map->r = resolver;

		if (map->wrk == NULL && how != RSPAMD_MAP_WATCH_WORKER) {
			/* Generic scanner map */
			map->wrk = worker;

			if (how == RSPAMD_MAP_WATCH_PRIMARY_CONTROLLER) {
				map->active_http = TRUE;
			}
			else {
				map->active_http = FALSE;
			}
		}
		else if (map->wrk != NULL && map->wrk == worker) {
			/* Map is bound to a specific worker */
			map->active_http = TRUE;
		}
		else {
			/* Skip map for this worker as irrelevant */
			cur = g_list_next (cur);
			continue;
		}

		if (!map->active_http) {
			/* Check cached version more frequently as it is cheap */

			if (map->poll_timeout >= cfg->map_timeout &&
					cfg->map_file_watch_multiplier < 1.0) {
				map->poll_timeout =
						map->poll_timeout * cfg->map_file_watch_multiplier;
			}
		}

		map->file_only = TRUE;
		map->static_only = TRUE;

		PTR_ARRAY_FOREACH (map->backends, i, bk) {
			bk->event_loop = event_loop;

			if (bk->protocol == MAP_PROTO_FILE) {
				struct file_map_data *data;

				data = bk->data.fd;

				if (map->user_data == NULL || *map->user_data == NULL) {
					/* Map has not been read, init it's reading if possible */
					struct stat st;

					if (stat (data->filename, &st) != -1) {
						data->need_modify = TRUE;
					}
				}

				ev_stat_init (&data->st_ev, rspamd_map_on_stat,
						data->filename, map->poll_timeout * cfg->map_file_watch_multiplier);
				data->st_ev.data = map;
				ev_stat_start (event_loop, &data->st_ev);
				map->static_only = FALSE;
			}
			else if ((bk->protocol == MAP_PROTO_HTTP ||
					  bk->protocol == MAP_PROTO_HTTPS)) {
				if (map->active_http) {
					map->non_trivial = TRUE;
				}

				map->static_only = FALSE;
				map->file_only = FALSE;
			}
		}

		rspamd_map_schedule_periodic (map, RSPAMD_MAP_SCHEDULE_INIT);

		cur = g_list_next (cur);
	}
}

void
rspamd_map_preload (struct rspamd_config *cfg)
{
	GList *cur = cfg->maps;
	struct rspamd_map *map;
	struct rspamd_map_backend *bk;
	guint i;
	gboolean map_ok;

	/* First of all do synced read of data */
	while (cur) {
		map = cur->data;
		map_ok = TRUE;

		PTR_ARRAY_FOREACH (map->backends, i, bk) {
			if (!(bk->protocol == MAP_PROTO_FILE ||
				  bk->protocol == MAP_PROTO_STATIC)) {

				if (bk->protocol == MAP_PROTO_HTTP ||
						bk->protocol == MAP_PROTO_HTTPS) {
					if (!rspamd_map_has_http_cached_file (map, bk)) {

						if (!map->fallback_backend) {
							map_ok = FALSE;
						}
						break;
					}
					else {
						continue; /* We are yet fine */
					}
				}
				map_ok = FALSE;
				break;
			}
		}

		if (map_ok) {
			struct map_periodic_cbdata fake_cbd;
			gboolean succeed = TRUE;

			memset (&fake_cbd, 0, sizeof (fake_cbd));
			fake_cbd.cbdata.state = 0;
			fake_cbd.cbdata.prev_data = *map->user_data;
			fake_cbd.cbdata.cur_data = NULL;
			fake_cbd.cbdata.map = map;
			fake_cbd.map = map;

			PTR_ARRAY_FOREACH (map->backends, i, bk) {
				fake_cbd.cur_backend = i;

				if (bk->protocol == MAP_PROTO_FILE) {
					if (!read_map_file (map, bk->data.fd, bk, &fake_cbd)) {
						succeed = FALSE;
						break;
					}
				}
				else if (bk->protocol == MAP_PROTO_STATIC) {
					if (!read_map_static (map, bk->data.sd, bk, &fake_cbd)) {
						succeed = FALSE;
						break;
					}
				}
				else if (bk->protocol == MAP_PROTO_HTTP ||
						 bk->protocol == MAP_PROTO_HTTPS) {
					if (!rspamd_map_read_http_cached_file (map, bk, bk->data.hd,
							&fake_cbd.cbdata)) {

						if (map->fallback_backend) {
							/* Try fallback */
							g_assert (map->fallback_backend->protocol ==
									  MAP_PROTO_FILE);
							if (!read_map_file (map,
									map->fallback_backend->data.fd,
									map->fallback_backend, &fake_cbd)) {
								succeed = FALSE;
								break;
							}
						}
						else {
							succeed = FALSE;
							break;
						}
					}
				}
				else {
					g_assert_not_reached ();
				}
			}

			if (succeed) {
				map->fin_callback (&fake_cbd.cbdata, map->user_data);
			}
			else {
				msg_info_map ("preload of %s failed", map->name);
			}

		}

		cur = g_list_next (cur);
	}
}

void
rspamd_map_remove_all (struct rspamd_config *cfg)
{
	struct rspamd_map *map;
	GList *cur;
	struct rspamd_map_backend *bk;
	struct map_cb_data cbdata;
	guint i;

	for (cur = cfg->maps; cur != NULL; cur = g_list_next (cur)) {
		map = cur->data;

		if (map->tmp_dtor) {
			map->tmp_dtor (map->tmp_dtor_data);
		}

		if (map->dtor) {
			cbdata.prev_data = NULL;
			cbdata.map = map;
			cbdata.cur_data = *map->user_data;

			map->dtor (&cbdata);
			*map->user_data = NULL;
		}

		for (i = 0; i < map->backends->len; i ++) {
			bk = g_ptr_array_index (map->backends, i);

			MAP_RELEASE (bk, "rspamd_map_backend");
		}

		if (map->fallback_backend) {
			MAP_RELEASE (map->fallback_backend, "rspamd_map_backend");
		}
	}

	g_list_free (cfg->maps);
	cfg->maps = NULL;
}

static const gchar *
rspamd_map_check_proto (struct rspamd_config *cfg,
		const gchar *map_line, struct rspamd_map_backend *bk)
{
	const gchar *pos = map_line, *end, *end_key;

	g_assert (bk != NULL);
	g_assert (pos != NULL);

	end = pos + strlen (pos);

	/* Static check */
	if (g_ascii_strcasecmp (pos, "static") == 0) {
		bk->protocol = MAP_PROTO_STATIC;
		bk->uri = g_strdup (pos);

		return pos;
	}
	else if (g_ascii_strcasecmp (pos, "zst+static") == 0) {
		bk->protocol = MAP_PROTO_STATIC;
		bk->uri = g_strdup (pos + 4);
		bk->is_compressed = TRUE;

		return pos + 4;
	}

	for (;;) {
		if (g_ascii_strncasecmp (pos, "sign+", sizeof ("sign+") - 1) == 0) {
			bk->is_signed = TRUE;
			pos += sizeof ("sign+") - 1;
		}
		else if (g_ascii_strncasecmp (pos, "fallback+", sizeof ("fallback+") - 1) == 0) {
			bk->is_fallback = TRUE;
			pos += sizeof ("fallback+") - 1;
		}
		else if (g_ascii_strncasecmp (pos, "key=", sizeof ("key=") - 1) == 0) {
			pos += sizeof ("key=") - 1;
			end_key = memchr (pos, '+', end - pos);

			if (end_key != NULL) {
				bk->trusted_pubkey = rspamd_pubkey_from_base32 (pos, end_key - pos,
						RSPAMD_KEYPAIR_SIGN, RSPAMD_CRYPTOBOX_MODE_25519);

				if (bk->trusted_pubkey == NULL) {
					msg_err_config ("cannot read pubkey from map: %s",
							map_line);
					return NULL;
				}
				pos = end_key + 1;
			} else if (end - pos > 64) {
				/* Try hex encoding */
				bk->trusted_pubkey = rspamd_pubkey_from_hex (pos, 64,
						RSPAMD_KEYPAIR_SIGN, RSPAMD_CRYPTOBOX_MODE_25519);

				if (bk->trusted_pubkey == NULL) {
					msg_err_config ("cannot read pubkey from map: %s",
							map_line);
					return NULL;
				}
				pos += 64;
			} else {
				msg_err_config ("cannot read pubkey from map: %s",
						map_line);
				return NULL;
			}

			if (*pos == '+' || *pos == ':') {
				pos++;
			}
		}
		else {
			/* No known flags */
			break;
		}
	}

	bk->protocol = MAP_PROTO_FILE;

	if (g_ascii_strncasecmp (pos, "http://", sizeof ("http://") - 1) == 0) {
		bk->protocol = MAP_PROTO_HTTP;
		/* Include http:// */
		bk->uri = g_strdup (pos);
		pos += sizeof ("http://") - 1;
	}
	else if (g_ascii_strncasecmp (pos, "https://", sizeof ("https://") - 1) == 0) {
		bk->protocol = MAP_PROTO_HTTPS;
		/* Include https:// */
		bk->uri = g_strdup (pos);
		pos += sizeof ("https://") - 1;
	}
	else if (g_ascii_strncasecmp (pos, "file://", sizeof ("file://") - 1) == 0) {
		pos += sizeof ("file://") - 1;
		/* Exclude file:// */
		bk->uri = g_strdup (pos);
	}
	else if (*pos == '/') {
		/* Trivial file case */
		bk->uri = g_strdup (pos);
	}
	else {
		msg_err_config ("invalid map fetching protocol: %s", map_line);

		return NULL;
	}

	if (bk->protocol != MAP_PROTO_FILE && bk->is_signed) {
		msg_err_config ("signed maps are no longer supported for HTTP(s): %s", map_line);
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
	else if (g_ascii_strncasecmp (map_line, "fallback+", sizeof ("fallback+") - 1) == 0) {
		ret = TRUE;
	}
	else if (g_ascii_strncasecmp (map_line, "file://", sizeof ("file://") - 1) == 0) {
		ret = TRUE;
	}
	else if (g_ascii_strncasecmp (map_line, "http://", sizeof ("http://") - 1) == 0) {
		ret = TRUE;
	}
	else if (g_ascii_strncasecmp (map_line, "https://", sizeof ("https://") - 1) == 0) {
		ret = TRUE;
	}

	return ret;
}

static void
rspamd_map_backend_dtor (struct rspamd_map_backend *bk)
{
	g_free (bk->uri);

	switch (bk->protocol) {
	case MAP_PROTO_FILE:
		if (bk->data.fd) {
			ev_stat_stop (bk->event_loop, &bk->data.fd->st_ev);
			g_free (bk->data.fd->filename);
			g_free (bk->data.fd);
		}
		break;
	case MAP_PROTO_STATIC:
		if (bk->data.sd) {
			if (bk->data.sd->data) {
				g_free (bk->data.sd->data);
			}

			g_free (bk->data.sd);
		}
		break;
	case MAP_PROTO_HTTP:
	case MAP_PROTO_HTTPS:
		if (bk->data.hd) {
			struct http_map_data *data = bk->data.hd;

			g_free (data->host);
			g_free (data->path);
			g_free (data->rest);

			if (data->userinfo) {
				g_free (data->userinfo);
			}

			if (data->etag) {
				rspamd_fstring_free (data->etag);
			}

			if (g_atomic_int_compare_and_exchange (&data->cache->available, 1, 0)) {
				if (data->cur_cache_cbd) {
					MAP_RELEASE (data->cur_cache_cbd->shm,
							"rspamd_http_map_cached_cbdata");
					ev_timer_stop (data->cur_cache_cbd->event_loop,
							&data->cur_cache_cbd->timeout);
					g_free (data->cur_cache_cbd);
					data->cur_cache_cbd = NULL;
				}

				unlink (data->cache->shmem_name);
			}

			g_free (bk->data.hd);
		}
		break;
	}

	if (bk->trusted_pubkey) {
		rspamd_pubkey_unref (bk->trusted_pubkey);
	}

	g_free (bk);
}

static struct rspamd_map_backend *
rspamd_map_parse_backend (struct rspamd_config *cfg, const gchar *map_line)
{
	struct rspamd_map_backend *bk;
	struct file_map_data *fdata = NULL;
	struct http_map_data *hdata = NULL;
	struct static_map_data *sdata = NULL;
	struct http_parser_url up;
	const gchar *end, *p;
	rspamd_ftok_t tok;

	bk = g_malloc0 (sizeof (*bk));
	REF_INIT_RETAIN (bk, rspamd_map_backend_dtor);

	if (!rspamd_map_check_proto (cfg, map_line, bk)) {
		goto err;
	}

	if (bk->is_fallback && bk->protocol != MAP_PROTO_FILE) {
		msg_err_config ("fallback backend must be file for %s", bk->uri);

		goto err;
	}

	end = map_line + strlen (map_line);
	if (end - map_line > 5) {
		p = end - 5;
		if (g_ascii_strcasecmp (p, ".zstd") == 0) {
			bk->is_compressed = TRUE;
		}
		p = end - 4;
		if (g_ascii_strcasecmp (p, ".zst") == 0) {
			bk->is_compressed = TRUE;
		}
	}

	/* Now check for each proto separately */
	if (bk->protocol == MAP_PROTO_FILE) {
		fdata = g_malloc0 (sizeof (struct file_map_data));

		if (access (bk->uri, R_OK) == -1) {
			if (errno != ENOENT) {
				msg_err_config ("cannot open file '%s': %s", bk->uri, strerror (errno));
				goto err;
			}

			msg_info_config (
					"map '%s' is not found, but it can be loaded automatically later",
					bk->uri);
		}

		fdata->filename = g_strdup (bk->uri);
		bk->data.fd = fdata;
	}
	else if (bk->protocol == MAP_PROTO_HTTP || bk->protocol == MAP_PROTO_HTTPS) {
		hdata = g_malloc0 (sizeof (struct http_map_data));

		memset (&up, 0, sizeof (up));
		if (http_parser_parse_url (bk->uri, strlen (bk->uri), FALSE,
				&up) != 0) {
			msg_err_config ("cannot parse HTTP url: %s", bk->uri);
			goto err;
		}
		else {
			if (!(up.field_set & 1u << UF_HOST)) {
				msg_err_config ("cannot parse HTTP url: %s: no host", bk->uri);
				goto err;
			}

			tok.begin = bk->uri + up.field_data[UF_HOST].off;
			tok.len = up.field_data[UF_HOST].len;
			hdata->host = rspamd_ftokdup (&tok);

			if (up.field_set & (1u << UF_PORT)) {
				hdata->port = up.port;
			}
			else {
				if (bk->protocol == MAP_PROTO_HTTP) {
					hdata->port = 80;
				}
				else {
					hdata->port = 443;
				}
			}

			if (up.field_set & (1u << UF_PATH)) {
				tok.begin = bk->uri + up.field_data[UF_PATH].off;
				tok.len = up.field_data[UF_PATH].len;

				hdata->path = rspamd_ftokdup (&tok);

				/* We also need to check query + fragment */
				if (up.field_set & ((1u << UF_QUERY) | (1u << UF_FRAGMENT))) {
					tok.begin = bk->uri + up.field_data[UF_PATH].off +
							up.field_data[UF_PATH].len;
					tok.len = strlen (tok.begin);
					hdata->rest = rspamd_ftokdup (&tok);
				}
				else {
					hdata->rest = g_strdup ("");
				}
			}

			if (up.field_set & (1u << UF_USERINFO)) {
				/* Create authorisation header for basic auth */
				guint len = sizeof ("Basic ") +
							up.field_data[UF_USERINFO].len * 8 / 5 + 4;
				hdata->userinfo = g_malloc (len);
				rspamd_snprintf (hdata->userinfo, len, "Basic %*Bs",
						(int)up.field_data[UF_USERINFO].len,
						bk->uri + up.field_data[UF_USERINFO].off);
			}
		}

		hdata->cache = rspamd_mempool_alloc0_shared (cfg->cfg_pool,
						sizeof (*hdata->cache));

		bk->data.hd = hdata;
	}
	else if (bk->protocol == MAP_PROTO_STATIC) {
		sdata = g_malloc0 (sizeof (*sdata));
		bk->data.sd = sdata;
	}

	bk->id = rspamd_cryptobox_fast_hash_specific (RSPAMD_CRYPTOBOX_T1HA,
			bk->uri, strlen (bk->uri), 0xdeadbabe);

	return bk;

err:
	MAP_RELEASE (bk, "rspamd_map_backend");

	if (hdata) {
		g_free (hdata);
	}

	if (fdata) {
		g_free (fdata);
	}

	if (sdata) {
		g_free (sdata);
	}

	return NULL;
}

static void
rspamd_map_calculate_hash (struct rspamd_map *map)
{
	struct rspamd_map_backend *bk;
	guint i;
	rspamd_cryptobox_hash_state_t st;
	gchar *cksum_encoded, cksum[rspamd_cryptobox_HASHBYTES];

	rspamd_cryptobox_hash_init (&st, NULL, 0);

	for (i = 0; i < map->backends->len; i ++) {
		bk = g_ptr_array_index (map->backends, i);
		rspamd_cryptobox_hash_update (&st, bk->uri, strlen (bk->uri));
	}

	rspamd_cryptobox_hash_final (&st, cksum);
	cksum_encoded = rspamd_encode_base32 (cksum, sizeof (cksum), RSPAMD_BASE32_DEFAULT);
	rspamd_strlcpy (map->tag, cksum_encoded, sizeof (map->tag));
	g_free (cksum_encoded);
}

static gboolean
rspamd_map_add_static_string (struct rspamd_config *cfg,
		const ucl_object_t *elt,
		GString *target)
{
	gsize sz;
	const gchar *dline;

	if (ucl_object_type (elt) != UCL_STRING) {
		msg_err_config ("map has static backend but `data` is "
						"not string like: %s",
				ucl_object_type_to_string (elt->type));
		return FALSE;
	}

	/* Otherwise, we copy data to the backend */
	dline = ucl_object_tolstring (elt, &sz);

	if (sz == 0) {
		msg_err_config ("map has static backend but empty no data");
		return FALSE;
	}

	g_string_append_len (target, dline, sz);
	g_string_append_c (target, '\n');

	return TRUE;
}

struct rspamd_map *
rspamd_map_add (struct rspamd_config *cfg,
				const gchar *map_line,
				const gchar *description,
				map_cb_t read_callback,
				map_fin_cb_t fin_callback,
				map_dtor_t dtor,
				void **user_data,
				struct rspamd_worker *worker,
				int flags)
{
	struct rspamd_map *map;
	struct rspamd_map_backend *bk;

	bk = rspamd_map_parse_backend (cfg, map_line);
	if (bk == NULL) {
		return NULL;
	}

	if (bk->is_fallback) {
		msg_err_config ("cannot add map with fallback only backend: %s", bk->uri);
		REF_RELEASE (bk);

		return NULL;
	}

	map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (struct rspamd_map));
	map->read_callback = read_callback;
	map->fin_callback = fin_callback;
	map->dtor = dtor;
	map->user_data = user_data;
	map->cfg = cfg;
	map->id = rspamd_random_uint64_fast ();
	map->locked =
		rspamd_mempool_alloc0_shared (cfg->cfg_pool, sizeof (gint));
	map->backends = g_ptr_array_sized_new (1);
	map->wrk = worker;
	rspamd_mempool_add_destructor (cfg->cfg_pool, rspamd_ptr_array_free_hard,
			map->backends);
	g_ptr_array_add (map->backends, bk);
	map->name = rspamd_mempool_strdup (cfg->cfg_pool, map_line);
	map->no_file_read = (flags & RSPAMD_MAP_FILE_NO_READ);

	if (bk->protocol == MAP_PROTO_FILE) {
		map->poll_timeout = (cfg->map_timeout * cfg->map_file_watch_multiplier);
	} else {
		map->poll_timeout = cfg->map_timeout;
	}

	if (description != NULL) {
		map->description = rspamd_mempool_strdup (cfg->cfg_pool, description);
	}

	rspamd_map_calculate_hash (map);
	msg_info_map ("added map %s", bk->uri);

	cfg->maps = g_list_prepend (cfg->maps, map);

	return map;
}

struct rspamd_map *
rspamd_map_add_fake (struct rspamd_config *cfg,
				const gchar *description,
				const gchar *name)
{
	struct rspamd_map *map;

	map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (struct rspamd_map));
	map->cfg = cfg;
	map->id = rspamd_random_uint64_fast ();
	map->name = rspamd_mempool_strdup (cfg->cfg_pool, name);
	map->user_data = (void **)&map; /* to prevent null pointer dereferencing */

	if (description != NULL) {
		map->description = rspamd_mempool_strdup (cfg->cfg_pool, description);
	}

	return map;
}

static inline void
rspamd_map_add_backend (struct rspamd_map *map, struct rspamd_map_backend *bk)
{
	if (bk->is_fallback) {
		if (map->fallback_backend) {
			msg_warn_map ("redefining fallback backend from %s to %s",
					map->fallback_backend->uri, bk->uri);
		}

		map->fallback_backend = bk;
	}
	else {
		g_ptr_array_add (map->backends, bk);
	}
}

struct rspamd_map*
rspamd_map_add_from_ucl (struct rspamd_config *cfg,
						 const ucl_object_t *obj,
						 const gchar *description,
						 map_cb_t read_callback,
						 map_fin_cb_t fin_callback,
						 map_dtor_t dtor,
						 void **user_data,
						 struct rspamd_worker *worker,
						 gint flags)
{
	ucl_object_iter_t it = NULL;
	const ucl_object_t *cur, *elt;
	struct rspamd_map *map;
	struct rspamd_map_backend *bk;
	guint i;

	g_assert (obj != NULL);

	if (ucl_object_type (obj) == UCL_STRING) {
		/* Just a plain string */
		return rspamd_map_add (cfg, ucl_object_tostring (obj), description,
				read_callback, fin_callback, dtor, user_data, worker, flags);
	}

	map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (struct rspamd_map));
	map->read_callback = read_callback;
	map->fin_callback = fin_callback;
	map->dtor = dtor;
	map->user_data = user_data;
	map->cfg = cfg;
	map->id = rspamd_random_uint64_fast ();
	map->locked =
			rspamd_mempool_alloc0_shared (cfg->cfg_pool, sizeof (gint));
	map->backends = g_ptr_array_new ();
	map->wrk = worker;
	map->no_file_read = (flags & RSPAMD_MAP_FILE_NO_READ);
	rspamd_mempool_add_destructor (cfg->cfg_pool, rspamd_ptr_array_free_hard,
			map->backends);
	map->poll_timeout = cfg->map_timeout;

	if (description) {
		map->description = rspamd_mempool_strdup (cfg->cfg_pool, description);
	}

	if (ucl_object_type (obj) == UCL_ARRAY) {
		/* Add array of maps as multiple backends */
		while ((cur = ucl_object_iterate (obj, &it, true)) != NULL) {
			if (ucl_object_type (cur) == UCL_STRING) {
				bk = rspamd_map_parse_backend (cfg, ucl_object_tostring (cur));

				if (bk != NULL) {
					rspamd_map_add_backend (map, bk);

					if (!map->name) {
						map->name = rspamd_mempool_strdup (cfg->cfg_pool,
								ucl_object_tostring (cur));
					}
				}
			}
			else {
				msg_err_config ("bad map element type: %s",
						ucl_object_type_to_string (ucl_object_type (cur)));
			}
		}

		if (map->backends->len == 0) {
			msg_err_config ("map has no urls to be loaded: empty list");
			goto err;
		}
	}
	else if (ucl_object_type (obj) == UCL_OBJECT) {
		elt = ucl_object_lookup (obj, "name");
		if (elt && ucl_object_type (elt) == UCL_STRING) {
			map->name = rspamd_mempool_strdup (cfg->cfg_pool,
					ucl_object_tostring (elt));
		}

		elt = ucl_object_lookup (obj, "description");
		if (elt && ucl_object_type (elt) == UCL_STRING) {
			map->description = rspamd_mempool_strdup (cfg->cfg_pool,
					ucl_object_tostring (elt));
		}

		elt = ucl_object_lookup_any (obj, "timeout", "poll", "poll_time",
				"watch_interval", NULL);
		if (elt) {
			map->poll_timeout = ucl_object_todouble (elt);
		}

		elt = ucl_object_lookup_any (obj, "upstreams", "url", "urls", NULL);
		if (elt == NULL) {
			msg_err_config ("map has no urls to be loaded: no elt");
			goto err;
		}

		if (ucl_object_type (elt) == UCL_ARRAY) {
			/* Add array of maps as multiple backends */
			it = ucl_object_iterate_new (elt);

			while ((cur = ucl_object_iterate_safe (it, true)) != NULL) {
				if (ucl_object_type (cur) == UCL_STRING) {
					bk = rspamd_map_parse_backend (cfg, ucl_object_tostring (cur));

					if (bk != NULL) {
						rspamd_map_add_backend (map, bk);

						if (!map->name) {
							map->name = rspamd_mempool_strdup (cfg->cfg_pool,
									ucl_object_tostring (cur));
						}
					}
				}
				else {
					msg_err_config ("bad map element type: %s",
							ucl_object_type_to_string (ucl_object_type (cur)));
					ucl_object_iterate_free (it);
					goto err;
				}
			}

			ucl_object_iterate_free (it);

			if (map->backends->len == 0) {
				msg_err_config ("map has no urls to be loaded: empty object list");
				goto err;
			}
		}
		else if (ucl_object_type (elt) == UCL_STRING) {
			bk = rspamd_map_parse_backend (cfg, ucl_object_tostring (elt));

			if (bk != NULL) {
				rspamd_map_add_backend (map, bk);

				if (!map->name) {
					map->name = rspamd_mempool_strdup (cfg->cfg_pool,
							ucl_object_tostring (elt));
				}
			}
		}

		if (!map->backends || map->backends->len == 0) {
			msg_err_config ("map has no urls to be loaded: no valid backends");
			goto err;
		}
	}
	else {
		msg_err_config ("map has invalid type for value: %s",
				ucl_object_type_to_string (ucl_object_type (obj)));
		goto err;
	}

	gboolean all_local = TRUE;

	PTR_ARRAY_FOREACH (map->backends, i, bk) {
		if (bk->protocol == MAP_PROTO_STATIC) {
			GString *map_data;
			/* We need data field in ucl */
			elt = ucl_object_lookup (obj, "data");

			if (elt == NULL) {
				msg_err_config ("map has static backend but no `data` field");
				goto err;
			}


			if (ucl_object_type (elt) == UCL_STRING) {
				map_data = g_string_sized_new (32);

				if (rspamd_map_add_static_string (cfg, elt, map_data)) {
					bk->data.sd->data = map_data->str;
					bk->data.sd->len = map_data->len;
					g_string_free (map_data, FALSE);
				}
				else {
					g_string_free (map_data, TRUE);
					msg_err_config ("map has static backend with invalid `data` field");
					goto err;
				}
			}
			else if (ucl_object_type (elt) == UCL_ARRAY) {
				map_data = g_string_sized_new (32);
				it = ucl_object_iterate_new (elt);

				while ((cur = ucl_object_iterate_safe (it, true))) {
					if (!rspamd_map_add_static_string (cfg, cur, map_data)) {
						g_string_free (map_data, TRUE);
						msg_err_config ("map has static backend with invalid "
										"`data` field");
						ucl_object_iterate_free (it);
						goto err;
					}
				}

				ucl_object_iterate_free (it);
				bk->data.sd->data = map_data->str;
				bk->data.sd->len = map_data->len;
				g_string_free (map_data, FALSE);
			}
		}
		else if (bk->protocol != MAP_PROTO_FILE) {
			all_local = FALSE;
		}
	}

	if (all_local) {
		map->poll_timeout = (map->poll_timeout *
							 cfg->map_file_watch_multiplier);
	}

	rspamd_map_calculate_hash (map);
	msg_debug_map ("added map from ucl");

	cfg->maps = g_list_prepend (cfg->maps, map);

	return map;

err:

	if (map) {
		PTR_ARRAY_FOREACH (map->backends, i, bk) {
			MAP_RELEASE (bk, "rspamd_map_backend");
		}
	}

	return NULL;
}

rspamd_map_traverse_function
rspamd_map_get_traverse_function (struct rspamd_map *map)
{
	if (map) {
		return map->traverse_function;
	}

	return NULL;
}

void
rspamd_map_traverse (struct rspamd_map *map, rspamd_map_traverse_cb cb,
		gpointer cbdata, gboolean reset_hits)
{
	if (*map->user_data && map->traverse_function) {
		map->traverse_function (*map->user_data, cb, cbdata, reset_hits);
	}
}
