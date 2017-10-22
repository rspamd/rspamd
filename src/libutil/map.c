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
#include "http_private.h"
#include "rspamd.h"
#include "contrib/zstd/zstd.h"

#ifdef WITH_HYPERSCAN
#include "hs.h"
#endif
#ifndef WITH_PCRE2
#include <pcre.h>
#else
#include <pcre2.h>
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

static const gchar *hash_fill = "1";
static void free_http_cbdata_common (struct http_callback_data *cbd, gboolean plan_new);
static void free_http_cbdata_dtor (gpointer p);
static void free_http_cbdata (struct http_callback_data *cbd);
static void rspamd_map_periodic_callback (gint fd, short what, void *ud);
static void rspamd_map_schedule_periodic (struct rspamd_map *map, gboolean locked,
		gboolean initial, gboolean errored);

struct rspamd_http_map_cached_cbdata {
	struct event timeout;
	struct rspamd_storage_shmem *shm;
	struct rspamd_map *map;
	struct http_map_data *data;
	guint64 gen;
	time_t last_checked;
};

/**
 * Write HTTP request
 */
static void
write_http_request (struct http_callback_data *cbd)
{
	gchar datebuf[128];
	struct rspamd_http_message *msg;
	struct rspamd_map *map;

	map = cbd->map;

	if (cbd->fd != -1) {
		close (cbd->fd);
	}

	cbd->fd = rspamd_inet_address_connect (cbd->addr, SOCK_STREAM, TRUE);

	if (cbd->fd != -1) {
		msg = rspamd_http_new_message (HTTP_REQUEST);

		if (cbd->bk->protocol == MAP_PROTO_HTTPS) {
			msg->flags |= RSPAMD_HTTP_FLAG_SSL;
		}

		if (cbd->check) {
			msg->method = HTTP_HEAD;
		}

		if (cbd->stage == map_load_file) {
			msg->url = rspamd_fstring_append (msg->url,
					cbd->data->path, strlen (cbd->data->path));

			if (cbd->check &&
					cbd->data->last_modified != 0 && cbd->stage == map_load_file) {
				rspamd_http_date_format (datebuf, sizeof (datebuf),
						cbd->data->last_modified);
				rspamd_http_message_add_header (msg, "If-Modified-Since", datebuf);
			}
		}
		else if (cbd->stage == map_load_pubkey) {
			msg->url = rspamd_fstring_append (msg->url,
					cbd->data->path, strlen (cbd->data->path));
			msg->url = rspamd_fstring_append (msg->url, ".pub", 4);
		}
		else if (cbd->stage == map_load_signature) {
			msg->url = rspamd_fstring_append (msg->url,
					cbd->data->path, strlen (cbd->data->path));
			msg->url = rspamd_fstring_append (msg->url, ".sig", 4);
		}
		else {
			g_assert_not_reached ();
		}

		MAP_RETAIN (cbd, "http_callback_data");
		rspamd_http_connection_write_message (cbd->conn, msg, cbd->data->host,
				NULL, cbd, cbd->fd, &cbd->tv, cbd->ev_base);
	}
	else {
		msg_err_map ("cannot connect to %s: %s", cbd->data->host,
				strerror (errno));
		cbd->periodic->errored = TRUE;
	}
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

	if (ret && !rspamd_cryptobox_verify (sig, input, inlen,
			rspamd_pubkey_get_pk (pk, NULL), RSPAMD_CRYPTOBOX_MODE_25519)) {
		msg_err_map ("can't verify signature for %s: incorrect signature", map->name);

		ret = FALSE;
	}

	if (ret) {
		b32_key = rspamd_pubkey_print (pk,
				RSPAMD_KEYPAIR_BASE32|RSPAMD_KEYPAIR_PUBKEY);
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
		gsize inlen)
{
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
				RSPAMD_KEYPAIR_BASE32|RSPAMD_KEYPAIR_PUBKEY);
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
 * Callback for destroying HTTP callback data
 */
static void
free_http_cbdata_common (struct http_callback_data *cbd, gboolean plan_new)
{
	struct map_periodic_cbdata *periodic = cbd->periodic;

	if (cbd->shmem_sig) {
		rspamd_http_message_shmem_unref (cbd->shmem_sig);
	}

	if (cbd->shmem_pubkey) {
		rspamd_http_message_shmem_unref (cbd->shmem_pubkey);
	}

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

	if (cbd->fd != -1) {
		close (cbd->fd);
	}

	if (cbd->addr) {
		rspamd_inet_address_free (cbd->addr);
	}


	MAP_RELEASE (cbd->bk, "rspamd_map_backend");
	MAP_RELEASE (periodic, "periodic");
	g_slice_free1 (sizeof (struct http_callback_data), cbd);
}

static void
free_http_cbdata (struct http_callback_data *cbd)
{
	cbd->map->dtor = NULL;
	cbd->map->dtor_data = NULL;

	free_http_cbdata_common (cbd, TRUE);
}

static void
free_http_cbdata_dtor (gpointer p)
{
	struct http_callback_data *cbd = p;
	struct rspamd_map *map;

	map = cbd->map;
	if (cbd->stage >= map_load_file) {
		REF_RELEASE (cbd);
	}
	else {
		/* We cannot terminate DNS requests sent */
		cbd->stage = map_finished;
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
	cbd->periodic->errored = TRUE;
	msg_err_map ("error reading %s(%s): "
			"connection with http server terminated incorrectly: %e",
			cbd->bk->uri,
			cbd->addr ? rspamd_inet_address_to_string_pretty (cbd->addr) : "",
			err);
	rspamd_map_periodic_callback (-1, EV_TIMEOUT, cbd->periodic);
	MAP_RELEASE (cbd, "http_callback_data");
}

static void
rspamd_map_cache_cb (gint fd, short what, gpointer ud)
{
	struct rspamd_http_map_cached_cbdata *cache_cbd = ud;
	struct rspamd_map *map;
	struct timeval tv;

	map = cache_cbd->map;

	if (cache_cbd->gen != cache_cbd->data->gen) {
		/* We have another update, so this cache element is obviously expired */
		/* Important: we do not set cache availability to zero here */
		MAP_RELEASE (cache_cbd->shm, "rspamd_http_map_cached_cbdata");
		msg_debug_map ("cached data is now expired (gen missmatch) for %s", map->name);
		event_del (&cache_cbd->timeout);
		g_slice_free1 (sizeof (*cache_cbd), cache_cbd);
	}
	else if (cache_cbd->data->last_checked > cache_cbd->last_checked) {
		/*
		 * We checked map but we have not found anything more recent,
		 * reschedule cache check
		 */
		cache_cbd->last_checked = cache_cbd->data->last_checked;
		msg_debug_map ("cached data is up to date for %s", map->name);
		double_to_tv (map->poll_timeout * 2, &tv);
		event_add (&cache_cbd->timeout, &tv);
	}
	else {
		g_atomic_int_set (&map->cache->available, 0);
		MAP_RELEASE (cache_cbd->shm, "rspamd_http_map_cached_cbdata");
		msg_debug_map ("cached data is now expired for %s", map->name);
		event_del (&cache_cbd->timeout);
		g_slice_free1 (sizeof (*cache_cbd), cache_cbd);
	}
}

static int
http_map_finish (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg)
{
	struct http_callback_data *cbd = conn->ud;
	struct rspamd_map *map;
	struct rspamd_map_backend *bk;
	struct rspamd_http_map_cached_cbdata *cache_cbd;
	struct timeval tv;
	const rspamd_ftok_t *expires_hdr;
	guchar *aux_data, *in = NULL;
	gsize inlen = 0, dlen = 0;

	map = cbd->map;
	bk = cbd->bk;

	if (msg->code == 200) {

		if (cbd->check) {
			cbd->periodic->need_modify = TRUE;
			/* Reset the whole chain */
			cbd->periodic->cur_backend = 0;
			rspamd_map_periodic_callback (-1, EV_TIMEOUT, cbd->periodic);
			MAP_RELEASE (cbd, "http_callback_data");

			return 0;
		}

		if (cbd->stage == map_load_file) {
			cbd->data->last_checked = msg->date;

			if (msg->last_modified) {
				cbd->data->last_modified = msg->last_modified;
			}
			else {
				cbd->data->last_modified = msg->date;
			}

			/* Maybe we need to check signature ? */
			if (bk->is_signed) {

				if (bk->trusted_pubkey) {
					/* No need to load key */
					cbd->stage = map_load_signature;
					cbd->pk = rspamd_pubkey_ref (bk->trusted_pubkey);
				}
				else {
					cbd->stage = map_load_pubkey;
				}

				cbd->shmem_data = rspamd_http_message_shmem_ref (msg);
				cbd->data_len = msg->body_buf.len;
				rspamd_http_connection_reset (cbd->conn);
				write_http_request (cbd);
				MAP_RELEASE (cbd, "http_callback_data");

				return 0;
			}
			else {
				/* Unsigned version - just open file */
				cbd->shmem_data = rspamd_http_message_shmem_ref (msg);
				cbd->data_len = msg->body_buf.len;

				goto read_data;
			}
		}
		else if (cbd->stage == map_load_pubkey) {
			/* We now can load pubkey */
			cbd->shmem_pubkey = rspamd_http_message_shmem_ref (msg);
			cbd->pubkey_len = msg->body_buf.len;

			aux_data = rspamd_shmem_xmap (cbd->shmem_pubkey->shm_name,
					PROT_READ, &inlen);

			if (aux_data == NULL) {
				msg_err_map ("cannot map pubkey file %s: %s",
						cbd->shmem_pubkey->shm_name, strerror (errno));
				goto err;
			}

			if (inlen < cbd->pubkey_len) {
				msg_err_map ("cannot map pubkey file %s: %s",
						cbd->shmem_pubkey->shm_name, strerror (errno));
				munmap (aux_data, inlen);
				goto err;
			}

			cbd->pk = rspamd_pubkey_from_base32 (aux_data, cbd->pubkey_len,
					RSPAMD_KEYPAIR_SIGN, RSPAMD_CRYPTOBOX_MODE_25519);
			munmap (aux_data, inlen);

			if (cbd->pk == NULL) {
				msg_err_map ("cannot load pubkey file %s: bad pubkey",
						cbd->shmem_pubkey->shm_name);
				goto err;
			}

			cbd->stage = map_load_signature;
			rspamd_http_connection_reset (cbd->conn);
			write_http_request (cbd);
			MAP_RELEASE (cbd, "http_callback_data");

			return 0;
		}
		else if (cbd->stage == map_load_signature) {
			/* We can now check signature */
			cbd->shmem_sig = rspamd_http_message_shmem_ref (msg);
			cbd->sig_len = msg->body_buf.len;

			aux_data = rspamd_shmem_xmap (cbd->shmem_sig->shm_name,
					PROT_READ, &inlen);

			if (aux_data == NULL) {
				msg_err_map ("cannot map signature file %s: %s",
						cbd->shmem_sig->shm_name, strerror (errno));
				goto err;
			}

			if (inlen < cbd->sig_len) {
				msg_err_map ("cannot map pubkey file %s: %s",
						cbd->shmem_pubkey->shm_name, strerror (errno));
				munmap (aux_data, inlen);
				goto err;
			}

			in = rspamd_shmem_xmap (cbd->shmem_data->shm_name, PROT_READ, &dlen);

			if (in == NULL) {
				msg_err_map ("cannot read tempfile %s: %s",
						cbd->shmem_data->shm_name,
						strerror (errno));
				munmap (aux_data, inlen);
				goto err;
			}

			if (!rspamd_map_check_sig_pk_mem (aux_data, cbd->sig_len, map, in,
					cbd->data_len, cbd->pk)) {
				munmap (aux_data, inlen);
				munmap (in, dlen);
				goto err;
			}

			munmap (in, dlen);
		}

read_data:
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
		expires_hdr = rspamd_http_message_find_header (msg, "Expires");

		if (expires_hdr) {
			time_t hdate;

			hdate = rspamd_http_parse_date (expires_hdr->begin, expires_hdr->len);

			if (hdate != (time_t)-1 && hdate > msg->date) {
				if (map->next_check) {
					/* If we have multiple backends */
					hdate = MIN (map->next_check, hdate);
				}

				double cached_timeout = map->next_check - msg->date +
					map->poll_timeout * 2;

				map->next_check = hdate;
				double_to_tv (cached_timeout, &tv);
			}
			else {
				double_to_tv (map->poll_timeout * 2, &tv);
			}
		}
		else {
			double_to_tv (map->poll_timeout * 2, &tv);
		}

		MAP_RETAIN (cbd->shmem_data, "shmem_data");
		cbd->data->gen ++;
		/*
		 * We know that a map is in the locked state
		 */
		g_atomic_int_set (&map->cache->available, 1);
		/* Store cached data */
		rspamd_strlcpy (map->cache->shmem_name, cbd->shmem_data->shm_name,
				sizeof (map->cache->shmem_name));
		map->cache->len = cbd->data_len;
		map->cache->last_modified = cbd->data->last_modified;
		cache_cbd = g_slice_alloc0 (sizeof (*cache_cbd));
		cache_cbd->shm = cbd->shmem_data;
		cache_cbd->map = map;
		cache_cbd->data = cbd->data;
		cache_cbd->last_checked = cbd->data->last_checked;
		cache_cbd->gen = cbd->data->gen;
		MAP_RETAIN (cache_cbd->shm, "shmem_data");

		event_set (&cache_cbd->timeout, -1, EV_TIMEOUT, rspamd_map_cache_cb,
				cache_cbd);
		event_base_set (cbd->ev_base, &cache_cbd->timeout);
		event_add (&cache_cbd->timeout, &tv);


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
					zout.size = zout.size * 1.5 + 1.0;
					out = g_realloc (zout.dst, zout.size);
					zout.dst = out;
				}
			}

			ZSTD_freeDStream (zstream);
			msg_info_map ("%s(%s): read map data %z bytes compressed, "
					"%z uncompressed",
					cbd->bk->uri,
					rspamd_inet_address_to_string_pretty (cbd->addr),
					dlen, zout.pos);
			map->read_callback (out, zout.pos, &cbd->periodic->cbdata, TRUE);
			g_free (out);
		}
		else {
			msg_info_map ("%s(%s): read map data %z bytes",
					cbd->bk->uri,
					rspamd_inet_address_to_string_pretty (cbd->addr),
					dlen);
			map->read_callback (in, cbd->data_len, &cbd->periodic->cbdata, TRUE);
		}

		MAP_RELEASE (cbd->shmem_data, "shmem_data");

		cbd->periodic->cur_backend ++;
		munmap (in, dlen);
		rspamd_map_periodic_callback (-1, EV_TIMEOUT, cbd->periodic);
	}
	else if (msg->code == 304 && (cbd->check && cbd->stage == map_load_file)) {
		msg_debug_map ("data is not modified for server %s",
				cbd->data->host);

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
				if (map->next_check) {
					/* If we have multiple backends */
					hdate = MIN (map->next_check, hdate);
				}

				map->next_check = hdate;
			}
		}

		cbd->periodic->cur_backend ++;
		rspamd_map_periodic_callback (-1, EV_TIMEOUT, cbd->periodic);
	}
	else {
		msg_info_map ("cannot load map %s from %s: HTTP error %d",
				bk->uri, cbd->data->host, msg->code);
	}

	MAP_RELEASE (cbd, "http_callback_data");
	return 0;

err:
	cbd->periodic->errored = 1;
	rspamd_map_periodic_callback (-1, EV_TIMEOUT, cbd->periodic);
	MAP_RELEASE (cbd, "http_callback_data");

	return 0;
}

/**
 * Callback for reading data from file
 */
static gboolean
read_map_file (struct rspamd_map *map, struct file_map_data *data,
		struct rspamd_map_backend *bk, struct map_periodic_cbdata *periodic)
{
	guchar *bytes;
	gsize len;

	if (map->read_callback == NULL || map->fin_callback == NULL) {
		msg_err_map ("%s: bad callback for reading map file",
				data->filename);
		return FALSE;
	}

	if (access (data->filename, R_OK) == -1) {
		/* File does not exist, skipping */
		msg_err_map ("%s: map file is unavailable for reading",
				data->filename);
		return TRUE;
	}

	bytes = rspamd_file_xmap (data->filename, PROT_READ, &len, TRUE);

	if (bytes == NULL) {
		msg_err_map ("can't open map %s: %s", data->filename, strerror (errno));
		return FALSE;
	}

	if (bk->is_signed) {
		if (!rspamd_map_check_file_sig (data->filename, map, bk, bytes, len)) {
			munmap (bytes, len);

			return FALSE;
		}
	}

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
							data->filename,
							ZSTD_getErrorName (r));
					ZSTD_freeDStream (zstream);
					g_free (out);
					munmap (bytes, len);
					return FALSE;
				}

				if (zout.pos == zout.size) {
					/* We need to extend output buffer */
					zout.size = zout.size * 1.5 + 1.0;
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
		}
		else {
			msg_info_map ("%s: read map dat, %z bytes", data->filename,
					len);
			map->read_callback (bytes, len, &periodic->cbdata, TRUE);
		}
	}
	else {
		map->read_callback (NULL, 0, &periodic->cbdata, TRUE);
	}

	munmap (bytes, len);

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
					zout.size = zout.size * 1.5 + 1.0;
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
	event_del (&periodic->ev);

	if (periodic->need_modify) {
		/* We are done */
		periodic->map->fin_callback (&periodic->cbdata);

		if (periodic->cbdata.cur_data) {
			*periodic->map->user_data = periodic->cbdata.cur_data;
		}
	}
	else {
		/* Not modified */
	}

	if (periodic->locked) {
		rspamd_map_schedule_periodic (periodic->map, FALSE, FALSE, FALSE);
		g_atomic_int_set (periodic->map->locked, 0);
		msg_debug_map ("unlocked map");
	}

	g_slice_free1 (sizeof (*periodic), periodic);
}

static void
rspamd_map_schedule_periodic (struct rspamd_map *map,
		gboolean locked, gboolean initial, gboolean errored)
{
	const gdouble error_mult = 20.0, lock_mult = 0.1;
	gdouble jittered_sec;
	gdouble timeout;
	struct map_periodic_cbdata *cbd;

	if (map->next_check != 0) {
		timeout = map->next_check - rspamd_get_calendar_ticks ();

		if (timeout < map->poll_timeout) {
			timeout = map->poll_timeout;

			if (errored) {
				timeout = map->poll_timeout * error_mult;
			}
			else if (locked) {
				timeout = map->poll_timeout * lock_mult;
			}

			jittered_sec = rspamd_time_jitter (timeout, 0);
		}
		else {
			jittered_sec = rspamd_time_jitter (timeout, map->poll_timeout);
		}

		/* Reset till the next usage */
		map->next_check = 0;
	}
	else {
		timeout = map->poll_timeout;

		if (initial) {
			timeout = 0.0;
		} else {
			if (errored) {
				timeout = map->poll_timeout * error_mult;
			}
			else if (locked) {
				timeout = map->poll_timeout * lock_mult;
			}
		}

		jittered_sec = rspamd_time_jitter (timeout, 0);
	}

	cbd = g_slice_alloc0 (sizeof (*cbd));
	cbd->cbdata.state = 0;
	cbd->cbdata.prev_data = *map->user_data;
	cbd->cbdata.cur_data = NULL;
	cbd->cbdata.map = map;
	cbd->map = map;
	REF_INIT_RETAIN (cbd, rspamd_map_periodic_dtor);

	evtimer_set (&cbd->ev, rspamd_map_periodic_callback, cbd);
	event_base_set (map->ev_base, &cbd->ev);


	msg_debug_map ("schedule new periodic event %p in %.2f seconds",
			cbd, jittered_sec);
	double_to_tv (jittered_sec, &map->tv);

	evtimer_add (&cbd->ev, &map->tv);
}

static void
rspamd_map_dns_callback (struct rdns_reply *reply, void *arg)
{
	struct http_callback_data *cbd = arg;
	struct rspamd_map *map;
	guint flags = RSPAMD_HTTP_CLIENT_SIMPLE|RSPAMD_HTTP_CLIENT_SHARED;

	map = cbd->map;

	if (cbd->stage == map_finished) {
		MAP_RELEASE (cbd, "http_callback_data");
		return;
	}

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
					cbd->conn = rspamd_http_connection_new (NULL,
							http_map_error,
							http_map_finish,
							flags,
							RSPAMD_HTTP_CLIENT,
							NULL,
							cbd->map->cfg->libs_ctx->ssl_ctx);

					write_http_request (cbd);
				}
				else {
					rspamd_inet_address_free (cbd->addr);
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
			msg_err_map ("cannot resolve %s", cbd->data->host);
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

	in = rspamd_shmem_xmap (map->cache->shmem_name, PROT_READ, &len);

	if (in == NULL) {
		msg_err ("cannot map cache from %s: %s", map->cache->shmem_name,
				strerror (errno));
		return FALSE;
	}

	if (len < map->cache->len) {
		msg_err ("cannot map cache from %s: bad length %z, %z expected",
				map->cache->shmem_name,
				len, map->cache->len);
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
				zout.size = zout.size * 1.5 + 1.0;
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

	if (g_atomic_int_get (&map->cache->available) == 1) {
		/* Read cached data */
		if (check) {
			if (data->last_modified < map->cache->last_modified) {
				periodic->need_modify = TRUE;
				/* Reset the whole chain */
				periodic->cur_backend = 0;
				rspamd_map_periodic_callback (-1, EV_TIMEOUT, periodic);
			}
			else {
				if (map->active_http) {
					/* Check even if there is a cached version */
					goto check;
				}
				else {
					/* Switch to the next backend */
					periodic->cur_backend++;
					rspamd_map_periodic_callback (-1, EV_TIMEOUT, periodic);
				}
			}

			return;
		}
		else {
			if (map->active_http &&
					data->last_modified > map->cache->last_modified) {
				goto check;
			}
			else if (rspamd_map_read_cached (map, bk, periodic, data->host)) {
				/* Switch to the next backend */
				periodic->cur_backend++;
				data->last_modified = map->cache->last_modified;
				rspamd_map_periodic_callback (-1, EV_TIMEOUT, periodic);

				return;
			}
		}
	}
	else if (!map->active_http) {
		/* Switch to the next backend */
		periodic->cur_backend ++;
		rspamd_map_periodic_callback (-1, EV_TIMEOUT, periodic);

		return;
	}

check:
	cbd = g_slice_alloc0 (sizeof (struct http_callback_data));

	cbd->ev_base = map->ev_base;
	cbd->map = map;
	cbd->data = data;
	cbd->fd = -1;
	cbd->check = check;
	cbd->periodic = periodic;
	MAP_RETAIN (periodic, "periodic");
	cbd->bk = bk;
	MAP_RETAIN (bk, "rspamd_map_backend");
	cbd->stage = map_resolve_host2;
	double_to_tv (map->cfg->map_timeout, &cbd->tv);
	REF_INIT_RETAIN (cbd, free_http_cbdata);

	msg_debug_map ("%s map data from %s", check ? "checking" : "reading",
			data->host);
	/* Send both A and AAAA requests */
	if (rspamd_parse_inet_address (&cbd->addr, data->host, strlen (data->host))) {
		rspamd_inet_address_set_port (cbd->addr, cbd->data->port);
		cbd->fd = rspamd_inet_address_connect (cbd->addr, SOCK_STREAM,
				TRUE);

		if (cbd->fd != -1) {
			cbd->stage = map_load_file;
			cbd->conn = rspamd_http_connection_new (NULL,
					http_map_error,
					http_map_finish,
					flags,
					RSPAMD_HTTP_CLIENT,
					NULL,
					cbd->map->cfg->libs_ctx->ssl_ctx);

			write_http_request (cbd);
			MAP_RELEASE (cbd, "http_callback_data");
		}
		else {
			msg_warn_map ("cannot load map: cannot connect to %s: %s",
					data->host, strerror (errno));
			rspamd_inet_address_free (cbd->addr);
			cbd->addr = NULL;
			MAP_RELEASE (cbd, "http_callback_data");
		}

		return;
	}
	else if (map->r->r) {
		if (rdns_make_request_full (map->r->r, rspamd_map_dns_callback, cbd,
				map->cfg->dns_timeout, map->cfg->dns_retransmits, 1,
				data->host, RDNS_REQUEST_A)) {
			MAP_RETAIN (cbd, "http_callback_data");
		}
		if (rdns_make_request_full (map->r->r, rspamd_map_dns_callback, cbd,
				map->cfg->dns_timeout, map->cfg->dns_retransmits, 1,
				data->host, RDNS_REQUEST_AAAA)) {
			MAP_RETAIN (cbd, "http_callback_data");
		}

		map->dtor = free_http_cbdata_dtor;
		map->dtor_data = cbd;
	}
	else {
		msg_warn_map ("cannot load map: DNS resolver is not initialized");
		cbd->periodic->errored = TRUE;
	}

	MAP_RELEASE (cbd, "http_callback_data");
}

static void
rspamd_map_http_check_callback (gint fd, short what, void *ud)
{
	struct map_periodic_cbdata *cbd = ud;
	struct rspamd_map *map;
	struct rspamd_map_backend *bk;

	map = cbd->map;
	bk = g_ptr_array_index (cbd->map->backends, cbd->cur_backend);

	rspamd_map_common_http_callback (map, bk, cbd, TRUE);
}

static void
rspamd_map_http_read_callback (gint fd, short what, void *ud)
{
	struct map_periodic_cbdata *cbd = ud;
	struct rspamd_map *map;
	struct rspamd_map_backend *bk;

	map = cbd->map;
	bk = g_ptr_array_index (cbd->map->backends, cbd->cur_backend);
	rspamd_map_common_http_callback (map, bk, cbd, FALSE);
}

static void
rspamd_map_file_check_callback (gint fd, short what, void *ud)
{
	struct rspamd_map *map;
	struct map_periodic_cbdata *periodic = ud;
	struct file_map_data *data;
	struct rspamd_map_backend *bk;
	struct stat st;

	map = periodic->map;

	bk = g_ptr_array_index (map->backends, periodic->cur_backend);
	data = bk->data.fd;

	if (stat (data->filename, &st) != -1 &&
			(st.st_mtime > data->st.st_mtime || data->st.st_mtime == -1)) {
		/* File was modified since last check */
		msg_info_map ("old mtime is %t, new mtime is %t for map file %s",
				data->st.st_mtime, st.st_mtime, data->filename);
		memcpy (&data->st, &st, sizeof (struct stat));
		periodic->need_modify = TRUE;
		periodic->cur_backend = 0;

		rspamd_map_periodic_callback (-1, EV_TIMEOUT, periodic);

		return;
	}

	/* Switch to the next backend */
	periodic->cur_backend ++;
	rspamd_map_periodic_callback (-1, EV_TIMEOUT, periodic);
}

static void
rspamd_map_static_check_callback (gint fd, short what, void *ud)
{
	struct rspamd_map *map;
	struct map_periodic_cbdata *periodic = ud;
	struct static_map_data *data;
	struct rspamd_map_backend *bk;

	map = periodic->map;
	bk = g_ptr_array_index (map->backends, periodic->cur_backend);
	data = bk->data.sd;

	if (!data->processed) {
		periodic->need_modify = TRUE;
		periodic->cur_backend = 0;

		rspamd_map_periodic_callback (-1, EV_TIMEOUT, periodic);

		return;
	}

	/* Switch to the next backend */
	periodic->cur_backend ++;
	rspamd_map_periodic_callback (-1, EV_TIMEOUT, periodic);
}

static void
rspamd_map_file_read_callback (gint fd, short what, void *ud)
{
	struct rspamd_map *map;
	struct map_periodic_cbdata *periodic = ud;
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
	rspamd_map_periodic_callback (-1, EV_TIMEOUT, periodic);
}

static void
rspamd_map_static_read_callback (gint fd, short what, void *ud)
{
	struct rspamd_map *map;
	struct map_periodic_cbdata *periodic = ud;
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
	rspamd_map_periodic_callback (-1, EV_TIMEOUT, periodic);
}

static void
rspamd_map_periodic_callback (gint fd, short what, void *ud)
{
	struct rspamd_map_backend *bk;
	struct map_periodic_cbdata *cbd = ud;
	struct rspamd_map *map;

	map = cbd->map;

	if (!cbd->locked) {
		if (!g_atomic_int_compare_and_exchange (cbd->map->locked, 0, 1)) {
			msg_debug_map (
					"don't try to reread map as it is locked by other process, "
					"will reread it later");
			rspamd_map_schedule_periodic (map, TRUE, FALSE, FALSE);
			MAP_RELEASE (cbd, "periodic");

			return;
		}
		else {
			msg_debug_map ("locked map");
			cbd->locked = TRUE;
		}
	}

	if (cbd->errored) {
		/* We should not check other backends if some backend has failed */
		rspamd_map_schedule_periodic (cbd->map, FALSE, FALSE, TRUE);

		if (cbd->locked) {
			g_atomic_int_set (cbd->map->locked, 0);
		}

		msg_debug_map ("unlocked map");
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

	bk = g_ptr_array_index (cbd->map->backends, cbd->cur_backend);
	g_assert (bk != NULL);

	if (cbd->need_modify) {
		/* Load data from the next backend */
		switch (bk->protocol) {
		case MAP_PROTO_HTTP:
		case MAP_PROTO_HTTPS:
			rspamd_map_http_read_callback (fd, what, cbd);
			break;
		case MAP_PROTO_FILE:
			rspamd_map_file_read_callback (fd, what, cbd);
			break;
		case MAP_PROTO_STATIC:
			rspamd_map_static_read_callback (fd, what, cbd);
			break;
		}
	}
	else {
		/* Check the next backend */
		switch (bk->protocol) {
		case MAP_PROTO_HTTP:
		case MAP_PROTO_HTTPS:
			rspamd_map_http_check_callback (fd, what, cbd);
			break;
		case MAP_PROTO_FILE:
			rspamd_map_file_check_callback (fd, what, cbd);
			break;
		case MAP_PROTO_STATIC:
			rspamd_map_static_check_callback (fd, what, cbd);
			break;
		}
	}
}

/* Start watching event for all maps */
void
rspamd_map_watch (struct rspamd_config *cfg, struct event_base *ev_base,
		struct rspamd_dns_resolver *resolver, gboolean active_http)
{
	GList *cur = cfg->maps;
	struct rspamd_map *map;

	/* First of all do synced read of data */
	while (cur) {
		map = cur->data;
		map->ev_base = ev_base;
		map->r = resolver;

		if (active_http) {
			map->active_http = active_http;
		}

		rspamd_map_schedule_periodic (map, FALSE, TRUE, FALSE);

		cur = g_list_next (cur);
	}
}

void
rspamd_map_remove_all (struct rspamd_config *cfg)
{
	struct rspamd_map *map;
	GList *cur;
	struct rspamd_map_backend *bk;
	guint i;

	for (cur = cfg->maps; cur != NULL; cur = g_list_next (cur)) {
		map = cur->data;

		for (i = 0; i < map->backends->len; i ++) {
			bk = g_ptr_array_index (map->backends, i);
			MAP_RELEASE (bk, "rspamd_map_backend");
		}

		if (g_atomic_int_compare_and_exchange (&map->cache->available, 1, 0)) {
			unlink (map->cache->shmem_name);
		}

		if (map->dtor) {
			map->dtor (map->dtor_data);
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

	if (g_ascii_strncasecmp (pos, "sign+", sizeof ("sign+") - 1) == 0) {
		bk->is_signed = TRUE;
		pos += sizeof ("sign+") - 1;
	}

	if (g_ascii_strncasecmp (pos, "key=", sizeof ("key=") - 1) == 0) {
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
		}
		else if (end - pos > 64) {
			/* Try hex encoding */
			bk->trusted_pubkey = rspamd_pubkey_from_hex (pos, 64,
					RSPAMD_KEYPAIR_SIGN, RSPAMD_CRYPTOBOX_MODE_25519);

			if (bk->trusted_pubkey == NULL) {
				msg_err_config ("cannot read pubkey from map: %s",
						map_line);
				return NULL;
			}
			pos += 64;
		}
		else {
			msg_err_config ("cannot read pubkey from map: %s",
					map_line);
			return NULL;
		}

		if (*pos == '+' || *pos == ':') {
			pos ++;
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
			g_free (bk->data.fd->filename);
			g_slice_free1 (sizeof (*bk->data.fd), bk->data.fd);
		}
		break;
	case MAP_PROTO_STATIC:
		if (bk->data.sd) {
			if (bk->data.sd->data) {
				g_free (bk->data.sd->data);
			}
		}
		break;
	case MAP_PROTO_HTTP:
	case MAP_PROTO_HTTPS:
		if (bk->data.hd) {
			g_free (bk->data.hd->host);
			g_free (bk->data.hd->path);
			g_slice_free1 (sizeof (*bk->data.hd), bk->data.hd);
		}
		break;
	}

	if (bk->trusted_pubkey) {
		rspamd_pubkey_unref (bk->trusted_pubkey);
	}

	g_slice_free1 (sizeof (*bk), bk);
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

	bk = g_slice_alloc0 (sizeof (*bk));
	REF_INIT_RETAIN (bk, rspamd_map_backend_dtor);

	if (!rspamd_map_check_proto (cfg, map_line, bk)) {
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
		fdata = g_slice_alloc0 (sizeof (struct file_map_data));
		fdata->st.st_mtime = -1;

		if (access (bk->uri, R_OK) == -1) {
			if (errno != ENOENT) {
				msg_err_config ("cannot open file '%s': %s", bk->uri, strerror (errno));
				return NULL;

			}
			msg_info_config (
					"map '%s' is not found, but it can be loaded automatically later",
					bk->uri);
		}

		fdata->filename = g_strdup (bk->uri);
		bk->data.fd = fdata;
	}
	else if (bk->protocol == MAP_PROTO_HTTP || bk->protocol == MAP_PROTO_HTTPS) {
		hdata = g_slice_alloc0 (sizeof (struct http_map_data));

		memset (&up, 0, sizeof (up));
		if (http_parser_parse_url (bk->uri, strlen (bk->uri), FALSE,
				&up) != 0) {
			msg_err_config ("cannot parse HTTP url: %s", bk->uri);
			goto err;
		}
		else {
			if (!(up.field_set & 1 << UF_HOST)) {
				msg_err_config ("cannot parse HTTP url: %s: no host", bk->uri);
				return NULL;
			}

			tok.begin = bk->uri + up.field_data[UF_HOST].off;
			tok.len = up.field_data[UF_HOST].len;
			hdata->host = rspamd_ftokdup (&tok);

			if (up.field_set & 1 << UF_PORT) {
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

			if (up.field_set & 1 << UF_PATH) {
				tok.begin = bk->uri + up.field_data[UF_PATH].off;
				tok.len = strlen (tok.begin);

				hdata->path = rspamd_ftokdup (&tok);
			}
		}

		bk->data.hd = hdata;
	}else if (bk->protocol == MAP_PROTO_STATIC) {
		sdata = g_slice_alloc0 (sizeof (*sdata));
		bk->data.sd = sdata;
	}

	bk->id = rspamd_cryptobox_fast_hash_specific (RSPAMD_CRYPTOBOX_T1HA,
			bk->uri, strlen (bk->uri), 0xdeadbabe);

	return bk;

err:
	MAP_RELEASE (bk, "rspamd_map_backend");

	if (hdata) {
		g_slice_free1 (sizeof (*hdata), hdata);
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
	cksum_encoded = rspamd_encode_base32 (cksum, sizeof (cksum));
	rspamd_strlcpy (map->tag, cksum_encoded, sizeof (map->tag));
	g_free (cksum_encoded);
}

struct rspamd_map *
rspamd_map_add (struct rspamd_config *cfg,
	const gchar *map_line,
	const gchar *description,
	map_cb_t read_callback,
	map_fin_cb_t fin_callback,
	void **user_data)
{
	struct rspamd_map *map;
	struct rspamd_map_backend *bk;

	bk = rspamd_map_parse_backend (cfg, map_line);
	if (bk == NULL) {
		return NULL;
	}

	map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (struct rspamd_map));
	map->read_callback = read_callback;
	map->fin_callback = fin_callback;
	map->user_data = user_data;
	map->cfg = cfg;
	map->id = rspamd_random_uint64_fast ();
	map->locked =
		rspamd_mempool_alloc0_shared (cfg->cfg_pool, sizeof (gint));
	map->cache =
			rspamd_mempool_alloc0_shared (cfg->cfg_pool, sizeof (*map->cache));
	map->backends = g_ptr_array_sized_new (1);
	rspamd_mempool_add_destructor (cfg->cfg_pool, rspamd_ptr_array_free_hard,
			map->backends);
	g_ptr_array_add (map->backends, bk);
	map->name = rspamd_mempool_strdup (cfg->cfg_pool, map_line);

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

struct rspamd_map*
rspamd_map_add_from_ucl (struct rspamd_config *cfg,
	const ucl_object_t *obj,
	const gchar *description,
	map_cb_t read_callback,
	map_fin_cb_t fin_callback,
	void **user_data)
{
	ucl_object_iter_t it = NULL;
	const ucl_object_t *cur, *elt;
	struct rspamd_map *map;
	struct rspamd_map_backend *bk;
	gsize sz;
	const gchar *dline;
	guint i;

	g_assert (obj != NULL);

	if (ucl_object_type (obj) == UCL_STRING) {
		/* Just a plain string */
		return rspamd_map_add (cfg, ucl_object_tostring (obj), description,
				read_callback, fin_callback, user_data);
	}

	map = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (struct rspamd_map));
	map->read_callback = read_callback;
	map->fin_callback = fin_callback;
	map->user_data = user_data;
	map->cfg = cfg;
	map->id = rspamd_random_uint64_fast ();
	map->locked =
			rspamd_mempool_alloc0_shared (cfg->cfg_pool, sizeof (gint));
	map->cache =
				rspamd_mempool_alloc0_shared (cfg->cfg_pool, sizeof (*map->cache));
	map->backends = g_ptr_array_new ();
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
					if (bk->protocol == MAP_PROTO_FILE) {
						map->poll_timeout = (map->poll_timeout * cfg->map_file_watch_multiplier);
					}
					g_ptr_array_add (map->backends, bk);

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
						if (bk->protocol == MAP_PROTO_FILE) {
							map->poll_timeout = (map->poll_timeout * cfg->map_file_watch_multiplier);
						}
						g_ptr_array_add (map->backends, bk);

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
				if (bk->protocol == MAP_PROTO_FILE) {
					map->poll_timeout = (map->poll_timeout * cfg->map_file_watch_multiplier);
				}
				g_ptr_array_add (map->backends, bk);

				if (!map->name) {
					map->name = rspamd_mempool_strdup (cfg->cfg_pool,
							ucl_object_tostring (elt));
				}
			}
		}

		if (map->backends->len == 0) {
			msg_err_config ("map has no urls to be loaded: no valid backends");
			goto err;
		}

		PTR_ARRAY_FOREACH (map->backends, i, bk) {
			if (bk->protocol == MAP_PROTO_STATIC) {
				/* We need data field in ucl */
				elt = ucl_object_lookup (obj, "data");

				if (elt == NULL || ucl_object_type (elt) != UCL_STRING) {
					msg_err_config ("map has static backend but no `data` field");
					goto err;
				}

				/* Otherwise, we copy data to the backend */
				dline = ucl_object_tolstring (elt, &sz);

				if (sz == 0) {
					msg_err_config ("map has static backend but empty `data` field");
					goto err;
				}

				bk->data.sd->data = g_malloc (sz);
				bk->data.sd->len = sz;
				memcpy (bk->data.sd->data, dline, sz);
			}
		}
	}
	else {
		msg_err_config ("map has invalid type for value: %s",
				ucl_object_type_to_string (ucl_object_type (obj)));
		goto err;
	}

	rspamd_map_calculate_hash (map);
	msg_info_map ("added map from ucl");

	cfg->maps = g_list_prepend (cfg->maps, map);

	return map;

err:

	return NULL;
}

/**
 * FSM for parsing lists
 */

#define MAP_STORE_KEY do { \
	while (g_ascii_isspace (*c) && p > c) { c ++; } \
	key = g_malloc (p - c + 1); \
	rspamd_strlcpy (key, c, p - c + 1); \
	key = g_strchomp (key); \
} while (0)

#define MAP_STORE_VALUE do { \
	while (g_ascii_isspace (*c) && p > c) { c ++; } \
	value = g_malloc (p - c + 1); \
	rspamd_strlcpy (value, c, p - c + 1); \
	value = g_strchomp (value); \
} while (0)

gchar *
rspamd_parse_kv_list (
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
		map_backslash_quoted,
		map_backslash_slashed,
		map_read_key_after_slash,
		map_read_value,
		map_read_comment_start,
		map_skip_comment,
		map_read_eol,
	};

	gchar *c, *p, *key = NULL, *value = NULL, *end;
	struct rspamd_map *map = data->map;

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
				if (*p == '"') {
					p++;
					c = p;
					data->state = map_read_key_quoted;
				}
				else if (*p == '/') {
					/* Note that c is on '/' here as '/' is a part of key */
					c = p;
					p++;
					data->state = map_read_key_slashed;
				}
				else {
					c = p;
					data->state = map_read_key;
				}
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
					msg_debug_map ("insert key only pair: %s -> %s",
							key, default_value);
					g_free (key);
				}

				key = NULL;
				data->state = map_read_comment_start;
			}
			else if (*p == '\r' || *p == '\n') {
				if (p - c > 0) {
					/* Store a single key */
					MAP_STORE_KEY;
					func (data->cur_data, key, default_value);
					msg_debug_map ("insert key only pair: %s -> %s",
							key, default_value);
					g_free (key);
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
		case map_read_key_quoted:
			if (*p == '\\') {
				data->state = map_backslash_quoted;
				p ++;
			}
			else if (*p == '"') {
				/* Allow empty keys in this case */
				if (p - c >= 0) {
					MAP_STORE_KEY;
					data->state = map_skip_spaces_after_key;
				}
				else {
					g_assert_not_reached ();
				}
				p ++;
			}
			else {
				p ++;
			}
			break;
		case map_read_key_slashed:
			if (*p == '\\') {
				data->state = map_backslash_slashed;
				p ++;
			}
			else if (*p == '/') {
				/* Allow empty keys in this case */
				if (p - c >= 0) {
					data->state = map_read_key_after_slash;
				}
				else {
					g_assert_not_reached ();
				}
			}
			else {
				p ++;
			}
			break;
		case map_read_key_after_slash:
			/*
			 * This state is equal to reading of key but '/' is not
			 * treated specially
			 */
			if (*p == '#') {
				if (p - c > 0) {
					/* Store a single key */
					MAP_STORE_KEY;
					func (data->cur_data, key, default_value);
					msg_debug_map ("insert key only pair: %s -> %s",
							key, default_value);
					g_free (key);
					key = NULL;
				}

				data->state = map_read_comment_start;
			}
			else if (*p == '\r' || *p == '\n') {
				if (p - c > 0) {
					/* Store a single key */
					MAP_STORE_KEY;
					func (data->cur_data, key, default_value);

					msg_debug_map ("insert key only pair: %s -> %s",
							key, default_value);
					g_free (key);
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
				p ++;
			}
			break;
		case map_backslash_quoted:
			p ++;
			data->state = map_read_key_quoted;
			break;
		case map_backslash_slashed:
			p ++;
			data->state = map_read_key_slashed;
			break;
		case map_skip_spaces_after_key:
			if (*p == ' ' || *p == '\t') {
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
					msg_debug_map ("insert key value pair: %s -> %s",
							key, value);
					g_free (key);
					g_free (value);
					key = NULL;
					value = NULL;
				}
				else {
					func (data->cur_data, key, default_value);
					msg_debug_map ("insert key only pair: %s -> %s",
							key, default_value);
					g_free (key);
					key = NULL;
				}

				data->state = map_read_comment_start;
			}
			else if (*p == '\r' || *p == '\n') {
				if (p - c > 0) {
					/* Store a single key */
					MAP_STORE_VALUE;
					func (data->cur_data, key, value);
					msg_debug_map ("insert key value pair: %s -> %s",
							key, value);
					g_free (key);
					g_free (value);
					key = NULL;
					value = NULL;
				}
				else {
					func (data->cur_data, key, default_value);
					msg_debug_map ("insert key only pair: %s -> %s",
							key, default_value);
					g_free (key);
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
				msg_debug_map ("insert key only pair: %s -> %s",
						key, default_value);
				g_free (key);
				key = NULL;
			}
			break;
		case map_read_value:
			g_assert (key != NULL);
			if (p - c > 0) {
				/* Store a single key */
				MAP_STORE_VALUE;
				func (data->cur_data, key, value);
				msg_debug_map ("insert key value pair: %s -> %s",
						key, value);
				g_free (key);
				g_free (value);
				key = NULL;
				value = NULL;
			}
			else {
				func (data->cur_data, key, default_value);
				msg_debug_map ("insert key only pair: %s -> %s",
						key, default_value);
				g_free (key);
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
radix_tree_insert_helper (gpointer st, gconstpointer key, gconstpointer value)
{
	radix_compressed_t *tree = (radix_compressed_t *)st;
	rspamd_mempool_t *pool;
	gpointer nvalue;

	pool = radix_get_pool (tree);
	nvalue = rspamd_mempool_strdup (pool, value);
	rspamd_radix_add_iplist (key, ",", tree, nvalue, FALSE);
}

static void
hash_insert_helper (gpointer st, gconstpointer key, gconstpointer value)
{
	GHashTable *ht = st;
	gpointer k, v;

	k = g_strdup (key);
	v = g_strdup (value);
	g_hash_table_replace (ht, k, v);
}

/* Helpers */
gchar *
rspamd_hosts_read (
	gchar * chunk,
	gint len,
	struct map_cb_data *data,
	gboolean final)
{
	if (data->cur_data == NULL) {
		data->cur_data = g_hash_table_new_full (rspamd_strcase_hash,
				rspamd_strcase_equal, g_free, g_free);
	}
	return rspamd_parse_kv_list (
			   chunk,
			   len,
			   data,
			   hash_insert_helper,
			   hash_fill,
			   final);
}

void
rspamd_hosts_fin (struct map_cb_data *data)
{
	struct rspamd_map *map = data->map;

	if (data->prev_data) {
		g_hash_table_unref (data->prev_data);
	}
	if (data->cur_data) {
		msg_info_map ("read hash of %d elements", g_hash_table_size
				(data->cur_data));
	}
}

gchar *
rspamd_kv_list_read (
	gchar * chunk,
	gint len,
	struct map_cb_data *data,
	gboolean final)
{
	if (data->cur_data == NULL) {
		data->cur_data = g_hash_table_new_full (rspamd_strcase_hash,
				rspamd_strcase_equal, g_free, g_free);
	}
	return rspamd_parse_kv_list (
			   chunk,
			   len,
			   data,
			   hash_insert_helper,
			   "",
			   final);
}

void
rspamd_kv_list_fin (struct map_cb_data *data)
{
	struct rspamd_map *map = data->map;

	if (data->prev_data) {
		g_hash_table_unref (data->prev_data);
	}
	if (data->cur_data) {
		msg_info_map ("read hash of %d elements", g_hash_table_size
				(data->cur_data));
	}
}

gchar *
rspamd_radix_read (
	gchar * chunk,
	gint len,
	struct map_cb_data *data,
	gboolean final)
{
	radix_compressed_t *tree;
	rspamd_mempool_t *rpool;
	struct rspamd_map *map = data->map;

	if (data->cur_data == NULL) {
		tree = radix_create_compressed ();
		rpool = radix_get_pool (tree);
		memcpy (rpool->tag.uid, map->tag, sizeof (rpool->tag.uid));
		data->cur_data = tree;
	}
	return rspamd_parse_kv_list (
			   chunk,
			   len,
			   data,
			   radix_tree_insert_helper,
			   hash_fill,
			   final);
}

void
rspamd_radix_fin (struct map_cb_data *data)
{
	struct rspamd_map *map = data->map;

	if (data->prev_data) {
		radix_destroy_compressed (data->prev_data);
	}
	if (data->cur_data) {
		msg_info_map ("read radix trie of %z elements: %s",
				radix_get_size (data->cur_data), radix_get_info (data->cur_data));
	}
}

enum rspamd_regexp_map_flags {
	RSPAMD_REGEXP_FLAG_UTF = (1 << 0),
	RSPAMD_REGEXP_FLAG_MULTIPLE = (1 << 1)
};

struct rspamd_regexp_map {
	struct rspamd_map *map;
	GPtrArray *regexps;
	GPtrArray *values;
	enum rspamd_regexp_map_flags map_flags;
#ifdef WITH_HYPERSCAN
	hs_database_t *hs_db;
	hs_scratch_t *hs_scratch;
	const gchar **patterns;
	gint *flags;
	gint *ids;
#endif
};

static struct rspamd_regexp_map *
rspamd_regexp_map_create (struct rspamd_map *map,
		enum rspamd_regexp_map_flags flags)
{
	struct rspamd_regexp_map *re_map;

	re_map = g_slice_alloc0 (sizeof (*re_map));
	re_map->values = g_ptr_array_new ();
	re_map->regexps = g_ptr_array_new ();
	re_map->map = map;
	re_map->map_flags = flags;

	return re_map;
}


static void
rspamd_regexp_map_destroy (struct rspamd_regexp_map *re_map)
{
	rspamd_regexp_t *re;
	guint i;

	for (i = 0; i < re_map->regexps->len; i ++) {
		re = g_ptr_array_index (re_map->regexps, i);
		rspamd_regexp_unref (re);
	}

	for (i = 0; i < re_map->values->len; i ++) {
		g_free (g_ptr_array_index (re_map->values, i));
	}

	g_ptr_array_free (re_map->regexps, TRUE);
	g_ptr_array_free (re_map->values, TRUE);

#ifdef WITH_HYPERSCAN
	if (re_map->hs_scratch) {
		hs_free_scratch (re_map->hs_scratch);
	}
	if (re_map->hs_db) {
		hs_free_database (re_map->hs_db);
	}
	if (re_map->patterns) {
		g_free (re_map->patterns);
	}
	if (re_map->flags) {
		g_free (re_map->flags);
	}
	if (re_map->ids) {
		g_free (re_map->ids);
	}
#endif

	g_slice_free1 (sizeof (*re_map), re_map);
}

static void
rspamd_re_map_insert_helper (gpointer st, gconstpointer key, gconstpointer value)
{
	struct rspamd_regexp_map *re_map = st;
	struct rspamd_map *map;
	rspamd_regexp_t *re;
	GError *err = NULL;
	gint pcre_flags;

	map = re_map->map;
	re = rspamd_regexp_new (key, NULL, &err);

	if (re == NULL) {
		msg_err_map ("cannot parse regexp %s: %e", key, err);

		if (err) {
			g_error_free (err);
		}

		return;
	}

	pcre_flags = rspamd_regexp_get_pcre_flags (re);

#ifndef WITH_PCRE2
	if (pcre_flags & PCRE_FLAG(UTF8)) {
		re_map->map_flags |= RSPAMD_REGEXP_FLAG_UTF;
	}
#else
	if (pcre_flags & PCRE_FLAG(UTF)) {
		re_map->map_flags |= RSPAMD_REGEXP_FLAG_UTF;
	}
#endif

	g_ptr_array_add (re_map->regexps, re);
	g_ptr_array_add (re_map->values, g_strdup (value));
}

static void
rspamd_re_map_finalize (struct rspamd_regexp_map *re_map)
{
#ifdef WITH_HYPERSCAN
	guint i;
	hs_platform_info_t plt;
	hs_compile_error_t *err;
	struct rspamd_map *map;
	rspamd_regexp_t *re;
	gint pcre_flags;

	map = re_map->map;

	if (!(map->cfg->libs_ctx->crypto_ctx->cpu_config & CPUID_SSSE3)) {
		msg_info_map ("disable hyperscan for map %s, ssse3 instructons are not supported by CPU",
				map->name);
		return;
	}

	if (hs_populate_platform (&plt) != HS_SUCCESS) {
		msg_err_map ("cannot populate hyperscan platform");
		return;
	}

	re_map->patterns = g_new (const gchar *, re_map->regexps->len);
	re_map->flags = g_new (gint, re_map->regexps->len);
	re_map->ids = g_new (gint, re_map->regexps->len);

	for (i = 0; i < re_map->regexps->len; i ++) {
		re = g_ptr_array_index (re_map->regexps, i);
		re_map->patterns[i] = rspamd_regexp_get_pattern (re);
		re_map->flags[i] = HS_FLAG_SINGLEMATCH;
		pcre_flags = rspamd_regexp_get_pcre_flags (re);

#ifndef WITH_PCRE2
		if (pcre_flags & PCRE_FLAG(UTF8)) {
			re_map->flags[i] |= HS_FLAG_UTF8;
		}
#else
		if (pcre_flags & PCRE_FLAG(UTF)) {
			re_map->flags[i] |= HS_FLAG_UTF8;
		}
#endif
		if (pcre_flags & PCRE_FLAG(CASELESS)) {
			re_map->flags[i] |= HS_FLAG_CASELESS;
		}
		if (pcre_flags & PCRE_FLAG(MULTILINE)) {
			re_map->flags[i] |= HS_FLAG_MULTILINE;
		}
		if (pcre_flags & PCRE_FLAG(DOTALL)) {
			re_map->flags[i] |= HS_FLAG_DOTALL;
		}
		if (rspamd_regexp_get_maxhits (re) == 1) {
			re_map->flags[i] |= HS_FLAG_SINGLEMATCH;
		}

		re_map->ids[i] = i;
	}

	if (re_map->regexps->len > 0 && re_map->patterns) {
		if (hs_compile_multi (re_map->patterns,
				re_map->flags,
				re_map->ids,
				re_map->regexps->len,
				HS_MODE_BLOCK,
				&plt,
				&re_map->hs_db,
				&err) != HS_SUCCESS) {

			msg_err_map ("cannot create tree of regexp when processing '%s': %s",
					err->expression >= 0 ?
							re_map->patterns[err->expression] :
							"unknown regexp", err->message);
			re_map->hs_db = NULL;
			hs_free_compile_error (err);

			return;
		}

		if (hs_alloc_scratch (re_map->hs_db, &re_map->hs_scratch) != HS_SUCCESS) {
			msg_err_map ("cannot allocate scratch space for hyperscan");
			hs_free_database (re_map->hs_db);
			re_map->hs_db = NULL;
		}
	}
	else {
		msg_err_map ("regexp map is empty");
	}
#endif
}

gchar *
rspamd_regexp_list_read_single (
		gchar *chunk,
		gint len,
		struct map_cb_data *data,
		gboolean final)
{
	struct rspamd_regexp_map *re_map;

	if (data->cur_data == NULL) {
		re_map = rspamd_regexp_map_create (data->map, 0);
		data->cur_data = re_map;
	}

	return rspamd_parse_kv_list (
			chunk,
			len,
			data,
			rspamd_re_map_insert_helper,
			hash_fill,
			final);
}

gchar *
rspamd_regexp_list_read_multiple (
		gchar *chunk,
		gint len,
		struct map_cb_data *data,
		gboolean final)
{
	struct rspamd_regexp_map *re_map;

	if (data->cur_data == NULL) {
		re_map = rspamd_regexp_map_create (data->map, RSPAMD_REGEXP_FLAG_MULTIPLE);
		data->cur_data = re_map;
	}

	return rspamd_parse_kv_list (
			chunk,
			len,
			data,
			rspamd_re_map_insert_helper,
			hash_fill,
			final);
}

void
rspamd_regexp_list_fin (struct map_cb_data *data)
{
	struct rspamd_regexp_map *re_map;
	struct rspamd_map *map = data->map;

	if (data->prev_data) {
		rspamd_regexp_map_destroy (data->prev_data);
	}
	if (data->cur_data) {
		re_map = data->cur_data;
		rspamd_re_map_finalize (re_map);
		msg_info_map ("read regexp list of %ud elements",
				re_map->regexps->len);
	}
}

#ifdef WITH_HYPERSCAN
static int
rspamd_match_hs_single_handler (unsigned int id, unsigned long long from,
		unsigned long long to,
		unsigned int flags, void *context)
{
	guint *i = context;
	/* Always return non-zero as we need a single match here */

	*i = id;

	return 1;
}
#endif

gpointer
rspamd_match_regexp_map_single (struct rspamd_regexp_map *map,
		const gchar *in, gsize len)
{
	guint i;
	rspamd_regexp_t *re;
	gint res = 0;
	gpointer ret = NULL;
	gboolean validated = FALSE;

	g_assert (in != NULL);

	if (map == NULL || len == 0) {
		return NULL;
	}

	if (map->map_flags & RSPAMD_REGEXP_FLAG_UTF) {
		if (g_utf8_validate (in, len, NULL)) {
			validated = TRUE;
		}
	}
	else {
		validated = TRUE;
	}

#ifdef WITH_HYPERSCAN
	if (map->hs_db && map->hs_scratch) {

		if (validated) {

			res = hs_scan (map->hs_db, in, len, 0, map->hs_scratch,
					rspamd_match_hs_single_handler, (void *)&i);

			if (res == HS_SCAN_TERMINATED) {
				res = 1;
				ret = g_ptr_array_index (map->values, i);
			}

			return ret;
		}
	}
#endif

	if (!res) {
		/* PCRE version */
		for (i = 0; i < map->regexps->len; i ++) {
			re = g_ptr_array_index (map->regexps, i);

			if (rspamd_regexp_search (re, in, len, NULL, NULL, !validated, NULL)) {
				ret = g_ptr_array_index (map->values, i);
				break;
			}
		}
	}

	return ret;
}

#ifdef WITH_HYPERSCAN
struct rspamd_multiple_cbdata {
	GPtrArray *ar;
	struct rspamd_regexp_map *map;
};

static int
rspamd_match_hs_multiple_handler (unsigned int id, unsigned long long from,
		unsigned long long to,
		unsigned int flags, void *context)
{
	struct rspamd_multiple_cbdata *cbd = context;

	if (id < cbd->map->values->len) {
		g_ptr_array_add (cbd->ar, g_ptr_array_index (cbd->map->values, id));
	}

	/* Always return zero as we need all matches here */
	return 0;
}
#endif

gpointer
rspamd_match_regexp_map_all (struct rspamd_regexp_map *map,
		const gchar *in, gsize len)
{
	guint i;
	rspamd_regexp_t *re;
	GPtrArray *ret;
	gint res = 0;
	gboolean validated = FALSE;

	g_assert (in != NULL);

	if (map == NULL || len == 0) {
		return NULL;
	}

	if (map->map_flags & RSPAMD_REGEXP_FLAG_UTF) {
		if (g_utf8_validate (in, len, NULL)) {
			validated = TRUE;
		}
	}
	else {
		validated = TRUE;
	}

	ret = g_ptr_array_new ();

#ifdef WITH_HYPERSCAN
	if (map->hs_db && map->hs_scratch) {

		if (validated) {
			struct rspamd_multiple_cbdata cbd;

			cbd.ar = ret;
			cbd.map = map;

			if (hs_scan (map->hs_db, in, len, 0, map->hs_scratch,
					rspamd_match_hs_multiple_handler, &cbd) == HS_SUCCESS) {
				res = 1;
			}
		}
	}
#endif

	if (!res) {
		/* PCRE version */
		for (i = 0; i < map->regexps->len; i ++) {
			re = g_ptr_array_index (map->regexps, i);

			if (rspamd_regexp_search (re, in, len, NULL, NULL,
					!validated, NULL)) {
				g_ptr_array_add (ret, g_ptr_array_index (map->values, i));
			}
		}
	}

	if (ret->len > 0) {
		return ret;
	}

	g_ptr_array_free (ret, TRUE);

	return NULL;
}
