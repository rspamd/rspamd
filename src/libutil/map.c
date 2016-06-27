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
#include "cryptobox.h"
#include "unix-std.h"
#include "http_parser.h"
#include "libutil/regexp.h"

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
#define MAP_RETAIN(x) do { \
	msg_err ("retain ref %p, refcount: %d -> %d", (x), (x)->ref.refcount, (x)->ref.refcount + 1); \
	REF_RETAIN(x);	\
} while (0)

#define MAP_RELEASE(x) do { \
	msg_err ("release ref %p, refcount: %d -> %d", (x), (x)->ref.refcount, (x)->ref.refcount - 1); \
	REF_RELEASE(x);	\
} while (0)
#else
#define MAP_RETAIN REF_RETAIN
#define MAP_RELEASE REF_RELEASE
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
			msg->url = rspamd_fstring_new_init (cbd->data->path, strlen (cbd->data->path));

			if (cbd->check &&
					cbd->data->last_checked != 0 && cbd->stage == map_load_file) {
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
		MAP_RETAIN (cbd);
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
		data = rspamd_file_xmap (fpath, PROT_READ, &len);

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
		rspamd_inet_address_destroy (cbd->addr);
	}

	MAP_RELEASE (cbd->bk);
	MAP_RELEASE (periodic);
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
	msg_warn_map ("connection with http server is terminated: worker is stopping");
	free_http_cbdata_common (cbd, FALSE);
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
	msg_err_map ("connection with http server terminated incorrectly: %e", err);
	rspamd_map_periodic_callback (-1, EV_TIMEOUT, cbd->periodic);
	MAP_RELEASE (cbd);
}

static void
rspamd_map_cache_cb (gint fd, short what, gpointer ud)
{
	struct rspamd_http_map_cached_cbdata *cache_cbd = ud;

	g_atomic_int_set (&cache_cbd->map->cache->available, 0);
	REF_RELEASE (cache_cbd->shm);
	event_del (&cache_cbd->timeout);
	g_slice_free1 (sizeof (*cache_cbd), cache_cbd);
}

static int
http_map_finish (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg)
{
	struct http_callback_data *cbd = conn->ud;
	struct rspamd_map *map;
	struct rspamd_map_backend *bk;
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
			MAP_RELEASE (cbd);

			return 0;
		}

		if (cbd->stage == map_load_file) {
			if (msg->last_modified) {
				cbd->data->last_checked = msg->last_modified;
			}
			else {
				cbd->data->last_checked = msg->date;
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
				MAP_RELEASE (cbd);

				return 0;
			}
			else {
				/* Unsinged version - just open file */
				cbd->shmem_data = rspamd_http_message_shmem_ref (msg);
				in = rspamd_shmem_xmap (cbd->shmem_data->shm_name, PROT_READ, &inlen);
				cbd->data_len = msg->body_buf.len;

				if (in == NULL) {
					msg_err_map ("cannot read tempfile %s: %s",
							cbd->shmem_data->shm_name,
							strerror (errno));
					goto err;
				}
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
			MAP_RELEASE (cbd);

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

		g_assert (cbd->shmem_data != NULL);

		in = rspamd_shmem_xmap (cbd->shmem_data->shm_name, PROT_READ, &dlen);

		if (in == NULL) {
			msg_err_map ("cannot read tempfile %s: %s",
					cbd->shmem_data->shm_name,
					strerror (errno));
			goto err;
		}

		map->read_callback (in, cbd->data_len, &cbd->periodic->cbdata, TRUE);
		msg_info_map ("read map data from %s", cbd->data->host);

		/*
		 * We know that a map is in the locked state
		 */
		if (g_atomic_int_compare_and_exchange (&map->cache->available, 0, 1)) {
			/* Store cached data */
			struct rspamd_http_map_cached_cbdata *cache_cbd;
			struct timeval tv;

			rspamd_strlcpy (map->cache->shmem_name, cbd->shmem_data->shm_name,
					sizeof (map->cache->shmem_name));
			map->cache->len = cbd->data_len;
			map->cache->last_checked = cbd->data->last_checked;
			cache_cbd = g_slice_alloc0 (sizeof (*cache_cbd));
			cache_cbd->shm = cbd->shmem_data;
			cache_cbd->map = map;
			REF_RETAIN (cache_cbd->shm);
			event_set (&cache_cbd->timeout, -1, EV_TIMEOUT, rspamd_map_cache_cb,
					cache_cbd);
			event_base_set (cbd->ev_base, &cache_cbd->timeout);
			double_to_tv (map->poll_timeout, &tv);
			event_add (&cache_cbd->timeout, &tv);
		}

		cbd->periodic->cur_backend ++;
		munmap (in, dlen);
		rspamd_map_periodic_callback (-1, EV_TIMEOUT, cbd->periodic);
	}
	else if (msg->code == 304 && (cbd->check && cbd->stage == map_load_file)) {
		msg_debug_map ("data is not modified for server %s",
				cbd->data->host);

		if (msg->last_modified) {
			cbd->data->last_checked = msg->last_modified;
		}
		else {
			cbd->data->last_checked = msg->date;
		}

		cbd->periodic->cur_backend ++;
		rspamd_map_periodic_callback (-1, EV_TIMEOUT, cbd->periodic);
	}
	else {
		msg_info_map ("cannot load map %s from %s: HTTP error %d",
				bk->uri, cbd->data->host, msg->code);
	}

	MAP_RELEASE (cbd);
	return 0;

err:
	cbd->periodic->errored = 1;
	rspamd_map_periodic_callback (-1, EV_TIMEOUT, cbd->periodic);
	MAP_RELEASE (cbd);

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
		msg_err_map ("bad callback for reading map file");
		return FALSE;
	}

	if (access (data->filename, R_OK) == -1) {
		/* File does not exist, skipping */
		msg_err_map ("map file is unavailable for reading");
		return TRUE;
	}

	bytes = rspamd_file_xmap (data->filename, PROT_READ, &len);

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
		map->read_callback (bytes, len, &periodic->cbdata, TRUE);
	}

	munmap (bytes, len);

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
		periodic->map->fin_callback (&periodic->cbdata);
		*periodic->map->user_data = periodic->cbdata.cur_data;
	}
	else {
		/* Not modified */
	}

	rspamd_map_schedule_periodic (periodic->map, FALSE, FALSE, FALSE);
	g_atomic_int_set (periodic->map->locked, 0);
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

	timeout = map->poll_timeout;

	if (initial) {
		timeout = 0.0;
	}

	if (errored) {
		timeout = map->poll_timeout * error_mult;
	}
	else if (locked) {
		timeout = map->poll_timeout * lock_mult;
	}

	cbd = g_slice_alloc0 (sizeof (*cbd));
	cbd->cbdata.state = 0;
	cbd->cbdata.prev_data = *map->user_data;
	cbd->cbdata.cur_data = NULL;
	cbd->cbdata.map = map;
	cbd->map = map;
	REF_INIT_RETAIN (cbd, rspamd_map_periodic_dtor);

	msg_debug_map ("schedule new periodic event %p in %.2f seconds", cbd, timeout);

	if (initial) {
		evtimer_set (&map->ev, rspamd_map_periodic_callback, cbd);
		event_base_set (map->ev_base, &map->ev);
	}
	else {
		evtimer_del (&map->ev);
		evtimer_set (&map->ev, rspamd_map_periodic_callback, cbd);
	}

	jittered_sec = rspamd_time_jitter (timeout, 0);
	double_to_tv (jittered_sec, &map->tv);

	evtimer_add (&map->ev, &map->tv);
}

static void
rspamd_map_dns_callback (struct rdns_reply *reply, void *arg)
{
	struct http_callback_data *cbd = arg;
	struct rspamd_map *map;
	guint flags = RSPAMD_HTTP_CLIENT_SIMPLE|RSPAMD_HTTP_CLIENT_SHARED;

	map = cbd->map;

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
			msg_err_map ("cannot resolve %s", cbd->data->host);
		}
	}

	MAP_RELEASE (cbd);
}

static gboolean
rspamd_map_read_cached (struct rspamd_map *map,
		struct map_periodic_cbdata *periodic, const gchar *host)
{
	gsize len;
	gpointer in;

	in = rspamd_shmem_xmap (map->cache->shmem_name, PROT_READ, &len);

	if (in == NULL) {
		return FALSE;
	}

	if (len < map->cache->len) {
		munmap (in, len);
		return FALSE;
	}

	map->read_callback (in, map->cache->len, &periodic->cbdata, TRUE);
	msg_info_map ("read map data from %s (cached)", host);
	munmap (in, len);

	return TRUE;
}

/**
 * Async HTTP callback
 */
static void
rspamd_map_common_http_callback (struct rspamd_map *map, struct rspamd_map_backend *bk,
		struct map_periodic_cbdata *periodic, gboolean check)
{
	struct http_map_data *data;
	struct http_callback_data *cbd;


	data = bk->data.hd;

	if (g_atomic_int_get (&map->cache->available) == 1) {
		/* Read cached data */
		if (check) {
			if (data->last_checked < map->cache->last_checked) {
				periodic->need_modify = TRUE;
				/* Reset the whole chain */
				periodic->cur_backend = 0;
				rspamd_map_periodic_callback (-1, EV_TIMEOUT, periodic);
			}

			return;
		}
		else if (rspamd_map_read_cached (map, periodic, data->host)) {
			/* Switch to the next backend */
			periodic->cur_backend ++;
			rspamd_map_periodic_callback (-1, EV_TIMEOUT, periodic);
			data->last_checked = map->cache->last_checked;

			return;
		}
	}

	cbd = g_slice_alloc0 (sizeof (struct http_callback_data));

	cbd->ev_base = map->ev_base;
	cbd->map = map;
	cbd->data = data;
	cbd->fd = -1;
	cbd->check = check;
	cbd->periodic = periodic;
	MAP_RETAIN (periodic);
	cbd->bk = bk;
	MAP_RETAIN (bk);
	cbd->stage = map_resolve_host2;
	double_to_tv (map->cfg->map_timeout, &cbd->tv);
	REF_INIT_RETAIN (cbd, free_http_cbdata);

	msg_debug_map ("%s map data from %s", check ? "checking" : "reading",
			data->host);
	/* Send both A and AAAA requests */
	if (map->r->r) {
		if (rdns_make_request_full (map->r->r, rspamd_map_dns_callback, cbd,
				map->cfg->dns_timeout, map->cfg->dns_retransmits, 1,
				data->host, RDNS_REQUEST_A)) {
			MAP_RETAIN (cbd);
		}
		if (rdns_make_request_full (map->r->r, rspamd_map_dns_callback, cbd,
				map->cfg->dns_timeout, map->cfg->dns_retransmits, 1,
				data->host, RDNS_REQUEST_AAAA)) {
			MAP_RETAIN (cbd);
		}

		map->dtor = free_http_cbdata_dtor;
		map->dtor_data = cbd;
	}
	else {
		msg_warn_map ("cannot load map: DNS resolver is not initialized");
		cbd->periodic->errored = TRUE;
	}

	/* We don't need own ref as it is now ref counted by DNS handlers */
	MAP_RELEASE (cbd);
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
rspamd_map_periodic_callback (gint fd, short what, void *ud)
{
	struct rspamd_map_backend *bk;
	struct map_periodic_cbdata *cbd = ud;

	if (cbd->errored) {
		/* We should not check other backends if some backend has failed */
		rspamd_map_schedule_periodic (cbd->map, FALSE, FALSE, TRUE);
		g_atomic_int_set (cbd->map->locked, 0);
		MAP_RELEASE (cbd);

		return;
	}

	/* For each backend we need to check for modifications */
	if (cbd->cur_backend >= cbd->map->backends->len) {
		/* Last backend */
		MAP_RELEASE (cbd);

		return;
	}

	bk = g_ptr_array_index (cbd->map->backends, cbd->cur_backend);
	g_assert (bk != NULL);

	if (cbd->need_modify) {
		/* Load data from the next backend */
		if (bk->protocol == MAP_PROTO_HTTP || bk->protocol == MAP_PROTO_HTTPS) {
			rspamd_map_http_read_callback (fd, what, cbd);
		}
		else {
			rspamd_map_file_read_callback (fd, what, cbd);
		}
	}
	else {
		/* Check the next backend */
		if (bk->protocol == MAP_PROTO_HTTP || bk->protocol == MAP_PROTO_HTTPS) {
			rspamd_map_http_check_callback (fd, what, cbd);
		}
		else {
			rspamd_map_file_check_callback (fd, what, cbd);
		}
	}
}

/* Start watching event for all maps */
void
rspamd_map_watch (struct rspamd_config *cfg,
		struct event_base *ev_base,
		struct rspamd_dns_resolver *resolver)
{
	GList *cur = cfg->maps;
	struct rspamd_map *map;

	/* First of all do synced read of data */
	while (cur) {
		map = cur->data;
		map->ev_base = ev_base;
		map->r = resolver;

		if (!g_atomic_int_compare_and_exchange (map->locked, 0, 1)) {
			msg_debug_map (
					"don't try to reread map as it is locked by other process, "
					"will reread it later");
			rspamd_map_schedule_periodic (map, TRUE, TRUE, FALSE);
		}
		else {
			rspamd_map_schedule_periodic (map, FALSE, TRUE, FALSE);
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
	guint i;

	for (cur = cfg->maps; cur != NULL; cur = g_list_next (cur)) {
		map = cur->data;

		for (i = 0; i < map->backends->len; i ++) {
			bk = g_ptr_array_index (map->backends, i);
			MAP_RELEASE (bk);
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
	if (bk->protocol == MAP_PROTO_FILE) {
		g_free (bk->data.fd->filename);
		g_slice_free1 (sizeof (*bk->data.fd), bk->data.fd);
	}
	else {
		g_free (bk->data.hd->host);
		g_free (bk->data.hd->path);
		g_slice_free1 (sizeof (*bk->data.hd), bk->data.hd);
	}

	g_slice_free1 (sizeof (*bk), bk);
}

static struct rspamd_map_backend *
rspamd_map_parse_backend (struct rspamd_config *cfg, const gchar *map_line)
{
	struct rspamd_map_backend *bk;
	struct file_map_data *fdata = NULL;
	struct http_map_data *hdata = NULL;
	struct http_parser_url up;
	rspamd_ftok_t tok;

	bk = g_slice_alloc0 (sizeof (*bk));
	REF_INIT_RETAIN (bk, rspamd_map_backend_dtor);

	if (!rspamd_map_check_proto (cfg, map_line, bk)) {
		goto err;
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
	}

	return bk;

err:
	MAP_RELEASE (bk);

	if (hdata) {
		g_slice_free1 (sizeof (*hdata), hdata);
	}

	if (fdata) {
		g_slice_free1 (sizeof (*fdata), fdata);
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

	map = g_slice_alloc0 (sizeof (struct rspamd_map));
	map->read_callback = read_callback;
	map->fin_callback = fin_callback;
	map->user_data = user_data;
	map->cfg = cfg;
	map->id = g_random_int ();
	map->locked =
		rspamd_mempool_alloc0_shared (cfg->cfg_pool, sizeof (gint));
	map->cache =
			rspamd_mempool_alloc0_shared (cfg->cfg_pool, sizeof (*map->cache));
	map->backends = g_ptr_array_sized_new (1);
	g_ptr_array_add (map->backends, bk);
	map->name = g_strdup (map_line);
	map->poll_timeout = cfg->map_timeout;

	if (description != NULL) {
		map->description = g_strdup (description);
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

	g_assert (obj != NULL);

	if (ucl_object_type (obj) == UCL_STRING) {
		/* Just a plain string */
		return rspamd_map_add (cfg, ucl_object_tostring (obj), NULL,
				read_callback, fin_callback, user_data);
	}

	map = g_slice_alloc0 (sizeof (struct rspamd_map));
	map->read_callback = read_callback;
	map->fin_callback = fin_callback;
	map->user_data = user_data;
	map->cfg = cfg;
	map->id = g_random_int ();
	map->locked =
			rspamd_mempool_alloc0_shared (cfg->cfg_pool, sizeof (gint));
	map->cache =
				rspamd_mempool_alloc0_shared (cfg->cfg_pool, sizeof (*map->cache));
	map->backends = g_ptr_array_new ();
	map->poll_timeout = cfg->map_timeout;

	if (description) {
		map->description = g_strdup (description);
	}

	if (ucl_object_type (obj) == UCL_ARRAY) {
		/* Add array of maps as multiple backends */
		while ((cur = ucl_object_iterate (obj, &it, true)) != NULL) {
			if (ucl_object_type (cur) == UCL_STRING) {
				bk = rspamd_map_parse_backend (cfg, ucl_object_tostring (cur));

				if (bk != NULL) {
					g_ptr_array_add (map->backends, bk);

					if (!map->name) {
						map->name = g_strdup (ucl_object_tostring (cur));
					}
				}
			}
			else {
				msg_err_config ("bad map element type: %s",
						ucl_object_type_to_string (ucl_object_type (cur)));
			}
		}

		if (map->backends->len == 0) {
			msg_err_config ("map has no urls to be loaded");
			goto err;
		}
	}
	else if (ucl_object_type (obj) == UCL_OBJECT) {
		elt = ucl_object_lookup (obj, "name");
		if (elt && ucl_object_type (elt) == UCL_STRING) {
			map->name = g_strdup (ucl_object_tostring (elt));
		}

		elt = ucl_object_lookup (obj, "description");
		if (elt && ucl_object_type (elt) == UCL_STRING) {
			if (map->description) {
				g_free (map->description);
			}

			map->description = g_strdup (ucl_object_tostring (elt));
		}

		elt = ucl_object_lookup_any (obj, "timeout", "poll", "poll_time",
				"watch_interval", NULL);
		if (elt) {
			map->poll_timeout = ucl_object_todouble (elt);
		}

		elt = ucl_object_lookup_any (obj, "upstreams", "url", "urls", NULL);
		if (elt == NULL) {
			msg_err_config ("map has no urls to be loaded");
			goto err;
		}

		if (ucl_object_type (obj) == UCL_ARRAY) {
			/* Add array of maps as multiple backends */
			while ((cur = ucl_object_iterate (elt, &it, true)) != NULL) {
				if (ucl_object_type (cur) == UCL_STRING) {
					bk = rspamd_map_parse_backend (cfg, ucl_object_tostring (cur));

					if (bk != NULL) {
						g_ptr_array_add (map->backends, bk);

						if (!map->name) {
							map->name = g_strdup (ucl_object_tostring (cur));
						}
					}
				}
				else {
					msg_err_config ("bad map element type: %s",
							ucl_object_type_to_string (ucl_object_type (cur)));
					goto err;
				}
			}

			if (map->backends->len == 0) {
				msg_err_config ("map has no urls to be loaded");
				goto err;
			}
		}
		else if (ucl_object_type (elt) == UCL_STRING) {
			bk = rspamd_map_parse_backend (cfg, ucl_object_tostring (elt));

			if (bk != NULL) {
				g_ptr_array_add (map->backends, bk);

				if (!map->name) {
					map->name = g_strdup (ucl_object_tostring (cur));
				}
			}
		}

		if (map->backends->len == 0) {
			msg_err_config ("map has no urls to be loaded");
			goto err;
		}
	}

	rspamd_map_calculate_hash (map);
	msg_info_map ("added map from ucl");

	cfg->maps = g_list_prepend (cfg->maps, map);

	return map;

err:
	g_ptr_array_free (map->backends, TRUE);
	g_free (map->name);
	g_free (map->description);
	g_slice_free1 (sizeof (*map), map);

	return NULL;
}

/**
 * FSM for parsing lists
 */

#define MAP_STORE_KEY do { \
	key = g_malloc (p - c + 1); \
	rspamd_strlcpy (key, c, p - c + 1); \
} while (0)

#define MAP_STORE_VALUE do { \
	value = g_malloc (p - c + 1); \
	rspamd_strlcpy (value, c, p - c + 1); \
	value = g_strstrip (value); \
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

	rspamd_radix_add_iplist ((gchar *)key, " ,;", tree, value, FALSE);
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

struct rspamd_regexp_map {
	struct rspamd_map *map;
	GPtrArray *regexps;
	GPtrArray *values;
#ifdef WITH_HYPERSCAN
	hs_database_t *hs_db;
	hs_scratch_t *hs_scratch;
	const gchar **patterns;
	gint *flags;
	gint *ids;
#endif
};

static struct rspamd_regexp_map *
rspamd_regexp_map_create (struct rspamd_map *map)
{
	struct rspamd_regexp_map *re_map;

	re_map = g_slice_alloc0 (sizeof (*re_map));
	re_map->values = g_ptr_array_new ();
	re_map->regexps = g_ptr_array_new ();
	re_map->map = map;

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

	map = re_map->map;
	re = rspamd_regexp_new (key, NULL, &err);

	if (re == NULL) {
		msg_err_map ("cannot parse regexp %s: %e", key, err);

		if (err) {
			g_error_free (err);
		}

		return;
	}

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
rspamd_regexp_list_read (
	gchar *chunk,
	gint len,
	struct map_cb_data *data,
	gboolean final)
{
	struct rspamd_regexp_map *re_map;

	if (data->cur_data == NULL) {
		re_map = rspamd_regexp_map_create (data->map);
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

gpointer
rspamd_match_regexp_map (struct rspamd_regexp_map *map,
		const gchar *in, gsize len)
{
	guint i;
	rspamd_regexp_t *re;
	gint res = 0;
	gpointer ret = NULL;

	g_assert (in != NULL && len > 0);

	if (map == NULL) {
		return NULL;
	}

#ifdef WITH_HYPERSCAN
	if (map->hs_db && map->hs_scratch) {
		res = hs_scan (map->hs_db, in, len, 0, map->hs_scratch,
				rspamd_match_hs_single_handler, (void *)&i);

		if (res == HS_SCAN_TERMINATED) {
			res = 1;
			ret = g_ptr_array_index (map->values, i);
		}

		return ret;
	}
#endif

	if (!res) {
		/* PCRE version */
		for (i = 0; i < map->regexps->len; i ++) {
			re = g_ptr_array_index (map->regexps, i);

			if (rspamd_regexp_search (re, in, len, NULL, NULL, FALSE, NULL)) {
				ret = g_ptr_array_index (map->values, i);
				break;
			}
		}
	}

	return ret;
}
