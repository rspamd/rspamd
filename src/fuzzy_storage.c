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
 * Rspamd fuzzy storage server
 */

#include "config.h"
#include "libserver/fuzzy_wire.h"
#include "util.h"
#include "rspamd.h"
#include "libserver/maps/map.h"
#include "libserver/maps/map_helpers.h"
#include "libserver/fuzzy_backend/fuzzy_backend.h"
#include "ottery.h"
#include "ref.h"
#include "xxhash.h"
#include "libserver/worker_util.h"
#include "libserver/rspamd_control.h"
#include "libcryptobox/cryptobox.h"
#include "libcryptobox/keypairs_cache.h"
#include "libcryptobox/keypair.h"
#include "libutil/hash.h"
#include "libserver/maps/map_private.h"
#include "contrib/uthash/utlist.h"
#include "lua/lua_common.h"
#include "unix-std.h"

#include <math.h>

/* Resync value in seconds */
#define DEFAULT_SYNC_TIMEOUT 60.0
#define DEFAULT_KEYPAIR_CACHE_SIZE 512
#define DEFAULT_MASTER_TIMEOUT 10.0
#define DEFAULT_UPDATES_MAXFAIL 3
#define COOKIE_SIZE 128
#define DEFAULT_MAX_BUCKETS 2000
#define DEFAULT_BUCKET_TTL 3600
#define DEFAULT_BUCKET_MASK 24

static const gchar *local_db_name = "local";

#define msg_err_fuzzy_update(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        session->name, session->uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_fuzzy_update(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        session->name, session->uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_fuzzy_update(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        session->name, session->uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_err_fuzzy_collection(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        "fuzzy_collection", session->uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_fuzzy_collection(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
       "fuzzy_collection", session->uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_fuzzy_collection(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
       "fuzzy_collection", session->uid, \
        G_STRFUNC, \
        __VA_ARGS__)

/* Init functions */
gpointer init_fuzzy (struct rspamd_config *cfg);
void start_fuzzy (struct rspamd_worker *worker);

worker_t fuzzy_worker = {
		"fuzzy",                    /* Name */
		init_fuzzy,                 /* Init function */
		start_fuzzy,                /* Start function */
		RSPAMD_WORKER_HAS_SOCKET,
		RSPAMD_WORKER_SOCKET_UDP,   /* UDP socket */
		RSPAMD_WORKER_VER           /* Version info */
};

struct fuzzy_global_stat {
	guint64 fuzzy_hashes;
	/**< number of fuzzy hashes stored					*/
	guint64 fuzzy_hashes_expired;
	/**< number of fuzzy hashes expired					*/
	guint64 fuzzy_hashes_checked[RSPAMD_FUZZY_EPOCH_MAX];
	/**< amount of check requests for each epoch		*/
	guint64 fuzzy_shingles_checked[RSPAMD_FUZZY_EPOCH_MAX];
	/**< amount of shingle check requests for each epoch	*/
	guint64 fuzzy_hashes_found[RSPAMD_FUZZY_EPOCH_MAX];
	/**< amount of invalid requests				*/
	guint64 invalid_requests;
	/**< amount of delayed hashes found				*/
	guint64 delayed_hashes;
};

struct fuzzy_key_stat {
	guint64 checked;
	guint64 matched;
	guint64 added;
	guint64 deleted;
	guint64 errors;
	rspamd_lru_hash_t *last_ips;
	ref_entry_t ref;
};

struct rspamd_fuzzy_mirror {
	gchar *name;
	struct upstream_list *u;
	struct rspamd_cryptobox_pubkey *key;
};

struct rspamd_leaky_bucket_elt {
	rspamd_inet_addr_t *addr;
	gdouble last;
	gdouble cur;
};

static const guint64 rspamd_fuzzy_storage_magic = 0x291a3253eb1b3ea5ULL;

struct rspamd_fuzzy_storage_ctx {
	guint64 magic;
	/* Events base */
	struct ev_loop *event_loop;
	/* DNS resolver */
	struct rspamd_dns_resolver *resolver;
	/* Config */
	struct rspamd_config *cfg;
	/* END OF COMMON PART */
	struct fuzzy_global_stat stat;
	gdouble expire;
	gdouble sync_timeout;
	gdouble delay;
	struct rspamd_radix_map_helper *update_ips;
	struct rspamd_radix_map_helper *blocked_ips;
	struct rspamd_radix_map_helper *ratelimit_whitelist;
	struct rspamd_radix_map_helper *delay_whitelist;

	const ucl_object_t *update_map;
	const ucl_object_t *delay_whitelist_map;
	const ucl_object_t *blocked_map;
	const ucl_object_t *ratelimit_whitelist_map;

	guint keypair_cache_size;
	ev_timer stat_ev;
	ev_io peer_ev;

	/* Local keypair */
	struct rspamd_cryptobox_keypair *default_keypair; /* Bad clash, need for parse keypair */
	struct fuzzy_key *default_key;
	GHashTable *keys;
	gboolean encrypted_only;
	gboolean read_only;
	gboolean dedicated_update_worker;
	struct rspamd_keypair_cache *keypair_cache;
	struct rspamd_http_context *http_ctx;
	rspamd_lru_hash_t *errors_ips;
	rspamd_lru_hash_t *ratelimit_buckets;
	struct rspamd_fuzzy_backend *backend;
	GArray *updates_pending;
	guint updates_failed;
	guint updates_maxfail;
	/* Used to send data between workers */
	gint peer_fd;

	/* Ratelimits */
	guint leaky_bucket_ttl;
	guint leaky_bucket_mask;
	guint max_buckets;
	gboolean ratelimit_log_only;
	gdouble leaky_bucket_burst;
	gdouble leaky_bucket_rate;

	struct rspamd_worker *worker;
	const ucl_object_t *skip_map;
	struct rspamd_hash_map_helper *skip_hashes;
	gint lua_pre_handler_cbref;
	gint lua_post_handler_cbref;
	guchar cookie[COOKIE_SIZE];
};

enum fuzzy_cmd_type {
	CMD_NORMAL,
	CMD_SHINGLE,
	CMD_ENCRYPTED_NORMAL,
	CMD_ENCRYPTED_SHINGLE
};

struct fuzzy_session {
	struct rspamd_worker *worker;
	rspamd_inet_addr_t *addr;
	struct rspamd_fuzzy_storage_ctx *ctx;

	struct rspamd_fuzzy_shingle_cmd cmd; /* Can handle both shingles and non-shingles */
	struct rspamd_fuzzy_encrypted_reply reply; /* Again: contains everything */
	struct fuzzy_key_stat *ip_stat;

	enum rspamd_fuzzy_epoch epoch;
	enum fuzzy_cmd_type cmd_type;
	gint fd;
	guint64 time;
	struct ev_io io;
	ref_entry_t ref;
	struct fuzzy_key_stat *key_stat;
	struct rspamd_fuzzy_cmd_extension *extensions;
	guchar nm[rspamd_cryptobox_MAX_NMBYTES];
};

struct fuzzy_peer_request {
	ev_io io_ev;
	struct fuzzy_peer_cmd cmd;
};

struct fuzzy_key {
	struct rspamd_cryptobox_keypair *key;
	struct rspamd_cryptobox_pubkey *pk;
	struct fuzzy_key_stat *stat;
};

struct rspamd_updates_cbdata {
	GArray *updates_pending;
	struct rspamd_fuzzy_storage_ctx *ctx;
	gchar *source;
	gboolean final;
};


static void rspamd_fuzzy_write_reply (struct fuzzy_session *session);
static gboolean rspamd_fuzzy_process_updates_queue (
		struct rspamd_fuzzy_storage_ctx *ctx,
		const gchar *source, gboolean final);

static gboolean
rspamd_fuzzy_check_ratelimit (struct fuzzy_session *session)
{
	rspamd_inet_addr_t *masked;
	struct rspamd_leaky_bucket_elt *elt;
	ev_tstamp now;

	if (session->ctx->ratelimit_whitelist != NULL) {
		if (rspamd_match_radix_map_addr (session->ctx->ratelimit_whitelist,
				session->addr) != NULL) {
			return TRUE;
		}
	}

	/*
	if (rspamd_inet_address_is_local (session->addr, TRUE)) {
		return TRUE;
	}
	*/

	masked = rspamd_inet_address_copy (session->addr);

	if (rspamd_inet_address_get_af (masked) == AF_INET) {
		rspamd_inet_address_apply_mask (masked,
				MIN (session->ctx->leaky_bucket_mask, 32));
	}
	else {
		/* Must be at least /64 */
		rspamd_inet_address_apply_mask (masked,
				MIN (MAX (session->ctx->leaky_bucket_mask * 4, 64), 128));
	}

	now = ev_now (session->ctx->event_loop);
	elt = rspamd_lru_hash_lookup (session->ctx->ratelimit_buckets, masked,
			now);

	if (elt) {
		gboolean ratelimited = FALSE;

		if (isnan (elt->cur)) {
			/* Ratelimit exceeded, preserve it for the whole ttl */
			ratelimited = TRUE;
		}
		else {
			/* Update bucket */
			if (elt->last < now) {
				elt->cur -= session->ctx->leaky_bucket_rate * (now - elt->last);
				elt->last = now;

				if (elt->cur < 0) {
					elt->cur = 0;
				}
			}
			else {
				elt->last = now;
			}

			/* Check bucket */
			if (elt->cur >= session->ctx->leaky_bucket_burst) {

				msg_info ("ratelimiting %s (%s), %.1f max elts",
						rspamd_inet_address_to_string (session->addr),
						rspamd_inet_address_to_string (masked),
						session->ctx->leaky_bucket_burst);
				elt->cur = NAN;
			}
			else {
				elt->cur ++; /* Allow one more request */
			}
		}

		rspamd_inet_address_free (masked);

		return !ratelimited;
	}
	else {
		/* New bucket */
		elt = g_malloc (sizeof (*elt));
		elt->addr = masked; /* transfer ownership */
		elt->cur = 1;
		elt->last = now;

		rspamd_lru_hash_insert (session->ctx->ratelimit_buckets,
				masked,
				elt,
				now,
				session->ctx->leaky_bucket_ttl);
	}

	return TRUE;
}

static gboolean
rspamd_fuzzy_check_client (struct rspamd_fuzzy_storage_ctx *ctx,
		rspamd_inet_addr_t *addr)
{
	if (ctx->blocked_ips != NULL) {
		if (rspamd_match_radix_map_addr (ctx->blocked_ips,
				addr) != NULL) {
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
rspamd_fuzzy_check_write (struct fuzzy_session *session)
{
	if (session->ctx->read_only) {
		return FALSE;
	}

	if (session->ctx->update_ips != NULL) {
		if (rspamd_match_radix_map_addr (session->ctx->update_ips,
				session->addr) == NULL) {
			return FALSE;
		}
		else {
			return TRUE;
		}
	}

	return FALSE;
}

static void
fuzzy_key_stat_dtor (gpointer p)
{
	struct fuzzy_key_stat *st = p;

	if (st->last_ips) {
		rspamd_lru_hash_destroy (st->last_ips);
	}

	g_free (st);
}

static void
fuzzy_key_stat_unref (gpointer p)
{
	struct fuzzy_key_stat *st = p;

	REF_RELEASE (st);
}

static void
fuzzy_key_dtor (gpointer p)
{
	struct fuzzy_key *key = p;

	if (key) {
		if (key->stat) {
			REF_RELEASE (key->stat);
		}

		g_free (key);
	}
}

static void
fuzzy_count_callback (guint64 count, void *ud)
{
	struct rspamd_fuzzy_storage_ctx *ctx = ud;

	ctx->stat.fuzzy_hashes = count;
}

static void
fuzzy_rl_bucket_free (gpointer p)
{
	struct rspamd_leaky_bucket_elt *elt = (struct rspamd_leaky_bucket_elt *)p;

	rspamd_inet_address_free (elt->addr);
	g_free (elt);
}

static void
fuzzy_stat_count_callback (guint64 count, void *ud)
{
	struct rspamd_fuzzy_storage_ctx *ctx = ud;

	ev_timer_again (ctx->event_loop, &ctx->stat_ev);
	ctx->stat.fuzzy_hashes = count;
}

static void
rspamd_fuzzy_stat_callback (EV_P_ ev_timer *w, int revents)
{
	struct rspamd_fuzzy_storage_ctx *ctx =
			(struct rspamd_fuzzy_storage_ctx *)w->data;
	rspamd_fuzzy_backend_count (ctx->backend, fuzzy_stat_count_callback, ctx);
}


static void
fuzzy_update_version_callback (guint64 ver, void *ud)
{
}

static void
rspamd_fuzzy_updates_cb (gboolean success,
						 guint nadded,
						 guint ndeleted,
						 guint nextended,
						 guint nignored,
						 void *ud)
{
	struct rspamd_updates_cbdata *cbdata = ud;
	struct rspamd_fuzzy_storage_ctx *ctx;
	const gchar *source;

	ctx = cbdata->ctx;
	source = cbdata->source;

	if (success) {
		rspamd_fuzzy_backend_count (ctx->backend, fuzzy_count_callback, ctx);

		msg_info ("successfully updated fuzzy storage %s: %d updates in queue; "
				  "%d pending currently; "
				  "%d added; %d deleted; %d extended; %d duplicates",
				ctx->worker->cf->bind_conf ?
					 ctx->worker->cf->bind_conf->bind_line :
					 "unknown",
				cbdata->updates_pending->len,
				ctx->updates_pending->len,
				nadded, ndeleted, nextended, nignored);
		rspamd_fuzzy_backend_version (ctx->backend, source,
				fuzzy_update_version_callback, NULL);
		ctx->updates_failed = 0;

		if (cbdata->final || ctx->worker->state != rspamd_worker_state_running) {
			/* Plan exit */
			ev_break (ctx->event_loop, EVBREAK_ALL);
		}
	}
	else {
		if (++ctx->updates_failed > ctx->updates_maxfail) {
			msg_err ("cannot commit update transaction to fuzzy backend %s, discard "
					 "%ud updates after %d retries",
					ctx->worker->cf->bind_conf ?
						ctx->worker->cf->bind_conf->bind_line :
						"unknown",
					cbdata->updates_pending->len,
					ctx->updates_maxfail);
			ctx->updates_failed = 0;

			if (cbdata->final || ctx->worker->state != rspamd_worker_state_running) {
				/* Plan exit */
				ev_break (ctx->event_loop, EVBREAK_ALL);
			}
		}
		else {
			msg_err ("cannot commit update transaction to fuzzy backend %s; "
					 "%ud updates are still left; %ud currently pending;"
					 " %d updates left",
					ctx->worker->cf->bind_conf ?
						ctx->worker->cf->bind_conf->bind_line :
						"unknown",
					cbdata->updates_pending->len,
					ctx->updates_pending->len,
					ctx->updates_maxfail - ctx->updates_failed);
			/* Move the remaining updates to ctx queue */
			g_array_append_vals (ctx->updates_pending,
					cbdata->updates_pending->data,
					cbdata->updates_pending->len);

			if (cbdata->final) {
				/* Try one more time */
				rspamd_fuzzy_process_updates_queue (cbdata->ctx, cbdata->source,
						cbdata->final);
			}
		}
	}

	g_array_free (cbdata->updates_pending, TRUE);
	g_free (cbdata->source);
	g_free (cbdata);
}

static gboolean
rspamd_fuzzy_process_updates_queue (struct rspamd_fuzzy_storage_ctx *ctx,
		const gchar *source, gboolean final)
{

	struct rspamd_updates_cbdata *cbdata;

	if (ctx->updates_pending->len > 0) {
		cbdata = g_malloc (sizeof (*cbdata));
		cbdata->ctx = ctx;
		cbdata->final = final;
		cbdata->updates_pending = ctx->updates_pending;
		ctx->updates_pending = g_array_sized_new (FALSE, FALSE,
				sizeof (struct fuzzy_peer_cmd),
				MAX (cbdata->updates_pending->len, 1024));
		cbdata->source = g_strdup (source);
		rspamd_fuzzy_backend_process_updates (ctx->backend,
				cbdata->updates_pending,
				source, rspamd_fuzzy_updates_cb, cbdata);
		return TRUE;
	}
	else if (final) {
		/* No need to sync */
		ev_break (ctx->event_loop, EVBREAK_ALL);
	}

	return FALSE;
}

static void
rspamd_fuzzy_reply_io (EV_P_ ev_io *w, int revents)
{
	struct fuzzy_session *session = (struct fuzzy_session *)w->data;

	ev_io_stop (EV_A_ w);
	rspamd_fuzzy_write_reply (session);
	REF_RELEASE (session);
}

static void
rspamd_fuzzy_write_reply (struct fuzzy_session *session)
{
	gssize r;
	gsize len;
	gconstpointer data;

	if (session->cmd_type == CMD_ENCRYPTED_NORMAL ||
				session->cmd_type == CMD_ENCRYPTED_SHINGLE) {
		/* Encrypted reply */
		data = &session->reply;

		if (session->epoch > RSPAMD_FUZZY_EPOCH10) {
			len = sizeof (session->reply);
		}
		else {
			len = sizeof (session->reply.hdr) + sizeof (session->reply.rep.v1);
		}
	}
	else {
		data = &session->reply.rep;

		if (session->epoch > RSPAMD_FUZZY_EPOCH10) {
			len = sizeof (session->reply.rep);
		}
		else {
			len = sizeof (session->reply.rep.v1);
		}
	}

	r = rspamd_inet_address_sendto (session->fd, data, len, 0,
			session->addr);

	if (r == -1) {
		if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
			/* Grab reference to avoid early destruction */
			REF_RETAIN (session);
			session->io.data = session;
			ev_io_init (&session->io,
					rspamd_fuzzy_reply_io, session->fd, EV_WRITE);
			ev_io_start (session->ctx->event_loop, &session->io);
		}
		else {
			msg_err ("error while writing reply: %s", strerror (errno));
		}
	}
}

static void
rspamd_fuzzy_update_stats (struct rspamd_fuzzy_storage_ctx *ctx,
		enum rspamd_fuzzy_epoch epoch,
		gboolean matched,
		gboolean is_shingle,
		gboolean is_delayed,
		struct fuzzy_key_stat *key_stat,
		struct fuzzy_key_stat *ip_stat,
		guint cmd, guint reply)
{
	ctx->stat.fuzzy_hashes_checked[epoch] ++;

	if (matched) {
		ctx->stat.fuzzy_hashes_found[epoch]++;
	}
	if (is_shingle) {
		ctx->stat.fuzzy_shingles_checked[epoch]++;
	}
	if (is_delayed) {
		ctx->stat.delayed_hashes ++;
	}

	if (key_stat) {
		if (!matched && reply != 0) {
			key_stat->errors ++;
		}
		else {
			if (cmd == FUZZY_CHECK) {
				key_stat->checked++;

				if (matched) {
					key_stat->matched ++;
				}
			}
			else if (cmd == FUZZY_WRITE) {
				key_stat->added++;
			}
			else if (cmd == FUZZY_DEL) {
				key_stat->deleted++;
			}
		}
	}

	if (ip_stat) {
		if (!matched && reply != 0) {
			ip_stat->errors++;
		}
		else {
			if (cmd == FUZZY_CHECK) {
				ip_stat->checked++;

				if (matched) {
					ip_stat->matched++;
				}
			}
			else if (cmd == FUZZY_WRITE) {
				ip_stat->added++;
			}
			else if (cmd == FUZZY_DEL) {
				ip_stat->deleted++;
			}
		}
	}
}

enum rspamd_fuzzy_reply_flags {
	RSPAMD_FUZZY_REPLY_ENCRYPTED = 0x1u << 0u,
	RSPAMD_FUZZY_REPLY_SHINGLE = 0x1u << 1u,
	RSPAMD_FUZZY_REPLY_DELAY = 0x1u << 2u,
};

static void
rspamd_fuzzy_make_reply (struct rspamd_fuzzy_cmd *cmd,
		struct rspamd_fuzzy_reply *result,
		struct fuzzy_session *session,
		gint flags)
{
	gsize len;

	if (cmd) {
		result->v1.tag = cmd->tag;
		memcpy (&session->reply.rep, result, sizeof (*result));

		rspamd_fuzzy_update_stats (session->ctx,
				session->epoch,
				result->v1.prob > 0.5,
				flags & RSPAMD_FUZZY_REPLY_SHINGLE,
				flags & RSPAMD_FUZZY_REPLY_DELAY,
				session->key_stat,
				session->ip_stat,
				cmd->cmd,
				result->v1.value);

		if (flags & RSPAMD_FUZZY_REPLY_DELAY) {
			/* Hash is too fresh, need to delay it */
			session->reply.rep.ts = 0;
			session->reply.rep.v1.prob = 0.0;
			session->reply.rep.v1.value = 0;
		}

		if (flags & RSPAMD_FUZZY_REPLY_ENCRYPTED) {
			/* We need also to encrypt reply */
			ottery_rand_bytes (session->reply.hdr.nonce,
					sizeof (session->reply.hdr.nonce));

			/*
			 * For old replies we need to encrypt just old part, otherwise
			 * decryption would fail due to mac verification mistake
			 */

			if (session->epoch > RSPAMD_FUZZY_EPOCH10) {
				len = sizeof (session->reply.rep);
			}
			else {
				len = sizeof (session->reply.rep.v1);
			}

			rspamd_cryptobox_encrypt_nm_inplace ((guchar *)&session->reply.rep,
					len,
					session->reply.hdr.nonce,
					session->nm,
					session->reply.hdr.mac,
					RSPAMD_CRYPTOBOX_MODE_25519);
		}
	}

	rspamd_fuzzy_write_reply (session);
}

static gboolean
fuzzy_peer_try_send (gint fd, struct fuzzy_peer_request *up_req)
{
	gssize r;

	r = write (fd, &up_req->cmd, sizeof (up_req->cmd));

	if (r != sizeof (up_req->cmd)) {
		return FALSE;
	}

	return TRUE;
}

static void
fuzzy_peer_send_io (EV_P_ ev_io *w, int revents)
{
	struct fuzzy_peer_request *up_req = (struct fuzzy_peer_request *)w->data;

	if (!fuzzy_peer_try_send (w->fd, up_req)) {
		msg_err ("cannot send update request to the peer: %s", strerror (errno));
	}

	ev_io_stop (EV_A_ w);
	g_free (up_req);
}

static void
rspamd_fuzzy_extensions_tolua (lua_State *L,
							   struct fuzzy_session *session)
{
	struct rspamd_fuzzy_cmd_extension *ext;
	rspamd_inet_addr_t *addr;

	lua_createtable (L, 0, 0);

	LL_FOREACH (session->extensions, ext) {
		switch (ext->ext) {
		case RSPAMD_FUZZY_EXT_SOURCE_DOMAIN:
			lua_pushlstring (L, ext->payload, ext->length);
			lua_setfield (L, -2, "domain");
			break;
		case RSPAMD_FUZZY_EXT_SOURCE_IP4:
			addr = rspamd_inet_address_new (AF_INET, ext->payload);
			rspamd_lua_ip_push (L, addr);
			rspamd_inet_address_free (addr);
			lua_setfield (L, -2, "ip");
			break;
		case RSPAMD_FUZZY_EXT_SOURCE_IP6:
			addr = rspamd_inet_address_new (AF_INET6, ext->payload);
			rspamd_lua_ip_push (L, addr);
			rspamd_inet_address_free (addr);
			lua_setfield (L, -2, "ip");
			break;
		}
	}
}

static void
rspamd_fuzzy_check_callback (struct rspamd_fuzzy_reply *result, void *ud)
{
	struct fuzzy_session *session = ud;
	gboolean is_shingle = FALSE, __attribute__ ((unused)) encrypted = FALSE;
	struct rspamd_fuzzy_cmd *cmd = NULL;
	const struct rspamd_shingle *shingle = NULL;
	struct rspamd_shingle sgl_cpy;
	gint send_flags = 0;

	switch (session->cmd_type) {
	case CMD_ENCRYPTED_NORMAL:
		encrypted = TRUE;
		send_flags |= RSPAMD_FUZZY_REPLY_ENCRYPTED;
		/* Fallthrough */
	case CMD_NORMAL:
		cmd = &session->cmd.basic;
		break;

	case CMD_ENCRYPTED_SHINGLE:
		encrypted = TRUE;
		send_flags |= RSPAMD_FUZZY_REPLY_ENCRYPTED;
		/* Fallthrough */
	case CMD_SHINGLE:
		cmd = &session->cmd.basic;
		memcpy (&sgl_cpy, &session->cmd.sgl, sizeof (sgl_cpy));
		shingle = &sgl_cpy;
		is_shingle = TRUE;
		send_flags |= RSPAMD_FUZZY_REPLY_SHINGLE;
		break;
	}

	if (session->ctx->lua_post_handler_cbref != -1) {
		/* Start lua post handler */
		lua_State *L = session->ctx->cfg->lua_state;
		gint err_idx, ret;

		lua_pushcfunction (L, &rspamd_lua_traceback);
		err_idx = lua_gettop (L);
		/* Preallocate stack (small opt) */
		lua_checkstack (L, err_idx + 9);
		/* function */
		lua_rawgeti (L, LUA_REGISTRYINDEX, session->ctx->lua_post_handler_cbref);
		/* client IP */
		rspamd_lua_ip_push (L, session->addr);
		/* client command */
		lua_pushinteger (L, cmd->cmd);
		/* command value (push as rspamd_text) */
		(void)lua_new_text (L, result->digest, sizeof (result->digest), FALSE);
		/* is shingle */
		lua_pushboolean (L, is_shingle);
		/* result value */
		lua_pushinteger (L, result->v1.value);
		/* result probability */
		lua_pushnumber (L, result->v1.prob);
		/* result flag */
		lua_pushinteger (L, result->v1.flag);
		/* result timestamp */
		lua_pushinteger (L, result->ts);
		/* TODO: add additional data maybe (encryption, pubkey, etc) */
		rspamd_fuzzy_extensions_tolua (L, session);

		if ((ret = lua_pcall (L, 9, LUA_MULTRET, err_idx)) != 0) {
			msg_err ("call to lua_post_handler lua "
					 "script failed (%d): %s", ret, lua_tostring (L, -1));
		}
		else {
			/* Return values order:
			 * the first reply will be on err_idx + 1
			 * if it is true, then we need to read the former ones:
			 * 2-nd will be reply code
			 * 3-rd will be probability (or 0.0 if missing)
			 * 4-th value is flag (or default flag if missing)
			 */
			ret = lua_toboolean (L, err_idx + 1);

			if (ret) {
				/* Artificial reply */
				result->v1.value = lua_tointeger (L, err_idx + 2);

				if (lua_isnumber (L, err_idx + 3)) {
					result->v1.prob = lua_tonumber (L, err_idx + 3);
				}
				else {
					result->v1.prob = 0.0f;
				}

				if (lua_isnumber (L, err_idx + 4)) {
					result->v1.flag = lua_tointeger (L, err_idx + 4);
				}

				lua_settop (L, 0);
				rspamd_fuzzy_make_reply (cmd, result, session, send_flags);
				REF_RELEASE (session);

				return;
			}
		}

		lua_settop (L, 0);
	}

	if (!isnan (session->ctx->delay) &&
			rspamd_match_radix_map_addr (session->ctx->delay_whitelist,
					session->addr) == NULL)  {
		gdouble hash_age = rspamd_get_calendar_ticks () - result->ts;
		gdouble jittered_age = rspamd_time_jitter (session->ctx->delay,
				session->ctx->delay / 2.0);

		if (hash_age < jittered_age) {
			send_flags |= RSPAMD_FUZZY_REPLY_DELAY;
		}
	}

	/* Refresh hash if found with strong confidence */
	if (result->v1.prob > 0.9 && !session->ctx->read_only) {
		struct fuzzy_peer_cmd up_cmd;
		struct fuzzy_peer_request *up_req;

		if (session->worker->index == 0) {
			/* Just add to the queue */
			memset (&up_cmd, 0, sizeof (up_cmd));
			up_cmd.is_shingle = is_shingle;
			memcpy (up_cmd.cmd.normal.digest, result->digest,
					sizeof (up_cmd.cmd.normal.digest));
			up_cmd.cmd.normal.flag = result->v1.flag;
			up_cmd.cmd.normal.cmd = FUZZY_REFRESH;
			up_cmd.cmd.normal.shingles_count = cmd->shingles_count;

			if (is_shingle && shingle) {
				memcpy (&up_cmd.cmd.shingle.sgl, shingle,
						sizeof (up_cmd.cmd.shingle.sgl));
			}

			g_array_append_val (session->ctx->updates_pending, up_cmd);
		}
		else {
			/* We need to send request to the peer */
			up_req = g_malloc0 (sizeof (*up_req));
			up_req->cmd.is_shingle = is_shingle;

			memcpy (up_req->cmd.cmd.normal.digest, result->digest,
					sizeof (up_req->cmd.cmd.normal.digest));
			up_req->cmd.cmd.normal.flag = result->v1.flag;
			up_req->cmd.cmd.normal.cmd = FUZZY_REFRESH;
			up_req->cmd.cmd.normal.shingles_count = cmd->shingles_count;

			if (is_shingle && shingle) {
				memcpy (&up_req->cmd.cmd.shingle.sgl, shingle,
						sizeof (up_req->cmd.cmd.shingle.sgl));
			}

			if (!fuzzy_peer_try_send (session->ctx->peer_fd, up_req)) {
				up_req->io_ev.data = up_req;
				ev_io_init (&up_req->io_ev, fuzzy_peer_send_io,
						session->ctx->peer_fd, EV_WRITE);
				ev_io_start (session->ctx->event_loop, &up_req->io_ev);
			}
			else {
				g_free (up_req);
			}
		}
	}

	rspamd_fuzzy_make_reply (cmd, result, session, send_flags);

	REF_RELEASE (session);
}

static void
rspamd_fuzzy_process_command (struct fuzzy_session *session)
{
	gboolean is_shingle = FALSE, __attribute__ ((unused)) encrypted = FALSE;
	struct rspamd_fuzzy_cmd *cmd = NULL;
	struct rspamd_fuzzy_reply result;
	struct fuzzy_peer_cmd up_cmd;
	struct fuzzy_peer_request *up_req;
	struct fuzzy_key_stat *ip_stat = NULL;
	gchar hexbuf[rspamd_cryptobox_HASHBYTES * 2 + 1];
	rspamd_inet_addr_t *naddr;
	gpointer ptr;
	gsize up_len = 0;
	gint send_flags = 0;

	cmd = &session->cmd.basic;

	switch (session->cmd_type) {
	case CMD_NORMAL:
		up_len = sizeof (session->cmd.basic);
		break;
	case CMD_SHINGLE:
		up_len = sizeof (session->cmd);
		is_shingle = TRUE;
		send_flags |= RSPAMD_FUZZY_REPLY_SHINGLE;
		break;
	case CMD_ENCRYPTED_NORMAL:
		up_len = sizeof (session->cmd.basic);
		encrypted = TRUE;
		send_flags |= RSPAMD_FUZZY_REPLY_ENCRYPTED;
		break;
	case CMD_ENCRYPTED_SHINGLE:
		up_len = sizeof (session->cmd);
		encrypted = TRUE;
		is_shingle = TRUE;
		send_flags |= RSPAMD_FUZZY_REPLY_SHINGLE|RSPAMD_FUZZY_REPLY_ENCRYPTED;
		break;
	default:
		msg_err ("invalid command type: %d", session->cmd_type);
		return;
	}

	memset (&result, 0, sizeof (result));
	memcpy (result.digest, cmd->digest, sizeof (result.digest));
	result.v1.flag = cmd->flag;
	result.v1.tag = cmd->tag;

	if (session->ctx->lua_pre_handler_cbref != -1) {
		/* Start lua pre handler */
		lua_State *L = session->ctx->cfg->lua_state;
		gint err_idx, ret;

		lua_pushcfunction (L, &rspamd_lua_traceback);
		err_idx = lua_gettop (L);
		/* Preallocate stack (small opt) */
		lua_checkstack (L, err_idx + 5);
		/* function */
		lua_rawgeti (L, LUA_REGISTRYINDEX, session->ctx->lua_pre_handler_cbref);
		/* client IP */
		rspamd_lua_ip_push (L, session->addr);
		/* client command */
		lua_pushinteger (L, cmd->cmd);
		/* command value (push as rspamd_text) */
		(void)lua_new_text (L, cmd->digest, sizeof (cmd->digest), FALSE);
		/* is shingle */
		lua_pushboolean (L, is_shingle);
		/* TODO: add additional data maybe (encryption, pubkey, etc) */
		rspamd_fuzzy_extensions_tolua (L, session);

		if ((ret = lua_pcall (L, 5, LUA_MULTRET, err_idx)) != 0) {
			msg_err ("call to lua_pre_handler lua "
						  "script failed (%d): %s", ret, lua_tostring (L, -1));
		}
		else {
			/* Return values order:
			 * the first reply will be on err_idx + 1
			 * if it is true, then we need to read the former ones:
			 * 2-nd will be reply code
			 * 3-rd will be probability (or 0.0 if missing)
			 */
			ret = lua_toboolean (L, err_idx + 1);

			if (ret) {
				/* Artificial reply */
				result.v1.value = lua_tointeger (L, err_idx + 2);

				if (lua_isnumber (L, err_idx + 3)) {
					result.v1.prob = lua_tonumber (L, err_idx + 3);
				}
				else {
					result.v1.prob = 0.0f;
				}

				lua_settop (L, 0);
				rspamd_fuzzy_make_reply (cmd, &result, session, send_flags);

				return;
			}
		}

		lua_settop (L, 0);
	}


	if (G_UNLIKELY (cmd == NULL || up_len == 0)) {
		result.v1.value = 500;
		result.v1.prob = 0.0f;
		rspamd_fuzzy_make_reply (cmd, &result, session, send_flags);
		return;
	}

	if (session->ctx->encrypted_only && !encrypted) {
		/* Do not accept unencrypted commands */
		result.v1.value = 403;
		result.v1.prob = 0.0f;
		rspamd_fuzzy_make_reply (cmd, &result, session, send_flags);
		return;
	}

	if (session->key_stat) {
		ip_stat = rspamd_lru_hash_lookup (session->key_stat->last_ips,
				session->addr, -1);

		if (ip_stat == NULL) {
			naddr = rspamd_inet_address_copy (session->addr);
			ip_stat = g_malloc0 (sizeof (*ip_stat));
			REF_INIT_RETAIN (ip_stat, fuzzy_key_stat_dtor);
			rspamd_lru_hash_insert (session->key_stat->last_ips,
					naddr, ip_stat, -1, 0);
		}

		REF_RETAIN (ip_stat);
		session->ip_stat = ip_stat;
	}

	if (cmd->cmd == FUZZY_CHECK) {
		bool can_continue = true;

		if (session->ctx->ratelimit_buckets) {
			if (session->ctx->ratelimit_log_only) {
				(void)rspamd_fuzzy_check_ratelimit (session); /* Check but ignore */
			}
			else {
				can_continue = rspamd_fuzzy_check_ratelimit (session);
			}
		}

		if (can_continue) {
			REF_RETAIN (session);
			rspamd_fuzzy_backend_check (session->ctx->backend, cmd,
					rspamd_fuzzy_check_callback, session);
		}
		else {
			result.v1.value = 403;
			result.v1.prob = 0.0f;
			result.v1.flag = 0;
			rspamd_fuzzy_make_reply (cmd, &result, session, send_flags);
		}
	}
	else if (cmd->cmd == FUZZY_STAT) {
		result.v1.prob = 1.0f;
		result.v1.value = 0;
		result.v1.flag = session->ctx->stat.fuzzy_hashes;
		rspamd_fuzzy_make_reply (cmd, &result, session, send_flags);
	}
	else {
		if (rspamd_fuzzy_check_write (session)) {
			/* Check whitelist */
			if (session->ctx->skip_hashes && cmd->cmd == FUZZY_WRITE) {
				rspamd_encode_hex_buf (cmd->digest, sizeof (cmd->digest),
					hexbuf, sizeof (hexbuf) - 1);
				hexbuf[sizeof (hexbuf) - 1] = '\0';

				if (rspamd_match_hash_map (session->ctx->skip_hashes,
						hexbuf, sizeof (hexbuf) - 1)) {
					result.v1.value = 401;
					result.v1.prob = 0.0f;

					goto reply;
				}
			}

			if (session->worker->index == 0 || session->ctx->peer_fd == -1) {
				/* Just add to the queue */
				up_cmd.is_shingle = is_shingle;
				ptr = is_shingle ?
						(gpointer)&up_cmd.cmd.shingle :
						(gpointer)&up_cmd.cmd.normal;
				memcpy (ptr, cmd, up_len);
				g_array_append_val (session->ctx->updates_pending, up_cmd);
			}
			else {
				/* We need to send request to the peer */
				up_req = g_malloc0 (sizeof (*up_req));
				up_req->cmd.is_shingle = is_shingle;
				ptr = is_shingle ?
						(gpointer)&up_req->cmd.cmd.shingle :
						(gpointer)&up_req->cmd.cmd.normal;
				memcpy (ptr, cmd, up_len);

				if (!fuzzy_peer_try_send (session->ctx->peer_fd, up_req)) {
					up_req->io_ev.data = up_req;
					ev_io_init (&up_req->io_ev, fuzzy_peer_send_io,
							session->ctx->peer_fd, EV_WRITE);
					ev_io_start (session->ctx->event_loop, &up_req->io_ev);
				}
				else {
					g_free (up_req);
				}
			}

			result.v1.value = 0;
			result.v1.prob = 1.0f;
		}
		else {
			result.v1.value = 403;
			result.v1.prob = 0.0f;
		}
reply:
		rspamd_fuzzy_make_reply (cmd, &result, session, send_flags);
	}
}


static enum rspamd_fuzzy_epoch
rspamd_fuzzy_command_valid (struct rspamd_fuzzy_cmd *cmd, gint r)
{
	enum rspamd_fuzzy_epoch ret = RSPAMD_FUZZY_EPOCH_MAX;

	switch (cmd->version) {
	case 4:
		if (cmd->shingles_count > 0) {
			if (r >= sizeof (struct rspamd_fuzzy_shingle_cmd)) {
				ret = RSPAMD_FUZZY_EPOCH11;
			}
		}
		else {
			if (r >= sizeof (*cmd)) {
				ret = RSPAMD_FUZZY_EPOCH11;
			}
		}
		break;
	case 3:
		if (cmd->shingles_count > 0) {
			if (r == sizeof (struct rspamd_fuzzy_shingle_cmd)) {
				ret = RSPAMD_FUZZY_EPOCH10;
			}
		}
		else {
			if (r == sizeof (*cmd)) {
				ret = RSPAMD_FUZZY_EPOCH10;
			}
		}
		break;
	case 2:
		/*
		 * rspamd 0.8 has slightly different tokenizer then it might be not
		 * 100% compatible
		 */
		if (cmd->shingles_count > 0) {
			if (r == sizeof (struct rspamd_fuzzy_shingle_cmd)) {
				ret = RSPAMD_FUZZY_EPOCH8;
			}
		}
		else {
			ret = RSPAMD_FUZZY_EPOCH8;
		}
		break;
	default:
		break;
	}

	return ret;
}

static gboolean
rspamd_fuzzy_decrypt_command (struct fuzzy_session *s, guchar *buf, gsize buflen)
{
	struct rspamd_fuzzy_encrypted_req_hdr hdr;
	struct rspamd_cryptobox_pubkey *rk;
	struct fuzzy_key *key;

	if (s->ctx->default_key == NULL) {
		msg_warn ("received encrypted request when encryption is not enabled");
		return FALSE;
	}

	if (buflen < sizeof (hdr)) {
		msg_warn ("XXX: should not be reached");
		return FALSE;
	}

	memcpy (&hdr, buf, sizeof (hdr));
	buf += sizeof (hdr);
	buflen -= sizeof (hdr);

	/* Try to find the desired key */
	key = g_hash_table_lookup (s->ctx->keys, hdr.key_id);

	if (key == NULL) {
		/* Unknown key, assume default one */
		key = s->ctx->default_key;
	}

	s->key_stat = key->stat;

	/* Now process keypair */
	rk = rspamd_pubkey_from_bin (hdr.pubkey, sizeof (hdr.pubkey),
			RSPAMD_KEYPAIR_KEX, RSPAMD_CRYPTOBOX_MODE_25519);

	if (rk == NULL) {
		msg_err ("bad key; ip=%s",
				rspamd_inet_address_to_string (s->addr));
		return FALSE;
	}

	rspamd_keypair_cache_process (s->ctx->keypair_cache, key->key, rk);

	/* Now decrypt request */
	if (!rspamd_cryptobox_decrypt_nm_inplace (buf, buflen, hdr.nonce,
			rspamd_pubkey_get_nm (rk, key->key),
			hdr.mac, RSPAMD_CRYPTOBOX_MODE_25519)) {
		msg_err ("decryption failed; ip=%s",
				rspamd_inet_address_to_string (s->addr));
		rspamd_pubkey_unref (rk);

		return FALSE;
	}

	memcpy (s->nm, rspamd_pubkey_get_nm (rk, key->key), sizeof (s->nm));
	rspamd_pubkey_unref (rk);

	return TRUE;
}


static gboolean
rspamd_fuzzy_extensions_from_wire (struct fuzzy_session *s, guchar *buf, gsize buflen)
{
	struct rspamd_fuzzy_cmd_extension *ext, *prev_ext;
	guchar *storage, *p = buf, *end = buf + buflen;
	gsize st_len = 0, n_ext = 0;

	/* Read number of extensions to allocate array */
	while (p < end) {
		guchar cmd = *p++;

		if (p < end) {
			if (cmd == RSPAMD_FUZZY_EXT_SOURCE_DOMAIN) {
				/* Next byte is buf length */
				guchar dom_len = *p++;

				if (dom_len <= (end - p)) {
					st_len += dom_len;
					n_ext ++;
				}
				else {
					/* Truncation */
					return FALSE;
				}

				p += dom_len;
			}
			else if (cmd == RSPAMD_FUZZY_EXT_SOURCE_IP4) {
				if (end - p >= sizeof (in_addr_t)) {
					n_ext ++;
					st_len += sizeof (in_addr_t);
				}
				else {
					/* Truncation */
					return FALSE;
				}

				p += sizeof (in_addr_t);
			}
			else if (cmd == RSPAMD_FUZZY_EXT_SOURCE_IP6) {
				if (end - p >= sizeof (struct in6_addr)) {
					n_ext ++;
					st_len += sizeof (struct in6_addr);
				}
				else {
					/* Truncation */
					return FALSE;
				}

				p += sizeof (struct in6_addr);
			}
			else {
				/* Invalid command */
				return FALSE;
			}
		}
		else {
			/* Truncated extension */
			return FALSE;
		}
	}

	if (n_ext > 0) {
		p = buf;
		/*
		 * Memory layout: n_ext of struct rspamd_fuzzy_cmd_extension
		 *                payload for each extension in a continious data segment
		 */
		storage = g_malloc (n_ext * sizeof (struct rspamd_fuzzy_cmd_extension) +
				st_len);

		guchar *data_buf = storage +
				n_ext * sizeof (struct rspamd_fuzzy_cmd_extension);
		ext = (struct rspamd_fuzzy_cmd_extension *)storage;

		/* All validation has been done, so we can just go further */
		while (p < end) {
			prev_ext = ext;
			guchar cmd = *p++;

			if (cmd == RSPAMD_FUZZY_EXT_SOURCE_DOMAIN) {
				/* Next byte is buf length */
				guchar dom_len = *p++;
				guchar *dest = data_buf;

				ext->ext = RSPAMD_FUZZY_EXT_SOURCE_DOMAIN;
				ext->next = ext + 1;
				ext->length = dom_len;
				ext->payload = dest;
				memcpy (dest, p, dom_len);
				p += dom_len;
				data_buf += dom_len;
				ext = ext->next;
			}
			else if (cmd == RSPAMD_FUZZY_EXT_SOURCE_IP4) {
				guchar *dest = data_buf;

				ext->ext = RSPAMD_FUZZY_EXT_SOURCE_IP4;
				ext->next = ext + 1;
				ext->length = sizeof (in_addr_t);
				ext->payload = dest;
				memcpy (dest, p, sizeof (in_addr_t));
				p += sizeof (in_addr_t);
				data_buf += sizeof (in_addr_t);
				ext = ext->next;
			}
			else if (cmd == RSPAMD_FUZZY_EXT_SOURCE_IP6) {
				guchar *dest = data_buf;

				ext->ext = RSPAMD_FUZZY_EXT_SOURCE_IP6;
				ext->next = ext + 1;
				ext->length = sizeof (struct in6_addr);
				ext->payload = dest;
				memcpy (dest, p, sizeof (struct in6_addr));
				p += sizeof (struct in6_addr);
				data_buf += sizeof (struct in6_addr);
				ext = ext->next;
			}
			else {
				g_assert_not_reached ();
			}
		}

		/* Last next should be NULL */
		prev_ext->next = NULL;

		/* Rewind to the begin */
		ext = (struct rspamd_fuzzy_cmd_extension *)storage;
		s->extensions = ext;
	}

	return TRUE;
}

static gboolean
rspamd_fuzzy_cmd_from_wire (guchar *buf, guint buflen, struct fuzzy_session *s)
{
	enum rspamd_fuzzy_epoch epoch;
	gboolean encrypted = FALSE;

	if (buflen < sizeof (struct rspamd_fuzzy_cmd)) {
		msg_debug ("truncated fuzzy command of size %d received", buflen);
		return FALSE;
	}

	/* Now check encryption */

	if (buflen >= sizeof (struct rspamd_fuzzy_encrypted_cmd)) {
		if (memcmp (buf, fuzzy_encrypted_magic, sizeof (fuzzy_encrypted_magic)) == 0) {
			/* Encrypted command */
			encrypted = TRUE;
		}
	}

	if (encrypted) {
		/* Decrypt first */
		if (!rspamd_fuzzy_decrypt_command (s, buf, buflen)) {
			return FALSE;
		}
		else {
			/*
			 * Advance buffer to skip encrypted header.
			 * Note that after rspamd_fuzzy_decrypt_command buf is unencrypted
			 */
			buf += sizeof (struct rspamd_fuzzy_encrypted_req_hdr);
			buflen -= sizeof (struct rspamd_fuzzy_encrypted_req_hdr);
		}
	}

	/* Fill the normal command */
	if (buflen < sizeof (s->cmd.basic)) {
		msg_debug ("truncated normal fuzzy command of size %d received", buflen);
		return FALSE;
	}

	memcpy (&s->cmd.basic, buf, sizeof (s->cmd.basic));
	epoch = rspamd_fuzzy_command_valid (&s->cmd.basic, buflen);

	if (epoch == RSPAMD_FUZZY_EPOCH_MAX) {
		msg_debug ("invalid fuzzy command of size %d received", buflen);
		return FALSE;
	}

	s->epoch = epoch;

	/* Advance buf */
	buf += sizeof (s->cmd.basic);
	buflen -= sizeof (s->cmd.basic);

	if (s->cmd.basic.shingles_count > 0) {
		if (buflen >= sizeof (s->cmd.sgl)) {
			/* Copy the shingles part */
			memcpy (&s->cmd.sgl, buf, sizeof (s->cmd.sgl));
		}
		else {
			/* Truncated stuff */
			msg_debug ("truncated fuzzy shingles command of size %d received", buflen);
			return FALSE;
		}

		buf += sizeof (s->cmd.sgl);
		buflen -= sizeof (s->cmd.sgl);

		if (encrypted) {
			s->cmd_type = CMD_ENCRYPTED_SHINGLE;
		}
		else {
			s->cmd_type = CMD_SHINGLE;
		}
	}
	else {
		if (encrypted) {
			s->cmd_type = CMD_ENCRYPTED_NORMAL;
		}
		else {
			s->cmd_type = CMD_NORMAL;
		}
	}

	if (buflen > 0) {
		/* Process possible extensions */
		if (!rspamd_fuzzy_extensions_from_wire (s, buf, buflen)) {
			msg_debug ("truncated fuzzy shingles command of size %d received", buflen);
			return FALSE;
		}
	}

	return TRUE;
}


static void
fuzzy_session_destroy (gpointer d)
{
	struct fuzzy_session *session = d;

	rspamd_inet_address_free (session->addr);
	rspamd_explicit_memzero (session->nm, sizeof (session->nm));
	session->worker->nconns--;

	if (session->ip_stat) {
		REF_RELEASE (session->ip_stat);
	}

	if (session->extensions) {
		g_free (session->extensions);
	}

	g_free (session);
}

#define FUZZY_INPUT_BUFLEN 1024
#ifdef HAVE_RECVMMSG
#define MSGVEC_LEN 16
#else
#define MSGVEC_LEN 1
#endif

/*
 * Accept new connection and construct task
 */
static void
accept_fuzzy_socket (EV_P_ ev_io *w, int revents)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)w->data;
	struct fuzzy_session *session;
	gssize r, msg_len;
	guint64 *nerrors;
	struct iovec iovs[MSGVEC_LEN];
	guint8 bufs[MSGVEC_LEN][FUZZY_INPUT_BUFLEN];
	struct sockaddr_storage peer_sa[MSGVEC_LEN];
	socklen_t salen = sizeof (peer_sa[0]);
#ifdef HAVE_RECVMMSG
#define MSG_FIELD(msg, field) msg.msg_hdr.field
	struct mmsghdr msg[MSGVEC_LEN];
#else
#define MSG_FIELD(msg, field) msg.field
	struct msghdr msg[MSGVEC_LEN];
#endif

	memset (msg, 0, sizeof (*msg) * MSGVEC_LEN);

	/* Prepare messages to receive */
	for (int i = 0; i < MSGVEC_LEN; i ++) {
		/* Prepare msghdr structs */
		iovs[i].iov_base = bufs[i];
		iovs[i].iov_len = sizeof (bufs[i]);
		MSG_FIELD(msg[i], msg_name) = (void *)&peer_sa[i];
		MSG_FIELD(msg[i], msg_namelen) = salen;
		MSG_FIELD(msg[i], msg_iov) = &iovs[i];
		MSG_FIELD(msg[i], msg_iovlen) = 1;
	}

	/* Got some data */
	if (revents == EV_READ) {

		for (;;) {
#ifdef HAVE_RECVMMSG
			r = recvmmsg (w->fd, msg, MSGVEC_LEN, 0, NULL);
#else
			r = recvmsg (w->fd, msg, 0);
#endif

			if (r == -1) {
				if (errno == EINTR) {
					continue;
				}
				else if (errno == EAGAIN || errno == EWOULDBLOCK) {

					return;
				}

				msg_err ("got error while reading from socket: %d, %s",
						errno,
						strerror (errno));
				return;
			}

#ifndef HAVE_RECVMMSG
			msg_len = r; /* Save real length in bytes here */
			r = 1; /* Assume that we have received a single message */
#endif

			for (int i = 0; i < r; i ++) {
				rspamd_inet_addr_t *client_addr;

				client_addr = rspamd_inet_address_from_sa (MSG_FIELD(msg[i], msg_name),
						MSG_FIELD(msg[i], msg_namelen));

				if (!rspamd_fuzzy_check_client (worker->ctx, client_addr)) {
					/* Disallow forbidden clients silently */
					rspamd_inet_address_free (client_addr);
					continue;
				}

				session = g_malloc0 (sizeof (*session));
				REF_INIT_RETAIN (session, fuzzy_session_destroy);
				session->worker = worker;
				session->fd = w->fd;
				session->ctx = worker->ctx;
				session->time = (guint64) time (NULL);
				session->addr = client_addr;
				worker->nconns++;

				/* Each message can have its length in case of recvmmsg */
#ifdef HAVE_RECVMMSG
				msg_len = msg[i].msg_len;
#endif

				if (rspamd_fuzzy_cmd_from_wire (iovs[i].iov_base,
						msg_len, session)) {
					/* Check shingles count sanity */
					rspamd_fuzzy_process_command (session);
				}
				else {
					/* Discard input */
					session->ctx->stat.invalid_requests ++;
					msg_debug ("invalid fuzzy command of size %z received", r);

					nerrors = rspamd_lru_hash_lookup (session->ctx->errors_ips,
							session->addr, -1);

					if (nerrors == NULL) {
						nerrors = g_malloc (sizeof (*nerrors));
						*nerrors = 1;
						rspamd_lru_hash_insert (session->ctx->errors_ips,
								rspamd_inet_address_copy (session->addr),
								nerrors, -1, -1);
					}
					else {
						*nerrors = *nerrors + 1;
					}
				}

				REF_RELEASE (session);
			}
#ifdef HAVE_RECVMMSG
			/* Stop reading as we are using recvmmsg instead of recvmsg */
			break;
#endif
		}
	}
}

static gboolean
rspamd_fuzzy_storage_periodic_callback (void *ud)
{
	struct rspamd_fuzzy_storage_ctx *ctx = ud;

	if (ctx->updates_pending->len > 0) {
		rspamd_fuzzy_process_updates_queue (ctx, local_db_name, FALSE);

		return TRUE;
	}

	return FALSE;
}

static gboolean
rspamd_fuzzy_storage_sync (struct rspamd_main *rspamd_main,
		struct rspamd_worker *worker, gint fd,
		gint attached_fd,
		struct rspamd_control_command *cmd,
		gpointer ud)
{
	struct rspamd_fuzzy_storage_ctx *ctx = ud;
	struct rspamd_control_reply rep;

	rep.reply.fuzzy_sync.status = 0;
	rep.type = RSPAMD_CONTROL_FUZZY_SYNC;

	if (ctx->backend && worker->index == 0) {
		rspamd_fuzzy_process_updates_queue (ctx, local_db_name, FALSE);
		rspamd_fuzzy_backend_start_update (ctx->backend, ctx->sync_timeout,
				rspamd_fuzzy_storage_periodic_callback, ctx);
	}

	if (write (fd, &rep, sizeof (rep)) != sizeof (rep)) {
		msg_err ("cannot write reply to the control socket: %s",
				strerror (errno));
	}

	return TRUE;
}

static gboolean
rspamd_fuzzy_storage_reload (struct rspamd_main *rspamd_main,
		struct rspamd_worker *worker, gint fd,
		gint attached_fd,
		struct rspamd_control_command *cmd,
		gpointer ud)
{
	struct rspamd_fuzzy_storage_ctx *ctx = ud;
	GError *err = NULL;
	struct rspamd_control_reply rep;

	msg_info ("reloading fuzzy storage after receiving reload command");

	if (ctx->backend) {
		/* Close backend and reopen it one more time */
		rspamd_fuzzy_backend_close (ctx->backend);
	}

	memset (&rep, 0, sizeof (rep));
	rep.type = RSPAMD_CONTROL_RELOAD;

	if ((ctx->backend = rspamd_fuzzy_backend_create (ctx->event_loop,
			worker->cf->options, rspamd_main->cfg,
			&err)) == NULL) {
		msg_err ("cannot open backend after reload: %e", err);
		rep.reply.reload.status = err->code;
		g_error_free (err);
	}
	else {
		rep.reply.reload.status = 0;
	}

	if (ctx->backend && worker->index == 0) {
		rspamd_fuzzy_backend_start_update (ctx->backend, ctx->sync_timeout,
				rspamd_fuzzy_storage_periodic_callback, ctx);
	}

	if (write (fd, &rep, sizeof (rep)) != sizeof (rep)) {
		msg_err ("cannot write reply to the control socket: %s",
				strerror (errno));
	}

	return TRUE;
}

static ucl_object_t *
rspamd_fuzzy_storage_stat_key (struct fuzzy_key_stat *key_stat)
{
	ucl_object_t *res;

	res = ucl_object_typed_new (UCL_OBJECT);

	ucl_object_insert_key (res, ucl_object_fromint (key_stat->checked),
			"checked", 0, false);
	ucl_object_insert_key (res, ucl_object_fromint (key_stat->matched),
			"matched", 0, false);
	ucl_object_insert_key (res, ucl_object_fromint (key_stat->added),
			"added", 0, false);
	ucl_object_insert_key (res, ucl_object_fromint (key_stat->deleted),
			"deleted", 0, false);
	ucl_object_insert_key (res, ucl_object_fromint (key_stat->errors),
			"errors", 0, false);

	return res;
}

static ucl_object_t *
rspamd_fuzzy_stat_to_ucl (struct rspamd_fuzzy_storage_ctx *ctx, gboolean ip_stat)
{
	struct fuzzy_key_stat *key_stat;
	GHashTableIter it;
	struct fuzzy_key *key;
	ucl_object_t *obj, *keys_obj, *elt, *ip_elt, *ip_cur;
	gpointer k, v;
	gint i;
	gchar keyname[17];

	obj = ucl_object_typed_new (UCL_OBJECT);

	keys_obj = ucl_object_typed_new (UCL_OBJECT);
	g_hash_table_iter_init (&it, ctx->keys);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		key = v;
		key_stat = key->stat;

		if (key_stat) {
			rspamd_snprintf (keyname, sizeof (keyname), "%8bs", k);

			elt = rspamd_fuzzy_storage_stat_key (key_stat);

			if (key_stat->last_ips && ip_stat) {
				i = 0;

				ip_elt = ucl_object_typed_new (UCL_OBJECT);

				while ((i = rspamd_lru_hash_foreach (key_stat->last_ips,
						i, &k, &v)) != -1) {
					ip_cur = rspamd_fuzzy_storage_stat_key (v);
					ucl_object_insert_key (ip_elt, ip_cur,
							rspamd_inet_address_to_string (k), 0, true);
				}

				ucl_object_insert_key (elt, ip_elt, "ips", 0, false);
			}

			ucl_object_insert_key (keys_obj, elt, keyname, 0, true);
		}
	}

	ucl_object_insert_key (obj, keys_obj, "keys", 0, false);

	/* Now generic stats */
	ucl_object_insert_key (obj,
			ucl_object_fromint (ctx->stat.fuzzy_hashes),
			"fuzzy_stored",
			0,
			false);
	ucl_object_insert_key (obj,
			ucl_object_fromint (ctx->stat.fuzzy_hashes_expired),
			"fuzzy_expired",
			0,
			false);
	ucl_object_insert_key (obj,
			ucl_object_fromint (ctx->stat.invalid_requests),
			"invalid_requests",
			0,
			false);
	ucl_object_insert_key (obj,
			ucl_object_fromint (ctx->stat.delayed_hashes),
			"delayed_hashes",
			0,
			false);

	if (ctx->errors_ips && ip_stat) {
		i = 0;

		ip_elt = ucl_object_typed_new (UCL_OBJECT);

		while ((i = rspamd_lru_hash_foreach (ctx->errors_ips, i, &k, &v)) != -1) {
			ucl_object_insert_key (ip_elt,
					ucl_object_fromint (*(guint64 *)v),
					rspamd_inet_address_to_string (k), 0, true);
		}

		ucl_object_insert_key (obj,
				ip_elt,
				"errors_ips",
				0,
				false);
	}

	/* Checked by epoch */
	elt = ucl_object_typed_new (UCL_ARRAY);

	for (i = RSPAMD_FUZZY_EPOCH6; i < RSPAMD_FUZZY_EPOCH_MAX; i++) {
		ucl_array_append (elt,
				ucl_object_fromint (ctx->stat.fuzzy_hashes_checked[i]));
	}

	ucl_object_insert_key (obj, elt, "fuzzy_checked", 0, false);

	/* Shingles by epoch */
	elt = ucl_object_typed_new (UCL_ARRAY);

	for (i = RSPAMD_FUZZY_EPOCH6; i < RSPAMD_FUZZY_EPOCH_MAX; i++) {
		ucl_array_append (elt,
				ucl_object_fromint (ctx->stat.fuzzy_shingles_checked[i]));
	}

	ucl_object_insert_key (obj, elt, "fuzzy_shingles", 0, false);

	/* Matched by epoch */
	elt = ucl_object_typed_new (UCL_ARRAY);

	for (i = RSPAMD_FUZZY_EPOCH6; i < RSPAMD_FUZZY_EPOCH_MAX; i++) {
		ucl_array_append (elt,
				ucl_object_fromint (ctx->stat.fuzzy_hashes_found[i]));
	}

	ucl_object_insert_key (obj, elt, "fuzzy_found", 0, false);


	return obj;
}

static int
lua_fuzzy_add_pre_handler (lua_State *L)
{
	struct rspamd_worker *wrk, **pwrk = (struct rspamd_worker **)
			rspamd_lua_check_udata (L, 1, "rspamd{worker}");
	struct rspamd_fuzzy_storage_ctx *ctx;

	if (!pwrk) {
		return luaL_error (L, "invalid arguments, worker + function are expected");
	}

	wrk = *pwrk;

	if (wrk && lua_isfunction (L, 2)) {
		ctx = (struct rspamd_fuzzy_storage_ctx *)wrk->ctx;

		if (ctx->lua_pre_handler_cbref != -1) {
			/* Should not happen */
			luaL_unref (L, LUA_REGISTRYINDEX, ctx->lua_pre_handler_cbref);
		}

		lua_pushvalue (L, 2);
		ctx->lua_pre_handler_cbref = luaL_ref (L, LUA_REGISTRYINDEX);
	}
	else {
		return luaL_error (L, "invalid arguments, worker + function are expected");
	}

	return 0;
}

static int
lua_fuzzy_add_post_handler (lua_State *L)
{
	struct rspamd_worker *wrk, **pwrk = (struct rspamd_worker **)
			rspamd_lua_check_udata (L, 1, "rspamd{worker}");
	struct rspamd_fuzzy_storage_ctx *ctx;

	if (!pwrk) {
		return luaL_error (L, "invalid arguments, worker + function are expected");
	}

	wrk = *pwrk;

	if (wrk && lua_isfunction (L, 2)) {
		ctx = (struct rspamd_fuzzy_storage_ctx *)wrk->ctx;

		if (ctx->lua_post_handler_cbref != -1) {
			/* Should not happen */
			luaL_unref (L, LUA_REGISTRYINDEX, ctx->lua_post_handler_cbref);
		}

		lua_pushvalue (L, 2);
		ctx->lua_post_handler_cbref = luaL_ref (L, LUA_REGISTRYINDEX);
	}
	else {
		return luaL_error (L, "invalid arguments, worker + function are expected");
	}

	return 0;
}

static gboolean
rspamd_fuzzy_storage_stat (struct rspamd_main *rspamd_main,
		struct rspamd_worker *worker, gint fd,
		gint attached_fd,
		struct rspamd_control_command *cmd,
		gpointer ud)
{
	struct rspamd_fuzzy_storage_ctx *ctx = ud;
	struct rspamd_control_reply rep;
	ucl_object_t *obj;
	struct ucl_emitter_functions *emit_subr;
	guchar fdspace[CMSG_SPACE(sizeof (int))];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;

	gint outfd = -1;
	gchar tmppath[PATH_MAX];

	memset (&rep, 0, sizeof (rep));
	rep.type = RSPAMD_CONTROL_FUZZY_STAT;

	rspamd_snprintf (tmppath, sizeof (tmppath), "%s%c%s-XXXXXXXXXX",
			rspamd_main->cfg->temp_dir, G_DIR_SEPARATOR, "fuzzy-stat");

	if ((outfd = mkstemp (tmppath)) == -1) {
		rep.reply.fuzzy_stat.status = errno;
		msg_info_main ("cannot make temporary stat file for fuzzy stat: %s",
			strerror (errno));
	}
	else {
		rep.reply.fuzzy_stat.status = 0;

		memcpy (rep.reply.fuzzy_stat.storage_id,
				rspamd_fuzzy_backend_id (ctx->backend),
				sizeof (rep.reply.fuzzy_stat.storage_id));

		obj = rspamd_fuzzy_stat_to_ucl (ctx, TRUE);
		emit_subr = ucl_object_emit_fd_funcs (outfd);
		ucl_object_emit_full (obj, UCL_EMIT_JSON_COMPACT, emit_subr, NULL);
		ucl_object_emit_funcs_free (emit_subr);
		ucl_object_unref (obj);
		/* Rewind output file */
		close (outfd);
		outfd = open (tmppath, O_RDONLY);
		unlink (tmppath);
	}

	/* Now we can send outfd and status message */
	memset (&msg, 0, sizeof (msg));

	/* Attach fd to the message */
	if (outfd != -1) {
		memset (fdspace, 0, sizeof (fdspace));
		msg.msg_control = fdspace;
		msg.msg_controllen = sizeof (fdspace);
		cmsg = CMSG_FIRSTHDR (&msg);

		if (cmsg) {
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SCM_RIGHTS;
			cmsg->cmsg_len = CMSG_LEN (sizeof (int));
			memcpy (CMSG_DATA (cmsg), &outfd, sizeof (int));
		}
	}

	iov.iov_base = &rep;
	iov.iov_len = sizeof (rep);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg (fd, &msg, 0) == -1) {
		msg_err_main ("cannot send fuzzy stat: %s", strerror (errno));
	}

	if (outfd != -1) {
		close (outfd);
	}

	return TRUE;
}

static gboolean
fuzzy_parse_keypair (rspamd_mempool_t *pool,
		const ucl_object_t *obj,
		gpointer ud,
		struct rspamd_rcl_section *section,
		GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	struct rspamd_fuzzy_storage_ctx *ctx;
	struct rspamd_cryptobox_keypair *kp;
	struct fuzzy_key_stat *keystat;
	struct fuzzy_key *key;
	const ucl_object_t *cur;
	const guchar *pk;
	ucl_object_iter_t it = NULL;
	gboolean ret;

	ctx = pd->user_struct;
	pd->offset = G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, default_keypair);

	/*
	 * Single key
	 */
	if (ucl_object_type (obj) == UCL_STRING || ucl_object_type (obj)
			== UCL_OBJECT) {
		ret = rspamd_rcl_parse_struct_keypair (pool, obj, pd, section, err);

		if (!ret) {
			return ret;
		}

		/* Insert key to the hash table */
		kp = ctx->default_keypair;

		if (kp == NULL) {
			return FALSE;
		}

		if (rspamd_keypair_alg (kp) != RSPAMD_CRYPTOBOX_MODE_25519 ||
				rspamd_keypair_type (kp) != RSPAMD_KEYPAIR_KEX) {
			return FALSE;
		}

		key = g_malloc0 (sizeof (*key));
		key->key = kp;
		keystat = g_malloc0 (sizeof (*keystat));
		REF_INIT_RETAIN (keystat, fuzzy_key_stat_dtor);
		/* Hash of ip -> fuzzy_key_stat */
		keystat->last_ips = rspamd_lru_hash_new_full (1024,
				(GDestroyNotify) rspamd_inet_address_free,
				fuzzy_key_stat_unref,
				rspamd_inet_address_hash, rspamd_inet_address_equal);
		key->stat = keystat;
		pk = rspamd_keypair_component (kp, RSPAMD_KEYPAIR_COMPONENT_PK,
				NULL);
		g_hash_table_insert (ctx->keys, (gpointer)pk, key);
		ctx->default_key = key;
		msg_info_pool ("loaded keypair %*xs", 8, pk);
	}
	else if (ucl_object_type (obj) == UCL_ARRAY) {
		while ((cur = ucl_object_iterate (obj, &it, true)) != NULL) {
			if (!fuzzy_parse_keypair (pool, cur, pd, section, err)) {
				msg_err_pool ("cannot parse keypair");
			}
		}
	}

	return TRUE;
}

static guint
fuzzy_kp_hash (gconstpointer p)
{
	return *(guint *)p;
}

static gboolean
fuzzy_kp_equal (gconstpointer a, gconstpointer b)
{
	const guchar *pa = a, *pb = b;

	return (memcmp (pa, pb, RSPAMD_FUZZY_KEYLEN) == 0);
}

gpointer
init_fuzzy (struct rspamd_config *cfg)
{
	struct rspamd_fuzzy_storage_ctx *ctx;
	GQuark type;

	type = g_quark_try_string ("fuzzy");

	ctx = rspamd_mempool_alloc0 (cfg->cfg_pool,
			sizeof (struct rspamd_fuzzy_storage_ctx));

	ctx->magic = rspamd_fuzzy_storage_magic;
	ctx->sync_timeout = DEFAULT_SYNC_TIMEOUT;
	ctx->keypair_cache_size = DEFAULT_KEYPAIR_CACHE_SIZE;
	ctx->lua_pre_handler_cbref = -1;
	ctx->lua_post_handler_cbref = -1;
	ctx->keys = g_hash_table_new_full (fuzzy_kp_hash, fuzzy_kp_equal,
			NULL, fuzzy_key_dtor);
	rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)g_hash_table_unref, ctx->keys);
	ctx->errors_ips = rspamd_lru_hash_new_full (1024,
			(GDestroyNotify) rspamd_inet_address_free, g_free,
			rspamd_inet_address_hash, rspamd_inet_address_equal);
	rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)rspamd_lru_hash_destroy, ctx->errors_ips);
	ctx->cfg = cfg;
	ctx->updates_maxfail = DEFAULT_UPDATES_MAXFAIL;
	ctx->leaky_bucket_mask = DEFAULT_BUCKET_MASK;
	ctx->leaky_bucket_ttl = DEFAULT_BUCKET_TTL;
	ctx->max_buckets = DEFAULT_MAX_BUCKETS;
	ctx->leaky_bucket_burst = NAN;
	ctx->leaky_bucket_rate = NAN;
	ctx->delay = NAN;

	rspamd_rcl_register_worker_option (cfg,
			type,
			"sync",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx,
						sync_timeout),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"Time to perform database sync, default: "
			G_STRINGIFY (DEFAULT_SYNC_TIMEOUT) " seconds");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"expire",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx,
						expire),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"Default expire time for hashes, default: "
			G_STRINGIFY (DEFAULT_EXPIRE) " seconds");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"delay",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx,
					delay),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"Default delay time for hashes, default: not enabled");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"allow_update",
			rspamd_rcl_parse_struct_ucl,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, update_map),
			0,
			"Allow modifications from the following IP addresses");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"delay_whitelist",
			rspamd_rcl_parse_struct_ucl,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, delay_whitelist_map),
			0,
			"Disable delay check for the following IP addresses");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"keypair",
			fuzzy_parse_keypair,
			ctx,
			0,
			RSPAMD_CL_FLAG_MULTIPLE,
			"Encryption keypair (can be repeated for different keys)");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"keypair_cache_size",
			rspamd_rcl_parse_struct_integer,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx,
						keypair_cache_size),
			RSPAMD_CL_FLAG_UINT,
			"Size of keypairs cache, default: "
					G_STRINGIFY (DEFAULT_KEYPAIR_CACHE_SIZE));

	rspamd_rcl_register_worker_option (cfg,
			type,
			"encrypted_only",
			rspamd_rcl_parse_struct_boolean,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, encrypted_only),
			0,
			"Allow encrypted requests only (and forbid all unknown keys or plaintext requests)");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"dedicated_update_worker",
			rspamd_rcl_parse_struct_boolean,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, dedicated_update_worker),
			0,
			"Use worker 0 for updates only");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"read_only",
			rspamd_rcl_parse_struct_boolean,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, read_only),
			0,
			"Work in read only mode");


	rspamd_rcl_register_worker_option (cfg,
			type,
			"blocked",
			rspamd_rcl_parse_struct_ucl,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, blocked_map),
			0,
			"Block requests from specific networks");


	rspamd_rcl_register_worker_option (cfg,
			type,
			"updates_maxfail",
			rspamd_rcl_parse_struct_integer,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, updates_maxfail),
			RSPAMD_CL_FLAG_UINT,
			"Maximum number of updates to be failed before discarding");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"skip_hashes",
			rspamd_rcl_parse_struct_ucl,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, skip_map),
			0,
			"Skip specific hashes from the map");

	/* Ratelimits */
	rspamd_rcl_register_worker_option (cfg,
			type,
			"ratelimit_whitelist",
			rspamd_rcl_parse_struct_ucl,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, ratelimit_whitelist_map),
			0,
			"Skip specific addresses from rate limiting");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"ratelimit_max_buckets",
			rspamd_rcl_parse_struct_integer,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, max_buckets),
			RSPAMD_CL_FLAG_UINT,
			"Maximum number of leaky buckets (default: " G_STRINGIFY(DEFAULT_MAX_BUCKETS) ")");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"ratelimit_network_mask",
			rspamd_rcl_parse_struct_integer,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, leaky_bucket_mask),
			RSPAMD_CL_FLAG_UINT,
			"Network mask to apply for IPv4 rate addresses (default: " G_STRINGIFY(DEFAULT_BUCKET_MASK) ")");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"ratelimit_bucket_ttl",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, leaky_bucket_ttl),
			RSPAMD_CL_FLAG_TIME_INTEGER,
			"Time to live for ratelimit element (default: " G_STRINGIFY(DEFAULT_BUCKET_TTL) ")");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"ratelimit_rate",
			rspamd_rcl_parse_struct_double,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, leaky_bucket_rate),
			0,
			"Leak rate in requests per second");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"ratelimit_burst",
			rspamd_rcl_parse_struct_double,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, leaky_bucket_burst),
			0,
			"Peak value for ratelimit bucket");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"ratelimit_log_only",
			rspamd_rcl_parse_struct_boolean,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, ratelimit_log_only),
			0,
			"Don't really ban on ratelimit reaching, just log");


	return ctx;
}

static void
rspamd_fuzzy_peer_io (EV_P_ ev_io *w, int revents)
{
	struct fuzzy_peer_cmd cmd;
	struct rspamd_fuzzy_storage_ctx *ctx =
			(struct rspamd_fuzzy_storage_ctx *)w->data;
	gssize r;

	for (;;) {
		r = read (w->fd, &cmd, sizeof (cmd));

		if (r != sizeof (cmd)) {
			if (errno == EINTR) {
				continue;
			}
			if (errno != EAGAIN) {
				msg_err ("cannot read command from peers: %s", strerror (errno));
			}

			break;
		}
		else {
			g_array_append_val (ctx->updates_pending, cmd);
		}
	}
}

static void
fuzzy_peer_rep (struct rspamd_worker *worker,
		struct rspamd_srv_reply *rep, gint rep_fd,
		gpointer ud)
{
	struct rspamd_fuzzy_storage_ctx *ctx = ud;
	GList *cur;
	struct rspamd_worker_listen_socket *ls;
	struct rspamd_worker_accept_event *ac_ev;

	ctx->peer_fd = rep_fd;

	if (rep_fd == -1) {
		msg_err ("cannot receive peer fd from the main process");
		exit (EXIT_FAILURE);
	}
	else {
		rspamd_socket_nonblocking (rep_fd);
	}

	msg_info ("got peer fd reply from the main process");

	/* Start listening */
	cur = worker->cf->listen_socks;
	while (cur) {
		ls = cur->data;

		if (ls->fd != -1) {
			msg_info ("start listening on %s",
					rspamd_inet_address_to_string_pretty (ls->addr));

			if (ls->type == RSPAMD_WORKER_SOCKET_UDP) {
				ac_ev = g_malloc0 (sizeof (*ac_ev));
				ac_ev->accept_ev.data = worker;
				ac_ev->event_loop = ctx->event_loop;
				ev_io_init (&ac_ev->accept_ev, accept_fuzzy_socket, ls->fd,
						EV_READ);
				ev_io_start (ctx->event_loop, &ac_ev->accept_ev);
				DL_APPEND (worker->accept_events, ac_ev);
			}
			else  {
				/* We allow TCP listeners only for a update worker */
				g_assert_not_reached ();
			}
		}

		cur = g_list_next (cur);
	}

	if (ctx->peer_fd != -1) {
		if (worker->index == 0) {
			/* Listen for peer requests */
			shutdown (ctx->peer_fd, SHUT_WR);
			ctx->peer_ev.data = ctx;
			ev_io_init (&ctx->peer_ev, rspamd_fuzzy_peer_io, ctx->peer_fd, EV_READ);
			ev_io_start (ctx->event_loop, &ctx->peer_ev);
		}
		else {
			shutdown (ctx->peer_fd, SHUT_RD);
		}
	}
}

/*
 * Start worker process
 */
__attribute__((noreturn))
void
start_fuzzy (struct rspamd_worker *worker)
{
	struct rspamd_fuzzy_storage_ctx *ctx = worker->ctx;
	GError *err = NULL;
	struct rspamd_srv_command srv_cmd;
	struct rspamd_config *cfg = worker->srv->cfg;

	g_assert (rspamd_worker_check_context (worker->ctx, rspamd_fuzzy_storage_magic));
	ctx->event_loop = rspamd_prepare_worker (worker,
			"fuzzy",
			NULL);
	ctx->peer_fd = -1;
	ctx->worker = worker;
	ctx->cfg = worker->srv->cfg;
	ctx->resolver = rspamd_dns_resolver_init (worker->srv->logger,
			ctx->event_loop,
			worker->srv->cfg);
	rspamd_upstreams_library_config (worker->srv->cfg, ctx->cfg->ups_ctx,
			ctx->event_loop, ctx->resolver->r);
	/* Since this worker uses maps it needs a valid HTTP context */
	ctx->http_ctx = rspamd_http_context_create (ctx->cfg, ctx->event_loop,
			ctx->cfg->ups_ctx);

	if (ctx->keypair_cache_size > 0) {
		/* Create keypairs cache */
		ctx->keypair_cache = rspamd_keypair_cache_new (ctx->keypair_cache_size);
	}


	if ((ctx->backend = rspamd_fuzzy_backend_create (ctx->event_loop,
			worker->cf->options, cfg, &err)) == NULL) {
		msg_err ("cannot open backend: %e", err);
		if (err) {
			g_error_free (err);
		}
		exit (EXIT_SUCCESS);
	}

	rspamd_fuzzy_backend_count (ctx->backend, fuzzy_count_callback, ctx);


	if (worker->index == 0) {
		ctx->updates_pending = g_array_sized_new (FALSE, FALSE,
				sizeof (struct fuzzy_peer_cmd), 1024);
		rspamd_fuzzy_backend_start_update (ctx->backend, ctx->sync_timeout,
				rspamd_fuzzy_storage_periodic_callback, ctx);

		if (ctx->dedicated_update_worker && worker->cf->count > 1) {
			msg_info_config ("stop serving clients request in dedicated update mode");
			rspamd_worker_stop_accept (worker);

			GList *cur = worker->cf->listen_socks;

			while (cur) {
				struct rspamd_worker_listen_socket *ls =
						(struct rspamd_worker_listen_socket *)cur->data;

				if (ls->fd != -1) {
					close (ls->fd);
				}

				cur = g_list_next (cur);
			}
		}
	}

	ctx->stat_ev.data = ctx;
	ev_timer_init (&ctx->stat_ev, rspamd_fuzzy_stat_callback, ctx->sync_timeout,
			ctx->sync_timeout);
	ev_timer_start (ctx->event_loop, &ctx->stat_ev);
	/* Register custom reload and stat commands for the control socket */
	rspamd_control_worker_add_cmd_handler (worker, RSPAMD_CONTROL_RELOAD,
			rspamd_fuzzy_storage_reload, ctx);
	rspamd_control_worker_add_cmd_handler (worker, RSPAMD_CONTROL_FUZZY_STAT,
			rspamd_fuzzy_storage_stat, ctx);
	rspamd_control_worker_add_cmd_handler (worker, RSPAMD_CONTROL_FUZZY_SYNC,
			rspamd_fuzzy_storage_sync, ctx);

	/* Create radix trees */
	if (ctx->update_map != NULL) {
		rspamd_config_radix_from_ucl (worker->srv->cfg, ctx->update_map,
				"Allow fuzzy updates from specified addresses",
				&ctx->update_ips, NULL, worker, "fuzzy update");
	}

	if (ctx->skip_map != NULL) {
		struct rspamd_map *m;

		if ((m = rspamd_map_add_from_ucl (cfg, ctx->skip_map,
				"Skip hashes",
				rspamd_kv_list_read,
				rspamd_kv_list_fin,
				rspamd_kv_list_dtor,
				(void **)&ctx->skip_hashes,
				worker, RSPAMD_MAP_DEFAULT)) == NULL) {
			msg_warn_config ("cannot load hashes list from %s",
					ucl_object_tostring (ctx->skip_map));
		}
		else {
			m->active_http = TRUE;
		}
	}

	if (ctx->blocked_map != NULL) {
		rspamd_config_radix_from_ucl (worker->srv->cfg, ctx->blocked_map,
				"Block fuzzy requests from the specific IPs",
				&ctx->blocked_ips,
				NULL,
				worker, "fuzzy blocked");
	}

	/* Create radix trees */
	if (ctx->ratelimit_whitelist_map != NULL) {
		rspamd_config_radix_from_ucl (worker->srv->cfg, ctx->ratelimit_whitelist_map,
				"Skip ratelimits from specific ip addresses/networks",
				&ctx->ratelimit_whitelist,
				NULL,
				worker, "fuzzy ratelimit whitelist");
	}

	if (!isnan (ctx->delay) && ctx->delay_whitelist_map != NULL) {
		rspamd_config_radix_from_ucl (worker->srv->cfg, ctx->delay_whitelist_map,
				"Skip delay from the following ips",
				&ctx->delay_whitelist, NULL, worker,
				"fuzzy delayed whitelist");
	}

	/* Ratelimits */
	if (!isnan (ctx->leaky_bucket_rate) && !isnan (ctx->leaky_bucket_burst)) {
		ctx->ratelimit_buckets = rspamd_lru_hash_new_full (ctx->max_buckets,
				NULL, fuzzy_rl_bucket_free,
				rspamd_inet_address_hash, rspamd_inet_address_equal);
	}

	/* Maps events */
	ctx->resolver = rspamd_dns_resolver_init (worker->srv->logger,
			ctx->event_loop,
			worker->srv->cfg);
	rspamd_map_watch (worker->srv->cfg, ctx->event_loop,
			ctx->resolver, worker, RSPAMD_MAP_WATCH_WORKER);

	/* Get peer pipe */
	memset (&srv_cmd, 0, sizeof (srv_cmd));
	srv_cmd.type = RSPAMD_SRV_SOCKETPAIR;
	srv_cmd.cmd.spair.af = SOCK_DGRAM;
	srv_cmd.cmd.spair.pair_num = worker->index;
	memset (srv_cmd.cmd.spair.pair_id, 0, sizeof (srv_cmd.cmd.spair.pair_id));
	/* 6 bytes of id (including \0) and bind_conf id */
	G_STATIC_ASSERT (sizeof (srv_cmd.cmd.spair.pair_id) >=
								sizeof ("fuzzy") + sizeof (guint64));

	memcpy (srv_cmd.cmd.spair.pair_id, "fuzzy", sizeof ("fuzzy"));

	/* Distinguish workers from each others... */
	if (worker->cf->bind_conf && worker->cf->bind_conf->bind_line) {
		guint64 bind_hash = rspamd_cryptobox_fast_hash (worker->cf->bind_conf->bind_line,
				strlen (worker->cf->bind_conf->bind_line), 0xdeadbabe);

		/* 8 more bytes */
		memcpy (srv_cmd.cmd.spair.pair_id + sizeof ("fuzzy"), &bind_hash,
				sizeof (bind_hash));
	}

	rspamd_srv_send_command (worker, ctx->event_loop, &srv_cmd, -1,
			fuzzy_peer_rep, ctx);

	luaL_Reg fuzzy_lua_reg = {
			.name = "add_fuzzy_pre_handler",
			.func = lua_fuzzy_add_pre_handler,
	};
	rspamd_lua_add_metamethod (ctx->cfg->lua_state, "rspamd{worker}", &fuzzy_lua_reg);
	fuzzy_lua_reg = (luaL_Reg){
			.name = "add_fuzzy_post_handler",
			.func = lua_fuzzy_add_post_handler,
	};
	rspamd_lua_add_metamethod (ctx->cfg->lua_state, "rspamd{worker}", &fuzzy_lua_reg);

	rspamd_lua_run_postloads (ctx->cfg->lua_state, ctx->cfg, ctx->event_loop,
			worker);

	ev_loop (ctx->event_loop, 0);
	rspamd_worker_block_signals ();

	if (ctx->peer_fd != -1) {
		if (worker->index == 0) {
			ev_io_stop (ctx->event_loop, &ctx->peer_ev);
		}
		close (ctx->peer_fd);
	}

	if (worker->index == 0 && ctx->updates_pending->len > 0) {

		msg_info_config ("start another event loop to sync fuzzy storage");

		if (rspamd_fuzzy_process_updates_queue (ctx, local_db_name, TRUE)) {
			ev_loop (ctx->event_loop, 0);
			msg_info_config ("sync cycle is done");
		}
		else {
			msg_info_config ("no need to sync");
		}
	}

	rspamd_fuzzy_backend_close (ctx->backend);

	if (worker->index == 0) {
		g_array_free (ctx->updates_pending, TRUE);
	}

	if (ctx->keypair_cache) {
		rspamd_keypair_cache_destroy (ctx->keypair_cache);
	}

	if (ctx->ratelimit_buckets) {
		rspamd_lru_hash_destroy (ctx->ratelimit_buckets);
	}

	if (ctx->lua_pre_handler_cbref != -1) {
		luaL_unref (ctx->cfg->lua_state, LUA_REGISTRYINDEX, ctx->lua_pre_handler_cbref);
	}

	if (ctx->lua_post_handler_cbref != -1) {
		luaL_unref (ctx->cfg->lua_state, LUA_REGISTRYINDEX, ctx->lua_post_handler_cbref);
	}

	REF_RELEASE (ctx->cfg);
	rspamd_log_close (worker->srv->logger);

	exit (EXIT_SUCCESS);
}
