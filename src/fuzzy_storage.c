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
 * Rspamd fuzzy storage server
 */

#include "config.h"
#include "util.h"
#include "rspamd.h"
#include "map.h"
#include "fuzzy_storage.h"
#include "fuzzy_backend.h"
#include "ottery.h"
#include "libserver/worker_util.h"
#include "libserver/rspamd_control.h"
#include "cryptobox.h"
#include "keypairs_cache.h"
#include "keypair_private.h"
#include "ref.h"
#include "xxhash.h"
#include "libutil/hash.h"

/* This number is used as expire time in seconds for cache items  (2 days) */
#define DEFAULT_EXPIRE 172800L
/* Resync value in seconds */
#define DEFAULT_SYNC_TIMEOUT 60.0
#define DEFAULT_KEYPAIR_CACHE_SIZE 512


#define INVALID_NODE_TIME (guint64) - 1

/* Init functions */
gpointer init_fuzzy (struct rspamd_config *cfg);
void start_fuzzy (struct rspamd_worker *worker);

worker_t fuzzy_worker = {
	"fuzzy",                    /* Name */
	init_fuzzy,                 /* Init function */
	start_fuzzy,                /* Start function */
	TRUE,                       /* No socket */
	FALSE,                      /* Unique */
	FALSE,                      /* Threaded */
	FALSE,                      /* Non killable */
	SOCK_DGRAM                  /* UDP socket */
};

/* For evtimer */
static struct timeval tmv;
static struct event tev;
static struct rspamd_stat *server_stat;

struct rspamd_fuzzy_storage_ctx {
	char *hashfile;
	gdouble expire;
	gdouble sync_timeout;
	radix_compressed_t *update_ips;
	gchar *update_map;
	guint keypair_cache_size;
	struct event_base *ev_base;
	gint peer_fd;
	struct event peer_ev;
	/* Local keypair */
	gpointer default_key;
	GHashTable *keys;
	GHashTable *keys_stats;
	gboolean encrypted_only;
	struct rspamd_keypair_cache *keypair_cache;
	struct rspamd_fuzzy_backend *backend;
	GQueue *updates_pending;
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

	union {
		struct rspamd_fuzzy_encrypted_shingle_cmd enc_shingle;
		struct rspamd_fuzzy_encrypted_cmd enc_normal;
		struct rspamd_fuzzy_cmd normal;
		struct rspamd_fuzzy_shingle_cmd shingle;
	} cmd;

	struct rspamd_fuzzy_encrypted_reply reply;

	enum rspamd_fuzzy_epoch epoch;
	enum fuzzy_cmd_type cmd_type;
	gint fd;
	guint64 time;
	struct event io;
	ref_entry_t ref;
	struct fuzzy_key_stat *key_stat;
	guchar nm[rspamd_cryptobox_MAX_NMBYTES];
};

struct fuzzy_peer_cmd {
	union {
		struct rspamd_fuzzy_cmd normal;
		struct rspamd_fuzzy_shingle_cmd shingle;
	} cmd;
};

struct fuzzy_peer_request {
	struct event io_ev;
	struct fuzzy_peer_cmd cmd;
};

struct fuzzy_key_stat {
	guint64 checked;
	guint64 matched;
	guint64 added;
	guint64 deleted;
	guint64 errors;
	rspamd_lru_hash_t *last_ips;
};

static void rspamd_fuzzy_write_reply (struct fuzzy_session *session);

static gboolean
rspamd_fuzzy_check_client (struct fuzzy_session *session)
{
	if (session->ctx->update_ips != NULL) {
		if (radix_find_compressed_addr (session->ctx->update_ips,
				session->addr) == RADIX_NO_VALUE) {
			return FALSE;
		}
	}
	return TRUE;
}

static void
fuzzy_key_stat_dtor (gpointer p)
{
	struct fuzzy_key_stat *st = p;

	if (st->last_ips) {
		rspamd_lru_hash_destroy (st->last_ips);
	}

	g_slice_free1 (sizeof (*st), st);
}

static void
rspamd_fuzzy_process_updates_queue (struct rspamd_fuzzy_storage_ctx *ctx)
{
	GList *cur;
	struct fuzzy_peer_cmd *cmd;
	guint nupdates = 0;

	if (rspamd_fuzzy_backend_prepare_update (ctx->backend)) {
		cur = ctx->updates_pending->head;
		while (cur) {
			cmd = cur->data;

			if (cmd->cmd.normal.cmd == FUZZY_WRITE) {
				rspamd_fuzzy_backend_add (ctx->backend, &cmd->cmd.normal);
			}
			else {
				rspamd_fuzzy_backend_del (ctx->backend, &cmd->cmd.normal);
			}

			nupdates++;
			cur = g_list_next (cur);
		}

		if (rspamd_fuzzy_backend_finish_update (ctx->backend)) {
			server_stat->fuzzy_hashes = rspamd_fuzzy_backend_count (ctx->backend);
			cur = ctx->updates_pending->head;

			while (cur) {
				cmd = cur->data;
				g_slice_free1 (sizeof (*cmd), cmd);
				cur = g_list_next (cur);
			}

			g_queue_clear (ctx->updates_pending);
			msg_info ("updated fuzzy storage: %ud updates processed", nupdates);
		}
		else {
			msg_err ("cannot commit update transaction to fuzzy backend, "
					"%ud updates are still pending",
					g_queue_get_length (ctx->updates_pending));
		}
	}
	else {
		msg_err ("cannot start transaction in fuzzy backend, "
				"%ud updates are still pending",
				g_queue_get_length (ctx->updates_pending));
	}
}

static void
rspamd_fuzzy_reply_io (gint fd, gshort what, gpointer d)
{
	struct fuzzy_session *session = d;

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
		len = sizeof (session->reply);
	}
	else {
		data = &session->reply.rep;
		len = sizeof (session->reply.rep);
	}

	r = rspamd_inet_address_sendto (session->fd, data, len, 0,
			session->addr);

	if (r == -1) {
		if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
			/* Grab reference to avoid early destruction */
			REF_RETAIN (session);
			event_set (&session->io, session->fd, EV_WRITE,
					rspamd_fuzzy_reply_io, session);
			event_base_set (session->ctx->ev_base, &session->io);
			event_add (&session->io, NULL);
		}
		else {
			msg_err ("error while writing reply: %s", strerror (errno));
		}
	}
}

static void
fuzzy_peer_send_io (gint fd, gshort what, gpointer d)
{
	struct fuzzy_peer_request *up_req = d;
	gssize r;

	r = write (fd, &up_req->cmd, sizeof (up_req->cmd));

	if (r != sizeof (up_req->cmd)) {
		msg_err ("cannot send update request to the peer: %s", strerror (errno));
	}

	event_del (&up_req->io_ev);
	g_slice_free1 (sizeof (*up_req), up_req);
}

static void
rspamd_fuzzy_update_stats (enum rspamd_fuzzy_epoch epoch, gboolean matched,
		struct fuzzy_key_stat *key_stat, struct fuzzy_key_stat *ip_stat,
		guint cmd, guint reply)
{
#ifndef HAVE_ATOMIC_BUILTINS
	server_stat->fuzzy_hashes_checked[epoch] ++;

	if (matched) {
		server_stat->fuzzy_hashes_found[epoch] ++;
	}
#else
	__atomic_add_fetch (&server_stat->fuzzy_hashes_checked[epoch],
			1, __ATOMIC_RELEASE);

	if (matched) {
		__atomic_add_fetch (&server_stat->fuzzy_hashes_found[epoch],
				1, __ATOMIC_RELEASE);
	}
#endif

	if (key_stat) {
		if (reply != 0) {
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
		if (reply != 0) {
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

static void
rspamd_fuzzy_process_command (struct fuzzy_session *session)
{
	gboolean encrypted = FALSE;
	struct rspamd_fuzzy_cmd *cmd;
	struct rspamd_fuzzy_reply result;
	struct fuzzy_peer_cmd *up_cmd;
	struct fuzzy_peer_request *up_req;
	struct fuzzy_key_stat *ip_stat = NULL;
	rspamd_inet_addr_t *naddr;
	gsize up_len;

	switch (session->cmd_type) {
	case CMD_NORMAL:
		cmd = &session->cmd.normal;
		up_len = sizeof (session->cmd.normal);
		break;
	case CMD_SHINGLE:
		cmd = &session->cmd.shingle.basic;
		up_len = sizeof (session->cmd.shingle);
		break;
	case CMD_ENCRYPTED_NORMAL:
		cmd = &session->cmd.enc_normal.cmd;
		up_len = sizeof (session->cmd.normal);
		encrypted = TRUE;
		break;
	case CMD_ENCRYPTED_SHINGLE:
		cmd = &session->cmd.enc_shingle.cmd.basic;
		up_len = sizeof (session->cmd.shingle);
		encrypted = TRUE;
		break;
	}

	if (session->ctx->encrypted_only && !encrypted) {
		/* Do not accept unencrypted commands */
		result.value = 403;
		result.prob = 0.0;
		goto reply;
	}

	if (session->key_stat) {
		ip_stat = rspamd_lru_hash_lookup (session->key_stat->last_ips,
				session->addr, -1);

		if (ip_stat == NULL) {
			naddr = rspamd_inet_address_copy (session->addr);
			ip_stat = g_slice_alloc0 (sizeof (*ip_stat));
			rspamd_lru_hash_insert (session->key_stat->last_ips,
					naddr, ip_stat, -1, 0);
		}
	}

	if (cmd->cmd == FUZZY_CHECK) {
		result = rspamd_fuzzy_backend_check (session->ctx->backend, cmd,
				session->ctx->expire);
	}
	else {
		result.flag = cmd->flag;
		if (rspamd_fuzzy_check_client (session)) {

			if (session->worker->index == 0 || session->ctx->peer_fd == -1) {
				/* Just add to the queue */
				up_cmd = g_slice_alloc (sizeof (*up_cmd));
				memcpy (up_cmd, cmd, up_len);
				g_queue_push_tail (session->ctx->updates_pending, up_cmd);
			}
			else {
				/* We need to send request to the peer */
				up_req = g_slice_alloc (sizeof (*up_req));
				memcpy (&up_req->cmd, cmd, up_len);
				event_set (&up_req->io_ev, session->ctx->peer_fd, EV_WRITE,
						fuzzy_peer_send_io, up_req);
				event_base_set (session->ctx->ev_base, &up_req->io_ev);
				event_add (&up_req->io_ev, NULL);
			}

			result.value = 0;
			result.prob = 1.0;
		}
		else {
			result.value = 403;
			result.prob = 0.0;
		}
	}

reply:
	result.tag = cmd->tag;
	memcpy (&session->reply.rep, &result, sizeof (result));

	rspamd_fuzzy_update_stats (session->epoch, result.prob > 0.5,
			session->key_stat, ip_stat, cmd->cmd, result.value);

	if (encrypted) {
		/* We need also to encrypt reply */
		ottery_rand_bytes (session->reply.hdr.nonce,
				sizeof (session->reply.hdr.nonce));
		rspamd_cryptobox_encrypt_nm_inplace ((guchar *)&session->reply.rep,
				sizeof (session->reply.rep),
				session->reply.hdr.nonce,
				session->nm,
				session->reply.hdr.mac);
	}

	rspamd_fuzzy_write_reply (session);
}


static enum rspamd_fuzzy_epoch
rspamd_fuzzy_command_valid (struct rspamd_fuzzy_cmd *cmd, gint r)
{
	enum rspamd_fuzzy_epoch ret = RSPAMD_FUZZY_EPOCH_MAX;

	if (cmd->version == RSPAMD_FUZZY_VERSION) {
		if (cmd->shingles_count > 0) {
			if (r == sizeof (struct rspamd_fuzzy_shingle_cmd)) {
				ret = RSPAMD_FUZZY_EPOCH9;
			}
		}
		else {
			if (r == sizeof (*cmd)) {
				ret = RSPAMD_FUZZY_EPOCH9;
			}
		}
	}
	else if (cmd->version == 2) {
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
	}

	return ret;
}

static gboolean
rspamd_fuzzy_decrypt_command (struct fuzzy_session *s)
{
	struct rspamd_fuzzy_encrypted_req_hdr *hdr;
	guchar *payload;
	gsize payload_len;
	struct rspamd_http_keypair rk, *lk;

	if (s->ctx->default_key == NULL) {
		msg_warn ("received encrypted request when encryption is not enabled");
		return FALSE;
	}

	if (s->cmd_type == CMD_ENCRYPTED_NORMAL) {
		hdr = &s->cmd.enc_normal.hdr;
		payload = (guchar *)&s->cmd.enc_normal.cmd;
		payload_len = sizeof (s->cmd.enc_normal.cmd);
	}
	else {
		hdr = &s->cmd.enc_shingle.hdr;
		payload = (guchar *) &s->cmd.enc_shingle.cmd;
		payload_len = sizeof (s->cmd.enc_shingle.cmd);
	}

	/* Compare magic */
	if (memcmp (hdr->magic, fuzzy_encrypted_magic, sizeof (hdr->magic)) != 0) {
		msg_debug ("invalid magic for the encrypted packet");
		return FALSE;
	}

	/* Try to find the desired key */
	lk = g_hash_table_lookup (s->ctx->keys, hdr->key_id);
	s->key_stat = g_hash_table_lookup (s->ctx->keys_stats, hdr->key_id);

	if (lk == NULL) {
		/* Unknown key, assume default one */
		lk = s->ctx->default_key;
	}

	/* Now process keypair */
	memcpy (rk.pk, hdr->pubkey, sizeof (rk.pk));
	rspamd_keypair_cache_process (s->ctx->keypair_cache, lk, &rk);

	/* Now decrypt request */
	if (!rspamd_cryptobox_decrypt_nm_inplace (payload, payload_len, hdr->nonce,
				rk.nm, hdr->mac)) {
		msg_debug ("decryption failed");
		rspamd_explicit_memzero (rk.nm, sizeof (rk.nm));
		return FALSE;
	}

	memcpy (s->nm, rk.nm, sizeof (s->nm));
	rspamd_explicit_memzero (rk.nm, sizeof (rk.nm));

	return TRUE;
}

static gboolean
rspamd_fuzzy_cmd_from_wire (guchar *buf, guint buflen, struct fuzzy_session *s)
{
	enum rspamd_fuzzy_epoch epoch;

	/* For now, we assume that recvfrom returns a complete datagramm */
	switch (buflen) {
	case sizeof (struct rspamd_fuzzy_cmd):
		s->cmd_type = CMD_NORMAL;
		memcpy (&s->cmd.normal, buf, sizeof (s->cmd.normal));
		epoch = rspamd_fuzzy_command_valid (&s->cmd.normal, buflen);

		if (epoch == RSPAMD_FUZZY_EPOCH_MAX) {
			msg_debug ("invalid fuzzy command of size %d received", buflen);
			return FALSE;
		}
		s->epoch = epoch;
		break;
	case sizeof (struct rspamd_fuzzy_shingle_cmd):
		s->cmd_type = CMD_SHINGLE;
		memcpy (&s->cmd.shingle, buf, sizeof (s->cmd.shingle));
		epoch = rspamd_fuzzy_command_valid (&s->cmd.shingle.basic, buflen);

		if (epoch == RSPAMD_FUZZY_EPOCH_MAX) {
			msg_debug ("invalid fuzzy command of size %d received", buflen);
			return FALSE;
		}
		s->epoch = epoch;
		break;
	case sizeof (struct rspamd_fuzzy_encrypted_cmd):
		s->cmd_type = CMD_ENCRYPTED_NORMAL;
		memcpy (&s->cmd.enc_normal, buf, sizeof (s->cmd.enc_normal));

		if (!rspamd_fuzzy_decrypt_command (s)) {
			return FALSE;
		}
		epoch = rspamd_fuzzy_command_valid (&s->cmd.enc_normal.cmd,
				sizeof (s->cmd.enc_normal.cmd));

		if (epoch == RSPAMD_FUZZY_EPOCH_MAX) {
			msg_debug ("invalid fuzzy command of size %d received", buflen);
			return FALSE;
		}
		/* Encrypted is epoch 10 at least */
		s->epoch = RSPAMD_FUZZY_EPOCH10;
		break;
	case sizeof (struct rspamd_fuzzy_encrypted_shingle_cmd):
		s->cmd_type = CMD_ENCRYPTED_SHINGLE;
		memcpy (&s->cmd.enc_shingle, buf, sizeof (s->cmd.enc_shingle));

		if (!rspamd_fuzzy_decrypt_command (s)) {
			return FALSE;
		}
		epoch = rspamd_fuzzy_command_valid (&s->cmd.enc_shingle.cmd.basic,
				sizeof (s->cmd.enc_shingle.cmd));

		if (epoch == RSPAMD_FUZZY_EPOCH_MAX) {
			msg_debug ("invalid fuzzy command of size %d received", buflen);
			return FALSE;
		}

		s->epoch = RSPAMD_FUZZY_EPOCH10;
		break;
	default:
		msg_debug ("invalid fuzzy command of size %d received", buflen);
		return FALSE;
	}

	return TRUE;
}

static void
fuzzy_session_destroy (gpointer d)
{
	struct fuzzy_session *session = d;

	rspamd_inet_address_destroy (session->addr);
	rspamd_explicit_memzero (session->nm, sizeof (session->nm));
	session->worker->nconns--;
	g_slice_free1 (sizeof (*session), session);
}

/*
 * Accept new connection and construct task
 */
static void
accept_fuzzy_socket (gint fd, short what, void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)arg;
	struct fuzzy_session *session;
	rspamd_inet_addr_t *addr;
	gssize r;
	guint8 buf[512];

	/* Got some data */
	if (what == EV_READ) {

		for (;;) {
			worker->nconns++;

			r = rspamd_inet_address_recvfrom (fd,
					buf,
					sizeof (buf),
					0,
					&addr);

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

			session = g_slice_alloc0 (sizeof (*session));
			REF_INIT_RETAIN (session, fuzzy_session_destroy);
			session->worker = worker;
			session->fd = fd;
			session->ctx = worker->ctx;
			session->time = (guint64) time (NULL);
			session->addr = addr;

			if (rspamd_fuzzy_cmd_from_wire (buf, r, session)) {
				/* Check shingles count sanity */
				rspamd_fuzzy_process_command (session);
			}
			else {
				/* Discard input */
				server_stat->fuzzy_hashes_checked[RSPAMD_FUZZY_EPOCH6]++;
				msg_debug ("invalid fuzzy command of size %z received", r);
			}

			REF_RELEASE (session);
		}
	}
}

static void
sync_callback (gint fd, short what, void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)arg;
	struct rspamd_fuzzy_storage_ctx *ctx;
	gdouble next_check;
	guint64 old_expired, new_expired;

	ctx = worker->ctx;

	if (ctx->backend) {
		rspamd_fuzzy_process_updates_queue (ctx);
		/* Call backend sync */
		old_expired = rspamd_fuzzy_backend_expired (ctx->backend);
		rspamd_fuzzy_backend_sync (ctx->backend, ctx->expire, TRUE);
		new_expired = rspamd_fuzzy_backend_expired (ctx->backend);

		if (old_expired < new_expired) {
			server_stat->fuzzy_hashes_expired += new_expired - old_expired;
		}
	}

	/* Timer event */
	event_del (&tev);
	evtimer_set (&tev, sync_callback, worker);
	event_base_set (ctx->ev_base, &tev);
	/* Plan event with jitter */
	next_check = rspamd_time_jitter (ctx->sync_timeout, 0);
	double_to_tv (next_check, &tmv);
	evtimer_add (&tev, &tmv);
}

static gboolean
rspamd_fuzzy_storage_reload (struct rspamd_main *rspamd_main,
		struct rspamd_worker *worker, gint fd,
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

	if ((ctx->backend = rspamd_fuzzy_backend_open (ctx->hashfile,
			TRUE,
			&err)) == NULL) {
		msg_err ("cannot open backend after reload: %e", err);
		g_error_free (err);
		rep.reply.reload.status = err->code;
	}
	else {
		rep.reply.reload.status = 0;
	}

	if (write (fd, &rep, sizeof (rep)) != sizeof (rep)) {
		msg_err ("cannot write reply to the control socket: %s",
				strerror (errno));
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
	struct rspamd_http_keypair *kp;
	struct fuzzy_key_stat *keystat;
	const ucl_object_t *cur;
	ucl_object_iter_t it = NULL;
	gboolean ret;

	ctx = pd->user_struct;
	pd->offset = G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, default_key);

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
		kp = ctx->default_key;

		if (kp == NULL) {
			return FALSE;
		}

		g_hash_table_insert (ctx->keys, kp->pk, kp);
		keystat = g_slice_alloc0 (sizeof (*keystat));
		/* Hash of ip -> fuzzy_key_stat */
		keystat->last_ips = rspamd_lru_hash_new_full (0, 1024,
				(GDestroyNotify)rspamd_inet_address_destroy, fuzzy_key_stat_dtor,
				rspamd_inet_address_hash, rspamd_inet_address_equal);
		msg_info_pool ("loaded keypair %8xs", kp->pk);
	}
	else if (ucl_object_type (obj) == UCL_ARRAY) {
		while ((cur = ucl_iterate_object (obj, &it, true)) != NULL) {
			if (!fuzzy_parse_keypair (pool, cur, pd, section, err)) {
				return FALSE;
			}
		}
	}

	return TRUE;
}

static guint
fuzzy_kp_hash (gconstpointer p)
{
	const guchar *pk = p;

	return XXH64 (pk, RSPAMD_FUZZY_KEYLEN, 0xdeadbabe);
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

	ctx = g_malloc0 (sizeof (struct rspamd_fuzzy_storage_ctx));

	ctx->sync_timeout = DEFAULT_SYNC_TIMEOUT;
	ctx->expire = DEFAULT_EXPIRE;
	ctx->keypair_cache_size = DEFAULT_KEYPAIR_CACHE_SIZE;
	ctx->keys = g_hash_table_new_full (fuzzy_kp_hash, fuzzy_kp_equal,
			NULL, rspamd_http_connection_key_unref);
	ctx->keys_stats = g_hash_table_new_full (fuzzy_kp_hash, fuzzy_kp_equal,
			NULL, fuzzy_key_stat_dtor);

	rspamd_rcl_register_worker_option (cfg, type, "hashfile",
			rspamd_rcl_parse_struct_string, ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, hashfile), 0);

	rspamd_rcl_register_worker_option (cfg, type, "hash_file",
			rspamd_rcl_parse_struct_string, ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, hashfile), 0);

	rspamd_rcl_register_worker_option (cfg, type, "file",
			rspamd_rcl_parse_struct_string, ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, hashfile), 0);

	rspamd_rcl_register_worker_option (cfg, type, "database",
			rspamd_rcl_parse_struct_string, ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, hashfile), 0);

	rspamd_rcl_register_worker_option (cfg, type, "sync",
			rspamd_rcl_parse_struct_time, ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx,
					sync_timeout), RSPAMD_CL_FLAG_TIME_FLOAT);

	rspamd_rcl_register_worker_option (cfg, type, "expire",
			rspamd_rcl_parse_struct_time, ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx,
					expire), RSPAMD_CL_FLAG_TIME_FLOAT);

	rspamd_rcl_register_worker_option (cfg, type, "allow_update",
			rspamd_rcl_parse_struct_string, ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, update_map), 0);

	rspamd_rcl_register_worker_option (cfg, type, "keypair",
			fuzzy_parse_keypair, ctx,
			0, RSPAMD_CL_FLAG_MULTIPLE);

	rspamd_rcl_register_worker_option (cfg, type, "keypair_cache_size",
			rspamd_rcl_parse_struct_integer, ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx,
					keypair_cache_size),
			RSPAMD_CL_FLAG_UINT);

	rspamd_rcl_register_worker_option (cfg, type, "encrypted_only",
			rspamd_rcl_parse_struct_boolean, ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, encrypted_only), 0);


	return ctx;
}

static void
rspamd_fuzzy_peer_io (gint fd, gshort what, gpointer d)
{
	struct fuzzy_peer_cmd cmd, *pcmd;
	struct rspamd_fuzzy_storage_ctx *ctx = d;
	gssize r;

	r = read (fd, &cmd, sizeof (cmd));

	if (r != sizeof (cmd)) {
		msg_err ("cannot read command from peers: %s", strerror (errno));
	}
	else {
		pcmd = g_slice_alloc (sizeof (*pcmd));
		memcpy (pcmd, &cmd, sizeof (cmd));
		g_queue_push_tail (ctx->updates_pending, pcmd);
	}
}

static void
fuzzy_peer_rep (struct rspamd_worker *worker,
		struct rspamd_srv_reply *rep, gint rep_fd,
		gpointer ud)
{
	struct rspamd_fuzzy_storage_ctx *ctx = ud;
	GList *cur;
	gint listen_socket;
	struct event *accept_event;
	gdouble next_check;

	ctx->peer_fd = rep_fd;

	if (rep_fd == -1) {
		msg_warn ("cannot receive peer fd from the main process");
	}

	/* Start listening */
	cur = worker->cf->listen_socks;
	while (cur) {
		listen_socket = GPOINTER_TO_INT (cur->data);
		if (listen_socket != -1) {
			accept_event = g_slice_alloc0 (sizeof (struct event));
			event_set (accept_event, listen_socket, EV_READ | EV_PERSIST,
					accept_fuzzy_socket, worker);
			event_base_set (ctx->ev_base, accept_event);
			event_add (accept_event, NULL);
			worker->accept_events = g_list_prepend (worker->accept_events,
					accept_event);
		}
		cur = g_list_next (cur);
	}

	if (worker->index == 0 && ctx->peer_fd != -1) {
		/* Listen for peer requests */
		event_set (&ctx->peer_ev, ctx->peer_fd, EV_READ | EV_PERSIST,
				rspamd_fuzzy_peer_io, ctx);
		event_base_set (ctx->ev_base, &ctx->peer_ev);
		event_add (&ctx->peer_ev, NULL);
		ctx->updates_pending = g_queue_new ();

		/* Timer event */
		evtimer_set (&tev, sync_callback, worker);
		event_base_set (ctx->ev_base, &tev);
		/* Plan event with jitter */
		next_check = rspamd_time_jitter (ctx->sync_timeout, 0);
		double_to_tv (next_check, &tmv);
		evtimer_add (&tev, &tmv);
	}
}

/*
 * Start worker process
 */
void
start_fuzzy (struct rspamd_worker *worker)
{
	struct rspamd_fuzzy_storage_ctx *ctx = worker->ctx;
	GError *err = NULL;
	struct rspamd_srv_command srv_cmd;

	ctx->ev_base = rspamd_prepare_worker (worker,
			"fuzzy",
			NULL);
	ctx->peer_fd = -1;
	server_stat = worker->srv->stat;

	/*
	 * Open DB and perform VACUUM
	 */
	if ((ctx->backend = rspamd_fuzzy_backend_open (ctx->hashfile, TRUE, &err)) == NULL) {
		msg_err ("cannot open backend: %e", err);
		g_error_free (err);
		exit (EXIT_SUCCESS);
	}

	server_stat->fuzzy_hashes = rspamd_fuzzy_backend_count (ctx->backend);

	if (ctx->default_key && ctx->keypair_cache_size > 0) {
		/* Create keypairs cache */
		ctx->keypair_cache = rspamd_keypair_cache_new (ctx->keypair_cache_size);
	}

	if (worker->index == 0) {
		rspamd_fuzzy_backend_sync (ctx->backend, ctx->expire, TRUE);
	}

	/* Register custom reload command for the control socket */
	rspamd_control_worker_add_cmd_handler (worker, RSPAMD_CONTROL_RELOAD,
			rspamd_fuzzy_storage_reload, ctx);
	/* Create radix tree */
	if (ctx->update_map != NULL) {
		if (!rspamd_map_add (worker->srv->cfg, ctx->update_map,
			"Allow fuzzy updates from specified addresses",
			rspamd_radix_read, rspamd_radix_fin, (void **)&ctx->update_ips)) {
			if (!radix_add_generic_iplist (ctx->update_map,
				&ctx->update_ips)) {
				msg_warn ("cannot load or parse ip list from '%s'",
					ctx->update_map);
			}
		}
	}

	/* Maps events */
	rspamd_map_watch (worker->srv->cfg, ctx->ev_base);

	/* Get peer pipe */
	memset (&srv_cmd, 0, sizeof (srv_cmd));
	srv_cmd.type = RSPAMD_SRV_SOCKETPAIR;
	srv_cmd.id = ottery_rand_uint64 ();
	srv_cmd.cmd.spair.af = SOCK_DGRAM;
	srv_cmd.cmd.spair.pair_num = worker->index;
	memset (srv_cmd.cmd.spair.pair_id, 0, sizeof (srv_cmd.cmd.spair.pair_id));
	memcpy (srv_cmd.cmd.spair.pair_id, "fuzzy", sizeof ("fuzzy"));

	rspamd_srv_send_command (worker, ctx->ev_base, &srv_cmd, fuzzy_peer_rep, ctx);

	event_base_loop (ctx->ev_base, 0);
	rspamd_worker_block_signals ();

	if (worker->index == 0) {
		rspamd_fuzzy_process_updates_queue (ctx);
		rspamd_fuzzy_backend_sync (ctx->backend, ctx->expire, TRUE);
	}

	rspamd_fuzzy_backend_close (ctx->backend);
	rspamd_log_close (worker->srv->logger);

	if (ctx->peer_fd != -1) {
		if (worker->index == 0) {
			event_del (&ctx->peer_ev);
		}
		close (ctx->peer_fd);
	}

	if (ctx->keypair_cache) {
		rspamd_keypair_cache_destroy (ctx->keypair_cache);
	}

	g_hash_table_unref (ctx->keys);

	exit (EXIT_SUCCESS);
}
