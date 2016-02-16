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

#include <libserver/rspamd_control.h>
#include "config.h"
#include "util.h"
#include "rspamd.h"
#include "map.h"
#include "fuzzy_storage.h"
#include "fuzzy_backend.h"
#include "ottery.h"
#include "libserver/worker_util.h"
#include "libserver/rspamd_control.h"
#include "libcryptobox/cryptobox.h"
#include "libcryptobox/keypairs_cache.h"
#include "libcryptobox/keypair.h"
#include "ref.h"
#include "xxhash.h"
#include "libutil/hash.h"
#include "unix-std.h"

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
	SOCK_DGRAM,                 /* UDP socket */
	RSPAMD_WORKER_VER           /* Version info */
};

/* For evtimer */
static struct timeval tmv;
static struct event tev;

struct fuzzy_global_stat {
	guint64 fuzzy_hashes;
	/**< number of fuzzy hashes stored					*/
	guint64 fuzzy_hashes_expired;
	/**< number of fuzzy hashes expired					*/
	guint64 fuzzy_hashes_checked[RSPAMD_FUZZY_EPOCH_MAX];
	/**< ammount of check requests for each epoch		*/
	guint64 fuzzy_shingles_checked[RSPAMD_FUZZY_EPOCH_MAX];
	/**< ammount of shingle check requests for each epoch	*/
	guint64 fuzzy_hashes_found[RSPAMD_FUZZY_EPOCH_MAX];
	/**< amount of hashes found by epoch				*/
	guint64 invalid_requests;
};

struct fuzzy_key_stat {
	guint64 checked;
	guint64 matched;
	guint64 added;
	guint64 deleted;
	guint64 errors;
	rspamd_lru_hash_t *last_ips;
};

struct rspamd_fuzzy_storage_ctx {
	struct fuzzy_global_stat stat;
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
	struct rspamd_cryptobox_keypair *default_keypair; /* Bad clash, need for parse keypair */
	struct fuzzy_key *default_key;
	GHashTable *keys;
	gboolean encrypted_only;
	struct rspamd_keypair_cache *keypair_cache;
	rspamd_lru_hash_t *errors_ips;
	struct rspamd_fuzzy_backend *backend;
	GQueue *updates_pending;
	struct rspamd_dns_resolver *resolver;
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
	gboolean is_shingle;
	union {
		struct rspamd_fuzzy_cmd normal;
		struct rspamd_fuzzy_shingle_cmd shingle;
	} cmd;
};

struct fuzzy_peer_request {
	struct event io_ev;
	struct fuzzy_peer_cmd cmd;
};

struct fuzzy_key {
	struct rspamd_cryptobox_keypair *key;
	struct rspamd_cryptobox_pubkey *pk;
	struct fuzzy_key_stat *stat;
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
fuzzy_key_dtor (gpointer p)
{
	struct fuzzy_key *key = p;

	if (key->stat) {
		fuzzy_key_stat_dtor (key->stat);
	}
	if (key->key) {
		rspamd_keypair_unref (key->key);
	}

	g_slice_free1 (sizeof (*key), key);
}

static void
rspamd_fuzzy_process_updates_queue (struct rspamd_fuzzy_storage_ctx *ctx)
{
	GList *cur;
	struct fuzzy_peer_cmd *io_cmd;
	struct rspamd_fuzzy_cmd *cmd;
	gpointer ptr;
	guint nupdates = 0;

	if (rspamd_fuzzy_backend_prepare_update (ctx->backend)) {
		cur = ctx->updates_pending->head;
		while (cur) {
			io_cmd = cur->data;

			if (io_cmd->is_shingle) {
				cmd = &io_cmd->cmd.shingle.basic;
				ptr = &io_cmd->cmd.shingle;
			}
			else {
				cmd = &io_cmd->cmd.normal;
				ptr = &io_cmd->cmd.normal;
			}

			if (cmd->cmd == FUZZY_WRITE) {
				rspamd_fuzzy_backend_add (ctx->backend, ptr);
			}
			else {
				rspamd_fuzzy_backend_del (ctx->backend, ptr);
			}

			nupdates++;
			cur = g_list_next (cur);
		}

		if (rspamd_fuzzy_backend_finish_update (ctx->backend)) {
			ctx->stat.fuzzy_hashes = rspamd_fuzzy_backend_count (ctx->backend);
			cur = ctx->updates_pending->head;

			while (cur) {
				io_cmd = cur->data;
				g_slice_free1 (sizeof (*io_cmd), io_cmd);
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
rspamd_fuzzy_update_stats (struct rspamd_fuzzy_storage_ctx *ctx,
		enum rspamd_fuzzy_epoch epoch,
		gboolean matched,
		gboolean is_shingle,
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

static void
rspamd_fuzzy_process_command (struct fuzzy_session *session)
{
	gboolean encrypted = FALSE, is_shingle = FALSE;
	struct rspamd_fuzzy_cmd *cmd = NULL;
	struct rspamd_fuzzy_reply result;
	struct fuzzy_peer_cmd *up_cmd;
	struct fuzzy_peer_request *up_req;
	struct fuzzy_key_stat *ip_stat = NULL;
	rspamd_inet_addr_t *naddr;
	gpointer ptr;
	gsize up_len = 0;

	switch (session->cmd_type) {
	case CMD_NORMAL:
		cmd = &session->cmd.normal;
		up_len = sizeof (session->cmd.normal);
		break;
	case CMD_SHINGLE:
		cmd = &session->cmd.shingle.basic;
		up_len = sizeof (session->cmd.shingle);
		is_shingle = TRUE;
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
		is_shingle = TRUE;
		break;
	}

	if (G_UNLIKELY (cmd == NULL || up_len == 0)) {
		result.value = 500;
		result.prob = 0.0;
		goto reply;
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
				up_cmd = g_slice_alloc0 (sizeof (*up_cmd));
				up_cmd->is_shingle = is_shingle;
				ptr = is_shingle ?
						(gpointer)&up_cmd->cmd.shingle :
						(gpointer)&up_cmd->cmd.normal;
				memcpy (ptr, cmd, up_len);
				g_queue_push_tail (session->ctx->updates_pending, up_cmd);
			}
			else {
				/* We need to send request to the peer */
				up_req = g_slice_alloc0 (sizeof (*up_req));
				up_req->cmd.is_shingle = is_shingle;
				ptr = is_shingle ?
						(gpointer)&up_req->cmd.cmd.shingle :
						(gpointer)&up_req->cmd.cmd.normal;
				memcpy (ptr, cmd, up_len);
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
	result.flag = cmd->flag;
	memcpy (&session->reply.rep, &result, sizeof (result));

	rspamd_fuzzy_update_stats (session->ctx,
			session->epoch,
			result.prob > 0.5,
			is_shingle,
			session->key_stat,
			ip_stat, cmd->cmd,
			result.value);

	if (encrypted) {
		/* We need also to encrypt reply */
		ottery_rand_bytes (session->reply.hdr.nonce,
				sizeof (session->reply.hdr.nonce));
		rspamd_cryptobox_encrypt_nm_inplace ((guchar *)&session->reply.rep,
				sizeof (session->reply.rep),
				session->reply.hdr.nonce,
				session->nm,
				session->reply.hdr.mac,
				RSPAMD_CRYPTOBOX_MODE_25519);
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
	struct rspamd_cryptobox_pubkey *rk;
	struct fuzzy_key *key;

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
	key = g_hash_table_lookup (s->ctx->keys, hdr->key_id);

	if (key == NULL) {
		/* Unknown key, assume default one */
		key = s->ctx->default_key;
	}

	s->key_stat = key->stat;

	/* Now process keypair */
	rk = rspamd_pubkey_from_bin (hdr->pubkey, sizeof (hdr->pubkey),
			RSPAMD_KEYPAIR_KEX, RSPAMD_CRYPTOBOX_MODE_25519);

	if (rk == NULL) {
		msg_err ("bad key");
		return FALSE;
	}

	rspamd_keypair_cache_process (s->ctx->keypair_cache, key->key, rk);

	/* Now decrypt request */
	if (!rspamd_cryptobox_decrypt_nm_inplace (payload, payload_len, hdr->nonce,
			rspamd_pubkey_get_nm (rk),
			hdr->mac, RSPAMD_CRYPTOBOX_MODE_25519)) {
		msg_err ("decryption failed");
		rspamd_pubkey_unref (rk);

		return FALSE;
	}

	memcpy (s->nm, rspamd_pubkey_get_nm (rk), sizeof (s->nm));
	rspamd_pubkey_unref (rk);

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
	guint64 *nerrors;

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
				session->ctx->stat.invalid_requests ++;
				msg_debug ("invalid fuzzy command of size %z received", r);

				nerrors = rspamd_lru_hash_lookup (session->ctx->errors_ips,
						addr, -1);

				if (nerrors == NULL) {
					nerrors = g_malloc (sizeof (*nerrors));
					*nerrors = 1;
					rspamd_lru_hash_insert (session->ctx->errors_ips,
							rspamd_inet_address_copy (addr),
							nerrors, -1, -1);
				}
				else {
					*nerrors = *nerrors + 1;
				}
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
			ctx->stat.fuzzy_hashes_expired += new_expired - old_expired;
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
	GHashTableIter it, ip_it;
	GHashTable *ip_hash;
	struct fuzzy_key_stat *key_stat;
	struct fuzzy_key *key;
	rspamd_lru_element_t *lru_elt;
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
				ip_hash = rspamd_lru_hash_get_htable (key_stat->last_ips);

				if (ip_hash) {
					g_hash_table_iter_init (&ip_it, ip_hash);
					ip_elt = ucl_object_typed_new (UCL_OBJECT);

					while (g_hash_table_iter_next (&ip_it, &k, &v)) {
						lru_elt = v;
						ip_cur = rspamd_fuzzy_storage_stat_key (lru_elt->data);
						ucl_object_insert_key (ip_elt, ip_cur,
								rspamd_inet_address_to_string (k), 0, true);
					}

					ucl_object_insert_key (elt, ip_elt, "ips", 0, false);
				}
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

	if (ctx->errors_ips && ip_stat) {
		ip_hash = rspamd_lru_hash_get_htable (ctx->errors_ips);

		if (ip_hash) {
			g_hash_table_iter_init (&ip_it, ip_hash);
			ip_elt = ucl_object_typed_new (UCL_OBJECT);

			while (g_hash_table_iter_next (&ip_it, &k, &v)) {
				lru_elt = v;

				ucl_object_insert_key (ip_elt,
						ucl_object_fromint (*(guint64 *)lru_elt->data),
						rspamd_inet_address_to_string (k), 0, true);
			}

			ucl_object_insert_key (obj,
					ip_elt,
					"errors_ips",
					0,
					false);
		}
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

static gboolean
rspamd_fuzzy_storage_stat (struct rspamd_main *rspamd_main,
		struct rspamd_worker *worker, gint fd,
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
	rep.type = RSPAMD_CONTROL_RELOAD;

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
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN (sizeof (int));
		memcpy (CMSG_DATA (cmsg), &outfd, sizeof (int));
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

		key = g_slice_alloc (sizeof (*key));
		key->key = kp;
		keystat = g_slice_alloc0 (sizeof (*keystat));
		/* Hash of ip -> fuzzy_key_stat */
		keystat->last_ips = rspamd_lru_hash_new_full (0, 1024,
				(GDestroyNotify)rspamd_inet_address_destroy, fuzzy_key_stat_dtor,
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
				return FALSE;
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

	ctx = g_malloc0 (sizeof (struct rspamd_fuzzy_storage_ctx));

	ctx->sync_timeout = DEFAULT_SYNC_TIMEOUT;
	ctx->expire = DEFAULT_EXPIRE;
	ctx->keypair_cache_size = DEFAULT_KEYPAIR_CACHE_SIZE;
	ctx->keys = g_hash_table_new_full (fuzzy_kp_hash, fuzzy_kp_equal,
			NULL, fuzzy_key_dtor);
	ctx->errors_ips = rspamd_lru_hash_new_full (0, 1024,
			(GDestroyNotify) rspamd_inet_address_destroy, g_free,
			rspamd_inet_address_hash, rspamd_inet_address_equal);

	rspamd_rcl_register_worker_option (cfg,
			type,
			"hashfile",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, hashfile),
			0,
			"Path to fuzzy database");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"hash_file",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, hashfile),
			0,
			"Path to fuzzy database (alias for hashfile)");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"file",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, hashfile),
			0,
			"Path to fuzzy database (alias for hashfile)");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"database",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, hashfile),
			0,
			"Path to fuzzy database (alias for hashfile)");

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
			"allow_update",
			rspamd_rcl_parse_struct_string,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, update_map),
			0,
			"Allow modifications from the following IP addresses");

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
		msg_err ("cannot receive peer fd from the main process");
		exit (EXIT_FAILURE);
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

	/*
	 * Open DB and perform VACUUM
	 */
	if ((ctx->backend = rspamd_fuzzy_backend_open (ctx->hashfile, TRUE, &err)) == NULL) {
		msg_err ("cannot open backend: %e", err);
		g_error_free (err);
		exit (EXIT_SUCCESS);
	}

	ctx->stat.fuzzy_hashes = rspamd_fuzzy_backend_count (ctx->backend);

	if (ctx->default_key && ctx->keypair_cache_size > 0) {
		/* Create keypairs cache */
		ctx->keypair_cache = rspamd_keypair_cache_new (ctx->keypair_cache_size);
	}

	if (worker->index == 0) {
		rspamd_fuzzy_backend_sync (ctx->backend, ctx->expire, TRUE);
	}

	/* Register custom reload and stat commands for the control socket */
	rspamd_control_worker_add_cmd_handler (worker, RSPAMD_CONTROL_RELOAD,
			rspamd_fuzzy_storage_reload, ctx);
	rspamd_control_worker_add_cmd_handler (worker, RSPAMD_CONTROL_FUZZY_STAT,
			rspamd_fuzzy_storage_stat, ctx);
	/* Create radix tree */
	if (ctx->update_map != NULL) {
		if (!rspamd_map_is_map (ctx->update_map)) {
			if (!radix_add_generic_iplist (ctx->update_map,
					&ctx->update_ips)) {
				msg_warn ("cannot load or parse ip list from '%s'",
						ctx->update_map);
			}
		}
		else {
			rspamd_map_add (worker->srv->cfg, ctx->update_map,
					"Allow fuzzy updates from specified addresses",
					rspamd_radix_read, rspamd_radix_fin,
					(void **)&ctx->update_ips);

		}
	}

	/* Maps events */
	ctx->resolver = dns_resolver_init (worker->srv->logger,
				ctx->ev_base,
				worker->srv->cfg);
	rspamd_map_watch (worker->srv->cfg, ctx->ev_base, ctx->resolver);

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

	rspamd_lru_hash_destroy (ctx->errors_ips);

	g_hash_table_unref (ctx->keys);

	exit (EXIT_SUCCESS);
}
