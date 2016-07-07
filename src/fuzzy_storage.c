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
#include "libutil/http_private.h"
#include "unix-std.h"

/* This number is used as expire time in seconds for cache items  (2 days) */
#define DEFAULT_EXPIRE 172800L
/* Resync value in seconds */
#define DEFAULT_SYNC_TIMEOUT 60.0
#define DEFAULT_KEYPAIR_CACHE_SIZE 512
#define DEFAULT_MASTER_TIMEOUT 10.0

#define INVALID_NODE_TIME (guint64) - 1

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
#define msg_debug_fuzzy_update(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
		session->name, session->uid, \
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
		RSPAMD_WORKER_SOCKET_UDP|RSPAMD_WORKER_SOCKET_TCP,   /* Both socket */
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

struct rspamd_fuzzy_mirror {
	gchar *name;
	struct upstream_list *u;
	struct rspamd_cryptobox_pubkey *key;
};

static const guint64 rspamd_fuzzy_storage_magic = 0x291a3253eb1b3ea5ULL;

struct rspamd_fuzzy_storage_ctx {
	guint64 magic;
	struct fuzzy_global_stat stat;
	char *hashfile;
	gdouble expire;
	gdouble sync_timeout;
	radix_compressed_t *update_ips;
	radix_compressed_t *master_ips;
	struct rspamd_cryptobox_keypair *sync_keypair;
	struct rspamd_cryptobox_pubkey *master_key;
	struct timeval master_io_tv;
	gdouble master_timeout;
	GPtrArray *mirrors;
	const ucl_object_t *update_map;
	const ucl_object_t *masters_map;
	GHashTable *master_flags;
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
	struct rspamd_config *cfg;
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

struct fuzzy_master_update_session {
	const gchar *name;
	gchar uid[16];
	struct rspamd_http_connection *conn;
	struct rspamd_fuzzy_storage_ctx *ctx;
	rspamd_inet_addr_t *addr;
	gboolean replied;
	gint sock;
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

struct fuzzy_slave_connection {
	struct rspamd_cryptobox_keypair *local_key;
	struct rspamd_cryptobox_pubkey *remote_key;
	struct upstream *up;
	struct rspamd_http_connection *http_conn;
	struct rspamd_fuzzy_mirror *mirror;
	gint sock;
};

static void
fuzzy_mirror_close_connection (struct fuzzy_slave_connection *conn)
{
	if (conn) {
		if (conn->http_conn) {
			rspamd_http_connection_reset (conn->http_conn);
			rspamd_http_connection_unref (conn->http_conn);
		}

		close (conn->sock);

		g_slice_free1 (sizeof (*conn), conn);
	}
}

static void
fuzzy_mirror_updates_to_http (struct rspamd_fuzzy_storage_ctx *ctx,
		struct rspamd_http_message *msg)
{
	GList *cur;
	struct fuzzy_peer_cmd *io_cmd;
	guint32 len;
	guint32 rev;
	const gchar *p;
	rspamd_fstring_t *reply;

	rev = rspamd_fuzzy_backend_version (ctx->backend, local_db_name);
	rev = GUINT32_TO_LE (rev);
	len = sizeof (guint32) * 2; /* revision + last chunk */

	for (cur = ctx->updates_pending->head; cur != NULL; cur = g_list_next (cur)) {
		io_cmd = cur->data;

		if (io_cmd->is_shingle) {
			len += sizeof (guint32) + sizeof (gboolean) +
					sizeof (struct rspamd_fuzzy_shingle_cmd);
		}
		else {
			len += sizeof (guint32) + sizeof (gboolean) +
					sizeof (struct rspamd_fuzzy_cmd);
		}
	}

	reply = rspamd_fstring_sized_new (len);
	reply = rspamd_fstring_append (reply, (const char *)&rev,
			sizeof (rev));

	for (cur = ctx->updates_pending->head; cur != NULL; cur = g_list_next (cur)) {
		io_cmd = cur->data;

		if (io_cmd->is_shingle) {
			len = sizeof (gboolean) +
					sizeof (struct rspamd_fuzzy_shingle_cmd);
		}
		else {
			len = sizeof (gboolean) +
					sizeof (struct rspamd_fuzzy_cmd);
		}

		p = (const char *)io_cmd;
		len = GUINT32_TO_LE (len);
		reply = rspamd_fstring_append (reply, (const char *)&len, sizeof (len));
		reply = rspamd_fstring_append (reply, p, len);
	}

	/* Last chunk */
	len = 0;
	reply = rspamd_fstring_append (reply, (const char *)&len, sizeof (len));
	rspamd_http_message_set_body_from_fstring_steal (msg, reply);
}

static void
fuzzy_mirror_error_handler (struct rspamd_http_connection *conn, GError *err)
{
	struct fuzzy_slave_connection *bk_conn = conn->ud;
	msg_info ("abnormally closing connection from backend: %s:%s, "
			"error: %e",
			bk_conn->mirror->name,
			rspamd_inet_address_to_string (rspamd_upstream_addr (bk_conn->up)),
			err);

	fuzzy_mirror_close_connection (bk_conn);
}

static gint
fuzzy_mirror_finish_handler (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg)
{
	struct fuzzy_slave_connection *bk_conn = conn->ud;

	msg_info ("finished mirror connection to %s", bk_conn->mirror->name);
	fuzzy_mirror_close_connection (bk_conn);

	return 0;
}

static void
rspamd_fuzzy_send_update_mirror (struct rspamd_fuzzy_storage_ctx *ctx,
		struct rspamd_fuzzy_mirror *m)
{
	struct fuzzy_slave_connection *conn;
	struct rspamd_http_message *msg;
	struct timeval tv;

	conn = g_slice_alloc0 (sizeof (*conn));
	conn->up = rspamd_upstream_get (m->u,
			RSPAMD_UPSTREAM_MASTER_SLAVE, NULL, 0);
	conn->mirror = m;

	if (conn->up == NULL) {
		msg_err ("cannot select upstream for %s", m->name);
		return;
	}

	conn->sock = rspamd_inet_address_connect (
			rspamd_upstream_addr (conn->up),
			SOCK_STREAM, TRUE);

	if (conn->sock == -1) {
		msg_err ("cannot connect upstream for %s", m->name);
		rspamd_upstream_fail (conn->up);
		return;
	}

	msg = rspamd_http_new_message (HTTP_REQUEST);
	rspamd_printf_fstring (&msg->url, "/update_v1/%s", m->name);

	conn->http_conn = rspamd_http_connection_new (NULL,
			fuzzy_mirror_error_handler,
			fuzzy_mirror_finish_handler,
			RSPAMD_HTTP_CLIENT_SIMPLE,
			RSPAMD_HTTP_CLIENT,
			ctx->keypair_cache,
			NULL);

	rspamd_http_connection_set_key (conn->http_conn,
			ctx->sync_keypair);
	msg->peer_key = rspamd_pubkey_ref (m->key);
	double_to_tv (ctx->sync_timeout, &tv);
	fuzzy_mirror_updates_to_http (ctx, msg);

	rspamd_http_connection_write_message (conn->http_conn,
			msg, NULL, NULL, conn,
			conn->sock,
			&tv, ctx->ev_base);
	msg_info ("send update request to %s", m->name);
}

static void
rspamd_fuzzy_process_updates_queue (struct rspamd_fuzzy_storage_ctx *ctx,
		const gchar *source)
{
	GList *cur;
	struct fuzzy_peer_cmd *io_cmd;
	struct rspamd_fuzzy_cmd *cmd;
	gpointer ptr;
	struct rspamd_fuzzy_mirror *m;
	guint nupdates = 0, i;

	if (ctx->updates_pending &&
			g_queue_get_length (ctx->updates_pending) > 0 &&
			rspamd_fuzzy_backend_prepare_update (ctx->backend, source)) {
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

		if (rspamd_fuzzy_backend_finish_update (ctx->backend, source, nupdates > 0)) {
			ctx->stat.fuzzy_hashes = rspamd_fuzzy_backend_count (ctx->backend);

			if (nupdates > 0) {
				for (i = 0; i < ctx->mirrors->len; i ++) {
					m = g_ptr_array_index (ctx->mirrors, i);

					rspamd_fuzzy_send_update_mirror (ctx, m);
				}
			}

			/* Clear updates */
			cur = ctx->updates_pending->head;

			while (cur) {
				io_cmd = cur->data;
				g_slice_free1 (sizeof (*io_cmd), io_cmd);
				cur = g_list_next (cur);
			}

			g_queue_clear (ctx->updates_pending);
			msg_info ("updated fuzzy storage: %ud updates processed, version: %d",
					nupdates, rspamd_fuzzy_backend_version (ctx->backend, source));
		}
		else {
			msg_err ("cannot commit update transaction to fuzzy backend, "
					"%ud updates are still pending",
					g_queue_get_length (ctx->updates_pending));
		}
	}
	else if (ctx->updates_pending &&
			g_queue_get_length (ctx->updates_pending) > 0) {
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

	result.flag = cmd->flag;
	if (cmd->cmd == FUZZY_CHECK) {
		result = rspamd_fuzzy_backend_check (session->ctx->backend, cmd,
				session->ctx->expire);
	}
	else if (cmd->cmd == FUZZY_STAT) {
		result.prob = 1.0;
		result.value = 0;
		result.flag = rspamd_fuzzy_backend_count (session->ctx->backend);
	}
	else {
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
	if (cmd) {
		result.tag = cmd->tag;

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
	}

	rspamd_fuzzy_write_reply (session);
}


static enum rspamd_fuzzy_epoch
rspamd_fuzzy_command_valid (struct rspamd_fuzzy_cmd *cmd, gint r)
{
	enum rspamd_fuzzy_epoch ret = RSPAMD_FUZZY_EPOCH_MAX;

	switch (cmd->version) {
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
		s->epoch = epoch;
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

		s->epoch = epoch;
		break;
	default:
		msg_debug ("invalid fuzzy command of size %d received", buflen);
		return FALSE;
	}

	return TRUE;
}

static void
rspamd_fuzzy_mirror_process_update (struct fuzzy_master_update_session *session,
		struct rspamd_http_message *msg)
{
	const guchar *p;
	gchar *src = NULL, *psrc;
	gsize remain;
	gint32 revision, our_rev;
	guint32 len = 0, cnt = 0;
	struct fuzzy_peer_cmd cmd, *pcmd;
	enum {
		read_len = 0,
		read_data,
		finish_processing
	} state = read_len;
	GList *updates = NULL, *cur;
	gpointer flag_ptr;

	if (!rspamd_http_message_get_body (msg, NULL) || !msg->url
			|| msg->url->len == 0) {
		msg_err_fuzzy_update ("empty update message, not processing");

		return;
	}

	/* Detect source from url: /update_v1/<source>, so we look for the last '/' */
	remain = msg->url->len;
	psrc = rspamd_fstringdup (msg->url);
	src = psrc;

	while (remain--) {
		if (src[remain] == '/') {
			src = &src[remain + 1];
			break;
		}
	}

	/*
	 * Message format:
	 * <uint32_le> - revision
	 * <uint32_le> - size of the next element
	 * <data> - command data
	 * ...
	 * <0> - end of data
	 * ... - ignored
	 */
	p = rspamd_http_message_get_body (msg, &remain);

	if (remain > sizeof (gint32) * 2) {
		memcpy (&revision, p, sizeof (gint32));
		revision = GINT32_TO_LE (revision);
		our_rev = rspamd_fuzzy_backend_version (session->ctx->backend, src);

		if (revision <= our_rev) {
			msg_err_fuzzy_update ("remote revision: %d is older than ours: %d, "
					"refusing update",
					revision, our_rev);
			g_free (psrc);

			return;
		}
		else if (revision - our_rev > 1) {
			msg_warn_fuzzy_update ("remote revision: %d is newer more than one revision "
					"than ours: %d, cold sync is recommended",
								revision, our_rev);
		}

		remain -= sizeof (gint32);
		p += sizeof (gint32);
	}
	else {
		msg_err_fuzzy_update ("short update message, not processing");
		goto err;
	}

	while (remain > 0) {
		switch (state) {
		case read_len:
			if (remain < sizeof (guint32)) {
				msg_err_fuzzy_update ("short update message while reading "
						"length, not processing");
				goto err;
			}

			memcpy (&len, p, sizeof (guint32));
			len = GUINT32_TO_LE (len);
			remain -= sizeof (guint32);
			p += sizeof (guint32);

			if (len == 0) {
				remain = 0;
				state = finish_processing;
			}
			else {
				state = read_data;
			}
			break;
		case read_data:
			if (remain < len) {
				msg_err_fuzzy_update ("short update message while reading data, "
						"not processing"
						" (%zd is available, %d is required)", remain, len);
				return;
			}

			if (len < sizeof (struct rspamd_fuzzy_cmd) + sizeof (gboolean) ||
					len > sizeof (cmd)) {
				/* Bad size command */
				msg_err_fuzzy_update ("incorrect element size: %d, at least "
						"%d expected", len,
						(gint)(sizeof (struct rspamd_fuzzy_cmd) + sizeof (gboolean)));
				goto err;
			}

			memcpy (&cmd, p, sizeof (gboolean));
			if (cmd.is_shingle && len < sizeof (cmd)) {
				/* Short command */
				msg_err_fuzzy_update ("incorrect element size: %d, at least "
						"%d expected", len,
						(gint)(sizeof (cmd)));
				goto err;
			}

			pcmd = g_slice_alloc (sizeof (cmd));
			memcpy (pcmd, p, len);
			updates = g_list_prepend (updates, pcmd);

			p += len;
			remain -= len;
			len = 0;
			state = read_len;
			cnt ++;
			break;
		case finish_processing:
			/* Do nothing */
			remain = 0;
			break;
		}
	}

	/* Insert elements to the updates from head */
	for (cur = updates; cur != NULL; cur = g_list_next (cur)) {
		pcmd = cur->data;

		if (pcmd->is_shingle) {
			if ((flag_ptr = g_hash_table_lookup (session->ctx->master_flags,
					GUINT_TO_POINTER (pcmd->cmd.shingle.basic.flag))) != NULL) {
				pcmd->cmd.shingle.basic.flag = GPOINTER_TO_UINT (flag_ptr);
			}
		}
		else {
			if ((flag_ptr = g_hash_table_lookup (session->ctx->master_flags,
					GUINT_TO_POINTER (pcmd->cmd.normal.flag))) != NULL) {
				pcmd->cmd.normal.flag = GPOINTER_TO_UINT (flag_ptr);
			}
		}


		g_queue_push_head (session->ctx->updates_pending, cur->data);
		cur->data = NULL;
	}

	rspamd_fuzzy_process_updates_queue (session->ctx, src);
	msg_info_fuzzy_update ("processed updates from the master %s, "
			"%ud operations processed,"
			" revision: %d (local revision: %d)",
			rspamd_inet_address_to_string (session->addr),
			cnt, revision, our_rev);

err:
	g_free (psrc);

	if (updates) {
		/* We still need to clear queue */
		for (cur = updates; cur != NULL; cur = g_list_next (cur)) {
			if (cur->data) {
				g_slice_free1 (sizeof (cmd), cur->data);
			}
		}

		/* This also update our version id */
		g_list_free (updates);
	}
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

static void
rspamd_fuzzy_mirror_session_destroy (struct fuzzy_master_update_session *session)
{
	if (session) {
		rspamd_http_connection_reset (session->conn);
		rspamd_http_connection_unref (session->conn);
		rspamd_inet_address_destroy (session->addr);
		close (session->sock);
		g_slice_free1 (sizeof (*session), session);
	}
}

static void
rspamd_fuzzy_mirror_error_handler (struct rspamd_http_connection *conn, GError *err)
{
	struct fuzzy_master_update_session *session = conn->ud;

	msg_err_fuzzy_update ("abnormally closing connection from: %s, error: %e",
		rspamd_inet_address_to_string (session->addr), err);
	/* Terminate session immediately */
	rspamd_fuzzy_mirror_session_destroy (session);
}

static void
rspamd_fuzzy_mirror_send_reply (struct fuzzy_master_update_session *session,
		guint code, const gchar *str)
{
	struct rspamd_http_message *msg;

	msg = rspamd_http_new_message (HTTP_RESPONSE);
	msg->url = rspamd_fstring_new_init (str, strlen (str));
	msg->code = code;
	session->replied = TRUE;

	rspamd_http_connection_reset (session->conn);
	rspamd_http_connection_write_message (session->conn, msg, NULL, "text/plain",
			session, session->sock, &session->ctx->master_io_tv,
			session->ctx->ev_base);
}

static gint
rspamd_fuzzy_mirror_finish_handler (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg)
{
	struct fuzzy_master_update_session *session = conn->ud;
	const struct rspamd_cryptobox_pubkey *rk;
	const gchar *err_str = NULL;

	if (session->replied) {
		rspamd_fuzzy_mirror_session_destroy (session);

		return 0;
	}

	/* Check key */
	if (!rspamd_http_connection_is_encrypted (conn)) {
		msg_err_fuzzy_update ("refuse unencrypted update from: %s",
				rspamd_inet_address_to_string (session->addr));
		err_str = "Unencrypted update is not allowed";
		goto end;
	}
	else {

		if (session->ctx->master_key) {
			rk = rspamd_http_connection_get_peer_key (conn);
			g_assert (rk != NULL);

			if (!rspamd_pubkey_equal (rk, session->ctx->master_key)) {
				msg_err_fuzzy_update ("refuse unknown pubkey update from: %s",
						rspamd_inet_address_to_string (session->addr));
				err_str = "Unknown pubkey";
				goto end;
			}
		}
		else {
			msg_warn_fuzzy_update ("no trusted key specified, accept any update from %s",
					rspamd_inet_address_to_string (session->addr));
		}

		rspamd_fuzzy_mirror_process_update (session, msg);
		rspamd_fuzzy_mirror_send_reply (session, 200, "OK");

		return 0;
	}

end:
	rspamd_fuzzy_mirror_send_reply (session, 403, err_str);

	return 0;
}

static void
accept_fuzzy_mirror_socket (gint fd, short what, void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)arg;
	rspamd_inet_addr_t *addr;
	gint nfd;
	struct rspamd_http_connection *http_conn;
	struct rspamd_fuzzy_storage_ctx *ctx;
	struct fuzzy_master_update_session *session;

	if ((nfd =
			rspamd_accept_from_socket (fd, &addr, worker->accept_events)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		return;
	}

	ctx = worker->ctx;

	if (!ctx->master_ips) {
		msg_err ("deny update request from %s as no masters defined",
				rspamd_inet_address_to_string (addr));
		rspamd_inet_address_destroy (addr);
		close (nfd);

		return;
	}
	else if (radix_find_compressed_addr (ctx->master_ips, addr) == RADIX_NO_VALUE) {
		msg_err ("deny update request from %s",
				rspamd_inet_address_to_string (addr));
		rspamd_inet_address_destroy (addr);
		close (nfd);

		return;
	}

	if (!ctx->sync_keypair) {
		msg_err ("deny update request from %s, as no local keypair is specified",
				rspamd_inet_address_to_string (addr));
		rspamd_inet_address_destroy (addr);
		close (nfd);

		return;
	}

	session = g_slice_alloc0 (sizeof (*session));
	session->name = rspamd_inet_address_to_string (addr);
	rspamd_random_hex (session->uid, sizeof (session->uid) - 1);
	session->uid[sizeof (session->uid) - 1] = '\0';
	http_conn = rspamd_http_connection_new (NULL,
			rspamd_fuzzy_mirror_error_handler,
			rspamd_fuzzy_mirror_finish_handler,
			0,
			RSPAMD_HTTP_SERVER,
			ctx->keypair_cache,
			NULL);

	rspamd_http_connection_set_key (http_conn, ctx->sync_keypair);
	session->ctx = ctx;
	session->conn = http_conn;
	session->addr = addr;
	session->sock = nfd;

	rspamd_http_connection_read_message (http_conn,
			session,
			nfd,
			&ctx->master_io_tv,
			ctx->ev_base);
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
		rspamd_fuzzy_process_updates_queue (ctx, local_db_name);
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
rspamd_fuzzy_storage_sync (struct rspamd_main *rspamd_main,
		struct rspamd_worker *worker, gint fd,
		gint attached_fd,
		struct rspamd_control_command *cmd,
		gpointer ud)
{
	struct rspamd_fuzzy_storage_ctx *ctx = ud;
	gdouble next_check;
	guint64 old_expired, new_expired;
	struct rspamd_control_reply rep;

	if (ctx->backend) {
		rspamd_fuzzy_process_updates_queue (ctx, local_db_name);
		/* Call backend sync */
		old_expired = rspamd_fuzzy_backend_expired (ctx->backend);
		rspamd_fuzzy_backend_sync (ctx->backend, ctx->expire, TRUE);
		new_expired = rspamd_fuzzy_backend_expired (ctx->backend);

		if (old_expired < new_expired) {
			ctx->stat.fuzzy_hashes_expired += new_expired - old_expired;
		}
	}

	rep.reply.fuzzy_sync.status = 0;

	/* Handle next timer event */
	event_del (&tev);
	next_check = rspamd_time_jitter (ctx->sync_timeout, 0);
	double_to_tv (next_check, &tmv);
	evtimer_add (&tev, &tmv);

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
fuzzy_storage_parse_mirror (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	const ucl_object_t *elt;
	struct rspamd_fuzzy_mirror *up = NULL;
	struct rspamd_rcl_struct_parser *pd = ud;
	struct rspamd_fuzzy_storage_ctx *ctx;

	ctx = pd->user_struct;

	if (ucl_object_type (obj) != UCL_OBJECT) {
		g_set_error (err, g_quark_try_string ("fuzzy"), 100,
				"mirror/slave option must be an object");

		return FALSE;
	}

	elt = ucl_object_lookup (obj, "name");
	if (elt == NULL) {
		g_set_error (err, g_quark_try_string ("fuzzy"), 100,
				"mirror option must have some name definition");

		return FALSE;
	}

	up = g_slice_alloc0 (sizeof (*up));
	up->name = g_strdup (ucl_object_tostring (elt));

	elt = ucl_object_lookup (obj, "key");
	if (elt != NULL) {
		up->key = rspamd_pubkey_from_base32 (ucl_object_tostring (elt), 0,
				RSPAMD_KEYPAIR_KEX, RSPAMD_CRYPTOBOX_MODE_25519);
	}

	if (up->key == NULL) {
		g_set_error (err, g_quark_try_string ("fuzzy"), 100,
				"cannot read mirror key");

		goto err;
	}

	elt = ucl_object_lookup (obj, "hosts");

	if (elt == NULL) {
		g_set_error (err, g_quark_try_string ("fuzzy"), 100,
				"mirror option must have some hosts definition");

		goto err;
	}

	up->u = rspamd_upstreams_create (ctx->cfg->ups_ctx);
	if (!rspamd_upstreams_from_ucl (up->u, elt, 11335, NULL)) {
		g_set_error (err,  g_quark_try_string ("fuzzy"), 100,
				"mirror has bad hosts definition");

		goto err;
	}

	g_ptr_array_add (ctx->mirrors, up);

	return TRUE;

err:

	if (up) {
		g_free (up->name);
		rspamd_upstreams_destroy (up->u);

		if (up->key) {
			rspamd_pubkey_unref (up->key);
		}

		g_slice_free1 (sizeof (*up), up);
	}

	return FALSE;
}

static gboolean
fuzzy_storage_parse_master_flags (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	const ucl_object_t *cur;
	struct rspamd_rcl_struct_parser *pd = ud;
	struct rspamd_fuzzy_storage_ctx *ctx;
	ucl_object_iter_t it = NULL;
	gulong remote_flag;
	gint64 local_flag;

	ctx = pd->user_struct;

	if (ucl_object_type (obj) != UCL_OBJECT) {
		g_set_error (err, g_quark_try_string ("fuzzy"), 100,
				"master_flags option must be an object");

		return FALSE;
	}

	while ((cur = ucl_iterate_object (obj, &it, true)) != NULL) {
		if (rspamd_strtoul (cur->key, cur->keylen, &remote_flag) &&
				ucl_object_toint_safe (cur, &local_flag)) {
			g_hash_table_insert (ctx->master_flags, GUINT_TO_POINTER (remote_flag),
					GUINT_TO_POINTER (local_flag));
		}
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
		keystat->last_ips = rspamd_lru_hash_new_full (1024,
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

	ctx->magic = rspamd_fuzzy_storage_magic;
	ctx->sync_timeout = DEFAULT_SYNC_TIMEOUT;
	ctx->master_timeout = DEFAULT_MASTER_TIMEOUT;
	ctx->expire = DEFAULT_EXPIRE;
	ctx->keypair_cache_size = DEFAULT_KEYPAIR_CACHE_SIZE;
	ctx->keys = g_hash_table_new_full (fuzzy_kp_hash, fuzzy_kp_equal,
			NULL, fuzzy_key_dtor);
	ctx->master_flags = g_hash_table_new (g_direct_hash, g_direct_equal);
	ctx->errors_ips = rspamd_lru_hash_new_full (1024,
			(GDestroyNotify) rspamd_inet_address_destroy, g_free,
			rspamd_inet_address_hash, rspamd_inet_address_equal);
	ctx->cfg = cfg;
	ctx->mirrors = g_ptr_array_new ();

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
			rspamd_rcl_parse_struct_ucl,
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

	rspamd_rcl_register_worker_option (cfg,
			type,
			"master_timeout",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, master_timeout),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"Master protocol IO timeout");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"sync_keypair",
			rspamd_rcl_parse_struct_keypair,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, sync_keypair),
			0,
			"Encryption key for master/slave updates");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"masters",
			rspamd_rcl_parse_struct_ucl,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, masters_map),
			0,
			"Allow master/slave updates from the following IP addresses");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"master_key",
			rspamd_rcl_parse_struct_pubkey,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, master_key),
			0,
			"Allow master/slave updates merely using the specified key");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"mirror",
			fuzzy_storage_parse_mirror,
			ctx,
			0,
			RSPAMD_CL_FLAG_MULTIPLE,
			"List of slave hosts");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"slave",
			fuzzy_storage_parse_mirror,
			ctx,
			0,
			RSPAMD_CL_FLAG_MULTIPLE,
			"List of slave hosts");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"master_flags",
			fuzzy_storage_parse_master_flags,
			ctx,
			0,
			0,
			"Map of flags in form master_flags = { master_flag = local_flag; ... }; ");

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
		if (errno == EINTR) {
			rspamd_fuzzy_peer_io (fd, what, d);
			return;
		}
		if (errno != EAGAIN) {
			msg_err ("cannot read command from peers: %s", strerror (errno));
		}
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
	struct rspamd_worker_listen_socket *ls;
	struct event *accept_events;
	gdouble next_check;

	ctx->peer_fd = rep_fd;

	if (rep_fd == -1) {
		msg_err ("cannot receive peer fd from the main process");
		exit (EXIT_FAILURE);
	}
	else {
		rspamd_socket_nonblocking (rep_fd);
	}

	/* Start listening */
	cur = worker->cf->listen_socks;
	while (cur) {
		ls = cur->data;

		if (ls->fd != -1) {
			if (ls->type == RSPAMD_WORKER_SOCKET_UDP) {
				accept_events = g_slice_alloc0 (sizeof (struct event) * 2);
				event_set (&accept_events[0], ls->fd, EV_READ | EV_PERSIST,
						accept_fuzzy_socket, worker);
				event_base_set (ctx->ev_base, &accept_events[0]);
				event_add (&accept_events[0], NULL);
				worker->accept_events = g_list_prepend (worker->accept_events,
						accept_events);
			}
			else if (worker->index == 0) {
				/* We allow TCP listeners only for a update worker */
				accept_events = g_slice_alloc0 (sizeof (struct event) * 2);
				event_set (&accept_events[0], ls->fd, EV_READ | EV_PERSIST,
						accept_fuzzy_mirror_socket, worker);
				event_base_set (ctx->ev_base, &accept_events[0]);
				event_add (&accept_events[0], NULL);
				worker->accept_events = g_list_prepend (worker->accept_events,
						accept_events);
			}
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
	struct rspamd_config *cfg = worker->srv->cfg;

	ctx->ev_base = rspamd_prepare_worker (worker,
			"fuzzy",
			NULL);
	ctx->peer_fd = -1;
	double_to_tv (ctx->master_timeout, &ctx->master_io_tv);

	/*
	 * Open DB and perform VACUUM
	 */
	if ((ctx->backend = rspamd_fuzzy_backend_open (ctx->hashfile, TRUE, &err)) == NULL) {
		msg_err ("cannot open backend: %e", err);
		g_error_free (err);
		exit (EXIT_SUCCESS);
	}

	ctx->stat.fuzzy_hashes = rspamd_fuzzy_backend_count (ctx->backend);

	if (ctx->keypair_cache_size > 0) {
		/* Create keypairs cache */
		ctx->keypair_cache = rspamd_keypair_cache_new (ctx->keypair_cache_size);
	}

	if (worker->index == 0) {
		rspamd_fuzzy_backend_sync (ctx->backend, ctx->expire, TRUE);
	}

	if (ctx->mirrors && ctx->mirrors->len != 0) {
		if (ctx->sync_keypair == NULL) {
			GString *pk_str = NULL;

			ctx->sync_keypair = rspamd_keypair_new (RSPAMD_KEYPAIR_KEX,
					RSPAMD_CRYPTOBOX_MODE_25519);
			pk_str = rspamd_keypair_print (ctx->sync_keypair,
								RSPAMD_KEYPAIR_COMPONENT_PK|RSPAMD_KEYPAIR_BASE32);
			msg_warn_config ("generating new temporary keypair for communicating"
					" with slave hosts, pk is %s", pk_str->str);
			g_string_free (pk_str, TRUE);
		}
	}

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
				&ctx->update_ips, NULL);
	}
	if (ctx->masters_map != NULL) {
		rspamd_config_radix_from_ucl (worker->srv->cfg, ctx->masters_map,
				"Allow fuzzy master/slave updates from specified addresses",
				&ctx->master_ips, NULL);
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

	rspamd_srv_send_command (worker, ctx->ev_base, &srv_cmd, -1,
			fuzzy_peer_rep, ctx);

	event_base_loop (ctx->ev_base, 0);
	rspamd_worker_block_signals ();

	if (worker->index == 0) {
		rspamd_fuzzy_process_updates_queue (ctx, local_db_name);
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
