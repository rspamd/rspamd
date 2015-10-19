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
#include "cryptobox.h"
#include "keypairs_cache.h"
#include "keypair_private.h"

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
	TRUE,                       /* Unique */
	TRUE,                       /* Threaded */
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
	/* Local keypair */
	gpointer key;
	struct rspamd_keypair_cache *keypair_cache;
	struct rspamd_fuzzy_backend *backend;
};

enum fuzzy_cmd_type {
	CMD_NORMAL,
	CMD_SHINGLE,
	CMD_ENCRYPTED_NORMAL,
	CMD_ENCRYPTED_SHINGLE
};

struct fuzzy_session {
	struct rspamd_worker *worker;

	union {
		struct rspamd_fuzzy_encrypted_shingle_cmd enc_shingle;
		struct rspamd_fuzzy_encrypted_cmd enc_normal;
		struct rspamd_fuzzy_cmd normal;
		struct rspamd_fuzzy_shingle_cmd shingle;
	} cmd;
	enum rspamd_fuzzy_epoch epoch;
	enum fuzzy_cmd_type cmd_type;
	gint fd;
	guint64 time;
	rspamd_inet_addr_t *addr;
	struct rspamd_fuzzy_storage_ctx *ctx;
	guchar nm[rspamd_cryptobox_MAX_NMBYTES];
};

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
rspamd_fuzzy_write_reply (struct fuzzy_session *session,
		gconstpointer data, gsize len)
{
	gssize r;

	r = rspamd_inet_address_sendto (session->fd, data, len, 0,
			session->addr);

	if (r == -1) {
		if (errno == EINTR) {
			rspamd_fuzzy_write_reply (session, data, len);
		}
		else {
			msg_err ("error while writing reply: %s", strerror (errno));
		}
	}
}

static void
rspamd_fuzzy_process_command (struct fuzzy_session *session)
{
	gboolean res = FALSE, encrypted = FALSE;
	struct rspamd_fuzzy_cmd *cmd;
	struct rspamd_fuzzy_encrypted_reply rep;
	struct rspamd_fuzzy_reply result;

	switch (session->cmd_type) {
	case CMD_NORMAL:
		cmd = &session->cmd.normal;
		break;
	case CMD_SHINGLE:
		cmd = &session->cmd.shingle.basic;
		break;
	case CMD_ENCRYPTED_NORMAL:
		cmd = &session->cmd.enc_normal.cmd;
		encrypted = TRUE;
		break;
	case CMD_ENCRYPTED_SHINGLE:
		cmd = &session->cmd.enc_shingle.cmd.basic;
		encrypted = TRUE;
		break;
	}

	if (cmd->cmd == FUZZY_CHECK) {
		result = rspamd_fuzzy_backend_check (session->ctx->backend, cmd,
				session->ctx->expire);
		/* XXX: actually, these updates are not atomic, but we don't care */
		server_stat->fuzzy_hashes_checked[session->epoch] ++;

		if (result.prob > 0.5) {
			server_stat->fuzzy_hashes_found[session->epoch] ++;
		}
	}
	else {
		result.flag = cmd->flag;
		if (rspamd_fuzzy_check_client (session)) {
			if (cmd->cmd == FUZZY_WRITE) {
				res = rspamd_fuzzy_backend_add (session->ctx->backend, cmd);
			}
			else {
				res = rspamd_fuzzy_backend_del (session->ctx->backend, cmd);
			}
			if (!res) {
				result.value = 404;
				result.prob = 0.0;
			}
			else {
				result.value = 0;
				result.prob = 1.0;
			}
		}
		else {
			result.value = 403;
			result.prob = 0.0;
		}

		server_stat->fuzzy_hashes = rspamd_fuzzy_backend_count (session->ctx->backend);
	}

	result.tag = cmd->tag;
	memcpy (&rep.rep, &result, sizeof (result));

	if (encrypted) {
		/* We need also to encrypt reply */
		ottery_rand_bytes (rep.hdr.nonce, sizeof (rep.hdr.nonce));
		rspamd_cryptobox_encrypt_nm_inplace ((guchar *)&rep.rep, sizeof (rep.rep),
				rep.hdr.nonce, session->nm, rep.hdr.mac);
		rspamd_fuzzy_write_reply (session, &rep, sizeof (rep));
	}
	else {
		rspamd_fuzzy_write_reply (session, &rep.rep, sizeof (rep.rep));
	}
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
	struct rspamd_http_keypair rk;

	if (s->ctx->key == NULL) {
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

	/* Now process keypair */
	memcpy (rk.pk, hdr->pubkey, sizeof (rk.pk));
	rspamd_keypair_cache_process (s->ctx->keypair_cache, s->ctx->key, &rk);

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

/*
 * Accept new connection and construct task
 */
static void
accept_fuzzy_socket (gint fd, short what, void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)arg;
	struct fuzzy_session session;
	gssize r;
	guint8 buf[512];

	session.worker = worker;
	session.fd = fd;
	session.ctx = worker->ctx;
	session.time = (guint64)time (NULL);

	/* Got some data */
	if (what == EV_READ) {
		worker->nconns++;

		while ((r = rspamd_inet_address_recvfrom (fd, buf, sizeof (buf), 0,
			&session.addr)) == -1) {
			if (errno == EINTR) {
				continue;
			}
			msg_err ("got error while reading from socket: %d, %s",
				errno,
				strerror (errno));
			return;
		}

		if (rspamd_fuzzy_cmd_from_wire (buf, r, &session)) {
			/* Check shingles count sanity */
			rspamd_fuzzy_process_command (&session);
		}
		else {
			/* Discard input */
			server_stat->fuzzy_hashes_checked[RSPAMD_FUZZY_EPOCH6] ++;
			msg_debug ("invalid fuzzy command of size %d received", r);
		}

		rspamd_inet_address_destroy (session.addr);
		worker->nconns --;
	}

	rspamd_explicit_memzero (session.nm, sizeof (session.nm));
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
			rspamd_rcl_parse_struct_keypair, ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, key), 0);

	rspamd_rcl_register_worker_option (cfg, type, "keypair_cache_size",
			rspamd_rcl_parse_struct_integer, ctx,
			G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, keypair_cache_size),
			RSPAMD_CL_FLAG_UINT);

	return ctx;
}

/*
 * Start worker process
 */
void
start_fuzzy (struct rspamd_worker *worker)
{
	struct rspamd_fuzzy_storage_ctx *ctx = worker->ctx;
	GError *err = NULL;
	gdouble next_check;

	ctx->ev_base = rspamd_prepare_worker (worker,
			"fuzzy",
			accept_fuzzy_socket);
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

	if (ctx->key && ctx->keypair_cache_size > 0) {
		/* Create keypairs cache */
		ctx->keypair_cache = rspamd_keypair_cache_new (ctx->keypair_cache_size);
	}

	rspamd_fuzzy_backend_sync (ctx->backend, ctx->expire, TRUE);
	/* Timer event */
	evtimer_set (&tev, sync_callback, worker);
	event_base_set (ctx->ev_base, &tev);
	/* Plan event with jitter */
	next_check = rspamd_time_jitter (ctx->sync_timeout, 0);
	double_to_tv (next_check, &tmv);
	evtimer_add (&tev, &tmv);

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

	event_base_loop (ctx->ev_base, 0);
	rspamd_worker_block_signals ();

	rspamd_fuzzy_backend_sync (ctx->backend, ctx->expire, TRUE);
	rspamd_fuzzy_backend_close (ctx->backend);
	rspamd_log_close (worker->srv->logger);

	if (ctx->keypair_cache) {
		rspamd_keypair_cache_destroy (ctx->keypair_cache);
	}
	if (ctx->key) {
		rspamd_http_connection_key_unref (ctx->key);
	}

	exit (EXIT_SUCCESS);
}
