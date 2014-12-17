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
#include "main.h"
#include "protocol.h"
#include "upstream.h"
#include "cfg_file.h"
#include "url.h"
#include "message.h"
#include "fuzzy.h"
#include "bloom.h"
#include "map.h"
#include "fuzzy_storage.h"

#include <lmdb.h>

/* This number is used as limit while comparing two fuzzy hashes, this value can vary from 0 to 100 */
#define LEV_LIMIT 99
/* This number is used as limit while we are making decision to write new hash file or not */
#define DEFAULT_MOD_LIMIT 10000
/* This number is used as expire time in seconds for cache items  (2 days) */
#define DEFAULT_EXPIRE 172800L
/* Resync value in seconds */
#define SYNC_TIMEOUT 60
/* Number of hash buckets */
#define BUCKETS 1024
/* Number of insuccessfull bind retries */
#define MAX_RETRIES 40
/* Weight of hash to consider it frequent */
#define DEFAULT_FREQUENT_SCORE 100
/* Magic sequence for hashes file */
#define FUZZY_FILE_MAGIC "rsh"
/* Current version of fuzzy hash file format */
#define CURRENT_FUZZY_VERSION 1

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

static GHashTable *static_hash;
static rspamd_bloom_filter_t *bf;

/* Number of cache modifications */
static guint32 mods = 0;
/* For evtimer */
static struct timeval tmv;
static struct event tev;
static struct rspamd_stat *server_stat;

struct rspamd_fuzzy_storage_ctx {
	char *hashfile;
	gdouble expire;
	guint32 frequent_score;
	guint32 max_mods;
	radix_compressed_t *update_ips;
	gchar *update_map;
	struct event_base *ev_base;
	gboolean legacy;

	/* Legacy portions */
	rspamd_rwlock_t *tree_lock;
	rspamd_mutex_t *update_mtx;
	GCond *update_cond;
	GThread *update_thread;

	/* lmdb interface */
	MDB_env *env;
};

struct rspamd_legacy_fuzzy_node {
	gint32 value;
	gint32 flag;
	guint64 time;
	rspamd_fuzzy_t h;
};

struct fuzzy_session {
	struct rspamd_worker *worker;
	union {
		struct legacy_fuzzy_cmd legacy;
		struct rspamd_fuzzy_cmd current;
	} cmd;
	gint fd;
	u_char *pos;
	guint64 time;
	rspamd_inet_addr_t addr;
	struct rspamd_fuzzy_storage_ctx *ctx;
};

extern sig_atomic_t wanna_die;

static GQuark
rspamd_fuzzy_quark(void)
{
	return g_quark_from_static_string ("fuzzy-storage");
}

static void
legacy_fuzzy_node_free (gpointer n)
{
	struct rspamd_legacy_fuzzy_node *node = (struct rspamd_legacy_fuzzy_node *)n;

	g_slice_free1 (sizeof (struct rspamd_legacy_fuzzy_node), node);
}

/**
 * Expire nodes from list (need to be called in tree write lock)
 * @param to_expire nodes that should be removed (if judy it is an array of nodes,
 * and it is array of GList * otherwise)
 * @param expired_num number of elements to expire
 * @param ctx context
 */
static void
legacy_expire_nodes (gpointer *to_expire, gint expired_num,
	struct rspamd_fuzzy_storage_ctx *ctx)
{
	gint i;
	struct rspamd_legacy_fuzzy_node *node;

	for (i = 0; i < expired_num; i++) {
		node = (struct rspamd_legacy_fuzzy_node *)to_expire[i];
		if (node->time != INVALID_NODE_TIME) {
			server_stat->fuzzy_hashes_expired++;
		}
		server_stat->fuzzy_hashes--;
		rspamd_bloom_del (bf, node->h.hash_pipe);
		g_hash_table_remove (static_hash, &node->h);
	}
}

static gpointer
rspamd_fuzzy_storage_sync_cb (gpointer ud)
{
	static const int max_expired = 8192;
	struct rspamd_worker *wrk = ud;
	gint fd, expired_num = 0;
	gchar *filename, header[4];
	struct rspamd_legacy_fuzzy_node *node;
	gpointer *nodes_expired = NULL;
	guint64 expire, now;
	struct rspamd_fuzzy_storage_ctx *ctx;
	GHashTableIter iter;

	ctx = wrk->ctx;

	for (;;) {

		rspamd_mutex_lock (ctx->update_mtx);

		/* Check for modifications */
		while (mods < ctx->max_mods && !wanna_die) {
			rspamd_cond_wait (ctx->update_cond, ctx->update_mtx);
		}

		msg_info ("syncing fuzzy hash storage");
		if (ctx->legacy) {
			filename = ctx->hashfile;
			if (filename == NULL ) {
				rspamd_mutex_unlock (ctx->update_mtx);
				if (wanna_die) {
					return NULL;
				}
				continue;
			}
			expire = ctx->expire;

			if ((fd = open (filename, O_WRONLY | O_TRUNC | O_CREAT,
					S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH)) == -1) {
				msg_err (
						"cannot create hash file %s: %s", filename,
						strerror (errno));
				rspamd_mutex_unlock (ctx->update_mtx);
				if (wanna_die) {
					return NULL;
				}
				continue;
			}

			(void) rspamd_file_lock (fd, FALSE);

			now = (guint64) time (NULL );

			/* Fill header */
			memcpy (header, FUZZY_FILE_MAGIC, 3);
			header[3] = (gchar) CURRENT_FUZZY_VERSION;
			if (write (fd, header, sizeof(header)) == -1) {
				msg_err (
						"cannot write file %s while writing header: %s",
						filename,
						strerror (errno));
				goto end;
			}

			rspamd_rwlock_reader_lock (ctx->tree_lock);
			g_hash_table_iter_init (&iter, static_hash);

			while (g_hash_table_iter_next (&iter, NULL, (void **)&node)) {
				if (node->time == INVALID_NODE_TIME ||
						now - node->time > expire) {
					if (nodes_expired == NULL) {
						nodes_expired = g_malloc (
								max_expired * sizeof (gpointer));
					}

					if (expired_num < max_expired) {
						nodes_expired[expired_num++] = node;
					}
					continue;
				}
				if (write (fd, node, sizeof (struct rspamd_legacy_fuzzy_node))
						== -1) {
					msg_err ("cannot write file %s: %s", filename,
							strerror (errno));
					goto end;
				}
			}
			rspamd_rwlock_reader_unlock (ctx->tree_lock);

			/* Now try to expire some nodes */
			if (expired_num > 0) {
				rspamd_rwlock_writer_lock (ctx->tree_lock);
				legacy_expire_nodes (nodes_expired, expired_num, ctx);
				rspamd_rwlock_writer_unlock (ctx->tree_lock);
			}
			mods = 0;
			end:
			if (nodes_expired != NULL) {
				g_free (nodes_expired);
			}
			(void) rspamd_file_unlock (fd, FALSE);
			close (fd);
		}
		else {
			mdb_env_sync (ctx->env, 0);
		}

		rspamd_mutex_unlock (ctx->update_mtx);
		if (wanna_die) {
			break;
		}
	}

	return NULL;
}

static void
sigterm_handler (void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)arg;
	struct rspamd_fuzzy_storage_ctx *ctx;

	ctx = worker->ctx;
	rspamd_mutex_lock (ctx->update_mtx);
	mods = ctx->max_mods + 1;
	g_cond_signal (ctx->update_cond);
	rspamd_mutex_unlock (ctx->update_mtx);
}

/*
 * Config reload is designed by sending sigusr to active workers and pending shutdown of them
 */
static void
sigusr2_handler (void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)arg;
	struct rspamd_fuzzy_storage_ctx *ctx;

	ctx = worker->ctx;
	rspamd_mutex_lock (ctx->update_mtx);
	mods = ctx->max_mods + 1;
	g_cond_signal (ctx->update_cond);
	rspamd_mutex_unlock (ctx->update_mtx);
}

static gboolean
legacy_read_db (struct rspamd_worker *wrk)
{
	gint r, fd, version = 0;
	struct stat st;
	gchar *filename, header[4];
	gboolean touch_stat = TRUE;
	struct rspamd_legacy_fuzzy_node *node;
	struct rspamd_fuzzy_storage_ctx *ctx = wrk->ctx;
	struct {
		gint32 value;
		guint64 time;
		rspamd_fuzzy_t h;
	}                               legacy_node;

	if (server_stat->fuzzy_hashes != 0) {
		touch_stat = FALSE;
	}

	filename = ctx->hashfile;
	if (filename == NULL) {
		return FALSE;
	}

	if ((fd = open (filename, O_RDONLY)) == -1) {
		msg_err ("cannot open hash file %s: %s", filename, strerror (errno));
		return FALSE;
	}

	(void)rspamd_file_lock (fd, FALSE);

	fstat (fd, &st);

	/* First of all try to read magic and version number */
	if ((r = read (fd, header, sizeof (header))) == sizeof (header)) {
		if (memcmp (header, FUZZY_FILE_MAGIC, sizeof (header) - 1) == 0) {
			/* We have version in last byte of header */
			version = (gint)header[3];
			if (version > CURRENT_FUZZY_VERSION) {
				msg_err ("unsupported version of fuzzy hash file: %d", version);
				close (fd);
				return FALSE;
			}
			msg_info (
				"reading fuzzy hashes storage file of version %d of size %d",
				version,
				(gint)(st.st_size -
				sizeof (header)) / sizeof (struct rspamd_legacy_fuzzy_node));
		}
		else {
			/* Old version */
			version = 0;
			msg_info (
				"got old version of fuzzy hashes storage, it would be converted to new version %d automatically",
				CURRENT_FUZZY_VERSION);
			/* Rewind file */
			(void)lseek (fd, 0, SEEK_SET);
		}
	}

	for (;; ) {
		node = g_slice_alloc (sizeof (struct rspamd_legacy_fuzzy_node));
		if (version == 0) {
			r = read (fd, &legacy_node, sizeof (legacy_node));
			if (r != sizeof (legacy_node)) {
				break;
			}
			node->value = legacy_node.value;
			node->time = legacy_node.time;
			memcpy (&node->h, &legacy_node.h, sizeof (rspamd_fuzzy_t));
			node->flag = 0;
		}
		else {
			r = read (fd, node, sizeof (struct rspamd_legacy_fuzzy_node));
			if (r != sizeof (struct rspamd_legacy_fuzzy_node)) {
				break;
			}
		}
		g_hash_table_insert (static_hash, &node->h, node);
		rspamd_bloom_add (bf, node->h.hash_pipe);
		if (touch_stat) {
			server_stat->fuzzy_hashes++;
		}
	}

	(void)rspamd_file_unlock (fd, FALSE);
	close (fd);

	if (r > 0) {
		msg_warn ("ignore garbage at the end of file, length of garbage: %d",
			r);
	}
	else if (r == -1) {
		msg_err ("cannot open read file %s: %s", filename, strerror (errno));
		return FALSE;
	}

	return TRUE;
}

static inline struct rspamd_legacy_fuzzy_node *
legacy_check_node (GQueue *hash, rspamd_fuzzy_t *s, gint update_value,
	guint64 time, struct rspamd_fuzzy_storage_ctx *ctx)
{
	struct rspamd_legacy_fuzzy_node *h;

	h = g_hash_table_lookup (static_hash, s);
	if (h != NULL) {
		if (h->time == INVALID_NODE_TIME) {
			/* Node is expired */
			return NULL;
		}
		else if (update_value == 0 && time - h->time > ctx->expire) {
			h->time = INVALID_NODE_TIME;
			server_stat->fuzzy_hashes_expired++;
			return NULL;
		}
		else if (h->h.block_size== s->block_size) {
			msg_debug ("fuzzy hash was found in tree");
			if (update_value) {
				h->value += update_value;
			}
			return h;
		}
	}

	return NULL;
}

static gint
legacy_check_cmd (struct legacy_fuzzy_cmd *cmd,
	gint *flag,
	guint64 time,
	struct rspamd_fuzzy_storage_ctx *ctx)
{
	rspamd_fuzzy_t s;
	struct rspamd_legacy_fuzzy_node *h;


	if (!rspamd_bloom_check (bf, cmd->hash)) {
		return 0;
	}

	memcpy (s.hash_pipe, cmd->hash, sizeof (s.hash_pipe));
	s.block_size = cmd->blocksize;

	rspamd_rwlock_reader_lock (ctx->tree_lock);
	h = legacy_check_node (NULL, &s, 0, time, ctx);
	rspamd_rwlock_reader_unlock (ctx->tree_lock);

	if (h == NULL) {
		return 0;
	}
	else {
		*flag = h->flag;
		return h->value;
	}
}

static struct rspamd_legacy_fuzzy_node *
legacy_add_node (struct legacy_fuzzy_cmd *cmd,
		guint64 time,
		struct rspamd_fuzzy_storage_ctx *ctx)
{
	struct rspamd_legacy_fuzzy_node *h;

	h = g_slice_alloc (sizeof (struct rspamd_legacy_fuzzy_node));
	memcpy (&h->h.hash_pipe, &cmd->hash, sizeof (cmd->hash));
	h->h.block_size = cmd->blocksize;
	h->time = time;
	h->value = cmd->value;
	h->flag = cmd->flag;
	g_hash_table_insert (static_hash, &h->h, h);
	rspamd_bloom_add (bf, cmd->hash);

	return h;
}

static gboolean
legacy_update_hash (struct legacy_fuzzy_cmd *cmd,
	guint64 time,
	struct rspamd_fuzzy_storage_ctx *ctx)
{
	rspamd_fuzzy_t s;
	struct rspamd_legacy_fuzzy_node *n;

	memcpy (s.hash_pipe, cmd->hash, sizeof (s.hash_pipe));
	s.block_size = cmd->blocksize;
	mods++;

	rspamd_rwlock_writer_lock (ctx->tree_lock);
	n = legacy_check_node (NULL, &s, cmd->value, time, ctx);
	if (n == NULL) {
		/* Bloom false positive */
		n = legacy_add_node (cmd, time, ctx);
	}
	rspamd_rwlock_writer_unlock (ctx->tree_lock);

	if (n != NULL) {
		n->time = time;
		return TRUE;
	}
	return FALSE;
}

static gboolean
legacy_write_cmd (struct legacy_fuzzy_cmd *cmd,
	guint64 time,
	struct rspamd_fuzzy_storage_ctx *ctx)
{
	if (rspamd_bloom_check (bf, cmd->hash)) {
		if (legacy_update_hash (cmd, time, ctx)) {
			return TRUE;
		}
	}

	rspamd_rwlock_writer_lock (ctx->tree_lock);
	legacy_add_node (cmd, time, ctx);
	rspamd_rwlock_writer_unlock (ctx->tree_lock);

	mods++;
	server_stat->fuzzy_hashes++;
	msg_info ("fuzzy hash was successfully added");

	return TRUE;
}

static gboolean
legacy_delete_hash (GQueue *hash, rspamd_fuzzy_t *s,
	struct rspamd_fuzzy_storage_ctx *ctx)
{
	gboolean res = FALSE;

	rspamd_rwlock_writer_lock (ctx->tree_lock);
	if (g_hash_table_remove (static_hash, s)) {
		rspamd_bloom_del (bf, s->hash_pipe);
		msg_info ("fuzzy hash was successfully deleted");
		server_stat->fuzzy_hashes--;
		mods++;
	}
	rspamd_rwlock_writer_unlock (ctx->tree_lock);

	return res;

}

static gboolean
legacy_delete_cmd (struct legacy_fuzzy_cmd *cmd,
	guint64 time,
	struct rspamd_fuzzy_storage_ctx *ctx)
{
	rspamd_fuzzy_t s;

	if (!rspamd_bloom_check (bf, cmd->hash)) {
		return FALSE;
	}

	memcpy (s.hash_pipe, cmd->hash, sizeof (s.hash_pipe));
	s.block_size = cmd->blocksize;

	return legacy_delete_hash (NULL, &s, ctx);
}

/**
 * Checks the client's address for update commands permission
 */
static gboolean
check_fuzzy_client (struct fuzzy_session *session)
{
	if (session->ctx->update_ips != NULL) {
		if (radix_find_compressed_addr (session->ctx->update_ips,
			&session->addr) == RADIX_NO_VALUE) {
			return FALSE;
		}
	}

	return TRUE;
}

#define LEGACY_CMD_PROCESS(x)                                                  \
	do {                                                                       \
		if (legacy_ ## x ## _cmd (&session->cmd.legacy, session->time,         \
			session->worker->ctx)) {                                           \
			if (sendto (session->fd, "OK" CRLF, sizeof ("OK" CRLF) - 1, 0,     \
					&session->addr.addr.sa, session->addr.slen) == -1) {       \
				msg_err ("error while writing reply: %s", strerror (errno));   \
			}                                                                  \
		}                                                                      \
		else {                                                                 \
			if (sendto (session->fd, "ERR" CRLF, sizeof ("ERR" CRLF) - 1, 0,   \
					&session->addr.addr.sa, session->addr.slen) == -1) {       \
				msg_err ("error while writing reply: %s", strerror (errno));   \
			}                                                                  \
		}                                                                      \
	} while (0)

static void
legacy_fuzzy_cmd (struct fuzzy_session *session)
{
	gint r, flag = 0;
	gchar buf[64];

	switch (session->cmd.legacy.cmd) {
	case FUZZY_CHECK:
		r = legacy_check_cmd (&session->cmd.legacy,
				&flag,
				session->time,
				session->worker->ctx);
		if (r != 0) {
			r = rspamd_snprintf (buf, sizeof (buf), "OK %d %d" CRLF, r, flag);
			if (sendto (session->fd, buf, r, 0,
				&session->addr.addr.sa, session->addr.slen) == -1) {
				msg_err ("error while writing reply: %s", strerror (errno));
			}
		}
		else {
			if (sendto (session->fd, "ERR" CRLF, sizeof ("ERR" CRLF) - 1, 0,
					&session->addr.addr.sa, session->addr.slen) == -1) {
				msg_err ("error while writing reply: %s", strerror (errno));
			}
		}
		break;
	case FUZZY_WRITE:
		if (!check_fuzzy_client (session)) {
			msg_info ("try to insert a hash from an untrusted address");
			if (sendto (session->fd, "UNAUTH" CRLF, sizeof ("UNAUTH" CRLF) - 1,
				0,
				&session->addr.addr.sa, session->addr.slen) == -1) {
				msg_err ("error while writing reply: %s", strerror (errno));
			}
		}
		else {
			LEGACY_CMD_PROCESS (write);
		}
		break;
	case FUZZY_DEL:
		if (!check_fuzzy_client (session)) {
			msg_info ("try to delete a hash from an untrusted address");
			if (sendto (session->fd, "UNAUTH" CRLF, sizeof ("UNAUTH" CRLF) - 1,
				0,
				&session->addr.addr.sa, session->addr.slen) == -1) {
				msg_err ("error while writing reply: %s", strerror (errno));
			}
		}
		else {
			LEGACY_CMD_PROCESS (delete);
		}
		break;
	default:
		if (sendto (session->fd, "ERR" CRLF, sizeof ("ERR" CRLF) - 1, 0,
				&session->addr.addr.sa, session->addr.slen) == -1) {
			msg_err ("error while writing reply: %s", strerror (errno));
		}
		break;
	}
}

#undef LEGACY_CMD_PROCESS

/*
 * MDB Interface
 */

static gboolean
rspamd_fuzzy_storage_open_db (struct rspamd_fuzzy_storage_ctx *ctx, GError **err)
{
	gchar *dir;
	gint rc;

	if (ctx->hashfile == NULL) {
		g_set_error (err, rspamd_fuzzy_quark(), 500, "Cannot work without file");
		return FALSE;
	}

	dir = g_path_get_dirname (ctx->hashfile);
	if (dir == NULL || access (dir, W_OK) == -1) {
		g_set_error (err, rspamd_fuzzy_quark(), errno, "Cannot access directory: %s",
				strerror (errno));
		return FALSE;
	}

	mdb_env_create (&ctx->env);

	if ((rc = mdb_env_open (ctx->env, dir, MDB_NOSYNC, 0600)) != 0) {
		g_set_error (err, rspamd_fuzzy_quark(), errno, "Cannot open mdb_env: %s",
						mdb_strerror (rc));
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
	struct rspamd_fuzzy_storage_ctx *ctx;
	struct fuzzy_session session;
	ssize_t r;
	struct {
		u_char cmd;
		guint32 blocksize;
		gint32 value;
		u_char hash[FUZZY_HASHLEN];
	} legacy_cmd;
	guint8 buf[2048];

	ctx = worker->ctx;
	session.worker = worker;
	session.fd = fd;
	session.pos = buf;
	session.addr.slen = sizeof (session.addr.addr);
	session.ctx = worker->ctx;
	session.time = (guint64)time (NULL);

	/* Got some data */
	if (what == EV_READ) {
		while ((r = recvfrom (fd, session.pos, sizeof (buf), 0,
			&session.addr.addr.sa, &session.addr.slen)) == -1) {
			if (errno == EINTR) {
				continue;
			}
			msg_err ("got error while reading from socket: %d, %s",
				errno,
				strerror (errno));
			return;
		}
		session.addr.af = session.addr.addr.sa.sa_family;
		if (r == sizeof (struct legacy_fuzzy_cmd) && ctx->legacy) {
			/* Assume that the whole command was read */
			legacy_fuzzy_cmd (&session);
		}
		else if (r == sizeof (legacy_cmd) && ctx->legacy) {
			/* Process requests from old rspamd */
			memcpy (&legacy_cmd, session.pos, sizeof (legacy_cmd));
			session.cmd.legacy.cmd = legacy_cmd.cmd;
			session.cmd.legacy.blocksize = legacy_cmd.blocksize;
			session.cmd.legacy.value = legacy_cmd.value;
			session.cmd.legacy.flag = 0;
			memcpy (session.cmd.legacy.hash, legacy_cmd.hash,
				sizeof (legacy_cmd.hash));
			legacy_fuzzy_cmd (&session);
		}
		else if (r == sizeof (struct rspamd_fuzzy_cmd) && !ctx->legacy) {
			/* We have the second version of request */
			memcpy (&session.cmd.current, buf, sizeof (session.cmd.current));
			if (session.cmd.current.size == RSPAMD_SHINGLE_SIZE &&
				session.cmd.current.version == RSPAMD_FUZZY_VERSION) {
				/* XXX: Process command */
			}
			else {
				/* XXX: Reply error */
			}
		}
		else {
			/* Discard input */

		}
	}
}

static void
sync_callback (gint fd, short what, void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)arg;
	struct rspamd_fuzzy_storage_ctx *ctx;

	ctx = worker->ctx;
	/* Timer event */
	evtimer_set (&tev, sync_callback, worker);
	event_base_set (ctx->ev_base, &tev);
	/* Plan event with jitter */
	tmv.tv_sec = SYNC_TIMEOUT + SYNC_TIMEOUT * g_random_double ();
	tmv.tv_usec = 0;
	evtimer_add (&tev, &tmv);

	rspamd_mutex_lock (ctx->update_mtx);
	g_cond_signal (ctx->update_cond);
	rspamd_mutex_unlock (ctx->update_mtx);
}

gpointer
init_fuzzy (struct rspamd_config *cfg)
{
	struct rspamd_fuzzy_storage_ctx *ctx;
	GQuark type;

	type = g_quark_try_string ("fuzzy");

	ctx = g_malloc0 (sizeof (struct rspamd_fuzzy_storage_ctx));

	ctx->max_mods = DEFAULT_MOD_LIMIT;
	ctx->expire = DEFAULT_EXPIRE;

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

	rspamd_rcl_register_worker_option (cfg, type, "legacy",
		rspamd_rcl_parse_struct_boolean, ctx,
		G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, legacy), 0);

	/* Legacy options */
	rspamd_rcl_register_worker_option (cfg, type, "max_mods",
		rspamd_rcl_parse_struct_integer, ctx,
		G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx,
		max_mods), RSPAMD_CL_FLAG_INT_32);

	rspamd_rcl_register_worker_option (cfg, type, "frequent_score",
		rspamd_rcl_parse_struct_integer, ctx,
		G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx,
		frequent_score), RSPAMD_CL_FLAG_INT_32);

	rspamd_rcl_register_worker_option (cfg, type, "expire",
		rspamd_rcl_parse_struct_time, ctx,
		G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx,
		expire), RSPAMD_CL_FLAG_TIME_FLOAT);


	rspamd_rcl_register_worker_option (cfg, type, "allow_update",
		rspamd_rcl_parse_struct_string, ctx,
		G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, update_map), 0);


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
	struct rspamd_worker_signal_handler *sigh;

	ctx->ev_base = rspamd_prepare_worker (worker,
			"fuzzy",
			accept_fuzzy_socket);
	server_stat = worker->srv->stat;

	/* Custom SIGUSR2 handler */
	sigh = g_hash_table_lookup (worker->signal_events, GINT_TO_POINTER (SIGUSR2));
	sigh->post_handler = sigusr2_handler;
	sigh->handler_data = worker;

	/* Sync on termination */
	sigh = g_hash_table_lookup (worker->signal_events, GINT_TO_POINTER (SIGTERM));
	sigh->post_handler = sigterm_handler;
	sigh->handler_data = worker;
	sigh = g_hash_table_lookup (worker->signal_events, GINT_TO_POINTER (SIGINT));
	sigh->post_handler = sigterm_handler;
	sigh->handler_data = worker;
	sigh = g_hash_table_lookup (worker->signal_events, GINT_TO_POINTER (SIGHUP));
	sigh->post_handler = sigterm_handler;
	sigh->handler_data = worker;

	if (ctx->legacy) {
		ctx->tree_lock = rspamd_rwlock_new ();
		ctx->update_mtx = rspamd_mutex_new ();
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
		ctx->update_cond = g_malloc0 (sizeof (GCond));
		g_cond_init (ctx->update_cond);
#else
		ctx->update_cond = g_cond_new ();
#endif
		static_hash = g_hash_table_new_full (rspamd_fuzzy_hash, rspamd_fuzzy_equal,
				NULL, legacy_fuzzy_node_free);

		/* Init bloom filter */
		bf = rspamd_bloom_create (2000000L, RSPAMD_DEFAULT_BLOOM_HASHES);
		/* Try to read hashes from file */
		if (!legacy_read_db (worker)) {
			msg_err (
					"cannot read hashes file, it can be created after save procedure");
		}
	}
	else {
		if (!rspamd_fuzzy_storage_open_db (ctx, &err)) {
			msg_err (err->message);
			g_error_free (err);
			exit (EXIT_FAILURE);
		}
	}

	/* Timer event */
	evtimer_set (&tev, sync_callback, worker);
	event_base_set (ctx->ev_base, &tev);
	/* Plan event with jitter */
	tmv.tv_sec = SYNC_TIMEOUT + SYNC_TIMEOUT * g_random_double ();
	tmv.tv_usec = 0;
	evtimer_add (&tev, &tmv);

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

	ctx->update_thread = rspamd_create_thread ("fuzzy update",
			rspamd_fuzzy_storage_sync_cb,
			worker,
			&err);
	if (ctx->update_thread == NULL) {
		msg_err ("error creating update thread: %s", err->message);
	}

	event_base_loop (ctx->ev_base, 0);

	if (ctx->update_thread != NULL) {
		g_thread_join (ctx->update_thread);
	}

	if (!ctx->legacy) {
		mdb_env_close (ctx->env);
	}

	rspamd_log_close (rspamd_main->logger);
	exit (EXIT_SUCCESS);
}
