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

static GQueue *hashes[BUCKETS];
static GQueue *frequent;
static GHashTable *static_hash;
static rspamd_bloom_filter_t *bf;

/* Number of cache modifications */
static guint32 mods = 0;
/* For evtimer */
static struct timeval tmv;
static struct event tev;
static struct rspamd_stat *server_stat;

struct rspamd_fuzzy_storage_ctx {
	gboolean strict_hash;
	char *hashfile;
	gdouble expire;
	guint32 frequent_score;
	guint32 max_mods;
	radix_compressed_t *update_ips;
	gchar *update_map;
	struct event_base *ev_base;
	rspamd_rwlock_t *tree_lock;
	rspamd_mutex_t *update_mtx;
	GCond *update_cond;
	GThread *update_thread;
};

struct rspamd_fuzzy_node {
	gint32 value;
	gint32 flag;
	guint64 time;
	fuzzy_hash_t h;
};

struct fuzzy_session {
	struct rspamd_worker *worker;
	struct fuzzy_cmd cmd;
	gint fd;
	u_char *pos;
	guint64 time;
	rspamd_inet_addr_t addr;
	struct rspamd_fuzzy_storage_ctx *ctx;
};

extern sig_atomic_t wanna_die;


static gint
compare_nodes (gconstpointer a, gconstpointer b, gpointer unused)
{
	const struct rspamd_fuzzy_node *n1 = a, *n2 = b;

	return n1->value - n2->value;
}

static void
rspamd_fuzzy_free_node (gpointer n)
{
	struct rspamd_fuzzy_node *node = (struct rspamd_fuzzy_node *)n;

	g_slice_free1 (sizeof (struct rspamd_fuzzy_node), node);
}

/**
 * Expire nodes from list (need to be called in tree write lock)
 * @param to_expire nodes that should be removed (if judy it is an array of nodes,
 * and it is array of GList * otherwise)
 * @param expired_num number of elements to expire
 * @param ctx context
 */
static void
expire_nodes (gpointer *to_expire, gint expired_num,
	struct rspamd_fuzzy_storage_ctx *ctx)
{
	gint i;
	struct rspamd_fuzzy_node *node;
	GList *cur;
	GQueue *head;

	for (i = 0; i < expired_num; i++) {
		if (ctx->strict_hash) {
			node = (struct rspamd_fuzzy_node *)to_expire[i];
			if (node->time != INVALID_NODE_TIME) {
				server_stat->fuzzy_hashes_expired++;
			}
			server_stat->fuzzy_hashes--;
			rspamd_bloom_del (bf, node->h.hash_pipe);
			g_hash_table_remove (static_hash, &node->h);
		}
		else {
			cur = (GList *)to_expire[i];
			node = (struct rspamd_fuzzy_node *)cur->data;
			head = hashes[node->h.block_size % BUCKETS];
			g_queue_delete_link (head, cur);
			rspamd_bloom_del (bf, node->h.hash_pipe);
			if (node->time != INVALID_NODE_TIME) {
				server_stat->fuzzy_hashes_expired++;
			}
			server_stat->fuzzy_hashes--;
			g_slice_free1 (sizeof(struct rspamd_fuzzy_node), node);
		}
	}
}

static gpointer
sync_cache (gpointer ud)
{
	static const int max_expired = 8192;
	struct rspamd_worker *wrk = ud;
	gint fd, i, expired_num = 0;
	gchar *filename, header[4];
	GList *cur;
	struct rspamd_fuzzy_node *node;
	gpointer *nodes_expired = NULL;
	guint64 expire, now;
	struct rspamd_fuzzy_storage_ctx *ctx;
	GHashTableIter iter;

	ctx = wrk->ctx;

	for (;; ) {

		rspamd_mutex_lock (ctx->update_mtx);

		/* Check for modifications */
		while (mods < ctx->max_mods && !wanna_die) {
			rspamd_cond_wait (ctx->update_cond, ctx->update_mtx);
		}

		msg_info ("syncing fuzzy hash storage");
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
				"cannot create hash file %s: %s", filename, strerror (errno));
			rspamd_mutex_unlock (ctx->update_mtx);
			if (wanna_die) {
				return NULL;
			}
			continue;
		}

		(void) lock_file (fd, FALSE);

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

		if (ctx->strict_hash) {
			rspamd_rwlock_reader_lock (ctx->tree_lock);
			g_hash_table_iter_init (&iter, static_hash);

			while (g_hash_table_iter_next (&iter, NULL, (void **)&node)) {
				if (node->time == INVALID_NODE_TIME || now - node->time >
					expire) {
					if (nodes_expired == NULL) {
						nodes_expired = g_malloc (
							max_expired * sizeof (gpointer));
					}

					if (expired_num < max_expired) {
						nodes_expired[expired_num++] = node;
					}
					continue;
				}
				if (write (fd, node, sizeof (struct rspamd_fuzzy_node)) == -1) {
					msg_err ("cannot write file %s: %s", filename,
						strerror (errno));
					goto end;
				}
			}
			rspamd_rwlock_reader_unlock (ctx->tree_lock);
		}
		else {
			rspamd_rwlock_reader_lock (ctx->tree_lock);
			cur = frequent->head;
			while (cur) {
				node = cur->data;
				if (write (fd, node, sizeof(struct rspamd_fuzzy_node)) == -1) {
					msg_err ("cannot write file %s: %s", filename,
						strerror (errno));
				}
				cur = g_list_next (cur);
			}
			for (i = 0; i < BUCKETS; i++) {
				cur = hashes[i]->head;
				while (cur) {
					node = cur->data;
					if (now - node->time > expire) {
						if (nodes_expired == NULL) {
							nodes_expired =
								g_malloc (max_expired * sizeof (gpointer));
						}

						if (expired_num < max_expired) {
							nodes_expired[expired_num++] = cur;
						}
						cur = g_list_next (cur);
						continue;
					}
					if (write (fd, node,
						sizeof(struct rspamd_fuzzy_node)) == -1) {
						msg_err (
							"cannot write file %s: %s", filename,
							strerror (errno));
						goto end;
					}
					cur = g_list_next (cur);
				}
			}
			rspamd_rwlock_reader_unlock (ctx->tree_lock);
		}

		/* Now try to expire some nodes */
		if (expired_num > 0) {
			rspamd_rwlock_writer_lock (ctx->tree_lock);
			expire_nodes (nodes_expired, expired_num, ctx);
			rspamd_rwlock_writer_unlock (ctx->tree_lock);
		}
		mods = 0;
end:
		if (nodes_expired != NULL) {
			g_free (nodes_expired);
		}
		(void) unlock_file (fd, FALSE);
		close (fd);

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
read_hashes_file (struct rspamd_worker *wrk)
{
	gint r, fd, i, version = 0;
	struct stat st;
	gchar *filename, header[4];
	gboolean touch_stat = TRUE;
	struct rspamd_fuzzy_node *node;
	struct rspamd_fuzzy_storage_ctx *ctx = wrk->ctx;
	struct {
		gint32 value;
		guint64 time;
		fuzzy_hash_t h;
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

	(void)lock_file (fd, FALSE);

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
				sizeof (header)) / sizeof (struct rspamd_fuzzy_node));
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
		node = g_slice_alloc (sizeof (struct rspamd_fuzzy_node));
		if (version == 0) {
			r = read (fd, &legacy_node, sizeof (legacy_node));
			if (r != sizeof (legacy_node)) {
				break;
			}
			node->value = legacy_node.value;
			node->time = legacy_node.time;
			memcpy (&node->h, &legacy_node.h, sizeof (fuzzy_hash_t));
			node->flag = 0;
		}
		else {
			r = read (fd, node, sizeof (struct rspamd_fuzzy_node));
			if (r != sizeof (struct rspamd_fuzzy_node)) {
				break;
			}
		}
		if (ctx->strict_hash) {
			g_hash_table_insert (static_hash, &node->h, node);
		}
		else {
			if (node->value > (gint)ctx->frequent_score) {
				g_queue_push_head (frequent, node);
			}
			else {
				g_queue_push_head (hashes[node->h.block_size % BUCKETS], node);
			}
		}
		rspamd_bloom_add (bf, node->h.hash_pipe);
		if (touch_stat) {
			server_stat->fuzzy_hashes++;
		}
	}

	if (!ctx->strict_hash) {
		/* Sort everything */
		g_queue_sort (frequent, compare_nodes, NULL);
		for (i = 0; i < BUCKETS; i++) {
			g_queue_sort (hashes[i], compare_nodes, NULL);
		}
	}

	(void)unlock_file (fd, FALSE);
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

static inline struct rspamd_fuzzy_node *
check_hash_node (GQueue *hash, fuzzy_hash_t *s, gint update_value,
	guint64 time, struct rspamd_fuzzy_storage_ctx *ctx)
{
	GList *cur;
	struct rspamd_fuzzy_node *h;
	gint prob = 0;

	if (ctx->strict_hash) {
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
	}
	else {
		cur = frequent->head;
		while (cur) {
			h = cur->data;
			if ((prob = fuzzy_compare_hashes (&h->h, s)) > LEV_LIMIT) {
				msg_info ("fuzzy hash was found, probability %d%%", prob);
				if (h->time == INVALID_NODE_TIME) {
					return NULL;
				}
				else if (update_value) {
					msg_info ("new hash weight: %d", h->value);
					h->value += update_value;
				}
				else if (time - h->time > ctx->expire) {
					h->time = INVALID_NODE_TIME;
					server_stat->fuzzy_hashes_expired++;
					return NULL;
				}
				return h;
			}
			cur = g_list_next (cur);
		}

		cur = hash->head;
		while (cur) {
			h = cur->data;
			if ((prob = fuzzy_compare_hashes (&h->h, s)) > LEV_LIMIT) {
				msg_info ("fuzzy hash was found, probability %d%%", prob);
				if (h->time == INVALID_NODE_TIME) {
					return NULL;
				}
				else if (update_value) {
					msg_info ("new hash weight: %d", h->value);
					h->value += update_value;
				}
				else if (time - h->time > ctx->expire) {
					h->time = INVALID_NODE_TIME;
					server_stat->fuzzy_hashes_expired++;
					return NULL;
				}
				if (h->value > (gint)ctx->frequent_score) {
					g_queue_unlink (hash, cur);
					g_queue_push_head_link (frequent, cur);
					msg_info ("moved hash to frequent list");
				}
				return h;
			}
			cur = g_list_next (cur);
		}
	}

	return NULL;
}

static gint
process_check_command (struct fuzzy_cmd *cmd,
	gint *flag,
	guint64 time,
	struct rspamd_fuzzy_storage_ctx *ctx)
{
	fuzzy_hash_t s;
	struct rspamd_fuzzy_node *h;


	if (!rspamd_bloom_check (bf, cmd->hash)) {
		return 0;
	}

	memcpy (s.hash_pipe, cmd->hash, sizeof (s.hash_pipe));
	s.block_size = cmd->blocksize;

	rspamd_rwlock_reader_lock (ctx->tree_lock);
	if (ctx->strict_hash) {
		h = check_hash_node (NULL, &s, 0, time, ctx);
	}
	else {
		h =
			check_hash_node (hashes[cmd->blocksize % BUCKETS], &s, 0, time,
				ctx);
	}
	rspamd_rwlock_reader_unlock (ctx->tree_lock);

	if (h == NULL) {
		return 0;
	}
	else {
		*flag = h->flag;
		return h->value;
	}
}

static struct rspamd_fuzzy_node *
add_hash_node (struct fuzzy_cmd *cmd,
		guint64 time,
		struct rspamd_fuzzy_storage_ctx *ctx)
{
	struct rspamd_fuzzy_node *h;

	h = g_slice_alloc (sizeof (struct rspamd_fuzzy_node));
	memcpy (&h->h.hash_pipe, &cmd->hash, sizeof (cmd->hash));
	h->h.block_size = cmd->blocksize;
	h->time = time;
	h->value = cmd->value;
	h->flag = cmd->flag;
	if (ctx->strict_hash) {
		g_hash_table_insert (static_hash, &h->h, h);
	}
	else {
		g_queue_push_head (hashes[cmd->blocksize % BUCKETS], h);
	}
	rspamd_bloom_add (bf, cmd->hash);

	return h;
}

static gboolean
update_hash (struct fuzzy_cmd *cmd,
	guint64 time,
	struct rspamd_fuzzy_storage_ctx *ctx)
{
	fuzzy_hash_t s;
	struct rspamd_fuzzy_node *n;

	memcpy (s.hash_pipe, cmd->hash, sizeof (s.hash_pipe));
	s.block_size = cmd->blocksize;
	mods++;

	rspamd_rwlock_writer_lock (ctx->tree_lock);
	if (ctx->strict_hash) {
		n = check_hash_node (NULL, &s, cmd->value, time, ctx);
	}
	else {
		n = check_hash_node (hashes[cmd->blocksize % BUCKETS],
				&s,
				cmd->value,
				time,
				ctx);
	}
	if (n == NULL) {
		/* Bloom false positive */
		n = add_hash_node (cmd, time, ctx);
	}
	rspamd_rwlock_writer_unlock (ctx->tree_lock);

	if (n != NULL) {
		n->time = time;
		return TRUE;
	}
	return FALSE;
}

static gboolean
process_write_command (struct fuzzy_cmd *cmd,
	guint64 time,
	struct rspamd_fuzzy_storage_ctx *ctx)
{
	if (rspamd_bloom_check (bf, cmd->hash)) {
		if (update_hash (cmd, time, ctx)) {
			return TRUE;
		}
	}

	rspamd_rwlock_writer_lock (ctx->tree_lock);
	add_hash_node (cmd, time, ctx);
	rspamd_rwlock_writer_unlock (ctx->tree_lock);

	mods++;
	server_stat->fuzzy_hashes++;
	msg_info ("fuzzy hash was successfully added");

	return TRUE;
}

static gboolean
delete_hash (GQueue *hash, fuzzy_hash_t *s,
	struct rspamd_fuzzy_storage_ctx *ctx)
{
	GList *cur, *tmp;
	struct rspamd_fuzzy_node *h;
	gboolean res = FALSE;

	if (ctx->strict_hash) {
		rspamd_rwlock_writer_lock (ctx->tree_lock);
		if (g_hash_table_remove (static_hash, s)) {
			rspamd_bloom_del (bf, s->hash_pipe);
			msg_info ("fuzzy hash was successfully deleted");
			server_stat->fuzzy_hashes--;
			mods++;
		}
		rspamd_rwlock_writer_unlock (ctx->tree_lock);
	}
	else {
		rspamd_rwlock_writer_lock (ctx->tree_lock);
		cur = hash->head;

		/* XXX: too slow way */
		while (cur) {
			h = cur->data;
			if (fuzzy_compare_hashes (&h->h, s) > LEV_LIMIT) {
				g_slice_free1 (sizeof (struct rspamd_fuzzy_node), h);
				tmp = cur;
				cur = g_list_next (cur);
				g_queue_delete_link (hash, tmp);
				rspamd_bloom_del (bf, s->hash_pipe);
				msg_info ("fuzzy hash was successfully deleted");
				server_stat->fuzzy_hashes--;
				mods++;
				res = TRUE;
				continue;
			}
			cur = g_list_next (cur);
		}
		rspamd_rwlock_writer_unlock (ctx->tree_lock);
	}

	return res;

}

static gboolean
process_delete_command (struct fuzzy_cmd *cmd,
	guint64 time,
	struct rspamd_fuzzy_storage_ctx *ctx)
{
	fuzzy_hash_t s;
	gboolean res = FALSE;

	if (!rspamd_bloom_check (bf, cmd->hash)) {
		return FALSE;
	}

	memcpy (s.hash_pipe, cmd->hash, sizeof (s.hash_pipe));
	s.block_size = cmd->blocksize;
	if (ctx->strict_hash) {
		return delete_hash (NULL, &s, ctx);
	}
	else {
		res = delete_hash (frequent, &s, ctx);
		if (!res) {
			res = delete_hash (hashes[cmd->blocksize % BUCKETS], &s, ctx);
		}
		else {
			(void)delete_hash (hashes[cmd->blocksize % BUCKETS], &s, ctx);
		}
	}

	return res;
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

#define CMD_PROCESS(x)                                                         \
	do {                                                                       \
		if (process_ ## x ## _command (&session->cmd, session->time,           \
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
process_fuzzy_command (struct fuzzy_session *session)
{
	gint r, flag = 0;
	gchar buf[64];

	switch (session->cmd.cmd) {
	case FUZZY_CHECK:
		r = process_check_command (&session->cmd,
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
			CMD_PROCESS (write);
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
			CMD_PROCESS (delete);
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

#undef CMD_PROCESS


/*
 * Accept new connection and construct task
 */
static void
accept_fuzzy_socket (gint fd, short what, void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)arg;
	struct fuzzy_session session;
	ssize_t r;
	struct {
		u_char cmd;
		guint32 blocksize;
		gint32 value;
		u_char hash[FUZZY_HASHLEN];
	}                               legacy_cmd;


	session.worker = worker;
	session.fd = fd;
	session.pos = (u_char *) &session.cmd;
	session.addr.slen = sizeof (session.addr.addr);
	session.ctx = worker->ctx;
	session.time = (guint64)time (NULL);

	/* Got some data */
	if (what == EV_READ) {
		while ((r = recvfrom (fd, session.pos, sizeof (struct fuzzy_cmd),
			MSG_WAITALL, &session.addr.addr.sa, &session.addr.slen)) == -1) {
			if (errno == EINTR) {
				continue;
			}
			msg_err ("got error while reading from socket: %d, %s",
				errno,
				strerror (errno));
			return;
		}
		session.addr.af = session.addr.addr.sa.sa_family;
		if (r == sizeof (struct fuzzy_cmd)) {
			/* Assume that the whole command was read */
			process_fuzzy_command (&session);
		}
		else if (r == sizeof (legacy_cmd)) {
			/* Process requests from old rspamd */
			memcpy (&legacy_cmd, session.pos, sizeof (legacy_cmd));
			session.cmd.cmd = legacy_cmd.cmd;
			session.cmd.blocksize = legacy_cmd.blocksize;
			session.cmd.value = legacy_cmd.value;
			session.cmd.flag = 0;
			memcpy (session.cmd.hash, legacy_cmd.hash,
				sizeof (legacy_cmd.hash));
			process_fuzzy_command (&session);
		}
		else {
			msg_err ("got incomplete data while reading from socket: %d, %s",
				errno,
				strerror (errno));
			return;
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
	ctx->frequent_score = DEFAULT_FREQUENT_SCORE;
	ctx->expire = DEFAULT_EXPIRE;
	ctx->tree_lock = rspamd_rwlock_new ();
	ctx->update_mtx = rspamd_mutex_new ();
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	ctx->update_cond = g_malloc0 (sizeof (GCond));
	g_cond_init (ctx->update_cond);
#else
	ctx->update_cond = g_cond_new ();
#endif

	rspamd_rcl_register_worker_option (cfg, type, "hashfile",
		rspamd_rcl_parse_struct_string, ctx,
		G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, hashfile), 0);

	rspamd_rcl_register_worker_option (cfg, type, "hash_file",
		rspamd_rcl_parse_struct_string, ctx,
		G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, hashfile), 0);

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

	rspamd_rcl_register_worker_option (cfg, type, "strict_hash",
		rspamd_rcl_parse_struct_boolean, ctx,
		G_STRUCT_OFFSET (struct rspamd_fuzzy_storage_ctx, strict_hash), 0);

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
	gint i;

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

	if (ctx->strict_hash) {
		static_hash = g_hash_table_new_full (rspamd_fuzzy_hash, rspamd_fuzzy_equal,
				NULL, rspamd_fuzzy_free_node);
	}
	else {
		for (i = 0; i < BUCKETS; i++) {
			hashes[i] = g_queue_new ();
		}
		frequent = g_queue_new ();
	}

	/* Init bloom filter */
	bf = rspamd_bloom_create (2000000L, RSPAMD_DEFAULT_BLOOM_HASHES);
	/* Try to read hashes from file */
	if (!read_hashes_file (worker)) {
		msg_err (
			"cannot read hashes file, it can be created after save procedure");
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
		if (!add_map (worker->srv->cfg, ctx->update_map,
			"Allow fuzzy updates from specified addresses",
			read_radix_list, fin_radix_list, (void **)&ctx->update_ips)) {
			if (!radix_add_generic_iplist (ctx->update_map,
				&ctx->update_ips)) {
				msg_warn ("cannot load or parse ip list from '%s'",
					ctx->update_map);
			}
		}
	}

	/* Maps events */
	start_map_watch (worker->srv->cfg, ctx->ev_base);

	ctx->update_thread = rspamd_create_thread ("fuzzy update",
			sync_cache,
			worker,
			&err);
	if (ctx->update_thread == NULL) {
		msg_err ("error creating update thread: %s", err->message);
	}

	event_base_loop (ctx->ev_base, 0);

	if (ctx->update_thread != NULL) {
		g_thread_join (ctx->update_thread);
	}

	close_log (rspamd_main->logger);
	exit (EXIT_SUCCESS);
}
