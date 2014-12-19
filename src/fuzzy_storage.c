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
#include "fuzzy_backend.h"

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

	struct rspamd_fuzzy_backend *backend;
};

struct rspamd_legacy_fuzzy_node {
	gint32 value;
	gint32 flag;
	guint64 time;
	rspamd_fuzzy_t h;
};

struct fuzzy_session {
	struct rspamd_worker *worker;
	struct rspamd_fuzzy_cmd cmd;
	gint fd;
	guint64 time;
	gboolean legacy;
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
sigterm_handler (void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)arg;
	struct rspamd_fuzzy_storage_ctx *ctx;

	ctx = worker->ctx;
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
}

/*
 * MDB Interface
 */

static void
rspamd_fuzzy_process_command (struct fuzzy_session *session)
{
	struct rspamd_fuzzy_reply rep;
	guint64 value;
	int rc, match = 0, i;
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
	struct rspamd_fuzzy_reply rep;
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
	session.addr.slen = sizeof (session.addr.addr);
	session.ctx = worker->ctx;
	session.time = (guint64)time (NULL);

	/* Got some data */
	if (what == EV_READ) {
		while ((r = recvfrom (fd, buf, sizeof (buf), 0,
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
		if (r == sizeof (struct legacy_fuzzy_cmd)) {
			/* Old command */
		}
		else if (r == sizeof (struct rspamd_fuzzy_cmd)) {
			/* New command */
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

	/* Call backend sync */
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

	if ((ctx->backend = rspamd_fuzzy_backend_open (ctx->hashfile, &err)) == NULL) {
		msg_err (err->message);
		g_error_free (err);
		exit (EXIT_FAILURE);
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

	event_base_loop (ctx->ev_base, 0);

	rspamd_log_close (rspamd_main->logger);
	exit (EXIT_SUCCESS);
}
