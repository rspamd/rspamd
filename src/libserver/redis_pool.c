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

#include "config.h"
#include <event.h>
#include "redis_pool.h"
#include "cfg_file.h"
#include "contrib/hiredis/hiredis.h"
#include "contrib/hiredis/async.h"
#include "contrib/hiredis/adapters/libevent.h"
#include "cryptobox.h"
#include "ref.h"
#include "logger.h"

struct rspamd_redis_pool_elt;

struct rspamd_redis_pool_connection {
	struct redisAsyncContext *ctx;
	struct rspamd_redis_pool_elt *elt;
	GList *entry;
	struct event timeout;
	gboolean active;
	gchar tag[MEMPOOL_UID_LEN];
	ref_entry_t ref;
};

struct rspamd_redis_pool_elt {
	struct rspamd_redis_pool *pool;
	guint64 key;
	GQueue *active;
	GQueue *inactive;
};

struct rspamd_redis_pool {
	struct event_base *ev_base;
	struct rspamd_config *cfg;
	GHashTable *elts_by_key;
	GHashTable *elts_by_ctx;
	gdouble timeout;
	guint max_conns;
};

static const gdouble default_timeout = 60.0;
static const guint default_max_conns = 100;

#define msg_err_rpool(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
		"redis_pool", conn->tag, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_rpool(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
		"redis_pool", conn->tag, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_rpool(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
		"redis_pool", conn->tag, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_rpool(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
        "redis_pool", conn->tag, \
        G_STRFUNC, \
        __VA_ARGS__)

static inline guint64
rspamd_redis_pool_get_key (const gchar *db, const gchar *password,
		const char *ip, int port)
{
	rspamd_cryptobox_fast_hash_state_t st;

	rspamd_cryptobox_fast_hash_init (&st, rspamd_hash_seed ());

	if (db) {
		rspamd_cryptobox_fast_hash_update (&st, db, strlen (db));
	}
	if (password) {
		rspamd_cryptobox_fast_hash_update (&st, password, strlen (password));
	}

	rspamd_cryptobox_fast_hash_update (&st, ip, strlen (ip));
	rspamd_cryptobox_fast_hash_update (&st, &port, sizeof (port));

	return rspamd_cryptobox_fast_hash_final (&st);
}


static void
rspamd_redis_pool_conn_dtor (struct rspamd_redis_pool_connection *conn)
{
	if (conn->active) {
		msg_debug_rpool ("active connection removed");

		if (conn->ctx) {
			g_hash_table_remove (conn->elt->pool->elts_by_ctx, conn->ctx);
			redisAsyncFree (conn->ctx);
		}

		g_queue_unlink (conn->elt->active, conn->entry);
	}
	else {
		msg_debug_rpool ("inactive connection removed");

		if (event_get_base (&conn->timeout)) {
			event_del (&conn->timeout);
		}

		g_queue_unlink (conn->elt->inactive, conn->entry);
	}


	g_list_free (conn->entry);
	g_slice_free1 (sizeof (*conn), conn);
}

static void
rspamd_redis_pool_elt_dtor (gpointer p)
{
	GList *cur;
	struct rspamd_redis_pool_elt *elt = p;
	struct rspamd_redis_pool_connection *c;

	for (cur = elt->active->head; cur != NULL; cur = g_list_next (cur)) {
		c = cur->data;
		REF_RELEASE (c);
	}

	for (cur = elt->inactive->head; cur != NULL; cur = g_list_next (cur)) {
		c = cur->data;
		REF_RELEASE (c);
	}

	g_queue_free (elt->active);
	g_queue_free (elt->inactive);
	g_slice_free1 (sizeof (*elt), elt);
}

static void
rspamd_redis_conn_timeout (gint fd, short what, gpointer p)
{
	struct rspamd_redis_pool_connection *conn = p;

	msg_debug_rpool ("scheduled removal of connection");
	REF_RELEASE (conn);
}

static void
rspamd_redis_pool_schedule_timeout (struct rspamd_redis_pool_connection *conn)
{
	struct timeval tv;
	gdouble real_timeout;
	guint active_elts;

	active_elts = g_queue_get_length (conn->elt->active);

	if (active_elts > conn->elt->pool->max_conns) {
		real_timeout = conn->elt->pool->timeout / 2.0;
		real_timeout = rspamd_time_jitter (real_timeout, real_timeout / 4.0);
	}
	else {
		real_timeout = conn->elt->pool->timeout;
		real_timeout = rspamd_time_jitter (real_timeout, real_timeout / 2.0);
	}

	msg_debug_rpool ("scheduled connection cleanup in %.1f seconds",
			real_timeout);
	double_to_tv (real_timeout, &tv);
	event_set (&conn->timeout, -1, EV_TIMEOUT, rspamd_redis_conn_timeout, conn);
	event_base_set (conn->elt->pool->ev_base, &conn->timeout);
	event_add (&conn->timeout, &tv);
}

static struct rspamd_redis_pool_connection *
rspamd_redis_pool_new_connection (struct rspamd_redis_pool *pool,
		struct rspamd_redis_pool_elt *elt,
		const char *db,
		const char *password,
		const char *ip,
		gint port)
{
	struct rspamd_redis_pool_connection *conn;
	struct redisAsyncContext *ctx;

	ctx = redisAsyncConnect (ip, port);

	if (ctx) {

		if (ctx->err != REDIS_OK) {
			redisAsyncFree (ctx);

			return NULL;
		}
		else {
			conn = g_slice_alloc0 (sizeof (*conn));
			conn->entry = g_list_prepend (NULL, conn);
			conn->elt = elt;
			conn->active = TRUE;

			g_hash_table_insert (elt->pool->elts_by_ctx, ctx, conn);
			g_queue_push_head_link (elt->active, conn->entry);
			conn->ctx = ctx;
			rspamd_random_hex (conn->tag, sizeof (conn->tag));
			REF_INIT_RETAIN (conn, rspamd_redis_pool_conn_dtor);
			msg_debug_rpool ("created new connection to %s:%d", ip, port);

			redisLibeventAttach (ctx, pool->ev_base);

			if (password) {
				redisAsyncCommand (ctx, NULL, NULL, "AUTH %s", password);
			}
			if (db) {
				redisAsyncCommand (ctx, NULL, NULL, "SELECT %s", db);
			}
		}

		return conn;
	}

	return NULL;
}

static struct rspamd_redis_pool_elt *
rspamd_redis_pool_new_elt (struct rspamd_redis_pool *pool)
{
	struct rspamd_redis_pool_elt *elt;

	elt = g_slice_alloc0 (sizeof (*elt));
	elt->active = g_queue_new ();
	elt->inactive = g_queue_new ();
	elt->pool = pool;

	return elt;
}

struct rspamd_redis_pool *
rspamd_redis_pool_init (void)
{
	struct rspamd_redis_pool *pool;

	pool = g_slice_alloc0 (sizeof (*pool));
	pool->elts_by_key = g_hash_table_new_full (g_int64_hash, g_int64_equal, NULL,
			rspamd_redis_pool_elt_dtor);
	pool->elts_by_ctx = g_hash_table_new (g_direct_hash, g_direct_equal);

	return pool;
}

void
rspamd_redis_pool_config (struct rspamd_redis_pool *pool,
		struct rspamd_config *cfg,
		struct event_base *ev_base)
{
	g_assert (pool != NULL);

	pool->ev_base = ev_base;
	pool->cfg = cfg;
	pool->timeout = default_timeout;
	pool->max_conns = default_max_conns;
}


struct redisAsyncContext*
rspamd_redis_pool_connect (struct rspamd_redis_pool *pool,
		const gchar *db, const gchar *password,
		const char *ip, int port)
{
	guint64 key;
	struct rspamd_redis_pool_elt *elt;
	GList *conn_entry;
	struct rspamd_redis_pool_connection *conn;

	g_assert (pool != NULL);
	g_assert (pool->ev_base != NULL);
	g_assert (ip != NULL);

	key = rspamd_redis_pool_get_key (db, password, ip, port);
	elt = g_hash_table_lookup (pool->elts_by_key, &key);

	if (elt) {
		if (g_queue_get_length (elt->inactive) > 0) {
			conn_entry = g_queue_pop_head_link (elt->inactive);
			conn = conn_entry->data;

			if (event_get_base (&conn->timeout)) {
				event_del (&conn->timeout);
			}

			conn->active = TRUE;
			g_queue_push_tail_link (elt->active, conn_entry);
			msg_debug_rpool ("reused existing connection to %s:%d", ip, port);

		}
		else {
			/* Need to create connection */
			conn = rspamd_redis_pool_new_connection (pool, elt,
					db, password, ip, port);
		}
	}
	else {
		elt = rspamd_redis_pool_new_elt (pool);
		elt->key = key;
		g_hash_table_insert (pool->elts_by_key, &elt->key, elt);

		conn = rspamd_redis_pool_new_connection (pool, elt,
				db, password, ip, port);
	}

	REF_RETAIN (conn);

	return conn->ctx;
}


void
rspamd_redis_pool_release_connection (struct rspamd_redis_pool *pool,
		struct redisAsyncContext *ctx, gboolean is_fatal)
{
	struct rspamd_redis_pool_connection *conn;

	g_assert (pool != NULL);
	g_assert (ctx != NULL);

	conn = g_hash_table_lookup (pool->elts_by_ctx, ctx);
	if (conn != NULL) {
		REF_RELEASE (conn);

		if (is_fatal || ctx->err == REDIS_ERR_IO || ctx->err == REDIS_ERR_EOF) {
			/* We need to terminate connection forcefully */
			msg_debug_rpool ("closed connection forcefully");
			REF_RELEASE (conn);
		}
		else {
			/* Just move it to the inactive queue */
			g_queue_unlink (conn->elt->active, conn->entry);
			g_queue_push_head_link (conn->elt->inactive, conn->entry);
			conn->active = FALSE;
			rspamd_redis_pool_schedule_timeout (conn);
			msg_debug_rpool ("mark connection inactive");
		}
	}
	else {
		g_assert_not_reached ();
	}
}


void
rspamd_redis_pool_destroy (struct rspamd_redis_pool *pool)
{
	struct rspamd_redis_pool_elt *elt;
	GHashTableIter it;
	gpointer k, v;

	g_assert (pool != NULL);

	g_hash_table_iter_init (&it, pool->elts_by_key);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		elt = v;
		rspamd_redis_pool_elt_dtor (elt);
		g_hash_table_iter_steal (&it);
	}

	g_hash_table_unref (pool->elts_by_ctx);
	g_hash_table_unref (pool->elts_by_key);

	g_slice_free1 (sizeof (*pool), pool);
}
