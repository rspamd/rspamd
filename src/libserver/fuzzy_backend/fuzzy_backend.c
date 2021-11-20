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
#include "fuzzy_backend.h"
#include "fuzzy_backend_sqlite.h"
#include "fuzzy_backend_redis.h"
#include "cfg_file.h"
#include "fuzzy_wire.h"

#define DEFAULT_EXPIRE 172800L

enum rspamd_fuzzy_backend_type {
	RSPAMD_FUZZY_BACKEND_SQLITE = 0,
	RSPAMD_FUZZY_BACKEND_REDIS = 1,
};

static void* rspamd_fuzzy_backend_init_sqlite (struct rspamd_fuzzy_backend *bk,
		const ucl_object_t *obj, struct rspamd_config *cfg, GError **err);
static void rspamd_fuzzy_backend_check_sqlite (struct rspamd_fuzzy_backend *bk,
		const struct rspamd_fuzzy_cmd *cmd,
		rspamd_fuzzy_check_cb cb, void *ud,
		void *subr_ud);
static void rspamd_fuzzy_backend_update_sqlite (struct rspamd_fuzzy_backend *bk,
		GArray *updates, const gchar *src,
		rspamd_fuzzy_update_cb cb, void *ud,
		void *subr_ud);
static void rspamd_fuzzy_backend_count_sqlite (struct rspamd_fuzzy_backend *bk,
		rspamd_fuzzy_count_cb cb, void *ud,
		void *subr_ud);
static void rspamd_fuzzy_backend_version_sqlite (struct rspamd_fuzzy_backend *bk,
		const gchar *src,
		rspamd_fuzzy_version_cb cb, void *ud,
		void *subr_ud);
static const gchar* rspamd_fuzzy_backend_id_sqlite (struct rspamd_fuzzy_backend *bk,
		void *subr_ud);
static void rspamd_fuzzy_backend_expire_sqlite (struct rspamd_fuzzy_backend *bk,
		void *subr_ud);
static void rspamd_fuzzy_backend_close_sqlite (struct rspamd_fuzzy_backend *bk,
		void *subr_ud);

struct rspamd_fuzzy_backend_subr {
	void* (*init) (struct rspamd_fuzzy_backend *bk, const ucl_object_t *obj,
			struct rspamd_config *cfg,
			GError **err);
	void (*check) (struct rspamd_fuzzy_backend *bk,
			const struct rspamd_fuzzy_cmd *cmd,
			rspamd_fuzzy_check_cb cb, void *ud,
			void *subr_ud);
	void (*update) (struct rspamd_fuzzy_backend *bk,
			GArray *updates, const gchar *src,
			rspamd_fuzzy_update_cb cb, void *ud,
			void *subr_ud);
	void (*count) (struct rspamd_fuzzy_backend *bk,
			rspamd_fuzzy_count_cb cb, void *ud,
			void *subr_ud);
	void (*version) (struct rspamd_fuzzy_backend *bk,
			const gchar *src,
			rspamd_fuzzy_version_cb cb, void *ud,
			void *subr_ud);
	const gchar* (*id) (struct rspamd_fuzzy_backend *bk, void *subr_ud);
	void (*periodic) (struct rspamd_fuzzy_backend *bk, void *subr_ud);
	void (*close) (struct rspamd_fuzzy_backend *bk, void *subr_ud);
};

static const struct rspamd_fuzzy_backend_subr fuzzy_subrs[] = {
	[RSPAMD_FUZZY_BACKEND_SQLITE] = {
		.init = rspamd_fuzzy_backend_init_sqlite,
		.check = rspamd_fuzzy_backend_check_sqlite,
		.update = rspamd_fuzzy_backend_update_sqlite,
		.count = rspamd_fuzzy_backend_count_sqlite,
		.version = rspamd_fuzzy_backend_version_sqlite,
		.id = rspamd_fuzzy_backend_id_sqlite,
		.periodic = rspamd_fuzzy_backend_expire_sqlite,
		.close = rspamd_fuzzy_backend_close_sqlite,
	},
	[RSPAMD_FUZZY_BACKEND_REDIS] = {
		.init = rspamd_fuzzy_backend_init_redis,
		.check = rspamd_fuzzy_backend_check_redis,
		.update = rspamd_fuzzy_backend_update_redis,
		.count = rspamd_fuzzy_backend_count_redis,
		.version = rspamd_fuzzy_backend_version_redis,
		.id = rspamd_fuzzy_backend_id_redis,
		.periodic = rspamd_fuzzy_backend_expire_redis,
		.close = rspamd_fuzzy_backend_close_redis,
	}
};

struct rspamd_fuzzy_backend {
	enum rspamd_fuzzy_backend_type type;
	gdouble expire;
	gdouble sync;
	struct ev_loop *event_loop;
	rspamd_fuzzy_periodic_cb periodic_cb;
	void *periodic_ud;
	const struct rspamd_fuzzy_backend_subr *subr;
	void *subr_ud;
	ev_timer periodic_event;
};

static GQuark
rspamd_fuzzy_backend_quark (void)
{
	return g_quark_from_static_string ("fuzzy-backend");
}

static void*
rspamd_fuzzy_backend_init_sqlite (struct rspamd_fuzzy_backend *bk,
		const ucl_object_t *obj, struct rspamd_config *cfg, GError **err)
{
	const ucl_object_t *elt;

	elt = ucl_object_lookup_any (obj, "hashfile", "hash_file", "file",
			"database", NULL);

	if (elt == NULL || ucl_object_type (elt) != UCL_STRING) {
		g_set_error (err, rspamd_fuzzy_backend_quark (),
				EINVAL, "missing sqlite3 path");
		return NULL;
	}

	return rspamd_fuzzy_backend_sqlite_open (ucl_object_tostring (elt),
			FALSE, err);
}

static void
rspamd_fuzzy_backend_check_sqlite (struct rspamd_fuzzy_backend *bk,
		const struct rspamd_fuzzy_cmd *cmd,
		rspamd_fuzzy_check_cb cb, void *ud,
		void *subr_ud)
{
	struct rspamd_fuzzy_backend_sqlite *sq = subr_ud;
	struct rspamd_fuzzy_reply rep;

	rep = rspamd_fuzzy_backend_sqlite_check (sq, cmd, bk->expire);

	if (cb) {
		cb (&rep, ud);
	}
}

static void
rspamd_fuzzy_backend_update_sqlite (struct rspamd_fuzzy_backend *bk,
		GArray *updates, const gchar *src,
		rspamd_fuzzy_update_cb cb, void *ud,
		void *subr_ud)
{
	struct rspamd_fuzzy_backend_sqlite *sq = subr_ud;
	gboolean success = FALSE;
	guint i;
	struct fuzzy_peer_cmd *io_cmd;
	struct rspamd_fuzzy_cmd *cmd;
	gpointer ptr;
	guint nupdates = 0, nadded = 0, ndeleted = 0, nextended = 0, nignored = 0;

	if (rspamd_fuzzy_backend_sqlite_prepare_update (sq, src)) {
		for (i = 0; i < updates->len; i ++) {
			io_cmd = &g_array_index (updates, struct fuzzy_peer_cmd, i);

			if (io_cmd->is_shingle) {
				cmd = &io_cmd->cmd.shingle.basic;
				ptr = &io_cmd->cmd.shingle;
			}
			else {
				cmd = &io_cmd->cmd.normal;
				ptr = &io_cmd->cmd.normal;
			}

			if (cmd->cmd == FUZZY_WRITE) {
				rspamd_fuzzy_backend_sqlite_add (sq, ptr);
				nadded ++;
				nupdates ++;
			}
			else if (cmd->cmd == FUZZY_DEL) {
				rspamd_fuzzy_backend_sqlite_del (sq, ptr);
				ndeleted ++;
				nupdates ++;
			}
			else {
				if (cmd->cmd == FUZZY_REFRESH) {
					nextended ++;
				}
				else {
					nignored ++;
				}
			}
		}

		if (rspamd_fuzzy_backend_sqlite_finish_update (sq, src,
				nupdates > 0)) {
			success = TRUE;
		}
	}

	if (cb) {
		cb (success, nadded, ndeleted, nextended, nignored, ud);
	}
}

static void
rspamd_fuzzy_backend_count_sqlite (struct rspamd_fuzzy_backend *bk,
		rspamd_fuzzy_count_cb cb, void *ud,
		void *subr_ud)
{
	struct rspamd_fuzzy_backend_sqlite *sq = subr_ud;
	guint64 nhashes;

	nhashes = rspamd_fuzzy_backend_sqlite_count (sq);

	if (cb) {
		cb (nhashes, ud);
	}
}

static void
rspamd_fuzzy_backend_version_sqlite (struct rspamd_fuzzy_backend *bk,
		const gchar *src,
		rspamd_fuzzy_version_cb cb, void *ud,
		void *subr_ud)
{
	struct rspamd_fuzzy_backend_sqlite *sq = subr_ud;
	guint64 rev;

	rev = rspamd_fuzzy_backend_sqlite_version (sq, src);

	if (cb) {
		cb (rev, ud);
	}
}

static const gchar*
rspamd_fuzzy_backend_id_sqlite (struct rspamd_fuzzy_backend *bk,
		void *subr_ud)
{
	struct rspamd_fuzzy_backend_sqlite *sq = subr_ud;

	return rspamd_fuzzy_sqlite_backend_id (sq);
}
static void
rspamd_fuzzy_backend_expire_sqlite (struct rspamd_fuzzy_backend *bk,
		void *subr_ud)
{
	struct rspamd_fuzzy_backend_sqlite *sq = subr_ud;

	rspamd_fuzzy_backend_sqlite_sync (sq, bk->expire, TRUE);
}

static void
rspamd_fuzzy_backend_close_sqlite (struct rspamd_fuzzy_backend *bk,
		void *subr_ud)
{
	struct rspamd_fuzzy_backend_sqlite *sq = subr_ud;

	rspamd_fuzzy_backend_sqlite_close (sq);
}


struct rspamd_fuzzy_backend *
rspamd_fuzzy_backend_create (struct ev_loop *ev_base,
		const ucl_object_t *config,
		struct rspamd_config *cfg,
		GError **err)
{
	struct rspamd_fuzzy_backend *bk;
	enum rspamd_fuzzy_backend_type type = RSPAMD_FUZZY_BACKEND_SQLITE;
	const ucl_object_t *elt;
	gdouble expire = DEFAULT_EXPIRE;

	if (config != NULL) {
		elt = ucl_object_lookup (config, "backend");

		if (elt != NULL && ucl_object_type (elt) == UCL_STRING) {
			if (strcmp (ucl_object_tostring (elt), "sqlite") == 0) {
				type = RSPAMD_FUZZY_BACKEND_SQLITE;
			}
			else if (strcmp (ucl_object_tostring (elt), "redis") == 0) {
				type = RSPAMD_FUZZY_BACKEND_REDIS;
			}
			else {
				g_set_error (err, rspamd_fuzzy_backend_quark (),
						EINVAL, "invalid backend type: %s",
						ucl_object_tostring (elt));
				return NULL;
			}
		}

		elt = ucl_object_lookup (config, "expire");

		if (elt != NULL) {
			expire = ucl_object_todouble (elt);
		}
	}

	bk = g_malloc0 (sizeof (*bk));
	bk->event_loop = ev_base;
	bk->expire = expire;
	bk->type = type;
	bk->subr = &fuzzy_subrs[type];

	if ((bk->subr_ud = bk->subr->init (bk, config, cfg, err)) == NULL) {
		g_free (bk);

		return NULL;
	}

	return bk;
}


void
rspamd_fuzzy_backend_check (struct rspamd_fuzzy_backend *bk,
		const struct rspamd_fuzzy_cmd *cmd,
		rspamd_fuzzy_check_cb cb, void *ud)
{
	g_assert (bk != NULL);

	bk->subr->check (bk, cmd, cb, ud, bk->subr_ud);
}

static guint
rspamd_fuzzy_digest_hash (gconstpointer key)
{
	guint ret;

	/* Distirbuted uniformly already */
	memcpy (&ret, key, sizeof (ret));

	return ret;
}

static gboolean
rspamd_fuzzy_digest_equal (gconstpointer v, gconstpointer v2)
{
	return memcmp (v, v2, rspamd_cryptobox_HASHBYTES) == 0;
}

static void
rspamd_fuzzy_backend_deduplicate_queue (GArray *updates)
{
	GHashTable *seen = g_hash_table_new (rspamd_fuzzy_digest_hash,
			rspamd_fuzzy_digest_equal);
	struct fuzzy_peer_cmd *io_cmd, *found;
	struct rspamd_fuzzy_cmd *cmd;
	guchar *digest;
	guint i;

	for (i = 0; i < updates->len; i ++) {
		io_cmd = &g_array_index (updates, struct fuzzy_peer_cmd, i);

		if (io_cmd->is_shingle) {
			cmd = &io_cmd->cmd.shingle.basic;
		}
		else {
			cmd = &io_cmd->cmd.normal;
		}

		digest = cmd->digest;

		found = g_hash_table_lookup (seen, digest);

		if (found == NULL) {
			/* Add to the seen list, if not a duplicate (huh?) */
			if (cmd->cmd != FUZZY_DUP) {
				g_hash_table_insert (seen, digest, io_cmd);
			}
		}
		else {
			if (found->cmd.normal.flag != cmd->flag) {
				/* TODO: deal with flags better at some point */
				continue;
			}

			/* Apply heuristic */
			switch (cmd->cmd) {
			case FUZZY_WRITE:
				if (found->cmd.normal.cmd == FUZZY_WRITE) {
					/* Already seen */
					found->cmd.normal.value += cmd->value;
					cmd->cmd = FUZZY_DUP; /* Ignore this one */
				}
				else if (found->cmd.normal.cmd == FUZZY_REFRESH) {
					/* Seen refresh command, remove it as write has higher priority */
					g_hash_table_replace (seen, digest, io_cmd);
					found->cmd.normal.cmd = FUZZY_DUP;
				}
				else if (found->cmd.normal.cmd == FUZZY_DEL) {
					/* Request delete + add, weird, but ignore add */
					cmd->cmd = FUZZY_DUP; /* Ignore this one */
				}
				break;
			case FUZZY_REFRESH:
				if (found->cmd.normal.cmd == FUZZY_WRITE) {
					/* No need to expire, handled by addition */
					cmd->cmd = FUZZY_DUP; /* Ignore this one */
				}
				else if (found->cmd.normal.cmd == FUZZY_DEL) {
					/* Request delete + expire, ignore expire */
					cmd->cmd = FUZZY_DUP; /* Ignore this one */
				}
				else if (found->cmd.normal.cmd == FUZZY_REFRESH) {
					/* Already handled */
					cmd->cmd = FUZZY_DUP; /* Ignore this one */
				}
				break;
			case FUZZY_DEL:
				/* Delete has priority over all other commands */
				g_hash_table_replace (seen, digest, io_cmd);
				found->cmd.normal.cmd = FUZZY_DUP;
				break;
			default:
				break;
			}
		}
	}

	g_hash_table_unref (seen);
}

void
rspamd_fuzzy_backend_process_updates (struct rspamd_fuzzy_backend *bk,
		GArray *updates, const gchar *src, rspamd_fuzzy_update_cb cb,
		void *ud)
{
	g_assert (bk != NULL);
	g_assert (updates != NULL);

	if (updates) {
		rspamd_fuzzy_backend_deduplicate_queue (updates);
		bk->subr->update (bk, updates, src, cb, ud, bk->subr_ud);
	}
	else if (cb) {
		cb (TRUE, 0, 0, 0, 0, ud);
	}
}


void
rspamd_fuzzy_backend_count (struct rspamd_fuzzy_backend *bk,
		rspamd_fuzzy_count_cb cb, void *ud)
{
	g_assert (bk != NULL);

	bk->subr->count (bk, cb, ud, bk->subr_ud);
}


void
rspamd_fuzzy_backend_version (struct rspamd_fuzzy_backend *bk,
		const gchar *src,
		rspamd_fuzzy_version_cb cb, void *ud)
{
	g_assert (bk != NULL);

	bk->subr->version (bk, src, cb, ud, bk->subr_ud);
}

const gchar *
rspamd_fuzzy_backend_id (struct rspamd_fuzzy_backend *bk)
{
	g_assert (bk != NULL);

	if (bk->subr->id) {
		return bk->subr->id (bk, bk->subr_ud);
	}

	return NULL;
}

static inline void
rspamd_fuzzy_backend_periodic_sync (struct rspamd_fuzzy_backend *bk)
{
	if (bk->periodic_cb) {
		if (bk->periodic_cb (bk->periodic_ud)) {
			if (bk->subr->periodic) {
				bk->subr->periodic (bk, bk->subr_ud);
			}
		}
	}
	else {
		if (bk->subr->periodic) {
			bk->subr->periodic (bk, bk->subr_ud);
		}
	}
}

static void
rspamd_fuzzy_backend_periodic_cb (EV_P_ ev_timer *w, int revents)
{
	struct rspamd_fuzzy_backend *bk = (struct rspamd_fuzzy_backend *)w->data;
	gdouble jittered;

	jittered = rspamd_time_jitter (bk->sync, bk->sync / 2.0);
	w->repeat = jittered;
	rspamd_fuzzy_backend_periodic_sync (bk);
	ev_timer_again (EV_A_ w);
}

void
rspamd_fuzzy_backend_start_update (struct rspamd_fuzzy_backend *bk,
		gdouble timeout,
		rspamd_fuzzy_periodic_cb cb,
		void *ud)
{
	gdouble jittered;

	g_assert (bk != NULL);

	if (bk->subr->periodic) {
		if (bk->sync > 0.0) {
			ev_timer_stop (bk->event_loop, &bk->periodic_event);
		}

		if (cb) {
			bk->periodic_cb = cb;
			bk->periodic_ud = ud;
		}

		rspamd_fuzzy_backend_periodic_sync (bk);
		bk->sync = timeout;
		jittered = rspamd_time_jitter (timeout, timeout / 2.0);

		bk->periodic_event.data = bk;
		ev_timer_init (&bk->periodic_event, rspamd_fuzzy_backend_periodic_cb,
				jittered, 0.0);
		ev_timer_start (bk->event_loop, &bk->periodic_event);
	}
}

void
rspamd_fuzzy_backend_close (struct rspamd_fuzzy_backend *bk)
{
	g_assert (bk != NULL);

	if (bk->sync > 0.0) {
		rspamd_fuzzy_backend_periodic_sync (bk);
		ev_timer_stop (bk->event_loop, &bk->periodic_event);
	}

	bk->subr->close (bk, bk->subr_ud);

	g_free (bk);
}

struct ev_loop*
rspamd_fuzzy_backend_event_base (struct rspamd_fuzzy_backend *backend)
{
	return backend->event_loop;
}

gdouble
rspamd_fuzzy_backend_get_expire (struct rspamd_fuzzy_backend *backend)
{
	return backend->expire;
}
