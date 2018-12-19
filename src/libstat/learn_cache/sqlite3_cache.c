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
#include "learn_cache.h"
#include "rspamd.h"
#include "stat_api.h"
#include "stat_internal.h"
#include "cryptobox.h"
#include "ucl.h"
#include "fstring.h"
#include "message.h"
#include "libutil/sqlite_utils.h"

static const char *create_tables_sql =
		""
		"CREATE TABLE IF NOT EXISTS learns("
		"id INTEGER PRIMARY KEY,"
		"flag INTEGER NOT NULL,"
		"digest TEXT NOT NULL);"
		"CREATE UNIQUE INDEX IF NOT EXISTS d ON learns(digest);"
		"";

#define SQLITE_CACHE_PATH RSPAMD_DBDIR "/learn_cache.sqlite"

enum rspamd_stat_sqlite3_stmt_idx {
	RSPAMD_STAT_CACHE_TRANSACTION_START_IM = 0,
	RSPAMD_STAT_CACHE_TRANSACTION_START_DEF,
	RSPAMD_STAT_CACHE_TRANSACTION_COMMIT,
	RSPAMD_STAT_CACHE_TRANSACTION_ROLLBACK,
	RSPAMD_STAT_CACHE_GET_LEARN,
	RSPAMD_STAT_CACHE_ADD_LEARN,
	RSPAMD_STAT_CACHE_UPDATE_LEARN,
	RSPAMD_STAT_CACHE_MAX
};

static struct rspamd_sqlite3_prstmt prepared_stmts[RSPAMD_STAT_CACHE_MAX] =
{
	{
		.idx = RSPAMD_STAT_CACHE_TRANSACTION_START_IM,
		.sql = "BEGIN IMMEDIATE TRANSACTION;",
		.args = "",
		.stmt = NULL,
		.result = SQLITE_DONE,
		.ret = ""
	},
	{
		.idx = RSPAMD_STAT_CACHE_TRANSACTION_START_DEF,
		.sql = "BEGIN DEFERRED TRANSACTION;",
		.args = "",
		.stmt = NULL,
		.result = SQLITE_DONE,
		.ret = ""
	},
	{
		.idx = RSPAMD_STAT_CACHE_TRANSACTION_COMMIT,
		.sql = "COMMIT;",
		.args = "",
		.stmt = NULL,
		.result = SQLITE_DONE,
		.ret = ""
	},
	{
		.idx = RSPAMD_STAT_CACHE_TRANSACTION_ROLLBACK,
		.sql = "ROLLBACK;",
		.args = "",
		.stmt = NULL,
		.result = SQLITE_DONE,
		.ret = ""
	},
	{
		.idx = RSPAMD_STAT_CACHE_GET_LEARN,
		.sql = "SELECT flag FROM learns WHERE digest=?1",
		.args = "V",
		.stmt = NULL,
		.result = SQLITE_ROW,
		.ret = "I"
	},
	{
		.idx = RSPAMD_STAT_CACHE_ADD_LEARN,
		.sql = "INSERT INTO learns(digest, flag) VALUES (?1, ?2);",
		.args = "VI",
		.stmt = NULL,
		.result = SQLITE_DONE,
		.ret = ""
	},
	{
		.idx = RSPAMD_STAT_CACHE_UPDATE_LEARN,
		.sql = "UPDATE learns SET flag=?1 WHERE digest=?2;",
		.args = "IV",
		.stmt = NULL,
		.result = SQLITE_DONE,
		.ret = ""
	}
};

struct rspamd_stat_sqlite3_ctx {
	sqlite3 *db;
	GArray *prstmt;
};

gpointer
rspamd_stat_cache_sqlite3_init (struct rspamd_stat_ctx *ctx,
		struct rspamd_config *cfg,
		struct rspamd_statfile *st,
		const ucl_object_t *cf)
{
	struct rspamd_stat_sqlite3_ctx *new = NULL;
	const ucl_object_t *elt;
	gchar dbpath[PATH_MAX];
	const gchar *path = SQLITE_CACHE_PATH;
	sqlite3 *sqlite;
	GError *err = NULL;

	if (cf) {
		elt = ucl_object_lookup_any (cf, "path", "file", NULL);

		if (elt != NULL) {
			path = ucl_object_tostring (elt);
		}
	}

	rspamd_snprintf (dbpath, sizeof (dbpath), "%s", path);

	sqlite = rspamd_sqlite3_open_or_create (cfg->cfg_pool,
			dbpath, create_tables_sql, 0, &err);

	if (sqlite == NULL) {
		msg_err ("cannot open sqlite3 cache: %e", err);
		g_error_free (err);
		err = NULL;
	}
	else {
		new = g_malloc0 (sizeof (*new));
		new->db = sqlite;
		new->prstmt = rspamd_sqlite3_init_prstmt (sqlite, prepared_stmts,
				RSPAMD_STAT_CACHE_MAX, &err);

		if (new->prstmt == NULL) {
			msg_err ("cannot open sqlite3 cache: %e", err);
			g_error_free (err);
			err = NULL;
			sqlite3_close (sqlite);
			g_free (new);
			new = NULL;
		}
	}

	return new;
}

gpointer
rspamd_stat_cache_sqlite3_runtime (struct rspamd_task *task,
				gpointer ctx, gboolean learn)
{
	/* No need of runtime for this type of classifier */
	return ctx;
}

gint
rspamd_stat_cache_sqlite3_check (struct rspamd_task *task,
		gboolean is_spam,
		gpointer runtime)
{
	struct rspamd_stat_sqlite3_ctx *ctx = runtime;
	rspamd_cryptobox_hash_state_t st;
	rspamd_token_t *tok;
	guchar *out;
	gchar *user = NULL;
	guint i;
	gint rc;
	gint64 flag;

	if (task->tokens == NULL || task->tokens->len == 0) {
		return RSPAMD_LEARN_INGORE;
	}

	if (ctx != NULL && ctx->db != NULL) {
		out = rspamd_mempool_alloc (task->task_pool, rspamd_cryptobox_HASHBYTES);

		rspamd_cryptobox_hash_init (&st, NULL, 0);

		user = rspamd_mempool_get_variable (task->task_pool, "stat_user");
		/* Use dedicated hash space for per users cache */
		if (user != NULL) {
			rspamd_cryptobox_hash_update (&st, user, strlen (user));
		}

		for (i = 0; i < task->tokens->len; i ++) {
			tok = g_ptr_array_index (task->tokens, i);
			rspamd_cryptobox_hash_update (&st, (guchar *)&tok->data,
					sizeof (tok->data));
		}

		rspamd_cryptobox_hash_final (&st, out);

		rspamd_sqlite3_run_prstmt (task->task_pool, ctx->db, ctx->prstmt,
				RSPAMD_STAT_CACHE_TRANSACTION_START_DEF);
		rc = rspamd_sqlite3_run_prstmt (task->task_pool, ctx->db, ctx->prstmt,
				RSPAMD_STAT_CACHE_GET_LEARN, (gint64)rspamd_cryptobox_HASHBYTES,
				out, &flag);
		rspamd_sqlite3_run_prstmt (task->task_pool, ctx->db, ctx->prstmt,
				RSPAMD_STAT_CACHE_TRANSACTION_COMMIT);

		/* Save hash into variables */
		rspamd_mempool_set_variable (task->task_pool, "words_hash", out, NULL);

		if (rc == SQLITE_OK) {
			/* We have some existing record in the table */
			if (!!flag == !!is_spam) {
				/* Already learned */
				msg_warn_task ("already seen stat hash: %*bs",
						rspamd_cryptobox_HASHBYTES, out);
				return RSPAMD_LEARN_INGORE;
			}
			else {
				/* Need to relearn */
				return RSPAMD_LEARN_UNLEARN;
			}
		}
	}

	return RSPAMD_LEARN_OK;
}

gint
rspamd_stat_cache_sqlite3_learn (struct rspamd_task *task,
		gboolean is_spam,
		gpointer runtime)
{
	struct rspamd_stat_sqlite3_ctx *ctx = runtime;
	gboolean unlearn = !!(task->flags & RSPAMD_TASK_FLAG_UNLEARN);
	guchar *h;
	gint64 flag;

	h = rspamd_mempool_get_variable (task->task_pool, "words_hash");

	if (h == NULL) {
		return RSPAMD_LEARN_INGORE;
	}

	flag = !!is_spam ? 1 : 0;

	if (!unlearn) {
		/* Insert result new id */
		rspamd_sqlite3_run_prstmt (task->task_pool, ctx->db, ctx->prstmt,
				RSPAMD_STAT_CACHE_TRANSACTION_START_IM);
		rspamd_sqlite3_run_prstmt (task->task_pool, ctx->db, ctx->prstmt,
				RSPAMD_STAT_CACHE_ADD_LEARN,
				(gint64)rspamd_cryptobox_HASHBYTES, h, flag);
		rspamd_sqlite3_run_prstmt (task->task_pool, ctx->db, ctx->prstmt,
				RSPAMD_STAT_CACHE_TRANSACTION_COMMIT);
	}
	else {
		rspamd_sqlite3_run_prstmt (task->task_pool, ctx->db, ctx->prstmt,
				RSPAMD_STAT_CACHE_TRANSACTION_START_IM);
		rspamd_sqlite3_run_prstmt (task->task_pool, ctx->db, ctx->prstmt,
				RSPAMD_STAT_CACHE_UPDATE_LEARN,
				flag,
				(gint64)rspamd_cryptobox_HASHBYTES, h);
		rspamd_sqlite3_run_prstmt (task->task_pool, ctx->db, ctx->prstmt,
				RSPAMD_STAT_CACHE_TRANSACTION_COMMIT);
	}

	rspamd_sqlite3_sync (ctx->db, NULL, NULL);

	return RSPAMD_LEARN_OK;
}

void
rspamd_stat_cache_sqlite3_close (gpointer c)
{
	struct rspamd_stat_sqlite3_ctx *ctx = (struct rspamd_stat_sqlite3_ctx *)c;

	if (ctx != NULL) {
		rspamd_sqlite3_close_prstmt (ctx->db, ctx->prstmt);
		sqlite3_close (ctx->db);
		g_free (ctx);
	}

}
