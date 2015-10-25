/* Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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
		.args = "VI",
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
rspamd_stat_cache_sqlite3_init(struct rspamd_stat_ctx *ctx,
		struct rspamd_config *cfg)
{
	struct rspamd_stat_sqlite3_ctx *new = NULL;
	struct rspamd_classifier_config *clf;
	const ucl_object_t *obj, *elt;
	GList *cur;
	gchar dbpath[PATH_MAX];
	sqlite3 *sqlite;
	gboolean has_sqlite_cache = FALSE;
	GError *err = NULL;

	rspamd_snprintf (dbpath, sizeof (dbpath), SQLITE_CACHE_PATH);
	cur = cfg->classifiers;

	while (cur) {
		clf = cur->data;

		obj = ucl_object_find_key (clf->opts, "cache");

		/* Sqlite3 cache is the default learn cache method */
		if (obj == NULL) {
			has_sqlite_cache = TRUE;
			break;
		}
		else if (ucl_object_type (obj) == UCL_OBJECT) {
			elt = ucl_object_find_key (obj, "name");

			if (ucl_object_type (elt) == UCL_STRING &&
				g_ascii_strcasecmp (ucl_object_tostring (elt), "sqlite3") == 0) {

				has_sqlite_cache = TRUE;
				elt = ucl_object_find_key (obj, "path");
				if (elt != NULL && ucl_object_type (elt) == UCL_STRING) {
					rspamd_snprintf (dbpath, sizeof (dbpath), "%s",
							ucl_object_tostring (elt));
				}
			}
		}

		cur = g_list_next (cur);
	}

	if (has_sqlite_cache) {
		sqlite = rspamd_sqlite3_open_or_create (cfg->cfg_pool,
				dbpath, create_tables_sql, &err);

		if (sqlite == NULL) {
			msg_err_config ("cannot open sqlite3 cache: %e", err);
			g_error_free (err);
			err = NULL;
		}
		else {
			new = g_slice_alloc (sizeof (*new));
			new->db = sqlite;
			new->prstmt = rspamd_sqlite3_init_prstmt (sqlite, prepared_stmts,
					RSPAMD_STAT_CACHE_MAX, &err);

			if (new->prstmt == NULL) {
				msg_err_config ("cannot open sqlite3 cache: %e", err);
				g_error_free (err);
				err = NULL;
				sqlite3_close (sqlite);
				g_slice_free1 (sizeof (*new), new);
				new = NULL;
			}
		}
	}

	return new;
}

static rspamd_learn_t
rspamd_stat_cache_sqlite3_check (rspamd_mempool_t *pool,
		const guchar *h, gsize len, gboolean is_spam,
		struct rspamd_stat_sqlite3_ctx *ctx)
{
	gint rc, ret = RSPAMD_LEARN_OK;
	gint64 flag;

	rspamd_sqlite3_run_prstmt (pool, ctx->db, ctx->prstmt,
			RSPAMD_STAT_CACHE_TRANSACTION_START_DEF);
	rc = rspamd_sqlite3_run_prstmt (pool, ctx->db, ctx->prstmt,
			RSPAMD_STAT_CACHE_GET_LEARN, (gint64)len, h, &flag);
	rspamd_sqlite3_run_prstmt (pool, ctx->db, ctx->prstmt,
			RSPAMD_STAT_CACHE_TRANSACTION_COMMIT);

	if (rc == SQLITE_OK) {
		/* We have some existing record in the table */
		if ((flag && is_spam) || (!flag && !is_spam)) {
			/* Already learned */
			ret = RSPAMD_LEARN_INGORE;
		}
		else {
			/* Need to relearn */
			flag = is_spam ? 1 : 0;
			rspamd_sqlite3_run_prstmt (pool, ctx->db, ctx->prstmt,
					RSPAMD_STAT_CACHE_TRANSACTION_START_IM);
			rspamd_sqlite3_run_prstmt (pool, ctx->db, ctx->prstmt,
					RSPAMD_STAT_CACHE_UPDATE_LEARN, (gint64)len, h, flag);
			rspamd_sqlite3_run_prstmt (pool, ctx->db, ctx->prstmt,
					RSPAMD_STAT_CACHE_TRANSACTION_COMMIT);

			return RSPAMD_LEARN_UNLEARN;
		}
	}
	else {
		/* Insert result new id */
		flag = is_spam ? 1 : 0;
		rspamd_sqlite3_run_prstmt (pool, ctx->db, ctx->prstmt,
				RSPAMD_STAT_CACHE_TRANSACTION_START_IM);
		rspamd_sqlite3_run_prstmt (pool, ctx->db, ctx->prstmt,
				RSPAMD_STAT_CACHE_ADD_LEARN, (gint64)len, h, flag);
		rspamd_sqlite3_run_prstmt (pool, ctx->db, ctx->prstmt,
				RSPAMD_STAT_CACHE_TRANSACTION_COMMIT);
	}

	return ret;
}

gint
rspamd_stat_cache_sqlite3_process (struct rspamd_task *task,
		gboolean is_spam, gpointer c)
{
	struct rspamd_stat_sqlite3_ctx *ctx = (struct rspamd_stat_sqlite3_ctx *)c;
	struct mime_text_part *part;
	rspamd_cryptobox_hash_state_t st;
	rspamd_ftok_t *word;
	guchar out[rspamd_cryptobox_HASHBYTES];
	guint i, j;

	if (ctx != NULL && ctx->db != NULL) {
		rspamd_cryptobox_hash_init (&st, NULL, 0);

		for (i = 0; i < task->text_parts->len; i ++) {
			part = g_ptr_array_index (task->text_parts, i);

			if (part->words != NULL) {
				for (j = 0; j < part->words->len; j ++) {
					word = &g_array_index (part->words, rspamd_ftok_t, j);
					rspamd_cryptobox_hash_update (&st, word->begin, word->len);
				}
			}
		}

		rspamd_cryptobox_hash_final (&st, out);

		return rspamd_stat_cache_sqlite3_check (task->task_pool,
				out, sizeof (out), is_spam, ctx);
	}

	return RSPAMD_LEARN_OK;
}

void
rspamd_stat_cache_sqlite3_close (gpointer c)
{
	struct rspamd_stat_sqlite3_ctx *ctx = (struct rspamd_stat_sqlite3_ctx *)c;

	if (ctx != NULL) {
		rspamd_sqlite3_close_prstmt (ctx->db, ctx->prstmt);
		sqlite3_close (ctx->db);
		g_slice_free1 (sizeof (*ctx), ctx);
	}

}
