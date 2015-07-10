/*
 * Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
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

#include "config.h"
#include "main.h"
#include "sqlite3.h"
#include "libutil/sqlite_utils.h"
#include "libstat/stat_internal.h"

#define SQLITE3_BACKEND_TYPE "sqlite3"
#define SQLITE3_SCHEMA_VERSION "1"
#define SQLITE3_DEFAULT "default"

struct rspamd_stat_sqlite3_db {
	sqlite3 *sqlite;
	GArray *prstmt;
	gboolean in_transaction;
};

struct rspamd_stat_sqlite3_ctx {
	GHashTable *files;
	gboolean enable_users;
	gboolean enable_languages;
};

struct rspamd_stat_sqlite3_rt {
	struct rspamd_stat_sqlite3_ctx *ctx;
	struct rspamd_task *task;
	struct rspamd_stat_sqlite3_db *db;
	gint64 user_id;
	gint64 lang_id;
};

static const char *create_tables_sql =
		"BEGIN IMMEDIATE;"
		"CREATE TABLE users("
		"id INTEGER PRIMARY KEY,"
		"name TEXT,"
		"learns INTEGER"
		");"
		"CREATE TABLE languages("
		"id INTEGER PRIMARY KEY,"
		"name TEXT,"
		"learns INTEGER"
		");"
		"CREATE TABLE tokens("
		"token INTEGER NOT NULL,"
		"user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
		"language INTEGER NOT NULL REFERENCES languages(id) ON DELETE CASCADE,"
		"value INTEGER,"
		"CONSTRAINT tid UNIQUE (token, user, language) ON CONFLICT REPLACE"
		");"
		"CREATE UNIQUE INDEX IF NOT EXISTS un ON users(name);"
		"CREATE INDEX IF NOT EXISTS tok ON tokens(token);"
		"CREATE UNIQUE INDEX IF NOT EXISTS ln ON languages(name);"
		"PRAGMA user_version=" SQLITE3_SCHEMA_VERSION ";"
		"INSERT INTO users(id, name, learns) VALUES(0, '" SQLITE3_DEFAULT "',0);"
		"INSERT INTO languages(id, name, learns) VALUES(0, '" SQLITE3_DEFAULT "',0);"
		"COMMIT;";

enum rspamd_stat_sqlite3_stmt_idx {
	RSPAMD_STAT_BACKEND_TRANSACTION_START_IM = 0,
	RSPAMD_STAT_BACKEND_TRANSACTION_START_DEF,
	RSPAMD_STAT_BACKEND_TRANSACTION_COMMIT,
	RSPAMD_STAT_BACKEND_TRANSACTION_ROLLBACK,
	RSPAMD_STAT_BACKEND_GET_TOKEN,
	RSPAMD_STAT_BACKEND_SET_TOKEN,
	RSPAMD_STAT_BACKEND_INC_LEARNS,
	RSPAMD_STAT_BACKEND_DEC_LEARNS,
	RSPAMD_STAT_BACKEND_GET_LEARNS,
	RSPAMD_STAT_BACKEND_MAX
};

static struct rspamd_sqlite3_prstmt prepared_stmts[RSPAMD_STAT_BACKEND_MAX] =
{
	{
		.idx = RSPAMD_STAT_BACKEND_TRANSACTION_START_IM,
		.sql = "BEGIN IMMEDIATE TRANSACTION;",
		.args = "",
		.stmt = NULL,
		.result = SQLITE_DONE,
		.ret = ""
	},
	{
		.idx = RSPAMD_STAT_BACKEND_TRANSACTION_START_DEF,
		.sql = "BEGIN DEFERRED TRANSACTION;",
		.args = "",
		.stmt = NULL,
		.result = SQLITE_DONE,
		.ret = ""
	},
	{
		.idx = RSPAMD_STAT_BACKEND_TRANSACTION_COMMIT,
		.sql = "COMMIT;",
		.args = "",
		.stmt = NULL,
		.result = SQLITE_DONE,
		.ret = ""
	},
	{
		.idx = RSPAMD_STAT_BACKEND_TRANSACTION_ROLLBACK,
		.sql = "ROLLBACK;",
		.args = "",
		.stmt = NULL,
		.result = SQLITE_DONE,
		.ret = ""
	},
	{
		.idx = RSPAMD_STAT_BACKEND_GET_TOKEN,
		.sql = "SELECT value FROM tokens "
				"LEFT JOIN languages ON tokens.language=languages.id "
				"LEFT JOIN users ON tokens.user=users.id "
				"WHERE token=?1 AND (users.id=?2 OR users.id=0) "
				"AND (languages.id=?3 OR languages.id=0);",
		.stmt = NULL,
		.args = "III",
		.result = SQLITE_ROW,
		.ret = "I"
	},
	{
		.idx = RSPAMD_STAT_BACKEND_SET_TOKEN,
		.sql = "INSERT OR REPLACE INTO tokens (token, user, language, value) "
				"VALUES (?1, ?2, ?3, ?4);",
		.stmt = NULL,
		.args = "IIII",
		.result = SQLITE_DONE,
		.ret = ""
	},
	{
		.idx = RSPAMD_STAT_BACKEND_INC_LEARNS,
		.sql = "UPDATE languages SET learns=learns + 1 WHERE name=?1;"
				"UPDATE users SET learns=learns + 1 WHERE name=?2;",
		.stmt = NULL,
		.args = "TT",
		.result = SQLITE_DONE,
		.ret = ""
	},
	{
		.idx = RSPAMD_STAT_BACKEND_DEC_LEARNS,
		.sql = "UPDATE languages SET learns=learns - 1 WHERE name=?1;"
				"UPDATE users SET learns=learns - 1 WHERE name=?2;",
		.stmt = NULL,
		.args = "TT",
		.result = SQLITE_DONE,
		.ret = ""
	},
	{
		.idx = RSPAMD_STAT_BACKEND_GET_LEARNS,
		.sql = "SELECT sum(learns) FROM languages;",
		.stmt = NULL,
		.args = "",
		.result = SQLITE_ROW,
		.ret = "I"
	}
};

static GQuark
rspamd_sqlite3_backend_quark (void)
{
	return g_quark_from_static_string ("sqlite3-stat-backend");
}

static struct rspamd_stat_sqlite3_db *
rspamd_sqlite3_opendb (const gchar *path, const ucl_object_t *opts,
		gboolean create, GError **err)
{
	struct rspamd_stat_sqlite3_db *bk;

	bk = g_slice_alloc0 (sizeof (*bk));
	bk->sqlite = rspamd_sqlite3_open_or_create (path, create_tables_sql, err);

	if (bk->sqlite == NULL) {
		g_slice_free1 (sizeof (*bk), bk);

		return NULL;
	}

	bk->prstmt = rspamd_sqlite3_init_prstmt (bk->sqlite, prepared_stmts,
			RSPAMD_STAT_BACKEND_MAX, err);

	if (bk->prstmt == NULL) {
		sqlite3_close (bk->sqlite);
		g_slice_free1 (sizeof (*bk), bk);

		return NULL;
	}

	return bk;
}

gpointer
rspamd_sqlite3_init (struct rspamd_stat_ctx *ctx,
		struct rspamd_config *cfg)
{
	struct rspamd_stat_sqlite3_ctx *new;
	struct rspamd_classifier_config *clf;
	struct rspamd_statfile_config *stf;
	GList *cur, *curst;
	const ucl_object_t *filenameo;
	const gchar *filename;
	struct rspamd_stat_sqlite3_db *bk;
	GError *err = NULL;

	new = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*new));
	new->files = g_hash_table_new (g_direct_hash, g_direct_equal);

	/* Iterate over all classifiers and load matching statfiles */
	cur = cfg->classifiers;

	while (cur) {
		clf = cur->data;

		curst = clf->statfiles;
		while (curst) {
			stf = curst->data;

			if (stf->backend && strcmp (stf->backend, SQLITE3_BACKEND_TYPE) == 0) {
				/*
				 * Check configuration sanity
				 */
				filenameo = ucl_object_find_key (stf->opts, "filename");
				if (filenameo == NULL || ucl_object_type (filenameo) != UCL_STRING) {
					filenameo = ucl_object_find_key (stf->opts, "path");
					if (filenameo == NULL || ucl_object_type (filenameo) != UCL_STRING) {
						msg_err ("statfile %s has no filename defined", stf->symbol);
						curst = curst->next;
						continue;
					}
				}

				filename = ucl_object_tostring (filenameo);

				if ((bk = rspamd_sqlite3_opendb (filename, stf->opts, TRUE,
						&err)) == NULL) {
					msg_err ("cannot open sqlite3 db: %e", err);
				}

				if (bk != NULL) {
					g_hash_table_insert (new->files, stf, bk);
				}
				else {
					g_error_free (err);
					err = NULL;
				}

				ctx->statfiles ++;
			}

			curst = curst->next;
		}

		cur = g_list_next (cur);
	}

	return (gpointer)new;
}

void
rspamd_sqlite3_close (gpointer p)
{
	struct rspamd_stat_sqlite3_ctx *ctx = p;
	struct rspamd_stat_sqlite3_db *bk;
	GHashTableIter it;
	gpointer k, v;

	g_hash_table_iter_init (&it, ctx->files);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		bk = v;

		if (bk->sqlite) {
			if (bk->in_transaction) {
				rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
						RSPAMD_STAT_BACKEND_TRANSACTION_COMMIT);
			}

			rspamd_sqlite3_close_prstmt (bk->sqlite, bk->prstmt);
			sqlite3_close (bk->sqlite);
			g_slice_free1 (sizeof (*bk), bk);
		}
	}

	g_hash_table_destroy (ctx->files);
}

gpointer
rspamd_sqlite3_runtime (struct rspamd_task *task,
		struct rspamd_statfile_config *stcf, gboolean learn, gpointer p)
{
	struct rspamd_stat_sqlite3_ctx *ctx = p;
	struct rspamd_stat_sqlite3_rt *rt = NULL;
	struct rspamd_stat_sqlite3_db *bk;

	bk = g_hash_table_lookup (ctx->files, stcf);

	if (bk) {
		rt = rspamd_mempool_alloc0 (task->task_pool, sizeof (*rt));
		rt->ctx = ctx;
		rt->db = bk;
		rt->task = task;
	}

	return rt;
}

gboolean
rspamd_sqlite3_process_token (struct rspamd_task *task, struct token_node_s *tok,
		struct rspamd_token_result *res, gpointer p)
{
	struct rspamd_stat_sqlite3_db *bk;
	struct rspamd_stat_sqlite3_rt *rt;
	gint64 iv = 0, idx;

	g_assert (res != NULL);
	g_assert (p != NULL);
	g_assert (res->st_runtime != NULL);
	g_assert (tok != NULL);
	g_assert (tok->datalen >= sizeof (guint32) * 2);

	rt = res->st_runtime->backend_runtime;
	bk = rt->db;

	if (bk == NULL) {
		/* Statfile is does not exist, so all values are zero */
		res->value = 0.0;
		return FALSE;
	}

	if (!bk->in_transaction) {
		rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
				RSPAMD_STAT_BACKEND_TRANSACTION_START_DEF);
		bk->in_transaction = TRUE;
	}

	memcpy (&idx, tok->data, sizeof (idx));

	/* TODO: language and user support */
	if (rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
			RSPAMD_STAT_BACKEND_GET_TOKEN,
			idx, rt->user_id, rt->lang_id, &iv) == SQLITE_OK) {
		res->value = iv;

		/* TODO: purge empty values */
		if (iv == 0) {
			return FALSE;
		}
	}
	else {
		res->value = 0.0;
		return FALSE;
	}


	return TRUE;
}

void
rspamd_sqlite3_finalize_process (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	struct rspamd_stat_sqlite3_rt *rt = runtime;
	struct rspamd_stat_sqlite3_db *bk;

	g_assert (rt != NULL);
	bk = rt->db;

	if (bk->in_transaction) {
		rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
				RSPAMD_STAT_BACKEND_TRANSACTION_COMMIT);
		bk->in_transaction = FALSE;
	}

	return;
}

gboolean
rspamd_sqlite3_learn_token (struct rspamd_task *task, struct token_node_s *tok,
		struct rspamd_token_result *res, gpointer p)
{
	struct rspamd_stat_sqlite3_db *bk;
	struct rspamd_stat_sqlite3_rt *rt;
	gint64 iv = 0, idx;

	g_assert (res != NULL);
	g_assert (p != NULL);
	g_assert (res->st_runtime != NULL);
	g_assert (tok != NULL);
	g_assert (tok->datalen >= sizeof (guint32) * 2);

	rt = res->st_runtime->backend_runtime;
	bk = rt->db;

	if (bk == NULL) {
		/* Statfile is does not exist, so all values are zero */
		return FALSE;
	}

	if (!bk->in_transaction) {
		rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
				RSPAMD_STAT_BACKEND_TRANSACTION_START_IM);
		bk->in_transaction = TRUE;
	}

	iv = res->value;
	memcpy (&idx, tok->data, sizeof (idx));

	if (rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
			RSPAMD_STAT_BACKEND_SET_TOKEN,
			idx, rt->user_id, rt->lang_id, iv) != SQLITE_OK) {
		return FALSE;
	}

	return TRUE;
}

void
rspamd_sqlite3_finalize_learn (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	struct rspamd_stat_sqlite3_rt *rt = runtime;
	struct rspamd_stat_sqlite3_db *bk;

	g_assert (rt != NULL);
	bk = rt->db;

	if (bk->in_transaction) {
		rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
				RSPAMD_STAT_BACKEND_TRANSACTION_COMMIT);
		bk->in_transaction = FALSE;
	}

	return;
}

gulong
rspamd_sqlite3_total_learns (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	struct rspamd_stat_sqlite3_rt *rt = runtime;
	struct rspamd_stat_sqlite3_db *bk;
	guint64 res;

	g_assert (rt != NULL);
	bk = rt->db;
	rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
			RSPAMD_STAT_BACKEND_GET_LEARNS, &res);

	return res;
}

gulong
rspamd_sqlite3_inc_learns (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	struct rspamd_stat_sqlite3_rt *rt = runtime;
	struct rspamd_stat_sqlite3_db *bk;
	guint64 res;

	g_assert (rt != NULL);
	bk = rt->db;
	rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
			RSPAMD_STAT_BACKEND_INC_LEARNS,
			SQLITE3_DEFAULT, SQLITE3_DEFAULT);

	if (bk->in_transaction) {
		rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
				RSPAMD_STAT_BACKEND_TRANSACTION_COMMIT);
		bk->in_transaction = FALSE;
	}

	rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
			RSPAMD_STAT_BACKEND_GET_LEARNS, &res);

	return res;
}

gulong
rspamd_sqlite3_dec_learns (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	struct rspamd_stat_sqlite3_rt *rt = runtime;
	struct rspamd_stat_sqlite3_db *bk;
	guint64 res;

	g_assert (rt != NULL);
	bk = rt->db;
	rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
			RSPAMD_STAT_BACKEND_DEC_LEARNS,
			SQLITE3_DEFAULT, SQLITE3_DEFAULT);

	if (bk->in_transaction) {
		rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
				RSPAMD_STAT_BACKEND_TRANSACTION_COMMIT);
		bk->in_transaction = FALSE;
	}

	rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
			RSPAMD_STAT_BACKEND_GET_LEARNS, &res);

	return res;
}

gulong
rspamd_sqlite3_learns (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	struct rspamd_stat_sqlite3_rt *rt = runtime;
	struct rspamd_stat_sqlite3_db *bk;
	guint64 res;

	g_assert (rt != NULL);
	bk = rt->db;
	rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
			RSPAMD_STAT_BACKEND_GET_LEARNS, &res);

	return res;
}

ucl_object_t *
rspamd_sqlite3_get_stat (gpointer runtime,
		gpointer ctx)
{
	return NULL;
}
