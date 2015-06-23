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
#include "stat_internal.h"
#include "main.h"
#include "sqlite3.h"

#define SQLITE3_BACKEND_TYPE "sqlite3"
#define SQLITE3_SCHEMA_VERSION "1"
#define SQLITE3_DEFAULT "default"

struct rspamd_sqlite3_prstmt;

struct rspamd_stat_sqlite3_db {
	sqlite3 *sqlite;
	struct rspamd_sqlite3_prstmt *prstmt;
	gboolean in_transaction;
};

struct rspamd_stat_sqlite3_ctx {
	GHashTable *files;
};

static const char *create_tables_sql =
		"BEGIN;"
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
		"token INTEGER PRIMARY KEY,"
		"user INTEGER REFERENCES users(id) ON DELETE CASCADE,"
		"language INTEGER REFERENCES languages(id) ON DELETE CASCADE,"
		"value INTEGER"
		");"
		"CREATE UNIQUE INDEX IF NOT EXISTS un ON users(name);"
		"CREATE UNIQUE INDEX IF NOT EXISTS ln ON languages(name);"
		"PRAGMA user_version=" SQLITE3_SCHEMA_VERSION ";"
		"INSERT INTO users(id, name, learns) VALUES(0, '" SQLITE3_DEFAULT "',0);"
		"INSERT INTO languages(id, name, learns) VALUES(0, '" SQLITE3_DEFAULT "',0);"
		"COMMIT;";

enum rspamd_stat_sqlite3_stmt_idx {
	RSPAMD_STAT_BACKEND_TRANSACTION_START = 0,
	RSPAMD_STAT_BACKEND_TRANSACTION_COMMIT,
	RSPAMD_STAT_BACKEND_TRANSACTION_ROLLBACK,
	RSPAMD_STAT_BACKEND_GET_TOKEN,
	RSPAMD_STAT_BACKEND_SET_TOKEN,
	RSPAMD_STAT_BACKEND_INC_LEARNS,
	RSPAMD_STAT_BACKEND_DEC_LEARNS,
	RSPAMD_STAT_BACKEND_GET_LEARNS,
	RSPAMD_STAT_BACKEND_MAX
};

static struct rspamd_sqlite3_prstmt {
	enum rspamd_stat_sqlite3_stmt_idx idx;
	const gchar *sql;
	const gchar *args;
	sqlite3_stmt *stmt;
	gint result;
	const gchar *ret;
} prepared_stmts[RSPAMD_STAT_BACKEND_MAX] =
{
	{
		.idx = RSPAMD_STAT_BACKEND_TRANSACTION_START,
		.sql = "BEGIN IMMEDIATE TRANSACTION;",
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
				"WHERE token=?1 AND users.name=?2 AND languages.name=?3;",
		.stmt = NULL,
		.args = "ITT",
		.result = SQLITE_ROW,
		.ret = "I"
	},
	{
		.idx = RSPAMD_STAT_BACKEND_SET_TOKEN,
		.sql = "INSERT OR REPLACE INTO tokens(token, user, language, value)"
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
rspamd_sqlite3_quark (void)
{
	return g_quark_from_static_string ("sqlite3-stat-backend");
}

static gboolean
rspamd_sqlite3_init_prstmt (struct rspamd_stat_sqlite3_db *db, GError **err)
{
	int i;

	for (i = 0; i < RSPAMD_STAT_BACKEND_MAX; i ++) {
		if (db->prstmt[i].stmt != NULL) {
			/* Skip already prepared statements */
			continue;
		}
		if (sqlite3_prepare_v2 (db->sqlite, db->prstmt[i].sql, -1,
				&db->prstmt[i].stmt, NULL) != SQLITE_OK) {
			g_set_error (err, rspamd_sqlite3_quark (),
				-1, "Cannot initialize prepared sql `%s`: %s",
				db->prstmt[i].sql, sqlite3_errmsg (db->sqlite));

			return FALSE;
		}
	}

	return TRUE;
}

static int
rspamd_sqlite3_run_prstmt (struct rspamd_stat_sqlite3_db *db, int idx, ...)
{
	gint retcode;
	va_list ap;
	sqlite3_stmt *stmt;
	gint i, rowid, nargs, j;
	const char *argtypes;

	if (idx < 0 || idx >= RSPAMD_STAT_BACKEND_MAX) {

		return -1;
	}

	stmt = db->prstmt[idx].stmt;
	if (stmt == NULL) {
		if ((retcode = sqlite3_prepare_v2 (db->sqlite, db->prstmt[idx].sql, -1,
				&db->prstmt[idx].stmt, NULL)) != SQLITE_OK) {
			msg_err ("Cannot initialize prepared sql `%s`: %s",
					db->prstmt[idx].sql, sqlite3_errmsg (db->sqlite));

			return retcode;
		}
		stmt = db->prstmt[idx].stmt;
	}

	msg_debug ("executing `%s`", db->prstmt[idx].sql);
	argtypes = db->prstmt[idx].args;
	sqlite3_reset (stmt);
	va_start (ap, idx);
	nargs = 1;

	for (i = 0, rowid = 1; argtypes[i] != '\0'; i ++, rowid ++) {
		switch (argtypes[i]) {
		case 'T':

			for (j = 0; j < nargs; j ++, rowid ++) {
				sqlite3_bind_text (stmt, rowid, va_arg (ap, const char*), -1,
					SQLITE_STATIC);
			}

			nargs = 1;
			break;
		case 'I':

			for (j = 0; j < nargs; j ++, rowid ++) {
				sqlite3_bind_int64 (stmt, rowid, va_arg (ap, gint64));
			}

			nargs = 1;
			break;
		case 'S':

			for (j = 0; j < nargs; j ++, rowid ++) {
				sqlite3_bind_int (stmt, rowid, va_arg (ap, gint));
			}

			nargs = 1;
			break;
		case '*':
			nargs = va_arg (ap, gint);
			break;
		}
	}

	va_end (ap);
	retcode = sqlite3_step (stmt);

	if (retcode == db->prstmt[idx].result) {
		argtypes = db->prstmt[idx].ret;

		for (i = 0; argtypes != NULL && argtypes[i] != '\0'; i ++) {
			switch (argtypes[i]) {
			case 'T':
				*va_arg (ap, char**) = g_strdup (sqlite3_column_text (stmt, i));
				break;
			case 'I':
				*va_arg (ap, gint64*) = sqlite3_column_int64 (stmt, i);
				break;
			case 'S':
				*va_arg (ap, int*) = sqlite3_column_int (stmt, i);
				break;
			}
		}

		return SQLITE_OK;
	}
	else if (retcode != SQLITE_DONE) {
		msg_debug ("failed to execute query %s: %d, %s", db->prstmt[idx].sql,
				retcode, sqlite3_errmsg (db->sqlite));
	}

	return retcode;
}

static void
rspamd_sqlite3_close_prstmt (struct rspamd_stat_sqlite3_db *db)
{
	int i;

	for (i = 0; i < RSPAMD_STAT_BACKEND_MAX; i++) {
		if (db->prstmt[i].stmt != NULL) {
			sqlite3_finalize (db->prstmt[i].stmt);
			db->prstmt[i].stmt = NULL;
		}
	}

	return;
}

static struct rspamd_stat_sqlite3_db *
rspamd_sqlite3_opendb (const gchar *path, const ucl_object_t *opts,
		gboolean create, GError **err)
{
	struct rspamd_stat_sqlite3_db *bk;
	sqlite3 *sqlite;
	sqlite3_stmt *stmt;
	gint rc, flags;
	static const char sqlite_wal[] = "PRAGMA journal_mode=WAL;",
			fallback_journal[] = "PRAGMA journal_mode=OFF;",
			user_version[] = "PRAGMA user_version;";

	flags = SQLITE_OPEN_READWRITE;

	if (create) {
		flags |= SQLITE_OPEN_CREATE;
	}

	if ((rc = sqlite3_open_v2 (path, &sqlite,
			flags, NULL)) != SQLITE_OK) {
		g_set_error (err, rspamd_sqlite3_quark (),
			rc, "cannot open sqlite db %s: %d",
			path, rc);

		return NULL;
	}

	if (sqlite3_exec (sqlite, sqlite_wal, NULL, NULL, NULL) != SQLITE_OK) {
		msg_warn ("WAL mode is not supported, locking issues might occur");
		sqlite3_exec (sqlite, fallback_journal, NULL, NULL, NULL);
	}

	/* Check user_version */
	g_assert (sqlite3_prepare_v2 (sqlite, user_version, -1, &stmt, NULL)
			== SQLITE_OK);
	g_assert (sqlite3_step (stmt) == SQLITE_ROW);

	if (sqlite3_column_int (stmt, 0) != atoi (SQLITE3_SCHEMA_VERSION)) {
		msg_warn ("bad sqlite database: %s, try to recreate it", path);
		create = TRUE;
	}

	sqlite3_finalize (stmt);

	if (create) {
		if (sqlite3_exec (sqlite, create_tables_sql, NULL, NULL, NULL) != SQLITE_OK) {
			g_set_error (err, rspamd_sqlite3_quark (),
					-1, "cannot execute create sql `%s`: %s",
					create_tables_sql, sqlite3_errmsg (sqlite));
			sqlite3_close (sqlite);

			return NULL;
		}
	}

	bk = g_slice_alloc0 (sizeof (*bk));
	bk->sqlite = sqlite;
	bk->prstmt = g_slice_alloc0 (sizeof (prepared_stmts));
	memcpy (bk->prstmt, prepared_stmts, sizeof (prepared_stmts));

	if (!rspamd_sqlite3_init_prstmt (bk, err)) {
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

				if ((bk = rspamd_sqlite3_opendb (filename, stf->opts, FALSE,
						&err)) == NULL) {
					msg_err ("cannot open sqlite3 db: %e", err);
					g_error_free (err);
					err = NULL;

					bk = rspamd_sqlite3_opendb (filename, stf->opts, TRUE,
							&err);
				}

				if (bk != NULL) {
					g_hash_table_insert (new->files, stf, bk);
				}
				else {
					msg_err ("cannot create sqlite3 db: %e", err);
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
				rspamd_sqlite3_run_prstmt (bk, RSPAMD_STAT_BACKEND_TRANSACTION_COMMIT);
			}

			sqlite3_close (bk->sqlite);
			rspamd_sqlite3_close_prstmt (bk);
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
	return g_hash_table_lookup (ctx->files, stcf);
}

gboolean
rspamd_sqlite3_process_token (struct token_node_s *tok,
		struct rspamd_token_result *res, gpointer p)
{
	struct rspamd_stat_sqlite3_db *bk;
	gint64 iv = 0, idx;

	g_assert (res != NULL);
	g_assert (p != NULL);
	g_assert (res->st_runtime != NULL);
	g_assert (tok != NULL);
	g_assert (tok->datalen >= sizeof (guint32) * 2);

	bk = res->st_runtime->backend_runtime;

	if (bk == NULL) {
		/* Statfile is does not exist, so all values are zero */
		res->value = 0.0;
		return FALSE;
	}

	memcpy (&idx, tok->data, sizeof (idx));

	/* TODO: language and user support */
	if (rspamd_sqlite3_run_prstmt (bk, RSPAMD_STAT_BACKEND_GET_TOKEN,
			idx, SQLITE3_DEFAULT, SQLITE3_DEFAULT, &iv) == SQLITE_OK) {
		res->value = iv;
	}
	else {
		res->value = 0.0;
		return FALSE;
	}


	return TRUE;
}

gboolean
rspamd_sqlite3_learn_token (struct token_node_s *tok,
		struct rspamd_token_result *res, gpointer p)
{
	struct rspamd_stat_sqlite3_db *bk;
	gint64 iv = 0, idx;

	g_assert (res != NULL);
	g_assert (p != NULL);
	g_assert (res->st_runtime != NULL);
	g_assert (tok != NULL);
	g_assert (tok->datalen >= sizeof (guint32) * 2);

	bk = res->st_runtime->backend_runtime;

	if (bk == NULL) {
		/* Statfile is does not exist, so all values are zero */
		return FALSE;
	}

	if (!bk->in_transaction) {
		rspamd_sqlite3_run_prstmt (bk, RSPAMD_STAT_BACKEND_TRANSACTION_START);
		bk->in_transaction = TRUE;
	}

	iv = res->value;
	memcpy (&idx, tok->data, sizeof (idx));

	if (rspamd_sqlite3_run_prstmt (bk, RSPAMD_STAT_BACKEND_SET_TOKEN,
				idx, 0, 0, iv) == SQLITE_OK) {
		return FALSE;
	}

	return TRUE;
}

void
rspamd_sqlite3_finalize_learn (gpointer runtime,
		gpointer ctx)
{
	struct rspamd_stat_sqlite3_db *bk = runtime;

	g_assert (bk != NULL);

	if (bk->in_transaction) {
		rspamd_sqlite3_run_prstmt (bk, RSPAMD_STAT_BACKEND_TRANSACTION_COMMIT);
		bk->in_transaction = FALSE;
	}

	return;
}

gulong
rspamd_sqlite3_total_learns (gpointer runtime,
		gpointer ctx)
{
	struct rspamd_stat_sqlite3_db *bk = runtime;
	guint64 res;

	g_assert (bk != NULL);

	rspamd_sqlite3_run_prstmt (bk, RSPAMD_STAT_BACKEND_GET_LEARNS, &res);

	return res;
}

gulong
rspamd_sqlite3_inc_learns (gpointer runtime,
		gpointer ctx)
{
	struct rspamd_stat_sqlite3_db *bk = runtime;
	guint64 res;

	g_assert (bk != NULL);
	rspamd_sqlite3_run_prstmt (bk, RSPAMD_STAT_BACKEND_GET_LEARNS, &res);
	rspamd_sqlite3_run_prstmt (bk, RSPAMD_STAT_BACKEND_INC_LEARNS,
			SQLITE3_DEFAULT, SQLITE3_DEFAULT);

	return res;
}

gulong
rspamd_sqlite3_dec_learns (gpointer runtime,
		gpointer ctx)
{
	struct rspamd_stat_sqlite3_db *bk = runtime;
	guint64 res;

	g_assert (bk != NULL);
	rspamd_sqlite3_run_prstmt (bk, RSPAMD_STAT_BACKEND_GET_LEARNS, &res);
	rspamd_sqlite3_run_prstmt (bk, RSPAMD_STAT_BACKEND_DEC_LEARNS,
			SQLITE3_DEFAULT, SQLITE3_DEFAULT);

	return res;
}

gulong
rspamd_sqlite3_learns (gpointer runtime,
		gpointer ctx)
{
	struct rspamd_stat_sqlite3_db *bk = runtime;
	guint64 res;

	g_assert (bk);
	rspamd_sqlite3_run_prstmt (bk, RSPAMD_STAT_BACKEND_GET_LEARNS, &res);

	return res;
}

ucl_object_t *
rspamd_sqlite3_get_stat (gpointer runtime,
		gpointer ctx)
{
	return NULL;
}
