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
		"token INTEGER,"
		"user INTEGER REFERENCES users(id) ON DELETE CASCADE,"
		"language INTEGER REFERENCES users(id) ON DELETE CASCADE,"
		"PRIMARY KEY (token,user,language)"
		");"
		"CREATE UNIQUE INDEX IF NOT EXISTS un ON users(name);"
		"CREATE UNIQUE INDEX IF NOT EXISTS ln ON languages(name);"
		"PRAGMA user_version=" SQLITE3_SCHEMA_VERSION
		"INSERT INTO users(id, name, learns) VALUES(0, '" SQLITE3_DEFAULT "',0);"
		"INSERT INTO languages(id, name, learns) VALUES(0, '" SQLITE3_DEFAULT "',0);"
		"COMMIT;";

enum rspamd_stat_sqlite3_stmt_idx {
	RSPAMD_STAT_BACKEND_TRANSACTION_START = 0,
	RSPAMD_STAT_BACKEND_TRANSACTION_COMMIT,
	RSPAMD_STAT_BACKEND_TRANSACTION_ROLLBACK,
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
		.sql = "BEGIN TRANSACTION;",
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
	int retcode;
	va_list ap;
	sqlite3_stmt *stmt;
	int i;
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

	for (i = 0; argtypes[i] != '\0'; i++) {
		switch (argtypes[i]) {
		case 'T':
			sqlite3_bind_text (stmt, i + 1, va_arg (ap, const char*), -1,
					SQLITE_STATIC);
			break;
		case 'I':
			sqlite3_bind_int64 (stmt, i + 1, va_arg (ap, gint64));
			break;
		case 'S':
			sqlite3_bind_int (stmt, i + 1, va_arg (ap, gint));
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
	gint rc, flags;

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

			if (strcmp (stf->backend, SQLITE3_BACKEND_TYPE)) {
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

gpointer
rspamd_sqlite3_runtime (struct rspamd_task *task,
		struct rspamd_statfile_config *stcf, gboolean learn, gpointer p)
{
	struct rspamd_stat_sqlite3_ctx *ctx = p;
	return g_hash_table_lookup (ctx->files, stcf);
}

gboolean
rspamd_sqlite3_process_token (struct token_node_s *tok,
		struct rspamd_token_result *res, gpointer ctx)
{
	return FALSE;
}

gboolean
rspamd_sqlite3_learn_token (struct token_node_s *tok,
		struct rspamd_token_result *res, gpointer ctx)
{
	return FALSE;
}

void
rspamd_sqlite3_finalize_learn (struct rspamd_statfile_runtime *runtime,
		gpointer ctx)
{
	return;
}

gulong
rspamd_sqlite3_total_learns (struct rspamd_statfile_runtime *runtime,
		gpointer ctx)
{
	return 0;
}

gulong
rspamd_sqlite3_inc_learns (struct rspamd_statfile_runtime *runtime,
		gpointer ctx)
{
	return 0;
}

gulong
rspamd_sqlite3_dec_learns (struct rspamd_statfile_runtime *runtime,
		gpointer ctx)
{
	return 0;
}

gulong
rspamd_sqlite3_learns (struct rspamd_statfile_runtime *runtime,
		gpointer ctx)
{
	return 0;
}

ucl_object_t *
rspamd_sqlite3_get_stat (struct rspamd_statfile_runtime *runtime,
		gpointer ctx)
{
	return NULL;
}
