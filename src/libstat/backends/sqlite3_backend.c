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
#include "libmime/message.h"

#define SQLITE3_BACKEND_TYPE "sqlite3"
#define SQLITE3_SCHEMA_VERSION "1"
#define SQLITE3_DEFAULT "default"

struct rspamd_stat_sqlite3_db {
	sqlite3 *sqlite;
	gchar *fname;
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
	struct rspamd_statfile_config *cf;
	gint64 user_id;
	gint64 lang_id;
};

static const char *create_tables_sql =
		"BEGIN IMMEDIATE;"
		"CREATE TABLE tokenizer(data BLOB);"
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
		"modified INTEGER,"
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
	RSPAMD_STAT_BACKEND_TRANSACTION_START_EXCL,
	RSPAMD_STAT_BACKEND_TRANSACTION_COMMIT,
	RSPAMD_STAT_BACKEND_TRANSACTION_ROLLBACK,
	RSPAMD_STAT_BACKEND_GET_TOKEN,
	RSPAMD_STAT_BACKEND_SET_TOKEN,
	RSPAMD_STAT_BACKEND_INC_LEARNS,
	RSPAMD_STAT_BACKEND_DEC_LEARNS,
	RSPAMD_STAT_BACKEND_GET_LEARNS,
	RSPAMD_STAT_BACKEND_GET_LANGUAGE,
	RSPAMD_STAT_BACKEND_GET_USER,
	RSPAMD_STAT_BACKEND_INSERT_LANGUAGE,
	RSPAMD_STAT_BACKEND_INSERT_USER,
	RSPAMD_STAT_BACKEND_SAVE_TOKENIZER,
	RSPAMD_STAT_BACKEND_LOAD_TOKENIZER,
	RSPAMD_STAT_BACKEND_NTOKENS,
	RSPAMD_STAT_BACKEND_NLANGUAGES,
	RSPAMD_STAT_BACKEND_NUSERS,
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
		.idx = RSPAMD_STAT_BACKEND_TRANSACTION_START_EXCL,
		.sql = "BEGIN EXCLUSIVE TRANSACTION;",
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
		.sql = "INSERT OR REPLACE INTO tokens (token, user, language, value, modified) "
				"VALUES (?1, ?2, ?3, ?4, strftime('%s','now'));",
		.stmt = NULL,
		.args = "IIII",
		.result = SQLITE_DONE,
		.ret = ""
	},
	{
		.idx = RSPAMD_STAT_BACKEND_INC_LEARNS,
		.sql = "UPDATE languages SET learns=learns + 1 WHERE id=?1;"
				"UPDATE users SET learns=learns + 1 WHERE id=?2;",
		.stmt = NULL,
		.args = "TT",
		.result = SQLITE_DONE,
		.ret = ""
	},
	{
		.idx = RSPAMD_STAT_BACKEND_DEC_LEARNS,
		.sql = "UPDATE languages SET learns=learns - 1 WHERE id=?1;"
				"UPDATE users SET learns=learns - 1 WHERE id=?2;",
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
	},
	{
		.idx = RSPAMD_STAT_BACKEND_GET_LANGUAGE,
		.sql = "SELECT id FROM languages WHERE name=?1;",
		.stmt = NULL,
		.args = "T",
		.result = SQLITE_ROW,
		.ret = "I"
	},
	{
		.idx = RSPAMD_STAT_BACKEND_GET_USER,
		.sql = "SELECT id FROM users WHERE name=?1;",
		.stmt = NULL,
		.args = "T",
		.result = SQLITE_ROW,
		.ret = "I"
	},
	{
		.idx = RSPAMD_STAT_BACKEND_INSERT_USER,
		.sql = "INSERT INTO users (name, learns) VALUES (?1, 0);",
		.stmt = NULL,
		.args = "T",
		.result = SQLITE_DONE,
		.ret = "L"
	},
	{
		.idx = RSPAMD_STAT_BACKEND_INSERT_LANGUAGE,
		.sql = "INSERT INTO languages (name, learns) VALUES (?1, 0);",
		.stmt = NULL,
		.args = "T",
		.result = SQLITE_DONE,
		.ret = "L"
	},
	{
		.idx = RSPAMD_STAT_BACKEND_SAVE_TOKENIZER,
		.sql = "INSERT INTO tokenizer(data) VALUES (?1);",
		.stmt = NULL,
		.args = "B",
		.result = SQLITE_DONE,
		.ret = ""
	},
	{
		.idx = RSPAMD_STAT_BACKEND_LOAD_TOKENIZER,
		.sql = "SELECT data FROM tokenizer;",
		.stmt = NULL,
		.args = "",
		.result = SQLITE_ROW,
		.ret = "B"
	},
	{
		.idx = RSPAMD_STAT_BACKEND_NTOKENS,
		.sql = "SELECT COUNT(*) FROM tokens;",
		.stmt = NULL,
		.args = "",
		.result = SQLITE_ROW,
		.ret = "I"
	},
	{
		.idx = RSPAMD_STAT_BACKEND_NLANGUAGES,
		.sql = "SELECT COUNT(*) FROM languages;",
		.stmt = NULL,
		.args = "",
		.result = SQLITE_ROW,
		.ret = "I"
	},
	{
		.idx = RSPAMD_STAT_BACKEND_NUSERS,
		.sql = "SELECT COUNT(*) FROM users;",
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

static gint64
rspamd_sqlite3_get_user (struct rspamd_stat_sqlite3_db *db,
		struct rspamd_task *task, gboolean learn)
{
	gint64 id = 0; /* Default user is 0 */
	gint rc;
	const gchar *user = NULL;
	const InternetAddress *ia;

	if (task->deliver_to != NULL) {
		/* Use deliver-to value if presented */
		user = task->deliver_to;
	}
	if (task->user != NULL) {
		/* Use user value if presented */
		user = task->user;
	}
	else if (task->rcpt_envelope != NULL) {
		/* Check envelope recipients */
		if (internet_address_list_length (task->rcpt_envelope) == 1) {
			/* XXX: we support now merely single recipient statistics */
			ia = internet_address_list_get_address (task->rcpt_envelope, 0);

			if (ia != NULL) {
				user = internet_address_mailbox_get_addr (INTERNET_ADDRESS_MAILBOX (ia));
			}
		}
	}

	/* XXX: We ignore now mime recipients as they could be easily forged */
	if (user != NULL) {
		rc = rspamd_sqlite3_run_prstmt (db->sqlite, db->prstmt,
				RSPAMD_STAT_BACKEND_GET_USER, user, &id);

		if (rc != SQLITE_OK && learn) {
			/* We need to insert a new user */
			if (!db->in_transaction) {
				rspamd_sqlite3_run_prstmt (db->sqlite, db->prstmt,
						RSPAMD_STAT_BACKEND_TRANSACTION_START_IM);
				db->in_transaction = TRUE;
			}

			rc =  rspamd_sqlite3_run_prstmt (db->sqlite, db->prstmt,
					RSPAMD_STAT_BACKEND_INSERT_USER, user, &id);
		}
	}

	return id;
}

static gint64
rspamd_sqlite3_get_language (struct rspamd_stat_sqlite3_db *db,
		struct rspamd_task *task, gboolean learn)
{
	gint64 id = 0; /* Default language is 0 */
	gint rc;
	guint i;
	const gchar *language = NULL;
	struct mime_text_part *tp;

	for (i = 0; i < task->text_parts->len; i ++) {
		tp = g_ptr_array_index (task->text_parts, i);

		if (tp->lang_code != NULL && tp->lang_code[0] != '\0' &&
				strcmp (tp->lang_code, "en") != 0) {
			language = tp->language;
			break;
		}
	}

	/* XXX: We ignore multiple languages but default + extra */
	if (language != NULL) {
		rc = rspamd_sqlite3_run_prstmt (db->sqlite, db->prstmt,
				RSPAMD_STAT_BACKEND_GET_LANGUAGE, language, &id);

		if (rc != SQLITE_OK && learn) {
			/* We need to insert a new language */
			if (!db->in_transaction) {
				rspamd_sqlite3_run_prstmt (db->sqlite, db->prstmt,
						RSPAMD_STAT_BACKEND_TRANSACTION_START_IM);
				db->in_transaction = TRUE;
			}

			rc =  rspamd_sqlite3_run_prstmt (db->sqlite, db->prstmt,
					RSPAMD_STAT_BACKEND_INSERT_LANGUAGE, language, &id);
		}
	}

	return id;
}

static struct rspamd_stat_sqlite3_db *
rspamd_sqlite3_opendb (rspamd_mempool_t *pool,
		struct rspamd_statfile_config *stcf,
		const gchar *path, const ucl_object_t *opts,
		gboolean create, GError **err)
{
	struct rspamd_stat_sqlite3_db *bk;
	struct rspamd_stat_tokenizer *tokenizer;
	gpointer tk_conf;
	guint64 sz;
	struct timespec sleep_ts = {
			.tv_sec = 0,
			.tv_nsec = 1000000
	};

	bk = g_slice_alloc0 (sizeof (*bk));
	bk->sqlite = rspamd_sqlite3_open_or_create (path, create_tables_sql, err);

	if (bk->sqlite == NULL) {
		g_slice_free1 (sizeof (*bk), bk);

		return NULL;
	}

	bk->fname = g_strdup (path);

	bk->prstmt = rspamd_sqlite3_init_prstmt (bk->sqlite, prepared_stmts,
			RSPAMD_STAT_BACKEND_MAX, err);

	if (bk->prstmt == NULL) {
		sqlite3_close (bk->sqlite);
		g_slice_free1 (sizeof (*bk), bk);

		return NULL;
	}

	/* Check tokenizer configuration */

	while (rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
			RSPAMD_STAT_BACKEND_TRANSACTION_START_EXCL) != SQLITE_OK) {
		nanosleep (&sleep_ts, NULL);
	}

	if (rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
			RSPAMD_STAT_BACKEND_LOAD_TOKENIZER, &sz, &tk_conf) != SQLITE_OK) {
		g_assert (stcf->clcf->tokenizer != NULL);
		tokenizer = rspamd_stat_get_tokenizer (stcf->clcf->tokenizer->name);
		g_assert (tokenizer != NULL);
		tk_conf = tokenizer->get_config (pool, stcf->clcf->tokenizer, (gsize *)&sz);

		if (rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
					RSPAMD_STAT_BACKEND_SAVE_TOKENIZER, sz, tk_conf) != SQLITE_OK) {
			sqlite3_close (bk->sqlite);
			g_slice_free1 (sizeof (*bk), bk);

			return NULL;
		}
	}
	else {
		g_free (tk_conf);
	}

	rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
				RSPAMD_STAT_BACKEND_TRANSACTION_COMMIT);

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
		if (clf->backend && strcmp (clf->backend, SQLITE3_BACKEND_TYPE) == 0) {
			curst = clf->statfiles;

			while (curst) {
				stf = curst->data;
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

				if ((bk = rspamd_sqlite3_opendb (cfg->cfg_pool, stf, filename,
						stf->opts, TRUE, &err)) == NULL) {
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

				curst = curst->next;
			}
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
			g_free (bk->fname);
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
		rt = rspamd_mempool_alloc (task->task_pool, sizeof (*rt));
		rt->ctx = ctx;
		rt->db = bk;
		rt->task = task;
		rt->user_id = -1;
		rt->lang_id = -1;
		rt->cf = stcf;
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

	if (rt->user_id == -1) {
		rt->user_id = rspamd_sqlite3_get_user (bk, task, FALSE);
	}

	if (rt->lang_id == -1) {
		rt->lang_id = rspamd_sqlite3_get_language (bk, task, FALSE);
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

	if (rt->user_id == -1) {
		rt->user_id = rspamd_sqlite3_get_user (bk, task, TRUE);
	}

	if (rt->lang_id == -1) {
		rt->lang_id = rspamd_sqlite3_get_language (bk, task, FALSE);
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
			rt->user_id, rt->lang_id);

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
			rt->user_id, rt->lang_id);

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
	ucl_object_t *res = NULL;
	struct rspamd_stat_sqlite3_rt *rt = runtime;
	struct rspamd_stat_sqlite3_db *bk;
	struct stat st;
	gint64 rev;

	g_assert (rt != NULL);
	bk = rt->db;

	(void)stat (bk->fname, &st);
	rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
				RSPAMD_STAT_BACKEND_GET_LEARNS, &rev);

	res = ucl_object_typed_new (UCL_OBJECT);
	ucl_object_insert_key (res, ucl_object_fromint (rev), "revision",
			0, false);
	ucl_object_insert_key (res, ucl_object_fromint (st.st_size), "size",
			0, false);
	rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
			RSPAMD_STAT_BACKEND_NTOKENS, &rev);
	ucl_object_insert_key (res, ucl_object_fromint (rev), "total", 0, false);
	ucl_object_insert_key (res, ucl_object_fromint (rev), "used", 0, false);
	ucl_object_insert_key (res, ucl_object_fromstring (rt->cf->symbol),
			"symbol", 0, false);
	ucl_object_insert_key (res, ucl_object_fromstring ("sqlite3"),
			"type", 0, false);
	rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
			RSPAMD_STAT_BACKEND_NLANGUAGES, &rev);
	ucl_object_insert_key (res, ucl_object_fromint (rev),
			"languages", 0, false);
	rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
			RSPAMD_STAT_BACKEND_NUSERS, &rev);
	ucl_object_insert_key (res, ucl_object_fromint (rev),
			"users", 0, false);

	if (rt->cf->label) {
		ucl_object_insert_key (res, ucl_object_fromstring (rt->cf->label),
				"label", 0, false);
	}

	return res;
}

gpointer
rspamd_sqlite3_load_tokenizer_config (gpointer runtime,
		gsize *len)
{
	gpointer tk_conf, copied_conf;
	guint64 sz;
	struct rspamd_stat_sqlite3_rt *rt = runtime;
	struct rspamd_stat_sqlite3_db *bk;

	g_assert (rt != NULL);
	bk = rt->db;

	g_assert (rspamd_sqlite3_run_prstmt (bk->sqlite, bk->prstmt,
				RSPAMD_STAT_BACKEND_LOAD_TOKENIZER, &sz, &tk_conf) == SQLITE_OK);
	g_assert (sz > 0);
	copied_conf = rspamd_mempool_alloc (rt->task->task_pool, sz);
	memcpy (copied_conf, tk_conf, sz);
	g_free (tk_conf);

	if (len) {
		*len = sz;
	}

	return copied_conf;
}
