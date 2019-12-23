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
#include "rspamd.h"
#include "fuzzy_backend.h"
#include "fuzzy_backend_sqlite.h"
#include "unix-std.h"

#include <sqlite3.h>
#include "libutil/sqlite_utils.h"

struct rspamd_fuzzy_backend_sqlite {
	sqlite3 *db;
	char *path;
	gchar id[MEMPOOL_UID_LEN];
	gsize count;
	gsize expired;
	rspamd_mempool_t *pool;
};

static const gdouble sql_sleep_time = 0.1;
static const guint max_retries = 10;

#define msg_err_fuzzy_backend(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        backend->pool->tag.tagname, backend->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_fuzzy_backend(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        backend->pool->tag.tagname, backend->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_fuzzy_backend(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        backend->pool->tag.tagname, backend->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_fuzzy_backend(...)  rspamd_conditional_debug_fast (NULL, NULL, \
       rspamd_fuzzy_sqlite_log_id, backend->pool->tag.tagname, backend->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(fuzzy_sqlite)

static const char *create_tables_sql =
		"BEGIN;"
		"CREATE TABLE IF NOT EXISTS digests("
		"	id INTEGER PRIMARY KEY,"
		"	flag INTEGER NOT NULL,"
		"	digest TEXT NOT NULL,"
		"	value INTEGER,"
		"	time INTEGER);"
		"CREATE TABLE IF NOT EXISTS shingles("
		"	value INTEGER NOT NULL,"
		"	number INTEGER NOT NULL,"
		"	digest_id INTEGER REFERENCES digests(id) ON DELETE CASCADE "
		"	ON UPDATE CASCADE);"
		"CREATE TABLE IF NOT EXISTS sources("
		"	name TEXT UNIQUE,"
		"	version INTEGER,"
		"	last INTEGER);"
		"CREATE UNIQUE INDEX IF NOT EXISTS d ON digests(digest);"
		"CREATE INDEX IF NOT EXISTS t ON digests(time);"
		"CREATE INDEX IF NOT EXISTS dgst_id ON shingles(digest_id);"
		"CREATE UNIQUE INDEX IF NOT EXISTS s ON shingles(value, number);"
		"COMMIT;";
#if 0
static const char *create_index_sql =
		"BEGIN;"
		"CREATE UNIQUE INDEX IF NOT EXISTS d ON digests(digest);"
		"CREATE INDEX IF NOT EXISTS t ON digests(time);"
		"CREATE INDEX IF NOT EXISTS dgst_id ON shingles(digest_id);"
		"CREATE UNIQUE INDEX IF NOT EXISTS s ON shingles(value, number);"
		"COMMIT;";
#endif
enum rspamd_fuzzy_statement_idx {
	RSPAMD_FUZZY_BACKEND_TRANSACTION_START = 0,
	RSPAMD_FUZZY_BACKEND_TRANSACTION_COMMIT,
	RSPAMD_FUZZY_BACKEND_TRANSACTION_ROLLBACK,
	RSPAMD_FUZZY_BACKEND_INSERT,
	RSPAMD_FUZZY_BACKEND_UPDATE,
	RSPAMD_FUZZY_BACKEND_UPDATE_FLAG,
	RSPAMD_FUZZY_BACKEND_INSERT_SHINGLE,
	RSPAMD_FUZZY_BACKEND_CHECK,
	RSPAMD_FUZZY_BACKEND_CHECK_SHINGLE,
	RSPAMD_FUZZY_BACKEND_GET_DIGEST_BY_ID,
	RSPAMD_FUZZY_BACKEND_DELETE,
	RSPAMD_FUZZY_BACKEND_COUNT,
	RSPAMD_FUZZY_BACKEND_EXPIRE,
	RSPAMD_FUZZY_BACKEND_VACUUM,
	RSPAMD_FUZZY_BACKEND_DELETE_ORPHANED,
	RSPAMD_FUZZY_BACKEND_ADD_SOURCE,
	RSPAMD_FUZZY_BACKEND_VERSION,
	RSPAMD_FUZZY_BACKEND_SET_VERSION,
	RSPAMD_FUZZY_BACKEND_MAX
};
static struct rspamd_fuzzy_stmts {
	enum rspamd_fuzzy_statement_idx idx;
	const gchar *sql;
	const gchar *args;
	sqlite3_stmt *stmt;
	gint result;
} prepared_stmts[RSPAMD_FUZZY_BACKEND_MAX] =
{
	{
		.idx = RSPAMD_FUZZY_BACKEND_TRANSACTION_START,
		.sql = "BEGIN TRANSACTION;",
		.args = "",
		.stmt = NULL,
		.result = SQLITE_DONE
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_TRANSACTION_COMMIT,
		.sql = "COMMIT;",
		.args = "",
		.stmt = NULL,
		.result = SQLITE_DONE
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_TRANSACTION_ROLLBACK,
		.sql = "ROLLBACK;",
		.args = "",
		.stmt = NULL,
		.result = SQLITE_DONE
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_INSERT,
		.sql = "INSERT INTO digests(flag, digest, value, time) VALUES"
				"(?1, ?2, ?3, strftime('%s','now'));",
		.args = "SDI",
		.stmt = NULL,
		.result = SQLITE_DONE
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_UPDATE,
		.sql = "UPDATE digests SET value = value + ?1, time = strftime('%s','now') WHERE "
				"digest==?2;",
		.args = "ID",
		.stmt = NULL,
		.result = SQLITE_DONE
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_UPDATE_FLAG,
		.sql = "UPDATE digests SET value = ?1, flag = ?2, time = strftime('%s','now') WHERE "
				"digest==?3;",
		.args = "IID",
		.stmt = NULL,
		.result = SQLITE_DONE
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_INSERT_SHINGLE,
		.sql = "INSERT OR REPLACE INTO shingles(value, number, digest_id) "
				"VALUES (?1, ?2, ?3);",
		.args = "III",
		.stmt = NULL,
		.result = SQLITE_DONE
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_CHECK,
		.sql = "SELECT value, time, flag FROM digests WHERE digest==?1;",
		.args = "D",
		.stmt = NULL,
		.result = SQLITE_ROW
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_CHECK_SHINGLE,
		.sql = "SELECT digest_id FROM shingles WHERE value=?1 AND number=?2",
		.args = "IS",
		.stmt = NULL,
		.result = SQLITE_ROW
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_GET_DIGEST_BY_ID,
		.sql = "SELECT digest, value, time, flag FROM digests WHERE id=?1",
		.args = "I",
		.stmt = NULL,
		.result = SQLITE_ROW
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_DELETE,
		.sql = "DELETE FROM digests WHERE digest==?1;",
		.args = "D",
		.stmt = NULL,
		.result = SQLITE_DONE
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_COUNT,
		.sql = "SELECT COUNT(*) FROM digests;",
		.args = "",
		.stmt = NULL,
		.result = SQLITE_ROW
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_EXPIRE,
		.sql = "DELETE FROM digests WHERE id IN (SELECT id FROM digests WHERE time < ?1 LIMIT ?2);",
		.args = "II",
		.stmt = NULL,
		.result = SQLITE_DONE
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_VACUUM,
		.sql = "VACUUM;",
		.args = "",
		.stmt = NULL,
		.result = SQLITE_DONE
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_DELETE_ORPHANED,
		.sql = "DELETE FROM shingles WHERE value=?1 AND number=?2;",
		.args = "II",
		.stmt = NULL,
		.result = SQLITE_DONE
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_ADD_SOURCE,
		.sql = "INSERT OR IGNORE INTO sources(name, version, last) VALUES (?1, ?2, ?3);",
		.args = "TII",
		.stmt = NULL,
		.result = SQLITE_DONE
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_VERSION,
		.sql = "SELECT version FROM sources WHERE name=?1;",
		.args = "T",
		.stmt = NULL,
		.result = SQLITE_ROW
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_SET_VERSION,
		.sql = "INSERT OR REPLACE INTO sources (name, version, last) VALUES (?3, ?1, ?2);",
		.args = "IIT",
		.stmt = NULL,
		.result = SQLITE_DONE
	},
};

static GQuark
rspamd_fuzzy_backend_sqlite_quark (void)
{
	return g_quark_from_static_string ("fuzzy-backend-sqlite");
}

static gboolean
rspamd_fuzzy_backend_sqlite_prepare_stmts (struct rspamd_fuzzy_backend_sqlite *bk, GError **err)
{
	int i;

	for (i = 0; i < RSPAMD_FUZZY_BACKEND_MAX; i ++) {
		if (prepared_stmts[i].stmt != NULL) {
			/* Skip already prepared statements */
			continue;
		}
		if (sqlite3_prepare_v2 (bk->db, prepared_stmts[i].sql, -1,
				&prepared_stmts[i].stmt, NULL) != SQLITE_OK) {
			g_set_error (err, rspamd_fuzzy_backend_sqlite_quark (),
				-1, "Cannot initialize prepared sql `%s`: %s",
				prepared_stmts[i].sql, sqlite3_errmsg (bk->db));

			return FALSE;
		}
	}

	return TRUE;
}

static int
rspamd_fuzzy_backend_sqlite_cleanup_stmt (struct rspamd_fuzzy_backend_sqlite *backend,
		int idx)
{
	sqlite3_stmt *stmt;

	if (idx < 0 || idx >= RSPAMD_FUZZY_BACKEND_MAX) {

		return -1;
	}

	msg_debug_fuzzy_backend ("resetting `%s`", prepared_stmts[idx].sql);
	stmt = prepared_stmts[idx].stmt;
	sqlite3_clear_bindings (stmt);
	sqlite3_reset (stmt);

	return SQLITE_OK;
}

static int
rspamd_fuzzy_backend_sqlite_run_stmt (struct rspamd_fuzzy_backend_sqlite *backend,
		gboolean auto_cleanup,
		int idx, ...)
{
	int retcode;
	va_list ap;
	sqlite3_stmt *stmt;
	int i;
	const char *argtypes;
	guint retries = 0;
	struct timespec ts;

	if (idx < 0 || idx >= RSPAMD_FUZZY_BACKEND_MAX) {

		return -1;
	}

	stmt = prepared_stmts[idx].stmt;
	g_assert ((int)prepared_stmts[idx].idx == idx);

	if (stmt == NULL) {
		if ((retcode = sqlite3_prepare_v2 (backend->db, prepared_stmts[idx].sql, -1,
				&prepared_stmts[idx].stmt, NULL)) != SQLITE_OK) {
			msg_err_fuzzy_backend ("Cannot initialize prepared sql `%s`: %s",
					prepared_stmts[idx].sql, sqlite3_errmsg (backend->db));

			return retcode;
		}
		stmt = prepared_stmts[idx].stmt;
	}

	msg_debug_fuzzy_backend ("executing `%s` %s auto cleanup",
			prepared_stmts[idx].sql, auto_cleanup ? "with" : "without");
	argtypes = prepared_stmts[idx].args;
	sqlite3_clear_bindings (stmt);
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
		case 'D':
			/* Special case for digests variable */
			sqlite3_bind_text (stmt, i + 1, va_arg (ap, const char*), 64,
					SQLITE_STATIC);
			break;
		}
	}

	va_end (ap);

retry:
	retcode = sqlite3_step (stmt);

	if (retcode == prepared_stmts[idx].result) {
		retcode = SQLITE_OK;
	}
	else {
		if ((retcode == SQLITE_BUSY ||
				retcode == SQLITE_LOCKED) && retries++ < max_retries) {
			double_to_ts (sql_sleep_time, &ts);
			nanosleep (&ts, NULL);
			goto retry;
		}

		msg_debug_fuzzy_backend ("failed to execute query %s: %d, %s", prepared_stmts[idx].sql,
				retcode, sqlite3_errmsg (backend->db));
	}

	if (auto_cleanup) {
		sqlite3_clear_bindings (stmt);
		sqlite3_reset (stmt);
	}

	return retcode;
}

static void
rspamd_fuzzy_backend_sqlite_close_stmts (struct rspamd_fuzzy_backend_sqlite *bk)
{
	int i;

	for (i = 0; i < RSPAMD_FUZZY_BACKEND_MAX; i++) {
		if (prepared_stmts[i].stmt != NULL) {
			sqlite3_finalize (prepared_stmts[i].stmt);
			prepared_stmts[i].stmt = NULL;
		}
	}

	return;
}

static gboolean
rspamd_fuzzy_backend_sqlite_run_sql (const gchar *sql, struct rspamd_fuzzy_backend_sqlite *bk,
		GError **err)
{
	guint retries = 0;
	struct timespec ts;
	gint ret;

	do {
		ret = sqlite3_exec (bk->db, sql, NULL, NULL, NULL);
		double_to_ts (sql_sleep_time, &ts);
	} while (ret == SQLITE_BUSY && retries++ < max_retries &&
			nanosleep (&ts, NULL) == 0);

	if (ret != SQLITE_OK) {
		g_set_error (err, rspamd_fuzzy_backend_sqlite_quark (),
				-1, "Cannot execute raw sql `%s`: %s",
				sql, sqlite3_errmsg (bk->db));
		return FALSE;
	}

	return TRUE;
}

static struct rspamd_fuzzy_backend_sqlite *
rspamd_fuzzy_backend_sqlite_open_db (const gchar *path, GError **err)
{
	struct rspamd_fuzzy_backend_sqlite *bk;
	rspamd_cryptobox_hash_state_t st;
	guchar hash_out[rspamd_cryptobox_HASHBYTES];

	g_assert (path != NULL);

	bk = g_malloc0 (sizeof (*bk));
	bk->path = g_strdup (path);
	bk->expired = 0;
	bk->pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
			"fuzzy_backend", 0);
	bk->db = rspamd_sqlite3_open_or_create (bk->pool, bk->path,
			create_tables_sql, 1, err);

	if (bk->db == NULL) {
		rspamd_fuzzy_backend_sqlite_close (bk);

		return NULL;
	}

	if (!rspamd_fuzzy_backend_sqlite_prepare_stmts (bk, err)) {
		rspamd_fuzzy_backend_sqlite_close (bk);

		return NULL;
	}

	/* Set id for the backend */
	rspamd_cryptobox_hash_init (&st, NULL, 0);
	rspamd_cryptobox_hash_update (&st, path, strlen (path));
	rspamd_cryptobox_hash_final (&st, hash_out);
	rspamd_snprintf (bk->id, sizeof (bk->id), "%xs", hash_out);
	memcpy (bk->pool->tag.uid, bk->id, sizeof (bk->pool->tag.uid));

	return bk;
}

struct rspamd_fuzzy_backend_sqlite *
rspamd_fuzzy_backend_sqlite_open (const gchar *path,
		gboolean vacuum,
		GError **err)
{
	struct rspamd_fuzzy_backend_sqlite *backend;

	if (path == NULL) {
		g_set_error (err, rspamd_fuzzy_backend_sqlite_quark (),
				ENOENT, "Path has not been specified");
		return NULL;
	}

	/* Open database */
	if ((backend = rspamd_fuzzy_backend_sqlite_open_db (path, err)) == NULL) {
		return NULL;
	}

	if (rspamd_fuzzy_backend_sqlite_run_stmt (backend, FALSE, RSPAMD_FUZZY_BACKEND_COUNT)
			== SQLITE_OK) {
		backend->count = sqlite3_column_int64 (
				prepared_stmts[RSPAMD_FUZZY_BACKEND_COUNT].stmt, 0);
	}

	rspamd_fuzzy_backend_sqlite_cleanup_stmt (backend, RSPAMD_FUZZY_BACKEND_COUNT);

	return backend;
}

static gint
rspamd_fuzzy_backend_sqlite_int64_cmp (const void *a, const void *b)
{
	gint64 ia = *(gint64 *)a, ib = *(gint64 *)b;

	return (ia - ib);
}

struct rspamd_fuzzy_reply
rspamd_fuzzy_backend_sqlite_check (struct rspamd_fuzzy_backend_sqlite *backend,
		const struct rspamd_fuzzy_cmd *cmd, gint64 expire)
{
	struct rspamd_fuzzy_reply rep;
	const struct rspamd_fuzzy_shingle_cmd *shcmd;
	int rc;
	gint64 timestamp;
	gint64 shingle_values[RSPAMD_SHINGLE_SIZE], i, sel_id, cur_id,
		cur_cnt, max_cnt;

	memset (&rep, 0, sizeof (rep));
	memcpy (rep.digest, cmd->digest, sizeof (rep.digest));

	if (backend == NULL) {
		return rep;
	}

	/* Try direct match first of all */
	rspamd_fuzzy_backend_sqlite_run_stmt (backend, TRUE,
			RSPAMD_FUZZY_BACKEND_TRANSACTION_START);
	rc = rspamd_fuzzy_backend_sqlite_run_stmt (backend, FALSE,
			RSPAMD_FUZZY_BACKEND_CHECK,
			cmd->digest);

	if (rc == SQLITE_OK) {
		timestamp = sqlite3_column_int64 (
				prepared_stmts[RSPAMD_FUZZY_BACKEND_CHECK].stmt, 1);
		if (time (NULL) - timestamp > expire) {
			/* Expire element */
			msg_debug_fuzzy_backend ("requested hash has been expired");
		}
		else {
			rep.v1.value = sqlite3_column_int64 (
				prepared_stmts[RSPAMD_FUZZY_BACKEND_CHECK].stmt, 0);
			rep.v1.prob = 1.0;
			rep.v1.flag = sqlite3_column_int (
					prepared_stmts[RSPAMD_FUZZY_BACKEND_CHECK].stmt, 2);
		}
	}
	else if (cmd->shingles_count > 0) {
		/* Fuzzy match */

		rspamd_fuzzy_backend_sqlite_cleanup_stmt (backend, RSPAMD_FUZZY_BACKEND_CHECK);
		shcmd = (const struct rspamd_fuzzy_shingle_cmd *)cmd;

		for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
			rc = rspamd_fuzzy_backend_sqlite_run_stmt (backend, FALSE,
					RSPAMD_FUZZY_BACKEND_CHECK_SHINGLE,
					shcmd->sgl.hashes[i], i);
			if (rc == SQLITE_OK) {
				shingle_values[i] = sqlite3_column_int64 (
						prepared_stmts[RSPAMD_FUZZY_BACKEND_CHECK_SHINGLE].stmt,
						0);
			}
			else {
				shingle_values[i] = -1;
			}
			msg_debug_fuzzy_backend ("looking for shingle %L -> %L: %d", i,
					shcmd->sgl.hashes[i], rc);
		}

		rspamd_fuzzy_backend_sqlite_cleanup_stmt (backend,
				RSPAMD_FUZZY_BACKEND_CHECK_SHINGLE);

		qsort (shingle_values, RSPAMD_SHINGLE_SIZE, sizeof (gint64),
				rspamd_fuzzy_backend_sqlite_int64_cmp);
		sel_id = -1;
		cur_id = -1;
		cur_cnt = 0;
		max_cnt = 0;

		for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
			if (shingle_values[i] == -1) {
				continue;
			}

			/* We have some value here, so we need to check it */
			if (shingle_values[i] == cur_id) {
				cur_cnt ++;
			}
			else {
				cur_id = shingle_values[i];
				if (cur_cnt >= max_cnt) {
					max_cnt = cur_cnt;
					sel_id = cur_id;
				}
				cur_cnt = 0;
			}
		}

		if (cur_cnt > max_cnt) {
			max_cnt = cur_cnt;
		}

		if (sel_id != -1) {
			/* We have some id selected here */
			rep.v1.prob = (float)max_cnt / (float)RSPAMD_SHINGLE_SIZE;

			if (rep.v1.prob > 0.5) {
				msg_debug_fuzzy_backend (
						"found fuzzy hash with probability %.2f",
						rep.v1.prob);
				rc = rspamd_fuzzy_backend_sqlite_run_stmt (backend, FALSE,
						RSPAMD_FUZZY_BACKEND_GET_DIGEST_BY_ID, sel_id);
				if (rc == SQLITE_OK) {
					timestamp = sqlite3_column_int64 (
							prepared_stmts[RSPAMD_FUZZY_BACKEND_GET_DIGEST_BY_ID].stmt,
							2);
					if (time (NULL) - timestamp > expire) {
						/* Expire element */
						msg_debug_fuzzy_backend (
								"requested hash has been expired");
						rep.v1.prob = 0.0;
					}
					else {
						rep.ts = timestamp;
						memcpy (rep.digest, sqlite3_column_blob (
								prepared_stmts[RSPAMD_FUZZY_BACKEND_GET_DIGEST_BY_ID].stmt,
								0), sizeof (rep.digest));
						rep.v1.value = sqlite3_column_int64 (
								prepared_stmts[RSPAMD_FUZZY_BACKEND_GET_DIGEST_BY_ID].stmt,
								1);
						rep.v1.flag = sqlite3_column_int (
								prepared_stmts[RSPAMD_FUZZY_BACKEND_GET_DIGEST_BY_ID].stmt,
								3);
					}
				}
			}
			else {
				/* Otherwise we assume that as error */
				rep.v1.value = 0;
			}

			rspamd_fuzzy_backend_sqlite_cleanup_stmt (backend,
					RSPAMD_FUZZY_BACKEND_GET_DIGEST_BY_ID);
		}
	}

	rspamd_fuzzy_backend_sqlite_cleanup_stmt (backend, RSPAMD_FUZZY_BACKEND_CHECK);
	rspamd_fuzzy_backend_sqlite_run_stmt (backend, TRUE,
			RSPAMD_FUZZY_BACKEND_TRANSACTION_COMMIT);

	return rep;
}

gboolean
rspamd_fuzzy_backend_sqlite_prepare_update (struct rspamd_fuzzy_backend_sqlite *backend,
		const gchar *source)
{
	gint rc;

	if (backend == NULL) {
		return FALSE;
	}

	rc = rspamd_fuzzy_backend_sqlite_run_stmt (backend, TRUE,
			RSPAMD_FUZZY_BACKEND_TRANSACTION_START);

	if (rc != SQLITE_OK) {
		msg_warn_fuzzy_backend ("cannot start transaction for updates: %s",
				sqlite3_errmsg (backend->db));
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_fuzzy_backend_sqlite_add (struct rspamd_fuzzy_backend_sqlite *backend,
		const struct rspamd_fuzzy_cmd *cmd)
{
	int rc, i;
	gint64 id, flag;
	const struct rspamd_fuzzy_shingle_cmd *shcmd;

	if (backend == NULL) {
		return FALSE;
	}

	rc = rspamd_fuzzy_backend_sqlite_run_stmt (backend, FALSE,
			RSPAMD_FUZZY_BACKEND_CHECK,
			cmd->digest);

	if (rc == SQLITE_OK) {
		/* Check flag */
		flag = sqlite3_column_int64 (
				prepared_stmts[RSPAMD_FUZZY_BACKEND_CHECK].stmt,
				2);
		rspamd_fuzzy_backend_sqlite_cleanup_stmt (backend, RSPAMD_FUZZY_BACKEND_CHECK);

		if (flag == cmd->flag) {
			/* We need to increase weight */
			rc = rspamd_fuzzy_backend_sqlite_run_stmt (backend, TRUE,
					RSPAMD_FUZZY_BACKEND_UPDATE,
					(gint64) cmd->value,
					cmd->digest);
			if (rc != SQLITE_OK) {
				msg_warn_fuzzy_backend ("cannot update hash to %d -> "
						"%*xs: %s", (gint) cmd->flag,
						(gint) sizeof (cmd->digest), cmd->digest,
						sqlite3_errmsg (backend->db));
			}
		}
		else {
			/* We need to relearn actually */

			rc = rspamd_fuzzy_backend_sqlite_run_stmt (backend, TRUE,
					RSPAMD_FUZZY_BACKEND_UPDATE_FLAG,
					(gint64) cmd->value,
					(gint64) cmd->flag,
					cmd->digest);

			if (rc != SQLITE_OK) {
				msg_warn_fuzzy_backend ("cannot update hash to %d -> "
						"%*xs: %s", (gint) cmd->flag,
						(gint) sizeof (cmd->digest), cmd->digest,
						sqlite3_errmsg (backend->db));
			}
		}
	}
	else {
		rspamd_fuzzy_backend_sqlite_cleanup_stmt (backend, RSPAMD_FUZZY_BACKEND_CHECK);
		rc = rspamd_fuzzy_backend_sqlite_run_stmt (backend, FALSE,
				RSPAMD_FUZZY_BACKEND_INSERT,
				(gint) cmd->flag,
				cmd->digest,
				(gint64) cmd->value);

		if (rc == SQLITE_OK) {
			if (cmd->shingles_count > 0) {
				id = sqlite3_last_insert_rowid (backend->db);
				shcmd = (const struct rspamd_fuzzy_shingle_cmd *) cmd;

				for (i = 0; i < RSPAMD_SHINGLE_SIZE; i++) {
					rc = rspamd_fuzzy_backend_sqlite_run_stmt (backend, TRUE,
							RSPAMD_FUZZY_BACKEND_INSERT_SHINGLE,
							shcmd->sgl.hashes[i], (gint64)i, id);
					msg_debug_fuzzy_backend ("add shingle %d -> %L: %L",
							i,
							shcmd->sgl.hashes[i],
							id);

					if (rc != SQLITE_OK) {
						msg_warn_fuzzy_backend ("cannot add shingle %d -> "
								"%L: %L: %s", i,
								shcmd->sgl.hashes[i],
								id, sqlite3_errmsg (backend->db));
					}
				}
			}
		}
		else {
			msg_warn_fuzzy_backend ("cannot add hash to %d -> "
					"%*xs: %s", (gint)cmd->flag,
					(gint)sizeof (cmd->digest), cmd->digest,
					sqlite3_errmsg (backend->db));
		}

		rspamd_fuzzy_backend_sqlite_cleanup_stmt (backend,
				RSPAMD_FUZZY_BACKEND_INSERT);
	}

	return (rc == SQLITE_OK);
}

gboolean
rspamd_fuzzy_backend_sqlite_finish_update (struct rspamd_fuzzy_backend_sqlite *backend,
		const gchar *source, gboolean version_bump)
{
	gint rc = SQLITE_OK, wal_frames, wal_checkpointed, ver;

	/* Get and update version */
	if (version_bump) {
		ver = rspamd_fuzzy_backend_sqlite_version (backend, source);
		++ver;

		rc = rspamd_fuzzy_backend_sqlite_run_stmt (backend, TRUE,
				RSPAMD_FUZZY_BACKEND_SET_VERSION,
				(gint64)ver, (gint64)time (NULL), source);
	}

	if (rc == SQLITE_OK) {
		rc = rspamd_fuzzy_backend_sqlite_run_stmt (backend, TRUE,
				RSPAMD_FUZZY_BACKEND_TRANSACTION_COMMIT);

		if (rc != SQLITE_OK) {
			msg_warn_fuzzy_backend ("cannot commit updates: %s",
					sqlite3_errmsg (backend->db));
			rspamd_fuzzy_backend_sqlite_run_stmt (backend, TRUE,
					RSPAMD_FUZZY_BACKEND_TRANSACTION_ROLLBACK);
			return FALSE;
		}
		else {
			if (!rspamd_sqlite3_sync (backend->db, &wal_frames, &wal_checkpointed)) {
				msg_warn_fuzzy_backend ("cannot commit checkpoint: %s",
						sqlite3_errmsg (backend->db));
			}
			else if (wal_checkpointed > 0) {
				msg_info_fuzzy_backend ("total number of frames in the wal file: "
						"%d, checkpointed: %d", wal_frames, wal_checkpointed);
			}
		}
	}
	else {
		msg_warn_fuzzy_backend ("cannot update version for %s: %s", source,
				sqlite3_errmsg (backend->db));
		rspamd_fuzzy_backend_sqlite_run_stmt (backend, TRUE,
				RSPAMD_FUZZY_BACKEND_TRANSACTION_ROLLBACK);
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_fuzzy_backend_sqlite_del (struct rspamd_fuzzy_backend_sqlite *backend,
		const struct rspamd_fuzzy_cmd *cmd)
{
	int rc = -1;

	if (backend == NULL) {
		return FALSE;
	}

	rc = rspamd_fuzzy_backend_sqlite_run_stmt (backend, FALSE,
			RSPAMD_FUZZY_BACKEND_CHECK,
			cmd->digest);

	if (rc == SQLITE_OK) {
		rspamd_fuzzy_backend_sqlite_cleanup_stmt (backend, RSPAMD_FUZZY_BACKEND_CHECK);

		rc = rspamd_fuzzy_backend_sqlite_run_stmt (backend, TRUE,
				RSPAMD_FUZZY_BACKEND_DELETE,
				cmd->digest);
		if (rc != SQLITE_OK) {
			msg_warn_fuzzy_backend ("cannot update hash to %d -> "
					"%*xs: %s", (gint) cmd->flag,
					(gint) sizeof (cmd->digest), cmd->digest,
					sqlite3_errmsg (backend->db));
		}
	}
	else {
		/* Hash is missing */
		rspamd_fuzzy_backend_sqlite_cleanup_stmt (backend, RSPAMD_FUZZY_BACKEND_CHECK);
	}

	return (rc == SQLITE_OK);
}

gboolean
rspamd_fuzzy_backend_sqlite_sync (struct rspamd_fuzzy_backend_sqlite *backend,
		gint64 expire,
		gboolean clean_orphaned)
{
	struct orphaned_shingle_elt {
		gint64 value;
		gint64 number;
	};

	/* Do not do more than 5k ops per step */
	const guint64 max_changes = 5000;
	gboolean ret = FALSE;
	gint64 expire_lim, expired;
	gint rc, i, orphaned_cnt = 0;
	GError *err = NULL;
	static const gchar orphaned_shingles[] = "SELECT shingles.value,shingles.number "
			"FROM shingles "
			"LEFT JOIN digests ON "
			"shingles.digest_id=digests.id WHERE "
			"digests.id IS NULL;";
	sqlite3_stmt *stmt;
	GArray *orphaned;
	struct orphaned_shingle_elt orphaned_elt, *pelt;


	if (backend == NULL) {
		return FALSE;
	}

	/* Perform expire */
	if (expire > 0) {
		expire_lim = time (NULL) - expire;

		if (expire_lim > 0) {
			ret = rspamd_fuzzy_backend_sqlite_run_stmt (backend, TRUE,
					RSPAMD_FUZZY_BACKEND_TRANSACTION_START);

			if (ret == SQLITE_OK) {

				rc = rspamd_fuzzy_backend_sqlite_run_stmt (backend, FALSE,
						RSPAMD_FUZZY_BACKEND_EXPIRE, expire_lim, max_changes);

				if (rc == SQLITE_OK) {
					expired = sqlite3_changes (backend->db);

					if (expired > 0) {
						backend->expired += expired;
						msg_info_fuzzy_backend ("expired %L hashes", expired);
					}
				}
				else {
					msg_warn_fuzzy_backend (
							"cannot execute expired statement: %s",
							sqlite3_errmsg (backend->db));
				}

				rspamd_fuzzy_backend_sqlite_cleanup_stmt (backend,
						RSPAMD_FUZZY_BACKEND_EXPIRE);

				ret = rspamd_fuzzy_backend_sqlite_run_stmt (backend, TRUE,
						RSPAMD_FUZZY_BACKEND_TRANSACTION_COMMIT);

				if (ret != SQLITE_OK) {
					rspamd_fuzzy_backend_sqlite_run_stmt (backend, TRUE,
							RSPAMD_FUZZY_BACKEND_TRANSACTION_ROLLBACK);
				}
			}
			if (ret != SQLITE_OK) {
				msg_warn_fuzzy_backend ("cannot expire db: %s",
						sqlite3_errmsg (backend->db));
			}
		}
	}

	/* Cleanup database */
	if (clean_orphaned) {
		ret = rspamd_fuzzy_backend_sqlite_run_stmt (backend, TRUE,
				RSPAMD_FUZZY_BACKEND_TRANSACTION_START);

		if (ret == SQLITE_OK) {
			if ((rc = sqlite3_prepare_v2 (backend->db,
					orphaned_shingles,
					-1,
					&stmt,
					NULL)) != SQLITE_OK) {
				msg_warn_fuzzy_backend ("cannot cleanup shingles: %s",
						sqlite3_errmsg (backend->db));
			}
			else {
				orphaned = g_array_new (FALSE,
						FALSE,
						sizeof (struct orphaned_shingle_elt));

				while (sqlite3_step (stmt) == SQLITE_ROW) {
					orphaned_elt.value = sqlite3_column_int64 (stmt, 0);
					orphaned_elt.number = sqlite3_column_int64 (stmt, 1);
					g_array_append_val (orphaned, orphaned_elt);

					if (orphaned->len > max_changes) {
						break;
					}
				}

				sqlite3_finalize (stmt);
				orphaned_cnt = orphaned->len;

				if (orphaned_cnt > 0) {
					msg_info_fuzzy_backend (
							"going to delete %ud orphaned shingles",
							orphaned_cnt);
					/* Need to delete orphaned elements */
					for (i = 0; i < (gint) orphaned_cnt; i++) {
						pelt = &g_array_index (orphaned,
								struct orphaned_shingle_elt,
								i);
						rspamd_fuzzy_backend_sqlite_run_stmt (backend, TRUE,
								RSPAMD_FUZZY_BACKEND_DELETE_ORPHANED,
								pelt->value, pelt->number);
					}
				}


				g_array_free (orphaned, TRUE);
			}

			ret = rspamd_fuzzy_backend_sqlite_run_stmt (backend, TRUE,
					RSPAMD_FUZZY_BACKEND_TRANSACTION_COMMIT);

			if (ret == SQLITE_OK) {
				msg_info_fuzzy_backend (
						"deleted %ud orphaned shingles",
						orphaned_cnt);
			}
			else {
				msg_warn_fuzzy_backend (
						"cannot synchronize fuzzy backend: %e",
						err);
				rspamd_fuzzy_backend_sqlite_run_stmt (backend, TRUE,
						RSPAMD_FUZZY_BACKEND_TRANSACTION_ROLLBACK);
			}
		}
	}

	return ret;
}


void
rspamd_fuzzy_backend_sqlite_close (struct rspamd_fuzzy_backend_sqlite *backend)
{
	if (backend != NULL) {
		if (backend->db != NULL) {
			rspamd_fuzzy_backend_sqlite_close_stmts (backend);
			sqlite3_close (backend->db);
		}

		if (backend->path != NULL) {
			g_free (backend->path);
		}

		if (backend->pool) {
			rspamd_mempool_delete (backend->pool);
		}

		g_free (backend);
	}
}


gsize
rspamd_fuzzy_backend_sqlite_count (struct rspamd_fuzzy_backend_sqlite *backend)
{
	if (backend) {
		if (rspamd_fuzzy_backend_sqlite_run_stmt (backend, FALSE,
				RSPAMD_FUZZY_BACKEND_COUNT) == SQLITE_OK) {
			backend->count = sqlite3_column_int64 (
					prepared_stmts[RSPAMD_FUZZY_BACKEND_COUNT].stmt, 0);
		}

		rspamd_fuzzy_backend_sqlite_cleanup_stmt (backend, RSPAMD_FUZZY_BACKEND_COUNT);

		return backend->count;
	}

	return 0;
}

gint
rspamd_fuzzy_backend_sqlite_version (struct rspamd_fuzzy_backend_sqlite *backend,
		const gchar *source)
{
	gint ret = 0;

	if (backend) {
		if (rspamd_fuzzy_backend_sqlite_run_stmt (backend, FALSE,
				RSPAMD_FUZZY_BACKEND_VERSION, source) == SQLITE_OK) {
			ret = sqlite3_column_int64 (
					prepared_stmts[RSPAMD_FUZZY_BACKEND_VERSION].stmt, 0);
		}

		rspamd_fuzzy_backend_sqlite_cleanup_stmt (backend, RSPAMD_FUZZY_BACKEND_VERSION);
	}

	return ret;
}

gsize
rspamd_fuzzy_backend_sqlite_expired (struct rspamd_fuzzy_backend_sqlite *backend)
{
	return backend != NULL ? backend->expired : 0;
}

const gchar *
rspamd_fuzzy_sqlite_backend_id (struct rspamd_fuzzy_backend_sqlite *backend)
{
	return backend != NULL ? backend->id : 0;
}
