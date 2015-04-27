/* Copyright (c) 2014, Vsevolod Stakhov
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
#include "main.h"
#include "fuzzy_backend.h"
#include "fuzzy_storage.h"

#include <sqlite3.h>

/* Magic sequence for hashes file */
#define FUZZY_FILE_MAGIC "rsh"

struct rspamd_legacy_fuzzy_node {
	gint32 value;
	gint32 flag;
	guint64 time;
	rspamd_fuzzy_t h;
};

struct rspamd_fuzzy_backend {
	sqlite3 *db;
	char *path;
	gsize count;
	gsize expired;
};


static const char *create_tables_sql =
		"BEGIN;"
		"CREATE TABLE digests("
		"id INTEGER PRIMARY KEY,"
		"flag INTEGER NOT NULL,"
		"digest TEXT NOT NULL,"
		"value INTEGER,"
		"time INTEGER);"
		"CREATE TABLE shingles("
		"value INTEGER NOT NULL,"
		"number INTEGER NOT NULL,"
		"digest_id INTEGER REFERENCES digests(id) ON DELETE CASCADE "
		"ON UPDATE CASCADE);"
		"COMMIT;";
static const char *create_index_sql =
		"BEGIN;"
		"CREATE UNIQUE INDEX IF NOT EXISTS d ON digests(digest);"
		"CREATE INDEX IF NOT EXISTS t ON digests(time);"
		"CREATE UNIQUE INDEX IF NOT EXISTS s ON shingles(value, number);"
		"COMMIT;";
enum rspamd_fuzzy_statement_idx {
	RSPAMD_FUZZY_BACKEND_TRANSACTION_START = 0,
	RSPAMD_FUZZY_BACKEND_TRANSACTION_COMMIT,
	RSPAMD_FUZZY_BACKEND_TRANSACTION_ROLLBACK,
	RSPAMD_FUZZY_BACKEND_INSERT,
	RSPAMD_FUZZY_BACKEND_UPDATE,
	RSPAMD_FUZZY_BACKEND_INSERT_SHINGLE,
	RSPAMD_FUZZY_BACKEND_CHECK,
	RSPAMD_FUZZY_BACKEND_CHECK_SHINGLE,
	RSPAMD_FUZZY_BACKEND_GET_DIGEST_BY_ID,
	RSPAMD_FUZZY_BACKEND_DELETE,
	RSPAMD_FUZZY_BACKEND_COUNT,
	RSPAMD_FUZZY_BACKEND_EXPIRE,
	RSPAMD_FUZZY_BACKEND_VACUUM,
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
				"(?1, ?2, ?3, ?4);",
		.args = "SDII",
		.stmt = NULL,
		.result = SQLITE_DONE
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_UPDATE,
		.sql = "UPDATE digests SET value = value + ?1 WHERE "
				"digest==?2;",
		.args = "ID",
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
		.sql = "DELETE FROM digests WHERE time < ?1;",
		.args = "I",
		.stmt = NULL,
		.result = SQLITE_DONE
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_VACUUM,
		.sql = "VACUUM;",
		.args = "",
		.stmt = NULL,
		.result = SQLITE_DONE
	}
};

static GQuark
rspamd_fuzzy_backend_quark(void)
{
	return g_quark_from_static_string ("fuzzy-storage-backend");
}

static gboolean
rspamd_fuzzy_backend_prepare_stmts (struct rspamd_fuzzy_backend *bk, GError **err)
{
	int i;

	for (i = 0; i < RSPAMD_FUZZY_BACKEND_MAX; i ++) {
		if (prepared_stmts[i].stmt != NULL) {
			/* Skip already prepared statements */
			continue;
		}
		if (sqlite3_prepare_v2 (bk->db, prepared_stmts[i].sql, -1,
				&prepared_stmts[i].stmt, NULL) != SQLITE_OK) {
			g_set_error (err, rspamd_fuzzy_backend_quark (),
				-1, "Cannot initialize prepared sql `%s`: %s",
				prepared_stmts[i].sql, sqlite3_errmsg (bk->db));

			return FALSE;
		}
	}

	return TRUE;
}

static int
rspamd_fuzzy_backend_run_stmt (struct rspamd_fuzzy_backend *bk, int idx, ...)
{
	int retcode;
	va_list ap;
	sqlite3_stmt *stmt;
	int i;
	const char *argtypes;

	if (idx < 0 || idx >= RSPAMD_FUZZY_BACKEND_MAX) {

		return -1;
	}

	stmt = prepared_stmts[idx].stmt;
	if (stmt == NULL) {
		if ((retcode = sqlite3_prepare_v2 (bk->db, prepared_stmts[idx].sql, -1,
				&prepared_stmts[idx].stmt, NULL)) != SQLITE_OK) {
			msg_err ("Cannot initialize prepared sql `%s`: %s",
					prepared_stmts[idx].sql, sqlite3_errmsg (bk->db));

			return retcode;
		}
		stmt = prepared_stmts[idx].stmt;
	}

	msg_debug ("executing `%s`", prepared_stmts[idx].sql);
	argtypes = prepared_stmts[idx].args;
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
	retcode = sqlite3_step (stmt);

	if (retcode == prepared_stmts[idx].result) {
		return SQLITE_OK;
	}
	else if (retcode != SQLITE_DONE) {
		msg_debug ("failed to execute query %s: %d, %s", prepared_stmts[idx].sql,
				retcode, sqlite3_errmsg (bk->db));
	}

	return retcode;
}

static void
rspamd_fuzzy_backend_close_stmts (struct rspamd_fuzzy_backend *bk)
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
rspamd_fuzzy_backend_run_simple (int idx, struct rspamd_fuzzy_backend *bk,
		GError **err)
{
	if (rspamd_fuzzy_backend_run_stmt (bk, idx) != SQLITE_OK) {
		g_set_error (err, rspamd_fuzzy_backend_quark (),
				-1, "Cannot execute sql `%s`: %s",
				prepared_stmts[idx].sql,
				sqlite3_errmsg (bk->db));
		return FALSE;
	}

	return TRUE;
}

static gboolean
rspamd_fuzzy_backend_run_sql (const gchar *sql, struct rspamd_fuzzy_backend *bk,
		GError **err)
{
	if (sqlite3_exec (bk->db, sql, NULL, NULL, NULL) != SQLITE_OK) {
		g_set_error (err, rspamd_fuzzy_backend_quark (),
				-1, "Cannot execute raw sql `%s`: %s",
				sql, sqlite3_errmsg (bk->db));
		return FALSE;
	}

	return TRUE;
}

static struct rspamd_fuzzy_backend *
rspamd_fuzzy_backend_create_db (const gchar *path, gboolean add_index,
		GError **err)
{
	struct rspamd_fuzzy_backend *bk;
	sqlite3 *sqlite;
	int rc;

	if ((rc = sqlite3_open_v2 (path, &sqlite,
			SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_NOMUTEX, NULL))
			!= SQLITE_OK) {
		g_set_error (err, rspamd_fuzzy_backend_quark (),
				rc, "Cannot open sqlite db %s: %d",
				path, rc);

		return NULL;
	}

	bk = g_slice_alloc (sizeof (*bk));
	bk->path = g_strdup (path);
	bk->db = sqlite;
	bk->expired = 0;
	bk->count = 0;

	/*
	 * Here we need to run create prior to preparing other statements
	 */
	if (!rspamd_fuzzy_backend_run_sql (create_tables_sql, bk, err)) {
		rspamd_fuzzy_backend_close (bk);
		return NULL;
	}

	if (!rspamd_fuzzy_backend_prepare_stmts (bk, err)) {
		rspamd_fuzzy_backend_close (bk);

		return NULL;
	}

	if (add_index) {
		rspamd_fuzzy_backend_run_sql (create_index_sql, bk, NULL);
	}

	rspamd_fuzzy_backend_run_simple (RSPAMD_FUZZY_BACKEND_TRANSACTION_START,
			bk, NULL);

	return bk;
}

static struct rspamd_fuzzy_backend *
rspamd_fuzzy_backend_open_db (const gchar *path, GError **err)
{
	struct rspamd_fuzzy_backend *bk;
	sqlite3 *sqlite;
	int rc;

	if ((rc = sqlite3_open_v2 (path, &sqlite,
			SQLITE_OPEN_READWRITE|SQLITE_OPEN_NOMUTEX, NULL)) != SQLITE_OK) {
		g_set_error (err, rspamd_fuzzy_backend_quark (),
			rc, "Cannot open sqlite db %s: %d",
			path, rc);

		return NULL;
	}

	bk = g_slice_alloc (sizeof (*bk));
	bk->path = g_strdup (path);
	bk->db = sqlite;
	bk->expired = 0;

	/* Cleanup database */
	rspamd_fuzzy_backend_run_simple (RSPAMD_FUZZY_BACKEND_VACUUM, bk, NULL);

	if (rspamd_fuzzy_backend_run_stmt (bk, RSPAMD_FUZZY_BACKEND_COUNT)
			== SQLITE_OK) {
		bk->count = sqlite3_column_int64 (
				prepared_stmts[RSPAMD_FUZZY_BACKEND_COUNT].stmt, 0);
	}

	rspamd_fuzzy_backend_run_simple (RSPAMD_FUZZY_BACKEND_TRANSACTION_START,
				bk, NULL);

	return bk;
}

/*
 * Convert old database to the new format
 */
static gboolean
rspamd_fuzzy_backend_convert (const gchar *path, int fd, GError **err)
{
	gchar tmpdb[PATH_MAX];
	struct rspamd_fuzzy_backend *nbackend;
	struct stat st;
	gint off;
	guint8 *map, *p, *end;
	struct rspamd_legacy_fuzzy_node *n;

	rspamd_snprintf (tmpdb, sizeof (tmpdb), "%s.converted", path);
	(void)unlink (tmpdb);
	nbackend = rspamd_fuzzy_backend_create_db (tmpdb, FALSE, err);

	if (nbackend == NULL) {
		return FALSE;
	}

	(void)fstat (fd, &st);
	(void)lseek (fd, 0, SEEK_SET);

	off = sizeof (FUZZY_FILE_MAGIC);
	if ((map = mmap (NULL, st.st_size - off, PROT_READ, MAP_SHARED, fd,
			0)) == MAP_FAILED) {
		g_set_error (err, rspamd_fuzzy_backend_quark (),
				errno, "Cannot mmap file %s: %s",
				path, strerror (errno));
		rspamd_fuzzy_backend_close (nbackend);

		return FALSE;
	}

	end = map + st.st_size;
	p = map + off;

	rspamd_fuzzy_backend_run_simple (RSPAMD_FUZZY_BACKEND_TRANSACTION_START,
				nbackend, NULL);
	while (p < end) {
		n = (struct rspamd_legacy_fuzzy_node *)p;
		/* Convert node flag, digest, value, time  */
		if (rspamd_fuzzy_backend_run_stmt (nbackend, RSPAMD_FUZZY_BACKEND_INSERT,
				(gint)n->flag, n->h.hash_pipe,
				(gint64)n->value, n->time) != SQLITE_OK) {
			msg_warn ("Cannot execute init sql %s: %s",
					prepared_stmts[RSPAMD_FUZZY_BACKEND_INSERT].sql,
					sqlite3_errmsg (nbackend->db));
		}
		p += sizeof (struct rspamd_legacy_fuzzy_node);
	}

	munmap (map, st.st_size);
	rspamd_fuzzy_backend_run_simple (RSPAMD_FUZZY_BACKEND_TRANSACTION_COMMIT,
					nbackend, NULL);
	rspamd_fuzzy_backend_run_sql (create_index_sql, nbackend, NULL);
	rspamd_fuzzy_backend_close (nbackend);
	rename (tmpdb, path);

	return TRUE;
}

struct rspamd_fuzzy_backend*
rspamd_fuzzy_backend_open (const gchar *path, GError **err)
{
	gchar *dir, header[4];
	gint fd, r;
	struct rspamd_fuzzy_backend *res;

	/* First of all we check path for existence */
	dir = g_path_get_dirname (path);
	if (dir == NULL) {
		g_set_error (err, rspamd_fuzzy_backend_quark (),
				errno, "Cannot get directory name for %s: %s", path,
				strerror (errno));
		return NULL;
	}

	if (access (path, W_OK) == -1 && access (dir, W_OK) == -1) {
		g_set_error (err, rspamd_fuzzy_backend_quark (),
				errno, "Cannot access directory %s to create database: %s",
				dir, strerror (errno));
		g_free (dir);

		return NULL;
	}

	g_free (dir);

	if ((fd = open (path, O_RDONLY)) == -1) {
		if (errno != ENOENT) {
			g_set_error (err, rspamd_fuzzy_backend_quark (),
					errno, "Cannot open file %s: %s",
					path, strerror (errno));

			return NULL;
		}
	}
	else {

		/* Check for legacy format */
		if ((r = read (fd, header, sizeof (header))) == sizeof (header)) {
			if (memcmp (header, FUZZY_FILE_MAGIC, sizeof (header) - 1) == 0) {
				msg_info ("Trying to convert old fuzzy database");
				if (!rspamd_fuzzy_backend_convert (path, fd, err)) {
					close (fd);
					return NULL;
				}
				msg_info ("Old database converted");
			}
			close (fd);
		}
	}

	close (fd);

	/* Open database */
	if ((res = rspamd_fuzzy_backend_open_db (path, err)) == NULL) {
		GError *tmp = NULL;

		if ((res = rspamd_fuzzy_backend_create_db (path, TRUE, &tmp)) == NULL) {
			g_clear_error (err);
			g_propagate_error (err, tmp);
			return NULL;
		}
		g_clear_error (err);
	}

	return res;
}

static gint
rspamd_fuzzy_backend_int64_cmp (const void *a, const void *b)
{
	gint64 ia = *(gint64 *)a, ib = *(gint64 *)b;

	return (ia - ib);
}

struct rspamd_fuzzy_reply
rspamd_fuzzy_backend_check (struct rspamd_fuzzy_backend *backend,
		const struct rspamd_fuzzy_cmd *cmd, gint64 expire)
{
	struct rspamd_fuzzy_reply rep = {0, 0, 0, 0.0};
	const struct rspamd_fuzzy_shingle_cmd *shcmd;
	int rc;
	gint64 timestamp;
	gint64 shingle_values[RSPAMD_SHINGLE_SIZE], i, sel_id, cur_id,
		cur_cnt, max_cnt;
	const char *digest;

	/* Try direct match first of all */
	rc = rspamd_fuzzy_backend_run_stmt (backend, RSPAMD_FUZZY_BACKEND_CHECK,
			cmd->digest);

	if (rc == SQLITE_OK) {
		timestamp = sqlite3_column_int64 (
				prepared_stmts[RSPAMD_FUZZY_BACKEND_CHECK].stmt, 1);
		if (time (NULL) - timestamp > expire) {
			/* Expire element */
			msg_debug ("requested hash has been expired");
			rspamd_fuzzy_backend_run_stmt (backend, RSPAMD_FUZZY_BACKEND_DELETE,
				cmd->digest);
			backend->expired ++;
		}
		else {
			rep.value = sqlite3_column_int64 (
				prepared_stmts[RSPAMD_FUZZY_BACKEND_CHECK].stmt, 0);
			rep.prob = 1.0;
			rep.flag = sqlite3_column_int (
					prepared_stmts[RSPAMD_FUZZY_BACKEND_CHECK].stmt, 2);
		}
	}
	else if (cmd->shingles_count > 0) {
		/* Fuzzy match */
		shcmd = (const struct rspamd_fuzzy_shingle_cmd *)cmd;
		for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
			rc = rspamd_fuzzy_backend_run_stmt (backend,
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
			msg_debug ("looking for shingle %d -> %L: %d", i, shcmd->sgl.hashes[i], rc);
		}
		qsort (shingle_values, RSPAMD_SHINGLE_SIZE, sizeof (gint64),
				rspamd_fuzzy_backend_int64_cmp);
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
			rep.prob = (gdouble)max_cnt / (gdouble)RSPAMD_SHINGLE_SIZE;
			msg_debug ("found fuzzy hash with probability %.2f", rep.prob);
			rc = rspamd_fuzzy_backend_run_stmt (backend,
					RSPAMD_FUZZY_BACKEND_GET_DIGEST_BY_ID, sel_id);
			if (rc == SQLITE_OK) {
				digest = sqlite3_column_text (
						prepared_stmts[RSPAMD_FUZZY_BACKEND_GET_DIGEST_BY_ID].stmt, 0);
				timestamp = sqlite3_column_int64 (
						prepared_stmts[RSPAMD_FUZZY_BACKEND_GET_DIGEST_BY_ID].stmt, 2);
				if (time (NULL) - timestamp > expire) {
					/* Expire element */
					msg_debug ("requested hash has been expired");
					backend->expired ++;
					rspamd_fuzzy_backend_run_stmt (backend, RSPAMD_FUZZY_BACKEND_DELETE,
							digest);
					rep.prob = 0.0;
				}
				else {
					rep.value = sqlite3_column_int64 (
							prepared_stmts[RSPAMD_FUZZY_BACKEND_GET_DIGEST_BY_ID].stmt, 1);
					rep.flag = sqlite3_column_int (
							prepared_stmts[RSPAMD_FUZZY_BACKEND_GET_DIGEST_BY_ID].stmt, 3);
				}
			}
		}
	}

	return rep;
}

gboolean
rspamd_fuzzy_backend_add (struct rspamd_fuzzy_backend *backend,
		const struct rspamd_fuzzy_cmd *cmd)
{
	int rc, i;
	gint64 id;
	const struct rspamd_fuzzy_shingle_cmd *shcmd;

	rc = rspamd_fuzzy_backend_run_stmt (backend, RSPAMD_FUZZY_BACKEND_CHECK,
				cmd->digest);

	if (rc == SQLITE_OK) {
		/* We need to increase weight */
		rc = rspamd_fuzzy_backend_run_stmt (backend, RSPAMD_FUZZY_BACKEND_UPDATE,
			(gint64)cmd->value, cmd->digest);
	}
	else {
		rc = rspamd_fuzzy_backend_run_stmt (backend, RSPAMD_FUZZY_BACKEND_INSERT,
			(gint)cmd->flag, cmd->digest, (gint64)cmd->value, (gint64)time (NULL));

		if (rc == SQLITE_OK) {
			backend->count ++;

			if (cmd->shingles_count > 0) {
				id = sqlite3_last_insert_rowid (backend->db);
				shcmd = (const struct rspamd_fuzzy_shingle_cmd *)cmd;

				for (i = 0; i < RSPAMD_SHINGLE_SIZE; i ++) {
					rspamd_fuzzy_backend_run_stmt (backend,
							RSPAMD_FUZZY_BACKEND_INSERT_SHINGLE,
							shcmd->sgl.hashes[i], i, id);
					msg_debug ("add shingle %d -> %L: %d", i, shcmd->sgl.hashes[i], id);
				}
			}
		}
	}

	return (rc == SQLITE_OK);
}


gboolean
rspamd_fuzzy_backend_del (struct rspamd_fuzzy_backend *backend,
		const struct rspamd_fuzzy_cmd *cmd)
{
	int rc;

	rc = rspamd_fuzzy_backend_run_stmt (backend, RSPAMD_FUZZY_BACKEND_DELETE,
			cmd->digest);

	backend->count -= sqlite3_changes (backend->db);

	return (rc == SQLITE_OK);
}

gboolean
rspamd_fuzzy_backend_sync (struct rspamd_fuzzy_backend *backend, gint64 expire)
{
	gboolean ret = FALSE;
	gint64 expire_lim, expired;
	gint rc;
	GError *err = NULL;

	/* Perform expire */
	if (expire > 0) {
		expire_lim = time (NULL) - expire;

		if (expire_lim > 0) {
			rc = rspamd_fuzzy_backend_run_stmt (backend,
					RSPAMD_FUZZY_BACKEND_EXPIRE, expire_lim);

			if (rc == SQLITE_OK) {
				expired = sqlite3_changes (backend->db);

				if (expired > 0) {
					backend->expired += expired;
					msg_info ("expired %L hashes", expired);
				}
			}
			else {
				msg_warn ("cannot execute expired statement: %s",
						sqlite3_errmsg (backend->db));
			}
		}

	}
	ret = rspamd_fuzzy_backend_run_simple (RSPAMD_FUZZY_BACKEND_TRANSACTION_COMMIT,
			backend, &err);

	if (ret) {
		ret = rspamd_fuzzy_backend_run_simple (RSPAMD_FUZZY_BACKEND_TRANSACTION_START,
			backend, NULL);
	}
	else {
		msg_warn ("cannot synchronise fuzzy backend: %e", err);
		g_error_free (err);
	}

	return ret;
}


void
rspamd_fuzzy_backend_close (struct rspamd_fuzzy_backend *backend)
{
	if (backend != NULL) {
		if (backend->db != NULL) {
			rspamd_fuzzy_backend_close_stmts (backend);
			sqlite3_close (backend->db);
		}

		if (backend->path != NULL) {
			g_free (backend->path);
		}

		g_slice_free1 (sizeof (*backend), backend);
	}
}


gsize
rspamd_fuzzy_backend_count (struct rspamd_fuzzy_backend *backend)
{
	return backend->count;
}

gsize
rspamd_fuzzy_backend_expired (struct rspamd_fuzzy_backend *backend)
{
	return backend->expired;
}
