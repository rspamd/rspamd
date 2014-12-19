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
};

enum rspamd_fuzzy_statement_idx {
	RSPAMD_FUZZY_BACKEND_CREATE,
	RSPAMD_FUZZY_BACKEND_INDEX,
	RSPAMD_FUZZY_BACKEND_TRANSACTION_START,
	RSPAMD_FUZZY_BACKEND_TRANSACTION_COMMIT,
	RSPAMD_FUZZY_BACKEND_TRANSACTION_ROLLBACK,
	RSPAMD_FUZZY_BACKEND_INSERT,
	RSPAMD_FUZZY_BACKEND_INSERT_SHINGLE,
	RSPAMD_FUZZY_BACKEND_CHECK,
	RSPAMD_FUZZY_BACKEND_CHECK_SHINGLE,
	RSPAMD_FUZZY_BACKEND_DELETE,
	RSPAMD_FUZZY_BACKEND_MAX
};
static struct rspamd_fuzzy_stmts {
	enum rspamd_fuzzy_statement_idx idx;
	const gchar *sql;
	const gchar *args;
	sqlite3_stmt *stmt;
} prepared_stmts[RSPAMD_FUZZY_BACKEND_MAX] =
{
	{
		.idx = RSPAMD_FUZZY_BACKEND_CREATE,
		.sql = "CREATE TABLE digests("
				"id INTEGER PRIMARY KEY,"
				"flag INTEGER NOT NULL,"
				"digest TEXT NOT NULL,"
				"value INTEGER);"
				""
				"CREATE TABLE shingles("
				"value INTEGER NOT NULL,"
				"number INTEGER NOT NULL,"
				"digest_id INTEGER REFERENCES digests(id) ON DELETE CASCADE"
				"ON UPDATE CASCADE);",
		.args = "",
		.stmt = NULL
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_INDEX,
		.sql = "CREATE UNIQUE INDEX d ON digests(digest, flag);"
				"CREATE UNIQUE INDEX s ON shingles(value, number);",
		.args = "",
		.stmt = NULL
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_TRANSACTION_START,
		.sql = "BEGIN TRANSACTION",
		.args = "",
		.stmt = NULL
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_TRANSACTION_COMMIT,
		.sql = "COMMIT",
		.args = "",
		.stmt = NULL
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_TRANSACTION_ROLLBACK,
		.sql = "ROLLBACK",
		.args = "",
		.stmt = NULL
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_INSERT,
		.sql = "",
		.args = "",
		.stmt = NULL
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_INSERT_SHINGLE,
		.sql = "",
		.args = "",
		.stmt = NULL
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_CHECK,
		.sql = "",
		.args = "",
		.stmt = NULL
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_CHECK_SHINGLE,
		.sql = "",
		.args = "",
		.stmt = NULL
	},
	{
		.idx = RSPAMD_FUZZY_BACKEND_DELETE,
		.sql = "",
		.args = "",
		.stmt = NULL
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
		if (sqlite3_prepare_v2 (bk->db, prepared_stmts[i].sql, -1,
				&prepared_stmts[i].stmt, NULL) != SQLITE_OK) {
			g_set_error (err, rspamd_fuzzy_backend_quark (),
				-1, "Cannot open init sql %s: %s",
				prepared_stmts[i].sql, sqlite3_errmsg (bk->db));

			return FALSE;
		}
	}

	return TRUE;
}

static int
rspamd_fuzzy_backend_run_stmt (int idx, ...)
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
	argtypes = prepared_stmts[idx].args;
	sqlite3_reset (stmt);
	va_start (ap, idx);

	for (i = 0; argtypes[i] != '\0'; i++) {
		switch (argtypes[i]) {
		case 'T':
			sqlite3_bind_text(stmt, i + 1, va_arg (ap, const char*), -1,
					SQLITE_STATIC);
			break;
		case 'I':
			sqlite3_bind_int64 (stmt, i + 1, va_arg (ap, int64_t));
			break;
		}
	}

	va_end (ap);
	retcode = sqlite3_step (stmt);

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
	if (rspamd_fuzzy_backend_run_stmt (idx)
			!= SQLITE_OK) {
		g_set_error (err, rspamd_fuzzy_backend_quark (),
				-1, "Cannot execute sql %s: %s",
				prepared_stmts[idx].sql,
				sqlite3_errmsg (bk->db));
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
				rc, "Cannot open sqlite db %s: %s",
				path, sqlite3_errstr (rc));

		return NULL;
	}

	bk = g_slice_alloc (sizeof (*bk));
	bk->path = g_strdup (path);
	bk->db = sqlite;

	if (!rspamd_fuzzy_backend_prepare_stmts (bk, err)) {
		rspamd_fuzzy_backend_close (bk);

		return NULL;
	}

	if (rspamd_fuzzy_backend_run_stmt (RSPAMD_FUZZY_BACKEND_CREATE)
			!= SQLITE_OK) {
		g_set_error (err, rspamd_fuzzy_backend_quark (),
				-1, "Cannot execute init sql %s: %s",
				prepared_stmts[RSPAMD_FUZZY_BACKEND_CREATE].sql,
				sqlite3_errmsg (bk->db));
		rspamd_fuzzy_backend_close (bk);

		return NULL;
	}

	if (add_index) {
		rspamd_fuzzy_backend_run_simple (RSPAMD_FUZZY_BACKEND_INDEX, bk, NULL);
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
			rc, "Cannot open sqlite db %s: %s",
			path, sqlite3_errstr (rc));

		return NULL;
	}

	bk = g_slice_alloc (sizeof (*bk));
	bk->path = g_strdup (path);
	bk = g_slice_alloc (sizeof (*bk));
	bk->db = sqlite;

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

	off = sizeof (FUZZY_FILE_MAGIC) - 1;
	if ((map = mmap (NULL, st.st_size - off, PROT_READ, MAP_SHARED, fd,
			off)) == MAP_FAILED) {
		g_set_error (err, rspamd_fuzzy_backend_quark (),
				errno, "Cannot mmap file %s: %s",
				path, strerror (errno));

		return FALSE;
	}

	end = map + st.st_size - off;
	p = map;

	rspamd_fuzzy_backend_run_simple (RSPAMD_FUZZY_BACKEND_TRANSACTION_START,
				nbackend, NULL);
	while (p < end) {
		n = (struct rspamd_legacy_fuzzy_node *)p;
		/* Convert node */

		p += sizeof (struct rspamd_legacy_fuzzy_node);
	}

	munmap (map, st.st_size - off);
	rspamd_fuzzy_backend_run_simple (RSPAMD_FUZZY_BACKEND_TRANSACTION_COMMIT,
					nbackend, NULL);
	rspamd_fuzzy_backend_run_simple (RSPAMD_FUZZY_BACKEND_INDEX,
			nbackend, NULL);
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
		g_set_error (err, rspamd_fuzzy_backend_quark (),
				errno, "Cannot open file %s: %s",
				path, strerror (errno));

		return NULL;
	}

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

struct rspamd_fuzzy_reply
rspamd_fuzzy_backend_check (struct rspamd_fuzzy_backend *backend,
		const struct rspamd_fuzzy_cmd *cmd)
{

}

gboolean
rspamd_fuzzy_backend_add (struct rspamd_fuzzy_backend *backend,
		const struct rspamd_fuzzy_cmd *cmd)
{

}


gboolean
rspamd_fuzzy_backend_del (struct rspamd_fuzzy_backend *backend,
		const struct rspamd_fuzzy_cmd *cmd)
{

}

gboolean
rspamd_fuzzy_backend_sync (struct rspamd_fuzzy_backend *backend)
{
	gboolean ret = FALSE;

	ret = rspamd_fuzzy_backend_run_simple (RSPAMD_FUZZY_BACKEND_TRANSACTION_COMMIT,
			backend, NULL);

	if (ret) {
		ret = rspamd_fuzzy_backend_run_simple (RSPAMD_FUZZY_BACKEND_TRANSACTION_START,
			backend, NULL);
	}

	return ret;
}


void
rspamd_fuzzy_backend_close (struct rspamd_fuzzy_backend *backend)
{
	if (backend != NULL) {
		if (backend->db != NULL) {
			rspamd_fuzzy_backend_close_stmts (backend);
			sqlite3_close_v2 (backend->db);
		}

		if (backend->path != NULL) {
			g_free (backend->path);
		}

		g_slice_free1 (sizeof (*backend), backend);
	}
}
