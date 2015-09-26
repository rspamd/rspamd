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
#include "rspamadm.h"
#include "logger.h"
#include "sqlite_utils.h"

static gchar *target = NULL;
static gchar **sources = NULL;
static gboolean quiet;

static void rspamadm_fuzzy_merge (gint argc, gchar **argv);
static const char *rspamadm_fuzzy_merge_help (gboolean full_help);

struct rspamadm_command fuzzy_merge_command = {
		.name = "fuzzy_merge",
		.flags = 0,
		.help = rspamadm_fuzzy_merge_help,
		.run = rspamadm_fuzzy_merge
};

static GOptionEntry entries[] = {
		{"source", 's', 0, G_OPTION_ARG_STRING_ARRAY, &sources,
				"Source for merge (can be repeated)",                    NULL},
		{"destination", 'd', 0, G_OPTION_ARG_STRING, &target,
				"Destination db",     NULL},
		{"quiet", 'q', 0, G_OPTION_ARG_NONE, &quiet,
				"Supress output", NULL},
		{NULL,  0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

static const gchar *create_tables_sql =
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
				"CREATE UNIQUE INDEX IF NOT EXISTS d ON digests(digest);"
				"CREATE INDEX IF NOT EXISTS t ON digests(time);"
				"CREATE UNIQUE INDEX IF NOT EXISTS s ON shingles(value, number);"
				"COMMIT;";
static const gchar *select_digests_sql =
				"SELECT * FROM digests;";
static const gchar *select_shingles_sql =
				"SELECT * FROM shingles WHERE digest_id=?1;";

enum statement_idx {
	TRANSACTION_START = 0,
	TRANSACTION_COMMIT,
	TRANSACTION_ROLLBACK,
	INSERT,
	UPDATE,
	INSERT_SHINGLE,
	CHECK,
	CHECK_DIGEST_ID,
	COUNT,
	STMAX
};

static struct rspamd_sqlite3_prstmt prepared_stmts[STMAX] = {
		[TRANSACTION_START] = {
				.idx = TRANSACTION_START,
				.sql = "BEGIN IMMEDIATE TRANSACTION;",
				.args = "",
				.stmt = NULL,
				.result = SQLITE_DONE,
				.ret = ""
		},
		[TRANSACTION_COMMIT] = {
				.idx = TRANSACTION_COMMIT,
				.sql = "COMMIT;",
				.args = "",
				.stmt = NULL,
				.result = SQLITE_DONE,
				.ret = ""
		},
		[TRANSACTION_ROLLBACK] = {
				.idx = TRANSACTION_ROLLBACK,
				.sql = "ROLLBACK;",
				.args = "",
				.stmt = NULL,
				.result = SQLITE_DONE,
				.ret = ""
		},
		[INSERT] = {
				.idx = INSERT,
				.sql = "INSERT INTO digests(flag, digest, value, time) VALUES"
						"(?1, ?2, ?3, ?4);",
				.args = "SBII",
				.stmt = NULL,
				.result = SQLITE_DONE,
				.ret = ""
		},
		[INSERT_SHINGLE] = {
				.idx = INSERT_SHINGLE,
				.sql = "INSERT OR REPLACE INTO shingles(value, number, digest_id) "
						"VALUES (?1, ?2, ?3);",
				.args = "III",
				.stmt = NULL,
				.result = SQLITE_DONE,
				.ret = ""
		},
		[UPDATE] = {
				.idx = UPDATE,
				.sql = "UPDATE digests SET value=?1, time=?2 WHERE "
						"digest==?3;",
				.args = "IIB",
				.stmt = NULL,
				.result = SQLITE_DONE,
				.ret = ""
		},
		[CHECK] = {
				.idx = CHECK,
				.sql = "SELECT value, time, flag FROM digests WHERE digest==?1;",
				.args = "B",
				.stmt = NULL,
				.result = SQLITE_ROW,
				.ret = "III"
		},
		[CHECK_DIGEST_ID] = {
				.idx = CHECK_DIGEST_ID,
				.sql = "SELECT id FROM digests WHERE digest==?1",
				.args = "B",
				.stmt = NULL,
				.result = SQLITE_ROW,
				.ret = "I"
		},
		[COUNT] = {
				.idx = COUNT,
				.sql = "SELECT COUNT(*) FROM digests;",
				.args = "",
				.stmt = NULL,
				.result = SQLITE_ROW,
				.ret = "I"
		},
};

static const char *
rspamadm_fuzzy_merge_help (gboolean full_help)
{
	const char *help_str;

	if (full_help) {
		help_str = "Merge multiple sources of fuzzy hashes db into a single destination\n\n"
				"Usage: rspamadm fuzzy_merge -s source1 [-s source2 ...] -d destination\n"
				"Where options are:\n\n"
				"-s: source db for merge\n"
				"-d: destination db for merge\n"
				"--help: shows available options and commands";
	}
	else {
		help_str = "Create encryption key pairs";
	}

	return help_str;
}

enum op_type {
	OP_INSERT = 0,
	OP_UPDATE,
	OP_INSERT_SHINGLE,
};
struct fuzzy_merge_op {
	enum op_type op;
	union {
		struct {
			guint flag;
			gint64 value;
			guchar digest[64];
			gint64 tm;
		} dgst;
		struct {
			guint number;
			gint64 value;
			guchar digest[64];
		} shgl;
	} data;
};

static void
rspamadm_fuzzy_merge (gint argc, gchar **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	sqlite3 *dest_db;
	GPtrArray *source_dbs;
	GArray *prstmt;
	GArray *ops;
	rspamd_mempool_t *pool;
	guint i, nsrc;
	guint64 old_count, inserted = 0, updated = 0, shingles_inserted = 0;
	gint64 value, flag, tm, dig_id;
	sqlite3 *src;
	sqlite3_stmt *stmt;
	struct fuzzy_merge_op nop, *op;

	context = g_option_context_new (
			"fuzzy_merge - merge fuzzy databases");
	g_option_context_set_summary (context,
			"Summary:\n  Rspamd administration utility version "
					RVERSION
					"\n  Release id: "
					RID);
	g_option_context_add_main_entries (context, entries, NULL);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		fprintf (stderr, "option parsing failed: %s\n", error->message);
		g_error_free (error);
		exit (1);
	}

	if (target == NULL || sources == NULL || sources[0] == NULL) {
		fprintf (stderr, "no sources or no destination has been specified\n");
		exit (1);
	}

	pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), "fuzzy_merge");
	dest_db = rspamd_sqlite3_open_or_create (pool, target, create_tables_sql,
			&error);

	if (dest_db == NULL) {
		fprintf (stderr, "cannot open destination: %s\n", error->message);
		g_error_free (error);
		exit (1);
	}

	prstmt = rspamd_sqlite3_init_prstmt (dest_db, prepared_stmts,
			STMAX, &error);

	if (prstmt == NULL) {
		fprintf (stderr, "cannot init prepared statements: %s\n", error->message);
		g_error_free (error);
		exit (1);
	}

	rspamd_sqlite3_run_prstmt (pool, dest_db, prstmt, COUNT, &old_count);

	nsrc = g_strv_length (sources);
	source_dbs = g_ptr_array_sized_new (nsrc);
	ops = g_array_new (FALSE, FALSE, sizeof (nop));

	for (i = 0; i < nsrc; i++) {
		src = rspamd_sqlite3_open_or_create (pool, sources[i], NULL, &error);

		if (src == NULL) {
			fprintf (stderr, "cannot open source %s: %s\n", sources[i],
					error->message);
			g_error_free (error);
			exit (1);
		}

		g_ptr_array_add (source_dbs, src);
	}

	for (i = 0; i < nsrc; i++) {
		const guchar *digest;

		src = g_ptr_array_index (source_dbs, i);

		if (sqlite3_prepare_v2 (src, select_digests_sql, -1, &stmt, NULL) !=
					SQLITE_OK) {
			fprintf (stderr, "cannot prepare statement %s\n", select_digests_sql);
			exit (1);
		}


		while (sqlite3_step (stmt) == SQLITE_ROW) {
			/* id, flag, digest, value, time */
			digest = sqlite3_column_text (stmt, 2);

			/* Now search for this digest in the destination */
			if (rspamd_sqlite3_run_prstmt (pool,
					dest_db,
					prstmt,
					CHECK,
					(gint64)sqlite3_column_bytes (stmt, 2), digest,
					&value, &tm, &flag) == SQLITE_OK) {
				/*
				 * We compare values and if src value is bigger than
				 * local one then we replace dest value with the src value
				 */
				gint64 src_value = sqlite3_column_int64 (stmt, 3);
				gint64 src_flag = sqlite3_column_int64 (stmt, 1);

				if (src_value > value && src_flag == flag) {
					nop.op = OP_UPDATE;
					memcpy (nop.data.dgst.digest, digest,
							sizeof (nop.data.dgst.digest));
					nop.data.dgst.flag = flag;
					/* Update time as well */
					nop.data.dgst.tm = sqlite3_column_int64 (stmt, 4);
					g_array_append_val (ops, nop);
				}
			}
			else {
				sqlite3_stmt *shgl_stmt;

				/* Digest has not been found in the destination db, insert it */
				nop.op = OP_INSERT;
				memcpy (nop.data.dgst.digest, digest,
						sizeof (nop.data.dgst.digest));
				nop.data.dgst.flag = flag;
				/* Update time as well */
				nop.data.dgst.tm = sqlite3_column_int64 (stmt, 4);
				g_array_append_val (ops, nop);

				/*
				 * If we have no digest registered, we also need to check
				 * shingles associated with this digest
				 */
				if (sqlite3_prepare_v2 (src,
						select_shingles_sql,
						-1,
						&shgl_stmt,
						NULL) != SQLITE_OK) {
					sqlite3_bind_int64 (shgl_stmt,
							sqlite3_column_int64 (stmt, 0), 1);

					while (sqlite3_step (shgl_stmt) == SQLITE_ROW) {
						/* value, number, digest_id */
						nop.op = OP_INSERT_SHINGLE;
						memcpy (nop.data.shgl.digest, digest,
								sizeof (nop.data.shgl.digest));
						nop.data.shgl.number = sqlite3_column_int64 (shgl_stmt, 1);
						nop.data.shgl.value = sqlite3_column_int64 (shgl_stmt,
								0);
						g_array_append_val (ops, nop);
					}

					sqlite3_finalize (shgl_stmt);
				}
			}
		}

		/* Cleanup */
		sqlite3_finalize (stmt);
		sqlite3_close (src);
	}

	/* Start transaction */
	if (rspamd_sqlite3_run_prstmt (pool,
			dest_db,
			prstmt,
			TRANSACTION_START) == SQLITE_OK) {
		fprintf (stderr, "cannot start transaction in destination\n");
		exit (1);
	}

	/* Now all ops are inside ops array, so we just iterate over it */
	for (i = 0; i < ops->len; i ++) {
		op = &g_array_index (ops, struct fuzzy_merge_op, i);

		switch (op->op) {
		case OP_INSERT:
			/* flag, digest, value, time */
			if (rspamd_sqlite3_run_prstmt (pool,
					dest_db,
					prstmt,
					INSERT,
					(gint64)op->data.dgst.flag,
					(gint64)sizeof (op->data.dgst.digest), op->data.dgst.digest,
					op->data.dgst.value,
					op->data.dgst.tm) != SQLITE_OK) {
				fprintf (stderr, "cannot insert digest\n");
				goto err;
			}

			inserted ++;
			break;
		case OP_UPDATE:
			if (rspamd_sqlite3_run_prstmt (pool,
					dest_db,
					prstmt,
					UPDATE,
					(gint64) op->data.dgst.value,
					op->data.dgst.tm,
					(gint64) sizeof (op->data.dgst.digest),
					op->data.dgst.digest) != SQLITE_OK) {
				fprintf (stderr, "cannot update digest\n");
				goto err;
			}

			updated ++;
			break;
		case OP_INSERT_SHINGLE:
			/* First select the appropriate digest */
			if (rspamd_sqlite3_run_prstmt (pool,
					dest_db,
					prstmt,
					CHECK_DIGEST_ID,
					(gint64) sizeof (op->data.dgst.digest),
					op->data.dgst.digest,
					&dig_id) == SQLITE_OK) {
				if (rspamd_sqlite3_run_prstmt (pool,
						dest_db,
						prstmt,
						INSERT_SHINGLE,
						(gint64)op->data.shgl.value,
						(gint64)op->data.shgl.number,
						dig_id) != SQLITE_OK) {
					fprintf (stderr, "cannot insert shingle\n");
					goto err;
				}

				shingles_inserted ++;
			}
			else {
				msg_warn_pool ("cannot find digest id for shingle");
			}

			break;
		}
	}

	/* Normal closing */
	rspamd_sqlite3_run_prstmt (pool,
			dest_db,
			prstmt,
			TRANSACTION_COMMIT);
	rspamd_sqlite3_close_prstmt (dest_db, prstmt);
	sqlite3_close (dest_db);
	g_array_free (ops, TRUE);
	rspamd_mempool_delete (pool);

	if (!quiet) {
		rspamd_printf ("Successfully merged data into %s\n%L hashes added, "
				"%L hashes updated, %L shingles inserted\nhashes count before update: "
				"%L\nhashes count after update: %L\n",
				inserted, updated, shingles_inserted,
				old_count, old_count + inserted);
	}

	exit (EXIT_SUCCESS);

err:
	rspamd_sqlite3_run_prstmt (pool,
		dest_db,
		prstmt,
		TRANSACTION_ROLLBACK);
	rspamd_sqlite3_close_prstmt (dest_db, prstmt);
	sqlite3_close (dest_db);
	g_array_free (ops, TRUE);
	rspamd_mempool_delete (pool);


	if (!quiet) {
		rspamd_printf ("Merge failed, rolled back\n");
	}

	exit (EXIT_FAILURE);
}
