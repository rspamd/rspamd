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
#include "sqlite_utils.h"

static gchar *target = NULL;
static gchar **sources = NULL;

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
				"SELECT * FROM shingles;";

enum statement_idx {
	TRANSACTION_START = 0,
	TRANSACTION_COMMIT,
	TRANSACTION_ROLLBACK,
	INSERT,
	UPDATE,
	INSERT_SHINGLE,
	CHECK,
	CHECK_SHINGLE,
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
				.sql = "UPDATE digests SET value = value + ?1 WHERE "
						"digest==?2;",
				.args = "IB",
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
				.ret = ""
		},
		[CHECK_SHINGLE] = {
				.idx = CHECK_SHINGLE,
				.sql = "SELECT digest_id FROM shingles WHERE value=?1 AND number=?2",
				.args = "IS",
				.stmt = NULL,
				.result = SQLITE_ROW,
				.ret = ""
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
			gint64 dgst;
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
	guint64 old_count, new_count, inserted = 0, updated = 0;
	sqlite3_stmt *stmt;

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

	for (i = 0; i < nsrc; i++) {
		sqlite3 *src;

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
		/* Select all digests */
	}
}