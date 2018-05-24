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
#include "rspamadm.h"
#include "logger.h"
#include "sqlite_utils.h"

static gchar *target = NULL;
static gchar **sources = NULL;
static gboolean quiet;

static void rspamadm_fuzzy_merge (gint argc, gchar **argv,
								  const struct rspamadm_command *cmd);
static const char *rspamadm_fuzzy_merge_help (gboolean full_help,
											  const struct rspamadm_command *cmd);

struct rspamadm_command fuzzy_merge_command = {
		.name = "fuzzy_merge",
		.flags = 0,
		.help = rspamadm_fuzzy_merge_help,
		.run = rspamadm_fuzzy_merge,
		.lua_subrs = NULL,
};

static GOptionEntry entries[] = {
		{"source", 's', 0, G_OPTION_ARG_STRING_ARRAY, &sources,
				"Source for merge (can be repeated)",                    NULL},
		{"destination", 'd', 0, G_OPTION_ARG_STRING, &target,
				"Destination db",     NULL},
		{"quiet", 'q', 0, G_OPTION_ARG_NONE, &quiet,
				"Suppress output", NULL},
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
rspamadm_fuzzy_merge_help (gboolean full_help, const struct rspamadm_command *cmd)
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
		help_str = "Merge fuzzy databases";
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
	guchar digest[64];
	union {
		struct {
			guint flag;
			gint64 value;
			gint64 tm;
			gint64 id;
		} dgst;
		struct {
			guint number;
			gint64 value;
		} shgl;
	} data;
};

static guint
rspamadm_op_hash (gconstpointer p)
{
	const struct fuzzy_merge_op *op = p;
	guint res;

	/* Uniformly distributed */
	memcpy (&res, op->digest, sizeof (res));
	return res;
}

static gboolean
rspamadm_op_equal (gconstpointer a, gconstpointer b)
{
	const struct fuzzy_merge_op *op1 = a, *op2 = b;

	return memcmp (op1->digest, op2->digest, sizeof (op1->digest)) == 0;
}

static void
rspamadm_fuzzy_merge (gint argc, gchar **argv, const struct rspamadm_command *cmd)
{
	GOptionContext *context;
	GError *error = NULL;
	sqlite3 *dest_db;
	GPtrArray *source_dbs;
	GArray *prstmt;
	GPtrArray *ops;
	GHashTable *unique_ops, *digests_id;
	rspamd_mempool_t *pool;
	guint i, nsrc;
	guint64 old_count, inserted = 0, updated = 0, shingles_inserted = 0;
	gint64 value, flag, tm, dig_id, src_value, src_flag;
	sqlite3 *src;
	sqlite3_stmt *stmt, *shgl_stmt;
	struct fuzzy_merge_op *nop, *op;

	context = g_option_context_new (
			"fuzzy_merge - merge fuzzy databases");
	g_option_context_set_summary (context,
			"Summary:\n  Rspamd administration utility version "
					RVERSION
					"\n  Release id: "
					RID);
	g_option_context_add_main_entries (context, entries, NULL);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		rspamd_fprintf(stderr, "option parsing failed: %s\n", error->message);
		g_error_free (error);
		exit (1);
	}

	if (target == NULL || sources == NULL || sources[0] == NULL) {
		rspamd_fprintf(stderr, "no sources or no destination has been specified\n");
		exit (1);
	}

	pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), "fuzzy_merge");
	dest_db = rspamd_sqlite3_open_or_create (pool, target, create_tables_sql,
			0, &error);

	if (dest_db == NULL) {
		rspamd_fprintf(stderr, "cannot open destination: %s\n", error->message);
		g_error_free (error);
		exit (1);
	}

	prstmt = rspamd_sqlite3_init_prstmt (dest_db, prepared_stmts,
			STMAX, &error);

	if (prstmt == NULL) {
		rspamd_fprintf(stderr, "cannot init prepared statements: %s\n", error->message);
		g_error_free (error);
		exit (1);
	}

	rspamd_sqlite3_run_prstmt (pool, dest_db, prstmt, COUNT, &old_count);

	nsrc = g_strv_length (sources);
	source_dbs = g_ptr_array_sized_new (nsrc);
	ops = g_ptr_array_new ();
	unique_ops = g_hash_table_new (rspamadm_op_hash, rspamadm_op_equal);

	for (i = 0; i < nsrc; i++) {
		src = rspamd_sqlite3_open_or_create (pool, sources[i], NULL, 0, &error);

		if (src == NULL) {
			rspamd_fprintf(stderr, "cannot open source %s: %s\n", sources[i],
					error->message);
			g_error_free (error);
			exit (1);
		}

		g_ptr_array_add (source_dbs, src);
	}

	for (i = 0; i < nsrc; i++) {
		const guchar *digest;
		guint64 nsrc_ops = 0, ndup_dst = 0, ndup_other = 0, nupdated = 0,
				nsrc_shingles = 0;

		src = g_ptr_array_index (source_dbs, i);

		if (!quiet) {
			rspamd_printf ("reading data from %s\n", sources[i]);
		}

		if (sqlite3_prepare_v2 (src, select_digests_sql, -1, &stmt, NULL) !=
					SQLITE_OK) {
			rspamd_fprintf(stderr, "cannot prepare statement %s: %s\n",
					select_digests_sql, sqlite3_errmsg (src));
			exit (1);
		}

		/* Temporary index for inserted IDs */
		digests_id = g_hash_table_new (g_int64_hash, g_int64_equal);

		while (sqlite3_step (stmt) == SQLITE_ROW) {
			/* id, flag, digest, value, time */
			digest = sqlite3_column_text (stmt, 2);
			src_value = sqlite3_column_int64 (stmt, 3);
			src_flag = sqlite3_column_int64 (stmt, 1);

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
				if (src_value > value && src_flag == flag) {
					nop = g_malloc0 (sizeof (*nop));
					nop->op = OP_UPDATE;
					memcpy (nop->digest, digest,
							sizeof (nop->digest));
					nop->data.dgst.flag = flag;
					/* Update time as well */
					nop->data.dgst.tm = sqlite3_column_int64 (stmt, 4);
					nop->data.dgst.id = sqlite3_column_int64 (stmt, 0);

					if ((op = g_hash_table_lookup (unique_ops, nop)) == NULL) {
						g_ptr_array_add (ops, nop);
						g_hash_table_insert (unique_ops, nop, nop);
						nupdated ++;
					}
					else {
						if (op->data.dgst.value < nop->data.dgst.value) {
							op->data.dgst.value = nop->data.dgst.value;
							op->data.dgst.tm = nop->data.dgst.tm;
							nupdated ++;
						}
						else {
							ndup_other ++;
						}
						g_free (nop);
					}
				}
				else {
					ndup_dst ++;
				}
			}
			else {
				/* Digest has not been found, but maybe we have the same in other
				 * sources ?
				 */
				nop = g_malloc0 (sizeof (*nop));
				nop->op = OP_INSERT;
				memcpy (nop->digest, digest,
						sizeof (nop->digest));
				nop->data.dgst.flag = src_flag;
				nop->data.dgst.value = src_value;
				/* Update time as well */
				nop->data.dgst.tm = sqlite3_column_int64 (stmt, 4);
				nop->data.dgst.id = sqlite3_column_int64 (stmt, 0);

				if ((op = g_hash_table_lookup (unique_ops, nop)) == NULL) {
					g_ptr_array_add (ops, nop);
					g_hash_table_insert (unique_ops, nop, nop);
					g_hash_table_insert (digests_id, &nop->data.dgst.id,
							nop);
					nsrc_ops ++;
				}
				else {
					if (op->data.dgst.value < nop->data.dgst.value) {
						op->data.dgst.value = nop->data.dgst.value;
						op->data.dgst.tm = nop->data.dgst.tm;
						op->data.dgst.tm = nop->data.dgst.tm;
						nupdated++;
					}
					else {
						ndup_other++;
					}
					g_free (nop);
				}
			}
		}

		/* We also need to scan all shingles and select those that
		 * are to be inserted
		 */
		if (sqlite3_prepare_v2 (src,
				select_shingles_sql,
				-1,
				&shgl_stmt,
				NULL) == SQLITE_OK) {
			sqlite3_bind_int64 (shgl_stmt,
					sqlite3_column_int64 (stmt, 0), 1);

			while (sqlite3_step (shgl_stmt) == SQLITE_ROW) {
				gint64 id = sqlite3_column_int64 (shgl_stmt, 2);

				if ((op = g_hash_table_lookup (digests_id, &id)) != NULL) {
					/* value, number, digest_id */
					nop = g_malloc0 (sizeof (*nop));
					nop->op = OP_INSERT_SHINGLE;
					memcpy (nop->digest, op->digest, sizeof (nop->digest));
					nop->data.shgl.number = sqlite3_column_int64 (shgl_stmt, 1);
					nop->data.shgl.value = sqlite3_column_int64 (shgl_stmt,
							0);
					g_ptr_array_add (ops, nop);
					nsrc_shingles ++;
				}
			}

			sqlite3_finalize (shgl_stmt);
		}
		else {
			rspamd_fprintf (stderr, "cannot prepare statement %s: %s\n",
					select_shingles_sql, sqlite3_errmsg (src));
			exit (1);
		}

		if (!quiet) {
			rspamd_printf ("processed %s: %L new hashes, %L duplicate hashes (other sources), "
							"%L duplicate hashes (destination), %L hashes to update, "
							"%L shingles to insert\n\n",
					sources[i],
					nsrc_ops,
					ndup_other,
					ndup_dst,
					nupdated,
					nsrc_shingles);
		}
		/* Cleanup */
		g_hash_table_unref (digests_id);
		sqlite3_finalize (stmt);
		sqlite3_close (src);
	}

	if (!quiet) {
		rspamd_printf ("start writing to %s, %ud ops pending\n", target, ops->len);
	}

	/* Start transaction */
	if (rspamd_sqlite3_run_prstmt (pool,
			dest_db,
			prstmt,
			TRANSACTION_START) != SQLITE_OK) {
		rspamd_fprintf (stderr, "cannot start transaction in destination: %s\n",
				sqlite3_errmsg (dest_db));
		exit (1);
	}

	/* Now all ops are inside ops array, so we just iterate over it */
	for (i = 0; i < ops->len; i ++) {
		op = g_ptr_array_index (ops, i);

		switch (op->op) {
		case OP_INSERT:
			/* flag, digest, value, time */
			if (rspamd_sqlite3_run_prstmt (pool,
					dest_db,
					prstmt,
					INSERT,
					(gint64)op->data.dgst.flag,
					(gint64)sizeof (op->digest), op->digest,
					op->data.dgst.value,
					op->data.dgst.tm) != SQLITE_OK) {
				rspamd_fprintf(stderr, "cannot insert digest: %s\n",
						sqlite3_errmsg (dest_db));
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
					(gint64) sizeof (op->digest),
					op->digest) != SQLITE_OK) {
				rspamd_fprintf(stderr, "cannot update digest: %s\n",
						sqlite3_errmsg (dest_db));
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
					(gint64) sizeof (op->digest),
					op->digest,
					&dig_id) == SQLITE_OK) {
				if (rspamd_sqlite3_run_prstmt (pool,
						dest_db,
						prstmt,
						INSERT_SHINGLE,
						(gint64)op->data.shgl.value,
						(gint64)op->data.shgl.number,
						dig_id) != SQLITE_OK) {
					rspamd_fprintf(stderr, "cannot insert shingle: %s\n",
							sqlite3_errmsg (dest_db));
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
	if (rspamd_sqlite3_run_prstmt (pool,
			dest_db,
			prstmt,
			TRANSACTION_COMMIT) != SQLITE_OK) {
		rspamd_fprintf (stderr, "cannot commit transaction: %s\n",
				sqlite3_errmsg (dest_db));
		goto err;
	}

	rspamd_sqlite3_close_prstmt (dest_db, prstmt);
	sqlite3_close (dest_db);
	for (i = 0; i < ops->len; i++) {
		op = g_ptr_array_index (ops, i);
		g_free (op);
	}
	g_ptr_array_free (ops, TRUE);
	rspamd_mempool_delete (pool);

	if (!quiet) {
		rspamd_printf ("Successfully merged data into %s\n%L hashes added, "
				"%L hashes updated, %L shingles inserted\nhashes count before update: "
				"%L\nhashes count after update: %L\n",
				target,
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
	for (i = 0; i < ops->len; i++) {
		op = g_ptr_array_index (ops, i);
		g_free (op);
	}
	g_ptr_array_free (ops, TRUE);
	rspamd_mempool_delete (pool);


	if (!quiet) {
		rspamd_printf ("Merge failed, rolled back\n");
	}

	exit (EXIT_FAILURE);
}
