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
#ifndef SRC_LIBUTIL_SQLITE_UTILS_H_
#define SRC_LIBUTIL_SQLITE_UTILS_H_

#include "config.h"
#include "mem_pool.h"
#include "sqlite3.h"

#define RSPAMD_SQLITE3_STMT_MULTIPLE (1 << 0)

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_sqlite3_prstmt {
	gint idx;
	const gchar *sql;
	const gchar *args;
	sqlite3_stmt *stmt;
	gint result;
	const gchar *ret;
	gint flags;
};

/**
 * Create prepared statements for specified database from init statements
 * @param db
 * @param max_idx
 * @param err
 * @return new prepared statements array or NULL
 */
GArray *rspamd_sqlite3_init_prstmt (sqlite3 *db,
									struct rspamd_sqlite3_prstmt *init_stmt,
									gint max_idx,
									GError **err);

/**
 * Run prepared statements by its index getting parameters and setting results from
 * varargs structure
 * @param db
 * @param stmts
 * @param idx
 * @return
 */
gint rspamd_sqlite3_run_prstmt (rspamd_mempool_t *pool, sqlite3 *db, GArray *stmts,
								gint idx, ...);

/**
 * Close and free prepared statements
 * @param db
 * @param stmts
 */
void rspamd_sqlite3_close_prstmt (sqlite3 *db, GArray *stmts);

/**
 * Creates or opens sqlite database trying to share it between processes
 * @param path
 * @param create_sql
 * @return
 */
sqlite3 *rspamd_sqlite3_open_or_create (rspamd_mempool_t *pool,
										const gchar *path, const gchar *create_sql,
										guint32 version, GError **err);


/**
 * Sync sqlite3 db ensuring that all wal things are done
 * @param db
 */
gboolean rspamd_sqlite3_sync (sqlite3 *db, gint *wal_frames, gint *wal_checkpoints);

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBUTIL_SQLITE_UTILS_H_ */
