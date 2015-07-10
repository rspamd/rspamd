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


#ifndef SRC_LIBUTIL_SQLITE_UTILS_H_
#define SRC_LIBUTIL_SQLITE_UTILS_H_

#include "config.h"
#include "sqlite3.h"

struct rspamd_sqlite3_prstmt {
	gint idx;
	const gchar *sql;
	const gchar *args;
	sqlite3_stmt *stmt;
	gint result;
	const gchar *ret;
};

/**
 * Create prepared statements for specified database from init statements
 * @param db
 * @param max_idx
 * @param err
 * @return new prepared statements array or NULL
 */
GArray* rspamd_sqlite3_init_prstmt (sqlite3 *db,
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
gint rspamd_sqlite3_run_prstmt (sqlite3 *db, GArray *stmts,
		gint idx, ...);

/**
 * Close and free prepared statements
 * @param db
 * @param stmts
 */
void rspamd_sqlite3_close_prstmt (sqlite3 *db, GArray *stmts);

#endif /* SRC_LIBUTIL_SQLITE_UTILS_H_ */
