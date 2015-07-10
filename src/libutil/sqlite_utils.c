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
#include "libutil/logger.h"
#include "libutil/sqlite_utils.h"


static GQuark
rspamd_sqlite3_quark (void)
{
	return g_quark_from_static_string ("rspamd-sqlite3");
}

GArray*
rspamd_sqlite3_init_prstmt (sqlite3 *db,
		struct rspamd_sqlite3_prstmt *init_stmt,
		gint max_idx,
		GError **err)
{
	gint i;
	GArray *res;
	struct rspamd_sqlite3_prstmt *nst;

	res = g_array_sized_new (FALSE, TRUE, sizeof (struct rspamd_sqlite3_prstmt),
			max_idx);
	g_array_set_size (res, max_idx);

	for (i = 0; i < max_idx; i ++) {
		nst = &g_array_index (res, struct rspamd_sqlite3_prstmt, i);
		memcpy (nst, &init_stmt[i], sizeof (*nst));

		if (sqlite3_prepare_v2 (db, init_stmt[i].sql, -1,
				&nst->stmt, NULL) != SQLITE_OK) {
			g_set_error (err, rspamd_sqlite3_quark (),
				-1, "Cannot initialize prepared sql `%s`: %s",
				nst->sql, sqlite3_errmsg (db));
			rspamd_sqlite3_close_prstmt (db, res);

			return NULL;
		}
	}

	return res;
}

int
rspamd_sqlite3_run_prstmt (sqlite3 *db, GArray *stmts,
		gint idx, ...)
{
	gint retcode;
	va_list ap;
	sqlite3_stmt *stmt;
	gint i, rowid, nargs, j;
	struct rspamd_sqlite3_prstmt *nst;
	const char *argtypes;

	if (idx < 0 || idx >= (gint)stmts->len) {

		return -1;
	}

	nst = &g_array_index (stmts, struct rspamd_sqlite3_prstmt, idx);
	stmt = nst->stmt;

	g_assert (nst != NULL);

	msg_debug ("executing `%s`", nst->sql);
	argtypes = nst->args;
	sqlite3_reset (stmt);
	va_start (ap, idx);
	nargs = 1;

	for (i = 0, rowid = 1; argtypes[i] != '\0'; i ++) {
		switch (argtypes[i]) {
		case 'T':

			for (j = 0; j < nargs; j ++, rowid ++) {
				sqlite3_bind_text (stmt, rowid, va_arg (ap, const char*), -1,
					SQLITE_STATIC);
			}

			nargs = 1;
			break;
		case 'I':

			for (j = 0; j < nargs; j ++, rowid ++) {
				sqlite3_bind_int64 (stmt, rowid, va_arg (ap, gint64));
			}

			nargs = 1;
			break;
		case 'S':

			for (j = 0; j < nargs; j ++, rowid ++) {
				sqlite3_bind_int (stmt, rowid, va_arg (ap, gint));
			}

			nargs = 1;
			break;
		case '*':
			nargs = va_arg (ap, gint);
			break;
		}
	}

	va_end (ap);
	retcode = sqlite3_step (stmt);

	if (retcode == nst->result) {
		argtypes = nst->ret;

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
		msg_debug ("failed to execute query %s: %d, %s", nst->sql,
				retcode, sqlite3_errmsg (db));
	}

	return retcode;
}

void
rspamd_sqlite3_close_prstmt (sqlite3 *db, GArray *stmts)
{
	guint i;
	struct rspamd_sqlite3_prstmt *nst;

	for (i = 0; i < stmts->len; i++) {
		nst = &g_array_index (stmts, struct rspamd_sqlite3_prstmt, i);
		if (nst->stmt != NULL) {
			sqlite3_finalize (nst->stmt);
		}
	}

	g_array_free (stmts, TRUE);

	return;
}
