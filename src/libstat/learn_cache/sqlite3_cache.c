/* Copyright (c) 2015, Vsevolod Stakhov
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
#include "learn_cache.h"
#include "main.h"
#include "stat_api.h"
#include "stat_internal.h"
#include "blake2.h"
#include "ucl.h"
#include "fstring.h"
#include "message.h"
#include <sqlite3.h>

static const char *create_tables_sql =
		"BEGIN;"
		"CREATE TABLE IF NOT EXISTS learns("
		"id INTEGER PRIMARY KEY,"
		"flag INTEGER NOT NULL,"
		"digest TEXT NOT NULL);"
		"CREATE UNIQUE INDEX IF NOT EXISTS d ON learns(digest);"
		"COMMIT;";

#define SQLITE_CACHE_PATH RSPAMD_DBDIR "/learn_cache.sqlite"

struct rspamd_stat_sqlite3_ctx {
	sqlite3 *db;
};

gpointer
rspamd_stat_cache_sqlite3_init(struct rspamd_stat_ctx *ctx,
		struct rspamd_config *cfg)
{
	struct rspamd_stat_sqlite3_ctx *new = NULL;
	struct rspamd_classifier_config *clf;
	const ucl_object_t *obj, *elt;
	GList *cur;
	gchar dbpath[PATH_MAX];
	sqlite3 *sqlite;
	gboolean has_sqlite_cache = FALSE;
	gint rc;

	rspamd_snprintf (dbpath, sizeof (dbpath), SQLITE_CACHE_PATH);
	cur = cfg->classifiers;

	while (cur) {
		clf = cur->data;

		obj = ucl_object_find_key (clf->opts, "cache");

		/* Sqlite3 cache is the default learn cache method */
		if (obj == NULL) {
			has_sqlite_cache = TRUE;
			break;
		}
		else if (ucl_object_type (obj) == UCL_OBJECT) {
			elt = ucl_object_find_key (obj, "name");

			if (ucl_object_type (elt) == UCL_STRING &&
				g_ascii_strcasecmp (ucl_object_tostring (elt), "sqlite3") == 0) {

				has_sqlite_cache = TRUE;
				elt = ucl_object_find_key (obj, "path");
				if (elt != NULL && ucl_object_type (elt) == UCL_STRING) {
					rspamd_snprintf (dbpath, sizeof (dbpath), "%s",
							ucl_object_tostring (elt));
				}
			}
		}

		cur = g_list_next (cur);
	}

	if (has_sqlite_cache) {
		if ((rc = sqlite3_open_v2 (dbpath, &sqlite,
				SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_NOMUTEX, NULL))
				!= SQLITE_OK) {
			msg_err ("Cannot open sqlite db %s: %s", SQLITE_CACHE_PATH,
					sqlite3_errmsg (sqlite));

			return NULL;
		}

		if ((rc = sqlite3_exec (sqlite, create_tables_sql, NULL, NULL, NULL))
				!= SQLITE_OK) {
			msg_err ("Cannot initialize sqlite db %s: %s", SQLITE_CACHE_PATH,
					sqlite3_errmsg (sqlite));
			sqlite3_close (sqlite);

			return NULL;
		}

		new = g_slice_alloc (sizeof (*new));
		new->db = sqlite;
	}

	return new;
}

static rspamd_learn_t
rspamd_stat_cache_sqlite3_check (const guchar *h, gsize len, gboolean is_spam,
		struct rspamd_stat_sqlite3_ctx *ctx)
{
	static const gchar select_sql[] = "SELECT flag FROM learns WHERE digest=?1";
	static const gchar insert_sql[] = "INSERT INTO learns(digest, flag) VALUES "
				"(?1, ?2);";
	static const gchar update_sql[] = "UPDATE learns SET flag=?1 WHERE digest=?2";
	sqlite3_stmt *st = NULL;
	gint rc, ret = RSPAMD_LEARN_OK, flag;

	if ((rc = sqlite3_prepare_v2 (ctx->db, select_sql,
			-1, &st, NULL)) != SQLITE_OK) {
		msg_err ("Cannot prepare sql %s: %s", select_sql, sqlite3_errmsg (ctx->db));
		return RSPAMD_LEARN_OK;
	}

	sqlite3_bind_text (st, 1, h, len, SQLITE_STATIC);

	rc = sqlite3_step (st);

	if (rc == SQLITE_ROW) {
		/* We have some existing record in the table */
		flag = sqlite3_column_int (st, 0);
		sqlite3_finalize (st);

		if ((flag && is_spam) || (!flag && !is_spam)) {
			/* Already learned */
			ret = RSPAMD_LEARN_INGORE;
		}
		else {
			/* Need to relearn */
			if ((rc = sqlite3_prepare_v2 (ctx->db, update_sql,
					-1, &st, NULL)) != SQLITE_OK) {
				msg_err ("Cannot prepare sql %s: %s", update_sql,
						sqlite3_errmsg (ctx->db));
			}
			else {
				sqlite3_bind_int (st, 1, is_spam ? 1 : 0);
				sqlite3_bind_text (st, 2, h, len, SQLITE_STATIC);
				sqlite3_step (st);
				sqlite3_finalize (st);
			}

			return RSPAMD_LEARN_UNLEARN;
		}
	}
	else {
		/* Insert result new id */
		sqlite3_finalize (st);
		if ((rc = sqlite3_prepare_v2 (ctx->db, insert_sql,
				-1, &st, NULL)) != SQLITE_OK) {
			msg_err ("Cannot prepare sql %s: %s", insert_sql,
					sqlite3_errmsg (ctx->db));
		}
		else {
			sqlite3_bind_text (st, 1, h, len, SQLITE_STATIC);
			sqlite3_bind_int (st, 2, is_spam ? 1 : 0);
			sqlite3_step (st);
			sqlite3_finalize (st);
		}
	}

	return ret;
}

gint
rspamd_stat_cache_sqlite3_process (struct rspamd_task *task,
		gboolean is_spam, gpointer c)
{
	struct rspamd_stat_sqlite3_ctx *ctx = (struct rspamd_stat_sqlite3_ctx *)c;
	struct mime_text_part *part;
	blake2b_state st;
	rspamd_fstring_t *word;
	guchar out[BLAKE2B_OUTBYTES];
	GList *cur;
	guint i;

	if (ctx != NULL && ctx->db != NULL) {
		blake2b_init (&st, sizeof (out));
		cur = task->text_parts;

		while (cur) {
			part = (struct mime_text_part *)cur->data;

			for (i = 0; i < part->words->len; i ++) {
				word = &g_array_index (part->words, rspamd_fstring_t, i);
				blake2b_update (&st, word->begin, word->len);
			}

			cur = g_list_next (cur);
		}

		blake2b_final (&st, out, sizeof (out));

		return rspamd_stat_cache_sqlite3_check (out, sizeof (out), is_spam, ctx);
	}

	return RSPAMD_LEARN_OK;
}

void
rspamd_stat_cache_sqlite3_close (gpointer c)
{
	struct rspamd_stat_sqlite3_ctx *ctx = (struct rspamd_stat_sqlite3_ctx *)c;

	if (ctx != NULL) {
		sqlite3_close (ctx->db);
		g_slice_free1 (sizeof (*ctx), ctx);
	}

}
