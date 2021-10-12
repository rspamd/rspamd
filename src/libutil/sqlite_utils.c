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
#include "libserver/logger.h"
#include "libutil/sqlite_utils.h"
#include "unix-std.h"


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
rspamd_sqlite3_run_prstmt (rspamd_mempool_t *pool, sqlite3 *db, GArray *stmts,
		gint idx, ...)
{
	gint retcode;
	va_list ap;
	sqlite3_stmt *stmt;
	gint i, rowid, nargs, j;
	gint64 len;
	gpointer p;
	struct rspamd_sqlite3_prstmt *nst;
	const char *argtypes;

	if (idx < 0 || idx >= (gint)stmts->len) {

		return -1;
	}

	nst = &g_array_index (stmts, struct rspamd_sqlite3_prstmt, idx);
	stmt = nst->stmt;

	g_assert (nst != NULL);

	msg_debug_pool ("executing `%s`", nst->sql);
	argtypes = nst->args;
	sqlite3_clear_bindings (stmt);
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
		case 'V':
		case 'B':

			for (j = 0; j < nargs; j ++, rowid ++) {
				len = va_arg (ap, gint64);
				sqlite3_bind_text (stmt, rowid, va_arg (ap, const char*), len,
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
			case 'L':
				*va_arg (ap, gint64*) = sqlite3_last_insert_rowid (db);
				break;
			case 'B':
				len = sqlite3_column_bytes (stmt, i);
				g_assert (len >= 0);
				p = g_malloc (len);
				memcpy (p, sqlite3_column_blob (stmt, i), len);
				*va_arg (ap, gint64*) = len;
				*va_arg (ap, gpointer*) = p;
				break;
			}
		}

		if (!(nst->flags & RSPAMD_SQLITE3_STMT_MULTIPLE)) {
			sqlite3_clear_bindings (stmt);
			sqlite3_reset (stmt);
		}

		va_end (ap);

		return SQLITE_OK;
	}
	else if (retcode != SQLITE_DONE && retcode != SQLITE_OK && retcode != SQLITE_ROW) {
		msg_warn_pool ("failed to execute query %s: %d, %s", nst->sql,
				retcode, sqlite3_errmsg (db));
	}

	if (!(nst->flags & RSPAMD_SQLITE3_STMT_MULTIPLE)) {
		sqlite3_clear_bindings (stmt);
		sqlite3_reset (stmt);
	}

	va_end (ap);

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

static gboolean
rspamd_sqlite3_wait (rspamd_mempool_t *pool, const gchar *lock)
{
	gint fd;
	pid_t pid;
	gssize r;
	struct timespec sleep_ts = {
		.tv_sec = 0,
		.tv_nsec = 1000000
	};

	while ((fd = open (lock, O_WRONLY|O_CREAT|O_EXCL, 00600)) == -1) {
		if (errno != EBUSY && errno != EEXIST) {
			msg_err_pool_check ("cannot open lock file %s: %s", lock,
					strerror (errno));

			return FALSE;
		}

		fd = open (lock, O_RDONLY);

		if (fd == -1) {
			msg_err_pool_check ("cannot open lock file %s: %s", lock,
					strerror (errno));

			return FALSE;
		}

		r = read (fd, &pid, sizeof (pid));

		if (r != sizeof (pid)) {
			msg_warn_pool_check ("stale lock file %s, removing", lock);
			unlink (lock);
			close (fd);

			return TRUE;
		}

		/* Now check for process existence */
		if (pid == getpid ()) {
			msg_warn_pool_check ("lock file %s, belongs to me, removing", lock);
			unlink (lock);
			close (fd);

			return TRUE;
		}
		else if (kill (pid, 0) == -1) {
			if (errno == ESRCH) {
				/* Process is already dead */
				msg_warn_pool_check ("stale lock file %s from pid: %P, removing",
						lock, pid);
				unlink (lock);
				close (fd);

				return TRUE;
			}
		}

		close (fd);

		if (nanosleep (&sleep_ts, NULL) == -1 && errno != EINTR) {
			msg_err_pool_check ("cannot sleep open lock file %s: %s", lock,
					strerror (errno));

			return FALSE;
		}
	}

	unlink (lock);
	close (fd);

	return TRUE;
}

#define RSPAMD_SQLITE_MMAP_LIMIT 268435456
#define RSPAMD_SQLITE_CACHE_SIZE 262144

sqlite3 *
rspamd_sqlite3_open_or_create (rspamd_mempool_t *pool, const gchar *path, const
		gchar *create_sql, guint version, GError **err)
{
	sqlite3 *sqlite;
	gint rc, flags, lock_fd;
	gchar lock_path[PATH_MAX], dbdir[PATH_MAX], *pdir;
	static const char sqlite_wal[] =
									"PRAGMA journal_mode=\"wal\";"
									"PRAGMA wal_autocheckpoint = 16;"
									"PRAGMA journal_size_limit = 1536;",
			exclusive_lock_sql[] =	"PRAGMA locking_mode=\"exclusive\";",

			fsync_sql[] = 			"PRAGMA synchronous=\"NORMAL\";",

			foreign_keys[] = 		"PRAGMA foreign_keys=\"ON\";",

#if defined(__LP64__) || defined(_LP64)
			enable_mmap[] = 		"PRAGMA mmap_size="
									G_STRINGIFY(RSPAMD_SQLITE_MMAP_LIMIT) ";",
#endif

			other_pragmas[] = 		"PRAGMA read_uncommitted=\"ON\";"
									"PRAGMA cache_size="
									G_STRINGIFY(RSPAMD_SQLITE_CACHE_SIZE) ";",
			db_version[] =			"PRAGMA user_version;";
	gboolean create = FALSE, has_lock = FALSE;

	flags = SQLITE_OPEN_READWRITE;
#ifdef SQLITE_OPEN_SHAREDCACHE
	flags |= SQLITE_OPEN_SHAREDCACHE;
#endif
#ifdef SQLITE_OPEN_WAL
	flags |= SQLITE_OPEN_WAL;
#endif

	rspamd_strlcpy (dbdir, path, sizeof (dbdir));
	pdir = dirname (dbdir);

	if (access (pdir, W_OK) == -1) {
		g_set_error (err, rspamd_sqlite3_quark (),
				errno, "cannot open sqlite directory %s: %s",
				pdir, strerror (errno));

		return NULL;
	}

	rspamd_snprintf (lock_path, sizeof (lock_path), "%s.lock", path);

	if (access (path, R_OK) == -1) {
		flags |= SQLITE_OPEN_CREATE;
		create = TRUE;
	}


	rspamd_snprintf (lock_path, sizeof (lock_path), "%s.lock", path);
	lock_fd = open (lock_path, O_WRONLY|O_CREAT|O_EXCL, 00600);

	if (lock_fd == -1) {
		if (errno == EEXIST || errno == EBUSY) {
			msg_debug_pool_check ("checking %s to wait for db being initialized", lock_path);

			if (!rspamd_sqlite3_wait(pool, lock_path)) {
				g_set_error(err, rspamd_sqlite3_quark(),
						errno, "cannot create sqlite file %s: %s",
						path, strerror(errno));

				return NULL;
			}


			/* At this point we have database created */
			create = FALSE;
			has_lock = FALSE;
		}
		else {
			g_set_error(err, rspamd_sqlite3_quark(),
					errno, "cannot lock sqlite file %s: %s",
					path, strerror(errno));
		}
	}
	else {
		pid_t myself = getpid ();
		msg_debug_pool_check ("locking %s to block other processes", lock_path);
		(void)write (lock_fd, &myself, sizeof (myself));

		g_assert (rspamd_file_lock (lock_fd, FALSE));
		has_lock = TRUE;
	}

	if ((rc = sqlite3_open_v2 (path, &sqlite,
			flags, NULL)) != SQLITE_OK) {
#if SQLITE_VERSION_NUMBER >= 3008000
		g_set_error (err, rspamd_sqlite3_quark (),
				rc, "cannot open sqlite db %s: %s",
				path, sqlite3_errstr (rc));
#else
		g_set_error (err, rspamd_sqlite3_quark (),
				rc, "cannot open sqlite db %s: %d",
				path, rc);
#endif

		if (has_lock && lock_fd != -1) {
			msg_debug_pool_check ("removing lock from %s", lock_path);
			rspamd_file_unlock (lock_fd, FALSE);
			unlink (lock_path);
			close (lock_fd);
		}

		return NULL;
	}

	if (create && has_lock) {
		while ((rc = sqlite3_exec (sqlite, sqlite_wal, NULL, NULL, NULL)) != SQLITE_OK) {
			if (rc == SQLITE_BUSY) {
				struct timespec sleep_ts = {
						.tv_sec = 0,
						.tv_nsec = 1000000
				};

				nanosleep (&sleep_ts, NULL);

				continue;
			}

			msg_warn_pool_check ("WAL mode is not supported (%s), locking issues might occur",
					sqlite3_errmsg (sqlite));
			break;
		}

		if (sqlite3_exec (sqlite, exclusive_lock_sql, NULL, NULL, NULL) != SQLITE_OK) {
			msg_warn_pool_check ("cannot exclusively lock database to create schema: %s",
					sqlite3_errmsg (sqlite));
		}

		if (create_sql) {
			while ((rc = sqlite3_exec (sqlite, create_sql, NULL, NULL, NULL)) != SQLITE_OK) {
				if (rc == SQLITE_BUSY) {
					struct timespec sleep_ts = {
							.tv_sec = 0,
							.tv_nsec = 1000000
					};

					nanosleep (&sleep_ts, NULL);

					continue;
				}

				g_set_error (err, rspamd_sqlite3_quark (),
						-1, "cannot execute create sql `%s`: %s",
						create_sql, sqlite3_errmsg (sqlite));
				sqlite3_close (sqlite);
				rspamd_file_unlock (lock_fd, FALSE);
				unlink (lock_path);
				if (lock_fd != -1) {
					close (lock_fd);
				}

				return NULL;
			}
		}

		sqlite3_close (sqlite);

		/* Reopen in normal mode */
		msg_debug_pool_check ("reopening %s in normal mode", path);
		flags &= ~SQLITE_OPEN_CREATE;

		if ((rc = sqlite3_open_v2 (path, &sqlite,
				flags, NULL)) != SQLITE_OK) {
	#if SQLITE_VERSION_NUMBER >= 3008000
			g_set_error (err, rspamd_sqlite3_quark (),
					rc, "cannot open sqlite db after creation %s: %s",
					path, sqlite3_errstr (rc));
	#else
			g_set_error (err, rspamd_sqlite3_quark (),
					rc, "cannot open sqlite db after creation %s: %d",
					path, rc);
	#endif
			rspamd_file_unlock (lock_fd, FALSE);
			unlink (lock_path);

			if (lock_fd != -1) {
				close (lock_fd);
			}

			return NULL;
		}
	}
	else if (has_lock && version > 0) {
		/* Check user version */
		sqlite3_stmt *stmt = NULL;
		guint32 db_ver;
		GString *new_ver_sql;

		if (sqlite3_prepare (sqlite, db_version, -1, &stmt, NULL) != SQLITE_OK) {
			msg_warn_pool_check ("Cannot get user version pragma: %s",
							sqlite3_errmsg (sqlite));
		}
		else {
			if (sqlite3_step (stmt) != SQLITE_ROW) {
				msg_warn_pool_check ("Cannot get user version pragma, step failed: %s",
											sqlite3_errmsg (sqlite));
				sqlite3_finalize (stmt);
			}
			else {
				db_ver = sqlite3_column_int (stmt, 0);
				sqlite3_reset (stmt);
				sqlite3_finalize (stmt);

				if (version > db_ver) {
					msg_warn_pool_check ("Database version %ud is less than "
							"desired version %ud, run create script", db_ver,
							version);

					if (create_sql) {
						if (sqlite3_exec (sqlite, create_sql, NULL, NULL, NULL) != SQLITE_OK) {
							g_set_error (err, rspamd_sqlite3_quark (),
									-1, "cannot execute create sql `%s`: %s",
									create_sql, sqlite3_errmsg (sqlite));
							sqlite3_close (sqlite);
							rspamd_file_unlock (lock_fd, FALSE);
							unlink (lock_path);
							if (lock_fd != -1) {
								close (lock_fd);
							}

							return NULL;
						}
					}

					new_ver_sql = g_string_new ("PRAGMA user_version=");
					rspamd_printf_gstring (new_ver_sql, "%ud", version);

					if (sqlite3_exec (sqlite, new_ver_sql->str, NULL, NULL, NULL)
							!= SQLITE_OK) {
						g_set_error (err, rspamd_sqlite3_quark (),
								-1, "cannot execute update version sql `%s`: %s",
								new_ver_sql->str, sqlite3_errmsg (sqlite));
						sqlite3_close (sqlite);
						rspamd_file_unlock (lock_fd, FALSE);
						unlink (lock_path);
						if (lock_fd != -1) {
							close (lock_fd);
						}

						g_string_free (new_ver_sql, TRUE);

						return NULL;
					}

					g_string_free (new_ver_sql, TRUE);
				}
				else if (db_ver > version) {
					msg_warn_pool_check ("Database version %ud is more than "
							"desired version %ud, this could cause"
							" unexpected behaviour", db_ver,
							version);
				}
			}
		}
	}

	while ((rc = sqlite3_exec (sqlite, sqlite_wal, NULL, NULL, NULL)) != SQLITE_OK) {
		if (rc == SQLITE_BUSY) {
			struct timespec sleep_ts = {
					.tv_sec = 0,
					.tv_nsec = 1000000
			};

			nanosleep (&sleep_ts, NULL);

			continue;
		}

		msg_warn_pool_check ("WAL mode is not supported (%s), locking issues might occur",
				sqlite3_errmsg (sqlite));
		break;
	}

	if (sqlite3_exec (sqlite, fsync_sql, NULL, NULL, NULL) != SQLITE_OK) {
		msg_warn_pool_check ("cannot set synchronous: %s",
				sqlite3_errmsg (sqlite));
	}

	if ((rc = sqlite3_exec (sqlite, foreign_keys, NULL, NULL, NULL)) !=
			SQLITE_OK) {
		msg_warn_pool_check ("cannot enable foreign keys: %s",
				sqlite3_errmsg (sqlite));
	}

#if defined(__LP64__) || defined(_LP64)
	if ((rc = sqlite3_exec (sqlite, enable_mmap, NULL, NULL, NULL)) != SQLITE_OK) {
		msg_warn_pool_check ("cannot enable mmap: %s",
				sqlite3_errmsg (sqlite));
	}
#endif

	if ((rc = sqlite3_exec (sqlite, other_pragmas, NULL, NULL, NULL)) !=
			SQLITE_OK) {
		msg_warn_pool_check ("cannot execute tuning pragmas: %s",
				sqlite3_errmsg (sqlite));
	}

	if (has_lock && lock_fd != -1) {
		msg_debug_pool_check ("removing lock from %s", lock_path);
		rspamd_file_unlock (lock_fd, FALSE);
		unlink (lock_path);
		close (lock_fd);
	}

	return sqlite;
}

gboolean
rspamd_sqlite3_sync (sqlite3 *db, gint *wal_frames, gint *wal_checkpoints)
{
	gint wf = 0, wc = 0, mode;

#ifdef SQLITE_OPEN_WAL
#ifdef SQLITE_CHECKPOINT_TRUNCATE
	mode = SQLITE_CHECKPOINT_TRUNCATE;
#elif defined(SQLITE_CHECKPOINT_RESTART)
	mode = SQLITE_CHECKPOINT_RESTART;
#elif defined(SQLITE_CHECKPOINT_FULL)
	mode = SQLITE_CHECKPOINT_FULL;
#endif
	/* Perform wal checkpoint (might be long) */
	if (sqlite3_wal_checkpoint_v2 (db,
			NULL,
			mode,
			&wf,
			&wc) != SQLITE_OK) {
		return FALSE;

	}
#endif

	if (wal_frames) {
		*wal_frames = wf;
	}
	if (wal_checkpoints) {
		*wal_checkpoints = wc;
	}

	return TRUE;
}
