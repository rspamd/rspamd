/* Copyright (c) 2010, Vsevolod Stakhov
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
#include "kvstorage.h"
#include "kvstorage_sqlite.h"
#include "util.h"
#include "main.h"
#include <sqlite3.h>

#define TABLE_NAME "kvstorage"
#define CREATE_TABLE_SQL "CREATE TABLE " TABLE_NAME " (key TEXT CONSTRAINT _key PRIMARY KEY, data BLOB)"
#define SET_SQL "INSERT OR REPLACE INTO " TABLE_NAME " (key, data) VALUES (?1, ?2)"
#define GET_SQL "SELECT data FROM " TABLE_NAME " WHERE key = ?1"
#define DELETE_SQL "DELETE FROM " TABLE_NAME " WHERE key = ?1"

struct sqlite_op {
	struct rspamd_kv_element *elt;
	enum {
		SQLITE_OP_INSERT,
		SQLITE_OP_DELETE,
		SQLITE_OP_REPLACE
	} op;
};

/* Main sqlite structure */
struct rspamd_sqlite_backend {
	backend_init init_func;						/*< this callback is called on kv storage initialization */
	backend_insert insert_func;					/*< this callback is called when element is inserted */
	backend_replace replace_func;				/*< this callback is called when element is replaced */
	backend_lookup lookup_func;					/*< this callback is used for lookup of element */
	backend_delete delete_func;					/*< this callback is called when an element is deleted */
	backend_sync sync_func;						/*< this callback is called when backend need to be synced */
	backend_destroy destroy_func;				/*< this callback is used for destroying all elements inside backend */
	sqlite3 *dbp;
	gchar *filename;
	gchar *dirname;
	guint sync_ops;
	GQueue *ops_queue;
	GHashTable *ops_hash;
	gboolean initialized;
	sqlite3_stmt *get_stmt;
	sqlite3_stmt *set_stmt;
	sqlite3_stmt *delete_stmt;
};

/* Process single sqlite operation */
static gboolean
sqlite_process_single_op (struct rspamd_sqlite_backend *db, struct sqlite_op *op)
{
	gboolean									 res = FALSE;

	op->elt->flags &= ~KV_ELT_DIRTY;
	switch (op->op) {
	case SQLITE_OP_INSERT:
	case SQLITE_OP_REPLACE:
		if (sqlite3_bind_text (db->set_stmt, 1, ELT_KEY (op->elt), op->elt->keylen, SQLITE_STATIC) == SQLITE_OK &&
				sqlite3_bind_blob (db->set_stmt, 2, op->elt, ELT_SIZE (op->elt), SQLITE_STATIC) == SQLITE_OK) {
			if (sqlite3_step (db->set_stmt) == SQLITE_DONE) {
				res = TRUE;
			}
		}
		sqlite3_reset (db->set_stmt);
		break;
	case SQLITE_OP_DELETE:
		if (sqlite3_bind_text (db->delete_stmt, 1, ELT_KEY (op->elt), op->elt->keylen, SQLITE_STATIC) == SQLITE_OK) {
			if (sqlite3_step (db->delete_stmt) == SQLITE_DONE) {
				res = TRUE;
			}
		}
		sqlite3_reset (db->delete_stmt);
		break;
	}

	if (!res) {
		op->elt->flags |= KV_ELT_DIRTY;
	}
	return res;
}

/* Process operations queue */
static gboolean
sqlite_process_queue (struct rspamd_kv_backend *backend)
{
	struct rspamd_sqlite_backend				*db = (struct rspamd_sqlite_backend *)backend;
	struct sqlite_op							*op;
	GList										*cur;

	cur = db->ops_queue->head;
	while (cur) {
		op = cur->data;
		if (! sqlite_process_single_op (db, op)) {
			return FALSE;
		}
		cur = g_list_next (cur);
	}

	/* Clean the queue */
	cur = db->ops_queue->head;
	while (cur) {
		op = cur->data;
		if (op->op == SQLITE_OP_DELETE || (op->elt->flags & KV_ELT_NEED_FREE) != 0) {
			/* Also clean memory */
			g_slice_free1 (ELT_SIZE (op->elt), op->elt);
		}
		g_slice_free1 (sizeof (struct sqlite_op), op);
		cur = g_list_next (cur);
	}

	g_hash_table_remove_all (db->ops_hash);
	g_queue_clear (db->ops_queue);

	return TRUE;

}

/* Create table for kvstorage */
static gboolean
rspamd_sqlite_create_table (struct rspamd_sqlite_backend *db)
{
	gint										 ret;
	sqlite3_stmt								*stmt = NULL;

	ret = sqlite3_prepare_v2 (db->dbp, CREATE_TABLE_SQL, sizeof (CREATE_TABLE_SQL) - 1, &stmt, NULL);
	if (ret != SQLITE_OK) {
		if (stmt != NULL) {
			sqlite3_finalize (stmt);
		}
		return FALSE;
	}

	ret = sqlite3_step (stmt);
	if (ret != SQLITE_DONE) {
		sqlite3_finalize (stmt);
		return FALSE;
	}

	sqlite3_finalize (stmt);
	return TRUE;
}

/* Backend callbacks */
static void
rspamd_sqlite_init (struct rspamd_kv_backend *backend)
{
	struct rspamd_sqlite_backend				*db = (struct rspamd_sqlite_backend *)backend;
	guint32										 flags;
	gint										 ret, r;
	gchar										 sqlbuf[BUFSIZ];
	sqlite3_stmt								*stmt = NULL;

	/* Set multi-threaded mode */
	if (sqlite3_config (SQLITE_CONFIG_MULTITHREAD) != SQLITE_OK) {
		goto err;
	}

	flags = SQLITE_OPEN_READWRITE |
			SQLITE_OPEN_CREATE    |
			SQLITE_OPEN_NOMUTEX;

	ret = sqlite3_open_v2 (db->filename, &db->dbp, flags, NULL);

	if (ret != 0) {
		goto err;
	}
	/* Now check if we have table */
	r = rspamd_snprintf (sqlbuf, sizeof (sqlbuf), "SELECT * FROM " TABLE_NAME " LIMIT 1");
	ret = sqlite3_prepare_v2 (db->dbp, sqlbuf, r, &stmt, NULL);

	if (ret == SQLITE_ERROR) {
		/* Try to create table */
		if (!rspamd_sqlite_create_table (db)) {
			goto err;
		}
	}
	else if (ret != SQLITE_OK) {
		goto err;
	}
	/* We have table here, perform vacuum */
	sqlite3_finalize (stmt);
	r = rspamd_snprintf (sqlbuf, sizeof (sqlbuf), "VACUUM");
	ret = sqlite3_prepare_v2 (db->dbp, sqlbuf, r, &stmt, NULL);
	if (ret != SQLITE_OK) {
		goto err;
	}
	/* Perform VACUUM */
	sqlite3_step (stmt);
	sqlite3_finalize (stmt);

	/* Prepare required statements */
	ret = sqlite3_prepare_v2 (db->dbp, GET_SQL, sizeof (GET_SQL) - 1, &db->get_stmt, NULL);
	if (ret != SQLITE_OK) {
		goto err;
	}
	ret = sqlite3_prepare_v2 (db->dbp, SET_SQL, sizeof (SET_SQL) - 1, &db->set_stmt, NULL);
	if (ret != SQLITE_OK) {
		goto err;
	}
	ret = sqlite3_prepare_v2 (db->dbp, DELETE_SQL, sizeof (DELETE_SQL) - 1, &db->delete_stmt, NULL);
	if (ret != SQLITE_OK) {
		goto err;
	}

	db->initialized = TRUE;

	return;
err:
	if (db->dbp != NULL) {
		msg_err ("error opening sqlite database: %d", ret);
	}
	if (stmt != NULL) {
		msg_err ("error executing statement: %d", ret);
		sqlite3_finalize (stmt);
	}
	if (db->get_stmt != NULL) {
		sqlite3_finalize (db->get_stmt);
	}
	if (db->set_stmt != NULL) {
		sqlite3_finalize (db->set_stmt);
	}
	if (db->delete_stmt != NULL) {
		sqlite3_finalize (db->delete_stmt);
	}
}

static gboolean
rspamd_sqlite_insert (struct rspamd_kv_backend *backend, gpointer key, struct rspamd_kv_element *elt)
{
	struct rspamd_sqlite_backend				*db = (struct rspamd_sqlite_backend *)backend;
	struct sqlite_op							*op;

	if (!db->initialized) {
		return FALSE;
	}

	op = g_slice_alloc (sizeof (struct sqlite_op));
	op->op = SQLITE_OP_INSERT;
	op->elt = elt;
	elt->flags |= KV_ELT_DIRTY;

	g_queue_push_head (db->ops_queue, op);
	g_hash_table_insert (db->ops_hash, ELT_KEY (elt), op);

	if (g_queue_get_length (db->ops_queue) >= db->sync_ops) {
		return sqlite_process_queue (backend);
	}

	return TRUE;
}

static gboolean
rspamd_sqlite_replace (struct rspamd_kv_backend *backend, gpointer key, struct rspamd_kv_element *elt)
{
	struct rspamd_sqlite_backend				*db = (struct rspamd_sqlite_backend *)backend;
	struct sqlite_op							*op;

	if (!db->initialized) {
		return FALSE;
	}

	op = g_slice_alloc (sizeof (struct sqlite_op));
	op->op = SQLITE_OP_REPLACE;
	op->elt = elt;
	elt->flags |= KV_ELT_DIRTY;

	g_queue_push_head (db->ops_queue, op);
	g_hash_table_insert (db->ops_hash, ELT_KEY (elt), op);

	if (g_queue_get_length (db->ops_queue) >= db->sync_ops) {
		return sqlite_process_queue (backend);
	}

	return TRUE;
}

static struct rspamd_kv_element*
rspamd_sqlite_lookup (struct rspamd_kv_backend *backend, gpointer key)
{
	struct rspamd_sqlite_backend				*db = (struct rspamd_sqlite_backend *)backend;
	struct sqlite_op							*op;
	struct rspamd_kv_element					*elt = NULL;
	gint										 l;
	gconstpointer								 d;

	if (!db->initialized) {
		return NULL;
	}
	/* First search in ops queue */
	if ((op = g_hash_table_lookup (db->ops_hash, key)) != NULL) {
		if (op->op == SQLITE_OP_DELETE) {
			/* To delete, so assume it as not found */
			return NULL;
		}
		return op->elt;
	}

	if (sqlite3_bind_text (db->get_stmt, 1, key, strlen (key), SQLITE_STATIC) == SQLITE_OK) {
		if (sqlite3_step (db->get_stmt) == SQLITE_ROW) {
			l = sqlite3_column_bytes (db->get_stmt, 0);
			elt = g_malloc (l);
			d = sqlite3_column_blob (db->get_stmt, 0);
			/* Make temporary copy */
			memcpy (elt, d, l);
		}
	}

	sqlite3_reset (db->get_stmt);
	return elt;
}

static void
rspamd_sqlite_delete (struct rspamd_kv_backend *backend, gpointer key)
{
	struct rspamd_sqlite_backend				*db = (struct rspamd_sqlite_backend *)backend;
	struct sqlite_op							*op;
	struct rspamd_kv_element					*elt;

	if (!db->initialized) {
		return;
	}

	if ((op = g_hash_table_lookup (db->ops_hash, key)) != NULL) {
		op->op = SQLITE_OP_DELETE;
		return;
	}

	elt = rspamd_sqlite_lookup (backend, key);
	if (elt == NULL) {
		return;
	}
	op = g_slice_alloc (sizeof (struct sqlite_op));
	op->op = SQLITE_OP_DELETE;
	op->elt = elt;
	elt->flags |= KV_ELT_DIRTY;

	g_queue_push_head (db->ops_queue, op);
	g_hash_table_insert (db->ops_hash, ELT_KEY(elt), op);

	if (g_queue_get_length (db->ops_queue) >= db->sync_ops) {
		sqlite_process_queue (backend);
	}

	return;
}

static void
rspamd_sqlite_destroy (struct rspamd_kv_backend *backend)
{
	struct rspamd_sqlite_backend				*db = (struct rspamd_sqlite_backend *)backend;

	if (db->initialized) {
		sqlite_process_queue (backend);
		if (db->get_stmt != NULL) {
			sqlite3_finalize (db->get_stmt);
		}
		if (db->set_stmt != NULL) {
			sqlite3_finalize (db->set_stmt);
		}
		if (db->delete_stmt != NULL) {
			sqlite3_finalize (db->delete_stmt);
		}
		sqlite3_close (db->dbp);
		g_free (db->filename);
		g_free (db->dirname);
		g_queue_free (db->ops_queue);
		g_hash_table_unref (db->ops_hash);
		g_slice_free1 (sizeof (struct rspamd_sqlite_backend), db);
	}
}

/* Create new sqlite backend */
struct rspamd_kv_backend *
rspamd_kv_sqlite_new (const gchar *filename, guint sync_ops)
{
	struct rspamd_sqlite_backend			 	*new;
	struct stat 								 st;
	gchar										*dirname;

	if (filename == NULL) {
		return NULL;
	}

	dirname = g_path_get_dirname (filename);
	if (dirname == NULL || stat (dirname, &st) == -1 || !S_ISDIR (st.st_mode)) {
		/* Inaccessible path */
		if (dirname != NULL) {
			g_free (dirname);
		}
		msg_err ("invalid file: %s", filename);
		return NULL;
	}

	new = g_slice_alloc0 (sizeof (struct rspamd_sqlite_backend));
	new->dirname = dirname;
	new->filename = g_strdup (filename);
	new->sync_ops = sync_ops;
	new->ops_queue = g_queue_new ();
	new->ops_hash = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);

	/* Init callbacks */
	new->init_func = rspamd_sqlite_init;
	new->insert_func = rspamd_sqlite_insert;
	new->lookup_func = rspamd_sqlite_lookup;
	new->delete_func = rspamd_sqlite_delete;
	new->replace_func = rspamd_sqlite_replace;
	new->sync_func = sqlite_process_queue;
	new->destroy_func = rspamd_sqlite_destroy;

	return (struct rspamd_kv_backend *)new;
}

