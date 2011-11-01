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
#include "kvstorage_bdb.h"
#include "util.h"
#include <db.h>

struct bdb_op {
	struct rspamd_kv_element *elt;
	enum {
		BDB_OP_INSERT,
		BDB_OP_DELETE,
		BDB_OP_REPLACE
	} op;
};

/* Main bdb structure */
struct rspamd_bdb_backend {
	backend_init init_func;						/*< this callback is called on kv storage initialization */
	backend_insert insert_func;					/*< this callback is called when element is inserted */
	backend_replace replace_func;				/*< this callback is called when element is replaced */
	backend_lookup lookup_func;					/*< this callback is used for lookup of element */
	backend_delete delete_func;					/*< this callback is called when an element is deleted */
	backend_destroy destroy_func;				/*< this callback is used for destroying all elements inside backend */
	DB_ENV *envp;								/*< db environment */
	DB *dbp;									/*< db pointer */
	gchar *filename;
	gchar *dirname;
	guint sync_ops;
	GQueue *ops_queue;
	GHashTable *ops_hash;
	gboolean initialized;
};

/* Process single bdb operation */
static gboolean
bdb_process_single_op (struct rspamd_bdb_backend *db, DB_TXN *txn, DBC *cursorp, struct bdb_op *op)
{
	DBT 										 db_key, db_data;

	memset (&db_key, 0, sizeof(DBT));
	memset (&db_data, 0, sizeof(DBT));
	db_key.size = strlen (op->elt->key);
	db_key.data = op->elt->key;
	db_data.size = op->elt->size;
	db_data.data = op->elt;

	switch (op->op) {
	case BDB_OP_INSERT:
	case BDB_OP_REPLACE:
		if (cursorp->put (cursorp, &db_key, &db_data, 0) != 0) {
			return FALSE;
		}
		break;
	case BDB_OP_DELETE:
		db_data.flags = DB_DBT_USERMEM;
		/* Set cursor */
		if (cursorp->get (cursorp, &db_key, &db_data, 0) != 0) {
			return FALSE;
		}
		/* Del record */
		if (cursorp->del (cursorp, 0) != 0) {
			return FALSE;
		}
		break;
	}

	return TRUE;
}

/* Process operations queue */
static gboolean
bdb_process_queue (struct rspamd_bdb_backend *db)
{
	struct bdb_op								*op;
	DBC 										*cursorp;
	DB_TXN 										*txn = NULL;
	GList										*cur, *tmp;

	/* Start transaction */
	if (db->envp->txn_begin (db->envp, NULL, &txn, 0) != 0) {
		return FALSE;
	}
	if (db->dbp->cursor (db->dbp, txn, &cursorp, 0) != 0) {
		txn->abort (txn);
		return FALSE;
	}

	cur = db->ops_queue->head;
	while (cur) {
		op = cur->data;
		if (! bdb_process_single_op (db, txn, cursorp, op)) {
			txn->abort (txn);
			return FALSE;
		}
		cur = g_list_next (cur);
	}

	/* Commit transaction */
	cursorp->close (cursorp);
	if (txn->commit (txn, 0) != 0) {
		return FALSE;
	}

	/* Clean the queue */
	cur = db->ops_queue->head;
	while (cur) {
		op = cur->data;
		tmp = cur;
		g_hash_table_remove (db->ops_hash, op->elt->key);
		if (op->op == BDB_OP_DELETE) {
			/* Also clean memory */
			g_free (op->elt);
		}
		cur = g_list_next (cur);
		g_queue_delete_link (db->ops_queue, tmp);
		g_slice_free1 (sizeof (struct bdb_op), op);
	}

	return TRUE;

}

/* Backend callbacks */
static void
rspamd_bdb_init (struct rspamd_kv_backend *backend)
{
	struct rspamd_bdb_backend					*db = (struct rspamd_bdb_backend *)backend;
	guint32										 flags;

	if (db_env_create (&db->envp, 0) != 0) {
		/* Cannot create environment */
		goto err;
	}

	flags = DB_CREATE    |    /* Create the environment if it does not already exist. */
			DB_INIT_TXN  |    /* Initialize transactions */
			DB_INIT_LOCK |    /* Initialize locking. */
			DB_THREAD;        /* Use threads */

	if (db->envp->open (db->envp, db->dirname, flags, 0) != 0) {
		/* Cannot open environment */
		goto err;
	}
	/*
	 * Configure db to perform deadlock detection internally, and to
	 * choose the transaction that has performed the least amount of
	 * writing to break the deadlock in the event that one is detected.
	 */
	db->envp->set_lk_detect(db->envp, DB_LOCK_MINWRITE);

	flags = DB_CREATE | DB_THREAD;
	/* Create and open db pointer */
	if (db_create (&db->dbp, db->envp, 0) != 0) {
		goto err;
	}

	if (db->dbp->open (db->dbp, NULL, db->filename, NULL, DB_BTREE, flags, 0) != 0) {
		goto err;
	}

	db->initialized = TRUE;

	return;
err:
	if (db->dbp != NULL) {
		db->dbp->close (db->dbp, 0);
	}
	if (db->envp != NULL) {
		db->envp->close (db->envp, 0);
	}
}

static gboolean
rspamd_bdb_insert (struct rspamd_kv_backend *backend, gpointer key, struct rspamd_kv_element *elt)
{
	struct rspamd_bdb_backend					*db = (struct rspamd_bdb_backend *)backend;
	struct bdb_op								*op;

	if (!db->initialized) {
		return FALSE;
	}

	op = g_slice_alloc (sizeof (struct bdb_op));
	op->op = BDB_OP_INSERT;
	op->elt = elt;
	elt->flags |= KV_ELT_DIRTY;

	g_queue_push_head (db->ops_queue, elt);
	g_hash_table_insert (db->ops_hash, key, elt);

	if (g_queue_get_length (db->ops_queue) >= db->sync_ops) {
		return bdb_process_queue (db);
	}

	return TRUE;
}

static gboolean
rspamd_bdb_replace (struct rspamd_kv_backend *backend, gpointer key, struct rspamd_kv_element *elt)
{
	struct rspamd_bdb_backend					*db = (struct rspamd_bdb_backend *)backend;
	struct bdb_op								*op;

	if (!db->initialized) {
		return FALSE;
	}

	op = g_slice_alloc (sizeof (struct bdb_op));
	op->op = BDB_OP_REPLACE;
	op->elt = elt;
	elt->flags |= KV_ELT_DIRTY;

	g_queue_push_head (db->ops_queue, elt);
	g_hash_table_insert (db->ops_hash, key, elt);

	if (g_queue_get_length (db->ops_queue) >= db->sync_ops) {
		return bdb_process_queue (db);
	}

	return TRUE;
}

static struct rspamd_kv_element*
rspamd_bdb_lookup (struct rspamd_kv_backend *backend, gpointer key)
{
	struct rspamd_bdb_backend					*db = (struct rspamd_bdb_backend *)backend;
	struct bdb_op								*op;
	DBC 										*cursorp;
	DBT 										 db_key, db_data;
	struct rspamd_kv_element					*elt = NULL;

	if (!db->initialized) {
		return NULL;
	}
	/* First search in ops queue */
	if ((op = g_hash_table_lookup (db->ops_hash, key)) != NULL) {
		if (op->op == BDB_OP_DELETE) {
			/* To delete, so assume it as not found */
			return NULL;
		}
		return op->elt;
	}

	/* Now try to search in bdb */
	if (db->dbp->cursor (db->dbp, NULL, &cursorp, 0) != 0) {
		return NULL;
	}
	memset (&db_key, 0, sizeof(DBT));
	memset (&db_data, 0, sizeof(DBT));
	db_key.size = strlen (key);
	db_key.data = key;
	db_data.flags = DB_DBT_MALLOC;

	if (cursorp->get (cursorp, &db_key, &db_data, 0) == 0) {
		elt = db_data.data;
	}

	cursorp->close (cursorp);
	return elt;
}

static void
rspamd_bdb_delete (struct rspamd_kv_backend *backend, gpointer key)
{
	struct rspamd_bdb_backend					*db = (struct rspamd_bdb_backend *)backend;
	struct bdb_op								*op;
	struct rspamd_kv_element					*elt;

	if (!db->initialized) {
		return;
	}

	if ((op = g_hash_table_lookup (db->ops_hash, key)) != NULL) {
		return;
	}

	elt = rspamd_bdb_lookup (backend, key);
	if (elt == NULL) {
		return;
	}
	op = g_slice_alloc (sizeof (struct bdb_op));
	op->op = BDB_OP_DELETE;
	op->elt = elt;
	elt->flags |= KV_ELT_DIRTY;

	g_queue_push_head (db->ops_queue, elt);
	g_hash_table_insert (db->ops_hash, key, elt);

	if (g_queue_get_length (db->ops_queue) >= db->sync_ops) {
		bdb_process_queue (db);
	}

	return;
}

static void
rspamd_bdb_destroy (struct rspamd_kv_backend *backend)
{
	struct rspamd_bdb_backend					*db = (struct rspamd_bdb_backend *)backend;

	if (db->initialized) {
		if (db->dbp != NULL) {
			db->dbp->close (db->dbp, 0);
		}
		if (db->envp != NULL) {
			db->envp->close (db->envp, 0);
		}
		g_free (db->filename);
		g_free (db->dirname);
		g_queue_free (db->ops_queue);
		g_hash_table_unref (db->ops_hash);
		g_slice_free1 (sizeof (struct rspamd_bdb_backend), db);
	}
}

/* Create new bdb backend */
struct rspamd_kv_backend *
rspamd_kv_bdb_new (const gchar *filename, guint sync_ops)
{
	struct rspamd_bdb_backend					*new;
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
		return NULL;
	}

	new = g_slice_alloc0 (sizeof (struct rspamd_bdb_backend));
	new->dirname = dirname;
	new->filename = g_strdup (filename);
	new->sync_ops = sync_ops;
	new->ops_queue = g_queue_new ();
	new->ops_hash = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);

	/* Init callbacks */
	new->init_func = rspamd_bdb_init;
	new->insert_func = rspamd_bdb_insert;
	new->lookup_func = rspamd_bdb_lookup;
	new->delete_func = rspamd_bdb_delete;
	new->replace_func = rspamd_bdb_replace;
	new->destroy_func = rspamd_bdb_destroy;

	return (struct rspamd_kv_backend *)new;
}
