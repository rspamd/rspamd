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
#include "kvstorage_file.h"
#include "util.h"
#include "main.h"

struct file_op {
	struct rspamd_kv_element *elt;
	enum {
		FILE_OP_INSERT,
		FILE_OP_DELETE,
		FILE_OP_REPLACE
	} op;
};

/* Main file structure */
struct rspamd_file_backend {
	backend_init init_func;						/*< this callback is called on kv storage initialization */
	backend_insert insert_func;					/*< this callback is called when element is inserted */
	backend_replace replace_func;				/*< this callback is called when element is replaced */
	backend_lookup lookup_func;					/*< this callback is used for lookup of element */
	backend_delete delete_func;					/*< this callback is called when an element is deleted */
	backend_sync sync_func;						/*< this callback is called when backend need to be synced */
	backend_destroy destroy_func;				/*< this callback is used for destroying all elements inside backend */
	gchar *filename;
	gchar *dirname;
	guint sync_ops;
	guint levels;
	GQueue *ops_queue;
	GHashTable *ops_hash;
	gboolean initialized;
};

static const gchar hexdigits[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

/* Process single file operation */
static gboolean
file_process_single_op (struct rspamd_file_backend *db, struct file_op *op)
{
	gboolean									 res = FALSE;

	return res;
}

/* Process operations queue */
static gboolean
file_process_queue (struct rspamd_kv_backend *backend)
{
	struct rspamd_file_backend					*db = (struct rspamd_file_backend *)backend;
	struct file_op								*op;
	GList										*cur;

	cur = db->ops_queue->head;
	while (cur) {
		op = cur->data;
		if (! file_process_single_op (db, op)) {
			return FALSE;
		}
		cur = g_list_next (cur);
	}

	/* Clean the queue */
	cur = db->ops_queue->head;
	while (cur) {
		op = cur->data;
		if (op->op == FILE_OP_DELETE || (op->elt->flags & KV_ELT_NEED_FREE) != 0) {
			/* Also clean memory */
			g_slice_free1 (ELT_SIZE (op->elt), op->elt);
		}
		g_slice_free1 (sizeof (struct file_op), op);
		cur = g_list_next (cur);
	}

	g_hash_table_remove_all (db->ops_hash);
	g_queue_clear (db->ops_queue);

	return TRUE;

}


/* Make 16 directories for each level */
static gboolean
rspamd_recursive_mkdir (guint levels)
{
	guint									i, j;
	gchar									nbuf[5];

	/* Create directories for backend */
	if (levels > 0) {
		/* Create 16 directories */
		for (j = 0; j < 16; j ++) {
			rspamd_snprintf (nbuf, sizeof (nbuf), "./%c", hexdigits[j]);
			if (mkdir (nbuf, 0755) != 0 && errno != EEXIST) {
				return FALSE;
			}
			else if (levels > 1) {
				chdir (nbuf);
				if (! rspamd_recursive_mkdir (levels - 1)) {
					return FALSE;
				}
				chdir ("../");
			}
		}
	}
	return TRUE;

}

/* Backend callbacks */
static void
rspamd_file_init (struct rspamd_kv_backend *backend)
{
	struct rspamd_file_backend				*db = (struct rspamd_file_backend *)backend;
	gint									 ret;
	gchar									 pathbuf[PATH_MAX];

	/* Save current directory */
	if (getcwd (pathbuf, sizeof (pathbuf) - 1) == NULL) {
		pathbuf[0] = '\0';
		msg_err ("getcwd failed: %s", strerror (errno));
		goto err;
	}

	/* Chdir to the working dir */
	if (chdir (db->dirname) == -1) {
		msg_err ("chdir failed: %s", strerror (errno));
		goto err;
	}

	/* Create directories for backend */
	rspamd_recursive_mkdir (db->levels);

	db->initialized = TRUE;

	chdir (pathbuf);
	return;
err:
	if (pathbuf[0] != '\0') {
		chdir (pathbuf);
	}
}

static gboolean
rspamd_file_insert (struct rspamd_kv_backend *backend, gpointer key, struct rspamd_kv_element *elt)
{
	struct rspamd_file_backend					*db = (struct rspamd_file_backend *)backend;
	struct file_op								*op;

	if (!db->initialized) {
		return FALSE;
	}

	if ((op = g_hash_table_lookup (db->ops_hash, key)) != NULL) {
		/* We found another op with such key in this queue */
		if (op->op == FILE_OP_DELETE || (op->elt->flags & KV_ELT_NEED_FREE) != 0) {
			/* Also clean memory */
			g_slice_free1 (ELT_SIZE (op->elt), op->elt);
		}
		op->op = FILE_OP_INSERT;
		op->elt = elt;
	}
	else {
		op = g_slice_alloc (sizeof (struct file_op));
		op->op = FILE_OP_INSERT;
		op->elt = elt;
		elt->flags |= KV_ELT_DIRTY;

		g_queue_push_head (db->ops_queue, op);
		g_hash_table_insert (db->ops_hash, ELT_KEY (elt), op);
	}

	if (db->sync_ops > 0 && g_queue_get_length (db->ops_queue) >= db->sync_ops) {
		return file_process_queue (backend);
	}

	return TRUE;
}

static gboolean
rspamd_file_replace (struct rspamd_kv_backend *backend, gpointer key, struct rspamd_kv_element *elt)
{
	struct rspamd_file_backend					*db = (struct rspamd_file_backend *)backend;
	struct file_op								*op;

	if (!db->initialized) {
		return FALSE;
	}
	if ((op = g_hash_table_lookup (db->ops_hash, key)) != NULL) {
		/* We found another op with such key in this queue */
		if (op->op == FILE_OP_DELETE || (op->elt->flags & KV_ELT_NEED_FREE) != 0) {
			/* Also clean memory */
			g_slice_free1 (ELT_SIZE (op->elt), op->elt);
		}
		op->op = FILE_OP_REPLACE;
		op->elt = elt;
	}
	else {
		op = g_slice_alloc (sizeof (struct file_op));
		op->op = FILE_OP_REPLACE;
		op->elt = elt;
		elt->flags |= KV_ELT_DIRTY;

		g_queue_push_head (db->ops_queue, op);
		g_hash_table_insert (db->ops_hash, ELT_KEY (elt), op);
	}

	if (db->sync_ops > 0 && g_queue_get_length (db->ops_queue) >= db->sync_ops) {
		return file_process_queue (backend);
	}

	return TRUE;
}

static struct rspamd_kv_element*
rspamd_file_lookup (struct rspamd_kv_backend *backend, gpointer key)
{
	struct rspamd_file_backend					*db = (struct rspamd_file_backend *)backend;
	struct file_op								*op;
	struct rspamd_kv_element					*elt = NULL;
	gint										 l;
	gconstpointer								 d;

	if (!db->initialized) {
		return NULL;
	}
	/* First search in ops queue */
	if ((op = g_hash_table_lookup (db->ops_hash, key)) != NULL) {
		if (op->op == FILE_OP_DELETE) {
			/* To delete, so assume it as not found */
			return NULL;
		}
		return op->elt;
	}
	return elt;
}

static void
rspamd_file_delete (struct rspamd_kv_backend *backend, gpointer key)
{
	struct rspamd_file_backend					*db = (struct rspamd_file_backend *)backend;
	struct file_op								*op;
	struct rspamd_kv_element					*elt;

	if (!db->initialized) {
		return;
	}

	if ((op = g_hash_table_lookup (db->ops_hash, key)) != NULL) {
		op->op = FILE_OP_DELETE;
		return;
	}

	elt = rspamd_file_lookup (backend, key);
	if (elt == NULL) {
		return;
	}
	op = g_slice_alloc (sizeof (struct file_op));
	op->op = FILE_OP_DELETE;
	op->elt = elt;
	elt->flags |= KV_ELT_DIRTY;

	g_queue_push_head (db->ops_queue, op);
	g_hash_table_insert (db->ops_hash, ELT_KEY(elt), op);

	if (db->sync_ops > 0 && g_queue_get_length (db->ops_queue) >= db->sync_ops) {
		file_process_queue (backend);
	}

	return;
}

static void
rspamd_file_destroy (struct rspamd_kv_backend *backend)
{
	struct rspamd_file_backend					*db = (struct rspamd_file_backend *)backend;

	if (db->initialized) {
		file_process_queue (backend);
		g_free (db->filename);
		g_free (db->dirname);
		g_queue_free (db->ops_queue);
		g_hash_table_unref (db->ops_hash);
		g_slice_free1 (sizeof (struct rspamd_file_backend), db);
	}
}

/* Create new file backend */
struct rspamd_kv_backend *
rspamd_kv_file_new (const gchar *filename, guint sync_ops, guint levels)
{
	struct rspamd_file_backend			 		*new;
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

	new = g_slice_alloc0 (sizeof (struct rspamd_file_backend));
	new->dirname = dirname;
	new->filename = g_strdup (filename);
	new->sync_ops = sync_ops;
	new->levels = levels;
	new->ops_queue = g_queue_new ();
	new->ops_hash = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);

	/* Init callbacks */
	new->init_func = rspamd_file_init;
	new->insert_func = rspamd_file_insert;
	new->lookup_func = rspamd_file_lookup;
	new->delete_func = rspamd_file_delete;
	new->replace_func = rspamd_file_replace;
	new->sync_func = file_process_queue;
	new->destroy_func = rspamd_file_destroy;

	return (struct rspamd_kv_backend *)new;
}

