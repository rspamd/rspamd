/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
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
#include "binlog.h"
#include "cfg_file.h"
#include "tokenizers/tokenizers.h"

#define BINLOG_SUFFIX ".binlog"
#define BACKUP_SUFFIX ".old"
#define VALID_MAGIC { 'r', 's', 'l' }
#define VALID_VERSION { '1', '0' }

static GHashTable *binlog_opened = NULL;
static rspamd_mempool_t *binlog_pool = NULL;

static gboolean
binlog_write_header (struct rspamd_binlog *log)
{
	struct rspamd_binlog_header header = {
		.magic = VALID_MAGIC,
		.version = VALID_VERSION,
		.padding = { '\0', '\0' },
	};

	header.create_time = time (NULL);
	lock_file (log->fd, FALSE);

	if (write (log->fd, &header, sizeof (struct rspamd_binlog_header)) == -1) {
		msg_warn ("cannot write file %s, error %d, %s",
			log->filename,
			errno,
			strerror (errno));
		return FALSE;
	}


	memcpy (&log->header, &header, sizeof (struct rspamd_binlog_header));

	/* Metaindex */
	log->metaindex = g_malloc (sizeof (struct rspamd_binlog_metaindex));
	bzero (log->metaindex, sizeof (struct rspamd_binlog_metaindex));
	/* Offset to metaindex */
	log->metaindex->indexes[0] = sizeof (struct rspamd_binlog_metaindex) +
		sizeof (struct rspamd_binlog_header);

	if (write (log->fd, log->metaindex,
		sizeof (struct rspamd_binlog_metaindex))  == -1) {
		g_free (log->metaindex);
		msg_warn ("cannot write file %s, error %d, %s",
			log->filename,
			errno,
			strerror (errno));
		unlock_file (log->fd, FALSE);
		return FALSE;
	}

	/* Alloc, write, mmap */
	log->cur_idx = g_malloc (sizeof (struct rspamd_index_block));
	bzero (log->cur_idx, sizeof (struct rspamd_index_block));
	if (write (log->fd, log->cur_idx,
		sizeof (struct rspamd_index_block))  == -1) {
		g_free (log->cur_idx);
		msg_warn ("cannot write file %s, error %d, %s",
			log->filename,
			errno,
			strerror (errno));
		unlock_file (log->fd, FALSE);
		return FALSE;
	}

	unlock_file (log->fd, FALSE);

	return TRUE;
}

static gboolean
binlog_check_file (struct rspamd_binlog *log)
{
	static gchar valid_magic[] = VALID_MAGIC, valid_version[] = VALID_VERSION;

	if (read (log->fd, &log->header,
		sizeof (struct rspamd_binlog_header)) !=
		sizeof (struct rspamd_binlog_header)) {
		msg_warn ("cannot read file %s, error %d, %s",
			log->filename,
			errno,
			strerror (errno));
		return FALSE;
	}

	/* Now check all fields */
	if (memcmp (&log->header.magic, valid_magic, sizeof (valid_magic)) != 0 ||
		memcmp (&log->header.version, valid_version,
		sizeof (valid_version)) != 0) {
		msg_warn ("cannot validate file %s");
		return FALSE;
	}
	/* Now mmap metaindex and current index */
	if (log->metaindex == NULL) {
		log->metaindex = g_malloc (sizeof (struct rspamd_binlog_metaindex));
	}
	if ((read (log->fd, log->metaindex,
		sizeof (struct rspamd_binlog_metaindex))) !=
		sizeof (struct rspamd_binlog_metaindex)) {
		msg_warn ("cannot read metaindex of file %s, error %d, %s",
			log->filename,
			errno,
			strerror (errno));
		return FALSE;
	}
	/* Current index */
	if (log->cur_idx == NULL) {
		log->cur_idx = g_malloc (sizeof (struct rspamd_index_block));
	}
	if (lseek (log->fd, log->metaindex->indexes[log->metaindex->last_index],
		SEEK_SET) == -1) {
		msg_info ("cannot seek in file: %s, error: %s",
			log->filename,
			strerror (errno));
		return FALSE;
	}
	if ((read (log->fd, log->cur_idx,
		sizeof (struct rspamd_index_block))) !=
		sizeof (struct rspamd_index_block)) {
		msg_warn ("cannot read index in file %s, error %d, %s",
			log->filename,
			errno,
			strerror (errno));
		return FALSE;
	}

	log->cur_seq = log->metaindex->last_index * BINLOG_IDX_LEN +
		log->cur_idx->last_index;
	log->cur_time = log->cur_idx->indexes[log->cur_idx->last_index].time;

	return TRUE;

}

static gboolean
binlog_create (struct rspamd_binlog *log)
{
	if ((log->fd =
		open (log->filename, O_RDWR | O_TRUNC | O_CREAT,
		S_IWUSR | S_IRUSR)) == -1) {
		msg_info ("cannot create file %s, error %d, %s",
			log->filename,
			errno,
			strerror (errno));
		return FALSE;
	}

	return binlog_write_header (log);
}

static gboolean
binlog_open_real (struct rspamd_binlog *log)
{
	if ((log->fd = open (log->filename, O_RDWR)) == -1) {
		msg_info ("cannot open file %s, error %d, %s",
			log->filename,
			errno,
			strerror (errno));
		return FALSE;
	}

	return binlog_check_file (log);
}


struct rspamd_binlog *
binlog_open (rspamd_mempool_t *pool,
	const gchar *path,
	time_t rotate_time,
	gint rotate_jitter)
{
	struct rspamd_binlog *new;
	gint len = strlen (path);
	struct stat st;

	new = rspamd_mempool_alloc0 (pool, sizeof (struct rspamd_binlog));
	new->pool = pool;
	new->rotate_time = rotate_time;
	new->fd = -1;

	if (rotate_time) {
		new->rotate_jitter = g_random_int_range (0, rotate_jitter);
	}

	new->filename = rspamd_mempool_alloc (pool, len + sizeof (BINLOG_SUFFIX));
	rspamd_strlcpy (new->filename,		 path,			len + 1);
	rspamd_strlcpy (new->filename + len, BINLOG_SUFFIX, sizeof (BINLOG_SUFFIX));

	if (stat (new->filename, &st) == -1) {
		/* Check errno to check whether we should create this file */
		if (errno != ENOENT) {
			msg_err ("cannot stat file: %s, error %s", new->filename,
				strerror (errno));
			return NULL;
		}
		else {
			/* In case of ENOENT try to create binlog */
			if (!binlog_create (new)) {
				return NULL;
			}
		}
	}
	else {
		/* Try to open binlog */
		if (!binlog_open_real (new)) {
			return NULL;
		}
	}

	return new;
}

void
binlog_close (struct rspamd_binlog *log)
{
	if (log) {
		if (log->metaindex) {
			g_free (log->metaindex);
		}
		if (log->cur_idx) {
			g_free (log->cur_idx);
		}
		close (log->fd);
	}
}

static gboolean
binlog_tree_callback (gpointer key, gpointer value, gpointer data)
{
	token_node_t *node = key;
	struct rspamd_binlog *log = data;
	struct rspamd_binlog_element elt;

	elt.h1 = node->h1;
	elt.h2 = node->h2;
	elt.value = node->value;

	if (write (log->fd, &elt, sizeof (elt)) == -1) {
		msg_info ("cannot write token to file: %s, error: %s",
			log->filename,
			strerror (errno));
		return TRUE;
	}

	return FALSE;
}

static gboolean
write_binlog_tree (struct rspamd_binlog *log, GTree *nodes)
{
	off_t seek;
	struct rspamd_binlog_index *idx;

	lock_file (log->fd, FALSE);
	log->cur_seq++;

	/* Seek to end of file */
	if ((seek = lseek (log->fd, 0, SEEK_END)) == -1) {
		unlock_file (log->fd, FALSE);
		msg_info ("cannot seek in file: %s, error: %s",
			log->filename,
			strerror (errno));
		return FALSE;
	}

	/* Now write all nodes to file */
	g_tree_foreach (nodes, binlog_tree_callback, (gpointer)log);

	/* Write index */
	idx = &log->cur_idx->indexes[log->cur_idx->last_index];
	idx->seek = seek;
	idx->time = (guint64)time (NULL);
	log->cur_time = idx->time;
	idx->len = g_tree_nnodes (nodes) * sizeof (struct rspamd_binlog_element);
	if (lseek (log->fd, log->metaindex->indexes[log->metaindex->last_index],
		SEEK_SET) == -1) {
		unlock_file (log->fd, FALSE);
		msg_info (
			"cannot seek in file: %s, error: %s, seek: %L, op: insert index",
			log->filename,
			strerror (errno),
			log->metaindex->indexes[log->metaindex->last_index]);
		return FALSE;
	}
	log->cur_idx->last_index++;
	if (write (log->fd, log->cur_idx,
		sizeof (struct rspamd_index_block)) == -1) {
		unlock_file (log->fd, FALSE);
		msg_info ("cannot write index to file: %s, error: %s",
			log->filename,
			strerror (errno));
		return FALSE;
	}

	unlock_file (log->fd, FALSE);

	return TRUE;
}

static gboolean
create_new_metaindex_block (struct rspamd_binlog *log)
{
	off_t seek;

	lock_file (log->fd, FALSE);

	log->metaindex->last_index++;
	/* Seek to end of file */
	if ((seek = lseek (log->fd, 0, SEEK_END)) == -1) {
		unlock_file (log->fd, FALSE);
		msg_info ("cannot seek in file: %s, error: %s",
			log->filename,
			strerror (errno));
		return FALSE;
	}
	if (write (log->fd, log->cur_idx,
		sizeof (struct rspamd_index_block))  == -1) {
		unlock_file (log->fd, FALSE);
		g_free (log->cur_idx);
		msg_warn ("cannot write file %s, error %d, %s",
			log->filename,
			errno,
			strerror (errno));
		return FALSE;
	}
	/* Offset to metaindex */
	log->metaindex->indexes[log->metaindex->last_index] = seek;
	/* Overwrite all metaindexes */
	if (lseek (log->fd, sizeof (struct rspamd_binlog_header), SEEK_SET) == -1) {
		unlock_file (log->fd, FALSE);
		msg_info ("cannot seek in file: %s, error: %s",
			log->filename,
			strerror (errno));
		return FALSE;
	}
	if (write (log->fd, log->metaindex,
		sizeof (struct rspamd_binlog_metaindex)) == -1) {
		unlock_file (log->fd, FALSE);
		msg_info ("cannot write metaindex in file: %s, error: %s",
			log->filename,
			strerror (errno));
		return FALSE;
	}
	bzero (log->cur_idx, sizeof (struct rspamd_index_block));
	unlock_file (log->fd, FALSE);

	return TRUE;
}

static gboolean
maybe_rotate_binlog (struct rspamd_binlog *log)
{
	guint64 now = time (NULL);

	if (log->rotate_time &&
		((now - log->header.create_time) >
		(guint)(log->rotate_time + log->rotate_jitter))) {
		return TRUE;
	}
	return FALSE;
}

static gboolean
rotate_binlog (struct rspamd_binlog *log)
{
	gchar *backup_name;
	struct stat st;

	lock_file (log->fd, FALSE);

	/* Unmap mapped fragments */
	if (log->metaindex) {
		g_free (log->metaindex);
		log->metaindex = NULL;
	}
	if (log->cur_idx) {
		g_free (log->cur_idx);
		log->cur_idx = NULL;
	}
	/* Format backup name */
	backup_name = g_strdup_printf ("%s.%s", log->filename, BACKUP_SUFFIX);

	if (stat (backup_name, &st) != -1) {
		msg_info ("replace old %s", backup_name);
		unlink (backup_name);
	}

	rename (log->filename, backup_name);
	g_free (backup_name);

	/* XXX: maybe race condition here */
	unlock_file (log->fd, FALSE);
	close (log->fd);

	return binlog_create (log);

}

gboolean
binlog_insert (struct rspamd_binlog *log, GTree *nodes)
{
	off_t seek;

	if (!log || !log->metaindex || !log->cur_idx || !nodes) {
		msg_info ("improperly opened binlog: %s",
			log != NULL ? log->filename : "unknown");
		return FALSE;
	}

	if (maybe_rotate_binlog (log)) {
		if (!rotate_binlog (log)) {
			return FALSE;
		}
	}
	/* First of all try to place new tokens in current index */
	if (log->cur_idx->last_index < BINLOG_IDX_LEN) {
		/* All is ok */
		return write_binlog_tree (log, nodes);
	}
	/* Current index table is all busy, try to allocate new index */

	/* Check metaindex free space */
	if (log->metaindex->last_index < METAINDEX_LEN) {
		/* Create new index block */
		if ((seek = lseek (log->fd, 0, SEEK_END)) == (off_t)-1) {
			msg_info ("cannot seek in file: %s, error: %s",
				log->filename,
				strerror (errno));
			return FALSE;
		}
		if (!create_new_metaindex_block (log)) {
			return FALSE;
		}
		return write_binlog_tree (log, nodes);
	}

	/* All binlog is filled, we need to rotate it forcefully */
	if (!rotate_binlog (log)) {
		return FALSE;
	}

	return write_binlog_tree (log, nodes);
}

gboolean
binlog_sync (struct rspamd_binlog *log,
	guint64 from_rev,
	guint64 *from_time,
	GByteArray **rep)
{
	guint32 metaindex_num;
	struct rspamd_index_block *idxb;
	struct rspamd_binlog_index *idx;
	gboolean idx_mapped = FALSE, res = TRUE, is_first = FALSE;

	if (!log || !log->metaindex || !log->cur_idx) {
		msg_info ("improperly opened binlog: %s",
			log != NULL ? log->filename : "unknown");
		return FALSE;
	}

	if (*rep == NULL) {
		*rep = g_malloc (sizeof (GByteArray));
		is_first = TRUE;
	}
	else {
		/* Unmap old fragment */
		g_free ((*rep)->data);
	}

	if (from_rev == log->cur_seq) {
		/* Last record */
		*rep = NULL;
		return FALSE;
	}
	else if (from_rev > log->cur_seq) {
		/* Slave has more actual copy, write this to log and abort sync */
		msg_warn (
			"slave has more recent revision of statfile %s: %uL and our is: %uL",
			log->filename,
			from_rev,
			log->cur_seq);
		*rep = NULL;
		*from_time = 0;
		return FALSE;
	}

	metaindex_num = from_rev / BINLOG_IDX_LEN;
	/* First of all try to find this revision */
	if (metaindex_num > log->metaindex->last_index) {
		return FALSE;
	}
	else if (metaindex_num != log->metaindex->last_index) {
		/* Need to remap index block */
		lock_file (log->fd, FALSE);
		idxb = g_malloc (sizeof (struct rspamd_index_block));
		idx_mapped = TRUE;
		if (lseek (log->fd, log->metaindex->indexes[metaindex_num],
			SEEK_SET) == -1) {
			unlock_file (log->fd, FALSE);
			msg_warn ("cannot seek file %s, error %d, %s",
				log->filename,
				errno,
				strerror (errno));
			res = FALSE;
			goto end;
		}
		if ((read (log->fd, idxb,
			sizeof (struct rspamd_index_block))) !=
			sizeof (struct rspamd_index_block)) {
			unlock_file (log->fd, FALSE);
			msg_warn ("cannot read index from file %s, error %d, %s",
				log->filename,
				errno,
				strerror (errno));
			res = FALSE;
			goto end;
		}
		unlock_file (log->fd, FALSE);
	}
	else {
		idxb = log->cur_idx;
	}
	/* Now check specified index */
	idx = &idxb->indexes[from_rev % BINLOG_IDX_LEN];
	if (is_first && idx->time != *from_time) {
		res = FALSE;
		*from_time = 0;
		goto end;
	}
	else {
		*from_time = idx->time;
	}

	/* Now fill reply structure */
	(*rep)->len = idx->len;
	/* Read result */
	msg_info (
		"update from binlog '%s' from revision: %uL to revision %uL size is %uL",
		log->filename,
		from_rev,
		log->cur_seq,
		idx->len);
	if (lseek (log->fd, idx->seek, SEEK_SET) == -1) {
		msg_warn ("cannot seek file %s, error %d, %s",
			log->filename,
			errno,
			strerror (errno));
		res = FALSE;
		goto end;
	}

	(*rep)->data = g_malloc (idx->len);
	if ((read (log->fd, (*rep)->data, idx->len)) != (ssize_t)idx->len) {
		msg_warn ("cannot read file %s, error %d, %s",
			log->filename,
			errno,
			strerror (errno));
		res = FALSE;
		goto end;
	}

end:
	if (idx_mapped) {
		g_free (idxb);
	}

	return res;
}

static gboolean
maybe_init_static (void)
{
	if (!binlog_opened) {
		binlog_opened = g_hash_table_new (g_direct_hash, g_direct_equal);
		if (!binlog_opened) {
			return FALSE;
		}
	}

	if (!binlog_pool) {
		binlog_pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());
		if (!binlog_pool) {
			return FALSE;
		}
	}

	return TRUE;
}

gboolean
maybe_write_binlog (struct rspamd_classifier_config *ccf,
	struct rspamd_statfile_config *st,
	stat_file_t *file,
	GTree *nodes)
{
	struct rspamd_binlog *log;

	if (ccf == NULL) {
		return FALSE;
	}


	if (st == NULL || nodes == NULL || st->binlog == NULL ||
		st->binlog->affinity != AFFINITY_MASTER) {
		return FALSE;
	}

	if (!maybe_init_static ()) {
		return FALSE;
	}

	if ((log = g_hash_table_lookup (binlog_opened, st)) == NULL) {
		if ((log =
			binlog_open (binlog_pool, st->path, st->binlog->rotate_time,
			st->binlog->rotate_time / 2)) != NULL) {
			g_hash_table_insert (binlog_opened, st, log);
		}
		else {
			return FALSE;
		}
	}

	if (binlog_insert (log, nodes)) {
		msg_info ("set new revision of statfile %s: %uL",
			st->symbol,
			log->cur_seq);
		(void)statfile_set_revision (file, log->cur_seq, log->cur_time);
		return TRUE;
	}

	return FALSE;
}

struct rspamd_binlog *
get_binlog_by_statfile (struct rspamd_statfile_config *st)
{
	struct rspamd_binlog *log;

	if (st == NULL || st->binlog == NULL || st->binlog->affinity !=
		AFFINITY_MASTER) {
		return NULL;
	}

	if (!maybe_init_static ()) {
		return NULL;
	}

	if ((log = g_hash_table_lookup (binlog_opened, st)) == NULL) {
		if ((log =
			binlog_open (binlog_pool, st->path, st->binlog->rotate_time,
			st->binlog->rotate_time / 2)) != NULL) {
			g_hash_table_insert (binlog_opened, st, log);
		}
		else {
			return NULL;
		}
	}

	return log;
}
