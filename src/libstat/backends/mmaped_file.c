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
#include "stat_internal.h"
#include "main.h"

#define CHAIN_LENGTH 128

/* Section types */
#define STATFILE_SECTION_COMMON 1
#define STATFILE_SECTION_HEADERS 2
#define STATFILE_SECTION_URLS 3
#define STATFILE_SECTION_REGEXP 4

#define DEFAULT_STATFILE_INVALIDATE_TIME 30
#define DEFAULT_STATFILE_INVALIDATE_JITTER 30

#define MMAPED_BACKEND_TYPE "mmap"

/**
 * Common statfile header
 */
struct stat_file_header {
	u_char magic[3];                        /**< magic signature ('r' 's' 'd')      */
	u_char version[2];                      /**< version of statfile				*/
	u_char padding[3];                      /**< padding							*/
	guint64 create_time;                    /**< create time (time_t->guint64)		*/
	guint64 revision;                       /**< revision number					*/
	guint64 rev_time;                       /**< revision time						*/
	guint64 used_blocks;                    /**< used blocks number					*/
	guint64 total_blocks;                   /**< total number of blocks				*/
	u_char unused[239];                     /**< some bytes that can be used in future */
};

/**
 * Section header
 */
struct stat_file_section {
	guint64 code;                           /**< section's code						*/
	guint64 length;                     /**< section's length in blocks			*/
};

/**
 * Block of data in statfile
 */
struct stat_file_block {
	guint32 hash1;                          /**< hash1 (also acts as index)			*/
	guint32 hash2;                          /**< hash2								*/
	double value;                           /**< double value                       */
};

/**
 * Statistic file
 */
struct stat_file {
	struct stat_file_header header;         /**< header								*/
	struct stat_file_section section;       /**< first section						*/
	struct stat_file_block blocks[1];       /**< first block of data				*/
};

/**
 * Common view of statfile object
 */
typedef struct {
#ifdef HAVE_PATH_MAX
	gchar filename[PATH_MAX];               /**< name of file						*/
#else
	gchar filename[MAXPATHLEN];             /**< name of file						*/
#endif
	gint fd;                                    /**< descriptor							*/
	void *map;                              /**< mmaped area						*/
	off_t seek_pos;                         /**< current seek position				*/
	struct stat_file_section cur_section;   /**< current section					*/
	size_t len;                             /**< length of file(in bytes)			*/
	rspamd_mempool_mutex_t *lock;               /**< mutex								*/
	struct rspamd_statfile_config *cf;
} rspamd_mmaped_file_t;

/**
 * Statfiles pool
 */
typedef struct  {
	GHashTable *files;                     /**< hash table of opened files indexed by name	*/
	rspamd_mempool_t *pool;                 /**< memory pool object					*/
	rspamd_mempool_mutex_t *lock;               /**< mutex								*/
	gboolean mlock_ok;                      /**< whether it is possible to use mlock (2) to avoid statfiles unloading */
} rspamd_mmaped_file_ctx;

#define RSPAMD_STATFILE_VERSION {'1', '2'}
#define BACKUP_SUFFIX ".old"

static void rspamd_mmaped_file_set_block_common (
	rspamd_mmaped_file_ctx * pool, rspamd_mmaped_file_t * file,
	guint32 h1, guint32 h2, double value);

rspamd_mmaped_file_t * rspamd_mmaped_file_is_open (
		rspamd_mmaped_file_ctx * pool, struct rspamd_statfile_config *stcf);
rspamd_mmaped_file_t * rspamd_mmaped_file_open (rspamd_mmaped_file_ctx * pool,
		const gchar *filename, size_t size, struct rspamd_statfile_config *stcf);
gint rspamd_mmaped_file_create (rspamd_mmaped_file_ctx * pool,
		const gchar *filename, size_t size, struct rspamd_statfile_config *stcf);

void
rspamd_mmaped_file_lock_file (rspamd_mmaped_file_ctx * pool, rspamd_mmaped_file_t * file)
{
	rspamd_mempool_lock_mutex (file->lock);
}

void
rspamd_mmaped_file_unlock_file (rspamd_mmaped_file_ctx * pool, rspamd_mmaped_file_t * file)
{

	rspamd_mempool_unlock_mutex (file->lock);
}

double
rspamd_mmaped_file_get_block (rspamd_mmaped_file_ctx * pool,
	rspamd_mmaped_file_t * file,
	guint32 h1,
	guint32 h2)
{
	struct stat_file_block *block;
	guint i, blocknum;
	u_char *c;

	if (!file->map) {
		return 0;
	}

	blocknum = h1 % file->cur_section.length;
	c = (u_char *) file->map + file->seek_pos + blocknum *
		sizeof (struct stat_file_block);
	block = (struct stat_file_block *)c;

	for (i = 0; i < CHAIN_LENGTH; i++) {
		if (i + blocknum >= file->cur_section.length) {
			break;
		}
		if (block->hash1 == h1 && block->hash2 == h2) {
			return block->value;
		}
		c += sizeof (struct stat_file_block);
		block = (struct stat_file_block *)c;
	}


	return 0;
}

static void
rspamd_mmaped_file_set_block_common (rspamd_mmaped_file_ctx * pool,
		rspamd_mmaped_file_t * file,
	guint32 h1,
	guint32 h2,
	double value)
{
	struct stat_file_block *block, *to_expire = NULL;
	struct stat_file_header *header;
	guint i, blocknum;
	u_char *c;
	double min = G_MAXDOUBLE;

	if (!file->map) {
		return;
	}

	blocknum = h1 % file->cur_section.length;
	header = (struct stat_file_header *)file->map;
	c = (u_char *) file->map + file->seek_pos + blocknum *
		sizeof (struct stat_file_block);
	block = (struct stat_file_block *)c;

	for (i = 0; i < CHAIN_LENGTH; i++) {
		if (i + blocknum >= file->cur_section.length) {
			/* Need to expire some block in chain */
			msg_info ("chain %ud is full in statfile %s, starting expire",
				blocknum,
				file->filename);
			break;
		}
		/* First try to find block in chain */
		if (block->hash1 == h1 && block->hash2 == h2) {
			block->value = value;
			return;
		}
		/* Check whether we have a free block in chain */
		if (block->hash1 == 0 && block->hash2 == 0) {
			/* Write new block here */
			msg_debug ("found free block %ud in chain %ud, set h1=%ud, h2=%ud",
				i,
				blocknum,
				h1,
				h2);
			block->hash1 = h1;
			block->hash2 = h2;
			block->value = value;
			header->used_blocks++;

			return;
		}

		/* Expire block with minimum value otherwise */
		if (block->value < min) {
			to_expire = block;
			min = block->value;
		}
		c += sizeof (struct stat_file_block);
		block = (struct stat_file_block *)c;
	}

	/* Try expire some block */
	if (to_expire) {
		block = to_expire;
	}
	else {
		/* Expire first block in chain */
		c = (u_char *) file->map + file->seek_pos + blocknum *
			sizeof (struct stat_file_block);
		block = (struct stat_file_block *)c;
	}

	block->hash1 = h1;
	block->hash2 = h2;
	block->value = value;
}

void
rspamd_mmaped_file_set_block (rspamd_mmaped_file_ctx * pool,
	rspamd_mmaped_file_t * file,
	guint32 h1,
	guint32 h2,
	double value)
{
	rspamd_mmaped_file_set_block_common (pool, file, h1, h2, value);
}

rspamd_mmaped_file_t *
rspamd_mmaped_file_is_open (rspamd_mmaped_file_ctx * pool,
		struct rspamd_statfile_config *stcf)
{
	return g_hash_table_lookup (pool->files, stcf);
}



gboolean
rspamd_mmaped_file_set_revision (rspamd_mmaped_file_t *file, guint64 rev, time_t time)
{
	struct stat_file_header *header;

	if (file == NULL || file->map == NULL) {
		return FALSE;
	}

	header = (struct stat_file_header *)file->map;

	header->revision = rev;
	header->rev_time = time;

	return TRUE;
}

gboolean
rspamd_mmaped_file_inc_revision (rspamd_mmaped_file_t *file)
{
	struct stat_file_header *header;

	if (file == NULL || file->map == NULL) {
		return FALSE;
	}

	header = (struct stat_file_header *)file->map;

	header->revision++;

	return TRUE;
}

gboolean
rspamd_mmaped_file_get_revision (rspamd_mmaped_file_t *file, guint64 *rev, time_t *time)
{
	struct stat_file_header *header;

	if (file == NULL || file->map == NULL) {
		return FALSE;
	}

	header = (struct stat_file_header *)file->map;

	if (rev != NULL) {
		*rev = header->revision;
	}
	if (time != NULL) {
		*time = header->rev_time;
	}

	return TRUE;
}

guint64
rspamd_mmaped_file_get_used (rspamd_mmaped_file_t *file)
{
	struct stat_file_header *header;

	if (file == NULL || file->map == NULL) {
		return (guint64) - 1;
	}

	header = (struct stat_file_header *)file->map;

	return header->used_blocks;
}

guint64
rspamd_mmaped_file_get_total (rspamd_mmaped_file_t *file)
{
	struct stat_file_header *header;

	if (file == NULL || file->map == NULL) {
		return (guint64) - 1;
	}

	header = (struct stat_file_header *)file->map;

	/* If total blocks is 0 we have old version of header, so set total blocks correctly */
	if (header->total_blocks == 0) {
		header->total_blocks = file->cur_section.length;
	}

	return header->total_blocks;
}

/* Check whether specified file is statistic file and calculate its len in blocks */
static gint
rspamd_mmaped_file_check (rspamd_mmaped_file_t * file)
{
	struct stat_file *f;
	gchar *c;
	static gchar valid_version[] = RSPAMD_STATFILE_VERSION;


	if (!file || !file->map) {
		return -1;
	}

	if (file->len < sizeof (struct stat_file)) {
		msg_info ("file %s is too short to be stat file: %z",
			file->filename,
			file->len);
		return -1;
	}

	f = (struct stat_file *)file->map;
	c = f->header.magic;
	/* Check magic and version */
	if (*c++ != 'r' || *c++ != 's' || *c++ != 'd') {
		msg_info ("file %s is invalid stat file", file->filename);
		return -1;
	}
	/* Now check version and convert old version to new one (that can be used for sync */
	if (*c == 1 && *(c + 1) == 0) {
		return -1;
	}
	else if (memcmp (c, valid_version, sizeof (valid_version)) != 0) {
		/* Unknown version */
		msg_info ("file %s has invalid version %c.%c",
			file->filename,
			'0' + *c,
			'0' + *(c + 1));
		return -1;
	}

	/* Check first section and set new offset */
	file->cur_section.code = f->section.code;
	file->cur_section.length = f->section.length;
	if (file->cur_section.length * sizeof (struct stat_file_block) >
		file->len) {
		msg_info ("file %s is truncated: %z, must be %z",
			file->filename,
			file->len,
			file->cur_section.length * sizeof (struct stat_file_block));
		return -1;
	}
	file->seek_pos = sizeof (struct stat_file) -
		sizeof (struct stat_file_block);

	return 0;
}


static rspamd_mmaped_file_t *
rspamd_mmaped_file_reindex (rspamd_mmaped_file_ctx * pool,
	const gchar *filename,
	size_t old_size,
	size_t size,
	struct rspamd_statfile_config *stcf)
{
	gchar *backup;
	gint fd;
	rspamd_mmaped_file_t *new;
	u_char *map, *pos;
	struct stat_file_block *block;
	struct stat_file_header *header;

	if (size <
		sizeof (struct stat_file_header) + sizeof (struct stat_file_section) +
		sizeof (block)) {
		msg_err ("file %s is too small to carry any statistic: %z",
			filename,
			size);
		return NULL;
	}

	/* First of all rename old file */
	rspamd_mempool_lock_mutex (pool->lock);

	backup = g_strconcat (filename, ".old", NULL);
	if (rename (filename, backup) == -1) {
		msg_err ("cannot rename %s to %s: %s", filename, backup, strerror (
				errno));
		g_free (backup);
		rspamd_mempool_unlock_mutex (pool->lock);
		return NULL;
	}

	rspamd_mempool_unlock_mutex (pool->lock);

	/* Now create new file with required size */
	if (rspamd_mmaped_file_create (pool, filename, size, stcf) != 0) {
		msg_err ("cannot create new file");
		g_free (backup);
		return NULL;
	}
	/* Now open new file and start copying */
	fd = open (backup, O_RDONLY);
	new = rspamd_mmaped_file_open (pool, filename, size, stcf);

	if (fd == -1 || new == NULL) {
		msg_err ("cannot open file: %s", strerror (errno));
		g_free (backup);
		return NULL;
	}

	/* Now start reading blocks from old statfile */
	if ((map =
		mmap (NULL, old_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		msg_err ("cannot mmap file: %s", strerror (errno));
		close (fd);
		g_free (backup);
		return NULL;
	}

	pos = map + (sizeof (struct stat_file) - sizeof (struct stat_file_block));
	while (old_size - (pos - map) >= sizeof (struct stat_file_block)) {
		block = (struct stat_file_block *)pos;
		if (block->hash1 != 0 && block->value != 0) {
			rspamd_mmaped_file_set_block_common (pool,
				new,
				block->hash1,
				block->hash2,
				block->value);
		}
		pos += sizeof (block);
	}

	header = (struct stat_file_header *)map;
	rspamd_mmaped_file_set_revision (new, header->revision, header->rev_time);

	munmap (map, old_size);
	close (fd);
	unlink (backup);
	g_free (backup);

	return new;

}

/*
 * Pre-load mmaped file into memory
 */
static void
rspamd_mmaped_file_preload (rspamd_mmaped_file_t *file)
{
	guint8 *pos, *end;
	volatile guint8 t;
	gsize size;

	pos = (guint8 *)file->map;
	end = (guint8 *)file->map + file->len;

	if (madvise (pos, end - pos, MADV_SEQUENTIAL) == -1) {
		msg_info ("madvise failed: %s", strerror (errno));
	}
	else {
		/* Load pages of file */
#ifdef HAVE_GETPAGESIZE
		size = getpagesize ();
#else
		size = sysconf (_SC_PAGESIZE);
#endif
		while (pos < end) {
			t = *pos;
			(void)t;
			pos += size;
		}
	}
}

rspamd_mmaped_file_t *
rspamd_mmaped_file_open (rspamd_mmaped_file_ctx * pool,
		const gchar *filename, size_t size,
		struct rspamd_statfile_config *stcf)
{
	struct stat st;
	rspamd_mmaped_file_t *new_file;

	if ((new_file = rspamd_mmaped_file_is_open (pool, stcf)) != NULL) {
		return new_file;
	}

	if (stat (filename, &st) == -1) {
		msg_info ("cannot stat file %s, error %s, %d", filename, strerror (
				errno), errno);
		return NULL;
	}

	rspamd_mempool_lock_mutex (pool->lock);
	if (labs (size - st.st_size) > (long)sizeof (struct stat_file) * 2
		&& size > sizeof (struct stat_file)) {
		rspamd_mempool_unlock_mutex (pool->lock);
		msg_warn ("need to reindex statfile old size: %Hz, new size: %Hz",
			(size_t)st.st_size, size);
		return rspamd_mmaped_file_reindex (pool, filename, st.st_size, size, stcf);
	}
	else if (size < sizeof (struct stat_file)) {
		msg_err ("requested to shrink statfile to %Hz but it is too small",
			size);
	}

	new_file = g_slice_alloc0 (sizeof (rspamd_mmaped_file_t));
	if ((new_file->fd = open (filename, O_RDWR)) == -1) {
		msg_info ("cannot open file %s, error %d, %s",
			filename,
			errno,
			strerror (errno));
		rspamd_mempool_unlock_mutex (pool->lock);
		g_slice_free1 (sizeof (*new_file), new_file);
		return NULL;
	}

	if ((new_file->map =
		mmap (NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		new_file->fd, 0)) == MAP_FAILED) {
		close (new_file->fd);
		rspamd_mempool_unlock_mutex (pool->lock);
		msg_info ("cannot mmap file %s, error %d, %s",
			filename,
			errno,
			strerror (errno));
		g_slice_free1 (sizeof (*new_file), new_file);
		return NULL;

	}

	rspamd_strlcpy (new_file->filename, filename, sizeof (new_file->filename));
	new_file->len = st.st_size;
	/* Try to lock pages in RAM */
	if (pool->mlock_ok) {
		if (mlock (new_file->map, new_file->len) == -1) {
			msg_warn (
				"mlock of statfile failed, maybe you need to increase RLIMIT_MEMLOCK limit for a process: %s",
				strerror (errno));
			pool->mlock_ok = FALSE;
		}
	}
	/* Acquire lock for this operation */
	rspamd_file_lock (new_file->fd, FALSE);
	if (rspamd_mmaped_file_check (new_file) == -1) {
		rspamd_mempool_unlock_mutex (pool->lock);
		rspamd_file_unlock (new_file->fd, FALSE);
		munmap (new_file->map, st.st_size);
		g_slice_free1 (sizeof (*new_file), new_file);
		return NULL;
	}
	rspamd_file_unlock (new_file->fd, FALSE);

	new_file->lock = rspamd_mempool_get_mutex (pool->pool);
	new_file->cf = stcf;

	rspamd_mmaped_file_preload (new_file);

	g_hash_table_insert (pool->files, stcf, new_file);

	rspamd_mempool_unlock_mutex (pool->lock);

	return rspamd_mmaped_file_is_open (pool, stcf);
}

gint
rspamd_mmaped_file_close (rspamd_mmaped_file_ctx * pool,
	rspamd_mmaped_file_t * file)
{
	rspamd_mmaped_file_t *pos;

	if ((pos = rspamd_mmaped_file_is_open (pool, file->cf)) == NULL) {
		msg_info ("file %s is not opened", file->filename);
		return -1;
	}

	rspamd_mempool_lock_mutex (pool->lock);

	if (file->map) {
		msg_info ("syncing statfile %s", file->filename);
		msync (file->map, file->len, MS_ASYNC);
		munmap (file->map, file->len);
	}
	if (file->fd != -1) {
		close (file->fd);
	}

	g_hash_table_remove (pool->files, file->cf);

	g_slice_free1 (sizeof (*file), file);

	rspamd_mempool_unlock_mutex (pool->lock);

	return 0;
}

gint
rspamd_mmaped_file_create (rspamd_mmaped_file_ctx * pool, const gchar *filename,
		size_t size, struct rspamd_statfile_config *stcf)
{
	struct stat_file_header header = {
		.magic = {'r', 's', 'd'},
		.version = RSPAMD_STATFILE_VERSION,
		.padding = {0, 0, 0},
		.revision = 0,
		.rev_time = 0,
		.used_blocks = 0
	};
	struct stat_file_section section = {
		.code = STATFILE_SECTION_COMMON,
	};
	struct stat_file_block block = { 0, 0, 0 };
	gint fd;
	guint buflen = 0, nblocks;
	gchar *buf = NULL;

	if (rspamd_mmaped_file_is_open (pool, stcf) != NULL) {
		msg_info ("file %s is already opened", filename);
		return 0;
	}

	if (size <
		sizeof (struct stat_file_header) + sizeof (struct stat_file_section) +
		sizeof (block)) {
		msg_err ("file %s is too small to carry any statistic: %z",
			filename,
			size);
		return -1;
	}

	rspamd_mempool_lock_mutex (pool->lock);
	nblocks =
		(size - sizeof (struct stat_file_header) -
		sizeof (struct stat_file_section)) / sizeof (struct stat_file_block);
	header.total_blocks = nblocks;

	if ((fd =
		open (filename, O_RDWR | O_TRUNC | O_CREAT, S_IWUSR | S_IRUSR)) == -1) {
		msg_info ("cannot create file %s, error %d, %s",
			filename,
			errno,
			strerror (errno));
		rspamd_mempool_unlock_mutex (pool->lock);
		return -1;
	}

	rspamd_fallocate (fd,
		0,
		sizeof (header) + sizeof (section) + sizeof (block) * nblocks);

	header.create_time = (guint64) time (NULL);
	if (write (fd, &header, sizeof (header)) == -1) {
		msg_info ("cannot write header to file %s, error %d, %s",
			filename,
			errno,
			strerror (errno));
		close (fd);
		rspamd_mempool_unlock_mutex (pool->lock);
		return -1;
	}

	section.length = (guint64) nblocks;
	if (write (fd, &section, sizeof (section)) == -1) {
		msg_info ("cannot write section header to file %s, error %d, %s",
			filename,
			errno,
			strerror (errno));
		close (fd);
		rspamd_mempool_unlock_mutex (pool->lock);
		return -1;
	}

	/* Buffer for write 256 blocks at once */
	if (nblocks > 256) {
		buflen = sizeof (block) * 256;
		buf = g_malloc0 (buflen);
	}

	while (nblocks) {
		if (nblocks > 256) {
			/* Just write buffer */
			if (write (fd, buf, buflen) == -1) {
				msg_info ("cannot write blocks buffer to file %s, error %d, %s",
					filename,
					errno,
					strerror (errno));
				close (fd);
				rspamd_mempool_unlock_mutex (pool->lock);
				g_free (buf);
				return -1;
			}
			nblocks -= 256;
		}
		else {
			if (write (fd, &block, sizeof (block)) == -1) {
				msg_info ("cannot write block to file %s, error %d, %s",
					filename,
					errno,
					strerror (errno));
				close (fd);
				if (buf) {
					g_free (buf);
				}
				rspamd_mempool_unlock_mutex (pool->lock);
				return -1;
			}
			nblocks--;
		}
	}

	close (fd);
	rspamd_mempool_unlock_mutex (pool->lock);

	if (buf) {
		g_free (buf);
	}

	return 0;
}

void
rspamd_mmaped_file_destroy (rspamd_mmaped_file_ctx * pool)
{
	GHashTableIter it;
	gpointer k, v;
	rspamd_mmaped_file_t *f;

	g_hash_table_iter_init (&it, pool->files);
	while (g_hash_table_iter_next (&it, &k, &v)) {
		f = (rspamd_mmaped_file_t *)v;
		rspamd_mmaped_file_close (pool, f);
	}

	g_hash_table_destroy (pool->files);
	rspamd_mempool_delete (pool->pool);
}

gpointer
rspamd_mmaped_file_init (struct rspamd_stat_ctx *ctx, struct rspamd_config *cfg)
{
	rspamd_mmaped_file_ctx *new;
	struct rspamd_classifier_config *clf;
	struct rspamd_statfile_config *stf;
	GList *cur, *curst;
	const ucl_object_t *filenameo, *sizeo;
	const gchar *filename;
	gsize size;

	new = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (rspamd_mmaped_file_ctx));
	new->lock = rspamd_mempool_get_mutex (new->pool);
	new->mlock_ok = cfg->mlock_statfile_pool;
	new->files = g_hash_table_new (g_direct_hash, g_direct_equal);

	/* Iterate over all classifiers and load matching statfiles */
	cur = cfg->classifiers;

	while (cur) {
		clf = cur->data;

		curst = clf->statfiles;
		while (curst) {
			stf = cur->data;

			/*
			 * By default, all statfiles are treated as mmaped files
			 */
			if (stf->backend == NULL ||
					strcmp (stf->backend, MMAPED_BACKEND_TYPE)) {
				/*
				 * Check configuration sanity
				 */
				filenameo = ucl_object_find_key (stf->opts, "filename");
				if (filenameo == NULL || ucl_object_type (filenameo) != UCL_STRING) {
					msg_err ("statfile %s has no filename defined", stf->symbol);
					return NULL;
				}

				filename = ucl_object_tostring (filenameo);

				sizeo = ucl_object_find_key (stf->opts, "size");
				if (sizeo == NULL || ucl_object_type (sizeo) != UCL_INT) {
					msg_err ("statfile %s has no size defined", stf->symbol);
					return NULL;
				}

				size = ucl_object_toint (sizeo);

				rspamd_mmaped_file_open (new, filename, size, stf);

				ctx->statfiles ++;
			}

			curst = curst->next;
		}

		cur = g_list_next (cur);
	}

	return (gpointer)new;
}

gpointer
rspamd_mmaped_file_runtime (struct rspamd_statfile_config *stcf, gboolean learn,
		gpointer p)
{
	rspamd_mmaped_file_ctx *ctx = (rspamd_mmaped_file_ctx *)p;
	rspamd_mmaped_file_t *mf;
	const ucl_object_t *filenameo, *sizeo;
	const gchar *filename;
	gsize size;

	g_assert (ctx != NULL);

	mf = rspamd_mmaped_file_is_open (ctx, stcf);

	if (mf == NULL && learn) {
		/* Create file here */

		filenameo = ucl_object_find_key (stcf->opts, "filename");
		if (filenameo == NULL || ucl_object_type (filenameo) != UCL_STRING) {
			msg_err ("statfile %s has no filename defined", stcf->symbol);
			return NULL;
		}

		filename = ucl_object_tostring (filenameo);

		sizeo = ucl_object_find_key (stcf->opts, "size");
		if (sizeo == NULL || ucl_object_type (sizeo) != UCL_INT) {
			msg_err ("statfile %s has no size defined", stcf->symbol);
			return NULL;
		}

		size = ucl_object_toint (sizeo);
		rspamd_mmaped_file_create (ctx, filename, size, stcf);

		mf = rspamd_mmaped_file_open (ctx, filename, size, stcf);
	}

	return (gpointer)mf;
}

gboolean
rspamd_mmaped_file_process_token (rspamd_token_t *tok,
		struct rspamd_token_result *res,
		gpointer p)
{
	rspamd_mmaped_file_ctx *ctx = (rspamd_mmaped_file_ctx *)p;
	rspamd_mmaped_file_t *mf;
	guint32 h1, h2;

	g_assert (res != NULL);
	g_assert (p != NULL);
	g_assert (res->st_runtime != NULL);
	g_assert (tok != NULL);
	g_assert (tok->datalen >= sizeof (guint32) * 2);

	mf = (rspamd_mmaped_file_t *)res->st_runtime->backend_runtime;

	if (mf == NULL) {
		/* Statfile is does not exist, so all values are zero */
		res->value = 0.0;
		return FALSE;
	}

	memcpy (&h1, tok->data, sizeof (h1));
	memcpy (&h2, tok->data + sizeof (h1), sizeof (h2));
	res->value = rspamd_mmaped_file_get_block (ctx, mf, h1, h2);

	if (res->value > 0.0) {
		return TRUE;
	}

	return FALSE;
}

gboolean
rspamd_mmaped_file_learn_token (rspamd_token_t *tok,
		struct rspamd_token_result *res,
		gpointer p)
{
	rspamd_mmaped_file_ctx *ctx = (rspamd_mmaped_file_ctx *)p;
	rspamd_mmaped_file_t *mf;
	guint32 h1, h2;

	g_assert (res != NULL);
	g_assert (p != NULL);
	g_assert (res->st_runtime != NULL);
	g_assert (tok != NULL);
	g_assert (tok->datalen >= sizeof (guint32) * 2);

	mf = (rspamd_mmaped_file_t *)res->st_runtime->backend_runtime;

	if (mf == NULL) {
		/* Statfile is does not exist, so all values are zero */
		res->value = 0.0;
		return FALSE;
	}

	memcpy (&h1, tok->data, sizeof (h1));
	memcpy (&h2, tok->data + sizeof (h1), sizeof (h2));
	rspamd_mmaped_file_set_block (ctx, mf, h1, h2, res->value);

	if (res->value > 0.0) {
		return TRUE;
	}

	return FALSE;
}

gulong
rspamd_mmaped_file_total_learns (struct rspamd_statfile_runtime *runtime,
		gpointer ctx)
{
	rspamd_mmaped_file_t *mf = (rspamd_mmaped_file_t *)runtime;
	guint64 rev = 0;
	time_t t;

	if (mf != NULL) {
		rspamd_mmaped_file_get_revision (mf, &rev, &t);
	}

	return rev;
}
