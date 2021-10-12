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
#include "stat_internal.h"
#include "unix-std.h"

#define CHAIN_LENGTH 128

/* Section types */
#define STATFILE_SECTION_COMMON 1

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
	guint64 tokenizer_conf_len;				/**< length of tokenizer configuration	*/
	u_char unused[231];                     /**< some bytes that can be used in future */
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
	rspamd_mempool_t *pool;
	gint fd;                                /**< descriptor							*/
	void *map;                              /**< mmaped area						*/
	off_t seek_pos;                         /**< current seek position				*/
	struct stat_file_section cur_section;   /**< current section					*/
	size_t len;                             /**< length of file(in bytes)			*/
	struct rspamd_statfile_config *cf;
} rspamd_mmaped_file_t;


#define RSPAMD_STATFILE_VERSION {'1', '2'}
#define BACKUP_SUFFIX ".old"

static void rspamd_mmaped_file_set_block_common (rspamd_mempool_t *pool,
	   rspamd_mmaped_file_t *file,
	   guint32 h1, guint32 h2, double value);

rspamd_mmaped_file_t * rspamd_mmaped_file_open (rspamd_mempool_t *pool,
		const gchar *filename, size_t size,
		struct rspamd_statfile_config *stcf);
gint rspamd_mmaped_file_create (const gchar *filename, size_t size,
		struct rspamd_statfile_config *stcf,
		rspamd_mempool_t *pool);
gint rspamd_mmaped_file_close_file (rspamd_mempool_t *pool,
		rspamd_mmaped_file_t * file);

double
rspamd_mmaped_file_get_block (rspamd_mmaped_file_t * file,
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
rspamd_mmaped_file_set_block_common (rspamd_mempool_t *pool,
		rspamd_mmaped_file_t *file,
		guint32 h1, guint32 h2, double value)
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
			msg_info_pool ("chain %ud is full in statfile %s, starting expire",
				blocknum,
				file->filename);
			break;
		}
		/* First try to find block in chain */
		if (block->hash1 == h1 && block->hash2 == h2) {
			msg_debug_pool ("%s found existing block %ud in chain %ud, value %.2f",
					file->filename,
					i,
					blocknum,
					value);
			block->value = value;
			return;
		}
		/* Check whether we have a free block in chain */
		if (block->hash1 == 0 && block->hash2 == 0) {
			/* Write new block here */
			msg_debug_pool ("%s found free block %ud in chain %ud, set h1=%ud, h2=%ud",
				file->filename,
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
rspamd_mmaped_file_set_block (rspamd_mempool_t *pool,
		rspamd_mmaped_file_t * file,
		guint32 h1,
		guint32 h2,
		double value)
{
	rspamd_mmaped_file_set_block_common (pool, file, h1, h2, value);
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
rspamd_mmaped_file_dec_revision (rspamd_mmaped_file_t *file)
{
	struct stat_file_header *header;

	if (file == NULL || file->map == NULL) {
		return FALSE;
	}

	header = (struct stat_file_header *)file->map;

	header->revision--;

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
rspamd_mmaped_file_check (rspamd_mempool_t *pool, rspamd_mmaped_file_t * file)
{
	struct stat_file *f;
	gchar *c;
	static gchar valid_version[] = RSPAMD_STATFILE_VERSION;


	if (!file || !file->map) {
		return -1;
	}

	if (file->len < sizeof (struct stat_file)) {
		msg_info_pool ("file %s is too short to be stat file: %z",
			file->filename,
			file->len);
		return -1;
	}

	f = (struct stat_file *)file->map;
	c = &f->header.magic[0];
	/* Check magic and version */
	if (*c++ != 'r' || *c++ != 's' || *c++ != 'd') {
		msg_info_pool ("file %s is invalid stat file", file->filename);
		return -1;
	}

	c = &f->header.version[0];
	/* Now check version and convert old version to new one (that can be used for sync */
	if (*c == 1 && *(c + 1) == 0) {
		return -1;
	}
	else if (memcmp (c, valid_version, sizeof (valid_version)) != 0) {
		/* Unknown version */
		msg_info_pool ("file %s has invalid version %c.%c",
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
		msg_info_pool ("file %s is truncated: %z, must be %z",
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
rspamd_mmaped_file_reindex (rspamd_mempool_t *pool,
		const gchar *filename,
		size_t old_size,
		size_t size,
		struct rspamd_statfile_config *stcf)
{
	gchar *backup, *lock;
	gint fd, lock_fd;
	rspamd_mmaped_file_t *new, *old = NULL;
	u_char *map, *pos;
	struct stat_file_block *block;
	struct stat_file_header *header, *nh;
	struct timespec sleep_ts = {
			.tv_sec = 0,
			.tv_nsec = 1000000
	};

	if (size <
		sizeof (struct stat_file_header) + sizeof (struct stat_file_section) +
		sizeof (block)) {
		msg_err_pool ("file %s is too small to carry any statistic: %z",
			filename,
			size);
		return NULL;
	}

	lock = g_strconcat (filename, ".lock", NULL);
	lock_fd = open (lock, O_WRONLY|O_CREAT|O_EXCL, 00600);

	while (lock_fd == -1) {
		/* Wait for lock */
		lock_fd = open (lock, O_WRONLY|O_CREAT|O_EXCL, 00600);
		if (lock_fd != -1) {
			unlink (lock);
			close (lock_fd);
			g_free (lock);

			return rspamd_mmaped_file_open (pool, filename, size, stcf);
		}
		else {
			nanosleep (&sleep_ts, NULL);
		}
	}

	backup = g_strconcat (filename, ".old", NULL);
	if (rename (filename, backup) == -1) {
		msg_err_pool ("cannot rename %s to %s: %s", filename, backup, strerror (
				errno));
		g_free (backup);
		unlink (lock);
		g_free (lock);
		close (lock_fd);

		return NULL;
	}

	old = rspamd_mmaped_file_open (pool, backup, old_size, stcf);

	if (old == NULL) {
		msg_warn_pool ("old file %s is invalid mmapped file, just move it",
				backup);
	}

	/* We need to release our lock here */
	unlink (lock);
	close (lock_fd);
	g_free (lock);

	/* Now create new file with required size */
	if (rspamd_mmaped_file_create (filename, size, stcf, pool) != 0) {
		msg_err_pool ("cannot create new file");
		rspamd_mmaped_file_close (old);
		g_free (backup);

		return NULL;
	}

	new = rspamd_mmaped_file_open (pool, filename, size, stcf);

	if (old) {
		/* Now open new file and start copying */
		fd = open (backup, O_RDONLY);
		if (fd == -1 || new == NULL) {
			if (fd != -1) {
				close (fd);
			}

			msg_err_pool ("cannot open file: %s", strerror (errno));
			rspamd_mmaped_file_close (old);
			g_free (backup);
			return NULL;
		}



		/* Now start reading blocks from old statfile */
		if ((map =
				mmap (NULL, old_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
			msg_err_pool ("cannot mmap file: %s", strerror (errno));
			close (fd);
			rspamd_mmaped_file_close (old);
			g_free (backup);
			return NULL;
		}

		pos = map + (sizeof (struct stat_file) - sizeof (struct stat_file_block));

		if (pos - map < (gssize)old_size) {
			while ((gssize)old_size - (pos - map) >= (gssize)sizeof (struct stat_file_block)) {
				block = (struct stat_file_block *)pos;
				if (block->hash1 != 0 && block->value != 0) {
					rspamd_mmaped_file_set_block_common (pool,
							new, block->hash1,
							block->hash2, block->value);
				}
				pos += sizeof (block);
			}
		}

		header = (struct stat_file_header *)map;
		rspamd_mmaped_file_set_revision (new, header->revision, header->rev_time);
		nh = new->map;
		/* Copy tokenizer configuration */
		memcpy (nh->unused, header->unused, sizeof (header->unused));
		nh->tokenizer_conf_len = header->tokenizer_conf_len;

		munmap (map, old_size);
		close (fd);
		rspamd_mmaped_file_close_file (pool, old);
	}

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
rspamd_mmaped_file_open (rspamd_mempool_t *pool,
		const gchar *filename, size_t size,
		struct rspamd_statfile_config *stcf)
{
	struct stat st;
	rspamd_mmaped_file_t *new_file;
	gchar *lock;
	gint lock_fd;

	lock = g_strconcat (filename, ".lock", NULL);
	lock_fd = open (lock, O_WRONLY|O_CREAT|O_EXCL, 00600);

	if (lock_fd == -1) {
		g_free (lock);
		msg_info_pool ("cannot open file %s, it is locked by another process",
				filename);
		return NULL;
	}

	close (lock_fd);
	unlink (lock);
	g_free (lock);

	if (stat (filename, &st) == -1) {
		msg_info_pool ("cannot stat file %s, error %s, %d", filename, strerror (
				errno), errno);
		return NULL;
	}

	if (labs ((glong)size - st.st_size) > (long)sizeof (struct stat_file) * 2
		&& size > sizeof (struct stat_file)) {
		msg_warn_pool ("need to reindex statfile old size: %Hz, new size: %Hz",
			(size_t)st.st_size, size);
		return rspamd_mmaped_file_reindex (pool, filename, st.st_size, size, stcf);
	}
	else if (size < sizeof (struct stat_file)) {
		msg_err_pool ("requested to shrink statfile to %Hz but it is too small",
			size);
	}

	new_file = g_malloc0 (sizeof (rspamd_mmaped_file_t));
	if ((new_file->fd = open (filename, O_RDWR)) == -1) {
		msg_info_pool ("cannot open file %s, error %d, %s",
			filename,
			errno,
			strerror (errno));
		g_free (new_file);
		return NULL;
	}

	if ((new_file->map =
		mmap (NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		new_file->fd, 0)) == MAP_FAILED) {
		close (new_file->fd);
		msg_info_pool ("cannot mmap file %s, error %d, %s",
			filename,
			errno,
			strerror (errno));
		g_free (new_file);
		return NULL;

	}

	rspamd_strlcpy (new_file->filename, filename, sizeof (new_file->filename));
	new_file->len = st.st_size;
	/* Try to lock pages in RAM */

	/* Acquire lock for this operation */
	if (!rspamd_file_lock (new_file->fd, FALSE)) {
		close (new_file->fd);
		munmap (new_file->map, st.st_size);
		msg_info_pool ("cannot lock file %s, error %d, %s",
				filename,
				errno,
				strerror (errno));
		g_free (new_file);
		return NULL;
	}

	if (rspamd_mmaped_file_check (pool, new_file) == -1) {
		close (new_file->fd);
		rspamd_file_unlock (new_file->fd, FALSE);
		munmap (new_file->map, st.st_size);
		g_free (new_file);
		return NULL;
	}

	rspamd_file_unlock (new_file->fd, FALSE);
	new_file->cf = stcf;
	new_file->pool = pool;
	rspamd_mmaped_file_preload (new_file);

	g_assert (stcf->clcf != NULL);

	msg_debug_pool ("opened statfile %s of size %l", filename, (long)size);

	return new_file;
}

gint
rspamd_mmaped_file_close_file (rspamd_mempool_t *pool,
	rspamd_mmaped_file_t * file)
{
	if (file->map) {
		msg_info_pool ("syncing statfile %s", file->filename);
		msync (file->map, file->len, MS_ASYNC);
		munmap (file->map, file->len);
	}
	if (file->fd != -1) {
		close (file->fd);
	}

	g_free (file);

	return 0;
}

gint
rspamd_mmaped_file_create (const gchar *filename,
		size_t size,
		struct rspamd_statfile_config *stcf,
		rspamd_mempool_t *pool)
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
	struct rspamd_stat_tokenizer *tokenizer;
	gint fd, lock_fd;
	guint buflen = 0, nblocks;
	gchar *buf = NULL, *lock;
	struct stat sb;
	gpointer tok_conf;
	gsize tok_conf_len;
	struct timespec sleep_ts = {
			.tv_sec = 0,
			.tv_nsec = 1000000
	};

	if (size <
		sizeof (struct stat_file_header) + sizeof (struct stat_file_section) +
		sizeof (block)) {
		msg_err_pool ("file %s is too small to carry any statistic: %z",
			filename,
			size);
		return -1;
	}

	lock = g_strconcat (filename, ".lock", NULL);
	lock_fd = open (lock, O_WRONLY|O_CREAT|O_EXCL, 00600);

	while (lock_fd == -1) {
		/* Wait for lock */
		lock_fd = open (lock, O_WRONLY|O_CREAT|O_EXCL, 00600);
		if (lock_fd != -1) {
			if (stat (filename, &sb) != -1) {
				/* File has been created by some other process */
				unlink (lock);
				close (lock_fd);
				g_free (lock);

				return 0;
			}

			/* We still need to create it */
			goto create;
		}
		else {
			nanosleep (&sleep_ts, NULL);
		}
	}

create:

	msg_debug_pool ("create statfile %s of size %l", filename, (long)size);
	nblocks =
		(size - sizeof (struct stat_file_header) -
		sizeof (struct stat_file_section)) / sizeof (struct stat_file_block);
	header.total_blocks = nblocks;

	if ((fd =
		open (filename, O_RDWR | O_TRUNC | O_CREAT, S_IWUSR | S_IRUSR)) == -1) {
		msg_info_pool ("cannot create file %s, error %d, %s",
			filename,
			errno,
			strerror (errno));
		unlink (lock);
		close (lock_fd);
		g_free (lock);

		return -1;
	}

	rspamd_fallocate (fd,
		0,
		sizeof (header) + sizeof (section) + sizeof (block) * nblocks);

	header.create_time = (guint64) time (NULL);
	g_assert (stcf->clcf != NULL);
	g_assert (stcf->clcf->tokenizer != NULL);
	tokenizer = rspamd_stat_get_tokenizer (stcf->clcf->tokenizer->name);
	g_assert (tokenizer != NULL);
	tok_conf = tokenizer->get_config (pool, stcf->clcf->tokenizer, &tok_conf_len);
	header.tokenizer_conf_len = tok_conf_len;
	g_assert (tok_conf_len < sizeof (header.unused) - sizeof (guint64));
	memcpy (header.unused, tok_conf, tok_conf_len);

	if (write (fd, &header, sizeof (header)) == -1) {
		msg_info_pool ("cannot write header to file %s, error %d, %s",
			filename,
			errno,
			strerror (errno));
		close (fd);
		unlink (lock);
		close (lock_fd);
		g_free (lock);

		return -1;
	}

	section.length = (guint64) nblocks;
	if (write (fd, &section, sizeof (section)) == -1) {
		msg_info_pool ("cannot write section header to file %s, error %d, %s",
			filename,
			errno,
			strerror (errno));
		close (fd);
		unlink (lock);
		close (lock_fd);
		g_free (lock);

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
				msg_info_pool ("cannot write blocks buffer to file %s, error %d, %s",
					filename,
					errno,
					strerror (errno));
				close (fd);
				g_free (buf);
				unlink (lock);
				close (lock_fd);
				g_free (lock);

				return -1;
			}
			nblocks -= 256;
		}
		else {
			if (write (fd, &block, sizeof (block)) == -1) {
				msg_info_pool ("cannot write block to file %s, error %d, %s",
					filename,
					errno,
					strerror (errno));
				close (fd);
				if (buf) {
					g_free (buf);
				}

				unlink (lock);
				close (lock_fd);
				g_free (lock);

				return -1;
			}
			nblocks--;
		}
	}

	close (fd);

	if (buf) {
		g_free (buf);
	}

	unlink (lock);
	close (lock_fd);
	g_free (lock);
	msg_debug_pool ("created statfile %s of size %l", filename, (long)size);

	return 0;
}

gpointer
rspamd_mmaped_file_init (struct rspamd_stat_ctx *ctx,
		struct rspamd_config *cfg, struct rspamd_statfile *st)
{
	struct rspamd_statfile_config *stf = st->stcf;
	rspamd_mmaped_file_t *mf;
	const ucl_object_t *filenameo, *sizeo;
	const gchar *filename;
	gsize size;

	filenameo = ucl_object_lookup (stf->opts, "filename");

	if (filenameo == NULL || ucl_object_type (filenameo) != UCL_STRING) {
		filenameo = ucl_object_lookup (stf->opts, "path");

		if (filenameo == NULL || ucl_object_type (filenameo) != UCL_STRING) {
			msg_err_config ("statfile %s has no filename defined", stf->symbol);
			return NULL;
		}
	}

	filename = ucl_object_tostring (filenameo);

	sizeo = ucl_object_lookup (stf->opts, "size");

	if (sizeo == NULL || ucl_object_type (sizeo) != UCL_INT) {
		msg_err_config ("statfile %s has no size defined", stf->symbol);
		return NULL;
	}

	size = ucl_object_toint (sizeo);
	mf = rspamd_mmaped_file_open (cfg->cfg_pool, filename, size, stf);

	if (mf != NULL) {
		mf->pool = cfg->cfg_pool;
	} else {
		/* Create file here */

		filenameo = ucl_object_find_key (stf->opts, "filename");
		if (filenameo == NULL || ucl_object_type (filenameo) != UCL_STRING) {
			filenameo = ucl_object_find_key (stf->opts, "path");
			if (filenameo == NULL || ucl_object_type (filenameo) != UCL_STRING) {
				msg_err_config ("statfile %s has no filename defined", stf->symbol);
				return NULL;
			}
		}

		filename = ucl_object_tostring (filenameo);

		sizeo = ucl_object_find_key (stf->opts, "size");
		if (sizeo == NULL || ucl_object_type (sizeo) != UCL_INT) {
			msg_err_config ("statfile %s has no size defined", stf->symbol);
			return NULL;
		}

		size = ucl_object_toint (sizeo);

		if (rspamd_mmaped_file_create (filename, size, stf, cfg->cfg_pool) != 0) {
			msg_err_config ("cannot create new file");
		}

		mf = rspamd_mmaped_file_open (cfg->cfg_pool, filename, size, stf);
	}

	return (gpointer)mf;
}

void
rspamd_mmaped_file_close (gpointer p)
{
	rspamd_mmaped_file_t *mf = p;


	if (mf) {
		rspamd_mmaped_file_close_file (mf->pool, mf);
	}

}

gpointer
rspamd_mmaped_file_runtime (struct rspamd_task *task,
		struct rspamd_statfile_config *stcf,
		gboolean learn,
		gpointer p)
{
	rspamd_mmaped_file_t *mf = p;

	return (gpointer)mf;
}

gboolean
rspamd_mmaped_file_process_tokens (struct rspamd_task *task, GPtrArray *tokens,
		gint id,
		gpointer p)
{
	rspamd_mmaped_file_t *mf = p;
	guint32 h1, h2;
	rspamd_token_t *tok;
	guint i;

	g_assert (tokens != NULL);
	g_assert (p != NULL);

	for (i = 0; i < tokens->len; i++) {
		tok = g_ptr_array_index (tokens, i);
		memcpy (&h1, (guchar *)&tok->data, sizeof (h1));
		memcpy (&h2, ((guchar *)&tok->data) + sizeof (h1), sizeof (h2));
		tok->values[id] = rspamd_mmaped_file_get_block (mf, h1, h2);
	}

	if (mf->cf->is_spam) {
		task->flags |= RSPAMD_TASK_FLAG_HAS_SPAM_TOKENS;
	}
	else {
		task->flags |= RSPAMD_TASK_FLAG_HAS_HAM_TOKENS;
	}

	return TRUE;
}

gboolean
rspamd_mmaped_file_learn_tokens (struct rspamd_task *task, GPtrArray *tokens,
		gint id,
		gpointer p)
{
	rspamd_mmaped_file_t *mf = p;
	guint32 h1, h2;
	rspamd_token_t *tok;
	guint i;

	g_assert (tokens != NULL);
	g_assert (p != NULL);

	for (i = 0; i < tokens->len; i++) {
		tok = g_ptr_array_index (tokens, i);
		memcpy (&h1, (guchar *)&tok->data, sizeof (h1));
		memcpy (&h2, ((guchar *)&tok->data) + sizeof (h1), sizeof (h2));
		rspamd_mmaped_file_set_block (task->task_pool, mf, h1, h2,
				tok->values[id]);
	}

	return TRUE;
}

gulong
rspamd_mmaped_file_total_learns (struct rspamd_task *task, gpointer runtime,
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

gulong
rspamd_mmaped_file_inc_learns (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	rspamd_mmaped_file_t *mf = (rspamd_mmaped_file_t *)runtime;
	guint64 rev = 0;
	time_t t;

	if (mf != NULL) {
		rspamd_mmaped_file_inc_revision (mf);
		rspamd_mmaped_file_get_revision (mf, &rev, &t);
	}

	return rev;
}

gulong
rspamd_mmaped_file_dec_learns (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	rspamd_mmaped_file_t *mf = (rspamd_mmaped_file_t *)runtime;
	guint64 rev = 0;
	time_t t;

	if (mf != NULL) {
		rspamd_mmaped_file_dec_revision (mf);
		rspamd_mmaped_file_get_revision (mf, &rev, &t);
	}

	return rev;
}


ucl_object_t *
rspamd_mmaped_file_get_stat (gpointer runtime,
		gpointer ctx)
{
	ucl_object_t *res = NULL;
	guint64 rev;
	rspamd_mmaped_file_t *mf = (rspamd_mmaped_file_t *)runtime;

	if (mf != NULL) {
		res = ucl_object_typed_new (UCL_OBJECT);
		rspamd_mmaped_file_get_revision (mf, &rev, NULL);
		ucl_object_insert_key (res, ucl_object_fromint (rev), "revision",
				0, false);
		ucl_object_insert_key (res, ucl_object_fromint (mf->len), "size",
				0, false);
		ucl_object_insert_key (res, ucl_object_fromint (
				rspamd_mmaped_file_get_total (mf)), "total",  0, false);
		ucl_object_insert_key (res, ucl_object_fromint (
				rspamd_mmaped_file_get_used (mf)), "used", 0, false);
		ucl_object_insert_key (res, ucl_object_fromstring (mf->cf->symbol),
				"symbol", 0, false);
		ucl_object_insert_key (res, ucl_object_fromstring ("mmap"),
				"type", 0, false);
		ucl_object_insert_key (res, ucl_object_fromint (0),
				"languages", 0, false);
		ucl_object_insert_key (res, ucl_object_fromint (0),
				"users", 0, false);

		if (mf->cf->label) {
			ucl_object_insert_key (res, ucl_object_fromstring (mf->cf->label),
					"label", 0, false);
		}
	}

	return res;
}

gboolean
rspamd_mmaped_file_finalize_learn (struct rspamd_task *task, gpointer runtime,
		gpointer ctx, GError **err)
{
	rspamd_mmaped_file_t *mf = (rspamd_mmaped_file_t *)runtime;

	if (mf != NULL) {
		msync (mf->map, mf->len, MS_INVALIDATE | MS_ASYNC);
	}

	return TRUE;
}

gboolean
rspamd_mmaped_file_finalize_process (struct rspamd_task *task, gpointer runtime,
		gpointer ctx)
{
	return TRUE;
}

gpointer
rspamd_mmaped_file_load_tokenizer_config (gpointer runtime,
		gsize *len)
{
	rspamd_mmaped_file_t *mf = runtime;
	struct stat_file_header *header;

	g_assert (mf != NULL);
	header = mf->map;

	if (len) {
		*len = header->tokenizer_conf_len;
	}

	return header->unused;
}
