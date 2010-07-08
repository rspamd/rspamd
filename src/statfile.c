/*
 * Copyright (c) 2009, Rambler media
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
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include "statfile.h"
#include "main.h"

#define RSPAMD_STATFILE_VERSION {'1', '2'}
#define BACKUP_SUFFIX ".old"

/* Maximum number of statistics files */
#define STATFILES_MAX 255
static void statfile_pool_set_block_common (
				statfile_pool_t * pool, stat_file_t * file, 
				uint32_t h1, uint32_t h2, 
				time_t t, double value, 
				gboolean from_now);

static int
cmpstatfile (const void *a, const void *b)
{
	const stat_file_t              *s1 = a, *s2 = b;

	return g_ascii_strcasecmp (s1->filename, s2->filename);
}

/* Convert statfile version 1.0 to statfile version 1.2, saving backup */
struct stat_file_header_10 {
	u_char magic[3];						/**< magic signature ('r' 's' 'd') 		*/
	u_char version[2];						/**< version of statfile				*/
	u_char padding[3];						/**< padding							*/
	uint64_t create_time;					/**< create time (time_t->uint64_t)		*/
};

static gboolean
convert_statfile_10 (stat_file_t * file)
{
	char *backup_name;
	struct stat st;
	struct stat_file_header         header = {
		.magic = {'r', 's', 'd'},
		.version = RSPAMD_STATFILE_VERSION,
		.padding = {0, 0, 0},
		.revision = 0,
		.rev_time = 0
	};


	/* Format backup name */
	backup_name = g_strdup_printf ("%s.%s", file->filename, BACKUP_SUFFIX);
	
	msg_info ("convert old statfile %s to version %c.%c, backup in %s", file->filename, 
			header.version[0], header.version[1], backup_name);

	if (stat (backup_name, &st) != -1) {
		msg_info ("replace old %s", backup_name);
		unlink (backup_name);
	}

	rename (file->filename, backup_name);
	g_free (backup_name);

	/* XXX: maybe race condition here */
	unlock_file (file->fd, FALSE);
	close (file->fd);
	if ((file->fd = open (file->filename, O_RDWR | O_TRUNC | O_CREAT, S_IWUSR | S_IRUSR)) == -1) {
		msg_info ("cannot create file %s, error %d, %s", file->filename, errno, strerror (errno));
		return FALSE;
	}
	lock_file (file->fd, FALSE);
	/* Now make new header and copy it to new file */
	if (write (file->fd, &header, sizeof (header)) == -1) {
		msg_info ("cannot write to file %s, error %d, %s", file->filename, errno, strerror (errno));
		return FALSE;
	}
	/* Now write old map to new file */
	if (write (file->fd, ((u_char *)file->map + sizeof (struct stat_file_header_10)),
						file->len - sizeof (struct stat_file_header_10)) == -1) {
		msg_info ("cannot write to file %s, error %d, %s", file->filename, errno, strerror (errno));
		return FALSE;
	}
	/* Unmap old memory and map new */
	munmap (file->map, file->len);
	file->len = file->len + sizeof (struct stat_file_header) - sizeof (struct stat_file_header_10);
#ifdef HAVE_MMAP_NOCORE
	if ((file->map = mmap (NULL, file->len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_NOCORE, file->fd, 0)) == MAP_FAILED) {
#else
	if ((file->map = mmap (NULL, file->len, PROT_READ | PROT_WRITE, MAP_SHARED, file->fd, 0)) == MAP_FAILED) {
#endif
		msg_info ("cannot mmap file %s, error %d, %s", file->filename, errno, strerror (errno));
		return FALSE;
	}

	return TRUE;
}

/* Check whether specified file is statistic file and calculate its len in blocks */
static int
statfile_pool_check (stat_file_t * file)
{
	struct stat_file               *f;
	char                           *c;
	static char                     valid_version[] = RSPAMD_STATFILE_VERSION;


	if (!file || !file->map) {
		return -1;
	}

	if (file->len < sizeof (struct stat_file)) {
		msg_info ("file %s is too short to be stat file: %z", file->filename, file->len);
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
		if (!convert_statfile_10 (file)) {
			return -1;
		}
		f = (struct stat_file *)file->map;
	}
	else if (memcmp (c, valid_version, sizeof (valid_version)) != 0) {
		/* Unknown version */
		msg_info ("file %s has invalid version %c.%c", file->filename, '0' + *c, '0' + *(c + 1));
		return -1;
	}

	/* Check first section and set new offset */
	file->cur_section.code = f->section.code;
	file->cur_section.length = f->section.length;
	if (file->cur_section.length * sizeof (struct stat_file_block) > file->len) {
		msg_info ("file %s is truncated: %z, must be %z", file->filename, file->len, file->cur_section.length * sizeof (struct stat_file_block));
		return -1;
	}
	file->seek_pos = sizeof (struct stat_file) - sizeof (struct stat_file_block);

	return 0;
}


struct expiration_data {
	statfile_pool_t                *pool;
	uint64_t                        oldest;
	char                           *filename;
};


static int
statfile_pool_expire (statfile_pool_t * pool)
{
	struct expiration_data          exp;
	stat_file_t                    *file;
	int                             i;

	if (pool->opened == 0) {
		return -1;
	}

	exp.pool = pool;
	exp.oldest = ULLONG_MAX;
	exp.filename = NULL;

	for (i = 0; i < pool->opened; i++) {
		file = &pool->files[i];
		if ((uint64_t) file->access_time < exp.oldest) {
			exp.oldest = file->access_time;
			exp.filename = file->filename;
		}
	}

	if (exp.filename) {
		statfile_pool_close (pool, file, TRUE);
	}

	return 0;
}

statfile_pool_t                *
statfile_pool_new (size_t max_size)
{
	statfile_pool_t                *new;

	new = g_malloc (sizeof (statfile_pool_t));
	bzero (new, sizeof (statfile_pool_t));
	new->pool = memory_pool_new (memory_pool_get_size ());
	new->max = max_size;
	new->files = memory_pool_alloc (new->pool, STATFILES_MAX * sizeof (stat_file_t));
	new->lock = memory_pool_get_mutex (new->pool);

	return new;
}

static stat_file_t *
statfile_pool_reindex (statfile_pool_t * pool, char *filename, size_t old_size, size_t size)
{
	char                           *backup;
	int                             fd;
	stat_file_t                    *new;
	u_char                         *map, *pos;
	struct stat_file_block         *block;

	/* First of all rename old file */
	memory_pool_lock_mutex (pool->lock);

	backup = g_strconcat (filename, ".old", NULL);
	if (rename (filename, backup) == -1) {
		msg_err ("cannot rename %s to %s: %s", filename, backup, strerror (errno));
		g_free (backup);
		memory_pool_unlock_mutex (pool->lock);
		return NULL;
	}

	memory_pool_unlock_mutex (pool->lock);

	/* Now create new file with required size */
	if (statfile_pool_create (pool, filename, size) != 0) {
		msg_err ("cannot create new file");
		g_free (backup);
		return NULL;
	}
	/* Now open new file and start copying */
	fd = open (backup, O_RDONLY);
	new = statfile_pool_open (pool, filename, size, TRUE);

	if (fd == -1 || new == NULL) {
		msg_err ("cannot open file: %s", strerror (errno));
		g_free (backup);
		return NULL;
	}

	/* Now start reading blocks from old statfile */
	if ((map = mmap (NULL, old_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		msg_err ("cannot mmap file: %s", strerror (errno));
		close (fd);
		g_free (backup);
		return NULL;
	}

	pos = map + (sizeof (struct stat_file) - sizeof (struct stat_file_block));
	while (pos - map < old_size) {
		block = (struct stat_file_block *)pos;
		if (block->hash1 != 0 && block->value != 0) {
			statfile_pool_set_block_common (pool, new, block->hash1, block->hash2, 0, block->value, FALSE);
		}
		pos += sizeof (block);
	}
	
	munmap (map, old_size);
	close (fd);
	unlink (backup);
	g_free (backup);

	return new;

}

stat_file_t                    *
statfile_pool_open (statfile_pool_t * pool, char *filename, size_t size, gboolean forced)
{
	struct stat                     st;
	stat_file_t                    *new_file;

	if ((new_file = statfile_pool_is_open (pool, filename)) != NULL) {
		return new_file;
	}

	if (pool->opened >= STATFILES_MAX - 1) {
		msg_err ("reached hard coded limit of statfiles opened: %d", STATFILES_MAX);
		return NULL;
	}

	if (stat (filename, &st) == -1) {
		msg_info ("cannot stat file %s, error %s, %d", filename, strerror (errno), errno);
		return NULL;
	}

	if (!forced && st.st_size > pool->max) {
		msg_info ("cannot attach file to pool, too large: %z", (size_t) st.st_size);
		return NULL;
	}

	memory_pool_lock_mutex (pool->lock);
	if (!forced && abs (st.st_size - size) > sizeof (struct stat_file)) {
		memory_pool_unlock_mutex (pool->lock);
		msg_warn ("need to reindex statfile old size: %z, new size: %z", st.st_size, size);
		return statfile_pool_reindex (pool, filename, st.st_size, size);
	}
	memory_pool_unlock_mutex (pool->lock);

	while (!forced && (pool->max + pool->opened * sizeof (struct stat_file) * 2 < pool->occupied + st.st_size)) {
		if (statfile_pool_expire (pool) == -1) {
			/* Failed to find any more free space in pool */
			msg_info ("expiration for pool failed, opening file %s failed", filename);
			return NULL;
		}
	}

	memory_pool_lock_mutex (pool->lock);
	new_file = &pool->files[pool->opened++];
	bzero (new_file, sizeof (stat_file_t));
	if ((new_file->fd = open (filename, O_RDWR)) == -1) {
		msg_info ("cannot open file %s, error %d, %s", filename, errno, strerror (errno));
		memory_pool_unlock_mutex (pool->lock);
		pool->opened--;
		return NULL;
	}

	if ((new_file->map = mmap (NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, new_file->fd, 0)) == MAP_FAILED) {
		close (new_file->fd);
		memory_pool_unlock_mutex (pool->lock);
		msg_info ("cannot mmap file %s, error %d, %s", filename, errno, strerror (errno));
		pool->opened--;
		return NULL;

	}

	g_strlcpy (new_file->filename, filename, sizeof (new_file->filename));
	new_file->len = st.st_size;
	/* Aqquire lock for this operation */
	lock_file (new_file->fd, FALSE);
	if (statfile_pool_check (new_file) == -1) {
		pool->opened--;
		memory_pool_unlock_mutex (pool->lock);
		unlock_file (new_file->fd, FALSE);
        munmap (new_file->map, st.st_size);
		return NULL;
	}
	unlock_file (new_file->fd, FALSE);

	pool->occupied += st.st_size;
	new_file->open_time = time (NULL);
	new_file->access_time = new_file->open_time;
	new_file->lock = memory_pool_get_mutex (pool->pool);

	/* Keep sorted */
	qsort (pool->files, pool->opened, sizeof (stat_file_t), cmpstatfile);
	memory_pool_unlock_mutex (pool->lock);

	return statfile_pool_is_open (pool, filename);
}

int
statfile_pool_close (statfile_pool_t * pool, stat_file_t * file, gboolean keep_sorted)
{
	stat_file_t                    *pos;

	if ((pos = statfile_pool_is_open (pool, file->filename)) == NULL) {
		msg_info ("file %s is not opened", file->filename);
		return -1;
	}

	memory_pool_lock_mutex (pool->lock);
	if (file->lock) {
		memory_pool_lock_mutex (file->lock);
	}

	if (file->map) {
		munmap (file->map, file->len);
	}
	if (file->fd != -1) {
		close (file->fd);
	}
	pool->occupied -= file->len;
	pool->opened--;

	if (keep_sorted) {
		memmove (pos, &pool->files[pool->opened], sizeof (stat_file_t));
		/* Keep sorted */
		qsort (pool->files, pool->opened, sizeof (stat_file_t), cmpstatfile);
	}
	memory_pool_unlock_mutex (pool->lock);

	return 0;
}

int
statfile_pool_create (statfile_pool_t * pool, char *filename, size_t size)
{
	struct stat_file_header         header = {
		.magic = {'r', 's', 'd'},
		.version = RSPAMD_STATFILE_VERSION,
		.padding = {0, 0, 0},
		.revision = 0,
		.rev_time = 0,
		.used_blocks = 0
	};
	struct stat_file_section        section = {
		.code = STATFILE_SECTION_COMMON,
	};
	struct stat_file_block          block = { 0, 0, 0 };
	int                             fd;
	unsigned int                    buflen = 0, nblocks;
	char                           *buf = NULL;

	if (statfile_pool_is_open (pool, filename) != NULL) {
		msg_info ("file %s is already opened", filename);
		return 0;
	}

	memory_pool_lock_mutex (pool->lock);
	nblocks = (size - sizeof (struct stat_file_header) - sizeof (struct stat_file_section)) / sizeof (struct stat_file_block);
	header.total_blocks = nblocks;

	if ((fd = open (filename, O_RDWR | O_TRUNC | O_CREAT, S_IWUSR | S_IRUSR)) == -1) {
		msg_info ("cannot create file %s, error %d, %s", filename, errno, strerror (errno));
		memory_pool_unlock_mutex (pool->lock);
		return -1;
	}

	header.create_time = (uint64_t) time (NULL);
	if (write (fd, &header, sizeof (header)) == -1) {
		msg_info ("cannot write header to file %s, error %d, %s", filename, errno, strerror (errno));
		close (fd);
		memory_pool_unlock_mutex (pool->lock);
		return -1;
	}

	section.length = (uint64_t) nblocks;
	if (write (fd, &section, sizeof (section)) == -1) {
		msg_info ("cannot write section header to file %s, error %d, %s", filename, errno, strerror (errno));
		close (fd);
		memory_pool_unlock_mutex (pool->lock);
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
				msg_info ("cannot write blocks buffer to file %s, error %d, %s", filename, errno, strerror (errno));
				close (fd);
				memory_pool_unlock_mutex (pool->lock);
				g_free (buf);
				return -1;
			}
			nblocks -= 256;
		}
		else {
			if (write (fd, &block, sizeof (block)) == -1) {
				msg_info ("cannot write block to file %s, error %d, %s", filename, errno, strerror (errno));
				close (fd);
				if (buf) {
					g_free (buf);
				}
				memory_pool_unlock_mutex (pool->lock);
				return -1;
			}
			nblocks --;
		}
	}

	close (fd);
	memory_pool_unlock_mutex (pool->lock);

	if (buf) {
		g_free (buf);
	}

	return 0;
}

void
statfile_pool_delete (statfile_pool_t * pool)
{
	int                             i;

	for (i = 0; i < pool->opened; i++) {
		statfile_pool_close (pool, &pool->files[i], FALSE);
	}
	memory_pool_delete (pool->pool);
	g_free (pool);
}

void
statfile_pool_lock_file (statfile_pool_t * pool, stat_file_t * file)
{

	memory_pool_lock_mutex (file->lock);
}

void
statfile_pool_unlock_file (statfile_pool_t * pool, stat_file_t * file)
{

	memory_pool_unlock_mutex (file->lock);
}

double
statfile_pool_get_block (statfile_pool_t * pool, stat_file_t * file, uint32_t h1, uint32_t h2, time_t now)
{
	struct stat_file_block         *block;
	struct stat_file_header        *header;
	unsigned int                    i, blocknum;
	u_char                         *c;


	file->access_time = now;
	if (!file->map) {
		return 0;
	}

	blocknum = h1 % file->cur_section.length;
	header = (struct stat_file_header *)file->map;
	c = (u_char *) file->map + file->seek_pos + blocknum * sizeof (struct stat_file_block);
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

#define RANDOM_EXPIRE G_MAXINT / CHAIN_LENGTH
static void
statfile_pool_set_block_common (statfile_pool_t * pool, stat_file_t * file, uint32_t h1, uint32_t h2, time_t t, double value, gboolean from_now)
{
	struct stat_file_block         *block, *to_expire = NULL;
	struct stat_file_header        *header;
	unsigned int                    i, blocknum;
	u_char                         *c;
    double                          min = G_MAXDOUBLE;


	if (from_now) {
		file->access_time = t;
	}
	if (!file->map) {
		return;
	}

	blocknum = h1 % file->cur_section.length;
	header = (struct stat_file_header *)file->map;
	c = (u_char *) file->map + file->seek_pos + blocknum * sizeof (struct stat_file_block);
	block = (struct stat_file_block *)c;

	for (i = 0; i < CHAIN_LENGTH; i++) {
		if (i + blocknum >= file->cur_section.length) {
			/* Need to expire some block in chain */
			msg_debug ("chain %u is full, starting expire", blocknum);
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
			msg_debug ("found free block %u in chain %u, set h1=%u, h2=%u", i, blocknum, h1, h2);
			block->hash1 = h1;
			block->hash2 = h2;
			block->value = value;
			header->used_blocks ++;

			return;
		}
		
		/* Expire block if we have some random value that is lower than RANDOM_EXPIRE value */
		if (g_random_int () < RANDOM_EXPIRE) {
			to_expire = block;
			break;
		}
		/* Expire block with minimum value otherwise */
		if (block->value < min) {
			to_expire = block;
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
		c = (u_char *) file->map + file->seek_pos + blocknum * sizeof (struct stat_file_block);
		block = (struct stat_file_block *)c;
	}

	block->hash1 = h1;
	block->hash2 = h2;
	block->value = value;
}

void
statfile_pool_set_block (statfile_pool_t * pool, stat_file_t * file, uint32_t h1, uint32_t h2, time_t now, double value)
{
	statfile_pool_set_block_common (pool, file, h1, h2, now, value, TRUE);
}

stat_file_t                    *
statfile_pool_is_open (statfile_pool_t * pool, char *filename)
{
	static stat_file_t              f, *ret;
	g_strlcpy (f.filename, filename, sizeof (f.filename));
	ret = bsearch (&f, pool->files, pool->opened, sizeof (stat_file_t), cmpstatfile);
	return ret;
}

uint32_t
statfile_pool_get_section (statfile_pool_t * pool, stat_file_t * file)
{

	return file->cur_section.code;
}

gboolean
statfile_pool_set_section (statfile_pool_t * pool, stat_file_t * file, uint32_t code, gboolean from_begin)
{
	struct stat_file_section       *sec;
	off_t                           cur_offset;


	/* Try to find section */
	if (from_begin) {
		cur_offset = sizeof (struct stat_file_header);
	}
	else {
		cur_offset = file->seek_pos - sizeof (struct stat_file_section);
	}
	while (cur_offset < file->len) {
		sec = (struct stat_file_section *)((char *)file->map + cur_offset);
		if (sec->code == code) {
			file->cur_section.code = code;
			file->cur_section.length = sec->length;
			file->seek_pos = cur_offset + sizeof (struct stat_file_section);
			return TRUE;
		}
		cur_offset += sec->length;
	}

	return FALSE;
}

gboolean
statfile_pool_add_section (statfile_pool_t * pool, stat_file_t * file, uint32_t code, uint64_t length)
{
	struct stat_file_section        sect;
	struct stat_file_block          block = { 0, 0, 0 };

	if (lseek (file->fd, 0, SEEK_END) == -1) {
		msg_info ("cannot lseek file %s, error %d, %s", file->filename, errno, strerror (errno));
		return FALSE;
	}

	sect.code = code;
	sect.length = length;

	if (write (file->fd, &sect, sizeof (sect)) == -1) {
		msg_info ("cannot write block to file %s, error %d, %s", file->filename, errno, strerror (errno));
		return FALSE;
	}

	while (length--) {
		if (write (file->fd, &block, sizeof (block)) == -1) {
			msg_info ("cannot write block to file %s, error %d, %s", file->filename, errno, strerror (errno));
			return FALSE;
		}
	}

	/* Lock statfile to remap memory */
	statfile_pool_lock_file (pool, file);
	munmap (file->map, file->len);
	fsync (file->fd);
	file->len += length;

	if (file->len > pool->max) {
		msg_info ("cannot attach file to pool, too large: %lu", (long int)file->len);
		return FALSE;
	}

	while (pool->max <= pool->occupied + file->len) {
		if (statfile_pool_expire (pool) == -1) {
			/* Failed to find any more free space in pool */
			msg_info ("expiration for pool failed, opening file %s failed", file->filename);
			return FALSE;
		}
	}
	if ((file->map = mmap (NULL, file->len, PROT_READ | PROT_WRITE, MAP_SHARED, file->fd, 0)) == NULL) {
		msg_info ("cannot mmap file %s, error %d, %s", file->filename, errno, strerror (errno));
		return FALSE;
	}
	statfile_pool_unlock_file (pool, file);

	return TRUE;

}

uint32_t
statfile_get_section_by_name (const char *name)
{
	if (g_ascii_strcasecmp (name, "common") == 0) {
		return STATFILE_SECTION_COMMON;
	}
	else if (g_ascii_strcasecmp (name, "header") == 0) {
		return STATFILE_SECTION_HEADERS;
	}
	else if (g_ascii_strcasecmp (name, "url") == 0) {
		return STATFILE_SECTION_URLS;
	}
	else if (g_ascii_strcasecmp (name, "regexp") == 0) {
		return STATFILE_SECTION_REGEXP;
	}

	return 0;
}

gboolean 
statfile_set_revision (stat_file_t *file, uint64_t rev, time_t time)
{
	struct stat_file_header        *header;

	if (file == NULL || file->map == NULL) {
		return FALSE;
	}
	
	header = (struct stat_file_header *)file->map;

	header->revision = rev;
	header->rev_time = time;

	return TRUE;
}

gboolean 
statfile_get_revision (stat_file_t *file, uint64_t *rev, time_t *time)
{
	struct stat_file_header        *header;

	if (file == NULL || file->map == NULL) {
		return FALSE;
	}
	
	header = (struct stat_file_header *)file->map;

	*rev = header->revision;
	*time = header->rev_time;

	return TRUE;
}

uint64_t 
statfile_get_used_blocks (stat_file_t *file)
{
	struct stat_file_header        *header;

	if (file == NULL || file->map == NULL) {
		return (uint64_t)-1;
	}
	
	header = (struct stat_file_header *)file->map;

	return header->used_blocks;
}

uint64_t 
statfile_get_total_blocks (stat_file_t *file)
{
	struct stat_file_header        *header;

	if (file == NULL || file->map == NULL) {
		return (uint64_t)-1;
	}
	
	header = (struct stat_file_header *)file->map;

	/* If total blocks is 0 we have old version of header, so set total blocks correctly */
	if (header->total_blocks == 0) {
		header->total_blocks = file->cur_section.length;
	}

	return header->total_blocks;
}
