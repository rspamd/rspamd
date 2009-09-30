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

/* Maximum number of statistics files */
#define STATFILES_MAX 255

static int
cmpstatfile (const void *a, const void *b)
{
	const stat_file_t *s1 = a, *s2 = b;

	return g_ascii_strcasecmp (s1->filename, s2->filename);
}

/* Check whether specified file is statistic file and calculate its len in blocks */
static int
statfile_pool_check (stat_file_t *file)
{
	struct stat_file *f;
	char *c;

	if (!file || !file->map) {
		return -1;
	}

	if (file->len < sizeof (struct stat_file)) {
		msg_info ("statfile_pool_check: file %s is too short to be stat file: %zd", file->filename, file->len);
		return -1;
	}

	f = (struct stat_file *)file->map;
	c = f->header.magic;
	/* Check magic and version */
	if (*c++ != 'r' || *c++ != 's' || *c++ != 'd' ||
		/* version */ *c++ != 1 || *c != 0) {
		msg_info ("statfile_pool_check: file %s is invalid stat file", file->filename);
		return -1;
	}

	/* Check first section and set new offset */
	file->cur_section.code = f->section.code;
	file->cur_section.length = f->section.length;
    if (file->cur_section.length * sizeof (struct stat_file_block) > file->len) {
		msg_info ("statfile_pool_check: file %s is truncated: %zd, must be %zd", file->filename, 
                file->len, file->cur_section.length * sizeof (struct stat_file_block));
		return -1;
    }
	file->seek_pos = sizeof (struct stat_file) - sizeof (struct stat_file_block);
	
	return 0;
}


struct expiration_data {
	statfile_pool_t *pool;
	uint64_t oldest;
	char *filename;
};


static int
statfile_pool_expire (statfile_pool_t *pool)
{
	struct expiration_data exp;
	stat_file_t *file;
	int i;

	if (pool->opened == 0) {
		return -1;
	}

	exp.pool = pool;
	exp.oldest = ULLONG_MAX;
	exp.filename = NULL;

	for (i = 0; i < pool->opened; i++) {
		file = &pool->files[i];
		if ((uint64_t)file->access_time < exp.oldest) {
			exp.oldest = file->access_time;
			exp.filename = file->filename;
		}
	}

	if (exp.filename) {
		statfile_pool_close (pool, file, TRUE);
	}

	return 0;
}

statfile_pool_t* 
statfile_pool_new (size_t max_size)
{
	statfile_pool_t *new;

	new = g_malloc (sizeof (statfile_pool_t));
	bzero (new, sizeof (statfile_pool_t));
	new->pool = memory_pool_new (memory_pool_get_size ());
	new->max = max_size;
	new->files = memory_pool_alloc_shared (new->pool, STATFILES_MAX * sizeof (stat_file_t));
    new->lock = memory_pool_get_mutex (new->pool);

	return new;
}

stat_file_t *
statfile_pool_open (statfile_pool_t *pool, char *filename)
{
	struct stat st;
	stat_file_t *new_file;	
	
	if ((new_file = statfile_pool_is_open (pool, filename)) != NULL) {
		return new_file;
	}

	if (pool->opened >= STATFILES_MAX - 1) {
		msg_err ("sttafile_pool_open: reached hard coded limit of statfiles opened: %d", STATFILES_MAX); 
		return NULL;
	}

	if (stat (filename, &st) == -1) {
		msg_info ("statfile_pool_open: cannot stat file %s, error %s, %d", filename, strerror (errno), errno);
		return NULL;
	}
	
	if (st.st_size > pool->max) {
		msg_info ("statfile_pool_open: cannot attach file to pool, too large: %zd", (size_t)st.st_size);
		return NULL;
	}

	while (pool->max + pool->opened * sizeof (struct stat_file) < pool->occupied + st.st_size) {
		if (statfile_pool_expire (pool) == -1) {
			/* Failed to find any more free space in pool */
			msg_info ("statfile_pool_open: expiration for pool failed, opening file %s failed", filename);
			return NULL;
		}
	}
    
    memory_pool_lock_mutex (pool->lock);
	new_file = &pool->files[pool->opened ++];
    bzero (new_file, sizeof (stat_file_t));
	if ((new_file->fd = open (filename, O_RDWR)) == -1 ) {
		msg_info ("statfile_pool_open: cannot open file %s, error %d, %s", filename, errno, strerror (errno));
        memory_pool_unlock_mutex (pool->lock);
		pool->opened --;
		return NULL;
	}
	
	if ((new_file->map = mmap (NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, new_file->fd, 0)) == MAP_FAILED) {
		close (new_file->fd);
        memory_pool_unlock_mutex (pool->lock);
		msg_info ("statfile_pool_open: cannot mmap file %s, error %d, %s", filename, errno, strerror (errno));
		pool->opened --;
		return NULL;
	
	}
	
	g_strlcpy (new_file->filename, filename, sizeof (new_file->filename));
	new_file->len = st.st_size;
	if (statfile_pool_check (new_file) == -1) {
		pool->opened --;
        memory_pool_unlock_mutex (pool->lock);
		return NULL;
	}

	pool->occupied += st.st_size;
	new_file->open_time = time (NULL);
	new_file->access_time = new_file->open_time;
	new_file->lock = memory_pool_get_mutex (pool->pool);
	
	/* Keep sorted */
	qsort (pool->files, pool->opened, sizeof (stat_file_t), cmpstatfile);
    memory_pool_unlock_mutex (pool->lock);

	return new_file;
}

int
statfile_pool_close (statfile_pool_t *pool, stat_file_t *file, gboolean keep_sorted)
{
	stat_file_t *pos;

	if ((pos = statfile_pool_is_open (pool, file->filename)) == NULL) {
		msg_info ("statfile_pool_open: file %s is not opened", file->filename);
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
    pool->opened --;

	if (keep_sorted) {
		memmove (pos, &pool->files[pool->opened], sizeof (stat_file_t));
		/* Keep sorted */
		qsort (pool->files, pool->opened, sizeof (stat_file_t), cmpstatfile);
	}
    memory_pool_unlock_mutex (pool->lock);

	return 0;
}

int
statfile_pool_create (statfile_pool_t *pool, char *filename, size_t blocks)
{
	struct stat_file_header header = {
		.magic = {'r', 's', 'd'},
		.version = {1, 0},
		.padding = {0, 0, 0},
	};
	struct stat_file_section section = {
		.code = STATFILE_SECTION_COMMON,
	};
	struct stat_file_block block = {0, 0, 0, 0};
	int fd;
	
	if (statfile_pool_is_open (pool, filename) != NULL) {
		msg_info ("statfile_pool_open: file %s is already opened", filename);
		return 0;
	}

    memory_pool_lock_mutex (pool->lock);

	if ((fd = open (filename, O_RDWR | O_TRUNC | O_CREAT, S_IWUSR | S_IRUSR)) == -1 ) {
		msg_info ("statfile_pool_create: cannot create file %s, error %d, %s", filename, errno, strerror (errno));
        memory_pool_unlock_mutex (pool->lock);
		return -1;
	}

	header.create_time = (uint64_t)time (NULL);
	if (write (fd, &header, sizeof (header)) == -1) {
		msg_info ("statfile_pool_create: cannot write header to file %s, error %d, %s", filename, errno, strerror (errno));
		close (fd);
        memory_pool_unlock_mutex (pool->lock);
		return -1;
	}
	
	section.length = (uint64_t)blocks;
	if (write (fd, &section, sizeof (section)) == -1) {
		msg_info ("statfile_pool_create: cannot write section header to file %s, error %d, %s", filename, errno, strerror (errno));
		close (fd);
        memory_pool_unlock_mutex (pool->lock);
		return -1;
	}
	
	while (blocks --) {
		if (write (fd, &block, sizeof (block)) == -1) {
			msg_info ("statfile_pool_create: cannot write block to file %s, error %d, %s", filename, errno, strerror (errno));
			close (fd);
            memory_pool_unlock_mutex (pool->lock);
			return -1;
		}
	}

	close (fd);
    memory_pool_unlock_mutex (pool->lock);
	
	return 0;
}

void
statfile_pool_delete (statfile_pool_t *pool)
{
	int i;

	for (i = 0; i < pool->opened; i ++) {
		statfile_pool_close (pool, &pool->files[i], FALSE);
	}
	memory_pool_delete (pool->pool);
	g_free (pool);
}

void
statfile_pool_lock_file (statfile_pool_t *pool, stat_file_t *file) 
{

	memory_pool_lock_mutex (file->lock);
}

void
statfile_pool_unlock_file (statfile_pool_t *pool, stat_file_t *file) 
{

	memory_pool_unlock_mutex (file->lock);
}

float
statfile_pool_get_block (statfile_pool_t *pool, stat_file_t *file, uint32_t h1, uint32_t h2, time_t now)
{
	struct stat_file_block *block;
	struct stat_file_header *header;
	unsigned int i, blocknum;
	u_char *c;
	
	
	file->access_time = now;
	if (!file->map) {
		return 0;
	}
	
	blocknum = h1 % file->cur_section.length;
	header = (struct stat_file_header *)file->map;
	c = (u_char *)file->map + file->seek_pos + blocknum * sizeof (struct stat_file_block);
	block = (struct stat_file_block *)c;

	for (i = 0; i < CHAIN_LENGTH; i ++) {
		if (i + blocknum > file->cur_section.length) {
			break;
		}
		if (block->hash1 == h1 && block->hash2 == h2) {
			block->last_access = now - (time_t)header->create_time;
			return block->value;
		}
		c += sizeof (struct stat_file_block);
		block = (struct stat_file_block *)c;
	}


	return 0;
}

void
statfile_pool_set_block (statfile_pool_t *pool, stat_file_t *file, uint32_t h1, uint32_t h2, time_t now, float value)
{
	struct stat_file_block *block, *to_expire = NULL;
	struct stat_file_header *header;
	unsigned int i, blocknum, oldest = 0;
	u_char *c;
	
	
	file->access_time = now;
	if (!file->map) {
		return;
	}
	
	blocknum = h1 % file->cur_section.length;
	header = (struct stat_file_header *)file->map;
	c = (u_char *)file->map + file->seek_pos + blocknum * sizeof (struct stat_file_block);
	block = (struct stat_file_block *)c;

	for (i = 0; i < CHAIN_LENGTH; i ++) {
		if (i + blocknum > file->cur_section.length) {
			/* Need to expire some block in chain */
			msg_debug ("statfile_pool_set_block: chain %u is full, starting expire", blocknum);
			break;
		}
		/* First try to find block in chain */
		if (block->hash1 == h1 && block->hash2 == h2) {
			block->last_access = now - (time_t)header->create_time;
			block->value = value;
			return;
		}
		/* Check whether we have a free block in chain */
		if (block->hash1 == 0 && block->hash2 == 0) {
			/* Write new block here */
			msg_debug ("statfile_pool_set_block: found free block %u in chain %u, set h1=%u, h2=%u", i, blocknum, h1, h2);
			block->hash1 = h1;
			block->hash2 = h2;
			block->value = value;
			block->last_access = now - (time_t)header->create_time;
			return;
		}
		if (block->last_access > oldest) {
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
		c = (u_char *)file->map + file->seek_pos + blocknum * sizeof (struct stat_file_block);
		block = (struct stat_file_block *)c;
	}
	block->last_access = now - (time_t)header->create_time;
	block->hash1 = h1;
	block->hash2 = h2;
	block->value = value;
}

stat_file_t *
statfile_pool_is_open (statfile_pool_t *pool, char *filename)
{
	static stat_file_t f, *ret;
	g_strlcpy (f.filename, filename, sizeof (f.filename));
	ret = bsearch (&f, pool->files, pool->opened, sizeof (stat_file_t), cmpstatfile);
	return ret;
}

uint32_t
statfile_pool_get_section (statfile_pool_t *pool, stat_file_t *file)
{

	return file->cur_section.code;
}

gboolean 
statfile_pool_set_section (statfile_pool_t *pool, stat_file_t *file, uint32_t code, gboolean from_begin)
{
	struct stat_file_section *sec;
	off_t cur_offset;

	
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
statfile_pool_add_section (statfile_pool_t *pool, stat_file_t *file, uint32_t code, uint64_t length)
{
	struct stat_file_section sect;
	struct stat_file_block block = {0, 0, 0, 0};
	
	if (lseek (file->fd, 0, SEEK_END) == -1) {
		msg_info ("statfile_pool_add_section: cannot lseek file %s, error %d, %s", file->filename, errno, strerror (errno));
		return FALSE;
	}
	
	sect.code = code;
	sect.length = length;

	if (write (file->fd, &sect, sizeof (sect)) == -1) {
		msg_info ("statfile_pool_add_section: cannot write block to file %s, error %d, %s", file->filename, errno, strerror (errno));
		return FALSE;
	}

	while (length --) {
		if (write (file->fd, &block, sizeof (block)) == -1) {
			msg_info ("statfile_pool_add_section: cannot write block to file %s, error %d, %s", file->filename, errno, strerror (errno));
			return FALSE;
		}
	}
	
	/* Lock statfile to remap memory */
	statfile_pool_lock_file (pool, file);
	munmap (file->map, file->len);
	fsync (file->fd);
	file->len += length;
	
	if (file->len > pool->max) {
		msg_info ("statfile_pool_open: cannot attach file to pool, too large: %lu", (long int)file->len);
		return FALSE;
	}

	while (pool->max <= pool->occupied + file->len) {
		if (statfile_pool_expire (pool) == -1) {
			/* Failed to find any more free space in pool */
			msg_info ("statfile_pool_open: expiration for pool failed, opening file %s failed", file->filename);
			return FALSE;
		}
	}
	if ((file->map = mmap (NULL, file->len, PROT_READ | PROT_WRITE, MAP_SHARED, file->fd, 0)) == NULL) {
		msg_info ("statfile_pool_open: cannot mmap file %s, error %d, %s", file->filename, errno, strerror (errno));
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
