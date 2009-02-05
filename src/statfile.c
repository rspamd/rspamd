#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <sys/mman.h>
#include "config.h"
#include <string.h>
#include <unistd.h>
#include <glib.h>

#include "statfile.h"
#include "main.h"

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
	
	if ((file->len - sizeof (f->header)) % sizeof (struct stat_file_block) != 0) {
		msg_info ("statfile_pool_check: file %s does not contain integer count of stat blocks", file->filename);
		return -1;
	}

	file->blocks = (file->len - sizeof (f->header)) / sizeof (struct stat_file_block);
	return 0;
}


struct expiration_data {
	statfile_pool_t *pool;
	uint64_t oldest;
	char *filename;
};

static void
pool_expiration_callback (gpointer key, gpointer value, void *data)
{
	struct expiration_data *exp = data;
	stat_file_t *file = (stat_file_t *)value;

	if ((uint64_t)file->access_time < exp->oldest) {
		exp->oldest = file->access_time;
		exp->filename = file->filename;
	}
}

static int
statfile_pool_expire (statfile_pool_t *pool)
{
	struct expiration_data exp;

	if (rspamd_hash_size (pool->files) == 0) {
		return -1;
	}

	exp.pool = pool;
	exp.oldest = ULLONG_MAX;
	exp.filename = NULL;
	rspamd_hash_foreach (pool->files, pool_expiration_callback, &exp);

	if (exp.filename) {
		statfile_pool_close (pool, exp.filename, TRUE);
	}
}

statfile_pool_t* 
statfile_pool_new (size_t max_size)
{
	statfile_pool_t *new;

	new = g_malloc (sizeof (statfile_pool_t));
	bzero (new, sizeof (statfile_pool_t));
	new->pool = memory_pool_new (memory_pool_get_size ());
	new->max = max_size;
	new->files = rspamd_hash_new_shared (new->pool, g_str_hash, g_str_equal);

	return new;
}

int 
statfile_pool_open (statfile_pool_t *pool, char *filename)
{
	struct stat st;
	stat_file_t *new_file;	
	
	if (rspamd_hash_lookup (pool->files, filename) != NULL) {
		msg_info ("statfile_pool_open: file %s is already opened", filename);
		return 0;
	}

	if (stat (filename, &st) == -1) {
		msg_info ("statfile_pool_open: cannot stat file %s, error %m, %d", filename, errno);
		return -1;
	}
	
	if (st.st_size > pool->max) {
		msg_info ("statfile_pool_open: cannot attach file to pool, too large: %zd", (size_t)st.st_size);
		return -1;
	}

	while (pool->max <= pool->occupied + st.st_size) {
		if (statfile_pool_expire (pool) == -1) {
			/* Failed to find any more free space in pool */
			msg_info ("statfile_pool_open: expiration for pool failed, opening file %s failed", filename);
			return -1;
		}
	}

	new_file = memory_pool_alloc (pool->pool, sizeof (stat_file_t));
	if ((new_file->fd = open (filename, O_RDWR)) == -1 ) {
		msg_info ("statfile_pool_open: cannot open file %s, error %m, %d", filename, errno);
		return -1;
	}
	
	if ((new_file->map = mmap (NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, new_file->fd, 0)) == NULL) {
		close (new_file->fd);
		msg_info ("statfile_pool_open: cannot mmap file %s, error %m, %d", filename, errno);
		return -1;
	
	}
	
	/* XXX: this is temporary copy of name to avoid strdup early */
	new_file->filename = filename;
	new_file->len = st.st_size;
	if (statfile_pool_check (new_file) == -1) {
		return -1;
	}

	pool->occupied += st.st_size;
	new_file->filename = memory_pool_strdup (pool->pool, filename);
	new_file->open_time = time (NULL);
	new_file->access_time = new_file->open_time;
	new_file->lock = memory_pool_get_mutex (pool->pool);
	rspamd_hash_insert (pool->files, new_file->filename, new_file);

	return 0;
}

int
statfile_pool_close (statfile_pool_t *pool, char *filename, gboolean remove_hash)
{
	stat_file_t *file;	
	
	if ((file = rspamd_hash_lookup (pool->files, filename)) == NULL) {
		msg_info ("statfile_pool_open: file %s is not opened", filename);
		return -1;
	}
	
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
	if (remove_hash) {
		rspamd_hash_remove (pool->files, file->filename);
	}
	return 0;
}

int
statfile_pool_create (statfile_pool_t *pool, char *filename, size_t blocks)
{
	static struct stat_file_header header = {
		{'r', 's', 'd'},
		{1, 0},
		{0, 0, 0},
		0
	};
	static struct stat_file_block block = {0, 0, 0, 0};
	int fd;
	
	if (rspamd_hash_lookup (pool->files, filename) != NULL) {
		msg_info ("statfile_pool_create: file %s is already opened", filename);
		return 0;
	}

	if ((fd = open (filename, O_RDWR | O_TRUNC | O_CREAT, S_IWUSR | S_IRUSR)) == -1 ) {
		msg_info ("statfile_pool_create: cannot create file %s, error %m, %d", filename, errno);
		return -1;
	}

	header.create_time = (uint64_t)time (NULL);
	if (write (fd, &header, sizeof (header)) == -1) {
		msg_info ("statfile_pool_create: cannot write header to file %s, error %m, %d", filename, errno);
		close (fd);
		return -1;
	}
	
	while (blocks --) {
		if (write (fd, &block, sizeof (block)) == -1) {
			msg_info ("statfile_pool_create: cannot write block to file %s, error %m, %d", filename, errno);
			close (fd);
			return -1;
		}
	}

	close (fd);
	
	return 0;
}

static void
pool_delete_callback (gpointer key, gpointer value, void *data)
{
	statfile_pool_t *pool = (statfile_pool_t *)data;

	statfile_pool_close (pool, (char *)key, FALSE);
}

void
statfile_pool_delete (statfile_pool_t *pool)
{
	rspamd_hash_foreach (pool->files, pool_delete_callback, pool);
	memory_pool_delete (pool->pool);
	g_free (pool);
}

void
statfile_pool_lock_file (statfile_pool_t *pool, char *filename) 
{
	stat_file_t *file;

	if ((file = rspamd_hash_lookup (pool->files, filename)) == NULL) {
		msg_info ("statfile_pool_lock_file: file %s is not opened", filename);
		return;
	}

	memory_pool_lock_mutex (file->lock);
}

void
statfile_pool_unlock_file (statfile_pool_t *pool, char *filename) 
{
	stat_file_t *file;

	if ((file = rspamd_hash_lookup (pool->files, filename)) == NULL) {
		msg_info ("statfile_pool_unlock_file: file %s is not opened", filename);
		return;
	}

	memory_pool_unlock_mutex (file->lock);
}

float
statfile_pool_get_block (statfile_pool_t *pool, char *filename, uint32_t h1, uint32_t h2, time_t now)
{
	stat_file_t *file;
	struct stat_file_block *block;
	struct stat_file_header *header;
	unsigned int i, blocknum;
	u_char *c;
	
	if ((file = rspamd_hash_lookup (pool->files, filename)) == NULL) {
		msg_info ("statfile_pool_get_block: file %s is not opened", filename);
		return 0;
	}
	
	file->access_time = now;
	if (!file->map) {
		return 0;
	}
	
	blocknum = h1 % file->blocks;
	header = (struct stat_file_header *)file->map;
	c = (u_char *)file->map + sizeof (struct stat_file_header) + blocknum * sizeof (struct stat_file_block);
	block = (struct stat_file_block *)c;

	for (i = 0; i < CHAIN_LENGTH; i ++) {
		if (i + blocknum > file->blocks) {
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
statfile_pool_set_block (statfile_pool_t *pool, char *filename, uint32_t h1, uint32_t h2, time_t now, float value)
{
	stat_file_t *file;
	struct stat_file_block *block, *to_expire = NULL;
	struct stat_file_header *header;
	unsigned int i, blocknum, oldest = 0;
	u_char *c;
	
	if ((file = rspamd_hash_lookup (pool->files, filename)) == NULL) {
		msg_info ("statfile_pool_set_block: file %s is not opened", filename);
		return;
	}
	
	file->access_time = now;
	if (!file->map) {
		return;
	}
	
	blocknum = h1 % file->blocks;
	header = (struct stat_file_header *)file->map;
	c = (u_char *)file->map + sizeof (struct stat_file_header) + blocknum * sizeof (struct stat_file_block);
	block = (struct stat_file_block *)c;

	for (i = 0; i < CHAIN_LENGTH; i ++) {
		if (i + blocknum > file->blocks) {
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
		c = (u_char *)file->map + sizeof (struct stat_file_header) + blocknum * sizeof (struct stat_file_block);
		block = (struct stat_file_block *)c;
	}
	block->last_access = now - (time_t)header->create_time;
	block->hash1 = h1;
	block->hash2 = h2;
	block->value = value;
}

gboolean
statfile_pool_is_open (statfile_pool_t *pool, char *filename)
{
	return (rspamd_hash_lookup (pool->files, filename) != NULL);
}
