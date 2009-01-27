/*
 * Describes common methods in accessing statistics files and caching them in memory
 */

#ifndef RSPAMD_STATFILE_H
#define RSPAMD_STATFILE_H

#include "config.h"
#include <sys/types.h>
#include <glib.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include "mem_pool.h"
#include "hash.h"

#define CHAIN_LENGTH 128

struct stat_file_header {
	u_char magic[3];
	u_char version[2];
	u_char padding[3];
	uint64_t create_time;
} __attribute__((__packed__));

struct stat_file_block {
	uint32_t hash1;
	uint32_t hash2;
	float value; /* In fact this is float */
	uint32_t last_access;
};

struct stat_file {
	struct stat_file_header header;
	struct stat_file_block blocks[1];
};

typedef struct stat_file_s {
	char *filename;
	int fd;
	void *map;
	time_t open_time;
	time_t access_time;
	size_t len;
	/* Length is in blocks */
	size_t blocks;
	gint *lock;
} stat_file_t;

typedef struct statfile_pool_s {
	rspamd_hash_t *files;
	int opened;
	size_t max;
	size_t occupied;
	memory_pool_t *pool;
} statfile_pool_t;

statfile_pool_t* statfile_pool_new (size_t max_size);
int statfile_pool_open (statfile_pool_t *pool, char *filename);
int statfile_pool_create (statfile_pool_t *pool, char *filename, size_t len);
int statfile_pool_close (statfile_pool_t *pool, char *filename, gboolean remove_hash);
void statfile_pool_delete (statfile_pool_t *pool);
void statfile_pool_lock_file (statfile_pool_t *pool, char *filename);
void statfile_pool_unlock_file (statfile_pool_t *pool, char *filename);
float statfile_pool_get_block (statfile_pool_t *pool, char *filename, uint32_t h1, uint32_t h2, time_t now);
void statfile_pool_set_block (statfile_pool_t *pool, char *filename, uint32_t h1, uint32_t h2, time_t now, float value);
int statfile_pool_is_open (statfile_pool_t *pool, char *filename);

#endif
