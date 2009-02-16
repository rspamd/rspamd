/**
 * @file statfile.h
 * Describes common methods for accessing statistics files and caching them in memory
 */

#ifndef RSPAMD_STATFILE_H
#define RSPAMD_STATFILE_H

#include "config.h"
#include "mem_pool.h"
#include "hash.h"

#define CHAIN_LENGTH 128

/**
 * Common statfile header
 */
struct stat_file_header {
	u_char magic[3];						/**< magic signature ('r' 's' 'd') 		*/
	u_char version[2];						/**< version of statfile (1.0)			*/
	u_char padding[3];						/**< padding							*/
	uint64_t create_time;					/**< create time (time_t->uint64_t)		*/
} __attribute__((__packed__));

/**
 * Block of data in statfile
 */
struct stat_file_block {
	uint32_t hash1;							/**< hash1 (also acts as index)			*/				
	uint32_t hash2;							/**< hash2								*/
	float value; 							/**< float value 						*/
	uint32_t last_access;					/**< last access to block since create time of file	*/
};

/**
 * Statistic file
 */
struct stat_file {
	struct stat_file_header header;			/**< header								*/
	struct stat_file_block blocks[1];		/**< first block of data				*/
};

/**
 * Common view of statfile object
 */
typedef struct stat_file_s {
	char *filename;							/**< name of file						*/
	int fd;									/**< descriptor							*/
	void *map;								/**< mmaped area						*/
	time_t open_time;						/**< time when file was opened			*/
	time_t access_time;						/**< last access time					*/
	size_t len;								/**< length of file(in bytes)			*/
	size_t blocks;							/**< length of file in blocks			*/
	gint *lock;								/**< mutex								*/
} stat_file_t;

/**
 * Statfiles pool
 */
typedef struct statfile_pool_s {
	rspamd_hash_t *files;					/**< hash table of opened files indexed by name	*/
	int opened;								/**< number of opened files				*/
	size_t max;								/**< maximum size						*/
	size_t occupied;						/**< current size						*/
	memory_pool_t *pool;					/**< memory pool object					*/
} statfile_pool_t;

/**
 * Create new statfile pool
 * @param max_size maximum size
 * @return statfile pool object
 */
statfile_pool_t* statfile_pool_new (size_t max_size);

/**
 * Open statfile and attach it to pool
 * @param pool statfile pool object
 * @param filename name of statfile to open
 * @return 0 if specified statfile is attached and -1 in case of error
 */
int statfile_pool_open (statfile_pool_t *pool, char *filename);

/**
 * Create new statfile but DOES NOT attach it to pool, use @see statfile_pool_open for attaching
 * @param pool statfile pool object
 * @param filename name of statfile to create
 * @param len length of new statfile
 * @return 0 if file was created and -1 in case of error
 */
int statfile_pool_create (statfile_pool_t *pool, char *filename, size_t len);

/**
 * Close specified statfile
 * @param pool statfile pool object
 * @param filename name of statfile to close
 * @param remove_hash remove filename from opened files hash also
 * @return 0 if file was closed and -1 if statfile was not opened
 */
int statfile_pool_close (statfile_pool_t *pool, char *filename, gboolean remove_hash);

/**
 * Delete statfile pool and close all attached statfiles
 * @param pool statfile pool object
 */
void statfile_pool_delete (statfile_pool_t *pool);

/**
 * Lock specified file for exclusive use (eg. learning)
 * @param pool statfile pool object
 * @param filename name of statfile
 */
void statfile_pool_lock_file (statfile_pool_t *pool, char *filename);

/**
 * Unlock specified file
 * @param pool statfile pool object
 * @param filename name of statfile
 */
void statfile_pool_unlock_file (statfile_pool_t *pool, char *filename);

/**
 * Get block from statfile with h1 and h2 values, use time argument for current time
 * @param pool statfile pool object
 * @param filename name of statfile
 * @param h1 h1 in file
 * @param h2 h2 in file
 * @param now current time
 * @return block value or 0 if block is not found
 */
float statfile_pool_get_block (statfile_pool_t *pool, char *filename, uint32_t h1, uint32_t h2, time_t now);

/**
 * Set specified block in statfile
 * @param pool statfile pool object
 * @param filename name of statfile
 * @param h1 h1 in file
 * @param h2 h2 in file
 * @param now current time
 * @param value value of block
 */
void statfile_pool_set_block (statfile_pool_t *pool, char *filename, uint32_t h1, uint32_t h2, time_t now, float value);

/**
 * Check whether statfile is opened
 * @param pool statfile pool object
 * @param filename name of statfile
 * @return TRUE if specified statfile is opened and FALSE otherwise
 */
gboolean statfile_pool_is_open (statfile_pool_t *pool, char *filename);

#endif
