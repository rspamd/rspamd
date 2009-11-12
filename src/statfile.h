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

/* Section types */
#define STATFILE_SECTION_COMMON 1
#define STATFILE_SECTION_HEADERS 2
#define STATFILE_SECTION_URLS 3
#define STATFILE_SECTION_REGEXP 4

/**
 * Common statfile header
 */
struct stat_file_header {
	u_char magic[3];						/**< magic signature ('r' 's' 'd') 		*/
	u_char version[2];						/**< version of statfile				*/
	u_char padding[3];						/**< padding							*/
	uint64_t create_time;					/**< create time (time_t->uint64_t)		*/
	uint64_t revision;						/**< revision number					*/
	uint64_t rev_time;						/**< revision time						*/
	u_char unused[255];						/**< some bytes that can be used in future */
};

/**
 * Section header
 */
struct stat_file_section {
	uint64_t code;							/**< section's code						*/
	uint64_t length;						/**< section's length in blocks			*/
};

/**
 * Block of data in statfile
 */
struct stat_file_block {
	uint32_t hash1;							/**< hash1 (also acts as index)			*/				
	uint32_t hash2;							/**< hash2								*/
	uint32_t last_access;					/**< last access to block since create time of file	*/
	float value; 							/**< float value 						*/
};

/**
 * Statistic file
 */
struct stat_file {
	struct stat_file_header header;			/**< header								*/
	struct stat_file_section section;		/**< first section						*/
	struct stat_file_block blocks[1];		/**< first block of data				*/
};

/**
 * Common view of statfile object
 */
typedef struct stat_file_s {
#ifdef HAVE_PATH_MAX
	char filename[PATH_MAX];				/**< name of file						*/
#else
	char filename[MAXPATHLEN];				/**< name of file						*/
#endif
	int fd;									/**< descriptor							*/
	void *map;								/**< mmaped area						*/
	off_t seek_pos;							/**< current seek position				*/
	struct stat_file_section cur_section;	/**< current section					*/
	time_t open_time;						/**< time when file was opened			*/
	time_t access_time;						/**< last access time					*/
	size_t len;								/**< length of file(in bytes)			*/
	memory_pool_mutex_t *lock;				/**< mutex								*/
} stat_file_t;

/**
 * Statfiles pool
 */
typedef struct statfile_pool_s {
	stat_file_t *files;						/**< hash table of opened files indexed by name	*/
	void **maps;							/**< shared hash table of mmaped areas indexed by name	*/
	int opened;								/**< number of opened files				*/
	size_t max;								/**< maximum size						*/
	size_t occupied;						/**< current size						*/
	memory_pool_t *pool;					/**< memory pool object					*/
	memory_pool_mutex_t *lock;				/**< mutex								*/
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
stat_file_t* statfile_pool_open (statfile_pool_t *pool, char *filename, size_t len, gboolean forced);

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
int statfile_pool_close (statfile_pool_t *pool, stat_file_t *file, gboolean keep_sorted);

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
void statfile_pool_lock_file (statfile_pool_t *pool, stat_file_t *file);

/**
 * Unlock specified file
 * @param pool statfile pool object
 * @param filename name of statfile
 */
void statfile_pool_unlock_file (statfile_pool_t *pool, stat_file_t *file);

/**
 * Get block from statfile with h1 and h2 values, use time argument for current time
 * @param pool statfile pool object
 * @param filename name of statfile
 * @param h1 h1 in file
 * @param h2 h2 in file
 * @param now current time
 * @return block value or 0 if block is not found
 */
float statfile_pool_get_block (statfile_pool_t *pool, stat_file_t *file, uint32_t h1, uint32_t h2, time_t now);

/**
 * Set specified block in statfile
 * @param pool statfile pool object
 * @param filename name of statfile
 * @param h1 h1 in file
 * @param h2 h2 in file
 * @param now current time
 * @param value value of block
 */
void statfile_pool_set_block (statfile_pool_t *pool, stat_file_t *file, uint32_t h1, uint32_t h2, time_t now, float value);

/**
 * Check whether statfile is opened
 * @param pool statfile pool object
 * @param filename name of statfile
 * @return TRUE if specified statfile is opened and FALSE otherwise
 */
stat_file_t* statfile_pool_is_open (statfile_pool_t *pool, char *filename);

/**
 * Returns current statfile section
 * @param pool statfile pool object
 * @param filename name of statfile
 * @return code of section or 0 if file is not opened
 */
uint32_t statfile_pool_get_section (statfile_pool_t *pool, stat_file_t *file);

/**
 * Go to other section of statfile
 * @param pool statfile pool object
 * @param filename name of statfile
 * @param code code of section to seek to
 * @param from_begin search for section from begin of file if true
 * @return TRUE if section was set and FALSE otherwise
 */
gboolean statfile_pool_set_section (statfile_pool_t *pool, stat_file_t *file, uint32_t code, gboolean from_begin);

/**
 * Add new section to statfile
 * @param pool statfile pool object
 * @param filename name of statfile
 * @param code code of section to seek to
 * @param length length in blocks of new section
 * @return TRUE if section was successfully added and FALSE in case of error
 */
gboolean statfile_pool_add_section (statfile_pool_t *pool, stat_file_t *file, uint32_t code, uint64_t length);


/**
 * Return code of section identified by name
 * @param name name of section
 * @return code of section or 0 if name of section is unknown
 */
uint32_t statfile_get_section_by_name (const char *name);

/**
 * Set statfile revision and revision time
 * @param pool statfile pool object
 * @param filename name of statfile
 * @param revision number of revision
 * @param time time of revision
 * @return TRUE if revision was set
 */
gboolean statfile_set_revision (stat_file_t *file, uint64_t rev, time_t time);

/**
 * Set statfile revision and revision time
 * @param pool statfile pool object
 * @param filename name of statfile
 * @param revision saved number of revision
 * @param time saved time of revision
 * @return TRUE if revision was saved in rev and time
 */
gboolean statfile_get_revision (stat_file_t *file, uint64_t *rev, time_t *time);


#endif
