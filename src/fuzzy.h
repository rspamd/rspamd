/**
 * @file fuzzy.h
 * Fuzzy hashes API
 */

#ifndef RSPAMD_FUZZY_H
#define RSPAMD_FUZZY_H

#include "config.h"
#include "mem_pool.h"
#include "fstring.h"

#define FUZZY_HASHLEN 64

typedef struct fuzzy_hash_s {
	char hash_pipe[FUZZY_HASHLEN];			/**< result hash					*/
	uint32_t block_size;					/**< current blocksize				*/
	uint32_t rh;							/**< roll hash value				*/
	uint32_t h;								/**< hash of block					*/
	uint32_t hi;							/**< current index in hash pipe		*/
} fuzzy_hash_t;

/**
 * Calculate fuzzy hash for specified string
 * @param in input string
 * @param pool pool object
 * @return fuzzy_hash object allocated in pool
 */
fuzzy_hash_t * fuzzy_init (f_str_t *in, memory_pool_t *pool);
fuzzy_hash_t * fuzzy_init_byte_array (GByteArray *in, memory_pool_t *pool);

/**
 * Compare score of difference between two hashes 
 * @param h1 first hash
 * @param h2 second hash
 * @return result in percents 0 - different hashes, 100 - identical hashes 
 */
int fuzzy_compare_hashes (fuzzy_hash_t *h1, fuzzy_hash_t *h2);


#endif
