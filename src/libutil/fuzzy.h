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
	gchar hash_pipe[FUZZY_HASHLEN];     /**< result hash					*/
	guint32 block_size;                 /**< current blocksize				*/
	guint32 rh;                         /**< roll hash value				*/
	guint32 h;                              /**< hash of block					*/
	guint32 hi;                         /**< current index in hash pipe		*/
} fuzzy_hash_t;

struct mime_text_part;

/**
 * Calculate fuzzy hash for specified string
 * @param in input string
 * @param pool pool object
 * @return fuzzy_hash object allocated in pool
 */
fuzzy_hash_t * fuzzy_init (f_str_t *in, rspamd_mempool_t *pool);
/**
 * Calculate fuzzy hash for specified byte array
 * @param in input string
 * @param pool pool object
 * @return fuzzy_hash object allocated in pool
 */
fuzzy_hash_t * fuzzy_init_byte_array (GByteArray *in, rspamd_mempool_t *pool);

/**
 * Calculate fuzzy hash for specified text part
 * @param part text part object
 * @param pool pool object
 * @param max_diff maximum text length to use diff algorithm in comparasions
 * @return fuzzy_hash object allocated in pool
 */
void fuzzy_init_part (struct mime_text_part *part,
	rspamd_mempool_t *pool,
	gsize max_diff);

/**
 * Compare score of difference between two hashes
 * @param h1 first hash
 * @param h2 second hash
 * @return result in percents 0 - different hashes, 100 - identical hashes
 */
gint fuzzy_compare_hashes (fuzzy_hash_t *h1, fuzzy_hash_t *h2);

/*
 * Compare two text parts and return percents of difference
 */
gint fuzzy_compare_parts (struct mime_text_part *p1, struct mime_text_part *p2);

/*
 * Calculate levenstein distance between two strings. Note: this algorithm should be used
 * only for short texts - it runs too slow on long ones.
 */
guint32 lev_distance (gchar *s1, gint len1, gchar *s2, gint len2);


#endif
