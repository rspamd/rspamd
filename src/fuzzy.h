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
	gchar hash_pipe[FUZZY_HASHLEN];		/**< result hash					*/
	guint32 block_size;					/**< current blocksize				*/
	guint32 rh;							/**< roll hash value				*/
	guint32 h;								/**< hash of block					*/
	guint32 hi;							/**< current index in hash pipe		*/
} fuzzy_hash_t;

struct mime_text_part;

/**
 * Calculate fuzzy hash for specified string
 * @param in input string
 * @param pool pool object
 * @return fuzzy_hash object allocated in pool
 */
fuzzy_hash_t * fuzzy_init (f_str_t *in, memory_pool_t *pool);
fuzzy_hash_t * fuzzy_init_byte_array (GByteArray *in, memory_pool_t *pool);
void fuzzy_init_part (struct mime_text_part *part, memory_pool_t *pool);

gint fuzzy_compare_parts (struct mime_text_part *p1, struct mime_text_part *p2);

/**
 * Compare score of difference between two hashes 
 * @param h1 first hash
 * @param h2 second hash
 * @return result in percents 0 - different hashes, 100 - identical hashes 
 */
gint fuzzy_compare_hashes (fuzzy_hash_t *h1, fuzzy_hash_t *h2);

guint32 lev_distance (gchar *s1, gint len1, gchar *s2, gint len2);


#endif
