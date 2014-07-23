#ifndef __RSPAMD_BLOOM_H__
#define __RSPAMD_BLOOM_H__

#include "config.h"

typedef struct rspamd_bloom_filter_s {
	size_t asize;
	gchar *a;
	size_t nfuncs;
	guint32 *seeds;
} rspamd_bloom_filter_t;


/*
 * Some random uint32 seeds for hashing
 */
#define RSPAMD_DEFAULT_BLOOM_HASHES 8, 0x61782caaU, 0x79ab8141U, 0xe45ee2d1U, \
	0xf97542d1U, 0x1e2623edU, 0xf5a23cfeU, 0xa41b2508U, 0x85abdce8U

/*
 * Create new bloom filter
 * @param size length of bloom buffer
 * @param nfuncs number of hash functions
 * @param ... hash functions list
 */
rspamd_bloom_filter_t * rspamd_bloom_create (size_t size, size_t nfuncs, ...);

/*
 * Destroy bloom filter
 */
void rspamd_bloom_destroy (rspamd_bloom_filter_t * bloom);

/*
 * Add a string to bloom filter
 */
gboolean rspamd_bloom_add (rspamd_bloom_filter_t * bloom, const gchar *s);

/*
 * Delete a string from bloom filter
 */
gboolean rspamd_bloom_del (rspamd_bloom_filter_t * bloom, const gchar *s);

/*
 * Check whether this string is in bloom filter (algorithm produces FALSE-POSITIVES, so result must be checked if it is positive)
 */
gboolean rspamd_bloom_check (rspamd_bloom_filter_t * bloom, const gchar *s);

#endif
