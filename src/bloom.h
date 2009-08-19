#ifndef __RSPAMD_BLOOM_H__
#define __RSPAMD_BLOOM_H__

#include "config.h"

typedef unsigned int (*hashfunc_t) (const char *);

typedef struct bloom_filter_s {
	size_t          asize;
	unsigned char  *a;
	size_t          nfuncs;
	hashfunc_t     *funcs;
} bloom_filter_t;

/* Hash functions */
unsigned int bloom_sax_hash (const char *key);
unsigned int bloom_sdbm_hash (const char *key);
unsigned int bloom_fnv_hash (const char *key);
unsigned int bloom_rs_hash (const char *key);
unsigned int bloom_js_hash (const char *key);
unsigned int bloom_elf_hash (const char *key);
unsigned int bloom_bkdr_hash (const char *key);
unsigned int bloom_ap_hash (const char *key);

#define DEFAULT_BLOOM_HASHES 8, bloom_sax_hash, bloom_sdbm_hash, bloom_fnv_hash, bloom_rs_hash, bloom_js_hash, bloom_elf_hash, bloom_bkdr_hash, bloom_ap_hash

bloom_filter_t* bloom_create (size_t size, size_t nfuncs, ...);
void bloom_destroy (bloom_filter_t * bloom);
gboolean bloom_add (bloom_filter_t * bloom, const char *s);
gboolean bloom_del (bloom_filter_t * bloom, const char *s);
gboolean bloom_check (bloom_filter_t * bloom, const char *s);

#endif
