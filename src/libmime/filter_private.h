//
// Created by Vsevolod Stakhov on 2019-01-14.
//

#ifndef RSPAMD_FILTER_PRIVATE_H
#define RSPAMD_FILTER_PRIVATE_H

#include "filter.h"
#include "contrib/libucl/khash.h"

KHASH_MAP_INIT_STR (rspamd_options_hash, struct rspamd_symbol_option *);
/**
 * Result of metric processing
 */
KHASH_MAP_INIT_STR (rspamd_symbols_hash, struct rspamd_symbol_result);
#if UINTPTR_MAX <= UINT_MAX
/* 32 bit */
#define rspamd_ptr_hash_func(key) (khint32_t)(((uintptr_t)(key))>>1)
#else
/* likely 64 bit */
#define rspamd_ptr_hash_func(key) (khint32_t)(((uintptr_t)(key))>>3)
#endif
#define rspamd_ptr_equal_func(a, b) ((a) == (b))
KHASH_INIT (rspamd_symbols_group_hash,
		void *,
		double,
		1,
		rspamd_ptr_hash_func,
		rspamd_ptr_equal_func);

#endif //RSPAMD_FILTER_PRIVATE_H
