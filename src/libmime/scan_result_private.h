//
// Created by Vsevolod Stakhov on 2019-01-14.
//

#ifndef RSPAMD_SCAN_RESULT_PRIVATE_H
#define RSPAMD_SCAN_RESULT_PRIVATE_H

#include "scan_result.h"
#include "contrib/libucl/khash.h"

#ifdef  __cplusplus
extern "C" {
#endif

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

#ifdef  __cplusplus
}
#endif

#endif //RSPAMD_SCAN_RESULT_PRIVATE_H
