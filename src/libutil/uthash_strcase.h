/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef UTHASH_STRCASE_H_
#define UTHASH_STRCASE_H_

#ifdef UTHASH_H
#error Invalid include order: uthash is already included
#endif

#include "libcryptobox/cryptobox.h"
#include "libutil/util.h"

/* Utils for uthash tuning */
#ifndef HASH_CASELESS
#define HASH_FUNCTION(key,keylen,num_bkts,hashv,bkt) do {\
	hashv = (__typeof (hashv))rspamd_cryptobox_fast_hash(key, keylen, rspamd_hash_seed ()); \
	bkt = (hashv) & (num_bkts-1); \
} while (0)

#define HASH_KEYCMP(a,b,len) memcmp(a,b,len)
#else
#define HASH_FUNCTION(key,keylen,num_bkts,hashv,bkt) do {\
	unsigned _len = keylen; \
	rspamd_cryptobox_fast_hash_state_t _hst; \
	unsigned _leftover = keylen % 8; \
	unsigned _fp, _i; \
	const uint8_t* _s = (const uint8_t*)(key); \
	union { \
		struct { \
			unsigned char c1, c2, c3, c4, c5, c6, c7, c8; \
		} c; \
		uint64_t pp; \
	} _u; \
	_fp = _len - _leftover; \
	rspamd_cryptobox_fast_hash_init (&_hst, rspamd_hash_seed ()); \
	for (_i = 0; _i != _fp; _i += 8) { \
		_u.c.c1 = _s[_i], _u.c.c2 = _s[_i + 1], _u.c.c3 = _s[_i + 2], _u.c.c4 = _s[_i + 3]; \
		_u.c.c5 = _s[_i + 4], _u.c.c6 = _s[_i + 5], _u.c.c7 = _s[_i + 6], _u.c.c8 = _s[_i + 7]; \
		_u.c.c1 = lc_map[_u.c.c1]; \
		_u.c.c2 = lc_map[_u.c.c2]; \
		_u.c.c3 = lc_map[_u.c.c3]; \
		_u.c.c4 = lc_map[_u.c.c4]; \
		_u.c.c1 = lc_map[_u.c.c5]; \
		_u.c.c2 = lc_map[_u.c.c6]; \
		_u.c.c3 = lc_map[_u.c.c7]; \
		_u.c.c4 = lc_map[_u.c.c8]; \
		rspamd_cryptobox_fast_hash_update (&_hst, &_u, sizeof (_u)); \
	} \
	_u.pp = 0; \
	switch (_leftover) { \
	case 7: \
		/* fallthrough */ _u.c.c7 = lc_map[(unsigned char)_s[_i++]]; \
	case 6: \
		/* fallthrough */ _u.c.c6 = lc_map[(unsigned char)_s[_i++]]; \
	case 5: \
		/* fallthrough */ _u.c.c5 = lc_map[(unsigned char)_s[_i++]]; \
	case 4: \
		/* fallthrough */ _u.c.c4 = lc_map[(unsigned char)_s[_i++]]; \
	case 3: \
		/* fallthrough */ _u.c.c3 = lc_map[(unsigned char)_s[_i++]]; \
	case 2: \
		/* fallthrough */ _u.c.c2 = lc_map[(unsigned char)_s[_i++]]; \
	case 1: \
		/* fallthrough */ _u.c.c1 = lc_map[(unsigned char)_s[_i]]; \
		rspamd_cryptobox_fast_hash_update (&_hst, &_u, sizeof (_u)); \
		break; \
	} \
	hashv = (__typeof (hashv))rspamd_cryptobox_fast_hash_final (&_hst); \
	bkt = (hashv) & (num_bkts-1); \
} while (0)
#define HASH_KEYCMP(a,b,len) rspamd_lc_cmp(a,b,len)
#endif

#include "uthash.h"

#endif /* UTHASH_STRCASE_H_ */
