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


/* Utils for uthash tuning */
#ifndef HASH_CASELESS
#define HASH_FUNCTION(key,keylen,num_bkts,hashv,bkt) do {\
	hashv = mum(key, keylen, 0xdeadbabe); \
	bkt = (hashv) & (num_bkts-1); \
} while (0)

#define HASH_KEYCMP(a,b,len) memcmp(a,b,len)
#else
#define HASH_FUNCTION(key,keylen,num_bkts,hashv,bkt) do {\
	unsigned len = keylen; \
	unsigned leftover = keylen % 8; \
	unsigned fp, i; \
	const uint8_t* s = (const uint8_t*)key; \
	union { \
		struct { \
			unsigned char c1, c2, c3, c4, c5, c6, c7, c8; \
		} c; \
		uint64_t pp; \
	} u; \
	uint64_t r; \
	fp = len - leftover; \
	r = 0xdeadbabe; \
	for (i = 0; i != fp; i += 8) { \
		u.c.c1 = s[i], u.c.c2 = s[i + 1], u.c.c3 = s[i + 2], u.c.c4 = s[i + 3]; \
		u.c.c5 = s[i + 4], u.c.c6 = s[i + 5], u.c.c7 = s[i + 6], u.c.c8 = s[i + 7]; \
		u.c.c1 = lc_map[u.c.c1]; \
		u.c.c2 = lc_map[u.c.c2]; \
		u.c.c3 = lc_map[u.c.c3]; \
		u.c.c4 = lc_map[u.c.c4]; \
		u.c.c1 = lc_map[u.c.c5]; \
		u.c.c2 = lc_map[u.c.c6]; \
		u.c.c3 = lc_map[u.c.c7]; \
		u.c.c4 = lc_map[u.c.c8]; \
		r = mum_hash_step (r, u.pp); \
	} \
	u.pp = 0; \
	switch (leftover) { \
	case 7: \
		u.c.c7 = lc_map[(unsigned char)s[i++]]; \
	case 6: \
		u.c.c6 = lc_map[(unsigned char)s[i++]]; \
	case 5: \
		u.c.c5 = lc_map[(unsigned char)s[i++]]; \
	case 4: \
		u.c.c4 = lc_map[(unsigned char)s[i++]]; \
	case 3: \
		u.c.c3 = lc_map[(unsigned char)s[i++]]; \
	case 2: \
		u.c.c2 = lc_map[(unsigned char)s[i++]]; \
	case 1: \
		u.c.c1 = lc_map[(unsigned char)s[i]]; \
		r = mum_hash_step (r, u.pp); \
		break; \
	} \
	hashv = mum_hash_finish (r); \
	bkt = (hashv) & (num_bkts-1); \
} while (0)
#define HASH_KEYCMP(a,b,len) rspamd_lc_cmp(a,b,len)
#endif

#include "uthash.h"

#endif /* UTHASH_STRCASE_H_ */
