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

#include "xxhash.h"


/* Utils for uthash tuning */
#ifndef HASH_CASELESS
#define HASH_FUNCTION(key,keylen,num_bkts,hashv,bkt) do {\
	hashv = XXH32(key, keylen, 0); \
	bkt = (hashv) & (num_bkts-1); \
} while (0)

#define HASH_KEYCMP(a,b,len) memcmp(a,b,len)
#else
#define HASH_FUNCTION(key,keylen,num_bkts,hashv,bkt) do {\
	XXH32_state_t xxh; \
	XXH32_reset(&xxh, 0xdead);	\
	unsigned char *p = (unsigned char *)key, t;	\
	for (unsigned int i = 0; i < keylen; i ++) {	\
		t = g_ascii_tolower(p[i]);	\
		XXH32_update(&xxh, &t, 1);	\
	}	\
	hashv = XXH32_digest(&xxh);	\
	bkt = (hashv) & (num_bkts-1);	\
} while (0)
#define HASH_KEYCMP(a,b,len) strncasecmp(a,b,len)
#endif

#include "uthash.h"

#endif /* UTHASH_STRCASE_H_ */
