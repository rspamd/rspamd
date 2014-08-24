/* Copyright (c) 2014, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
	void *xxh = XXH32_init(0xdead);	\
	unsigned char *p = (unsigned char *)key, t;	\
	for (unsigned int i = 0; i < keylen; i ++) {	\
		t = g_ascii_tolower(p[i]);	\
		XXH32_update(xxh, &t, 1);	\
	}	\
	hashv = XXH32_digest(xxh);	\
	bkt = (hashv) & (num_bkts-1);	\
} while (0)
#define HASH_KEYCMP(a,b,len) strncasecmp(a,b,len)
#endif

#include "uthash.h"

#endif /* UTHASH_STRCASE_H_ */
