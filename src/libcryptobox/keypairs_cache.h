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
#ifndef KEYPAIRS_CACHE_H_
#define KEYPAIRS_CACHE_H_

#include "config.h"
#include "keypair.h"


#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_keypair_cache;

/**
 * Create new keypair cache of the specified size
 * @param max_items defines maximum count of elements in the cache
 * @return new cache
 */
struct rspamd_keypair_cache *rspamd_keypair_cache_new (guint max_items);


/**
 * Process local and remote keypair setting beforenm value as appropriate
 * @param c cache of keypairs
 * @param lk local key
 * @param rk remote key
 */
void rspamd_keypair_cache_process (struct rspamd_keypair_cache *c,
								   struct rspamd_cryptobox_keypair *lk,
								   struct rspamd_cryptobox_pubkey *rk);

/**
 * Destroy old keypair cache
 * @param c cache object
 */
void rspamd_keypair_cache_destroy (struct rspamd_keypair_cache *c);

#ifdef  __cplusplus
}
#endif

#endif /* KEYPAIRS_CACHE_H_ */
