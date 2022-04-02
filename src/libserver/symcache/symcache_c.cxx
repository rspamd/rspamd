/*-
 * Copyright 2022 Vsevolod Stakhov
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

#include "symcache_internal.hxx"

/**
 * C API for symcache
 */

#define C_API_SYMCACHE(ptr) (reinterpret_cast<rspamd::symcache::symcache *>(ptr))
#define C_API_SYMCACHE_ITEM(ptr) (reinterpret_cast<rspamd::symcache::cache_item *>(ptr))

void
rspamd_symcache_destroy (struct rspamd_symcache *cache)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	delete real_cache;
}

struct rspamd_symcache*
rspamd_symcache_new (struct rspamd_config *cfg)
{
	auto *ncache = new rspamd::symcache::symcache(cfg);

	return (struct rspamd_symcache*)ncache;
}

gboolean
rspamd_symcache_init (struct rspamd_symcache *cache)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	return real_cache->init();
}
