/*
 * Copyright 2026 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Runtime configuration of whichever allocator the build is using.
 *
 * The symbols below are interposition hooks: the allocator runtime looks them up
 * in the dynamic linker's global scope and uses whatever definition it finds
 * first. They live in librspamd-server rather than in src/rspamd.c on purpose.
 * An executable exports nothing unless it is linked with -rdynamic, whereas a
 * shared library always exports its symbols, so keeping them here makes them
 * effective for every rspamd binary (rspamd, rspamadm, rspamc, unit tests)
 * instead of just the daemon.
 */

#include "config.h"

#ifdef WITH_JEMALLOC
/*
 * Tune jemalloc for single-threaded, multi-process architecture:
 * - narenas:1 — one arena is sufficient since workers are single-threaded
 * - dirty_decay_ms:5000 — return dirty pages to OS faster than default (10s)
 * - muzzy_decay_ms:30000 — hold muzzy (MADV_FREE) pages for 30s before release
 *
 * libjemalloc carries its own weak malloc_conf, and the dynamic linker takes the
 * first definition in the lookup scope regardless of binding, so this only wins
 * as long as librspamd-server precedes libjemalloc in DT_NEEDED order. That
 * ordering is what cmake/Jemalloc.cmake maintains.
 *
 * Effective values can be inspected with `rspamadm memstat`, which reads them
 * back through mallctl("opt.narenas") and friends.
 */
const char *malloc_conf = "narenas:1,dirty_decay_ms:5000,muzzy_decay_ms:30000";
#endif
