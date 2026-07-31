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
 * Default sanitizer runtime options.
 *
 * This file is compiled into every rspamd executable rather than into
 * librspamd-server. The sanitizer runtime resolves __asan_default_options
 * through the dynamic linker's global lookup scope and takes the first
 * definition it finds regardless of binding, and libasan carries its own weak
 * fallback, so only the executable - which is always at position 0 of that scope
 * - is guaranteed to win.
 */

#include "config.h"

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if (defined(__has_feature) && __has_feature(address_sanitizer)) || defined(ADDRESS_SANITIZER) || defined(__SANITIZE_ADDRESS__)
/*
 * detect_odr_violation defaults to 2, which flags every duplicated global with
 * vague linkage. Constants such as std::piecewise_construct legitimately end up
 * in more than one of our shared objects, and the resulting report aborts the
 * process from a library constructor before main() is ever reached. Level 1
 * keeps the check for the case that actually indicates a bug: two definitions of
 * different size.
 *
 * ASAN_OPTIONS in the environment still overrides this.
 */
const char *__asan_default_options(void);

const char *__asan_default_options(void)
{
	return "detect_odr_violation=1";
}
#endif
