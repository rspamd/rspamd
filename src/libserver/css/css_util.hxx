/*-
 * Copyright 2021 Vsevolod Stakhov
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

#pragma once

#ifndef RSPAMD_CSS_UTIL_HXX
#define RSPAMD_CSS_UTIL_HXX

#include <string_view>
#include "mem_pool.h"

namespace rspamd::css {

/*
 * Unescape css escapes
 * \20AC : must be followed by a space if the next character is one of a-f, A-F, 0-9
 * \0020AC : must be 6 digits long, no space needed (but can be included)
 *
 * The result is lowercased. An escape is decoded only if the result is a name
 * character, any other escape is kept in place so that it cannot become a
 * syntax character. With in_string set the input is the content of a string
 * and every escape is decoded.
 */
std::string_view unescape_css(rspamd_mempool_t *pool,
							  const std::string_view &sv,
							  bool in_string = false);

/*
 * Returns true if the input has a backslash outside of strings and comments;
 * strings end the way the tokeniser ends them
 */
bool css_has_escape(const std::string_view &sv);

}// namespace rspamd::css

#endif//RSPAMD_CSS_UTIL_HXX
