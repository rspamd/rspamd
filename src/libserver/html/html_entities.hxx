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

#ifndef RSPAMD_HTML_ENTITIES_H
#define RSPAMD_HTML_ENTITIES_H
#pragma once

#include <utility>
#include <string>

namespace rspamd::html {

auto decode_html_entitles_inplace(char *s, std::size_t len, bool norm_spaces = false) -> std::size_t ;
auto decode_html_entitles_inplace(std::string &st) -> void;

}

#endif
