/*
 * Copyright 2024 Vsevolod Stakhov
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

//
// Created by Vsevolod Stakhov on 09/02/2024.
//

#ifndef RSPAMD_STRING_HXX
#define RSPAMD_STRING_HXX

#include <stringzilla/stringzilla.hpp>
#include <fmt/core.h>
#include <string_view>
#include <string>

namespace sz = ashvardanian::stringzilla;
using sz::literals::operator""_sz;

template<>
struct fmt::formatter<sz::string_view> : formatter<std::string_view> {
};

template<>
struct fmt::formatter<sz::string> : formatter<std::string_view> {
};

#endif//RSPAMD_STRING_HXX
