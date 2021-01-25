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

#ifndef RSPAMD_CSS_TOKENISER_HXX
#define RSPAMD_CSS_TOKENISER_HXX

#include <string_view>
#include <utility>
#include "mem_pool.h"

namespace rspamd::css {

enum class css_parser_token {
	whitespace_token,
	ident_token,
	function_token,
	at_keyword_token,
	hash_token,
	string_token,
	number_token,
	url_token,
	dimension_token,
	percentage_token,
	cdo_token, /* xml open comment */
	cdc_token, /* xml close comment */
	delim_token,
	obrace_token, /* ( */
	ebrace_token, /* ) */
	osqbrace_token, /* [ */
	esqbrace_token, /* ] */
	comma_token,
	colon_token,
	semicolon_token,
	eof_token,
};

class css_tokeniser {
public:
	css_tokeniser() = delete;
	css_tokeniser(rspamd_mempool_t *pool, const std::string_view &sv) :
			input(sv), offset(0), pool(pool) {}

	auto next_token(void) -> std::pair<css_parser_token, std::string_view>;
private:
	std::string_view input;
	std::size_t offset;
	rspamd_mempool_t *pool;
};

}


#endif //RSPAMD_CSS_TOKENISER_HXX
