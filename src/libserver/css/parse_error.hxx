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

#ifndef RSPAMD_PARSE_ERROR_HXX
#define RSPAMD_PARSE_ERROR_HXX

#include <string>
#include <optional>

namespace rspamd::css {

/*
 * Generic parser errors
 */
enum class css_parse_error_type {
	PARSE_ERROR_UNKNOWN_OPTION,
	PARSE_ERROR_INVALID_SYNTAX,
	PARSE_ERROR_BAD_NESTING,
	PARSE_ERROR_NYI,
	PARSE_ERROR_UNKNOWN_ERROR,
	/* All above is treated as fatal error in parsing */
	PARSE_ERROR_NO_ERROR,
	PARSE_ERROR_EMPTY,
};

struct css_parse_error {
	css_parse_error_type type = css_parse_error_type::PARSE_ERROR_UNKNOWN_ERROR;
	std::optional<std::string> description;

	explicit css_parse_error (css_parse_error_type type, const std::string &description) :
		type(type), description(description) {}
	explicit css_parse_error (css_parse_error_type type = css_parse_error_type::PARSE_ERROR_NO_ERROR) :
			type(type) {}

	constexpr auto is_fatal(void) const -> bool {
		return type < css_parse_error_type::PARSE_ERROR_NO_ERROR;
	}
};

}
#endif //RSPAMD_PARSE_ERROR_HXX
