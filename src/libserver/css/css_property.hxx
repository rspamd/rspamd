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

#ifndef RSPAMD_CSS_PROPERTY_HXX
#define RSPAMD_CSS_PROPERTY_HXX

#include <string>
#include "parse_error.hxx"
#include "contrib/expected/expected.hpp"

namespace rspamd::css {

/*
 * To be extended with properties that are interesting from the email
 * point of view
 */
enum class css_property_type {
	PROPERTY_FONT,
	PROPERTY_COLOR,
	PROPERTY_BGCOLOR,
	PROPERTY_BACKGROUND,
	PROPERTY_HEIGHT,
	PROPERTY_WIDTH,
	PROPERTY_DISPLAY,
	PROPERTY_VISIBILITY,
};

struct css_property {
	css_property_type type;
	static tl::expected<css_property,css_parse_error> from_bytes (const char *input,
																 size_t inlen);
};

}

/* Make properties hashable */
namespace std {
template<>
class hash<rspamd::css::css_property> {
public:
	/* Mix bits to provide slightly better distribution but being constexpr */
	constexpr size_t operator() (const rspamd::css::css_property &prop) const {
		std::size_t key = 0xdeadbeef ^static_cast<std::size_t>(prop.type);
		key = (~key) + (key << 21);
		key = key ^ (key >> 24);
		key = (key + (key << 3)) + (key << 8);
		key = key ^ (key >> 14);
		key = (key + (key << 2)) + (key << 4);
		key = key ^ (key >> 28);
		key = key + (key << 31);
		return key;
	}
};
}

#endif //RSPAMD_CSS_PROPERTY_HXX