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

#define U_CHARSET_IS_UTF8 1
#include <unicode/utypes.h>
#include <unicode/utf8.h>
#include <unicode/uchar.h>
#include <utility>
#include <string>

#include "utf8_util.h"
#include "str_util.h"

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

char *
rspamd_string_unicode_trim_inplace (char *str, size_t *len)
{
	auto *p = str, *end = str + *len;
	auto i = 0;

	while (i < *len) {
		UChar32 uc;
		auto prev_i = i;

		U8_NEXT(p, i, *len, uc);

		if (!u_isUWhiteSpace(uc) && !IS_ZERO_WIDTH_SPACE(uc)) {
			i = prev_i;
			break;
		}
	}

	p += i;
	(*len) -= i;
	i = end - p;
	auto *ret = p;

	if (i > 0) {

		while (i > 0) {
			UChar32 uc;
			auto prev_i = i;

			U8_PREV(p, 0, i, uc);

			if (!u_isUWhiteSpace(uc) && !IS_ZERO_WIDTH_SPACE(uc)) {
				i = prev_i;
				break;
			}
		}

		*len = i;
	}

	return ret;
}

TEST_SUITE("utf8 utils") {
	TEST_CASE("utf8 trim") {
		std::pair<const char *, const char *> cases[] = {
				{" \u200B""abc ", "abc"},
				{"   ",  ""},
				{"   a", "a"},
				{"a   ", "a"},
				{"a a",  "a a"},
				{"abc",  "abc"},
				{"a ", "a"},
				{"   abc      ", "abc"},
				{" abc ", "abc"},
				{" \xE2\x80\x8B""a\xE2\x80\x8B""bc ", "a\xE2\x80\x8B""bc"},
				{" \xE2\x80\x8B""abc\xE2\x80\x8B ", "abc"},
				{" \xE2\x80\x8B""abc \xE2\x80\x8B  ", "abc"},
		};

		for (const auto &c : cases) {
			std::string cpy{c.first};
			auto ns = cpy.size();
			auto *nstart = rspamd_string_unicode_trim_inplace(cpy.data(), &ns);
			std::string res{nstart, ns};
			CHECK(res == std::string{c.second});
		}
	}
}


