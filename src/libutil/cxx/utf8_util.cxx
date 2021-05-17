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
#include <unicode/normalizer2.h>
#include <unicode/schriter.h>
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



enum rspamd_normalise_result
rspamd_normalise_unicode_inplace(char *start, size_t *len)
{
	UErrorCode uc_err = U_ZERO_ERROR;
	const auto *nfkc_norm = icu::Normalizer2::getNFKCInstance(uc_err);
	static icu::UnicodeSet zw_spaces{};

	if (!zw_spaces.isFrozen()) {
		/* Add zw spaces to the set */
		zw_spaces.add(0x200B);
		zw_spaces.add(0x200C);
		zw_spaces.add(0x200D);
		zw_spaces.add(0xFEF);
		zw_spaces.add(0x00AD);
		zw_spaces.freeze();
	}

	int ret = RSPAMD_UNICODE_NORM_NORMAL;

	g_assert (U_SUCCESS (uc_err));

	auto uc_string = icu::UnicodeString::fromUTF8(icu::StringPiece(start, *len));
	auto is_normal = nfkc_norm->quickCheck(uc_string, uc_err);

	if (!U_SUCCESS (uc_err)) {
		return RSPAMD_UNICODE_NORM_ERROR;
	}

	/* Filter zero width spaces and push resulting string back */
	const auto filter_zw_spaces_and_push_back = [&](const icu::UnicodeString &input) -> size_t {
		icu::StringCharacterIterator it{input};
		size_t i = 0;

		while(it.hasNext()) {
			auto uc = it.next32PostInc();

			if (zw_spaces.contains(uc)) {
				ret |= RSPAMD_UNICODE_NORM_ZERO_SPACES;
			}
			else {
				UBool err = 0;
				U8_APPEND(start, i, *len, uc, err);

				if (err) {
					ret = RSPAMD_UNICODE_NORM_ERROR;

					return i;
				}
			}
		}

		return i;
	};

	if (is_normal != UNORM_YES) {
		/* Need to normalise */
		ret |= RSPAMD_UNICODE_NORM_UNNORMAL;

		auto normalised = nfkc_norm->normalize(uc_string, uc_err);

		if (!U_SUCCESS (uc_err)) {
			return RSPAMD_UNICODE_NORM_ERROR;
		}

		*len = filter_zw_spaces_and_push_back(normalised);
	}
	else {
		*len = filter_zw_spaces_and_push_back(uc_string);
	}

	return static_cast<enum rspamd_normalise_result>(ret);
}

TEST_SUITE("utf8 utils") {
	TEST_CASE("utf8 normalise") {
		std::tuple<const char *, const char *, int> cases[] = {
				{"abc", "abc", RSPAMD_UNICODE_NORM_NORMAL},
				{"тест", "тест", RSPAMD_UNICODE_NORM_NORMAL},
				/* Zero width spaces */
				{"\xE2\x80\x8B""те""\xE2\x80\x8B""ст", "тест", RSPAMD_UNICODE_NORM_ZERO_SPACES},
				/* Special case of diacritic */
				{"13_\u0020\u0308\u0301\u038e\u03ab", "13_ ̈́ΎΫ", RSPAMD_UNICODE_NORM_UNNORMAL},
				/* Same with zw spaces */
				{"13\u200C_\u0020\u0308\u0301\u038e\u03ab\u200D", "13_ ̈́ΎΫ",
	 							RSPAMD_UNICODE_NORM_UNNORMAL|RSPAMD_UNICODE_NORM_ZERO_SPACES},
		};

		for (const auto &c : cases) {
			std::string cpy{std::get<0>(c)};
			auto ns = cpy.size();
			auto res = rspamd_normalise_unicode_inplace(cpy.data(), &ns);
			cpy.resize(ns);
			CHECK(cpy == std::string(std::get<1>(c)));
			CHECK(res == std::get<2>(c));
		}
	}
}