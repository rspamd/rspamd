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

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"
#include "mime_string.hxx"
#include "unicode/uchar.h"

TEST_SUITE("mime_string") {
using namespace rspamd::mime;
TEST_CASE("mime_string unfiltered ctors")
{
	SUBCASE("empty") {
		mime_string st;
		CHECK(st.size() == 0);
		CHECK(st == "");
	}
	SUBCASE("unfiltered valid") {
		mime_string st{std::string_view("abcd")};
		CHECK(st == "abcd");
	}
	SUBCASE("unfiltered zero character") {
		mime_string st{"abc\0d", 5};
		CHECK(st.has_zeroes());
		CHECK(st == "abcd");
	}
	SUBCASE("unfiltered invalid character - middle") {
		mime_string st{std::string("abc\234d")};
		CHECK(st.has_invalid());
		CHECK(st == "abc\uFFFDd");
	}
	SUBCASE("unfiltered invalid character - end") {
		mime_string st{std::string("abc\234")};
		CHECK(st.has_invalid());
		CHECK(st == "abc\uFFFD");
	}
	SUBCASE("unfiltered invalid character - start") {
		mime_string st{std::string("\234abc")};
		CHECK(st.has_invalid());
		CHECK(st == "\uFFFDabc");
	}
}

TEST_CASE("mime_string filtered ctors")
{
	auto print_filter = [](UChar32 inp) -> UChar32 {
		if (!u_isprint(inp)) {
			return 0;
		}

		return inp;
	};

	auto tolower_filter = [](UChar32 inp) -> UChar32 {
		return u_tolower(inp);
	};

	SUBCASE("empty") {
		mime_string st{std::string_view(""), tolower_filter};
		CHECK(st.size() == 0);
		CHECK(st == "");
	}
	SUBCASE("filtered valid") {
		mime_string st{std::string("AbCdУ"), tolower_filter};
		CHECK(st == "abcdу");
	}
	SUBCASE("filtered invalid + filtered") {
		mime_string st{std::string("abcd\234\1"), print_filter};
		CHECK(st == "abcd\uFFFD");
	}
}
TEST_CASE("mime_string assign")
{
	SUBCASE("assign from valid") {
		mime_string st;

		CHECK(st.assign_if_valid(std::string("test")));
		CHECK(st == "test");
	}
	SUBCASE("assign from invalid") {
		mime_string st;

		CHECK(!st.assign_if_valid(std::string("test\234t")));
		CHECK(st == "");
	}
}

TEST_CASE("mime_string iterators")
{

	SUBCASE("unfiltered iterator ascii") {
		auto in = std::string("abcd");
		mime_string st{in};
		CHECK(st == "abcd");

		int i = 0;
		for (auto &&c : st) {
			CHECK(c == in[i++]);
		}
	}

	SUBCASE("unfiltered iterator utf8") {
		auto in = std::string("тест");
		UChar32 ucs[4] = {1090, 1077, 1089, 1090};
		mime_string st{in};
		CHECK(st == "тест");

		int i = 0;
		for (auto &&c : st) {
			CHECK(c == ucs[i++]);
		}
		CHECK(i == sizeof(ucs) / sizeof(ucs[0]));
	}

	SUBCASE("unfiltered raw iterator ascii") {
		auto in = std::string("abcd");
		mime_string st{in};
		CHECK(st == "abcd");

		int i = 0;
		for (auto it = st.raw_begin(); it != st.raw_end(); ++it) {
			CHECK(*it == in[i++]);
		}
	}

	SUBCASE("unfiltered raw iterator utf8") {
		auto in = std::string("тест");
		mime_string st{in};
		CHECK(st == "тест");

		int i = 0;
		for (auto it = st.raw_begin(); it != st.raw_end(); ++it) {
			CHECK(*it == in[i++]);
		}
		CHECK(i == in.size());
	}
}
}