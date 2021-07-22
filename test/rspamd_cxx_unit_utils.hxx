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

/* Detached unit tests for the utils */

#ifndef RSPAMD_RSPAMD_CXX_UNIT_UTILS_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_UTILS_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libmime/mime_headers.h"

#include <vector>
#include <utility>
#include <string>

TEST_SUITE("rspamd_utils") {

TEST_CASE("rspamd_strip_smtp_comments_inplace")
{
	std::vector<std::pair<std::string, std::string>> cases{
			{"abc",                    "abc"},
			{"abc(foo)",               "abc"},
			{"abc(foo()",              "abc"},
			{"abc(foo))",              "abc)"},
			{"abc(foo(bar))",          "abc"},
			{"(bar)abc(foo)",          "abc"},
			{"ab(ololo)c(foo)",        "abc"},
			{"ab(olo\\)lo)c(foo)",     "abc"},
			{"ab(trol\\\1lo)c(foo)",   "abc"},
			{"\\ab(trol\\\1lo)c(foo)", "abc"},
			{"",                       ""},
	};

	for (const auto &c : cases) {
		SUBCASE (("strip comments in " + c.first).c_str()) {
			auto *cpy = new char[c.first.size()];
			memcpy(cpy, c.first.data(), c.first.size());
			auto nlen = rspamd_strip_smtp_comments_inplace(cpy, c.first.size());
			CHECK(std::string{cpy, nlen} == c.second);
			delete[] cpy;
		}
	}
}

}

#endif
