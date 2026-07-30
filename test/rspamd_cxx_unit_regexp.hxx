/*
 * Copyright 2026 Vsevolod Stakhov
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

#ifndef RSPAMD_RSPAMD_CXX_UNIT_REGEXP_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_REGEXP_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

extern "C" {
#include "libutil/regexp.h"
}

#include <cstring>
#include <string>

/*
 * `rspamd_regexp_new_len` takes a pointer plus a length, so the pattern is not
 * required to be NULL terminated: callers such as the composites parser and the
 * symcache delayed symbols hand it a slice of a larger buffer. These tests pin
 * that contract - the identity of a regexp must be derived from exactly `len`
 * bytes and nothing that happens to follow them in memory.
 */
TEST_SUITE("regexp bounded patterns")
{
	static bool same_id(rspamd_regexp_t * a, rspamd_regexp_t * b)
	{
		return rspamd_regexp_equal(rspamd_regexp_get_id(a),
								   rspamd_regexp_get_id(b));
	}

	TEST_CASE("id ignores the bytes past len")
	{
		/* The slice is the same regexp as the standalone pattern */
		const char *slice = "/foo/,/bar/";
		auto *bounded = rspamd_regexp_new_len(slice, 5, nullptr, nullptr);
		auto *terminated = rspamd_regexp_new("/foo/", nullptr, nullptr);

		REQUIRE(bounded != nullptr);
		REQUIRE(terminated != nullptr);
		CHECK(std::string(rspamd_regexp_get_pattern(bounded)) == "foo");
		CHECK(same_id(bounded, terminated));

		rspamd_regexp_unref(bounded);
		rspamd_regexp_unref(terminated);
	}

	TEST_CASE("different lengths at the same address are distinct regexps")
	{
		const char *buf = "/foo/,/bar/";
		auto *short_re = rspamd_regexp_new_len(buf, 5, nullptr, nullptr);
		auto *long_re = rspamd_regexp_new_len(buf, strlen(buf), nullptr, nullptr);

		REQUIRE(short_re != nullptr);
		REQUIRE(long_re != nullptr);
		CHECK(std::string(rspamd_regexp_get_pattern(short_re)) == "foo");
		CHECK(std::string(rspamd_regexp_get_pattern(long_re)) == "foo/,/bar");
		/* Same id would make the two collide in the regexp cache */
		CHECK_FALSE(same_id(short_re, long_re));

		rspamd_regexp_unref(short_re);
		rspamd_regexp_unref(long_re);
	}

	TEST_CASE("pattern is never read past len")
	{
		/*
		 * Exact sized allocations with no terminator: any read beyond `len`
		 * is a heap overflow that ASAN/valgrind builds will catch.
		 */
		const std::string good{"/foo/i"};
		auto *raw = (char *) g_malloc(good.size());
		memcpy(raw, good.data(), good.size());
		auto *re = rspamd_regexp_new_len(raw, good.size(), nullptr, nullptr);
		CHECK(re != nullptr);

		if (re) {
			CHECK(std::string(rspamd_regexp_get_pattern(re)) == "foo");
			rspamd_regexp_unref(re);
		}

		g_free(raw);

		/* The same holds for the paths that bail out with an error */
		GError *err = nullptr;
		const std::string unterminated{"/foo"};
		raw = (char *) g_malloc(unterminated.size());
		memcpy(raw, unterminated.data(), unterminated.size());
		CHECK(rspamd_regexp_new_len(raw, unterminated.size(), nullptr, &err) == nullptr);
		CHECK(err != nullptr);
		g_clear_error(&err);
		g_free(raw);

		/* ... and for an invalid flag reported against explicit flags */
		const std::string flagged{"/foo/"};
		raw = (char *) g_malloc(flagged.size());
		memcpy(raw, flagged.data(), flagged.size());
		CHECK(rspamd_regexp_new_len(raw, flagged.size(), "Z", &err) == nullptr);
		CHECK(err != nullptr);
		g_clear_error(&err);
		g_free(raw);
	}
}

#endif
