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

#ifndef RSPAMD_RSPAMD_CXX_UNIT_MULTIPATTERN_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_MULTIPATTERN_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

extern "C" {
#include "libutil/multipattern.h"
}

#include <string>
#include <vector>
#include <tuple>
#include <algorithm>

/*
 * Start-of-match (SOM) tests for the multipattern engine. These assert the
 * (pattern_id, start, end) contract against hand-computed positions. Offsets
 * are byte offsets: start is 0-based inclusive, end is 0-based exclusive (one
 * past the last matched byte), so end - start is the match length. The
 * assertions are backend-agnostic and must hold whether the lookup is served
 * by hyperscan or the ACISM/regex fallback.
 */
TEST_SUITE("multipattern som")
{
	/* One reported occurrence: (pattern id, start offset, end offset) */
	using mp_match = std::tuple<unsigned int, int, int>;

	static int mp_collect_cb(struct rspamd_multipattern * mp, unsigned int strnum,
							 int match_start, int match_pos, const char *text,
							 gsize len, void *context)
	{
		auto *acc = static_cast<std::vector<mp_match> *>(context);
		acc->emplace_back(strnum, match_start, match_pos);

		return 0;
	}

	static std::vector<mp_match> mp_scan(const std::vector<std::string> &pats,
										 int flags, const std::string &input)
	{
		struct rspamd_multipattern *mp =
			rspamd_multipattern_create((enum rspamd_multipattern_flags) flags);

		for (const auto &p: pats) {
			rspamd_multipattern_add_pattern_len(mp, p.data(), p.size(), flags);
		}

		GError *err = nullptr;
		bool ok = rspamd_multipattern_compile(mp, RSPAMD_MULTIPATTERN_COMPILE_NO_FS, &err);
		REQUIRE(ok);

		std::vector<mp_match> res;
		unsigned int nfound = 0;
		rspamd_multipattern_lookup(mp, input.data(), input.size(),
								   mp_collect_cb, &res, &nfound);
		rspamd_multipattern_destroy(mp);

		CHECK(nfound == res.size());

		/* Deterministic ordering: by end, then start, then id */
		std::sort(res.begin(), res.end(),
				  [](const mp_match &a, const mp_match &b) {
					  if (std::get<2>(a) != std::get<2>(b)) {
						  return std::get<2>(a) < std::get<2>(b);
					  }
					  if (std::get<1>(a) != std::get<1>(b)) {
						  return std::get<1>(a) < std::get<1>(b);
					  }
					  return std::get<0>(a) < std::get<0>(b);
				  });

		return res;
	}

	TEST_CASE("literal: multiple occurrences with ordered start offsets")
	{
		/* "ab" at byte offsets 0, 3, 6 in "abXabYab" */
		auto res = mp_scan({"ab"}, RSPAMD_MULTIPATTERN_SOM, "abXabYab");

		REQUIRE(res.size() == 3);
		CHECK(res[0] == mp_match{0, 0, 2});
		CHECK(res[1] == mp_match{0, 3, 5});
		CHECK(res[2] == mp_match{0, 6, 8});
	}

	TEST_CASE("literal: overlapping occurrences")
	{
		/* "aa" in "aaaa" matches ending at 2,3,4 with leftmost starts 0,1,2 */
		auto res = mp_scan({"aa"}, RSPAMD_MULTIPATTERN_SOM, "aaaa");

		REQUIRE(res.size() == 3);
		CHECK(res[0] == mp_match{0, 0, 2});
		CHECK(res[1] == mp_match{0, 1, 3});
		CHECK(res[2] == mp_match{0, 2, 4});
	}

	TEST_CASE("literal: case-insensitive start offsets")
	{
		/* "ABC" matched caselessly at offset 1 in "xABCy" */
		auto res = mp_scan({"abc"},
						   RSPAMD_MULTIPATTERN_ICASE | RSPAMD_MULTIPATTERN_SOM,
						   "xABCy");

		REQUIRE(res.size() == 1);
		CHECK(res[0] == mp_match{0, 1, 4});
	}

	TEST_CASE("multiple distinct patterns keep their own ids")
	{
		/* id0="foo" at 0; id1="bar" at 4 in "foo bar" */
		auto res = mp_scan({"foo", "bar"}, RSPAMD_MULTIPATTERN_SOM, "foo bar");

		REQUIRE(res.size() == 2);
		CHECK(res[0] == mp_match{0, 0, 3});
		CHECK(res[1] == mp_match{1, 4, 7});
	}

	TEST_CASE("regex pattern reports real start offsets")
	{
		/* fixed-length regex "a.c" at offsets 0 and 4 in "axc-ayc" */
		auto res = mp_scan({"a.c"},
						   RSPAMD_MULTIPATTERN_RE | RSPAMD_MULTIPATTERN_SOM,
						   "axc-ayc");

		REQUIRE(res.size() == 2);
		CHECK(res[0] == mp_match{0, 0, 3});
		CHECK(res[1] == mp_match{0, 4, 7});
	}

	TEST_CASE("no match yields no occurrences")
	{
		auto res = mp_scan({"zzz"}, RSPAMD_MULTIPATTERN_SOM, "abcdef");

		CHECK(res.empty());
	}

	TEST_CASE("SOM overrides single_match")
	{
		/*
		 * single_match alone would collapse to one occurrence; the explicit
		 * SOM flag must drop single_match and report every occurrence with a
		 * start offset.
		 */
		auto res = mp_scan({"ab"},
						   RSPAMD_MULTIPATTERN_SINGLEMATCH | RSPAMD_MULTIPATTERN_SOM,
						   "abab");

		REQUIRE(res.size() == 2);
		CHECK(res[0] == mp_match{0, 0, 2});
		CHECK(res[1] == mp_match{0, 2, 4});
	}

	TEST_CASE("large buffer: start offsets at known positions")
	{
		const std::string needle = "needle";
		std::string buf(100000, 'x');
		/* Plant the needle at two known offsets */
		buf.replace(1000, needle.size(), needle);
		buf.replace(50000, needle.size(), needle);

		auto res = mp_scan({needle}, RSPAMD_MULTIPATTERN_SOM, buf);

		REQUIRE(res.size() == 2);
		CHECK(res[0] == mp_match{0, 1000, 1000 + (int) needle.size()});
		CHECK(res[1] == mp_match{0, 50000, 50000 + (int) needle.size()});
	}
}

#endif
