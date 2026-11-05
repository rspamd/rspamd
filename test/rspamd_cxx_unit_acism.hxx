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

#ifndef RSPAMD_RSPAMD_CXX_UNIT_ACISM_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_ACISM_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

extern "C" {
#include "acism.h"
}

#include <algorithm>
#include <compare>
#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

/*
 * The ACISM trie is called directly: rspamd_multipattern uses hyperscan when
 * it is available, so a multipattern test would not reach this code.
 */
TEST_SUITE("acism")
{
	/* A pattern index and the offset one past the last matched byte */
	struct acism_hit {
		int strnum;
		int textpos;

		auto operator<=>(const acism_hit &) const = default;

		/* Found by doctest through ADL, a std::pair would not be */
		friend std::ostream &operator<<(std::ostream &os, const acism_hit &h)
		{
			return os << "{" << h.strnum << ", " << h.textpos << "}";
		}
	};

	static int acism_collect_cb(int strnum, int textpos, void *context)
	{
		static_cast<std::vector<acism_hit> *>(context)->push_back({strnum, textpos});

		return 0;
	}

	static std::vector<acism_hit> acism_scan(const std::vector<std::string> &pats,
											 const std::string &text)
	{
		std::vector<ac_trie_pat_t> strv;

		for (const auto &p: pats) {
			strv.push_back({p.data(), p.size()});
		}

		ac_trie_t *t = acism_create(strv.data(), (int) strv.size());
		REQUIRE(t != nullptr);

		std::vector<acism_hit> hits;
		int state = 0;
		acism_lookup(t, text.data(), text.size(), acism_collect_cb, &hits, &state, false);
		acism_destroy(t);
		std::sort(hits.begin(), hits.end());

		return hits;
	}

	TEST_CASE("lookup stays inside the transition table")
	{
		/*
		 * The MIME boundary trie. The "\n-" state has the highest base and
		 * '\n' the highest symbol, so "\n-\n" reads the slot a whole
		 * alphabet past that base (heap-buffer-overflow under ASan).
		 */
		std::vector<std::string> pats{"\r--", "\n--"};

		CHECK(acism_scan(pats, "x\n-\ny\r-\rz\n-\r\r-\n").empty());
		CHECK(acism_scan(pats, "a\n-\n--b\r--") ==
			  std::vector<acism_hit>{{0, 10}, {1, 6}});
	}

	TEST_CASE("lookup does not read the match hash as transitions")
	{
		/*
		 * "a" is a match with a child ("ab"), so the match hash follows the
		 * transitions in the same allocation. The second 'a' used to read
		 * the first hash entry, which decoded as a valid transition to the
		 * root, and the second match was lost. No sanitizer is needed here.
		 */
		std::vector<std::string> pats{"a", "ab", "bb"};

		CHECK(acism_scan(pats, "aa") == std::vector<acism_hit>{{0, 1}, {0, 2}});
		CHECK(acism_scan(pats, "abba") ==
			  std::vector<acism_hit>{{0, 1}, {0, 4}, {1, 2}, {2, 3}});
	}

	static std::vector<acism_hit> naive_scan(const std::vector<std::string> &pats,
											 const std::string &text)
	{
		std::vector<acism_hit> hits;

		for (std::size_t i = 0; i < pats.size(); i++) {
			for (auto pos = text.find(pats[i]); pos != std::string::npos;
				 pos = text.find(pats[i], pos + 1)) {
				hits.push_back({(int) i, (int) (pos + pats[i].size())});
			}
		}

		std::sort(hits.begin(), hits.end());

		return hits;
	}

	TEST_CASE("suffix that is a leaf")
	{
		/*
		 * "bc" is the longest suffix of "abc", but it is a leaf: the lookup
		 * must go on from "c", or "cd" is not found after "abc"
		 */
		std::vector<std::string> pats{"abcd", "bc", "cd"};

		CHECK(acism_scan(pats, "abcd") ==
			  std::vector<acism_hit>{{0, 4}, {1, 3}, {2, 4}});
		CHECK(acism_scan(pats, "abce") == std::vector<acism_hit>{{1, 3}});
		CHECK(acism_scan(pats, "abcbcd") ==
			  std::vector<acism_hit>{{1, 3}, {1, 5}, {2, 6}});
	}

	TEST_CASE("all matches as a naive search finds them")
	{
		/* Small alphabet, so the patterns are often suffixes of each other */
		std::uint32_t seed = 42;
		auto next_rand = [&seed](std::uint32_t mod) {
			seed = seed * 1103515245u + 12345u;
			return (seed >> 16) % mod;
		};
		auto random_string = [&](std::size_t len) {
			std::string s;

			for (std::size_t i = 0; i < len; i++) {
				s.push_back("abcd"[next_rand(4)]);
			}

			return s;
		};

		for (int round = 0; round < 2000; round++) {
			std::vector<std::string> pats;
			auto npats = 1 + next_rand(8);

			while (pats.size() < npats) {
				auto p = random_string(1 + next_rand(5));

				if (std::find(pats.begin(), pats.end(), p) == pats.end()) {
					pats.push_back(std::move(p));
				}
			}

			auto text = random_string(next_rand(40));
			CAPTURE(round);
			CAPTURE(text);
			CHECK(acism_scan(pats, text) == naive_scan(pats, text));
		}
	}
}

#endif
