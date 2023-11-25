/*
 * Copyright 2023 Vsevolod Stakhov
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

/* Detached unit tests for the utils */

#ifndef RSPAMD_RSPAMD_CXX_UNIT_UTILS_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_UTILS_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libmime/mime_headers.h"
#include "contrib/libottery/ottery.h"
#include "libcryptobox/cryptobox.h"

#include <vector>
#include <utility>
#include <string>

extern "C" long rspamd_http_parse_keepalive_timeout(const rspamd_ftok_t *tok);

TEST_SUITE("rspamd_utils")
{

	TEST_CASE("rspamd_strip_smtp_comments_inplace")
	{
		std::vector<std::pair<std::string, std::string>> cases{
			{"abc", "abc"},
			{"abc(foo)", "abc"},
			{"abc(foo()", "abc"},
			{"abc(foo))", "abc)"},
			{"abc(foo(bar))", "abc"},
			{"(bar)abc(foo)", "abc"},
			{"ab(ololo)c(foo)", "abc"},
			{"ab(olo\\)lo)c(foo)", "abc"},
			{"ab(trol\\\1lo)c(foo)", "abc"},
			{"\\ab(trol\\\1lo)c(foo)", "abc"},
			{"", ""},
			{"<test_id@example.net> (added by postmaster@example.net)", "<test_id@example.net> "}};

		for (const auto &c: cases) {
			SUBCASE(("strip comments in " + c.first).c_str())
			{
				auto *cpy = new char[c.first.size()];
				memcpy(cpy, c.first.data(), c.first.size());
				auto nlen = rspamd_strip_smtp_comments_inplace(cpy, c.first.size());
				CHECK(std::string{cpy, nlen} == c.second);
				delete[] cpy;
			}
		}
	}

	TEST_CASE("rspamd_http_parse_keepalive_timeout")
	{
		std::vector<std::pair<std::string, long>> cases{
			{"timeout=5, max=1000", 5},
			{"max=1000, timeout=5", 5},
			{"max=1000, timeout=", -1},
			{"max=1000, timeout=0", 0},
			{"max=1000, timeout=-5", -1},
			{"timeout=5", 5},
			{"    timeout=5;    ", 5},
			{"timeout  =   5", 5},
		};

		for (const auto &c: cases) {
			SUBCASE(("parse http keepalive header " + c.first).c_str())
			{
				rspamd_ftok_t t;
				t.begin = c.first.data();
				t.len = c.first.size();
				auto res = rspamd_http_parse_keepalive_timeout(&t);
				CHECK(res == c.second);
			}
		}
	}

	TEST_CASE("rspamd_fstring_gzip tests")
	{
		rspamd_fstring_t *fstr;

		// Test empty data compression
		SUBCASE("Empty data")
		{
			fstr = rspamd_fstring_new_init("", 0);
			gboolean result = rspamd_fstring_gzip(&fstr);
			CHECK(result == TRUE);
			CHECK(fstr->len == 20);
			result = rspamd_fstring_gunzip(&fstr);
			CHECK(result == TRUE);
			CHECK(fstr->len == 0);
			rspamd_fstring_free(fstr);
		}

		SUBCASE("Non empty data")
		{
			fstr = RSPAMD_FSTRING_LIT("helohelo");
			gboolean result = rspamd_fstring_gzip(&fstr);
			CHECK(result == TRUE);
			CHECK(fstr->len == 26);
			result = rspamd_fstring_gunzip(&fstr);
			CHECK(result == TRUE);
			CHECK(memcmp(fstr->str, "helohelo", fstr->len) == 0);
			CHECK(fstr->len == sizeof("helohelo") - 1);
			rspamd_fstring_free(fstr);
		}

		SUBCASE("Some real compression")
		{
			fstr = rspamd_fstring_sized_new(sizeof("helohelo") * 1024);
			for (int i = 0; i < 1024; i++) {
				fstr = rspamd_fstring_append(fstr, "helohelo", sizeof("helohelo") - 1);
			}
			gboolean result = rspamd_fstring_gzip(&fstr);
			CHECK(result == TRUE);
			CHECK(fstr->len == 49);
			result = rspamd_fstring_gunzip(&fstr);
			CHECK(result == TRUE);
			CHECK(memcmp(fstr->str, "helohelo", sizeof("helohelo") - 1) == 0);
			CHECK(fstr->len == (sizeof("helohelo") - 1) * 1024);
			rspamd_fstring_free(fstr);
		}

		SUBCASE("Random data compression")
		{
			rspamd_cryptobox_fast_hash_state_t hst;
			rspamd_cryptobox_fast_hash_init(&hst, 0);
			fstr = rspamd_fstring_sized_new(30 * 1024 * 1024);
			for (int i = 0; i < 30 * 1024; i++) {
				char tmp[1024];
				ottery_rand_bytes(tmp, sizeof(tmp));
				fstr = rspamd_fstring_append(fstr, tmp, sizeof(tmp));
				rspamd_cryptobox_fast_hash_update(&hst, tmp, sizeof(tmp));
			}
			auto crc = rspamd_cryptobox_fast_hash(fstr->str, fstr->len, 0);
			CHECK(crc == rspamd_cryptobox_fast_hash_final(&hst));
			gboolean result = rspamd_fstring_gzip(&fstr);
			CHECK(result == TRUE);
			// Assuming there are no miracles
			CHECK(fstr->len >= 30 * 1024 * 1024);
			result = rspamd_fstring_gunzip(&fstr);
			CHECK(result == TRUE);
			CHECK(fstr->len == 30 * 1024 * 1024);
			auto final_crc = rspamd_cryptobox_fast_hash(fstr->str, fstr->len, 0);
			CHECK(crc == final_crc);
			rspamd_fstring_free(fstr);
		}
	}

	TEST_CASE("rspamd_message_header_unfold_inplace")
	{
		std::vector<std::pair<std::string, std::string>> cases{
			{"abc", "abc"},
			{"abc\r\n def", "abc def"},
			{"abc\r\n\tdef", "abc def"},
			{"abc\r\n\tdef\r\n\tghi", "abc def ghi"},
			{"abc\r\n\tdef\r\n\tghi\r\n", "abc def ghi"},
			{"abc\r\n\tdef\r\n\tghi\r\n\t", "abc def ghi"},
			{"abc\r\n\tdef\r\n\tghi\r\n\tjkl", "abc def ghi jkl"},
			{"abc\r\n\tdef\r\n\tghi\r\n\tjkl\r\n", "abc def ghi jkl"},
			{"abc\r\n\tdef\r\n\tghi\r\n\tjkl\r\n\t", "abc def ghi jkl"},
			{"abc\r\n\tdef\r\n\tghi\r\n\tjkl\r\n\tmno", "abc def ghi jkl mno"},
			{"abc\r\n\tdef\r\n\tghi\r\n\tjkl\r\n\tmno\r\n", "abc def ghi jkl mno"},
			{"abc\r\n\tdef\r\n\tghi\r\n\tjkl\r\n\tmno\r\n\t", "abc def ghi jkl mno"},
			{"abc\r\n\tdef\r\n\tghi\r\n\tjkl\r\n\tmno\r\n\tpqr", "abc def ghi jkl mno pqr"},
			{"abc\r\n\tdef\r\n\tghi\r\n\tjkl\r\n\tmno\r\n\tpqr\r\n", "abc def ghi jkl mno pqr"},
			{"abc\r\n\tdef\r\n\tghi\r\n\tjkl\r\n\tmno\r\n\tpqr\r\n\t", "abc def ghi jkl mno pqr"},
			{"abc\r\n\tdef\r\n\tghi\r\n\tjkl\r\n\tmno\r\n\tpqr\r\n\tstu", "abc def ghi jkl mno pqr stu"},
			// Newline at the end
			{
				"abc\r\n\tdef\r\n\tghi\r\n\tjkl\r\n\tmno\r\n\tpqr\r\n\tstu\r\n", "abc def ghi jkl mno pqr stu"},
			// Spaces at the end
			{
				"abc\r\n\tdef\r\n\tghi\r\n\tjkl\r\n\tmno\r\n\tpqr\r\n\tstu\r\n\t", "abc def ghi jkl mno pqr stu"},
			// Multiple spaces at the end
			{
				"abc\r\n\tdef\r\n\tghi\r\n\tjkl\r\n\tmno\r\n\tpqr\r\n\tstu\r\n\t   ", "abc def ghi jkl mno pqr stu"},
			// Multiple spaces in middle
			{
				"abc\r\n\tdef\r\n\tghi\r\n\tjkl\r\n\tmno\r\n\tpqr\r\n\tstu   \r\n\t   a", "abc def ghi jkl mno pqr stu    a"},
		};

		for (const auto &c: cases) {
			SUBCASE(("unfold header " + c.second).c_str())
			{
				auto *cpy = new char[c.first.size()];
				memcpy(cpy, c.first.data(), c.first.size());
				auto nlen = rspamd_message_header_unfold_inplace(cpy, c.first.size());
				CHECK(std::string{cpy, nlen} == c.second);
				delete[] cpy;
			}
		}
	}
}

#endif
