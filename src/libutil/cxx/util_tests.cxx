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

#include "util.hxx"

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

using namespace rspamd;
using namespace std::literals::string_view_literals;

TEST_SUITE("cxx utils")
{
	TEST_CASE("string_split_on")
	{
		std::tuple<std::string_view, char, std::pair<std::string_view, std::string_view>> cases[] = {
			{"test test"sv, ' ', std::pair{"test"sv, "test"sv}},
			{"test    test"sv, ' ', std::pair{"test"sv, "test"sv}},
			{"test  test  "sv, ' ', std::pair{"test"sv, "test  "sv}},
			{"testtest  "sv, ' ', std::pair{"testtest"sv, ""sv}},
			{"   testtest  "sv, ' ', std::pair{""sv, "testtest  "sv}},
			{"testtest"sv, ' ', std::pair{"testtest"sv, ""sv}},
			{""sv, ' ', std::pair{""sv, ""sv}},
		};

		for (const auto &c: cases) {
			auto res = string_split_on(std::get<0>(c), std::get<1>(c));
			auto expected = std::get<2>(c);
			CHECK(res.first == expected.first);
			CHECK(res.second == expected.second);
		}
	}

	TEST_CASE("string_foreach_delim")
	{
		std::tuple<std::string_view, std::string_view, std::pair<std::vector<std::string_view>, std::vector<std::string_view>>> cases[] = {
			{"test"sv, ","sv, {{"test"}, {"test"}}},
			{"test,test"sv, ","sv, {{"test", "test"}, {"test", "test"}}},
			{"test, test"sv, ", "sv, {{"test", "test"}, {"test", "", "test"}}},
			{"test, test,,"sv, ", "sv, {{"test", "test"}, {"test", "", "test", ""}}},
		};

		for (const auto &c: cases) {
			auto res = std::vector<std::string_view>();
			string_foreach_delim(std::get<0>(c), std::get<1>(c), [&](const auto &v) {
				res.push_back(v);
			});

			auto compare_vec = []<class T>(const std::vector<T> &v1, const std::vector<T> &v2) {
				CHECK(v1.size() == v2.size());
				for (size_t i = 0; i < v1.size(); ++i) {
					CHECK(v1[i] == v2[i]);
				}
			};

			compare_vec(res, std::get<2>(c).first);

			res.clear();
			// Perform the same test but with no skip empty
			string_foreach_delim(
				std::get<0>(c), std::get<1>(c), [&](const auto &v) {
					res.push_back(v);
				},
				false);
			compare_vec(res, std::get<2>(c).second);
		}
	}
}