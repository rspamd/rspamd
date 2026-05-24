/*
 * Copyright 2026 Alexander Moisseev
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

#ifndef RSPAMD_RSPAMD_CXX_UNIT_FPCONV_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_FPCONV_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

extern "C" {
#include "contrib/fpconv/fpconv.h"
}

#include <string>
#include <vector>
#include <utility>
#include <cstring>

TEST_SUITE("fpconv")
{
	static std::string dtoa(double d, unsigned precision = 0, bool scientific = false)
	{
		char buf[FPCONV_BUFLEN];
		int len = fpconv_dtoa(d, buf, precision, scientific);
		return std::string(buf, len);
	}

	TEST_CASE("fpconv_dtoa basic integers")
	{
		CHECK(dtoa(0.0) == "0");
		CHECK(dtoa(1.0) == "1");
		CHECK(dtoa(42.0) == "42");
		CHECK(dtoa(123456.0) == "123456");
	}

	TEST_CASE("fpconv_dtoa precision=0 rounding (fixed-point)")
	{
		std::vector<std::pair<double, std::string>> cases{
			{1.001, "1"},
			{1.4, "1"},
			{1.5, "2"},
			{1.6, "2"},
			{1.999, "2"},
			{9.9, "10"},
			{9.5, "10"},
			{9.4, "9"},
			{0.1, "0"},
			{0.4, "0"},
			{0.5, "1"},
			{0.9, "1"},
			{0.001, "0"},
			{60.0, "60"},
			{59.999, "60"},
			/* Negative numbers (sign preserved, consistent with libc %.0f) */
			{-1.5, "-2"},
			{-1.4, "-1"},
			{-0.5, "-1"},
			{-0.4, "-0"}, /* "-0" is correct: sign is preserved */
			{-9.9, "-10"},
		};

		for (const auto &c: cases) {
			SUBCASE(("round %.0f for " + std::to_string(c.first)).c_str())
			{
				auto result = dtoa(c.first, 0);
				CHECK(result == c.second);
			}
		}
	}

	TEST_CASE("fpconv_dtoa precision=0 offset boundary (0.4 vs 0.5)")
	{
		/*
		 * When offset >= 0, digits[0] is the tenths-place digit;
		 * >= '5' rounds up.  When offset < 0 (e.g. 0.05, K=-2),
		 * the value is < 0.1 and rounds to "0".
		 */
		CHECK(dtoa(0.499, 0) == "0");
		CHECK(dtoa(0.5, 0) == "1");
		CHECK(dtoa(0.5001, 0) == "1");
		CHECK(dtoa(0.05, 0) == "0");
		CHECK(dtoa(0.005, 0) == "0");
	}

	TEST_CASE("fpconv_dtoa precision=1 rounding")
	{
		CHECK(dtoa(1.001, 1) == "1.0");
		CHECK(dtoa(1.04, 1) == "1.0");
		CHECK(dtoa(0.04, 1) == "0.0");
	}

	TEST_CASE("fpconv_dtoa precision=2 rounding")
	{
		CHECK(dtoa(1.001, 2) == "1.00");
		CHECK(dtoa(0.004, 2) == "0.00");
	}

	TEST_CASE("fpconv_dtoa scientific notation")
	{
		/* Verify leading digit and 'e' presence */
		auto r1 = dtoa(1e20, 0, true);
		CHECK(r1.substr(0, 1) == "1");
		CHECK(r1.find('e') != std::string::npos);

		auto r2 = dtoa(1.5e-10, 0, true);
		CHECK(r2.substr(0, 1) == "1");
		CHECK(r2.find('e') != std::string::npos);
	}

	TEST_CASE("fpconv_dtoa precision=20 (all significant digits, rspamd %f default)")
	{
		/* Trim mode: emit shortest accurate representation */
		CHECK(dtoa(1.001, 20) == "1.001");
		CHECK(dtoa(0.5, 20) == "0.5");
		CHECK(dtoa(0.0, 20) == "0");
		CHECK(dtoa(1.0, 20) == "1");
		/* Exact digit count depends on Grisu2 shortest representation */
		CHECK(dtoa(1.0 / 3.0, 20) == "0.3333333333333333");
	}

	TEST_CASE("fpconv_dtoa special values")
	{
		CHECK(dtoa(0.0) == "0");
		CHECK(dtoa(1.0 / 0.0) == "inf");
		CHECK(dtoa(-1.0 / 0.0) == "-inf");
		std::string nan_result = dtoa(0.0 / 0.0);
		CHECK(nan_result == "nan");
	}
}

#endif
