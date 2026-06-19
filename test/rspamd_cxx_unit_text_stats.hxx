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

#ifndef RSPAMD_RSPAMD_CXX_UNIT_TEXT_STATS_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_TEXT_STATS_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "lua/lua_text_stats.hxx"

#include <vector>
#include <string>
#include <span>
#include <cstddef>
#include <cmath>

/*
 * Golden-vector tests for the byte-statistics primitives. The expected values
 * are derived analytically from the statistic definitions over buffers whose
 * statistics are determined exactly:
 *
 *   - all-zeros / all-same-byte: entropy 0; mean = that byte; deviation 0;
 *     serial_correlation -100000 (the n*scct3 - scct2 == 0 sentinel).
 *   - every byte 0..255 once: entropy 8; mean 127.5; deviation(127.5) 64.
 *   - "aaaabbbb" (two values, equal counts): entropy 1; mean 97.5.
 *   - {0,1,2,3}: serial_correlation -0.2 (hand-computed).
 *   - 0xFF*6 / 0x00*6: monte_carlo_pi returns |4*in/groups - PI|/PI.
 *
 * entropy/mean/deviation are asserted exactly (the values above are exactly
 * representable doubles); the float metrics use a small epsilon.
 */
TEST_SUITE("text stats")
{
	static constexpr double EPS = 1e-9;
	static constexpr double REF_PI = 3.141592653589793;

	static std::span<const std::byte> as_bytes(const std::vector<unsigned char> &v)
	{
		return {reinterpret_cast<const std::byte *>(v.data()), v.size()};
	}

	static std::span<const std::byte> as_bytes(const std::string &s)
	{
		return {reinterpret_cast<const std::byte *>(s.data()), s.size()};
	}

	using namespace rspamd::text_stats;

	TEST_CASE("empty buffer is defined and division-free")
	{
		std::vector<unsigned char> empty;
		auto sp = as_bytes(empty);

		CHECK(entropy(sp) == 0.0);
		CHECK(byte_mean(sp) == 0.0);
		CHECK(byte_deviation(sp, 0.0) == 0.0);
		CHECK(serial_correlation(sp) == 0.0);
		CHECK(monte_carlo_pi(sp) == 0.0);
	}

	TEST_CASE("all-zeros buffer")
	{
		std::vector<unsigned char> z(256, 0);
		auto sp = as_bytes(z);

		CHECK(entropy(sp) == 0.0);
		CHECK(byte_mean(sp) == 0.0);
		CHECK(byte_deviation(sp, 0.0) == 0.0);
		/* all bytes identical -> n*scct3 - scct2 == 0 -> sentinel */
		CHECK(serial_correlation(sp) == -100000.0);
		/* 42 full groups, every point at origin -> in circle -> mpi == 4 */
		CHECK(monte_carlo_pi(sp) ==
			  doctest::Approx(std::fabs((4.0 - REF_PI) / REF_PI)).epsilon(EPS));
	}

	TEST_CASE("uniform distribution: every byte value once")
	{
		std::vector<unsigned char> u(256);
		for (int i = 0; i < 256; i++) {
			u[i] = (unsigned char) i;
		}
		auto sp = as_bytes(u);

		/* 256 bins each with p = 1/256 = 2^-8 -> entropy exactly 8 bits/byte */
		CHECK(entropy(sp) == 8.0);
		/* mean of 0..255 == 127.5 */
		CHECK(byte_mean(sp) == 127.5);
		/* mean abs deviation about 127.5 == 64 */
		CHECK(byte_deviation(sp, 127.5) == 64.0);
	}

	TEST_CASE("two-symbol ASCII: aaaabbbb")
	{
		std::string s = "aaaabbbb"; /* 4x 'a'(97), 4x 'b'(98) */
		auto sp = as_bytes(s);

		/* two equally-likely symbols -> 1 bit/byte */
		CHECK(entropy(sp) == 1.0);
		CHECK(byte_mean(sp) == 97.5);
		/* |97-97.5|*4 + |98-97.5|*4 = 4, /8 = 0.5 */
		CHECK(byte_deviation(sp, 97.5) == 0.5);
	}

	TEST_CASE("byte_mean uses unsigned byte values (high bytes)")
	{
		/* 0xFF and 0x00, equal counts: unsigned mean is 127.5, not -0.5 */
		std::vector<unsigned char> v{0x00, 0xFF, 0x00, 0xFF};
		auto sp = as_bytes(v);

		CHECK(byte_mean(sp) == 127.5);
		CHECK(entropy(sp) == 1.0);
	}

	TEST_CASE("serial_correlation hand-computed and edge cases")
	{
		/* {0,1,2,3}: scct2=6, scct3=14, scct1=8 (+last*first=0);
		 * scc = 4*14 - 36 = 20; (4*8 - 36)/20 = -4/20 = -0.2 */
		std::vector<unsigned char> ramp{0, 1, 2, 3};
		CHECK(serial_correlation(as_bytes(ramp)) ==
			  doctest::Approx(-0.2).epsilon(EPS));

		/* single byte -> n*scct3 - scct2 == b^2 - b^2 == 0 -> sentinel */
		std::vector<unsigned char> one{0x41};
		CHECK(serial_correlation(as_bytes(one)) == -100000.0);
	}

	TEST_CASE("monte_carlo_pi point outside the circle")
	{
		/* 6x0xFF: x = y = 256^3-1, x^2+y^2 = 2*INCIRC > INCIRC -> outside
		 * -> inmont 0, groups 1 -> mpi 0 -> |0 - PI|/PI == 1 */
		std::vector<unsigned char> ff(6, 0xFF);
		CHECK(monte_carlo_pi(as_bytes(ff)) == doctest::Approx(1.0).epsilon(EPS));

		/* 6x0x00 in circle, 6x0xFF outside -> mpi = 4*1/2 = 2 */
		std::vector<unsigned char> mix(6, 0x00);
		mix.insert(mix.end(), 6, 0xFF);
		CHECK(monte_carlo_pi(as_bytes(mix)) ==
			  doctest::Approx(std::fabs((2.0 - REF_PI) / REF_PI)).epsilon(EPS));

		/* fewer than 6 bytes -> no complete group -> defined 0 */
		std::vector<unsigned char> tiny{1, 2, 3};
		CHECK(monte_carlo_pi(as_bytes(tiny)) == 0.0);
	}

	TEST_CASE("entropy is bounded in [0, 8]")
	{
		std::vector<unsigned char> v(1024);
		for (std::size_t i = 0; i < v.size(); i++) {
			v[i] = (unsigned char) ((i * 37 + 11) & 0xff);
		}
		double e = entropy(as_bytes(v));
		CHECK(e >= 0.0);
		CHECK(e <= 8.0);
	}

	TEST_CASE("shared distribution matches per-metric span overloads")
	{
		std::string s = "The quick brown fox jumps over the lazy dog.";
		auto sp = as_bytes(s);

		/* one histogram pass, reused by entropy/mean/deviation */
		auto dist = make_distribution(sp);
		double m = byte_mean(dist);

		CHECK(entropy(dist) == entropy(sp));
		CHECK(m == byte_mean(sp));
		CHECK(byte_deviation(dist, m) == byte_deviation(sp, m));
	}
}

#endif
