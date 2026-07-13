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

#ifndef RSPAMD_LUA_TEXT_STATS_HXX
#define RSPAMD_LUA_TEXT_STATS_HXX
#pragma once

/*
 * Byte-distribution statistics over a buffer: Shannon entropy, byte mean and
 * mean absolute deviation, and the serial-correlation and Monte-Carlo-Pi
 * randomness metrics (the classic ENT test-suite formulas, John Walker,
 * fourmilab.ch/random). They are specified to produce deterministic,
 * portable, bit-reproducible results so callers can compare them against
 * fixed thresholds.
 *
 * These are pure, header-only, allocation-free C++; the Lua bindings in
 * lua_text_stats.cxx and the C++ unit tests both call them directly.
 *
 * Two accumulation strategies are used, and the order is part of the contract
 * (floating-point addition is not associative, so it affects the exact bits):
 *   - entropy / mean / deviation build a 256-bin histogram of the byte values
 *     and accumulate over the bins 0..255 - the order is fixed by the bin
 *     index (byte value), NOT by buffer position.
 *   - serial_correlation / monte_carlo_pi walk the buffer in order with no
 *     histogram.
 *
 * std::log2 is used directly for the entropy term.
 */

#include <array>
#include <span>
#include <cstdint>
#include <cstddef>
#include <cmath>

namespace rspamd::text_stats {

/* 256-bin histogram of byte values plus the total number of bytes. */
struct byte_distribution {
	std::array<std::uint64_t, 256> bins{};
	std::uint64_t total = 0;
};

/* Single O(n) pass; shared by entropy/mean/deviation (no allocation). */
inline byte_distribution
make_distribution(std::span<const std::byte> data) noexcept
{
	byte_distribution dist{};

	for (auto b: data) {
		dist.bins[std::to_integer<std::uint8_t>(b)]++;
	}

	dist.total = data.size();

	return dist;
}

/*
 * Shannon entropy in bits/byte over [0, 8]:
 *   total = Σ bins; for each non-empty bin: x = bin/total; entropy -= x*log2(x)
 * Empty input has no non-empty bins, so entropy is 0 with no division.
 */
inline double
entropy(const byte_distribution &dist) noexcept
{
	double entropy = 0.0;

	if (dist.total == 0) {
		return 0.0;
	}

	for (std::size_t i = 0; i < 256; i++) {
		if (dist.bins[i] != 0) {
			double x = (double) dist.bins[i] / (double) dist.total;
			entropy -= x * std::log2(x);
		}
	}

	return entropy;
}

inline double
entropy(std::span<const std::byte> data) noexcept
{
	return entropy(make_distribution(data));
}

/*
 * Arithmetic mean of byte values:
 *   sum = Σ_{i=0..255} (double) i * bins[i];  return sum / total
 * Uses the unsigned byte value i (0..255).
 */
inline double
byte_mean(const byte_distribution &dist) noexcept
{
	double sum = 0.0;

	if (dist.total == 0) {
		return 0.0;
	}

	for (std::size_t i = 0; i < 256; i++) {
		sum += (double) i * (double) dist.bins[i];
	}

	return sum / (double) dist.total;
}

inline double
byte_mean(std::span<const std::byte> data) noexcept
{
	return byte_mean(make_distribution(data));
}

/*
 * Mean absolute deviation from `mean`:
 *   sum = Σ_{i=0..255} fabs((double) i - mean) * bins[i];  return sum / total
 * The reference mean is supplied by the caller (typically byte_mean of the
 * same range).
 */
inline double
byte_deviation(const byte_distribution &dist, double mean) noexcept
{
	double sum = 0.0;

	if (dist.total == 0) {
		return 0.0;
	}

	for (std::size_t i = 0; i < 256; i++) {
		sum += std::fabs((double) i - mean) * (double) dist.bins[i];
	}

	return sum / (double) dist.total;
}

inline double
byte_deviation(std::span<const std::byte> data, double mean) noexcept
{
	return byte_deviation(make_distribution(data), mean);
}

/*
 * Serial correlation coefficient (ENT algorithm), walking the buffer in order:
 *   for each byte u: scct1 += last*u; scct2 += u; scct3 += u*u; last = u
 *   (the first byte is remembered as `first`)
 *   scct1 += last*first;  scct2 *= scct2
 *   scc = n*scct3 - scct2
 *   scc = (scc == 0) ? -100000 : (n*scct1 - scct2) / scc
 * A single byte therefore yields the -100000 sentinel; an empty buffer
 * yields 0.
 */
inline double
serial_correlation(std::span<const std::byte> data) noexcept
{
	const std::size_t n = data.size();

	if (n == 0) {
		return 0.0;
	}

	double sccun = 0, sccfirst = 0, scclast = 0;
	double scct1 = 0, scct2 = 0, scct3 = 0;

	for (std::size_t i = 0; i < n; i++) {
		sccun = (double) std::to_integer<std::uint8_t>(data[i]);

		if (i == 0) {
			sccfirst = sccun;
		}

		scct1 += scclast * sccun;
		scct2 += sccun;
		scct3 += sccun * sccun;
		scclast = sccun;
	}

	scct1 += scclast * sccfirst;
	scct2 *= scct2;

	double scc = (double) n * scct3 - scct2;

	if (scc == 0.0) {
		return -100000.0;
	}

	return ((double) n * scct1 - scct2) / scc;
}

/*
 * Monte-Carlo Pi metric (ENT algorithm), consuming the buffer in groups of 6
 * bytes: the first 3 bytes form a 24-bit x coordinate and the next 3 a y
 * coordinate; a group counts as "in circle" when x^2 + y^2 <= (256^3-1)^2.
 *
 * IMPORTANT: this does NOT return the Pi estimate. It returns the normalized
 * deviation from Pi, fabs((mpi - PI) / PI), where mpi = 4 * inmont / groups and
 * PI = 3.141592653589793. Fewer than 6 bytes complete no group, which yields 0.
 */
inline double
monte_carlo_pi(std::span<const std::byte> data) noexcept
{
	constexpr double pi = 3.141592653589793;
	const double incirc = std::pow(std::pow(256.0, 3.0) - 1, 2.0);

	unsigned int monte[6];
	int mcount = 0;
	int inmont = 0;
	const std::size_t n = data.size();

	for (std::size_t i = 0; i < n; i++) {
		monte[i % 6] = (unsigned int) std::to_integer<std::uint8_t>(data[i]);

		if (i % 6 == 5) {
			double mx = 0;
			double my = 0;

			mcount++;

			for (int j = 0; j < 3; j++) {
				mx = (mx * 256.0) + monte[j];
				my = (my * 256.0) + monte[j + 3];
			}

			if ((mx * mx + my * my) <= incirc) {
				inmont++;
			}
		}
	}

	if (mcount == 0) {
		return 0.0;
	}

	double mpi = 4.0 * ((double) inmont / mcount);

	return std::fabs((mpi - pi) / pi);
}

}// namespace rspamd::text_stats

#endif
