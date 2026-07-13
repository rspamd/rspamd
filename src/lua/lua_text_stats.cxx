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

#include "lua_common.h"
#include "lua_text_stats.hxx"

#include <span>
#include <cstddef>
#include <algorithm>

/***
 * @module rspamd_text
 * The following byte-distribution statistics methods are added to the
 * `rspamd_text` class. They produce deterministic, bit-reproducible results so
 * callers can compare them against fixed thresholds. Each takes an optional
 * byte range:
 *
 *   - `start` is a 1-based byte index (consistent with rspamd_text:span/sub/at),
 *     defaulting to 1;
 *   - `len` is a byte count, defaulting to the rest of the buffer after `start`.
 *
 * The range is clamped to the buffer (`start` in `[1, #text]`, `len` truncated
 * to the bytes available after `start`); an out-of-range or empty range yields 0
 * for every metric.
 */

using namespace rspamd::text_stats;

/*
 * Validate the optional (start, len) range of a text and return it as a byte
 * span. `start` is a 1-based index (consistent with rspamd_text:span/sub/at) and
 * len is truncated to the bytes available after it. An out-of-range or empty
 * request yields an empty span.
 */
static std::span<const std::byte>
lua_text_stats_slice(lua_State *L, const struct rspamd_lua_text *t,
					 int start_idx, int len_idx)
{
	const auto n = static_cast<std::size_t>(t->len);
	const auto *base = reinterpret_cast<const std::byte *>(t->start);

	lua_Integer start = luaL_optinteger(L, start_idx, 1);

	if (start < 1 || static_cast<std::size_t>(start) > n) {
		return {};
	}

	const std::size_t off = static_cast<std::size_t>(start) - 1;
	const std::size_t avail = n - off;
	lua_Integer len = luaL_optinteger(L, len_idx, static_cast<lua_Integer>(avail));

	if (len <= 0) {
		return {};
	}

	const std::size_t take = std::min(static_cast<std::size_t>(len), avail);

	return {base + off, take};
}

/***
 * @method text:entropy([start[, len]])
 * Shannon entropy of the byte range in bits/byte, in [0, 8].
 * @param {number} start optional 1-based byte index (default 1)
 * @param {number} len optional byte count (default: to end of text)
 * @return {number} entropy in bits per byte
 */
static int
lua_text_entropy(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *t = lua_check_text(L, 1);

	if (t == nullptr) {
		return luaL_error(L, "invalid arguments");
	}

	lua_pushnumber(L, entropy(lua_text_stats_slice(L, t, 2, 3)));

	return 1;
}

/***
 * @method text:byte_mean([start[, len]])
 * Arithmetic mean of the (unsigned) byte values in the range.
 * @param {number} start optional 1-based byte index (default 1)
 * @param {number} len optional byte count (default: to end of text)
 * @return {number} mean byte value
 */
static int
lua_text_byte_mean(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *t = lua_check_text(L, 1);

	if (t == nullptr) {
		return luaL_error(L, "invalid arguments");
	}

	lua_pushnumber(L, byte_mean(lua_text_stats_slice(L, t, 2, 3)));

	return 1;
}

/***
 * @method text:byte_deviation(mean[, start[, len]])
 * Mean absolute deviation of the byte values from `mean` (typically
 * `byte_mean` of the same range).
 * @param {number} mean reference mean value
 * @param {number} start optional 1-based byte index (default 1)
 * @param {number} len optional byte count (default: to end of text)
 * @return {number} mean absolute deviation
 */
static int
lua_text_byte_deviation(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *t = lua_check_text(L, 1);

	if (t == nullptr) {
		return luaL_error(L, "invalid arguments");
	}

	double mean = static_cast<double>(luaL_checknumber(L, 2));

	lua_pushnumber(L, byte_deviation(lua_text_stats_slice(L, t, 3, 4), mean));

	return 1;
}

/***
 * @method text:serial_correlation([start[, len]])
 * Serial correlation coefficient (ENT) of the byte range.
 * @param {number} start optional 1-based byte index (default 1)
 * @param {number} len optional byte count (default: to end of text)
 * @return {number} serial correlation coefficient
 */
static int
lua_text_serial_correlation(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *t = lua_check_text(L, 1);

	if (t == nullptr) {
		return luaL_error(L, "invalid arguments");
	}

	lua_pushnumber(L, serial_correlation(lua_text_stats_slice(L, t, 2, 3)));

	return 1;
}

/***
 * @method text:monte_carlo_pi([start[, len]])
 * Monte-Carlo Pi metric (ENT) of the byte range: the normalized deviation from
 * Pi, `fabs((4*inmont/groups - PI) / PI)` (note: this is the deviation from Pi,
 * not Pi itself).
 * @param {number} start optional 1-based byte index (default 1)
 * @param {number} len optional byte count (default: to end of text)
 * @return {number} normalized deviation from Pi
 */
static int
lua_text_monte_carlo_pi(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *t = lua_check_text(L, 1);

	if (t == nullptr) {
		return luaL_error(L, "invalid arguments");
	}

	lua_pushnumber(L, monte_carlo_pi(lua_text_stats_slice(L, t, 2, 3)));

	return 1;
}

static const struct luaL_reg text_stats_m[] = {
	{"entropy", lua_text_entropy},
	{"byte_mean", lua_text_byte_mean},
	{"byte_deviation", lua_text_byte_deviation},
	{"serial_correlation", lua_text_serial_correlation},
	{"monte_carlo_pi", lua_text_monte_carlo_pi},
	{nullptr, nullptr},
};

void rspamd_lua_text_stats_init(lua_State *L)
{
	/*
	 * Augment the existing rspamd{text} metatable (created by luaopen_text)
	 * with the statistics methods, so lua_text.c stays untouched. Methods live
	 * directly on the metatable (rspamd_lua_new_class sets __index = metatable).
	 */
	rspamd_lua_class_metatable(L, rspamd_text_classname);
	luaL_register(L, nullptr, text_stats_m);
	lua_pop(L, 1);
}
