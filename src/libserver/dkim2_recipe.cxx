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

/*
 * Recipes of the DKIM2 Message-Instance header field, see dkim2_recipe.hxx
 */

#include "config.h"
#include "dkim2_recipe.hxx"
#include "dkim2_util.hxx"

#include "contrib/fmt/include/fmt/core.h"

#include <algorithm>
#include <optional>

namespace rspamd::dkim2 {

/* How much of an invalid recipe step is quoted in an error */
constexpr std::size_t DKIM2_MAX_QUOTED_STEP = 64;
/* Nesting of a valid recipe: object, "h" object, steps, step, values */
constexpr unsigned int DKIM2_MAX_JSON_DEPTH = 8;

/*
 * A strict JSON (RFC 8259) reader for recipes. A general purpose parser is
 * deliberately not used here: recipes MUST have unique keys, which lenient
 * parsers silently merge or overwrite, and any syntax accepted here but not
 * by other Verifiers (comments, unquoted keys and so on) would make the
 * verdict depend on the implementation.
 */
class recipe_reader {
public:
	recipe_reader(std::string_view json, const recipe_limits_t &limits)
		: in(json), limits(limits)
	{
	}

	auto parse() -> tl::expected<recipe_t, recipe_error_t>
	{
		recipe_t res;

		skip_ws();

		if (!parse_top(res)) {
			return tl::make_unexpected(std::move(err));
		}

		skip_ws();

		if (pos != in.size()) {
			return tl::make_unexpected(recipe_error_t{recipe_error_kind::invalid_json,
													  "trailing data"});
		}

		if (!res.has_headers && !res.has_body) {
			return tl::make_unexpected(recipe_error_t{recipe_error_kind::invalid_recipe,
													  "{}"});
		}

		return res;
	}

private:
	std::string_view in;
	const recipe_limits_t &limits;
	std::size_t pos = 0;
	std::size_t ndata = 0; /* strings of all "d" and "u" steps */
	recipe_error_t err{recipe_error_kind::invalid_json, {}};

	auto bad_json(std::string what) -> bool
	{
		err = recipe_error_t{recipe_error_kind::invalid_json, std::move(what)};
		return false;
	}

	/* `from` is where the offending text starts, it is quoted in the error */
	auto bad_recipe(std::size_t from) -> bool
	{
		auto end = pos;

		/* An error is usually found just before the step is closed */
		while (end < in.size() && (in[end] == ' ' || in[end] == '\t')) {
			end++;
		}
		if (end < in.size() && in[end] == '}') {
			end++;
		}

		auto quoted = in.substr(from, std::min(end > from ? end - from : in.size() - from,
											   DKIM2_MAX_QUOTED_STEP));
		std::string what;

		for (auto c: quoted) {
			/* It ends up in logs and in the symbol options */
			what.push_back(static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) >= 0x7f ? '?' : c);
		}

		err = recipe_error_t{recipe_error_kind::invalid_recipe, std::move(what)};
		return false;
	}

	auto too_complex(std::string what) -> bool
	{
		err = recipe_error_t{recipe_error_kind::too_complex, std::move(what)};
		return false;
	}

	void skip_ws()
	{
		while (pos < in.size() &&
			   (in[pos] == ' ' || in[pos] == '\t' || in[pos] == '\r' || in[pos] == '\n')) {
			pos++;
		}
	}

	auto peek() const -> char
	{
		return pos < in.size() ? in[pos] : '\0';
	}

	auto expect(char c) -> bool
	{
		skip_ws();

		if (peek() != c) {
			return bad_json(fmt::format("'{}' expected at offset {}", c, pos));
		}

		pos++;

		return true;
	}

	auto parse_hex4(unsigned int &out) -> bool
	{
		if (in.size() - pos < 4) {
			return false;
		}

		out = 0;

		for (int k = 0; k < 4; k++) {
			auto c = in[pos++];
			out <<= 4;

			if (c >= '0' && c <= '9') {
				out |= c - '0';
			}
			else if (c >= 'a' && c <= 'f') {
				out |= c - 'a' + 10;
			}
			else if (c >= 'A' && c <= 'F') {
				out |= c - 'A' + 10;
			}
			else {
				return false;
			}
		}

		return true;
	}

	static void append_utf8(std::string &out, unsigned int cp)
	{
		if (cp < 0x80) {
			out.push_back(static_cast<char>(cp));
		}
		else if (cp < 0x800) {
			out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
			out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
		}
		else if (cp < 0x10000) {
			out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
			out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
			out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
		}
		else {
			out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
			out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
			out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
			out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
		}
	}

	auto parse_string(std::string &out) -> bool
	{
		skip_ws();

		if (peek() != '"') {
			return bad_json(fmt::format("string expected at offset {}", pos));
		}

		pos++;

		for (;;) {
			if (pos >= in.size()) {
				return bad_json("unterminated string");
			}

			auto c = in[pos++];

			if (c == '"') {
				return true;
			}

			if (static_cast<unsigned char>(c) < 0x20) {
				return bad_json("control character in a string");
			}

			if (c != '\\') {
				out.push_back(c);
				continue;
			}

			if (pos >= in.size()) {
				return bad_json("unterminated string");
			}

			switch (in[pos++]) {
			case '"':
				out.push_back('"');
				break;
			case '\\':
				out.push_back('\\');
				break;
			case '/':
				out.push_back('/');
				break;
			case 'b':
				out.push_back('\b');
				break;
			case 'f':
				out.push_back('\f');
				break;
			case 'n':
				out.push_back('\n');
				break;
			case 'r':
				out.push_back('\r');
				break;
			case 't':
				out.push_back('\t');
				break;
			case 'u': {
				unsigned int cp = 0;

				if (!parse_hex4(cp)) {
					return bad_json("invalid \\u escape");
				}

				if (cp >= 0xD800 && cp <= 0xDBFF) {
					/* A high surrogate must be followed by a low one */
					unsigned int low = 0;

					if (in.size() - pos < 6 || in[pos] != '\\' || in[pos + 1] != 'u') {
						return bad_json("unpaired surrogate");
					}

					pos += 2;

					if (!parse_hex4(low) || low < 0xDC00 || low > 0xDFFF) {
						return bad_json("unpaired surrogate");
					}

					cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
				}
				else if (cp >= 0xDC00 && cp <= 0xDFFF) {
					return bad_json("unpaired surrogate");
				}

				append_utf8(out, cp);
				break;
			}
			default:
				return bad_json("invalid escape");
			}
		}
	}

	/* An integer of the schema: digits only, at least 1 */
	auto parse_index(std::size_t &out) -> bool
	{
		skip_ws();

		auto start = pos;

		while (pos < in.size() && in[pos] >= '0' && in[pos] <= '9') {
			pos++;
		}

		auto digits = in.substr(start, pos - start);
		auto c = peek();

		if (digits.empty() || c == '.' || c == 'e' || c == 'E' ||
			(digits.size() > 1 && digits.front() == '0')) {
			/* Not an integer in the plain form; minus is not a digit either */
			return bad_recipe(start);
		}

		auto val = parse_uint(digits);

		if (!val || *val == 0 || *val > G_MAXUINT32) {
			return bad_recipe(start);
		}

		out = static_cast<std::size_t>(*val);

		return true;
	}

	/*
	 * Iterate over `"key": value` members of an object, checking that the
	 * keys are unique and in lower case. `func(key, key_pos)` must consume
	 * the value.
	 */
	template<typename Func>
	auto parse_object(Func &&func) -> bool
	{
		if (!expect('{')) {
			return false;
		}

		std::vector<std::string> seen;

		skip_ws();

		if (peek() == '}') {
			pos++;
			return true;
		}

		for (;;) {
			std::string key;

			skip_ws();
			auto key_pos = pos;

			if (!parse_string(key)) {
				return false;
			}

			if (std::any_of(key.begin(), key.end(), [](char c) { return g_ascii_isupper(c); }) ||
				std::find(seen.begin(), seen.end(), key) != seen.end()) {
				/* Keys MUST be in lower case and MUST be unique */
				return bad_recipe(key_pos);
			}

			if (seen.size() >= limits.max_names) {
				return too_complex("too many keys in an object");
			}

			if (!expect(':') || !func(key, key_pos)) {
				return false;
			}

			seen.emplace_back(std::move(key));
			skip_ws();

			if (peek() == ',') {
				pos++;
				continue;
			}

			return expect('}');
		}
	}

	/* Iterate over the elements of an array; `func()` must consume one */
	template<typename Func>
	auto parse_array(Func &&func) -> bool
	{
		if (!expect('[')) {
			return false;
		}

		skip_ws();

		if (peek() == ']') {
			pos++;
			return true;
		}

		for (;;) {
			if (!func()) {
				return false;
			}

			skip_ws();

			if (peek() == ',') {
				pos++;
				continue;
			}

			return expect(']');
		}
	}

	/* Skip any JSON value: used for the keys that the schema does not define */
	auto skip_value(unsigned int depth) -> bool
	{
		if (depth > DKIM2_MAX_JSON_DEPTH) {
			return too_complex("JSON is nested too deeply");
		}

		skip_ws();

		auto c = peek();

		if (c == '{') {
			return parse_object([&](const std::string &, std::size_t) {
				return skip_value(depth + 1);
			});
		}
		if (c == '[') {
			return parse_array([&]() {
				return skip_value(depth + 1);
			});
		}
		if (c == '"') {
			std::string unused;
			return parse_string(unused);
		}

		for (std::string_view lit: {"true", "false", "null"}) {
			if (in.substr(pos).starts_with(lit)) {
				pos += lit.size();
				return true;
			}
		}

		/* A number: -?int frac? exp? */
		auto start = pos;

		if (peek() == '-') {
			pos++;
		}

		auto digits = [&]() -> bool {
			auto from = pos;

			while (pos < in.size() && in[pos] >= '0' && in[pos] <= '9') {
				pos++;
			}

			return pos > from;
		};

		auto int_start = pos;

		if (!digits() || (pos - int_start > 1 && in[int_start] == '0')) {
			pos = start;
			return bad_json(fmt::format("value expected at offset {}", start));
		}

		if (peek() == '.') {
			pos++;

			if (!digits()) {
				return bad_json("invalid number");
			}
		}

		if (peek() == 'e' || peek() == 'E') {
			pos++;

			if (peek() == '+' || peek() == '-') {
				pos++;
			}

			if (!digits()) {
				return bad_json("invalid number");
			}
		}

		return true;
	}

	/* An array of strings of a "d" or a "u" step */
	auto parse_data(recipe_step_t &step, bool is_base64, std::size_t step_pos) -> bool
	{
		skip_ws();

		if (peek() != '[') {
			return skip_value(0) && bad_recipe(step_pos);
		}

		auto ok = parse_array([&]() {
			std::string line;

			skip_ws();

			if (peek() != '"') {
				return skip_value(0) && bad_recipe(step_pos);
			}

			if (!parse_string(line)) {
				return false;
			}

			if (is_base64) {
				/* No whitespace is allowed inside (Section 5) */
				auto decoded = b64_decode(line, false);

				if (!decoded) {
					return bad_recipe(step_pos);
				}

				line = std::move(*decoded);
			}

			if (line.find_first_of("\r\n") != std::string::npos) {
				return bad_recipe(step_pos);
			}

			if (++ndata > limits.max_data_lines) {
				return too_complex("too many data lines in a recipe");
			}

			step.data.emplace_back(std::move(line));

			return true;
		});

		if (ok && step.data.empty()) {
			/* minItems is 1 */
			return bad_recipe(step_pos);
		}

		return ok;
	}

	/* recipe-steps: an array of objects with exactly one of "c", "d", "u" */
	auto parse_steps(std::vector<recipe_step_t> &steps) -> bool
	{
		skip_ws();

		auto steps_pos = pos;

		if (peek() != '[') {
			return skip_value(0) && bad_recipe(steps_pos);
		}

		/* The end of the last copy range: they must ascend without overlaps */
		std::size_t prev_end = 0;

		return parse_array([&]() {
			skip_ws();

			auto step_pos = pos;

			if (peek() != '{') {
				return skip_value(0) && bad_recipe(step_pos);
			}

			if (steps.size() >= limits.max_steps) {
				return too_complex("too many recipe steps");
			}

			recipe_step_t step;
			unsigned int nkeys = 0;

			auto ok = parse_object([&](const std::string &key, std::size_t) {
				if (++nkeys > 1) {
					return skip_value(0) && bad_recipe(step_pos);
				}

				if (key == "c") {
					std::size_t nvals = 0;

					skip_ws();

					if (peek() != '[') {
						return skip_value(0) && bad_recipe(step_pos);
					}

					auto arr_ok = parse_array([&]() {
						if (nvals >= 2) {
							return skip_value(0) && bad_recipe(step_pos);
						}

						return parse_index(nvals++ == 0 ? step.start : step.end);
					});

					if (!arr_ok) {
						return false;
					}

					if (nvals != 2 || step.end < step.start || step.start <= prev_end) {
						return bad_recipe(step_pos);
					}

					step.is_copy = true;
					prev_end = step.end;

					return true;
				}
				if (key == "d") {
					return parse_data(step, false, step_pos);
				}
				if (key == "u") {
					return parse_data(step, true, step_pos);
				}

				return skip_value(0) && bad_recipe(step_pos);
			});

			if (!ok) {
				return false;
			}

			if (nkeys != 1) {
				return bad_recipe(step_pos);
			}

			steps.emplace_back(std::move(step));

			return true;
		});
	}

	auto parse_top(recipe_t &res) -> bool
	{
		skip_ws();

		if (peek() != '{') {
			/* Something else, check that it is JSON to report it properly */
			return skip_value(0) && bad_recipe(0);
		}

		return parse_object([&](const std::string &key, std::size_t key_pos) {
			if (key == "h") {
				skip_ws();

				if (peek() != '{') {
					return skip_value(0) && bad_recipe(key_pos);
				}

				res.has_headers = true;

				auto ok = parse_object([&](const std::string &name, std::size_t name_pos) {
					auto is_ftext = [](char c) {
						return c > 0x20 && c < 0x7f && c != ':';
					};

					if (name.empty() || !std::all_of(name.begin(), name.end(), is_ftext) ||
						is_unsigned_header(name)) {
						/* Not a field name at all, or */
						/* Recipes MUST NOT be specified for unsigned header fields */
						return skip_value(0) && bad_recipe(name_pos);
					}

					auto &entry = res.headers.emplace_back();
					entry.first = name;

					return parse_steps(entry.second);
				});

				if (ok && res.headers.empty()) {
					/* minProperties is 1 */
					return bad_recipe(key_pos);
				}

				return ok;
			}
			if (key == "b") {
				skip_ws();
				res.has_body = true;

				if (in.substr(pos).starts_with("null")) {
					pos += 4;
					res.body_null = true;

					return true;
				}

				return parse_steps(res.body);
			}

			/* Not in the schema, which does not forbid additional properties */
			return skip_value(0);
		});
	}
};

/* Well-formed UTF-8: no overlong forms, no surrogates, nothing above U+10FFFF */
static auto
is_valid_utf8(std::string_view in) -> bool
{
	std::size_t pos = 0;

	while (pos < in.size()) {
		auto c = static_cast<unsigned char>(in[pos]);
		std::size_t ntail;
		unsigned int cp, min_cp;

		if (c < 0x80) {
			pos++;
			continue;
		}
		else if ((c & 0xE0) == 0xC0) {
			ntail = 1;
			cp = c & 0x1F;
			min_cp = 0x80;
		}
		else if ((c & 0xF0) == 0xE0) {
			ntail = 2;
			cp = c & 0x0F;
			min_cp = 0x800;
		}
		else if ((c & 0xF8) == 0xF0) {
			ntail = 3;
			cp = c & 0x07;
			min_cp = 0x10000;
		}
		else {
			return false;
		}

		if (in.size() - pos <= ntail) {
			return false;
		}

		for (std::size_t k = 1; k <= ntail; k++) {
			auto t = static_cast<unsigned char>(in[pos + k]);

			if ((t & 0xC0) != 0x80) {
				return false;
			}

			cp = (cp << 6) | (t & 0x3F);
		}

		if (cp < min_cp || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
			return false;
		}

		pos += ntail + 1;
	}

	return true;
}

auto recipe_t::find_header(std::string_view lc_name) const -> const std::vector<recipe_step_t> *
{
	for (const auto &[name, steps]: headers) {
		if (name == lc_name) {
			return &steps;
		}
	}

	return nullptr;
}

auto parse_recipe(std::string_view json, const recipe_limits_t &limits)
	-> tl::expected<recipe_t, recipe_error_t>
{
	if (json.size() > limits.max_recipe_len) {
		return tl::make_unexpected(recipe_error_t{
			recipe_error_kind::too_complex,
			fmt::format("recipe is too large: {} bytes (max {})",
						json.size(), limits.max_recipe_len)});
	}

	if (!is_valid_utf8(json)) {
		/* JSON text is UTF-8 by definition; other octets need "u" steps */
		return tl::make_unexpected(recipe_error_t{recipe_error_kind::invalid_json,
												  "not valid UTF-8"});
	}

	return recipe_reader{json, limits}.parse();
}

auto apply_recipe_steps(const std::vector<std::string_view> &current,
						const std::vector<recipe_step_t> &steps,
						std::size_t max_elements,
						std::size_t &budget)
	-> tl::expected<std::vector<std::string_view>, recipe_error_t>
{
	std::vector<std::string_view> out;

	auto emit = [&](std::string_view elt) -> bool {
		/* Two extra octets per element account for the line terminator */
		auto cost = elt.size() + 2;

		if (budget < cost || out.size() >= max_elements) {
			return false;
		}

		budget -= cost;
		out.emplace_back(elt);

		return true;
	};

	auto over_limits = []() {
		return tl::make_unexpected(recipe_error_t{recipe_error_kind::too_complex,
												  "recipe output limits exceeded"});
	};

	for (const auto &step: steps) {
		if (step.is_copy) {
			if (step.start < 1 || step.end < step.start || step.end > current.size()) {
				return tl::make_unexpected(recipe_error_t{
					recipe_error_kind::invalid_recipe,
					fmt::format("{{\"c\":[{},{}]}}", step.start, step.end)});
			}

			for (auto k = step.start; k <= step.end; k++) {
				if (!emit(current[k - 1])) {
					return over_limits();
				}
			}
		}
		else {
			for (const auto &d: step.data) {
				if (!emit(d)) {
					return over_limits();
				}
			}
		}
	}

	return out;
}

}// namespace rspamd::dkim2
