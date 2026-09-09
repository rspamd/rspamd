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

#ifndef RSPAMD_LUA_XML_SCANNER_HXX
#define RSPAMD_LUA_XML_SCANNER_HXX

#include "config.h"
#include "lua_common.h"

#include "contrib/ankerl/unordered_dense.h"
#include "contrib/expected/expected.hpp"
#include "contrib/fmt/include/fmt/format.h"
#include "libmime/mime_encoding.h"
#include "libserver/html/html_entities.hxx"
#include "libutil/mem_pool.h"
#include "libutil/rspamd_simdutf.h"
#include "libutil/str_util.h"
#include "libutil/util.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

/*
 * Bounded, non-validating XML scanner shared by the content extractors
 * (OOXML packages, SVG images). It is deliberately strict: no DTD internal
 * subsets, no unbound prefixes, no unescaped markup in attributes, and a hard
 * limit on every dimension an attacker controls (input size, depth, token
 * count, attribute count and length, namespace declarations, text volume,
 * wall clock).
 *
 * A Handler provides:
 *
 *   using namespaces = <policy>;
 *   auto start_element(namespace_id, std::string_view name,
 *                      const std::vector<attribute<namespaces>> &) -> status;
 *   auto end_element(namespace_id, std::string_view name) -> status;
 *   auto text(std::string_view) -> status;
 *
 * A namespaces policy provides an `id` enum class with at least the members
 * `unbound`, `none`, `xml` and `xmlns`, plus
 * `static auto classify(std::string_view uri) -> id`.
 */

namespace rspamd::xml {

constexpr std::string_view xml_namespace = "http://www.w3.org/XML/1998/namespace";
constexpr std::string_view xmlns_namespace = "http://www.w3.org/2000/xmlns/";

template<typename T>
using result = tl::expected<T, std::string>;

using status = result<void>;

struct limits {
	std::size_t max_input = 8U * 1024U * 1024U;
	std::size_t max_depth = 64;
	std::size_t max_tokens = 200000;
	std::size_t max_attributes = 256;
	std::size_t max_attribute_length = 64U * 1024U;
	std::size_t max_namespace_declarations = 1024;
	std::size_t max_text = 2U * 1024U * 1024U;
	double end_timestamp = 0;
	double timeout = 0;
	/* Accept a DOCTYPE that names an external subset; internal subsets are always rejected */
	bool allow_doctype = false;
	html::entity_decode_mode entities = html::entity_decode_mode::xml;
};

inline auto is_name_start(unsigned char ch) -> bool
{
	return ch == ':' || ch == '_' || (ch >= 'A' && ch <= 'Z') ||
		   (ch >= 'a' && ch <= 'z');
}

inline auto is_name_char(unsigned char ch) -> bool
{
	return is_name_start(ch) || ch == '-' || ch == '.' ||
		   (ch >= '0' && ch <= '9');
}

inline auto decode_entities(std::string_view input, html::entity_decode_mode mode)
	-> result<std::string>
{
	if (input.find('&') == std::string_view::npos) {
		return std::string{input};
	}

	std::string out{input};
	auto decoded = html::decode_entities_inplace(out.data(), out.size(), mode);
	if (!decoded) return tl::make_unexpected(std::move(decoded.error()));
	out.resize(*decoded);
	return out;
}

inline auto convert_encoding(std::string_view input, const char *encoding, std::size_t max_input)
	-> result<std::string>
{
	if (input.size() > G_MAXINT32) {
		return tl::make_unexpected(fmt::format("cannot convert XML from {}", encoding));
	}
	auto pool = std::unique_ptr<rspamd_mempool_t, decltype(&rspamd_mempool_delete)>{
		rspamd_mempool_new_short_lived("xml"), rspamd_mempool_delete};
	GError *error = nullptr;
	gsize output_len = 0;
	auto *converted = rspamd_mime_text_to_utf8(pool.get(),
											   const_cast<char *>(input.data()), input.size(), encoding, &output_len, &error);
	if (converted == nullptr) {
		if (error != nullptr) g_error_free(error);
		return tl::make_unexpected(fmt::format("cannot convert XML from {}", encoding));
	}
	if (output_len > max_input) {
		return tl::make_unexpected("XML input limit exceeded at byte 1");
	}
	return std::string{converted, output_len};
}

/* The encoding named by an XML declaration, unless it is UTF-8 already */
inline auto declared_encoding(std::string_view input) -> std::optional<std::string>
{
	if (!input.starts_with("<?xml")) return std::nullopt;
	auto close = input.find("?>");
	if (close == std::string_view::npos) return std::nullopt;
	auto declaration = input.substr(0, close);
	auto found = rspamd_substring_search_caseless(declaration.data(), declaration.size(),
												  "encoding", sizeof("encoding") - 1);
	if (found == -1) return std::nullopt;
	auto pos = static_cast<std::size_t>(found) + sizeof("encoding") - 1;
	while (pos < declaration.size() && g_ascii_isspace(declaration[pos])) pos++;
	if (pos >= declaration.size() || declaration[pos] != '=') return std::nullopt;
	pos++;
	while (pos < declaration.size() && g_ascii_isspace(declaration[pos])) pos++;
	if (pos >= declaration.size() || (declaration[pos] != '"' && declaration[pos] != '\'')) {
		return std::nullopt;
	}
	auto quote = declaration[pos++];
	auto end = declaration.find(quote, pos);
	if (end == std::string_view::npos || end == pos || end - pos > 32) return std::nullopt;
	auto value = declaration.substr(pos, end - pos);
	if (!std::all_of(value.begin(), value.end(), [](char ch) {
			return g_ascii_isalnum(static_cast<unsigned char>(ch)) || ch == '-' || ch == '_' || ch == '.';
		})) {
		return std::nullopt;
	}
	if ((value.size() == 5 && rspamd_lc_cmp(value.data(), "utf-8", 5) == 0) ||
		(value.size() == 4 && rspamd_lc_cmp(value.data(), "utf8", 4) == 0)) {
		return std::nullopt;
	}
	return std::string{value};
}

template<typename Namespaces>
struct attribute {
	typename Namespaces::id namespace_value;
	std::string_view name;
	std::string value;
};

template<typename Handler>
class scanner {
public:
	using namespaces = typename Handler::namespaces;
	using namespace_id = typename namespaces::id;
	using attribute_type = attribute<namespaces>;

	scanner(std::string_view raw_input, const limits &limits_value, Handler &handler)
		: raw_input_{raw_input}, limits_{limits_value}, handler_{handler}
	{
		namespaces_.emplace("xml", namespace_id::xml);
		namespaces_.emplace("xmlns", namespace_id::xmlns);
	}

	auto parse() -> status
	{
		if (auto ret = check_deadline(0); !ret) return ret;
		if (auto ret = prepare_input(); !ret) return ret;
		if (auto ret = check_deadline(0); !ret) return ret;

		while (pos_ < input_.size()) {
			if (input_[pos_] != '<') {
				auto next = input_.find('<', pos_);
				if (next == std::string_view::npos) {
					next = input_.size();
				}
				if (auto ret = emit_text(input_.substr(pos_, next - pos_), pos_, true); !ret) {
					return ret;
				}
				pos_ = next;
			}
			else if (starts_with(pos_, "<!--")) {
				auto close = input_.find("-->", pos_ + 4);
				if (close == std::string_view::npos) {
					return fail("unterminated XML comment", pos_);
				}
				if (auto ret = add_token(pos_); !ret) return ret;
				pos_ = close + 3;
			}
			else if (starts_with(pos_, "<![CDATA[")) {
				auto close = input_.find("]]>", pos_ + 9);
				if (close == std::string_view::npos) {
					return fail("unterminated CDATA section", pos_);
				}
				if (auto ret = emit_text(input_.substr(pos_ + 9, close - pos_ - 9), pos_, false);
					!ret) {
					return ret;
				}
				pos_ = close + 3;
			}
			else if (starts_with(pos_, "<?")) {
				auto close = input_.find("?>", pos_ + 2);
				if (close == std::string_view::npos) {
					return fail("unterminated processing instruction", pos_);
				}
				if (auto ret = add_token(pos_); !ret) return ret;
				pos_ = close + 2;
			}
			else if (pos_ + 9 <= input_.size() &&
					 rspamd_lc_cmp(input_.data() + pos_, "<!doctype", 9) == 0) {
				if (auto ret = parse_doctype(); !ret) return ret;
			}
			else if (starts_with(pos_, "<!")) {
				return fail("unsupported XML declaration", pos_);
			}
			else if (starts_with(pos_, "</")) {
				if (auto ret = parse_end_element(); !ret) return ret;
			}
			else {
				if (auto ret = parse_start_element(); !ret) return ret;
			}
		}
		if (!stack_.empty()) {
			return fail("unclosed XML element", input_.size());
		}
		return {};
	}

	auto tokens() const -> std::size_t
	{
		return tokens_;
	}

	auto has_doctype() const -> bool
	{
		return doctype_seen_;
	}

private:
	auto prepare_input() -> status
	{
		auto raw = raw_input_;
		if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xff &&
			static_cast<unsigned char>(raw[1]) == 0xfe) {
			auto converted = convert_encoding(raw.substr(2), "UTF-16LE", limits_.max_input);
			if (!converted) return tl::make_unexpected(std::move(converted.error()));
			owned_input_ = std::move(*converted);
			input_ = owned_input_;
		}
		else if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xfe &&
				 static_cast<unsigned char>(raw[1]) == 0xff) {
			auto converted = convert_encoding(raw.substr(2), "UTF-16BE", limits_.max_input);
			if (!converted) return tl::make_unexpected(std::move(converted.error()));
			owned_input_ = std::move(*converted);
			input_ = owned_input_;
		}
		else {
			input_ = raw;
			if (input_.size() >= 3 && static_cast<unsigned char>(input_[0]) == 0xef &&
				static_cast<unsigned char>(input_[1]) == 0xbb &&
				static_cast<unsigned char>(input_[2]) == 0xbf) {
				input_.remove_prefix(3);
			}
		}

		if (input_.size() > limits_.max_input) {
			return fail("XML input limit exceeded", 0);
		}
		if (!is_valid_utf8(input_)) {
			/* Honour a declared legacy encoding before giving up */
			auto encoding = declared_encoding(input_);
			if (!encoding) {
				return tl::make_unexpected("XML input is not valid UTF-8");
			}
			auto converted = convert_encoding(input_, encoding->c_str(), limits_.max_input);
			if (!converted) return tl::make_unexpected(std::move(converted.error()));
			owned_input_ = std::move(*converted);
			input_ = owned_input_;
			if (!is_valid_utf8(input_)) {
				return tl::make_unexpected("XML input is not valid UTF-8");
			}
		}
		for (auto ch: input_) {
			if (g_ascii_iscntrl(ch) && ch != '\t' && ch != '\n' && ch != '\r') {
				return tl::make_unexpected("XML input contains an invalid control character");
			}
		}
		return {};
	}

	static auto is_valid_utf8(std::string_view input) -> bool
	{
		return rspamd_fast_utf8_validate(
				   reinterpret_cast<const unsigned char *>(input.data()), input.size()) == 0;
	}

	auto fail(std::string_view message, std::size_t pos) const -> tl::unexpected<std::string>
	{
		return tl::make_unexpected(fmt::format("{} at byte {}", message, pos + 1));
	}

	auto starts_with(std::size_t pos, std::string_view needle) const -> bool
	{
		return pos <= input_.size() && needle.size() <= input_.size() - pos &&
			   input_.compare(pos, needle.size(), needle) == 0;
	}

	auto parse_doctype() -> status
	{
		if (!limits_.allow_doctype) {
			return fail("XML DTD declarations are not supported", pos_);
		}
		if (doctype_seen_ || root_seen_) {
			return fail("misplaced XML DTD declaration", pos_);
		}
		auto cursor = pos_ + 9;
		char quote = 0;
		while (cursor < input_.size()) {
			auto ch = input_[cursor];
			if (quote != 0) {
				if (ch == quote) quote = 0;
			}
			else if (ch == '"' || ch == '\'') {
				quote = ch;
			}
			else if (ch == '[') {
				return fail("XML DTD internal subsets are not supported", cursor);
			}
			else if (ch == '>') {
				break;
			}
			cursor++;
		}
		if (cursor >= input_.size()) {
			return fail("unterminated XML DTD declaration", pos_);
		}
		if (auto ret = add_token(pos_); !ret) return ret;
		doctype_seen_ = true;
		pos_ = cursor + 1;
		return {};
	}

	auto parse_name(std::size_t &cursor) const -> std::string_view
	{
		auto start = cursor;
		if (cursor >= input_.size() ||
			!is_name_start(static_cast<unsigned char>(input_[cursor]))) {
			return {};
		}
		cursor++;
		while (cursor < input_.size() &&
			   is_name_char(static_cast<unsigned char>(input_[cursor]))) {
			cursor++;
		}
		return input_.substr(start, cursor - start);
	}

	static auto split_qname(std::string_view qname)
		-> std::optional<std::pair<std::string_view, std::string_view>>
	{
		auto colon = qname.find(':');
		if (colon == std::string_view::npos) {
			return std::pair<std::string_view, std::string_view>{{}, qname};
		}
		if (colon == 0 || colon + 1 == qname.size() ||
			qname.find(':', colon + 1) != std::string_view::npos) {
			return std::nullopt;
		}
		return std::pair<std::string_view, std::string_view>{
			qname.substr(0, colon), qname.substr(colon + 1)};
	}

	auto lookup_namespace(std::string_view prefix) const -> namespace_id
	{
		auto found = namespaces_.find(prefix);
		return found == namespaces_.end() ? namespace_id::unbound : found->second;
	}

	void restore_namespaces(std::size_t base)
	{
		while (namespace_changes_.size() > base) {
			auto change = namespace_changes_.back();
			namespace_changes_.pop_back();
			if (change.previous == namespace_id::unbound) {
				namespaces_.erase(change.prefix);
			}
			else {
				namespaces_.find(change.prefix)->second = change.previous;
			}
		}
	}

	auto check_deadline(std::size_t at) const -> status
	{
		if (limits_.end_timestamp > 0 &&
			rspamd_get_ticks(FALSE) >= limits_.end_timestamp) {
			return fail("XML processing timeout", at);
		}
		return {};
	}

	auto add_token(std::size_t at) -> status
	{
		tokens_++;
		if (tokens_ > limits_.max_tokens) {
			return fail("XML token limit exceeded", at);
		}
		if ((tokens_ % 256U) == 0) return check_deadline(at);
		return {};
	}

	auto emit_text(std::string_view raw, std::size_t at, bool decode) -> status
	{
		if (raw.empty()) {
			return {};
		}
		std::string decoded;
		std::string_view value = raw;
		if (decode && raw.find('&') != std::string_view::npos) {
			auto decoded_result = decode_entities(raw, limits_.entities);
			if (!decoded_result) {
				return tl::make_unexpected(std::move(decoded_result.error()));
			}
			decoded = std::move(*decoded_result);
			value = decoded;
		}
		text_bytes_ += value.size();
		if (text_bytes_ > limits_.max_text) {
			return fail("XML text limit exceeded", at);
		}
		if (auto ret = add_token(at); !ret) return ret;
		return handler_.text(value);
	}

	auto parse_end_element() -> status
	{
		auto at = pos_;
		auto cursor = pos_ + 2;
		auto qname = parse_name(cursor);
		if (qname.empty()) {
			return fail("invalid XML end element", at);
		}
		while (cursor < input_.size() && g_ascii_isspace(input_[cursor])) {
			cursor++;
		}
		if (cursor >= input_.size() || input_[cursor] != '>') {
			return fail("invalid XML end element", cursor);
		}
		if (stack_.empty() || stack_.back().qname != qname) {
			return fail("mismatched XML end element", at);
		}
		if (auto ret = add_token(at); !ret) return ret;
		auto element = std::move(stack_.back());
		stack_.pop_back();
		auto handler_result = handler_.end_element(element.namespace_value, element.name);
		if (!handler_result) return handler_result;
		restore_namespaces(element.namespace_base);
		pos_ = cursor + 1;
		return {};
	}

	auto parse_start_element() -> status
	{
		auto at = pos_;
		auto cursor = pos_ + 1;
		auto qname = parse_name(cursor);
		if (qname.empty()) {
			return fail("invalid XML start element", at);
		}

		struct raw_attribute {
			std::string_view qname;
			std::string value;
		};
		std::vector<raw_attribute> raw_attributes;
		ankerl::unordered_dense::set<std::string_view> attribute_names;
		bool self_closing = false;
		bool closed = false;

		while (cursor < input_.size()) {
			while (cursor < input_.size() && g_ascii_isspace(input_[cursor])) {
				cursor++;
			}
			if (cursor < input_.size() && input_[cursor] == '>') {
				cursor++;
				closed = true;
				break;
			}
			if (cursor + 1 < input_.size() && input_[cursor] == '/' &&
				input_[cursor + 1] == '>') {
				cursor += 2;
				self_closing = true;
				closed = true;
				break;
			}
			if ((raw_attributes.size() % 16U) == 0) {
				if (auto ret = check_deadline(cursor); !ret) return ret;
			}
			if (auto ret = add_token(cursor); !ret) return ret;

			auto attribute_qname = parse_name(cursor);
			if (attribute_qname.empty()) {
				return fail("invalid XML attribute name", cursor);
			}
			if (!attribute_names.emplace(attribute_qname).second) {
				return fail("duplicate XML attribute", cursor);
			}
			while (cursor < input_.size() && g_ascii_isspace(input_[cursor])) {
				cursor++;
			}
			if (cursor >= input_.size() || input_[cursor] != '=') {
				return fail("missing XML attribute value", cursor);
			}
			cursor++;
			while (cursor < input_.size() && g_ascii_isspace(input_[cursor])) {
				cursor++;
			}
			if (cursor >= input_.size() || (input_[cursor] != '"' && input_[cursor] != '\'')) {
				return fail("unquoted XML attribute value", cursor);
			}
			auto quote = input_[cursor];
			auto value_start = ++cursor;
			auto value_end = input_.find(quote, value_start);
			if (value_end == std::string_view::npos) {
				return fail("unterminated XML attribute value", cursor - 1);
			}
			if (value_end - value_start > limits_.max_attribute_length) {
				return fail("XML attribute length limit exceeded", cursor - 1);
			}
			auto raw_value = input_.substr(value_start, value_end - value_start);
			if (raw_value.find('<') != std::string_view::npos) {
				return fail("unescaped less-than sign in XML attribute", value_start);
			}
			auto decoded = decode_entities(raw_value, limits_.entities);
			if (!decoded) return tl::make_unexpected(std::move(decoded.error()));
			raw_attributes.push_back({attribute_qname, std::move(*decoded)});
			if (raw_attributes.size() > limits_.max_attributes) {
				return fail("XML attribute limit exceeded", cursor);
			}
			cursor = value_end + 1;
		}
		if (!closed) {
			return fail("unterminated XML start element", at);
		}

		if (auto ret = check_deadline(at); !ret) return ret;
		auto namespace_base = namespace_changes_.size();
		for (const auto &attribute_value: raw_attributes) {
			std::optional<std::string_view> prefix;
			if (attribute_value.qname == "xmlns") {
				prefix = std::string_view{};
			}
			else if (attribute_value.qname.starts_with("xmlns:")) {
				prefix = attribute_value.qname.substr(6);
			}
			if (prefix) {
				if (*prefix == "xmlns" ||
					(*prefix == "xml" && attribute_value.value != xml_namespace) ||
					(*prefix != "xml" && attribute_value.value == xml_namespace) ||
					attribute_value.value == xmlns_namespace) {
					restore_namespaces(namespace_base);
					return fail("invalid XML namespace declaration", at);
				}
				namespace_declarations_++;
				if (namespace_declarations_ > limits_.max_namespace_declarations) {
					restore_namespaces(namespace_base);
					return fail("XML namespace declaration limit exceeded", at);
				}
				auto value = namespaces::classify(attribute_value.value);
				auto previous = lookup_namespace(*prefix);
				namespace_changes_.push_back({*prefix, previous});
				auto [it, inserted] = namespaces_.try_emplace(*prefix, value);
				if (!inserted) it->second = value;
			}
		}

		auto element_name = split_qname(qname);
		if (!element_name) {
			restore_namespaces(namespace_base);
			return fail("invalid qualified XML element name", at);
		}
		auto element_namespace = lookup_namespace(element_name->first);
		if (!element_name->first.empty() && element_namespace == namespace_id::unbound) {
			restore_namespaces(namespace_base);
			return fail("unbound XML element prefix", at);
		}
		if (element_name->first.empty() && element_namespace == namespace_id::unbound) {
			element_namespace = namespace_id::none;
		}

		std::vector<attribute_type> attributes;
		attributes.reserve(raw_attributes.size());
		for (auto &attribute_value: raw_attributes) {
			if (attribute_value.qname == "xmlns" || attribute_value.qname.starts_with("xmlns:")) {
				continue;
			}
			auto name = split_qname(attribute_value.qname);
			if (!name) {
				restore_namespaces(namespace_base);
				return fail("invalid qualified XML attribute name", at);
			}
			auto attribute_namespace = namespace_id::none;
			if (!name->first.empty()) {
				attribute_namespace = lookup_namespace(name->first);
				if (attribute_namespace == namespace_id::unbound) {
					restore_namespaces(namespace_base);
					return fail("unbound XML attribute prefix", at);
				}
			}
			attributes.push_back({attribute_namespace, name->second, std::move(attribute_value.value)});
		}

		if (stack_.size() + 1 > limits_.max_depth) {
			restore_namespaces(namespace_base);
			return fail("XML depth limit exceeded", at);
		}
		if (auto ret = add_token(at); !ret) return ret;
		root_seen_ = true;
		if (auto ret = handler_.start_element(element_namespace, element_name->second, attributes);
			!ret) {
			return ret;
		}

		if (self_closing) {
			if (auto ret = add_token(at); !ret) return ret;
			if (auto ret = handler_.end_element(element_namespace, element_name->second); !ret) {
				return ret;
			}
			restore_namespaces(namespace_base);
		}
		else {
			stack_.push_back({qname, element_namespace, element_name->second, namespace_base});
		}
		pos_ = cursor;
		return {};
	}

	struct namespace_change {
		std::string_view prefix;
		namespace_id previous;
	};

	struct element_state {
		std::string_view qname;
		namespace_id namespace_value;
		std::string_view name;
		std::size_t namespace_base;
	};

	std::string_view raw_input_;
	limits limits_;
	Handler &handler_;
	std::string owned_input_;
	std::string_view input_;
	ankerl::unordered_dense::map<std::string_view, namespace_id> namespaces_;
	std::vector<namespace_change> namespace_changes_;
	std::vector<element_state> stack_;
	std::size_t pos_ = 0;
	std::size_t tokens_ = 0;
	std::size_t namespace_declarations_ = 0;
	std::size_t text_bytes_ = 0;
	bool doctype_seen_ = false;
	bool root_seen_ = false;
};

template<typename Namespaces>
auto get_attribute(const std::vector<attribute<Namespaces>> &attributes, std::string_view name,
				   typename Namespaces::id namespace_value = Namespaces::id::none)
	-> const std::string *
{
	for (const auto &attribute_value: attributes) {
		if (attribute_value.name == name && attribute_value.namespace_value == namespace_value) {
			return &attribute_value.value;
		}
	}
	return nullptr;
}

inline auto has_ascii_control(std::string_view value) -> bool
{
	return std::any_of(value.begin(), value.end(), [](char ch) {
		return g_ascii_iscntrl(static_cast<unsigned char>(ch));
	});
}

inline auto has_uri_scheme(std::string_view value) -> bool
{
	auto is_alpha = [](unsigned char ch) {
		return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
	};
	auto is_digit = [](unsigned char ch) {
		return ch >= '0' && ch <= '9';
	};

	if (value.empty() || !is_alpha(static_cast<unsigned char>(value.front()))) {
		return false;
	}
	for (std::size_t i = 1; i < value.size(); i++) {
		auto ch = static_cast<unsigned char>(value[i]);
		if (ch == ':') return true;
		if (!is_alpha(ch) && !is_digit(ch) && ch != '+' && ch != '-' && ch != '.') {
			return false;
		}
	}

	return false;
}

/* Derive the wall clock deadline from a relative timeout when none is set */
inline auto effective_limits(const limits &configured) -> limits
{
	auto result_value = configured;
	if (result_value.end_timestamp <= 0 && result_value.timeout > 0) {
		result_value.end_timestamp = rspamd_get_ticks(FALSE) + result_value.timeout;
	}
	return result_value;
}

/* Read the `xml` sub-table of a Lua options table on top of `defaults` */
inline auto read_limits(lua_State *L, int table_index, const limits &defaults) -> result<limits>
{
	auto result_value = defaults;
	if (!lua_istable(L, table_index)) return result_value;
	table_index = lua_absindex(L, table_index);
	lua_getfield(L, table_index, "xml");
	if (lua_istable(L, -1)) {
		auto xml_index = lua_absindex(L, -1);
		int64_t max_input = result_value.max_input;
		int64_t max_depth = result_value.max_depth;
		int64_t max_tokens = result_value.max_tokens;
		int64_t max_attributes = result_value.max_attributes;
		int64_t max_attribute_length = result_value.max_attribute_length;
		int64_t max_namespace_declarations = result_value.max_namespace_declarations;
		int64_t max_text = result_value.max_text;
		double end_timestamp = result_value.end_timestamp;
		double timeout = result_value.timeout;
		GError *error = nullptr;
		if (!rspamd_lua_parse_table_arguments(L, xml_index, &error,
											  RSPAMD_LUA_PARSE_ARGUMENTS_IGNORE_MISSING,
											  "max_input=I;max_depth=I;max_tokens=I;max_attributes=I;"
											  "max_attribute_length=I;max_namespace_declarations=I;"
											  "max_text=I;end_timestamp=N;timeout=N",
											  &max_input, &max_depth, &max_tokens, &max_attributes,
											  &max_attribute_length, &max_namespace_declarations,
											  &max_text, &end_timestamp, &timeout)) {
			auto message = error != nullptr ? std::string{error->message} : "invalid XML limits";
			if (error != nullptr) g_error_free(error);
			lua_pop(L, 1);
			return tl::make_unexpected(std::move(message));
		}
		if (max_input >= 0) result_value.max_input = max_input;
		if (max_depth >= 0) result_value.max_depth = max_depth;
		if (max_tokens >= 0) result_value.max_tokens = max_tokens;
		if (max_attributes >= 0) result_value.max_attributes = max_attributes;
		if (max_attribute_length >= 0) result_value.max_attribute_length = max_attribute_length;
		if (max_namespace_declarations >= 0) {
			result_value.max_namespace_declarations = max_namespace_declarations;
		}
		if (max_text >= 0) result_value.max_text = max_text;
		result_value.end_timestamp = end_timestamp;
		result_value.timeout = timeout;
	}
	lua_pop(L, 1);
	return result_value;
}

}// namespace rspamd::xml

#endif
