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
#include "lua_classnames.h"

#include "contrib/ankerl/unordered_dense.h"
#include "libutil/rspamd_simdutf.h"
#include "libutil/util.h"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

/***
 * @module rspamd_ooxml
 * Native bounded parsing for the small OOXML schemas used by lua_content.
 */

namespace {

constexpr std::string_view xml_namespace = "http://www.w3.org/XML/1998/namespace";
constexpr std::string_view xmlns_namespace = "http://www.w3.org/2000/xmlns/";
constexpr std::string_view content_types_namespace =
	"http://schemas.openxmlformats.org/package/2006/content-types";
constexpr std::string_view strict_content_types_namespace =
	"http://purl.oclc.org/ooxml/package/content-types";
constexpr std::string_view relationships_namespace =
	"http://schemas.openxmlformats.org/package/2006/relationships";
constexpr std::string_view strict_relationships_namespace =
	"http://purl.oclc.org/ooxml/package/relationships";
constexpr std::string_view word_namespace =
	"http://schemas.openxmlformats.org/wordprocessingml/2006/main";
constexpr std::string_view strict_word_namespace =
	"http://purl.oclc.org/ooxml/wordprocessingml/main";
constexpr std::string_view drawing_namespace =
	"http://schemas.openxmlformats.org/drawingml/2006/main";
constexpr std::string_view strict_drawing_namespace =
	"http://purl.oclc.org/ooxml/drawingml/main";
constexpr std::string_view document_relationship_namespace =
	"http://schemas.openxmlformats.org/officeDocument/2006/relationships";
constexpr std::string_view strict_document_relationship_namespace =
	"http://purl.oclc.org/ooxml/officeDocument/relationships";
constexpr std::string_view hyperlink_relationship =
	"http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink";
constexpr std::string_view strict_hyperlink_relationship =
	"http://purl.oclc.org/ooxml/officeDocument/relationships/hyperlink";

struct xml_limits {
	std::size_t max_input = 8U * 1024U * 1024U;
	std::size_t max_depth = 64;
	std::size_t max_tokens = 200000;
	std::size_t max_attributes = 256;
	std::size_t max_attribute_length = 64U * 1024U;
	std::size_t max_text = 2U * 1024U * 1024U;
	double end_timestamp = 0;
	double timeout = 0;
};

struct ooxml_limits {
	xml_limits xml;
	std::size_t max_relationships = 4096;
	std::size_t max_target_length = 16U * 1024U;
	std::size_t max_text = 2U * 1024U * 1024U;
	std::size_t max_urls = 1024;
};

class ooxml_error final : public std::runtime_error {
public:
	explicit ooxml_error(std::string message)
		: std::runtime_error(std::move(message))
	{
	}
};

auto ascii_lower(std::string_view input) -> std::string
{
	std::string result;
	result.reserve(input.size());
	for (auto ch: input) {
		if (ch >= 'A' && ch <= 'Z') {
			ch = static_cast<char>(ch + ('a' - 'A'));
		}
		result.push_back(ch);
	}
	return result;
}

auto ascii_iequal(std::string_view lhs, std::string_view rhs) -> bool
{
	if (lhs.size() != rhs.size()) {
		return false;
	}
	for (std::size_t i = 0; i < lhs.size(); i++) {
		auto l = lhs[i];
		auto r = rhs[i];
		if (l >= 'A' && l <= 'Z') {
			l = static_cast<char>(l + ('a' - 'A'));
		}
		if (r >= 'A' && r <= 'Z') {
			r = static_cast<char>(r + ('a' - 'A'));
		}
		if (l != r) {
			return false;
		}
	}
	return true;
}

auto is_space(unsigned char ch) -> bool
{
	return ch == 0x20 || ch == 0x09 || ch == 0x0a || ch == 0x0d;
}

auto is_name_start(unsigned char ch) -> bool
{
	return ch == ':' || ch == '_' || (ch >= 'A' && ch <= 'Z') ||
		   (ch >= 'a' && ch <= 'z');
}

auto is_name_char(unsigned char ch) -> bool
{
	return is_name_start(ch) || ch == '-' || ch == '.' ||
		   (ch >= '0' && ch <= '9');
}

auto valid_xml_codepoint(std::uint32_t cp) -> bool
{
	return cp == 0x09 || cp == 0x0a || cp == 0x0d ||
		   (cp >= 0x20 && cp <= 0xd7ff) ||
		   (cp >= 0xe000 && cp <= 0xfffd) ||
		   (cp >= 0x10000 && cp <= 0x10ffff);
}

void append_utf8(std::string &out, std::uint32_t cp)
{
	if (!valid_xml_codepoint(cp)) {
		throw ooxml_error{"invalid XML character reference"};
	}
	if (cp <= 0x7f) {
		out.push_back(static_cast<char>(cp));
	}
	else if (cp <= 0x7ff) {
		out.push_back(static_cast<char>(0xc0U + (cp >> 6U)));
		out.push_back(static_cast<char>(0x80U + (cp & 0x3fU)));
	}
	else if (cp <= 0xffff) {
		out.push_back(static_cast<char>(0xe0U + (cp >> 12U)));
		out.push_back(static_cast<char>(0x80U + ((cp >> 6U) & 0x3fU)));
		out.push_back(static_cast<char>(0x80U + (cp & 0x3fU)));
	}
	else {
		out.push_back(static_cast<char>(0xf0U + (cp >> 18U)));
		out.push_back(static_cast<char>(0x80U + ((cp >> 12U) & 0x3fU)));
		out.push_back(static_cast<char>(0x80U + ((cp >> 6U) & 0x3fU)));
		out.push_back(static_cast<char>(0x80U + (cp & 0x3fU)));
	}
}

auto decode_entities(std::string_view input) -> std::string
{
	if (input.find('&') == std::string_view::npos) {
		return std::string{input};
	}

	std::string out;
	out.reserve(input.size());
	std::size_t pos = 0;
	while (pos < input.size()) {
		auto amp = input.find('&', pos);
		if (amp == std::string_view::npos) {
			out.append(input.substr(pos));
			break;
		}
		out.append(input.substr(pos, amp - pos));
		auto semi = input.find(';', amp + 1);
		if (semi == std::string_view::npos || semi - amp > 16) {
			throw ooxml_error{"unterminated or oversized entity"};
		}
		auto entity = input.substr(amp + 1, semi - amp - 1);
		if (entity == "amp") {
			out.push_back('&');
		}
		else if (entity == "apos") {
			out.push_back('\'');
		}
		else if (entity == "gt") {
			out.push_back('>');
		}
		else if (entity == "lt") {
			out.push_back('<');
		}
		else if (entity == "quot") {
			out.push_back('"');
		}
		else if (!entity.empty() && entity.front() == '#') {
			int base = 10;
			auto digits = entity.substr(1);
			if (!digits.empty() && (digits.front() == 'x' || digits.front() == 'X')) {
				base = 16;
				digits.remove_prefix(1);
			}
			std::uint32_t cp = 0;
			auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), cp, base);
			if (digits.empty() || parsed.ec != std::errc{} ||
				parsed.ptr != digits.data() + digits.size()) {
				throw ooxml_error{"invalid XML character reference"};
			}
			append_utf8(out, cp);
		}
		else {
			throw ooxml_error{"unsupported XML entity &" + std::string{entity} + ";"};
		}
		pos = semi + 1;
	}
	return out;
}

auto read_u16(const unsigned char *p, bool little_endian) -> std::uint16_t
{
	if (little_endian) {
		return static_cast<std::uint16_t>(p[0] | (static_cast<std::uint16_t>(p[1]) << 8U));
	}
	return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8U) | p[1]);
}

auto convert_utf16(std::string_view input, bool little_endian, std::size_t max_input)
	-> std::string
{
	if ((input.size() % 2U) != 0) {
		throw ooxml_error{"cannot convert UTF-16 XML"};
	}
	std::string out;
	out.reserve(std::min(max_input, input.size()));
	for (std::size_t pos = 0; pos < input.size(); pos += 2) {
		auto cp = static_cast<std::uint32_t>(read_u16(
			reinterpret_cast<const unsigned char *>(input.data() + pos), little_endian));
		if (cp >= 0xd800 && cp <= 0xdbff) {
			if (pos + 3 >= input.size()) {
				throw ooxml_error{"cannot convert UTF-16 XML"};
			}
			auto low = static_cast<std::uint32_t>(read_u16(
				reinterpret_cast<const unsigned char *>(input.data() + pos + 2), little_endian));
			if (low < 0xdc00 || low > 0xdfff) {
				throw ooxml_error{"cannot convert UTF-16 XML"};
			}
			cp = 0x10000U + ((cp - 0xd800U) << 10U) + (low - 0xdc00U);
			pos += 2;
		}
		else if (cp >= 0xdc00 && cp <= 0xdfff) {
			throw ooxml_error{"cannot convert UTF-16 XML"};
		}
		append_utf8(out, cp);
		if (out.size() > max_input) {
			throw ooxml_error{"XML input limit exceeded at byte 1"};
		}
	}
	return out;
}

enum class namespace_id : std::uint8_t {
	unbound,
	none,
	xml,
	xmlns,
	content_types,
	relationships,
	word,
	drawing,
	document_relationships,
	other,
};

auto classify_namespace(std::string_view uri) -> namespace_id
{
	if (uri.empty()) return namespace_id::unbound;
	if (uri == xml_namespace) return namespace_id::xml;
	if (uri == xmlns_namespace) return namespace_id::xmlns;
	if (uri == content_types_namespace || uri == strict_content_types_namespace) {
		return namespace_id::content_types;
	}
	if (uri == relationships_namespace || uri == strict_relationships_namespace) {
		return namespace_id::relationships;
	}
	if (uri == word_namespace || uri == strict_word_namespace) return namespace_id::word;
	if (uri == drawing_namespace || uri == strict_drawing_namespace) return namespace_id::drawing;
	if (uri == document_relationship_namespace || uri == strict_document_relationship_namespace) {
		return namespace_id::document_relationships;
	}
	return namespace_id::other;
}

struct xml_attribute {
	namespace_id namespace_value;
	std::string_view name;
	std::string value;
};

struct namespace_binding {
	std::string_view prefix;
	namespace_id value;
};

struct element_state {
	std::string_view qname;
	namespace_id namespace_value;
	std::string_view name;
	std::size_t namespace_base;
};

template<typename Handler>
class xml_scanner {
public:
	xml_scanner(std::string_view raw_input, const xml_limits &limits, Handler &handler)
		: limits_{limits}, handler_{handler}
	{
		prepare_input(raw_input);
		namespaces_.push_back({"xml", namespace_id::xml});
		namespaces_.push_back({"xmlns", namespace_id::xmlns});
	}

	void parse()
	{
		while (pos_ < input_.size()) {
			if (input_[pos_] != '<') {
				auto next = input_.find('<', pos_);
				if (next == std::string_view::npos) {
					next = input_.size();
				}
				emit_text(input_.substr(pos_, next - pos_), pos_, true);
				pos_ = next;
			}
			else if (starts_with(pos_, "<!--")) {
				auto close = input_.find("-->", pos_ + 4);
				if (close == std::string_view::npos) {
					fail("unterminated XML comment", pos_);
				}
				add_token(pos_);
				pos_ = close + 3;
			}
			else if (starts_with(pos_, "<![CDATA[")) {
				auto close = input_.find("]]>", pos_ + 9);
				if (close == std::string_view::npos) {
					fail("unterminated CDATA section", pos_);
				}
				emit_text(input_.substr(pos_ + 9, close - pos_ - 9), pos_, false);
				pos_ = close + 3;
			}
			else if (starts_with(pos_, "<?")) {
				auto close = input_.find("?>", pos_ + 2);
				if (close == std::string_view::npos) {
					fail("unterminated processing instruction", pos_);
				}
				add_token(pos_);
				pos_ = close + 2;
			}
			else if (pos_ + 9 <= input_.size() &&
					 ascii_iequal(input_.substr(pos_, 9), "<!doctype")) {
				fail("XML DTD declarations are not supported", pos_);
			}
			else if (starts_with(pos_, "<!")) {
				fail("unsupported XML declaration", pos_);
			}
			else if (starts_with(pos_, "</")) {
				parse_end_element();
			}
			else {
				parse_start_element();
			}
		}
		if (!stack_.empty()) {
			fail("unclosed XML element", input_.size());
		}
	}

private:
	void prepare_input(std::string_view raw)
	{
		if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xff &&
			static_cast<unsigned char>(raw[1]) == 0xfe) {
			owned_input_ = convert_utf16(raw.substr(2), true, limits_.max_input);
			input_ = owned_input_;
		}
		else if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xfe &&
				 static_cast<unsigned char>(raw[1]) == 0xff) {
			owned_input_ = convert_utf16(raw.substr(2), false, limits_.max_input);
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
			fail("XML input limit exceeded", 0);
		}
		if (rspamd_fast_utf8_validate(
				reinterpret_cast<const unsigned char *>(input_.data()), input_.size()) != 0) {
			throw ooxml_error{"XML input is not valid UTF-8"};
		}
		for (auto ch: input_) {
			auto byte = static_cast<unsigned char>(ch);
			if (byte == 0 || (byte < 0x20 && byte != 0x09 && byte != 0x0a && byte != 0x0d)) {
				throw ooxml_error{"XML input contains an invalid control character"};
			}
		}
	}

	[[noreturn]] void fail(std::string_view message, std::size_t pos) const
	{
		throw ooxml_error{std::string{message} + " at byte " + std::to_string(pos + 1)};
	}

	auto starts_with(std::size_t pos, std::string_view needle) const -> bool
	{
		return pos <= input_.size() && needle.size() <= input_.size() - pos &&
			   input_.compare(pos, needle.size(), needle) == 0;
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
		for (auto it = namespaces_.rbegin(); it != namespaces_.rend(); ++it) {
			if (it->prefix == prefix) {
				return it->value;
			}
		}
		return namespace_id::unbound;
	}

	void add_token(std::size_t at)
	{
		tokens_++;
		if (tokens_ > limits_.max_tokens) {
			fail("XML token limit exceeded", at);
		}
		if (limits_.end_timestamp > 0 && (tokens_ % 256U) == 0 &&
			rspamd_get_ticks(FALSE) >= limits_.end_timestamp) {
			fail("XML processing timeout", at);
		}
	}

	void emit_text(std::string_view raw, std::size_t at, bool decode)
	{
		if (raw.empty()) {
			return;
		}
		std::string decoded;
		std::string_view value = raw;
		if (decode && raw.find('&') != std::string_view::npos) {
			decoded = decode_entities(raw);
			value = decoded;
		}
		text_bytes_ += value.size();
		if (text_bytes_ > limits_.max_text) {
			fail("XML text limit exceeded", at);
		}
		add_token(at);
		handler_.text(value);
	}

	void parse_end_element()
	{
		auto at = pos_;
		auto cursor = pos_ + 2;
		auto qname = parse_name(cursor);
		if (qname.empty()) {
			fail("invalid XML end element", at);
		}
		while (cursor < input_.size() && is_space(static_cast<unsigned char>(input_[cursor]))) {
			cursor++;
		}
		if (cursor >= input_.size() || input_[cursor] != '>') {
			fail("invalid XML end element", cursor);
		}
		if (stack_.empty() || stack_.back().qname != qname) {
			fail("mismatched XML end element", at);
		}
		add_token(at);
		auto element = std::move(stack_.back());
		stack_.pop_back();
		handler_.end_element(element.namespace_value, element.name);
		namespaces_.resize(element.namespace_base);
		pos_ = cursor + 1;
	}

	void parse_start_element()
	{
		auto at = pos_;
		auto cursor = pos_ + 1;
		auto qname = parse_name(cursor);
		if (qname.empty()) {
			fail("invalid XML start element", at);
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
			while (cursor < input_.size() && is_space(static_cast<unsigned char>(input_[cursor]))) {
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

			auto attribute_qname = parse_name(cursor);
			if (attribute_qname.empty()) {
				fail("invalid XML attribute name", cursor);
			}
			if (!attribute_names.emplace(attribute_qname).second) {
				fail("duplicate XML attribute", cursor);
			}
			while (cursor < input_.size() && is_space(static_cast<unsigned char>(input_[cursor]))) {
				cursor++;
			}
			if (cursor >= input_.size() || input_[cursor] != '=') {
				fail("missing XML attribute value", cursor);
			}
			cursor++;
			while (cursor < input_.size() && is_space(static_cast<unsigned char>(input_[cursor]))) {
				cursor++;
			}
			if (cursor >= input_.size() || (input_[cursor] != '"' && input_[cursor] != '\'')) {
				fail("unquoted XML attribute value", cursor);
			}
			auto quote = input_[cursor];
			auto value_start = ++cursor;
			auto value_end = input_.find(quote, value_start);
			if (value_end == std::string_view::npos) {
				fail("unterminated XML attribute value", cursor - 1);
			}
			if (value_end - value_start > limits_.max_attribute_length) {
				fail("XML attribute length limit exceeded", cursor - 1);
			}
			auto raw_value = input_.substr(value_start, value_end - value_start);
			if (raw_value.find('<') != std::string_view::npos) {
				fail("unescaped less-than sign in XML attribute", value_start);
			}
			raw_attributes.push_back({attribute_qname, decode_entities(raw_value)});
			if (raw_attributes.size() > limits_.max_attributes) {
				fail("XML attribute limit exceeded", cursor);
			}
			cursor = value_end + 1;
		}
		if (!closed) {
			fail("unterminated XML start element", at);
		}

		auto namespace_base = namespaces_.size();
		for (const auto &attribute: raw_attributes) {
			std::optional<std::string_view> prefix;
			if (attribute.qname == "xmlns") {
				prefix = std::string_view{};
			}
			else if (attribute.qname.starts_with("xmlns:")) {
				prefix = attribute.qname.substr(6);
			}
			if (prefix) {
				if (*prefix == "xmlns" ||
					(*prefix == "xml" && attribute.value != xml_namespace) ||
					(*prefix != "xml" && attribute.value == xml_namespace) ||
					attribute.value == xmlns_namespace) {
					namespaces_.resize(namespace_base);
					fail("invalid XML namespace declaration", at);
				}
				namespaces_.push_back({*prefix, classify_namespace(attribute.value)});
			}
		}

		auto element_name = split_qname(qname);
		if (!element_name) {
			namespaces_.resize(namespace_base);
			fail("invalid qualified XML element name", at);
		}
		auto element_namespace = lookup_namespace(element_name->first);
		if (!element_name->first.empty() && element_namespace == namespace_id::unbound) {
			namespaces_.resize(namespace_base);
			fail("unbound XML element prefix", at);
		}
		if (element_name->first.empty() && element_namespace == namespace_id::unbound) {
			element_namespace = namespace_id::none;
		}

		std::vector<xml_attribute> attributes;
		attributes.reserve(raw_attributes.size());
		for (auto &attribute: raw_attributes) {
			if (attribute.qname == "xmlns" || attribute.qname.starts_with("xmlns:")) {
				continue;
			}
			auto name = split_qname(attribute.qname);
			if (!name) {
				namespaces_.resize(namespace_base);
				fail("invalid qualified XML attribute name", at);
			}
			auto attribute_namespace = namespace_id::none;
			if (!name->first.empty()) {
				attribute_namespace = lookup_namespace(name->first);
				if (attribute_namespace == namespace_id::unbound) {
					namespaces_.resize(namespace_base);
					fail("unbound XML attribute prefix", at);
				}
			}
			attributes.push_back({attribute_namespace, name->second, std::move(attribute.value)});
		}

		if (stack_.size() + 1 > limits_.max_depth) {
			namespaces_.resize(namespace_base);
			fail("XML depth limit exceeded", at);
		}
		add_token(at);
		handler_.start_element(element_namespace, element_name->second, attributes);

		if (self_closing) {
			add_token(at);
			handler_.end_element(element_namespace, element_name->second);
			namespaces_.resize(namespace_base);
		}
		else {
			stack_.push_back({qname, element_namespace, element_name->second, namespace_base});
		}
		pos_ = cursor;
	}

	xml_limits limits_;
	Handler &handler_;
	std::string owned_input_;
	std::string_view input_;
	std::vector<namespace_binding> namespaces_;
	std::vector<element_state> stack_;
	std::size_t pos_ = 0;
	std::size_t tokens_ = 0;
	std::size_t text_bytes_ = 0;
};

auto get_attribute(const std::vector<xml_attribute> &attributes,
				   std::string_view name, namespace_id namespace_value = namespace_id::none)
	-> const std::string *
{
	for (const auto &attribute: attributes) {
		if (attribute.name == name && attribute.namespace_value == namespace_value) {
			return &attribute.value;
		}
	}
	return nullptr;
}

auto has_ascii_control(std::string_view value) -> bool
{
	return std::any_of(value.begin(), value.end(), [](char ch) {
		return static_cast<unsigned char>(ch) < 0x20;
	});
}

auto hex_value(char ch) -> int
{
	if (ch >= '0' && ch <= '9') return ch - '0';
	if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
	if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
	return -1;
}

auto validate_segment(std::string_view segment) -> bool
{
	if (segment.empty()) return false;
	std::string decoded;
	decoded.reserve(segment.size());
	for (std::size_t i = 0; i < segment.size(); i++) {
		auto ch = segment[i];
		if (ch == '%') {
			if (i + 2 >= segment.size()) return false;
			auto high = hex_value(segment[i + 1]);
			auto low = hex_value(segment[i + 2]);
			if (high < 0 || low < 0) return false;
			decoded.push_back(static_cast<char>((high << 4) | low));
			i += 2;
		}
		else {
			decoded.push_back(ch);
		}
	}
	if (decoded == "." || decoded == "..") return false;
	return std::none_of(decoded.begin(), decoded.end(), [](char ch) {
		auto byte = static_cast<unsigned char>(ch);
		return byte < 0x20 || ch == '\\' || ch == '/';
	});
}

auto has_uri_scheme(std::string_view target) -> bool
{
	if (target.empty() || !((target[0] >= 'A' && target[0] <= 'Z') ||
							(target[0] >= 'a' && target[0] <= 'z'))) {
		return false;
	}
	for (std::size_t i = 1; i < target.size(); i++) {
		auto ch = target[i];
		if (ch == ':') return true;
		if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
			  (ch >= '0' && ch <= '9') || ch == '+' || ch == '.' || ch == '-')) {
			return false;
		}
	}
	return false;
}

auto resolve_part_name(std::string_view source_part, std::string_view target) -> std::string
{
	if (target.empty()) throw ooxml_error{"empty relationship target"};
	if (target.front() == '/' || has_uri_scheme(target) ||
		std::any_of(target.begin(), target.end(), [](char ch) {
			auto byte = static_cast<unsigned char>(ch);
			return byte < 0x20 || ch == '\\';
		})) {
		throw ooxml_error{"absolute or invalid internal relationship target"};
	}
	auto fragment = target.find('#');
	auto path = target.substr(0, fragment);
	if (path.empty() || path.find('?') != std::string_view::npos ||
		path.find("//") != std::string_view::npos || path.back() == '/') {
		throw ooxml_error{"invalid internal relationship target"};
	}

	std::vector<std::string_view> components;
	auto add_components = [&components](std::string_view value) {
		std::size_t start = 0;
		while (start < value.size()) {
			auto slash = value.find('/', start);
			if (slash == std::string_view::npos) slash = value.size();
			if (slash > start) components.push_back(value.substr(start, slash - start));
			start = slash + 1;
		}
	};
	if (!source_part.empty()) {
		add_components(source_part);
		if (!components.empty()) components.pop_back();
	}

	std::size_t start = 0;
	while (start < path.size()) {
		auto slash = path.find('/', start);
		if (slash == std::string_view::npos) slash = path.size();
		auto segment = path.substr(start, slash - start);
		if (segment == "..") {
			if (components.empty()) {
				throw ooxml_error{"relationship target escapes package root"};
			}
			components.pop_back();
		}
		else if (segment != ".") {
			if (!validate_segment(segment)) {
				throw ooxml_error{"invalid relationship path segment"};
			}
			components.push_back(segment);
		}
		start = slash + 1;
	}
	if (components.empty()) {
		throw ooxml_error{"relationship target does not name a part"};
	}
	std::string result;
	for (const auto component: components) {
		if (!result.empty()) result.push_back('/');
		result.append(component);
	}
	return result;
}

struct content_types_result {
	ankerl::unordered_dense::map<std::string, std::string> defaults;
	ankerl::unordered_dense::map<std::string, std::string> overrides;
};

class content_types_handler {
public:
	void start_element(namespace_id ns, std::string_view name,
					   const std::vector<xml_attribute> &attributes)
	{
		depth_++;
		if (depth_ == 1) {
			if (name != "Types" || ns != namespace_id::content_types) {
				throw ooxml_error{"invalid OOXML content types root"};
			}
			root_seen_ = true;
		}
		else if (depth_ == 2 && ns == namespace_id::content_types) {
			if (name == "Default") {
				auto *extension = get_attribute(attributes, "Extension");
				auto *content_type = get_attribute(attributes, "ContentType");
				if (extension == nullptr || extension->empty() || content_type == nullptr ||
					content_type->empty()) {
					throw ooxml_error{"invalid OOXML default content type"};
				}
				auto key = ascii_lower(*extension);
				if (!result_.defaults.emplace(std::move(key), *content_type).second) {
					throw ooxml_error{"duplicate OOXML default content type"};
				}
			}
			else if (name == "Override") {
				auto *part_name = get_attribute(attributes, "PartName");
				auto *content_type = get_attribute(attributes, "ContentType");
				if (part_name == nullptr || part_name->empty() || part_name->front() != '/' ||
					content_type == nullptr || content_type->empty()) {
					throw ooxml_error{"invalid OOXML content type override"};
				}
				auto normalized = resolve_part_name({}, std::string_view{*part_name}.substr(1));
				if (!result_.overrides.emplace(std::move(normalized), *content_type).second) {
					throw ooxml_error{"duplicate OOXML content type override"};
				}
			}
		}
	}

	void end_element(namespace_id, std::string_view)
	{
		depth_--;
	}
	void text(std::string_view)
	{
	}

	auto finish() -> content_types_result
	{
		if (!root_seen_) throw ooxml_error{"missing OOXML content types root"};
		return std::move(result_);
	}

private:
	content_types_result result_;
	std::size_t depth_ = 0;
	bool root_seen_ = false;
};

struct relationship {
	std::string id;
	std::string type;
	std::string target;
	std::string part_name;
	bool external = false;
};

class relationships_handler {
public:
	relationships_handler(std::string_view source_part, const ooxml_limits &limits)
		: source_part_{source_part}, limits_{limits}
	{
	}

	void start_element(namespace_id ns, std::string_view name,
					   const std::vector<xml_attribute> &attributes)
	{
		depth_++;
		if (depth_ == 1) {
			if (name != "Relationships" || ns != namespace_id::relationships) {
				throw ooxml_error{"invalid OOXML relationships root"};
			}
			root_seen_ = true;
		}
		else if (depth_ == 2 && name == "Relationship" && ns == namespace_id::relationships) {
			auto *id = get_attribute(attributes, "Id");
			auto *type = get_attribute(attributes, "Type");
			auto *target = get_attribute(attributes, "Target");
			auto *mode = get_attribute(attributes, "TargetMode");
			if (id == nullptr || id->empty() || type == nullptr || type->empty() ||
				target == nullptr || target->empty()) {
				throw ooxml_error{"invalid OOXML relationship"};
			}
			if (target->size() > limits_.max_target_length) {
				throw ooxml_error{"OOXML relationship target limit exceeded"};
			}
			if (has_ascii_control(*target)) {
				throw ooxml_error{"control character in OOXML relationship target"};
			}
			if (ids_.contains(*id)) {
				throw ooxml_error{"duplicate OOXML relationship id"};
			}
			if (relationships_.size() >= limits_.max_relationships) {
				throw ooxml_error{"OOXML relationship limit exceeded"};
			}
			bool external = false;
			if (mode != nullptr) {
				auto normalized_mode = ascii_lower(*mode);
				if (normalized_mode != "external" && normalized_mode != "internal") {
					throw ooxml_error{"invalid OOXML relationship target mode"};
				}
				external = normalized_mode == "external";
			}

			relationship rel{*id, *type, *target, {}, external};
			if (!external) {
				rel.part_name = resolve_part_name(source_part_, *target);
			}
			ids_.emplace(rel.id);
			relationships_.push_back(std::move(rel));
		}
	}

	void end_element(namespace_id, std::string_view)
	{
		depth_--;
	}
	void text(std::string_view)
	{
	}

	auto finish() -> std::vector<relationship>
	{
		if (!root_seen_) throw ooxml_error{"missing OOXML relationships root"};
		return std::move(relationships_);
	}

private:
	std::string source_part_;
	ooxml_limits limits_;
	std::vector<relationship> relationships_;
	ankerl::unordered_dense::set<std::string> ids_;
	std::size_t depth_ = 0;
	bool root_seen_ = false;
};

struct gstring_deleter {
	void operator()(GString *str) const
	{
		if (str != nullptr) g_string_free(str, TRUE);
	}
};

struct docx_result {
	std::unique_ptr<GString, gstring_deleter> text{g_string_sized_new(1024)};
	std::vector<std::string> urls;
	ankerl::unordered_dense::set<std::string> url_seen;
	std::size_t max_text;
	std::size_t max_urls;
	bool last_chunk_is_newline = false;

	docx_result(std::size_t max_text, std::size_t max_urls)
		: max_text{max_text}, max_urls{max_urls}
	{
	}

	void add_text(std::string_view value)
	{
		if (text->len + value.size() > max_text) {
			throw ooxml_error{"DOCX text limit exceeded"};
		}
		g_string_append_len(text.get(), value.data(), value.size());
		last_chunk_is_newline = value == "\n";
	}

	void add_url(std::string value)
	{
		if (value.empty() || url_seen.contains(value)) return;
		if (urls.size() >= max_urls) {
			throw ooxml_error{"DOCX URL limit exceeded"};
		}
		url_seen.emplace(value);
		urls.push_back(std::move(value));
	}
};

auto is_hyperlink_relationship(std::string_view type) -> bool
{
	return type == hyperlink_relationship || type == strict_hyperlink_relationship;
}

auto hyperlink_from_instruction(std::string_view instruction) -> std::optional<std::string>
{
	std::string upper = ascii_lower(instruction);
	auto start = upper.find("hyperlink");
	if (start == std::string::npos) return std::nullopt;
	auto is_word = [](char ch) {
		return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
			   (ch >= '0' && ch <= '9') || ch == '_';
	};
	if ((start > 0 && is_word(instruction[start - 1])) ||
		(start + 9 < instruction.size() && is_word(instruction[start + 9]))) {
		return std::nullopt;
	}
	auto pos = start + 9;
	while (pos < instruction.size() && is_space(static_cast<unsigned char>(instruction[pos]))) pos++;
	auto end = instruction.size();
	while (end > pos && is_space(static_cast<unsigned char>(instruction[end - 1]))) end--;
	if (pos == end || instruction[pos] == '\\') return std::nullopt;

	std::string_view target;
	if (instruction[pos] == '"' || instruction[pos] == '\'') {
		auto quote = instruction[pos++];
		auto close = instruction.find(quote, pos);
		if (close == std::string_view::npos) return std::nullopt;
		target = instruction.substr(pos, close - pos);
	}
	else {
		auto close = pos;
		while (close < end && !is_space(static_cast<unsigned char>(instruction[close]))) close++;
		target = instruction.substr(pos, close - pos);
	}
	if (target.empty()) return std::nullopt;
	std::string unescaped;
	unescaped.reserve(target.size());
	for (std::size_t i = 0; i < target.size(); i++) {
		if (target[i] == '\\' && i + 1 < target.size()) i++;
		unescaped.push_back(target[i]);
	}
	return unescaped;
}

using hyperlink_map = ankerl::unordered_dense::map<std::string, std::string>;

class word_story_handler {
public:
	word_story_handler(const hyperlink_map &relationships, docx_result &result)
		: relationships_{relationships}, result_{result}
	{
	}

	void start_element(namespace_id ns, std::string_view name,
					   const std::vector<xml_attribute> &attributes)
	{
		depth_++;
		if (ns == namespace_id::word) {
			if ((name == "del" || name == "moveFrom") && !excluded_depth_) {
				excluded_depth_ = depth_;
			}
			else if (name == "t" && !excluded_depth_) {
				text_depth_ = depth_;
			}
			else if (name == "tab" && !excluded_depth_) {
				result_.add_text("\t");
			}
			else if ((name == "br" || name == "cr") && !excluded_depth_) {
				result_.add_text("\n");
			}
			else if (name == "hyperlink") {
				const std::string *id = nullptr;
				for (const auto &attribute: attributes) {
					if (attribute.name == "id" &&
						attribute.namespace_value == namespace_id::document_relationships) {
						id = &attribute.value;
						break;
					}
				}
				if (id != nullptr) {
					auto found = relationships_.find(*id);
					if (found != relationships_.end()) result_.add_url(found->second);
				}
			}
			else if (name == "fldSimple") {
				for (const auto &attribute: attributes) {
					if (attribute.name == "instr" && attribute.namespace_value == namespace_id::word) {
						auto url = hyperlink_from_instruction(attribute.value);
						if (url) result_.add_url(std::move(*url));
						break;
					}
				}
			}
			else if (name == "fldChar") {
				const std::string *field_type = nullptr;
				for (const auto &attribute: attributes) {
					if (attribute.name == "fldCharType" &&
						attribute.namespace_value == namespace_id::word) {
						field_type = &attribute.value;
						break;
					}
				}
				if (field_type != nullptr && *field_type == "begin") {
					fields_.push_back({});
				}
				else if (field_type != nullptr && *field_type == "separate") {
					finish_field();
				}
				else if (field_type != nullptr && *field_type == "end" && !fields_.empty()) {
					finish_field();
					fields_.pop_back();
				}
			}
			else if (name == "instrText" && !fields_.empty()) {
				instruction_depth_ = depth_;
			}
		}
		else if (ns == namespace_id::drawing && name == "t" && !excluded_depth_) {
			text_depth_ = depth_;
		}
	}

	void end_element(namespace_id ns, std::string_view name)
	{
		if (ns == namespace_id::word && name == "p" && !excluded_depth_) {
			result_.add_text("\n");
		}
		if (text_depth_ == depth_) text_depth_.reset();
		if (instruction_depth_ == depth_) instruction_depth_.reset();
		if (excluded_depth_ == depth_) excluded_depth_.reset();
		depth_--;
	}

	void text(std::string_view value)
	{
		if (instruction_depth_ && !fields_.empty()) {
			fields_.back().instruction.append(value);
		}
		else if (text_depth_ && !excluded_depth_) {
			result_.add_text(value);
		}
	}

private:
	struct field_state {
		std::string instruction;
		bool parsed = false;
	};

	void finish_field()
	{
		if (!fields_.empty() && !fields_.back().parsed) {
			auto url = hyperlink_from_instruction(fields_.back().instruction);
			if (url) result_.add_url(std::move(*url));
			fields_.back().parsed = true;
		}
	}

	const hyperlink_map &relationships_;
	docx_result &result_;
	std::vector<field_state> fields_;
	std::size_t depth_ = 0;
	std::optional<std::size_t> excluded_depth_;
	std::optional<std::size_t> text_depth_;
	std::optional<std::size_t> instruction_depth_;
};

auto get_size_option(lua_State *L, int table_index, const char *name,
					 std::size_t default_value) -> std::size_t
{
	if (!lua_istable(L, table_index)) return default_value;
	table_index = lua_absindex(L, table_index);
	lua_getfield(L, table_index, name);
	auto result = default_value;
	if (lua_isnumber(L, -1)) {
		auto value = lua_tonumber(L, -1);
		if (value >= 0) result = static_cast<std::size_t>(value);
	}
	lua_pop(L, 1);
	return result;
}

auto get_number_option(lua_State *L, int table_index, const char *name,
					   double default_value) -> double
{
	if (!lua_istable(L, table_index)) return default_value;
	table_index = lua_absindex(L, table_index);
	lua_getfield(L, table_index, name);
	auto result = lua_isnumber(L, -1) ? static_cast<double>(lua_tonumber(L, -1)) : default_value;
	lua_pop(L, 1);
	return result;
}

auto read_limits(lua_State *L, int table_index) -> ooxml_limits
{
	ooxml_limits result;
	if (!lua_istable(L, table_index)) return result;
	table_index = lua_absindex(L, table_index);
	result.max_relationships = get_size_option(L, table_index, "max_relationships",
											   result.max_relationships);
	result.max_target_length = get_size_option(L, table_index, "max_target_length",
											   result.max_target_length);
	result.max_text = get_size_option(L, table_index, "max_text", result.max_text);
	result.max_urls = get_size_option(L, table_index, "max_urls", result.max_urls);

	lua_getfield(L, table_index, "xml");
	if (lua_istable(L, -1)) {
		auto xml_index = lua_absindex(L, -1);
		result.xml.max_input = get_size_option(L, xml_index, "max_input", result.xml.max_input);
		result.xml.max_depth = get_size_option(L, xml_index, "max_depth", result.xml.max_depth);
		result.xml.max_tokens = get_size_option(L, xml_index, "max_tokens", result.xml.max_tokens);
		result.xml.max_attributes = get_size_option(L, xml_index, "max_attributes",
													result.xml.max_attributes);
		result.xml.max_attribute_length = get_size_option(L, xml_index, "max_attribute_length",
														  result.xml.max_attribute_length);
		result.xml.max_text = get_size_option(L, xml_index, "max_text", result.xml.max_text);
		result.xml.end_timestamp = get_number_option(L, xml_index, "end_timestamp", 0);
		result.xml.timeout = get_number_option(L, xml_index, "timeout", 0);
	}
	lua_pop(L, 1);
	return result;
}

auto check_input(lua_State *L, int pos) -> std::optional<std::string_view>
{
	if (lua_type(L, pos) == LUA_TSTRING) {
		size_t len;
		auto *value = lua_tolstring(L, pos, &len);
		return std::string_view{value, len};
	}
	if (lua_type(L, pos) == LUA_TUSERDATA) {
		auto *text = static_cast<rspamd_lua_text *>(
			rspamd_lua_check_udata_maybe(L, pos, rspamd_text_classname));
		if (text != nullptr) return std::string_view{text->start, text->len};
	}
	return std::nullopt;
}

auto check_string(lua_State *L, int pos) -> std::optional<std::string_view>
{
	if (lua_type(L, pos) != LUA_TSTRING) return std::nullopt;
	size_t len;
	auto *value = lua_tolstring(L, pos, &len);
	return std::string_view{value, len};
}

auto scanner_limits(const xml_limits &configured) -> xml_limits
{
	auto result = configured;
	if (result.end_timestamp <= 0 && result.timeout > 0) {
		result.end_timestamp = rspamd_get_ticks(FALSE) + result.timeout;
	}
	return result;
}

auto push_error(lua_State *L, std::string_view error) -> int
{
	lua_pushnil(L);
	lua_pushlstring(L, error.data(), error.size());
	return 2;
}

void push_relationship(lua_State *L, const relationship &rel)
{
	lua_createtable(L, 0, 5);
	lua_pushlstring(L, rel.id.data(), rel.id.size());
	lua_setfield(L, -2, "id");
	lua_pushlstring(L, rel.type.data(), rel.type.size());
	lua_setfield(L, -2, "type");
	lua_pushlstring(L, rel.target.data(), rel.target.size());
	lua_setfield(L, -2, "target");
	lua_pushboolean(L, rel.external);
	lua_setfield(L, -2, "external");
	if (!rel.part_name.empty()) {
		lua_pushlstring(L, rel.part_name.data(), rel.part_name.size());
		lua_setfield(L, -2, "part_name");
	}
}

auto get_table_string(lua_State *L, int table_index, const char *field)
	-> std::optional<std::string>
{
	table_index = lua_absindex(L, table_index);
	lua_getfield(L, table_index, field);
	std::optional<std::string> result;
	if (lua_isstring(L, -1)) {
		size_t len;
		auto *value = lua_tolstring(L, -1, &len);
		result.emplace(value, len);
	}
	lua_pop(L, 1);
	return result;
}

auto read_hyperlinks(lua_State *L, int relationships_index) -> hyperlink_map
{
	hyperlink_map result;
	if (!lua_istable(L, relationships_index)) return result;
	relationships_index = lua_absindex(L, relationships_index);
	lua_getfield(L, relationships_index, "list");
	if (!lua_istable(L, -1)) {
		lua_pop(L, 1);
		return result;
	}
	auto list_index = lua_absindex(L, -1);
	auto count = rspamd_lua_table_size(L, list_index);
	for (int i = 1; i <= count; i++) {
		lua_rawgeti(L, list_index, i);
		if (lua_istable(L, -1)) {
			auto rel_index = lua_absindex(L, -1);
			auto id = get_table_string(L, rel_index, "id");
			auto type = get_table_string(L, rel_index, "type");
			auto target = get_table_string(L, rel_index, "target");
			lua_getfield(L, rel_index, "external");
			auto external = lua_toboolean(L, -1);
			lua_pop(L, 1);
			if (external && id && type && target && is_hyperlink_relationship(*type)) {
				result.emplace(std::move(*id), std::move(*target));
			}
		}
		lua_pop(L, 1);
	}
	lua_pop(L, 1);
	return result;
}

void collapse_newlines(GString *text)
{
	std::size_t read = 0;
	std::size_t write = 0;
	std::size_t newlines = 0;
	while (read < text->len) {
		auto ch = text->str[read++];
		if (ch == '\n') {
			newlines++;
			if (newlines > 2) continue;
		}
		else {
			newlines = 0;
		}
		text->str[write++] = ch;
	}
	g_string_truncate(text, write);
}

static int lua_ooxml_resolve_part_name(lua_State *L)
{
	auto source = check_string(L, 1);
	auto target = check_string(L, 2);
	if (!source || !target) return push_error(L, "source and target strings expected");
	try {
		auto result = resolve_part_name(*source, *target);
		lua_pushlstring(L, result.data(), result.size());
		return 1;
	} catch (const ooxml_error &error) {
		return push_error(L, error.what());
	}
}

static int lua_ooxml_hyperlink_from_instruction(lua_State *L)
{
	auto instruction = check_string(L, 1);
	if (!instruction) {
		lua_pushnil(L);
		return 1;
	}
	auto result = hyperlink_from_instruction(*instruction);
	if (result) {
		lua_pushlstring(L, result->data(), result->size());
	}
	else {
		lua_pushnil(L);
	}
	return 1;
}

static int lua_ooxml_parse_content_types(lua_State *L)
{
	auto input = check_input(L, 1);
	if (!input) return push_error(L, "string or rspamd_text expected");
	auto limits = read_limits(L, 2);
	try {
		content_types_handler handler;
		xml_scanner scanner{*input, scanner_limits(limits.xml), handler};
		scanner.parse();
		auto result = handler.finish();
		lua_createtable(L, 0, 2);
		lua_createtable(L, 0, result.defaults.size());
		for (const auto &[key, value]: result.defaults) {
			lua_pushlstring(L, value.data(), value.size());
			lua_setfield(L, -2, key.c_str());
		}
		lua_setfield(L, -2, "defaults");
		lua_createtable(L, 0, result.overrides.size());
		for (const auto &[key, value]: result.overrides) {
			lua_pushlstring(L, value.data(), value.size());
			lua_setfield(L, -2, key.c_str());
		}
		lua_setfield(L, -2, "overrides");
		return 1;
	} catch (const ooxml_error &error) {
		return push_error(L, error.what());
	}
}

static int lua_ooxml_parse_relationships(lua_State *L)
{
	auto input = check_input(L, 1);
	if (!input) return push_error(L, "string or rspamd_text expected");
	auto source = check_string(L, 2);
	if (!source) return push_error(L, "source part string expected");
	auto limits = read_limits(L, 3);
	try {
		relationships_handler handler{*source, limits};
		xml_scanner scanner{*input, scanner_limits(limits.xml), handler};
		scanner.parse();
		auto relationships = handler.finish();
		lua_createtable(L, 0, 2);
		auto result_index = lua_absindex(L, -1);
		lua_createtable(L, relationships.size(), 0);
		auto list_index = lua_absindex(L, -1);
		lua_createtable(L, 0, relationships.size());
		auto by_id_index = lua_absindex(L, -1);
		for (std::size_t i = 0; i < relationships.size(); i++) {
			push_relationship(L, relationships[i]);
			lua_pushvalue(L, -1);
			lua_rawseti(L, list_index, i + 1);
			lua_setfield(L, by_id_index, relationships[i].id.c_str());
		}
		lua_setfield(L, result_index, "by_id");
		lua_setfield(L, result_index, "list");
		return 1;
	} catch (const ooxml_error &error) {
		return push_error(L, error.what());
	}
}

static int lua_ooxml_extract_docx(lua_State *L)
{
	if (!lua_istable(L, 1)) return push_error(L, "stories table expected");
	auto limits = read_limits(L, 2);
	try {
		docx_result result{limits.max_text, limits.max_urls};
		auto stories_index = lua_absindex(L, 1);
		auto count = rspamd_lua_table_size(L, stories_index);
		for (int i = 1; i <= count; i++) {
			lua_rawgeti(L, stories_index, i);
			if (!lua_istable(L, -1)) {
				lua_pop(L, 1);
				throw ooxml_error{"invalid DOCX story entry"};
			}
			auto story_index = lua_absindex(L, -1);
			lua_getfield(L, story_index, "content");
			auto input = check_input(L, -1);
			if (!input) {
				lua_pop(L, 2);
				throw ooxml_error{"invalid DOCX story content"};
			}
			lua_getfield(L, story_index, "relationships");
			auto hyperlinks = read_hyperlinks(L, -1);
			lua_pop(L, 1);

			word_story_handler handler{hyperlinks, result};
			xml_scanner scanner{*input, scanner_limits(limits.xml), handler};
			scanner.parse();
			lua_pop(L, 1); /* content */
			if (!result.last_chunk_is_newline) {
				result.add_text("\n");
			}
			lua_pop(L, 1); /* story */
		}

		collapse_newlines(result.text.get());
		lua_createtable(L, 0, 2);
		lua_pushstring(L, "text");
		auto text_len = result.text->len;
		auto *text_data = g_string_free(result.text.release(), FALSE);
		auto *text = lua_new_text(L, text_data, text_len, FALSE);
		text->flags |= RSPAMD_TEXT_FLAG_OWN;
		lua_settable(L, -3);
		lua_createtable(L, result.urls.size(), 0);
		for (std::size_t i = 0; i < result.urls.size(); i++) {
			lua_pushlstring(L, result.urls[i].data(), result.urls[i].size());
			lua_rawseti(L, -2, i + 1);
		}
		lua_setfield(L, -2, "urls");
		return 1;
	} catch (const ooxml_error &error) {
		return push_error(L, error.what());
	}
}

static const struct luaL_reg ooxml_lib[] = {
	{"resolve_part_name", lua_ooxml_resolve_part_name},
	{"hyperlink_from_instruction", lua_ooxml_hyperlink_from_instruction},
	{"parse_content_types", lua_ooxml_parse_content_types},
	{"parse_relationships", lua_ooxml_parse_relationships},
	{"extract_docx", lua_ooxml_extract_docx},
	{nullptr, nullptr},
};

}// namespace

void luaopen_ooxml(lua_State *L)
{
	rspamd_lua_add_preload(L, "rspamd_ooxml", [](lua_State *LL) -> int {
		luaL_register(LL, "rspamd_ooxml", ooxml_lib);
		return 1;
	});
}
