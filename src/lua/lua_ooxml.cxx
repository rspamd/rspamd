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

#include "contrib/ankerl/unordered_dense.h"
#include "contrib/expected/expected.hpp"
#include "contrib/fmt/include/fmt/format.h"
#include "libmime/mime_encoding.h"
#include "libserver/html/html_entities.hxx"
#include "libserver/url.h"
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

template<typename T>
using ooxml_result = tl::expected<T, std::string>;

using ooxml_status = ooxml_result<void>;

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

auto decode_xml_entities(std::string_view input) -> ooxml_result<std::string>
{
	if (input.find('&') == std::string_view::npos) {
		return std::string{input};
	}

	std::string out{input};
	auto decoded = rspamd::html::decode_entities_inplace(out.data(), out.size(),
														 rspamd::html::entity_decode_mode::xml);
	if (!decoded) return tl::make_unexpected(std::move(decoded.error()));
	out.resize(*decoded);
	return out;
}

auto convert_utf16(std::string_view input, const char *encoding, std::size_t max_input)
	-> ooxml_result<std::string>
{
	if (input.size() > G_MAXINT32) {
		return tl::make_unexpected("cannot convert UTF-16 XML");
	}
	auto pool = std::unique_ptr<rspamd_mempool_t, decltype(&rspamd_mempool_delete)>{
		rspamd_mempool_new_short_lived("ooxml"), rspamd_mempool_delete};
	GError *error = nullptr;
	gsize output_len = 0;
	auto *converted = rspamd_mime_text_to_utf8(pool.get(),
											   const_cast<char *>(input.data()), input.size(), encoding, &output_len, &error);
	if (converted == nullptr) {
		if (error != nullptr) g_error_free(error);
		return tl::make_unexpected("cannot convert UTF-16 XML");
	}
	if (output_len > max_input) {
		return tl::make_unexpected("XML input limit exceeded at byte 1");
	}
	return std::string{converted, output_len};
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
		: raw_input_{raw_input}, limits_{limits}, handler_{handler}
	{
		namespaces_.push_back({"xml", namespace_id::xml});
		namespaces_.push_back({"xmlns", namespace_id::xmlns});
	}

	auto parse() -> ooxml_status
	{
		if (auto ret = prepare_input(); !ret) return ret;

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
				return fail("XML DTD declarations are not supported", pos_);
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

private:
	auto prepare_input() -> ooxml_status
	{
		auto raw = raw_input_;
		if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xff &&
			static_cast<unsigned char>(raw[1]) == 0xfe) {
			auto converted = convert_utf16(raw.substr(2), "UTF-16LE", limits_.max_input);
			if (!converted) return tl::make_unexpected(std::move(converted.error()));
			owned_input_ = std::move(*converted);
			input_ = owned_input_;
		}
		else if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xfe &&
				 static_cast<unsigned char>(raw[1]) == 0xff) {
			auto converted = convert_utf16(raw.substr(2), "UTF-16BE", limits_.max_input);
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
		if (rspamd_fast_utf8_validate(
				reinterpret_cast<const unsigned char *>(input_.data()), input_.size()) != 0) {
			return tl::make_unexpected("XML input is not valid UTF-8");
		}
		for (auto ch: input_) {
			if (g_ascii_iscntrl(ch) && ch != '\t' && ch != '\n' && ch != '\r') {
				return tl::make_unexpected("XML input contains an invalid control character");
			}
		}
		return {};
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

	auto add_token(std::size_t at) -> ooxml_status
	{
		tokens_++;
		if (tokens_ > limits_.max_tokens) {
			return fail("XML token limit exceeded", at);
		}
		if (limits_.end_timestamp > 0 && (tokens_ % 256U) == 0 &&
			rspamd_get_ticks(FALSE) >= limits_.end_timestamp) {
			return fail("XML processing timeout", at);
		}
		return {};
	}

	auto emit_text(std::string_view raw, std::size_t at, bool decode) -> ooxml_status
	{
		if (raw.empty()) {
			return {};
		}
		std::string decoded;
		std::string_view value = raw;
		if (decode && raw.find('&') != std::string_view::npos) {
			auto decoded_result = decode_xml_entities(raw);
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

	auto parse_end_element() -> ooxml_status
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
		namespaces_.resize(element.namespace_base);
		pos_ = cursor + 1;
		return {};
	}

	auto parse_start_element() -> ooxml_status
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
			auto decoded = decode_xml_entities(raw_value);
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
					return fail("invalid XML namespace declaration", at);
				}
				namespaces_.push_back({*prefix, classify_namespace(attribute.value)});
			}
		}

		auto element_name = split_qname(qname);
		if (!element_name) {
			namespaces_.resize(namespace_base);
			return fail("invalid qualified XML element name", at);
		}
		auto element_namespace = lookup_namespace(element_name->first);
		if (!element_name->first.empty() && element_namespace == namespace_id::unbound) {
			namespaces_.resize(namespace_base);
			return fail("unbound XML element prefix", at);
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
				return fail("invalid qualified XML attribute name", at);
			}
			auto attribute_namespace = namespace_id::none;
			if (!name->first.empty()) {
				attribute_namespace = lookup_namespace(name->first);
				if (attribute_namespace == namespace_id::unbound) {
					namespaces_.resize(namespace_base);
					return fail("unbound XML attribute prefix", at);
				}
			}
			attributes.push_back({attribute_namespace, name->second, std::move(attribute.value)});
		}

		if (stack_.size() + 1 > limits_.max_depth) {
			namespaces_.resize(namespace_base);
			return fail("XML depth limit exceeded", at);
		}
		if (auto ret = add_token(at); !ret) return ret;
		if (auto ret = handler_.start_element(element_namespace, element_name->second, attributes);
			!ret) {
			return ret;
		}

		if (self_closing) {
			if (auto ret = add_token(at); !ret) return ret;
			if (auto ret = handler_.end_element(element_namespace, element_name->second); !ret) {
				return ret;
			}
			namespaces_.resize(namespace_base);
		}
		else {
			stack_.push_back({qname, element_namespace, element_name->second, namespace_base});
		}
		pos_ = cursor;
		return {};
	}

	std::string_view raw_input_;
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
		return g_ascii_iscntrl(static_cast<unsigned char>(ch));
	});
}

auto has_uri_scheme(std::string_view value) -> bool
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

auto validate_segment(std::string_view segment) -> bool
{
	if (segment.empty()) return false;
	for (std::size_t i = 0; i < segment.size(); i++) {
		if (segment[i] == '%') {
			if (i + 2 >= segment.size()) return false;
			if (!g_ascii_isxdigit(segment[i + 1]) || !g_ascii_isxdigit(segment[i + 2])) {
				return false;
			}
			i += 2;
		}
	}
	std::string decoded{segment};
	decoded.resize(rspamd_url_decode(decoded.data(), segment.data(), segment.size()));
	if (decoded == "." || decoded == "..") return false;
	return std::none_of(decoded.begin(), decoded.end(), [](char ch) {
		return g_ascii_iscntrl(static_cast<unsigned char>(ch)) || ch == '\\' || ch == '/';
	});
}

auto resolve_part_name(std::string_view source_part, std::string_view target)
	-> ooxml_result<std::string>
{
	if (target.empty()) return tl::make_unexpected("empty relationship target");
	if (target.front() == '/' || has_uri_scheme(target) ||
		std::any_of(target.begin(), target.end(), [](char ch) {
			return g_ascii_iscntrl(static_cast<unsigned char>(ch)) || ch == '\\';
		})) {
		return tl::make_unexpected("absolute or invalid internal relationship target");
	}
	auto fragment = target.find('#');
	auto path = target.substr(0, fragment);
	if (path.empty() || path.find('?') != std::string_view::npos ||
		path.find("//") != std::string_view::npos || path.back() == '/') {
		return tl::make_unexpected("invalid internal relationship target");
	}

	auto source_directory_end = source_part.rfind('/');
	std::size_t depth = 0;
	if (source_directory_end != std::string_view::npos) {
		for (std::size_t pos = 0; pos < source_directory_end;) {
			auto slash = source_part.find('/', pos);
			if (slash == std::string_view::npos || slash > source_directory_end) {
				slash = source_directory_end;
			}
			if (slash > pos) depth++;
			pos = slash + 1;
		}
	}

	std::size_t start = 0;
	while (start < path.size()) {
		auto slash = path.find('/', start);
		if (slash == std::string_view::npos) slash = path.size();
		auto segment = path.substr(start, slash - start);
		if (segment == "..") {
			if (depth == 0) {
				return tl::make_unexpected("relationship target escapes package root");
			}
			depth--;
		}
		else if (segment != ".") {
			if (!validate_segment(segment)) {
				return tl::make_unexpected("invalid relationship path segment");
			}
			depth++;
		}
		start = slash + 1;
	}
	if (depth == 0) {
		return tl::make_unexpected("relationship target does not name a part");
	}

	std::string result{"/"};
	if (source_directory_end != std::string_view::npos) {
		result.append(source_part.substr(0, source_directory_end + 1));
	}
	result.append(path);
	if (result.size() > G_MAXUINT) {
		return tl::make_unexpected("internal relationship target is too long");
	}
	gsize normalized_size;
	rspamd_normalize_path_inplace(result.data(), result.size(), &normalized_size);
	result.resize(normalized_size);
	result.erase(0, 1);
	return result;
}

struct content_types_result {
	ankerl::unordered_dense::map<std::string, std::string> defaults;
	ankerl::unordered_dense::map<std::string, std::string> overrides;
};

class content_types_handler {
public:
	auto start_element(namespace_id ns, std::string_view name,
					   const std::vector<xml_attribute> &attributes) -> ooxml_status
	{
		depth_++;
		if (depth_ == 1) {
			if (name != "Types" || ns != namespace_id::content_types) {
				return tl::make_unexpected("invalid OOXML content types root");
			}
			root_seen_ = true;
		}
		else if (depth_ == 2 && ns == namespace_id::content_types) {
			if (name == "Default") {
				auto *extension = get_attribute(attributes, "Extension");
				auto *content_type = get_attribute(attributes, "ContentType");
				if (extension == nullptr || extension->empty() || content_type == nullptr ||
					content_type->empty()) {
					return tl::make_unexpected("invalid OOXML default content type");
				}
				auto key = *extension;
				rspamd_str_lc(key.data(), key.size());
				if (!result_.defaults.emplace(std::move(key), *content_type).second) {
					return tl::make_unexpected("duplicate OOXML default content type");
				}
			}
			else if (name == "Override") {
				auto *part_name = get_attribute(attributes, "PartName");
				auto *content_type = get_attribute(attributes, "ContentType");
				if (part_name == nullptr || part_name->empty() || part_name->front() != '/' ||
					content_type == nullptr || content_type->empty()) {
					return tl::make_unexpected("invalid OOXML content type override");
				}
				auto normalized = resolve_part_name({}, std::string_view{*part_name}.substr(1));
				if (!normalized) return tl::make_unexpected(std::move(normalized.error()));
				if (!result_.overrides.emplace(std::move(*normalized), *content_type).second) {
					return tl::make_unexpected("duplicate OOXML content type override");
				}
			}
		}
		return {};
	}

	auto end_element(namespace_id, std::string_view) -> ooxml_status
	{
		depth_--;
		return {};
	}
	auto text(std::string_view) -> ooxml_status
	{
		return {};
	}

	auto finish() -> ooxml_result<content_types_result>
	{
		if (!root_seen_) return tl::make_unexpected("missing OOXML content types root");
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

	auto start_element(namespace_id ns, std::string_view name,
					   const std::vector<xml_attribute> &attributes) -> ooxml_status
	{
		depth_++;
		if (depth_ == 1) {
			if (name != "Relationships" || ns != namespace_id::relationships) {
				return tl::make_unexpected("invalid OOXML relationships root");
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
				return tl::make_unexpected("invalid OOXML relationship");
			}
			if (target->size() > limits_.max_target_length) {
				return tl::make_unexpected("OOXML relationship target limit exceeded");
			}
			if (has_ascii_control(*target)) {
				return tl::make_unexpected("control character in OOXML relationship target");
			}
			if (ids_.contains(*id)) {
				return tl::make_unexpected("duplicate OOXML relationship id");
			}
			if (relationships_.size() >= limits_.max_relationships) {
				return tl::make_unexpected("OOXML relationship limit exceeded");
			}
			bool external = false;
			if (mode != nullptr) {
				auto normalized_mode = *mode;
				rspamd_str_lc(normalized_mode.data(), normalized_mode.size());
				if (normalized_mode != "external" && normalized_mode != "internal") {
					return tl::make_unexpected("invalid OOXML relationship target mode");
				}
				external = normalized_mode == "external";
			}

			relationship rel{*id, *type, *target, {}, external};
			if (!external) {
				auto part_name = resolve_part_name(source_part_, *target);
				if (!part_name) return tl::make_unexpected(std::move(part_name.error()));
				rel.part_name = std::move(*part_name);
			}
			ids_.emplace(rel.id);
			relationships_.push_back(std::move(rel));
		}
		return {};
	}

	auto end_element(namespace_id, std::string_view) -> ooxml_status
	{
		depth_--;
		return {};
	}
	auto text(std::string_view) -> ooxml_status
	{
		return {};
	}

	auto finish() -> ooxml_result<std::vector<relationship>>
	{
		if (!root_seen_) return tl::make_unexpected("missing OOXML relationships root");
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

	auto add_text(std::string_view value) -> ooxml_status
	{
		if (text->len + value.size() > max_text) {
			return tl::make_unexpected("DOCX text limit exceeded");
		}
		g_string_append_len(text.get(), value.data(), value.size());
		last_chunk_is_newline = value == "\n";
		return {};
	}

	auto add_url(std::string value) -> ooxml_status
	{
		if (value.empty() || url_seen.contains(value)) return {};
		if (urls.size() >= max_urls) {
			return tl::make_unexpected("DOCX URL limit exceeded");
		}
		url_seen.emplace(value);
		urls.push_back(std::move(value));
		return {};
	}
};

auto is_hyperlink_relationship(std::string_view type) -> bool
{
	return type == hyperlink_relationship || type == strict_hyperlink_relationship;
}

auto hyperlink_from_instruction(std::string_view instruction) -> std::optional<std::string>
{
	auto start_offset = rspamd_substring_search_caseless(instruction.data(), instruction.size(),
														 "hyperlink", sizeof("hyperlink") - 1);
	if (start_offset == -1) return std::nullopt;
	auto start = static_cast<std::size_t>(start_offset);
	auto is_word = [](char ch) {
		return g_ascii_isalnum(static_cast<unsigned char>(ch)) || ch == '_';
	};
	if ((start > 0 && is_word(instruction[start - 1])) ||
		(start + 9 < instruction.size() && is_word(instruction[start + 9]))) {
		return std::nullopt;
	}
	auto pos = start + 9;
	while (pos < instruction.size() && g_ascii_isspace(instruction[pos])) pos++;
	auto end = instruction.size();
	while (end > pos && g_ascii_isspace(instruction[end - 1])) end--;
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
		while (close < end && !g_ascii_isspace(instruction[close])) close++;
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

	auto start_element(namespace_id ns, std::string_view name,
					   const std::vector<xml_attribute> &attributes) -> ooxml_status
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
				if (auto ret = result_.add_text("\t"); !ret) return ret;
			}
			else if ((name == "br" || name == "cr") && !excluded_depth_) {
				if (auto ret = result_.add_text("\n"); !ret) return ret;
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
					if (found != relationships_.end()) {
						if (auto ret = result_.add_url(found->second); !ret) return ret;
					}
				}
			}
			else if (name == "fldSimple") {
				for (const auto &attribute: attributes) {
					if (attribute.name == "instr" && attribute.namespace_value == namespace_id::word) {
						auto url = hyperlink_from_instruction(attribute.value);
						if (url) {
							if (auto ret = result_.add_url(std::move(*url)); !ret) return ret;
						}
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
					if (auto ret = finish_field(); !ret) return ret;
				}
				else if (field_type != nullptr && *field_type == "end" && !fields_.empty()) {
					if (auto ret = finish_field(); !ret) return ret;
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
		return {};
	}

	auto end_element(namespace_id ns, std::string_view name) -> ooxml_status
	{
		if (ns == namespace_id::word && name == "p" && !excluded_depth_) {
			if (auto ret = result_.add_text("\n"); !ret) return ret;
		}
		if (text_depth_ == depth_) text_depth_.reset();
		if (instruction_depth_ == depth_) instruction_depth_.reset();
		if (excluded_depth_ == depth_) excluded_depth_.reset();
		depth_--;
		return {};
	}

	auto text(std::string_view value) -> ooxml_status
	{
		if (instruction_depth_ && !fields_.empty()) {
			fields_.back().instruction.append(value);
		}
		else if (text_depth_ && !excluded_depth_) {
			return result_.add_text(value);
		}
		return {};
	}

private:
	struct field_state {
		std::string instruction;
		bool parsed = false;
	};

	auto finish_field() -> ooxml_status
	{
		if (!fields_.empty() && !fields_.back().parsed) {
			auto url = hyperlink_from_instruction(fields_.back().instruction);
			if (url) {
				if (auto ret = result_.add_url(std::move(*url)); !ret) return ret;
			}
			fields_.back().parsed = true;
		}
		return {};
	}

	const hyperlink_map &relationships_;
	docx_result &result_;
	std::vector<field_state> fields_;
	std::size_t depth_ = 0;
	std::optional<std::size_t> excluded_depth_;
	std::optional<std::size_t> text_depth_;
	std::optional<std::size_t> instruction_depth_;
};

auto read_limits(lua_State *L, int table_index) -> ooxml_result<ooxml_limits>
{
	ooxml_limits result;
	if (!lua_istable(L, table_index)) return result;
	table_index = lua_absindex(L, table_index);
	int64_t max_relationships = result.max_relationships;
	int64_t max_target_length = result.max_target_length;
	int64_t max_text = result.max_text;
	int64_t max_urls = result.max_urls;
	GError *error = nullptr;
	if (!rspamd_lua_parse_table_arguments(L, table_index, &error,
										  RSPAMD_LUA_PARSE_ARGUMENTS_IGNORE_MISSING,
										  "max_relationships=I;max_target_length=I;max_text=I;max_urls=I",
										  &max_relationships, &max_target_length, &max_text, &max_urls)) {
		auto message = error != nullptr ? std::string{error->message} : "invalid OOXML limits";
		if (error != nullptr) g_error_free(error);
		return tl::make_unexpected(std::move(message));
	}
	if (max_relationships >= 0) result.max_relationships = max_relationships;
	if (max_target_length >= 0) result.max_target_length = max_target_length;
	if (max_text >= 0) result.max_text = max_text;
	if (max_urls >= 0) result.max_urls = max_urls;

	lua_getfield(L, table_index, "xml");
	if (lua_istable(L, -1)) {
		auto xml_index = lua_absindex(L, -1);
		int64_t max_input = result.xml.max_input;
		int64_t max_depth = result.xml.max_depth;
		int64_t max_tokens = result.xml.max_tokens;
		int64_t max_attributes = result.xml.max_attributes;
		int64_t max_attribute_length = result.xml.max_attribute_length;
		int64_t xml_max_text = result.xml.max_text;
		double end_timestamp = result.xml.end_timestamp;
		double timeout = result.xml.timeout;
		error = nullptr;
		if (!rspamd_lua_parse_table_arguments(L, xml_index, &error,
											  RSPAMD_LUA_PARSE_ARGUMENTS_IGNORE_MISSING,
											  "max_input=I;max_depth=I;max_tokens=I;max_attributes=I;"
											  "max_attribute_length=I;max_text=I;end_timestamp=N;timeout=N",
											  &max_input, &max_depth, &max_tokens, &max_attributes,
											  &max_attribute_length, &xml_max_text, &end_timestamp, &timeout)) {
			auto message = error != nullptr ? std::string{error->message} : "invalid XML limits";
			if (error != nullptr) g_error_free(error);
			lua_pop(L, 1);
			return tl::make_unexpected(std::move(message));
		}
		if (max_input >= 0) result.xml.max_input = max_input;
		if (max_depth >= 0) result.xml.max_depth = max_depth;
		if (max_tokens >= 0) result.xml.max_tokens = max_tokens;
		if (max_attributes >= 0) result.xml.max_attributes = max_attributes;
		if (max_attribute_length >= 0) result.xml.max_attribute_length = max_attribute_length;
		if (xml_max_text >= 0) result.xml.max_text = xml_max_text;
		result.xml.end_timestamp = end_timestamp;
		result.xml.timeout = timeout;
	}
	lua_pop(L, 1);
	return result;
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
			const char *id = nullptr;
			const char *type = nullptr;
			const char *target = nullptr;
			gboolean external = false;
			GError *error = nullptr;
			if (rspamd_lua_parse_table_arguments(L, rel_index, &error,
												 RSPAMD_LUA_PARSE_ARGUMENTS_DEFAULT,
												 "id=S;type=S;target=S;external=B",
												 &id, &type, &target, &external) &&
				external && id != nullptr && type != nullptr && target != nullptr &&
				is_hyperlink_relationship(type)) {
				result.emplace(id, target);
			}
			if (error != nullptr) g_error_free(error);
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
	auto result = resolve_part_name(*source, *target);
	if (!result) return push_error(L, result.error());
	lua_pushlstring(L, result->data(), result->size());
	return 1;
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
	auto *input = lua_check_text_or_string(L, 1);
	if (input == nullptr) return push_error(L, "string or rspamd_text expected");
	auto limits = read_limits(L, 2);
	if (!limits) return push_error(L, limits.error());
	content_types_handler handler;
	xml_scanner scanner{std::string_view{input->start, input->len},
						scanner_limits(limits->xml), handler};
	if (auto parsed = scanner.parse(); !parsed) {
		return push_error(L, parsed.error());
	}
	auto result = handler.finish();
	if (!result) return push_error(L, result.error());
	lua_createtable(L, 0, 2);
	lua_createtable(L, 0, result->defaults.size());
	for (const auto &[key, value]: result->defaults) {
		lua_pushlstring(L, value.data(), value.size());
		lua_setfield(L, -2, key.c_str());
	}
	lua_setfield(L, -2, "defaults");
	lua_createtable(L, 0, result->overrides.size());
	for (const auto &[key, value]: result->overrides) {
		lua_pushlstring(L, value.data(), value.size());
		lua_setfield(L, -2, key.c_str());
	}
	lua_setfield(L, -2, "overrides");
	return 1;
}

static int lua_ooxml_parse_relationships(lua_State *L)
{
	auto *input = lua_check_text_or_string(L, 1);
	if (input == nullptr) return push_error(L, "string or rspamd_text expected");
	auto source = check_string(L, 2);
	if (!source) return push_error(L, "source part string expected");
	auto limits = read_limits(L, 3);
	if (!limits) return push_error(L, limits.error());
	relationships_handler handler{*source, *limits};
	xml_scanner scanner{std::string_view{input->start, input->len},
						scanner_limits(limits->xml), handler};
	if (auto parsed = scanner.parse(); !parsed) {
		return push_error(L, parsed.error());
	}
	auto relationships = handler.finish();
	if (!relationships) return push_error(L, relationships.error());
	lua_createtable(L, 0, 2);
	auto result_index = lua_absindex(L, -1);
	lua_createtable(L, relationships->size(), 0);
	auto list_index = lua_absindex(L, -1);
	lua_createtable(L, 0, relationships->size());
	auto by_id_index = lua_absindex(L, -1);
	for (std::size_t i = 0; i < relationships->size(); i++) {
		push_relationship(L, (*relationships)[i]);
		lua_pushvalue(L, -1);
		lua_rawseti(L, list_index, i + 1);
		lua_setfield(L, by_id_index, (*relationships)[i].id.c_str());
	}
	lua_setfield(L, result_index, "by_id");
	lua_setfield(L, result_index, "list");
	return 1;
}

static int lua_ooxml_extract_docx(lua_State *L)
{
	if (!lua_istable(L, 1)) return push_error(L, "stories table expected");
	auto limits = read_limits(L, 2);
	if (!limits) return push_error(L, limits.error());
	docx_result result{limits->max_text, limits->max_urls};
	auto stories_index = lua_absindex(L, 1);
	auto count = rspamd_lua_table_size(L, stories_index);
	for (int i = 1; i <= count; i++) {
		lua_rawgeti(L, stories_index, i);
		if (!lua_istable(L, -1)) {
			lua_pop(L, 1);
			return push_error(L, "invalid DOCX story entry");
		}
		auto story_index = lua_absindex(L, -1);
		lua_getfield(L, story_index, "content");
		auto *input = lua_check_text_or_string(L, -1);
		if (input == nullptr) {
			lua_pop(L, 2);
			return push_error(L, "invalid DOCX story content");
		}
		lua_getfield(L, story_index, "relationships");
		auto hyperlinks = read_hyperlinks(L, -1);
		lua_pop(L, 1);

		word_story_handler handler{hyperlinks, result};
		xml_scanner scanner{std::string_view{input->start, input->len},
							scanner_limits(limits->xml), handler};
		if (auto parsed = scanner.parse(); !parsed) {
			lua_pop(L, 2);
			return push_error(L, parsed.error());
		}
		lua_pop(L, 1); /* content */
		if (!result.last_chunk_is_newline) {
			if (auto added = result.add_text("\n"); !added) {
				lua_pop(L, 1);
				return push_error(L, added.error());
			}
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
