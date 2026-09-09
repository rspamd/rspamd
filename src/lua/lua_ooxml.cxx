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
#include "lua_xml_scanner.hxx"

#include "libserver/url.h"

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

using xml_limits = rspamd::xml::limits;

struct ooxml_limits {
	xml_limits xml;
	std::size_t max_relationships = 4096;
	std::size_t max_content_types = 4096;
	std::size_t max_target_length = 16U * 1024U;
	std::size_t max_text = 2U * 1024U * 1024U;
	std::size_t max_urls = 1024;
};

template<typename T>
using ooxml_result = rspamd::xml::result<T>;

using ooxml_status = rspamd::xml::status;

struct ooxml_namespaces {
	enum class id : std::uint8_t {
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

	static auto classify(std::string_view uri) -> id
	{
		if (uri.empty()) return id::unbound;
		if (uri == rspamd::xml::xml_namespace) return id::xml;
		if (uri == rspamd::xml::xmlns_namespace) return id::xmlns;
		if (uri == content_types_namespace || uri == strict_content_types_namespace) {
			return id::content_types;
		}
		if (uri == relationships_namespace || uri == strict_relationships_namespace) {
			return id::relationships;
		}
		if (uri == word_namespace || uri == strict_word_namespace) return id::word;
		if (uri == drawing_namespace || uri == strict_drawing_namespace) return id::drawing;
		if (uri == document_relationship_namespace ||
			uri == strict_document_relationship_namespace) {
			return id::document_relationships;
		}
		return id::other;
	}
};

using namespace_id = ooxml_namespaces::id;
using xml_attribute = rspamd::xml::attribute<ooxml_namespaces>;
using rspamd::xml::get_attribute;
using rspamd::xml::has_ascii_control;
using rspamd::xml::has_uri_scheme;

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
	using namespaces = ooxml_namespaces;

	explicit content_types_handler(const ooxml_limits &limits)
		: limits_{limits}
	{
	}

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
			if ((name == "Default" || name == "Override") &&
				result_.defaults.size() + result_.overrides.size() >= limits_.max_content_types) {
				return tl::make_unexpected("OOXML content type limit exceeded");
			}
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
	ooxml_limits limits_;
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
	using namespaces = ooxml_namespaces;

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
	using namespaces = ooxml_namespaces;

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
	int64_t max_content_types = result.max_content_types;
	int64_t max_target_length = result.max_target_length;
	int64_t max_text = result.max_text;
	int64_t max_urls = result.max_urls;
	GError *error = nullptr;
	if (!rspamd_lua_parse_table_arguments(L, table_index, &error,
										  RSPAMD_LUA_PARSE_ARGUMENTS_IGNORE_MISSING,
										  "max_relationships=I;max_content_types=I;max_target_length=I;"
										  "max_text=I;max_urls=I",
										  &max_relationships, &max_content_types, &max_target_length,
										  &max_text, &max_urls)) {
		auto message = error != nullptr ? std::string{error->message} : "invalid OOXML limits";
		if (error != nullptr) g_error_free(error);
		return tl::make_unexpected(std::move(message));
	}
	if (max_relationships >= 0) result.max_relationships = max_relationships;
	if (max_content_types >= 0) result.max_content_types = max_content_types;
	if (max_target_length >= 0) result.max_target_length = max_target_length;
	if (max_text >= 0) result.max_text = max_text;
	if (max_urls >= 0) result.max_urls = max_urls;

	auto xml = rspamd::xml::read_limits(L, table_index, result.xml);
	if (!xml) return tl::make_unexpected(std::move(xml.error()));
	result.xml = *xml;
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

auto push_error(lua_State *L, std::string_view error) -> int
{
	lua_pushnil(L);
	lua_pushlstring(L, error.data(), error.size());
	return 2;
}

auto push_error_with_tokens(lua_State *L, std::string_view error, std::size_t tokens) -> int
{
	push_error(L, error);
	lua_pushinteger(L, tokens);
	return 3;
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
	content_types_handler handler{*limits};
	rspamd::xml::scanner scanner{std::string_view{input->start, input->len},
								 rspamd::xml::effective_limits(limits->xml), handler};
	if (auto parsed = scanner.parse(); !parsed) {
		return push_error_with_tokens(L, parsed.error(), scanner.tokens());
	}
	auto result = handler.finish();
	if (!result) return push_error_with_tokens(L, result.error(), scanner.tokens());
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
	lua_pushnil(L);
	lua_pushinteger(L, scanner.tokens());
	return 3;
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
	rspamd::xml::scanner scanner{std::string_view{input->start, input->len},
								 rspamd::xml::effective_limits(limits->xml), handler};
	if (auto parsed = scanner.parse(); !parsed) {
		return push_error_with_tokens(L, parsed.error(), scanner.tokens());
	}
	auto relationships = handler.finish();
	if (!relationships) {
		return push_error_with_tokens(L, relationships.error(), scanner.tokens());
	}
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
	lua_pushnil(L);
	lua_pushinteger(L, scanner.tokens());
	return 3;
}

static int lua_ooxml_extract_docx(lua_State *L)
{
	if (!lua_istable(L, 1)) return push_error(L, "stories table expected");
	auto limits = read_limits(L, 2);
	if (!limits) return push_error(L, limits.error());
	docx_result result{limits->max_text, limits->max_urls};
	std::size_t total_tokens = 0;
	auto stories_index = lua_absindex(L, 1);
	auto count = rspamd_lua_table_size(L, stories_index);
	for (int i = 1; i <= count; i++) {
		lua_rawgeti(L, stories_index, i);
		if (!lua_istable(L, -1)) {
			lua_pop(L, 1);
			return push_error_with_tokens(L, "invalid DOCX story entry", total_tokens);
		}
		auto story_index = lua_absindex(L, -1);
		lua_getfield(L, story_index, "content");
		auto *input = lua_check_text_or_string(L, -1);
		if (input == nullptr) {
			lua_pop(L, 2);
			return push_error_with_tokens(L, "invalid DOCX story content", total_tokens);
		}
		lua_getfield(L, story_index, "relationships");
		auto hyperlinks = read_hyperlinks(L, -1);
		lua_pop(L, 1);

		word_story_handler handler{hyperlinks, result};
		rspamd::xml::scanner scanner{std::string_view{input->start, input->len},
									 rspamd::xml::effective_limits(limits->xml), handler};
		auto parsed = scanner.parse();
		total_tokens += scanner.tokens();
		if (!parsed) {
			lua_pop(L, 2);
			return push_error_with_tokens(L, parsed.error(), total_tokens);
		}
		lua_pop(L, 1); /* content */
		if (!result.last_chunk_is_newline) {
			if (auto added = result.add_text("\n"); !added) {
				lua_pop(L, 1);
				return push_error_with_tokens(L, added.error(), total_tokens);
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
	lua_pushnil(L);
	lua_pushinteger(L, total_tokens);
	return 3;
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
