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

#include "libcryptobox/cryptobox.h"
#include "libserver/url.h"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

/***
 * @module rspamd_svg
 * Native bounded SVG content extraction for lua_content: visible text,
 * hyperlinks, remote resources and the scripting / HTML smuggling
 * indicators that make an SVG attachment dangerous.
 */

namespace {

using rspamd::xml::status;

template<typename T>
using result = rspamd::xml::result<T>;

struct svg_namespaces {
	enum class id : std::uint8_t {
		unbound,
		none,
		xml,
		xmlns,
		svg,
		xlink,
		xhtml,
		other,
	};

	static auto classify(std::string_view uri) -> id
	{
		if (uri.empty()) return id::unbound;
		if (uri == rspamd::xml::xml_namespace) return id::xml;
		if (uri == rspamd::xml::xmlns_namespace) return id::xmlns;
		if (uri == "http://www.w3.org/2000/svg") return id::svg;
		if (uri == "http://www.w3.org/1999/xlink") return id::xlink;
		if (uri == "http://www.w3.org/1999/xhtml") return id::xhtml;
		return id::other;
	}
};

using namespace_id = svg_namespaces::id;
using xml_attribute = rspamd::xml::attribute<svg_namespaces>;

struct svg_limits {
	rspamd::xml::limits xml;
	std::size_t max_text = 1U * 1024U * 1024U;
	std::size_t max_urls = 512;
	std::size_t max_payloads = 4;
	std::size_t max_payload_size = 256U * 1024U;
	std::size_t max_resources = 32;
	std::size_t max_indicators = 16;
	std::size_t max_data_uri_types = 16;
	std::size_t max_css = 64U * 1024U;
	std::size_t max_dimension_length = 64;
};

struct gstring_deleter {
	void operator()(GString *str) const
	{
		if (str != nullptr) g_string_free(str, TRUE);
	}
};

struct svg_payload {
	std::string type;
	std::string content;
	bool truncated = false;
};

struct svg_resource {
	std::string kind;
	std::string url;
};

struct svg_result {
	std::unique_ptr<GString, gstring_deleter> text{g_string_sized_new(256)};
	std::vector<std::string> urls;
	ankerl::unordered_dense::set<std::string> url_seen;
	std::vector<svg_resource> resources;
	std::vector<std::string> data_uri_types;
	ankerl::unordered_dense::set<std::string> data_uri_type_seen;
	std::vector<svg_payload> payloads;
	std::vector<std::string> script_indicators;
	ankerl::unordered_dense::set<std::string> indicator_seen;
	std::string width;
	std::string height;
	std::string view_box;
	std::size_t elements = 0;
	std::size_t scripts = 0;
	std::size_t external_scripts = 0;
	std::size_t event_handlers = 0;
	std::size_t javascript_urls = 0;
	std::size_t foreign_objects = 0;
	std::size_t data_uris = 0;
	std::size_t hyperlinks = 0;
	std::size_t forms = 0;
	std::size_t password_inputs = 0;
	std::size_t meta_refresh = 0;
	std::size_t embedded_documents = 0;
	std::size_t css_urls = 0;
	bool last_chunk_is_newline = true;
	const svg_limits &limits;

	explicit svg_result(const svg_limits &limits_value)
		: limits{limits_value}
	{
	}

	auto add_text(std::string_view value) -> status
	{
		if (text->len + value.size() > limits.max_text) {
			return tl::make_unexpected("SVG text limit exceeded");
		}
		g_string_append_len(text.get(), value.data(), value.size());
		last_chunk_is_newline = value == "\n";
		return {};
	}

	auto add_newline() -> status
	{
		if (text->len == 0 || last_chunk_is_newline) return {};
		return add_text("\n");
	}

	auto add_url(std::string value) -> status
	{
		if (value.empty() || url_seen.contains(value)) return {};
		if (urls.size() >= limits.max_urls) {
			return tl::make_unexpected("SVG URL limit exceeded");
		}
		url_seen.emplace(value);
		urls.push_back(std::move(value));
		return {};
	}

	void add_resource(std::string_view kind, std::string_view url)
	{
		if (resources.size() < limits.max_resources) {
			resources.push_back({std::string{kind}, std::string{url}});
		}
	}

	void add_data_uri_type(std::string type)
	{
		if (data_uri_type_seen.contains(type) ||
			data_uri_types.size() >= limits.max_data_uri_types) {
			return;
		}
		data_uri_type_seen.emplace(type);
		data_uri_types.push_back(std::move(type));
	}

	void add_indicator(std::string_view name)
	{
		if (indicator_seen.contains(std::string{name}) ||
			script_indicators.size() >= limits.max_indicators) {
			return;
		}
		indicator_seen.emplace(name);
		script_indicators.emplace_back(name);
	}
};

auto caseless_equals(std::string_view a, std::string_view b) -> bool
{
	return a.size() == b.size() && rspamd_lc_cmp(a.data(), b.data(), a.size()) == 0;
}

auto starts_with_caseless(std::string_view value, std::string_view prefix) -> bool
{
	return value.size() >= prefix.size() &&
		   rspamd_lc_cmp(value.data(), prefix.data(), prefix.size()) == 0;
}

auto is_blank(unsigned char ch) -> bool
{
	return g_ascii_isspace(ch) || g_ascii_iscntrl(ch);
}

auto trim(std::string_view value) -> std::string_view
{
	while (!value.empty() && is_blank(static_cast<unsigned char>(value.front()))) {
		value.remove_prefix(1);
	}
	while (!value.empty() && is_blank(static_cast<unsigned char>(value.back()))) {
		value.remove_suffix(1);
	}
	return value;
}

auto to_lower(std::string_view value) -> std::string
{
	std::string out{value};
	rspamd_str_lc(out.data(), out.size());
	return out;
}

auto matches_any(std::string_view name, std::initializer_list<std::string_view> candidates) -> bool
{
	for (auto candidate: candidates) {
		if (caseless_equals(name, candidate)) return true;
	}
	return false;
}

/* Something a mail client or browser would fetch over the network */
auto is_fetchable(std::string_view value) -> bool
{
	if (value.starts_with("//")) return true;
	return rspamd::xml::has_uri_scheme(value) && value.find("://") != std::string_view::npos;
}

/* Something worth reporting as a hyperlink target */
auto is_link(std::string_view value) -> bool
{
	return is_fetchable(value) || starts_with_caseless(value, "www.") ||
		   starts_with_caseless(value, "mailto:") || starts_with_caseless(value, "tel:");
}

auto is_word_char(unsigned char ch) -> bool
{
	return g_ascii_isalnum(ch) || ch == '_' || ch == '$';
}

/* Case insensitive whole-word search; a dot inside the needle is literal */
auto contains_word(std::string_view haystack, std::string_view needle) -> bool
{
	std::size_t offset = 0;
	while (offset + needle.size() <= haystack.size()) {
		auto found = rspamd_substring_search_caseless(haystack.data() + offset,
													  haystack.size() - offset,
													  needle.data(), needle.size());
		if (found == -1) return false;
		auto start = offset + static_cast<std::size_t>(found);
		auto end = start + needle.size();
		bool left_ok = start == 0 || !is_word_char(static_cast<unsigned char>(haystack[start - 1]));
		bool right_ok = end >= haystack.size() ||
						!is_word_char(static_cast<unsigned char>(haystack[end]));
		if (left_ok && right_ok) return true;
		offset = start + 1;
	}
	return false;
}

/* Script fragments that turn an SVG into a dropper or a redirector */
constexpr std::array<std::string_view, 13> script_keywords{
	"atob",
	"Blob",
	"createObjectURL",
	"msSaveOrOpenBlob",
	"document.write",
	"eval",
	"fromCharCode",
	"unescape",
	"location",
	"innerHTML",
	"XMLHttpRequest",
	"fetch",
	"setTimeout",
};

class svg_handler {
public:
	using namespaces = svg_namespaces;

	explicit svg_handler(svg_result &result)
		: result_{result}
	{
	}

	auto start_element(namespace_id ns, std::string_view name,
					   const std::vector<xml_attribute> &attributes) -> status
	{
		depth_++;
		result_.elements++;
		if (depth_ == 1) {
			if (!caseless_equals(name, "svg")) {
				return tl::make_unexpected("not an SVG document");
			}
			capture_dimension(attributes, "width", result_.width);
			capture_dimension(attributes, "height", result_.height);
			capture_dimension(attributes, "viewBox", result_.view_box);
		}

		for (const auto &attribute: attributes) {
			if (attribute.name.size() > 2 && starts_with_caseless(attribute.name, "on")) {
				result_.event_handlers++;
				scan_script(attribute.value);
			}
			else if (caseless_equals(attribute.name, "style")) {
				if (auto ret = scan_css(attribute.value); !ret) return ret;
			}
		}

		if (in_html(ns)) {
			return start_html_element(name, attributes);
		}
		return start_svg_element(name, attributes);
	}

	auto end_element(namespace_id ns, std::string_view name) -> status
	{
		bool html = in_html(ns);
		if (script_depth_ == depth_) script_depth_.reset();
		if (style_depth_ == depth_) {
			style_depth_.reset();
			auto ret = scan_css(css_);
			css_.clear();
			if (!ret) return ret;
		}

		status ret;
		if (html_depth_ == depth_) {
			html_depth_.reset();
			ret = result_.add_newline();
		}
		else if (html) {
			if (matches_any(name, {"p", "div", "br", "li", "tr", "table", "h1", "h2", "h3", "h4",
								   "h5", "h6", "section", "article", "header", "footer", "form",
								   "ul", "ol", "pre", "blockquote", "body", "html", "title",
								   "label", "button"})) {
				ret = result_.add_newline();
			}
			else if (matches_any(name, {"td", "th"})) {
				ret = result_.add_text("\t");
			}
		}
		else if (is_svg_text_element(name)) {
			if (text_nesting_ > 0) text_nesting_--;
			if (matches_any(name, {"text", "title", "desc"})) {
				ret = result_.add_newline();
			}
		}
		depth_--;
		return ret;
	}

	auto text(std::string_view value) -> status
	{
		if (script_depth_) {
			scan_script(value);
			return {};
		}
		if (style_depth_) {
			if (css_.size() < result_.limits.max_css) {
				css_.append(value.substr(0, result_.limits.max_css - css_.size()));
			}
			return {};
		}
		if (!html_depth_ && text_nesting_ == 0) return {};
		if (trim(value).empty()) return {};
		return result_.add_text(value);
	}

private:
	auto in_html(namespace_id ns) const -> bool
	{
		return ns == namespace_id::xhtml || (ns != namespace_id::svg && html_depth_.has_value());
	}

	static auto is_svg_text_element(std::string_view name) -> bool
	{
		return matches_any(name, {"text", "tspan", "textPath", "tref", "title", "desc"});
	}

	void capture_dimension(const std::vector<xml_attribute> &attributes, std::string_view name,
						   std::string &target) const
	{
		for (const auto &attribute: attributes) {
			if (attribute.namespace_value == namespace_id::none &&
				caseless_equals(attribute.name, name)) {
				auto value = trim(attribute.value);
				target.assign(value.substr(0, result_.limits.max_dimension_length));
				return;
			}
		}
	}

	static auto find_attribute(const std::vector<xml_attribute> &attributes, std::string_view name)
		-> const std::string *
	{
		for (const auto &attribute: attributes) {
			if ((attribute.namespace_value == namespace_id::none ||
				 attribute.namespace_value == namespace_id::xlink ||
				 attribute.namespace_value == namespace_id::svg ||
				 attribute.namespace_value == namespace_id::xhtml) &&
				caseless_equals(attribute.name, name)) {
				return &attribute.value;
			}
		}
		return nullptr;
	}

	auto start_svg_element(std::string_view name, const std::vector<xml_attribute> &attributes)
		-> status
	{
		if (caseless_equals(name, "foreignObject")) {
			result_.foreign_objects++;
			if (!html_depth_) html_depth_ = depth_;
			return {};
		}
		if (caseless_equals(name, "script")) {
			result_.scripts++;
			script_depth_ = depth_;
			if (auto *href = find_attribute(attributes, "href"); href != nullptr) {
				if (is_fetchable(trim(*href))) result_.external_scripts++;
				return handle_url(*href, "script", true);
			}
			return {};
		}
		if (caseless_equals(name, "style")) {
			style_depth_ = depth_;
			return {};
		}
		if (is_svg_text_element(name)) {
			text_nesting_++;
			return {};
		}
		if (caseless_equals(name, "a")) {
			if (auto *href = find_attribute(attributes, "href"); href != nullptr) {
				return handle_url(*href, "a", false);
			}
			return {};
		}
		if (matches_any(name, {"image", "use", "feImage", "video", "audio", "iframe"})) {
			if (auto *href = find_attribute(attributes, "href"); href != nullptr) {
				return handle_url(*href, name, true);
			}
			return {};
		}
		if (matches_any(name, {"set", "animate", "animateMotion", "animateTransform"})) {
			/* Animation elements can rewrite href to javascript: after load */
			for (auto target_name: {"to", "from", "by", "values"}) {
				if (auto *value = find_attribute(attributes, target_name); value != nullptr) {
					if (auto ret = handle_animation_value(*value); !ret) return ret;
				}
			}
		}
		return {};
	}

	auto start_html_element(std::string_view name, const std::vector<xml_attribute> &attributes)
		-> status
	{
		if (caseless_equals(name, "script")) {
			result_.scripts++;
			script_depth_ = depth_;
			if (auto *src = find_attribute(attributes, "src"); src != nullptr) {
				if (is_fetchable(trim(*src))) result_.external_scripts++;
				return handle_url(*src, "script", true);
			}
			return {};
		}
		if (caseless_equals(name, "style")) {
			style_depth_ = depth_;
			return {};
		}
		if (matches_any(name, {"a", "area"})) {
			if (auto *href = find_attribute(attributes, "href"); href != nullptr) {
				return handle_url(*href, "a", false);
			}
			return {};
		}
		if (matches_any(name, {"iframe", "frame", "embed"})) {
			result_.embedded_documents++;
			if (auto *src = find_attribute(attributes, "src"); src != nullptr) {
				return handle_url(*src, name, true);
			}
			return {};
		}
		if (caseless_equals(name, "object")) {
			result_.embedded_documents++;
			if (auto *data = find_attribute(attributes, "data"); data != nullptr) {
				return handle_url(*data, name, true);
			}
			return {};
		}
		if (matches_any(name, {"img", "source", "video", "audio", "track"})) {
			if (auto *src = find_attribute(attributes, "src"); src != nullptr) {
				return handle_url(*src, name, true);
			}
			return {};
		}
		if (caseless_equals(name, "link")) {
			if (auto *href = find_attribute(attributes, "href"); href != nullptr) {
				return handle_url(*href, name, true);
			}
			return {};
		}
		if (caseless_equals(name, "form")) {
			result_.forms++;
			if (auto *action = find_attribute(attributes, "action"); action != nullptr) {
				return handle_url(*action, "form", false);
			}
			return {};
		}
		if (matches_any(name, {"input", "button"})) {
			if (auto *type = find_attribute(attributes, "type"); type != nullptr) {
				if (caseless_equals(trim(*type), "password")) result_.password_inputs++;
			}
			if (auto *action = find_attribute(attributes, "formaction"); action != nullptr) {
				return handle_url(*action, "form", false);
			}
			return {};
		}
		if (caseless_equals(name, "meta")) {
			auto *equiv = find_attribute(attributes, "http-equiv");
			if (equiv != nullptr && caseless_equals(trim(*equiv), "refresh")) {
				result_.meta_refresh++;
				if (auto *content = find_attribute(attributes, "content"); content != nullptr) {
					return handle_meta_refresh(*content);
				}
			}
			return {};
		}
		return {};
	}

	auto handle_meta_refresh(std::string_view content) -> status
	{
		auto found = rspamd_substring_search_caseless(content.data(), content.size(), "url", 3);
		if (found == -1) return {};
		auto pos = static_cast<std::size_t>(found) + 3;
		while (pos < content.size() && (g_ascii_isspace(content[pos]) || content[pos] == '=')) {
			pos++;
		}
		auto value = trim(content.substr(pos));
		if (!value.empty() && (value.front() == '"' || value.front() == '\'')) {
			auto quote = value.front();
			value.remove_prefix(1);
			auto close = value.find(quote);
			if (close != std::string_view::npos) value = value.substr(0, close);
		}
		return handle_url(value, "meta", false);
	}

	auto handle_animation_value(std::string_view values) -> status
	{
		std::size_t start = 0;
		while (start <= values.size()) {
			auto semicolon = values.find(';', start);
			if (semicolon == std::string_view::npos) semicolon = values.size();
			auto value = trim(values.substr(start, semicolon - start));
			if (starts_with_caseless(value, "javascript:") || starts_with_caseless(value, "data:")) {
				if (auto ret = handle_url(value, "animation", false); !ret) return ret;
			}
			start = semicolon + 1;
		}
		return {};
	}

	auto handle_url(std::string_view raw, std::string_view kind, bool as_resource) -> status
	{
		auto value = trim(raw);
		if (value.empty() || value.front() == '#') return {};
		if (starts_with_caseless(value, "javascript:")) {
			result_.javascript_urls++;
			scan_script(value.substr(11));
			return {};
		}
		if (starts_with_caseless(value, "vbscript:")) {
			result_.javascript_urls++;
			return {};
		}
		if (starts_with_caseless(value, "data:")) {
			return handle_data_uri(value);
		}

		std::string normalized{value};
		if (value.starts_with("//")) {
			normalized.insert(0, "https:");
		}
		if (as_resource) {
			/* Relative references mean nothing in a mail attachment */
			if (!is_fetchable(normalized)) return {};
			if (kind == "css") result_.css_urls++;
			result_.add_resource(kind, normalized);
			return result_.add_url(std::move(normalized));
		}
		if (!is_link(normalized)) return {};
		result_.hyperlinks++;
		return result_.add_url(std::move(normalized));
	}

	auto handle_data_uri(std::string_view value) -> status
	{
		result_.data_uris++;
		auto body = value.substr(5);
		auto comma = body.find(',');
		if (comma == std::string_view::npos) {
			result_.add_data_uri_type("invalid");
			return {};
		}
		auto header = body.substr(0, comma);
		auto data = body.substr(comma + 1);

		std::string type;
		bool base64 = false;
		bool first = true;
		std::size_t start = 0;
		while (start <= header.size()) {
			auto semicolon = header.find(';', start);
			if (semicolon == std::string_view::npos) semicolon = header.size();
			auto token = trim(header.substr(start, semicolon - start));
			if (first) {
				type = to_lower(token);
				first = false;
			}
			else if (caseless_equals(token, "base64")) {
				base64 = true;
			}
			start = semicolon + 1;
		}
		if (type.empty()) type = "text/plain";
		if (type.size() > 64) type.resize(64);
		result_.add_data_uri_type(type);

		bool wanted = type == "text/html" || type == "application/xhtml+xml" ||
					  type == "image/svg+xml";
		if (!wanted || result_.payloads.size() >= result_.limits.max_payloads) return {};

		/*
		 * Oversized payloads are truncated rather than dropped: the head of a
		 * smuggled page still carries its URLs and markup.
		 */
		auto max_size = result_.limits.max_payload_size;
		bool truncated = false;
		std::string decoded;
		if (base64) {
			auto max_encoded = (max_size + 2) / 3 * 4;
			std::string stripped;
			stripped.reserve(std::min(data.size(), max_encoded));
			for (auto ch: data) {
				if (stripped.size() >= max_encoded) {
					truncated = true;
					break;
				}
				if (!g_ascii_isspace(static_cast<unsigned char>(ch))) stripped.push_back(ch);
			}
			decoded.resize(stripped.size() + 4);
			gsize decoded_len = decoded.size();
			if (!rspamd_cryptobox_base64_decode(stripped.data(), stripped.size(),
												reinterpret_cast<unsigned char *>(decoded.data()),
												&decoded_len)) {
				return {};
			}
			decoded.resize(decoded_len);
		}
		else {
			/* Percent encoding expands a byte to at most three characters */
			if (data.size() > max_size * 3) {
				data = data.substr(0, max_size * 3);
				truncated = true;
			}
			decoded.resize(data.size() + 1);
			auto decoded_len = rspamd_url_decode(decoded.data(), data.data(), data.size());
			decoded.resize(decoded_len);
		}
		if (decoded.empty()) return {};
		if (decoded.size() > max_size) {
			decoded.resize(max_size);
			truncated = true;
		}
		result_.payloads.push_back({std::move(type), std::move(decoded), truncated});
		return {};
	}

	void scan_script(std::string_view code)
	{
		if (trim(code).empty()) return;
		for (auto keyword: script_keywords) {
			if (contains_word(code, keyword)) result_.add_indicator(keyword);
		}
	}

	/* url(...) and @import targets inside CSS */
	auto scan_css(std::string_view css) -> status
	{
		std::size_t offset = 0;
		while (offset < css.size()) {
			auto found = rspamd_substring_search_caseless(css.data() + offset, css.size() - offset,
														  "url(", 4);
			auto import_found = rspamd_substring_search_caseless(css.data() + offset,
																 css.size() - offset, "@import", 7);
			if (found == -1 && import_found == -1) break;

			std::size_t value_start;
			std::size_t value_end;
			if (found != -1 && (import_found == -1 || found <= import_found)) {
				value_start = offset + static_cast<std::size_t>(found) + 4;
				value_end = css.find(')', value_start);
				if (value_end == std::string_view::npos) value_end = css.size();
			}
			else {
				value_start = offset + static_cast<std::size_t>(import_found) + 7;
				while (value_start < css.size() && g_ascii_isspace(css[value_start])) value_start++;
				if (value_start + 4 <= css.size() &&
					rspamd_lc_cmp(css.data() + value_start, "url(", 4) == 0) {
					offset = value_start;
					continue;
				}
				value_end = value_start;
				while (value_end < css.size() && css[value_end] != ';' && css[value_end] != '\n') {
					value_end++;
				}
			}
			auto value = trim(css.substr(value_start, value_end - value_start));
			if (!value.empty() && (value.front() == '"' || value.front() == '\'')) {
				auto quote = value.front();
				value.remove_prefix(1);
				auto close = value.find(quote);
				if (close != std::string_view::npos) value = value.substr(0, close);
			}
			if (auto ret = handle_url(value, "css", true); !ret) return ret;
			offset = value_end + 1;
		}
		return {};
	}

	svg_result &result_;
	std::string css_;
	std::size_t depth_ = 0;
	std::size_t text_nesting_ = 0;
	std::optional<std::size_t> html_depth_;
	std::optional<std::size_t> script_depth_;
	std::optional<std::size_t> style_depth_;
};

auto read_svg_limits(lua_State *L, int table_index) -> result<svg_limits>
{
	svg_limits limits;
	limits.xml.allow_doctype = true;
	limits.xml.entities = rspamd::html::entity_decode_mode::html;
	limits.xml.max_depth = 128;
	limits.xml.max_input = 4U * 1024U * 1024U;
	limits.xml.max_attribute_length = 4U * 1024U * 1024U;
	limits.xml.max_text = limits.max_text;
	if (!lua_istable(L, table_index)) return limits;
	table_index = lua_absindex(L, table_index);

	int64_t max_text = limits.max_text;
	int64_t max_urls = limits.max_urls;
	int64_t max_payloads = limits.max_payloads;
	int64_t max_payload_size = limits.max_payload_size;
	int64_t max_resources = limits.max_resources;
	GError *error = nullptr;
	if (!rspamd_lua_parse_table_arguments(L, table_index, &error,
										  RSPAMD_LUA_PARSE_ARGUMENTS_IGNORE_MISSING,
										  "max_text=I;max_urls=I;max_payloads=I;max_payload_size=I;"
										  "max_resources=I",
										  &max_text, &max_urls, &max_payloads, &max_payload_size,
										  &max_resources)) {
		auto message = error != nullptr ? std::string{error->message} : "invalid SVG limits";
		if (error != nullptr) g_error_free(error);
		return tl::make_unexpected(std::move(message));
	}
	if (max_text >= 0) limits.max_text = max_text;
	if (max_urls >= 0) limits.max_urls = max_urls;
	if (max_payloads >= 0) limits.max_payloads = max_payloads;
	if (max_payload_size >= 0) limits.max_payload_size = max_payload_size;
	if (max_resources >= 0) limits.max_resources = max_resources;

	auto xml = rspamd::xml::read_limits(L, table_index, limits.xml);
	if (!xml) return tl::make_unexpected(std::move(xml.error()));
	limits.xml = *xml;
	/* The policy bits are not configurable from Lua */
	limits.xml.allow_doctype = true;
	limits.xml.entities = rspamd::html::entity_decode_mode::html;
	return limits;
}

auto push_error(lua_State *L, std::string_view error) -> int
{
	lua_pushnil(L);
	lua_pushlstring(L, error.data(), error.size());
	return 2;
}

void push_string_list(lua_State *L, const std::vector<std::string> &values, const char *field)
{
	lua_createtable(L, values.size(), 0);
	for (std::size_t i = 0; i < values.size(); i++) {
		lua_pushlstring(L, values[i].data(), values[i].size());
		lua_rawseti(L, -2, i + 1);
	}
	lua_setfield(L, -2, field);
}

void push_counter(lua_State *L, std::size_t value, const char *field)
{
	lua_pushinteger(L, value);
	lua_setfield(L, -2, field);
}

/***
 * @function rspamd_svg.extract(data[, options])
 * Parses an SVG document within strict limits.
 * @param {string/rspamd_text} data SVG source (already decompressed)
 * @param {table} options limits: max_text, max_urls, max_payloads, max_payload_size, max_resources, xml = {...}
 * @return {table} extraction result, or nil, error, tokens
 */
static int lua_svg_extract(lua_State *L)
{
	auto *input = lua_check_text_or_string(L, 1);
	if (input == nullptr) return push_error(L, "string or rspamd_text expected");
	auto limits = read_svg_limits(L, 2);
	if (!limits) return push_error(L, limits.error());

	svg_result result{*limits};
	svg_handler handler{result};
	rspamd::xml::scanner scanner{std::string_view{input->start, input->len},
								 rspamd::xml::effective_limits(limits->xml), handler};
	auto parsed = scanner.parse();
	if (!parsed) {
		push_error(L, parsed.error());
		lua_pushinteger(L, scanner.tokens());
		return 3;
	}
	if (auto ret = result.add_newline(); !ret) {
		push_error(L, ret.error());
		lua_pushinteger(L, scanner.tokens());
		return 3;
	}

	lua_createtable(L, 0, 24);
	lua_pushstring(L, "text");
	auto text_len = result.text->len;
	auto *text_data = g_string_free(result.text.release(), FALSE);
	auto *text = lua_new_text(L, text_data, text_len, FALSE);
	text->flags |= RSPAMD_TEXT_FLAG_OWN;
	lua_settable(L, -3);

	push_string_list(L, result.urls, "urls");
	push_string_list(L, result.data_uri_types, "data_uri_types");
	push_string_list(L, result.script_indicators, "script_indicators");

	lua_createtable(L, result.resources.size(), 0);
	for (std::size_t i = 0; i < result.resources.size(); i++) {
		lua_createtable(L, 0, 2);
		lua_pushlstring(L, result.resources[i].kind.data(), result.resources[i].kind.size());
		lua_setfield(L, -2, "kind");
		lua_pushlstring(L, result.resources[i].url.data(), result.resources[i].url.size());
		lua_setfield(L, -2, "url");
		lua_rawseti(L, -2, i + 1);
	}
	lua_setfield(L, -2, "resources");

	lua_createtable(L, result.payloads.size(), 0);
	for (std::size_t i = 0; i < result.payloads.size(); i++) {
		lua_createtable(L, 0, 2);
		lua_pushlstring(L, result.payloads[i].type.data(), result.payloads[i].type.size());
		lua_setfield(L, -2, "type");
		lua_pushlstring(L, result.payloads[i].content.data(), result.payloads[i].content.size());
		lua_setfield(L, -2, "content");
		lua_pushboolean(L, result.payloads[i].truncated);
		lua_setfield(L, -2, "truncated");
		lua_rawseti(L, -2, i + 1);
	}
	lua_setfield(L, -2, "payloads");

	push_counter(L, result.elements, "elements");
	push_counter(L, result.scripts, "scripts");
	push_counter(L, result.external_scripts, "external_scripts");
	push_counter(L, result.event_handlers, "event_handlers");
	push_counter(L, result.javascript_urls, "javascript_urls");
	push_counter(L, result.foreign_objects, "foreign_objects");
	push_counter(L, result.data_uris, "data_uris");
	push_counter(L, result.hyperlinks, "hyperlinks");
	push_counter(L, result.forms, "forms");
	push_counter(L, result.password_inputs, "password_inputs");
	push_counter(L, result.meta_refresh, "meta_refresh");
	push_counter(L, result.embedded_documents, "embedded_documents");
	push_counter(L, result.css_urls, "css_urls");
	lua_pushboolean(L, scanner.has_doctype());
	lua_setfield(L, -2, "doctype");
	for (auto [value, field]: {std::pair{&result.width, "width"}, std::pair{&result.height, "height"},
							   std::pair{&result.view_box, "view_box"}}) {
		if (!value->empty()) {
			lua_pushlstring(L, value->data(), value->size());
			lua_setfield(L, -2, field);
		}
	}
	lua_pushnil(L);
	lua_pushinteger(L, scanner.tokens());
	return 3;
}

static const struct luaL_reg svg_lib[] = {
	{"extract", lua_svg_extract},
	{nullptr, nullptr},
};

}// namespace

void luaopen_svg(lua_State *L)
{
	rspamd_lua_add_preload(L, "rspamd_svg", [](lua_State *LL) -> int {
		luaL_register(LL, "rspamd_svg", svg_lib);
		return 1;
	});
}
