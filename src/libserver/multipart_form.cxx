/*
 * Copyright 2025 Vsevolod Stakhov
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

#include "multipart_form.hxx"
#include <algorithm>
#include <cstring>

namespace rspamd::http {

namespace {

/* Trim leading and trailing whitespace (spaces and tabs) */
auto trim(std::string_view sv) -> std::string_view
{
	while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t')) {
		sv.remove_prefix(1);
	}
	while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t')) {
		sv.remove_suffix(1);
	}
	return sv;
}

/* Case-insensitive prefix check */
auto starts_with_ci(std::string_view haystack, std::string_view needle) -> bool
{
	if (haystack.size() < needle.size()) {
		return false;
	}
	for (size_t i = 0; i < needle.size(); i++) {
		if (std::tolower(static_cast<unsigned char>(haystack[i])) !=
			std::tolower(static_cast<unsigned char>(needle[i]))) {
			return false;
		}
	}
	return true;
}

/**
 * Extract a quoted or unquoted parameter value from a header value string.
 * Given: name="value"; other="x"
 * extract_param(sv, "name") returns "value"
 */
auto extract_param(std::string_view header, std::string_view param_name) -> std::string_view
{
	auto pos = size_t{0};

	while (pos < header.size()) {
		/* Find param_name */
		auto found = header.find(param_name, pos);
		if (found == std::string_view::npos) {
			return {};
		}

		/* Check that it's preceded by ; or start, not part of another word */
		if (found > 0) {
			auto prev = header[found - 1];
			if (prev != ';' && prev != ' ' && prev != '\t') {
				pos = found + param_name.size();
				continue;
			}
		}

		auto after = found + param_name.size();
		/* Skip whitespace before = */
		while (after < header.size() && (header[after] == ' ' || header[after] == '\t')) {
			after++;
		}
		if (after >= header.size() || header[after] != '=') {
			pos = after;
			continue;
		}
		after++; /* skip = */
		while (after < header.size() && (header[after] == ' ' || header[after] == '\t')) {
			after++;
		}
		if (after >= header.size()) {
			return {};
		}

		if (header[after] == '"') {
			/* Quoted value */
			after++; /* skip opening quote */
			auto end = header.find('"', after);
			if (end == std::string_view::npos) {
				return header.substr(after);
			}
			return header.substr(after, end - after);
		}
		else {
			/* Unquoted value - ends at ; or end */
			auto end = header.find(';', after);
			if (end == std::string_view::npos) {
				return trim(header.substr(after));
			}
			return trim(header.substr(after, end - after));
		}
	}

	return {};
}

/**
 * Parse headers from a part preamble.
 * Headers end at the first \r\n\r\n or \n\n.
 * Returns: (headers_end_offset, entry with parsed headers)
 */
auto parse_part_headers(std::string_view part_data, multipart_entry &entry) -> size_t
{
	/* Find end of headers */
	auto hdr_end = part_data.find("\r\n\r\n");
	size_t skip = 4;

	if (hdr_end == std::string_view::npos) {
		hdr_end = part_data.find("\n\n");
		skip = 2;
		if (hdr_end == std::string_view::npos) {
			return 0;
		}
	}

	auto headers = part_data.substr(0, hdr_end);

	/* Parse individual headers (split by \r\n or \n) */
	size_t pos = 0;
	while (pos < headers.size()) {
		auto line_end = headers.find('\n', pos);
		std::string_view line;
		if (line_end == std::string_view::npos) {
			line = headers.substr(pos);
			pos = headers.size();
		}
		else {
			line = headers.substr(pos, line_end - pos);
			pos = line_end + 1;
		}

		/* Strip trailing \r */
		if (!line.empty() && line.back() == '\r') {
			line.remove_suffix(1);
		}

		if (line.empty()) {
			continue;
		}

		auto colon = line.find(':');
		if (colon == std::string_view::npos) {
			continue;
		}

		auto hdr_name = trim(line.substr(0, colon));
		auto hdr_value = trim(line.substr(colon + 1));

		if (starts_with_ci(hdr_name, "content-disposition")) {
			entry.name = extract_param(hdr_value, "name");
			entry.filename = extract_param(hdr_value, "filename");
		}
		else if (starts_with_ci(hdr_name, "content-type")) {
			/* Content-Type value is everything up to first ; or end */
			auto semi = hdr_value.find(';');
			if (semi != std::string_view::npos) {
				entry.content_type = trim(hdr_value.substr(0, semi));
			}
			else {
				entry.content_type = hdr_value;
			}
		}
		else if (starts_with_ci(hdr_name, "content-encoding") ||
				 starts_with_ci(hdr_name, "content-transfer-encoding")) {
			entry.content_encoding = hdr_value;
		}
	}

	return hdr_end + skip;
}

}// anonymous namespace

auto parse_multipart_form(std::string_view data,
						  std::string_view boundary) -> std::optional<multipart_form>
{
	if (boundary.empty() || data.empty()) {
		return std::nullopt;
	}

	/* Build delimiter strings: "\r\n--<boundary>" and "--<boundary>" */
	std::string delim;
	delim.reserve(boundary.size() + 4);
	delim = "--";
	delim.append(boundary.data(), boundary.size());

	std::string crlf_delim = "\r\n";
	crlf_delim.append(delim);

	std::string lf_delim = "\n";
	lf_delim.append(delim);

	/* Find the first boundary */
	auto first = data.find(delim);
	if (first == std::string_view::npos) {
		return std::nullopt;
	}

	/* Skip past first boundary line */
	auto pos = first + delim.size();

	/* Skip optional \r\n after boundary */
	if (pos < data.size() && data[pos] == '\r') {
		pos++;
	}
	if (pos < data.size() && data[pos] == '\n') {
		pos++;
	}

	static constexpr size_t max_parts = 8;
	multipart_form form;

	while (pos < data.size()) {
		/* Find next boundary (try \r\n-- first, then \n--) */
		auto next = data.find(crlf_delim, pos);
		size_t delim_size = crlf_delim.size();

		if (next == std::string_view::npos) {
			next = data.find(lf_delim, pos);
			delim_size = lf_delim.size();
		}

		if (next == std::string_view::npos) {
			break;
		}

		auto part_data = data.substr(pos, next - pos);

		/* Parse headers from this part */
		multipart_entry entry{};
		auto body_offset = parse_part_headers(part_data, entry);

		if (body_offset > 0 && body_offset <= part_data.size()) {
			entry.data = part_data.substr(body_offset);
		}
		else {
			/* No headers found, treat entire part as data */
			entry.data = part_data;
		}

		form.parts.push_back(entry);

		if (form.parts.size() >= max_parts) {
			break;
		}

		/* Move past the boundary */
		pos = next + delim_size;

		/* Check for closing boundary -- */
		if (pos + 1 < data.size() && data[pos] == '-' && data[pos + 1] == '-') {
			break;
		}

		/* Skip \r\n after boundary */
		if (pos < data.size() && data[pos] == '\r') {
			pos++;
		}
		if (pos < data.size() && data[pos] == '\n') {
			pos++;
		}
	}

	if (form.parts.empty()) {
		return std::nullopt;
	}

	return form;
}

auto find_part(const multipart_form &form,
			   std::string_view name) -> const multipart_entry *
{
	for (const auto &entry: form.parts) {
		if (entry.name == name) {
			return &entry;
		}
	}
	return nullptr;
}

}// namespace rspamd::http


/*
 * C bridge implementation
 */

struct rspamd_multipart_form_c {
	rspamd::http::multipart_form form;
	/* Pre-built C entries for find() results */
	std::vector<rspamd_multipart_entry_c> c_entries;

	void build_c_entries()
	{
		c_entries.clear();
		c_entries.reserve(form.parts.size());
		for (const auto &p: form.parts) {
			rspamd_multipart_entry_c ce{};
			ce.name = p.name.data();
			ce.name_len = p.name.size();
			ce.filename = p.filename.data();
			ce.filename_len = p.filename.size();
			ce.content_type = p.content_type.data();
			ce.content_type_len = p.content_type.size();
			ce.content_encoding = p.content_encoding.data();
			ce.content_encoding_len = p.content_encoding.size();
			ce.data = p.data.data();
			ce.data_len = p.data.size();
			c_entries.push_back(ce);
		}
	}
};

extern "C" {

struct rspamd_multipart_form_c *
rspamd_multipart_form_parse(const char *data, gsize len,
							const char *boundary, gsize boundary_len)
{
	auto result = rspamd::http::parse_multipart_form(
		{data, len}, {boundary, boundary_len});

	if (!result) {
		return nullptr;
	}

	auto *form = new rspamd_multipart_form_c();
	form->form = std::move(*result);
	form->build_c_entries();
	return form;
}

gsize rspamd_multipart_form_nparts(const struct rspamd_multipart_form_c *form)
{
	if (!form) {
		return 0;
	}
	return form->form.parts.size();
}

const struct rspamd_multipart_entry_c *
rspamd_multipart_form_find(const struct rspamd_multipart_form_c *form,
						   const char *name, gsize name_len)
{
	if (!form || !name) {
		return nullptr;
	}

	std::string_view name_sv{name, name_len};
	for (size_t i = 0; i < form->form.parts.size(); i++) {
		if (form->form.parts[i].name == name_sv) {
			return &form->c_entries[i];
		}
	}
	return nullptr;
}

void rspamd_multipart_form_free(struct rspamd_multipart_form_c *form)
{
	delete form;
}

} /* extern "C" */
