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

#ifndef RSPAMD_MULTIPART_FORM_HXX
#define RSPAMD_MULTIPART_FORM_HXX

#include <string_view>
#include <vector>
#include <optional>

namespace rspamd::http {

struct multipart_entry {
	std::string_view name;
	std::string_view filename;
	std::string_view content_type;
	std::string_view content_encoding;
	std::string_view data;
};

struct multipart_form {
	std::vector<multipart_entry> parts;
};

/**
 * Parse multipart/form-data body.
 * All string_views point into the original data buffer (zero-copy).
 * @param data raw body
 * @param boundary boundary string (without leading --)
 * @return parsed form or nullopt on error
 */
auto parse_multipart_form(std::string_view data,
						  std::string_view boundary) -> std::optional<multipart_form>;

/**
 * Find part by name.
 * @return pointer to entry or nullptr
 */
auto find_part(const multipart_form &form,
			   std::string_view name) -> const multipart_entry *;

}// namespace rspamd::http

/* C bridge - include the C-only header */
#include "multipart_form.h"

#endif// RSPAMD_MULTIPART_FORM_HXX
