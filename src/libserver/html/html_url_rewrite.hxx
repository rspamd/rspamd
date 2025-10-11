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

#ifndef RSPAMD_HTML_URL_REWRITE_HXX
#define RSPAMD_HTML_URL_REWRITE_HXX
#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <cstddef>

struct rspamd_task;

namespace rspamd::html {

struct html_content;
struct html_tag;

/**
 * Candidate for URL rewriting
 * Represents a single href/src attribute that may be rewritten
 */
struct rewrite_candidate {
	const html_tag *tag;       // Tag containing the attribute
	std::string_view attr_name;// "href" or "src"
	std::string absolute_url;  // Absolute/canonicalized URL for Lua policy
	std::size_t offset;        // Offset of attribute value in decoded HTML buffer
	std::size_t len;           // Length of attribute value in decoded HTML buffer
	int part_id;               // MIME part ID (for multi-part messages)
};

/**
 * Patch to apply to the decoded HTML buffer
 * Represents a single replacement operation
 */
struct rewrite_patch {
	int part_id;            // MIME part ID
	std::size_t offset;     // Offset in decoded buffer
	std::size_t len;        // Length to replace
	std::string replacement;// Replacement string

	// For sorting patches by offset
	bool operator<(const rewrite_patch &other) const
	{
		if (part_id != other.part_id) {
			return part_id < other.part_id;
		}
		return offset < other.offset;
	}
};

/**
 * Enumerate rewrite candidates from parsed HTML content
 * @param hc HTML content structure
 * @param task Rspamd task
 * @param part_id MIME part ID
 * @return vector of rewrite candidates
 */
auto enumerate_rewrite_candidates(const html_content *hc, struct rspamd_task *task, int part_id)
	-> std::vector<rewrite_candidate>;

/**
 * Validate and sort patches to ensure no overlaps
 * @param patches vector of patches to validate
 * @return true if valid (no overlaps), false otherwise
 */
auto validate_patches(std::vector<rewrite_patch> &patches) -> bool;

/**
 * Apply patches to a decoded HTML buffer
 * @param original original decoded buffer
 * @param patches sorted, non-overlapping patches
 * @return rewritten buffer
 */
auto apply_patches(std::string_view original, const std::vector<rewrite_patch> &patches)
	-> std::string;

/**
 * Process HTML URL rewriting for a task
 * Enumerates candidates, calls Lua callback, applies patches, and returns rewritten HTML
 * @param task Rspamd task
 * @param hc HTML content
 * @param func_name Lua function name for URL rewriting
 * @param part_id MIME part ID
 * @param original_html Original HTML content (decoded)
 * @return Rewritten HTML or nullopt if no changes
 */
auto process_html_url_rewrite(struct rspamd_task *task,
							  const html_content *hc,
							  const char *func_name,
							  int part_id,
							  std::string_view original_html)
	-> std::optional<std::string>;

/**
 * Re-encode HTML content using MIME transfer encoding
 * @param decoded_html Decoded HTML content (after URL rewriting)
 * @param cte Content Transfer Encoding type (from rspamd_mime_part)
 * @param fold_limit Line length limit for quoted-printable and base64 (0 = no folding)
 * @return Encoded content or nullopt on error
 */
auto reencode_html_content(std::string_view decoded_html,
						   int cte_type,
						   int fold_limit = 76)
	-> std::optional<std::string>;

}// namespace rspamd::html

#endif//RSPAMD_HTML_URL_REWRITE_HXX
