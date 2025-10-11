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

#include "lua/lua_common.h"
#include "html_url_rewrite.hxx"
#include "html.hxx"
#include "html_tag.hxx"
#include "libserver/task.h"
#include "libserver/cfg_file.h"
#include "libserver/url.h"
#include "libmime/message.h"
#include "libutil/str_util.h"

#include <algorithm>

#define msg_debug_html_rewrite(...) rspamd_conditional_debug_fast(NULL, NULL,                                                   \
																  rspamd_task_log_id, "html_rewrite", task->task_pool->tag.uid, \
																  __FUNCTION__,                                                 \
																  __VA_ARGS__)

namespace rspamd::html {

/**
 * Call Lua url_rewriter function to get replacement URL
 * @param task Rspamd task
 * @param func_name Lua function name (e.g., "url_rewriter")
 * @param url Original URL string
 * @return Replacement URL or empty optional if no replacement
 */
static auto call_lua_url_rewriter(struct rspamd_task *task, const char *func_name, const std::string &url)
	-> std::optional<std::string>
{
	if (!func_name || !task || !task->cfg) {
		return std::nullopt;
	}

	auto *L = RSPAMD_LUA_CFG_STATE(task->cfg);
	if (!L) {
		return std::nullopt;
	}

	// Push error handler
	lua_pushcfunction(L, &rspamd_lua_traceback);
	auto err_idx = lua_gettop(L);

	// Get the function
	if (!rspamd_lua_require_function(L, func_name, nullptr)) {
		msg_debug_html_rewrite("cannot require function %s", func_name);
		lua_settop(L, err_idx - 1);
		return std::nullopt;
	}

	// Push task
	struct rspamd_task **ptask = (struct rspamd_task **) lua_newuserdata(L, sizeof(struct rspamd_task *));
	*ptask = task;
	rspamd_lua_setclass(L, rspamd_task_classname, -1);

	// Push URL string
	lua_pushlstring(L, url.c_str(), url.size());

	// Call function with 2 args, 1 result
	if (lua_pcall(L, 2, 1, err_idx) != 0) {
		msg_warn_task("call to %s failed: %s", func_name, lua_tostring(L, -1));
		lua_settop(L, err_idx - 1);
		return std::nullopt;
	}

	// Check return value
	std::optional<std::string> result;
	if (lua_type(L, -1) == LUA_TSTRING) {
		std::size_t len;
		const char *str = lua_tolstring(L, -1, &len);
		if (str && len > 0) {
			result = std::string{str, len};
			msg_debug_html_rewrite("URL rewrite: %s -> %s", url.c_str(), result->c_str());
		}
	}
	else if (!lua_isnil(L, -1)) {
		msg_warn_task("%s returned non-string value", func_name);
	}

	lua_settop(L, err_idx - 1);
	return result;
}

auto enumerate_rewrite_candidates(const html_content *hc, struct rspamd_task *task, int part_id)
	-> std::vector<rewrite_candidate>
{
	std::vector<rewrite_candidate> candidates;

	if (!hc) {
		return candidates;
	}

	// Enumerate all clickable attributes with spans
	hc->for_each_clickable_attr([&](const html_tag *tag, std::string_view attr_name, const attr_span &span) -> bool {
		// Get the href or src value
		std::string_view url_value;
		if (attr_name == "href") {
			if (auto href = tag->find_href()) {
				url_value = href.value();
			}
		}
		else if (attr_name == "src") {
			if (auto src_comp = tag->find_component<html_component_src>()) {
				url_value = src_comp.value()->value;
			}
		}

		if (url_value.empty()) {
			return true;// Continue to next
		}

		// Skip data: and cid: schemes by default
		if (url_value.size() >= 5) {
			if (url_value.substr(0, 5) == "data:" || url_value.substr(0, 4) == "cid:") {
				return true;// Continue to next
			}
		}

		// Build absolute URL (already done by parser, but we have it in url_value)
		// For now, just use url_value as-is. In real implementation, this should
		// handle base URL resolution if needed.
		std::string absolute_url{url_value};

		// Create candidate
		candidates.push_back(rewrite_candidate{tag, attr_name, std::move(absolute_url), span.offset, span.len, part_id});

		return true;// Continue to next
	});

	return candidates;
}

auto validate_patches(std::vector<rewrite_patch> &patches) -> bool
{
	if (patches.empty()) {
		return true;
	}

	// Sort patches by part_id and offset
	std::sort(patches.begin(), patches.end());

	// Check for overlaps within same part
	for (std::size_t i = 1; i < patches.size(); i++) {
		const auto &prev = patches[i - 1];
		const auto &curr = patches[i];

		// If same part, check for overlap
		if (prev.part_id == curr.part_id) {
			auto prev_end = prev.offset + prev.len;
			if (prev_end > curr.offset) {
				// Overlap detected
				return false;
			}
		}
	}

	return true;
}

auto apply_patches(std::string_view original, const std::vector<rewrite_patch> &patches)
	-> std::string
{
	if (patches.empty()) {
		return std::string{original};
	}

	std::string result;
	result.reserve(original.size() + 1024);// Reserve extra space for potential growth

	std::size_t pos = 0;

	for (const auto &patch: patches) {
		// Copy everything from pos to patch.offset
		if (patch.offset > pos) {
			result.append(original.substr(pos, patch.offset - pos));
		}

		// Apply the replacement
		result.append(patch.replacement);

		// Move position to after the patched region
		pos = patch.offset + patch.len;
	}

	// Copy remaining content
	if (pos < original.size()) {
		result.append(original.substr(pos));
	}

	return result;
}

auto process_html_url_rewrite(struct rspamd_task *task,
							  const html_content *hc,
							  const char *func_name,
							  int part_id,
							  std::string_view original_html)
	-> std::optional<std::string>
{
	if (!task || !hc || !func_name) {
		return std::nullopt;
	}

	// Enumerate candidates
	auto candidates = enumerate_rewrite_candidates(hc, task, part_id);
	if (candidates.empty()) {
		msg_debug_html_rewrite("no URL rewrite candidates found");
		return std::nullopt;
	}

	msg_debug_html_rewrite("found %zu URL rewrite candidates", candidates.size());

	// Build patches by calling Lua for each candidate
	std::vector<rewrite_patch> patches;
	patches.reserve(candidates.size());

	for (const auto &candidate: candidates) {
		// Call Lua callback
		auto replacement = call_lua_url_rewriter(task, func_name, candidate.absolute_url);
		if (!replacement) {
			continue;// Skip if Lua returned nil
		}

		// Create patch
		patches.push_back(rewrite_patch{
			candidate.part_id,
			candidate.offset,
			candidate.len,
			std::move(replacement.value())});
	}

	if (patches.empty()) {
		msg_debug_html_rewrite("no patches generated from Lua callbacks");
		return std::nullopt;
	}

	// Validate and sort patches
	if (!validate_patches(patches)) {
		msg_warn_task("URL rewrite patches overlap, skipping rewrite");
		return std::nullopt;
	}

	msg_debug_html_rewrite("applying %zu patches", patches.size());

	// Apply patches
	return apply_patches(original_html, patches);
}

auto reencode_html_content(std::string_view decoded_html,
						   int cte_type,
						   int fold_limit)
	-> std::optional<std::string>
{
	if (decoded_html.empty()) {
		return std::nullopt;
	}

	auto cte = static_cast<enum rspamd_cte>(cte_type);

	switch (cte) {
	case RSPAMD_CTE_7BIT:
	case RSPAMD_CTE_8BIT:
		// No encoding needed, return as-is
		return std::string{decoded_html};

	case RSPAMD_CTE_QP: {
		// Encode using quoted-printable with CRLF line endings (MIME standard)
		if (fold_limit > 0) {
			char *encoded = rspamd_encode_qp_fold(
				reinterpret_cast<const unsigned char *>(decoded_html.data()),
				decoded_html.size(),
				fold_limit,
				nullptr,
				RSPAMD_TASK_NEWLINES_CRLF);
			if (encoded) {
				std::string result{encoded};
				g_free(encoded);
				return result;
			}
		}
		return std::nullopt;
	}

	case RSPAMD_CTE_B64: {
		// Encode using base64 with CRLF line endings (MIME standard)
		char *encoded = nullptr;
		if (fold_limit > 0) {
			encoded = rspamd_encode_base64_fold(
				reinterpret_cast<const unsigned char *>(decoded_html.data()),
				decoded_html.size(),
				fold_limit,
				nullptr,
				RSPAMD_TASK_NEWLINES_CRLF);
		}
		else {
			// No folding
			encoded = rspamd_encode_base64(
				reinterpret_cast<const unsigned char *>(decoded_html.data()),
				decoded_html.size(),
				-1,
				nullptr);
		}

		if (encoded) {
			std::string result{encoded};
			g_free(encoded);
			return result;
		}
		return std::nullopt;
	}

	case RSPAMD_CTE_UUE:
		// UUE encoding not supported for rewriting
		return std::nullopt;

	case RSPAMD_CTE_UNKNOWN:
	default:
		// Unknown encoding, return decoded content
		return std::string{decoded_html};
	}
}

}// namespace rspamd::html
