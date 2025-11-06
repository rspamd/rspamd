/*-
 * Copyright 2025 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "config.h"
#include "libserver/html/html_cta.hxx"

#include "util.h"
#include "message.h"
#include "libserver/html/html.hxx"
#include "libserver/html/html_block.hxx"
#include "libserver/html/html_tag.hxx"
#include "libserver/css/css.hxx"
#include "libserver/url.h"
#include "libserver/task.h"
#include "libutil/cxx/util.hxx"
#include "libutil/heap.h"

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include <glib.h>

static constexpr unsigned int CTA_WEIGHT_SCALE = 1000;

namespace rspamd::html {
namespace {

using namespace std::string_view_literals;

static auto trim_ascii(std::string_view input) -> std::string_view
{
	while (!input.empty() && g_ascii_isspace(static_cast<gchar>(input.front()))) {
		input.remove_prefix(1);
	}

	while (!input.empty() && g_ascii_isspace(static_cast<gchar>(input.back()))) {
		input.remove_suffix(1);
	}

	return input;
}

static auto space_separated_token_match(std::string_view attr,
										std::string_view token,
										bool allow_partial) -> bool
{
	attr = trim_ascii(attr);
	if (attr.empty()) {
		return false;
	}

	std::size_t pos = 0;
	while (pos < attr.size()) {
		while (pos < attr.size() && g_ascii_isspace(static_cast<gchar>(attr[pos]))) {
			pos++;
		}
		if (pos >= attr.size()) {
			break;
		}

		auto end = pos;
		while (end < attr.size() && !g_ascii_isspace(static_cast<gchar>(attr[end]))) {
			end++;
		}

		auto chunk = attr.substr(pos, end - pos);
		if (allow_partial) {
			if (chunk.find(token) != std::string_view::npos) {
				return true;
			}
		}
		else {
			if (chunk == token) {
				return true;
			}
		}

		pos = end + 1;
	}

	return false;
}

static auto optional_attr_contains(const std::optional<std::string_view> &attr,
								   std::string_view token,
								   bool allow_partial = false) -> bool
{
	if (!attr) {
		return false;
	}

	return space_separated_token_match(attr.value(), token, allow_partial);
}

template<typename Range>
static auto optional_attr_contains_any(const std::optional<std::string_view> &attr,
									   const Range &tokens,
									   bool allow_partial = false) -> bool
{
	if (!attr) {
		return false;
	}

	for (auto token: tokens) {
		if (space_separated_token_match(attr.value(), token, allow_partial)) {
			return true;
		}
	}

	return false;
}

static auto to_lower_ascii(std::string_view input) -> std::string
{
	std::string out;
	out.reserve(input.size());
	for (auto ch: input) {
		out.push_back(static_cast<char>(g_ascii_tolower(static_cast<guchar>(ch))));
	}
	return out;
}

static auto get_cta_label(const html_tag &tag, const html_content &hc) -> std::string
{
	auto content = trim_ascii(tag.get_content(&hc));
	if (!content.empty()) {
		return std::string{content};
	}

	if (auto title = tag.find_component<html_component_title>()) {
		auto value = trim_ascii(title.value()->value);
		if (!value.empty()) {
			return std::string{value};
		}
	}

	if (auto aria_label = tag.find_component_by_name("aria-label"sv)) {
		auto value = trim_ascii(aria_label.value());
		if (!value.empty()) {
			return std::string{value};
		}
	}

	if (auto alt = tag.find_component<html_component_alt>()) {
		auto value = trim_ascii(alt.value()->value);
		if (!value.empty()) {
			return std::string{value};
		}
	}

	return {};
}

static auto tag_is_effectively_hidden(const html_tag *tag) -> bool
{
	for (auto current = tag; current != nullptr; current = current->parent) {
		if (current->block && !current->block->is_visible()) {
			return true;
		}
		if (current->flags & FL_IGNORE) {
			return true;
		}
	}

	return false;
}

static constexpr auto buttonish_class_tokens = rspamd::array_of<std::string_view>(
	"btn", "button", "cta", "call-to-action", "submit", "primary",
	"confirm", "action", "purchase", "buy", "signup", "sign-up", "apply");

static constexpr auto negative_context_tokens = rspamd::array_of<std::string_view>(
	"logo", "footer", "header", "nav", "menu", "social",
	"tracking", "pixel", "unsubscribe", "legal", "copyright");

static constexpr auto service_rel_tokens = rspamd::array_of<std::string_view>(
	"alternate", "canonical", "dns-prefetch", "icon", "manifest",
	"preconnect", "prefetch", "preload", "stylesheet");

static constexpr auto cta_keywords = rspamd::array_of<std::string_view>(
	"buy", "purchase", "order", "checkout", "pay", "confirm", "verify",
	"update", "login", "log in", "sign in", "sign up", "signup", "register",
	"download", "upgrade", "continue", "next", "open", "submit", "apply",
	"approve", "activate", "subscribe");

static auto is_service_link_tag(const html_tag &tag, const rspamd_url &url) -> bool
{
	if (tag.flags & (FL_XML | FL_VIRTUAL | FL_COMMENT | FL_IGNORE | CM_HEAD)) {
		return true;
	}

	switch (tag.id) {
	case Tag_LINK:
	case Tag_SCRIPT:
	case Tag_STYLE:
	case Tag_META:
	case Tag_BASE:
	case Tag_IMG:
		return true;
	default:
		break;
	}

	if (tag.block && !tag.block->is_visible()) {
		return true;
	}

	if (url.flags & RSPAMD_URL_FLAG_IMAGE) {
		return true;
	}

	if (tag.id == Tag_A) {
		if (optional_attr_contains_any(tag.find_rel(), service_rel_tokens, false)) {
			return true;
		}
		if (tag.parent && (tag.parent->flags & CM_HEAD)) {
			return true;
		}
	}

	return false;
}

static auto compute_semantic_base_score(const html_tag &tag, const rspamd_url &url) -> float
{
	switch (tag.id) {
	case Tag_BUTTON:
		return 0.9f;
	case Tag_INPUT: {
		float base = 0.35f;
		if (auto type_comp = tag.find_component<html_component_type>()) {
			auto lowered = to_lower_ascii(trim_ascii(type_comp.value()->get_string_value()));
			if (lowered == "submit" || lowered == "button" || lowered == "send") {
				base = 0.85f;
			}
			else if (lowered == "image") {
				base = 0.75f;
			}
			else if (lowered == "reset") {
				base = 0.25f;
			}
		}
		return base;
	}
	case Tag_FORM:
		return 0.8f;
	case Tag_A: {
		float base = 0.35f;
		if (optional_attr_contains_any(tag.find_class(), buttonish_class_tokens, true) ||
			optional_attr_contains_any(tag.find_id(), buttonish_class_tokens, true)) {
			base = 0.75f;
		}
		if (auto role_comp = tag.find_component<html_component_role>()) {
			auto lowered = to_lower_ascii(trim_ascii(role_comp.value()->value));
			if (lowered == "button" || lowered == "tab" || lowered == "menuitem") {
				base = std::max(base, 0.7f);
			}
		}
		if (url.protocol == PROTOCOL_MAILTO) {
			base = std::min(base, 0.4f);
		}
		return base;
	}
	case Tag_AREA:
		return 0.3f;
	default:
		if (tag.flags & FL_HREF) {
			return 0.2f;
		}
		break;
	}

	return 0.0f;
}

static auto compute_visual_bonus(const html_tag &tag) -> float
{
	if (!tag.block || !tag.block->is_visible()) {
		return 0.0f;
	}

	float bonus = 0.0f;
	const auto &block = *tag.block;

	switch (block.display) {
	case css::css_display_value::DISPLAY_BLOCK:
		bonus += 0.12f;
		break;
	case css::css_display_value::DISPLAY_TABLE_ROW:
		bonus += 0.05f;
		break;
	default:
		break;
	}

	if (block.width > 0 && block.height > 0) {
		const auto area = static_cast<int>(block.width) * static_cast<int>(block.height);
		if (area >= 6000) {
			bonus += 0.2f;
		}
		else if (area >= 2000) {
			bonus += 0.12f;
		}
		else if (area >= 400) {
			bonus += 0.06f;
		}
	}

	if (block.font_size >= 16) {
		bonus += 0.08f;
	}
	else if (block.font_size >= 13) {
		bonus += 0.04f;
	}

	return bonus;
}

static auto compute_text_bonus(std::string_view text_lower) -> float
{
	if (text_lower.empty()) {
		return 0.0f;
	}

	float bonus = 0.0f;
	for (auto kw: cta_keywords) {
		if (text_lower.find(kw) != std::string_view::npos) {
			bonus += 0.18f;
			break;
		}
	}

	if (text_lower.find('!') != std::string_view::npos) {
		bonus += 0.03f;
	}

	if (text_lower.size() <= 18 && text_lower.size() >= 3) {
		bonus += 0.04f;
	}

	return bonus;
}

static auto compute_penalty(const html_tag &tag,
							const rspamd_url &url,
							std::string_view text_lower,
							std::string_view text_original) -> float
{
	float penalty = 0.0f;

	if (text_lower.empty()) {
		penalty += 0.35f;
	}
	else {
		unsigned int alpha = 0;
		unsigned int graph = 0;
		for (auto ch: text_lower) {
			if (g_ascii_isspace(static_cast<gchar>(ch))) {
				continue;
			}
			graph++;
			if (g_ascii_isalpha(static_cast<gchar>(ch))) {
				alpha++;
			}
		}
		if (graph > 0 && alpha == 0) {
			penalty += 0.25f;
		}
		if (text_original.size() > 80) {
			penalty += 0.1f;
		}
	}

	if (tag.block) {
		const auto &block = *tag.block;
		if (block.width > 0 && block.height > 0) {
			const auto area = static_cast<int>(block.width) * static_cast<int>(block.height);
			if (area <= 64) {
				penalty += 0.25f;
			}
			else if (area <= 150) {
				penalty += 0.15f;
			}
		}
		if (block.font_size > 0 && block.font_size <= 9) {
			penalty += 0.08f;
		}
		if (block.is_transparent()) {
			penalty += 0.2f;
		}
	}

	if (optional_attr_contains_any(tag.find_class(), negative_context_tokens, true) ||
		optional_attr_contains_any(tag.find_id(), negative_context_tokens, true)) {
		penalty += 0.2f;
	}

	if (url.flags & RSPAMD_URL_FLAG_INVISIBLE) {
		penalty += 0.3f;
	}

	if (url.protocol == PROTOCOL_MAILTO || url.protocol == PROTOCOL_FTP) {
		penalty += 0.05f;
	}

	return penalty;
}

static auto compute_cta_weight(const html_tag &tag,
							   const rspamd_url &url,
							   const html_content &hc) -> float
{
	if (is_service_link_tag(tag, url)) {
		return 0.0f;
	}

	if (tag_is_effectively_hidden(&tag)) {
		return 0.0f;
	}

	float base = compute_semantic_base_score(tag, url);
	if (base <= 0.0f) {
		return 0.0f;
	}

	auto label = get_cta_label(tag, hc);
	std::string_view label_view = trim_ascii(label);
	std::string lowered = to_lower_ascii(label_view);

	float visual = compute_visual_bonus(tag);
	float text_bonus = compute_text_bonus(lowered);
	float order_bonus = 0.0f;
	if (url.order == 0) {
		order_bonus = 0.1f;
	}
	else {
		order_bonus = std::max(0.0f, 0.06f / (1.0f + static_cast<float>(url.order)));
	}
	if (url.ext && url.ext->linked_url && url.ext->linked_url != &url) {
		order_bonus += 0.12f;
	}
	float penalty = compute_penalty(tag, url, lowered, label_view);

	float weight = base + visual + text_bonus + order_bonus - penalty;
	if (weight < 0.0f) {
		weight = 0.0f;
	}
	else if (weight > 1.0f) {
		weight = 1.0f;
	}

	return weight;
}

}// namespace

void html_compute_cta_weights(html_content &hc)
{
	hc.url_button_weights.clear();

	for (const auto &tag_ptr: hc.all_tags) {
		const auto &tag = *tag_ptr;
		if (!std::holds_alternative<rspamd_url *>(tag.extra)) {
			continue;
		}

		auto *url = std::get<rspamd_url *>(tag.extra);
		if (!url) {
			continue;
		}

		float weight = compute_cta_weight(tag, *url, hc);
		if (weight <= 0.0f) {
			continue;
		}

		auto it = hc.url_button_weights.find(url);
		if (it == hc.url_button_weights.end()) {
			hc.url_button_weights.emplace(url, weight);
		}
		else {
			it->second = std::max(it->second, weight);
		}
	}
}

}// namespace rspamd::html

extern "C" {

void rspamd_html_process_cta_urls(struct rspamd_mime_text_part *text_part,
								  struct rspamd_task *task,
								  unsigned int max_cta)
{
	using namespace rspamd::html;

	if (!text_part || !text_part->html || !text_part->mime_part || !text_part->mime_part->urls) {
		return;
	}
	auto *part_urls = text_part->mime_part->urls;
	unsigned int i;
	rspamd_url *u;

	auto *heap_ptr = rspamd_mempool_alloc_type(task->task_pool, rspamd_html_heap_storage_t);
	rspamd_heap_init(rspamd_html_heap_storage, heap_ptr);
	text_part->cta_urls = heap_ptr;
	rspamd_mempool_add_destructor(task->task_pool, [](void *ptr) {
                auto *h = static_cast<rspamd_html_heap_storage_t *>(ptr);
                rspamd_heap_destroy(rspamd_html_heap_storage, h); }, heap_ptr);
	PTR_ARRAY_FOREACH(part_urls, i, u)
	{
		if (!u) continue;
		if (!(u->protocol == PROTOCOL_HTTP || u->protocol == PROTOCOL_HTTPS)) continue;
		if (u->flags & RSPAMD_URL_FLAG_INVISIBLE) continue;
		if (u->flags & RSPAMD_URL_FLAG_IMAGE) continue;

		/* Use button_weight to filter CTA URLs vs technical URLs
         * Technical tags like <link rel>, <script src> have weight=0
         * Only actual content URLs (buttons, links) have weight > 0
         */
		float weight = rspamd_html_url_button_weight(text_part->html, u);

		if (weight > 0.0) {
			if (rspamd_heap_size(rspamd_html_heap_storage, heap_ptr) < max_cta) {
				rspamd_html_cta_entry entry = {
					.pri = static_cast<unsigned int>(weight * -CTA_WEIGHT_SCALE),
					.idx = 0,
					.url = u,
					.weight = weight};
				rspamd_heap_push_safe(rspamd_html_heap_storage, heap_ptr, &entry, heap_error);
			}
			else {
				auto *min = rspamd_heap_index(rspamd_html_heap_storage, heap_ptr, 0);
				if (weight > min->weight) {
					rspamd_heap_pop(rspamd_html_heap_storage, heap_ptr);
					rspamd_html_cta_entry entry = {
						.pri = static_cast<unsigned int>(weight * -CTA_WEIGHT_SCALE),
						.idx = 0,
						.url = u,
						.weight = weight};
					rspamd_heap_push_safe(rspamd_html_heap_storage, heap_ptr, &entry, heap_error);
				}
			}
		}
	}

	return;

heap_error:
	rspamd_heap_destroy(rspamd_html_heap_storage, heap_ptr);
	text_part->cta_urls = nullptr;
}

}// extern "C"
