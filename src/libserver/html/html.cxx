/*-
 * Copyright 2016 Vsevolod Stakhov
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
#include "util.h"
#include "message.h"
#include "html.h"
#include "html_tags.h"
#include "html_block.hxx"
#include "html.hxx"
#include "libserver/css/css_value.hxx"
#include "libserver/css/css.hxx"

#include "url.h"
#include "contrib/libucl/khash.h"
#include "libmime/images.h"
#include "libutil/cxx/utf8_util.h"

#include "html_tag_defs.hxx"
#include "html_entities.hxx"
#include "html_tag.hxx"
#include "html_url.hxx"

#include <vector>
#include <frozen/unordered_map.h>
#include <frozen/string.h>
#include <fmt/core.h>

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"


#include <unicode/uversion.h>

namespace rspamd::html {

static const guint max_tags = 8192; /* Ignore tags if this maximum is reached */

static const html_tags_storage html_tags_defs;

auto html_components_map = frozen::make_unordered_map<frozen::string, html_component_type>(
		{
				{"name", html_component_type::RSPAMD_HTML_COMPONENT_NAME},
				{"href", html_component_type::RSPAMD_HTML_COMPONENT_HREF},
				{"src", html_component_type::RSPAMD_HTML_COMPONENT_HREF},
				{"action", html_component_type::RSPAMD_HTML_COMPONENT_HREF},
				{"color", html_component_type::RSPAMD_HTML_COMPONENT_COLOR},
				{"bgcolor", html_component_type::RSPAMD_HTML_COMPONENT_BGCOLOR},
				{"style", html_component_type::RSPAMD_HTML_COMPONENT_STYLE},
				{"class", html_component_type::RSPAMD_HTML_COMPONENT_CLASS},
				{"width", html_component_type::RSPAMD_HTML_COMPONENT_WIDTH},
				{"height", html_component_type::RSPAMD_HTML_COMPONENT_HEIGHT},
				{"size", html_component_type::RSPAMD_HTML_COMPONENT_SIZE},
				{"rel", html_component_type::RSPAMD_HTML_COMPONENT_REL},
				{"alt", html_component_type::RSPAMD_HTML_COMPONENT_ALT},
				{"id", html_component_type::RSPAMD_HTML_COMPONENT_ID},
		});

#define msg_debug_html(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_html_log_id, "html", pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(html)

static auto
html_check_balance(struct html_content *hc,
				   struct html_tag *tag,
				   struct html_tag *parent,
				   std::vector<html_tag *> &tags_stack,
				   goffset tag_start_offset,
				   goffset tag_end_offset) -> bool
{

	auto calculate_content_length = [tag_start_offset](html_tag *t) {
		auto opening_content_offset = t->content_offset;

		if (opening_content_offset <= tag_start_offset) {
			t->content_length = tag_start_offset - opening_content_offset;
		}
		else {
			t->content_length = 0;
		}
	};

	auto balance_tag = [&]() -> void {
		auto it = tags_stack.rbegin();

		for (auto end_it = tags_stack.rend(); it != end_it; ++it) {
			if ((*it)->id == tag->id && !((*it)->flags & FL_CLOSING)) {
				break;
			}
			/* Insert a virtual closing tag for all tags that are not closed */
			auto &&vtag = std::make_unique<html_tag>();
			vtag->id = (*it)->id;
			vtag->flags = FL_VIRTUAL|FL_CLOSING;
			vtag->tag_start = tag->tag_start;
			vtag->content_offset = tag->content_offset;
			vtag->content_length = 0;
			vtag->parent = (*it)->parent;
			calculate_content_length(*it);
			(*it)->flags |= FL_CLOSED;
			hc->all_tags.emplace_back(std::move(vtag));
		}

		/* Remove tags */
		tags_stack.erase(it.base(), std::end(tags_stack));
	};

	if (tag->flags & FL_CLOSING) {
		if (!tags_stack.empty()) {
			auto *last_tag = tags_stack.back();

			if (last_tag->id == tag->id && !(last_tag->flags & FL_CLOSED)) {
				last_tag->flags |= FL_CLOSED;

				calculate_content_length(last_tag);
				tags_stack.pop_back();
				/* All good */
				return true;
			}
			else {
				balance_tag();

				return false;
			}
		}
		else {
			/*
			 * We have no opening tags in the stack, so we need to assume that there
			 * is an opening tag at the beginning of the document.
			 * There are two possibilities:
			 *
			 * 1) We have some block tag in hc->all_tags;
			 * 2) We have no tags
			 */

			if (hc->all_tags.empty()) {
				auto &&vtag = std::make_unique<html_tag>();
				vtag->id = tag->id;
				vtag->flags = FL_VIRTUAL|FL_CLOSED;
				vtag->tag_start = 0;
				vtag->content_offset = 0;
				calculate_content_length(vtag.get());


				if (!hc->root_tag) {
					hc->root_tag = vtag.get();
				}
				else {
					vtag->parent = hc->root_tag;
				}
				hc->all_tags.emplace_back(std::move(vtag));
			}
			else {
				auto found_closing = std::find_if(hc->all_tags.rbegin(),
						hc->all_tags.rend(),
						[&](const auto &t) {
							constexpr const auto expect_flags = FL_BLOCK|FL_CLOSING;
							return (t->flags & expect_flags) == (expect_flags) &&
									t.get() != tag &&
									t->parent != nullptr;
						});

				if (found_closing != hc->all_tags.rend()) {
					auto *closing_tag = (*found_closing).get();
					auto &&vtag = std::make_unique<html_tag>();
					vtag->id = tag->id;
					vtag->flags = FL_VIRTUAL|FL_CLOSED;
					vtag->tag_start = closing_tag->content_offset - 1;
					vtag->content_offset = vtag->tag_start + 1;
					vtag->parent = closing_tag->parent;
					vtag->content_length = tag->tag_start - vtag->content_offset;
					hc->all_tags.emplace_back(std::move(vtag));
				}
				else {
					auto &&vtag = std::make_unique<html_tag>();
					vtag->id = tag->id;
					vtag->flags = FL_VIRTUAL|FL_CLOSED;
					vtag->tag_start = 0;
					vtag->content_offset = 0;
					calculate_content_length(vtag.get());


					if (!hc->root_tag) {
						hc->root_tag = vtag.get();
					}
					else {
						vtag->parent = hc->root_tag;
					}
					hc->all_tags.emplace_back(std::move(vtag));
				}
			}
		}

		return false;
	}

	/* Misuse */
	RSPAMD_UNREACHABLE;
}

static auto
html_process_tag(rspamd_mempool_t *pool,
				 struct html_content *hc,
				 struct html_tag *tag,
				 std::vector<html_tag *> &tags_stack,
				 goffset tag_start_offset,
				 goffset tag_end_offset) -> bool
{
	struct html_tag *parent;

	if (hc->total_tags > rspamd::html::max_tags) {
		hc->flags |= RSPAMD_HTML_FLAG_TOO_MANY_TAGS;
	}

	if (tag->id == -1) {
		/* Ignore unknown tags */
		hc->total_tags++;
		return false;
	}


	if (tags_stack.empty()) {
		parent = hc->root_tag;
	}
	else {
		parent = tags_stack.back();
	}

	tag->parent = parent;

	if (!(tag->flags & (CM_EMPTY))) {
		/* Block tag */
		if ((tag->flags & (FL_CLOSING | FL_CLOSED))) {
			/* Closed block tag */
			if (parent == nullptr) {
				msg_debug_html ("bad parent node");
				return false;
			}

			if (!html_check_balance(hc, tag, parent, tags_stack,
					tag_start_offset, tag_end_offset)) {
				msg_debug_html (
						"mark part as unbalanced as it has not pairable closing tags");
				hc->flags |= RSPAMD_HTML_FLAG_UNBALANCED;
			}
		}
		else {
			/* Opening block tag */
			if (parent) {
				if ((parent->flags & FL_IGNORE)) {
					tag->flags |= FL_IGNORE;
				}

				if (!(tag->flags & FL_CLOSED) &&
					(parent->flags & CM_EMPTY)) {
					/* We likely have some bad nesting */
					if (parent->id == tag->id) {
						/* Something like <a>bla<a>foo... */
						hc->flags |= RSPAMD_HTML_FLAG_UNBALANCED;
						tag->parent = parent->parent;

						if (hc->total_tags < rspamd::html::max_tags) {
							parent->children.push_back(tag);
							tags_stack.push_back(tag);
							hc->total_tags++;
						}

						return true;
					}
				}

				if (hc->total_tags < rspamd::html::max_tags) {
					parent->children.push_back(tag);

					if ((tag->flags & FL_CLOSED) == 0) {
						tags_stack.push_back(tag);
					}

					hc->total_tags++;
				}
			}
			else {
				hc->root_tag = tag;
				if (hc->total_tags < rspamd::html::max_tags) {
					if ((tag->flags & FL_CLOSED) == 0) {
						tags_stack.push_back(tag);
					}

					hc->total_tags++;
				}
			}

			if (tag->flags & (CM_HEAD | CM_UNKNOWN | FL_IGNORE)) {
				tag->flags |= FL_IGNORE;

				return false;
			}
		}
	}
	else {
		/* Inline tag */
		if (parent) {
			if (hc->total_tags < rspamd::html::max_tags) {
				parent->children.push_back(tag);

				hc->total_tags++;
			}
			if ((parent->flags & (CM_HEAD | CM_UNKNOWN | FL_IGNORE))) {
				tag->flags |= FL_IGNORE;

				return false;
			}
		}
	}

	return true;
}

auto
html_component_from_string(const std::string_view &st) -> std::optional<html_component_type>
{
	auto known_component_it = html_components_map.find(st);

	if (known_component_it != html_components_map.end()) {
		return known_component_it->second;
	}
	else {
		return std::nullopt;
	}
}

static auto
find_tag_component_name(rspamd_mempool_t *pool,
					const gchar *begin,
					const gchar *end) -> std::optional<html_component_type>
{
	if (end <= begin) {
		return std::nullopt;
	}

	auto *p = rspamd_mempool_alloc_buffer(pool, end - begin);
	memcpy(p, begin, end - begin);
	auto len = decode_html_entitles_inplace(p, end - begin);
	len = rspamd_str_lc(p, len);
	auto known_component_it = html_components_map.find({p, len});

	if (known_component_it != html_components_map.end()) {
		return known_component_it->second;
	}
	else {
		return std::nullopt;
	}
}

struct tag_content_parser_state {
	int cur_state = 0;
	const char *saved_p = nullptr;
	std::optional<html_component_type> cur_component;

	void reset()
	{
		cur_state = 0;
		saved_p = nullptr;
		cur_component = std::nullopt;
	}
};

static inline void
html_parse_tag_content(rspamd_mempool_t *pool,
					   struct html_content *hc,
					   struct html_tag *tag,
					   const char *in,
					   struct tag_content_parser_state &parser_env)
{
	enum tag_parser_state {
		parse_start = 0,
		parse_name,
		parse_attr_name,
		parse_equal,
		parse_start_dquote,
		parse_dqvalue,
		parse_end_dquote,
		parse_start_squote,
		parse_sqvalue,
		parse_end_squote,
		parse_value,
		spaces_after_name,
		spaces_before_eq,
		spaces_after_eq,
		spaces_after_param,
		ignore_bad_tag
	} state;
	gboolean store = FALSE;

	state = static_cast<enum tag_parser_state>(parser_env.cur_state);

	/*
	 * Stores tag component if it doesn't exist, performing copy of the
	 * value + decoding of the entities
	 * Parser env is set to clear the current html attribute fields (saved_p and
	 * cur_component)
	 */
	auto store_tag_component = [&]() -> void {
		if (parser_env.saved_p != nullptr && parser_env.cur_component &&
			in > parser_env.saved_p) {

			/* We ignore repeated attributes */
				auto sz = (std::size_t)(in - parser_env.saved_p);
				auto *s = rspamd_mempool_alloc_buffer(pool, sz);
				memcpy(s, parser_env.saved_p, sz);
				sz = rspamd_html_decode_entitles_inplace(s, in - parser_env.saved_p);
				tag->parameters.emplace_back(parser_env.cur_component.value(),
						std::string_view{s, sz});
		}

		parser_env.saved_p = nullptr;
		parser_env.cur_component = std::nullopt;
	};

	switch (state) {
	case parse_start:
		if (!g_ascii_isalpha (*in) && !g_ascii_isspace (*in)) {
			hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
			state = ignore_bad_tag;
			tag->id = -1;
			tag->flags |= FL_BROKEN;
		}
		else if (g_ascii_isalpha (*in)) {
			state = parse_name;
			tag->name = std::string_view{in, 0};
		}
		break;

	case parse_name:
		if (g_ascii_isspace (*in) || *in == '>' || *in == '/') {
			const auto *start = tag->name.begin();
			g_assert (in >= start);

			if (*in == '/') {
				tag->flags |= FL_CLOSED;
			}

			tag->name = std::string_view{start, (std::size_t)(in - start)};

			if (tag->name.empty()) {
				hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
				tag->id = -1;
				tag->flags |= FL_BROKEN;
				state = ignore_bad_tag;
			}
			else {
				/*
				 * Copy tag name to the temporary buffer for modifications
				 */
				auto *s = rspamd_mempool_alloc_buffer(pool, tag->name.size() + 1);
				rspamd_strlcpy(s, tag->name.data(), tag->name.size() + 1);
				auto nsize = rspamd_html_decode_entitles_inplace(s,
						tag->name.size());
				nsize =  rspamd_str_lc_utf8(s, nsize);
				tag->name = std::string_view{s, nsize};

				const auto *tag_def = rspamd::html::html_tags_defs.by_name(tag->name);

				if (tag_def == nullptr) {
					hc->flags |= RSPAMD_HTML_FLAG_UNKNOWN_ELEMENTS;
					tag->id = -1;
				}
				else {
					tag->id = tag_def->id;
					tag->flags = tag_def->flags;
				}

				state = spaces_after_name;
			}
		}
		break;

	case parse_attr_name:
		if (parser_env.saved_p == nullptr) {
			state = ignore_bad_tag;
		}
		else {
			const auto *attr_name_end = in;

			if (*in == '=') {
				state = parse_equal;
			}
			else if (*in == '"') {
				/* No equal or something sane but we have quote character */
				state = parse_start_dquote;
				attr_name_end = in - 1;

				while (attr_name_end > parser_env.saved_p) {
					if (!g_ascii_isalnum (*attr_name_end)) {
						attr_name_end--;
					}
					else {
						break;
					}
				}

				/* One character forward to obtain length */
				attr_name_end++;
			}
			else if (g_ascii_isspace (*in)) {
				state = spaces_before_eq;
			}
			else if (*in == '/') {
				tag->flags |= FL_CLOSED;
			}
			else if (!g_ascii_isgraph (*in)) {
				state = parse_value;
				attr_name_end = in - 1;

				while (attr_name_end > parser_env.saved_p) {
					if (!g_ascii_isalnum (*attr_name_end)) {
						attr_name_end--;
					}
					else {
						break;
					}
				}

				/* One character forward to obtain length */
				attr_name_end++;
			}
			else {
				return;
			}

			parser_env.cur_component = find_tag_component_name(pool,
					parser_env.saved_p,
					attr_name_end);

			if (!parser_env.cur_component) {
				/* Ignore unknown params */
				parser_env.saved_p = nullptr;
			}
			else if (state == parse_value) {
				parser_env.saved_p = in + 1;
			}
		}

		break;

	case spaces_after_name:
		if (!g_ascii_isspace (*in)) {
			parser_env.saved_p = in;

			if (*in == '/') {
				tag->flags |= FL_CLOSED;
			}
			else if (*in != '>') {
				state = parse_attr_name;
			}
		}
		break;

	case spaces_before_eq:
		if (*in == '=') {
			state = parse_equal;
		}
		else if (!g_ascii_isspace (*in)) {
			/*
			 * HTML defines that crap could still be restored and
			 * calculated somehow... So we have to follow this stupid behaviour
			 */
			/*
			 * TODO: estimate what insane things do email clients in each case
			 */
			if (*in == '>') {
				/*
				 * Attribtute name followed by end of tag
				 * Should be okay (empty attribute). The rest is handled outside
				 * this automata.
				 */

			}
			else if (*in == '"' || *in == '\'') {
				/* Attribute followed by quote... Missing '=' ? Dunno, need to test */
				hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
				tag->flags |= FL_BROKEN;
				state = ignore_bad_tag;
			}
			else {
				/*
				 * Just start another attribute ignoring an empty attributes for
				 * now. We don't use them in fact...
				 */
				state = parse_attr_name;
				parser_env.saved_p = in;
			}
		}
		break;

	case spaces_after_eq:
		if (*in == '"') {
			state = parse_start_dquote;
		}
		else if (*in == '\'') {
			state = parse_start_squote;
		}
		else if (!g_ascii_isspace (*in)) {
			if (parser_env.saved_p != nullptr) {
				/* We need to save this param */
				parser_env.saved_p = in;
			}
			state = parse_value;
		}
		break;

	case parse_equal:
		if (g_ascii_isspace (*in)) {
			state = spaces_after_eq;
		}
		else if (*in == '"') {
			state = parse_start_dquote;
		}
		else if (*in == '\'') {
			state = parse_start_squote;
		}
		else {
			if (parser_env.saved_p != nullptr) {
				/* We need to save this param */
				parser_env.saved_p = in;
			}
			state = parse_value;
		}
		break;

	case parse_start_dquote:
		if (*in == '"') {
			if (parser_env.saved_p != nullptr) {
				/* We have an empty attribute value */
				parser_env.saved_p = nullptr;
			}
			state = spaces_after_param;
		}
		else {
			if (parser_env.saved_p != nullptr) {
				/* We need to save this param */
				parser_env.saved_p = in;
			}
			state = parse_dqvalue;
		}
		break;

	case parse_start_squote:
		if (*in == '\'') {
			if (parser_env.saved_p != nullptr) {
				/* We have an empty attribute value */
				parser_env.saved_p = nullptr;
			}
			state = spaces_after_param;
		}
		else {
			if (parser_env.saved_p != nullptr) {
				/* We need to save this param */
				parser_env.saved_p = in;
			}
			state = parse_sqvalue;
		}
		break;

	case parse_dqvalue:
		if (*in == '"') {
			store = TRUE;
			state = parse_end_dquote;
		}

		if (store) {
			store_tag_component();
		}
		break;

	case parse_sqvalue:
		if (*in == '\'') {
			store = TRUE;
			state = parse_end_squote;
		}
		if (store) {
			store_tag_component();
		}
		break;

	case parse_value:
		if (*in == '/' && *(in + 1) == '>') {
			tag->flags |= FL_CLOSED;
			store = TRUE;
		}
		else if (g_ascii_isspace (*in) || *in == '>' || *in == '"') {
			store = TRUE;
			state = spaces_after_param;
		}

		if (store) {
			store_tag_component();
		}
		break;

	case parse_end_dquote:
	case parse_end_squote:
		if (g_ascii_isspace (*in)) {
			state = spaces_after_param;
		}
		else if (*in == '/' && *(in + 1) == '>') {
			tag->flags |= FL_CLOSED;
		}
		else {
			/* No space, proceed immediately to the attribute name */
			state = parse_attr_name;
			parser_env.saved_p = in;
		}
		break;

	case spaces_after_param:
		if (!g_ascii_isspace (*in)) {
			if (*in == '/' && *(in + 1) == '>') {
				tag->flags |= FL_CLOSED;
			}

			state = parse_attr_name;
			parser_env.saved_p = in;
		}
		break;

	case ignore_bad_tag:
		break;
	}

	parser_env.cur_state = state;
}

static auto
html_process_url_tag(rspamd_mempool_t *pool,
					 struct html_tag *tag,
					 struct html_content *hc) -> std::optional<struct rspamd_url *>
{
	auto found_href_maybe = tag->find_component(html_component_type::RSPAMD_HTML_COMPONENT_HREF);

	if (found_href_maybe) {
		/* Check base url */
		auto &href_value = found_href_maybe.value();

		if (hc && hc->base_url && href_value.size() > 2) {
			/*
			 * Relative url cannot start from the following:
			 * schema://
			 * data:
			 * slash
			 */

			if (rspamd_substring_search(href_value.data(), href_value.size(), "://", 3) == -1) {

				if (href_value.size() >= sizeof("data:") &&
					g_ascii_strncasecmp(href_value.data(), "data:", sizeof("data:") - 1) == 0) {
					/* Image data url, never insert as url */
					return std::nullopt;
				}

				/* Assume relative url */
				auto need_slash = false;

				auto orig_len = href_value.size();
				auto len = orig_len + hc->base_url->urllen;

				if (hc->base_url->datalen == 0) {
					need_slash = true;
					len++;
				}

				auto *buf = rspamd_mempool_alloc_buffer(pool, len + 1);
				auto nlen = (std::size_t)rspamd_snprintf(buf, len + 1,
						"%*s%s%*s",
						(int)hc->base_url->urllen, hc->base_url->string,
						need_slash ? "/" : "",
						(gint)orig_len, href_value.data());
				href_value = {buf, nlen};
			}
			else if (href_value[0] == '/' && href_value[1] != '/') {
				/* Relative to the hostname */
				auto orig_len = href_value.size();
				auto len = orig_len + hc->base_url->hostlen + hc->base_url->protocollen +
					   3 /* for :// */;
				auto *buf = rspamd_mempool_alloc_buffer(pool, len + 1);
				auto nlen = (std::size_t)rspamd_snprintf(buf, len + 1, "%*s://%*s/%*s",
						(int)hc->base_url->protocollen, hc->base_url->string,
						(int)hc->base_url->hostlen, rspamd_url_host_unsafe (hc->base_url),
						(gint)orig_len, href_value.data());
				href_value = {buf, nlen};
			}
		}

		auto url = html_process_url(pool, href_value);

		if (url && std::holds_alternative<std::monostate>(tag->extra)) {
			tag->extra = url.value();
		}

		return url;
	}

	return std::nullopt;
}

struct rspamd_html_url_query_cbd {
	rspamd_mempool_t *pool;
	khash_t (rspamd_url_hash) *url_set;
	struct rspamd_url *url;
	GPtrArray *part_urls;
};

static gboolean
html_url_query_callback(struct rspamd_url *url, gsize start_offset,
							   gsize end_offset, gpointer ud)
{
	struct rspamd_html_url_query_cbd *cbd =
			(struct rspamd_html_url_query_cbd *) ud;
	rspamd_mempool_t *pool;

	pool = cbd->pool;

	if (url->protocol == PROTOCOL_MAILTO) {
		if (url->userlen == 0) {
			return FALSE;
		}
	}

	msg_debug_html ("found url %s in query of url"
					" %*s", url->string,
			cbd->url->querylen, rspamd_url_query_unsafe(cbd->url));

	url->flags |= RSPAMD_URL_FLAG_QUERY;

	if (rspamd_url_set_add_or_increase(cbd->url_set, url, false)
		&& cbd->part_urls) {
		g_ptr_array_add(cbd->part_urls, url);
	}

	return TRUE;
}

static void
html_process_query_url(rspamd_mempool_t *pool, struct rspamd_url *url,
					   khash_t (rspamd_url_hash) *url_set,
					   GPtrArray *part_urls)
{
	if (url->querylen > 0) {
		struct rspamd_html_url_query_cbd qcbd;

		qcbd.pool = pool;
		qcbd.url_set = url_set;
		qcbd.url = url;
		qcbd.part_urls = part_urls;

		rspamd_url_find_multiple(pool,
				rspamd_url_query_unsafe (url), url->querylen,
				RSPAMD_URL_FIND_ALL, NULL,
				html_url_query_callback, &qcbd);
	}

	if (part_urls) {
		g_ptr_array_add(part_urls, url);
	}
}

static auto
html_process_data_image(rspamd_mempool_t *pool,
						struct html_image *img,
						std::string_view input) -> void
{
	/*
	 * Here, we do very basic processing of the data:
	 * detect if we have something like: `data:image/xxx;base64,yyyzzz==`
	 * We only parse base64 encoded data.
	 * We ignore content type so far
	 */
	struct rspamd_image *parsed_image;
	const gchar *semicolon_pos = input.data(),
			*end = input.data() + input.size();

	if ((semicolon_pos = (const gchar *)memchr(semicolon_pos, ';', end - semicolon_pos)) != NULL) {
		if (end - semicolon_pos > sizeof("base64,")) {
			if (memcmp(semicolon_pos + 1, "base64,", sizeof("base64,") - 1) == 0) {
				const gchar *data_pos = semicolon_pos + sizeof("base64,");
				gchar *decoded;
				gsize encoded_len = end - data_pos, decoded_len;
				rspamd_ftok_t inp;

				decoded_len = (encoded_len / 4 * 3) + 12;
				decoded = rspamd_mempool_alloc_buffer(pool, decoded_len);
				rspamd_cryptobox_base64_decode(data_pos, encoded_len,
						reinterpret_cast<guchar *>(decoded), &decoded_len);
				inp.begin = decoded;
				inp.len = decoded_len;

				parsed_image = rspamd_maybe_process_image(pool, &inp);

				if (parsed_image) {
					msg_debug_html ("detected %s image of size %ud x %ud in data url",
							rspamd_image_type_str(parsed_image->type),
							parsed_image->width, parsed_image->height);
					img->embedded_image = parsed_image;
				}
			}
		}
		else {
			/* Nothing useful */
			return;
		}
	}
}

static void
html_process_img_tag(rspamd_mempool_t *pool,
					 struct html_tag *tag,
					 struct html_content *hc,
					 khash_t (rspamd_url_hash) *url_set,
					 GPtrArray *part_urls)
{
	struct html_image *img;

	img = rspamd_mempool_alloc0_type (pool, struct html_image);
	img->tag = tag;

	for (const auto &param : tag->parameters) {

		if (param.type == html_component_type::RSPAMD_HTML_COMPONENT_HREF) {
			/* Check base url */
			const auto &href_value = param.value;

			if (href_value.size() > 0) {
				rspamd_ftok_t fstr;
				fstr.begin = href_value.data();
				fstr.len = href_value.size();
				img->src = rspamd_mempool_ftokdup (pool, &fstr);

				if (href_value.size() > sizeof("cid:") - 1 && memcmp(href_value.data(),
						"cid:", sizeof("cid:") - 1) == 0) {
					/* We have an embedded image */
					img->flags |= RSPAMD_HTML_FLAG_IMAGE_EMBEDDED;
				}
				else {
					if (href_value.size() > sizeof("data:") - 1 && memcmp(href_value.data(),
							"data:", sizeof("data:") - 1) == 0) {
						/* We have an embedded image in HTML tag */
						img->flags |=
								(RSPAMD_HTML_FLAG_IMAGE_EMBEDDED | RSPAMD_HTML_FLAG_IMAGE_DATA);
						html_process_data_image(pool, img, href_value);
						hc->flags |= RSPAMD_HTML_FLAG_HAS_DATA_URLS;
					}
					else {
						img->flags |= RSPAMD_HTML_FLAG_IMAGE_EXTERNAL;
						if (img->src) {

							std::string_view cpy{href_value};
							auto maybe_url = html_process_url(pool, cpy);

							if (maybe_url) {
								img->url = maybe_url.value();
								struct rspamd_url *existing;

								img->url->flags |= RSPAMD_URL_FLAG_IMAGE;
								existing = rspamd_url_set_add_or_return(url_set, img->url);

								if (existing != img->url) {
									/*
									 * We have some other URL that could be
									 * found, e.g. from another part. However,
									 * we still want to set an image flag on it
									 */
									existing->flags |= img->url->flags;
									existing->count++;
								}
								else if (part_urls) {
									/* New url */
									g_ptr_array_add(part_urls, img->url);
								}
							}
						}
					}
				}
			}
		}


		if (param.type == html_component_type::RSPAMD_HTML_COMPONENT_HEIGHT) {
			unsigned long val;

			rspamd_strtoul(param.value.data(), param.value.size(), &val);
			img->height = val;
		}

		if (param.type == html_component_type::RSPAMD_HTML_COMPONENT_WIDTH) {
			unsigned long val;

			rspamd_strtoul(param.value.data(), param.value.size(), &val);
			img->width = val;
		}

		/* TODO: rework to css at some time */
		if (param.type == html_component_type::RSPAMD_HTML_COMPONENT_STYLE) {
			if (img->height == 0) {
				auto style_st = param.value;
				auto pos = rspamd_substring_search_caseless(style_st.data(),
						style_st.size(),
						"height", sizeof("height") - 1);
				if (pos != -1) {
					auto substr = style_st.substr(pos + sizeof("height") - 1);

					for (auto i = 0; i < substr.size(); i++) {
						auto t = substr[i];
						if (g_ascii_isdigit (t)) {
							unsigned long val;
							rspamd_strtoul(substr.data(),
									substr.size(), &val);
							img->height = val;
							break;
						}
						else if (!g_ascii_isspace (t) && t != '=' && t != ':') {
							/* Fallback */
							break;
						}
					}
				}
			}
			if (img->width == 0) {
				auto style_st = param.value;
				auto pos = rspamd_substring_search_caseless(style_st.data(),
						style_st.size(),
						"width", sizeof("width") - 1);
				if (pos != -1) {
					auto substr = style_st.substr(pos + sizeof("width") - 1);

					for (auto i = 0; i < substr.size(); i++) {
						auto t = substr[i];
						if (g_ascii_isdigit (t)) {
							unsigned long val;
							rspamd_strtoul(substr.data(),
									substr.size(), &val);
							img->width = val;
							break;
						}
						else if (!g_ascii_isspace (t) && t != '=' && t != ':') {
							/* Fallback */
							break;
						}
					}
				}
			}
		}
	}

	if (img->embedded_image) {
		if (img->height == 0) {
			img->height = img->embedded_image->height;
		}
		if (img->width == 0) {
			img->width = img->embedded_image->width;
		}
	}

	hc->images.push_back(img);
	tag->extra = img;
}

static auto
html_process_link_tag(rspamd_mempool_t *pool, struct html_tag *tag,
					  struct html_content *hc,
					  khash_t (rspamd_url_hash) *url_set,
					  GPtrArray *part_urls) -> void
{
	auto found_rel_maybe = tag->find_component(html_component_type::RSPAMD_HTML_COMPONENT_REL);

	if (found_rel_maybe) {
		if (found_rel_maybe.value() == "icon") {
			html_process_img_tag(pool, tag, hc, url_set, part_urls);
		}
	}
}

static auto
html_process_block_tag(rspamd_mempool_t *pool, struct html_tag *tag,
					   struct html_content *hc) -> void
{
	std::optional<css::css_value> maybe_fgcolor, maybe_bgcolor;

	for (const auto &param : tag->parameters) {
		if (param.type == html_component_type::RSPAMD_HTML_COMPONENT_COLOR) {
			maybe_fgcolor = css::css_value::maybe_color_from_string(param.value);
		}

		if (param.type == html_component_type::RSPAMD_HTML_COMPONENT_BGCOLOR) {
			maybe_bgcolor = css::css_value::maybe_color_from_string(param.value);
		}

		if (param.type == html_component_type::RSPAMD_HTML_COMPONENT_STYLE) {
			tag->block = rspamd::css::parse_css_declaration(pool, param.value);
		}
	}

	if (!tag->block) {
		tag->block = html_block::undefined_html_block_pool(pool);
	}

	if (maybe_fgcolor) {
		tag->block->set_fgcolor(maybe_fgcolor->to_color().value());
	}

	if (maybe_bgcolor) {
		tag->block->set_bgcolor(maybe_bgcolor->to_color().value());
	}
}

static inline auto
html_append_content(struct html_content *hc, std::string_view data) -> auto
{
	auto cur_offset = hc->parsed.size();
	hc->parsed.append(data);
	auto nlen = decode_html_entitles_inplace(hc->parsed.data() + cur_offset,
			hc->parsed.size() - cur_offset, true);
	hc->parsed.resize(nlen + cur_offset);

	return nlen;
}

static auto
html_process_displayed_href_tag (rspamd_mempool_t *pool,
								 struct html_content *hc,
								 std::string_view data,
								 const struct html_tag *cur_tag,
								 GList **exceptions,
								 khash_t (rspamd_url_hash) *url_set,
								 goffset dest_offset) -> void
{

	if (std::holds_alternative<rspamd_url *>(cur_tag->extra)) {
		auto *url = std::get<rspamd_url *>(cur_tag->extra);

		html_check_displayed_url(pool,
				exceptions, url_set,
				data,
				dest_offset,
				url);
	}
}

static auto
html_append_tag_content(rspamd_mempool_t *pool,
						const gchar *start, gsize len,
						struct html_content *hc,
						const html_tag *tag,
						std::vector<const html_tag *> &enclosed_tags,
						GList **exceptions,
						khash_t (rspamd_url_hash) *url_set) -> goffset
{
	auto is_visible = true, is_block = false;
	goffset next_tag_offset = tag->content_length + tag->content_offset,
			initial_dest_offset = hc->parsed.size();

	if (tag->id == Tag_BR || tag->id == Tag_HR) {
		hc->parsed.append("\n");

		return tag->content_offset;
	}

	if (!tag->block) {
		if ((tag->flags & (FL_COMMENT|FL_XML))) {
			is_visible = false;
		}
		else {
			is_visible = true;
		}
	}
	else if (!tag->block->is_visible()) {
		is_visible = false;
	}
	else {
		is_block = tag->block->has_display() &&
				   tag->block->display == css::css_display_value::DISPLAY_BLOCK;
	}

	if (is_block) {
		if (!hc->parsed.empty() && hc->parsed.back() != '\n') {
			hc->parsed.append("\n");
		}
	}

	goffset cur_offset = tag->content_offset;

	do {
		auto enclosed_end = 0, enclosed_start = 0;
		decltype(tag) next_enclosed = nullptr;

		if (!enclosed_tags.empty()) {
			next_enclosed = enclosed_tags.back();
			enclosed_start = next_enclosed->tag_start;
			enclosed_end = next_enclosed->content_length +
						   next_enclosed->content_offset;

			if (enclosed_end > next_tag_offset) {
				next_tag_offset = enclosed_end;
			}
			enclosed_tags.pop_back();
		}
		else {
			enclosed_start = next_tag_offset;
		}

		goffset initial_part_len = enclosed_start - cur_offset;

		if (is_visible && initial_part_len > 0) {
			html_append_content(hc, {start + cur_offset,
									 std::size_t(initial_part_len)});
		}

		/* Deal with the remaining part */
		std::decay_t<decltype(enclosed_tags)> nested_stack;

		while (!enclosed_tags.empty() && enclosed_end > 0) {
			const auto *last_tag = enclosed_tags.back();

			if (last_tag->tag_start <= enclosed_end) {
				nested_stack.push_back(last_tag);
				enclosed_tags.pop_back();
			}
			else {
				break;
			}
		}

		if (next_enclosed) {
			/* Recursively print enclosed tags */
			std::reverse(std::begin(nested_stack), std::end(nested_stack));
			cur_offset = html_append_tag_content(pool, start, len, hc, next_enclosed,
					nested_stack, exceptions, url_set);

			if (enclosed_tags.empty()) {
				initial_part_len = next_tag_offset - cur_offset;
				if (is_visible && initial_part_len > 0) {
					html_append_content(hc, {start + cur_offset,
											 std::size_t(initial_part_len)});
				}
			}
		}

	} while (!enclosed_tags.empty());

	if (is_block && is_visible) {
		if (!hc->parsed.empty() && hc->parsed.back() != '\n') {
			hc->parsed.append("\n");
		}
	}

	if (is_visible && !(tag->flags & FL_CLOSING)) {
		if (tag->id == Tag_A) {
			auto written_len = hc->parsed.size() - initial_dest_offset;
			html_process_displayed_href_tag(pool, hc,
					{hc->parsed.data() + initial_dest_offset, written_len},
					tag, exceptions,
					url_set, initial_dest_offset);
		}
		else if (tag->id == Tag_IMG) {
			/* Process ALT if presented */
			auto maybe_alt = tag->find_component(html_component_type::RSPAMD_HTML_COMPONENT_ALT);

			if (maybe_alt) {
				if (!hc->parsed.empty() && !g_ascii_isspace (hc->parsed.back())) {
					/* Add a space */
					hc->parsed += ' ';
				}
				hc->parsed.append(maybe_alt.value());

				if (!g_ascii_isspace (hc->parsed.back())) {
					/* Add a space */
					hc->parsed += ' ';
				}
			}
		}
	}

	return next_tag_offset;
}

static auto
html_append_tags_content(rspamd_mempool_t *pool,
						 const gchar *start, gsize len,
						 struct html_content *hc,
						 GList **exceptions,
						 khash_t (rspamd_url_hash) *url_set) -> void
{
	auto cur_offset = 0;
	std::vector<const html_tag *> enclosed_tags_stack;

	for (auto i = 0; i < hc->all_tags.size();) {
		const auto &tag = hc->all_tags[i];
		html_tag *next_tag = nullptr;
		auto next_offset = tag->content_offset + tag->content_length;

		auto j = i + 1;
		while (j < hc->all_tags.size()) {
			next_tag = hc->all_tags[j].get();

			if (next_tag->content_offset <= next_offset) {
				enclosed_tags_stack.push_back(next_tag);
				if (next_tag->content_offset + next_tag->content_length > next_offset) {
					/* Tag spans over its parent */
					next_offset = next_tag->content_offset + next_tag->content_length;
				}
				j ++;
			}
			else {
				break;
			}
		}

		std::reverse(enclosed_tags_stack.begin(), enclosed_tags_stack.end());
		cur_offset = html_append_tag_content(pool, start, len, hc, tag.get(),
				enclosed_tags_stack, exceptions, url_set);
		i = j;
	}
}

static auto
html_process_input(rspamd_mempool_t *pool,
					GByteArray *in,
					GList **exceptions,
					khash_t (rspamd_url_hash) *url_set,
					GPtrArray *part_urls,
					bool allow_css) -> html_content *
{
	const gchar *p, *c, *end, *start;
	guchar t;
	auto closing = false, in_head = false;
	guint obrace = 0, ebrace = 0;
	struct rspamd_url *url = NULL;
	gint href_offset = -1;
	struct html_tag *cur_tag = NULL;
	std::vector<html_tag *> tags_stack;
	struct tag_content_parser_state content_parser_env;

	enum {
		parse_start = 0,
		content_before_start,
		tag_begin,
		sgml_tag,
		xml_tag,
		compound_tag,
		comment_tag,
		comment_content,
		sgml_content,
		tag_content,
		tag_end,
		html_text_content,
		xml_tag_end,
		content_style,
	} state = parse_start;

	g_assert (in != NULL);
	g_assert (pool != NULL);

	struct html_content *hc = new html_content;
	rspamd_mempool_add_destructor(pool, html_content::html_content_dtor, hc);

	p = (const char *)in->data;
	c = p;
	end = p + in->len;
	start = c;

	while (p < end) {
		t = *p;

		switch (state) {
		case parse_start:
			if (t == '<') {
				state = tag_begin;
			}
			else {
				/* We have no starting tag, so assume that it's content */
				hc->flags |= RSPAMD_HTML_FLAG_BAD_START;
				hc->all_tags.emplace_back(std::make_unique<html_tag>());
				cur_tag = hc->all_tags.back().get();
				cur_tag->id = Tag_HTML;
				state = content_before_start;
			}
			break;
		case content_before_start:
			if (t == '<') {
				html_append_content(hc, {c, std::size_t(p - c)});
				state = tag_begin;
			}
			else {
				p ++;
			}
			break;
		case tag_begin:
			switch (t) {
			case '<':
				c = p;
				p ++;
				closing = FALSE;
				break;
			case '!':
				state = sgml_tag;
				hc->all_tags.emplace_back(std::make_unique<html_tag>());
				cur_tag = hc->all_tags.back().get();
				cur_tag->tag_start = c - start;
				p ++;
				break;
			case '?':
				state = xml_tag;
				hc->all_tags.emplace_back(std::make_unique<html_tag>());
				cur_tag = hc->all_tags.back().get();
				cur_tag->tag_start = c - start;
				cur_tag->flags |= FL_XML;
				hc->flags |= RSPAMD_HTML_FLAG_XML;
				p ++;
				break;
			case '/':
				closing = TRUE;
				p ++;
				break;
			case '>':
				/* Empty tag */
				hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
				state = tag_end;
				continue;
			default:
				state = tag_content;
				content_parser_env.reset();

				hc->all_tags.emplace_back(std::make_unique<html_tag>());
				cur_tag = hc->all_tags.back().get();
				cur_tag->tag_start = c - start;
				break;
			}

			break;

		case sgml_tag:
			switch (t) {
			case '[':
				state = compound_tag;
				obrace = 1;
				ebrace = 0;
				p ++;
				break;
			case '-':
				cur_tag->flags |= FL_COMMENT;
				state = comment_tag;
				p ++;
				break;
			default:
				state = sgml_content;
				break;
			}

			break;

		case xml_tag:
			if (t == '?') {
				state = xml_tag_end;
			}
			else if (t == '>') {
				/* Misformed xml tag */
				hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
				state = tag_end;
				continue;
			}
			/* We efficiently ignore xml tags */
			p ++;
			break;

		case xml_tag_end:
			if (t == '>') {
				state = tag_end;
				continue;
			}
			else {
				hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
				p ++;
			}
			break;

		case compound_tag:
			if (t == '[') {
				obrace ++;
			}
			else if (t == ']') {
				ebrace ++;
			}
			else if (t == '>' && obrace == ebrace) {
				state = tag_end;
				continue;
			}
			p ++;
			break;

		case comment_tag:
			if (t != '-')  {
				hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
				state = tag_end;
			}
			else {
				p++;
				ebrace = 0;
				/*
				 * https://www.w3.org/TR/2012/WD-html5-20120329/syntax.html#syntax-comments
				 *  ... the text must not start with a single
				 *  U+003E GREATER-THAN SIGN character (>),
				 *  nor start with a "-" (U+002D) character followed by
				 *  a U+003E GREATER-THAN SIGN (>) character,
				 *  nor contain two consecutive U+002D HYPHEN-MINUS
				 *  characters (--), nor end with a "-" (U+002D) character.
				 */
				if (p[0] == '-' && p + 1 < end && p[1] == '>') {
					hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
					p ++;
					state = tag_end;
				}
				else if (*p == '>') {
					hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
					state = tag_end;
				}
				else {
					state = comment_content;
				}
			}
			break;

		case comment_content:
			if (t == '-') {
				ebrace ++;
			}
			else if (t == '>' && ebrace >= 2) {
				state = tag_end;
				continue;
			}
			else {
				ebrace = 0;
			}

			p ++;
			break;

		case html_text_content:
			if (t != '<') {
				p ++;
			}
			else {
				state = tag_begin;
			}
			break;

		case content_style: {

			/*
			 * We just search for the first </style> substring and then pass
			 * the content to the parser (if needed)
			 *
			 * TODO: Handle other stuff, we actually need an FSM here to find
			 * the ending tag...
			 */
			auto end_style = rspamd_substring_search_caseless(p, end - p,
					"</style>", 8);
			if (end_style == -1) {
				/* Invalid style */
				state = html_text_content;
			}
			else {

				if (allow_css) {
					auto ret_maybe =  rspamd::css::parse_css(pool, {p, std::size_t(end_style)},
							std::move(hc->css_style));

					if (!ret_maybe.has_value()) {
						auto err_str = fmt::format("cannot parse css (error code: {}): {}",
								static_cast<int>(ret_maybe.error().type),
								ret_maybe.error().description.value_or("unknown error"));
						msg_info_pool ("cannot parse css: %*s",
								(int)err_str.size(), err_str.data());
					}

					hc->css_style = ret_maybe.value();
				}

				p += end_style;
				state = tag_begin;
			}
			break;
		}
		case sgml_content:
			/* TODO: parse DOCTYPE here */
			if (t == '>') {
				state = tag_end;
				/* We don't know a lot about sgml tags, ignore them */
				cur_tag = nullptr;
				continue;
			}
			p ++;
			break;

		case tag_content:
			html_parse_tag_content(pool, hc, cur_tag, p, content_parser_env);

			if (t == '>') {
				if (closing) {
					cur_tag->flags |= FL_CLOSING;

					if (cur_tag->flags & FL_CLOSED) {
						/* Bad mix of closed and closing */
						hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
					}

					closing = FALSE;
				}

				state = tag_end;
				continue;
			}
			p ++;
			break;

		case tag_end:
			content_parser_env.reset();

			if (cur_tag != nullptr) {

				cur_tag->content_offset = p - start + 1;

				html_process_tag(pool, hc, cur_tag, tags_stack,
						c - start, p - start);

				if (cur_tag->id != -1 && cur_tag->id < N_TAGS) {
					if (cur_tag->flags & CM_UNIQUE) {
						if (!hc->tags_seen[cur_tag->id]) {
							/* Duplicate tag has been found */
							hc->flags |= RSPAMD_HTML_FLAG_DUPLICATE_ELEMENTS;
						}
					}
					hc->tags_seen[cur_tag->id] = true;
				}

				if (cur_tag->id == Tag_HEAD) {
					in_head = !(cur_tag->flags & FL_CLOSING);
				}

				/* XXX: uncomment when styles parsing is not so broken */
				if (cur_tag->flags & FL_HREF && !in_head) {
					if (!(cur_tag->flags & (FL_CLOSING))) {
						auto maybe_url = html_process_url_tag(pool, cur_tag, hc);

						if (maybe_url) {
							url = maybe_url.value();

							if (url_set != NULL) {
								struct rspamd_url *maybe_existing =
										rspamd_url_set_add_or_return (url_set, maybe_url.value());
								if (maybe_existing == maybe_url.value()) {
									html_process_query_url(pool, url, url_set,
											part_urls);
								}
								else {
									url = maybe_existing;
									/* Increase count to avoid odd checks failure */
									url->count ++;
								}
							}

							href_offset = hc->parsed.size();
						}
					}
				}
				else if (cur_tag->id == Tag_BASE && !(cur_tag->flags & (FL_CLOSING))) {
					/*
					 * Base is allowed only within head tag but HTML is retarded
					 */
					if (hc->base_url == NULL) {
						auto maybe_url = html_process_url_tag(pool, cur_tag, hc);

						if (maybe_url) {
							msg_debug_html ("got valid base tag");
							hc->base_url = url;
							cur_tag->extra = url;
							cur_tag->flags |= FL_HREF;
						}
						else {
							msg_debug_html ("got invalid base tag!");
						}
					}
				}

				if (cur_tag->id == Tag_IMG && !(cur_tag->flags & FL_CLOSING)) {
					html_process_img_tag(pool, cur_tag, hc, url_set,
							part_urls);
				}
				else if (cur_tag->id == Tag_LINK && !(cur_tag->flags & FL_CLOSING)) {
					html_process_link_tag(pool, cur_tag, hc, url_set,
							part_urls);
				}

				if (!(cur_tag->flags & CM_EMPTY)) {

					if (!(cur_tag->flags & FL_CLOSING)) {
						html_process_block_tag(pool, cur_tag, hc);
					}
				}
			}

			if (cur_tag && (cur_tag->id == Tag_STYLE && !(cur_tag->flags & FL_CLOSING))) {
				state = content_style;
			}
			else {
				state = html_text_content;
			}

			p++;
			c = p;
			cur_tag = NULL;
			break;
		}
	}

	/* Propagate styles */
	hc->traverse_block_tags([&hc](const html_tag *tag) -> bool {
		if (tag->flags & FL_CLOSING) {
			return true;
		}

		if (hc->css_style) {
			auto *css_block = hc->css_style->check_tag_block(tag);

			if (css_block) {
				if (tag->block) {
					tag->block->propagate_block(*css_block);
				}
				else {
					tag->block = css_block;
				}
			}
		}
		if (tag->block) {
			if (!tag->block->has_display()) {
				/* If we have no display field, we can check it by tag */
				if (tag->flags & CM_BLOCK) {
					tag->block->set_display(css::css_display_value::DISPLAY_BLOCK);
				}
				else if (tag->flags & CM_HEAD) {
					tag->block->set_display(css::css_display_value::DISPLAY_HIDDEN);
				}
				else {
					tag->block->set_display(css::css_display_value::DISPLAY_INLINE);
				}
			}

			tag->block->compute_visibility();

			for (const auto *cld_tag : tag->children) {
				if (cld_tag->block) {
					cld_tag->block->propagate_block(*tag->block);
				}
				else {
					cld_tag->block = tag->block;
				}
			}
		}
		return true;
	}, html_content::traverse_type::PRE_ORDER);

	if (!hc->all_tags.empty()) {
		std::sort(hc->all_tags.begin(), hc->all_tags.end(), [](const auto &pt1, const auto &pt2) -> auto {
			return pt1->tag_start < pt2->tag_start;
		});
		html_append_tags_content(pool, start, end - start, hc, exceptions, url_set);
	}

	/* Leftover */
	switch (state) {
	case html_text_content:
	case content_before_start:
		if (p > c) {
			html_append_content(hc, {c, std::size_t(p - c)});
		}
		break;
	default:
		/* Do nothing */
		break;
	}

	if (!hc->parsed.empty()) {
		/* Trim extra spaces at the at the end if needed */
		if (g_ascii_isspace(hc->parsed.back())) {
			auto last_it = std::end(hc->parsed);

			/* Allow last newline */
			if (hc->parsed.back() == '\n') {
				--last_it;
			}

			hc->parsed.erase(std::find_if(hc->parsed.rbegin(), hc->parsed.rend(),
					[](auto ch) -> auto {
						return !g_ascii_isspace(ch);
					}).base(),
					last_it);
		}
	}

	return hc;
}

static auto
html_find_image_by_cid(const html_content &hc, std::string_view cid)
	-> std::optional<const html_image *>
{
	for (const auto *html_image : hc.images) {
		/* Filter embedded images */
		if (html_image->flags & RSPAMD_HTML_FLAG_IMAGE_EMBEDDED &&
				html_image->src != nullptr) {
			if (cid == html_image->src) {
				return html_image;
			}
		}
	}

	return std::nullopt;
}

static auto
html_debug_structure(const html_content &hc) -> std::string
{
	std::string output;

	if (hc.root_tag) {
		auto rec_functor = [&](const html_tag *t, int level, auto rec_functor) -> void {
			std::string pluses(level, '+');
			output += fmt::format("{}{};", pluses, t->name);
			for (const auto *cld : t->children) {
				rec_functor(cld, level + 1, rec_functor);
			}
		};

		rec_functor(hc.root_tag, 1, rec_functor);
	}

	return output;
}

auto html_tag_by_name(const std::string_view &name)
	-> std::optional<tag_id_t>
{
	const auto *td = rspamd::html::html_tags_defs.by_name(name);

	if (td != nullptr) {
		return td->id;
	}

	return std::nullopt;
}

/*
 * Tests part
 */

TEST_SUITE("html") {
TEST_CASE("html parsing")
{

	const std::vector<std::pair<std::string, std::string>> cases{
			{"<html><!DOCTYPE html><body>",                    "+html;++body;"},
			{"<html><div><div></div></div></html>",            "+html;++div;+++div;"},
			{"<html><div><div></div></html>",                  "+html;++div;+++div;"},
			{"<html><div><div></div></html></div>",            "+html;++div;+++div;"},
			{"<p><p><a></p></a></a>",                          "+p;++p;+++a;"},
			{"<div><a href=\"http://example.com\"></div></a>", "+div;++a;"},
			{"<html><!DOCTYPE html><body><head><body></body></html></body></html>",
															   "+html;++body;+++head;++++body;"}
	};

	rspamd_url_init(NULL);
	auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
			"html", 0);

	for (const auto &c : cases) {
		SUBCASE((std::string("extract tags from: ") + c.first).c_str()) {
			GByteArray *tmp = g_byte_array_sized_new(c.first.size());
			g_byte_array_append(tmp, (const guint8 *) c.first.data(), c.first.size());
			auto *hc = html_process_input(pool, tmp, nullptr, nullptr, nullptr, true);
			CHECK(hc != nullptr);
			auto dump = html_debug_structure(*hc);
			CHECK(c.second == dump);
			g_byte_array_free(tmp, TRUE);
		}
	}

	rspamd_mempool_delete(pool);
}

TEST_CASE("html text extraction")
{

	const std::vector<std::pair<std::string, std::string>> cases{
			{"test", "test"},
			{"test   ", "test"},
			{"test   foo,   bar", "test foo, bar"},
			{"<p>text</p>", "text\n"},
			{"olo<p>text</p>lolo", "olo\ntext\nlolo"},
			{"<b>foo<i>bar</i>baz</b>", "foobarbaz"},
			{"<b>foo<i>bar</b>baz</i>", "foobarbaz"},
			{"foo<br>baz", "foo\nbaz"},
			{"<div>foo</div><div>bar</div>", "foo\nbar\n"},
			{"<a href=https://example.com>test</a>", "test"},
			{"<img alt=test>", "test"},
			{"<html><head><meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"></head>"
			 "  <body>\n"
			 "    <p><br>\n"
			 "    </p>\n"
			 "    <div class=\"moz-forward-container\"><br>\n"
			 "      <br>\n"
			 "      test</div>"
			 "</body>", "\n\n\ntest\n"},
			{"<div>fi<span style=\"FONT-SIZE: 0px\">le </span>"
			 "sh<span style=\"FONT-SIZE: 0px\">aring </span></div>", "fish\n"},
			/* FIXME: broken until rework */
			//{"<div>fi<span style=\"FONT-SIZE: 0px\">le </span>"
			// "sh<span style=\"FONT-SIZE: 0px\">aring </div>foo</span>", "fish\nfoo"},
			{"<p><!--comment-->test", "test"},
			{"<!DOCTYPE html>\n"
			 "<html lang=\"en\">\n"
			 "  <head>\n"
			 "    <meta charset=\"utf-8\">\n"
			 "    <title>title</title>\n"
			 "    <link rel=\"stylesheet\" href=\"style.css\">\n"
			 "    <script src=\"script.js\"></script>\n"
			 "  </head>\n"
			 "  <body>\n"
			 "    <!-- page content -->\n"
			 "    Hello, world! <b>test</b>\n"
			 "    <p>data<>\n"
			 "    </P>\n"
			 "    <b>stuff</p>?\n"
			 "  </body>\n"
			 "</html>", "Hello, world! test\ndata<> \nstuff?"}
	};

	rspamd_url_init(NULL);
	auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
			"html", 0);

	auto replace_newlines = [](std::string &str) {
		auto start_pos = 0;
		while((start_pos = str.find("\n", start_pos, 1)) != std::string::npos) {
			str.replace(start_pos, 1, "\\n", 2);
			start_pos += 2;
		}
	};

	for (const auto &c : cases) {
		SUBCASE((std::string("extract text from: ") + c.first).c_str()) {
			GByteArray *tmp = g_byte_array_sized_new(c.first.size());
			g_byte_array_append(tmp, (const guint8 *) c.first.data(), c.first.size());
			auto *hc = html_process_input(pool, tmp, nullptr, nullptr, nullptr, true);
			CHECK(hc != nullptr);
			replace_newlines(hc->parsed);
			auto expected = c.second;
			replace_newlines(expected);
			CHECK(hc->parsed == expected);
			g_byte_array_free(tmp, TRUE);
		}
	}

	rspamd_mempool_delete(pool);
}

}

}

void *
rspamd_html_process_part_full(rspamd_mempool_t *pool,
							  GByteArray *in, GList **exceptions,
							  khash_t (rspamd_url_hash) *url_set,
							  GPtrArray *part_urls,
							  bool allow_css)
{
	return rspamd::html::html_process_input(pool, in, exceptions, url_set,
			part_urls, allow_css);
}

void *
rspamd_html_process_part(rspamd_mempool_t *pool,
						 GByteArray *in)
{
	return rspamd_html_process_part_full (pool, in, NULL,
			NULL, NULL, FALSE);
}

guint
rspamd_html_decode_entitles_inplace (gchar *s, gsize len)
{
	return rspamd::html::decode_html_entitles_inplace(s, len);
}

gint
rspamd_html_tag_by_name(const gchar *name)
{
	const auto *td = rspamd::html::html_tags_defs.by_name(name);

	if (td != nullptr) {
		return td->id;
	}

	return -1;
}

gboolean
rspamd_html_tag_seen(void *ptr, const gchar *tagname)
{
	gint id;
	auto *hc = rspamd::html::html_content::from_ptr(ptr);

	g_assert (hc != NULL);

	id = rspamd_html_tag_by_name(tagname);

	if (id != -1) {
		return hc->tags_seen[id];
	}

	return FALSE;
}

const gchar *
rspamd_html_tag_by_id(gint id)
{
	const auto *td = rspamd::html::html_tags_defs.by_id(id);

	if (td != nullptr) {
		return td->name.c_str();
	}

	return nullptr;
}

const gchar *
rspamd_html_tag_name(void *p, gsize *len)
{
	auto *tag = reinterpret_cast<rspamd::html::html_tag *>(p);

	if (len) {
		*len = tag->name.size();
	}

	return tag->name.data();
}

struct html_image*
rspamd_html_find_embedded_image(void *html_content,
								const char *cid, gsize cid_len)
{
	auto *hc = rspamd::html::html_content::from_ptr(html_content);

	auto maybe_img = rspamd::html::html_find_image_by_cid(*hc, {cid, cid_len});

	if (maybe_img) {
		return (html_image *)maybe_img.value();
	}

	return nullptr;
}

bool
rspamd_html_get_parsed_content(void *html_content, rspamd_ftok_t *dest)
{
	auto *hc = rspamd::html::html_content::from_ptr(html_content);

	dest->begin = hc->parsed.data();
	dest->len = hc->parsed.size();

	return true;
}