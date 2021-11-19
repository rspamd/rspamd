/*-
 * Copyright 2021 Vsevolod Stakhov
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

#include <frozen/unordered_map.h>
#include <frozen/string.h>
#include <fmt/core.h>

#include <unicode/uversion.h>

namespace rspamd::html {

static const guint max_tags = 8192; /* Ignore tags if this maximum is reached */

static const html_tags_storage html_tags_defs;

auto html_components_map = frozen::make_unordered_map<frozen::string, html_component_type>(
		{
				{"name",    html_component_type::RSPAMD_HTML_COMPONENT_NAME},
				{"href",    html_component_type::RSPAMD_HTML_COMPONENT_HREF},
				{"src",     html_component_type::RSPAMD_HTML_COMPONENT_HREF},
				{"action",  html_component_type::RSPAMD_HTML_COMPONENT_HREF},
				{"color",   html_component_type::RSPAMD_HTML_COMPONENT_COLOR},
				{"bgcolor", html_component_type::RSPAMD_HTML_COMPONENT_BGCOLOR},
				{"style",   html_component_type::RSPAMD_HTML_COMPONENT_STYLE},
				{"class",   html_component_type::RSPAMD_HTML_COMPONENT_CLASS},
				{"width",   html_component_type::RSPAMD_HTML_COMPONENT_WIDTH},
				{"height",  html_component_type::RSPAMD_HTML_COMPONENT_HEIGHT},
				{"size",    html_component_type::RSPAMD_HTML_COMPONENT_SIZE},
				{"rel",     html_component_type::RSPAMD_HTML_COMPONENT_REL},
				{"alt",     html_component_type::RSPAMD_HTML_COMPONENT_ALT},
				{"id",      html_component_type::RSPAMD_HTML_COMPONENT_ID},
				{"hidden",  html_component_type::RSPAMD_HTML_COMPONENT_HIDDEN},
		});

#define msg_debug_html(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_html_log_id, "html", pool->tag.uid, \
        __FUNCTION__, \
        __VA_ARGS__)

INIT_LOG_MODULE(html)

/*
 * This function is expected to be called on a closing tag to fill up all tags
 * and return the current parent (meaning unclosed) tag
 */
static auto
html_check_balance(struct html_content *hc,
				   struct html_tag *tag,
				   goffset tag_start_offset,
				   goffset tag_end_offset) -> html_tag *
{
	/* As agreed, the closing tag has the last opening at the parent ptr */
	auto *opening_tag = tag->parent;

	auto calculate_content_length = [tag_start_offset, tag_end_offset](html_tag *t) {
		auto opening_content_offset = t->content_offset;

		if (t->flags & (CM_EMPTY)) {
			/* Attach closing tag just at the opening tag */
			t->closing.start = t->tag_start;
			t->closing.end = t->content_offset;
		}
		else {

			if (opening_content_offset <= tag_start_offset) {
				t->closing.start = tag_start_offset;
				t->closing.end = tag_end_offset;
			}
			else {

				t->closing.start = t->content_offset;
				t->closing.end = tag_end_offset;
			}
		}
	};

	auto balance_tag = [&]() -> html_tag * {
		auto it = tag->parent;
		auto found_pair = false;

		for (; it != nullptr; it = it->parent) {
			if (it->id == tag->id && !(it->flags & FL_CLOSED)) {
				found_pair = true;
				break;
			}

		}

		/*
		 * If we have found a closing pair, then we need to close all tags and
		 * return the top-most tag
		 */
		if (found_pair) {
			for (it = tag->parent; it != nullptr; it = it->parent) {
				it->flags |= FL_CLOSED;
				/* Insert a virtual closing tag for all tags that are not closed */
				calculate_content_length(it);
				if (it->id == tag->id && !(it->flags & FL_CLOSED)) {
					break;
				}
			}

			return it;
		}
		else {
			/*
			 * We have not found a pair, so this closing tag is bogus and should
			 * be ignored completely.
			 * Unfortunately, it also means that we need to insert another tag,
			 * as the current closing tag is unusable for that purposes.
			 *
			 * We assume that callee will recognise that and reconstruct the
			 * tag at the tag_end_closing state, so we return nullptr...
			 */

		}

		/* Tag must be ignored and reconstructed */
		return nullptr;
	};

	if (opening_tag) {

		if (opening_tag->id == tag->id) {
			opening_tag->flags |= FL_CLOSED;

			calculate_content_length(opening_tag);
			/* All good */
			return opening_tag->parent;
		}
		else {
			return balance_tag();
		}
	}
	else {
		/*
		 * We have no opening tag
		 * There are two possibilities:
		 *
		 * 1) We have some block tag in hc->all_tags;
		 * 2) We have no tags
		 */

		if (hc->all_tags.empty()) {
			hc->all_tags.push_back(std::make_unique<html_tag>());
			auto *vtag = hc->all_tags.back().get();
			vtag->id = Tag_HTML;
			vtag->flags = FL_VIRTUAL;
			vtag->tag_start = 0;
			vtag->content_offset = 0;
			calculate_content_length(vtag);

			if (!hc->root_tag) {
				hc->root_tag = vtag;
			}
			else {
				vtag->parent = hc->root_tag;
			}

			tag->parent = vtag;

			/* Recursively call with a virtual <html> tag inserted */
			return html_check_balance(hc, tag, tag_start_offset, tag_end_offset);
		}
	}

	return nullptr;
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

struct tag_content_parser_state {
	int cur_state = 0;
	std::string buf;
	std::optional<html_component_type> cur_component;

	void reset()
	{
		cur_state = 0;
		buf.clear();
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
		spaces_before_eq,
		spaces_after_eq,
		spaces_after_param,
		ignore_bad_tag,
		tag_end,
		slash_after_value,
		slash_in_unqouted_value,
	} state;

	state = static_cast<enum tag_parser_state>(parser_env.cur_state);

	/*
	 * Stores tag component if it doesn't exist, performing copy of the
	 * value + decoding of the entities
	 * Parser env is set to clear the current html attribute fields (saved_p and
	 * cur_component)
	 */
	auto store_component_value = [&]() -> void {
		if (parser_env.cur_component) {

			if (parser_env.buf.empty()) {
				tag->components.emplace_back(parser_env.cur_component.value(),
						std::string_view{});
			}
			else {
				/* We need to copy buf to a persistent storage */
				auto *s = rspamd_mempool_alloc_buffer(pool, parser_env.buf.size());

				if (parser_env.cur_component.value() == html_component_type::RSPAMD_HTML_COMPONENT_ID ||
						parser_env.cur_component.value() == html_component_type::RSPAMD_HTML_COMPONENT_CLASS) {
					/* Lowercase */
					rspamd_str_copy_lc(parser_env.buf.data(), s, parser_env.buf.size());
				}
				else {
					memcpy(s, parser_env.buf.data(), parser_env.buf.size());
				}

				auto sz = rspamd_html_decode_entitles_inplace(s, parser_env.buf.size());
				tag->components.emplace_back(parser_env.cur_component.value(),
						std::string_view{s, sz});
			}
		}

		parser_env.buf.clear();
		parser_env.cur_component = std::nullopt;
	};

	auto store_component_name = [&]() -> bool {
		decode_html_entitles_inplace(parser_env.buf);
		auto known_component_it = html_components_map.find(std::string_view{parser_env.buf});
		parser_env.buf.clear();

		if (known_component_it != html_components_map.end()) {
			parser_env.cur_component = known_component_it->second;

			return true;
		}
		else {
			parser_env.cur_component = std::nullopt;
		}

		return false;
	};

	auto store_value_character = [&](bool lc) -> void {
		auto c = lc ? g_ascii_tolower(*in) : *in;

		if (c == '\0') {
			/* Replace with u0FFD */
			parser_env.buf.append(u8"\uFFFD");
		}
		else {
			parser_env.buf.push_back(c);
		}
	};

	switch (state) {
	case parse_start:
		if (!g_ascii_isalpha (*in) && !g_ascii_isspace (*in)) {
			hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
			state = ignore_bad_tag;
			tag->id = N_TAGS;
			tag->flags |= FL_BROKEN;
		}
		else if (g_ascii_isalpha (*in)) {
			state = parse_name;
			store_value_character(true);
		}
		break;

	case parse_name:
		if ((g_ascii_isspace (*in) || *in == '>' || *in == '/')) {
			if (*in == '/') {
				tag->flags |= FL_CLOSED;
			}

			if (parser_env.buf.empty()) {
				hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
				tag->id = N_TAGS;
				tag->flags |= FL_BROKEN;
				state = ignore_bad_tag;
			}
			else {
				decode_html_entitles_inplace(parser_env.buf);
				const auto *tag_def = rspamd::html::html_tags_defs.by_name(parser_env.buf);

				if (tag_def == nullptr) {
					hc->flags |= RSPAMD_HTML_FLAG_UNKNOWN_ELEMENTS;
					/* Assign -hash to match closing tag if needed */
					auto nhash = static_cast<std::int32_t>(std::hash<std::string>{}(parser_env.buf));
					/* Always negative */
					tag->id = static_cast<tag_id_t>(nhash | G_MININT32);
				}
				else {
					tag->id = tag_def->id;
					tag->flags = tag_def->flags;
				}

				parser_env.buf.clear();

				state = spaces_after_param;
			}
		}
		else {
			store_value_character(true);
		}
		break;

	case parse_attr_name:
		if (*in == '=') {
			if (!parser_env.buf.empty()) {
				store_component_name();
			}
			state = parse_equal;
		}
		else if (g_ascii_isspace(*in)) {
			store_component_name();
			state = spaces_before_eq;
		}
		else if (*in == '/') {
			store_component_name();
			store_component_value();
			state = slash_after_value;
		}
		else if (*in == '>') {
			store_component_name();
			store_component_value();
			state = tag_end;
		}
		else {
			if (*in == '"' || *in == '\'' || *in == '<') {
				/* Should never be in attribute names but ignored */
				tag->flags |= FL_BROKEN;
			}

			store_value_character(true);
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
				store_component_value();
				state = tag_end;
			}
			else if (*in == '"' || *in == '\'' || *in == '<') {
				/* Attribute followed by quote... Missing '=' ? Dunno, need to test */
				hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
				tag->flags |= FL_BROKEN;
				store_component_value();
				store_value_character(true);
				state = spaces_after_param;
			}
			else {
				/* Empty attribute */
				store_component_value();
				store_value_character(true);
				state = spaces_after_param;
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
			store_value_character(true);
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
			store_value_character(true);
			state = parse_value;
		}
		break;

	case parse_start_dquote:
		if (*in == '"') {
			state = spaces_after_param;
		}
		else {
			store_value_character(false);
			state = parse_dqvalue;
		}
		break;

	case parse_start_squote:
		if (*in == '\'') {
			state = spaces_after_param;
		}
		else {
			store_value_character(false);
			state = parse_sqvalue;
		}
		break;

	case parse_dqvalue:
		if (*in == '"') {
			store_component_value();
			state = parse_end_dquote;
		}
		else {
			store_value_character(false);
		}
		break;

	case parse_sqvalue:
		if (*in == '\'') {
			store_component_value();
			state = parse_end_squote;
		}
		else {
			store_value_character(false);
		}

		break;

	case parse_value:
		if (*in == '/') {
			state = slash_in_unqouted_value;
		}
		else if (g_ascii_isspace (*in) || *in == '>' || *in == '"') {
			store_component_value();
			state = spaces_after_param;
		}
		else {
			store_value_character(false);
		}
		break;

	case parse_end_dquote:
	case parse_end_squote:
		if (g_ascii_isspace (*in)) {
			state = spaces_after_param;
		}
		else if (*in == '/') {
			store_component_value();
			store_value_character(true);
			state = slash_after_value;
		}
		else {
			/* No space, proceed immediately to the attribute name */
			state = parse_attr_name;
			store_component_value();
			store_value_character(true);
		}
		break;

	case spaces_after_param:
		if (!g_ascii_isspace (*in)) {
			if (*in == '/') {
				state = slash_after_value;
			}
			else if (*in == '=') {
				/* Attributes cannot start with '=' */
				tag->flags |= FL_BROKEN;
				store_value_character(true);
				state = parse_attr_name;
			}
			else {
				store_value_character(true);
				state = parse_attr_name;
			}
		}
		break;
	case slash_after_value:
		if (*in == '>') {
			tag->flags |= FL_CLOSED;
			state = tag_end;
		}
		else if (!g_ascii_isspace(*in)) {
			tag->flags |= FL_BROKEN;
			state = parse_attr_name;
		}
		break;
	case slash_in_unqouted_value:
		if (*in == '>') {
			/* That slash was in fact closing tag slash, wohoo */
			tag->flags |= FL_CLOSED;
			state = tag_end;
			store_component_value();
		}
		else {
			/* Welcome to the world of html, revert state and save missing / */
			parser_env.buf.push_back('/');
			store_value_character(false);
			state = parse_value;
		}
		break;
	case ignore_bad_tag:
	case tag_end:
		break;
	}

	parser_env.cur_state = state;
}

static inline auto
html_is_absolute_url(std::string_view st) -> bool
{
	auto alnum_pos = std::find_if(std::begin(st), std::end(st),
			[](auto c) {return !g_ascii_isalnum(c);});

	if (alnum_pos != std::end(st) && alnum_pos != std::begin(st)) {
		if (*alnum_pos == ':') {
			if (st.substr(0, std::distance(std::begin(st), alnum_pos)) == "mailto") {
				return true;
			}

			std::advance(alnum_pos, 1);
			if (alnum_pos != std::end(st)) {
				/* Include even malformed urls */
				if (*alnum_pos == '/' || *alnum_pos == '\\') {
					return true;
				}
			}
		}
	}

	return false;
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

		if (hc && hc->base_url) {
			/*
			 * Relative url cannot start from the following:
			 * schema://
			 * data:
			 * slash
			 */

			if (!html_is_absolute_url(href_value)) {

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
				auto nlen = (std::size_t) rspamd_snprintf(buf, len + 1,
						"%*s%s%*s",
						(int) hc->base_url->urllen, hc->base_url->string,
						need_slash ? "/" : "",
						(gint) orig_len, href_value.data());
				href_value = {buf, nlen};
			}
			else if (href_value.size() > 2 && href_value[0] == '/' && href_value[1] != '/') {
				/* Relative to the hostname */
				auto orig_len = href_value.size();
				auto len = orig_len + hc->base_url->hostlen + hc->base_url->protocollen +
						   3 /* for :// */;
				auto *buf = rspamd_mempool_alloc_buffer(pool, len + 1);
				auto nlen = (std::size_t) rspamd_snprintf(buf, len + 1, "%*s://%*s/%*s",
						(int) hc->base_url->protocollen, hc->base_url->string,
						(int) hc->base_url->hostlen, rspamd_url_host_unsafe (hc->base_url),
						(gint) orig_len, href_value.data());
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

	if ((semicolon_pos = (const gchar *) memchr(semicolon_pos, ';', end - semicolon_pos)) != NULL) {
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

	for (const auto &param : tag->components) {

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
					img->src += sizeof("cid:") - 1;
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
								existing = rspamd_url_set_add_or_return(url_set,
										img->url);

								if (existing && existing != img->url) {
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
	bool hidden = false;

	for (const auto &param : tag->components) {
		if (param.type == html_component_type::RSPAMD_HTML_COMPONENT_COLOR) {
			maybe_fgcolor = css::css_value::maybe_color_from_string(param.value);
		}

		if (param.type == html_component_type::RSPAMD_HTML_COMPONENT_BGCOLOR) {
			maybe_bgcolor = css::css_value::maybe_color_from_string(param.value);
		}

		if (param.type == html_component_type::RSPAMD_HTML_COMPONENT_STYLE) {
			tag->block = rspamd::css::parse_css_declaration(pool, param.value);
		}

		if (param.type == html_component_type::RSPAMD_HTML_COMPONENT_HIDDEN) {
			hidden = true;
		}
	}

	if (!tag->block) {
		tag->block = html_block::undefined_html_block_pool(pool);
	}

	if (hidden) {
		tag->block->set_display(false);
	}

	if (maybe_fgcolor) {
		tag->block->set_fgcolor(maybe_fgcolor->to_color().value());
	}

	if (maybe_bgcolor) {
		tag->block->set_bgcolor(maybe_bgcolor->to_color().value());
	}
}

static inline auto
html_append_parsed(struct html_content *hc,
				   std::string_view data,
				   bool transparent,
				   std::size_t input_len,
				   std::string &dest) -> std::size_t
{
	auto cur_offset = dest.size();

	if (dest.size() > input_len) {
		/* Impossible case, refuse to append */
		return 0;
	}

	if (data.size() > 0) {
		/* Handle multiple spaces at the begin */

		if (cur_offset > 0) {
			auto last = dest.back();
			if (!g_ascii_isspace(last) && g_ascii_isspace(data.front())) {
				dest.append(" ");
				data = {data.data() + 1, data.size() - 1};
				cur_offset++;
			}
		}

		if (data.find('\0') != std::string_view::npos) {
			auto replace_zero_func = [](const auto &input, auto &output) {
				const auto last = input.cend();
				for (auto it = input.cbegin(); it != last; ++it) {
					if (*it == '\0') {
						output.append(u8"\uFFFD");
					}
					else {
						output.push_back(*it);
					}
				}
			};

			dest.reserve(dest.size() + data.size() + sizeof(u8"\uFFFD"));
			replace_zero_func(data, dest);
			hc->flags |= RSPAMD_HTML_FLAG_HAS_ZEROS;
		}
		else {
			dest.append(data);
		}
	}

	auto nlen = decode_html_entitles_inplace(dest.data() + cur_offset,
			dest.size() - cur_offset, true);

	dest.resize(nlen + cur_offset);

	if (transparent) {
		/* Replace all visible characters with spaces */
		auto start = std::next(dest.begin(), cur_offset);
		std::replace_if(start, std::end(dest), [](const auto c) {
			return !g_ascii_isspace(c);
		}, ' ');
	}

	return nlen;
}

static auto
html_process_displayed_href_tag(rspamd_mempool_t *pool,
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
						html_tag *tag,
						GList **exceptions,
						khash_t (rspamd_url_hash) *url_set) -> goffset
{
	auto is_visible = true, is_block = false, is_spaces = false, is_transparent = false;
	goffset next_tag_offset = tag->closing.end,
			initial_parsed_offset = hc->parsed.size(),
			initial_invisible_offset = hc->invisible.size();

	auto calculate_final_tag_offsets = [&]() -> void {
		if (is_visible) {
			tag->content_offset = initial_parsed_offset;
			tag->closing.start = hc->parsed.size();
		}
		else {
			tag->content_offset = initial_invisible_offset;
			tag->closing.start = hc->invisible.size();
		}
	};

	if (tag->closing.end == -1) {
		if (tag->closing.start != -1) {
			next_tag_offset = tag->closing.start;
			tag->closing.end = tag->closing.start;
		}
		else {
			next_tag_offset = tag->content_offset;
			tag->closing.end = tag->content_offset;
		}
	}
	if (tag->closing.start == -1) {
		tag->closing.start = tag->closing.end;
	}

	auto append_margin = [&](char c) -> void {
		/* We do care about visible margins only */
		if (is_visible) {
			if (!hc->parsed.empty() && hc->parsed.back() != c && hc->parsed.back() != '\n') {
				if (hc->parsed.back() == ' ') {
					/* We also strip extra spaces at the end, but limiting the start */
					auto last = std::make_reverse_iterator(hc->parsed.begin() + initial_parsed_offset);
					auto first = std::find_if(hc->parsed.rbegin(), last,
							[](auto ch) -> auto {
								return ch != ' ';
							});
					hc->parsed.erase(first.base(), hc->parsed.end());
					g_assert(hc->parsed.size() >= initial_parsed_offset);
				}
				hc->parsed.push_back(c);
			}
		}
	};

	if (tag->id == Tag_BR || tag->id == Tag_HR) {

		if (!(tag->flags & FL_IGNORE)) {
			hc->parsed.append("\n");
		}

		auto ret = tag->content_offset;
		calculate_final_tag_offsets();

		return ret;
	}
	else if ((tag->id == Tag_HEAD && (tag->flags & FL_IGNORE)) || (tag->flags & CM_HEAD)) {
		auto ret = tag->closing.end;
		calculate_final_tag_offsets();

		return ret;
	}

	if ((tag->flags & (FL_COMMENT | FL_XML | FL_IGNORE | CM_HEAD))) {
		is_visible = false;
	}
	else {
		if (!tag->block) {
			is_visible = true;
		}
		else if (!tag->block->is_visible()) {
			if (!tag->block->is_transparent()) {
				is_visible = false;
			}
			else {
				if (tag->block->has_display() &&
					tag->block->display == css::css_display_value::DISPLAY_HIDDEN) {
					is_visible = false;
				}
				else {
					is_transparent = true;
				}
			}
		}
		else {
			if (tag->block->display == css::css_display_value::DISPLAY_BLOCK) {
				is_block = true;
			}
			else if (tag->block->display == css::css_display_value::DISPLAY_TABLE_ROW) {
				is_spaces = true;
			}
		}
	}

	if (is_block) {
		append_margin('\n');
	}
	else if (is_spaces) {
		append_margin(' ');
	}

	goffset cur_offset = tag->content_offset;

	for (auto *cld : tag->children) {
		auto enclosed_start = cld->tag_start;
		goffset initial_part_len = enclosed_start - cur_offset;

		if (initial_part_len > 0) {
			if (is_visible) {
				html_append_parsed(hc,
						{start + cur_offset, std::size_t(initial_part_len)},
						is_transparent, len, hc->parsed);
			}
			else {
				html_append_parsed(hc,
						{start + cur_offset, std::size_t(initial_part_len)},
						is_transparent, len, hc->invisible);
			}
		}

		auto next_offset = html_append_tag_content(pool, start, len,
				hc, cld, exceptions, url_set);

		/* Do not allow shifting back */
		if (next_offset > cur_offset) {
			cur_offset = next_offset;
		}
	}

	if (cur_offset < tag->closing.start) {
		goffset final_part_len = tag->closing.start - cur_offset;

		if (final_part_len > 0) {
			if (is_visible) {
				html_append_parsed(hc,
						{start + cur_offset, std::size_t(final_part_len)},
						is_transparent,
						len,
						hc->parsed);
			}
			else {
				html_append_parsed(hc,
						{start + cur_offset, std::size_t(final_part_len)},
						is_transparent,
						len,
						hc->invisible);
			}
		}
	}
	if (is_block) {
		append_margin('\n');
	}
	else if (is_spaces) {
		append_margin(' ');
	}

	if (is_visible) {
		if (tag->id == Tag_A) {
			auto written_len = hc->parsed.size() - initial_parsed_offset;
			html_process_displayed_href_tag(pool, hc,
					{hc->parsed.data() + initial_parsed_offset, std::size_t(written_len)},
					tag, exceptions,
					url_set, initial_parsed_offset);
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

				if (!hc->parsed.empty() && !g_ascii_isspace (hc->parsed.back())) {
					/* Add a space */
					hc->parsed += ' ';
				}
			}
		}
	}
	else {
		/* Invisible stuff */
		if (std::holds_alternative<rspamd_url *>(tag->extra)) {
			auto *url_enclosed = std::get<rspamd_url *>(tag->extra);

			/*
			 * TODO: when hash is fixed to include flags we need to remove and add
			 * url to the hash set
			 */
			if (url_enclosed) {
				url_enclosed->flags |= RSPAMD_URL_FLAG_INVISIBLE;
			}
		}
	}

	calculate_final_tag_offsets();

	return next_tag_offset;
}

auto
html_process_input(rspamd_mempool_t *pool,
				   GByteArray *in,
				   GList **exceptions,
				   khash_t (rspamd_url_hash) *url_set,
				   GPtrArray *part_urls,
				   bool allow_css) -> html_content *
{
	const gchar *p, *c, *end, *start;
	guchar t;
	auto closing = false;
	guint obrace = 0, ebrace = 0;
	struct rspamd_url *url = nullptr;
	gint href_offset = -1;
	struct html_tag *cur_tag = nullptr, *parent_tag = nullptr, cur_closing_tag;
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
		tag_end_opening,
		tag_end_closing,
		html_text_content,
		xml_tag_end,
		tag_raw_text,
		tag_raw_text_less_than,
		tags_limit_overflow,
	} state = parse_start;

	enum class html_document_state {
		doctype,
		head,
		body
	} html_document_state = html_document_state::doctype;

	g_assert (in != NULL);
	g_assert (pool != NULL);

	struct html_content *hc = new html_content;
	rspamd_mempool_add_destructor(pool, html_content::html_content_dtor, hc);

	auto new_tag = [&](int flags = 0) -> struct html_tag * {

		if (hc->all_tags.size() > rspamd::html::max_tags) {
			hc->flags |= RSPAMD_HTML_FLAG_TOO_MANY_TAGS;

			return nullptr;
		}

		hc->all_tags.emplace_back(std::make_unique<html_tag>());
		auto *ntag = hc->all_tags.back().get();
		ntag->tag_start = c - start;
		ntag->flags = flags;

		if (cur_tag && !(cur_tag->flags & (CM_EMPTY | FL_CLOSED)) && cur_tag != &cur_closing_tag) {
			parent_tag = cur_tag;
		}

		if (flags & FL_XML) {
			return ntag;
		}

		return ntag;
	};

	auto process_opening_tag = [&]() {
		if (cur_tag->id > Tag_UNKNOWN) {
			if (cur_tag->flags & CM_UNIQUE) {
				if (!hc->tags_seen[cur_tag->id]) {
					/* Duplicate tag has been found */
					hc->flags |= RSPAMD_HTML_FLAG_DUPLICATE_ELEMENTS;
				}
			}
			hc->tags_seen[cur_tag->id] = true;
		}

		/* Shift to the first unclosed tag */
		auto *pt = parent_tag;
		while (pt && (pt->flags & FL_CLOSED)) {
			pt = pt->parent;
		}

		if (pt) {
			g_assert(cur_tag != pt);
			cur_tag->parent = pt;
			g_assert(cur_tag->parent != &cur_closing_tag);
			parent_tag = pt;
			parent_tag->children.push_back(cur_tag);
		}
		else {
			if (hc->root_tag) {
				if (cur_tag != hc->root_tag) {
					cur_tag->parent = hc->root_tag;
					g_assert(cur_tag->parent != cur_tag);
					hc->root_tag->children.push_back(cur_tag);
					parent_tag = hc->root_tag;
				}
			}
			else {
				if (cur_tag->id == Tag_HTML) {
					hc->root_tag = cur_tag;
				}
				else {
					/* Insert a fake html tag */
					hc->all_tags.emplace_back(std::make_unique<html_tag>());
					auto *top_tag = hc->all_tags.back().get();
					top_tag->tag_start = 0;
					top_tag->flags = FL_VIRTUAL;
					top_tag->id = Tag_HTML;
					top_tag->content_offset = 0;
					top_tag->children.push_back(cur_tag);
					cur_tag->parent = top_tag;
					g_assert(cur_tag->parent != cur_tag);
					hc->root_tag = top_tag;
					parent_tag = top_tag;
				}
			}
		}

		if (cur_tag->flags & FL_HREF && html_document_state == html_document_state::body) {
			auto maybe_url = html_process_url_tag(pool, cur_tag, hc);

			if (maybe_url) {
				url = maybe_url.value();

				if (url_set != NULL) {
					struct rspamd_url *maybe_existing =
							rspamd_url_set_add_or_return(url_set, maybe_url.value());
					if (maybe_existing == maybe_url.value()) {
						html_process_query_url(pool, url, url_set,
								part_urls);
					}
					else {
						url = maybe_existing;
						/* Replace extra as well */
						cur_tag->extra = maybe_existing;
						/* Increase count to avoid odd checks failure */
						url->count++;
					}
				}
				if (part_urls) {
					g_ptr_array_add(part_urls, url);
				}

				href_offset = hc->parsed.size();
			}
		}
		else if (cur_tag->id == Tag_BASE) {
			/*
			 * Base is allowed only within head tag but HTML is retarded
			 */
			auto maybe_url = html_process_url_tag(pool, cur_tag, hc);

			if (maybe_url) {
				msg_debug_html ("got valid base tag");
				cur_tag->extra = maybe_url.value();
				cur_tag->flags |= FL_HREF;

				if (hc->base_url == nullptr) {
					hc->base_url = maybe_url.value();
				}
				else {
					msg_debug_html ("ignore redundant base tag");
				}
			}
			else {
				msg_debug_html ("got invalid base tag!");
			}
		}

		if (cur_tag->id == Tag_IMG) {
			html_process_img_tag(pool, cur_tag, hc, url_set,
					part_urls);
		}
		else if (cur_tag->id == Tag_LINK) {
			html_process_link_tag(pool, cur_tag, hc, url_set,
					part_urls);
		}

		if (!(cur_tag->flags & CM_EMPTY)) {
			html_process_block_tag(pool, cur_tag, hc);
		}
		else {
			/* Implicitly close */
			cur_tag->flags |= FL_CLOSED;
		}

		if (cur_tag->flags & FL_CLOSED) {
			cur_tag->closing.end = cur_tag->content_offset;
			cur_tag->closing.start = cur_tag->tag_start;

			cur_tag = parent_tag;
		}
	};

	p = (const char *) in->data;
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
				cur_tag = new_tag();
				html_document_state = html_document_state::body;

				if (cur_tag) {
					cur_tag->id = Tag_HTML;
					hc->root_tag = cur_tag;
					state = content_before_start;
				}
				else {
					state = tags_limit_overflow;
				}
			}
			break;
		case content_before_start:
			if (t == '<') {
				state = tag_begin;
			}
			else {
				p++;
			}
			break;
		case tag_begin:
			switch (t) {
			case '<':
				c = p;
				p++;
				closing = FALSE;
				break;
			case '!':
				cur_tag = new_tag(FL_XML | FL_CLOSED);
				if (cur_tag) {
					state = sgml_tag;
				}
				else {
					state = tags_limit_overflow;
				}
				p++;
				break;
			case '?':
				cur_tag = new_tag(FL_XML | FL_CLOSED);
				if (cur_tag) {
					state = xml_tag;
				}
				else {
					state = tags_limit_overflow;
				}
				hc->flags |= RSPAMD_HTML_FLAG_XML;
				p++;
				break;
			case '/':
				closing = TRUE;
				/* We fill fake closing tag to fill it with the content parser */
				cur_closing_tag.clear();
				/*
				 * For closing tags, we need to find some corresponding opening tag.
				 * However, at this point we have not even parsed a name, so we
				 * can not assume anything about balancing, etc.
				 *
				 * So we need to ensure that:
				 * 1) We have some opening tag in the chain cur_tag->parent...
				 * 2) cur_tag is nullptr - okay, html is just brain damaged
				 * 3) cur_tag must NOT be equal to cur_closing tag. It means that
				 * we had some poor closing tag but we still need to find an opening
				 * tag... Somewhere...
				 */

				if (cur_tag == &cur_closing_tag) {
					if (parent_tag != &cur_closing_tag) {
						cur_closing_tag.parent = parent_tag;
					}
					else {
						cur_closing_tag.parent = nullptr;
					}
				}
				else if (cur_tag && cur_tag->flags & FL_CLOSED) {
					/* Cur tag is already closed, we should find something else */
					auto *tmp = cur_tag;
					while (tmp) {
						tmp = tmp->parent;

						if (tmp == nullptr || !(tmp->flags & FL_CLOSED)) {
							break;
						}
					}

					cur_closing_tag.parent = tmp;
				}
				else {
					cur_closing_tag.parent = cur_tag;
				}

				cur_tag = &cur_closing_tag;
				p++;
				break;
			case '>':
				/* Empty tag */
				hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
				state = html_text_content;
				continue;
			default:
				if (g_ascii_isalpha(t)) {
					state = tag_content;
					content_parser_env.reset();

					if (!closing) {
						cur_tag = new_tag();
					}

					if (cur_tag) {
						state = tag_content;
					}
					else {
						state = tags_limit_overflow;
					}
				}
				else {
					/* Wrong bad tag */
					state = html_text_content;
				}
				break;
			}

			break;

		case sgml_tag:
			switch (t) {
			case '[':
				state = compound_tag;
				obrace = 1;
				ebrace = 0;
				p++;
				break;
			case '-':
				cur_tag->flags |= FL_COMMENT;
				state = comment_tag;
				p++;
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
				state = tag_end_opening;
				continue;
			}
			/* We efficiently ignore xml tags */
			p++;
			break;

		case xml_tag_end:
			if (t == '>') {
				state = tag_end_opening;
				cur_tag->content_offset = p - start + 1;
				continue;
			}
			else {
				hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
			}
			p++;
			break;

		case compound_tag:
			if (t == '[') {
				obrace++;
			}
			else if (t == ']') {
				ebrace++;
			}
			else if (t == '>' && obrace == ebrace) {
				state = tag_end_opening;
				cur_tag->content_offset = p - start + 1;
				continue;
			}
			p++;
			break;

		case comment_tag:
			if (t != '-') {
				hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
				state = tag_end_opening;
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
					p++;
					state = tag_end_opening;
				}
				else if (*p == '>') {
					hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
					state = tag_end_opening;
				}
				else {
					state = comment_content;
				}
			}
			break;

		case comment_content:
			if (t == '-') {
				ebrace++;
			}
			else if (t == '>' && ebrace >= 2) {
				cur_tag->content_offset = p - start + 1;
				state = tag_end_opening;
				continue;
			}
			else {
				ebrace = 0;
			}

			p++;
			break;

		case html_text_content:
			if (t != '<') {
				p++;
			}
			else {
				state = tag_begin;
			}
			break;

		case tag_raw_text:
			if (t == '<') {
				c = p;
				state = tag_raw_text_less_than;
			}
			p ++;
			break;
		case tag_raw_text_less_than:
			if (t == '/') {
				/* Here are special things: we look for obrace and then ensure
				 * that if there is any closing brace nearby
				 * (we look maximum at 30 characters). We also need to ensure
				 * that we have no special characters, such as punctuation marks and
				 * so on.
				 * Basically, we validate the input to be sane.
				 * Since closing tags must not have attributes, these assumptions
				 * seems to be reasonable enough for our toy parser.
				 */
				gint cur_lookahead = 1;
				gint max_lookahead = MIN (end - p, 30);
				bool valid_closing_tag = true;

				if (p + 1 < end && !g_ascii_isalpha (p[1])) {
					valid_closing_tag = false;
				}
				else {
					while (cur_lookahead < max_lookahead) {
						gchar tt = p[cur_lookahead];
						if (tt == '>') {
							break;
						}
						else if (tt < '\n' || tt == ',') {
							valid_closing_tag = false;
							break;
						}
						cur_lookahead ++;
					}

					if (cur_lookahead == max_lookahead) {
						valid_closing_tag = false;
					}
				}

				if (valid_closing_tag) {
					/* Shift back */
					p = c;
					state = tag_begin;
				}
				else {
					p ++;
					state = tag_raw_text;
				}
			}
			else {
				p ++;
				state = tag_raw_text;
			}
			break;
		case sgml_content:
			/* TODO: parse DOCTYPE here */
			if (t == '>') {
				cur_tag->content_offset = p - start + 1;
				state = tag_end_opening;
			}
			else {
				p++;
			}
			break;

		case tag_content:
			html_parse_tag_content(pool, hc, cur_tag, p, content_parser_env);

			if (t == '>') {
				if (closing) {
					cur_tag->closing.start = c - start;
					cur_tag->closing.end = p - start + 1;

					closing = FALSE;
					state = tag_end_closing;
				}
				else {
					cur_tag->content_offset = p - start + 1;
					state = tag_end_opening;
				}


				continue;
			}
			p++;
			break;

		case tag_end_opening:
			content_parser_env.reset();
			state = html_text_content;

			if (cur_tag) {
				if (cur_tag->id == Tag_STYLE || cur_tag->id == Tag_NOSCRIPT || cur_tag->id == Tag_SCRIPT) {
					state = tag_raw_text;
				}
				if (html_document_state == html_document_state::doctype) {
					if (cur_tag->id == Tag_HEAD || (cur_tag->flags & CM_HEAD)) {
						html_document_state = html_document_state::head;
						cur_tag->flags |= FL_IGNORE;
					}
					else if (cur_tag->id != Tag_HTML) {
						html_document_state = html_document_state::body;
					}
				}
				else if (html_document_state == html_document_state::head) {
					if (!(cur_tag->flags & (CM_EMPTY | CM_HEAD))) {
						if (parent_tag && (parent_tag->id == Tag_HEAD || !(parent_tag->flags & CM_HEAD))) {
							/*
							 * As by standard, we have to close the HEAD tag
							 * and switch to the body state
							 */
							parent_tag->flags |= FL_CLOSED;
							parent_tag->closing.start = cur_tag->tag_start;
							parent_tag->closing.end = cur_tag->content_offset;

							html_document_state = html_document_state::body;
						}
						else if (cur_tag->id == Tag_BODY) {
							html_document_state = html_document_state::body;
						}
						else {
							/*
							 * For propagation in something like
							 * <title><p><a>ololo</a></p></title> - should be unprocessed
							 */
							cur_tag->flags |= CM_HEAD;
						}
					}
				}

				process_opening_tag();
			}

			p++;
			c = p;
			break;
		case tag_end_closing: {
			if (cur_tag) {

				if (cur_tag->flags & CM_EMPTY) {
					/* Ignore closing empty tags */
					cur_tag->flags |= FL_IGNORE;
				}
				if (html_document_state == html_document_state::doctype) {

				}
				else if (html_document_state == html_document_state::head) {
					if (cur_tag->id == Tag_HEAD) {
						html_document_state = html_document_state::body;
					}
				}

				/* cur_tag here is a closing tag */
				auto *next_cur_tag = html_check_balance(hc, cur_tag,
						c - start, p - start + 1);

				if (cur_tag->id == Tag_STYLE && allow_css) {
					auto *opening_tag = cur_tag->parent;

					if (opening_tag && opening_tag->id == Tag_STYLE &&
						(int)opening_tag->content_offset < opening_tag->closing.start) {
						auto ret_maybe = rspamd::css::parse_css(pool,
								{start + opening_tag->content_offset,
								 opening_tag->closing.start - opening_tag->content_offset},
								std::move(hc->css_style));

						if (!ret_maybe.has_value()) {
							if (ret_maybe.error().is_fatal()) {
								auto err_str = fmt::format(
										"cannot parse css (error code: {}): {}",
										static_cast<int>(ret_maybe.error().type),
										ret_maybe.error().description.value_or("unknown error"));
								msg_info_pool ("%*s", (int) err_str.size(), err_str.data());
							}
						}
						else {
							hc->css_style = ret_maybe.value();
						}
					}
				}

				if (next_cur_tag != nullptr) {
					cur_tag = next_cur_tag;
				}
				else {
					/*
					 * Here, we handle cases like <p>lala</b>...
					 * So the tag </b> is bogus and unpaired
					 * However, we need to exclude it from the output of <p> tag
					 * To do that, we create a fake opening tag and insert that to
					 * the current opening tag
					 */
					auto *cur_opening_tag = cur_tag->parent;

					while (cur_opening_tag && (cur_opening_tag->flags & FL_CLOSED)) {
						cur_opening_tag = cur_opening_tag->parent;
					}

					if (!cur_opening_tag) {
						cur_opening_tag = hc->root_tag;
					}

					auto &&vtag = std::make_unique<html_tag>();
					vtag->id = cur_tag->id;
					vtag->flags = FL_VIRTUAL | FL_CLOSED | cur_tag->flags;
					vtag->tag_start = cur_tag->closing.start;
					vtag->content_offset = p - start + 1;
					vtag->closing = cur_tag->closing;
					vtag->parent = cur_opening_tag;
					g_assert(vtag->parent != &cur_closing_tag);
					cur_opening_tag->children.push_back(vtag.get());
					hc->all_tags.emplace_back(std::move(vtag));
					cur_tag = cur_opening_tag;
					parent_tag = cur_tag->parent;
					g_assert(cur_tag->parent != &cur_closing_tag);
				}
			} /* if cur_tag != nullptr */
			state = html_text_content;
			p++;
			c = p;
			break;
		}
		case tags_limit_overflow:
			msg_warn_pool("tags limit of %d tags is reached at the position %d;"
						  " ignoring the rest of the HTML content",
					(int) hc->all_tags.size(), (int) (p - start));
			c = p;
			p = end;
			break;
		}
	}

	if (cur_tag && !(cur_tag->flags & FL_CLOSED) && cur_tag != &cur_closing_tag) {
		cur_closing_tag.parent = cur_tag;
		cur_closing_tag.id = cur_tag->id;
		cur_tag = &cur_closing_tag;
		html_check_balance(hc, cur_tag,
				end - start, end - start);
	}

	/* Propagate styles */
	hc->traverse_block_tags([&hc, &pool](const html_tag *tag) -> bool {

		if (hc->css_style) {
			auto *css_block = hc->css_style->check_tag_block(tag);

			if (css_block) {
				if (tag->block) {
					tag->block->set_block(*css_block);
				}
				else {
					tag->block = css_block;
				}
			}
		}
		if (tag->block) {
			if (!tag->block->has_display()) {
				/* If we have no display field, we can check it by tag */
				if (tag->flags & CM_HEAD) {
					tag->block->set_display(css::css_display_value::DISPLAY_HIDDEN,
							html_block::set);
				}
				else if (tag->flags & (CM_BLOCK | CM_TABLE)) {
					tag->block->set_display(css::css_display_value::DISPLAY_BLOCK,
							html_block::implicit);
				}
				else if (tag->flags & CM_ROW) {
					tag->block->set_display(css::css_display_value::DISPLAY_TABLE_ROW,
							html_block::implicit);
				}
				else {
					tag->block->set_display(css::css_display_value::DISPLAY_INLINE,
							html_block::implicit);
				}
			}

			tag->block->compute_visibility();

			for (const auto *cld_tag : tag->children) {

				if (cld_tag->block) {
					cld_tag->block->propagate_block(*tag->block);
				}
				else {
					cld_tag->block = rspamd_mempool_alloc0_type(pool, html_block);
					*cld_tag->block = *tag->block;
				}
			}
		}
		return true;
	}, html_content::traverse_type::PRE_ORDER);

	/* Leftover before content */
	switch (state) {
	case tag_end_opening:
		if (cur_tag != nullptr) {
			process_opening_tag();
		}
		break;
	default:
		/* Do nothing */
		break;
	}

	if (!hc->all_tags.empty() && hc->root_tag) {
		html_append_tag_content(pool, start, end - start, hc, hc->root_tag,
				exceptions, url_set);
	}

	/* Leftover after content */
	switch (state) {
	case tags_limit_overflow:
		html_append_parsed(hc, {c, (std::size_t) (end - c)},
				false, end - start, hc->parsed);
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

auto
html_debug_structure(const html_content &hc) -> std::string
{
	std::string output;

	if (hc.root_tag) {
		auto rec_functor = [&](const html_tag *t, int level, auto rec_functor) -> void {
			std::string pluses(level, '+');

			if (!(t->flags & (FL_VIRTUAL | FL_IGNORE))) {
				if (t->flags & FL_XML) {
					output += fmt::format("{}xml;", pluses);
				}
				else {
					output += fmt::format("{}{};", pluses,
							html_tags_defs.name_by_id_safe(t->id));
				}
				level++;
			}
			for (const auto *cld : t->children) {
				rec_functor(cld, level, rec_functor);
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

auto
html_tag::get_content(const struct html_content *hc) const -> std::string_view
{
	const std::string *dest = &hc->parsed;

	if (block && !block->is_visible()) {
		dest = &hc->invisible;
	}
	const auto clen = get_content_length();
	if (content_offset < dest->size()) {
		if (dest->size() - content_offset >= clen) {
			return std::string_view{*dest}.substr(content_offset, clen);
		}
		else {
			return std::string_view{*dest}.substr(content_offset, dest->size() - content_offset);
		}
	}

	return std::string_view{};
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
	auto tname = rspamd::html::html_tags_defs.name_by_id_safe(tag->id);

	if (len) {
		*len = tname.size();
	}

	return tname.data();
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

gsize
rspamd_html_get_tags_count(void *html_content)
{
	auto *hc = rspamd::html::html_content::from_ptr(html_content);

	if (!hc) {
		return 0;
	}

	return hc->all_tags.size();
}