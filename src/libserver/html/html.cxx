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
#include "rspamd.h"
#include "message.h"
#include "html.h"
#include "html_tags.h"
#include "html.hxx"
#include "libserver/css/css_value.hxx"

#include "url.h"
#include "contrib/libucl/khash.h"
#include "libmime/images.h"
#include "css/css.h"
#include "libutil/cxx/utf8_util.h"

#include "html_tag_defs.hxx"
#include "html_entities.hxx"
#include "html_tag.hxx"
#include "html_url.hxx"

#include <vector>
#include <frozen/unordered_map.h>
#include <frozen/string.h>

#include <unicode/uversion.h>
#include <unicode/ucnv.h>
#if U_ICU_VERSION_MAJOR_NUM >= 46
#include <unicode/uidna.h>
#endif

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
		});

#define msg_debug_html(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_html_log_id, "html", pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(html)

static gboolean
html_check_balance(GNode *node, GNode **cur_level)
{
	struct html_tag *arg = (struct html_tag *)node->data, *tmp;
	GNode *cur;

	if (arg->flags & FL_CLOSING) {
		/* First of all check whether this tag is closing tag for parent node */
		cur = node->parent;
		while (cur && cur->data) {
			tmp = (struct html_tag *)cur->data;
			if (tmp->id == arg->id &&
				(tmp->flags & FL_CLOSED) == 0) {
				tmp->flags |= FL_CLOSED;
				/* Destroy current node as we find corresponding parent node */
				g_node_destroy(node);
				/* Change level */
				*cur_level = cur->parent;
				return TRUE;
			}
			cur = cur->parent;
		}
	}
	else {
		return TRUE;
	}

	return FALSE;
}

static gboolean
html_process_tag(rspamd_mempool_t *pool,
						struct html_content *hc,
						struct html_tag *tag,
						GNode **cur_level,
						gboolean *balanced)
{
	GNode *nnode;
	struct html_tag *parent;

	if (hc->total_tags > rspamd::html::max_tags) {
		hc->flags |= RSPAMD_HTML_FLAG_TOO_MANY_TAGS;
	}

	if (tag->id == -1) {
		/* Ignore unknown tags */
		hc->total_tags++;
		return FALSE;
	}

	if (*cur_level == nullptr) {
		*cur_level = hc->html_tags;
	}

	tag->parent = *cur_level;

	if (!(tag->flags & (CM_INLINE | CM_EMPTY))) {
		/* Block tag */
		if (tag->flags & (FL_CLOSING | FL_CLOSED)) {
			if (!*cur_level) {
				msg_debug_html ("bad parent node");
				return FALSE;
			}

			if (hc->total_tags < rspamd::html::max_tags) {
				nnode = g_node_new(tag);
				g_node_append (*cur_level, nnode);

				if (!html_check_balance(nnode, cur_level)) {
					msg_debug_html (
							"mark part as unbalanced as it has not pairable closing tags");
					hc->flags |= RSPAMD_HTML_FLAG_UNBALANCED;
					*balanced = FALSE;
				}
				else {
					*balanced = TRUE;
				}

				hc->total_tags++;
			}
		}
		else {
			parent = (struct html_tag *)(*cur_level)->data;

			if (parent) {
				if ((parent->flags & FL_IGNORE)) {
					tag->flags |= FL_IGNORE;
				}

				if (!(tag->flags & FL_CLOSED) &&
					!(parent->flags & FL_BLOCK)) {
					/* We likely have some bad nesting */
					if (parent->id == tag->id) {
						/* Something like <a>bla<a>foo... */
						hc->flags |= RSPAMD_HTML_FLAG_UNBALANCED;
						*balanced = FALSE;
						tag->parent = parent->parent;

						if (hc->total_tags < rspamd::html::max_tags) {
							nnode = g_node_new(tag);
							g_node_append (parent->parent, nnode);
							*cur_level = nnode;
							hc->total_tags++;
						}

						return TRUE;
					}
				}
			}

			if (hc->total_tags < rspamd::html::max_tags) {
				nnode = g_node_new(tag);
				g_node_append (*cur_level, nnode);

				if ((tag->flags & FL_CLOSED) == 0) {
					*cur_level = nnode;
				}

				hc->total_tags++;
			}

			if (tag->flags & (CM_HEAD | CM_UNKNOWN | FL_IGNORE)) {
				tag->flags |= FL_IGNORE;

				return FALSE;
			}

		}
	}
	else {
		/* Inline tag */
		parent = (struct html_tag *)(*cur_level)->data;

		if (parent) {
			if (hc->total_tags < rspamd::html::max_tags) {
				nnode = g_node_new(tag);
				g_node_append (*cur_level, nnode);

				hc->total_tags++;
			}
			if ((parent->flags & (CM_HEAD | CM_UNKNOWN | FL_IGNORE))) {
				tag->flags |= FL_IGNORE;

				return FALSE;
			}
		}
	}

	return TRUE;
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
			auto found_it = tag->parameters.find(parser_env.cur_component.value());

			if (found_it == tag->parameters.end()) {
				auto sz = (std::size_t)(in - parser_env.saved_p);
				auto *s = rspamd_mempool_alloc_buffer(pool, sz);
				memcpy(s, parser_env.saved_p, sz);
				sz = rspamd_html_decode_entitles_inplace(s, in - parser_env.saved_p);
				tag->parameters.emplace(parser_env.cur_component.value(),
						std::string_view{s, sz});
			}
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
	auto found_href_it = tag->parameters.find(html_component_type::RSPAMD_HTML_COMPONENT_HREF);

	if (found_href_it != tag->parameters.end()) {
		/* Check base url */
		auto &href_value = found_href_it->second;

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
						hc->base_url->urllen, hc->base_url->string,
						need_slash ? "/" : "",
						(gint) orig_len, href_value.size());
				href_value = {buf, nlen};
			}
			else if (href_value[0] == '/' && href_value[1] != '/') {
				/* Relative to the hostname */
				auto orig_len = href_value.size();
				auto len = orig_len + hc->base_url->hostlen + hc->base_url->protocollen +
					   3 /* for :// */;
				auto *buf = rspamd_mempool_alloc_buffer(pool, len + 1);
				auto nlen = (std::size_t)rspamd_snprintf(buf, len + 1, "%*s://%*s/%*s",
						hc->base_url->protocollen, hc->base_url->string,
						hc->base_url->hostlen, rspamd_url_host_unsafe (hc->base_url),
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
	tag->flags |= FL_IMAGE;

	auto found_href_it = tag->parameters.find(html_component_type::RSPAMD_HTML_COMPONENT_HREF);

	if (found_href_it != tag->parameters.end()) {
		/* Check base url */
		const auto &href_value = found_href_it->second;

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


	auto found_height_it = tag->parameters.find(html_component_type::RSPAMD_HTML_COMPONENT_HEIGHT);
	if (found_height_it != tag->parameters.end()) {
		unsigned long val;

		rspamd_strtoul(found_height_it->second.data(), found_height_it->second.size(), &val);
		img->height = val;
	}

	auto found_width_it = tag->parameters.find(html_component_type::RSPAMD_HTML_COMPONENT_WIDTH);
	if (found_width_it != tag->parameters.end()) {
		unsigned long val;

		rspamd_strtoul(found_width_it->second.data(), found_width_it->second.size(), &val);
		img->width = val;
	}

	/* TODO: rework to css at some time */
	auto found_style_it = tag->parameters.find(html_component_type::RSPAMD_HTML_COMPONENT_STYLE);
	if (found_style_it != tag->parameters.end()) {
		if (found_height_it == tag->parameters.end()) {
			auto style_st = found_style_it->second;
			auto pos = rspamd_substring_search_caseless(style_st.data(),
					style_st.size(),
					"height", sizeof("height") - 1);
			if (pos != -1) {
				auto substr = style_st.substr(pos + sizeof("height") - 1);

				for (auto i = 0; i < substr.size(); i ++) {
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
		if (found_width_it == tag->parameters.end()) {
			auto style_st = found_style_it->second;
			auto pos = rspamd_substring_search_caseless(style_st.data(),
					style_st.size(),
					"width", sizeof("width") - 1);
			if (pos != -1) {
				auto substr = style_st.substr(pos + sizeof("width") - 1);

				for (auto i = 0; i < substr.size(); i ++) {
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

	auto found_alt_it = tag->parameters.find(html_component_type::RSPAMD_HTML_COMPONENT_ALT);

	if (found_alt_it != tag->parameters.end()) {
		if (!hc->parsed.empty() && !g_ascii_isspace (hc->parsed.back())) {
			/* Add a space */
			hc->parsed += ' ';
		}
		hc->parsed.append(found_alt_it->second);

		if (!g_ascii_isspace (hc->parsed.back())) {
			/* Add a space */
			hc->parsed += ' ';
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
	auto found_rel_it = tag->parameters.find(html_component_type::RSPAMD_HTML_COMPONENT_REL);

	if (found_rel_it != tag->parameters.end()) {
		if (found_rel_it->second == "icon") {
			html_process_img_tag(pool, tag, hc, url_set, part_urls);
		}
	}
}

static void
html_process_color(std::string_view input, struct html_color *cl)
{
	const gchar *p = input.data(), *end = input.data() + input.size();
	char hexbuf[7];

	memset(cl, 0, sizeof(*cl));

	if (*p == '#') {
		/* HEX color */
		p++;
		rspamd_strlcpy(hexbuf, p, MIN ((gint) sizeof(hexbuf), end - p + 1));
		cl->d.val = strtoul(hexbuf, NULL, 16);
		cl->d.comp.alpha = 255;
		cl->valid = TRUE;
	}
	else if (input.size() > 4 && rspamd_lc_cmp(p, "rgb", 3) == 0) {
		/* We have something like rgba(x,x,x,x) or rgb(x,x,x) */
		enum {
			obrace,
			num1,
			num2,
			num3,
			num4,
			skip_spaces
		} state = skip_spaces, next_state = obrace;
		gulong r = 0, g = 0, b = 0, opacity = 255;
		const gchar *c;
		gboolean valid = FALSE;

		p += 3;

		if (*p == 'a') {
			p++;
		}

		c = p;

		while (p < end) {
			switch (state) {
			case obrace:
				if (*p == '(') {
					p++;
					state = skip_spaces;
					next_state = num1;
				}
				else if (g_ascii_isspace (*p)) {
					state = skip_spaces;
					next_state = obrace;
				}
				else {
					goto stop;
				}
				break;
			case num1:
				if (*p == ',') {
					if (!rspamd_strtoul(c, p - c, &r)) {
						goto stop;
					}

					p++;
					state = skip_spaces;
					next_state = num2;
				}
				else if (!g_ascii_isdigit (*p)) {
					goto stop;
				}
				else {
					p++;
				}
				break;
			case num2:
				if (*p == ',') {
					if (!rspamd_strtoul(c, p - c, &g)) {
						goto stop;
					}

					p++;
					state = skip_spaces;
					next_state = num3;
				}
				else if (!g_ascii_isdigit (*p)) {
					goto stop;
				}
				else {
					p++;
				}
				break;
			case num3:
				if (*p == ',') {
					if (!rspamd_strtoul(c, p - c, &b)) {
						goto stop;
					}

					valid = TRUE;
					p++;
					state = skip_spaces;
					next_state = num4;
				}
				else if (*p == ')') {
					if (!rspamd_strtoul(c, p - c, &b)) {
						goto stop;
					}

					valid = TRUE;
					goto stop;
				}
				else if (!g_ascii_isdigit (*p)) {
					goto stop;
				}
				else {
					p++;
				}
				break;
			case num4:
				if (*p == ',') {
					if (!rspamd_strtoul(c, p - c, &opacity)) {
						goto stop;
					}

					valid = TRUE;
					goto stop;
				}
				else if (*p == ')') {
					if (!rspamd_strtoul(c, p - c, &opacity)) {
						goto stop;
					}

					valid = TRUE;
					goto stop;
				}
				else if (!g_ascii_isdigit (*p)) {
					goto stop;
				}
				else {
					p++;
				}
				break;
			case skip_spaces:
				if (!g_ascii_isspace (*p)) {
					c = p;
					state = next_state;
				}
				else {
					p++;
				}
				break;
			}
		}

stop:

		if (valid) {
			cl->d.comp.r = r;
			cl->d.comp.g = g;
			cl->d.comp.b = b;
			cl->d.comp.alpha = opacity;
			cl->valid = TRUE;
		}
	}
	else {
		auto maybe_color_value =
				rspamd::css::css_value::maybe_color_from_string(input);

		if (maybe_color_value.has_value()) {
			auto color = maybe_color_value->to_color().value();
			cl->d.val = color.to_number();
			cl->d.comp.alpha = 255; /* Non transparent */
		}
	}
}

/*
 * Target is used for in and out if this function returns TRUE
 */
static auto
html_process_css_size(const gchar *suffix, gsize len,
							 double &tgt)  -> bool
{
	gdouble sz = tgt;
	gboolean ret = FALSE;

	if (len >= 2) {
		if (memcmp(suffix, "px", 2) == 0) {
			sz = (guint) sz; /* Round to number */
			ret = TRUE;
		}
		else if (memcmp(suffix, "em", 2) == 0) {
			/* EM is 16 px, so multiply and round */
			sz = (guint) (sz * 16.0);
			ret = TRUE;
		}
		else if (len >= 3 && memcmp(suffix, "rem", 3) == 0) {
			/* equal to EM in our case */
			sz = (guint) (sz * 16.0);
			ret = TRUE;
		}
		else if (memcmp(suffix, "ex", 2) == 0) {
			/*
			 * Represents the x-height of the element's font.
			 * On fonts with the "x" letter, this is generally the height
			 * of lowercase letters in the font; 1ex = 0.5em in many fonts.
			 */
			sz = (guint) (sz * 8.0);
			ret = TRUE;
		}
		else if (memcmp(suffix, "vw", 2) == 0) {
			/*
			 * Vewport width in percentages:
			 * we assume 1% of viewport width as 8px
			 */
			sz = (guint) (sz * 8.0);
			ret = TRUE;
		}
		else if (memcmp(suffix, "vh", 2) == 0) {
			/*
			 * Vewport height in percentages
			 * we assume 1% of viewport width as 6px
			 */
			sz = (guint) (sz * 6.0);
			ret = TRUE;
		}
		else if (len >= 4 && memcmp(suffix, "vmax", 4) == 0) {
			/*
			 * Vewport width in percentages
			 * we assume 1% of viewport width as 6px
			 */
			sz = (guint) (sz * 8.0);
			ret = TRUE;
		}
		else if (len >= 4 && memcmp(suffix, "vmin", 4) == 0) {
			/*
			 * Vewport height in percentages
			 * we assume 1% of viewport width as 6px
			 */
			sz = (guint) (sz * 6.0);
			ret = TRUE;
		}
		else if (memcmp(suffix, "pt", 2) == 0) {
			sz = (guint) (sz * 96.0 / 72.0); /* One point. 1pt = 1/72nd of 1in */
			ret = TRUE;
		}
		else if (memcmp(suffix, "cm", 2) == 0) {
			sz = (guint) (sz * 96.0 / 2.54); /* 96px/2.54 */
			ret = TRUE;
		}
		else if (memcmp(suffix, "mm", 2) == 0) {
			sz = (guint) (sz * 9.6 / 2.54); /* 9.6px/2.54 */
			ret = TRUE;
		}
		else if (memcmp(suffix, "in", 2) == 0) {
			sz = (guint) (sz * 96.0); /* 96px */
			ret = TRUE;
		}
		else if (memcmp(suffix, "pc", 2) == 0) {
			sz = (guint) (sz * 96.0 / 6.0); /* 1pc = 12pt = 1/6th of 1in. */
			ret = TRUE;
		}
	}
	else if (suffix[0] == '%') {
		/* Percentages from 16 px */
		sz = (guint) (sz / 100.0 * 16.0);
		ret = TRUE;
	}

	if (ret) {
		tgt = sz;
	}

	return ret;
}

static auto
html_process_font_size(const gchar *line, guint len, guint &fs,
							  gboolean is_css) -> void
{
	const gchar *p = line, *end = line + len;
	gchar *err = NULL, numbuf[64];
	gdouble sz = 0;
	gboolean failsafe = FALSE;

	while (p < end && g_ascii_isspace (*p)) {
		p++;
		len--;
	}

	if (g_ascii_isdigit (*p)) {
		rspamd_strlcpy(numbuf, p, MIN (sizeof(numbuf), len + 1));
		sz = strtod(numbuf, &err);

		/* Now check leftover */
		if (sz < 0) {
			sz = 0;
		}
	}
	else {
		/* Ignore the rest */
		failsafe = TRUE;
		sz = is_css ? 16 : 1;
		/* TODO: add textual fonts descriptions */
	}

	if (err && *err != '\0') {
		const gchar *e = err;
		gsize slen;

		/* Skip spaces */
		while (*e && g_ascii_isspace (*e)) {
			e++;
		}

		/* Lowercase */
		slen = strlen(e);
		rspamd_str_lc((gchar *) e, slen);

		if (!html_process_css_size(e, slen, sz)) {
			failsafe = TRUE;
		}
	}
	else {
		/* Failsafe naked number */
		failsafe = TRUE;
	}

	if (failsafe) {
		if (is_css) {
			/*
			 * In css mode we usually ignore sizes, but let's treat
			 * small sizes specially
			 */
			if (sz < 1) {
				sz = 0;
			}
			else {
				sz = 16; /* Ignore */
			}
		}
		else {
			/* In non-css mode we have to check legacy size */
			sz = sz >= 1 ? sz * 16 : 16;
		}
	}

	if (sz > 32) {
		sz = 32;
	}

	fs = sz;
}

static void
html_process_style(rspamd_mempool_t *pool, struct html_block *bl,
				   struct html_content *hc,
				   std::string_view style)
{
	const gchar *p, *c, *end, *key = NULL;
	enum {
		read_key,
		read_colon,
		read_value,
		skip_spaces,
	} state = skip_spaces, next_state = read_key;
	guint klen = 0;
	gdouble opacity = 1.0;

	p = style.data();
	c = p;
	end = p + style.size();

	while (p <= end) {
		switch (state) {
		case read_key:
			if (p == end || *p == ':') {
				key = c;
				klen = p - c;
				state = skip_spaces;
				next_state = read_value;
			}
			else if (g_ascii_isspace (*p)) {
				key = c;
				klen = p - c;
				state = skip_spaces;
				next_state = read_colon;
			}

			p++;
			break;

		case read_colon:
			if (p == end || *p == ':') {
				state = skip_spaces;
				next_state = read_value;
			}

			p++;
			break;

		case read_value:
			if (p == end || *p == ';') {
				if (key && klen && p - c > 0) {
					if ((klen == 5 && g_ascii_strncasecmp(key, "color", 5) == 0)
						|| (klen == 10 && g_ascii_strncasecmp(key, "font-color", 10) == 0)) {

						html_process_color({c, (std::size_t)(p - c)}, &bl->font_color);
						msg_debug_html ("got color: %xd", bl->font_color.d.val);
					}
					else if ((klen == 16 && g_ascii_strncasecmp(key,
							"background-color", 16) == 0) ||
							 (klen == 10 && g_ascii_strncasecmp(key,
									 "background", 10) == 0)) {

						html_process_color({c, (std::size_t)(p - c)}, &bl->background_color);
						msg_debug_html ("got bgcolor: %xd", bl->background_color.d.val);
					}
					else if (klen == 7 && g_ascii_strncasecmp(key, "display", 7) == 0) {
						if (p - c >= 4 && rspamd_substring_search_caseless(c, p - c,
								"none", 4) != -1) {
							bl->visible = FALSE;
							msg_debug_html ("tag is not visible");
						}
					}
					else if (klen == 9 &&
							 g_ascii_strncasecmp(key, "font-size", 9) == 0) {
						html_process_font_size(c, p - c,
								bl->font_size, TRUE);
						msg_debug_html ("got font size: %ud", bl->font_size);
					}
					else if (klen == 7 &&
							 g_ascii_strncasecmp(key, "opacity", 7) == 0) {
						gchar numbuf[64];

						rspamd_strlcpy(numbuf, c,
								MIN (sizeof(numbuf), p - c + 1));
						opacity = strtod(numbuf, NULL);

						if (opacity > 1) {
							opacity = 1;
						}
						else if (opacity < 0) {
							opacity = 0;
						}

						bl->font_color.d.comp.alpha = (guint8) (opacity * 255.0);
					}
					else if (klen == 10 &&
							 g_ascii_strncasecmp(key, "visibility", 10) == 0) {
						if (p - c >= 6 && rspamd_substring_search_caseless(c,
								p - c,
								"hidden", 6) != -1) {
							bl->visible = FALSE;
							msg_debug_html ("tag is not visible");
						}
					}
				}

				key = NULL;
				klen = 0;
				state = skip_spaces;
				next_state = read_key;
			}

			p++;
			break;

		case skip_spaces:
			if (p < end && !g_ascii_isspace (*p)) {
				c = p;
				state = next_state;
			}
			else {
				p++;
			}

			break;
		}
	}
}

static auto
html_process_block_tag(rspamd_mempool_t *pool, struct html_tag *tag,
					   struct html_content *hc) -> void
{
	auto *bl = rspamd_mempool_alloc0_type (pool, struct html_block);
	bl->tag = tag;
	bl->visible = TRUE;
	bl->font_size = (guint) -1;
	bl->font_color.d.comp.alpha = 255;

	auto found_color_it = tag->parameters.find(html_component_type::RSPAMD_HTML_COMPONENT_COLOR);

	if (found_color_it != tag->parameters.end()) {
		html_process_color(found_color_it->second, &bl->font_color);
		msg_debug_html ("tag %*s; got color: %xd",
				(int)tag->name.size(), tag->name.data(),
				bl->font_color.d.val);
	}

	auto found_bgcolor_it = tag->parameters.find(html_component_type::RSPAMD_HTML_COMPONENT_BGCOLOR);

	if (found_bgcolor_it != tag->parameters.end()) {
		html_process_color(found_bgcolor_it->second, &bl->background_color);
		msg_debug_html ("tag %*s; got bgcolor: %xd",
				(int)tag->name.size(), tag->name.data(),
				bl->background_color.d.val);
		if (tag->id == Tag_BODY) {
			/* Set global background color */
			memcpy(&hc->bgcolor, &bl->background_color,
					sizeof(hc->bgcolor));
		}
	}

	auto found_style_it = tag->parameters.find(html_component_type::RSPAMD_HTML_COMPONENT_STYLE);
	if (found_style_it != tag->parameters.end()) {
		html_process_style(pool, bl, hc, found_style_it->second);
		msg_debug_html ("tag: %*s; got style: %*s",
				(int)tag->name.size(), tag->name.data(),
				(int) bl->style.len, bl->style.begin);
	}

	auto found_class_it = tag->parameters.find(html_component_type::RSPAMD_HTML_COMPONENT_CLASS);
	if (found_class_it != tag->parameters.end()) {
		rspamd_ftok_t fstr;
		fstr.begin = found_class_it->second.data();
		fstr.len = found_class_it->second.size();
		bl->html_class = rspamd_mempool_ftokdup (pool, &fstr);
		msg_debug_html ("tag: %*s; got class: %s",
				(int)tag->name.size(), tag->name.data(), bl->html_class);
	}

	hc->blocks.push_back(bl);
	tag->block = bl;
}

static auto
html_propagate_lengths(GNode *node, gpointer _unused) -> gboolean
{
	GNode *child;
	struct html_tag *tag = static_cast<html_tag *>(node->data), *cld_tag;

	if (tag) {
		child = node->children;

		/* Summarize content length from children */
		while (child) {
			cld_tag = static_cast<html_tag *>(child->data);
			tag->content_length += cld_tag->content_length;
			child = child->next;
		}
	}

	return FALSE;
}

static auto
html_propagate_style(struct html_content *hc,
							struct html_tag *tag,
							struct html_block *bl,
							std::vector<struct html_block *> &blocks) -> void
{
	gboolean push_block = FALSE;

	if (blocks.empty()) {
		/* No blocks to propagate */
		return;
	}
	/* Propagate from the parent if needed */
	auto *bl_parent = blocks.back();

	if (!bl->background_color.valid) {
		/* Try to propagate background color from parent nodes */
		if (bl_parent->background_color.valid) {
			memcpy(&bl->background_color, &bl_parent->background_color,
					sizeof(bl->background_color));
		}
	}
	else {
		push_block = TRUE;
	}

	if (!bl->font_color.valid) {
		/* Try to propagate background color from parent nodes */
		if (bl_parent->font_color.valid) {
			memcpy(&bl->font_color, &bl_parent->font_color,
					sizeof(bl->font_color));
		}
	}
	else {
		push_block = TRUE;
	}

	/* Propagate font size */
	if (bl->font_size == (guint) -1) {
		if (bl_parent->font_size != (guint) -1) {
			bl->font_size = bl_parent->font_size;
		}
	}
	else {
		push_block = TRUE;
	}

	/* Set bgcolor to the html bgcolor and font color to black as a last resort */
	if (!bl->font_color.valid) {
		/* Don't touch opacity as it can be set separately */
		bl->font_color.d.comp.r = 0;
		bl->font_color.d.comp.g = 0;
		bl->font_color.d.comp.b = 0;
		bl->font_color.valid = TRUE;
	}
	else {
		push_block = TRUE;
	}

	if (!bl->background_color.valid) {
		memcpy(&bl->background_color, &hc->bgcolor, sizeof(hc->bgcolor));
	}
	else {
		push_block = TRUE;
	}

	if (bl->font_size == (guint) -1) {
		bl->font_size = 16; /* Default for browsers */
	}
	else {
		push_block = TRUE;
	}

	if (push_block && !(tag->flags & FL_CLOSED)) {
		blocks.push_back(bl);
	}
}

using tags_vector = std::vector<std::unique_ptr<struct html_tag>>;

static auto
tags_vector_ptr_dtor(void *ptr)
{
	auto *ptags = (tags_vector *)ptr;

	delete ptags;
}

static auto
html_process_part_full (rspamd_mempool_t *pool,
						GByteArray *in,
						GList **exceptions,
						khash_t (rspamd_url_hash) *url_set,
						GPtrArray *part_urls,
						bool allow_css) -> html_content *
{
	const gchar *p, *c, *end;
	guchar t;
	gboolean closing = FALSE, need_decode = FALSE, save_space = FALSE,
			balanced;
	guint obrace = 0, ebrace = 0;
	GNode *cur_level = NULL;
	struct rspamd_url *url = NULL;
	gint len, href_offset = -1;
	struct html_tag *cur_tag = NULL, *content_tag = NULL;
	std::vector<html_block *> blocks_stack;
	struct tag_content_parser_state content_parser_env;

	enum {
		parse_start = 0,
		tag_begin,
		sgml_tag,
		xml_tag,
		compound_tag,
		comment_tag,
		comment_content,
		sgml_content,
		tag_content,
		tag_end,
		xml_tag_end,
		content_ignore,
		content_write,
		content_style,
		content_ignore_sp
	} state = parse_start;

	g_assert (in != NULL);
	g_assert (pool != NULL);

	struct html_content *hc = new html_content;
	rspamd_mempool_add_destructor(pool, html_content::html_content_dtor, hc);

	p = (const char *)in->data;
	c = p;
	end = p + in->len;

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
				state = content_write;
			}

			break;
		case tag_begin:
			switch (t) {
			case '<':
				p ++;
				closing = FALSE;
				break;
			case '!':
				state = sgml_tag;
				p ++;
				break;
			case '?':
				state = xml_tag;
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

		case content_ignore:
			if (t != '<') {
				p ++;
			}
			else {
				state = tag_begin;
			}
			break;

		case content_write:

			if (t != '<') {
				if (t == '&') {
					need_decode = TRUE;
				}
				else if (g_ascii_isspace (t)) {
					save_space = TRUE;

					if (p > c) {
						if (need_decode) {
							goffset old_offset = hc->parsed.size();

							if (content_tag) {
								if (content_tag->content_length == 0) {
									content_tag->content_offset = old_offset;
								}
							}

							hc->parsed.append(c, p - c);

							len = decode_html_entitles_inplace(
									hc->parsed.data() + old_offset,
									(std::size_t)(p - c));
							hc->parsed.resize(hc->parsed.size() + len - (p - c));

							if (content_tag) {
								content_tag->content_length += len;
							}
						}
						else {
							len = p - c;

							if (content_tag) {
								if (content_tag->content_length == 0) {
									content_tag->content_offset = hc->parsed.size();
								}

								content_tag->content_length += len;
							}

							hc->parsed.append(c, len);
						}
					}

					c = p;
					state = content_ignore_sp;
				}
				else {
					if (save_space) {
						/* Append one space if needed */
						if (!hc->parsed.empty() &&
							!g_ascii_isspace (hc->parsed.back())) {
							hc->parsed += " ";

							if (content_tag) {
								if (content_tag->content_length == 0) {
									/*
									 * Special case
									 * we have a space at the beginning but
									 * we have no set content_offset
									 * so we need to do it here
									 */
									content_tag->content_offset = hc->parsed.size();
								}
								else {
									content_tag->content_length++;
								}
							}
						}
						save_space = FALSE;
					}
				}
			}
			else {
				if (c != p) {

					if (need_decode) {
						goffset old_offset = hc->parsed.size();

						if (content_tag) {
							if (content_tag->content_length == 0) {
								content_tag->content_offset = hc->parsed.size();
							}
						}

						hc->parsed.append(c, p - c);
						len = decode_html_entitles_inplace(
								hc->parsed.data() + old_offset,
								(std::size_t)(p - c));
						hc->parsed.resize(hc->parsed.size() + len - (p - c));

						if (content_tag) {
							content_tag->content_length += len;
						}
					}
					else {
						len = p - c;

						if (content_tag) {
							if (content_tag->content_length == 0) {
								content_tag->content_offset = hc->parsed.size();
							}

							content_tag->content_length += len;
						}

						hc->parsed.append(c, len);
					}
				}

				content_tag = NULL;

				state = tag_begin;
				continue;
			}

			p ++;
			break;

		case content_style: {

			/*
			 * We just search for the first </s substring and then pass
			 * the content to the parser (if needed)
			 */
			goffset end_style = rspamd_substring_search (p, end - p,
					"</", 2);
			if (end_style == -1 || g_ascii_tolower (p[end_style + 2]) != 's') {
				/* Invalid style */
				state = content_ignore;
			}
			else {

				if (allow_css) {
					GError *err = NULL;
					hc->css_style = rspamd_css_parse_style(pool, p, end_style, hc->css_style,
							&err);

					if (err) {
						msg_info_pool ("cannot parse css: %e", err);
						g_error_free (err);
					}
				}

				p += end_style;
				state = tag_begin;
			}
			break;
		}

		case content_ignore_sp:
			if (!g_ascii_isspace (t)) {
				c = p;
				state = content_write;
				continue;
			}

			p ++;
			break;

		case sgml_content:
			/* TODO: parse DOCTYPE here */
			if (t == '>') {
				state = tag_end;
				/* We don't know a lot about sgml tags, ignore them */
				cur_tag = NULL;
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

			if (cur_tag != NULL) {
				balanced = TRUE;

				if (html_process_tag (pool, hc, cur_tag, &cur_level,
						&balanced)) {
					state = content_write;
					need_decode = FALSE;
				}
				else {
					if (cur_tag->id == Tag_STYLE) {
						state = content_style;
					}
					else {
						state = content_ignore;
					}
				}

				if (cur_tag->id != -1 && cur_tag->id < N_TAGS) {
					if (cur_tag->flags & CM_UNIQUE) {
						if (!hc->tags_seen[cur_tag->id]) {
							/* Duplicate tag has been found */
							hc->flags |= RSPAMD_HTML_FLAG_DUPLICATE_ELEMENTS;
						}
					}
					hc->tags_seen[cur_tag->id] = true;
				}

				if (!(cur_tag->flags & (FL_CLOSED|FL_CLOSING))) {
					content_tag = cur_tag;
				}

				/* Handle newlines */
				if (cur_tag->id == Tag_BR || cur_tag->id == Tag_HR) {
					if (!hc->parsed.empty() &&
						hc->parsed.back() != '\n') {

						hc->parsed += "\r\n";

						if (content_tag) {
							if (content_tag->content_length == 0) {
								/*
								 * Special case
								 * we have a \r\n at the beginning but
								 * we have no set content_offset
								 * so we need to do it here
								 */
								content_tag->content_offset = hc->parsed.size();
							}
							else {
								content_tag->content_length += 2;
							}
						}
					}
					save_space = FALSE;
				}

				if ((cur_tag->id == Tag_P ||
					 cur_tag->id == Tag_TR ||
					 cur_tag->id == Tag_DIV)) {
					if (!hc->parsed.empty() &&
						hc->parsed.back() != '\n') {

						hc->parsed += "\r\n";

						if (content_tag) {
							if (content_tag->content_length == 0) {
								/*
								 * Special case
								 * we have a \r\n at the beginning but
								 * we have no set content_offset
								 * so we need to get it here
								 */
								content_tag->content_offset = hc->parsed.size();
							}
							else {
								content_tag->content_length += 2;
							}
						}
					}
					save_space = FALSE;
				}

				/* XXX: uncomment when styles parsing is not so broken */
				if (cur_tag->flags & FL_HREF /* && !(cur_tag->flags & FL_IGNORE) */) {
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

					if (cur_tag->id == Tag_A) {
						if (!balanced && cur_level && cur_level->prev) {
							struct html_tag *prev_tag;
							struct rspamd_url *prev_url;

							prev_tag = static_cast<html_tag *>(cur_level->prev->data);

							if (prev_tag->id == Tag_A &&
								!(prev_tag->flags & (FL_CLOSING)) &&
								std::holds_alternative<rspamd_url *>(prev_tag->extra)) {
								prev_url = std::get<rspamd_url *>(prev_tag->extra);

								std::string_view disp_part{
										hc->parsed.data() + href_offset,
										hc->parsed.size() - href_offset};
								html_check_displayed_url (pool,
										exceptions, url_set,
										disp_part,
										href_offset,
										prev_url);
							}
						}

						if (cur_tag->flags & (FL_CLOSING)) {

							/* Insert exception */
							if (url != NULL && hc->parsed.size() > href_offset) {
								std::string_view disp_part{
										hc->parsed.data() + href_offset,
										hc->parsed.size() - href_offset};
								html_check_displayed_url (pool,
										exceptions, url_set,
										disp_part,
										href_offset,
										url);

							}

							href_offset = -1;
							url = NULL;
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
				else if (cur_tag->flags & FL_BLOCK) {
					struct html_block *bl;

					if (cur_tag->flags & FL_CLOSING) {
						/* Just remove block element from the queue if any */
						if (!blocks_stack.empty()) {
							blocks_stack.pop_back();
						}
					}
					else {
						html_process_block_tag(pool, cur_tag, hc);
						bl = cur_tag->block;

						if (bl) {
							html_propagate_style(hc, cur_tag,
									bl, blocks_stack);

							/* Check visibility */
							if (bl->font_size < 3 ||
								bl->font_color.d.comp.alpha < 10) {

								bl->visible = FALSE;
								msg_debug_html ("tag is not visible: font size: "
												"%d, alpha: %d",
										(int)bl->font_size,
										(int)bl->font_color.d.comp.alpha);
							}

							if (!bl->visible) {
								state = content_ignore;
							}
						}
					}
				}
			}
			else {
				state = content_write;
			}


			p++;
			c = p;
			cur_tag = NULL;
			break;
		}
	}

	if (hc->html_tags) {
		g_node_traverse (hc->html_tags, G_POST_ORDER, G_TRAVERSE_ALL, -1,
				html_propagate_lengths, NULL);
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

}

void *
rspamd_html_process_part_full(rspamd_mempool_t *pool,
							  GByteArray *in, GList **exceptions,
							  khash_t (rspamd_url_hash) *url_set,
							  GPtrArray *part_urls,
							  bool allow_css)
{
	return rspamd::html::html_process_part_full(pool, in, exceptions, url_set,
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