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
#ifndef RSPAMD_HTML_TAG_DEFS_HXX
#define RSPAMD_HTML_TAG_DEFS_HXX

#include "config.h"
#include "html_tags.h"
#include "libutil/cxx/util.hxx"

#include <string>
#include <contrib/robin-hood/robin_hood.h>

namespace rspamd::html {

struct html_tag_def {
	std::string name;
	tag_id_t id;
	guint flags;
};

#define TAG_DEF(id, name, flags) html_tag_def{(name), (id), (flags)}

static const auto html_tag_defs_array = rspamd::array_of<html_tag_def>(
		/* W3C defined elements */
		TAG_DEF(Tag_A, "a", FL_HREF),
		TAG_DEF(Tag_ABBR, "abbr", (CM_INLINE)),
		TAG_DEF(Tag_ACRONYM, "acronym", (CM_INLINE)),
		TAG_DEF(Tag_ADDRESS, "address", (CM_BLOCK)),
		TAG_DEF(Tag_APPLET, "applet", (CM_IMG | CM_INLINE | CM_PARAM)),
		TAG_DEF(Tag_AREA, "area", (CM_BLOCK | CM_EMPTY | FL_HREF)),
		TAG_DEF(Tag_B, "b", (CM_INLINE | FL_BLOCK)),
		TAG_DEF(Tag_BASE, "base", (CM_HEAD | CM_EMPTY)),
		TAG_DEF(Tag_BASEFONT, "basefont", (CM_INLINE | CM_EMPTY)),
		TAG_DEF(Tag_BDO, "bdo", (CM_INLINE)),
		TAG_DEF(Tag_BIG, "big", (CM_INLINE)),
		TAG_DEF(Tag_BLOCKQUOTE, "blockquote", (CM_BLOCK)),
		TAG_DEF(Tag_BODY, "body", (CM_HTML | CM_OPT | CM_OMITST | CM_UNIQUE | FL_BLOCK)),
		TAG_DEF(Tag_BR, "br", (CM_INLINE | CM_EMPTY)),
		TAG_DEF(Tag_BUTTON, "button", (CM_INLINE | FL_BLOCK)),
		TAG_DEF(Tag_CAPTION, "caption", (CM_TABLE)),
		TAG_DEF(Tag_CENTER, "center", (CM_BLOCK)),
		TAG_DEF(Tag_CITE, "cite", (CM_INLINE)),
		TAG_DEF(Tag_CODE, "code", (CM_INLINE)),
		TAG_DEF(Tag_COL, "col", (CM_TABLE | CM_EMPTY)),
		TAG_DEF(Tag_COLGROUP, "colgroup", (CM_TABLE | CM_OPT)),
		TAG_DEF(Tag_DD, "dd", (CM_DEFLIST | CM_OPT | CM_NO_INDENT)),
		TAG_DEF(Tag_DEL, "del", (CM_INLINE | CM_BLOCK)),
		TAG_DEF(Tag_DFN, "dfn", (CM_INLINE)),
		TAG_DEF(Tag_DIR, "dir", (CM_BLOCK)),
		TAG_DEF(Tag_DIV, "div", (CM_BLOCK | FL_BLOCK)),
		TAG_DEF(Tag_DL, "dl", (CM_BLOCK | FL_BLOCK)),
		TAG_DEF(Tag_DT, "dt", (CM_DEFLIST | CM_OPT | CM_NO_INDENT)),
		TAG_DEF(Tag_EM, "em", (CM_INLINE)),
		TAG_DEF(Tag_FIELDSET, "fieldset", (CM_BLOCK)),
		TAG_DEF(Tag_FONT, "font", (FL_BLOCK)),
		TAG_DEF(Tag_FORM, "form", (CM_BLOCK | FL_HREF)),
		TAG_DEF(Tag_FRAME, "frame", (CM_EMPTY | FL_HREF)),
		TAG_DEF(Tag_FRAMESET, "frameset", (CM_HTML)),
		TAG_DEF(Tag_H1, "h1", (CM_BLOCK)),
		TAG_DEF(Tag_H2, "h2", (CM_BLOCK)),
		TAG_DEF(Tag_H3, "h3", (CM_BLOCK)),
		TAG_DEF(Tag_H4, "h4", (CM_BLOCK)),
		TAG_DEF(Tag_H5, "h5", (CM_BLOCK)),
		TAG_DEF(Tag_H6, "h6", (CM_BLOCK)),
		TAG_DEF(Tag_HEAD, "head", (CM_HTML | CM_OPT | CM_OMITST | CM_UNIQUE)),
		TAG_DEF(Tag_HR, "hr", (CM_BLOCK | CM_EMPTY)),
		TAG_DEF(Tag_HTML, "html", (CM_HTML | CM_OPT | CM_OMITST | CM_UNIQUE)),
		TAG_DEF(Tag_I, "i", (CM_INLINE)),
		TAG_DEF(Tag_IFRAME, "iframe", (FL_HREF)),
		TAG_DEF(Tag_IMG, "img", (CM_INLINE | CM_IMG | CM_EMPTY)),
		TAG_DEF(Tag_INPUT, "input", (CM_INLINE | CM_IMG | CM_EMPTY)),
		TAG_DEF(Tag_INS, "ins", (CM_INLINE | CM_BLOCK)),
		TAG_DEF(Tag_ISINDEX, "isindex", (CM_BLOCK | CM_EMPTY)),
		TAG_DEF(Tag_KBD, "kbd", (CM_INLINE)),
		TAG_DEF(Tag_LABEL, "label", (CM_INLINE)),
		TAG_DEF(Tag_LEGEND, "legend", (CM_INLINE)),
		TAG_DEF(Tag_LI, "li", (CM_LIST | CM_OPT | CM_NO_INDENT | FL_BLOCK)),
		TAG_DEF(Tag_LINK, "link", (CM_EMPTY | FL_HREF)),
		TAG_DEF(Tag_LISTING, "listing", (CM_BLOCK)),
		TAG_DEF(Tag_MAP, "map", (CM_INLINE | FL_HREF)),
		TAG_DEF(Tag_MENU, "menu", (CM_BLOCK)),
		TAG_DEF(Tag_META, "meta", (CM_HEAD | CM_INLINE | CM_EMPTY)),
		TAG_DEF(Tag_NOFRAMES, "noframes", (CM_BLOCK)),
		TAG_DEF(Tag_NOSCRIPT, "noscript", (CM_BLOCK | CM_INLINE | CM_RAW)),
		TAG_DEF(Tag_OBJECT, "object", (CM_HEAD | CM_IMG | CM_INLINE | CM_PARAM)),
		TAG_DEF(Tag_OL, "ol", (CM_BLOCK | FL_BLOCK)),
		TAG_DEF(Tag_OPTGROUP, "optgroup", (CM_FIELD | CM_OPT)),
		TAG_DEF(Tag_OPTION, "option", (CM_FIELD | CM_OPT)),
		TAG_DEF(Tag_P, "p", (CM_BLOCK | CM_OPT | FL_BLOCK)),
		TAG_DEF(Tag_PARAM, "param", (CM_INLINE | CM_EMPTY)),
		TAG_DEF(Tag_PLAINTEXT, "plaintext", (CM_BLOCK)),
		TAG_DEF(Tag_PRE, "pre", (CM_BLOCK)),
		TAG_DEF(Tag_Q, "q", (CM_INLINE)),
		TAG_DEF(Tag_RB, "rb", (CM_INLINE)),
		TAG_DEF(Tag_RBC, "rbc", (CM_INLINE)),
		TAG_DEF(Tag_RP, "rp", (CM_INLINE)),
		TAG_DEF(Tag_RT, "rt", (CM_INLINE)),
		TAG_DEF(Tag_RTC, "rtc", (CM_INLINE)),
		TAG_DEF(Tag_RUBY, "ruby", (CM_INLINE)),
		TAG_DEF(Tag_S, "s", (CM_INLINE)),
		TAG_DEF(Tag_SAMP, "samp", (CM_INLINE)),
		TAG_DEF(Tag_SCRIPT, "script", (CM_HEAD | CM_RAW)),
		TAG_DEF(Tag_SELECT, "select", (CM_INLINE | CM_FIELD)),
		TAG_DEF(Tag_SMALL, "small", (CM_INLINE)),
		TAG_DEF(Tag_SPAN, "span", (CM_NO_INDENT | FL_BLOCK)),
		TAG_DEF(Tag_STRIKE, "strike", (CM_INLINE)),
		TAG_DEF(Tag_STRONG, "strong", (CM_INLINE)),
		TAG_DEF(Tag_STYLE, "style", (CM_HEAD | CM_RAW)),
		TAG_DEF(Tag_SUB, "sub", (CM_INLINE)),
		TAG_DEF(Tag_SUP, "sup", (CM_INLINE)),
		TAG_DEF(Tag_TABLE, "table", (CM_BLOCK | FL_BLOCK)),
		TAG_DEF(Tag_TBODY, "tbody", (CM_TABLE | CM_ROWGRP | CM_OPT | FL_BLOCK)),
		TAG_DEF(Tag_TD, "td", (CM_ROW | CM_OPT | CM_NO_INDENT | FL_BLOCK)),
		TAG_DEF(Tag_TEXTAREA, "textarea", (CM_INLINE | CM_FIELD)),
		TAG_DEF(Tag_TFOOT, "tfoot", (CM_TABLE | CM_ROWGRP | CM_OPT)),
		TAG_DEF(Tag_TH, "th", (CM_ROW | CM_OPT | CM_NO_INDENT | FL_BLOCK)),
		TAG_DEF(Tag_THEAD, "thead", (CM_TABLE | CM_ROWGRP | CM_OPT)),
		TAG_DEF(Tag_TITLE, "title", (CM_HEAD | CM_UNIQUE)),
		TAG_DEF(Tag_TR, "tr", (CM_TABLE | CM_OPT | FL_BLOCK)),
		TAG_DEF(Tag_TT, "tt", (CM_INLINE)),
		TAG_DEF(Tag_U, "u", (CM_INLINE)),
		TAG_DEF(Tag_UL, "ul", (CM_BLOCK | FL_BLOCK)),
		TAG_DEF(Tag_VAR, "var", (CM_INLINE)),
		TAG_DEF(Tag_XMP, "xmp", (CM_BLOCK)),
		TAG_DEF(Tag_NEXTID, "nextid", (CM_HEAD | CM_EMPTY))
);

class html_tags_storage {
	robin_hood::unordered_flat_map<std::string_view, html_tag_def> tag_by_name;
	robin_hood::unordered_flat_map<tag_id_t, html_tag_def> tag_by_id;
public:
	html_tags_storage() {
		tag_by_name.reserve(html_tag_defs_array.size());
		tag_by_id.reserve(html_tag_defs_array.size());

		for (const auto &t : html_tag_defs_array) {
			tag_by_name[t.name] = t;
			tag_by_id[t.id] = t;
		}
	}

	auto by_name(std::string_view name) const -> const html_tag_def* {
		auto it = tag_by_name.find(name);

		if (it != tag_by_name.end()) {
			return &(it->second);
		}

		return nullptr;
	}

	auto by_id(int id) const -> const html_tag_def* {
		auto it = tag_by_id.find(static_cast<tag_id_t>(id));
		if (it != tag_by_id.end()) {
			return &(it->second);
		}

		return nullptr;
	}

	auto name_by_id_safe(int id) const -> std::string_view {
		auto it = tag_by_id.find(static_cast<tag_id_t>(id));
		if (it != tag_by_id.end()) {
			return it->second.name;
		}

		return "unknown";
	}
};

}

#endif //RSPAMD_HTML_TAG_DEFS_HXX
