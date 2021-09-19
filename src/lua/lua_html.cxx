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
#include "lua_common.h"
#include "message.h"
#include "libserver/html/html.h"
#include "libserver/html/html.hxx"
#include "libserver/html/html_tag.hxx"
#include "libserver/html/html_block.hxx"
#include "images.h"

#include <contrib/robin-hood/robin_hood.h>
#include <frozen/string.h>
#include <frozen/unordered_map.h>

/***
 * @module rspamd_html
 * This module provides different methods to access HTML tags. To get HTML context
 * from an HTML part you could use method `part:get_html()`
 * @example
rspamd_config.R_EMPTY_IMAGE = function(task)
  local tp = task:get_text_parts() -- get text parts in a message

  for _,p in ipairs(tp) do -- iterate over text parts array using `ipairs`
    if p:is_html() then -- if the current part is html part
      local hc = p:get_html() -- we get HTML context
      local len = p:get_length() -- and part's length

      if len < 50 then -- if we have a part that has less than 50 bytes of text
        local images = hc:get_images() -- then we check for HTML images

        if images then -- if there are images
          for _,i in ipairs(images) do -- then iterate over images in the part
            if i['height'] + i['width'] >= 400 then -- if we have a large image
              return true -- add symbol
            end
          end
        end
      end
    end
  end
end
 */

/***
 * @method html:has_tag(name)
 * Checks if a specified tag `name` is presented in a part
 * @param {string} name name of tag to check
 * @return {boolean} `true` if the tag exists in HTML tree
 */
LUA_FUNCTION_DEF (html, has_tag);

/***
 * @method html:check_property(name)
 * Checks if the HTML has a specific property. Here is the list of available properties:
 *
 * - `no_html` - no html tag presented
 * - `bad_element` - part has some broken elements
 * - `xml` - part is xhtml
 * - `unknown_element` - part has some unknown elements
 * - `duplicate_element` - part has some duplicate elements that should be unique (namely, `title` tag)
 * - `unbalanced` - part has unbalanced tags
 * @param {string} name name of property
 * @return {boolean} true if the part has the specified property
 */
LUA_FUNCTION_DEF (html, has_property);

/***
 * @method html:get_images()
 * Returns a table of images found in html. Each image is, in turn, a table with the following fields:
 *
 * - `src` - link to the source
 * - `height` - height in pixels
 * - `width` - width in pixels
 * - `embedded` - `true` if an image is embedded in a message
 * @return {table} table of images in html part
 */
LUA_FUNCTION_DEF (html, get_images);

/***
 * @method html:foreach_tag(tagname, callback)
 * Processes HTML tree calling the specified callback for each tag of the specified
 * type.
 *
 * Callback is called with the following attributes:
 *
 * - `tag`: html tag structure
 * - `content_length`: length of content within a tag
 *
 * Callback function should return `true` to **stop** processing and `false` to continue
 * @return nothing
 */
LUA_FUNCTION_DEF (html, foreach_tag);

/***
 * @method html:get_invisible()
 * Returns invisible content of the HTML data
 * @return
 */
LUA_FUNCTION_DEF (html, get_invisible);

static const struct luaL_reg htmllib_m[] = {
	LUA_INTERFACE_DEF (html, has_tag),
	LUA_INTERFACE_DEF (html, has_property),
	LUA_INTERFACE_DEF (html, get_images),
	LUA_INTERFACE_DEF (html, foreach_tag),
	LUA_INTERFACE_DEF (html, get_invisible),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

/***
 * @method html_tag:get_type()
 * Returns string representation of HTML type for a tag
 * @return {string} type of tag
 */
LUA_FUNCTION_DEF (html_tag, get_type);
/***
 * @method html_tag:get_extra()
 * Returns extra data associated with the tag
 * @return {url|image|nil} extra data associated with the tag
 */
LUA_FUNCTION_DEF (html_tag, get_extra);
/***
 * @method html_tag:get_parent()
 * Returns parent node for a specified tag
 * @return {html_tag} parent object for a specified tag
 */
LUA_FUNCTION_DEF (html_tag, get_parent);

/***
 * @method html_tag:get_flags()
 * Returns flags a specified tag:
 *
 * - `closed`: tag is properly closed
 * - `closing`: tag is a closing tag
 * - `broken`: tag is somehow broken
 * - `unbalanced`: tag is unbalanced
 * - `xml`: tag is xml tag
 * @return {table} table of flags
 */
LUA_FUNCTION_DEF (html_tag, get_flags);
/***
 * @method html_tag:get_content()
 * Returns content of tag (approximate for some cases)
 * @return {rspamd_text} rspamd text with tag's content
 */
LUA_FUNCTION_DEF (html_tag, get_content);
/***
 * @method html_tag:get_content_length()
 * Returns length of a tag's content
 * @return {number} size of content enclosed within a tag
 */
LUA_FUNCTION_DEF (html_tag, get_content_length);

/***
 * @method html_tag:get_style()
 * Returns style calculated for the element
 * @return {table} table associated with the style
 */
LUA_FUNCTION_DEF (html_tag, get_style);

/***
 * @method html_tag:get_style()
 * Returns style calculated for the element
 * @return {table} table associated with the style
 */
LUA_FUNCTION_DEF (html_tag, get_attribute);

static const struct luaL_reg taglib_m[] = {
	LUA_INTERFACE_DEF (html_tag, get_type),
	LUA_INTERFACE_DEF (html_tag, get_extra),
	LUA_INTERFACE_DEF (html_tag, get_parent),
	LUA_INTERFACE_DEF (html_tag, get_flags),
	LUA_INTERFACE_DEF (html_tag, get_content),
	LUA_INTERFACE_DEF (html_tag, get_content_length),
	LUA_INTERFACE_DEF (html_tag, get_style),
	LUA_INTERFACE_DEF (html_tag, get_attribute),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

static struct rspamd::html::html_content *
lua_check_html (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{html}");
	luaL_argcheck (L, ud != NULL, pos, "'html' expected");
	return ud ? *((struct rspamd::html::html_content **)ud) : NULL;
}

struct lua_html_tag {
	rspamd::html::html_content *html;
	const rspamd::html::html_tag *tag;
};

static struct lua_html_tag *
lua_check_html_tag (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{html_tag}");
	luaL_argcheck (L, ud != NULL, pos, "'html_tag' expected");
	return ud ? ((struct lua_html_tag *)ud) : NULL;
}

static gint
lua_html_has_tag (lua_State *L)
{
	LUA_TRACE_POINT;
	auto *hc = lua_check_html (L, 1);
	const gchar *tagname = luaL_checkstring (L, 2);
	gboolean ret = FALSE;

	if (hc && tagname) {
		if (rspamd_html_tag_seen (hc, tagname)) {
			ret = TRUE;
		}
	}

	lua_pushboolean (L, ret);

	return 1;
}

constexpr const auto prop_map = frozen::make_unordered_map<frozen::string, int>({
		{"no_html", RSPAMD_HTML_FLAG_BAD_START},
		{"bad_start", RSPAMD_HTML_FLAG_BAD_START},
		{"bad_element", RSPAMD_HTML_FLAG_BAD_ELEMENTS},
		{"bad_elements", RSPAMD_HTML_FLAG_BAD_ELEMENTS},
		{"xml", RSPAMD_HTML_FLAG_XML},
		{"unknown_element", RSPAMD_HTML_FLAG_UNKNOWN_ELEMENTS},
		{"unknown_elements", RSPAMD_HTML_FLAG_UNKNOWN_ELEMENTS},
		{"duplicate_element", RSPAMD_HTML_FLAG_DUPLICATE_ELEMENTS},
		{"duplicate_elements", RSPAMD_HTML_FLAG_DUPLICATE_ELEMENTS},
		{"unbalanced", RSPAMD_HTML_FLAG_UNBALANCED},
		{"data_urls", RSPAMD_HTML_FLAG_HAS_DATA_URLS},
});

static gint
lua_html_has_property (lua_State *L)
{
	LUA_TRACE_POINT;
	auto *hc = lua_check_html (L, 1);
	const gchar *propname = luaL_checkstring (L, 2);
	gboolean ret = FALSE;

	if (hc && propname) {
		auto found_prop = prop_map.find(frozen::string(propname));

		if (found_prop != prop_map.end()) {
			ret = hc->flags & found_prop->second;
		}
	}

	lua_pushboolean (L, ret);

	return 1;
}

static void
lua_html_push_image (lua_State *L, const struct html_image *img)
{
	LUA_TRACE_POINT;
	struct lua_html_tag *ltag;
	struct rspamd_url **purl;

	lua_createtable (L, 0, 7);

	if (img->src) {
		lua_pushstring (L, "src");

		if (img->flags & RSPAMD_HTML_FLAG_IMAGE_DATA) {
			struct rspamd_lua_text *t;

			t = static_cast<rspamd_lua_text *>(lua_newuserdata(L, sizeof(*t)));
			t->start = img->src;
			t->len = strlen (img->src);
			t->flags = 0;

			rspamd_lua_setclass (L, "rspamd{text}", -1);
		}
		else {
			lua_pushstring (L, img->src);
		}

		lua_settable (L, -3);
	}

	if (img->url) {
		lua_pushstring (L, "url");
		purl = static_cast<rspamd_url **>(lua_newuserdata(L, sizeof(gpointer)));
		*purl = img->url;
		rspamd_lua_setclass (L, "rspamd{url}", -1);
		lua_settable (L, -3);
	}

	if (img->tag) {
		lua_pushstring (L, "tag");
		ltag = static_cast<lua_html_tag *>(lua_newuserdata(L, sizeof(struct lua_html_tag)));
		ltag->tag = static_cast<rspamd::html::html_tag *>(img->tag);
		ltag->html = NULL;
		rspamd_lua_setclass (L, "rspamd{html_tag}", -1);
		lua_settable (L, -3);
	}

	lua_pushstring (L, "height");
	lua_pushinteger (L, img->height);
	lua_settable (L, -3);
	lua_pushstring (L, "width");
	lua_pushinteger (L, img->width);
	lua_settable (L, -3);
	lua_pushstring (L, "embedded");
	lua_pushboolean (L, img->flags & RSPAMD_HTML_FLAG_IMAGE_EMBEDDED);
	lua_settable (L, -3);
	lua_pushstring (L, "data");
	lua_pushboolean (L, img->flags & RSPAMD_HTML_FLAG_IMAGE_DATA);
	lua_settable (L, -3);
}

static gint
lua_html_get_images (lua_State *L)
{
	LUA_TRACE_POINT;
	auto *hc = lua_check_html (L, 1);
	guint i = 1;

	if (hc != NULL) {
		lua_createtable (L, hc->images.size(), 0);

		for (const auto *img : hc->images) {
			lua_html_push_image (L, img);
			lua_rawseti (L, -2, i++);
		}
	}
	else {
		lua_newtable (L);
	}

	return 1;
}

static void
lua_html_push_block (lua_State *L, const struct rspamd::html::html_block *bl)
{
	LUA_TRACE_POINT;

	lua_createtable (L, 0, 6);

	if (bl->fg_color_mask) {
		lua_pushstring (L, "color");
		lua_createtable (L, 4, 0);
		lua_pushinteger (L, bl->fg_color.r);
		lua_rawseti (L, -2, 1);
		lua_pushinteger (L, bl->fg_color.g);
		lua_rawseti (L, -2, 2);
		lua_pushinteger (L, bl->fg_color.b);
		lua_rawseti (L, -2, 3);
		lua_pushinteger (L, bl->fg_color.alpha);
		lua_rawseti (L, -2, 4);
		lua_settable (L, -3);
	}
	if (bl->bg_color_mask) {
		lua_pushstring (L, "bgcolor");
		lua_createtable (L, 4, 0);
		lua_pushinteger (L, bl->bg_color.r);
		lua_rawseti (L, -2, 1);
		lua_pushinteger (L, bl->bg_color.g);
		lua_rawseti (L, -2, 2);
		lua_pushinteger (L, bl->bg_color.b);
		lua_rawseti (L, -2, 3);
		lua_pushinteger (L, bl->bg_color.alpha);
		lua_rawseti (L, -2, 4);
		lua_settable (L, -3);
	}

	if (bl->font_mask) {
		lua_pushstring(L, "font_size");
		lua_pushinteger(L, bl->font_size);
		lua_settable(L, -3);
	}

	lua_pushstring(L, "visible");
	lua_pushboolean(L, bl->is_visible());
	lua_settable(L, -3);

	lua_pushstring(L, "transparent");
	lua_pushboolean(L, bl->is_transparent());
	lua_settable(L, -3);
}

static gint
lua_html_foreach_tag (lua_State *L)
{
	LUA_TRACE_POINT;
	auto *hc = lua_check_html (L, 1);
	const gchar *tagname;
	gint id;
	auto any = false;
	robin_hood::unordered_flat_set<int> tags;


	if (lua_type (L, 2) == LUA_TSTRING) {
		tagname = luaL_checkstring (L, 2);
		if (strcmp (tagname, "any") == 0) {
			any = true;
		}
		else {
			id = rspamd_html_tag_by_name(tagname);

			if (id == -1) {
				return luaL_error (L, "invalid tagname: %s", tagname);
			}


			tags.insert(id);
		}
	}
	else if (lua_type (L, 2) == LUA_TTABLE) {
		lua_pushvalue (L, 2);

		for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
			tagname = luaL_checkstring (L, -1);
			if (strcmp (tagname, "any") == 0) {
				any = TRUE;
			}
			else {
				id = rspamd_html_tag_by_name (tagname);

				if (id == -1) {
					return luaL_error (L, "invalid tagname: %s", tagname);
				}
				tags.insert(id);
			}
		}

		lua_pop (L, 1);
	}

	if (hc && (any || !tags.empty()) && lua_isfunction (L, 3)) {
		hc->traverse_all_tags([&](const rspamd::html::html_tag *tag) -> bool {
			if (tag && (any || tags.contains(tag->id))) {
				lua_pushcfunction (L, &rspamd_lua_traceback);
				auto err_idx = lua_gettop(L);
				lua_pushvalue(L, 3);

				auto *ltag = static_cast<lua_html_tag *>(lua_newuserdata(L, sizeof(lua_html_tag)));
				ltag->tag = tag;
				ltag->html = hc;
				auto ct = ltag->tag->get_content(hc);
				rspamd_lua_setclass (L, "rspamd{html_tag}", -1);
				lua_pushinteger (L, ct.size());

				/* Leaf flag */
				if (tag->children.empty()) {
					lua_pushboolean (L, true);
				}
				else {
					lua_pushboolean (L, false);
				}

				if (lua_pcall (L, 3, 1, err_idx) != 0) {
					msg_err ("error in foreach_tag callback: %s", lua_tostring (L, -1));
					lua_settop(L, err_idx - 1);
					return false;
				}

				if (lua_toboolean (L, -1)) {
					lua_settop(L, err_idx - 1);
					return false;
				}

				lua_settop(L, err_idx - 1);
			}

			return true;
		});
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_html_get_invisible (lua_State *L)
{
	LUA_TRACE_POINT;
	auto *hc = lua_check_html (L, 1);

	if (hc != NULL) {
		lua_new_text (L, hc->invisible.c_str(), hc->invisible.size(), false);
	}
	else {
		lua_newtable (L);
	}

	return 1;
}

static gint
lua_html_tag_get_type (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_html_tag *ltag = lua_check_html_tag (L, 1);
	const gchar *tagname;

	if (ltag != NULL) {
		tagname = rspamd_html_tag_by_id (ltag->tag->id);

		if (tagname) {
			lua_pushstring (L, tagname);
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_html_tag_get_parent (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_html_tag *ltag = lua_check_html_tag (L, 1), *ptag;

	if (ltag != NULL) {
		auto *parent = ltag->tag->parent;

		if (parent) {
			ptag = static_cast<lua_html_tag *>(lua_newuserdata(L, sizeof(*ptag)));
			ptag->tag = static_cast<rspamd::html::html_tag *>(parent);
			ptag->html = ltag->html;
			rspamd_lua_setclass (L, "rspamd{html_tag}", -1);
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_html_tag_get_flags (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_html_tag *ltag = lua_check_html_tag (L, 1);
	gint i = 1;

	if (ltag && ltag->tag) {
		/* Push flags */
		lua_createtable (L, 4, 0);
		if (ltag->tag->flags & FL_HREF) {
			lua_pushstring (L, "href");
			lua_rawseti (L, -2, i++);
		}
		if (ltag->tag->flags & FL_CLOSED) {
			lua_pushstring (L, "closed");
			lua_rawseti (L, -2, i++);
		}
		if (ltag->tag->flags & FL_BROKEN) {
			lua_pushstring (L, "broken");
			lua_rawseti (L, -2, i++);
		}
		if (ltag->tag->flags & FL_XML) {
			lua_pushstring (L, "xml");
			lua_rawseti (L, -2, i++);
		}
		if (ltag->tag->flags & RSPAMD_HTML_FLAG_UNBALANCED) {
			lua_pushstring (L, "unbalanced");
			lua_rawseti (L, -2, i++);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_html_tag_get_content (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_html_tag *ltag = lua_check_html_tag (L, 1);
	struct rspamd_lua_text *t;

	if (ltag) {

		if (ltag->html) {
			auto ct = ltag->tag->get_content(ltag->html);
			if (ct.size() > 0) {
				t = static_cast<rspamd_lua_text *>(lua_newuserdata(L, sizeof(*t)));
				rspamd_lua_setclass(L, "rspamd{text}", -1);
				t->start = ct.data();
				t->len = ct.size();
				t->flags = 0;
			}
			else {
				lua_pushnil (L);
			}
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_html_tag_get_content_length (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_html_tag *ltag = lua_check_html_tag (L, 1);

	if (ltag) {
		if (ltag->html) {
			auto ct = ltag->tag->get_content(ltag->html);
			lua_pushinteger (L, ct.size());
		}
		else {
			lua_pushinteger (L, ltag->tag->get_content_length());
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_html_tag_get_extra (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_html_tag *ltag = lua_check_html_tag (L, 1);
	struct html_image *img;

	if (ltag) {
		if (!std::holds_alternative<std::monostate>(ltag->tag->extra)) {
			if (std::holds_alternative<struct html_image *>(ltag->tag->extra)) {
				img = std::get<struct html_image *>(ltag->tag->extra);
				lua_html_push_image (L, img);
			}
			else if (std::holds_alternative<struct rspamd_url *>(ltag->tag->extra)) {
				/* For A that's URL */
				auto *lua_url =  static_cast<rspamd_lua_url *>(lua_newuserdata(L, sizeof(rspamd_lua_url)));
				lua_url->url = std::get<struct rspamd_url *>(ltag->tag->extra);
				rspamd_lua_setclass (L, "rspamd{url}", -1);
			}
			else {
				/* Unknown extra ? */
				lua_pushnil (L);
			}
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_html_tag_get_style (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_html_tag *ltag = lua_check_html_tag(L, 1);

	if (ltag) {
		if (ltag->tag->block) {
			lua_html_push_block(L, ltag->tag->block);
		}
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

static gint
lua_html_tag_get_attribute (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_html_tag *ltag = lua_check_html_tag(L, 1);
	gsize slen;
	const gchar *attr_name = luaL_checklstring(L, 2, &slen);

	if (ltag && attr_name) {
		auto maybe_attr = ltag->tag->find_component(
				rspamd::html::html_component_from_string({attr_name, slen}));

		if (maybe_attr) {
			lua_pushlstring(L, maybe_attr->data(), maybe_attr->size());
		}
		else {
			lua_pushnil(L);
		}
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

void
luaopen_html (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{html}", htmllib_m);
	lua_pop (L, 1);
	rspamd_lua_new_class (L, "rspamd{html_tag}", taglib_m);
	lua_pop (L, 1);
}
