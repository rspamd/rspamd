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
#include "html.h"
#include "images.h"

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
 * - `embeded` - `true` if an image is embedded in a message
 * @return {table} table of images in html part
 */
LUA_FUNCTION_DEF (html, get_images);

/***
 * @method html:get_blocks()
 * Retruns a table of html blocks. Each block provides the following data:
 *
 * `tag` - corresponding tag
 * `color` - a triplet (r g b) for font color
 * `bgcolor` - a triplet (r g b) for background color
 * `style` - rspamd{text} with the full style description
 * @return {table} table of blocks in html part
 */
LUA_FUNCTION_DEF (html, get_blocks);

static const struct luaL_reg htmllib_m[] = {
	LUA_INTERFACE_DEF (html, has_tag),
	LUA_INTERFACE_DEF (html, has_property),
	LUA_INTERFACE_DEF (html, get_images),
	LUA_INTERFACE_DEF (html, get_blocks),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

static struct html_content *
lua_check_html (lua_State * L, gint pos)
{
	void *ud = luaL_checkudata (L, pos, "rspamd{html}");
	luaL_argcheck (L, ud != NULL, pos, "'html' expected");
	return ud ? *((struct html_content **)ud) : NULL;
}

static gint
lua_html_has_tag (lua_State *L)
{
	struct html_content *hc = lua_check_html (L, 1);
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

static gint
lua_html_has_property (lua_State *L)
{
	struct html_content *hc = lua_check_html (L, 1);
	const gchar *propname = luaL_checkstring (L, 2);
	gboolean ret = FALSE;

	if (hc && propname) {
		/*
		 * - `no_html`
		 * - `bad_element`
		 * - `xml`
		 * - `unknown_element`
		 * - `duplicate_element`
		 * - `unbalanced`
		 */
		if (strcmp (propname, "no_html") == 0) {
			ret = hc->flags & RSPAMD_HTML_FLAG_BAD_START;
		}
		else if (strcmp (propname, "bad_element") == 0) {
			ret = hc->flags & RSPAMD_HTML_FLAG_BAD_ELEMENTS;
		}
		else if (strcmp (propname, "xml") == 0) {
			ret = hc->flags & RSPAMD_HTML_FLAG_XML;
		}
		else if (strcmp (propname, "unknown_element") == 0) {
			ret = hc->flags & RSPAMD_HTML_FLAG_UNKNOWN_ELEMENTS;
		}
		else if (strcmp (propname, "duplicate_element") == 0) {
			ret = hc->flags & RSPAMD_HTML_FLAG_DUPLICATE_ELEMENTS;
		}
		else if (strcmp (propname, "unbalanced") == 0) {
			ret = hc->flags & RSPAMD_HTML_FLAG_UNBALANCED;
		}
	}

	lua_pushboolean (L, ret);

	return 1;
}

static gint
lua_html_get_images (lua_State *L)
{
	struct html_content *hc = lua_check_html (L, 1);
	struct html_image *img;
	guint i;

	if (hc != NULL) {
		lua_newtable (L);

		if (hc->images) {
			for (i = 0; i < hc->images->len; i ++) {
				img = g_ptr_array_index (hc->images, i);

				lua_newtable (L);

				if (img->src) {
					lua_pushstring (L, "src");
					lua_pushstring (L, img->src);
					lua_settable (L, -3);
				}

				lua_pushstring (L, "height");
				lua_pushnumber (L, img->height);
				lua_settable (L, -3);
				lua_pushstring (L, "width");
				lua_pushnumber (L, img->width);
				lua_settable (L, -3);
				lua_pushstring (L, "embedded");
				lua_pushboolean (L, img->flags & RSPAMD_HTML_FLAG_IMAGE_EMBEDDED);
				lua_settable (L, -3);

				lua_rawseti (L, -2, i + 1);
			}
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_html_get_blocks (lua_State *L)
{
	struct html_content *hc = lua_check_html (L, 1);
	struct html_block *bl;
	struct rspamd_lua_text *t;
	guint i;

	if (hc != NULL) {
		lua_newtable (L);

		if (hc->blocks) {
			for (i = 0; i < hc->blocks->len; i ++) {
				bl = g_ptr_array_index (hc->blocks, i);

				lua_newtable (L);

				if (bl->tag) {
					lua_pushstring (L, "tag");
					lua_pushlstring (L, bl->tag->name.start, bl->tag->name.len);
					lua_settable (L, -3);
				}

				if (bl->font_color.valid) {
					lua_pushstring (L, "color");
					lua_newtable (L);
					lua_pushnumber (L, bl->font_color.d.comp.r);
					lua_rawseti (L, -2, 1);
					lua_pushnumber (L, bl->font_color.d.comp.g);
					lua_rawseti (L, -2, 2);
					lua_pushnumber (L, bl->font_color.d.comp.b);
					lua_rawseti (L, -2, 3);
					lua_settable (L, -3);
				}
				if (bl->background_color.valid) {
					lua_pushstring (L, "color");
					lua_newtable (L);
					lua_pushnumber (L, bl->background_color.d.comp.r);
					lua_rawseti (L, -2, 1);
					lua_pushnumber (L, bl->background_color.d.comp.g);
					lua_rawseti (L, -2, 2);
					lua_pushnumber (L, bl->background_color.d.comp.b);
					lua_rawseti (L, -2, 3);
					lua_settable (L, -3);
				}

				if (bl->style.len > 0) {
					lua_pushstring (L, "style");
					t = lua_newuserdata (L, sizeof (*t));
					t->start = bl->style.start;
					t->len = bl->style.len;
					t->own = FALSE;
					lua_settable (L, -3);
				}

				lua_rawseti (L, -2, i + 1);
			}
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

void
luaopen_html (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{html}", htmllib_m);
	lua_pop (L, 1);
}
