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
#include "html_tags.h"
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
 * Returns a table of html blocks. Each block provides the following data:
 *
 * `tag` - corresponding tag
 * `color` - a triplet (r g b) for font color
 * `bgcolor` - a triplet (r g b) for background color
 * `style` - rspamd{text} with the full style description
 * @return {table} table of blocks in html part
 */
LUA_FUNCTION_DEF (html, get_blocks);

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

static const struct luaL_reg htmllib_m[] = {
	LUA_INTERFACE_DEF (html, has_tag),
	LUA_INTERFACE_DEF (html, has_property),
	LUA_INTERFACE_DEF (html, get_images),
	LUA_INTERFACE_DEF (html, get_blocks),
	LUA_INTERFACE_DEF (html, foreach_tag),
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

static const struct luaL_reg taglib_m[] = {
	LUA_INTERFACE_DEF (html_tag, get_type),
	LUA_INTERFACE_DEF (html_tag, get_extra),
	LUA_INTERFACE_DEF (html_tag, get_parent),
	LUA_INTERFACE_DEF (html_tag, get_flags),
	LUA_INTERFACE_DEF (html_tag, get_content),
	LUA_INTERFACE_DEF (html_tag, get_content_length),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

static struct html_content *
lua_check_html (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{html}");
	luaL_argcheck (L, ud != NULL, pos, "'html' expected");
	return ud ? *((struct html_content **)ud) : NULL;
}

static struct html_tag *
lua_check_html_tag (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{html_tag}");
	luaL_argcheck (L, ud != NULL, pos, "'html_tag' expected");
	return ud ? *((struct html_tag **)ud) : NULL;
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

static void
lua_html_push_image (lua_State *L, struct html_image *img)
{
	struct html_tag **ptag;

	lua_newtable (L);

	if (img->src) {
		lua_pushstring (L, "src");
		lua_pushstring (L, img->src);
		lua_settable (L, -3);
	}

	if (img->tag) {
		lua_pushstring (L, "tag");
		ptag = lua_newuserdata (L, sizeof (gpointer));
		*ptag = img->tag;
		rspamd_lua_setclass (L, "rspamd{html_tag}", -1);
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
}

static gint
lua_html_get_images (lua_State *L)
{
	struct html_content *hc = lua_check_html (L, 1);
	struct html_image *img;

	guint i;

	if (hc != NULL) {
		lua_newtable (L);

		if (hc->images && hc->images->len > 0) {
			for (i = 0; i < hc->images->len; i ++) {
				img = g_ptr_array_index (hc->images, i);
				lua_html_push_image (L, img);
				lua_rawseti (L, -2, i + 1);
			}
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static void
lua_html_push_block (lua_State *L, struct html_block *bl)
{
	struct rspamd_lua_text *t;
	struct html_tag **ptag;

	lua_createtable (L, 0, 4);

	if (bl->tag) {
		lua_pushstring (L, "tag");
		ptag = lua_newuserdata (L, sizeof (gpointer));
		*ptag = bl->tag;
		rspamd_lua_setclass (L, "rspamd{html_tag}", -1);
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
		lua_pushstring (L, "bgcolor");
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
}

static gint
lua_html_get_blocks (lua_State *L)
{
	struct html_content *hc = lua_check_html (L, 1);
	struct html_block *bl;

	guint i;

	if (hc != NULL) {
		lua_createtable (L, hc->blocks->len, 0);

		if (hc->blocks && hc->blocks->len > 0) {
			for (i = 0; i < hc->blocks->len; i ++) {
				bl = g_ptr_array_index (hc->blocks, i);
				lua_html_push_block (L, bl);
				lua_rawseti (L, -2, i + 1);
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

struct lua_html_traverse_ud {
	lua_State *L;
	gint cbref;
	gint tag_id;
};

static gboolean
lua_html_node_foreach_cb (GNode *n, gpointer d)
{
	struct lua_html_traverse_ud *ud = d;
	struct html_tag *tag = n->data, **ptag;

	if (tag && (ud->tag_id == -1 || ud->tag_id == tag->id)) {

		lua_rawgeti (ud->L, LUA_REGISTRYINDEX, ud->cbref);

		ptag = lua_newuserdata (ud->L, sizeof (*ptag));
		*ptag = tag;
		rspamd_lua_setclass (ud->L, "rspamd{html_tag}", -1);
		lua_pushnumber (ud->L, tag->content_length);

		if (lua_pcall (ud->L, 2, 1, 0) != 0) {
			msg_err ("error in foreach_tag callback: %s", lua_tostring (ud->L, -1));
			lua_pop (ud->L, 1);
			return TRUE;
		}

		if (lua_toboolean (ud->L, -1)) {
			lua_pop (ud->L, 1);
			return TRUE;
		}

		lua_pop (ud->L, 1);
	}

	return FALSE;
}

static gint
lua_html_foreach_tag (lua_State *L)
{
	struct html_content *hc = lua_check_html (L, 1);
	struct lua_html_traverse_ud ud;
	const gchar *tagname;
	gint id;

	tagname = luaL_checkstring (L, 2);

	if (hc && tagname && lua_isfunction (L, 3)) {
		if (hc->html_tags) {
			if (strcmp (tagname, "any") == 0) {
				id = -1;
			}
			else {
				id = rspamd_html_tag_by_name (tagname);

				if (id == -1) {
					return luaL_error (L, "invalid tagname: %s", tagname);
				}
			}

			lua_pushvalue (L, 3);
			ud.cbref = luaL_ref (L, LUA_REGISTRYINDEX);
			ud.L = L;
			ud.tag_id = id;

			g_node_traverse (hc->html_tags, G_PRE_ORDER, G_TRAVERSE_ALL, -1,
					lua_html_node_foreach_cb, &ud);

			luaL_unref (L, LUA_REGISTRYINDEX, ud.cbref);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_html_tag_get_type (lua_State *L)
{
	struct html_tag *tag = lua_check_html_tag (L, 1);
	const gchar *tagname;

	if (tag != NULL) {
		tagname = rspamd_html_tag_by_id (tag->id);

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
	struct html_tag *tag = lua_check_html_tag (L, 1), **ptag;
	GNode *node;

	if (tag != NULL) {
		node = tag->parent;

		if (node && node->data) {
			ptag = lua_newuserdata (L, sizeof (gpointer));
			*ptag = node->data;
			rspamd_lua_setclass (L, "rspamd{html_tag}", -1);
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
	struct html_tag *tag = lua_check_html_tag (L, 1);
	gint i = 1;

	if (tag) {
		/* Push flags */
		lua_createtable (L, 4, 0);
		if (tag->flags & FL_CLOSING) {
			lua_pushstring (L, "closing");
			lua_rawseti (L, -2, i++);
		}
		if (tag->flags & FL_CLOSED) {
			lua_pushstring (L, "closed");
			lua_rawseti (L, -2, i++);
		}
		if (tag->flags & FL_BROKEN) {
			lua_pushstring (L, "broken");
			lua_rawseti (L, -2, i++);
		}
		if (tag->flags & FL_XML) {
			lua_pushstring (L, "xml");
			lua_rawseti (L, -2, i++);
		}
		if (tag->flags & RSPAMD_HTML_FLAG_UNBALANCED) {
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
	struct html_tag *tag = lua_check_html_tag (L, 1);
	struct rspamd_lua_text *t;

	if (tag) {
		if (tag->content && tag->content_length) {
			t = lua_newuserdata (L, sizeof (*t));
			rspamd_lua_setclass (L, "rspamd{text}", -1);
			t->start = tag->content;
			t->len = tag->content_length;
			t->own = FALSE;
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
	struct html_tag *tag = lua_check_html_tag (L, 1);

	if (tag) {
		lua_pushnumber (L, tag->content_length);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_html_tag_get_extra (lua_State *L)
{
	struct html_tag *tag = lua_check_html_tag (L, 1);
	struct html_image *img;
	struct rspamd_url **purl;

	if (tag) {
		if (tag->extra) {
			if (tag->id == Tag_A || tag->id == Tag_IFRAME) {
				/* For A that's URL */
				purl = lua_newuserdata (L, sizeof (gpointer));
				*purl = tag->extra;
				rspamd_lua_setclass (L, "rspamd{url}", -1);
			}
			else if (tag->id == Tag_IMG) {
				img = tag->extra;
				lua_html_push_image (L, img);
			}
			else if (tag->flags & FL_BLOCK) {
				lua_html_push_block (L, tag->extra);
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

void
luaopen_html (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{html}", htmllib_m);
	lua_pop (L, 1);
	rspamd_lua_new_class (L, "rspamd{html_tag}", taglib_m);
	lua_pop (L, 1);
}
