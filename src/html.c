/*
 * Copyright (c) 2009, Rambler media
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "util.h"
#include "main.h"
#include "message.h"
#include "html.h"

sig_atomic_t tags_sorted = 0;

static struct html_tag tag_defs[] =
{
  /* W3C defined elements */
  { Tag_A,          "a",          (CM_INLINE)},
  { Tag_ABBR,       "abbr",       (CM_INLINE)},
  { Tag_ACRONYM,    "acronym",    (CM_INLINE)},
  { Tag_ADDRESS,    "address",    (CM_BLOCK)},
  { Tag_APPLET,     "applet",     (CM_OBJECT|CM_IMG|CM_INLINE|CM_PARAM)},
  { Tag_AREA,       "area",       (CM_BLOCK|CM_EMPTY)},
  { Tag_B,          "b",          (CM_INLINE)},
  { Tag_BASE,       "base",       (CM_HEAD|CM_EMPTY)},
  { Tag_BASEFONT,   "basefont",   (CM_INLINE|CM_EMPTY)},
  { Tag_BDO,        "bdo",        (CM_INLINE)},
  { Tag_BIG,        "big",        (CM_INLINE)},
  { Tag_BLOCKQUOTE, "blockquote", (CM_BLOCK)},
  { Tag_BODY,       "body",       (CM_HTML|CM_OPT|CM_OMITST)},
  { Tag_BR,         "br",         (CM_INLINE|CM_EMPTY)},
  { Tag_BUTTON,     "button",     (CM_INLINE)},
  { Tag_CAPTION,    "caption",    (CM_TABLE)},
  { Tag_CENTER,     "center",     (CM_BLOCK)},
  { Tag_CITE,       "cite",       (CM_INLINE)},
  { Tag_CODE,       "code",       (CM_INLINE)},
  { Tag_COL,        "col",        (CM_TABLE|CM_EMPTY)},
  { Tag_COLGROUP,   "colgroup",   (CM_TABLE|CM_OPT)},
  { Tag_DD,         "dd",         (CM_DEFLIST|CM_OPT|CM_NO_INDENT)},
  { Tag_DEL,        "del",        (CM_INLINE|CM_BLOCK|CM_MIXED)},
  { Tag_DFN,        "dfn",        (CM_INLINE)},
  { Tag_DIR,        "dir",        (CM_BLOCK|CM_OBSOLETE)},
  { Tag_DIV,        "div",        (CM_BLOCK)},
  { Tag_DL,         "dl",         (CM_BLOCK)},
  { Tag_DT,         "dt",         (CM_DEFLIST|CM_OPT|CM_NO_INDENT)},
  { Tag_EM,         "em",         (CM_INLINE)},
  { Tag_FIELDSET,   "fieldset",   (CM_BLOCK)},
  { Tag_FONT,       "font",       (CM_INLINE)},
  { Tag_FORM,       "form",       (CM_BLOCK)},
  { Tag_FRAME,      "frame",      (CM_FRAMES|CM_EMPTY)},
  { Tag_FRAMESET,   "frameset",   (CM_HTML|CM_FRAMES)},
  { Tag_H1,         "h1",         (CM_BLOCK|CM_HEADING)},
  { Tag_H2,         "h2",         (CM_BLOCK|CM_HEADING)},
  { Tag_H3,         "h3",         (CM_BLOCK|CM_HEADING)},
  { Tag_H4,         "h4",         (CM_BLOCK|CM_HEADING)},
  { Tag_H5,         "h5",         (CM_BLOCK|CM_HEADING)},
  { Tag_H6,         "h6",         (CM_BLOCK|CM_HEADING)},
  { Tag_HEAD,       "head",       (CM_HTML|CM_OPT|CM_OMITST)},
  { Tag_HR,         "hr",         (CM_BLOCK|CM_EMPTY)},
  { Tag_HTML,       "html",       (CM_HTML|CM_OPT|CM_OMITST)},
  { Tag_I,          "i",          (CM_INLINE)},
  { Tag_IFRAME,     "iframe",     (CM_INLINE)},
  { Tag_IMG,        "img",        (CM_INLINE|CM_IMG|CM_EMPTY)},
  { Tag_INPUT,      "input",      (CM_INLINE|CM_IMG|CM_EMPTY)},
  { Tag_INS,        "ins",        (CM_INLINE|CM_BLOCK|CM_MIXED)},
  { Tag_ISINDEX,    "isindex",    (CM_BLOCK|CM_EMPTY)},
  { Tag_KBD,        "kbd",        (CM_INLINE)},
  { Tag_LABEL,      "label",      (CM_INLINE)},
  { Tag_LEGEND,     "legend",     (CM_INLINE)},
  { Tag_LI,         "li",         (CM_LIST|CM_OPT|CM_NO_INDENT)},
  { Tag_LINK,       "link",       (CM_HEAD|CM_EMPTY)},
  { Tag_LISTING,    "listing",    (CM_BLOCK|CM_OBSOLETE)},
  { Tag_MAP,        "map",        (CM_INLINE)},
  { Tag_MENU,       "menu",       (CM_BLOCK|CM_OBSOLETE)},
  { Tag_META,       "meta",       (CM_HEAD|CM_EMPTY)},
  { Tag_NOFRAMES,   "noframes",   (CM_BLOCK|CM_FRAMES)},
  { Tag_NOSCRIPT,   "noscript",   (CM_BLOCK|CM_INLINE|CM_MIXED)},
  { Tag_OBJECT,     "object",     (CM_OBJECT|CM_HEAD|CM_IMG|CM_INLINE|CM_PARAM)},
  { Tag_OL,         "ol",         (CM_BLOCK)},
  { Tag_OPTGROUP,   "optgroup",   (CM_FIELD|CM_OPT)},
  { Tag_OPTION,     "option",     (CM_FIELD|CM_OPT)},
  { Tag_P,          "p",          (CM_BLOCK|CM_OPT)},
  { Tag_PARAM,      "param",      (CM_INLINE|CM_EMPTY)},
  { Tag_PLAINTEXT,  "plaintext",  (CM_BLOCK|CM_OBSOLETE)},
  { Tag_PRE,        "pre",        (CM_BLOCK)},
  { Tag_Q,          "q",          (CM_INLINE)},
  { Tag_RB,         "rb",         (CM_INLINE)},
  { Tag_RBC,        "rbc",        (CM_INLINE)},
  { Tag_RP,         "rp",         (CM_INLINE)},
  { Tag_RT,         "rt",         (CM_INLINE)},
  { Tag_RTC,        "rtc",        (CM_INLINE)},
  { Tag_RUBY,       "ruby",       (CM_INLINE)},
  { Tag_S,          "s",          (CM_INLINE)},
  { Tag_SAMP,       "samp",       (CM_INLINE)},
  { Tag_SCRIPT,     "script",     (CM_HEAD|CM_MIXED|CM_BLOCK|CM_INLINE)},
  { Tag_SELECT,     "select",     (CM_INLINE|CM_FIELD)},
  { Tag_SMALL,      "small",      (CM_INLINE)},
  { Tag_SPAN,       "span",       (CM_INLINE)},
  { Tag_STRIKE,     "strike",     (CM_INLINE)},
  { Tag_STRONG,     "strong",     (CM_INLINE)},
  { Tag_STYLE,      "style",      (CM_HEAD)},
  { Tag_SUB,        "sub",        (CM_INLINE)},
  { Tag_SUP,        "sup",        (CM_INLINE)},
  { Tag_TABLE,      "table",      (CM_BLOCK)},
  { Tag_TBODY,      "tbody",      (CM_TABLE|CM_ROWGRP|CM_OPT)},
  { Tag_TD,         "td",         (CM_ROW|CM_OPT|CM_NO_INDENT)},
  { Tag_TEXTAREA,   "textarea",   (CM_INLINE|CM_FIELD)},
  { Tag_TFOOT,      "tfoot",      (CM_TABLE|CM_ROWGRP|CM_OPT)},
  { Tag_TH,         "th",         (CM_ROW|CM_OPT|CM_NO_INDENT)},
  { Tag_THEAD,      "thead",      (CM_TABLE|CM_ROWGRP|CM_OPT)},
  { Tag_TITLE,      "title",      (CM_HEAD)},
  { Tag_TR,         "tr",         (CM_TABLE|CM_OPT)},
  { Tag_TT,         "tt",         (CM_INLINE)},
  { Tag_U,          "u",          (CM_INLINE)},
  { Tag_UL,         "ul",         (CM_BLOCK)},
  { Tag_VAR,        "var",        (CM_INLINE)},
  { Tag_XMP,        "xmp",        (CM_BLOCK|CM_OBSOLETE)},
  { Tag_NEXTID,     "nextid",     (CM_HEAD|CM_EMPTY)},

  /* proprietary elements */
  { Tag_ALIGN,      "align",      (CM_BLOCK)},
  { Tag_BGSOUND,    "bgsound",    (CM_HEAD|CM_EMPTY)},
  { Tag_BLINK,      "blink",      (CM_INLINE)},
  { Tag_COMMENT,    "comment",    (CM_INLINE)},
  { Tag_EMBED,      "embed",      (CM_INLINE|CM_IMG|CM_EMPTY)},
  { Tag_ILAYER,     "ilayer",     (CM_INLINE)},
  { Tag_KEYGEN,     "keygen",     (CM_INLINE|CM_EMPTY)},
  { Tag_LAYER,      "layer",      (CM_BLOCK)},
  { Tag_MARQUEE,    "marquee",    (CM_INLINE|CM_OPT)},
  { Tag_MULTICOL,   "multicol",   (CM_BLOCK)},
  { Tag_NOBR,       "nobr",       (CM_INLINE)},
  { Tag_NOEMBED,    "noembed",    (CM_INLINE)},
  { Tag_NOLAYER,    "nolayer",    (CM_BLOCK|CM_INLINE|CM_MIXED)},
  { Tag_NOSAVE,     "nosave",     (CM_BLOCK)},
  { Tag_SERVER,     "server",     (CM_HEAD|CM_MIXED|CM_BLOCK|CM_INLINE)},
  { Tag_SERVLET,    "servlet",    (CM_OBJECT|CM_IMG|CM_INLINE|CM_PARAM)},
  { Tag_SPACER,     "spacer",     (CM_INLINE|CM_EMPTY)},
  { Tag_WBR,        "wbr",        (CM_INLINE|CM_EMPTY)},
};

static int
tag_cmp (const void *m1, const void *m2)
{
	const struct html_tag *p1 = m1;
	const struct html_tag *p2 = m2;

	return g_ascii_strcasecmp (p1->name, p2->name);
}

static GNode* 
construct_html_node (memory_pool_t *pool, char *text)
{
	struct html_node *html;
	GNode *n = NULL;
	struct html_tag key, *found;
	char t;
	int taglen = strlen (text);

	if (text == NULL || *text == '\0') {
		return NULL;
	}
	
	html = memory_pool_alloc0 (pool, sizeof (struct html_node));

	/* Check whether this tag is fully closed */
	if (*(text + taglen - 1) == '/') {
		html->flags |= FL_CLOSED;
	}

	/* Check xml tag */
	if (*text == '?' && g_ascii_strncasecmp (text + 1, "xml", sizeof ("xml") - 1) == 0) {
			html->flags |= FL_XML;
			html->tag = NULL;
	}
	else {
		if (*text == '/') {
			html->flags |= FL_CLOSING;
			text ++;
		}

		/* Find end of tag name */
		key.name = text;
		while (*text && g_ascii_isalnum (*(++text)));

		t = *text;
		*text = '\0';

		/* Match tag id by tag name */
		if ((found = bsearch (&key, tag_defs, G_N_ELEMENTS (tag_defs), sizeof (struct html_tag), tag_cmp)) != NULL) {
			*text = t;
			html->tag = found;
		}
		else {
			*text = t;
			return NULL;
		}
	}

	n = g_node_new (html);

	return n;
}

static gboolean
check_balance (GNode *node, GNode **cur_level)
{
	struct html_node *arg = node->data, *tmp;
	GNode *cur;
	
	if (arg->flags & FL_CLOSING) {
		/* First of all check whether this tag is closing tag for parent node */
		cur = node->parent;
		while (cur && cur->data) {
			tmp = cur->data;
			if ((tmp->tag && arg->tag) && tmp->tag->id == arg->tag->id && (tmp->flags & FL_CLOSED) == 0) {
				tmp->flags |= FL_CLOSED;
				/* Destroy current node as we find corresponding parent node */
				g_node_destroy (node);
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

struct html_tag * 
get_tag_by_name (const char *name)
{
	struct html_tag key;

	key.name = name;

	return bsearch (&key, tag_defs, G_N_ELEMENTS (tag_defs), sizeof (struct html_tag), tag_cmp);
}

gboolean
add_html_node (memory_pool_t *pool, struct mime_text_part *part, char *tag_text, GNode **cur_level)
{
	GNode *new;
	struct html_node *data;

	if (!tags_sorted) {
		qsort (tag_defs, G_N_ELEMENTS (tag_defs), sizeof (struct html_tag), tag_cmp);
		tags_sorted = 1;
	}

	/* First call of this function */
	if (part->html_nodes == NULL) {
		/* Insert root node */
		new = g_node_new (NULL);
		*cur_level = new;
		part->html_nodes = new;
		memory_pool_add_destructor (pool, (pool_destruct_func)g_node_destroy, part->html_nodes);
		/* Call once again with root node */
		return add_html_node (pool, part, tag_text, cur_level);
	}
	else {
		new = construct_html_node (pool, tag_text);
		if (new == NULL) {
			msg_debug ("add_html_node: cannot construct HTML node for text '%s'", tag_text);
			return -1;
		}
		data = new->data;
		if (data->flags & FL_CLOSING) {
			if (! *cur_level) {
				msg_debug ("add_html_node: bad parent node");
				return FALSE;
			}
			g_node_append (*cur_level, new);
			if (!check_balance (new, cur_level)) {
				msg_debug ("add_html_node: mark part as unbalanced as it has not pairable closing tags");
				part->is_balanced = FALSE;
			}
		}
		else {
			g_node_append (*cur_level, new);
			if ((data->flags & FL_CLOSED) == 0) {
				*cur_level = new;
			}
		}
	}

	return TRUE;
}

/*
 * vi:ts=4
 */
