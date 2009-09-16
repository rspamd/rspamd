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
#include "url.h"

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

sig_atomic_t entities_sorted = 0;
struct _entity;
typedef struct _entity entity;

struct _entity
{
    char *name;
    uint    code;
};


static entity entities_defs[] =
{
    /*
    ** Markup pre-defined character entities
    */
    { "quot",        34 },
    { "amp",         38 },
    { "apos",		 39 },
    { "lt",          60 },
    { "gt",          62 },

    /*
    ** Latin-1 character entities
    */
    { "nbsp",           160 },
    { "iexcl",          161 },
    { "cent",           162 },
    { "pound",          163 },
    { "curren",         164 },
    { "yen",            165 },
    { "brvbar",         166 },
    { "sect",           167 },
    { "uml",            168 },
    { "copy",           169 },
    { "ordf",           170 },
    { "laquo",          171 },
    { "not",            172 },
    { "shy",            173 },
    { "reg",            174 },
    { "macr",           175 },
    { "deg",            176 },
    { "plusmn",         177 },
    { "sup2",           178 },
    { "sup3",           179 },
    { "acute",          180 },
    { "micro",          181 },
    { "para",           182 },
    { "middot",         183 },
    { "cedil",          184 },
    { "sup1",           185 },
    { "ordm",           186 },
    { "raquo",          187 },
    { "frac14",         188 },
    { "frac12",         189 },
    { "frac34",         190 },
    { "iquest",         191 },
    { "Agrave",         192 },
    { "Aacute",         193 },
    { "Acirc",          194 },
    { "Atilde",         195 },
    { "Auml",           196 },
    { "Aring",          197 },
    { "AElig",          198 },
    { "Ccedil",         199 },
    { "Egrave",         200 },
    { "Eacute",         201 },
    { "Ecirc",          202 },
    { "Euml",           203 },
    { "Igrave",         204 },
    { "Iacute",         205 },
    { "Icirc",          206 },
    { "Iuml",           207 },
    { "ETH",            208 },
    { "Ntilde",         209 },
    { "Ograve",         210 },
    { "Oacute",         211 },
    { "Ocirc",          212 },
    { "Otilde",         213 },
    { "Ouml",           214 },
    { "times",          215 },
    { "Oslash",         216 },
    { "Ugrave",         217 },
    { "Uacute",         218 },
    { "Ucirc",          219 },
    { "Uuml",           220 },
    { "Yacute",         221 },
    { "THORN",          222 },
    { "szlig",          223 },
    { "agrave",         224 },
    { "aacute",         225 },
    { "acirc",          226 },
    { "atilde",         227 },
    { "auml",           228 },
    { "aring",          229 },
    { "aelig",          230 },
    { "ccedil",         231 },
    { "egrave",         232 },
    { "eacute",         233 },
    { "ecirc",          234 },
    { "euml",           235 },
    { "igrave",         236 },
    { "iacute",         237 },
    { "icirc",          238 },
    { "iuml",           239 },
    { "eth",            240 },
    { "ntilde",         241 },
    { "ograve",         242 },
    { "oacute",         243 },
    { "ocirc",          244 },
    { "otilde",         245 },
    { "ouml",           246 },
    { "divide",         247 },
    { "oslash",         248 },
    { "ugrave",         249 },
    { "uacute",         250 },
    { "ucirc",          251 },
    { "uuml",           252 },
    { "yacute",         253 },
    { "thorn",          254 },
    { "yuml",           255 },

    /*
    ** Extended Entities defined in HTML 4: Symbols 
    */
    { "fnof",        402 },
    { "Alpha",       913 },
    { "Beta",        914 },
    { "Gamma",       915 },
    { "Delta",       916 },
    { "Epsilon",     917 },
    { "Zeta",        918 },
    { "Eta",         919 },
    { "Theta",       920 },
    { "Iota",        921 },
    { "Kappa",       922 },
    { "Lambda",      923 },
    { "Mu",          924 },
    { "Nu",          925 },
    { "Xi",          926 },
    { "Omicron",     927 },
    { "Pi",          928 },
    { "Rho",         929 },
    { "Sigma",       931 },
    { "Tau",         932 },
    { "Upsilon",     933 },
    { "Phi",         934 },
    { "Chi",         935 },
    { "Psi",         936 },
    { "Omega",       937 },
    { "alpha",       945 },
    { "beta",        946 },
    { "gamma",       947 },
    { "delta",       948 },
    { "epsilon",     949 },
    { "zeta",        950 },
    { "eta",         951 },
    { "theta",       952 },
    { "iota",        953 },
    { "kappa",       954 },
    { "lambda",      955 },
    { "mu",          956 },
    { "nu",          957 },
    { "xi",          958 },
    { "omicron",     959 },
    { "pi",          960 },
    { "rho",         961 },
    { "sigmaf",      962 },
    { "sigma",       963 },
    { "tau",         964 },
    { "upsilon",     965 },
    { "phi",         966 },
    { "chi",         967 },
    { "psi",         968 },
    { "omega",       969 },
    { "thetasym",    977 },
    { "upsih",       978 },
    { "piv",         982 },
    { "bull",       8226 },
    { "hellip",     8230 },
    { "prime",      8242 },
    { "Prime",      8243 },
    { "oline",      8254 },
    { "frasl",      8260 },
    { "weierp",     8472 },
    { "image",      8465 },
    { "real",       8476 },
    { "trade",      8482 },
    { "alefsym",    8501 },
    { "larr",       8592 },
    { "uarr",       8593 },
    { "rarr",       8594 },
    { "darr",       8595 },
    { "harr",       8596 },
    { "crarr",      8629 },
    { "lArr",       8656 },
    { "uArr",       8657 },
    { "rArr",       8658 },
    { "dArr",       8659 },
    { "hArr",       8660 },
    { "forall",     8704 },
    { "part",       8706 },
    { "exist",      8707 },
    { "empty",      8709 },
    { "nabla",      8711 },
    { "isin",       8712 },
    { "notin",      8713 },
    { "ni",         8715 },
    { "prod",       8719 },
    { "sum",        8721 },
    { "minus",      8722 },
    { "lowast",     8727 },
    { "radic",      8730 },
    { "prop",       8733 },
    { "infin",      8734 },
    { "ang",        8736 },
    { "and",        8743 },
    { "or",         8744 },
    { "cap",        8745 },
    { "cup",        8746 },
    { "int",        8747 },
    { "there4",     8756 },
    { "sim",        8764 },
    { "cong",       8773 },
    { "asymp",      8776 },
    { "ne",         8800 },
    { "equiv",      8801 },
    { "le",         8804 },
    { "ge",         8805 },
    { "sub",        8834 },
    { "sup",        8835 },
    { "nsub",       8836 },
    { "sube",       8838 },
    { "supe",       8839 },
    { "oplus",      8853 },
    { "otimes",     8855 },
    { "perp",       8869 },
    { "sdot",       8901 },
    { "lceil",      8968 },
    { "rceil",      8969 },
    { "lfloor",     8970 },
    { "rfloor",     8971 },
    { "lang",       9001 },
    { "rang",       9002 },
    { "loz",        9674 },
    { "spades",     9824 },
    { "clubs",      9827 },
    { "hearts",     9829 },
    { "diams",      9830 },

    /*
    ** Extended Entities defined in HTML 4: Special (less Markup at top)
    */
    { "OElig",       338 },
    { "oelig",       339 },
    { "Scaron",      352 },
    { "scaron",      353 },
    { "Yuml",        376 },
    { "circ",        710 },
    { "tilde",       732 },
    { "ensp",       8194 },
    { "emsp",       8195 },
    { "thinsp",     8201 },
    { "zwnj",       8204 },
    { "zwj",        8205 },
    { "lrm",        8206 },
    { "rlm",        8207 },
    { "ndash",      8211 },
    { "mdash",      8212 },
    { "lsquo",      8216 },
    { "rsquo",      8217 },
    { "sbquo",      8218 },
    { "ldquo",      8220 },
    { "rdquo",      8221 },
    { "bdquo",      8222 },
    { "dagger",     8224 },
    { "Dagger",     8225 },
    { "permil",     8240 },
    { "lsaquo",     8249 },
    { "rsaquo",     8250 },
    { "euro",       8364 },
    { NULL,        0 }
};


static int
tag_cmp (const void *m1, const void *m2)
{
	const struct html_tag *p1 = m1;
	const struct html_tag *p2 = m2;

	return g_ascii_strcasecmp (p1->name, p2->name);
}

static int
entity_cmp (const void *m1, const void *m2)
{
	const entity *p1 = m1;
	const entity *p2 = m2;

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

/* Decode HTML entitles in text */
void
decode_entitles (char *s, guint *len)
{
	guint l;
	char *t = s;			/* t - tortoise */
	char *h = s;			/* h - hare     */
	char *e = s;
	char *end_ptr;
	int state = 0, val, base;
	entity *found, key;

	if (len == NULL || *len == 0) {
		l = strlen (s);	
	}
	else {
		l = *len;	
	}
   	
	while (h - s < l) {
		switch (state) {
			/* Out of entitle */
			case 0:
				if (*h == '&') {
					state = 1;
					e = h;
					h ++;
					continue;
				}
				else {
					*t = *h;
					h ++;
					t ++;
				}
				break;
			case 1:
				if (*h == ';') {
					/* Determine base */
					/* First find in entities table */

					key.name = e + 1;
					*h = '\0';
					if (*(e + 1) != '#' && 
							(found = bsearch (&key, entities_defs, G_N_ELEMENTS (entities_defs), sizeof ( entity), entity_cmp)) != NULL) {
						if (found->code > 0 || found->code < 127) {
							*t = (char)found->code;
						} 
						else {
							/* Skip undecoded */
							t = h;
						}
					}
					else {
						if (*(e + 2) == 'x' || *(e + 2) == 'X') {
							base = 16;
						}
						else if (*(e + 2) == 'o' || *(e + 2) == 'O') {
							base = 8;
						}
						else {
							base = 10;
						}
						if (base == 10) {
							val = strtoul ((e + 2), &end_ptr, base);
						}
						else {
							val = strtoul ((e + 3), &end_ptr, base);
						}
						if ((end_ptr != NULL && *end_ptr != '\0') || (val == 0 || val > 127)) {
							/* Skip undecoded */
							t = h;
						}
						else {
							*t = (char)val;
						}
					}
					*h = ';';
					state = 0;
					t ++;
				}
				h ++;
				break;
		}
	}
	*t = '\0';
	
	if (len != NULL) {
		*len = t - s;
	}
}

static void
parse_tag_url (struct worker_task *task, struct mime_text_part *part, tag_id_t id, char *tag_text)
{
	char *c = NULL, *p;
	int len, rc;
	char *url_text;
	struct uri *url;
	gboolean got_single_quote = FALSE, got_double_quote = FALSE;

	/* For A tags search for href= and for IMG tags search for src= */
	if (id == Tag_A) {
		c = strcasestr (tag_text, "href=");
		len = sizeof ("href=") - 1;
	}
	else if (id == Tag_IMG) {
		c = strcasestr (tag_text, "src=");
		len = sizeof ("src=") - 1;
	}

	if (c != NULL) {
		/* First calculate length */
		c += len;
		/* Skip spaces after eqsign */
		while (g_ascii_isspace (*c)) {
			c ++;
		}
		len = 0;
		p = c;
		while (*p) {
			if (got_double_quote) {
				if (*p == '"') {
					break;
				}
				else {
					len ++;
				}
			}
			else if (got_single_quote) {
				if (*p == '\'') {
					break;
				}
				else {
					len ++;
				}
			}
			else if (g_ascii_isspace(*p) || *p == '>' || (*p == '/' && *(p + 1) == '>') || *p == '\r' || *p == '\n') {
				break;
			}
			else {
				if (*p == '"' && !got_single_quote) {
					got_double_quote = !got_double_quote;
				}
				else if (*p == '\'' && !got_double_quote) {
					got_single_quote = !got_single_quote;
				}
				else {
					len ++;
				}
			}
			p ++;
		}

		if (got_single_quote || got_double_quote) {
			c++;
		}

		if (len == 0) {
			return;
		}
		
		url_text = memory_pool_alloc (task->task_pool, len + 1);
		g_strlcpy (url_text, c, len + 1);
		decode_entitles (url_text, NULL);

        if (g_ascii_strncasecmp (url_text, "http://", sizeof ("http://") - 1) != 0) {
            return;
        }

		url = memory_pool_alloc (task->task_pool, sizeof (struct uri));
		rc = parse_uri (url, url_text, task->task_pool);

		if (rc != URI_ERRNO_EMPTY && rc != URI_ERRNO_NO_HOST && url->hostlen != 0) {
			if (part->html_urls && g_tree_lookup (part->html_urls, url_text) == NULL) {
				g_tree_insert (part->html_urls, url_text, url);
				task->urls = g_list_prepend (task->urls, url);
			}
		}
	}	
}

gboolean
add_html_node (struct worker_task *task, memory_pool_t *pool, struct mime_text_part *part, char *tag_text, GNode **cur_level)
{
	GNode *new;
	struct html_node *data;

	if (!tags_sorted) {
		qsort (tag_defs, G_N_ELEMENTS (tag_defs), sizeof (struct html_tag), tag_cmp);
		tags_sorted = 1;
	}
	if (!entities_sorted) {
		qsort (entities_defs, G_N_ELEMENTS (entities_defs), sizeof (entity), entity_cmp);
		entities_sorted = 1;
	}

	/* First call of this function */
	if (part->html_nodes == NULL) {
		/* Insert root node */
		new = g_node_new (NULL);
		*cur_level = new;
		part->html_nodes = new;
		memory_pool_add_destructor (pool, (pool_destruct_func)g_node_destroy, part->html_nodes);
		/* Call once again with root node */
		return add_html_node (task, pool, part, tag_text, cur_level);
	}
	else {
		new = construct_html_node (pool, tag_text);
		if (new == NULL) {
			msg_debug ("add_html_node: cannot construct HTML node for text '%s'", tag_text);
			return -1;
		}
		data = new->data;
		if (data->tag && (data->tag->id == Tag_A || data->tag->id == Tag_IMG) && ((data->flags & FL_CLOSING) == 0)) {
			parse_tag_url (task, part, data->tag->id, tag_text);
		}
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
