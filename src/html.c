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

sig_atomic_t                    tags_sorted = 0;

static struct html_tag          tag_defs[] = {
	/* W3C defined elements */
	{Tag_A, "a", (CM_INLINE)},
	{Tag_ABBR, "abbr", (CM_INLINE)},
	{Tag_ACRONYM, "acronym", (CM_INLINE)},
	{Tag_ADDRESS, "address", (CM_BLOCK)},
	{Tag_APPLET, "applet", (CM_OBJECT | CM_IMG | CM_INLINE | CM_PARAM)},
	{Tag_AREA, "area", (CM_BLOCK | CM_EMPTY)},
	{Tag_B, "b", (CM_INLINE)},
	{Tag_BASE, "base", (CM_HEAD | CM_EMPTY)},
	{Tag_BASEFONT, "basefont", (CM_INLINE | CM_EMPTY)},
	{Tag_BDO, "bdo", (CM_INLINE)},
	{Tag_BIG, "big", (CM_INLINE)},
	{Tag_BLOCKQUOTE, "blockquote", (CM_BLOCK)},
	{Tag_BODY, "body", (CM_HTML | CM_OPT | CM_OMITST)},
	{Tag_BR, "br", (CM_INLINE | CM_EMPTY)},
	{Tag_BUTTON, "button", (CM_INLINE)},
	{Tag_CAPTION, "caption", (CM_TABLE)},
	{Tag_CENTER, "center", (CM_BLOCK)},
	{Tag_CITE, "cite", (CM_INLINE)},
	{Tag_CODE, "code", (CM_INLINE)},
	{Tag_COL, "col", (CM_TABLE | CM_EMPTY)},
	{Tag_COLGROUP, "colgroup", (CM_TABLE | CM_OPT)},
	{Tag_DD, "dd", (CM_DEFLIST | CM_OPT | CM_NO_INDENT)},
	{Tag_DEL, "del", (CM_INLINE | CM_BLOCK | CM_MIXED)},
	{Tag_DFN, "dfn", (CM_INLINE)},
	{Tag_DIR, "dir", (CM_BLOCK | CM_OBSOLETE)},
	{Tag_DIV, "div", (CM_BLOCK)},
	{Tag_DL, "dl", (CM_BLOCK)},
	{Tag_DT, "dt", (CM_DEFLIST | CM_OPT | CM_NO_INDENT)},
	{Tag_EM, "em", (CM_INLINE)},
	{Tag_FIELDSET, "fieldset", (CM_BLOCK)},
	{Tag_FONT, "font", (CM_INLINE)},
	{Tag_FORM, "form", (CM_BLOCK)},
	{Tag_FRAME, "frame", (CM_FRAMES | CM_EMPTY)},
	{Tag_FRAMESET, "frameset", (CM_HTML | CM_FRAMES)},
	{Tag_H1, "h1", (CM_BLOCK | CM_HEADING)},
	{Tag_H2, "h2", (CM_BLOCK | CM_HEADING)},
	{Tag_H3, "h3", (CM_BLOCK | CM_HEADING)},
	{Tag_H4, "h4", (CM_BLOCK | CM_HEADING)},
	{Tag_H5, "h5", (CM_BLOCK | CM_HEADING)},
	{Tag_H6, "h6", (CM_BLOCK | CM_HEADING)},
	{Tag_HEAD, "head", (CM_HTML | CM_OPT | CM_OMITST)},
	{Tag_HR, "hr", (CM_BLOCK | CM_EMPTY)},
	{Tag_HTML, "html", (CM_HTML | CM_OPT | CM_OMITST)},
	{Tag_I, "i", (CM_INLINE)},
	{Tag_IFRAME, "iframe", (CM_INLINE)},
	{Tag_IMG, "img", (CM_INLINE | CM_IMG | CM_EMPTY)},
	{Tag_INPUT, "input", (CM_INLINE | CM_IMG | CM_EMPTY)},
	{Tag_INS, "ins", (CM_INLINE | CM_BLOCK | CM_MIXED)},
	{Tag_ISINDEX, "isindex", (CM_BLOCK | CM_EMPTY)},
	{Tag_KBD, "kbd", (CM_INLINE)},
	{Tag_LABEL, "label", (CM_INLINE)},
	{Tag_LEGEND, "legend", (CM_INLINE)},
	{Tag_LI, "li", (CM_LIST | CM_OPT | CM_NO_INDENT)},
	{Tag_LINK, "link", (CM_HEAD | CM_EMPTY)},
	{Tag_LISTING, "listing", (CM_BLOCK | CM_OBSOLETE)},
	{Tag_MAP, "map", (CM_INLINE)},
	{Tag_MENU, "menu", (CM_BLOCK | CM_OBSOLETE)},
	{Tag_META, "meta", (CM_HEAD | CM_EMPTY)},
	{Tag_NOFRAMES, "noframes", (CM_BLOCK | CM_FRAMES)},
	{Tag_NOSCRIPT, "noscript", (CM_BLOCK | CM_INLINE | CM_MIXED)},
	{Tag_OBJECT, "object", (CM_OBJECT | CM_HEAD | CM_IMG | CM_INLINE | CM_PARAM)},
	{Tag_OL, "ol", (CM_BLOCK)},
	{Tag_OPTGROUP, "optgroup", (CM_FIELD | CM_OPT)},
	{Tag_OPTION, "option", (CM_FIELD | CM_OPT)},
	{Tag_P, "p", (CM_BLOCK | CM_OPT)},
	{Tag_PARAM, "param", (CM_INLINE | CM_EMPTY)},
	{Tag_PLAINTEXT, "plaintext", (CM_BLOCK | CM_OBSOLETE)},
	{Tag_PRE, "pre", (CM_BLOCK)},
	{Tag_Q, "q", (CM_INLINE)},
	{Tag_RB, "rb", (CM_INLINE)},
	{Tag_RBC, "rbc", (CM_INLINE)},
	{Tag_RP, "rp", (CM_INLINE)},
	{Tag_RT, "rt", (CM_INLINE)},
	{Tag_RTC, "rtc", (CM_INLINE)},
	{Tag_RUBY, "ruby", (CM_INLINE)},
	{Tag_S, "s", (CM_INLINE)},
	{Tag_SAMP, "samp", (CM_INLINE)},
	{Tag_SCRIPT, "script", (CM_HEAD | CM_MIXED | CM_BLOCK | CM_INLINE)},
	{Tag_SELECT, "select", (CM_INLINE | CM_FIELD)},
	{Tag_SMALL, "small", (CM_INLINE)},
	{Tag_SPAN, "span", (CM_INLINE)},
	{Tag_STRIKE, "strike", (CM_INLINE)},
	{Tag_STRONG, "strong", (CM_INLINE)},
	{Tag_STYLE, "style", (CM_HEAD)},
	{Tag_SUB, "sub", (CM_INLINE)},
	{Tag_SUP, "sup", (CM_INLINE)},
	{Tag_TABLE, "table", (CM_BLOCK)},
	{Tag_TBODY, "tbody", (CM_TABLE | CM_ROWGRP | CM_OPT)},
	{Tag_TD, "td", (CM_ROW | CM_OPT | CM_NO_INDENT)},
	{Tag_TEXTAREA, "textarea", (CM_INLINE | CM_FIELD)},
	{Tag_TFOOT, "tfoot", (CM_TABLE | CM_ROWGRP | CM_OPT)},
	{Tag_TH, "th", (CM_ROW | CM_OPT | CM_NO_INDENT)},
	{Tag_THEAD, "thead", (CM_TABLE | CM_ROWGRP | CM_OPT)},
	{Tag_TITLE, "title", (CM_HEAD)},
	{Tag_TR, "tr", (CM_TABLE | CM_OPT)},
	{Tag_TT, "tt", (CM_INLINE)},
	{Tag_U, "u", (CM_INLINE)},
	{Tag_UL, "ul", (CM_BLOCK)},
	{Tag_VAR, "var", (CM_INLINE)},
	{Tag_XMP, "xmp", (CM_BLOCK | CM_OBSOLETE)},
	{Tag_NEXTID, "nextid", (CM_HEAD | CM_EMPTY)},

	/* proprietary elements */
	{Tag_ALIGN, "align", (CM_BLOCK)},
	{Tag_BGSOUND, "bgsound", (CM_HEAD | CM_EMPTY)},
	{Tag_BLINK, "blink", (CM_INLINE)},
	{Tag_COMMENT, "comment", (CM_INLINE)},
	{Tag_EMBED, "embed", (CM_INLINE | CM_IMG | CM_EMPTY)},
	{Tag_ILAYER, "ilayer", (CM_INLINE)},
	{Tag_KEYGEN, "keygen", (CM_INLINE | CM_EMPTY)},
	{Tag_LAYER, "layer", (CM_BLOCK)},
	{Tag_MARQUEE, "marquee", (CM_INLINE | CM_OPT)},
	{Tag_MULTICOL, "multicol", (CM_BLOCK)},
	{Tag_NOBR, "nobr", (CM_INLINE)},
	{Tag_NOEMBED, "noembed", (CM_INLINE)},
	{Tag_NOLAYER, "nolayer", (CM_BLOCK | CM_INLINE | CM_MIXED)},
	{Tag_NOSAVE, "nosave", (CM_BLOCK)},
	{Tag_SERVER, "server", (CM_HEAD | CM_MIXED | CM_BLOCK | CM_INLINE)},
	{Tag_SERVLET, "servlet", (CM_OBJECT | CM_IMG | CM_INLINE | CM_PARAM)},
	{Tag_SPACER, "spacer", (CM_INLINE | CM_EMPTY)},
	{Tag_WBR, "wbr", (CM_INLINE | CM_EMPTY)},
};

sig_atomic_t                    entities_sorted = 0;
struct _entity;
typedef struct _entity          entity;

struct _entity {
	gchar                           *name;
	uint                            code;
	gchar                           *replacement;
};


static entity                   entities_defs[] = {
	/*
	 ** Markup pre-defined character entities
	 */
	{"quot", 34, "\""},
	{"amp", 38, "&"},
	{"apos", 39, "'"},
	{"lt", 60, "<"},
	{"gt", 62, ">"},

	/*
	 ** Latin-1 character entities
	 */
	{"nbsp", 160, " "},
	{"iexcl", 161, "!"},
	{"cent", 162, "cent"},
	{"pound", 163, "pound"},
	{"curren", 164, "current"},
	{"yen", 165, "yen"},
	{"brvbar", 166, NULL},
	{"sect", 167, NULL},
	{"uml", 168, "uml"},
	{"copy", 169, "c"},
	{"ordf", 170, NULL},
	{"laquo", 171, "\""},
	{"not", 172, "!"},
	{"shy", 173, NULL},
	{"reg", 174, "r"},
	{"macr", 175, NULL},
	{"deg", 176, "deg"},
	{"plusmn", 177, "+-"},
	{"sup2", 178, "2"},
	{"sup3", 179, "3"},
	{"acute", 180, NULL},
	{"micro", 181, NULL},
	{"para", 182, NULL},
	{"middot", 183, "."},
	{"cedil", 184, NULL},
	{"sup1", 185, "1"},
	{"ordm", 186, NULL},
	{"raquo", 187, "\""},
	{"frac14", 188, "1/4"},
	{"frac12", 189, "1/2"},
	{"frac34", 190, "3/4"},
	{"iquest", 191, "i"},
	{"Agrave", 192, "a"},
	{"Aacute", 193, "a"},
	{"Acirc", 194, "a"},
	{"Atilde", 195, "a"},
	{"Auml", 196, "a"},
	{"Aring", 197, "a"},
	{"AElig", 198, "a"},
	{"Ccedil", 199, "c"},
	{"Egrave", 200, "e"},
	{"Eacute", 201, "e"},
	{"Ecirc", 202, "e"},
	{"Euml", 203, "e"},
	{"Igrave", 204, "i"},
	{"Iacute", 205, "i"},
	{"Icirc", 206, "i"},
	{"Iuml", 207, "i"},
	{"ETH", 208, "e"},
	{"Ntilde", 209, "n"},
	{"Ograve", 210, "o"},
	{"Oacute", 211, "o"},
	{"Ocirc", 212, "o"},
	{"Otilde", 213, "o"},
	{"Ouml", 214, "o"},
	{"times", 215, "t"},
	{"Oslash", 216, "o"},
	{"Ugrave", 217, "u"},
	{"Uacute", 218, "u"},
	{"Ucirc", 219, "u"},
	{"Uuml", 220, "u"},
	{"Yacute", 221, "y"},
	{"THORN", 222, "t"},
	{"szlig", 223, "s"},
	{"agrave", 224, "a"},
	{"aacute", 225, "a"},
	{"acirc", 226, "a"},
	{"atilde", 227, "a"},
	{"auml", 228, "a"},
	{"aring", 229, "a"},
	{"aelig", 230, "a"},
	{"ccedil", 231, "c"},
	{"egrave", 232, "e"},
	{"eacute", 233, "e"},
	{"ecirc", 234, "e"},
	{"euml", 235, "e"},
	{"igrave", 236, "e"},
	{"iacute", 237, "e"},
	{"icirc", 238, "e"},
	{"iuml", 239, "e"},
	{"eth", 240, "e"},
	{"ntilde", 241, "n"},
	{"ograve", 242, "o"},
	{"oacute", 243, "o"},
	{"ocirc", 244, "o"},
	{"otilde", 245, "o"},
	{"ouml", 246, "o"},
	{"divide", 247, "/"},
	{"oslash", 248, "/"},
	{"ugrave", 249, "u"},
	{"uacute", 250, "u"},
	{"ucirc", 251, "u"},
	{"uuml", 252, "u"},
	{"yacute", 253, "y"},
	{"thorn", 254, "t"},
	{"yuml", 255, "y"},

	/*
	 ** Extended Entities defined in HTML 4: Symbols 
	 */
	{"fnof", 402, "f"},
	{"Alpha", 913, "alpha"},
	{"Beta", 914, "beta"},
	{"Gamma", 915, "gamma"},
	{"Delta", 916, "delta"},
	{"Epsilon", 917, "epsilon"},
	{"Zeta", 918, "zeta"},
	{"Eta", 919, "eta"},
	{"Theta", 920, "theta"},
	{"Iota", 921, "iota"},
	{"Kappa", 922, "kappa"},
	{"Lambda", 923, "lambda"},
	{"Mu", 924, "mu"},
	{"Nu", 925, "nu"},
	{"Xi", 926, "xi"},
	{"Omicron", 927, "omicron"},
	{"Pi", 928, "pi"},
	{"Rho", 929, "rho"},
	{"Sigma", 931, "sigma"},
	{"Tau", 932, "tau"},
	{"Upsilon", 933, "upsilon"},
	{"Phi", 934, "phi"},
	{"Chi", 935, "chi"},
	{"Psi", 936, "psi"},
	{"Omega", 937, "omega"},
	{"alpha", 945, "alpha"},
	{"beta", 946, "beta"},
	{"gamma", 947, "gamma"},
	{"delta", 948, "delta"},
	{"epsilon", 949, "epsilon"},
	{"zeta", 950, "zeta"},
	{"eta", 951, "eta"},
	{"theta", 952, "theta"},
	{"iota", 953, "iota"},
	{"kappa", 954, "kappa"},
	{"lambda", 955, "lambda"},
	{"mu", 956, "mu"},
	{"nu", 957, "nu"},
	{"xi", 958, "xi"},
	{"omicron", 959, "omicron"},
	{"pi", 960, "pi"},
	{"rho", 961, "rho"},
	{"sigmaf", 962, "sigmaf"},
	{"sigma", 963, "sigma"},
	{"tau", 964, "tau"},
	{"upsilon", 965, "upsilon"},
	{"phi", 966, "phi"},
	{"chi", 967, "chi"},
	{"psi", 968, "psi"},
	{"omega", 969, "omega"},
	{"thetasym", 977, "thetasym"},
	{"upsih", 978, "upsih"},
	{"piv", 982, "piv"},
	{"bull", 8226, "bull"},
	{"hellip", 8230, "hellip"},
	{"prime", 8242, "'"},
	{"Prime", 8243, "'"},
	{"oline", 8254, "-"},
	{"frasl", 8260, NULL},
	{"weierp", 8472, NULL},
	{"image", 8465, NULL},
	{"real", 8476, NULL},
	{"trade", 8482, NULL},
	{"alefsym", 8501, "a"},
	{"larr", 8592, NULL},
	{"uarr", 8593, NULL},
	{"rarr", 8594, NULL},
	{"darr", 8595, NULL},
	{"harr", 8596, NULL},
	{"crarr", 8629, NULL},
	{"lArr", 8656, NULL},
	{"uArr", 8657, NULL},
	{"rArr", 8658, NULL},
	{"dArr", 8659, NULL},
	{"hArr", 8660, NULL},
	{"forall", 8704, NULL},
	{"part", 8706, NULL},
	{"exist", 8707, NULL},
	{"empty", 8709, NULL},
	{"nabla", 8711, NULL},
	{"isin", 8712, NULL},
	{"notin", 8713, NULL},
	{"ni", 8715, NULL},
	{"prod", 8719, NULL},
	{"sum", 8721, "E"},
	{"minus", 8722, "-"},
	{"lowast", 8727, NULL},
	{"radic", 8730, NULL},
	{"prop", 8733, NULL},
	{"infin", 8734, NULL},
	{"ang", 8736, "'"},
	{"and", 8743, "&"},
	{"or", 8744, "|"},
	{"cap", 8745, NULL},
	{"cup", 8746, NULL},
	{"gint", 8747, NULL},
	{"there4", 8756, NULL},
	{"sim", 8764, NULL},
	{"cong", 8773, NULL},
	{"asymp", 8776, NULL},
	{"ne", 8800, "!="},
	{"equiv", 8801, "=="},
	{"le", 8804, "<="},
	{"ge", 8805, ">="},
	{"sub", 8834, NULL},
	{"sup", 8835, NULL},
	{"nsub", 8836, NULL},
	{"sube", 8838, NULL},
	{"supe", 8839, NULL},
	{"oplus", 8853, NULL},
	{"otimes", 8855, NULL},
	{"perp", 8869, NULL},
	{"sdot", 8901, NULL},
	{"lceil", 8968, NULL},
	{"rceil", 8969, NULL},
	{"lfloor", 8970, NULL},
	{"rfloor", 8971, NULL},
	{"lang", 9001, NULL},
	{"rang", 9002, NULL},
	{"loz", 9674, NULL},
	{"spades", 9824, NULL},
	{"clubs", 9827, NULL},
	{"hearts", 9829, NULL},
	{"diams", 9830, NULL},

	/*
	 ** Extended Entities defined in HTML 4: Special (less Markup at top)
	 */
	{"OElig", 338, NULL},
	{"oelig", 339, NULL},
	{"Scaron", 352, NULL},
	{"scaron", 353, NULL},
	{"Yuml", 376, NULL},
	{"circ", 710, NULL},
	{"tilde", 732, NULL},
	{"ensp", 8194, NULL},
	{"emsp", 8195, NULL},
	{"thinsp", 8201, NULL},
	{"zwnj", 8204, NULL},
	{"zwj", 8205, NULL},
	{"lrm", 8206, NULL},
	{"rlm", 8207, NULL},
	{"ndash", 8211, "-"},
	{"mdash", 8212, "-"},
	{"lsquo", 8216, "'"},
	{"rsquo", 8217, "'"},
	{"sbquo", 8218, "\""},
	{"ldquo", 8220, "\""},
	{"rdquo", 8221, "\""},
	{"bdquo", 8222, "\""},
	{"dagger", 8224, "T"},
	{"Dagger", 8225, "T"},
	{"permil", 8240, NULL},
	{"lsaquo", 8249, "\""},
	{"rsaquo", 8250, "\""},
	{"euro", 8364, "E"},
};

static entity                  *entities_defs_num = NULL;

static gint
tag_cmp (const void *m1, const void *m2)
{
	const struct html_tag          *p1 = m1;
	const struct html_tag          *p2 = m2;

	return g_ascii_strcasecmp (p1->name, p2->name);
}

static gint
entity_cmp (const void *m1, const void *m2)
{
	const entity                   *p1 = m1;
	const entity                   *p2 = m2;

	return g_ascii_strcasecmp (p1->name, p2->name);
}

static gint
entity_cmp_num (const void *m1, const void *m2)
{
	const entity                   *p1 = m1;
	const entity                   *p2 = m2;

	return p1->code - p2->code;
}

static GNode                   *
construct_html_node (memory_pool_t * pool, gchar *text, gsize tag_len)
{
	struct html_node               *html;
	GNode                          *n = NULL;
	struct html_tag                 key, *found;
	gchar                           t;

	if (text == NULL || *text == '\0') {
		return NULL;
	}

	html = memory_pool_alloc0 (pool, sizeof (struct html_node));

	/* Check whether this tag is fully closed */
	if (*(text + tag_len - 1) == '/') {
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
			text++;
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

static                          gboolean
check_balance (GNode * node, GNode ** cur_level)
{
	struct html_node               *arg = node->data, *tmp;
	GNode                          *cur;

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

struct html_tag                *
get_tag_by_name (const gchar *name)
{
	struct html_tag                 key;

	key.name = name;

	return bsearch (&key, tag_defs, G_N_ELEMENTS (tag_defs), sizeof (struct html_tag), tag_cmp);
}

/* Decode HTML entitles in text */
void
decode_entitles (gchar *s, guint * len)
{
	guint                           l, rep_len;
	gchar                           *t = s;	/* t - tortoise */
	gchar                           *h = s;	/* h - hare     */
	gchar                           *e = s;
	gchar                           *end_ptr;
	gint                            state = 0, val, base;
	entity                         *found, key;

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
				h++;
				continue;
			}
			else {
				*t = *h;
				h++;
				t++;
			}
			break;
		case 1:
			if (*h == ';') {
				/* Determine base */
				/* First find in entities table */

				key.name = e + 1;
				*h = '\0';
				if (*(e + 1) != '#' && (found = bsearch (&key, entities_defs, G_N_ELEMENTS (entities_defs), sizeof (entity), entity_cmp)) != NULL) {
					if (found->replacement) {
						rep_len = strlen (found->replacement);
						memcpy (t, found->replacement, rep_len);
						t += rep_len;
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
					if (end_ptr != NULL && *end_ptr != '\0') {
						/* Skip undecoded */
						t = h;
					}
					else {
						/* Search for a replacement */
						key.code = val;
						found = bsearch (&key, entities_defs_num, G_N_ELEMENTS (entities_defs), sizeof (entity), entity_cmp_num);
						if (found) {
							if (found->replacement) {
								rep_len = strlen (found->replacement);
								memcpy (t, found->replacement, rep_len);
								t += rep_len;
							}
						}
					}
				}
				*h = ';';
				state = 0;
			}
			h++;
			break;
		}
	}
	*t = '\0';

	if (len != NULL) {
		*len = t - s;
	}
}

/*
 * Find the first occurrence of find in s, ignore case.
 */
static gchar *
html_strncasestr (const gchar *s, const gchar *find, gsize len)
{
	gchar                           c, sc;
	size_t mlen;

	if ((c = *find++) != 0) {
		c = g_ascii_tolower (c);
		mlen = strlen (find);
		do {
			do {
				if ((sc = *s++) == 0 || len -- == 0)
					return (NULL);
			} while (g_ascii_tolower (sc) != c);
		} while (g_ascii_strncasecmp (s, find, mlen) != 0);
		s--;
	}
	return ((gchar *)s);
}

static void
check_phishing (struct worker_task *task, struct uri *href_url, const gchar *url_text)
{
	struct uri                     *new;
	gchar                          *url_str;
	gsize                           len;
	gint                            off, rc;

	len = strcspn (url_text, "<>");

	if (url_try_text (task->task_pool, url_text, len, &off, &url_str) && url_str != NULL) {
		new = memory_pool_alloc0 (task->task_pool, sizeof (struct uri));
		if (new != NULL) {
			g_strstrip (url_str);
			rc = parse_uri (new, url_str, task->task_pool);
			if (rc == URI_ERRNO_OK || rc == URI_ERRNO_NO_SLASHES || rc == URI_ERRNO_NO_HOST_SLASH) {
				if (g_ascii_strncasecmp (href_url->host, new->host,
						MAX (href_url->hostlen, new->hostlen)) != 0) {
					href_url->is_phished = TRUE;
					href_url->phished_url = new;
				}
			}
			else {
				msg_info ("extract of url '%s' failed: %s", url_str, url_strerror (rc));
			}
		}
	}

}

static void
parse_tag_url (struct worker_task *task, struct mime_text_part *part, tag_id_t id, gchar *tag_text, gsize tag_len)
{
	gchar                           *c = NULL, *p, *url_text;
	gint                            len, rc;
	struct uri                     *url;
	gboolean                        got_single_quote = FALSE, got_double_quote = FALSE;

	/* For A tags search for href= and for IMG tags search for src= */
	if (id == Tag_A) {
		c = html_strncasestr (tag_text, "href=", tag_len);
		len = sizeof ("href=") - 1;
	}
	else if (id == Tag_IMG) {
		c = html_strncasestr (tag_text, "src=", tag_len);
		len = sizeof ("src=") - 1;
	}

	if (c != NULL) {
		/* First calculate length */
		c += len;
		/* Skip spaces after eqsign */
		while (g_ascii_isspace (*c)) {
			c++;
		}
		len = 0;
		p = c;
		while (*p && p - tag_text < tag_len) {
			if (got_double_quote) {
				if (*p == '"') {
					break;
				}
				else {
					len++;
				}
			}
			else if (got_single_quote) {
				if (*p == '\'') {
					break;
				}
				else {
					len++;
				}
			}
			else if (g_ascii_isspace (*p) || *p == '>' || (*p == '/' && *(p + 1) == '>') || *p == '\r' || *p == '\n') {
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
					len++;
				}
			}
			p++;
		}

		if (got_single_quote || got_double_quote) {
			c++;
		}

		if (len == 0) {
			return;
		}

		url_text = memory_pool_alloc (task->task_pool, len + 1);
		rspamd_strlcpy (url_text, c, len + 1);
		decode_entitles (url_text, NULL);

		if (g_ascii_strncasecmp (url_text, "http://", sizeof ("http://") - 1) != 0 &&
				g_ascii_strncasecmp (url_text, "www", sizeof ("www") - 1) != 0 &&
				g_ascii_strncasecmp (url_text, "ftp://", sizeof ("ftp://") - 1) != 0 &&
				g_ascii_strncasecmp (url_text, "mailto:", sizeof ("mailto:") - 1) != 0) {
			return;
		}

		url = memory_pool_alloc (task->task_pool, sizeof (struct uri));
		rc = parse_uri (url, url_text, task->task_pool);

		if (rc != URI_ERRNO_EMPTY && rc != URI_ERRNO_NO_HOST && url->hostlen != 0) {
			/*
			 * Check for phishing
			 */
			if ((p = strchr (c, '>')) != NULL ) {
				check_phishing (task, url, p + 1);
			}
			if (part->html_urls && g_tree_lookup (part->html_urls, url_text) == NULL) {
				g_tree_insert (part->html_urls, url_text, url);
				task->urls = g_list_prepend (task->urls, url);
			}
		}
	}
}

gboolean
add_html_node (struct worker_task *task, memory_pool_t * pool, struct mime_text_part *part,
		gchar *tag_text, gsize tag_len, GNode ** cur_level)
{
	GNode                          *new;
	struct html_node               *data;

	if (!tags_sorted) {
		qsort (tag_defs, G_N_ELEMENTS (tag_defs), sizeof (struct html_tag), tag_cmp);
		tags_sorted = 1;
	}
	if (!entities_sorted) {
		qsort (entities_defs, G_N_ELEMENTS (entities_defs), sizeof (entity), entity_cmp);
		entities_defs_num = g_new (entity, G_N_ELEMENTS (entities_defs));
		memcpy (entities_defs_num, entities_defs, sizeof (entities_defs));
		qsort (entities_defs_num, G_N_ELEMENTS (entities_defs), sizeof (entity), entity_cmp_num);
		entities_sorted = 1;
	}

	/* First call of this function */
	if (part->html_nodes == NULL) {
		/* Insert root node */
		new = g_node_new (NULL);
		*cur_level = new;
		part->html_nodes = new;
		memory_pool_add_destructor (pool, (pool_destruct_func) g_node_destroy, part->html_nodes);
		/* Call once again with root node */
		return add_html_node (task, pool, part, tag_text, tag_len, cur_level);
	}
	else {
		new = construct_html_node (pool, tag_text, tag_len);
		if (new == NULL) {
			debug_task ("cannot construct HTML node for text '%s'", tag_text);
			return FALSE;
		}
		data = new->data;
		if (data->tag && (data->tag->id == Tag_A || data->tag->id == Tag_IMG) && ((data->flags & FL_CLOSING) == 0)) {
			parse_tag_url (task, part, data->tag->id, tag_text, tag_len);
		}

		if (data->flags & FL_CLOSING) {
			if (!*cur_level) {
				debug_task ("bad parent node");
				return FALSE;
			}
			g_node_append (*cur_level, new);
			if (!check_balance (new, cur_level)) {
				debug_task ("mark part as unbalanced as it has not pairable closing tags");
				part->is_balanced = FALSE;
			}
		}
		else {

			g_node_append (*cur_level, new);
			if ((data->flags & FL_CLOSED) == 0) {
				*cur_level = new;
			}
			/* Skip some tags */
			if (data->tag && (data->tag->id == Tag_STYLE ||
							  data->tag->id == Tag_SCRIPT ||
							  data->tag->id == Tag_OBJECT)) {
				return FALSE;
			}
		}
	}

	return TRUE;
}

/*
 * vi:ts=4
 */
