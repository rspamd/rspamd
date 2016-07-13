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
#include "url.h"

static sig_atomic_t tags_sorted = 0;

struct html_tag_def {
	gint id;
	const gchar *name;
	guint flags;
};

static struct html_tag_def tag_defs[] = {
	/* W3C defined elements */
	{Tag_A, "a", (0)},
	{Tag_ABBR, "abbr", (CM_INLINE)},
	{Tag_ACRONYM, "acronym", (CM_INLINE)},
	{Tag_ADDRESS, "address", (CM_BLOCK)},
	{Tag_APPLET, "applet", (CM_OBJECT | CM_IMG | CM_INLINE | CM_PARAM)},
	{Tag_AREA, "area", (CM_BLOCK | CM_EMPTY)},
	{Tag_B, "b", (CM_INLINE|FL_BLOCK)},
	{Tag_BASE, "base", (CM_HEAD | CM_EMPTY)},
	{Tag_BASEFONT, "basefont", (CM_INLINE | CM_EMPTY)},
	{Tag_BDO, "bdo", (CM_INLINE)},
	{Tag_BIG, "big", (CM_INLINE)},
	{Tag_BLOCKQUOTE, "blockquote", (CM_BLOCK)},
	{Tag_BODY, "body", (CM_HTML | CM_OPT | CM_OMITST | CM_UNIQUE)},
	{Tag_BR, "br", (CM_INLINE | CM_EMPTY)},
	{Tag_BUTTON, "button", (CM_INLINE|FL_BLOCK)},
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
	{Tag_DIV, "div", (CM_BLOCK|FL_BLOCK)},
	{Tag_DL, "dl", (CM_BLOCK|FL_BLOCK)},
	{Tag_DT, "dt", (CM_DEFLIST | CM_OPT | CM_NO_INDENT)},
	{Tag_EM, "em", (CM_INLINE)},
	{Tag_FIELDSET, "fieldset", (CM_BLOCK)},
	{Tag_FONT, "font", (CM_INLINE|FL_BLOCK)},
	{Tag_FORM, "form", (CM_BLOCK)},
	{Tag_FRAME, "frame", (CM_FRAMES | CM_EMPTY)},
	{Tag_FRAMESET, "frameset", (CM_HTML | CM_FRAMES)},
	{Tag_H1, "h1", (CM_BLOCK | CM_HEADING)},
	{Tag_H2, "h2", (CM_BLOCK | CM_HEADING)},
	{Tag_H3, "h3", (CM_BLOCK | CM_HEADING)},
	{Tag_H4, "h4", (CM_BLOCK | CM_HEADING)},
	{Tag_H5, "h5", (CM_BLOCK | CM_HEADING)},
	{Tag_H6, "h6", (CM_BLOCK | CM_HEADING)},
	{Tag_HEAD, "head", (CM_HTML | CM_OPT | CM_OMITST | CM_UNIQUE)},
	{Tag_HR, "hr", (CM_BLOCK | CM_EMPTY)},
	{Tag_HTML, "html", (CM_HTML | CM_OPT | CM_OMITST | CM_UNIQUE)},
	{Tag_I, "i", (CM_INLINE)},
	{Tag_IFRAME, "iframe", (0)},
	{Tag_IMG, "img", (CM_INLINE | CM_IMG | CM_EMPTY)},
	{Tag_INPUT, "input", (CM_INLINE | CM_IMG | CM_EMPTY)},
	{Tag_INS, "ins", (CM_INLINE | CM_BLOCK | CM_MIXED)},
	{Tag_ISINDEX, "isindex", (CM_BLOCK | CM_EMPTY)},
	{Tag_KBD, "kbd", (CM_INLINE)},
	{Tag_LABEL, "label", (CM_INLINE)},
	{Tag_LEGEND, "legend", (CM_INLINE)},
	{Tag_LI, "li", (CM_LIST | CM_OPT | CM_NO_INDENT | FL_BLOCK)},
	{Tag_LINK, "link", (CM_HEAD | CM_EMPTY)},
	{Tag_LISTING, "listing", (CM_BLOCK | CM_OBSOLETE)},
	{Tag_MAP, "map", (CM_INLINE)},
	{Tag_MENU, "menu", (CM_BLOCK | CM_OBSOLETE)},
	{Tag_META, "meta", (CM_HEAD | CM_INLINE | CM_EMPTY)},
	{Tag_NOFRAMES, "noframes", (CM_BLOCK | CM_FRAMES)},
	{Tag_NOSCRIPT, "noscript", (CM_BLOCK | CM_INLINE | CM_MIXED)},
	{Tag_OBJECT, "object",
	 (CM_OBJECT | CM_HEAD | CM_IMG | CM_INLINE | CM_PARAM)},
	{Tag_OL, "ol", (CM_BLOCK | FL_BLOCK)},
	{Tag_OPTGROUP, "optgroup", (CM_FIELD | CM_OPT)},
	{Tag_OPTION, "option", (CM_FIELD | CM_OPT)},
	{Tag_P, "p", (CM_BLOCK | CM_OPT | FL_BLOCK)},
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
	{Tag_SPAN, "span", (CM_INLINE|FL_BLOCK)},
	{Tag_STRIKE, "strike", (CM_INLINE)},
	{Tag_STRONG, "strong", (CM_INLINE)},
	{Tag_STYLE, "style", (CM_HEAD)},
	{Tag_SUB, "sub", (CM_INLINE)},
	{Tag_SUP, "sup", (CM_INLINE)},
	{Tag_TABLE, "table", (CM_BLOCK)},
	{Tag_TBODY, "tbody", (CM_TABLE | CM_ROWGRP | CM_OPT)},
	{Tag_TD, "td", (CM_ROW | CM_OPT | CM_NO_INDENT | FL_BLOCK)},
	{Tag_TEXTAREA, "textarea", (CM_INLINE | CM_FIELD)},
	{Tag_TFOOT, "tfoot", (CM_TABLE | CM_ROWGRP | CM_OPT)},
	{Tag_TH, "th", (CM_ROW | CM_OPT | CM_NO_INDENT)},
	{Tag_THEAD, "thead", (CM_TABLE | CM_ROWGRP | CM_OPT)},
	{Tag_TITLE, "title", (CM_HEAD | CM_UNIQUE)},
	{Tag_TR, "tr", (CM_TABLE | CM_OPT| FL_BLOCK)},
	{Tag_TT, "tt", (CM_INLINE)},
	{Tag_U, "u", (CM_INLINE)},
	{Tag_UL, "ul", (CM_BLOCK|FL_BLOCK)},
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

static sig_atomic_t entities_sorted = 0;
struct _entity;
typedef struct _entity entity;

struct _entity {
	gchar *name;
	uint code;
	gchar *replacement;
};


static entity entities_defs[] = {
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
	{"hellip", 8230, "..."},
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

static entity entities_defs_num[ (G_N_ELEMENTS (entities_defs)) ];
static struct html_tag_def tag_defs_num[ (G_N_ELEMENTS (tag_defs)) ];

static gint
tag_cmp (const void *m1, const void *m2)
{
	const struct html_tag_def *p1 = m1;
	const struct html_tag_def *p2 = m2;
	gsize l1, l2;

	l1 = strlen (p1->name);
	l2 = strlen (p2->name);

	if (l1 == l2) {
		return g_ascii_strcasecmp (p1->name, p2->name);
	}

	return l1 - l2;
}

static gint
tag_cmp_id (const void *m1, const void *m2)
{
	const struct html_tag_def *p1 = m1;
	const struct html_tag_def *p2 = m2;

	return p1->id - p2->id;
}

static gint
tag_find_id (const void *skey, const void *elt)
{
	const struct html_tag *tag = skey;
	const struct html_tag_def *d = elt;

	return tag->id - d->id;
}

static gint
tag_find (const void *skey, const void *elt)
{
	const struct html_tag *tag = skey;
	const struct html_tag_def *d = elt;
	gsize tlen;

	tlen = strlen (d->name);

	if (tlen == tag->name.len) {
		return g_ascii_strncasecmp (tag->name.start, d->name, tag->name.len);
	}

	return tag->name.len - tlen;
}

static gint
entity_cmp (const void *m1, const void *m2)
{
	const entity *p1 = m1;
	const entity *p2 = m2;

	return g_ascii_strcasecmp (p1->name, p2->name);
}

static gint
entity_cmp_num (const void *m1, const void *m2)
{
	const entity *p1 = m1;
	const entity *p2 = m2;

	return p1->code - p2->code;
}

static gboolean
rspamd_html_check_balance (GNode * node, GNode ** cur_level)
{
	struct html_tag *arg = node->data, *tmp;
	GNode *cur;

	if (arg->flags & FL_CLOSING) {
		/* First of all check whether this tag is closing tag for parent node */
		cur = node->parent;
		while (cur && cur->data) {
			tmp = cur->data;
			if (tmp->id == arg->id &&
				(tmp->flags & FL_CLOSED) == 0) {
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

gboolean
rspamd_html_tag_seen (struct html_content *hc, const gchar *tagname)
{
	struct html_tag tag;
	struct html_tag_def *found;

	g_assert (hc != NULL);
	g_assert (hc->tags_seen != NULL);

	tag.name.start = tagname;
	tag.name.len = strlen (tagname);

	found = bsearch (&tag, tag_defs, G_N_ELEMENTS (tag_defs),
			sizeof (tag_defs[0]), tag_find);

	if (found) {
		return isset (hc->tags_seen, found->id);
	}

	return FALSE;
}

const gchar*
rspamd_html_tag_by_id (gint id)
{
	struct html_tag tag;
	struct html_tag_def *found;

	tag.id = id;
	/* Should work as IDs monotonically increase */
	found = bsearch (&tag, tag_defs_num, G_N_ELEMENTS (tag_defs_num),
				sizeof (tag_defs_num[0]), tag_find_id);

	if (found) {
		return found->name;
	}

	return NULL;
}

/* Decode HTML entitles in text */
guint
rspamd_html_decode_entitles_inplace (gchar *s, guint len)
{
	guint l, rep_len;
	gchar *t = s, *h = s, *e = s, *end_ptr;
	gint state = 0, val, base;
	entity *found, key;

	if (len == 0) {
		l = strlen (s);
	}
	else {
		l = len;
	}

	while (h - s < (gint)l) {
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
			if (*h == ';' && h > e) {
				/* Determine base */
				/* First find in entities table */

				key.name = e + 1;
				*h = '\0';
				if (*(e + 1) != '#' &&
					(found =
					bsearch (&key, entities_defs, G_N_ELEMENTS (entities_defs),
							sizeof (entity), entity_cmp)) != NULL) {
					if (found->replacement) {
						rep_len = strlen (found->replacement);
						memcpy (t, found->replacement, rep_len);
						t += rep_len;
					}
					else {
						memcpy (t, e, h - e);
						t += h - e;
					}
				}
				else if (e + 2 < h) {
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
						memcpy (t, e, h - e);
						t += h - e;
					}
					else {
						/* Search for a replacement */
						key.code = val;
						found =
							bsearch (&key, entities_defs_num, G_N_ELEMENTS (
									entities_defs), sizeof (entity),
								entity_cmp_num);
						if (found) {
							if (found->replacement) {
								rep_len = strlen (found->replacement);
								memcpy (t, found->replacement, rep_len);
								t += rep_len;
							}
						}
						else {
							/* Unicode point */
							if (g_unichar_isgraph (val)) {
								t += g_unichar_to_utf8 (val, t);
							}
							else {
								memcpy (t, e, h - e);
								t += h - e;
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

	return (t - s);
}

static void
rspamd_html_url_is_phished (rspamd_mempool_t *pool,
	struct rspamd_url *href_url,
	const guchar *url_text,
	gsize len,
	gboolean *url_found)
{
	struct rspamd_url *text_url;
	gint rc;
	gchar *url_str = NULL;

	*url_found = FALSE;

	if (rspamd_url_find (pool, url_text, len, &url_str, TRUE) && url_str != NULL) {
		text_url = rspamd_mempool_alloc0 (pool, sizeof (struct rspamd_url));
		rc = rspamd_url_parse (text_url, url_str, strlen (url_str), pool);

		if (rc == URI_ERRNO_OK) {
			if (href_url->hostlen != text_url->hostlen || memcmp (href_url->host,
					text_url->host, href_url->hostlen) != 0) {

				if (href_url->tldlen != text_url->tldlen || memcmp (href_url->tld,
						text_url->tld, href_url->tldlen) != 0) {
					href_url->flags |= RSPAMD_URL_FLAG_PHISHED;
					href_url->phished_url = text_url;
				}
			}

			*url_found = TRUE;
		}
		else {
			msg_info_pool ("extract of url '%s' failed: %s",
					url_str,
					rspamd_url_strerror (rc));
		}
	}

}

static gboolean
rspamd_html_process_tag (rspamd_mempool_t *pool, struct html_content *hc,
		struct html_tag *tag, GNode **cur_level, gboolean *balanced)
{
	GNode *nnode;
	struct html_tag *parent;

	if (hc->html_tags == NULL) {
		nnode = g_node_new (NULL);
		*cur_level = nnode;
		hc->html_tags = nnode;
		rspamd_mempool_add_destructor (pool,
				(rspamd_mempool_destruct_t) g_node_destroy,
				nnode);
	}

	tag->parent = *cur_level;

	if (!(tag->flags & CM_INLINE)) {
		/* Block tag */
		nnode = g_node_new (tag);

		if (tag->flags & FL_CLOSING) {
			if (!*cur_level) {
				msg_debug_pool ("bad parent node");
				g_node_destroy (nnode);
				return FALSE;
			}

			g_node_append (*cur_level, nnode);

			if (!rspamd_html_check_balance (nnode, cur_level)) {
				msg_debug_pool (
						"mark part as unbalanced as it has not pairable closing tags");
				hc->flags |= RSPAMD_HTML_FLAG_UNBALANCED;
				*balanced = FALSE;
			}
			else {
				*balanced = TRUE;
			}
		}
		else {
			parent = (*cur_level)->data;

			if (parent && (parent->flags & FL_IGNORE)) {
				tag->flags |= FL_IGNORE;
			}

			g_node_append (*cur_level, nnode);

			if ((tag->flags & FL_CLOSED) == 0) {
				*cur_level = nnode;
			}

			if (tag->flags & (CM_HEAD|CM_UNKNOWN|FL_IGNORE)) {
				tag->flags |= FL_IGNORE;

				return FALSE;
			}

		}
	}
	else {
		/* Inline tag */
		parent = (*cur_level)->data;

		if (parent && (parent->flags & (CM_HEAD|CM_UNKNOWN|FL_IGNORE))) {
			tag->flags |= FL_IGNORE;

			return FALSE;
		}
	}

	return TRUE;
}

#define NEW_COMPONENT(comp_type) do {							\
	comp = rspamd_mempool_alloc (pool, sizeof (*comp));			\
	comp->type = (comp_type);									\
	comp->start = NULL;											\
	comp->len = 0;												\
	g_queue_push_tail (tag->params, comp);						\
	ret = TRUE;													\
} while(0)

static gboolean
rspamd_html_parse_tag_component (rspamd_mempool_t *pool,
		const guchar *begin, const guchar *end,
		struct html_tag *tag)
{
	struct html_tag_component *comp;
	gint len;
	gboolean ret = FALSE;

	g_assert (end >= begin);
	len = rspamd_html_decode_entitles_inplace ((gchar *)begin, end - begin);

	if (len == 3) {
		if (g_ascii_strncasecmp (begin, "src", len) == 0) {
			NEW_COMPONENT (RSPAMD_HTML_COMPONENT_HREF);
		}
	}
	else if (len == 4) {
		if (g_ascii_strncasecmp (begin, "href", len) == 0) {
			NEW_COMPONENT (RSPAMD_HTML_COMPONENT_HREF);
		}
	}
	else if (tag->id == Tag_IMG) {
		/* Check width and height if presented */
		if (len == 5 && g_ascii_strncasecmp (begin, "width", len) == 0) {
			NEW_COMPONENT (RSPAMD_HTML_COMPONENT_WIDTH);
		}
		else if (len == 6 && g_ascii_strncasecmp (begin, "height", len) == 0) {
			NEW_COMPONENT (RSPAMD_HTML_COMPONENT_HEIGHT);
		}
		else if (g_ascii_strncasecmp (begin, "style", len) == 0) {
			NEW_COMPONENT (RSPAMD_HTML_COMPONENT_STYLE);
		}
	}
	else if (tag->flags & FL_BLOCK) {
		if (len == 5){
			if (g_ascii_strncasecmp (begin, "color", len) == 0) {
				NEW_COMPONENT (RSPAMD_HTML_COMPONENT_COLOR);
			}
			else if (g_ascii_strncasecmp (begin, "style", len) == 0) {
				NEW_COMPONENT (RSPAMD_HTML_COMPONENT_STYLE);
			}
			else if (g_ascii_strncasecmp (begin, "class", len) == 0) {
				NEW_COMPONENT (RSPAMD_HTML_COMPONENT_CLASS);
			}
		}
	}

	return ret;
}

static void
rspamd_html_parse_tag_content (rspamd_mempool_t *pool,
		struct html_content *hc, struct html_tag *tag, const guchar *in,
		gint *statep, guchar const **savep)
{
	enum {
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
	struct html_tag_def *found;
	gboolean store = FALSE;
	struct html_tag_component *comp;

	state = *statep;

	switch (state) {
	case parse_start:
		if (!g_ascii_isalpha (*in) && !g_ascii_isspace (*in)) {
			hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
			state = ignore_bad_tag;
		}
		else if (g_ascii_isalpha (*in)) {
			state = parse_name;
			tag->name.start = in;
		}
		break;

	case parse_name:
		if (g_ascii_isspace (*in) || *in == '>' || *in == '/') {
			g_assert (in >= tag->name.start);

			if (*in == '/') {
				tag->flags |= FL_CLOSED;
			}

			tag->name.len = in - tag->name.start;

			if (tag->name.len == 0) {
				hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
				tag->flags |= FL_BROKEN;
				state = ignore_bad_tag;
			}
			else {
				/* We can safely modify tag's name here, as it is already parsed */
				tag->name.len = rspamd_html_decode_entitles_inplace (
						(gchar *)tag->name.start,
						tag->name.len);

				found = bsearch (tag, tag_defs, G_N_ELEMENTS (tag_defs),
					sizeof (tag_defs[0]), tag_find);
				if (found == NULL) {
					hc->flags |= RSPAMD_HTML_FLAG_UNKNOWN_ELEMENTS;
					tag->id = -1;
				}
				else {
					tag->id = found->id;
					tag->flags = found->flags;
				}
				state = spaces_after_name;
			}
		}
		break;

	case parse_attr_name:
		if (*savep == NULL) {
			state = ignore_bad_tag;
		}
		else {
			if (*in == '=') {
				state = parse_equal;
			}
			else if (g_ascii_isspace (*in)) {
				state = spaces_before_eq;
			}
			else if (*in == '/') {
				tag->flags |= FL_CLOSED;
			}
			else {
				return;
			}

			if (!rspamd_html_parse_tag_component (pool, *savep, in, tag)) {
				/* Ignore unknown params */
				*savep = NULL;
			}
		}

		break;

	case spaces_after_name:
		if (!g_ascii_isspace (*in)) {
			*savep = in;
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
			hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
			tag->flags |= FL_BROKEN;
			state = ignore_bad_tag;
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
			if (*savep != NULL) {
				/* We need to save this param */
				*savep = in;
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
			if (*savep != NULL) {
				/* We need to save this param */
				*savep = in;
			}
			state = parse_value;
		}
		break;

	case parse_start_dquote:
		if (*in == '"') {
			if (*savep != NULL) {
				/* We have an empty attribute value */
				savep = NULL;
			}
			state = spaces_after_param;
		}
		else {
			if (*savep != NULL) {
				/* We need to save this param */
				*savep = in;
			}
			state = parse_dqvalue;
		}
		break;

	case parse_start_squote:
		if (*in == '\'') {
			if (*savep != NULL) {
				/* We have an empty attribute value */
				savep = NULL;
			}
			state = spaces_after_param;
		}
		else {
			if (*savep != NULL) {
				/* We need to save this param */
				*savep = in;
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
			if (*savep != NULL) {
				g_assert (tag->params != NULL);
				comp = g_queue_peek_tail (tag->params);
				g_assert (comp != NULL);
				comp->len = in - *savep;
				comp->start = *savep;
				*savep = NULL;
			}
		}
		break;

	case parse_sqvalue:
		if (*in == '\'') {
			store = TRUE;
			state = parse_end_squote;
		}
		if (store) {
			if (*savep != NULL) {
				g_assert (tag->params != NULL);
				comp = g_queue_peek_tail (tag->params);
				g_assert (comp != NULL);
				comp->len = in - *savep;
				comp->start = *savep;
				*savep = NULL;
			}
		}
		break;

	case parse_value:
		if (g_ascii_isspace (*in) || *in == '>' || *in == '/') {
			if (*in == '/') {
				tag->flags |= FL_CLOSED;
			}
			store = TRUE;
			state = spaces_after_param;
		}
		if (store) {
			if (*savep != NULL) {
				g_assert (tag->params != NULL);
				comp = g_queue_peek_tail (tag->params);
				g_assert (comp != NULL);
				comp->len = in - *savep;
				comp->start = *savep;
				*savep = NULL;
			}
		}
		break;

	case parse_end_dquote:
	case parse_end_squote:
		if (g_ascii_isspace (*in)) {
			state = spaces_after_param;
		}
		break;

	case spaces_after_param:
		if (!g_ascii_isspace (*in)) {
			state = parse_attr_name;
			*savep = in;
		}
		break;

	case ignore_bad_tag:
		break;
	}

	*statep = state;
}

struct rspamd_url *
rspamd_html_process_url (rspamd_mempool_t *pool, const gchar *start, guint len,
		struct html_tag_component *comp)
{
	struct rspamd_url *url;
	gchar *decoded;
	gint rc;
	gsize decoded_len;
	const gchar *p;
	gchar *t, *h;

	p = start;

	/* Strip spaces from the url */
	/* Head spaces */
	while (g_ascii_isspace (*p) && p < start + len) {
		p ++;
		start ++;
		len --;
	}

	if (comp) {
		comp->start = p;
		comp->len = len;
	}

	/* Trailing spaces */
	p = start + len - 1;

	while (g_ascii_isspace (*p) && p >= start) {
		p --;
		len --;

		if (comp) {
			comp->len --;
		}
	}

	/* Also we need to perform url decode */
	decoded = rspamd_mempool_alloc (pool, len + 1);
	rspamd_strlcpy (decoded, start, len + 1);
	decoded_len = rspamd_decode_url (decoded, start, len);

	/* We also need to remove all internal newlines */
	t = decoded;
	h = t;

	while (*h) {
		if (*h == '\r' || *h == '\n') {
			h ++;
			decoded_len --;
		}
		else {
			*t++ = *h++;
		}
	}
	*t = *h;

	if (comp) {
		comp->start = decoded;
		comp->len = decoded_len;
	}

	url = rspamd_mempool_alloc (pool, sizeof (*url));
	rc = rspamd_url_parse (url, decoded, decoded_len, pool);

	if (rc == URI_ERRNO_OK) {

		/* Spaces in href usually mean an attempt to obfuscate URL */
		/* See https://github.com/vstakhov/rspamd/issues/593 */
#if 0
		if (has_spaces) {
			url->flags |= RSPAMD_URL_FLAG_OBSCURED;
		}
#endif

		return url;
	}

	return NULL;
}

static struct rspamd_url *
rspamd_html_process_url_tag (rspamd_mempool_t *pool, struct html_tag *tag)
{
	struct html_tag_component *comp;
	GList *cur;
	struct rspamd_url *url;

	cur = tag->params->head;

	while (cur) {
		comp = cur->data;

		if (comp->type == RSPAMD_HTML_COMPONENT_HREF && comp->len > 0) {
			url = rspamd_html_process_url (pool, comp->start, comp->len, comp);

			if (url && tag->extra == NULL) {
				tag->extra = url;
			}

			return url;
		}

		cur = g_list_next (cur);
	}

	return NULL;
}

static void
rspamd_process_html_url (rspamd_mempool_t *pool, struct rspamd_url *url,
		GHashTable *target)
{
	struct rspamd_url *query_url;
	gchar *url_str;
	gint rc;

	if (url->querylen > 0) {

		if (rspamd_url_find (pool, url->query, url->querylen, &url_str, TRUE)) {
			query_url = rspamd_mempool_alloc0 (pool,
					sizeof (struct rspamd_url));

			rc = rspamd_url_parse (query_url,
					url_str,
					strlen (url_str),
					pool);

			if (rc == URI_ERRNO_OK &&
					url->hostlen > 0) {
				msg_debug_pool ("found url %s in query of url"
						" %*s", url_str, url->querylen, url->query);

				if (!g_hash_table_lookup (target,
						query_url)) {
					g_hash_table_insert (target,
							query_url,
							query_url);
				}
			}
		}
	}
}

static void
rspamd_html_process_img_tag (rspamd_mempool_t *pool, struct html_tag *tag,
		struct html_content *hc)
{
	struct html_tag_component *comp;
	struct html_image *img;
	rspamd_ftok_t fstr;
	const guchar *p;
	GList *cur;
	gulong val;
	gboolean seen_width = FALSE, seen_height = FALSE;

	cur = tag->params->head;
	img = rspamd_mempool_alloc0 (pool, sizeof (*img));
	img->tag = tag;

	while (cur) {
		comp = cur->data;

		if (comp->type == RSPAMD_HTML_COMPONENT_HREF && comp->len > 0) {
			fstr.begin = (gchar *)comp->start;
			fstr.len = comp->len;
			img->src = rspamd_mempool_ftokdup (pool, &fstr);

			if (comp->len > sizeof ("cid:") - 1 && memcmp (comp->start,
					"cid:", sizeof ("cid:") - 1) == 0) {
				/* We have an embedded image */
				img->flags |= RSPAMD_HTML_FLAG_IMAGE_EMBEDDED;
			}
			else {
				img->flags |= RSPAMD_HTML_FLAG_IMAGE_EXTERNAL;
			}
		}
		else if (comp->type == RSPAMD_HTML_COMPONENT_HEIGHT) {
			rspamd_strtoul (comp->start, comp->len, &val);
			img->height = val;
			seen_height = TRUE;
		}
		else if (comp->type == RSPAMD_HTML_COMPONENT_WIDTH) {
			rspamd_strtoul (comp->start, comp->len, &val);
			img->width = val;
			seen_width = TRUE;
		}
		else if (comp->type == RSPAMD_HTML_COMPONENT_STYLE) {
			/* Try to search for height= or width= in style tag */
			if (!seen_height && comp->len > 0) {
				p = rspamd_strncasestr (comp->start, "height", comp->len);

				if (p != NULL) {
					p += sizeof ("height") - 1;

					while (p < comp->start + comp->len) {
						if (g_ascii_isdigit (*p)) {
							rspamd_strtoul (p, comp->len - (p - comp->start), &val);
							img->height = val;
							break;
						}
						else if (!g_ascii_isspace (*p) && *p != '=' && *p != ':') {
							/* Fallback */
							break;
						}
						p ++;
					}
				}
			}

			if (!seen_width && comp->len > 0) {
				p = rspamd_strncasestr (comp->start, "width", comp->len);

				if (p != NULL) {
					p += sizeof ("width") - 1;

					while (p < comp->start + comp->len) {
						if (g_ascii_isdigit (*p)) {
							rspamd_strtoul (p, comp->len - (p - comp->start), &val);
							img->width = val;
							break;
						}
						else if (!g_ascii_isspace (*p) && *p != '=' && *p != ':') {
							/* Fallback */
							break;
						}
						p ++;
					}
				}
			}
		}

		cur = g_list_next (cur);
	}

	if (hc->images == NULL) {
		hc->images = g_ptr_array_sized_new (4);
		rspamd_mempool_add_destructor (pool, rspamd_ptr_array_free_hard,
				hc->images);
	}

	g_ptr_array_add (hc->images, img);
	tag->extra = img;
}

/* Keep sorted by name */
struct html_color_match {
	const char *name;
	guint8 r;
	guint8 g;
	guint8 b;
} html_colors[] = {
	{"black", 0x00, 0x00, 0x00},
	{"blue", 0x00, 0x00, 0xFF},
	{"brown", 0xA5, 0x2A, 0x2A},
	{"cyan", 0x00, 0xFF, 0xFF},
	{"darkblue", 0x00, 0x0, 0x0A0},
	{"gray", 0x80, 0x80, 0x80},
	{"green", 0x00, 0x80, 0x00},
	{"lightblue", 0xAD, 0xD8, 0xE6},
	{"lime", 0x00, 0xFF, 0x00},
	{"magenta", 0xFF, 0x00, 0xFF},
	{"maroon", 0x80, 0x00, 0x00},
	{"olive", 0x80, 0x80, 0x00},
	{"orange", 0xFF, 0xA5, 0x00},
	{"purple", 0x80, 0x00, 0x80},
	{"red",0xFF, 0x00, 0x00},
	{"silver", 0xC0, 0xC0, 0xC0},
	{"white", 0xFF, 0xFF, 0xFF},
	{"yellow", 0xFF, 0xFF, 0x00},
};

static gint
rspamd_html_color_cmp (const void *key, const void *elt)
{
	const rspamd_ftok_t *fk = key;
	const struct html_color_match *el = elt;

	return g_ascii_strncasecmp (fk->begin, el->name, fk->len);
}

static void
rspamd_html_process_color (const gchar *line, guint len, struct html_color *cl)
{
	const gchar *p = line, *end = line + len;
	char hexbuf[7];
	rspamd_ftok_t search;
	struct html_color_match *el;

	memset (cl, 0, sizeof (*cl));

	if (*p == '#') {
		/* HEX color */
		p ++;
		rspamd_strlcpy (hexbuf, p, MIN ((gint)sizeof(hexbuf), end - p + 1));
		cl->d.val = strtoul (hexbuf, NULL, 16);
		cl->valid = TRUE;
	}
	else {
		/* Compare color by name */
		search.begin = line;
		search.len = len;

		el = bsearch (&search, html_colors, G_N_ELEMENTS (html_colors),
				sizeof (html_colors[0]), rspamd_html_color_cmp);

		if (el != NULL) {
			cl->d.comp.r = el->r;
			cl->d.comp.g = el->g;
			cl->d.comp.b = el->b;
			cl->valid = TRUE;
		}
	}
}

static void
rspamd_html_process_style (rspamd_mempool_t *pool, struct html_block *bl,
		struct html_content *hc, const gchar *style, guint len)
{
	const gchar *p, *c, *end, *key = NULL;
	enum {
		read_key,
		read_colon,
		read_value,
		skip_spaces,
	} state = skip_spaces, next_state = read_key;
	guint klen = 0;

	p = style;
	c = p;
	end = p + len;

	while (p <= end) {
		switch(state) {
		case read_key:
			if (*p == ':') {
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

			p ++;
			break;

		case read_colon:
			if (*p == ':') {
				state = skip_spaces;
				next_state = read_value;
			}

			p ++;
			break;

		case read_value:
			if (*p == ';' || p == end) {
				if (key && klen && p - c > 0) {
					if ((klen == 5 && g_ascii_strncasecmp (key, "color", 5) == 0)
					|| (klen == 10 && g_ascii_strncasecmp (key, "font-color", 10) == 0)) {

						rspamd_html_process_color (c, p - c, &bl->font_color);
						msg_debug_pool ("got color: %xd", bl->font_color.d.val);
					}
					if (klen == 16 && g_ascii_strncasecmp (key,
							"background-color", 16) == 0) {

						rspamd_html_process_color (c, p - c, &bl->background_color);
						msg_debug_pool ("got bgcolor: %xd", bl->background_color.d.val);
					}
				}

				key = NULL;
				klen = 0;
				state = skip_spaces;
				next_state = read_key;
			}

			p ++;
			break;

		case skip_spaces:
			if (!g_ascii_isspace (*p)) {
				c = p;
				state = next_state;
			}
			else {
				p ++;
			}

			break;
		}
	}
}

static void
rspamd_html_process_block_tag (rspamd_mempool_t *pool, struct html_tag *tag,
		struct html_content *hc)
{
	struct html_tag_component *comp;
	struct html_block *bl;
	rspamd_ftok_t fstr;
	GList *cur;

	cur = tag->params->head;
	bl = rspamd_mempool_alloc0 (pool, sizeof (*bl));
	bl->tag = tag;

	while (cur) {
		comp = cur->data;

		if (comp->type == RSPAMD_HTML_COMPONENT_COLOR && comp->len > 0) {
			fstr.begin = (gchar *)comp->start;
			fstr.len = comp->len;
			rspamd_html_process_color (comp->start, comp->len, &bl->font_color);
			msg_debug_pool ("got color: %xd", bl->font_color.d.val);
		}
		else if (comp->type == RSPAMD_HTML_COMPONENT_STYLE && comp->len > 0) {
			bl->style.len = comp->len;
			bl->style.start =  comp->start;
			msg_debug_pool ("got style: %*s", (gint)bl->style.len, bl->style.start);
			rspamd_html_process_style (pool, bl, hc, comp->start, comp->len);
		}
		else if (comp->type == RSPAMD_HTML_COMPONENT_CLASS && comp->len > 0) {
			fstr.begin = (gchar *)comp->start;
			fstr.len = comp->len;
			bl->class = rspamd_mempool_ftokdup (pool, &fstr);
			msg_debug_pool ("got class: %s", bl->class);
		}

		cur = g_list_next (cur);
	}

	if (hc->blocks == NULL) {
		hc->blocks = g_ptr_array_sized_new (64);
		rspamd_mempool_add_destructor (pool, rspamd_ptr_array_free_hard,
				hc->blocks);
	}

	g_ptr_array_add (hc->blocks, bl);
	tag->extra = bl;
}

GByteArray*
rspamd_html_process_part_full (rspamd_mempool_t *pool, struct html_content *hc,
		GByteArray *in, GList **exceptions, GHashTable *urls,  GHashTable *emails)
{
	const guchar *p, *c, *end, *savep = NULL;
	guchar t;
	gboolean closing = FALSE, need_decode = FALSE, save_space = FALSE,
			balanced, url_text;
	GByteArray *dest;
	GHashTable *target_tbl;
	guint obrace = 0, ebrace = 0;
	GNode *cur_level = NULL;
	gint substate = 0, len, href_offset = -1;
	struct html_tag *cur_tag = NULL;
	struct rspamd_url *url = NULL, *turl;
	struct rspamd_process_exception *ex;
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
		content_ignore_sp
	} state = parse_start;

	g_assert (in != NULL);
	g_assert (hc != NULL);
	g_assert (pool != NULL);

	if (!tags_sorted) {
		qsort (tag_defs, G_N_ELEMENTS (
				tag_defs), sizeof (struct html_tag_def), tag_cmp);
		memcpy (tag_defs_num, tag_defs, sizeof (tag_defs));
		qsort (tag_defs_num, G_N_ELEMENTS (tag_defs_num),
				sizeof (struct html_tag_def), tag_cmp_id);
		tags_sorted = 1;
	}
	if (!entities_sorted) {
		qsort (entities_defs, G_N_ELEMENTS (
				entities_defs), sizeof (entity), entity_cmp);
		memcpy (entities_defs_num, entities_defs, sizeof (entities_defs));
		qsort (entities_defs_num, G_N_ELEMENTS (
				entities_defs), sizeof (entity), entity_cmp_num);
		entities_sorted = 1;
	}

	hc->tags_seen = rspamd_mempool_alloc0 (pool, NBYTES (G_N_ELEMENTS (tag_defs)));

	dest = g_byte_array_sized_new (in->len / 3 * 2);

	p = in->data;
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
				p ++;
				break;
			default:
				state = tag_content;
				substate = 0;
				savep = NULL;
				cur_tag = rspamd_mempool_alloc0 (pool, sizeof (*cur_tag));
				cur_tag->params = g_queue_new ();
				rspamd_mempool_add_destructor (pool,
						(rspamd_mempool_destruct_t)g_queue_free, cur_tag->params);
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
			}
			p ++;
			break;

		case comment_tag:
			if (t != '-')  {
				hc->flags |= RSPAMD_HTML_FLAG_BAD_ELEMENTS;
			}
			p ++;
			ebrace = 0;
			state = comment_content;
			break;

		case comment_content:
			if (t == '-') {
				ebrace ++;
			}
			else if (t == '>' && ebrace == 2) {
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

					if (c != p) {
						if (need_decode) {
							len = rspamd_html_decode_entitles_inplace ((gchar *)c,
									p - c);
						}
						else {
							len = p - c;
						}

						g_byte_array_append (dest, c, len);
					}

					c = p;
					state = content_ignore_sp;
				}
				else {
					if (save_space) {
						/* Append one space if needed */
						if (dest->len > 0 &&
								!g_ascii_isspace (dest->data[dest->len - 1])) {
							g_byte_array_append (dest, " ", 1);
						}
						save_space = FALSE;
					}
				}
			}
			else {
				if (c != p) {

					if (need_decode) {
						len = rspamd_html_decode_entitles_inplace ((gchar *)c,
								p - c);
					}
					else {
						len = p - c;
					}

					g_byte_array_append (dest, c, len);
				}

				state = tag_begin;
				continue;
			}

			p ++;
			break;

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
				continue;
			}
			p ++;
			break;

		case tag_content:
			rspamd_html_parse_tag_content (pool, hc, cur_tag,
					p, &substate, &savep);
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
			substate = 0;
			savep = NULL;

			if (cur_tag != NULL) {
				balanced = TRUE;

				if (rspamd_html_process_tag (pool, hc, cur_tag, &cur_level,
						&balanced)) {
					state = content_write;
					need_decode = FALSE;
				}
				else {
					state = content_ignore;
				}

				if (cur_tag->id != -1 && cur_tag->id < N_TAGS) {
					if (cur_tag->flags & CM_UNIQUE) {
						if (isset (hc->tags_seen, cur_tag->id)) {
							/* Duplicate tag has been found */
							hc->flags |= RSPAMD_HTML_FLAG_DUPLICATE_ELEMENTS;
						}
					}
					setbit (hc->tags_seen, cur_tag->id);
				}

				/* Handle newlines */
				if (cur_tag->id == Tag_BR || cur_tag->id == Tag_HR) {
					if (dest->len > 0 && dest->data[dest->len - 1] != '\n') {
						g_byte_array_append (dest, "\r\n", 2);
					}
					save_space = FALSE;
				}
				else if ((cur_tag->flags & (FL_CLOSED|FL_CLOSING)) &&
						(cur_tag->id == Tag_P ||
						cur_tag->id == Tag_TR ||
						cur_tag->id == Tag_DIV) && balanced) {
					if (dest->len > 0 && dest->data[dest->len - 1] != '\n') {
						g_byte_array_append (dest, "\r\n", 2);
					}
					save_space = FALSE;
				}

				if (cur_tag->id == Tag_A || cur_tag->id == Tag_IFRAME) {
					if (!(cur_tag->flags & (FL_CLOSED|FL_CLOSING))) {
						url = rspamd_html_process_url_tag (pool, cur_tag);

						if (url != NULL) {

							if (url->protocol == PROTOCOL_MAILTO) {
								target_tbl = emails;
							}
							else {
								target_tbl = urls;
							}

							if (target_tbl != NULL) {
								turl = g_hash_table_lookup (target_tbl, url);

								if (turl != NULL && turl->phished_url == NULL) {
									g_hash_table_insert (target_tbl, url, url);
								}
								else if (turl == NULL) {
									g_hash_table_insert (target_tbl, url, url);
								}
								else {
									url = NULL;
								}

								if (turl == NULL && url != NULL) {
									rspamd_process_html_url (pool,
											url,
											target_tbl);
								}
							}

							href_offset = dest->len;
						}
					}
					else if (cur_tag->id == Tag_A &&
							(cur_tag->flags & FL_CLOSING)) {
						/* Insert exception */
						if (url != NULL && (gint)dest->len > href_offset) {
							rspamd_html_url_is_phished (pool, url,
									dest->data + href_offset,
									dest->len - href_offset,
									&url_text);
							if (exceptions && url_text) {
								ex = rspamd_mempool_alloc (pool, sizeof (*ex));
								ex->pos = href_offset;
								ex->len = dest->len - href_offset;
								ex->type = RSPAMD_EXCEPTION_URL;

								*exceptions = g_list_prepend (*exceptions, ex);
							}
						}

						href_offset = -1;
						url_text = FALSE;
						url = NULL;
					}
				}

				if (cur_tag->id == Tag_IMG && !(cur_tag->flags & FL_CLOSING)) {
					rspamd_html_process_img_tag (pool, cur_tag, hc);
				}
				else if (!(cur_tag->flags & FL_CLOSING) &&
						(cur_tag->flags & FL_BLOCK)) {
					rspamd_html_process_block_tag (pool, cur_tag, hc);
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

	return dest;
}

GByteArray*
rspamd_html_process_part (rspamd_mempool_t *pool,
		struct html_content *hc,
		GByteArray *in)
{
	return rspamd_html_process_part_full (pool, hc, in, NULL, NULL, NULL);
}
