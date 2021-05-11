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
#include "html_colors.h"
#include "html_entities.h"
#include "url.h"
#include "contrib/libucl/khash.h"
#include "libmime/images.h"
#include "css/css.h"

#include <unicode/uversion.h>
#include <unicode/ucnv.h>
#if U_ICU_VERSION_MAJOR_NUM >= 46
#include <unicode/uidna.h>
#endif

static sig_atomic_t tags_sorted = 0;
static sig_atomic_t entities_sorted = 0;
static const guint max_tags = 8192; /* Ignore tags if this maximum is reached */

struct html_tag_def {
	const gchar *name;
	gint16 id;
	guint16 len;
	guint flags;
};

#define msg_debug_html(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_html_log_id, "html", pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(html)

#define TAG_DEF(id, name, flags) {(name), (id), (sizeof(name) - 1), (flags)}

static struct html_tag_def tag_defs[] = {
	/* W3C defined elements */
	TAG_DEF(Tag_A, "a", FL_HREF),
	TAG_DEF(Tag_ABBR, "abbr", (CM_INLINE)),
	TAG_DEF(Tag_ACRONYM, "acronym", (CM_INLINE)),
	TAG_DEF(Tag_ADDRESS, "address", (CM_BLOCK)),
	TAG_DEF(Tag_APPLET, "applet", (CM_OBJECT | CM_IMG | CM_INLINE | CM_PARAM)),
	TAG_DEF(Tag_AREA, "area", (CM_BLOCK | CM_EMPTY | FL_HREF)),
	TAG_DEF(Tag_B, "b", (CM_INLINE|FL_BLOCK)),
	TAG_DEF(Tag_BASE, "base", (CM_HEAD | CM_EMPTY)),
	TAG_DEF(Tag_BASEFONT, "basefont", (CM_INLINE | CM_EMPTY)),
	TAG_DEF(Tag_BDO, "bdo", (CM_INLINE)),
	TAG_DEF(Tag_BIG, "big", (CM_INLINE)),
	TAG_DEF(Tag_BLOCKQUOTE, "blockquote", (CM_BLOCK)),
	TAG_DEF(Tag_BODY, "body", (CM_HTML | CM_OPT | CM_OMITST | CM_UNIQUE | FL_BLOCK)),
	TAG_DEF(Tag_BR, "br", (CM_INLINE | CM_EMPTY)),
	TAG_DEF(Tag_BUTTON, "button", (CM_INLINE|FL_BLOCK)),
	TAG_DEF(Tag_CAPTION, "caption", (CM_TABLE)),
	TAG_DEF(Tag_CENTER, "center", (CM_BLOCK)),
	TAG_DEF(Tag_CITE, "cite", (CM_INLINE)),
	TAG_DEF(Tag_CODE, "code", (CM_INLINE)),
	TAG_DEF(Tag_COL, "col", (CM_TABLE | CM_EMPTY)),
	TAG_DEF(Tag_COLGROUP, "colgroup", (CM_TABLE | CM_OPT)),
	TAG_DEF(Tag_DD, "dd", (CM_DEFLIST | CM_OPT | CM_NO_INDENT)),
	TAG_DEF(Tag_DEL, "del", (CM_INLINE | CM_BLOCK | CM_MIXED)),
	TAG_DEF(Tag_DFN, "dfn", (CM_INLINE)),
	TAG_DEF(Tag_DIR, "dir", (CM_BLOCK | CM_OBSOLETE)),
	TAG_DEF(Tag_DIV, "div", (CM_BLOCK|FL_BLOCK)),
	TAG_DEF(Tag_DL, "dl", (CM_BLOCK|FL_BLOCK)),
	TAG_DEF(Tag_DT, "dt", (CM_DEFLIST | CM_OPT | CM_NO_INDENT)),
	TAG_DEF(Tag_EM, "em", (CM_INLINE)),
	TAG_DEF(Tag_FIELDSET, "fieldset", (CM_BLOCK)),
	TAG_DEF(Tag_FONT, "font", (FL_BLOCK)),
	TAG_DEF(Tag_FORM, "form", (CM_BLOCK|FL_HREF)),
	TAG_DEF(Tag_FRAME, "frame", (CM_FRAMES | CM_EMPTY | FL_HREF)),
	TAG_DEF(Tag_FRAMESET, "frameset", (CM_HTML | CM_FRAMES)),
	TAG_DEF(Tag_H1, "h1", (CM_BLOCK | CM_HEADING)),
	TAG_DEF(Tag_H2, "h2", (CM_BLOCK | CM_HEADING)),
	TAG_DEF(Tag_H3, "h3", (CM_BLOCK | CM_HEADING)),
	TAG_DEF(Tag_H4, "h4", (CM_BLOCK | CM_HEADING)),
	TAG_DEF(Tag_H5, "h5", (CM_BLOCK | CM_HEADING)),
	TAG_DEF(Tag_H6, "h6", (CM_BLOCK | CM_HEADING)),
	TAG_DEF(Tag_HEAD, "head", (CM_HTML | CM_OPT | CM_OMITST | CM_UNIQUE)),
	TAG_DEF(Tag_HR, "hr", (CM_BLOCK | CM_EMPTY)),
	TAG_DEF(Tag_HTML, "html", (CM_HTML | CM_OPT | CM_OMITST | CM_UNIQUE)),
	TAG_DEF(Tag_I, "i", (CM_INLINE)),
	TAG_DEF(Tag_IFRAME, "iframe", (FL_HREF)),
	TAG_DEF(Tag_IMG, "img", (CM_INLINE | CM_IMG | CM_EMPTY)),
	TAG_DEF(Tag_INPUT, "input", (CM_INLINE | CM_IMG | CM_EMPTY)),
	TAG_DEF(Tag_INS, "ins", (CM_INLINE | CM_BLOCK | CM_MIXED)),
	TAG_DEF(Tag_ISINDEX, "isindex", (CM_BLOCK | CM_EMPTY)),
	TAG_DEF(Tag_KBD, "kbd", (CM_INLINE)),
	TAG_DEF(Tag_LABEL, "label", (CM_INLINE)),
	TAG_DEF(Tag_LEGEND, "legend", (CM_INLINE)),
	TAG_DEF(Tag_LI, "li", (CM_LIST | CM_OPT | CM_NO_INDENT | FL_BLOCK)),
	TAG_DEF(Tag_LINK, "link", (CM_EMPTY|FL_HREF)),
	TAG_DEF(Tag_LISTING, "listing", (CM_BLOCK | CM_OBSOLETE)),
	TAG_DEF(Tag_MAP, "map", (CM_INLINE|FL_HREF)),
	TAG_DEF(Tag_MENU, "menu", (CM_BLOCK | CM_OBSOLETE)),
	TAG_DEF(Tag_META, "meta", (CM_HEAD | CM_INLINE | CM_EMPTY)),
	TAG_DEF(Tag_NOFRAMES, "noframes", (CM_BLOCK | CM_FRAMES)),
	TAG_DEF(Tag_NOSCRIPT, "noscript", (CM_BLOCK | CM_INLINE | CM_MIXED)),
	TAG_DEF(Tag_OBJECT, "object", (CM_OBJECT | CM_HEAD | CM_IMG | CM_INLINE | CM_PARAM)),
	TAG_DEF(Tag_OL, "ol", (CM_BLOCK | FL_BLOCK)),
	TAG_DEF(Tag_OPTGROUP, "optgroup", (CM_FIELD | CM_OPT)),
	TAG_DEF(Tag_OPTION, "option", (CM_FIELD | CM_OPT)),
	TAG_DEF(Tag_P, "p", (CM_BLOCK | CM_OPT | FL_BLOCK)),
	TAG_DEF(Tag_PARAM, "param", (CM_INLINE | CM_EMPTY)),
	TAG_DEF(Tag_PLAINTEXT, "plaintext", (CM_BLOCK | CM_OBSOLETE)),
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
	TAG_DEF(Tag_SCRIPT, "script", (CM_HEAD | CM_MIXED)),
	TAG_DEF(Tag_SELECT, "select", (CM_INLINE | CM_FIELD)),
	TAG_DEF(Tag_SMALL, "small", (CM_INLINE)),
	TAG_DEF(Tag_SPAN, "span", (CM_BLOCK|FL_BLOCK)),
	TAG_DEF(Tag_STRIKE, "strike", (CM_INLINE)),
	TAG_DEF(Tag_STRONG, "strong", (CM_INLINE)),
	TAG_DEF(Tag_STYLE, "style", (CM_HEAD)),
	TAG_DEF(Tag_SUB, "sub", (CM_INLINE)),
	TAG_DEF(Tag_SUP, "sup", (CM_INLINE)),
	TAG_DEF(Tag_TABLE, "table", (CM_BLOCK | FL_BLOCK)),
	TAG_DEF(Tag_TBODY, "tbody", (CM_TABLE | CM_ROWGRP | CM_OPT| FL_BLOCK)),
	TAG_DEF(Tag_TD, "td", (CM_ROW | CM_OPT | CM_NO_INDENT | FL_BLOCK)),
	TAG_DEF(Tag_TEXTAREA, "textarea", (CM_INLINE | CM_FIELD)),
	TAG_DEF(Tag_TFOOT, "tfoot", (CM_TABLE | CM_ROWGRP | CM_OPT)),
	TAG_DEF(Tag_TH, "th", (CM_ROW | CM_OPT | CM_NO_INDENT | FL_BLOCK)),
	TAG_DEF(Tag_THEAD, "thead", (CM_TABLE | CM_ROWGRP | CM_OPT)),
	TAG_DEF(Tag_TITLE, "title", (CM_HEAD | CM_UNIQUE)),
	TAG_DEF(Tag_TR, "tr", (CM_TABLE | CM_OPT| FL_BLOCK)),
	TAG_DEF(Tag_TT, "tt", (CM_INLINE)),
	TAG_DEF(Tag_U, "u", (CM_INLINE)),
	TAG_DEF(Tag_UL, "ul", (CM_BLOCK|FL_BLOCK)),
	TAG_DEF(Tag_VAR, "var", (CM_INLINE)),
	TAG_DEF(Tag_XMP, "xmp", (CM_BLOCK | CM_OBSOLETE)),
	TAG_DEF(Tag_NEXTID, "nextid", (CM_HEAD | CM_EMPTY)),

	/* proprietary elements */
	TAG_DEF(Tag_ALIGN, "align", (CM_BLOCK)),
	TAG_DEF(Tag_BGSOUND, "bgsound", (CM_HEAD | CM_EMPTY)),
	TAG_DEF(Tag_BLINK, "blink", (CM_INLINE)),
	TAG_DEF(Tag_COMMENT, "comment", (CM_INLINE)),
	TAG_DEF(Tag_EMBED, "embed", (CM_INLINE | CM_IMG | CM_EMPTY)),
	TAG_DEF(Tag_ILAYER, "ilayer", (CM_INLINE)),
	TAG_DEF(Tag_KEYGEN, "keygen", (CM_INLINE | CM_EMPTY)),
	TAG_DEF(Tag_LAYER, "layer", (CM_BLOCK)),
	TAG_DEF(Tag_MARQUEE, "marquee", (CM_INLINE | CM_OPT)),
	TAG_DEF(Tag_MULTICOL, "multicol", (CM_BLOCK)),
	TAG_DEF(Tag_NOBR, "nobr", (CM_INLINE)),
	TAG_DEF(Tag_NOEMBED, "noembed", (CM_INLINE)),
	TAG_DEF(Tag_NOLAYER, "nolayer", (CM_BLOCK | CM_INLINE | CM_MIXED)),
	TAG_DEF(Tag_NOSAVE, "nosave", (CM_BLOCK)),
	TAG_DEF(Tag_SERVER, "server", (CM_HEAD | CM_MIXED | CM_BLOCK | CM_INLINE)),
	TAG_DEF(Tag_SERVLET, "servlet", (CM_OBJECT | CM_IMG | CM_INLINE | CM_PARAM)),
	TAG_DEF(Tag_SPACER, "spacer", (CM_INLINE | CM_EMPTY)),
	TAG_DEF(Tag_WBR, "wbr", (CM_INLINE | CM_EMPTY)),
};

KHASH_MAP_INIT_INT (entity_by_number, const char *);
KHASH_MAP_INIT_STR (entity_by_name, const char *);
KHASH_MAP_INIT_STR (tag_by_name, struct html_tag_def);
KHASH_MAP_INIT_INT (tag_by_id, struct html_tag_def);
KHASH_INIT (color_by_name, const rspamd_ftok_t *, struct html_color, true,
		rspamd_ftok_icase_hash, rspamd_ftok_icase_equal);

khash_t(entity_by_number) *html_entity_by_number;
khash_t(entity_by_name) *html_entity_by_name;
khash_t(tag_by_name) *html_tag_by_name;
khash_t(tag_by_id) *html_tag_by_id;
khash_t(color_by_name) *html_color_by_name;

static struct rspamd_url *rspamd_html_process_url (rspamd_mempool_t *pool,
												   const gchar *start, guint len,
												   struct html_tag_component *comp);

static void
rspamd_html_library_init (void)
{
	guint i;
	khiter_t k;
	gint rc;

	if (!tags_sorted) {
		html_tag_by_id = kh_init (tag_by_id);
		html_tag_by_name = kh_init (tag_by_name);
		kh_resize (tag_by_id, html_tag_by_id, G_N_ELEMENTS (tag_defs));
		kh_resize (tag_by_name, html_tag_by_name, G_N_ELEMENTS (tag_defs));

		for (i = 0; i < G_N_ELEMENTS (tag_defs); i++) {
			k = kh_put (tag_by_id, html_tag_by_id, tag_defs[i].id, &rc);

			if (rc == 0) {
				/* Collision by id */
				msg_err ("collision in html tag id: %d (%s) vs %d (%s)",
						(int)tag_defs[i].id, tag_defs[i].name,
						(int)kh_val (html_tag_by_id, k).id, kh_val (html_tag_by_id, k).name);
			}

			kh_val (html_tag_by_id, k) = tag_defs[i];

			k = kh_put (tag_by_name, html_tag_by_name, tag_defs[i].name, &rc);

			if (rc == 0) {
				/* Collision by name */
				msg_err ("collision in html tag name: %d (%s) vs %d (%s)",
						(int)tag_defs[i].id, tag_defs[i].name,
						(int)kh_val (html_tag_by_id, k).id, kh_val (html_tag_by_id, k).name);
			}

			kh_val (html_tag_by_name, k) = tag_defs[i];
		}

		tags_sorted = 1;
	}

	if (!entities_sorted) {
		html_entity_by_number = kh_init (entity_by_number);
		html_entity_by_name = kh_init (entity_by_name);
		kh_resize (entity_by_number, html_entity_by_number,
				G_N_ELEMENTS (entities_defs));
		kh_resize (entity_by_name, html_entity_by_name,
				G_N_ELEMENTS (entities_defs));

		for (i = 0; i < G_N_ELEMENTS (entities_defs); i++) {
			if (entities_defs[i].code != 0) {
				k = kh_put (entity_by_number, html_entity_by_number,
						entities_defs[i].code, &rc);

				if (rc == 0) {
					/* Collision by id */
					gint cmp_res = strcmp (entities_defs[i].replacement,
							kh_val (html_entity_by_number, k));
					if (cmp_res != 0) {
						if (strlen (entities_defs[i].replacement) <
							strlen (kh_val (html_entity_by_number, k))) {
							/* Shorter replacement is more likely to be valid */
							msg_debug ("1 collision in html entity id: %d (%s); replace %s by %s",
									(int) entities_defs[i].code, entities_defs[i].name,
									kh_val (html_entity_by_number, k),
									entities_defs[i].replacement);
							kh_val (html_entity_by_number, k) = entities_defs[i].replacement;
						}
						else if (strlen (entities_defs[i].replacement) ==
								 strlen (kh_val (html_entity_by_number, k)) &&
										 cmp_res < 0) {
							/* Identical len but lexicographically shorter */
							msg_debug ("collision in html entity id: %d (%s); replace %s by %s",
									(int) entities_defs[i].code, entities_defs[i].name,
									kh_val (html_entity_by_number, k),
									entities_defs[i].replacement);
							kh_val (html_entity_by_number, k) = entities_defs[i].replacement;
						}
						/* Do not replace otherwise */
					}
					/* Identic replacement */
				}
				else {
					kh_val (html_entity_by_number, k) = entities_defs[i].replacement;
				}
			}

			k = kh_put (entity_by_name, html_entity_by_name,
					entities_defs[i].name, &rc);

			if (rc == 0) {
				/* Collision by name */
				if (strcmp (kh_val (html_entity_by_number, k),
						entities_defs[i].replacement) != 0) {
					msg_err ("collision in html entity name: %d (%s)",
							(int) entities_defs[i].code, entities_defs[i].name);
				}
			}

			kh_val (html_entity_by_name, k) = entities_defs[i].replacement;
		}

		html_color_by_name = kh_init (color_by_name);
		kh_resize (color_by_name, html_color_by_name,
				G_N_ELEMENTS (html_colornames));

		rspamd_ftok_t *keys;

		keys = g_malloc0 (sizeof (rspamd_ftok_t) *
						  G_N_ELEMENTS (html_colornames));

		for (i = 0; i < G_N_ELEMENTS (html_colornames); i ++) {
			struct html_color c;

			keys[i].begin = html_colornames[i].name;
			keys[i].len = strlen (html_colornames[i].name);
			k = kh_put (color_by_name, html_color_by_name,
					&keys[i], &rc);
			c.valid = true;
			c.d.comp.r = html_colornames[i].rgb.r;
			c.d.comp.g = html_colornames[i].rgb.g;
			c.d.comp.b = html_colornames[i].rgb.b;
			c.d.comp.alpha = 255;
			kh_val (html_color_by_name, k) = c;

		}

		entities_sorted = 1;
	}
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

gint
rspamd_html_tag_by_name (const gchar *name)
{
	khiter_t k;

	k = kh_get (tag_by_name, html_tag_by_name, name);

	if (k != kh_end (html_tag_by_name)) {
		return kh_val (html_tag_by_name, k).id;
	}

	return -1;
}

gboolean
rspamd_html_tag_seen (struct html_content *hc, const gchar *tagname)
{
	gint id;

	g_assert (hc != NULL);
	g_assert (hc->tags_seen != NULL);

	id = rspamd_html_tag_by_name (tagname);

	if (id != -1) {
		return isset (hc->tags_seen, id);
	}

	return FALSE;
}

const gchar *
rspamd_html_tag_by_id (gint id)
{
	khiter_t k;

	k = kh_get (tag_by_id, html_tag_by_id, id);

	if (k != kh_end (html_tag_by_id)) {
		return kh_val (html_tag_by_id, k).name;
	}

	return NULL;
}

/* Decode HTML entitles in text */
guint
rspamd_html_decode_entitles_inplace (gchar *s, gsize len)
{
	goffset l, rep_len;
	gchar *t = s, *h = s, *e = s, *end_ptr, old_c;
	const gchar *end;
	const gchar *entity;
	gboolean seen_hash = FALSE, seen_hex = FALSE;
	enum {
		do_undefined,
		do_digits_only,
		do_mixed,
	} seen_digit_only;
	gint state = 0, base;
	UChar32 uc;
	khiter_t k;

	if (len == 0) {
		return 0;
	}
	else {
		l = len;
	}

	end = s + l;

	while (h - s < l && t <= h) {
		switch (state) {
		/* Out of entity */
		case 0:
			if (*h == '&') {
				state = 1;
				seen_hash = FALSE;
				seen_hex = FALSE;
				seen_digit_only = do_undefined;
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
decode_entity:
				/* Determine base */
				/* First find in entities table */
				old_c = *h;
				*h = '\0';
				entity = e + 1;
				uc = 0;

				if (*entity != '#') {
					k = kh_get (entity_by_name, html_entity_by_name, entity);
					*h = old_c;

					if (k != kh_end (html_entity_by_name)) {
						if (kh_val (html_entity_by_name, k)) {
							rep_len = strlen (kh_val (html_entity_by_name, k));

							if (end - t >= rep_len) {
								memcpy (t, kh_val (html_entity_by_name, k),
										rep_len);
								t += rep_len;
							}
						} else {
							if (end - t > h - e + 1) {
								memmove (t, e, h - e + 1);
								t += h - e + 1;
							}
						}
					}
					else {
						if (end - t > h - e + 1) {
							memmove (t, e, h - e + 1);
							t += h - e + 1;
						}
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
						uc = strtoul ((e + 2), &end_ptr, base);
					}
					else {
						uc = strtoul ((e + 3), &end_ptr, base);
					}

					if (end_ptr != NULL && *end_ptr != '\0') {
						/* Skip undecoded */
						*h = old_c;

						if (end - t > h - e + 1) {
							memmove (t, e, h - e + 1);
							t += h - e + 1;
						}
					}
					else {
						/* Search for a replacement */
						*h = old_c;
						k = kh_get (entity_by_number, html_entity_by_number, uc);

						if (k != kh_end (html_entity_by_number)) {
							if (kh_val (html_entity_by_number, k)) {
								rep_len = strlen (kh_val (html_entity_by_number, k));

								if (end - t >= rep_len) {
									memcpy (t, kh_val (html_entity_by_number, k),
											rep_len);
									t += rep_len;
								}
							} else {
								if (end - t > h - e + 1) {
									memmove (t, e, h - e + 1);
									t += h - e + 1;
								}
							}
						}
						else {
							/* Unicode point */
							goffset off = t - s;
							UBool is_error = 0;

							if (uc > 0) {
								U8_APPEND (s, off, len, uc, is_error);
								if (!is_error) {
									t = s + off;
								}
								else {
									/* Leave invalid entities as is */
									if (end - t > h - e + 1) {
										memmove (t, e, h - e + 1);
										t += h - e + 1;
									}
								}
							}
							else if (end - t > h - e + 1) {
								memmove (t, e, h - e + 1);
								t += h - e + 1;
							}
						}

						if (end - t > 0 && old_c != ';') {
							/* Fuck email clients, fuck them */
							*t++ = old_c;
						}
					}
				}

				state = 0;
			}
			else if (*h == '&') {
				/* Previous `&` was bogus */
				state = 1;

				if (end - t > h - e) {
					memmove (t, e, h - e);
					t += h - e;
				}

				e = h;
			}
			else if (*h == '#') {
				seen_hash = TRUE;

				if (h + 1 < end && h[1] == 'x') {
					seen_hex = TRUE;
					/* Skip one more character */
					h ++;
				}
			}
			else if (seen_digit_only != do_mixed &&
				(g_ascii_isdigit (*h) || (seen_hex && g_ascii_isxdigit (*h)))) {
				seen_digit_only = do_digits_only;
			}
			else {
				if (seen_digit_only == do_digits_only && seen_hash && h > e) {
					/* We have seen some digits, so we can try to decode, eh */
					/* Fuck retarded email clients... */
					goto decode_entity;
				}

				seen_digit_only = do_mixed;
			}

			h++;

			break;
		}
	}

	/* Leftover */
	if (state == 1 && h > e) {
		/* Unfinished entity, copy as is */
		if (end - t >= h - e) {
			memmove (t, e, h - e);
			t += h - e;
		}
	}

	return (t - s);
}

static gboolean
rspamd_url_is_subdomain (rspamd_ftok_t *t1, rspamd_ftok_t *t2)
{
	const gchar *p1, *p2;

	p1 = t1->begin + t1->len - 1;
	p2 = t2->begin + t2->len - 1;

	/* Skip trailing dots */
	while (p1 > t1->begin) {
		if (*p1 != '.') {
			break;
		}

		p1 --;
	}

	while (p2 > t2->begin) {
		if (*p2 != '.') {
			break;
		}

		p2 --;
	}

	while (p1 > t1->begin && p2 > t2->begin) {
		if (*p1 != *p2) {
			break;
		}

		p1 --;
		p2 --;
	}

	if (p2 == t2->begin) {
		/* p2 can be subdomain of p1 if *p1 is '.' */
		if (p1 != t1->begin && *(p1 - 1) == '.') {
			return TRUE;
		}
	}
	else if (p1 == t1->begin) {
		if (p2 != t2->begin && *(p2 - 1) == '.') {
			return TRUE;
		}
	}

	return FALSE;
}

static void
rspamd_html_url_is_phished (rspamd_mempool_t *pool,
	struct rspamd_url *href_url,
	const guchar *url_text,
	gsize len,
	gboolean *url_found,
	struct rspamd_url **ptext_url)
{
	struct rspamd_url *text_url;
	rspamd_ftok_t disp_tok, href_tok;
	gint rc;
	goffset url_pos;
	gchar *url_str = NULL, *idn_hbuf;
	const guchar *end = url_text + len, *p;
#if U_ICU_VERSION_MAJOR_NUM >= 46
	static UIDNA *udn;
	UErrorCode uc_err = U_ZERO_ERROR;
	UIDNAInfo uinfo = UIDNA_INFO_INITIALIZER;
#endif

	*url_found = FALSE;
#if U_ICU_VERSION_MAJOR_NUM >= 46
	if (udn == NULL) {
		udn = uidna_openUTS46 (UIDNA_DEFAULT, &uc_err);

		if (uc_err != U_ZERO_ERROR) {
			msg_err_pool ("cannot init idna converter: %s", u_errorName (uc_err));
		}
	}
#endif

	while (url_text < end && g_ascii_isspace (*url_text)) {
		url_text ++;
	}

	if (end > url_text + 4 &&
			rspamd_url_find (pool, url_text, end - url_text, &url_str,
					RSPAMD_URL_FIND_ALL,
					&url_pos, NULL) &&
			url_str != NULL) {
		if (url_pos > 0) {
			/*
			 * We have some url at some offset, so we need to check what is
			 * at the start of the text
			 */
			p = url_text;

			while (p < url_text + url_pos) {
				if (!g_ascii_isspace (*p)) {
					*url_found = FALSE;
					return;
				}

				p++;
			}
		}

		text_url = rspamd_mempool_alloc0 (pool, sizeof (struct rspamd_url));
		rc = rspamd_url_parse (text_url, url_str, strlen (url_str), pool,
				RSPAMD_URL_PARSE_TEXT);

		if (rc == URI_ERRNO_OK) {
			disp_tok.len = text_url->hostlen;
			disp_tok.begin = rspamd_url_host_unsafe (text_url);
#if U_ICU_VERSION_MAJOR_NUM >= 46
			if (rspamd_substring_search_caseless (rspamd_url_host_unsafe (text_url),
					text_url->hostlen, "xn--", 4) != -1) {
				idn_hbuf = rspamd_mempool_alloc (pool, text_url->hostlen * 2 + 1);
				/* We need to convert it to the normal value first */
				disp_tok.len = uidna_nameToUnicodeUTF8 (udn,
						rspamd_url_host_unsafe (text_url), text_url->hostlen,
						idn_hbuf, text_url->hostlen * 2 + 1, &uinfo, &uc_err);

				if (uc_err != U_ZERO_ERROR) {
					msg_err_pool ("cannot convert to IDN: %s",
							u_errorName (uc_err));
					disp_tok.len = text_url->hostlen;
				}
				else {
					disp_tok.begin = idn_hbuf;
				}
			}
#endif
			href_tok.len = href_url->hostlen;
			href_tok.begin = rspamd_url_host_unsafe (href_url);
#if U_ICU_VERSION_MAJOR_NUM >= 46
			if (rspamd_substring_search_caseless (rspamd_url_host_unsafe (href_url),
					href_url->hostlen, "xn--", 4) != -1) {
				idn_hbuf = rspamd_mempool_alloc (pool, href_url->hostlen * 2 + 1);
				/* We need to convert it to the normal value first */
				href_tok.len = uidna_nameToUnicodeUTF8 (udn,
						rspamd_url_host_unsafe (href_url), href_url->hostlen,
						idn_hbuf, href_url->hostlen * 2 + 1, &uinfo, &uc_err);

				if (uc_err != U_ZERO_ERROR) {
					msg_err_pool ("cannot convert to IDN: %s",
							u_errorName (uc_err));
					href_tok.len = href_url->hostlen;
				}
				else {
					href_tok.begin = idn_hbuf;
				}
			}
#endif
			if (rspamd_ftok_casecmp (&disp_tok, &href_tok) != 0 &&
					text_url->tldlen > 0 && href_url->tldlen > 0) {

				/* Apply the same logic for TLD */
				disp_tok.len = text_url->tldlen;
				disp_tok.begin = rspamd_url_tld_unsafe (text_url);
#if U_ICU_VERSION_MAJOR_NUM >= 46
				if (rspamd_substring_search_caseless (rspamd_url_tld_unsafe (text_url),
						text_url->tldlen, "xn--", 4) != -1) {
					idn_hbuf = rspamd_mempool_alloc (pool, text_url->tldlen * 2 + 1);
					/* We need to convert it to the normal value first */
					disp_tok.len = uidna_nameToUnicodeUTF8 (udn,
							rspamd_url_tld_unsafe (text_url), text_url->tldlen,
							idn_hbuf, text_url->tldlen * 2 + 1, &uinfo, &uc_err);

					if (uc_err != U_ZERO_ERROR) {
						msg_err_pool ("cannot convert to IDN: %s",
								u_errorName (uc_err));
						disp_tok.len = text_url->tldlen;
					}
					else {
						disp_tok.begin = idn_hbuf;
					}
				}
#endif
				href_tok.len = href_url->tldlen;
				href_tok.begin = rspamd_url_tld_unsafe (href_url);
#if U_ICU_VERSION_MAJOR_NUM >= 46
				if (rspamd_substring_search_caseless (rspamd_url_tld_unsafe (href_url),
						href_url->tldlen, "xn--", 4) != -1) {
					idn_hbuf = rspamd_mempool_alloc (pool, href_url->tldlen * 2 + 1);
					/* We need to convert it to the normal value first */
					href_tok.len = uidna_nameToUnicodeUTF8 (udn,
							rspamd_url_tld_unsafe (href_url), href_url->tldlen,
							idn_hbuf, href_url->tldlen * 2 + 1, &uinfo, &uc_err);

					if (uc_err != U_ZERO_ERROR) {
						msg_err_pool ("cannot convert to IDN: %s",
								u_errorName (uc_err));
						href_tok.len = href_url->tldlen;
					}
					else {
						href_tok.begin = idn_hbuf;
					}
				}
#endif
				if (rspamd_ftok_casecmp (&disp_tok, &href_tok) != 0) {
					/* Check if one url is a subdomain for another */

					if (!rspamd_url_is_subdomain (&disp_tok, &href_tok)) {
						href_url->flags |= RSPAMD_URL_FLAG_PHISHED;
						href_url->linked_url = text_url;
						text_url->flags |= RSPAMD_URL_FLAG_HTML_DISPLAYED;
					}
				}
			}

			*ptext_url = text_url;
			*url_found = TRUE;
		}
		else {
			/*
			 * We have found something that looks like an url but it was
			 * not parsed correctly.
			 * Sometimes it means an obfuscation attempt, so we have to check
			 * what's inside of the text
			 */
			gboolean obfuscation_found = FALSE;

			if (len > 4 && g_ascii_strncasecmp (url_text, "http", 4) == 0 &&
				rspamd_substring_search (url_text, len,"://", 3) != -1) {
				/* Clearly an obfuscation attempt */
				obfuscation_found = TRUE;
			}

			msg_info_pool ("extract of url '%s' failed: %s; obfuscation detected: %s",
					url_str,
					rspamd_url_strerror (rc),
					obfuscation_found ? "yes" : "no");

			if (obfuscation_found) {
				href_url->flags |= RSPAMD_URL_FLAG_PHISHED|RSPAMD_URL_FLAG_OBSCURED;
			}
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

	if (hc->total_tags > max_tags) {
		hc->flags |= RSPAMD_HTML_FLAG_TOO_MANY_TAGS;
	}

	if (tag->id == -1) {
		/* Ignore unknown tags */
		hc->total_tags ++;
		return FALSE;
	}

	tag->parent = *cur_level;

	if (!(tag->flags & (CM_INLINE|CM_EMPTY))) {
		/* Block tag */
		if (tag->flags & (FL_CLOSING|FL_CLOSED)) {
			if (!*cur_level) {
				msg_debug_html ("bad parent node");
				return FALSE;
			}

			if (hc->total_tags < max_tags) {
				nnode = g_node_new (tag);
				g_node_append (*cur_level, nnode);

				if (!rspamd_html_check_balance (nnode, cur_level)) {
					msg_debug_html (
							"mark part as unbalanced as it has not pairable closing tags");
					hc->flags |= RSPAMD_HTML_FLAG_UNBALANCED;
					*balanced = FALSE;
				} else {
					*balanced = TRUE;
				}

				hc->total_tags ++;
			}
		}
		else {
			parent = (*cur_level)->data;

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

						if (hc->total_tags < max_tags) {
							nnode = g_node_new (tag);
							g_node_append (parent->parent, nnode);
							*cur_level = nnode;
							hc->total_tags ++;
						}

						return TRUE;
					}
				}
			}

			if (hc->total_tags < max_tags) {
				nnode = g_node_new (tag);
				g_node_append (*cur_level, nnode);

				if ((tag->flags & FL_CLOSED) == 0) {
					*cur_level = nnode;
				}

				hc->total_tags ++;
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

		if (parent) {
			if (hc->total_tags < max_tags) {
				nnode = g_node_new (tag);
				g_node_append (*cur_level, nnode);

				hc->total_tags ++;
			}
			if ((parent->flags & (CM_HEAD|CM_UNKNOWN|FL_IGNORE))) {
				tag->flags |= FL_IGNORE;

				return FALSE;
			}
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
	gchar *p;

	if (end <= begin) {
		return FALSE;
	}

	p = rspamd_mempool_alloc (pool, end - begin);
	memcpy (p, begin, end - begin);
	len = rspamd_html_decode_entitles_inplace (p, end - begin);

	if (len == 3) {
		if (g_ascii_strncasecmp (p, "src", len) == 0) {
			NEW_COMPONENT (RSPAMD_HTML_COMPONENT_HREF);
		}
		else if (g_ascii_strncasecmp (p, "rel", len) == 0) {
			NEW_COMPONENT (RSPAMD_HTML_COMPONENT_REL);
		}
		else if (g_ascii_strncasecmp (p, "alt", len) == 0) {
			NEW_COMPONENT (RSPAMD_HTML_COMPONENT_ALT);
		}
	}
	else if (len == 4) {
		if (g_ascii_strncasecmp (p, "href", len) == 0) {
			NEW_COMPONENT (RSPAMD_HTML_COMPONENT_HREF);
		}
	}
	else if (len == 6) {
		if (g_ascii_strncasecmp (p, "action", len) == 0) {
			NEW_COMPONENT (RSPAMD_HTML_COMPONENT_HREF);
		}
	}

	if (tag->id == Tag_IMG) {
		/* Check width and height if presented */
		if (len == 5 && g_ascii_strncasecmp (p, "width", len) == 0) {
			NEW_COMPONENT (RSPAMD_HTML_COMPONENT_WIDTH);
		}
		else if (len == 6 && g_ascii_strncasecmp (p, "height", len) == 0) {
			NEW_COMPONENT (RSPAMD_HTML_COMPONENT_HEIGHT);
		}
		else if (g_ascii_strncasecmp (p, "style", len) == 0) {
			NEW_COMPONENT (RSPAMD_HTML_COMPONENT_STYLE);
		}
	}
	else if (tag->id == Tag_FONT) {
		if (len == 5){
			if (g_ascii_strncasecmp (p, "color", len) == 0) {
				NEW_COMPONENT (RSPAMD_HTML_COMPONENT_COLOR);
			}
			else if (g_ascii_strncasecmp (p, "style", len) == 0) {
				NEW_COMPONENT (RSPAMD_HTML_COMPONENT_STYLE);
			}
			else if (g_ascii_strncasecmp (p, "class", len) == 0) {
				NEW_COMPONENT (RSPAMD_HTML_COMPONENT_CLASS);
			}
		}
		else if (len == 7) {
			if (g_ascii_strncasecmp (p, "bgcolor", len) == 0) {
				NEW_COMPONENT (RSPAMD_HTML_COMPONENT_BGCOLOR);
			}
		}
		else if (len == 4) {
			if (g_ascii_strncasecmp (p, "size", len) == 0) {
				NEW_COMPONENT (RSPAMD_HTML_COMPONENT_SIZE);
			}
		}
	}
	else if (tag->flags & FL_BLOCK) {
		if (len == 5){
			if (g_ascii_strncasecmp (p, "color", len) == 0) {
				NEW_COMPONENT (RSPAMD_HTML_COMPONENT_COLOR);
			}
			else if (g_ascii_strncasecmp (p, "style", len) == 0) {
				NEW_COMPONENT (RSPAMD_HTML_COMPONENT_STYLE);
			}
			else if (g_ascii_strncasecmp (p, "class", len) == 0) {
				NEW_COMPONENT (RSPAMD_HTML_COMPONENT_CLASS);
			}
		}
		else if (len == 7) {
			if (g_ascii_strncasecmp (p, "bgcolor", len) == 0) {
				NEW_COMPONENT (RSPAMD_HTML_COMPONENT_BGCOLOR);
			}
		}
	}

	return ret;
}

static inline void
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
			tag->id = -1;
			tag->flags |= FL_BROKEN;
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
				tag->id = -1;
				tag->flags |= FL_BROKEN;
				state = ignore_bad_tag;
			}
			else {
				gchar *s;
				khiter_t k;
				/* We CANNOT safely modify tag's name here, as it is already parsed */

				s = rspamd_mempool_alloc (pool, tag->name.len + 1);
				memcpy (s, tag->name.start, tag->name.len);
				tag->name.len = rspamd_html_decode_entitles_inplace (s,
						tag->name.len);
				tag->name.start = s;
				tag->name.len = rspamd_str_lc_utf8 (s, tag->name.len);
				s[tag->name.len] = '\0';

				k = kh_get (tag_by_name, html_tag_by_name, s);

				if (k == kh_end (html_tag_by_name)) {
					hc->flags |= RSPAMD_HTML_FLAG_UNKNOWN_ELEMENTS;
					tag->id = -1;
				}
				else {
					found = &kh_val (html_tag_by_name, k);
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
			const guchar *attr_name_end = in;

			if (*in == '=') {
				state = parse_equal;
			}
			else if (*in == '"') {
				/* No equal or something sane but we have quote character */
				state = parse_start_dquote;
				attr_name_end = in - 1;

				while (attr_name_end > *savep) {
					if (!g_ascii_isalnum (*attr_name_end)) {
						attr_name_end --;
					}
					else {
						break;
					}
				}

				/* One character forward to obtain length */
				attr_name_end ++;
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

				while (attr_name_end > *savep) {
					if (!g_ascii_isalnum (*attr_name_end)) {
						attr_name_end --;
					}
					else {
						break;
					}
				}

				/* One character forward to obtain length */
				attr_name_end ++;
			}
			else {
				return;
			}

			if (!rspamd_html_parse_tag_component (pool, *savep, attr_name_end, tag)) {
				/* Ignore unknown params */
				*savep = NULL;
			}
			else if (state == parse_value) {
				*savep = in + 1;
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
				*savep = in;
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
				gchar *s;

				g_assert (tag->params != NULL);
				comp = g_queue_peek_tail (tag->params);
				g_assert (comp != NULL);
				comp->len = in - *savep;
				s = rspamd_mempool_alloc (pool, comp->len);
				memcpy (s, *savep, comp->len);
				comp->len = rspamd_html_decode_entitles_inplace (s, comp->len);
				comp->start = s;
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
				gchar *s;

				g_assert (tag->params != NULL);
				comp = g_queue_peek_tail (tag->params);
				g_assert (comp != NULL);
				comp->len = in - *savep;
				s = rspamd_mempool_alloc (pool, comp->len);
				memcpy (s, *savep, comp->len);
				comp->len = rspamd_html_decode_entitles_inplace (s, comp->len);
				comp->start = s;
				*savep = NULL;
			}
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
			if (*savep != NULL) {
				gchar *s;

				g_assert (tag->params != NULL);
				comp = g_queue_peek_tail (tag->params);
				g_assert (comp != NULL);
				comp->len = in - *savep;
				s = rspamd_mempool_alloc (pool, comp->len);
				memcpy (s, *savep, comp->len);
				comp->len = rspamd_html_decode_entitles_inplace (s, comp->len);
				comp->start = s;
				*savep = NULL;
			}
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
			*savep = in;
		}
		break;

	case spaces_after_param:
		if (!g_ascii_isspace (*in)) {
			if (*in == '/' && *(in + 1) == '>') {
				tag->flags |= FL_CLOSED;
			}

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
	guint saved_flags = 0;
	gchar *decoded;
	gint rc;
	gsize decoded_len;
	const gchar *p, *s, *prefix = "http://";
	gchar *d;
	guint i;
	gsize dlen;
	gboolean has_bad_chars = FALSE, no_prefix = FALSE;
	static const gchar hexdigests[16] = "0123456789abcdef";

	p = start;

	/* Strip spaces from the url */
	/* Head spaces */
	while (p < start + len && g_ascii_isspace (*p)) {
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

	while (p >= start && g_ascii_isspace (*p)) {
		p --;
		len --;

		if (comp) {
			comp->len --;
		}
	}

	s = start;
	dlen = 0;

	for (i = 0; i < len; i ++) {
		if (G_UNLIKELY (((guint)s[i]) < 0x80 && !g_ascii_isgraph (s[i]))) {
			dlen += 3;
		}
		else {
			dlen ++;
		}
	}

	if (rspamd_substring_search (start, len, "://", 3) == -1) {
		if (len >= sizeof ("mailto:") &&
				(memcmp (start, "mailto:", sizeof ("mailto:") - 1) == 0 ||
				 memcmp (start, "tel:", sizeof ("tel:") - 1) == 0 ||
				 memcmp (start, "callto:", sizeof ("callto:") - 1) == 0)) {
			/* Exclusion, has valid but 'strange' prefix */
		}
		else {
			for (i = 0; i < len; i ++) {
				if (!((s[i] & 0x80) || g_ascii_isalnum (s[i]))) {
					if (i == 0 && len > 2 && s[i] == '/'  && s[i + 1] == '/') {
						prefix = "http:";
						dlen += sizeof ("http:") - 1;
						no_prefix = TRUE;
					}
					else if (s[i] == '@') {
						/* Likely email prefix */
						prefix = "mailto://";
						dlen += sizeof ("mailto://") - 1;
						no_prefix = TRUE;
					}
					else if (s[i] == ':' && i != 0) {
						/* Special case */
						no_prefix = FALSE;
					}
					else {
						if (i == 0) {
							/* No valid data */
							return NULL;
						}
						else {
							no_prefix = TRUE;
							dlen += strlen (prefix);
						}
					}

					break;
				}
			}
		}
	}

	decoded = rspamd_mempool_alloc (pool, dlen + 1);
	d = decoded;

	if (no_prefix) {
		gsize plen = strlen (prefix);
		memcpy (d, prefix, plen);
		d += plen;
	}

	/*
	 * We also need to remove all internal newlines, spaces
	 * and encode unsafe characters
	 */
	for (i = 0; i < len; i ++) {
		if (G_UNLIKELY (g_ascii_isspace (s[i]))) {
			continue;
		}
		else if (G_UNLIKELY (((guint)s[i]) < 0x80 && !g_ascii_isgraph (s[i]))) {
			/* URL encode */
			*d++ = '%';
			*d++ = hexdigests[(s[i] >> 4) & 0xf];
			*d++ = hexdigests[s[i] & 0xf];
			has_bad_chars = TRUE;
		}
		else {
			*d++ = s[i];
		}
	}

	*d = '\0';
	dlen = d - decoded;

	url = rspamd_mempool_alloc0 (pool, sizeof (*url));

	rspamd_url_normalise_propagate_flags (pool, decoded, &dlen, saved_flags);

	rc = rspamd_url_parse (url, decoded, dlen, pool, RSPAMD_URL_PARSE_HREF);

	/* Filter some completely damaged urls */
	if (rc == URI_ERRNO_OK && url->hostlen > 0 &&
		!((url->protocol & PROTOCOL_UNKNOWN))) {
		url->flags |= saved_flags;

		if (has_bad_chars) {
			url->flags |= RSPAMD_URL_FLAG_OBSCURED;
		}

		if (no_prefix) {
			url->flags |= RSPAMD_URL_FLAG_SCHEMALESS;

			if (url->tldlen == 0 || (url->flags & RSPAMD_URL_FLAG_NO_TLD)) {
				/* Ignore urls with both no schema and no tld */
				return NULL;
			}
		}

		decoded = url->string;
		decoded_len = url->urllen;

		if (comp) {
			comp->start = decoded;
			comp->len = decoded_len;
		}
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
rspamd_html_process_url_tag (rspamd_mempool_t *pool, struct html_tag *tag,
							 struct html_content *hc)
{
	struct html_tag_component *comp;
	GList *cur;
	struct rspamd_url *url;
	const gchar *start;
	gsize len;

	cur = tag->params->head;

	while (cur) {
		comp = cur->data;

		if (comp->type == RSPAMD_HTML_COMPONENT_HREF && comp->len > 0) {
			start = comp->start;
			len = comp->len;

			/* Check base url */
			if (hc && hc->base_url && comp->len > 2) {
				/*
				 * Relative url cannot start from the following:
				 * schema://
				 * data:
				 * slash
				 */
				gchar *buf;
				gsize orig_len;

				if (rspamd_substring_search (start, len, "://", 3) == -1) {

					if (len >= sizeof ("data:") &&
						g_ascii_strncasecmp (start, "data:", sizeof ("data:") - 1) == 0) {
						/* Image data url, never insert as url */
						return NULL;
					}

					/* Assume relative url */

					gboolean need_slash = FALSE;

					orig_len = len;
					len += hc->base_url->urllen;

					if (hc->base_url->datalen == 0) {
						need_slash = TRUE;
						len ++;
					}

					buf = rspamd_mempool_alloc (pool, len + 1);
					rspamd_snprintf (buf, len + 1, "%*s%s%*s",
							hc->base_url->urllen, hc->base_url->string,
							need_slash ? "/" : "",
							(gint)orig_len, start);
					start = buf;
				}
				else if (start[0] == '/' && start[1] != '/') {
					/* Relative to the hostname */
					orig_len = len;
					len += hc->base_url->hostlen + hc->base_url->protocollen +
							3 /* for :// */;
					buf = rspamd_mempool_alloc (pool, len + 1);
					rspamd_snprintf (buf, len + 1, "%*s://%*s/%*s",
							hc->base_url->protocollen, hc->base_url->string,
							hc->base_url->hostlen, rspamd_url_host_unsafe (hc->base_url),
							(gint)orig_len, start);
					start = buf;
				}
			}

			url = rspamd_html_process_url (pool, start, len, comp);

			if (url && tag->extra == NULL) {
				tag->extra = url;
			}

			return url;
		}

		cur = g_list_next (cur);
	}

	return NULL;
}

struct rspamd_html_url_query_cbd {
	rspamd_mempool_t *pool;
	khash_t (rspamd_url_hash) *url_set;
	struct rspamd_url *url;
	GPtrArray *part_urls;
};

static gboolean
rspamd_html_url_query_callback (struct rspamd_url *url, gsize start_offset,
						   gsize end_offset, gpointer ud)
{
	struct rspamd_html_url_query_cbd *cbd =
			(struct rspamd_html_url_query_cbd *)ud;
	rspamd_mempool_t *pool;

	pool = cbd->pool;

	if (url->protocol == PROTOCOL_MAILTO) {
		if (url->userlen == 0) {
			return FALSE;
		}
	}

	msg_debug_html ("found url %s in query of url"
					" %*s", url->string,
					cbd->url->querylen, rspamd_url_query_unsafe (cbd->url));

	url->flags |= RSPAMD_URL_FLAG_QUERY;

	if (rspamd_url_set_add_or_increase (cbd->url_set, url, false)
		&& cbd->part_urls) {
		g_ptr_array_add (cbd->part_urls, url);
	}

	return TRUE;
}

static void
rspamd_process_html_url (rspamd_mempool_t *pool, struct rspamd_url *url,
						 khash_t (rspamd_url_hash) *url_set,
						 GPtrArray *part_urls)
{
	if (url->flags & RSPAMD_URL_FLAG_UNNORMALISED) {
		url->flags |= RSPAMD_URL_FLAG_OBSCURED;
	}

	if (url->querylen > 0) {
		struct rspamd_html_url_query_cbd qcbd;

		qcbd.pool = pool;
		qcbd.url_set = url_set;
		qcbd.url = url;
		qcbd.part_urls = part_urls;

		rspamd_url_find_multiple(pool,
				rspamd_url_query_unsafe (url), url->querylen,
				RSPAMD_URL_FIND_ALL, NULL,
				rspamd_html_url_query_callback, &qcbd);
	}

	if (part_urls) {
		g_ptr_array_add (part_urls, url);
	}
}

static void
rspamd_html_process_data_image (rspamd_mempool_t *pool,
								struct html_image *img,
								struct html_tag_component *src)
{
	/*
	 * Here, we do very basic processing of the data:
	 * detect if we have something like: `data:image/xxx;base64,yyyzzz==`
	 * We only parse base64 encoded data.
	 * We ignore content type so far
	 */
	struct rspamd_image *parsed_image;
	const gchar *semicolon_pos = NULL, *end = src->start + src->len;

	semicolon_pos = src->start;

	while ((semicolon_pos = memchr (semicolon_pos, ';', end - semicolon_pos)) != NULL) {
		if (end - semicolon_pos > sizeof ("base64,")) {
			if (memcmp (semicolon_pos + 1, "base64,", sizeof ("base64,") - 1) == 0) {
				const gchar *data_pos = semicolon_pos + sizeof ("base64,");
				gchar *decoded;
				gsize encoded_len = end - data_pos, decoded_len;
				rspamd_ftok_t inp;

				decoded_len = (encoded_len / 4 * 3) + 12;
				decoded = rspamd_mempool_alloc (pool, decoded_len);
				rspamd_cryptobox_base64_decode (data_pos, encoded_len,
						decoded, &decoded_len);
				inp.begin = decoded;
				inp.len = decoded_len;

				parsed_image = rspamd_maybe_process_image (pool, &inp);

				if (parsed_image) {
					msg_debug_html ("detected %s image of size %ud x %ud in data url",
							rspamd_image_type_str (parsed_image->type),
							parsed_image->width, parsed_image->height);
					img->embedded_image = parsed_image;
				}
			}

			break;
		}
		else {
			/* Nothing useful */
			return;
		}

		semicolon_pos ++;
	}
}

static void
rspamd_html_process_img_tag (rspamd_mempool_t *pool, struct html_tag *tag,
							 struct html_content *hc, khash_t (rspamd_url_hash) *url_set,
							 GPtrArray *part_urls,
							 GByteArray *dest)
{
	struct html_tag_component *comp;
	struct html_image *img;
	rspamd_ftok_t fstr;
	const guchar *p;
	GList *cur;
	gulong val;
	gboolean seen_width = FALSE, seen_height = FALSE;
	goffset pos;

	cur = tag->params->head;
	img = rspamd_mempool_alloc0 (pool, sizeof (*img));
	img->tag = tag;
	tag->flags |= FL_IMAGE;

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
				if (comp->len > sizeof ("data:") - 1 && memcmp (comp->start,
						"data:", sizeof ("data:") - 1) == 0) {
					/* We have an embedded image in HTML tag */
					img->flags |=
							(RSPAMD_HTML_FLAG_IMAGE_EMBEDDED | RSPAMD_HTML_FLAG_IMAGE_DATA);
					rspamd_html_process_data_image (pool, img, comp);
					hc->flags |= RSPAMD_HTML_FLAG_HAS_DATA_URLS;
				}
				else {
					img->flags |= RSPAMD_HTML_FLAG_IMAGE_EXTERNAL;
					if (img->src) {

						img->url = rspamd_html_process_url (pool,
								img->src, fstr.len, NULL);

						if (img->url) {
							struct rspamd_url *existing;

							img->url->flags |= RSPAMD_URL_FLAG_IMAGE;
							existing = rspamd_url_set_add_or_return (url_set, img->url);

							if (existing != img->url) {
								/*
								 * We have some other URL that could be
								 * found, e.g. from another part. However,
								 * we still want to set an image flag on it
								 */
								existing->flags |= img->url->flags;
								existing->count ++;
							}
							else if (part_urls) {
								/* New url */
								g_ptr_array_add (part_urls, img->url);
							}
						}
					}
				}
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
				pos = rspamd_substring_search_caseless (comp->start, comp->len,
						"height", sizeof ("height") - 1);

				if (pos != -1) {
					p = comp->start + pos + sizeof ("height") - 1;

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
				pos = rspamd_substring_search_caseless (comp->start, comp->len,
						"width", sizeof ("width") - 1);

				if (pos != -1) {
					p = comp->start + pos + sizeof ("width") - 1;

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
		else if (comp->type == RSPAMD_HTML_COMPONENT_ALT && comp->len > 0 && dest != NULL) {
			if (dest->len > 0 && !g_ascii_isspace (dest->data[dest->len - 1])) {
				/* Add a space */
				g_byte_array_append (dest, " ", 1);
			}

			g_byte_array_append (dest, comp->start, comp->len);

			if (!g_ascii_isspace (dest->data[dest->len - 1])) {
				/* Add a space */
				g_byte_array_append (dest, " ", 1);
			}
		}

		cur = g_list_next (cur);
	}

	if (hc->images == NULL) {
		hc->images = g_ptr_array_sized_new (4);
		rspamd_mempool_notify_alloc (pool, 4 * sizeof (gpointer) + sizeof (GPtrArray));
		rspamd_mempool_add_destructor (pool, rspamd_ptr_array_free_hard,
				hc->images);
	}

	if (img->embedded_image) {
		if (!seen_height) {
			img->height = img->embedded_image->height;
		}
		if (!seen_width) {
			img->width = img->embedded_image->width;
		}
	}

	g_ptr_array_add (hc->images, img);
	tag->extra = img;
}

static void
rspamd_html_process_link_tag (rspamd_mempool_t *pool, struct html_tag *tag,
							 struct html_content *hc, khash_t (rspamd_url_hash) *url_set,
							 GPtrArray *part_urls)
{
	struct html_tag_component *comp;
	GList *cur;

	cur = tag->params->head;

	while (cur) {
		comp = cur->data;

		if (comp->type == RSPAMD_HTML_COMPONENT_REL && comp->len > 0) {
			if (comp->len == sizeof ("icon") - 1 &&
				rspamd_lc_cmp (comp->start, "icon", sizeof ("icon") - 1) == 0) {

				rspamd_html_process_img_tag (pool, tag, hc, url_set, part_urls, NULL);
			}
		}

		cur = g_list_next (cur);
	}
}

static void
rspamd_html_process_color (const gchar *line, guint len, struct html_color *cl)
{
	const gchar *p = line, *end = line + len;
	char hexbuf[7];
	rspamd_ftok_t search;
	struct html_color *el;

	memset (cl, 0, sizeof (*cl));

	if (*p == '#') {
		/* HEX color */
		p ++;
		rspamd_strlcpy (hexbuf, p, MIN ((gint)sizeof(hexbuf), end - p + 1));
		cl->d.val = strtoul (hexbuf, NULL, 16);
		cl->d.comp.alpha = 255;
		cl->valid = TRUE;
	}
	else if (len > 4 && rspamd_lc_cmp (p, "rgb", 3) == 0) {
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
			p ++;
		}

		c = p;

		while (p < end) {
			switch (state) {
			case obrace:
				if (*p == '(') {
					p ++;
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
					if (!rspamd_strtoul (c, p - c, &r)) {
						goto stop;
					}

					p ++;
					state = skip_spaces;
					next_state = num2;
				}
				else if (!g_ascii_isdigit (*p)) {
					goto stop;
				}
				else {
					p ++;
				}
				break;
			case num2:
				if (*p == ',') {
					if (!rspamd_strtoul (c, p - c, &g)) {
						goto stop;
					}

					p ++;
					state = skip_spaces;
					next_state = num3;
				}
				else if (!g_ascii_isdigit (*p)) {
					goto stop;
				}
				else {
					p ++;
				}
				break;
			case num3:
				if (*p == ',') {
					if (!rspamd_strtoul (c, p - c, &b)) {
						goto stop;
					}

					valid = TRUE;
					p ++;
					state = skip_spaces;
					next_state = num4;
				}
				else if (*p == ')') {
					if (!rspamd_strtoul (c, p - c, &b)) {
						goto stop;
					}

					valid = TRUE;
					goto stop;
				}
				else if (!g_ascii_isdigit (*p)) {
					goto stop;
				}
				else {
					p ++;
				}
				break;
			case num4:
				if (*p == ',') {
					if (!rspamd_strtoul (c, p - c, &opacity)) {
						goto stop;
					}

					valid = TRUE;
					goto stop;
				}
				else if (*p == ')') {
					if (!rspamd_strtoul (c, p - c, &opacity)) {
						goto stop;
					}

					valid = TRUE;
					goto stop;
				}
				else if (!g_ascii_isdigit (*p)) {
					goto stop;
				}
				else {
					p ++;
				}
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
		khiter_t k;
		/* Compare color by name */
		search.begin = line;
		search.len = len;

		k = kh_get (color_by_name, html_color_by_name, &search);

		if (k != kh_end (html_color_by_name)) {
			el = &kh_val (html_color_by_name, k);
			memcpy (cl, el, sizeof (*cl));
			cl->d.comp.alpha = 255; /* Non transparent */
		}
	}
}

/*
 * Target is used for in and out if this function returns TRUE
 */
static gboolean
rspamd_html_process_css_size (const gchar *suffix, gsize len,
		gdouble *tgt)
{
	gdouble sz = *tgt;
	gboolean ret = FALSE;

	if (len >= 2) {
		if (memcmp (suffix, "px", 2) == 0) {
			sz = (guint) sz; /* Round to number */
			ret = TRUE;
		}
		else if (memcmp (suffix, "em", 2) == 0) {
			/* EM is 16 px, so multiply and round */
			sz = (guint) (sz * 16.0);
			ret = TRUE;
		}
		else if (len >= 3 && memcmp (suffix, "rem", 3) == 0) {
			/* equal to EM in our case */
			sz = (guint) (sz * 16.0);
			ret = TRUE;
		}
		else if (memcmp (suffix, "ex", 2) == 0) {
			/*
			 * Represents the x-height of the element's font.
			 * On fonts with the "x" letter, this is generally the height
			 * of lowercase letters in the font; 1ex = 0.5em in many fonts.
			 */
			sz = (guint) (sz * 8.0);
			ret = TRUE;
		}
		else if (memcmp (suffix, "vw", 2) == 0) {
			/*
			 * Vewport width in percentages:
			 * we assume 1% of viewport width as 8px
			 */
			sz = (guint) (sz * 8.0);
			ret = TRUE;
		}
		else if (memcmp (suffix, "vh", 2) == 0) {
			/*
			 * Vewport height in percentages
			 * we assume 1% of viewport width as 6px
			 */
			sz = (guint) (sz * 6.0);
			ret = TRUE;
		}
		else if (len >= 4 && memcmp (suffix, "vmax", 4) == 0) {
			/*
			 * Vewport width in percentages
			 * we assume 1% of viewport width as 6px
			 */
			sz = (guint) (sz * 8.0);
			ret = TRUE;
		}
		else if (len >= 4 && memcmp (suffix, "vmin", 4) == 0) {
			/*
			 * Vewport height in percentages
			 * we assume 1% of viewport width as 6px
			 */
			sz = (guint) (sz * 6.0);
			ret = TRUE;
		}
		else if (memcmp (suffix, "pt", 2) == 0) {
			sz = (guint) (sz * 96.0 / 72.0); /* One point. 1pt = 1/72nd of 1in */
			ret = TRUE;
		}
		else if (memcmp (suffix, "cm", 2) == 0) {
			sz = (guint) (sz * 96.0 / 2.54); /* 96px/2.54 */
			ret = TRUE;
		}
		else if (memcmp (suffix, "mm", 2) == 0) {
			sz = (guint) (sz * 9.6 / 2.54); /* 9.6px/2.54 */
			ret = TRUE;
		}
		else if (memcmp (suffix, "in", 2) == 0) {
			sz = (guint) (sz * 96.0); /* 96px */
			ret = TRUE;
		}
		else if (memcmp (suffix, "pc", 2) == 0) {
			sz = (guint) (sz * 96.0 / 6.0); /* 1pc = 12pt = 1/6th of 1in. */
			ret = TRUE;
		}
	}
	else if (suffix[0] == '%') {
		/* Percentages from 16 px */
		sz = (guint)(sz / 100.0 * 16.0);
		ret = TRUE;
	}

	if (ret) {
		*tgt = sz;
	}

	return ret;
}

static void
rspamd_html_process_font_size (const gchar *line, guint len, guint *fs,
							   gboolean is_css)
{
	const gchar *p = line, *end = line + len;
	gchar *err = NULL, numbuf[64];
	gdouble sz = 0;
	gboolean failsafe = FALSE;

	while (p < end && g_ascii_isspace (*p)) {
		p ++;
		len --;
	}

	if (g_ascii_isdigit (*p)) {
		rspamd_strlcpy (numbuf, p, MIN (sizeof (numbuf), len + 1));
		sz = strtod (numbuf, &err);

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
			e ++;
		}

		/* Lowercase */
		slen = strlen (e);
		rspamd_str_lc ((gchar *)e, slen);

		if (!rspamd_html_process_css_size (e, slen, &sz)) {
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
			} else {
				sz = 16; /* Ignore */
			}
		} else {
			/* In non-css mode we have to check legacy size */
			sz = sz >= 1 ? sz * 16 : 16;
		}
	}

	if (sz > 32) {
		sz = 32;
	}

	*fs = sz;
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
	gdouble opacity = 1.0;

	p = style;
	c = p;
	end = p + len;

	while (p <= end) {
		switch(state) {
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

			p ++;
			break;

		case read_colon:
			if (p == end || *p == ':') {
				state = skip_spaces;
				next_state = read_value;
			}

			p ++;
			break;

		case read_value:
			if (p == end || *p == ';') {
				if (key && klen && p - c > 0) {
					if ((klen == 5 && g_ascii_strncasecmp (key, "color", 5) == 0)
					|| (klen == 10 && g_ascii_strncasecmp (key, "font-color", 10) == 0)) {

						rspamd_html_process_color (c, p - c, &bl->font_color);
						msg_debug_html ("got color: %xd", bl->font_color.d.val);
					}
					else if ((klen == 16 && g_ascii_strncasecmp (key,
							"background-color", 16) == 0) ||
							(klen == 10 && g_ascii_strncasecmp (key,
									"background", 10) == 0)) {

						rspamd_html_process_color (c, p - c, &bl->background_color);
						msg_debug_html ("got bgcolor: %xd", bl->background_color.d.val);
					}
					else if (klen == 7 && g_ascii_strncasecmp (key, "display", 7) == 0) {
						if (p - c >= 4 && rspamd_substring_search_caseless (c, p - c,
								"none", 4) != -1) {
							bl->visible = FALSE;
							msg_debug_html ("tag is not visible");
						}
					}
					else if (klen == 9 &&
							 g_ascii_strncasecmp (key, "font-size", 9) == 0) {
						rspamd_html_process_font_size (c, p - c,
								&bl->font_size, TRUE);
						msg_debug_html ("got font size: %ud", bl->font_size);
					}
					else if (klen == 7 &&
							 g_ascii_strncasecmp (key, "opacity", 7) == 0) {
						gchar numbuf[64];

						rspamd_strlcpy (numbuf, c,
								MIN (sizeof (numbuf), p - c + 1));
						opacity = strtod (numbuf, NULL);

						if (opacity > 1) {
							opacity = 1;
						}
						else if (opacity < 0) {
							opacity = 0;
						}

						bl->font_color.d.comp.alpha = (guint8)(opacity * 255.0);
					}
					else if (klen == 10 &&
							 g_ascii_strncasecmp (key, "visibility", 10) == 0) {
						if (p - c >= 6 && rspamd_substring_search_caseless (c,
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

			p ++;
			break;

		case skip_spaces:
			if (p < end && !g_ascii_isspace (*p)) {
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
	bl->visible = TRUE;
	bl->font_size = (guint)-1;
	bl->font_color.d.comp.alpha = 255;

	while (cur) {
		comp = cur->data;

		if (comp->len > 0) {
			switch (comp->type) {
			case RSPAMD_HTML_COMPONENT_COLOR:
				fstr.begin = (gchar *) comp->start;
				fstr.len = comp->len;
				rspamd_html_process_color (comp->start, comp->len,
						&bl->font_color);
				msg_debug_html ("tag %*s; got color: %xd",
						tag->name.len, tag->name.start, bl->font_color.d.val);
				break;
			case RSPAMD_HTML_COMPONENT_BGCOLOR:
				fstr.begin = (gchar *) comp->start;
				fstr.len = comp->len;
				rspamd_html_process_color (comp->start, comp->len,
						&bl->background_color);
				msg_debug_html ("tag %*s; got color: %xd",
						tag->name.len, tag->name.start, bl->font_color.d.val);

				if (tag->id == Tag_BODY) {
					/* Set global background color */
					memcpy (&hc->bgcolor, &bl->background_color,
							sizeof (hc->bgcolor));
				}
				break;
			case RSPAMD_HTML_COMPONENT_STYLE:
				bl->style.len = comp->len;
				bl->style.start = comp->start;
				msg_debug_html ("tag: %*s; got style: %*s",
						tag->name.len, tag->name.start,
						(gint) bl->style.len, bl->style.start);
				rspamd_html_process_style (pool, bl, hc, comp->start, comp->len);
				break;
			case RSPAMD_HTML_COMPONENT_CLASS:
				fstr.begin = (gchar *) comp->start;
				fstr.len = comp->len;
				bl->html_class = rspamd_mempool_ftokdup (pool, &fstr);
				msg_debug_html ("tag: %*s; got class: %s",
						tag->name.len, tag->name.start, bl->html_class);
				break;
			case RSPAMD_HTML_COMPONENT_SIZE:
				/* Not supported by html5 */
				/* FIXME maybe support it */
				bl->font_size = 16;
				msg_debug_html ("tag %*s; got size: %*s",
						tag->name.len, tag->name.start,
						(gint)comp->len, comp->start);
				break;
			default:
				/* NYI */
				break;
			}
		}

		cur = g_list_next (cur);
	}

	if (hc->blocks == NULL) {
		hc->blocks = g_ptr_array_sized_new (64);
		rspamd_mempool_notify_alloc (pool, 64 * sizeof (gpointer) + sizeof (GPtrArray));
		rspamd_mempool_add_destructor (pool, rspamd_ptr_array_free_hard,
				hc->blocks);
	}

	g_ptr_array_add (hc->blocks, bl);
	tag->extra = bl;
}

static void
rspamd_html_check_displayed_url (rspamd_mempool_t *pool,
								 GList **exceptions,
								 khash_t (rspamd_url_hash) *url_set,
								 GByteArray *dest,
								 gint href_offset,
								 struct rspamd_url *url)
{
	struct rspamd_url *displayed_url = NULL;
	struct rspamd_url *turl;
	gboolean url_found = FALSE;
	struct rspamd_process_exception *ex;
	enum rspamd_normalise_result norm_res;
	guint saved_flags = 0;
	gsize dlen;

	if (href_offset < 0) {
		/* No dispalyed url, just some text within <a> tag */
		return;
	}

	url->visible_part = rspamd_mempool_alloc (pool, dest->len - href_offset + 1);
	rspamd_strlcpy (url->visible_part, dest->data + href_offset,
			dest->len - href_offset + 1);
	dlen = dest->len - href_offset;
	url->visible_part =
			(gchar *)rspamd_string_len_strip (url->visible_part, &dlen, " \t\v\r\n");

	norm_res = rspamd_normalise_unicode_inplace (pool, url->visible_part, &dlen);

	if (norm_res & RSPAMD_UNICODE_NORM_UNNORMAL) {
		saved_flags |= RSPAMD_URL_FLAG_UNNORMALISED;
	}
	if (norm_res & RSPAMD_UNICODE_NORM_ZERO_SPACES) {
		saved_flags |= RSPAMD_URL_FLAG_ZW_SPACES;
	}

	rspamd_html_url_is_phished (pool, url,
			url->visible_part,
			dlen,
			&url_found, &displayed_url);

	if (url_found) {
		url->flags |= saved_flags|RSPAMD_URL_FLAG_DISPLAY_URL;
	}

	if (exceptions && url_found) {
		ex = rspamd_mempool_alloc (pool,
				sizeof (*ex));
		ex->pos = href_offset;
		ex->len = dest->len - href_offset;
		ex->type = RSPAMD_EXCEPTION_URL;
		ex->ptr = url;

		*exceptions = g_list_prepend (*exceptions,
				ex);
	}

	if (displayed_url && url_set) {
		turl = rspamd_url_set_add_or_return (url_set,
				displayed_url);

		if (turl != NULL) {
			/* Here, we assume the following:
			 * if we have a URL in the text part which
			 * is the same as displayed URL in the
			 * HTML part, we assume that it is also
			 * hint only.
			 */
			if (turl->flags &
				RSPAMD_URL_FLAG_FROM_TEXT) {
				turl->flags |= RSPAMD_URL_FLAG_HTML_DISPLAYED;
				turl->flags &= ~RSPAMD_URL_FLAG_FROM_TEXT;
			}

			turl->count ++;
		}
		else {
			/* Already inserted by `rspamd_url_set_add_or_return` */
		}
	}
}

static gboolean
rspamd_html_propagate_lengths (GNode *node, gpointer _unused)
{
	GNode *child;
	struct html_tag *tag = node->data, *cld_tag;

	if (tag) {
		child = node->children;

		/* Summarize content length from children */
		while (child) {
			cld_tag = child->data;
			tag->content_length += cld_tag->content_length;
			child = child->next;
		}
	}

	return FALSE;
}

static void
rspamd_html_propagate_style (struct html_content *hc,
							 struct html_tag *tag,
							 struct html_block *bl,
							 GQueue *blocks)
{
	struct html_block *bl_parent;
	gboolean push_block = FALSE;


	/* Propagate from the parent if needed */
	bl_parent = g_queue_peek_tail (blocks);

	if (bl_parent) {
		if (!bl->background_color.valid) {
			/* Try to propagate background color from parent nodes */
			if (bl_parent->background_color.valid) {
				memcpy (&bl->background_color, &bl_parent->background_color,
						sizeof (bl->background_color));
			}
		}
		else {
			push_block = TRUE;
		}

		if (!bl->font_color.valid) {
			/* Try to propagate background color from parent nodes */
			if (bl_parent->font_color.valid) {
				memcpy (&bl->font_color, &bl_parent->font_color,
						sizeof (bl->font_color));
			}
		}
		else {
			push_block = TRUE;
		}

		/* Propagate font size */
		if (bl->font_size == (guint)-1) {
			if (bl_parent->font_size != (guint)-1) {
				bl->font_size = bl_parent->font_size;
			}
		}
		else {
			push_block = TRUE;
		}
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
		memcpy (&bl->background_color, &hc->bgcolor, sizeof (hc->bgcolor));
	}
	else {
		push_block = TRUE;
	}

	if (bl->font_size == (guint)-1) {
		bl->font_size = 16; /* Default for browsers */
	}
	else {
		push_block = TRUE;
	}

	if (push_block && !(tag->flags & FL_CLOSED)) {
		g_queue_push_tail (blocks, bl);
	}
}

GByteArray*
rspamd_html_process_part_full (rspamd_mempool_t *pool,
							   struct html_content *hc,
							   GByteArray *in,
							   GList **exceptions,
							   khash_t (rspamd_url_hash) *url_set,
							   GPtrArray *part_urls,
							   bool allow_css)
{
	const guchar *p, *c, *end, *savep = NULL;
	guchar t;
	gboolean closing = FALSE, need_decode = FALSE, save_space = FALSE,
			balanced;
	GByteArray *dest;
	guint obrace = 0, ebrace = 0;
	GNode *cur_level = NULL;
	gint substate = 0, len, href_offset = -1;
	struct html_tag *cur_tag = NULL, *content_tag = NULL;
	struct rspamd_url *url = NULL;
	GQueue *styles_blocks;

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
	g_assert (hc != NULL);
	g_assert (pool != NULL);

	rspamd_html_library_init ();
	hc->tags_seen = rspamd_mempool_alloc0 (pool, NBYTES (N_TAGS));

	/* Set white background color by default */
	hc->bgcolor.d.comp.alpha = 0;
	hc->bgcolor.d.comp.r = 255;
	hc->bgcolor.d.comp.g = 255;
	hc->bgcolor.d.comp.b = 255;
	hc->bgcolor.valid = TRUE;

	dest = g_byte_array_sized_new (in->len / 3 * 2);
	styles_blocks = g_queue_new ();

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
				continue;
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
							goffset old_offset = dest->len;

							if (content_tag) {
								if (content_tag->content_length == 0) {
									content_tag->content_offset = old_offset;
								}
							}

							g_byte_array_append (dest, c, (p - c));

							len = rspamd_html_decode_entitles_inplace (
									dest->data + old_offset,
									p - c);
							dest->len = dest->len + len - (p - c);

							if (content_tag) {
								content_tag->content_length += len;
							}
						}
						else {
							len = p - c;

							if (content_tag) {
								if (content_tag->content_length == 0) {
									content_tag->content_offset = dest->len;
								}

								content_tag->content_length += len;
							}

							g_byte_array_append (dest, c, len);
						}
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
							if (content_tag) {
								if (content_tag->content_length == 0) {
									/*
									 * Special case
									 * we have a space at the beginning but
									 * we have no set content_offset
									 * so we need to do it here
									 */
									content_tag->content_offset = dest->len;
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
						goffset old_offset = dest->len;

						if (content_tag) {
							if (content_tag->content_length == 0) {
								content_tag->content_offset = dest->len;
							}
						}

						g_byte_array_append (dest, c, (p - c));
						len = rspamd_html_decode_entitles_inplace (
								dest->data + old_offset,
								p - c);
						dest->len = dest->len + len - (p - c);

						if (content_tag) {
							content_tag->content_length += len;
						}
					}
					else {
						len = p - c;

						if (content_tag) {
							if (content_tag->content_length == 0) {
								content_tag->content_offset = dest->len;
							}

							content_tag->content_length += len;
						}

						g_byte_array_append (dest, c, len);
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
					hc->css_style = rspamd_css_parse_style (pool, p, end_style, hc->css_style,
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
					if (cur_tag->id == Tag_STYLE) {
						state = content_style;
					}
					else {
						state = content_ignore;
					}
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

				if (!(cur_tag->flags & (FL_CLOSED|FL_CLOSING))) {
					content_tag = cur_tag;
				}

				/* Handle newlines */
				if (cur_tag->id == Tag_BR || cur_tag->id == Tag_HR) {
					if (dest->len > 0 && dest->data[dest->len - 1] != '\n') {
						g_byte_array_append (dest, "\r\n", 2);

						if (content_tag) {
							if (content_tag->content_length == 0) {
								/*
								 * Special case
								 * we have a \r\n at the beginning but
								 * we have no set content_offset
								 * so we need to do it here
								 */
								content_tag->content_offset = dest->len;
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
					if (dest->len > 0 && dest->data[dest->len - 1] != '\n') {
						g_byte_array_append (dest, "\r\n", 2);

						if (content_tag) {
							if (content_tag->content_length == 0) {
								/*
								 * Special case
								 * we have a \r\n at the beginning but
								 * we have no set content_offset
								 * so we need to get it here
								 */
								content_tag->content_offset = dest->len;
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
						url = rspamd_html_process_url_tag (pool, cur_tag, hc);

						if (url != NULL) {

							if (url_set != NULL) {
								struct rspamd_url *maybe_existing =
										rspamd_url_set_add_or_return (url_set, url);
								if (maybe_existing == url) {
									rspamd_process_html_url (pool, url, url_set,
											part_urls);
								}
								else {
									url = maybe_existing;
									/* Increase count to avoid odd checks failure */
									url->count ++;
								}
							}

							href_offset = dest->len;
						}
					}

					if (cur_tag->id == Tag_A) {
						if (!balanced && cur_level && cur_level->prev) {
							struct html_tag *prev_tag;
							struct rspamd_url *prev_url;

							prev_tag = cur_level->prev->data;

							if (prev_tag->id == Tag_A &&
									!(prev_tag->flags & (FL_CLOSING)) &&
									prev_tag->extra) {
								prev_url = prev_tag->extra;

								rspamd_html_check_displayed_url (pool,
										exceptions, url_set,
										dest, href_offset,
										prev_url);
							}
						}

						if (cur_tag->flags & (FL_CLOSING)) {

							/* Insert exception */
							if (url != NULL && (gint) dest->len > href_offset) {
								rspamd_html_check_displayed_url (pool,
										exceptions, url_set,
										dest, href_offset,
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
						url = rspamd_html_process_url_tag (pool, cur_tag, hc);

						if (url != NULL) {
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
					rspamd_html_process_img_tag (pool, cur_tag, hc, url_set,
							part_urls, dest);
				}
				else if (cur_tag->id == Tag_LINK && !(cur_tag->flags & FL_CLOSING)) {
					rspamd_html_process_link_tag (pool, cur_tag, hc, url_set,
							part_urls);
				}
				else if (cur_tag->flags & FL_BLOCK) {
					struct html_block *bl;

					if (cur_tag->flags & FL_CLOSING) {
						/* Just remove block element from the queue if any */
						if (styles_blocks->length > 0) {
							g_queue_pop_tail (styles_blocks);
						}
					}
					else {
						rspamd_html_process_block_tag (pool, cur_tag, hc);
						bl = cur_tag->extra;

						if (bl) {
							rspamd_html_propagate_style (hc, cur_tag,
									cur_tag->extra, styles_blocks);

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
				rspamd_html_propagate_lengths, NULL);
	}

	g_queue_free (styles_blocks);
	hc->parsed = dest;

	return dest;
}

GByteArray*
rspamd_html_process_part (rspamd_mempool_t *pool,
		struct html_content *hc,
		GByteArray *in)
{
	return rspamd_html_process_part_full (pool, hc, in, NULL,
			NULL, NULL, FALSE);
}
