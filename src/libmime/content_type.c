/*
 * Copyright 2024 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "libmime/content_type.h"
#include "smtp_parsers.h"
#include "utlist.h"
#include "libmime/mime_encoding.h"
#include "rspamd_simdutf.h"

/*
 * Upper bound on the number of parameters we materialise for a single
 * Content-Type or Content-Disposition header. Real messages use a handful;
 * this cap exists purely to stop a crafted header (e.g. `text/plain; a=;a=;...`)
 * from amplifying a bounded input into millions of per-parameter allocations.
 */
static const unsigned int max_content_type_params = 1024;
/*
 * RFC 2231 pieces of a value that readers join (Thunderbird stops at 999,
 * the highest number of a piece)
 */
#define max_rfc2231_pieces 1000u

/* The data of an RFC 2231 value, after charset'language' (or charset') */
static const char *
rspamd_rfc2231_value_data(const char *start, const char *end)
{
	const char *quote = memchr(start, '\'', end - start);

	if (quote != NULL) {
		const char *second = memchr(quote + 1, '\'', end - quote - 1);

		return second != NULL ? second + 1 : quote + 1;
	}

	return start;
}

/* The charset label and the data of an RFC 2231 value: charset'language'data, charset'data or data */
static void
rspamd_rfc2231_split(const char *start, const char *end, rspamd_ftok_t *label, rspamd_ftok_t *data)
{
	label->begin = start;
	label->len = 0;
	data->begin = rspamd_rfc2231_value_data(start, end);
	data->len = end - data->begin;

	if (data->begin != start) {
		label->len = (const char *) memchr(start, '\'', end - start) - start;
	}
}

/*
 * Percent decoding of RFC 2231 data in place, as readers do it (Thunderbird):
 * '%' and two hex digits is a byte, anything else stays, '+' too
 */
static gsize
rspamd_rfc2231_percent_decode(char *buf, gsize len)
{
	const char *p = buf, *end = buf + len;
	char *d = buf;

	while (p < end) {
		if (*p == '%' && end - p >= 3 && g_ascii_isxdigit(p[1]) && g_ascii_isxdigit(p[2])) {
			*d++ = (char) ((g_ascii_xdigit_value(p[1]) << 4) | g_ascii_xdigit_value(p[2]));
			p += 3;
		}
		else {
			*d++ = *p++;
		}
	}

	return d - buf;
}

/* Percent decoded into a copy */
static rspamd_ftok_t
rspamd_rfc2231_unescape(rspamd_mempool_t *pool, const char *start, gsize len)
{
	rspamd_ftok_t res;
	char *buf = rspamd_mempool_alloc(pool, len + 1);

	memcpy(buf, start, len);
	res.begin = buf;
	res.len = rspamd_rfc2231_percent_decode(buf, len);

	return res;
}

/* ISO-2022-*, HZ and UTF-7 write their characters in ASCII */
static gboolean
rspamd_rfc2231_seven_bit_charset(const rspamd_ftok_t *label)
{
	return (label->len >= 8 && g_ascii_strncasecmp(label->begin, "ISO-2022", 8) == 0) ||
		   (label->len >= 5 && g_ascii_strncasecmp(label->begin, "HZ-GB", 5) == 0) ||
		   (label->len >= 5 && g_ascii_strncasecmp(label->begin, "UTF-7", 5) == 0);
}

/*
 * The bytes of an RFC 2231 value as readers take them (Thunderbird): ASCII or
 * UTF-8, or with no charset, as they are, unless the charset writes its
 * characters in ASCII; others in the charset of the label, which must be
 * known and convert them, else they are no value (FALSE). x-user-defined,
 * which only WHATWG knows, is served by an internal table
 */
static gboolean
rspamd_rfc2231_convert(rspamd_mempool_t *pool, const rspamd_ftok_t *bytes,
					   const rspamd_ftok_t *label, rspamd_ftok_t *out)
{
	const char *charset;
	char *converted;
	gsize converted_len = 0;
	GError *err = NULL;
	gboolean utf8 = rspamd_fast_utf8_validate((const unsigned char *) bytes->begin, bytes->len) == 0;

	if (label->len == 0 || (utf8 && !rspamd_rfc2231_seven_bit_charset(label))) {
		*out = *bytes;

		return TRUE;
	}

	if (label->len == sizeof("x-user-defined") - 1 &&
		g_ascii_strncasecmp(label->begin, "x-user-defined", label->len) == 0) {
		charset = "x-user-defined";
	}
	else {
		charset = rspamd_mime_detect_charset(label, pool);
	}

	/* Not UTF-8 under UTF-8 is not valid there */
	if (charset == NULL || g_ascii_strcasecmp(charset, "UTF-8") == 0) {
		if (utf8) {
			*out = *bytes;
		}

		return utf8;
	}

	converted = rspamd_mime_text_to_utf8(pool, (char *) bytes->begin, bytes->len,
										 charset, &converted_len, &err);

	if (converted == NULL) {
		msg_debug_pool("cannot convert parameter from charset %s: %e", charset, err);

		if (err) {
			g_error_free(err);
		}
	}
	else if (rspamd_substring_search(converted, converted_len, "\xEF\xBF\xBD", 3) != -1) {
		/* Bytes that are no characters there, which the conversion replaced */
		converted = NULL;
	}

	if (converted == NULL) {
		if (utf8) {
			/* A 7-bit charset that was wrong: as they are */
			*out = *bytes;

			return TRUE;
		}

		return FALSE;
	}

	out->begin = converted;
	out->len = converted_len;

	return TRUE;
}

/* The same, for a value no reader takes: converted as it can be, to keep what it holds */
static rspamd_ftok_t
rspamd_rfc2231_convert_any(rspamd_mempool_t *pool, const rspamd_ftok_t *bytes,
						   const rspamd_ftok_t *label)
{
	rspamd_ftok_t out;
	const char *charset;

	if (rspamd_rfc2231_convert(pool, bytes, label, &out)) {
		return out;
	}

	charset = rspamd_mime_charset_find_by_content(bytes->begin, bytes->len, TRUE);

	if (charset != NULL) {
		gsize converted_len = 0;
		char *converted = rspamd_mime_text_to_utf8(pool, (char *) bytes->begin, bytes->len,
												   charset, &converted_len, NULL);

		if (converted != NULL) {
			out.begin = converted;
			out.len = converted_len;

			return out;
		}
	}

	return *bytes;
}

/* Whether each '%' is followed by two hex digits, which readers require of the data of name*= */
static gboolean
rspamd_rfc2231_escapes_valid(const char *p, const char *end)
{
	const char *pct;

	while ((pct = memchr(p, '%', end - p)) != NULL) {
		if (end - pct < 3 || !g_ascii_isxdigit(pct[1]) || !g_ascii_isxdigit(pct[2])) {
			return FALSE;
		}

		p = pct + 3;
	}

	return TRUE;
}

/*
 * The number of an RFC 2231 piece in [p, end), as readers take it: digits,
 * without a leading zero, below max_rfc2231_pieces. Others make no piece
 * (Thunderbird), so 00 or 4294967296 are not piece 0
 */
static gboolean
rspamd_rfc2231_piece_number(const char *p, const char *end, unsigned int *num)
{
	unsigned int n = 0;

	if (p >= end || (end - p > 1 && *p == '0')) {
		return FALSE;
	}

	for (; p < end; p++) {
		if (!g_ascii_isdigit(*p)) {
			return FALSE;
		}

		n = n * 10 + (*p - '0');

		if (n >= max_rfc2231_pieces) {
			return FALSE;
		}
	}

	*num = n;

	return TRUE;
}

static gboolean
rspamd_param_maybe_rfc2231_process(rspamd_mempool_t *pool,
								   struct rspamd_content_type_param *param,
								   char *name_start, char *name_end,
								   char *value_start, char *value_end)
{
	const char *star_pos;

	star_pos = memchr(name_start, '*', name_end - name_start);

	if (star_pos == NULL) {
		return FALSE;
	}

	/* We have three possibilities here:
	 * 1. name* (just name + 2231 encoding)
	 * 2. name*(\d+) (piecewise stuff but no rfc2231 encoding)
	 * 3. name*(\d+)* (piecewise stuff and rfc2231 encoding)
	 */

	if (star_pos == name_end - 1) {
		/* First: decoded with the other values of the name, see rspamd_content_param_resolve */
		param->flags |= RSPAMD_CONTENT_PARAM_RFC2231;
		param->name.begin = name_start;
		param->name.len = name_end - name_start - 1;
		param->value.begin = value_start;
		param->value.len = value_end - value_start;

		if (!rspamd_rfc2231_escapes_valid(rspamd_rfc2231_value_data(value_start, value_end),
										  value_end)) {
			param->flags |= RSPAMD_CONTENT_PARAM_BAD_ESCAPE;
		}
	}
	else if (*(name_end - 1) == '*') {
		/* Third */
		/* Check number */
		unsigned int tmp;

		if (!rspamd_rfc2231_piece_number(star_pos + 1, name_end - 1, &tmp)) {
			return FALSE;
		}

		param->flags |= RSPAMD_CONTENT_PARAM_PIECEWISE | RSPAMD_CONTENT_PARAM_RFC2231;
		param->rfc2231_id = tmp;
		param->name.begin = name_start;
		param->name.len = star_pos - name_start;
		param->value.begin = value_start;
		param->value.len = value_end - value_start;

		/* Deal with that later... */
	}
	else {
		/* Second case */
		unsigned int tmp;

		if (!rspamd_rfc2231_piece_number(star_pos + 1, name_end, &tmp)) {
			return FALSE;
		}

		param->flags |= RSPAMD_CONTENT_PARAM_PIECEWISE;
		param->rfc2231_id = tmp;
		param->name.begin = name_start;
		param->name.len = star_pos - name_start;
		param->value.begin = value_start;
		param->value.len = value_end - value_start;
	}

	return TRUE;
}

static int32_t
rspamd_cmp_pieces(struct rspamd_content_type_param *p1, struct rspamd_content_type_param *p2)
{
	/*
	 * Explicit comparison: subtracting two unsigned ids and truncating to
	 * int32_t overflows when they differ by more than INT32_MAX, which yields
	 * an inconsistent ordering for the sort below.
	 */
	if (p1->rfc2231_id < p2->rfc2231_id) {
		return -1;
	}
	else if (p1->rfc2231_id > p2->rfc2231_id) {
		return 1;
	}

	return 0;
}

/*
 * The RFC 2231 values of a name read in the order of the header, as
 * Thunderbird reads them: what is taken so far
 */
struct rspamd_rfc2231_walk {
	rspamd_ftok_t label_b;  /* The charset of name*=: that of the last one */
	rspamd_ftok_t label_cd; /* The charset of the pieces: that of the last name*0*= */
	gboolean have_ext;      /* A value of name*= is taken */
	gboolean accept;        /* Pieces are still taken */
};

enum rspamd_rfc2231_step {
	/* No value, which may still name a charset or end the pieces */
	RSPAMD_RFC2231_STEP_NONE = 0,
	/* The value of name*= */
	RSPAMD_RFC2231_STEP_EXT,
	/* A piece: its number, or 0 for a later name*= */
	RSPAMD_RFC2231_STEP_PIECE,
};

/*
 * Reads one RFC 2231 value of a name, `cur`, after the ones before it:
 * - each name*= names the charset of name*=; the first one with data and
 *   good escapes is the value of name*=, a later one with data is piece 0,
 *   unless piece 0 is taken or it is quoted, which ends the pieces;
 * - pieces are taken up to a repeated one or a quoted one with percent
 *   encoding; name*0*= names the charset of the pieces, even repeated.
 * `have_piece` is whether its piece (0 for name*=) is taken already. `data`
 * is the data of name*= and of name*0*=
 */
static enum rspamd_rfc2231_step
rspamd_rfc2231_walk_step(struct rspamd_rfc2231_walk *walk, const struct rspamd_content_type_param *cur,
						 gboolean have_piece, rspamd_ftok_t *data)
{
	const char *end = cur->value.begin + cur->value.len;

	if (!(cur->flags & RSPAMD_CONTENT_PARAM_PIECEWISE)) {
		/* name*= */
		rspamd_rfc2231_split(cur->value.begin, end, &walk->label_b, data);

		if (data->len == 0) {
			return RSPAMD_RFC2231_STEP_NONE;
		}

		if (!walk->have_ext) {
			if (cur->flags & RSPAMD_CONTENT_PARAM_BAD_ESCAPE) {
				return RSPAMD_RFC2231_STEP_NONE;
			}

			walk->have_ext = TRUE;

			return RSPAMD_RFC2231_STEP_EXT;
		}

		if (have_piece || (cur->flags & RSPAMD_CONTENT_PARAM_QUOTED)) {
			walk->accept = FALSE;

			return RSPAMD_RFC2231_STEP_NONE;
		}

		return RSPAMD_RFC2231_STEP_PIECE;
	}

	if (!walk->accept) {
		return RSPAMD_RFC2231_STEP_NONE;
	}

	if (cur->rfc2231_id == 0 && (cur->flags & RSPAMD_CONTENT_PARAM_RFC2231)) {
		/* name*0*=charset'language'data: names the charset, even if it is no piece */
		rspamd_rfc2231_split(cur->value.begin, end, &walk->label_cd, data);

		if (data->len == 0) {
			return RSPAMD_RFC2231_STEP_NONE;
		}
	}

	if (cur->rfc2231_id >= max_rfc2231_pieces || have_piece ||
		((cur->flags & RSPAMD_CONTENT_PARAM_RFC2231) && (cur->flags & RSPAMD_CONTENT_PARAM_QUOTED))) {
		walk->accept = FALSE;

		return RSPAMD_RFC2231_STEP_NONE;
	}

	return RSPAMD_RFC2231_STEP_PIECE;
}

/* The piece number of an RFC 2231 value for rspamd_rfc2231_walk_step: name*= is piece 0 */
static inline unsigned int
rspamd_rfc2231_walk_piece(const struct rspamd_content_type_param *cur)
{
	return (cur->flags & RSPAMD_CONTENT_PARAM_PIECEWISE) ? cur->rfc2231_id : 0;
}

/*
 * Names rspamd relies on, which are still taken past the parameters cap (see
 * rspamd_content_param_take_past_cap)
 */
static const char *const rspamd_past_cap_names[] = {"boundary", "charset", "name", "filename"};

/*
 * Of each of these names: all its values read so far, of which only those
 * readers take are kept past the cap
 */
struct rspamd_content_params_past_cap {
	struct rspamd_past_cap_name {
		struct rspamd_rfc2231_walk walk;
		uint8_t pieces[(max_rfc2231_pieces + 7) / 8]; /* Those taken */
		/* Copies of the charsets named past the cap: the header is not kept */
		char *label_b, *label_cd;
		gsize label_b_size, label_cd_size;
		gboolean started, have_plain;
		gboolean have_head; /* Its first value is kept */
	} names[G_N_ELEMENTS(rspamd_past_cap_names)];
};

static int
rspamd_past_cap_name_index(const char *name, gsize len)
{
	unsigned int i;

	for (i = 0; i < G_N_ELEMENTS(rspamd_past_cap_names); i++) {
		if (len == strlen(rspamd_past_cap_names[i]) &&
			g_ascii_strncasecmp(name, rspamd_past_cap_names[i], len) == 0) {
			return i;
		}
	}

	return -1;
}

/*
 * The whole read of the values of a name, when some are past the cap: the
 * values kept give the same pieces and the same value of name*=, but not the
 * charsets that values not kept named
 */
static const struct rspamd_rfc2231_walk *
rspamd_past_cap_walk(const struct rspamd_content_params_past_cap *past_cap, const rspamd_ftok_t *name)
{
	int i;

	if (past_cap == NULL || (i = rspamd_past_cap_name_index(name->begin, name->len)) < 0 ||
		!past_cap->names[i].started) {
		return NULL;
	}

	return &past_cap->names[i].walk;
}

/*
 * Joins the pieces in their order, each name*N*= percent decoded on its own;
 * `first` is the data of piece 0 when it is not the value of pieces[0]
 */
static rspamd_ftok_t
rspamd_content_param_join(rspamd_mempool_t *pool, struct rspamd_content_type_param **pieces,
						  unsigned int npieces, const rspamd_ftok_t *first, gboolean first_ext)
{
	rspamd_ftok_t res;
	gsize tlen = 0;
	char *ndata, *pos;
	unsigned int n;

	for (n = 0; n < npieces; n++) {
		tlen += (n == 0 && first) ? first->len : pieces[n]->value.len;
	}

	ndata = rspamd_mempool_alloc(pool, tlen + 1);
	pos = ndata;

	for (n = 0; n < npieces; n++) {
		const char *src = pieces[n]->value.begin;
		gsize len = pieces[n]->value.len;
		gboolean ext = (pieces[n]->flags & RSPAMD_CONTENT_PARAM_RFC2231) != 0;

		if (n == 0 && first) {
			src = first->begin;
			len = first->len;
			ext = first_ext;
		}

		memcpy(pos, src, len);
		pos += ext ? rspamd_rfc2231_percent_decode(pos, len) : len;
	}

	res.begin = ndata;
	res.len = pos - ndata;

	return res;
}

/*
 * The value of a name whose first value is name*= (RFC 2231) or a piece
 * (name*0, name*1*...), as Thunderbird takes it: name*= if it is valid, else
 * the pieces joined from 0 up to a missing one, else the first plain value. A plain value is never a
 * piece (name*1=x; name="a.exe" is a.exe, not a.exex). The values are read
 * in the order of the header (rspamd_rfc2231_walk_step), and bytes are valid
 * when they are ASCII or UTF-8, or convert from the charset named
 * (rspamd_rfc2231_convert); joined into nothing, the pieces are no value.
 * `whole` is the read of all values when some are past the cap.
 * With no value readers take, what the values hold is kept, flagged BROKEN
 * and NO_VALUE.
 */
static struct rspamd_content_type_param *
rspamd_content_param_resolve(rspamd_mempool_t *pool, struct rspamd_content_type_param *head,
							 const struct rspamd_rfc2231_walk *whole)
{
	struct rspamd_content_type_param *by_num[max_rfc2231_pieces];
	struct rspamd_content_type_param *plain = NULL, *ext = NULL, *cur, *sorted, **all;
	struct rspamd_rfc2231_walk walk = {.accept = TRUE};
	rspamd_ftok_t ext_data = {0, NULL}, label_b, label_cd, first = {0, NULL}, data, bytes, out;
	gboolean have_first = FALSE;
	unsigned int n, nall = 0;

	memset(by_num, 0, sizeof(by_num));

	DL_FOREACH(head, cur)
	{
		if (!(cur->flags & (RSPAMD_CONTENT_PARAM_RFC2231 | RSPAMD_CONTENT_PARAM_PIECEWISE))) {
			if (plain == NULL) {
				plain = cur;
			}

			continue;
		}

		if (cur->flags & RSPAMD_CONTENT_PARAM_PIECEWISE) {
			nall++;
		}

		n = rspamd_rfc2231_walk_piece(cur);

		switch (rspamd_rfc2231_walk_step(&walk, cur, n < max_rfc2231_pieces && by_num[n] != NULL, &data)) {
		case RSPAMD_RFC2231_STEP_EXT:
			ext = cur;
			ext_data = data;
			break;
		case RSPAMD_RFC2231_STEP_PIECE:
			by_num[n] = cur;

			if (n == 0 && (cur->flags & RSPAMD_CONTENT_PARAM_RFC2231)) {
				first = data;
				have_first = TRUE;
			}
			break;
		default:
			break;
		}
	}

	/* Values not kept past the cap still named charsets */
	if (whole != NULL) {
		walk.label_b = whole->label_b;
		walk.label_cd = whole->label_cd;
	}

	label_b = walk.label_b;
	label_cd = walk.label_cd;

	if (ext != NULL) {
		bytes = rspamd_rfc2231_unescape(pool, ext_data.begin, ext_data.len);

		if (rspamd_rfc2231_convert(pool, &bytes, &label_b, &out)) {
			ext->value = out;

			return ext;
		}
	}

	if (by_num[0] != NULL) {
		for (n = 0; n < max_rfc2231_pieces && by_num[n] != NULL; n++) {}

		bytes = rspamd_content_param_join(pool, by_num, n, have_first ? &first : NULL, TRUE);

		if (bytes.len > 0 && rspamd_rfc2231_convert(pool, &bytes, &label_cd, &out)) {
			by_num[0]->value = out;

			return by_num[0];
		}
	}

	if (plain != NULL) {
		return plain;
	}

	/* No value readers take: what the values hold */
	if (ext != NULL) {
		bytes = rspamd_rfc2231_unescape(pool, ext_data.begin, ext_data.len);
		ext->value = rspamd_rfc2231_convert_any(pool, &bytes, &label_b);
		ext->flags |= RSPAMD_CONTENT_PARAM_BROKEN | RSPAMD_CONTENT_PARAM_NO_VALUE;

		return ext;
	}

	if (nall == 0) {
		head->flags |= RSPAMD_CONTENT_PARAM_BROKEN | RSPAMD_CONTENT_PARAM_NO_VALUE;

		return head;
	}

	/* All the pieces in the order of their numbers */
	all = rspamd_mempool_alloc(pool, nall * sizeof(*all));
	sorted = head;
	DL_SORT(sorted, rspamd_cmp_pieces);
	n = 0;
	label_cd.len = 0;

	DL_FOREACH(sorted, cur)
	{
		if ((cur->flags & RSPAMD_CONTENT_PARAM_PIECEWISE) && n < nall) {
			all[n++] = cur;
		}
	}

	if (all[0]->flags & RSPAMD_CONTENT_PARAM_RFC2231) {
		rspamd_rfc2231_split(all[0]->value.begin, all[0]->value.begin + all[0]->value.len,
							 &label_cd, &first);
		bytes = rspamd_content_param_join(pool, all, n, &first, TRUE);
	}
	else {
		bytes = rspamd_content_param_join(pool, all, n, NULL, FALSE);
	}

	all[0]->value = rspamd_rfc2231_convert_any(pool, &bytes, &label_cd);
	all[0]->flags |= RSPAMD_CONTENT_PARAM_BROKEN | RSPAMD_CONTENT_PARAM_NO_VALUE;

	return all[0];
}

static void
rspamd_postprocess_ct_attributes(rspamd_mempool_t *pool,
								 GHashTable *htb,
								 const struct rspamd_content_params_past_cap *past_cap,
								 void (*proc)(rspamd_mempool_t *, struct rspamd_content_type_param *, gpointer ud),
								 gpointer procd)
{
	GHashTableIter it;
	gpointer k, v;
	struct rspamd_content_type_param *param;

	if (htb == NULL) {
		return;
	}

	g_hash_table_iter_init(&it, htb);

	while (g_hash_table_iter_next(&it, &k, &v)) {
		param = (struct rspamd_content_type_param *) v;

		/*
		 * A name whose first value is an RFC 2231 one. When the first one is
		 * plain, it is the value, as on Python and as before: Thunderbird
		 * would take name*= or pieces after it, but its parser and rspamd's do
		 * not read the same parameters (comments, quoted names, quotes past
		 * the value), so these could change a name every reader shows
		 */
		if (param->flags & (RSPAMD_CONTENT_PARAM_PIECEWISE | RSPAMD_CONTENT_PARAM_RFC2231)) {
			struct rspamd_content_type_param *chosen = rspamd_content_param_resolve(pool, param,
																					rspamd_past_cap_walk(past_cap, &param->name));

			if (chosen != param) {
				param = chosen;
				g_hash_table_iter_replace(&it, param);
			}

			/* Detach from list */
			param->next = NULL;
			param->prev = param;
		}

		gboolean invalid_utf = FALSE;

		if (param->value.begin != NULL && param->value.len > 0) {
			param->value.begin = rspamd_mime_header_decode(pool, param->value.begin,
														   param->value.len, &invalid_utf);
			param->value.len = strlen(param->value.begin);
		}

		if (invalid_utf) {
			param->flags |= RSPAMD_CONTENT_PARAM_BROKEN;
		}

		proc(pool, param, procd);
	}
}

static void
rspamd_content_type_postprocess(rspamd_mempool_t *pool,
								struct rspamd_content_type_param *param,
								gpointer ud)
{
	rspamd_ftok_t srch;
	struct rspamd_content_type_param *found = NULL;

	struct rspamd_content_type *ct = (struct rspamd_content_type *) ud;

	RSPAMD_FTOK_ASSIGN(&srch, "charset");

	if (rspamd_ftok_icase_equal(&param->name, &srch)) {
		/* Adjust charset */
		found = param;
		ct->charset.begin = param->value.begin;
		ct->charset.len = param->value.len;
	}

	RSPAMD_FTOK_ASSIGN(&srch, "boundary");

	if (rspamd_ftok_icase_equal(&param->name, &srch)) {
		found = param;
		char *lc_boundary;
		/* Adjust boundary */
		lc_boundary = rspamd_mempool_alloc(pool, param->value.len);
		memcpy(lc_boundary, param->value.begin, param->value.len);
		rspamd_str_lc(lc_boundary, param->value.len);
		ct->boundary.begin = lc_boundary;
		ct->boundary.len = param->value.len;
		/* Preserve original (case sensitive) boundary */
		ct->orig_boundary.begin = param->value.begin;
		ct->orig_boundary.len = param->value.len;
	}

	if (!found) {
		RSPAMD_FTOK_ASSIGN(&srch, "name");
		if (!rspamd_ftok_icase_equal(&param->name, &srch)) {
			/* Just lowercase */
			rspamd_str_lc_utf8((char *) param->value.begin, param->value.len);
		}
	}
}

static void
rspamd_content_disposition_postprocess(rspamd_mempool_t *pool,
									   struct rspamd_content_type_param *param,
									   gpointer ud)
{
	rspamd_ftok_t srch;
	struct rspamd_content_disposition *cd = (struct rspamd_content_disposition *) ud;

	srch.begin = "filename";
	srch.len = 8;

	if (rspamd_ftok_icase_equal(&param->name, &srch)) {
		/* Adjust filename */
		cd->filename.begin = param->value.begin;
		cd->filename.len = param->value.len;
	}
}

/* Keeps a charset named past the cap in `*buf`, which grows as needed */
static void
rspamd_past_cap_keep_label(rspamd_mempool_t *pool, rspamd_ftok_t *label, char **buf, gsize *size)
{
	if (label->len > *size) {
		*size = MAX(label->len, *size * 2);
		*buf = rspamd_mempool_alloc(pool, *size);
	}

	if (label->len > 0) {
		memcpy(*buf, label->begin, label->len);
	}

	label->begin = *buf;
}

static inline gboolean
rspamd_past_cap_has_piece(const struct rspamd_past_cap_name *st, unsigned int n)
{
	return n < max_rfc2231_pieces && (st->pieces[n / 8] & (1u << (n % 8)));
}

/* Reads a value of the name, and keeps the piece it is */
static enum rspamd_rfc2231_step
rspamd_past_cap_read(struct rspamd_past_cap_name *st, const struct rspamd_content_type_param *param)
{
	unsigned int n = rspamd_rfc2231_walk_piece(param);
	rspamd_ftok_t data;
	enum rspamd_rfc2231_step step;

	step = rspamd_rfc2231_walk_step(&st->walk, param, rspamd_past_cap_has_piece(st, n), &data);

	if (step == RSPAMD_RFC2231_STEP_PIECE && n < max_rfc2231_pieces) {
		st->pieces[n / 8] |= 1u << (n % 8);
	}

	return step;
}

/*
 * Parameters rspamd relies on are still taken past the parameters cap: a
 * reader that follows the RFC takes them from anywhere in the header, so junk
 * parameters in front must not hide them. All the values of such a name are
 * read as readers read them (rspamd_rfc2231_walk_step), from the first one on,
 * and a value past the cap is kept when it is one readers take: the first
 * plain one, the value of name*=, or a piece, each once. The first value of a
 * name is kept whatever it is, as it decides how the name is taken (see
 * rspamd_postprocess_ct_attributes). A value that is not kept still names a
 * charset or ends the pieces, which the read keeps for
 * rspamd_content_param_resolve; with no value readers take, what is kept of
 * the values may hold less than they do. So copies or junk of one value cannot
 * crowd out another one, and the work is still bounded whatever the names
 * look like. Other names with a star are no RFC 2231 forms, which readers do
 * not take for these parameters.
 */
static gboolean
rspamd_content_param_take_past_cap(rspamd_mempool_t *pool, GHashTable *attrs,
								   struct rspamd_content_params_past_cap **past_cap,
								   const char *name_start, const char *name_end,
								   const char *value_start, const char *value_end)
{
	const char *star = memchr(name_start, '*', name_end - name_start);
	struct rspamd_content_type_param cur, *found = NULL, *elt;
	struct rspamd_past_cap_name *st;
	rspamd_ftok_t srch;
	enum rspamd_rfc2231_step step;
	int i;

	srch.begin = name_start;
	srch.len = (star ? star : name_end) - name_start;
	i = rspamd_past_cap_name_index(srch.begin, srch.len);

	if (i < 0) {
		return FALSE;
	}

	memset(&cur, 0, sizeof(cur));

	if (star != NULL &&
		!rspamd_param_maybe_rfc2231_process(pool, &cur, (char *) name_start, (char *) name_end,
											(char *) value_start, (char *) value_end)) {
		return FALSE;
	}

	if (*past_cap == NULL) {
		*past_cap = rspamd_mempool_alloc0(pool, sizeof(**past_cap));
	}

	st = &(*past_cap)->names[i];

	if (!st->started) {
		/* The values before the cap, read once */
		st->started = TRUE;
		st->walk.accept = TRUE;

		if (attrs != NULL) {
			found = g_hash_table_lookup(attrs, &srch);
		}

		DL_FOREACH(found, elt)
		{
			if (elt->flags & (RSPAMD_CONTENT_PARAM_RFC2231 | RSPAMD_CONTENT_PARAM_PIECEWISE)) {
				rspamd_past_cap_read(st, elt);
			}
			else {
				st->have_plain = TRUE;
			}
		}

		st->have_head = found != NULL;
	}

	if (star == NULL) {
		/* The first plain value is the one taken */
		if (st->have_plain) {
			return FALSE;
		}

		st->have_plain = TRUE;
		st->have_head = TRUE;

		return TRUE;
	}

	if (value_start > name_end && *(value_start - 1) == '"') {
		cur.flags |= RSPAMD_CONTENT_PARAM_QUOTED;
	}

	step = rspamd_past_cap_read(st, &cur);

	/* The header is not kept: neither are the charsets that point into it */
	if (st->walk.label_b.begin == value_start) {
		rspamd_past_cap_keep_label(pool, &st->walk.label_b, &st->label_b, &st->label_b_size);
	}

	if (st->walk.label_cd.begin == value_start) {
		rspamd_past_cap_keep_label(pool, &st->walk.label_cd, &st->label_cd, &st->label_cd_size);
	}

	if (step != RSPAMD_RFC2231_STEP_NONE || !st->have_head) {
		st->have_head = TRUE;

		return TRUE;
	}

	return FALSE;
}

void rspamd_content_type_add_param(rspamd_mempool_t *pool,
								   struct rspamd_content_type *ct,
								   char *name_start, char *name_end,
								   char *value_start, char *value_end)
{
	struct rspamd_content_type_param *nparam;
	rspamd_ftok_t srch;
	struct rspamd_content_type_param *found = NULL;

	g_assert(ct != NULL);

	if (ct->nparams >= max_content_type_params) {
		/* Refuse to amplify a crafted header into unbounded allocations */
		ct->flags |= RSPAMD_CONTENT_TYPE_BROKEN;

		if (!rspamd_content_param_take_past_cap(pool, ct->attrs, &ct->past_cap,
												name_start, name_end, value_start, value_end)) {
			return;
		}
	}

	ct->nparams++;

	nparam = rspamd_mempool_alloc0(pool, sizeof(*nparam));
	rspamd_str_lc(name_start, name_end - name_start);

	if (!rspamd_param_maybe_rfc2231_process(pool, nparam, name_start,
											name_end, value_start, value_end)) {
		nparam->name.begin = name_start;
		nparam->name.len = name_end - name_start;
		nparam->value.begin = value_start;
		nparam->value.len = value_end - value_start;
	}

	if (value_start > name_end && *(value_start - 1) == '"') {
		nparam->flags |= RSPAMD_CONTENT_PARAM_QUOTED;
	}

	srch.begin = nparam->name.begin;
	srch.len = nparam->name.len;

	if (ct->attrs) {
		found = g_hash_table_lookup(ct->attrs, &srch);
	}
	else {
		ct->attrs = g_hash_table_new(rspamd_ftok_icase_hash,
									 rspamd_ftok_icase_equal);
		/*
		 * The parser may still reject the whole value (e.g. an empty type),
		 * so the pool owns the table from the start
		 */
		rspamd_mempool_add_destructor(pool,
									  (rspamd_mempool_destruct_t) g_hash_table_unref, ct->attrs);
	}

	if (!found) {
		DL_APPEND(found, nparam);
		g_hash_table_insert(ct->attrs, &nparam->name, nparam);
	}
	else {
		DL_APPEND(found, nparam);
	}
}

static struct rspamd_content_type *
rspamd_content_type_parser(char *in, gsize len, rspamd_mempool_t *pool)
{
	unsigned int obraces = 0, ebraces = 0, qlen = 0;
	char *p, *c, *end, *pname_start = NULL, *pname_end = NULL;
	struct rspamd_content_type *res = NULL, val;
	gboolean eqsign_seen = FALSE;
	enum {
		parse_type,
		parse_subtype,
		parse_after_subtype,
		parse_param_name,
		parse_param_after_name,
		parse_param_value,
		parse_param_value_after_quote,
		parse_space,
		parse_quoted,
		parse_comment,
	} state = parse_space,
	  next_state = parse_type;

	p = in;
	c = p;
	end = p + len;
	memset(&val, 0, sizeof(val));
	val.cpy = in;

	while (p < end) {
		switch (state) {
		case parse_type:
			if (g_ascii_isspace(*p) || *p == ';') {
				/* We have type without subtype */
				val.type.begin = c;
				val.type.len = p - c;
				state = parse_after_subtype;
			}
			else if (*p == '/') {
				val.type.begin = c;
				val.type.len = p - c;
				state = parse_space;
				next_state = parse_subtype;
				p++;
			}
			else {
				p++;
			}
			break;
		case parse_subtype:
			if (g_ascii_isspace(*p) || *p == ';') {
				val.subtype.begin = c;
				val.subtype.len = p - c;
				state = parse_after_subtype;
			}
			else {
				p++;
			}
			break;
		case parse_after_subtype:
			if (*p == ';' || g_ascii_isspace(*p)) {
				p++;
			}
			else if (*p == '(') {
				c = p;
				state = parse_comment;
				next_state = parse_param_name;
				obraces = 1;
				ebraces = 0;
				pname_start = NULL;
				pname_end = NULL;
				eqsign_seen = FALSE;
				p++;
			}
			else {
				c = p;
				state = parse_param_name;
				pname_start = NULL;
				pname_end = NULL;
				eqsign_seen = FALSE;
			}
			break;
		case parse_param_name:
			if (*p == '=') {
				pname_start = c;
				pname_end = p;
				state = parse_param_after_name;
				eqsign_seen = TRUE;
				p++;
			}
			else if (g_ascii_isspace(*p)) {
				pname_start = c;
				pname_end = p;
				state = parse_param_after_name;
			}
			else {
				p++;
			}
			break;
		case parse_param_after_name:
			if (g_ascii_isspace(*p)) {
				p++;
			}
			else if (*p == '=') {
				if (eqsign_seen) {
					/* Treat as value start */
					c = p;
					eqsign_seen = FALSE;
					state = parse_param_value;
					p++;
				}
				else {
					eqsign_seen = TRUE;
					p++;
				}
			}
			else {
				if (eqsign_seen) {
					state = parse_param_value;
					c = p;
				}
				else {
					/* Invalid parameter without value */
					c = p;
					state = parse_param_name;
					pname_start = NULL;
					pname_end = NULL;
				}
			}
			break;
		case parse_param_value:
			if (*p == '"') {
				p++;
				c = p;
				state = parse_quoted;
				next_state = parse_param_value_after_quote;
			}
			else if (g_ascii_isspace(*p)) {
				if (pname_start && pname_end && pname_end > pname_start) {
					rspamd_content_type_add_param(pool, &val, pname_start,
												  pname_end, c, p);
				}

				state = parse_space;
				next_state = parse_param_name;
				pname_start = NULL;
				pname_end = NULL;
			}
			else if (*p == '(') {
				if (pname_start && pname_end && pname_end > pname_start) {
					rspamd_content_type_add_param(pool, &val, pname_start,
												  pname_end, c, p);
				}

				obraces = 1;
				ebraces = 0;
				p++;
				state = parse_comment;
				next_state = parse_param_name;
				pname_start = NULL;
				pname_end = NULL;
			}
			else if (*p == ';') {
				if (pname_start && pname_end && pname_end > pname_start) {
					rspamd_content_type_add_param(pool, &val, pname_start,
												  pname_end, c, p);
				}

				p++;
				state = parse_space;
				next_state = parse_param_name;
				pname_start = NULL;
				pname_end = NULL;
			}
			else {
				p++;
			}
			break;
		case parse_param_value_after_quote:
			if (pname_start && pname_end && pname_end > pname_start) {
				rspamd_content_type_add_param(pool, &val, pname_start,
											  pname_end, c, c + qlen);
			}

			if (*p == '"') {
				p++;

				if (p == end) {
					/* Last quote: done... */
					state = parse_space;
					break;
				}

				if (*p == ';') {
					p++;
					state = parse_space;
					next_state = parse_param_name;
					pname_start = NULL;
					pname_end = NULL;
					continue;
				}
			}

			/* We should not normally be here in fact */
			if (g_ascii_isspace(*p)) {
				state = parse_space;
				next_state = parse_param_name;
				pname_start = NULL;
				pname_end = NULL;
			}
			else if (*p == '(') {
				obraces = 1;
				ebraces = 0;
				p++;
				state = parse_comment;
				next_state = parse_param_name;
				pname_start = NULL;
				pname_end = NULL;
			}
			else {
				state = parse_param_name;
				pname_start = NULL;
				pname_end = NULL;
				c = p;
			}
			break;
		case parse_quoted:
			if (*p == '\\') {
				/* Quoted pair */
				if (p + 1 < end) {
					p += 2;
				}
				else {
					p++;
				}
			}
			else if (*p == '"') {
				qlen = p - c;
				state = next_state;
			}
			else {
				p++;
			}
			break;
		case parse_comment:
			if (*p == '(') {
				obraces++;
				p++;
			}
			else if (*p == ')') {
				ebraces++;
				p++;

				if (ebraces == obraces && p < end) {
					if (g_ascii_isspace(*p)) {
						state = parse_space;
					}
					else {
						c = p;
						state = next_state;
					}
				}
			}
			else {
				p++;
			}
			break;
		case parse_space:
			if (g_ascii_isspace(*p)) {
				p++;
			}
			else if (*p == '(') {
				obraces = 1;
				ebraces = 0;
				p++;
				state = parse_comment;
			}
			else {
				c = p;
				state = next_state;
			}
			break;
		}
	}

	/* Process leftover */
	switch (state) {
	case parse_type:
		val.type.begin = c;
		val.type.len = p - c;
		break;
	case parse_subtype:
		val.subtype.begin = c;
		val.subtype.len = p - c;
		break;
	case parse_param_value:
		if (pname_start && pname_end && pname_end > pname_start) {
			if (p > c && *(p - 1) == ';') {
				p--;
			}

			rspamd_content_type_add_param(pool, &val, pname_start,
										  pname_end, c, p);
		}
		break;
	case parse_param_value_after_quote:
		if (pname_start && pname_end && pname_end > pname_start) {
			rspamd_content_type_add_param(pool, &val, pname_start,
										  pname_end, c, c + qlen);
		}
		break;
	default:
		break;
	}

	if (val.type.len > 0) {
		char *tmp;

		res = rspamd_mempool_alloc(pool, sizeof(val));
		memcpy(res, &val, sizeof(val));

		/*
		 * Lowercase type and subtype as they are specified as case insensitive
		 * in rfc2045 section 5.1
		 */
		tmp = rspamd_mempool_alloc(pool, val.type.len);
		memcpy(tmp, val.type.begin, val.type.len);
		rspamd_str_lc(tmp, val.type.len);
		res->type.begin = tmp;

		if (val.subtype.len > 0) {
			tmp = rspamd_mempool_alloc(pool, val.subtype.len);
			memcpy(tmp, val.subtype.begin, val.subtype.len);
			rspamd_str_lc(tmp, val.subtype.len);
			res->subtype.begin = tmp;
		}
	}

	return res;
}

struct rspamd_content_type *
rspamd_content_type_parse(const char *in,
						  gsize len, rspamd_mempool_t *pool)
{
	struct rspamd_content_type *res = NULL;
	rspamd_ftok_t srch;
	char *cpy;

	cpy = rspamd_mempool_alloc(pool, len + 1);
	rspamd_strlcpy(cpy, in, len + 1);

	if ((res = rspamd_content_type_parser(cpy, len, pool)) != NULL) {
		if (res->attrs) {
			rspamd_postprocess_ct_attributes(pool, res->attrs, res->past_cap,
											 rspamd_content_type_postprocess, res);
		}

		/* Now do some hacks to work with broken content types */
		if (res->subtype.len == 0) {
			res->flags |= RSPAMD_CONTENT_TYPE_BROKEN;
			RSPAMD_FTOK_ASSIGN(&srch, "text");

			if (rspamd_ftok_casecmp(&res->type, &srch) == 0) {
				/* Workaround for Content-Type: text */
				/* Assume text/plain */
				RSPAMD_FTOK_ASSIGN(&srch, "plain");
			}
			else {
				RSPAMD_FTOK_ASSIGN(&srch, "html");

				if (rspamd_ftok_casecmp(&res->type, &srch) == 0) {
					/* Workaround for Content-Type: html */
					RSPAMD_FTOK_ASSIGN(&res->type, "text");
					RSPAMD_FTOK_ASSIGN(&res->subtype, "html");
				}
				else {
					RSPAMD_FTOK_ASSIGN(&srch, "application");

					if (rspamd_ftok_casecmp(&res->type, &srch) == 0) {
						RSPAMD_FTOK_ASSIGN(&res->subtype, "octet-stream");
					}
				}
			}
		}
		else {
			/* Common mistake done by retards */
			RSPAMD_FTOK_ASSIGN(&srch, "alternate");

			if (rspamd_ftok_casecmp(&res->subtype, &srch) == 0) {
				res->flags |= RSPAMD_CONTENT_TYPE_BROKEN;
				RSPAMD_FTOK_ASSIGN(&res->subtype, "alternative");
			}

			/* PKCS7 smime */
			RSPAMD_FTOK_ASSIGN(&srch, "pkcs7-mime");
			if (rspamd_substring_search(res->subtype.begin, res->subtype.len,
										srch.begin, srch.len) != -1) {
				res->flags |= RSPAMD_CONTENT_TYPE_SMIME;
			}
		}

		RSPAMD_FTOK_ASSIGN(&srch, "multipart");

		if (rspamd_ftok_casecmp(&res->type, &srch) == 0) {
			res->flags |= RSPAMD_CONTENT_TYPE_MULTIPART;

			RSPAMD_FTOK_ASSIGN(&srch, "encrypted");
			if (rspamd_ftok_casecmp(&res->subtype, &srch) == 0) {
				res->flags |= RSPAMD_CONTENT_TYPE_ENCRYPTED;
			}
		}
		else {
			RSPAMD_FTOK_ASSIGN(&srch, "text");

			if (rspamd_ftok_casecmp(&res->type, &srch) == 0) {
				res->flags |= RSPAMD_CONTENT_TYPE_TEXT;
			}
			else {
				RSPAMD_FTOK_ASSIGN(&srch, "message");

				if (rspamd_ftok_casecmp(&res->type, &srch) == 0) {
					RSPAMD_FTOK_ASSIGN(&srch, "delivery-status");

					if (rspamd_ftok_casecmp(&res->subtype, &srch) == 0) {
						res->flags |= RSPAMD_CONTENT_TYPE_TEXT | RSPAMD_CONTENT_TYPE_DSN;
					}
					else {
						RSPAMD_FTOK_ASSIGN(&srch, "notification");

						if (rspamd_substring_search_caseless(res->subtype.begin,
															 res->subtype.len, srch.begin, srch.len) != -1) {
							res->flags |= RSPAMD_CONTENT_TYPE_TEXT |
										  RSPAMD_CONTENT_TYPE_DSN;
						}
						else {
							res->flags |= RSPAMD_CONTENT_TYPE_MESSAGE;
						}
					}
				}
			}
		}
	}
	else {
		msg_warn_pool("cannot parse content type: %*s", (int) len, cpy);
	}

	return res;
}

void rspamd_content_disposition_add_param(rspamd_mempool_t *pool,
										  struct rspamd_content_disposition *cd,
										  const char *name_start, const char *name_end,
										  const char *value_start, const char *value_end)
{
	rspamd_ftok_t srch;
	char *name_cpy, *value_cpy, *name_cpy_end, *value_cpy_end;
	struct rspamd_content_type_param *found = NULL, *nparam;

	g_assert(cd != NULL);

	if (cd->nparams >= max_content_type_params) {
		/* Refuse to amplify a crafted header into unbounded allocations */
		if (!rspamd_content_param_take_past_cap(pool, cd->attrs, &cd->past_cap,
												name_start, name_end, value_start, value_end)) {
			return;
		}
	}

	cd->nparams++;

	name_cpy = rspamd_mempool_alloc(pool, name_end - name_start);
	memcpy(name_cpy, name_start, name_end - name_start);
	name_cpy_end = name_cpy + (name_end - name_start);

	value_cpy = rspamd_mempool_alloc(pool, value_end - value_start);
	memcpy(value_cpy, value_start, value_end - value_start);
	value_cpy_end = value_cpy + (value_end - value_start);

	nparam = rspamd_mempool_alloc0(pool, sizeof(*nparam));
	rspamd_str_lc(name_cpy, name_cpy_end - name_cpy);

	if (!rspamd_param_maybe_rfc2231_process(pool, nparam, name_cpy,
											name_cpy_end, value_cpy, value_cpy_end)) {
		nparam->name.begin = name_cpy;
		nparam->name.len = name_cpy_end - name_cpy;
		nparam->value.begin = value_cpy;
		nparam->value.len = value_cpy_end - value_cpy;
	}

	if (value_start > name_end && *(value_start - 1) == '"') {
		nparam->flags |= RSPAMD_CONTENT_PARAM_QUOTED;
	}

	srch.begin = nparam->name.begin;
	srch.len = nparam->name.len;

	if (cd->attrs) {
		found = g_hash_table_lookup(cd->attrs, &srch);
	}
	else {
		cd->attrs = g_hash_table_new(rspamd_ftok_icase_hash,
									 rspamd_ftok_icase_equal);
		rspamd_mempool_add_destructor(pool,
									  (rspamd_mempool_destruct_t) g_hash_table_unref, cd->attrs);
	}

	if (!found) {
		DL_APPEND(found, nparam);
		g_hash_table_insert(cd->attrs, &nparam->name, nparam);
	}
	else {
		DL_APPEND(found, nparam);
	}
}

struct rspamd_content_disposition *
rspamd_content_disposition_parse(const char *in,
								 gsize len, rspamd_mempool_t *pool)
{
	struct rspamd_content_disposition *res = NULL, val;

	if (rspamd_content_disposition_parser(in, len, &val, pool)) {

		if (val.type == RSPAMD_CT_UNKNOWN) {
			/* 'Fix' type to attachment as MUA does */
			val.type = RSPAMD_CT_ATTACHMENT;
		}

		res = rspamd_mempool_alloc(pool, sizeof(val));
		memcpy(res, &val, sizeof(val));
		res->lc_data = rspamd_mempool_alloc(pool, len + 1);
		rspamd_strlcpy(res->lc_data, in, len + 1);
		rspamd_str_lc(res->lc_data, len);

		if (res->attrs) {
			rspamd_postprocess_ct_attributes(pool, res->attrs, res->past_cap,
											 rspamd_content_disposition_postprocess, res);
		}
	}
	else {
		msg_warn_pool("cannot parse content disposition: %*s",
					  (int) len, in);
	}

	return res;
}
