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
#include "libserver/url.h"
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

/*
 * Decodes an RFC 2231 value, charset'language'data or data, percent encoded,
 * into the value of `param`, which is not changed when it cannot be. A value
 * that readers do not take (Thunderbird) is flagged BROKEN: bytes that are
 * not UTF-8 (ASCII included) under a charset that is not known or is UTF-8
 */
static gboolean
rspamd_rfc2231_decode(rspamd_mempool_t *pool,
					  struct rspamd_content_type_param *param,
					  char *value_start, char *value_end)
{
	char *quote_pos;

	quote_pos = memchr(value_start, '\'', value_end - value_start);

	if (quote_pos == NULL) {
		/* Plain percent encoding */
		gsize r = rspamd_url_decode(value_start, value_start,
									value_end - value_start);
		param->value.begin = value_start;
		param->value.len = r;
	}
	else {
		/*
		 * We can have encoding'language'data, or
		 * encoding'data (in theory).
		 * Try to handle both...
		 */
		const char *charset = NULL, *label_charset;
		const char *converted;
		gsize converted_len = 0;
		gboolean utf8;
		rspamd_ftok_t ctok;

		ctok.begin = value_start;
		ctok.len = quote_pos - value_start;

		if (ctok.len > 0) {
			charset = rspamd_mime_detect_charset(&ctok, pool);
		}

		label_charset = charset;

		/* Now, we can check for either next quote sign or, eh, ignore that */
		value_start = quote_pos + 1;

		quote_pos = memchr(value_start, '\'', value_end - value_start);

		if (quote_pos) {
			/* Ignore language */
			value_start = quote_pos + 1;
		}

		/* Perform percent decoding */
		gsize r = rspamd_url_decode(value_start, value_start,
									value_end - value_start);
		GError *err = NULL;

		utf8 = rspamd_fast_utf8_validate((const unsigned char *) value_start, r) == 0;

		if (charset == NULL) {
			/* Try heuristic */
			charset = rspamd_mime_charset_find_by_content(value_start, r, TRUE);
		}

		if (charset == NULL) {
			msg_warn_pool("cannot convert parameter from charset %T", &ctok);

			return FALSE;
		}

		converted = rspamd_mime_text_to_utf8(pool,
											 value_start, r,
											 charset, &converted_len, &err);

		if (converted == NULL) {
			msg_warn_pool("cannot convert parameter from charset %s: %e",
						  charset, err);

			if (err) {
				g_error_free(err);
			}

			return FALSE;
		}

		param->value.begin = converted;
		param->value.len = converted_len;

		if (!utf8 && ctok.len > 0 &&
			(label_charset == NULL || g_ascii_strcasecmp(label_charset, "UTF-8") == 0)) {
			param->flags |= RSPAMD_CONTENT_PARAM_BROKEN;
		}
	}

	param->flags |= RSPAMD_CONTENT_PARAM_RFC2231;

	return TRUE;
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
		/* First */
		gboolean escapes_valid = rspamd_rfc2231_escapes_valid(
			rspamd_rfc2231_value_data(value_start, value_end), value_end);

		if (rspamd_rfc2231_decode(pool, param, value_start, value_end)) {
			param->name.begin = name_start;
			param->name.len = name_end - name_start - 1;

			if (!escapes_valid) {
				param->flags |= RSPAMD_CONTENT_PARAM_BAD_ESCAPE;
			}
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

/* Joins the pieces in [first, ...) in their order, flagged and decoded as name*0* says */
static void
rspamd_content_param_join(rspamd_mempool_t *pool, struct rspamd_content_type_param **pieces,
						  unsigned int npieces, struct rspamd_content_type_param *res)
{
	gsize tlen = 0;
	char *ndata, *pos;
	unsigned int n;
	gboolean ext = (pieces[0]->flags & RSPAMD_CONTENT_PARAM_RFC2231) != 0;

	for (n = 0; n < npieces; n++) {
		tlen += pieces[n]->value.len;
	}

	ndata = rspamd_mempool_alloc(pool, tlen + 1);
	pos = ndata;

	for (n = 0; n < npieces; n++) {
		struct rspamd_content_type_param *cur = pieces[n];

		memcpy(pos, cur->value.begin, cur->value.len);

		if (n > 0 && !ext && (cur->flags & RSPAMD_CONTENT_PARAM_RFC2231)) {
			/* Percent encoded, without a charset */
			pos += rspamd_url_decode(pos, pos, cur->value.len);
		}
		else {
			pos += cur->value.len;
		}
	}

	*res = *pieces[0];
	res->flags &= ~RSPAMD_CONTENT_PARAM_BROKEN;
	res->value.begin = ndata;
	res->value.len = pos - ndata;

	if (ext && !rspamd_rfc2231_decode(pool, res, ndata, pos)) {
		/* As they are */
		res->value.begin = ndata;
		res->value.len = pos - ndata;
		res->flags |= RSPAMD_CONTENT_PARAM_BROKEN;
	}
}

/*
 * The value of a parameter whose first one is a piece (name*0, name*1...):
 * other ones of that name may be name*= (RFC 2231) or name= (plain). As in
 * Thunderbird, name*= is taken, else the pieces joined from 0 up to a missing
 * one, else the plain one: a plain value is never a piece (name*1=x;
 * name="a.exe" is a.exe, not a.exex). Pieces are taken in their order up to a
 * repeated one or a quoted one with percent encoding, which readers refuse.
 * The name*= taken is the first with data and good escapes; it or the pieces
 * are no value when empty or when they do not decode (BROKEN, see
 * rspamd_rfc2231_decode). With no value at all, the pieces are joined as they
 * are, to keep what they hold. Also used when the first one is a name*= that
 * is no value.
 */
static struct rspamd_content_type_param *
rspamd_content_param_resolve(rspamd_mempool_t *pool, struct rspamd_content_type_param *head)
{
	struct rspamd_content_type_param *by_num[max_rfc2231_pieces], **all;
	struct rspamd_content_type_param *ext = NULL, *plain = NULL, *cur, *sorted, joined;
	unsigned int n, nall = 0;
	gboolean accept = TRUE, seen_ext = FALSE;

	memset(by_num, 0, sizeof(by_num));

	DL_FOREACH(head, cur)
	{
		if (!(cur->flags & RSPAMD_CONTENT_PARAM_PIECEWISE)) {
			if (cur->flags & RSPAMD_CONTENT_PARAM_RFC2231) {
				/* The first one with data and good escapes, even if it does not decode */
				if (!seen_ext && cur->value.len > 0 && !(cur->flags & RSPAMD_CONTENT_PARAM_BAD_ESCAPE)) {
					seen_ext = TRUE;

					if (!(cur->flags & RSPAMD_CONTENT_PARAM_BROKEN)) {
						ext = cur;
					}
				}
			}
			else if (plain == NULL) {
				plain = cur;
			}

			continue;
		}

		if (cur->rfc2231_id >= max_rfc2231_pieces) {
			accept = FALSE;
			continue;
		}

		if (accept) {
			if (by_num[cur->rfc2231_id] != NULL ||
				((cur->flags & RSPAMD_CONTENT_PARAM_RFC2231) &&
				 (cur->flags & RSPAMD_CONTENT_PARAM_QUOTED))) {
				accept = FALSE;
			}
			else {
				by_num[cur->rfc2231_id] = cur;
			}
		}

		nall++;
	}

	if (ext != NULL) {
		return ext;
	}

	if (by_num[0] != NULL) {
		for (n = 0; n < max_rfc2231_pieces && by_num[n] != NULL; n++) {}

		rspamd_content_param_join(pool, by_num, n, &joined);

		if (joined.value.len > 0 && !(joined.flags & RSPAMD_CONTENT_PARAM_BROKEN)) {
			*by_num[0] = joined;

			return by_num[0];
		}
	}

	if (plain != NULL) {
		return plain;
	}

	if (nall == 0) {
		/* A name*= that readers do not take, alone: as it is */
		return head;
	}

	/* No value readers take: all the pieces in the order of their numbers */
	all = rspamd_mempool_alloc(pool, nall * sizeof(*all));
	sorted = head;
	DL_SORT(sorted, rspamd_cmp_pieces);
	n = 0;

	DL_FOREACH(sorted, cur)
	{
		if ((cur->flags & RSPAMD_CONTENT_PARAM_PIECEWISE) && n < nall) {
			all[n++] = cur;
		}
	}

	rspamd_content_param_join(pool, all, n, &joined);
	joined.flags |= RSPAMD_CONTENT_PARAM_BROKEN;
	*all[0] = joined;

	return all[0];
}

static void
rspamd_postprocess_ct_attributes(rspamd_mempool_t *pool,
								 GHashTable *htb,
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

		if ((param->flags & RSPAMD_CONTENT_PARAM_PIECEWISE) ||
			((param->flags & RSPAMD_CONTENT_PARAM_RFC2231) &&
			 (param->value.len == 0 ||
			  (param->flags & (RSPAMD_CONTENT_PARAM_BROKEN | RSPAMD_CONTENT_PARAM_BAD_ESCAPE))))) {
			struct rspamd_content_type_param *chosen = rspamd_content_param_resolve(pool, param);

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

/*
 * Places taken past the cap: of each name, its pieces, then name*, then
 * name, then whether a repeated piece has ended its pieces
 */
#define rspamd_past_cap_ext max_rfc2231_pieces
#define rspamd_past_cap_plain (max_rfc2231_pieces + 1)
#define rspamd_past_cap_stopped (max_rfc2231_pieces + 2)

struct rspamd_content_params_past_cap {
	uint8_t taken[4][(max_rfc2231_pieces + 3 + 7) / 8];
};

/*
 * Parameters rspamd relies on are still taken past the parameters cap: a
 * reader that follows the RFC takes them from anywhere in the header, so junk
 * parameters in front must not hide them. A plain name is taken once, and so
 * is each RFC 2231 form of it: name*, and each piece name*N or name*N* that
 * readers join. Each of these places is taken by the first parameter that
 * comes for it, so copies or junk of one cannot crowd out another one, and
 * the work is still bounded whatever the names look like. As readers do, a
 * repeated piece ends the pieces, and a name*= with no data or a bad escape
 * is no value. Other
 * names with a star are no RFC 2231 forms, which readers do not take for
 * these parameters. A plain name is not taken after a value that is no
 * piece, which comes first and is the value (see
 * rspamd_content_param_resolve).
 */
static gboolean
rspamd_content_param_take_past_cap(rspamd_mempool_t *pool, GHashTable *attrs,
								   struct rspamd_content_params_past_cap **past_cap,
								   const char *name_start, const char *name_end,
								   const char *value_start, const char *value_end)
{
	static const char *const kept[] = {"boundary", "charset", "name", "filename"};
	const char *star = memchr(name_start, '*', name_end - name_start);
	rspamd_ftok_t srch;
	unsigned int place = rspamd_past_cap_plain, i;

	G_STATIC_ASSERT(G_N_ELEMENTS(kept) == G_N_ELEMENTS(((struct rspamd_content_params_past_cap *) NULL)->taken));

	if (star != NULL) {
		const char *num_end = name_end;

		if (star == name_end - 1) {
			/* No data or a bad escape in it is no value, which readers skip */
			const char *data = rspamd_rfc2231_value_data(value_start, value_end);

			if (data == value_end || !rspamd_rfc2231_escapes_valid(data, value_end)) {
				return FALSE;
			}

			place = rspamd_past_cap_ext;
		}
		else {
			if (*(name_end - 1) == '*') {
				num_end--;
			}

			if (!rspamd_rfc2231_piece_number(star + 1, num_end, &place)) {
				return FALSE;
			}
		}
	}

	srch.begin = name_start;
	srch.len = (star ? star : name_end) - name_start;

	for (i = 0; i < G_N_ELEMENTS(kept); i++) {
		if (srch.len == strlen(kept[i]) &&
			g_ascii_strncasecmp(srch.begin, kept[i], srch.len) == 0) {
			uint8_t *taken;

			if (place == rspamd_past_cap_plain && attrs != NULL) {
				struct rspamd_content_type_param *found = g_hash_table_lookup(attrs, &srch);

				if (found != NULL && !(found->flags & RSPAMD_CONTENT_PARAM_PIECEWISE)) {
					return FALSE;
				}
			}

			if (*past_cap == NULL) {
				*past_cap = rspamd_mempool_alloc0(pool, sizeof(**past_cap));
			}

			taken = (*past_cap)->taken[i];

			if (place < max_rfc2231_pieces &&
				(taken[rspamd_past_cap_stopped / 8] & (1u << (rspamd_past_cap_stopped % 8)))) {
				return FALSE;
			}

			if (taken[place / 8] & (1u << (place % 8))) {
				if (place < max_rfc2231_pieces) {
					taken[rspamd_past_cap_stopped / 8] |= 1u << (rspamd_past_cap_stopped % 8);
				}

				return FALSE;
			}

			taken[place / 8] |= 1u << (place % 8);

			return TRUE;
		}
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
			rspamd_postprocess_ct_attributes(pool, res->attrs,
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
			rspamd_postprocess_ct_attributes(pool, res->attrs,
											 rspamd_content_disposition_postprocess, res);
		}
	}
	else {
		msg_warn_pool("cannot parse content disposition: %*s",
					  (int) len, in);
	}

	return res;
}
