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

#include "libmime/content_type.h"
#include "smtp_parsers.h"
#include "utlist.h"
#include "libserver/url.h"
#include "libmime/mime_encoding.h"

static gboolean
rspamd_rfc2231_decode (rspamd_mempool_t *pool,
		struct rspamd_content_type_param *param,
		gchar *value_start, gchar *value_end)
{
	gchar *quote_pos;

	quote_pos = memchr (value_start, '\'', value_end - value_start);

	if (quote_pos == NULL) {
		/* Plain percent encoding */
		gsize r = rspamd_url_decode (value_start, value_start,
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
		const gchar *charset = NULL;
		rspamd_ftok_t ctok;

		ctok.begin = value_start;
		ctok.len = quote_pos - value_start;

		if (ctok.len > 0) {
			charset = rspamd_mime_detect_charset (&ctok, pool);
		}

		/* Now, we can check for either next quote sign or, eh, ignore that */
		value_start = quote_pos + 1;

		quote_pos = memchr (value_start, '\'', value_end - value_start);

		if (quote_pos) {
			/* Ignore language */
			value_start = quote_pos + 1;
		}

		/* Perform percent decoding */
		gsize r = rspamd_url_decode (value_start, value_start,
				value_end - value_start);
		GError *err = NULL;

		if (charset == NULL) {
			/* Try heuristic */
			charset = rspamd_mime_charset_find_by_content (value_start, r, TRUE);
		}

		if (charset == NULL) {
			msg_warn_pool ("cannot convert parameter from charset %T", &ctok);

			return FALSE;
		}

		param->value.begin = rspamd_mime_text_to_utf8 (pool,
				value_start, r,
				charset, &param->value.len, &err);

		if (param->value.begin == NULL) {
			msg_warn_pool ("cannot convert parameter from charset %s: %e",
					charset, err);

			if (err) {
				g_error_free (err);
			}

			return FALSE;
		}
	}

	param->flags |= RSPAMD_CONTENT_PARAM_RFC2231;

	return TRUE;
}

static gboolean
rspamd_param_maybe_rfc2231_process (rspamd_mempool_t *pool,
									struct rspamd_content_type_param *param,
									gchar *name_start, gchar *name_end,
									gchar *value_start, gchar *value_end)
{
	const gchar *star_pos;

	star_pos = memchr (name_start, '*', name_end - name_start);

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
		if (rspamd_rfc2231_decode (pool, param, value_start, value_end)) {
			param->name.begin = name_start;
			param->name.len = name_end - name_start - 1;
		}
	}
	else if (*(name_end - 1) == '*') {
		/* Third */
		/* Check number */
		gulong tmp;

		if (!rspamd_strtoul (star_pos + 1, name_end - star_pos - 2, &tmp)) {
			return FALSE;
		}

		param->flags |= RSPAMD_CONTENT_PARAM_PIECEWISE|RSPAMD_CONTENT_PARAM_RFC2231;
		param->rfc2231_id = tmp;
		param->name.begin = name_start;
		param->name.len = star_pos - name_start;
		param->value.begin = value_start;
		param->value.len = value_end - value_start;

		/* Deal with that later... */
	}
	else {
		/* Second case */
		gulong tmp;

		if (!rspamd_strtoul (star_pos + 1, name_end - star_pos - 1, &tmp)) {
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

static gint32
rspamd_cmp_pieces (struct rspamd_content_type_param *p1, struct rspamd_content_type_param *p2)
{
	return p1->rfc2231_id - p2->rfc2231_id;
}

static void
rspamd_postprocess_ct_attributes (rspamd_mempool_t *pool,
								  GHashTable *htb,
								  void (*proc)(rspamd_mempool_t *, struct rspamd_content_type_param *, gpointer ud),
								  gpointer procd)
{
	GHashTableIter it;
	gpointer k, v;
	struct rspamd_content_type_param *param, *sorted, *cur;

	if (htb == NULL) {
		return;
	}

	g_hash_table_iter_init (&it, htb);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		param = (struct rspamd_content_type_param *)v;

		if (param->flags & RSPAMD_CONTENT_PARAM_PIECEWISE) {
			/* Reconstruct param */
			gsize tlen = 0;
			gchar *ndata, *pos;

			sorted = param;
			DL_SORT (sorted, rspamd_cmp_pieces);

			DL_FOREACH (sorted, cur) {
				tlen += cur->value.len;
			}

			ndata = rspamd_mempool_alloc (pool, tlen);
			pos = ndata;

			DL_FOREACH (sorted, cur) {
				memcpy (pos, cur->value.begin, cur->value.len);
				pos += cur->value.len;
			}

			if (param->flags & RSPAMD_CONTENT_PARAM_RFC2231) {
				if (!rspamd_rfc2231_decode (pool, param,
						ndata, pos)) {
					param->flags |= RSPAMD_CONTENT_PARAM_BROKEN;
					param->value.begin = ndata;
					param->value.len = tlen;
				}
			}
			else {
				param->value.begin = ndata;
				param->value.len = tlen;
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

		proc (pool, param, procd);
	}
}

static void
rspamd_content_type_postprocess (rspamd_mempool_t *pool,
								 struct rspamd_content_type_param *param,
								 gpointer ud)
{
	rspamd_ftok_t srch;
	struct rspamd_content_type_param *found = NULL;

	struct rspamd_content_type *ct = (struct rspamd_content_type *)ud;

	RSPAMD_FTOK_ASSIGN (&srch, "charset");

	if (rspamd_ftok_icase_equal (&param->name, &srch)) {
		/* Adjust charset */
		found = param;
		ct->charset.begin = param->value.begin;
		ct->charset.len = param->value.len;
	}

	RSPAMD_FTOK_ASSIGN (&srch, "boundary");

	if (rspamd_ftok_icase_equal (&param->name, &srch)) {
		found = param;
		gchar *lc_boundary;
		/* Adjust boundary */
		lc_boundary = rspamd_mempool_alloc (pool, param->value.len);
		memcpy (lc_boundary, param->value.begin, param->value.len);
		rspamd_str_lc (lc_boundary, param->value.len);
		ct->boundary.begin = lc_boundary;
		ct->boundary.len = param->value.len;
		/* Preserve original (case sensitive) boundary */
		ct->orig_boundary.begin = param->value.begin;
		ct->orig_boundary.len = param->value.len;
	}

	if (!found) {
		RSPAMD_FTOK_ASSIGN (&srch, "name");
		if (!rspamd_ftok_icase_equal (&param->name, &srch)) {
			/* Just lowercase */
			rspamd_str_lc_utf8 ((gchar *) param->value.begin, param->value.len);
		}
	}
}

static void
rspamd_content_disposition_postprocess (rspamd_mempool_t *pool,
										struct rspamd_content_type_param *param,
										gpointer ud)
{
	rspamd_ftok_t srch;
	struct rspamd_content_disposition *cd = (struct rspamd_content_disposition *)ud;

	srch.begin = "filename";
	srch.len = 8;

	if (rspamd_ftok_icase_equal (&param->name, &srch)) {
		/* Adjust filename */
		cd->filename.begin = param->value.begin;
		cd->filename.len = param->value.len;
	}
}

void
rspamd_content_type_add_param (rspamd_mempool_t *pool,
		struct rspamd_content_type *ct,
		gchar *name_start, gchar *name_end,
		gchar *value_start, gchar *value_end)
{
	struct rspamd_content_type_param *nparam;
	rspamd_ftok_t srch;
	struct rspamd_content_type_param *found = NULL;

	g_assert (ct != NULL);

	nparam = rspamd_mempool_alloc0 (pool, sizeof (*nparam));
	rspamd_str_lc (name_start, name_end - name_start);

	if (!rspamd_param_maybe_rfc2231_process (pool, nparam, name_start,
			name_end, value_start, value_end)) {
		nparam->name.begin = name_start;
		nparam->name.len = name_end - name_start;
		nparam->value.begin = value_start;
		nparam->value.len = value_end - value_start;
	}

	srch.begin = nparam->name.begin;
	srch.len = nparam->name.len;

	if (ct->attrs) {
		found = g_hash_table_lookup (ct->attrs, &srch);
	} else {
		ct->attrs = g_hash_table_new (rspamd_ftok_icase_hash,
				rspamd_ftok_icase_equal);
	}

	if (!found) {
		DL_APPEND (found, nparam);
		g_hash_table_insert (ct->attrs, &nparam->name, nparam);
	}
	else {
		DL_APPEND (found, nparam);
	}
}

static struct rspamd_content_type *
rspamd_content_type_parser (gchar *in, gsize len, rspamd_mempool_t *pool)
{
	guint obraces = 0, ebraces = 0, qlen = 0;
	gchar *p, *c, *end, *pname_start = NULL, *pname_end = NULL;
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
	} state = parse_space, next_state = parse_type;

	p = in;
	c = p;
	end = p + len;
	memset (&val, 0, sizeof (val));
	val.cpy = in;

	while (p < end) {
		switch (state) {
		case parse_type:
			if (g_ascii_isspace (*p) || *p == ';') {
				/* We have type without subtype */
				val.type.begin = c;
				val.type.len = p - c;
				state = parse_after_subtype;
			} else if (*p == '/') {
				val.type.begin = c;
				val.type.len = p - c;
				state = parse_space;
				next_state = parse_subtype;
				p++;
			} else {
				p++;
			}
			break;
		case parse_subtype:
			if (g_ascii_isspace (*p) || *p == ';') {
				val.subtype.begin = c;
				val.subtype.len = p - c;
				state = parse_after_subtype;
			} else {
				p++;
			}
			break;
		case parse_after_subtype:
			if (*p == ';' || g_ascii_isspace (*p)) {
				p++;
			} else if (*p == '(') {
				c = p;
				state = parse_comment;
				next_state = parse_param_name;
				obraces = 1;
				ebraces = 0;
				pname_start = NULL;
				pname_end = NULL;
				eqsign_seen = FALSE;
				p++;
			} else {
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
			} else if (g_ascii_isspace (*p)) {
				pname_start = c;
				pname_end = p;
				state = parse_param_after_name;
			} else {
				p++;
			}
			break;
		case parse_param_after_name:
			if (g_ascii_isspace (*p)) {
				p++;
			} else if (*p == '=') {
				if (eqsign_seen) {
					/* Treat as value start */
					c = p;
					eqsign_seen = FALSE;
					state = parse_param_value;
					p++;
				} else {
					eqsign_seen = TRUE;
					p++;
				}
			} else {
				if (eqsign_seen) {
					state = parse_param_value;
					c = p;
				} else {
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
			} else if (g_ascii_isspace (*p)) {
				if (pname_start && pname_end && pname_end > pname_start) {
					rspamd_content_type_add_param (pool, &val, pname_start,
							pname_end, c, p);

				}

				state = parse_space;
				next_state = parse_param_name;
				pname_start = NULL;
				pname_end = NULL;
			} else if (*p == '(') {
				if (pname_start && pname_end && pname_end > pname_start) {
					rspamd_content_type_add_param (pool, &val, pname_start,
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
					rspamd_content_type_add_param (pool, &val, pname_start,
							pname_end, c, p);
				}

				p ++;
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
				rspamd_content_type_add_param (pool, &val, pname_start,
						pname_end, c, c + qlen);
			}

			if (*p == '"') {
				p ++;

				if (p == end) {
					/* Last quote: done... */
					state = parse_space;
					break;
				}

				if (*p == ';') {
					p ++;
					state = parse_space;
					next_state = parse_param_name;
					pname_start = NULL;
					pname_end = NULL;
					continue;
				}
			}

			/* We should not normally be here in fact */
			if (g_ascii_isspace (*p)) {
				state = parse_space;
				next_state = parse_param_name;
				pname_start = NULL;
				pname_end = NULL;
			} else if (*p == '(') {
				obraces = 1;
				ebraces = 0;
				p++;
				state = parse_comment;
				next_state = parse_param_name;
				pname_start = NULL;
				pname_end = NULL;
			} else {
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
				} else {
					p++;
				}
			} else if (*p == '"') {
				qlen = p - c;
				state = next_state;
			} else {
				p++;
			}
			break;
		case parse_comment:
			if (*p == '(') {
				obraces++;
				p++;
			} else if (*p == ')') {
				ebraces++;
				p++;

				if (ebraces == obraces && p < end) {
					if (g_ascii_isspace (*p)) {
						state = parse_space;
					} else {
						c = p;
						state = next_state;
					}
				}
			} else {
				p++;
			}
			break;
		case parse_space:
			if (g_ascii_isspace (*p)) {
				p++;
			} else if (*p == '(') {
				obraces = 1;
				ebraces = 0;
				p++;
				state = parse_comment;
			} else {
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
				p --;
			}

			rspamd_content_type_add_param (pool, &val, pname_start,
					pname_end, c, p);

		}
		break;
	case parse_param_value_after_quote:
		if (pname_start && pname_end && pname_end > pname_start) {
			rspamd_content_type_add_param (pool, &val, pname_start,
					pname_end, c, c + qlen);
		}
		break;
	default:
		break;
	}

	if (val.type.len > 0) {
		gchar *tmp;

		res = rspamd_mempool_alloc (pool, sizeof (val));
		memcpy (res, &val, sizeof (val));

		/*
		 * Lowercase type and subtype as they are specified as case insensitive
		 * in rfc2045 section 5.1
		 */
		tmp = rspamd_mempool_alloc (pool, val.type.len);
		memcpy (tmp, val.type.begin, val.type.len);
		rspamd_str_lc (tmp, val.type.len);
		res->type.begin = tmp;

		if (val.subtype.len > 0) {
			tmp = rspamd_mempool_alloc (pool, val.subtype.len);
			memcpy (tmp, val.subtype.begin, val.subtype.len);
			rspamd_str_lc (tmp, val.subtype.len);
			res->subtype.begin = tmp;
		}
	}

	return res;
}

struct rspamd_content_type *
rspamd_content_type_parse (const gchar *in,
		gsize len, rspamd_mempool_t *pool)
{
	struct rspamd_content_type *res = NULL;
	rspamd_ftok_t srch;
	gchar *cpy;

	cpy = rspamd_mempool_alloc (pool, len + 1);
	rspamd_strlcpy (cpy, in, len + 1);

	if ((res = rspamd_content_type_parser (cpy, len, pool)) != NULL) {
		if (res->attrs) {
			rspamd_mempool_add_destructor (pool,
					(rspamd_mempool_destruct_t)g_hash_table_unref, res->attrs);

			rspamd_postprocess_ct_attributes (pool, res->attrs,
					rspamd_content_type_postprocess, res);
		}

		/* Now do some hacks to work with broken content types */
		if (res->subtype.len == 0) {
			res->flags |= RSPAMD_CONTENT_TYPE_BROKEN;
			RSPAMD_FTOK_ASSIGN (&srch, "text");

			if (rspamd_ftok_casecmp (&res->type, &srch) == 0) {
				/* Workaround for Content-Type: text */
				/* Assume text/plain */
				RSPAMD_FTOK_ASSIGN (&srch, "plain");
			}
			else {
				RSPAMD_FTOK_ASSIGN (&srch, "html");

				if (rspamd_ftok_casecmp (&res->type, &srch) == 0) {
					/* Workaround for Content-Type: html */
					RSPAMD_FTOK_ASSIGN (&res->type, "text");
					RSPAMD_FTOK_ASSIGN (&res->subtype, "html");
				}
				else {
					RSPAMD_FTOK_ASSIGN (&srch, "application");

					if (rspamd_ftok_casecmp (&res->type, &srch) == 0) {
						RSPAMD_FTOK_ASSIGN (&res->subtype, "octet-stream");
					}
				}
			}
		}
		else {
			/* Common mistake done by retards */
			RSPAMD_FTOK_ASSIGN (&srch, "alternate");

			if (rspamd_ftok_casecmp (&res->subtype, &srch) == 0) {
				res->flags |= RSPAMD_CONTENT_TYPE_BROKEN;
				RSPAMD_FTOK_ASSIGN (&res->subtype, "alternative");
			}

			/* PKCS7 smime */
			RSPAMD_FTOK_ASSIGN (&srch, "pkcs7-mime");
			if (rspamd_substring_search (res->subtype.begin, res->subtype.len,
					srch.begin, srch.len) != -1) {
				res->flags |= RSPAMD_CONTENT_TYPE_SMIME;
			}
		}

		RSPAMD_FTOK_ASSIGN (&srch, "multipart");

		if (rspamd_ftok_casecmp (&res->type, &srch) == 0) {
			res->flags |= RSPAMD_CONTENT_TYPE_MULTIPART;

			RSPAMD_FTOK_ASSIGN (&srch, "encrypted");
			if (rspamd_ftok_casecmp (&res->subtype, &srch) == 0) {
				res->flags |= RSPAMD_CONTENT_TYPE_ENCRYPTED;
			}
		}
		else {
			RSPAMD_FTOK_ASSIGN (&srch, "text");

			if (rspamd_ftok_casecmp (&res->type, &srch) == 0) {
				res->flags |= RSPAMD_CONTENT_TYPE_TEXT;
			}
			else {
				RSPAMD_FTOK_ASSIGN (&srch, "message");

				if (rspamd_ftok_casecmp (&res->type, &srch) == 0) {
					RSPAMD_FTOK_ASSIGN (&srch, "delivery-status");

					if (rspamd_ftok_casecmp (&res->subtype, &srch) == 0) {
						res->flags |= RSPAMD_CONTENT_TYPE_TEXT|RSPAMD_CONTENT_TYPE_DSN;
					}
					else {
						RSPAMD_FTOK_ASSIGN (&srch, "notification");

						if (rspamd_substring_search_caseless (res->subtype.begin,
								res->subtype.len, srch.begin, srch.len) != -1) {
							res->flags |= RSPAMD_CONTENT_TYPE_TEXT|
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
		msg_warn_pool ("cannot parse content type: %*s", (gint)len, cpy);
	}

	return res;
}

void
rspamd_content_disposition_add_param (rspamd_mempool_t *pool,
		struct rspamd_content_disposition *cd,
		const gchar *name_start, const gchar *name_end,
		const gchar *value_start, const gchar *value_end)
{
	rspamd_ftok_t srch;
	gchar *name_cpy, *value_cpy, *name_cpy_end, *value_cpy_end;
	struct rspamd_content_type_param *found = NULL, *nparam;

	g_assert (cd != NULL);

	name_cpy = rspamd_mempool_alloc (pool, name_end - name_start);
	memcpy (name_cpy, name_start, name_end - name_start);
	name_cpy_end = name_cpy + (name_end - name_start);

	value_cpy = rspamd_mempool_alloc (pool, value_end - value_start);
	memcpy (value_cpy, value_start, value_end - value_start);
	value_cpy_end = value_cpy + (value_end - value_start);

	nparam = rspamd_mempool_alloc0 (pool, sizeof (*nparam));
	rspamd_str_lc (name_cpy, name_cpy_end - name_cpy);

	if (!rspamd_param_maybe_rfc2231_process (pool, nparam, name_cpy,
			name_cpy_end, value_cpy, value_cpy_end)) {
		nparam->name.begin = name_cpy;
		nparam->name.len = name_cpy_end - name_cpy;
		nparam->value.begin = value_cpy;
		nparam->value.len = value_cpy_end - value_cpy;
	}

	srch.begin = nparam->name.begin;
	srch.len = nparam->name.len;

	if (cd->attrs) {
		found = g_hash_table_lookup (cd->attrs, &srch);
	} else {
		cd->attrs = g_hash_table_new (rspamd_ftok_icase_hash,
				rspamd_ftok_icase_equal);
	}

	if (!found) {
		DL_APPEND (found, nparam);
		g_hash_table_insert (cd->attrs, &nparam->name, nparam);
	}
	else {
		DL_APPEND (found, nparam);
	}
}

struct rspamd_content_disposition *
rspamd_content_disposition_parse (const gchar *in,
		gsize len, rspamd_mempool_t *pool)
{
	struct rspamd_content_disposition *res = NULL, val;

	if (rspamd_content_disposition_parser (in, len, &val, pool)) {

		if (val.type == RSPAMD_CT_UNKNOWN) {
			/* 'Fix' type to attachment as MUA does */
			val.type = RSPAMD_CT_ATTACHMENT;
		}

		res = rspamd_mempool_alloc (pool, sizeof (val));
		memcpy (res, &val, sizeof (val));
		res->lc_data = rspamd_mempool_alloc (pool, len + 1);
		rspamd_strlcpy (res->lc_data, in, len + 1);
		rspamd_str_lc (res->lc_data, len);

		if (res->attrs) {
			rspamd_postprocess_ct_attributes (pool, res->attrs,
					rspamd_content_disposition_postprocess, res);
			rspamd_mempool_add_destructor (pool,
					(rspamd_mempool_destruct_t)g_hash_table_unref, res->attrs);
		}
	}
	else {
		msg_warn_pool ("cannot parse content disposition: %*s",
				(gint)len, in);
	}

	return res;
}
