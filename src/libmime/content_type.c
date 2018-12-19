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

void
rspamd_content_type_add_param (rspamd_mempool_t *pool,
		struct rspamd_content_type *ct,
		gchar *name_start, gchar *name_end,
		gchar *value_start, gchar *value_end)
{
	rspamd_ftok_t srch;
	struct rspamd_content_type_param *found = NULL, *nparam;

	g_assert (ct != NULL);


	nparam = rspamd_mempool_alloc (pool, sizeof (*nparam));
	nparam->name.begin = name_start;
	nparam->name.len = name_end - name_start;
	rspamd_str_lc (name_start, name_end - name_start);

	nparam->value.begin = value_start;
	nparam->value.len = value_end - value_start;

	RSPAMD_FTOK_ASSIGN (&srch, "charset");

	if (rspamd_ftok_cmp (&nparam->name, &srch) == 0) {
		/* Adjust charset */
		found = nparam;
		ct->charset.begin = nparam->value.begin;
		ct->charset.len = nparam->value.len;
	}

	RSPAMD_FTOK_ASSIGN (&srch, "boundary");

	if (rspamd_ftok_cmp (&nparam->name, &srch) == 0) {
		found = nparam;
		gchar *lc_boundary;
		/* Adjust boundary */
		lc_boundary = rspamd_mempool_alloc (pool, nparam->value.len);
		memcpy (lc_boundary, nparam->value.begin, nparam->value.len);
		rspamd_str_lc (lc_boundary, nparam->value.len);
		ct->boundary.begin = lc_boundary;
		ct->boundary.len = nparam->value.len;
		/* Preserve original (case sensitive) boundary */
		ct->orig_boundary.begin = nparam->value.begin;
		ct->orig_boundary.len = nparam->value.len;
	}

	if (!found) {
		srch.begin = nparam->name.begin;
		srch.len = nparam->name.len;

		rspamd_str_lc (value_start, value_end - value_start);

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
					state = parse_space;
					next_state = parse_param_value;
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
		res = rspamd_mempool_alloc (pool, sizeof (val));
		memcpy (res, &val, sizeof (val));

		/* Lowercase common thingies */

	}

	return res;
}

struct rspamd_content_type *
rspamd_content_type_parse (const gchar *in,
		gsize len, rspamd_mempool_t *pool)
{
	struct rspamd_content_type *res = NULL;
	rspamd_ftok_t srch;
	gchar *lc_data;

	lc_data = rspamd_mempool_alloc (pool, len + 1);
	rspamd_strlcpy (lc_data, in, len + 1);

	if ((res = rspamd_content_type_parser (lc_data, len, pool)) != NULL) {
		if (res->attrs) {
			rspamd_mempool_add_destructor (pool,
					(rspamd_mempool_destruct_t)g_hash_table_unref, res->attrs);
		}

		/* Now do some hacks to work with broken content types */
		if (res->subtype.len == 0) {
			res->flags |= RSPAMD_CONTENT_TYPE_BROKEN;
			RSPAMD_FTOK_ASSIGN (&srch, "text");

			if (rspamd_ftok_cmp (&res->type, &srch) == 0) {
				/* Workaround for Content-Type: text */
				/* Assume text/plain */
				RSPAMD_FTOK_ASSIGN (&srch, "plain");
			}
			else {
				RSPAMD_FTOK_ASSIGN (&srch, "html");

				if (rspamd_ftok_cmp (&res->type, &srch) == 0) {
					/* Workaround for Content-Type: html */
					RSPAMD_FTOK_ASSIGN (&res->type, "text");
					RSPAMD_FTOK_ASSIGN (&res->subtype, "html");
				}
				else {
					RSPAMD_FTOK_ASSIGN (&srch, "application");

					if (rspamd_ftok_cmp (&res->type, &srch) == 0) {
						RSPAMD_FTOK_ASSIGN (&res->subtype, "octet-stream");
					}
				}
			}
		}
		else {
			/* Common mistake done by retards */
			RSPAMD_FTOK_ASSIGN (&srch, "alternate");

			if (rspamd_ftok_cmp (&res->subtype, &srch) == 0) {
				res->flags |= RSPAMD_CONTENT_TYPE_BROKEN;
				RSPAMD_FTOK_ASSIGN (&res->subtype, "alternative");
			}
		}

		RSPAMD_FTOK_ASSIGN (&srch, "multipart");

		if (rspamd_ftok_cmp (&res->type, &srch) == 0) {
			res->flags |= RSPAMD_CONTENT_TYPE_MULTIPART;
		}
		else {
			RSPAMD_FTOK_ASSIGN (&srch, "text");

			if (rspamd_ftok_cmp (&res->type, &srch) == 0) {
				res->flags |= RSPAMD_CONTENT_TYPE_TEXT;
			}
			else {
				RSPAMD_FTOK_ASSIGN (&srch, "message");

				if (rspamd_ftok_cmp (&res->type, &srch) == 0) {
					RSPAMD_FTOK_ASSIGN (&srch, "delivery-status");

					if (rspamd_ftok_cmp (&res->subtype, &srch) == 0) {
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
		msg_warn_pool ("cannot parse content type: %*s", (gint)len, lc_data);
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
	gchar *decoded;
	struct rspamd_content_type_param *found = NULL, *nparam;

	g_assert (cd != NULL);

	srch.begin = name_start;
	srch.len = name_end - name_start;

	if (cd->attrs) {
		found = g_hash_table_lookup (cd->attrs, &srch);
	}
	else {
		cd->attrs = g_hash_table_new (rspamd_ftok_icase_hash,
				rspamd_ftok_icase_equal);
		rspamd_mempool_add_destructor (pool,
				(rspamd_mempool_destruct_t)g_hash_table_unref, cd->attrs);
	}

	nparam = rspamd_mempool_alloc (pool, sizeof (*nparam));
	nparam->name.begin = name_start;
	nparam->name.len = name_end - name_start;
	decoded = rspamd_mime_header_decode (pool, value_start,
			value_end - value_start, NULL);
	RSPAMD_FTOK_FROM_STR (&nparam->value, decoded);

	if (!found) {
		g_hash_table_insert (cd->attrs, &nparam->name, nparam);
	}

	DL_APPEND (found, nparam);

	srch.begin = "filename";
	srch.len = 8;

	if (rspamd_ftok_cmp (&nparam->name, &srch) == 0) {
		/* Adjust filename */
		cd->filename.begin = nparam->value.begin;
		cd->filename.len = nparam->value.len;
	}
}

struct rspamd_content_disposition *
rspamd_content_disposition_parse (const gchar *in,
		gsize len, rspamd_mempool_t *pool)
{
	struct rspamd_content_disposition *res = NULL, val;

	if (rspamd_content_disposition_parser (in, len, &val, pool)) {
		res = rspamd_mempool_alloc (pool, sizeof (val));
		memcpy (res, &val, sizeof (val));
		res->lc_data = rspamd_mempool_alloc (pool, len + 1);
		rspamd_strlcpy (res->lc_data, in, len + 1);
		rspamd_str_lc (res->lc_data, len);
	}
	else {
		msg_warn_pool ("cannot parse content disposition: %*s",
				(gint)len, val.lc_data);
	}

	return res;
}
