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
		const gchar *name_start, const gchar *name_end,
		const gchar *value_start, const gchar *value_end)
{
	rspamd_ftok_t srch;
	struct rspamd_content_type_param *found = NULL, *nparam;

	g_assert (ct != NULL);

	srch.begin = name_start;
	srch.len = name_end - name_start;

	if (ct->attrs) {
		found = g_hash_table_lookup (ct->attrs, &srch);
	}
	else {
		ct->attrs = g_hash_table_new (rspamd_ftok_icase_hash,
				rspamd_ftok_icase_equal);
	}

	nparam = rspamd_mempool_alloc (pool, sizeof (*nparam));
	nparam->name.begin = name_start;
	nparam->name.len = name_end - name_start;
	nparam->value.begin = value_start;
	nparam->value.len = value_end - value_start;

	if (!found) {
		DL_APPEND (found, nparam);
		g_hash_table_insert (ct->attrs, &nparam->name, nparam);
	}
	else {
		DL_APPEND (found, nparam);
	}

	RSPAMD_FTOK_ASSIGN (&srch, "charset");

	if (rspamd_ftok_cmp (&nparam->name, &srch) == 0) {
		/* Adjust charset */
		ct->charset.begin = nparam->value.begin;
		ct->charset.len = nparam->value.len;
	}

	RSPAMD_FTOK_ASSIGN (&srch, "boundary");

	if (rspamd_ftok_cmp (&nparam->name, &srch) == 0) {
		/* Adjust boundary */
		ct->boundary.begin = nparam->value.begin;
		ct->boundary.len = nparam->value.len;
	}
}

struct rspamd_content_type *
rspamd_content_type_parse (const gchar *in,
		gsize len, rspamd_mempool_t *pool)
{
	struct rspamd_content_type *res = NULL, val;
	rspamd_ftok_t srch;

	val.lc_data = rspamd_mempool_alloc (pool, len);
	memcpy (val.lc_data, in, len);
	rspamd_str_lc (val.lc_data, len);

	if (rspamd_content_type_parser (val.lc_data, len, &val, pool)) {
		res = rspamd_mempool_alloc (pool, sizeof (val));
		memcpy (res, &val, sizeof (val));

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
					res->flags |= RSPAMD_CONTENT_TYPE_MESSAGE;
				}
			}
		}
	}
	else {
		msg_warn_pool ("cannot parse content type: %*s", (gint)len, val.lc_data);
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
	}

	nparam = rspamd_mempool_alloc (pool, sizeof (*nparam));
	nparam->name.begin = name_start;
	nparam->name.len = name_end - name_start;
	decoded = rspamd_mime_header_decode (pool, value_start, value_end - value_start);
	RSPAMD_FTOK_FROM_STR (&nparam->value, decoded);
	DL_APPEND (found, nparam);

	if (!found) {
		g_hash_table_insert (cd->attrs, &nparam->name, nparam);
	}

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

	val.lc_data = rspamd_mempool_alloc (pool, len);
	memcpy (val.lc_data, in, len);
	rspamd_str_lc (val.lc_data, len);

	if (rspamd_content_disposition_parser (val.lc_data, len, &val, pool)) {
		res = rspamd_mempool_alloc (pool, sizeof (val));
		memcpy (res, &val, sizeof (val));

		if (res->attrs) {
			rspamd_mempool_add_destructor (pool,
					(rspamd_mempool_destruct_t)g_hash_table_unref, res->attrs);
		}
	}
	else {
		msg_warn_pool ("cannot parse content disposition: %*s",
				(gint)len, val.lc_data);
	}

	return res;
}
