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
	DL_APPEND (found, nparam);

	if (!found) {
		g_hash_table_insert (ct->attrs, &nparam->name, nparam);
	}

	srch.begin = "charset";
	srch.len = 7;

	if (rspamd_ftok_cmp (&nparam->name, &srch) == 0) {
		/* Adjust charset */
		ct->charset.begin = nparam->value.begin;
		ct->charset.len = nparam->value.len;
	}
}

struct rspamd_content_type *
rspamd_content_type_parse (const gchar *in,
		gsize len, rspamd_mempool_t *pool)
{
	struct rspamd_content_type *res = NULL, val;

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
	}
	else {
		msg_warn_pool ("cannot parse content type: %*s", (gint)len, val.lc_data);
	}

	return res;
}
