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
#include "email_addr.h"
#include "message.h"
#include "printf.h"

#include "./parsers/smtp_addr_parser.c"

static void
rspamd_email_addr_dtor (struct rspamd_email_address *addr)
{
	if (addr->flags & RSPAMD_EMAIL_ADDR_ALLOCATED) {
		g_free ((void *)addr->addr);
	}
	g_slice_free1 (sizeof (*addr), addr);
}

struct rspamd_email_address *
rspamd_email_address_from_smtp (const gchar *str, guint len)
{
	struct rspamd_email_address addr, *ret;
	gsize nlen;

	if (str == NULL || len == 0) {
		return NULL;
	}

	rspamd_smtp_addr_parse (str, len, &addr);

	if (addr.flags & RSPAMD_EMAIL_ADDR_VALID) {
		ret = g_slice_alloc (sizeof (*ret));
		memcpy (ret, &addr, sizeof (addr));

		if ((ret->flags & RSPAMD_EMAIL_ADDR_QUOTED) && ret->addr[0] == '"') {
			/* We need to unquote addr */
			nlen = ret->domain_len + ret->user_len + 2;
			ret->addr = g_malloc (nlen + 1);
			ret->addr_len = rspamd_snprintf ((char *)ret->addr, nlen, "%*s@%*s",
					(gint)ret->user_len, ret->user,
					(gint)ret->domain_len, ret->domain);
			ret->flags |= RSPAMD_EMAIL_ADDR_ALLOCATED;
		}

		REF_INIT_RETAIN (ret, rspamd_email_addr_dtor);

		return ret;
	}

	return NULL;
}

struct rspamd_email_address *
rspamd_email_address_ref (struct rspamd_email_address *addr)
{
	REF_RETAIN (addr);

	return addr;
}

void
rspamd_email_address_unref (struct rspamd_email_address *addr)
{
	REF_RELEASE (addr);
}
