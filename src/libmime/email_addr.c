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
#include "smtp_parsers.h"
#include "mime_headers.h"

static void
rspamd_email_addr_dtor (struct rspamd_email_address *addr)
{
	if (addr->flags & RSPAMD_EMAIL_ADDR_ADDR_ALLOCATED) {
		g_free ((void *)addr->addr);
	}

	if (addr->flags & RSPAMD_EMAIL_ADDR_USER_ALLOCATED) {
		g_free ((void *)addr->user);
	}

	g_slice_free1 (sizeof (*addr), addr);
}

static void
rspamd_email_address_unescape (struct rspamd_email_address *addr)
{
	const char *h, *end;
	char *t, *d;

	if (addr->user_len == 0) {
		return;
	}

	d = g_malloc (addr->user_len);
	t = d;
	h = addr->user;
	end = h + addr->user_len;

	while (h < end) {
		if (*h != '\\') {
			*t++ = *h;
		}
		h ++;
	}

	addr->user = d;
	addr->user_len = t - d;
	addr->flags |= RSPAMD_EMAIL_ADDR_USER_ALLOCATED;
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
			if (ret->flags & RSPAMD_EMAIL_ADDR_HAS_BACKSLASH) {
				/* We also need to unquote user */
				rspamd_email_address_unescape (ret);
			}

			/* We need to unquote addr */
			nlen = ret->domain_len + ret->user_len + 2;
			ret->addr = g_malloc (nlen + 1);
			ret->addr_len = rspamd_snprintf ((char *)ret->addr, nlen, "%*s@%*s",
					(gint)ret->user_len, ret->user,
					(gint)ret->domain_len, ret->domain);
			ret->flags |= RSPAMD_EMAIL_ADDR_ADDR_ALLOCATED;
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

static inline void
rspamd_email_address_add (rspamd_mempool_t *pool,
		GPtrArray *ar,
		struct rspamd_email_address *addr,
		GString *name)
{
	struct rspamd_email_address *elt;
	guint nlen;

	elt = g_slice_alloc (sizeof (*elt));
	memcpy (elt, addr, sizeof (*addr));

	if ((elt->flags & RSPAMD_EMAIL_ADDR_QUOTED) && elt->addr[0] == '"') {
		if (elt->flags & RSPAMD_EMAIL_ADDR_HAS_BACKSLASH) {
			/* We also need to unquote user */
			rspamd_email_address_unescape (elt);
		}

		/* We need to unquote addr */
		nlen = elt->domain_len + elt->user_len + 2;
		elt->addr = g_malloc (nlen + 1);
		elt->addr_len = rspamd_snprintf ((char *)elt->addr, nlen, "%*s@%*s",
				(gint)elt->user_len, elt->user,
				(gint)elt->domain_len, elt->domain);
		elt->flags |= RSPAMD_EMAIL_ADDR_ADDR_ALLOCATED;
	}

	REF_INIT_RETAIN (elt, rspamd_email_addr_dtor);

	if (name->len > 0) {
		elt->name = rspamd_mime_header_decode (pool, name->str, name->len);
		elt->name_len = strlen (elt->name);
	}

	g_ptr_array_add (ar, elt);
}

GPtrArray *
rspamd_email_address_from_mime (rspamd_mempool_t *pool,
		const gchar *hdr, guint len,
		GPtrArray *src)
{
	GPtrArray *res = src;
	struct rspamd_email_address addr;
	const gchar *p = hdr, *end = hdr + len, *c = hdr, *t;
	GString *ns;
	enum {
		parse_name = 0,
		parse_quoted,
		parse_addr,
		skip_spaces
	} state = parse_name, next_state = parse_name;

	if (res == NULL) {
		res = g_ptr_array_sized_new (2);
		rspamd_mempool_add_destructor (pool, rspamd_email_address_list_destroy,
				res);
	}

	ns = g_string_sized_new (127);

	while (p < end) {
		switch (state) {
		case parse_name:
			if (*p == '"') {
				/* We need to strip last spaces and update `ns` */
				if (p > c) {
					t = p - 1;

					while (t > c && g_ascii_isspace (*t)) {
						t --;
					}

					g_string_append_len (ns, c, t - c + 1);
				}

				state = parse_quoted;
				c = p + 1;
			}
			else if (*p == '<') {
				if (p > c) {
					t = p - 1;

					while (t > c && g_ascii_isspace (*t)) {
						t --;
					}

					g_string_append_len (ns, c, t - c + 1);
				}

				c = p;
				state = parse_addr;
			}
			else if (*p == ',') {
				if (p > c) {
					/*
					 * Last token must be the address:
					 * e.g. Some name name@domain.com
					 */
					t = p - 1;

					while (t > c && g_ascii_isspace (*t)) {
						t --;
					}

					rspamd_smtp_addr_parse (c, t - c + 1, &addr);

					if (addr.flags & RSPAMD_EMAIL_ADDR_VALID) {
						rspamd_email_address_add (pool, res, &addr, ns);
					}

					/* Cleanup for the next use */
					g_string_set_size (ns, 0);
				}

				state = skip_spaces;
				next_state = parse_name;
			}
			p ++;
			break;
		case parse_quoted:
			if (*p == '"') {
				if (p > c) {
					g_string_append_len (ns, c, p - c);
				}

				state = skip_spaces;
				next_state = parse_name;
			}
			p ++;
			break;
		case parse_addr:
			if (*p == '>') {
				rspamd_smtp_addr_parse (c, p - c + 1, &addr);

				if (addr.flags & RSPAMD_EMAIL_ADDR_VALID) {
					rspamd_email_address_add (pool, res, &addr, ns);
				}

				/* Cleanup for the next use */
				g_string_set_size (ns, 0);

				state = skip_spaces;
				next_state = parse_name;
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

	/* Handle leftover */
	switch (state) {
	case parse_name:
	case parse_addr:
		if (p > c) {
			rspamd_smtp_addr_parse (c, p - c, &addr);

			if (addr.flags & RSPAMD_EMAIL_ADDR_VALID) {
				rspamd_email_address_add (pool, res, &addr, ns);
			}
		}
		break;
	case parse_quoted:
		/* Unfinished quoted string */
		break;
	default:
		/* Do nothing */
		break;
	}

	return res;
}

void
rspamd_email_address_list_destroy (gpointer ptr)
{
	GPtrArray *ar = ptr;
	guint i;
	struct rspamd_email_address *addr;

	PTR_ARRAY_FOREACH (ar, i, addr) {
		REF_RELEASE (addr);
	}

	g_ptr_array_free (ar, TRUE);
}
