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
		ret = g_malloc (sizeof (*ret));
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

		return ret;
	}

	return NULL;
}

void
rspamd_email_address_free (struct rspamd_email_address *addr)
{
	if (addr) {
		if (addr->flags & RSPAMD_EMAIL_ADDR_ADDR_ALLOCATED) {
			g_free ((void *) addr->addr);
		}

		if (addr->flags & RSPAMD_EMAIL_ADDR_USER_ALLOCATED) {
			g_free ((void *) addr->user);
		}

		g_free (addr);
	}
}

static inline void
rspamd_email_address_add (rspamd_mempool_t *pool,
		GPtrArray *ar,
		struct rspamd_email_address *addr,
		GString *name)
{
	struct rspamd_email_address *elt;
	guint nlen;

	elt = g_malloc0 (sizeof (*elt));
	rspamd_mempool_notify_alloc (pool, sizeof (*elt));

	if (addr != NULL) {
		memcpy (elt, addr, sizeof (*addr));
	}
	else {
		elt->addr = "";
		elt->domain = "";
		elt->raw = "<>";
		elt->raw_len = 2;
		elt->user = "";
		elt->flags |= RSPAMD_EMAIL_ADDR_EMPTY;
	}

	if ((elt->flags & RSPAMD_EMAIL_ADDR_QUOTED) && elt->addr[0] == '"') {
		if (elt->flags & RSPAMD_EMAIL_ADDR_HAS_BACKSLASH) {
			/* We also need to unquote user */
			rspamd_email_address_unescape (elt);
		}

		/* We need to unquote addr */
		nlen = elt->domain_len + elt->user_len + 2;
		elt->addr = g_malloc (nlen + 1);
		rspamd_mempool_notify_alloc (pool, nlen + 1);
		elt->addr_len = rspamd_snprintf ((char *)elt->addr, nlen, "%*s@%*s",
				(gint)elt->user_len, elt->user,
				(gint)elt->domain_len, elt->domain);
		elt->flags |= RSPAMD_EMAIL_ADDR_ADDR_ALLOCATED;
	}

	if (name->len > 0) {
		rspamd_gstring_strip (name, " \t\v");
		elt->name = rspamd_mime_header_decode (pool, name->str, name->len, NULL);
	}

	rspamd_mempool_notify_alloc (pool, name->len);
	g_ptr_array_add (ar, elt);
}

/*
 * Tries to parse an email address that doesn't conform RFC
 */
static gboolean
rspamd_email_address_parse_heuristic (const char *data, size_t len,
		struct rspamd_email_address *addr)
{
	const gchar *p = data, *at = NULL, *end = data + len;
	gboolean ret = FALSE;

	memset (addr, 0, sizeof (*addr));

	if (*p == '<' && len > 1) {
		/* Angled address */
		addr->addr_len = rspamd_memcspn (p + 1, ">", len - 1);
		addr->addr = p + 1;
		addr->raw = p;
		addr->raw_len = len;
		ret = TRUE;

		p = p + 1;
		len = addr->addr_len;
		end = p + len;
	}
	else if (len > 0) {
		addr->addr = p;
		addr->addr_len = len;
		addr->raw = p;
		addr->raw_len = len;
		ret = TRUE;
	}

	if (ret) {
		at = rspamd_memrchr (p, '@', len);

		if (at != NULL && at + 1 < end) {
			addr->domain = at + 1;
			addr->domain_len = end - (at + 1);
			addr->user = p;
			addr->user_len = at - p;
		}

		if (rspamd_str_has_8bit (p, len)) {
			addr->flags |= RSPAMD_EMAIL_ADDR_HAS_8BIT;
		}
	}

	return ret;
}

static inline int
rspamd_email_address_check_and_add (const gchar *start, gsize len,
									GPtrArray *res,
									rspamd_mempool_t *pool,
									GString *ns,
									gint max_elements)
{
	struct rspamd_email_address addr;

	g_assert (res != NULL);

	if (max_elements > 0 && res->len >= max_elements) {
		msg_info_pool_check ("reached maximum number of elements %d when adding %v",
				max_elements,
				ns);

		return -1;
	}

	/* The whole email is likely address */
	memset (&addr, 0, sizeof (addr));
	rspamd_smtp_addr_parse (start, len, &addr);

	if (addr.flags & RSPAMD_EMAIL_ADDR_VALID) {
		rspamd_email_address_add (pool, res, &addr, ns);
	}
	else {
		/* Try heuristic */
		if (rspamd_email_address_parse_heuristic (start,
				len, &addr)) {
			rspamd_email_address_add (pool, res, &addr, ns);

			return 1;
		}
		else {
			return 0;
		}
	}

	return 1;
}

GPtrArray *
rspamd_email_address_from_mime (rspamd_mempool_t *pool, const gchar *hdr,
								guint len,
								GPtrArray *src,
								gint max_elements)
{
	GPtrArray *res = src;
	gboolean seen_at = FALSE, seen_obrace = FALSE;

	const gchar *p = hdr, *end = hdr + len, *c = hdr, *t;
	GString *ns, *cpy;
	gint obraces, ebraces;
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
	else if (max_elements > 0 && res->len >= max_elements) {
		msg_info_pool_check ("reached maximum number of elements %d", max_elements);

		return res;
	}

	ns = g_string_sized_new (len);
	cpy = g_string_sized_new (len);

	rspamd_mempool_add_destructor (pool, rspamd_gstring_free_hard, cpy);

	/* First, we need to remove all comments as they are terrible */
	obraces = 0;
	ebraces = 0;

	while (p < end) {
		if (state == parse_name) {
			if (*p == '\\') {
				if (obraces == 0) {
					g_string_append_c (cpy, *p);
				}

				p++;
			}
			else {
				if (*p == '"') {
					state = parse_quoted;
				}
				else if (*p == '(') {
					obraces ++; /* To avoid ) itself being copied */
				}
				else if (*p == ')') {
					ebraces ++;
					p ++;
				}

				if (obraces == ebraces) {
					obraces = 0;
					ebraces = 0;
				}
			}

			if (p < end && obraces == 0) {
				g_string_append_c (cpy, *p);
			}
		}
		else {
			/* Quoted elt */
			if (*p == '\\') {
				g_string_append_c (cpy, *p);
				p++;
			}
			else {
				if (*p == '"') {
					state = parse_name;
				}
			}

			if (p < end) {
				g_string_append_c (cpy, *p);
			}
		}

		p++;
	}

	state = parse_name;

	p = cpy->str;
	c = p;
	end = p + cpy->len;

	while (p < end) {
		switch (state) {
		case parse_name:
			if (*p == '"') {
				/* We need to strip last spaces and update `ns` */
				if (p > c) {
					guint nspaces = 0;

					t = p - 1;

					while (t > c && g_ascii_isspace (*t)) {
						t --;
						nspaces ++;
					}

					g_string_append_len (ns, c, t - c + 1);

					if (nspaces > 0) {
						g_string_append_c (ns, ' ');
					}
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
				if (p > c && seen_at) {
					/*
					 * Last token must be the address:
					 * e.g. Some name name@domain.com
					 */
					t = p - 1;

					while (t > c && g_ascii_isspace (*t)) {
						t --;
					}

					int check = rspamd_email_address_check_and_add (c, t - c + 1,
							res, pool, ns, max_elements);

					if (check == 0 && res->len == 0) {
						/* Insert fake address */
						rspamd_email_address_add (pool, res, NULL, ns);
					}
					else if (check != 1) {
						goto end;
					}

					/* Cleanup for the next use */
					g_string_set_size (ns, 0);
					seen_at = FALSE;
				}

				state = skip_spaces;
				next_state = parse_name;
			}
			else if (*p == '@') {
				seen_at = TRUE;
			}

			p ++;
			break;
		case parse_quoted:
			if (*p == '\\') {
				if (p > c) {
					g_string_append_len (ns, c, p - c);
				}

				p ++;
				c = p;
			}
			else if (*p == '"') {
				if (p > c) {
					g_string_append_len (ns, c, p - c);
				}

				if (p + 1 < end && g_ascii_isspace (p[1])) {
					g_string_append_c (ns, ' ');
				}

				state = skip_spaces;
				next_state = parse_name;
			}
			else if (*p == '@' && seen_obrace) {
				seen_at = TRUE;
			}
			else if (*p == '<') {
				seen_obrace = TRUE;
			}
			p ++;
			break;
		case parse_addr:
			if (*p == '>') {
				int check = rspamd_email_address_check_and_add (c, p - c + 1,
						res, pool, ns, max_elements);
				if (check == 0 && res->len == 0) {
					/* Insert a fake address */
					rspamd_email_address_add (pool, res, NULL, ns);
				}
				else if (check != 1) {
					goto end;
				}

				/* Cleanup for the next use */
				g_string_set_size (ns, 0);
				seen_at = FALSE;
				state = skip_spaces;
				next_state = parse_name;
			}
			else if (*p == '@') {
				seen_at = TRUE;
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
		/* Assume the whole header as name (bad thing) */
		if (p > c) {
			while (p > c && g_ascii_isspace (*p)) {
				p --;
			}

			if (p > c) {
				if (seen_at) {
					/* The whole email is likely address */
					int check = rspamd_email_address_check_and_add (c, p - c,
							res, pool, ns, max_elements);
					if (check == 0 && res->len == 0) {
						/* Insert a fake address */
						rspamd_email_address_add (pool, res, NULL, ns);
					}
					else if (check != 1) {
						goto end;
					}
				} else {
					/* No @ seen */
					g_string_append_len (ns, c, p - c);

					if (res->len == 0) {
						rspamd_email_address_add (pool, res, NULL, ns);
					}
				}
			}
			else if (res->len == 0) {
				rspamd_email_address_add (pool, res, NULL, ns);
			}
		}
		break;
	case parse_addr:
		if (p > c) {
			if (rspamd_email_address_check_and_add (c, p - c,
					res, pool, ns, max_elements) == 0) {
				if (res->len == 0) {
					rspamd_email_address_add (pool, res, NULL, ns);
				}
			}
		}
		break;
	case parse_quoted:
		/* Unfinished quoted string or a comment */
		/* If we have seen obrace + at, then we still can try to resolve address */
		if (seen_at && seen_obrace) {
			p = rspamd_memrchr (cpy->str, '<', cpy->len);
			g_assert (p != NULL);
			if (rspamd_email_address_check_and_add (p, end - p,
					res, pool, ns, max_elements) == 0) {
				if (res->len == 0) {
					rspamd_email_address_add (pool, res, NULL, ns);
				}
			}
		}
		break;
	default:
		/* Do nothing */
		break;
	}
end:
	rspamd_mempool_notify_alloc (pool, cpy->len);
	g_string_free (ns, TRUE);

	return res;
}

void
rspamd_email_address_list_destroy (gpointer ptr)
{
	GPtrArray *ar = ptr;
	guint i;
	struct rspamd_email_address *addr;

	PTR_ARRAY_FOREACH (ar, i, addr) {
		rspamd_email_address_free (addr);
	}

	g_ptr_array_free (ar, TRUE);
}