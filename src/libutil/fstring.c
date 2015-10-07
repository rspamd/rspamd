/*
 * Copyright (c) 2009-2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "fstring.h"
#include "str_util.h"

static const gsize default_initial_size = 48;
/* Maximum size when we double the size of new string */
static const gsize max_grow = 1024 * 1024;

#define fstravail(s) ((s)->allocated - (s)->len)
static rspamd_fstring_t * rspamd_fstring_grow (rspamd_fstring_t *str,
		gsize needed_len) G_GNUC_WARN_UNUSED_RESULT;

rspamd_fstring_t *
rspamd_fstring_new (void)
{
	rspamd_fstring_t *s;

	g_assert (posix_memalign ((void**)&s, 16, default_initial_size + sizeof (*s)) == 0);
	s->len = 0;
	s->allocated = default_initial_size;

	return s;
}

rspamd_fstring_t *
rspamd_fstring_sized_new (gsize initial_size)
{
	rspamd_fstring_t *s;
	gsize real_size = MAX (default_initial_size, initial_size);

	g_assert (posix_memalign ((void **)&s, 16, real_size + sizeof (*s)) == 0);
	s->len = 0;
	s->allocated = real_size;

	return s;
}

rspamd_fstring_t *
rspamd_fstring_new_init (const gchar *init, gsize len)
{
	rspamd_fstring_t *s;
	gsize real_size = MAX (default_initial_size, len);

	g_assert (posix_memalign ((void **) &s, 16, real_size + sizeof (*s)) == 0);
	s->len = len;
	s->allocated = real_size;
	memcpy (s->str, init, len);

	return s;
}

rspamd_fstring_t *
rspamd_fstring_assign (rspamd_fstring_t *str, const gchar *init, gsize len)
{
	gsize avail = str->allocated;

	if (avail < len) {
		str = rspamd_fstring_grow (str, len);
	}

	if (len > 0) {
		memcpy (str->str, init, len);
	}

	str->len = len;

	return str;
}

void
rspamd_fstring_free (rspamd_fstring_t *str)
{
	free (str);
}

static rspamd_fstring_t *
rspamd_fstring_grow (rspamd_fstring_t *str, gsize needed_len)
{
	gsize newlen;
	gpointer nptr;

	newlen = str->len + needed_len;

	/*
	 * Stop exponential grow at some point, since it might be slow for the
	 * vast majority of cases
	 */
	if (newlen < max_grow) {
		newlen *= 2;
	}
	else {
		newlen += max_grow;
	}

	nptr = realloc (str, newlen + sizeof (*str));

	if (nptr == NULL) {
		/* Avoid memory leak */
		free (str);
		g_assert (nptr);
	}

	str = nptr;
	str->allocated = newlen;

	return str;
}

rspamd_fstring_t *
rspamd_fstring_append (rspamd_fstring_t *str, const char *in, gsize len)
{
	gsize avail = fstravail (str);

	if (avail < len) {
		str = rspamd_fstring_grow (str, len);
	}

	memcpy (str->str + str->len, in, len);
	str->len += len;

	return str;
}

void
rspamd_fstring_erase (rspamd_fstring_t *str, gsize pos, gsize len)
{
	if (pos < str->len) {
		if (pos + len > str->len) {
			len = str->len - pos;
		}

		if (len == str->len - pos) {
			/* Fast path */
			str->len = pos;
		}
		else {
			memmove (str->str + pos, str->str + pos + len, str->len - pos);
			str->len -= pos;
		}
	}
	else {
		/* Do nothing */
	}
}

char *rspamd_fstring_cstr (const rspamd_fstring_t *str);

/* Compat code */
static guint32
fstrhash_c (gchar c, guint32 hval)
{
	guint32 tmp;
	/*
	 * xor in the current byte against each byte of hval
	 * (which alone gaurantees that every bit of input will have
	 * an effect on the output)
	 */
	tmp = c & 0xFF;
	tmp = tmp | (tmp << 8) | (tmp << 16) | (tmp << 24);
	hval ^= tmp;

	/* add some bits out of the middle as low order bits */
	hval = hval + ((hval >> 12) & 0x0000ffff);

	/* swap most and min significative bytes */
	tmp = (hval << 24) | ((hval >> 24) & 0xff);
	/* zero most and min significative bytes of hval */
	hval &= 0x00ffff00;
	hval |= tmp;
	/*
	 * rotate hval 3 bits to the left (thereby making the
	 * 3rd msb of the above mess the hsb of the output hash)
	 */
	return (hval << 3) + (hval >> 29);
}


/*
 * Return hash value for a string
 */
guint32
rspamd_fstrhash_lc (const rspamd_ftok_t * str, gboolean is_utf)
{
	gsize i;
	guint32 j, hval;
	const gchar *p, *end = NULL;
	gchar t;
	gunichar uc;

	if (str == NULL) {
		return 0;
	}

	p = str->begin;
	hval = str->len;

	if (is_utf) {
		while (end < str->begin + str->len) {
			if (!g_utf8_validate (p, str->len, &end)) {
				return rspamd_fstrhash_lc (str, FALSE);
			}
			while (p < end) {
				uc = g_unichar_tolower (g_utf8_get_char (p));
				for (j = 0; j < sizeof (gunichar); j++) {
					t = (uc >> (j * 8)) & 0xff;
					if (t != 0) {
						hval = fstrhash_c (t, hval);
					}
				}
				p = g_utf8_next_char (p);
			}
			p = end + 1;
		}

	}
	else {
		for (i = 0; i < str->len; i++, p++) {
			hval = fstrhash_c (g_ascii_tolower (*p), hval);
		}
	}

	return hval;
}

gboolean
rspamd_fstring_equal (const rspamd_fstring_t *s1,
		const rspamd_fstring_t *s2)
{
	g_assert (s1 != NULL && s2 != NULL);

	if (s1->len == s2->len) {
		return (memcmp (s1->str, s2->str, s1->len) == 0);
	}

	return FALSE;
}

gint
rspamd_fstring_casecmp (const rspamd_fstring_t *s1,
		const rspamd_fstring_t *s2)
{
	gint ret = 0;

	g_assert (s1 != NULL && s2 != NULL);

	if (s1->len == s2->len) {
		ret = rspamd_lc_cmp (s1->str, s2->str, s1->len);
	}
	else {
		ret = s1->len - s2->len;
	}

	return ret;
}

gint
rspamd_fstring_cmp (const rspamd_fstring_t *s1,
		const rspamd_fstring_t *s2)
{
	g_assert (s1 != NULL && s2 != NULL);

	if (s1->len == s2->len) {
		return memcmp (s1->str, s2->str, s1->len);
	}

	return s1->len - s2->len;
}

gint
rspamd_ftok_casecmp (const rspamd_ftok_t *s1,
		const rspamd_ftok_t *s2)
{
	gint ret = 0;

	g_assert (s1 != NULL && s2 != NULL);

	if (s1->len == s2->len) {
		ret = rspamd_lc_cmp (s1->begin, s2->begin, s1->len);
	}
	else {
		ret = s1->len - s2->len;
	}

	return ret;
}

gint
rspamd_ftok_cmp (const rspamd_ftok_t *s1,
		const rspamd_ftok_t *s2)
{
	g_assert (s1 != NULL && s2 != NULL);

	if (s1->len == s2->len) {
		return memcmp (s1->begin, s2->begin, s1->len);
	}

	return s1->len - s2->len;
}

void
rspamd_fstring_mapped_ftok_free (gpointer p)
{
	rspamd_ftok_t *tok = p;
	rspamd_fstring_t *storage;

	storage = (rspamd_fstring_t *) (tok->begin - 2 * sizeof (gsize));
	rspamd_fstring_free (storage);
	g_slice_free1 (sizeof (*tok), tok);
}