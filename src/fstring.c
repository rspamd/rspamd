/*
 * Copyright (c) 2012, Vsevolod Stakhov
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

/*
 * Search first occurence of character in string
 */
ssize_t
fstrchr (f_str_t * src, gchar c)
{
	register size_t                cur = 0;

	while (cur < src->len) {
		if (*(src->begin + cur) == c) {
			return cur;
		}
		cur++;
	}

	return -1;
}

/*
 * Search last occurence of character in string
 */
ssize_t
fstrrchr (f_str_t * src, gchar c)
{
	register ssize_t                cur = src->len;

	while (cur > 0) {
		if (*(src->begin + cur) == c) {
			return cur;
		}
		cur--;
	}

	return -1;
}

/*
 * Search for pattern in orig
 */
ssize_t
fstrstr (f_str_t * orig, f_str_t * pattern)
{
	register size_t                cur = 0, pcur = 0;

	if (pattern->len > orig->len) {
		return -1;
	}

	while (cur < orig->len) {
		if (*(orig->begin + cur) == *pattern->begin) {
			while (cur < orig->len && pcur < pattern->len) {
				if (*(orig->begin + cur) != *(pattern->begin + pcur)) {
					pcur = 0;
					break;
				}
				cur++;
				pcur++;
			}
			return cur - pattern->len;
		}
		cur++;
	}

	return -1;

}

/*
 * Search for pattern in orig ignoring case
 */
ssize_t
fstrstri (f_str_t * orig, f_str_t * pattern)
{
	register size_t                cur = 0, pcur = 0;

	if (pattern->len > orig->len) {
		return -1;
	}

	while (cur < orig->len) {
		if (g_ascii_tolower (*(orig->begin + cur)) == g_ascii_tolower (*pattern->begin)) {
			while (cur < orig->len && pcur < pattern->len) {
				if (g_ascii_tolower (*(orig->begin + cur)) != g_ascii_tolower (*(pattern->begin + pcur))) {
					pcur = 0;
					break;
				}
				cur++;
				pcur++;
			}
			return cur - pattern->len;
		}
		cur++;
	}

	return -1;

}

/*
 * Split string by tokens
 * word contains parsed word
 *
 * Return: -1 - no new words can be extracted
 * 			1 - word was extracted and there are more words
 * 			0 - last word extracted
 */
gint
fstrtok (f_str_t * text, const gchar *sep, f_tok_t * state)
{
	register size_t                 cur;
	const gchar                     *csep = sep;

	if (state->pos >= text->len) {
		return -1;
	}

	cur = state->pos;

	while (cur < text->len) {
		while (*csep) {
			if (*(text->begin + cur) == *csep) {
				state->word.begin = (text->begin + state->pos);
				state->word.len = cur - state->pos;
				state->pos = cur + 1;
				return 1;
			}
			csep++;
		}
		csep = sep;
		cur++;
	}

	/* Last word */
	state->word.begin = (text->begin + state->pos);
	state->word.len = cur - state->pos;
	state->pos = cur;

	return 0;
}

/*
 * Copy one string into other
 */
size_t
fstrcpy (f_str_t * dest, f_str_t * src)
{
	register size_t                 cur = 0;

	if (dest->size < src->len) {
		return 0;
	}

	while (cur < src->len && cur < dest->size) {
		*(dest->begin + cur) = *(src->begin + cur);
		cur++;
	}

	return cur;
}

/*
 * Concatenate two strings
 */
size_t
fstrcat (f_str_t * dest, f_str_t * src)
{
	register size_t                 cur = 0;
	gchar                           *p = dest->begin + dest->len;

	if (dest->size < src->len + dest->len) {
		return 0;
	}

	while (cur < src->len) {
		*p = *(src->begin + cur);
		p++;
		cur++;
	}

	dest->len += src->len;

	return cur;

}

/*
 * Make copy of string to 0-terminated string
 */
gchar                           *
fstrcstr (f_str_t * str, memory_pool_t * pool)
{
	gchar                           *res;
	res = memory_pool_alloc (pool, str->len + 1);

	memcpy (res, str->begin, str->len);
	res[str->len] = 0;

	return res;
}

/*
 * Push one character to fstr
 */
gint
fstrpush (f_str_t * dest, gchar c)
{
	if (dest->size < dest->len) {
		/* Need to reallocate string */
		return 0;
	}

	*(dest->begin + dest->len) = c;
	dest->len++;
	return 1;
}

/*
 * Push one character to fstr
 */
gint
fstrpush_unichar (f_str_t * dest, gunichar c)
{
	int                            l;
	if (dest->size < dest->len) {
		/* Need to reallocate string */
		return 0;
	}

	l = g_unichar_to_utf8 (c, dest->begin + dest->len);
	dest->len += l;
	return l;
}

/*
 * Allocate memory for f_str_t
 */
f_str_t                        *
fstralloc (memory_pool_t * pool, size_t len)
{
	f_str_t                        *res = memory_pool_alloc (pool, sizeof (f_str_t));

	res->begin = memory_pool_alloc (pool, len);

	res->size = len;
	res->len = 0;
	return res;
}

/*
 * Allocate memory for f_str_t from temporary pool
 */
f_str_t                        *
fstralloc_tmp (memory_pool_t * pool, size_t len)
{
	f_str_t                        *res = memory_pool_alloc_tmp (pool, sizeof (f_str_t));

	res->begin = memory_pool_alloc_tmp (pool, len);

	res->size = len;
	res->len = 0;
	return res;
}

/*
 * Truncate string to its len
 */
f_str_t                        *
fstrtruncate (memory_pool_t * pool, f_str_t * orig)
{
	f_str_t                        *res;

	if (orig == NULL || orig->len == 0 || orig->size <= orig->len) {
		return orig;
	}

	res = fstralloc (pool, orig->len);
	if (res == NULL) {
		return NULL;
	}
	fstrcpy (res, orig);

	return res;
}

/*
 * Enlarge string to new size
 */
f_str_t                        *
fstrgrow (memory_pool_t * pool, f_str_t * orig, size_t newlen)
{
	f_str_t                        *res;

	if (orig == NULL || orig->len == 0 || orig->size >= newlen) {
		return orig;
	}

	res = fstralloc (pool, newlen);
	if (res == NULL) {
		return NULL;
	}
	fstrcpy (res, orig);

	return res;
}

static guint32
fstrhash_c (gchar c, guint32 hval)
{
	guint32                         tmp;
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
fstrhash (f_str_t * str)
{
	size_t                          i;
	guint32                         hval;
	gchar                           *c = str->begin;

	if (str == NULL) {
		return 0;
	}
	hval = str->len;

	for (i = 0; i < str->len; i++, c++) {
		hval = fstrhash_c (*c, hval);
	}
	return hval;
}

/*
 * Return hash value for a string
 */
guint32
fstrhash_lowercase (f_str_t * str, gboolean is_utf)
{
	gsize                           i;
	guint32                         j, hval;
	const gchar                    *p = str->begin, *end = NULL;
	gchar                           t;
	gunichar                        uc;

	if (str == NULL) {
		return 0;
	}
	hval = str->len;

	if (is_utf) {
		while (end < str->begin + str->len) {
			g_utf8_validate (p, str->len, &end);
			while (p < end) {
				uc = g_unichar_tolower (g_utf8_get_char (p));
				for (j = 0; j < sizeof (gunichar); j ++) {
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

void
fstrstrip (f_str_t * str)
{
	gchar                           *p = str->begin;
	guint                            r = 0;

	while (r < str->len) {
		if (g_ascii_isspace (*p)) {
			p++;
			r++;
		}
		else {
			break;
		}
	}

	if (r > 0) {
		memmove (str->begin, p, str->len - r);
		str->len -= r;
	}

	r = str->len;
	p = str->begin + str->len;
	while (r > 0) {
		if (g_ascii_isspace (*p)) {
			p--;
			r--;
		}
		else {
			break;
		}
	}

	str->len = r;
}
