/*
 * Copyright (c) 2009, Rambler media
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
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
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
fstrchr (f_str_t *src, char c)
{
	register ssize_t cur = 0;

	while (cur < src->len) {
		if (*(src->begin + cur) == c) {
			return cur;
		}
		cur ++;
	}

	return -1;
}

/*
 * Search last occurence of character in string
 */
ssize_t
fstrrchr (f_str_t *src, char c)
{
	register ssize_t cur = src->len;

	while (cur > 0) {
		if (*(src->begin + cur) == c) {
			return cur;
		}
		cur --;
	}

	return -1;
}

/*
 * Search for pattern in orig
 */
ssize_t
fstrstr (f_str_t *orig, f_str_t *pattern)
{
	register ssize_t cur = 0, pcur = 0;

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
				cur ++;
				pcur ++;
			}
			return cur - pattern->len;
		}
		cur ++;
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
int
fstrtok (f_str_t *text, const char *sep, f_tok_t *state)
{
	register size_t cur;
	const char *csep = sep;

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
			csep ++;
		}
		csep = sep;
		cur ++;
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
fstrcpy (f_str_t *dest, f_str_t *src)
{
	register size_t cur = 0;

	if (dest->size < src->len) {
		return 0;
	}

	while (cur < src->len && cur < dest->size) {
		*(dest->begin + cur) = *(src->begin + cur);
		cur ++;
	}

	return cur;
}

/*
 * Concatenate two strings
 */
size_t
fstrcat (f_str_t *dest, f_str_t *src)
{
	register size_t cur = src->len;

	if (dest->size < src->len + dest->len) {
		return 0;
	}

	while (cur < src->len && cur < dest->size) {
		*(dest->begin + cur) = *(src->begin + cur);
		cur ++;
	}

	dest->len += src->len;

	return cur;

}

/*
 * Make copy of string to 0-terminated string
 */
char* 
fstrcstr (f_str_t *str, memory_pool_t *pool)
{
	char *res;
	res = memory_pool_alloc (pool, str->len + 1);

	memcpy (res, str->begin, str->len);
	res[str->len] = 0;

	return res;
}

/*
 * Push one character to fstr
 */
int
fstrpush (f_str_t *dest, char c)
{
	if (dest->size < dest->len) {
		/* Need to reallocate string */
		return 0;
	}

	*(dest->begin + dest->len) = c;
	dest->len ++;
	return 1;
}

/*
 * Allocate memory for f_str_t
 */
f_str_t*
fstralloc (memory_pool_t *pool, size_t len)
{
	f_str_t *res = memory_pool_alloc (pool, sizeof (f_str_t));

	if (res == NULL) {
		return NULL;
	}
	res->begin = memory_pool_alloc (pool, len);
	if (res->begin == NULL) {
		free (res);
		return NULL;
	}

	res->size = len;
    res->len = 0;
	return res;
}

/*
 * Truncate string to its len
 */
f_str_t*
fstrtruncate (memory_pool_t *pool, f_str_t *orig)
{
	f_str_t *res;

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
f_str_t*
fstrgrow (memory_pool_t *pool, f_str_t *orig, size_t newlen)
{
	f_str_t *res;

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

/*
 * Return hash value for a string
 */
uint32_t
fstrhash (f_str_t *str)
{
	size_t i;
	uint32_t hval;
	uint32_t tmp;

	if (str == NULL) {
		return 0;
	}
	hval = str->len;

	for	(i = 0; i < str->len; i++) {
		/* 
		 * xor in the current byte against each byte of hval
		 * (which alone gaurantees that every bit of input will have
		 * an effect on the output)
		 */
		tmp = *(str->begin + i) & 0xFF;
		tmp = tmp | (tmp << 8) | (tmp << 16) | (tmp << 24);
		hval ^= tmp;

		/* add some bits out of the middle as low order bits */
		hval = hval + ((hval >> 12) & 0x0000ffff) ;

		/* swap most and min significative bytes */
		tmp = (hval << 24) | ((hval >> 24) & 0xff);
		/* zero most and min significative bytes of hval */
		hval &= 0x00ffff00;
		hval |= tmp;
		/*
		 * rotate hval 3 bits to the left (thereby making the
		 * 3rd msb of the above mess the hsb of the output hash)
		 */
		hval = (hval << 3) + (hval >> 29);
	}
	return hval;
}
