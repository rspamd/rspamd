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


#include "config.h"
#include "mem_pool.h"
#include "fstring.h"
#include "fuzzy.h"

#define ROLL_WINDOW_SIZE 9
#define MIN_FUZZY_BLOCK_SIZE 3
#define HASH_INIT      0x28021967

struct roll_state {
	uint32_t                        h[3];
	char                            window[ROLL_WINDOW_SIZE];
	int                             n;
};

static struct roll_state        rs;


/* Rolling hash function based on Adler-32 checksum */
static                          uint32_t
fuzzy_roll_hash (char c)
{
	/* Check window position */
	if (rs.n == ROLL_WINDOW_SIZE) {
		rs.n = 0;
	}

	rs.h[1] -= rs.h[0];
	rs.h[1] += ROLL_WINDOW_SIZE * c;

	rs.h[0] += c;
	rs.h[0] -= rs.window[rs.n];

	/* Save current symbol */
	rs.window[rs.n] = c;
	rs.n++;

	rs.h[2] <<= 5;
	rs.h[2] ^= c;

	return rs.h[0] + rs.h[1] + rs.h[2];
}

/* A simple non-rolling hash, based on the FNV hash */
static                          uint32_t
fuzzy_fnv_hash (char c, uint32_t hval)
{
	hval ^= c;
	hval += (hval << 1) + (hval << 4) + (hval << 7) + (hval << 8) + (hval << 24);
	return hval;
}

/* Calculate blocksize depending on length of input */
static                          uint32_t
fuzzy_blocksize (uint32_t len)
{

	if (len < MIN_FUZZY_BLOCK_SIZE) {
		return MIN_FUZZY_BLOCK_SIZE;
	}
	return g_spaced_primes_closest (len / FUZZY_HASHLEN);
}

/* Update hash with new symbol */
void
fuzzy_update (fuzzy_hash_t * h, char c)
{
	h->rh = fuzzy_roll_hash (c);
	h->h = fuzzy_fnv_hash (c, h->h);

	if (h->rh % h->block_size == (h->block_size - 1)) {
		h->hash_pipe[h->hi] = h->h;
		if (h->hi < FUZZY_HASHLEN - 2) {
			h->h = HASH_INIT;
			h->hi++;
		}
	}
}

/*
 * Levenshtein distance between string1 and string2.
 *
 * Replace cost is normally 1, and 2 with nonzero xcost.
 */
uint32_t
lev_distance (char *s1, int len1, char *s2, int len2)
{
	int                             i;
	int                            *row;	/* we only need to keep one row of costs */
	int                            *end;
	int                             half, nx;
	char                           *sx, *char2p, char1;
	int                            *p, D, x, offset, c3;

	/* strip common prefix */
	while (len1 > 0 && len2 > 0 && *s1 == *s2) {
		len1--;
		len2--;
		s1++;
		s2++;
	}

	/* strip common suffix */
	while (len1 > 0 && len2 > 0 && s1[len1 - 1] == s2[len2 - 1]) {
		len1--;
		len2--;
	}

	/* catch trivial cases */
	if (len1 == 0) {
		return len2;
	}

	if (len2 == 0) {
		return len1;
	}

	/* make the inner cycle (i.e. string2) the longer one */
	if (len1 > len2) {
		nx = len1;
		sx = s1;
		len1 = len2;
		len2 = nx;
		s1 = s2;
		s2 = sx;
	}
	/* check len1 == 1 separately */
	if (len1 == 1) {
		return len2 - (memchr (s2, *s1, len2) != NULL);
	}

	len1++;
	len2++;
	half = len1 >> 1;

	/* initalize first row */
	row = g_malloc (len2 * sizeof (int));
	end = row + len2 - 1;
	for (i = 0; i < len2; i++) {
		row[i] = i;
	}

	/* in this case we don't have to scan two corner triangles (of size len1/2)
	 * in the matrix because no best path can go throught them. note this
	 * breaks when len1 == len2 == 2 so the memchr() special case above is
	 * necessary */
	row[0] = len1 - half - 1;
	for (i = 1; i < len1; i++) {
		char1 = s1[i - 1];
		/* skip the upper triangle */
		if (i >= len1 - half) {
			offset = i - (len1 - half);
			char2p = s2 + offset;
			p = row + offset;
			c3 = *(p++) + (char1 != *(char2p++));
			x = *p;
			x++;
			D = x;
			if (x > c3)
				x = c3;
			*(p++) = x;
		}
		else {
			p = row + 1;
			char2p = s2;
			D = x = i;
		}
		/* skip the lower triangle */
		if (i <= half + 1)
			end = row + len2 + i - half - 2;
		/* main */
		while (p <= end) {
			c3 = --D + (char1 != *(char2p++));
			x++;
			if (x > c3)
				x = c3;
			D = *p;
			D++;
			if (x > D)
				x = D;
			*(p++) = x;
		}
		/* lower triangle sentinel */
		if (i <= half) {
			c3 = --D + (char1 != *char2p);
			x++;
			if (x > c3)
				x = c3;
			*p = x;
		}
	}

	i = *end;
	g_free (row);
	return i;
}

/* Calculate fuzzy hash for specified string */
fuzzy_hash_t                   *
fuzzy_init (f_str_t * in, memory_pool_t * pool)
{
	fuzzy_hash_t                   *new;
	int                             i, repeats = 0;
	char                           *c = in->begin, last = '\0';

	new = memory_pool_alloc0 (pool, sizeof (fuzzy_hash_t));
	bzero (&rs, sizeof (rs));
	new->block_size = fuzzy_blocksize (in->len);

	for (i = 0; i < in->len; i++) {
		if (*c == last) {
			repeats++;
		}
		else {
			repeats = 0;
		}
		if (!g_ascii_isspace (*c) && !g_ascii_ispunct (*c) && repeats < 3) {
			fuzzy_update (new, *c);
		}
		last = *c;
		c++;
	}

	return new;
}

fuzzy_hash_t                   *
fuzzy_init_byte_array (GByteArray * in, memory_pool_t * pool)
{
	f_str_t                         f;

	f.begin = in->data;
	f.len = in->len;

	return fuzzy_init (&f, pool);
}

/* Compare score of difference between two hashes 0 - different hashes, 100 - identical hashes */
int
fuzzy_compare_hashes (fuzzy_hash_t * h1, fuzzy_hash_t * h2)
{
	int                             res, l1, l2;

	/* If we have hashes of different size, input strings are too different */
	if (h1->block_size != h2->block_size) {
		return 0;
	}

	l1 = strlen (h1->hash_pipe);
	l2 = strlen (h2->hash_pipe);

	if (l1 == 0 || l2 == 0) {
		return 0;
	}

	res = lev_distance (h1->hash_pipe, l1, h2->hash_pipe, l2);
	res = 100 - (2 * res * 100) / (l1 + l2);

	return res;
}

/* 
 * vi:ts=4 
 */
