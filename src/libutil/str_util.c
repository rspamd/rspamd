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
#include "util.h"
#include "cryptobox.h"
#include "url.h"
#include "str_util.h"
#include "logger.h"
#include "contrib/t1ha/t1ha.h"
#include <unicode/uversion.h>
#include <unicode/ucnv.h>
#if U_ICU_VERSION_MAJOR_NUM >= 44
#include <unicode/unorm2.h>
#endif
#include <math.h>

#ifdef __x86_64__
#include <immintrin.h>
#endif

#include "contrib/fastutf8/fastutf8.h"

const guchar lc_map[256] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
		0x40, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
		0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
		0x78, 0x79, 0x7a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
		0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
		0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
		0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
		0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
		0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
		0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
		0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
		0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
		0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
		0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
		0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

guint
rspamd_str_lc (gchar *str, guint size)
{
	guint leftover = size % 4;
	guint fp, i;
	const uint8_t* s = (const uint8_t*) str;
	gchar *dest = str;
	guchar c1, c2, c3, c4;

	fp = size - leftover;

	for (i = 0; i != fp; i += 4) {
		c1 = s[i], c2 = s[i + 1], c3 = s[i + 2], c4 = s[i + 3];
		dest[0] = lc_map[c1];
		dest[1] = lc_map[c2];
		dest[2] = lc_map[c3];
		dest[3] = lc_map[c4];
		dest += 4;
	}

	switch (leftover) {
	case 3:
		*dest++ = lc_map[(guchar)str[i++]];
		/* FALLTHRU */
	case 2:
		*dest++ = lc_map[(guchar)str[i++]];
		/* FALLTHRU */
	case 1:
		*dest = lc_map[(guchar)str[i]];
	}

	return size;
}

gsize
rspamd_str_copy_lc (const gchar *src, gchar *dst, gsize size)
{
	gchar *d = dst;

	/* Find aligned start */
	while ((0xf & (uintptr_t)src) && size > 0) {
		*d++ = lc_map[(guchar)*src++];
		size --;
	}

	/* Aligned start in src */
#ifdef __x86_64__
	while (size >= 16) {
		__m128i sv = _mm_load_si128((const __m128i*)src);
		/* From A */
		__m128i rangeshift = _mm_sub_epi8(sv, _mm_set1_epi8((char)('A'+128)));
		/* To Z */
		__m128i nomodify = _mm_cmpgt_epi8(rangeshift, _mm_set1_epi8(-128 + 25));
		/* ^ ' ' */
		__m128i flip  = _mm_andnot_si128(nomodify, _mm_set1_epi8(0x20));
		__m128i uc = _mm_xor_si128(sv, flip);
		_mm_storeu_si128((__m128i*)d, uc);
		d += 16;
		src += 16;
		size -= 16;
	}
#endif

	/* Leftover */
	while (size > 0) {
		*d++ = lc_map[(guchar)*src++];
		size --;
	}

	return (d - dst);
}

gint
rspamd_lc_cmp (const gchar *s, const gchar *d, gsize l)
{
	gsize fp, i;
	guchar c1, c2, c3, c4;
	union {
		guchar c[4];
		guint32 n;
	} cmp1, cmp2;
	gsize leftover = l % 4;
	gint ret = 0;

	fp = l - leftover;

	for (i = 0; i != fp; i += 4) {
		c1 = s[i], c2 = s[i + 1], c3 = s[i + 2], c4 = s[i + 3];
		cmp1.c[0] = lc_map[c1];
		cmp1.c[1] = lc_map[c2];
		cmp1.c[2] = lc_map[c3];
		cmp1.c[3] = lc_map[c4];

		c1 = d[i], c2 = d[i + 1], c3 = d[i + 2], c4 = d[i + 3];
		cmp2.c[0] = lc_map[c1];
		cmp2.c[1] = lc_map[c2];
		cmp2.c[2] = lc_map[c3];
		cmp2.c[3] = lc_map[c4];

		if (cmp1.n != cmp2.n) {
			return cmp1.n - cmp2.n;
		}
	}

	while (leftover > 0) {
		if (g_ascii_tolower (s[i]) != g_ascii_tolower (d[i])) {
			return s[i] - d[i];
		}

		leftover--;
		i++;
	}

	return ret;
}

/*
 * The purpose of this function is fast and in place conversion of a unicode
 * string to lower case, so some locale peculiarities are simply ignored
 * If the target string is longer than initial one, then we just trim it
 */
guint
rspamd_str_lc_utf8 (gchar *str, guint size)
{
	guchar *d = (guchar *)str, tst[6];
	gint32 i = 0, prev = 0;
	UChar32 uc;

	while (i < size) {
		prev = i;

		U8_NEXT ((guint8*)str, i, size, uc);
		uc = u_tolower (uc);

		gint32 olen = 0;
		U8_APPEND_UNSAFE (tst, olen, uc);

		if (olen <= (i - prev)) {
			memcpy (d, tst, olen);
			d += olen;
		}
		else {
			/* Lowercasing has increased the length, so we need to ignore it */
			d += i - prev;
		}
	}

	return d - (guchar *)str;
}

gboolean
rspamd_strcase_equal (gconstpointer v, gconstpointer v2)
{
	if (g_ascii_strcasecmp ((const gchar *)v, (const gchar *)v2) == 0) {
		return TRUE;
	}

	return FALSE;
}

guint64
rspamd_icase_hash (const gchar *in, gsize len, guint64 seed)
{
	guint leftover = len % sizeof (guint64);
	guint fp, i;
	const uint8_t* s = (const uint8_t*) in;
	union {
		struct {
			guchar c1, c2, c3, c4, c5, c6, c7, c8;
		} c;
		guint64 pp;
	} u;
	guint64 h = seed;

	fp = len - leftover;

	for (i = 0; i != fp; i += 8) {
		u.c.c1 = s[i], u.c.c2 = s[i + 1], u.c.c3 = s[i + 2], u.c.c4 = s[i + 3];
		u.c.c5 = s[i + 4], u.c.c6 = s[i + 5], u.c.c7 = s[i + 6], u.c.c8 = s[i + 7];
		u.c.c1 = lc_map[u.c.c1];
		u.c.c2 = lc_map[u.c.c2];
		u.c.c3 = lc_map[u.c.c3];
		u.c.c4 = lc_map[u.c.c4];
		u.c.c5 = lc_map[u.c.c5];
		u.c.c6 = lc_map[u.c.c6];
		u.c.c7 = lc_map[u.c.c7];
		u.c.c8 = lc_map[u.c.c8];
		h = t1ha (&u.pp, sizeof (u), h);
	}

	u.pp = 0;

	switch (leftover) {
	case 7:
		u.c.c7 = lc_map[(guchar)s[i++]]; /* FALLTHRU */
	case 6:
		u.c.c6 = lc_map[(guchar)s[i++]]; /* FALLTHRU */
	case 5:
		u.c.c5 = lc_map[(guchar)s[i++]]; /* FALLTHRU */
	case 4:
		u.c.c4 = lc_map[(guchar)s[i++]]; /* FALLTHRU */
	case 3:
		u.c.c3 = lc_map[(guchar)s[i++]]; /* FALLTHRU */
	case 2:
		u.c.c2 = lc_map[(guchar)s[i++]]; /* FALLTHRU */
	case 1:
		u.c.c1 = lc_map[(guchar)s[i]];
		break;
	}

	h = t1ha (&u.pp, sizeof (u), h);

	return h;
}

guint
rspamd_strcase_hash (gconstpointer key)
{
	const gchar *p = key;
	gsize len;

	len = strlen (p);

	return (guint)rspamd_icase_hash (p, len, rspamd_hash_seed ());
}

guint
rspamd_str_hash (gconstpointer key)
{
	gsize len;

	len = strlen ((const gchar *)key);

	return (guint)rspamd_cryptobox_fast_hash (key, len, rspamd_hash_seed ());
}

gboolean
rspamd_str_equal (gconstpointer v, gconstpointer v2)
{
	return strcmp ((const gchar *)v, (const gchar *)v2) == 0;
}

gboolean
rspamd_ftok_icase_equal (gconstpointer v, gconstpointer v2)
{
	const rspamd_ftok_t *f1 = v, *f2 = v2;

	if (f1->len == f2->len &&
			rspamd_lc_cmp (f1->begin, f2->begin, f1->len) == 0) {
		return TRUE;
	}

	return FALSE;
}


guint
rspamd_ftok_icase_hash (gconstpointer key)
{
	const rspamd_ftok_t *f = key;

	return (guint)rspamd_icase_hash (f->begin, f->len, rspamd_hash_seed ());
}

gboolean
rspamd_ftok_equal (gconstpointer v, gconstpointer v2)
{
	const rspamd_ftok_t *f1 = v, *f2 = v2;

	if (f1->len == f2->len &&
		memcmp (f1->begin, f2->begin, f1->len) == 0) {
		return TRUE;
	}

	return FALSE;
}

guint
rspamd_ftok_hash (gconstpointer key)
{
	const rspamd_ftok_t *f = key;

	return (guint)rspamd_cryptobox_fast_hash (f->begin, f->len, rspamd_hash_seed ());
}

gboolean
rspamd_gstring_icase_equal (gconstpointer v, gconstpointer v2)
{
	const GString *f1 = v, *f2 = v2;
	if (f1->len == f2->len &&
		rspamd_lc_cmp (f1->str, f2->str, f1->len) == 0) {
		return TRUE;
	}

	return FALSE;
}

guint
rspamd_gstring_icase_hash (gconstpointer key)
{
	const GString *f = key;

	return (guint)rspamd_icase_hash (f->str, f->len, rspamd_hash_seed ());
}

/* https://graphics.stanford.edu/~seander/bithacks.html#ZeroInWord */
#define MEM_ALIGN (sizeof(gsize)-1)
#if defined(__LP64__) || defined(_LP64)
#define WORD_TYPE guint64
#define ZEROMASK  0x7F7F7F7F7F7F7F7FLLU
#else
#define WORD_TYPE guint32
#define ZEROMASK  0x7F7F7F7FU
#endif

#define HASZERO(x) ~(((((x) & ZEROMASK) + ZEROMASK) | (x)) | ZEROMASK)

gsize
rspamd_strlcpy_fast (gchar *dst, const gchar *src, gsize siz)
{
	gchar *d = dst;
	const gchar *s = src;
	gsize n = siz;
	WORD_TYPE *wd;
	const WORD_TYPE *ws;

	/* Copy as many bytes as will fit */
	if (n-- != 0) {
		if (((uintptr_t) s & MEM_ALIGN) == ((uintptr_t) d & MEM_ALIGN)) {
			/* Init copy byte by byte */
			for (; ((uintptr_t) s & MEM_ALIGN) && n && (*d = *s); n--, s++, d++);
			if (n && *s) {
				wd = (void *) d;
				ws = (const void *) s;
				/*
				 * Copy by 32 or 64 bits (causes valgrind warnings)
				 */
				for (; n >= sizeof (WORD_TYPE) && !HASZERO(*ws);
					   n -= sizeof (WORD_TYPE), ws++, wd++) {
					*wd = *ws;
				}

				d = (void *) wd;
				s = (const void *) ws;
			}
		}

		/* Copy the rest */
		for (; n && (*d = *s); n--, s++, d++);

		*d = 0;
	}
	else {
		return 0;
	}

	return (d - dst);
}

gsize
rspamd_null_safe_copy (const gchar *src, gsize srclen,
					   gchar *dest, gsize destlen)
{
	gsize copied = 0, si = 0, di = 0;

	if (destlen == 0) {
		return 0;
	}

	while (si < srclen && di + 1 < destlen) {
		if (src[si] != '\0') {
			dest[di++] = src[si++];
			copied ++;
		}
		else {
			si ++;
		}
	}

	dest[di] = '\0';

	return copied;
}


size_t
rspamd_strlcpy_safe (gchar *dst, const gchar *src, gsize siz)
{
	gchar *d = dst;
	gsize nleft = siz;

	if (nleft != 0) {
		while (--nleft != 0) {
			if ((*d++ = *src++) == '\0') {
				d --;
				break;
			}
		}
	}

	if (nleft == 0) {
		if (siz != 0) {
			*d = '\0';
		}
	}

	return (d - dst);
}

/*
 * Try to convert string of length to long
 */
gboolean
rspamd_strtol (const gchar *s, gsize len, glong *value)
{
	const gchar *p = s, *end = s + len;
	gchar c;
	glong v = 0;
	const glong cutoff = G_MAXLONG / 10, cutlim = G_MAXLONG % 10;
	gboolean neg;

	/* Case negative values */
	if (*p == '-') {
		neg = TRUE;
		p++;
	}
	else {
		neg = FALSE;
	}
	/* Some preparations for range errors */

	while (p < end) {
		c = *p;
		if (c >= '0' && c <= '9') {
			c -= '0';
			if (v > cutoff || (v == cutoff && c > cutlim)) {
				/* Range error */
				*value = neg ? G_MINLONG : G_MAXLONG;
				return FALSE;
			}
			else {
				v *= 10;
				v += c;
			}
		}
		else {
			return FALSE;
		}
		p++;
	}

	*value = neg ? -(v) : v;
	return TRUE;
}

/*
 * Try to convert string of length to long
 */
#define CONV_STR_LIM_DECIMAL(max_num) do { \
    while (p < end) { \
        c = *p; \
        if (c >= '0' && c <= '9') { \
            c -= '0'; \
            if (v > cutoff || (v == cutoff && (guint8)c > cutlim)) { \
                *value = (max_num); \
                return FALSE; \
            } \
            else { \
                v *= 10; \
                v += c; \
            } \
        } \
        else { \
            *value = v; \
            return FALSE; \
        } \
    p++; \
    } \
} while(0)

gboolean
rspamd_strtoul (const gchar *s, gsize len, gulong *value)
{
	const gchar *p = s, *end = s + len;
	gchar c;
	gulong v = 0;
	const gulong cutoff = G_MAXULONG / 10, cutlim = G_MAXULONG % 10;

	/* Some preparations for range errors */
	CONV_STR_LIM_DECIMAL(G_MAXULONG);

	*value = v;
	return TRUE;
}

gboolean
rspamd_strtou64 (const gchar *s, gsize len, guint64 *value)
{
	const gchar *p = s, *end = s + len;
	gchar c;
	guint64 v = 0;
	const guint64 cutoff = G_MAXUINT64 / 10, cutlim = G_MAXUINT64 % 10;

	/* Some preparations for range errors */
	CONV_STR_LIM_DECIMAL(G_MAXUINT64);

	*value = v;
	return TRUE;
}

gboolean
rspamd_xstrtoul (const gchar *s, gsize len, gulong *value)
{
	const gchar *p = s, *end = s + len;
	gchar c;
	gulong v = 0;
	const gulong cutoff = G_MAXULONG / 10, cutlim = G_MAXULONG % 10;

	/* Some preparations for range errors */
	while (p < end) {
		c = g_ascii_tolower (*p);
		if (c >= '0' && c <= '9') {
			c -= '0';
			if (v > cutoff || (v == cutoff && (guint8)c > cutlim)) {
				/* Range error */
				*value = G_MAXULONG;
				return FALSE;
			}
			else {
				v *= 16;
				v += c;
			}
		}
		else if (c >= 'a' || c <= 'f') {
			c = c - 'a' + 10;
			if (v > cutoff || (v == cutoff && (guint8)c > cutlim)) {
				/* Range error */
				*value = G_MAXULONG;
				return FALSE;
			}
			else {
				v *= 16;
				v += c;
			}
		}
		else {
			*value = v;

			return FALSE;
		}
		p++;
	}

	*value = v;
	return TRUE;
}

/**
 * Utility function to provide mem_pool copy for rspamd_hash_table_copy function
 * @param data string to copy
 * @param ud memory pool to use
 * @return
 */
gpointer
rspamd_str_pool_copy (gconstpointer data, gpointer ud)
{
	rspamd_mempool_t *pool = ud;

	return data ? rspamd_mempool_strdup (pool, data) : NULL;
}

/*
 * We use here z-base32 encoding described here:
 * http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
 */

gint
rspamd_encode_base32_buf (const guchar *in, gsize inlen, gchar *out, gsize outlen,
		enum rspamd_base32_type type)
{
	static const char b32_default[] = "ybndrfg8ejkmcpqxot1uwisza345h769",
		b32_bleach[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l",
		b32_rfc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
		*b32;
	gchar *o, *end;
	gsize i;
	gint remain = -1, x;
	bool inverse_order = true;

	end = out + outlen;
	o = out;

	switch (type) {
	case RSPAMD_BASE32_DEFAULT:
		b32 = b32_default;
		break;
	case RSPAMD_BASE32_BLEACH:
		b32 = b32_bleach;
		inverse_order = false;
		break;
	case RSPAMD_BASE32_RFC:
		b32 = b32_rfc;
		inverse_order = false;
		break;
	default:
		g_assert_not_reached ();
		abort ();
	}

	if (inverse_order) {
		/* Zbase32 as used in Rspamd */
		for (i = 0; i < inlen && o < end - 1; i++) {
			switch (i % 5) {
			case 0:
				/* 8 bits of input and 3 to remain */
				x = in[i];
				remain = in[i] >> 5;
				*o++ = b32[x & 0x1F];
				break;
			case 1:
				/* 11 bits of input, 1 to remain */
				x = remain | in[i] << 3;
				*o++ = b32[x & 0x1F];
				*o++ = b32[x >> 5 & 0x1F];
				remain = x >> 10;
				break;
			case 2:
				/* 9 bits of input, 4 to remain */
				x = remain | in[i] << 1;
				*o++ = b32[x & 0x1F];
				remain = x >> 5;
				break;
			case 3:
				/* 12 bits of input, 2 to remain */
				x = remain | in[i] << 4;
				*o++ = b32[x & 0x1F];
				*o++ = b32[x >> 5 & 0x1F];
				remain = x >> 10 & 0x3;
				break;
			case 4:
				/* 10 bits of output, nothing to remain */
				x = remain | in[i] << 2;
				*o++ = b32[x & 0x1F];
				*o++ = b32[x >> 5 & 0x1F];
				remain = -1;
				break;
			default:
				/* Not to be happen */
				break;
			}
		}
	}
	else {
		/* Traditional base32 with no bits inversion */
		for (i = 0; i < inlen && o < end - 1; i++) {
			switch (i % 5) {
			case 0:
				/* 8 bits of input and 3 to remain */
				x = in[i] >> 3;
				remain = (in[i] & 7) << 2;
				*o++ = b32[x & 0x1F];
				break;
			case 1:
				/* 11 bits of input, 1 to remain */
				x = (remain << 6) | in[i];
				*o++ = b32[(x >> 6) & 0x1F];
				*o++ = b32[(x >> 1) & 0x1F];
				remain = (x & 0x1) << 4;
				break;
			case 2:
				/* 9 bits of input, 4 to remain */
				x = (remain << 4) | in[i];
				*o++ = b32[(x >> 4) & 0x1F];
				remain = (x & 15) << 1;
				break;
			case 3:
				/* 12 bits of input, 2 to remain */
				x = (remain << 7) | in[i];
				*o++ = b32[(x >> 7) & 0x1F];
				*o++ = b32[(x >> 2) & 0x1F];
				remain = (x & 3) << 3;
				break;
			case 4:
				/* 10 bits of output, nothing to remain */
				x = (remain << 5) | in[i];
				*o++ = b32[(x >> 5) & 0x1F];
				*o++ = b32[x & 0x1F];
				remain = -1;
				break;
			default:
				/* Not to be happen */
				break;
			}
		}
	}
	if (remain >= 0 && o < end) {
		*o++ = b32[remain & 0x1F];
	}

	if (o <= end) {
		return (o - out);
	}

	return -1;
}

gchar *
rspamd_encode_base32 (const guchar *in, gsize inlen, enum rspamd_base32_type type)
{
	gsize allocated_len = inlen * 8 / 5 + 2;
	gchar *out;
	gint outlen;

	out = g_malloc (allocated_len);
	outlen = rspamd_encode_base32_buf (in, inlen, out,
			allocated_len - 1, type);

	if (outlen >= 0) {
		out[outlen] = 0;

		return out;
	}

	g_free (out);

	return NULL;
}

enum rspamd_base32_type
rspamd_base32_decode_type_from_str (const gchar *str)
{
	enum rspamd_base32_type ret = RSPAMD_BASE32_INVALID;

	if (str == NULL) {
		return RSPAMD_BASE32_DEFAULT;
	}

	if (strcmp (str, "default") == 0 || strcmp (str, "zbase") == 0) {
		ret = RSPAMD_BASE32_ZBASE;
	}
	else if (strcmp (str, "bleach") == 0) {
		ret = RSPAMD_BASE32_BLEACH;
	}
	else if (strcmp (str, "rfc") == 0) {
		ret = RSPAMD_BASE32_RFC;
	}

	return ret;
}

static const guchar b32_dec_zbase[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0x12, 0xff, 0x19, 0x1a, 0x1b, 0x1e, 0x1d,
		0x07, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0x18, 0x01, 0x0c, 0x03, 0x08, 0x05, 0x06,
		0x1c, 0x15, 0x09, 0x0a, 0xff, 0x0b, 0x02, 0x10,
		0x0d, 0x0e, 0x04, 0x16, 0x11, 0x13, 0xff, 0x14,
		0x0f, 0x00, 0x17, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
static const guchar b32_dec_bleach[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x0f, 0xff, 0x0a, 0x11, 0x15, 0x14, 0x1a, 0x1e,
		0x07, 0x05, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0x1d, 0xff, 0x18, 0x0d, 0x19, 0x09, 0x08,
		0x17, 0xff, 0x12, 0x16, 0x1f, 0x1b, 0x13, 0xff,
		0x01, 0x00, 0x03, 0x10, 0x0b, 0x1c, 0x0c, 0x0e,
		0x06, 0x04, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
static const guchar b32_dec_rfc[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
		0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
		0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};


gint
rspamd_decode_base32_buf (const gchar *in, gsize inlen, guchar *out, gsize outlen,
		enum rspamd_base32_type type)
{
	guchar *o, *end, decoded;
	guchar c;
	guint acc = 0U;
	guint processed_bits = 0;
	gsize i;
	const guchar *b32_dec;
	bool inverse_bits = true;

	end = out + outlen;
	o = out;

	switch (type) {
	case RSPAMD_BASE32_DEFAULT:
		b32_dec = b32_dec_zbase;
		break;
	case RSPAMD_BASE32_BLEACH:
		b32_dec = b32_dec_bleach;
		inverse_bits = false;
		break;
	case RSPAMD_BASE32_RFC:
		b32_dec = b32_dec_rfc;
		inverse_bits = false;
		break;
	default:
		g_assert_not_reached ();
		abort ();
	}

	if (inverse_bits) {
		for (i = 0; i < inlen; i++) {
			c = (guchar) in[i];

			if (processed_bits >= 8) {
				/* Emit from left to right */
				processed_bits -= 8;
				*o++ = acc & 0xFF;
				acc >>= 8;
			}

			decoded = b32_dec[c];
			if (decoded == 0xff || o >= end) {
				return -1;
			}

			acc = (decoded << processed_bits) | acc;
			processed_bits += 5;
		}

		if (processed_bits > 0 && o < end) {
			*o++ = (acc & 0xFF);
		}
		else if (o > end) {
			return -1;
		}
	}
	else {
		for (i = 0; i < inlen; i++) {
			c = (guchar) in[i];

			decoded = b32_dec[c];
			if (decoded == 0xff) {
				return -1;
			}

			acc = (acc << 5) | decoded;
			processed_bits += 5;

			if (processed_bits >= 8) {
				/* Emit from right to left */
				processed_bits -= 8;

				/* Output buffer overflow */
				if (o >= end) {
					return -1;
				}

				*o++ = (acc >> processed_bits) & 0xFF;
				/* Preserve lowers at the higher parts of the input */
				acc = (acc & ((1u << processed_bits) - 1));
			}
		}

		if (processed_bits > 0 && o < end) {
			*o++ = (acc & 0xFF);
		}
		else if (o > end) {
			return -1;
		}
	}

	return (o - out);
}

guchar *
rspamd_decode_base32 (const gchar *in, gsize inlen, gsize *outlen,
		enum rspamd_base32_type type)
{
	guchar *res;

	gsize allocated_len = inlen * 5 / 8 + 2;
	gssize olen;

	res = g_malloc (allocated_len);

	olen = rspamd_decode_base32_buf (in, inlen, res, allocated_len - 1,
			type);

	if (olen >= 0) {
		res[olen] = '\0';
	}
	else {
		g_free (res);

		if (outlen) {
			*outlen = 0;
		}

		return NULL;
	}

	if (outlen) {
		*outlen = olen;
	}

	return res;
}


gchar *
rspamd_encode_base64_common (const guchar *in, gsize inlen, gint str_len,
		gsize *outlen, gboolean fold, enum rspamd_newlines_type how)
{
#define ADD_SPLIT do { \
	if (how == RSPAMD_TASK_NEWLINES_CR || how == RSPAMD_TASK_NEWLINES_CRLF) *o++ = '\r'; \
	if (how == RSPAMD_TASK_NEWLINES_LF || how == RSPAMD_TASK_NEWLINES_CRLF) *o++ = '\n'; \
	if (fold) *o++ = '\t'; \
} while (0)
#define CHECK_SPLIT \
	do { if (str_len > 0 && cols >= str_len) { \
		ADD_SPLIT; \
		cols = 0; \
	} } \
while (0)

	gsize allocated_len = (inlen / 3) * 4 + 5;
	gchar *out, *o;
	guint64 n;
	guint32 rem, t, carry;
	gint cols, shift;
	static const char b64_enc[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";

	if (str_len > 0) {
		g_assert (str_len > 8);
		if (fold) {
			switch (how) {
			case RSPAMD_TASK_NEWLINES_CR:
			case RSPAMD_TASK_NEWLINES_LF:
				allocated_len += (allocated_len / str_len + 1) * 2 + 1;
				break;
			default:
				allocated_len += (allocated_len / str_len + 1) * 3 + 1;
				break;
			}
		}
		else {
			switch (how) {
			case RSPAMD_TASK_NEWLINES_CR:
			case RSPAMD_TASK_NEWLINES_LF:
				allocated_len += (allocated_len / str_len + 1) * 1 + 1;
				break;
			default:
				allocated_len += (allocated_len / str_len + 1) * 2 + 1;
				break;
			}
		}
	}

	out = g_malloc (allocated_len);
	o = out;
	cols = 0;

	while (inlen > 6) {
		memcpy (&n, in, sizeof (n));
		n = GUINT64_TO_BE (n);

		if (str_len <= 0 || cols <= str_len - 8) {
			*o++ = b64_enc[(n >> 58) & 0x3F];
			*o++ = b64_enc[(n >> 52) & 0x3F];
			*o++ = b64_enc[(n >> 46) & 0x3F];
			*o++ = b64_enc[(n >> 40) & 0x3F];
			*o++ = b64_enc[(n >> 34) & 0x3F];
			*o++ = b64_enc[(n >> 28) & 0x3F];
			*o++ = b64_enc[(n >> 22) & 0x3F];
			*o++ = b64_enc[(n >> 16) & 0x3F];
			cols += 8;
		}
		else {
			cols = str_len - cols;
			shift = 58;
			while (cols) {
				*o++ = b64_enc[(n >> shift) & 0x3F];
				shift -= 6;
				cols --;
			}

			ADD_SPLIT;

			/* Remaining bytes */
			while (shift >= 16) {
				*o++ = b64_enc[(n >> shift) & 0x3F];
				shift -= 6;
				cols ++;
			}
		}

		in += 6;
		inlen -= 6;
	}

	CHECK_SPLIT;

	rem = 0;
	carry = 0;

	for (;;) {
		/* Padding + remaining data (0 - 2 bytes) */
		switch (rem) {
		case 0:
			if (inlen-- == 0) {
				goto end;
			}
			t = *in++;
			*o++ = b64_enc[t >> 2];
			carry = (t << 4) & 0x30;
			rem = 1;
			cols ++;
		case 1:
			if (inlen-- == 0) {
				goto end;
			}
			CHECK_SPLIT;
			t = *in++;
			*o++ = b64_enc[carry | (t >> 4)];
			carry = (t << 2) & 0x3C;
			rem = 2;
			cols ++;
		default:
			if (inlen-- == 0) {
				goto end;
			}
			CHECK_SPLIT;
			t = *in ++;
			*o++ = b64_enc[carry | (t >> 6)];
			cols ++;
			CHECK_SPLIT;
			*o++ = b64_enc[t & 0x3F];
			cols ++;
			CHECK_SPLIT;
			rem = 0;
		}
	}

end:
	if (rem == 1) {
		*o++ = b64_enc[carry];
		cols ++;
		CHECK_SPLIT;
		*o++ = '=';
		cols ++;
		CHECK_SPLIT;
		*o++ = '=';
		cols ++;
		CHECK_SPLIT;
	}
	else if (rem == 2) {
		*o++ = b64_enc[carry];
		cols ++;
		CHECK_SPLIT;
		*o++ = '=';
		cols ++;
	}

	CHECK_SPLIT;

	*o = '\0';

	if (outlen != NULL) {
		*outlen = o - out;
	}

	return out;
}

gchar *
rspamd_encode_base64 (const guchar *in, gsize inlen, gint str_len,
		gsize *outlen)
{
	return rspamd_encode_base64_common (in, inlen, str_len, outlen, FALSE,
			RSPAMD_TASK_NEWLINES_CRLF);
}

gchar *
rspamd_encode_base64_fold (const guchar *in, gsize inlen, gint str_len,
		gsize *outlen, enum rspamd_newlines_type how)
{
	return rspamd_encode_base64_common (in, inlen, str_len, outlen, TRUE, how);
}

#define QP_RANGE(x) (((x) >= 33 && (x) <= 60) || ((x) >= 62 && (x) <= 126) \
		|| (x) == '\r' || (x) == '\n' || (x) == ' ' || (x) == '\t')
#define QP_SPAN_NORMAL(span, str_len) ((str_len) > 0 && \
		((span) + 1) >= (str_len))
#define QP_SPAN_SPECIAL(span, str_len) ((str_len) > 0 && \
		((span) + 4) >= (str_len))

gchar *
rspamd_encode_qp_fold (const guchar *in, gsize inlen, gint str_len,
						   gsize *outlen, enum rspamd_newlines_type how)
{
	gsize olen = 0, span = 0, i = 0, seen_spaces = 0;
	gchar *out;
	gint ch, last_sp;
	const guchar *end = in + inlen, *p = in;
	static const gchar hexdigests[16] = "0123456789ABCDEF";

	while (p < end) {
		ch = *p;

		if (QP_RANGE(ch)) {
			olen ++;
			span ++;

			if (ch == '\r' || ch == '\n') {
				if (seen_spaces > 0) {
					/* We must encode spaces at the end of line */
					olen += 3;
					seen_spaces = 0;
					/* Special stuff for space character at the end */
					if (QP_SPAN_SPECIAL(span, str_len)) {
						if (how == RSPAMD_TASK_NEWLINES_CRLF) {
							/* =\r\n */
							olen += 3;
						}
						else {
							olen += 2;
						}
					}
					/* Continue with the same `ch` but without spaces logic */
					continue;
				}

				span = 0;
			}
			else if (ch == ' ' || ch == '\t') {
				seen_spaces ++;
				last_sp = ch;
			}
			else {
				seen_spaces = 0;
			}
		}
		else {
			if (QP_SPAN_SPECIAL(span, str_len)) {
				if (how == RSPAMD_TASK_NEWLINES_CRLF) {
					/* =\r\n */
					olen += 3;
				}
				else {
					olen += 2;
				}
				span = 0;
			}

			olen += 3;
			span += 3;
		}

		if (QP_SPAN_NORMAL(span, str_len)) {
			if (how == RSPAMD_TASK_NEWLINES_CRLF) {
				/* =\r\n */
				olen += 3;
			}
			else {
				olen += 2;
			}
			span = 0;
		}

		p ++;
	}

	if (seen_spaces > 0) {
		/* Reserve length for the last space encoded */
		olen += 3;
	}

	out = g_malloc (olen + 1);
	p = in;
	i = 0;
	span = 0;
	seen_spaces = 0;

	while (p < end) {
		ch = *p;

		if (QP_RANGE (ch)) {
			if (ch == '\r' || ch == '\n') {
				if (seen_spaces > 0) {
					if (QP_SPAN_SPECIAL(span, str_len)) {
						/* Add soft newline */
						i --;

						if (p + 1 < end || span + 3 >= str_len) {
							switch (how) {
							default:
							case RSPAMD_TASK_NEWLINES_CRLF:
								out[i++] = '=';
								out[i++] = '\r';
								out[i++] = '\n';
								break;
							case RSPAMD_TASK_NEWLINES_LF:
								out[i++] = '=';
								out[i++] = '\n';
								break;
							case RSPAMD_TASK_NEWLINES_CR:
								out[i++] = '=';
								out[i++] = '\r';
								break;
							}
						}

						/* Now write encoded `last_sp` but after newline */
						out[i++] = '=';
						out[i++] = hexdigests[((last_sp >> 4) & 0xF)];
						out[i++] = hexdigests[(last_sp & 0xF)];

						span = 0;
					}
					else {
						/* Encode last space */
						--i;
						out[i++] = '=';
						out[i++] = hexdigests[((last_sp >> 4) & 0xF)];
						out[i++] = hexdigests[(last_sp & 0xF)];
						seen_spaces = 0;
					}

					continue;
				}
				span = 0;
			}
			else if (ch == ' ' || ch == '\t') {
				seen_spaces ++;
				last_sp = ch;
				span ++;
			}
			else {
				seen_spaces = 0;
				span ++;
			}

			out[i++] = ch;
		}
		else {
			if (QP_SPAN_SPECIAL(span, str_len)) {
				/* Add new line and then continue */
				if (p + 1 < end || span + 3 >= str_len) {
					switch (how) {
					default:
					case RSPAMD_TASK_NEWLINES_CRLF:
						out[i++] = '=';
						out[i++] = '\r';
						out[i++] = '\n';
						break;
					case RSPAMD_TASK_NEWLINES_LF:
						out[i++] = '=';
						out[i++] = '\n';
						break;
					case RSPAMD_TASK_NEWLINES_CR:
						out[i++] = '=';
						out[i++] = '\r';
						break;
					}
					span = 0;
				}
			}

			out[i++] = '=';
			out[i++] = hexdigests[((ch >> 4) & 0xF)];
			out[i++] = hexdigests[(ch & 0xF)];
			span += 3;
			seen_spaces = 0;
		}

		if (QP_SPAN_NORMAL(span, str_len)) {
			/* Add new line and then continue */
			if (p + 1 < end || span > str_len || seen_spaces) {
				switch (how) {
				default:
				case RSPAMD_TASK_NEWLINES_CRLF:
					out[i++] = '=';
					out[i++] = '\r';
					out[i++] = '\n';
					break;
				case RSPAMD_TASK_NEWLINES_LF:
					out[i++] = '=';
					out[i++] = '\n';
					break;
				case RSPAMD_TASK_NEWLINES_CR:
					out[i++] = '=';
					out[i++] = '\r';
					break;
				}
				span = 0;
				seen_spaces = 0;
			}
		}

		g_assert (i <= olen);
		p ++;
	}

	/* Deal with the last space character */
	if (seen_spaces > 0) {
		i --;
		out[i++] = '=';
		out[i++] = hexdigests[((last_sp >> 4) & 0xF)];
		out[i++] = hexdigests[(last_sp & 0xF)];
	}

	out[i] = '\0';

	if (outlen) {
		*outlen = i;
	}

	return out;
}

#define MIN3(a, b, c) ((a) < (b) ? ((a) < (c) ? (a) : (c)) : ((b) < (c) ? (b) : (c)))

gint
rspamd_strings_levenshtein_distance (const gchar *s1, gsize s1len,
		const gchar *s2, gsize s2len,
		guint replace_cost)
{
	gchar c1, c2, last_c2, last_c1;
	static GArray *current_row = NULL, *prev_row = NULL, *transp_row = NULL;
	gint eq;
	static const guint max_cmp = 8192;
	gint ret;

	g_assert (s1 != NULL);
	g_assert (s2 != NULL);

	if (s1len == 0) {
		s1len = strlen (s1);
	}
	if (s2len == 0) {
		s2len = strlen (s2);
	}

	if (MAX(s1len, s2len) > max_cmp) {
		/* Cannot compare too many characters */
		return max_cmp;
	}

	if (s1len > s2len) {
		/* Exchange s1 and s2 */
		const gchar *tmp;
		gsize tmplen;

		tmp = s2;
		s2 = s1;
		s1 = tmp;

		tmplen = s2len;
		s2len = s1len;
		s1len = tmplen;
	}

	/* Adjust static space */
	if (current_row == NULL) {
		current_row = g_array_sized_new (FALSE, FALSE, sizeof (gint), s1len + 1);
		prev_row = g_array_sized_new (FALSE, FALSE, sizeof (gint), s1len + 1);
		transp_row = g_array_sized_new (FALSE, FALSE, sizeof (gint), s1len + 1);
		g_array_set_size (current_row, s1len + 1);
		g_array_set_size (prev_row, s1len + 1);
		g_array_set_size (transp_row, s1len + 1);
	}
	else if (current_row->len < s1len + 1) {
		g_array_set_size (current_row, s1len + 1);
		g_array_set_size (prev_row, s1len + 1);
		g_array_set_size (transp_row, s1len + 1);
	}

	memset (current_row->data, 0, (s1len + 1) * sizeof (gint));
	memset (transp_row->data, 0, (s1len + 1) * sizeof (gint));

	for (gint i = 0; i <= s1len; i++) {
		g_array_index (prev_row, gint, i) = i;
	}

	last_c2 = '\0';

	for (gint i = 1; i <= s2len; i++) {
		c2 = s2[i - 1];
		g_array_index (current_row, gint, 0) = i;
		last_c1 = '\0';

		for (gint j = 1; j <= s1len; j++) {
			c1 = s1[j - 1];
			eq = c1 == c2 ? 0 : replace_cost;
			ret = MIN3 (g_array_index (current_row, gint, j - 1) + 1, /* Insert */
					g_array_index (prev_row, gint, j) + 1, /* Remove */
					g_array_index (prev_row, gint, j - 1) + eq /* Replace */);

			/* Take reordering into account */
			if (c1 == last_c2 && c2 == last_c1 && j >= 2) {
				ret = MIN (ret, g_array_index (transp_row, gint, j - 2) + eq);
			}

			g_array_index (current_row, gint, j) = ret;
			last_c1 = c1;
		}

		last_c2 = c2;

		/* Exchange pointers */
		GArray *tmp;
		tmp = transp_row;
		transp_row = prev_row;
		prev_row = current_row;
		current_row = tmp;
	}

	ret = g_array_index (prev_row, gint, s1len);

	return ret;
}

GString *
rspamd_header_value_fold (const gchar *name,
		const gchar *value,
		guint fold_max,
		enum rspamd_newlines_type how,
		const gchar *fold_on_chars)
{
	GString *res;
	const guint default_fold_max = 76;
	guint cur_len;
	const gchar *p, *c;
	guint nspaces = 0;
	const gchar *last;
	gboolean first_token = TRUE;
	enum {
		fold_before = 0,
		fold_after
	} fold_type = fold_before;
	enum {
		read_token = 0,
		read_quoted,
		after_quote,
		fold_token,
	} state = read_token, next_state = read_token;

	g_assert (name != NULL);
	g_assert (value != NULL);

	/* Filter insane values */
	if (fold_max < 20) {
		fold_max = default_fold_max;
	}

	res = g_string_sized_new (strlen (value));

	c = value;
	p = c;
	/* name:<WSP> */
	cur_len = strlen (name) + 2;

	while (*p) {
		switch (state) {

		case read_token:
			if (fold_on_chars) {
				if (strchr (fold_on_chars, *p) != NULL) {
					fold_type = fold_after;
					state = fold_token;
					next_state = read_token;
				}

				p ++;
			}
			else {
				if (*p == ',' || *p == ';') {
					/* We have something similar to the token's end, so check len */
					if (cur_len > fold_max * 0.8 && cur_len < fold_max) {
						/* We want fold */
						fold_type = fold_after;
						state = fold_token;
						next_state = read_token;
					} else if (cur_len > fold_max && !first_token) {
						fold_type = fold_before;
						state = fold_token;
						next_state = read_token;
					} else {
						g_string_append_len (res, c, p - c + 1);
						c = p + 1;
						first_token = FALSE;
					}
					p++;
				} else if (*p == '"') {
					/* Fold before quoted tokens */
					g_string_append_len (res, c, p - c);
					c = p;
					state = read_quoted;
				} else if (*p == '\r' || *p == '\n') {
					if (cur_len > fold_max && !first_token) {
						fold_type = fold_before;
						state = fold_token;
						next_state = read_token;
					} else {
						/* Reset line length */
						cur_len = 0;

						while (g_ascii_isspace (*p)) {
							p++;
						}

						g_string_append_len (res, c, p - c);
						c = p;
						first_token = TRUE;
					}
				} else if (g_ascii_isspace (*p)) {
					if (cur_len > fold_max * 0.8 && cur_len < fold_max) {
						/* We want fold */
						fold_type = fold_after;
						state = fold_token;
						next_state = read_token;
					} else if (cur_len > fold_max && !first_token) {
						fold_type = fold_before;
						state = fold_token;
						next_state = read_token;
					} else {
						g_string_append_len (res, c, p - c);
						c = p;
						first_token = FALSE;
						p++;
						cur_len++;
					}
				} else {
					p++;
					cur_len++;
				}
			}
			break;
		case fold_token:
			/* Here, we have token start at 'c' and token end at 'p' */
			if (fold_type == fold_after) {
				nspaces = 0;
				if (p > c) {
					g_string_append_len (res, c, p - c);

					/*
					 * Check any spaces that are appended to the result
					 * before folding
					 */
					last = &res->str[res->len - 1];

					while (g_ascii_isspace (*last)) {
						last --;
						nspaces ++;
						res->len --;
					}
				}

				switch (how) {
				case RSPAMD_TASK_NEWLINES_LF:
					g_string_append_len (res, "\n\t", 2);
					break;
				case RSPAMD_TASK_NEWLINES_CR:
					g_string_append_len (res, "\r\t", 2);
					break;
				case RSPAMD_TASK_NEWLINES_CRLF:
				default:
					g_string_append_len (res, "\r\n\t", 3);
					break;
				}

				/* Skip space if needed */
				if (g_ascii_isspace (*p)) {
					p ++;
				}

				/* Move leftover spaces */
				while (nspaces) {
					g_string_append_c (res, ' ');
					nspaces --;
				}

				cur_len = 0;
			}
			else {
				const gchar *last;

				/* Skip space if needed */
				if (g_ascii_isspace (*c) && p > c) {
					c ++;
				}

				/* Avoid double folding */
				last = &res->str[res->len - 1];
				last --;

				if (*last != '\r' && *last != '\n') {
					last ++;
					while (g_ascii_isspace (*last)) {
						last --;
						nspaces ++;
						res->len --;
					}

					switch (how) {
					case RSPAMD_TASK_NEWLINES_LF:
						g_string_append_len (res, "\n\t", 2);
						break;
					case RSPAMD_TASK_NEWLINES_CR:
						g_string_append_len (res, "\r\t", 2);
						break;
					case RSPAMD_TASK_NEWLINES_CRLF:
					default:
						g_string_append_len (res, "\r\n\t", 3);
						break;
					}
				}

				/* Move leftover spaces */
				cur_len = nspaces;

				while (nspaces) {
					g_string_append_c (res, ' ');
					nspaces --;
				}

				if (p > c) {
					g_string_append_len (res, c, p - c);
					cur_len += p - c;
				}
				else {
					cur_len = 0;
				}
			}

			first_token = TRUE;
			c = p;
			state = next_state;
			break;

		case read_quoted:
			if (p != c && *p == '"') {
				state = after_quote;
			}
			p ++;
			cur_len ++;
			break;

		case after_quote:
			state = read_token;
			/* Skip one more character after the quote */
			p ++;
			cur_len ++;
			g_string_append_len (res, c, p - c);
			c = p;
			first_token = TRUE;
			break;
		}
	}

	/* Last token */
	switch (state) {
	case read_token:
		if (!fold_on_chars && cur_len > fold_max && !first_token) {
			if (g_ascii_isspace (*c)) {
				c ++;
			}
			switch (how) {
			case RSPAMD_TASK_NEWLINES_LF:
				g_string_append_len (res, "\n\t", 2);
				break;
			case RSPAMD_TASK_NEWLINES_CR:
				g_string_append_len (res, "\r\t", 2);
				break;
			case RSPAMD_TASK_NEWLINES_CRLF:
			default:
				g_string_append_len (res, "\r\n\t", 3);
				break;
			}
			g_string_append_len (res, c, p - c);
		}
		else {
			g_string_append_len (res, c, p - c);
		}
		break;
	case read_quoted:
	case after_quote:
		g_string_append_len (res, c, p - c);
		break;
	case fold_token:
		/* Here, we have token start at 'c' and token end at 'p' */
		if (g_ascii_isspace (res->str[res->len - 1])) {
			g_string_append_len (res, c, p - c);
		}
		else {
			if (*c != '\r' && *c != '\n') {
				/* We need to add folding as well */
				switch (how) {
				case RSPAMD_TASK_NEWLINES_LF:
					g_string_append_len (res, "\n\t", 2);
					break;
				case RSPAMD_TASK_NEWLINES_CR:
					g_string_append_len (res, "\r\t", 2);
					break;
				case RSPAMD_TASK_NEWLINES_CRLF:
				default:
					g_string_append_len (res, "\r\n\t", 3);
					break;
				}
				g_string_append_len (res, c, p - c);
			}
			else {
				g_string_append_len (res, c, p - c);
			}
		}
		break;
	default:
		g_assert (p == c);
		break;
	}

	return res;
}

static inline bool rspamd_substring_cmp_func (guchar a, guchar b) { return a == b; }

static inline bool rspamd_substring_casecmp_func (guchar a, guchar b) { return lc_map[a] == lc_map[b]; }

typedef bool (*rspamd_cmpchar_func_t) (guchar a, guchar b);

static inline void
rspamd_substring_preprocess_kmp (const gchar *pat, gsize len, goffset *fsm,
		rspamd_cmpchar_func_t f)
{
	goffset i, j;

	i = 0;
	j = -1;
	fsm[0] = -1;

	while (i < len) {
		while (j > -1 && !f(pat[i], pat[j])) {
			j = fsm[j];
		}

		i++;
		j++;

		if (i < len && j < len && f(pat[i], pat[j])) {
			fsm[i] = fsm[j];
		}
		else {
			fsm[i] = j;
		}
	}
}

static inline goffset
rspamd_substring_search_preprocessed (const gchar *in, gsize inlen,
								const gchar *srch,
								gsize srchlen,
								const goffset *fsm,
								rspamd_cmpchar_func_t f)
{
	goffset i, j, k, ell;

	for (ell = 1; f(srch[ell - 1], srch[ell]); ell++) {}
	if (ell == srchlen) {
		ell = 0;
	}

	/* Searching */
	i = ell;
	j = k = 0;

	while (j <= inlen - srchlen) {
		while (i < srchlen && f(srch[i], in[i + j])) {
			++i;
		}

		if (i >= srchlen) {
			while (k < ell && f(srch[k], in[j + k])) {
				++k;
			}

			if (k >= ell) {
				return j;
			}
		}

		j += (i - fsm[i]);

		if (i == ell) {
			k = MAX(0, k - 1);
		}
		else {
			if (fsm[i] <= ell) {
				k = MAX(0, fsm[i]);
				i = ell;
			} else {
				k = ell;
				i = fsm[i];
			}
		}
	}

	return -1;
}

static inline goffset
rspamd_substring_search_common (const gchar *in, gsize inlen,
		const gchar *srch, gsize srchlen, rspamd_cmpchar_func_t f)
{
	static goffset st_fsm[128];
	goffset *fsm, ret;

	if (G_LIKELY (srchlen < G_N_ELEMENTS (st_fsm))) {
		fsm = st_fsm;
	}
	else {
		fsm = g_malloc ((srchlen + 1) * sizeof (*fsm));
	}

	rspamd_substring_preprocess_kmp (srch, srchlen, fsm, f);
	ret = rspamd_substring_search_preprocessed (in, inlen, srch, srchlen, fsm, f);

	if (G_UNLIKELY (srchlen >= G_N_ELEMENTS (st_fsm))) {
		g_free (fsm);
	}

	return ret;
}

goffset
rspamd_substring_search (const gchar *in, gsize inlen,
		const gchar *srch, gsize srchlen)
{
	if (inlen > srchlen) {
		if (G_UNLIKELY (srchlen == 1)) {
			const gchar *p;

			p = memchr (in, srch[0], inlen);

			if (p) {
				return p - in;
			}

			return (-1);
		}
		else if (G_UNLIKELY (srchlen == 0)) {
			return 0;
		}

		return rspamd_substring_search_common (in, inlen, srch, srchlen,
				rspamd_substring_cmp_func);
	}
	else if (inlen == srchlen) {
		return (rspamd_lc_cmp (srch, in, srchlen) == 0 ? 0 : -1);
	}
	else {
		return (-1);
	}

	return (-1);
}

goffset
rspamd_substring_search_caseless (const gchar *in, gsize inlen,
		const gchar *srch, gsize srchlen)
{
	if (inlen > srchlen) {
		if (G_UNLIKELY (srchlen == 1)) {
			goffset i;
			gchar s = lc_map[(guchar)srch[0]];

			for (i = 0; i < inlen; i++) {
				if (lc_map[(guchar)in[i]] == s) {
					return i;
				}
			}

			return (-1);
		}

		return rspamd_substring_search_common (in, inlen, srch, srchlen,
				rspamd_substring_casecmp_func);
	}
	else if (inlen == srchlen) {
		return rspamd_lc_cmp (srch, in, srchlen) == 0 ? 0 : (-1);
	}

	return (-1);
}

goffset
rspamd_string_find_eoh (GString *input, goffset *body_start)
{
	const gchar *p, *c = NULL, *end;
	enum {
		skip_char = 0,
		got_cr,
		got_lf,
		got_linebreak,
		got_linebreak_cr,
		got_linebreak_lf,
		obs_fws
	} state = skip_char;

	g_assert (input != NULL);

	p = input->str;
	end = p + input->len;

	while (p < end) {
		switch (state) {
		case skip_char:
			if (*p == '\r') {
				p++;
				state = got_cr;
			}
			else if (*p == '\n') {
				p++;
				state = got_lf;
			}
			else {
				p++;
			}
			break;

		case got_cr:
			if (*p == '\r') {
				/*
				 * Double \r\r, so need to check the current char
				 * if it is '\n', then we have \r\r\n sequence, that is NOT
				 * double end of line
				 */
				if (p < end && p[1] == '\n') {
					p++;
					state = got_lf;
				}
				else {
					/* We have \r\r[^\n] */
					if (body_start) {
						*body_start = p - input->str + 1;
					}

					return p - input->str;
				}
			}
			else if (*p == '\n') {
				p++;
				state = got_lf;
			}
			else if (g_ascii_isspace (*p)) {
				/* We have \r<space>*, allow to stay in this state */
				c = p;
				p ++;
				state = obs_fws;
			}
			else {
				p++;
				state = skip_char;
			}
			break;
		case got_lf:
			if (*p == '\n') {
				/* We have \n\n, which is obviously end of headers */
				if (body_start) {
					*body_start = p - input->str + 1;
				}
				return p - input->str;
			}
			else if (*p == '\r') {
				state = got_linebreak;
			}
			else if (g_ascii_isspace (*p)) {
				/* We have \n<space>*, allow to stay in this state */
				c = p;
				p ++;
				state = obs_fws;
			}
			else {
				p++;
				state = skip_char;
			}
			break;
		case got_linebreak:
			if (*p == '\r') {
				c = p;
				p++;
				state = got_linebreak_cr;
			}
			else if (*p == '\n') {
				c = p;
				p++;
				state = got_linebreak_lf;
			}
			else if (g_ascii_isspace (*p)) {
				/* We have <linebreak><space>*, allow to stay in this state */
				c = p;
				p ++;
				state = obs_fws;
			}
			else {
				p++;
				state = skip_char;
			}
			break;
		case got_linebreak_cr:
			if (*p == '\r') {
				/* Got double \r\r after \n, so does not treat it as EOH */
				state = got_linebreak_cr;
				p++;
			}
			else if (*p == '\n') {
				state = got_linebreak_lf;
				p++;
			}
			else if (g_ascii_isspace (*p)) {
				/* We have \r\n<space>*, allow to keep in this state */
				c = p;
				state = obs_fws;
				p ++;
			}
			else {
				p++;
				state = skip_char;
			}
			break;
		case got_linebreak_lf:
			g_assert (c != NULL);
			if (body_start) {
				/* \r\n\r\n */
				*body_start = p - input->str;
			}

			return c - input->str;
		case obs_fws:
			if (*p == ' ' || *p == '\t') {
				p ++;
			}
			else if (*p == '\r') {
				/* Perform lookahead due to #2349 */
				if (end - p > 2) {
					if (p[1] == '\n' && g_ascii_isspace (p[2])) {
						/* Real obs_fws state, switch */
						c = p;
						p ++;
						state = got_cr;
					}
					else if (g_ascii_isspace (p[1])) {
						p ++;
						state = obs_fws;
					}
					else {
						/*
						 * <nline> <wsp>+ \r <nwsp>.
						 * It is an empty header likely, so we can go further...
						 * https://tools.ietf.org/html/rfc2822#section-4.2
						 */
						c = p;
						p ++;
						state = got_cr;
					}
				}
				else {
					/* shortage */
					if (body_start) {
						*body_start = p - input->str + 1;
					}

					return p - input->str;
				}
			}
			else if (*p == '\n') {
				/* Perform lookahead due to #2349 */
				if (end - p > 1) {
					/* Continue folding with an empty line */
					if (p[1] == ' ' || p[1] == '\t') {
						c = p;
						p ++;
						state = obs_fws;
					}
					else if (p[1] == '\r') {
						/* WTF state: we have seen spaces, \n and then it follows \r */
						c = p;
						p ++;
						state = got_lf;
					}
					else if (p[1] == '\n') {
						/*
						 * Switching to got_lf state here will let us to finish
						 * the cycle.
						 */
						c = p;
						p ++;
						state = got_lf;
					}
					else {
						/*
						 * <nline> <wsp>+ \n <nwsp>.
						 * It is an empty header likely, so we can go further...
						 * https://tools.ietf.org/html/rfc2822#section-4.2
						 */
						c = p;
						p ++;
						state = got_lf;
					}

				}
				else {
					/* shortage */
					if (body_start) {
						*body_start = p - input->str + 1;
					}

					return p - input->str;
				}
			}
			else {
				p++;
				state = skip_char;
			}
			break;
		}

	}

	if (state == got_linebreak_lf) {
		if (body_start) {
			/* \r\n\r\n */
			*body_start = p - input->str;
		}

		return c - input->str;
	}

	return -1;
}

gint
rspamd_encode_hex_buf (const guchar *in, gsize inlen, gchar *out,
		gsize outlen)
{
	gchar *o, *end;
	const guchar *p;
	static const gchar hexdigests[16] = "0123456789abcdef";

	end = out + outlen;
	o = out;
	p = in;

	while (inlen > 0 && o < end - 1) {
		*o++ = hexdigests[((*p >> 4) & 0xF)];
		*o++ = hexdigests[((*p++) & 0xF)];
		inlen --;
	}

	if (o <= end) {
		return (o - out);
	}

	return -1;
}

gchar *
rspamd_encode_hex (const guchar *in, gsize inlen)
{
	gchar *out;
	gsize outlen = inlen * 2 + 1;
	gint olen;

	if (in == NULL) {
		return NULL;
	}

	out = g_malloc (outlen);
	olen = rspamd_encode_hex_buf (in, inlen, out, outlen - 1);

	if (olen >= 0) {
		out[olen] = '\0';
	}
	else {
		g_free (out);

		return NULL;
	}

	return out;
}

gssize
rspamd_decode_hex_buf (const gchar *in, gsize inlen,
		guchar *out, gsize outlen)
{
	guchar *o, *end, ret = 0;
	const gchar *p;
	gchar c;

	end = out + outlen;
	o = out;
	p = in;

	/* We ignore trailing chars if we have not even input */
	inlen = inlen - inlen % 2;

	while (inlen > 1 && o < end) {
		c = *p++;

		if      (c >= '0' && c <= '9') ret = c - '0';
		else if (c >= 'A' && c <= 'F') ret = c - 'A' + 10;
		else if (c >= 'a' && c <= 'f') ret = c - 'a' + 10;

		c = *p++;
		ret *= 16;

		if      (c >= '0' && c <= '9') ret += c - '0';
		else if (c >= 'A' && c <= 'F') ret += c - 'A' + 10;
		else if (c >= 'a' && c <= 'f') ret += c - 'a' + 10;

		*o++ = ret;

		inlen -= 2;
	}

	if (o <= end) {
		return (o - out);
	}

	return -1;
}

guchar*
rspamd_decode_hex (const gchar *in, gsize inlen)
{
	guchar *out;
	gsize outlen = (inlen / 2 + inlen % 2) + 1;
	gint olen;

	if (in == NULL) {
		return NULL;
	}

	out = g_malloc (outlen);

	olen = rspamd_decode_hex_buf (in, inlen, out, outlen - 1);

	if (olen >= 0) {
		out[olen] = '\0';

		return out;
	}

	g_free (out);

	return NULL;
}

gssize
rspamd_decode_qp_buf (const gchar *in, gsize inlen,
		gchar *out, gsize outlen)
{
	gchar *o, *end, *pos, c;
	const gchar *p;
	guchar ret;
	gssize remain, processed;

	p = in;
	o = out;
	end = out + outlen;
	remain = inlen;

	while (remain > 0 && o < end) {
		if (*p == '=') {
			remain --;

			if (remain == 0) {
				/* Last '=' character, bugon */
				if (end - o > 0) {
					*o++ = *p;
				}
				else {
					/* Buffer overflow */
					return (-1);
				}

				break;
			}

			p ++;
decode:
			/* Decode character after '=' */
			c = *p++;
			remain --;
			ret = 0;

			if (c >= '0' && c <= '9') {
				ret = c - '0';
			}
			else if (c >= 'A' && c <= 'F') {
				ret = c - 'A' + 10;
			}
			else if (c >= 'a' && c <= 'f') {
				ret = c - 'a' + 10;
			}
			else if (c == '\r') {
				/* Eat one more endline */
				if (remain > 0 && *p == '\n') {
					p ++;
					remain --;
				}

				continue;
			}
			else if (c == '\n') {
				/* Soft line break */
				continue;
			}
			else {
				/* Hack, hack, hack, treat =<garbadge> as =<garbadge> */
				if (end - o > 1) {
					*o++ = '=';
					*o++ = *(p - 1);
				}
				else {
					return (-1);
				}

				continue;
			}

			if (remain > 0) {
				c = *p++;
				ret *= 16;
				remain --;

				if (c >= '0' && c <= '9') {
					ret += c - '0';
				}
				else if (c >= 'A' && c <= 'F') {
					ret += c - 'A' + 10;
				}
				else if (c >= 'a' && c <= 'f') {
					ret += c - 'a' + 10;
				}
				else {
					/* Treat =<good><rubbish> as =<good><rubbish> */
					if (end - o > 2) {
						*o++ = '=';
						*o++ = *(p - 2);
						*o++ = *(p - 1);
					}
					else {
						return (-1);
					}

					continue;
				}

				if (end - o > 0) {
					*o++ = (gchar)ret;
				}
				else {
					return (-1);
				}
			}
		}
		else {
			if (end - o >= remain) {
				if ((pos = memccpy (o, p, '=', remain)) == NULL) {
					/* All copied */
					o += remain;
					break;
				}
				else {
					processed = pos - o;
					remain -= processed;
					p += processed;

					if (remain > 0) {
						o = pos - 1;
						/*
						 * Skip comparison and jump inside decode branch,
						 * as we know that we have found match
						 */
						goto decode;
					}
					else {
						/* Last '=' character, bugon */
						o = pos;

						if (end - o > 0) {
							*o = '=';
						}
						else {
							/* Buffer overflow */
							return (-1);
						}

						break;
					}
				}
			}
			else {
				/* Buffer overflow */
				return (-1);
			}
		}
	}

	return (o - out);
}

gssize
rspamd_decode_uue_buf (const gchar *in, gsize inlen,
					  gchar *out, gsize outlen)
{
	gchar *o, *out_end;
	const gchar *p;
	gssize remain;
	gboolean base64 = FALSE;
	goffset pos;
	const gchar *nline = "\r\n";

	p = in;
	o = out;
	out_end = out + outlen;
	remain = inlen;

	/* Skip newlines */
#define SKIP_NEWLINE do { while (remain > 0 && (*p == '\n' || *p == '\r')) {p ++; remain --; } } while (0)
	SKIP_NEWLINE;

	/* First of all, we need to read the first line (and probably skip it) */
	if (remain < sizeof ("begin-base64 ")) {
		/* Obviously truncated */
		return -1;
	}

	if (memcmp (p, "begin ", sizeof ("begin ") - 1) == 0) {
		p += sizeof ("begin ") - 1;
		remain -= sizeof ("begin ") - 1;

		pos = rspamd_memcspn (p, nline, remain);
	}
	else if (memcmp (p, "begin-base64 ", sizeof ("begin-base64 ") - 1) == 0) {
		base64 = TRUE;
		p += sizeof ("begin-base64 ") - 1;
		remain -= sizeof ("begin-base64 ") - 1;
		pos = rspamd_memcspn (p, nline, remain);
	}
	else {
		/* Crap */
		return (-1);
	}

	if (pos == -1 || remain == 0) {
		/* Crap */
		return (-1);
	}

#define	DEC(c)	(((c) - ' ') & 077)		/* single character decode */
#define IS_DEC(c) ( (((c) - ' ') >= 0) && (((c) - ' ') <= 077 + 1) )
#define CHAR_OUT(c) do { if (o < out_end) { *o++ = c; } else { return (-1); } } while(0)

	remain -= pos;
	p = p + pos;
	SKIP_NEWLINE;

	if (base64) {
		if (!rspamd_cryptobox_base64_decode (p,
				remain,
				out, &outlen)) {
			return (-1);
		}

		return outlen;
	}

	while (remain > 0 && o < out_end) {
		/* Main cycle */
		const gchar *eol;
		gint i, ch;

		pos = rspamd_memcspn (p, nline, remain);

		if (pos == 0) {
			/* Skip empty lines */
			SKIP_NEWLINE;

			if (remain == 0) {
				break;
			}
		}

		eol = p + pos;
		remain -= eol - p;

		if ((i = DEC(*p)) <= 0) {
			/* Last pos */
			break;
		}

		/* i can be less than eol - p, it means uue padding which we ignore */
		for (++p; i > 0 && p < eol; p += 4, i -= 3) {
			if (i >= 3 && p + 3 < eol) {
				/* Process 4 bytes of input */
				if (!IS_DEC(*p)) {
					return (-1);
				}
				if (!IS_DEC(*(p + 1))) {
					return (-1);
				}
				if (!IS_DEC(*(p + 2))) {
					return (-1);
				}
				if (!IS_DEC(*(p + 3))) {
					return (-1);
				}
				ch = DEC(p[0]) << 2 | DEC(p[1]) >> 4;
				CHAR_OUT(ch);
				ch = DEC(p[1]) << 4 | DEC(p[2]) >> 2;
				CHAR_OUT(ch);
				ch = DEC(p[2]) << 6 | DEC(p[3]);
				CHAR_OUT(ch);
			}
			else {
				if (i >= 1 && p + 1 < eol) {
					if (!IS_DEC(*p)) {
						return (-1);
					}
					if (!IS_DEC(*(p + 1))) {
						return (-1);
					}

					ch = DEC(p[0]) << 2 | DEC(p[1]) >> 4;
					CHAR_OUT(ch);
				}
				if (i >= 2 && p + 2 < eol) {
					if (!IS_DEC(*(p + 1))) {
						return (-1);
					}
					if (!IS_DEC(*(p + 2))) {
						return (-1);
					}

					ch = DEC(p[1]) << 4 | DEC(p[2]) >> 2;
					CHAR_OUT(ch);
				}
			}
		}
		/* Skip newline */
		p = eol;
		SKIP_NEWLINE;
	}

	return (o - out);
}

#define BITOP(a,b,op) \
		((a)[(gsize)(b)/(8*sizeof *(a))] op (gsize)1<<((gsize)(b)%(8*sizeof *(a))))


gsize
rspamd_memcspn (const gchar *s, const gchar *e, gsize len)
{
	gsize byteset[32 / sizeof(gsize)];
	const gchar *p = s, *end = s + len;

	if (!e[1]) {
		for (; p < end && *p != *e; p++);
		return p - s;
	}

	memset (byteset, 0, sizeof byteset);

	for (; *e && BITOP (byteset, *(guchar *)e, |=); e++);
	for (; p < end && !BITOP (byteset, *(guchar *)p, &); p++);

	return p - s;
}

gsize
rspamd_memspn (const gchar *s, const gchar *e, gsize len)
{
	gsize byteset[32 / sizeof(gsize)];
	const gchar *p = s, *end = s + len;

	if (!e[1]) {
		for (; p < end && *p == *e; p++);
		return p - s;
	}

	memset (byteset, 0, sizeof byteset);

	for (; *e && BITOP (byteset, *(guchar *)e, |=); e++);
	for (; p < end && BITOP (byteset, *(guchar *)p, &); p++);

	return p - s;
}

gssize
rspamd_decode_qp2047_buf (const gchar *in, gsize inlen,
		gchar *out, gsize outlen)
{
	gchar *o, *end, c;
	const gchar *p;
	guchar ret;
	gsize remain, processed;

	p = in;
	o = out;
	end = out + outlen;
	remain = inlen;

	while (remain > 0 && o < end) {
		if (*p == '=') {
			p ++;
			remain --;

			if (remain == 0) {
				if (end - o > 0) {
					*o++ = *p;
					break;
				}
			}
decode:
			/* Decode character after '=' */
			c = *p++;
			remain --;
			ret = 0;

			if      (c >= '0' && c <= '9') { ret = c - '0'; }
			else if (c >= 'A' && c <= 'F') { ret = c - 'A' + 10; }
			else if (c >= 'a' && c <= 'f') { ret = c - 'a' + 10; }
			else if (c == '\r' || c == '\n') {
				/* Soft line break */
				while (remain > 0 && (*p == '\r' || *p == '\n')) {
					remain --;
					p ++;
				}

				continue;
			}

			if (remain > 0) {
				c = *p++;
				ret *= 16;

				if      (c >= '0' && c <= '9') { ret += c - '0'; }
				else if (c >= 'A' && c <= 'F') { ret += c - 'A' + 10; }
				else if (c >= 'a' && c <= 'f') { ret += c - 'a' + 10; }

				if (end - o > 0) {
					*o++ = (gchar)ret;
				}
				else {
					return (-1);
				}

				remain --;
			}
		}
		else {
			if (end - o >= remain) {
				processed = rspamd_memcspn (p, "=_", remain);
				memcpy (o, p, processed);
				o += processed;

				if (processed == remain) {
					break;
				}
				else {

					remain -= processed;
					p += processed;

					if (G_LIKELY (*p == '=')) {
						p ++;
						/* Skip comparison, as we know that we have found match */
						remain --;
						goto decode;
					}
					else {
						*o++ = ' ';
						p ++;
						remain --;
					}
				}
			}
			else {
				/* Buffer overflow */
				return (-1);
			}
		}
	}

	return (o - out);
}

gssize
rspamd_encode_qp2047_buf (const gchar *in, gsize inlen,
		gchar *out, gsize outlen)
{
	gchar *o = out, *end = out + outlen, c;
	static const gchar hexdigests[16] = "0123456789ABCDEF";

	while (inlen > 0 && o < end) {
		c = *in;

		if (g_ascii_isalnum (c)) {
			*o++ = c;
		}
		else if (c == ' ') {
			*o++ = '_';
		}
		else if (end - o >= 3){
			*o++ = '=';
			*o++ = hexdigests[((c >> 4) & 0xF)];
			*o++ = hexdigests[(c & 0xF)];
		}
		else {
			return (-1);
		}

		in ++;
		inlen --;
	}

	if (inlen != 0) {
		return (-1);
	}

	return (o - out);
}


/*
 * GString ucl emitting functions
 */
static int
rspamd_gstring_append_character (unsigned char c, size_t len, void *ud)
{
	GString *buf = ud;
	gsize old_len;

	if (len == 1) {
		g_string_append_c (buf, c);
	}
	else {
		if (buf->allocated_len - buf->len <= len) {
			old_len = buf->len;
			g_string_set_size (buf, buf->len + len + 1);
			buf->len = old_len;
		}
		memset (&buf->str[buf->len], c, len);
		buf->len += len;
	}

	return 0;
}

static int
rspamd_gstring_append_len (const unsigned char *str, size_t len, void *ud)
{
	GString *buf = ud;

	g_string_append_len (buf, str, len);

	return 0;
}

static int
rspamd_gstring_append_int (int64_t val, void *ud)
{
	GString *buf = ud;

	rspamd_printf_gstring (buf, "%L", (intmax_t) val);
	return 0;
}

static int
rspamd_gstring_append_double (double val, void *ud)
{
	GString *buf = ud;
	const double delta = 0.0000001;

	if (isfinite (val)) {
		if (val == (double) (int) val) {
			rspamd_printf_gstring (buf, "%.1f", val);
		} else if (fabs (val - (double) (int) val) < delta) {
			/* Write at maximum precision */
			rspamd_printf_gstring (buf, "%.*g", DBL_DIG, val);
		} else {
			rspamd_printf_gstring (buf, "%f", val);
		}
	}
	else {
		rspamd_printf_gstring (buf, "null");
	}

	return 0;
}

void
rspamd_ucl_emit_gstring_comments (const ucl_object_t *obj,
		enum ucl_emitter emit_type,
		GString *target,
		const ucl_object_t *comments)
{
	struct ucl_emitter_functions func = {
			.ucl_emitter_append_character = rspamd_gstring_append_character,
			.ucl_emitter_append_len = rspamd_gstring_append_len,
			.ucl_emitter_append_int = rspamd_gstring_append_int,
			.ucl_emitter_append_double = rspamd_gstring_append_double
	};

	func.ud = target;
	ucl_object_emit_full (obj, emit_type, &func, comments);
}

/*
 * FString ucl emitting functions
 */
static int
rspamd_fstring_emit_append_character (unsigned char c, size_t len, void *ud)
{
	rspamd_fstring_t **buf = ud;

	*buf = rspamd_fstring_append_chars (*buf, c, len);

	return 0;
}

static int
rspamd_fstring_emit_append_len (const unsigned char *str, size_t len, void *ud)
{
	rspamd_fstring_t **buf = ud;

	*buf = rspamd_fstring_append (*buf, str, len);

	return 0;
}

static int
rspamd_fstring_emit_append_int (int64_t val, void *ud)
{
	rspamd_fstring_t **buf = ud;

	rspamd_printf_fstring (buf, "%L", (intmax_t) val);
	return 0;
}

static int
rspamd_fstring_emit_append_double (double val, void *ud)
{
	rspamd_fstring_t **buf = ud;
#define MAX_PRECISION 6

	if (isfinite (val)) {
		if (val == (double) ((gint) val)) {
			rspamd_printf_fstring (buf, "%.1f", val);
		} else {
			rspamd_printf_fstring (buf, "%." G_STRINGIFY (MAX_PRECISION) "f",
					val);
		}
	}
	else {
		rspamd_printf_fstring (buf, "null");
	}

	return 0;
}

void
rspamd_ucl_emit_fstring_comments (const ucl_object_t *obj,
		enum ucl_emitter emit_type,
		rspamd_fstring_t **buf,
		const ucl_object_t *comments)
{
	struct ucl_emitter_functions func = {
			.ucl_emitter_append_character = rspamd_fstring_emit_append_character,
			.ucl_emitter_append_len = rspamd_fstring_emit_append_len,
			.ucl_emitter_append_int = rspamd_fstring_emit_append_int,
			.ucl_emitter_append_double = rspamd_fstring_emit_append_double
	};

	func.ud = buf;
	ucl_object_emit_full (obj, emit_type, &func, comments);
}

#ifndef HAVE_MEMRCHR
void *
rspamd_memrchr (const void *m, gint c, gsize len)
{
	const guint8 *p = m;

	for (gsize i = len; i > 0; i --) {
		if (p[i - 1] == c) {
			return (void *)(p + i - 1);
		}
	}

	return NULL;
}
#endif

struct UConverter *
rspamd_get_utf8_converter (void)
{
	static UConverter *utf8_conv = NULL;
	UErrorCode uc_err = U_ZERO_ERROR;

	if (utf8_conv == NULL) {
		utf8_conv = ucnv_open ("UTF-8", &uc_err);
		if (!U_SUCCESS (uc_err)) {
			msg_err ("FATAL error: cannot open converter for utf8: %s",
					u_errorName (uc_err));

			g_assert_not_reached ();
		}

		ucnv_setFromUCallBack (utf8_conv,
				UCNV_FROM_U_CALLBACK_SUBSTITUTE,
				NULL,
				NULL,
				NULL,
				&uc_err);
		ucnv_setToUCallBack (utf8_conv,
				UCNV_TO_U_CALLBACK_SUBSTITUTE,
				NULL,
				NULL,
				NULL,
				&uc_err);
	}

	return utf8_conv;
}


const struct UNormalizer2 *
rspamd_get_unicode_normalizer (void)
{
#if U_ICU_VERSION_MAJOR_NUM >= 44
	UErrorCode uc_err = U_ZERO_ERROR;
	static const UNormalizer2 *norm = NULL;

	if (norm == NULL) {
		norm = unorm2_getInstance (NULL, "nfkc", UNORM2_COMPOSE, &uc_err);
		g_assert (U_SUCCESS (uc_err));
	}

	return norm;
#else
	/* Old libicu */
	return NULL;
#endif
}

gchar *
rspamd_str_regexp_escape (const gchar *pattern, gsize slen,
		gsize *dst_len, enum rspamd_regexp_escape_flags flags)
{
	const gchar *p, *end = pattern + slen;
	gchar *res, *d, t, *tmp_utf = NULL, *dend;
	gsize len;
	static const gchar hexdigests[16] = "0123456789abcdef";

	len = 0;
	p = pattern;

	/* [-[\]{}()*+?.,\\^$|#\s] need to be escaped */
	while (p < end) {
		t = *p ++;

		switch (t) {
		case '[':
		case ']':
		case '-':
		case '\\':
		case '{':
		case '}':
		case '(':
		case ')':
		case '*':
		case '+':
		case '?':
		case '.':
		case ',':
		case '^':
		case '$':
		case '|':
		case '#':
			if (!(flags & RSPAMD_REGEXP_ESCAPE_RE)) {
				len++;
			}
			break;
		default:
			if (g_ascii_isspace (t)) {
				len ++;
			}
			else {
				if (!g_ascii_isprint (t) || (t & 0x80)) {

					if (flags & RSPAMD_REGEXP_ESCAPE_UTF) {
						/* \x{code}, where code can be up to 5 digits */
						len += 4;
					}
					else {
						/* \\xHH -> 4 symbols */
						len += 3;
					}
				}
			}
			break;
		}
	}

	if (flags & RSPAMD_REGEXP_ESCAPE_UTF) {
		if (rspamd_fast_utf8_validate (pattern, slen) != 0) {
			tmp_utf = rspamd_str_make_utf_valid (pattern, slen, NULL, NULL);
		}
	}

	if (len == 0) {
		/* No need to escape anything */

		if (dst_len) {
			*dst_len = slen;
		}

		if (tmp_utf) {
			return tmp_utf;
		}
		else {
			return g_strdup (pattern);
		}
	}

	/* Escape logic */
	if (tmp_utf) {
		pattern = tmp_utf;
	}

	len = slen + len;
	res = g_malloc (len + 1);
	p = pattern;
	d = res;
	dend = d + len;

	while (p < end) {
		g_assert (d < dend);
		t = *p ++;

		switch (t) {
		case '[':
		case ']':
		case '-':
		case '\\':
		case '{':
		case '}':
		case '(':
		case ')':
		case '.':
		case ',':
		case '^':
		case '$':
		case '|':
		case '#':
			if (!(flags & RSPAMD_REGEXP_ESCAPE_RE)) {
				*d++ = '\\';
			}
			break;
		case '*':
		case '?':
		case '+':
			if (flags & RSPAMD_REGEXP_ESCAPE_GLOB) {
				/* Treat * as .* and ? as .? */
				*d++ = '.';
			}
			else {
				if (!(flags & RSPAMD_REGEXP_ESCAPE_RE)) {
					*d++ = '\\';
				}
			}
			break;
		default:
			if (g_ascii_isspace (t)) {
				if (!(flags & RSPAMD_REGEXP_ESCAPE_RE)) {
					*d++ = '\\';
				}
			}
			else if (t & 0x80 || !g_ascii_isprint (t)) {
				if (!(flags & RSPAMD_REGEXP_ESCAPE_UTF)) {
					*d++ = '\\';
					*d++ = 'x';
					*d++ = hexdigests[((t >> 4) & 0xF)];
					*d++ = hexdigests[((t) & 0xF)];
					continue; /* To avoid *d++ = t; */
				}
				else {
					if (flags & (RSPAMD_REGEXP_ESCAPE_RE|RSPAMD_REGEXP_ESCAPE_GLOB)) {
						UChar32 uc;
						gint32 off = p - pattern - 1;
						U8_NEXT (pattern, off, slen, uc);

						if (uc > 0) {
							d += rspamd_snprintf (d, dend - d,
									"\\x{%xd}", uc);
							p = pattern + off;
						}

						continue; /* To avoid *d++ = t; */
					}
				}
			}
			break;
		}

		*d++ = t;
	}

	*d = '\0';

	if (dst_len) {
		*dst_len = d - res;
	}

	if (tmp_utf) {
		g_free (tmp_utf);
	}

	return res;
}


gchar *
rspamd_str_make_utf_valid (const guchar *src, gsize slen,
		gsize *dstlen,
		rspamd_mempool_t *pool)
{
	UChar32 uc;
	goffset err_offset;
	const guchar *p;
	gchar *dst, *d;
	gsize remain = slen, dlen = 0;

	if (src == NULL) {
		return NULL;
	}

	if (slen == 0) {
		if (dstlen) {
			*dstlen = 0;
		}

		return pool ? rspamd_mempool_strdup (pool, "") : g_strdup ("");
	}

	p = src;
	dlen = slen + 1; /* As we add '\0' */

	/* Check space required */
	while (remain > 0 && (err_offset = rspamd_fast_utf8_validate (p, remain)) > 0) {
		gint i = 0;

		err_offset --; /* As it returns it 1 indexed */
		p += err_offset;
		remain -= err_offset;
		dlen += err_offset;

		/* Each invalid character of input requires 3 bytes of output (+2 bytes) */
		while (i < remain) {
			U8_NEXT (p, i, remain, uc);

			if (uc < 0) {
				dlen += 2;
			}
			else {
				break;
			}
		}

		p += i;
		remain -= i;
	}

	if (pool) {
		dst = rspamd_mempool_alloc (pool, dlen + 1);
	}
	else {
		dst = g_malloc (dlen + 1);
	}

	p = src;
	d = dst;
	remain = slen;

	while (remain > 0 && (err_offset = rspamd_fast_utf8_validate (p, remain)) > 0) {
		/* Copy valid */
		err_offset --; /* As it returns it 1 indexed */
		memcpy (d, p, err_offset);
		d += err_offset;

		/* Append 0xFFFD for each bad character */
		gint i = 0;

		p += err_offset;
		remain -= err_offset;

		while (i < remain) {
			gint old_i = i;
			U8_NEXT (p, i, remain, uc);

			if (uc < 0) {
				*d++ = '\357';
				*d++ = '\277';
				*d++ = '\275';
			}
			else {
				/* Adjust p and remaining stuff and go to the outer cycle */
				i = old_i;
				break;
			}
		}
		/*
		 * Now p is the first valid utf8 character and remain is the rest of the string
		 * so we can continue our loop
		 */
		p += i;
		remain -= i;
	}

	if (err_offset == 0 && remain > 0) {
		/* Last piece */
		memcpy (d, p, remain);
		d += remain;
	}

	/* Last '\0' */
	g_assert (dlen > d - dst);
	*d = '\0';

	if (dstlen) {
		*dstlen = d - dst;
	}

	return dst;
}

gsize
rspamd_gstring_strip (GString *s, const gchar *strip_chars)
{
	const gchar *p, *sc;
	gsize strip_len = 0, total = 0;

	p = s->str + s->len - 1;

	while (p >= s->str) {
		gboolean seen = FALSE;

		sc = strip_chars;

		while (*sc != '\0') {
			if (*p == *sc) {
				strip_len ++;
				seen = TRUE;
				break;
			}

			sc ++;
		}

		if (!seen) {
			break;
		}

		p --;
	}

	if (strip_len > 0) {
		s->len -= strip_len;
		s->str[s->len] = '\0';
		total += strip_len;
	}

	if (s->len > 0) {
		strip_len = rspamd_memspn (s->str, strip_chars, s->len);

		if (strip_len > 0) {
			memmove (s->str, s->str + strip_len, s->len - strip_len);
			s->len -= strip_len;
			total += strip_len;
		}
	}

	return total;
}

const gchar* rspamd_string_len_strip (const gchar *in,
									  gsize *len,
									  const gchar *strip_chars)
{
	const gchar *p, *sc;
	gsize strip_len = 0, old_len = *len;

	p = in + old_len - 1;

	/* Trail */
	while (p >= in) {
		gboolean seen = FALSE;

		sc = strip_chars;

		while (*sc != '\0') {
			if (*p == *sc) {
				strip_len ++;
				seen = TRUE;
				break;
			}

			sc ++;
		}

		if (!seen) {
			break;
		}

		p --;
	}

	if (strip_len > 0) {
		*len -= strip_len;
	}

	/* Head */
	old_len = *len;

	if (old_len > 0) {
		strip_len = rspamd_memspn (in, strip_chars, old_len);

		if (strip_len > 0) {
			*len -= strip_len;

			return in + strip_len;
		}
	}

	return in;
}

gchar **
rspamd_string_len_split (const gchar *in, gsize len, const gchar *spill,
		gint max_elts, rspamd_mempool_t *pool)
{
	const gchar *p = in, *end = in + len;
	gsize detected_elts = 0;
	gchar **res;

	/* Detect number of elements */
	while (p < end) {
		gsize cur_fragment = rspamd_memcspn (p, spill, end - p);

		if (cur_fragment > 0) {
			detected_elts ++;
			p += cur_fragment;

			if (max_elts > 0 && detected_elts >= max_elts) {
				break;
			}
		}

		/* Something like a,,b produces {'a', 'b'} not {'a', '', 'b'} */
		p += rspamd_memspn (p, spill, end - p);
	}

	res = pool ?
			rspamd_mempool_alloc (pool, sizeof (gchar *) * (detected_elts + 1)) :
			g_malloc (sizeof (gchar *) * (detected_elts + 1));
	/* Last one */
	res[detected_elts] = NULL;
	detected_elts = 0;
	p = in;

	while (p < end) {
		gsize cur_fragment = rspamd_memcspn (p, spill, end - p);

		if (cur_fragment > 0) {
			gchar *elt;

			elt = pool ?
				  rspamd_mempool_alloc (pool, cur_fragment + 1) :
				  g_malloc (cur_fragment + 1);

			memcpy (elt, p, cur_fragment);
			elt[cur_fragment] = '\0';

			res[detected_elts ++] = elt;
			p += cur_fragment;

			if (max_elts > 0 && detected_elts >= max_elts) {
				break;
			}
		}

		p += rspamd_memspn (p, spill, end - p);
	}

	return res;
}

#if defined(__x86_64__)
#include <x86intrin.h>
#endif

static inline gboolean
rspamd_str_has_8bit_u64 (const guchar *beg, gsize len)
{
	guint8 orb = 0;

	if (len >= 16) {
		const guchar *nextd = beg+8;
		guint64 n1 = 0, n2 = 0;

		do {
			n1 |= *(const guint64 *)beg;
			n2 |= *(const guint64 *)nextd;
			beg += 16;
			nextd += 16;
			len -= 16;
		} while (len >= 16);

		/*
		 * Idea from Benny Halevy <bhalevy@scylladb.com>
		 * - 7-th bit set   ==> orb = !(non-zero) - 1 = 0 - 1 = 0xFF
		 * - 7-th bit clear ==> orb = !0 - 1          = 1 - 1 = 0x00
		 */
		orb = !((n1 | n2) & 0x8080808080808080ULL) - 1;
	}

	while (len--) {
		orb |= *beg++;
	}

	return orb >= 0x80;
}

gboolean
rspamd_str_has_8bit (const guchar *beg, gsize len)
{
#if defined(__x86_64__)
	if (len >= 32) {
		const uint8_t *nextd = beg + 16;

		__m128i n1 = _mm_set1_epi8 (0), n2;

		n2 = n1;

		while (len >= 32) {
			__m128i xmm1 = _mm_loadu_si128 ((const __m128i *)beg);
			__m128i xmm2 = _mm_loadu_si128 ((const __m128i *)nextd);

			n1 = _mm_or_si128 (n1, xmm1);
			n2 = _mm_or_si128 (n2, xmm2);

			beg += 32;
			nextd += 32;
			len -= 32;
		}

		n1 = _mm_or_si128 (n1, n2);

		/* We assume 2 complement here */
		if (_mm_movemask_epi8 (n1)) {
			return TRUE;
		}
	}
#endif

	return rspamd_str_has_8bit_u64 (beg, len);
}
