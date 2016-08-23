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
#include <math.h>

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

void
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
	case 2:
		*dest++ = lc_map[(guchar)str[i++]];
	case 1:
		*dest++ = lc_map[(guchar)str[i]];
	}

}

gint
rspamd_lc_cmp (const gchar *s, const gchar *d, gsize l)
{
	guint fp, i;
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
		if (g_ascii_tolower (*s) != g_ascii_tolower (*d)) {
			return (*s) - (*d);
		}

		leftover--;
		s++;
		d++;
	}

	return ret;
}

/*
 * The purpose of this function is fast and in place conversion of a unicode
 * string to lower case, so some locale peculiarities are simply ignored
 * If the target string is longer than initial one, then we just trim it
 */
void
rspamd_str_lc_utf8 (gchar *str, guint size)
{
	const gchar *s = str, *p;
	gchar *d = str, tst[6];
	gint remain = size;
	gint r;
	gunichar uc;

	while (remain > 0) {
		uc = g_utf8_get_char (s);
		uc = g_unichar_tolower (uc);
		p = g_utf8_next_char (s);

		if (p - s > remain) {
			break;
		}

		if (remain >= 6) {
			r = g_unichar_to_utf8 (uc, d);
		}
		else {
			/* We must be cautious here to avoid broken unicode being append */
			r = g_unichar_to_utf8 (uc, tst);
			if (r > remain) {
				break;
			}
			else {
				memcpy (d, tst, r);
			}
		}
		remain -= r;
		s = p;
		d += r;
	}
}

gboolean
rspamd_strcase_equal (gconstpointer v, gconstpointer v2)
{
	if (g_ascii_strcasecmp ((const gchar *)v, (const gchar *)v2) == 0) {
		return TRUE;
	}

	return FALSE;
}

static guint
rspamd_icase_hash (const gchar *in, gsize len)
{
	guint leftover = len % 4;
	guint fp, i;
	const uint8_t* s = (const uint8_t*) in;
	union {
		struct {
			guchar c1, c2, c3, c4;
		} c;
		guint32 pp;
	} u;
	rspamd_cryptobox_fast_hash_state_t st;

	fp = len - leftover;
	rspamd_cryptobox_fast_hash_init (&st, rspamd_hash_seed ());

	for (i = 0; i != fp; i += 4) {
		u.c.c1 = s[i], u.c.c2 = s[i + 1], u.c.c3 = s[i + 2], u.c.c4 = s[i + 3];
		u.c.c1 = lc_map[u.c.c1];
		u.c.c2 = lc_map[u.c.c2];
		u.c.c3 = lc_map[u.c.c3];
		u.c.c4 = lc_map[u.c.c4];
		rspamd_cryptobox_fast_hash_update (&st, &u.pp, sizeof (u));
	}

	u.pp = 0;
	switch (leftover) {
	case 3:
		u.c.c3 = lc_map[(guchar)s[i++]];
	case 2:
		u.c.c2 = lc_map[(guchar)s[i++]];
	case 1:
		u.c.c1 = lc_map[(guchar)s[i]];
		rspamd_cryptobox_fast_hash_update (&st, &u.pp, leftover);
		break;
	}

	return rspamd_cryptobox_fast_hash_final (&st);
}

guint
rspamd_strcase_hash (gconstpointer key)
{
	const gchar *p = key;
	gsize len;

	len = strlen (p);

	return rspamd_icase_hash (p, len);
}

guint
rspamd_str_hash (gconstpointer key)
{
	gsize len;

	len = strlen ((const gchar *)key);

	return rspamd_cryptobox_fast_hash (key, len, rspamd_hash_seed ());
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

	return rspamd_icase_hash (f->begin, f->len);
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

	return rspamd_icase_hash (f->str, f->len);
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
rspamd_strlcpy (gchar *dst, const gchar *src, gsize siz)
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
rspamd_strlcpy_tolower (gchar *dst, const gchar *src, gsize siz)
{
	gchar *d = dst;
	const gchar *s = src;
	gsize n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0) {
		while (--n != 0) {
			if ((*d++ = g_ascii_tolower (*s++)) == '\0') {
				break;
			}
		}
	}

	if (n == 0 && siz != 0) {
		*d = '\0';
	}

	return (s - src - 1);    /* count does not include NUL */
}


/*
 * Find the first occurrence of find in s, ignore case.
 */
gchar *
rspamd_strncasestr (const gchar *s, const gchar *find, gint len)
{
	gchar c, sc;
	gsize mlen;

	if ((c = *find++) != 0) {
		c = g_ascii_tolower (c);
		mlen = strlen (find);
		do {
			do {
				if ((sc = *s++) == 0 || len-- == 0)
					return (NULL);
			} while (g_ascii_tolower (sc) != c);
		} while (g_ascii_strncasecmp (s, find, mlen) != 0);
		s--;
	}
	return ((gchar *)s);
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
gboolean
rspamd_strtoul (const gchar *s, gsize len, gulong *value)
{
	const gchar *p = s, *end = s + len;
	gchar c;
	gulong v = 0;
	const gulong cutoff = G_MAXULONG / 10, cutlim = G_MAXULONG % 10;

	/* Some preparations for range errors */
	while (p < end) {
		c = *p;
		if (c >= '0' && c <= '9') {
			c -= '0';
			if (v > cutoff || (v == cutoff && (guint8)c > cutlim)) {
				/* Range error */
				*value = G_MAXULONG;
				return FALSE;
			}
			else {
				v *= 10;
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
rspamd_encode_base32_buf (const guchar *in, gsize inlen, gchar *out,
		gsize outlen)
{
	static const char b32[]="ybndrfg8ejkmcpqxot1uwisza345h769";
	gchar *o, *end;
	gsize i;
	gint remain = -1, x;

	end = out + outlen;
	o = out;

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
	if (remain >= 0 && o < end) {
		*o++ = b32[remain];
	}

	if (o <= end) {
		return (o - out);
	}

	return -1;
}

gchar *
rspamd_encode_base32 (const guchar *in, gsize inlen)
{
	gsize allocated_len = inlen * 8 / 5 + 2;
	gchar *out;
	gint outlen;

	out = g_malloc (allocated_len);
	outlen = rspamd_encode_base32_buf (in, inlen, out, allocated_len - 1);

	if (outlen >= 0) {
		out[outlen] = 0;

		return out;
	}

	g_free (out);

	return NULL;
}

static const guchar b32_dec[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x12, 0xff, 0x19, 0x1a, 0x1b, 0x1e, 0x1d,
	0x07, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x18, 0x01, 0x0c, 0x03, 0x08, 0x05, 0x06,
	0x1c, 0x15, 0x09, 0x0a, 0xff, 0x0b, 0x02, 0x10,
	0x0d, 0x0e, 0x04, 0x16, 0x11, 0x13, 0xff, 0x14,
	0x0f, 0x00, 0x17, 0xff, 0xff, 0xff, 0xff, 0xff,
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

gint
rspamd_decode_base32_buf (const gchar *in, gsize inlen,
		guchar *out, gsize outlen)
{
	guchar *o, *end, decoded;
	guchar c;
	guint acc = 0U;
	guint processed_bits = 0;
	gsize i;

	end = out + outlen;
	o = out;

	for (i = 0; i < inlen; i ++) {
		c = (guchar)in[i];

		if (processed_bits >= 8) {
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

	return (o - out);
}

guchar*
rspamd_decode_base32 (const gchar *in, gsize inlen, gsize *outlen)
{
	guchar *res;

	gsize allocated_len = inlen * 5 / 8 + 2;
	gssize olen;

	res = g_malloc (allocated_len);

	olen = rspamd_decode_base32_buf (in, inlen, res, allocated_len - 1);

	if (olen >= 0) {
		res[olen] = '\0';
	}
	else {
		g_free (res);

		return NULL;
	}

	if (outlen) {
		*outlen = olen;
	}

	return res;
}



/**
 * Decode string using base32 encoding
 * @param in input
 * @param inlen input length
 * @param out output buf (may overlap with `in`)
 * @param outlen output buf len
 * @return TRUE if in is valid base32 and `outlen` is enough to encode `inlen`
 */


static gchar *
rspamd_encode_base64_common (const guchar *in, gsize inlen, gint str_len,
		gsize *outlen, gboolean fold)
{
#define CHECK_SPLIT \
	do { if (str_len > 0 && cols >= str_len) { \
				*o++ = '\r'; \
				*o++ = '\n'; \
				if (fold) *o++ = '\t'; \
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
		allocated_len += (allocated_len / str_len + 1) * (fold ? 3 : 2) + 1;
	}

	out = g_malloc (allocated_len);
	o = out;
	cols = 0;

	while (inlen > 6) {
		n = *(guint64 *)in;
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

			*o++ = '\r';
			*o++ = '\n';
			if (fold) {
				*o ++ = '\t';
			}

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
	return rspamd_encode_base64_common (in, inlen, str_len, outlen, FALSE);
}

gchar *
rspamd_encode_base64_fold (const guchar *in, gsize inlen, gint str_len,
		gsize *outlen)
{
	return rspamd_encode_base64_common (in, inlen, str_len, outlen, TRUE);
}

gsize
rspamd_decode_url (gchar *dst, const gchar *src, gsize size)
{
	gchar *d, ch, c, decoded;
	const gchar *s;
	enum {
		sw_usual = 0,
		sw_quoted,
		sw_quoted_second
	} state;

	d = dst;
	s = src;

	state = 0;
	decoded = 0;

	while (size--) {

		ch = *s++;

		switch (state) {
		case sw_usual:

			if (ch == '%') {
				state = sw_quoted;
				break;
			}
			else if (ch == '+') {
				*d++ = ' ';
			}
			else {
				*d++ = ch;
			}
			break;

		case sw_quoted:

			if (ch >= '0' && ch <= '9') {
				decoded = (ch - '0');
				state = sw_quoted_second;
				break;
			}

			c = (ch | 0x20);
			if (c >= 'a' && c <= 'f') {
				decoded = (c - 'a' + 10);
				state = sw_quoted_second;
				break;
			}

			/* the invalid quoted character */

			state = sw_usual;

			*d++ = ch;

			break;

		case sw_quoted_second:

			state = sw_usual;

			if (ch >= '0' && ch <= '9') {
				ch = ((decoded << 4) + ch - '0');
				*d++ = ch;

				break;
			}

			c = (u_char) (ch | 0x20);
			if (c >= 'a' && c <= 'f') {
				ch = ((decoded << 4) + c - 'a' + 10);

				*d++ = ch;
				break;
			}

			/* the invalid quoted character */
			break;
		}
	}

	return (d - dst);
}
#define MIN3(a, b, c) ((a) < (b) ? ((a) < (c) ? (a) : (c)) : ((b) < (c) ? (b) : (c)))

gint
rspamd_strings_levenshtein_distance (const gchar *s1, gsize s1len,
		const gchar *s2, gsize s2len,
		guint replace_cost)
{
	guint x, y, lastdiag, olddiag;
	gchar c1, c2;
	guint *column;
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
		return 0;
	}

	column = g_malloc0 ((s1len + 1) * sizeof (guint));

	for (y = 1; y <= s1len; y++) {
		column[y] = y;
	}

	for (x = 1; x <= s2len; x++) {
		column[0] = x;

		for (y = 1, lastdiag = x - 1; y <= s1len; y++) {
			olddiag = column[y];
			c1 = s1[y - 1];
			c2 = s2[x - 1];
			eq = (c1 == c2) ? 0 : replace_cost;
			column[y] = MIN3 (column[y] + 1, column[y - 1] + 1,
					lastdiag + (eq));
			lastdiag = olddiag;
		}
	}

	ret = column[s1len];
	g_free (column);

	return ret;
}

GString *
rspamd_header_value_fold (const gchar *name,
		const gchar *value,
		guint fold_max)
{
	GString *res;
	const guint default_fold_max = 76;
	guint cur_len;
	const gchar *p, *c;
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
			if (*p == ',' || *p == ';') {
				/* We have something similar to the token's end, so check len */
				if (cur_len > fold_max * 0.8 && cur_len < fold_max) {
					/* We want fold */
					fold_type = fold_after;
					state = fold_token;
					next_state = read_token;
				}
				else if (cur_len > fold_max && !first_token) {
					fold_type = fold_before;
					state = fold_token;
					next_state = read_token;
				}
				else {
					g_string_append_len (res, c, p - c + 1);
					c = p + 1;
					first_token = FALSE;
				}
				p ++;
			}
			else if (*p == '"') {
				/* Fold before quoted tokens */
				g_string_append_len (res, c, p - c);
				c = p;
				state = read_quoted;
			}
			else if (*p == '\r') {
				/* Reset line length */
				cur_len = 0;

				while (g_ascii_isspace (*p)) {
					p ++;
				}

				g_string_append_len (res, c, p - c);
				c = p;
			}
			else if (g_ascii_isspace (*p)) {
				if (cur_len > fold_max * 0.8 && cur_len < fold_max) {
					/* We want fold */
					fold_type = fold_after;
					state = fold_token;
					next_state = read_token;
				}
				else if (cur_len > fold_max && !first_token) {
					fold_type = fold_before;
					state = fold_token;
					next_state = read_token;
				}
				else {
					g_string_append_len (res, c, p - c);
					c = p;
					first_token = FALSE;
					p ++;
				}
			}
			else {
				p ++;
				cur_len ++;
			}
			break;
		case fold_token:
			/* Here, we have token start at 'c' and token end at 'p' */
			if (fold_type == fold_after) {
				g_string_append_len (res, c, p - c);
				g_string_append_len (res, "\r\n\t", 3);

				/* Skip space if needed */
				if (g_ascii_isspace (*p)) {
					p ++;
				}
			}
			else {
				/* Skip space if needed */
				if (g_ascii_isspace (*c)) {
					c ++;
				}

				g_string_append_len (res, "\r\n\t", 3);
				g_string_append_len (res, c, p - c);
			}

			c = p;
			state = next_state;
			cur_len = 0;
			first_token = TRUE;
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
		if (cur_len > fold_max && !first_token) {
			if (g_ascii_isspace (*c)) {
				c ++;
			}
			g_string_append_len (res, "\r\n\t", 3);
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

	default:
		g_assert (p == c);
		break;
	}

	return res;
}

#define RKHASH(a, b, h) ((((h) - (a)*d) << 1) + (b))

goffset
rspamd_substring_search (const gchar *in, gsize inlen,
		const gchar *srch, gsize srchlen)
{
	gint d, hash_srch, hash_in;
	gsize i, j;

	if (inlen < srchlen) {
		return -1;
	}

	/* Preprocessing */
	for (d = i = 1; i < srchlen; ++i) {
		/* computes d = 2^(m-1) with the left-shift operator */
		d = (d << 1);
	}

	for (hash_in = hash_srch = i = 0; i < srchlen; ++i) {
		hash_srch = ((hash_srch << 1) + srch[i]);
		hash_in = ((hash_in << 1) + in[i]);
	}

	/* Searching */
	j = 0;
	while (j <= inlen - srchlen) {

		if (hash_srch == hash_in && memcmp (srch, in + j, srchlen) == 0) {
			return (goffset)j;
		}

		hash_in = RKHASH (in[j], in[j + srchlen], hash_in);
		++j;
	}

	return -1;
}

goffset
rspamd_substring_search_caseless (const gchar *in, gsize inlen,
		const gchar *srch, gsize srchlen)
{
	gint d, hash_srch, hash_in;
	gsize i, j;
	gchar c1, c2;

	if (inlen < srchlen) {
		return -1;
	}

	/* Preprocessing */
	for (d = i = 1; i < srchlen; ++i) {
		/* computes d = 2^(m-1) with the left-shift operator */
		d = (d << 1);
	}

	for (hash_in = hash_srch = i = 0; i < srchlen; ++i) {
		hash_srch = ((hash_srch << 1) + g_ascii_tolower (srch[i]));
		hash_in = ((hash_in << 1) + g_ascii_tolower (in[i]));
	}

	/* Searching */
	j = 0;
	while (j <= inlen - srchlen) {

		if (hash_srch == hash_in && rspamd_lc_cmp (srch, in + j, srchlen) == 0) {
			return (goffset) j;
		}

		c1 = g_ascii_tolower (in[j]);
		c2 = g_ascii_tolower (in[j + srchlen]);
		hash_in = RKHASH (c1, c2, hash_in);
		++j;
	}

	return -1;
}

/* Computing of the maximal suffix for <= */
static inline gint
rspamd_two_way_max_suffix (const gchar *srch, gint srchlen, gint *p)
{
	gint ms, j, k;
	gchar a, b;

	ms = -1;
	j = 0;
	k = *p = 1;

	while (j + k < srchlen) {
		a = srch[j + k];
		b = srch[ms + k];

		if (a < b) {
			j += k;
			k = 1;
			*p = j - ms;
		}
		else if (a == b)
			if (k != *p) {
				k++;
			}
			else {
				j += *p;
				k = 1;
			}
		else { /* a > b */
			ms = j;
			j = ms + 1;
			k = *p = 1;
		}
	}

	return (ms);
}

/* Computing of the maximal suffix for >= */
static inline gint
rspamd_two_way_max_suffix_tilde (const gchar *srch, gint srchlen, gint *p)
{
	gint ms, j, k;
	gchar a, b;

	ms = -1;
	j = 0;
	k = *p = 1;

	while (j + k < srchlen) {
		a = srch[j + k];
		b = srch[ms + k];

		if (a > b) {
			j += k;
			k = 1;
			*p = j - ms;
		}
		else if (a == b)
			if (k != *p) {
				k ++;
			}
			else {
				j += *p;
				k = 1;
			}
		else { /* a < b */
			ms = j;
			j = ms + 1;
			k = *p = 1;
		}
	}
	return (ms);
}

/* Two Way string matching algorithm. */
goffset
rspamd_substring_search_twoway (const gchar *in, gint inlen,
		const gchar *srch, gint srchlen)
{
	int i, j, ell, memory, p, per, q;

	/* Preprocessing */
	i = rspamd_two_way_max_suffix (srch, srchlen, &p);
	j = rspamd_two_way_max_suffix_tilde (srch, srchlen, &q);

	if (i > j) {
		ell = i;
		per = p;
	}
	else {
		ell = j;
		per = q;
	}

	/* Searching */
	if (memcmp (srch, srch + per, ell + 1) == 0) {
		j = 0;
		memory = -1;

		while (j <= inlen - srchlen) {
			i = MAX (ell, memory) + 1;

			while (i < srchlen && srch[i] == in[i + j]) {
				i ++;
			}

			if (i >= srchlen) {
				i = ell;

				while (i > memory && srch[i] == in[i + j]) {
					i --;
				}

				if (i <= memory) {
					return j;
				}

				j += per;
				memory = srchlen - per - 1;
			}
			else {
				j += (i - ell);
				memory = -1;
			}
		}
	}
	else {
		per = MAX (ell + 1, srchlen - ell - 1) + 1;
		j = 0;

		while (j <= inlen - srchlen) {
			i = ell + 1;

			while (i < srchlen && srch[i] == in[i + j]) {
				i ++;
			}

			if (i >= srchlen) {
				i = ell;

				while (i >= 0 && srch[i] == in[i + j]) {
					i --;
				}

				if (i < 0) {
					return j;
				}

				j += per;
			}
			else {
				j += (i - ell);
			}
		}
	}

	return -1;
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
		got_linebreak_lf
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

gint
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

	if (val == (double) (int) val) {
		rspamd_printf_gstring (buf, "%.1f", val);
	}
	else if (fabs (val - (double) (int) val) < delta) {
		/* Write at maximum precision */
		rspamd_printf_gstring (buf, "%.*g", DBL_DIG, val);
	}
	else {
		rspamd_printf_gstring (buf, "%f", val);
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
	const double delta = 0.0000001;

	if (val == (double)((gint) val)) {
		rspamd_printf_fstring (buf, "%.1f", val);
	}
	else if (fabs (val - (double) (int) val) < delta) {
		/* Write at maximum precision */
		rspamd_printf_fstring (buf, "%.*g", DBL_DIG, val);
	}
	else {
		rspamd_printf_fstring (buf, "%f", val);
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

guint
rspamd_url_hash (gconstpointer u)
{
	const struct rspamd_url *url = u;
	rspamd_cryptobox_fast_hash_state_t st;

	rspamd_cryptobox_fast_hash_init (&st, rspamd_hash_seed ());

	if (url->urllen > 0) {
		rspamd_cryptobox_fast_hash_update (&st, url->string, url->urllen);
	}

	rspamd_cryptobox_fast_hash_update (&st, &url->flags, sizeof (url->flags));

	return rspamd_cryptobox_fast_hash_final (&st);
}

/* Compare two emails for building emails tree */
gboolean
rspamd_emails_cmp (gconstpointer a, gconstpointer b)
{
	const struct rspamd_url *u1 = a, *u2 = b;
	gint r;

	if (u1->hostlen != u2->hostlen || u1->hostlen == 0) {
		return FALSE;
	}
	else {
		if ((r = rspamd_lc_cmp (u1->host, u2->host, u1->hostlen)) == 0) {
			if (u1->userlen != u2->userlen || u1->userlen == 0) {
				return FALSE;
			}
			else {
				return rspamd_lc_cmp (u1->user, u2->user, u1->userlen) ==
						0;
			}
		}
		else {
			return r == 0;
		}
	}

	return FALSE;
}

gboolean
rspamd_urls_cmp (gconstpointer a, gconstpointer b)
{
	const struct rspamd_url *u1 = a, *u2 = b;
	int r;

	if (u1->urllen != u2->urllen) {
		return FALSE;
	}
	else {
		r = memcmp (u1->string, u2->string, u1->urllen);
		if (r == 0 && u1->flags != u2->flags) {
			/* Always insert phished urls to the tree */
			return FALSE;
		}
	}

	return r == 0;
}

const void *
rspamd_memrchr (const void *m, gint c, gsize len)
{
	const guint8 *p = m;
	gsize i;

	for (i = len; i > 0; i --) {
		if (p[i - 1] == c) {
			return p + i - 1;
		}
	}

	return NULL;
}
