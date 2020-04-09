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

/* Copyright (C) 2002-2015 Igor Sysoev
 * Copyright (C) 2011-2015 Nginx, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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

#include "printf.h"
#include "str_util.h"
#include "contrib/fpconv/fpconv.h"

/**
 * From FreeBSD libutil code
 */
static const int maxscale = 6;
static const gchar _hex[] = "0123456789abcdef";
static const gchar _HEX[] = "0123456789ABCDEF";

static gchar *
rspamd_humanize_number (gchar *buf, gchar *last, gint64 num, gboolean bytes)
{
	const gchar *prefixes;
	int i, r, remainder, sign;
	gint64 divisor;
	gsize len = last - buf;

	remainder = 0;

	if (!bytes) {
		divisor = 1000;
		prefixes = "\0\0\0\0k\0\0\0M\0\0\0G\0\0\0T\0\0\0P\0\0\0E";
	}
	else {
		divisor = 1024;
		prefixes = "B\0\0\0KiB\0MiB\0GiB\0TiB\0PiB\0EiB";
	}

#define SCALE2PREFIX(scale)     (&prefixes[(scale) * 4])

	if (num < 0) {
		sign = -1;
		num = -num;
	}
	else {
		sign = 1;
	}

	/*
	 * Divide the number until it fits the given column.
	 * If there will be an overflow by the rounding below,
	 * divide once more.
	 */
	for (i = 0; i < maxscale && num > divisor; i++) {
		remainder = num % divisor;
		num /= divisor;
	}

	if (remainder == 0 || num > divisor / 2) {
		r = rspamd_snprintf (buf, len, "%L%s",
				sign * (num + (remainder + 50) / divisor),
				SCALE2PREFIX (i));
	}
	else {
		/* Floating point version */
		r = rspamd_snprintf (buf, len, "%.2f%s",
				sign * (num + remainder / (gdouble)divisor),
				SCALE2PREFIX (i));
	}

#undef SCALE2PREFIX

	return buf + r;
}


static inline unsigned
rspamd_decimal_digits32 (guint32 val)
{
	static const guint32 powers_of_10[] = {
			0,
			10,
			100,
			1000,
			10000,
			100000,
			1000000,
			10000000,
			100000000,
			1000000000
	};
	unsigned tmp;

#if defined(_MSC_VER)
	unsigned long r = 0;
	_BitScanReverse (&r, val | 1);
	tmp = (r + 1) * 1233 >> 12;
#elif defined(__GNUC__) && (__GNUC__ >= 3)
	tmp = (32 - __builtin_clz (val | 1U)) * 1233 >> 12;

#else /* Software version */
	static const unsigned debruijn_tbl[32] = { 0,  9,  1, 10, 13, 21,  2, 29,
											   11, 14, 16, 18, 22, 25,  3, 30,
											   8, 12, 20, 28, 15, 17, 24,  7,
											   19, 27, 23,  6, 26,  5,  4, 31 };
	guint32 v = val | 1;

	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	tmp = (1 + debruijn_tbl[(v * 0x07C4ACDDU) >> 27]) * 1233 >> 12;
#endif
	return tmp - (val < powers_of_10[tmp]) + 1;
}

static inline unsigned
rspamd_decimal_digits64 (guint64 val)
{
	static const guint64 powers_of_10[] = {
			0,
			10ULL,
			100ULL,
			1000ULL,
			10000ULL,
			100000ULL,
			1000000ULL,
			10000000ULL,
			100000000ULL,
			1000000000ULL,
			10000000000ULL,
			100000000000ULL,
			1000000000000ULL,
			10000000000000ULL,
			100000000000000ULL,
			1000000000000000ULL,
			10000000000000000ULL,
			100000000000000000ULL,
			1000000000000000000ULL,
			10000000000000000000ULL
	};
	unsigned tmp;

#if defined(_MSC_VER)
#if _M_IX86
	unsigned long r = 0;
	guint64 m = val | 1;
	if (_BitScanReverse (&r, m >> 32)) {
		r += 32;
	}
	else {
		_BitScanReverse (&r, m & 0xFFFFFFFF);
	}
	tmp = (r + 1) * 1233 >> 12;
#else
	unsigned long r = 0;
	_BitScanReverse64 (&r, val | 1);
	tmp = (r + 1) * 1233 >> 12;
#endif
#elif defined(__GNUC__) && (__GNUC__ >= 3)
	tmp = (64 - __builtin_clzll (val | 1ULL)) * 1233 >> 12;
#else /* Software version */
	static const unsigned debruijn_tbl[32] = { 0,  9,  1, 10, 13, 21,  2, 29,
											   11, 14, 16, 18, 22, 25,  3, 30,
											   8, 12, 20, 28, 15, 17, 24,  7,
											   19, 27, 23,  6, 26,  5,  4, 31 };
	guint32 v = val >> 32;

	if (v) {
		v |= 1;
		v |= v >> 1;
		v |= v >> 2;
		v |= v >> 4;
		v |= v >> 8;
		v |= v >> 16;
		tmp = 32 + debruijn_tbl[(v * 0x07C4ACDDU) >> 27];
	}
	else {
		v = val & 0xFFFFFFFF;
		v |= 1;
		v |= v >> 1;
		v |= v >> 2;
		v |= v >> 4;
		v |= v >> 8;
		v |= v >> 16;

		tmp = debruijn_tbl[(v * 0x07C4ACDDU) >> 27];
	}


	tmp = (tmp + 1) * 1233 >> 12;
#endif

	return tmp - (val < powers_of_10[tmp]) + 1;
}

/*
 * Idea from https://github.com/miloyip/itoa-benchmark:
 * Uses lookup table (LUT) of digit pairs for division/modulo of 100.
 *
 * Mentioned in:
 * https://www.slideshare.net/andreialexandrescu1/three-optimization-tips-for-c-15708507
 */

static const char int_lookup_table[200] = {
		'0','0','0','1','0','2','0','3','0','4',
		'0','5','0','6','0','7','0','8','0','9',
		'1','0','1','1','1','2','1','3','1','4',
		'1','5','1','6','1','7','1','8','1','9',
		'2','0','2','1','2','2','2','3','2','4',
		'2','5','2','6','2','7','2','8','2','9',
		'3','0','3','1','3','2','3','3','3','4',
		'3','5','3','6','3','7','3','8','3','9',
		'4','0','4','1','4','2','4','3','4','4',
		'4','5','4','6','4','7','4','8','4','9',
		'5','0','5','1','5','2','5','3','5','4',
		'5','5','5','6','5','7','5','8','5','9',
		'6','0','6','1','6','2','6','3','6','4',
		'6','5','6','6','6','7','6','8','6','9',
		'7','0','7','1','7','2','7','3','7','4',
		'7','5','7','6','7','7','7','8','7','9',
		'8','0','8','1','8','2','8','3','8','4',
		'8','5','8','6','8','7','8','8','8','9',
		'9','0','9','1','9','2','9','3','9','4',
		'9','5','9','6','9','7','9','8','9','9'
};

static inline guint
rspamd_uint32_print (guint32 in, gchar *out)
{
	guint ndigits = rspamd_decimal_digits32 (in);
	gchar *p;

	p = out + ndigits - 1;

	while (in >= 100) {
		unsigned idx = (in % 100) * 2;

		/* Do two digits at once */
		*p-- = int_lookup_table[idx + 1];
		*p-- = int_lookup_table[idx];

		in /= 100;
	}

	if (in < 10) {
		*p = ((char)in) + '0';
	}
	else {
		unsigned idx = in * 2;

		*p-- = int_lookup_table[idx + 1];
		*p = int_lookup_table[idx];
	}

	return ndigits;
}

static inline guint
rspamd_uint64_print (guint64 in, gchar *out)
{
	guint ndigits = rspamd_decimal_digits64 (in);
	guint32 v32;
	gchar *p;

	p = out + ndigits - 1;

	while (in >= 100000000) {
		v32 = (guint32)(in % 100000000);
		guint32 a, b, a1, a2, b1, b2;

		/* Initial spill */
		a = v32 / 10000;
		b = v32 % 10000;
		a1 = (a / 100) * 2;
		a2 = (a % 100) * 2;
		b1 = (b / 100) * 2;
		b2 = (b % 100) * 2;

		/* Fill 8 digits at once */
		*p-- = int_lookup_table[b2 + 1];
		*p-- = int_lookup_table[b2];
		*p-- = int_lookup_table[b1 + 1];
		*p-- = int_lookup_table[b1];
		*p-- = int_lookup_table[a2 + 1];
		*p-- = int_lookup_table[a2];
		*p-- = int_lookup_table[a1 + 1];
		*p-- = int_lookup_table[a1];

		in /= 100000000;
	}

	/* Remaining 32 bit */
	v32 = (guint32)in;

	while (v32 >= 100) {
		unsigned idx = (v32 % 100) << 1;

		/* Do 2 digits at once */
		*p-- = int_lookup_table[idx + 1];
		*p-- = int_lookup_table[idx];

		v32 /= 100;
	}

	if (v32 < 10) {
		*p = ((char)v32) + '0';
	}
	else {
		unsigned idx = v32 * 2;

		*p-- = int_lookup_table[idx + 1];
		*p = int_lookup_table[idx];
	}

	return ndigits;
}

static gchar *
rspamd_sprintf_num (gchar *buf, gchar *last, guint64 ui64, gchar zero,
					  guint hexadecimal, guint width)
{
	gchar *p, temp[sizeof ("18446744073709551615")];
	size_t len;

	if (hexadecimal == 0) {
		p = temp;

		if (ui64 < G_MAXUINT32) {
			len = rspamd_uint32_print ((guint32)ui64, temp);
		}
		else {
			len = rspamd_uint64_print (ui64, temp);
		}
	}
	else if (hexadecimal == 1) {
		p = temp + sizeof(temp);
		do {
			*--p = _hex[(guint32) (ui64 & 0xf)];
		} while (ui64 >>= 4);

		len = (temp + sizeof (temp)) - p;
	}
	else { /* hexadecimal == 2 */
		p = temp + sizeof(temp);
		do {
			*--p = _HEX[(guint32) (ui64 & 0xf)];
		} while (ui64 >>= 4);

		len = (temp + sizeof (temp)) - p;
	}

	/* zero or space padding */

	if (len < width) {
		width -= len;

		while (width-- > 0 && buf < last) {
			*buf++ = zero;
		}
	}

	/* number safe copy */

	if (buf + len > last) {
		len = last - buf;
	}

	return ((gchar *)memcpy (buf, p, len)) + len;
}

struct rspamd_printf_char_buf {
	char *begin;
	char *pos;
	glong remain;
};

static glong
rspamd_printf_append_char (const gchar *buf, glong buflen, gpointer ud)
{
	struct rspamd_printf_char_buf *dst = (struct rspamd_printf_char_buf *)ud;
	glong wr;

	if (dst->remain <= 0) {
		return dst->remain;
	}

	wr = MIN (dst->remain, buflen);
	memcpy (dst->pos, buf, wr);
	dst->remain -= wr;
	dst->pos += wr;

	return wr;
}

static glong
rspamd_printf_append_file (const gchar *buf, glong buflen, gpointer ud)
{
	FILE *dst = (FILE *)ud;
	if (buflen > 0) {
		return fwrite (buf, 1, buflen, dst);
	}
	else {
		return 0;
	}
}

static glong
rspamd_printf_append_gstring (const gchar *buf, glong buflen, gpointer ud)
{
	GString *dst = (GString *)ud;

	if (buflen > 0) {
		g_string_append_len (dst, buf, buflen);
	}

	return buflen;
}

static glong
rspamd_printf_append_fstring (const gchar *buf, glong buflen, gpointer ud)
{
	rspamd_fstring_t **dst = ud;

	if (buflen > 0) {
		*dst = rspamd_fstring_append (*dst, buf, buflen);
	}

	return buflen;
}

glong
rspamd_fprintf (FILE *f, const gchar *fmt, ...)
{
	va_list args;
	glong r;

	va_start (args, fmt);
	r = rspamd_vprintf_common (rspamd_printf_append_file, f, fmt, args);
	va_end (args);

	return r;
}

glong
rspamd_printf (const gchar *fmt, ...)
{
	va_list args;
	glong r;

	va_start (args, fmt);
	r = rspamd_vprintf_common (rspamd_printf_append_file, stdout, fmt, args);
	va_end (args);

	return r;
}

glong
rspamd_log_fprintf (FILE *f, const gchar *fmt, ...)
{
	va_list args;
	glong r;

	va_start (args, fmt);
	r = rspamd_vprintf_common (rspamd_printf_append_file, f, fmt, args);
	va_end (args);

	fflush (f);

	return r;
}


glong
rspamd_snprintf (gchar *buf, glong max, const gchar *fmt, ...)
{
	gchar *r;
	va_list args;

	va_start (args, fmt);
	r = rspamd_vsnprintf (buf, max, fmt, args);
	va_end (args);

	return (r - buf);
}

gchar *
rspamd_vsnprintf (gchar *buf, glong max, const gchar *fmt, va_list args)
{
	struct rspamd_printf_char_buf dst;

	dst.begin = buf;
	dst.pos = dst.begin;
	dst.remain = max - 1;
	(void)rspamd_vprintf_common (rspamd_printf_append_char, &dst, fmt, args);
	*dst.pos = '\0';

	return dst.pos;
}

glong
rspamd_printf_gstring (GString *s, const gchar *fmt, ...)
{
	va_list args;
	glong r;

	va_start (args, fmt);
	r = rspamd_vprintf_gstring (s, fmt, args);
	va_end (args);

	return r;
}

glong
rspamd_vprintf_gstring (GString *s, const gchar *fmt, va_list args)
{
	return rspamd_vprintf_common (rspamd_printf_append_gstring, s, fmt, args);
}

glong
rspamd_printf_fstring (rspamd_fstring_t **s, const gchar *fmt, ...)
{
	va_list args;
	glong r;

	va_start (args, fmt);
	r = rspamd_vprintf_fstring (s, fmt, args);
	va_end (args);

	return r;
}

glong
rspamd_vprintf_fstring (rspamd_fstring_t **s, const gchar *fmt, va_list args)
{
	return rspamd_vprintf_common (rspamd_printf_append_fstring, s, fmt, args);
}

#define RSPAMD_PRINTF_APPEND(buf, len)                                         \
	do {                                                                       \
		RSPAMD_PRINTF_APPEND_BUF(buf, len);                                    \
		fmt++;                                                                 \
		buf_start = fmt;                                                       \
	} while (0)

#define RSPAMD_PRINTF_APPEND_BUF(buf, len)                                     \
	do {                                                                       \
		wr = func ((buf), (len), apd);                                         \
		if (wr < (__typeof (wr))(len)) {                                       \
			goto oob;                                                          \
		}                                                                      \
		written += wr;                                                         \
	} while (0)

glong
rspamd_vprintf_common (rspamd_printf_append_func func,
	gpointer apd,
	const gchar *fmt,
	va_list args)
{
	gchar zero, numbuf[G_ASCII_DTOSTR_BUF_SIZE], dtoabuf[32], *p, *last;
	guchar c;
	const gchar *buf_start = fmt;
	gint d;
	gdouble f;
	glong written = 0, wr, slen;
	gint64 i64;
	guint64 ui64;
	guint width, sign, hex, humanize, bytes, frac_width, b32, b64;
	rspamd_fstring_t *v;
	rspamd_ftok_t *tok;
	GString *gs;
	GError *err;

	while (*fmt) {

		/*
		 * "buf < last" means that we could copy at least one character:
		 * the plain character, "%%", "%c", and minus without the checking
		 */

		if (*fmt == '%') {

			/* Append what we have in buf */
			if (fmt > buf_start) {
				wr = func (buf_start, fmt - buf_start, apd);
				if (wr <= 0) {
					goto oob;
				}
				written += wr;
			}

			i64 = 0;
			ui64 = 0;

			zero = (gchar) ((*++fmt == '0') ? '0' : ' ');
			width = 0;
			sign = 1;
			hex = 0;
			b32 = 0;
			b64 = 0;
			bytes = 0;
			humanize = 0;
			frac_width = 0;
			slen = -1;

			while (*fmt >= '0' && *fmt <= '9') {
				width = width * 10 + *fmt++ - '0';
			}


			for (;; ) {
				switch (*fmt) {

				case 'u':
					sign = 0;
					fmt++;
					continue;

				case 'm':
					fmt++;
					continue;

				case 'X':
					hex = 2;
					sign = 0;
					fmt++;
					continue;

				case 'x':
					hex = 1;
					sign = 0;
					fmt++;
					continue;
				case 'b':
					b32 = 1;
					sign = 0;
					fmt++;
					continue;
				case 'B':
					b64 = 1;
					sign = 0;
					fmt++;
					continue;
				case 'H':
					humanize = 1;
					bytes = 1;
					sign = 0;
					fmt++;
					continue;
				case 'h':
					humanize = 1;
					sign = 0;
					fmt++;
					continue;
				case '.':
					fmt++;

					if (*fmt == '*') {
						d = (gint)va_arg (args, gint);
						if (G_UNLIKELY (d < 0)) {
							return 0;
						}
						frac_width = (guint)d;
						fmt++;
					}
					else {
						while (*fmt >= '0' && *fmt <= '9') {
							frac_width = frac_width * 10 + *fmt++ - '0';
						}
					}

					break;

				case '*':
					d = (gint)va_arg (args, gint);
					if (G_UNLIKELY (d < 0)) {
						return 0;
					}
					slen = (glong)d;
					fmt++;
					continue;

				default:
					break;
				}

				break;
			}


			switch (*fmt) {

			case 'V':
				v = va_arg (args, rspamd_fstring_t *);

				if (v) {
					slen = v->len;

					if (G_UNLIKELY (width != 0)) {
						slen = MIN (v->len, width);
					}

					RSPAMD_PRINTF_APPEND (v->str, slen);
				}
				else {
					RSPAMD_PRINTF_APPEND ("(NULL)", 6);
				}

				continue;

			case 'T':
				tok = va_arg (args, rspamd_ftok_t *);

				if (tok) {
					slen = tok->len;

					if (G_UNLIKELY (width != 0)) {
						slen = MIN (tok->len, width);
					}
					RSPAMD_PRINTF_APPEND (tok->begin, slen);
				}
				else {
					RSPAMD_PRINTF_APPEND ("(NULL)", 6);
				}
				continue;

			case 'v':
				gs = va_arg (args, GString *);

				if (gs) {
					slen = gs->len;

					if (G_UNLIKELY (width != 0)) {
						slen = MIN (gs->len, width);
					}

					RSPAMD_PRINTF_APPEND (gs->str, slen);
				}
				else {
					RSPAMD_PRINTF_APPEND ("(NULL)", 6);
				}

				continue;

			case 'e':
				err = va_arg (args, GError *);

				if (err) {
					p = err->message;

					if (p == NULL) {
						p = "(NULL)";
					}
				}
				else {
					p = "unknown error";
				}

				slen = strlen (p);
				RSPAMD_PRINTF_APPEND (p, slen);

				continue;

			case 's':
				p = va_arg (args, gchar *);
				if (p == NULL) {
					p = "(NULL)";
					slen = sizeof ("(NULL)") - 1;
				}

				if (G_UNLIKELY (b32)) {
					gchar *b32buf;

					if (G_UNLIKELY (slen == -1)) {
						if (G_LIKELY (width != 0)) {
							slen = width;
						}
						else {
							/* NULL terminated string */
							slen = strlen (p);
						}
					}

					b32buf = rspamd_encode_base32 (p, slen, RSPAMD_BASE32_DEFAULT);

					if (b32buf) {
						RSPAMD_PRINTF_APPEND (b32buf, strlen (b32buf));
						g_free (b32buf);
					}
					else {
						RSPAMD_PRINTF_APPEND ("(NULL)", sizeof ("(NULL)") - 1);
					}
				}
				else if (G_UNLIKELY (hex)) {
					gchar hexbuf[2];

					if (G_UNLIKELY (slen == -1)) {
						if (G_LIKELY (width != 0)) {
							slen = width;
						}
						else {
							/* NULL terminated string */
							slen = strlen (p);
						}
					}

					while (slen) {
						hexbuf[0] = hex == 2 ? _HEX[(*p >> 4u) & 0xfu] :
								_hex[(*p >> 4u) & 0xfu];
						hexbuf[1] = hex == 2 ? _HEX[*p & 0xfu] : _hex[*p & 0xfu];
						RSPAMD_PRINTF_APPEND_BUF (hexbuf, 2);
						p++;
						slen--;
					}

					fmt++;
					buf_start = fmt;

				}
				else if (G_UNLIKELY (b64)) {
					gchar *b64buf;
					gsize olen = 0;

					if (G_UNLIKELY (slen == -1)) {
						if (G_LIKELY (width != 0)) {
							slen = width;
						}
						else {
							/* NULL terminated string */
							slen = strlen (p);
						}
					}

					b64buf = rspamd_encode_base64 (p, slen, 0, &olen);

					if (b64buf) {
						RSPAMD_PRINTF_APPEND (b64buf, olen);
						g_free (b64buf);
					}
					else {
						RSPAMD_PRINTF_APPEND ("(NULL)", sizeof ("(NULL)") - 1);
					}
				}
				else {
					if (slen == -1) {
						/* NULL terminated string */
						slen = strlen (p);
					}

					if (G_UNLIKELY (width != 0)) {
						slen = MIN (slen, width);
					}

					RSPAMD_PRINTF_APPEND (p, slen);
				}

				continue;

			case 'O':
				i64 = (gint64) va_arg (args, off_t);
				sign = 1;
				break;

			case 'P':
				i64 = (gint64) va_arg (args, pid_t);
				sign = 1;
				break;

			case 't':
				i64 = (gint64) va_arg (args, time_t);
				sign = 1;
				break;

			case 'z':
				if (sign) {
					i64 = (gint64) va_arg (args, ssize_t);
				} else {
					ui64 = (guint64) va_arg (args, size_t);
				}
				break;

			case 'd':
				if (sign) {
					i64 = (gint64) va_arg (args, gint);
				} else {
					ui64 = (guint64) va_arg (args, guint);
				}
				break;

			case 'l':
				if (sign) {
					i64 = (gint64) va_arg (args, glong);
				} else {
					ui64 = (guint64) va_arg (args, gulong);
				}
				break;

			case 'D':
				if (sign) {
					i64 = (gint64) va_arg (args, gint32);
				} else {
					ui64 = (guint64) va_arg (args, guint32);
				}
				break;

			case 'L':
				if (sign) {
					i64 = va_arg (args, gint64);
				} else {
					ui64 = va_arg (args, guint64);
				}
				break;


			case 'f':
				f = (gdouble) va_arg (args, double);
				slen = fpconv_dtoa (f, dtoabuf, frac_width, false);

				RSPAMD_PRINTF_APPEND (dtoabuf, slen);

				continue;

			case 'g':
				f = (gdouble) va_arg (args, double);
				slen = fpconv_dtoa (f, dtoabuf, 0, true);
				RSPAMD_PRINTF_APPEND (dtoabuf, slen);

				continue;

			case 'F':
				f = (gdouble) va_arg (args, long double);
				slen = fpconv_dtoa (f, dtoabuf, frac_width, false);

				RSPAMD_PRINTF_APPEND (dtoabuf, slen);

				continue;

			case 'G':
				f = (gdouble) va_arg (args, long double);
				slen = fpconv_dtoa (f, dtoabuf, 0, true);
				RSPAMD_PRINTF_APPEND (dtoabuf, slen);

				continue;

			case 'p':
				ui64 = (uintptr_t) va_arg (args, void *);
				hex = 2;
				sign = 0;
				zero = '0';
				width = sizeof (void *) * 2;
				break;

			case 'c':
				c = va_arg (args, gint);
				c &= 0xffu;
				if (G_UNLIKELY (hex)) {
					gchar hexbuf[2];
					hexbuf[0] = hex == 2 ? _HEX[(c >> 4u) & 0xfu] :
								_hex[(c >> 4u) & 0xfu];
					hexbuf[1] = hex == 2 ? _HEX[c & 0xfu] : _hex[c & 0xfu];

					RSPAMD_PRINTF_APPEND (hexbuf, 2);
				}
				else {
					RSPAMD_PRINTF_APPEND (&c, 1);
				}

				continue;

			case 'Z':
				c = '\0';
				RSPAMD_PRINTF_APPEND (&c, 1);

				continue;

			case 'N':
				c = '\n';
				RSPAMD_PRINTF_APPEND (&c, 1);

				continue;

			case '%':
				c = '%';
				RSPAMD_PRINTF_APPEND (&c, 1);

				continue;

			default:
				c = *fmt;
				RSPAMD_PRINTF_APPEND (&c, 1);

				continue;
			}

			/* Print number */
			p = numbuf;
			last = p + sizeof (numbuf);
			if (sign) {
				if (i64 < 0) {
					*p++ = '-';
					ui64 = (guint64) - i64;

				} else {
					ui64 = (guint64) i64;
				}
			}

			if (!humanize) {
				p = rspamd_sprintf_num (p, last, ui64, zero, hex, width);
			}
			else {
				p = rspamd_humanize_number (p, last, ui64, bytes);
			}
			slen = p - numbuf;
			RSPAMD_PRINTF_APPEND (numbuf, slen);

		} else {
			fmt++;
		}
	}

	/* Finish buffer */
	if (fmt > buf_start) {
		wr = func (buf_start, fmt - buf_start, apd);
		if (wr <= 0) {
			goto oob;
		}
		written += wr;
	}

oob:
	return written;
}

