/* Copyright (c) 2010, Vsevolod Stakhov
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
#include "fstring.h"
#include "main.h"

/**
 * From FreeBSD libutil code
 */
static const int maxscale = 6;

static gchar *
rspamd_humanize_number (gchar *buf, gchar *last, gint64 num, gboolean bytes)
{
	const gchar *prefixes;
	int i, r, remainder, sign;
	gint64 divisor;
	gsize baselen, len = last - buf;

	remainder = 0;

	baselen = 1;
	if (!bytes) {
		divisor = 1000;
		prefixes = "\0\0\0k\0\0M\0\0G\0\0T\0\0P\0\0E";
	}
	else {
		divisor = 1024;
		prefixes = "B\0\0k\0\0M\0\0G\0\0T\0\0P\0\0E";
	}


#define SCALE2PREFIX(scale)     (&prefixes[(scale) * 3])

	if (num < 0) {
		sign = -1;
		num = -num;
		baselen += 2; /* sign, digit */
	}
	else {
		sign = 1;
		baselen += 1; /* digit */
	}

	/* Check if enough room for `x y' + suffix + `\0' */
	if (len < baselen + 1) {
		return buf;
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

	r = rspamd_snprintf (buf, len, "%L%s",
			sign * (num + (remainder + 50) / 1000),
			SCALE2PREFIX (i));

#undef SCALE2PREFIX

	return buf + r;
}


static gchar *
rspamd_sprintf_num (gchar *buf, gchar *last, guint64 ui64, gchar zero,
	guint                           hexadecimal, guint width)
{
	gchar		   *p, temp[sizeof ("18446744073709551615")];
	size_t		    len;
	guint32                         ui32;
	static gchar   hex[] = "0123456789abcdef";
	static gchar   HEX[] = "0123456789ABCDEF";

	p = temp + sizeof(temp);

	if (hexadecimal == 0) {

		if (ui64 <= G_MAXUINT32) {

			/*
			 * To divide 64-bit numbers and to find remainders
			 * on the x86 platform gcc and icc call the libc functions
			 * [u]divdi3() and [u]moddi3(), they call another function
			 * in its turn.  On FreeBSD it is the qdivrem() function,
			 * its source code is about 170 lines of the code.
			 * The glibc counterpart is about 150 lines of the code.
			 *
			 * For 32-bit numbers and some divisors gcc and icc use
			 * a inlined multiplication and shifts.  For example,
			 * guint "i32 / 10" is compiled to
			 *
			 *	 (i32 * 0xCCCCCCCD) >> 35
			 */

			ui32 = (guint32) ui64;

			do {
				*--p = (gchar) (ui32 % 10 + '0');
			} while (ui32 /= 10);

		} else {
			do {
				*--p = (gchar) (ui64 % 10 + '0');
			} while (ui64 /= 10);
		}

	} else if (hexadecimal == 1) {

		do {

			/* the "(guint32)" cast disables the BCC's warning */
			*--p = hex[(guint32) (ui64 & 0xf)];

		} while (ui64 >>= 4);

	} else { /* hexadecimal == 2 */

		do {

			/* the "(guint32)" cast disables the BCC's warning */
			*--p = HEX[(guint32) (ui64 & 0xf)];

		} while (ui64 >>= 4);
	}

	/* zero or space padding */

	len = (temp + sizeof (temp)) - p;

	while (len++ < width && buf < last) {
		*buf++ = zero;
	}

	/* number safe copy */

	len = (temp + sizeof (temp)) - p;

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

	return fwrite (buf, 1, buflen, dst);
}

static glong
rspamd_printf_append_gstring (const gchar *buf, glong buflen, gpointer ud)
{
	GString *dst = (GString *)ud;

	g_string_append_len (dst, buf, buflen);

	return buflen;
}

glong
rspamd_fprintf (FILE *f, const gchar *fmt, ...)
{
	va_list   args;
	glong r;

	va_start (args, fmt);
	r = rspamd_vprintf_common (rspamd_printf_append_file, f, fmt, args);
	va_end (args);

	return r;
}

glong
rspamd_printf (const gchar *fmt, ...)
{
	va_list   args;
	glong r;

	va_start (args, fmt);
	r = rspamd_vprintf_common (rspamd_printf_append_file, stdout, fmt, args);
	va_end (args);

	return r;
}

glong
rspamd_log_fprintf (FILE *f, const gchar *fmt, ...)
{
	va_list   args;
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
	r = rspamd_vprintf_common (rspamd_printf_append_gstring, s, fmt, args);
	va_end (args);

	return r;
}

#define RSPAMD_PRINTF_APPEND(buf, len)											\
    do {																		\
    wr = func ((buf), (len), apd);												\
    if (wr <= 0) {																\
        goto oob;																\
    }																			\
    written += wr;																\
    fmt ++;																		\
    buf_start = fmt;															\
    } while(0)

glong
rspamd_vprintf_common (rspamd_printf_append_func func, gpointer apd, const gchar *fmt, va_list args)
{
	gchar               zero, numbuf[G_ASCII_DTOSTR_BUF_SIZE], *p, *last, c;
	const gchar        *buf_start = fmt;
	gint                d;
	long double         f, scale;
	glong               written = 0, wr, slen;
	gint64              i64;
	guint64             ui64;
	guint               width, sign, hex, humanize, bytes, frac_width, i;
	f_str_t			   *v;
	GString            *gs;
	gboolean            bv;

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
			bytes = 0;
			humanize = 0;
			frac_width = 0;
			slen = -1;

			while (*fmt >= '0' && *fmt <= '9') {
				width = width * 10 + *fmt++ - '0';
			}


			for ( ;; ) {
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
				case 'H':
					humanize = 1;
					bytes = 1;
					sign = 0;
					fmt ++;
					continue;
				case 'h':
					humanize = 1;
					sign = 0;
					fmt ++;
					continue;
				case '.':
					fmt++;

					while (*fmt >= '0' && *fmt <= '9') {
						frac_width = frac_width * 10 + *fmt++ - '0';
					}

					break;

				case '*':
					d = (gint)va_arg (args, gint);
					if (G_UNLIKELY (d < 0)) {
						msg_err ("critical error: size is less than 0");
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
				v = va_arg (args, f_str_t *);
				RSPAMD_PRINTF_APPEND (v->begin, v->len);

				continue;

			case 'v':
				gs = va_arg (args, GString *);
				RSPAMD_PRINTF_APPEND (gs->str, gs->len);

				continue;

			case 's':
				p = va_arg (args, gchar *);
				if (p == NULL) {
					p = "(NULL)";
				}

				if (slen == -1) {
					/* NULL terminated string */
					slen = strlen (p);
				}

				RSPAMD_PRINTF_APPEND (p, slen);

				continue;

			case 'O':
				i64 = (gint64) va_arg (args, off_t);
				sign = 1;
				break;

			case 'P':
				i64 = (gint64) va_arg (args, pid_t);
				sign = 1;
				break;

			case 'T':
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
					i64 = (gint64) va_arg(args, glong);
				} else {
					ui64 = (guint64) va_arg(args, gulong);
				}
				break;

			case 'D':
				if (sign) {
					i64 = (gint64) va_arg(args, gint32);
				} else {
					ui64 = (guint64) va_arg(args, guint32);
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
			case 'F':
				if (*fmt == 'f') {
					f = (long double) va_arg (args, double);
				}
				else {
					f = (long double) va_arg (args, long double);
				}
				p = numbuf;
				last = p + sizeof (numbuf);
				if (f < 0) {
					*p++ = '-';
					f = -f;
				}

				ui64 = (gint64) f;

				p = rspamd_sprintf_num (p, last, ui64, zero, 0, width);

				if (frac_width) {

					if (p < last) {
						*p++ = '.';
					}

					scale = 1.0;

					for (i = 0; i < frac_width; i++) {
						scale *= 10.0;
					}

					/*
					* (gint64) cast is required for msvc6:
					* it can not convert guint64 to double
					*/
					ui64 = (guint64) ((f - (gint64) ui64) * scale);

					p = rspamd_sprintf_num (p, last, ui64, '0', 0, frac_width);
				}

				slen = p - numbuf;
				RSPAMD_PRINTF_APPEND (numbuf, slen);

				continue;

			case 'g':
			case 'G':
				if (*fmt == 'g') {
					f = (long double) va_arg (args, double);
				}
				else {
					f = (long double) va_arg (args, long double);
				}

				g_ascii_formatd (numbuf, sizeof (numbuf), "%g", (double)f);
				slen = strlen (numbuf);
				RSPAMD_PRINTF_APPEND (numbuf, slen);

				continue;

			case 'b':
				bv = (gboolean) va_arg (args, double);
				RSPAMD_PRINTF_APPEND (bv ? "true" : "false", bv ? 4 : 5);

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
				c &= 0xff;
				RSPAMD_PRINTF_APPEND (&c, 1);

				continue;

			case 'Z':
				c = '\0';
				RSPAMD_PRINTF_APPEND (&c, 1);

				continue;

			case 'N':
				c = LF;
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
					ui64 = (guint64) -i64;

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

