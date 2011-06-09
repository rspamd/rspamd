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
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
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

gint
rspamd_fprintf (FILE *f, const gchar *fmt, ...)
{
	gchar   *p;
	va_list   args;
    gchar buf[BUFSIZ];
    gint r;

	va_start (args, fmt);
	p = rspamd_vsnprintf (buf, sizeof (buf), fmt, args);
	va_end (args);

    r = fprintf (f, "%s", buf);

    return r;
}

gint
rspamd_sprintf (gchar *buf, const gchar *fmt, ...)
{
	gchar   *p;
	va_list   args;

	va_start (args, fmt);
	p = rspamd_vsnprintf (buf, /* STUB */ 65536, fmt, args);
	va_end (args);

	return p - buf;
}


gint
rspamd_snprintf (gchar *buf, glong max, const gchar *fmt, ...)
{
	gchar   *p;
	va_list   args;

	va_start (args, fmt);
	p = rspamd_vsnprintf (buf, max - 1, fmt, args);
	va_end (args);
	*p = '\0';

	return p - buf;
}

gchar *
rspamd_escape_string (gchar *dst, const gchar *src, glong len)
{
	gchar              *buf = dst, *last = dst + len;
	guint8              c;
	const gchar        *p = src;
	gunichar            uc;

	if (len <= 0) {
		return dst;
	}

	while (*p && buf < last) {
		/* Detect utf8 */
		uc = g_utf8_get_char_validated (p, last - buf);
		if (uc > 0) {
			c = g_unichar_to_utf8 (uc, buf);
			buf += c;
			p += c;
		}
		else {
			c = *p ++;
			if (G_UNLIKELY ((c & 0x80))) {
				c &= 0x7F;
				if (last - buf >= 3) {
					*buf++ = 'M';
					*buf++ = '-';
				}
			}
			if (G_UNLIKELY ( g_ascii_iscntrl (c))) {
				if (c == '\n') {
					*buf++ = ' ';
				}
				else if (c == '\t') {
					*buf++ = '\t';
				}
				else {
					*buf++ = '^';
					if (buf != last) {
						*buf++ = c ^ 0100;
					}
				}
			}
			else {
				*buf++ = c;
			}
		}
	}

	*buf = '\0';

	return buf;
}

gchar *
rspamd_vsnprintf (gchar *buf, glong max, const gchar *fmt, va_list args)
{
	gchar              *p, zero, *last;
	gint                d;
	long double         f, scale;
	size_t              len, slen;
	gint64              i64;
	guint64             ui64;
	guint               width, sign, hex, max_width, frac_width, i;
	f_str_t			   *v;

	if (max <= 0) {
		return buf;
	}

	last = buf + max;

	while (*fmt && buf < last) {

		/*
		 * "buf < last" means that we could copy at least one character:
		 * the plain character, "%%", "%c", and minus without the checking
		 */

		if (*fmt == '%') {

			i64 = 0;
			ui64 = 0;

			zero = (gchar) ((*++fmt == '0') ? '0' : ' ');
			width = 0;
			sign = 1;
			hex = 0;
			max_width = 0;
			frac_width = 0;
			slen = (size_t) -1;

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
					max_width = 1;
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
				case '.':
					fmt++;

					while (*fmt >= '0' && *fmt <= '9') {
						frac_width = frac_width * 10 + *fmt++ - '0';
					}

					break;

				case '*':
					d = (gint)va_arg (args, gint);
					if (G_UNLIKELY (d < 0)) {
						msg_err ("crititcal error: size is less than 0");
						g_assert (0);
					}
					slen = (size_t)d;
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

				len = v->len;
				len = (buf + len < last) ? len : (size_t) (last - buf);

				buf = ((gchar *)memcpy (buf, v->begin, len)) + len;
				fmt++;

				continue;

			case 's':
				p = va_arg(args, gchar *);
				if (p == NULL) {
					p = "(NULL)";
				}

				if (slen == (size_t) -1) {
					while (*p && buf < last) {
						*buf++ = *p++;
					}

				} else {
					len = (buf + slen < last) ? slen : (size_t) (last - buf);

					buf = ((gchar *)memcpy (buf, p, len)) + len;
				}

				fmt++;

				continue;

			case 'S':
				p = va_arg(args, gchar *);
				if (p == NULL) {
					p = "(NULL)";
				}

				if (slen == (size_t) -1) {
					buf = rspamd_escape_string (buf, p, last - buf);

				} else {
					len = (buf + slen < last) ? slen : (size_t) (last - buf);

					buf = rspamd_escape_string (buf, p, len);
				}

				fmt++;

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
					i64 = (gint64) va_arg(args, long);
				} else {
					ui64 = (guint64) va_arg(args, guint32);
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
				f = (double) va_arg (args, double);
				if (f < 0) {
					*buf++ = '-';
					f = -f;
				}

				ui64 = (gint64) f;

				buf = rspamd_sprintf_num (buf, last, ui64, zero, 0, width);

				if (frac_width) {

					if (buf < last) {
						*buf++ = '.';
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

					buf = rspamd_sprintf_num (buf, last, ui64, '0', 0, frac_width);
				}

				fmt++;

				continue;

			case 'F':
				f = (long double) va_arg (args, long double);

				if (f < 0) {
					*buf++ = '-';
					f = -f;
				}

				ui64 = (gint64) f;

				buf = rspamd_sprintf_num (buf, last, ui64, zero, 0, width);

				if (frac_width) {

					if (buf < last) {
						*buf++ = '.';
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

					buf = rspamd_sprintf_num (buf, last, ui64, '0', 0, frac_width);
				}

				fmt++;

				continue;

			case 'g':
				f = (long double) va_arg (args, double);

				if (f < 0) {
					*buf++ = '-';
					f = -f;
				}
				g_ascii_formatd (buf, last - buf, "%g", (double)f);
				buf += strlen (buf);
				fmt++;

				continue;

			case 'G':
				f = (long double) va_arg (args, long double);

				if (f < 0) {
					*buf++ = '-';
					f = -f;
				}
				g_ascii_formatd (buf, last - buf, "%g", (double)f);
				buf += strlen (buf);
				fmt++;

				continue;

			case 'p':
				ui64 = (uintptr_t) va_arg (args, void *);
				hex = 2;
				sign = 0;
				zero = '0';
				width = sizeof (void *) * 2;
				break;

			case 'c':
				d = va_arg (args, gint);
				*buf++ = (gchar) (d & 0xff);
				fmt++;

				continue;

			case 'Z':
				*buf++ = '\0';
				fmt++;

				continue;

			case 'N':
				*buf++ = LF;
				fmt++;

				continue;

			case '%':
				*buf++ = '%';
				fmt++;

				continue;

			default:
				*buf++ = *fmt++;

				continue;
			}

			if (sign) {
				if (i64 < 0) {
					*buf++ = '-';
					ui64 = (guint64) -i64;

				} else {
					ui64 = (guint64) i64;
				}
			}

			buf = rspamd_sprintf_num (buf, last, ui64, zero, hex, width);

			fmt++;

		} else {
			*buf++ = *fmt++;
		}
	}

	return buf;
}

