/*-
 * Copyright 2019 Vsevolod Stakhov
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

#include "libserver/http/http_util.h"
#include "libutil/printf.h"
#include "libutil/util.h"

static const gchar *http_week[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static const gchar *http_month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
									 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

/*
 * Obtained from nginx
 * Copyright (C) Igor Sysoev
 */
static guint mday[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

time_t
rspamd_http_parse_date (const gchar *header, gsize len)
{
	const gchar *p, *end;
	gint month;
	guint day, year, hour, min, sec;
	guint64 time;
	enum {
		no = 0, rfc822, /* Tue, 10 Nov 2002 23:50:13   */
		rfc850, /* Tuesday, 10-Dec-02 23:50:13 */
		isoc /* Tue Dec 10 23:50:13 2002    */
	} fmt;

	fmt = 0;
	if (len > 0) {
		end = header + len;
	}
	else {
		end = header + strlen (header);
	}

	day = 32;
	year = 2038;

	for (p = header; p < end; p++) {
		if (*p == ',') {
			break;
		}

		if (*p == ' ') {
			fmt = isoc;
			break;
		}
	}

	for (p++; p < end; p++)
		if (*p != ' ') {
			break;
		}

	if (end - p < 18) {
		return (time_t)-1;
	}

	if (fmt != isoc) {
		if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
			return (time_t)-1;
		}

		day = (*p - '0') * 10 + *(p + 1) - '0';
		p += 2;

		if (*p == ' ') {
			if (end - p < 18) {
				return (time_t)-1;
			}
			fmt = rfc822;

		}
		else if (*p == '-') {
			fmt = rfc850;

		}
		else {
			return (time_t)-1;
		}

		p++;
	}

	switch (*p) {

	case 'J':
		month = *(p + 1) == 'a' ? 0 : *(p + 2) == 'n' ? 5 : 6;
		break;

	case 'F':
		month = 1;
		break;

	case 'M':
		month = *(p + 2) == 'r' ? 2 : 4;
		break;

	case 'A':
		month = *(p + 1) == 'p' ? 3 : 7;
		break;

	case 'S':
		month = 8;
		break;

	case 'O':
		month = 9;
		break;

	case 'N':
		month = 10;
		break;

	case 'D':
		month = 11;
		break;

	default:
		return (time_t)-1;
	}

	p += 3;

	if ((fmt == rfc822 && *p != ' ') || (fmt == rfc850 && *p != '-')) {
		return (time_t)-1;
	}

	p++;

	if (fmt == rfc822) {
		if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9'
			|| *(p + 2) < '0' || *(p + 2) > '9' || *(p + 3) < '0'
			|| *(p + 3) > '9') {
			return (time_t)-1;
		}

		year = (*p - '0') * 1000 + (*(p + 1) - '0') * 100
			   + (*(p + 2) - '0') * 10 + *(p + 3) - '0';
		p += 4;

	}
	else if (fmt == rfc850) {
		if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
			return (time_t)-1;
		}

		year = (*p - '0') * 10 + *(p + 1) - '0';
		year += (year < 70) ? 2000 : 1900;
		p += 2;
	}

	if (fmt == isoc) {
		if (*p == ' ') {
			p++;
		}

		if (*p < '0' || *p > '9') {
			return (time_t)-1;
		}

		day = *p++ - '0';

		if (*p != ' ') {
			if (*p < '0' || *p > '9') {
				return (time_t)-1;
			}

			day = day * 10 + *p++ - '0';
		}

		if (end - p < 14) {
			return (time_t)-1;
		}
	}

	if (*p++ != ' ') {
		return (time_t)-1;
	}

	if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
		return (time_t)-1;
	}

	hour = (*p - '0') * 10 + *(p + 1) - '0';
	p += 2;

	if (*p++ != ':') {
		return (time_t)-1;
	}

	if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
		return (time_t)-1;
	}

	min = (*p - '0') * 10 + *(p + 1) - '0';
	p += 2;

	if (*p++ != ':') {
		return (time_t)-1;
	}

	if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
		return (time_t)-1;
	}

	sec = (*p - '0') * 10 + *(p + 1) - '0';

	if (fmt == isoc) {
		p += 2;

		if (*p++ != ' ') {
			return (time_t)-1;
		}

		if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9'
			|| *(p + 2) < '0' || *(p + 2) > '9' || *(p + 3) < '0'
			|| *(p + 3) > '9') {
			return (time_t)-1;
		}

		year = (*p - '0') * 1000 + (*(p + 1) - '0') * 100
			   + (*(p + 2) - '0') * 10 + *(p + 3) - '0';
	}

	if (hour > 23 || min > 59 || sec > 59) {
		return (time_t)-1;
	}

	if (day == 29 && month == 1) {
		if ((year & 3) || ((year % 100 == 0) && (year % 400) != 0)) {
			return (time_t)-1;
		}

	}
	else if (day > mday[month]) {
		return (time_t)-1;
	}

	/*
	 * shift new year to March 1 and start months from 1 (not 0),
	 * it is needed for Gauss' formula
	 */

	if (--month <= 0) {
		month += 12;
		year -= 1;
	}

	/* Gauss' formula for Gregorian days since March 1, 1 BC */

	time = (guint64) (
			/* days in years including leap years since March 1, 1 BC */

			365 * year + year / 4 - year / 100 + year / 400

			/* days before the month */

			+ 367 * month / 12 - 30

			/* days before the day */

			+ day - 1

			/*
			 * 719527 days were between March 1, 1 BC and March 1, 1970,
			 * 31 and 28 days were in January and February 1970
			 */

			- 719527 + 31 + 28) * 86400 + hour * 3600 + min * 60 + sec;

	return (time_t) time;
}

glong
rspamd_http_date_format (gchar *buf, gsize len, time_t time)
{
	struct tm tms;

	rspamd_gmtime (time, &tms);

	return rspamd_snprintf (buf, len, "%s, %02d %s %4d %02d:%02d:%02d GMT",
			http_week[tms.tm_wday], tms.tm_mday,
			http_month[tms.tm_mon], tms.tm_year + 1900,
			tms.tm_hour, tms.tm_min, tms.tm_sec);
}

void
rspamd_http_normalize_path_inplace (gchar *path, guint len, gsize *nlen)
{
	const gchar *p, *end, *slash = NULL, *dot = NULL;
	gchar *o;
	enum {
		st_normal = 0,
		st_got_dot,
		st_got_dot_dot,
		st_got_slash,
		st_got_slash_slash,
	} state = st_normal;

	p = path;
	end = path + len;
	o = path;

	while (p < end) {
		switch (state) {
		case st_normal:
			if (G_UNLIKELY (*p == '/')) {
				state = st_got_slash;
				slash = p;
			}
			else if (G_UNLIKELY (*p == '.')) {
				state = st_got_dot;
				dot = p;
			}
			else {
				*o++ = *p;
			}
			p ++;
			break;
		case st_got_slash:
			if (G_UNLIKELY (*p == '/')) {
				/* Ignore double slash */
				*o++ = *p;
				state = st_got_slash_slash;
			}
			else if (G_UNLIKELY (*p == '.')) {
				dot = p;
				state = st_got_dot;
			}
			else {
				*o++ = '/';
				*o++ = *p;
				slash = NULL;
				dot = NULL;
				state = st_normal;
			}
			p ++;
			break;
		case st_got_slash_slash:
			if (G_LIKELY (*p != '/')) {
				slash = p - 1;
				dot = NULL;
				state = st_normal;
				continue;
			}
			p ++;
			break;
		case st_got_dot:
			if (G_UNLIKELY (*p == '/')) {
				/* Remove any /./ or ./ paths */
				if (((o > path && *(o - 1) != '/') || (o == path)) && slash) {
					/* Preserve one slash */
					*o++ = '/';
				}

				slash = p;
				dot = NULL;
				/* Ignore last slash */
				state = st_normal;
			}
			else if (*p == '.') {
				/* Double dot character */
				state = st_got_dot_dot;
			}
			else {
				/* We have something like .some or /.some */
				if (dot && p > dot) {
					if (slash == dot - 1 && (o > path && *(o - 1) != '/')) {
						/* /.blah */
						memmove (o, slash, p - slash);
						o += p - slash;
					}
					else {
						memmove (o, dot, p - dot);
						o += p - dot;
					}
				}

				slash = NULL;
				dot = NULL;
				state = st_normal;
				continue;
			}

			p ++;
			break;
		case st_got_dot_dot:
			if (*p == '/') {
				/* We have something like /../ or ../ */
				if (slash) {
					/* We need to remove the last component from o if it is there */
					if (o > path + 2 && *(o - 1) == '/') {
						slash = rspamd_memrchr (path, '/', o - path - 2);
					}
					else if (o > path + 1) {
						slash = rspamd_memrchr (path, '/', o - path - 1);
					}
					else {
						slash = NULL;
					}

					if (slash) {
						o = (gchar *)slash;
					}
					/* Otherwise we keep these dots */
					slash = p;
					state = st_got_slash;
				}
				else {
					/* We have something like bla../, so we need to copy it as is */
					if (o > path && dot && p > dot) {
						memmove (o, dot, p - dot);
						o += p - dot;
					}

					slash = NULL;
					dot = NULL;
					state = st_normal;
					continue;
				}
			}
			else {
				/* We have something like ..bla or ... */
				if (slash) {
					*o ++ = '/';
				}

				if (dot && p > dot) {
					memmove (o, dot, p - dot);
					o += p - dot;
				}

				slash = NULL;
				dot = NULL;
				state = st_normal;
				continue;
			}

			p ++;
			break;
		}
	}

	/* Leftover */
	switch (state) {
	case st_got_dot_dot:
		/* Trailing .. */
		if (slash) {
			/* We need to remove the last component from o if it is there */
			if (o > path + 2 && *(o - 1) == '/') {
				slash = rspamd_memrchr (path, '/', o - path - 2);
			}
			else if (o > path + 1) {
				slash = rspamd_memrchr (path, '/', o - path - 1);
			}
			else {
				if (o == path) {
					/* Corner case */
					*o++ = '/';
				}

				slash = NULL;
			}

			if (slash) {
				/* Remove last / */
				o = (gchar *)slash;
			}
		}
		else {
			/* Corner case */
			if (o == path) {
				*o++ = '/';
			}
			else {
				if (dot && p > dot) {
					memmove (o, dot, p - dot);
					o += p - dot;
				}
			}
		}
		break;
	case st_got_dot:
		if (slash) {
			/* /. -> must be / */
			*o++ = '/';
		}
		else {
			if (o > path) {
				*o++ = '.';
			}
		}
		break;
	case st_got_slash:
		*o++ = '/';
		break;
	default:
#if 0
		if (o > path + 1 && *(o - 1) == '/') {
			o --;
		}
#endif
		break;
	}

	if (nlen) {
		*nlen = (o - path);
	}
}