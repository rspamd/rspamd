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

#include "libutil/http_util.h"
#include "libutil/printf.h"
#include "libutil/util.h"

static const gchar *http_week[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static const gchar *http_month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
									 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

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
rspamd_http_normalize_path_inplace (gchar *path, guint len, guint *nlen)
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
	case st_got_slash:
		*o++ = '/';
		break;
	default:
		if (o > path + 1 && *(o - 1) == '/') {
			o --;
		}
		break;
	}

	if (nlen) {
		*nlen = (o - path);
	}
}